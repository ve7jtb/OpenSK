// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! WebAuthn `previewSign5` Signing Extension (`Version 5-SNAPSHOT-2026-10-06T12:44`).

use crate::api::crypto::ec_signing::{EcPublicKey as _, EcSecretKey as _, EcSignature as _};
use crate::api::crypto::hkdf256::Hkdf256 as _;
use crate::api::crypto::hmac256::Hmac256 as _;
use crate::api::crypto::sha256::Sha256 as _;
use crate::api::crypto::{EC_FIELD_SIZE, HASH_SIZE};
use crate::api::customization::Customization as _;
use crate::api::key_store::KeyStore as _;
use crate::api::persist::{Attestation, AttestationId, Persist as _};
use crate::api::private_key::PrivateKey;
use crate::api::rng::Rng as _;
use crate::ctap::arkg::{
    self, ArkgSeed, COSE_ALG_ES256, COSE_ALG_ESP256, COSE_ALG_ESP256_SPLIT_ARKG,
};
use crate::ctap::data_formats::{
    PackedAttestationStatement, extract_array, extract_bool, extract_byte_string, extract_integer,
    extract_map, extract_unsigned,
};
use crate::ctap::status_code::{Ctap2StatusCode, CtapResult};
use crate::ctap::{
    AT_FLAG, ED_FLAG, SUPPORTED_CRED_PARAMS, UP_FLAG, UV_FLAG, cbor_read, cbor_write, mtc,
};
use crate::env::{EcdsaSk, Env, Hkdf, Hmac, Sha};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use arrayref::array_ref;
use sk_cbor as cbor;
use sk_cbor::{cbor_array, cbor_bytes, cbor_int, cbor_map, cbor_map_options};
use zeroize::Zeroize;

/// Extension identifier for `previewSign` (v4, YubiKey 5.8).
pub const PREVIEW_SIGN_4_EXT_ID: &str = "previewSign";

/// Extension identifier for `previewSign5` (v5).
pub const PREVIEW_SIGN_5_EXT_ID: &str = "previewSign5";

/// COSE algorithm identifier for `ESP256-split` (`draft-ietf-cose-split-signing-algs`).
pub const COSE_ALG_ESP256_SPLIT: i64 = -300;

/// Prototype placeholder COSE algorithm identifier for `ESP256-split`.
pub const COSE_ALG_ESP256_SPLIT_PLACEHOLDER: i64 = -70009;

/// Supported `previewSign5` signing algorithms in order of preference.
pub const SUPPORTED_PREVIEW_SIGN_ALGS: &[i64] = &[
    COSE_ALG_ESP256,
    COSE_ALG_ES256,
    COSE_ALG_ESP256_SPLIT,
    COSE_ALG_ESP256_SPLIT_PLACEHOLDER,
    COSE_ALG_ESP256_SPLIT_ARKG,
];

// CBOR integer keys for `previewSign5` authenticator inputs and outputs.
const KEY_ERR: i64 = -1;
const KEY_KH: i64 = 2;
const KEY_ALG: i64 = 3;
const KEY_FLAGS: i64 = 4;
const KEY_TBS: i64 = 6;
const KEY_SIG: i64 = 6;
const KEY_ARGS: i64 = 7;
const KEY_ATT_OBJ: i64 = 7;
const KEY_SUPPORT: i64 = 8;

// `previewSignError` error codes.
pub const ERR_UNSUPPORTED_ASSERTION_OPERATION: i64 = 1;
pub const ERR_UNSUPPORTED_ALGORITHM: i64 = 2;
pub const ERR_UNSUPPORTED_ALGORITHM_COMBINATION: i64 = 3;
pub const ERR_INVALID_KEY_HANDLE: i64 = 4;
pub const ERR_COSE_SIGN_ARGS_INVALID: i64 = 5;
pub const ERR_COSE_SIGN_ARGS_ALG_MISMATCH: i64 = 6;
pub const ERR_COSE_SIGN_ARGS_MISSING_PARAM: i64 = 7;
pub const ERR_COSE_SIGN_ARGS_UNKNOWN_PARAM: i64 = 8;

// Valid `flags` values (`unattended`, `require-up`, `require-uv`, `require-up-uv`).
pub const FLAG_UNATTENDED: u8 = 0b000;
pub const FLAG_REQUIRE_UP: u8 = 0b001;
pub const FLAG_REQUIRE_UV: u8 = 0b100;
pub const FLAG_REQUIRE_UP_UV: u8 = 0b101;

fn is_valid_sign_flags_v4(flags: u64) -> bool {
    matches!(flags, 0b000 | 0b001 | 0b101)
}

fn is_valid_sign_flags(flags: u64) -> bool {
    matches!(
        flags,
        0b000 | 0b001 | 0b100 | 0b101
    )
}

/// Attestation statement format selected for the ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedAttestationFormat {
    Mtc,
    Packed,
    NoneFormat,
}

/// Parsed and validated `extensions["previewSign"]` (v4) input map.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PreviewSign4Input {
    pub kh: Option<Vec<u8>>,
    pub alg: Option<Vec<i64>>,
    pub flags: Option<u8>,
    pub tbs: Option<Vec<u8>>,
    pub args: Option<Vec<u8>>,
}

impl PreviewSign4Input {
    /// Parses and validates `extensions["previewSign"]` (v4) according to the v4 specification.
    pub fn try_from_cbor(cbor_value: cbor::Value, is_make_credential: bool) -> CtapResult<Self> {
        let map = extract_map(cbor_value)?;
        if map.is_empty() {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
        }

        let mut kh: Option<Vec<u8>> = None;
        let mut alg: Option<Vec<i64>> = None;
        let mut flags: Option<u8> = None;
        let mut tbs: Option<Vec<u8>> = None;
        let mut args: Option<Vec<u8>> = None;

        for (k, v) in map {
            let key_int = extract_integer(k)?;
            match key_int {
                KEY_KH => {
                    kh = Some(extract_byte_string(v)?);
                }
                KEY_ALG => {
                    let arr = extract_array(v)?;
                    if arr.is_empty() {
                        return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                    }
                    let mut algs = Vec::with_capacity(arr.len());
                    for item in arr {
                        algs.push(extract_integer(item)?);
                    }
                    alg = Some(algs);
                }
                KEY_FLAGS => {
                    let f = extract_unsigned(v)?;
                    if !is_valid_sign_flags_v4(f) {
                        return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                    }
                    flags = Some(f as u8);
                }
                KEY_TBS => {
                    tbs = Some(extract_byte_string(v)?);
                }
                KEY_ARGS => {
                    args = Some(extract_byte_string(v)?);
                }
                _ => return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION),
            }
        }

        if is_make_credential {
            if alg.is_none() || kh.is_some() || tbs.is_some() || args.is_some() {
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
            }
        } else if kh.is_none() || tbs.is_none() || alg.is_some() || flags.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
        }

        Ok(Self {
            kh,
            alg,
            flags,
            tbs,
            args,
        })
    }
}

/// Parsed and validated `extensions["previewSign5"]` input map.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PreviewSign5Input {
    pub kh: Option<Vec<u8>>,
    pub alg: Option<Vec<i64>>,
    pub flags: Option<u8>,
    pub tbs: Option<Vec<u8>>,
    pub args: Option<Vec<u8>>,
    pub support: bool,
}

impl PreviewSign5Input {
    /// Parses and validates `extensions["previewSign5"]` according to the CDDL and processing steps.
    pub fn try_from_cbor(cbor_value: cbor::Value, is_make_credential: bool) -> CtapResult<Self> {
        let map = extract_map(cbor_value)?;
        if map.is_empty() {
            return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        let mut kh: Option<Vec<u8>> = None;
        let mut alg: Option<Vec<i64>> = None;
        let mut flags: Option<u8> = None;
        let mut tbs: Option<Vec<u8>> = None;
        let mut args: Option<Vec<u8>> = None;
        let mut support = false;

        for (k, v) in map {
            let key_int =
                extract_integer(k).map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
            match key_int {
                KEY_KH => {
                    let bytes = extract_byte_string(v)
                        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
                    kh = Some(bytes);
                }
                KEY_ALG => {
                    let arr = extract_array(v)
                        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
                    if arr.is_empty() {
                        return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }
                    let mut algs = Vec::with_capacity(arr.len());
                    for item in arr {
                        let a = extract_integer(item)
                            .map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
                        algs.push(a);
                    }
                    alg = Some(algs);
                }
                KEY_FLAGS => {
                    let f = extract_unsigned(v)
                        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
                    if !is_valid_sign_flags(f) {
                        return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }
                    flags = Some(f as u8);
                }
                KEY_TBS => {
                    let bytes = extract_byte_string(v)
                        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
                    tbs = Some(bytes);
                }
                KEY_ARGS => {
                    let bytes = extract_byte_string(v)
                        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
                    args = Some(bytes);
                }
                KEY_SUPPORT => {
                    let b = extract_bool(v)
                        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)?;
                    if !b {
                        return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                    }
                    support = true;
                }
                _ => return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            }
        }

        // Validate input field combinations per § 10.2.1:
        // - extInput[flags] is present and extInput[alg] is not present -> CBOR_UNEXPECTED_TYPE
        if flags.is_some() && alg.is_none() {
            return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        // - At least one of kh, tbs, args is present and at least one of kh or tbs is not present -> CBOR_UNEXPECTED_TYPE
        if (kh.is_some() || tbs.is_some() || args.is_some()) && (kh.is_none() || tbs.is_none()) {
            return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        // - alg is present and at least one of kh, tbs, args is present -> CBOR_UNEXPECTED_TYPE
        if alg.is_some() && (kh.is_some() || tbs.is_some() || args.is_some()) {
            return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        // - Must have at least one of support, alg, or (kh && tbs)
        if alg.is_none() && kh.is_none() && !support {
            return Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }
        // - If extInput[kh] is present and the current operation is not authenticatorGetAssertion -> INVALID_OPTION
        if kh.is_some() && is_make_credential {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
        }

        Ok(Self {
            kh,
            alg,
            flags,
            tbs,
            args,
            support,
        })
    }
}

/// Output of `previewSign5` processing to be included in `authData.extensions` and `unsignedExtensionOutputs`.
pub struct PreviewSign5ProcessedOutput {
    /// Value for `authData.extensions["previewSign5"]`.
    pub signed_output: cbor::Value,
    /// Optional value for `unsignedExtensionOutputs["previewSign5"]` (map `{ 7: att_obj_bytes }`).
    pub unsigned_output: Option<cbor::Value>,
}

/// Builds the `previewSignSupport` CBOR array (`[parent-algorithms, algorithms]`).
pub fn build_support_value() -> cbor::Value {
    let parent_algs: Vec<cbor::Value> = SUPPORTED_CRED_PARAMS
        .iter()
        .map(|p| cbor::Value::from(p.alg as i64))
        .collect();
    let child_algs: Vec<cbor::Value> = SUPPORTED_PREVIEW_SIGN_ALGS
        .iter()
        .map(|&a| cbor::Value::from(a))
        .collect();
    cbor_array![
        cbor::Value::array(parent_algs),
        cbor::Value::array(child_algs),
    ]
}

/// Derives the 32-byte per-credential secret and 32-byte MAC key for `previewSign5` from the parent credential's private key.
fn derive_credential_secrets<E: Env>(
    env: &mut E,
    parent_private_key: &PrivateKey<E>,
) -> CtapResult<([u8; HASH_SIZE], [u8; HASH_SIZE])> {
    let key_bytes = parent_private_key.export();
    let salt = Sha::<E>::digest(&key_bytes);
    let base_key = env
        .key_store()
        .cred_random(false)
        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
    let mut cred_secret = [0u8; HASH_SIZE];
    Hkdf::<E>::hkdf_256(&*base_key, &salt, b"previewSign5-credSecret", &mut cred_secret);
    let mut mac_key = [0u8; HASH_SIZE];
    Hkdf::<E>::hkdf_empty_salt_256(&cred_secret, b"previewSign5-macKey", &mut mac_key);
    Ok((cred_secret, mac_key))
}

/// Encodes `khParams = [chosenAlg, signFlags, auxIkm]` and prepends `khMac = HMAC-SHA-256(macKey, khParams || ext_id || rpIdHash)`.
fn encode_key_handle<E: Env>(
    mac_key: &[u8; HASH_SIZE],
    chosen_alg: i64,
    sign_flags: u8,
    aux_ikm: &[u8; 32],
    rp_id_hash: &[u8; 32],
    ext_id: &str,
) -> CtapResult<(Vec<u8>, Vec<u8>)> {
    let kh_params_val = cbor_array![
        cbor_int!(chosen_alg),
        cbor_int!(sign_flags as i64),
        cbor_bytes!(aux_ikm.to_vec()),
    ];
    let mut kh_params = Vec::new();
    cbor_write(kh_params_val, &mut kh_params)?;

    let mut mac_input = Vec::with_capacity(kh_params.len() + ext_id.len() + 32);
    mac_input.extend_from_slice(&kh_params);
    mac_input.extend_from_slice(ext_id.as_bytes());
    mac_input.extend_from_slice(rp_id_hash);

    let mut kh_mac = [0u8; HASH_SIZE];
    Hmac::<E>::mac(mac_key, &mac_input, &mut kh_mac);

    let mut kh = Vec::with_capacity(HASH_SIZE + kh_params.len());
    kh.extend_from_slice(&kh_mac);
    kh.extend_from_slice(&kh_params);
    Ok((kh, kh_params))
}

/// Verifies `kh` MAC and decodes `khParams = [chosenAlg, signFlags, auxIkm]`.
fn decode_key_handle<E: Env>(
    mac_key: &[u8; HASH_SIZE],
    kh: &[u8],
    rp_id_hash: &[u8; 32],
    ext_id: &str,
) -> Option<(i64, u8, [u8; 32], Vec<u8>)> {
    if kh.len() <= HASH_SIZE {
        return None;
    }
    let mac = array_ref![kh, 0, HASH_SIZE];
    let kh_params = &kh[HASH_SIZE..];

    let mut mac_input = Vec::with_capacity(kh_params.len() + ext_id.len() + 32);
    mac_input.extend_from_slice(kh_params);
    mac_input.extend_from_slice(ext_id.as_bytes());
    mac_input.extend_from_slice(rp_id_hash);

    if !Hmac::<E>::verify(mac_key, &mac_input, mac) {
        return None;
    }

    let cbor_val = cbor_read(kh_params).ok()?;
    let mut arr = extract_array(cbor_val).ok()?;
    if arr.len() != 3 {
        return None;
    }
    let aux_ikm_vec = extract_byte_string(arr.pop()?).ok()?;
    let sign_flags_u64 = extract_unsigned(arr.pop()?).ok()?;
    let chosen_alg = extract_integer(arr.pop()?).ok()?;

    if !SUPPORTED_PREVIEW_SIGN_ALGS.contains(&chosen_alg)
        || !is_valid_sign_flags(sign_flags_u64)
        || aux_ikm_vec.len() != 32
    {
        return None;
    }
    let mut aux_ikm = [0u8; 32];
    aux_ikm.copy_from_slice(&aux_ikm_vec);
    Some((chosen_alg, sign_flags_u64 as u8, aux_ikm, kh_params.to_vec()))
}

/// Derives an ECDSA P-256 signing key from `(cred_secret, aux_ikm, kh_params)`.
fn derive_p256_signing_key<E: Env>(
    cred_secret: &[u8; HASH_SIZE],
    aux_ikm: &[u8; 32],
    kh_params: &[u8],
) -> Option<EcdsaSk<E>> {
    let mut ikm = [0u8; HASH_SIZE];
    Hkdf::<E>::hkdf_256(cred_secret, aux_ikm, kh_params, &mut ikm);
    let mut scalar = arkg::hash_to_field::<Sha<E>>(&ikm, b"previewSign5-ECDSA-P256");
    ikm.zeroize();
    let sk = EcdsaSk::<E>::import(&scalar);
    scalar.zeroize();
    sk
}

/// Derives an `ARKG-P256` seed from `(cred_secret, aux_ikm, kh_params)`.
fn derive_arkg_seed<E: Env>(
    cred_secret: &[u8; HASH_SIZE],
    aux_ikm: &[u8; 32],
    kh_params: &[u8],
) -> Option<ArkgSeed> {
    let mut info_bl = Vec::with_capacity(24 + kh_params.len());
    info_bl.extend_from_slice(b"previewSign5-arkg-bl:");
    info_bl.extend_from_slice(kh_params);

    let mut info_kem = Vec::with_capacity(25 + kh_params.len());
    info_kem.extend_from_slice(b"previewSign5-arkg-kem:");
    info_kem.extend_from_slice(kh_params);

    let mut ikm_bl = [0u8; HASH_SIZE];
    let mut ikm_kem = [0u8; HASH_SIZE];
    Hkdf::<E>::hkdf_256(cred_secret, aux_ikm, &info_bl, &mut ikm_bl);
    Hkdf::<E>::hkdf_256(cred_secret, aux_ikm, &info_kem, &mut ikm_kem);

    let seed = ArkgSeed::derive::<E>(&ikm_bl, &ikm_kem);
    ikm_bl.zeroize();
    ikm_kem.zeroize();
    seed
}

/// Generates the inner `att-obj` CBOR bytes (`{ 1: fmt, 2: authData, 3: attStmt }`) for a generated signing key.
#[allow(clippy::too_many_arguments)]
fn build_signing_key_att_obj<E: Env>(
    env: &mut E,
    rp_id_hash: &[u8; 32],
    outer_flags: u8,
    kh: &[u8],
    public_cose_key_cbor: cbor::Value,
    sign_flags: u8,
    client_data_hash: &[u8],
    self_attestation_key: Option<(&EcdsaSk<E>, i64)>,
    selected_format: Option<SelectedAttestationFormat>,
    ep_att: bool,
    ext_id: &str,
) -> CtapResult<Vec<u8>> {
    let aaguid = env.persist().aaguid()?;
    let inner_flags = outer_flags | AT_FLAG | ED_FLAG;
    let kh_len = kh.len() as u16;

    let mut inner_auth_data = Vec::with_capacity(37 + 16 + 2 + kh.len() + 128);
    inner_auth_data.extend_from_slice(rp_id_hash);
    inner_auth_data.push(inner_flags);
    inner_auth_data.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]); // signCount = 0
    inner_auth_data.extend_from_slice(&aaguid);
    inner_auth_data.extend_from_slice(&kh_len.to_be_bytes());
    inner_auth_data.extend_from_slice(kh);
    cbor_write(public_cose_key_cbor, &mut inner_auth_data)?;

    let inner_ext = cbor_map! {
        ext_id => cbor_map! {
            KEY_FLAGS => sign_flags as u64,
        },
    };
    cbor_write(inner_ext, &mut inner_auth_data)?;

    let attestation = if ep_att {
        Some(
            env.persist()
                .get_attestation(AttestationId::Enterprise)?
                .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
        )
    } else if env.customization().use_batch_attestation() {
        env.persist()
            .get_attestation(AttestationId::Batch)?
            .filter(|att| !att.certificate.is_empty())
    } else {
        None
    };
    let mtc_att = attestation
        .as_ref()
        .and_then(|att| mtc::ProvisionedMtcAttestation::from_bytes(&att.certificate));

    let resolved_format = match selected_format {
        Some(fmt) => fmt,
        None => match mtc_att.as_ref() {
            Some(active_mtc) => {
                let use_classical_packed = !ep_att
                    && active_mtc.classical_key.is_some()
                    && active_mtc.classical_x5c.is_some();
                let use_tier1_packed = active_mtc.x5c.is_some();
                if use_classical_packed || use_tier1_packed {
                    SelectedAttestationFormat::Packed
                } else {
                    SelectedAttestationFormat::Mtc
                }
            }
            None => SelectedAttestationFormat::Packed,
        },
    };

    let mut sig_data = inner_auth_data.clone();
    sig_data.extend_from_slice(client_data_hash);

    let (fmt, att_stmt) = match resolved_format {
        SelectedAttestationFormat::NoneFormat => (
            String::from("none"),
            PackedAttestationStatement {
                alg: 0,
                sig: Vec::new(),
                x5c: None,
                ecdaa_key_id: None,
                pub_key: None,
                mtc_cert: None,
            },
        ),
        SelectedAttestationFormat::Mtc => {
            let Attestation {
                wrapped_private_key,
                ..
            } = attestation.ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
            let mtc_att = mtc_att.ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
            let att_key = PrivateKey::<E>::from_attestation_bytes(&wrapped_private_key)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
            let alg = att_key.signature_algorithm() as i64;
            let sig = att_key.sign_and_encode(&sig_data)?;
            let wire_mtc_cert = mtc_att.cert.to_key_ref();
            (
                String::from(mtc::MTC_FORMAT_STR),
                PackedAttestationStatement {
                    alg,
                    sig,
                    x5c: None,
                    ecdaa_key_id: None,
                    pub_key: None,
                    mtc_cert: Some(wire_mtc_cert),
                },
            )
        }
        SelectedAttestationFormat::Packed => match (attestation, mtc_att, self_attestation_key) {
            (
                Some(Attestation {
                    wrapped_private_key,
                    certificate,
                }),
                None,
                _,
            ) => {
                let att_key = PrivateKey::<E>::from_attestation_bytes(&wrapped_private_key)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                (
                    String::from("packed"),
                    PackedAttestationStatement {
                        alg: att_key.signature_algorithm() as i64,
                        sig: att_key.sign_and_encode(&sig_data)?,
                        x5c: Some(vec![certificate]),
                        ecdaa_key_id: None,
                        pub_key: None,
                        mtc_cert: None,
                    },
                )
            }
            (
                Some(_),
                Some(mtc::ProvisionedMtcAttestation {
                    classical_key: Some(c_key),
                    classical_x5c: Some(c_x5c),
                    ..
                }),
                _,
            ) if !ep_att => {
                let c_att_key = PrivateKey::<E>::from_attestation_bytes(&c_key)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                (
                    String::from("packed"),
                    PackedAttestationStatement {
                        alg: c_att_key.signature_algorithm() as i64,
                        sig: c_att_key.sign_and_encode(&sig_data)?,
                        x5c: Some(vec![c_x5c]),
                        ecdaa_key_id: None,
                        pub_key: None,
                        mtc_cert: None,
                    },
                )
            }
            (
                Some(Attestation {
                    wrapped_private_key,
                    ..
                }),
                Some(mtc::ProvisionedMtcAttestation {
                    x5c: Some(x5c_der), ..
                }),
                _,
            ) => {
                let att_key = PrivateKey::<E>::from_attestation_bytes(&wrapped_private_key)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                (
                    String::from("packed"),
                    PackedAttestationStatement {
                        alg: att_key.signature_algorithm() as i64,
                        sig: att_key.sign_and_encode(&sig_data)?,
                        x5c: Some(vec![x5c_der]),
                        ecdaa_key_id: None,
                        pub_key: None,
                        mtc_cert: None,
                    },
                )
            }
            (_, _, Some((child_sk, cose_key_alg))) => (
                String::from("packed"),
                PackedAttestationStatement {
                    alg: cose_key_alg,
                    sig: child_sk.sign(&sig_data).to_der(),
                    x5c: None,
                    ecdaa_key_id: None,
                    pub_key: None,
                    mtc_cert: None,
                },
            ),
            (_, _, None) => (
                String::from("none"),
                PackedAttestationStatement {
                    alg: 0,
                    sig: Vec::new(),
                    x5c: None,
                    ecdaa_key_id: None,
                    pub_key: None,
                    mtc_cert: None,
                },
            ),
        },
    };

    let att_obj_int = cbor_map! {
        1 => fmt,
        2 => inner_auth_data,
        3 => cbor::Value::from(att_stmt),
    };
    let mut att_obj_bytes = Vec::new();
    cbor_write(att_obj_int, &mut att_obj_bytes)?;
    Ok(att_obj_bytes)
}

/// Processes `previewSign5` extension input for `authenticatorMakeCredential` or `authenticatorGetAssertion`.
#[allow(clippy::too_many_arguments)]
pub fn process_preview_sign_5<E: Env>(
    env: &mut E,
    input: &PreviewSign5Input,
    rp_id_hash: &[u8; 32],
    outer_flags: u8,
    client_data_hash: &[u8],
    parent_private_key: &PrivateKey<E>,
    selected_format: Option<SelectedAttestationFormat>,
    ep_att: bool,
) -> CtapResult<PreviewSign5ProcessedOutput> {
    let (mut cred_secret, mut mac_key) = derive_credential_secrets(env, parent_private_key)?;

    // 1. Key Generation (`alg` is present)
    if let Some(ref candidate_algs) = input.alg {
        let chosen_alg = candidate_algs
            .iter()
            .copied()
            .find(|alg| SUPPORTED_PREVIEW_SIGN_ALGS.contains(alg));

        let Some(chosen_alg) = chosen_alg else {
            cred_secret.zeroize();
            mac_key.zeroize();
            let support_val = build_support_value();
            return Ok(PreviewSign5ProcessedOutput {
                signed_output: cbor_map! {
                    KEY_ERR => ERR_UNSUPPORTED_ALGORITHM,
                    KEY_SUPPORT => support_val,
                },
                unsigned_output: None,
            });
        };

        let sign_flags = input.flags.unwrap_or(FLAG_REQUIRE_UP);
        let aux_ikm = env.rng().gen_uniform_u8x32();
        let (kh, kh_params) = encode_key_handle::<E>(
            &mac_key,
            chosen_alg,
            sign_flags,
            &aux_ikm,
            rp_id_hash,
            PREVIEW_SIGN_5_EXT_ID,
        )?;

        let (public_cose_key_cbor, child_signing_key) =
            if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG {
                let seed = derive_arkg_seed::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                (seed.to_cose_key_cbor(), None)
            } else {
                let sk = derive_p256_signing_key::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let pk = sk.public_key();
                let mut x = [0u8; EC_FIELD_SIZE];
                let mut y = [0u8; EC_FIELD_SIZE];
                pk.to_coordinates(&mut x, &mut y);
                // Per § 10.2.1: for split algorithms (`-300`, `-70009`), the `alg` (3) attribute of
                // `publicKey` identifies the corresponding verification procedure (`-9` `ESP256`).
                let cose_key_alg = if chosen_alg == COSE_ALG_ES256 {
                    COSE_ALG_ES256
                } else {
                    COSE_ALG_ESP256
                };
                let cose_key = cbor_map! {
                    1 => 2,
                    3 => cose_key_alg,
                    -1 => 1,
                    -2 => x.to_vec(),
                    -3 => y.to_vec(),
                };
                (cose_key, Some((sk, cose_key_alg)))
            };

        cred_secret.zeroize();
        mac_key.zeroize();

        let self_att_key = child_signing_key.as_ref().map(|(sk, alg)| (sk, *alg));
        let att_obj_bytes = build_signing_key_att_obj(
            env,
            rp_id_hash,
            outer_flags,
            &kh,
            public_cose_key_cbor,
            sign_flags,
            client_data_hash,
            self_att_key,
            selected_format,
            ep_att,
            PREVIEW_SIGN_5_EXT_ID,
        )?;

        let support_opt = if input.support {
            Some(build_support_value())
        } else {
            None
        };
        let signed_output = cbor_map_options! {
            KEY_ALG => chosen_alg,
            KEY_SUPPORT => support_opt,
        };
        let unsigned_output = Some(cbor_map! {
            KEY_ATT_OBJ => att_obj_bytes,
        });
        return Ok(PreviewSign5ProcessedOutput {
            signed_output,
            unsigned_output,
        });
    }

    // 2. Signing (`kh` and `tbs` are present)
    if let (Some(kh), Some(tbs)) = (&input.kh, &input.tbs) {
        let support_opt = if input.support {
            Some(build_support_value())
        } else {
            None
        };

        let Some((chosen_alg, sign_flags, aux_ikm, kh_params)) =
            decode_key_handle::<E>(&mac_key, kh, rp_id_hash, PREVIEW_SIGN_5_EXT_ID)
        else {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Ok(PreviewSign5ProcessedOutput {
                signed_output: cbor_map_options! {
                    KEY_ERR => ERR_INVALID_KEY_HANDLE,
                    KEY_SUPPORT => support_opt,
                },
                unsigned_output: None,
            });
        };

        // Validate `args` (`COSE_Sign_Args`) before checking UP/UV flags per § 10.2.1.
        let mut arkg_params: Option<(Vec<u8>, Vec<u8>)> = None;
        if let Some(ref args_bytes) = input.args {
            let Ok(args_cbor) = cbor_read(args_bytes) else {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Ok(PreviewSign5ProcessedOutput {
                    signed_output: cbor_map_options! {
                        KEY_ERR => ERR_COSE_SIGN_ARGS_INVALID,
                        KEY_SUPPORT => support_opt,
                    },
                    unsigned_output: None,
                });
            };
            let Ok(args_map) = extract_map(args_cbor) else {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Ok(PreviewSign5ProcessedOutput {
                    signed_output: cbor_map_options! {
                        KEY_ERR => ERR_COSE_SIGN_ARGS_INVALID,
                        KEY_SUPPORT => support_opt,
                    },
                    unsigned_output: None,
                });
            };

            let mut args_alg: Option<i64> = None;
            let mut kh_arkg: Option<Vec<u8>> = None;
            let mut ctx_arkg: Option<Vec<u8>> = None;
            let mut has_unknown_param = false;
            let mut has_invalid_type = false;

            for (k, v) in args_map {
                let Ok(k_int) = extract_integer(k) else {
                    has_unknown_param = true;
                    continue;
                };
                match k_int {
                    3 => {
                        if let Ok(a) = extract_integer(v) {
                            args_alg = Some(a);
                        } else {
                            has_invalid_type = true;
                        }
                    }
                    -1 if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG => {
                        if let Ok(b) = extract_byte_string(v) {
                            kh_arkg = Some(b);
                        } else {
                            has_invalid_type = true;
                        }
                    }
                    -2 if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG => {
                        if let Ok(b) = extract_byte_string(v) {
                            ctx_arkg = Some(b);
                        } else {
                            has_invalid_type = true;
                        }
                    }
                    _ => {
                        has_unknown_param = true;
                    }
                }
            }

            // 1. Decode `args` as `COSE_Sign_Args` (validate field types).
            if has_invalid_type {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Ok(PreviewSign5ProcessedOutput {
                    signed_output: cbor_map_options! {
                        KEY_ERR => ERR_COSE_SIGN_ARGS_INVALID,
                        KEY_SUPPORT => support_opt,
                    },
                    unsigned_output: None,
                });
            }
            // 2. Check `args[alg]` is present and equals `chosenAlg`.
            if args_alg != Some(chosen_alg) {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Ok(PreviewSign5ProcessedOutput {
                    signed_output: cbor_map_options! {
                        KEY_ERR => ERR_COSE_SIGN_ARGS_ALG_MISMATCH,
                        KEY_SUPPORT => support_opt,
                    },
                    unsigned_output: None,
                });
            }
            // 3. Check that all required algorithm arguments are present.
            if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG {
                let (Some(kh_b), Some(ctx_b)) = (kh_arkg, ctx_arkg) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Ok(PreviewSign5ProcessedOutput {
                        signed_output: cbor_map_options! {
                            KEY_ERR => ERR_COSE_SIGN_ARGS_MISSING_PARAM,
                            KEY_SUPPORT => support_opt,
                        },
                        unsigned_output: None,
                    });
                };
                arkg_params = Some((kh_b, ctx_b));
            }
            // 4. Check for unknown or inapplicable parameters.
            if has_unknown_param {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Ok(PreviewSign5ProcessedOutput {
                    signed_output: cbor_map_options! {
                        KEY_ERR => ERR_COSE_SIGN_ARGS_UNKNOWN_PARAM,
                        KEY_SUPPORT => support_opt,
                    },
                    unsigned_output: None,
                });
            }
        } else if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Ok(PreviewSign5ProcessedOutput {
                signed_output: cbor_map_options! {
                    KEY_ERR => ERR_COSE_SIGN_ARGS_MISSING_PARAM,
                    KEY_SUPPORT => support_opt,
                },
                unsigned_output: None,
            });
        }

        // Check `signFlags` against `authData.flags` per § 10.2.1:
        // 1. If the UP bit is set in signFlags but not in authData.flags -> CTAP2_ERR_UP_REQUIRED.
        if (sign_flags & FLAG_REQUIRE_UP) != 0 && (outer_flags & UP_FLAG) == 0 {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Err(Ctap2StatusCode::CTAP2_ERR_UP_REQUIRED);
        }
        // 2. If the UV bit is set in signFlags but not in authData.flags -> CTAP2_ERR_PUAT_REQUIRED.
        if (sign_flags & FLAG_REQUIRE_UV) != 0 && (outer_flags & UV_FLAG) == 0 {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
        }

        let sig = match chosen_alg {
            COSE_ALG_ESP256 | COSE_ALG_ES256 => {
                let sk = derive_p256_signing_key::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                sk.sign(tbs).to_der()
            }
            COSE_ALG_ESP256_SPLIT | COSE_ALG_ESP256_SPLIT_PLACEHOLDER => {
                // Per draft-ietf-cose-split-signing-algs-01 § 2.1, the digester performs Step 1
                // (SHA-256 hashing) and passes the 32-octet digest H as `tbs`; the signer resumes
                // from Step 2 and MUST NOT re-hash non-32-octet inputs.
                let Ok(prehash) = <&[u8; HASH_SIZE]>::try_from(tbs.as_slice()) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH);
                };
                let sk = derive_p256_signing_key::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                sk.sign_prehash(prehash).to_der()
            }
            COSE_ALG_ESP256_SPLIT_ARKG => {
                let Ok(prehash) = <&[u8; HASH_SIZE]>::try_from(tbs.as_slice()) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH);
                };
                let (kh_arkg, ctx_arkg) = arkg_params.unwrap();
                let seed = derive_arkg_seed::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let Some(sig) = arkg::derive_and_sign_prehash::<E>(
                    &seed.sk_bl,
                    &seed.sk_kem,
                    &kh_arkg,
                    &ctx_arkg,
                    prehash,
                ) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Ok(PreviewSign5ProcessedOutput {
                        signed_output: cbor_map_options! {
                            KEY_ERR => ERR_COSE_SIGN_ARGS_INVALID,
                            KEY_SUPPORT => support_opt,
                        },
                        unsigned_output: None,
                    });
                };
                sig
            }
            _ => unreachable!(),
        };

        cred_secret.zeroize();
        mac_key.zeroize();

        return Ok(PreviewSign5ProcessedOutput {
            signed_output: cbor_map_options! {
                KEY_SIG => sig,
                KEY_SUPPORT => support_opt,
            },
            unsigned_output: None,
        });
    }

    // 3. Support-only inquiry (`support: true` without `alg` or `kh`/`tbs`)
    cred_secret.zeroize();
    mac_key.zeroize();
    Ok(PreviewSign5ProcessedOutput {
        signed_output: cbor_map! {
            KEY_SUPPORT => build_support_value(),
        },
        unsigned_output: None,
    })
}

/// Processes `previewSign` (v4, YubiKey 5.8) extension input for `authenticatorMakeCredential` or `authenticatorGetAssertion`.
#[allow(clippy::too_many_arguments)]
pub fn process_preview_sign_4<E: Env>(
    env: &mut E,
    input: &PreviewSign4Input,
    rp_id_hash: &[u8; 32],
    outer_flags: u8,
    client_data_hash: &[u8],
    parent_private_key: &PrivateKey<E>,
    selected_format: Option<SelectedAttestationFormat>,
    ep_att: bool,
) -> CtapResult<PreviewSign5ProcessedOutput> {
    let (mut cred_secret, mut mac_key) = derive_credential_secrets(env, parent_private_key)?;

    // 1. Key Generation (`alg` is present in `makeCredential`)
    if let Some(ref candidate_algs) = input.alg {
        let chosen_alg = candidate_algs
            .iter()
            .copied()
            .find(|alg| SUPPORTED_PREVIEW_SIGN_ALGS.contains(alg));

        let Some(chosen_alg) = chosen_alg else {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        };

        let sign_flags = input.flags.unwrap_or(FLAG_REQUIRE_UP);
        let aux_ikm = env.rng().gen_uniform_u8x32();
        let (kh, kh_params) = encode_key_handle::<E>(
            &mac_key,
            chosen_alg,
            sign_flags,
            &aux_ikm,
            rp_id_hash,
            PREVIEW_SIGN_4_EXT_ID,
        )?;

        let (public_cose_key_cbor, child_signing_key) =
            if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG {
                let seed = derive_arkg_seed::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                (seed.to_cose_key_cbor(), None)
            } else {
                let sk = derive_p256_signing_key::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let pk = sk.public_key();
                let mut x = [0u8; EC_FIELD_SIZE];
                let mut y = [0u8; EC_FIELD_SIZE];
                pk.to_coordinates(&mut x, &mut y);
                let cose_key_alg = if chosen_alg == COSE_ALG_ES256 {
                    COSE_ALG_ES256
                } else {
                    COSE_ALG_ESP256
                };
                let cose_key = cbor_map! {
                    1 => 2,
                    3 => cose_key_alg,
                    -1 => 1,
                    -2 => x.to_vec(),
                    -3 => y.to_vec(),
                };
                (cose_key, Some((sk, cose_key_alg)))
            };

        cred_secret.zeroize();
        mac_key.zeroize();

        let self_att_key = child_signing_key.as_ref().map(|(sk, alg)| (sk, *alg));
        let att_obj_bytes = build_signing_key_att_obj(
            env,
            rp_id_hash,
            outer_flags,
            &kh,
            public_cose_key_cbor,
            sign_flags,
            client_data_hash,
            self_att_key,
            selected_format,
            ep_att,
            PREVIEW_SIGN_4_EXT_ID,
        )?;

        return Ok(PreviewSign5ProcessedOutput {
            signed_output: cbor_map! {
                KEY_ALG => chosen_alg,
            },
            unsigned_output: Some(cbor_map! {
                KEY_ATT_OBJ => att_obj_bytes,
            }),
        });
    }

    // 2. Signing (`kh` and `tbs` are present in `getAssertion`)
    if let (Some(kh), Some(tbs)) = (&input.kh, &input.tbs) {
        let Some((chosen_alg, sign_flags, aux_ikm, kh_params)) =
            decode_key_handle::<E>(&mac_key, kh, rp_id_hash, PREVIEW_SIGN_4_EXT_ID)
        else {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
        };

        let mut arkg_params: Option<(Vec<u8>, Vec<u8>)> = None;
        if let Some(ref args_bytes) = input.args {
            let Ok(args_cbor) = cbor_read(args_bytes) else {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
            };
            let Ok(args_map) = extract_map(args_cbor) else {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
            };

            let mut args_alg: Option<i64> = None;
            let mut kh_arkg: Option<Vec<u8>> = None;
            let mut ctx_arkg: Option<Vec<u8>> = None;

            for (k, v) in args_map {
                let Ok(k_int) = extract_integer(k) else {
                    continue;
                };
                match k_int {
                    3 => {
                        let Ok(a) = extract_integer(v) else {
                            cred_secret.zeroize();
                            mac_key.zeroize();
                            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
                        };
                        args_alg = Some(a);
                    }
                    -1 if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG => {
                        let Ok(b) = extract_byte_string(v) else {
                            cred_secret.zeroize();
                            mac_key.zeroize();
                            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
                        };
                        kh_arkg = Some(b);
                    }
                    -2 if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG => {
                        let Ok(b) = extract_byte_string(v) else {
                            cred_secret.zeroize();
                            mac_key.zeroize();
                            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
                        };
                        ctx_arkg = Some(b);
                    }
                    _ => {}
                }
            }

            if args_alg != Some(chosen_alg) {
                cred_secret.zeroize();
                mac_key.zeroize();
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
            }

            if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG {
                let (Some(kh_b), Some(ctx_b)) = (kh_arkg, ctx_arkg) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER);
                };
                arkg_params = Some((kh_b, ctx_b));
            }
        } else if chosen_alg == COSE_ALG_ESP256_SPLIT_ARKG {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER);
        }

        if (sign_flags & FLAG_REQUIRE_UP) != 0 && (outer_flags & UP_FLAG) == 0 {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Err(Ctap2StatusCode::CTAP2_ERR_UP_REQUIRED);
        }
        if (sign_flags & FLAG_REQUIRE_UV) != 0 && (outer_flags & UV_FLAG) == 0 {
            cred_secret.zeroize();
            mac_key.zeroize();
            return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
        }

        let sig = match chosen_alg {
            COSE_ALG_ESP256 | COSE_ALG_ES256 => {
                let sk = derive_p256_signing_key::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                sk.sign(tbs).to_der()
            }
            COSE_ALG_ESP256_SPLIT | COSE_ALG_ESP256_SPLIT_PLACEHOLDER => {
                let Ok(prehash) = <&[u8; HASH_SIZE]>::try_from(tbs.as_slice()) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH);
                };
                let sk = derive_p256_signing_key::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                sk.sign_prehash(prehash).to_der()
            }
            COSE_ALG_ESP256_SPLIT_ARKG => {
                let Ok(prehash) = <&[u8; HASH_SIZE]>::try_from(tbs.as_slice()) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH);
                };
                let (kh_arkg, ctx_arkg) = arkg_params.unwrap();
                let seed = derive_arkg_seed::<E>(&cred_secret, &aux_ikm, &kh_params)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let Some(sig) = arkg::derive_and_sign_prehash::<E>(
                    &seed.sk_bl,
                    &seed.sk_kem,
                    &kh_arkg,
                    &ctx_arkg,
                    prehash,
                ) else {
                    cred_secret.zeroize();
                    mac_key.zeroize();
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL);
                };
                sig
            }
            _ => unreachable!(),
        };

        cred_secret.zeroize();
        mac_key.zeroize();

        return Ok(PreviewSign5ProcessedOutput {
            signed_output: cbor_map! {
                KEY_SIG => sig,
            },
            unsigned_output: None,
        });
    }

    cred_secret.zeroize();
    mac_key.zeroize();
    Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::crypto::ecdh::{PublicKey as _, SecretKey as _, SharedSecret as _};
    use crate::ctap::command::{
        AuthenticatorGetAssertionParameters, AuthenticatorMakeCredentialParameters,
    };
    use crate::ctap::data_formats::{
        GetAssertionExtensions, GetAssertionOptions, MakeCredentialExtensions,
        MakeCredentialOptions, PinUvAuthProtocol, PublicKeyCredentialDescriptor,
        PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
    };
    use crate::ctap::response::ResponseData;
    use crate::ctap::{Channel, CtapState, ES256_CRED_PARAM};
    use crate::env::test::TestEnv;
    use crate::env::{EcdhPk, EcdhSk};

    const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);

    /// Helper to parse `authData` and extract `(credential_id, extensions_cbor_map)`.
    fn parse_auth_data_extensions(auth_data: &[u8]) -> (Option<Vec<u8>>, cbor::Value) {
        let flags = auth_data[32];
        let mut offset = 37;
        if (flags & AT_FLAG) != 0 {
            offset += 16; // aaguid
            let cred_id_len = u16::from_be_bytes([auth_data[offset], auth_data[offset + 1]]) as usize;
            offset += 2;
            let cred_id = Some(auth_data[offset..offset + cred_id_len].to_vec());
            offset += cred_id_len;
            // Skip public key CBOR by finding where extensions map starts
            // Read COSE key by trying slices until `cbor_read` succeeds on both COSE key and extensions
            for split in (offset + 1)..auth_data.len() {
                if cbor_read(&auth_data[offset..split]).is_ok()
                    && let Ok(ext_val) = cbor_read(&auth_data[split..])
                {
                    return (cred_id, ext_val);
                }
            }
            panic!("Failed to split COSE_Key and extensions in attested authData");
        } else {
            let ext_val = cbor_read(&auth_data[offset..]).unwrap();
            (None, ext_val)
        }
    }

    /// Helper to parse `att-obj` CBOR bytes (`{ 1: fmt, 2: authData, 3: attStmt }`) and extract `(kh, public_cose_key_map, inner_flags)`.
    fn parse_signing_key_att_obj(att_obj_bytes: &[u8]) -> (Vec<u8>, Vec<(cbor::Value, cbor::Value)>, u8) {
        let att_obj_map = extract_map(cbor_read(att_obj_bytes).unwrap()).unwrap();
        let mut auth_data = Vec::new();
        for (k, v) in att_obj_map {
            if extract_integer(k).unwrap() == 2 {
                auth_data = extract_byte_string(v).unwrap();
            }
        }
        assert!(auth_data.len() > 55);
        let kh_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let kh = auth_data[55..55 + kh_len].to_vec();
        let offset = 55 + kh_len;
        for split in (offset + 1)..auth_data.len() {
            if let Ok(pk_val) = cbor_read(&auth_data[offset..split])
                && let Ok(ext_val) = cbor_read(&auth_data[split..])
            {
                let pk_map = extract_map(pk_val).unwrap();
                let ext_map = extract_map(ext_val).unwrap();
                let ps5_map = extract_map(ext_map[0].1.clone()).unwrap();
                let sign_flags = extract_unsigned(ps5_map[0].1.clone()).unwrap() as u8;
                return (kh, pk_map, sign_flags);
            }
        }
        panic!("Failed to parse signing key att-obj authData");
    }

    fn make_cred_with_ps5(
        ctap_state: &mut CtapState<TestEnv>,
        env: &mut TestEnv,
        ps5_cbor: cbor::Value,
    ) -> CtapResult<ResponseData> {
        let ps5_input = PreviewSign5Input::try_from_cbor(ps5_cbor, true)?;
        let params = AuthenticatorMakeCredentialParameters {
            client_data_hash: vec![0xCD; 32],
            rp: PublicKeyCredentialRpEntity {
                rp_id: String::from("example.com"),
                rp_name: None,
                rp_icon: None,
            },
            user: PublicKeyCredentialUserEntity {
                user_id: vec![0x1D; 16],
                user_name: None,
                user_display_name: None,
                user_icon: None,
            },
            pub_key_cred_params: vec![ES256_CRED_PARAM],
            exclude_list: None,
            extensions: MakeCredentialExtensions {
                preview_sign_5: Some(ps5_input),
                ..Default::default()
            },
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
            attestation_formats_preference: None,
        };
        ctap_state.process_make_credential(env, params, DUMMY_CHANNEL)
    }

    fn get_assertion_with_ps5(
        ctap_state: &mut CtapState<TestEnv>,
        env: &mut TestEnv,
        cred_id: Vec<u8>,
        ps5_cbor: cbor::Value,
        up: bool,
        pin_uv_auth_param: Option<Vec<u8>>,
        pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    ) -> CtapResult<ResponseData> {
        let ps5_input = PreviewSign5Input::try_from_cbor(ps5_cbor, false)?;
        let params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD; 32],
            allow_list: Some(vec![PublicKeyCredentialDescriptor {
                key_type: PublicKeyCredentialType::PublicKey,
                key_id: cred_id,
                transports: None,
            }]),
            extensions: GetAssertionExtensions {
                preview_sign_5: Some(ps5_input),
                ..Default::default()
            },
            options: GetAssertionOptions { up, uv: false },
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        };
        ctap_state.process_get_assertion(env, params, DUMMY_CHANNEL)
    }

    #[test]
    fn test_preview_sign_5_all_algorithms_keygen_and_sign() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        for &alg in &[
            COSE_ALG_ESP256,
            COSE_ALG_ES256,
            COSE_ALG_ESP256_SPLIT,
            COSE_ALG_ESP256_SPLIT_PLACEHOLDER,
        ] {
            let mc_resp = make_cred_with_ps5(
                &mut ctap_state,
                &mut env,
                cbor_map! {
                    KEY_ALG => cbor_array![alg],
                    KEY_FLAGS => FLAG_UNATTENDED as i64,
                },
            )
            .unwrap();
            let ResponseData::AuthenticatorMakeCredential(mc) = mc_resp else {
                panic!("Expected MakeCredential");
            };
            let (Some(cred_id), ext_val) = parse_auth_data_extensions(&mc.auth_data) else {
                panic!("Missing cred_id");
            };
            let ext_map = extract_map(ext_val).unwrap();
            let ps5_out = extract_map(ext_map[0].1.clone()).unwrap();
            assert_eq!(ps5_out[0], (cbor_int!(KEY_ALG), cbor_int!(alg)));

            let unsigned_map = extract_map(mc.unsigned_extension_outputs.unwrap()).unwrap();
            let ps5_unsigned = extract_map(unsigned_map[0].1.clone()).unwrap();
            let att_obj_bytes = extract_byte_string(ps5_unsigned[0].1.clone()).unwrap();
            let (kh, pk_map, sign_flags) = parse_signing_key_att_obj(&att_obj_bytes);
            assert_eq!(sign_flags, FLAG_UNATTENDED);

            let mut x_vec = Vec::new();
            let mut y_vec = Vec::new();
            let mut pk_alg = 0i64;
            for (k, v) in pk_map {
                match extract_integer(k).unwrap() {
                    3 => pk_alg = extract_integer(v).unwrap(),
                    -2 => x_vec = extract_byte_string(v).unwrap(),
                    -3 => y_vec = extract_byte_string(v).unwrap(),
                    _ => {}
                }
            }
            let expected_pk_alg = if alg == COSE_ALG_ES256 {
                COSE_ALG_ES256
            } else {
                COSE_ALG_ESP256
            };
            assert_eq!(pk_alg, expected_pk_alg);

            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..33].copy_from_slice(&x_vec);
            sec1[33..65].copy_from_slice(&y_vec);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();

            // Verify inner self-attestation (`fmt == "packed"`, `attStmt.alg == expected_pk_alg`,
            // and `attStmt.sig` verifies against the generated public key `vk`).
            let att_obj_map = extract_map(cbor_read(&att_obj_bytes).unwrap()).unwrap();
            assert_eq!(att_obj_map[0].1, sk_cbor::cbor_text!("packed"));
            let inner_auth_data = extract_byte_string(att_obj_map[1].1.clone()).unwrap();
            let att_stmt_map = extract_map(att_obj_map[2].1.clone()).unwrap();
            let mut att_alg = 0i64;
            let mut att_sig = Vec::new();
            for (k, v) in att_stmt_map {
                if k == sk_cbor::cbor_text!("alg") {
                    att_alg = extract_integer(v).unwrap();
                } else if k == sk_cbor::cbor_text!("sig") {
                    att_sig = extract_byte_string(v).unwrap();
                }
            }
            assert_eq!(att_alg, expected_pk_alg);
            let mut att_sig_data = inner_auth_data;
            att_sig_data.extend_from_slice(&[0xCD; 32]);
            let att_p256_sig = p256::ecdsa::Signature::from_der(&att_sig).unwrap();
            {
                use p256::ecdsa::signature::Verifier;
                assert!(
                    vk.verify(&att_sig_data, &att_p256_sig).is_ok(),
                    "inner self-attestation signature must verify under the generated public key"
                );
            }

            let tbs = vec![0x42; 32];
            let ga_resp = get_assertion_with_ps5(
                &mut ctap_state,
                &mut env,
                cred_id.clone(),
                cbor_map! {
                    KEY_KH => kh.clone(),
                    KEY_TBS => tbs.clone(),
                },
                false,
                None,
                None,
            )
            .unwrap();
            let ResponseData::AuthenticatorGetAssertion(ga) = ga_resp else {
                panic!("Expected GetAssertion");
            };
            let (_, ga_ext_val) = parse_auth_data_extensions(&ga.auth_data);
            let ga_ext_map = extract_map(ga_ext_val).unwrap();
            let ga_ps5_out = extract_map(ga_ext_map[0].1.clone()).unwrap();
            assert_eq!(extract_integer(ga_ps5_out[0].0.clone()).unwrap(), KEY_SIG);
            let sig_der = extract_byte_string(ga_ps5_out[0].1.clone()).unwrap();
            let p256_sig = p256::ecdsa::Signature::from_der(&sig_der).unwrap();

            if alg == COSE_ALG_ESP256 || alg == COSE_ALG_ES256 {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                assert!(vk.verify(&tbs, &p256_sig).is_ok());
                assert!(
                    vk.verify_prehash(&tbs, &p256_sig).is_err(),
                    "full-signing algorithms (-9, -7) must hash 32-byte tbs rather than treating it as prehash"
                );

                // Full-signing algorithms (-9, -7) must also accept arbitrary non-32-byte message lengths.
                for &msg_len in &[0usize, 1, 15, 31, 33, 64, 128] {
                    let msg = vec![0x5A; msg_len];
                    let ResponseData::AuthenticatorGetAssertion(ga_msg) = get_assertion_with_ps5(
                        &mut ctap_state,
                        &mut env,
                        cred_id.clone(),
                        cbor_map! {
                            KEY_KH => kh.clone(),
                            KEY_TBS => msg.clone(),
                        },
                        false,
                        None,
                        None,
                    )
                    .unwrap() else {
                        panic!("Expected GetAssertion");
                    };
                    let (_, ga_msg_ext) = parse_auth_data_extensions(&ga_msg.auth_data);
                    let ga_msg_ps5 =
                        extract_map(extract_map(ga_msg_ext).unwrap()[0].1.clone()).unwrap();
                    let msg_sig_der = extract_byte_string(ga_msg_ps5[0].1.clone()).unwrap();
                    let msg_sig = p256::ecdsa::Signature::from_der(&msg_sig_der).unwrap();
                    assert!(vk.verify(&msg, &msg_sig).is_ok());
                }
            } else {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                assert!(vk.verify_prehash(&tbs, &p256_sig).is_ok());
                assert!(
                    vk.verify(&tbs, &p256_sig).is_err(),
                    "split-signing algorithms (-300, -70009) must sign 32-byte tbs as raw prehash"
                );

                // Split-signing algorithms (-300, -70009) must reject malformed digest lengths (!= 32 bytes).
                for &bad_len in &[0usize, 1, 15, 31, 33, 64] {
                    let bad_tbs = vec![0x42; bad_len];
                    assert_eq!(
                        get_assertion_with_ps5(
                            &mut ctap_state,
                            &mut env,
                            cred_id.clone(),
                            cbor_map! {
                                KEY_KH => kh.clone(),
                                KEY_TBS => bad_tbs,
                            },
                            false,
                            None,
                            None,
                        ),
                        Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH),
                        "split-signing algorithm {alg} must reject tbs length {bad_len}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_preview_sign_5_arkg_keygen_and_sign() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mc_resp = make_cred_with_ps5(
            &mut ctap_state,
            &mut env,
            cbor_map! {
                KEY_ALG => cbor_array![COSE_ALG_ESP256_SPLIT_ARKG],
                KEY_FLAGS => FLAG_UNATTENDED as i64,
            },
        )
        .unwrap();
        let ResponseData::AuthenticatorMakeCredential(mc) = mc_resp else {
            panic!("Expected MakeCredential");
        };
        let (Some(cred_id), _) = parse_auth_data_extensions(&mc.auth_data) else {
            panic!("Missing cred_id");
        };
        let unsigned_map = extract_map(mc.unsigned_extension_outputs.unwrap()).unwrap();
        let ps5_unsigned = extract_map(unsigned_map[0].1.clone()).unwrap();
        let att_obj_bytes = extract_byte_string(ps5_unsigned[0].1.clone()).unwrap();
        // Without a provisioned batch/enterprise attestation certificate, ARKG-P256 cannot
        // self-attest and must fall back to `"none"` attestation with an empty `attStmt`.
        let arkg_att_obj_map = extract_map(cbor_read(&att_obj_bytes).unwrap()).unwrap();
        assert_eq!(arkg_att_obj_map[0].1, sk_cbor::cbor_text!("none"));
        assert_eq!(arkg_att_obj_map[2].1, cbor_map! {});
        let (kh, pk_map, _) = parse_signing_key_att_obj(&att_obj_bytes);

        // Extract ARKG public seed components (`bl` at -1, `kem` at -2, `dkalg` at -3)
        let mut x_bl = [0u8; 32];
        let mut y_bl = [0u8; 32];
        let mut x_kem = [0u8; 32];
        let mut y_kem = [0u8; 32];
        let mut arkg_alg = 0i64;
        let mut dkalg = 0i64;
        for (k, v) in pk_map {
            match extract_integer(k).unwrap() {
                3 => arkg_alg = extract_integer(v).unwrap(),
                -1 => {
                    for (bk, bv) in extract_map(v).unwrap() {
                        match extract_integer(bk).unwrap() {
                            -2 => x_bl.copy_from_slice(&extract_byte_string(bv).unwrap()),
                            -3 => y_bl.copy_from_slice(&extract_byte_string(bv).unwrap()),
                            _ => {}
                        }
                    }
                }
                -2 => {
                    for (kk, kv) in extract_map(v).unwrap() {
                        match extract_integer(kk).unwrap() {
                            -2 => x_kem.copy_from_slice(&extract_byte_string(kv).unwrap()),
                            -3 => y_kem.copy_from_slice(&extract_byte_string(kv).unwrap()),
                            _ => {}
                        }
                    }
                }
                -3 => dkalg = extract_integer(v).unwrap(),
                _ => {}
            }
        }
        assert_eq!(arkg_alg, arkg::COSE_ALG_ARKG_P256);
        assert_eq!(dkalg, COSE_ALG_ESP256);

        // Client-side ARKG-P256-DerivePublicKey (§ 2.3, § 3.1, § 3.3, § 3.4)
        let ikm_eph = [0x55u8; 32];
        let ctx = b"python-fido2.test_sign_extension_v5";
        let mut ctx_prime = Vec::with_capacity(1 + ctx.len());
        ctx_prime.push(ctx.len() as u8);
        ctx_prime.extend_from_slice(ctx);

        let sk_eph_bytes = arkg::hash_to_field::<Sha<TestEnv>>(
            &ikm_eph,
            b"ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256",
        );
        let sk_eph = EcdhSk::<TestEnv>::from_bytes(&sk_eph_bytes).unwrap();
        let pk_eph = sk_eph.public_key();
        let mut x_eph = [0u8; 32];
        let mut y_eph = [0u8; 32];
        pk_eph.to_coordinates(&mut x_eph, &mut y_eph);
        let mut c_prime = vec![0x04];
        c_prime.extend_from_slice(&x_eph);
        c_prime.extend_from_slice(&y_eph);

        let pk_kem = EcdhPk::<TestEnv>::from_coordinates(&x_kem, &y_kem).unwrap();
        let mut k_prime = [0u8; 32];
        sk_eph.diffie_hellman(&pk_kem).raw_secret_bytes(&mut k_prime);

        // mk = HKDF-Expand(HKDF-Extract(None, k'), "ARKG-KEM-HMAC-mac.ARKG-ECDH.ARKG-P256ARKG-Derive-Key-KEM." || ctx', 32)
        let mut mac_info =
            Vec::from(&b"ARKG-KEM-HMAC-mac.ARKG-ECDH.ARKG-P256ARKG-Derive-Key-KEM."[..]);
        mac_info.extend_from_slice(&ctx_prime);
        let mut mk = [0u8; 32];
        Hkdf::<TestEnv>::hkdf_empty_salt_256(&k_prime, &mac_info, &mut mk);

        let mut full_mac = [0u8; 32];
        Hmac::<TestEnv>::mac(&mk, &c_prime, &mut full_mac);
        let mut kh_arkg = Vec::with_capacity(81);
        kh_arkg.extend_from_slice(&full_mac[..16]);
        kh_arkg.extend_from_slice(&c_prime);

        // ikm_tau = HKDF-Expand(HKDF-Extract(None, k'), "ARKG-KEM-HMAC-shared.ARKG-ECDH.ARKG-P256ARKG-Derive-Key-KEM." || ctx', 32)
        let mut shared_info =
            Vec::from(&b"ARKG-KEM-HMAC-shared.ARKG-ECDH.ARKG-P256ARKG-Derive-Key-KEM."[..]);
        shared_info.extend_from_slice(&ctx_prime);
        let mut ikm_tau = [0u8; 32];
        Hkdf::<TestEnv>::hkdf_empty_salt_256(&k_prime, &shared_info, &mut ikm_tau);

        // tau = hash_to_field(ikm_tau, "ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL." || ctx')
        let mut dst_tau = Vec::from(&b"ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL."[..]);
        dst_tau.extend_from_slice(&ctx_prime);
        let tau = arkg::hash_to_field::<Sha<TestEnv>>(&ikm_tau, &dst_tau);

        let mut pk_bl_sec1 = [0u8; 65];
        pk_bl_sec1[0] = 0x04;
        pk_bl_sec1[1..33].copy_from_slice(&x_bl);
        pk_bl_sec1[33..65].copy_from_slice(&y_bl);

        // Compute derived child public key `pk_derived = pk_bl + [tau]*G` using p256
        use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
        let bl_point = p256::ProjectivePoint::from_encoded_point(
            &p256::EncodedPoint::from_bytes(&pk_bl_sec1).unwrap(),
        )
        .unwrap();
        let tau_sk = p256::SecretKey::from_slice(&tau).unwrap();
        let tau_point = tau_sk.public_key().to_projective();
        let derived_point = (bl_point + tau_point).to_affine();
        let derived_vk =
            p256::ecdsa::VerifyingKey::from_encoded_point(&derived_point.to_encoded_point(false))
                .unwrap();

        // Sign with ARKG via `getAssertion`
        let mut args_bytes = Vec::new();
        cbor_write(
            cbor_map! {
                3 => COSE_ALG_ESP256_SPLIT_ARKG,
                -1 => kh_arkg,
                -2 => ctx.to_vec(),
            },
            &mut args_bytes,
        )
        .unwrap();
        let tbs = vec![0x99; 32];
        let ga_resp = get_assertion_with_ps5(
            &mut ctap_state,
            &mut env,
            cred_id.clone(),
            cbor_map! {
                KEY_KH => kh.clone(),
                KEY_TBS => tbs.clone(),
                KEY_ARGS => args_bytes.clone(),
            },
            false,
            None,
            None,
        )
        .unwrap();
        let ResponseData::AuthenticatorGetAssertion(ga) = ga_resp else {
            panic!("Expected GetAssertion");
        };
        let (_, ga_ext_val) = parse_auth_data_extensions(&ga.auth_data);
        let ga_ext_map = extract_map(ga_ext_val).unwrap();
        let ga_ps5_out = extract_map(ga_ext_map[0].1.clone()).unwrap();
        let sig_der = extract_byte_string(ga_ps5_out[0].1.clone()).unwrap();

        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let p256_sig = p256::ecdsa::Signature::from_der(&sig_der).unwrap();
        assert!(derived_vk.verify_prehash(&tbs, &p256_sig).is_ok());
        assert!(derived_vk.verify(&tbs, &p256_sig).is_err());

        // Malformed digest lengths (!= 32 bytes) for ESP256-split-ARKG must return CTAP2_ERR_INVALID_LENGTH.
        for &bad_len in &[0usize, 1, 15, 31, 33, 64] {
            let bad_tbs = vec![0x99; bad_len];
            assert_eq!(
                get_assertion_with_ps5(
                    &mut ctap_state,
                    &mut env,
                    cred_id.clone(),
                    cbor_map! {
                        KEY_KH => kh.clone(),
                        KEY_TBS => bad_tbs,
                        KEY_ARGS => args_bytes.clone(),
                    },
                    false,
                    None,
                    None,
                ),
                Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH),
                "ESP256-split-ARKG must reject tbs length {bad_len}"
            );
        }
    }

    #[test]
    fn test_preview_sign_5_validation_and_error_codes() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // 1. Empty input -> CBOR_UNEXPECTED_TYPE
        assert_eq!(
            make_cred_with_ps5(&mut ctap_state, &mut env, cbor_map! {}),
            Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );

        // 2. Flags validation (0..256): only 0b000, 0b001, 0b100, 0b101 are valid
        for flags in 0u64..256 {
            let res = PreviewSign5Input::try_from_cbor(
                cbor_map! {
                    KEY_ALG => cbor_array![COSE_ALG_ESP256],
                    KEY_FLAGS => flags,
                },
                true,
            );
            if matches!(flags as u8, FLAG_UNATTENDED | FLAG_REQUIRE_UP | FLAG_REQUIRE_UV | FLAG_REQUIRE_UP_UV) {
                assert!(res.is_ok());
            } else {
                assert_eq!(res, Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE));
            }
        }

        // 3. support: false -> CBOR_UNEXPECTED_TYPE; support: true -> ok
        assert_eq!(
            make_cred_with_ps5(&mut ctap_state, &mut env, cbor_map! { KEY_SUPPORT => false }),
            Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert!(make_cred_with_ps5(&mut ctap_state, &mut env, cbor_map! { KEY_SUPPORT => true }).is_ok());

        // 4. Sign inputs in MakeCredential -> INVALID_OPTION
        assert_eq!(
            make_cred_with_ps5(
                &mut ctap_state,
                &mut env,
                cbor_map! {
                    KEY_KH => vec![0x01; 40],
                    KEY_TBS => vec![0x02; 32],
                }
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
        );

        // 5. Unsupported algorithm [-18] -> ERR_UNSUPPORTED_ALGORITHM + support
        let unsup_resp = make_cred_with_ps5(
            &mut ctap_state,
            &mut env,
            cbor_map! {
                KEY_ALG => cbor_array![-18],
            },
        )
        .unwrap();
        let ResponseData::AuthenticatorMakeCredential(unsup_mc) = unsup_resp else {
            panic!();
        };
        assert!(unsup_mc.unsigned_extension_outputs.is_none());
        let (_, unsup_ext_val) = parse_auth_data_extensions(&unsup_mc.auth_data);
        let unsup_ps5 = extract_map(extract_map(unsup_ext_val).unwrap()[0].1.clone()).unwrap();
        assert!(unsup_ps5.contains(&(cbor_int!(KEY_ERR), cbor_int!(ERR_UNSUPPORTED_ALGORITHM))));

        // 6. Register an ARKG key for assertion-time error code tests
        let mc_resp = make_cred_with_ps5(
            &mut ctap_state,
            &mut env,
            cbor_map! {
                KEY_ALG => cbor_array![COSE_ALG_ESP256_SPLIT_ARKG],
                KEY_FLAGS => FLAG_UNATTENDED as i64,
            },
        )
        .unwrap();
        let ResponseData::AuthenticatorMakeCredential(mc) = mc_resp else {
            panic!();
        };
        let (Some(cred_id), _) = parse_auth_data_extensions(&mc.auth_data) else {
            panic!();
        };
        let att_obj_bytes = extract_byte_string(
            extract_map(
                extract_map(mc.unsigned_extension_outputs.unwrap()).unwrap()[0]
                    .1
                    .clone(),
            )
            .unwrap()[0]
                .1
                .clone(),
        )
        .unwrap();
        let (kh, _, _) = parse_signing_key_att_obj(&att_obj_bytes);
        let tbs = vec![0x11; 32];

        // 6a. Both alg and kh/tbs in GetAssertion -> CBOR_UNEXPECTED_TYPE
        assert_eq!(
            get_assertion_with_ps5(
                &mut ctap_state,
                &mut env,
                cred_id.clone(),
                cbor_map! {
                    KEY_KH => kh.clone(),
                    KEY_ALG => cbor_array![COSE_ALG_ESP256],
                    KEY_TBS => tbs.clone(),
                },
                false,
                None,
                None,
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );

        // 6b. Missing kh or missing tbs -> CBOR_UNEXPECTED_TYPE
        assert_eq!(
            get_assertion_with_ps5(
                &mut ctap_state,
                &mut env,
                cred_id.clone(),
                cbor_map! { KEY_KH => kh.clone() },
                false,
                None,
                None,
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            get_assertion_with_ps5(
                &mut ctap_state,
                &mut env,
                cred_id.clone(),
                cbor_map! { KEY_TBS => tbs.clone() },
                false,
                None,
                None,
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );

        // 6c. Corrupted key handle -> ERR_INVALID_KEY_HANDLE (4)
        let mut bad_kh = kh.clone();
        bad_kh[0] ^= 0x01;
        let ResponseData::AuthenticatorGetAssertion(ga_bad_kh) = get_assertion_with_ps5(
            &mut ctap_state,
            &mut env,
            cred_id.clone(),
            cbor_map! {
                KEY_KH => bad_kh,
                KEY_TBS => tbs.clone(),
            },
            false,
            None,
            None,
        )
        .unwrap() else {
            panic!();
        };
        let (_, ext_bad_kh) = parse_auth_data_extensions(&ga_bad_kh.auth_data);
        let ps5_bad_kh = extract_map(extract_map(ext_bad_kh).unwrap()[0].1.clone()).unwrap();
        assert_eq!(ps5_bad_kh, vec![(cbor_int!(KEY_ERR), cbor_int!(ERR_INVALID_KEY_HANDLE))]);

        // 6d. Missing args for ARKG -> ERR_COSE_SIGN_ARGS_MISSING_PARAM (7)
        let ResponseData::AuthenticatorGetAssertion(ga_no_args) = get_assertion_with_ps5(
            &mut ctap_state,
            &mut env,
            cred_id.clone(),
            cbor_map! {
                KEY_KH => kh.clone(),
                KEY_TBS => tbs.clone(),
            },
            false,
            None,
            None,
        )
        .unwrap() else {
            panic!();
        };
        let (_, ext_no_args) = parse_auth_data_extensions(&ga_no_args.auth_data);
        let ps5_no_args = extract_map(extract_map(ext_no_args).unwrap()[0].1.clone()).unwrap();
        assert_eq!(
            ps5_no_args,
            vec![(cbor_int!(KEY_ERR), cbor_int!(ERR_COSE_SIGN_ARGS_MISSING_PARAM))]
        );

        // 6e. Invalid args CBOR type (array instead of map) -> ERR_COSE_SIGN_ARGS_INVALID (5)
        let mut bad_args = Vec::new();
        cbor_write(cbor_array![], &mut bad_args).unwrap();
        let ResponseData::AuthenticatorGetAssertion(ga_bad_args) = get_assertion_with_ps5(
            &mut ctap_state,
            &mut env,
            cred_id.clone(),
            cbor_map! {
                KEY_KH => kh.clone(),
                KEY_TBS => tbs.clone(),
                KEY_ARGS => bad_args,
            },
            false,
            None,
            None,
        )
        .unwrap() else {
            panic!();
        };
        let (_, ext_bad_args) = parse_auth_data_extensions(&ga_bad_args.auth_data);
        let ps5_bad_args = extract_map(extract_map(ext_bad_args).unwrap()[0].1.clone()).unwrap();
        assert_eq!(
            ps5_bad_args,
            vec![(cbor_int!(KEY_ERR), cbor_int!(ERR_COSE_SIGN_ARGS_INVALID))]
        );

        // 6f. Wrong alg in args -> ERR_COSE_SIGN_ARGS_ALG_MISMATCH (6)
        let mut wrong_alg_args = Vec::new();
        cbor_write(
            cbor_map! {
                3 => COSE_ALG_ESP256_SPLIT_ARKG + 1,
                -1 => vec![0x04; 65],
                -2 => b"ctx".to_vec(),
            },
            &mut wrong_alg_args,
        )
        .unwrap();
        let ResponseData::AuthenticatorGetAssertion(ga_wrong_alg) = get_assertion_with_ps5(
            &mut ctap_state,
            &mut env,
            cred_id.clone(),
            cbor_map! {
                KEY_KH => kh.clone(),
                KEY_TBS => tbs.clone(),
                KEY_ARGS => wrong_alg_args,
            },
            false,
            None,
            None,
        )
        .unwrap() else {
            panic!();
        };
        let (_, ext_wrong_alg) = parse_auth_data_extensions(&ga_wrong_alg.auth_data);
        let ps5_wrong_alg = extract_map(extract_map(ext_wrong_alg).unwrap()[0].1.clone()).unwrap();
        assert_eq!(
            ps5_wrong_alg,
            vec![(cbor_int!(KEY_ERR), cbor_int!(ERR_COSE_SIGN_ARGS_ALG_MISMATCH))]
        );

        // 6g. Unknown param in args -> ERR_COSE_SIGN_ARGS_UNKNOWN_PARAM (8)
        let mut unk_args = Vec::new();
        cbor_write(
            cbor_map! {
                3 => COSE_ALG_ESP256_SPLIT_ARKG,
                42 => 1337,
                -1 => vec![0x04; 65],
                -2 => b"ctx".to_vec(),
            },
            &mut unk_args,
        )
        .unwrap();
        let ResponseData::AuthenticatorGetAssertion(ga_unk) = get_assertion_with_ps5(
            &mut ctap_state,
            &mut env,
            cred_id.clone(),
            cbor_map! {
                KEY_KH => kh.clone(),
                KEY_TBS => tbs.clone(),
                KEY_ARGS => unk_args,
            },
            false,
            None,
            None,
        )
        .unwrap() else {
            panic!();
        };
        let (_, ext_unk) = parse_auth_data_extensions(&ga_unk.auth_data);
        let ps5_unk = extract_map(extract_map(ext_unk).unwrap()[0].1.clone()).unwrap();
        assert_eq!(
            ps5_unk,
            vec![(cbor_int!(KEY_ERR), cbor_int!(ERR_COSE_SIGN_ARGS_UNKNOWN_PARAM))]
        );

        // 6h. Missing required ARKG arguments AND unknown argument coexisting ({3: -65539, 42: 1})
        // must return ERR_COSE_SIGN_ARGS_MISSING_PARAM (7) before ERR_COSE_SIGN_ARGS_UNKNOWN_PARAM (8).
        let mut missing_and_unk_args = Vec::new();
        cbor_write(
            cbor_map! {
                3 => COSE_ALG_ESP256_SPLIT_ARKG,
                42 => 1,
            },
            &mut missing_and_unk_args,
        )
        .unwrap();
        let ResponseData::AuthenticatorGetAssertion(ga_missing_unk) = get_assertion_with_ps5(
            &mut ctap_state,
            &mut env,
            cred_id,
            cbor_map! {
                KEY_KH => kh,
                KEY_TBS => tbs,
                KEY_ARGS => missing_and_unk_args,
            },
            false,
            None,
            None,
        )
        .unwrap() else {
            panic!();
        };
        let (_, ext_missing_unk) = parse_auth_data_extensions(&ga_missing_unk.auth_data);
        let ps5_missing_unk =
            extract_map(extract_map(ext_missing_unk).unwrap()[0].1.clone()).unwrap();
        assert_eq!(
            ps5_missing_unk,
            vec![(cbor_int!(KEY_ERR), cbor_int!(ERR_COSE_SIGN_ARGS_MISSING_PARAM))]
        );
    }

    #[test]
    fn test_preview_sign_5_up_and_uv_flag_enforcement() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        for &flags in &[FLAG_REQUIRE_UP, FLAG_REQUIRE_UV, FLAG_REQUIRE_UP_UV] {
            let ResponseData::AuthenticatorMakeCredential(mc) = make_cred_with_ps5(
                &mut ctap_state,
                &mut env,
                cbor_map! {
                    KEY_ALG => cbor_array![COSE_ALG_ESP256],
                    KEY_FLAGS => flags as i64,
                },
            )
            .unwrap() else {
                panic!();
            };
            let (Some(cred_id), _) = parse_auth_data_extensions(&mc.auth_data) else {
                panic!();
            };
            let att_obj_bytes = extract_byte_string(
                extract_map(
                    extract_map(mc.unsigned_extension_outputs.unwrap()).unwrap()[0]
                        .1
                        .clone(),
                )
                .unwrap()[0]
                    .1
                    .clone(),
            )
            .unwrap();
            let (kh, _, _) = parse_signing_key_att_obj(&att_obj_bytes);
            let tbs = vec![0x77; 32];

            match flags {
                FLAG_REQUIRE_UP => {
                    assert_eq!(
                        get_assertion_with_ps5(
                            &mut ctap_state,
                            &mut env,
                            cred_id.clone(),
                            cbor_map! { KEY_KH => kh.clone(), KEY_TBS => tbs.clone() },
                            false,
                            None,
                            None,
                        ),
                        Err(Ctap2StatusCode::CTAP2_ERR_UP_REQUIRED)
                    );
                    assert!(
                        get_assertion_with_ps5(
                            &mut ctap_state,
                            &mut env,
                            cred_id,
                            cbor_map! { KEY_KH => kh, KEY_TBS => tbs },
                            true,
                            None,
                            None,
                        )
                        .is_ok()
                    );
                }
                FLAG_REQUIRE_UV => {
                    assert_eq!(
                        get_assertion_with_ps5(
                            &mut ctap_state,
                            &mut env,
                            cred_id,
                            cbor_map! { KEY_KH => kh, KEY_TBS => tbs },
                            false,
                            None,
                            None,
                        ),
                        Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
                    );
                }
                FLAG_REQUIRE_UP_UV => {
                    assert_eq!(
                        get_assertion_with_ps5(
                            &mut ctap_state,
                            &mut env,
                            cred_id.clone(),
                            cbor_map! { KEY_KH => kh.clone(), KEY_TBS => tbs.clone() },
                            false,
                            None,
                            None,
                        ),
                        Err(Ctap2StatusCode::CTAP2_ERR_UP_REQUIRED)
                    );
                    assert_eq!(
                        get_assertion_with_ps5(
                            &mut ctap_state,
                            &mut env,
                            cred_id,
                            cbor_map! { KEY_KH => kh, KEY_TBS => tbs },
                            true,
                            None,
                            None,
                        ),
                        Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    fn make_cred_with_ps4(
        ctap_state: &mut CtapState<TestEnv>,
        env: &mut TestEnv,
        ps4_cbor: cbor::Value,
    ) -> CtapResult<ResponseData> {
        let ps4_input = PreviewSign4Input::try_from_cbor(ps4_cbor, true)?;
        let params = AuthenticatorMakeCredentialParameters {
            client_data_hash: vec![0xCD; 32],
            rp: PublicKeyCredentialRpEntity {
                rp_id: String::from("example.com"),
                rp_name: None,
                rp_icon: None,
            },
            user: PublicKeyCredentialUserEntity {
                user_id: vec![0x1D; 16],
                user_name: None,
                user_display_name: None,
                user_icon: None,
            },
            pub_key_cred_params: vec![ES256_CRED_PARAM],
            exclude_list: None,
            extensions: MakeCredentialExtensions {
                preview_sign: Some(ps4_input),
                ..Default::default()
            },
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
            attestation_formats_preference: None,
        };
        ctap_state.process_make_credential(env, params, DUMMY_CHANNEL)
    }

    fn get_assertion_with_ps4(
        ctap_state: &mut CtapState<TestEnv>,
        env: &mut TestEnv,
        cred_id: Option<Vec<u8>>,
        ps4_cbor: cbor::Value,
        up: bool,
    ) -> CtapResult<ResponseData> {
        let ps4_input = PreviewSign4Input::try_from_cbor(ps4_cbor, false)?;
        let allow_list = cred_id.map(|id| {
            vec![PublicKeyCredentialDescriptor {
                key_type: PublicKeyCredentialType::PublicKey,
                key_id: id,
                transports: None,
            }]
        });
        let params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD; 32],
            allow_list,
            extensions: GetAssertionExtensions {
                preview_sign: Some(ps4_input),
                ..Default::default()
            },
            options: GetAssertionOptions { up, uv: false },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        ctap_state.process_get_assertion(env, params, DUMMY_CHANNEL)
    }

    #[test]
    fn test_preview_sign_4_keygen_sign_and_errors() {
        use sk_cbor::cbor_text;
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // 1. Keygen and sign with ESP256 under v4 "previewSign"
        let ResponseData::AuthenticatorMakeCredential(mc_resp) = make_cred_with_ps4(
            &mut ctap_state,
            &mut env,
            cbor_map! {
                KEY_ALG => cbor_array![COSE_ALG_ESP256],
                KEY_FLAGS => 0i64,
            },
        )
        .unwrap() else {
            panic!("Expected AuthenticatorMakeCredential");
        };
        let (Some(cred_id), signed_ext) = parse_auth_data_extensions(&mc_resp.auth_data) else {
            panic!("Expected cred_id");
        };
        let signed_ext_map = extract_map(signed_ext).unwrap();
        assert_eq!(signed_ext_map[0].0, cbor_text!(PREVIEW_SIGN_4_EXT_ID));

        let unsigned_map = extract_map(mc_resp.unsigned_extension_outputs.unwrap()).unwrap();
        assert_eq!(unsigned_map[0].0, cbor_text!(PREVIEW_SIGN_4_EXT_ID));
        let ps4_unsigned = extract_map(unsigned_map[0].1.clone()).unwrap();
        let att_obj_bytes = extract_byte_string(ps4_unsigned[0].1.clone()).unwrap();
        let (kh, _, inner_flags) = parse_signing_key_att_obj(&att_obj_bytes);
        assert_eq!(inner_flags, 0);

        // 2. Unknown parameter in args is allowed in v4 (ignored)
        let mut args_bytes = Vec::new();
        cbor_write(
            cbor_map! {
                3 => COSE_ALG_ESP256,
                42 => 1337,
            },
            &mut args_bytes,
        )
        .unwrap();
        let tbs = vec![0xAA; 32];
        assert!(
            get_assertion_with_ps4(
                &mut ctap_state,
                &mut env,
                Some(cred_id.clone()),
                cbor_map! {
                    KEY_KH => kh.clone(),
                    KEY_TBS => tbs.clone(),
                    KEY_ARGS => args_bytes,
                },
                false,
            )
            .is_ok()
        );

        // 3. Empty allowList in v4 returns CTAP2_ERR_INVALID_OPTION
        assert_eq!(
            get_assertion_with_ps4(
                &mut ctap_state,
                &mut env,
                None,
                cbor_map! {
                    KEY_KH => kh.clone(),
                    KEY_TBS => tbs.clone(),
                },
                false,
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
        );

        // 4. Unsupported algorithm in v4 returns CTAP2_ERR_UNSUPPORTED_ALGORITHM
        assert_eq!(
            make_cred_with_ps4(
                &mut ctap_state,
                &mut env,
                cbor_map! {
                    KEY_ALG => cbor_array![1337],
                },
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );

        // 5. Invalid flags (0b100 = UV without UP) in v4 returns CTAP2_ERR_INVALID_OPTION
        assert_eq!(
            make_cred_with_ps4(
                &mut ctap_state,
                &mut env,
                cbor_map! {
                    KEY_ALG => cbor_array![COSE_ALG_ESP256],
                    KEY_FLAGS => FLAG_REQUIRE_UV as i64,
                },
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
        );

        // 6. Corrupted kh in v4 returns CTAP2_ERR_INVALID_CREDENTIAL
        let mut bad_kh = kh.clone();
        bad_kh[0] ^= 0xFF;
        assert_eq!(
            get_assertion_with_ps4(
                &mut ctap_state,
                &mut env,
                Some(cred_id.clone()),
                cbor_map! {
                    KEY_KH => bad_kh,
                    KEY_TBS => tbs.clone(),
                },
                false,
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL)
        );

        // 7. Mismatched args[3] in v4 returns CTAP2_ERR_INVALID_CREDENTIAL
        let mut bad_alg_args = Vec::new();
        cbor_write(cbor_map! { 3 => COSE_ALG_ES256 }, &mut bad_alg_args).unwrap();
        assert_eq!(
            get_assertion_with_ps4(
                &mut ctap_state,
                &mut env,
                Some(cred_id.clone()),
                cbor_map! {
                    KEY_KH => kh.clone(),
                    KEY_TBS => tbs,
                    KEY_ARGS => bad_alg_args,
                },
                false,
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL)
        );

        // 8. Non-32-byte message lengths succeed for full-signing ESP256 (-9) in v4, whereas
        // split-signing algorithms (-300, -70009) reject non-32-byte tbs with CTAP2_ERR_INVALID_LENGTH.
        for &msg_len in &[0usize, 1, 15, 31, 33, 64] {
            let msg = vec![0xBB; msg_len];
            assert!(
                get_assertion_with_ps4(
                    &mut ctap_state,
                    &mut env,
                    Some(cred_id.clone()),
                    cbor_map! {
                        KEY_KH => kh.clone(),
                        KEY_TBS => msg,
                    },
                    false,
                )
                .is_ok()
            );
        }

        for &split_alg in &[COSE_ALG_ESP256_SPLIT, COSE_ALG_ESP256_SPLIT_PLACEHOLDER] {
            let ResponseData::AuthenticatorMakeCredential(mc_split) = make_cred_with_ps4(
                &mut ctap_state,
                &mut env,
                cbor_map! {
                    KEY_ALG => cbor_array![split_alg],
                    KEY_FLAGS => 0i64,
                },
            )
            .unwrap() else {
                panic!("Expected AuthenticatorMakeCredential");
            };
            let (Some(split_cred_id), _) = parse_auth_data_extensions(&mc_split.auth_data) else {
                panic!("Expected cred_id");
            };
            let split_unsigned = extract_map(mc_split.unsigned_extension_outputs.unwrap()).unwrap();
            let split_ps4_unsigned = extract_map(split_unsigned[0].1.clone()).unwrap();
            let split_att_obj_bytes = extract_byte_string(split_ps4_unsigned[0].1.clone()).unwrap();
            let (split_kh, _, _) = parse_signing_key_att_obj(&split_att_obj_bytes);

            for &bad_len in &[0usize, 1, 15, 31, 33, 64] {
                let bad_tbs = vec![0xCC; bad_len];
                assert_eq!(
                    get_assertion_with_ps4(
                        &mut ctap_state,
                        &mut env,
                        Some(split_cred_id.clone()),
                        cbor_map! {
                            KEY_KH => split_kh.clone(),
                            KEY_TBS => bad_tbs,
                        },
                        false,
                    ),
                    Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH)
                );
            }
        }
    }

    #[test]
    fn test_preview_sign_5_propagates_mtc_format_and_enterprise_attestation() {
        use crate::ctap::mtc::{
            MtcAttestationFormat, MtcCertDescriptor, ProvisionedMtcAttestation,
        };
        use crate::ctap::storage;
        use sk_cbor::cbor_text;

        let mut env = TestEnv::default();
        env.persist().set_aaguid(&[0xAA; 16]).unwrap();

        // 1. Provision Batch MTC attestation and Enterprise X.509 attestation.
        let batch_att_key = PrivateKey::<TestEnv>::new_ecdsa(&mut env);
        let batch_sk_bytes = batch_att_key.export();
        let batch_mtc = ProvisionedMtcAttestation {
            format: MtcAttestationFormat::Mtc,
            x5c: None,
            classical_key: None,
            classical_x5c: None,
            key_ref: true,
            cert: MtcCertDescriptor {
                ca_id: vec![0x83, 0x99, 0x3f, 0x01, 0x01],
                serial: 42,
                mtc_proof: vec![0x11; 32],
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                firmware_version: None,
            },
        };
        env.persist()
            .set_attestation(
                AttestationId::Batch,
                Some(&Attestation {
                    wrapped_private_key: batch_sk_bytes,
                    certificate: batch_mtc.to_bytes().unwrap(),
                }),
            )
            .unwrap();

        let ent_att_key = PrivateKey::<TestEnv>::new_ecdsa(&mut env);
        let ent_sk_bytes = ent_att_key.export();
        let ent_cert_der = vec![0x30, 0x82, 0x01, 0x23, 0xEE, 0xFF];
        env.persist()
            .set_attestation(
                AttestationId::Enterprise,
                Some(&Attestation {
                    wrapped_private_key: ent_sk_bytes,
                    certificate: ent_cert_der.clone(),
                }),
            )
            .unwrap();
        storage::enable_enterprise_attestation(&mut env).unwrap();

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // Case A: Outer credential selects `"mtc"` -> inner `att-obj` must also emit `fmt: "mtc"`
        // and `attStmt.mtcCert`.
        let ps5_input = PreviewSign5Input::try_from_cbor(
            cbor_map! {
                KEY_ALG => cbor_array![COSE_ALG_ESP256],
            },
            true,
        )
        .unwrap();
        let mtc_params = AuthenticatorMakeCredentialParameters {
            client_data_hash: vec![0xCD; 32],
            rp: PublicKeyCredentialRpEntity {
                rp_id: String::from("example.com"),
                rp_name: None,
                rp_icon: None,
            },
            user: PublicKeyCredentialUserEntity {
                user_id: vec![0x1D; 16],
                user_name: None,
                user_display_name: None,
                user_icon: None,
            },
            pub_key_cred_params: vec![ES256_CRED_PARAM],
            exclude_list: None,
            extensions: MakeCredentialExtensions {
                preview_sign_5: Some(ps5_input.clone()),
                ..Default::default()
            },
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
            attestation_formats_preference: Some(vec![String::from("mtc")]),
        };
        let ResponseData::AuthenticatorMakeCredential(mc_mtc) = ctap_state
            .process_make_credential(&mut env, mtc_params, DUMMY_CHANNEL)
            .unwrap()
        else {
            panic!("Expected AuthenticatorMakeCredential");
        };
        assert_eq!(mc_mtc.fmt, "mtc");
        assert!(mc_mtc.att_stmt.mtc_cert.is_some());

        let mtc_unsigned = extract_map(mc_mtc.unsigned_extension_outputs.unwrap()).unwrap();
        let ps5_mtc_unsigned = extract_map(mtc_unsigned[0].1.clone()).unwrap();
        let inner_mtc_att_obj_bytes = extract_byte_string(ps5_mtc_unsigned[0].1.clone()).unwrap();
        let inner_mtc_att_obj = extract_map(cbor_read(&inner_mtc_att_obj_bytes).unwrap()).unwrap();
        assert_eq!(inner_mtc_att_obj[0].1, cbor_text!("mtc"));
        let inner_mtc_stmt = extract_map(inner_mtc_att_obj[2].1.clone()).unwrap();
        assert!(
            inner_mtc_stmt
                .iter()
                .any(|(k, _)| *k == cbor_text!("mtcCert")),
            "inner att-obj must include mtcCert when mtc format is selected"
        );

        // Case B: Outer credential uses Enterprise Attestation (`enterprise_attestation = Some(2)`) ->
        // inner `att-obj` must use the `AttestationId::Enterprise` certificate (`ent_cert_der`).
        let ep_params = AuthenticatorMakeCredentialParameters {
            client_data_hash: vec![0xCD; 32],
            rp: PublicKeyCredentialRpEntity {
                rp_id: String::from("example.com"),
                rp_name: None,
                rp_icon: None,
            },
            user: PublicKeyCredentialUserEntity {
                user_id: vec![0x2D; 16],
                user_name: None,
                user_display_name: None,
                user_icon: None,
            },
            pub_key_cred_params: vec![ES256_CRED_PARAM],
            exclude_list: None,
            extensions: MakeCredentialExtensions {
                preview_sign_5: Some(ps5_input),
                ..Default::default()
            },
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: Some(2),
            attestation_formats_preference: None,
        };
        let ResponseData::AuthenticatorMakeCredential(mc_ep) = ctap_state
            .process_make_credential(&mut env, ep_params, DUMMY_CHANNEL)
            .unwrap()
        else {
            panic!("Expected AuthenticatorMakeCredential");
        };
        assert_eq!(mc_ep.ep_att, Some(true));
        assert_eq!(mc_ep.fmt, "packed");
        assert_eq!(mc_ep.att_stmt.x5c, Some(vec![ent_cert_der.clone()]));

        let ep_unsigned = extract_map(mc_ep.unsigned_extension_outputs.unwrap()).unwrap();
        let ps5_ep_unsigned = extract_map(ep_unsigned[0].1.clone()).unwrap();
        let inner_ep_att_obj_bytes = extract_byte_string(ps5_ep_unsigned[0].1.clone()).unwrap();
        let inner_ep_att_obj = extract_map(cbor_read(&inner_ep_att_obj_bytes).unwrap()).unwrap();
        assert_eq!(inner_ep_att_obj[0].1, cbor_text!("packed"));
        let inner_ep_stmt = extract_map(inner_ep_att_obj[2].1.clone()).unwrap();
        let inner_x5c = inner_ep_stmt
            .into_iter()
            .find_map(|(k, v)| (k == cbor_text!("x5c")).then_some(v))
            .expect("inner att-obj must contain x5c from Enterprise attestation");
        assert_eq!(inner_x5c, cbor_array![cbor_bytes!(ent_cert_der)]);
    }
}
