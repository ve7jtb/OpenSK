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

//! Post-Quantum Merkle Tree Certificate (`mtc`) attestation support
//! based on `draft-ietf-plants-merkle-tree-certs` and RFC 9162 §2.1.

use crate::api::crypto::HASH_SIZE;
use crate::api::crypto::sha256::Sha256;
use crate::api::persist::AAGUID_LENGTH;
use crate::ctap::data_formats::{
    TruncatedBytes, extract_bool, extract_byte_string, extract_map, extract_text_string,
    extract_unsigned, ok_or_missing,
};
use crate::ctap::status_code::{Ctap2StatusCode, CtapResult};
use crate::ctap::{cbor_read, cbor_write};
use alloc::string::String;
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
use sk_cbor as cbor;
use sk_cbor::{cbor_map_options, destructure_cbor_map};

/// WebAuthn attestation statement format identifier for Merkle Tree Certificates (`fmt: "mtc"`).
/// Always omits inline `pubKey` on the wire (`attStmt = { alg, sig, mtcCert }`); RPs resolve
/// `pubKey` by `(caId, serial)` from FIDO MDS `MtcTrustAnchor.batchKeys` (or `"mtc-debug"`).
pub const MTC_FORMAT_STR: &str = "mtc";

/// Provisioning format alias indicating compact proof-less `mtcKeyRef` (`{ caId, serial }`) on the wire.
pub const MTC_KEYREF_FORMAT_STR: &str = "mtc-keyref";

/// Legacy alias for `"mtc"` accepted for backwards compatibility during deserialization.
pub const MTC_MDS_FORMAT_STR: &str = "mtc-mds";

/// GeneralizedTime `99991231235959Z` (`9999-12-31T23:59:59Z`, `0x3AFF44417F`) per RFC 5280 §4.1.2.5
/// and WebAuthn Level 4 §8.10 for authenticators with non-expiring attestation lifetimes.
pub const MTC_NON_EXPIRING_NOT_AFTER: u64 = 253_402_300_799;

/// Represents the `"mtc"` attestation format (`attStmt = { alg, sig, mtcCert }`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtcAttestationFormat {
    /// `fmt: "mtc"` — omits `pubKey` on the wire; RP fetches `pubKey` by `(caId, serial)` from MDS/log
    /// (or from the `"mtc-debug"` extension output when requested).
    Mtc,
    /// Legacy/key-ref alias for [`MtcAttestationFormat::Mtc`]; always serializes as `"mtc"` on the wire.
    MtcMds,
}

impl MtcAttestationFormat {
    pub fn as_str(&self) -> &'static str {
        MTC_FORMAT_STR
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            MTC_FORMAT_STR | MTC_KEYREF_FORMAT_STR | MTC_MDS_FORMAT_STR => Some(Self::Mtc),
            _ => None,
        }
    }
}

/// Compact MTC certificate descriptor (`mtcCert = mtcEntryDesc / mtcKeyRef`) carried inside `"mtc"` statements.
#[derive(Clone, PartialEq, Eq)]
pub struct MtcCertDescriptor {
    /// ASN.1 DER Binary `TrustAnchorID` (RFC 9879 / `draft-ietf-plants-merkle-tree-certs` §4).
    pub ca_id: Vec<u8>,
    /// 64-bit certificate serial number: `(log_number << 48) | index`.
    pub serial: u64,
    /// Validity start timestamp (Unix epoch seconds). Zero when serialized as a compact `mtcKeyRef`.
    pub not_before: u64,
    /// Validity end timestamp (Unix epoch seconds, or [`MTC_NON_EXPIRING_NOT_AFTER`]). Zero when `mtcKeyRef`.
    pub not_after: u64,
    /// Optional authenticator firmware version (CTAP 2.3 parameter `0x0E`, replaces X.509 `id-fido-gen-ce-fw-version`).
    pub firmware_version: Option<u64>,
    /// TLS-serialized `MTCProof` (`draft-ietf-plants-merkle-tree-certs` §4.2). Empty when `mtcKeyRef` or proof-less.
    pub mtc_proof: Vec<u8>,
}

impl MtcCertDescriptor {
    /// Returns a compact proof-less `mtcKeyRef` (`{ caId, serial }`) view of this descriptor for wire serialization.
    pub fn to_key_ref(&self) -> Self {
        Self {
            ca_id: self.ca_id.clone(),
            serial: self.serial,
            not_before: 0,
            not_after: 0,
            firmware_version: None,
            mtc_proof: Vec::new(),
        }
    }

    /// Returns `true` if this descriptor represents a compact 2-field `mtcKeyRef` (`{ caId, serial }`).
    pub fn is_key_ref(&self) -> bool {
        self.mtc_proof.is_empty()
            && self.not_before == 0
            && self.not_after == 0
            && self.firmware_version.is_none()
    }

    /// Returns `true` if `not_after` is set to [`MTC_NON_EXPIRING_NOT_AFTER`] (`253402300799` / `9999-12-31T23:59:59Z`).
    pub fn is_non_expiring(&self) -> bool {
        self.not_after == MTC_NON_EXPIRING_NOT_AFTER
    }
}

impl core::fmt::Debug for MtcCertDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MtcCertDescriptor")
            .field("ca_id", &TruncatedBytes(&self.ca_id))
            .field("serial", &self.serial)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("firmware_version", &self.firmware_version)
            .field("mtc_proof", &TruncatedBytes(&self.mtc_proof))
            .finish()
    }
}

impl From<MtcCertDescriptor> for cbor::Value {
    fn from(desc: MtcCertDescriptor) -> Self {
        if desc.is_key_ref() {
            // Proof-less `mtcKeyRef = { caId: bytes, serial: uint }` (WebAuthn Level 4 §8.10).
            cbor_map_options! {
                "caId" => desc.ca_id,
                "serial" => desc.serial,
            }
        } else {
            // Canonical CBOR map key order (sorted by UTF-8 byte length, then lexicographically):
            // "caId" (4), "serial" (6), "mtcProof" (8), "notAfter" (8), "notBefore" (9), "firmwareVersion" (15)
            cbor_map_options! {
                "caId" => desc.ca_id,
                "serial" => desc.serial,
                "mtcProof" => if desc.mtc_proof.is_empty() { None } else { Some(desc.mtc_proof) },
                "notAfter" => desc.not_after,
                "notBefore" => desc.not_before,
                "firmwareVersion" => desc.firmware_version,
            }
        }
    }
}

impl TryFrom<cbor::Value> for MtcCertDescriptor {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                "caId" => ca_id,
                "serial" => serial,
                "mtcProof" => mtc_proof,
                "notAfter" => not_after,
                "fwVersion" => fw_version_legacy,
                "notBefore" => not_before,
                "firmwareVersion" => firmware_version,
            } = extract_map(cbor_value)?;
        }
        let ca_id = extract_byte_string(ok_or_missing(ca_id)?)?;
        let serial = extract_unsigned(ok_or_missing(serial)?)?;
        let mtc_proof = mtc_proof
            .map(extract_byte_string)
            .transpose()?
            .unwrap_or_default();
        let not_after = not_after.map(extract_unsigned).transpose()?.unwrap_or(0);
        let not_before = not_before.map(extract_unsigned).transpose()?.unwrap_or(0);
        let firmware_version = match firmware_version {
            Some(fw) => Some(extract_unsigned(fw)?),
            None => fw_version_legacy.map(extract_unsigned).transpose()?,
        };
        Ok(Self {
            ca_id,
            serial,
            mtc_proof,
            not_after,
            firmware_version,
            not_before,
        })
    }
}

/// Authenticator extension output for `"mtc-debug"` (`MtcDebugAuthOutput`, WebAuthn Level 4 §10.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtcDebugOutput {
    /// Canonical CBOR-encoded `COSE_Key` (`bstr`) of the attestation public key.
    pub pub_key: Vec<u8>,
    /// UTF-8 device serial number (`tstr`); strictly omitted unless `ep_att == true`.
    pub device_serial: Option<String>,
    /// Start of validity window (Unix epoch seconds).
    pub not_before: Option<u64>,
    /// End of validity window (Unix epoch seconds, or [`MTC_NON_EXPIRING_NOT_AFTER`]).
    pub not_after: Option<u64>,
    /// Authenticator firmware version (CTAP 2.3 parameter `0x0E`).
    pub firmware_version: Option<u64>,
    /// Binary RFC 9162 / PLANTS `MTCProof` (`bstr`).
    pub mtc_proof: Option<Vec<u8>>,
    /// 32-byte Merkle subtree root hash (`bstr`) computed from the leaf and `mtcProof`.
    pub root_hash: Option<Vec<u8>>,
}

impl From<MtcDebugOutput> for cbor::Value {
    fn from(debug: MtcDebugOutput) -> Self {
        // Canonical CBOR map key order (sorted by UTF-8 byte length, then lexicographically):
        // "pubKey" (6), "mtcProof" (8), "notAfter" (8), "rootHash" (8),
        // "notBefore" (9), "deviceSerial" (12), "firmwareVersion" (15)
        cbor_map_options! {
            "pubKey" => debug.pub_key,
            "mtcProof" => debug.mtc_proof,
            "notAfter" => debug.not_after,
            "rootHash" => debug.root_hash,
            "notBefore" => debug.not_before,
            "deviceSerial" => debug.device_serial,
            "firmwareVersion" => debug.firmware_version,
        }
    }
}

impl TryFrom<cbor::Value> for MtcDebugOutput {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                "pubKey" => pub_key,
                "mtcProof" => mtc_proof,
                "notAfter" => not_after,
                "rootHash" => root_hash,
                "notBefore" => not_before,
                "deviceSerial" => device_serial,
                "firmwareVersion" => firmware_version,
            } = extract_map(cbor_value)?;
        }
        Ok(Self {
            pub_key: extract_byte_string(ok_or_missing(pub_key)?)?,
            mtc_proof: mtc_proof.map(extract_byte_string).transpose()?,
            not_after: not_after.map(extract_unsigned).transpose()?,
            root_hash: root_hash.map(extract_byte_string).transpose()?,
            not_before: not_before.map(extract_unsigned).transpose()?,
            device_serial: device_serial.map(extract_text_string).transpose()?,
            firmware_version: firmware_version.map(extract_unsigned).transpose()?,
        })
    }
}

/// Provisioned MTC attestation material stored in `Attestation.certificate`.
///
/// Encoded as a canonical 2- to 6-element CBOR map:
/// `{ "fmt": "mtc", "x5c"?: bstr, "cKey"?: bstr, "cX5c"?: bstr, "keyRef"?: bool, "mtcCert": ... }`.
/// Because a 2- to 6-element CBOR map begins with `0xA2..=0xA6` and `"fmt"` (`\x63fmt`) while an X.509 DER
/// certificate always begins with `0x30` (ASN.1 `SEQUENCE`), `ProvisionedMtcAttestation::from_bytes`
/// unambiguously distinguishes MTC attestation material from legacy X.509 certificates while optionally
/// carrying the PQ batch X.509 DER certificate (`x5c`) and a second non-enterprise classical batch key
/// (`cKey`) + X.509 DER certificate (`cX5c`) for non-ML-DSA `MakeCredential` operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionedMtcAttestation {
    pub format: MtcAttestationFormat,
    pub cert: MtcCertDescriptor,
    pub x5c: Option<Vec<u8>>,
    pub classical_key: Option<Vec<u8>>,
    pub classical_x5c: Option<Vec<u8>>,
    /// When `true`, non-Enterprise `"mtc"` responses emit a compact 2-field `mtcKeyRef` (`{ caId, serial }`)
    /// in `attStmt.mtcCert` on the wire while retaining full `cert` metadata in flash for `"mtc-debug"`.
    pub key_ref: bool,
}

impl ProvisionedMtcAttestation {
    pub fn to_bytes(&self) -> CtapResult<Vec<u8>> {
        let cbor_val = cbor_map_options! {
            "fmt" => String::from(self.format.as_str()),
            "x5c" => self.x5c.clone(),
            "cKey" => self.classical_key.clone(),
            "cX5c" => self.classical_x5c.clone(),
            "keyRef" => if self.key_ref { Some(true) } else { None },
            "mtcCert" => self.cert.clone(),
        };
        let mut buf = Vec::new();
        cbor_write(cbor_val, &mut buf)?;
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Quick prefix check: CBOR maps start with 0xA0..=0xBF, whereas X.509 DER starts with 0x30.
        let first = *bytes.first()?;
        if (first & 0xE0) != 0xA0 {
            return None;
        }
        let cbor_val = cbor_read(bytes).ok()?;
        if matches!(first, 0xA2..=0xA6) && bytes.get(1..5) == Some(b"\x63fmt") {
            destructure_cbor_map! {
                let {
                    "fmt" => fmt,
                    "x5c" => x5c,
                    "cKey" => c_key,
                    "cX5c" => c_x5c,
                    "keyRef" => key_ref,
                    "mtcCert" => mtc_cert,
                } = extract_map(cbor_val).ok()?;
            }
            let fmt_str = extract_text_string(fmt?).ok()?;
            let format = MtcAttestationFormat::from_str(&fmt_str)?;
            let x5c = x5c.map(extract_byte_string).transpose().ok()?;
            let classical_key = c_key.map(extract_byte_string).transpose().ok()?;
            let classical_x5c = c_x5c.map(extract_byte_string).transpose().ok()?;
            let key_ref_flag = key_ref.map(extract_bool).transpose().ok()?.unwrap_or(false)
                || fmt_str == MTC_KEYREF_FORMAT_STR;
            let cert = MtcCertDescriptor::try_from(mtc_cert?).ok()?;
            Some(Self {
                format,
                cert,
                x5c,
                classical_key,
                classical_x5c,
                key_ref: key_ref_flag,
            })
        } else {
            // Bare MtcCertDescriptor (2-, 5-, or 6-element CBOR map): defaults to Mtc.
            let cert = MtcCertDescriptor::try_from(cbor_val).ok()?;
            let is_kr = cert.is_key_ref();
            Some(Self {
                format: MtcAttestationFormat::Mtc,
                cert,
                x5c: None,
                classical_key: None,
                classical_x5c: None,
                key_ref: is_kr,
            })
        }
    }

    /// Selects `"mtc"` using the provisioned keypair and `MtcCertDescriptor`
    /// based on CTAP 2.3 `attestationFormatsPreference` (`0x0B`), falling back to the provisioned default.
    pub fn select_format(&self, preference: Option<&[String]>) -> MtcAttestationFormat {
        if let Some(prefs) = preference {
            for pref in prefs {
                if let Some(matched) = MtcAttestationFormat::from_str(pref) {
                    return matched;
                }
            }
        }
        self.format
    }
}

/// Binary `MTCProof` structure per `draft-ietf-plants-merkle-tree-certs` §4.2:
///
/// ```text
/// struct {
///     MTCLogEntryExtension extensions<0..2^16-1>;
///     uint48 start;
///     uint48 end;
///     opaque inclusion_proof<0..2^16-1>;
///     Cosignature signatures<0..2^24-1>;
/// } MTCProof;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtcProof {
    pub extensions: Vec<u8>,
    pub start: u64,
    pub end: u64,
    pub inclusion_proof: Vec<[u8; HASH_SIZE]>,
    pub signatures: Vec<u8>,
}

const MAX_UINT48: u64 = 0x0000_FFFF_FFFF_FFFF;

impl MtcProof {
    /// Creates a Landmark-Relative `MTCProof` (zero cosignatures on the wire).
    pub fn new_landmark(start: u64, end: u64, inclusion_proof: Vec<[u8; HASH_SIZE]>) -> Self {
        Self {
            extensions: Vec::new(),
            start,
            end,
            inclusion_proof,
            signatures: Vec::new(),
        }
    }

    /// Serializes `MTCProof` using TLS presentation language encoding (`draft-ietf-plants-merkle-tree-certs` §4.2).
    pub fn to_tls_bytes(&self) -> Option<Vec<u8>> {
        if self.start > MAX_UINT48 || self.end > MAX_UINT48 {
            return None;
        }
        let ext_len = u16::try_from(self.extensions.len()).ok()?;
        let proof_bytes_len = u16::try_from(self.inclusion_proof.len() * HASH_SIZE).ok()?;
        if self.signatures.len() > 0x00FF_FFFF {
            return None;
        }

        let total_len =
            2 + self.extensions.len() + 6 + 6 + 2 + (self.inclusion_proof.len() * HASH_SIZE) + 3 + self.signatures.len();
        let mut out = Vec::with_capacity(total_len);

        // extensions<0..2^16-1>
        out.extend_from_slice(&ext_len.to_be_bytes());
        out.extend_from_slice(&self.extensions);

        // uint48 start
        let start_be = self.start.to_be_bytes();
        out.extend_from_slice(&start_be[2..8]);

        // uint48 end
        let end_be = self.end.to_be_bytes();
        out.extend_from_slice(&end_be[2..8]);

        // opaque inclusion_proof<0..2^16-1>
        out.extend_from_slice(&proof_bytes_len.to_be_bytes());
        for node in &self.inclusion_proof {
            out.extend_from_slice(node);
        }

        // Cosignature signatures<0..2^24-1>
        let sig_len = self.signatures.len();
        out.push(((sig_len >> 16) & 0xFF) as u8);
        out.push(((sig_len >> 8) & 0xFF) as u8);
        out.push((sig_len & 0xFF) as u8);
        out.extend_from_slice(&self.signatures);

        Some(out)
    }

    /// Deserializes `MTCProof` from TLS presentation bytes.
    pub fn from_tls_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let ext_len = BigEndian::read_u16(&bytes[0..2]) as usize;
        let mut pos = 2;
        if bytes.len() < pos + ext_len + 6 + 6 + 2 {
            return None;
        }
        let extensions = bytes[pos..pos + ext_len].to_vec();
        pos += ext_len;

        let mut start_buf = [0u8; 8];
        start_buf[2..8].copy_from_slice(&bytes[pos..pos + 6]);
        let start = u64::from_be_bytes(start_buf);
        pos += 6;

        let mut end_buf = [0u8; 8];
        end_buf[2..8].copy_from_slice(&bytes[pos..pos + 6]);
        let end = u64::from_be_bytes(end_buf);
        pos += 6;

        let proof_bytes_len = BigEndian::read_u16(&bytes[pos..pos + 2]) as usize;
        pos += 2;
        if proof_bytes_len % HASH_SIZE != 0 || bytes.len() < pos + proof_bytes_len + 3 {
            return None;
        }
        let num_nodes = proof_bytes_len / HASH_SIZE;
        let mut inclusion_proof = Vec::with_capacity(num_nodes);
        for i in 0..num_nodes {
            let mut node = [0u8; HASH_SIZE];
            node.copy_from_slice(&bytes[pos + i * HASH_SIZE..pos + (i + 1) * HASH_SIZE]);
            inclusion_proof.push(node);
        }
        pos += proof_bytes_len;

        let sig_len =
            ((bytes[pos] as usize) << 16) | ((bytes[pos + 1] as usize) << 8) | (bytes[pos + 2] as usize);
        pos += 3;
        if bytes.len() != pos + sig_len {
            return None;
        }
        let signatures = bytes[pos..pos + sig_len].to_vec();

        Some(Self {
            extensions,
            start,
            end,
            inclusion_proof,
            signatures,
        })
    }
}

/// Deterministic FIDO MTC issuance log entry (`FidoMtcLogEntry`).
///
/// Binds the batch/enterprise attestation key (`pub_key_hash = SHA-256(pubKey)`) to its
/// `ca_id`, `serial` (`(log_number << 48) | index`), validity window, `aaguid`, and optional `fw_version`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidoMtcLogEntry {
    pub ca_id: Vec<u8>,
    pub serial: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub aaguid: [u8; AAGUID_LENGTH],
    pub fw_version: Option<u64>,
    pub pub_key_hash: [u8; HASH_SIZE],
    pub extensions: Vec<u8>,
}

impl FidoMtcLogEntry {
    /// Serializes the log entry for Merkle leaf hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.ca_id.len() + 8 + 8 + 8 + 16 + 9 + 32 + 2 + self.extensions.len());
        let ca_len = self.ca_id.len() as u16;
        out.extend_from_slice(&ca_len.to_be_bytes());
        out.extend_from_slice(&self.ca_id);
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.aaguid);
        match self.fw_version {
            Some(fw) => {
                out.push(1);
                out.extend_from_slice(&fw.to_be_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.pub_key_hash);
        let ext_len = self.extensions.len() as u16;
        out.extend_from_slice(&ext_len.to_be_bytes());
        out.extend_from_slice(&self.extensions);
        out
    }

    /// Computes RFC 9162 §2.1.1 Merkle Tree Leaf Hash: `SHA-256(0x00 || entry_bytes)`.
    pub fn leaf_hash<S: Sha256>(&self) -> [u8; HASH_SIZE] {
        let entry_bytes = self.to_bytes();
        let mut data = Vec::with_capacity(1 + entry_bytes.len());
        data.push(0x00);
        data.extend_from_slice(&entry_bytes);
        S::digest(&data)
    }
}

/// Computes RFC 9162 §2.1.1 Merkle Tree Interior Node Hash: `SHA-256(0x01 || left || right)`.
pub fn merkle_node_hash<S: Sha256>(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut buf = [0u8; 1 + 2 * HASH_SIZE];
    buf[0] = 0x01;
    buf[1..1 + HASH_SIZE].copy_from_slice(left);
    buf[1 + HASH_SIZE..].copy_from_slice(right);
    S::digest(&buf)
}

/// Largest power of two strictly less than `n` (for `n >= 2`), per RFC 9162 §2.1.1.
fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while (k << 1) < n {
        k <<= 1;
    }
    k
}

/// Computes the RFC 9162 §2.1.1 Merkle Tree Hash (`MTH`) over a slice of leaf hashes.
pub fn compute_subtree_hash<S: Sha256>(leaf_hashes: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
    match leaf_hashes.len() {
        0 => S::digest(&[]),
        1 => leaf_hashes[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = compute_subtree_hash::<S>(&leaf_hashes[..k]);
            let right = compute_subtree_hash::<S>(&leaf_hashes[k..]);
            merkle_node_hash::<S>(&left, &right)
        }
    }
}

/// Computes the RFC 9162 §2.1.3.1 Merkle audit path (`PATH(m, D_n)`) for leaf `m` in `leaf_hashes`.
pub fn compute_inclusion_proof<S: Sha256>(
    m: usize,
    leaf_hashes: &[[u8; HASH_SIZE]],
) -> Vec<[u8; HASH_SIZE]> {
    let n = leaf_hashes.len();
    assert!(m < n);
    if n <= 1 {
        return Vec::new();
    }
    let k = largest_power_of_two_less_than(n);
    if m < k {
        let mut path = compute_inclusion_proof::<S>(m, &leaf_hashes[..k]);
        path.push(compute_subtree_hash::<S>(&leaf_hashes[k..]));
        path
    } else {
        let mut path = compute_inclusion_proof::<S>(m - k, &leaf_hashes[k..]);
        path.push(compute_subtree_hash::<S>(&leaf_hashes[..k]));
        path
    }
}

/// Verifies an RFC 9162 §2.1.3.2 Merkle inclusion proof for leaf `index` in subtree `[start, end)`
/// (`draft-ietf-plants-merkle-tree-certs` §6.2 Step 5), returning `expected_subtree_hash`.
pub fn evaluate_inclusion_proof<S: Sha256>(
    index: u64,
    start: u64,
    end: u64,
    leaf_hash: &[u8; HASH_SIZE],
    inclusion_proof: &[[u8; HASH_SIZE]],
) -> Option<[u8; HASH_SIZE]> {
    if start >= end || index < start || index >= end {
        return None;
    }
    let mut fn_idx = index - start;
    let mut sn = (end - start) - 1;
    if sn == 0 {
        return if inclusion_proof.is_empty() {
            Some(*leaf_hash)
        } else {
            None
        };
    }
    let mut r = *leaf_hash;
    for p in inclusion_proof {
        if sn == 0 {
            return None;
        }
        if (fn_idx & 1) == 1 || fn_idx == sn {
            r = merkle_node_hash::<S>(p, &r);
            while (fn_idx & 1) == 0 && fn_idx != 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            r = merkle_node_hash::<S>(&r, p);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return None;
    }
    Some(r)
}

/// Computes the 32-byte Merkle subtree root hash from a provisioned `MtcCertDescriptor`,
/// canonical CBOR `COSE_Key` bytes (`pub_key_bytes`), and 16-byte `aaguid`.
pub fn compute_mtc_root_hash<S: Sha256>(
    mtc_cert: &MtcCertDescriptor,
    pub_key_bytes: &[u8],
    aaguid: &[u8; AAGUID_LENGTH],
) -> Option<[u8; HASH_SIZE]> {
    let proof = MtcProof::from_tls_bytes(&mtc_cert.mtc_proof)?;
    let index = mtc_cert.serial & MAX_UINT48;
    let pub_key_hash = S::digest(pub_key_bytes);
    let log_entry = FidoMtcLogEntry {
        ca_id: mtc_cert.ca_id.clone(),
        serial: mtc_cert.serial,
        not_before: mtc_cert.not_before,
        not_after: mtc_cert.not_after,
        aaguid: *aaguid,
        fw_version: mtc_cert.firmware_version,
        pub_key_hash,
        extensions: proof.extensions,
    };
    let leaf_hash = log_entry.leaf_hash::<S>();
    evaluate_inclusion_proof::<S>(
        index,
        proof.start,
        proof.end,
        &leaf_hash,
        &proof.inclusion_proof,
    )
}

/// Extracts `MtcDebugOutput` from `authenticatorData` when `ED_FLAG` (`0x80`) is set
/// and `"mtc-debug"` is present in the trailing CBOR extensions map.
pub fn extract_mtc_debug_from_auth_data(auth_data: &[u8]) -> Option<MtcDebugOutput> {
    if auth_data.len() < 55 || (auth_data[32] & 0x80) == 0 {
        return None;
    }
    let cred_id_len = BigEndian::read_u16(&auth_data[53..55]) as usize;
    let rest = auth_data.get(55 + cred_id_len..)?;
    for split in (1..rest.len()).rev() {
        if (rest[split] & 0xE0) != 0xA0 {
            continue;
        }
        if cbor_read(&rest[..split]).is_ok()
            && let Ok(ext_val) = cbor_read(&rest[split..])
            && let Ok(ext_map) = extract_map(ext_val)
        {
            for (k, v) in ext_map {
                if extract_text_string(k).as_deref() == Ok("mtc-debug") {
                    return MtcDebugOutput::try_from(v).ok();
                }
            }
        }
    }
    None
}

/// Pre-authenticated Landmark Subtree entry distributed via FIDO MDS (`MtcTrustAnchor.trustedSubtrees`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtcSubtree {
    pub start: u64,
    pub end: u64,
    pub subtree_hash: [u8; HASH_SIZE],
}

/// Revoked serial number range (`[min_serial, max_serial]` inclusive) per `draft-ietf-plants-merkle-tree-certs` §6.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtcRevokedSerialRange {
    pub min_serial: u64,
    pub max_serial: u64,
}

/// FIDO MDS Trust Anchor for `mtc` attestation verification (`MetadataStatement.mtcTrustAnchors`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtcTrustAnchor {
    pub ca_id: Vec<u8>,
    pub log_number: u16,
    pub trusted_subtrees: Vec<MtcSubtree>,
    pub revoked_serial_ranges: Vec<MtcRevokedSerialRange>,
    /// Batch public keys `(serial, canonical_cose_key_bytes)` distributed via MDS/log.
    pub batch_keys: Vec<(u64, Vec<u8>)>,
}

/// Error returned during Relying Party verification of an `"mtc"` attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtcVerificationError {
    UnsupportedFormat,
    MissingMtcCert,
    UntrustedCaId,
    LogNumberMismatch,
    CertificateExpiredOrNotYetValid,
    CertificateRevoked,
    BatchPublicKeyNotFoundInMds,
    InvalidMtcProofEncoding,
    InclusionProofFailed,
    SubtreeNotTrusted,
    InvalidAuthData,
}

/// Relying Party verification of the MTC certificate (`mtcEntryDesc` or proof-less `mtcKeyRef`),
/// log entry reconstruction, and landmark proof (WebAuthn Level 4 §8.10).
///
/// Returns the resolved canonical CBOR-encoded `COSE_Key` bytes of the attestation public key
/// so the caller can verify `attStmt.sig` over `authenticatorData || clientDataHash`.
pub fn verify_mtc_cert_and_resolve_pubkey<S: Sha256>(
    fmt: &str,
    inline_pub_key: Option<&[u8]>,
    mtc_cert: &MtcCertDescriptor,
    auth_data: &[u8],
    trust_anchor: &MtcTrustAnchor,
    current_timestamp: u64,
) -> Result<Vec<u8>, MtcVerificationError> {
    // 1. Extract AAGUID from authenticatorData[37..53] and optional "mtc-debug" extension output.
    if auth_data.len() < 53 {
        return Err(MtcVerificationError::InvalidAuthData);
    }
    let mut aaguid = [0u8; AAGUID_LENGTH];
    aaguid.copy_from_slice(&auth_data[37..53]);
    let debug_out = extract_mtc_debug_from_auth_data(auth_data);

    // 2. Verify CA ID, Log Number, and serial range revocation.
    if mtc_cert.ca_id != trust_anchor.ca_id {
        return Err(MtcVerificationError::UntrustedCaId);
    }
    let log_number = (mtc_cert.serial >> 48) as u16;
    let index = mtc_cert.serial & MAX_UINT48;
    if log_number != trust_anchor.log_number {
        return Err(MtcVerificationError::LogNumberMismatch);
    }
    for range in &trust_anchor.revoked_serial_ranges {
        if mtc_cert.serial >= range.min_serial && mtc_cert.serial <= range.max_serial {
            return Err(MtcVerificationError::CertificateRevoked);
        }
    }

    // 3. Resolve attestation public key for "mtc":
    //    `attStmt.pubKey` is never present in `fmt: "mtc"`; RPs resolve the public key from
    //    `trust_anchor.batch_keys` by `serial`, or from `debug_out.pub_key` (when `"mtc-debug"` was requested).
    if MtcAttestationFormat::from_str(fmt).is_none() || inline_pub_key.is_some() {
        return Err(MtcVerificationError::UnsupportedFormat);
    }
    let resolved_pub_key = trust_anchor
        .batch_keys
        .iter()
        .find(|(serial, _)| *serial == mtc_cert.serial)
        .map(|(_, pk)| pk.clone())
        .or_else(|| debug_out.as_ref().map(|d| d.pub_key.clone()))
        .ok_or(MtcVerificationError::BatchPublicKeyNotFoundInMds)?;

    // 4. Resolve metadata and inclusion proof from `mtcEntryDesc` or `mtc-debug` (for `mtcKeyRef`).
    let (eff_not_before, eff_not_after, eff_fw_version, eff_proof_bytes) = if mtc_cert.is_key_ref() {
        if let Some(ref d) = debug_out
            && let (Some(nb), Some(na)) = (d.not_before, d.not_after)
        {
            (
                nb,
                na,
                d.firmware_version,
                d.mtc_proof.clone().unwrap_or_default(),
            )
        } else {
            // Pure manifest-assisted proof-less `mtcKeyRef` verification (WebAuthn Level 4 §8.10 Step 3):
            // Verify that `index` falls within a trusted subtree in `trust_anchor.trusted_subtrees`.
            let in_subtree = trust_anchor
                .trusted_subtrees
                .iter()
                .any(|st| index >= st.start && index < st.end);
            if !in_subtree {
                return Err(MtcVerificationError::SubtreeNotTrusted);
            }
            return Ok(resolved_pub_key);
        }
    } else {
        (
            mtc_cert.not_before,
            mtc_cert.not_after,
            mtc_cert.firmware_version,
            if !mtc_cert.mtc_proof.is_empty() {
                mtc_cert.mtc_proof.clone()
            } else {
                debug_out
                    .as_ref()
                    .and_then(|d| d.mtc_proof.clone())
                    .unwrap_or_default()
            },
        )
    };

    // 5. Verify validity window (`draft-ietf-plants-merkle-tree-certs` §6.2 Step 2).
    if current_timestamp < eff_not_before || current_timestamp > eff_not_after {
        return Err(MtcVerificationError::CertificateExpiredOrNotYetValid);
    }

    // 6. Parse MTCProof and reconstruct FidoMtcLogEntry (`draft-ietf-plants-merkle-tree-certs` §6.2 Steps 4-5).
    let proof = MtcProof::from_tls_bytes(&eff_proof_bytes)
        .ok_or(MtcVerificationError::InvalidMtcProofEncoding)?;
    let pub_key_hash = S::digest(&resolved_pub_key);
    let extensions = if !proof.extensions.is_empty() {
        proof.extensions.clone()
    } else if let Some(ref d) = debug_out
        && let Some(ref serial_str) = d.device_serial
    {
        serial_str.as_bytes().to_vec()
    } else {
        Vec::new()
    };
    let log_entry = FidoMtcLogEntry {
        ca_id: mtc_cert.ca_id.clone(),
        serial: mtc_cert.serial,
        not_before: eff_not_before,
        not_after: eff_not_after,
        aaguid,
        fw_version: eff_fw_version,
        pub_key_hash,
        extensions,
    };
    let leaf_hash = log_entry.leaf_hash::<S>();
    let expected_subtree_hash = evaluate_inclusion_proof::<S>(
        index,
        proof.start,
        proof.end,
        &leaf_hash,
        &proof.inclusion_proof,
    )
    .ok_or(MtcVerificationError::InclusionProofFailed)?;

    if let Some(ref d) = debug_out
        && let Some(ref rh) = d.root_hash
        && rh.as_slice() != expected_subtree_hash
    {
        return Err(MtcVerificationError::SubtreeNotTrusted);
    }

    // 7. Verify that `(proof.start, proof.end, expected_subtree_hash)` matches a Landmark Subtree in MDS.
    let matched = trust_anchor.trusted_subtrees.iter().any(|st| {
        st.start == proof.start && st.end == proof.end && st.subtree_hash == expected_subtree_hash
    });
    if !matched {
        return Err(MtcVerificationError::SubtreeNotTrusted);
    }

    Ok(resolved_pub_key)
}
