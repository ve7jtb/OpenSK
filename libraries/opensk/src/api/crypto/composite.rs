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

//! PQ/T Hybrid Composite Signatures for COSE (`draft-ietf-jose-pq-composite-sigs-05`
//! and `draft-ietf-lamps-pq-composite-sigs-19`).
//!
//! Implements the 6 registered COSE composite signature algorithms:
//! - `ML-DSA-44-ES256` (`-54`)
//! - `ML-DSA-65-ES256` (`-55`)
//! - `ML-DSA-87-ES384` (`-56`)
//! - `ML-DSA-44-Ed25519` (`-57`)
//! - `ML-DSA-65-Ed25519` (`-58`)
//! - `ML-DSA-87-Ed448` (`-59`)

use crate::api::crypto::EC_FIELD_SIZE;
use crate::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature};
use crate::api::crypto::ec_signing::{EdPublicKey, EdSecretKey, EdSignature};
use crate::api::crypto::ed448::{ED448_KEY_SIZE, Ed448SecretKey};
use crate::api::crypto::es384::{ES384_FIELD_SIZE, Es384SecretKey};
use crate::api::crypto::mldsa::{
    ML_DSA_44_PK_SIZE, ML_DSA_65_PK_SIZE, ML_DSA_87_PK_SIZE, ML_DSA_SEED_SIZE, MlDsaSecretKey,
    MlDsaVariant,
};
use crate::api::crypto::sha256::Sha256;
use crate::env::{EcdsaSk, Ed25519Sk, Env, Sha};
use alloc::vec::Vec;
use sha2::{Digest, Sha512};
use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

/// Fixed 32-byte ASCII prefix `"CompositeAlgorithmSignatures2025"` (`0x436f...32303235`).
pub const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Domain separator labels from `draft-ietf-lamps-pq-composite-sigs-19` / `draft-ietf-jose-pq-composite-sigs-05`.
pub const LABEL_MLDSA44_ES256: &[u8] = b"COMPSIG-MLDSA44-ECDSA-P256-SHA256";
pub const LABEL_MLDSA65_ES256: &[u8] = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";
pub const LABEL_MLDSA87_ES384: &[u8] = b"COMPSIG-MLDSA87-ECDSA-P384-SHA512";
pub const LABEL_MLDSA44_ED25519: &[u8] = b"COMPSIG-MLDSA44-Ed25519-SHA512";
pub const LABEL_MLDSA65_ED25519: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";
pub const LABEL_MLDSA87_ED448: &[u8] = b"COMPSIG-MLDSA87-Ed448-SHAKE256";

/// Serialized composite public key sizes (`mldsaPK || tradPK`).
pub const ML_DSA_44_ES256_PK_SIZE: usize = ML_DSA_44_PK_SIZE + 1 + 2 * EC_FIELD_SIZE; // 1312 + 65 = 1377
pub const ML_DSA_65_ES256_PK_SIZE: usize = ML_DSA_65_PK_SIZE + 1 + 2 * EC_FIELD_SIZE; // 1952 + 65 = 2017
pub const ML_DSA_87_ES384_PK_SIZE: usize = ML_DSA_87_PK_SIZE + 1 + 2 * ES384_FIELD_SIZE; // 2592 + 97 = 2689
pub const ML_DSA_44_ED25519_PK_SIZE: usize = ML_DSA_44_PK_SIZE + EC_FIELD_SIZE; // 1312 + 32 = 1344
pub const ML_DSA_65_ED25519_PK_SIZE: usize = ML_DSA_65_PK_SIZE + EC_FIELD_SIZE; // 1952 + 32 = 1984
pub const ML_DSA_87_ED448_PK_SIZE: usize = ML_DSA_87_PK_SIZE + ED448_KEY_SIZE; // 2592 + 57 = 2649

/// RFC 5915 `ECPrivateKey` DER header/footer for P-256 (`secp256r1`, OID `1.2.840.10045.3.1.7`, 51 bytes total).
const P256_RFC5915_PREFIX: [u8; 7] = [0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
const P256_RFC5915_SUFFIX: [u8; 12] = [
    0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

/// RFC 5915 `ECPrivateKey` DER header/footer for P-384 (`secp384r1`, OID `1.3.132.0.34`, 64 bytes total).
const P384_RFC5915_PREFIX: [u8; 7] = [0x30, 0x3e, 0x02, 0x01, 0x01, 0x04, 0x30];
const P384_RFC5915_SUFFIX: [u8; 9] = [0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

/// COSE PQ/T composite signature algorithm variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositeVariant {
    MlDsa44Es256,
    MlDsa65Es256,
    MlDsa87Es384,
    MlDsa44Ed25519,
    MlDsa65Ed25519,
    MlDsa87Ed448,
}

impl CompositeVariant {
    /// Returns the underlying ML-DSA parameter set for this composite algorithm.
    pub const fn mldsa_variant(self) -> MlDsaVariant {
        match self {
            Self::MlDsa44Es256 | Self::MlDsa44Ed25519 => MlDsaVariant::MlDsa44,
            Self::MlDsa65Es256 | Self::MlDsa65Ed25519 => MlDsaVariant::MlDsa65,
            Self::MlDsa87Es384 | Self::MlDsa87Ed448 => MlDsaVariant::MlDsa87,
        }
    }

    /// Returns the ASCII domain separator label (`Label`) for this composite algorithm.
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::MlDsa44Es256 => LABEL_MLDSA44_ES256,
            Self::MlDsa65Es256 => LABEL_MLDSA65_ES256,
            Self::MlDsa87Es384 => LABEL_MLDSA87_ES384,
            Self::MlDsa44Ed25519 => LABEL_MLDSA44_ED25519,
            Self::MlDsa65Ed25519 => LABEL_MLDSA65_ED25519,
            Self::MlDsa87Ed448 => LABEL_MLDSA87_ED448,
        }
    }

    /// Returns the expected serialized public key length (`mldsaPK || tradPK`).
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::MlDsa44Es256 => ML_DSA_44_ES256_PK_SIZE,
            Self::MlDsa65Es256 => ML_DSA_65_ES256_PK_SIZE,
            Self::MlDsa87Es384 => ML_DSA_87_ES384_PK_SIZE,
            Self::MlDsa44Ed25519 => ML_DSA_44_ED25519_PK_SIZE,
            Self::MlDsa65Ed25519 => ML_DSA_65_ED25519_PK_SIZE,
            Self::MlDsa87Ed448 => ML_DSA_87_ED448_PK_SIZE,
        }
    }

    /// Builds the composite message representative:
    /// `M' = Prefix || Label || len(ctx) || ctx || PH(M)` with empty context (`ctx = b""`).
    pub fn build_message_prime<E: Env>(self, message: &[u8]) -> Vec<u8> {
        let label = self.label();
        let mut m_prime = Vec::with_capacity(COMPOSITE_PREFIX.len() + label.len() + 1 + 64);
        m_prime.extend_from_slice(COMPOSITE_PREFIX);
        m_prime.extend_from_slice(label);
        m_prime.push(0x00); // len(ctx) = 0 in JOSE/COSE
        match self {
            Self::MlDsa44Es256 => {
                let ph = Sha::<E>::digest(message);
                m_prime.extend_from_slice(&ph);
            }
            Self::MlDsa65Es256
            | Self::MlDsa87Es384
            | Self::MlDsa44Ed25519
            | Self::MlDsa65Ed25519 => {
                let ph = Sha512::digest(message);
                m_prime.extend_from_slice(&ph);
            }
            Self::MlDsa87Ed448 => {
                let mut hasher = Shake256::default();
                hasher.update(message);
                let mut ph = [0u8; 64];
                hasher.finalize_xof().read(&mut ph);
                m_prime.extend_from_slice(&ph);
            }
        }
        m_prime
    }
}

/// Composite private key combining an `MlDsaSecretKey` and a traditional signing key.
pub enum CompositeSecretKey<E: Env> {
    Es256 {
        variant: CompositeVariant,
        mldsa: MlDsaSecretKey,
        trad: EcdsaSk<E>,
        seed: Option<[u8; ML_DSA_SEED_SIZE]>,
    },
    Es384 {
        variant: CompositeVariant,
        mldsa: MlDsaSecretKey,
        trad: Es384SecretKey,
        seed: Option<[u8; ML_DSA_SEED_SIZE]>,
    },
    Ed25519 {
        variant: CompositeVariant,
        mldsa: MlDsaSecretKey,
        trad: Ed25519Sk<E>,
        seed: Option<[u8; ML_DSA_SEED_SIZE]>,
    },
    Ed448 {
        variant: CompositeVariant,
        mldsa: MlDsaSecretKey,
        trad: Ed448SecretKey,
        seed: Option<[u8; ML_DSA_SEED_SIZE]>,
    },
}

#[cfg(test)]
impl<E: Env> PartialEq for CompositeSecretKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.variant() == other.variant() && self.export() == other.export()
    }
}

impl<E: Env> CompositeSecretKey<E> {
    /// Derives both component private keys deterministically from a 32-byte master seed.
    pub fn from_master_seed(variant: CompositeVariant, master_seed: [u8; ML_DSA_SEED_SIZE]) -> Option<Self> {
        let mut hasher = Shake256::default();
        hasher.update(b"OpenSK-Composite-KeyGen-v1");
        hasher.update(variant.label());
        hasher.update(&master_seed);
        let mut reader = hasher.finalize_xof();

        let mut mldsa_seed = [0u8; ML_DSA_SEED_SIZE];
        reader.read(&mut mldsa_seed);
        let mldsa = MlDsaSecretKey::import(variant.mldsa_variant(), &mldsa_seed)?;

        match variant {
            CompositeVariant::MlDsa44Es256 | CompositeVariant::MlDsa65Es256 => {
                for _ in 0..8 {
                    let mut trad_bytes = [0u8; EC_FIELD_SIZE];
                    reader.read(&mut trad_bytes);
                    if let Some(trad) = EcdsaSk::<E>::import(&trad_bytes) {
                        return Some(Self::Es256 {
                            variant,
                            mldsa,
                            trad,
                            seed: Some(master_seed),
                        });
                    }
                }
                None
            }
            CompositeVariant::MlDsa87Es384 => {
                for _ in 0..8 {
                    let mut trad_bytes = [0u8; ES384_FIELD_SIZE];
                    reader.read(&mut trad_bytes);
                    if let Some(trad) = Es384SecretKey::import(&trad_bytes) {
                        return Some(Self::Es384 {
                            variant,
                            mldsa,
                            trad,
                            seed: Some(master_seed),
                        });
                    }
                }
                None
            }
            CompositeVariant::MlDsa44Ed25519 | CompositeVariant::MlDsa65Ed25519 => {
                let mut trad_bytes = [0u8; EC_FIELD_SIZE];
                reader.read(&mut trad_bytes);
                let trad = Ed25519Sk::<E>::import(&trad_bytes)?;
                Some(Self::Ed25519 {
                    variant,
                    mldsa,
                    trad,
                    seed: Some(master_seed),
                })
            }
            CompositeVariant::MlDsa87Ed448 => {
                let mut trad_bytes = [0u8; ED448_KEY_SIZE];
                reader.read(&mut trad_bytes);
                let trad = Ed448SecretKey::import(&trad_bytes)?;
                Some(Self::Ed448 {
                    variant,
                    mldsa,
                    trad,
                    seed: Some(master_seed),
                })
            }
        }
    }

    /// Deterministically expands a 3-byte nonce into a 32-byte master seed using SHAKE256 XOF.
    pub fn expand_short_nonce(nonce: [u8; 3]) -> [u8; ML_DSA_SEED_SIZE] {
        let mut seed = [0u8; ML_DSA_SEED_SIZE];
        seed[..3].copy_from_slice(&nonce);
        let mut hasher = Shake256::default();
        hasher.update(b"OpenSK-Short-Nonce-DRBG");
        hasher.update(&nonce);
        hasher.finalize_xof().read(&mut seed[3..]);
        seed
    }

    /// Generates a new random composite signing key for the given `CompositeVariant`.
    pub fn random(env: &mut E, variant: CompositeVariant) -> Self {
        use rand_core::RngCore;
        loop {
            let master_seed = match variant {
                CompositeVariant::MlDsa87Es384 | CompositeVariant::MlDsa87Ed448 => {
                    let mut nonce = [0u8; 3];
                    env.rng().fill_bytes(&mut nonce);
                    Self::expand_short_nonce(nonce)
                }
                _ => {
                    let mut s = [0u8; ML_DSA_SEED_SIZE];
                    env.rng().fill_bytes(&mut s);
                    s
                }
            };
            if let Some(sk) = Self::from_master_seed(variant, master_seed) {
                return sk;
            }
        }
    }

    /// Returns the composite algorithm variant.
    pub fn variant(&self) -> CompositeVariant {
        match self {
            Self::Es256 { variant, .. }
            | Self::Es384 { variant, .. }
            | Self::Ed25519 { variant, .. }
            | Self::Ed448 { variant, .. } => *variant,
        }
    }

    /// Serializes the composite public key `mldsaPK || tradPK` per
    /// `draft-ietf-lamps-pq-composite-sigs-19` §4.1 and `draft-ietf-jose-pq-composite-sigs-05` §4.1.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let variant = self.variant();
        let mut out = Vec::with_capacity(variant.public_key_size());
        match self {
            Self::Es256 { mldsa, trad, .. } => {
                out.extend_from_slice(&mldsa.public_key_bytes());
                let mut x = [0u8; EC_FIELD_SIZE];
                let mut y = [0u8; EC_FIELD_SIZE];
                trad.public_key().to_coordinates(&mut x, &mut y);
                out.push(0x04);
                out.extend_from_slice(&x);
                out.extend_from_slice(&y);
            }
            Self::Es384 { mldsa, trad, .. } => {
                out.extend_from_slice(&mldsa.public_key_bytes());
                let (x, y) = trad.public_key_coordinates();
                out.push(0x04);
                out.extend_from_slice(&x);
                out.extend_from_slice(&y);
            }
            Self::Ed25519 { mldsa, trad, .. } => {
                out.extend_from_slice(&mldsa.public_key_bytes());
                let mut pk = [0u8; EC_FIELD_SIZE];
                trad.public_key().to_slice(&mut pk);
                out.extend_from_slice(&pk);
            }
            Self::Ed448 { mldsa, trad, .. } => {
                out.extend_from_slice(&mldsa.public_key_bytes());
                out.extend_from_slice(&trad.public_key_bytes());
            }
        }
        out
    }

    /// Signs a message per `Composite-ML-DSA.Sign` (`draft-ietf-lamps-pq-composite-sigs-19` §3.2):
    /// 1. `M' = Prefix || Label || 0x00 || PH(M)`
    /// 2. `mldsaSig = ML-DSA.Sign(mldsaSK, M', ctx = Label)`
    /// 3. `tradSig = Trad.Sign(tradSK, M')`
    /// 4. `sig = mldsaSig || tradSig`
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let variant = self.variant();
        let label = variant.label();
        let m_prime = variant.build_message_prime::<E>(message);
        match self {
            Self::Es256 { mldsa, trad, .. } => {
                let mut sig = mldsa.sign_with_ctx(&m_prime, label);
                let trad_sig = trad.sign(&m_prime).to_der();
                sig.extend_from_slice(&trad_sig);
                sig
            }
            Self::Es384 { mldsa, trad, .. } => {
                let mut sig = mldsa.sign_with_ctx(&m_prime, label);
                let trad_sig = trad.sign_der(&m_prime);
                sig.extend_from_slice(&trad_sig);
                sig
            }
            Self::Ed25519 { mldsa, trad, .. } => {
                let mut sig = mldsa.sign_with_ctx(&m_prime, label);
                let trad_sig = trad.sign(&m_prime).to_bytes();
                sig.extend_from_slice(&trad_sig);
                sig
            }
            Self::Ed448 { mldsa, trad, .. } => {
                let mut sig = mldsa.sign_with_ctx(&m_prime, label);
                let trad_sig = trad.sign(&m_prime);
                sig.extend_from_slice(&trad_sig);
                sig
            }
        }
    }

    /// Exports the serialized composite private key (32-byte master seed when generated locally,
    /// or `mldsaSeed || tradSK` per `draft-ietf-lamps-pq-composite-sigs-19` §4.2).
    pub fn export(&self) -> Vec<u8> {
        match self {
            Self::Es256 { seed: Some(s), .. }
            | Self::Es384 { seed: Some(s), .. }
            | Self::Ed25519 { seed: Some(s), .. }
            | Self::Ed448 { seed: Some(s), .. } => return s.to_vec(),
            _ => {}
        }
        match self {
            Self::Es256 { mldsa, trad, .. } => {
                let mldsa_seed = mldsa.export();
                let trad_raw = trad.export();
                if trad_raw.len() == EC_FIELD_SIZE {
                    let mut out = Vec::with_capacity(
                        ML_DSA_SEED_SIZE
                            + P256_RFC5915_PREFIX.len()
                            + EC_FIELD_SIZE
                            + P256_RFC5915_SUFFIX.len(),
                    );
                    out.extend_from_slice(&mldsa_seed);
                    out.extend_from_slice(&P256_RFC5915_PREFIX);
                    out.extend_from_slice(&trad_raw);
                    out.extend_from_slice(&P256_RFC5915_SUFFIX);
                    out
                } else {
                    let mut out = Vec::with_capacity(ML_DSA_SEED_SIZE + trad_raw.len());
                    out.extend_from_slice(&mldsa_seed);
                    out.extend_from_slice(&trad_raw);
                    out
                }
            }
            Self::Es384 { mldsa, trad, .. } => {
                let mldsa_seed = mldsa.export();
                let trad_raw = trad.export();
                let mut out = Vec::with_capacity(
                    ML_DSA_SEED_SIZE
                        + P384_RFC5915_PREFIX.len()
                        + ES384_FIELD_SIZE
                        + P384_RFC5915_SUFFIX.len(),
                );
                out.extend_from_slice(&mldsa_seed);
                out.extend_from_slice(&P384_RFC5915_PREFIX);
                out.extend_from_slice(&trad_raw);
                out.extend_from_slice(&P384_RFC5915_SUFFIX);
                out
            }
            Self::Ed25519 { mldsa, trad, .. } => {
                let mldsa_seed = mldsa.export();
                let trad_raw = trad.export();
                let seed_slice = if trad_raw.len() == 64 {
                    &trad_raw[..32]
                } else {
                    &trad_raw[..]
                };
                let mut out = Vec::with_capacity(ML_DSA_SEED_SIZE + seed_slice.len());
                out.extend_from_slice(&mldsa_seed);
                out.extend_from_slice(seed_slice);
                out
            }
            Self::Ed448 { mldsa, trad, .. } => {
                let mldsa_seed = mldsa.export();
                let trad_raw = trad.export();
                let mut out = Vec::with_capacity(ML_DSA_SEED_SIZE + trad_raw.len());
                out.extend_from_slice(&mldsa_seed);
                out.extend_from_slice(&trad_raw);
                out
            }
        }
    }

    /// Imports a composite private key from a 32-byte master seed or `mldsaSeed || tradSK`.
    ///
    /// Accepts both RFC 5915 `ECPrivateKey` DER and raw 32/48-byte scalars for `ES256`/`ES384`.
    pub fn import(variant: CompositeVariant, bytes: &[u8]) -> Option<Self> {
        if bytes.len() == ML_DSA_SEED_SIZE {
            let mut master_seed = [0u8; ML_DSA_SEED_SIZE];
            master_seed.copy_from_slice(bytes);
            return Self::from_master_seed(variant, master_seed);
        }
        if bytes.len() < ML_DSA_SEED_SIZE {
            return None;
        }
        let (mldsa_bytes, trad_bytes) = bytes.split_at(ML_DSA_SEED_SIZE);
        let mldsa = MlDsaSecretKey::import(variant.mldsa_variant(), mldsa_bytes)?;
        match variant {
            CompositeVariant::MlDsa44Es256 | CompositeVariant::MlDsa65Es256 => {
                let scalar_slice = if trad_bytes.len()
                    == P256_RFC5915_PREFIX.len() + EC_FIELD_SIZE + P256_RFC5915_SUFFIX.len()
                    && trad_bytes.starts_with(&P256_RFC5915_PREFIX)
                    && trad_bytes.ends_with(&P256_RFC5915_SUFFIX)
                {
                    &trad_bytes[P256_RFC5915_PREFIX.len()..P256_RFC5915_PREFIX.len() + EC_FIELD_SIZE]
                } else {
                    trad_bytes
                };
                let trad = EcdsaSk::<E>::import(scalar_slice)?;
                Some(Self::Es256 {
                    variant,
                    mldsa,
                    trad,
                    seed: None,
                })
            }
            CompositeVariant::MlDsa87Es384 => {
                let scalar_slice = if trad_bytes.len()
                    == P384_RFC5915_PREFIX.len() + ES384_FIELD_SIZE + P384_RFC5915_SUFFIX.len()
                    && trad_bytes.starts_with(&P384_RFC5915_PREFIX)
                    && trad_bytes.ends_with(&P384_RFC5915_SUFFIX)
                {
                    &trad_bytes
                        [P384_RFC5915_PREFIX.len()..P384_RFC5915_PREFIX.len() + ES384_FIELD_SIZE]
                } else {
                    trad_bytes
                };
                let trad = Es384SecretKey::import(scalar_slice)?;
                Some(Self::Es384 {
                    variant,
                    mldsa,
                    trad,
                    seed: None,
                })
            }
            CompositeVariant::MlDsa44Ed25519 | CompositeVariant::MlDsa65Ed25519 => {
                let trad = Ed25519Sk::<E>::import(trad_bytes)?;
                Some(Self::Ed25519 {
                    variant,
                    mldsa,
                    trad,
                    seed: None,
                })
            }
            CompositeVariant::MlDsa87Ed448 => {
                let trad = Ed448SecretKey::import(trad_bytes)?;
                Some(Self::Ed448 {
                    variant,
                    mldsa,
                    trad,
                    seed: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::crypto::mldsa::{
        ML_DSA_44_SIG_SIZE, ML_DSA_65_SIG_SIZE, ML_DSA_87_SIG_SIZE,
    };
    use crate::env::test::TestEnv;
    use sk_cbor as cbor;
    use sk_cbor::{cbor_array, cbor_bytes, cbor_map, cbor_text};

    fn decode_hex_ws(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut iter = s.bytes().filter(|b| !b.is_ascii_whitespace());
        while let Some(hi) = iter.next() {
            let lo = iter.next().expect("even number of hex digits");
            let h = match hi {
                b'0'..=b'9' => hi - b'0',
                b'a'..=b'f' => hi - b'a' + 10,
                b'A'..=b'F' => hi - b'A' + 10,
                _ => panic!("invalid hex char"),
            };
            let l = match lo {
                b'0'..=b'9' => lo - b'0',
                b'a'..=b'f' => lo - b'a' + 10,
                b'A'..=b'F' => lo - b'A' + 10,
                _ => panic!("invalid hex char"),
            };
            out.push((h << 4) | l);
        }
        out
    }

    fn build_cose_sig_structure(alg: i64, kid: &[u8], payload: &[u8]) -> Vec<u8> {
        let protected = cbor_map! {
            1 => alg,
            4 => kid,
        };
        let mut protected_bytes = Vec::new();
        cbor::write(protected, &mut protected_bytes).unwrap();
        let sig_structure = cbor_array![
            cbor_text!("Signature1"),
            cbor_bytes!(protected_bytes),
            cbor_bytes!(Vec::new()),
            cbor_bytes!(payload.to_vec()),
        ];
        let mut out = Vec::new();
        cbor::write(sig_structure, &mut out).unwrap();
        out
    }

    /// Official COSE test vector from `draft-ietf-jose-pq-composite-sigs-05` Appendix A.2 Figure 7 (`ML-DSA-44-ES256`, `-54`).
    #[test]
    fn test_ietf_cose_vector_mldsa44_es256() {
        let sk_hex = "
            0000000000000000000000000000000000000000000000000000000000000000
            3031020101042000000000000000000000000000000000000000000000000000
            00000000000001a00a06082a8648ce3d030107
        ";
        let expected_sk_bytes = decode_hex_ws(sk_hex);
        let sk = CompositeSecretKey::<TestEnv>::import(
            CompositeVariant::MlDsa44Es256,
            &expected_sk_bytes,
        )
        .expect("import ML-DSA-44-ES256 key");
        assert_eq!(sk.export(), expected_sk_bytes);

        let pk = sk.public_key_bytes();
        assert_eq!(pk.len(), ML_DSA_44_ES256_PK_SIZE);
        // Check prefix and suffix of public key from Figure 7
        assert_eq!(
            &pk[..16],
            decode_hex_ws("ba71f9f64e11baeb58fa9c6fbb6e14e6").as_slice()
        );
        assert_eq!(
            &pk[ML_DSA_44_PK_SIZE..],
            decode_hex_ws(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2
                 964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            )
            .as_slice()
        );

        let kid = decode_hex_ws("08e7acdb81ec1e3e");
        let payload = decode_hex_ws("68656c6c6f20706f7374207175616e74756d207369676e617475726573");
        let sig_structure = build_cose_sig_structure(-54, &kid, &payload);

        let expected_m_prime = decode_hex_ws(
            "436f6d706f73697465416c676f726974686d5369676e61747572657332303235
             434f4d505349472d4d4c44534134342d45434453412d503235362d5348413235
             3600ad9c56542caaef74ac6ad7cbf62386c2f4aac8c329e4a6a614fd272572cc
             bead",
        );
        let m_prime = CompositeVariant::MlDsa44Es256.build_message_prime::<TestEnv>(&sig_structure);
        assert_eq!(m_prime, expected_m_prime);

        let sig = sk.sign(&sig_structure);
        // Verify ML-DSA-44 component matches Figure 7 byte-for-byte
        assert_eq!(
            &sig[..32],
            decode_hex_ws("2a2fa6272a8cabd04670e6adce8f462c9c905742f528d59012cb6ad1aabe8734")
                .as_slice()
        );
        assert_eq!(
            &sig[ML_DSA_44_SIG_SIZE - 16..ML_DSA_44_SIG_SIZE],
            decode_hex_ws("000000000000000000000000141f2c3a").as_slice()
        );
        // Verify P-256 ECDSA DER signature component over M'
        let trad_der = &sig[ML_DSA_44_SIG_SIZE..];
        let p256_vk =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk[ML_DSA_44_PK_SIZE..]).unwrap();
        let p256_sig = p256::ecdsa::Signature::from_der(trad_der).unwrap();
        use p256::ecdsa::signature::Verifier as _;
        assert!(p256_vk.verify(&m_prime, &p256_sig).is_ok());
    }

    /// Official COSE test vector from `draft-ietf-jose-pq-composite-sigs-05` Appendix A.2 Figure 8 (`ML-DSA-44-Ed25519`, `-57`).
    #[test]
    fn test_ietf_cose_vector_mldsa44_ed25519() {
        let expected_sk_bytes = vec![0u8; 64];
        let sk = CompositeSecretKey::<TestEnv>::import(
            CompositeVariant::MlDsa44Ed25519,
            &expected_sk_bytes,
        )
        .expect("import ML-DSA-44-Ed25519 key");
        assert_eq!(sk.export(), expected_sk_bytes);

        let pk = sk.public_key_bytes();
        assert_eq!(pk.len(), ML_DSA_44_ED25519_PK_SIZE);
        assert_eq!(
            &pk[ML_DSA_44_PK_SIZE..],
            decode_hex_ws("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
                .as_slice()
        );

        let kid = decode_hex_ws("b930f85dd9be4a04");
        let payload = decode_hex_ws("68656c6c6f20706f7374207175616e74756d207369676e617475726573");
        let sig_structure = build_cose_sig_structure(-57, &kid, &payload);

        let expected_m_prime = decode_hex_ws(
            "436f6d706f73697465416c676f726974686d5369676e61747572657332303235
             434f4d505349472d4d4c44534134342d456432353531392d53484135313200e1
             3c73e6534f34e69f9e2dfa19e812f1f92e308c477bf2eb351a47fa69e68af55e
             dea2a595419d44082ea6d38d0908d59ea3e97aac61ae9391dbe56c0e5b85eb",
        );
        let m_prime =
            CompositeVariant::MlDsa44Ed25519.build_message_prime::<TestEnv>(&sig_structure);
        assert_eq!(m_prime, expected_m_prime);

        let sig = sk.sign(&sig_structure);
        assert_eq!(sig.len(), ML_DSA_44_SIG_SIZE + 64);
        // Verify both ML-DSA-44 and Ed25519 components match Figure 8 byte-for-byte!
        assert_eq!(
            &sig[..32],
            decode_hex_ws("b90b8fd47a1c28cb219c3cfc816935c875de6c45578c2f0188e3be659eee9003")
                .as_slice()
        );
        assert_eq!(
            &sig[ML_DSA_44_SIG_SIZE - 20..],
            decode_hex_ws(
                "b5b7bbd5dbe8f5000000000000000000192b3847c9961e24ac6f9ffe772eeb6a
                 c83bccfd7c09891a34e65475b990a446c6dfe19c88afee71cf55978a927cc021
                 127ec31626c3284c31c05eb64cc58fcec24c9d06"
            )
            .as_slice()
        );
    }

    #[test]
    fn test_all_6_composite_variants_roundtrip() {
        let mut env = TestEnv::default();
        let variants = [
            (CompositeVariant::MlDsa44Es256, ML_DSA_44_SIG_SIZE),
            (CompositeVariant::MlDsa65Es256, ML_DSA_65_SIG_SIZE),
            (CompositeVariant::MlDsa87Es384, ML_DSA_87_SIG_SIZE),
            (CompositeVariant::MlDsa44Ed25519, ML_DSA_44_SIG_SIZE),
            (CompositeVariant::MlDsa65Ed25519, ML_DSA_65_SIG_SIZE),
            (CompositeVariant::MlDsa87Ed448, ML_DSA_87_SIG_SIZE),
        ];
        let msg = b"WebAuthn / CTAP2 composite signature test payload";
        for (variant, mldsa_sig_len) in variants {
            let sk = CompositeSecretKey::<TestEnv>::random(&mut env, variant);
            let exported = sk.export();
            // Ensure exported private key fits comfortably in stateless credential IDs (<= 96 bytes)
            assert!(exported.len() <= 96);
            let sk2 = CompositeSecretKey::<TestEnv>::import(variant, &exported).unwrap();
            assert!(sk == sk2);

            let pk = sk.public_key_bytes();
            assert_eq!(pk.len(), variant.public_key_size());

            let sig = sk.sign(msg);
            assert!(sig.len() > mldsa_sig_len);
        }
    }
}
