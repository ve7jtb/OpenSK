// Copyright 2021-2023 Google LLC
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

use crate::api::crypto::ec_signing::{EcSecretKey, EcSignature};
#[cfg(feature = "ed25519")]
use crate::api::crypto::ec_signing::{EdSecretKey, EdSignature};
#[cfg(feature = "ed448")]
use crate::api::crypto::ed448::Ed448SecretKey;
#[cfg(feature = "es384")]
use crate::api::crypto::es384::Es384SecretKey;
#[cfg(feature = "es512")]
use crate::api::crypto::es512::Es512SecretKey;
#[cfg(feature = "es256k")]
use crate::api::crypto::es256k::Es256kSecretKey;
#[cfg(feature = "mldsa")]
use crate::api::crypto::mldsa::{MlDsaSecretKey, MlDsaVariant};
#[cfg(feature = "fndsa")]
use crate::api::crypto::fndsa::{FnDsaSecretKey, FnDsaVariant};
#[cfg(feature = "pq_composite")]
use crate::api::crypto::composite::{CompositeSecretKey, CompositeVariant};
#[cfg(feature = "rs256")]
use crate::api::crypto::rs256::Rs256SecretKey;
use crate::ctap::data_formats::{CoseKey, SignatureAlgorithm, extract_array, extract_byte_string};
use crate::ctap::status_code::{Ctap2StatusCode, CtapResult};
#[cfg(feature = "ed25519")]
use crate::env::Ed25519Sk;
use crate::env::{EcdsaSk, Env};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use sk_cbor as cbor;
use sk_cbor::{cbor_array, cbor_bytes, cbor_int};

/// An asymmetric private key that can sign messages.
pub enum PrivateKey<E: Env> {
    Ecdsa(EcdsaSk<E>),
    #[cfg(feature = "es384")]
    Es384(Es384SecretKey),
    #[cfg(feature = "es512")]
    Es512(Es512SecretKey),
    #[cfg(feature = "es256k")]
    Es256k(Es256kSecretKey),
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519Sk<E>),
    #[cfg(feature = "ed448")]
    Ed448(Ed448SecretKey),
    #[cfg(feature = "mldsa")]
    MlDsa(MlDsaSecretKey),
    #[cfg(feature = "fndsa")]
    FnDsa(FnDsaSecretKey),
    #[cfg(feature = "pq_composite")]
    Composite(CompositeSecretKey<E>),
    #[cfg(feature = "rs256")]
    Rs256(Rs256SecretKey),
}

// We shouldn't compare private keys in prod without constant-time operations.
#[cfg(test)]
impl<E: Env> PartialEq for PrivateKey<E> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PrivateKey::Ecdsa(key1), PrivateKey::Ecdsa(key2)) => key1.export() == key2.export(),
            #[cfg(feature = "es384")]
            (PrivateKey::Es384(key1), PrivateKey::Es384(key2)) => key1 == key2,
            #[cfg(feature = "es512")]
            (PrivateKey::Es512(key1), PrivateKey::Es512(key2)) => key1 == key2,
            #[cfg(feature = "es256k")]
            (PrivateKey::Es256k(key1), PrivateKey::Es256k(key2)) => key1 == key2,
            #[cfg(feature = "ed25519")]
            (PrivateKey::Ed25519(key1), PrivateKey::Ed25519(key2)) => {
                key1.export() == key2.export()
            }
            #[cfg(feature = "ed448")]
            (PrivateKey::Ed448(key1), PrivateKey::Ed448(key2)) => key1 == key2,
            #[cfg(feature = "mldsa")]
            (PrivateKey::MlDsa(key1), PrivateKey::MlDsa(key2)) => key1 == key2,
            #[cfg(feature = "fndsa")]
            (PrivateKey::FnDsa(key1), PrivateKey::FnDsa(key2)) => key1 == key2,
            #[cfg(feature = "pq_composite")]
            (PrivateKey::Composite(key1), PrivateKey::Composite(key2)) => key1 == key2,
            #[cfg(feature = "rs256")]
            (PrivateKey::Rs256(key1), PrivateKey::Rs256(key2)) => key1 == key2,
            #[cfg(any(
                feature = "es384",
                feature = "es512",
                feature = "es256k",
                feature = "ed25519",
                feature = "ed448",
                feature = "mldsa",
                feature = "fndsa",
                feature = "pq_composite",
                feature = "rs256"
            ))]
            _ => false,
        }
    }
}

impl<E: Env> PrivateKey<E> {
    /// Creates a new private key for the given algorithm.
    ///
    /// # Panics
    ///
    /// Panics if the algorithm is [`SignatureAlgorithm::Unknown`].
    pub fn new(env: &mut E, alg: SignatureAlgorithm) -> Self {
        match alg {
            SignatureAlgorithm::Es256 => Self::Ecdsa(EcdsaSk::<E>::random(env.rng())),
            #[cfg(feature = "es384")]
            SignatureAlgorithm::Es384 => Self::Es384(Es384SecretKey::random(env.rng())),
            #[cfg(feature = "es512")]
            SignatureAlgorithm::Es512 => Self::Es512(Es512SecretKey::random(env.rng())),
            #[cfg(feature = "es256k")]
            SignatureAlgorithm::Es256k => Self::Es256k(Es256kSecretKey::random(env.rng())),
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::Eddsa => Self::Ed25519(Ed25519Sk::<E>::random(env.rng())),
            #[cfg(feature = "ed448")]
            SignatureAlgorithm::Ed448 => Self::Ed448(Ed448SecretKey::random(env.rng())),
            #[cfg(feature = "mldsa")]
            SignatureAlgorithm::MlDsa44 => {
                Self::MlDsa(MlDsaSecretKey::random(env.rng(), MlDsaVariant::MlDsa44))
            }
            #[cfg(feature = "mldsa")]
            SignatureAlgorithm::MlDsa65 => {
                Self::MlDsa(MlDsaSecretKey::random(env.rng(), MlDsaVariant::MlDsa65))
            }
            #[cfg(feature = "mldsa")]
            SignatureAlgorithm::MlDsa87 => {
                Self::MlDsa(MlDsaSecretKey::random(env.rng(), MlDsaVariant::MlDsa87))
            }
            #[cfg(feature = "fndsa")]
            SignatureAlgorithm::FnDsa512 => {
                Self::FnDsa(FnDsaSecretKey::random(env.rng(), FnDsaVariant::FnDsa512))
            }
            #[cfg(feature = "fndsa")]
            SignatureAlgorithm::FnDsa1024 => {
                Self::FnDsa(FnDsaSecretKey::random(env.rng(), FnDsaVariant::FnDsa1024))
            }
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa44Es256 => Self::Composite(CompositeSecretKey::random(
                env,
                CompositeVariant::MlDsa44Es256,
            )),
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa65Es256 => Self::Composite(CompositeSecretKey::random(
                env,
                CompositeVariant::MlDsa65Es256,
            )),
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa87Es384 => Self::Composite(CompositeSecretKey::random(
                env,
                CompositeVariant::MlDsa87Es384,
            )),
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa44Ed25519 => Self::Composite(CompositeSecretKey::random(
                env,
                CompositeVariant::MlDsa44Ed25519,
            )),
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa65Ed25519 => Self::Composite(CompositeSecretKey::random(
                env,
                CompositeVariant::MlDsa65Ed25519,
            )),
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa87Ed448 => Self::Composite(CompositeSecretKey::random(
                env,
                CompositeVariant::MlDsa87Ed448,
            )),
            #[cfg(feature = "rs256")]
            SignatureAlgorithm::Rs256 => Self::Rs256(Rs256SecretKey::random(env.rng())),
            SignatureAlgorithm::Unknown => unreachable!(),
        }
    }

    /// Creates a new ecdsa private key.
    pub fn new_ecdsa(env: &mut E) -> PrivateKey<E> {
        Self::new(env, SignatureAlgorithm::Es256)
    }

    /// Returns the corresponding public key.
    pub fn get_pub_key(&self) -> CtapResult<CoseKey> {
        Ok(match self {
            PrivateKey::Ecdsa(key) => CoseKey::from_ecdsa_public_key::<E>(key.public_key()),
            #[cfg(feature = "es384")]
            PrivateKey::Es384(key) => {
                let (x, y) = key.public_key_coordinates();
                CoseKey::from_es384_public_key(x, y)
            }
            #[cfg(feature = "es512")]
            PrivateKey::Es512(key) => {
                let (x, y) = key.public_key_coordinates();
                CoseKey::from_es512_public_key(x, y)
            }
            #[cfg(feature = "es256k")]
            PrivateKey::Es256k(key) => {
                let (x, y) = key.public_key_coordinates();
                CoseKey::from_es256k_public_key(x, y)
            }
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(key) => CoseKey::from_ed25519_public_key::<E>(key.public_key()),
            #[cfg(feature = "ed448")]
            PrivateKey::Ed448(key) => CoseKey::from_ed448_public_key(key.public_key_bytes()),
            #[cfg(feature = "mldsa")]
            PrivateKey::MlDsa(key) => CoseKey::from_mldsa_public_key(
                self.signature_algorithm() as i64,
                key.public_key_bytes(),
            ),
            #[cfg(feature = "fndsa")]
            PrivateKey::FnDsa(key) => CoseKey::from_mldsa_public_key(
                self.signature_algorithm() as i64,
                key.public_key_bytes(),
            ),
            #[cfg(feature = "pq_composite")]
            PrivateKey::Composite(key) => CoseKey::from_mldsa_public_key(
                self.signature_algorithm() as i64,
                key.public_key_bytes(),
            ),
            #[cfg(feature = "rs256")]
            PrivateKey::Rs256(key) => {
                let (n, e) = key.public_key();
                CoseKey::from_rs256_public_key(n.to_vec(), e.to_vec())
            }
        })
    }

    /// Returns the encoded signature for a given message.
    pub fn sign_and_encode(&self, message: &[u8]) -> CtapResult<Vec<u8>> {
        Ok(match self {
            PrivateKey::Ecdsa(key) => key.sign(message).to_der(),
            #[cfg(feature = "es384")]
            PrivateKey::Es384(key) => key.sign_der(message),
            #[cfg(feature = "es512")]
            PrivateKey::Es512(key) => key.sign_der(message),
            #[cfg(feature = "es256k")]
            PrivateKey::Es256k(key) => key.sign_der(message),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(key) => key.sign(message).to_bytes(),
            #[cfg(feature = "ed448")]
            PrivateKey::Ed448(key) => key.sign(message),
            #[cfg(feature = "mldsa")]
            PrivateKey::MlDsa(key) => key.sign(message),
            #[cfg(feature = "fndsa")]
            PrivateKey::FnDsa(key) => key.sign(message),
            #[cfg(feature = "pq_composite")]
            PrivateKey::Composite(key) => key.sign(message),
            #[cfg(feature = "rs256")]
            PrivateKey::Rs256(key) => key.sign(message),
        })
    }

    /// The associated COSE signature algorithm identifier.
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            PrivateKey::Ecdsa(_) => SignatureAlgorithm::Es256,
            #[cfg(feature = "es384")]
            PrivateKey::Es384(_) => SignatureAlgorithm::Es384,
            #[cfg(feature = "es512")]
            PrivateKey::Es512(_) => SignatureAlgorithm::Es512,
            #[cfg(feature = "es256k")]
            PrivateKey::Es256k(_) => SignatureAlgorithm::Es256k,
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(_) => SignatureAlgorithm::Eddsa,
            #[cfg(feature = "ed448")]
            PrivateKey::Ed448(_) => SignatureAlgorithm::Ed448,
            #[cfg(feature = "mldsa")]
            PrivateKey::MlDsa(key) => match key.variant() {
                MlDsaVariant::MlDsa44 => SignatureAlgorithm::MlDsa44,
                MlDsaVariant::MlDsa65 => SignatureAlgorithm::MlDsa65,
                MlDsaVariant::MlDsa87 => SignatureAlgorithm::MlDsa87,
            },
            #[cfg(feature = "fndsa")]
            PrivateKey::FnDsa(key) => match key.variant() {
                FnDsaVariant::FnDsa512 => SignatureAlgorithm::FnDsa512,
                FnDsaVariant::FnDsa1024 => SignatureAlgorithm::FnDsa1024,
            },
            #[cfg(feature = "pq_composite")]
            PrivateKey::Composite(key) => match key.variant() {
                CompositeVariant::MlDsa44Es256 => SignatureAlgorithm::MlDsa44Es256,
                CompositeVariant::MlDsa65Es256 => SignatureAlgorithm::MlDsa65Es256,
                CompositeVariant::MlDsa87Es384 => SignatureAlgorithm::MlDsa87Es384,
                CompositeVariant::MlDsa44Ed25519 => SignatureAlgorithm::MlDsa44Ed25519,
                CompositeVariant::MlDsa65Ed25519 => SignatureAlgorithm::MlDsa65Ed25519,
                CompositeVariant::MlDsa87Ed448 => SignatureAlgorithm::MlDsa87Ed448,
            },
            #[cfg(feature = "rs256")]
            PrivateKey::Rs256(_) => SignatureAlgorithm::Rs256,
        }
    }

    /// Writes the key bytes.
    pub fn export(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ecdsa(key) => key.export(),
            #[cfg(feature = "es384")]
            PrivateKey::Es384(key) => key.export(),
            #[cfg(feature = "es512")]
            PrivateKey::Es512(key) => key.export(),
            #[cfg(feature = "es256k")]
            PrivateKey::Es256k(key) => key.export(),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(key) => key.export(),
            #[cfg(feature = "ed448")]
            PrivateKey::Ed448(key) => key.export(),
            #[cfg(feature = "mldsa")]
            PrivateKey::MlDsa(key) => key.export(),
            #[cfg(feature = "fndsa")]
            PrivateKey::FnDsa(key) => key.export(),
            #[cfg(feature = "pq_composite")]
            PrivateKey::Composite(key) => key.export(),
            #[cfg(feature = "rs256")]
            PrivateKey::Rs256(key) => key.export(),
        }
    }

    /// Encodes the private key into a CBOR array with type information.
    pub fn to_cbor(&self) -> cbor::Value {
        cbor_array![
            cbor_int!(self.signature_algorithm() as i64),
            cbor_bytes!(self.export()),
        ]
    }

    pub fn from_cbor(cbor_value: cbor::Value) -> CtapResult<Self> {
        let mut array = extract_array(cbor_value)?;
        if array.len() != 2 {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR);
        }
        let wrapped_bytes = extract_byte_string(array.pop().unwrap())?;
        match SignatureAlgorithm::try_from(array.pop().unwrap())? {
            SignatureAlgorithm::Es256 => EcdsaSk::<E>::import(&wrapped_bytes)
                .map(|k| PrivateKey::Ecdsa(k))
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "es384")]
            SignatureAlgorithm::Es384 => Es384SecretKey::import(&wrapped_bytes)
                .map(PrivateKey::Es384)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "es512")]
            SignatureAlgorithm::Es512 => Es512SecretKey::import(&wrapped_bytes)
                .map(PrivateKey::Es512)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "es256k")]
            SignatureAlgorithm::Es256k => Es256kSecretKey::import(&wrapped_bytes)
                .map(PrivateKey::Es256k)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::Eddsa => Ed25519Sk::<E>::import(&wrapped_bytes)
                .map(|k| PrivateKey::Ed25519(k))
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "ed448")]
            SignatureAlgorithm::Ed448 => Ed448SecretKey::import(&wrapped_bytes)
                .map(PrivateKey::Ed448)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "mldsa")]
            SignatureAlgorithm::MlDsa44 => {
                MlDsaSecretKey::import(MlDsaVariant::MlDsa44, &wrapped_bytes)
                    .map(PrivateKey::MlDsa)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "mldsa")]
            SignatureAlgorithm::MlDsa65 => {
                MlDsaSecretKey::import(MlDsaVariant::MlDsa65, &wrapped_bytes)
                    .map(PrivateKey::MlDsa)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "mldsa")]
            SignatureAlgorithm::MlDsa87 => {
                MlDsaSecretKey::import(MlDsaVariant::MlDsa87, &wrapped_bytes)
                    .map(PrivateKey::MlDsa)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "fndsa")]
            SignatureAlgorithm::FnDsa512 => {
                FnDsaSecretKey::import(FnDsaVariant::FnDsa512, &wrapped_bytes)
                    .map(PrivateKey::FnDsa)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "fndsa")]
            SignatureAlgorithm::FnDsa1024 => {
                FnDsaSecretKey::import(FnDsaVariant::FnDsa1024, &wrapped_bytes)
                    .map(PrivateKey::FnDsa)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa44Es256 => {
                CompositeSecretKey::import(CompositeVariant::MlDsa44Es256, &wrapped_bytes)
                    .map(PrivateKey::Composite)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa65Es256 => {
                CompositeSecretKey::import(CompositeVariant::MlDsa65Es256, &wrapped_bytes)
                    .map(PrivateKey::Composite)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa87Es384 => {
                CompositeSecretKey::import(CompositeVariant::MlDsa87Es384, &wrapped_bytes)
                    .map(PrivateKey::Composite)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa44Ed25519 => {
                CompositeSecretKey::import(CompositeVariant::MlDsa44Ed25519, &wrapped_bytes)
                    .map(PrivateKey::Composite)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa65Ed25519 => {
                CompositeSecretKey::import(CompositeVariant::MlDsa65Ed25519, &wrapped_bytes)
                    .map(PrivateKey::Composite)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "pq_composite")]
            SignatureAlgorithm::MlDsa87Ed448 => {
                CompositeSecretKey::import(CompositeVariant::MlDsa87Ed448, &wrapped_bytes)
                    .map(PrivateKey::Composite)
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
            }
            #[cfg(feature = "rs256")]
            SignatureAlgorithm::Rs256 => Rs256SecretKey::import(&wrapped_bytes)
                .map(PrivateKey::Rs256)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        }
    }

    /// Decodes a stored attestation private key.
    ///
    /// Supports both CBOR-encoded `[alg, key_bytes]` (for ML-DSA, EdDSA, ES384, ES512, or ES256)
    /// and legacy raw 32-byte ECDSA P-256 keys.
    pub fn from_attestation_bytes(bytes: &[u8]) -> Option<Self> {
        if let Ok(cbor_value) = crate::ctap::cbor_read(bytes) {
            if let Ok(key) = Self::from_cbor(cbor_value) {
                return Some(key);
            }
        }
        EcdsaSk::<E>::import(bytes).map(PrivateKey::Ecdsa)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    #[test]
    fn test_new_ecdsa_export_import() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new_ecdsa(&mut env);
        let key_bytes = private_key.export();
        let ecdsa_key = EcdsaSk::<TestEnv>::import(&key_bytes).unwrap();
        let reconstructed = PrivateKey::<TestEnv>::Ecdsa(ecdsa_key);
        assert!(private_key == reconstructed);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_new_ed25519_export_import() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new(&mut env, SignatureAlgorithm::Eddsa);
        let key_bytes = private_key.export();
        let ed25519_key = Ed25519Sk::<TestEnv>::import(&key_bytes).unwrap();
        let reconstructed = PrivateKey::<TestEnv>::Ed25519(ed25519_key);
        assert!(private_key == reconstructed);
    }

    #[test]
    fn test_private_key_get_pub_key() {
        let mut env = TestEnv::default();
        let ecdsa_key = EcdsaSk::<TestEnv>::random(env.rng());
        let public_key = ecdsa_key.public_key();
        let private_key = PrivateKey::<TestEnv>::Ecdsa(ecdsa_key);
        assert_eq!(
            private_key.get_pub_key(),
            Ok(CoseKey::from_ecdsa_public_key::<TestEnv>(public_key))
        );
    }

    #[test]
    fn test_private_key_sign_and_encode() {
        let mut env = TestEnv::default();
        let message = [0x5A; 32];
        let ecdsa_key = EcdsaSk::<TestEnv>::random(env.rng());
        let signature = ecdsa_key.sign(&message).to_der();
        let private_key = PrivateKey::<TestEnv>::Ecdsa(ecdsa_key);
        assert_eq!(private_key.sign_and_encode(&message), Ok(signature));
    }

    fn test_private_key_signature_algorithm(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new(&mut env, signature_algorithm);
        assert_eq!(private_key.signature_algorithm(), signature_algorithm);
    }

    #[test]
    fn test_ecdsa_private_key_signature_algorithm() {
        test_private_key_signature_algorithm(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_signature_algorithm() {
        test_private_key_signature_algorithm(SignatureAlgorithm::Eddsa);
    }

    fn test_private_key_from_to_cbor(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new(&mut env, signature_algorithm);
        let cbor = private_key.to_cbor();
        assert!(PrivateKey::<TestEnv>::from_cbor(cbor) == Ok(private_key));
    }

    #[test]
    fn test_ecdsa_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Eddsa);
    }

    #[test]
    #[cfg(feature = "es384")]
    fn test_es384_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Es384);
        test_private_key_signature_algorithm(SignatureAlgorithm::Es384);
    }

    #[test]
    #[cfg(feature = "es512")]
    fn test_es512_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Es512);
        test_private_key_signature_algorithm(SignatureAlgorithm::Es512);
    }

    #[test]
    #[cfg(feature = "es256k")]
    fn test_es256k_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Es256k);
        test_private_key_signature_algorithm(SignatureAlgorithm::Es256k);
    }

    #[test]
    #[cfg(feature = "ed448")]
    fn test_ed448_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Ed448);
        test_private_key_signature_algorithm(SignatureAlgorithm::Ed448);
    }

    #[test]
    #[cfg(feature = "rs256")]
    fn test_rs256_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Rs256);
        test_private_key_signature_algorithm(SignatureAlgorithm::Rs256);
    }

    fn test_private_key_from_bad_cbor(signature_algorithm: SignatureAlgorithm) {
        let cbor = cbor_array![
            cbor_int!(signature_algorithm as i64),
            cbor_bytes!(vec![0x88; 32]),
            // The array is too long.
            cbor_int!(0),
        ];
        assert!(
            PrivateKey::<TestEnv>::from_cbor(cbor) == Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
        );
    }

    #[test]
    fn test_ecdsa_private_key_from_bad_cbor() {
        test_private_key_from_bad_cbor(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_from_bad_cbor() {
        test_private_key_from_bad_cbor(SignatureAlgorithm::Eddsa);
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::MlDsa44);
        test_private_key_from_to_cbor(SignatureAlgorithm::MlDsa65);
        test_private_key_from_to_cbor(SignatureAlgorithm::MlDsa87);
    }

    #[test]
    #[cfg(feature = "pq_composite")]
    fn test_composite_private_key_from_to_cbor() {
        let algs = [
            SignatureAlgorithm::MlDsa44Es256,
            SignatureAlgorithm::MlDsa65Es256,
            SignatureAlgorithm::MlDsa87Es384,
            SignatureAlgorithm::MlDsa44Ed25519,
            SignatureAlgorithm::MlDsa65Ed25519,
            SignatureAlgorithm::MlDsa87Ed448,
        ];
        for alg in algs {
            test_private_key_from_to_cbor(alg);
            test_private_key_signature_algorithm(alg);
            let mut env = TestEnv::default();
            let sk = PrivateKey::<TestEnv>::new(&mut env, alg);
            let cose_val = cbor::Value::from(sk.get_pub_key().unwrap());
            assert_eq!(CoseKey::try_from(cose_val), sk.get_pub_key());
        }
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa_private_key_sign_and_verify() {
        use ml_dsa::{EncodedVerifyingKey, MlDsa44, Signature, Verifier, VerifyingKey};
        let mut env = TestEnv::default();
        let message = [0x5A; 32];

        let sk44 = PrivateKey::<TestEnv>::new(&mut env, SignatureAlgorithm::MlDsa44);
        let sig44 = sk44.sign_and_encode(&message).unwrap();
        assert_eq!(sig44.len(), 2420);
        let cose44 = cbor::Value::from(sk44.get_pub_key().unwrap());
        assert_eq!(CoseKey::try_from(cose44), sk44.get_pub_key());
        if let PrivateKey::MlDsa(inner) = &sk44 {
            let pk_enc = EncodedVerifyingKey::<MlDsa44>::try_from(inner.public_key_bytes().as_slice()).unwrap();
            let vk = VerifyingKey::<MlDsa44>::decode(&pk_enc);
            let sig = Signature::<MlDsa44>::try_from(sig44.as_slice()).unwrap();
            assert!(vk.verify(&message, &sig).is_ok());
        } else {
            panic!("Expected MlDsa key");
        }
    }

    #[test]
    #[cfg(feature = "fndsa")]
    fn test_fndsa_private_key_from_to_cbor() {
        for alg in [SignatureAlgorithm::FnDsa512, SignatureAlgorithm::FnDsa1024] {
            test_private_key_from_to_cbor(alg);
            test_private_key_signature_algorithm(alg);
            let mut env = TestEnv::default();
            let sk = PrivateKey::<TestEnv>::new(&mut env, alg);
            let cose_val = cbor::Value::from(sk.get_pub_key().unwrap());
            assert_eq!(CoseKey::try_from(cose_val), sk.get_pub_key());
        }
    }

    #[test]
    fn test_private_key_from_bad_cbor_unsupported_algo() {
        let cbor = cbor_array![
            // This algorithms doesn't exist.
            cbor_int!(-1),
            cbor_bytes!(vec![0x88; 32]),
        ];
        assert!(
            PrivateKey::<TestEnv>::from_cbor(cbor) == Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
        );
    }
}
