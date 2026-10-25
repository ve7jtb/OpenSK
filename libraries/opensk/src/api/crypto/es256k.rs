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

//! ECDSA over SECP256k1 with SHA-256 (`ES256K`, COSE `alg: -47`).

use crate::api::rng::Rng;
use alloc::vec::Vec;
use k256::ecdsa::signature::Signer as _;

/// Field coordinate and secret scalar size in bytes for SECP256k1 (256 bits = 32 bytes).
pub const ES256K_FIELD_SIZE: usize = 32;

/// SECP256k1 ECDSA signing key (`ES256K`, COSE `alg: -47`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Es256kSecretKey {
    signing_key: k256::ecdsa::SigningKey,
}

impl Es256kSecretKey {
    /// Generates a new random SECP256k1 ECDSA signing key.
    #[inline(never)]
    pub fn random(rng: &mut impl Rng) -> Self {
        let signing_key = k256::ecdsa::SigningKey::random(rng);
        Self { signing_key }
    }

    /// Returns the 32-byte big-endian `(x, y)` affine coordinates of the public key.
    #[inline(never)]
    pub fn public_key_coordinates(&self) -> ([u8; ES256K_FIELD_SIZE], [u8; ES256K_FIELD_SIZE]) {
        let verifying_key = k256::ecdsa::VerifyingKey::from(&self.signing_key);
        let point = verifying_key.to_encoded_point(false);
        let mut x = [0u8; ES256K_FIELD_SIZE];
        let mut y = [0u8; ES256K_FIELD_SIZE];
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
        (x, y)
    }

    /// Signs the message using deterministic ECDSA with SHA-256 (RFC 6979) and encodes as ASN.1 DER
    /// (`secp256k1_ecdsa_sha256_der`, WebAuthn §8.1 standard).
    #[inline(never)]
    pub fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let signature: k256::ecdsa::Signature = self.signing_key.sign(message);
        signature.to_der().to_bytes().into_vec()
    }

    /// Signs the message using deterministic ECDSA with SHA-256 and returns raw 64-byte `[R || S]`
    /// (`secp256k1_ecdsa_sha256_raw`, FIDO Registry 0x0005).
    #[inline(never)]
    pub fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        let signature: k256::ecdsa::Signature = self.signing_key.sign(message);
        let mut raw = [0u8; 64];
        raw.copy_from_slice(signature.to_bytes().as_slice());
        raw
    }

    /// Exports the 32-byte big-endian secret scalar.
    pub fn export(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Imports a SECP256k1 signing key from its 32-byte big-endian secret scalar.
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(bytes).ok()?;
        Some(Self { signing_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;
    use crate::env::test::TestEnv;
    use k256::ecdsa::signature::Verifier as _;

    #[test]
    fn test_es256k_sign_and_verify() {
        let mut env = TestEnv::default();
        let sk = Es256kSecretKey::random(env.rng());
        let exported = sk.export();
        assert_eq!(exported.len(), ES256K_FIELD_SIZE);
        let sk2 = Es256kSecretKey::import(&exported).unwrap();
        assert_eq!(sk, sk2);

        let (x, y) = sk.public_key_coordinates();
        let encoded_point =
            k256::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
        let vk = k256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).unwrap();

        let msg = b"CTAP2 ES256K test message";
        let der = sk.sign_der(msg);
        let sig = k256::ecdsa::Signature::from_der(&der).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());

        let raw = sk.sign_raw(msg);
        assert_eq!(raw.len(), 64);
        let raw_sig = k256::ecdsa::Signature::try_from(raw.as_slice()).unwrap();
        assert!(vk.verify(msg, &raw_sig).is_ok());
    }
}
