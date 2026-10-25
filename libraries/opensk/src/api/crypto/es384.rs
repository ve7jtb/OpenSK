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

//! ECDSA over NIST P-384 with SHA-384 (`ES384`, COSE `alg: -35`).

use crate::api::rng::Rng;
use alloc::vec::Vec;
use p384::ecdsa::signature::Signer as _;

/// Field coordinate and secret scalar size in bytes for NIST P-384 (384 bits = 48 bytes).
pub const ES384_FIELD_SIZE: usize = 48;

/// NIST P-384 ECDSA signing key (`ES384`, COSE `alg: -35`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Es384SecretKey {
    signing_key: p384::ecdsa::SigningKey,
}

impl Es384SecretKey {
    /// Generates a new random P-384 ECDSA signing key.
    #[inline(never)]
    pub fn random(rng: &mut impl Rng) -> Self {
        let signing_key = p384::ecdsa::SigningKey::random(rng);
        Self { signing_key }
    }

    /// Returns the 48-byte big-endian `(x, y)` affine coordinates of the public key.
    #[inline(never)]
    pub fn public_key_coordinates(&self) -> ([u8; ES384_FIELD_SIZE], [u8; ES384_FIELD_SIZE]) {
        let verifying_key = p384::ecdsa::VerifyingKey::from(&self.signing_key);
        let point = verifying_key.to_encoded_point(false);
        let mut x = [0u8; ES384_FIELD_SIZE];
        let mut y = [0u8; ES384_FIELD_SIZE];
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
        (x, y)
    }

    /// Signs the message using deterministic ECDSA with SHA-384 (RFC 6979) and encodes as ASN.1 DER.
    #[inline(never)]
    pub fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let signature: p384::ecdsa::Signature = self.signing_key.sign(message);
        signature.to_der().to_bytes().into_vec()
    }

    /// Exports the 48-byte big-endian secret scalar.
    pub fn export(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Imports a P-384 signing key from its 48-byte big-endian secret scalar.
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let signing_key = p384::ecdsa::SigningKey::from_slice(bytes).ok()?;
        Some(Self { signing_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;
    use crate::env::test::TestEnv;
    use p384::ecdsa::signature::Verifier as _;

    #[test]
    fn test_es384_sign_and_verify() {
        let mut env = TestEnv::default();
        let sk = Es384SecretKey::random(env.rng());
        let exported = sk.export();
        assert_eq!(exported.len(), ES384_FIELD_SIZE);
        let sk2 = Es384SecretKey::import(&exported).unwrap();
        assert_eq!(sk, sk2);

        let (x, y) = sk.public_key_coordinates();
        let encoded_point =
            p384::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
        let vk = p384::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).unwrap();

        let msg = b"CTAP2 ES384 test message";
        let der = sk.sign_der(msg);
        let sig = p384::ecdsa::Signature::from_der(&der).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }
}
