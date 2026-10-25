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

//! ECDSA over NIST P-521 with SHA-512 (`ES512`, COSE `alg: -36`).

use crate::api::rng::Rng;
use alloc::vec::Vec;
use core::fmt;
use p521::ecdsa::signature::RandomizedSigner as _;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// Field coordinate and secret scalar size in bytes for NIST P-521 (521 bits = 66 bytes).
pub const ES512_FIELD_SIZE: usize = 66;

/// Computes `HMAC-SHA-512(key, slices)` (SHA-512 block size = 128 bytes).
fn hmac_sha512(key: &[u8; 64], slices: &[&[u8]]) -> [u8; 64] {
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    for s in slices {
        inner.update(s);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut res = [0u8; 64];
    res.copy_from_slice(&out);
    res
}

/// NIST SP 800-90A Rev. 1 / RFC 6979 `HMAC_DRBG` (HMAC-SHA-512) seeded from the P-521 private scalar
/// and SHA-512 message digest for deterministic signing.
struct HmacDrbgSha512 {
    k: [u8; 64],
    v: [u8; 64],
    buf: [u8; 128],
    pos: usize,
}

impl HmacDrbgSha512 {
    fn new(key_bytes: [u8; ES512_FIELD_SIZE], message: &[u8]) -> Self {
        let digest = Sha512::digest(message);
        let mut msg_hash = [0u8; 64];
        msg_hash.copy_from_slice(&digest);

        let mut k = [0x00u8; 64];
        let mut v = [0x01u8; 64];

        // NIST SP 800-90A §10.1.2.2 / RFC 6979 §3.2(d)-(g): HMAC_DRBG_Update(key_bytes || msg_hash)
        k = hmac_sha512(&k, &[&v, &[0x00], &key_bytes, &msg_hash]);
        v = hmac_sha512(&k, &[&v]);
        k = hmac_sha512(&k, &[&v, &[0x01], &key_bytes, &msg_hash]);
        v = hmac_sha512(&k, &[&v]);

        Self {
            k,
            v,
            buf: [0u8; 128],
            pos: 128,
        }
    }

    fn refill(&mut self) {
        // Generate 128 bytes (2 * SHA-512 output blocks) to cover a 66-byte P-521 scalar draw,
        // then perform the SP 800-90A §10.1.2.5 / RFC 6979 §3.2(h.3) state update.
        self.v = hmac_sha512(&self.k, &[&self.v]);
        self.buf[..64].copy_from_slice(&self.v);
        self.v = hmac_sha512(&self.k, &[&self.v]);
        self.buf[64..128].copy_from_slice(&self.v);

        self.k = hmac_sha512(&self.k, &[&self.v, &[0x00]]);
        self.v = hmac_sha512(&self.k, &[&self.v]);
        self.pos = 0;
    }
}

impl RngCore for HmacDrbgSha512 {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            if self.pos >= self.buf.len() {
                self.refill();
            }
            *b = self.buf[self.pos];
            self.pos += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for HmacDrbgSha512 {}

/// NIST P-521 ECDSA signing key (`ES512`, COSE `alg: -36`).
#[derive(Clone)]
pub struct Es512SecretKey {
    signing_key: p521::ecdsa::SigningKey,
}

impl fmt::Debug for Es512SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Es512SecretKey").finish_non_exhaustive()
    }
}

impl PartialEq for Es512SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.signing_key.to_bytes() == other.signing_key.to_bytes()
    }
}

impl Eq for Es512SecretKey {}

impl Es512SecretKey {
    /// Generates a new random P-521 ECDSA signing key.
    #[inline(never)]
    pub fn random(rng: &mut impl Rng) -> Self {
        let signing_key = p521::ecdsa::SigningKey::random(rng);
        Self { signing_key }
    }

    /// Returns the 66-byte big-endian `(x, y)` affine coordinates of the public key.
    #[inline(never)]
    pub fn public_key_coordinates(&self) -> ([u8; ES512_FIELD_SIZE], [u8; ES512_FIELD_SIZE]) {
        let verifying_key = p521::ecdsa::VerifyingKey::from(&self.signing_key);
        let point = verifying_key.to_encoded_point(false);
        let mut x = [0u8; ES512_FIELD_SIZE];
        let mut y = [0u8; ES512_FIELD_SIZE];
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
        (x, y)
    }

    /// Signs the message using deterministic ECDSA with SHA-512 and encodes as ASN.1 DER.
    #[inline(never)]
    pub fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let mut key_bytes = [0u8; ES512_FIELD_SIZE];
        key_bytes.copy_from_slice(&self.signing_key.to_bytes());
        let mut det_rng = HmacDrbgSha512::new(key_bytes, message);
        let signature: p521::ecdsa::Signature =
            self.signing_key.sign_with_rng(&mut det_rng, message);
        signature.to_der().to_bytes().into_vec()
    }

    /// Exports the 66-byte big-endian secret scalar.
    pub fn export(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Imports a P-521 signing key from its 66-byte big-endian secret scalar.
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let signing_key = p521::ecdsa::SigningKey::from_slice(bytes).ok()?;
        Some(Self { signing_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;
    use crate::env::test::TestEnv;
    use alloc::vec;
    use p521::ecdsa::signature::Verifier as _;

    #[test]
    fn test_es512_sign_and_verify() {
        let mut env = TestEnv::default();
        let sk = Es512SecretKey::random(env.rng());
        let exported = sk.export();
        assert_eq!(exported.len(), ES512_FIELD_SIZE);
        let sk2 = Es512SecretKey::import(&exported).unwrap();
        assert_eq!(sk, sk2);

        let (x, y) = sk.public_key_coordinates();
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();

        let msg = b"CTAP2 ES512 test message";
        let der = sk.sign_der(msg);
        let sig = p521::ecdsa::Signature::from_der(&der).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }
}
