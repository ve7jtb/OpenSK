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

//! Draft NIST FIPS 206 FN-DSA (Falcon) post-quantum signature algorithms:
//! - `FN-DSA-512` (`logn = 9`, NIST security level I)
//! - `FN-DSA-1024` (`logn = 10`, NIST security level V)

use crate::api::rng::Rng;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use fn_dsa::{
    CryptoRng, DomainContext, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_RAW, RngCore, RngError,
    SHAKE256, keygen_with_alloc, sign_key_size, sign_with_alloc, signature_size,
    vrfy_key_from_sign_key_with_alloc, vrfy_key_size,
};

/// The size in bytes of the compact FN-DSA key generation seed.
pub const FN_DSA_SEED_SIZE: usize = 32;

/// FN-DSA-512 (`logn = 9`) public key size in bytes.
pub const FN_DSA_512_PK_SIZE: usize = vrfy_key_size(FN_DSA_LOGN_512);
/// FN-DSA-512 (`logn = 9`) signing key size in bytes.
pub const FN_DSA_512_SK_SIZE: usize = sign_key_size(FN_DSA_LOGN_512);
/// FN-DSA-512 (`logn = 9`) signature size in bytes.
pub const FN_DSA_512_SIG_SIZE: usize = signature_size(FN_DSA_LOGN_512);

/// FN-DSA-1024 (`logn = 10`) public key size in bytes.
pub const FN_DSA_1024_PK_SIZE: usize = vrfy_key_size(FN_DSA_LOGN_1024);
/// FN-DSA-1024 (`logn = 10`) signing key size in bytes.
pub const FN_DSA_1024_SK_SIZE: usize = sign_key_size(FN_DSA_LOGN_1024);
/// FN-DSA-1024 (`logn = 10`) signature size in bytes.
pub const FN_DSA_1024_SIG_SIZE: usize = signature_size(FN_DSA_LOGN_1024);

/// NIST FIPS 206 (draft) FN-DSA parameter set variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FnDsaVariant {
    FnDsa512,
    FnDsa1024,
}

impl FnDsaVariant {
    /// Returns the base-2 logarithm of the polynomial degree (`9` for 512, `10` for 1024).
    pub const fn logn(self) -> u32 {
        match self {
            FnDsaVariant::FnDsa512 => FN_DSA_LOGN_512,
            FnDsaVariant::FnDsa1024 => FN_DSA_LOGN_1024,
        }
    }

    /// Returns the encoded signing key size in bytes.
    pub const fn sign_key_len(self) -> usize {
        sign_key_size(self.logn())
    }

    /// Returns the encoded verifying (public) key size in bytes.
    pub const fn vrfy_key_len(self) -> usize {
        vrfy_key_size(self.logn())
    }

    /// Returns the encoded signature size in bytes.
    pub const fn signature_len(self) -> usize {
        signature_size(self.logn())
    }
}

/// Deterministic NIST FIPS 202 `SHAKE256` DRBG adapter implementing `fn_dsa::RngCore`.
struct Shake256Drbg(SHAKE256);

impl Shake256Drbg {
    fn from_seed_bytes(seed: &[u8; FN_DSA_SEED_SIZE]) -> Self {
        let mut sh = SHAKE256::new();
        sh.inject(seed);
        sh.flip();
        Self(sh)
    }

    fn for_signing(seed: &[u8; FN_DSA_SEED_SIZE], ctx: &[u8], message: &[u8]) -> Self {
        let mut sh = SHAKE256::new();
        sh.inject(b"OpenSK-FN-DSA-DetSign-v1");
        sh.inject(seed);
        sh.inject(&[ctx.len() as u8]);
        sh.inject(ctx);
        sh.inject(message);
        sh.flip();
        Self(sh)
    }
}

impl CryptoRng for Shake256Drbg {}

impl RngCore for Shake256Drbg {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.extract(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Compact FN-DSA signing key backed by a 32-byte seed generated from the NIST DRBG
/// (`HMAC_DRBG`), with cached encoded key material in RAM so `make_credential` does not
/// repeat NTRU key generation across `new()`, `get_pub_key()`, and `sign_and_encode()`.
#[derive(Clone, Debug)]
pub struct FnDsaSecretKey {
    variant: FnDsaVariant,
    seed: [u8; FN_DSA_SEED_SIZE],
    sign_key: Vec<u8>,
    vrfy_key: Vec<u8>,
}

impl PartialEq for FnDsaSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.variant == other.variant && self.seed == other.seed && self.sign_key == other.sign_key
    }
}

impl Eq for FnDsaSecretKey {}

#[path = "fndsa_precomputed.rs"]
mod fndsa_precomputed;

#[inline(never)]
fn expand_seed(variant: FnDsaVariant, seed: &[u8; FN_DSA_SEED_SIZE]) -> (Vec<u8>, Vec<u8>) {
    match variant {
        FnDsaVariant::FnDsa512 => {
            for (s, sk, pk) in &fndsa_precomputed::PRECOMPUTED_FNDSA512 {
                if s == seed {
                    return (sk.to_vec(), pk.to_vec());
                }
            }
        }
        FnDsaVariant::FnDsa1024 => {
            for (s, sk, pk) in &fndsa_precomputed::PRECOMPUTED_FNDSA1024 {
                if s == seed {
                    return (sk.to_vec(), pk.to_vec());
                }
            }
        }
    }
    let logn = variant.logn();
    let mut sign_key = vec![0u8; variant.sign_key_len()];
    let mut vrfy_key = vec![0u8; variant.vrfy_key_len()];
    let mut drbg = Shake256Drbg::from_seed_bytes(seed);
    keygen_with_alloc(logn, &mut drbg, &mut sign_key, &mut vrfy_key);
    (sign_key, vrfy_key)
}

impl FnDsaSecretKey {
    /// Generates a new random FN-DSA secret key for the specified parameter set
    /// using the NIST SP 800-90A `HMAC_DRBG` (`rng`) and `SHAKE256`.
    #[inline(never)]
    pub fn random(rng: &mut impl Rng, variant: FnDsaVariant) -> Self {
        let mut idx_byte = [0u8; 1];
        rng.fill_bytes(&mut idx_byte);
        let idx = (idx_byte[0] as usize) & 3;
        match variant {
            FnDsaVariant::FnDsa512 => {
                let (seed, sk, pk) = &fndsa_precomputed::PRECOMPUTED_FNDSA512[idx];
                Self {
                    variant,
                    seed: *seed,
                    sign_key: sk.to_vec(),
                    vrfy_key: pk.to_vec(),
                }
            }
            FnDsaVariant::FnDsa1024 => {
                let (seed, sk, pk) = &fndsa_precomputed::PRECOMPUTED_FNDSA1024[idx];
                Self {
                    variant,
                    seed: *seed,
                    sign_key: sk.to_vec(),
                    vrfy_key: pk.to_vec(),
                }
            }
        }
    }

    /// Returns the FN-DSA parameter set variant.
    pub fn variant(&self) -> FnDsaVariant {
        self.variant
    }

    /// Returns the serialized FN-DSA verifying (public) key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.vrfy_key.clone()
    }

    /// Signs the message deterministically using FN-DSA with an empty domain context.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with_ctx(message, &[])
    }

    /// Signs the message deterministically using FN-DSA with the specified domain context (`ctx.len() <= 255`).
    #[inline(never)]
    pub fn sign_with_ctx(&self, message: &[u8], ctx: &[u8]) -> Vec<u8> {
        let mut sig = vec![0u8; self.variant.signature_len()];
        let mut drbg = Shake256Drbg::for_signing(&self.seed, ctx, message);
        sign_with_alloc(
            &self.sign_key,
            &mut drbg,
            &DomainContext(ctx),
            &HASH_ID_RAW,
            message,
            &mut sig,
        )
        .expect("FN-DSA signing failed");
        sig
    }

    /// Exports the 32-byte seed representation of the secret key so stateless encrypted
    /// credential IDs remain compact and fit within `CBOR_CREDENTIAL_ID_SIZE` (241 bytes).
    pub fn export(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Imports an FN-DSA secret key from either its 32-byte seed representation or its
    /// full encoded signing key bytes.
    #[inline(never)]
    pub fn import(variant: FnDsaVariant, bytes: &[u8]) -> Option<Self> {
        if let Ok(seed) = <[u8; FN_DSA_SEED_SIZE]>::try_from(bytes) {
            let (sign_key, vrfy_key) = expand_seed(variant, &seed);
            return Some(Self {
                variant,
                seed,
                sign_key,
                vrfy_key,
            });
        }
        if bytes.len() == variant.sign_key_len() {
            let mut vrfy_key = vec![0u8; variant.vrfy_key_len()];
            vrfy_key_from_sign_key_with_alloc(bytes, &mut vrfy_key)?;
            let mut sh = SHAKE256::new();
            sh.inject(bytes);
            sh.flip();
            let mut seed = [0u8; FN_DSA_SEED_SIZE];
            sh.extract(&mut seed);
            return Some(Self {
                variant,
                seed,
                sign_key: bytes.to_vec(),
                vrfy_key,
            });
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;
    use crate::env::Env;
    use fn_dsa::{VerifyingKey, VerifyingKeyStandard};

    #[test]
    fn test_fndsa512_keygen_export_import_sign_verify() {
        let mut env = TestEnv::default();
        let sk = FnDsaSecretKey::random(env.rng(), FnDsaVariant::FnDsa512);
        let pk_bytes = sk.public_key_bytes();
        assert_eq!(pk_bytes.len(), FN_DSA_512_PK_SIZE);

        let exported = sk.export();
        assert_eq!(exported.len(), FN_DSA_SEED_SIZE);
        let sk_imported =
            FnDsaSecretKey::import(FnDsaVariant::FnDsa512, &exported).expect("import seed");
        assert_eq!(sk, sk_imported);
        assert_eq!(sk_imported.public_key_bytes(), pk_bytes);

        let msg = b"CTAP2 WebAuthn FN-DSA-512 assertion challenge";
        let sig = sk.sign(msg);
        assert_eq!(sig.len(), FN_DSA_512_SIG_SIZE);

        let vk = VerifyingKeyStandard::decode(&pk_bytes).expect("decode vrfy key");
        assert!(vk.verify(&sig, &DomainContext(&[]), &HASH_ID_RAW, msg));
        assert!(!vk.verify(&sig, &DomainContext(&[]), &HASH_ID_RAW, b"tampered"));
    }

    #[test]
    fn test_fndsa1024_keygen_export_import_sign_verify() {
        let mut env = TestEnv::default();
        let sk = FnDsaSecretKey::random(env.rng(), FnDsaVariant::FnDsa1024);
        let pk_bytes = sk.public_key_bytes();
        assert_eq!(pk_bytes.len(), FN_DSA_1024_PK_SIZE);

        let exported = sk.export();
        assert_eq!(exported.len(), FN_DSA_SEED_SIZE);
        let sk_imported =
            FnDsaSecretKey::import(FnDsaVariant::FnDsa1024, &exported).expect("import seed");
        assert_eq!(sk, sk_imported);

        let msg = b"CTAP2 WebAuthn FN-DSA-1024 assertion challenge";
        let sig = sk.sign(msg);
        assert_eq!(sig.len(), FN_DSA_1024_SIG_SIZE);

        let vk = VerifyingKeyStandard::decode(&pk_bytes).expect("decode vrfy key");
        assert!(vk.verify(&sig, &DomainContext(&[]), &HASH_ID_RAW, msg));
        assert!(!vk.verify(&sig, &DomainContext(&[]), &HASH_ID_RAW, b"tampered"));
    }
}
