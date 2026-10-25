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

use crate::api::rng::Rng;
use alloc::vec::Vec;
use core::convert::TryFrom;
use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey,
};

/// The size in bytes of the FIPS 204 key generation seed (xi).
pub const ML_DSA_SEED_SIZE: usize = 32;

/// NIST FIPS 204 ML-DSA-44 public key size in bytes.
pub const ML_DSA_44_PK_SIZE: usize = 1312;
/// NIST FIPS 204 ML-DSA-44 signature size in bytes.
pub const ML_DSA_44_SIG_SIZE: usize = 2420;

/// NIST FIPS 204 ML-DSA-65 public key size in bytes.
pub const ML_DSA_65_PK_SIZE: usize = 1952;
/// NIST FIPS 204 ML-DSA-65 signature size in bytes.
pub const ML_DSA_65_SIG_SIZE: usize = 3309;

/// NIST FIPS 204 ML-DSA-87 public key size in bytes.
pub const ML_DSA_87_PK_SIZE: usize = 2592;
/// NIST FIPS 204 ML-DSA-87 signature size in bytes.
pub const ML_DSA_87_SIG_SIZE: usize = 4627;

/// NIST FIPS 204 ML-DSA parameter set variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Compact ML-DSA signing key backed by its 32-byte FIPS 204 seed (xi).
///
/// Storing the 32-byte seed keeps the wrapped key size identical to ECDSA/Ed25519
/// so stateless encrypted credential IDs fit within `CBOR_CREDENTIAL_ID_SIZE` (241 bytes)
/// and avoids holding large expanded polynomial matrices on the stack across frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaSecretKey {
    variant: MlDsaVariant,
    seed: [u8; ML_DSA_SEED_SIZE],
}

#[inline(never)]
fn public_key_from_seed<P: MlDsaParams>(seed: &[u8; ML_DSA_SEED_SIZE]) -> Vec<u8> {
    let seed = Seed::from(*seed);
    SigningKey::<P>::verifying_key_bytes_from_seed(&seed)
        .as_slice()
        .to_vec()
}

#[inline(never)]
fn sign_from_seed<P: MlDsaParams>(
    seed: &[u8; ML_DSA_SEED_SIZE],
    message: &[u8],
    ctx: &[u8],
) -> Vec<u8> {
    let seed = Seed::from(*seed);
    SigningKey::<P>::sign_deterministic_from_seed(&seed, message, ctx)
        .expect("ML-DSA deterministic sign failed")
        .as_slice()
        .to_vec()
}

impl MlDsaSecretKey {
    /// Generates a new random ML-DSA secret key for the specified parameter set.
    pub fn random(rng: &mut impl Rng, variant: MlDsaVariant) -> Self {
        let seed = rng.gen_uniform_u8x32();
        Self { variant, seed }
    }

    /// Returns the ML-DSA parameter set variant.
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// Derives and serializes the raw FIPS 204 public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self.variant {
            MlDsaVariant::MlDsa44 => public_key_from_seed::<MlDsa44>(&self.seed),
            MlDsaVariant::MlDsa65 => public_key_from_seed::<MlDsa65>(&self.seed),
            MlDsaVariant::MlDsa87 => public_key_from_seed::<MlDsa87>(&self.seed),
        }
    }

    /// Signs the message deterministically using FIPS 204 ML-DSA with an empty context.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with_ctx(message, &[])
    }

    /// Signs the message deterministically using FIPS 204 ML-DSA with the specified context (`ctx.len() <= 255`).
    pub fn sign_with_ctx(&self, message: &[u8], ctx: &[u8]) -> Vec<u8> {
        match self.variant {
            MlDsaVariant::MlDsa44 => sign_from_seed::<MlDsa44>(&self.seed, message, ctx),
            MlDsaVariant::MlDsa65 => sign_from_seed::<MlDsa65>(&self.seed, message, ctx),
            MlDsaVariant::MlDsa87 => sign_from_seed::<MlDsa87>(&self.seed, message, ctx),
        }
    }

    /// Exports the 32-byte seed representation of the secret key.
    pub fn export(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Imports an ML-DSA secret key from its 32-byte seed representation.
    pub fn import(variant: MlDsaVariant, bytes: &[u8]) -> Option<Self> {
        let seed = <[u8; ML_DSA_SEED_SIZE]>::try_from(bytes).ok()?;
        Some(Self { variant, seed })
    }
}
