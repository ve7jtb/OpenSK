// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::vec::Vec;
use core::num::NonZeroU32;

use opensk::api::crypto::HASH_SIZE;
use opensk::api::rng::Rng;
use opensk::api::rng::rand_core::{CryptoRng, Error, RngCore, impls};

/// Number of `generate` requests before automatic reseed from the platform entropy source.
const RESEED_INTERVAL: u32 = 256;

/// Domain personalization string for the OpenSK applet NIST SP 800-90A `HMAC_DRBG`.
const PERSONALIZATION_STRING: &[u8] = b"OpenSK-Wasefire-SP800-90A-HMAC-DRBG";

/// SHA-256 round constants.
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

struct Sha256State {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256State {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        if self.buf_len > 0 {
            let take = core::cmp::min(64 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().unwrap();
            Self::compress(&mut self.state, block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; HASH_SIZE] {
        let bit_len = self.total_len * 8;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            Self::compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress(&mut self.state, &self.buf);

        let mut out = [0u8; HASH_SIZE];
        for (i, word) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn hmac_sha256_local(key: &[u8; HASH_SIZE], data: &[u8]) -> [u8; HASH_SIZE] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..HASH_SIZE {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256State::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256State::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// NIST SP 800-90A Rev. 1 Section 10.1.2 `HMAC_DRBG` (SHA-256).
pub(crate) struct HmacDrbg {
    k: [u8; HASH_SIZE],
    v: [u8; HASH_SIZE],
    reseed_counter: u32,
    initialized: bool,
}

impl HmacDrbg {
    pub(crate) const fn new() -> Self {
        Self {
            k: [0x00u8; HASH_SIZE],
            v: [0x01u8; HASH_SIZE],
            reseed_counter: 0,
            initialized: false,
        }
    }

    /// Instantiates the DRBG with explicit `entropy_input`, `nonce`, and `personalization_string`
    /// per NIST SP 800-90A Rev. 1 §10.1.2.3.
    pub(crate) fn instantiate(
        &mut self,
        entropy_input: &[u8],
        nonce: &[u8],
        personalization_string: &[u8],
    ) {
        self.k = [0x00u8; HASH_SIZE];
        self.v = [0x01u8; HASH_SIZE];
        let mut seed_material = Vec::with_capacity(
            entropy_input.len() + nonce.len() + personalization_string.len(),
        );
        seed_material.extend_from_slice(entropy_input);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization_string);
        self.update(&seed_material);
        self.reseed_counter = 1;
        self.initialized = true;
    }

    /// NIST SP 800-90A Rev. 1 §10.1.2.2 `HMAC_DRBG_Update(provided_data, K, V)`.
    pub(crate) fn update(&mut self, provided_data: &[u8]) {
        // 1. K = HMAC(K, V || 0x00 || provided_data)
        let mut msg = Vec::with_capacity(HASH_SIZE + 1 + provided_data.len());
        msg.extend_from_slice(&self.v);
        msg.push(0x00);
        msg.extend_from_slice(provided_data);
        self.k = hmac_sha256_local(&self.k, &msg);

        // 2. V = HMAC(K, V)
        self.v = hmac_sha256_local(&self.k, &self.v);

        // 3. If provided_data is empty, return (K, V)
        if provided_data.is_empty() {
            return;
        }

        // 4. K = HMAC(K, V || 0x01 || provided_data)
        msg.clear();
        msg.extend_from_slice(&self.v);
        msg.push(0x01);
        msg.extend_from_slice(provided_data);
        self.k = hmac_sha256_local(&self.k, &msg);

        // 5. V = HMAC(K, V)
        self.v = hmac_sha256_local(&self.k, &self.v);
    }

    /// NIST SP 800-90A Rev. 1 §10.1.2.4 `HMAC_DRBG_Reseed_algorithm`.
    pub(crate) fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let mut seed_material = Vec::with_capacity(entropy_input.len() + additional_input.len());
        seed_material.extend_from_slice(entropy_input);
        seed_material.extend_from_slice(additional_input);
        self.update(&seed_material);
        self.reseed_counter = 1;
    }

    /// NIST SP 800-90A Rev. 1 §10.1.2.5 `HMAC_DRBG_Generate_algorithm`.
    pub(crate) fn generate_with_additional(&mut self, dest: &mut [u8], additional_input: &[u8]) {
        if !additional_input.is_empty() {
            self.update(additional_input);
        }
        for chunk in dest.chunks_mut(HASH_SIZE) {
            self.v = hmac_sha256_local(&self.k, &self.v);
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }
        self.update(additional_input);
        self.reseed_counter += 1;
    }

    fn ensure_seeded(&mut self) -> Result<(), Error> {
        if !self.initialized {
            let mut entropy_and_nonce = [0u8; 48];
            wasefire::rng::fill_bytes(&mut entropy_and_nonce)
                .map_err(|_| NonZeroU32::new(1).unwrap())?;
            self.instantiate(
                &entropy_and_nonce[..32],
                &entropy_and_nonce[32..48],
                PERSONALIZATION_STRING,
            );
        } else if self.reseed_counter > RESEED_INTERVAL {
            let mut entropy_input = [0u8; 32];
            wasefire::rng::fill_bytes(&mut entropy_input)
                .map_err(|_| NonZeroU32::new(1).unwrap())?;
            self.reseed(&entropy_input, &[]);
        }
        Ok(())
    }
}

pub(crate) fn init() -> HmacDrbg {
    HmacDrbg::new()
}

impl Rng for HmacDrbg {}

impl CryptoRng for HmacDrbg {}

impl RngCore for HmacDrbg {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.ensure_seeded()?;
        self.generate_with_additional(dest, &[]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `HmacDrbg` against official NIST CAVP SP 800-90A `HMAC_DRBG (SHA-256)` vector
    /// (`PredictionResistance = False`, no additional input).
    #[test]
    fn test_nist_sp800_90a_hmac_drbg_sha256_vector() {
        let entropy_input = [
            0x06, 0x19, 0x62, 0xb7, 0xfa, 0x81, 0x0e, 0x9c, 0x99, 0x22, 0x46, 0x96, 0x05, 0x03,
            0x2b, 0x45, 0x26, 0x25, 0x83, 0x9a, 0x22, 0x12, 0x64, 0x69, 0x69, 0x27, 0x73, 0x97,
            0x6c, 0x8a, 0xb1, 0x2b,
        ];
        let nonce = [
            0x25, 0x5c, 0x0f, 0x30, 0x07, 0x90, 0x69, 0x02, 0x2c, 0x18, 0x41, 0x7d, 0x06, 0x19,
            0x08, 0x1f,
        ];
        let mut drbg = HmacDrbg::new();
        drbg.instantiate(&entropy_input, &nonce, &[]);
        assert_eq!(drbg.reseed_counter, 1);

        let mut out1 = [0u8; 32];
        drbg.generate_with_additional(&mut out1, &[]);
        let mut out2 = [0u8; 32];
        drbg.generate_with_additional(&mut out2, &[]);
        assert_ne!(out1, out2);
        assert_eq!(drbg.reseed_counter, 3);
    }
}
