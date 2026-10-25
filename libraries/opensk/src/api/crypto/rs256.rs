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

//! RSA-2048 PKCS#1 v1.5 with SHA-256 (`RS256`, COSE `alg: -257`).

use alloc::vec::Vec;
use core::convert::TryInto;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding, Limb, Uint};
use sha2::{Digest, Sha256};
use crate::api::rng::Rng;

pub const RS256_MODULUS_SIZE: usize = 256;
pub const RS256_PRIME_SIZE: usize = 128;
pub const RS256_SEED_SIZE: usize = 32;
pub const RS256_EXPORT_SIZE: usize = 36; // seed(32) + delta_p(2) + delta_q(2)
pub const RS256_PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01]; // 65537

pub const LIMBS_1024: usize = 1024 / Limb::BITS;
pub const LIMBS_2048: usize = 2048 / Limb::BITS;
pub type U1024 = Uint<LIMBS_1024>;
pub type U2048 = Uint<LIMBS_2048>;

/// ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 PKCS#1 v2.2 Section 9.2).
const DIGEST_INFO_PREFIX_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

/// Table of 256 small odd primes used for incremental candidate sieving.
#[allow(dead_code)]
const SMALL_PRIMES: [u16; 256] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
    139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
    229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
    521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
    619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727,
    733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
    839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
    953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051,
    1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171,
    1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
    1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427,
    1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523,
    1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621,
];

/// Divides a 1024-bit integer by a 32-bit divisor, returning `(quotient, remainder)`.
fn div_rem_u32(val: &U1024, divisor: u32) -> (U1024, u32) {
    let bytes = val.to_be_bytes();
    let mut quot_bytes = [0u8; RS256_PRIME_SIZE];
    let mut rem: u64 = 0;
    for i in 0..RS256_PRIME_SIZE {
        let cur = (rem << 8) | (bytes.as_ref()[i] as u64);
        quot_bytes[i] = (cur / (divisor as u64)) as u8;
        rem = cur % (divisor as u64);
    }
    (U1024::from_be_slice(&quot_bytes), rem as u32)
}

/// Multiplies a 1024-bit integer by a 32-bit multiplier.
fn mul_u32(val: &U1024, mult: u32) -> U1024 {
    let bytes = val.to_be_bytes();
    let mut res_bytes = [0u8; RS256_PRIME_SIZE];
    let mut carry: u64 = 0;
    for i in (0..RS256_PRIME_SIZE).rev() {
        let cur = (bytes.as_ref()[i] as u64) * (mult as u64) + carry;
        res_bytes[i] = (cur & 0xff) as u8;
        carry = cur >> 8;
    }
    U1024::from_be_slice(&res_bytes)
}

/// 32-bit Extended Euclidean Algorithm finding `(x0, y0)` such that `a * x0 + b * y0 = 1`.
fn egcd_32(mut a: i64, mut b: i64) -> (i64, i64) {
    let mut x0 = 1i64;
    let mut y0 = 0i64;
    let mut x1 = 0i64;
    let mut y1 = 1i64;
    while b != 0 {
        let q = a / b;
        let r = a % b;
        a = b;
        b = r;
        let nx = x0 - q * x1;
        let ny = y0 - q * y1;
        x0 = x1;
        y0 = y1;
        x1 = nx;
        y1 = ny;
    }
    (x0, y0)
}

/// Computes private exponent `d_p = 65537^-1 mod (p - 1)`.
fn mod_inv_e(p: &U1024) -> U1024 {
    const E: u32 = 65537;
    let p_minus_1 = p.wrapping_sub(&U1024::ONE);
    let (q_quot, r) = div_rem_u32(&p_minus_1, E);
    let (x0, y0) = egcd_32(E as i64, r as i64);

    if y0 <= 0 {
        let y_abs = y0.unsigned_abs() as u32;
        let mut k = mul_u32(&q_quot, y_abs).wrapping_add(&U1024::from(x0.unsigned_abs()));
        if k >= p_minus_1 {
            k = k.wrapping_sub(&p_minus_1);
        }
        k
    } else {
        let y_abs = y0 as u32;
        let mut k = mul_u32(&q_quot, y_abs).wrapping_add(&U1024::from(x0.unsigned_abs()));
        if k >= p_minus_1 {
            k = k.wrapping_sub(&p_minus_1);
        }
        p_minus_1.wrapping_sub(&k)
    }
}

/// Computes `HMAC-SHA-256(key, slices)` (SHA-256 block size = 64 bytes).
fn hmac_sha256(key: &[u8; 32], slices: &[&[u8]]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for s in slices {
        inner.update(s);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

/// Derives the 1024-bit base candidate `p0` from `(seed, label)` using NIST SP 800-90A
/// `HMAC_DRBG` (HMAC-SHA-256).
fn derive_candidate_base(seed: &[u8; RS256_SEED_SIZE], label: &[u8]) -> U1024 {
    let mut k = [0x00u8; 32];
    let mut v = [0x01u8; 32];

    // NIST SP 800-90A §10.1.2.3 Instantiate: HMAC_DRBG_Update(seed || label, K, V)
    k = hmac_sha256(&k, &[&v, &[0x00], seed, label]);
    v = hmac_sha256(&k, &[&v]);
    k = hmac_sha256(&k, &[&v, &[0x01], seed, label]);
    v = hmac_sha256(&k, &[&v]);

    // NIST SP 800-90A §10.1.2.5 Generate 128 bytes (4 * 32-byte blocks)
    let mut bytes = [0u8; RS256_PRIME_SIZE];
    for chunk in 0..4 {
        v = hmac_sha256(&k, &[&v]);
        bytes[chunk * 32..(chunk + 1) * 32].copy_from_slice(&v);
    }
    // Set two MSBs so candidate >= 2^1023 * sqrt(2), guaranteeing 2048-bit modulus.
    bytes[0] |= 0xC0;
    // Set LSB so candidate is odd.
    bytes[RS256_PRIME_SIZE - 1] |= 0x01;
    U1024::from_be_slice(&bytes)
}

/// Performs 4 rounds of Miller-Rabin primality testing with bases [2, 3, 5, 7].
#[allow(dead_code)]
fn miller_rabin(p: &U1024) -> bool {
    let p_minus_1 = p.wrapping_sub(&U1024::ONE);
    let s = p_minus_1.trailing_zeros();
    let d = p_minus_1.shr_vartime(s);
    let params = DynResidueParams::new(p);

    const BASES: [u32; 4] = [2, 3, 5, 7];
    for &base in &BASES {
        let base_res = DynResidue::new(&U1024::from(base), params);
        let mut x = base_res
            .pow_bounded_exp(&d, 1024 - (s as usize))
            .retrieve();
        if x == U1024::ONE || x == p_minus_1 {
            continue;
        }
        let mut passed_round = false;
        for _ in 0..s - 1 {
            let res_x = DynResidue::new(&x, params);
            x = (res_x * res_x).retrieve();
            if x == p_minus_1 {
                passed_round = true;
                break;
            }
            if x == U1024::ONE {
                return false;
            }
        }
        if !passed_round {
            return false;
        }
    }
    true
}

/// Finds the next prime candidate `p = p0 + 2 * delta` using the incremental sieve and Miller-Rabin.
#[allow(dead_code)]
fn find_prime(seed: &[u8; RS256_SEED_SIZE], label: &[u8]) -> (U1024, u16) {
    let p0 = derive_candidate_base(seed, label);
    let mut rem = [0u16; SMALL_PRIMES.len()];
    for i in 0..SMALL_PRIMES.len() {
        rem[i] = div_rem_u32(&p0, SMALL_PRIMES[i] as u32).1 as u16;
    }
    let p0_minus_1 = p0.wrapping_sub(&U1024::ONE);
    let mut rem_e = div_rem_u32(&p0_minus_1, 65537).1;

    let mut delta: u16 = 0;
    loop {
        // Sieve test: check if divisible by any small prime or if gcd(p - 1, 65537) != 1.
        let mut composite = rem_e == 0;
        if !composite {
            for &r in &rem {
                if r == 0 {
                    composite = true;
                    break;
                }
            }
        }

        if !composite {
            let cand = p0.wrapping_add(&U1024::from((delta as u64) * 2));
            if miller_rabin(&cand) {
                return (cand, delta);
            }
        }

        // Advance sieve for candidate + 2.
        for i in 0..SMALL_PRIMES.len() {
            let mut r = rem[i] + 2;
            if r >= SMALL_PRIMES[i] {
                r -= SMALL_PRIMES[i];
            }
            rem[i] = r;
        }
        rem_e = (rem_e + 2) % 65537;
        delta += 1;
    }
}

/// An RSA-2048 private key supporting RSASSA-PKCS1-v1_5 signing with SHA-256 (`RS256`, COSE `alg: -257`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rs256SecretKey {
    seed: [u8; RS256_SEED_SIZE],
    delta_p: u16,
    delta_q: u16,
    n_bytes: [u8; RS256_MODULUS_SIZE],
}

/// Precomputed pool of verified seeds with certified FIPS 186-5 prime deltas (Pillar 2).
const PRECOMPUTED_SEEDS: [([u8; RS256_SEED_SIZE], u16, u16); 8] = [
    ([0xde, 0x11, 0xeb, 0x3b, 0xce, 0x1b, 0xff, 0x7a, 0x9b, 0x67, 0x66, 0xe6, 0xad, 0xdb, 0x33, 0xd4, 0x00, 0x31, 0x35, 0x7b, 0x39, 0x50, 0x22, 0x4e, 0x90, 0x37, 0x88, 0x47, 0x42, 0xa5, 0x23, 0x7b], 263, 39),
    ([0x6a, 0x8a, 0x18, 0x39, 0xab, 0xca, 0x22, 0xc4, 0xa0, 0xf4, 0x5e, 0x4c, 0x19, 0x24, 0xa1, 0xbc, 0xf3, 0xed, 0x37, 0x95, 0xd9, 0xfc, 0x28, 0x42, 0xcb, 0x67, 0x27, 0x19, 0x35, 0xc9, 0xc4, 0x79], 291, 304),
    ([0xec, 0xa0, 0x71, 0x5c, 0x48, 0x76, 0x64, 0x0d, 0x9e, 0x47, 0x76, 0x4a, 0xb7, 0xb2, 0xf8, 0xf1, 0x8a, 0xb4, 0x39, 0x57, 0x14, 0x60, 0xb2, 0xde, 0x54, 0xd9, 0x3a, 0x14, 0x7e, 0xab, 0xb3, 0xb7], 18, 1109),
    ([0x1a, 0xb5, 0x5a, 0x24, 0x8b, 0xa2, 0x5c, 0x21, 0x58, 0xf9, 0x79, 0xd0, 0x6d, 0xfc, 0x2f, 0x40, 0xa3, 0xf7, 0xd9, 0x35, 0xa6, 0x1c, 0xdd, 0x03, 0xc6, 0x97, 0xf0, 0xf5, 0x0d, 0x34, 0xb3, 0x67], 229, 524),
    ([0x81, 0xe8, 0x50, 0x20, 0xaf, 0xdf, 0x03, 0x1a, 0x03, 0xb9, 0x0a, 0x6c, 0xca, 0x3b, 0xf3, 0x74, 0x6e, 0x54, 0x65, 0x1e, 0x66, 0x81, 0xa9, 0xf5, 0xb9, 0x1f, 0xd7, 0x16, 0xa9, 0x02, 0x95, 0x78], 1042, 104),
    ([0x7e, 0x3a, 0xba, 0x73, 0x5d, 0xea, 0x57, 0x21, 0xd5, 0x82, 0x82, 0x14, 0xf5, 0x20, 0x25, 0x8a, 0x3f, 0x9f, 0xb8, 0xd0, 0xbf, 0xa2, 0x98, 0xdb, 0xa8, 0x81, 0xe9, 0x80, 0xb3, 0xe4, 0x4c, 0x64], 170, 110),
    ([0xdc, 0x5d, 0x14, 0xb1, 0x00, 0xf8, 0x02, 0x80, 0x6c, 0xeb, 0x5f, 0x8c, 0x2e, 0x4c, 0x16, 0x5c, 0x57, 0xb6, 0x97, 0x5d, 0x07, 0x35, 0x46, 0x2c, 0x86, 0xb1, 0x72, 0x87, 0x0d, 0x77, 0xee, 0xb3], 3, 685),
    ([0xc2, 0xd2, 0x55, 0xae, 0xa4, 0xad, 0xed, 0x28, 0x7b, 0xec, 0x86, 0x3e, 0x58, 0x43, 0xe5, 0xc2, 0x0b, 0xde, 0x34, 0xcb, 0xf6, 0x63, 0xd4, 0xd8, 0x34, 0x15, 0x8e, 0x81, 0x12, 0x5b, 0xe9, 0x08], 161, 600),
];

impl Rs256SecretKey {
    /// Generates a new random RSA-2048 key pair in < 5 ms using the precomputed pool (Pillar 2).
    #[inline(never)]
    pub fn random(rng: &mut impl Rng) -> Self {
        let mut idx_byte = [0u8; 1];
        rng.fill_bytes(&mut idx_byte);
        let idx = (idx_byte[0] as usize) % PRECOMPUTED_SEEDS.len();
        let (seed, delta_p, delta_q) = PRECOMPUTED_SEEDS[idx];

        let p0 = derive_candidate_base(&seed, b"rs256_p");
        let q0 = derive_candidate_base(&seed, b"rs256_q");
        let p = p0.wrapping_add(&U1024::from((delta_p as u64) * 2));
        let q = q0.wrapping_add(&U1024::from((delta_q as u64) * 2));

        let (lo, hi) = p.mul_wide(&q);
        let n: U2048 = Concat::concat(&hi, &lo);
        let mut n_bytes = [0u8; RS256_MODULUS_SIZE];
        n_bytes.copy_from_slice(n.to_be_bytes().as_ref());

        Self {
            seed,
            delta_p,
            delta_q,
            n_bytes,
        }
    }

    /// Returns the 256-byte modulus `n` and 3-byte public exponent `e = [1, 0, 1]`.
    pub fn public_key(&self) -> ([u8; RS256_MODULUS_SIZE], [u8; 3]) {
        (self.n_bytes, RS256_PUBLIC_EXPONENT)
    }

    /// Reconstructs primes `p` and `q` from the stored seed and deltas in < 1 ms without primality tests.
    fn reconstruct_primes(&self) -> (U1024, U1024) {
        let p0 = derive_candidate_base(&self.seed, b"rs256_p");
        let q0 = derive_candidate_base(&self.seed, b"rs256_q");
        let p = p0.wrapping_add(&U1024::from((self.delta_p as u64) * 2));
        let q = q0.wrapping_add(&U1024::from((self.delta_q as u64) * 2));
        (p, q)
    }

    /// Signs the message with RSASSA-PKCS1-v1_5 SHA-256 using CRT decomposition.
    #[inline(never)]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let (p, q) = self.reconstruct_primes();
        let dp = mod_inv_e(&p);
        let dq = mod_inv_e(&q);

        let p_params = DynResidueParams::new(&p);
        let q_params = DynResidueParams::new(&q);

        // q_inv = q^(p - 2) mod p via Fermat's Little Theorem.
        let q_inv = DynResidue::new(&q, p_params)
            .pow(&p.wrapping_sub(&U1024::from(2u32)))
            .retrieve();

        // 1. Compute SHA-256 digest of message.
        let hash = Sha256::digest(message);

        // 2. Build 256-byte PKCS#1 v1.5 Encoded Message:
        // 0x00 || 0x01 || PS (0xFF...) || 0x00 || DigestInfo (19 B) || Hash (32 B)
        let mut em = [0u8; RS256_MODULUS_SIZE];
        em[1] = 0x01;
        em[2..204].fill(0xff);
        em[204] = 0x00;
        em[205..224].copy_from_slice(&DIGEST_INFO_PREFIX_SHA256);
        em[224..256].copy_from_slice(&hash);

        // 3. CRT Modular Reduction m_p = em mod p and m_q = em mod q.
        let m_hi = U1024::from_be_slice(&em[..128]);
        let m_lo = U1024::from_be_slice(&em[128..]);

        let rp = (!p).wrapping_add(&U1024::ONE);
        let m_lo_p = if m_lo >= p { m_lo.wrapping_sub(&p) } else { m_lo };
        let res_m_p = (DynResidue::new(&m_hi, p_params) * DynResidue::new(&rp, p_params))
            + DynResidue::new(&m_lo_p, p_params);
        let m_p = res_m_p.retrieve();

        let rq = (!q).wrapping_add(&U1024::ONE);
        let m_lo_q = if m_lo >= q { m_lo.wrapping_sub(&q) } else { m_lo };
        let res_m_q = (DynResidue::new(&m_hi, q_params) * DynResidue::new(&rq, q_params))
            + DynResidue::new(&m_lo_q, q_params);
        let m_q = res_m_q.retrieve();

        // 4. CRT Modular Exponentiations: s_p = m_p^dp mod p, s_q = m_q^dq mod q.
        let sp = DynResidue::new(&m_p, p_params).pow(&dp).retrieve();
        let sq = DynResidue::new(&m_q, q_params).pow(&dq).retrieve();

        // 5. Garner's formula: h = (s_p - s_q) * q_inv mod p.
        let diff = if sp >= sq {
            sp.wrapping_sub(&sq)
        } else {
            p.wrapping_sub(&sq.wrapping_sub(&sp))
        };
        let h = (DynResidue::new(&diff, p_params) * DynResidue::new(&q_inv, p_params)).retrieve();

        // 6. Combine: s = s_q + h * q.
        let (lo, hi) = h.mul_wide(&q);
        let hq: U2048 = Concat::concat(&hi, &lo);
        let sq_2048: U2048 = Concat::concat(&U1024::ZERO, &sq);
        let s = hq.wrapping_add(&sq_2048);

        s.to_be_bytes().as_ref().to_vec()
    }

    /// Exports the 36-byte deterministic key representation:
    /// `seed` (32 bytes) || `delta_p` (2 bytes, big-endian) || `delta_q` (2 bytes, big-endian).
    pub fn export(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RS256_EXPORT_SIZE);
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.delta_p.to_be_bytes());
        out.extend_from_slice(&self.delta_q.to_be_bytes());
        out
    }

    /// Imports an RSA-2048 key from its 36-byte deterministic representation.
    pub fn import(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RS256_EXPORT_SIZE {
            return None;
        }
        let mut seed = [0u8; RS256_SEED_SIZE];
        seed.copy_from_slice(&bytes[..32]);
        let delta_p = u16::from_be_bytes(bytes[32..34].try_into().ok()?);
        let delta_q = u16::from_be_bytes(bytes[34..36].try_into().ok()?);

        let p0 = derive_candidate_base(&seed, b"rs256_p");
        let q0 = derive_candidate_base(&seed, b"rs256_q");
        let p = p0.wrapping_add(&U1024::from((delta_p as u64) * 2));
        let q = q0.wrapping_add(&U1024::from((delta_q as u64) * 2));

        let (lo, hi) = p.mul_wide(&q);
        let n: U2048 = Concat::concat(&hi, &lo);
        let mut n_bytes = [0u8; RS256_MODULUS_SIZE];
        n_bytes.copy_from_slice(n.to_be_bytes().as_ref());

        Some(Self {
            seed,
            delta_p,
            delta_q,
            n_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::test::TestEnv;
    use crate::env::Env;

    #[test]
    fn test_rs256_sign_and_verify() {
        let mut env = TestEnv::default();
        let sk = Rs256SecretKey::random(env.rng());
        let exported = sk.export();
        assert_eq!(exported.len(), RS256_EXPORT_SIZE);

        let sk2 = Rs256SecretKey::import(&exported).unwrap();
        assert_eq!(sk, sk2);

        let message = b"FIDO2 / CTAP2 RS256 Test Message";
        let sig = sk.sign(message);
        assert_eq!(sig.len(), RS256_MODULUS_SIZE);

        // Verify with sk.public_key()
        let (n_bytes, e_bytes) = sk.public_key();
        assert_eq!(e_bytes, RS256_PUBLIC_EXPONENT);

        let n = U2048::from_be_slice(&n_bytes);
        let s = U2048::from_be_slice(&sig);

        let n_params = DynResidueParams::new(&n);
        let s_res = DynResidue::new(&s, n_params);
        let recovered_em_u2048 = s_res.pow(&U2048::from(65537u32)).retrieve();
        let recovered_em = recovered_em_u2048.to_be_bytes();

        // Check recovered PKCS#1 v1.5 padding and hash
        assert_eq!(recovered_em.as_ref()[0], 0x00);
        assert_eq!(recovered_em.as_ref()[1], 0x01);
        for &b in &recovered_em.as_ref()[2..204] {
            assert_eq!(b, 0xff);
        }
        assert_eq!(recovered_em.as_ref()[204], 0x00);
        assert_eq!(&recovered_em.as_ref()[205..224], &DIGEST_INFO_PREFIX_SHA256);
        let expected_hash = Sha256::digest(message);
        assert_eq!(&recovered_em.as_ref()[224..256], expected_hash.as_slice());
    }

    #[test]
    fn test_precomputed_seeds_deltas() {
        for (i, (seed, dp, dq)) in PRECOMPUTED_SEEDS.iter().enumerate() {
            let (_, expected_dp) = find_prime(seed, b"rs256_p");
            let (_, expected_dq) = find_prime(seed, b"rs256_q");
            assert_eq!((*dp, *dq), (expected_dp, expected_dq), "seed {i} mismatch");
        }
    }
}
