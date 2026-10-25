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

//! Pure-Rust `no_std` implementation of RFC 8032 Ed448 (Curve448-Goldilocks) for COSE `Ed448` (`-53`).

use crate::api::rng::Rng;
use alloc::vec::Vec;
use core::convert::TryFrom;
use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

/// Size in bytes of an RFC 8032 Ed448 private key seed or public key (57 octets / 456 bits).
pub const ED448_KEY_SIZE: usize = 57;

/// Size in bytes of an RFC 8032 Ed448 signature (114 octets).
pub const ED448_SIG_SIZE: usize = 114;

const MASK56: u64 = (1u64 << 56) - 1;
const EDWARDS_D_ABS: u64 = 39081; // d = -39081 mod p

/// Goldilocks prime field element modulo `p = 2^448 - 2^224 - 1` in radix `2^56` (little-endian limbs).
#[derive(Clone, Copy, Debug)]
struct Fe([u64; 8]);

impl Fe {
    const ZERO: Self = Self([0; 8]);
    const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    #[cfg(test)]
    fn from_le_bytes_56(bytes: &[u8; 56]) -> Self {
        let mut limbs = [0u64; 8];
        for i in 0..8 {
            let offset = i * 7;
            let mut w = 0u64;
            for j in 0..7 {
                w |= (bytes[offset + j] as u64) << (j * 8);
            }
            limbs[i] = w;
        }
        Self(limbs)
    }

    /// Decodes a 57-byte field element `< p` (used for point decompression).
    #[cfg(test)]
    fn from_canonical_bytes(bytes: &[u8; ED448_KEY_SIZE]) -> Option<Self> {
        if bytes[56] != 0 {
            return None;
        }
        let mut le56 = [0u8; 56];
        le56.copy_from_slice(&bytes[..56]);
        let fe = Self::from_le_bytes_56(&le56);
        if &fe.to_bytes()[..56] != &le56[..] {
            return None;
        }
        Some(fe)
    }

    #[inline]
    fn reduce_weak(&mut self) {
        let mut carry = self.0[7] >> 56;
        self.0[7] &= MASK56;
        self.0[0] += carry;
        self.0[4] += carry;
        for i in 0..7 {
            let c = self.0[i] >> 56;
            self.0[i] &= MASK56;
            self.0[i + 1] += c;
        }
        carry = self.0[7] >> 56;
        self.0[7] &= MASK56;
        self.0[0] += carry;
        self.0[4] += carry;
    }

    fn add(&self, rhs: &Self) -> Self {
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = self.0[i] + rhs.0[i];
        }
        let mut res = Self(out);
        res.reduce_weak();
        res
    }

    fn sub(&self, rhs: &Self) -> Self {
        // Add 2*p to avoid underflow before weak reduction.
        let mut out = [0u64; 8];
        for i in 0..8 {
            let two_p_i = if i == 4 {
                2 * (MASK56 - 1)
            } else {
                2 * MASK56
            };
            out[i] = self.0[i] + two_p_i - rhs.0[i];
        }
        let mut res = Self(out);
        res.reduce_weak();
        res
    }

    #[cfg(test)]
    fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    fn mul_small(&self, rhs: u64) -> Self {
        let mut c = [0u128; 8];
        for i in 0..8 {
            c[i] = (self.0[i] as u128) * (rhs as u128);
        }
        Self::reduce_u128(&mut c)
    }

    fn mul(&self, rhs: &Self) -> Self {
        let mut c = [0u128; 15];
        for i in 0..8 {
            let a_i = self.0[i] as u128;
            for j in 0..8 {
                c[i + j] += a_i * (rhs.0[j] as u128);
            }
        }
        // Fold c[12..15] using 2^448 == 2^224 + 1 (mod p)
        for i in 12..15 {
            let v = c[i];
            c[i - 8] += v;
            c[i - 4] += v;
        }
        // Fold c[8..12] using 2^448 == 2^224 + 1 (mod p)
        for i in 8..12 {
            let v = c[i];
            c[i - 8] += v;
            c[i - 4] += v;
        }
        let mut low = [0u128; 8];
        low.copy_from_slice(&c[..8]);
        Self::reduce_u128(&mut low)
    }

    #[inline]
    fn square(&self) -> Self {
        self.mul(self)
    }

    fn reduce_u128(c: &mut [u128; 8]) -> Self {
        let mut carry: u128 = 0;
        let mut out = [0u64; 8];
        for i in 0..8 {
            let v = c[i] + carry;
            out[i] = (v as u64) & MASK56;
            carry = v >> 56;
        }
        // Fold carry * 2^448 == carry * (2^224 + 1)
        let v0 = (out[0] as u128) + carry;
        out[0] = (v0 as u64) & MASK56;
        let mut c_lo = (v0 >> 56) as u64;
        for i in 1..4 {
            let v = out[i] + c_lo;
            out[i] = v & MASK56;
            c_lo = v >> 56;
        }
        let v4 = (out[4] as u128) + carry + (c_lo as u128);
        out[4] = (v4 as u64) & MASK56;
        let mut c_hi = (v4 >> 56) as u64;
        for i in 5..8 {
            let v = out[i] + c_hi;
            out[i] = v & MASK56;
            c_hi = v >> 56;
        }
        out[0] += c_hi;
        out[4] += c_hi;
        let mut res = Self(out);
        res.reduce_weak();
        res
    }

    /// Computes canonical 57-byte little-endian encoding of `self mod p`.
    fn to_bytes(&self) -> [u8; ED448_KEY_SIZE] {
        let mut tmp = *self;
        tmp.reduce_weak();
        for i in 0..7 {
            let c = tmp.0[i] >> 56;
            tmp.0[i] &= MASK56;
            tmp.0[i + 1] += c;
        }
        let carry = tmp.0[7] >> 56;
        tmp.0[7] &= MASK56;
        tmp.0[0] += carry;
        tmp.0[4] += carry;
        for i in 0..7 {
            let c = tmp.0[i] >> 56;
            tmp.0[i] &= MASK56;
            tmp.0[i + 1] += c;
        }

        // Conditionally subtract p if tmp >= p.
        let mut diff = [0u64; 8];
        let mut borrow: i64 = 0;
        for i in 0..8 {
            let p_i = if i == 4 { MASK56 - 1 } else { MASK56 };
            let v = (tmp.0[i] as i64) - (p_i as i64) - borrow;
            diff[i] = (v as u64) & MASK56;
            borrow = (v >> 56) & 1;
        }
        // If borrow == 0, tmp >= p so use diff; if borrow == 1, keep tmp.0.
        let mask = (borrow as u64).wrapping_neg(); // 0 if borrow==0, !0 if borrow==1
        let mut out = [0u8; ED448_KEY_SIZE];
        for i in 0..8 {
            let limb = (tmp.0[i] & mask) | (diff[i] & !mask);
            let bytes = limb.to_le_bytes();
            out[7 * i..7 * i + 7].copy_from_slice(&bytes[..7]);
        }
        out
    }

    #[inline]
    fn square_n(&self, mut n: usize) -> Self {
        let mut res = *self;
        while n > 0 {
            res = res.square();
            n -= 1;
        }
        res
    }

    /// Computes `self^(p - 2) mod p` for field inversion.
    /// Uses Hamburg's addition chain for Goldilocks prime p = 2^448 - 2^224 - 1:
    /// p - 2 = ((2^223 - 1) * 2) * 2^224 + ((2^222 - 1) * 4 + 1)
    /// 449 squarings and only 15 field multiplications (vs 446 multiplications previously).
    fn invert(&self) -> Self {
        let t1 = *self;
        let t2 = t1.square().mul(&t1);
        let t3 = t2.square().mul(&t1);
        let t6 = t3.square_n(3).mul(&t3);
        let t12 = t6.square_n(6).mul(&t6);
        let t24 = t12.square_n(12).mul(&t12);
        let t27 = t24.square_n(3).mul(&t3);
        let t54 = t27.square_n(27).mul(&t27);
        let t55 = t54.square().mul(&t1);
        let t110 = t55.square_n(55).mul(&t55);
        let t220 = t110.square_n(110).mul(&t110);
        let t221 = t220.square().mul(&t1);
        let t222 = t221.square().mul(&t1);
        let t223 = t222.square().mul(&t1);

        // high part: a^((2^223 - 1) * 2) = t223^2, shifted by 224 bits
        let high = t223.square().square_n(224);

        // low part: a^((2^222 - 1) * 4 + 1) = t222^4 * a
        let low = t222.square_n(2).mul(&t1);

        high.mul(&low)
    }

    /// Computes `self^((p + 1) / 4) mod p` for candidate square root (`p == 3 mod 4`).
    /// `(p + 1) / 4 = 2^446 - 2^222`:
    /// - bits 445..=222: 1 (224 ones)
    /// - bits 221..=0: 0 (222 zeros)
    #[cfg(test)]
    fn sqrt_candidate(&self) -> Self {
        let mut acc = Self::ONE;
        for bit in (0..446).rev() {
            acc = acc.square();
            if bit >= 222 {
                acc = acc.mul(self);
            }
        }
        acc
    }

    #[inline]
    fn ct_select(a: &Self, b: &Self, choice: u64) -> Self {
        let mask = choice.wrapping_neg();
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = (a.0[i] & !mask) | (b.0[i] & mask);
        }
        Self(out)
    }
}

/// Projective point `(X : Y : Z)` on untwisted Edwards448 (`x^2 + y^2 = 1 + d x^2 y^2`).
#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// RFC 8032 Section 5.2 group order `L` in little-endian `u64` limbs (`L < 2^446`).
const ORDER_L: [u64; 7] = [
    0x2378_c292_ab58_44f3,
    0x216c_c272_8dc5_8f55,
    0xc44e_db49_aed6_3690,
    0xffff_ffff_7cca_23e9,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
];

/// Precomputed 4-tooth comb table for basepoint B:
/// T[i] = sum_{k=0}^3 b_k * 2^(112*k) * B for i = (b_3 b_2 b_1 b_0)_2.
/// Stored in affine coordinates (x, y) where each coordinate is 8 x 56-bit radix limbs.
const BASE_COMB_TABLE: [(Fe, Fe); 16] = [
    // Index  0 (b3..b0 = 0000)
    (Fe([0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000]), Fe([0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000])),
    // Index  1 (b3..b0 = 0001)
    (Fe([0x26a82bc70cc05e, 0x80e18b00938e26, 0xf72ab66511433b, 0xa3d3a46412ae1a, 0x0f1767ea6de324, 0x36da9e14657047, 0xed221d15a622bf, 0x4f1970c66bed0d]), Fe([0x08795bf230fa14, 0x132c4ed7c8ad98, 0x1ce67c39c4fdbd, 0x05a0c2d73ad3ff, 0xa3984087789c1e, 0xc7624bea73736c, 0x248876203756c9, 0x693f46716eb6bc])),
    // Index  2 (b3..b0 = 0010)
    (Fe([0x0079817464238e, 0x21103020d381ca, 0x1cc4c6ed9f01b5, 0x5e35dc55a131b1, 0xb61848d06944eb, 0x83792a029631a3, 0xbe1017fafca0dd, 0x70aaa01782fcbb]), Fe([0xc63b7a099945e7, 0xe9164ecc4486c1, 0xb133e35885f2c1, 0x186f0d3c99ae02, 0x2fca4922bf53e6, 0xf922aa248a02bc, 0x4fe64900dd3dca, 0xe8c313ff6a8207])),
    // Index  3 (b3..b0 = 0011)
    (Fe([0xb2f9f62e7661f9, 0x3b9980309fae89, 0x67900ef66014d2, 0xc8eacf36556c10, 0x20a44d0ad4a82e, 0xe7819e70572f1c, 0xc0ed140fd08cdf, 0xa16934a9aee1da]), Fe([0xa1ffe8b579a4e2, 0x1d006b3ce472b4, 0x7c8f68989def96, 0x79d7bd1a32ae93, 0xebb47763a02760, 0x19b3c6c5b4c55e, 0x66ff7827da436f, 0xee40076659536d])),
    // Index  4 (b3..b0 = 0100)
    (Fe([0xa7ea98991780c7, 0x04e4eccd2476b6, 0x0af9f58c494b68, 0xe0f269fdee64fd, 0x85a61f6021bd26, 0xc265c35b5d284b, 0x58755ea3775afd, 0x617f1742ecf2c6]), Fe([0x50109e25ec556a, 0x235366bfd57e39, 0x7b3c97644b6b2e, 0xf7f9e82b2b7b9c, 0xb6196ab0ec6409, 0x88f1d160a20d9e, 0xe3be3b4586f761, 0x9983c26e26395d])),
    // Index  5 (b3..b0 = 0101)
    (Fe([0xdbf4eb667f4947, 0x2206a2ab8716d9, 0x4a148b0e7cad5a, 0xfbf12cde483133, 0xe022d5ac6458f7, 0xa60afe61b7e39d, 0xc62f4585a5208c, 0xa08a4c33311553]), Fe([0xded288efab8e56, 0xa4e6f4e57277e6, 0xa2a4c4fe949681, 0x508a46c721fdb3, 0xf98049efb44de2, 0x71f37242fb0f31, 0xd3fbbb39067763, 0x696ec4aa83faaa])),
    // Index  6 (b3..b0 = 0110)
    (Fe([0xad5dc54054a90d, 0x97f2af40ac9fd6, 0x1b0f7b3f4ddbc7, 0x1d5d092324ce0b, 0x8cb96e2cd2798f, 0xbd045b5957bc39, 0x46308a9f76fbfb, 0xc86d628ef679ce]), Fe([0xf52ae707a04bb0, 0x784d14bae14cdb, 0x9aa386934acc37, 0x8f79c879703f7b, 0x859cde5264026c, 0xb2a45f7486b035, 0x809740f3d5144b, 0xdcf324d416dc87])),
    // Index  7 (b3..b0 = 0111)
    (Fe([0xf251539d5d9262, 0x240708f711a956, 0x7f7e4dd4a0b0bc, 0x65dd24f55b70a8, 0xe83cec77ef8979, 0xf1db2d19589db8, 0xfcc7e8a9d93037, 0xcb99f0b4e0b8f4]), Fe([0x4125ceca0c8bc7, 0xd30ff7eeac3f20, 0x6901f0529ad678, 0x33c307d4805ff1, 0x80f071049d6a79, 0xd1ba22b2dece6c, 0x1692a0b778cccb, 0xf8c02d32df78fb])),
    // Index  8 (b3..b0 = 1000)
    (Fe([0x6f241004acea57, 0xdace1c6da68597, 0xea7dd4150ce77f, 0x1aecb841585884, 0x92ff208ea4a85c, 0xde9433c88eebd2, 0x53cd3183f4d289, 0x397085826539af]), Fe([0x4b57599b827d87, 0xdc82ac03d77638, 0x694336652f6e61, 0xb8fc4b0ad5e8a6, 0x1b6f7dcf388642, 0x6f24533a74dd57, 0xc66937841750cf, 0x06757eb28a37af])),
    // Index  9 (b3..b0 = 1001)
    (Fe([0x6e9fd2bd229665, 0x49345aa878dd51, 0xccde72af45bacf, 0xbc249d1be16b6f, 0xa25bae9448a61d, 0xc93b6ead773878, 0x55f708a2cda508, 0xfa568528cf49e6]), Fe([0xef186a880128d5, 0x1ceb43b4a54843, 0xc112a4245be148, 0x621b93a1ac9412, 0xa2ca24f5e16552, 0xcf3fecf86301c0, 0x51088055c2e2e0, 0xd2ba3419e9d8ab])),
    // Index 10 (b3..b0 = 1010)
    (Fe([0x7bec8db93bfef9, 0xce4dcdcfafda3d, 0xa75c8726f62ed7, 0xc39ac927b3dadd, 0xae1b8d1f926d90, 0xd7dbeca48da0a9, 0xec13f742a52b3b, 0x2071ceed4c5ce2]), Fe([0xf0d3e4c2138911, 0x62382cec1a371b, 0x9d954e75b3a392, 0x047d71a517d2a1, 0x9cd17337f70073, 0x549d0d1efc3aea, 0x666e074df78457, 0xf67e924a48e084])),
    // Index 11 (b3..b0 = 1011)
    (Fe([0xe56b0a95a644a6, 0x1ecf90ebe6360b, 0xc3bbcf723b73a8, 0x5417d25292054b, 0xca1ea057b91b46, 0x1560b217ea6c44, 0x463cd2a4f12989, 0x092781c3d7e086]), Fe([0x73bec50b3114fe, 0x1c5e7b6e8b6172, 0xa1c3ae1e896bcc, 0xbb3f870bcd8cab, 0xeea85467e9fa9d, 0x56431f0042e2cf, 0x8eb9b9c469e8d2, 0x6856458a9adf2c])),
    // Index 12 (b3..b0 = 1100)
    (Fe([0xce08d7ed59796d, 0xe46444355bc822, 0x542002fd243cc4, 0x44fc57698259b3, 0x865055012781de, 0x137f762055e6b4, 0xa391cccfbf007e, 0xa9c9ad339fe6f6]), Fe([0x18555307b2cfdd, 0x181624673bd43a, 0x2f82d128897062, 0x65178573563816, 0x529bf2e394a8c7, 0x660c4f275a3141, 0x787c8ad18e5a16, 0xabaec0145b679e])),
    // Index 13 (b3..b0 = 1101)
    (Fe([0xccddbb01ca2765, 0x5d18f4c563b46c, 0x2ff700d462647e, 0x670b143822dc83, 0x1627d780013963, 0x435f41355dbfb9, 0x66c95cd63d41e8, 0x8e27dfbc797bba]), Fe([0x7c9fabb6d87d9e, 0x673b28a3b2a99d, 0xefb205e68816ee, 0x3d21920dd5e3d5, 0x85f40c27544f4d, 0x57d045b6fb538d, 0x28a93c35470e4e, 0xd1cf7a563adfd4])),
    // Index 14 (b3..b0 = 1110)
    (Fe([0x1ff4dd63da4531, 0x2d0de4ccd39a3c, 0x003561ebc9da8d, 0x01eea0033e1e9a, 0x5458c5378bf710, 0x69043abf56338e, 0x637cf4161ffba0, 0xfc0975739fb551]), Fe([0xc83c8376699694, 0x621103f386dade, 0x6058f43f247dc3, 0xb1ac29aaec07c3, 0x6e35e33bde5d50, 0x516263c78fd31c, 0x4a133790a9d127, 0xf39316a78bec6e])),
    // Index 15 (b3..b0 = 1111)
    (Fe([0xf1e0e38256141f, 0xefd5f470ab2673, 0xb749116af4a4af, 0x4242f82ac6540b, 0xb26730cabaf195, 0x76fbe60d06842d, 0x2613d91580cad8, 0xc2e5b1db568ae0]), Fe([0x5ecf40ee26ea19, 0x7c284a03bdf1b5, 0x83934626f461fa, 0x7d4f6a564a69aa, 0x23059e96e88ea4, 0xc4a8035f92bd0b, 0xfccec22c5c44a2, 0x598207c7f57ea1])),
];

impl Point {
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    #[cfg(test)]
    fn basepoint() -> Self {
        Self {
            x: BASE_COMB_TABLE[1].0,
            y: BASE_COMB_TABLE[1].1,
            z: Fe::ONE,
        }
    }

    /// Complete projective point addition (`add-2007-bl`, RFC 8032 Section 5.2.4).
    #[cfg(test)]
    #[inline(never)]
    fn add(&self, other: &Self) -> Self {
        let a = self.z.mul(&other.z);
        let b = a.square();
        let c = self.x.mul(&other.x);
        let d = self.y.mul(&other.y);
        // E = d * C * D where d = -39081, so -E = 39081 * C * D
        let neg_e = c.mul(&d).mul_small(EDWARDS_D_ABS);
        let f = b.add(&neg_e); // B - E = B + (-E)
        let g = b.sub(&neg_e); // B + E = B - (-E)
        let h = self.x.add(&self.y).mul(&other.x.add(&other.y));
        let x3 = a.mul(&f).mul(&h.sub(&c).sub(&d));
        let y3 = a.mul(&g).mul(&d.sub(&c));
        let z3 = f.mul(&g);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed projective + affine point addition (`add-2007-bl` with Z2 = 1).
    /// Saves 1 squaring and 1 field multiplication per addition.
    #[inline(never)]
    fn add_affine(&self, other_x: &Fe, other_y: &Fe) -> Self {
        let b = self.z.square();
        let c = self.x.mul(other_x);
        let d = self.y.mul(other_y);
        // -E = 39081 * C * D
        let neg_e = c.mul(&d).mul_small(EDWARDS_D_ABS);
        let f = b.add(&neg_e);
        let g = b.sub(&neg_e);
        let h = self.x.add(&self.y).mul(&other_x.add(other_y));
        let x3 = self.z.mul(&f).mul(&h.sub(&c).sub(&d));
        let y3 = self.z.mul(&g).mul(&d.sub(&c));
        let z3 = f.mul(&g);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete projective point doubling (`dbl-2007-bl`, RFC 8032 Section 5.2.4).
    #[inline(never)]
    fn double(&self) -> Self {
        let b = self.x.add(&self.y).square();
        let c = self.x.square();
        let d = self.y.square();
        let e = c.add(&d);
        let h = self.z.square();
        let j = e.sub(&h.add(&h));
        let x3 = b.sub(&e).mul(&j);
        let y3 = e.mul(&c.sub(&d));
        let z3 = e.mul(&j);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    #[cfg(test)]
    #[inline]
    fn ct_select(a: &Self, b: &Self, choice: u64) -> Self {
        Self {
            x: Fe::ct_select(&a.x, &b.x, choice),
            y: Fe::ct_select(&a.y, &b.y, choice),
            z: Fe::ct_select(&a.z, &b.z, choice),
        }
    }

    #[cfg(test)]
    #[inline]
    fn ct_select_16(table: &[Self; 16], index: u8) -> Self {
        let mut res = Self::IDENTITY;
        for i in 0..16 {
            let choice = (index == i) as u64;
            res = Self::ct_select(&res, &table[i as usize], choice);
        }
        res
    }

    /// Constant-time windowed scalar multiplication `[scalar]self` for a 57-byte little-endian scalar.
    /// Uses a 4-bit fixed window (16-point table), reducing point additions from 448 down to 126.
    #[cfg(test)]
    #[inline(never)]
    fn scalar_mul(&self, scalar: &[u8; ED448_KEY_SIZE]) -> Self {
        let mut table = [Self::IDENTITY; 16];
        table[1] = *self;
        for i in 2..16 {
            table[i] = table[i - 1].add(self);
        }

        let mut acc = Self::IDENTITY;
        for byte_idx in (0..56).rev() {
            let byte = scalar[byte_idx];
            // High nibble
            let hi = byte >> 4;
            acc = acc.double().double().double().double();
            let p_hi = Self::ct_select_16(&table, hi);
            acc = acc.add(&p_hi);

            // Low nibble
            let lo = byte & 0x0f;
            acc = acc.double().double().double().double();
            let p_lo = Self::ct_select_16(&table, lo);
            acc = acc.add(&p_lo);
        }
        acc
    }

    #[inline]
    fn ct_select_affine(table: &[(Fe, Fe); 16], index: u8) -> (Fe, Fe) {
        let mut x = Fe::ZERO;
        let mut y = Fe::ONE;
        for i in 0..16 {
            let choice = (index == i) as u64;
            x = Fe::ct_select(&x, &table[i as usize].0, choice);
            y = Fe::ct_select(&y, &table[i as usize].1, choice);
        }
        (x, y)
    }

    /// Fast constant-time fixed-base scalar multiplication `[scalar]B` using a 4-tooth comb table.
    /// Evaluates 448 bits in 112 iterations, reducing point doublings from 448 down to 111
    /// and total point operations by >60%.
    #[inline(never)]
    fn basepoint_scalar_mul(scalar: &[u8; ED448_KEY_SIZE]) -> Self {
        let mut acc = Self::IDENTITY;
        for j in (0..112).rev() {
            if j < 111 {
                acc = acc.double();
            }
            let b0 = ((scalar[j / 8] >> (j % 8)) & 1) as u8;
            let j1 = j + 112;
            let b1 = ((scalar[j1 / 8] >> (j1 % 8)) & 1) as u8;
            let j2 = j + 224;
            let b2 = ((scalar[j2 / 8] >> (j2 % 8)) & 1) as u8;
            let j3 = j + 336;
            let b3 = ((scalar[j3 / 8] >> (j3 % 8)) & 1) as u8;
            let idx = b0 | (b1 << 1) | (b2 << 2) | (b3 << 3);
            let (px, py) = Self::ct_select_affine(&BASE_COMB_TABLE, idx);
            acc = acc.add_affine(&px, &py);
        }
        acc
    }

    /// Encodes the point into 57 bytes per RFC 8032 Section 5.2.2.
    fn encode(&self) -> [u8; ED448_KEY_SIZE] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        let mut out = y.to_bytes();
        let x_bytes = x.to_bytes();
        out[56] = (x_bytes[0] & 1) << 7;
        out
    }

    /// Decodes a 57-byte encoded point per RFC 8032 Section 5.2.3.
    #[cfg(test)]
    fn decode(bytes: &[u8; ED448_KEY_SIZE]) -> Option<Self> {
        if (bytes[56] & 0x7f) != 0 {
            return None;
        }
        let sign = (bytes[56] >> 7) & 1;
        let mut y_bytes = *bytes;
        y_bytes[56] = 0;
        let y = Fe::from_canonical_bytes(&y_bytes)?;
        let y2 = y.square();
        let u = y2.sub(&Fe::ONE); // y^2 - 1
        // v = d * y^2 - 1 = -(39081 * y^2 + 1)
        let v = Fe::ZERO.sub(&y2.mul_small(EDWARDS_D_ABS).add(&Fe::ONE));
        let u_div_v = u.mul(&v.invert());
        let mut x = u_div_v.sqrt_candidate();
        if x.square().to_bytes() != u_div_v.to_bytes() {
            return None;
        }
        let x_bytes = x.to_bytes();
        let is_zero = x_bytes.iter().all(|&b| b == 0);
        if is_zero && sign == 1 {
            return None;
        }
        if (x_bytes[0] & 1) != sign {
            x = x.neg();
        }
        Some(Self { x, y, z: Fe::ONE })
    }
}

/// Constant-time conditional subtraction of `ORDER_L` from an 8-limb accumulator if `rem >= ORDER_L`.
#[inline]
fn ct_sub_l_if_ge(rem: &mut [u64; 8]) {
    let mut diff = [0u64; 8];
    let mut borrow: u64 = 0;
    for i in 0..7 {
        let (d1, b1) = rem[i].overflowing_sub(ORDER_L[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    let (d7, b7) = rem[7].overflowing_sub(borrow);
    diff[7] = d7;
    let underflow = b7 as u64;
    let mask = underflow.wrapping_neg(); // 0 if rem >= L, !0 if rem < L
    for i in 0..8 {
        rem[i] = (rem[i] & mask) | (diff[i] & !mask);
    }
}

/// Reduces an arbitrary-length little-endian `u64` slice modulo `ORDER_L` in constant time.
fn reduce_limbs_mod_l(limbs: &[u64]) -> [u64; 7] {
    let mut rem = [0u64; 8];
    for &word in limbs.iter().rev() {
        for bit in (0..64).rev() {
            let b = (word >> bit) & 1;
            let mut carry = b;
            for r in rem.iter_mut() {
                let next_carry = *r >> 63;
                *r = (*r << 1) | carry;
                carry = next_carry;
            }
            ct_sub_l_if_ge(&mut rem);
        }
    }
    let mut out = [0u64; 7];
    out.copy_from_slice(&rem[..7]);
    out
}

fn reduce_114_mod_l(hash: &[u8; 114]) -> [u64; 7] {
    let mut padded = [0u8; 120];
    padded[..114].copy_from_slice(hash);
    let mut limbs = [0u64; 15];
    for i in 0..15 {
        limbs[i] = u64::from_le_bytes(*array_ref![padded, 8 * i, 8]);
    }
    reduce_limbs_mod_l(&limbs)
}

fn scalar_to_57_bytes(scalar: &[u64; 7]) -> [u8; ED448_KEY_SIZE] {
    let mut out = [0u8; ED448_KEY_SIZE];
    for i in 0..7 {
        out[8 * i..8 * i + 8].copy_from_slice(&scalar[i].to_le_bytes());
    }
    out
}

/// Computes `(r + k * s) mod L` and returns its 57-byte little-endian encoding.
fn compute_s_scalar(r: &[u64; 7], k: &[u64; 7], s_bytes: &[u8; ED448_KEY_SIZE]) -> [u8; ED448_KEY_SIZE] {
    let mut s_limbs = [0u64; 7];
    for i in 0..7 {
        s_limbs[i] = u64::from_le_bytes(*array_ref![s_bytes, 8 * i, 8]);
    }
    let mut prod = [0u64; 14];
    for i in 0..7 {
        prod[i] = r[i];
    }
    for i in 0..7 {
        let mut carry: u128 = 0;
        let k_i = k[i] as u128;
        for j in 0..7 {
            let v = (prod[i + j] as u128) + k_i * (s_limbs[j] as u128) + carry;
            prod[i + j] = v as u64;
            carry = v >> 64;
        }
        prod[i + 7] += carry as u64;
    }
    let reduced = reduce_limbs_mod_l(&prod);
    scalar_to_57_bytes(&reduced)
}

/// Expands a 57-byte secret key into `(clamped_scalar_bytes, prefix)` per RFC 8032 Section 5.2.5.
fn expand_secret(secret: &[u8; ED448_KEY_SIZE]) -> ([u8; ED448_KEY_SIZE], [u8; ED448_KEY_SIZE]) {
    let mut hasher = Shake256::default();
    hasher.update(secret);
    let mut reader = hasher.finalize_xof();
    let mut h = [0u8; 114];
    reader.read(&mut h);

    let mut s = [0u8; ED448_KEY_SIZE];
    s.copy_from_slice(&h[..57]);
    s[0] &= 0xfc;
    s[56] = 0;
    s[55] |= 0x80;

    let mut prefix = [0u8; ED448_KEY_SIZE];
    prefix.copy_from_slice(&h[57..114]);
    (s, prefix)
}

/// RFC 8032 Ed448 secret key (57-byte seed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed448SecretKey {
    seed: [u8; ED448_KEY_SIZE],
    public_key: [u8; ED448_KEY_SIZE],
}

impl Ed448SecretKey {
    /// Generates a new random 57-byte Ed448 secret key.
    pub fn random(rng: &mut impl Rng) -> Self {
        let mut seed = [0u8; ED448_KEY_SIZE];
        rng.fill_bytes(&mut seed);
        let (s, _) = expand_secret(&seed);
        let public_key = Point::basepoint_scalar_mul(&s).encode();
        Self { seed, public_key }
    }

    /// Returns the 57-byte RFC 8032 encoded Ed448 public key.
    #[inline(always)]
    pub fn public_key_bytes(&self) -> [u8; ED448_KEY_SIZE] {
        self.public_key
    }

    /// Signs a message using PureEd448 with an empty context (`ctx = b""`).
    #[inline(never)]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with_context(message, b"").to_vec()
    }

    /// Signs a message using PureEd448 with the given context (`ctx.len() <= 255`).
    #[inline(never)]
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> [u8; ED448_SIG_SIZE] {
        let (s, prefix) = expand_secret(&self.seed);
        let pub_bytes = self.public_key;

        let dom_header = [0u8, context.len() as u8];

        // r = SHAKE256("SigEd448" || 0x00 || len(ctx) || ctx || prefix || M, 114) mod L
        let mut r_hash = [0u8; 114];
        {
            let mut hasher = Shake256::default();
            hasher.update(b"SigEd448");
            hasher.update(&dom_header);
            hasher.update(context);
            hasher.update(&prefix);
            hasher.update(message);
            hasher.finalize_xof().read(&mut r_hash);
        }
        let r_limbs = reduce_114_mod_l(&r_hash);
        let r_scalar_bytes = scalar_to_57_bytes(&r_limbs);
        let r_point_bytes = Point::basepoint_scalar_mul(&r_scalar_bytes).encode();

        // k = SHAKE256("SigEd448" || 0x00 || len(ctx) || ctx || R || A || M, 114) mod L
        let mut k_hash = [0u8; 114];
        {
            let mut hasher = Shake256::default();
            hasher.update(b"SigEd448");
            hasher.update(&dom_header);
            hasher.update(context);
            hasher.update(&r_point_bytes);
            hasher.update(&pub_bytes);
            hasher.update(message);
            hasher.finalize_xof().read(&mut k_hash);
        }
        let k_limbs = reduce_114_mod_l(&k_hash);
        let s_out = compute_s_scalar(&r_limbs, &k_limbs, &s);

        let mut sig = [0u8; ED448_SIG_SIZE];
        sig[..57].copy_from_slice(&r_point_bytes);
        sig[57..114].copy_from_slice(&s_out);
        sig
    }

    /// Exports the 57-byte secret key seed.
    pub fn export(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Imports an Ed448 secret key from its 57-byte seed.
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let seed = <[u8; ED448_KEY_SIZE]>::try_from(bytes).ok()?;
        let (s, _) = expand_secret(&seed);
        let public_key = Point::basepoint_scalar_mul(&s).encode();
        Some(Self { seed, public_key })
    }
}

/// Verifies an RFC 8032 PureEd448 signature (used in unit tests).
#[cfg(test)]
pub fn verify_with_context(
    public_key: &[u8; ED448_KEY_SIZE],
    message: &[u8],
    signature: &[u8; ED448_SIG_SIZE],
    context: &[u8],
) -> bool {
    let mut r_raw = [0u8; ED448_KEY_SIZE];
    r_raw.copy_from_slice(&signature[..57]);
    let mut s_raw = [0u8; ED448_KEY_SIZE];
    s_raw.copy_from_slice(&signature[57..114]);
    if s_raw[56] != 0 {
        return false;
    }
    let mut s_limbs = [0u64; 7];
    for i in 0..7 {
        s_limbs[i] = u64::from_le_bytes(*array_ref![s_raw, 8 * i, 8]);
    }
    // Check S < L
    let mut check = [0u64; 8];
    check[..7].copy_from_slice(&s_limbs);
    ct_sub_l_if_ge(&mut check);
    if check[..7] != s_limbs {
        return false;
    }

    let Some(r_point) = Point::decode(&r_raw) else {
        return false;
    };
    let Some(a_point) = Point::decode(public_key) else {
        return false;
    };

    let dom_header = [0u8, context.len() as u8];
    let mut k_hash = [0u8; 114];
    {
        let mut hasher = Shake256::default();
        hasher.update(b"SigEd448");
        hasher.update(&dom_header);
        hasher.update(context);
        hasher.update(&r_raw);
        hasher.update(public_key);
        hasher.update(message);
        hasher.finalize_xof().read(&mut k_hash);
    }
    let k_limbs = reduce_114_mod_l(&k_hash);
    let k_bytes = scalar_to_57_bytes(&k_limbs);

    // Check [4][S]B == [4](R + [k]A)
    let lhs = Point::basepoint_scalar_mul(&s_raw).double().double();
    let rhs = r_point.add(&a_point.scalar_mul(&k_bytes)).double().double();
    lhs.encode() == rhs.encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        clean
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
                let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    #[test]
    fn test_rfc8032_ed448_blank_message() {
        let sk_bytes = unhex(
            "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3\
             528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
        );
        let expected_pk = unhex(
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778\
             edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        );
        let expected_sig = unhex(
            "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f\
             2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a\
             9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db\
             b61149f05a7363268c71d95808ff2e652600",
        );

        let sk = Ed448SecretKey::import(&sk_bytes).unwrap();
        let pk = sk.public_key_bytes();
        assert_eq!(&pk[..], &expected_pk[..]);

        let sig = sk.sign(b"");
        assert_eq!(&sig[..], &expected_sig[..]);

        let sig_arr = <[u8; ED448_SIG_SIZE]>::try_from(sig.as_slice()).unwrap();
        assert!(verify_with_context(&pk, b"", &sig_arr, b""));
    }

    #[test]
    fn test_rfc8032_ed448_1_octet_and_context() {
        let sk_bytes = unhex(
            "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a\
             fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
        );
        let expected_pk = unhex(
            "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086\
             6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        );
        let expected_sig_no_ctx = unhex(
            "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435\
             2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb\
             cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f\
             f3348ab21aa4adafd1d234441cf807c03a00",
        );
        let expected_sig_foo = unhex(
            "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2\
             151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da\
             1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d\
             5428407e85dcbc98a49155c13764e66c3c00",
        );

        let sk = Ed448SecretKey::import(&sk_bytes).unwrap();
        let pk = sk.public_key_bytes();
        assert_eq!(&pk[..], &expected_pk[..]);

        let sig_no_ctx = sk.sign(&[0x03]);
        assert_eq!(&sig_no_ctx[..], &expected_sig_no_ctx[..]);

        let sig_foo = sk.sign_with_context(&[0x03], b"foo");
        assert_eq!(&sig_foo[..], &expected_sig_foo[..]);
        assert!(verify_with_context(&pk, &[0x03], &sig_foo, b"foo"));
        assert!(!verify_with_context(&pk, &[0x03], &sig_foo, b"bar"));
    }

    #[test]
    fn test_rfc8032_ed448_64_octets() {
        let sk_bytes = unhex(
            "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bf\
             f21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
        );
        let expected_pk = unhex(
            "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a\
             39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
        );
        let msg = unhex(
            "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5\
             512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944",
        );
        let expected_sig = unhex(
            "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b1\
             8dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722e\
             f552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba\
             5f30e88e36ec2703b349ca229c2670833900",
        );

        let sk = Ed448SecretKey::import(&sk_bytes).unwrap();
        let pk = sk.public_key_bytes();
        assert_eq!(&pk[..], &expected_pk[..]);
        let sig = sk.sign(&msg);
        assert_eq!(&sig[..], &expected_sig[..]);
    }
}
