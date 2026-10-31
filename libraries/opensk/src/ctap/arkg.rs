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

//! Asynchronous Remote Key Generation (`ARKG-P256`) per `draft-bradleylundberg-cfrg-arkg-11`.

use crate::api::crypto::ec_signing::{EcPublicKey as _, EcSecretKey as _, EcSignature as _};
use crate::api::crypto::ecdh::{PublicKey as _, SecretKey as _, SharedSecret as _};
use crate::api::crypto::hkdf256::Hkdf256 as _;
use crate::api::crypto::hmac256::Hmac256 as _;
use crate::api::crypto::sha256::Sha256;
use crate::api::crypto::{EC_FIELD_SIZE, HASH_SIZE, TRUNCATED_HMAC_SIZE};
use crate::env::{EcdhPk, EcdhSk, EcdsaSk, Env, Hkdf, Hmac, Sha};
use alloc::vec::Vec;
use arrayref::array_ref;
use sk_cbor as cbor;
use sk_cbor::cbor_map;
use zeroize::Zeroize;

/// COSE key type `kty` for `ARKG-pub` (`draft-bradleylundberg-cfrg-arkg-11` § 8.1).
pub const COSE_KTY_ARKG_PUB: i64 = -65537;

/// COSE algorithm identifier for `ARKG-P256` (`draft-bradleylundberg-cfrg-arkg-11` § 8.3).
pub const COSE_ALG_ARKG_P256: i64 = -65700;

/// COSE algorithm identifier for `ESP256-split-ARKG` (`draft-bradleylundberg-cfrg-arkg-11` § 8.3).
pub const COSE_ALG_ESP256_SPLIT_ARKG: i64 = -65539;

/// COSE algorithm identifier for `ESP256` (RFC 9864).
pub const COSE_ALG_ESP256: i64 = -9;

/// COSE algorithm identifier for `ES256` (RFC 9053).
pub const COSE_ALG_ES256: i64 = -7;

/// COSE algorithm identifier for `ECDH-ES + HKDF-256` (RFC 9053).
pub const COSE_ALG_ECDH_ES_HKDF_256: i64 = -25;

/// Maximum length in bytes of the `ctx` parameter in `ARKG-Derive-Private-Key` (§ 2.5).
pub const MAX_ARKG_CTX_LEN: usize = 64;

/// Expected byte length of an `ARKG-P256` key handle `kh` (16-byte MAC + 65-byte uncompressed point).
pub const ARKG_P256_KH_LEN: usize = TRUNCATED_HMAC_SIZE + 1 + 2 * EC_FIELD_SIZE;

// Domain separation tags for ARKG-P256.
const DST_BL_SK: &[u8] = b"ARKG-BL-EC-KG.ARKG-P256";
const DST_KEM_SK: &[u8] = b"ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256";
const PREFIX_CTX_BL: &[u8] = b"ARKG-Derive-Key-BL.";
const PREFIX_CTX_KEM: &[u8] = b"ARKG-Derive-Key-KEM.";
const PREFIX_INFO_MK: &[u8] = b"ARKG-KEM-HMAC-mac.ARKG-ECDH.ARKG-P256";
const PREFIX_INFO_K: &[u8] = b"ARKG-KEM-HMAC-shared.ARKG-ECDH.ARKG-P256";
const PREFIX_DST_TAU: &[u8] = b"ARKG-BL-EC.ARKG-P256";

/// NIST P-256 subgroup order `N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`
/// in little-endian 64-bit limbs.
const P256_ORDER_N: [u64; 4] = [
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
];

/// Returns `true` if `a >= b` (both in little-endian 4-limb representation).
#[inline]
fn limbs_gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// Subtracts `b` from `a` in place (`a -= b`), returning borrow.
#[inline]
fn limbs_sub_assign(a: &mut [u64; 4], b: &[u64; 4]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    borrow
}

/// Converts a 32-byte big-endian integer into 4 little-endian `u64` limbs.
fn bytes32_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes(*array_ref![bytes, 24, 8]),
        u64::from_be_bytes(*array_ref![bytes, 16, 8]),
        u64::from_be_bytes(*array_ref![bytes, 8, 8]),
        u64::from_be_bytes(*array_ref![bytes, 0, 8]),
    ]
}

/// Converts 4 little-endian `u64` limbs into a 32-byte big-endian integer.
fn limbs_to_bytes32(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&limbs[3].to_be_bytes());
    out[8..16].copy_from_slice(&limbs[2].to_be_bytes());
    out[16..24].copy_from_slice(&limbs[1].to_be_bytes());
    out[24..32].copy_from_slice(&limbs[0].to_be_bytes());
    out
}

/// Reduces a 48-byte big-endian integer modulo the P-256 curve order `N`.
pub fn reduce_48_mod_n(tv: &[u8; 48]) -> [u8; 32] {
    let mut acc = bytes32_to_limbs(array_ref![tv, 0, 32]);
    if limbs_gte(&acc, &P256_ORDER_N) {
        limbs_sub_assign(&mut acc, &P256_ORDER_N);
    }
    for &byte in &tv[32..48] {
        for bit_idx in (0..8).rev() {
            let bit = ((byte >> bit_idx) & 1) as u64;
            let carry = acc[3] >> 63;
            acc[3] = (acc[3] << 1) | (acc[2] >> 63);
            acc[2] = (acc[2] << 1) | (acc[1] >> 63);
            acc[1] = (acc[1] << 1) | (acc[0] >> 63);
            acc[0] = (acc[0] << 1) | bit;
            if carry != 0 || limbs_gte(&acc, &P256_ORDER_N) {
                limbs_sub_assign(&mut acc, &P256_ORDER_N);
            }
        }
    }
    limbs_to_bytes32(&acc)
}

/// Computes `(a + b) mod N` for two 32-byte big-endian scalars `a, b < N`.
/// Returns `None` if the result is zero.
pub fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut acc = bytes32_to_limbs(a);
    let rhs = bytes32_to_limbs(b);
    if limbs_gte(&acc, &P256_ORDER_N) {
        limbs_sub_assign(&mut acc, &P256_ORDER_N);
    }
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = acc[i].overflowing_add(rhs[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        acc[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    if carry != 0 || limbs_gte(&acc, &P256_ORDER_N) {
        limbs_sub_assign(&mut acc, &P256_ORDER_N);
    }
    if acc == [0u64; 4] {
        None
    } else {
        Some(limbs_to_bytes32(&acc))
    }
}

/// RFC 9380 § 5.3.1 `expand_message_xmd` instantiated with SHA-256 (`b_in_bytes = 32`,
/// `s_in_bytes = 64`) and output length `len_in_bytes = 48` (`ell = 2`).
///
/// Requires `dst.len() <= 255`.
pub fn expand_message_xmd_48<S: Sha256>(msg: &[u8], dst: &[u8]) -> [u8; 48] {
    assert!(dst.len() <= 255);
    let dst_len_byte = [dst.len() as u8];
    let z_pad = [0u8; 64];
    // l_i_b_str = I2OSP(48, 2) = [0x00, 0x30], followed by I2OSP(0, 1) = [0x00].
    let l_i_b_str_and_zero = [0x00u8, 0x30u8, 0x00u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut b_0 = [0u8; HASH_SIZE];
    {
        let mut hasher = S::new();
        hasher.update(&z_pad);
        hasher.update(msg);
        hasher.update(&l_i_b_str_and_zero);
        hasher.update(dst);
        hasher.update(&dst_len_byte);
        hasher.finalize(&mut b_0);
    }

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut b_1 = [0u8; HASH_SIZE];
    {
        let mut hasher = S::new();
        hasher.update(&b_0);
        hasher.update(&[0x01u8]);
        hasher.update(dst);
        hasher.update(&dst_len_byte);
        hasher.finalize(&mut b_1);
    }

    // b_2 = H((b_0 XOR b_1) || I2OSP(2, 1) || DST_prime)
    let mut b_0_xor_b_1 = [0u8; HASH_SIZE];
    for i in 0..HASH_SIZE {
        b_0_xor_b_1[i] = b_0[i] ^ b_1[i];
    }
    let mut b_2 = [0u8; HASH_SIZE];
    {
        let mut hasher = S::new();
        hasher.update(&b_0_xor_b_1);
        hasher.update(&[0x02u8]);
        hasher.update(dst);
        hasher.update(&dst_len_byte);
        hasher.finalize(&mut b_2);
    }

    let mut out = [0u8; 48];
    out[0..32].copy_from_slice(&b_1);
    out[32..48].copy_from_slice(&b_2[0..16]);
    b_0.zeroize();
    b_1.zeroize();
    b_0_xor_b_1.zeroize();
    b_2.zeroize();
    out
}

/// RFC 9380 § 5.2 `hash_to_field(msg, 1)` into `GF(N)` for `P256_XMD:SHA-256_SSWU_RO_`.
pub fn hash_to_field<S: Sha256>(msg: &[u8], dst: &[u8]) -> [u8; 32] {
    let mut tv = expand_message_xmd_48::<S>(msg, dst);
    let scalar = reduce_48_mod_n(&tv);
    tv.zeroize();
    scalar
}

/// An `ARKG-P256` key seed pair `(pk, sk)` where `pk = (pk_bl, pk_kem)` and `sk = (sk_bl, sk_kem)`.
#[derive(Clone, Zeroize)]
pub struct ArkgSeed {
    pub sk_bl: [u8; 32],
    pub sk_kem: [u8; 32],
    pub pk_bl_x: [u8; 32],
    pub pk_bl_y: [u8; 32],
    pub pk_kem_x: [u8; 32],
    pub pk_kem_y: [u8; 32],
}

impl Drop for ArkgSeed {
    fn drop(&mut self) {
        self.sk_bl.zeroize();
        self.sk_kem.zeroize();
    }
}

impl ArkgSeed {
    /// Derives an `ARKG-P256` seed from `(ikm_bl, ikm_kem)` per `ARKG-Derive-Seed` (§ 2.2, § 4.1).
    pub fn derive<E: Env>(ikm_bl: &[u8], ikm_kem: &[u8]) -> Option<Self> {
        let sk_bl = hash_to_field::<Sha<E>>(ikm_bl, DST_BL_SK);
        let bl_secret = EcdsaSk::<E>::import(&sk_bl)?;
        let bl_public = bl_secret.public_key();
        let mut pk_bl_x = [0u8; EC_FIELD_SIZE];
        let mut pk_bl_y = [0u8; EC_FIELD_SIZE];
        bl_public.to_coordinates(&mut pk_bl_x, &mut pk_bl_y);

        let sk_kem = hash_to_field::<Sha<E>>(ikm_kem, DST_KEM_SK);
        let kem_secret = EcdhSk::<E>::from_bytes(&sk_kem)?;
        let kem_public = kem_secret.public_key();
        let mut pk_kem_x = [0u8; EC_FIELD_SIZE];
        let mut pk_kem_y = [0u8; EC_FIELD_SIZE];
        kem_public.to_coordinates(&mut pk_kem_x, &mut pk_kem_y);

        Some(Self {
            sk_bl,
            sk_kem,
            pk_bl_x,
            pk_bl_y,
            pk_kem_x,
            pk_kem_y,
        })
    }

    /// Encodes the `ARKG-pub` public seed as a `COSE_Key` CBOR map (§ 5.1):
    /// ```cddl
    /// {
    ///   1: -65537,  ; kty: ARKG-pub
    ///   3: -65700,  ; alg: ARKG-P256
    ///   -1: { 1: 2, 3: -7, -1: 1, -2: pk_bl_x, -3: pk_bl_y },   ; pk_bl
    ///   -2: { 1: 2, 3: -25, -1: 1, -2: pk_kem_x, -3: pk_kem_y }, ; pk_kem
    ///   -3: -9,     ; dkalg: ESP256
    /// }
    /// ```
    pub fn to_cose_key_cbor(&self) -> cbor::Value {
        let pk_bl = cbor_map! {
            1 => 2,
            3 => COSE_ALG_ES256,
            -1 => 1,
            -2 => self.pk_bl_x.to_vec(),
            -3 => self.pk_bl_y.to_vec(),
        };
        let pk_kem = cbor_map! {
            1 => 2,
            3 => COSE_ALG_ECDH_ES_HKDF_256,
            -1 => 1,
            -2 => self.pk_kem_x.to_vec(),
            -3 => self.pk_kem_y.to_vec(),
        };
        cbor_map! {
            1 => COSE_KTY_ARKG_PUB,
            3 => COSE_ALG_ARKG_P256,
            -1 => pk_bl,
            -2 => pk_kem,
            -3 => COSE_ALG_ESP256,
        }
    }
}

/// Derives the blinded P-256 private scalar `sk'` using `ARKG-Derive-Private-Key` (§ 2.4, § 4.1).
///
/// Returns `None` if `ctx.len() > 64`, `kh` is malformed, the KEM point is invalid,
/// the 128-bit HMAC tag fails verification, or `sk_bl + tau == 0 (mod N)`.
pub fn derive_private_key<E: Env>(
    sk_bl: &[u8; 32],
    sk_kem: &[u8; 32],
    kh: &[u8],
    ctx: &[u8],
) -> Option<[u8; 32]> {
    if ctx.len() > MAX_ARKG_CTX_LEN || kh.len() != ARKG_P256_KH_LEN {
        return None;
    }
    let t = array_ref![kh, 0, TRUNCATED_HMAC_SIZE];
    let c_prime = &kh[TRUNCATED_HMAC_SIZE..];
    if c_prime[0] != 0x04 {
        return None;
    }
    let x_prime = array_ref![c_prime, 1, EC_FIELD_SIZE];
    let y_prime = array_ref![c_prime, 1 + EC_FIELD_SIZE, EC_FIELD_SIZE];

    let pk_prime = EcdhPk::<E>::from_coordinates(x_prime, y_prime)?;
    let kem_secret = EcdhSk::<E>::from_bytes(sk_kem)?;
    let shared = kem_secret.diffie_hellman(&pk_prime);
    let mut k_prime = [0u8; EC_FIELD_SIZE];
    shared.raw_secret_bytes(&mut k_prime);

    // ctx' = I2OSP(LEN(ctx), 1) || ctx
    // info_mk = "ARKG-KEM-HMAC-mac.ARKG-ECDH.ARKG-P256" || "ARKG-Derive-Key-KEM." || ctx'
    let mut info_mk =
        Vec::with_capacity(PREFIX_INFO_MK.len() + PREFIX_CTX_KEM.len() + 1 + ctx.len());
    info_mk.extend_from_slice(PREFIX_INFO_MK);
    info_mk.extend_from_slice(PREFIX_CTX_KEM);
    info_mk.push(ctx.len() as u8);
    info_mk.extend_from_slice(ctx);

    let mut mk = [0u8; HASH_SIZE];
    Hkdf::<E>::hkdf_empty_salt_256(&k_prime, &info_mk, &mut mk);

    if !Hmac::<E>::verify_truncated_left(&mk, c_prime, t) {
        k_prime.zeroize();
        mk.zeroize();
        return None;
    }
    mk.zeroize();

    // info_k = "ARKG-KEM-HMAC-shared.ARKG-ECDH.ARKG-P256" || "ARKG-Derive-Key-KEM." || ctx'
    let mut info_k = Vec::with_capacity(PREFIX_INFO_K.len() + PREFIX_CTX_KEM.len() + 1 + ctx.len());
    info_k.extend_from_slice(PREFIX_INFO_K);
    info_k.extend_from_slice(PREFIX_CTX_KEM);
    info_k.push(ctx.len() as u8);
    info_k.extend_from_slice(ctx);

    let mut ikm_tau = [0u8; HASH_SIZE];
    Hkdf::<E>::hkdf_empty_salt_256(&k_prime, &info_k, &mut ikm_tau);
    k_prime.zeroize();

    // DST_tau = "ARKG-BL-EC.ARKG-P256" || "ARKG-Derive-Key-BL." || ctx'
    let mut dst_tau =
        Vec::with_capacity(PREFIX_DST_TAU.len() + PREFIX_CTX_BL.len() + 1 + ctx.len());
    dst_tau.extend_from_slice(PREFIX_DST_TAU);
    dst_tau.extend_from_slice(PREFIX_CTX_BL);
    dst_tau.push(ctx.len() as u8);
    dst_tau.extend_from_slice(ctx);

    let mut tau = hash_to_field::<Sha<E>>(&ikm_tau, &dst_tau);
    ikm_tau.zeroize();

    let sk_prime = scalar_add_mod_n(sk_bl, &tau);
    tau.zeroize();
    sk_prime
}

/// Derives the blinded P-256 private key via `ARKG-Derive-Private-Key` and signs a 32-byte
/// pre-hashed `tbs` digest (`ESP256-split-ARKG`), returning the ASN.1 DER-encoded ECDSA signature.
pub fn derive_and_sign_prehash<E: Env>(
    sk_bl: &[u8; 32],
    sk_kem: &[u8; 32],
    kh: &[u8],
    ctx: &[u8],
    tbs_digest: &[u8; 32],
) -> Option<Vec<u8>> {
    let mut sk_prime = derive_private_key::<E>(sk_bl, sk_kem, kh, ctx)?;
    let signing_key = EcdsaSk::<E>::import(&sk_prime);
    sk_prime.zeroize();
    let signing_key = signing_key?;
    Some(signing_key.sign_prehash(tbs_digest).to_der())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::test::TestEnv;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let clean: Vec<u8> = hex
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        assert_eq!(clean.len() % 2, 0);
        clean
            .chunks(2)
            .map(|pair| {
                let s = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(s, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn test_arkg_p256_rfc_vector_1() {
        let ctx = b"ARKG-P256.test vectors";
        let ikm_bl = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ikm_kem = hex_to_bytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

        let expected_sk_bl = hex_to_bytes("d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455");
        let expected_sk_kem = hex_to_bytes("74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5");
        let expected_pk_bl = hex_to_bytes(
            "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df\
               65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        );
        let expected_pk_kem = hex_to_bytes(
            "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5\
               dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        );
        let kh = hex_to_bytes(
            "27987995f184a44cfa548d104b0a461d0487fc739dbcdabc293ac5469221da91\
             b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e635\
             89f0c00dc88f290d660c65a65a50c86361",
        );
        let expected_pk_prime = hex_to_bytes(
            "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107\
               dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd",
        );
        let expected_sk_prime =
            hex_to_bytes("775d7fe9a6dfba43ce671cb38afca3d272c4d14aff97bd67559eb500a092e5e7");

        let seed = ArkgSeed::derive::<TestEnv>(&ikm_bl, &ikm_kem).unwrap();
        assert_eq!(&seed.sk_bl[..], &expected_sk_bl[..]);
        assert_eq!(&seed.sk_kem[..], &expected_sk_kem[..]);
        assert_eq!(&seed.pk_bl_x[..], &expected_pk_bl[1..33]);
        assert_eq!(&seed.pk_bl_y[..], &expected_pk_bl[33..65]);
        assert_eq!(&seed.pk_kem_x[..], &expected_pk_kem[1..33]);
        assert_eq!(&seed.pk_kem_y[..], &expected_pk_kem[33..65]);

        let sk_prime =
            derive_private_key::<TestEnv>(&seed.sk_bl, &seed.sk_kem, &kh, ctx).unwrap();
        assert_eq!(&sk_prime[..], &expected_sk_prime[..]);

        // Verify sk_prime * G == pk_prime
        let derived_sk = EcdsaSk::<TestEnv>::import(&sk_prime).unwrap();
        let derived_pk = derived_sk.public_key();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        derived_pk.to_coordinates(&mut x, &mut y);
        assert_eq!(&x[..], &expected_pk_prime[1..33]);
        assert_eq!(&y[..], &expected_pk_prime[33..65]);
    }

    #[test]
    fn test_arkg_p256_rfc_vector_2() {
        let ctx = b"ARKG-P256.test vectors";
        let ikm_bl = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ikm_kem = hex_to_bytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let kh = hex_to_bytes(
            "b7507a82771776fbac41a18d94e19a7e0457fd1e438280c127dd55a6138d1baf\
             0a35e3e9671f7e42d8345f47374afa83247a078fa2196cd69497aed59ef92c05\
             cb6b03d306ec24f2f4ff2db09cd95d1b11",
        );
        let expected_pk_prime = hex_to_bytes(
            "04ea7d962c9f44ffe8b18f1058a471f394ef81b674948eefc1865b5c021cf858f5\
               77f9632b84220e4a1444a20b9430b86731c37e4dcb285eda38d76bf758918d86",
        );
        let expected_sk_prime =
            hex_to_bytes("6228e470290e9d7cc0feff32a74caafa14c608c956337eba23997f5904cff226");

        let seed = ArkgSeed::derive::<TestEnv>(&ikm_bl, &ikm_kem).unwrap();
        let sk_prime =
            derive_private_key::<TestEnv>(&seed.sk_bl, &seed.sk_kem, &kh, ctx).unwrap();
        assert_eq!(&sk_prime[..], &expected_sk_prime[..]);

        let derived_sk = EcdsaSk::<TestEnv>::import(&sk_prime).unwrap();
        let derived_pk = derived_sk.public_key();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        derived_pk.to_coordinates(&mut x, &mut y);
        assert_eq!(&x[..], &expected_pk_prime[1..33]);
        assert_eq!(&y[..], &expected_pk_prime[33..65]);
    }

    #[test]
    fn test_arkg_p256_rfc_vector_3() {
        let ctx = b"ARKG-P256.test vectors.0";
        let ikm_bl = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ikm_kem = hex_to_bytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let kh = hex_to_bytes(
            "81c4e65b552e52350b49864b98b87d510487fc739dbcdabc293ac5469221da91\
             b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e635\
             89f0c00dc88f290d660c65a65a50c86361",
        );
        let expected_pk_prime = hex_to_bytes(
            "04b79b65d6bbb419ff97006a1bd52e3f4ad53042173992423e06e52987a037cb61\
               dd82b126b162e4e7e8dc5c9fd86e82769d402a1968c7c547ef53ae4f96e10b0e",
        );
        let expected_sk_prime =
            hex_to_bytes("2a97f4232f9abba32fbfc28c6686f8afd2d851c2a95a3ed2f0a384b9ad55068d");

        let seed = ArkgSeed::derive::<TestEnv>(&ikm_bl, &ikm_kem).unwrap();
        let sk_prime =
            derive_private_key::<TestEnv>(&seed.sk_bl, &seed.sk_kem, &kh, ctx).unwrap();
        assert_eq!(&sk_prime[..], &expected_sk_prime[..]);

        let derived_sk = EcdsaSk::<TestEnv>::import(&sk_prime).unwrap();
        let derived_pk = derived_sk.public_key();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        derived_pk.to_coordinates(&mut x, &mut y);
        assert_eq!(&x[..], &expected_pk_prime[1..33]);
        assert_eq!(&y[..], &expected_pk_prime[33..65]);
    }

    #[test]
    fn test_arkg_p256_invalid_inputs_rejected() {
        let ctx = b"ARKG-P256.test vectors";
        let ikm_bl = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ikm_kem = hex_to_bytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let kh = hex_to_bytes(
            "27987995f184a44cfa548d104b0a461d0487fc739dbcdabc293ac5469221da91\
             b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e635\
             89f0c00dc88f290d660c65a65a50c86361",
        );
        let seed = ArkgSeed::derive::<TestEnv>(&ikm_bl, &ikm_kem).unwrap();

        // Corrupted MAC tag
        let mut bad_mac_kh = kh.clone();
        bad_mac_kh[0] ^= 0x01;
        assert!(derive_private_key::<TestEnv>(&seed.sk_bl, &seed.sk_kem, &bad_mac_kh, ctx).is_none());

        // Wrong context
        assert!(derive_private_key::<TestEnv>(&seed.sk_bl, &seed.sk_kem, &kh, b"wrong ctx").is_none());

        // Context > 64 bytes
        assert!(derive_private_key::<TestEnv>(&seed.sk_bl, &seed.sk_kem, &kh, &[b'a'; 65]).is_none());
    }
}
