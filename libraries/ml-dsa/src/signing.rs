use crate::{
    B32, B64, EncodedSignature, EncodedVerifyingKey, ExpandedSigningKeyBytes, MlDsaParams,
    MuBuilder, Seed, Signature, VerifyingKey,
    algebra::{AlgebraExt, NttVector, Vector},
    crypto::H,
    hint::Hint,
    ntt::{Ntt, NttInverse},
    param::{SamplingSize, SpecQ},
    sampling::{expand_mask, expand_s, mul_a_hat, rej_bounded_poly, rej_ntt_poly, sample_in_ball},
};
use common::{KeyExport, KeyInit, KeySizeUser, typenum::U32};
use core::fmt;
use ctutils::{Choice, CtEq};
use hybrid_array::typenum::Unsigned;
use module_lattice::{MaybeBox, Truncate};
use shake::Shake256;
use signature::{DigestSigner, Error, MultipartSigner, Signer};

#[cfg(feature = "rand_core")]
use {
    common::Generate,
    signature::{
        RandomizedDigestSigner, RandomizedMultipartSigner, RandomizedSigner,
        rand_core::TryCryptoRng,
    },
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct SigningKey<P: MlDsaParams> {
    expanded_key: MaybeBox<ExpandedSigningKey<P>>,
    seed: MaybeBox<Seed>,
    #[cfg(feature = "alloc")]
    verifying_key: VerifyingKey<P>,
}

#[inline(never)]
fn compute_as1_hat_from_rhop<P: MlDsaParams>(rho: &B32, rhop: &B64) -> NttVector<P::K> {
    let mut out = NttVector::<P::K>::default();
    for s in 0..P::L::USIZE {
        let s1_s = rej_bounded_poly(rhop, P::Eta::ETA, Truncate::truncate(s)).ntt();
        for r in 0..P::K::USIZE {
            let a_rs = rej_ntt_poly(rho, Truncate::truncate(r), Truncate::truncate(s));
            out.0[r] = &out.0[r] + &(&a_rs * &s1_s);
        }
    }
    out
}

#[inline(never)]
fn compute_t1_from_as1_hat<P: MlDsaParams>(
    as1_hat: &NttVector<P::K>,
    rhop: &B64,
) -> Vector<P::K> {
    let mut t1 = Vector::<P::K>::default();
    for r in 0..P::K::USIZE {
        let s2_r = rej_bounded_poly(rhop, P::Eta::ETA, Truncate::truncate(P::L::USIZE + r));
        let t_r = &as1_hat.0[r].ntt_inverse() + &s2_r;
        let (t1_r, _) = t_r.power2round();
        t1.0[r] = t1_r;
    }
    t1
}

#[inline(never)]
fn derive_signing_ntt_vectors<P: MlDsaParams>(
    rho: &B32,
    rhop: &B64,
    s1_hat: &mut NttVector<P::L>,
    s2_hat: &mut NttVector<P::K>,
    t0_hat: &mut NttVector<P::K>,
) -> B64 {
    for s in 0..P::L::USIZE {
        s1_hat.0[s] = rej_bounded_poly(rhop, P::Eta::ETA, Truncate::truncate(s)).ntt();
    }
    let as1_hat = mul_a_hat::<P::K, P::L>(rho, s1_hat);
    let mut t1 = Vector::<P::K>::default();
    for r in 0..P::K::USIZE {
        let s2_r = rej_bounded_poly(rhop, P::Eta::ETA, Truncate::truncate(P::L::USIZE + r));
        let t_r = &as1_hat.0[r].ntt_inverse() + &s2_r;
        s2_hat.0[r] = s2_r.ntt();
        let (t1_r, t0_r) = t_r.power2round();
        t1.0[r] = t1_r;
        t0_hat.0[r] = t0_r.ntt();
    }
    let enc = VerifyingKey::<P>::encode_internal(rho, &t1);
    H::default().absorb(&enc).squeeze_new()
}

#[inline(never)]
fn raw_sign_encoded_mu<P: MlDsaParams>(
    rho: &B32,
    K: &B32,
    s1_hat: &NttVector<P::L>,
    s2_hat: &NttVector<P::K>,
    t0_hat: &NttVector<P::K>,
    mu: &B64,
    rnd: &B32,
) -> EncodedSignature<P> {
    let rhopp: B64 = H::default()
        .absorb(K)
        .absorb(rnd)
        .absorb(mu)
        .squeeze_new();

    for kappa in (0..u16::MAX).step_by(P::L::USIZE) {
        let y = expand_mask::<P::L, P::Gamma1>(&rhopp, kappa);
        let w = mul_a_hat::<P::K, P::L>(rho, &y.ntt()).ntt_inverse();
        let w1 = w.high_bits::<P::TwoGamma2>();

        let w1_tilde = P::encode_w1(&w1);
        let c_tilde = H::default()
            .absorb(mu)
            .absorb(&w1_tilde)
            .squeeze_new::<P::Lambda>();
        let c = sample_in_ball(&c_tilde, P::TAU);
        let c_hat = c.ntt();

        let cs1 = (&c_hat * s1_hat).ntt_inverse();
        let z = &y + &cs1;
        if z.infinity_norm() >= P::GAMMA1_MINUS_BETA {
            continue;
        }

        let cs2 = (&c_hat * s2_hat).ntt_inverse();
        let w_minus_cs2 = &w - &cs2;
        let r0 = w_minus_cs2.low_bits::<P::TwoGamma2>();
        if r0.infinity_norm() >= P::GAMMA2_MINUS_BETA {
            continue;
        }

        let ct0 = (&c_hat * t0_hat).ntt_inverse();
        if ct0.infinity_norm() >= P::Gamma2::U32 {
            continue;
        }

        let minus_ct0 = -&ct0;
        let w_cs2_ct0 = &w_minus_cs2 + &ct0;
        let h = Hint::<P>::new(&minus_ct0, &w_cs2_ct0);
        if h.hamming_weight() > P::Omega::USIZE {
            continue;
        }

        let z_mod = z.mod_plus_minus::<SpecQ>();
        let z_enc = P::encode_z(&z_mod);
        let h_enc = h.bit_pack();
        return P::concat_sig(c_tilde, z_enc, h_enc);
    }

    unreachable!("Rejection sampling failed to find a valid signature");
}

impl<P: MlDsaParams> SigningKey<P> {
    /// Low-stack helper to derive and encode the FIPS 204 verifying key directly from the 32-byte seed.
    #[inline(never)]
    #[must_use]
    pub fn verifying_key_bytes_from_seed(xi: &Seed) -> EncodedVerifyingKey<P> {
        let mut h = H::default()
            .absorb(xi)
            .absorb(&[P::K::U8])
            .absorb(&[P::L::U8]);

        let rho: B32 = h.squeeze_new();
        let rhop: B64 = h.squeeze_new();

        let as1_hat = compute_as1_hat_from_rhop::<P>(&rho, &rhop);
        let t1 = compute_t1_from_as1_hat::<P>(&as1_hat, &rhop);
        VerifyingKey::<P>::encode_internal(&rho, &t1)
    }

    /// Low-stack helper to deterministically sign a message directly from the 32-byte seed.
    #[inline(never)]
    pub fn sign_deterministic_from_seed(
        xi: &Seed,
        M: &[u8],
        ctx: &[u8],
    ) -> Result<EncodedSignature<P>, Error> {
        if ctx.len() > 255 {
            return Err(Error::new());
        }

        let mut h = H::default()
            .absorb(xi)
            .absorb(&[P::K::U8])
            .absorb(&[P::L::U8]);

        let rho: B32 = h.squeeze_new();
        let rhop: B64 = h.squeeze_new();
        let K: B32 = h.squeeze_new();

        let mut s1_hat = NttVector::<P::L>::default();
        let mut s2_hat = NttVector::<P::K>::default();
        let mut t0_hat = NttVector::<P::K>::default();
        let tr = derive_signing_ntt_vectors::<P>(&rho, &rhop, &mut s1_hat, &mut s2_hat, &mut t0_hat);

        let mu = MuBuilder::new(&tr, ctx).message(&[M]);
        let rnd = B32::default();
        Ok(raw_sign_encoded_mu::<P>(
            &rho, &K, &s1_hat, &s2_hat, &t0_hat, &mu, &rnd,
        ))
    }

    #[must_use]
    pub fn from_seed(xi: &Seed) -> Self {
        let mut h = H::default()
            .absorb(xi)
            .absorb(&[P::K::U8])
            .absorb(&[P::L::U8]);

        let rho: B32 = h.squeeze_new();
        let rhop: B64 = h.squeeze_new();
        let K: B32 = h.squeeze_new();

        let s1 = expand_s::<P::L>(&rhop, P::Eta::ETA, 0);
        let s2 = expand_s::<P::K>(&rhop, P::Eta::ETA, P::L::USIZE);

        let s1_hat = s1.ntt();
        let As1_hat = mul_a_hat::<P::K, P::L>(&rho, &s1_hat);
        let t = &As1_hat.ntt_inverse() + &s2;

        let (t1, t0) = t.power2round();

        let enc = VerifyingKey::<P>::encode_internal(&rho, &t1);
        let tr: B64 = H::default().absorb(&enc).squeeze_new();
        let expanded_key = ExpandedSigningKey::new(rho, K, tr, s1, s2, t0);

        #[cfg(feature = "alloc")]
        let verifying_key = expanded_key.verifying_key();

        SigningKey {
            expanded_key: MaybeBox::new(expanded_key),
            seed: MaybeBox::new(xi.clone()),
            #[cfg(feature = "alloc")]
            verifying_key,
        }
    }

    #[inline]
    #[must_use]
    pub fn as_seed(&self) -> &Seed {
        &self.seed
    }

    #[inline]
    #[must_use]
    pub fn to_seed(&self) -> Seed {
        *self.seed
    }

    #[doc(hidden)]
    #[must_use]
    pub fn expanded_key(&self) -> &ExpandedSigningKey<P> {
        &self.expanded_key
    }
}

impl<P: MlDsaParams> KeySizeUser for SigningKey<P> {
    type KeySize = U32;
}

impl<P: MlDsaParams> KeyInit for SigningKey<P> {
    fn new(seed: &Seed) -> Self {
        Self::from_seed(seed)
    }
}

impl<P: MlDsaParams> KeyExport for SigningKey<P> {
    fn to_bytes(&self) -> Seed {
        self.to_seed()
    }
}

#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> Generate for SigningKey<P> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let seed = Seed::try_generate_from_rng(rng)?;
        Ok(Self::from_seed(&seed))
    }
}

impl<P: MlDsaParams> fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

#[cfg(not(feature = "alloc"))]
impl<P: MlDsaParams> signature::Keypair for SigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;
    fn verifying_key(&self) -> VerifyingKey<P> {
        self.expanded_key.verifying_key()
    }
}

#[cfg(feature = "alloc")]
impl<P: MlDsaParams> AsRef<VerifyingKey<P>> for SigningKey<P> {
    fn as_ref(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

#[cfg(feature = "alloc")]
impl<P: MlDsaParams> signature::KeypairRef for SigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;
}

impl<P: MlDsaParams> Signer<Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.try_multipart_sign(&[msg])
    }
}

impl<P: MlDsaParams> MultipartSigner<Signature<P>> for SigningKey<P> {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
        self.expanded_key.raw_sign_deterministic(msg, &[])
    }
}

impl<P: MlDsaParams> DigestSigner<Shake256, Signature<P>> for SigningKey<P> {
    fn try_sign_digest<F: Fn(&mut Shake256) -> Result<(), Error>>(
        &self,
        f: F,
    ) -> Result<Signature<P>, Error> {
        self.expanded_key.try_sign_digest(&f)
    }
}

impl<P: MlDsaParams> PartialEq for SigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: MlDsaParams> CtEq for SigningKey<P> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expanded_key
            .ct_eq(&other.expanded_key)
            .and(self.seed.ct_eq(&other.seed))
    }
}

impl<P: MlDsaParams> Drop for SigningKey<P> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.seed.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> ZeroizeOnDrop for SigningKey<P> {}

#[derive(Clone)]
pub struct ExpandedSigningKey<P: MlDsaParams> {
    rho: B32,
    K: B32,
    pub(crate) tr: B64,
    s1: Vector<P::L>,
    s2: Vector<P::K>,
    t0: Vector<P::K>,

    s1_hat: NttVector<P::L>,
    s2_hat: NttVector<P::K>,
    t0_hat: NttVector<P::K>,
}

impl<P: MlDsaParams> ExpandedSigningKey<P> {
    pub(crate) fn new(
        rho: B32,
        K: B32,
        tr: B64,
        s1: Vector<P::L>,
        s2: Vector<P::K>,
        t0: Vector<P::K>,
    ) -> Self {
        let s1_hat = s1.ntt();
        let s2_hat = s2.ntt();
        let t0_hat = t0.ntt();

        Self {
            rho,
            K,
            tr,
            s1,
            s2,
            t0,
            s1_hat,
            s2_hat,
            t0_hat,
        }
    }

    #[must_use]
    #[inline]
    pub fn from_seed(seed: &Seed) -> Self {
        let kp = SigningKey::from_seed(seed);
        (*kp.expanded_key).clone()
    }

    pub fn sign_internal(&self, Mp: &[&[u8]], rnd: &B32) -> Signature<P>
    where
        P: MlDsaParams,
    {
        let mu = MuBuilder::internal(&self.tr, Mp);
        self.raw_sign_mu(&mu, rnd)
    }

    pub(crate) fn raw_sign_mu(&self, mu: &B64, rnd: &B32) -> Signature<P>
    where
        P: MlDsaParams,
    {
        let rhopp: B64 = H::default()
            .absorb(&self.K)
            .absorb(rnd)
            .absorb(mu)
            .squeeze_new();

        for kappa in (0..u16::MAX).step_by(P::L::USIZE) {
            let y = expand_mask::<P::L, P::Gamma1>(&rhopp, kappa);
            let w = mul_a_hat::<P::K, P::L>(&self.rho, &y.ntt()).ntt_inverse();
            let w1 = w.high_bits::<P::TwoGamma2>();

            let w1_tilde = P::encode_w1(&w1);
            let c_tilde = H::default()
                .absorb(mu)
                .absorb(&w1_tilde)
                .squeeze_new::<P::Lambda>();
            let c = sample_in_ball(&c_tilde, P::TAU);
            let c_hat = c.ntt();

            let cs1 = (&c_hat * &self.s1_hat).ntt_inverse();
            let cs2 = (&c_hat * &self.s2_hat).ntt_inverse();

            let z = &y + &cs1;
            let r0 = (&w - &cs2).low_bits::<P::TwoGamma2>();

            if z.infinity_norm() >= P::GAMMA1_MINUS_BETA
                || r0.infinity_norm() >= P::GAMMA2_MINUS_BETA
            {
                continue;
            }

            let ct0 = (&c_hat * &self.t0_hat).ntt_inverse();
            let minus_ct0 = -&ct0;
            let w_cs2_ct0 = &(&w - &cs2) + &ct0;
            let h = Hint::<P>::new(&minus_ct0, &w_cs2_ct0);

            if ct0.infinity_norm() >= P::Gamma2::U32 || h.hamming_weight() > P::Omega::USIZE {
                continue;
            }

            let z = MaybeBox::new(z.mod_plus_minus::<SpecQ>());
            return Signature { c_tilde, z, h };
        }

        unreachable!("Rejection sampling failed to find a valid signature");
    }

    #[cfg(feature = "rand_core")]
    pub fn sign_randomized<R: TryCryptoRng + ?Sized>(
        &self,
        M: &[u8],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Signature<P>, Error> {
        self.raw_sign_randomized(&[M], ctx, rng)
    }

    #[cfg(feature = "rand_core")]
    fn raw_sign_randomized<R: TryCryptoRng + ?Sized>(
        &self,
        Mp: &[&[u8]],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Signature<P>, Error> {
        if ctx.len() > 255 {
            return Err(Error::new());
        }

        let mut rnd = B32::default();
        rng.try_fill_bytes(&mut rnd).map_err(|_| Error::new())?;

        let mu = MuBuilder::new(&self.tr, ctx).message(Mp);
        Ok(self.raw_sign_mu(&mu, &rnd))
    }

    #[cfg(feature = "rand_core")]
    pub fn sign_mu_randomized<R: TryCryptoRng + ?Sized>(
        &self,
        mu: &B64,
        rng: &mut R,
    ) -> Result<Signature<P>, Error> {
        let mut rnd = B32::default();
        rng.try_fill_bytes(&mut rnd).map_err(|_| Error::new())?;

        Ok(self.raw_sign_mu(mu, &rnd))
    }

    pub fn sign_deterministic(&self, M: &[u8], ctx: &[u8]) -> Result<Signature<P>, Error> {
        self.raw_sign_deterministic(&[M], ctx)
    }

    pub fn sign_mu_deterministic(&self, mu: &B64) -> Signature<P> {
        let rnd = B32::default();
        self.raw_sign_mu(mu, &rnd)
    }

    fn raw_sign_deterministic(&self, Mp: &[&[u8]], ctx: &[u8]) -> Result<Signature<P>, Error> {
        if ctx.len() > 255 {
            return Err(Error::new());
        }

        let mu = MuBuilder::new(&self.tr, ctx).message(Mp);
        Ok(self.sign_mu_deterministic(&mu))
    }

    pub fn verifying_key(&self) -> VerifyingKey<P> {
        let kp: &dyn signature::Keypair<VerifyingKey = VerifyingKey<P>> = self;
        kp.verifying_key()
    }

    #[deprecated(since = "0.1.0", note = "use `ExpandedSigningKey::from_seed` instead")]
    pub fn from_expanded(enc: &ExpandedSigningKeyBytes<P>) -> Self
    where
        P: MlDsaParams,
    {
        let (rho, K, tr, s1_enc, s2_enc, t0_enc) = P::split_sk(enc);
        Self::new(
            rho.clone(),
            K.clone(),
            tr.clone(),
            P::decode_s1(s1_enc),
            P::decode_s2(s2_enc),
            P::decode_t0(t0_enc),
        )
    }

    #[deprecated(since = "0.1.0", note = "use `SigningKey::to_seed` instead")]
    pub fn to_expanded(&self) -> ExpandedSigningKeyBytes<P>
    where
        P: MlDsaParams,
    {
        let s1_enc = P::encode_s1(&self.s1);
        let s2_enc = P::encode_s2(&self.s2);
        let t0_enc = P::encode_t0(&self.t0);
        P::concat_sk(
            self.rho.clone(),
            self.K.clone(),
            self.tr.clone(),
            s1_enc,
            s2_enc,
            t0_enc,
        )
    }
}

impl<P: MlDsaParams> Signer<Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.try_multipart_sign(&[msg])
    }
}

impl<P: MlDsaParams> MultipartSigner<Signature<P>> for ExpandedSigningKey<P> {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
        self.raw_sign_deterministic(msg, &[])
    }
}

impl<P: MlDsaParams> DigestSigner<Shake256, Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign_digest<F: Fn(&mut Shake256) -> Result<(), Error>>(
        &self,
        f: F,
    ) -> Result<Signature<P>, Error> {
        let mut mu = MuBuilder::new(&self.tr, &[]);
        f(mu.as_mut())?;
        let mu = mu.finish();

        Ok(self.sign_mu_deterministic(&mu))
    }
}

impl<P: MlDsaParams> signature::Keypair for ExpandedSigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        let As1 = mul_a_hat::<P::K, P::L>(&self.rho, &self.s1_hat);
        let t = &As1.ntt_inverse() + &self.s2;
        let (t1, _) = t.power2round();

        VerifyingKey::new(self.rho.clone(), t1, None)
    }
}

#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedSigner<Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Signature<P>, Error> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedMultipartSigner<Signature<P>> for ExpandedSigningKey<P> {
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> Result<Signature<P>, Error> {
        self.raw_sign_randomized(msg, &[], rng)
    }
}

#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedDigestSigner<Shake256, Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign_digest_with_rng<
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut Shake256) -> Result<(), Error>,
    >(
        &self,
        rng: &mut R,
        f: F,
    ) -> Result<Signature<P>, Error> {
        let mut mu = MuBuilder::new(&self.tr, &[]);
        f(mu.as_mut())?;
        let mu = mu.finish();

        self.sign_mu_randomized(&mu, rng)
    }
}

impl<P: MlDsaParams> PartialEq for ExpandedSigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: MlDsaParams> CtEq for ExpandedSigningKey<P> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.rho
            .ct_eq(&other.rho)
            .and(self.K.ct_eq(&other.K))
            .and(self.tr.ct_eq(&other.tr))
            .and(self.s1.ct_eq(&other.s1))
            .and(self.s2.ct_eq(&other.s2))
            .and(self.t0.ct_eq(&other.t0))
    }
}

impl<P: MlDsaParams> fmt::Debug for ExpandedSigningKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandedSigningKey").finish_non_exhaustive()
    }
}

impl<P: MlDsaParams> Drop for ExpandedSigningKey<P> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.rho.zeroize();
            self.K.zeroize();
            self.tr.zeroize();
            self.s1.zeroize();
            self.s2.zeroize();
            self.t0.zeroize();
            self.s1_hat.zeroize();
            self.s2_hat.zeroize();
            self.t0_hat.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> ZeroizeOnDrop for ExpandedSigningKey<P> {}
