#![no_std]
#![allow(non_snake_case)]
#![allow(clippy::similar_names)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::clone_on_copy)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod algebra;
mod crypto;
mod encode;
mod hint;
mod ntt;
mod param;
mod sampling;
mod signing;
mod verifying;

pub use crate::{
    param::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKeyBytes, MlDsaParams},
    signing::{ExpandedSigningKey, SigningKey},
    verifying::VerifyingKey,
};
pub use common::{self, KeyExport, KeyInit, KeySizeUser};
pub use signature::{self, Error, Keypair, SignatureEncoding, Signer, Verifier};

#[cfg(feature = "rand_core")]
pub use common::Generate;

use crate::{
    algebra::{AlgebraExt, Vector},
    crypto::H,
    hint::Hint,
    param::{ParameterSet, QMinus1},
};
use core::convert::{TryFrom, TryInto};
use hybrid_array::{
    Array,
    sizes::{U1, U2, U4, U5, U6, U7, U8, U17, U19, U32, U48, U55, U64, U75, U80, U88},
    typenum::{Diff, Length, Prod, Quot, Shleft},
};
use module_lattice::{MaybeBox, Truncate};
use shake::Shake256;

pub type B32 = Array<u8, U32>;
pub(crate) type B64 = Array<u8, U64>;
pub type Seed = B32;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature<P: MlDsaParams> {
    c_tilde: Array<u8, P::Lambda>,
    z: MaybeBox<Vector<P::L>>,
    h: Hint<P>,
}

impl<P: MlDsaParams> Signature<P> {
    pub fn encode(&self) -> EncodedSignature<P> {
        let c_tilde = self.c_tilde.clone();
        let z = P::encode_z(&self.z);
        let h = self.h.bit_pack();
        P::concat_sig(c_tilde, z, h)
    }

    pub fn decode(enc: &EncodedSignature<P>) -> Option<Self> {
        let (c_tilde, z, h) = P::split_sig(enc);

        let c_tilde = c_tilde.clone();
        let z = MaybeBox::new(P::decode_z(z));
        let h = Hint::bit_unpack(h)?;

        if z.infinity_norm() >= P::GAMMA1_MINUS_BETA {
            return None;
        }

        Some(Self { c_tilde, z, h })
    }
}

impl<'a, P: MlDsaParams> TryFrom<&'a [u8]> for Signature<P> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let enc = EncodedSignature::<P>::try_from(value).map_err(|_| Error::new())?;
        Self::decode(&enc).ok_or(Error::new())
    }
}

impl<P: MlDsaParams> TryInto<EncodedSignature<P>> for Signature<P> {
    type Error = Error;

    fn try_into(self) -> Result<EncodedSignature<P>, Self::Error> {
        Ok(self.encode())
    }
}

impl<P: MlDsaParams> SignatureEncoding for Signature<P> {
    type Repr = EncodedSignature<P>;
}

impl<P: MlDsaParams> core::hash::Hash for Signature<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}

struct MuBuilder(H);

impl MuBuilder {
    fn new(tr: &[u8], ctx: &[u8]) -> Self {
        let mut h = H::default();
        h = h.absorb(tr);
        h = h.absorb(&[0]);
        h = h.absorb(&[Truncate::truncate(ctx.len())]);
        h = h.absorb(ctx);

        Self(h)
    }

    fn internal(tr: &[u8], Mp: &[&[u8]]) -> B64 {
        let mut h = H::default().absorb(tr);

        for m in Mp {
            h = h.absorb(m);
        }

        h.squeeze_new()
    }

    fn message(mut self, M: &[&[u8]]) -> B64 {
        for m in M {
            self.0 = self.0.absorb(m);
        }

        self.0.squeeze_new()
    }

    fn finish(mut self) -> B64 {
        self.0.squeeze_new()
    }
}

impl AsMut<Shake256> for MuBuilder {
    fn as_mut(&mut self) -> &mut Shake256 {
        self.0.updatable()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MlDsa44;

impl ParameterSet for MlDsa44 {
    type K = U4;
    type L = U4;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U17>;
    type Gamma2 = Quot<QMinus1, U88>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U88, U2>, U1>>;
    type Lambda = U32;
    type Omega = U80;
    const TAU: usize = 39;
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MlDsa65;

impl ParameterSet for MlDsa65 {
    type K = U6;
    type L = U5;
    type Eta = U4;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
    type Lambda = U48;
    type Omega = U55;
    const TAU: usize = 49;
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MlDsa87;

impl ParameterSet for MlDsa87 {
    type K = U8;
    type L = U7;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
    type Lambda = U64;
    type Omega = U75;
    const TAU: usize = 60;
}
