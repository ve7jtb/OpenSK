use core::ops::Add;
use hybrid_array::{
    Array,
    typenum::{Len, Length, Sum, Unsigned},
};
use module_lattice::{ArraySize, Encode, EncodingSize, VectorEncodingSize};

use crate::algebra::{Elem, Polynomial, Vector};

pub trait RangeEncodingSize {
    type Min: Unsigned;
    type Max: Unsigned;
    type EncodingSize: EncodingSize;
}

impl<A, B> RangeEncodingSize for (A, B)
where
    A: Unsigned + Add<B>,
    B: Unsigned,
    Sum<A, B>: Len,
    Length<Sum<A, B>>: EncodingSize,
{
    type Min = A;
    type Max = B;
    type EncodingSize = Length<Sum<A, B>>;
}

pub(crate) type RangeMin<A, B> = <(A, B) as RangeEncodingSize>::Min;
pub(crate) type RangeMax<A, B> = <(A, B) as RangeEncodingSize>::Max;
pub(crate) type RangeEncodingBits<A, B> = <(A, B) as RangeEncodingSize>::EncodingSize;
pub(crate) type RangeEncodedPolynomialSize<A, B> =
    <RangeEncodingBits<A, B> as EncodingSize>::EncodedPolynomialSize;
pub(crate) type RangeEncodedPolynomial<A, B> = Array<u8, RangeEncodedPolynomialSize<A, B>>;
pub(crate) type RangeEncodedVectorSize<A, B, K> =
    <RangeEncodingBits<A, B> as VectorEncodingSize<K>>::EncodedVectorSize;
pub(crate) type RangeEncodedVector<A, B, K> = Array<u8, RangeEncodedVectorSize<A, B, K>>;

pub(crate) trait BitPack<A, B> {
    type PackedSize: ArraySize;
    fn pack(&self) -> Array<u8, Self::PackedSize>;
    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self;
}

impl<A, B> BitPack<A, B> for Polynomial
where
    (A, B): RangeEncodingSize,
{
    type PackedSize = RangeEncodedPolynomialSize<A, B>;

    fn pack(&self) -> RangeEncodedPolynomial<A, B> {
        let a = Elem::new(RangeMin::<A, B>::U32);
        let b = Elem::new(RangeMax::<A, B>::U32);

        let to_encode = Self::new(
            self.0
                .iter()
                .map(|w| {
                    assert!(w.0 <= b.0 || w.0 >= (-a).0);
                    b - *w
                })
                .collect(),
        );
        Encode::<RangeEncodingBits<A, B>>::encode(&to_encode)
    }

    fn unpack(enc: &RangeEncodedPolynomial<A, B>) -> Self {
        let a = Elem::new(RangeMin::<A, B>::U32);
        let b = Elem::new(RangeMax::<A, B>::U32);
        let mut decoded: Self = Encode::<RangeEncodingBits<A, B>>::decode(enc);

        for z in &mut decoded.0 {
            assert!(z.0 <= (a + b).0);
            *z = b - *z;
        }

        decoded
    }
}

impl<K, A, B> BitPack<A, B> for Vector<K>
where
    K: ArraySize,
    (A, B): RangeEncodingSize,
    RangeEncodingBits<A, B>: VectorEncodingSize<K>,
{
    type PackedSize = RangeEncodedVectorSize<A, B, K>;

    fn pack(&self) -> RangeEncodedVector<A, B, K> {
        let polys = self.0.iter().map(|x| BitPack::<A, B>::pack(x)).collect();
        RangeEncodingBits::<A, B>::flatten(polys)
    }

    fn unpack(enc: &RangeEncodedVector<A, B, K>) -> Self {
        let unfold = RangeEncodingBits::<A, B>::unflatten(enc);
        Self(
            unfold
                .into_iter()
                .map(|x| <Polynomial as BitPack<A, B>>::unpack(x))
                .collect(),
        )
    }
}
