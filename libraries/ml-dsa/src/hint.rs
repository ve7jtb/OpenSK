use crate::{
    algebra::{AlgebraExt, BaseField, Decompose, Elem, Polynomial, Vector},
    param::{EncodedHint, SignatureParams},
};
use ctutils::{Choice, CtEq, CtGt, CtSelect};
use hybrid_array::{
    Array,
    typenum::{U256, Unsigned},
};
use module_lattice::{Field, Truncate};

fn make_hint<TwoGamma2: Unsigned>(z: Elem, r: Elem) -> bool {
    let r1 = r.high_bits::<TwoGamma2>();
    let v1 = (r + z).high_bits::<TwoGamma2>();
    r1 != v1
}

#[allow(clippy::integer_division_remainder_used, reason = "params are public")]
fn use_hint<TwoGamma2: Unsigned>(h: bool, r: Elem) -> Elem {
    let m: u32 = (BaseField::Q - 1) / TwoGamma2::U32;
    let (r1, r0) = r.decompose::<TwoGamma2>();
    let gamma2 = TwoGamma2::U32 / 2;

    let r1_inc = Elem::new((r1.0 + 1) % m);
    let r1_dec = Elem::new((r1.0 + m - 1) % m);

    let r0_positive = !r0.0.ct_eq(&0) & !r0.0.ct_gt(&gamma2);
    let hinted = Elem::new(u32::ct_select(&r1_dec.0, &r1_inc.0, r0_positive));

    Elem::new(u32::ct_select(
        &r1.0,
        &hinted.0,
        Choice::from_u8_lsb(u8::from(h)),
    ))
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Hint<P>(pub Array<Array<bool, U256>, P::K>)
where
    P: SignatureParams;

impl<P> Default for Hint<P>
where
    P: SignatureParams,
{
    fn default() -> Self {
        Self(Array::default())
    }
}

impl<P> Hint<P>
where
    P: SignatureParams,
{
    pub(crate) fn new(z: &Vector<P::K>, r: &Vector<P::K>) -> Self {
        let zi = z.0.iter();
        let ri = r.0.iter();

        Self(
            zi.zip(ri)
                .map(|(zv, rv)| {
                    let zvi = zv.0.iter();
                    let rvi = rv.0.iter();

                    zvi.zip(rvi)
                        .map(|(&z, &r)| make_hint::<P::TwoGamma2>(z, r))
                        .collect()
                })
                .collect(),
        )
    }

    pub(crate) fn hamming_weight(&self) -> usize {
        self.0
            .iter()
            .map(|x| x.iter().filter(|x| **x).count())
            .sum()
    }

    pub(crate) fn use_hint(&self, r: &Vector<P::K>) -> Vector<P::K> {
        let hi = self.0.iter();
        let ri = r.0.iter();

        Vector::new(
            hi.zip(ri)
                .map(|(hv, rv)| {
                    let hvi = hv.iter();
                    let rvi = rv.0.iter();

                    Polynomial::new(
                        hvi.zip(rvi)
                            .map(|(&h, &r)| use_hint::<P::TwoGamma2>(h, r))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    pub(crate) fn bit_pack(&self) -> EncodedHint<P> {
        let mut y: EncodedHint<P> = Array::default();
        let mut index = 0;
        let omega = P::Omega::USIZE;
        for i in 0..P::K::U8 {
            let i_usize: usize = i.into();
            for j in 0..256 {
                if self.0[i_usize][j] {
                    y[index] = Truncate::truncate(j);
                    index += 1;
                }
            }

            y[omega + i_usize] = Truncate::truncate(index);
        }

        y
    }

    pub(crate) fn bit_unpack(y: &EncodedHint<P>) -> Option<Self> {
        let (indices, cuts) = P::split_hint(y);
        let cuts: Array<usize, P::K> = cuts.iter().map(|x| usize::from(*x)).collect();

        let indices: Array<usize, P::Omega> = indices.iter().map(|x| usize::from(*x)).collect();
        let max_cut: usize = cuts.iter().copied().max().expect("should have a maximum");

        if !cuts.windows(2).all(|w| w[0] <= w[1])
            || max_cut > indices.len()
            || indices[max_cut..].iter().copied().max().unwrap_or(0) > 0
        {
            return None;
        }

        let mut h = Self::default();
        let mut start = 0;
        for (i, &end) in cuts.iter().enumerate() {
            let indices = &indices[start..end];

            if !indices.windows(2).all(|w| w[0] < w[1]) {
                return None;
            }

            for &j in indices {
                h.0[i][j] = true;
            }

            start = end;
        }

        Some(h)
    }
}
