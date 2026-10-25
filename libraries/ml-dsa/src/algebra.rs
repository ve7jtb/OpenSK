use ctutils::{CtEq, CtGt, CtLt, CtSelect};
use hybrid_array::{
    ArraySize,
    typenum::{Shleft, U1, U13, Unsigned},
};
use module_lattice::{Field, Truncate};

module_lattice::define_field!(BaseField, u32, u64, u128, 8_380_417);

pub(crate) type Int = <BaseField as Field>::Int;

pub(crate) type Elem = module_lattice::Elem<BaseField>;
pub(crate) type Polynomial = module_lattice::Polynomial<BaseField>;
pub(crate) type Vector<K> = module_lattice::Vector<BaseField, K>;
pub(crate) type NttPolynomial = module_lattice::NttPolynomial<BaseField>;
pub(crate) type NttVector<K> = module_lattice::NttVector<BaseField, K>;
#[cfg(test)]
pub(crate) type NttMatrix<K, L> = module_lattice::NttMatrix<BaseField, K, L>;

pub(crate) trait BarrettReduce: Unsigned {
    const SHIFT: usize;
    const MULTIPLIER: u64;

    fn reduce(x: u32) -> u32 {
        let m = Self::U64;
        let x: u64 = x.into();
        let quotient = (x * Self::MULTIPLIER) >> Self::SHIFT;
        let remainder = x - quotient * m;

        let r_small: u32 = Truncate::truncate(remainder);
        let r_large: u32 = Truncate::truncate(remainder.wrapping_sub(m));
        u32::ct_select(&r_large, &r_small, remainder.ct_lt(&m))
    }
}

impl<M> BarrettReduce for M
where
    M: Unsigned,
{
    #[allow(clippy::as_conversions)]
    const SHIFT: usize = 2 * (M::U64.ilog2() + 1) as usize;
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const MULTIPLIER: u64 = (1 << Self::SHIFT) / M::U64;
}

pub(crate) trait Decompose {
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem);
}

pub(crate) trait ConstantTimeDiv: Unsigned {
    const CT_DIV_SHIFT: usize;
    const CT_DIV_MULTIPLIER: u64;

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_div(x: u32) -> u32 {
        let x64 = u64::from(x);
        let quotient = (x64 * Self::CT_DIV_MULTIPLIER) >> Self::CT_DIV_SHIFT;
        #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
        let result = quotient as u32;
        result
    }
}

impl<M> ConstantTimeDiv for M
where
    M: Unsigned,
{
    const CT_DIV_SHIFT: usize = 48;

    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const CT_DIV_MULTIPLIER: u64 = (1u64 << Self::CT_DIV_SHIFT).div_ceil(M::U64);
}

impl Decompose for Elem {
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem) {
        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<TwoGamma2>();

        let diff = r_plus - r0;
        let is_edge = diff.0.ct_eq(&(BaseField::Q - 1));

        let edge = (Elem::new(0), r0 - Elem::new(1));
        let r1 = Elem::new(TwoGamma2::ct_div(diff.0));
        let normal = (r1, r0);

        let r1_out = Elem::new(u32::ct_select(&normal.0.0, &edge.0.0, is_edge));
        let r0_out = Elem::new(u32::ct_select(&normal.1.0, &edge.1.0, is_edge));
        (r1_out, r0_out)
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) trait AlgebraExt: Sized {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self;
    fn infinity_norm(&self) -> Int;
    fn power2round(&self) -> (Self, Self);
    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self;
    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self;
}

impl AlgebraExt for Elem {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        let raw_mod = Elem::new(M::reduce(self.0));
        let in_lower_half = !raw_mod.0.ct_gt(&(M::U32 >> 1));
        Elem::new(u32::ct_select(
            &(raw_mod - Elem::new(M::U32)).0,
            &raw_mod.0,
            in_lower_half,
        ))
    }

    fn infinity_norm(&self) -> u32 {
        let in_lower_half = !self.0.ct_gt(&(BaseField::Q >> 1));
        u32::ct_select(&(BaseField::Q - self.0), &self.0, in_lower_half)
    }

    fn power2round(&self) -> (Self, Self) {
        type D = U13;
        type Pow2D = Shleft<U1, D>;

        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<Pow2D>();
        let r1 = Elem::new((r_plus - r0).0 >> D::USIZE);

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().0
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().1
    }
}

impl AlgebraExt for Polynomial {
    #[inline(never)]
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    #[inline(never)]
    fn infinity_norm(&self) -> u32 {
        self.0
            .iter()
            .map(AlgebraExt::infinity_norm)
            .max()
            .expect("should have a maximum")
    }

    #[inline(never)]
    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    #[inline(never)]
    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    #[inline(never)]
    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}

impl<K: ArraySize> AlgebraExt for Vector<K> {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0
            .iter()
            .map(AlgebraExt::infinity_norm)
            .max()
            .expect("should have a maximum")
    }

    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}
