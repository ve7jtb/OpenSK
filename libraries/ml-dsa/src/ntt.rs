use crate::algebra::{BaseField, Elem, NttPolynomial, NttVector, Polynomial, Vector};
use module_lattice::{ArraySize, Field, MultiplyNtt};

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::as_conversions)]
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const ZETA_POW_BITREV: [Elem; 256] = {
    const ZETA: u64 = 1753;
    const fn bitrev8(x: usize) -> usize {
        (x as u8).reverse_bits() as usize
    }

    let mut pow = [Elem::new(0); 256];
    let mut i = 0;
    let mut curr = 1u64;
    while i < 256 {
        pow[i] = Elem::new(curr as u32);
        i += 1;
        curr = (curr * ZETA) % BaseField::QL;
    }

    let mut pow_bitrev = [Elem::new(0); 256];
    let mut i = 1;
    while i < 256 {
        pow_bitrev[i] = pow[bitrev8(i)];
        i += 1;
    }
    pow_bitrev
};

pub(crate) trait Ntt {
    type Output;
    fn ntt(&self) -> Self::Output;
}

#[allow(clippy::inline_always)]
#[inline(always)]
fn ntt_layer<const LEN: usize, const ITERATIONS: usize>(w: &mut [Elem; 256], m: &mut usize) {
    for i in 0..ITERATIONS {
        let start = i * 2 * LEN;
        *m += 1;
        let z = ZETA_POW_BITREV[*m];
        for j in start..(start + LEN) {
            let t = z * w[j + LEN];
            w[j + LEN] = w[j] - t;
            w[j] = w[j] + t;
        }
    }
}

impl Ntt for Polynomial {
    type Output = NttPolynomial;

    #[inline(never)]
    fn ntt(&self) -> Self::Output {
        let mut w: [Elem; 256] = self.0.clone().into();
        let mut m = 0;

        ntt_layer::<128, 1>(&mut w, &mut m);
        ntt_layer::<64, 2>(&mut w, &mut m);
        ntt_layer::<32, 4>(&mut w, &mut m);
        ntt_layer::<16, 8>(&mut w, &mut m);
        ntt_layer::<8, 16>(&mut w, &mut m);
        ntt_layer::<4, 32>(&mut w, &mut m);
        ntt_layer::<2, 64>(&mut w, &mut m);
        ntt_layer::<1, 128>(&mut w, &mut m);

        NttPolynomial::new(w.into())
    }
}

impl<K: ArraySize> Ntt for Vector<K> {
    type Output = NttVector<K>;

    fn ntt(&self) -> Self::Output {
        NttVector::new(self.0.iter().map(Polynomial::ntt).collect())
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) trait NttInverse {
    type Output;
    fn ntt_inverse(&self) -> Self::Output;
}

#[allow(clippy::inline_always)]
#[inline(always)]
fn ntt_inverse_layer<const LEN: usize, const ITERATIONS: usize>(
    w: &mut [Elem; 256],
    m: &mut usize,
) {
    for i in 0..ITERATIONS {
        let start = i * 2 * LEN;
        *m -= 1;
        let z = -ZETA_POW_BITREV[*m];
        for j in start..(start + LEN) {
            let t = w[j];
            w[j] = t + w[j + LEN];
            w[j + LEN] = z * (t - w[j + LEN]);
        }
    }
}

impl NttInverse for NttPolynomial {
    type Output = Polynomial;

    #[inline(never)]
    fn ntt_inverse(&self) -> Self::Output {
        const INVERSE_256: Elem = Elem::new(8_347_681);

        let mut w: [Elem; 256] = self.0.clone().into();
        let mut m = 256;

        ntt_inverse_layer::<1, 128>(&mut w, &mut m);
        ntt_inverse_layer::<2, 64>(&mut w, &mut m);
        ntt_inverse_layer::<4, 32>(&mut w, &mut m);
        ntt_inverse_layer::<8, 16>(&mut w, &mut m);
        ntt_inverse_layer::<16, 8>(&mut w, &mut m);
        ntt_inverse_layer::<32, 4>(&mut w, &mut m);
        ntt_inverse_layer::<64, 2>(&mut w, &mut m);
        ntt_inverse_layer::<128, 1>(&mut w, &mut m);

        INVERSE_256 * &Polynomial::new(w.into())
    }
}

impl<K: ArraySize> NttInverse for NttVector<K> {
    type Output = Vector<K>;

    fn ntt_inverse(&self) -> Self::Output {
        Vector::new(self.0.iter().map(NttPolynomial::ntt_inverse).collect())
    }
}

impl MultiplyNtt for BaseField {
    #[inline(never)]
    fn multiply_ntt(lhs: &NttPolynomial, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial::new(
            lhs.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x * y)
                .collect(),
        )
    }
}
