use crate::{
    algebra::{BaseField, Elem, Int, NttPolynomial, NttVector, Polynomial, Vector},
    crypto::{G, H},
    param::{Eta, MaskSamplingSize},
};
use hybrid_array::Array;
use module_lattice::{ArraySize, Field, Truncate};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fn bit_set(z: &[u8], i: usize) -> bool {
    let bit_index = i & 0x07;
    let byte_index = i >> 3;
    z[byte_index] & (1 << bit_index) != 0
}

fn coeff_from_three_bytes(b: [u8; 3]) -> Option<Elem> {
    let b0: Int = b[0].into();
    let b1: Int = b[1].into();
    let b2: Int = b[2].into();

    let b2p = if b2 > 127 { b2 - 128 } else { b2 };

    let z = (b2p << 16) + (b1 << 8) + b0;
    (z < BaseField::Q).then_some(Elem::new(z))
}

fn coeff_from_half_byte(b: u8, eta: Eta) -> Option<Elem> {
    match eta {
        Eta::Two if b < 15 => {
            let b = Int::from(match b {
                b if b < 5 => b,
                b if b < 10 => b - 5,
                _ => b - 10,
            });

            if b <= 2 {
                Some(Elem::new(2 - b))
            } else {
                Some(-Elem::new(b - 2))
            }
        }
        Eta::Four if b < 9 => {
            let b = Int::from(b);
            if b <= 4 {
                Some(Elem::new(4 - b))
            } else {
                Some(-Elem::new(b - 4))
            }
        }
        _ => None,
    }
}

fn coeffs_from_byte(z: u8, eta: Eta) -> (Option<Elem>, Option<Elem>) {
    (
        coeff_from_half_byte(z & 0x0F, eta),
        coeff_from_half_byte(z >> 4, eta),
    )
}

#[inline(never)]
pub(crate) fn sample_in_ball(rho: &[u8], tau: usize) -> Polynomial {
    const ONE: Elem = Elem::new(1);
    const MINUS_ONE: Elem = Elem::new(BaseField::Q - 1);

    let mut c = Polynomial::default();
    let mut ctx = H::default().absorb(rho);

    let mut s = [0u8; 8];
    ctx.squeeze(&mut s);

    let mut j = [0u8];
    for i in (256 - tau)..256 {
        ctx.squeeze(&mut j);
        while usize::from(j[0]) > i {
            ctx.squeeze(&mut j);
        }

        let j = usize::from(j[0]);
        c.0[i] = c.0[j];
        c.0[j] = if bit_set(&s, i + tau - 256) {
            MINUS_ONE
        } else {
            ONE
        };
    }

    c
}

#[inline(never)]
pub(crate) fn rej_ntt_poly(rho: &[u8], r: u8, s: u8) -> NttPolynomial {
    let mut j = 0;
    let mut ctx = G::default().absorb(rho).absorb(&[s]).absorb(&[r]);
    let mut a = NttPolynomial::default();

    let mut buf = [0u8; 840];
    ctx.squeeze(&mut buf);

    for chunk in buf.chunks_exact(3) {
        if let Some(x) = coeff_from_three_bytes([chunk[0], chunk[1], chunk[2]]) {
            a.0[j] = x;
            j += 1;
            if j == 256 {
                break;
            }
        }
    }

    let mut tmp = [0u8; 3];
    while j < 256 {
        ctx.squeeze(&mut tmp);
        if let Some(x) = coeff_from_three_bytes(tmp) {
            a.0[j] = x;
            j += 1;
        }
    }
    #[cfg(feature = "zeroize")]
    {
        buf.zeroize();
        tmp.zeroize();
    }
    a
}

#[inline(never)]
pub(crate) fn rej_bounded_poly(rho: &[u8], eta: Eta, r: u16) -> Polynomial {
    let mut j = 0;
    let mut ctx = H::default().absorb(rho).absorb(&r.to_le_bytes());
    let mut a = Polynomial::default();

    let mut buf = [0u8; 272];
    ctx.squeeze(&mut buf);

    for &byte in &buf {
        let (z0, z1) = coeffs_from_byte(byte, eta);
        if let Some(x) = z0 {
            a.0[j] = x;
            j += 1;
            if j == 256 {
                break;
            }
        }
        if let Some(x) = z1 {
            a.0[j] = x;
            j += 1;
            if j == 256 {
                break;
            }
        }
    }

    let mut tmp = [0u8; 1];
    while j < 256 {
        ctx.squeeze(&mut tmp);
        let (z0, z1) = coeffs_from_byte(tmp[0], eta);
        if let Some(x) = z0 {
            a.0[j] = x;
            j += 1;
        }
        if j < 256 {
            if let Some(x) = z1 {
                a.0[j] = x;
                j += 1;
            }
        }
    }
    #[cfg(feature = "zeroize")]
    {
        buf.zeroize();
        tmp.zeroize();
    }
    a
}

#[inline(never)]
fn mul_a_hat_slice(rho: &[u8], v_hat: &[NttPolynomial], out: &mut [NttPolynomial]) {
    for (r, out_r) in out.iter_mut().enumerate() {
        let mut acc = NttPolynomial::default();
        for (s, v_s) in v_hat.iter().enumerate() {
            let a_rs = rej_ntt_poly(rho, Truncate::truncate(r), Truncate::truncate(s));
            acc = &acc + &(&a_rs * v_s);
        }
        *out_r = acc;
    }
}

pub(crate) fn mul_a_hat<K: ArraySize, L: ArraySize>(
    rho: &[u8],
    v_hat: &NttVector<L>,
) -> NttVector<K> {
    let mut out = NttVector::<K>::default();
    mul_a_hat_slice(rho, &v_hat.0, &mut out.0);
    out
}

#[inline(never)]
pub(crate) fn expand_s<K: ArraySize>(rho: &[u8], eta: Eta, base: usize) -> Vector<K> {
    Vector::new(Array::from_fn(|r| {
        let r = Truncate::truncate(r + base);
        rej_bounded_poly(rho, eta, r)
    }))
}

#[inline(never)]
pub(crate) fn expand_mask_poly<Gamma1: MaskSamplingSize>(rho: &[u8], mu_plus_r: u16) -> Polynomial {
    let v = H::default()
        .absorb(rho)
        .absorb(&mu_plus_r.to_le_bytes())
        .squeeze_new::<Gamma1::SampleSize>();
    Gamma1::unpack(&v)
}

#[inline(never)]
pub(crate) fn expand_mask<K, Gamma1>(rho: &[u8], mu: u16) -> Vector<K>
where
    K: ArraySize,
    Gamma1: MaskSamplingSize,
{
    Vector::new(Array::from_fn(|r| {
        let r: u16 = Truncate::truncate(r);
        expand_mask_poly::<Gamma1>(rho, mu + r)
    }))
}
