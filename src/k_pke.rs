use rand::random;

use crate::byte_fns::{byte_decode, byte_encode};
use crate::helpers::{compress, decompress, dot_t_prod, g, mat_mul, mat_t_mul, prf, vec_add, xof};
use crate::ntt::{ntt, ntt_inv, sample_ntt, sample_poly_cbd};
use crate::Q;

#[derive(Clone, Copy)]
pub struct Z256(pub u16);

// Stored as u16, but arithmetic as u32 (so we can multiply/reduce/etc)
impl Z256 {
    pub fn get_u32(&self) -> u32 {
        u32::from(self.0)
    }
    pub fn get_u16(&self) -> u16 {
        self.0
    }
    pub fn set_u16(&mut self, a: u32) {
        assert!(a < u16::MAX as u32);
        self.0 = a as u16
    }
    #[allow(dead_code)] // stitch in when we get overall correct
    pub fn mul(&self, other: Self) -> Self {
        let prod = self.0 as u64 * other.0 as u64;
        let div = prod * (2u64.pow(24) / (Q as u64));
        let (diff, borrow) = div.overflowing_sub(Q as u64);
        let result = if borrow { div } else { diff }; // TODO: CT MUX
        return Self(result as u16);
    }
}

/// Algorithm 12 page 26
pub fn k_pke_key_gen<const K: usize, const ETA1: usize, const ETA1_64: usize>(ek_pke: &mut [u8], dk_pke: &mut [u8]) {
    debug_assert_eq!(ek_pke.len(), 384 * K + 32);
    debug_assert_eq!(dk_pke.len(), 384 * K);
    let d = random::<[u8; 32]>();
    let (rho, sigma) = g(&d);
    let mut n = 0;
    let mut a_hat = [[[Z256(0); 256]; K]; K];
    #[allow(clippy::needless_range_loop)] // Follow algorithm as written, for now
    for i in 0..K {
        for j in 0..K {
            a_hat[i][j] = sample_ntt(xof(&rho, u8::try_from(i).unwrap(), u8::try_from(j).unwrap()));
        }
    }
    let mut s = [[Z256(0); 256]; K];
    for i in 0..K {
        s[i] = sample_poly_cbd::<ETA1, ETA1_64>(&prf::<ETA1_64>(&sigma, n));
        n += 1;
    }
    let mut e = [[Z256(0); 256]; K];
    for i in 0..K {
        e[i] = sample_poly_cbd::<ETA1, ETA1_64>(&prf::<ETA1_64>(&sigma, n));
        n += 1;
    }

    let mut s_hat = [[Z256(0); 256]; K];
    for i in 0..K {
        s_hat[i] = ntt(&s[i]);
    }
    let mut e_hat = [[Z256(0); 256]; K];
    for i in 0..K {
        e_hat[i] = ntt(&e[i]);
    }

    let t_hat = vec_add(&mat_mul(&a_hat, &s_hat), &e_hat);

    for i in 0..K {
        byte_encode::<12, 3072>(&t_hat[i], &mut ek_pke[i * 384..(i + 1) * 384]); // 384 = 32*d, d=12
    }
    ek_pke[K * 384..].copy_from_slice(&rho);

    for i in 0..K {
        byte_encode::<12, 3072>(&s[i], &mut dk_pke[i * 384..(i + 1) * 384]);
    }
}

pub(crate) fn k_pke_encrypt<
    const K: usize,
    const ETA1: usize,
    const ETA1_64: usize,
    const ETA2: usize,
    const ETA2_64: usize,
    const DU: usize,
    const DU_256: usize,
    const DV: usize,
    const DV_256: usize
>(
    ek: &[u8], m: &[u8], randomness: &[u8; 32], ct: &mut [u8],
) {
    debug_assert_eq!(ek.len(), 384 * K + 32);
    debug_assert_eq!(m.len(), 32);
    debug_assert_eq!(randomness.len(), 32);
    let mut n = 0;
    let mut t_hat = [[Z256(0); 256]; K];
    for i in 0..K {
        byte_decode::<12, { 384 * 8 }>(&ek[384 * i..384 * (i + 1)], &mut t_hat[i]);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..(384 * K + 32)]);
    let mut a_hat = [[[Z256(0); 256]; K]; K];
    for i in 0..K {
        for j in 0..K {
            a_hat[i][j] = sample_ntt(xof(&rho, u8::try_from(i).unwrap(), u8::try_from(j).unwrap()));
        }
    }
    let mut r = [[Z256(0); 256]; K];
    for i in 0..K {
        r[i] = sample_poly_cbd::<ETA1, ETA1_64>(&prf::<ETA1_64>(&randomness, n));
        n += 1;
    }
    let mut e1 = [[Z256(0); 256]; K];
    for i in 0..K {
        e1[i] = sample_poly_cbd::<ETA2, ETA2_64>(&prf::<ETA2_64>(&randomness, n));
        n += 1;
    }

    let e2 = sample_poly_cbd::<ETA2, ETA2_64>(&prf::<ETA2_64>(&randomness, n));

    let mut r_hat = [[Z256(0); 256]; K];
    for i in 0..K {
        r_hat[i] = ntt(&r[i]);
    }

    let mut u = mat_t_mul(&a_hat, &r_hat);
    for i in 0..K {
        u[i] = ntt_inv(&u[i]);
    }
    u = vec_add(&u, &e1);

    let mut mu = [Z256(0); 256];
    byte_decode::<1, { 32 * 8 }>(m, &mut mu);
    decompress::<1>(&mut mu);

    let mut v = vec_add(&vec_add(&[dot_t_prod(&t_hat, &r_hat)], &[e2]), &[mu]);

    for i in 0..K {
        compress::<DU>(&mut u[i]);
        byte_encode::<DU, DU_256>(&u[i], &mut ct[i * 320..(i + 1) * 320]);
    }

    compress::<DV>(&mut v[0]);
    byte_encode::<DV, DV_256>(&v[0], &mut ct[K * 320..(K * 320 + 128)]); // DV = 4 FIX!!

    ct[0] = 99;
}

pub(crate) fn k_pke_decrypt<const K: usize, const DU: usize, const DU_8: usize, const DV: usize, const DV_8: usize>(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let c1 = &ct[0..32 * DU * K];
    let c2 = &ct[32 * DU * K..32 * (DU * K + DV)];

    let mut u = [[Z256(0); 256]; K];
    for i in 0..K {
        byte_decode::<DU, DU_8>(&c1[32 * DU * i..32 * DU * (i + 1)], &mut u[i]);
        decompress::<DU>(&mut u[i]);
    }

    let mut v = [Z256(0); 256];
    byte_decode::<DV, DV_8>(c2, &mut v);
    decompress::<DV>(&mut v);

    let mut s_hat = [Z256(0); 256];
    byte_decode::<12, { 384 * 8 }>(&dk[0..384], &mut s_hat);

    let mut w = [Z256(0); 256];
    for i in 0..K {
        let xx = mat_t_mul(&[[s_hat]], &[ntt(&u[i])]);
        let yy = ntt_inv(&xx[0]);
        for i in 0..256 {
            w[i].set_u16((Q + v[i].get_u32() - yy[i].get_u32()) % Q);
        }
    }
    compress::<1>(&mut w);
    let mut m = [0u8; 32];
    byte_encode::<1, 256>(&w, &mut m);
    m
}
