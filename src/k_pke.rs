use rand::random;

use crate::aux_fns::{g, prf, xof};
use crate::byte_fns::{byte_decode, byte_encode};
use crate::ntt::{multiply_ntts, ntt, ntt_inv, sample_ntt, sample_poly_cbd};

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

    let mut t_hat = [[Z256(0); 256]; K];

    // matrix product of a_hat and s_hat
    for i in 0..K {
        for j in 0..K {
            for (t_ref, m_val) in t_hat[i]
                .iter_mut()
                .zip(multiply_ntts(&a_hat[i][j], &s_hat[j]))
            {
                t_ref.set_u16(t_ref.get_u32() + m_val.get_u32());
            }
        }
    }

    // add in e_hat
    for i in 0..K {
        for (t_ref, m_val) in t_hat[i].iter_mut().zip(&e_hat[i]) {
            t_ref.set_u16(t_ref.get_u32() + m_val.get_u32());
        }
    }

    for i in 0..K {
        byte_encode::<12>(&t_hat[i], &mut ek_pke[i * 384..(i + 1) * 384]); // 384 = 32*d, d=12
    }
    ek_pke[K * 384..].copy_from_slice(&rho);

    for i in 0..K {
        byte_encode::<12>(&s[i], &mut dk_pke[i * 384..(i + 1) * 384]);
    }
}

pub(crate) fn k_pke_encrypt<
    const K: usize,
    const ETA1: usize,
    const ETA1_64: usize,
    const ETA2: usize,
    const ETA2_64: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &[u8], m: &[u8], randomness: &[u8; 32], ct: &mut [u8],
) {
    debug_assert_eq!(ek.len(), 384 * K + 32);
    debug_assert_eq!(m.len(), 32);
    debug_assert_eq!(randomness.len(), 32);
    let mut n = 0;
    let mut t_hat = [[Z256(0); 256]; K];
    for i in 0..K {
        byte_decode::<12>(&ek[384 * i..384 * (i + 1)], &mut t_hat[i]);
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

    let _e2 = sample_poly_cbd::<ETA2, ETA2_64>(&prf::<ETA2_64>(&randomness, n));

    let mut r_hat = [[Z256(0); 256]; K];
    for i in 0..K {
        r_hat[i] = ntt(&r[i]);
    }

    // matrix product of a_hat^T and r_hat  // TODO: doubt this is correct
    let mut aht_rh = [[Z256(0); 256]; K];
    for i in 0..K {
        for j in 0..K {
            for (a_ref, m_val) in aht_rh[j]
                .iter_mut()
                .zip(multiply_ntts(&a_hat[j][i], &r_hat[j]))
            {
                a_ref.set_u16(a_ref.get_u32() + m_val.get_u32());
            }
        }
    }

    let mut u = [[Z256(0); 256]; K];
    for i in 0..K {
        u[i] = ntt_inv(&aht_rh[i]);
    }

    for i in 0..K {
        for (u_ref, m_val) in u[i].iter_mut().zip(&e1[i]) {
            u_ref.set_u16(u_ref.get_u32() + m_val.get_u32());
        }
    }

    // TODO: Implement step 20 onwards...

    ct[0] = 99;
}
