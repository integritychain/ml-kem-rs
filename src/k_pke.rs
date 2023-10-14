use rand::random;
use crate::auxiliary_algorithms::{g, prf, xof};
use crate::old_lib::{sample_ntt, sample_poly_cbd, ntt, multiply_ntts, byte_encode};

type Z256 = u16; //TODO: should be u32;

/// Algorithm 12 page 26 TODO: 2 is a placeholder for k
pub fn k_pke_key_gen<const K: usize>(ek_pke: &mut [u8], dk_pke: &mut [u8]) {
    let d = random::<[u8; 32]>();
    let (rho, sigma) = g(&d);
    let mut n = 0;
    let mut a_hat: [[[Z256; 256]; K]; K] = [[[0; 256]; K]; K];
    for i in 0..K {
        for j in 0..K {
            a_hat[i][j] = sample_ntt::<3329>(xof(&d, i.try_into().unwrap(), j.try_into().unwrap()));
        }
    }
    let mut s: [[Z256; 256]; K] = [[0; 256]; K];
    for i in 0..K {
        s[i] = sample_poly_cbd::<2, 3379>(&prf::<2>(&sigma, n));
        n += 1;
    }
    let mut e: [[Z256; 256]; K] = [[0; 256]; K];
    for i in 0..K {
        e[i] = sample_poly_cbd::<2, 3379>(&prf::<2>(&sigma, n));
        n += 1;
    }

    let mut s_hat: [[Z256; 256]; K] = [[0; 256]; K];
    for i in 0..K {
        s_hat[i] = ntt(&s[i]);
    }
    let mut e_hat: [[Z256; 256]; K] = [[0; 256]; K];
    for i in 0..K {
        e_hat[i] = ntt(&e[i]);
    }

    let mut t_hat: [[Z256; 256]; K] = [[0; 256]; K];
    for i in 0..K {
        for j in 0..K {
            for (t_ref, m_val) in t_hat[i]
                .iter_mut()
                .zip(multiply_ntts(&a_hat[i][j], &s_hat[j]))
            {
                *t_ref = *t_ref + m_val
            }
        }
    }

    for i in 0..K {
        for (t_ref, m_val) in t_hat[i].iter_mut().zip(&e_hat[i]) {
            *t_ref = *t_ref + m_val
        }
    }

    let mut ek = Vec::new();  // TODO: stuff into ek_pke directly
    for i in 0..K {
        let t = byte_encode::<12, 3379>(t_hat[i]);
        ek.extend(t);
    }
    ek.extend(rho);

    let mut dk = Vec::new();  // TODO: stuff into dk_pke directly
    for i in 0..K {
        let t = byte_encode::<12, 3379>(s[i]);
        dk.extend(t);
    }

    ek_pke.copy_from_slice(&ek);
    dk_pke.copy_from_slice(&dk);
}
