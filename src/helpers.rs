use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::digest::Update;

use crate::k_pke::Z256;
use crate::ntt::multiply_ntts;
use crate::Q;

/// Function PRF on line 726 of page 16  TODO:hardcode N1 to 2
pub fn prf<const ETA1_64: usize>(s: &[u8; 32], b: u8) -> [u8; ETA1_64] {
    let mut hasher = Shake256::default();
    hasher.update(s);
    hasher.update(&[b]);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; ETA1_64];
    reader.read(&mut result);
    result
}

/// XOF
pub fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[i]);
    hasher.update(&[j]);
    hasher.finalize_xof()
}

/// Function G from line 746 on page 17
pub(crate) fn g(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&digest[0..32]);
    b.copy_from_slice(&digest[32..64]);
    (a, b)
}

/// Function H from line 746 on page 17
pub fn h(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    digest.into()
}

/// Function J from line 746 on page 17
pub fn j(bytes: &[u8], int: u8) -> [u8; 32] {
    debug_assert_eq!(int, 32);
    let mut hasher = Shake256::default();
    hasher.update(bytes);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; 32];
    reader.read(&mut result);
    result
}

/// BitRev7(i) -- an unnumbered algorithm -- reverse lower 7 bits
#[must_use]
pub fn bit_rev_7(a: u8) -> u8 {
    ((a >> 6) & 1) | ((a >> 4) & 2) | ((a >> 2) & 4) | (a & 8) | ((a << 2) & 16) | ((a << 4) & 32) | ((a << 6) & 64)
}

/// HAC Algorithm 14.76 Right-to-left binary exponentiation
pub fn pow_mod_q(g: u32, e: u8) -> u32 {
    let mut result = 1;
    let mut s = g;
    let mut e = e;
    while e != 0 {
        if e & 1 != 0 {
            result = (result * s) % Q;
        };
        e >>= 1;
        if e != 0 {
            s = (s * s) % Q;
        };
    }
    result
}

#[allow(dead_code)]
pub fn compress<const D: usize>(inout: &mut [Z256]) {
    for x_ref in inout.iter_mut() {
        x_ref.0 = ((x_ref.0 as u32) * (2u32.pow(D as u32) / Q)) as u16;
    }
}

pub fn decompress<const D: usize>(inout: &mut [Z256]) {
    for y_ref in inout.iter_mut() {
        y_ref.0 = ((y_ref.0 as u32) * (Q / 2u32.pow(D as u32))) as u16;
    }
}

// See page 10 just above line 531 -- defition of w_hat = A_hat o u_hat
pub fn mat_mul<const K: usize>(mat_a: &[[[Z256; 256]; K]; K], vec_b: &[[Z256; 256]; K]) -> [[Z256; 256]; K] {
    let mut result = [[Z256(0); 256]; K];
    for (i, result_ref) in result.iter_mut().enumerate() {
        for j in 0..K {
            let tmp = multiply_ntts(&mat_a[i][j], &vec_b[j]);
            for k in 0..tmp.len() {
                result_ref[k].set_u16(result_ref[k].get_u32() + tmp[k].get_u32());
            }
        }
    }
    result
}

pub fn vec_add<const K: usize>(vec_a: &[[Z256; 256]; K], vec_b: &[[Z256; 256]; K]) -> [[Z256; 256]; K] {
    let mut result = [[Z256(0); 256]; K];
    for i in 0..vec_a.len() {
        for j in 0..vec_a[i].len() {
            result[i][j].set_u16(vec_a[i][j].get_u32() + vec_b[i][j].get_u32());
        }
    }
    result
}

// See transpose page 10 just above line 531 -- defition of y_hat = A_hat^T o u_hat
pub fn mat_t_mul<const K: usize>(mat_a: &[[[Z256; 256]; K]; K], vec_b: &[[Z256; 256]; K]) -> [[Z256; 256]; K] {
    let mut result = [[Z256(0); 256]; K];
    for (i, result_ref) in result.iter_mut().enumerate() {
        for j in 0..K {
            let tmp = multiply_ntts(&mat_a[j][i], &vec_b[j]); // Note i and j are reversed
            for k in 0..tmp.len() {
                result_ref[k].set_u16(result_ref[k].get_u32() + tmp[k].get_u32());
            }
        }
    }
    result
}

pub fn dot_t_prod<const K: usize>(vec_a: &[[Z256; 256]; K], vec_b: &[[Z256; 256]; K]) -> [Z256; 256] {
    let mut result = [Z256(0); 256];
    for j in 0..vec_a.len() {
        let tmp = multiply_ntts(&vec_a[j], &vec_b[j]);
        for k in 0..vec_a[j].len() {
            result[k].set_u16(result[k].get_u32() + tmp[k].get_u32());
        }
    }
    result
}
