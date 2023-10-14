//use crate::auxiliary_algorithms::{g, prf};


/// Implements <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>

// TODO: Need to add zeroization (?)

/// Algorithm 2 `BitsToBytes(b)` near line 760 of page 17
///
/// # Panics
/// Will panic if input bit array length is not a multiple of 8 or length does not fit within `u32`
#[must_use]
pub fn bits_to_bytes(bit_array: &[u8]) -> Vec<u8> {
    assert_eq!(
        bit_array.len() % 8,
        0,
        "bit_array length must be a multiple of 8" // zero is OK
    );
    assert!(
        u32::try_from(bit_array.len()).is_ok(), // TODO: Find better max
        "bit_array length must fit within u32"
    );
    let mut byte_array = vec![0u8; bit_array.len() / 8]; // TODO: Any way to avoid heap alloc?
    for i in 0..bit_array.len() {
        byte_array[&i / 8] += bit_array[i] * 2u8.pow(u32::try_from(i).expect("too many bits") % 8);
    }
    byte_array
}

/// Algorithm 3 `BytesToBits(B)` near line 760 of page 17-18
/// # Panics
/// Will panic if output byte array length does not fit within `u32`
#[must_use]
pub fn bytes_to_bits(byte_array: &[u8]) -> Vec<u8> {
    assert!(byte_array.len() < (u32::MAX / 8) as usize); // TODO: Find better max
    let mut bit_array = vec![0u8; 8 * byte_array.len()];
    for i in 0..byte_array.len() {
        let mut byte = byte_array[i];
        for j in 0..8usize {
            bit_array[8 * i + j] = &byte % 2u8;
            byte /= 2;
        }
    }
    bit_array
}

// TODO: Maybe this whould be a wrapper
type Z256 = u16;

/// Algorithm 4 `ByteEncode<d>(F)` near line 774 of page 18-19
/// # Panics
/// Will panic if D is outside of 1..12
#[must_use]
pub fn byte_encode<const D: u32, const Q: u32>(integer_array: [Z256; 256]) -> Vec<u8> {
    // TODO:We know output size
    assert!((1 <= D) & (D <= 12));
    let m: u32 = if D < 12 { 2_u32.pow(D) } else { Q };
    let mut bit_array = vec![0u8; 256 * D as usize];
    for i in 0..256 {
        let mut a = integer_array[i] % u16::try_from(m).unwrap();
        for j in 0..(D as usize) {
            bit_array[i * (D as usize) + j] = (&a % 2) as u8;
            a = (a - u16::from(bit_array[i * (D as usize) + j])) / 2;
        }
    }
    bits_to_bytes(&bit_array)
}

/// Algorithm 5 `ByteDecode<d>(F)` near line 774 of page 18-19
/// # Panics
/// Will panic if D is outside of 1..12, or if `byte_array` length is not 32*D
#[must_use]
#[allow(dead_code)]
pub fn byte_decode<const D: usize, const Q: u32>(byte_array: &[u8]) -> Vec<Z256> {
    // TODO: We know output size
    assert!((1 <= D) & (D <= 12));
    assert_eq!(byte_array.len(), 32 * D);
    let m: u32 = if D < 12 {
        2_u32.pow(D.try_into().unwrap())
    } else {
        Q
    };
    let mut integer_array: Vec<Z256> = vec![0; 256];
    let bit_array = bytes_to_bits(byte_array);
    for i in 0..256 {
        integer_array[i] = (0..D).fold(0, |acc, j| {
            acc + u16::from(bit_array[i * D + j]) * 2_u16.pow(u32::try_from(j).unwrap())
                % (u16::try_from(m).unwrap())
        });
    }
    integer_array
}

/// Algorithm 6 `SampleNTT(B)` near line 800 of page 20
/// Hmmmm, `byte_stream` has to be an object that bytes can be drawn from
/// # Panics
/// Will panic if input `byte_stream` cannot be put into u32
#[must_use]
pub fn sample_ntt<const Q: u32>(mut reader: impl XofReader) -> [Z256; 256] {
    let mut a_hat: [Z256; 256] = [0; 256];
    // let mut i = 0; // BECAUSE USING A XOF READER BELOW
    let mut j = 0;
    while j < 256 {
        let mut bbb = [0u8; 3];
        reader.read(&mut bbb);
        let d1 = u32::try_from(bbb[0]).unwrap() + 256 * (u32::try_from(bbb[1]).unwrap() % 16);
        let d2 = u32::try_from(bbb[0]).unwrap() / 16 + 16 * u32::try_from(bbb[2]).unwrap();
        if d1 < Q {
            a_hat[j] = Z256::try_from(d1).unwrap();
            j += 1;
        }
        if (d2 < Q) & (j < 256) {
            a_hat[j] = Z256::try_from(d2).unwrap();
            j += 1;
        }
        // i += 3;  XOF READER
    }
    a_hat
}

/// Algorithm 7 SamplePolyCBDη(B) near line 800 of page 20
/// # Panics
/// Will panic if input `byte_array` cannot be put into u32
#[must_use]
pub fn sample_poly_cbd<const ETA: u32, const Q: u32>(byte_array: &[u8]) -> [Z256; 256] {
    assert_eq!(byte_array.len(), 64 * ETA as usize);
    let mut integer_array: [Z256; 256] = [0; 256];
    let bit_array = bytes_to_bits(byte_array);
    for i in 0..256 {
        let x = (0..(ETA as usize)).fold(0, |acc: u32, j| {
            acc + u32::try_from(bit_array[2 * i * (ETA as usize) + j]).unwrap()
        });
        let y = (0..(ETA as usize)).fold(0, |acc: u32, j| {
            acc + u32::try_from(bit_array[2 * i * (ETA as usize) + (ETA as usize) + j]).unwrap()
        });
        integer_array[i] = Z256::try_from((Q + x - y) % Q).unwrap();
    }
    integer_array
}

/// BitRev7(i) -- an unnumbered algorithm -- reverse lower 7 bits
#[must_use]
pub fn bit_rev_7(a: u8) -> u8 {
    ((a >> 6) & 1)
        | ((a >> 4) & 2)
        | ((a >> 2) & 4)
        | (a & 8)
        | ((a << 2) & 16)
        | ((a << 4) & 32)
        | ((a << 6) & 64)
}
// probably ought to implement a quicker mod Q

const ZETA: u32 = 17;
const Q: u32 = 3329;

// HAC Algorithm 14.76 Right-to-left binary exponentiation
fn pow_mod_q(g: u32, e: u8) -> u32 {
    let mut result = 1;
    let mut s = g;
    let mut e = e;
    while e != 0 {
        if e & 1 != 0 {
            result = (result * s) % Q
        };
        e >>= 1;
        if e != 0 {
            s = (s * s) % Q
        };
    }
    result
}

/// Algorithm 8 NTT(f) near line 847 on page 22
/// # Panics
/// Will panic if input `byte_array` cannot be put into u32
#[must_use]
pub fn ntt(integer_array: &[Z256; 256]) -> [Z256; 256] {
    let mut output_array: [Z256; 256] = [0; 256];
    output_array.copy_from_slice(integer_array);
    let mut k = 1;
    for len in [128, 64, 32, 16, 8, 4, 2] {
        for start in (0..256).step_by(2 * len) {
            let zeta = pow_mod_q(ZETA, bit_rev_7(k));
            k += 1;
            for j in start..(start + len) {
                let t = (zeta * u32::try_from(output_array[j + len]).unwrap()) % Q;
                output_array[j + len] =
                    ((Q + u32::try_from(output_array[j]).unwrap() - t) % Q) as u16;
                output_array[j] = ((u32::try_from(output_array[j]).unwrap() + t) % Q) as u16;
            }
        }
    }
    output_array
}

/// Algorithm 9 NTTinv(f) near line 855 on page 23
/// # Panics
/// blah blah
#[must_use]
#[allow(dead_code)]
pub fn ntt_inv(f_hat: &[Z256; 256]) -> [Z256; 256] {
    let mut f: [Z256; 256] = [0; 256];
    f.copy_from_slice(f_hat);
    let mut k = 127;
    for len in [2, 4, 8, 16, 32, 64, 128] {
        for start in (0..256).step_by(2 * len) {
            let zeta = pow_mod_q(ZETA, bit_rev_7(k));
            k -= 1;
            for j in start..(start + len) {
                let t = f[j];
                f[j] = (t + f[j + len]) % (u16::try_from(Q).unwrap());
                f[j + len] = ((zeta
                    * (Q + u32::try_from(f[j + len]).unwrap() - u32::try_from(t).unwrap()))
                    % Q) as u16;
            }
        }
    }
    f.iter_mut()
        .for_each(|item| *item = ((u32::from(*item) * 3303) % Q) as u16);
    f
}

/// Algorithm 10 `MultiplyNTTs(f, g)`
/// # Panics
/// blah blah
#[must_use]
pub fn multiply_ntts(f_hat: &[Z256; 256], g_hat: &[Z256; 256]) -> [Z256; 256] {
    let mut h_hat: [Z256; 256] = [0; 256];
    for i in 0..128 {
        let (h_hat_2i, h_hat_2ip1) = base_case_multiply(
            f_hat[2 * i],
            f_hat[2 * i + 1],
            g_hat[2 * i],
            g_hat[2 * i + 1],
            Z256::try_from(pow_mod_q(ZETA, 2 * bit_rev_7(u8::try_from(i).unwrap()) + 1)).unwrap(),
        );
        h_hat[2 * i] = h_hat_2i;
        h_hat[2 * i + 1] = h_hat_2ip1;
    }
    h_hat
}

/// Algorithm 11 `BaseCaseMultiply(a0, a1, b0, b1, gamma)`
#[must_use]
pub fn base_case_multiply(a0: Z256, a1: Z256, b0: Z256, b1: Z256, gamma: Z256) -> (Z256, Z256) {
    let c0 = (u32::from(a0) * u32::from(b0)
        + (u32::from(a1) * u32::from(b1) % Q) * u32::from(gamma))
        % Q;
    let c1 = (u32::from(a0) * u32::from(b1) + u32::from(a1) * u32::from(b0)) % Q;

    (c0 as Z256, c1 as Z256)
}

use sha3::digest::XofReader; //, Digest, Sha3_512, Shake128, Shake256;

/// XOF
// fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
//     let mut hasher = Shake128::default();
//     hasher.update(rho);
//     hasher.update(&[i]);
//     hasher.update(&[j]);
//     let reader = hasher.finalize_xof();
//     reader
// }

//use rand::Rng;
//use crate::auxiliary_algorithms::xof;

/// Function G from line 746 on page 17
// fn g(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
//     let mut hasher = Sha3_512::new();
//     Digest::update(&mut hasher, bytes);
//     let digest = hasher.finalize();
//     let mut a = [0u8; 32];
//     let mut b = [0u8; 32];
//     a.copy_from_slice(&digest[0..32]);
//     b.copy_from_slice(&digest[32..64]);
//     (a, b)
// }

/// Function PRF on line 726 of page 16  TODO:hardcode N1 to 2
// fn prf<const N1: usize>(s: &[u8; 32], b: u8) -> [u8; 64 * 2] {
//     let mut hasher = Shake256::default();
//     hasher.update(s);
//     hasher.update(&[b]);
//     let mut reader = hasher.finalize_xof();
//     let mut result = [0u8; 64 * 2];
//     reader.read(&mut result);
//     result
// }

/// Algorithm 12 page 26 TODO: 2 is a placeholder for k
// pub fn k_pke_keygen() -> ([u8; 384 * 2 + 32], [u8; 384 * 2]) {
//     const K: usize = 2;
//     let mut ek_pke = [0u8; 384 * K + 32];
//     let mut dk_pke = [0u8; 384 * K];
//     let d = rand::thread_rng().gen::<[u8; 32]>();
//     let (rho, sigma) = g(&d);
//     let mut n = 0;
//     let mut a_hat: [[[Z256; 256]; K]; K] = [[[0; 256]; K]; K];
//     for i in 0..K {
//         for j in 0..K {
//             a_hat[i][j] = sample_ntt::<3329>(xof(&d, i.try_into().unwrap(), j.try_into().unwrap()));
//         }
//     }
//     let mut s: [[Z256; 256]; K] = [[0; 256]; K];
//     for i in 0..K {
//         s[i] = sample_poly_cbd::<2, 3379>(&prf::<2>(&sigma, n));
//         n += 1;
//     }
//     let mut e: [[Z256; 256]; K] = [[0; 256]; K];
//     for i in 0..K {
//         e[i] = sample_poly_cbd::<2, 3379>(&prf::<2>(&sigma, n));
//         n += 1;
//     }
//
//     let mut s_hat: [[Z256; 256]; 2] = [[0; 256]; 2];
//     for i in 0..2 {
//         s_hat[i] = ntt(&s[i]);
//     }
//     let mut e_hat: [[Z256; 256]; 2] = [[0; 256]; 2];
//     for i in 0..2 {
//         e_hat[i] = ntt(&e[i]);
//     }
//
//     let mut t_hat: [[Z256; 256]; 2] = [[0; 256]; 2];
//     for i in 0..2 {
//         for j in 0..2 {
//             for (t_ref, m_val) in t_hat[i]
//                 .iter_mut()
//                 .zip(multiply_ntts(&a_hat[i][j], &s_hat[j]))
//             {
//                 *t_ref = *t_ref + m_val
//             }
//         }
//     }
//
//     for i in 0..2 {
//         for (t_ref, m_val) in t_hat[i].iter_mut().zip(&e_hat[i]) {
//             *t_ref = *t_ref + m_val
//         }
//     }
//
//     let mut ek = Vec::new();
//     for i in 0..2 {
//         let t = byte_encode::<12, 3379>(t_hat[i]);
//         ek.extend(t);
//     }
//     ek.extend(rho);
//
//     let mut dk = Vec::new();
//     for i in 0..2 {
//         let t = byte_encode::<12, 3379>(s[i]);
//         dk.extend(t);
//     }
//
//     ek_pke.copy_from_slice(&ek);
//     dk_pke.copy_from_slice(&dk);
//     (ek_pke, dk_pke)
// }

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_k_pke_keygen() {
        let x = k_pke_keygen();
        //assert_eq!(x.0[0], 0);
    }

    #[test]
    fn test_bytes_and_bits() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);

        for _i in 0..100 {
            let num_bytes = rng.gen::<u8>();
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let bits = bytes_to_bits(&bytes1);
            let bytes2 = bits_to_bytes(&bits);
            assert_eq!(bytes1, bytes2);
        }
    }

    #[test]
    fn test_decode_and_encode() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);

        for _i in 0..100 {
            let num_bytes = 32 * 11; //256;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let integer_array = byte_decode::<11, 3329>(&bytes1);
            let bytes2 =
                byte_encode::<11, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 10; //256;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let integer_array = byte_decode::<10, 3329>(&bytes1);
            let bytes2 =
                byte_encode::<10, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 5; //256;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let integer_array = byte_decode::<5, 3329>(&bytes1);
            let bytes2 =
                byte_encode::<5, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 4; //256;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let integer_array = byte_decode::<4, 3329>(&bytes1);
            let bytes2 =
                byte_encode::<4, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
            assert_eq!(bytes1, bytes2);
        }
    }
}
