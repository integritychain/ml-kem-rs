use sha3::digest::XofReader;

//pub(crate) type Z256 = u16;
use crate::byte_fns::bytes_to_bits;
use crate::helpers;
use crate::k_pke::Z256;

//, Digest, Sha3_512, Shake128, Shake256;

/// Algorithm 6 `SampleNTT(B)` near line 800 of page 20
/// # Panics
/// Will panic if input `byte_stream` cannot be put into u32
#[must_use]
pub fn sample_ntt(mut reader: impl XofReader) -> [Z256; 256] {
    let mut a_hat = [Z256(0); 256];
    // i is not needed as we are repeatedly draw three bytes from the rng bytestream via bbb
    let mut j = 0;
    while j < 256 {
        let mut bbb = [0u8; 3];
        reader.read(&mut bbb);
        let d1 = u32::from(bbb[0]) + 256 * (u32::from(bbb[1]) % 16);
        let d2 = u32::from(bbb[1]) / 16 + 16 * u32::from(bbb[2]);
        if d1 < Q {
            a_hat[j].set_u16(d1); // = Z256::try_from(d1).unwrap();
            j += 1;
        }
        if (d2 < Q) & (j < 256) {
            a_hat[j].set_u16(d2); // = Z256::try_from(d2).unwrap();
            j += 1;
        }
    }
    a_hat
}

/// Algorithm 7 SamplePolyCBDη(B) near line 800 of page 20
/// # Panics
/// Will panic if input `byte_array` cannot be put into u32
#[must_use]
pub fn sample_poly_cbd<const ETA: usize, const ETA_64: usize>(byte_array: &[u8]) -> [Z256; 256] {
    debug_assert_eq!(byte_array.len(), ETA_64);
    let mut integer_array: [Z256; 256] = [Z256(0); 256];
    let bit_array = bytes_to_bits(byte_array);
    for i in 0..256 {
        let x = (0..(ETA as usize)).fold(0, |acc: u32, j| acc + u32::from(bit_array[2 * i * ETA + j]));
        let y = (0..(ETA as usize)).fold(0, |acc: u32, j| acc + u32::from(bit_array[2 * i * ETA + ETA + j]));
        integer_array[i].set_u16((Q + x - y) % Q);
    }
    integer_array
}

const ZETA: u32 = 17;
const Q: u32 = 3329;

/// Algorithm 8 NTT(f) near line 847 on page 22
/// # Panics
/// Will panic if input `byte_array` cannot be put into u32
#[must_use]
pub fn ntt(integer_array: &[Z256; 256]) -> [Z256; 256] {
    let mut output_array = [Z256(0); 256];
    output_array.copy_from_slice(integer_array);
    let mut k = 1;
    for len in [128, 64, 32, 16, 8, 4, 2] {
        for start in (0..256).step_by(2 * len) {
            let zeta = helpers::pow_mod_q(ZETA, helpers::bit_rev_7(k));
            k += 1;
            for j in start..(start + len) {
                let t = (zeta * (output_array[j + len]).get_u32()) % Q;
                output_array[j + len].set_u16((Q + output_array[j].get_u32() - t) % Q);
                output_array[j].set_u16(((output_array[j]).get_u32() + t) % Q);
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
    let mut f: [Z256; 256] = [Z256(0); 256];
    f.copy_from_slice(f_hat);
    let mut k = 127;
    for len in [2, 4, 8, 16, 32, 64, 128] {
        for start in (0..256).step_by(2 * len) {
            let zeta = helpers::pow_mod_q(ZETA, helpers::bit_rev_7(k));
            k -= 1;
            for j in start..(start + len) {
                let t = f[j];
                f[j].set_u16((t.get_u32() + f[j + len].get_u32()) % Q);
                f[j + len].set_u16((zeta * (Q + f[j + len].get_u32() - (t.get_u32() % Q))) % Q);
                // TODO: fail on t too large
            }
        }
    }
    f.iter_mut()
        .for_each(|item| item.set_u16(item.get_u32() * 3303 % Q));
    f
}

/// Algorithm 10 `MultiplyNTTs(f, g)`
/// # Panics
/// blah blah
#[must_use]
pub fn multiply_ntts(f_hat: &[Z256; 256], g_hat: &[Z256; 256]) -> [Z256; 256] {
    let mut h_hat: [Z256; 256] = [Z256(0); 256];
    for i in 0..128 {
        let (h_hat_2i, h_hat_2ip1) = base_case_multiply(
            f_hat[2 * i],
            f_hat[2 * i + 1],
            g_hat[2 * i],
            g_hat[2 * i + 1],
            Z256(helpers::pow_mod_q(ZETA, 2 * helpers::bit_rev_7(u8::try_from(i).unwrap()) + 1) as u16),
        );
        h_hat[2 * i] = h_hat_2i;
        h_hat[2 * i + 1] = h_hat_2ip1;
    }
    h_hat
}

/// Algorithm 11 `BaseCaseMultiply(a0, a1, b0, b1, gamma)`
#[must_use]
pub fn base_case_multiply(a0: Z256, a1: Z256, b0: Z256, b1: Z256, gamma: Z256) -> (Z256, Z256) {
    let c0 = Z256((((a0.get_u32() * b0.get_u32() % Q + a1.get_u32() * b1.get_u32() % Q) * gamma.get_u32()) % Q) as u16);
    let c1 = Z256(((a0.get_u32() * b1.get_u32() + a1.get_u32() * b0.get_u32()) % Q) as u16);

    (c0, c1)
}

// #[cfg(test)]
// mod tests {
//     use rand::{Rng, SeedableRng};
//     use crate::bytes2::{bits_to_bytes, byte_decode, byte_encode, bytes_to_bits};
//
//     #[test]
//     fn test_k_pke_keygen() {
//         let x = k_pke_keygen();
//         //assert_eq!(x.0[0], 0);
//     }
//
//     #[test]
//     fn test_bytes_and_bits() {
//         let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
//
//         for _i in 0..100 {
//             let num_bytes = rng.gen::<u8>();
//             let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
//             let bits = bytes_to_bits(&bytes1);
//             let bytes2 = bits_to_bytes(&bits);
//             assert_eq!(bytes1, bytes2);
//         }
//     }
//
//     #[test]
//     fn test_decode_and_encode() {
//         let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
//
//         for _i in 0..100 {
//             let num_bytes = 32 * 11; //256;
//             let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
//             let integer_array = byte_decode::<11, 3329>(&bytes1);
//             let bytes2 =
//                 byte_encode::<11, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
//             assert_eq!(bytes1, bytes2);
//
//             let num_bytes = 32 * 10; //256;
//             let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
//             let integer_array = byte_decode::<10, 3329>(&bytes1);
//             let bytes2 =
//                 byte_encode::<10, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
//             assert_eq!(bytes1, bytes2);
//
//             let num_bytes = 32 * 5; //256;
//             let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
//             let integer_array = byte_decode::<5, 3329>(&bytes1);
//             let bytes2 =
//                 byte_encode::<5, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
//             assert_eq!(bytes1, bytes2);
//
//             let num_bytes = 32 * 4; //256;
//             let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
//             let integer_array = byte_decode::<4, 3329>(&bytes1);
//             let bytes2 =
//                 byte_encode::<4, 3329>(integer_array.try_into().expect("vec to array gone wrong"));
//             assert_eq!(bytes1, bytes2);
//         }
//     }
// }
