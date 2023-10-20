use std::convert::{TryFrom, TryInto};

use crate::{k_pke::Z256, Q};

/// Implements <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>

/// Algorithm 2 `BitsToBytes(b)` near line 760 of page 17
///
/// # Panics
/// Will panic if input bit array length is not a multiple of 8 or length does not fit within `u32`
pub fn bits_to_bytes(bit_array: &[u8], byte_array: &mut [u8]) {
    for i in 0..bit_array.len() {
        byte_array[&i / 8] += &bit_array[i] * 2u8.pow(u32::try_from(i).expect("too many bits") % 8);
    }
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
            bit_array[8 * i + j] = byte % 2u8;
            byte /= 2;
        }
    }
    bit_array
}

/// Algorithm 4 `ByteEncode<d>(F)` near line 774 of page 18-19
/// # Panics
/// Will panic if D is outside of 1..12
pub fn byte_encode<const D: u32>(integer_array: &[Z256; 256], byte_array: &mut [u8]) {
    assert!((1 <= D) & (D <= 12));
    assert_eq!(byte_array.len(), 32 * D as usize);
    let m: u32 = if D < 12 { 2_u32.pow(D) } else { Q };
    let mut bit_array = vec![0u8; 256 * D as usize]; // TODO: remove vec
    for i in 0..256 {
        let mut a = integer_array[i].get_u16() % u16::try_from(m).unwrap();
        for j in 0..(D as usize) {
            bit_array[i * (D as usize) + j] = (&a % 2) as u8;
            a = (a - u16::from(bit_array[i * (D as usize) + j])) / 2;
        }
    }
    bits_to_bytes(&bit_array, byte_array);
}

/// Algorithm 5 `ByteDecode<d>(F)` near line 774 of page 18-19
/// # Panics
/// Will panic if D is outside of 1..12, or if `byte_array` length is not 32*D
#[allow(dead_code)]
pub fn byte_decode<const D: usize>(byte_array: &[u8], integer_array: &mut [Z256]) {
    assert!((1 <= D) & (D <= 12));
    assert_eq!(byte_array.len(), 32 * D);
    let m: u32 = if D < 12 {
        2_u32.pow(D.try_into().unwrap())
    } else {
        Q
    };
    let bit_array = bytes_to_bits(byte_array);
    for i in 0..256 {
        integer_array[i] = (0..D).fold(Z256(0), |acc: Z256, j| {
            Z256(
                acc.get_u16()
                    + u16::from(bit_array[i * D + j]) * 2_u16.pow(u32::try_from(j).unwrap())
                    % (u16::try_from(m).unwrap()),
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use crate::byte_fns::{bits_to_bytes, byte_decode, byte_encode, bytes_to_bits};
    use crate::k_pke::Z256;

    #[test]
    fn test_bytes_and_bits() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);

        for _i in 0..100 {
            let num_bytes = rng.gen::<u8>();
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let bits = bytes_to_bits(&bytes1);
            let mut bytes2 = vec![0u8; num_bytes as usize];
            bits_to_bytes(&bits, &mut bytes2[..]);
            assert_eq!(bytes1, bytes2);
        }
    }

    #[test]
    fn test_decode_and_encode() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let mut integer_array = [Z256(0); 256];
        for _i in 0..100 {
            let num_bytes = 32 * 11;
            let mut bytes2 = vec![0u8; num_bytes];
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            byte_decode::<11>(&bytes1, &mut integer_array);
            byte_encode::<11>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 10;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode::<10>(&bytes1, &mut integer_array);
            byte_encode::<10>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 5;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode::<5>(&bytes1, &mut integer_array);
            byte_encode::<5>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 4;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode::<4>(&bytes1, &mut integer_array);
            byte_encode::<4>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);
        }
    }
}
