use crate::ntt::Z256;
use std::convert::{TryFrom, TryInto};

/// Implements <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>

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

/// Algorithm 4 `ByteEncode<d>(F)` near line 774 of page 18-19
/// # Panics
/// Will panic if D is outside of 1..12
#[must_use]
pub fn byte_encode<const D: u32, const Q: u32>(integer_array: &[Z256; 256]) -> Vec<u8> {
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
