use crate::{k_pke::Z256, Q};

/// Algorithm 2 `BitsToBytes(b)` on page 17.
/// Converts a bit string (of length a multiple of eight) into an array of bytes.
pub fn bits_to_bytes(bit_array_b: &[u8], byte_array_b: &mut [u8]) {
    // Input: bit array b ∈ {0, 1}^{8·ℓ}
    // Output: byte array B ∈ B^ℓ
    debug_assert_eq!(bit_array_b.len() % 8, 0); // bit_array length is 8ℓ
    debug_assert_eq!(bit_array_b.len(), 8 * byte_array_b.len());
    // 1: B ← (0, . . . , 0)  (returned mutable data struct is provided by the caller)
    // 2: for (i ← 0; i < 8ℓ; i ++)
    for i in 0..bit_array_b.len() {
        // 3: B [⌊i/8⌋] ← B [⌊i/8⌋] + b[i] · 2^{i mod 8}
        byte_array_b[&i / 8] += &bit_array_b[i] * 2u8.pow(u32::try_from(i).expect("too many bits") % 8);
    } // 4: end for
    // 5: return B
}

/// Algorithm 3 `BytesToBits(B)` on page 18.
/// Performs the inverse of `BitsToBytes`, converting a byte array into a bit array.
pub fn bytes_to_bits(byte_array_b: &[u8], bit_array_b: &mut [u8]) {
    // Input: byte array B ∈ B^ℓ
    // Output: bit array b ∈ {0, 1}^{8·ℓ}
    debug_assert_eq!(bit_array_b.len() % 8, 0);
    debug_assert_eq!(byte_array_b.len() * 8, bit_array_b.len());
    // 1: for (i ← 0; i < ℓ; i ++)
    for i in 0..byte_array_b.len() {
        let mut byte = byte_array_b[i];
        // 2: for ( j ← 0; j < 8; j ++)
        for j in 0..8usize {
            // 3: b[8i + j] ← B[i] mod 2
            bit_array_b[8 * i + j] = byte % 2u8;
            // 4: B[i] ← ⌊B[i]/2⌋
            byte /= 2;
        } // 5: end for
    } // 6: end for
    // 7: return b
}

/// Algorithm 4 `ByteEncode<d>(F)` on page 19.
/// Encodes an array of d-bit integers into a byte array, for 1 ≤ d ≤ 12.
pub fn byte_encode<const D: usize, const D_256: usize>(integer_array_f: &[Z256; 256], byte_array_b: &mut [u8]) {
    // Input: integer array F ∈ Z^256_m, where m = 2^d if d < 12 and m = q if d = 12
    // Output: byte array B ∈ B^{32d}
    debug_assert!((1 <= D) & (D <= 12));
    debug_assert_eq!(D * 256, D_256);
    debug_assert_eq!(integer_array_f.len(), 256);
    debug_assert_eq!(byte_array_b.len(), 32 * D);
    let z_mod = if D < 12 {
        2_u16.pow(D as u32)
    } else {
        u16::try_from(Q).unwrap()
    };
    let mut bit_array = [0u8; D_256];
    // 1: for (i ← 0; i < 256; i ++)
    for i in 0..256 {
        // 2: a ← F[i]      ▷ a ∈ Z_{2^d}
        let mut a = integer_array_f[i].get_u16() % z_mod;
        // 3: for ( j ← 0; j < d; j ++)
        for j in 0..D {
            // 4: b[i · d + j] ← a mod 2        ▷ b ∈ {0, 1}^{256·d}
            bit_array[i * D + j] = (&a % 2) as u8;
            // 5: a ← (a − b[i · d + j])/2      ▷ note a − b[i · d + j] is always even.
            a = (a - u16::from(bit_array[i * D + j])) / 2;
        } // 6: end for
    } // 7: end for
    // 8: B ← BitsToBytes(b)
    bits_to_bytes(&bit_array, byte_array_b);
    // 9: return B
}

/// Algorithm 5 `ByteDecode<d>(B)` on page 19.
/// Decodes a byte array into an array of d-bit integers, for 1 ≤ d ≤ 12.
pub fn byte_decode<const D: usize, const D_256: usize>(byte_array_b: &[u8], integer_array_f: &mut [Z256; 256]) {
    // Input: byte array B ∈ B^{32d}
    // Output: integer array F ∈ Z^256_m, where m = 2^d if d < 12 and m = q if d = 12
    debug_assert!((1 <= D) & (D <= 12));
    debug_assert_eq!(D * 256, D_256);
    debug_assert_eq!(byte_array_b.len(), 32 * D);
    debug_assert_eq!(integer_array_f.len(), 256);
    let z_mod = if D < 12 {
        2_u16.pow(D as u32)
    } else {
        u16::try_from(Q).unwrap()
    };
    let mut bit_array = [0u8; D_256];
    // 1: b ← BytesToBits(B)
    bytes_to_bits(byte_array_b, &mut bit_array);
    // 2: for (i ← 0; i < 256; i ++)
    for i in 0..256 {
        // 3: F[i] ← ∑^{d-1}_{j=0} b[i · d + j] · 2 mod m
        integer_array_f[i] = (0..D).fold(Z256(0), |acc: Z256, j| {
            Z256(acc.get_u16() + u16::from(bit_array[i * D + j]) * 2_u16.pow(u32::try_from(j).unwrap()) % (z_mod))
            // TODO: yuk!
        });
    } // 4: end for
    // 5: return F
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use rand::{Rng, SeedableRng};

    use crate::byte_fns::{bits_to_bytes, byte_decode, byte_encode, bytes_to_bits};
    use crate::k_pke::Z256;

    #[test]
    fn test_bytes_and_bits() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);

        for _i in 0..100 {
            let num_bytes = rng.gen::<u8>();
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bits = vec![0u8; num_bytes as usize * 8];
            bytes_to_bits(&bytes1, &mut bits[..]);
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
            byte_decode::<11, { 11 * 256 }>(&bytes1, &mut integer_array);
            byte_encode::<11, 2816>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 10;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode::<10, 2560>(&bytes1, &mut integer_array);
            byte_encode::<10, 2560>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 5;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode::<5, 1280>(&bytes1, &mut integer_array);
            byte_encode::<5, 1280>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 4;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode::<4, 1024>(&bytes1, &mut integer_array);
            byte_encode::<4, 1024>(&integer_array, &mut bytes2);
            assert_eq!(bytes1, bytes2);
        }
    }
}
