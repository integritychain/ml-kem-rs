#![no_std]
#![deny(clippy::pedantic)]
#![deny(warnings)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

/// Implements FIPS 203 draft Module-Lattice-based Key-Encapsulation Mechanism Standard.
/// See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>

// TODO
//   3. Implement bench
//   4. Fix github actions
//   5. Review main Doc; features: no_std, no alloc, minimal dependencies, CT
//   6. Git push to CC, publish as 0.1.1
//   7. Re-read spec
#[cfg(test)]
extern crate alloc;

// Supports automatically clearing sensitive data on drop
use zeroize::{Zeroize, ZeroizeOnDrop};

// Functionality map per FIPS 203 draft
//
// Algorithm 2 BitsToBytes(b) on page 17                    --> byte_fns.rs
// Algorithm 3 BytesToBits(B) on page 18                    --> byte_fns.rs
// Algorithm 4 ByteEncoded(F) on page 19                    --> byte_fns.rs
// Algorithm 5 ByteDecoded(B) on page 19                    --> byte_fns.rs
// Algorithm 6 SampleNTT(B) on page 20                      --> sampling.rs
// Algorithm 7 SamplePolyCBDη(B) on page 20                 --> sampling.rs
// Algorithm 8 NTT(f) on page 22                            --> ntt.rs
// Algorithm 9 NTT−1(fˆ) on page 23                         --> ntt.rs
// Algorithm 10 MultiplyNTTs(fˆ,ĝ) on page 24               --> ntt.rs
// Algorithm 11 BaseCaseMultiply(a0,a1,b0,b1,γ) on page 24  --> ntt.rs
// Algorithm 12 K-PKE.KeyGen() on page 26                   --> k_pke.rs
// Algorithm 13 K-PKE.Encrypt(ekPKE,m,r) on page 27         --> k_pke.rs
// Algorithm 14 K-PKE.Decrypt(dkPKE,c) on page 28           --> k_pke.rs
// Algorithm 15 ML-KEM.KeyGen() on page 29                  --> ml_kem.rs
// Algorithm 16 ML-KEM.Encaps(ek) on page 30                --> ml_ke.rs
// Algorithm 17 ML-KEM.Decaps(c,dk) on page 32              --> ml_kem.rs
// PRF and XOF on page 16                                   --> helpers.rs
// Three has functions: G, H, J on page 17                  --> helpers.rs
// Compress and Decompress on page 18                       --> helpers.rs
//
// The three parameter sets are modules in this file with macro code that
// connects them into the functionality in ml_kem.rs

mod byte_fns;
mod helpers;
mod k_pke;
mod ml_kem;
mod ntt;
mod sampling;
mod types;

#[cfg(test)]
mod smoke_test;

// Relevant to all parameter sets
const _N: u32 = 256;
const Q: u32 = 3329;
const ZETA: u32 = 17;
const SSK_LEN: usize = 32;

// Relevant to all parameter sets
/// The (opaque) secret key that can be deserialized by each party.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey([u8; SSK_LEN]);

impl SharedSecretKey {
    #[must_use]
    /// The `to_bytes` function deserializes an encapsulation key into a byte array.
    pub fn to_bytes(&self) -> [u8; SSK_LEN] { self.0 }
}

// Conservative (constant-time) paranoia...
impl PartialEq for SharedSecretKey {
    fn eq(&self, other: &Self) -> bool {
        let mut result = true;
        for i in 0..self.0.len() {
            result &= self.0[i] == other.0[i];
        }
        result
    }
}


// This common functionality is injected into each parameter set module
macro_rules! functionality {
    () => {
        const ETA1_64: usize = ETA1 * 64; // Currently, Rust does not allow expressions involving
        const ETA1_512: usize = ETA1 * 512; // constants in type expressions such as [u8, ETA1 * 64].
        const ETA2_64: usize = ETA2 * 64; // So this is handled manually...what a pain
        const ETA2_512: usize = ETA2 * 512; // TODO: consider a single 'global scratch pad' buffer
        const DU_256: usize = DU * 256;
        const DV_256: usize = DV * 256;
        const J_LEN: usize = 32 + 32 * (DU * K + DV);

        use rand::random;
        use zeroize::{Zeroize, ZeroizeOnDrop};

        /// Correctly sized encapsulation key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct EncapsKey([u8; EK_LEN]);

        /// Correctly sized decapsulation key specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct DecapsKey([u8; DK_LEN]);

        /// Correctly sized ciphertext specific to the target parameter set.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct CipherText([u8; CT_LEN]);

        /// Per FIPS 203, the key generation algorithm ML-KEM.KeyGen for ML-KEM (Algorithm 15)
        /// accepts no input, utilizes randomness, and produces an encapsulation key and a
        /// decapsulation key. While the encapsulation key can be made public, the decapsulation key
        /// must remain private. This outputs of this function are opaque structs specific to a
        /// target parameter set.
        #[must_use]
        pub fn key_gen() -> (EncapsKey, DecapsKey) {
            let (mut ek, mut dk) = (EncapsKey::default(), DecapsKey::default());
            let random_z = random::<[u8; 32]>();
            let random_d = random::<[u8; 32]>();
            ml_kem::ml_kem_key_gen::<K, ETA1, ETA1_64, ETA1_512>(
                &random_z, &random_d, &mut ek.0, &mut dk.0,
            );
            (ek, dk)
        }

        /// Test only access to seed
        #[must_use]
        #[cfg(test)]
        pub fn key_gen_test(seed: &[u8; 32]) -> (EncapsKey, DecapsKey) {
            let (mut ek, mut dk) = (EncapsKey::default(), DecapsKey::default());
            ml_kem::ml_kem_key_gen::<K, ETA1, ETA1_64, ETA1_512>(&seed, &seed, &mut ek.0, &mut dk.0);
            (ek, dk)
        }

        /// The `new_ek` function deserializes a byte array of the correct length into an
        /// encapsulation key. The correct length of the input byte array is specific to a target
        /// parameter set and the output is an opaque struct.
        #[must_use]
        pub fn new_ek(bytes: [u8; EK_LEN]) -> EncapsKey { EncapsKey(bytes) }

        /// The `new_ct` function deserializes a byte array of the correct length into an opaque
        /// cipher text value. The correct length of the input byte array is specific to a target
        /// parameter set and the output is an opaque struct.
        #[must_use]
        pub fn new_ct(bytes: [u8; CT_LEN]) -> CipherText { CipherText(bytes) }

        impl EncapsKey {
            fn default() -> Self { EncapsKey([0u8; EK_LEN]) }

            /// Per FIPS 203, the encapsulation algorithm ML-KEM.Encaps of ML-KEM (Algorithm 16)
            /// accepts an encapsulation key as input, requires randomness, and outputs a ciphertext
            /// and a shared key. The inputs and outputs to this function are opaque structs
            /// specific to a target parameter set.
            #[must_use]
            pub fn encaps(&self) -> (SharedSecretKey, CipherText) {
                let mut ct = CipherText::default();
                let random_m = random::<[u8; 32]>();
                let ssk = ml_kem::ml_kem_encaps::<
                    K,
                    ETA1,
                    ETA1_64,
                    ETA1_512,
                    ETA2,
                    ETA2_64,
                    ETA2_512,
                    DU,
                    DU_256,
                    DV,
                    DV_256,
                >(&random_m, &self.0, &mut ct.0);
                (ssk, ct)
            }

            /// Test only access to seed
            #[must_use]
            pub fn encaps_test(&self, seed: &[u8; 32]) -> (SharedSecretKey, CipherText) {
                let mut ct = CipherText::default();
                let ssk = ml_kem::ml_kem_encaps::<
                    K,
                    ETA1,
                    ETA1_64,
                    ETA1_512,
                    ETA2,
                    ETA2_64,
                    ETA2_512,
                    DU,
                    DU_256,
                    DV,
                    DV_256,
                >(&seed, &self.0, &mut ct.0);
                (ssk, ct)
            }

            #[must_use]
            /// The `to_bytes` function deserializes an encapsulation key into a byte array.
            pub fn to_bytes(&self) -> [u8; EK_LEN] { self.0.clone() }
        }


        impl DecapsKey {
            fn default() -> Self { DecapsKey([0u8; DK_LEN]) }

            #[must_use]
            /// Per FIPS 203, the decapsulation algorithm ML-KEM.Decaps of ML-KEM (Algorithm 16)
            /// accepts a decapsulation key and a ML-KEM ciphertext as input, does not use any
            /// randomness, and outputs a shared secret. The inputs and outputs to this function are
            /// opaque structs specific to a target parameter set.
            pub fn decaps(&self, ct: &CipherText) -> SharedSecretKey {
                ml_kem::ml_kem_decaps::<
                    K,
                    ETA1,
                    ETA1_64,
                    ETA1_512,
                    ETA2,
                    ETA2_64,
                    ETA2_512,
                    DU,
                    DU_256,
                    DV,
                    DV_256,
                    J_LEN,
                    CT_LEN
                >(&self.0, &ct.0)
            }

            /// The `to_bytes` function deserializes a cipher text into a byte array.
            #[must_use]
            #[cfg(test)]
            pub fn to_bytes_test(&self) -> [u8; DK_LEN] { self.0.clone() }
        }


        impl CipherText {
            fn default() -> Self { CipherText([0u8; CT_LEN]) }

            /// The `to_bytes` function deserializes a cipher text into a byte array.
            #[must_use]
            pub fn to_bytes(&self) -> [u8; CT_LEN] { self.0.clone() }
        }
    };
}


///  ML-KEM-512 is claimed to be in security category 1, see table 2 & 3 on page 33.
#[cfg(feature = "ml_kem_512")]
pub mod ml_kem_512 {
    use crate::{ml_kem, SharedSecretKey};

    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const EK_LEN: usize = 800;
    const DK_LEN: usize = 1632;
    const CT_LEN: usize = 768;

    functionality!();
}


/// ML-KEM-768 is claimed to be in security category 3, see table 2 & 3 on page 33.
#[cfg(feature = "ml_kem_768")]
pub mod ml_kem_768 {
    use crate::{ml_kem, SharedSecretKey};

    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const EK_LEN: usize = 1184;
    const DK_LEN: usize = 2400;
    const CT_LEN: usize = 1088;

    functionality!();
}


/// ML-KEM-1024 is claimed to be in security category 5, see table 2 & 3 on page 33.
#[cfg(feature = "ml_kem_1024")]
pub mod ml_kem_1024 {
    use crate::{ml_kem, SharedSecretKey};

    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
    const EK_LEN: usize = 1568;
    const DK_LEN: usize = 3168;
    const CT_LEN: usize = 1568;

    functionality!();
}
