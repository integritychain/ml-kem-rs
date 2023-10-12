#![deny(clippy::pedantic)]
#![deny(warnings)]
use zeroize::{Zeroize, ZeroizeOnDrop};
mod ml_kem;
mod auxiliary_algorithms;
mod k_pke;

pub const N: u32 = 11;
pub const Q: u32 = 12;
pub const SSK_LEN: usize = 32;

#[derive(Default, PartialEq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey([u8; SSK_LEN]);

macro_rules! functionality {
    () => {
        use zeroize::{Zeroize, ZeroizeOnDrop};

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct EncapsKey([u8; EK_LEN]);

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct DecapsKey([u8; DK_LEN]);

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct CipherText([u8; CT_LEN]);

        pub fn key_gen() -> (EncapsKey, DecapsKey) {
            let (mut ek, mut dk) = (EncapsKey::default(), DecapsKey::default());
            ml_kem::key_gen::<K>(K, ETA1, &mut ek.0, &mut dk.0);
            (ek, dk)
        }

        pub fn new_ek(bytes: [u8; EK_LEN]) -> EncapsKey {
            EncapsKey(bytes)
        }

        pub fn new_ct(bytes: [u8; CT_LEN]) -> CipherText {
            CipherText(bytes)
        }

        impl EncapsKey {
            fn default() -> Self {
                EncapsKey([0u8; EK_LEN])
            }
            pub fn encaps(&self) -> (SharedSecretKey, CipherText) {
                let (ek, mut ct) = (EncapsKey::default(), CipherText::default());
                let ssk = ml_kem::encaps(K, ETA1, ETA2, DU, DV, &ek.0, &mut ct.0);
                (ssk, ct)
            }
            pub fn to_bytes(&self) -> [u8; EK_LEN] {
                self.0.clone()
            }
        }

        impl DecapsKey {
            fn default() -> Self {
                DecapsKey([0u8; DK_LEN])
            }
            pub fn decaps(&self, ct: &CipherText) -> SharedSecretKey {
                ml_kem::decaps(K, DU, DV, &self.0, &ct.0)
            }
        }

        impl CipherText {
            fn default() -> Self {
                CipherText([0u8; CT_LEN])
            }
            pub fn to_bytes(&self) -> [u8; CT_LEN] {
                self.0.clone()
            }
        }
    };
}

pub mod ml_kem_512 {
    use crate::{ml_kem, SharedSecretKey};

    const K: usize = 2;
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const EK_LEN: usize = 800;
    const DK_LEN: usize = 1632;
    const CT_LEN: usize = 768;

    functionality!();
}

pub mod ml_kem_768 {
    use crate::{ml_kem, SharedSecretKey};

    const K: usize = 3;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const EK_LEN: usize = 1184;
    const DK_LEN: usize = 2400;
    const CT_LEN: usize = 1088;

    functionality!();
}

pub mod ml_kem_1024 {
    use crate::{ml_kem, SharedSecretKey};

    const K: usize = 4;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 11;
    const DV: u32 = 5;
    const EK_LEN: usize = 1568;
    const DK_LEN: usize = 3168;
    const CT_LEN: usize = 1568;

    functionality!();
}
