#![deny(clippy::pedantic)]
#![deny(warnings)]
#![doc = include_str!("../README.md")]

use zeroize::{Zeroize, ZeroizeOnDrop};

mod byte_fns;
mod helpers;
mod k_pke;
mod ml_kem;
mod ntt;

const _N: u32 = 256;
const Q: u32 = 3329;
const SSK_LEN: usize = 32;

#[derive(Default, PartialEq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey([u8; SSK_LEN]);

macro_rules! functionality {
    () => {
        const ETA1_64: usize = ETA1 * 64;
        const ETA2_64: usize = ETA2 * 64;
        const DU_8: usize = DU * 256;
        const DU_256: usize = DU * 256;
        const DV_8: usize = DV * 256;
        const DV_256: usize = DV * 256;

        use zeroize::{Zeroize, ZeroizeOnDrop};

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct EncapsKey([u8; EK_LEN]);

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct DecapsKey([u8; DK_LEN]);

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct CipherText([u8; CT_LEN]);

        #[must_use]
        pub fn key_gen() -> (EncapsKey, DecapsKey) {
            let (mut ek, mut dk) = (EncapsKey::default(), DecapsKey::default());
            ml_kem::key_gen::<K, ETA1, ETA1_64>(&mut ek.0, &mut dk.0);
            (ek, dk)
        }

        #[must_use]
        pub fn new_ek(bytes: [u8; EK_LEN]) -> EncapsKey {
            EncapsKey(bytes)
        }

        #[must_use]
        pub fn new_ct(bytes: [u8; CT_LEN]) -> CipherText {
            CipherText(bytes)
        }

        impl EncapsKey {
            fn default() -> Self {
                EncapsKey([0u8; EK_LEN])
            }

            #[must_use]
            pub fn encaps(&self) -> (SharedSecretKey, CipherText) {
                let (ek, mut ct) = (EncapsKey::default(), CipherText::default());
                let ssk = ml_kem::encaps::<K, ETA1, ETA1_64, ETA2, ETA2_64, DU, DU_256, DV, DV_256>(&ek.0, &mut ct.0);
                (ssk, ct)
            }

            #[must_use]
            pub fn to_bytes(&self) -> [u8; EK_LEN] {
                self.0.clone()
            }
        }

        impl DecapsKey {
            fn default() -> Self {
                DecapsKey([0u8; DK_LEN])
            }

            #[must_use]
            pub fn decaps(&self, ct: &CipherText) -> SharedSecretKey {
                ml_kem::decaps::<K, ETA1, ETA1_64, ETA2, ETA2_64, DU, DU_8, DU_256, DV, DV_8, DV_256>(&self.0, &ct.0)
            }
        }

        impl CipherText {
            fn default() -> Self {
                CipherText([0u8; CT_LEN])
            }

            #[must_use]
            pub fn to_bytes(&self) -> [u8; CT_LEN] {
                self.0.clone()
            }
        }
    };
}

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
