use zeroize::{Zeroize, ZeroizeOnDrop};

const SSK_LEN: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey([u8; SSK_LEN]);


pub mod ml_kem_512 {
    use crate::types3::{ml_kem_key_gen, SharedSecretKey, SSK_LEN};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    const N: u32 = 256;
    const Q: u32 = 3329;
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const EK_LEN: usize = 800;
    const DK_LEN: usize = 1632;
    const CT_LEN: usize = 768;

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct EncapsKey([u8; EK_LEN]);

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct DecapsKey([u8; DK_LEN]);

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct CipherText([u8; CT_LEN]);

    pub fn key_gen() -> (EncapsKey, DecapsKey) {
        let mut ek = [0u8; EK_LEN];
        let mut dk = [0u8; DK_LEN];
        ml_kem_key_gen::<{ 384 * K + 32 }, ETA1>(&mut ek, &mut dk);
        (EncapsKey([0u8; EK_LEN]), DecapsKey([0u8; DK_LEN]))
    }

    impl EncapsKey {
        pub fn encaps(&self) -> (SharedSecretKey, CipherText) {
            (SharedSecretKey([0u8; SSK_LEN]), CipherText([0u8; CT_LEN]))
        }
        pub fn new(bytes: &[u8]) -> Self {
            assert_eq!(bytes.len(), EK_LEN);
            let mut result = Self([0u8; EK_LEN]);
            result.0.copy_from_slice(bytes);
            result
        }
        pub fn to_bytes(self) -> [u8; EK_LEN] {
            self.0.clone()
        }

    }

    impl DecapsKey {
        pub fn decaps(&self, ct: CipherText) -> SharedSecretKey {
            SharedSecretKey([0u8; SSK_LEN])
        }
    }

    impl CipherText {
        pub fn new(bytes: &[u8]) -> Self {
            assert_eq!(bytes.len(), CT_LEN);
            let mut result = Self([0u8; CT_LEN]);
            result.0.copy_from_slice(bytes);
            result
        }
        pub fn to_bytes(self) -> [u8; CT_LEN] {
            self.0.clone()
        }
    }
}

fn ml_kem_key_gen<const K: usize, const ETA1: usize>(ek: &mut [u8], dk: &mut [u8]) {
    assert_eq!(ek.len(), 384 * K + 32);
    assert_eq!(dk.len(), 384 * K);
    ek.copy_from_slice(&[0u8; K]); //384 * K + 32]);  // TODO: NEEEEED   VEC !!!
    dk.copy_from_slice(&[0u8; K])
}



pub mod ml_kem_768 {
    pub struct EncapsKey([u8; 1184]);
    pub struct DecapsKey([u8; 2400]);
    pub struct CipherText([u8; 1088]);

    pub fn key_gen() -> (EncapsKey, DecapsKey) {
        (EncapsKey([0u8; 1184]), DecapsKey([0u8; 2400]))
    }

}

