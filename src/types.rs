use generic_array::{ArrayLength, GenericArray};
use zeroize::{Zeroize, ZeroizeOnDrop};

// using structs gives opportunity for auto-zeroization; internal privace
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey {
    v: [u8; 32],
}

impl SharedSecretKey {
    pub fn get_bytes(ssk: SharedSecretKey) -> [u8; 32] {
        ssk.v
    }
}

///////////////////////////////////////////////////////////////////////////////
// ML-KEM-512 keys and ciphertext

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncapsulationKey<N: ArrayLength>(GenericArray<u8, N>);

trait KeyGen {
    type EK_LEN: ArrayLength;
    //const DkLen: ArrayLength<>;
    fn key_gen() -> EncapsulationKey<Self::EK_LEN>;
}

// impl<N> EncapsulationKey<N> {
//     pub fn new(slice: &[u8]) -> EncapsulationKey<{ N }> {
//         assert_eq!(slice.len(), N, "Incorrect input slice length");
//         let mut ek = EncapsulationKey([0u8; N]);
//         ek.0.copy_from_slice(slice);
//         ek
//     }
//     pub fn get_bytes(ek: EncapsulationKey<N>) -> [u8; N] {
//         ek.0
//     }
// }

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey512 {
    v: [u8; 1632],
}

impl DecapsulationKey512 {
    pub fn new(slice: &[u8]) -> DecapsulationKey512 {
        assert_eq!(slice.len(), 1632, "Incorrect input slice length");
        let mut dk = DecapsulationKey512 { v: [0u8; 1632] };
        dk.v.copy_from_slice(slice);
        dk
    }
    pub fn get_bytes(dk: DecapsulationKey512) -> [u8; 1632] {
        dk.v
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherText512 {
    v: [u8; 768],
}

impl CipherText512 {
    pub fn new(slice: &[u8]) -> CipherText512 {
        assert_eq!(slice.len(), 768, "Incorrect input slice length");
        let mut dk = CipherText512 { v: [0u8; 768] };
        dk.v.copy_from_slice(slice);
        dk
    }
}

///////////////////////////////////////////////////////////////////////////////
// ML-KEM-768 keys and ciphertext

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncapsulationKey768 {
    v: [u8; 1184],
}

impl EncapsulationKey768 {
    pub fn new(slice: &[u8]) -> EncapsulationKey768 {
        assert_eq!(slice.len(), 1184, "Incorrect input slice length");
        let mut ek = EncapsulationKey768 { v: [0u8; 1184] };
        ek.v.copy_from_slice(slice);
        ek
    }
    pub fn get_bytes(ek: EncapsulationKey768) -> [u8; 1184] {
        ek.v
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey768 {
    v: [u8; 2400],
}

impl DecapsulationKey768 {
    pub fn new(slice: &[u8]) -> DecapsulationKey768 {
        assert_eq!(slice.len(), 2400, "Incorrect input slice length");
        let mut dk = DecapsulationKey768 { v: [0u8; 2400] };
        dk.v.copy_from_slice(slice);
        dk
    }
    pub fn get_bytes(dk: DecapsulationKey768) -> [u8; 2400] {
        dk.v
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherText768 {
    v: [u8; 1088],
}

impl CipherText768 {
    pub fn new(slice: &[u8]) -> CipherText768 {
        assert_eq!(slice.len(), 1088, "Incorrect input slice length");
        let mut dk = CipherText768 { v: [0u8; 1088] };
        dk.v.copy_from_slice(slice);
        dk
    }
}
