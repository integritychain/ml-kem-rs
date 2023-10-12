use generic_array::typenum::{Sum, U384, U1024, U2048, U800, U832, P800, P832, P100, P132, UInt, UTerm, B0, B1, ToUInt, Const};
use generic_array::{ArrayLength, GenericArray};
use typenum::op;
use zeroize::{Zeroize, ZeroizeOnDrop};

//use typenum::generic_const_mappings::ToUInt;
//pub type U3072 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>, B0>, B0>, B0>, B0>, B0>, B0>, B0>, B0>;
// impl ToUInt for Const<3072> {
//     type Output = U3072;
// }

type U3072 = op!(U1024 + U2048);
// TODO:
//   1. aim to get ser-deser correct (challenge: variable types)
//   2. have a test run for top-level functions (challenge: crystallizes traits etc)
//   3. and connect those functions to lower-level routines (challenge: exposes ETA1, ETA2 etc)

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey([u8; 32]);
impl SharedSecretKey {
    pub fn get_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncapsulationKey<N: ArrayLength>(GenericArray<u8, N>);

impl<N: ArrayLength> EncapsulationKey<N> {
    pub fn get_bytes(self) -> GenericArray<u8, N> {
        self.0.clone()
    }

    fn new(bytes: &[u8]) -> Self {
        let mut result = Self(GenericArray::default());
        assert_eq!(bytes.len(), result.0.len());
        result.0.copy_from_slice(bytes);
        result
    }
}

// Decapsulation keys never need to be serialized or deserialized
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey<N: ArrayLength>(GenericArray<u8, N>);

//#[test]
impl<N: ArrayLength> DecapsulationKey<N> {
    //#[test]
    pub fn get_bytes(self) -> GenericArray<u8, N> {
        self.0.clone()
    }

    //#[test]
    fn new(bytes: &[u8]) -> Self {
        let mut result = Self(GenericArray::default());
        assert_eq!(bytes.len(), result.0.len());
        result.0.copy_from_slice(bytes);
        result
    }
}


//#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherText<N: ArrayLength>(GenericArray<u8, N>);
impl<N: ArrayLength> CipherText<N> {
    pub fn get_bytes(self) -> GenericArray<u8, N> {
        self.0.clone()
    }

    fn new(bytes: &[u8]) -> Self {
        let mut result = Self(GenericArray::default());
        assert_eq!(bytes.len(), result.0.len());
        result.0.copy_from_slice(bytes);
        result
    }
}

pub trait KeyGen {
    type EK_LEN: ArrayLength;
    type DK_LEN: ArrayLength;
    fn key_gen() -> (EncapsulationKey<Self::EK_LEN>, DecapsulationKey<Self::DK_LEN>);
}

pub struct MlKem512asdf();

impl MlKem512asdf {
    pub fn new_encapsulation_key(bytes: &[u8]) -> EncapsulationKey<U800> {
        EncapsulationKey::new(bytes)
    }
}

impl KeyGen for MlKem512asdf {
    type EK_LEN = U800;
    type DK_LEN = U3072;
    //Sum<U800, U832>;

    fn key_gen() -> (EncapsulationKey<Self::EK_LEN>, DecapsulationKey<Self::DK_LEN>) {
        (EncapsulationKey::<Self::EK_LEN>(GenericArray::default()),
        DecapsulationKey::<Self::DK_LEN>(GenericArray::default()))
    }
}

pub struct MlKem768asdf();

impl KeyGen for MlKem768asdf {
    type EK_LEN = Sum<U800, U384>;
    type DK_LEN = Sum<U800, Sum<U800, U800>>;

    fn key_gen() -> (EncapsulationKey<Self::EK_LEN>, DecapsulationKey<Self::DK_LEN>) {
        (EncapsulationKey::<Self::EK_LEN>(GenericArray::default()),
         DecapsulationKey::<Self::DK_LEN>(GenericArray::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_deser() {
        let x = MlKem512asdf::key_gen();
        //assert_eq!(x.0[0], 0);
        let mut buf = [0u8; 800];
        let jimmy = x.get_bytes(&mut buf);
        assert_eq!(buf[0], 0);
    }
}
