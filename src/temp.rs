// struct EncapsulationKey<N: ArrayLength> {
//     data: GenericArray<u8, N>
// }

// struct Foo<const N: usize> {
//     data: [u8; N],
// }

use crate::old_lib::k_pke_keygen;

pub trait MlKem {
    const K: u32;
    const ETA1: u32;
    const ETA2: u32;
    const DU: u32;
    const DV: u32;
    const EK_LEN: usize;
    const DK_LEN: usize;
    const CT_LEN: usize;
    const SSK_LEN: usize;

    type Ek;
    type Dk;
    type Ct;
    type Ssk;
    fn key_gen() -> (Self::Ek, Self::Dk);
    fn encaps(ek: Self::Ek) -> (Self::Ssk, Self::Ct);
    fn decaps(dk: Self::Dk, ct: Self::Ct) -> Self::Ssk;
}

struct MlKem512 {}

//impl MlKem512 for dyn MlKem<Dk=[u8; 1632], Ek=[u8; 800]> {
impl MlKem for MlKem512 {
    const K: u32 = 2;
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const EK_LEN: usize = 800;
    const DK_LEN: usize = 1632;
    const CT_LEN: usize = 768;
    const SSK_LEN: usize = 32;

    type Ek = [u8; Self::EK_LEN];
    type Dk = [u8; Self::DK_LEN];
    type Ct = [u8; Self::CT_LEN];
    type Ssk = [u8; Self::SSK_LEN];

    fn key_gen() -> (Self::Ek, Self::Dk) {
        let (ek_pke, dk_pke) = k_pke_keygen();
        let mut dk = [0; Self::DK_LEN];
        dk[0..dk_pke.len()].copy_from_slice(&dk_pke);
        (ek_pke, dk)
    }
    fn encaps(_ek: Self::Ek) -> (Self::Ssk, Self::Ct) {
        todo!()
    }
    fn decaps(_dk: Self::Dk, _ct: Self::Ct) -> Self::Ssk {
        todo!()
    }
}

// trait Bar {
//     const LEN: usize;
//
//     // Error: cannot perform const operation using `Self`
//     fn bar(&self) -> Foo<{ Self::LEN }>;
// }

// KenGen() k n1

// Encrypt() k du dv n1 n2

// Decrypt() k du dv

// Narrative:
// Alice calls 1 of 3 keyGen functions. they return differently sized (ek, dk) keys specific to algorithm; she passes ek to Bob
// Then using the encryption key ek, Bob calls Encaps function which returns fixed sized shared secret and differently sized ciphertext ct
// Then using the decryption key dk and ciphertext, Alice calls Decaps function returns shared secret

// So, first Alice calls
//            TODO <------------ should we make ML-KEM-512 look like a namespace
//            TODO <------------ should we make 512, 768, 1024 look like a parameter to a single KeyGen
//   - ML-KEM-512.KeyGen()   -> ek512, dk512
//   - ML-KEM-768.KeyGen()   -> ek768, dk768
//   - ML-KEM-1024.KeyGen()  -> ek1012, dk1024

// Then, Bob calls
//   - ek512.Encaps()        -> SSK, ct512
//   - ek768.Encaps()        -> SSK, ct768
//   - ek1024.Encaps()       -> SSK, ct1024

// Finally, Alice calls
//   - dk512.Decaps(ct512)   -> SSK
//   - dk768.Decaps(ct768)   -> SSK
//   - dk1024.Decaps(ct1024) -> SSK
