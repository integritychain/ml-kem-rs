use sha3::{Digest, Sha3_256, Sha3_512, Shake128};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::digest::Update;

/// Function H from line 746 on page 17
pub fn h(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    digest.into()
}

/// XOF
pub fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[i]);
    hasher.update(&[j]);
    let reader = hasher.finalize_xof();
    reader
}

// use rand::Rng;
//
/// Function G from line 746 on page 17
pub(crate) fn g(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&digest[0..32]);
    b.copy_from_slice(&digest[32..64]);
    (a, b)
}
//
// /// Function PRF on line 726 of page 16  TODO:hardcode N1 to 2
// fn prf<const N1: usize>(s: &[u8; 32], b: u8) -> [u8; 64 * 2] {
//     let mut hasher = Shake256::default();
//     hasher.update(s);
//     hasher.update(&[b]);
//     let mut reader = hasher.finalize_xof();
//     let mut result = [0u8; 64 * 2];
//     reader.read(&mut result);
//     result
// }