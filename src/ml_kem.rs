use rand::Rng;
use crate::{SharedSecretKey, SSK_LEN};
use super::auxiliary_algorithms::h;
use super::k_pke::k_pke_key_gen;

pub(crate) fn key_gen<const K: usize>(k: usize, _eta1: u32, ek: &mut [u8], dk: &mut [u8]) {
    debug_assert_eq!(ek.len(), 384 * k + 32);
    debug_assert_eq!(dk.len(), 768 * k + 96);
    let z = rand::thread_rng().gen::<[u8; 32]>();
    k_pke_key_gen::<K>(ek, dk);
    let h_ek = h(ek);
    let p1 = (384*k) as usize;
    let p2 = p1 + ek.len();
    let p3 = p2 + h_ek.len();
    dk[p1..p2].copy_from_slice(ek);
    dk[p2..p3].copy_from_slice(&h(ek));
    dk[p3..].copy_from_slice(&z);
}

pub(crate) fn encaps(
    _k: usize,
    _eta1: u32,
    _eta2: u32,
    _du: u32,
    _dv: u32,
    _ek: &[u8],
    ct: &mut [u8],
) -> SharedSecretKey {
    for item in ct.iter_mut() {
        *item = 33
    }
    SharedSecretKey([44u8; SSK_LEN])
}

pub(crate) fn decaps(_k: usize, _du: u32, _dv: u32, _dk: &[u8], _ct: &[u8]) -> SharedSecretKey {
    SharedSecretKey([55u8; SSK_LEN])
}
