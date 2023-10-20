use rand::random;

use crate::{SharedSecretKey, SSK_LEN};
use crate::aux_fns::g;

use super::aux_fns::h;
use super::k_pke::{k_pke_encrypt, k_pke_key_gen};

pub(crate) fn key_gen<const K: usize, const ETA1: usize, const ETA1_64: usize>(ek: &mut [u8], dk: &mut [u8]) {
    debug_assert_eq!(ek.len(), 384 * K + 32);
    debug_assert_eq!(dk.len(), 768 * K + 96);
    let z = random::<[u8; 32]>();
    let p1 = 384 * K; // size of dk_pke
    k_pke_key_gen::<K, ETA1, ETA1_64>(ek, &mut dk[..p1]);
    let h_ek = h(ek);
    let p2 = p1 + ek.len();
    let p3 = p2 + h_ek.len();
    dk[p1..p2].copy_from_slice(ek);
    dk[p2..p3].copy_from_slice(&h_ek);
    dk[p3..].copy_from_slice(&z);
}

pub(crate) fn encaps<
    const K: usize,
    const ETA1: usize,
    const ETA1_64: usize,
    const ETA2: usize,
    const ETA2_64: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &[u8], ct: &mut [u8],
) -> SharedSecretKey {
    let m = random::<[u8; 32]>();
    let h_ek = h(ek);
    let mut g_input = [0u8; 64];
    g_input[0..32].copy_from_slice(&m);
    g_input[32..64].copy_from_slice(&h_ek);
    let (k, r) = g(&g_input);
    k_pke_encrypt::<K, ETA1, ETA1_64, ETA2, ETA2_64, DU, DV>(ek, &m, &r, ct);
    assert_eq!(ct[0], 99);
    SharedSecretKey(k)
}

pub(crate) fn decaps(_k: usize, _du: usize, _dv: usize, _dk: &[u8], _ct: &[u8]) -> SharedSecretKey {
    SharedSecretKey([55u8; SSK_LEN])
}
