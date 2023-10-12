use crate::{SharedSecretKey, SSK_LEN};

pub(crate) fn key_gen(_k: u32, _eta1: u32, ek: &mut [u8], dk: &mut [u8]) {
    for item in ek.iter_mut() {
        *item = 11
    }
    for item in dk.iter_mut() {
        *item = 22
    }
}

pub(crate) fn encaps(
    _k: u32,
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

pub(crate) fn decaps(_k: u32, _du: u32, _dv: u32, _dk: &[u8], _ct: &[u8]) -> SharedSecretKey {
    SharedSecretKey([55u8; SSK_LEN])
}
