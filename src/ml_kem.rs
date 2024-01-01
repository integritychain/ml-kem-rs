use rand_core::CryptoRngCore;

use crate::byte_fns::{byte_decode, byte_encode};
use crate::helpers::{ensure, g, h, j};
use crate::k_pke::k_pke_decrypt;
use crate::SharedSecretKey;
use crate::types::Z256;

use super::k_pke::{k_pke_encrypt, k_pke_key_gen};

/// Algorithm 15 `ML-KEM.KeyGen()` on page 29.
/// Generates an encapsulation key and a corresponding decapsulation key.
pub(crate) fn ml_kem_key_gen<
    const K: usize,
    const ETA1: usize,
    const ETA1_64: usize,
    const ETA1_512: usize,
>(
    rng: &mut impl CryptoRngCore, ek: &mut [u8], dk: &mut [u8],
) -> Result<(), &'static str> {
    // Output: Encapsulation key ek ∈ B^{384k+32}
    // Output: Decapsulation key dk ∈ B^{768k+96}
    ensure!(ek.len() == 384 * K + 32, "TKTK");
    ensure!(dk.len() == 768 * K + 96, "TKTK");

    // 1: z ←− B32         ▷ z is 32 random bytes (see Section 3.3)
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut z);

    // 2: (ek_{PKE}, dk_{PKE}) ← K-PKE.KeyGen()     ▷ run key generation for K-PKE
    let p1 = 384 * K;
    k_pke_key_gen::<K, ETA1, ETA1_64, ETA1_512>(rng, ek, &mut dk[..p1])?; // 3: ek ← ekPKE

    // 4: dk ← (dkPKE ∥ek∥H(ek)∥z)  (first concat element is done above alongside ek)
    let h_ek = h(ek);
    let p2 = p1 + ek.len();
    let p3 = p2 + h_ek.len();
    dk[p1..p2].copy_from_slice(ek);
    dk[p2..p3].copy_from_slice(&h_ek);
    dk[p3..].copy_from_slice(&z);

    // 5: return (ek, dk)
    Ok(())
}


/// Algorithm 16 `ML-KEM.Encaps(ek)` on page 30.
/// Uses the encapsulation key to generate a shared key and an associated ciphertext.
pub(crate) fn ml_kem_encaps<
    const K: usize,
    const ETA1: usize,
    const ETA1_64: usize,
    const ETA1_512: usize,
    const ETA2: usize,
    const ETA2_64: usize,
    const ETA2_512: usize,
    const DU: usize,
    const DU_256: usize,
    const DV: usize,
    const DV_256: usize,
>(
    rng: &mut impl CryptoRngCore, ek: &[u8], ct: &mut [u8],
) -> Result<SharedSecretKey, &'static str> {
    // Validated input: encapsulation key ek ∈ B^{384k+32}
    // Output: shared key K ∈ B^{32}
    // Output: ciphertext c ∈ B^{32(du k+dv)}
    ensure!(ek.len() == 384 * K + 32, "TKTK"); // type check: array of length 384k + 32

    // modulus check: perform the computation ek ← ByteEncode12 (ByteDecode12(ek_tidle)
    // note: after checking, we run with the original input (due to const array allocation); the last 32 bytes is rho  // TODO: revisit
    let mut ek_hat = [Z256(0); 256];
    for i in 0..K {
        let mut ek_tilde = [0u8; 384];
        byte_decode::<12, { 12 * 256 }>(&ek[384 * i..384 * (i + 1)], &mut ek_hat)?;
        byte_encode::<12, { 384 * 8 }>(&ek_hat, &mut ek_tilde)?;
        ensure!(ek_tilde == ek[384 * i..384 * (i + 1)], "TKTK");
    }

    // 1: m ←− B32          ▷ m is 32 random bytes (see Section 3.3)
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m); //random::<[u8; 32]>();

    // 2: (K, r) ← G(m∥H(ek))       ▷ derive shared secret key K and randomness r
    let h_ek = h(ek);
    let mut g_input = [0u8; 64];
    g_input[0..32].copy_from_slice(&m);
    g_input[32..64].copy_from_slice(&h_ek);
    let (k, r) = g(&g_input);

    // 3: 3: c ← K-PKE.Encrypt(ek, m, r)        ▷ encrypt m using K-PKE with randomness r
    k_pke_encrypt::<K, ETA1, ETA1_64, ETA1_512, ETA2, ETA2_64, ETA2_512, DU, DU_256, DV, DV_256>(
        ek, &m, &r, ct,
    )?;

    // 4: return (K, c)  (note: ct is mutable input)
    Ok(SharedSecretKey(k))
}


/// Algorithm 17 `ML-KEM.Decaps(c, dk)` on page 32.
/// Uses the decapsulation key to produce a shared key from a ciphertext.
#[allow(clippy::similar_names)]
pub(crate) fn ml_kem_decaps<
    const K: usize,
    const ETA1: usize,
    const ETA1_64: usize,
    const ETA1_512: usize,
    const ETA2: usize,
    const ETA2_64: usize,
    const ETA2_512: usize,
    const DU: usize,
    const DU_256: usize,
    const DV: usize,
    const DV_256: usize,
    const J_LEN: usize,
    const CT_LEN: usize,
>(
    dk: &[u8], ct: &[u8],
) -> Result<SharedSecretKey, &'static str> {
    // Validated input: ciphertext c ∈ B^{32(du k+dv )}
    // Validated input: decapsulation key dk ∈ B^{768k+96}
    // Output: shared key K ∈ B^{32}
    // These length checks are a bit redundant...but present for completeness and paranoia
    ensure!(ct.len() == 32 * (DU * K + DV), "TKTK");
    // Ciphertext type check
    ensure!(dk.len() == 768 * K + 96, "TKTK"); // Decapsulation key type check

    // 1019 For some applications, further validation of the decapsulation key dk_tilde may be appropriate. For
    // 1020 instance, in cases where dk_tilde was generated by a third party, users may want to ensure that the four
    // 1021 components of dk_tilde have the correct relationship with each other, as in line 4 of ML-KEM.KeyGen.
    // 1022 In all cases, implementers shall validate the inputs to ML-KEM.Decaps in a manner that is
    // 1023 appropriate for their application.
    // NOTE: The decaps key is an opaque struct to the user of this library and has no serialization/deserialization
    // functionality. This limits the amount of validation that is appropriate/necessary.

    // 1: dkPKE ← dk[0 : 384k]              ▷ extract (from KEM decaps key) the PKE decryption key
    let dk_pke = &dk[0..384 * K];

    // 2: ekPKE ← dk[384k : 768k + 32]      ▷ extract PKE encryption key
    let ek_pke = &dk[384 * K..768 * K + 32];

    // 3: h ← dk[768k + 32 : 768k + 64]     ▷ extract hash of PKE encryption key
    let h = &dk[768 * K + 32..768 * K + 64];

    // 4: z ← dk[768k + 64 : 768k + 96]     ▷ extract implicit rejection value
    let z = &dk[768 * K + 64..768 * K + 96];

    // 5: m′ ← K-PKE.Decrypt(dkPKE,c)
    let m_prime = k_pke_decrypt::<K, DU, DU_256, DV, DV_256>(dk_pke, ct)?;

    // 6: (K′, r′) ← G(m′ ∥ h)
    let mut g_input = [0u8; 32 + 32];
    g_input[0..32].copy_from_slice(&m_prime);
    g_input[32..64].copy_from_slice(h);
    let (mut k_prime, r_prime) = g(&g_input);

    // 7: K̄ ← J(z∥c, 32)
    let mut j_input = [0u8; J_LEN];
    debug_assert_eq!(j_input.len(), 32 + ct.len());
    j_input[0..32].copy_from_slice(z);
    j_input[32..32 + ct.len()].copy_from_slice(ct);
    let k_bar = j(&j_input);

    // 8: c′ ← K-PKE.Encrypt(ekPKE , m′ , r′ )      ▷ re-encrypt using the derived randomness r′
    let mut c_prime = [0u8; CT_LEN];
    k_pke_encrypt::<K, ETA1, ETA1_64, ETA1_512, ETA2, ETA2_64, ETA2_512, DU, DU_256, DV, DV_256>(
        ek_pke,
        &m_prime,
        &r_prime,
        &mut c_prime[0..ct.len()],
    )?;
    if *ct != c_prime[0..ct.len()] {
        k_prime = k_bar;
    };

    Ok(SharedSecretKey(k_prime))
}
