use crate::{helpers, Q, ZETA};
use crate::helpers::{bit_rev_7, pow_mod_q};
use crate::types::Z256;

/// Algorithm 8 `NTT(f)` on page 22.
/// Computes the NTT representation f_hat of the given polynomial f ∈ R_q.
#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn ntt(array_f: &[Z256; 256]) -> [Z256; 256] {
    // Input: array f ∈ Z^{256}_q           ▷ the coeffcients of the input polynomial
    // Output: array f_hat ∈ Z^{256}_q      ▷ the coeffcients of the NTT of the input polynomial
    // 1: f_hat ← f                         ▷ will compute NTT in-place on a copy of input array
    let mut f_hat = [Z256(0); 256];
    f_hat.copy_from_slice(array_f);

    // 2: k ← 1
    let mut k = 1;

    // 3: for (len ← 128; len ≥ 2; len ← len/2)
    for len in [128, 64, 32, 16, 8, 4, 2] {
        // 4: for (start ← 0; start < 256; start ← start + 2 · len)
        for start in (0..256).step_by(2 * len) {
            // 5: zeta ← ζ^{BitRev7 (k)} mod q
            let zeta = pow_mod_q(ZETA, bit_rev_7(k));

            // 6: k ← k+1
            k += 1;

            // 7: for ( j ← start; j < start + len; j ++)
            for j in start..(start + len) {
                // 8: t ← zeta · f_hat[ j + len]           ▷ steps 8-10 done modulo q
                let t = zeta * f_hat[j + len].get_u32() % Q;

                // 9: f_hat[ j + len] ← f_hat [ j] − t
                f_hat[j + len].set_u16((Q + f_hat[j].get_u32() - t) % Q);

                // 10: f_hat[ j] ← f_hat[ j] + t
                f_hat[j].set_u16((f_hat[j].get_u32() + t) % Q);
            } // 11: end for
        } // 12: end for
    } // 13: end for

    f_hat // 14: return f_hat
}


/// Algorithm 9 `NTTinv(f)` on page 23.
/// Computes the polynomial f ∈ R_q corresponding to the given NTT representation f_hat ∈ T_q.
#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn ntt_inv(f_hat: &[Z256; 256]) -> [Z256; 256] {
    // Input: array f_hat ∈ Z^{256}     ▷ the coeffcients of input NTT representation
    // Output: array f ∈ Z^{256}        ▷ the coeffcients of the inverse-NTT of the input

    // 1: f ← f_hat                     ▷ will compute in-place on a copy of input array
    let mut f: [Z256; 256] = [Z256(0); 256];
    f.copy_from_slice(f_hat);

    // 2: k ← 127
    let mut k = 127;

    // 3: for (len ← 2; len ≤ 128; len ← 2 · len)
    for len in [2, 4, 8, 16, 32, 64, 128] {
        //
        // 4: for (start ← 0; start < 256; start ← start + 2 · len)
        for start in (0..256).step_by(2 * len) {
            //
            // 5: zeta ← ζ^{BitRev7(k)} mod q
            let zeta = helpers::pow_mod_q(ZETA, helpers::bit_rev_7(k));

            // 6: k ← k − 1
            k -= 1;

            // 7: for ( j ← start; j < start + len; j ++)
            for j in start..(start + len) {
                //
                // 8: t ← f [ j]
                let t = f[j];

                // 9: f [ j] ← t + f [ j + len]         ▷ steps 9-10 done modulo q
                f[j].set_u16((t.get_u32() + f[j + len].get_u32()) % Q);

                // 10: f [ j + len] ← zeta · ( f [ j + len] − t)
                f[j + len].set_u16((zeta * (Q + f[j + len].get_u32() - t.get_u32())) % Q);
            } // 11: end for
        } // 12: end for
    } // 13: end for
    // 14: f ← f · 3303 mod q                   ▷ multiply every entry by 3303 ≡ 128^{−1} mod q
    f.iter_mut()
        .for_each(|item| item.set_u16(item.get_u32() * 3303 % Q));

    // 15: return f
    f
}


/// Algorithm 10 `MultiplyNTTs(f, g)` on page 24.
/// Computes the product (in the ring Tq ) of two NTT representations.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn multiply_ntts(f_hat: &[Z256; 256], g_hat: &[Z256; 256]) -> [Z256; 256] {
    // Input: Two arrays f_hat ∈ Z^{256}_q and g_hat ∈ Z^{256}_q        ▷ the coeffcients of two NTT representations
    // Output: An array h_hat ∈ Z^{256}_q                               ▷ the coeffcients of the product of the inputs
    let mut h_hat: [Z256; 256] = [Z256(0); 256];

    // for (i ← 0; i < 128; i ++)
    for i in 0..128 {
        // 2: (h_hat[2i], h_hat[2i + 1]) ← BaseCaseMultiply( f_hat[2i], f_hat[2i + 1], g_hat[2i], g_hat[2i + 1], ζ^{2BitRev7(i) + 1})
        let (h_hat_2i, h_hat_2ip1) = base_case_multiply(
            f_hat[2 * i],
            f_hat[2 * i + 1],
            g_hat[2 * i],
            g_hat[2 * i + 1],
            Z256(helpers::pow_mod_q(ZETA, 2 * helpers::bit_rev_7(u8::try_from(i).unwrap()) + 1)
                as u16),
        );
        h_hat[2 * i] = h_hat_2i;
        h_hat[2 * i + 1] = h_hat_2ip1;
    } // 3: end for

    h_hat // 4: return h_hat
}


/// Algorithm 11 `BaseCaseMultiply(a0, a1, b0, b1, gamma)` on page 24.
/// Computes the product of two degree-one polynomials with respect to a quadratic modulus.
#[must_use]
pub fn base_case_multiply(a0: Z256, a1: Z256, b0: Z256, b1: Z256, gamma: Z256) -> (Z256, Z256) {
    // Input: a0 , a1 , b0 , b1 ∈ Z_q               ▷ the coefficients of a0 + a1 X and b0 + b1 X
    // Input: γ ∈ Z_q                               ▷ the modulus is X^2 − γ
    // Output: c0 , c1 ∈ Z_q                        ▷ the coeffcients of the product of the two polynomials
    // 1: c0 ← a0 · b0 + a1 · b1 · γ                ▷ steps 1-2 done modulo q
    let c0 = Z256(
        ((a0.get_u32() * b0.get_u32() + (a1.get_u32() * b1.get_u32() % Q) * gamma.get_u32()) % Q)
            as u16,
    );

    // 2: 2: c1 ← a0 · b1 + a1 · b0
    let c1 = Z256(((a0.get_u32() * b1.get_u32() + a1.get_u32() * b0.get_u32()) % Q) as u16);

    // 3: return c0 , c1
    (c0, c1)
}
