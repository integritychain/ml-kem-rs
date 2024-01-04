use rand_core::CryptoRngCore;
#[cfg(feature = "default-rng")]
use rand_core::OsRng;

/// The `KeyGen` trait is defined to allow trait objects.
pub trait KeyGen {
    /// TKTK
    type EncapsKey;
    /// TKTK
    type DecapsKey;

    /// TKTK
    /// # Errors
    /// TKTK
    #[cfg(feature = "default-rng")]
    fn try_keygen_vt() -> Result<(Self::EncapsKey, Self::DecapsKey), &'static str> {
        Self::try_keygen_with_rng_vt(&mut OsRng)
    }

    /// TKTK
    /// # Errors
    /// TKTK
    fn try_keygen_with_rng_vt(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::EncapsKey, Self::DecapsKey), &'static str>;
}


/// TKTK
pub trait Encaps {
    /// TKTK
    type SharedSecretKey;
    /// TKTK
    type CipherText;

    /// TKTK
    /// # Errors
    /// TKTK
    #[cfg(feature = "default-rng")]
    fn try_encaps_vt(&self) -> Result<(Self::SharedSecretKey, Self::CipherText), &'static str> {
        self.try_encaps_with_rng_vt(&mut OsRng)
    }

    /// TKTK
    /// # Errors
    /// TKTK
    fn try_encaps_with_rng_vt(
        &self, rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SharedSecretKey, Self::CipherText), &'static str>;
}


/// TKTK
pub trait Decaps {
    /// TKTK
    type CipherText;
    /// TKTK
    type SharedSecretKey;

    /// TKTK
    /// # Errors
    /// TKTK
    fn try_decaps_vt(&self, ct: &Self::CipherText) -> Result<Self::SharedSecretKey, &'static str>;
}


/// TKTK
pub trait SerDes {
    /// TKTK
    type ByteArray;

    /// TKTK
    fn into_bytes(self) -> Self::ByteArray;

    /// TKTK
    /// # Errors
    /// TKTK
    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
