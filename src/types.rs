use crate::Q;

// While Z256 is nice, simple and correct, the performance is atrocious.
// This will be addressed (particularly in matrix operations etc).

/// Stored as u16, but arithmetic as u32 (so we can multiply/reduce/etc)
#[derive(Clone, Copy)]
pub struct Z256(pub u16);

impl Z256 {
    pub fn get_u32(self) -> u32 { u32::from(self.0) }

    pub fn get_u16(self) -> u16 { self.0 }

    pub fn set_u16(&mut self, a: u32) {
        //debug_assert!(a < Q); //u32::from(u16::MAX));
        self.0 = u16::try_from(a % Q).unwrap(); // TODO: Revisit
    }

    #[allow(dead_code)] // Barrett mult/reduce; Will be incorporated shortly...
    pub fn mul(self, other: Self) -> Self {
        let prod = u64::from(self.0) * u64::from(other.0);
        let div = prod * (2u64.pow(24) / (u64::from(Q)));
        let (diff, borrow) = div.overflowing_sub(u64::from(Q));
        let result = if borrow { div } else { diff }; // TODO: CT MUX
        Self(u16::try_from(result).unwrap()) // TODO: Revisit
    }
}
