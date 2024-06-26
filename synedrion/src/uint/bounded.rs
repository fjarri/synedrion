use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeLess, CtOption},
    CheckedAdd, CheckedMul, HasWide, Integer, NonZero, Signed, UintLike,
};
use crate::tools::serde_bytes;

/// A packed representation for serializing Bounded objects.
/// Usually they have the bound much lower than the full size of the integer,
/// so this way we avoid serializing a bunch of zeros.
#[derive(Serialize, Deserialize)]
pub(crate) struct PackedBounded {
    bound: u32,
    #[serde(with = "serde_bytes::as_hex")]
    bytes: Box<[u8]>,
}

impl<T: UintLike> From<Bounded<T>> for PackedBounded {
    fn from(val: Bounded<T>) -> Self {
        let repr = val.as_ref().to_be_bytes();
        let bound_bytes = (val.bound() + 7) / 8;
        let slice = &repr.as_ref()[(repr.as_ref().len() - bound_bytes as usize)..];
        Self {
            bound: val.bound(),
            bytes: slice.into(),
        }
    }
}

impl<T: UintLike> TryFrom<PackedBounded> for Bounded<T> {
    type Error = String;
    fn try_from(val: PackedBounded) -> Result<Self, Self::Error> {
        let mut repr = T::ZERO.to_be_bytes();
        let bytes_len: usize = val.bytes.len();
        let repr_len: usize = repr.as_ref().len();

        if repr_len < bytes_len {
            return Err(format!(
                "The bytestring of length {} does not fit the expected integer size {}",
                bytes_len, repr_len
            ));
        }

        repr.as_mut()[(repr_len - bytes_len)..].copy_from_slice(&val.bytes);
        let abs_value = T::from_be_bytes(repr);

        Self::new(abs_value, val.bound)
            .ok_or_else(|| "Invalid values for the signed integer".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PackedBounded", into = "PackedBounded")]
pub struct Bounded<T: UintLike> {
    /// bound on the bit size of the value
    bound: u32,
    value: T,
}

impl<T: UintLike> Bounded<T> {
    pub fn bound(&self) -> u32 {
        self.bound
    }

    pub fn bound_usize(&self) -> usize {
        // Extracted into a method to localize the conversion
        self.bound as usize
    }

    pub fn new(value: T, bound: u32) -> Option<Self> {
        if bound > T::BITS as u32 || value.bits() as u32 > bound {
            return None;
        }
        Some(Self { value, bound })
    }

    pub fn add_mod(&self, rhs: &Self, modulus: &NonZero<T>) -> Self {
        // Note: assuming that the bit size of the modulus is not secret
        // (although the modulus itself might be)
        Self {
            value: self.value.add_mod(&rhs.value, modulus),
            bound: modulus.bits_vartime() as u32,
        }
    }

    pub fn into_signed(self) -> Option<Signed<T>> {
        Signed::new_positive(self.value, self.bound)
    }
}

impl<T: UintLike> AsRef<T> for Bounded<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T: UintLike + HasWide> Bounded<T> {
    pub fn into_wide(self) -> Bounded<T::Wide> {
        Bounded {
            value: self.value.into_wide(),
            bound: self.bound,
        }
    }

    pub fn mul_wide(&self, rhs: &Self) -> Bounded<T::Wide> {
        let result = self.value.mul_wide(&rhs.value);
        Bounded {
            value: result,
            bound: self.bound + rhs.bound,
        }
    }
}

impl<T: UintLike> CheckedAdd for Bounded<T> {
    type Output = Self;
    fn checked_add(&self, rhs: Self) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
        let in_range = bound.ct_lt(&(<T as Integer>::BITS as u32));

        let result = Self {
            bound,
            value: self.value.wrapping_add(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T: UintLike> CheckedMul for Bounded<T> {
    type Output = Self;
    fn checked_mul(&self, rhs: Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&(<T as Integer>::BITS as u32));

        let result = Self {
            bound,
            value: self.value.wrapping_mul(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T: UintLike> ConditionallySelectable for Bounded<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            bound: u32::conditional_select(&a.bound, &b.bound, choice),
            value: T::conditional_select(&a.value, &b.value, choice),
        }
    }
}
