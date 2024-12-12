use core::ops::BitAnd;

use crypto_bigint::{subtle::Choice, Bounded, Integer, Monty, NonZero};
use zeroize::Zeroize;

use super::{HasWide, SecretSigned};
use crate::tools::Secret;

/// A bounded integer with sensitive data.
#[derive(Debug, Clone)]
pub(crate) struct SecretBounded<T: Zeroize> {
    /// bound on the bit size of the value
    bound: u32,
    value: Secret<T>,
}

impl<T> SecretBounded<T>
where
    T: Zeroize + Integer + Bounded,
{
    pub fn is_zero(&self) -> Choice {
        self.value.expose_secret().is_zero()
    }

    pub fn bound(&self) -> u32 {
        self.bound
    }

    /// Creates a new [`Bounded`] wrapper around `T`, restricted to `bound`.
    ///
    /// Returns `None` if the bound is invalid, i.e.:
    /// - The bound is bigger than a `T` can represent.
    /// - The value of `T` is too big to be bounded by the provided bound.
    pub fn new(value: T, bound: u32) -> Option<Self> {
        if bound > T::BITS || value.bits() > bound {
            return None;
        }
        Some(Self {
            value: Secret::init_with(|| value),
            bound,
        })
    }

    pub fn add_mod(&self, rhs: &Self, modulus: &Secret<NonZero<T>>) -> Self {
        // Note: assuming that the bit size of the modulus is not secret
        // (although the modulus itself might be)
        Self {
            value: Secret::init_with(|| {
                self.value
                    .expose_secret()
                    .add_mod(rhs.value.expose_secret(), modulus.expose_secret())
            }),
            bound: modulus.expose_secret().bits_vartime(),
        }
    }

    pub fn to_signed(&self) -> Option<SecretSigned<T>> {
        SecretSigned::new_positive(self.value.expose_secret().clone(), self.bound)
    }

    pub fn expose_secret(&self) -> &T {
        self.value.expose_secret()
    }
}

impl<T> BitAnd<T> for SecretBounded<T>
where
    T: Zeroize + Bounded + Integer,
{
    type Output = Self;
    fn bitand(self, rhs: T) -> Self::Output {
        Self {
            value: Secret::init_with(|| {
                let mut result = self.value.expose_secret().clone();
                result &= rhs;
                result
            }),
            bound: self.bound,
        }
    }
}

impl<T> SecretBounded<T>
where
    T: Zeroize + Bounded + Integer<Monty: Zeroize>,
{
    pub fn to_montgomery(&self, params: &<T::Monty as Monty>::Params) -> Secret<T::Monty> {
        Secret::init_with(|| <T::Monty as Monty>::new(self.expose_secret().clone(), params.clone()))
    }
}

impl<T> SecretBounded<T>
where
    T: Zeroize + HasWide + Integer + Bounded,
    T::Wide: Zeroize + Integer + Bounded,
{
    pub fn mul_wide(&self, rhs: &T) -> SecretBounded<T::Wide> {
        SecretBounded::new(
            self.value.expose_secret().mul_wide(rhs),
            self.bound + rhs.bits_vartime(),
        )
        .expect("The call to new_positive cannot fail when the input is the absolute value ")
    }
}

impl<T> SecretBounded<T>
where
    T: Zeroize + Clone + HasWide,
    T::Wide: Zeroize,
{
    pub fn to_wide(&self) -> SecretBounded<T::Wide> {
        SecretBounded {
            value: self.value.to_wide(),
            bound: self.bound,
        }
    }
}
