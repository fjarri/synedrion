use crypto_bigint::{
    modular::MontyForm,
    nlimbs,
    subtle::{ConditionallySelectable, CtOption},
    Bounded, ConcatMixed, Encoding, Integer, Invert, PowBoundedExp, RandomMod, SplitMixed, WideningMul, Zero, U1024,
    U2048, U4096, U512, U8192,
};
use zeroize::Zeroize;

use crate::uint::{PublicBounded, PublicSigned, SecretBounded, SecretSigned};

pub trait ToMontgomery: Integer {
    fn to_montgomery(
        self,
        params: &<<Self as Integer>::Monty as crypto_bigint::Monty>::Params,
    ) -> <Self as Integer>::Monty {
        <<Self as Integer>::Monty as crypto_bigint::Monty>::new(self, params.clone())
    }
}

pub trait Exponentiable<Exponent> {
    fn pow(&self, exp: &Exponent) -> Self;
}

impl<T, V> Exponentiable<SecretSigned<V>> for T
where
    T: ConditionallySelectable + PowBoundedExp<V> + Invert<Output = CtOption<T>>,
    V: ConditionallySelectable + Zeroize + Integer + Bounded,
{
    fn pow(&self, exp: &SecretSigned<V>) -> Self {
        let abs_exp = exp.abs();
        let abs_result = self.pow_bounded_exp(abs_exp.expose_secret(), exp.bound());
        let inv_result = abs_result.invert().expect("`self` is assumed to be invertible");
        Self::conditional_select(&abs_result, &inv_result, exp.is_negative())
    }
}

impl<T, V> Exponentiable<SecretBounded<V>> for T
where
    T: PowBoundedExp<V> + Invert<Output = CtOption<T>>,
    V: ConditionallySelectable + Zeroize + Integer + Bounded,
{
    fn pow(&self, exp: &SecretBounded<V>) -> Self {
        self.pow_bounded_exp(exp.expose_secret(), exp.bound())
    }
}

impl<T, V> Exponentiable<PublicSigned<V>> for T
where
    T: PowBoundedExp<V> + Invert<Output = CtOption<T>>,
    V: Integer + Bounded,
{
    fn pow(&self, exp: &PublicSigned<V>) -> Self {
        let abs_exp = exp.abs();
        let abs_result = self.pow_bounded_exp(&abs_exp, exp.bound());
        if exp.is_negative() {
            abs_result.invert().expect("`self` is assumed invertible")
        } else {
            abs_result
        }
    }
}

impl<T, V> Exponentiable<PublicBounded<V>> for T
where
    T: PowBoundedExp<V> + Invert<Output = CtOption<T>>,
    V: Integer + Bounded,
{
    fn pow(&self, exp: &PublicBounded<V>) -> Self {
        self.pow_bounded_exp(exp.as_ref(), exp.bound())
    }
}

pub trait HasWide:
    Sized + Zero + Integer + for<'a> WideningMul<&'a Self, Output = Self::Wide> + ConcatMixed<MixedOutput = Self::Wide>
{
    type Wide: Integer + Encoding + RandomMod + SplitMixed<Self, Self>;

    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }

    /// Converts `self` to a new `Wide` uint, setting the higher half to `0`s.
    fn to_wide(&self) -> Self::Wide {
        // Note that this minimizes the presense of `self` on the stack (to the extent we can ensure it),
        // in case it is secret.
        Self::concat_mixed(self, &Self::zero())
    }

    /// Splits a `Wide` in two halves and returns the halves (`Self` sized) in a
    /// tuple (lower half first).
    fn from_wide(value: &Self::Wide) -> (Self, Self) {
        value.split_mixed()
    }

    /// Tries to convert a `Wide` into a `Self` sized uint. Splits a `Wide`
    /// value in two halves and returns the lower half if the high half is zero.
    /// Otherwise returns `None`.
    fn try_from_wide(value: &Self::Wide) -> Option<Self> {
        let (lo, hi) = Self::from_wide(value);
        if hi.is_zero().into() {
            return Some(lo);
        }
        None
    }
}

impl HasWide for U512 {
    type Wide = U1024;
}

impl HasWide for U1024 {
    type Wide = U2048;
}

impl HasWide for U2048 {
    type Wide = U4096;
}

impl HasWide for U4096 {
    type Wide = U8192;
}

pub type U512Mod = MontyForm<{ nlimbs!(512) }>;
pub type U1024Mod = MontyForm<{ nlimbs!(1024) }>;
pub type U2048Mod = MontyForm<{ nlimbs!(2048) }>;
pub type U4096Mod = MontyForm<{ nlimbs!(4096) }>;

impl ToMontgomery for U512 {}
impl ToMontgomery for U1024 {}
impl ToMontgomery for U2048 {}
impl ToMontgomery for U4096 {}
impl ToMontgomery for U8192 {}
