use core::ops::{Add, Mul, Neg, Sub};

use crypto_bigint::{
    rand_core::CryptoRngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeLess, CtOption},
    zeroize::Zeroize,
    BitOps, Bounded, CheckedAdd, CheckedMul, Integer, NonZero, RandomMod, ShlVartime, WrappingAdd, WrappingMul,
    WrappingNeg, WrappingSub,
};

use super::{HasWide, PublicSigned, SecretBounded};
use crate::tools::Secret;

/// A wrapper over secret unsigned integers that treats two's complement numbers as negative.
#[derive(Debug, Clone)]
pub(crate) struct SecretSigned<T: Zeroize> {
    /// bound on the bit size of the absolute value (that is, `abs(value) < 2^bound`)
    bound: u32,
    value: Secret<T>,
}

impl<T> SecretSigned<T>
where
    T: Zeroize + Bounded + Integer,
{
    /// Creates a signed value from an unsigned one,
    /// assuming that it encodes a positive value.
    pub fn new_positive(value: T, bound: u32) -> Option<Self> {
        // Reserving one bit as the sign bit (MSB)
        if bound >= T::BITS || value.bits() > bound {
            return None;
        }
        let result = Self {
            value: Secret::init_with(|| value),
            bound,
        };
        if result.is_negative().into() {
            return None;
        }
        Some(result)
    }

    pub fn zero() -> Self {
        Self {
            value: Secret::init_with(|| T::zero()),
            bound: 0,
        }
    }

    /// Returns a truthy `Choice` if this number is negative.
    pub fn is_negative(&self) -> Choice {
        // Check the MSB, `1` indicates that it is negative.
        Choice::from(self.value.expose_secret().bit_vartime(T::BITS - 1) as u8)
    }

    pub fn bound(&self) -> u32 {
        self.bound
    }

    pub fn to_public(&self) -> PublicSigned<T> {
        PublicSigned::new_from_unsigned(self.value.expose_secret().clone(), self.bound).expect("the bound is valid")
    }

    /// Performs the unary `-` operation.
    pub fn neg(&self) -> Self {
        Self {
            value: self.value.wrapping_neg(),
            bound: self.bound,
        }
    }

    fn checked_sub(&self, rhs: &Self) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound()) + 1;
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: self.value.wrapping_sub(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedAdd<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_add(&self, rhs: &SecretSigned<T>) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: self.value.wrapping_add(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedAdd<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_add(&self, rhs: &PublicSigned<T>) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound()) + 1;
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: Secret::init_with(|| self.value.expose_secret().wrapping_add(rhs.value())),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedMul<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_mul(&self, rhs: &SecretSigned<T>) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: self.value.wrapping_mul(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedMul<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_mul(&self, rhs: &PublicSigned<T>) -> CtOption<Self> {
        let bound = self.bound + rhs.bound();
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: Secret::init_with(|| self.value.expose_secret().wrapping_mul(rhs.value())),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> SecretSigned<T>
where
    T: ConditionallySelectable + Zeroize + Bounded + Integer,
{
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            bound: u32::conditional_select(&a.bound, &b.bound, choice),
            value: Secret::<T>::conditional_select(&a.value, &b.value, choice),
        }
    }

    /// Computes the absolute value of [`self`]
    pub fn abs(&self) -> SecretBounded<T> {
        SecretBounded::new(
            T::conditional_select(
                self.value.expose_secret(),
                self.value.wrapping_neg().expose_secret(),
                self.is_negative(),
            ),
            self.bound,
        )
        .expect("the absolute value is within the same bound")
    }

    /// Creates a signed value from an unsigned one,
    /// treating it as if the sign is encoded in the MSB.
    pub fn new_from_unsigned(value: T, bound: u32) -> Option<Self> {
        // TODO: handle secrets
        let is_negative = Choice::from(value.bit_vartime(T::BITS - 1) as u8);
        let abs = T::conditional_select(&value, &value.wrapping_neg(), is_negative);
        if bound >= T::BITS || abs.bits() > bound {
            return None;
        }
        Some(Self {
            value: Secret::init_with(|| value),
            bound,
        })
    }

    /// Creates a signed value from an unsigned one, treating it as if it is the absolute value.
    /// Returns `None` if `abs_value` is actually negative or if the bounds are invalid.
    fn new_from_abs(abs_value: T, bound: u32, is_negative: Choice) -> Option<Self> {
        Self::new_from_unsigned(
            T::conditional_select(&abs_value, &abs_value.wrapping_neg(), is_negative),
            bound,
        )
    }

    /// Asserts that the absolute value is within the bit bound `bound`.
    /// If that is the case, returns the value with the bound set to it.
    pub fn assert_bit_bound(&self, bound: u32) -> Option<Self> {
        let abs = self.abs();
        let mask = T::one().wrapping_neg().wrapping_shl_vartime(bound);
        let masked = abs & mask;
        if masked.is_zero().into() {
            Some(Self {
                value: self.value.clone(),
                bound,
            })
        } else {
            None
        }
    }

    /// Asserts that the value is within the interval the paper denotes as $\pm 2^bound$.
    /// Panics if it is not the case.
    ///
    /// That is, the value must be within $[-2^{bound}, 2^{bound}]$
    /// (See Section 2).
    pub fn assert_bound(&self, bound: u32) {
        assert!(self.assert_bit_bound(bound).is_some(), "out of bounds $\\pm 2^{bound}$",)
    }
}

impl<T> SecretSigned<T>
where
    T: ConditionallySelectable + Zeroize + Bounded + Integer + RandomMod,
{
    // Returns a random value in range `[-bound, bound]`.
    //
    // Note: variable time in bit size of `bound`.
    fn random_bounded(rng: &mut impl CryptoRngCore, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(
            bound_bits < T::BITS,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );
        // Will not overflow because of the assertion above
        let positive_bound = bound
            .as_ref()
            .overflowing_shl_vartime(1)
            .expect("Just asserted that bound is smaller than precision; qed")
            .checked_add(&T::one())
            .expect("Checked bounds above");
        let positive_result = T::random_mod(
            rng,
            &NonZero::new(positive_bound).expect("the bound is non-zero by construction"),
        );
        // Will not panic because of the assertion above
        Self::new_from_unsigned(positive_result.wrapping_sub(bound.as_ref()), bound_bits)
            .expect("bounded by `bound_bits` by construction")
    }

    /// Returns a random value in range `[-2^bound_bits, 2^bound_bits]`.
    ///
    /// Note: variable time in `bound_bits`.
    pub fn random_bounded_bits(rng: &mut impl CryptoRngCore, bound_bits: u32) -> Self {
        assert!(
            bound_bits < T::BITS - 1,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );

        let bound = NonZero::new(T::one() << bound_bits).expect("Checked bound_bits just above; qed");
        Self::random_bounded(rng, &bound)
    }
}

impl<T> Neg for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        SecretSigned::neg(&self)
    }
}

impl<T> Neg for &SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;
    fn neg(self) -> Self::Output {
        SecretSigned::neg(self)
    }
}

impl<T> SecretSigned<T>
where
    T: Zeroize + Bounded + HasWide + Integer,
    T::Wide: Zeroize + RandomMod,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and bit size of `scale`.
    pub fn random_bounded_bits_scaled(
        rng: &mut impl CryptoRngCore,
        bound_bits: u32,
        scale: &T,
    ) -> SecretSigned<T::Wide> {
        assert!(
            bound_bits < T::BITS - 1,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );
        let scaled_bound: <T as HasWide>::Wide = scale
            .to_wide()
            .overflowing_shl_vartime(bound_bits)
            .expect("Just asserted that bound bits is smaller than T's bit precision");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect(concat![
                "`scaled_bound` is double the size of a T; we asserted that the `bound_bits` ",
                "will not cause overflow in T ⇒ it's safe to left-shift 1 step ",
                "(aka multiply by 2)."
            ])
            .checked_add(&T::Wide::one())
            .expect(concat![
                "`scaled_bound` is double the size of a T; we asserted that the `bound_bits` ",
                "will not cause overflow in T ⇒ it's safe to add 1."
            ]);
        let positive_result = T::Wide::random_mod(
            rng,
            &NonZero::new(positive_bound)
                .expect("Input guaranteed to be positive and it's non-zero because we added 1"),
        );
        let result = positive_result.wrapping_sub(&scaled_bound);

        SecretSigned {
            bound: bound_bits + scale.bits_vartime(),
            value: Secret::init_with(|| result),
        }
    }
}

impl<T> SecretSigned<T>
where
    T: ConditionallySelectable + Zeroize + Bounded + HasWide + Integer,
    T::Wide: Zeroize + ConditionallySelectable + Bounded,
{
    /// Returns a [`SecretSigned`] with the same value, but twice the bit-width.
    /// Consumes `self`, but under the hood this method clones.
    pub fn to_wide(&self) -> SecretSigned<T::Wide> {
        let abs_result = self.abs().expose_secret().to_wide();
        SecretSigned::new_from_abs(abs_result, self.bound(), self.is_negative())
            .expect("the value fit the bound before, and the bound won't overflow for `WideUint`")
    }

    /// Multiplies two [`SecretSigned`] and returns a new [`SecretSigned`] of twice the bit-width
    pub fn mul_wide(&self, rhs: &PublicSigned<T>) -> SecretSigned<T::Wide> {
        let abs_value = self.abs().expose_secret().mul_wide(&rhs.abs());
        SecretSigned::new_from_abs(
            abs_value,
            self.bound() + rhs.bound(),
            self.is_negative() ^ Choice::from(rhs.is_negative() as u8),
        )
        .expect("The call to new_positive cannot fail when the input is the absolute value ")
    }
}

impl<T> SecretSigned<T>
where
    T: Zeroize + Bounded + HasWide + Integer,
    T::Wide: Zeroize + ConditionallySelectable + Bounded + HasWide + Integer,
    <T::Wide as HasWide>::Wide: Zeroize,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and `scale`.
    pub fn random_bounded_bits_scaled_wide(
        rng: &mut impl CryptoRngCore,
        bound_bits: u32,
        scale: &T::Wide,
    ) -> SecretSigned<<T::Wide as HasWide>::Wide> {
        assert!(
            bound_bits < T::BITS - 1,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );
        let scaled_bound = scale
            .to_wide()
            .overflowing_shl_vartime(bound_bits)
            .expect("Just asserted that bound_bits is smaller than bit precision of T");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect(concat![
                "`scaled_bound` is double the size of a T::Wide; we asserted that the `bound_bits` ",
                "will not cause overflow in T::Wide ⇒ it's safe to left-shift 1 step ",
                "(aka multiply by 2)."
            ])
            .checked_add(&<T::Wide as HasWide>::Wide::one())
            .expect(concat![
                "`scaled_bound` is double the size of a T::Wide; we asserted that the `bound_bits` ",
                "will not cause overflow in T::Wide ⇒ it's safe to add 1."
            ]);
        let positive_result = <T::Wide as HasWide>::Wide::random_mod(
            rng,
            &NonZero::new(positive_bound)
                .expect("Input guaranteed to be positive and it's non-zero because we added 1"),
        );
        let result = positive_result.wrapping_sub(&scaled_bound);

        SecretSigned {
            bound: bound_bits + scale.bits_vartime(),
            value: Secret::init_with(|| result),
        }
    }
}

impl<T> Add<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Add<&SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn add(self, rhs: &SecretSigned<T>) -> Self::Output {
        self.checked_add(rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Sub<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Bounded + Integer,
{
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Mul<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Mul<&SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.checked_mul(rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Add<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;

    fn add(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_add(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Mul<PublicSigned<T>> for &SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;

    fn mul(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Mul<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;

    fn mul(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<'b, T> core::iter::Sum<&'b SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn sum<I: Iterator<Item = &'b SecretSigned<T>>>(iter: I) -> Self {
        iter.fold(Self::zero(), |accum, x| accum + x)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use crypto_bigint::{CheckedMul, U1024, U128};
    use rand::SeedableRng;
    use rand_chacha::{self, ChaCha8Rng};

    use super::SecretSigned;
    use crate::uint::PublicSigned;

    const SEED: u64 = 123;

    #[test]
    fn adding_signed_numbers_increases_the_bound() {
        let s1 = SecretSigned::new_from_unsigned(U128::from_u8(5), 13).unwrap();
        let s2 = SecretSigned::new_from_unsigned(U128::from_u8(3), 10).unwrap();
        // The sum has a bound that is equal to the biggest bound of the operands + 1
        assert_eq!((s1 + s2).bound(), 14);
    }

    #[test]
    #[should_panic]
    fn adding_signed_numbers_with_max_bounds_panics() {
        let s1 = SecretSigned::new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let s2 = SecretSigned::new_from_unsigned(U128::from_u8(3), 127).unwrap();

        let _ = s1 + s2;
    }

    #[test]
    fn checked_mul_sums_bounds() {
        let s1 = SecretSigned::new_from_unsigned(U128::from_u8(5), 27).unwrap();
        let s2 = SecretSigned::new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let mul = s1.checked_mul(&s2).unwrap();

        assert_eq!(mul.bound(), 44);
    }

    #[test]
    fn checked_mul_fails_when_sum_of_bounds_is_too_large() {
        let s1 = SecretSigned::new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let s2 = SecretSigned::new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let mul = s1.checked_mul(&s2);

        assert!(bool::from(mul.is_none()));
    }

    #[test]
    fn mul_wide_sums_bounds() {
        let s = SecretSigned::new_from_unsigned(U1024::MAX >> 1, 1023).unwrap();
        let s1 = PublicSigned::new_from_unsigned(U1024::MAX >> 1, 1023).unwrap();
        let mul = s.mul_wide(&s1);
        assert_eq!(mul.bound(), 2046);

        let s2 = PublicSigned::new_from_unsigned(U1024::from_u8(8), 4).unwrap();
        let mul = s.mul_wide(&s2);
        assert_eq!(mul.bound(), 1027);
    }

    #[test]
    fn checked_mul_handles_sign() {
        let n = SecretSigned::new_from_unsigned(U128::from_u8(5), 27).unwrap().neg();
        let p = SecretSigned::new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let neg_pos = n.checked_mul(&p).unwrap();
        let pos_neg = p.checked_mul(&n).unwrap();
        let pos_pos = p.checked_mul(&p).unwrap();
        let neg_neg = n.checked_mul(&n).unwrap();
        // negative * positive ⇒ negative
        assert!(bool::from(neg_pos.is_negative()));
        // positive * negative ⇒ negative
        assert!(bool::from(pos_neg.is_negative()));
        // positive * positive ⇒ positive
        assert!(!bool::from(pos_pos.is_negative()));
        // negative * negative ⇒ positive
        assert!(!bool::from(neg_neg.is_negative()));
    }

    #[test]
    fn random_bounded_bits_is_sane() {
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        for bound_bits in 1..U1024::BITS - 1 {
            let signed: SecretSigned<U1024> = SecretSigned::random_bounded_bits(&mut rng, bound_bits);
            assert!(*signed.abs().expose_secret() < U1024::MAX >> (U1024::BITS - 1 - bound_bits));
            signed.assert_bound(bound_bits);
        }
    }

    #[test]
    fn signed_with_low_bounds() {
        // a 2 bit bound means numbers must be smaller or equal to 3
        let bound = 2;
        let value = U1024::from_u8(3);
        let signed = SecretSigned::new_from_unsigned(value, bound).unwrap();
        assert!(*signed.abs().expose_secret() < U1024::MAX >> (U1024::BITS - 1 - bound));
        signed.assert_bound(bound);
        // 4 is too big
        let value = U1024::from_u8(4);
        let signed = SecretSigned::new_from_unsigned(value, bound);
        assert!(signed.is_none());

        // a 1 bit bound means numbers must be smaller or equal to 1
        let bound = 1;
        let value = U1024::from_u8(1);
        let signed = SecretSigned::new_from_unsigned(value, bound).unwrap();
        assert!(*signed.abs().expose_secret() < U1024::MAX >> (U1024::BITS - 1 - bound));
        signed.assert_bound(bound);
        // 2 is too big
        let value = U1024::from_u8(2);
        let signed = SecretSigned::new_from_unsigned(value, bound);
        assert!(signed.is_none());

        // a 0 bit bound means only 0 is a valid value
        let bound = 0;
        let value = U1024::from_u8(0);
        let signed = SecretSigned::new_from_unsigned(value, bound).unwrap();
        assert!(*signed.abs().expose_secret() < U1024::MAX >> (U1024::BITS - 1 - bound));
        signed.assert_bound(bound);
        // 1 is too big
        let value = U1024::from_u8(1);
        let signed = SecretSigned::new_from_unsigned(value, bound);
        assert!(signed.is_none());
    }

    #[test]
    fn neg_u128() {
        let n = SecretSigned::new_from_unsigned(U128::from_be_hex("fffffffffffffffffffffffffffffff0"), 127).unwrap();
        let neg_n =
            SecretSigned::new_from_unsigned(U128::from_be_hex("00000000000000000000000000000010"), 127).unwrap();
        assert!(bool::from(n.is_negative()));
        assert!(!bool::from(neg_n.is_negative()));
        assert_eq!(n.clone().neg().to_public(), neg_n.to_public());
        assert_eq!(n.clone().neg().neg().to_public(), n.to_public());
    }

    #[test]
    #[should_panic(expected = "does not overflow by the construction of the arguments")]
    fn sub_panics_on_underflow() {
        // Biggest/smallest SecretSigned<U128> is |2^127|:
        use crypto_bigint::U128;
        let max_uint = U128::from_u128(u128::MAX >> 1);
        let one_signed = SecretSigned::new_from_abs(U128::ONE, U128::BITS - 1, 0u8.into()).unwrap();
        let min_signed =
            SecretSigned::new_from_abs(max_uint, U128::BITS - 1, 1u8.into()).expect("|2^127| is a valid SecretSigned");
        let _ = min_signed - one_signed;
    }
    #[test]
    #[should_panic(expected = "does not overflow by the construction of the arguments")]
    fn sub_panics_on_underflow_1024() {
        // Biggest/smallest SecretSigned<U1024> is |2^1023|:
        let max_uint = U1024::MAX >> 1;
        let one_signed = SecretSigned::new_from_abs(U1024::ONE, U1024::BITS - 1, 0u8.into()).unwrap();
        let min_signed = SecretSigned::new_from_abs(max_uint, U1024::BITS - 1, 1u8.into())
            .expect("|2^1023| is a valid SecretSigned");
        let _ = min_signed - one_signed;
    }

    #[test]
    fn checked_sub_handles_underflow() {
        // Biggest/smallest SecretSigned<U1024> is |2^1023|
        let max_uint = U1024::MAX >> 1;
        let one_signed = SecretSigned::new_from_abs(U1024::ONE, U1024::BITS - 1, 0u8.into()).unwrap();
        let min_signed = SecretSigned::new_from_abs(max_uint, U1024::BITS - 1, 1u8.into())
            .expect("|2^1023| is a valid SecretSigned");

        let result = min_signed.checked_sub(&one_signed);
        assert!(bool::from(result.is_none()))
    }
}
