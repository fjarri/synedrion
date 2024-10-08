//! Math functions for generic integers (mostly `Signed`).

use crypto_bigint::{
    subtle::{ConditionallySelectable, CtOption},
    Encoding, Integer, Invert, PowBoundedExp, Square,
};

use crate::uint::{HasWide, Signed};

/// Constant-time exponentiation of an integer in Montgomery form by a signed exponent.
///
/// #Panics
///
/// Panics if `uint` is not invertible.
pub(crate) fn pow_signed<T>(
    uint: <T as Integer>::Monty,
    exponent: &Signed<T>,
) -> <T as Integer>::Monty
where
    T: Integer + crypto_bigint::Bounded + Encoding + ConditionallySelectable,
    T::Monty: Invert<Output = CtOption<<T as Integer>::Monty>> + ConditionallySelectable,
{
    let abs_exponent = exponent.abs();
    let abs_result = uint.pow_bounded_exp(&abs_exponent, exponent.bound());
    let inv_result = abs_result
        .invert()
        .expect("The `uint` param is assumed invertible");
    <T as Integer>::Monty::conditional_select(&abs_result, &inv_result, exponent.is_negative())
}

/// Constant-time exponentiation of an integer in Montgomery form by a "wide" and signed exponent.
///
/// #Panics
///
/// Panics if `uint` is not invertible.
pub(crate) fn pow_signed_wide<T>(
    uint: <T as Integer>::Monty,
    exponent: &Signed<<T as HasWide>::Wide>,
) -> <T as Integer>::Monty
where
    T: Integer + crypto_bigint::Bounded + Encoding + ConditionallySelectable + HasWide,
    <T as HasWide>::Wide: crypto_bigint::Bounded + ConditionallySelectable,
    T::Monty: Invert<Output = CtOption<<T as Integer>::Monty>> + ConditionallySelectable,
{
    let abs_exponent = exponent.abs();
    let abs_result = pow_wide::<T>(uint, &abs_exponent, exponent.bound());
    let inv_result = abs_result
        .invert()
        .expect("The `uint` param is assumed invertible");
    <T as Integer>::Monty::conditional_select(&abs_result, &inv_result, exponent.is_negative())
}

/// Constant-time exponentiation of an integer in Montgomery form by an "extra wide" and signed exponent.
///
/// #Panics
///
/// Panics if `uint` is not invertible.
pub(crate) fn pow_signed_extra_wide<T>(
    uint: <T as Integer>::Monty,
    exponent: &Signed<<<T as HasWide>::Wide as HasWide>::Wide>,
) -> <T as Integer>::Monty
where
    T: Integer + HasWide + crypto_bigint::Bounded + ConditionallySelectable,
    <T as HasWide>::Wide: HasWide + crypto_bigint::Bounded,
    <<T as HasWide>::Wide as HasWide>::Wide: crypto_bigint::Bounded + ConditionallySelectable,
    T::Monty: ConditionallySelectable + Invert<Output = CtOption<<T as Integer>::Monty>>,
{
    let bits = <<T as HasWide>::Wide as crypto_bigint::Bounded>::BITS;
    let bound = exponent.bound();

    let abs_exponent = exponent.abs();
    let (wlo, whi) = <T as HasWide>::Wide::from_wide(abs_exponent);

    let lo_res = pow_wide::<T>(uint, &wlo, core::cmp::min(bits, bound));

    let abs_result = if bound > bits {
        let mut hi_res = pow_wide::<T>(uint, &whi, bound - bits);
        for _ in 0..bits {
            hi_res = hi_res.square();
        }
        hi_res * lo_res
    } else {
        lo_res
    };

    let inv_result = abs_result
        .invert()
        .expect("The `uint` param is assumed invertible");
    <T as Integer>::Monty::conditional_select(&abs_result, &inv_result, exponent.is_negative())
}

/// Variable-time exponentiation of an integer in Montgomery form by a signed exponent.
///
/// #Panics
///
/// Panics if `uint` is not invertible.
pub(crate) fn pow_signed_vartime<T>(
    uint: <T as Integer>::Monty,
    exponent: &Signed<T>,
) -> <T as Integer>::Monty
where
    T: Integer + crypto_bigint::Bounded + ConditionallySelectable + Encoding,
    <T as Integer>::Monty: Invert<Output = CtOption<<T as Integer>::Monty>>,
{
    let abs_exponent = exponent.abs();
    let abs_result = uint.pow_bounded_exp(&abs_exponent, exponent.bound());
    if exponent.is_negative().into() {
        abs_result
            .invert()
            .expect("The `uint` param is assumed invertible")
    } else {
        abs_result
    }
}

fn pow_wide<T>(
    uint: <T as Integer>::Monty,
    exponent: &<T as HasWide>::Wide,
    bound: u32,
) -> <T as Integer>::Monty
where
    T: Integer + HasWide + crypto_bigint::Bounded,
    <T as Integer>::Monty: Square,
{
    let bits = <T as crypto_bigint::Bounded>::BITS;
    let bound = bound % (2 * bits + 1);

    let (lo, hi) = <T as HasWide>::from_wide(exponent.clone());
    let lo_res = uint.pow_bounded_exp(&lo, core::cmp::min(bits, bound));

    // TODO (#34): this may be faster if we could get access to Uint's pow_bounded_exp() that takes
    // exponents of any size - it keeps the self^(2^k) already.
    if bound > bits {
        let mut hi_res = uint.pow_bounded_exp(&hi, bound - bits);
        for _ in 0..bits {
            hi_res = hi_res.square()
        }
        hi_res * lo_res
    } else {
        lo_res
    }
}
