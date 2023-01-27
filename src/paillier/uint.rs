use rand_core::{CryptoRng, RngCore};

use crypto_bigint::{Integer, RandomMod, Zero, U128, U64};
use crypto_primes::RandomPrimeWithRng;

pub trait Uint: Zero + Integer + RandomMod + RandomPrimeWithRng {
    fn sub(&self, rhs: &Self) -> Self;
    fn mul_wide(&self, rhs: &Self) -> (Self, Self);
    fn safe_prime_with_rng(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        <Self as RandomPrimeWithRng>::safe_prime_with_rng(rng, Self::BITS)
    }
}

impl Uint for U64 {
    fn sub(&self, rhs: &Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        self.mul_wide(&rhs)
    }
}

impl Uint for U128 {
    fn sub(&self, rhs: &Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        self.mul_wide(&rhs)
    }
}
