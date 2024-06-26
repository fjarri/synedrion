use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::uint::{HasWide, UintLike, UintModLike};

#[cfg(test)]
use crate::uint::{U1024Mod, U2048Mod, U512Mod, U1024, U2048, U4096, U512};

pub trait PaillierParams: Debug + PartialEq + Eq + Clone + Send + Sync {
    /// The size of one of the pair of RSA primes.
    const PRIME_BITS: usize;
    /// The size of the RSA modulus (a product of two primes).
    const MODULUS_BITS: usize = Self::PRIME_BITS * 2;
    /// An integer that fits a single RSA prime.
    type HalfUint: UintLike<ModUint = Self::HalfUintMod>
        + HasWide<Wide = Self::Uint>
        + Zeroize
        + Serialize
        + for<'de> Deserialize<'de>;
    /// A modulo-residue counterpart of `HalfUint`.
    type HalfUintMod: UintModLike<RawUint = Self::HalfUint>;
    /// An integer that fits the RSA modulus.
    type Uint: UintLike<ModUint = Self::UintMod>
        + HasWide<Wide = Self::WideUint>
        + Zeroize
        + Serialize
        + for<'de> Deserialize<'de>;
    /// A modulo-residue counterpart of `Uint`.
    type UintMod: UintModLike<RawUint = Self::Uint> + Zeroize;
    /// An integer that fits the squared RSA modulus.
    /// Used for Paillier ciphertexts.
    type WideUint: UintLike<ModUint = Self::WideUintMod>
        + HasWide<Wide = Self::ExtraWideUint>
        + Zeroize
        + Serialize
        + for<'de> Deserialize<'de>;
    /// A modulo-residue counterpart of `WideUint`.
    type WideUintMod: UintModLike<RawUint = Self::WideUint>;
    /// An integer that fits the squared RSA modulus times a small factor.
    /// Used in some ZK proofs.
    // Technically, it doesn't have to be that large, but the time spent multiplying these
    // is negligible, and when it is used as an exponent, it is bounded anyway.
    // So it is easier to keep it as a double of `WideUint`.
    type ExtraWideUint: UintLike + Serialize + for<'de> Deserialize<'de>;
}

/// Paillier parameters for unit tests in this submodule.
#[cfg(test)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct PaillierTest;

#[cfg(test)]
impl PaillierParams for PaillierTest {
    const PRIME_BITS: usize = 512;
    type HalfUint = U512;
    type HalfUintMod = U512Mod;
    type Uint = U1024;
    type UintMod = U1024Mod;
    type WideUint = U2048;
    type WideUintMod = U2048Mod;
    type ExtraWideUint = U4096;
}
