//! Paillier Special Decryption in the Exponent ($\Pi^{dec}$, Section A.6, Fig. 28)

#![allow(dead_code)]

use alloc::{boxed::Box, vec::Vec};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    conversion::{scalar_from_signed, secret_scalar_from_signed},
    SchemeParams,
};
use crate::{
    curve::Point,
    paillier::{Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPParams, Randomizer},
    tools::{
        bitvec::BitVec,
        hashing::{Chain, Hashable, XofHasher},
    },
    uint::{PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_dec";

pub(crate) struct DecSecretInputs<'a, P: SchemeParams> {
    /// $x ∈ \mathbb{I}$, that is $x ∈ ±2^\ell$ (see N.B. just before Section 4.1)
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $y ∈ \mathbb{I}$, that is $x ∈ ±2^{\ell^\prime}$ (see N.B. just before Section 4.1)
    pub y: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho$, a Paillier randomizer for the public key $N_0$.
    pub rho: &'a Randomizer<P::Paillier>,
}

pub(crate) struct DecPublicInputs<'a, P: SchemeParams> {
    /// Paillier public key $N_0$.
    pub pk0: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier ciphertext $K$ such that $enc_0(y, \rho) = K (*) x + D$.
    // NOTE: paper says `enc_0(z, \rho)` which is a typo.
    pub cap_k: &'a Ciphertext<P::Paillier>,
    /// Point $X = g^x$, where $g$ is the curve generator.
    pub cap_x: &'a Point,
    /// Paillier ciphertext $D$, see the doc for `cap_k` above.
    pub cap_d: &'a Ciphertext<P::Paillier>,
    /// Point $S = g^y$, where $g$ is the curve generator.
    pub cap_s: &'a Point,
}

/// ZK proof: Paillier decryption modulo $q$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DecProof<P: SchemeParams> {
    e: BitVec,
    commitments: Box<[DecProofCommitment<P>]>,
    elements: Box<[DecProofElement<P>]>,
}

struct DecProofEphemeral<P: SchemeParams> {
    alpha: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    beta: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    r: Randomizer<P::Paillier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DecProofCommitment<P: SchemeParams> {
    cap_a: CiphertextWire<P::Paillier>,
    cap_b: Point,
    cap_c: Point,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DecProofElement<P: SchemeParams> {
    z: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    w: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    nu: MaskedRandomizer<P::Paillier>,
}

impl<P: SchemeParams> DecProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: DecSecretInputs<'_, P>,
        public: DecPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        secret.x.assert_exponent_range(P::L_BOUND);
        secret.y.assert_exponent_range(P::LP_BOUND);
        assert_eq!(public.cap_k.public_key(), public.pk0);
        assert_eq!(public.cap_d.public_key(), public.pk0);

        let (ephemerals, commitments): (Vec<_>, Vec<_>) = (0..P::SECURITY_PARAMETER)
            .map(|_| {
                let alpha = SecretSigned::random_in_exponent_range(rng, P::L_BOUND + P::EPS_BOUND);
                let beta = SecretSigned::random_in_exponent_range(rng, P::LP_BOUND + P::EPS_BOUND);
                let r = Randomizer::random(rng, public.pk0);

                let cap_a =
                    (public.cap_k * &-&alpha + Ciphertext::new_with_randomizer(public.pk0, &beta, &r)).to_wire();
                let cap_b = secret_scalar_from_signed::<P>(&beta).mul_by_generator();
                let cap_c = secret_scalar_from_signed::<P>(&alpha).mul_by_generator();

                let ephemeral = DecProofEphemeral::<P> { alpha, beta, r };
                let commitment = DecProofCommitment { cap_a, cap_b, cap_c };

                (ephemeral, commitment)
            })
            .unzip();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&commitments)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_k.to_wire())
            .chain(&public.cap_x)
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_s)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = BitVec::from_xof_reader(&mut reader, P::SECURITY_PARAMETER);

        let elements = ephemerals
            .into_iter()
            .zip(e.bits())
            .map(|(ephemeral, e_bit)| {
                let z = if *e_bit {
                    ephemeral.alpha + secret.x
                } else {
                    ephemeral.alpha
                };
                let w = if *e_bit {
                    ephemeral.beta + secret.y
                } else {
                    ephemeral.beta
                };

                let exponent = if *e_bit {
                    PublicSigned::one()
                } else {
                    PublicSigned::zero()
                };
                let nu = secret.rho.to_masked(&ephemeral.r, &exponent);

                DecProofElement {
                    z: z.to_public(),
                    w: w.to_public(),
                    nu,
                }
            })
            .collect::<Vec<_>>();

        Self {
            e,
            elements: elements.into(),
            commitments: commitments.into(),
        }
    }

    pub fn verify(&self, public: DecPublicInputs<'_, P>, setup: &RPParams<P::Paillier>, aux: &impl Hashable) -> bool {
        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.commitments)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_k.to_wire())
            .chain(&public.cap_x)
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_s)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = BitVec::from_xof_reader(&mut reader, P::SECURITY_PARAMETER);

        if e != self.e {
            return false;
        }

        if e.bits().len() != self.commitments.len() || e.bits().len() != self.elements.len() {
            return false;
        }

        for ((e_bit, commitment), element) in e
            .bits()
            .iter()
            .cloned()
            .zip(self.commitments.iter())
            .zip(self.elements.iter())
        {
            // enc(w_j, \nu_j) (+) K (*) (-z_j) == A_j (+) D (*) e_j
            let cap_a = commitment.cap_a.to_precomputed(public.pk0);
            let lhs = Ciphertext::new_public_with_randomizer(public.pk0, &element.w, &element.nu)
                + public.cap_k * &-element.z;
            let rhs = if e_bit { cap_a + public.cap_d } else { cap_a };
            if lhs != rhs {
                return false;
            }

            // g^z_j == C_j X^{e_j}
            let lhs = scalar_from_signed::<P>(&element.z).mul_by_generator();
            let rhs = if e_bit {
                commitment.cap_c + *public.cap_x
            } else {
                commitment.cap_c
            };
            if lhs != rhs {
                return false;
            }

            // g^{w_j} == B_j S^{e_j}
            let lhs = scalar_from_signed::<P>(&element.w).mul_by_generator();
            let rhs = if e_bit {
                commitment.cap_b + *public.cap_s
            } else {
                commitment.cap_b
            };
            if lhs != rhs {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{DecProof, DecPublicInputs, DecSecretInputs};
    use crate::{
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        paillier::{Ciphertext, PaillierParams, RPParams, Randomizer, SecretKeyPaillierWire},
        uint::SecretSigned,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(&mut OsRng, Params::LP_BOUND);
        let rho = Randomizer::random(&mut OsRng, pk);

        // We need $enc_0(y, \rho) = K (*) x + D$,
        // so we can choose the plaintext of `K` at random, and derive the plaintext of `D`
        // (not deriving `y` since we want it to be in a specific range).

        let k = SecretSigned::random_in_exponent_range(&mut OsRng, Paillier::PRIME_BITS * 2 - 1);
        let cap_k = Ciphertext::new(&mut OsRng, pk, &k);
        let cap_d = Ciphertext::new_with_randomizer(pk, &y, &rho) + &cap_k * &-&x;

        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();
        let cap_s = secret_scalar_from_signed::<Params>(&y).mul_by_generator();

        let proof = DecProof::<Params>::new(
            &mut OsRng,
            DecSecretInputs {
                x: &x,
                y: &y,
                rho: &rho,
            },
            DecPublicInputs {
                pk0: pk,
                cap_k: &cap_k,
                cap_x: &cap_x,
                cap_d: &cap_d,
                cap_s: &cap_s,
            },
            &setup,
            &aux,
        );
        assert!(proof.verify(
            DecPublicInputs {
                pk0: pk,
                cap_k: &cap_k,
                cap_x: &cap_x,
                cap_d: &cap_d,
                cap_s: &cap_s,
            },
            &setup,
            &aux
        ));
    }
}