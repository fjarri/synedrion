//! Knowledge of Exponent vs Paillier Encryption ($\Pi^{log*}$, Section C.2, Fig. 25)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    conversion::{scalar_from_signed, secret_scalar_from_signed},
    SchemeParams,
};
use crate::{
    curve::Point,
    paillier::{
        Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams,
        Randomizer,
    },
    tools::hashing::{Chain, Hashable, XofHasher},
    uint::{PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_log*";

/**
ZK proof: Knowledge of Exponent vs Paillier Encryption.

Secret inputs:
- $x \in \pm 2^\ell$,
- $\rho$, a Paillier randomizer for the public key $N_0$.

Public inputs:
- Paillier public key $N_0$,
- Paillier ciphertext $C = enc_0(x, \rho)$,
- Point $g$,
- Point $X = g * x$,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LogStarProof<P: SchemeParams> {
    e: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_a: CiphertextWire<P::Paillier>,
    cap_y: Point,
    cap_d: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z2: MaskedRandomizer<P::Paillier>,
    z3: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
}

impl<P: SchemeParams> LogStarProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        x: &SecretSigned<<P::Paillier as PaillierParams>::Uint>,
        rho: &Randomizer<P::Paillier>,
        pk0: &PublicKeyPaillier<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        g: &Point,
        cap_x: &Point,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        x.assert_exponent_range(P::L_BOUND);
        assert_eq!(cap_c.public_key(), pk0);

        let hat_cap_n = setup.modulus(); // $\hat{N}$

        let alpha = SecretSigned::random_in_exp_range(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let r = Randomizer::random(rng, pk0);
        let gamma = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let cap_s = setup.commit(x, &mu).to_wire();
        let cap_a = Ciphertext::new_with_randomizer_signed(pk0, &alpha, &r).to_wire();
        let cap_y = g * secret_scalar_from_signed::<P>(&alpha);
        let cap_d = setup.commit(&alpha, &gamma).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_s)
            .chain(&cap_a)
            .chain(&cap_y)
            .chain(&cap_d)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&cap_c.to_wire())
            .chain(g)
            .chain(cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = (alpha + x * e).to_public();
        let z2 = rho.to_masked(&r, &e);
        let z3 = (gamma + mu * e.to_wide()).to_public();

        Self {
            e,
            cap_s,
            cap_a,
            cap_y,
            cap_d,
            z1,
            z2,
            z3,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        pk0: &PublicKeyPaillier<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        g: &Point,
        cap_x: &Point,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_c.public_key(), pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_a)
            .chain(&self.cap_y)
            .chain(&self.cap_d)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&cap_c.to_wire())
            .chain(g)
            .chain(cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // Range check
        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // enc_0(z1, z2) == A (+) C (*) e
        let c = Ciphertext::new_public_with_randomizer_signed(pk0, &self.z1, &self.z2);
        if c != self.cap_a.to_precomputed(pk0) + cap_c * &e {
            return false;
        }

        // g^{z_1} == Y X^e
        if g * &scalar_from_signed::<P>(&self.z1) != self.cap_y + cap_x * &scalar_from_signed::<P>(&e) {
            return false;
        }

        // s^{z_1} t^{z_3} == D S^e \mod \hat{N}
        let cap_d = self.cap_d.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z3) != &cap_d * &cap_s.pow(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::LogStarProof;
    use crate::{
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        curve::{Point, Scalar},
        paillier::{Ciphertext, RPParams, Randomizer, SecretKeyPaillierWire},
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

        let g = Point::GENERATOR * Scalar::random(&mut OsRng);
        let x = SecretSigned::random_in_exp_range(&mut OsRng, Params::L_BOUND);
        let rho = Randomizer::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_with_randomizer_signed(pk, &x, &rho);
        let cap_x = g * secret_scalar_from_signed::<Params>(&x);

        let proof = LogStarProof::<Params>::new(&mut OsRng, &x, &rho, pk, &cap_c, &g, &cap_x, &setup, &aux);
        assert!(proof.verify(pk, &cap_c, &g, &cap_x, &setup, &aux));
    }
}
