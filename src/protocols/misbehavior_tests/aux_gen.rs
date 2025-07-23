use alloc::collections::BTreeSet;

use manul::{
    dev::{
        BinaryFormat, RoundExtension, TestSessionParams, TestSigner, TestVerifier, check_evidence_with_extension,
        check_evidence_with_extensions,
    },
    protocol::{LocalError, Round},
    signature::Keypair,
};
use rand_chacha::ChaCha8Rng;
use rand_core::{CryptoRngCore, OsRng, SeedableRng};

use super::super::aux_gen::{
    AuxGen, AuxGenSharedData, Round1, Round1EchoBroadcast, Round2, Round2EchoBroadcast, Round2NormalBroadcast, Round3,
    Round3DirectMessage, Round3NormalBroadcast,
};
use crate::{
    dev::TestParams,
    paillier::{PaillierParams, PublicKeyPaillierWire, RPParams, RPParamsWire, RPSecret, SecretKeyPaillierWire},
    params::SchemeParams,
    tools::hashing::Hasher,
    zk::{FacProof, ModProof, PrmProof},
};

type Id = TestVerifier;
type P = TestParams;
type SP = TestSessionParams<BinaryFormat>;

#[allow(clippy::type_complexity)]
fn make_entry_points() -> (Vec<(TestSigner, AuxGen<P, Id>)>, AuxGenSharedData<Id>) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers.iter().map(TestSigner::verifying_key).collect::<BTreeSet<_>>();

    let entry_points = signers
        .into_iter()
        .map(|signer| (signer, AuxGen::new(all_ids.clone()).unwrap()))
        .collect();
    (entry_points, AuxGenSharedData { ids: all_ids })
}

#[test]
fn r2_hash_mismatch() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round1<P, Id>;

        fn make_echo_broadcast(
            &self,
            _rng: &mut impl CryptoRngCore,
            _round: &Self::Round,
        ) -> Result<Round1EchoBroadcast, LocalError> {
            Ok(Round1EchoBroadcast {
                cap_v: Hasher::<<P as SchemeParams>::Digest>::new_with_dst(b"bad hash").finalize(P::SECURITY_BITS),
            })
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 2): The previously sent hash does not match the public data.",
    )
}

#[test]
fn r2_paillier_modulus_too_small() -> Result<(), LocalError> {
    fn make_small_modulus_pk<P: PaillierParams>() -> PublicKeyPaillierWire<P> {
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let paillier_sk = SecretKeyPaillierWire::<P>::random_small(&mut rng);
        paillier_sk.public_key()
    }

    #[derive(Debug, Clone)]
    struct R1Override;

    impl RoundExtension<Id> for R1Override {
        type Round = Round1<P, Id>;
        fn make_echo_broadcast(
            &self,
            _rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round1EchoBroadcast, LocalError> {
            let mut data = round.public_data.clone();
            data.paillier_pk = make_small_modulus_pk::<<P as SchemeParams>::Paillier>().into_precomputed();
            Ok(Round1EchoBroadcast {
                cap_v: data.hash(&round.context.sid, &round.context.my_id),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct R2Override;

    impl RoundExtension<Id> for R2Override {
        type Round = Round2<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2NormalBroadcast<P>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;
            message.paillier_pk = make_small_modulus_pk::<<P as SchemeParams>::Paillier>();
            Ok(message)
        }
    }

    check_evidence_with_extensions::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        |entry_point| entry_point.with_extension(R1Override).with_extension(R2Override),
        "Protocol error (Round 2): Paillier modulus is too small.",
    )
}

#[test]
fn r2_rp_modulus_too_small() -> Result<(), LocalError> {
    fn make_small_modulus_rp_params<P: PaillierParams>() -> RPParamsWire<P> {
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        RPParams::random_small(&mut rng).to_wire()
    }

    #[derive(Debug, Clone)]
    struct R1Override;

    impl RoundExtension<Id> for R1Override {
        type Round = Round1<P, Id>;
        fn make_echo_broadcast(
            &self,
            _rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round1EchoBroadcast, LocalError> {
            let mut data = round.public_data.clone();
            data.rp_params = make_small_modulus_rp_params::<<P as SchemeParams>::Paillier>().to_precomputed();

            Ok(Round1EchoBroadcast {
                cap_v: data.hash(&round.context.sid, &round.context.my_id),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct R2Override;

    impl RoundExtension<Id> for R2Override {
        type Round = Round2<P, Id>;

        fn make_echo_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2EchoBroadcast<P>, LocalError> {
            let mut message = round.make_echo_broadcast(rng)?;
            message.rp_params = make_small_modulus_rp_params::<<P as SchemeParams>::Paillier>();
            Ok(message)
        }
    }

    check_evidence_with_extensions::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        |entry_point| entry_point.with_extension(R1Override).with_extension(R2Override),
        "Protocol error (Round 2): Ring-Pedersen modulus is too small.",
    )
}

#[test]
fn r2_prm_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct R1Override;

    impl RoundExtension<Id> for R1Override {
        type Round = Round1<P, Id>;
        fn make_echo_broadcast(
            &self,
            _rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round1EchoBroadcast, LocalError> {
            let mut data = round.public_data.clone();

            let mut rng = ChaCha8Rng::seed_from_u64(123);
            let secret = RPSecret::random(&mut rng);
            let rp_params = RPParams::random_with_secret(&mut rng, &secret);
            data.psi = PrmProof::new(&mut rng, &secret, &rp_params, &1u8);

            Ok(Round1EchoBroadcast {
                cap_v: data.hash(&round.context.sid, &round.context.my_id),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct R2Override;

    impl RoundExtension<Id> for R2Override {
        type Round = Round2<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2NormalBroadcast<P>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;

            let mut rng = ChaCha8Rng::seed_from_u64(123);
            let secret = RPSecret::random(&mut rng);
            let rp_params = RPParams::random_with_secret(&mut rng, &secret);
            message.psi = PrmProof::new(&mut rng, &secret, &rp_params, &1u8);

            Ok(message)
        }
    }

    check_evidence_with_extensions::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        |entry_point| entry_point.with_extension(R1Override).with_extension(R2Override),
        "Protocol error (Round 2): `П^{prm}` verification failed.",
    )
}

#[test]
fn r3_mod_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round3<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round3NormalBroadcast<P>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;

            let sk = SecretKeyPaillierWire::random(rng).into_precomputed();
            message.psi_prime = ModProof::new(rng, &sk, &1u8);

            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 3): `П^{mod}` verification failed.",
    )
}

#[test]
fn r3_fac_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round3<P, Id>;

        fn make_direct_message(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
            destination: &Id,
        ) -> Result<(Round3DirectMessage<P>, ()), LocalError> {
            let (mut message, artifact) = round.make_direct_message(rng, destination)?;

            let sk = SecretKeyPaillierWire::random(&mut OsRng).into_precomputed();
            let rp_params = RPParams::random(rng);
            message.psi = FacProof::new(rng, &sk, &rp_params, &1u8);

            Ok((message, artifact))
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 3): `П^{fac}` verification failed.",
    )
}
