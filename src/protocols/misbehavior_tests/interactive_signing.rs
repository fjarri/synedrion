use alloc::collections::{BTreeMap, BTreeSet};

use elliptic_curve::FieldBytes;
use manul::{
    dev::{
        BinaryFormat, RoundExtension, TestSessionParams, TestSigner, TestVerifier, check_evidence_with_extension,
        check_evidence_with_extensions,
    },
    protocol::{BoxedRound, FinalizeOutcome, LocalError, Round},
    signature::Keypair,
    utils::{MapValues, MapValuesRef},
};
use rand_core::{CryptoRngCore, OsRng, RngCore};

use super::super::interactive_signing::{
    InteractiveSigning, InteractiveSigningSharedData, Round1, Round1EchoBroadcast, Round2, Round2EchoBroadcast,
    Round2NormalBroadcast, Round3, Round3EchoBroadcast, Round3NormalBroadcast, Round4, Round4NormalBroadcast, Round5,
    Round6,
};
use crate::{
    curve::{Point, RecoverableSignature, Scalar},
    dev::TestParams,
    entities::{AuxInfo, KeyShare},
    params::SchemeParams,
    zk::{ElogProof, ElogPublicInputs, ElogSecretInputs},
};

type Id = TestVerifier;
type P = TestParams;
type SP = TestSessionParams<BinaryFormat>;
type Curve = <TestParams as SchemeParams>::Curve;

#[allow(clippy::type_complexity)]
fn make_entry_points() -> (
    Vec<(TestSigner, InteractiveSigning<P, Id>)>,
    InteractiveSigningSharedData<P, Id>,
) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers.iter().map(TestSigner::verifying_key).collect::<BTreeSet<_>>();

    let key_shares = KeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &all_ids, None);
    let aux_infos = AuxInfo::new_centralized(&mut OsRng, &all_ids);

    let mut message = FieldBytes::<Curve>::default();
    OsRng.fill_bytes(&mut message);

    let entry_points = signers
        .into_iter()
        .map(|signer| {
            let id = signer.verifying_key();
            let entry_point =
                InteractiveSigning::new(message, key_shares[&id].clone(), aux_infos[&id].clone()).unwrap();
            (signer, entry_point)
        })
        .collect();

    let id = all_ids.first().unwrap();
    let shared_data = InteractiveSigningSharedData {
        shares: key_shares[id].public().clone(),
        aux: aux_infos[id].public().clone(),
        message,
    };

    (entry_points, shared_data)
}

#[test]
fn r1_enc_elg_0_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round1<P, Id>;

        fn make_echo_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round1EchoBroadcast<P>, LocalError> {
            let mut message = round.make_echo_broadcast(rng)?;
            message.cap_a1 = Scalar::random(rng).mul_by_generator();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 1): failed to verify `\\psi^0` (`П^{enc-elg}` proof).",
    )
}

#[test]
fn r1_enc_elg_1_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round1<P, Id>;

        fn make_echo_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round1EchoBroadcast<P>, LocalError> {
            let mut message = round.make_echo_broadcast(rng)?;
            message.cap_b1 = Scalar::random(rng).mul_by_generator();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 1): failed to verify `\\psi^1` (`П^{enc-elg}` proof).",
    )
}

#[test]
fn r2_wrong_ids_d() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round2<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2NormalBroadcast<P, Id>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;
            message.cap_ds.pop_first();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 2): wrong IDs in `D` map.",
    )
}

#[test]
fn r2_wrong_ids_f() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round2<P, Id>;

        fn make_echo_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2EchoBroadcast<P, Id>, LocalError> {
            let mut message = round.make_echo_broadcast(rng)?;
            message.cap_fs.pop_first();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 2): wrong IDs in `F` map.",
    )
}

#[test]
fn r2_wrong_ids_psi() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round2<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2NormalBroadcast<P, Id>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;
            message.psis.pop_first();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 2): wrong IDs in `\\psi` map (`П^{aff-g}` proofs for `D`).",
    )
}

#[test]
fn r2_aff_g_psi_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round2<P, Id>;

        fn make_echo_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2EchoBroadcast<P, Id>, LocalError> {
            let mut message = round.make_echo_broadcast(rng)?;
            message.cap_gamma = Scalar::random(rng).mul_by_generator();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 2): failed to verify `\\psi` (`П^{aff-g}` proof for `D`).",
    )
}

#[test]
fn r2_aff_g_hat_psi_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round2<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2NormalBroadcast<P, Id>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;
            message.hat_cap_ds = message.cap_ds.clone();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 2): failed to verify `\\hat{psi}` (`П^{aff-g}` proof for `\\hat{D}`).",
    )
}

#[test]
fn r2_elog_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round2<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2NormalBroadcast<P, Id>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;

            let aux = (&round.context.epid, &round.context.my_id);

            // An invalid `y`
            let y = Scalar::random(rng);
            let cap_y = y.mul_by_generator();
            let cap_b1 = round.context.b.mul_by_generator();
            let cap_b2 = cap_y * &round.context.b + round.context.gamma.mul_by_generator();

            // We can't replace any dependent values in the messages because
            // it will trigger errors in earlier proofs.
            // So we're replacing the elog proof itself, with one incorrect value (`y`).

            message.psi_elog = ElogProof::new(
                rng,
                ElogSecretInputs {
                    y: &round.context.gamma,
                    lambda: &round.context.b,
                },
                // Note that the parameter order in the protocol description
                // and in the ZK proof description do not match.
                ElogPublicInputs {
                    cap_l: &cap_b1,
                    cap_m: &cap_b2,
                    cap_x: &cap_y,
                    cap_y: &round.cap_gamma,
                    h: &Point::generator(),
                },
                &aux,
            );

            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 2): failed to verify `П^{elog}` proof.",
    )
}

#[test]
fn r3_elog_failed() -> Result<(), LocalError> {
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
            message.cap_delta = Scalar::random(rng).mul_by_generator();
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 3): failed to verify `П^{elog}` proof.",
    )
}

#[test]
fn r4_invalid_signature_share() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round4<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round4NormalBroadcast<P>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;
            message.sigma = Scalar::random(rng);
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 4): signature share verification failed.",
    )
}

#[test]
fn r5_dec_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct R3Override;

    impl RoundExtension<Id> for R3Override {
        type Round = Round3<P, Id>;

        fn make_echo_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round3EchoBroadcast<P>, LocalError> {
            let mut message = round.make_echo_broadcast(rng)?;
            message.delta = Scalar::random(rng);
            Ok(message)
        }

        fn finalize(
            &self,
            _rng: &mut impl CryptoRngCore,
            round: Self::Round,
            payloads: BTreeMap<Id, <Self::Round as Round<Id>>::Payload>,
            _artifacts: BTreeMap<Id, <Self::Round as Round<Id>>::Artifact>,
        ) -> Result<FinalizeOutcome<Id, <Self::Round as Round<Id>>::Protocol>, LocalError> {
            // Manually start the error round in the malicious node

            let mut deltas = payloads.map_values(|payload| payload.delta);
            deltas.insert(round.context.my_id, round.r3_echo_broadcast.delta);

            let mut cap_ks = round.r1_payloads.map_values_ref(|payload| payload.cap_k.clone());
            cap_ks.insert(round.context.my_id, round.cap_k);

            Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(Round5 {
                context: round.context,
                deltas,
                betas: round.betas,
                ss: round.ss,
                rs: round.rs,
                cap_gammas: round.cap_gammas,
                cap_ks,
                cap_ds: round.cap_ds,
                cap_fs: round.cap_fs,
            })))
        }
    }

    #[derive(Debug, Clone)]
    struct R5Override;

    impl RoundExtension<Id> for R5Override {
        type Round = Round5<P, Id>;

        fn finalize(
            &self,
            rng: &mut impl CryptoRngCore,
            _round: Self::Round,
            _payloads: BTreeMap<Id, <Self::Round as Round<Id>>::Payload>,
            _artifacts: BTreeMap<Id, <Self::Round as Round<Id>>::Artifact>,
        ) -> Result<FinalizeOutcome<Id, <Self::Round as Round<Id>>::Protocol>, LocalError> {
            // Return a bogus signature in the malicious node,
            // so that it finishes successfully.
            // Since it's the only malicious node, all the messages it receives will contain
            // valid correctness proofs, which will normally lead to a finalization error.
            Ok(FinalizeOutcome::Result(
                RecoverableSignature::random(rng).ok_or_else(|| LocalError::new("Failed to create signature"))?,
            ))
        }
    }

    check_evidence_with_extensions::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        |entry_point| entry_point.with_extension(R3Override).with_extension(R5Override),
        "Protocol error (Round 5): `П^{dec}` proof verification failed.",
    )
}

#[test]
fn r6_dec_failed() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct R3Override;

    impl RoundExtension<Id> for R3Override {
        type Round = Round3<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round3NormalBroadcast<P>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;
            // Trigger the error round in lawful nodes
            message.cap_s = Scalar::random(rng).mul_by_generator();
            Ok(message)
        }

        fn finalize(
            &self,
            _rng: &mut impl CryptoRngCore,
            round: Self::Round,
            payloads: BTreeMap<Id, <Self::Round as Round<Id>>::Payload>,
            _artifacts: BTreeMap<Id, <Self::Round as Round<Id>>::Artifact>,
        ) -> Result<FinalizeOutcome<Id, <Self::Round as Round<Id>>::Protocol>, LocalError> {
            // Manually start the error round in the malicious node

            let mut cap_ks = round.r1_payloads.map_values_ref(|payload| payload.cap_k.clone());
            cap_ks.insert(round.context.my_id, round.cap_k);

            let mut cap_ss = payloads.map_values_ref(|payload| payload.cap_s);
            cap_ss.insert(round.context.my_id, round.r3_normal_broadcast.cap_s);

            Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(Round6 {
                context: round.context,
                cap_gamma_combined: round.cap_gamma_combined,
                hat_betas: round.hat_betas,
                hat_ss: round.hat_ss,
                hat_rs: round.hat_rs,
                cap_ks,
                cap_ss,
                hat_cap_ds: round.hat_cap_ds,
                hat_cap_fs: round.hat_cap_fs,
            })))
        }
    }

    #[derive(Debug, Clone)]
    struct R6Override;

    impl RoundExtension<Id> for R6Override {
        type Round = Round6<P, Id>;

        fn finalize(
            &self,
            rng: &mut impl CryptoRngCore,
            _round: Self::Round,
            _payloads: BTreeMap<Id, <Self::Round as Round<Id>>::Payload>,
            _artifacts: BTreeMap<Id, <Self::Round as Round<Id>>::Artifact>,
        ) -> Result<FinalizeOutcome<Id, <Self::Round as Round<Id>>::Protocol>, LocalError> {
            // Return a bogus signature in the malicious node,
            // so that it finishes successfully.
            // Since it's the only malicious node, all the messages it receives will contain
            // valid correctness proofs, which will normally lead to a finalization error.
            Ok(FinalizeOutcome::Result(
                RecoverableSignature::random(rng).ok_or_else(|| LocalError::new("Failed to create signature"))?,
            ))
        }
    }

    check_evidence_with_extensions::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        |entry_point| entry_point.with_extension(R3Override).with_extension(R6Override),
        "Protocol error (Round 6): `П^{dec}` proof verification failed.",
    )
}
