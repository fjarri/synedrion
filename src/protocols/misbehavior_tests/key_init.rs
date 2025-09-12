use alloc::collections::BTreeSet;

use manul::{
    dev::{BinaryFormat, RoundExtension, TestSessionParams, TestSigner, TestVerifier, check_evidence_with_extension},
    protocol::{LocalError, Round},
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};

use super::super::key_init::{
    KeyInit, KeyInitSharedData, Round2, Round2NormalBroadcast, Round3, Round3NormalBroadcast,
};
use crate::{
    curve::Scalar,
    dev::TestParams,
    tools::{Secret, bitvec::BitVec},
    zk::SchProof,
};

type Id = TestVerifier;
type P = TestParams;
type SP = TestSessionParams<BinaryFormat>;

#[allow(clippy::type_complexity)]
fn make_entry_points() -> (Vec<(TestSigner, KeyInit<P, Id>)>, KeyInitSharedData<Id>) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .into_iter()
        .map(|signer| (signer, KeyInit::new(all_ids.clone()).unwrap()))
        .collect();

    (entry_points, KeyInitSharedData { ids: all_ids })
}

#[test]
fn r2_hash_mismatch() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round2<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round2NormalBroadcast<P>, LocalError> {
            let mut message = round.make_normal_broadcast(rng)?;

            // Replace `u` with something other than we committed to when hashing it in Round 1.
            message.u = BitVec::random(rng, message.u.bits().len());

            Ok(message)
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
fn r3_invalid_sch_proof() {
    #[derive(Debug, Clone)]
    struct Override;

    impl RoundExtension<Id> for Override {
        type Round = Round3<P, Id>;

        fn make_normal_broadcast(
            &self,
            rng: &mut impl CryptoRngCore,
            round: &Self::Round,
        ) -> Result<Round3NormalBroadcast<P>, LocalError> {
            let context = &round.context;
            let aux = (&context.sid, &context.my_id, &round.rho_combined);

            // Make a proof for a random secret. This won't pass verification.
            let x = Secret::init_with(|| Scalar::random(rng));
            let psi = SchProof::new(
                &context.tau,
                &x,
                &context.public_data.cap_a,
                &x.mul_by_generator(),
                &aux,
            );

            let message = Round3NormalBroadcast { psi };
            Ok(message)
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Override,
        "Protocol error (Round 3): Failed to verify `П^{sch}`.",
    )
    .unwrap();
}
