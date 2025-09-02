use alloc::collections::BTreeSet;

use manul::{
    dev::{BinaryFormat, RoundExtension, TestSessionParams, TestSigner, TestVerifier, check_evidence_with_extension},
    protocol::{EntryPoint, LocalError, Round},
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};

use super::super::key_resharing::{
    KeyResharing,
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
fn make_entry_points() -> (KeyResharingSharedData<Id>, Vec<(TestSigner, KeyResharing<P, Id>)>) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .into_iter()
        .map(|signer| (signer, KeyResharing::new(all_ids.clone()).unwrap()))
        .collect();

    (KeyResharingSharedData { ids: all_ids }, entry_points)
}

fn check_evidence<Ext>(extension: &Ext, expected_description: &str) -> Result<(), LocalError>
where
    Ext: RoundExtension<Id>,
    Ext::Round: Round<Id, Protocol = <KeyResharing<P, Id> as EntryPoint<Id>>::Protocol>,
{
    let (shared_data, entry_points) = make_entry_points();
    check_evidence_with_extension::<SP, _, _>(&mut OsRng, entry_points, extension, &shared_data, expected_description)
}
