//! KeyInit protocol, in the paper ECDSA Key-Generation (Fig. 6).
//! Note that this protocol only generates the key itself which is not enough to perform signing;
//! auxiliary parameters need to be generated as well (during the KeyRefresh protocol).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
};
use core::{fmt::Debug, marker::PhantomData};

use manul::{
    protocol::{
        BoxedRound, CommunicationInfo, EntryPoint, EvidenceError, EvidenceMessages, FinalizeOutcome, LocalError,
        NoArtifact, NoMessage, NoProtocolErrors, PartyId, Protocol, ProtocolError, ProtocolMessage, ReceiveError,
        RequiredMessageParts, RequiredMessages, Round, RoundId, RoundInfo, TransitionInfo,
    },
    utils::{GetOrLocalError, MapValues, MapValuesRef, Without, verify_that},
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    entities::{KeyShare, Sid},
    params::SchemeParams,
    tools::{
        Secret,
        bitvec::BitVec,
        hashing::{Chain, HashOutput, Hasher},
    },
    zk::{SchCommitment, SchProof, SchSecret},
};

/// A protocol that generates shares of a new secret key on each node.
#[derive(Debug)]
pub struct KeyInitProtocol<P: SchemeParams, Id: Debug>(PhantomData<(P, Id)>);

impl<P: SchemeParams, Id: PartyId> Protocol<Id> for KeyInitProtocol<P, Id> {
    type Result = KeyShare<P, Id>;
    type SharedData = KeyInitSharedData<Id>;
    fn round_info(round_id: &RoundId) -> Option<RoundInfo<Id, Self>> {
        match round_id {
            _ if round_id == 1 => Some(RoundInfo::new::<Round1<P, Id>>()),
            _ if round_id == 2 => Some(RoundInfo::new::<Round2<P, Id>>()),
            _ if round_id == 3 => Some(RoundInfo::new::<Round3<P, Id>>()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) struct R2Error<P> {
    error: R2ErrorEnum,
    phantom: PhantomData<fn() -> P>,
}

impl<P> From<R2ErrorEnum> for R2Error<P> {
    fn from(error: R2ErrorEnum) -> Self {
        Self {
            error,
            phantom: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum R2ErrorEnum {
    HashMismatch,
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for R2Error<P> {
    type Round = Round2<P, Id>;

    fn description(&self) -> String {
        match self.error {
            R2ErrorEnum::HashMismatch => "The previously sent hash does not match the public data.".into(),
        }
    }

    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        match self.error {
            R2ErrorEnum::HashMismatch => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
        }
    }

    fn verify_evidence(
        &self,
        _round_id: &RoundId,
        guilty_party: &Id,
        shared_randomness: &[u8],
        shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<'_, Id, Self::Round>,
    ) -> Result<(), EvidenceError> {
        let sid = Sid::new::<P, Id>(shared_randomness, &shared_data.ids);
        match self.error {
            R2ErrorEnum::HashMismatch => {
                let r1_eb = messages.previous_echo_broadcast::<Round1<P, Id>>(1)?;
                let r2_nb = messages.normal_broadcast()?;
                let r2_eb = messages.echo_broadcast()?;
                let data = PublicData {
                    cap_x: r2_nb.cap_x,
                    cap_a: r2_nb.cap_a,
                    u: r2_nb.u,
                    rho: r2_eb.rho,
                };
                verify_that(data.hash(&sid, guilty_party) != r1_eb.cap_v)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) struct R3Error<P> {
    error: R3ErrorEnum,
    phantom: PhantomData<fn() -> P>,
}

impl<P> From<R3ErrorEnum> for R3Error<P> {
    fn from(error: R3ErrorEnum) -> Self {
        Self {
            error,
            phantom: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum R3ErrorEnum {
    InvalidSchProof,
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for R3Error<P> {
    type Round = Round3<P, Id>;

    fn description(&self) -> String {
        match self.error {
            R3ErrorEnum::InvalidSchProof => "Failed to verify `П^{sch}`.".into(),
        }
    }

    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        match self.error {
            R3ErrorEnum::InvalidSchProof => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
        }
    }

    fn verify_evidence(
        &self,
        _round_id: &RoundId,
        guilty_party: &Id,
        shared_randomness: &[u8],
        shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<'_, Id, Self::Round>,
    ) -> Result<(), EvidenceError> {
        let sid = Sid::new::<P, Id>(shared_randomness, &shared_data.ids);
        match self.error {
            R3ErrorEnum::InvalidSchProof => {
                let r2_ebs = messages.combined_echos::<Round2<P, Id>>(2)?;
                let r2_nb = messages.previous_normal_broadcast::<Round2<P, Id>>(2)?;
                let r2_eb = messages.previous_echo_broadcast::<Round2<P, Id>>(2)?;
                let r3_nb = messages.normal_broadcast()?;

                let mut rho = r2_eb.rho;
                for message in r2_ebs.values() {
                    rho ^= &message.rho;
                }

                let aux = (&sid, guilty_party, &rho);
                verify_that(!r3_nb.psi.verify(&r2_nb.cap_a, &r2_nb.cap_x, &aux))
            }
        }
    }
}

/// Associated data for KeyInit protocol.
#[derive(Debug, Clone)]
pub struct KeyInitSharedData<Id> {
    /// IDs of all participating nodes.
    pub ids: BTreeSet<Id>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PublicData<P: SchemeParams> {
    cap_x: Point<P>,
    pub(super) cap_a: SchCommitment<P>,
    rho: BitVec,
    u: BitVec,
}

impl<P> PublicData<P>
where
    P: SchemeParams,
{
    pub(super) fn hash<Id: Serialize>(&self, sid: &Sid, id: &Id) -> HashOutput {
        Hasher::<P::Digest>::new_with_dst(b"KeyInit")
            .chain(sid)
            .chain(id)
            .chain(&self.cap_x)
            .chain(&self.cap_a)
            .chain(&self.rho)
            .chain(&self.u)
            .finalize(P::SECURITY_BITS)
    }
}

/// An entry point for the [`KeyInitProtocol`].
#[derive(Debug, Clone)]
pub struct KeyInit<P, Id> {
    all_ids: BTreeSet<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id: PartyId> KeyInit<P, Id> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<Id>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams, Id: PartyId> EntryPoint<Id> for KeyInit<P, Id> {
    type Protocol = KeyInitProtocol<P, Id>;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        if !self.all_ids.contains(id) {
            return Err(LocalError::new("The given node IDs must contain this node's ID"));
        }

        let other_ids = self.all_ids.clone().without(id);

        let sid = Sid::new::<P, Id>(shared_randomness, &self.all_ids);

        // The secret share
        let x = Secret::init_with(|| Scalar::random(rng));
        // The public share
        let cap_x = x.mul_by_generator();

        let rho = BitVec::random(rng, P::SECURITY_PARAMETER);
        let tau = SchSecret::random(rng);
        let cap_a = SchCommitment::new(&tau);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        let public_data = PublicData { cap_x, cap_a, rho, u };

        let context = Context {
            other_ids,
            my_id: id.clone(),
            x,
            tau,
            public_data,
            sid,
        };

        Ok(BoxedRound::new(Round1 { context }))
    }
}

#[derive(Debug)]
pub(super) struct Context<P: SchemeParams, Id> {
    pub(super) other_ids: BTreeSet<Id>,
    pub(super) my_id: Id,
    pub(super) x: Secret<Scalar<P>>,
    pub(super) tau: SchSecret<P>,
    pub(super) public_data: PublicData<P>,
    pub(super) sid: Sid,
}

#[derive(Debug)]
pub(super) struct Round1<P: SchemeParams, Id> {
    context: Context<P, Id>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round1EchoBroadcast {
    cap_v: HashOutput,
}

pub(super) struct Round1Payload {
    cap_v: HashOutput,
}

impl<P, Id> Round<Id> for Round1<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    type Protocol = KeyInitProtocol<P, Id>;

    type DirectMessage = NoMessage;
    type NormalBroadcast = NoMessage;
    type EchoBroadcast = Round1EchoBroadcast;

    type Payload = Round1Payload;
    type Artifact = NoArtifact;

    type ProtocolError = NoProtocolErrors<Self>;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear(1)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::EchoBroadcast, LocalError> {
        let cap_v = self.context.public_data.hash(&self.context.sid, &self.context.my_id);
        Ok(Round1EchoBroadcast { cap_v })
    }

    fn receive_message(
        &self,
        _from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        Ok(Round1Payload {
            cap_v: message.echo_broadcast.cap_v,
        })
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let cap_vs = payloads.map_values(|payload| payload.cap_v);
        let next_round = Round2 {
            context: self.context,
            cap_vs,
        };
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round2<P: SchemeParams, Id> {
    context: Context<P, Id>,
    cap_vs: BTreeMap<Id, HashOutput>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Round2EchoBroadcast {
    rho: BitVec,
}

#[derive(Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round2NormalBroadcast<P: SchemeParams> {
    cap_x: Point<P>,
    cap_a: SchCommitment<P>,
    pub(super) u: BitVec,
}

pub(super) struct Round2Payload<P: SchemeParams> {
    cap_x: Point<P>,
    cap_a: SchCommitment<P>,
    rho: BitVec,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round2<P, Id> {
    type Protocol = KeyInitProtocol<P, Id>;

    type DirectMessage = NoMessage;
    type NormalBroadcast = Round2NormalBroadcast<P>;
    type EchoBroadcast = Round2EchoBroadcast;

    type Payload = Round2Payload<P>;
    type Artifact = NoArtifact;

    type ProtocolError = R2Error<P>;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear(2)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::EchoBroadcast, LocalError> {
        Ok(Round2EchoBroadcast {
            rho: self.context.public_data.rho.clone(),
        })
    }

    fn make_normal_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::NormalBroadcast, LocalError> {
        Ok(Round2NormalBroadcast {
            cap_x: self.context.public_data.cap_x,
            cap_a: self.context.public_data.cap_a.clone(),
            u: self.context.public_data.u.clone(),
        })
    }

    fn receive_message(
        &self,
        from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        let cap_v = self.cap_vs.get_or_local_error("vector `V`", from)?;
        let data = PublicData {
            cap_x: message.normal_broadcast.cap_x,
            cap_a: message.normal_broadcast.cap_a,
            u: message.normal_broadcast.u,
            rho: message.echo_broadcast.rho,
        };

        if &data.hash(&self.context.sid, from) != cap_v {
            return Err(ReceiveError::Protocol(R2ErrorEnum::HashMismatch.into()));
        }

        Ok(Round2Payload {
            cap_x: data.cap_x,
            rho: data.rho,
            cap_a: data.cap_a,
        })
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let mut rho_combined = self.context.public_data.rho.clone();
        for payload in payloads.values() {
            rho_combined ^= &payload.rho;
        }

        let cap_xs = payloads.map_values_ref(|payload| payload.cap_x);
        let cap_as = payloads.map_values_ref(|payload| payload.cap_a.clone());

        let next_round = Round3 {
            context: self.context,
            cap_xs,
            cap_as,
            rho_combined,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round3<P: SchemeParams, Id> {
    pub(super) context: Context<P, Id>,
    pub(super) cap_xs: BTreeMap<Id, Point<P>>,
    pub(super) cap_as: BTreeMap<Id, SchCommitment<P>>,
    pub(super) rho_combined: BitVec,
}

#[derive(Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round3NormalBroadcast<P: SchemeParams> {
    pub(super) psi: SchProof<P>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round3<P, Id> {
    type Protocol = KeyInitProtocol<P, Id>;

    type DirectMessage = NoMessage;
    type NormalBroadcast = Round3NormalBroadcast<P>;
    type EchoBroadcast = NoMessage;

    type Payload = ();
    type Artifact = NoArtifact;

    type ProtocolError = R3Error<P>;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(3)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    fn make_normal_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::NormalBroadcast, LocalError> {
        let aux = (&self.context.sid, &self.context.my_id, &self.rho_combined);
        let psi = SchProof::new(
            &self.context.tau,
            &self.context.x,
            &self.context.public_data.cap_a,
            &self.context.public_data.cap_x,
            &aux,
        );
        Ok(Round3NormalBroadcast { psi })
    }

    fn receive_message(
        &self,
        from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        let cap_a = self.cap_as.get_or_local_error("`A` map", from)?;
        let cap_x = self.cap_xs.get_or_local_error("`X` map", from)?;

        let aux = (&self.context.sid, from, &self.rho_combined);
        if !message.normal_broadcast.psi.verify(cap_a, cap_x, &aux) {
            return Err(ReceiveError::Protocol(R3ErrorEnum::InvalidSchProof.into()));
        }
        Ok(())
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let my_id = self.context.my_id.clone();
        let mut public_shares = self.cap_xs;
        public_shares.insert(my_id.clone(), self.context.public_data.cap_x);

        // This can fail if the shares add up to zero.
        // Can't really protect from it, and it should be extremely rare.
        // If that happens one can only restart the whole thing.
        let key_share = KeyShare::<P, Id>::new(my_id, self.context.x, public_shares)?;

        Ok(FinalizeOutcome::Result(key_share))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier, run_sync},
        signature::Keypair,
        utils::MapValuesRef,
    };
    use rand_core::OsRng;

    use super::KeyInit;
    use crate::dev::TestParams;

    #[test]
    fn execute_keygen() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let id0 = signers[0].verifying_key();

        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let entry_point = KeyInit::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                (signer, entry_point)
            })
            .collect::<Vec<_>>();

        let shares = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        // Check that the sets of public keys are the same at each node
        let public_sets = shares.map_values_ref(|share| share.public_shares().clone());
        assert!(public_sets.values().all(|pk| pk == &public_sets[&id0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[&id0];
        let public_from_secret = shares.map_values_ref(|share| share.secret_share().mul_by_generator());
        assert!(public_set == &public_from_secret);
    }
}
