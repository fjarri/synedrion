//! AuxGen protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 7).
//!
//! This is a subset of the protocol that generates the auxiliary data, with share update bits removed.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
};
use core::{fmt::Debug, marker::PhantomData};

use crypto_bigint::BitOps;
use manul::{
    protocol::{
        BoxedRound, CommunicationInfo, EntryPoint, EvidenceError, EvidenceMessages, FinalizeOutcome, LocalError,
        NoArtifact, NoMessage, NoProtocolErrors, PartyId, Protocol, ProtocolError, ProtocolMessage, ReceiveError,
        RequiredMessageParts, RequiredMessages, Round, RoundId, RoundInfo, TransitionInfo,
    },
    utils::{GetOrInvalidEvidence, GetOrLocalError, MapValues, Without, verify_that},
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    entities::{AuxInfo, PublicAuxInfo, PublicAuxInfos, SecretAuxInfo, Sid},
    paillier::{
        PaillierParams, PublicKeyPaillier, PublicKeyPaillierWire, RPParams, RPParamsWire, RPSecret, SecretKeyPaillier,
        SecretKeyPaillierWire,
    },
    params::SchemeParams,
    tools::{
        bitvec::BitVec,
        hashing::{Chain, HashOutput, Hasher},
    },
    zk::{FacProof, ModProof, PrmProof},
};

/// A protocol for generating auxiliary information for signing.
#[derive(Debug)]
pub struct AuxGenProtocol<P: SchemeParams, Id: PartyId>(PhantomData<(P, Id)>);

impl<P: SchemeParams, Id: PartyId> Protocol<Id> for AuxGenProtocol<P, Id> {
    type Result = AuxInfo<P, Id>;
    type SharedData = AuxGenSharedData<Id>;
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
    PaillierModulusTooSmall,
    RPModulusTooSmall,
    PrmFailed,
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for R2Error<P> {
    type Round = Round2<P, Id>;

    fn description(&self) -> String {
        match self.error {
            R2ErrorEnum::HashMismatch => "The previously sent hash does not match the public data.",
            R2ErrorEnum::PaillierModulusTooSmall => "Paillier modulus is too small.",
            R2ErrorEnum::RPModulusTooSmall => "Ring-Pedersen modulus is too small.",
            R2ErrorEnum::PrmFailed => "`П^{prm}` verification failed.",
        }
        .into()
    }

    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        match self.error {
            R2ErrorEnum::HashMismatch => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast().and_echo_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            R2ErrorEnum::PaillierModulusTooSmall => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            R2ErrorEnum::RPModulusTooSmall => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            R2ErrorEnum::PrmFailed => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                None,
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

        match &self.error {
            R2ErrorEnum::HashMismatch => {
                let r1_eb = messages.previous_echo_broadcast::<Round1<P, Id>>(1)?;
                let r2_nb = messages.normal_broadcast()?;
                let r2_eb = messages.echo_broadcast()?;

                let data = PublicData {
                    paillier_pk: r2_nb.paillier_pk.into_precomputed(),
                    rp_params: r2_eb.rp_params.to_precomputed(),
                    psi: r2_nb.psi,
                    rid: r2_eb.rid,
                    u: r2_nb.u,
                };
                verify_that(data.hash(&sid, guilty_party) != r1_eb.cap_v)
            }
            R2ErrorEnum::PaillierModulusTooSmall => {
                let r2_nb = messages.normal_broadcast()?;
                verify_that(
                    r2_nb.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            R2ErrorEnum::RPModulusTooSmall => {
                let r2_eb = messages.echo_broadcast()?;
                verify_that(
                    r2_eb.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            R2ErrorEnum::PrmFailed => {
                let r2_eb = messages.echo_broadcast()?;
                let r2_nb = messages.normal_broadcast()?;
                let aux = (&sid, guilty_party);
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r2_nb.psi.verify(&rp_params, &aux))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct R3Error<P, Id: PartyId> {
    error: R3ErrorEnum<Id>,
    phantom: PhantomData<fn() -> P>,
}

impl<P, Id: PartyId> From<R3ErrorEnum<Id>> for R3Error<P, Id> {
    fn from(error: R3ErrorEnum<Id>) -> Self {
        Self {
            error,
            phantom: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[derive_where::derive_where(Serialize, Deserialize)]
enum R3ErrorEnum<Id: PartyId> {
    ModFailed,
    FacFailed {
        /// The index $i$ of the node that produced the evidence.
        reported_by: Id,
    },
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for R3Error<P, Id> {
    type Round = Round3<P, Id>;

    fn description(&self) -> String {
        match self.error {
            R3ErrorEnum::ModFailed => "`П^{mod}` verification failed.",
            R3ErrorEnum::FacFailed { .. } => "`П^{fac}` verification failed.",
        }
        .into()
    }

    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        match self.error {
            R3ErrorEnum::ModFailed => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            R3ErrorEnum::FacFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
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

        match &self.error {
            R3ErrorEnum::ModFailed => {
                let rid = reconstruct_rid::<P, _>(&messages)?;
                let aux = (&sid, guilty_party, &rid);
                let r2_nb = messages.previous_normal_broadcast::<Round2<P, Id>>(2)?;
                let r3_nb = messages.normal_broadcast()?;
                let paillier_pk = r2_nb.paillier_pk.into_precomputed();
                verify_that(!r3_nb.psi_prime.verify(&paillier_pk, &aux))
            }
            R3ErrorEnum::FacFailed { reported_by } => {
                let rid = reconstruct_rid::<P, _>(&messages)?;
                let aux = (&sid, guilty_party, &rid);

                let r2_eb = messages
                    .combined_echos::<Round2<P, Id>>(2)?
                    .get_or_invalid_evidence("combined echos for Round 2", reported_by)?
                    .clone();
                let r2_nb = messages.previous_normal_broadcast::<Round2<P, Id>>(2)?;
                let r3_dm = messages.direct_message()?;
                let paillier_pk = r2_nb.paillier_pk.into_precomputed();
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r3_dm.psi.verify(&paillier_pk, &rp_params, &aux))
            }
        }
    }
}

/// Reconstruct `rid` from echoed messages
fn reconstruct_rid<P: SchemeParams, Id: PartyId>(
    messages: &EvidenceMessages<'_, Id, Round3<P, Id>>,
) -> Result<BitVec, EvidenceError> {
    let r2_ebs = messages.combined_echos::<Round2<P, Id>>(2)?;
    let r2_eb = messages.previous_echo_broadcast::<Round2<P, Id>>(2)?;
    let mut rid_combined = r2_eb.rid;
    for message in r2_ebs.values() {
        rid_combined ^= &message.rid;
    }
    Ok(rid_combined)
}

/// Associated data for AuxGen protocol.
#[derive(Debug, Clone)]
pub struct AuxGenSharedData<Id> {
    /// IDs of all participating nodes.
    pub ids: BTreeSet<Id>,
}

#[derive(Debug, Clone)]
pub(super) struct PublicData<P: SchemeParams> {
    pub(super) paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    pub(super) rp_params: RPParams<P::Paillier>,            // $\hat{N}_i$, $s_i$, and $t_i$
    pub(super) psi: PrmProof<P>,
    rid: BitVec,
    u: BitVec,
}

impl<P: SchemeParams> PublicData<P> {
    pub(super) fn hash<Id: PartyId>(&self, sid: &Sid, id: &Id) -> HashOutput {
        Hasher::<P::Digest>::new_with_dst(b"KeyInit")
            .chain(sid)
            .chain(id)
            .chain(&self.paillier_pk.clone().into_wire())
            .chain(&self.rp_params.to_wire())
            .chain(&self.psi)
            .chain(&self.rid)
            .chain(&self.u)
            .finalize(P::SECURITY_BITS)
    }
}

/// An entry point for the [`AuxGenProtocol`].
#[derive(Debug, Clone)]
pub struct AuxGen<P, Id> {
    all_ids: BTreeSet<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id: PartyId> AuxGen<P, Id> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<Id>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P, Id> EntryPoint<Id> for AuxGen<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    type Protocol = AuxGenProtocol<P, Id>;

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

        // Paillier secret key $p_i$, $q_i$
        let paillier_sk = SecretKeyPaillierWire::<P::Paillier>::random(rng);
        // Paillier public key $N_i$
        let paillier_pk = paillier_sk.public_key();

        // Ring-Pedersen secret $\lambda$.
        let rp_secret = RPSecret::random(rng);
        // Ring-Pedersen parameters ($N$, $s$, $t$) bundled in a single object.
        let rp_params = RPParams::random_with_secret(rng, &rp_secret);

        let aux = (&sid, id);
        let psi = PrmProof::<P>::new(rng, &rp_secret, &rp_params, &aux);

        let rid = BitVec::random(rng, P::SECURITY_PARAMETER);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        // Note: typo in the paper, $V$ hashes in $B_i$ which is not present in the '24 version of the paper.
        let public_data = PublicData {
            paillier_pk: paillier_pk.into_precomputed(),
            rp_params: rp_params.clone(),
            psi,
            rid,
            u,
        };

        let context = Context {
            paillier_sk: paillier_sk.into_precomputed(),
            rp_params,
            my_id: id.clone(),
            other_ids,
            sid,
        };

        let round = Round1 { context, public_data };

        Ok(BoxedRound::new(round))
    }
}

#[derive(Debug)]
pub(super) struct Context<P: SchemeParams, Id> {
    paillier_sk: SecretKeyPaillier<P::Paillier>,
    rp_params: RPParams<P::Paillier>,
    pub(super) my_id: Id,
    other_ids: BTreeSet<Id>,
    pub(super) sid: Sid,
}

#[derive(Debug)]
pub(super) struct Round1<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    pub(super) public_data: PublicData<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round1EchoBroadcast {
    pub(super) cap_v: HashOutput,
}

pub(super) struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round1<P, Id> {
    type Protocol = AuxGenProtocol<P, Id>;

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
        Ok(Round1EchoBroadcast {
            cap_v: self.public_data.hash(&self.context.sid, &self.context.my_id),
        })
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
            public_data: self.public_data,
            cap_vs,
        };
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round2<P: SchemeParams, Id: PartyId> {
    context: Context<P, Id>,
    public_data: PublicData<P>,
    cap_vs: BTreeMap<Id, HashOutput>,
}

#[derive(Debug, Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round2NormalBroadcast<P: SchemeParams> {
    pub(super) paillier_pk: PublicKeyPaillierWire<P::Paillier>, // $N_i$
    pub(super) psi: PrmProof<P>,
    u: BitVec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round2EchoBroadcast<P: SchemeParams> {
    pub(super) rp_params: RPParamsWire<P::Paillier>, // $\hat{N}_i$, $s_i$, and $t_i$
    rid: BitVec,
}

#[derive(Debug)]
pub(super) struct Round2Payload<P: SchemeParams> {
    paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    rp_params: RPParams<P::Paillier>,            // $\hat{N}_i$, $s_i$, and $t_i$
    rid: BitVec,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round2<P, Id> {
    type Protocol = AuxGenProtocol<P, Id>;

    type DirectMessage = NoMessage;
    type NormalBroadcast = Round2NormalBroadcast<P>;
    type EchoBroadcast = Round2EchoBroadcast<P>;

    type Payload = Round2Payload<P>;
    type Artifact = NoArtifact;

    type ProtocolError = R2Error<P>;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear(2)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    fn make_normal_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::NormalBroadcast, LocalError> {
        Ok(Round2NormalBroadcast {
            paillier_pk: self.public_data.paillier_pk.clone().into_wire(),
            psi: self.public_data.psi.clone(),
            u: self.public_data.u.clone(),
        })
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::EchoBroadcast, LocalError> {
        Ok(Round2EchoBroadcast::<P> {
            rid: self.public_data.rid.clone(),
            rp_params: self.public_data.rp_params.to_wire(),
        })
    }

    fn receive_message(
        &self,
        from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        let echo_broadcast = message.echo_broadcast;
        let normal_broadcast = message.normal_broadcast;

        let data = PublicData {
            paillier_pk: normal_broadcast.paillier_pk.into_precomputed(),
            rp_params: echo_broadcast.rp_params.to_precomputed(),
            psi: normal_broadcast.psi,
            rid: echo_broadcast.rid,
            u: normal_broadcast.u,
        };

        let cap_v = self.cap_vs.get_or_local_error("other nodes' `V`", from)?;

        if &data.hash(&self.context.sid, from) != cap_v {
            return Err(ReceiveError::Protocol(R2ErrorEnum::HashMismatch.into()));
        }

        if data.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::Protocol(R2ErrorEnum::PaillierModulusTooSmall.into()));
        }

        if data.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::Protocol(R2ErrorEnum::RPModulusTooSmall.into()));
        }

        let aux = (&self.context.sid, &from);
        if !data.psi.verify(&data.rp_params, &aux) {
            return Err(ReceiveError::Protocol(R2ErrorEnum::PrmFailed.into()));
        }

        Ok(Round2Payload::<P> {
            paillier_pk: data.paillier_pk,
            rp_params: data.rp_params,
            rid: data.rid,
        })
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let mut payloads = payloads;

        let mut rid_combined = self.public_data.rid.clone();
        for payload in payloads.values() {
            rid_combined ^= &payload.rid;
        }

        let my_id = &self.context.my_id;
        let aux = (&self.context.sid, my_id, &rid_combined);
        let psi_prime = ModProof::new(rng, &self.context.paillier_sk, &aux);

        // Add in the payload with this node's info, for the sake of uniformity
        let my_r2_payload = Round2Payload::<P> {
            paillier_pk: self.public_data.paillier_pk,
            rp_params: self.public_data.rp_params,
            rid: self.public_data.rid,
        };
        payloads.insert(self.context.my_id.clone(), my_r2_payload);

        let next_round = Round3 {
            context: self.context,
            r2_payloads: payloads,
            rid_combined,
            psi_prime,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round3<P: SchemeParams, Id> {
    context: Context<P, Id>,
    rid_combined: BitVec,
    r2_payloads: BTreeMap<Id, Round2Payload<P>>,
    psi_prime: ModProof<P>,
}

#[derive(Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round3NormalBroadcast<P: SchemeParams> {
    pub(super) psi_prime: ModProof<P>,
}

#[derive(Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round3DirectMessage<P: SchemeParams> {
    pub(super) psi: FacProof<P>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round3<P, Id> {
    type Protocol = AuxGenProtocol<P, Id>;

    type DirectMessage = Round3DirectMessage<P>;
    type NormalBroadcast = Round3NormalBroadcast<P>;
    type EchoBroadcast = NoMessage;

    type Payload = ();
    type Artifact = ();

    type ProtocolError = R3Error<P, Id>;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(3)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    fn make_normal_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::NormalBroadcast, LocalError> {
        Ok(Round3NormalBroadcast {
            psi_prime: self.psi_prime.clone(),
        })
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(Self::DirectMessage, Self::Artifact), LocalError> {
        let my_id = &self.context.my_id;
        let aux = (&self.context.sid, my_id, &self.rid_combined);

        let r2_payload = self.r2_payloads.get_or_local_error("Round 2 payloads", destination)?;

        let psi = FacProof::<P>::new(rng, &self.context.paillier_sk, &r2_payload.rp_params, &aux);

        Ok((Round3DirectMessage { psi }, ()))
    }

    fn receive_message(
        &self,
        from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        let normal_broadcast = message.normal_broadcast;
        let direct_message = message.direct_message;

        let my_id = &self.context.my_id;

        let r2_payload = self.r2_payloads.get_or_local_error("Round 2 payloads", from)?;

        let aux = (&self.context.sid, from, &self.rid_combined);
        if !normal_broadcast.psi_prime.verify(&r2_payload.paillier_pk, &aux) {
            return Err(ReceiveError::Protocol(R3ErrorEnum::ModFailed.into()));
        }

        if !direct_message
            .psi
            .verify(&r2_payload.paillier_pk, &self.context.rp_params, &aux)
        {
            return Err(ReceiveError::Protocol(
                R3ErrorEnum::FacFailed {
                    reported_by: my_id.clone(),
                }
                .into(),
            ));
        }

        Ok(())
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let my_id = &self.context.my_id;

        let public_aux = self.r2_payloads.map_values(|payload| PublicAuxInfo {
            paillier_pk: payload.paillier_pk.into_wire(),
            rp_params: payload.rp_params.to_wire(),
        });

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.into_wire(),
        };

        let aux_info = AuxInfo {
            owner: my_id.clone(),
            secret: secret_aux,
            public: PublicAuxInfos(public_aux.into()),
        };

        Ok(FinalizeOutcome::Result(aux_info))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier, run_sync},
        signature::Keypair,
    };
    use rand_core::OsRng;

    use super::AuxGen;
    use crate::dev::TestParams;

    #[test]
    fn execute_aux_gen() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();

        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let entry_point = AuxGen::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                (signer, entry_point)
            })
            .collect::<Vec<_>>();

        let _aux_infos = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();
    }
}
