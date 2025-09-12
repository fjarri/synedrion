//! KeyRefresh protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 7).
//! This protocol generates an update to the secret key shares and new auxiliary parameters
//! for ZK proofs (e.g. Paillier keys).

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
    utils::{GetOrInvalidEvidence, GetOrLocalError, MapValues, MapValuesRef, SerializableMap, Without, verify_that},
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar, secret_split},
    entities::{AuxInfo, KeyShareChange, PublicAuxInfo, PublicAuxInfos, SecretAuxInfo, Sid},
    paillier::{
        PaillierParams, PublicKeyPaillier, PublicKeyPaillierWire, RPParams, RPParamsWire, RPSecret, SecretKeyPaillier,
        SecretKeyPaillierWire,
    },
    params::SchemeParams,
    tools::{
        Secret,
        bitvec::BitVec,
        hashing::{Chain, HashOutput, Hasher},
    },
    zk::{FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret},
};

/// A protocol for generating auxiliary information for signing,
/// and a simultaneous generation of updates for the secret key shares.
#[derive(Debug)]
pub struct KeyRefreshProtocol<P: SchemeParams, Id: PartyId>(PhantomData<(P, Id)>);

impl<P, Id> Protocol<Id> for KeyRefreshProtocol<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    type Result = (KeyShareChange<P, Id>, AuxInfo<P, Id>);
    type SharedData = KeyRefreshSharedData<Id>;
    fn round_info(round_id: &RoundId) -> Option<RoundInfo<Id, Self>> {
        match round_id {
            _ if round_id == 1 => Some(RoundInfo::new::<Round1<P, Id>>()),
            _ if round_id == 2 => Some(RoundInfo::new::<Round2<P, Id>>()),
            _ if round_id == 3 => Some(RoundInfo::new::<Round3<P, Id>>()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct R2Error<P> {
    error: R2ErrorEnum,
    phantom: PhantomData<fn() -> P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum R2ErrorEnum {
    HashMismatch,
    WrongIdsX,
    WrongIdsY,
    WrongIdsA,
    PaillierModulusTooSmall,
    RPModulusTooSmall,
    NonZeroSumOfChanges,
    PrmFailed,
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for R2Error<P> {
    type Round = Round2<P, Id>;

    fn description(&self) -> String {
        match self.error {
            R2ErrorEnum::HashMismatch => "The previously sent hash does not match the public data.".into(),
            R2ErrorEnum::WrongIdsX => "Wrong IDs in public shares map.".into(),
            R2ErrorEnum::WrongIdsY => "Wrong IDs in Elgamal keys map.".into(),
            R2ErrorEnum::WrongIdsA => "Wrong IDs in Schnorr commitments map.".into(),
            R2ErrorEnum::PaillierModulusTooSmall => "Paillier modulus is too small.".into(),
            R2ErrorEnum::RPModulusTooSmall => "Ring-Pedersen modulus is too small.".into(),
            R2ErrorEnum::NonZeroSumOfChanges => "Sum of share changes is not zero.".into(),
            R2ErrorEnum::PrmFailed => "`П^{prm}` verification failed.".into(),
        }
    }

    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        match self.error {
            R2ErrorEnum::HashMismatch => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast().and_echo_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            R2ErrorEnum::WrongIdsX => RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None),
            R2ErrorEnum::WrongIdsY => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            R2ErrorEnum::WrongIdsA => RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None),
            R2ErrorEnum::PaillierModulusTooSmall => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            R2ErrorEnum::RPModulusTooSmall => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            R2ErrorEnum::NonZeroSumOfChanges => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
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
                    cap_xs: r2_nb.cap_xs.into(),
                    cap_ys: r2_eb.cap_ys.into(),
                    cap_as: r2_nb.cap_as.into(),
                    paillier_pk: r2_nb.paillier_pk.into_precomputed(),
                    rp_params: r2_eb.rp_params.to_precomputed(),
                    psi: r2_nb.psi,
                    rid: r2_eb.rid,
                    u: r2_nb.u,
                };
                verify_that(data.hash(&sid, guilty_party) != r1_eb.cap_v)
            }
            R2ErrorEnum::WrongIdsX => {
                let r2_nb = messages.normal_broadcast()?;
                verify_that(r2_nb.cap_xs.keys().cloned().collect::<BTreeSet<_>>() != shared_data.ids)
            }
            R2ErrorEnum::WrongIdsY => {
                let r2_eb = messages.echo_broadcast()?;
                verify_that(r2_eb.cap_ys.keys().cloned().collect::<BTreeSet<_>>() != shared_data.ids)
            }
            R2ErrorEnum::WrongIdsA => {
                let r2_nb = messages.normal_broadcast()?;
                verify_that(r2_nb.cap_as.keys().cloned().collect::<BTreeSet<_>>() != shared_data.ids)
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
            R2ErrorEnum::NonZeroSumOfChanges => {
                let r2_nb = messages.normal_broadcast()?;
                verify_that(r2_nb.cap_xs.values().sum::<Point<P>>() != Point::identity())
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

#[derive(Debug, Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) enum R3Error<P: SchemeParams, Id: PartyId> {
    ShareChangeMismatch {
        /// The index $i$ of the node that produced the evidence.
        reported_by: Id,
        /// $y_{i,j}$, where where $j$ is the index of the guilty party.
        y: Scalar<P>,
    },
    ModFailed,
    FacFailed {
        /// The index $i$ of the node that produced the evidence.
        reported_by: Id,
    },
    WrongIdsHatPsi,
    SchFailed {
        /// The index $k$ for which the verification of $\hat{\psi}_{j,k}$ failed
        /// (where $j$ is the index of the guilty party).
        failed_for: Id,
    },
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for R3Error<P, Id> {
    type Round = Round3<P, Id>;

    fn description(&self) -> String {
        match self {
            Self::ShareChangeMismatch { .. } => "Secret share change does not match the public commitment.".into(),
            Self::ModFailed => "`П^{mod}` verification failed.".into(),
            Self::FacFailed { .. } => "`П^{fac}` verification failed.".into(),
            Self::WrongIdsHatPsi => "Wrong IDs in Schnorr proofs map.".into(),
            Self::SchFailed { .. } => "`П^{sch}` verification failed.".into(),
        }
    }

    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        match self {
            Self::ShareChangeMismatch { .. } => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            Self::ModFailed => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            Self::FacFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            Self::WrongIdsHatPsi => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Self::SchFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
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

        match self {
            Self::ShareChangeMismatch { reported_by, y } => {
                // Check that `y` attached to the evidence is correct
                // (that is, can be verified against something signed by `guilty_party`).
                // It is `y_{i,j}` where `i == reported_by` and `j == guilty_party`
                let r2_eb_i = messages
                    .combined_echos::<Round2<P, Id>>(2)?
                    .get_or_invalid_evidence("Round 2 echoed messsages", reported_by)?
                    .clone();
                let cap_y_ij = r2_eb_i
                    .cap_ys
                    .get_or_invalid_evidence("public Elgamal values", guilty_party)?;
                if &y.mul_by_generator() != cap_y_ij {
                    return Err(EvidenceError::InvalidEvidence("The provided `y` is invalid".into()));
                }

                let rid = reconstruct_rid::<P, _>(&messages)?;

                let r2_eb = messages.previous_echo_broadcast::<Round2<P, Id>>(2)?;
                let cap_y_ji = r2_eb
                    .cap_ys
                    .get_or_invalid_evidence("public Elgamal values", reported_by)?;
                let mut reader = Hasher::<P::Digest>::new_with_dst(b"KeyRefresh Round3")
                    .chain(&sid)
                    .chain(&rid)
                    .chain(guilty_party)
                    .chain(&(cap_y_ji * y))
                    .finalize_to_reader();
                let rho = Scalar::from_xof_reader(&mut reader);

                let r2_nb = messages.previous_normal_broadcast::<Round2<P, Id>>(2)?;
                let r3_dm = messages.direct_message()?;

                let x = r3_dm.cap_c - rho;
                let cap_x_ji = r2_nb
                    .cap_xs
                    .get_or_invalid_evidence("public key share changes", reported_by)?;
                verify_that(&x.mul_by_generator() != cap_x_ji)
            }
            Self::ModFailed => {
                let rid = reconstruct_rid::<P, _>(&messages)?;
                let aux = (&sid, guilty_party, &rid);
                let r2_nb = messages.previous_normal_broadcast::<Round2<P, Id>>(2)?;
                let r3_nb = messages.normal_broadcast()?;
                let paillier_pk = r2_nb.paillier_pk.into_precomputed();
                verify_that(!r3_nb.psi_prime.verify(&paillier_pk, &aux))
            }
            Self::FacFailed { reported_by } => {
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
            Self::WrongIdsHatPsi => {
                let r3_eb = messages.echo_broadcast()?;
                verify_that(r3_eb.hat_psis.keys().cloned().collect::<BTreeSet<_>>() != shared_data.ids)
            }
            Self::SchFailed { failed_for } => {
                let rid = reconstruct_rid::<P, _>(&messages)?;
                let aux = (&sid, guilty_party, &rid);

                let r2_bc = messages.previous_normal_broadcast::<Round2<P, Id>>(2)?;
                let r3_eb = messages.echo_broadcast()?;

                let cap_a = r2_bc
                    .cap_as
                    .get_or_invalid_evidence("Schnorr commitments", failed_for)?;
                let cap_x = r2_bc
                    .cap_xs
                    .get_or_invalid_evidence("public share changes", failed_for)?;
                let hat_psi = r3_eb.hat_psis.get_or_invalid_evidence("Schnorr proofs", failed_for)?;
                verify_that(!hat_psi.verify(cap_a, cap_x, &aux))
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

/// Associated data for KeyRefresh protocol.
#[derive(Debug, Clone)]
pub struct KeyRefreshSharedData<Id> {
    /// IDs of all participating nodes.
    pub ids: BTreeSet<Id>,
}

#[derive(Debug, Clone)]
pub(super) struct PublicData<P: SchemeParams, Id> {
    pub(super) cap_xs: BTreeMap<Id, Point<P>>, // $X_{i,j}$ where $i$ is this party's index
    pub(super) cap_ys: BTreeMap<Id, Point<P>>, // $Y_{i,j}$ where $i$ is this party's index
    pub(super) cap_as: BTreeMap<Id, SchCommitment<P>>, // $A_{i,j}$ where $i$ is this party's index
    pub(super) paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    pub(super) rp_params: RPParams<P::Paillier>, // $\hat{N}_i$, $s_i$, and $t_i$
    pub(super) psi: PrmProof<P>,
    rid: BitVec,
    u: BitVec,
}

impl<P: SchemeParams, Id: PartyId> PublicData<P, Id> {
    pub(super) fn hash(&self, sid: &Sid, id: &Id) -> HashOutput {
        Hasher::<P::Digest>::new_with_dst(b"KeyInit")
            .chain(sid)
            .chain(id)
            .chain(&self.cap_xs)
            .chain(&self.cap_ys)
            .chain(&self.cap_as)
            .chain(&self.paillier_pk.clone().into_wire())
            .chain(&self.rp_params.to_wire())
            .chain(&self.psi)
            .chain(&self.rid)
            .chain(&self.u)
            .finalize(P::SECURITY_BITS)
    }
}

/// An entry point for the [`KeyRefreshProtocol`].
#[derive(Debug, Clone)]
pub struct KeyRefresh<P, Id> {
    all_ids: BTreeSet<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id: PartyId> KeyRefresh<P, Id> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<Id>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams, Id: PartyId> EntryPoint<Id> for KeyRefresh<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

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

        // Ephemeral DH keys $y_{i,j}$ where $i$ is this party's index.
        let ys = self
            .all_ids
            .iter()
            .cloned()
            .map(|id| (id, Secret::init_with(|| Scalar::random(rng))))
            .collect::<BTreeMap<_, _>>();
        // Corresponding public keys $Y_{i,j}$.
        let cap_ys = ys.map_values_ref(|y| y.mul_by_generator());

        // Secret share updates for each node ($x_{i,j}$ where $i$ is this party's index).
        let split_zero = secret_split(rng, Secret::init_with(|| Scalar::ZERO), self.all_ids.len());
        let xs = self.all_ids.iter().cloned().zip(split_zero).collect::<BTreeMap<_, _>>();

        // Public counterparts of secret share updates ($X_i^j$ where $i$ is this party's index).
        let cap_xs = xs.map_values_ref(|x| x.mul_by_generator());

        // Schnorr proof secrets $\tau_j$
        let taus = self
            .all_ids
            .iter()
            .map(|id| (id.clone(), SchSecret::random(rng)))
            .collect::<BTreeMap<_, _>>();

        // Schnorr commitments for share changes ($A_{i,j}$ where $i$ is this party's index)
        let cap_as = taus.map_values_ref(SchCommitment::new);

        let rid = BitVec::random(rng, P::SECURITY_PARAMETER);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        // Note: typo in the paper, $V$ hashes in $B_i$ which is not present in the '24 version of the paper.
        let public_data = PublicData {
            cap_xs,
            cap_ys,
            cap_as,
            paillier_pk: paillier_pk.into_precomputed(),
            rp_params: rp_params.clone(),
            psi,
            rid,
            u,
        };

        let context = Context {
            paillier_sk: paillier_sk.into_precomputed(),
            rp_params,
            xs,
            ys,
            taus,
            my_id: id.clone(),
            other_ids,
            all_ids: self.all_ids,
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
    xs: BTreeMap<Id, Secret<Scalar<P>>>, // $x_{i,j}$ where $i$ is this party's index
    ys: BTreeMap<Id, Secret<Scalar<P>>>, // $y_{i,j}$ where $i$ is this party's index
    taus: BTreeMap<Id, SchSecret<P>>,
    pub(super) my_id: Id,
    other_ids: BTreeSet<Id>,
    all_ids: BTreeSet<Id>,
    pub(super) sid: Sid,
}

#[derive(Debug)]
pub(super) struct Round1<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    pub(super) public_data: PublicData<P, Id>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round1EchoBroadcast {
    pub(super) cap_v: HashOutput,
}

pub(super) struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round1<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

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
    public_data: PublicData<P, Id>,
    cap_vs: BTreeMap<Id, HashOutput>,
}

#[derive(Debug, Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round2NormalBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) cap_xs: SerializableMap<Id, Point<P>>, // $X_{i,j}$ where $i$ is this party's index
    pub(super) cap_as: SerializableMap<Id, SchCommitment<P>>, // $A_{i,j}$ where $i$ is this party's index
    pub(super) paillier_pk: PublicKeyPaillierWire<P::Paillier>, // $N_i$
    pub(super) psi: PrmProof<P>,
    u: BitVec,
}

#[derive(Debug, Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round2EchoBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) rp_params: RPParamsWire<P::Paillier>, // $\hat{N}_i$, $s_i$, and $t_i$
    pub(super) cap_ys: SerializableMap<Id, Point<P>>, // $Y_{i,j}$ where $i$ is this party's index
    rid: BitVec,
}

#[derive(Debug)]
pub(super) struct Round2Payload<P: SchemeParams, Id> {
    cap_xs: BTreeMap<Id, Point<P>>,              // $X_{i,j}$ where $i$ is this party's index
    cap_as: BTreeMap<Id, SchCommitment<P>>,      // $A_{i,j}$ where $i$ is this party's index
    cap_ys: BTreeMap<Id, Point<P>>,              // $Y_{i,j}$ where $i$ is this party's index
    paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    rp_params: RPParams<P::Paillier>,            // $\hat{N}_i$, $s_i$, and $t_i$
    rid: BitVec,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round2<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

    type DirectMessage = NoMessage;
    type NormalBroadcast = Round2NormalBroadcast<P, Id>;
    type EchoBroadcast = Round2EchoBroadcast<P, Id>;

    type Payload = Round2Payload<P, Id>;
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
            cap_xs: self.public_data.cap_xs.clone().into(),
            cap_as: self.public_data.cap_as.clone().into(),
            paillier_pk: self.public_data.paillier_pk.clone().into_wire(),
            psi: self.public_data.psi.clone(),
            u: self.public_data.u.clone(),
        })
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::EchoBroadcast, LocalError> {
        Ok(Round2EchoBroadcast::<P, Id> {
            cap_ys: self.public_data.cap_ys.clone().into(),
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
            cap_xs: normal_broadcast.cap_xs.into(),
            cap_ys: echo_broadcast.cap_ys.into(),
            cap_as: normal_broadcast.cap_as.into(),
            paillier_pk: normal_broadcast.paillier_pk.into_precomputed(),
            rp_params: echo_broadcast.rp_params.to_precomputed(),
            psi: normal_broadcast.psi,
            rid: echo_broadcast.rid,
            u: normal_broadcast.u,
        };

        let cap_v = self.cap_vs.get_or_local_error("other nodes' `V`", from)?;

        if &data.hash(&self.context.sid, from) != cap_v {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::HashMismatch,
                phantom: PhantomData,
            }));
        }

        if data.cap_xs.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::WrongIdsX,
                phantom: PhantomData,
            }));
        }

        if data.cap_ys.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::WrongIdsY,
                phantom: PhantomData,
            }));
        }

        if data.cap_as.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::WrongIdsA,
                phantom: PhantomData,
            }));
        }

        if data.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::PaillierModulusTooSmall,
                phantom: PhantomData,
            }));
        }

        if data.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::RPModulusTooSmall,
                phantom: PhantomData,
            }));
        }

        if data.cap_xs.values().sum::<Point<P>>() != Point::identity() {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::NonZeroSumOfChanges,
                phantom: PhantomData,
            }));
        }

        let aux = (&self.context.sid, &from);
        if !data.psi.verify(&data.rp_params, &aux) {
            return Err(ReceiveError::Protocol(R2Error {
                error: R2ErrorEnum::PrmFailed,
                phantom: PhantomData,
            }));
        }

        Ok(Round2Payload {
            cap_xs: data.cap_xs,
            cap_as: data.cap_as,
            cap_ys: data.cap_ys,
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
        let mut rid_combined = self.public_data.rid.clone();
        for payload in payloads.values() {
            rid_combined ^= &payload.rid;
        }

        let my_id = &self.context.my_id;
        let aux = (&self.context.sid, my_id, &rid_combined);
        let psi_prime = ModProof::new(rng, &self.context.paillier_sk, &aux);

        let mut hat_psis = BTreeMap::new();
        for id in self.context.all_ids.iter() {
            let x = self.context.xs.get_or_local_error("secret share changes", id)?;
            let tau = self.context.taus.get_or_local_error("Schnorr secrets", id)?;
            let cap_a = self.public_data.cap_as.get_or_local_error("Schnorr commitments", id)?;
            let cap_x = self.public_data.cap_xs.get_or_local_error("public share changes", id)?;
            let hat_psi = SchProof::new(tau, x, cap_a, cap_x, &aux);
            hat_psis.insert(id.clone(), hat_psi);
        }

        // Add in the payload with this node's info, for the sake of uniformity
        let mut payloads = payloads;
        let my_r2_payload = Round2Payload::<P, Id> {
            cap_xs: self.public_data.cap_xs,
            cap_as: self.public_data.cap_as,
            cap_ys: self.public_data.cap_ys,
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
            hat_psis,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round3<P: SchemeParams, Id> {
    context: Context<P, Id>,
    rid_combined: BitVec,
    r2_payloads: BTreeMap<Id, Round2Payload<P, Id>>,
    psi_prime: ModProof<P>,
    hat_psis: BTreeMap<Id, SchProof<P>>,
}

#[derive(Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(super) struct Round3EchoBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) hat_psis: SerializableMap<Id, SchProof<P>>,
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
    pub(super) cap_c: Scalar<P>,
}

pub(super) struct Round3Payload<P: SchemeParams> {
    x: Secret<Scalar<P>>, // $x_j^i$, a secret share change received from the party $j$
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round3<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

    type DirectMessage = Round3DirectMessage<P>;
    type NormalBroadcast = Round3NormalBroadcast<P>;
    type EchoBroadcast = Round3EchoBroadcast<P, Id>;

    type Payload = Round3Payload<P>;
    type Artifact = ();

    type ProtocolError = R3Error<P, Id>;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(3)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::EchoBroadcast, LocalError> {
        Ok(Round3EchoBroadcast {
            hat_psis: self.hat_psis.clone().into(),
        })
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

        let cap_y = r2_payload.cap_ys.get_or_local_error("Elgamal public keys", my_id)?;
        let y = self.context.ys.get_or_local_error("Elgamal secrets", destination)?;
        let mut reader = Hasher::<P::Digest>::new_with_dst(b"KeyRefresh Round3")
            .chain(&self.context.sid)
            .chain(&self.rid_combined)
            .chain(my_id)
            .chain(&(cap_y * y))
            .finalize_to_reader();
        let rho = Scalar::from_xof_reader(&mut reader);
        let x = self
            .context
            .xs
            .get_or_local_error("secret share changes", destination)?;
        let cap_c = *(x + &rho).expose_secret();

        Ok((Round3DirectMessage { psi, cap_c }, ()))
    }

    fn receive_message(
        &self,
        from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        let echo_broadcast = message.echo_broadcast;
        let normal_broadcast = message.normal_broadcast;
        let direct_message = message.direct_message;

        let my_id = &self.context.my_id;

        let r2_payload = self.r2_payloads.get_or_local_error("Round 2 payloads", from)?;
        let cap_y = r2_payload.cap_ys.get_or_local_error("Elgamal public keys", my_id)?;
        let y = self.context.ys.get_or_local_error("Elgamal secrets", from)?;
        let mut reader = Hasher::<P::Digest>::new_with_dst(b"KeyRefresh Round3")
            .chain(&self.context.sid)
            .chain(&self.rid_combined)
            .chain(from)
            .chain(&(cap_y * y))
            .finalize_to_reader();
        let rho = Scalar::from_xof_reader(&mut reader);

        let x = Secret::init_with(|| direct_message.cap_c - rho);
        let my_cap_x = r2_payload.cap_xs.get_or_local_error("public share changes", my_id)?;
        if &x.mul_by_generator() != my_cap_x {
            return Err(ReceiveError::Protocol(R3Error::ShareChangeMismatch {
                reported_by: my_id.clone(),
                y: *y.expose_secret(),
            }));
        }

        let aux = (&self.context.sid, from, &self.rid_combined);
        if !normal_broadcast.psi_prime.verify(&r2_payload.paillier_pk, &aux) {
            return Err(ReceiveError::Protocol(R3Error::ModFailed));
        }

        if !direct_message
            .psi
            .verify(&r2_payload.paillier_pk, &self.context.rp_params, &aux)
        {
            return Err(ReceiveError::Protocol(R3Error::FacFailed {
                reported_by: my_id.clone(),
            }));
        }

        if echo_broadcast.hat_psis.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::Protocol(R3Error::WrongIdsHatPsi));
        }

        for (id, hat_psi) in echo_broadcast.hat_psis.iter() {
            let cap_a = r2_payload.cap_as.get_or_local_error("Schnorr commitments", id)?;
            let cap_x = r2_payload.cap_xs.get_or_local_error("Public share changes", id)?;
            if !hat_psi.verify(cap_a, cap_x, &aux) {
                return Err(ReceiveError::Protocol(R3Error::SchFailed { failed_for: id.clone() }));
            }
        }

        Ok(Round3Payload { x })
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let my_id = &self.context.my_id;

        // Share changes from other nodes
        let xs = payloads.map_values(|payload| payload.x);

        // Share change generated by this node
        let my_x = self.context.xs.get_or_local_error("secret share changes", my_id)?;

        // The combined secret share change
        let x_star = xs.into_values().sum::<Secret<Scalar<P>>>() + my_x;

        // The combined public share changes for each node
        let mut cap_x_star = BTreeMap::new();

        for id_k in self.context.all_ids.iter() {
            let mut result = Point::identity();
            for payload in self.r2_payloads.values() {
                let cap_x = payload.cap_xs.get_or_local_error("public share changes", id_k)?;
                result = result + *cap_x;
            }
            cap_x_star.insert(id_k.clone(), result);
        }

        let public_aux = self.r2_payloads.map_values(|payload| PublicAuxInfo {
            paillier_pk: payload.paillier_pk.into_wire(),
            rp_params: payload.rp_params.to_wire(),
        });

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.into_wire(),
        };

        let key_share_change = KeyShareChange {
            owner: my_id.clone(),
            secret_share_change: x_star,
            public_share_changes: cap_x_star.into(),
        };

        let aux_info = AuxInfo {
            owner: my_id.clone(),
            secret: secret_aux,
            public: PublicAuxInfos(public_aux.into()),
        };

        Ok(FinalizeOutcome::Result((key_share_change, aux_info)))
    }
}

#[cfg(test)]
mod tests {

    use alloc::collections::BTreeSet;

    use manul::{
        dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier, run_sync},
        signature::Keypair,
        utils::MapValues,
    };
    use rand_core::OsRng;

    use super::KeyRefresh;
    use crate::{curve::Scalar, dev::TestParams};

    #[test]
    fn execute_key_refresh() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();

        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let entry_point = KeyRefresh::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                (signer, entry_point)
            })
            .collect::<Vec<_>>();

        let results = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        let changes = results.map_values(|(change, _aux_info)| change);

        // Check that public points correspond to secret scalars
        for (id, change) in changes.iter() {
            for other_change in changes.values() {
                assert_eq!(
                    change.secret_share_change.mul_by_generator(),
                    other_change.public_share_changes[id]
                );
            }
        }

        // The resulting sum of masks should be zero, since the combined secret key
        // should not change after applying the masks at each node.
        let mask_sum: Scalar<TestParams> = changes
            .values()
            .map(|change| change.secret_share_change.expose_secret())
            .sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
