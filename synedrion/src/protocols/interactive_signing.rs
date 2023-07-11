use alloc::boxed::Box;

use rand_core::CryptoRngCore;

use super::common::{KeyShare, PartyIdx, SchemeParams};
use super::generic::{
    FinalizeError, FinalizeSuccess, FirstRound, InitError, NonExistent, ReceiveError, Round,
    ToSendTyped,
};
use super::presigning;
use super::signing;
use crate::curve::{RecoverableSignature, Scalar};
use crate::tools::collections::HoleVec;

pub struct Round1Part1<P: SchemeParams> {
    context: RoundContext<P>,
    round: presigning::Round1Part1<P>,
}

struct RoundContext<P: SchemeParams> {
    shared_randomness: Box<[u8]>,
    key_share: KeyShare<P>,
    message: Scalar,
}

#[derive(Clone)]
pub(crate) struct Context<P: SchemeParams> {
    pub(crate) key_share: KeyShare<P>,
    pub(crate) message: Scalar,
}

impl<P: SchemeParams> FirstRound for Round1Part1<P> {
    type Context = Context<P>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let round = presigning::Round1Part1::new(
            rng,
            shared_randomness,
            num_parties,
            party_idx,
            context.key_share.clone(),
        )?;
        let context = RoundContext {
            shared_randomness: shared_randomness.into(),
            key_share: context.key_share,
            message: context.message,
        };
        Ok(Self { context, round })
    }
}

impl<P: SchemeParams> Round for Round1Part1<P> {
    type Payload = <presigning::Round1Part1<P> as Round>::Payload;
    type Message = <presigning::Round1Part1<P> as Round>::Message;
    type NextRound = Round1Part2<P>;
    type Result = RecoverableSignature;

    fn round_num() -> u8 {
        1
    }
    fn next_round_num() -> Option<u8> {
        Some(2)
    }
    fn requires_broadcast_consensus() -> bool {
        presigning::Round1Part1::<P>::requires_broadcast_consensus()
    }

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        self.round.to_send(rng)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.round.verify_received(from, msg)
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        self.round
            .finalize(rng, payloads)
            .map(|success| match success {
                // TODO: figure out how to avoid this. Type erasure should happen in `type_erased.rs`,
                // not here.
                FinalizeSuccess::Result(_res) => unreachable!(),
                FinalizeSuccess::AnotherRound(round) => {
                    FinalizeSuccess::AnotherRound(Round1Part2 {
                        context: self.context,
                        round,
                    })
                }
            })
    }
}

pub struct Round1Part2<P: SchemeParams> {
    context: RoundContext<P>,
    round: presigning::Round1Part2<P>,
}

impl<P: SchemeParams> Round for Round1Part2<P> {
    type Payload = <presigning::Round1Part2<P> as Round>::Payload;
    type Message = <presigning::Round1Part2<P> as Round>::Message;
    type NextRound = Round2<P>;
    type Result = RecoverableSignature;

    fn round_num() -> u8 {
        2
    }
    fn next_round_num() -> Option<u8> {
        Some(3)
    }
    fn requires_broadcast_consensus() -> bool {
        presigning::Round1Part2::<P>::requires_broadcast_consensus()
    }

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        self.round.to_send(rng)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.round.verify_received(from, msg)
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        self.round
            .finalize(rng, payloads)
            .map(|success| match success {
                // TODO: figure out how to avoid this. Type erasure should happen in `type_erased.rs`,
                // not here.
                FinalizeSuccess::Result(_res) => unreachable!(),
                FinalizeSuccess::AnotherRound(round) => FinalizeSuccess::AnotherRound(Round2 {
                    context: self.context,
                    round,
                }),
            })
    }
}

pub struct Round2<P: SchemeParams> {
    context: RoundContext<P>,
    round: presigning::Round2<P>,
}

impl<P: SchemeParams> Round for Round2<P> {
    type Payload = <presigning::Round2<P> as Round>::Payload;
    type Message = <presigning::Round2<P> as Round>::Message;
    type NextRound = Round3<P>;
    type Result = RecoverableSignature;

    fn round_num() -> u8 {
        3
    }
    fn next_round_num() -> Option<u8> {
        Some(4)
    }
    fn requires_broadcast_consensus() -> bool {
        presigning::Round2::<P>::requires_broadcast_consensus()
    }

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        self.round.to_send(rng)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.round.verify_received(from, msg)
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        self.round
            .finalize(rng, payloads)
            .map(|success| match success {
                // TODO: figure out how to avoid this. Type erasure should happen in `type_erased.rs`,
                // not here.
                FinalizeSuccess::Result(_res) => unreachable!(),
                FinalizeSuccess::AnotherRound(round) => FinalizeSuccess::AnotherRound(Round3 {
                    context: self.context,
                    round,
                }),
            })
    }
}

pub struct Round3<P: SchemeParams> {
    context: RoundContext<P>,
    round: presigning::Round3<P>,
}

impl<P: SchemeParams> Round for Round3<P> {
    type Payload = <presigning::Round3<P> as Round>::Payload;
    type Message = <presigning::Round3<P> as Round>::Message;
    type NextRound = SigningRound;
    type Result = RecoverableSignature;

    fn round_num() -> u8 {
        4
    }
    fn next_round_num() -> Option<u8> {
        Some(5)
    }
    fn requires_broadcast_consensus() -> bool {
        presigning::Round3::<P>::requires_broadcast_consensus()
    }

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        self.round.to_send(rng)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.round.verify_received(from, msg)
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let num_parties = self.context.key_share.num_parties();
        let party_idx = self.context.key_share.party_index();
        let outcome = self.round.finalize(rng, payloads)?;
        match outcome {
            // TODO: figure out how to avoid this. Type erasure should happen in `type_erased.rs`,
            // not here.
            FinalizeSuccess::Result(presigning) => {
                let signing_context = signing::Context {
                    message: self.context.message,
                    presigning,
                    verifying_key: self.context.key_share.verifying_key_as_point(),
                };
                let signing_round = signing::Round1::new(
                    rng,
                    &self.context.shared_randomness,
                    num_parties,
                    party_idx,
                    signing_context,
                )
                .map_err(FinalizeError::ProtocolMerge)?;
                Ok(FinalizeSuccess::AnotherRound(SigningRound {
                    round: signing_round,
                }))
            }
            FinalizeSuccess::AnotherRound(_round) => unreachable!(),
        }
    }
}

pub struct SigningRound {
    round: signing::Round1,
}

impl Round for SigningRound {
    type Payload = <signing::Round1 as Round>::Payload;
    type Message = <signing::Round1 as Round>::Message;
    type NextRound = NonExistent<Self::Result>;
    type Result = RecoverableSignature;

    fn round_num() -> u8 {
        5
    }
    fn next_round_num() -> Option<u8> {
        None
    }
    fn requires_broadcast_consensus() -> bool {
        signing::Round1::requires_broadcast_consensus()
    }

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        self.round.to_send(rng)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.round.verify_received(from, msg)
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        self.round
            .finalize(rng, payloads)
            .map(|success| match success {
                FinalizeSuccess::Result(res) => FinalizeSuccess::Result(res),
                FinalizeSuccess::AnotherRound(_round) => unreachable!(),
            })
    }
}