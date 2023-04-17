use rand_core::{CryptoRng, RngCore};

use super::generic::{SessionState, Stage, ToSendSerialized};
use crate::protocols::auxiliary::{Round1, Round2, Round3};
use crate::protocols::common::{KeyShareChange, SchemeParams, SessionId};
use crate::protocols::generic::{ConsensusSubround, PreConsensusSubround};
use crate::tools::collections::PartyIdx;

#[derive(Clone)]
enum AuxiliaryStage<P: SchemeParams> {
    Round1(Stage<PreConsensusSubround<Round1<P>>>),
    Round1Consensus(Stage<ConsensusSubround<Round1<P>>>),
    Round2(Stage<Round2<P>>),
    Round3(Stage<Round3<P>>),
    Result(KeyShareChange<P::Paillier>),
}

#[derive(Clone)]
pub struct AuxiliaryState<P: SchemeParams>(AuxiliaryStage<P>);

impl<P: SchemeParams> SessionState for AuxiliaryState<P> {
    type Result = KeyShareChange<P::Paillier>;
    type Context = usize;

    fn new(
        rng: &mut (impl RngCore + CryptoRng),
        session_id: &SessionId,
        context: &usize,
        index: PartyIdx,
    ) -> Self {
        let num_parties = *context;
        let round1 = Round1::<P>::new(rng, session_id, index, num_parties);
        Self(AuxiliaryStage::Round1(Stage::new(PreConsensusSubround(
            round1,
        ))))
    }

    fn get_messages(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        num_parties: usize,
        index: PartyIdx,
    ) -> ToSendSerialized {
        match &mut self.0 {
            AuxiliaryStage::Round1(r) => r.get_messages(rng, num_parties, index),
            AuxiliaryStage::Round1Consensus(r) => r.get_messages(rng, num_parties, index),
            AuxiliaryStage::Round2(r) => r.get_messages(rng, num_parties, index),
            AuxiliaryStage::Round3(r) => r.get_messages(rng, num_parties, index),
            _ => panic!(),
        }
    }

    fn receive_current_stage(&mut self, from: PartyIdx, message_bytes: &[u8]) {
        match &mut self.0 {
            AuxiliaryStage::Round1(r) => r.receive(from, message_bytes),
            AuxiliaryStage::Round1Consensus(r) => r.receive(from, message_bytes),
            AuxiliaryStage::Round2(r) => r.receive(from, message_bytes),
            AuxiliaryStage::Round3(r) => r.receive(from, message_bytes),
            _ => panic!(),
        }
    }

    fn is_finished_receiving(&self) -> bool {
        match &self.0 {
            AuxiliaryStage::Round1(r) => r.is_finished_receiving(),
            AuxiliaryStage::Round1Consensus(r) => r.is_finished_receiving(),
            AuxiliaryStage::Round2(r) => r.is_finished_receiving(),
            AuxiliaryStage::Round3(r) => r.is_finished_receiving(),
            _ => panic!(),
        }
    }

    fn finalize_stage(self, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(match self.0 {
            AuxiliaryStage::Round1(r) => {
                AuxiliaryStage::Round1Consensus(Stage::new(r.finalize(rng)))
            }
            AuxiliaryStage::Round1Consensus(r) => {
                AuxiliaryStage::Round2(Stage::new(r.finalize(rng)))
            }
            AuxiliaryStage::Round2(r) => AuxiliaryStage::Round3(Stage::new(r.finalize(rng))),
            AuxiliaryStage::Round3(r) => AuxiliaryStage::Result(r.finalize(rng)),
            _ => panic!(),
        })
    }

    fn result(&self) -> Self::Result {
        match &self.0 {
            AuxiliaryStage::Result(r) => r.clone(),
            _ => panic!(),
        }
    }

    fn is_final_stage(&self) -> bool {
        matches!(self.0, AuxiliaryStage::Result(_))
    }

    fn current_stage_num(&self) -> u8 {
        match self.0 {
            AuxiliaryStage::Round1(_) => 1,
            AuxiliaryStage::Round1Consensus(_) => 2,
            AuxiliaryStage::Round2(_) => 3,
            AuxiliaryStage::Round3(_) => 4,
            _ => panic!(),
        }
    }

    fn stages_num(&self) -> u8 {
        4
    }
}