use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

use super::signed_message::SignedMessage;
use crate::rounds::{EvidenceRequiresMessages, PartyIdx, ProtocolResult};

#[derive(Debug, Clone)]
pub struct Evidence<Res: ProtocolResult, Sig> {
    result: Res::ProvableError,
    // Map round number -> message signed by the offending party
    messages: BTreeMap<(u8, bool), SignedMessage<Sig>>,
}

impl<Res: ProtocolResult, Sig: Clone> Evidence<Res, Sig> {
    fn new(
        result: Res::ProvableError,
        all_messages: &BTreeMap<(u8, bool), SignedMessage<Sig>>,
    ) -> Self {
        let messages = result
            .requires_messages()
            .iter()
            .map(|(round_num, echo)| {
                (
                    (*round_num, *echo),
                    all_messages[&(*round_num, *echo)].clone(),
                )
            })
            .collect();
        Self { result, messages }
    }

    fn verify_malicious<Verifier: PrehashVerifier<Sig>>(
        &self,
        verifier: &Verifier,
        shared_randomness: &[u8],
        party_idx: PartyIdx,
        num_parties: usize,
    ) -> bool {
        let vmessages = self
            .messages
            .iter()
            .map(|((round, echo), message)| {
                ((round, echo), message.clone().verify(verifier).unwrap())
            })
            .collect::<Vec<_>>();

        self.result.verify_malicious(shared_randomness, party_idx, num_parties, typed_messages)
    }
}

/*
pub trait Evidence<Verifier>: Clone + Serialize + for<'a> Deserialize<'a> {
    fn verify_malicious(&self,
            verifier: &Verifier,
            shared_randomness: &[u8],
            party_idx: PartyIdx,
            num_parties: usize) -> bool;
}
*/
