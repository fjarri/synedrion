use alloc::collections::{BTreeMap, BTreeSet};

use signature::hazmat::{PrehashVerifier};

use super::signed_message::SignedMessage;
use crate::rounds::{EvidenceRequiresMessages, ProtocolResult};

#[derive(Debug, Clone)]
pub struct Evidence<Res: ProtocolResult, Sig, Verifier> {
    party: Verifier,
    result: Res::ProvableError,
    // Map round number -> message signed by the offending party
    messages: BTreeMap<(u8, bool), SignedMessage<Sig>>,
}

impl<Res: ProtocolResult, Sig: Clone, Verifier> Evidence<Res, Sig, Verifier>
where
    Res::ProvableError: EvidenceRequiresMessages<Verifier>,
    Verifier: Clone + PrehashVerifier<Sig>,
{
    fn new(
        party: &Verifier,
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
        Self {
            party: party.clone(),
            result,
            messages,
        }
    }

    fn verify_malicious(
        &self,
        verifier: &Verifier,
        shared_randomness: &[u8],
        other_ids: &BTreeSet<Verifier>,
        my_id: &Verifier,
    ) -> bool {
        let vmessages = self
            .messages
            .iter()
            .map(|((round, echo), message)| {
                let vmessage = message.clone().verify(verifier).unwrap();
                ((*round, *echo), vmessage.to_message())
            })
            .collect::<BTreeMap<_, _>>();

        self.result
            .verify_malicious(shared_randomness, other_ids, my_id, &vmessages)
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
