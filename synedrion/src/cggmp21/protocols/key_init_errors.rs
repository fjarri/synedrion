use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::key_init::{Round1Message, Round2Message, Round3Message};
use crate::cggmp21::SchemeParams;
use crate::rounds::{EvidenceRequiresMessages, PartyIdx};
use crate::tools::{
    bitvec::BitVec,
    hashing::{Chain, Hash},
};

/// Possible verifiable errors of the KeyGen protocol.
#[derive(Debug, Clone, Copy)]
pub struct KeyInitError<P: SchemeParams> {
    pub(crate) error: KeyInitErrorType,
    pub(crate) phantom: PhantomData<P>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KeyInitErrorType {
    /// A hash mismatch in Round 2.
    R2HashMismatch,
    /// Failed to verify `П^{sch}` in Round 3.
    R3InvalidSchProof,
}

enum ErrorMessages<P: SchemeParams> {
    R2HashMismatch {
        r1: Round1Message,
        r2: Round2Message<P>,
    },
    R3InvalidSchProof {
        r2: Vec<Round2Message<P>>,
        r3: Round3Message,
    },
}

impl<P: SchemeParams> EvidenceRequiresMessages for KeyInitError<P> {
    type Messages = ErrorMessages<P>;

    fn requires_messages(&self) -> Vec<(u8, bool)> {
        match self.error {
            KeyInitErrorType::R2HashMismatch => vec![(1, false), (2, false)],
            KeyInitErrorType::R3InvalidSchProof => vec![(2, true), (3, false)],
        }
    }

    fn verify_malicious(
        &self,
        shared_randomness: &[u8],
        party_idx: PartyIdx,
        num_parties: usize,
        messages: &Self::Messages,
    ) -> bool {
        match (self.error, messages) {
            (KeyInitErrorType::R2HashMismatch, ErrorMessages::R2HashMismatch { r1, r2 }) => {
                self.verify_r2_hash_mismatch(shared_randomness, party_idx, num_parties, &r1, &r2)
            }
            (KeyInitErrorType::R3InvalidSchProof, ErrorMessages::R3InvalidSchProof { r2, r3 }) => {
                self.verify_r3_invalid_sch_proof(
                    shared_randomness,
                    party_idx,
                    num_parties,
                    &r2,
                    &r3,
                )
            }
            _ => panic!(""),
        }
    }
}

impl<P: SchemeParams> KeyInitError<P> {
    pub fn verify_r2_hash_mismatch(
        &self,
        shared_randomness: &[u8],
        party_idx: PartyIdx,
        num_parties: usize,
        r1_bcast: &Round1Message,
        r2_bcast: &Round2Message<P>,
    ) -> bool {
        let sid_hash = Hash::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&(u32::try_from(num_parties).unwrap()))
            .finalize();
        let r1_hash = r1_bcast.cap_v;
        let r2_hash = r2_bcast.data.hash(&sid_hash, party_idx);
        r1_hash != r2_hash
    }

    pub fn verify_r3_invalid_sch_proof(
        &self,
        shared_randomness: &[u8],
        party_idx: PartyIdx,
        num_parties: usize,
        r2_bcasts: &[Round2Message<P>],
        r3_bcast: &Round3Message,
    ) -> bool {
        let sid_hash = Hash::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&(u32::try_from(num_parties).unwrap()))
            .finalize();
        let rid = BitVec::xor_all(r2_bcasts.iter().map(|bcast| &bcast.data.rid));
        let data = &r2_bcasts[party_idx.as_usize()].data;
        let aux = (&sid_hash, &party_idx, &rid);
        if !r3_bcast.psi.verify(&data.cap_a, &data.cap_x, &aux) {
            return false;
        }
        true
    }
}
