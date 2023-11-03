use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{KeySharePrecomputed, PartyIdx, PresigningData};
use super::generic::{
    BaseRound, BroadcastRound, DirectRound, FinalizableToResult, FinalizeError, FirstRound,
    InitError, ProtocolResult, ReceiveError, ToResult,
};
use crate::cggmp21::{
    sigma::{AffGProof, DecProof, MulStarProof},
    SchemeParams,
};
use crate::curve::{RecoverableSignature, Scalar};
use crate::paillier::RandomizerMod;
use crate::tools::collections::{HoleRange, HoleVec};
use crate::uint::{Bounded, FromScalar, Signed};

#[derive(Debug, Clone, Copy)]
pub struct SigningResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for SigningResult<P> {
    type Success = RecoverableSignature;
    type ProvableError = ();
    type CorrectnessProof = SigningProof<P>;
}

// TODO: this can be removed when error verification is added
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SigningProof<P: SchemeParams> {
    aff_g_proofs: Vec<(PartyIdx, PartyIdx, AffGProof<P>)>,
    mul_star_proofs: Vec<(PartyIdx, MulStarProof<P>)>,
    dec_proofs: Vec<(PartyIdx, DecProof<P>)>,
}

pub struct Round1<P: SchemeParams> {
    r: Scalar,
    s_part: Scalar,
    context: Context<P>,
    num_parties: usize,
    party_idx: PartyIdx,
    shared_randomness: Box<[u8]>,
}

#[derive(Clone)]
pub(crate) struct Context<P: SchemeParams> {
    pub(crate) message: Scalar,
    pub(crate) presigning: PresigningData<P>,
    pub(crate) key_share: KeySharePrecomputed<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = Context<P>;
    fn new(
        _rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let r = context.presigning.nonce.x_coordinate();
        let s_part = context.presigning.ephemeral_scalar_share * context.message
            + r * context.presigning.product_share;
        Ok(Self {
            r,
            s_part,
            context,
            num_parties,
            party_idx,
            shared_randomness: shared_randomness.into(),
        })
    }
}

impl<P: SchemeParams> BaseRound for Round1<P> {
    type Type = ToResult;
    type Result = SigningResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = None;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    s_part: Scalar,
}

impl<P: SchemeParams> BroadcastRound for Round1<P> {
    const REQUIRES_CONSENSUS: bool = false;
    type Message = Round1Bcast;
    type Payload = Scalar;
    fn broadcast_destinations(&self) -> Option<HoleRange> {
        Some(HoleRange::new(self.num_parties, self.party_idx.as_usize()))
    }
    fn make_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        Ok(Round1Bcast {
            s_part: self.s_part,
        })
    }

    fn verify_broadcast(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Ok(msg.s_part)
    }
}

impl<P: SchemeParams> DirectRound for Round1<P> {
    type Message = ();
    type Payload = ();
    type Artefact = ();
}

impl<P: SchemeParams> FinalizableToResult for Round1<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        _dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        _dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let shares = bc_payloads.unwrap();
        let s: Scalar = shares.iter().sum();
        let s = s + self.s_part;

        // CHECK: should `s` be normalized here?

        let sig = RecoverableSignature::from_scalars(
            &self.r,
            &s,
            &self.context.key_share.verifying_key_as_point(),
            &self.context.message,
        );

        if let Some(sig) = sig {
            return Ok(sig);
        }

        let my_idx = self.party_idx.as_usize();
        let num_parties = self.num_parties;

        let aux = (&self.shared_randomness, &self.party_idx);

        let sk = &self.context.key_share.secret_aux.paillier_sk;
        let pk = sk.public_key();

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        for j in HoleRange::new(num_parties, my_idx) {
            // TODO: can exclude `j` in addition to `my_idx`.
            // Should we have a "double hole vec" for that?
            for l in HoleRange::new(num_parties, my_idx) {
                let target_pk = &self.context.key_share.public_aux[j].paillier_pk;
                let aux_rp = &self.context.key_share.public_aux[l].aux_rp_params;

                let p_aff_g = AffGProof::<P>::random(
                    rng,
                    &Signed::from_scalar(&self.context.key_share.secret_share),
                    self.context.presigning.hat_beta.get(j).unwrap(),
                    &self
                        .context
                        .presigning
                        .hat_s
                        .get(j)
                        .unwrap()
                        .to_mod(target_pk),
                    &self.context.presigning.hat_r.get(j).unwrap().to_mod(pk),
                    target_pk,
                    pk,
                    &self.context.presigning.cap_k,
                    aux_rp,
                    &aux,
                );

                aff_g_proofs.push((PartyIdx::from_usize(j), PartyIdx::from_usize(l), p_aff_g));
            }
        }

        // mul* proofs

        let x = self.context.key_share.secret_share;

        let rho = RandomizerMod::random(rng, pk);
        let hat_cap_h = self
            .context
            .presigning
            .cap_k
            .homomorphic_mul_unsigned(pk, &Bounded::from_scalar(&x))
            .mul_randomizer(pk, &rho.retrieve());

        let aux = (
            &self.shared_randomness,
            &self.context.key_share.party_index(),
        );

        let mut mul_star_proofs = Vec::new();

        for l in HoleRange::new(num_parties, my_idx) {
            let p_mul = MulStarProof::<P>::random(
                rng,
                &Signed::from_scalar(&x),
                &rho,
                pk,
                &self.context.presigning.cap_k,
                &self.context.key_share.public_aux[l].aux_rp_params,
                &aux,
            );

            mul_star_proofs.push((PartyIdx::from_usize(l), p_mul));
        }

        // dec proofs

        let mut ciphertext = hat_cap_h.homomorphic_add(
            pk,
            &self
                .context
                .presigning
                .cap_k
                .homomorphic_mul_unsigned(pk, &Bounded::from_scalar(&self.context.message)),
        );

        for j in HoleRange::new(num_parties, my_idx) {
            ciphertext = ciphertext
                .homomorphic_add(pk, self.context.presigning.hat_cap_d.get(j).unwrap())
                .homomorphic_add(pk, self.context.presigning.hat_cap_f.get(j).unwrap());
        }

        let rho = ciphertext.derive_randomizer(sk);

        let mut dec_proofs = Vec::new();
        for l in HoleRange::new(num_parties, my_idx) {
            let p_dec = DecProof::<P>::random(
                rng,
                &Signed::from_scalar(&s),
                &rho,
                pk,
                &self.context.key_share.public_aux[l].rp_params,
                &aux,
            );
            dec_proofs.push((PartyIdx::from_usize(l), p_dec));
        }

        let proof = SigningProof {
            aff_g_proofs,
            mul_star_proofs,
            dec_proofs,
        };

        Err(FinalizeError::Proof(proof))
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand_core::{OsRng, RngCore};

    use super::super::{
        common::PresigningData,
        test_utils::{step_result, step_round},
        FirstRound,
    };
    use super::{Context, Round1};
    use crate::cggmp21::{KeyShare, PartyIdx, TestParams};
    use crate::curve::Scalar;

    #[test]
    fn execute_signing() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let key_shares = KeyShare::<TestParams>::new_centralized(&mut OsRng, num_parties, None);

        let presigning_datas = PresigningData::new_centralized(&mut OsRng, &key_shares);

        let message = Scalar::random(&mut OsRng);

        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    Context {
                        presigning: presigning_datas[idx].clone(),
                        message,
                        key_share: key_shares[idx].to_precomputed(),
                    },
                )
                .unwrap()
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let signatures = step_result(&mut OsRng, r1a).unwrap();

        for signature in signatures {
            let (sig, rec_id) = signature.to_backend();

            let vkey = key_shares[0].verifying_key();

            // Check that the signature can be verified
            vkey.verify_prehash(&message.to_be_bytes(), &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key =
                VerifyingKey::recover_from_prehash(&message.to_be_bytes(), &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }
    }
}
