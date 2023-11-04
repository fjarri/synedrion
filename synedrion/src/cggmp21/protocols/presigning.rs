use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{KeyShare, KeySharePrecomputed, PartyIdx, PresigningData};
use super::generic::{
    BaseRound, BroadcastRound, DirectRound, FinalizableToNextRound, FinalizableToResult,
    FinalizeError, FirstRound, InitError, ProtocolResult, ReceiveError, ToNextRound, ToResult,
};
use crate::cggmp21::{
    sigma::{AffGProof, DecProof, EncProof, LogStarProof, MulProof},
    SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{Ciphertext, PaillierParams, Randomizer, RandomizerMod};
use crate::tools::collections::{HoleRange, HoleVec};
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{Bounded, FromScalar, Signed};

fn uint_from_scalar<P: SchemeParams>(
    x: &Scalar,
) -> <<P as SchemeParams>::Paillier as PaillierParams>::Uint {
    <<P as SchemeParams>::Paillier as PaillierParams>::Uint::from_scalar(x)
}

#[derive(Debug, Clone, Copy)]
pub struct PresigningResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for PresigningResult<P> {
    type Success = PresigningData<P>;
    type ProvableError = PresigningError;
    type CorrectnessProof = PresigningProof<P>;
}

#[derive(Debug, Clone)]
pub enum PresigningError {
    Round1(String),
    Round2(String),
    Round3(String),
}

pub struct Context<P: SchemeParams> {
    shared_randomness: Box<[u8]>,
    key_share: KeySharePrecomputed<P>,
    ephemeral_scalar_share: Scalar,
    gamma: Scalar,
    rho: RandomizerMod<P::Paillier>,
    nu: RandomizerMod<P::Paillier>,
}

pub struct Round1<P: SchemeParams> {
    context: Context<P>,
    k_ciphertext: Ciphertext<P::Paillier>,
    g_ciphertext: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = KeyShare<P>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        _num_parties: usize,
        _party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let key_share = context.to_precomputed();

        // TODO: check that KeyShare is consistent with num_parties/party_idx

        let ephemeral_scalar_share = Scalar::random(rng);
        let gamma = Scalar::random(rng);

        let pk = key_share.secret_aux.paillier_sk.public_key();

        let rho = RandomizerMod::<P::Paillier>::random(rng, pk);
        let nu = RandomizerMod::<P::Paillier>::random(rng, pk);

        let g_ciphertext =
            Ciphertext::new_with_randomizer(pk, &uint_from_scalar::<P>(&gamma), &nu.retrieve());
        let k_ciphertext = Ciphertext::new_with_randomizer(
            pk,
            &uint_from_scalar::<P>(&ephemeral_scalar_share),
            &rho.retrieve(),
        );

        Ok(Self {
            context: Context {
                shared_randomness: shared_randomness.into(),
                key_share,
                ephemeral_scalar_share,
                gamma,
                rho,
                nu,
            },
            k_ciphertext,
            g_ciphertext,
        })
    }
}

impl<P: SchemeParams> BaseRound for Round1<P> {
    type Type = ToNextRound;
    type Result = PresigningResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Ciphertext<P>: Serialize"))]
#[serde(bound(deserialize = "Ciphertext<P>: for<'x> Deserialize<'x>"))]
pub struct Round1Bcast<P: PaillierParams> {
    k_ciphertext: Ciphertext<P>,
    g_ciphertext: Ciphertext<P>,
}

impl<P: PaillierParams> Hashable for Round1Bcast<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.k_ciphertext).chain(&self.g_ciphertext)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "EncProof<P>: Serialize"))]
#[serde(bound(deserialize = "EncProof<P>: for<'x> Deserialize<'x>"))]
pub struct Round1Direct<P: SchemeParams>(EncProof<P>);

impl<P: SchemeParams> BroadcastRound for Round1<P> {
    const REQUIRES_CONSENSUS: bool = true;
    type Message = Round1Bcast<P::Paillier>;
    type Payload = Round1Bcast<P::Paillier>;

    fn broadcast_destinations(&self) -> Option<HoleRange> {
        Some(HoleRange::new(
            self.context.key_share.num_parties(),
            self.context.key_share.party_index().as_usize(),
        ))
    }

    fn make_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        Ok(Round1Bcast {
            k_ciphertext: self.k_ciphertext.clone(),
            g_ciphertext: self.g_ciphertext.clone(),
        })
    }

    fn verify_broadcast(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Ok(msg)
    }
}

impl<P: SchemeParams> DirectRound for Round1<P> {
    type Message = Round1Direct<P>;
    type Payload = Round1Direct<P>;
    type Artefact = ();

    fn direct_message_destinations(&self) -> Option<HoleRange> {
        Some(HoleRange::new(
            self.context.key_share.num_parties(),
            self.context.key_share.party_index().as_usize(),
        ))
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artefact), String> {
        let aux = (&self.context.shared_randomness, &destination);
        let proof = EncProof::random(
            rng,
            &Signed::from_scalar(&self.context.ephemeral_scalar_share),
            &self.context.rho,
            &self.context.key_share.secret_aux.paillier_sk,
            &self.context.key_share.public_aux[destination.as_usize()].aux_rp_params,
            &aux,
        );
        Ok((Round1Direct(proof), ()))
    }

    fn verify_direct_message(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Ok(msg)
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        _dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let ciphertexts = bc_payloads.unwrap();
        let proofs = dm_payloads.unwrap();

        let aux = (
            &self.context.shared_randomness,
            &self.context.key_share.party_index(),
        );

        let public_aux =
            &self.context.key_share.public_aux[self.context.key_share.party_index().as_usize()];

        for ((from, ciphertexts), proof) in ciphertexts.enumerate().zip(proofs.iter()) {
            if !proof.0.verify(
                &self.context.key_share.public_aux[from].paillier_pk,
                &ciphertexts.k_ciphertext,
                &public_aux.aux_rp_params,
                &aux,
            ) {
                return Err(FinalizeError::Provable {
                    party: PartyIdx::from_usize(from),
                    error: PresigningError::Round1("Failed to verify EncProof".into()),
                });
            }
        }

        let (k_ciphertexts, g_ciphertexts) = ciphertexts
            .map(|data| (data.k_ciphertext, data.g_ciphertext))
            .unzip();
        let k_ciphertexts = k_ciphertexts.into_vec(self.k_ciphertext);
        let g_ciphertexts = g_ciphertexts.into_vec(self.g_ciphertext);
        Ok(Round2 {
            context: self.context,
            k_ciphertexts,
            g_ciphertexts,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Ciphertext<P::Paillier>: Serialize,
    AffGProof<P>: Serialize,
    LogStarProof<P>: Serialize"))]
#[serde(bound(deserialize = "Ciphertext<P::Paillier>: for<'x> Deserialize<'x>,
    AffGProof<P>: for<'x> Deserialize<'x>,
    LogStarProof<P>: for<'x> Deserialize<'x>"))]
pub struct Round2Direct<P: SchemeParams> {
    gamma: Point,
    d: Ciphertext<P::Paillier>,
    d_hat: Ciphertext<P::Paillier>,
    f: Ciphertext<P::Paillier>,
    f_hat: Ciphertext<P::Paillier>,
    psi: AffGProof<P>,
    psi_hat: AffGProof<P>,
    psi_hat_prime: LogStarProof<P>,
}

pub struct Round2<P: SchemeParams> {
    context: Context<P>,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    g_ciphertexts: Vec<Ciphertext<P::Paillier>>,
}

#[derive(Debug, Clone)]
pub struct Round2Artefact<P: SchemeParams> {
    beta: Signed<<P::Paillier as PaillierParams>::Uint>, // TODO: secret
    beta_hat: Signed<<P::Paillier as PaillierParams>::Uint>, // TODO: secret
    r: Randomizer<P::Paillier>,                          // TODO: secret
    s: Randomizer<P::Paillier>,                          // TODO: secret
    hat_r: Randomizer<P::Paillier>,                      // TODO: secret
    hat_s: Randomizer<P::Paillier>,                      // TODO: secret
    cap_f: Ciphertext<P::Paillier>,
    hat_cap_f: Ciphertext<P::Paillier>,
}

pub struct Round2Payload<P: SchemeParams> {
    gamma: Point,
    alpha: Signed<<P::Paillier as PaillierParams>::Uint>,
    alpha_hat: Scalar,
    cap_d: Ciphertext<P::Paillier>,
    hat_cap_d: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams> BaseRound for Round2<P> {
    type Type = ToNextRound;
    type Result = PresigningResult<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
}

impl<P: SchemeParams> BroadcastRound for Round2<P> {
    type Message = ();
    type Payload = ();
}

impl<P: SchemeParams> DirectRound for Round2<P> {
    type Message = Round2Direct<P>;
    type Payload = Round2Payload<P>;
    type Artefact = Round2Artefact<P>;

    fn direct_message_destinations(&self) -> Option<HoleRange> {
        Some(HoleRange::new(
            self.context.key_share.num_parties(),
            self.context.key_share.party_index().as_usize(),
        ))
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artefact), String> {
        let aux = (
            &self.context.shared_randomness,
            &self.context.key_share.party_index(),
        );

        let gamma = self.context.gamma.mul_by_generator();
        let pk = &self.context.key_share.secret_aux.paillier_sk.public_key();
        let idx = destination.as_usize();

        let target_pk = &self.context.key_share.public_aux[idx].paillier_pk;

        let beta = Signed::random_bounded_bits(rng, P::LP_BOUND);
        let beta_hat = Signed::random_bounded_bits(rng, P::LP_BOUND);
        let r = RandomizerMod::random(rng, pk);
        let s = RandomizerMod::random(rng, target_pk);
        let r_hat = RandomizerMod::random(rng, pk);
        let s_hat = RandomizerMod::random(rng, target_pk);

        let cap_f = Ciphertext::new_with_randomizer_signed(pk, &beta, &r.retrieve());

        let d = self.k_ciphertexts[idx]
            .homomorphic_mul(target_pk, &Signed::from_scalar(&self.context.gamma))
            .homomorphic_add(
                target_pk,
                &Ciphertext::new_with_randomizer_signed(target_pk, &-beta, &s.retrieve()),
            );

        let d_hat = self.k_ciphertexts[idx]
            .homomorphic_mul(
                target_pk,
                &Signed::from_scalar(&self.context.key_share.secret_share),
            )
            .homomorphic_add(
                target_pk,
                &Ciphertext::new_with_randomizer_signed(target_pk, &-beta_hat, &s_hat.retrieve()),
            );
        let f_hat = Ciphertext::new_with_randomizer_signed(pk, &beta_hat, &r_hat.retrieve());

        let public_aux = &self.context.key_share.public_aux[idx];
        let aux_rp = &public_aux.aux_rp_params;

        let psi = AffGProof::random(
            rng,
            &Signed::from_scalar(&self.context.gamma),
            &beta,
            &s,
            &r,
            target_pk,
            pk,
            &self.k_ciphertexts[idx],
            aux_rp,
            &aux,
        );

        let psi_hat = AffGProof::random(
            rng,
            &Signed::from_scalar(&self.context.key_share.secret_share),
            &beta_hat,
            &s_hat,
            &r_hat,
            target_pk,
            pk,
            &self.k_ciphertexts[idx],
            aux_rp,
            &aux,
        );

        let psi_hat_prime = LogStarProof::random(
            rng,
            &Signed::from_scalar(&self.context.gamma),
            &self.context.nu,
            pk,
            &Point::GENERATOR,
            aux_rp,
            &aux,
        );

        let msg = Round2Direct {
            gamma,
            d,
            f: cap_f.clone(),
            d_hat,
            f_hat: f_hat.clone(),
            psi,
            psi_hat,
            psi_hat_prime,
        };

        let artefact = Round2Artefact {
            beta,
            beta_hat,
            r: r.retrieve(),
            s: s.retrieve(),
            hat_r: r_hat.retrieve(),
            hat_s: s_hat.retrieve(),
            cap_f,
            hat_cap_f: f_hat,
        };

        Ok((msg, artefact))
    }

    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let aux = (&self.context.shared_randomness, &from);
        let pk = &self.context.key_share.secret_aux.paillier_sk.public_key();
        let from_pk = &self.context.key_share.public_aux[from.as_usize()].paillier_pk;

        let big_x = self.context.key_share.public_shares[from.as_usize()];

        let public_aux =
            &self.context.key_share.public_aux[self.context.key_share.party_index().as_usize()];
        let aux_rp = &public_aux.aux_rp_params;

        if !msg.psi.verify(
            pk,
            from_pk,
            &self.k_ciphertexts[self.context.key_share.party_index().as_usize()],
            &msg.d,
            &msg.f,
            &msg.gamma,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::Provable(PresigningError::Round2(
                "Failed to verify AffGProof (psi)".into(),
            )));
        }

        if !msg.psi_hat.verify(
            pk,
            from_pk,
            &self.k_ciphertexts[self.context.key_share.party_index().as_usize()],
            &msg.d_hat,
            &msg.f_hat,
            &big_x,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::Provable(PresigningError::Round2(
                "Failed to verify AffGProof (psi_hat)".into(),
            )));
        }

        if !msg.psi_hat_prime.verify(
            from_pk,
            &self.g_ciphertexts[from.as_usize()],
            &Point::GENERATOR,
            &msg.gamma,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::Provable(PresigningError::Round2(
                "Failed to verify LogStarProof".into(),
            )));
        }

        let alpha = msg
            .d
            .decrypt_signed(&self.context.key_share.secret_aux.paillier_sk);

        // `alpha == x * y + z` where `0 <= x, y < q`, and `-2^l' <= z <= 2^l'`,
        // where `q` is the curve order.
        // We will need this bound later, so we're asserting it.
        let alpha = alpha
            .assert_bound_usize(core::cmp::max(2 * P::L_BOUND, P::LP_BOUND) + 1)
            .unwrap();

        let alpha_hat = msg
            .d_hat
            .decrypt_signed(&self.context.key_share.secret_aux.paillier_sk)
            .to_scalar();

        Ok(Round2Payload {
            gamma: msg.gamma,
            alpha,
            alpha_hat,
            cap_d: msg.d,
            hat_cap_d: msg.d_hat,
        })
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        _bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let dm_payloads = dm_payloads.unwrap();
        let dm_artefacts = dm_artefacts.unwrap();

        let gamma: Point = dm_payloads.iter().map(|payload| payload.gamma).sum();
        let gamma = gamma + self.context.gamma.mul_by_generator();

        let big_delta = &gamma * &self.context.ephemeral_scalar_share;

        let delta = Signed::from_scalar(&self.context.gamma)
            * Signed::from_scalar(&self.context.ephemeral_scalar_share)
            + dm_payloads.iter().map(|p| p.alpha).sum()
            + dm_artefacts.iter().map(|p| p.beta).sum();

        let alpha_hat_sum: Scalar = dm_payloads.iter().map(|payload| payload.alpha_hat).sum();
        let beta_hat_sum: Signed<_> = dm_artefacts.iter().map(|artefact| artefact.beta_hat).sum();

        let product_share = self.context.key_share.secret_share
            * self.context.ephemeral_scalar_share
            + alpha_hat_sum
            + beta_hat_sum.to_scalar();

        let cap_ds = dm_payloads.map_ref(|payload| payload.cap_d.clone());
        let hat_cap_d = dm_payloads.map_ref(|payload| payload.hat_cap_d.clone());

        Ok(Round3 {
            context: self.context,
            delta,
            product_share,
            big_delta,
            big_gamma: gamma,
            k_ciphertexts: self.k_ciphertexts,
            g_ciphertexts: self.g_ciphertexts,
            cap_ds,
            hat_cap_d,
            round2_artefacts: dm_artefacts,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "LogStarProof<P>: Serialize"))]
#[serde(bound(deserialize = "LogStarProof<P>: for<'x> Deserialize<'x>"))]
pub struct Round3Direct<P: SchemeParams> {
    delta: Scalar,
    big_delta: Point,
    psi_hat_pprime: LogStarProof<P>,
}

pub struct Round3<P: SchemeParams> {
    context: Context<P>,
    delta: Signed<<P::Paillier as PaillierParams>::Uint>,
    product_share: Scalar,
    big_delta: Point,
    big_gamma: Point,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    g_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    cap_ds: HoleVec<Ciphertext<P::Paillier>>,
    hat_cap_d: HoleVec<Ciphertext<P::Paillier>>,
    round2_artefacts: HoleVec<Round2Artefact<P>>,
}

impl<P: SchemeParams> BaseRound for Round3<P> {
    type Type = ToResult;
    type Result = PresigningResult<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;
}

pub struct Round3Payload {
    delta: Scalar,
    big_delta: Point,
}

impl<P: SchemeParams> BroadcastRound for Round3<P> {
    type Message = ();
    type Payload = ();
}

impl<P: SchemeParams> DirectRound for Round3<P> {
    type Message = Round3Direct<P>;
    type Payload = Round3Payload;
    type Artefact = ();

    fn direct_message_destinations(&self) -> Option<HoleRange> {
        Some(HoleRange::new(
            self.context.key_share.num_parties(),
            self.context.key_share.party_index().as_usize(),
        ))
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artefact), String> {
        let aux = (
            &self.context.shared_randomness,
            &self.context.key_share.party_index(),
        );
        let pk = &self.context.key_share.secret_aux.paillier_sk.public_key();
        let idx = destination.as_usize();

        let public_aux = &self.context.key_share.public_aux[idx];
        let aux_rp = &public_aux.aux_rp_params;

        let psi_hat_pprime = LogStarProof::random(
            rng,
            &Signed::from_scalar(&self.context.ephemeral_scalar_share),
            &self.context.rho,
            pk,
            &self.big_gamma,
            aux_rp,
            &aux,
        );
        let message = Round3Direct {
            delta: self.delta.to_scalar(),
            big_delta: self.big_delta,
            psi_hat_pprime,
        };

        Ok((message, ()))
    }

    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let aux = (&self.context.shared_randomness, &from);
        let from_pk = &self.context.key_share.public_aux[from.as_usize()].paillier_pk;

        let public_aux =
            &self.context.key_share.public_aux[self.context.key_share.party_index().as_usize()];
        let aux_rp = &public_aux.aux_rp_params;

        if !msg.psi_hat_pprime.verify(
            from_pk,
            &self.k_ciphertexts[from.as_usize()],
            &self.big_gamma,
            &msg.big_delta,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::Provable(PresigningError::Round3(
                "Failed to verify Log-Star proof".into(),
            )));
        }
        Ok(Round3Payload {
            delta: msg.delta,
            big_delta: msg.big_delta,
        })
    }
}

// TODO: this can be removed when error verification is added
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PresigningProof<P: SchemeParams> {
    aff_g_proofs: Vec<(PartyIdx, PartyIdx, AffGProof<P>)>,
    mul_proof: MulProof<P>,
    dec_proofs: Vec<(PartyIdx, DecProof<P>)>,
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        _bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        _dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let dm_payloads = dm_payloads.unwrap();
        let (deltas, big_deltas) = dm_payloads
            .map(|payload| (payload.delta, payload.big_delta))
            .unzip();

        let delta: Scalar = deltas.iter().sum();
        let delta = delta + self.delta.to_scalar();

        let big_delta: Point = big_deltas.iter().sum();
        let big_delta = big_delta + self.big_delta;

        let my_idx = self.context.key_share.party_index().as_usize();

        if delta.mul_by_generator() == big_delta {
            // TODO: seems like we only need the x-coordinate of this (as a Scalar)
            let nonce = &self.big_gamma * &delta.invert().unwrap();

            let hat_beta = self.round2_artefacts.map_ref(|artefact| artefact.beta_hat);
            let hat_r = self
                .round2_artefacts
                .map_ref(|artefact| artefact.hat_r.clone());
            let hat_s = self
                .round2_artefacts
                .map_ref(|artefact| artefact.hat_s.clone());
            let hat_cap_f = self
                .round2_artefacts
                .map_ref(|artefact| artefact.hat_cap_f.clone());

            return Ok(PresigningData {
                nonce,
                ephemeral_scalar_share: self.context.ephemeral_scalar_share,
                product_share: self.product_share,

                hat_beta,
                hat_r,
                hat_s,
                cap_k: self.k_ciphertexts[my_idx].clone(),
                hat_cap_d: self.hat_cap_d,
                hat_cap_f,
            });
        }

        // Construct the correctness proofs

        let sk = &self.context.key_share.secret_aux.paillier_sk;
        let pk = sk.public_key();
        let num_parties = self.context.key_share.num_parties();

        let aux = (
            &self.context.shared_randomness,
            &self.context.key_share.party_index(),
        );

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        let beta = self.round2_artefacts.map_ref(|artefact| artefact.beta);
        let r = self.round2_artefacts.map_ref(|artefact| artefact.r.clone());
        let s = self.round2_artefacts.map_ref(|artefact| artefact.s.clone());

        for j in HoleRange::new(num_parties, my_idx) {
            // TODO: can exclude `j` in addition to `my_idx`.
            // Should we have a "double hole vec" for that?
            for l in HoleRange::new(num_parties, my_idx) {
                let target_pk = &self.context.key_share.public_aux[j].paillier_pk;
                let aux_rp = &self.context.key_share.public_aux[l].aux_rp_params;

                let p_aff_g = AffGProof::<P>::random(
                    rng,
                    &Signed::from_scalar(&self.context.gamma),
                    beta.get(j).unwrap(),
                    &s.get(j).unwrap().to_mod(target_pk),
                    &r.get(j).unwrap().to_mod(pk),
                    target_pk,
                    pk,
                    &self.k_ciphertexts[j],
                    aux_rp,
                    &aux,
                );

                aff_g_proofs.push((PartyIdx::from_usize(j), PartyIdx::from_usize(l), p_aff_g));
            }
        }

        // Mul proof

        let rho = RandomizerMod::random(rng, pk);
        let cap_h = self.k_ciphertexts[my_idx]
            .homomorphic_mul_unsigned(pk, &Bounded::from_scalar(&self.context.gamma))
            .mul_randomizer(pk, &rho.retrieve());

        let p_mul = MulProof::<P>::random(
            rng,
            &Signed::from_scalar(&self.context.ephemeral_scalar_share),
            &self.context.rho,
            &rho,
            pk,
            &self.g_ciphertexts[my_idx],
            &aux,
        );
        assert!(p_mul.verify(
            pk,
            &self.k_ciphertexts[my_idx],
            &self.g_ciphertexts[my_idx],
            &cap_h,
            &aux
        ));

        // Dec proof

        let range = HoleRange::new(self.context.key_share.num_parties(), my_idx);

        let mut ciphertext = cap_h.clone();

        for j in range {
            ciphertext = ciphertext
                .homomorphic_add(pk, self.cap_ds.get(j).unwrap())
                .homomorphic_add(pk, &self.round2_artefacts.get(j).unwrap().cap_f);
        }

        let rho = ciphertext.derive_randomizer(sk);

        let mut dec_proofs = Vec::new();
        for j in range {
            let p_dec = DecProof::<P>::random(
                rng,
                &self.delta,
                &rho,
                pk,
                &self.context.key_share.public_aux[j].rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                pk,
                &self.delta.to_scalar(),
                &ciphertext,
                &self.context.key_share.public_aux[j].rp_params,
                &aux
            ));
            dec_proofs.push((PartyIdx::from_usize(j), p_dec));
        }

        Err(FinalizeError::Proof(PresigningProof {
            aff_g_proofs,
            dec_proofs,
            mul_proof: p_mul,
        }))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::super::{
        test_utils::{step_next_round, step_result, step_round},
        FirstRound,
    };
    use super::Round1;
    use crate::cggmp21::{KeyShare, PartyIdx, TestParams};
    use crate::curve::{Point, Scalar};

    #[test]
    fn execute_presigning() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let key_shares = KeyShare::new_centralized(&mut OsRng, num_parties, None);
        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::<TestParams>::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    key_shares[idx].clone(),
                )
                .unwrap()
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let presigning_datas = step_result(&mut OsRng, r3a).unwrap();

        // Check that each node ends up with the same nonce.
        assert_eq!(presigning_datas[0].nonce, presigning_datas[1].nonce);
        assert_eq!(presigning_datas[0].nonce, presigning_datas[2].nonce);

        // Check that the additive shares were constructed in a consistent way.
        let k: Scalar = presigning_datas
            .iter()
            .map(|data| data.ephemeral_scalar_share)
            .sum();
        let k_times_x: Scalar = presigning_datas.iter().map(|data| data.product_share).sum();
        let x: Scalar = key_shares.iter().map(|share| share.secret_share).sum();
        assert_eq!(x * k, k_times_x);
        assert_eq!(
            &Point::GENERATOR * &k.invert().unwrap(),
            presigning_datas[0].nonce
        );
    }
}
