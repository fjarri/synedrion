use alloc::boxed::Box;

use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::curve::{Point, Scalar};
use crate::paillier::{PaillierParams, PaillierTest, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::hashing::{Chain, Hashable};

// TODO (#27): this trait can include curve scalar/point types as well,
// but for now they are hardcoded to `k256`.
pub trait SchemeParams: Clone + Send {
    const SECURITY_PARAMETER: usize;
    type Paillier: PaillierParams;
}

#[derive(Clone)]
pub struct TestSchemeParams;

impl SchemeParams for TestSchemeParams {
    const SECURITY_PARAMETER: usize = 10;
    type Paillier = PaillierTest;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PartyIdx(u32);

impl PartyIdx {
    pub fn as_usize(self) -> usize {
        self.0.try_into().unwrap()
    }

    pub fn from_usize(val: usize) -> Self {
        Self(val.try_into().unwrap())
    }
}

impl Hashable for PartyIdx {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

/// The result of the Keygen protocol.
#[derive(Clone)]
pub struct KeyShareSeed {
    /// Secret key share of this node.
    pub share_sk: Scalar, // `x`
    /// Public key shares of all nodes (including this one).
    pub share_pk: Box<[Point]>, // `X`
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillier<P::Paillier>: for<'x> Deserialize<'x>"))]
pub struct KeyShareSecret<P: SchemeParams> {
    pub(crate) share_sk: Scalar,
    pub(crate) paillier_sk: SecretKeyPaillier<P::Paillier>,
    pub(crate) el_gamal_sk: Scalar, // `y_i`
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "KeyShareSecret<P>: Serialize,
        KeySharePublic<P>: Serialize"))]
#[serde(bound(deserialize = "KeyShareSecret<P>: for<'x> Deserialize<'x>,
        KeySharePublic<P>: for <'x> Deserialize<'x>"))]
pub struct KeyShare<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) secret: KeyShareSecret<P>,
    pub(crate) public: Box<[KeySharePublic<P>]>,
}

impl<P: SchemeParams> KeyShare<P> {
    pub fn new(seed: KeyShareSeed, change: KeyShareChange<P>) -> Self {
        // TODO: check that party_idx is the same for both, and the number of parties is the same
        let secret = KeyShareSecret {
            share_sk: seed.share_sk + change.secret.share_sk,
            paillier_sk: change.secret.paillier_sk,
            el_gamal_sk: change.secret.el_gamal_sk,
        };
        let public = seed
            .share_pk
            .iter()
            .zip(change.public.into_vec().into_iter())
            .map(|(seed_share_pk, change_public)| KeySharePublic {
                share_pk: seed_share_pk + &change_public.share_pk,
                el_gamal_pk: change_public.el_gamal_pk,
                paillier_pk: change_public.paillier_pk,
                rp_generator: change_public.rp_generator,
                rp_power: change_public.rp_power,
            })
            .collect();
        Self {
            index: change.index,
            secret,
            public,
        }
    }

    pub fn update(self, change: KeyShareChange<P>) -> Self {
        // TODO: check that party_idx is the same for both, and the number of parties is the same
        let secret = KeyShareSecret {
            share_sk: self.secret.share_sk + change.secret.share_sk,
            paillier_sk: change.secret.paillier_sk,
            el_gamal_sk: change.secret.el_gamal_sk,
        };
        let public = self
            .public
            .into_vec()
            .into_iter()
            .zip(change.public.into_vec().into_iter())
            .map(|(self_public, change_public)| KeySharePublic {
                share_pk: self_public.share_pk + change_public.share_pk,
                el_gamal_pk: change_public.el_gamal_pk,
                paillier_pk: change_public.paillier_pk,
                rp_generator: change_public.rp_generator,
                rp_power: change_public.rp_power,
            })
            .collect();
        Self {
            index: change.index,
            secret,
            public,
        }
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public.iter().map(|p| p.share_pk).sum()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO: need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub fn num_parties(&self) -> usize {
        // TODO: technically it is `num_shares`, but for now we are equating the two,
        // since we assume that one party has one share.
        self.public.len()
    }

    pub fn party_index(&self) -> PartyIdx {
        // TODO: technically it is the share index, but for now we are equating the two,
        // since we assume that one party has one share.
        self.index
    }
}

impl<P: SchemeParams> core::fmt::Debug for KeyShare<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "KeyShare(vkey={})",
            hex::encode(self.verifying_key_as_point().to_compressed_array())
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeySharePublic<P: SchemeParams> {
    pub(crate) share_pk: Point,
    pub(crate) el_gamal_pk: Point, // `Y_i`
    /// The Paillier public key.
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    /// The ring-Pedersen generator.
    pub(crate) rp_generator: <P::Paillier as PaillierParams>::DoubleUint, // `t_i`
    /// The ring-Pedersen power (a number belonging to the group produced by the generator).
    pub(crate) rp_power: <P::Paillier as PaillierParams>::DoubleUint, // `s_i`
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillier<P::Paillier>: for <'x> Deserialize<'x>"))]
pub struct KeyShareChangeSecret<P: SchemeParams> {
    /// The value to be added to the secret share.
    pub(crate) share_sk: Scalar, // `x_i^* - x_i == \sum_{j} x_j^i`
    pub(crate) paillier_sk: SecretKeyPaillier<P::Paillier>,
    pub(crate) el_gamal_sk: Scalar, // `y_i`
}

// TODO: can it be `KeySharePublic`?
#[derive(Clone)]
pub struct KeyShareChangePublic<P: SchemeParams> {
    /// The value to be added to the public share of a remote node.
    pub(crate) share_pk: Point, // `X_k^* - X_k == \sum_j X_j^k`, for all nodes
    pub(crate) el_gamal_pk: Point, // `Y_i`
    /// The Paillier public key.
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    /// The ring-Pedersen generator.
    pub(crate) rp_generator: <P::Paillier as PaillierParams>::DoubleUint, // `t_i`
    /// The ring-Pedersen power (a number belonging to the group produced by the generator).
    pub(crate) rp_power: <P::Paillier as PaillierParams>::DoubleUint, // `s_i`
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Clone)]
pub struct KeyShareChange<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) secret: KeyShareChangeSecret<P>,
    pub(crate) public: Box<[KeyShareChangePublic<P>]>,
}

/// The result of the Presigning protocol.
#[derive(Clone)]
pub struct PresigningData {
    pub(crate) big_r: Point,
    pub(crate) k: Scalar,
    pub(crate) chi: Scalar,
}
