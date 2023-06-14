use alloc::string::String;

use crate::protocols::common::PartyIdx;

#[derive(Debug)]
pub enum Error {
    ErrorRound, // TODO: to be replaced with actual error round handling
    MyFault(MyFault),
    TheirFault { party: PartyIdx, error: TheirFault },
    TheirFaultUnprovable { party: PartyIdx, error: TheirFault },
}

#[derive(Debug)]
pub enum MyFault {
    /// A mutable object was in an invalid state for calling a method.
    ///
    /// This indicates a logic error either in the calling code or in the method code.
    InvalidState(String),
    /// A message could not be serialized.
    ///
    /// Refer to the documentation of the chosen serialization library for more info.
    SerializationError(rmp_serde::encode::Error),
    InvalidId(PartyIdx),
    SigningError(String),
}

#[derive(Debug)]
pub enum TheirFault {
    SignatureFormatError(String),
    DeserializationError(rmp_serde::decode::Error),
    DuplicateMessage,
    OutOfOrderMessage {
        current_stage: u8,
        message_stage: u8,
    },
    VerificationFail(String),
}