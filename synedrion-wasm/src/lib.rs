use bincode::{
    config::{
        BigEndian, Bounded, RejectTrailing, VarintEncoding, WithOtherEndian, WithOtherIntEncoding,
        WithOtherLimit, WithOtherTrailing,
    },
    DefaultOptions, Options,
};
use js_sys::Error;
use rand_core::OsRng;
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use wasm_bindgen_derive::TryFromJsValue;

use synedrion::TestSchemeParams;

extern crate alloc;

/// Max message length allowed to be (de)serialized
const MAX_MSG_LEN: u64 = 1000 * 1000; // 1 MB

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "KeyShare[]")]
    pub type KeyShareArray;
}

/// Synedrion key share.
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct KeyShare(synedrion::KeyShare<TestSchemeParams>);

#[wasm_bindgen]
impl KeyShare {
    /// Serializes the key share to bytes using standard Entropy format.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        // TODO: can we ensure consistency here?
        // Should `entropy-core` expose the serialization function?
        bincoder()
            .serialize(&self.0)
            .map_err(|err| Error::new(&format!("{}", err)))
    }
}

/// Creates a set of key shares.
#[wasm_bindgen(js_name = makeKeyShares)]
pub fn make_key_shares(num_parties: usize) -> KeyShareArray {
    let shares = synedrion::make_key_shares::<TestSchemeParams>(&mut OsRng, num_parties);
    shares
        .into_vec()
        .into_iter()
        .map(KeyShare)
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<KeyShareArray>()
}

/// Prepares a `bincode` serde backend with our preferred config
/// This is copied from `entropy-core/crypto/kvdb/src/kv_manager/helpers.rs`
/// In the hope that it gives us shares which are encoded just the same as
/// the are in the key value store there.
#[allow(clippy::type_complexity)]
fn bincoder() -> WithOtherTrailing<
    WithOtherIntEncoding<
        WithOtherEndian<WithOtherLimit<DefaultOptions, Bounded>, BigEndian>,
        VarintEncoding,
    >,
    RejectTrailing,
> {
    DefaultOptions::new()
        .with_limit(MAX_MSG_LEN)
        .with_big_endian() // big endian representation for integers
        .with_varint_encoding() // saves a lot of space in smaller messages
        .reject_trailing_bytes() // do not ignore extra bytes at the end of the buffer
}