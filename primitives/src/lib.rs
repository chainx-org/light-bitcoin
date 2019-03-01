#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate rstd;

use fixed_hash::construct_fixed_hash;

mod bytes;
mod compact;

pub use bytes::{Bytes, TaggedBytes};
pub use compact::Compact;
pub use primitive_types::*;

construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 4 bytes (32 bits) size.
    pub struct H32(4);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 6 bytes (48 bits) size.
    pub struct H48(6);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 12 bytes (96 bits) size.
    pub struct H96(12);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 33 bytes (264 bits) size.
    pub struct H264(33);
}
construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 65 bytes (520 bits) size.
    pub struct H520(65);
}

/*
#[cfg(feature = "impl-serde")]
mod serde {
    use super::*;

    impl_uint_serde!(U128, 2);
    impl_uint_serde!(U256, 4);
    impl_uint_serde!(U512, 8);

    impl_fixed_hash_serde!(H160, 20);
    impl_fixed_hash_serde!(H256, 32);
    impl_fixed_hash_serde!(H512, 64);
}
*/

/*
#[cfg(feature = "impl-codec")]
mod codec {
    use super::*;

    impl_uint_codec!(U128, 2);
    impl_uint_codec!(U256, 4);
    impl_uint_codec!(U512, 8);

    impl_fixed_hash_codec!(H160, 20);
    impl_fixed_hash_codec!(H256, 32);
    impl_fixed_hash_codec!(H512, 64);
}
*/
