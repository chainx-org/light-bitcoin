#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::str;

use light_bitcoin_crypto::dhash256;
use light_bitcoin_primitives::{io, Compact, H256};
use light_bitcoin_serialization::{deserialize, serialize, Deserializable, Reader, Serializable};

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[rustfmt::skip]
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Serializable, Deserializable)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_header_hash: H256,
    pub merkle_root_hash: H256,
    pub time: u32,
    pub bits: Compact,
    pub nonce: u32,
}

impl str::FromStr for BlockHeader {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| io::Error::InvalidData)?;
        deserialize(bytes.as_slice())
    }
}

impl BlockHeader {
    /// Compute hash of the block header.
    pub fn hash(&self) -> H256 {
        block_header_hash(self)
    }
}

/// Compute hash of the block header.
pub(crate) fn block_header_hash(block_header: &BlockHeader) -> H256 {
    dhash256(&serialize(block_header))
}

impl codec::Encode for BlockHeader {
    fn encode(&self) -> Vec<u8> {
        let value = serialize::<BlockHeader>(&self);
        value.encode()
    }
}

impl codec::EncodeLike for BlockHeader {}

impl codec::Decode for BlockHeader {
    fn decode<I: codec::Input>(value: &mut I) -> Result<Self, codec::Error> {
        let value: Vec<u8> = codec::Decode::decode(value)?;
        deserialize(Reader::new(&value)).map_err(|_| "deserialize BlockHeader error".into())
    }
}

#[cfg(test)]
mod tests {
    use light_bitcoin_serialization::{primitives, Reader, Stream};

    use super::*;

    #[test]
    fn test_block_header_stream() {
        let block_header = BlockHeader {
            version: 1,
            previous_header_hash: [2; 32].into(),
            merkle_root_hash: [3; 32].into(),
            time: 4,
            bits: 5.into(),
            nonce: 6,
        };

        let mut stream = Stream::default();
        stream.append(&block_header);

        #[rustfmt::skip]
        let expected = vec![
            1, 0, 0, 0,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            4, 0, 0, 0,
            5, 0, 0, 0,
            6, 0, 0, 0,
        ].into();

        assert_eq!(stream.out(), expected);
    }

    #[test]
    fn test_block_header_reader() {
        #[rustfmt::skip]
        let buffer = vec![
            1, 0, 0, 0,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            4, 0, 0, 0,
            5, 0, 0, 0,
            6, 0, 0, 0,
        ];

        let mut reader = Reader::new(&buffer);

        let expected = BlockHeader {
            version: 1,
            previous_header_hash: [2; 32].into(),
            merkle_root_hash: [3; 32].into(),
            time: 4,
            bits: 5.into(),
            nonce: 6,
        };

        assert_eq!(expected, reader.read().unwrap());
        assert_eq!(
            primitives::io::Error::UnexpectedEof,
            reader.read::<BlockHeader>().unwrap_err()
        );
    }
}
