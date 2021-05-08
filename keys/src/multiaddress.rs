//!For multiChain such as dogecoin
use core::{fmt, str};
use light_bitcoin_crypto::checksum;
use light_bitcoin_primitives::io;
use light_bitcoin_serialization::{Deserializable, Reader, Serializable, Stream};

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::address::{AddressDisplayLayout, Network, Type};
use crate::display::DisplayLayout;
use crate::error::Error;
use crate::AddressHash;

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Encode, Decode)]
pub enum Chain {
    Dogecoin,
    Bitcoin,
}

impl Default for Chain {
    fn default() -> Chain {
        Chain::Bitcoin
    }
}

impl Chain {
    pub fn from(v: u32) -> Option<Self> {
        match v {
            0 => Some(Chain::Bitcoin),
            1 => Some(Chain::Dogecoin),
            _ => None,
        }
    }
}

impl Serializable for Chain {
    fn serialize(&self, s: &mut Stream) {
        let _stream = match *self {
            Chain::Bitcoin => s.append(&Chain::Bitcoin),
            Chain::Dogecoin => s.append(&Chain::Dogecoin),
        };
    }
}

impl Deserializable for Chain {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        let t: u32 = reader.read()?;
        Chain::from(t).ok_or(io::Error::ReadMalformedData)
    }
}

/// `AddressHash` with network identifier and format type
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Serializable, Deserializable)]
#[derive(Encode, Decode)]
pub struct MultiAddress {
    /// The chain-name of the address
    pub chain: Chain,
    /// The type of the address.
    pub kind: Type,
    /// The network of the address.
    pub network: Network,
    /// Public key hash.
    pub hash: AddressHash,
}

impl fmt::Display for MultiAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bs58::encode(self.layout().0).into_string().fmt(f)
    }
}

impl str::FromStr for MultiAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let hex = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::InvalidAddress)?;
        MultiAddress::from_layout(&hex)
    }
}

impl DisplayLayout for MultiAddress {
    type Target = AddressDisplayLayout;

    fn layout(&self) -> Self::Target {
        let mut result = [0u8; 25];

        result[0] = match (self.chain, self.network, self.kind) {
            (Chain::Bitcoin, Network::Mainnet, Type::P2PKH) => 0,
            (Chain::Bitcoin, Network::Mainnet, Type::P2SH) => 5,
            (Chain::Bitcoin, Network::Testnet, Type::P2PKH) => 111,
            (Chain::Bitcoin, Network::Testnet, Type::P2SH) => 196,
            (Chain::Dogecoin, Network::Mainnet, Type::P2PKH) => 30,
            (Chain::Dogecoin, Network::Testnet, Type::P2PKH) => 113,
            _ => panic!("Unsupported tri-tuple"),
        };

        result[1..21].copy_from_slice(self.hash.as_bytes());
        let cs = checksum(&result[0..21]);
        result[21..25].copy_from_slice(cs.as_bytes());
        AddressDisplayLayout(result)
    }

    fn from_layout(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if data.len() != 25 {
            return Err(Error::InvalidAddress);
        }

        let cs = checksum(&data[0..21]);
        if &data[21..] != cs.as_bytes() {
            return Err(Error::InvalidChecksum);
        }

        let (chain, network, kind) = match data[0] {
            0 => (Chain::Bitcoin, Network::Mainnet, Type::P2PKH),
            5 => (Chain::Bitcoin, Network::Mainnet, Type::P2SH),
            111 => (Chain::Bitcoin, Network::Testnet, Type::P2PKH),
            196 => (Chain::Bitcoin, Network::Testnet, Type::P2SH),
            30 => (Chain::Dogecoin, Network::Mainnet, Type::P2PKH),
            113 => (Chain::Dogecoin, Network::Testnet, Type::P2PKH),
            _ => return Err(Error::InvalidAddress),
        };

        let hash = AddressHash::from_slice(&data[1..21]);
        Ok(MultiAddress {
            chain,
            kind,
            network,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dogecoin_address() {
        let address: MultiAddress = "D5gKqqDSirsdVpNA9efWKaBmsGD7TcckQ9".parse().unwrap();
        assert_eq!(
            address.to_string(),
            "D5gKqqDSirsdVpNA9efWKaBmsGD7TcckQ9".to_string(),
        )
    }
}
