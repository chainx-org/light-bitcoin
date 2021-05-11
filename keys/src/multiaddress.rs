//!For multiChain such as dogecoin and bitcoincash
use core::{fmt, str};
use light_bitcoin_crypto::checksum;
use light_bitcoin_primitives::io;
use light_bitcoin_serialization::{Deserializable, Reader, Serializable, Stream};

use codec::{Decode, Encode};
use bch_addr::Converter;
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
    Bitcoincash,
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
            2 => Some(Chain::Bitcoincash),
            _ => None,
        }
    }
}

impl Serializable for Chain {
    fn serialize(&self, s: &mut Stream) {
        let _stream = match *self {
            Chain::Bitcoin => s.append(&Chain::Bitcoin),
            Chain::Dogecoin => s.append(&Chain::Dogecoin),
            Chain::Bitcoincash => s.append(&Chain::Bitcoincash),
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
        // The new BCH address length is 42
        // Used for BCH old and new address translation
        // the old addresses are not supported
        if s.len() == 42 {
            let converter = Converter::new();
            let legacy_addr = converter.to_legacy_addr(&s).unwrap();
            // The old BCH address format is similar to the Bitcoin address format
            let mut new_hex = bs58::decode(legacy_addr)
                .into_vec()
                .map_err(|_| Error::InvalidAddress)?;
            // If the address is BCH, the tail is marked with 0
            new_hex.push(0);
            return MultiAddress::from_layout(&new_hex);
        }
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
            (Chain::Bitcoincash, Network::Mainnet, Type::P2PKH) => 0,
            (Chain::Bitcoincash, Network::Mainnet, Type::P2SH) => 5,
            (Chain::Bitcoincash, Network::Testnet, Type::P2PKH) => 111,
            (Chain::Bitcoincash, Network::Testnet, Type::P2SH) => 196,
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
        if data.len() != 25 && data.len() != 26 {
            return Err(Error::InvalidAddress);
        }

        let cs = checksum(&data[0..21]);
        if &data[21..25] != cs.as_bytes() {
            return Err(Error::InvalidChecksum);
        }

        let (chain, network, kind) = match data[0] {
            0 => {
                // Determine the type of blockchain based on the tail identifier(BTC or BCH)
                if data.len() == 26 {
                    (Chain::Bitcoincash, Network::Mainnet, Type::P2PKH)
                }else{
                    (Chain::Bitcoin, Network::Mainnet, Type::P2PKH)
                }
            },
            5 => {
                if data.len() == 26 {
                    (Chain::Bitcoincash, Network::Mainnet, Type::P2SH)
                }else{
                    (Chain::Bitcoin, Network::Mainnet, Type::P2SH)
                }
            },
            111 => {
                if data.len() == 26 {
                    (Chain::Bitcoincash, Network::Testnet, Type::P2PKH)
                }else{
                    (Chain::Bitcoin, Network::Testnet, Type::P2PKH)
                }
            },
            196 => {
                if data.len() == 26 {
                    (Chain::Bitcoincash, Network::Testnet, Type::P2SH)
                }else{
                    (Chain::Bitcoin, Network::Testnet, Type::P2SH)
                }
            },
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

    #[test]
    fn test_bitcoincash_address() {
        let address: MultiAddress = "qqfc3lxxylme0w87c5j2wdmsqln6e844xcmsdssvzy".parse().unwrap();
        assert_eq!(
            address.to_string(),
            "12nHwhNfruCi7jZ2zMxSNGHmjUGjN2xhmR".to_string(),
        )
    }
}