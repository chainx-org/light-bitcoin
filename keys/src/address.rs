//! `AddressHash` with network identifier and format type
//!
//! A Bitcoin address, or simply address, is an identifier of 26-35 alphanumeric characters, beginning with the number 1
//! or 3, that represents a possible destination for a bitcoin payment.
//!
//! https://en.bitcoin.it/wiki/Address

use core::{fmt, ops, str};

use light_bitcoin_crypto::checksum;
use light_bitcoin_primitives::io;
use light_bitcoin_serialization::{Deserializable, Reader, Serializable, Stream};

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::display::DisplayLayout;
use crate::error::Error;
use crate::AddressHash;

/// There are two address formats currently in use.
/// https://bitcoin.org/en/developer-reference#address-conversion
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Encode, Decode)]
pub enum Type {
    /// Pay to PubKey Hash
    /// Common P2PKH which begin with the number 1, eg: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
    /// https://bitcoin.org/en/glossary/p2pkh-address
    P2PKH,
    /// Pay to Script Hash
    /// Newer P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
    /// https://bitcoin.org/en/glossary/p2sh-address
    P2SH,
}

impl Default for Type {
    fn default() -> Type {
        Type::P2PKH
    }
}

impl Type {
    pub fn from(v: u32) -> Option<Self> {
        match v {
            0 => Some(Type::P2PKH),
            1 => Some(Type::P2SH),
            _ => None,
        }
    }
}

impl Serializable for Type {
    fn serialize(&self, s: &mut Stream) {
        let _stream = match *self {
            Type::P2PKH => s.append(&Type::P2PKH),
            Type::P2SH => s.append(&Type::P2SH),
        };
    }
}

impl Deserializable for Type {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        let t: u32 = reader.read()?;
        Type::from(t).ok_or(io::Error::ReadMalformedData)
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Encode, Decode)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Default for Network {
    fn default() -> Network {
        Network::Mainnet
    }
}

impl Network {
    pub fn from(v: u32) -> Option<Self> {
        match v {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            _ => None,
        }
    }
}

impl Serializable for Network {
    fn serialize(&self, s: &mut Stream) {
        let _stream = match *self {
            Network::Mainnet => s.append(&Network::Mainnet),
            Network::Testnet => s.append(&Network::Testnet),
        };
    }
}

impl Deserializable for Network {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        let t: u32 = reader.read()?;
        Network::from(t).ok_or(io::Error::ReadMalformedData)
    }
}

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

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Default)]
pub struct AddressDisplayLayout([u8; 25]);

impl ops::Deref for AddressDisplayLayout {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
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

/// `AddressHash` with network identifier and format type
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Serializable, Deserializable)]
#[derive(Encode, Decode)]
pub struct Address {
    /// The type of the address.
    pub kind: Type,
    /// The network of the address.
    pub network: Network,
    /// Public key hash.
    pub hash: AddressHash,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bs58::encode(self.layout().0).into_string().fmt(f)
    }
}

impl str::FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let hex = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::InvalidAddress)?;
        Address::from_layout(&hex)
    }
}

impl DisplayLayout for Address {
    type Target = AddressDisplayLayout;

    fn layout(&self) -> Self::Target {
        let mut result = [0u8; 25];

        result[0] = match (self.network, self.kind) {
            (Network::Mainnet, Type::P2PKH) => 0,
            (Network::Mainnet, Type::P2SH) => 5,
            (Network::Testnet, Type::P2PKH) => 111,
            (Network::Testnet, Type::P2SH) => 196,
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

        let (network, kind) = match data[0] {
            0 => (Network::Mainnet, Type::P2PKH),
            5 => (Network::Mainnet, Type::P2SH),
            111 => (Network::Testnet, Type::P2PKH),
            196 => (Network::Testnet, Type::P2SH),
            _ => return Err(Error::InvalidAddress),
        };

        let hash = AddressHash::from_slice(&data[1..21]);
        Ok(Address {
            kind,
            network,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use light_bitcoin_primitives::h160;

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
    fn test_address_to_string() { 
        let address = Address {
            kind: Type::P2PKH,
            network: Network::Mainnet,
            hash: h160("3f4aa1fedf1f54eeb03b759deadb36676b184911"),
        };
        assert_eq!(
            address.to_string(),
            "16meyfSoQV6twkAAxPe51RtMVz7PGRmWna".to_string(),
        );
        let address = Address {
           
            kind: Type::P2SH,
            network: Network::Mainnet,
            hash: h160("d246f700f4969106291a75ba85ad863cae68d667"),
        };
        assert_eq!(
            address.to_string(),
            "3LrrqZ2LtZxAcroVaYKgM6yDeRszV2sY1r".to_string(),
        );
    }

    #[test]
    fn test_address_from_str() {
        let address = Address {
           
            kind: Type::P2PKH,
            network: Network::Mainnet,
            hash: h160("3f4aa1fedf1f54eeb03b759deadb36676b184911"),
        };
        assert_eq!(
            address,
            "16meyfSoQV6twkAAxPe51RtMVz7PGRmWna".parse().unwrap()
        );

        let address = Address {
          
            kind: Type::P2SH,
            network: Network::Mainnet,
            hash: h160("d246f700f4969106291a75ba85ad863cae68d667"),
        };
        assert_eq!(
            address,
            "3LrrqZ2LtZxAcroVaYKgM6yDeRszV2sY1r".parse().unwrap()
        );
    }
}
