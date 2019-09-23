#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use chain::merkle_node_hash;
use primitives::{io, H256};
use serialization::{deserialize, serialize, Deserializable, Reader, Serializable, Stream};

/// The maximum allowed weight for a block, see BIP 141 (network rule)
const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;

#[derive(Debug)]
pub enum Error {
    /// When header merkle root don't match to the root calculated from the partial merkle tree
    MerkleRootMismatch,
    /// When partial merkle tree contains no transactions
    NoTransactions,
    /// When there are too many transactions
    TooManyTransactions,
    /// General format error
    BadFormat(String),
}

impl From<&'static str> for Error {
    fn from(err: &'static str) -> Self {
        Error::BadFormat(err.into())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Partial merkle tree
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PartialMerkleTree {
    /// THe total number of transactions in the block
    pub tx_count: u32,
    /// Transaction hashes and internal hashes
    pub hashes: Vec<H256>,
    /// node-is-parent-of-matched-txid bits
    pub bits: Vec<bool>,
}

impl PartialMerkleTree {
    /// Construct a partial merkle tree
    /// The `txids` are the transaction hashes of the block and the `matches` is the contains flags
    /// wherever a tx hash should be included in the proof.
    ///
    /// Panics when `txids` is empty or when `matches` has a different length
    pub fn from_txids(txids: &[H256], matches: &[bool]) -> Self {
        assert_ne!(txids.len(), 0);
        assert_eq!(txids.len(), matches.len());

        let mut pmt = PartialMerkleTree {
            tx_count: txids.len() as u32,
            hashes: vec![],
            bits: Vec::with_capacity(txids.len()),
        };
        // calculate height of tree
        let height = pmt.calc_tree_height();
        // traverse the partial tree
        pmt.traverse_and_build(height, 0, txids, matches);
        pmt
    }

    pub fn extract_matches(&self, matches: &mut Vec<H256>, indexes: &mut Vec<u32>) -> Result<H256> {
        matches.clear();
        indexes.clear();
        // An empty set will not work
        if self.tx_count == 0 {
            return Err(Error::NoTransactions);
        }
        // check for excessively high numbers of transactions
        if self.tx_count > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT {
            return Err(Error::TooManyTransactions);
        }
        // there can never be more hashes provided than one for every txid
        if self.hashes.len() as u32 > self.tx_count {
            return Err("Proof contains more hashes than transactions".into());
        }
        // there must be at least one bit per node in the partial tree, and at least one node per hash
        if self.bits.len() < self.hashes.len() {
            return Err("Proof contains less bits than hashes".into());
        }
        // calculate height of tree
        let height = self.calc_tree_height();
        // traverse the partial tree
        let mut bits_used = 0u32;
        let mut hash_used = 0u32;
        let merkle_root =
            self.traverse_and_extract(height, 0, &mut bits_used, &mut hash_used, matches, indexes)?;
        // Verify that all bits were consumed (except for the padding caused by
        // serializing it as a byte sequence)
        if (bits_used + 7) / 8 != (self.bits.len() as u32 + 7) / 8 {
            return Err("Not all bit were consumed".into());
        }
        // Verify that all hashes were consumed
        if hash_used != self.hashes.len() as u32 {
            return Err("Not all hashes were consumed".into());
        }
        Ok(merkle_root)
    }

    fn calc_tree_height(&self) -> u32 {
        let mut height = 0u32;
        while self.calc_tree_width(height) > 1 {
            height += 1;
        }
        height
    }

    /// Helper function to efficiently calculate the number of nodes at given height in the merkle tree
    #[inline]
    fn calc_tree_width(&self, height: u32) -> u32 {
        (self.tx_count + (1 << height) - 1) >> height
    }

    #[inline]
    fn has_right_child(&self, height: u32, pos: u32) -> bool {
        (pos << 1) + 1 < self.calc_tree_width(height - 1)
    }

    /// Calculate the hash of a node in the merkle tree (at leaf level: the txid's themselves)
    fn calc_hash(&self, height: u32, pos: u32, txids: &[H256]) -> H256 {
        if height == 0 {
            // Hash at height 0 is the txid itself
            txids[pos as usize]
        } else {
            // Calculate left hash
            let left = self.calc_hash(height - 1, pos << 1, txids);
            // Calculate right hash if not beyond the end of the array - copy left hash otherwise
            let right = if self.has_right_child(height, pos) {
                self.calc_hash(height - 1, (pos << 1) + 1, txids)
            } else {
                left
            };
            // Combine sub hashes
            merkle_node_hash(&left, &right)
        }
    }

    /// Recursive function that traverses tree nodes, storing the data as bits and hashes
    fn traverse_and_build(&mut self, height: u32, pos: u32, txids: &[H256], matches: &[bool]) {
        // Determine whether this node is the parent of at least one matched txid
        let mut parent_of_match = false;
        let mut p = pos << height;
        while p < (pos + 1) << height && p < self.tx_count {
            parent_of_match |= matches[p as usize];
            p += 1;
        }
        // Store as flag bit
        self.bits.push(parent_of_match);

        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, store hash and stop
            let hash = self.calc_hash(height, pos, txids);
            self.hashes.push(hash);
        } else {
            // Otherwise, don't store any hash, but descend into the subtrees
            self.traverse_and_build(height - 1, pos * 2, txids, matches);
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                self.traverse_and_build(height - 1, pos * 2 + 1, txids, matches);
            }
        }
    }

    /// Recursive function that traverses tree nodes, consuming the bits and hashes produced by
    /// TraverseAndBuild. It returns the hash of the respective node and its respective index.
    fn traverse_and_extract(
        &self,
        height: u32,
        pos: u32,
        bits_used: &mut u32,
        hash_used: &mut u32,
        matches: &mut Vec<H256>,
        indexes: &mut Vec<u32>,
    ) -> Result<H256> {
        if *bits_used as usize >= self.bits.len() {
            return Err("Overflowed the bits array".into());
        }
        let parent_of_match = self.bits[*bits_used as usize];
        *bits_used += 1;
        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, use stored hash and do not descend
            if *hash_used as usize >= self.hashes.len() {
                return Err("Overflowed the hash array".into());
            }
            let hash = self.hashes[*hash_used as usize];
            *hash_used += 1;
            if height == 0 && parent_of_match {
                // in case of height 0, we have a matched txid
                matches.push(hash);
                indexes.push(pos);
            }
            Ok(hash)
        } else {
            // otherwise, descend into the subtrees to extract matched txids and hashes
            let left = self.traverse_and_extract(
                height - 1,
                pos * 2,
                bits_used,
                hash_used,
                matches,
                indexes,
            )?;
            let right;
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                right = self.traverse_and_extract(
                    height - 1,
                    pos * 2 + 1,
                    bits_used,
                    hash_used,
                    matches,
                    indexes,
                )?;
                if right == left {
                    // The left and right branches should never be identical, as the transaction
                    // hashes covered by them must each be unique.
                    return Err("Found identical transaction hashes".into());
                }
            } else {
                right = left;
            }
            // and combine them before returning
            Ok(merkle_node_hash(&left, &right))
        }
    }
}

impl Serializable for PartialMerkleTree {
    fn serialize(&self, stream: &mut Stream) {
        let mut bytes: Vec<u8> = vec![0; (self.bits.len() + 7) / 8];
        for p in 0..self.bits.len() {
            bytes[p / 8] |= (self.bits[p] as u8) << (p % 8) as u8;
        }
        stream
            .append(&self.tx_count)
            .append_list(&self.hashes)
            .append_list(&bytes);
    }
}

impl Deserializable for PartialMerkleTree {
    fn deserialize<T>(reader: &mut Reader<T>) -> core::result::Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        Ok(PartialMerkleTree {
            tx_count: reader.read()?,
            hashes: reader.read_list()?,
            bits: {
                let bytes: Vec<u8> = reader.read_list()?;
                let mut flags: Vec<bool> = vec![false; bytes.len() * 8];
                for (p, flag) in flags.iter_mut().enumerate() {
                    *flag = bytes[p / 8] & (1 << (p % 8) as u8) != 0
                }
                flags
            },
        })
    }
}

impl codec::Encode for PartialMerkleTree {
    fn encode(&self) -> Vec<u8> {
        let value = serialize::<PartialMerkleTree>(&self);
        value.encode()
    }
}

impl codec::Decode for PartialMerkleTree {
    fn decode<I: codec::Input>(input: &mut I) -> Option<Self> {
        let value: Option<Vec<u8>> = codec::Decode::decode(input);
        if let Some(value) = value {
            deserialize(Reader::new(&value)).ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {}
