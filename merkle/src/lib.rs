// Copyright 2018 Chainpool

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::cmp;

use chain::merkle_node_hash;
use parity_codec::{Decode, Encode, Input};
use primitives::{io, H256};
use serialization::{deserialize, serialize, Deserializable, Reader, Serializable, Stream};

#[derive(Debug)]
pub enum Error {
    NoTx,
    SurplusHash,
    NotMatch,
    AllUsed,
    SameHash,
}

/// Partial merkle tree
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PartialMerkleTree {
    /// THe total number of transactions in the block
    pub tx_count: usize,
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
            tx_count: txids.len(),
            hashes: vec![],
            bits: Vec::with_capacity(txids.len()),
        };
        // calculate height of tree
        let height = pmt.calc_tree_height();
        // traverse the partial tree
        pmt.traverse_and_build(height, 0, txids, matches);
        pmt
    }

    /// Helper function to efficiently calculate the number of nodes at given height
    /// in the merkle tree
    fn calc_tree_height(&self) -> usize {
        let mut height = 0usize;
        while self.calc_tree_width(height) > 1 {
            height += 1;
        }
        height
    }

    #[inline]
    fn calc_tree_width(&self, height: usize) -> usize {
        (self.tx_count + (1 << height) - 1) >> height
    }

    #[inline]
    fn has_right_child(&self, height: usize, pos: usize) -> bool {
        (pos << 1) + 1 < self.calc_tree_width(height - 1)
    }

    /// Calculate the hash of a node in the merkle tree (at leaf level: the txid's themselves)
    fn calc_hash(&self, height: usize, pos: usize, txids: &[H256]) -> H256 {
        if height == 0 {
            // Hash at height 0 is the txid itself
            txids[pos]
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
    fn traverse_and_build(&mut self, height: usize, pos: usize, txids: &[H256], matches: &[bool]) {
        // Determine whether this node is the parent of at least one matched txid
        let mut parent_of_match = false;
        let mut p = pos << height;
        while p < (pos + 1) << height && p < self.tx_count {
            parent_of_match |= matches[p];
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
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
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

impl Encode for PartialMerkleTree {
    fn encode(&self) -> Vec<u8> {
        let value = serialize::<PartialMerkleTree>(&self);
        value.encode()
    }
}

impl Decode for PartialMerkleTree {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let value: Option<Vec<u8>> = Decode::decode(input);
        if let Some(value) = value {
            deserialize(Reader::new(&value)).ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use crypto::dhash256;

    use super::*;
}
