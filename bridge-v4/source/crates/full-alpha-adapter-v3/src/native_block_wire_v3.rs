//! Canonical Alpha block transport, not proof or consensus validation.
//! Preserve native extension fields and the conditional BMM body verbatim.
use super::native_header_v3::{NativeHeader, HeaderError, BMM};
use elements::{Transaction, encode::{serialize, Decodable}};
use std::io::Cursor;

#[derive(Debug)]
pub enum BlockWireError { Header(HeaderError), Decode(elements::encode::Error), Size, NonCanonical, HistoricalBmm }
impl From<HeaderError> for BlockWireError {
    fn from(e: HeaderError) -> Self { Self::Header(e) }
}
impl From<elements::encode::Error> for BlockWireError {
    fn from(e: elements::encode::Error) -> Self { Self::Decode(e) }
}

#[derive(Clone, Debug)]
pub struct NativeBlock {
    pub header: NativeHeader,
    pub transactions: Vec<Transaction>,
    pub bmm_proof: Vec<u8>,
}
impl NativeBlock {
    /// Native Elements drivechain-slot consensus rejects the historical signet
    /// proof lane (CheckBmmHeaderCommitments / ConnectBmmState). Decodability
    /// must never be confused with authorization to accept that lane on Alpha.
    pub fn check_alpha_bmm_lane(&self) -> Result<(), BlockWireError> {
        if self.header.base.version & BMM != 0 || self.header.bmm_proof != [0;32]
            || !self.bmm_proof.is_empty() {
            return Err(BlockWireError::HistoricalBmm);
        }
        Ok(())
    }
    /// Match native GetBlockWeight, whose stripped-block serializer still
    /// includes the complete header (including its DynaFed witness). Only
    /// transaction witnesses are discounted by that native serialization path.
    pub fn weight(&self) -> Result<usize, BlockWireError> {
        let header = self.header.encode(false,true)?.len();
        let count = serialize(&elements::encode::VarInt(self.transactions.len() as u64)).len();
        let proof = if self.header.base.version & BMM != 0 {
            serialize(&self.bmm_proof).len()
        } else if self.bmm_proof.is_empty() { 0 } else {
            return Err(BlockWireError::NonCanonical);
        };
        let base = header.checked_add(count).and_then(|n|n.checked_add(proof))
            .and_then(|n|n.checked_mul(4)).ok_or(BlockWireError::Size)?;
        self.transactions.iter().try_fold(base, |n, tx|
            n.checked_add(tx.weight()).ok_or(BlockWireError::Size))
    }
    pub fn decode(raw: &[u8]) -> Result<Self, BlockWireError> {
        if raw.is_empty() || raw.len() > super::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES {
            return Err(BlockWireError::Size);
        }
        let (header, consumed) = NativeHeader::decode_prefix(raw, true)?;
        let mut cursor = Cursor::new(&raw[consumed..]);
        let transactions = Vec::<Transaction>::consensus_decode(&mut cursor)?;
        let bmm_proof = if header.base.version & BMM != 0 {
            Vec::<u8>::consensus_decode(&mut cursor)?
        } else { Vec::new() };
        if consumed + cursor.position() as usize != raw.len() {
            return Err(BlockWireError::NonCanonical);
        }
        let block = Self { header, transactions, bmm_proof };
        if block.encode()? != raw { return Err(BlockWireError::NonCanonical); }
        Ok(block)
    }

    pub fn encode(&self) -> Result<Vec<u8>, BlockWireError> {
        let mut raw = self.header.encode(false,true)?;
        raw.extend(serialize(&self.transactions));
        if self.header.base.version & BMM != 0 {
            raw.extend(serialize(&self.bmm_proof));
        } else if !self.bmm_proof.is_empty() {
            // Do not silently discard caller-supplied proof bytes.
            return Err(BlockWireError::NonCanonical);
        }
        if raw.len() > super::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES {
            return Err(BlockWireError::Size);
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    #[test]
    fn native_full_block_differential_corpus() {
        #[derive(serde::Deserialize)]
        struct Corpus { blocks: Vec<Vector> }
        #[derive(serde::Deserialize)]
        struct Vector { name: String, wire: String, digest: String, critical: String, weight: usize }
        fn bytes(hex: &str) -> Vec<u8> {
            assert_eq!(hex.len()%2,0);
            (0..hex.len()).step_by(2)
                .map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect()
        }
        let corpus: Corpus = serde_json::from_str(include_str!(
            "../test-vectors/native-header-wire.json")).unwrap();
        assert_eq!(corpus.blocks.len(),256);
        for v in corpus.blocks {
            let wire = bytes(&v.wire);
            let block = NativeBlock::decode(&wire)
                .unwrap_or_else(|e|panic!("{}: {:?}",v.name,e));
            assert_eq!(block.encode().unwrap(),wire,"{}",v.name);
            assert_eq!(block.weight().unwrap(),v.weight,"{}",v.name);
            assert_eq!(block.header.hash_internal().unwrap().as_slice(),bytes(&v.digest),"{}",v.name);
            assert_eq!(block.header.bmm_critical_hash_internal().unwrap().as_slice(),
                bytes(&v.critical),"{}",v.name);
            assert_eq!(block.transactions.len(),1);
            assert_eq!(block.check_alpha_bmm_lane().is_ok(),block.header.base.version & BMM == 0);
            assert_eq!(block.transactions[0].input[0].witness.script_witness,
                if block.header.withdrawal != [0;32] { vec![vec![6,7],vec![8]] } else { vec![] });
            assert_eq!(block.bmm_proof,if block.header.base.version & BMM != 0 {
                vec![1,2,3,4,5]
            } else { vec![] });
        }
    }
    #[test]
    fn legacy_and_bmm_body_are_exact_and_never_ignored() {
        let standard = elements::Block {
            header: elements::BlockHeader { version: 1,
                prev_blockhash: elements::BlockHash::all_zeros(),
                merkle_root: elements::TxMerkleNode::all_zeros(), time: 1, height: 0,
                ext: elements::BlockExtData::Proof {
                    challenge: elements::Script::new(), solution: elements::Script::new() } },
            txdata: vec![Transaction { version: 2, lock_time: elements::LockTime::ZERO,
                input: vec![elements::TxIn::default()], output: vec![elements::TxOut::default()] }],
        };
        let raw = serialize(&standard);
        let mut native = NativeBlock::decode(&raw).unwrap();
        assert!(native.check_alpha_bmm_lane().is_ok());
        native.header.bmm_proof = [9;32];
        assert!(native.check_alpha_bmm_lane().is_err());
        native.header.bmm_proof = [0;32];
        assert_eq!(native.encode().unwrap(),raw);
        native.bmm_proof = vec![1,2,3];
        assert!(native.encode().is_err());
        native.header.base.version |= BMM;
        native.header.bmm_proof = [9;32];
        let encoded = native.encode().unwrap();
        assert!(encoded.ends_with(&[3,1,2,3]));
        let decoded = NativeBlock::decode(&encoded).unwrap();
        assert_eq!(decoded.bmm_proof,vec![1,2,3]);
        assert_eq!(decoded.header.bmm_proof,[9;32]);
        for end in 0..encoded.len() { assert!(NativeBlock::decode(&encoded[..end]).is_err()); }
        let mut trailing = encoded.clone(); trailing.push(0);
        assert!(NativeBlock::decode(&trailing).is_err());
        // Non-minimal CompactSize for the same three proof bytes is rejected.
        let mut alias = encoded[..encoded.len()-4].to_vec();
        alias.extend([253,3,0,1,2,3]);
        assert!(NativeBlock::decode(&alias).is_err());
    }
}
