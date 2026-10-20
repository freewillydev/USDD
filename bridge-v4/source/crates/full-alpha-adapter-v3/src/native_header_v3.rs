//! Extended signed, height-bearing Elements-mode Alpha header encoding.
//! Synthetic native differential fixtures; not yet integrated into the child producer.
use bitcoin::hashes::{sha256d, Hash};
use elements::{BlockHeader, BlockExtData};
use elements::encode::{serialize, Decodable};
use std::io::Cursor;

#[derive(Debug)]
pub enum HeaderError {
    Decode(elements::encode::Error),
    NonCanonical,
    NullDynafed,
    CheckpointMismatch,
}
impl From<elements::encode::Error> for HeaderError {
    fn from(error: elements::encode::Error) -> Self { Self::Decode(error) }
}

pub const WITHDRAWAL: u32 = 1 << 30;
pub const BMM: u32 = 1 << 20;
pub const EXCHANGE: u32 = 1 << 19;
pub const FORCED: u32 = 1 << 18;
pub const DEPOSIT: u32 = 1 << 17;
pub const CURSORS: u32 = 1 << 16;

/// Prior-header portion of the native execution environment. Absence is
/// all-or-nothing, matching BindPriorActiveExchangeStateRoot in validation.cpp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorExchangeContext {
    pub exchange: [u8; 32],
    pub forced: [u8; 32],
    pub deposit: [u8; 32],
    pub forced_cursor: u64,
    pub deposit_cursor: u64,
}

#[derive(Clone, Debug)]
pub struct NativeHeader {
    pub base: BlockHeader,
    pub withdrawal: [u8; 32],
    pub bmm_proof: [u8; 32],
    pub exchange: [u8; 32],
    pub forced: [u8; 32],
    pub deposit: [u8; 32],
    pub parent_height: u32,
    pub forced_cursor: u64,
    pub deposit_cursor: u64,
    pub oldest_backlog_height: u64,
}

impl NativeHeader {
    /// Bind the supplied header to an independently authenticated child tip.
    /// This does not authenticate a caller-selected checkpoint, configuration,
    /// bond-inbox projection, or the transition that produced the header.
    pub fn prior_exchange_context(
        &self, expected_tip: [u8; 32], expected_height: u32,
    ) -> Result<Option<PriorExchangeContext>, HeaderError> {
        if expected_tip == [0; 32] || self.base.height != expected_height
            || self.hash_internal()? != expected_tip {
            return Err(HeaderError::CheckpointMismatch);
        }
        let required = EXCHANGE | FORCED | DEPOSIT | CURSORS;
        if self.base.version & required != required
            || [self.exchange, self.forced, self.deposit].contains(&[0; 32]) {
            return Ok(None);
        }
        Ok(Some(PriorExchangeContext {
            exchange: self.exchange, forced: self.forced, deposit: self.deposit,
            forced_cursor: self.forced_cursor, deposit_cursor: self.deposit_cursor,
        }))
    }
    /// Decode exactly one canonical signed, height-bearing Alpha wire header.
    /// This does not accept hash preimages or a block body. `witness` specifies
    /// whether DynaFed witness bytes are present in the transport encoding.
    pub fn decode(bytes: &[u8], witness: bool) -> Result<Self, HeaderError> {
        let (header, consumed) = Self::decode_prefix(bytes, witness)?;
        if consumed != bytes.len() { return Err(HeaderError::NonCanonical); }
        Ok(header)
    }

    /// Parse a header at the start of a block without discarding body bytes.
    pub(crate) fn decode_prefix(bytes: &[u8], witness: bool) -> Result<(Self, usize), HeaderError> {
        fn read<T: Decodable>(r: &mut Cursor<&[u8]>) -> Result<T, HeaderError> {
            Ok(T::consensus_decode(r)?)
        }
        let mut r = Cursor::new(bytes);
        let version: u32 = read(&mut r)?;
        let has = |flag| version & flag != 0;
        let prev_blockhash = read(&mut r)?;
        let merkle_root = read(&mut r)?;
        let withdrawal = if has(WITHDRAWAL) { read(&mut r)? } else { [0;32] };
        let bmm_proof = if has(BMM) { read(&mut r)? } else { [0;32] };
        let time = read(&mut r)?;
        let height = read(&mut r)?;
        let dynamic = has(1 << 31);
        let ext = if dynamic {
            BlockExtData::Dynafed { current: read(&mut r)?, proposed: read(&mut r)?,
                signblock_witness: Vec::new() }
        } else {
            BlockExtData::Proof { challenge: read(&mut r)?, solution: read(&mut r)? }
        };
        let mut h = Self::from_standard(BlockHeader {
            version: version & !(WITHDRAWAL | (1 << 31)),
            prev_blockhash, merkle_root, time, height, ext,
        });
        h.withdrawal = withdrawal;
        h.bmm_proof = bmm_proof;
        if has(EXCHANGE) { h.exchange = read(&mut r)?; }
        if has(FORCED) { h.forced = read(&mut r)?; }
        if has(DEPOSIT) { h.deposit = read(&mut r)?; }
        if has(FORCED) && has(DEPOSIT) { h.parent_height = read(&mut r)?; }
        if has(CURSORS) {
            h.forced_cursor = read(&mut r)?;
            h.deposit_cursor = read(&mut r)?;
            h.oldest_backlog_height = read(&mut r)?;
        }
        if dynamic && witness {
            if let BlockExtData::Dynafed { signblock_witness, .. } = &mut h.base.ext {
                *signblock_witness = read(&mut r)?;
            }
        }
        let consumed = r.position() as usize;
        if h.encode(false, witness)? != bytes[..consumed] {
            return Err(HeaderError::NonCanonical);
        }
        Ok((h, consumed))
    }
    pub fn from_standard(base: BlockHeader) -> Self {
        Self { base, withdrawal: [0;32], bmm_proof: [0;32], exchange: [0;32],
            forced: [0;32], deposit: [0;32], parent_height: 0,
            forced_cursor: 0, deposit_cursor: 0, oldest_backlog_height: 0 }
    }

    /// `hashing` excludes legacy solution and DynaFed witness. `witness`
    /// only controls DynaFed wire witness (legacy solution is always on wire).
    pub fn encode(&self, hashing: bool, witness: bool) -> Result<Vec<u8>, HeaderError> {
        let dynamic = matches!(&self.base.ext, BlockExtData::Dynafed { current, proposed, .. }
            if !matches!(current, elements::dynafed::Params::Null)
                || !matches!(proposed, elements::dynafed::Params::Null));
        let mut version = self.base.version & !(WITHDRAWAL | (1 << 31));
        if dynamic { version |= 1 << 31; }
        if self.withdrawal != [0;32] { version |= WITHDRAWAL; }
        let has = |flag| version & flag != 0;
        let mut out = serialize(&version);
        out.extend(serialize(&self.base.prev_blockhash));
        out.extend(serialize(&self.base.merkle_root));
        if has(WITHDRAWAL) { out.extend(self.withdrawal); }
        if has(BMM) { out.extend(self.bmm_proof); }
        out.extend(serialize(&self.base.time));
        out.extend(serialize(&self.base.height));
        match &self.base.ext {
            BlockExtData::Proof { challenge, solution } => {
                out.extend(serialize(challenge));
                if !hashing { out.extend(serialize(solution)); }
            }
            BlockExtData::Dynafed { current, proposed, .. } if dynamic => {
                out.extend(serialize(current)); out.extend(serialize(proposed));
            }
            // No parallel legacy proof fields exist in the upstream enum.
            // Never invent those bytes for an unrepresentable native state.
            _ => return Err(HeaderError::NullDynafed),
        }
        if has(EXCHANGE) { out.extend(self.exchange); }
        if has(FORCED) { out.extend(self.forced); }
        if has(DEPOSIT) { out.extend(self.deposit); }
        if has(FORCED) && has(DEPOSIT) { out.extend(serialize(&self.parent_height)); }
        if has(CURSORS) {
            out.extend(serialize(&self.forced_cursor));
            out.extend(serialize(&self.deposit_cursor));
            out.extend(serialize(&self.oldest_backlog_height));
        }
        if dynamic && !hashing && witness {
            if let BlockExtData::Dynafed { signblock_witness, .. } = &self.base.ext {
                out.extend(serialize(signblock_witness));
            }
        }
        Ok(out)
    }

    pub fn hash_internal(&self) -> Result<[u8;32], HeaderError> {
        Ok(sha256d::Hash::hash(&self.encode(true, false)?).to_byte_array())
    }

    pub fn bmm_critical_hash_internal(&self) -> Result<[u8;32], HeaderError> {
        let mut critical = self.clone(); critical.bmm_proof = [0;32];
        critical.hash_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header() -> NativeHeader {
        NativeHeader::from_standard(BlockHeader { version: 1,
            prev_blockhash: elements::BlockHash::from_byte_array([1;32]),
            merkle_root: elements::TxMerkleNode::from_byte_array([2;32]),
            time: 100, height: 7, ext: BlockExtData::Proof {
                challenge: elements::Script::from(vec![0x51]), solution: elements::Script::new() } })
    }
    #[test]
    fn prior_exchange_context_requires_exact_tip_and_complete_native_fields() {
        let mut h = header();
        h.base.version |= EXCHANGE | FORCED | DEPOSIT | CURSORS;
        h.exchange = [3; 32]; h.forced = [4; 32]; h.deposit = [5; 32];
        h.forced_cursor = 17; h.deposit_cursor = 23;
        let tip = h.hash_internal().unwrap();
        let context = h.prior_exchange_context(tip, 7).unwrap().unwrap();
        assert_eq!((context.forced_cursor, context.deposit_cursor), (17, 23));
        assert!(h.prior_exchange_context(tip, 8).is_err());
        assert!(h.prior_exchange_context([0; 32], 7).is_err());
        h.deposit_cursor += 1;
        assert!(h.prior_exchange_context(tip, 7).is_err());
        for flag in [EXCHANGE, FORCED, DEPOSIT, CURSORS] {
            let mut absent = h.clone(); absent.base.version &= !flag;
            assert_eq!(absent.prior_exchange_context(absent.hash_internal().unwrap(), 7).unwrap(), None);
        }
        for index in 0..3 {
            let mut absent = h.clone();
            match index { 0 => absent.exchange = [0; 32], 1 => absent.forced = [0; 32], _ => absent.deposit = [0; 32] }
            assert_eq!(absent.prior_exchange_context(absent.hash_internal().unwrap(), 7).unwrap(), None);
        }
    }

    #[test]
    fn standard_compatibility_and_extended_commitments() {
        let mut h = header();
        assert_eq!(h.hash_internal().unwrap(), h.base.block_hash().to_byte_array());
        assert_eq!(h.encode(false,true).unwrap(),serialize(&h.base));
        h.base.version |= BMM | EXCHANGE | FORCED | DEPOSIT | CURSORS;
        h.withdrawal = [3;32]; h.bmm_proof = [4;32];
        h.exchange = [5;32]; h.forced = [6;32]; h.deposit = [7;32];
        h.parent_height = 19; h.forced_cursor = 20; h.deposit_cursor = 21;
        h.oldest_backlog_height = 22;
        assert_eq!(h.encode(true,false).unwrap().len(), 4+64+64+8+2+96+4+24);
        assert_ne!(h.hash_internal().unwrap(), h.bmm_critical_hash_internal().unwrap());
        let critical = h.bmm_critical_hash_internal().unwrap(); h.bmm_proof = [8;32];
        assert_eq!(critical,h.bmm_critical_hash_internal().unwrap());
        h.deposit_cursor += 1;
        assert_ne!(critical,h.bmm_critical_hash_internal().unwrap());
        let hash = h.hash_internal().unwrap();
        if let BlockExtData::Proof {solution,..} = &mut h.base.ext {
            *solution = elements::Script::from(vec![0x51]);
        }
        assert_eq!(hash,h.hash_internal().unwrap());
    }

    #[test]
    fn canonical_wire_roundtrip_all_extension_flag_combinations() {
        let flags = [BMM, EXCHANGE, FORCED, DEPOSIT, CURSORS];
        for mask in 0..32 {
            for withdrawal in [false, true] {
                let mut h = header();
                for (i, flag) in flags.iter().enumerate() {
                    if mask & (1 << i) != 0 { h.base.version |= flag; }
                }
                if withdrawal { h.withdrawal = [3;32]; }
                h.bmm_proof = [4;32]; h.exchange = [5;32];
                h.forced = [6;32]; h.deposit = [7;32];
                h.parent_height = 19; h.forced_cursor = 20;
                h.deposit_cursor = 21; h.oldest_backlog_height = 22;
                let bytes = h.encode(false,true).unwrap();
                let decoded = NativeHeader::decode(&bytes,true).unwrap();
                assert_eq!(decoded.encode(false,true).unwrap(),bytes);
                assert_eq!(decoded.hash_internal().unwrap(),h.hash_internal().unwrap());
                for end in 0..bytes.len() {
                    assert!(NativeHeader::decode(&bytes[..end],true).is_err());
                }
                let mut trailing = bytes.clone(); trailing.push(0);
                assert!(NativeHeader::decode(&trailing,true).is_err());
            }
        }
    }

    #[test]
    fn rejects_noncanonical_withdrawal_and_unrepresentable_dynafed() {
        let mut h = header(); h.withdrawal = [3;32];
        let mut bytes = h.encode(false,true).unwrap();
        bytes[68..100].fill(0);
        assert!(matches!(NativeHeader::decode(&bytes,true),Err(HeaderError::NonCanonical)));
        h.base.ext = BlockExtData::Dynafed { current: elements::dynafed::Params::Null,
            proposed: elements::dynafed::Params::Null, signblock_witness: vec![] };
        assert!(matches!(h.encode(false,true),Err(HeaderError::NullDynafed)));
        assert!(h.hash_internal().is_err());
    }

    #[test]
    fn matches_native_extended_header_wire_and_hashes() {
        #[derive(serde::Deserialize)]
        struct Corpus { vectors: Vec<Vector> }
        #[derive(serde::Deserialize)]
        struct Vector { name: String, witness: bool, wire: String,
            digest: String, critical: String }
        fn bytes(hex: &str) -> Vec<u8> {
            assert_eq!(hex.len() % 2, 0);
            (0..hex.len()).step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect()
        }
        let corpus: Corpus = serde_json::from_str(include_str!(
            "../test-vectors/native-header-wire.json")).unwrap();
        assert_eq!(corpus.vectors.len(),512);
        for v in corpus.vectors {
            let wire = bytes(&v.wire);
            let h = NativeHeader::decode(&wire,v.witness)
                .unwrap_or_else(|e| panic!("{}: {:?}",v.name,e));
            assert_eq!(h.encode(false,v.witness).unwrap(),wire,"{}",v.name);
            assert_eq!(h.hash_internal().unwrap().as_slice(),bytes(&v.digest),"{}",v.name);
            assert_eq!(h.bmm_critical_hash_internal().unwrap().as_slice(),
                bytes(&v.critical),"{}",v.name);
            for end in 0..wire.len() {
                assert!(NativeHeader::decode(&wire[..end],v.witness).is_err(),
                    "{} truncated at {}",v.name,end);
            }
        }
    }
}
