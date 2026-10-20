//! Exact Truthcoin authority journal for the parameterized authority leaf.
//! The execution domain is fixed, not caller-selected. This codec alone is
//! not a source receipt verifier or a qualified authority guest.
//! Encoding does not authenticate these fields. The enclosing guest must bind
//! every field to verified state, transactions and prior-active parent context.
use sha2::{Digest, Sha256};
use crate::truthcoin_authority_policy::EXECUTION_DOMAIN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalDecodeError { Length, WrongDomain }

fn take<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
    let (head, tail) = bytes.split_at(N);
    *bytes = tail;
    head.try_into().expect("fixed field width")
}

fn read_input(bytes: &mut &[u8]) -> InputBinding {
    InputBinding {
        txid: take(bytes), vout: u32::from_be_bytes(take(bytes)),
        script_hash: take(bytes), asset: take(bytes),
        amount: u64::from_be_bytes(take(bytes)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputBinding {
    /// Exact bytes returned by the Simplicity outpoint jet; no host reversal.
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TruthcoinAuthorityJournalV1 {
    pub configuration_hash: [u8; 32],
    pub prior_commitment: [u8; 32],
    pub next_commitment: [u8; 32],
    pub transaction_id: [u8; 32],
    pub authority: InputBinding,
    pub sponsor: InputBinding,
    /// Prior-active endpoint, NOT the future transaction inclusion block.
    pub prior_parent_hash: [u8; 32],
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub prior_parent_chainwork: [u8; 32],
}

impl TruthcoinAuthorityJournalV1 {
    pub const ENCODED_LEN: usize = 456;
    /// Exact-width wire decode only. Semantic/authentication checks are separate.
    pub fn decode_exact(mut bytes: &[u8]) -> Result<Self, JournalDecodeError> {
        if bytes.len() != Self::ENCODED_LEN { return Err(JournalDecodeError::Length); }
        let domain: [u8; 32] = take(&mut bytes);
        if domain != <[u8; 32]>::from(Sha256::digest(EXECUTION_DOMAIN)) {
            return Err(JournalDecodeError::WrongDomain);
        }
        let journal = Self {
            configuration_hash: take(&mut bytes),
            prior_commitment: take(&mut bytes), next_commitment: take(&mut bytes),
            transaction_id: take(&mut bytes), authority: read_input(&mut bytes),
            sponsor: read_input(&mut bytes), prior_parent_hash: take(&mut bytes),
            prior_parent_height: u64::from_be_bytes(take(&mut bytes)),
            prior_parent_mtp: u64::from_be_bytes(take(&mut bytes)),
            prior_parent_chainwork: take(&mut bytes),
        };
        debug_assert!(bytes.is_empty());
        Ok(journal)
    }
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = Vec::with_capacity(Self::ENCODED_LEN);
        for field in [Sha256::digest(EXECUTION_DOMAIN).into(), self.configuration_hash,
            self.prior_commitment, self.next_commitment, self.transaction_id] {
            bytes.extend_from_slice(&field);
        }
        for input in [&self.authority, &self.sponsor] {
            bytes.extend_from_slice(&input.txid);
            bytes.extend_from_slice(&input.vout.to_be_bytes());
            bytes.extend_from_slice(&input.script_hash);
            bytes.extend_from_slice(&input.asset);
            bytes.extend_from_slice(&input.amount.to_be_bytes());
        }
        bytes.extend_from_slice(&self.prior_parent_hash);
        bytes.extend_from_slice(&self.prior_parent_height.to_be_bytes());
        bytes.extend_from_slice(&self.prior_parent_mtp.to_be_bytes());
        bytes.extend_from_slice(&self.prior_parent_chainwork);
        bytes.try_into().expect("fixed checkpoint journal length")
    }

    /// The guest commits these 32 bytes, not the 456-byte preimage.
    pub fn public_values(&self) -> [u8; 32] { Sha256::digest(self.encode()).into() }

    /// The native compressed-proof jet takes SHA256(exact public values).
    pub fn verifier_public_values_hash(&self) -> [u8; 32] {
        Sha256::digest(self.public_values()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_offsets_and_every_byte_are_bound() {
        let j = TruthcoinAuthorityJournalV1 {
            configuration_hash: [2;32],
            prior_commitment: [3;32], next_commitment: [4;32], transaction_id: [5;32],
            authority: InputBinding {txid:[6;32],vout:0x01020304,script_hash:[7;32],asset:[8;32],amount:0x0102030405060708},
            sponsor: InputBinding {txid:[9;32],vout:0x11121314,script_hash:[10;32],asset:[11;32],amount:0x1112131415161718},
            prior_parent_hash:[12;32],prior_parent_height:0x2122232425262728,
            prior_parent_mtp:0x3132333435363738,prior_parent_chainwork:[13;32],
        };
        let bytes=j.encode();
        // Independently encoded with Perl pack(N)/pack(H*) and Digest::SHA.
        assert_eq!(j.public_values(), [0xaf,0xab,0x38,0xcc,0x82,0x32,0xf7,0xad,0xcd,0xca,0x11,0x88,0xfc,0x25,0x88,0xf7,0x78,0xd3,0x3b,0x3d,0xbc,0x15,0x60,0xf2,0xf2,0x17,0xe8,0x13,0xcd,0x16,0xe2,0xdd]);
        assert_eq!(j.verifier_public_values_hash(), [0x43,0x31,0x73,0xbd,0x8d,0x83,0xf0,0x8b,0x71,0xfc,0x1c,0xb6,0x53,0x3b,0x9d,0xb0,0x4e,0xa6,0x71,0x30,0x02,0xaf,0x5c,0xa9,0x96,0xa5,0x5e,0x7a,0xe1,0x87,0xa9,0x91]);
        assert_eq!(TruthcoinAuthorityJournalV1::decode_exact(&bytes), Ok(j.clone()));
        for n in 0..bytes.len() {
            assert_eq!(TruthcoinAuthorityJournalV1::decode_exact(&bytes[..n]), Err(JournalDecodeError::Length));
        }
        let mut extra=bytes.to_vec(); extra.push(0);
        assert_eq!(TruthcoinAuthorityJournalV1::decode_exact(&extra),Err(JournalDecodeError::Length));
        assert_eq!(&bytes[..32], Sha256::digest(EXECUTION_DOMAIN).as_slice());
        let mut foreign = bytes;
        foreign[..32].copy_from_slice(&Sha256::digest(b"ECX_USDD_DEX_CHECKPOINT_EXECUTION_V1"));
        assert_eq!(TruthcoinAuthorityJournalV1::decode_exact(&foreign), Err(JournalDecodeError::WrongDomain));
        assert_eq!(&bytes[192..196], &[1,2,3,4]);
        assert_eq!(&bytes[260..268], &[1,2,3,4,5,6,7,8]);
        assert_eq!(&bytes[300..304], &[17,18,19,20]);
        assert_eq!(&bytes[408..416], &[33,34,35,36,37,38,39,40]);
        assert_eq!(&bytes[416..424], &[49,50,51,52,53,54,55,56]);
        assert_eq!(&bytes[424..], &[13;32]);
        for i in 0..bytes.len() {
            let mut changed=bytes; changed[i]^=1;
            if i < 32 {
                assert_eq!(TruthcoinAuthorityJournalV1::decode_exact(&changed), Err(JournalDecodeError::WrongDomain));
            } else {
                assert_eq!(TruthcoinAuthorityJournalV1::decode_exact(&changed).unwrap().encode(),changed);
            }
            assert_ne!(<[u8;32]>::from(Sha256::digest(changed)),j.public_values());
        }
        assert_ne!(j.public_values(),j.verifier_public_values_hash());
    }
}
