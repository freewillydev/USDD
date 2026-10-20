//! Elements witness-only commitment, not Bitcoin's wtxid Merkle tree.
//! The activation flag must be derived from authenticated consensus history.
use bitcoin::hashes::{sha256d, Hash};
use elements::{Block, Transaction, TxInWitness, encode::{serialize, Encodable}};

fn hash<T: Encodable>(value: &T) -> [u8;32] {
    sha256d::Hash::hash(&serialize(value)).to_byte_array()
}
fn root(leaves: &[[u8;32]]) -> [u8;32] {
    elements::fast_merkle_root(leaves).to_byte_array()
}
fn input_hash(w: &TxInWitness) -> [u8;32] {
    root(&[hash(&w.amount_rangeproof), hash(&w.inflation_keys_rangeproof),
        hash(&w.script_witness), hash(&w.pegin_witness)])
}
pub fn witness_only_hash(tx: &Transaction) -> [u8;32] {
    let inputs: Vec<_> = tx.input.iter().map(|i| {
        if i.previous_output.is_null() { input_hash(&TxInWitness::empty()) }
        else { input_hash(&i.witness) }
    }).collect();
    let outputs: Vec<_> = tx.output.iter().map(|o| root(&[
        hash(&o.witness.surjection_proof), hash(&o.witness.rangeproof)
    ])).collect();
    root(&[root(&inputs), root(&outputs)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessError { Coinbase, ReservedValue, Commitment, UnexpectedWitness }

pub fn verify_witness_commitment(block: &Block, segwit_active: bool) -> Result<(),WitnessError> {
    let cb = block.txdata.first().filter(|t| t.is_coinbase()).ok_or(WitnessError::Coinbase)?;
    let input = cb.input.first().ok_or(WitnessError::Coinbase)?;
    // Native ContextualCheckBlock rejects coinbase issuance/pegin witness data.
    if input.witness.amount_rangeproof.is_some() || input.witness.inflation_keys_rangeproof.is_some()
        || !input.witness.pegin_witness.is_empty() { return Err(WitnessError::Coinbase); }
    let commitment = cb.output.iter().rev().map(|o| o.script_pubkey.as_bytes())
        .find(|s| s.len() >= 38 && s[..6] == [0x6a,0x24,0xaa,0x21,0xa9,0xed]);
    if let Some(script) = commitment.filter(|_| segwit_active) {
        let stack = &input.witness.script_witness;
        if stack.len() != 1 || stack[0].len() != 32 { return Err(WitnessError::ReservedValue); }
        let leaves: Vec<_> = block.txdata.iter().map(witness_only_hash).collect();
        let mut preimage = root(&leaves).to_vec();
        preimage.extend_from_slice(&stack[0]);
        if sha256d::Hash::hash(&preimage).to_byte_array() != script[6..38] {
            return Err(WitnessError::Commitment);
        }
        return Ok(());
    }
    if block.txdata.iter().any(Transaction::has_witness) { return Err(WitnessError::UnexpectedWitness); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{BlockHeader, BlockHash, TxMerkleNode, BlockExtData, Script, TxIn, TxOut, LockTime};
    fn fixture() -> Block {
        Block { header: BlockHeader { version:1,prev_blockhash:BlockHash::all_zeros(),
            merkle_root:TxMerkleNode::all_zeros(),time:1,height:1,
            ext:BlockExtData::Proof {challenge:Script::new(),solution:Script::new()} },
            txdata:vec![Transaction {version:2,lock_time:LockTime::ZERO,
                input:vec![TxIn::default()],output:vec![TxOut::default()]}] }
    }
    fn commit(b: &mut Block) {
        b.txdata[0].input[0].witness.script_witness = vec![vec![0;32]];
        let mut preimage = root(&b.txdata.iter().map(witness_only_hash).collect::<Vec<_>>()).to_vec();
        preimage.extend_from_slice(&[0;32]);
        let mut script = vec![0x6a,0x24,0xaa,0x21,0xa9,0xed];
        script.extend_from_slice(&sha256d::Hash::hash(&preimage).to_byte_array());
        b.txdata[0].output[0].script_pubkey = Script::from(script);
    }
    #[test]
    fn commitment_and_reserved_value_checked() {
        let mut b = fixture();
        assert_eq!(verify_witness_commitment(&b,true),Ok(()));
        commit(&mut b);
        assert_eq!(verify_witness_commitment(&b,true),Ok(()));
        assert_eq!(verify_witness_commitment(&b,false),Err(WitnessError::UnexpectedWitness));
        b.txdata[0].input[0].witness.script_witness[0][0] = 1;
        assert_eq!(verify_witness_commitment(&b,true),Err(WitnessError::Commitment));
        b.txdata[0].input[0].witness.script_witness[0].pop();
        assert_eq!(verify_witness_commitment(&b,true),Err(WitnessError::ReservedValue));
    }
    #[test]
    fn coinbase_witness_exclusions_and_uncommitted_witness() {
        let mut b = fixture();
        b.txdata[0].input[0].witness.script_witness = vec![vec![0;32]];
        assert_eq!(verify_witness_commitment(&b,true),Err(WitnessError::UnexpectedWitness));
        commit(&mut b);
        b.txdata[0].input[0].witness.pegin_witness = vec![vec![1]];
        assert_eq!(verify_witness_commitment(&b,true),Err(WitnessError::Coinbase));
    }
    #[test]
    fn noncoinbase_witness_change_preserves_txid_but_fails_commitment() {
        let mut b = fixture();
        let mut tx = b.txdata[0].clone();
        tx.input[0].previous_output.vout = 0;
        tx.input[0].witness.script_witness = vec![vec![1,2,3]];
        b.txdata.push(tx);
        commit(&mut b);
        assert_eq!(verify_witness_commitment(&b,true),Ok(()));
        let txid = b.txdata[1].txid();
        b.txdata[1].input[0].witness.script_witness[0][0] ^= 1;
        assert_eq!(b.txdata[1].txid(),txid);
        assert_eq!(verify_witness_commitment(&b,true),Err(WitnessError::Commitment));
    }
    #[test]
    fn output_rangeproof_removal_and_substitution_fail_without_changing_txid() {
        use elements::secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, Secp256k1, SecretKey, Tag, Tweak};
        let secp = Secp256k1::new();
        let generator = Generator::new_unblinded(&secp, Tag::from([7;32]));
        let blinder = Tweak::from_slice(&[3;32]).unwrap();
        let commitment = PedersenCommitment::new(&secp, 100, blinder, generator);
        let proof = |nonce| RangeProof::new(&secp, 1, commitment, 100, blinder,
            b"commitment regression", &[], SecretKey::from_slice(&[nonce;32]).unwrap(),
            0, 8, generator).unwrap();
        let mut block = fixture();
        let mut tx = block.txdata[0].clone();
        tx.input[0].previous_output.vout = 0;
        tx.output[0].asset = elements::confidential::Asset::Confidential(generator);
        tx.output[0].value = elements::confidential::Value::Confidential(commitment);
        tx.output[0].witness.rangeproof = Some(Box::new(proof(2)));
        block.txdata.push(tx);
        commit(&mut block);
        assert_eq!(verify_witness_commitment(&block, true), Ok(()));
        let txid = block.txdata[1].txid();
        let original = witness_only_hash(&block.txdata[1]);
        let output_encoding = serialize(&block.txdata[1].output[0]);
        for replacement in [None, Some(Box::new(proof(4)))] {
            block.txdata[1].output[0].witness.rangeproof = replacement;
            // Neither the txid nor the ordinary TxOut encoding authenticates
            // these bytes. The executed block's witness commitment does.
            assert_eq!(block.txdata[1].txid(), txid);
            assert_eq!(serialize(&block.txdata[1].output[0]), output_encoding);
            assert_ne!(witness_only_hash(&block.txdata[1]), original);
            assert_eq!(verify_witness_commitment(&block, true), Err(WitnessError::Commitment));
        }
    }

    #[test]
    fn last_matching_output_wins_and_trailing_script_is_allowed() {
        let mut b = fixture();
        b.txdata[0].output.push(TxOut::default());
        commit(&mut b);
        let valid = b.txdata[0].output[0].script_pubkey.clone();
        let mut wrong = valid.as_bytes().to_vec(); wrong[6] ^= 1;
        b.txdata[0].output[1].script_pubkey = Script::from(wrong);
        assert_eq!(verify_witness_commitment(&b,true),Err(WitnessError::Commitment));
        let mut trailing = valid.as_bytes().to_vec(); trailing.push(0);
        b.txdata[0].output[1].script_pubkey = Script::from(trailing);
        assert_eq!(verify_witness_commitment(&b,true),Ok(()));
    }
}
