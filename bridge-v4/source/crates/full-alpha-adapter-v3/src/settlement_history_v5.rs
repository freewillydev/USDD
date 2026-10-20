//! Witness-preserving transaction opening under an authenticated V5 lineage.
//! This establishes historical inclusion, NOT current unspentness or an amount
//! opening. The caller must pin policy and terminal state independently.
use crate::{FullAlphaReceiptVerifierV3,
    custody_child_lineage_v2::{CustodyChildLineagePolicyV5, CustodyChildLineageReceiptV5,
        verify_custody_child_lineage_v5},
    child_execution_statement_v4::AlphaChildExecutionPublicValuesV5,
    native_block_wire_v3::NativeBlock};
use elements::{hashes::Hash as _, encode::serialize};

#[derive(Debug, PartialEq, Eq)]
pub enum SettlementHistoryErrorV5 { Lineage, Selection, Block, Witness, Coin, Membership, Opening }

/// Private construction ensures callers cannot relabel arbitrary transaction
/// bytes as an authenticated history opening.
pub struct HistoricalTransactionV5 {
    transaction: elements::Transaction,
    creation_height: u32,
}
impl HistoricalTransactionV5 {
    pub fn canonical_bytes(&self) -> Vec<u8> { serialize(&self.transaction) }
    pub fn txid_internal(&self) -> [u8;32] { self.transaction.txid().to_byte_array() }

    /// Compose authenticated history with current membership and a real output
    /// opening. `root` must be authenticated by the enclosing settlement replay
    /// at its pre-spend checkpoint; a witness-selected root is not sufficient.
    /// Historical inclusion alone deliberately cannot produce this projection.
    pub fn open_unspent_output(
        &self,
        root: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoNodeV2,
        leaf: &ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
        path: &ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
        opening: ecx_elements_settlement::PreviousTransactionOutputOpeningV2,
    ) -> Result<ecx_elements_settlement::VerifiedPreviousTransactionOutputV2, SettlementHistoryErrorV5> {
        use ecx_full_consensus_validator_v2::elements_v2::{
            elements_sparse_utxo_root_from_path_v2, elements_utxo_leaf_node_v2};
        use SettlementHistoryErrorV5::*;
        if leaf.outpoint.txid != self.transaction.txid()
            || leaf.outpoint.vout != opening.previous_vout
            || leaf.creation_height != self.creation_height
            || leaf.coinbase != self.transaction.is_coinbase() { return Err(Coin); }
        let output = self.transaction.output.get(opening.previous_vout as usize).ok_or(Coin)?;
        // TxOut serialization excludes its witness. Check both explicitly so
        // membership cannot silently replace the authenticated history witness.
        if serialize(output) != serialize(&leaf.output)
            || serialize(&output.witness) != serialize(&leaf.output.witness) { return Err(Coin); }
        if elements_sparse_utxo_root_from_path_v2(leaf.outpoint,
            elements_utxo_leaf_node_v2(leaf), path).map_err(|_| Membership)? != root {
            return Err(Membership);
        }
        let verified = ecx_elements_settlement::verify_previous_transaction_output_openings_v2(
            &self.canonical_bytes(), &[opening]).map_err(|_| Opening)?;
        verified.outputs.into_iter().next().ok_or(Opening)
    }
}

/// Verify ancestry all the way to the independently accepted terminal before
/// opening a transaction from one of its executed blocks. Coinbase witness
/// commitments are checked in addition to the header's transaction merkle root.
pub fn open_historical_transaction_v5(
    policy: &CustodyChildLineagePolicyV5,
    lineage: &[CustodyChildLineageReceiptV5],
    terminal: [u8;32], terminal_height: u32,
    receipt_index: usize, raw_block: &[u8], transaction_index: usize,
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<HistoricalTransactionV5, SettlementHistoryErrorV5> {
    use SettlementHistoryErrorV5::*;
    verify_custody_child_lineage_v5(policy, lineage, terminal, terminal_height, verifier)
        .map_err(|_| Lineage)?;
    let entry = lineage.get(receipt_index).ok_or(Selection)?;
    let statement = AlphaChildExecutionPublicValuesV5::from_canonical_bytes(
        &entry.receipt.public_values).map_err(|_| Lineage)?.0;
    let native = NativeBlock::decode(raw_block).map_err(|_| Block)?;
    native.check_alpha_bmm_lane().map_err(|_| Block)?;
    if native.header.hash_internal().map_err(|_| Block)? != statement.child_hash_internal
        || native.header.base.height != statement.child_height { return Err(Block); }
    let block = elements::Block { header: native.header.base, txdata: native.transactions };
    if ecx_full_consensus_validator_v2::elements_v2::elements_transaction_merkle_root_v2(
        &block.txdata).map_err(|_| Block)? != block.header.merkle_root { return Err(Block); }
    // This is an additional commitment check, not a replacement for the
    // activation rules already proved by the pinned execution guest. Without
    // a commitment the helper accepts only entirely witness-free blocks.
    crate::native_child_witness_v3::verify_witness_commitment(&block, true)
        .map_err(|_| Witness)?;
    let transaction = block.txdata.get(transaction_index).ok_or(Selection)?.clone();
    Ok(HistoricalTransactionV5 { transaction, creation_height: statement.child_height })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_full_consensus_validator_v2::elements_v2::*;
    use elements::{confidential, AssetId, OutPoint, Script, TxIn, TxOut};

    #[test]
    fn history_membership_and_amount_opening_are_all_required() {
        use elements::secp256k1_zkp::{RangeProof, Secp256k1, SecretKey, PublicKey, Tweak};
        let secp=Secp256k1::new();
        let asset=confidential::Asset::new_confidential(&secp,AssetId::from_byte_array([7;32]),
            confidential::AssetBlindingFactor::from_slice(&[0;32]).unwrap());
        let generator=asset.commitment().unwrap();
        let value=confidential::Value::new_confidential(&secp,123,generator,
            confidential::ValueBlindingFactor::from_slice(&[3;32]).unwrap());
        let nonce=SecretKey::from_slice(&[2;32]).unwrap();
        let mut output = TxOut { asset, value,
            nonce: confidential::Nonce::Confidential(PublicKey::from_secret_key(&secp,&nonce)),
            script_pubkey: Script::from(vec![0x51]), witness: Default::default() };
        output.witness.rangeproof=Some(Box::new(RangeProof::new(&secp,1,value.commitment().unwrap(),
            123,Tweak::from_slice(&[3;32]).unwrap(),b"settlement opening",output.script_pubkey.as_bytes(),
            nonce,0,8,generator).unwrap()));
        // Private construction only for unit testing this composition layer;
        // production construction requires the verified lineage/block opening.
        let history = HistoricalTransactionV5 { creation_height: 2,
            transaction: elements::Transaction { version:2, lock_time: elements::LockTime::ZERO,
                input:vec![TxIn::default()], output:vec![output.clone()] } };
        let leaf = ElementsUtxoLeafV2 { outpoint: OutPoint {txid:history.transaction.txid(),vout:0},
            output, creation_height:2, creation_parent_mtp:1, coinbase:true,
            created_by_issuance:false,created_by_pegin:false };
        let mut empty = canonical_empty_elements_utxo_leaf_v2();
        let mut siblings = vec![];
        for _ in 0..256 { siblings.push(empty); empty=elements_sparse_utxo_parent_v2(empty,empty).unwrap(); }
        let path = ElementsSparseUtxoPathV2 {siblings};
        let root = elements_sparse_utxo_root_from_path_v2(leaf.outpoint,elements_utxo_leaf_node_v2(&leaf),&path).unwrap();
        let opening = ecx_elements_settlement::PreviousTransactionOutputOpeningV2 {
            previous_vout:0,expected_asset_id:[7;32],amount:123,
            asset_blinding_factor:[0;32],value_blinding_factor:[3;32] };
        assert_eq!(history.open_unspent_output(root,&leaf,&path,opening).unwrap().amount,123);
        assert!(history.open_unspent_output(empty,&leaf,&path,opening).is_err());
        let mut bad_path=path.clone(); bad_path.siblings.pop();
        assert!(history.open_unspent_output(root,&leaf,&bad_path,opening).is_err());
        let mut wrong=opening; wrong.amount+=1;
        assert!(history.open_unspent_output(root,&leaf,&path,wrong).is_err());
        wrong=opening; wrong.expected_asset_id[0]^=1;
        assert!(history.open_unspent_output(root,&leaf,&path,wrong).is_err());
        let mut bad=leaf.clone(); bad.creation_height+=1;
        assert!(history.open_unspent_output(root,&bad,&path,opening).is_err());
        bad=leaf.clone(); bad.outpoint.vout=1;
        assert!(history.open_unspent_output(root,&bad,&path,opening).is_err());
        bad=leaf.clone(); bad.output.script_pubkey=Script::from(vec![0x52]);
        assert!(history.open_unspent_output(root,&bad,&path,opening).is_err());
        bad=leaf.clone(); bad.output.witness.rangeproof=None;
        // Ordinary UTXO leaves do not hash output witnesses. Historical opening
        // must still reject removal even though the membership root is unchanged.
        assert_eq!(elements_utxo_leaf_node_v2(&bad),elements_utxo_leaf_node_v2(&leaf));
        assert!(history.open_unspent_output(root,&bad,&path,opening).is_err());
    }
}
