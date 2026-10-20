//! Trace the exact pool pair through receipt-authenticated block bodies.
//! This supplements native execution receipts; it never substitutes for them.
use super::*;
use ecx_full_alpha_adapter_v3::{child_execution_state_v3::ChildExecutionCheckpointV3,
    native_block_wire_v3::NativeBlock};

pub(super) fn trace_pool_lineage(
    initial_checkpoint: &ChildExecutionCheckpointV3,
    checkpoints: &[&ChildExecutionCheckpointV3],
    blocks: &[Vec<u8>],
    initial_inventory: &ElementsEconomicLeafV2,
    initial_reserve: &ElementsEconomicLeafV2,
    inventory: &ElementsEconomicLeafV2,
    reserve: &ElementsEconomicLeafV2,
) -> Result<(), RedemptionCapabilityErrorV2> {
    use RedemptionCapabilityErrorV2::Configuration;
    if blocks.len()!=checkpoints.len() {return Err(Configuration);}
    let mut previous_tip=initial_checkpoint.tip_internal;
    let mut height=initial_checkpoint.height;
    let mut pair=[initial_inventory.utxo.outpoint,initial_reserve.utxo.outpoint];
    let scripts=[&initial_inventory.utxo.output.script_pubkey,&initial_reserve.utxo.output.script_pubkey];
    let assets=[initial_inventory.asset_id,initial_reserve.asset_id];
    for (raw,checkpoint) in blocks.iter().zip(checkpoints) {
        let block=NativeBlock::decode(raw).map_err(|_| Configuration)?;
        block.check_alpha_bmm_lane().map_err(|_| Configuration)?;
        height=height.checked_add(1).ok_or(Configuration)?;
        if checkpoint.height!=height || block.header.base.height!=height
            || block.header.base.prev_blockhash.to_byte_array()!=previous_tip
            || block.header.hash_internal().map_err(|_| Configuration)?!=checkpoint.tip_internal
            || ecx_full_consensus_validator_v2::elements_v2::elements_transaction_merkle_root_v2(
                &block.transactions).map_err(|_| Configuration)?!=block.header.base.merkle_root {
            return Err(Configuration);
        }
        for tx in &block.transactions {
            let uses=pair.map(|outpoint|tx.input.iter().filter(|input|input.previous_output==outpoint).count());
            if uses==[0,0] {continue;}
            // The compiled covenant fixes pool input and successor output roles.
            // A full reserve drain has no live reserve and cannot satisfy a
            // subsequent funded-conversion probe; it is not relabeled as one.
            if uses!=[1,1] || tx.input.get(1).map(|i|i.previous_output)!=Some(pair[0])
                || tx.input.get(2).map(|i|i.previous_output)!=Some(pair[1]) {return Err(Configuration);}
            for role in 0..2 {
                let output=tx.output.get(role+1).ok_or(Configuration)?;
                if &output.script_pubkey!=scripts[role]
                    || output.asset!=elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array(assets[role]))
                    || !matches!(output.value,elements::confidential::Value::Explicit(_)) {
                    return Err(Configuration);
                }
                pair[role]=elements::OutPoint {txid:tx.txid(),vout:(role+1) as u32};
            }
        }
        previous_tip=checkpoint.tip_internal;
    }
    if pair!=[inventory.utxo.outpoint,reserve.utxo.outpoint] {return Err(Configuration);}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{confidential::{Asset,Value,Nonce},Script,TxOutWitness,Transaction,TxIn,LockTime};
    use ecx_full_consensus_validator_v2::elements_v2::*;
    use ecx_full_alpha_adapter_v3::native_withdrawal_accumulator_v3::WithdrawalAccumulator;

    #[test]
    fn traces_multiple_spends_in_a_block_and_rejects_substitutions() {
        // Synthetic transport/trace fixture, not an executed Alpha block.
        let (fixture,_)=crate::wire_tests::fixture();
        let mut initial_i=fixture.inventory.leaf.decode().unwrap();
        initial_i.asset_id=[1;32];
        initial_i.utxo.outpoint.vout=1;
        initial_i.utxo.output.asset=Asset::Explicit(elements::AssetId::from_byte_array([1;32]));
        initial_i.utxo.output.value=Value::Explicit(100);
        initial_i.utxo.output.nonce=Nonce::Null;
        initial_i.utxo.output.witness=TxOutWitness::default();
        initial_i.utxo.output.script_pubkey=Script::from(vec![0x51]);
        let mut initial_r=initial_i.clone();
        initial_r.asset_id=[2;32];initial_r.utxo.outpoint.vout=2;
        initial_r.utxo.output.asset=Asset::Explicit(elements::AssetId::from_byte_array([2;32]));
        initial_r.utxo.output.script_pubkey=Script::from(vec![0x52]);
        let cp=ChildExecutionCheckpointV3 {genesis_internal:[3;32],configuration_commitment:[4;32],
            tip_internal:[5;32],height:10,history_commitment:[6;32],spent_claims_root:[7;32],
            withdrawals:WithdrawalAccumulator::empty(),roots:ElementsTransactionStateRootsV2 {
                utxo_root:canonical_empty_elements_utxo_leaf_v2(),
                economic_root:canonical_empty_elements_economic_leaf_v2(),
            }};
        let make_tx=|pair: [elements::OutPoint;2]| Transaction {version:2,lock_time:LockTime::ZERO,
            input:vec![TxIn::default(),TxIn {previous_output:pair[0],..TxIn::default()},
                TxIn {previous_output:pair[1],..TxIn::default()}],
            output:vec![initial_r.utxo.output.clone(),initial_i.utxo.output.clone(),initial_r.utxo.output.clone()]};
        let tx1=make_tx([initial_i.utxo.outpoint,initial_r.utxo.outpoint]);
        let pair1=[1,2].map(|vout|elements::OutPoint {txid:tx1.txid(),vout});
        let tx2=make_tx(pair1);
        let mut current_i=initial_i.clone();current_i.utxo.outpoint=elements::OutPoint {txid:tx2.txid(),vout:1};
        let mut current_r=initial_r.clone();current_r.utxo.outpoint=elements::OutPoint {txid:tx2.txid(),vout:2};
        let block=elements::Block {header:elements::BlockHeader {version:1,
            prev_blockhash:elements::BlockHash::from_byte_array(cp.tip_internal),
            merkle_root:elements_transaction_merkle_root_v2(&[tx1.clone(),tx2.clone()]).unwrap(),
            time:100,height:11,ext:elements::BlockExtData::Proof {challenge:Script::new(),solution:Script::new()}},
            txdata:vec![tx1,tx2]};
        let raw=elements::encode::serialize(&block);
        let native=NativeBlock::decode(&raw).unwrap();
        let mut next=cp.clone();next.height=11;next.tip_internal=native.header.hash_internal().unwrap();
        let check=|raw:Vec<u8>,i:&ElementsEconomicLeafV2| trace_pool_lineage(&cp,&[&next],&[raw],
            &initial_i,&initial_r,i,&current_r);
        assert_eq!(check(raw.clone(),&current_i),Ok(()));
        assert!(check(raw.clone(),&initial_i).is_err());
        let mut changed=block.clone();changed.txdata.swap(0,1);
        assert!(check(elements::encode::serialize(&changed),&current_i).is_err());
        let mut changed=block.clone();changed.txdata[1].output[1].value=Value::Explicit(999);
        assert!(check(elements::encode::serialize(&changed),&current_i).is_err());
        assert!(trace_pool_lineage(&cp,&[&next],&[],&initial_i,&initial_r,&current_i,&current_r).is_err());
        assert!(trace_pool_lineage(&cp,&[&next,&next],&[raw.clone(),raw],
            &initial_i,&initial_r,&current_i,&current_r).is_err());

        // Recommit each mutated body so these checks exercise the pool tracer,
        // rather than failing only at the header's transaction Merkle root.
        // These are still synthetic transport fixtures, not execution receipts.
        let recommitted = |mut changed: elements::Block| {
            changed.header.merkle_root=elements_transaction_merkle_root_v2(&changed.txdata).unwrap();
            let raw=elements::encode::serialize(&changed);
            let mut checkpoint=next.clone();
            checkpoint.tip_internal=NativeBlock::decode(&raw).unwrap().header.hash_internal().unwrap();
            let last=changed.txdata.last().unwrap().txid();
            let mut i=current_i.clone();i.utxo.outpoint.txid=last;
            let mut r=current_r.clone();r.utxo.outpoint.txid=last;
            trace_pool_lineage(&cp,&[&checkpoint],&[raw],&initial_i,&initial_r,&i,&r)
        };
        assert_eq!(recommitted(block.clone()),Ok(()));
        let mut changed=block.clone();changed.txdata[1].input.swap(1,2);
        assert!(recommitted(changed).is_err());
        let mut changed=block.clone();changed.txdata[1].input.pop();
        assert!(recommitted(changed).is_err());
        let mut changed=block.clone();
        let duplicate=changed.txdata[1].input[1].clone();
        changed.txdata[1].input.push(duplicate);
        assert!(recommitted(changed).is_err());
        let mut changed=block.clone();changed.txdata[1].output[1].script_pubkey=Script::from(vec![0x53]);
        assert!(recommitted(changed).is_err());
        let mut changed=block.clone();changed.txdata[1].output[2].asset=initial_i.utxo.output.asset;
        assert!(recommitted(changed).is_err());
        let mut changed=block.clone();changed.txdata[1].output[2].value=Value::Null;
        assert!(recommitted(changed).is_err());
        let mut changed=block.clone();changed.txdata[1].output.pop();
        assert!(recommitted(changed).is_err());
    }
}
