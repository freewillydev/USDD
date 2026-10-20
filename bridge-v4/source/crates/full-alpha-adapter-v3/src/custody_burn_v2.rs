//! Exact V2 custody-burn extraction. This is not a V1 accumulator claim and
//! does not authenticate transaction execution, deployment, supply or M6.
//! The enclosing relation must authenticate the transaction and freeze every
//! supplied identity and the asset-atoms-per-reserve-micro conversion.
use bitcoin::hashes::{sha256, Hash};
use elements::{confidential, Transaction};
use ecx_full_consensus_validator_v2::Hash32;
use crate::native_withdrawal_accumulator_v3::AccumulatorError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyBurnV2 {
    pub txid_display: Hash32,
    pub vout: u32,
    pub custody_id: Hash32,
    pub recipient: [u8;20],
    pub amount_micro: u64,
    pub burn_id: Hash32,
}

#[derive(Debug)]
pub enum CommittedBurnError {
    Checkpoint,
    Child(crate::native_child_block_v3::ChildFoundationError),
    TransactionIndex,
    /// Burn extraction cannot relabel the asset tracked by checked execution.
    AssetBinding,
    Burn(AccumulatorError),
}

/// Select the burn from the exact native transaction list committed by the
/// expected Alpha critical hash, never from a separately supplied transaction.
/// Expected hashes, predecessor accumulator and deployment parameters MUST be
/// authenticated by the enclosing relation. This checks commitments only: it
/// does not prove UTXO execution, supply conservation, M6 approval or finality,
/// and does not turn this V2 burn into a native V1 accumulator claim.
#[allow(clippy::too_many_arguments)]
pub fn verify_committed_custody_burn_v2(
    raw: &[u8], genesis_internal: Hash32, previous_child: elements::BlockHash,
    height: u32, expected_parent: Hash32, expected_critical: Hash32,
    previous_accumulator: &crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator,
    segwit_active: bool, transaction_index: usize, vout: u32,
    asset_display: Hash32, custody_id: Hash32, vault_address: [u8;20],
    atoms_per_micro: u64,
) -> Result<CustodyBurnV2, CommittedBurnError> {
    let child = crate::native_child_block_v3::verify_native_child_commitments(
        raw, genesis_internal, previous_child, height, expected_parent,
        expected_critical, previous_accumulator, segwit_active,
    ).map_err(CommittedBurnError::Child)?;
    // A coinbase cannot demonstrate destruction of previously held custody.
    if transaction_index == 0 { return Err(CommittedBurnError::TransactionIndex); }
    let tx = child.block.txdata.get(transaction_index)
        .ok_or(CommittedBurnError::TransactionIndex)?;
    let mut genesis_display = genesis_internal;
    genesis_display.reverse();
    extract_custody_burn_v2(tx, vout, genesis_display, asset_display,
        custody_id, vault_address, atoms_per_micro).map_err(CommittedBurnError::Burn)
}

pub fn extract_custody_burn_v2(
    tx: &Transaction, vout: u32, genesis_display: Hash32,
    asset_display: Hash32, custody_id: Hash32, vault_address: [u8;20],
    atoms_per_micro: u64,
) -> Result<CustodyBurnV2, AccumulatorError> {
    if [genesis_display, asset_display, custody_id].contains(&[0;32])
        || vault_address == [0;20] || atoms_per_micro == 0 {
        return Err(AccumulatorError::NullIdentity);
    }
    let output = tx.output.get(vout as usize).ok_or(AccumulatorError::Malformed)?;
    let script = output.script_pubkey.as_bytes();
    if script.len() != 67 || &script[..7] != b"\x6a\x41USDD\x02"
        || script[7..39] != custody_id { return Err(AccumulatorError::Malformed); }
    let recipient: [u8;20] = script[39..59].try_into().unwrap();
    let amount_micro = u64::from_be_bytes(script[59..67].try_into().unwrap());
    if recipient == [0;20] || recipient == vault_address || amount_micro == 0
        || amount_micro > 20_000_000_000_000 { return Err(AccumulatorError::Malformed); }
    let (confidential::Asset::Explicit(asset), confidential::Value::Explicit(value), confidential::Nonce::Null) =
        (output.asset, output.value, output.nonce) else { return Err(AccumulatorError::Malformed); };
    let mut asset_bytes = asset.into_inner().to_byte_array(); asset_bytes.reverse();
    if asset_bytes != asset_display || value > i64::MAX as u64
        || amount_micro.checked_mul(atoms_per_micro) != Some(value) {
        return Err(AccumulatorError::Malformed);
    }
    let mut txid_display = tx.txid().to_byte_array(); txid_display.reverse();
    Ok(CustodyBurnV2 { txid_display, vout, custody_id, recipient, amount_micro,
        burn_id: burn_id(custody_id, genesis_display, txid_display, vout) })
}

fn burn_id(custody_id: Hash32, genesis_display: Hash32, txid_display: Hash32, vout: u32) -> Hash32 {
    // Keccak256("USDD_BURN_ID_V2"), exactly the Solidity domain.
    let mut preimage = vec![0x1c,0x81,0xc3,0x28,0xc1,0x81,0x7f,0x67,0xa0,0x97,0xf5,0x69,0x9d,0x07,0xf6,0x71,0xa3,0x09,0xdd,0xdf,0xfe,0x89,0xb1,0xd2,0xf9,0xb5,0xa2,0x0b,0x74,0x47,0xe1,0xe2];
    for h in [custody_id, genesis_display, txid_display] { preimage.extend_from_slice(&h); }
    preimage.extend_from_slice(&vout.to_be_bytes());
    sha256::Hash::hash(&preimage).to_byte_array()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    // Test-only deployment input, supplied before constructing/signing the burn.
    pub(crate) fn fixture_verifier_address() -> [u8;20] {
        match std::env::var("USDD_TEST_REDEMPTION_VERIFIER") {
            Ok(json) => serde_json::from_str(&json).expect("test verifier address"),
            Err(std::env::VarError::NotPresent) => [17;20],
            Err(error) => panic!("test verifier environment: {error}"),
        }
    }
    #[test]
    fn v2_burn_consumes_authenticated_utxo_and_economic_supply() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        use elements::{OutPoint, Txid, TxIn, Script, BlockHash};
        let (mut tx, genesis) = crate::native_withdrawal_extraction_v3::tests::fixture();
        tx.output.truncate(1);
        // Pin synthetic history independently of this burn, avoiding a circular
        // custody -> transaction -> genesis -> custody fixture construction.
        use crate::custody_redemption_statement_v2::{RedemptionDomainV2,
            extract_domain_bound_executed_burn_v2,ExecutedCustodyBurnErrorV2};
        let fixture_secp = bitcoin::secp256k1::Secp256k1::new();
        let fixture_key = bitcoin::secp256k1::SecretKey::from_slice(&[19;32]).unwrap();
        let mut fixture_challenge = vec![33];
        fixture_challenge.extend_from_slice(&bitcoin::secp256k1::PublicKey::from_secret_key(&fixture_secp,&fixture_key).serialize());
        fixture_challenge.push(0xac);
        let fixture_genesis = elements::BlockHeader {version:1,prev_blockhash:BlockHash::all_zeros(),
            merkle_root:elements::TxMerkleNode::all_zeros(),time:10,height:0,
            ext:elements::BlockExtData::Proof {challenge:Script::from(fixture_challenge),solution:Script::new()}};
        let mut domain_genesis = fixture_genesis.block_hash().to_byte_array(); domain_genesis.reverse();
        let confidential::Asset::Explicit(domain_asset) = tx.output[0].asset else {panic!()};
        let mut domain_asset = domain_asset.into_inner().to_byte_array(); domain_asset.reverse();
        let mut redemption_domain = RedemptionDomainV2 {chain_id:[1;32],vault:[9;20],custody_id:[0;32],
            vault_id:[3;32],protocol_id:[4;32],security_model_id:[5;32],verifier_program_id:[6;32],
            verifier_config_hash:[7;32],elements_genesis_display:domain_genesis,usdd_asset_display:domain_asset};
        redemption_domain.custody_id = redemption_domain.derive_custody_id(fixture_verifier_address());
        let mut script = tx.output[0].script_pubkey.as_bytes().to_vec(); script[6] = 2;
        script[7..39].copy_from_slice(&redemption_domain.custody_id);
        tx.output[0].script_pubkey = Script::from(script);
        let outpoint = OutPoint::new(Txid::from_byte_array([42;32]),0);
        tx.input.push(TxIn { previous_output:outpoint,..TxIn::default() });
        use bitcoin::secp256k1::{Secp256k1,SecretKey,PublicKey,Message};
        let spend_secp = Secp256k1::new();
        let spend_key = SecretKey::from_slice(&[23;32]).unwrap();
        let mut spend_script = vec![33];
        spend_script.extend_from_slice(&PublicKey::from_secret_key(&spend_secp,&spend_key).serialize());
        spend_script.push(0xac);
        let mut previous = tx.output[0].clone(); previous.script_pubkey = Script::from(spend_script);
        let digest = elements::sighash::SighashCache::new(&tx)
            .legacy_sighash(0,&previous.script_pubkey,elements::EcdsaSighashType::All).to_byte_array();
        let mut signature = spend_secp.sign_ecdsa(&Message::from_digest(digest),&spend_key).serialize_der().to_vec();
        signature.push(elements::EcdsaSighashType::All.as_u32() as u8);
        let mut unlocking = vec![signature.len() as u8]; unlocking.extend_from_slice(&signature);
        tx.input[0].script_sig = Script::from(unlocking);
        let leaf = ElementsUtxoLeafV2 { outpoint,output:previous,
            creation_height:1,creation_parent_mtp:1,coinbase:false,
            created_by_issuance:false,created_by_pegin:false };
        let confidential::Asset::Explicit(asset) = leaf.output.asset else { panic!() };
        let confidential::Value::Explicit(value) = leaf.output.value else { panic!() };
        let asset_internal = asset.into_inner().to_byte_array();
        let classification = ElementsEconomicClassificationV2 {
            base_asset_id:asset_internal,policy_asset_id:[99;32],
            redemption_inventory_script_sha256:[98;32],reserve_script_sha256:[97;32] };
        let economic_leaf = ElementsEconomicLeafV2 { utxo:leaf.clone(),
            asset_id:asset_internal,amount:value,asset_blinding_factor:[0;32],
            value_blinding_factor:[0;32],role:ElementsLiveEconomicRoleV2::OutstandingBase };
        let mut unode = canonical_empty_elements_utxo_leaf_v2();
        let mut enode = canonical_empty_elements_economic_leaf_v2();
        let mut usiblings = vec![]; let mut esiblings = vec![];
        for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
            usiblings.push(unode); esiblings.push(enode);
            unode = elements_sparse_utxo_parent_v2(unode,unode).unwrap();
            enode = elements_sparse_economic_parent_v2(enode,enode).unwrap();
        }
        let upath = ElementsSparseUtxoPathV2 {siblings:usiblings};
        let epath = ElementsSparseEconomicPathV2 {siblings:esiblings};
        let uinsert = ElementsSparseUtxoMutationV2 {outpoint,old_leaf:None,new_leaf:Some(leaf.clone()),path:upath.clone()};
        let einsert = ElementsSparseEconomicMutationV2 {outpoint,old_leaf:None,new_leaf:Some(economic_leaf.clone()),path:epath.clone()};
        let initial_u = apply_elements_sparse_utxo_mutation_v2(unode,&uinsert).unwrap();
        let initial_e = apply_elements_sparse_economic_mutation_v2(enode,&einsert,classification).unwrap();
        let uw = ElementsTransactionUtxoWitnessV2 {spends:vec![ElementsSparseUtxoMutationV2 {
            outpoint,old_leaf:Some(leaf),new_leaf:None,path:upath}],creates:vec![]};
        let ew = ElementsTransactionEconomicWitnessV2 {spends:vec![ElementsSparseEconomicMutationV2 {
            outpoint,old_leaf:Some(economic_leaf),new_leaf:None,path:epath}],creates:vec![]};
        // Real script engine and ECDSA spend authorization with a fixture key.
        // This does not authenticate production deployment/history.
        let verifier = FullElementsInputVerifierV2::new(BlockHash::from_byte_array(genesis));
        let run = |t:&Transaction,u:&ElementsTransactionUtxoWitnessV2,e:&ElementsTransactionEconomicWitnessV2| {
            apply_elements_transaction_state_native_v3(t,
                ElementsTransactionSpendContextV2 {height:7,parent_mtp:100},initial_u,initial_e,
                u,e,classification,&ElementsTransactionKernelWitnessV2::Ordinary,&verifier,None,
                NativeElementsLockPolicyV3 {csv_active:true,absolute_time_cutoff:100})
        };
        let next = run(&tx,&uw,&ew).unwrap();
        assert_eq!(next.utxo_root,unode); assert_eq!(next.economic_root,enode);
        assert_eq!(initial_e.aggregate.outstanding_base_atoms,u128::from(value));
        assert_eq!(next.economic_root.aggregate.outstanding_base_atoms,0);
        let mut display_genesis = genesis; display_genesis.reverse();
        let mut display_asset = asset_internal; display_asset.reverse();
        let custody = tx.output[0].script_pubkey.as_bytes()[7..39].try_into().unwrap();
        let burn = extract_custody_burn_v2(&tx,0,display_genesis,display_asset,custody,[9;20],100).unwrap();
        assert_eq!(burn.amount_micro.checked_mul(100),Some(value));
        let mut inflation = tx.clone(); inflation.output[0].value = confidential::Value::Explicit(value+1);
        // Re-sign the inflated transaction so rejection tests conservation,
        // rather than merely observing an obsolete input signature.
        let digest = elements::sighash::SighashCache::new(&inflation).legacy_sighash(0,
            &uw.spends[0].old_leaf.as_ref().unwrap().output.script_pubkey,
            elements::EcdsaSighashType::All).to_byte_array();
        let mut sig = spend_secp.sign_ecdsa(&Message::from_digest(digest),&spend_key).serialize_der().to_vec();
        sig.push(elements::EcdsaSighashType::All.as_u32() as u8);
        let mut bytes = vec![sig.len() as u8]; bytes.extend_from_slice(&sig);
        inflation.input[0].script_sig = Script::from(bytes);
        assert!(run(&inflation,&uw,&ew).is_err());
        let mut omitted = ew.clone(); omitted.spends.clear();
        assert!(run(&tx,&uw,&omitted).is_err());
        let mut forged = uw.clone(); forged.spends[0].old_leaf.as_mut().unwrap().output.value = confidential::Value::Explicit(value+1);
        assert!(run(&tx,&forged,&ew).is_err());
        let mut wrong_input = tx.clone(); wrong_input.input[0].previous_output.vout += 1;
        assert!(run(&wrong_input,&uw,&ew).is_err());
        let mut unsigned = tx.clone(); unsigned.input[0].script_sig = Script::new();
        assert!(matches!(run(&unsigned,&uw,&ew),Err(ElementsStateErrorV2::AuthorizationConsensus)));
        // Exercise the distinct-asset custody path with the same real ECDSA
        // authorization and USDD burn envelope. No native ECX is USDD supply.
        let custody_classification = ElementsCustodyClassificationV3 {
            native_pegged_asset_id: [99;32], custody_asset_id: asset_internal,
        };
        assert_ne!(custody_classification.native_pegged_asset_id, asset_internal);
        let mut custody_empty = empty_elements_custody_leaf_v3();
        let mut custody_siblings = Vec::new();
        for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
            custody_siblings.push(custody_empty);
            custody_empty = elements_custody_parent_v3(custody_empty,custody_empty).unwrap();
        }
        let custody_leaf = ew.spends[0].old_leaf.clone().unwrap();
        let custody_insert = ElementsSparseCustodyMutationV3 {
            outpoint, old_leaf:None, new_leaf:Some(custody_leaf.clone()),
            siblings:custody_siblings.clone(),
        };
        let custody_initial = apply_elements_custody_mutation_v3(
            custody_empty,&custody_insert,custody_classification).unwrap();
        let custody_witness = ElementsTransactionCustodyWitnessV3 {
            spends:vec![ElementsSparseCustodyMutationV3 {
                outpoint,old_leaf:Some(custody_leaf),new_leaf:None,siblings:custody_siblings,
            }],creates:vec![],
        };
        let run_custody = |t:&Transaction,w:&ElementsTransactionCustodyWitnessV3| {
            apply_elements_transaction_custody_native_v3(t,
                ElementsTransactionSpendContextV2 {height:7,parent_mtp:100},
                ElementsTransactionCustodyRootsV3 {utxo_root:initial_u,custody_root:custody_initial},
                &uw,w,custody_classification,&ElementsTransactionKernelWitnessV2::Ordinary,
                &verifier,None,NativeElementsLockPolicyV3 {csv_active:true,absolute_time_cutoff:100})
        };
        let custody_next = run_custody(&tx,&custody_witness).unwrap();
        assert_eq!(custody_initial.custody_supply_atoms,u128::from(value));
        assert_eq!(custody_next.custody_root,custody_empty);
        assert_eq!(custody_next.utxo_root,unode);
        assert!(matches!(run_custody(&unsigned,&custody_witness),
            Err(ElementsStateErrorV2::AuthorizationConsensus)));
        assert!(run_custody(&inflation,&custody_witness).is_err());
        assert!(run_custody(&wrong_input,&custody_witness).is_err());
        let mut omitted_custody = custody_witness.clone(); omitted_custody.spends.clear();
        assert!(run_custody(&tx,&omitted_custody).is_err());
        // Compose the same spend with full local child-block checking and a
        // real ECDSA header signature. History/roots remain synthetic fixtures.
        use elements::{Block,BlockHeader,BlockExtData,LockTime,TxOut};
        use crate::native_child_block_v3::{verify_native_child_state,ChildTransactionStateWitness,ChildStateError};
        use crate::native_withdrawal_accumulator_v3::{WithdrawalAccumulator,critical_hash_internal};
        let secp = Secp256k1::new(); let secret = SecretKey::from_slice(&[19;32]).unwrap();
        let mut challenge = vec![33]; challenge.extend_from_slice(&PublicKey::from_secret_key(&secp,&secret).serialize()); challenge.push(0xac);
        let challenge = Script::from(challenge);
        let mut marker = vec![0x6a,37]; marker.extend_from_slice(b"ELMTP"); marker.extend_from_slice(&[2;32]);
        let coinbase = Transaction {version:2,lock_time:LockTime::ZERO,
            input:vec![TxIn {script_sig:Script::from(vec![0x57,0]),..TxIn::default()}],
            output:vec![TxOut {asset:confidential::Asset::Explicit(asset),value:confidential::Value::Explicit(0),
                script_pubkey:Script::from(marker),..TxOut::default()}]};
        let mut block = Block {header:BlockHeader {version:1,prev_blockhash:BlockHash::all_zeros(),
            merkle_root:elements_transaction_merkle_root_v2(&[coinbase.clone(),tx.clone()]).unwrap(),
            time:100,height:7,ext:BlockExtData::Proof {challenge:challenge.clone(),solution:Script::new()}},
            txdata:vec![coinbase,tx.clone()]};
        let mut headers = Vec::<BlockHeader>::new();
        for height in 0..7 {
            let mut h = block.header.clone(); h.height = height; h.time = 10+height;
            h.merkle_root = elements::TxMerkleNode::all_zeros();
            h.prev_blockhash = headers.last().map(|p| p.block_hash()).unwrap_or(BlockHash::all_zeros());
            headers.push(h);
        }
        block.header.prev_blockhash = headers.last().unwrap().block_hash();
        let context = crate::native_child_context_v3::ChildContext {
            previous_headers:headers.into_iter().map(crate::native_header_v3::NativeHeader::from_standard).collect(),
            observation_time:100,csv_active:true,height_in_coinbase_active:true};
        let authorization = ElementsHeaderConsensusContextV2 {
            previous_block_hash:block.header.prev_blockhash,next_height:7,
            previous_11_times:context.previous_headers.iter().map(|h| h.base.time).collect(),
            authenticated_adjusted_time:100,expected_current_dynafed_params:None,
            expected_full_current_dynafed_params:None,legacy_signblock_challenge:challenge.clone(),legacy_signblock_witness_limit:100};
        let sign = |b:&mut Block| {
            let sig = secp.sign_ecdsa(&Message::from_digest(b.block_hash().to_byte_array()),&secret).serialize_der();
            let mut bytes = vec![sig.len() as u8]; bytes.extend_from_slice(&sig);
            b.header.ext = BlockExtData::Proof {challenge:challenge.clone(),solution:Script::from(bytes)};
        };
        sign(&mut block);
        let empty = WithdrawalAccumulator::empty();
        let execute = |b:&Block,e:&ElementsTransactionEconomicWitnessV2| {
            let critical = critical_hash_internal(genesis,24,b.block_hash().to_byte_array(),&empty,&empty).unwrap();
            verify_native_child_state(&elements::encode::serialize(b),genesis,b.header.prev_blockhash,7,
                [2;32],critical,&empty,true,&context,&authorization,
                &crate::native_header_signature_v3::NativeHeaderScriptVerifier,
                ElementsTransactionStateRootsV2 {utxo_root:initial_u,economic_root:initial_e},
                crate::native_reward_v3::RewardParameters {subsidy_asset:asset,genesis_subsidy:0,halving_interval:210000},
                &[ChildTransactionStateWitness {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionStateWitness {utxo:uw.clone(),economic:e.clone(),kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                classification,&verifier,None,None)
        };
        let checked = execute(&block,&ew).unwrap();
        assert_eq!(checked.roots(),next);
        let execute_custody_block = |b:&Block,w:&ElementsTransactionCustodyWitnessV3| {
            use crate::native_child_block_v3::{ChildTransactionCustodyWitnessV3,NativeBlockDepositsV3};
            let entries = [None,None];
            let deposits = NativeBlockDepositsV3 {entries:&entries,frozen_parent_binding:[11;32],
                frozen_deposit_configuration:[12;32],minimum_depth:1,scheduled_policy:None};
            let critical = critical_hash_internal(genesis,24,b.block_hash().to_byte_array(),&empty,&empty).unwrap();
            crate::native_child_block_v3::verify_native_child_custody_state_v3(
                &elements::encode::serialize(b),genesis,b.header.prev_blockhash,7,[2;32],critical,
                &empty,true,&context,&authorization,&crate::native_header_signature_v3::NativeHeaderScriptVerifier,
                ElementsTransactionCustodyRootsV3 {utxo_root:initial_u,custody_root:custody_initial},
                crate::native_reward_v3::RewardParameters {subsidy_asset:asset,genesis_subsidy:0,halving_interval:210000},
                &[ChildTransactionCustodyWitnessV3 {
                    utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    custody:ElementsTransactionCustodyWitnessV3 {spends:vec![],creates:vec![]},
                    kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionCustodyWitnessV3 {utxo:uw.clone(),custody:w.clone(),
                    kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                custody_classification,&verifier,&deposits,crate::native_claims_v3::empty_root())
        };
        let checked_custody = execute_custody_block(&block,&custody_witness).unwrap();
        assert_eq!(checked_custody.roots(),custody_next);
        assert_eq!(checked_custody.spent_claims_root(),crate::native_claims_v3::empty_root());
        assert!(execute_custody_block(&block,&omitted_custody).is_err());
        let mut unsigned_header = block.clone();
        if let BlockExtData::Proof {solution,..} = &mut unsigned_header.header.ext {
            *solution = Script::new();
        } else { panic!("fixture must use a signed header"); }
        assert!(matches!(execute_custody_block(&unsigned_header,&custody_witness),
            Err(ChildStateError::Authorization)));
        // Exercise the checkpoint entry point with the actual synthetic history
        // genesis, rather than the unrelated legacy fixture identity above.
        use crate::child_execution_state_v3::{ChildExecutionCheckpointV3,child_history_commitment};
        let checkpoint = ChildExecutionCheckpointV3 {
            genesis_internal: context.previous_headers[0].hash_internal().unwrap(),
            configuration_commitment: [8;32], tip_internal: block.header.prev_blockhash.to_byte_array(),
            height: 6, history_commitment: child_history_commitment(&context.previous_headers).unwrap(),
            roots: ElementsTransactionStateRootsV2 {utxo_root:initial_u,economic_root:initial_e},
            spent_claims_root: crate::native_claims_v3::empty_root(),
            withdrawals: empty.clone(),
        };
        let frozen = checkpoint.commitment().unwrap();
        let checkpoint_critical = critical_hash_internal(checkpoint.genesis_internal,24,
            block.block_hash().to_byte_array(),&empty,&empty).unwrap();
        use crate::child_deployments_v3::{ChildDeploymentConfigurationV3,BuriedDeploymentsV3,ElementsVersionbitsV3};
        let inactive = ElementsVersionbitsV3 {bit:2,start:-2,timeout:0,min_activation_height:0,period:4,threshold:3};
        let deployments = ChildDeploymentConfigurationV3 {
            buried:BuriedDeploymentsV3 {height_in_coinbase:0,strict_der:0,cltv:0,csv:0,segwit:0},
            taproot:inactive,dynafed:inactive,simplicity:inactive,
            bip16_exception_internal:[0;32],usdd_sp1_annex:false,
        };
        let frozen_deployments = deployments.commitment().unwrap();
        let (candidate, _) = crate::native_header_v3::NativeHeader::decode_prefix(
            &elements::encode::serialize(&block),true).unwrap();
        let input_rules = deployments.checked_candidate_rules(frozen_deployments,&checkpoint,frozen,
            &context.previous_headers,&candidate).unwrap().base_input_rules();
        let checkpoint_verifier = FullElementsInputVerifierV2::with_rules(
            BlockHash::from_byte_array(checkpoint.genesis_internal),input_rules);
        let custody_checkpoint=crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3 {
            genesis_internal:checkpoint.genesis_internal,configuration_commitment:checkpoint.configuration_commitment,
            tip_internal:checkpoint.tip_internal,height:checkpoint.height,history_commitment:checkpoint.history_commitment,
            classification:custody_classification,
            roots:ElementsTransactionCustodyRootsV3 {utxo_root:initial_u,custody_root:custody_initial},
            spent_claims_root:checkpoint.spent_claims_root,withdrawals:empty.clone(),
        };
        let frozen_custody=custody_checkpoint.commitment().unwrap();
        let execute_custody_checkpoint=|cp:&crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
            v:&FullElementsInputVerifierV2,w:&ElementsTransactionCustodyWitnessV3| {
            use crate::native_child_block_v3::{ChildTransactionCustodyWitnessV3,NativeBlockDepositsV3};
            let entries=[None,None];
            let deposits=NativeBlockDepositsV3 {entries:&entries,frozen_parent_binding:[11;32],
                frozen_deposit_configuration:[12;32],minimum_depth:1,scheduled_policy:None};
            crate::native_child_block_v3::verify_checkpoint_child_custody_state_v3(
                &elements::encode::serialize(&block),cp,frozen_custody,&context.previous_headers,
                [2;32],checkpoint_critical,deployments,frozen_deployments,100,&authorization,
                &crate::native_header_signature_v3::NativeHeaderScriptVerifier,
                crate::native_reward_v3::RewardParameters {subsidy_asset:asset,genesis_subsidy:0,halving_interval:210000},
                &[ChildTransactionCustodyWitnessV3 {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    custody:ElementsTransactionCustodyWitnessV3 {spends:vec![],creates:vec![]},kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionCustodyWitnessV3 {utxo:uw.clone(),custody:w.clone(),kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                v,&deposits)
        };
        let result=execute_custody_checkpoint(&custody_checkpoint,&checkpoint_verifier,&custody_witness).unwrap();
        let successor=result.next_checkpoint().unwrap();
        assert_eq!(successor.roots,custody_next);
        assert_eq!(successor.classification,custody_classification);
        assert_eq!(successor.height,7);
        assert_eq!(successor.tip_internal,block.block_hash().to_byte_array());
        assert_eq!(successor.configuration_commitment,custody_checkpoint.configuration_commitment);
        assert_eq!(successor.spent_claims_root,custody_checkpoint.spent_claims_root);
        assert_eq!(successor.withdrawals,empty);
        let mut successor_history=context.previous_headers.clone();successor_history.push(candidate.clone());
        assert_eq!(successor.history_commitment,child_history_commitment(&successor_history).unwrap());
        successor.checked_mtp_history(&successor_history).unwrap();
        assert!(checked_custody.next_checkpoint().is_none());
        let mut changed=custody_checkpoint.clone();changed.classification.custody_asset_id=[42;32];
        assert!(execute_custody_checkpoint(&changed,&checkpoint_verifier,&custody_witness).is_err());
        assert!(matches!(execute_custody_checkpoint(&custody_checkpoint,&verifier,&custody_witness),Err(ChildStateError::InputVerifierBinding)));
        assert!(execute_custody_checkpoint(&custody_checkpoint,&checkpoint_verifier,&omitted_custody).is_err());
        let execute_bound = |cp:&ChildExecutionCheckpointV3, verifier:&FullElementsInputVerifierV2| {
            crate::native_child_block_v3::verify_checkpoint_child_state(
                &elements::encode::serialize(&block),cp,frozen,&context.previous_headers,
                [2;32],checkpoint_critical,deployments,frozen_deployments,100,&authorization,
                &crate::native_header_signature_v3::NativeHeaderScriptVerifier,
                crate::native_reward_v3::RewardParameters {subsidy_asset:asset,genesis_subsidy:0,halving_interval:210000},
                &[ChildTransactionStateWitness {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionStateWitness {utxo:uw.clone(),economic:ew.clone(),kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                classification,verifier,None,None)
        };
        let execute_checkpoint = |cp:&ChildExecutionCheckpointV3| execute_bound(cp,&checkpoint_verifier);
        assert_eq!(execute_checkpoint(&checkpoint).unwrap().roots(),next);
        // Exercise the composed parent replay + signed child execution pipeline.
        // Parent receipts remain test transcripts, not cryptographic evidence.
        use crate::conversion_parent_link_v3::tests::{parent_for_child_checkpoint,TranscriptVerifier};
        use crate::native_child_block_v3::{verify_parent_bound_checkpoint_child_state,ParentBoundChildError};
        let seed_parent = parent_for_child_checkpoint(&checkpoint,[1;32]);
        let mut linked_block = block.clone();
        let mut marker = vec![0x6a,37]; marker.extend_from_slice(b"ELMTP");
        marker.extend_from_slice(&seed_parent.expected_parent_hash_internal);
        linked_block.txdata[0].output[0].script_pubkey = Script::from(marker);
        linked_block.header.merkle_root = elements_transaction_merkle_root_v2(&linked_block.txdata).unwrap();
        sign(&mut linked_block);
        let critical = critical_hash_internal(checkpoint.genesis_internal,24,
            linked_block.block_hash().to_byte_array(),&empty,&empty).unwrap();
        let parent = parent_for_child_checkpoint(&checkpoint,critical);
        let parent_frozen = parent.binding.commitment().unwrap();
        let execution_policy = crate::child_execution_policy_v3::ChildExecutionPolicyV3 {
            header_policy_commitment: crate::child_header_policy_v3::ChildHeaderPolicyV3 {
                epoch_length: 10,
                bootstrap: crate::native_child_context_v3::NativeDynafedBootstrap {
                    legacy_challenge: authorization.legacy_signblock_challenge.clone(),
                    maximum_signature_size: authorization.legacy_signblock_witness_limit,
                    fedpeg_script: vec![], start_p2wsh: false, first_extension_space: vec![],
                },
            }.commitment().unwrap(),
            genesis_internal: checkpoint.genesis_internal,
            consensus_configuration_commitment: checkpoint.configuration_commitment,
            deployments,
            reward: crate::native_reward_v3::RewardParameters {
                subsidy_asset:asset,genesis_subsidy:0,halving_interval:210000,
            },
            classification,
        };
        let frozen_policy = execution_policy.commitment().unwrap();
        let policy_wire = bincode::serialize(&execution_policy).unwrap();
        let decoded_policy: crate::child_execution_policy_v3::ChildExecutionPolicyV3 =
            bincode::deserialize(&policy_wire).unwrap();
        assert_eq!(decoded_policy, execution_policy);
        assert_eq!(decoded_policy.commitment().unwrap(), frozen_policy);
        use crate::child_execution_policy_v3::ExecutionPolicyErrorV3;
        assert_eq!(execution_policy.require_frozen(frozen_policy,&checkpoint),Ok(()));
        assert_eq!(execution_policy.require_frozen([0;32],&checkpoint),
            Err(ExecutionPolicyErrorV3::FrozenCommitment));
        for field in 0..11 {
            let mut changed = execution_policy;
            match field {
                0 => changed.genesis_internal = [90;32],
                1 => changed.consensus_configuration_commitment = [90;32],
                2 => changed.deployments.buried.csv += 1,
                3 => changed.reward.genesis_subsidy += 1,
                4 => changed.reward.halving_interval += 1,
                5 => changed.reward.subsidy_asset = elements::AssetId::from_slice(&[90;32]).unwrap(),
                6 => changed.classification.base_asset_id = [90;32],
                7 => changed.classification.policy_asset_id = [90;32],
                8 => changed.classification.redemption_inventory_script_sha256 = [90;32],
                9 => changed.classification.reserve_script_sha256 = [90;32],
                _ => changed.header_policy_commitment = [90;32],
            }
            assert_ne!(changed.commitment().unwrap(),frozen_policy);
            assert_eq!(changed.require_frozen(frozen_policy,&checkpoint),
                Err(ExecutionPolicyErrorV3::FrozenCommitment));
            if field < 2 {
                assert_eq!(changed.require_frozen(changed.commitment().unwrap(),&checkpoint),
                    Err(ExecutionPolicyErrorV3::Checkpoint));
            }
        }
        let mut invalid_policy = execution_policy;
        invalid_policy.reward.halving_interval = 0;
        assert_eq!(invalid_policy.commitment(),Err(ExecutionPolicyErrorV3::Parameters));
        invalid_policy = execution_policy;
        invalid_policy.reward.genesis_subsidy = u64::MAX;
        assert_eq!(invalid_policy.commitment(),Err(ExecutionPolicyErrorV3::Parameters));
        let header_policy = crate::child_header_policy_v3::ChildHeaderPolicyV3 {
            epoch_length: 10,
            bootstrap: crate::native_child_context_v3::NativeDynafedBootstrap {
                legacy_challenge: authorization.legacy_signblock_challenge.clone(),
                maximum_signature_size: authorization.legacy_signblock_witness_limit,
                fedpeg_script: vec![], start_p2wsh: false, first_extension_space: vec![],
            },
        };
        let frozen_header = execution_policy.header_policy_commitment;
        let custody_policy=crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV3 {
            creation: crate::native_creation_policy_v1::NativeCreationPolicyV1 { explicit_only_height: Some(0) },
            genesis_internal:custody_checkpoint.genesis_internal,
            consensus_configuration_commitment:custody_checkpoint.configuration_commitment,
            deployments,reward:execution_policy.reward,classification:custody_classification,
            header_policy_commitment:header_policy.commitment().unwrap(),
        };
        let custody_policy_hash=custody_policy.commitment().unwrap();
        for height in [None, Some(1)] {
            let mut substituted = custody_policy;
            substituted.creation.explicit_only_height = height;
            assert_ne!(substituted.commitment().unwrap(), custody_policy_hash);
            assert_eq!(substituted.require_frozen(custody_policy_hash, &custody_checkpoint),
                Err(crate::child_execution_policy_v3::ExecutionPolicyErrorV3::FrozenCommitment));
        }
        let linked_custody=|p:&crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
            deposit_parent:[u8;32],deposit_config:[u8;32],expected_config:[u8;32]| {
            use crate::native_child_block_v3::{ChildTransactionCustodyWitnessV3,NativeBlockDepositsV3};
            let entries=[None,None];
            let deposits=NativeBlockDepositsV3 {entries:&entries,frozen_parent_binding:deposit_parent,
                frozen_deposit_configuration:deposit_config,minimum_depth:1,scheduled_policy:None};
            crate::native_child_block_v3::verify_parent_bound_checkpoint_custody_state_v3(
                p,parent_frozen,&TranscriptVerifier::for_input(&parent),&elements::encode::serialize(&linked_block),
                &custody_checkpoint,frozen_custody,&context.previous_headers,&custody_policy,custody_policy_hash,
                100,&header_policy,
                &[ChildTransactionCustodyWitnessV3 {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    custody:ElementsTransactionCustodyWitnessV3 {spends:vec![],creates:vec![]},kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionCustodyWitnessV3 {utxo:uw.clone(),custody:custody_witness.clone(),kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                &checkpoint_verifier,&deposits,expected_config)
        };
        let linked=linked_custody(&parent,parent_frozen,[12;32],[12;32]).unwrap();
        assert_eq!(linked.child().roots(),custody_next);
        assert_eq!(linked.child().next_checkpoint().unwrap().tip_internal,linked_block.block_hash().to_byte_array());
        assert_eq!(linked.parent().m7_critical_hash_internal,critical);
        let join_custody = |checkpoint| crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4::join_executed_parent(
            checkpoint, None, &linked, &parent, parent_frozen, &TranscriptVerifier::for_input(&parent));
        let full_custody = join_custody(linked.child().next_checkpoint().unwrap().clone()).unwrap();
        full_custody.evaluator_anchor_commitment(full_custody.commitment().unwrap()).unwrap();
        let mut substituted = linked.child().next_checkpoint().unwrap().clone();
        substituted.roots.custody_root.custody_supply_atoms += 1;
        assert!(join_custody(substituted).is_err());
        assert!(join_custody(custody_checkpoint.clone()).is_err());
        let mut custody_genesis=custody_checkpoint.genesis_internal;custody_genesis.reverse();
        let expected_custody_burn=extract_custody_burn_v2(&tx,0,custody_genesis,display_asset,custody,[9;20],100).unwrap();
        assert_eq!(linked.child().custody_burn_v2(1,0,custody,[9;20],100).unwrap(),expected_custody_burn);
        assert!(matches!(checked_custody.custody_burn_v2(1,0,custody,[9;20],100),Err(CommittedBurnError::Checkpoint)));
        assert!(linked.child().custody_burn_v2(0,0,custody,[9;20],100).is_err());
        assert!(linked.child().custody_burn_v2(2,0,custody,[9;20],100).is_err());
        assert!(linked.child().custody_burn_v2(1,1,custody,[9;20],100).is_err());
        assert!(linked.child().custody_burn_v2(1,0,[88;32],[9;20],100).is_err());
        assert!(linked.child().custody_burn_v2(1,0,custody,[9;20],101).is_err());
        // No peg-ins in this block: configuration/anchor checks still apply.
        for (anchor,actual,expected) in [(parent_frozen,[12;32],[0;32]),
            (parent_frozen,[13;32],[12;32]),([0;32],[12;32],[12;32])] {
            assert!(linked_custody(&parent,anchor,actual,expected).is_err());
        }
        let mut bad_parent=parent.clone();bad_parent.expected_critical_hash_internal[0]^=1;
        assert!(linked_custody(&bad_parent,parent_frozen,[12;32],[12;32]).is_err());
        let mut bad_parent=parent.clone();bad_parent.terminal_parent_block[0]^=1;
        assert!(linked_custody(&bad_parent,parent_frozen,[12;32],[12;32]).is_err());
        custody_policy.require_frozen(custody_policy_hash,&custody_checkpoint).unwrap();
        let roundtrip:crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV3=
            bincode::deserialize(&bincode::serialize(&custody_policy).unwrap()).unwrap();
        assert_eq!(roundtrip,custody_policy);
        for field in 0..9 {
            let mut changed=custody_policy;
            match field {
                0=>changed.genesis_internal=[90;32],
                1=>changed.consensus_configuration_commitment=[90;32],
                2=>changed.deployments.buried.csv+=1,
                3=>changed.reward.genesis_subsidy+=1,
                4=>changed.reward.halving_interval+=1,
                5=>changed.reward.subsidy_asset=elements::AssetId::from_slice(&[90;32]).unwrap(),
                6=>changed.classification.native_pegged_asset_id=[90;32],
                7=>changed.classification.custody_asset_id=[90;32],
                _=>changed.header_policy_commitment=[90;32],
            }
            assert!(changed.require_frozen(custody_policy_hash,&custody_checkpoint).is_err());
            if matches!(field,0|1|6|7) {
                assert_eq!(changed.require_frozen(changed.commitment().unwrap(),&custody_checkpoint),Err(ExecutionPolicyErrorV3::Checkpoint));
            }
        }
        assert!(custody_policy.require_frozen(frozen_policy,&custody_checkpoint).is_err());
        let mut invalid=custody_policy;invalid.classification.custody_asset_id=invalid.classification.native_pegged_asset_id;
        assert!(invalid.commitment().is_err());
        let custody_context=header_policy.derive_custody_context(custody_policy.header_policy_commitment,
            &custody_checkpoint,&context.previous_headers,deployments,100).unwrap();
        assert_eq!(custody_context,header_policy.derive_context(frozen_header,&checkpoint,
            &context.previous_headers,deployments,100).unwrap());
        assert!(header_policy.derive_custody_context([0;32],&custody_checkpoint,
            &context.previous_headers,deployments,100).is_err());
        assert!(header_policy.derive_custody_context(custody_policy.header_policy_commitment,&custody_checkpoint,
            &context.previous_headers[..6],deployments,100).is_err());
        let header_wire = bincode::serialize(&header_policy).unwrap();
        let decoded_header: crate::child_header_policy_v3::ChildHeaderPolicyV3 =
            bincode::deserialize(&header_wire).unwrap();
        assert_eq!(decoded_header, header_policy);
        assert_eq!(decoded_header.commitment().unwrap(), frozen_header);
        let derived_header = header_policy.derive_context(frozen_header, &checkpoint,
            &context.previous_headers, deployments, authorization.authenticated_adjusted_time).unwrap();
        assert_eq!(derived_header, authorization);
        assert!(header_policy.derive_context([0;32], &checkpoint, &context.previous_headers,
            deployments, authorization.authenticated_adjusted_time).is_err());
        assert!(header_policy.check_context(frozen_header,&checkpoint,&context.previous_headers,
            deployments,&authorization).is_ok());
        for field in 0..7 {
            let mut substituted = authorization.clone();
            match field {
                0 => substituted.legacy_signblock_challenge = Script::from(vec![0x51]),
                1 => substituted.legacy_signblock_witness_limit += 1,
                2 => substituted.next_height += 1,
                3 => substituted.previous_block_hash = BlockHash::all_zeros(),
                4 => substituted.expected_current_dynafed_params = Some(elements::dynafed::Params::Null),
                5 => substituted.previous_11_times[0] ^= 1,
                _ => substituted.previous_11_times.clear(),
            }
            assert!(header_policy.check_context(frozen_header,&checkpoint,&context.previous_headers,
                deployments,&substituted).is_err());
        }
        assert!(header_policy.check_context([0;32],&checkpoint,&context.previous_headers,
            deployments,&authorization).is_err());
        for field in 0..6 {
            let mut changed = crate::child_header_policy_v3::ChildHeaderPolicyV3 {
                epoch_length: header_policy.epoch_length,
                bootstrap: crate::native_child_context_v3::NativeDynafedBootstrap {
                    legacy_challenge: header_policy.bootstrap.legacy_challenge.clone(),
                    maximum_signature_size: header_policy.bootstrap.maximum_signature_size,
                    fedpeg_script: vec![], start_p2wsh: false, first_extension_space: vec![],
                },
            };
            match field {
                0 => changed.epoch_length += 1,
                1 => changed.bootstrap.legacy_challenge = Script::from(vec![0x51]),
                2 => changed.bootstrap.maximum_signature_size += 1,
                3 => changed.bootstrap.fedpeg_script.push(0x51),
                4 => changed.bootstrap.start_p2wsh = true,
                _ => changed.bootstrap.first_extension_space.push(vec![]),
            }
            assert_ne!(changed.commitment().unwrap(),frozen_header);
            assert!(changed.check_context(frozen_header,&checkpoint,&context.previous_headers,
                deployments,&authorization).is_err());
        }
        // Policy selection test only: these synthetic ancestors are not a
        // consensus-qualified always-active DynaFed chain or a live receipt.
        let active_deployments = ChildDeploymentConfigurationV3 {
            dynafed: ElementsVersionbitsV3 {start:-1,..inactive},..deployments
        };
        assert!(header_policy.check_context(frozen_header,&checkpoint,&context.previous_headers,
            active_deployments,&authorization).is_err());
        let derived = crate::native_child_context_v3::select_native_dynafed_parameters(
            &context.previous_headers,10,7,true,&header_policy.bootstrap).unwrap();
        let mut dynafed_context = authorization.clone();
        dynafed_context.expected_current_dynafed_params = Some(derived.expected_current);
        dynafed_context.expected_full_current_dynafed_params = Some(derived.expected_full_current);
        assert!(header_policy.check_context(frozen_header,&checkpoint,&context.previous_headers,
            active_deployments,&dynafed_context).is_ok());
        dynafed_context.expected_current_dynafed_params = Some(elements::dynafed::Params::Null);
        assert!(header_policy.check_context(frozen_header,&checkpoint,&context.previous_headers,
            active_deployments,&dynafed_context).is_err());
        let joined = |raw:&[u8],p:&crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3| {
            verify_parent_bound_checkpoint_child_state(p,parent_frozen,&TranscriptVerifier::for_input(&parent),
                raw,&checkpoint,frozen,&context.previous_headers,&execution_policy,frozen_policy,100,
                &header_policy,&authorization,
                &[ChildTransactionStateWitness {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionStateWitness {utxo:uw.clone(),economic:ew.clone(),kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                &checkpoint_verifier,None,None,None)
        };
        let raw = elements::encode::serialize(&linked_block);
        let joined_state = joined(&raw,&parent).unwrap();
        crate::ecx_deposit_membership_v1::tests::exercise_native_match(&|source, trade, ecx_state, resume, expected_transition| {
            // Reuse authenticated header history and real native script
            // checking, but construct a distinct single-coin ECX checkpoint.
            // Parent receipts remain exact synthetic transcripts.
            let point = trade.input[0].previous_output;
            let old = resume.map(|r| r.coin.clone()).unwrap_or_else(|| ElementsUtxoLeafV2 { outpoint: point,
                output: source.output[point.vout as usize].clone(),
                creation_height: 6, creation_parent_mtp: 13, coinbase: false,
                created_by_issuance: false, created_by_pegin: false });
            assert_eq!(old.outpoint, point);
            assert_eq!(old.output, source.output[point.vout as usize]);
            let confidential::Asset::Explicit(ecx_asset) = old.output.asset else { panic!() };
            let mut class = classification; class.base_asset_id = ecx_asset.into_inner().to_byte_array();
            let mut uempty = canonical_empty_elements_utxo_leaf_v2();
            let mut eempty = canonical_empty_elements_economic_leaf_v2();
            let mut us = Vec::new(); let mut es = Vec::new();
            for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
                us.push(uempty); es.push(eempty);
                uempty = elements_sparse_utxo_parent_v2(uempty,uempty).unwrap();
                eempty = elements_sparse_economic_parent_v2(eempty,eempty).unwrap();
            }
            let up = ElementsSparseUtxoPathV2 { siblings: us };
            let ep = ElementsSparseEconomicPathV2 { siblings: es };
            let economic = |utxo: ElementsUtxoLeafV2| ElementsEconomicLeafV2 {
                amount: utxo.output.value.explicit().unwrap(),
                utxo, asset_id: class.base_asset_id,
                asset_blinding_factor: [0;32], value_blinding_factor: [0;32],
                role: ElementsLiveEconomicRoleV2::OutstandingBase,
            };
            let old_e = economic(old.clone());
            let ui = ElementsSparseUtxoMutationV2 {outpoint:point,old_leaf:None,new_leaf:Some(old.clone()),path:up.clone()};
            let ei = ElementsSparseEconomicMutationV2 {outpoint:point,old_leaf:None,new_leaf:Some(old_e.clone()),path:ep.clone()};
            let mut cp = checkpoint.clone();
            // Real Alpha genesis followed by synthetic history, NOT a replay
            // of the live chain. V5 retains its actual deposit policy gate.
            let mut deposit_policy = crate::native_deposit_policy_v4::tests::policy();
            deposit_policy.historical.pegged_asset_internal = class.base_asset_id;
            cp.genesis_internal = deposit_policy.child_genesis_internal;
            cp.height = 16;
            let mut history = Vec::<crate::native_header_v3::NativeHeader>::new();
            let genesis_bytes = hex::decode(include_str!("test-alpha-genesis.hex").trim()).unwrap();
            let (genesis_header, _) = crate::native_header_v3::NativeHeader::decode_prefix(&genesis_bytes,true).unwrap();
            assert_eq!(genesis_header.hash_internal().unwrap(), cp.genesis_internal);
            history.push(genesis_header);
            for height in 1..=16 {
                let mut h = context.previous_headers[0].clone();
                h.base.height = height; h.base.time = 10 + height;
                h.base.prev_blockhash = BlockHash::from_byte_array(history.last()
                    .map(|p| p.hash_internal().unwrap()).unwrap_or([3;32]));
                history.push(h);
            }
            cp.tip_internal = history.last().unwrap().hash_internal().unwrap();
            cp.history_commitment = child_history_commitment(&history).unwrap();
            cp.roots.utxo_root = apply_elements_sparse_utxo_mutation_v2(uempty,&ui).unwrap();
            cp.roots.economic_root = apply_elements_sparse_economic_mutation_v2(eempty,&ei,class).unwrap();
            if let Some(resume) = resume {
                assert_eq!(resume.checkpoint.state.execution.roots.utxo_root, cp.roots.utxo_root);
                assert_eq!(resume.checkpoint.state.execution.roots.economic_root, cp.roots.economic_root);
                cp = resume.checkpoint.state.execution.clone();
                history = resume.history.iter().map(|bytes|
                    crate::native_header_v3::NativeHeader::decode_prefix(bytes,true).unwrap().0).collect();
                assert_eq!(child_history_commitment(&history).unwrap(), cp.history_commitment);
                assert_eq!(history.last().unwrap().hash_internal().unwrap(), cp.tip_internal);
            }
            let mut child_times: Vec<_> = history.iter().rev().take(11).map(|h| h.base.time).collect();
            child_times.sort_unstable();
            let created = ElementsUtxoLeafV2 {outpoint:OutPoint::new(trade.txid(),0),
                output:trade.output[0].clone(),creation_height:cp.height + 1,
                creation_parent_mtp:child_times[child_times.len()/2],coinbase:false,created_by_issuance:false,created_by_pegin:false};
            let new_point = created.outpoint;
            let mut tw = ChildTransactionStateWitness {
                utxo:ElementsTransactionUtxoWitnessV2 {
                    spends:vec![ElementsSparseUtxoMutationV2 {outpoint:point,old_leaf:Some(old),new_leaf:None,path:up.clone()}],
                    creates:vec![ElementsSparseUtxoMutationV2 {outpoint:new_point,old_leaf:None,new_leaf:Some(created.clone()),path:up}],
                },
                economic:ElementsTransactionEconomicWitnessV2 {
                    spends:vec![ElementsSparseEconomicMutationV2 {outpoint:point,old_leaf:Some(old_e),new_leaf:None,path:ep.clone()}],
                    creates:vec![ElementsSparseEconomicMutationV2 {outpoint:new_point,old_leaf:None,new_leaf:Some(economic(created.clone())),path:ep}],
                },kernel:ElementsTransactionKernelWitnessV2::Ordinary,
            };
            assert!((1..=2).contains(&trade.output.len()));
            if trade.output.len() == 2 {
                let mut recipient = created.clone();
                recipient.outpoint.vout = 1;
                recipient.output = trade.output[1].clone();
                // The second insertion opens the tree AFTER the vault was
                // inserted, not another empty tree. Economic amounts derive
                // from each output rather than the spent coin's amount.
                let a = elements_sparse_utxo_key_v2(created.outpoint);
                let b = elements_sparse_utxo_key_v2(recipient.outpoint);
                let bit = |key: [u8;32], level: usize| (key[(255-level)/8] >> (level%8)) & 1;
                let split = (0..256).rev().find(|&i| bit(a,i) != bit(b,i)).unwrap();
                let mut up = tw.utxo.creates[0].path.clone();
                let mut ep = tw.economic.creates[0].path.clone();
                let mut un = elements_utxo_leaf_node_v2(&created);
                let mut en = verify_elements_economic_leaf_v2(&economic(created),class).unwrap();
                for level in 0..split {
                    un = if bit(a,level) == 0 { elements_sparse_utxo_parent_v2(un,up.siblings[level]) }
                        else { elements_sparse_utxo_parent_v2(up.siblings[level],un) }.unwrap();
                    en = if bit(a,level) == 0 { elements_sparse_economic_parent_v2(en,ep.siblings[level]) }
                        else { elements_sparse_economic_parent_v2(ep.siblings[level],en) }.unwrap();
                }
                up.siblings[split] = un;
                ep.siblings[split] = en;
                tw.utxo.creates.push(ElementsSparseUtxoMutationV2 { outpoint:recipient.outpoint,
                    old_leaf:None,new_leaf:Some(recipient.clone()),path:up });
                tw.economic.creates.push(ElementsSparseEconomicMutationV2 { outpoint:recipient.outpoint,
                    old_leaf:None,new_leaf:Some(economic(recipient)),path:ep });
            }
            let mut policy = execution_policy; policy.classification = class;
            policy.genesis_internal = cp.genesis_internal;
            policy.reward.subsidy_asset = ecx_asset;
            let mut candidate = linked_block.clone(); candidate.txdata[1] = trade.clone();
            candidate.header.height = cp.height + 1;
            candidate.header.time = history.last().unwrap().base.time + 1;
            candidate.header.prev_blockhash = BlockHash::from_byte_array(cp.tip_internal);
            candidate.txdata[0].input[0].script_sig = Script::from(vec![1,(cp.height + 1).try_into().unwrap(),0]);
            candidate.txdata[0].output[0].asset = confidential::Asset::Explicit(ecx_asset);
            let seed = parent_for_child_checkpoint(&cp,[1;32]);
            let mut marker = vec![0x6a,37]; marker.extend_from_slice(b"ELMTP");
            marker.extend_from_slice(&seed.expected_parent_hash_internal);
            candidate.txdata[0].output[0].script_pubkey = Script::from(marker);
            candidate.header.merkle_root = elements_transaction_merkle_root_v2(&candidate.txdata).unwrap();
            sign(&mut candidate);
            let critical = critical_hash_internal(cp.genesis_internal,24,
                candidate.block_hash().to_byte_array(),&empty,&empty).unwrap();
            let p = parent_for_child_checkpoint(&cp,critical);
            let native_candidate = crate::native_header_v3::NativeHeader::from_standard(candidate.header.clone());
            let ecx_input_verifier = FullElementsInputVerifierV2::with_rules(
                BlockHash::from_byte_array(cp.genesis_internal),
                policy.deployments.checked_candidate_rules(policy.deployments.commitment().unwrap(),
                    &cp,cp.commitment().unwrap(),&history,&native_candidate).unwrap().base_input_rules());
            let generic = verify_parent_bound_checkpoint_child_state(&p,p.binding.commitment().unwrap(),
                &TranscriptVerifier::for_input(&p),&elements::encode::serialize(&candidate),
                &cp,cp.commitment().unwrap(),&history,&policy,policy.commitment().unwrap(),
                100,&header_policy,&header_policy.derive_context(policy.header_policy_commitment,
                    &cp,&history,policy.deployments,100).unwrap(),
                &[ChildTransactionStateWitness {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},
                    kernel:ElementsTransactionKernelWitnessV2::Coinbase},tw.clone()],
                &ecx_input_verifier,None,None,None).unwrap();
            // Execute the same real ECX vault spend through the context-aware
            // dispatch, not a fabricated checked-state wrapper. No Simplicity
            // receipt is needed for this synthetic OP_TRUE source script.
            struct DenyReceipt;
            impl ElementsSimplicityReceiptVerifierV2 for DenyReceipt {
                fn verify(&self, _: [u8;32], _: &[u8], _: &[u8]) -> Result<(), ElementsStateErrorV2> {
                    Err(ElementsStateErrorV2::AuthorizationConsensus)
                }
            }
            use crate::native_header_v3::{NativeHeader, EXCHANGE, FORCED, DEPOSIT, CURSORS};
            let prior_header = history.last_mut().unwrap();
            if resume.is_none() {
                prior_header.base.version |= EXCHANGE | FORCED | DEPOSIT | CURSORS;
                prior_header.exchange = ecx_state.digest().unwrap();
                prior_header.forced = [34;32]; prior_header.deposit = [35;32];
            } else {
                assert_eq!(prior_header.exchange, ecx_state.digest().unwrap());
            }
            cp.tip_internal = prior_header.hash_internal().unwrap();
            cp.history_commitment = child_history_commitment(&history).unwrap();
            let extended = crate::child_execution_state_v4::ChildExecutionCheckpointV4 {
                execution: cp.clone(), capital: None,
            };
            let frozen_extended = extended.commitment().unwrap();
            let prior_header = history.last().unwrap();
            let seed = parent_for_child_checkpoint(&cp, [1;32]);
            let mut marker = vec![0x6a,37]; marker.extend_from_slice(b"ELMTP");
            marker.extend_from_slice(&seed.expected_parent_hash_internal);
            candidate.txdata[0].output[0].script_pubkey = Script::from(marker);
            let mut header = NativeHeader::from_standard(candidate.header.clone());
            header.base.prev_blockhash = elements::BlockHash::from_byte_array(cp.tip_internal);
            header.base.merkle_root = elements_transaction_merkle_root_v2(&candidate.txdata).unwrap();
            // Derive the expected single-match result before constructing the
            // inclusion commitment. Its clock uses predecessor P, not Q or the
            // candidate hash, so there is no own-block commitment cycle.
            let mut final_ecx_state = ecx_state.clone();
            final_ecx_state.sidechain_height = u64::from(cp.height) + 1;
            final_ecx_state.parent_hash = seed.expected_parent_hash_internal;
            final_ecx_state.parent_height = u64::from(seed.terminal_parent_predecessor.tip.height);
            final_ecx_state.parent_mtp = u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                &seed.terminal_parent_predecessor.pow_context.previous_11_times).unwrap());
            if let Some(transition) = expected_transition {
                // Supply predecessor P's clock before the relation executes.
                // Never repair a returned result after verification.
                let next = transition(&final_ecx_state);
                assert_eq!(next.sidechain_height, final_ecx_state.sidechain_height);
                assert_eq!(next.parent_hash, final_ecx_state.parent_hash);
                assert_eq!(next.parent_height, final_ecx_state.parent_height);
                assert_eq!(next.parent_mtp, final_ecx_state.parent_mtp);
                final_ecx_state = next;
            } else {
                final_ecx_state.matcher_sequence = ecx_state.matcher_sequence + 1;
            }
            header.base.version |= EXCHANGE | FORCED | DEPOSIT | CURSORS;
            header.exchange = final_ecx_state.digest().unwrap();
            header.forced = prior_header.forced;
            header.deposit = prior_header.deposit;
            let signature = secp.sign_ecdsa(&Message::from_digest(header.hash_internal().unwrap()), &secret).serialize_der();
            let mut solution = vec![signature.len() as u8]; solution.extend_from_slice(&signature);
            header.base.ext = BlockExtData::Proof { challenge: challenge.clone(), solution: Script::from(solution) };
            let mut candidate_raw = header.encode(false,true).unwrap();
            candidate_raw.extend(elements::encode::serialize(&candidate.txdata));
            let critical = critical_hash_internal(cp.genesis_internal,24,
                header.hash_internal().unwrap(),&empty,&empty).unwrap();
            let p = parent_for_child_checkpoint(&cp, critical);
            let mut environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::default();
            environment.bind_checkpoint_projection(&extended, frozen_extended, prior_header).unwrap();
            environment.current_bmm_parent = Some(crate::ecx_environment_v4::Parent {
                block_hash_wire: p.expected_parent_hash_internal,
                height: u64::from(p.terminal_parent_predecessor.tip.height),
                median_time_past: u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                    &p.terminal_parent_predecessor.pow_context.previous_11_times).unwrap()),
            });
            let dispatch = |env: &crate::ecx_environment_v4::EcxExecutionEnvironmentV1| {
                crate::native_child_block_v3::execute_parent_bound_child_with_ecx_v4(
                    &p, p.binding.commitment().unwrap(), &TranscriptVerifier::for_inputs([&p,&p]),
                    &candidate_raw, &extended, frozen_extended,
                    &history, prior_header, &policy, policy.commitment().unwrap(),
                    100, &header_policy,
                    &[ChildTransactionStateWitness {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                        economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},
                        kernel:ElementsTransactionKernelWitnessV2::Coinbase}, tw.clone()],
                    env, env.commitment().unwrap(), [14;32], [1;32], &[], &DenyReceipt, None, None)
            };
            let dispatched = dispatch(&environment).unwrap();
            assert_eq!(dispatched.child().roots(), generic.child().roots());
            assert_eq!(dispatched.ecx_checkpoint, Some(frozen_extended));
            assert_eq!(dispatched.ecx_context().unwrap().ecx_environment, environment.commitment().unwrap());
            let mut wrong = environment.clone();
            wrong.current_bmm_parent.as_mut().unwrap().median_time_past += 1;
            assert!(dispatch(&wrong).is_err());
            let checked_context = crate::ecx_environment_v4::CheckedAlphaExecutionContextV4::authenticate(
                &environment, environment.commitment().unwrap(), [14;32], &extended, frozen_extended,
                prior_header, &p, p.binding.commitment().unwrap(), &TranscriptVerifier::for_input(&p)).unwrap();
            let continuity = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1 {
                execution: cp.clone(), exchange_state_root: ecx_state.digest().unwrap(),
                bindings_hash: ecx_state.bindings_hash, vault_outpoint: point,
            };
            let v5_checkpoint = crate::child_execution_state_v4::ChildExecutionCheckpointV5 {
                state: extended.clone(), bmm_endpoint: resume.map(|r| r.checkpoint.bmm_endpoint.clone())
                    .unwrap_or_else(|| Some(vec![1;80])),
            };
            let binding = crate::child_execution_statement_v4::AlphaChildExecutionBindingV5 {
                execution: crate::child_execution_guest_v3::AlphaChildExecutionBindingV3 {
                    parent_binding: p.binding.commitment().unwrap(),
                    predecessor_checkpoint: v5_checkpoint.commitment().unwrap(),
                    execution_policy: policy.commitment().unwrap(),
                    simplicity_evaluator_program_id: [1;32],
                    deposit_configuration: deposit_policy.commitment().unwrap(),
                }, evaluator_source_closure: [14;32], environment: environment.commitment().unwrap(),
                genesis_bindings: [15;32], successor: None,
            };
            let execution = crate::child_execution_guest_v3::AlphaChildExecutionInputV3 {
                version: crate::child_execution_guest_v3::ALPHA_CHILD_EXECUTION_VERSION_V3,
                binding: binding.execution, parent: p, checkpoint: cp,
                history: history.iter().map(|h| h.encode(false,true).unwrap()).collect(),
                policy, header_policy: header_policy.clone(),
                deposit_configuration: deposit_policy.historical.clone(), observation_time: 100,
                raw_block: candidate_raw,
                witnesses: vec![ChildTransactionStateWitness {
                    utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},
                    kernel:ElementsTransactionKernelWitnessV2::Coinbase}, tw],
                deposits: vec![None,None], simplicity_receipts: vec![],
            };
            (dispatched, checked_context, continuity,
                crate::ecx_deposit_membership_v1::tests::NativeMatchInput {
                    execution, binding, checkpoint: v5_checkpoint, deposit_policy, environment,
                })
        });
        // Concrete dispatch plumbing test. This fixture spends an ECDSA output,
        // not Simplicity: no receipt may be consumed or silently ignored.
        struct RejectSimplicityReceipt;
        impl ElementsSimplicityReceiptVerifierV2 for RejectSimplicityReceipt {
            fn verify(&self, _: [u8;32], _: &[u8], _: &[u8]) -> Result<(), ElementsStateErrorV2> {
                Err(ElementsStateErrorV2::AuthorizationConsensus)
            }
        }
        let custody_execution_checkpoint = crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4 {
            execution: custody_checkpoint.clone(), capital: None, bmm_endpoint: Some(vec![1;80]),
        };
        let custody_execution_hash = custody_execution_checkpoint.commitment().unwrap();
        let prior_header = context.previous_headers.last().unwrap();
        let mut custody_environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::default();
        custody_environment.bind_custody_checkpoint_projection(
            &custody_execution_checkpoint,custody_execution_hash,prior_header).unwrap();
        custody_environment.current_bmm_parent = Some(crate::ecx_environment_v4::Parent {
            block_hash_wire: parent.expected_parent_hash_internal,
            height: u64::from(parent.terminal_parent_predecessor.tip.height),
            median_time_past: u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                &parent.terminal_parent_predecessor.pow_context.previous_11_times).unwrap()),
        });
        let custody_dispatch_checkpoint = |custody_execution_checkpoint: &crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
            env: &crate::ecx_environment_v4::EcxExecutionEnvironmentV1,
            closure, id, receipts: &[ElementsSimplicityReceiptBindingV2]| {
            let custody_execution_hash = custody_execution_checkpoint.commitment().unwrap();
            use crate::native_child_block_v3::{ChildTransactionCustodyWitnessV3,NativeBlockDepositsV3};
            let entries=[None,None];
            let deposits=NativeBlockDepositsV3 {entries:&entries,frozen_parent_binding:parent_frozen,
                frozen_deposit_configuration:[12;32],minimum_depth:1,scheduled_policy:None};
            crate::native_child_block_v3::execute_parent_bound_custody_with_ecx_v4(
                &parent,parent_frozen,&TranscriptVerifier::for_inputs([&parent,&parent]),&raw,
                &custody_execution_checkpoint,custody_execution_hash,&context.previous_headers,prior_header,
                &custody_policy,custody_policy_hash,100,&header_policy,
                &[ChildTransactionCustodyWitnessV3 {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    custody:ElementsTransactionCustodyWitnessV3 {spends:vec![],creates:vec![]},kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionCustodyWitnessV3 {utxo:uw.clone(),custody:custody_witness.clone(),kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                env,env.commitment().unwrap(),closure,id,receipts,&RejectSimplicityReceipt,&deposits,[12;32])
        };
        let custody_dispatch = |env: &crate::ecx_environment_v4::EcxExecutionEnvironmentV1,
            closure, id, receipts: &[ElementsSimplicityReceiptBindingV2]| {
            custody_dispatch_checkpoint(&custody_execution_checkpoint,env,closure,id,receipts)
        };
        // Diagnostic regression: these must become rejections when full anchor
        // continuity is enforced. This is not a valid production checkpoint.
        // No evaluator receipt is present to supply a per-input anchor check.
        let (_, current_endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
            &parent,parent_frozen,&TranscriptVerifier::for_input(&parent)).unwrap();
        let (anchor_statement, full_anchor) = crate::native_bmm_anchor_v1::NativeBmmAnchorV1::authenticate(
            &parent,parent_frozen,&TranscriptVerifier::for_input(&parent)).unwrap();
        assert_eq!(&anchor_statement,joined_state.parent());
        assert_eq!(crate::native_bmm_anchor_v1::NativeBmmAnchorV1::from_canonical_bytes(
            &full_anchor.canonical_bytes()),Some(full_anchor.clone()));
        assert!(!full_anchor.follows_ordering(&full_anchor));
        assert!(crate::native_bmm_anchor_v1::NativeBmmAnchorV1::authenticate(
            &parent,[0;32],&TranscriptVerifier::for_input(&parent)).is_err());
        for backwards in [false,true] {
            let mut cp = custody_execution_checkpoint.clone();
            let mut endpoint = current_endpoint.to_vec();
            if backwards {
                let height = u64::from_be_bytes(endpoint[32..40].try_into().unwrap());
                endpoint[32..40].copy_from_slice(&height.checked_add(1).unwrap().to_be_bytes());
            }
            cp.bmm_endpoint = Some(endpoint);
            let mut env = custody_environment.clone();
            env.bind_custody_checkpoint_projection(&cp,cp.commitment().unwrap(),prior_header).unwrap();
            assert!(custody_dispatch_checkpoint(&cp,&env,[14;32],[1;32],&[]).is_ok(),
                "diagnostic changed: recheck anchor enforcement before updating this assertion");
        }
        let (custody_dispatched, custody_checked_context)=custody_dispatch(&custody_environment,[14;32],[1;32],&[]).unwrap();
        assert_eq!(custody_dispatched.child().roots(),custody_next);
        assert_eq!(custody_dispatched.ecx_checkpoint,Some(custody_execution_hash));
        assert_eq!(custody_dispatched.ecx_context,Some(custody_checked_context.context()));
        assert!(custody_dispatch(&custody_environment,[0;32],[1;32],&[]).is_err());
        assert!(custody_dispatch(&custody_environment,[14;32],[255;32],&[]).is_err());
        assert!(custody_dispatch(&custody_environment,[14;32],[1;32],&[
            ElementsSimplicityReceiptBindingV2 {public_values:vec![0;33],proof_marker:vec![1]}]).is_err());
        let mut wrong_environment=custody_environment.clone();
        wrong_environment.current_bmm_parent.as_mut().unwrap().median_time_past+=1;
        assert!(custody_dispatch(&wrong_environment,[14;32],[1;32],&[]).is_err());
        let receipt_dispatch = |id, receipts: &[ElementsSimplicityReceiptBindingV2]| {
            crate::native_child_block_v3::execute_parent_bound_child_with_simplicity_v3(
                &parent,parent_frozen,&TranscriptVerifier::for_input(&parent),&raw,
                &checkpoint,frozen,&context.previous_headers,&execution_policy,frozen_policy,100,
                &header_policy,
                &[ChildTransactionStateWitness {utxo:ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    economic:ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},kernel:ElementsTransactionKernelWitnessV2::Coinbase},
                  ChildTransactionStateWitness {utxo:uw.clone(),economic:ew.clone(),kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                id,receipts,&RejectSimplicityReceipt,None,None)
        };
        let dispatched = receipt_dispatch([1;32], &[]).unwrap();
        assert_eq!(dispatched.child().next_checkpoint(), joined_state.child().next_checkpoint());
        assert!(receipt_dispatch([0;32], &[]).is_err());
        assert!(receipt_dispatch([255;32], &[]).is_err());
        assert!(receipt_dispatch([1;32], &[ElementsSimplicityReceiptBindingV2 {
            public_values:vec![0;33],proof_marker:vec![1] }]).is_err());
        // Exercise the owned guest relation with the same signed native block.
        // TranscriptVerifier is test-only: this is not a live/SP1 receipt.
        use crate::child_execution_guest_v3::{
            AlphaChildExecutionInputV3, AlphaChildExecutionBindingV3,
            AlphaDepositConfigurationV3, ALPHA_CHILD_EXECUTION_VERSION_V3,
            encode_alpha_child_execution_input_v3, decode_alpha_child_execution_input_v3,
            execute_alpha_child_execution_v3,
        };
        let params = elements::AddressParams::ELEMENTS;
        let deposit_configuration = AlphaDepositConfigurationV3 {
            pegged_asset_internal: classification.base_asset_id, minimum_depth: 1,
            p2pkh_prefix: params.p2pkh_prefix, p2sh_prefix: params.p2sh_prefix,
            blinded_prefix: params.blinded_prefix, bech_hrp: params.bech_hrp.to_string(),
            blech_hrp: params.blech_hrp.to_string(),
        };
        let guest_input = AlphaChildExecutionInputV3 {
            version: ALPHA_CHILD_EXECUTION_VERSION_V3,
            binding: AlphaChildExecutionBindingV3 {
                parent_binding: parent_frozen, predecessor_checkpoint: frozen,
                execution_policy: frozen_policy, simplicity_evaluator_program_id: [1;32],
                deposit_configuration: deposit_configuration.commitment().unwrap(),
            },
            parent: parent.clone(), checkpoint: checkpoint.clone(),
            history: context.previous_headers.iter().map(|h|h.encode(false,true).unwrap()).collect(),
            policy: execution_policy, header_policy: header_policy.clone(), deposit_configuration,
            observation_time: 100, raw_block: raw.clone(),
            witnesses: vec![
                ChildTransactionStateWitness {
                    utxo: ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    economic: ElementsTransactionEconomicWitnessV2 {spends:vec![],creates:vec![]},
                    kernel: ElementsTransactionKernelWitnessV2::Coinbase,
                },
                ChildTransactionStateWitness {utxo:uw.clone(),economic:ew.clone(),
                    kernel:ElementsTransactionKernelWitnessV2::Ordinary},
            ],
            deposits: vec![None,None], simplicity_receipts:vec![],
        };
        let run_guest = |input:&AlphaChildExecutionInputV3| execute_alpha_child_execution_v3(
            input,&TranscriptVerifier::for_input(&parent),&RejectSimplicityReceipt);
        let wire_fixture = crate::child_execution_guest_v4::check_owned_wire_fixture(&guest_input);
        // Native custody execution alone does not establish capital. Neither
        // carry mode may bootstrap a missing authenticated capital projection.
        // This fixture's parent receipts are transcript-only, not SP1 proofs.
        let successor_identity = crate::child_execution_statement_v4::SuccessorIdentityV4 {
            configuration_hash: [21;32], program_id: [22;32], transition_cmr: [23;32],
        };
        for successor in [None, Some(&successor_identity)] {
            assert!(matches!(custody_checked_context.carry_projection(
                &custody_dispatched, &wire_fixture.configuration,
                &wire_fixture.genesis_bindings, wire_fixture.genesis_bindings.commitment(),
                successor, &[]), Err(crate::capital_genesis_utxos_v4::GenesisCoinError::Context)));
        }
        // Carry fixtures authenticate an extended header and full predecessor;
        // no checked-result fields are fabricated. Parent receipts remain
        // transcript-only test evidence, not live chain qualification.
        for (successor_mode, changed_root) in [(false,false),(true,false),(false,true),(true,true)] {
            use crate::native_header_v3::{NativeHeader, EXCHANGE, FORCED, DEPOSIT, CURSORS};
            use crate::ecx_environment_v4::{BondIdentity, IncrementalIdentity};
            use crate::native_child_block_v3::{ChildTransactionCustodyWitnessV3, NativeBlockDepositsV3};
            let configuration = &wire_fixture.configuration;
            let mut bindings = wire_fixture.genesis_bindings.clone();
            bindings.child_genesis = custody_checkpoint.genesis_internal;
            bindings.activation_height = 1;
            let capital = crate::child_execution_state_v4::CapitalProjectionV4 {
                proof_profile: u8::from(successor_mode), exchange_state_root: [31;32],
                configuration_hash: if successor_mode { successor_identity.configuration_hash } else { configuration.digest() },
                asset_id: configuration.bond_asset_id,
                deployment_commitment: configuration.bond_deployment_commitment,
                transition_program_id: if successor_mode { successor_identity.program_id } else { bindings.transition_program_id },
                transition_cmr: if successor_mode { successor_identity.transition_cmr } else { bindings.transition_cmr },
                covenant_state_hash: [32;32], covenant_inbox_root: [33;32],
                covenant_inbox_count: 0, node_inbox_root: [33;32], node_inbox_count: 0,
            };
            let mut history = context.previous_headers.clone();
            let prior = history.last_mut().unwrap();
            prior.base.version |= EXCHANGE | FORCED | DEPOSIT | CURSORS;
            prior.exchange = capital.exchange_state_root;
            prior.forced = [34;32]; prior.deposit = [35;32];
            let mut cp = custody_execution_checkpoint.clone();
            cp.capital = Some(capital.clone());
            cp.execution.tip_internal = prior.hash_internal().unwrap();
            cp.execution.history_commitment = child_history_commitment(&history).unwrap();
            let cp_hash = cp.commitment().unwrap();
            // Legacy fixture helper reads only chain identity, height and tip;
            // custody execution below always consumes the actual custody cp.
            let mut parent_identity = checkpoint.clone();
            parent_identity.tip_internal = cp.execution.tip_internal;
            let seed = parent_for_child_checkpoint(&parent_identity, [1;32]);
            let mut txs = linked_block.txdata.clone();
            let mut marker = vec![0x6a,37]; marker.extend_from_slice(b"ELMTP");
            marker.extend_from_slice(&seed.expected_parent_hash_internal);
            txs[0].output[0].script_pubkey = Script::from(marker);
            let mut header = NativeHeader::from_standard(linked_block.header.clone());
            header.base.prev_blockhash = elements::BlockHash::from_byte_array(cp.execution.tip_internal);
            header.base.merkle_root = elements_transaction_merkle_root_v2(&txs).unwrap();
            header.base.version |= EXCHANGE | FORCED | DEPOSIT | CURSORS;
            header.exchange = capital.exchange_state_root;
            if changed_root { header.exchange[0] ^= 1; }
            header.forced = [34;32]; header.deposit = [35;32];
            let signature = secp.sign_ecdsa(&Message::from_digest(header.hash_internal().unwrap()), &secret).serialize_der();
            let mut solution = vec![signature.len() as u8]; solution.extend_from_slice(&signature);
            header.base.ext = BlockExtData::Proof { challenge: challenge.clone(), solution: Script::from(solution) };
            let mut carry_raw = header.encode(false,true).unwrap();
            carry_raw.extend(elements::encode::serialize(&txs));
            let critical = critical_hash_internal(cp.execution.genesis_internal,24,
                header.hash_internal().unwrap(),&empty,&empty).unwrap();
            let carry_parent = parent_for_child_checkpoint(&parent_identity,critical);
            let carry_parent_hash = carry_parent.binding.commitment().unwrap();
            let mut env = custody_environment.clone();
            env.bond_identity = Some(BondIdentity {
                configuration_hash: configuration.digest(), asset_id: configuration.bond_asset_id,
                deployment_commitment: configuration.bond_deployment_commitment,
                transition_cmr: bindings.transition_cmr,
                collateral_vault_script_sha256: [36;32], collateral_vault_cmr: [37;32],
                insurance_reserve_script_sha256: [38;32], insurance_reserve_cmr: [39;32],
            });
            env.incremental_identity = Some(IncrementalIdentity {
                activation_cmr: bindings.activation_cmr, successor_transition_cmr: successor_identity.transition_cmr,
            });
            env.bind_custody_checkpoint_projection(&cp,cp_hash,history.last().unwrap()).unwrap();
            let entries = [None,None];
            let deposits = NativeBlockDepositsV3 { entries: &entries,
                frozen_parent_binding: carry_parent_hash, frozen_deposit_configuration: [12;32],
                minimum_depth: 1, scheduled_policy: None };
            let (executed, checked) = crate::native_child_block_v3::execute_parent_bound_custody_with_ecx_v4(
                &carry_parent,carry_parent_hash,&TranscriptVerifier::for_inputs([&carry_parent,&carry_parent]),
                &carry_raw,&cp,cp_hash,&history,history.last().unwrap(),&custody_policy,custody_policy_hash,
                100,&header_policy,
                &[ChildTransactionCustodyWitnessV3 { utxo: ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                    custody: ElementsTransactionCustodyWitnessV3 {spends:vec![],creates:vec![]}, kernel: ElementsTransactionKernelWitnessV2::Coinbase },
                  ChildTransactionCustodyWitnessV3 { utxo: uw.clone(), custody: custody_witness.clone(), kernel: ElementsTransactionKernelWitnessV2::Ordinary }],
                &env,env.commitment().unwrap(),[14;32],[1;32],&[],&RejectSimplicityReceipt,&deposits,[12;32]).unwrap();
            let identity = successor_mode.then_some(&successor_identity);
            {
                use crate::child_custody_guest_v4::*;
                use crate::child_execution_guest_v4::OwnedCapitalWitnessV4;
                use crate::child_execution_guest_v3::{AlphaChildExecutionBindingV3, AlphaChildExecutionErrorV3};
                let deposit_policy = crate::native_deposit_policy_v4::tests::policy();
                let initialization = crate::genesis_initialization_v2::GenesisInitializationV2 {
                    version: 2, child_genesis: cp.execution.genesis_internal,
                    height: 1, block_internal: [45;32], parent_mtp: 1,
                };
                let owned = CustodyExecutionInputV4 {
                    version: CUSTODY_EXECUTION_VERSION_V4,
                    binding: CustodyExecutionBindingV4 { roots: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5 {
                        execution: AlphaChildExecutionBindingV3 {
                            parent_binding: carry_parent_hash, predecessor_checkpoint: cp_hash,
                            execution_policy: custody_policy_hash, simplicity_evaluator_program_id: [1;32],
                            deposit_configuration: deposit_policy.commitment().unwrap(),
                        }, evaluator_source_closure: [14;32], environment: env.commitment().unwrap(),
                        genesis_bindings: bindings.commitment(), successor: identity.copied(),
                    }, genesis_initialization: initialization.commitment().unwrap() },
                    genesis_initialization: initialization,
                    parent: carry_parent.clone(), checkpoint: cp.clone(),
                    history: history.iter().map(|h| h.encode(false,true).unwrap()).collect(),
                    policy: custody_policy, header_policy: header_policy.clone(), deposit_policy,
                    observation_time: 100, raw_block: carry_raw.clone(),
                    witnesses: vec![ChildTransactionCustodyWitnessV3 {
                        utxo: ElementsTransactionUtxoWitnessV2 {spends:vec![],creates:vec![]},
                        custody: ElementsTransactionCustodyWitnessV3 {spends:vec![],creates:vec![]},
                        kernel: ElementsTransactionKernelWitnessV2::Coinbase },
                        ChildTransactionCustodyWitnessV3 {utxo:uw.clone(),custody:custody_witness.clone(),
                            kernel:ElementsTransactionKernelWitnessV2::Ordinary}],
                    deposits: vec![None,None], simplicity_receipts:vec![], environment:env.encode().unwrap(),
                    configuration:configuration.clone(), genesis_bindings:bindings.clone(),
                    capital:if successor_mode {OwnedCapitalWitnessV4::SuccessorCarry} else {OwnedCapitalWitnessV4::FiniteCarry},
                    registry:vec![],
                };
                let bytes = encode_custody_execution_input_v4(&owned).unwrap();
                assert_eq!(decode_custody_execution_input_v4(&bytes).unwrap(),owned);
                let mut trailing=bytes.clone(); trailing.push(0);
                assert!(decode_custody_execution_input_v4(&trailing).is_err());
                assert!(decode_custody_execution_input_v4(&bytes[..bytes.len()-1]).is_err());
                let mut legacy=bytes; legacy[0]=crate::child_execution_statement_v4::ALPHA_CHILD_EXECUTION_VERSION_V5;
                assert!(decode_custody_execution_input_v4(&legacy).is_err());
                assert_ne!(owned.binding.commitment().unwrap(),owned.binding.roots.commitment().unwrap());
                // This fixture's synthetic genesis cannot be used as live Alpha.
                assert_ne!(owned.checkpoint.execution.genesis_internal,owned.deposit_policy.child_genesis_internal);
                assert!(matches!(execute_owned_custody_v4(&owned,
                    &TranscriptVerifier::for_input(&carry_parent),&RejectSimplicityReceipt),
                    Err(crate::child_execution_guest_v4::AlphaChildExecutionErrorV4::Execution(AlphaChildExecutionErrorV3::Binding))));
                if !changed_root {
                    // Actual Alpha genesis, LOCAL history and transcript parents:
                    // positive guest integration, never a live replay claim.
                    let mut alpha = owned.clone();
                    let mut ah = crate::child_custody_guest_v4::tests::alpha_test_history(6);
                    let prior = ah.last_mut().unwrap();
                    prior.base.version |= EXCHANGE | FORCED | DEPOSIT | CURSORS;
                    prior.exchange = capital.exchange_state_root;
                    prior.forced = [34;32]; prior.deposit = [35;32];
                    alpha.checkpoint.execution.genesis_internal = alpha.deposit_policy.child_genesis_internal;
                    alpha.checkpoint.execution.tip_internal = prior.hash_internal().unwrap();
                    alpha.checkpoint.execution.history_commitment = child_history_commitment(&ah).unwrap();
                    alpha.checkpoint.execution.classification.native_pegged_asset_id = alpha.deposit_policy.historical.pegged_asset_internal;
                    alpha.checkpoint.execution.roots.custody_root = apply_elements_custody_mutation_v3(
                        custody_empty,&custody_insert,alpha.checkpoint.execution.classification).unwrap();
                    alpha.policy.genesis_internal = alpha.checkpoint.execution.genesis_internal;
                    alpha.policy.classification = alpha.checkpoint.execution.classification;
                    alpha.header_policy.bootstrap.legacy_challenge = Script::from(vec![0x51]);
                    alpha.policy.header_policy_commitment = alpha.header_policy.commitment().unwrap();
                    alpha.policy.reward.subsidy_asset = elements::AssetId::from_slice(
                        &alpha.deposit_policy.historical.pegged_asset_internal).unwrap();
                    let effective = crate::effective_child_configuration_v1::EffectiveChildConfigurationV1::from_policies(
                        &alpha.policy, &alpha.header_policy, &alpha.deposit_policy).unwrap().commitment();
                    alpha.policy.consensus_configuration_commitment = effective;
                    alpha.checkpoint.execution.configuration_commitment = effective;
                    alpha.genesis_bindings.child_genesis = alpha.checkpoint.execution.genesis_internal;
                    let mut pi = checkpoint.clone();
                    pi.genesis_internal = alpha.checkpoint.execution.genesis_internal;
                    pi.configuration_commitment = alpha.checkpoint.execution.configuration_commitment;
                    pi.tip_internal = alpha.checkpoint.execution.tip_internal;
                    let seed = parent_for_child_checkpoint(&pi,[1;32]);
                    let mut atxs = txs.clone();
                    let mut alpha_domain = redemption_domain.clone();
                    alpha_domain.elements_genesis_display = pi.genesis_internal;
                    alpha_domain.elements_genesis_display.reverse();
                    if let Ok(json) = std::env::var("USDD_TEST_REDEMPTION_DOMAIN") {
                        let deployed: RedemptionDomainV2 = serde_json::from_str(&json).unwrap();
                        assert_eq!(deployed.elements_genesis_display,alpha_domain.elements_genesis_display,
                            "deployment must use the native fixture genesis");
                        assert_eq!(deployed.usdd_asset_display,alpha_domain.usdd_asset_display,
                            "deployment must use the native fixture asset");
                        assert!(deployed.require_frozen_custody(fixture_verifier_address(),deployed.custody_id));
                        alpha_domain = deployed;
                    }
                    alpha_domain.custody_id = alpha_domain.derive_custody_id(fixture_verifier_address());
                    let mut burn_script = atxs[1].output[0].script_pubkey.as_bytes().to_vec();
                    burn_script[7..39].copy_from_slice(&alpha_domain.custody_id);
                    atxs[1].output[0].script_pubkey = Script::from(burn_script);
                    let digest = elements::sighash::SighashCache::new(&atxs[1])
                        .legacy_sighash(0,&uw.spends[0].old_leaf.as_ref().unwrap().output.script_pubkey,elements::EcdsaSighashType::All).to_byte_array();
                    let mut sig = spend_secp.sign_ecdsa(&Message::from_digest(digest),&spend_key).serialize_der().to_vec();
                    sig.push(elements::EcdsaSighashType::All.as_u32() as u8);
                    let mut unlock = vec![sig.len() as u8]; unlock.extend_from_slice(&sig);
                    atxs[1].input[0].script_sig = Script::from(unlock);
                    let mut marker = vec![0x6a,37]; marker.extend_from_slice(b"ELMTP");
                    marker.extend_from_slice(&seed.expected_parent_hash_internal);
                    atxs[0].output[0].script_pubkey = Script::from(marker);
                    let mut head = header.clone();
                    head.base.prev_blockhash = BlockHash::from_byte_array(pi.tip_internal);
                    head.base.time = ah.last().unwrap().base.time + 1;
                    head.base.merkle_root = elements_transaction_merkle_root_v2(&atxs).unwrap();
                    head.base.ext = BlockExtData::Proof {challenge:Script::from(vec![0x51]),solution:Script::new()};
                    alpha.observation_time = u64::from(head.base.time);
                    alpha.raw_block = head.encode(false,true).unwrap();
                    alpha.raw_block.extend(elements::encode::serialize(&atxs));
                    alpha.parent = parent_for_child_checkpoint(&pi,critical_hash_internal(pi.genesis_internal,24,
                        head.hash_internal().unwrap(),&empty,&empty).unwrap());
                    alpha.history = ah.iter().map(|h|h.encode(false,true).unwrap()).collect();
                    let mut ae = env.clone();
                    ae.bind_custody_checkpoint_projection(&alpha.checkpoint,alpha.checkpoint.commitment().unwrap(),ah.last().unwrap()).unwrap();
                    ae.current_bmm_parent = Some(crate::ecx_environment_v4::Parent {
                        block_hash_wire:alpha.parent.expected_parent_hash_internal,
                        height:u64::from(alpha.parent.terminal_parent_predecessor.tip.height),
                        median_time_past:u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                            &alpha.parent.terminal_parent_predecessor.pow_context.previous_11_times).unwrap()),
                    });
                    alpha.environment = ae.encode().unwrap();
                    alpha.binding.roots.environment = ae.commitment().unwrap();
                    alpha.binding.roots.genesis_bindings = alpha.genesis_bindings.commitment();
                    alpha.binding.roots.execution.parent_binding = alpha.parent.binding.commitment().unwrap();
                    alpha.binding.roots.execution.predecessor_checkpoint = alpha.checkpoint.commitment().unwrap();
                    alpha.binding.roots.execution.execution_policy = alpha.policy.commitment().unwrap();
                    // Context, native execution and endpoint join each authenticate
                    // the parent. Require all three exact transcript passes.
                    let verifier = TranscriptVerifier::for_inputs([&alpha.parent,&alpha.parent,&alpha.parent]);
                    let output = execute_owned_custody_v4(&alpha,&verifier,&RejectSimplicityReceipt).unwrap();
                    verifier.assert_consumed();
                    crate::child_custody_guest_v6::tests::qualify_anchor_wrapper(&alpha,&alpha_domain,&RejectSimplicityReceipt);
                    let mut unbound = alpha.clone();
                    unbound.policy.creation.explicit_only_height = None;
                    // Even a newly self-consistent execution-policy hash cannot
                    // reuse a checkpoint with the old effective rules.
                    unbound.binding.roots.execution.execution_policy = unbound.policy.commitment().unwrap();
                    assert!(matches!(execute_owned_custody_v4(&unbound,
                        &TranscriptVerifier::for_input(&unbound.parent), &RejectSimplicityReceipt),
                        Err(crate::child_execution_guest_v4::AlphaChildExecutionErrorV4::Execution(AlphaChildExecutionErrorV3::Binding))));
                    assert_eq!(output.checkpoint().capital.as_ref(),Some(&capital));
                    assert_eq!(output.checkpoint().execution.height,7);
                    use crate::custody_redemption_statement_v2::extract_owned_accounting_checkpoint_v4;
                    let extracted = extract_owned_accounting_checkpoint_v4(&alpha_domain,fixture_verifier_address(),
                        alpha_domain.custody_id,&output,1,0).unwrap();
                    assert_eq!(extracted.burn(), &extract_custody_burn_v2(&atxs[1],0,
                        alpha_domain.elements_genesis_display,alpha_domain.usdd_asset_display,
                        alpha_domain.custody_id,alpha_domain.vault,100).unwrap());
                    for field in 0..4 {
                        let mut bad = alpha_domain.clone();
                        match field {
                            0 => bad.elements_genesis_display[0] ^= 1,
                            1 => bad.usdd_asset_display[0] ^= 1,
                            2 => bad.vault[0] ^= 1,
                            _ => bad.verifier_config_hash[0] ^= 1,
                        }
                        bad.custody_id = bad.derive_custody_id(fixture_verifier_address());
                        assert!(extract_owned_accounting_checkpoint_v4(&bad,fixture_verifier_address(),bad.custody_id,&output,1,0).is_err());
                    }
                    assert!(extract_owned_accounting_checkpoint_v4(&alpha_domain,[18;20],alpha_domain.custody_id,&output,1,0).is_err());
                    assert!(extract_owned_accounting_checkpoint_v4(&alpha_domain,fixture_verifier_address(),alpha_domain.custody_id,&output,0,0).is_err());
                    let statement = output.public_values();
                    assert_eq!(statement.canonical_bytes().len(),407);
                    assert_eq!(statement.0.source_binding,alpha.binding.commitment().unwrap());
                    assert_eq!(statement.0.predecessor_checkpoint,alpha.checkpoint.commitment().unwrap());
                    assert_eq!(statement.0.next_checkpoint,output.checkpoint().commitment().unwrap());
                    assert_eq!(statement.0.child_hash_internal,head.hash_internal().unwrap());
                    assert_eq!(statement.0.child_height,7);
                    assert_eq!(statement.0.observation_time,alpha.observation_time);
                    assert_eq!(CustodyExecutionPublicValuesV4::from_canonical_bytes(&statement.canonical_bytes()).unwrap().canonical_bytes(),statement.canonical_bytes());
                    for field in 0..3 {
                        let mut substituted = alpha.clone();
                        match field {
                            0 => substituted.binding.roots.execution.predecessor_checkpoint[0] ^= 1,
                            1 => substituted.binding.roots.execution.execution_policy[0] ^= 1,
                            _ => substituted.binding.roots.environment[0] ^= 1,
                        }
                        assert!(execute_owned_custody_v4(&substituted,
                            &TranscriptVerifier::for_inputs([&alpha.parent,&alpha.parent,&alpha.parent]),
                            &RejectSimplicityReceipt).is_err());
                    }
                    if !successor_mode {
                        // Connect the owned accounting checkpoint to a real fixture
                        // approval history; synthetic receipts remain test-only.
                        let mut steps = Vec::new();
                        let approval = crate::conversion_parent_link_v3::tests::approve_checkpoint_after_fixture(
                            alpha.parent.clone(), alpha_domain.custody_id, extracted.checkpoint(),
                            |step| steps.push(step.clone()));
                        let approval_index = steps.len() - 1;
                        let approval_transaction = approval.approval().transaction_id;
                        let confirmed = crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2::new(approval);
                        let history = crate::custody_history_wire_v2::CustodyHistoryWitnessV2 {
                            version: crate::custody_history_wire_v2::CUSTODY_HISTORY_VERSION_V2,
                            steps, approval_index: approval_index as u32, approval_transaction, approval_bundle: None,
                        };
                        let roots = &alpha.binding.roots;
                        let policy = crate::custody_execution_v2::CustodyAccountingExecutionPolicyV4 {
                            domain: alpha_domain.clone(), verifier_address: fixture_verifier_address(),
                            child_execution_binding: alpha.binding.commitment().unwrap(),
                            lineage: crate::custody_child_lineage_v2::CustodyAccountingLineagePolicyV4 {
                                genesis_initialization: alpha.binding.genesis_initialization,
                                roots: crate::custody_child_lineage_v2::CustodyChildLineagePolicyV5 {
                                    execution: crate::custody_child_lineage_v2::CustodyChildLineagePolicyV2 {
                                        execution_program: [42;32],
                                        initial_checkpoint: alpha.checkpoint.commitment().unwrap(),
                                        initial_height: alpha.checkpoint.execution.height,
                                        parent_binding: roots.execution.parent_binding,
                                        execution_policy: roots.execution.execution_policy,
                                        simplicity_program: roots.execution.simplicity_evaluator_program_id,
                                        deposit_configuration: roots.execution.deposit_configuration,
                                    },
                                    evaluator_source_closure: roots.evaluator_source_closure,
                                    genesis_bindings: roots.genesis_bindings, successor: roots.successor,
                                },
                            },
                            observation_time: alpha.observation_time,
                            destination_state: confirmed.state(), destination_anchor: confirmed.anchor(),
                            minimum_confirmations: 1,
                        };
                        let verifier = || TranscriptVerifier::for_inputs(
                            [&alpha.parent,&alpha.parent,&alpha.parent].into_iter()
                                .chain(history.steps[..=approval_index].iter())
                                .chain(std::iter::once(&history.steps[approval_index])));
                        let exact = verifier();
                        use crate::custody_execution_wire_v2::{CustodyAccountingWitnessV4,
                            CUSTODY_ACCOUNTING_WIRE_VERSION_V4,encode_custody_accounting_v4,
                            decode_custody_accounting_v4};
                        let transport = CustodyAccountingWitnessV4 {
                            version: CUSTODY_ACCOUNTING_WIRE_VERSION_V4,
                            policy: policy.clone(), child: alpha.clone(), history: history.clone(),
                            lineage_receipts: vec![], transaction_index: 1, output_index: 0,
                        };
                        let bytes = encode_custody_accounting_v4(&transport).unwrap();
                        let recovered = decode_custody_accounting_v4(&bytes).unwrap();
                        assert_eq!(encode_custody_accounting_v4(&recovered).unwrap(),bytes);
                        let mut trailing = bytes.clone(); trailing.push(0);
                        assert!(decode_custody_accounting_v4(&trailing).is_err());
                        for version in [0xb3,0xb5,0] {
                            let mut wrong = bytes.clone(); wrong[0] = version;
                            assert!(decode_custody_accounting_v4(&wrong).is_err());
                        }
                        assert!(decode_custody_accounting_v4(&bytes[..bytes.len()-1]).is_err());
                        assert!(crate::custody_execution_wire_v2::decode_custody_execution_v5(&bytes).is_err());
                        let composed = crate::custody_execution_v2::execute_custody_accounting_v4(
                            &recovered.policy,&recovered.child,&recovered.history,&recovered.lineage_receipts,
                            recovered.transaction_index as usize,recovered.output_index,
                            &exact,&RejectSimplicityReceipt).unwrap();
                        exact.assert_consumed();
                        let expected = extracted.checked_statement(&alpha_domain,fixture_verifier_address(),&confirmed,
                            confirmed.state(),confirmed.anchor(),1);
                        // The original cursor has not traversed history and must
                        // not itself authorize the destination.
                        assert!(expected.is_err());
                        let history_verifier = TranscriptVerifier::for_inputs(
                            history.steps.iter().chain(std::iter::once(&history.steps[approval_index])));
                        let (cursor, confirmation) = extracted.finish_history(&history.steps,
                            approval_index, approval_transaction, &history_verifier).unwrap();
                        history_verifier.assert_consumed();
                        let expected_statement = cursor.checked_statement(&alpha_domain,fixture_verifier_address(),
                            &confirmation,confirmed.state(),confirmed.anchor(),1).unwrap();
                        assert_eq!(&composed.canonical_bytes()[32..],&expected_statement);
                        assert_eq!(&composed.extended_bytes_v3()[32..64],&expected_statement);
                        assert_eq!(&composed.canonical_bytes()[..32],&policy.commitment().unwrap());
                        assert_eq!(&composed.extended_bytes_v3()[..32],&policy.release_commitment().unwrap());
                        for field in 0..5 {
                            let mut bad = policy.clone();
                            match field {
                                0 => bad.observation_time += 1,
                                1 => bad.destination_state[0] ^= 1,
                                2 => bad.destination_anchor[0] ^= 1,
                                3 => bad.minimum_confirmations = 2,
                                _ => bad.lineage.roots.evaluator_source_closure[0] ^= 1,
                            }
                            assert!(crate::custody_execution_v2::execute_custody_accounting_v4(
                                &bad,&alpha,&history,&[],1,0,&verifier(),&RejectSimplicityReceipt).is_err());
                        }
                        let mut activation=alpha.clone();
                        let initial_mtp=ae.current_bmm_parent.as_ref().unwrap().median_time_past - 1;
                        activation.genesis_initialization=crate::genesis_initialization_v2::GenesisInitializationV2 {
                            version:2, child_genesis:pi.genesis_internal, height:5,
                            block_internal:ah.iter().find(|h| h.base.height==5).unwrap().hash_internal().unwrap(),
                            parent_mtp:initial_mtp,
                        };
                        activation.binding.genesis_initialization=activation.genesis_initialization.commitment().unwrap();
                        let fixture=crate::capital_genesis_utxos_v4::tests::checkpoint_activation_fixture(
                            pi.genesis_internal,6,7,ae.current_bmm_parent.as_ref().unwrap().median_time_past,5,initial_mtp);
                        activation.checkpoint.capital=None;
                        activation.checkpoint.execution.roots.utxo_root=fixture.root;
                        activation.checkpoint.execution.roots.custody_root=fixture.custody_root(activation.policy.classification);
                        activation.configuration=fixture.configuration.clone();
                        activation.genesis_bindings=fixture.bindings.clone();
                        activation.capital=OwnedCapitalWitnessV4::Activation {
                            deployment:fixture.deployment.clone(),genesis:elements::encode::serialize(&fixture.genesis),
                            inventory:fixture.inventory.clone(),state:fixture.state.clone(),
                        };
                        activation.witnesses.truncate(1);activation.deposits.truncate(1);
                        atxs.truncate(1);
                        head.exchange=fixture.bindings.state_utxo_root;
                        head.base.merkle_root=elements_transaction_merkle_root_v2(&atxs).unwrap();
                        activation.raw_block=head.encode(false,true).unwrap();
                        activation.raw_block.extend(elements::encode::serialize(&atxs));
                        activation.parent=parent_for_child_checkpoint(&pi,critical_hash_internal(pi.genesis_internal,24,
                            head.hash_internal().unwrap(),&empty,&empty).unwrap());
                        let mut activation_env=ae.clone();
                        let bond=activation_env.bond_identity.as_mut().unwrap();
                        bond.configuration_hash=fixture.configuration.digest();
                        bond.asset_id=fixture.configuration.bond_asset_id;
                        bond.deployment_commitment=fixture.configuration.bond_deployment_commitment;
                        bond.transition_cmr=fixture.bindings.transition_cmr;
                        activation_env.incremental_identity.as_mut().unwrap().activation_cmr=fixture.bindings.activation_cmr;
                        activation_env.bind_custody_checkpoint_projection(&activation.checkpoint,
                            activation.checkpoint.commitment().unwrap(),ah.last().unwrap()).unwrap();
                        activation.environment=activation_env.encode().unwrap();
                        activation.binding.roots.environment=activation_env.commitment().unwrap();
                        activation.binding.roots.genesis_bindings=fixture.bindings.commitment();
                        activation.binding.roots.execution.predecessor_checkpoint=activation.checkpoint.commitment().unwrap();
                        activation.binding.roots.execution.parent_binding=activation.parent.binding.commitment().unwrap();
                        let verifier=TranscriptVerifier::for_inputs([&activation.parent,&activation.parent,&activation.parent]);
                        let activated=execute_owned_custody_v4(&activation,&verifier,&RejectSimplicityReceipt).unwrap();
                        verifier.assert_consumed();
                        assert_eq!(activated.checkpoint().capital.as_ref().unwrap().covenant_state_hash,
                            fixture.public.state_hash(fixture.bindings.public_state_domain));
                        // Run the actual host materializer on this direct-price,
                        // public-deployment fixture, not a different V18 vector.
                        let b = &fixture.bindings;
                        let materialized = crate::genesis_materializer_test_bridge::materialize_test_json(
                            fixture.configuration.clone(), serde_json::json!({
                                "initialization": activation.genesis_initialization,
                                "initialization_commitment_hex": hex::encode(activation.binding.genesis_initialization),
                                "state_creation_sidechain_height": fixture.state.leaf.creation_height,
                                "prior_parent_mtp": ae.current_bmm_parent.as_ref().unwrap().median_time_past,
                                "genesis_mark_price_atoms": b.mark_price_atoms,
                                "genesis_availability_root_hex": hex::encode(b.availability_root),
                                "order_receipts_genesis_root_hex": hex::encode(b.order_receipts_root),
                                "public_state_domain_sha256_hex": hex::encode(b.public_state_domain),
                                "state_node_domain_sha256_hex": hex::encode(b.state_node_domain),
                                "transition_journal_domain_sha256_hex": hex::encode(b.journal_domain),
                                "transition_cmr_hex": hex::encode(b.transition_cmr),
                                "incremental_activation_cmr_hex": hex::encode(b.activation_cmr),
                                "keyless_internal_key_hex": hex::encode(b.internal_key),
                            }));
                        assert_eq!(materialized["covenant_public_state"], serde_json::to_value(&fixture.public).unwrap());
                        assert_eq!(materialized["state_script_hex"], hex::encode(fixture.genesis.output[0].script_pubkey.as_bytes()));
                        assert_eq!(materialized["covenant_state_hash_hex"],
                            hex::encode(activated.checkpoint().capital.as_ref().unwrap().covenant_state_hash));
                        assert_eq!(activated.public_values().0.next_checkpoint,activated.checkpoint().commitment().unwrap());
                        assert_eq!(activated.public_values().0.child_hash_internal,head.hash_internal().unwrap());
                        let statement=activated.public_values();
                        assert_eq!(statement.canonical_bytes().len(),407);
                        assert_eq!(statement.0.source_binding,activation.binding.commitment().unwrap());
                        assert_eq!(statement.0.predecessor_checkpoint,activation.checkpoint.commitment().unwrap());
                        assert_eq!(statement.0.child_height,7);
                        assert_eq!(statement.0.observation_time,activation.observation_time);
                        let mut old_statement=statement.canonical_bytes(); old_statement[0]=0xac;
                        assert!(CustodyExecutionPublicValuesV4::from_canonical_bytes(&old_statement).is_err());
                        for field in 0..5 {
                            let mut bad=activation.clone();
                            match field {
                                0 => bad.genesis_initialization.block_internal[0]^=1,
                                1 => { bad.genesis_initialization.block_internal[0]^=1;
                                    bad.binding.genesis_initialization=bad.genesis_initialization.commitment().unwrap(); },
                                2 => { bad.genesis_initialization.height=6;
                                    bad.binding.genesis_initialization=bad.genesis_initialization.commitment().unwrap(); },
                                3 => { bad.genesis_initialization.parent_mtp=initial_mtp+2;
                                    bad.binding.genesis_initialization=bad.genesis_initialization.commitment().unwrap(); },
                                _ => bad.version=0xac,
                            }
                            assert!(execute_owned_custody_v4(&bad,
                                &TranscriptVerifier::for_inputs([&activation.parent,&activation.parent,&activation.parent]),
                                &RejectSimplicityReceipt).is_err(), "initializer substitution {field}");
                        }
                        assert_eq!(CustodyExecutionPublicValuesV4::from_canonical_bytes(&statement.canonical_bytes()).unwrap().canonical_bytes(),statement.canonical_bytes());
                        for field in 0..2 {
                            let mut bad=activation.clone();
                            if let OwnedCapitalWitnessV4::Activation {deployment,genesis,..}=&mut bad.capital {
                                if field==0 {deployment.version=2;} else {genesis[0]^=1;}
                            }
                            assert!(execute_owned_custody_v4(&bad,
                                &TranscriptVerifier::for_inputs([&activation.parent,&activation.parent,&activation.parent]),
                                &RejectSimplicityReceipt).is_err());
                        }
                    }
                }
            }
            if changed_root {
                // The changed root has a valid signature and parent linkage;
                // execution alone must not turn it into an unchanged carry.
                assert!(checked.carry_projection(&executed,configuration,&bindings,bindings.commitment(),identity,&[]).is_err());
                continue;
            }
            let carried = checked.carry_projection(&executed,configuration,&bindings,bindings.commitment(),identity,&[]).unwrap();
            assert_eq!(carried,capital);
            let next = executed.child().next_checkpoint().unwrap().clone();
            let joined = crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4::join_executed_parent(
                next.clone(),Some(carried.clone()),&executed,&carry_parent,carry_parent_hash,
                &TranscriptVerifier::for_input(&carry_parent)).unwrap();
            assert_eq!(joined.capital,Some(capital.clone()));
            assert_eq!(joined.execution.height,7);
            assert_eq!(joined.bmm_endpoint.as_ref().unwrap().len(),80);
            assert!(crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4::join_executed_parent(
                next,Some(carried),&executed,&parent,parent_frozen,
                &TranscriptVerifier::for_input(&parent)).is_err());
            assert!(checked.carry_projection(&custody_dispatched,configuration,&bindings,bindings.commitment(),identity,&[]).is_err());
            assert!(checked.carry_projection(&executed,configuration,&bindings,[0;32],identity,&[]).is_err());
            let mut changed_bindings = bindings.clone(); changed_bindings.child_genesis[0] ^= 1;
            assert!(checked.carry_projection(&executed,configuration,&changed_bindings,changed_bindings.commitment(),identity,&[]).is_err());
            let mut changed_configuration = configuration.clone(); changed_configuration.bond_deployment_commitment[0] ^= 1;
            assert!(checked.carry_projection(&executed,&changed_configuration,&bindings,bindings.commitment(),identity,&[]).is_err());
            let mut premature = bindings.clone(); premature.activation_height = 7;
            assert!(checked.carry_projection(&executed,configuration,&premature,premature.commitment(),identity,&[]).is_err());
            if successor_mode {
                for field in 0..3 {
                    let mut wrong = successor_identity.clone();
                    match field { 0 => wrong.configuration_hash[0] ^= 1,
                        1 => wrong.program_id[0] ^= 1, _ => wrong.transition_cmr[0] ^= 1 }
                    assert!(checked.carry_projection(&executed,configuration,&bindings,bindings.commitment(),Some(&wrong),&[]).is_err());
                }
                assert!(checked.carry_projection(&executed,configuration,&bindings,bindings.commitment(),None,&[]).is_err());
            } else {
                assert!(checked.carry_projection(&executed,configuration,&bindings,bindings.commitment(),Some(&successor_identity),&[]).is_err());
            }
        }
        let encoded = encode_alpha_child_execution_input_v3(&guest_input).unwrap();
        let raw_decoded: AlphaChildExecutionInputV3 = bincode::deserialize(&encoded)
            .expect("owned child guest fixture must be bincode-deserializable");
        assert_eq!(raw_decoded, guest_input);
        assert_eq!(decode_alpha_child_execution_input_v3(&encoded).unwrap(),guest_input);
        let executed_guest = run_guest(&guest_input).unwrap();
        assert_eq!(executed_guest.checked().child().next_checkpoint(),
            joined_state.child().next_checkpoint());
        let journal = executed_guest.public_values();
        use crate::custody_child_lineage_v2::{CustodyChildLineagePolicyV2,verify_custody_child_lineage_v2};
        let lineage_policy = CustodyChildLineagePolicyV2 {execution_program:[2;32],
            initial_checkpoint:frozen,initial_height:checkpoint.height,parent_binding:parent_frozen,
            execution_policy:frozen_policy,simplicity_program:[1;32],
            deposit_configuration:guest_input.binding.deposit_configuration};
        struct ChildReceiptFixture(Vec<u8>);
        impl crate::FullAlphaReceiptVerifierV3 for ChildReceiptFixture {
            fn verify(&self,program:[u8;32],journal:&[u8],marker:&[u8])
                -> Result<(),crate::FullAlphaAdapterErrorV3> {
                if program == [2;32] && journal == self.0 && marker == [42] { Ok(()) }
                else { Err(crate::FullAlphaAdapterErrorV3::Receipt) }
            }
        }
        let receipt = crate::AlphaRecursiveReceiptBindingV3 {
            public_values:journal.canonical_bytes().to_vec(),proof_marker:vec![42]};
        let receipt_verifier=ChildReceiptFixture(receipt.public_values.clone());
        verify_custody_child_lineage_v2(&lineage_policy,std::slice::from_ref(&receipt),
            journal.next_checkpoint,journal.child_height,&receipt_verifier).unwrap();
        verify_custody_child_lineage_v2(&lineage_policy,&[],frozen,checkpoint.height,&receipt_verifier).unwrap();
        assert!(verify_custody_child_lineage_v2(&lineage_policy,&[],journal.next_checkpoint,
            journal.child_height,&receipt_verifier).is_err());
        let mut substituted=receipt.clone(); substituted.proof_marker[0]^=1;
        assert!(verify_custody_child_lineage_v2(&lineage_policy,&[substituted],journal.next_checkpoint,
            journal.child_height,&receipt_verifier).is_err());
        assert!(verify_custody_child_lineage_v2(&lineage_policy,&[receipt.clone(),receipt],
            journal.next_checkpoint,journal.child_height,&receipt_verifier).is_err());
        assert_eq!(journal.canonical_bytes().len(),407);
        assert_eq!(journal.parent,*joined_state.parent());
        journal.require_source_and_clock(guest_input.binding.commitment().unwrap(),100).unwrap();
        assert!(journal.require_source_and_clock([0;32],100).is_err());
        assert!(journal.require_source_and_clock(guest_input.binding.commitment().unwrap(),101).is_err());
        let mut trailing = encoded.clone(); trailing.push(0);
        assert!(decode_alpha_child_execution_input_v3(&trailing).is_err());
        assert!(decode_alpha_child_execution_input_v3(&encoded[..encoded.len()-1]).is_err());
        assert!(decode_alpha_child_execution_input_v3(&[]).is_err());
        for field in 0..11 {
            let mut changed = guest_input.clone();
            match field {
                0 => changed.binding.parent_binding[0] ^= 1,
                1 => changed.binding.predecessor_checkpoint[0] ^= 1,
                2 => changed.binding.execution_policy[0] ^= 1,
                3 => changed.binding.deposit_configuration[0] ^= 1,
                4 => changed.binding.simplicity_evaluator_program_id = [0;32],
                5 => changed.history[0].push(0),
                6 => changed.parent.parent.checkpoint_receipt.proof_marker.push(99),
                7 => changed.deposits.clear(),
                8 => changed.simplicity_receipts.push(ElementsSimplicityReceiptBindingV2 {
                    public_values:vec![0;33],proof_marker:vec![1] }),
                9 => changed.deposit_configuration.minimum_depth = 0,
                _ => changed.header_policy.epoch_length += 1,
            }
            assert!(run_guest(&changed).is_err(),"guest mutation {field} accepted");
        }
        // The signature solution is excluded from the block ID and M7
        // critical hash. Parent authentication must not let it bypass the
        // concrete header script engine in the composed path.
        let mut unsigned_header_block = linked_block.clone();
        if let BlockExtData::Proof { solution, .. } = &mut unsigned_header_block.header.ext {
            *solution = Script::new();
        } else { panic!("expected signed legacy fixture"); }
        assert_eq!(unsigned_header_block.block_hash(),linked_block.block_hash());
        let mut unsigned_guest = guest_input.clone();
        unsigned_guest.raw_block = elements::encode::serialize(&unsigned_header_block);
        assert!(run_guest(&unsigned_guest).is_err());
        assert!(matches!(joined(&elements::encode::serialize(&unsigned_header_block),&parent),
            Err(ParentBoundChildError::State(ChildStateError::Authorization))));
        let verified_parent = joined_state.parent();
        let verified_child = joined_state.child();
        use crate::native_conversion_accounting_v3::{ConversionAccountingBindingV3,ConversionAccountingErrorV3};
        let accounting = ConversionAccountingBindingV3 {
            child_genesis_internal: checkpoint.genesis_internal,
            child_configuration_commitment: checkpoint.configuration_commitment,
            classification, quote_atoms_per_whole_base: 1,
        };
        let accounting_hash = accounting.commitment().unwrap();
        // This real signed-spend fixture burns the entire outstanding supply.
        // Parent/child success therefore must NOT imply conversion readiness.
        assert_eq!(joined_state.conversion_accounting(&accounting,accounting_hash),
            Err(ConversionAccountingErrorV3::EmptySupply));
        // Cross the new 407-byte receipt boundary using the result of actual
        // native signed execution above. Only parent/child proof transport is a
        // TEST transcript; no SP1 proof, live replay or source review is claimed.
        use crate::native_conversion_source_v3::{NativeConversionSourceInputV3,
            NativeConversionSourceBindingV3, NativeSourceClockPolicyV3,
            NATIVE_CONVERSION_SOURCE_VERSION_V3, execute_native_conversion_source_v3,
            NativeConversionSourceErrorV3, tests::ExactTranscript};
        let source_observation = crate::execute_full_alpha_adapter_v3(
            &parent.parent,&TranscriptVerifier::for_input(&parent)).unwrap();
        let mut timed_guest = guest_input.clone();
        timed_guest.observation_time = source_observation.terminal_mtp;
        let timed_execution = run_guest(&timed_guest).unwrap();
        let source = NativeConversionSourceInputV3 {
            version: NATIVE_CONVERSION_SOURCE_VERSION_V3,
            binding: NativeConversionSourceBindingV3 {
                child_execution_program_id:[4;32], parent:parent.binding,
                predecessor_checkpoint:frozen, execution_policy:frozen_policy,
                simplicity_evaluator_program_id:timed_guest.binding.simplicity_evaluator_program_id,
                deposit_configuration:timed_guest.binding.deposit_configuration,
                accounting_binding:accounting_hash,
                clock_policy:NativeSourceClockPolicyV3::ParentObservationMtp,
                minimum_parent_confirmations:1, maximum_child_age_seconds:2_000_000_000,
            },
            child_receipt:crate::AlphaRecursiveReceiptBindingV3 {
                public_values:timed_execution.public_values().canonical_bytes().to_vec(),
                proof_marker:vec![0x7e],
            },
            parent:parent.clone(), observation:parent.parent.clone(),parent_continuation:vec![],
            predecessor:checkpoint.clone(),
            successor:timed_execution.checked().child().next_checkpoint().unwrap().clone(),
            predecessor_history:timed_guest.history.clone(),raw_child_block:timed_guest.raw_block.clone(),
            execution_policy,deposit_configuration:timed_guest.deposit_configuration.clone(),accounting,
        };
        assert_eq!(execute_native_conversion_source_v3(&source,source.binding.commitment().unwrap(),
            &ExactTranscript::for_input(&source)),
            Err(NativeConversionSourceErrorV3::Accounting(ConversionAccountingErrorV3::EmptySupply)));
        // The signed solution does not affect the native block hash or M7, but
        // it DOES affect the executed checkpoint history. A substituted signed
        // material preimage is rejected even alongside the original receipt.
        let mut substituted_source = source.clone();
        substituted_source.raw_child_block = unsigned_guest.raw_block.clone();
        assert_eq!(execute_native_conversion_source_v3(&substituted_source,
            source.binding.commitment().unwrap(),&ExactTranscript::for_input(&source)),
            Err(NativeConversionSourceErrorV3::History));
        use crate::conversion_composition_v3::{
            project_parent_bound_child_conversion_v3, ConversionCompositionErrorV3,
        };
        assert_eq!(
            project_parent_bound_child_conversion_v3(
                &joined_state, parent_frozen, &accounting, accounting_hash
            ),
            Err(ConversionCompositionErrorV3::Accounting(
                ConversionAccountingErrorV3::EmptySupply
            ))
        );
        assert_eq!(
            project_parent_bound_child_conversion_v3(
                &joined_state, [0;32], &accounting, accounting_hash
            ),
            Err(ConversionCompositionErrorV3::Binding)
        );
        let mut wrong_accounting = accounting;
        wrong_accounting.child_configuration_commitment = [99;32];
        // Even a separately frozen mismatching accounting preimage cannot
        // reinterpret the already-checked child's configuration.
        assert_eq!(joined_state.conversion_accounting(&wrong_accounting,wrong_accounting.commitment().unwrap()),
            Err(ConversionAccountingErrorV3::Configuration));
        wrong_accounting = accounting;
        wrong_accounting.child_genesis_internal = [99;32];
        assert_eq!(joined_state.conversion_accounting(&wrong_accounting,wrong_accounting.commitment().unwrap()),
            Err(ConversionAccountingErrorV3::Configuration));
        verified_parent.require_frozen_binding(parent_frozen).unwrap();
        assert_eq!(verified_child.roots(),next);
        let next_checkpoint = verified_child.next_checkpoint().unwrap();
        assert_eq!(next_checkpoint.genesis_internal,checkpoint.genesis_internal);
        assert_eq!(next_checkpoint.configuration_commitment,checkpoint.configuration_commitment);
        assert_eq!(next_checkpoint.height,checkpoint.height + 1);
        assert_eq!(next_checkpoint.roots,next);
        assert_eq!(next_checkpoint.withdrawals,verified_child.foundation().next_accumulator);
        let mut advanced_history = context.previous_headers.clone();
        advanced_history.push(verified_child.foundation().native_header.clone());
        next_checkpoint.checked_mtp_history(&advanced_history).unwrap();
        assert!(next_checkpoint.checked_mtp_history(&context.previous_headers).is_err());
        assert_ne!(next_checkpoint.commitment().unwrap(),frozen);
        assert!(checked.next_checkpoint().is_none());
        let mut checkpoint_genesis_display = checkpoint.genesis_internal;
        checkpoint_genesis_display.reverse();
        let expected_checkpoint_burn = extract_custody_burn_v2(&tx,0,
            checkpoint_genesis_display,display_asset,custody,[9;20],100).unwrap();
        assert_eq!(extract_domain_bound_executed_burn_v2(&redemption_domain,fixture_verifier_address(),custody,
            &joined_state,1,0).unwrap(),expected_checkpoint_burn);
        let mut bound = crate::custody_redemption_statement_v2::extract_executed_custody_checkpoint_v2(
            &redemption_domain,fixture_verifier_address(),custody,&joined_state,1,0).unwrap();
        assert_eq!(bound.burn(), &expected_checkpoint_burn);
        let empty_history = crate::custody_redemption_statement_v2::extract_executed_custody_checkpoint_v2(
            &redemption_domain,fixture_verifier_address(),custody,&joined_state,1,0).unwrap();
        assert!(empty_history.finish_history(&[],0,bitcoin::Txid::all_zeros(),
            &TranscriptVerifier::for_input(&parent)).is_err());
        assert_eq!(bound.checkpoint(), joined_state.child().next_checkpoint().unwrap().commitment().unwrap());
        assert_ne!(bound.checkpoint(), frozen);
        // Compose actual child execution with independently replayed synthetic
        // M6 approval. This exercises commitment linkage, NOT shared ancestry
        // or finality between the two synthetic parent histories.
        let approval = crate::conversion_parent_link_v3::tests::authenticated_checkpoint_approval_fixture(
            custody,bound.checkpoint());
        bound.require_approval(&approval,approval.binding_commitment()).unwrap();
        assert!(bound.require_history_approval(&approval).is_err()); // unrelated parent histories
        assert_eq!(bound.parent_state(),joined_state.parent().parent_terminal_state_commitment);
        assert_eq!(bound.parent_anchor(),joined_state.parent().parent_block_hash_internal);
        let original_state = bound.parent_state();
        let original_anchor = bound.parent_anchor();
        assert!(bound.advance_parent(&parent.binding,&parent.parent,&parent.terminal_parent_predecessor,
            &parent.terminal_parent_block,&TranscriptVerifier::for_input(&parent)).is_err());
        assert_eq!(bound.parent_state(),original_state); // failed advance is atomic
        assert_eq!(bound.parent_anchor(),original_anchor);
        let successor = crate::conversion_parent_link_v3::tests::successor_fixture(&parent);
        bound.advance_parent(&successor.binding,&successor.parent,&successor.terminal_parent_predecessor,
            &successor.terminal_parent_block,&TranscriptVerifier::for_input(&successor)).unwrap();
        assert_eq!(bound.parent_state(),successor.parent.terminal_selected_state.commitment().unwrap());
        assert_eq!(bound.parent_anchor(),successor.parent.terminal_selected_state.tip.block_hash.to_byte_array());
        assert_eq!(bound.burn(),&expected_checkpoint_burn);
        assert_eq!(bound.checkpoint(),joined_state.child().next_checkpoint().unwrap().commitment().unwrap());
        assert!(bound.advance_parent(&successor.binding,&successor.parent,&successor.terminal_parent_predecessor,
            &successor.terminal_parent_block,&TranscriptVerifier::for_input(&successor)).is_err());
        let second = crate::conversion_parent_link_v3::tests::successor_fixture(&successor);
        bound.advance_parent(&second.binding,&second.parent,&second.terminal_parent_predecessor,
            &second.terminal_parent_block,&TranscriptVerifier::for_input(&second)).unwrap();
        assert_eq!(bound.parent_state(),second.parent.terminal_selected_state.commitment().unwrap());
        assert!(bound.require_history_approval(&approval).is_err());
        let approved_checkpoint = bound.checkpoint();
        let mut history = vec![successor.clone(),second.clone()];
        let linked_approval = crate::conversion_parent_link_v3::tests::approve_checkpoint_after_fixture(
            second,custody,approved_checkpoint,|step| {
                history.push(step.clone());
                bound.advance_parent(&step.binding,&step.parent,&step.terminal_parent_predecessor,
                    &step.terminal_parent_block,&TranscriptVerifier::for_input(step)).unwrap();
            });
        bound.require_history_approval(&linked_approval).unwrap();
        let approval_index = history.len()-1;
        let approval_transaction = linked_approval.approval().transaction_id;
        let confirmations = crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2::new(linked_approval);
        bound.require_confirmed_history(&confirmations, confirmations.state(), confirmations.anchor(), 1).unwrap();
        assert!(bound.require_confirmed_history(&confirmations, confirmations.state(), confirmations.anchor(), 2).is_err());
        assert!(bound.require_confirmed_history(&confirmations, [0;32], confirmations.anchor(), 1).is_err());
        assert!(bound.require_confirmed_history(&confirmations, confirmations.state(), [0;32], 1).is_err());
        let unrelated = crate::conversion_parent_link_v3::CustodyApprovalConfirmationsV2::new(approval.clone());
        assert!(bound.require_confirmed_history(&unrelated, unrelated.state(), unrelated.anchor(), 1).is_err());
        let journal = bound.checked_statement(&redemption_domain,fixture_verifier_address(),&confirmations,
            confirmations.state(),confirmations.anchor(),1).unwrap();
        // Full orchestration must consume the exact ordered receipt transcript,
        // including the independent second authentication of the approval block.
        let fresh_cursor = || crate::custody_redemption_statement_v2::extract_executed_custody_checkpoint_v2(
            &redemption_domain,fixture_verifier_address(),custody,&joined_state,1,0).unwrap();
        let history_verifier = |steps: &[crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3]| {
            TranscriptVerifier::for_inputs(steps[..=approval_index].iter()
                .chain(std::iter::once(&steps[approval_index]))
                .chain(steps[approval_index+1..].iter()))
        };
        let verifier = history_verifier(&history);
        let (assembled, confirmed) = fresh_cursor().finish_history(&history,approval_index,
            approval_transaction,&verifier).unwrap();
        verifier.assert_consumed();
        use crate::custody_history_wire_v2::{CustodyHistoryWitnessV2,
            CUSTODY_HISTORY_VERSION_V2,encode_custody_history_v2,decode_custody_history_v2};
        let witness = CustodyHistoryWitnessV2 { version:CUSTODY_HISTORY_VERSION_V2,
            steps:history.clone(),approval_index:approval_index as u32,approval_transaction,approval_bundle:None };
        let encoded = encode_custody_history_v2(&witness).unwrap();
        let decoded = decode_custody_history_v2(&encoded).unwrap();
        assert_eq!(decoded,witness);
        let verifier = history_verifier(&decoded.steps);
        let (decoded_cursor,decoded_confirmations) = fresh_cursor().finish_history(
            &decoded.steps,decoded.approval_index as usize,decoded.approval_transaction,&verifier).unwrap();
        verifier.assert_consumed();
        assert_eq!(decoded_cursor.checked_statement(&redemption_domain,fixture_verifier_address(),&decoded_confirmations,
            confirmations.state(),confirmations.anchor(),1).unwrap(),journal);
        let destination = &decoded.steps.last().unwrap().parent.terminal_selected_state;
        let tuple = decoded_confirmations.destination_tuple(destination).unwrap();
        let mut display_hash = destination.tip.block_hash.to_byte_array(); display_hash.reverse();
        assert_eq!(tuple.block_hash_display,display_hash);
        assert_eq!(tuple.height,destination.tip.height);
        assert_eq!(tuple.chainwork_be,destination.tip.chainwork_be);
        assert_eq!(tuple.median_time_past,ecx_full_consensus_validator_v2::median_time_past_v2(
            &destination.pow_context.previous_11_times).unwrap());
        let mut substituted = destination.clone(); substituted.tip.chainwork_be[31] ^= 1;
        assert!(decoded_confirmations.destination_tuple(&substituted).is_err());
        let mut substituted = destination.clone(); substituted.pow_context.previous_11_times[0] ^= 1;
        assert!(decoded_confirmations.destination_tuple(&substituted).is_err());
        assert!(decoded_confirmations.destination_tuple(&decoded.steps[0].parent.terminal_selected_state).is_err());
        use crate::custody_execution_v2::{CustodyExecutionPolicyV2,execute_custody_v2};
        let mut custody_policy = CustodyExecutionPolicyV2 {domain:redemption_domain.clone(),
            lineage:lineage_policy,
            verifier_address:fixture_verifier_address(),child_execution_binding:guest_input.binding.commitment().unwrap(),
            observation_time:guest_input.observation_time,destination_state:confirmations.state(),
            destination_anchor:confirmations.anchor(),minimum_confirmations:1};
        let complete_verifier = || TranscriptVerifier::for_inputs(std::iter::once(&parent)
            .chain(decoded.steps[..=approval_index].iter())
            .chain(std::iter::once(&decoded.steps[approval_index]))
            .chain(decoded.steps[approval_index+1..].iter()));
        let verifier = complete_verifier();
        use crate::custody_execution_wire_v2::{CustodyExecutionWitnessV2,
            CUSTODY_EXECUTION_WIRE_VERSION_V2,encode_custody_execution_v2,decode_custody_execution_v2};
        let transport = CustodyExecutionWitnessV2 {version:CUSTODY_EXECUTION_WIRE_VERSION_V2,
            policy:custody_policy.clone(),child:guest_input.clone(),history:decoded.clone(),
            lineage_receipts:vec![],transaction_index:1,output_index:0};
        let wire = encode_custody_execution_v2(&transport).unwrap();
        let recovered = decode_custody_execution_v2(&wire).unwrap();
        assert_eq!(encode_custody_execution_v2(&recovered).unwrap(),wire);
        let mut bad_wire = wire.clone(); bad_wire.push(0);
        assert!(decode_custody_execution_v2(&bad_wire).is_err());
        let mut bad_wire = wire.clone(); bad_wire[0] ^= 1;
        assert!(decode_custody_execution_v2(&bad_wire).is_err());
        assert!(decode_custody_execution_v2(&wire[..wire.len()-1]).is_err());
        // Synthetic transport only: this does not authenticate a V5 endpoint
        // or establish that this candidate passes the V5 execution guest.
        {
            use crate::custody_execution_wire_v2::{CustodyExecutionWitnessV5,
                CUSTODY_EXECUTION_WIRE_VERSION_V5, encode_custody_execution_v5,
                decode_custody_execution_v5};
            let child = crate::child_execution_guest_v4::check_owned_wire_fixture(&guest_input);
            let policy = crate::custody_execution_v2::CustodyExecutionPolicyV5 {
                domain: custody_policy.domain.clone(), verifier_address: custody_policy.verifier_address,
                child_execution_binding: child.binding.commitment().unwrap(),
                lineage: crate::custody_child_lineage_v2::CustodyChildLineagePolicyV5 {
                    execution: custody_policy.lineage.clone(),
                    evaluator_source_closure: child.binding.evaluator_source_closure,
                    genesis_bindings: child.binding.genesis_bindings, successor: None,
                },
                observation_time: custody_policy.observation_time,
                destination_state: custody_policy.destination_state,
                destination_anchor: custody_policy.destination_anchor, minimum_confirmations: 1,
            };
            let transport = CustodyExecutionWitnessV5 { version: CUSTODY_EXECUTION_WIRE_VERSION_V5,
                policy, child, history: decoded.clone(), lineage_receipts: vec![],
                transaction_index: 1, output_index: 0 };
            let bytes = encode_custody_execution_v5(&transport).unwrap();
            let recovered = decode_custody_execution_v5(&bytes).unwrap();
            assert_eq!(encode_custody_execution_v5(&recovered).unwrap(), bytes);
            assert_eq!(recovered.child, transport.child);
            assert_eq!(recovered.policy.commitment().unwrap(), transport.policy.commitment().unwrap());
            assert_eq!(&bytes[bytes.len()-8..], &[0,0,0,1,0,0,0,0]);
            assert!(decode_custody_execution_v2(&bytes).is_err());
            assert!(decode_custody_execution_v5(&wire).is_err());
            assert!(decode_custody_execution_v5(&bytes[..bytes.len()-1]).is_err());
            let mut suffix = bytes.clone(); suffix.push(0);
            assert!(decode_custody_execution_v5(&suffix).is_err());
            let mut malformed = transport.clone(); malformed.child.version = 0xaa;
            assert!(encode_custody_execution_v5(&malformed).is_err());
            let mut malformed = transport.clone(); malformed.child.checkpoint.bmm_endpoint = Some(vec![1;79]);
            assert!(encode_custody_execution_v5(&malformed).is_err());
            let mut malformed = transport.clone(); malformed.policy.minimum_confirmations = 0;
            assert!(encode_custody_execution_v5(&malformed).is_err());
        }
        let complete = execute_custody_v2(&recovered.policy,&recovered.child,&recovered.history,
            &recovered.lineage_receipts,recovered.transaction_index as usize,recovered.output_index,
            &verifier,&RejectSimplicityReceipt).unwrap();
        verifier.assert_consumed();
        assert_eq!(&complete.canonical_bytes()[..32],&custody_policy.commitment().unwrap());
        assert_eq!(&complete.canonical_bytes()[32..],&journal);
        // Same executed, permanently consumed burn; stop parent history at six
        // M4 acks instead of waiting for the later M6 transaction.
        {
            use crate::conversion_parent_link_v3::{CustodyAckBundleV3,
                custody_checkpoint_approval_commitment_v2};
            let bundle = CustodyAckBundleV3 {transaction_version:2,lock_time:0,fee_sat:1000,
                checkpoint_commitment:custody_checkpoint_approval_commitment_v2(custody,approved_checkpoint).unwrap()};
            let mut early = recovered.clone();
            let index = early.history.steps.iter().position(|step|
                step.parent.terminal_selected_state.bip300_state.as_state().active_slots[&24]
                    .pending_m6ids.iter().any(|p| p.m6id == bundle.compute_txid() && p.score == 7)).unwrap();
            early.history.steps.truncate(index+1);
            early.history.approval_index = index as u32;
            early.history.approval_transaction = bundle.compute_txid();
            early.history.approval_bundle = Some(bundle);
            let tip = &early.history.steps[index].parent.terminal_selected_state;
            early.policy.destination_state = tip.commitment().unwrap();
            early.policy.destination_anchor = tip.tip.block_hash.to_byte_array();
            let wire = encode_custody_execution_v2(&early).unwrap();
            let early = decode_custody_execution_v2(&wire).unwrap();
            let verifier = TranscriptVerifier::for_inputs(std::iter::once(&parent)
                .chain(early.history.steps.iter()).chain(std::iter::once(&early.history.steps[index])));
            let result = execute_custody_v2(&early.policy,&early.child,&early.history,
                &early.lineage_receipts,early.transaction_index as usize,early.output_index,
                &verifier,&RejectSimplicityReceipt).unwrap();
            verifier.assert_consumed();
            assert_ne!(result.canonical_bytes(),complete.canonical_bytes());
            let mut missing_burn = early.clone(); missing_burn.transaction_index = 0;
            assert!(execute_custody_v2(&missing_burn.policy,&missing_burn.child,&missing_burn.history,
                &[],0,0,&TranscriptVerifier::for_inputs(std::iter::once(&parent)
                    .chain(early.history.steps.iter()).chain(std::iter::once(&early.history.steps[index]))),
                &RejectSimplicityReceipt).is_err());
        }
        custody_policy.minimum_confirmations = 2;
        assert!(execute_custody_v2(&custody_policy,&guest_input,&decoded,&[],1,0,
            &complete_verifier(),&RejectSimplicityReceipt).is_err());
        custody_policy.minimum_confirmations = 1;
        custody_policy.observation_time += 1;
        assert!(execute_custody_v2(&custody_policy,&guest_input,&decoded,&[],1,0,
            &complete_verifier(),&RejectSimplicityReceipt).is_err());
        custody_policy.observation_time -= 1;
        assert!(execute_custody_v2(&custody_policy,&guest_input,&decoded,&[],0,0,
            &complete_verifier(),&RejectSimplicityReceipt).is_err());
        let mut tampered_child = guest_input.clone();
        tampered_child.raw_block[0] ^= 1;
        assert!(execute_custody_v2(&custody_policy,&tampered_child,&decoded,&[],1,0,
            &complete_verifier(),&RejectSimplicityReceipt).is_err());
        custody_policy.lineage.initial_checkpoint[0] ^= 1;
        assert!(matches!(execute_custody_v2(&custody_policy,&guest_input,&decoded,&[],1,0,
            &complete_verifier(),&RejectSimplicityReceipt),Err(crate::custody_execution_v2::CustodyExecutionErrorV2::Lineage)));
        custody_policy.lineage.initial_checkpoint[0] ^= 1;
        custody_policy.lineage.execution_policy[0] ^= 1;
        assert!(matches!(execute_custody_v2(&custody_policy,&guest_input,&decoded,&[],1,0,
            &complete_verifier(),&RejectSimplicityReceipt),Err(crate::custody_execution_v2::CustodyExecutionErrorV2::Lineage)));
        custody_policy.lineage.execution_policy[0] ^= 1;
        let mut malformed = encoded.clone(); malformed.push(0);
        assert!(decode_custody_history_v2(&malformed).is_err());
        malformed = encoded.clone(); malformed[0] ^= 1;
        assert!(decode_custody_history_v2(&malformed).is_err());
        assert!(decode_custody_history_v2(&encoded[..encoded.len()-1]).is_err());
        assert!(decode_custody_history_v2(&[]).is_err());
        let mut invalid = witness.clone(); invalid.approval_index = invalid.steps.len() as u32;
        assert!(encode_custody_history_v2(&invalid).is_err());
        invalid = witness; invalid.approval_transaction = bitcoin::Txid::all_zeros();
        assert!(encode_custody_history_v2(&invalid).is_err());
        assert_eq!(assembled.checked_statement(&redemption_domain,fixture_verifier_address(),&confirmed,
            confirmations.state(),confirmations.anchor(),1).unwrap(),journal);
        history.push(crate::conversion_parent_link_v3::tests::successor_fixture(history.last().unwrap()));
        let verifier = history_verifier(&history);
        let (assembled, confirmed) = fresh_cursor().finish_history(&history,approval_index,
            approval_transaction,&verifier).unwrap();
        verifier.assert_consumed();
        let destination = history.last().unwrap();
        assembled.checked_statement(&redemption_domain,fixture_verifier_address(),&confirmed,
            destination.parent.terminal_selected_state.commitment().unwrap(),
            destination.parent.terminal_selected_state.tip.block_hash.to_byte_array(),2).unwrap();
        assert!(assembled.checked_statement(&redemption_domain,fixture_verifier_address(),&confirmed,
            confirmations.state(),confirmations.anchor(),2).is_err());
        history.swap(0,1);
        assert!(fresh_cursor().finish_history(&history,approval_index,approval_transaction,
            &history_verifier(&history)).is_err());
        history.swap(0,1);
        let verifier = history_verifier(&history);
        history[0].parent.checkpoint_receipt.proof_marker.push(99);
        assert!(fresh_cursor().finish_history(&history,approval_index,approval_transaction,&verifier).is_err());
        history[0].parent.checkpoint_receipt.proof_marker.pop();
        assert!(fresh_cursor().finish_history(&history,approval_index,bitcoin::Txid::all_zeros(),
            &history_verifier(&history)).is_err());
        assert!(fresh_cursor().finish_history(&history,history.len(),approval_transaction,
            &history_verifier(&history)).is_err());
        let mut approved_m6 = confirmations.approval().approval().m6id.to_byte_array();
        approved_m6.reverse();
        assert_eq!(journal,crate::custody_redemption_statement_v2::encode_redemption_statement_v2(
            &redemption_domain,bound.burn(),approved_m6,bound.checkpoint(),confirmations.state()));
        assert!(bound.checked_statement(&redemption_domain,[18;20],&confirmations,
            confirmations.state(),confirmations.anchor(),1).is_err());
        assert!(bound.checked_statement(&redemption_domain,fixture_verifier_address(),&confirmations,
            confirmations.state(),confirmations.anchor(),2).is_err());
        assert!(bound.checked_statement(&redemption_domain,fixture_verifier_address(),&unrelated,
            unrelated.state(),unrelated.anchor(),1).is_err());
        let stale = crate::conversion_parent_link_v3::tests::authenticated_checkpoint_approval_fixture(
            custody,frozen);
        assert!(bound.require_approval(&stale,stale.binding_commitment()).is_err());
        let mut wrong_custody = custody; wrong_custody[0] ^= 1;
        let substituted = crate::conversion_parent_link_v3::tests::authenticated_checkpoint_approval_fixture(
            wrong_custody,bound.checkpoint());
        assert!(bound.require_approval(&substituted,substituted.binding_commitment()).is_err());
        assert!(bound.require_approval(&approval,[0;32]).is_err());
        assert!(matches!(extract_domain_bound_executed_burn_v2(&redemption_domain,[18;20],custody,
            &joined_state,1,0),Err(ExecutedCustodyBurnErrorV2::Domain)));
        assert!(extract_domain_bound_executed_burn_v2(&redemption_domain,fixture_verifier_address(),custody,
            &joined_state,0,0).is_err());
        assert!(extract_domain_bound_executed_burn_v2(&redemption_domain,fixture_verifier_address(),custody,
            &joined_state,1,99).is_err());
        let mut wrong_domain = redemption_domain.clone();
        wrong_domain.elements_genesis_display[0] ^= 1;
        wrong_domain.custody_id = wrong_domain.derive_custody_id(fixture_verifier_address());
        assert!(matches!(extract_domain_bound_executed_burn_v2(&wrong_domain,fixture_verifier_address(),wrong_domain.custody_id,
            &joined_state,1,0),Err(ExecutedCustodyBurnErrorV2::Genesis)));
        assert_eq!(verified_child.custody_burn_v2(1,0,display_asset,custody,[9;20],100).unwrap(),expected_checkpoint_burn);
        let mut wrong_asset = display_asset; wrong_asset[0] ^= 1;
        assert!(matches!(verified_child.custody_burn_v2(1,0,wrong_asset,custody,[9;20],100),
            Err(CommittedBurnError::AssetBinding)));
        assert_ne!(expected_checkpoint_burn.burn_id,burn.burn_id);
        // Parent authentication must not authorize a different custody domain or scale.
        assert!(verified_child.custody_burn_v2(1,0,display_asset,[8;32],[9;20],100).is_err());
        assert!(verified_child.custody_burn_v2(1,0,display_asset,custody,[9;20],101).is_err());
        crate::child_execution_guest_v4::check_custody_checkpoint_extraction_fixture(
            joined_state, &redemption_domain, fixture_verifier_address(), custody);
        assert!(matches!(joined(&elements::encode::serialize(&block),&parent),Err(ParentBoundChildError::State(_))));
        let mut rejected_parent = parent.clone(); rejected_parent.parent.checkpoint_receipt.proof_marker.push(99);
        assert!(matches!(joined(&raw,&rejected_parent),Err(ParentBoundChildError::Parent(_))));
        let wrong_genesis = FullElementsInputVerifierV2::with_rules(BlockHash::from_byte_array([99;32]),input_rules);
        assert!(matches!(execute_bound(&checkpoint,&wrong_genesis),Err(ChildStateError::InputVerifierBinding)));
        let mut wrong_rules = input_rules; wrong_rules.csv = !wrong_rules.csv;
        let wrong_rules = FullElementsInputVerifierV2::with_rules(
            BlockHash::from_byte_array(checkpoint.genesis_internal),wrong_rules);
        assert!(matches!(execute_bound(&checkpoint,&wrong_rules),Err(ChildStateError::InputVerifierBinding)));
        let mut wrong_simplicity = input_rules; wrong_simplicity.simplicity_active = !wrong_simplicity.simplicity_active;
        let wrong_simplicity = FullElementsInputVerifierV2::with_rules(
            BlockHash::from_byte_array(checkpoint.genesis_internal),wrong_simplicity);
        assert!(matches!(execute_bound(&checkpoint,&wrong_simplicity),Err(ChildStateError::InputVerifierBinding)));
        let policy_defaults = FullElementsInputVerifierV2::new(BlockHash::from_byte_array(checkpoint.genesis_internal));
        assert!(matches!(execute_bound(&checkpoint,&policy_defaults),Err(ChildStateError::InputVerifierBinding)));
        let mut substituted = checkpoint.clone();
        substituted.roots.utxo_root.aggregate.count += 1;
        assert!(matches!(execute_checkpoint(&substituted),Err(ChildStateError::Checkpoint(_))));
        substituted = checkpoint.clone(); substituted.history_commitment[0] ^= 1;
        assert!(matches!(execute_checkpoint(&substituted),Err(ChildStateError::Checkpoint(_))));
        assert_eq!(checked.custody_burn_v2(1,0,display_asset,custody,[9;20],100).unwrap(),burn);
        assert!(matches!(execute(&block,&omitted),Err(ChildStateError::Transaction {index:1,..})));
        let mut changed = block.clone(); changed.header.time += 1;
        assert!(matches!(execute(&changed,&ew),Err(ChildStateError::Authorization)));
        let mut inflated = block.clone(); inflated.txdata[1] = inflation;
        inflated.header.merkle_root = elements_transaction_merkle_root_v2(&inflated.txdata).unwrap();
        sign(&mut inflated);
        assert!(matches!(execute(&inflated,&ew),Err(ChildStateError::Transaction {index:1,..})));
        let mut unauthorized = block.clone(); unauthorized.txdata[1] = unsigned;
        unauthorized.header.merkle_root = elements_transaction_merkle_root_v2(&unauthorized.txdata).unwrap();
        sign(&mut unauthorized);
        assert!(matches!(execute(&unauthorized,&ew),Err(ChildStateError::Transaction {
            index:1,error:ElementsStateErrorV2::AuthorizationConsensus })));
    }
    #[test]
    fn burn_id_matches_independent_packed_sha256_vector() {
        // Independently computed with Node crypto over the Solidity packed
        // domain || custody || genesis || display-txid || uint32-BE index.
        let hex = "8dbc7ac653b153af8bd8496868f20fce1b97c743c16bbbed9bbe92240b65746b";
        let expected: Vec<u8> = (0..64).step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
        let actual = burn_id([1;32],[2;32],[3;32],0x01020304);
        assert_eq!(actual.as_slice(), expected);
        for altered in [burn_id([4;32],[2;32],[3;32],0x01020304),
            burn_id([1;32],[4;32],[3;32],0x01020304),
            burn_id([1;32],[2;32],[4;32],0x01020304),
            burn_id([1;32],[2;32],[3;32],0x04030201)] {
            assert_ne!(actual, altered);
        }
    }
    #[test]
    fn v2_extraction_binds_custody_asset_scale_and_recipient() {
        let (mut tx, mut genesis) = crate::native_withdrawal_extraction_v3::tests::fixture();
        genesis.reverse();
        let confidential::Asset::Explicit(asset) = tx.output[0].asset else { panic!() };
        let mut asset = asset.into_inner().to_byte_array(); asset.reverse();
        let mut script = tx.output[0].script_pubkey.as_bytes().to_vec();
        let custody: Hash32 = script[7..39].try_into().unwrap();
        let verify = |t: &Transaction, c, a, v, scale| extract_custody_burn_v2(t,0,genesis,a,c,v,scale);
        assert!(verify(&tx,custody,asset,[9;20],100).is_err());
        script[6] = 2; tx.output[0].script_pubkey = elements::Script::from(script);
        let burn = verify(&tx,custody,asset,[9;20],100).unwrap();
        assert_eq!(burn.amount_micro,777000);
        assert!(verify(&tx,[8;32],asset,[9;20],100).is_err());
        assert!(verify(&tx,custody,[8;32],[9;20],100).is_err());
        assert!(verify(&tx,custody,asset,burn.recipient,100).is_err());
        for scale in [0,1,99,u64::MAX] { assert!(verify(&tx,custody,asset,[9;20],scale).is_err()); }
        assert!(extract_custody_burn_v2(&tx,99,genesis,asset,custody,[9;20],100).is_err());
    }
}
