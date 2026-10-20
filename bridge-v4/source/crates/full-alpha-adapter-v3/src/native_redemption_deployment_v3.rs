//! Initial deployment/output linkage, not a redemption-availability proof.
//! The caller must separately authenticate inclusion and current checkpoint
//! membership, execute the covenant, and prove successor lineage. This check
//! must not be applied to later successors as though they were initial outputs.
use ecx_full_consensus_validator_v2::elements_v2::{
    verify_elements_economic_leaf_v2, ElementsEconomicClassificationV2,
    ElementsEconomicLeafV2, ElementsLiveEconomicRoleV2,
};
use elements::{encode, Transaction};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentLinkErrorV3 { Encoding, Outpoint, Output, Economics }

/// Authenticate an economic leaf to the exact native checkpoint returned by a
/// verified source receipt. Passing a witness-computed expected commitment is
/// not authentication. This verifies membership, not covenant spendability.
pub fn verify_native_redemption_membership_v3(
    checkpoint: &crate::child_execution_state_v3::ChildExecutionCheckpointV3,
    expected_checkpoint: [u8; 32],
    accounting: &crate::native_conversion_accounting_v3::ConversionAccountingBindingV3,
    expected_accounting: [u8; 32],
    leaf: &ElementsEconomicLeafV2,
    utxo_path: &ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
    economic_path: &ecx_full_consensus_validator_v2::elements_v2::ElementsSparseEconomicPathV2,
) -> Result<(), NativeMembershipErrorV3> {
    use ecx_full_consensus_validator_v2::elements_v2::{
        elements_sparse_utxo_root_from_path_v2, elements_utxo_leaf_node_v2,
        elements_sparse_economic_root_from_path_v2,
    };
    use NativeMembershipErrorV3::*;
    checkpoint.require_frozen(expected_checkpoint).map_err(|_| Binding)?;
    accounting.require_frozen(expected_accounting).map_err(|_| Binding)?;
    if checkpoint.genesis_internal != accounting.child_genesis_internal
        || checkpoint.configuration_commitment != accounting.child_configuration_commitment
        || checkpoint.roots.utxo_root.aggregate.count != checkpoint.roots.economic_root.aggregate.count
        || leaf.utxo.creation_height > checkpoint.height {
        return Err(Binding);
    }
    let economic = verify_elements_economic_leaf_v2(leaf, accounting.classification)
        .map_err(|_| Opening)?;
    if elements_sparse_utxo_root_from_path_v2(leaf.utxo.outpoint,
        elements_utxo_leaf_node_v2(&leaf.utxo), utxo_path).map_err(|_| Membership)?
        != checkpoint.roots.utxo_root
        || elements_sparse_economic_root_from_path_v2(leaf.utxo.outpoint,
            economic, economic_path).map_err(|_| Membership)? != checkpoint.roots.economic_root {
        return Err(Membership);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeMembershipErrorV3 { Binding, Opening, Membership }

/// Verify both exact initial outputs, including their serialized witnesses and
/// actual confidential openings/rangeproofs. `classification` must be obtained
/// from the independently frozen accounting binding, not selected by a witness.
pub fn verify_initial_redemption_outputs_v3(
    transaction_bytes: &[u8],
    inventory: &ElementsEconomicLeafV2,
    reserve: &ElementsEconomicLeafV2,
    classification: ElementsEconomicClassificationV2,
) -> Result<(), DeploymentLinkErrorV3> {
    use DeploymentLinkErrorV3::*;
    if transaction_bytes.is_empty() || transaction_bytes.len() > 4 * 1024 * 1024 {
        return Err(Encoding);
    }
    let tx: Transaction = encode::deserialize(transaction_bytes).map_err(|_| Encoding)?;
    if encode::serialize(&tx) != transaction_bytes { return Err(Encoding); }
    if inventory.utxo.outpoint == reserve.utxo.outpoint { return Err(Outpoint); }
    let txid = tx.txid();
    for leaf in [inventory, reserve] {
        if leaf.utxo.outpoint.txid != txid { return Err(Outpoint); }
        let output = tx.output.get(leaf.utxo.outpoint.vout as usize).ok_or(Outpoint)?;
        if output != &leaf.utxo.output { return Err(Output); }
        verify_elements_economic_leaf_v2(leaf, classification).map_err(|_| Economics)?;
    }
    if inventory.role != ElementsLiveEconomicRoleV2::RedemptionInventory
        || reserve.role != ElementsLiveEconomicRoleV2::RedeemableReserve
        || inventory.asset_id != classification.base_asset_id
        || reserve.asset_id != classification.policy_asset_id {
        return Err(Economics);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{hashes::{sha256, Hash}, confidential::{Asset, Value, Nonce},
        AssetId, LockTime, OutPoint, Script, TxOut, TxOutWitness};
    use ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2;

    fn fixture() -> (Vec<u8>, ElementsEconomicLeafV2, ElementsEconomicLeafV2, ElementsEconomicClassificationV2) {
        let scripts = [Script::from(vec![0x51]), Script::from(vec![0x52])];
        let outputs = (0..2).map(|i| TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array([i as u8 + 1;32])),
            value: Value::Explicit(100), nonce: Nonce::Null,
            script_pubkey: scripts[i].clone(), witness: TxOutWitness::default(),
        }).collect();
        let tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![], output: outputs };
        let leaf = |i: usize| ElementsEconomicLeafV2 {
            utxo: ElementsUtxoLeafV2 {
                outpoint: OutPoint { txid: tx.txid(), vout: i as u32 },
                output: tx.output[i].clone(), creation_height: 1, creation_parent_mtp: 1,
                coinbase: false, created_by_issuance: false, created_by_pegin: false,
            }, asset_id: [i as u8 + 1;32], amount: 100,
            asset_blinding_factor: [0;32], value_blinding_factor: [0;32],
            role: if i == 0 { ElementsLiveEconomicRoleV2::RedemptionInventory }
                  else { ElementsLiveEconomicRoleV2::RedeemableReserve },
        };
        (encode::serialize(&tx), leaf(0), leaf(1), ElementsEconomicClassificationV2 {
            base_asset_id: [1;32], policy_asset_id: [2;32],
            redemption_inventory_script_sha256: sha256::Hash::hash(scripts[0].as_bytes()).to_byte_array(),
            reserve_script_sha256: sha256::Hash::hash(scripts[1].as_bytes()).to_byte_array(),
        })
    }

    #[test]
    fn exact_initial_outputs_link() {
        let (tx, i, r, c) = fixture();
        assert_eq!(verify_initial_redemption_outputs_v3(&tx, &i, &r, c), Ok(()));
    }

    #[test]
    fn native_membership_binds_checkpoint_accounting_and_both_trees() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        use crate::{child_execution_state_v3::ChildExecutionCheckpointV3,
            native_conversion_accounting_v3::ConversionAccountingBindingV3,
            native_withdrawal_accumulator_v3::WithdrawalAccumulator};
        let (_, leaf, _, classification) = fixture();
        let mut up = ElementsSparseUtxoPathV2 { siblings: vec![] };
        let mut ep = ElementsSparseEconomicPathV2 { siblings: vec![] };
        let mut u = canonical_empty_elements_utxo_leaf_v2();
        let mut e = canonical_empty_elements_economic_leaf_v2();
        for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
            up.siblings.push(u); ep.siblings.push(e);
            u = elements_sparse_utxo_parent_v2(u,u).unwrap();
            e = elements_sparse_economic_parent_v2(e,e).unwrap();
        }
        let accounting = ConversionAccountingBindingV3 {
            child_genesis_internal: [1;32], child_configuration_commitment: [2;32],
            classification, quote_atoms_per_whole_base: 100_000_000,
        };
        let cp = ChildExecutionCheckpointV3 {
            genesis_internal: [1;32], configuration_commitment: [2;32],
            tip_internal: [3;32], height: 1, history_commitment: [4;32],
            spent_claims_root: [5;32], withdrawals: WithdrawalAccumulator::empty(),
            roots: ElementsTransactionStateRootsV2 {
                utxo_root: elements_sparse_utxo_root_from_path_v2(leaf.utxo.outpoint,
                    elements_utxo_leaf_node_v2(&leaf.utxo), &up).unwrap(),
                economic_root: elements_sparse_economic_root_from_path_v2(leaf.utxo.outpoint,
                    verify_elements_economic_leaf_v2(&leaf, classification).unwrap(), &ep).unwrap(),
            },
        };
        let expected = cp.commitment().unwrap();
        let ab = accounting.commitment().unwrap();
        let verify = |cp: &ChildExecutionCheckpointV3, leaf: &ElementsEconomicLeafV2,
            up: &ElementsSparseUtxoPathV2, ep: &ElementsSparseEconomicPathV2|
            verify_native_redemption_membership_v3(cp, expected, &accounting, ab, leaf, up, ep);
        assert_eq!(verify(&cp, &leaf, &up, &ep), Ok(()));
        let mut changed = cp.clone(); changed.history_commitment = [9;32];
        assert_eq!(verify(&changed, &leaf, &up, &ep), Err(NativeMembershipErrorV3::Binding));
        let mut changed = leaf.clone(); changed.utxo.creation_parent_mtp += 1;
        assert_eq!(verify(&cp, &changed, &up, &ep), Err(NativeMembershipErrorV3::Membership));
        let mut changed = leaf.clone(); changed.amount += 1;
        assert_eq!(verify(&cp, &changed, &up, &ep), Err(NativeMembershipErrorV3::Opening));
        let mut bad_up = up.clone(); bad_up.siblings.pop();
        assert!(verify(&cp, &leaf, &bad_up, &ep).is_err());
        let mut bad_ep = ep.clone(); bad_ep.siblings[0].hash = [9;32];
        assert!(verify(&cp, &leaf, &up, &bad_ep).is_err());
        let mut future_leaf = leaf.clone(); future_leaf.utxo.creation_height = cp.height + 1;
        assert_eq!(verify(&cp, &future_leaf, &up, &ep), Err(NativeMembershipErrorV3::Binding));
        let mut wrong_network = cp.clone(); wrong_network.genesis_internal = [9;32];
        // Even a caller who supplies the altered checkpoint's own hash cannot
        // cross the independently pinned accounting network binding.
        assert_eq!(verify_native_redemption_membership_v3(&wrong_network,
            wrong_network.commitment().unwrap(), &accounting, ab, &leaf, &up, &ep),
            Err(NativeMembershipErrorV3::Binding));
        let mut wrong_policy = cp.clone(); wrong_policy.configuration_commitment = [9;32];
        assert_eq!(verify_native_redemption_membership_v3(&wrong_policy,
            wrong_policy.commitment().unwrap(), &accounting, ab, &leaf, &up, &ep),
            Err(NativeMembershipErrorV3::Binding));
        let mut wrong_leaf = leaf.clone(); wrong_leaf.utxo.outpoint.vout += 1;
        assert_eq!(verify(&cp, &wrong_leaf, &up, &ep), Err(NativeMembershipErrorV3::Membership));
        assert_eq!(verify_native_redemption_membership_v3(&cp, expected, &accounting,
            [0;32], &leaf, &up, &ep), Err(NativeMembershipErrorV3::Binding));
    }

    #[test]
    fn altered_deployment_outpoints_openings_roles_and_scripts_reject() {
        let (tx, i, r, c) = fixture();
        for mutation in 0..7 {
            let mut altered = i.clone();
            match mutation {
                0 => altered.utxo.outpoint.txid = elements::Txid::from_byte_array([9;32]),
                1 => altered.utxo.outpoint.vout = 9,
                2 => altered.utxo.outpoint = r.utxo.outpoint,
                3 => altered.amount += 1,
                4 => altered.role = ElementsLiveEconomicRoleV2::OutstandingBase,
                5 => altered.asset_id = [9;32],
                _ => altered.utxo.output.script_pubkey = Script::from(vec![0x53]),
            }
            assert!(verify_initial_redemption_outputs_v3(&tx, &altered, &r, c).is_err());
        }
        let mut trailing = tx;
        trailing.push(0);
        assert_eq!(verify_initial_redemption_outputs_v3(&trailing, &i, &r, c), Err(DeploymentLinkErrorV3::Encoding));
    }
}
