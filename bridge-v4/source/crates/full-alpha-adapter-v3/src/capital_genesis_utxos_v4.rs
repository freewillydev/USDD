//! Activation coin membership, against an independently authenticated UTXO root.
//! Composes issuance, empty-state derivation and output membership. The enclosing
//! consensus relation must authenticate the configuration, UTXO root and parent time.
use ecx_full_consensus_validator_v2::elements_v2::{
    elements_sparse_utxo_root_from_path_v2, elements_utxo_leaf_node_v2,
    ElementsSparseUtxoNodeV2, ElementsSparseUtxoPathV2, ElementsUtxoLeafV2,
};
use elements::{OutPoint, TxOut};

#[cfg(test)]
#[path = "native_bond_inbox_test_configuration.rs"]
mod test_configuration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisCoinError { Context, Coin, Membership, Order, Issuance, State }

/// Frozen bindings outside the physical exchange configuration. These must be
/// authenticated by the enclosing release/consensus relation, not witness-selected.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisStateBindings {
    pub public_state_domain: [u8;32],
    pub state_node_domain: [u8;32],
    pub journal_domain: [u8;32],
    pub transition_cmr: [u8;32],
    pub activation_cmr: [u8;32],
    pub internal_key: [u8;32],
    pub order_receipts_root: [u8;32],
    pub availability_root: [u8;32],
    pub mark_price_atoms: u64,
    #[serde(with = "crate::native_child_block_v3::transaction_witness_wire::outpoint")]
    pub state_outpoint: OutPoint,
    pub child_genesis: [u8;32],
    pub state_utxo_root: [u8;32],
    pub activation_height: u32,
    pub transition_program_id: [u8;32],
}

impl GenesisStateBindings {
    /// The expected digest must come from the reviewed release, not the witness.
    pub fn commitment(&self) -> [u8;32] {
        let mut bytes = vec![1];
        for hash in [self.public_state_domain, self.state_node_domain, self.journal_domain,
            self.transition_cmr, self.activation_cmr, self.internal_key,
            self.order_receipts_root, self.availability_root, self.child_genesis,
            self.state_utxo_root, self.transition_program_id] { bytes.extend_from_slice(&hash); }
        bytes.extend_from_slice(&self.activation_height.to_be_bytes());
        bytes.extend_from_slice(&self.mark_price_atoms.to_be_bytes());
        bytes.extend_from_slice(&elements::encode::serialize(&self.state_outpoint));
        crate::tagged_hash("ECX/alpha-genesis-state-bindings/v1", &bytes)
    }
}

/// Derive the empty public state at the coin's authenticated creation height,
/// construct its exact covenant, then verify issuance/linkage and both coins.
/// Nonzero time alone is not authentication: the enclosing Alpha replay must
/// supply its verified parent median time and post-execution activation UTXO
/// root (the native node checks its coin view after applying block transactions).
pub fn verify_derived_activation_coins(
    root: ElementsSparseUtxoNodeV2, activation_height: u32, parent_mtp: u64,
    configuration: &ecx_protocol_core::FrozenConfigurationV2,
    bindings: &GenesisStateBindings,
    deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
    genesis: &elements::Transaction,
    inventory: ActivationCoinWitness<'_>, state: ActivationCoinWitness<'_>,
) -> Result<ecx_proof_core::CovenantPublicStateV2, GenesisCoinError> {
    verify_derived_activation_coins_inner(root, activation_height, parent_mtp,
        configuration, bindings, deployment, genesis, inventory, state, false, None)
}

/// Public-only deployment lane. Never falls back to confidential V2 issuance.
pub fn verify_derived_public_activation_coins(
    root: ElementsSparseUtxoNodeV2, activation_height: u32, parent_mtp: u64,
    configuration: &ecx_protocol_core::FrozenConfigurationV2,
    bindings: &GenesisStateBindings,
    deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
    genesis: &elements::Transaction,
    inventory: ActivationCoinWitness<'_>, state: ActivationCoinWitness<'_>,
) -> Result<ecx_proof_core::CovenantPublicStateV2, GenesisCoinError> {
    verify_derived_activation_coins_inner(root, activation_height, parent_mtp,
        configuration, bindings, deployment, genesis, inventory, state, true, None)
}

/// Checkpoint-initialized public lane. The token comes from authenticated history
/// and an independently pinned reviewed record, never from raw witness time.
pub fn verify_checkpoint_public_activation_coins(
    root: ElementsSparseUtxoNodeV2, activation_height: u32, parent_mtp: u64,
    configuration: &ecx_protocol_core::FrozenConfigurationV2,
    bindings: &GenesisStateBindings,
    deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
    genesis: &elements::Transaction,
    inventory: ActivationCoinWitness<'_>, state: ActivationCoinWitness<'_>,
    initialization: crate::genesis_initialization_v2::CheckedGenesisInitialization,
) -> Result<ecx_proof_core::CovenantPublicStateV2, GenesisCoinError> {
    verify_derived_activation_coins_inner(root, activation_height, parent_mtp,
        configuration, bindings, deployment, genesis, inventory, state, true, Some(initialization))
}

fn verify_derived_activation_coins_inner(
    root: ElementsSparseUtxoNodeV2, activation_height: u32, parent_mtp: u64,
    configuration: &ecx_protocol_core::FrozenConfigurationV2,
    bindings: &GenesisStateBindings,
    deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
    genesis: &elements::Transaction,
    inventory: ActivationCoinWitness<'_>, state: ActivationCoinWitness<'_>,
    public_only: bool,
    initialization: Option<crate::genesis_initialization_v2::CheckedGenesisInitialization>,
) -> Result<ecx_proof_core::CovenantPublicStateV2, GenesisCoinError> {
    let domains = [bindings.public_state_domain, bindings.state_node_domain, bindings.journal_domain];
    if domains.contains(&[0;32]) || domains[0] == domains[1]
        || domains[0] == domains[2] || domains[1] == domains[2]
        || parent_mtp == 0 || bindings.child_genesis == [0;32]
        || activation_height != bindings.activation_height
        || !crate::alpha_sp1_program_id_is_canonical_v3(bindings.transition_program_id)
        || bindings.state_utxo_root == [0;32] || bindings.state_outpoint.vout != 0
        || bindings.state_outpoint.txid != genesis.txid() {
        return Err(GenesisCoinError::Context);
    }
    configuration.validate().map_err(|_| GenesisCoinError::Context)?;
    let genesis_output = genesis.output.first().ok_or(GenesisCoinError::Coin)?;
    if ecx_elements_settlement::finite_genesis::state_utxo_root(
        bindings.child_genesis, bindings.state_outpoint, genesis_output,
    ) != bindings.state_utxo_root {
        return Err(GenesisCoinError::State);
    }
    let (initial_height, initial_mtp) = match initialization {
        Some(initial) if initial.height() < u64::from(state.leaf.creation_height)
            && initial.parent_mtp() <= parent_mtp => (initial.height(), initial.parent_mtp()),
        Some(_) => return Err(GenesisCoinError::Context),
        None => (u64::from(state.leaf.creation_height), parent_mtp),
    };
    let public_state = ecx_proof_core::CovenantPublicStateV2::derive_empty_genesis(
        configuration, initial_height, initial_mtp,
        bindings.mark_price_atoms, bindings.order_receipts_root, bindings.availability_root,
    ).map_err(|_| GenesisCoinError::State)?;
    let script = ecx_elements_settlement::finite_genesis::derive_finite_genesis_script(
        public_state.state_hash(bindings.public_state_domain), bindings.state_node_domain,
        bindings.transition_cmr, bindings.activation_cmr, bindings.internal_key,
    ).map_err(|_| GenesisCoinError::State)?;
    let asset = ecx_elements_settlement::FrozenBondAssetV2 {
        version: ecx_elements_settlement::FrozenBondAssetV2::VERSION,
        asset_id: configuration.bond_asset_id,
        inventory_vault_script_sha256: configuration.bond_inventory_script_sha256,
        redemption_queue_script_sha256: configuration.bond_redemption_queue_script_sha256,
        reissuance_token_burn_script_sha256: configuration.destroyed_reissuance_token_script_sha256,
    };
    verify_issued_activation_coins_inner(root, activation_height, deployment, &asset,
        configuration.bond_deployment_commitment, genesis,
        elements::AssetId::from_byte_array(configuration.base.state_authority_asset_id),
        &script.script, inventory, state, public_only)?;
    Ok(public_state)
}

pub struct ActivationCoinWitness<'a> {
    pub leaf: &'a ElementsUtxoLeafV2,
    pub path: &'a ElementsSparseUtxoPathV2,
}

/// Owned guest input, not authenticated evidence until the enclosing executor
/// verifies this path against the post-block checkpoint root.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedActivationCoinWitnessV4 {
    #[serde(with = "crate::native_child_block_v3::transaction_witness_wire::leaf")]
    pub leaf: ElementsUtxoLeafV2,
    pub path: ElementsSparseUtxoPathV2,
}
impl OwnedActivationCoinWitnessV4 {
    pub fn as_witness(&self) -> ActivationCoinWitness<'_> {
        ActivationCoinWitness { leaf: &self.leaf, path: &self.path }
    }
}

/// Physical authority and singleton check. `expected_script` must be derived
/// from the frozen empty-state configuration, creation height and authenticated
/// parent MTP by the enclosing verifier, never taken from the transaction.
pub fn verify_genesis_authority_outputs(
    deployment: &elements::Transaction, genesis: &elements::Transaction,
    authority_asset: elements::AssetId, expected_script: &elements::Script,
) -> Result<(), GenesisCoinError> {
    use elements::confidential::{Asset, Nonce, Value};
    if authority_asset.into_inner().to_byte_array() == [0;32]
        || authority_script_is_unspendable(expected_script) {
        return Err(GenesisCoinError::Context);
    }
    let source = deployment.output.get(2).ok_or(GenesisCoinError::Coin)?;
    let state = genesis.output.first().ok_or(GenesisCoinError::Coin)?;
    for output in [source, state] {
        if output.asset != Asset::Explicit(authority_asset)
            || output.value != Value::Explicit(1) || output.nonce != Nonce::Null {
            return Err(GenesisCoinError::Coin);
        }
    }
    if authority_script_is_unspendable(&source.script_pubkey)
        || &state.script_pubkey != expected_script {
        return Err(GenesisCoinError::Coin);
    }
    Ok(())
}

// Native CScript::IsUnspendable in Elements mode also prunes oversized
// scripts and empty fee scripts. Do not accept an authority the node prunes.
fn authority_script_is_unspendable(script: &elements::Script) -> bool {
    script.is_empty() || script.is_op_return() || script.len() > 10_000
}

/// Verify the real confidential issuance before checking its inventory's
/// membership. The frozen deployment commitment must come from the enclosing
/// trusted configuration. This is still only the issuance/linkage/membership
/// portion of genesis: callers must independently derive and verify its state
/// covenant, authority asset, empty state and authenticated parent context.
pub fn verify_issued_activation_coins(
    root: ElementsSparseUtxoNodeV2, activation_height: u32,
    deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
    frozen_asset: &ecx_elements_settlement::FrozenBondAssetV2,
    expected_deployment_commitment: [u8; 32],
    genesis: &elements::Transaction,
    authority_asset: elements::AssetId, expected_genesis_script: &elements::Script,
    inventory: ActivationCoinWitness<'_>, state: ActivationCoinWitness<'_>,
) -> Result<(ecx_elements_settlement::VerifiedFrozenBondDeploymentV2, (u32, u32)), GenesisCoinError> {
    verify_issued_activation_coins_inner(root, activation_height, deployment, frozen_asset,
        expected_deployment_commitment, genesis, authority_asset, expected_genesis_script,
        inventory, state, false)
}

fn verify_issued_activation_coins_inner(
    root: ElementsSparseUtxoNodeV2, activation_height: u32,
    deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
    frozen_asset: &ecx_elements_settlement::FrozenBondAssetV2,
    expected_deployment_commitment: [u8; 32],
    genesis: &elements::Transaction,
    authority_asset: elements::AssetId, expected_genesis_script: &elements::Script,
    inventory: ActivationCoinWitness<'_>, state: ActivationCoinWitness<'_>,
    public_only: bool,
) -> Result<(ecx_elements_settlement::VerifiedFrozenBondDeploymentV2, (u32, u32)), GenesisCoinError> {
    if expected_deployment_commitment == [0; 32] {
        return Err(GenesisCoinError::Context);
    }
    let verified = if public_only {
        ecx_elements_settlement::public_deployment::verify_public_bond_deployment(deployment, frozen_asset)
    } else {
        ecx_elements_settlement::verify_frozen_bond_deployment_v2(deployment, frozen_asset)
    }
        .map_err(|_| GenesisCoinError::Issuance)?;
    if verified.deployment_commitment != expected_deployment_commitment
        || verified.reissuance_token_burn_output_index == 2 {
        return Err(GenesisCoinError::Issuance);
    }
    let transaction: elements::Transaction = elements::encode::deserialize(&deployment.transaction)
        .map_err(|_| GenesisCoinError::Issuance)?;
    verify_genesis_authority_outputs(&transaction, genesis, authority_asset, expected_genesis_script)?;
    let heights = verify_activation_transaction_coins(root, activation_height,
        &transaction, verified.inventory_output_index, 2, genesis, 0, inventory, state)?;
    Ok((verified, heights))
}

fn check_coin(root: ElementsSparseUtxoNodeV2, activation_height: u32,
    witness: &ActivationCoinWitness<'_>, outpoint: OutPoint, output: &TxOut,
) -> Result<u32, GenesisCoinError> {
    if root.hash == [0; 32] || root.aggregate.count == 0 || activation_height == 0
        || activation_height >= 0x7fff_ffff {
        return Err(GenesisCoinError::Context);
    }
    let leaf = witness.leaf;
    if leaf.outpoint != outpoint || &leaf.output != output || leaf.creation_height == 0
        || leaf.creation_height >= activation_height || leaf.creation_height == 0x7fff_ffff {
        return Err(GenesisCoinError::Coin);
    }
    let derived = elements_sparse_utxo_root_from_path_v2(outpoint,
        elements_utxo_leaf_node_v2(leaf), witness.path).map_err(|_| GenesisCoinError::Membership)?;
    if derived != root { return Err(GenesisCoinError::Membership); }
    Ok(leaf.creation_height)
}

/// Exact deployment inventory and genesis singleton must coexist at the same
/// authenticated post-execution activation root. Expected outputs come from the verified
/// transactions, not RPC summaries. Both coins must precede the activation block.
pub fn verify_activation_coins(
    root: ElementsSparseUtxoNodeV2, activation_height: u32,
    inventory: ActivationCoinWitness<'_>, inventory_outpoint: OutPoint, inventory_output: &TxOut,
    state: ActivationCoinWitness<'_>, state_outpoint: OutPoint, state_output: &TxOut,
) -> Result<(u32, u32), GenesisCoinError> {
    if inventory_outpoint.txid == state_outpoint.txid { return Err(GenesisCoinError::Context); }
    let deployment_height = check_coin(root, activation_height, &inventory, inventory_outpoint, inventory_output)?;
    let genesis_height = check_coin(root, activation_height, &state, state_outpoint, state_output)?;
    if genesis_height < deployment_height { return Err(GenesisCoinError::Order); }
    Ok((deployment_height, genesis_height))
}

/// Bind membership to the actual candidate transactions. This is an additional
/// check after issuance and covenant verification, not a replacement for them.
/// In particular, neither transaction signatures nor the root's provenance are
/// established here.
pub fn verify_activation_transaction_coins(
    root: ElementsSparseUtxoNodeV2, activation_height: u32,
    deployment: &elements::Transaction, inventory_index: u32, authority_index: u32,
    genesis: &elements::Transaction, state_index: u32,
    inventory: ActivationCoinWitness<'_>, state: ActivationCoinWitness<'_>,
) -> Result<(u32, u32), GenesisCoinError> {
    if authority_index != 2 || state_index != 0 || inventory_index == authority_index
        || deployment.output.get(authority_index as usize).is_none()
        || genesis.input.first().map(|i| i.previous_output)
            != Some(OutPoint::new(deployment.txid(), authority_index))
        || genesis.input.iter().any(|i| i.has_issuance() || i.is_pegin()) {
        return Err(GenesisCoinError::Coin);
    }
    let inventory_output = deployment.output.get(inventory_index as usize)
        .ok_or(GenesisCoinError::Coin)?;
    let state_output = genesis.output.get(state_index as usize)
        .ok_or(GenesisCoinError::Coin)?;
    verify_activation_coins(root, activation_height,
        inventory, OutPoint::new(deployment.txid(), inventory_index), inventory_output,
        state, OutPoint::new(genesis.txid(), state_index), state_output)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use elements::hashes::Hash;
    use ecx_full_consensus_validator_v2::elements_v2::canonical_empty_elements_utxo_leaf_v2;

    // Build an actual two-leaf sparse tree, including depth-specific empty
    // subtrees. Both paths must reconstruct the identical hash AND count.
    pub(crate) fn pair_paths(a: &ElementsUtxoLeafV2, b: &ElementsUtxoLeafV2)
        -> (ElementsSparseUtxoNodeV2, ElementsSparseUtxoPathV2, ElementsSparseUtxoPathV2) {
        use ecx_full_consensus_validator_v2::elements_v2::{
            elements_sparse_utxo_key_v2, elements_sparse_utxo_parent_v2,
        };
        let ka = elements_sparse_utxo_key_v2(a.outpoint);
        let kb = elements_sparse_utxo_key_v2(b.outpoint);
        let bit = |k: [u8; 32], level: usize| (k[(255-level)/8] >> (level%8)) & 1;
        let split = (0..256).rev().find(|&i| bit(ka, i) != bit(kb, i)).unwrap();
        let mut empty = canonical_empty_elements_utxo_leaf_v2();
        let mut na = elements_utxo_leaf_node_v2(a);
        let mut nb = elements_utxo_leaf_node_v2(b);
        let mut pa = Vec::new(); let mut pb = Vec::new();
        for level in 0..256 {
            let sa = if level == split { nb } else { empty };
            let sb = if level == split { na } else { empty };
            pa.push(sa); pb.push(sb);
            na = if bit(ka, level) == 0 { elements_sparse_utxo_parent_v2(na, sa) }
                else { elements_sparse_utxo_parent_v2(sa, na) }.unwrap();
            nb = if bit(kb, level) == 0 { elements_sparse_utxo_parent_v2(nb, sb) }
                else { elements_sparse_utxo_parent_v2(sb, nb) }.unwrap();
            empty = elements_sparse_utxo_parent_v2(empty, empty).unwrap();
        }
        assert_eq!(na, nb); assert_eq!(na.aggregate.count, 2);
        (na, ElementsSparseUtxoPathV2 { siblings: pa }, ElementsSparseUtxoPathV2 { siblings: pb })
    }

    pub(crate) struct PublicActivationFixture {
        pub configuration: ecx_protocol_core::FrozenConfigurationV2,
        pub bindings: GenesisStateBindings,
        pub deployment: ecx_elements_settlement::FrozenBondDeploymentV2,
        pub genesis: elements::Transaction,
        pub root: ElementsSparseUtxoNodeV2,
        pub inventory: OwnedActivationCoinWitnessV4,
        pub state: OwnedActivationCoinWitnessV4,
        pub public: ecx_proof_core::CovenantPublicStateV2,
    }

    impl PublicActivationFixture {
        pub(crate) fn custody_root(&self, classification: ecx_full_consensus_validator_v2::elements_v2::ElementsCustodyClassificationV3)
            -> ecx_full_consensus_validator_v2::elements_v2::ElementsSparseCustodyNodeV3 {
            use ecx_full_consensus_validator_v2::elements_v2::*;
            let node=|utxo:&ElementsUtxoLeafV2| {
                let asset_id=utxo.output.asset.explicit().unwrap().into_inner().to_byte_array();
                verify_elements_custody_leaf_v3(&ElementsEconomicLeafV2 {
                    utxo:utxo.clone(),asset_id,amount:utxo.output.value.explicit().unwrap(),
                    asset_blinding_factor:[0;32],value_blinding_factor:[0;32],
                    role:if asset_id==classification.custody_asset_id {ElementsLiveEconomicRoleV2::OutstandingBase}
                        else {ElementsLiveEconomicRoleV2::Irrelevant},
                },classification).unwrap()
            };
            let ka=elements_sparse_utxo_key_v2(self.inventory.leaf.outpoint);
            let kb=elements_sparse_utxo_key_v2(self.state.leaf.outpoint);
            let bit=|k:[u8;32],level:usize| (k[(255-level)/8]>>(level%8))&1;
            let split=(0..256).rev().find(|&i|bit(ka,i)!=bit(kb,i)).unwrap();
            let (mut a,mut b)=(node(&self.inventory.leaf),node(&self.state.leaf));
            let mut empty=empty_elements_custody_leaf_v3();
            for level in 0..256 {
                let sa=if level==split {b} else {empty};
                let sb=if level==split {a} else {empty};
                a=if bit(ka,level)==0 {elements_custody_parent_v3(a,sa)} else {elements_custody_parent_v3(sa,a)}.unwrap();
                b=if bit(kb,level)==0 {elements_custody_parent_v3(b,sb)} else {elements_custody_parent_v3(sb,b)}.unwrap();
                empty=elements_custody_parent_v3(empty,empty).unwrap();
            }
            assert_eq!(a,b);assert_eq!(a.count,2);a
        }
    }

    // Local issuance fixture only; caller must independently authenticate the
    // checkpoint and execute the activation block. No live coin provenance.
    pub(crate) fn public_activation_fixture(child_genesis: [u8;32],
        creation_height: u32, activation_height: u32, parent_mtp: u64,
    ) -> PublicActivationFixture {
        checkpoint_activation_fixture(child_genesis, creation_height, activation_height,
            parent_mtp, creation_height, parent_mtp)
    }

    pub(crate) fn checkpoint_activation_fixture(child_genesis: [u8;32],
        creation_height: u32, activation_height: u32, parent_mtp: u64,
        initialization_height: u32, initialization_mtp: u64,
    ) -> PublicActivationFixture {
        use elements::confidential::{Asset, Value};
        let authority = elements::AssetId::from_byte_array([9;32]);
        let script = elements::Script::from(vec![0x51]);
        let burn_script = elements::Script::from(vec![0x6a]);
        let mut input = elements::TxIn::default();
        input.previous_output = OutPoint::new(elements::Txid::from_byte_array([13;32]),0);
        let entropy = [14;32];
        let mut issued = input.clone();
        issued.asset_issuance.asset_entropy = entropy;
        issued.asset_issuance.amount = Value::Explicit(ecx_elements_settlement::FrozenBondAssetV2::FIXED_SUPPLY_ATOMS);
        issued.asset_issuance.inflation_keys = Value::Explicit(1);
        let asset = ecx_elements_settlement::FrozenBondAssetV2 {
            version: ecx_elements_settlement::FrozenBondAssetV2::VERSION,
            asset_id: issued.issuance_ids().0.into_inner().to_byte_array(),
            inventory_vault_script_sha256: elements::hashes::sha256::Hash::hash(script.as_bytes()).to_byte_array(),
            redemption_queue_script_sha256: [15;32],
            reissuance_token_burn_script_sha256: elements::hashes::sha256::Hash::hash(burn_script.as_bytes()).to_byte_array(),
        };
        let output = TxOut {asset:Asset::Explicit(authority),value:Value::Explicit(1),
            script_pubkey:script.clone(),..TxOut::default()};
        let mut burn = output.clone();burn.script_pubkey=burn_script;
        let template = elements::Transaction {version:2,lock_time:elements::LockTime::ZERO,
            input:vec![input],output:vec![output.clone(),burn,output.clone()]};
        let (deployment, verified) = ecx_elements_settlement::public_deployment::compose_public_bond_deployment(
            template,0,0,1,entropy,&asset).unwrap();
        let transaction:elements::Transaction=elements::encode::deserialize(&deployment.transaction).unwrap();
        let mut input=elements::TxIn::default();input.previous_output=OutPoint::new(transaction.txid(),2);
        let genesis=elements::Transaction {version:2,lock_time:elements::LockTime::ZERO,
            input:vec![input],output:vec![output]};
        let inventory=ElementsUtxoLeafV2 {outpoint:OutPoint::new(transaction.txid(),0),
            output:transaction.output[0].clone(),creation_height,creation_parent_mtp:u32::try_from(parent_mtp).unwrap(),
            coinbase:false,created_by_issuance:true,created_by_pegin:false};
        let state=ElementsUtxoLeafV2 {outpoint:OutPoint::new(genesis.txid(),0),
            output:genesis.output[0].clone(),created_by_issuance:false,..inventory.clone()};
        let (root,pa,pb)=pair_paths(&inventory,&state);
        let check=|d:&ecx_elements_settlement::FrozenBondDeploymentV2,r,public_only| {
            verify_issued_activation_coins_inner(r,activation_height,d,&asset,verified.deployment_commitment,
                &genesis,authority,&script,ActivationCoinWitness {leaf:&inventory,path:&pa},
                ActivationCoinWitness {leaf:&state,path:&pb},public_only)
        };
        assert!(check(&deployment,root,true).is_ok());
        assert_eq!(check(&deployment,root,false).err(),Some(GenesisCoinError::Issuance));
        let mut wrong=deployment.clone();wrong.version=2;
        assert_eq!(check(&wrong,root,true).err(),Some(GenesisCoinError::Issuance));
        wrong=deployment.clone();wrong.inventory_value_blinding_factor=[1;32];
        assert_eq!(check(&wrong,root,true).err(),Some(GenesisCoinError::Issuance));
        let mut wrong_root=root;wrong_root.hash[0]^=1;
        assert_eq!(check(&deployment,wrong_root,true).err(),Some(GenesisCoinError::Membership));
        // Derive the real empty-state covenant with direct-price configuration;
        // all values remain synthetic, not production release bindings.
        let mut configuration=test_configuration::configuration();
        configuration.version=ecx_protocol_core::FrozenConfigurationV2::DIRECT_PRICE_VERSION;
        configuration.base.policy_asset_id=configuration.base.ecx_asset_id;
        configuration.base.oracle.ecx_satoshis_per_coin=ecx_protocol_core::PRICE_SCALE;
        configuration.base.oracle.usdd_usd_price_units=ecx_protocol_core::PRICE_SCALE;
        configuration.ecx_btc_conversion_program_id=[0;32];
        configuration.usdd_usd_conversion_program_id=[0;32];
        configuration.ecx_btc_redemption_covenant_commitment=[0;32];
        configuration.ecx_btc_source_checkpoint_commitment=[0;32];
        configuration.usdd_usd_redemption_covenant_commitment=[0;32];
        configuration.usdd_usd_source_checkpoint_commitment=[0;32];
        configuration.base.state_authority_asset_id=authority.into_inner().to_byte_array();
        configuration.bond_asset_id=asset.asset_id;
        configuration.bond_deployment_commitment=verified.deployment_commitment;
        configuration.bond_inventory_script_sha256=asset.inventory_vault_script_sha256;
        configuration.bond_redemption_queue_script_sha256=asset.redemption_queue_script_sha256;
        configuration.destroyed_reissuance_token_script_sha256=asset.reissuance_token_burn_script_sha256;
        configuration.validate().unwrap();
        let keypair=elements::secp256k1_zkp::Keypair::from_secret_key(
            &elements::secp256k1_zkp::Secp256k1::new(),
            &elements::secp256k1_zkp::SecretKey::from_slice(&[11;32]).unwrap());
        let mut bindings=GenesisStateBindings {
            public_state_domain:[1;32],state_node_domain:[2;32],journal_domain:[3;32],
            transition_cmr:[4;32],activation_cmr:[5;32],
            internal_key:elements::secp256k1_zkp::XOnlyPublicKey::from_keypair(&keypair).0.serialize(),
            order_receipts_root:[6;32],availability_root:[7;32],mark_price_atoms:3_000_000_000,
            state_outpoint:state.outpoint,child_genesis,state_utxo_root:[9;32],
            activation_height,transition_program_id:[1;32],
        };
        let public=ecx_proof_core::CovenantPublicStateV2::derive_empty_genesis(
            &configuration,u64::from(initialization_height),initialization_mtp,bindings.mark_price_atoms,bindings.order_receipts_root,
            bindings.availability_root).unwrap();
        let covenant=ecx_elements_settlement::finite_genesis::derive_finite_genesis_script(
            public.state_hash(bindings.public_state_domain),bindings.state_node_domain,
            bindings.transition_cmr,bindings.activation_cmr,bindings.internal_key).unwrap();
        let mut genesis=genesis.clone();genesis.output[0].script_pubkey=covenant.script;
        bindings.state_outpoint=OutPoint::new(genesis.txid(),0);
        bindings.state_utxo_root=ecx_elements_settlement::finite_genesis::state_utxo_root(
            bindings.child_genesis,bindings.state_outpoint,&genesis.output[0]);
        let mut state=state.clone();state.outpoint=bindings.state_outpoint;state.output=genesis.output[0].clone();
        let (root,pa,pb)=pair_paths(&inventory,&state);
        PublicActivationFixture { configuration, bindings, deployment, genesis, root,
            inventory:OwnedActivationCoinWitnessV4 {leaf:inventory,path:pa},
            state:OwnedActivationCoinWitnessV4 {leaf:state,path:pb}, public }
    }

    #[test]
    fn public_activation_fixture_binds_alpha_context() {
        let policy=crate::native_deposit_policy_v4::tests::policy();
        let fixture=public_activation_fixture(policy.child_genesis_internal,6,7,1_784_334_600);
        let verify=|f:&PublicActivationFixture,mtp| verify_derived_public_activation_coins(
            f.root,7,mtp,&f.configuration,&f.bindings,&f.deployment,&f.genesis,
            f.inventory.as_witness(),f.state.as_witness());
        assert_eq!(verify(&fixture,1_784_334_600).unwrap(),fixture.public);
        assert_eq!(fixture.bindings.child_genesis,policy.child_genesis_internal);
        assert_eq!(fixture.bindings.mark_price_atoms,3_000_000_000);
        assert!(verify(&fixture,1_784_334_601).is_err());
        let wire=bincode::serialize(&fixture.inventory).unwrap();
        let decoded:OwnedActivationCoinWitnessV4=bincode::deserialize(&wire).unwrap();
        assert_eq!(decoded,fixture.inventory);
        // The selected time is test data, not an authenticated parent record.
    }

    #[test]
    fn public_activation_requires_preexisting_confirmed_coins() {
        let policy = crate::native_deposit_policy_v4::tests::policy();
        let mtp = 1_784_334_600;
        // Each fixture has real sparse membership paths and a matching derived
        // genesis script. Rejection must not rely on a stale root or script.
        for (creation, activation, accepted) in [(6, 7, true), (7, 7, false), (8, 7, false)] {
            // Builder qualifies issuance membership before returning, so build
            // with a valid later height, then vary only the activation rule.
            let mut f = public_activation_fixture(policy.child_genesis_internal, creation, 9, mtp);
            f.bindings.activation_height = activation;
            let result = verify_derived_public_activation_coins(f.root, activation, mtp,
                &f.configuration, &f.bindings, &f.deployment, &f.genesis,
                f.inventory.as_witness(), f.state.as_witness());
            if accepted {
                assert_eq!(result.unwrap(), f.public);
            } else {
                assert!(matches!(result, Err(GenesisCoinError::Coin)));
            }
        }
    }

    #[test]
    fn public_activation_issuance_is_version_separated_and_checks_membership() {
        let PublicActivationFixture {configuration,bindings,deployment,genesis,root,
            inventory,state,public}=public_activation_fixture([8;32],7,8,100);
        let derive=|b:&GenesisStateBindings,mtp| verify_derived_public_activation_coins(
            root,8,mtp,&configuration,b,&deployment,&genesis,
            inventory.as_witness(),state.as_witness());
        assert_eq!(derive(&bindings,100).unwrap(),public);
        assert!(derive(&bindings,0).is_err());
        for field in 0..5 {
            let mut wrong=bindings.clone();
            match field {
                0=>wrong.transition_cmr[0]^=1,
                1=>wrong.activation_cmr[0]^=1,
                2=>wrong.mark_price_atoms+=1,
                3=>wrong.state_utxo_root[0]^=1,
                _=>wrong.activation_height+=1,
            }
            assert!(derive(&wrong,100).is_err(),"accepted substituted field {field}");
        }
        // Unsigned synthetic transactions: native block execution and context
        // authentication are separate obligations, not established by this test.
    }

    #[test]
    fn transaction_binding_rejects_output_substitution() {
        let deployment = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()], output: vec![TxOut::default(); 3] };
        let mut input = elements::TxIn::default();
        input.previous_output = OutPoint::new(deployment.txid(), 2);
        let genesis = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![input], output: vec![TxOut::default()] };
        let inventory = ElementsUtxoLeafV2 {
            outpoint: OutPoint::new(deployment.txid(), 0), output: deployment.output[0].clone(),
            creation_height: 7, creation_parent_mtp: 100, coinbase: false,
            created_by_issuance: true, created_by_pegin: false,
        };
        let mut state = inventory.clone(); state.outpoint = OutPoint::new(genesis.txid(), 0);
        state.output = genesis.output[0].clone(); state.created_by_issuance = false;
        let (root, pa, pb) = pair_paths(&inventory, &state);
        let check = |d: &elements::Transaction, g: &elements::Transaction, index| {
            verify_activation_transaction_coins(root, 8, d, index, 2, g, 0,
                ActivationCoinWitness { leaf: &inventory, path: &pa },
                ActivationCoinWitness { leaf: &state, path: &pb })
        };
        // Synthetic linkage only: these transactions are not signed or issued.
        assert_eq!(check(&deployment, &genesis, 0), Ok((7,7)));
        // Linkage alone must not be usable as an issuance proof.
        let fake_issuance = ecx_elements_settlement::FrozenBondDeploymentV2 {
            version: 2, transaction: elements::encode::serialize(&deployment),
            issuance_input_index: 0, inventory_output_index: 0,
            inventory_asset_blinding_factor: [1;32], inventory_value_blinding_factor: [2;32],
            issuance_value_blinding_factor: [3;32], reissuance_token_burn_output_index: 1,
        };
        let asset = ecx_elements_settlement::FrozenBondAssetV2 {
            version: ecx_elements_settlement::FrozenBondAssetV2::VERSION,
            asset_id: [4;32], inventory_vault_script_sha256: [5;32],
            redemption_queue_script_sha256: [6;32], reissuance_token_burn_script_sha256: [7;32],
        };
        for commitment in [[0;32], [8;32]] {
            assert!(verify_issued_activation_coins(root, 8, &fake_issuance, &asset, commitment,
                &genesis, elements::AssetId::from_byte_array([9;32]), &elements::Script::from(vec![0x51]),
                ActivationCoinWitness { leaf: &inventory, path: &pa },
                ActivationCoinWitness { leaf: &state, path: &pb }).is_err());
        }
        let configuration = test_configuration::configuration();
        let secret = elements::secp256k1_zkp::SecretKey::from_slice(&[11;32]).unwrap();
        let keypair = elements::secp256k1_zkp::Keypair::from_secret_key(
            &elements::secp256k1_zkp::Secp256k1::new(), &secret);
        let mut bindings = GenesisStateBindings {
            public_state_domain: [1;32], state_node_domain: [2;32], journal_domain: [3;32],
            transition_cmr: [4;32], activation_cmr: [5;32],
            internal_key: elements::secp256k1_zkp::XOnlyPublicKey::from_keypair(&keypair).0.serialize(),
            order_receipts_root: [6;32], availability_root: [7;32], mark_price_atoms: 3_000_000_000,
            state_outpoint: OutPoint::new(genesis.txid(), 0),
            child_genesis: [8;32],
            activation_height: 8, transition_program_id: [1;32],
            state_utxo_root: ecx_elements_settlement::finite_genesis::state_utxo_root(
                [8;32], OutPoint::new(genesis.txid(), 0), &genesis.output[0]),
        };
        let derived_check = |b: &GenesisStateBindings, mtp| verify_derived_activation_coins(
            root, 8, mtp, &configuration, b, &fake_issuance, &genesis,
            ActivationCoinWitness { leaf: &inventory, path: &pa },
            ActivationCoinWitness { leaf: &state, path: &pb }).err();
        let frozen = bindings.commitment();
        for field in 0..15 {
            let mut changed = bindings.clone();
            match field {
                0 => changed.public_state_domain[0] ^= 1,
                1 => changed.state_node_domain[0] ^= 1,
                2 => changed.journal_domain[0] ^= 1,
                3 => changed.transition_cmr[0] ^= 1,
                4 => changed.activation_cmr[0] ^= 1,
                5 => changed.internal_key[0] ^= 1,
                6 => changed.order_receipts_root[0] ^= 1,
                7 => changed.availability_root[0] ^= 1,
                8 => changed.child_genesis[0] ^= 1,
                9 => changed.state_utxo_root[0] ^= 1,
                10 => changed.mark_price_atoms += 1,
                11 => changed.state_outpoint.vout += 1,
                12 => changed.state_outpoint.txid = elements::Txid::from_byte_array([99;32]),
                13 => changed.activation_height += 1,
                _ => changed.transition_program_id[0] ^= 1,
            }
            assert_ne!(frozen, changed.commitment(), "uncommitted genesis field {field}");
        }
        // Valid synthetic state bindings reach issuance verification, which
        // rejects these unissued transactions. Derivation is not a bypass.
        assert_eq!(derived_check(&bindings, 100), Some(GenesisCoinError::Issuance));
        assert_eq!(derived_check(&bindings, 0), Some(GenesisCoinError::Context));
        bindings.child_genesis[0] ^= 1;
        assert_eq!(derived_check(&bindings, 100), Some(GenesisCoinError::State));
        bindings.child_genesis[0] ^= 1;
        bindings.availability_root = [0;32];
        assert_eq!(derived_check(&bindings, 100), Some(GenesisCoinError::State));
        bindings.availability_root = [7;32];
        bindings.state_outpoint.vout = 1;
        assert_eq!(derived_check(&bindings, 100), Some(GenesisCoinError::Context));
        for index in [1, 2, 3, u32::MAX] { assert!(check(&deployment, &genesis, index).is_err()); }
        let mut changed = genesis.clone(); changed.output[0].value = elements::confidential::Value::Explicit(1);
        assert!(check(&deployment, &changed, 0).is_err());
        changed = genesis.clone(); changed.input[0].previous_output.vout = 1;
        assert!(check(&deployment, &changed, 0).is_err());
        changed.input.clear(); assert!(check(&deployment, &changed, 0).is_err());
    }

    #[test]
    fn authority_outputs_require_exact_asset_amount_and_script() {
        let asset = elements::AssetId::from_byte_array([9;32]);
        let script = elements::Script::from(vec![0x51]);
        let output = TxOut { asset: elements::confidential::Asset::Explicit(asset),
            value: elements::confidential::Value::Explicit(1), script_pubkey: script.clone(),
            ..TxOut::default() };
        let deployment = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![], output: vec![output.clone();3] };
        let genesis = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![], output: vec![output] };
        assert_eq!(verify_genesis_authority_outputs(&deployment, &genesis, asset, &script), Ok(()));
        let mut bad = genesis.clone(); bad.output[0].value = elements::confidential::Value::Explicit(2);
        assert!(verify_genesis_authority_outputs(&deployment, &bad, asset, &script).is_err());
        bad = genesis.clone(); bad.output[0].script_pubkey = elements::Script::from(vec![0x52]);
        assert!(verify_genesis_authority_outputs(&deployment, &bad, asset, &script).is_err());
        assert!(verify_genesis_authority_outputs(&deployment, &genesis,
            elements::AssetId::from_byte_array([8;32]), &script).is_err());
        let mut bad_source = deployment.clone();
        bad_source.output[2].script_pubkey = elements::Script::from(vec![0x6a]);
        assert!(verify_genesis_authority_outputs(&bad_source, &genesis, asset, &script).is_err());
        for (size, accepted) in [(0, false), (10_000, true), (10_001, false)] {
            let boundary_script = elements::Script::from(vec![0x51; size]);
            let mut source = deployment.clone();
            source.output[2].script_pubkey = boundary_script.clone();
            assert_eq!(verify_genesis_authority_outputs(&source, &genesis, asset, &script).is_ok(), accepted);
            let mut state = genesis.clone();
            state.output[0].script_pubkey = boundary_script.clone();
            assert_eq!(verify_genesis_authority_outputs(&deployment, &state, asset, &boundary_script).is_ok(), accepted);
        }
    }

    #[test]
    fn activation_pair_requires_coexistence_and_creation_order() {
        let inventory = ElementsUtxoLeafV2 {
            outpoint: OutPoint::new(elements::Txid::from_byte_array([1;32]), 0),
            output: TxOut::default(), creation_height: 7, creation_parent_mtp: 100,
            coinbase: false, created_by_issuance: true, created_by_pegin: false,
        };
        let mut state = inventory.clone();
        state.outpoint.txid = elements::Txid::from_byte_array([2;32]);
        state.created_by_issuance = false;
        for (height, expected) in [(6, Err(GenesisCoinError::Order)), (7, Ok((7,7))),
            (8, Ok((7,8))), (9, Err(GenesisCoinError::Coin))] {
            state.creation_height = height;
            let (root, pa, pb) = pair_paths(&inventory, &state);
            let check = |r, p: &ElementsSparseUtxoPathV2| verify_activation_coins(r, 9,
                ActivationCoinWitness { leaf: &inventory, path: &pa }, inventory.outpoint, &inventory.output,
                ActivationCoinWitness { leaf: &state, path: p }, state.outpoint, &state.output);
            assert_eq!(check(root, &pb), expected);
            // An activation-block spend removes the coin from the post-state.
            // Its valid predecessor membership must not authorize activation.
            for (coin, path) in [(&inventory, &pa), (&state, &pb)] {
                let spent_root = elements_sparse_utxo_root_from_path_v2(
                    coin.outpoint, canonical_empty_elements_utxo_leaf_v2(), path).unwrap();
                assert_eq!(spent_root.aggregate.count, 1);
                assert!(check(spent_root, &pb).is_err());
            }
            let mut wrong_count = root; wrong_count.aggregate.count += 1;
            assert!(check(wrong_count, &pb).is_err());
            assert!(check(root, &pa).is_err());
        }
    }

    #[test]
    fn exact_coin_membership_rejects_substitution_and_unconfirmed_heights() {
        let leaf = ElementsUtxoLeafV2 {
            outpoint: OutPoint::new(elements::Txid::from_byte_array([1; 32]), 2),
            output: TxOut::default(), creation_height: 7, creation_parent_mtp: 100,
            coinbase: false, created_by_issuance: true, created_by_pegin: false,
        };
        let path = ElementsSparseUtxoPathV2 {
            siblings: vec![canonical_empty_elements_utxo_leaf_v2(); 256],
        };
        // Synthetic membership tree only; not production chain history.
        let root = elements_sparse_utxo_root_from_path_v2(leaf.outpoint,
            elements_utxo_leaf_node_v2(&leaf), &path).unwrap();
        let check = |l: &ElementsUtxoLeafV2, p: &ElementsSparseUtxoPathV2, h| {
            check_coin(root, h, &ActivationCoinWitness { leaf: l, path: p }, leaf.outpoint, &leaf.output)
        };
        assert_eq!(check(&leaf, &path, 8), Ok(7));
        for h in [0, 7, 0x7fff_ffff, u32::MAX] { assert!(check(&leaf, &path, h).is_err()); }
        for h in [0, 8, 0x7fff_ffff] {
            let mut bad = leaf.clone(); bad.creation_height = h;
            assert!(check(&bad, &path, 8).is_err());
        }
        let mut changed = leaf.clone(); changed.creation_parent_mtp += 1;
        assert_eq!(check(&changed, &path, 8), Err(GenesisCoinError::Membership));
        changed = leaf.clone(); changed.outpoint.vout += 1;
        assert_eq!(check(&changed, &path, 8), Err(GenesisCoinError::Coin));
        changed = leaf.clone(); changed.output.value = elements::confidential::Value::Explicit(1);
        assert_eq!(check(&changed, &path, 8), Err(GenesisCoinError::Coin));
        let mut truncated = path.clone(); truncated.siblings.pop();
        assert_eq!(check(&leaf, &truncated, 8), Err(GenesisCoinError::Membership));
    }
}
