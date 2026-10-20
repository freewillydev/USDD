//! Reviewed complete-snapshot checkpoint for the recursive full-Elements
//! validator. Roots and economic totals are rebuilt from every live UTXO; no
//! host-provided aggregate is accepted.

use crate::bmm_v2::{bmm_l1_state_commitment_v2, BmmL1StateV2};
use crate::elements_v2::{
    apply_elements_sparse_economic_mutation_v2, apply_elements_sparse_utxo_mutation_v2,
    canonical_empty_elements_economic_root_v2, canonical_empty_elements_utxo_root_v2,
    ElementsEconomicClassificationV2, ElementsEconomicLeafV2, ElementsLiveEconomicRoleV2,
    ElementsSparseEconomicMutationV2, ElementsSparseEconomicPathV2, ElementsSparseUtxoMutationV2,
    ElementsSparseUtxoPathV2, ElementsUtxoLeafV2,
};
use crate::elements_wire_v2::{
    decode_elements_output_with_witness_v2, outpoint as checkpoint_outpoint_wire,
};
use crate::full_elements_v2::{
    compute_state_utxo_root_v2, full_elements_economic_state_root_v2, ElementsHeaderStateV2,
    FiniteV18CovenantStateV2, FiniteV18StateRendererV2, FullPatchedElementsErrorV2,
};
use bincode::Options;
#[cfg(test)]
use elements::TxOutWitness;
use elements::{confidential, AssetId, OutPoint, TxOut};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Hash32 = [u8; 32];
/// Wire revision 3 adds mandatory output witnesses and canonical outpoints.
/// Revision 2 inputs must be regenerated; they lost confidential rangeproofs.
/// Public statements retain the 305-byte V2 format, but this changed guest
/// requires a newly derived and qualified program identity.
pub const REVIEWED_ELEMENTS_CHECKPOINT_INPUT_WIRE_VERSION_V3: u8 = 3;
pub const REVIEWED_ELEMENTS_CHECKPOINT_INPUT_VERSION_V2: u8 =
    REVIEWED_ELEMENTS_CHECKPOINT_INPUT_WIRE_VERSION_V3;
pub const REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_VERSION_V2: u8 = 2;
pub const REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_BYTES_V2: usize = 305;
pub const MAX_REVIEWED_ELEMENTS_CHECKPOINT_INPUT_BYTES_V2: usize = 512 * 1024 * 1024;
pub const MAX_REVIEWED_ELEMENTS_CHECKPOINT_ENTRIES_V2: usize = 262_144;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedElementsCheckpointEntryV2 {
    #[serde(with = "checkpoint_outpoint_wire")]
    pub outpoint: OutPoint,
    /// Canonical consensus TxOut bytes, which omit the output witness.
    pub output: Vec<u8>,
    /// Canonical consensus TxOutWitness bytes, mandatory even when empty.
    pub output_witness: Vec<u8>,
    pub creation_height: u32,
    pub creation_parent_mtp: u32,
    pub coinbase: bool,
    pub created_by_issuance: bool,
    pub created_by_pegin: bool,
    pub asset_id: Hash32,
    pub amount: u64,
    pub asset_blinding_factor: Hash32,
    pub value_blinding_factor: Hash32,
    pub role: ElementsLiveEconomicRoleV2,
    pub utxo_path: ElementsSparseUtxoPathV2,
    pub economic_path: ElementsSparseEconomicPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedElementsCheckpointInputV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub block_hash_internal: Hash32,
    pub height: u32,
    pub block_time: u32,
    pub mtp_context_times: Vec<u32>,
    pub header_state: ElementsHeaderStateV2,
    pub classification: ElementsEconomicClassificationV2,
    pub entries: Vec<ReviewedElementsCheckpointEntryV2>,
    pub exchange_renderer: FiniteV18StateRendererV2,
    pub exchange_state: FiniteV18CovenantStateV2,
    pub child_genesis_hash: Hash32,
    pub state_authority_asset_id: Hash32,
    pub state_authority_value: u64,
    #[serde(with = "checkpoint_outpoint_wire")]
    pub state_authority_outpoint: OutPoint,
    pub parent_bmm_state: BmmL1StateV2,
}

impl ReviewedElementsCheckpointEntryV2 {
    /// Matching producer: capture both the native output and its witness.
    pub fn from_economic_leaf(
        leaf: &ElementsEconomicLeafV2,
        utxo_path: ElementsSparseUtxoPathV2,
        economic_path: ElementsSparseEconomicPathV2,
    ) -> Self {
        Self {
            outpoint: leaf.utxo.outpoint,
            output: elements::encode::serialize(&leaf.utxo.output),
            output_witness: elements::encode::serialize(&leaf.utxo.output.witness),
            creation_height: leaf.utxo.creation_height,
            creation_parent_mtp: leaf.utxo.creation_parent_mtp,
            coinbase: leaf.utxo.coinbase,
            created_by_issuance: leaf.utxo.created_by_issuance,
            created_by_pegin: leaf.utxo.created_by_pegin,
            asset_id: leaf.asset_id,
            amount: leaf.amount,
            asset_blinding_factor: leaf.asset_blinding_factor,
            value_blinding_factor: leaf.value_blinding_factor,
            role: leaf.role,
            utxo_path,
            economic_path,
        }
    }

    pub fn decode_output(&self) -> Result<TxOut, ReviewedElementsCheckpointErrorV2> {
        decode_elements_output_with_witness_v2(&self.output, &self.output_witness)
            .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidSnapshot)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewedElementsCheckpointPublicValuesV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub block_hash_internal: Hash32,
    pub state_root: Hash32,
    pub utxo_root: Hash32,
    pub economic_root: Hash32,
    pub exchange_state_root: Hash32,
    pub parent_bmm_state_commitment: Hash32,
    pub header_state_commitment: Hash32,
    pub height: u64,
    pub mtp: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
}

impl ReviewedElementsCheckpointPublicValuesV2 {
    pub fn canonical_bytes(self) -> [u8; REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_BYTES_V2] {
        let mut out = Vec::with_capacity(REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_BYTES_V2);
        out.push(self.version);
        for hash in [
            self.source_configuration_commitment,
            self.block_hash_internal,
            self.state_root,
            self.utxo_root,
            self.economic_root,
            self.exchange_state_root,
            self.parent_bmm_state_commitment,
            self.header_state_commitment,
        ] {
            out.extend_from_slice(&hash);
        }
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.mtp.to_be_bytes());
        out.extend_from_slice(&self.outstanding_base_atoms.to_be_bytes());
        out.extend_from_slice(&self.redeemable_reserve_quote_atoms.to_be_bytes());
        out.try_into()
            .expect("fixed reviewed Elements checkpoint journal")
    }
}

pub fn decode_reviewed_elements_checkpoint_public_values_v2(
    bytes: &[u8],
) -> Result<ReviewedElementsCheckpointPublicValuesV2, ReviewedElementsCheckpointErrorV2> {
    if bytes.len() != REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_BYTES_V2
        || bytes[0] != REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_VERSION_V2
    {
        return Err(ReviewedElementsCheckpointErrorV2::NonCanonicalInput);
    }
    let mut offset = 1usize;
    let mut read_hash = || {
        let value: Hash32 = bytes[offset..offset + 32]
            .try_into()
            .expect("checked checkpoint journal length");
        offset += 32;
        value
    };
    let public = ReviewedElementsCheckpointPublicValuesV2 {
        version: bytes[0],
        source_configuration_commitment: read_hash(),
        block_hash_internal: read_hash(),
        state_root: read_hash(),
        utxo_root: read_hash(),
        economic_root: read_hash(),
        exchange_state_root: read_hash(),
        parent_bmm_state_commitment: read_hash(),
        header_state_commitment: read_hash(),
        height: u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("checked checkpoint journal length"),
        ),
        mtp: u64::from_be_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .expect("checked checkpoint journal length"),
        ),
        outstanding_base_atoms: u128::from_be_bytes(
            bytes[offset + 16..offset + 32]
                .try_into()
                .expect("checked checkpoint journal length"),
        ),
        redeemable_reserve_quote_atoms: u128::from_be_bytes(
            bytes[offset + 32..offset + 48]
                .try_into()
                .expect("checked checkpoint journal length"),
        ),
    };
    if public.source_configuration_commitment == [0; 32]
        || public.block_hash_internal == [0; 32]
        || public.state_root == [0; 32]
        || public.utxo_root == [0; 32]
        || public.economic_root == [0; 32]
        || public.exchange_state_root == [0; 32]
        || public.parent_bmm_state_commitment == [0; 32]
        || public.header_state_commitment == [0; 32]
        || public.height == 0
        || public.mtp == 0
        || public.outstanding_base_atoms == 0
        || public.canonical_bytes() != bytes
    {
        return Err(ReviewedElementsCheckpointErrorV2::InvalidShape);
    }
    Ok(public)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ReviewedElementsCheckpointErrorV2 {
    #[error("reviewed Elements checkpoint input is noncanonical or oversized")]
    NonCanonicalInput,
    #[error("reviewed Elements checkpoint shape is invalid")]
    InvalidShape,
    #[error("reviewed Elements complete UTXO/economic snapshot is invalid")]
    InvalidSnapshot,
    #[error("reviewed Elements exchange-state preimage is invalid")]
    InvalidExchangeState,
    #[error("reviewed Elements BMM parent state is invalid")]
    InvalidParentState,
}

pub fn encode_reviewed_elements_checkpoint_input_v2(
    input: &ReviewedElementsCheckpointInputV2,
) -> Result<Vec<u8>, ReviewedElementsCheckpointErrorV2> {
    validate_shape(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| ReviewedElementsCheckpointErrorV2::NonCanonicalInput)
}

pub fn decode_reviewed_elements_checkpoint_input_v2(
    bytes: &[u8],
) -> Result<ReviewedElementsCheckpointInputV2, ReviewedElementsCheckpointErrorV2> {
    if bytes.first() != Some(&REVIEWED_ELEMENTS_CHECKPOINT_INPUT_WIRE_VERSION_V3)
        || bytes.len() > MAX_REVIEWED_ELEMENTS_CHECKPOINT_INPUT_BYTES_V2
    {
        return Err(ReviewedElementsCheckpointErrorV2::NonCanonicalInput);
    }
    let input: ReviewedElementsCheckpointInputV2 = canonical_options()
        .deserialize(bytes)
        .map_err(|_| ReviewedElementsCheckpointErrorV2::NonCanonicalInput)?;
    validate_shape(&input)?;
    if encode_reviewed_elements_checkpoint_input_v2(&input)? != bytes {
        return Err(ReviewedElementsCheckpointErrorV2::NonCanonicalInput);
    }
    Ok(input)
}

pub fn execute_reviewed_elements_checkpoint_v2(
    input: &ReviewedElementsCheckpointInputV2,
) -> Result<ReviewedElementsCheckpointPublicValuesV2, ReviewedElementsCheckpointErrorV2> {
    validate_shape(input)?;
    let mut utxo_root = canonical_empty_elements_utxo_root_v2()
        .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidSnapshot)?;
    let mut economic_root = canonical_empty_elements_economic_root_v2()
        .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidSnapshot)?;
    for entry in &input.entries {
        let output = entry.decode_output()?;
        let utxo_leaf = ElementsUtxoLeafV2 {
            outpoint: entry.outpoint,
            output,
            creation_height: entry.creation_height,
            creation_parent_mtp: entry.creation_parent_mtp,
            coinbase: entry.coinbase,
            created_by_issuance: entry.created_by_issuance,
            created_by_pegin: entry.created_by_pegin,
        };
        let economic_leaf = ElementsEconomicLeafV2 {
            utxo: utxo_leaf.clone(),
            asset_id: entry.asset_id,
            amount: entry.amount,
            asset_blinding_factor: entry.asset_blinding_factor,
            value_blinding_factor: entry.value_blinding_factor,
            role: entry.role,
        };
        let utxo_mutation = ElementsSparseUtxoMutationV2 {
            outpoint: entry.outpoint,
            old_leaf: None,
            new_leaf: Some(utxo_leaf),
            path: entry.utxo_path.clone(),
        };
        let economic_mutation = ElementsSparseEconomicMutationV2 {
            outpoint: entry.outpoint,
            old_leaf: None,
            new_leaf: Some(economic_leaf),
            path: entry.economic_path.clone(),
        };
        utxo_root = apply_elements_sparse_utxo_mutation_v2(utxo_root, &utxo_mutation)
            .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidSnapshot)?;
        economic_root = apply_elements_sparse_economic_mutation_v2(
            economic_root,
            &economic_mutation,
            input.classification,
        )
        .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidSnapshot)?;
    }
    if utxo_root.aggregate.count != economic_root.aggregate.count
        || utxo_root.aggregate.count
            != u128::try_from(input.entries.len())
                .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidSnapshot)?
    {
        return Err(ReviewedElementsCheckpointErrorV2::InvalidSnapshot);
    }

    let state_script = input
        .exchange_renderer
        .render(input.exchange_state)
        .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidExchangeState)?;
    let state_asset = AssetId::from_slice(&input.state_authority_asset_id)
        .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidExchangeState)?;
    if input.state_authority_value == 0 {
        return Err(ReviewedElementsCheckpointErrorV2::InvalidExchangeState);
    }
    let state_output = TxOut {
        asset: confidential::Asset::Explicit(state_asset),
        value: confidential::Value::Explicit(input.state_authority_value),
        nonce: confidential::Nonce::Null,
        script_pubkey: state_script,
        witness: Default::default(),
    };
    let exchange_state_root = compute_state_utxo_root_v2(
        input.child_genesis_hash,
        input.state_authority_outpoint,
        &state_output,
    );
    let state_root =
        full_elements_economic_state_root_v2(utxo_root, economic_root, exchange_state_root)
            .map_err(map_full_error)?;
    let parent_bmm_state_commitment = bmm_l1_state_commitment_v2(&input.parent_bmm_state)
        .map_err(|_| ReviewedElementsCheckpointErrorV2::InvalidParentState)?;
    let mut mtp = input.mtp_context_times.clone();
    mtp.sort_unstable();
    Ok(ReviewedElementsCheckpointPublicValuesV2 {
        version: REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_VERSION_V2,
        source_configuration_commitment: input.source_configuration_commitment,
        block_hash_internal: input.block_hash_internal,
        state_root,
        utxo_root: utxo_root.hash,
        economic_root: economic_root.hash,
        exchange_state_root,
        parent_bmm_state_commitment,
        header_state_commitment: input.header_state.commitment().map_err(map_full_error)?,
        height: u64::from(input.height),
        mtp: u64::from(mtp[5]),
        outstanding_base_atoms: economic_root.aggregate.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: economic_root.aggregate.redeemable_reserve_quote_atoms,
    })
}

fn validate_shape(
    input: &ReviewedElementsCheckpointInputV2,
) -> Result<(), ReviewedElementsCheckpointErrorV2> {
    if input.version != REVIEWED_ELEMENTS_CHECKPOINT_INPUT_VERSION_V2
        || input.source_configuration_commitment == [0; 32]
        || input.block_hash_internal == [0; 32]
        || input.height == 0
        || input.block_time == 0
        || input.mtp_context_times.len() != 11
        || input.mtp_context_times.contains(&0)
        || input.mtp_context_times.last() != Some(&input.block_time)
        || input.header_state.validate().is_err()
        || input.header_state.block_hash != input.block_hash_internal
        || input.header_state.height != input.height
        || input.header_state.previous_11_times != input.mtp_context_times
        || input.entries.is_empty()
        || input.entries.len() > MAX_REVIEWED_ELEMENTS_CHECKPOINT_ENTRIES_V2
        || input.child_genesis_hash == [0; 32]
        || input.state_authority_asset_id == [0; 32]
        || input.state_authority_value == 0
    {
        return Err(ReviewedElementsCheckpointErrorV2::InvalidShape);
    }
    Ok(())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_REVIEWED_ELEMENTS_CHECKPOINT_INPUT_BYTES_V2 as u64)
}

fn map_full_error(_: FullPatchedElementsErrorV2) -> ReviewedElementsCheckpointErrorV2 {
    ReviewedElementsCheckpointErrorV2::InvalidSnapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements_v2::{
        canonical_empty_elements_economic_leaf_v2, canonical_empty_elements_utxo_leaf_v2,
        elements_sparse_economic_parent_v2, elements_sparse_utxo_parent_v2, ElementsEconomicLeafV2,
        ElementsLiveEconomicRoleV2, ElementsSparseEconomicPathV2, ElementsSparseUtxoPathV2,
        ElementsUtxoLeafV2, ELEMENTS_SPARSE_UTXO_DEPTH_V2,
    };
    use crate::full_elements_v2::{
        FINITE_V18_COVENANT_STATE_VERSION, FINITE_V18_NUMS_INTERNAL_KEY,
        FINITE_V18_SIMPLICITY_LEAF_VERSION,
    };
    use bitcoin::hashes::Hash as _;
    use elements::{BlockHash as ElementsBlockHash, Script, Txid};

    fn utxo_empty_path() -> ElementsSparseUtxoPathV2 {
        let mut siblings = Vec::with_capacity(ELEMENTS_SPARSE_UTXO_DEPTH_V2);
        let mut node = canonical_empty_elements_utxo_leaf_v2();
        for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
            siblings.push(node);
            node = elements_sparse_utxo_parent_v2(node, node).unwrap();
        }
        ElementsSparseUtxoPathV2 { siblings }
    }

    fn economic_empty_path() -> ElementsSparseEconomicPathV2 {
        let mut siblings = Vec::with_capacity(ELEMENTS_SPARSE_UTXO_DEPTH_V2);
        let mut node = canonical_empty_elements_economic_leaf_v2();
        for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
            siblings.push(node);
            node = elements_sparse_economic_parent_v2(node, node).unwrap();
        }
        ElementsSparseEconomicPathV2 { siblings }
    }

    fn input() -> ReviewedElementsCheckpointInputV2 {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([21; 32]),
            vout: 0,
        };
        let output = TxOut {
            asset: confidential::Asset::Explicit(AssetId::from_slice(&[9; 32]).unwrap()),
            value: confidential::Value::Explicit(100),
            nonce: confidential::Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let utxo_leaf = ElementsUtxoLeafV2 {
            outpoint,
            output,
            creation_height: 100,
            creation_parent_mtp: 95,
            coinbase: false,
            created_by_issuance: true,
            created_by_pegin: false,
        };
        let economic_leaf = ElementsEconomicLeafV2 {
            utxo: utxo_leaf.clone(),
            asset_id: [9; 32],
            amount: 100,
            asset_blinding_factor: [0; 32],
            value_blinding_factor: [0; 32],
            role: ElementsLiveEconomicRoleV2::OutstandingBase,
        };
        ReviewedElementsCheckpointInputV2 {
            version: REVIEWED_ELEMENTS_CHECKPOINT_INPUT_VERSION_V2,
            source_configuration_commitment: [20; 32],
            block_hash_internal: ElementsBlockHash::from_byte_array([22; 32]).to_byte_array(),
            height: 100,
            block_time: 100,
            mtp_context_times: (90..=100).collect(),
            header_state: ElementsHeaderStateV2 {
                block_hash: [22; 32],
                height: 100,
                previous_11_times: (90..=100).collect(),
                full_current_dynafed_parameters: elements::dynafed::Params::Full(
                    elements::dynafed::FullParams::new(
                        Script::from(vec![0x51]),
                        1000,
                        bitcoin::ScriptBuf::new(),
                        vec![],
                        vec![],
                    ),
                ),
                dynamic_epoch_length: 10,
                epoch_proposals: vec![elements::dynafed::Params::Null],
                authenticated_adjusted_time: 200,
            },
            classification: ElementsEconomicClassificationV2 {
                base_asset_id: [9; 32],
                policy_asset_id: [10; 32],
                redemption_inventory_script_sha256: crate::sha256_bytes(&[0x52]),
                reserve_script_sha256: crate::sha256_bytes(&[0x53]),
            },
            entries: vec![ReviewedElementsCheckpointEntryV2::from_economic_leaf(
                &economic_leaf,
                utxo_empty_path(),
                economic_empty_path(),
            )],
            exchange_renderer: FiniteV18StateRendererV2 {
                public_state_domain_sha256: [1; 32],
                state_node_domain_sha256: [2; 32],
                transition_cmr: [3; 32],
                incremental_activation_cmr: [4; 32],
                keyless_internal_key: FINITE_V18_NUMS_INTERNAL_KEY,
                simplicity_leaf_version: FINITE_V18_SIMPLICITY_LEAF_VERSION,
            },
            exchange_state: FiniteV18CovenantStateV2 {
                version: FINITE_V18_COVENANT_STATE_VERSION,
                sequence: 1,
                private_state_root: [31; 32],
                encrypted_availability_root: [32; 32],
                forced_inbox_root: [33; 32],
                deposit_inbox_root: [34; 32],
                configuration_hash: [35; 32],
                bond_state_root: [36; 32],
                funding_state_root: [37; 32],
                active_order_risk_root: [38; 32],
                position_risk_root: [39; 32],
                bond_inbox_head_root: [40; 32],
                bond_inbox_entry_count: 0,
                bond_inbox_processed_root: [41; 32],
                bond_inbox_processed_cursor: 0,
                bond_inbox_outcome_root: [42; 32],
                bond_inbox_outcome_count: 0,
                matcher_execution_sequence: 1,
                last_transition_sidechain_height: 100,
            },
            child_genesis_hash: [43; 32],
            state_authority_asset_id: [44; 32],
            state_authority_value: 1,
            state_authority_outpoint: OutPoint {
                txid: Txid::from_byte_array([45; 32]),
                vout: 0,
            },
            parent_bmm_state: BmmL1StateV2 {
                block_hash: bitcoin::BlockHash::from_byte_array([46; 32]),
                height: 200,
                block_time: 200,
                bits: 0x1d00ffff,
                period_start_height: 0,
                period_start_time: 1,
                recent_times: (190..=200).collect(),
            },
        }
    }

    #[test]
    fn checkpoint_binds_ordered_header_frontier_and_rejects_mismatched_duplicates() {
        let input = input();
        let public = execute_reviewed_elements_checkpoint_v2(&input).unwrap();
        assert_eq!(
            public.header_state_commitment,
            input.header_state.commitment().unwrap()
        );
        let mut changed = input.clone();
        changed.header_state.previous_11_times.swap(0, 1);
        assert_eq!(
            execute_reviewed_elements_checkpoint_v2(&changed),
            Err(ReviewedElementsCheckpointErrorV2::InvalidShape)
        );
        changed.mtp_context_times.swap(0, 1);
        let changed_public = execute_reviewed_elements_checkpoint_v2(&changed).unwrap();
        assert_eq!(changed_public.mtp, public.mtp);
        assert_eq!(changed_public.state_root, public.state_root);
        assert_ne!(
            changed_public.header_state_commitment,
            public.header_state_commitment
        );
        assert_ne!(changed_public.canonical_bytes(), public.canonical_bytes());
        changed = input.clone();
        changed.header_state.block_hash[0] ^= 1;
        assert!(execute_reviewed_elements_checkpoint_v2(&changed).is_err());
        changed = input.clone();
        changed.header_state.height += 10;
        assert!(execute_reviewed_elements_checkpoint_v2(&changed).is_err());
        changed = input;
        changed.header_state.full_current_dynafed_parameters = elements::dynafed::Params::Null;
        assert!(execute_reviewed_elements_checkpoint_v2(&changed).is_err());

        let bytes = public.canonical_bytes();
        let mut legacy = bytes[..225].to_vec();
        legacy[0] = 1;
        legacy.extend_from_slice(&bytes[257..]);
        assert_eq!(legacy.len(), 273);
        assert!(decode_reviewed_elements_checkpoint_public_values_v2(&legacy).is_err());
    }

    #[test]
    fn complete_snapshot_derives_checkpoint_roots_and_rejects_omission() {
        let input = input();
        let encoded = encode_reviewed_elements_checkpoint_input_v2(&input).unwrap();
        assert_eq!(
            decode_reviewed_elements_checkpoint_input_v2(&encoded).unwrap(),
            input
        );
        let public = execute_reviewed_elements_checkpoint_v2(&input).unwrap();
        assert_eq!(public.height, 100);
        assert_eq!(public.mtp, 95);
        assert_eq!(public.outstanding_base_atoms, 100);
        assert_eq!(public.redeemable_reserve_quote_atoms, 0);
        assert_eq!(
            public.canonical_bytes().len(),
            REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_BYTES_V2
        );
        assert_eq!(
            decode_reviewed_elements_checkpoint_public_values_v2(&public.canonical_bytes())
                .unwrap(),
            public
        );

        let mut omitted = input.clone();
        omitted.entries.clear();
        assert_eq!(
            execute_reviewed_elements_checkpoint_v2(&omitted),
            Err(ReviewedElementsCheckpointErrorV2::InvalidShape)
        );
        let mut forged = input;
        forged.entries[0].amount += 1;
        assert_eq!(
            execute_reviewed_elements_checkpoint_v2(&forged),
            Err(ReviewedElementsCheckpointErrorV2::InvalidSnapshot)
        );
    }

    #[test]
    fn checkpoint_outpoints_use_exact_consensus_bytes_and_preserve_json() {
        #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
        struct Wrapper(#[serde(with = "checkpoint_outpoint_wire")] OutPoint);
        let value = Wrapper(OutPoint {
            txid: Txid::from_byte_array(std::array::from_fn(|i| i as u8)),
            vout: 0x01020304,
        });
        let bytes = canonical_options().serialize(&value).unwrap();
        assert_eq!(bytes.len(), 36);
        assert_eq!(bytes, elements::encode::serialize(&value.0));
        assert_eq!(&bytes[32..], &[4, 3, 2, 1]);
        assert_eq!(
            canonical_options().deserialize::<Wrapper>(&bytes).unwrap(),
            value
        );
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::to_value(value.0).unwrap()
        );
        assert_eq!(
            serde_json::from_value::<Wrapper>(serde_json::to_value(value.0).unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn checkpoint_wire_rejects_old_version_missing_witness_and_noncanonical_bytes() {
        let input = input();
        let encoded = encode_reviewed_elements_checkpoint_input_v2(&input).unwrap();
        assert_eq!(encoded[0], 3);
        for version in [0, 1, 2, 4] {
            let mut changed = encoded.clone();
            changed[0] = version;
            assert!(decode_reviewed_elements_checkpoint_input_v2(&changed).is_err());
        }
        for trim in [1, encoded.len() / 2, encoded.len()] {
            assert!(
                decode_reviewed_elements_checkpoint_input_v2(&encoded[..encoded.len() - trim])
                    .is_err()
            );
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_reviewed_elements_checkpoint_input_v2(&trailing).is_err());
        let mut json = serde_json::to_value(&input).unwrap();
        json["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("output_witness");
        assert!(serde_json::from_value::<ReviewedElementsCheckpointInputV2>(json).is_err());
        for bad_witness in [vec![], vec![0], vec![0, 0, 0], vec![0xfd, 0, 0, 0]] {
            let mut changed = input.clone();
            changed.entries[0].output_witness = bad_witness;
            assert_eq!(
                execute_reviewed_elements_checkpoint_v2(&changed),
                Err(ReviewedElementsCheckpointErrorV2::InvalidSnapshot)
            );
        }
    }

    #[test]
    fn checkpoint_preserves_and_verifies_real_confidential_rangeproof() {
        use elements::secp256k1_zkp::{PublicKey, RangeProof, Secp256k1, SecretKey};
        let mut input = input();
        let secp = Secp256k1::new();
        let abf = confidential::AssetBlindingFactor::from_slice(&[2; 32]).unwrap();
        let vbf = confidential::ValueBlindingFactor::from_slice(&[3; 32]).unwrap();
        let asset =
            confidential::Asset::new_confidential(&secp, AssetId::from_byte_array([9; 32]), abf);
        let generator = asset.commitment().unwrap();
        let value = confidential::Value::new_confidential(&secp, 100, generator, vbf);
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let mut output = input.entries[0].decode_output().unwrap();
        output.asset = asset;
        output.value = value;
        output.nonce =
            confidential::Nonce::Confidential(PublicKey::from_secret_key(&secp, &secret));
        output.witness.rangeproof = Some(Box::new(
            RangeProof::new(
                &secp,
                1,
                value.commitment().unwrap(),
                100,
                vbf.into_inner(),
                b"checkpoint wire regression",
                output.script_pubkey.as_bytes(),
                secret,
                0,
                8,
                generator,
            )
            .unwrap(),
        ));
        let prior = input.entries[0].clone();
        input.entries[0] = ReviewedElementsCheckpointEntryV2::from_economic_leaf(
            &ElementsEconomicLeafV2 {
                utxo: ElementsUtxoLeafV2 {
                    outpoint: prior.outpoint,
                    output: output.clone(),
                    creation_height: prior.creation_height,
                    creation_parent_mtp: prior.creation_parent_mtp,
                    coinbase: prior.coinbase,
                    created_by_issuance: prior.created_by_issuance,
                    created_by_pegin: prior.created_by_pegin,
                },
                asset_id: prior.asset_id,
                amount: prior.amount,
                asset_blinding_factor: [2; 32],
                value_blinding_factor: [3; 32],
                role: prior.role,
            },
            prior.utxo_path,
            prior.economic_path,
        );
        assert_eq!(input.entries[0].decode_output().unwrap(), output);
        let lost: TxOut = elements::encode::deserialize(&input.entries[0].output).unwrap();
        assert!(lost.witness.is_empty());
        let public = execute_reviewed_elements_checkpoint_v2(&input).unwrap();
        assert_eq!(public.outstanding_base_atoms, 100);
        let encoded = encode_reviewed_elements_checkpoint_input_v2(&input).unwrap();
        let decoded = decode_reviewed_elements_checkpoint_input_v2(&encoded).unwrap();
        assert_eq!(decoded, input);
        assert_eq!(decoded.entries[0].decode_output().unwrap(), output);
        assert_eq!(
            execute_reviewed_elements_checkpoint_v2(&decoded).unwrap(),
            public
        );

        let mut missing = input.clone();
        missing.entries[0].output_witness = elements::encode::serialize(&TxOutWitness::default());
        assert_eq!(
            execute_reviewed_elements_checkpoint_v2(&missing),
            Err(ReviewedElementsCheckpointErrorV2::InvalidSnapshot)
        );
        let mut wrong_script = input.clone();
        output.script_pubkey = Script::from(vec![0x52]);
        wrong_script.entries[0].output = elements::encode::serialize(&output);
        assert_eq!(
            execute_reviewed_elements_checkpoint_v2(&wrong_script),
            Err(ReviewedElementsCheckpointErrorV2::InvalidSnapshot)
        );
        let mut wrong_opening = input;
        wrong_opening.entries[0].value_blinding_factor = [5; 32];
        assert_eq!(
            execute_reviewed_elements_checkpoint_v2(&wrong_opening),
            Err(ReviewedElementsCheckpointErrorV2::InvalidSnapshot)
        );
    }
}
