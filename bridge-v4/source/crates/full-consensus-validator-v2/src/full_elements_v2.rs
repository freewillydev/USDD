//! Atomic full-block composition for the patched Elements V18 relation.

use crate::bmm_v2::{bmm_l1_state_commitment_v2, BmmConsensusParametersV2, BmmL1StateV2};
use crate::elements_v2::{
    apply_elements_sparse_economic_mutation_v2, apply_elements_transaction_utxos_v2,
    DrivechainDepositReceiptVerifierV2, ElementsEconomicClassificationV2, ElementsInputVerifierV2,
    ElementsSparseEconomicNodeV2, ElementsSparseUtxoNodeV2, ElementsStateErrorV2,
    ElementsTransactionEconomicWitnessV2, ElementsTransactionKernelWitnessV2,
    ElementsTransactionSpendContextV2, ElementsTransactionUtxoWitnessV2,
};
use crate::patched_elements_v2::{
    verify_patched_elements_bmm_transition_v2, Hash32, PatchedElementsBlockV2,
    PatchedElementsCodecErrorV2,
};
use crate::script_v2::{
    verify_native_witness_program_with_checker_v2, ScriptLockContextV2, ScriptPrimitiveErrorV2,
    ScriptSignatureCheckerV2, WitnessV0FlagsV2,
};
use bincode::Options;
use ecx_sp1_consensus_interface::{
    parse_groth16_public_values_v5_annex, verify_groth16_public_values_v5_annex, Groth16Sp1Backend,
    ProgramId,
};
use elements::dynafed::Params;
use elements::encode::serialize;
use elements::hashes::{Hash as _, HashEngine as _};
use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use elements::{confidential, OutPoint, TxOut};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PATCHED_ELEMENTS_RESERVED_DYNAFED_VERSION_MASK_V2: u32 =
    (1 << 23) | (1 << 24) | (1 << 25) | (1 << 26);
pub const ELEMENTS_CONSENSUS_CONFIGURATION_VERSION_V2: u8 = 2;
pub const MAX_ELEMENTS_CONSENSUS_CONFIGURATION_BYTES_V2: usize = 4 * 1024 * 1024;
pub const MAX_ELEMENTS_HEADER_EPOCH_PROPOSALS_V2: usize = 65_536;

/// Post-DynaFed frontier. Its initial value must come from the reviewed source
/// checkpoint; hashing this structure does not authenticate an imported history.
/// Timestamps are oldest first. Proposals include every block of the current
/// epoch through the tip, in that same order (including null proposals).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "ElementsHeaderStateWireV2",
    into = "ElementsHeaderStateWireV2"
)]
pub struct ElementsHeaderStateV2 {
    pub block_hash: Hash32,
    pub height: u32,
    pub previous_11_times: Vec<u32>,
    pub full_current_dynafed_parameters: Params,
    pub dynamic_epoch_length: u32,
    pub epoch_proposals: Vec<Params>,
    /// Fixed source observation bound, not a freely replaceable per-block clock.
    pub authenticated_adjusted_time: u64,
}

// rust-elements Params uses a JSON-oriented Serde map; the proof ABI must use
// canonical consensus bytes instead, just like the block/header wire codec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ElementsHeaderStateWireV2 {
    block_hash: Hash32,
    height: u32,
    previous_11_times: Vec<u32>,
    full_current_dynafed_parameters: Vec<u8>,
    dynamic_epoch_length: u32,
    epoch_proposals: Vec<Vec<u8>>,
    authenticated_adjusted_time: u64,
}

impl From<ElementsHeaderStateV2> for ElementsHeaderStateWireV2 {
    fn from(state: ElementsHeaderStateV2) -> Self {
        Self {
            block_hash: state.block_hash,
            height: state.height,
            previous_11_times: state.previous_11_times,
            full_current_dynafed_parameters: serialize(&state.full_current_dynafed_parameters),
            dynamic_epoch_length: state.dynamic_epoch_length,
            epoch_proposals: state.epoch_proposals.iter().map(serialize).collect(),
            authenticated_adjusted_time: state.authenticated_adjusted_time,
        }
    }
}

impl TryFrom<ElementsHeaderStateWireV2> for ElementsHeaderStateV2 {
    type Error = FullPatchedElementsErrorV2;
    fn try_from(wire: ElementsHeaderStateWireV2) -> Result<Self, Self::Error> {
        let decode = |bytes: &[u8]| -> Result<Params, Self::Error> {
            let params = elements::encode::deserialize(bytes)
                .map_err(|_| FullPatchedElementsErrorV2::HeaderAuthorization)?;
            if serialize(&params) != bytes {
                return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
            }
            Ok(params)
        };
        let state = Self {
            block_hash: wire.block_hash,
            height: wire.height,
            previous_11_times: wire.previous_11_times,
            full_current_dynafed_parameters: decode(&wire.full_current_dynafed_parameters)?,
            dynamic_epoch_length: wire.dynamic_epoch_length,
            epoch_proposals: wire
                .epoch_proposals
                .iter()
                .map(|p| decode(p))
                .collect::<Result<_, _>>()?,
            authenticated_adjusted_time: wire.authenticated_adjusted_time,
        };
        state.validate()?;
        Ok(state)
    }
}

impl ElementsHeaderStateV2 {
    pub fn validate(&self) -> Result<(), FullPatchedElementsErrorV2> {
        if self.block_hash == [0; 32]
            || self.height < 10
            || self.previous_11_times.len() != 11
            || self.previous_11_times.contains(&0)
            || self.full_current_dynafed_parameters.full().is_none()
            || self.dynamic_epoch_length == 0
            || self.authenticated_adjusted_time == 0
            || self.epoch_proposals.len() > MAX_ELEMENTS_HEADER_EPOCH_PROPOSALS_V2
            || self.epoch_proposals.len() as u64
                != u64::from(self.height % self.dynamic_epoch_length) + 1
            || self
                .epoch_proposals
                .iter()
                .any(|p| !p.is_null() && !p.is_full())
        {
            return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, FullPatchedElementsErrorV2> {
        self.validate()?;
        let bytes = canonical_full_elements_options()
            .serialize(self)
            .map_err(|_| FullPatchedElementsErrorV2::HeaderAuthorization)?;
        if bytes.len() > MAX_ELEMENTS_CONSENSUS_CONFIGURATION_BYTES_V2 {
            return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
        }
        let tag = Sha256::digest(b"ECX/elements-header-frontier/v2");
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(tag);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    /// Mirror ComputeNextBlock{Full,}CurrentParameters for an already-active
    /// DynaFed chain. A bounded reviewed checkpoint supplies the epoch prefix.
    pub fn next_parameters(&self) -> Result<(Params, Params), FullPatchedElementsErrorV2> {
        self.validate()?;
        let next_height = self
            .height
            .checked_add(1)
            .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?;
        let epoch_start = next_height % self.dynamic_epoch_length == 0;
        let mut full = self.full_current_dynafed_parameters.clone();
        if epoch_start {
            let threshold = u64::from(self.dynamic_epoch_length) * 4 / 5;
            let mut tally = std::collections::BTreeMap::<Hash32, u64>::new();
            // Core scans backwards and returns the proposal which first reaches
            // floor(4*N/5); preserve that ordering even for very short epochs.
            for proposal in self.epoch_proposals.iter().rev() {
                let root = proposal.calculate_root().to_byte_array();
                let count = tally.entry(root).or_default();
                *count += 1;
                if !proposal.is_null() && *count >= threshold {
                    full = proposal.clone();
                    break;
                }
            }
        }
        let current = if epoch_start {
            full.clone()
        } else {
            full.clone()
                .into_compact()
                .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?
        };
        Ok((current, full))
    }

    pub fn advance(
        &self,
        block: &PatchedElementsBlockV2,
    ) -> Result<Self, FullPatchedElementsErrorV2> {
        let (current, full) = self.next_parameters()?;
        let header = &block.header;
        if header.previous_block_hash != self.block_hash
            || self.height.checked_add(1) != Some(header.height)
            || header.current_dynafed_parameters != current
        {
            return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
        }
        validate_proposal(&full, &header.proposed_dynafed_parameters)?;
        let mut times = self.previous_11_times.clone();
        times.sort_unstable();
        let future_limit = self
            .authenticated_adjusted_time
            .checked_add(crate::elements_v2::ELEMENTS_MAX_FUTURE_BLOCK_SECONDS_V2)
            .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?;
        if header.time <= times[5] || u64::from(header.time) > future_limit {
            return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
        }
        let mut times = self.previous_11_times[1..].to_vec();
        times.push(header.time);
        let mut proposals = if header.height % self.dynamic_epoch_length == 0 {
            Vec::new()
        } else {
            self.epoch_proposals.clone()
        };
        proposals.push(header.proposed_dynafed_parameters.clone());
        let next = Self {
            block_hash: header.block_hash()?,
            height: header.height,
            previous_11_times: times,
            full_current_dynafed_parameters: full,
            dynamic_epoch_length: self.dynamic_epoch_length,
            epoch_proposals: proposals,
            authenticated_adjusted_time: self.authenticated_adjusted_time,
        };
        next.validate()?;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchedElementsHeaderContextV2 {
    pub previous_header_state: ElementsHeaderStateV2,
    pub previous_block_hash: Hash32,
    pub next_height: u32,
    pub previous_11_times: Vec<u32>,
    pub authenticated_adjusted_time: u64,
    pub expected_current_dynafed_parameters: Params,
    /// Must be the exact `Params::Full` preimage underlying the current entry.
    pub expected_full_current_dynafed_parameters: Params,
    pub expected_forced_inbox_root: Hash32,
    pub expected_deposit_inbox_root: Hash32,
    pub expected_parent_height: u32,
    pub expected_forced_processed_cursor: u64,
    pub expected_deposit_processed_cursor: u64,
    pub expected_source_backlog_oldest_parent_height: u64,
}

/// Canonical, network-agnostic profile preimage bound by checkpoints and every
/// transition journal. Network identity is data, not a guest compile-time
/// constant, while the relation and codec remain identical across networks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsConsensusConfigurationV2 {
    pub version: u8,
    pub child_genesis: Hash32,
    pub dynamic_epoch_length: u32,
    pub classification: ElementsEconomicClassificationV2,
    pub quote_atoms_per_whole_base: u64,
    pub bmm_consensus: BmmConsensusParametersV2,
    pub simplicity_evaluator_program_id: Hash32,
    pub redemption_capability_program_id: Hash32,
    pub finite_transition_program_id: Hash32,
    pub finite_configuration_hash: Hash32,
    pub renderer: FiniteV18StateRendererV2,
    pub state_authority_asset_id: Hash32,
    pub state_authority_value: u64,
    pub covenant_commitment: Hash32,
}

impl ElementsConsensusConfigurationV2 {
    pub fn validate(&self) -> Result<(), FullPatchedElementsErrorV2> {
        let ids = [
            self.simplicity_evaluator_program_id,
            self.redemption_capability_program_id,
            self.finite_transition_program_id,
        ];
        if self.version != ELEMENTS_CONSENSUS_CONFIGURATION_VERSION_V2
            || self.child_genesis == [0; 32]
            || self.dynamic_epoch_length == 0
            || self.classification.base_asset_id == [0; 32]
            || self.classification.policy_asset_id == [0; 32]
            || self.classification.base_asset_id == self.classification.policy_asset_id
            || self.classification.redemption_inventory_script_sha256 == [0; 32]
            || self.classification.reserve_script_sha256 == [0; 32]
            || self.quote_atoms_per_whole_base == 0
            || ids.iter().any(|id| ProgramId::from_bytes(*id).is_err())
            || ids
                .iter()
                .enumerate()
                .any(|(index, id)| ids[..index].contains(id))
            || self.finite_configuration_hash == [0; 32]
            || self.state_authority_asset_id == [0; 32]
            || self.state_authority_value == 0
            || self.covenant_commitment == [0; 32]
        {
            return Err(FullPatchedElementsErrorV2::TransactionConsensus);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullPatchedElementsErrorV2> {
        self.validate()?;
        canonical_full_elements_options()
            .serialize(self)
            .map_err(|_| FullPatchedElementsErrorV2::TransactionConsensus)
    }

    pub fn commitment(&self) -> Result<Hash32, FullPatchedElementsErrorV2> {
        let bytes = self.canonical_bytes()?;
        let tag = Sha256::digest(b"ECX/elements-consensus-configuration/v2");
        let mut preimage = Vec::with_capacity(64 + bytes.len());
        preimage.extend_from_slice(&tag);
        preimage.extend_from_slice(&tag);
        preimage.extend_from_slice(&bytes);
        Ok(Sha256::digest(preimage).into())
    }
}

pub fn decode_elements_consensus_configuration_v2(
    bytes: &[u8],
) -> Result<ElementsConsensusConfigurationV2, FullPatchedElementsErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_ELEMENTS_CONSENSUS_CONFIGURATION_BYTES_V2 {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    let configuration: ElementsConsensusConfigurationV2 = canonical_full_elements_options()
        .deserialize(bytes)
        .map_err(|_| FullPatchedElementsErrorV2::TransactionConsensus)?;
    if configuration.canonical_bytes()? != bytes {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    Ok(configuration)
}

fn canonical_full_elements_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchedElementsBlockExecutionWitnessV2 {
    pub transaction_utxos: Vec<ElementsTransactionUtxoWitnessV2>,
    pub transaction_kernels: Vec<ElementsTransactionKernelWitnessV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchedElementsEconomicBlockExecutionWitnessV2 {
    pub consensus: PatchedElementsBlockExecutionWitnessV2,
    pub transaction_economics: Vec<ElementsTransactionEconomicWitnessV2>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullPatchedElementsStatementV2 {
    pub block_hash: Hash32,
    pub bmm_critical_hash: Hash32,
    pub previous_utxo_root: ElementsSparseUtxoNodeV2,
    pub next_utxo_root: ElementsSparseUtxoNodeV2,
    pub previous_parent_state: BmmL1StateV2,
    pub next_parent_state: BmmL1StateV2,
    pub previous_exchange_state_root: Hash32,
    pub next_exchange_state_root: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullPatchedElementsEconomicStatementV2 {
    pub consensus: FullPatchedElementsStatementV2,
    pub source_configuration_commitment: Hash32,
    pub previous_economic_root: ElementsSparseEconomicNodeV2,
    pub next_economic_root: ElementsSparseEconomicNodeV2,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub previous_header_state_commitment: Hash32,
    pub next_header_state_commitment: Hash32,
    pub source_tip_height: u64,
    pub source_tip_mtp: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullPatchedElementsConversionStatementV2 {
    pub economic: FullPatchedElementsEconomicStatementV2,
    pub covenant_commitment: Hash32,
    pub redemption_capability_commitment: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElementsRedemptionCapabilityV2 {
    /// Exact deployed covenant whose current redemption path was executed.
    pub covenant_commitment: Hash32,
    /// Commitment to the proof-carrying execution and authenticated controls.
    pub proof_commitment: Hash32,
}

/// Mandatory boundary for proving that the final inventory/reserve covenant
/// can execute a canonical redemption under the authenticated MTP and current
/// pause/timelock/governance state. A nonzero host assertion is not an
/// implementation of this trait for a release guest.
pub trait ElementsRedemptionCapabilityVerifierV2 {
    fn verify_current_redemption_capability(
        &self,
        block: &PatchedElementsBlockV2,
        state: &FullPatchedElementsEconomicStatementV2,
    ) -> Result<ElementsRedemptionCapabilityV2, FullPatchedElementsErrorV2>;
}

pub const ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_VERSION_V2: u8 = 1;
pub const ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_BYTES_V2: usize = 273;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElementsRedemptionCapabilityPublicValuesV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub covenant_commitment: Hash32,
    pub block_hash: Hash32,
    pub state_root: Hash32,
    pub utxo_root: Hash32,
    pub economic_root: Hash32,
    pub exchange_state_root: Hash32,
    pub source_tip_height: u64,
    pub source_tip_mtp: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
}

impl ElementsRedemptionCapabilityPublicValuesV2 {
    pub fn canonical_bytes(self) -> [u8; ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_BYTES_V2] {
        let mut out = Vec::with_capacity(ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_BYTES_V2);
        out.push(self.version);
        for hash in [
            self.source_configuration_commitment,
            self.covenant_commitment,
            self.block_hash,
            self.state_root,
            self.utxo_root,
            self.economic_root,
            self.exchange_state_root,
        ] {
            out.extend_from_slice(&hash);
        }
        out.extend_from_slice(&self.source_tip_height.to_be_bytes());
        out.extend_from_slice(&self.source_tip_mtp.to_be_bytes());
        out.extend_from_slice(&self.outstanding_base_atoms.to_be_bytes());
        out.extend_from_slice(&self.redeemable_reserve_quote_atoms.to_be_bytes());
        out.try_into().expect("fixed redemption capability journal")
    }
}

pub fn decode_elements_redemption_capability_public_values_v2(
    bytes: &[u8],
) -> Result<ElementsRedemptionCapabilityPublicValuesV2, FullPatchedElementsErrorV2> {
    if bytes.len() != ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_BYTES_V2
        || bytes[0] != ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_VERSION_V2
    {
        return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
    }
    let mut offset = 1usize;
    let mut read_hash = || {
        let value = bytes[offset..offset + 32]
            .try_into()
            .expect("checked capability journal length");
        offset += 32;
        value
    };
    let public = ElementsRedemptionCapabilityPublicValuesV2 {
        version: bytes[0],
        source_configuration_commitment: read_hash(),
        covenant_commitment: read_hash(),
        block_hash: read_hash(),
        state_root: read_hash(),
        utxo_root: read_hash(),
        economic_root: read_hash(),
        exchange_state_root: read_hash(),
        source_tip_height: u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("checked capability journal length"),
        ),
        source_tip_mtp: u64::from_be_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .expect("checked capability journal length"),
        ),
        outstanding_base_atoms: u128::from_be_bytes(
            bytes[offset + 16..offset + 32]
                .try_into()
                .expect("checked capability journal length"),
        ),
        redeemable_reserve_quote_atoms: u128::from_be_bytes(
            bytes[offset + 32..offset + 48]
                .try_into()
                .expect("checked capability journal length"),
        ),
    };
    if public.source_configuration_commitment == [0; 32]
        || public.covenant_commitment == [0; 32]
        || public.block_hash == [0; 32]
        || public.state_root == [0; 32]
        || public.utxo_root == [0; 32]
        || public.economic_root == [0; 32]
        || public.exchange_state_root == [0; 32]
        || public.source_tip_height == 0
        || public.source_tip_mtp == 0
        || public.outstanding_base_atoms == 0
        || public.canonical_bytes() != bytes
    {
        return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
    }
    Ok(public)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsRedemptionCapabilityReceiptBindingV2 {
    pub public_values: Vec<u8>,
    pub proof_marker: Vec<u8>,
}

pub trait ElementsRedemptionCapabilityReceiptVerifierV2 {
    fn verify(
        &self,
        program_id: Hash32,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), FullPatchedElementsErrorV2>;
}

/// Recursive boundary for the separately reviewed redemption-capability
/// relation. The receipt must prove capability for the exact terminal roots,
/// MTP, totals, configuration and covenant; no host boolean enters the claim.
pub struct ProofCarryingElementsRedemptionCapabilityVerifierV2<'a, V> {
    pub program_id: Hash32,
    pub covenant_commitment: Hash32,
    pub receipt: &'a ElementsRedemptionCapabilityReceiptBindingV2,
    pub verifier: &'a V,
}

impl<V: ElementsRedemptionCapabilityReceiptVerifierV2> ElementsRedemptionCapabilityVerifierV2
    for ProofCarryingElementsRedemptionCapabilityVerifierV2<'_, V>
{
    fn verify_current_redemption_capability(
        &self,
        block: &PatchedElementsBlockV2,
        state: &FullPatchedElementsEconomicStatementV2,
    ) -> Result<ElementsRedemptionCapabilityV2, FullPatchedElementsErrorV2> {
        if ProgramId::from_bytes(self.program_id).is_err()
            || self.covenant_commitment == [0; 32]
            || self.receipt.proof_marker.is_empty()
            || self.receipt.proof_marker.len() > 256
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        let public = ElementsRedemptionCapabilityPublicValuesV2 {
            version: ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_VERSION_V2,
            source_configuration_commitment: state.source_configuration_commitment,
            covenant_commitment: self.covenant_commitment,
            block_hash: block
                .header
                .block_hash()
                .map_err(|_| FullPatchedElementsErrorV2::BlockConsensus)?,
            state_root: state.next_state_root,
            utxo_root: state.consensus.next_utxo_root.hash,
            economic_root: state.next_economic_root.hash,
            exchange_state_root: state.consensus.next_exchange_state_root,
            source_tip_height: state.source_tip_height,
            source_tip_mtp: state.source_tip_mtp,
            outstanding_base_atoms: state.outstanding_base_atoms,
            redeemable_reserve_quote_atoms: state.redeemable_reserve_quote_atoms,
        };
        let bytes = public.canonical_bytes();
        if self.receipt.public_values != bytes {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        self.verifier
            .verify(self.program_id, &bytes, &self.receipt.proof_marker)?;
        let mut commitment_preimage =
            Vec::with_capacity(64 + ELEMENTS_REDEMPTION_CAPABILITY_PUBLIC_VALUES_BYTES_V2);
        commitment_preimage.extend_from_slice(b"ECX/redemption-capability-receipt/v2");
        commitment_preimage.extend_from_slice(&self.program_id);
        commitment_preimage.extend_from_slice(&bytes);
        Ok(ElementsRedemptionCapabilityV2 {
            covenant_commitment: self.covenant_commitment,
            proof_commitment: Sha256::digest(commitment_preimage).into(),
        })
    }
}

/// Breaking, unreleased journal revision: version 1 omitted the BMM frontier,
/// and version 2 omitted the child MTP/DynaFed frontier. Old journals cannot
/// establish continuity; checkpoint, transition and adapter guests need new IDs.
pub const FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_VERSION_V2: u8 = 3;
pub const FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2: usize = 529;
pub const FULL_ELEMENTS_CONVERSION_TRANSITION_PUBLIC_VALUES_BYTES_V2: usize =
    FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2 + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullElementsEconomicTransitionPublicValuesV2 {
    pub version: u8,
    pub source_configuration_commitment: Hash32,
    pub block_hash: Hash32,
    pub bmm_critical_hash: Hash32,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub previous_utxo_root: Hash32,
    pub next_utxo_root: Hash32,
    pub previous_economic_root: Hash32,
    pub next_economic_root: Hash32,
    pub previous_exchange_state_root: Hash32,
    pub next_exchange_state_root: Hash32,
    pub previous_parent_bmm_state_commitment: Hash32,
    pub next_parent_bmm_state_commitment: Hash32,
    pub previous_header_state_commitment: Hash32,
    pub next_header_state_commitment: Hash32,
    pub source_tip_height: u64,
    pub source_tip_mtp: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullElementsConversionTransitionPublicValuesV2 {
    pub economic: FullElementsEconomicTransitionPublicValuesV2,
    pub covenant_commitment: Hash32,
    pub redemption_capability_commitment: Hash32,
}

impl FullElementsConversionTransitionPublicValuesV2 {
    pub fn canonical_bytes(
        self,
    ) -> [u8; FULL_ELEMENTS_CONVERSION_TRANSITION_PUBLIC_VALUES_BYTES_V2] {
        let mut out =
            Vec::with_capacity(FULL_ELEMENTS_CONVERSION_TRANSITION_PUBLIC_VALUES_BYTES_V2);
        out.extend_from_slice(&self.economic.canonical_bytes());
        out.extend_from_slice(&self.covenant_commitment);
        out.extend_from_slice(&self.redemption_capability_commitment);
        out.try_into()
            .expect("fixed full-Elements conversion journal length")
    }
}

impl FullElementsEconomicTransitionPublicValuesV2 {
    pub fn canonical_bytes(self) -> [u8; FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2] {
        let mut out = Vec::with_capacity(FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2);
        out.push(self.version);
        for hash in [
            self.source_configuration_commitment,
            self.block_hash,
            self.bmm_critical_hash,
            self.previous_state_root,
            self.next_state_root,
            self.previous_utxo_root,
            self.next_utxo_root,
            self.previous_economic_root,
            self.next_economic_root,
            self.previous_exchange_state_root,
            self.next_exchange_state_root,
            self.previous_parent_bmm_state_commitment,
            self.next_parent_bmm_state_commitment,
            self.previous_header_state_commitment,
            self.next_header_state_commitment,
        ] {
            out.extend_from_slice(&hash);
        }
        out.extend_from_slice(&self.source_tip_height.to_be_bytes());
        out.extend_from_slice(&self.source_tip_mtp.to_be_bytes());
        out.extend_from_slice(&self.outstanding_base_atoms.to_be_bytes());
        out.extend_from_slice(&self.redeemable_reserve_quote_atoms.to_be_bytes());
        out.try_into().expect("fixed full-Elements journal length")
    }
}

pub fn full_elements_economic_transition_public_values_v2(
    statement: &FullPatchedElementsEconomicStatementV2,
) -> Result<FullElementsEconomicTransitionPublicValuesV2, FullPatchedElementsErrorV2> {
    let public = FullElementsEconomicTransitionPublicValuesV2 {
        version: FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_VERSION_V2,
        source_configuration_commitment: statement.source_configuration_commitment,
        block_hash: statement.consensus.block_hash,
        bmm_critical_hash: statement.consensus.bmm_critical_hash,
        previous_state_root: statement.previous_state_root,
        next_state_root: statement.next_state_root,
        previous_utxo_root: statement.consensus.previous_utxo_root.hash,
        next_utxo_root: statement.consensus.next_utxo_root.hash,
        previous_economic_root: statement.previous_economic_root.hash,
        next_economic_root: statement.next_economic_root.hash,
        previous_exchange_state_root: statement.consensus.previous_exchange_state_root,
        next_exchange_state_root: statement.consensus.next_exchange_state_root,
        previous_parent_bmm_state_commitment: bmm_l1_state_commitment_v2(
            &statement.consensus.previous_parent_state,
        )
        .map_err(|_| FullPatchedElementsErrorV2::BlockConsensus)?,
        next_parent_bmm_state_commitment: bmm_l1_state_commitment_v2(
            &statement.consensus.next_parent_state,
        )
        .map_err(|_| FullPatchedElementsErrorV2::BlockConsensus)?,
        previous_header_state_commitment: statement.previous_header_state_commitment,
        next_header_state_commitment: statement.next_header_state_commitment,
        source_tip_height: statement.source_tip_height,
        source_tip_mtp: statement.source_tip_mtp,
        outstanding_base_atoms: statement.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: statement.redeemable_reserve_quote_atoms,
    };
    validate_full_elements_economic_transition_public_values_v2(public)?;
    Ok(public)
}

fn validate_full_elements_economic_transition_public_values_v2(
    public: FullElementsEconomicTransitionPublicValuesV2,
) -> Result<(), FullPatchedElementsErrorV2> {
    if public.version != FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_VERSION_V2
        || public.source_tip_height == 0
        || public.source_tip_mtp == 0
        || public.outstanding_base_atoms == 0
        || [
            public.source_configuration_commitment,
            public.block_hash,
            public.bmm_critical_hash,
            public.previous_state_root,
            public.next_state_root,
            public.previous_utxo_root,
            public.next_utxo_root,
            public.previous_economic_root,
            public.next_economic_root,
            public.previous_exchange_state_root,
            public.next_exchange_state_root,
            public.previous_parent_bmm_state_commitment,
            public.next_parent_bmm_state_commitment,
            public.previous_header_state_commitment,
            public.next_header_state_commitment,
        ]
        .contains(&[0; 32])
    {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    Ok(())
}

pub fn decode_full_elements_economic_transition_public_values_v2(
    bytes: &[u8],
) -> Result<FullElementsEconomicTransitionPublicValuesV2, FullPatchedElementsErrorV2> {
    if bytes.len() != FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2
        || bytes[0] != FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_VERSION_V2
    {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    let mut offset = 1usize;
    let mut read_hash = || {
        let value: Hash32 = bytes[offset..offset + 32]
            .try_into()
            .expect("checked journal length");
        offset += 32;
        value
    };
    let source_configuration_commitment = read_hash();
    let block_hash = read_hash();
    let bmm_critical_hash = read_hash();
    let previous_state_root = read_hash();
    let next_state_root = read_hash();
    let previous_utxo_root = read_hash();
    let next_utxo_root = read_hash();
    let previous_economic_root = read_hash();
    let next_economic_root = read_hash();
    let previous_exchange_state_root = read_hash();
    let next_exchange_state_root = read_hash();
    let previous_parent_bmm_state_commitment = read_hash();
    let next_parent_bmm_state_commitment = read_hash();
    let previous_header_state_commitment = read_hash();
    let next_header_state_commitment = read_hash();
    let source_tip_height = u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked journal length"),
    );
    offset += 8;
    let source_tip_mtp = u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked journal length"),
    );
    offset += 8;
    let outstanding_base_atoms = u128::from_be_bytes(
        bytes[offset..offset + 16]
            .try_into()
            .expect("checked journal length"),
    );
    offset += 16;
    let redeemable_reserve_quote_atoms = u128::from_be_bytes(
        bytes[offset..offset + 16]
            .try_into()
            .expect("checked journal length"),
    );
    let public = FullElementsEconomicTransitionPublicValuesV2 {
        version: bytes[0],
        source_configuration_commitment,
        block_hash,
        bmm_critical_hash,
        previous_state_root,
        next_state_root,
        previous_utxo_root,
        next_utxo_root,
        previous_economic_root,
        next_economic_root,
        previous_exchange_state_root,
        next_exchange_state_root,
        previous_parent_bmm_state_commitment,
        next_parent_bmm_state_commitment,
        previous_header_state_commitment,
        next_header_state_commitment,
        source_tip_height,
        source_tip_mtp,
        outstanding_base_atoms,
        redeemable_reserve_quote_atoms,
    };
    validate_full_elements_economic_transition_public_values_v2(public)?;
    if public.canonical_bytes() != bytes {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    Ok(public)
}

pub fn decode_full_elements_conversion_transition_public_values_v2(
    bytes: &[u8],
) -> Result<FullElementsConversionTransitionPublicValuesV2, FullPatchedElementsErrorV2> {
    if bytes.len() != FULL_ELEMENTS_CONVERSION_TRANSITION_PUBLIC_VALUES_BYTES_V2 {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    let economic = decode_full_elements_economic_transition_public_values_v2(
        &bytes[..FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2],
    )?;
    let covenant_offset = FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2;
    let proof_offset = covenant_offset + 32;
    let covenant_commitment = bytes[covenant_offset..proof_offset]
        .try_into()
        .expect("checked conversion journal length");
    let redemption_capability_commitment = bytes[proof_offset..]
        .try_into()
        .expect("checked conversion journal length");
    if covenant_commitment == [0; 32] || redemption_capability_commitment == [0; 32] {
        return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
    }
    let public = FullElementsConversionTransitionPublicValuesV2 {
        economic,
        covenant_commitment,
        redemption_capability_commitment,
    };
    if public.canonical_bytes() != bytes {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    Ok(public)
}

/// Canonical complete-state identity used by recursive full-Elements
/// checkpoints. Counts and economic totals are included as well as tree hashes
/// so malformed aggregate-carrying nodes cannot alias a valid state.
pub fn full_elements_economic_state_root_v2(
    utxo_root: ElementsSparseUtxoNodeV2,
    economic_root: ElementsSparseEconomicNodeV2,
    exchange_state_root: Hash32,
) -> Result<Hash32, FullPatchedElementsErrorV2> {
    if utxo_root.aggregate.count != economic_root.aggregate.count || exchange_state_root == [0; 32]
    {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    let mut payload = Vec::with_capacity(160);
    payload.extend_from_slice(b"ECX/full-elements-economic-state/v2");
    payload.extend_from_slice(&utxo_root.hash);
    payload.extend_from_slice(&utxo_root.aggregate.count.to_be_bytes());
    payload.extend_from_slice(&economic_root.hash);
    payload.extend_from_slice(&economic_root.aggregate.count.to_be_bytes());
    payload.extend_from_slice(&economic_root.aggregate.outstanding_base_atoms.to_be_bytes());
    payload.extend_from_slice(
        &economic_root
            .aggregate
            .redeemable_reserve_quote_atoms
            .to_be_bytes(),
    );
    payload.extend_from_slice(&exchange_state_root);
    Ok(Sha256::digest(payload).into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FullPatchedElementsErrorV2 {
    #[error("patched Elements block or BMM relation failed")]
    BlockConsensus,
    #[error("patched Elements DynaFed context or authorization failed")]
    HeaderAuthorization,
    #[error("patched Elements transaction witness sequence failed")]
    TransactionConsensus,
    #[error("patched Elements ECX state-root transition failed")]
    ExchangeStateTransition,
}

/// Mandatory block-signing boundary. The verifier receives the actual patched
/// header hash; an upstream header hash omitting ECX/BMM extensions is invalid.
pub trait PatchedElementsBlockAuthorizationVerifierV2 {
    fn verify_dynafed_authorization(
        &self,
        patched_header_hash: Hash32,
        signblock_challenge: &elements::Script,
        signblock_witness: &[Vec<u8>],
    ) -> Result<(), FullPatchedElementsErrorV2>;
}

/// Concrete mirror of Elements Core's `CheckProofGeneric` DynaFed branch.
/// Signatures commit the exact patched header hash and must carry SIGHASH_ALL.
#[derive(Clone, Copy, Debug, Default)]
pub struct FullPatchedElementsBlockAuthorizationVerifierV2;

impl PatchedElementsBlockAuthorizationVerifierV2
    for FullPatchedElementsBlockAuthorizationVerifierV2
{
    fn verify_dynafed_authorization(
        &self,
        patched_header_hash: Hash32,
        signblock_challenge: &elements::Script,
        signblock_witness: &[Vec<u8>],
    ) -> Result<(), FullPatchedElementsErrorV2> {
        let checker = BlockHeaderEcdsaCheckerV2 {
            digest: patched_header_hash,
        };
        verify_native_witness_program_with_checker_v2(
            signblock_challenge.as_bytes(),
            signblock_witness,
            ScriptLockContextV2 {
                alpha_drivechain: false,
                transaction_version: 2,
                transaction_lock_time: 0,
                input_sequence: 0,
                check_lock_time_verify: false,
                check_sequence_verify: false,
                null_fail: false,
                null_dummy: true,
                discourage_upgradable_nops: false,
                const_script_code: false,
                witness_v0: false,
            },
            WitnessV0FlagsV2 {
                require_minimal_if: false,
                require_compressed_public_key: false,
                strict_der: true,
                strict_encoding: true,
                low_s: true,
            },
            &checker,
        )
        .map_err(|_| FullPatchedElementsErrorV2::HeaderAuthorization)
    }
}

struct BlockHeaderEcdsaCheckerV2 {
    digest: Hash32,
}

impl ScriptSignatureCheckerV2 for BlockHeaderEcdsaCheckerV2 {
    fn check_ecdsa_signature(
        &self,
        signature_with_hash_type: &[u8],
        public_key: &[u8],
        _: &[u8],
        _: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        if signature_with_hash_type.last() != Some(&1) {
            return Ok(false);
        }
        let der = &signature_with_hash_type[..signature_with_hash_type.len() - 1];
        let signature = bitcoin::secp256k1::ecdsa::Signature::from_der(der)
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return Ok(false);
        }
        let key = bitcoin::secp256k1::PublicKey::from_slice(public_key)
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let message = bitcoin::secp256k1::Message::from_digest(self.digest);
        Ok(bitcoin::secp256k1::Secp256k1::verification_only()
            .verify_ecdsa(&message, &signature, &key)
            .is_ok())
    }
}

/// Mandatory ECX transition boundary. This is where the recursive SP1 receipt,
/// singleton transaction and exact public successor root are tied together.
pub trait PatchedExchangeStateTransitionVerifierV2 {
    fn verify_exchange_state_transition(
        &self,
        block: &PatchedElementsBlockV2,
        previous_exchange_state_root: Hash32,
        next_exchange_state_root: Hash32,
    ) -> Result<(), FullPatchedElementsErrorV2>;
}

pub const FINITE_V18_COVENANT_STATE_VERSION: u32 = 4;
pub const FINITE_V18_SIMPLICITY_LEAF_VERSION: u8 = 0xbe;
pub const FINITE_V18_NUMS_INTERNAL_KEY: Hash32 = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Exact 468-byte public state preimage consumed by the finite V18 covenant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteV18CovenantStateV2 {
    pub version: u32,
    pub sequence: u64,
    pub private_state_root: Hash32,
    pub encrypted_availability_root: Hash32,
    pub forced_inbox_root: Hash32,
    pub deposit_inbox_root: Hash32,
    pub configuration_hash: Hash32,
    pub bond_state_root: Hash32,
    pub funding_state_root: Hash32,
    pub active_order_risk_root: Hash32,
    pub position_risk_root: Hash32,
    pub bond_inbox_head_root: Hash32,
    pub bond_inbox_entry_count: u64,
    pub bond_inbox_processed_root: Hash32,
    pub bond_inbox_processed_cursor: u64,
    pub bond_inbox_outcome_root: Hash32,
    pub bond_inbox_outcome_count: u64,
    pub matcher_execution_sequence: u64,
    pub last_transition_sidechain_height: u64,
}

impl FiniteV18CovenantStateV2 {
    pub fn hash(
        self,
        public_state_domain_sha256: Hash32,
    ) -> Result<Hash32, FullPatchedElementsErrorV2> {
        let required_roots = [
            self.private_state_root,
            self.encrypted_availability_root,
            self.forced_inbox_root,
            self.deposit_inbox_root,
            self.configuration_hash,
            self.bond_state_root,
            self.funding_state_root,
            self.active_order_risk_root,
            self.position_risk_root,
            self.bond_inbox_head_root,
            self.bond_inbox_processed_root,
            self.bond_inbox_outcome_root,
        ];
        if self.version != FINITE_V18_COVENANT_STATE_VERSION
            || public_state_domain_sha256 == [0; 32]
            || required_roots.contains(&[0; 32])
            || self.bond_inbox_processed_cursor > self.bond_inbox_entry_count
            || self.bond_inbox_outcome_count != self.bond_inbox_processed_cursor
            || self.last_transition_sidechain_height == 0
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        let mut preimage = Vec::with_capacity(468);
        preimage.extend_from_slice(&public_state_domain_sha256);
        preimage.extend_from_slice(&self.version.to_be_bytes());
        preimage.extend_from_slice(&self.sequence.to_be_bytes());
        preimage.extend_from_slice(&self.private_state_root);
        preimage.extend_from_slice(&self.encrypted_availability_root);
        preimage.extend_from_slice(&self.forced_inbox_root);
        preimage.extend_from_slice(&self.deposit_inbox_root);
        preimage.extend_from_slice(&self.configuration_hash);
        preimage.extend_from_slice(&self.bond_state_root);
        preimage.extend_from_slice(&self.funding_state_root);
        preimage.extend_from_slice(&self.active_order_risk_root);
        preimage.extend_from_slice(&self.position_risk_root);
        preimage.extend_from_slice(&self.bond_inbox_head_root);
        preimage.extend_from_slice(&self.bond_inbox_entry_count.to_be_bytes());
        preimage.extend_from_slice(&self.bond_inbox_processed_root);
        preimage.extend_from_slice(&self.bond_inbox_processed_cursor.to_be_bytes());
        preimage.extend_from_slice(&self.bond_inbox_outcome_root);
        preimage.extend_from_slice(&self.bond_inbox_outcome_count.to_be_bytes());
        preimage.extend_from_slice(&self.matcher_execution_sequence.to_be_bytes());
        preimage.extend_from_slice(&self.last_transition_sidechain_height.to_be_bytes());
        if preimage.len() != 468 {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        Ok(Sha256::digest(preimage).into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteV18StateRendererV2 {
    pub public_state_domain_sha256: Hash32,
    pub state_node_domain_sha256: Hash32,
    pub transition_cmr: Hash32,
    pub incremental_activation_cmr: Hash32,
    pub keyless_internal_key: Hash32,
    pub simplicity_leaf_version: u8,
}

fn tapbranch_elements_v2(left: TapNodeHash, right: TapNodeHash) -> TapNodeHash {
    let mut engine = TapNodeHash::engine();
    if left.as_byte_array() < right.as_byte_array() {
        engine.input(left.as_ref());
        engine.input(right.as_ref());
    } else {
        engine.input(right.as_ref());
        engine.input(left.as_ref());
    }
    TapNodeHash::from_engine(engine)
}

impl FiniteV18StateRendererV2 {
    pub fn render(
        self,
        state: FiniteV18CovenantStateV2,
    ) -> Result<elements::Script, FullPatchedElementsErrorV2> {
        let identities = [
            self.public_state_domain_sha256,
            self.state_node_domain_sha256,
            self.transition_cmr,
            self.incremental_activation_cmr,
        ];
        if identities.contains(&[0; 32])
            || identities
                .iter()
                .enumerate()
                .any(|(index, value)| identities[..index].contains(value))
            || self.keyless_internal_key != FINITE_V18_NUMS_INTERNAL_KEY
            || self.simplicity_leaf_version != FINITE_V18_SIMPLICITY_LEAF_VERSION
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        let state_hash = state.hash(self.public_state_domain_sha256)?;
        let mut state_preimage = [0_u8; 64];
        state_preimage[..32].copy_from_slice(&self.state_node_domain_sha256);
        state_preimage[32..].copy_from_slice(&state_hash);
        let state_node = TapNodeHash::from_byte_array(Sha256::digest(state_preimage).into());
        let leaf_version = LeafVersion::from_u8(self.simplicity_leaf_version)
            .map_err(|_| FullPatchedElementsErrorV2::ExchangeStateTransition)?;
        let transition_leaf = TapNodeHash::from_byte_array(
            TapLeafHash::from_script(
                &elements::Script::from(self.transition_cmr.to_vec()),
                leaf_version,
            )
            .to_byte_array(),
        );
        let activation_leaf = TapNodeHash::from_byte_array(
            TapLeafHash::from_script(
                &elements::Script::from(self.incremental_activation_cmr.to_vec()),
                leaf_version,
            )
            .to_byte_array(),
        );
        let activation_or_state = tapbranch_elements_v2(activation_leaf, state_node);
        let root = tapbranch_elements_v2(transition_leaf, activation_or_state);
        let internal_key = XOnlyPublicKey::from_slice(&self.keyless_internal_key)
            .map_err(|_| FullPatchedElementsErrorV2::ExchangeStateTransition)?;
        Ok(elements::Script::new_v1_p2tr(
            &Secp256k1::verification_only(),
            internal_key,
            Some(root),
        ))
    }
}

/// Authenticated node context for one finite-V18 successor. The caller must
/// derive the state hashes from the exact current/successor singleton state
/// preimages and the exchange roots from the active block index and candidate
/// header. None of these values may come from the proof annex itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FiniteV18ExchangeProofContextV2 {
    pub program_id: ProgramId,
    pub configuration_hash: Hash32,
    pub renderer: FiniteV18StateRendererV2,
    pub current_state: FiniteV18CovenantStateV2,
    pub next_state: FiniteV18CovenantStateV2,
    pub child_genesis: Hash32,
    pub previous_state_outpoint: OutPoint,
    pub previous_state_output: TxOut,
    pub state_authority_asset_id: Hash32,
    pub state_authority_value: u64,
}

/// Exact mirror of the node's `ComputeStateUtxoRoot`: the checkpoint is a
/// commitment to network genesis, consensus-order outpoint bytes and the full
/// serialized Elements TxOut (including asset/value/nonce/script/witness).
pub fn compute_state_utxo_root_v2(
    child_genesis: Hash32,
    outpoint: OutPoint,
    output: &TxOut,
) -> Hash32 {
    let mut payload = Vec::with_capacity(100);
    payload.extend_from_slice(&child_genesis);
    payload.extend_from_slice(&outpoint.txid.to_byte_array());
    payload.extend_from_slice(&outpoint.vout.to_le_bytes());
    payload.extend_from_slice(&Sha256::digest(serialize(output)));
    let tag = Sha256::digest(b"ECX/header-state/v1");
    let mut preimage = Vec::with_capacity(64 + payload.len());
    preimage.extend_from_slice(&tag);
    preimage.extend_from_slice(&tag);
    preimage.extend_from_slice(&payload);
    Sha256::digest(preimage).into()
}

fn is_p2tr_state_output_v2(output: &TxOut) -> bool {
    let script = output.script_pubkey.as_bytes();
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

/// Concrete finite-V18 Groth16 boundary. It locates exactly one V5 proof annex
/// in the block, binds it to the transaction carrying it and to independently
/// authenticated state/header context, then invokes the production SP1
/// Groth16 backend. This replaces digest-only or test-callback acceptance.
pub struct FiniteV18Groth16ExchangeStateVerifierV2<'a, B> {
    pub backend: &'a B,
    pub context: FiniteV18ExchangeProofContextV2,
}

impl<B: Groth16Sp1Backend> PatchedExchangeStateTransitionVerifierV2
    for FiniteV18Groth16ExchangeStateVerifierV2<'_, B>
{
    fn verify_exchange_state_transition(
        &self,
        block: &PatchedElementsBlockV2,
        previous_exchange_state_root: Hash32,
        next_exchange_state_root: Hash32,
    ) -> Result<(), FullPatchedElementsErrorV2> {
        let current_state_hash = self
            .context
            .current_state
            .hash(self.context.renderer.public_state_domain_sha256)?;
        let next_state_hash = self
            .context
            .next_state
            .hash(self.context.renderer.public_state_domain_sha256)?;
        let prior_state_script = self.context.renderer.render(self.context.current_state)?;
        let successor_state_script = self.context.renderer.render(self.context.next_state)?;
        if self.context.configuration_hash == [0; 32]
            || self.context.child_genesis == [0; 32]
            || self.context.state_authority_asset_id == [0; 32]
            || self.context.state_authority_value == 0
            || self.context.current_state.configuration_hash != self.context.configuration_hash
            || self.context.next_state.configuration_hash != self.context.configuration_hash
            || self.context.current_state.sequence == u64::MAX
            || self.context.next_state.sequence != self.context.current_state.sequence + 1
            || compute_state_utxo_root_v2(
                self.context.child_genesis,
                self.context.previous_state_outpoint,
                &self.context.previous_state_output,
            ) != previous_exchange_state_root
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }

        let expected_asset = elements::AssetId::from_slice(&self.context.state_authority_asset_id)
            .map_err(|_| FullPatchedElementsErrorV2::ExchangeStateTransition)?;
        if self.context.previous_state_output.asset != confidential::Asset::Explicit(expected_asset)
            || self.context.previous_state_output.value
                != confidential::Value::Explicit(self.context.state_authority_value)
            || self.context.previous_state_output.nonce != confidential::Nonce::Null
            || !is_p2tr_state_output_v2(&self.context.previous_state_output)
            || self.context.previous_state_output.script_pubkey != prior_state_script
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }

        let mut transition_index = None;
        for (index, transaction) in block.transactions.iter().enumerate() {
            if transaction
                .input
                .iter()
                .any(|input| input.previous_output == self.context.previous_state_outpoint)
            {
                if transition_index.is_some() {
                    return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
                }
                transition_index = Some(index);
            }
        }
        let transition_index =
            transition_index.ok_or(FullPatchedElementsErrorV2::ExchangeStateTransition)?;
        let transaction = &block.transactions[transition_index];
        if transaction.input.first().map(|input| input.previous_output)
            != Some(self.context.previous_state_outpoint)
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        let successor = transaction
            .output
            .first()
            .ok_or(FullPatchedElementsErrorV2::ExchangeStateTransition)?;
        if successor.asset != confidential::Asset::Explicit(expected_asset)
            || successor.value != confidential::Value::Explicit(self.context.state_authority_value)
            || successor.nonce != confidential::Nonce::Null
            || !is_p2tr_state_output_v2(successor)
            || successor.script_pubkey != successor_state_script
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        let transaction_txid = transaction.txid().to_byte_array();
        let successor_outpoint = OutPoint::new(transaction.txid(), 0);
        if block.transactions[transition_index + 1..]
            .iter()
            .any(|later| {
                later
                    .input
                    .iter()
                    .any(|input| input.previous_output == successor_outpoint)
            })
            || compute_state_utxo_root_v2(self.context.child_genesis, successor_outpoint, successor)
                != next_exchange_state_root
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }

        let annex = transaction.input[0]
            .witness
            .script_witness
            .last()
            .filter(|item| item.first() == Some(&0x50))
            .ok_or(FullPatchedElementsErrorV2::ExchangeStateTransition)?;
        let parsed = parse_groth16_public_values_v5_annex(annex)
            .map_err(|_| FullPatchedElementsErrorV2::ExchangeStateTransition)?;
        let additional_v5_annexes = block
            .transactions
            .iter()
            .flat_map(|tx| &tx.input)
            .filter_map(|input| input.witness.script_witness.last())
            .filter(|item| item.first() == Some(&0x50))
            .filter(|item| parse_groth16_public_values_v5_annex(item).is_ok())
            .count();
        if additional_v5_annexes != 1 {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        let values = parsed.public_values;
        if parsed.program_id != self.context.program_id
            || values.configuration_hash != self.context.configuration_hash
            || values.current_state_hash != current_state_hash
            || values.next_state_hash != next_state_hash
            || values.transition_txid_consensus != transaction_txid
            || values.prior_exchange_header_root != previous_exchange_state_root
        {
            return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
        }
        verify_groth16_public_values_v5_annex(
            self.backend,
            annex,
            self.context.program_id,
            parsed.public_values_sha256,
        )
        .map_err(|_| FullPatchedElementsErrorV2::ExchangeStateTransition)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_full_patched_elements_block_v2<
    I: ElementsInputVerifierV2,
    A: PatchedElementsBlockAuthorizationVerifierV2,
    E: PatchedExchangeStateTransitionVerifierV2,
>(
    raw_block: &[u8],
    header_context: &PatchedElementsHeaderContextV2,
    initial_utxo_root: ElementsSparseUtxoNodeV2,
    previous_parent_state: &BmmL1StateV2,
    previous_exchange_state_root: Hash32,
    execution_witness: &PatchedElementsBlockExecutionWitnessV2,
    input_verifier: &I,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    authorization_verifier: &A,
    exchange_state_verifier: &E,
    bmm_consensus: &BmmConsensusParametersV2,
) -> Result<FullPatchedElementsStatementV2, FullPatchedElementsErrorV2> {
    let bmm =
        verify_patched_elements_bmm_transition_v2(raw_block, previous_parent_state, bmm_consensus)
            .map_err(|_| FullPatchedElementsErrorV2::BlockConsensus)?;
    let block = PatchedElementsBlockV2::decode(raw_block)
        .map_err(|_| FullPatchedElementsErrorV2::BlockConsensus)?;
    verify_patched_dynafed_header_context_v2(&block, header_context, authorization_verifier)?;
    if execution_witness.transaction_utxos.len() != block.transactions.len()
        || execution_witness.transaction_kernels.len() != block.transactions.len()
    {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    let mut ordered_times: [u32; 11] = header_context
        .previous_11_times
        .clone()
        .try_into()
        .map_err(|_| FullPatchedElementsErrorV2::HeaderAuthorization)?;
    ordered_times.sort_unstable();
    let parent_mtp = ordered_times[5];
    let mut utxo_root = initial_utxo_root;
    for ((transaction, witness), kernel) in block
        .transactions
        .iter()
        .zip(&execution_witness.transaction_utxos)
        .zip(&execution_witness.transaction_kernels)
    {
        utxo_root = apply_elements_transaction_utxos_v2(
            transaction,
            ElementsTransactionSpendContextV2 {
                height: header_context.next_height,
                parent_mtp,
            },
            utxo_root,
            witness,
            kernel,
            input_verifier,
            deposit_verifier,
        )
        .map_err(|_| FullPatchedElementsErrorV2::TransactionConsensus)?;
    }
    let next_exchange_state_root = block
        .header
        .exchange_state_root
        .ok_or(FullPatchedElementsErrorV2::ExchangeStateTransition)?;
    exchange_state_verifier.verify_exchange_state_transition(
        &block,
        previous_exchange_state_root,
        next_exchange_state_root,
    )?;
    Ok(FullPatchedElementsStatementV2 {
        block_hash: bmm.foundation.block_hash,
        bmm_critical_hash: bmm
            .foundation
            .bmm_critical_hash
            .ok_or(FullPatchedElementsErrorV2::BlockConsensus)?,
        previous_utxo_root: initial_utxo_root,
        next_utxo_root: utxo_root,
        previous_parent_state: previous_parent_state.clone(),
        next_parent_state: bmm.next_parent_state,
        previous_exchange_state_root,
        next_exchange_state_root,
    })
}

/// Strong full-block relation used by conversion proofs. It preserves the
/// original consensus statement while additionally proving that every live
/// UTXO has exactly one opened, classified economic leaf and deriving the
/// resulting ECX supply and redeemable policy-asset reserve from that root.
#[allow(clippy::too_many_arguments)]
pub fn verify_full_patched_elements_economic_block_v2<
    I: ElementsInputVerifierV2,
    A: PatchedElementsBlockAuthorizationVerifierV2,
    E: PatchedExchangeStateTransitionVerifierV2,
>(
    raw_block: &[u8],
    source_configuration_commitment: Hash32,
    header_context: &PatchedElementsHeaderContextV2,
    initial_utxo_root: ElementsSparseUtxoNodeV2,
    initial_economic_root: ElementsSparseEconomicNodeV2,
    classification: ElementsEconomicClassificationV2,
    previous_parent_state: &BmmL1StateV2,
    previous_exchange_state_root: Hash32,
    execution_witness: &PatchedElementsEconomicBlockExecutionWitnessV2,
    input_verifier: &I,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    authorization_verifier: &A,
    exchange_state_verifier: &E,
    bmm_consensus: &BmmConsensusParametersV2,
) -> Result<FullPatchedElementsEconomicStatementV2, FullPatchedElementsErrorV2> {
    if source_configuration_commitment == [0; 32] {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    let consensus = verify_full_patched_elements_block_v2(
        raw_block,
        header_context,
        initial_utxo_root,
        previous_parent_state,
        previous_exchange_state_root,
        &execution_witness.consensus,
        input_verifier,
        deposit_verifier,
        authorization_verifier,
        exchange_state_verifier,
        bmm_consensus,
    )?;
    if execution_witness.transaction_economics.len()
        != execution_witness.consensus.transaction_utxos.len()
    {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }

    let mut economic_root = initial_economic_root;
    for (utxo_witness, economic_witness) in execution_witness
        .consensus
        .transaction_utxos
        .iter()
        .zip(&execution_witness.transaction_economics)
    {
        if utxo_witness.spends.len() != economic_witness.spends.len()
            || utxo_witness.creates.len() != economic_witness.creates.len()
        {
            return Err(FullPatchedElementsErrorV2::TransactionConsensus);
        }
        for (utxo, economic) in utxo_witness
            .spends
            .iter()
            .zip(&economic_witness.spends)
            .chain(utxo_witness.creates.iter().zip(&economic_witness.creates))
        {
            if utxo.outpoint != economic.outpoint
                || utxo.old_leaf.as_ref() != economic.old_leaf.as_ref().map(|leaf| &leaf.utxo)
                || utxo.new_leaf.as_ref() != economic.new_leaf.as_ref().map(|leaf| &leaf.utxo)
            {
                return Err(FullPatchedElementsErrorV2::TransactionConsensus);
            }
            economic_root =
                apply_elements_sparse_economic_mutation_v2(economic_root, economic, classification)
                    .map_err(|_| FullPatchedElementsErrorV2::TransactionConsensus)?;
        }
    }
    if economic_root.aggregate.count != consensus.next_utxo_root.aggregate.count {
        return Err(FullPatchedElementsErrorV2::TransactionConsensus);
    }
    let previous_state_root = full_elements_economic_state_root_v2(
        consensus.previous_utxo_root,
        initial_economic_root,
        consensus.previous_exchange_state_root,
    )?;
    let next_state_root = full_elements_economic_state_root_v2(
        consensus.next_utxo_root,
        economic_root,
        consensus.next_exchange_state_root,
    )?;
    let block = PatchedElementsBlockV2::decode(raw_block)
        .map_err(|_| FullPatchedElementsErrorV2::BlockConsensus)?;
    let mut tip_mtp_window = header_context.previous_11_times[1..].to_vec();
    tip_mtp_window.push(block.header.time);
    tip_mtp_window.sort_unstable();
    let source_tip_mtp = u64::from(tip_mtp_window[5]);
    let previous_header_state_commitment = header_context.previous_header_state.commitment()?;
    let next_header_state_commitment = header_context
        .previous_header_state
        .advance(&block)?
        .commitment()?;
    Ok(FullPatchedElementsEconomicStatementV2 {
        source_configuration_commitment,
        outstanding_base_atoms: economic_root.aggregate.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: economic_root.aggregate.redeemable_reserve_quote_atoms,
        consensus,
        previous_economic_root: initial_economic_root,
        next_economic_root: economic_root,
        previous_state_root,
        next_state_root,
        previous_header_state_commitment,
        next_header_state_commitment,
        source_tip_height: u64::from(block.header.height),
        source_tip_mtp,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_full_patched_elements_conversion_block_v2<
    I: ElementsInputVerifierV2,
    A: PatchedElementsBlockAuthorizationVerifierV2,
    E: PatchedExchangeStateTransitionVerifierV2,
    R: ElementsRedemptionCapabilityVerifierV2,
>(
    raw_block: &[u8],
    source_configuration_commitment: Hash32,
    header_context: &PatchedElementsHeaderContextV2,
    initial_utxo_root: ElementsSparseUtxoNodeV2,
    initial_economic_root: ElementsSparseEconomicNodeV2,
    classification: ElementsEconomicClassificationV2,
    previous_parent_state: &BmmL1StateV2,
    previous_exchange_state_root: Hash32,
    execution_witness: &PatchedElementsEconomicBlockExecutionWitnessV2,
    input_verifier: &I,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    authorization_verifier: &A,
    exchange_state_verifier: &E,
    redemption_capability_verifier: &R,
    bmm_consensus: &BmmConsensusParametersV2,
) -> Result<FullPatchedElementsConversionStatementV2, FullPatchedElementsErrorV2> {
    let economic = verify_full_patched_elements_economic_block_v2(
        raw_block,
        source_configuration_commitment,
        header_context,
        initial_utxo_root,
        initial_economic_root,
        classification,
        previous_parent_state,
        previous_exchange_state_root,
        execution_witness,
        input_verifier,
        deposit_verifier,
        authorization_verifier,
        exchange_state_verifier,
        bmm_consensus,
    )?;
    let block = PatchedElementsBlockV2::decode(raw_block)
        .map_err(|_| FullPatchedElementsErrorV2::BlockConsensus)?;
    let capability =
        redemption_capability_verifier.verify_current_redemption_capability(&block, &economic)?;
    if capability.covenant_commitment == [0; 32] || capability.proof_commitment == [0; 32] {
        return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
    }
    Ok(FullPatchedElementsConversionStatementV2 {
        economic,
        covenant_commitment: capability.covenant_commitment,
        redemption_capability_commitment: capability.proof_commitment,
    })
}

pub fn full_elements_conversion_transition_public_values_v2(
    statement: &FullPatchedElementsConversionStatementV2,
) -> Result<FullElementsConversionTransitionPublicValuesV2, FullPatchedElementsErrorV2> {
    if statement.covenant_commitment == [0; 32]
        || statement.redemption_capability_commitment == [0; 32]
    {
        return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
    }
    Ok(FullElementsConversionTransitionPublicValuesV2 {
        economic: full_elements_economic_transition_public_values_v2(&statement.economic)?,
        covenant_commitment: statement.covenant_commitment,
        redemption_capability_commitment: statement.redemption_capability_commitment,
    })
}

pub fn verify_patched_dynafed_header_context_v2<A: PatchedElementsBlockAuthorizationVerifierV2>(
    block: &PatchedElementsBlockV2,
    context: &PatchedElementsHeaderContextV2,
    authorization_verifier: &A,
) -> Result<(), FullPatchedElementsErrorV2> {
    let header = &block.header;
    let state = &context.previous_header_state;
    let (derived_current, derived_full) = state.next_parameters()?;
    state.advance(block)?;
    if context.previous_11_times.len() != 11
        || context.previous_11_times != state.previous_11_times
        || context.previous_block_hash != state.block_hash
        || state.height.checked_add(1) != Some(context.next_height)
        || context.authenticated_adjusted_time != state.authenticated_adjusted_time
        || context.expected_current_dynafed_parameters != derived_current
        || context.expected_full_current_dynafed_parameters != derived_full
        || header.previous_block_hash != context.previous_block_hash
        || header.height != context.next_height
        || header.forced_inbox_root != Some(context.expected_forced_inbox_root)
        || header.deposit_inbox_root != Some(context.expected_deposit_inbox_root)
        || header.ecx_parent_height != Some(context.expected_parent_height)
        || header.forced_processed_cursor != Some(context.expected_forced_processed_cursor)
        || header.deposit_processed_cursor != Some(context.expected_deposit_processed_cursor)
        || header.source_backlog_oldest_parent_height
            != Some(context.expected_source_backlog_oldest_parent_height)
        || header.wire_version & PATCHED_ELEMENTS_RESERVED_DYNAFED_VERSION_MASK_V2 != 0
    {
        return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
    }
    let mut ordered = context.previous_11_times.clone();
    ordered.sort_unstable();
    let future_limit = context
        .authenticated_adjusted_time
        .checked_add(crate::elements_v2::ELEMENTS_MAX_FUTURE_BLOCK_SECONDS_V2)
        .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?;
    if header.time <= ordered[5] || u64::from(header.time) > future_limit {
        return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
    }
    let expected_full = &context.expected_full_current_dynafed_parameters;
    let current = &header.current_dynafed_parameters;
    if current.is_null()
        || current != &context.expected_current_dynafed_parameters
        || expected_full.full().is_none()
        || current.calculate_root() != expected_full.calculate_root()
        || serialize(&header.signblock_witness).len()
            > usize::try_from(
                current
                    .signblock_witness_limit()
                    .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?,
            )
            .map_err(|_| FullPatchedElementsErrorV2::HeaderAuthorization)?
    {
        return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
    }
    validate_proposal(expected_full, &header.proposed_dynafed_parameters)?;
    authorization_verifier.verify_dynafed_authorization(
        header
            .block_hash()
            .map_err(|_| FullPatchedElementsErrorV2::HeaderAuthorization)?,
        current
            .signblockscript()
            .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?,
        &header.signblock_witness,
    )
}

fn validate_proposal(
    current: &Params,
    proposed: &Params,
) -> Result<(), FullPatchedElementsErrorV2> {
    if proposed.is_null() {
        return Ok(());
    }
    // Compact proposals cannot supply the full fedpeg and extension preimage.
    // Unsupported extension changes fail closed until exact PAK policy is bound.
    if !proposed.is_full()
        || !current.is_full()
        || proposed.extension_space() != current.extension_space()
    {
        return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
    }
    if proposed.fedpeg_program() != current.fedpeg_program()
        || proposed.fedpegscript() != current.fedpegscript()
    {
        let program = proposed
            .fedpeg_program()
            .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?;
        let script = proposed
            .fedpegscript()
            .ok_or(FullPatchedElementsErrorV2::HeaderAuthorization)?;
        if !program.is_witness_program() {
            return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
        }
        if program.as_bytes()[0] == 0 {
            let mut expected = vec![0, 32];
            expected.extend_from_slice(&Sha256::digest(script));
            if program.as_bytes() != expected || script.first() == Some(&0x74) {
                return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
            }
        }
    }
    if proposed.signblockscript() != current.signblockscript()
        && !proposed
            .signblockscript()
            .is_some_and(elements::Script::is_witness_program)
    {
        return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
    }
    if let Some(full) = proposed.full() {
        let expected = Params::Full(full.clone());
        if expected.calculate_root() != proposed.calculate_root() {
            return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
        }
    }
    Ok(())
}

impl From<PatchedElementsCodecErrorV2> for FullPatchedElementsErrorV2 {
    fn from(_: PatchedElementsCodecErrorV2) -> Self {
        Self::BlockConsensus
    }
}

impl From<ElementsStateErrorV2> for FullPatchedElementsErrorV2 {
    fn from(_: ElementsStateErrorV2) -> Self {
        Self::TransactionConsensus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements_v2::{
        canonical_empty_elements_utxo_leaf_v2, ElementsTransactionKernelWitnessV2,
    };
    use crate::patched_elements_v2::{
        PatchedElementsHeaderV2, BMM_PROOF_HF_MASK_V2, DEPOSIT_INBOX_HF_MASK_V2,
        DYNAFED_HF_MASK_V2, EXCHANGE_STATE_HF_MASK_V2, FORCED_INBOX_HF_MASK_V2,
        INBOX_CURSOR_HF_MASK_V2,
    };
    use elements::hashes::sha256;
    use std::cell::Cell;

    fn consensus_configuration() -> ElementsConsensusConfigurationV2 {
        ElementsConsensusConfigurationV2 {
            version: ELEMENTS_CONSENSUS_CONFIGURATION_VERSION_V2,
            child_genesis: [20; 32],
            dynamic_epoch_length: 10,
            classification: ElementsEconomicClassificationV2 {
                base_asset_id: [21; 32],
                policy_asset_id: [22; 32],
                redemption_inventory_script_sha256: [23; 32],
                reserve_script_sha256: [24; 32],
            },
            quote_atoms_per_whole_base: 100_000_000,
            bmm_consensus: BmmConsensusParametersV2 {
                pow_limit: bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(
                    0x207f_ffff,
                )),
                target_timespan: 14 * 24 * 60 * 60,
                target_spacing: 600,
                sidechain_slot: 24,
            },
            simplicity_evaluator_program_id: [1; 32],
            redemption_capability_program_id: [2; 32],
            finite_transition_program_id: [3; 32],
            finite_configuration_hash: [25; 32],
            renderer: FiniteV18StateRendererV2 {
                public_state_domain_sha256: [26; 32],
                state_node_domain_sha256: [27; 32],
                transition_cmr: [28; 32],
                incremental_activation_cmr: [29; 32],
                keyless_internal_key: FINITE_V18_NUMS_INTERNAL_KEY,
                simplicity_leaf_version: FINITE_V18_SIMPLICITY_LEAF_VERSION,
            },
            state_authority_asset_id: [30; 32],
            state_authority_value: 1,
            covenant_commitment: [31; 32],
        }
    }

    #[test]
    fn consensus_configuration_is_canonical_network_bound_and_mutation_bound() {
        let configuration = consensus_configuration();
        let bytes = configuration.canonical_bytes().unwrap();
        assert_eq!(
            decode_elements_consensus_configuration_v2(&bytes).unwrap(),
            configuration
        );
        let commitment = configuration.commitment().unwrap();
        assert_ne!(commitment, [0; 32]);
        let mut changed = configuration;
        changed.quote_atoms_per_whole_base += 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut epoch_change = consensus_configuration();
        epoch_change.dynamic_epoch_length += 1;
        assert_ne!(epoch_change.commitment().unwrap(), commitment);
        epoch_change.dynamic_epoch_length = 0;
        assert!(epoch_change.commitment().is_err());
        let mut changed = consensus_configuration();
        changed.bmm_consensus.sidechain_slot += 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        assert!(decode_elements_consensus_configuration_v2(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn economic_transition_journal_is_fixed_round_trips_and_binds_every_field() {
        let public = FullElementsEconomicTransitionPublicValuesV2 {
            version: FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_VERSION_V2,
            source_configuration_commitment: [16; 32],
            block_hash: [1; 32],
            bmm_critical_hash: [2; 32],
            previous_state_root: [3; 32],
            next_state_root: [4; 32],
            previous_utxo_root: [5; 32],
            next_utxo_root: [6; 32],
            previous_economic_root: [7; 32],
            next_economic_root: [8; 32],
            previous_exchange_state_root: [9; 32],
            next_exchange_state_root: [10; 32],
            previous_parent_bmm_state_commitment: [17; 32],
            next_parent_bmm_state_commitment: [18; 32],
            previous_header_state_commitment: [19; 32],
            next_header_state_commitment: [20; 32],
            source_tip_height: 11,
            source_tip_mtp: 12,
            outstanding_base_atoms: 13,
            redeemable_reserve_quote_atoms: 14,
        };
        let bytes = public.canonical_bytes();
        assert_eq!(bytes.len(), 529);
        assert_eq!(
            &bytes[353..385],
            &public.previous_parent_bmm_state_commitment
        );
        assert_eq!(&bytes[385..417], &public.next_parent_bmm_state_commitment);
        assert_eq!(&bytes[417..449], &public.previous_header_state_commitment);
        assert_eq!(&bytes[449..481], &public.next_header_state_commitment);
        assert_eq!(
            bytes.len(),
            FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2
        );
        assert_eq!(
            decode_full_elements_economic_transition_public_values_v2(&bytes).unwrap(),
            public
        );
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            if decode_full_elements_economic_transition_public_values_v2(&changed).is_ok() {
                assert_ne!(changed, bytes);
                assert_ne!(
                    decode_full_elements_economic_transition_public_values_v2(&changed).unwrap(),
                    public
                );
            }
        }
        assert!(decode_full_elements_economic_transition_public_values_v2(
            &bytes[..FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2 - 1]
        )
        .is_err());

        let conversion = FullElementsConversionTransitionPublicValuesV2 {
            economic: public,
            covenant_commitment: [14; 32],
            redemption_capability_commitment: [15; 32],
        };
        let conversion_bytes = conversion.canonical_bytes();
        assert_eq!(conversion_bytes.len(), 593);
        assert_eq!(
            decode_full_elements_conversion_transition_public_values_v2(&conversion_bytes).unwrap(),
            conversion
        );
        // Reconstruct the exact old layouts (version 1; the BMM fields were
        // absent), rather than merely truncating the current journal.
        let mut legacy_economic = bytes[..353].to_vec();
        legacy_economic[0] = 1;
        legacy_economic.extend_from_slice(&bytes[481..]);
        assert_eq!(legacy_economic.len(), 401);
        let mut revision_two = bytes[..417].to_vec();
        revision_two[0] = 2;
        revision_two.extend_from_slice(&bytes[481..]);
        assert_eq!(revision_two.len(), 465);
        assert!(decode_full_elements_economic_transition_public_values_v2(&revision_two).is_err());
        assert!(
            decode_full_elements_economic_transition_public_values_v2(&legacy_economic).is_err()
        );
        let mut legacy_conversion = legacy_economic;
        legacy_conversion.extend_from_slice(&conversion.covenant_commitment);
        legacy_conversion.extend_from_slice(&conversion.redemption_capability_commitment);
        assert_eq!(legacy_conversion.len(), 465);
        assert!(
            decode_full_elements_conversion_transition_public_values_v2(&legacy_conversion)
                .is_err()
        );
        let mut legacy_version = conversion_bytes;
        legacy_version[0] = 1;
        assert!(
            decode_full_elements_conversion_transition_public_values_v2(&legacy_version).is_err()
        );
        for offset in [353, 385] {
            let mut absent_frontier = conversion_bytes;
            absent_frontier[offset..offset + 32].fill(0);
            assert!(
                decode_full_elements_conversion_transition_public_values_v2(&absent_frontier)
                    .is_err()
            );
        }
        let mut missing_capability = conversion_bytes;
        missing_capability[FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2 + 32..].fill(0);
        assert!(
            decode_full_elements_conversion_transition_public_values_v2(&missing_capability)
                .is_err()
        );
        let mut missing_covenant = conversion_bytes;
        missing_covenant[FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2
            ..FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_BYTES_V2 + 32]
            .fill(0);
        assert!(
            decode_full_elements_conversion_transition_public_values_v2(&missing_covenant).is_err()
        );
    }

    #[test]
    fn economic_journal_derives_and_binds_every_previous_and_next_bmm_state_field() {
        use crate::elements_v2::{ElementsEconomicAggregateV2, ElementsUtxoAggregateV2};

        let parent = BmmL1StateV2 {
            block_hash: bitcoin::BlockHash::from_byte_array([31; 32]),
            height: 100,
            block_time: 100_000,
            bits: 0x207f_ffff,
            period_start_height: 0,
            period_start_time: 40_000,
            recent_times: (0..11).map(|index| 94_000 + index * 600).collect(),
        };
        let mut next_parent = parent.clone();
        next_parent.block_hash = bitcoin::BlockHash::from_byte_array([32; 32]);
        next_parent.height += 1;
        next_parent.block_time += 600;
        next_parent.recent_times.remove(0);
        next_parent.recent_times.push(next_parent.block_time);
        // Projection-unit fixture, not an assertion that a full block ran.
        let statement = FullPatchedElementsEconomicStatementV2 {
            consensus: FullPatchedElementsStatementV2 {
                block_hash: [1; 32],
                bmm_critical_hash: [2; 32],
                previous_utxo_root: ElementsSparseUtxoNodeV2 {
                    hash: [3; 32],
                    aggregate: ElementsUtxoAggregateV2 { count: 1 },
                },
                next_utxo_root: ElementsSparseUtxoNodeV2 {
                    hash: [4; 32],
                    aggregate: ElementsUtxoAggregateV2 { count: 1 },
                },
                previous_parent_state: parent,
                next_parent_state: next_parent,
                previous_exchange_state_root: [5; 32],
                next_exchange_state_root: [6; 32],
            },
            source_configuration_commitment: [7; 32],
            previous_economic_root: ElementsSparseEconomicNodeV2 {
                hash: [8; 32],
                aggregate: ElementsEconomicAggregateV2 {
                    count: 1,
                    outstanding_base_atoms: 10,
                    redeemable_reserve_quote_atoms: 20,
                },
            },
            next_economic_root: ElementsSparseEconomicNodeV2 {
                hash: [9; 32],
                aggregate: ElementsEconomicAggregateV2 {
                    count: 1,
                    outstanding_base_atoms: 10,
                    redeemable_reserve_quote_atoms: 20,
                },
            },
            previous_state_root: [10; 32],
            next_state_root: [11; 32],
            previous_header_state_commitment: [12; 32],
            next_header_state_commitment: [13; 32],
            source_tip_height: 50,
            source_tip_mtp: 200,
            outstanding_base_atoms: 10,
            redeemable_reserve_quote_atoms: 20,
        };
        let public = full_elements_economic_transition_public_values_v2(&statement).unwrap();
        assert_eq!(
            public.previous_parent_bmm_state_commitment,
            bmm_l1_state_commitment_v2(&statement.consensus.previous_parent_state).unwrap()
        );
        assert_eq!(
            public.next_parent_bmm_state_commitment,
            bmm_l1_state_commitment_v2(&statement.consensus.next_parent_state).unwrap()
        );
        assert_ne!(
            public.previous_parent_bmm_state_commitment,
            public.next_parent_bmm_state_commitment
        );
        let mutations: [fn(&mut BmmL1StateV2); 7] = [
            |state| state.block_hash = bitcoin::BlockHash::from_byte_array([33; 32]),
            |state| state.height += 1,
            |state| {
                state.block_time += 1;
                *state.recent_times.last_mut().unwrap() += 1;
            },
            |state| state.bits ^= 1,
            |state| state.period_start_height += 1,
            |state| state.period_start_time += 1,
            |state| state.recent_times[0] += 1,
        ];
        for mutate in mutations {
            for previous in [true, false] {
                let mut changed = statement.clone();
                mutate(if previous {
                    &mut changed.consensus.previous_parent_state
                } else {
                    &mut changed.consensus.next_parent_state
                });
                let changed_public =
                    full_elements_economic_transition_public_values_v2(&changed).unwrap();
                assert_ne!(changed_public.canonical_bytes(), public.canonical_bytes());
                assert_eq!(
                    decode_full_elements_economic_transition_public_values_v2(
                        &changed_public.canonical_bytes()
                    )
                    .unwrap(),
                    changed_public
                );
                if previous {
                    assert_ne!(
                        changed_public.previous_parent_bmm_state_commitment,
                        public.previous_parent_bmm_state_commitment
                    );
                    assert_eq!(
                        changed_public.next_parent_bmm_state_commitment,
                        public.next_parent_bmm_state_commitment
                    );
                } else {
                    assert_eq!(
                        changed_public.previous_parent_bmm_state_commitment,
                        public.previous_parent_bmm_state_commitment
                    );
                    assert_ne!(
                        changed_public.next_parent_bmm_state_commitment,
                        public.next_parent_bmm_state_commitment
                    );
                }
            }
        }
        let mut malformed = statement.clone();
        malformed.consensus.previous_parent_state.recent_times.pop();
        assert_eq!(
            full_elements_economic_transition_public_values_v2(&malformed),
            Err(FullPatchedElementsErrorV2::BlockConsensus)
        );
        let mut malformed = statement;
        malformed.consensus.next_parent_state.block_hash = bitcoin::BlockHash::all_zeros();
        assert_eq!(
            full_elements_economic_transition_public_values_v2(&malformed),
            Err(FullPatchedElementsErrorV2::BlockConsensus)
        );
    }

    struct RecordingGroth16Backend {
        calls: Cell<usize>,
    }

    impl Groth16Sp1Backend for RecordingGroth16Backend {
        type Error = ();

        fn verify_groth16_sha256(
            &self,
            proof: &[u8],
            program_id_words: [u32; 8],
            _: [u8; 32],
        ) -> Result<(), Self::Error> {
            if proof != [0xa5; ecx_sp1_consensus_interface::GROTH16_PROOF_LEN]
                || program_id_words != [1, 2, 3, 4, 5, 6, 7, 8]
            {
                return Err(());
            }
            self.calls.set(self.calls.get() + 1);
            Ok(())
        }
    }

    struct NoOrdinaryInputs;

    impl ElementsInputVerifierV2 for NoOrdinaryInputs {
        fn verify_input(
            &self,
            _: &elements::Transaction,
            _: usize,
            _: &[elements::TxOut],
        ) -> Result<(), ElementsStateErrorV2> {
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        }
    }

    struct ExactExchangeRoot {
        expected_previous: Hash32,
        expected_next: Hash32,
    }

    impl PatchedExchangeStateTransitionVerifierV2 for ExactExchangeRoot {
        fn verify_exchange_state_transition(
            &self,
            _: &PatchedElementsBlockV2,
            previous_exchange_state_root: Hash32,
            next_exchange_state_root: Hash32,
        ) -> Result<(), FullPatchedElementsErrorV2> {
            if previous_exchange_state_root != self.expected_previous
                || next_exchange_state_root != self.expected_next
            {
                return Err(FullPatchedElementsErrorV2::ExchangeStateTransition);
            }
            Ok(())
        }
    }

    struct ExactAuthorization {
        expected_hash: Hash32,
        called: Cell<bool>,
    }

    impl PatchedElementsBlockAuthorizationVerifierV2 for ExactAuthorization {
        fn verify_dynafed_authorization(
            &self,
            patched_header_hash: Hash32,
            signblock_challenge: &elements::Script,
            signblock_witness: &[Vec<u8>],
        ) -> Result<(), FullPatchedElementsErrorV2> {
            if patched_header_hash != self.expected_hash
                || signblock_challenge.as_bytes() != [0x51]
                || signblock_witness != [vec![1, 2, 3]]
            {
                return Err(FullPatchedElementsErrorV2::HeaderAuthorization);
            }
            self.called.set(true);
            Ok(())
        }
    }

    fn header_and_context() -> (PatchedElementsBlockV2, PatchedElementsHeaderContextV2) {
        let full = elements::dynafed::FullParams::new(
            elements::Script::from(vec![0x51]),
            1_000,
            bitcoin::ScriptBuf::new(),
            vec![],
            vec![],
        );
        let full_params = Params::Full(full.clone());
        let header = PatchedElementsHeaderV2 {
            wire_version: DYNAFED_HF_MASK_V2
                | BMM_PROOF_HF_MASK_V2
                | EXCHANGE_STATE_HF_MASK_V2
                | FORCED_INBOX_HF_MASK_V2
                | DEPOSIT_INBOX_HF_MASK_V2
                | INBOX_CURSOR_HF_MASK_V2
                | 7,
            previous_block_hash: [1; 32],
            transaction_merkle_root: [2; 32],
            withdrawal_bundle_hash: None,
            bmm_proof_hash: Some([3; 32]),
            time: 200,
            height: 50,
            current_dynafed_parameters: full_params.clone(),
            proposed_dynafed_parameters: Params::Null,
            exchange_state_root: Some([4; 32]),
            forced_inbox_root: Some([5; 32]),
            deposit_inbox_root: Some([6; 32]),
            ecx_parent_height: Some(700),
            forced_processed_cursor: Some(8),
            deposit_processed_cursor: Some(9),
            source_backlog_oldest_parent_height: Some(650),
            signblock_witness: vec![vec![1, 2, 3]],
        };
        let context = PatchedElementsHeaderContextV2 {
            previous_header_state: ElementsHeaderStateV2 {
                block_hash: [1; 32],
                height: 49,
                previous_11_times: (100..111).collect(),
                full_current_dynafed_parameters: full_params.clone(),
                dynamic_epoch_length: 10,
                epoch_proposals: vec![Params::Null; 10],
                authenticated_adjusted_time: 200,
            },
            previous_block_hash: [1; 32],
            next_height: 50,
            previous_11_times: (0..11).map(|value| 100 + value).collect(),
            authenticated_adjusted_time: 200,
            expected_current_dynafed_parameters: full_params.clone(),
            expected_full_current_dynafed_parameters: full_params,
            expected_forced_inbox_root: [5; 32],
            expected_deposit_inbox_root: [6; 32],
            expected_parent_height: 700,
            expected_forced_processed_cursor: 8,
            expected_deposit_processed_cursor: 9,
            expected_source_backlog_oldest_parent_height: 650,
        };
        (
            PatchedElementsBlockV2 {
                header,
                transactions: vec![],
                bmm_proof: Some(vec![]),
            },
            context,
        )
    }

    #[test]
    fn patched_dynafed_authorization_binds_extensions_and_exact_header_hash() {
        let (block, context) = header_and_context();
        let verifier = ExactAuthorization {
            expected_hash: block.header.block_hash().unwrap(),
            called: Cell::new(false),
        };
        verify_patched_dynafed_header_context_v2(&block, &context, &verifier).unwrap();
        assert!(verifier.called.get());

        let mut substituted = block.clone();
        substituted.header.forced_inbox_root = Some([7; 32]);
        assert_eq!(
            verify_patched_dynafed_header_context_v2(&substituted, &context, &verifier),
            Err(FullPatchedElementsErrorV2::HeaderAuthorization)
        );
        let mut reserved = block;
        reserved.header.wire_version |= 1 << 23;
        assert_eq!(
            verify_patched_dynafed_header_context_v2(&reserved, &context, &verifier),
            Err(FullPatchedElementsErrorV2::HeaderAuthorization)
        );
    }

    #[test]
    fn child_header_frontier_commits_every_ordered_consensus_input() {
        let (_, context) = header_and_context();
        let state = context.previous_header_state;
        let commitment = state.commitment().unwrap();
        let bytes = canonical_full_elements_options().serialize(&state).unwrap();
        let roundtrip: ElementsHeaderStateV2 = canonical_full_elements_options()
            .deserialize(&bytes)
            .unwrap();
        assert_eq!(roundtrip, state);
        let mut malformed = ElementsHeaderStateWireV2::from(state.clone());
        malformed.full_current_dynafed_parameters.push(0);
        assert!(ElementsHeaderStateV2::try_from(malformed).is_err());
        let mut changed = state.clone();
        changed.previous_11_times.swap(0, 1); // Same median, different history.
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = state.clone();
        changed.block_hash[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = state.clone();
        changed.authenticated_adjusted_time += 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = state.clone();
        changed.epoch_proposals[0] = changed.full_current_dynafed_parameters.clone();
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = state.clone();
        changed.full_current_dynafed_parameters = proposed_params();
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = state.clone();
        changed.height += 10;
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = state.clone();
        changed.dynamic_epoch_length = 50;
        changed.epoch_proposals = vec![Params::Null; 50];
        assert_ne!(changed.commitment().unwrap(), commitment);
        for invalid in [0, 10, 12] {
            changed = state.clone();
            changed.previous_11_times.resize(invalid, 100);
            assert!(changed.commitment().is_err());
        }
        changed = state.clone();
        changed.epoch_proposals.pop();
        assert!(changed.commitment().is_err());
        changed = state;
        changed.full_current_dynafed_parameters = Params::Null;
        assert!(changed.commitment().is_err());
    }

    fn proposed_params() -> Params {
        Params::Full(elements::dynafed::FullParams::new(
            elements::Script::from([vec![0, 32], vec![7; 32]].concat()),
            2_000,
            bitcoin::ScriptBuf::new(),
            vec![],
            vec![],
        ))
    }

    #[test]
    fn dynafed_epoch_vote_threshold_and_format_derive_from_committed_prefix() {
        let (mut block, context) = header_and_context();
        let mut state = context.previous_header_state;
        let old = state.full_current_dynafed_parameters.clone();
        let proposed = proposed_params();
        state.epoch_proposals = vec![proposed.clone(); 7];
        state.epoch_proposals.extend(vec![Params::Null; 3]);
        assert_eq!(state.next_parameters().unwrap(), (old.clone(), old));
        state.epoch_proposals[7] = proposed.clone();
        assert_eq!(
            state.next_parameters().unwrap(),
            (proposed.clone(), proposed.clone())
        );
        assert!(state.advance(&block).is_err()); // Stale/current authority rejected.
        block.header.current_dynafed_parameters = proposed.clone();
        let next = state.advance(&block).unwrap();
        assert_eq!(next.full_current_dynafed_parameters, proposed);
        assert_eq!(next.epoch_proposals, vec![Params::Null]);
        assert_eq!(
            next.previous_11_times,
            [Vec::from_iter(101..111), vec![200]].concat()
        );
        assert_eq!(
            next.authenticated_adjusted_time,
            state.authenticated_adjusted_time
        );

        let (compact, full) = next.next_parameters().unwrap();
        assert!(compact.is_compact());
        assert_eq!(full, proposed);
        block.header.previous_block_hash = next.block_hash;
        block.header.height = 51;
        block.header.time = 201;
        // Non-boundary headers must be compact, not merely an equal root.
        assert!(next.advance(&block).is_err());
        block.header.current_dynafed_parameters = compact;
        assert!(next.advance(&block).is_ok());
    }

    #[test]
    fn dynafed_short_epoch_reverse_scan_matches_native_tie_rule() {
        let (_, context) = header_and_context();
        let mut state = context.previous_header_state;
        state.dynamic_epoch_length = 2;
        let older = state.full_current_dynafed_parameters.clone();
        let newer = proposed_params();
        state.epoch_proposals = vec![older.clone(), newer.clone()];
        assert_eq!(state.next_parameters().unwrap(), (newer.clone(), newer));
        state.epoch_proposals.reverse();
        assert_eq!(state.next_parameters().unwrap(), (older.clone(), older));
    }

    #[test]
    fn header_context_rejects_witness_selected_history_authority_or_clock() {
        let (block, context) = header_and_context();
        let verifier = ExactAuthorization {
            expected_hash: block.header.block_hash().unwrap(),
            called: Cell::new(false),
        };
        let mutations: [fn(&mut PatchedElementsHeaderContextV2); 4] = [
            |c| c.previous_11_times.swap(0, 1),
            |c| c.authenticated_adjusted_time += 1,
            |c| c.expected_current_dynafed_parameters = proposed_params(),
            |c| c.expected_full_current_dynafed_parameters = proposed_params(),
        ];
        for mutate in mutations {
            let mut changed = context.clone();
            mutate(&mut changed);
            assert_eq!(
                verify_patched_dynafed_header_context_v2(&block, &changed, &verifier),
                Err(FullPatchedElementsErrorV2::HeaderAuthorization)
            );
        }
        let mut bad_time = block.clone();
        bad_time.header.time = 105; // Exactly prior median is invalid.
        assert!(context.previous_header_state.advance(&bad_time).is_err());
        bad_time.header.time =
            200 + crate::elements_v2::ELEMENTS_MAX_FUTURE_BLOCK_SECONDS_V2 as u32 + 1;
        assert!(context.previous_header_state.advance(&bad_time).is_err());
        assert!(!verifier.called.get());
    }

    #[test]
    fn dynafed_proposals_reject_invalid_fedpeg_and_unsupported_extension_changes() {
        let (_, context) = header_and_context();
        let full = context.expected_full_current_dynafed_parameters;
        let proposal = |program, script, extension| {
            Params::Full(elements::dynafed::FullParams::new(
                full.signblockscript().unwrap().clone(),
                1_000,
                program,
                script,
                extension,
            ))
        };
        assert!(validate_proposal(
            &full,
            &proposal(bitcoin::ScriptBuf::new(), vec![], vec![vec![1]])
        )
        .is_err());
        assert!(validate_proposal(
            &full,
            &proposal(
                bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                vec![0x51],
                vec![]
            )
        )
        .is_err());
        let script = vec![0x51];
        let program = bitcoin::ScriptBuf::from_bytes(
            [vec![0, 32], Sha256::digest(&script).to_vec()].concat(),
        );
        assert!(validate_proposal(&full, &proposal(program.clone(), script, vec![])).is_ok());
        assert!(validate_proposal(&full, &proposal(program, vec![0x52], vec![])).is_err());
        let depth = vec![0x74];
        let program =
            bitcoin::ScriptBuf::from_bytes([vec![0, 32], Sha256::digest(&depth).to_vec()].concat());
        assert!(validate_proposal(&full, &proposal(program, depth, vec![])).is_err());
        assert!(validate_proposal(&full, &full.clone().into_compact().unwrap()).is_err());
    }

    #[test]
    fn full_params_root_preimage_is_not_replaceable_by_compact_only_assertion() {
        let (_, mut context) = header_and_context();
        context.expected_full_current_dynafed_parameters = Params::Compact {
            signblockscript: elements::Script::from(vec![0x51]),
            signblock_witness_limit: 1_000,
            elided_root: sha256::Midstate::from_byte_array([0; 32]),
        };
        let (block, _) = header_and_context();
        let verifier = ExactAuthorization {
            expected_hash: block.header.block_hash().unwrap(),
            called: Cell::new(false),
        };
        assert_eq!(
            verify_patched_dynafed_header_context_v2(&block, &context, &verifier),
            Err(FullPatchedElementsErrorV2::HeaderAuthorization)
        );
    }

    #[test]
    fn concrete_dynafed_authorization_executes_exact_patched_hash_signature() {
        use bitcoin::hashes::{sha256, Hash as _};
        use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret);
        let witness_script = bitcoin::script::Builder::new()
            .push_slice(
                bitcoin::script::PushBytesBuf::try_from(public.serialize().to_vec()).unwrap(),
            )
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let witness_program = sha256::Hash::hash(witness_script.as_bytes()).to_byte_array();
        let mut challenge = vec![0x00, 0x20];
        challenge.extend_from_slice(&witness_program);
        let digest = [42; 32];
        let mut signature = secp
            .sign_ecdsa(&Message::from_digest(digest), &secret)
            .serialize_der()
            .to_vec();
        signature.push(1);
        let witness = vec![signature.clone(), witness_script.to_bytes()];
        FullPatchedElementsBlockAuthorizationVerifierV2
            .verify_dynafed_authorization(
                digest,
                &elements::Script::from(challenge.clone()),
                &witness,
            )
            .unwrap();

        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert_eq!(
            FullPatchedElementsBlockAuthorizationVerifierV2.verify_dynafed_authorization(
                wrong_digest,
                &elements::Script::from(challenge.clone()),
                &witness,
            ),
            Err(FullPatchedElementsErrorV2::HeaderAuthorization)
        );
        let mut wrong_hash_type = signature;
        *wrong_hash_type.last_mut().unwrap() = 2;
        assert_eq!(
            FullPatchedElementsBlockAuthorizationVerifierV2.verify_dynafed_authorization(
                digest,
                &elements::Script::from(challenge),
                &[wrong_hash_type, witness_script.to_bytes()],
            ),
            Err(FullPatchedElementsErrorV2::HeaderAuthorization)
        );
    }

    #[test]
    fn finite_v18_exchange_verifier_binds_unique_transaction_state_and_real_backend_boundary() {
        use ecx_sp1_consensus_interface::{encode_groth16_public_values_v5_annex, PublicValuesV5};
        use elements::{
            confidential::{Asset, Nonce, Value},
            hashes::Hash as _,
            AssetId, LockTime, Script, Transaction, TxIn, TxOut, Txid,
        };

        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../zkvm/artifacts/annex-v4-public-values-v5-test-vector.json"
        ))
        .unwrap();
        let public_values_hex: String = vector["public_values_v5_hex_chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|chunk| chunk.as_str().unwrap())
            .collect();
        let public_values_bytes = hex::decode(public_values_hex).unwrap();
        let mut values = PublicValuesV5::decode(&public_values_bytes).unwrap();
        let program_id = ProgramId::from_words([1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let authority_asset = AssetId::from_slice(&[0x71; 32]).unwrap();
        let previous_outpoint = OutPoint::new(Txid::from_byte_array([0x72; 32]), 3);
        let p2tr = |key: u8| {
            let mut bytes = vec![0x51, 0x20];
            bytes.extend_from_slice(&[key; 32]);
            Script::from(bytes)
        };
        let renderer = FiniteV18StateRendererV2 {
            public_state_domain_sha256: [0x80; 32],
            state_node_domain_sha256: [0x81; 32],
            transition_cmr: [0x82; 32],
            incremental_activation_cmr: [0x83; 32],
            keyless_internal_key: FINITE_V18_NUMS_INTERNAL_KEY,
            simplicity_leaf_version: FINITE_V18_SIMPLICITY_LEAF_VERSION,
        };
        let state = |sequence: u64, root: u8| FiniteV18CovenantStateV2 {
            version: FINITE_V18_COVENANT_STATE_VERSION,
            sequence,
            private_state_root: [root; 32],
            encrypted_availability_root: [root.wrapping_add(1); 32],
            forced_inbox_root: [root.wrapping_add(2); 32],
            deposit_inbox_root: [root.wrapping_add(3); 32],
            configuration_hash: values.configuration_hash,
            bond_state_root: [root.wrapping_add(4); 32],
            funding_state_root: [root.wrapping_add(5); 32],
            active_order_risk_root: [root.wrapping_add(6); 32],
            position_risk_root: [root.wrapping_add(7); 32],
            bond_inbox_head_root: [root.wrapping_add(8); 32],
            bond_inbox_entry_count: 7,
            bond_inbox_processed_root: [root.wrapping_add(9); 32],
            bond_inbox_processed_cursor: 5,
            bond_inbox_outcome_root: [root.wrapping_add(10); 32],
            bond_inbox_outcome_count: 5,
            matcher_execution_sequence: sequence,
            last_transition_sidechain_height: 100 + sequence,
        };
        let current_state = state(1, 0x90);
        let next_state = state(2, 0xa0);
        assert_eq!(
            hex::encode(
                current_state
                    .hash(renderer.public_state_domain_sha256)
                    .unwrap()
            ),
            "f9bd166b0043933f0e42a991b07eb90a07ce1b01da573bd65af04b132e7697ed"
        );
        assert_eq!(
            hex::encode(renderer.render(current_state).unwrap().as_bytes()),
            "5120c4f527f1950cf8d2d4dc3da9d037e271561fc5ea89a8470aae773d031402c3b7"
        );
        values.current_state_hash = current_state
            .hash(renderer.public_state_domain_sha256)
            .unwrap();
        values.next_state_hash = next_state
            .hash(renderer.public_state_domain_sha256)
            .unwrap();
        let previous_state_output = TxOut {
            asset: Asset::Explicit(authority_asset),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: renderer.render(current_state).unwrap(),
            witness: Default::default(),
        };
        let child_genesis = [0x75; 32];
        let previous_exchange_header_root =
            compute_state_utxo_root_v2(child_genesis, previous_outpoint, &previous_state_output);
        values.prior_exchange_header_root = previous_exchange_header_root;
        let successor_state_output = TxOut {
            script_pubkey: renderer.render(next_state).unwrap(),
            ..previous_state_output.clone()
        };
        let state_input = TxIn {
            previous_output: previous_outpoint,
            ..TxIn::default()
        };
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![state_input],
            output: vec![successor_state_output],
        };
        values.transition_txid_consensus = transaction.txid().to_byte_array();
        let annex = encode_groth16_public_values_v5_annex(
            program_id,
            &[0xa5; ecx_sp1_consensus_interface::GROTH16_PROOF_LEN],
            &values,
        )
        .unwrap();
        transaction.input[0].witness.script_witness = vec![vec![1; 64], annex.clone()];
        let (mut block, _) = header_and_context();
        block.transactions = vec![transaction.clone()];
        let backend = RecordingGroth16Backend {
            calls: Cell::new(0),
        };
        let context = FiniteV18ExchangeProofContextV2 {
            program_id,
            configuration_hash: values.configuration_hash,
            renderer,
            current_state,
            next_state,
            child_genesis,
            previous_state_outpoint: previous_outpoint,
            previous_state_output: previous_state_output.clone(),
            state_authority_asset_id: authority_asset.into_inner().to_byte_array(),
            state_authority_value: 1,
        };
        assert_eq!(
            previous_exchange_header_root,
            values.prior_exchange_header_root
        );
        let next_exchange_header_root = compute_state_utxo_root_v2(
            context.child_genesis,
            OutPoint::new(transaction.txid(), 0),
            &transaction.output[0],
        );
        let verifier = FiniteV18Groth16ExchangeStateVerifierV2 {
            backend: &backend,
            context: context.clone(),
        };
        verifier
            .verify_exchange_state_transition(
                &block,
                previous_exchange_header_root,
                next_exchange_header_root,
            )
            .unwrap();
        assert_eq!(backend.calls.get(), 1);

        let mut wrong_renderer_context = context.clone();
        wrong_renderer_context.renderer.state_node_domain_sha256[0] ^= 1;
        let wrong_renderer = FiniteV18Groth16ExchangeStateVerifierV2 {
            backend: &backend,
            context: wrong_renderer_context,
        };
        assert_eq!(
            wrong_renderer.verify_exchange_state_transition(
                &block,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut known_key_context = context.clone();
        known_key_context.renderer.keyless_internal_key = [2; 32];
        let known_key = FiniteV18Groth16ExchangeStateVerifierV2 {
            backend: &backend,
            context: known_key_context,
        };
        assert_eq!(
            known_key.verify_exchange_state_transition(
                &block,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut wrong_state_context = context.clone();
        wrong_state_context.next_state.private_state_root[0] ^= 1;
        let wrong_state = FiniteV18Groth16ExchangeStateVerifierV2 {
            backend: &backend,
            context: wrong_state_context,
        };
        assert_eq!(
            wrong_state.verify_exchange_state_transition(
                &block,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut wrong_sequence_context = context.clone();
        wrong_sequence_context.next_state.sequence += 1;
        let wrong_sequence = FiniteV18Groth16ExchangeStateVerifierV2 {
            backend: &backend,
            context: wrong_sequence_context,
        };
        assert_eq!(
            wrong_sequence.verify_exchange_state_transition(
                &block,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut wrong_previous_context = context.clone();
        wrong_previous_context.previous_state_output.script_pubkey = p2tr(0x76);
        let wrong_previous = FiniteV18Groth16ExchangeStateVerifierV2 {
            backend: &backend,
            context: wrong_previous_context,
        };
        assert_eq!(
            wrong_previous.verify_exchange_state_transition(
                &block,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut wrong_successor = block.clone();
        wrong_successor.transactions[0].output[0].script_pubkey = p2tr(0x77);
        assert_eq!(
            verifier.verify_exchange_state_transition(
                &wrong_successor,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut input_not_zero = block.clone();
        input_not_zero.transactions[0]
            .input
            .insert(0, TxIn::default());
        assert_eq!(
            verifier.verify_exchange_state_transition(
                &input_not_zero,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut successor_spent = block.clone();
        let spend_successor = TxIn {
            previous_output: OutPoint::new(successor_spent.transactions[0].txid(), 0),
            ..TxIn::default()
        };
        successor_spent.transactions.push(Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![spend_successor],
            output: vec![],
        });
        assert_eq!(
            verifier.verify_exchange_state_transition(
                &successor_spent,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut multiple_spends = block.clone();
        let spend_previous_again = TxIn {
            previous_output: previous_outpoint,
            ..TxIn::default()
        };
        multiple_spends.transactions.push(Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![spend_previous_again],
            output: vec![],
        });
        assert_eq!(
            verifier.verify_exchange_state_transition(
                &multiple_spends,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut duplicate = block.clone();
        duplicate.transactions[0].input.push(TxIn::default());
        duplicate.transactions[0].input[1].witness.script_witness =
            vec![vec![2; 64], annex.clone()];
        assert_eq!(
            verifier.verify_exchange_state_transition(
                &duplicate,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );

        let mut wrong_transaction = block;
        wrong_transaction.transactions[0].version = 3;
        assert_eq!(
            verifier.verify_exchange_state_transition(
                &wrong_transaction,
                previous_exchange_header_root,
                next_exchange_header_root,
            ),
            Err(FullPatchedElementsErrorV2::ExchangeStateTransition)
        );
        assert_eq!(backend.calls.get(), 1);
    }

    #[test]
    fn full_patched_block_composes_bmm_header_utxo_and_exchange_state() {
        use crate::bmm_v2::{BmmConsensusParametersV2, BmmL1StateV2, BmmProofEntryV2, BmmProofV2};
        use crate::patched_elements_v2::{PatchedElementsHeaderV2, WITHDRAWAL_BUNDLE_HF_MASK_V2};
        use bitcoin::block::{Header, Version};
        use bitcoin::consensus::serialize as bitcoin_serialize;
        use bitcoin::hashes::{sha256, sha256d, Hash as _};
        use bitcoin::merkle_tree::{MerkleBlock, PartialMerkleTree};
        use bitcoin::pow::{CompactTarget, Target};
        use bitcoin::{absolute, transaction, Amount, OutPoint, Sequence, TxIn, TxOut, Witness};
        use elements::confidential::{Asset, Nonce, Value};

        let parent = BmmL1StateV2 {
            block_hash: bitcoin::BlockHash::from_byte_array([1; 32]),
            height: 100,
            block_time: 100_000,
            bits: 0x207f_ffff,
            period_start_height: 0,
            period_start_time: 40_000,
            recent_times: (0..11).map(|index| 94_000 + index * 600).collect(),
        };
        let mut parent_script = vec![0x6a, 0x20];
        parent_script.extend_from_slice(&parent.block_hash.to_byte_array());
        let sidechain_coinbase = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()],
            output: vec![elements::TxOut {
                asset: Asset::Null,
                value: Value::Null,
                nonce: Nonce::Null,
                script_pubkey: elements::Script::from(parent_script),
                witness: Default::default(),
            }],
        };
        let signblock_witness_script = vec![0x51];
        let signblock_hash = sha256::Hash::hash(&signblock_witness_script).to_byte_array();
        let mut signblock_program = vec![0x00, 0x20];
        signblock_program.extend_from_slice(&signblock_hash);
        let full = elements::dynafed::FullParams::new(
            elements::Script::from(signblock_program),
            1_000,
            bitcoin::ScriptBuf::new(),
            vec![],
            vec![],
        );
        let full_params = Params::Full(full);
        let mut header = PatchedElementsHeaderV2 {
            wire_version: DYNAFED_HF_MASK_V2
                | WITHDRAWAL_BUNDLE_HF_MASK_V2
                | BMM_PROOF_HF_MASK_V2
                | EXCHANGE_STATE_HF_MASK_V2
                | FORCED_INBOX_HF_MASK_V2
                | DEPOSIT_INBOX_HF_MASK_V2
                | INBOX_CURSOR_HF_MASK_V2
                | 7,
            previous_block_hash: [11; 32],
            transaction_merkle_root: sidechain_coinbase.txid().to_byte_array(),
            withdrawal_bundle_hash: Some([12; 32]),
            bmm_proof_hash: Some([0; 32]),
            time: 200,
            height: 50,
            current_dynafed_parameters: full_params.clone(),
            proposed_dynafed_parameters: Params::Null,
            exchange_state_root: Some([13; 32]),
            forced_inbox_root: Some([14; 32]),
            deposit_inbox_root: Some([15; 32]),
            ecx_parent_height: Some(101),
            forced_processed_cursor: Some(8),
            deposit_processed_cursor: Some(9),
            source_backlog_oldest_parent_height: Some(99),
            signblock_witness: vec![signblock_witness_script],
        };
        let critical = header.bmm_critical_hash().unwrap();
        let mut m8 = vec![0xd1, 0x61, 0x73, 0x68, 24];
        let mut displayed = critical;
        displayed.reverse();
        m8.extend_from_slice(&displayed);
        let bitcoin_coinbase = bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::script::Builder::new().push_int(101).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: bitcoin::script::Builder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                    .push_slice(bitcoin::script::PushBytesBuf::try_from(m8).unwrap())
                    .into_script(),
            }],
        };
        let txid = bitcoin_coinbase.compute_txid();
        let target = Target::from_compact(CompactTarget::from_consensus(parent.bits));
        let mut bitcoin_header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: parent.block_hash,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(txid.to_byte_array()),
            time: 100_600,
            bits: CompactTarget::from_consensus(parent.bits),
            nonce: 0,
        };
        while bitcoin_header.validate_pow(target).is_err() {
            bitcoin_header.nonce = bitcoin_header.nonce.wrapping_add(1);
        }
        let merkle = MerkleBlock {
            header: bitcoin_header,
            txn: PartialMerkleTree::from_txids(&[txid], &[true]),
        };
        let bmm_proof = BmmProofV2 {
            version: 1,
            previous_state: parent.clone(),
            entries: vec![BmmProofEntryV2 {
                coinbase_transaction: bitcoin_serialize(&bitcoin_coinbase),
                coinbase_merkle_proof: bitcoin_serialize(&merkle),
            }],
        }
        .encode()
        .unwrap();
        header.bmm_proof_hash = Some(sha256d::Hash::hash(&bmm_proof).to_byte_array());
        let block = PatchedElementsBlockV2 {
            header,
            transactions: vec![sidechain_coinbase],
            bmm_proof: Some(bmm_proof),
        };
        let raw = block.encode().unwrap();
        let header_context = PatchedElementsHeaderContextV2 {
            previous_header_state: ElementsHeaderStateV2 {
                block_hash: [11; 32],
                height: 49,
                previous_11_times: (100..111).collect(),
                full_current_dynafed_parameters: full_params.clone(),
                dynamic_epoch_length: 10,
                epoch_proposals: vec![Params::Null; 10],
                authenticated_adjusted_time: 200,
            },
            previous_block_hash: [11; 32],
            next_height: 50,
            previous_11_times: (0..11).map(|value| 100 + value).collect(),
            authenticated_adjusted_time: 200,
            expected_current_dynafed_parameters: full_params.clone(),
            expected_full_current_dynafed_parameters: full_params,
            expected_forced_inbox_root: [14; 32],
            expected_deposit_inbox_root: [15; 32],
            expected_parent_height: 101,
            expected_forced_processed_cursor: 8,
            expected_deposit_processed_cursor: 9,
            expected_source_backlog_oldest_parent_height: 99,
        };
        let bmm_consensus = BmmConsensusParametersV2 {
            pow_limit: target,
            target_timespan: 14 * 24 * 60 * 60,
            target_spacing: 600,
            sidechain_slot: 24,
        };
        let initial_root = canonical_empty_elements_utxo_leaf_v2();
        let statement = verify_full_patched_elements_block_v2(
            &raw,
            &header_context,
            initial_root,
            &parent,
            [16; 32],
            &PatchedElementsBlockExecutionWitnessV2 {
                transaction_utxos: vec![ElementsTransactionUtxoWitnessV2 {
                    spends: vec![],
                    creates: vec![],
                }],
                transaction_kernels: vec![ElementsTransactionKernelWitnessV2::Coinbase],
            },
            &NoOrdinaryInputs,
            None,
            &FullPatchedElementsBlockAuthorizationVerifierV2,
            &ExactExchangeRoot {
                expected_previous: [16; 32],
                expected_next: [13; 32],
            },
            &bmm_consensus,
        )
        .unwrap();
        assert_eq!(statement.next_utxo_root, initial_root);
        assert_eq!(statement.next_parent_state.height, 101);
        assert_eq!(statement.next_exchange_state_root, [13; 32]);

        let wrong_witness = PatchedElementsBlockExecutionWitnessV2 {
            transaction_utxos: vec![],
            transaction_kernels: vec![],
        };
        assert_eq!(
            verify_full_patched_elements_block_v2(
                &raw,
                &header_context,
                initial_root,
                &parent,
                [16; 32],
                &wrong_witness,
                &NoOrdinaryInputs,
                None,
                &FullPatchedElementsBlockAuthorizationVerifierV2,
                &ExactExchangeRoot {
                    expected_previous: [16; 32],
                    expected_next: [13; 32],
                },
                &bmm_consensus,
            ),
            Err(FullPatchedElementsErrorV2::TransactionConsensus)
        );
    }
}
