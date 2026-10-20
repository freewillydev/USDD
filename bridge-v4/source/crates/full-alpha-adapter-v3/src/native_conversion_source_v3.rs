//! Versioned, checkpoint-relative native Alpha source/accounting composition.
//!
//! This is NOT the final 275-byte ECX/BTC conversion relation. Its 0xa7 journal
//! authenticates execution, native P/Q/M7 continuity, an explicit clock rule,
//! source age, parent confirmations and accounting. It deliberately makes no
//! claim that a redemption covenant is available or spendable. Consumers must
//! pin `source_binding` independently and prove redemption before producing a
//! conversion receipt. The legacy 0xa5 projection is unchanged.
//!
//! `ParentObservationMtp` is selected for the staged Alpha proof workflow:
//! authenticated
//! parent MTP is NOT the node's wall-clock adjusted_time. It can reject blocks
//! accepted by wall-clock validation. Compatibility still requires qualification;
//! this module neither changes consensus nor fills the canonical profile.
//!
//! This version advances exactly one child block from a reviewed frozen anchor.
//! A witness-selected new checkpoint is not a recursive checkpoint evolution.

use bincode::Options;
use bitcoin::hashes::Hash as _;
use ecx_full_consensus_validator_v2::Hash32;
use serde::{Deserialize, Serialize};

use crate::{
    child_execution_guest_v3::{
        AlphaChildExecutionBindingV3, AlphaChildExecutionPublicValuesV3,
        AlphaDepositConfigurationV3, ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3,
    },
    child_execution_policy_v3::ChildExecutionPolicyV3,
    child_execution_state_v3::{child_history_commitment, ChildExecutionCheckpointV3},
    conversion_parent_link_v3::{
        execute_alpha_conversion_parent_link_v3, AlphaConversionLinkBindingV3,
        AlphaConversionParentLinkInputV3, AlphaConversionParentLinkPublicValuesV3,
    },
    native_conversion_accounting_v3::{
        derive_accounting, ConversionAccountingBindingV3, ConversionAccountingErrorV3,
        ConversionAccountingV3,
    },
    native_header_v3::NativeHeader,
    AlphaRecursiveReceiptBindingV3, FullAlphaAdapterInputV3, FullAlphaReceiptVerifierV3,
    FullAlphaStatementV3, MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3,
};

pub const NATIVE_CONVERSION_SOURCE_VERSION_V3: u8 = 0xa7;
pub const NATIVE_CONVERSION_SOURCE_PUBLIC_BYTES_V3: usize = 676;
pub const MAX_NATIVE_CONVERSION_SOURCE_INPUT_BYTES_V3: usize = 128 * 1024 * 1024;
const MAX_SOURCE_HISTORY_V3: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeSourceClockPolicyV3 {
    /// Selected Alpha proof rule, not a claim of equivalence to adjusted_time.
    ParentObservationMtp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConversionSourceBindingV3 {
    pub child_execution_program_id: Hash32,
    pub parent: AlphaConversionLinkBindingV3,
    pub predecessor_checkpoint: Hash32,
    pub execution_policy: Hash32,
    pub simplicity_evaluator_program_id: Hash32,
    pub deposit_configuration: Hash32,
    pub accounting_binding: Hash32,
    pub clock_policy: NativeSourceClockPolicyV3,
    pub minimum_parent_confirmations: u32,
    pub maximum_child_age_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeConversionSourceErrorV3 {
    Input,
    Binding,
    Parent,
    ChildJournal,
    ChildReceipt,
    Clock,
    Checkpoint,
    NativeMaterial,
    History,
    Finality,
    Accounting(ConversionAccountingErrorV3),
}

impl NativeConversionSourceBindingV3 {
    pub fn child_binding(
        &self,
    ) -> Result<AlphaChildExecutionBindingV3, NativeConversionSourceErrorV3> {
        Ok(AlphaChildExecutionBindingV3 {
            parent_binding: self
                .parent
                .commitment()
                .map_err(|_| NativeConversionSourceErrorV3::Binding)?,
            predecessor_checkpoint: self.predecessor_checkpoint,
            execution_policy: self.execution_policy,
            simplicity_evaluator_program_id: self.simplicity_evaluator_program_id,
            deposit_configuration: self.deposit_configuration,
        })
    }

    pub fn commitment(&self) -> Result<Hash32, NativeConversionSourceErrorV3> {
        use NativeConversionSourceErrorV3::Binding;
        let roles = [
            self.child_execution_program_id,
            self.simplicity_evaluator_program_id,
            self.parent.parent.checkpoint_program_id,
            self.parent.parent.transition_program_id,
        ];
        if roles
            .iter()
            .any(|id| !crate::alpha_sp1_program_id_is_canonical_v3(*id))
            || roles
                .iter()
                .enumerate()
                .any(|(i, id)| roles[i + 1..].contains(id))
            || self.accounting_binding == [0; 32]
            || self.minimum_parent_confirmations == 0
            || self.maximum_child_age_seconds == 0
        {
            return Err(Binding);
        }
        let mut bytes = vec![NATIVE_CONVERSION_SOURCE_VERSION_V3];
        for hash in [
            self.child_execution_program_id,
            self.child_binding()?.commitment().map_err(|_| Binding)?,
            self.accounting_binding,
        ] {
            bytes.extend_from_slice(&hash);
        }
        bytes.push(match self.clock_policy {
            NativeSourceClockPolicyV3::ParentObservationMtp => 0,
        });
        bytes.extend_from_slice(&self.minimum_parent_confirmations.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_child_age_seconds.to_be_bytes());
        Ok(crate::tagged_hash(
            "ECX/alpha-native-conversion-source-binding/v3",
            &bytes,
        ))
    }

    pub fn require_frozen(&self, expected: Hash32) -> Result<(), NativeConversionSourceErrorV3> {
        if expected == [0; 32] || self.commitment()? != expected {
            return Err(NativeConversionSourceErrorV3::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConversionSourceInputV3 {
    pub version: u8,
    pub binding: NativeConversionSourceBindingV3,
    pub child_receipt: AlphaRecursiveReceiptBindingV3,
    pub parent: AlphaConversionParentLinkInputV3,
    /// Full Alpha replay for the observation tip, under the SAME parent anchor.
    pub observation: FullAlphaAdapterInputV3,
    /// Exact 80-byte Bitcoin headers after mining parent Q through observation.
    /// Their hashes connect Q to the tip authenticated by full Alpha execution;
    /// these are ancestry witnesses, NOT a header-only consensus fallback.
    pub parent_continuation: Vec<Vec<u8>>,
    pub predecessor: ChildExecutionCheckpointV3,
    pub successor: ChildExecutionCheckpointV3,
    pub predecessor_history: Vec<Vec<u8>>,
    pub raw_child_block: Vec<u8>,
    pub execution_policy: ChildExecutionPolicyV3,
    pub deposit_configuration: AlphaDepositConfigurationV3,
    pub accounting: ConversionAccountingBindingV3,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_NATIVE_CONVERSION_SOURCE_INPUT_BYTES_V3 as u64)
}

impl NativeConversionSourceInputV3 {
    fn check_shape(&self) -> Result<(), NativeConversionSourceErrorV3> {
        if self.version != NATIVE_CONVERSION_SOURCE_VERSION_V3
            || self.child_receipt.public_values.len() != ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3
            || self.child_receipt.proof_marker.is_empty()
            || self.child_receipt.proof_marker.len() > MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3
            || self.predecessor_history.is_empty()
            || self.predecessor_history.len() > MAX_SOURCE_HISTORY_V3
            || self.predecessor_history.iter().any(|h| {
                h.is_empty() || h.len() > crate::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES
            })
            || self.parent_continuation.len() > MAX_SOURCE_HISTORY_V3
            || self.parent_continuation.iter().any(|h| h.len() != 80)
            || self.raw_child_block.is_empty()
            || self.raw_child_block.len() > crate::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES
            || options()
                .serialized_size(self)
                .map_err(|_| NativeConversionSourceErrorV3::Input)?
                > MAX_NATIVE_CONVERSION_SOURCE_INPUT_BYTES_V3 as u64
        {
            return Err(NativeConversionSourceErrorV3::Input);
        }
        Ok(())
    }
}

pub fn encode_native_conversion_source_input_v3(
    input: &NativeConversionSourceInputV3,
) -> Result<Vec<u8>, NativeConversionSourceErrorV3> {
    input.check_shape()?;
    options()
        .serialize(input)
        .map_err(|_| NativeConversionSourceErrorV3::Input)
}

pub fn decode_native_conversion_source_input_v3(
    bytes: &[u8],
) -> Result<NativeConversionSourceInputV3, NativeConversionSourceErrorV3> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_CONVERSION_SOURCE_INPUT_BYTES_V3 {
        return Err(NativeConversionSourceErrorV3::Input);
    }
    let input: NativeConversionSourceInputV3 = options()
        .deserialize(bytes)
        .map_err(|_| NativeConversionSourceErrorV3::Input)?;
    if encode_native_conversion_source_input_v3(&input)? != bytes {
        return Err(NativeConversionSourceErrorV3::Input);
    }
    Ok(input)
}

/// Authenticated source/accounting claims ONLY, with the exact child statement.
/// There is deliberately no conversion-success or redemption-available field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConversionSourcePublicValuesV3 {
    pub source_binding: Hash32,
    pub child: AlphaChildExecutionPublicValuesV3,
    pub accounting_binding: Hash32,
    pub observation_statement_commitment: Hash32,
    pub native_material_commitment: Hash32,
    pub child_mtp: u64,
    pub observation_mtp: u64,
    pub parent_confirmations: u32,
    pub accounting: ConversionAccountingV3,
}

impl NativeConversionSourcePublicValuesV3 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NativeConversionSourceErrorV3> {
        use NativeConversionSourceErrorV3::ChildJournal;
        if bytes.len() != NATIVE_CONVERSION_SOURCE_PUBLIC_BYTES_V3
            || bytes[0] != NATIVE_CONVERSION_SOURCE_VERSION_V3
        {
            return Err(ChildJournal);
        }
        let hash = |start: usize| -> Hash32 { bytes[start..start + 32].try_into().unwrap() };
        let u64_at = |start: usize| u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
        let u128_at =
            |start: usize| u128::from_be_bytes(bytes[start..start + 16].try_into().unwrap());
        let child = AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&bytes[33..440])
            .map_err(|_| ChildJournal)?;
        let value = Self {
            source_binding: hash(1),
            child,
            accounting_binding: hash(440),
            observation_statement_commitment: hash(472),
            native_material_commitment: hash(504),
            child_mtp: u64_at(536),
            observation_mtp: u64_at(544),
            parent_confirmations: u32::from_be_bytes(bytes[552..556].try_into().unwrap()),
            accounting: ConversionAccountingV3 {
                child_checkpoint_commitment: child.next_checkpoint,
                base_asset_internal: hash(556),
                quote_asset_internal: hash(588),
                quote_atoms_per_whole_base: u64_at(620),
                outstanding_base_atoms: u128_at(628),
                redeemable_reserve_quote_atoms: u128_at(644),
                required_reserve_quote_atoms: u128_at(660),
            },
        };
        let a = value.accounting;
        let product = a
            .outstanding_base_atoms
            .checked_mul(u128::from(a.quote_atoms_per_whole_base))
            .ok_or(ChildJournal)?;
        let required = product / 100_000_000 + u128::from(product % 100_000_000 != 0);
        if [
            value.source_binding,
            value.accounting_binding,
            value.observation_statement_commitment,
            value.native_material_commitment,
            a.base_asset_internal,
            a.quote_asset_internal,
        ]
        .contains(&[0; 32])
            || a.base_asset_internal == a.quote_asset_internal
            || a.quote_atoms_per_whole_base == 0
            || a.outstanding_base_atoms == 0
            || required != a.required_reserve_quote_atoms
            || a.redeemable_reserve_quote_atoms < required
            || value.parent_confirmations == 0
            || value.child_mtp == 0
            || value.child_mtp > value.observation_mtp
            || value.observation_mtp != child.observation_time
        {
            return Err(ChildJournal);
        }
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> [u8; NATIVE_CONVERSION_SOURCE_PUBLIC_BYTES_V3] {
        let mut bytes = Vec::with_capacity(NATIVE_CONVERSION_SOURCE_PUBLIC_BYTES_V3);
        bytes.push(NATIVE_CONVERSION_SOURCE_VERSION_V3);
        bytes.extend_from_slice(&self.source_binding);
        bytes.extend_from_slice(&self.child.canonical_bytes());
        for hash in [
            self.accounting_binding,
            self.observation_statement_commitment,
            self.native_material_commitment,
        ] {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&self.child_mtp.to_be_bytes());
        bytes.extend_from_slice(&self.observation_mtp.to_be_bytes());
        bytes.extend_from_slice(&self.parent_confirmations.to_be_bytes());
        for hash in [
            self.accounting.base_asset_internal,
            self.accounting.quote_asset_internal,
        ] {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&self.accounting.quote_atoms_per_whole_base.to_be_bytes());
        for amount in [
            self.accounting.outstanding_base_atoms,
            self.accounting.redeemable_reserve_quote_atoms,
            self.accounting.required_reserve_quote_atoms,
        ] {
            bytes.extend_from_slice(&amount.to_be_bytes());
        }
        bytes.try_into().expect("fixed native source journal size")
    }

    /// Mandatory downstream trust-root check; a receipt does not review its
    /// own witness-selected checkpoint or authorize redemption.
    pub fn require_frozen_source(
        &self,
        expected: Hash32,
    ) -> Result<(), NativeConversionSourceErrorV3> {
        if expected == [0; 32] || expected != self.source_binding {
            return Err(NativeConversionSourceErrorV3::Binding);
        }
        Ok(())
    }

    /// Recover final-conversion context only from byte-exact committed preimages.
    /// The caller must first cryptographically verify this source journal under
    /// its pinned source-program ID. This method does not verify a receipt or
    /// establish redemption availability.
    pub fn require_conversion_preimages(
        &self,
        frozen: &NativeConversionSourceBindingV3,
        expected_source: Hash32,
        observation: &FullAlphaStatementV3,
        successor: &ChildExecutionCheckpointV3,
        accounting: &ConversionAccountingBindingV3,
    ) -> Result<(), NativeConversionSourceErrorV3> {
        use NativeConversionSourceErrorV3::Binding;
        frozen.require_frozen(expected_source)?;
        self.require_frozen_source(expected_source)?;
        // Public structs are constructible directly: validate the exact journal
        // too, rather than assuming every caller used the canonical decoder.
        if Self::from_canonical_bytes(&self.canonical_bytes())? != *self {
            return Err(Binding);
        }
        accounting.require_frozen(frozen.accounting_binding).map_err(|_| Binding)?;
        successor.require_frozen(self.child.next_checkpoint).map_err(|_| Binding)?;
        if self.accounting_binding != frozen.accounting_binding
            || observation.binding != frozen.parent.parent
            || statement_commitment(observation)? != self.observation_statement_commitment
            || observation.terminal_mtp != self.observation_mtp
            || successor.genesis_internal != accounting.child_genesis_internal
            || successor.configuration_commitment != accounting.child_configuration_commitment
            || self.child.source_binding != frozen.child_binding()?.commitment().map_err(|_| Binding)?
            || self.parent_confirmations < frozen.minimum_parent_confirmations
            || self.observation_mtp.checked_sub(self.child_mtp).ok_or(Binding)? > frozen.maximum_child_age_seconds
            || derive_accounting(successor, accounting.classification,
                accounting.quote_atoms_per_whole_base).map_err(|_| Binding)? != self.accounting {
            return Err(Binding);
        }
        Ok(())
    }
}

fn statement_commitment(
    statement: &FullAlphaStatementV3,
) -> Result<Hash32, NativeConversionSourceErrorV3> {
    let bytes = crate::encode_full_alpha_statement_v3(statement)
        .map_err(|_| NativeConversionSourceErrorV3::Parent)?;
    Ok(crate::tagged_hash(
        "ECX/alpha-conversion-parent-statement/v3",
        &bytes,
    ))
}

/// Verify the source receipt and its exact final-conversion preimages together.
/// Both expected values must originate in the independently frozen outer
/// configuration. This authenticates source context, NOT redemption capability.
pub fn verify_native_conversion_source_receipt_v3(
    receipt: &AlphaRecursiveReceiptBindingV3,
    expected_program: Hash32,
    expected_source: Hash32,
    frozen: &NativeConversionSourceBindingV3,
    observation: &FullAlphaStatementV3,
    successor: &ChildExecutionCheckpointV3,
    accounting: &ConversionAccountingBindingV3,
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<NativeConversionSourcePublicValuesV3, NativeConversionSourceErrorV3> {
    use NativeConversionSourceErrorV3::Binding;
    if !crate::alpha_sp1_program_id_is_canonical_v3(expected_program)
        || [frozen.child_execution_program_id, frozen.simplicity_evaluator_program_id,
            frozen.parent.parent.checkpoint_program_id, frozen.parent.parent.transition_program_id]
            .contains(&expected_program)
        || receipt.proof_marker.is_empty()
        || receipt.proof_marker.len() > MAX_FULL_ALPHA_RECEIPT_MARKER_BYTES_V3 {
        return Err(Binding);
    }
    let source = NativeConversionSourcePublicValuesV3::from_canonical_bytes(&receipt.public_values)?;
    source.require_conversion_preimages(frozen, expected_source, observation, successor, accounting)?;
    verifier.verify(expected_program, &receipt.public_values, &receipt.proof_marker)
        .map_err(|_| Binding)?;
    Ok(source)
}

/// Q-to-observation ancestry is proved by hash links ending at a fully executed
/// Alpha selected tip. A reorg branch which excludes Q cannot satisfy this.
pub(crate) fn verify_continuation(
    parent: &AlphaConversionParentLinkPublicValuesV3,
    observation: &FullAlphaStatementV3,
    headers: &[Vec<u8>],
    minimum: u32,
) -> Result<u32, NativeConversionSourceErrorV3> {
    use NativeConversionSourceErrorV3::Finality;
    let distance = observation
        .terminal_selected_height
        .checked_sub(parent.parent_height)
        .ok_or(Finality)?;
    if usize::try_from(distance).map_err(|_| Finality)? != headers.len() {
        return Err(Finality);
    }
    let mut previous = parent.parent_block_hash_internal;
    for bytes in headers {
        let header: bitcoin::block::Header =
            bitcoin::consensus::deserialize(bytes).map_err(|_| Finality)?;
        if bytes.len() != 80
            || bitcoin::consensus::serialize(&header) != *bytes
            || header.prev_blockhash.to_byte_array() != previous
        {
            return Err(Finality);
        }
        previous = header.block_hash().to_byte_array();
    }
    if previous != observation.terminal_tip_hash_internal {
        return Err(Finality);
    }
    if distance == 0
        && (parent.parent_terminal_state_commitment
            != observation.terminal_selected_state_commitment
            || parent.parent_statement_commitment != statement_commitment(observation)?)
    {
        return Err(Finality);
    }
    let confirmations = distance.checked_add(1).ok_or(Finality)?;
    if minimum == 0 || confirmations < minimum {
        return Err(Finality);
    }
    Ok(confirmations)
}

/// Verify the exact child receipt, independent parent replay, branch, committed
/// native checkpoint/history preimages and accounting under a frozen source.
/// The real SP1 guest supplies a cryptographic verifier, not a marker matcher.
pub fn execute_native_conversion_source_v3(
    input: &NativeConversionSourceInputV3,
    expected_source_binding: Hash32,
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<NativeConversionSourcePublicValuesV3, NativeConversionSourceErrorV3> {
    use NativeConversionSourceErrorV3::*;
    input.check_shape()?;
    input.binding.require_frozen(expected_source_binding)?;
    let frozen = &input.binding;
    if input.parent.binding != frozen.parent || input.observation.binding != frozen.parent.parent {
        return Err(Binding);
    }
    input
        .predecessor
        .require_frozen(frozen.predecessor_checkpoint)
        .map_err(|_| Checkpoint)?;
    if input.predecessor.genesis_internal != frozen.parent.child_genesis_hash_internal
        || input.predecessor.configuration_commitment
            != frozen.parent.child_consensus_configuration_commitment
        || input.predecessor.tip_internal != frozen.parent.child_checkpoint_hash_internal
        || input.predecessor.height != frozen.parent.child_checkpoint_height
    {
        return Err(Checkpoint);
    }
    input
        .execution_policy
        .require_frozen(frozen.execution_policy, &input.predecessor)
        .map_err(|_| Binding)?;
    if input
        .deposit_configuration
        .commitment()
        .map_err(|_| Binding)?
        != frozen.deposit_configuration
        || input.deposit_configuration.pegged_asset_internal
            != input.execution_policy.classification.base_asset_id
    {
        return Err(Binding);
    }
    input
        .accounting
        .require_frozen(frozen.accounting_binding)
        .map_err(|_| Binding)?;
    if input.accounting.classification != input.execution_policy.classification
        || input.accounting.child_genesis_internal != input.predecessor.genesis_internal
        || input.accounting.child_configuration_commitment
            != input.predecessor.configuration_commitment
    {
        return Err(Binding);
    }
    let parent =
        execute_alpha_conversion_parent_link_v3(&input.parent, verifier).map_err(|_| Parent)?;
    let observation =
        crate::execute_full_alpha_adapter_v3(&input.observation, verifier).map_err(|_| Parent)?;
    let confirmations = verify_continuation(
        &parent,
        &observation,
        &input.parent_continuation,
        frozen.minimum_parent_confirmations,
    )?;
    let observed_time = match frozen.clock_policy {
        NativeSourceClockPolicyV3::ParentObservationMtp => observation.terminal_mtp,
    };
    if observed_time == 0 {
        return Err(Clock);
    }
    let child =
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&input.child_receipt.public_values)
            .map_err(|_| ChildJournal)?;
    child
        .require_source_and_clock(
            frozen.child_binding()?.commitment().map_err(|_| Binding)?,
            observed_time,
        )
        .map_err(|_| Clock)?;
    if child.parent != parent {
        return Err(Parent);
    }
    if child.predecessor_checkpoint != frozen.predecessor_checkpoint
        || child.next_checkpoint != input.successor.commitment().map_err(|_| Checkpoint)?
        || child.child_height != input.predecessor.height.checked_add(1).ok_or(Checkpoint)?
        || input.successor.height != child.child_height
        || input.successor.tip_internal != child.child_hash_internal
        || input.successor.genesis_internal != input.predecessor.genesis_internal
        || input.successor.configuration_commitment != input.predecessor.configuration_commitment
    {
        return Err(Checkpoint);
    }
    verifier
        .verify(
            frozen.child_execution_program_id,
            &input.child_receipt.public_values,
            &input.child_receipt.proof_marker,
        )
        .map_err(|_| ChildReceipt)?;
    let mut history: Vec<NativeHeader> = input
        .predecessor_history
        .iter()
        .map(|h| NativeHeader::decode(h, true).map_err(|_| History))
        .collect::<Result<_, _>>()?;
    input
        .predecessor
        .checked_mtp_history(&history)
        .map_err(|_| History)?;
    let segwit = input
        .execution_policy
        .deployments
        .buried
        .at_height(child.child_height)
        .map_err(|_| Binding)?
        .segwit;
    let material = crate::native_child_block_v3::verify_native_child_commitments(
        &input.raw_child_block,
        input.predecessor.genesis_internal,
        elements::BlockHash::from_byte_array(input.predecessor.tip_internal),
        child.child_height,
        parent.parent_predecessor_hash_internal,
        parent.m7_critical_hash_internal,
        &input.predecessor.withdrawals,
        segwit,
    )
    .map_err(|_| NativeMaterial)?;
    if material
        .native_header
        .hash_internal()
        .map_err(|_| NativeMaterial)?
        != child.child_hash_internal
        || material.next_accumulator != input.successor.withdrawals
    {
        return Err(NativeMaterial);
    }
    history.push(material.native_header);
    if child_history_commitment(&history).map_err(|_| History)?
        != input.successor.history_commitment
    {
        return Err(History);
    }
    let mut times: Vec<u64> = input
        .successor
        .checked_mtp_history(&history)
        .map_err(|_| History)?
        .iter()
        .map(|h| u64::from(h.base.time))
        .collect();
    times.sort_unstable();
    let child_mtp = times[times.len() / 2];
    if child_mtp == 0
        || observed_time.checked_sub(child_mtp).ok_or(Clock)? > frozen.maximum_child_age_seconds
    {
        return Err(Clock);
    }
    // Both the authenticated checkpoint AND its economic classification are
    // now tied to the exact executed policy; equal unbound totals cannot pass.
    let accounting = derive_accounting(
        &input.successor,
        input.accounting.classification,
        input.accounting.quote_atoms_per_whole_base,
    )
    .map_err(Accounting)?;
    let mut material_bytes = vec![NATIVE_CONVERSION_SOURCE_VERSION_V3];
    material_bytes.extend_from_slice(&(input.predecessor_history.len() as u32).to_be_bytes());
    material_bytes.extend_from_slice(&(input.parent_continuation.len() as u32).to_be_bytes());
    for raw in std::iter::once(&input.raw_child_block)
        .chain(std::iter::once(&input.parent.terminal_parent_block))
        .chain(input.predecessor_history.iter())
        .chain(input.parent_continuation.iter())
    {
        material_bytes.extend_from_slice(&(raw.len() as u64).to_be_bytes());
        material_bytes.extend_from_slice(raw);
    }
    Ok(NativeConversionSourcePublicValuesV3 {
        source_binding: expected_source_binding,
        child,
        accounting_binding: frozen.accounting_binding,
        observation_statement_commitment: statement_commitment(&observation)?,
        native_material_commitment: crate::tagged_hash(
            "ECX/alpha-native-conversion-material/v3",
            &material_bytes,
        ),
        child_mtp,
        observation_mtp: observed_time,
        parent_confirmations: confirmations,
        accounting,
    })
}

#[cfg(test)]
pub(crate) mod tests;
