//! Alpha conversion's parent/BMM boundary, NOT its economic conversion proof.
//!
//! This distinct relation composes the real Alpha recursive receipt verifier
//! with the exact terminal parent block, its authenticated predecessor state,
//! fixed-policy slot-24 replay and its opaque M7 critical commitment. It proves
//! the parent half only, NOT a child block link, child consensus, deposit
//! validity, reserves, or conversion. In particular, current native Alpha's
//! ELMTP coinbase and withdrawal-accumulator checkpoint are NOT the legacy
//! patched BMM-proof header format. Neither child format is accepted here.
//! A consumer MUST freeze/check `binding_commitment`; a caller-selected
//! checkpoint/program ID is not a trust root. In particular, the reviewed
//! checkpoint relation authenticates a *reviewed preimage*, not genesis replay.
//!
//! Only a one-step terminal selected-chain extension is supported here. Earlier
//! receipts retain the complete Alpha frontier/reorg semantics. Child bindings
//! are declared consumer trust roots, not statements that a child checkpoint
//! has been verified here. A future native child receipt must prove its own
//! branch/consensus/accumulator transition and cross-bind the exact parent P,
//! M7 critical commitment, frozen child configuration and checkpoint before
//! any economic journal exists.

use super::*;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::Block;
use ecx_full_consensus_validator_v2::bip300_v2::alpha_bip300_v3::{
    apply_alpha_bip300_block_v3, ALPHA_BIP300_ACTIVATION_HEIGHT_V3,
};
use ecx_full_consensus_validator_v2::BITCOIN_MAX_BLOCK_WEIGHT_V2;

/// Intentionally neither the 0xa3 parent-adapter ABI nor the v2 economic ABI.
pub const ALPHA_CONVERSION_PARENT_LINK_VERSION_V3: u8 = 0xa4;
pub const ALPHA_CONVERSION_PARENT_LINK_PUBLIC_BYTES_V3: usize = 266;
pub const MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3: usize = 24 * 1024 * 1024;
pub const ALPHA_CONVERSION_SLOT_V3: u8 = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AlphaConversionPurposeV3 {
    ParentBmmLinkOnly,
    /// Deliberately rejected: no Alpha child-deposit relation is implemented.
    EconomicConversion,
    /// Also rejected: the native Alpha child/accumulator relation is missing.
    NativeChildAndParentLink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaConversionLinkBindingV3 {
    pub parent: AlphaRecursiveBindingV3,
    pub child_consensus_configuration_commitment: Hash32,
    pub child_genesis_hash_internal: Hash32,
    /// Independently authenticated/frozen child checkpoint; not inferred from
    /// a native node's claimed tip or one-confirmation peg-in acceptance.
    pub child_checkpoint_hash_internal: Hash32,
    pub child_checkpoint_height: u32,
    pub slot24_proposal_hash: Hash32,
    pub slot24_activation_height: u32,
}

impl AlphaConversionLinkBindingV3 {
    pub fn commitment(&self) -> Result<Hash32, AlphaConversionLinkErrorV3> {
        self.parent
            .validate()
            .map_err(|_| AlphaConversionLinkErrorV3::Binding)?;
        if [
            self.child_consensus_configuration_commitment,
            self.child_genesis_hash_internal,
            self.child_checkpoint_hash_internal,
            self.slot24_proposal_hash,
        ]
        .contains(&[0; 32])
            || self.slot24_activation_height < ALPHA_BIP300_ACTIVATION_HEIGHT_V3
            || self.child_checkpoint_height == u32::MAX
            || (self.child_checkpoint_height == 0
                && self.child_checkpoint_hash_internal != self.child_genesis_hash_internal)
        {
            return Err(AlphaConversionLinkErrorV3::Binding);
        }
        let mut bytes = vec![
            ALPHA_CONVERSION_PARENT_LINK_VERSION_V3,
            ALPHA_CONVERSION_SLOT_V3,
        ];
        bytes.extend_from_slice(&alpha_consensus_profile_commitment_v3());
        bytes.extend_from_slice(
            &self
                .parent
                .commitment()
                .map_err(|_| AlphaConversionLinkErrorV3::Binding)?,
        );
        for hash in [
            self.child_consensus_configuration_commitment,
            self.child_genesis_hash_internal,
            self.child_checkpoint_hash_internal,
            self.slot24_proposal_hash,
        ] {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&self.child_checkpoint_height.to_be_bytes());
        bytes.extend_from_slice(&self.slot24_activation_height.to_be_bytes());
        Ok(tagged_hash(
            "ECX/alpha-conversion-parent-link-binding/v3",
            &bytes,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaConversionParentLinkInputV3 {
    pub version: u8,
    pub purpose: AlphaConversionPurposeV3,
    pub binding: AlphaConversionLinkBindingV3,
    pub parent: FullAlphaAdapterInputV3,
    /// Authenticated by the last transition's predecessor-state commitment.
    pub terminal_parent_predecessor: AlphaExecutedConsensusStateV3,
    pub terminal_parent_block: Vec<u8>,
    /// Intended downstream child binding, independently matched against P.
    pub expected_parent_hash_internal: Hash32,
    /// Opaque native critical commitment. Its child/accumulator preimage is
    /// intentionally not authenticated by this parent-only relation.
    pub expected_critical_hash_internal: Hash32,
    /// MUST be empty. Legacy or native child bytes cannot turn parent-only
    /// success into an accepted child lane, and are never decoded/indexed.
    pub candidate_child_block: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlphaConversionParentLinkPublicValuesV3 {
    pub binding_commitment: Hash32,
    pub parent_statement_commitment: Hash32,
    pub parent_predecessor_state_commitment: Hash32,
    pub parent_terminal_state_commitment: Hash32,
    pub parent_block_hash_internal: Hash32,
    pub parent_height: u32,
    pub parent_predecessor_hash_internal: Hash32,
    pub m7_critical_hash_internal: Hash32,
    pub m7_coinbase_vout: u32,
}

impl AlphaConversionParentLinkPublicValuesV3 {
    /// Exact native parent-link ABI. In particular, neither a legacy economic
    /// journal nor a different consensus profile is a parent receipt.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AlphaConversionLinkErrorV3> {
        if bytes.len() != ALPHA_CONVERSION_PARENT_LINK_PUBLIC_BYTES_V3
            || bytes[0] != ALPHA_CONVERSION_PARENT_LINK_VERSION_V3 || bytes[1] != 0
            || bytes[2..34] != alpha_consensus_profile_commitment_v3() {
            return Err(AlphaConversionLinkErrorV3::Input);
        }
        let hash = |start: usize| -> Hash32 { bytes[start..start+32].try_into().unwrap() };
        let result = Self {
            binding_commitment: hash(34), parent_statement_commitment: hash(66),
            parent_predecessor_state_commitment: hash(98), parent_terminal_state_commitment: hash(130),
            parent_block_hash_internal: hash(162), parent_predecessor_hash_internal: hash(194),
            m7_critical_hash_internal: hash(226),
            parent_height: u32::from_be_bytes(bytes[258..262].try_into().unwrap()),
            m7_coinbase_vout: u32::from_be_bytes(bytes[262..266].try_into().unwrap()),
        };
        if [result.binding_commitment,result.parent_statement_commitment,
            result.parent_predecessor_state_commitment,result.parent_terminal_state_commitment,
            result.parent_block_hash_internal,result.parent_predecessor_hash_internal,
            result.m7_critical_hash_internal].contains(&[0;32]) || result.parent_height == 0
            || result.parent_block_hash_internal == result.parent_predecessor_hash_internal {
            return Err(AlphaConversionLinkErrorV3::Binding);
        }
        Ok(result)
    }

    pub fn canonical_bytes(self) -> [u8; ALPHA_CONVERSION_PARENT_LINK_PUBLIC_BYTES_V3] {
        let mut bytes = [0; ALPHA_CONVERSION_PARENT_LINK_PUBLIC_BYTES_V3];
        bytes[0] = ALPHA_CONVERSION_PARENT_LINK_VERSION_V3;
        bytes[1] = 0; // ParentBmmLinkOnly; there is no economic success encoding.
        let mut cursor = 2;
        for hash in [
            alpha_consensus_profile_commitment_v3(),
            self.binding_commitment,
            self.parent_statement_commitment,
            self.parent_predecessor_state_commitment,
            self.parent_terminal_state_commitment,
            self.parent_block_hash_internal,
            self.parent_predecessor_hash_internal,
            self.m7_critical_hash_internal,
        ] {
            bytes[cursor..cursor + 32].copy_from_slice(&hash);
            cursor += 32;
        }
        for value in [self.parent_height, self.m7_coinbase_vout] {
            bytes[cursor..cursor + 4].copy_from_slice(&value.to_be_bytes());
            cursor += 4;
        }
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }

    /// Mandatory outer-consumer trust-root check, separate from guest proof
    /// verification. No witness or helper here claims to perform review.
    pub fn require_frozen_binding(
        &self,
        expected: Hash32,
    ) -> Result<(), AlphaConversionLinkErrorV3> {
        if expected == [0; 32] || expected != self.binding_commitment {
            Err(AlphaConversionLinkErrorV3::Binding)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum AlphaConversionLinkErrorV3 {
    #[error("unsupported Alpha conversion-link version or noncanonical/resource-limited input")]
    Input,
    #[error("Alpha conversion source/program/checkpoint binding mismatch")]
    Binding,
    #[error("Alpha recursive receipt chain rejected")]
    Receipt,
    #[error("terminal parent is not a supported authenticated selected-chain extension")]
    ParentBranch,
    #[error("terminal parent block or all-slot replay mismatch")]
    ParentBlock,
    #[error("slot 24 is not the frozen active deployment")]
    Slot24,
    #[error("opaque M7 critical commitment or predecessor parent binding mismatch")]
    M7Link,
    #[error("USDD root transaction was not approved by authenticated Alpha replay")]
    M6Approval,
    #[error("full Alpha child consensus/deposit/economic conversion lane is not implemented")]
    UnsupportedAlphaChildEconomicLane,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3 as u64)
}

fn validate_input(
    input: &AlphaConversionParentLinkInputV3,
) -> Result<(), AlphaConversionLinkErrorV3> {
    if input.purpose != AlphaConversionPurposeV3::ParentBmmLinkOnly
        || !input.candidate_child_block.is_empty()
    {
        return Err(AlphaConversionLinkErrorV3::UnsupportedAlphaChildEconomicLane);
    }
    if input.version != ALPHA_CONVERSION_PARENT_LINK_VERSION_V3
        || options()
            .serialized_size(input)
            .map_err(|_| AlphaConversionLinkErrorV3::Input)?
            > MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3 as u64
    {
        return Err(AlphaConversionLinkErrorV3::Input);
    }
    input.binding.commitment()?;
    if input.expected_parent_hash_internal == [0; 32]
        || input.expected_critical_hash_internal == [0; 32]
    {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    if input.binding.parent != input.parent.binding {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    Ok(())
}

pub fn encode_alpha_conversion_parent_link_input_v3(
    input: &AlphaConversionParentLinkInputV3,
) -> Result<Vec<u8>, AlphaConversionLinkErrorV3> {
    validate_input(input)?;
    options()
        .serialize(input)
        .map_err(|_| AlphaConversionLinkErrorV3::Input)
}

pub fn decode_alpha_conversion_parent_link_input_v3(
    bytes: &[u8],
) -> Result<AlphaConversionParentLinkInputV3, AlphaConversionLinkErrorV3> {
    if bytes.is_empty() || bytes.len() > MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3 {
        return Err(AlphaConversionLinkErrorV3::Input);
    }
    let input = options()
        .deserialize(bytes)
        .map_err(|_| AlphaConversionLinkErrorV3::Input)?;
    if encode_alpha_conversion_parent_link_input_v3(&input)? != bytes {
        return Err(AlphaConversionLinkErrorV3::Input);
    }
    Ok(input)
}

pub(crate) fn authenticate_terminal_parent<V: FullAlphaReceiptVerifierV3>(
    binding: &AlphaConversionLinkBindingV3,
    parent_input: &FullAlphaAdapterInputV3,
    predecessor: &AlphaExecutedConsensusStateV3,
    raw_block: &[u8],
    verifier: &V,
) -> Result<(FullAlphaStatementV3, Block, ecx_full_consensus_validator_v2::bip300_v2::Bip300BlockEffectsV2), AlphaConversionLinkErrorV3> {
    binding.commitment()?;
    if binding.parent != parent_input.binding {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    if options().serialized_size(&(binding, parent_input, predecessor, raw_block))
        .map_err(|_| AlphaConversionLinkErrorV3::Input)?
        > MAX_ALPHA_CONVERSION_PARENT_LINK_INPUT_BYTES_V3 as u64 {
        return Err(AlphaConversionLinkErrorV3::Input);
    }
    // No host-only or marker-only substitute: every underlying receipt is
    // verified by this trait, implemented with SP1 verify_sp1_proof in guest.
    let parent = execute_full_alpha_adapter_v3(parent_input, verifier)
        .map_err(|_| AlphaConversionLinkErrorV3::Receipt)?;
    let last = decode_full_alpha_transition_public_values_v3(
        &parent_input
            .transition_receipts
            .last()
            .ok_or(AlphaConversionLinkErrorV3::ParentBranch)?
            .public_values,
    )
    .map_err(|_| AlphaConversionLinkErrorV3::ParentBranch)?;
    let terminal = &parent_input.terminal_selected_state;
    let predecessor_commitment = predecessor
        .commitment()
        .map_err(|_| AlphaConversionLinkErrorV3::ParentBranch)?;
    if predecessor.source_configuration_commitment
        != binding.parent.source_configuration_commitment
        || predecessor_commitment != last.predecessor_state_commitment
        || predecessor.tip.height != last.predecessor_height
        || predecessor.tip.height.checked_add(1) != Some(terminal.tip.height)
        || last.step_count != 1
        || terminal.tip.discovery_sequence != last.final_discovery_sequence
        || predecessor.tip.discovery_sequence >= terminal.tip.discovery_sequence
        || predecessor.deployment_state != terminal.deployment_state
    {
        return Err(AlphaConversionLinkErrorV3::ParentBranch);
    }
    // Receipts establish full Alpha PoW/script/UTXO/frontier consensus. Here
    // bind exact raw transactions to that authenticated terminal header again.
    let block: Block = deserialize(raw_block)
        .map_err(|_| AlphaConversionLinkErrorV3::ParentBlock)?;
    if serialize(&block) != raw_block
        || block.weight().to_wu() > BITCOIN_MAX_BLOCK_WEIGHT_V2
        || block.block_hash() != terminal.tip.block_hash
        || block.header != terminal.pow_context.previous_header
        || block.header.prev_blockhash != predecessor.tip.block_hash
        || !block.check_merkle_root()
        || !block.check_witness_commitment()
        || !block
            .txdata
            .first()
            .is_some_and(bitcoin::Transaction::is_coinbase)
        || block
            .txdata
            .iter()
            .skip(1)
            .any(bitcoin::Transaction::is_coinbase)
    {
        return Err(AlphaConversionLinkErrorV3::ParentBlock);
    }
    let mut txids = std::collections::HashSet::new();
    if !block
        .txdata
        .iter()
        .all(|tx| txids.insert(tx.compute_txid()))
    {
        return Err(AlphaConversionLinkErrorV3::ParentBlock);
    }
    for state in [&predecessor.bip300_state, &terminal.bip300_state] {
        let active = state
            .as_state()
            .active_slots
            .get(&ALPHA_CONVERSION_SLOT_V3)
            .ok_or(AlphaConversionLinkErrorV3::Slot24)?;
        if active.proposal_hash != binding.slot24_proposal_hash
            || active.activation_height != binding.slot24_activation_height
        {
            return Err(AlphaConversionLinkErrorV3::Slot24);
        }
    }
    let (next_slots, effects) = apply_alpha_bip300_block_v3(&predecessor.bip300_state, &block)
        .map_err(|_| AlphaConversionLinkErrorV3::ParentBlock)?;
    if next_slots != terminal.bip300_state {
        return Err(AlphaConversionLinkErrorV3::ParentBlock);
    }
    Ok((parent, block, effects))
}

/// Owned, untrusted parent-block evidence for guest transport. Authentication
/// is reconstructed inside the consumer, never deserialized as a trusted flag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaDepositParentBlockWitnessV3 {
    pub parent: FullAlphaAdapterInputV3,
    pub predecessor: AlphaExecutedConsensusStateV3,
    pub raw_block: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaDepositWitnessV3 {
    pub outpoint: bitcoin::OutPoint,
    pub inclusion: AlphaDepositParentBlockWitnessV3,
    /// Every intervening selected parent block, oldest first.
    pub confirmations: Vec<AlphaDepositParentBlockWitnessV3>,
}

impl AlphaDepositWitnessV3 {
    /// The anchor, state, binding and depth are consumer trust inputs, not
    /// fields accepted from this witness. Child kernel/claim checks still apply.
    pub fn authenticate<V: FullAlphaReceiptVerifierV3>(
        &self, binding: &AlphaConversionLinkBindingV3, frozen_binding: Hash32,
        expected_anchor: Hash32, expected_state: Hash32, minimum_depth: u32,
        verifier: &V,
    ) -> Result<AuthenticatedAlphaDepositV3, AlphaConversionLinkErrorV3> {
        if expected_anchor == [0;32] || expected_state == [0;32] {
            return Err(AlphaConversionLinkErrorV3::ParentBranch);
        }
        let mut authenticated = authenticate_alpha_deposit_v3(binding, frozen_binding,
            &self.inclusion.parent, &self.inclusion.predecessor,
            &self.inclusion.raw_block, self.outpoint, verifier)?;
        for block in &self.confirmations {
            authenticated = extend_alpha_deposit_confirmation_v3(&authenticated,
                binding, &block.parent, &block.predecessor, &block.raw_block, verifier)?;
        }
        if authenticated.confirmed_anchor() != expected_anchor
            || authenticated.parent_state_commitment() != expected_state
            || authenticated.confirmations() < minimum_depth.max(1) {
            return Err(AlphaConversionLinkErrorV3::ParentBranch);
        }
        Ok(authenticated)
    }
}

/// Parent-side M5 inclusion only. Child asset/address checks and confirmation
/// policy remain mandatory before this effect can authorize a child mint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedAlphaDepositV3 {
    deposit: ecx_full_consensus_validator_v2::bip300_v2::Bip300DepositV2,
    binding_commitment: Hash32,
    parent_state_commitment: Hash32,
    confirmed_anchor: Hash32,
    confirmations: u32,
}

impl AuthenticatedAlphaDepositV3 {
    pub fn deposit(&self) -> &ecx_full_consensus_validator_v2::bip300_v2::Bip300DepositV2 {
        &self.deposit
    }
    pub fn binding_commitment(&self) -> Hash32 { self.binding_commitment }
    pub fn parent_state_commitment(&self) -> Hash32 { self.parent_state_commitment }
    pub fn confirmed_anchor(&self) -> Hash32 { self.confirmed_anchor }
    pub fn confirmations(&self) -> u32 { self.confirmations }
}

/// Extend deposit authentication by exactly one fully verified parent block.
/// Linking complete state commitments, not merely heights, prevents an unrelated
/// branch from supplying confirmations. Repeat for each block up to the child
/// anchor; checkpoint-to-tip proofs alone do not establish deposit ancestry.
pub fn extend_alpha_deposit_confirmation_v3<V: FullAlphaReceiptVerifierV3>(
    deposit: &AuthenticatedAlphaDepositV3,
    binding: &AlphaConversionLinkBindingV3,
    parent: &FullAlphaAdapterInputV3,
    predecessor: &AlphaExecutedConsensusStateV3,
    raw_block: &[u8], verifier: &V,
) -> Result<AuthenticatedAlphaDepositV3, AlphaConversionLinkErrorV3> {
    if binding.commitment()? != deposit.binding_commitment
        || predecessor.commitment().map_err(|_|AlphaConversionLinkErrorV3::ParentBranch)?
            != deposit.parent_state_commitment
        || predecessor.tip.block_hash.to_byte_array() != deposit.confirmed_anchor {
        return Err(AlphaConversionLinkErrorV3::ParentBranch);
    }
    let (statement, _, _) = authenticate_terminal_parent(binding,parent,predecessor,raw_block,verifier)?;
    let mut confirmed = deposit.clone();
    confirmed.parent_state_commitment = statement.terminal_selected_state_commitment;
    confirmed.confirmed_anchor = statement.terminal_tip_hash_internal;
    confirmed.confirmations = confirmed.confirmations.checked_add(1)
        .ok_or(AlphaConversionLinkErrorV3::ParentBranch)?;
    Ok(confirmed)
}

/// Authenticate the receipt chain and replay exact terminal-block M5 effects.
/// The frozen binding must come from the consumer's independently reviewed
/// configuration. This function deliberately does not implement the legacy
/// Bitcoin deposit receipt trait or claim complete child deposit validity.
pub fn authenticate_alpha_deposit_v3<V: FullAlphaReceiptVerifierV3>(
    binding: &AlphaConversionLinkBindingV3,
    frozen_binding: Hash32,
    parent: &FullAlphaAdapterInputV3,
    predecessor: &AlphaExecutedConsensusStateV3,
    raw_block: &[u8],
    outpoint: bitcoin::OutPoint,
    verifier: &V,
) -> Result<AuthenticatedAlphaDepositV3, AlphaConversionLinkErrorV3> {
    if frozen_binding == [0; 32] || binding.commitment()? != frozen_binding {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    let (statement, _, effects) =
        authenticate_terminal_parent(binding, parent, predecessor, raw_block, verifier)?;
    let mut matching = effects.deposits.into_iter().filter(|deposit| {
        deposit.slot == ALPHA_CONVERSION_SLOT_V3 && deposit.outpoint.outpoint == outpoint
    });
    let deposit = matching.next().ok_or(AlphaConversionLinkErrorV3::ParentBlock)?;
    if matching.next().is_some() {
        return Err(AlphaConversionLinkErrorV3::ParentBlock);
    }
    Ok(AuthenticatedAlphaDepositV3 {
        confirmed_anchor: deposit.block_hash.to_byte_array(),
        confirmations: 1,
        deposit,
        binding_commitment: frozen_binding,
        parent_state_commitment: statement.terminal_selected_state_commitment,
    })
}

/// Result of exact terminal-parent replay, not a caller-declared approval.
/// The marker preimage and its custody meaning remain the consumer's duty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedUsddM6V3 {
    approval: ecx_full_consensus_validator_v2::bip300_v2::Bip300ApprovedM6V2,
    marker: Hash32,
    binding_commitment: Hash32,
}
impl AuthenticatedUsddM6V3 {
    pub fn approval(&self) -> &ecx_full_consensus_validator_v2::bip300_v2::Bip300ApprovedM6V2 { &self.approval }
    pub fn marker(&self) -> Hash32 { self.marker }
    pub fn binding_commitment(&self) -> Hash32 { self.binding_commitment }

    /// Bind exact root-preimage bytes to the transaction approved by replay.
    /// This is not a custody/deployment or valid-transition check: the enclosing
    /// economic relation must match identities to its frozen configuration and
    /// authenticate the roots/counts against complete child history.
    pub fn verify_root_preimage(
        &self,
        root: &super::native_withdrawal_extraction_v3::UsddRootTransitionV1,
    ) -> Result<(), AlphaConversionLinkErrorV3> {
        if root.commitment() != self.marker {
            return Err(AlphaConversionLinkErrorV3::M6Approval);
        }
        Ok(())
    }

    /// Compose actual parent approval, exact root commitment, deployment
    /// matching and per-M6 claim inclusion. The enclosing economic guest must
    /// still authenticate child transaction position, frozen configuration,
    /// complete supply/history and redemption replay protection.
    pub fn verify_introduced_claim(
        &self, root: &super::native_withdrawal_extraction_v3::UsddRootTransitionV1,
        transaction: &elements::Transaction, genesis_internal: Hash32,
        first_index: u64, vout: u32, expected_parent_display: Hash32,
        expected_asset_display: Hash32, expected_vault: Hash32, siblings: &[Hash32],
    ) -> Result<super::native_withdrawal_extraction_v3::WithdrawalClaim, AlphaConversionLinkErrorV3> {
        self.verify_root_preimage(root)?;
        root.verify_introduced_claim(transaction, genesis_internal, first_index,
            vout, expected_parent_display, expected_asset_display, expected_vault, siblings)
            .map_err(|_| AlphaConversionLinkErrorV3::M6Approval)
    }
}

/// Does not require an M7 in the approval block: withdrawal approval can occur
/// independently of mining a child block. All receipts and exact block replay
/// are checked through the same terminal-parent path used by the M7 relation.
pub fn authenticate_usdd_m6_v3<V: FullAlphaReceiptVerifierV3>(
    binding: &AlphaConversionLinkBindingV3, frozen_binding: Hash32,
    parent: &FullAlphaAdapterInputV3, predecessor: &AlphaExecutedConsensusStateV3,
    raw_block: &[u8], transaction_id: bitcoin::Txid, verifier: &V,
) -> Result<AuthenticatedUsddM6V3, AlphaConversionLinkErrorV3> {
    if frozen_binding == [0;32] || binding.commitment()? != frozen_binding {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    let (_, block, effects) = authenticate_terminal_parent(binding, parent, predecessor, raw_block, verifier)?;
    let mut matches = effects.successful_m6s.iter().filter(|m|
        m.slot == ALPHA_CONVERSION_SLOT_V3 && m.transaction_id == transaction_id);
    let approval = *matches.next().ok_or(AlphaConversionLinkErrorV3::M6Approval)?;
    if matches.next().is_some() { return Err(AlphaConversionLinkErrorV3::M6Approval); }
    let transaction = block.txdata.iter().find(|tx| tx.compute_txid() == transaction_id)
        .ok_or(AlphaConversionLinkErrorV3::M6Approval)?;
    let marker = super::native_withdrawal_extraction_v3::usdd_m6_root_marker(transaction, ALPHA_CONVERSION_SLOT_V3)
        .map_err(|_| AlphaConversionLinkErrorV3::M6Approval)?;
    Ok(AuthenticatedUsddM6V3 { approval, marker, binding_commitment: frozen_binding })
}

/// Distinct V2 custody approval. A parent-approved opaque commitment is NOT
/// proof of a valid custody burn. No V1 root/claim methods are exposed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCustodyM6V2 {
    approval: CustodyBundleApprovalV3,
    commitment: Hash32,
    binding_commitment: Hash32,
    /// Complete replayed state, needed for ancestry checks; height alone is
    /// insufficient and a separate checkpoint-to-tip proof may select a fork.
    parent_state_commitment: Hash32,
}
/// Ethereum custody approval, not evidence that a parent CTIP was spent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyBundleApprovalV3 {
    pub slot: u8,
    pub m6id: bitcoin::Txid,
    pub transaction_id: bitcoin::Txid,
    pub block_hash: bitcoin::BlockHash,
    pub block_height: u32,
    pub early_acks: bool,
}

/// Six net acknowledgments, excluding the M3 proposal's initial score of one.
pub const ETH_CUSTODY_REQUIRED_ACKS_V3: u16 = 6;

/// Fixed-size opening of a checkpoint-only bundle. Store fields, not consensus
/// transaction bytes: a blinded zero-input M6 is not a decodable Bitcoin tx.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAckBundleV3 {
    pub transaction_version: i32,
    pub lock_time: u32,
    pub fee_sat: u64,
    pub checkpoint_commitment: Hash32,
}
impl CustodyAckBundleV3 {
    pub fn compute_txid(&self) -> bitcoin::Txid {
        let mut fee = vec![0x6a,8];
        fee.extend_from_slice(&self.fee_sat.to_be_bytes());
        let mut marker = b"\x6a\x27USDDM6\x02".to_vec();
        marker.extend_from_slice(&self.checkpoint_commitment);
        bitcoin::Transaction {
            version: bitcoin::transaction::Version(self.transaction_version),
            lock_time: bitcoin::absolute::LockTime::from_consensus(self.lock_time),
            input: vec![],
            output: [fee,marker].into_iter().map(|script| bitcoin::TxOut {
                value: bitcoin::Amount::ZERO, script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
            }).collect(),
        }.compute_txid()
    }
}

fn require_custody_ack_score(state: &AlphaExecutedConsensusStateV3, bundle: bitcoin::Txid)
    -> Result<(), AlphaConversionLinkErrorV3> {
    let pending = state.bip300_state.as_state().active_slots.get(&ALPHA_CONVERSION_SLOT_V3)
        .and_then(|slot| slot.pending_m6ids.iter().find(|pending| pending.m6id == bundle))
        .ok_or(AlphaConversionLinkErrorV3::M6Approval)?;
    if pending.score < 1 + ETH_CUSTODY_REQUIRED_ACKS_V3 {
        return Err(AlphaConversionLinkErrorV3::M6Approval);
    }
    Ok(())
}

/// Authenticate a blinded bundle preimage against replayed slot-24 pending
/// state. The preimage is NOT a mined transaction and cannot authorize L1 funds.
pub fn authenticate_custody_acks_v3<V: FullAlphaReceiptVerifierV3>(
    binding: &AlphaConversionLinkBindingV3, frozen_binding: Hash32,
    parent: &FullAlphaAdapterInputV3, predecessor: &AlphaExecutedConsensusStateV3,
    raw_block: &[u8], bundle: &CustodyAckBundleV3, verifier: &V,
) -> Result<AuthenticatedCustodyM6V2, AlphaConversionLinkErrorV3> {
    if frozen_binding == [0;32] || binding.commitment()? != frozen_binding {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    let commitment = bundle.checkpoint_commitment;
    if commitment == [0;32] { return Err(AlphaConversionLinkErrorV3::M6Approval); }
    let (statement, block, _) = authenticate_terminal_parent(binding,parent,predecessor,raw_block,verifier)?;
    let m6id = bundle.compute_txid();
    require_custody_ack_score(&parent.terminal_selected_state, m6id)?;
    Ok(AuthenticatedCustodyM6V2 { approval: CustodyBundleApprovalV3 {
        slot: ALPHA_CONVERSION_SLOT_V3, m6id, transaction_id: m6id,
        block_hash: block.block_hash(), block_height: parent.terminal_selected_state.tip.height,
        early_acks: true,
    }, commitment, binding_commitment: frozen_binding,
        parent_state_commitment: statement.terminal_selected_state_commitment })
}
impl AuthenticatedCustodyM6V2 {
    pub fn approval(&self) -> &CustodyBundleApprovalV3 { &self.approval }
    pub fn commitment(&self) -> Hash32 { self.commitment }
    pub fn binding_commitment(&self) -> Hash32 { self.binding_commitment }
    pub fn parent_state_commitment(&self) -> Hash32 { self.parent_state_commitment }
    /// Open the candidate checkpoint-approval commitment. The caller must
    /// supply the custody ID from frozen deployment configuration and the
    /// checkpoint from checked child execution, not from an unverified claim.
    /// This does not prove ancestry or post-approval finality.
    pub fn require_checkpoint_approval(&self, frozen_parent_binding: Hash32,
        frozen_custody: Hash32, executed_checkpoint: Hash32,
    ) -> Result<(), AlphaConversionLinkErrorV3> {
        if self.binding_commitment != frozen_parent_binding
            || self.commitment != custody_checkpoint_approval_commitment_v2(
                frozen_custody,executed_checkpoint)? {
            return Err(AlphaConversionLinkErrorV3::M6Approval);
        }
        Ok(())
    }
}

/// Authenticated descendants of an approval, not an assertion of economic
/// finality. The enclosing frozen policy must require an appropriate depth
/// and authenticate its destination anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyApprovalConfirmationsV2 {
    approval: AuthenticatedCustodyM6V2,
    state: Hash32,
    anchor: Hash32,
    confirmations: u32,
}
impl CustodyApprovalConfirmationsV2 {
    /// Open the already receipt-authenticated destination commitment into the
    /// tuple consumed by a parent relay. This does NOT establish canonical
    /// membership or freshness; the enclosing verifier must check the tuple
    /// against an independently authenticated relay.
    pub fn destination_tuple(&self, destination: &AlphaExecutedConsensusStateV3)
        -> Result<CustodyParentTupleV2, AlphaConversionLinkErrorV3> {
        if destination.commitment().map_err(|_|AlphaConversionLinkErrorV3::ParentBranch)? != self.state
            || destination.tip.block_hash.to_byte_array() != self.anchor {
            return Err(AlphaConversionLinkErrorV3::ParentBranch);
        }
        let mut block_hash_display = self.anchor;
        block_hash_display.reverse();
        Ok(CustodyParentTupleV2 { block_hash_display, height:destination.tip.height,
            median_time_past:ecx_full_consensus_validator_v2::median_time_past_v2(
                &destination.pow_context.previous_11_times).map_err(|_|AlphaConversionLinkErrorV3::ParentBranch)?,
            chainwork_be:destination.tip.chainwork_be })
    }
    pub fn new(approval: AuthenticatedCustodyM6V2) -> Self {
        Self { state: approval.parent_state_commitment,
            anchor: approval.approval.block_hash.to_byte_array(), confirmations: 1, approval }
    }
    pub fn approval(&self) -> &AuthenticatedCustodyM6V2 { &self.approval }
    pub fn state(&self) -> Hash32 { self.state }
    pub fn anchor(&self) -> Hash32 { self.anchor }
    /// Includes the approval block itself.
    pub fn confirmations(&self) -> u32 { self.confirmations }
    /// The caller must obtain these values from independently authenticated
    /// destination state and frozen policy, never from the witness's choices.
    /// This check does not itself authenticate a relay or choose finality rules.
    pub fn require_destination(&self, expected_state: Hash32, expected_anchor: Hash32,
        minimum_confirmations: u32,
    ) -> Result<(), AlphaConversionLinkErrorV3> {
        if minimum_confirmations == 0 || self.confirmations < minimum_confirmations
            || [expected_state,expected_anchor].contains(&[0;32])
            || self.state != expected_state || self.anchor != expected_anchor {
            return Err(AlphaConversionLinkErrorV3::ParentBranch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyParentTupleV2 {
    pub block_hash_display: Hash32,
    pub height: u32,
    pub median_time_past: u32,
    pub chainwork_be: Hash32,
}

pub fn extend_custody_approval_confirmation_v2<V: FullAlphaReceiptVerifierV3>(
    prior: &CustodyApprovalConfirmationsV2, binding: &AlphaConversionLinkBindingV3,
    parent: &FullAlphaAdapterInputV3, predecessor: &AlphaExecutedConsensusStateV3,
    raw_block: &[u8], verifier: &V,
) -> Result<CustodyApprovalConfirmationsV2, AlphaConversionLinkErrorV3> {
    if binding.commitment()? != prior.approval.binding_commitment
        || predecessor.commitment().map_err(|_|AlphaConversionLinkErrorV3::ParentBranch)? != prior.state
        || predecessor.tip.block_hash.to_byte_array() != prior.anchor {
        return Err(AlphaConversionLinkErrorV3::ParentBranch);
    }
    let (statement, _, _) = authenticate_terminal_parent(binding,parent,predecessor,raw_block,verifier)?;
    if prior.approval.approval.early_acks {
        // A lost score, expired/removed proposal, or different branch must not
        // inherit an earlier approval merely through confirmation depth.
        require_custody_ack_score(&parent.terminal_selected_state, prior.approval.approval.m6id)?;
    }
    let mut next = prior.clone();
    next.state = statement.terminal_selected_state_commitment;
    next.anchor = statement.terminal_tip_hash_internal;
    next.confirmations = prior.confirmations.checked_add(1)
        .ok_or(AlphaConversionLinkErrorV3::ParentBranch)?;
    Ok(next)
}

/// Candidate V2 preimage shared by the M6 producer and consumer. Approves
/// custody burns in one exact child execution checkpoint (whose tip commits
/// the block), not arbitrary V1 roots. This format is not deployed/frozen yet.
pub fn custody_checkpoint_approval_commitment_v2(custody_id: Hash32, executed_checkpoint: Hash32,
) -> Result<Hash32, AlphaConversionLinkErrorV3> {
    if [custody_id,executed_checkpoint].contains(&[0;32]) {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    let mut bytes = vec![2,ALPHA_CONVERSION_SLOT_V3];
    // Do not commit the terminal replay binding: it includes the approval
    // block itself and would make the M6 transaction self-referential.
    for value in [alpha_consensus_profile_commitment_v3(),custody_id,executed_checkpoint] { bytes.extend_from_slice(&value); }
    Ok(tagged_hash("USDD/custody-checkpoint-approval/v2",&bytes))
}

/// Candidate V2 marker transport over unchanged generic parent M6 rules.
/// Requires actual terminal replay approval and exact zero-value version-2
/// marker bytes. The enclosing redemption relation MUST verify the committed
/// preimage, custody/execution history and post-M6 finality separately.
pub fn authenticate_custody_m6_v2<V: FullAlphaReceiptVerifierV3>(
    binding: &AlphaConversionLinkBindingV3, frozen_binding: Hash32,
    parent: &FullAlphaAdapterInputV3, predecessor: &AlphaExecutedConsensusStateV3,
    raw_block: &[u8], transaction_id: bitcoin::Txid, verifier: &V,
) -> Result<AuthenticatedCustodyM6V2, AlphaConversionLinkErrorV3> {
    if frozen_binding == [0;32] || binding.commitment()? != frozen_binding {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    let (statement, block, effects) = authenticate_terminal_parent(binding, parent, predecessor, raw_block, verifier)?;
    let mut approvals = effects.successful_m6s.iter().filter(|m|
        m.slot == ALPHA_CONVERSION_SLOT_V3 && m.transaction_id == transaction_id);
    let approval = *approvals.next().ok_or(AlphaConversionLinkErrorV3::M6Approval)?;
    if approvals.next().is_some() { return Err(AlphaConversionLinkErrorV3::M6Approval); }
    let tx = block.txdata.iter().find(|tx| tx.compute_txid() == transaction_id)
        .ok_or(AlphaConversionLinkErrorV3::M6Approval)?;
    if tx.input.len() != 1 || tx.output.len() != 2 || tx.is_coinbase()
        || tx.output[0].script_pubkey.as_bytes() != [0xb4,1,ALPHA_CONVERSION_SLOT_V3,0x51]
        || tx.output[1].value != bitcoin::Amount::ZERO {
        return Err(AlphaConversionLinkErrorV3::M6Approval);
    }
    let marker = tx.output[1].script_pubkey.as_bytes();
    if marker.len() != 41 || &marker[..9] != b"\x6a\x27USDDM6\x02" {
        return Err(AlphaConversionLinkErrorV3::M6Approval);
    }
    let commitment: Hash32 = marker[9..].try_into().unwrap();
    if commitment == [0;32] { return Err(AlphaConversionLinkErrorV3::M6Approval); }
    Ok(AuthenticatedCustodyM6V2 { approval: CustodyBundleApprovalV3 {
        slot: approval.slot, m6id: approval.m6id, transaction_id: approval.transaction_id,
        block_hash: approval.block_hash, block_height: approval.block_height, early_acks: false,
    }, commitment, binding_commitment: frozen_binding,
        parent_state_commitment: statement.terminal_selected_state_commitment })
}

/// Authenticate the P->Q edge and extract the native endpoint for P, not the
/// mining block Q. The enclosing child still must verify its own critical hash
/// and persist this endpoint with its next checkpoint. This is not evidence
/// that a supplied endpoint belongs to a previous child checkpoint.
pub fn authenticate_alpha_bmm_endpoint_v4<V: FullAlphaReceiptVerifierV3>(
    input: &AlphaConversionParentLinkInputV3,
    expected_binding: Hash32,
    verifier: &V,
) -> Result<(AlphaConversionParentLinkPublicValuesV3, [u8; 80]), AlphaConversionLinkErrorV3> {
    if expected_binding == [0; 32] || input.binding.commitment()? != expected_binding {
        return Err(AlphaConversionLinkErrorV3::Binding);
    }
    let statement = execute_alpha_conversion_parent_link_v3(input, verifier)?;
    let predecessor = &input.terminal_parent_predecessor;
    let mut endpoint = [0; 80];
    let mut display_hash = predecessor.tip.block_hash.to_byte_array();
    display_hash.reverse();
    endpoint[..32].copy_from_slice(&display_hash);
    endpoint[32..40].copy_from_slice(&u64::from(predecessor.tip.height).to_be_bytes());
    let mtp = ecx_full_consensus_validator_v2::median_time_past_v2(
        &predecessor.pow_context.previous_11_times)
        .map_err(|_| AlphaConversionLinkErrorV3::ParentBranch)?;
    endpoint[40..48].copy_from_slice(&u64::from(mtp).to_be_bytes());
    endpoint[48..].copy_from_slice(&predecessor.tip.chainwork_be);
    Ok((statement, endpoint))
}

pub fn execute_alpha_conversion_parent_link_v3<V: FullAlphaReceiptVerifierV3>(
    input: &AlphaConversionParentLinkInputV3,
    verifier: &V,
) -> Result<AlphaConversionParentLinkPublicValuesV3, AlphaConversionLinkErrorV3> {
    validate_input(input)?;
    let predecessor = &input.terminal_parent_predecessor;
    let (parent, _, effects) = authenticate_terminal_parent(
        &input.binding, &input.parent, predecessor, &input.terminal_parent_block, verifier,
    )?;
    let predecessor_commitment = predecessor.commitment()
        .map_err(|_| AlphaConversionLinkErrorV3::ParentBranch)?;
    // Native child context commits P, the predecessor of the mining parent Q.
    // This authenticates P; it does not parse or authenticate a child coinbase.
    if input.expected_parent_hash_internal != predecessor.tip.block_hash.to_byte_array() {
        return Err(AlphaConversionLinkErrorV3::M7Link);
    }
    let mut slot_commitments = effects
        .bmm_commitments
        .iter()
        .filter(|m| m.slot == ALPHA_CONVERSION_SLOT_V3);
    let m7 = slot_commitments
        .next()
        .ok_or(AlphaConversionLinkErrorV3::M7Link)?;
    // Native mainchainrpc.cpp::ParseDrivechainParentMessage and
    // ExtractDrivechainM7BmmCommitment reverse_copy the ConsensusHex display
    // payload into uint256 internal bytes. This is also the reversal in
    // bmm_v2::extract_unique_m8_commitment,
    // not a selectable endianness or fallback accepting both representations.
    let mut committed_critical = m7.child_hash.to_byte_array();
    committed_critical.reverse();
    if slot_commitments.next().is_some()
        || committed_critical != input.expected_critical_hash_internal
    {
        return Err(AlphaConversionLinkErrorV3::M7Link);
    }
    Ok(AlphaConversionParentLinkPublicValuesV3 {
        binding_commitment: input.binding.commitment()?,
        parent_statement_commitment: tagged_hash(
            "ECX/alpha-conversion-parent-statement/v3",
            &encode_full_alpha_statement_v3(&parent)
                .map_err(|_| AlphaConversionLinkErrorV3::Receipt)?,
        ),
        parent_predecessor_state_commitment: predecessor_commitment,
        parent_terminal_state_commitment: parent.terminal_selected_state_commitment,
        parent_block_hash_internal: parent.terminal_tip_hash_internal,
        parent_height: parent.terminal_selected_height,
        parent_predecessor_hash_internal: predecessor.tip.block_hash.to_byte_array(),
        m7_critical_hash_internal: committed_critical,
        m7_coinbase_vout: m7.coinbase_vout,
    })
}

#[cfg(test)]
pub(crate) mod tests;
