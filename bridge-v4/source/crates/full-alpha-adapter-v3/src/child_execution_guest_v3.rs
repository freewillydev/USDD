//! Owned input and execution relation for the native Alpha child guest.
//!
//! The public journal commits every external execution trust root and the
//! observation time. Consumers must match those against their reviewed source
//! profile and authenticated clock. A valid transition alone does not establish
//! checkpoint provenance, finality, conversion pricing, or redemption capacity.

use bincode::Options;
use bitcoin::hashes::Hash as _;
use ecx_full_consensus_validator_v2::{Hash32, elements_v2::{
    ElementsSimplicityReceiptBindingV2, ElementsSimplicityReceiptVerifierV2,
    ElementsStateErrorV2,
}};
use serde::{Deserialize, Serialize};
use crate::{FullAlphaReceiptVerifierV3, child_execution_policy_v3::ChildExecutionPolicyV3,
    child_execution_state_v3::ChildExecutionCheckpointV3,
    child_header_policy_v3::ChildHeaderPolicyV3,
    conversion_parent_link_v3::{AlphaConversionParentLinkInputV3,
        AlphaConversionParentLinkPublicValuesV3, AlphaDepositWitnessV3},
    native_child_block_v3::{ChildTransactionStateWitness, NativeBlockDepositsV3,
        ParentBoundCheckedChildState, execute_parent_bound_child_with_simplicity_v3},
    native_deposit_outputs_v3::{NativeDepositKernelV3, deposit_configuration_commitment_v3},
    native_header_v3::NativeHeader};

pub const ALPHA_CHILD_EXECUTION_VERSION_V3: u8 = 0xa6;
pub const MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V3: usize = 128 * 1024 * 1024;
pub const ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3: usize = 407;

/// These values are public trust inputs, not witness-selected verifier defaults.
/// The guest commits their aggregate hash, which the outer consumer must pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaChildExecutionBindingV3 {
    pub parent_binding: Hash32,
    pub predecessor_checkpoint: Hash32,
    pub execution_policy: Hash32,
    pub simplicity_evaluator_program_id: Hash32,
    pub deposit_configuration: Hash32,
}

#[derive(Debug)]
pub enum AlphaChildExecutionErrorV3 {
    Input,
    Binding,
    Header,
    Deposit,
    Execution(crate::native_child_block_v3::ParentBoundChildError),
}

impl AlphaChildExecutionBindingV3 {
    pub fn commitment(&self) -> Result<Hash32, AlphaChildExecutionErrorV3> {
        if [self.parent_binding, self.predecessor_checkpoint, self.execution_policy,
            self.deposit_configuration].contains(&[0;32])
            || !crate::alpha_sp1_program_id_is_canonical_v3(self.simplicity_evaluator_program_id) {
            return Err(AlphaChildExecutionErrorV3::Binding);
        }
        let mut bytes = vec![ALPHA_CHILD_EXECUTION_VERSION_V3];
        for hash in [self.parent_binding, self.predecessor_checkpoint, self.execution_policy,
            self.simplicity_evaluator_program_id, self.deposit_configuration] {
            bytes.extend_from_slice(&hash);
        }
        Ok(crate::tagged_hash("ECX/alpha-child-execution-binding/v3", &bytes))
    }
}

/// Address parameters travel as data and are authenticated by the deposit
/// configuration commitment. There is no network enum or fallback profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaDepositConfigurationV3 {
    pub pegged_asset_internal: Hash32,
    pub minimum_depth: u32,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub blinded_prefix: u8,
    pub bech_hrp: String,
    pub blech_hrp: String,
}

impl AlphaDepositConfigurationV3 {
    pub fn address_params(&self) -> Result<elements::AddressParams, AlphaChildExecutionErrorV3> {
        if self.minimum_depth == 0 || self.bech_hrp.is_empty() || self.blech_hrp.is_empty()
            || self.bech_hrp != self.bech_hrp.to_ascii_lowercase()
            || self.blech_hrp != self.blech_hrp.to_ascii_lowercase()
            || self.bech_hrp == self.blech_hrp {
            return Err(AlphaChildExecutionErrorV3::Binding);
        }
        Ok(elements::AddressParams {
            p2pkh_prefix: self.p2pkh_prefix, p2sh_prefix: self.p2sh_prefix,
            blinded_prefix: self.blinded_prefix,
            bech_hrp: bitcoin::bech32::Hrp::parse(&self.bech_hrp)
                .map_err(|_|AlphaChildExecutionErrorV3::Binding)?,
            blech_hrp: bitcoin::bech32::Hrp::parse(&self.blech_hrp)
                .map_err(|_|AlphaChildExecutionErrorV3::Binding)?,
        })
    }

    pub fn commitment(&self) -> Result<Hash32, AlphaChildExecutionErrorV3> {
        let asset = elements::AssetId::from_slice(&self.pegged_asset_internal)
            .map_err(|_|AlphaChildExecutionErrorV3::Binding)?;
        deposit_configuration_commitment_v3(asset, alpha_parent_genesis(),
            &self.address_params()?, self.minimum_depth)
            .ok_or(AlphaChildExecutionErrorV3::Binding)
    }
}

pub(crate) fn alpha_parent_genesis() -> Hash32 {
    // Alpha shares Bitcoin's genesis; its fork/PoW/BIP300 rules are enforced by
    // the full Alpha parent relation, not selected by this genesis constant.
    bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin)
        .block_hash().to_byte_array()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaChildDepositInputV3 {
    pub evidence: AlphaDepositWitnessV3,
    pub spent_claim_absence_path: Vec<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaChildExecutionInputV3 {
    pub version: u8,
    pub binding: AlphaChildExecutionBindingV3,
    pub parent: AlphaConversionParentLinkInputV3,
    pub checkpoint: ChildExecutionCheckpointV3,
    /// Exact native header encodings, including Alpha extensions/signatures.
    pub history: Vec<Vec<u8>>,
    pub policy: ChildExecutionPolicyV3,
    pub header_policy: ChildHeaderPolicyV3,
    pub deposit_configuration: AlphaDepositConfigurationV3,
    pub observation_time: u64,
    pub raw_block: Vec<u8>,
    pub witnesses: Vec<ChildTransactionStateWitness>,
    /// One entry per transaction, including None for non-deposits.
    pub deposits: Vec<Option<AlphaChildDepositInputV3>>,
    pub simplicity_receipts: Vec<ElementsSimplicityReceiptBindingV2>,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V3 as u64)
}

impl AlphaChildExecutionInputV3 {
    pub(crate) fn check_shape(&self) -> Result<(), AlphaChildExecutionErrorV3> {
        if self.version != ALPHA_CHILD_EXECUTION_VERSION_V3
            || self.raw_block.is_empty()
            || self.raw_block.len() > crate::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES
            || self.history.is_empty() || self.history.len() > 65_536
            || self.history.iter().any(|h| h.is_empty()
                || h.len() > crate::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES)
            || self.witnesses.is_empty() || self.witnesses.len() > 100_000
            || self.deposits.len() != self.witnesses.len()
            || self.simplicity_receipts.len() > 65_536
            || self.deposits.iter().flatten().any(|d| d.spent_claim_absence_path.len() != 256)
            || options().serialized_size(self).map_err(|_|AlphaChildExecutionErrorV3::Input)?
                > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V3 as u64 {
            return Err(AlphaChildExecutionErrorV3::Input);
        }
        Ok(())
    }
}

pub fn decode_alpha_child_execution_input_v3(bytes: &[u8])
    -> Result<AlphaChildExecutionInputV3, AlphaChildExecutionErrorV3> {
    if bytes.is_empty() || bytes.len() > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V3 {
        return Err(AlphaChildExecutionErrorV3::Input);
    }
    let input: AlphaChildExecutionInputV3 = options().deserialize(bytes)
        .map_err(|_|AlphaChildExecutionErrorV3::Input)?;
    input.check_shape()?;
    if options().serialize(&input).map_err(|_|AlphaChildExecutionErrorV3::Input)? != bytes {
        return Err(AlphaChildExecutionErrorV3::Input);
    }
    Ok(input)
}

pub fn encode_alpha_child_execution_input_v3(input: &AlphaChildExecutionInputV3)
    -> Result<Vec<u8>, AlphaChildExecutionErrorV3> {
    input.check_shape()?;
    options().serialize(input).map_err(|_|AlphaChildExecutionErrorV3::Input)
}

/// Only this executor can construct a checked result. It reconstructs every
/// deposit authentication inside the relation and consumes all script receipts.
pub fn execute_alpha_child_execution_v3<P: FullAlphaReceiptVerifierV3,
    S: ElementsSimplicityReceiptVerifierV2>(input: &AlphaChildExecutionInputV3,
    parent_verifier: &P, simplicity_verifier: &S)
    -> Result<AlphaChildExecutionOutputV3, AlphaChildExecutionErrorV3> {
    input.check_shape()?;
    let source_binding = input.binding.commitment()?;
    if input.deposit_configuration.commitment()? != input.binding.deposit_configuration
        || input.deposit_configuration.pegged_asset_internal != input.policy.classification.base_asset_id {
        return Err(AlphaChildExecutionErrorV3::Binding);
    }
    let history = input.history.iter().map(|h|NativeHeader::decode(h, true))
        .collect::<Result<Vec<_>,_>>().map_err(|_|AlphaChildExecutionErrorV3::Header)?;
    let params = input.deposit_configuration.address_params()?;
    let asset = elements::AssetId::from_slice(&input.deposit_configuration.pegged_asset_internal)
        .map_err(|_|AlphaChildExecutionErrorV3::Binding)?;
    let anchor_state = input.parent.terminal_parent_predecessor.commitment()
        .map_err(|_|AlphaChildExecutionErrorV3::Binding)?;
    let authenticated = input.deposits.iter().map(|entry| match entry {
        None => Ok(None),
        Some(deposit) => deposit.evidence.authenticate(&input.parent.binding,
            input.binding.parent_binding, input.parent.expected_parent_hash_internal,
            anchor_state, input.deposit_configuration.minimum_depth, parent_verifier)
            .map(Some).map_err(|_|AlphaChildExecutionErrorV3::Deposit),
    }).collect::<Result<Vec<_>,_>>()?;
    let entries = authenticated.iter().zip(&input.deposits).map(|(authenticated,input)| {
        authenticated.as_ref().zip(input.as_ref()).map(|(deposit,input)| (
            NativeDepositKernelV3 { deposit, pegged_asset: asset,
                parent_genesis_internal: alpha_parent_genesis(), address_params: &params },
            input.spent_claim_absence_path.clone()))
    }).collect::<Vec<_>>();
    let deposits = NativeBlockDepositsV3 { entries: &entries,
        frozen_parent_binding: input.binding.parent_binding,
        frozen_deposit_configuration: input.binding.deposit_configuration,
        minimum_depth: input.deposit_configuration.minimum_depth, scheduled_policy: None };
    let checked = execute_parent_bound_child_with_simplicity_v3(&input.parent,
        input.binding.parent_binding, parent_verifier, &input.raw_block,
        &input.checkpoint, input.binding.predecessor_checkpoint, &history,
        &input.policy, input.binding.execution_policy, input.observation_time,
        &input.header_policy, &input.witnesses, input.binding.simplicity_evaluator_program_id,
        &input.simplicity_receipts, simplicity_verifier, Some(&deposits),
        Some(input.binding.deposit_configuration)).map_err(AlphaChildExecutionErrorV3::Execution)?;
    let next = checked.child().next_checkpoint().ok_or(AlphaChildExecutionErrorV3::Binding)?;
    let public_values = AlphaChildExecutionPublicValuesV3 {
        source_binding, predecessor_checkpoint: input.binding.predecessor_checkpoint,
        next_checkpoint: next.commitment().map_err(|_|AlphaChildExecutionErrorV3::Binding)?,
        child_hash_internal: next.tip_internal, child_height: next.height,
        observation_time: input.observation_time, parent: *checked.parent(),
    };
    Ok(AlphaChildExecutionOutputV3 { checked, public_values })
}

pub struct AlphaChildExecutionOutputV3 {
    checked: ParentBoundCheckedChildState,
    public_values: AlphaChildExecutionPublicValuesV3,
}
impl AlphaChildExecutionOutputV3 {
    pub fn checked(&self) -> &ParentBoundCheckedChildState { &self.checked }
    pub fn public_values(&self) -> AlphaChildExecutionPublicValuesV3 { self.public_values }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlphaChildExecutionPublicValuesV3 {
    pub source_binding: Hash32,
    pub predecessor_checkpoint: Hash32,
    pub next_checkpoint: Hash32,
    pub child_hash_internal: Hash32,
    pub child_height: u32,
    pub observation_time: u64,
    pub parent: AlphaConversionParentLinkPublicValuesV3,
}
impl AlphaChildExecutionPublicValuesV3 {
    /// Strict decoder for the native execution statement, not the incompatible
    /// 0xa5 accounting projection. Integers are big-endian, with no suffix.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AlphaChildExecutionErrorV3> {
        if bytes.len() != ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3
            || bytes[0] != ALPHA_CHILD_EXECUTION_VERSION_V3 {
            return Err(AlphaChildExecutionErrorV3::Input);
        }
        let hash = |start: usize| -> Hash32 { bytes[start..start+32].try_into().unwrap() };
        let result = Self {
            source_binding: hash(1), predecessor_checkpoint: hash(33), next_checkpoint: hash(65),
            child_hash_internal: hash(97),
            child_height: u32::from_be_bytes(bytes[129..133].try_into().unwrap()),
            observation_time: u64::from_be_bytes(bytes[133..141].try_into().unwrap()),
            parent: AlphaConversionParentLinkPublicValuesV3::from_canonical_bytes(&bytes[141..])
                .map_err(|_| AlphaChildExecutionErrorV3::Binding)?,
        };
        if [result.source_binding,result.predecessor_checkpoint,result.next_checkpoint,
            result.child_hash_internal].contains(&[0;32]) || result.child_height == 0
            || result.child_height == u32::MAX || result.observation_time == 0
            || result.predecessor_checkpoint == result.next_checkpoint {
            return Err(AlphaChildExecutionErrorV3::Binding);
        }
        Ok(result)
    }

    pub fn canonical_bytes(self) -> [u8; ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3] {
        let mut out = [0; ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3];
        out[0] = ALPHA_CHILD_EXECUTION_VERSION_V3;
        let mut cursor = 1;
        for hash in [self.source_binding,self.predecessor_checkpoint,self.next_checkpoint,
            self.child_hash_internal] {
            out[cursor..cursor+32].copy_from_slice(&hash); cursor += 32;
        }
        out[cursor..cursor+4].copy_from_slice(&self.child_height.to_be_bytes()); cursor += 4;
        out[cursor..cursor+8].copy_from_slice(&self.observation_time.to_be_bytes()); cursor += 8;
        out[cursor..].copy_from_slice(&self.parent.canonical_bytes());
        out
    }

    pub fn require_source_and_clock(self, expected_binding: Hash32, observation_time: u64)
        -> Result<(), AlphaChildExecutionErrorV3> {
        if expected_binding == [0;32] || expected_binding != self.source_binding
            || observation_time != self.observation_time {
            return Err(AlphaChildExecutionErrorV3::Binding);
        }
        Ok(())
    }
}

// Re-export the exact verifier interface so the guest need not choose another
// validator version as a direct dependency.
pub use ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2
    as AlphaChildSimplicityReceiptVerifierV3;
pub type AlphaChildScriptErrorV3 = ElementsStateErrorV2;
