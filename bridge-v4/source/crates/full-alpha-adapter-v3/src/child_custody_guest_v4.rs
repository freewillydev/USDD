//! Owned custody execution relation. Transport is not receipt verification;
//! consumers must independently pin this relation's source binding and guest.
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::{Hash32, FullAlphaReceiptVerifierV3};
use crate::child_execution_guest_v3::{AlphaChildExecutionErrorV3 as E,
    AlphaChildExecutionPublicValuesV3, AlphaChildDepositInputV3, alpha_parent_genesis};
use crate::child_execution_guest_v4::{AlphaChildExecutionErrorV4 as Error,
    OwnedCapitalWitnessV4, CustodianInputV4, MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4};
use crate::child_execution_statement_v4::AlphaChildExecutionBindingV5;
use crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4;
use crate::native_child_block_v3::{ChildTransactionCustodyWitnessV3,
    ParentBoundCheckedCustodyStateV3, NativeBlockDepositsV3, execute_parent_bound_custody_with_ecx_v4};
use crate::ecx_environment_v4::EcxExecutionEnvironmentV1;

// Rust API names retained; wire/relation revision 5 adds reviewed initialization.
// Old 0xac receipts and owned inputs are not accepted as this relation.
pub const CUSTODY_EXECUTION_VERSION_V4: u8 = 0xad;

/// Reuse named trust-root components, not the legacy relation commitment.
/// predecessor_checkpoint opens a full custody checkpoint; execution_policy
/// opens ChildCustodyExecutionPolicyV3, never the old inventory/reserve policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionBindingV4 {
    pub roots: AlphaChildExecutionBindingV5,
    pub genesis_initialization: Hash32,
}
impl CustodyExecutionBindingV4 {
    pub fn commitment(&self) -> Result<Hash32, E> {
        if self.genesis_initialization == [0;32] { return Err(E::Binding); }
        let mut bytes = vec![CUSTODY_EXECUTION_VERSION_V4];
        bytes.extend_from_slice(&self.roots.commitment()?);
        bytes.extend_from_slice(&self.genesis_initialization);
        Ok(crate::tagged_hash("ECX/alpha-child-custody-execution-binding/v5", &bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyExecutionPublicValuesV4(pub AlphaChildExecutionPublicValuesV3);
impl CustodyExecutionPublicValuesV4 {
    pub fn canonical_bytes(self) -> [u8; crate::child_execution_guest_v3::ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3] {
        let mut bytes = self.0.canonical_bytes(); bytes[0] = CUSTODY_EXECUTION_VERSION_V4; bytes
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, E> {
        if bytes.len() != crate::child_execution_guest_v3::ALPHA_CHILD_EXECUTION_PUBLIC_BYTES_V3
            || bytes[0] != CUSTODY_EXECUTION_VERSION_V4 { return Err(E::Input); }
        let mut layout = bytes.to_vec();
        layout[0] = crate::child_execution_guest_v3::ALPHA_CHILD_EXECUTION_VERSION_V3;
        AlphaChildExecutionPublicValuesV3::from_canonical_bytes(&layout).map(Self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExecutionInputV4 {
    pub version: u8,
    pub binding: CustodyExecutionBindingV4,
    pub parent: crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
    pub checkpoint: ChildCustodyExecutionCheckpointV4,
    pub history: Vec<Vec<u8>>,
    pub policy: crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV3,
    pub header_policy: crate::child_header_policy_v3::ChildHeaderPolicyV3,
    pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    pub observation_time: u64,
    pub raw_block: Vec<u8>,
    pub witnesses: Vec<ChildTransactionCustodyWitnessV3>,
    pub deposits: Vec<Option<AlphaChildDepositInputV3>>,
    pub simplicity_receipts: Vec<ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptBindingV2>,
    pub environment: Vec<u8>,
    pub configuration: ecx_protocol_core::FrozenConfigurationV2,
    pub genesis_bindings: crate::capital_genesis_utxos_v4::GenesisStateBindings,
    pub genesis_initialization: crate::genesis_initialization_v2::GenesisInitializationV2,
    pub capital: OwnedCapitalWitnessV4,
    pub registry: Vec<CustodianInputV4>,
}
fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64)
}
impl CustodyExecutionInputV4 {
    fn check_shape(&self) -> Result<(), E> {
        let limit = crate::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES;
        if self.version != CUSTODY_EXECUTION_VERSION_V4 || self.registry.len() > 255
            || self.environment.len() != crate::ecx_environment_v4::ENCODED_LENGTH
            || self.raw_block.is_empty() || self.raw_block.len() > limit
            || self.history.is_empty() || self.history.len() > 65_536
            || self.history.iter().any(|h| h.is_empty() || h.len() > limit)
            || self.witnesses.is_empty() || self.witnesses.len() > 100_000
            || self.deposits.len() != self.witnesses.len() || self.simplicity_receipts.len() > 65_536
            || self.deposits.iter().flatten().any(|d| d.spent_claim_absence_path.len() != 256)
            || options().serialized_size(self).map_err(|_| E::Input)? > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64 {
            return Err(E::Input);
        }
        self.binding.commitment()?;
        if self.genesis_initialization.commitment().map_err(|_| E::Binding)?
            != self.binding.genesis_initialization { return Err(E::Binding); }
        self.checkpoint.commitment().map_err(|_| E::Binding)?;
        EcxExecutionEnvironmentV1::decode(&self.environment).map_err(|_| E::Input)?;
        if matches!(self.capital, OwnedCapitalWitnessV4::SuccessorCarry)
            && self.binding.roots.successor.is_none() { return Err(E::Binding); }
        if let OwnedCapitalWitnessV4::Activation { deployment, genesis, inventory, state } = &self.capital {
            if deployment.transaction.is_empty() || deployment.transaction.len() > limit
                || genesis.is_empty() || genesis.len() > limit
                || inventory.path.siblings.len() != 256 || state.path.siblings.len() != 256 { return Err(E::Input); }
            let tx: elements::Transaction = elements::encode::deserialize(genesis).map_err(|_| E::Input)?;
            if elements::encode::serialize(&tx) != *genesis { return Err(E::Input); }
        }
        Ok(())
    }
}
pub fn encode_custody_execution_input_v4(input: &CustodyExecutionInputV4) -> Result<Vec<u8>, E> {
    input.check_shape()?; options().serialize(input).map_err(|_| E::Input)
}
pub fn decode_custody_execution_input_v4(bytes: &[u8]) -> Result<CustodyExecutionInputV4, E> {
    if bytes.is_empty() || bytes.len() > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 { return Err(E::Input); }
    let input = options().deserialize(bytes).map_err(|_| E::Input)?;
    if encode_custody_execution_input_v4(&input)? != bytes { return Err(E::Input); }
    Ok(input)
}

pub struct CustodyExecutionOutputV4 {
    checked: ParentBoundCheckedCustodyStateV3,
    checkpoint: ChildCustodyExecutionCheckpointV4,
    public_values: CustodyExecutionPublicValuesV4,
}
impl CustodyExecutionOutputV4 {
    pub fn checked(&self) -> &ParentBoundCheckedCustodyStateV3 { &self.checked }
    pub fn checkpoint(&self) -> &ChildCustodyExecutionCheckpointV4 { &self.checkpoint }
    pub fn public_values(&self) -> CustodyExecutionPublicValuesV4 { self.public_values }
}

pub fn execute_owned_custody_v4<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &CustodyExecutionInputV4, parent_verifier: &P, simplicity: &S,
) -> Result<CustodyExecutionOutputV4, Error> {
    execute_owned_custody_projection(input, parent_verifier, simplicity, None)
}

/// Internal projection only. A new full-anchor transport must bind the V4
/// policy and publish its own versioned journal, never this legacy journal.
pub(crate) fn execute_owned_custody_projection<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &CustodyExecutionInputV4, parent_verifier: &P, simplicity: &S,
    versioned_policy: Option<&crate::child_execution_policy_v3::ChildCustodyExecutionPolicyV4>,
) -> Result<CustodyExecutionOutputV4, Error> {
    input.check_shape()?;
    if let Some(policy) = versioned_policy {
        if policy.base != input.policy { return Err(E::Binding.into()); }
        crate::effective_child_configuration_v1::EffectiveChildConfigurationV2::from_policies(
            policy, &input.header_policy, &input.deposit_policy,
        ).map_err(|_| E::Binding)?
            .require_bound(input.policy.consensus_configuration_commitment)
            .map_err(|_| E::Binding)?;
        policy.require_frozen(input.binding.roots.execution.execution_policy,
            &input.checkpoint.execution).map_err(|_| E::Binding)?;
    } else {
        crate::effective_child_configuration_v1::EffectiveChildConfigurationV1::from_policies(
            &input.policy, &input.header_policy, &input.deposit_policy,
        ).map_err(|_| E::Binding)?
            .require_bound(input.policy.consensus_configuration_commitment)
            .map_err(|_| E::Binding)?;
    }
    let binding = &input.binding.roots;
    let policy = &input.deposit_policy;
    let deposit = &policy.historical;
    if input.checkpoint.commitment().map_err(|_| E::Binding)? != binding.execution.predecessor_checkpoint
        || policy.child_genesis_internal != input.checkpoint.execution.genesis_internal
        || policy.commitment().ok_or(E::Binding)? != binding.execution.deposit_configuration
        || deposit.pegged_asset_internal != input.policy.classification.native_pegged_asset_id {
        return Err(E::Binding.into());
    }
    let depth = policy.required_depth(input.checkpoint.execution.height).ok_or(E::Binding)?;
    let history = input.history.iter().map(|h| crate::native_header_v3::NativeHeader::decode(h, true))
        .collect::<Result<Vec<_>,_>>().map_err(|_| E::Header)?;
    let prior = history.last().ok_or(E::Header)?;
    let environment = EcxExecutionEnvironmentV1::decode(&input.environment).map_err(|_| E::Input)?;
    let params = deposit.address_params()?;
    let asset = elements::AssetId::from_slice(&deposit.pegged_asset_internal).map_err(|_| E::Binding)?;
    let anchor = input.parent.terminal_parent_predecessor.commitment().map_err(|_| E::Binding)?;
    let authenticated = input.deposits.iter().map(|entry| match entry {
        None => Ok(None), Some(d) => d.evidence.authenticate(&input.parent.binding,
            binding.execution.parent_binding, input.parent.expected_parent_hash_internal,
            anchor, depth, parent_verifier).map(Some).map_err(|_| E::Deposit),
    }).collect::<Result<Vec<_>,_>>()?;
    let entries = authenticated.iter().zip(&input.deposits).map(|(a, d)| {
        a.as_ref().zip(d.as_ref()).map(|(a, d)| (
            crate::native_deposit_outputs_v3::NativeDepositKernelV3 { deposit: a, pegged_asset: asset,
                parent_genesis_internal: alpha_parent_genesis(), address_params: &params },
            d.spent_claim_absence_path.clone()))
    }).collect::<Vec<_>>();
    let deposits = NativeBlockDepositsV3 { entries: &entries,
        frozen_parent_binding: binding.execution.parent_binding,
        frozen_deposit_configuration: binding.execution.deposit_configuration,
        minimum_depth: deposit.minimum_depth, scheduled_policy: Some(policy) };
    macro_rules! execute_projection {
        ($executor:path, $policy:expr) => { $executor(
        &input.parent, binding.execution.parent_binding, parent_verifier, &input.raw_block,
        &input.checkpoint, binding.execution.predecessor_checkpoint, &history, prior,
        $policy, binding.execution.execution_policy, input.observation_time,
        &input.header_policy, &input.witnesses, &environment, binding.environment,
        binding.evaluator_source_closure, binding.execution.simplicity_evaluator_program_id,
        &input.simplicity_receipts, simplicity, &deposits, binding.execution.deposit_configuration)
        .map_err(E::Execution)? };
    }
    let (checked, context) = match versioned_policy {
        None => execute_projection!(execute_parent_bound_custody_with_ecx_v4, &input.policy),
        Some(policy) => execute_projection!(
            crate::native_child_block_v3::execute_parent_bound_custody_with_ecx_v5, policy),
    };
    let registry = input.registry.iter().map(|c| ecx_witness_availability::CustodianPublic {
        index: c.index, encryption_public_key: c.encryption_public_key,
        attestation_public_key: c.attestation_public_key,
    }).collect::<Vec<_>>();
    let capital = match &input.capital {
        OwnedCapitalWitnessV4::Activation { deployment, genesis, inventory, state } => {
            let genesis = elements::encode::deserialize(genesis).map_err(|_| E::Input)?;
            let initialization = input.genesis_initialization.authenticate_custody(
                input.binding.genesis_initialization, &input.checkpoint,
                binding.execution.predecessor_checkpoint, &history, state.leaf.creation_height,
                context.environment().current_bmm_parent.as_ref().ok_or(E::Binding)?.median_time_past,
            ).map_err(|_| Error::Capital(crate::capital_genesis_utxos_v4::GenesisCoinError::Context))?;
            context.activation_projection(&checked, &input.configuration, &input.genesis_bindings,
                binding.genesis_bindings, deployment, &genesis, inventory.as_witness(), state.as_witness(), &registry,
                initialization)
        },
        OwnedCapitalWitnessV4::FiniteCarry => context.carry_projection(&checked, &input.configuration,
            &input.genesis_bindings, binding.genesis_bindings, None, &registry),
        OwnedCapitalWitnessV4::SuccessorCarry => context.carry_projection(&checked, &input.configuration,
            &input.genesis_bindings, binding.genesis_bindings, Some(binding.successor.as_ref().ok_or(E::Binding)?), &registry),
    }.map_err(Error::Capital)?;
    let execution = checked.child().next_checkpoint().ok_or(E::Binding)?.clone();
    let next = ChildCustodyExecutionCheckpointV4::join_executed_parent(execution, Some(capital),
        &checked, &input.parent, binding.execution.parent_binding, parent_verifier).map_err(|_| E::Binding)?;
    let public_values = CustodyExecutionPublicValuesV4(AlphaChildExecutionPublicValuesV3 {
        source_binding: input.binding.commitment()?, predecessor_checkpoint: binding.execution.predecessor_checkpoint,
        next_checkpoint: next.commitment().map_err(|_| E::Binding)?, child_hash_internal: next.execution.tip_internal,
        child_height: next.execution.height, observation_time: input.observation_time, parent: *checked.parent(),
    });
    CustodyExecutionPublicValuesV4::from_canonical_bytes(&public_values.canonical_bytes())?;
    Ok(CustodyExecutionOutputV4 { checked, checkpoint: next, public_values })
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::native_header_v3::NativeHeader;
    use elements::{hashes::Hash, Block, BlockExtData, BlockHash, Script};

    /// Preserved Alpha genesis followed by LOCAL test headers, not live replay.
    /// No authenticated checkpoint or parent receipt is manufactured here.
    pub(crate) fn alpha_test_history(last_height: u32) -> Vec<NativeHeader> {
        assert!(last_height <= 64);
        let text = include_str!("test-alpha-genesis.hex").trim();
        let bytes: Vec<u8> = (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i+2],16).unwrap()).collect();
        let block: Block = elements::encode::deserialize(&bytes).unwrap();
        assert_eq!(elements::encode::serialize(&block),bytes);
        let genesis = NativeHeader::decode(&elements::encode::serialize(&block.header),true).unwrap();
        assert_eq!(genesis.hash_internal().unwrap(),
            crate::native_deposit_policy_v4::tests::policy().child_genesis_internal);
        assert_eq!(genesis.base.height,0);
        assert!(matches!(&genesis.base.ext, BlockExtData::Proof {challenge,solution}
            if challenge.as_bytes()==[0x51] && solution.is_empty()));
        let mut history = vec![genesis];
        for height in 1..=last_height {
            let prior = history.last().unwrap();
            let mut next = prior.clone();
            next.base.height = height;
            next.base.time = prior.base.time.checked_add(1).unwrap();
            next.base.prev_blockhash = BlockHash::from_byte_array(prior.hash_internal().unwrap());
            next.base.merkle_root = elements::TxMerkleNode::all_zeros();
            next.base.ext = BlockExtData::Proof {challenge:Script::from(vec![0x51]),solution:Script::new()};
            history.push(next);
        }
        history
    }

    #[test]
    fn alpha_fixture_history_preserves_genesis_and_native_authorization() {
        use ecx_full_consensus_validator_v2::elements_v2::ElementsBlockAuthorizationVerifierV2;
        let history = alpha_test_history(6);
        let commitment = crate::child_execution_state_v3::child_history_commitment(&history).unwrap();
        for header in &history {
            let wire = header.encode(false,true).unwrap();
            assert_eq!(NativeHeader::decode(&wire,true).unwrap().encode(false,true).unwrap(),wire);
            let BlockExtData::Proof {challenge,solution} = &header.base.ext else {panic!()};
            let verifier = crate::native_header_signature_v3::BoundNativeHeaderVerifier(header);
            verifier.verify_legacy_proof(&header.base,challenge,solution).unwrap();
            assert!(verifier.verify_legacy_proof(&header.base,&Script::from(vec![0x00]),solution).is_err());
        }
        let mut broken = history.clone();
        broken[3].base.prev_blockhash = BlockHash::all_zeros();
        assert!(crate::child_execution_state_v3::child_history_commitment(&broken).is_err());
        assert_ne!(commitment,[0;32]);
        assert_eq!(crate::native_deposit_policy_v4::tests::policy().required_depth(6),Some(100));
    }
}
