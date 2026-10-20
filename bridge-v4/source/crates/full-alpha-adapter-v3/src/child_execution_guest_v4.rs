//! ECX-aware child execution composed with capital-state validation.
//! Owned wire and guest dispatch cover activation and finite/successor unchanged-root
//! carry only; this is not a qualified production release.
//! Frozen source bindings must be pinned by the receipt consumer.
use crate::FullAlphaReceiptVerifierV3;
use crate::child_execution_guest_v3::{AlphaChildExecutionInputV3,
    AlphaChildExecutionErrorV3, AlphaChildExecutionPublicValuesV3, alpha_parent_genesis};
use crate::child_execution_statement_v4::{AlphaChildExecutionBindingV4, AlphaChildExecutionPublicValuesV4};
use crate::child_execution_state_v4::ChildExecutionCheckpointV4;
use crate::capital_genesis_utxos_v4::{ActivationCoinWitness, GenesisStateBindings, GenesisCoinError};
use crate::ecx_environment_v4::{EcxExecutionEnvironmentV1, CheckedAlphaExecutionContextV4};
use crate::native_child_block_v3::{ParentBoundCheckedChildState, NativeBlockDepositsV3,
    execute_parent_bound_child_with_ecx_v4};
use crate::native_deposit_outputs_v3::NativeDepositKernelV3;
use bincode::Options;
use serde::{Serialize, Deserialize};

pub const MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodianInputV4 {
    pub index: u8,
    pub encryption_public_key: [u8;32],
    pub attestation_public_key: [u8;32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OwnedCapitalWitnessV4 {
    Activation {
        deployment: ecx_elements_settlement::FrozenBondDeploymentV2,
        /// Full consensus transaction encoding, including output witnesses.
        genesis: Vec<u8>,
        inventory: crate::capital_genesis_utxos_v4::OwnedActivationCoinWitnessV4,
        state: crate::capital_genesis_utxos_v4::OwnedActivationCoinWitnessV4,
    },
    FiniteCarry,
    SuccessorCarry,
}

/// Versioned transport only. All source roots remain subject to the composed
/// executor and to the receipt consumer's independently pinned source binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaChildExecutionInputV4 {
    pub version: u8,
    pub execution: AlphaChildExecutionInputV3,
    pub binding: AlphaChildExecutionBindingV4,
    pub checkpoint: ChildExecutionCheckpointV4,
    pub environment: Vec<u8>,
    pub configuration: ecx_protocol_core::FrozenConfigurationV2,
    pub genesis_bindings: GenesisStateBindings,
    pub capital: OwnedCapitalWitnessV4,
    pub registry: Vec<CustodianInputV4>,
}

fn input_options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64)
}

/// V5 witness transport carries the entire authenticated checkpoint, rather
/// than treating a V4 checkpoint hash as an opening of the parent anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaChildExecutionInputV5 {
    pub version: u8,
    pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    pub execution: AlphaChildExecutionInputV3,
    pub binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    pub checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    pub environment: Vec<u8>,
    pub configuration: ecx_protocol_core::FrozenConfigurationV2,
    pub genesis_bindings: GenesisStateBindings,
    pub capital: OwnedCapitalWitnessV4,
    pub registry: Vec<CustodianInputV4>,
}

impl AlphaChildExecutionInputV5 {
    fn check_shape(&self) -> Result<(), AlphaChildExecutionErrorV3> {
        use AlphaChildExecutionErrorV3 as E;
        if self.version != crate::child_execution_statement_v4::ALPHA_CHILD_EXECUTION_VERSION_V5
            || self.registry.len() > 255
            || self.environment.len() != crate::ecx_environment_v4::ENCODED_LENGTH
            || input_options().serialized_size(self).map_err(|_| E::Input)?
                > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64 {
            return Err(E::Input);
        }
        self.execution.check_shape()?;
        self.binding.commitment()?;
        self.checkpoint.commitment().map_err(|_| E::Binding)?;
        if matches!(self.capital, OwnedCapitalWitnessV4::SuccessorCarry)
            && self.binding.successor.is_none() { return Err(E::Binding); }
        EcxExecutionEnvironmentV1::decode(&self.environment).map_err(|_| E::Input)?;
        if let OwnedCapitalWitnessV4::Activation { deployment, genesis, inventory, state } = &self.capital {
            let limit = crate::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES;
            if deployment.transaction.is_empty() || deployment.transaction.len() > limit
                || genesis.is_empty() || genesis.len() > limit
                || inventory.path.siblings.len() != 256 || state.path.siblings.len() != 256 {
                return Err(E::Input);
            }
            let decoded: elements::Transaction = elements::encode::deserialize(genesis).map_err(|_| E::Input)?;
            if elements::encode::serialize(&decoded) != *genesis { return Err(E::Input); }
        }
        Ok(())
    }
}

pub fn encode_alpha_child_execution_input_v5(input: &AlphaChildExecutionInputV5)
    -> Result<Vec<u8>, AlphaChildExecutionErrorV3> {
    input.check_shape()?;
    input_options().serialize(input).map_err(|_| AlphaChildExecutionErrorV3::Input)
}

pub fn decode_alpha_child_execution_input_v5(bytes: &[u8])
    -> Result<AlphaChildExecutionInputV5, AlphaChildExecutionErrorV3> {
    if bytes.is_empty() || bytes.len() > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 {
        return Err(AlphaChildExecutionErrorV3::Input);
    }
    let input: AlphaChildExecutionInputV5 = input_options().deserialize(bytes)
        .map_err(|_| AlphaChildExecutionErrorV3::Input)?;
    if encode_alpha_child_execution_input_v5(&input)? != bytes {
        return Err(AlphaChildExecutionErrorV3::Input);
    }
    Ok(input)
}

pub fn execute_owned_alpha_child_execution_v5<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &AlphaChildExecutionInputV5, parent: &P, simplicity: &S,
) -> Result<AlphaChildExecutionOutputV5, AlphaChildExecutionErrorV4> {
    input.check_shape()?;
    let environment = EcxExecutionEnvironmentV1::decode(&input.environment)
        .map_err(|_| AlphaChildExecutionErrorV3::Input)?;
    let registry = input.registry.iter().map(|c| ecx_witness_availability::CustodianPublic {
        index: c.index, encryption_public_key: c.encryption_public_key,
        attestation_public_key: c.attestation_public_key,
    }).collect::<Vec<_>>();
    let genesis;
    let capital = match &input.capital {
        OwnedCapitalWitnessV4::FiniteCarry => CapitalWitnessV4::FiniteCarry,
        OwnedCapitalWitnessV4::SuccessorCarry => CapitalWitnessV4::SuccessorCarry,
        OwnedCapitalWitnessV4::Activation { deployment, genesis: bytes, inventory, state } => {
            genesis = elements::encode::deserialize(bytes).map_err(|_| AlphaChildExecutionErrorV3::Input)?;
            CapitalWitnessV4::Activation { deployment, genesis: &genesis,
                inventory: inventory.as_witness(), state: state.as_witness() }
        }
    };
    execute_alpha_child_execution_v5(&input.execution, &input.binding, &input.checkpoint,
        &input.deposit_policy, &environment, &input.configuration, &input.genesis_bindings, capital, &registry, parent, simplicity)
}

impl AlphaChildExecutionInputV4 {
    fn check_shape(&self) -> Result<(), AlphaChildExecutionErrorV3> {
        use AlphaChildExecutionErrorV3 as E;
        if self.version != crate::child_execution_statement_v4::ALPHA_CHILD_EXECUTION_VERSION_V4
            || self.registry.len() > 255
            || self.environment.len() != crate::ecx_environment_v4::ENCODED_LENGTH
            || input_options().serialized_size(self).map_err(|_| E::Input)?
                > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 as u64 {
            return Err(E::Input);
        }
        self.execution.check_shape()?;
        self.binding.commitment()?;
        if matches!(self.capital, OwnedCapitalWitnessV4::SuccessorCarry)
            && self.binding.successor.is_none() {
            return Err(E::Binding);
        }
        EcxExecutionEnvironmentV1::decode(&self.environment).map_err(|_| E::Input)?;
        if let OwnedCapitalWitnessV4::Activation { deployment, genesis, inventory, state } = &self.capital {
            let limit = crate::native_child_block_v3::ALPHA_MAX_BLOCK_BYTES;
            if deployment.transaction.is_empty() || deployment.transaction.len() > limit
                || genesis.is_empty() || genesis.len() > limit
                || inventory.path.siblings.len() != 256 || state.path.siblings.len() != 256 {
                return Err(E::Input);
            }
            let decoded: elements::Transaction = elements::encode::deserialize(genesis).map_err(|_| E::Input)?;
            if elements::encode::serialize(&decoded) != *genesis { return Err(E::Input); }
        }
        Ok(())
    }
}

pub fn encode_alpha_child_execution_input_v4(input: &AlphaChildExecutionInputV4)
    -> Result<Vec<u8>, AlphaChildExecutionErrorV3> {
    input.check_shape()?;
    input_options().serialize(input).map_err(|_| AlphaChildExecutionErrorV3::Input)
}

pub fn decode_alpha_child_execution_input_v4(bytes: &[u8])
    -> Result<AlphaChildExecutionInputV4, AlphaChildExecutionErrorV3> {
    if bytes.is_empty() || bytes.len() > MAX_ALPHA_CHILD_EXECUTION_INPUT_BYTES_V4 {
        return Err(AlphaChildExecutionErrorV3::Input);
    }
    let input: AlphaChildExecutionInputV4 = input_options().deserialize(bytes)
        .map_err(|_| AlphaChildExecutionErrorV3::Input)?;
    if encode_alpha_child_execution_input_v4(&input)? != bytes {
        return Err(AlphaChildExecutionErrorV3::Input);
    }
    Ok(input)
}

pub fn execute_owned_alpha_child_execution_v4<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &AlphaChildExecutionInputV4, parent: &P, simplicity: &S,
) -> Result<AlphaChildExecutionOutputV4, AlphaChildExecutionErrorV4> {
    input.check_shape()?;
    let environment = EcxExecutionEnvironmentV1::decode(&input.environment)
        .map_err(|_| AlphaChildExecutionErrorV3::Input)?;
    let registry = input.registry.iter().map(|c| ecx_witness_availability::CustodianPublic {
        index: c.index, encryption_public_key: c.encryption_public_key,
        attestation_public_key: c.attestation_public_key,
    }).collect::<Vec<_>>();
    let genesis;
    let capital = match &input.capital {
        OwnedCapitalWitnessV4::FiniteCarry => CapitalWitnessV4::FiniteCarry,
        OwnedCapitalWitnessV4::SuccessorCarry => CapitalWitnessV4::SuccessorCarry,
        OwnedCapitalWitnessV4::Activation { deployment, genesis: bytes, inventory, state } => {
            genesis = elements::encode::deserialize(bytes).map_err(|_| AlphaChildExecutionErrorV3::Input)?;
            CapitalWitnessV4::Activation { deployment, genesis: &genesis,
                inventory: inventory.as_witness(), state: state.as_witness() }
        }
    };
    execute_alpha_child_execution_v4(&input.execution, &input.binding, &input.checkpoint,
        &environment, &input.configuration, &input.genesis_bindings, capital, &registry, parent, simplicity)
}

#[cfg(test)]
#[path = "native_bond_inbox_test_configuration.rs"]
mod test_configuration;

/// Reuses the existing signed-block fixture to qualify transport, not V4
/// consensus execution. Its synthetic empty capital context is not a proof.
#[cfg(test)]
pub(crate) fn check_owned_wire_fixture(execution: &AlphaChildExecutionInputV3) -> AlphaChildExecutionInputV5 {
    use elements::hashes::Hash as _;
    let genesis_bindings = GenesisStateBindings {
        public_state_domain: [1;32], state_node_domain: [2;32], journal_domain: [3;32],
        transition_cmr: [4;32], activation_cmr: [5;32], internal_key: [6;32],
        order_receipts_root: [7;32], availability_root: [8;32], mark_price_atoms: 3_000_000_000,
        state_outpoint: elements::OutPoint { txid: elements::Txid::from_byte_array([9;32]), vout: 17 },
        child_genesis: [10;32], state_utxo_root: [11;32], activation_height: 100,
        transition_program_id: [1;32],
    };
    let input = AlphaChildExecutionInputV4 {
        version: crate::child_execution_statement_v4::ALPHA_CHILD_EXECUTION_VERSION_V4,
        execution: execution.clone(),
        binding: AlphaChildExecutionBindingV4 { execution: execution.binding.clone(),
            evaluator_binding: [12;32], environment: [13;32], genesis_bindings: genesis_bindings.commitment(), successor: None },
        checkpoint: ChildExecutionCheckpointV4 { execution: execution.checkpoint.clone(), capital: None },
        environment: EcxExecutionEnvironmentV1::default().encode().unwrap(),
        configuration: test_configuration::configuration(), genesis_bindings,
        capital: OwnedCapitalWitnessV4::FiniteCarry, registry: vec![],
    };
    let encoded = encode_alpha_child_execution_input_v4(&input).unwrap();
    assert_eq!(decode_alpha_child_execution_input_v4(&encoded).unwrap(), input);
    assert_eq!(serde_json::from_slice::<AlphaChildExecutionInputV4>(
        &serde_json::to_vec(&input).unwrap()).unwrap(), input);
    let mut bad = encoded.clone(); bad.push(0);
    assert!(decode_alpha_child_execution_input_v4(&bad).is_err());
    assert!(decode_alpha_child_execution_input_v4(&encoded[..encoded.len()-1]).is_err());
    let mut wrong_version = input.clone(); wrong_version.version = 0xa6;
    assert!(encode_alpha_child_execution_input_v4(&wrong_version).is_err());
    assert!(crate::child_execution_guest_v3::decode_alpha_child_execution_input_v3(&encoded).is_err());
    assert!(decode_alpha_child_execution_input_v4(
        &crate::child_execution_guest_v3::encode_alpha_child_execution_input_v3(execution).unwrap()).is_err());
    let mut environment = input.clone(); environment.environment.push(0);
    assert!(encode_alpha_child_execution_input_v4(&environment).is_err());
    let mut previous_revision = input.clone(); previous_revision.version = 0xa9;
    assert!(encode_alpha_child_execution_input_v4(&previous_revision).is_err());
    let mut successor = input.clone();
    successor.capital = OwnedCapitalWitnessV4::SuccessorCarry;
    assert!(encode_alpha_child_execution_input_v4(&successor).is_err());
    successor.binding.successor = Some(crate::child_execution_statement_v4::SuccessorIdentityV4 {
        configuration_hash: [21;32], program_id: [22;32], transition_cmr: [23;32] });
    let encoded = encode_alpha_child_execution_input_v4(&successor).unwrap();
    assert_eq!(decode_alpha_child_execution_input_v4(&encoded).unwrap(), successor);

    // Transport fixture only: this synthetic endpoint is not authenticated
    // evidence and must never be used to derive production profile fields.
    let mut v5 = AlphaChildExecutionInputV5 {
        version: crate::child_execution_statement_v4::ALPHA_CHILD_EXECUTION_VERSION_V5,
        // Synthetic transport only; the executor rejects this unqualified policy.
        deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4 {
            historical: input.execution.deposit_configuration.clone(),
            child_genesis_internal: input.execution.checkpoint.genesis_internal,
            parent_genesis_internal: alpha_parent_genesis(),
            protocol_manifest: [1;32], slot: 24,
        },
        execution: input.execution.clone(),
        binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5 {
            execution: input.binding.execution.clone(), evaluator_source_closure: [12;32],
            environment: input.binding.environment, genesis_bindings: input.binding.genesis_bindings,
            successor: None,
        },
        checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5 {
            state: input.checkpoint.clone(),
            bmm_endpoint: if input.checkpoint.execution.height == 0 { None } else { Some(vec![1;80]) },
        },
        environment: input.environment.clone(), configuration: input.configuration.clone(),
        genesis_bindings: input.genesis_bindings.clone(), capital: input.capital.clone(),
        registry: input.registry.clone(),
    };
    v5.binding.execution.predecessor_checkpoint = v5.checkpoint.commitment().unwrap();
    v5.execution.binding = v5.binding.execution.clone();
    let bytes = encode_alpha_child_execution_input_v5(&v5).unwrap();
    assert_eq!(decode_alpha_child_execution_input_v5(&bytes).unwrap(), v5);
    // The previous V5 private schema had the same journal version but no
    // deposit policy. Fixed-width bincode structs and tuples serialize fields
    // in order, so this reproduces that schema without the newly required field.
    // Do not silently interpret old witnesses under the new execution relation.
    let legacy_bytes = input_options().serialize(&(
        v5.version, &v5.execution, &v5.binding, &v5.checkpoint,
        &v5.environment, &v5.configuration, &v5.genesis_bindings,
        &v5.capital, &v5.registry,
    )).unwrap();
    assert!(decode_alpha_child_execution_input_v5(&legacy_bytes).is_err());
    let mut missing_policy = serde_json::to_value(&v5).unwrap();
    missing_policy.as_object_mut().unwrap().remove("deposit_policy");
    assert!(serde_json::from_value::<AlphaChildExecutionInputV5>(missing_policy).is_err());
    assert_eq!(serde_json::from_slice::<AlphaChildExecutionInputV5>(
        &serde_json::to_vec(&v5).unwrap()).unwrap(), v5);
    assert!(decode_alpha_child_execution_input_v4(&bytes).is_err());
    assert!(decode_alpha_child_execution_input_v5(&encoded).is_err());
    assert!(crate::child_execution_guest_v3::decode_alpha_child_execution_input_v3(&bytes).is_err());
    assert!(decode_alpha_child_execution_input_v5(&bytes[..bytes.len()-1]).is_err());
    let mut suffix = bytes.clone(); suffix.push(0);
    assert!(decode_alpha_child_execution_input_v5(&suffix).is_err());
    let mut bad = v5.clone(); bad.version = crate::child_execution_statement_v4::ALPHA_CHILD_EXECUTION_VERSION_V4;
    assert!(encode_alpha_child_execution_input_v5(&bad).is_err());
    let mut bad = v5.clone(); bad.binding.evaluator_source_closure = [0;32];
    assert!(encode_alpha_child_execution_input_v5(&bad).is_err());
    for length in [0, 32, 79, 81] {
        let mut bad = v5.clone(); bad.checkpoint.bmm_endpoint = Some(vec![1;length]);
        assert!(encode_alpha_child_execution_input_v5(&bad).is_err());
    }
    let mut bad = v5.clone(); bad.capital = OwnedCapitalWitnessV4::SuccessorCarry;
    assert!(encode_alpha_child_execution_input_v5(&bad).is_err());
    v5
}

pub enum CapitalWitnessV4<'a> {
    Activation {
        deployment: &'a ecx_elements_settlement::FrozenBondDeploymentV2,
        genesis: &'a elements::Transaction,
        inventory: ActivationCoinWitness<'a>,
        state: ActivationCoinWitness<'a>,
    },
    FiniteCarry,
    SuccessorCarry,
}

/// V5 commits both the validated capital state and its authenticated BMM
/// endpoint. Construction is private so callers cannot attach an unchecked
/// capital projection to an otherwise valid transaction execution.
pub struct AlphaChildExecutionOutputV5 {
    checked: ParentBoundCheckedChildState,
    checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    public_values: crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5,
}
impl AlphaChildExecutionOutputV5 {
    pub fn checked(&self) -> &ParentBoundCheckedChildState { &self.checked }
    pub fn checkpoint(&self) -> &crate::child_execution_state_v4::ChildExecutionCheckpointV5 { &self.checkpoint }
    pub fn public_values(&self) -> crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5 { self.public_values }
}

/// Composes per-input evaluator authentication with capital validation and
/// the full next-parent checkpoint. This is not a V4 receipt reinterpretation.
#[allow(clippy::too_many_arguments)]
pub fn execute_alpha_child_execution_v5<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &AlphaChildExecutionInputV3,
    binding: &crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    deposit_policy: &crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    environment: &EcxExecutionEnvironmentV1,
    configuration: &ecx_protocol_core::FrozenConfigurationV2,
    genesis_bindings: &GenesisStateBindings,
    capital: CapitalWitnessV4<'_>,
    registry: &[ecx_witness_availability::CustodianPublic],
    parent_verifier: &P, simplicity_verifier: &S,
) -> Result<AlphaChildExecutionOutputV5, AlphaChildExecutionErrorV4> {
    use AlphaChildExecutionErrorV3 as E;
    use crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5;
    let source_binding = binding.commitment()?;
    let (checked, context) = execute_alpha_child_native_v5(input, binding, checkpoint,
        deposit_policy, environment, parent_verifier, simplicity_verifier)?;
    let state = match capital {
        CapitalWitnessV4::Activation { deployment, genesis, inventory, state } =>
            context.activation_checkpoint(&checked, configuration, genesis_bindings,
                binding.genesis_bindings, deployment, genesis, inventory, state, registry),
        CapitalWitnessV4::FiniteCarry => context.finite_carry_checkpoint(&checked,
            configuration, genesis_bindings, binding.genesis_bindings, registry),
        CapitalWitnessV4::SuccessorCarry => context.successor_carry_checkpoint(&checked,
            configuration, genesis_bindings, binding.genesis_bindings,
            binding.successor.as_ref().ok_or(E::Binding)?, registry),
    }.map_err(AlphaChildExecutionErrorV4::Capital)?;
    let next = crate::child_execution_state_v4::ChildExecutionCheckpointV5::join_executed_parent(
        state, &checked, &input.parent, binding.execution.parent_binding, parent_verifier)
        .map_err(|_| E::Binding)?;
    let public_values = AlphaChildExecutionPublicValuesV5(AlphaChildExecutionPublicValuesV3 {
        source_binding, predecessor_checkpoint: binding.execution.predecessor_checkpoint,
        next_checkpoint: next.commitment().map_err(|_| E::Binding)?,
        child_hash_internal: next.state.execution.tip_internal,
        child_height: next.state.execution.height,
        observation_time: input.observation_time, parent: *checked.parent(),
    });
    AlphaChildExecutionPublicValuesV5::from_canonical_bytes(&public_values.canonical_bytes())?;
    Ok(AlphaChildExecutionOutputV5 { checked, checkpoint: next, public_values })
}

/// Shared native execution stage. This does not validate or emit a capital
/// projection; callers must finish their distinct capital/ECX relation before
/// exposing a proof journal. Keep receipt trust roots pinned by the consumer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_alpha_child_native_v5<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &AlphaChildExecutionInputV3,
    binding: &crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    deposit_policy: &crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    environment: &EcxExecutionEnvironmentV1,
    parent_verifier: &P, simplicity_verifier: &S,
) -> Result<(ParentBoundCheckedChildState, CheckedAlphaExecutionContextV4), AlphaChildExecutionErrorV3> {
    use AlphaChildExecutionErrorV3 as E;
    input.check_shape()?;
    binding.commitment()?;
    if input.binding != binding.execution || input.checkpoint != checkpoint.state.execution
        || checkpoint.commitment().map_err(|_| E::Binding)? != binding.execution.predecessor_checkpoint
        || deposit_policy.historical != input.deposit_configuration
        || deposit_policy.child_genesis_internal != checkpoint.state.execution.genesis_internal
        || deposit_policy.commitment().ok_or(E::Binding)? != binding.execution.deposit_configuration
        || input.deposit_configuration.pegged_asset_internal != input.policy.classification.base_asset_id {
        return Err(E::Binding.into());
    }
    let effective_depth = deposit_policy.required_depth(checkpoint.state.execution.height)
        .ok_or(E::Binding)?;
    let history = input.history.iter().map(|h| crate::native_header_v3::NativeHeader::decode(h, true))
        .collect::<Result<Vec<_>,_>>().map_err(|_| E::Header)?;
    let prior_header = history.last().ok_or(E::Header)?;
    let params = input.deposit_configuration.address_params()?;
    let asset = elements::AssetId::from_slice(&input.deposit_configuration.pegged_asset_internal)
        .map_err(|_| E::Binding)?;
    let anchor_state = input.parent.terminal_parent_predecessor.commitment().map_err(|_| E::Binding)?;
    let authenticated = input.deposits.iter().map(|entry| match entry {
        None => Ok(None),
        Some(deposit) => deposit.evidence.authenticate(&input.parent.binding,
            binding.execution.parent_binding, input.parent.expected_parent_hash_internal,
            anchor_state, effective_depth, parent_verifier)
            .map(Some).map_err(|_| E::Deposit),
    }).collect::<Result<Vec<_>,_>>()?;
    let entries = authenticated.iter().zip(&input.deposits).map(|(authenticated, input)| {
        authenticated.as_ref().zip(input.as_ref()).map(|(deposit, input)| (
            NativeDepositKernelV3 { deposit, pegged_asset: asset,
                parent_genesis_internal: alpha_parent_genesis(), address_params: &params },
            input.spent_claim_absence_path.clone()))
    }).collect::<Vec<_>>();
    let deposits = NativeBlockDepositsV3 { entries: &entries,
        frozen_parent_binding: binding.execution.parent_binding,
        frozen_deposit_configuration: binding.execution.deposit_configuration,
        minimum_depth: input.deposit_configuration.minimum_depth, scheduled_policy: Some(deposit_policy) };
    let (checked, context) = crate::native_child_block_v3::execute_parent_bound_child_with_ecx_v5(
        &input.parent, binding.execution.parent_binding, parent_verifier, &input.raw_block,
        checkpoint, binding.execution.predecessor_checkpoint, &history, prior_header,
        &input.policy, binding.execution.execution_policy, input.observation_time,
        &input.header_policy, &input.witnesses, environment, binding.environment,
        binding.evaluator_source_closure, binding.execution.simplicity_evaluator_program_id,
        &input.simplicity_receipts, simplicity_verifier, Some(&deposits),
        Some(binding.execution.deposit_configuration)).map_err(E::Execution)?;
    Ok((checked, context))
}

#[derive(Debug)]
pub enum AlphaChildExecutionErrorV4 {
    Execution(AlphaChildExecutionErrorV3),
    Capital(GenesisCoinError),
}
impl From<AlphaChildExecutionErrorV3> for AlphaChildExecutionErrorV4 {
    fn from(e: AlphaChildExecutionErrorV3) -> Self { Self::Execution(e) }
}

/// Only the composed executor constructs this result. The next checkpoint is
/// the capital-bearing V4 state, never the transaction-only projection.
pub struct AlphaChildExecutionOutputV4 {
    checked: ParentBoundCheckedChildState,
    checkpoint: ChildExecutionCheckpointV4,
    public_values: AlphaChildExecutionPublicValuesV4,
}
impl AlphaChildExecutionOutputV4 {
    pub fn checked(&self) -> &ParentBoundCheckedChildState { &self.checked }
    pub fn checkpoint(&self) -> &ChildExecutionCheckpointV4 { &self.checkpoint }
    pub fn public_values(&self) -> AlphaChildExecutionPublicValuesV4 { self.public_values }
}

/// Synthetic extraction regression only, not V4 execution qualification.
/// The private constructor is intentionally available only inside this module
/// under cfg(test); production callers must run the actual executor.
#[cfg(test)]
pub(crate) fn check_custody_checkpoint_extraction_fixture(
    checked: ParentBoundCheckedChildState,
    domain: &crate::custody_redemption_statement_v2::RedemptionDomainV2,
    verifier_address: [u8;20], custody: [u8;32],
) {
    use crate::custody_redemption_statement_v2::extract_executed_custody_checkpoint_v4;
    let execution = checked.child().next_checkpoint().unwrap().clone();
    let legacy = execution.commitment().unwrap();
    let checkpoint = ChildExecutionCheckpointV4 { execution, capital: None };
    let commitment = checkpoint.commitment().unwrap();
    assert_ne!(legacy, commitment);
    let public_values = AlphaChildExecutionPublicValuesV4(AlphaChildExecutionPublicValuesV3 {
        source_binding: [1;32], predecessor_checkpoint: [2;32], next_checkpoint: commitment,
        child_hash_internal: checkpoint.execution.tip_internal,
        child_height: checkpoint.execution.height, observation_time: 1,
        parent: *checked.parent(),
    });
    let mut output = AlphaChildExecutionOutputV4 { checked, checkpoint, public_values };
    let extract = |out: &AlphaChildExecutionOutputV4| {
        extract_executed_custody_checkpoint_v4(domain, verifier_address, custody, out, 1, 0)
    };
    let result = extract(&output).unwrap();
    assert_eq!(result.checkpoint(), commitment);
    let expected_burn = result.burn().clone();
    output.public_values.0.next_checkpoint = legacy;
    assert!(extract(&output).is_err());
    output.public_values = public_values;
    for field in 0..3 {
        match field {
            0 => output.public_values.0.child_hash_internal[0] ^= 1,
            1 => output.public_values.0.child_height ^= 1,
            _ => output.public_values.0.parent.parent_terminal_state_commitment[0] ^= 1,
        }
        assert!(extract(&output).is_err());
        output.public_values = public_values;
    }
    output.checkpoint.execution.height ^= 1;
    output.public_values.0.next_checkpoint = output.checkpoint.commitment().unwrap();
    assert!(extract(&output).is_err());
    output.checkpoint.execution.height ^= 1;
    output.public_values = public_values;
    output.checkpoint.capital = Some(crate::child_execution_state_v4::CapitalProjectionV4 {
        proof_profile: 0, exchange_state_root: [3;32], configuration_hash: [4;32],
        asset_id: [5;32], deployment_commitment: [6;32], transition_program_id: [7;32],
        transition_cmr: [8;32], covenant_state_hash: [9;32],
        covenant_inbox_root: [10;32], covenant_inbox_count: 0,
        node_inbox_root: [10;32], node_inbox_count: 0,
    });
    assert!(extract(&output).is_err()); // stale journal cannot omit capital
    output.public_values.0.next_checkpoint = output.checkpoint.commitment().unwrap();
    let with_capital = extract(&output).unwrap();
    assert_ne!(with_capital.checkpoint(), commitment);
    assert_ne!(with_capital.checkpoint(), legacy);
    assert_eq!(with_capital.burn(), &expected_burn);
    assert!(extract_executed_custody_checkpoint_v4(domain, [0;20], custody, &output, 1, 0).is_err());
    assert!(extract_executed_custody_checkpoint_v4(domain, verifier_address, custody, &output, 0, 0).is_err());

    // Synthetic extraction test, not an authenticated V5 execution fixture.
    use crate::custody_redemption_statement_v2::extract_executed_custody_checkpoint_v5;
    let checkpoint = crate::child_execution_state_v4::ChildExecutionCheckpointV5 {
        state: output.checkpoint, bmm_endpoint: Some(vec![1;80]),
    };
    let mut statement = output.public_values.0;
    let v4_commitment = statement.next_checkpoint;
    statement.next_checkpoint = checkpoint.commitment().unwrap();
    let mut output = AlphaChildExecutionOutputV5 { checked: output.checked, checkpoint,
        public_values: crate::child_execution_statement_v4::AlphaChildExecutionPublicValuesV5(statement) };
    let extract = |out: &AlphaChildExecutionOutputV5| {
        extract_executed_custody_checkpoint_v5(domain, verifier_address, custody, out, 1, 0)
    };
    let result = extract(&output).unwrap();
    assert_eq!(result.burn(), &expected_burn);
    assert_eq!(result.checkpoint(), statement.next_checkpoint);
    assert_ne!(result.checkpoint(), v4_commitment);
    assert_ne!(result.checkpoint(), legacy);
    for replacement in [v4_commitment, legacy, [0;32]] {
        output.public_values.0.next_checkpoint = replacement;
        assert!(extract(&output).is_err());
    }
    output.public_values.0 = statement;
    for byte in 0..80 {
        output.checkpoint.bmm_endpoint.as_mut().unwrap()[byte] ^= 1;
        assert!(extract(&output).is_err());
        output.checkpoint.bmm_endpoint.as_mut().unwrap()[byte] ^= 1;
    }
    for field in 0..3 {
        match field {
            0 => output.public_values.0.child_hash_internal[0] ^= 1,
            1 => output.public_values.0.child_height ^= 1,
            _ => output.public_values.0.parent.parent_terminal_state_commitment[0] ^= 1,
        }
        assert!(extract(&output).is_err());
        output.public_values.0 = statement;
    }
    output.checkpoint.state.capital.as_mut().unwrap().exchange_state_root[0] ^= 1;
    assert!(extract(&output).is_err());
    output.checkpoint.state.capital.as_mut().unwrap().exchange_state_root[0] ^= 1;
    assert!(extract_executed_custody_checkpoint_v5(domain, [0;20], custody, &output, 1, 0).is_err());
    assert!(extract_executed_custody_checkpoint_v5(domain, verifier_address, custody, &output, 0, 0).is_err());
    assert!(extract(&output).is_ok());
}

/// Reuses the V3 transaction input container only, NOT its executor or receipt.
/// Its checkpoint is checked as the exact V3 projection of the supplied V4
/// state; its binding's predecessor is the complete V4 commitment.
#[allow(clippy::too_many_arguments)]
pub fn execute_alpha_child_execution_v4<P: FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2>(
    input: &AlphaChildExecutionInputV3,
    binding: &AlphaChildExecutionBindingV4,
    checkpoint: &ChildExecutionCheckpointV4,
    environment: &EcxExecutionEnvironmentV1,
    configuration: &ecx_protocol_core::FrozenConfigurationV2,
    genesis_bindings: &GenesisStateBindings,
    capital: CapitalWitnessV4<'_>,
    registry: &[ecx_witness_availability::CustodianPublic],
    parent_verifier: &P,
    simplicity_verifier: &S,
) -> Result<AlphaChildExecutionOutputV4, AlphaChildExecutionErrorV4> {
    use AlphaChildExecutionErrorV3 as E;
    input.check_shape()?;
    let source_binding = binding.commitment()?;
    if input.binding != binding.execution || input.checkpoint != checkpoint.execution
        || checkpoint.commitment().map_err(|_| E::Binding)? != binding.execution.predecessor_checkpoint
        || input.deposit_configuration.commitment()? != binding.execution.deposit_configuration
        || input.deposit_configuration.pegged_asset_internal != input.policy.classification.base_asset_id {
        return Err(E::Binding.into());
    }
    let history = input.history.iter().map(|h| crate::native_header_v3::NativeHeader::decode(h, true))
        .collect::<Result<Vec<_>,_>>().map_err(|_| E::Header)?;
    let prior_header = history.last().ok_or(E::Header)?;
    let context = CheckedAlphaExecutionContextV4::authenticate(environment, binding.environment,
        binding.evaluator_binding, checkpoint, binding.execution.predecessor_checkpoint,
        prior_header, &input.parent, binding.execution.parent_binding, parent_verifier)
        .map_err(|_| E::Binding)?;
    let params = input.deposit_configuration.address_params()?;
    let asset = elements::AssetId::from_slice(&input.deposit_configuration.pegged_asset_internal)
        .map_err(|_| E::Binding)?;
    let anchor_state = input.parent.terminal_parent_predecessor.commitment().map_err(|_| E::Binding)?;
    let authenticated = input.deposits.iter().map(|entry| match entry {
        None => Ok(None),
        Some(deposit) => deposit.evidence.authenticate(&input.parent.binding,
            binding.execution.parent_binding, input.parent.expected_parent_hash_internal,
            anchor_state, input.deposit_configuration.minimum_depth, parent_verifier)
            .map(Some).map_err(|_| E::Deposit),
    }).collect::<Result<Vec<_>,_>>()?;
    let entries = authenticated.iter().zip(&input.deposits).map(|(authenticated, input)| {
        authenticated.as_ref().zip(input.as_ref()).map(|(deposit, input)| (
            NativeDepositKernelV3 { deposit, pegged_asset: asset,
                parent_genesis_internal: alpha_parent_genesis(), address_params: &params },
            input.spent_claim_absence_path.clone()))
    }).collect::<Vec<_>>();
    let deposits = NativeBlockDepositsV3 { entries: &entries,
        frozen_parent_binding: binding.execution.parent_binding,
        frozen_deposit_configuration: binding.execution.deposit_configuration,
        minimum_depth: input.deposit_configuration.minimum_depth, scheduled_policy: None };
    let checked = execute_parent_bound_child_with_ecx_v4(&input.parent,
        binding.execution.parent_binding, parent_verifier, &input.raw_block,
        checkpoint, binding.execution.predecessor_checkpoint, &history, prior_header,
        &input.policy, binding.execution.execution_policy, input.observation_time,
        &input.header_policy, &input.witnesses, environment, binding.environment,
        binding.evaluator_binding, binding.execution.simplicity_evaluator_program_id,
        &input.simplicity_receipts, simplicity_verifier, Some(&deposits),
        Some(binding.execution.deposit_configuration)).map_err(E::Execution)?;
    let next = match capital {
        CapitalWitnessV4::Activation { deployment, genesis, inventory, state } =>
            context.activation_checkpoint(&checked, configuration, genesis_bindings,
                binding.genesis_bindings, deployment, genesis, inventory, state, registry),
        CapitalWitnessV4::FiniteCarry => context.finite_carry_checkpoint(&checked,
            configuration, genesis_bindings, binding.genesis_bindings, registry),
        CapitalWitnessV4::SuccessorCarry => context.successor_carry_checkpoint(&checked,
            configuration, genesis_bindings, binding.genesis_bindings,
            binding.successor.as_ref().ok_or(E::Binding)?, registry),
    }.map_err(AlphaChildExecutionErrorV4::Capital)?;
    let public_values = AlphaChildExecutionPublicValuesV4(AlphaChildExecutionPublicValuesV3 {
        source_binding, predecessor_checkpoint: binding.execution.predecessor_checkpoint,
        next_checkpoint: next.commitment().map_err(|_| E::Binding)?,
        child_hash_internal: next.execution.tip_internal, child_height: next.execution.height,
        observation_time: input.observation_time, parent: *checked.parent(),
    });
    // Validate the complete statement before allowing it to leave the executor.
    AlphaChildExecutionPublicValuesV4::from_canonical_bytes(&public_values.canonical_bytes())?;
    Ok(AlphaChildExecutionOutputV4 { checked, checkpoint: next, public_values })
}
