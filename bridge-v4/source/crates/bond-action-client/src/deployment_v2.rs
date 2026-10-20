//! Deterministic, unsigned physical deployment/genesis candidate for bond V2.
//!
//! This host/wallet module deliberately lives outside the frozen proof source
//! graph. It reuses the consensus-facing settlement verifier, but adding or
//! changing candidate construction cannot silently relabel an existing guest.

use ecx_elements_settlement::{
    verify_frozen_bond_deployment_v2, FrozenBondAssetV2, FrozenBondDeploymentV2,
    VerifiedFrozenBondDeploymentV2, BOND_DEPLOYMENT_VERSION, BOND_FIXED_SUPPLY_ATOMS_V2,
    BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2, MAX_ELEMENTS_TRANSACTION_BYTES,
};
use ecx_protocol_core::{FrozenConfigurationV2, Hash32};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::{sha256, Hash};
use elements::opcodes;
use elements::secp256k1_zkp::{Secp256k1, SecretKey};
use elements::{encode, AssetId, OutPoint, Script, Transaction, TxIn, TxOut, TxOutSecrets};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeploymentCandidateErrorV2 {
    #[error("two-transaction frozen bond deployment/genesis candidate is invalid")]
    InvalidCandidate,
    #[error("frozen deployment verifier rejected the candidate: {0}")]
    Settlement(#[from] ecx_elements_settlement::SettlementError),
}

/// Fully specified inputs for the deterministic unsigned two-transaction
/// initialization. The caller supplies the confidential inventory output
/// because its range proof must be produced with wallet CSPRNG state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenBondDeploymentGenesisPlanV2 {
    pub issuance_input: TxIn,
    pub issuance_contract_entropy: Hash32,
    pub deployment_additional_inputs: Vec<TxIn>,
    pub deployment_additional_explicit_outputs: Vec<TxOut>,
    pub inventory_output: TxOut,
    pub inventory_asset_blinding_factor: [u8; 32],
    pub inventory_value_blinding_factor: [u8; 32],
    pub issuance_value_blinding_factor: [u8; 32],
    pub issuance_blinding_secret: [u8; 32],
    pub inventory_vault_script: Script,
    pub redemption_queue_script: Script,
    pub reissuance_token_burn_script: Script,
    pub state_authority_asset_id: Hash32,
    pub state_authority_source_script: Script,
    pub genesis_state_script: Script,
    pub usdd_asset_id: Hash32,
    pub genesis_additional_inputs: Vec<TxIn>,
    pub genesis_additional_explicit_outputs: Vec<TxOut>,
}

/// Deterministic unsigned output. Witness-only signatures may be added later
/// without changing either txid. This is not confirmation or activation
/// evidence and does not assert that the supplied prevouts exist or are funded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenBondDeploymentGenesisCandidateV2 {
    pub deployment: FrozenBondDeploymentV2,
    pub frozen_asset: FrozenBondAssetV2,
    pub verified_deployment: VerifiedFrozenBondDeploymentV2,
    pub genesis_transaction: Vec<u8>,
    pub genesis_transaction_id: Hash32,
    pub state_authority_source_output_index: u32,
    pub genesis_state_output_index: u32,
}

pub const DEPLOYMENT_CANDIDATE_SCHEMA_V2: &str =
    "ECX_BOND_V2_UNSIGNED_PHYSICAL_DEPLOYMENT_CANDIDATE_V1";
pub const PUBLIC_DEPLOYMENT_CANDIDATE_SCHEMA_V3: &str =
    "ECX_BOND_V3_UNSIGNED_PUBLIC_PHYSICAL_DEPLOYMENT_CANDIDATE_V1";
pub const DEPLOYMENT_CANDIDATE_STATUS_V2: &str =
    "UNSIGNED_UNFUNDED_UNCONFIRMED_UNFROZEN_NOT_ACTIVATED";
pub const DEPLOYMENT_CONFIGURATION_BINDING_SCHEMA_V2: &str =
    "ECX_BOND_V2_PHYSICAL_DEPLOYMENT_CONFIGURATION_BINDING_V1";
pub const DEPLOYMENT_CONFIGURATION_BINDING_STATUS_V2: &str =
    "CONFIGURATION_BOUND_UNSIGNED_UNFUNDED_UNCONFIRMED_UNFROZEN_NOT_ACTIVATED";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedFrozenBondDeploymentDocumentV2 {
    pub transaction_id: Hash32,
    pub issuance_previous_txid: Hash32,
    pub issuance_previous_vout: u32,
    pub bond_asset_id: Hash32,
    pub reissuance_token_asset_id: Hash32,
    pub inventory_output_index: u32,
    pub reissuance_token_burn_output_index: u32,
    pub fixed_supply_atoms: u64,
    pub deployment_commitment: Hash32,
}

impl From<VerifiedFrozenBondDeploymentV2> for VerifiedFrozenBondDeploymentDocumentV2 {
    fn from(value: VerifiedFrozenBondDeploymentV2) -> Self {
        Self {
            transaction_id: value.transaction_id,
            issuance_previous_txid: value.issuance_previous_txid,
            issuance_previous_vout: value.issuance_previous_vout,
            bond_asset_id: value.bond_asset_id,
            reissuance_token_asset_id: value.reissuance_token_asset_id,
            inventory_output_index: value.inventory_output_index,
            reissuance_token_burn_output_index: value.reissuance_token_burn_output_index,
            fixed_supply_atoms: value.fixed_supply_atoms,
            deployment_commitment: value.deployment_commitment,
        }
    }
}

impl From<VerifiedFrozenBondDeploymentDocumentV2> for VerifiedFrozenBondDeploymentV2 {
    fn from(value: VerifiedFrozenBondDeploymentDocumentV2) -> Self {
        Self {
            transaction_id: value.transaction_id,
            issuance_previous_txid: value.issuance_previous_txid,
            issuance_previous_vout: value.issuance_previous_vout,
            bond_asset_id: value.bond_asset_id,
            reissuance_token_asset_id: value.reissuance_token_asset_id,
            inventory_output_index: value.inventory_output_index,
            reissuance_token_burn_output_index: value.reissuance_token_burn_output_index,
            fixed_supply_atoms: value.fixed_supply_atoms,
            deployment_commitment: value.deployment_commitment,
        }
    }
}

/// Portable create-new output of the offline composer. All authority flags are
/// fixed false so these bytes cannot be mistaken for funding, confirmation,
/// identity freeze, proof verification, or activation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenBondDeploymentGenesisDocumentV2 {
    pub schema: String,
    pub status: String,
    pub funded: bool,
    pub signed: bool,
    pub mempool_accepted: bool,
    pub confirmed: bool,
    pub identities_frozen: bool,
    pub activated: bool,
    pub frozen_asset: FrozenBondAssetV2,
    pub deployment: FrozenBondDeploymentV2,
    pub verified_deployment: VerifiedFrozenBondDeploymentDocumentV2,
    pub genesis_transaction: Vec<u8>,
    pub genesis_transaction_id: Hash32,
    pub state_authority_source_output_index: u32,
    pub genesis_state_output_index: u32,
    pub expected_state_authority_asset_id: Hash32,
    pub expected_genesis_state_script_sha256: Hash32,
    pub expected_usdd_asset_id: Hash32,
}

impl FrozenBondDeploymentGenesisDocumentV2 {
    /// Offline second pass for an unsigned public document. No deployment or
    /// sponsor fields are reconstructed, and existing status gates still apply.
    pub fn rebind_public_genesis_script(
        &self,
        script: Script,
    ) -> Result<Self, DeploymentCandidateErrorV2> {
        self.verify()?;
        if self.schema != PUBLIC_DEPLOYMENT_CANDIDATE_SCHEMA_V3 {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        let mut genesis = decode_transaction(&self.genesis_transaction)?;
        let output = genesis.output.get_mut(self.genesis_state_output_index as usize)
            .ok_or(DeploymentCandidateErrorV2::InvalidCandidate)?;
        output.script_pubkey = script.clone();
        let mut rebound = self.clone();
        rebound.genesis_transaction = encode::serialize(&genesis);
        rebound.genesis_transaction_id = genesis.txid().to_byte_array();
        rebound.expected_genesis_state_script_sha256 = script_sha256(&script);
        rebound.verify()?;
        Ok(rebound)
    }

    pub fn from_candidate(
        candidate: FrozenBondDeploymentGenesisCandidateV2,
        expected_state_authority_asset_id: Hash32,
        expected_genesis_state_script_sha256: Hash32,
        expected_usdd_asset_id: Hash32,
    ) -> Result<Self, DeploymentCandidateErrorV2> {
        let document = Self {
            schema: match candidate.deployment.version {
                BOND_DEPLOYMENT_VERSION => DEPLOYMENT_CANDIDATE_SCHEMA_V2,
                ecx_elements_settlement::public_deployment::PUBLIC_DEPLOYMENT_VERSION => PUBLIC_DEPLOYMENT_CANDIDATE_SCHEMA_V3,
                _ => return Err(DeploymentCandidateErrorV2::InvalidCandidate),
            }.to_owned(),
            status: DEPLOYMENT_CANDIDATE_STATUS_V2.to_owned(),
            funded: false,
            signed: false,
            mempool_accepted: false,
            confirmed: false,
            identities_frozen: false,
            activated: false,
            frozen_asset: candidate.frozen_asset,
            deployment: candidate.deployment,
            verified_deployment: candidate.verified_deployment.into(),
            genesis_transaction: candidate.genesis_transaction,
            genesis_transaction_id: candidate.genesis_transaction_id,
            state_authority_source_output_index: candidate.state_authority_source_output_index,
            genesis_state_output_index: candidate.genesis_state_output_index,
            expected_state_authority_asset_id,
            expected_genesis_state_script_sha256,
            expected_usdd_asset_id,
        };
        document.verify()?;
        Ok(document)
    }

    pub fn verify(&self) -> Result<(), DeploymentCandidateErrorV2> {
        let public = match (self.schema.as_str(), self.deployment.version) {
            (DEPLOYMENT_CANDIDATE_SCHEMA_V2, BOND_DEPLOYMENT_VERSION) => false,
            (PUBLIC_DEPLOYMENT_CANDIDATE_SCHEMA_V3, ecx_elements_settlement::public_deployment::PUBLIC_DEPLOYMENT_VERSION) => true,
            _ => return Err(DeploymentCandidateErrorV2::InvalidCandidate),
        };
        if self.status != DEPLOYMENT_CANDIDATE_STATUS_V2
            || self.funded
            || self.signed
            || self.mempool_accepted
            || self.confirmed
            || self.identities_frozen
            || self.activated
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        verify_deployment_genesis_candidate(
            &FrozenBondDeploymentGenesisCandidateV2 {
                deployment: self.deployment.clone(),
                frozen_asset: self.frozen_asset,
                verified_deployment: self.verified_deployment.into(),
                genesis_transaction: self.genesis_transaction.clone(),
                genesis_transaction_id: self.genesis_transaction_id,
                state_authority_source_output_index: self.state_authority_source_output_index,
                genesis_state_output_index: self.genesis_state_output_index,
            },
            self.expected_state_authority_asset_id,
            self.expected_genesis_state_script_sha256,
            self.expected_usdd_asset_id,
            public,
        )
    }
}

/// Replace only the physical deployment identities in a complete validated
/// V2 configuration template, then validate the resulting candidate. This is
/// intentionally separate from [`FrozenBondDeploymentConfigurationBindingDocumentV2`]:
/// deriving a candidate configuration is not evidence that any identity has
/// been reviewed, frozen, funded, confirmed, or activated.
pub fn derive_physical_deployment_configuration_candidate_v2(
    candidate: &FrozenBondDeploymentGenesisDocumentV2,
    mut template: FrozenConfigurationV2,
) -> Result<FrozenConfigurationV2, DeploymentCandidateErrorV2> {
    candidate.verify()?;
    template.bond_asset_id = candidate.verified_deployment.bond_asset_id;
    template.bond_deployment_commitment = candidate.verified_deployment.deployment_commitment;
    template.bond_inventory_script_sha256 = candidate.frozen_asset.inventory_vault_script_sha256;
    template.bond_redemption_queue_script_sha256 =
        candidate.frozen_asset.redemption_queue_script_sha256;
    template.destroyed_reissuance_token_script_sha256 =
        candidate.frozen_asset.reissuance_token_burn_script_sha256;
    template.base.state_authority_asset_id = candidate.expected_state_authority_asset_id;
    template.base.usdd_asset_id = candidate.expected_usdd_asset_id;
    template.fixed_supply_atoms = candidate.verified_deployment.fixed_supply_atoms;
    template
        .validate()
        .map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
    Ok(template)
}

/// Second-stage join between a deterministic physical candidate and the exact
/// validated V18 configuration. The singleton script hash remains explicit
/// because it is a separately frozen node identity, not a configuration field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenBondDeploymentConfigurationBindingDocumentV2 {
    pub schema: String,
    pub status: String,
    pub funded: bool,
    pub signed: bool,
    pub mempool_accepted: bool,
    pub confirmed: bool,
    pub identities_frozen: bool,
    pub activated: bool,
    pub configuration: FrozenConfigurationV2,
    pub configuration_hash: Hash32,
    pub candidate: FrozenBondDeploymentGenesisDocumentV2,
}

impl FrozenBondDeploymentConfigurationBindingDocumentV2 {
    pub fn bind(
        candidate: FrozenBondDeploymentGenesisDocumentV2,
        configuration: FrozenConfigurationV2,
    ) -> Result<Self, DeploymentCandidateErrorV2> {
        let document = Self {
            schema: DEPLOYMENT_CONFIGURATION_BINDING_SCHEMA_V2.to_owned(),
            status: DEPLOYMENT_CONFIGURATION_BINDING_STATUS_V2.to_owned(),
            funded: false,
            signed: false,
            mempool_accepted: false,
            confirmed: false,
            identities_frozen: false,
            activated: false,
            configuration_hash: configuration.digest(),
            configuration,
            candidate,
        };
        document.verify()?;
        Ok(document)
    }

    pub fn verify(&self) -> Result<(), DeploymentCandidateErrorV2> {
        if self.schema != DEPLOYMENT_CONFIGURATION_BINDING_SCHEMA_V2
            || self.status != DEPLOYMENT_CONFIGURATION_BINDING_STATUS_V2
            || self.funded
            || self.signed
            || self.mempool_accepted
            || self.confirmed
            || self.identities_frozen
            || self.activated
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        self.configuration
            .validate()
            .map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
        self.candidate.verify()?;
        let verified = self.candidate.verified_deployment;
        if self.configuration.digest() != self.configuration_hash
            || self.configuration.bond_asset_id != verified.bond_asset_id
            || self.configuration.bond_deployment_commitment != verified.deployment_commitment
            || self.configuration.bond_inventory_script_sha256
                != self.candidate.frozen_asset.inventory_vault_script_sha256
            || self.configuration.bond_redemption_queue_script_sha256
                != self.candidate.frozen_asset.redemption_queue_script_sha256
            || self.configuration.destroyed_reissuance_token_script_sha256
                != self
                    .candidate
                    .frozen_asset
                    .reissuance_token_burn_script_sha256
            || self.configuration.base.state_authority_asset_id
                != self.candidate.expected_state_authority_asset_id
            || self.configuration.base.usdd_asset_id != self.candidate.expected_usdd_asset_id
            || self.configuration.fixed_supply_atoms != verified.fixed_supply_atoms
            || self.candidate.expected_genesis_state_script_sha256 == [0; 32]
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        Ok(())
    }
}

fn script_sha256(script: &Script) -> Hash32 {
    sha256::Hash::hash(script.as_bytes()).to_byte_array()
}

fn is_valid_p2tr(script: &Script) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 34
        && bytes[0] == 0x51
        && bytes[1] == 0x20
        && elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&bytes[2..]).is_ok()
}

fn explicit_output_amount(output: &TxOut, expected_asset: Hash32) -> Option<u64> {
    if output.asset.explicit()?.into_inner().to_byte_array() != expected_asset {
        return None;
    }
    output.value.explicit()
}

fn decode_transaction(bytes: &[u8]) -> Result<Transaction, DeploymentCandidateErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_ELEMENTS_TRANSACTION_BYTES {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let transaction: Transaction =
        encode::deserialize(bytes).map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
    if encode::serialize(&transaction) != bytes {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    Ok(transaction)
}

fn validate_unsigned_inputs(inputs: &[TxIn]) -> Result<(), DeploymentCandidateErrorV2> {
    if inputs
        .iter()
        .any(|input| input.has_issuance() || input.is_pegin() || !input.script_sig.is_empty())
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    Ok(())
}

fn validate_distinct_prevouts<'a>(
    inputs: impl IntoIterator<Item = &'a TxIn>,
) -> Result<(), DeploymentCandidateErrorV2> {
    let mut prevouts = BTreeSet::new();
    for input in inputs {
        let key = (
            input.previous_output.txid.to_byte_array(),
            input.previous_output.vout,
        );
        if input.previous_output == OutPoint::default() || !prevouts.insert(key) {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
    }
    Ok(())
}

fn validate_extra_outputs(
    outputs: &[TxOut],
    forbidden_assets: &[Hash32],
) -> Result<(), DeploymentCandidateErrorV2> {
    for output in outputs {
        let Some(asset) = output.asset.explicit() else {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        };
        if output.value.explicit().is_none() || output.nonce != Nonce::Null {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        if forbidden_assets.contains(&asset.into_inner().to_byte_array()) {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
    }
    Ok(())
}

/// Compose canonical Tx1 and Tx2 without creating a deployment/genesis txid
/// fixed point. Tx1 output order is inventory, token burn, state authority,
/// then explicit sponsor outputs. Tx2 input zero spends Tx1 output two and Tx2
/// output zero is the exact state singleton.
pub fn compose_frozen_bond_deployment_genesis_v2(
    plan: FrozenBondDeploymentGenesisPlanV2,
) -> Result<FrozenBondDeploymentGenesisCandidateV2, DeploymentCandidateErrorV2> {
    const INVENTORY_OUTPUT_INDEX: u32 = 0;
    const TOKEN_BURN_OUTPUT_INDEX: u32 = 1;
    const STATE_AUTHORITY_SOURCE_OUTPUT_INDEX: u32 = 2;
    const GENESIS_STATE_OUTPUT_INDEX: u32 = 0;

    if plan.issuance_contract_entropy == [0; 32]
        || plan.state_authority_asset_id == [0; 32]
        || plan.usdd_asset_id == [0; 32]
        || plan.state_authority_asset_id == plan.usdd_asset_id
        || plan.inventory_asset_blinding_factor == [0; 32]
        || plan.inventory_value_blinding_factor == [0; 32]
        || plan.inventory_asset_blinding_factor == plan.inventory_value_blinding_factor
        || plan.issuance_value_blinding_factor == [0; 32]
        || plan.issuance_value_blinding_factor == plan.inventory_asset_blinding_factor
        || plan.issuance_value_blinding_factor == plan.inventory_value_blinding_factor
        || plan.issuance_blinding_secret == [0; 32]
        || plan.issuance_input.has_issuance()
        || plan.issuance_input.is_pegin()
        || !plan.issuance_input.script_sig.is_empty()
        || !is_valid_p2tr(&plan.state_authority_source_script)
        || !is_valid_p2tr(&plan.genesis_state_script)
        || plan.state_authority_source_script == plan.genesis_state_script
        || plan.reissuance_token_burn_script.as_bytes() != [opcodes::all::OP_RETURN.into_u8()]
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    validate_unsigned_inputs(&plan.deployment_additional_inputs)?;
    validate_unsigned_inputs(&plan.genesis_additional_inputs)?;
    validate_distinct_prevouts(
        std::iter::once(&plan.issuance_input).chain(plan.deployment_additional_inputs.iter()),
    )?;

    let expected_authority = plan.state_authority_asset_id;
    let expected_usdd = plan.usdd_asset_id;
    let expected_genesis_script = script_sha256(&plan.genesis_state_script);
    let mut issuance_input = plan.issuance_input;
    issuance_input.asset_issuance.asset_blinding_nonce = elements::secp256k1_zkp::ZERO_TWEAK;
    issuance_input.asset_issuance.asset_entropy = plan.issuance_contract_entropy;
    issuance_input.asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2);
    issuance_input.asset_issuance.inflation_keys = Value::Null;
    let issuance_vbf = elements::confidential::ValueBlindingFactor::from_slice(
        &plan.issuance_value_blinding_factor,
    )
    .map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
    let issuance_secret = SecretKey::from_slice(&plan.issuance_blinding_secret)
        .map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
    issuance_input
        .blind_issuances_with_bfs(
            &Secp256k1::new(),
            issuance_vbf,
            elements::confidential::ValueBlindingFactor::zero(),
            issuance_secret,
            issuance_secret,
        )
        .map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
    issuance_input.asset_issuance.inflation_keys =
        Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2);
    let (bond_asset, token_asset) = issuance_input.issuance_ids();
    let bond_asset_id = bond_asset.into_inner().to_byte_array();
    let token_asset_id = token_asset.into_inner().to_byte_array();
    if bond_asset_id == token_asset_id
        || [bond_asset_id, token_asset_id].contains(&expected_authority)
        || [bond_asset_id, token_asset_id].contains(&expected_usdd)
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let inventory_abf = AssetBlindingFactor::from_slice(&plan.inventory_asset_blinding_factor)
        .map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
    let inventory_vbf = ValueBlindingFactor::from_slice(&plan.inventory_value_blinding_factor)
        .map_err(|_| DeploymentCandidateErrorV2::InvalidCandidate)?;
    let inventory_secrets = TxOutSecrets::new(
        bond_asset,
        inventory_abf,
        BOND_FIXED_SUPPLY_ATOMS_V2,
        inventory_vbf,
    );
    let expected_issuance_vbf = ValueBlindingFactor::last(
        &Secp256k1::new(),
        BOND_FIXED_SUPPLY_ATOMS_V2,
        AssetBlindingFactor::zero(),
        &[inventory_secrets.value_blind_inputs()],
        &[],
    );
    if issuance_vbf != expected_issuance_vbf {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let frozen_asset = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: bond_asset_id,
        inventory_vault_script_sha256: script_sha256(&plan.inventory_vault_script),
        redemption_queue_script_sha256: script_sha256(&plan.redemption_queue_script),
        reissuance_token_burn_script_sha256: script_sha256(&plan.reissuance_token_burn_script),
    };
    frozen_asset.validate()?;
    if plan.inventory_output.script_pubkey != plan.inventory_vault_script {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let forbidden = [
        bond_asset_id,
        token_asset_id,
        expected_authority,
        expected_usdd,
    ];
    validate_extra_outputs(&plan.deployment_additional_explicit_outputs, &forbidden)?;
    validate_extra_outputs(&plan.genesis_additional_explicit_outputs, &forbidden)?;

    let burn = TxOut {
        asset: Asset::Explicit(AssetId::from_byte_array(token_asset_id)),
        value: Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2),
        nonce: Nonce::Null,
        script_pubkey: plan.reissuance_token_burn_script,
        witness: Default::default(),
    };
    let authority = TxOut {
        asset: Asset::Explicit(AssetId::from_byte_array(expected_authority)),
        value: Value::Explicit(1),
        nonce: Nonce::Null,
        script_pubkey: plan.state_authority_source_script,
        witness: Default::default(),
    };
    let mut tx1_inputs = vec![issuance_input];
    tx1_inputs.extend(plan.deployment_additional_inputs);
    let mut tx1_outputs = vec![plan.inventory_output, burn, authority];
    tx1_outputs.extend(plan.deployment_additional_explicit_outputs);
    let tx1 = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: tx1_inputs,
        output: tx1_outputs,
    };
    let deployment = FrozenBondDeploymentV2 {
        version: BOND_DEPLOYMENT_VERSION,
        transaction: encode::serialize(&tx1),
        issuance_input_index: 0,
        inventory_output_index: INVENTORY_OUTPUT_INDEX,
        inventory_asset_blinding_factor: plan.inventory_asset_blinding_factor,
        inventory_value_blinding_factor: plan.inventory_value_blinding_factor,
        issuance_value_blinding_factor: plan.issuance_value_blinding_factor,
        reissuance_token_burn_output_index: TOKEN_BURN_OUTPUT_INDEX,
    };
    let verified_deployment = verify_frozen_bond_deployment_v2(&deployment, &frozen_asset)?;

    if plan
        .genesis_additional_inputs
        .iter()
        .any(|input| input.previous_output.txid == tx1.txid())
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }

    let authority_input = TxIn {
        previous_output: OutPoint::new(tx1.txid(), STATE_AUTHORITY_SOURCE_OUTPUT_INDEX),
        ..TxIn::default()
    };
    let singleton = TxOut {
        asset: Asset::Explicit(AssetId::from_byte_array(expected_authority)),
        value: Value::Explicit(1),
        nonce: Nonce::Null,
        script_pubkey: plan.genesis_state_script,
        witness: Default::default(),
    };
    let mut tx2_inputs = vec![authority_input];
    tx2_inputs.extend(plan.genesis_additional_inputs);
    validate_distinct_prevouts(tx2_inputs.iter())?;
    let mut tx2_outputs = vec![singleton];
    tx2_outputs.extend(plan.genesis_additional_explicit_outputs);
    let tx2 = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: tx2_inputs,
        output: tx2_outputs,
    };
    let candidate = FrozenBondDeploymentGenesisCandidateV2 {
        deployment,
        frozen_asset,
        verified_deployment,
        genesis_transaction: encode::serialize(&tx2),
        genesis_transaction_id: tx2.txid().to_byte_array(),
        state_authority_source_output_index: STATE_AUTHORITY_SOURCE_OUTPUT_INDEX,
        genesis_state_output_index: GENESIS_STATE_OUTPUT_INDEX,
    };
    verify_frozen_bond_deployment_genesis_candidate_v2(
        &candidate,
        expected_authority,
        expected_genesis_script,
        expected_usdd,
    )?;
    Ok(candidate)
}

pub fn compose_frozen_bond_deployment_genesis_document_v2(
    plan: FrozenBondDeploymentGenesisPlanV2,
) -> Result<FrozenBondDeploymentGenesisDocumentV2, DeploymentCandidateErrorV2> {
    let expected_authority = plan.state_authority_asset_id;
    let expected_genesis_script = script_sha256(&plan.genesis_state_script);
    let expected_usdd = plan.usdd_asset_id;
    let candidate = compose_frozen_bond_deployment_genesis_v2(plan)?;
    FrozenBondDeploymentGenesisDocumentV2::from_candidate(
        candidate,
        expected_authority,
        expected_genesis_script,
        expected_usdd,
    )
}

/// Replace only the Tx2 singleton script after the exact finite configuration
/// has been derived from Tx1. The confidential inventory proof and every Tx1
/// byte are retained from the original plan. This is the supported second pass
/// for the otherwise circular physical-deployment/genesis workflow.
pub fn rebind_frozen_bond_deployment_genesis_plan_v2(
    mut plan: FrozenBondDeploymentGenesisPlanV2,
    genesis_state_script: Script,
) -> Result<FrozenBondDeploymentGenesisPlanV2, DeploymentCandidateErrorV2> {
    let original = compose_frozen_bond_deployment_genesis_v2(plan.clone())?;
    plan.genesis_state_script = genesis_state_script;
    let rebound = compose_frozen_bond_deployment_genesis_v2(plan.clone())?;
    if original.deployment != rebound.deployment
        || original.frozen_asset != rebound.frozen_asset
        || original.verified_deployment != rebound.verified_deployment
        || original.state_authority_source_output_index
            != rebound.state_authority_source_output_index
        || original.genesis_state_output_index != rebound.genesis_state_output_index
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    Ok(plan)
}

/// Independently re-verify the physical linkage portion of node activation.
/// Confirmation/header membership and frozen identity equality remain node
/// responsibilities and are intentionally not inferred here.
pub fn verify_frozen_bond_deployment_genesis_candidate_v2(
    candidate: &FrozenBondDeploymentGenesisCandidateV2,
    expected_authority: Hash32,
    expected_genesis_script: Hash32,
    expected_usdd: Hash32,
) -> Result<(), DeploymentCandidateErrorV2> {
    verify_deployment_genesis_candidate(candidate, expected_authority, expected_genesis_script, expected_usdd, false)
}

/// Explicit opt-in to the public V3 deployment relation; legacy V2 documents
/// continue to use the historical verifier and cannot silently change meaning.
pub fn compose_public_bond_genesis_candidate(
    deployment: FrozenBondDeploymentV2,
    frozen_asset: FrozenBondAssetV2,
    expected_authority: Hash32,
    expected_usdd: Hash32,
    genesis_state_script: Script,
    additional_inputs: Vec<TxIn>,
    additional_outputs: Vec<TxOut>,
) -> Result<FrozenBondDeploymentGenesisCandidateV2, DeploymentCandidateErrorV2> {
    let verified = ecx_elements_settlement::public_deployment::verify_public_bond_deployment(
        &deployment, &frozen_asset,
    )?;
    validate_unsigned_inputs(&additional_inputs)?;
    if additional_inputs.iter().any(|input| input.previous_output.txid.to_byte_array() == verified.transaction_id) {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    validate_extra_outputs(&additional_outputs, &[
        verified.bond_asset_id, verified.reissuance_token_asset_id, expected_authority, expected_usdd,
    ])?;
    let expected_script = script_sha256(&genesis_state_script);
    let mut inputs = vec![TxIn {
        previous_output: OutPoint::new(elements::Txid::from_byte_array(verified.transaction_id), 2),
        ..TxIn::default()
    }];
    inputs.extend(additional_inputs);
    validate_distinct_prevouts(inputs.iter())?;
    let mut outputs = vec![TxOut {
        asset: Asset::Explicit(AssetId::from_byte_array(expected_authority)),
        value: Value::Explicit(1),
        nonce: Nonce::Null,
        script_pubkey: genesis_state_script,
        witness: Default::default(),
    }];
    outputs.extend(additional_outputs);
    let genesis = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    let candidate = FrozenBondDeploymentGenesisCandidateV2 {
        deployment,
        frozen_asset,
        verified_deployment: verified,
        genesis_transaction: encode::serialize(&genesis),
        genesis_transaction_id: genesis.txid().to_byte_array(),
        state_authority_source_output_index: 2,
        genesis_state_output_index: 0,
    };
    verify_public_bond_deployment_genesis_candidate(&candidate, expected_authority, expected_script, expected_usdd)?;
    Ok(candidate)
}

/// Verify the public V3 deployment and its linked genesis singleton.
pub fn verify_public_bond_deployment_genesis_candidate(
    candidate: &FrozenBondDeploymentGenesisCandidateV2,
    expected_authority: Hash32,
    expected_genesis_script: Hash32,
    expected_usdd: Hash32,
) -> Result<(), DeploymentCandidateErrorV2> {
    verify_deployment_genesis_candidate(candidate, expected_authority, expected_genesis_script, expected_usdd, true)
}

fn verify_deployment_genesis_candidate(
    candidate: &FrozenBondDeploymentGenesisCandidateV2,
    expected_authority: Hash32,
    expected_genesis_script: Hash32,
    expected_usdd: Hash32,
    public: bool,
) -> Result<(), DeploymentCandidateErrorV2> {
    if expected_authority == [0; 32]
        || expected_genesis_script == [0; 32]
        || expected_usdd == [0; 32]
        || expected_authority == expected_usdd
        || candidate.state_authority_source_output_index != 2
        || candidate.genesis_state_output_index != 0
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let verified = if public {
        ecx_elements_settlement::public_deployment::verify_public_bond_deployment(
            &candidate.deployment, &candidate.frozen_asset,
        )?
    } else {
        verify_frozen_bond_deployment_v2(&candidate.deployment, &candidate.frozen_asset)?
    };
    if verified != candidate.verified_deployment {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let tx1 = decode_transaction(&candidate.deployment.transaction)?;
    let tx2 = decode_transaction(&candidate.genesis_transaction)?;
    if public && !ecx_elements_settlement::explicit_creations::has_only_explicit_creations(&tx2) {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    if tx1.txid().to_byte_array() != verified.transaction_id
        || tx2.txid().to_byte_array() != candidate.genesis_transaction_id
        || tx2.txid() == tx1.txid()
        || tx2.input.is_empty()
        || tx2.input[0].previous_output
            != OutPoint::new(tx1.txid(), candidate.state_authority_source_output_index)
        || tx2
            .input
            .iter()
            .any(|input| input.has_issuance() || input.is_pegin())
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let authority_index = candidate.state_authority_source_output_index as usize;
    let state_index = candidate.genesis_state_output_index as usize;
    let authority = tx1
        .output
        .get(authority_index)
        .ok_or(DeploymentCandidateErrorV2::InvalidCandidate)?;
    let state = tx2
        .output
        .get(state_index)
        .ok_or(DeploymentCandidateErrorV2::InvalidCandidate)?;
    if explicit_output_amount(authority, expected_authority) != Some(1)
        || authority.nonce != Nonce::Null
        || !is_valid_p2tr(&authority.script_pubkey)
        || explicit_output_amount(state, expected_authority) != Some(1)
        || state.nonce != Nonce::Null
        || !is_valid_p2tr(&state.script_pubkey)
        || script_sha256(&state.script_pubkey) != expected_genesis_script
    {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let inventory_index = candidate.deployment.inventory_output_index as usize;
    let burn_index = candidate.deployment.reissuance_token_burn_output_index as usize;
    if authority_index == inventory_index || authority_index == burn_index {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    let mut authority_count = 0usize;
    for (index, output) in tx1.output.iter().enumerate() {
        if index != inventory_index
            && (output.asset.explicit().is_none()
                || output.value.explicit().is_none()
                || output.nonce != Nonce::Null)
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        if explicit_output_amount(output, expected_authority).is_some() {
            authority_count += 1;
            if index != authority_index || output.value.explicit() != Some(1) {
                return Err(DeploymentCandidateErrorV2::InvalidCandidate);
            }
        }
        if explicit_output_amount(output, expected_usdd).is_some()
            && output.value.explicit() != Some(0)
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
    }
    if authority_count != 1 {
        return Err(DeploymentCandidateErrorV2::InvalidCandidate);
    }
    for (index, output) in tx2.output.iter().enumerate() {
        if output.asset.explicit().is_none()
            || output.value.explicit().is_none()
            || output.nonce != Nonce::Null
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        if explicit_output_amount(output, expected_authority).is_some()
            && (index != state_index || output.value.explicit() != Some(1))
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
        if explicit_output_amount(output, expected_usdd).is_some()
            && output.value.explicit() != Some(0)
        {
            return Err(DeploymentCandidateErrorV2::InvalidCandidate);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
    use elements::{TxOutSecrets, Txid};
    use rand::thread_rng;

    const KEY_ONE: Hash32 = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];
    const KEY_TWO: Hash32 = [
        0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c,
        0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70,
        0x9e, 0xe5,
    ];
    const KEY_THREE: Hash32 = [
        0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52,
        0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0,
        0x36, 0xf9,
    ];
    const KEY_FOUR: Hash32 = [
        0xe4, 0x93, 0xdb, 0xf1, 0xc1, 0x0d, 0x80, 0xf3, 0x58, 0x1e, 0x49, 0x04, 0x93, 0x0b, 0x14,
        0x04, 0xcc, 0x6c, 0x13, 0x90, 0x0e, 0xe0, 0x75, 0x84, 0x74, 0xfa, 0x94, 0xab, 0xe8, 0xc4,
        0xcd, 0x13,
    ];

    fn p2tr(key: Hash32) -> Script {
        let mut bytes = vec![0x51, 0x20];
        bytes.extend_from_slice(&key);
        Script::from(bytes)
    }

    fn confidential_inventory(asset: Hash32, script: Script) -> TxOut {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let asset = AssetId::from_byte_array(asset);
        let abf = AssetBlindingFactor::from_slice(&[0x31; 32]).unwrap();
        let vbf = ValueBlindingFactor::from_slice(&[0x32; 32]).unwrap();
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = SecretKey::new(&mut rng);
        TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            script,
            receiver_public,
            ephemeral_secret,
            TxOutSecrets::new(asset, abf, BOND_FIXED_SUPPLY_ATOMS_V2, vbf),
            &[TxOutSecrets::new(
                asset,
                AssetBlindingFactor::zero(),
                BOND_FIXED_SUPPLY_ATOMS_V2,
                ValueBlindingFactor::zero(),
            )],
        )
        .unwrap()
    }

    fn valid_plan() -> FrozenBondDeploymentGenesisPlanV2 {
        let entropy = [0xa1; 32];
        let input = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0xa0; 32]), 7),
            ..TxIn::default()
        };
        let mut derived = input.clone();
        derived.asset_issuance.asset_entropy = entropy;
        derived.asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2);
        derived.asset_issuance.inflation_keys =
            Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2);
        let asset = derived.issuance_ids().0.into_inner().to_byte_array();
        let inventory_script = p2tr(KEY_ONE);
        let asset_id = AssetId::from_byte_array(asset);
        let inventory_abf = AssetBlindingFactor::from_slice(&[0x31; 32]).unwrap();
        let inventory_vbf = ValueBlindingFactor::from_slice(&[0x32; 32]).unwrap();
        let issuance_vbf = ValueBlindingFactor::last(
            &Secp256k1::new(),
            BOND_FIXED_SUPPLY_ATOMS_V2,
            AssetBlindingFactor::zero(),
            &[TxOutSecrets::new(
                asset_id,
                inventory_abf,
                BOND_FIXED_SUPPLY_ATOMS_V2,
                inventory_vbf,
            )
            .value_blind_inputs()],
            &[],
        );
        let mut issuance_vbf_bytes = [0; 32];
        issuance_vbf_bytes.copy_from_slice(issuance_vbf.into_inner().as_ref());
        FrozenBondDeploymentGenesisPlanV2 {
            issuance_input: input,
            issuance_contract_entropy: entropy,
            deployment_additional_inputs: vec![],
            deployment_additional_explicit_outputs: vec![],
            inventory_output: confidential_inventory(asset, inventory_script.clone()),
            inventory_asset_blinding_factor: [0x31; 32],
            inventory_value_blinding_factor: [0x32; 32],
            issuance_value_blinding_factor: issuance_vbf_bytes,
            issuance_blinding_secret: [0x33; 32],
            inventory_vault_script: inventory_script,
            redemption_queue_script: Script::from(vec![0x51, 0x42]),
            reissuance_token_burn_script: Script::from(vec![opcodes::all::OP_RETURN.into_u8()]),
            state_authority_asset_id: [0xb0; 32],
            state_authority_source_script: p2tr(KEY_TWO),
            genesis_state_script: p2tr(KEY_THREE),
            usdd_asset_id: [0xb1; 32],
            genesis_additional_inputs: vec![],
            genesis_additional_explicit_outputs: vec![],
        }
    }

    fn configuration_for(
        document: &FrozenBondDeploymentGenesisDocumentV2,
    ) -> FrozenConfigurationV2 {
        derive_physical_deployment_configuration_candidate_v2(
            document,
            crate::tests::frozen_configuration_fixture(),
        )
        .unwrap()
    }

    #[test]
    fn public_candidate_checks_genesis_linkage_and_version() {
        let plan = valid_plan();
        let mut candidate = compose_frozen_bond_deployment_genesis_v2(plan.clone()).unwrap();
        // Build a fresh public template; do not reuse confidential proof bytes.
        let mut template = decode_transaction(&candidate.deployment.transaction).unwrap();
        template.input[0] = plan.issuance_input.clone();
        template.output[0] = TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array(candidate.frozen_asset.asset_id)),
            value: Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2),
            nonce: Nonce::Null,
            script_pubkey: plan.inventory_vault_script.clone(),
            witness: Default::default(),
        };
        let (deployment, verified) = ecx_elements_settlement::public_deployment::compose_public_bond_deployment(
            template, 0, 0, 1, plan.issuance_contract_entropy, &candidate.frozen_asset,
        ).unwrap();
        candidate.deployment = deployment;
        candidate.verified_deployment = verified;
        let mut genesis = decode_transaction(&candidate.genesis_transaction).unwrap();
        genesis.input[0].previous_output = OutPoint::new(Txid::from_byte_array(verified.transaction_id), 2);
        candidate.genesis_transaction = encode::serialize(&genesis);
        candidate.genesis_transaction_id = genesis.txid().to_byte_array();
        let check = |c: &FrozenBondDeploymentGenesisCandidateV2| {
            verify_public_bond_deployment_genesis_candidate(c, plan.state_authority_asset_id,
                script_sha256(&plan.genesis_state_script), plan.usdd_asset_id)
        };
        check(&candidate).unwrap();
        let assembled = compose_public_bond_genesis_candidate(
            candidate.deployment.clone(), candidate.frozen_asset.clone(),
            plan.state_authority_asset_id, plan.usdd_asset_id,
            plan.genesis_state_script.clone(), vec![], vec![],
        ).unwrap();
        assert_eq!(assembled, candidate);
        let document = FrozenBondDeploymentGenesisDocumentV2::from_candidate(
            assembled.clone(), plan.state_authority_asset_id,
            script_sha256(&plan.genesis_state_script), plan.usdd_asset_id,
        ).unwrap();
        assert_eq!(document.schema, PUBLIC_DEPLOYMENT_CANDIDATE_SCHEMA_V3);
        document.verify().unwrap();
        let rebound_document = document.rebind_public_genesis_script(p2tr(KEY_FOUR)).unwrap();
        assert_eq!(rebound_document.deployment, document.deployment);
        assert_eq!(rebound_document.frozen_asset, document.frozen_asset);
        let mut restored = decode_transaction(&rebound_document.genesis_transaction).unwrap();
        restored.output[0].script_pubkey = plan.genesis_state_script.clone();
        assert_eq!(encode::serialize(&restored), document.genesis_transaction);
        assert_ne!(rebound_document.genesis_transaction_id, document.genesis_transaction_id);
        assert!(document.rebind_public_genesis_script(Script::new()).is_err());
        let mut signed_document = document.clone();
        signed_document.signed = true;
        assert!(signed_document.rebind_public_genesis_script(p2tr(KEY_FOUR)).is_err());
        let mut substituted = document.clone();
        substituted.schema = DEPLOYMENT_CANDIDATE_SCHEMA_V2.to_owned();
        assert!(substituted.verify().is_err());
        substituted = document.clone();
        substituted.deployment.version = BOND_DEPLOYMENT_VERSION;
        assert!(substituted.verify().is_err());
        let rebound = compose_public_bond_genesis_candidate(
            candidate.deployment.clone(), candidate.frozen_asset.clone(),
            plan.state_authority_asset_id, plan.usdd_asset_id,
            p2tr(KEY_FOUR), vec![], vec![],
        ).unwrap();
        assert_eq!(rebound.deployment, candidate.deployment);
        assert_eq!(rebound.verified_deployment, candidate.verified_deployment);
        assert_ne!(rebound.genesis_transaction_id, candidate.genesis_transaction_id);
        assert!(verify_frozen_bond_deployment_genesis_candidate_v2(&candidate,
            plan.state_authority_asset_id, script_sha256(&plan.genesis_state_script), plan.usdd_asset_id).is_err());
        genesis.input[0].previous_output.vout = 1;
        candidate.genesis_transaction = encode::serialize(&genesis);
        candidate.genesis_transaction_id = genesis.txid().to_byte_array();
        assert!(check(&candidate).is_err());
    }

    #[test]
    fn physical_candidate_is_deterministic_and_non_circular() {
        let plan = valid_plan();
        let first = compose_frozen_bond_deployment_genesis_v2(plan.clone()).unwrap();
        let second = compose_frozen_bond_deployment_genesis_v2(plan.clone()).unwrap();
        assert_eq!(first, second);
        let expected_script = script_sha256(&plan.genesis_state_script);
        verify_frozen_bond_deployment_genesis_candidate_v2(
            &first,
            plan.state_authority_asset_id,
            expected_script,
            plan.usdd_asset_id,
        )
        .unwrap();
        let tx1 = decode_transaction(&first.deployment.transaction).unwrap();
        let tx2 = decode_transaction(&first.genesis_transaction).unwrap();
        assert_eq!(tx2.input[0].previous_output, OutPoint::new(tx1.txid(), 2));
        assert_ne!(tx1.txid(), tx2.txid());

        let mut alternate = plan.clone();
        alternate.genesis_state_script = p2tr(KEY_FOUR);
        let alternate = compose_frozen_bond_deployment_genesis_v2(alternate).unwrap();
        assert_eq!(first.deployment, alternate.deployment);
        assert_eq!(
            first.verified_deployment.deployment_commitment,
            alternate.verified_deployment.deployment_commitment
        );
        assert_ne!(
            first.genesis_transaction_id,
            alternate.genesis_transaction_id
        );

        let rebound_plan =
            rebind_frozen_bond_deployment_genesis_plan_v2(plan, p2tr(KEY_FOUR)).unwrap();
        let rebound = compose_frozen_bond_deployment_genesis_v2(rebound_plan).unwrap();
        assert_eq!(first.deployment, rebound.deployment);
        assert_eq!(first.verified_deployment, rebound.verified_deployment);
        assert_ne!(first.genesis_transaction_id, rebound.genesis_transaction_id);
    }

    #[test]
    fn physical_candidate_rejects_substitution_and_unsafe_shapes() {
        let plan = valid_plan();
        let expected_script = script_sha256(&plan.genesis_state_script);
        let candidate = compose_frozen_bond_deployment_genesis_v2(plan.clone()).unwrap();
        let mut wrong_source = candidate.clone();
        let mut tx2 = decode_transaction(&wrong_source.genesis_transaction).unwrap();
        tx2.input[0].previous_output.vout = 1;
        wrong_source.genesis_transaction_id = tx2.txid().to_byte_array();
        wrong_source.genesis_transaction = encode::serialize(&tx2);
        assert!(verify_frozen_bond_deployment_genesis_candidate_v2(
            &wrong_source,
            plan.state_authority_asset_id,
            expected_script,
            plan.usdd_asset_id,
        )
        .is_err());

        let mut zero = plan.clone();
        zero.inventory_asset_blinding_factor = [0; 32];
        assert_eq!(
            compose_frozen_bond_deployment_genesis_v2(zero),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );
        let mut same_script = plan.clone();
        same_script.genesis_state_script = same_script.state_authority_source_script.clone();
        assert_eq!(
            compose_frozen_bond_deployment_genesis_v2(same_script),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );
        let mut confidential_extra = plan.clone();
        confidential_extra
            .deployment_additional_explicit_outputs
            .push(confidential_inventory([0xc0; 32], Script::new()));
        assert_eq!(
            compose_frozen_bond_deployment_genesis_v2(confidential_extra),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );
        let mut preissued = plan;
        preissued.issuance_input.asset_issuance.asset_entropy = [1; 32];
        preissued.issuance_input.asset_issuance.amount = Value::Explicit(1);
        assert_eq!(
            compose_frozen_bond_deployment_genesis_v2(preissued),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );

        let plan = valid_plan();
        let mut duplicate_input = plan.clone();
        duplicate_input
            .deployment_additional_inputs
            .push(plan.issuance_input.clone());
        assert_eq!(
            compose_frozen_bond_deployment_genesis_v2(duplicate_input),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );

        let first = compose_frozen_bond_deployment_genesis_v2(plan.clone()).unwrap();
        let mut spends_tx1_non_authority = plan;
        spends_tx1_non_authority
            .genesis_additional_inputs
            .push(TxIn {
                previous_output: OutPoint::new(
                    Txid::from_byte_array(first.verified_deployment.transaction_id),
                    0,
                ),
                ..TxIn::default()
            });
        assert_eq!(
            compose_frozen_bond_deployment_genesis_v2(spends_tx1_non_authority),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );
    }

    #[test]
    fn physical_candidate_document_round_trips_and_cannot_claim_activation() {
        let document = compose_frozen_bond_deployment_genesis_document_v2(valid_plan()).unwrap();
        assert!(!document.funded);
        assert!(!document.signed);
        assert!(!document.confirmed);
        assert!(!document.identities_frozen);
        assert!(!document.activated);
        let encoded = serde_json::to_vec(&document).unwrap();
        let decoded: FrozenBondDeploymentGenesisDocumentV2 =
            serde_json::from_slice(&encoded).unwrap();
        decoded.verify().unwrap();

        let mut false_claim = decoded.clone();
        false_claim.activated = true;
        assert_eq!(
            false_claim.verify(),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );
        let mut substituted_txid = decoded;
        substituted_txid.genesis_transaction_id[0] ^= 1;
        assert_eq!(
            substituted_txid.verify(),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );
    }

    #[test]
    fn physical_candidate_binds_every_deployment_identity_to_v18_configuration() {
        let candidate = compose_frozen_bond_deployment_genesis_document_v2(valid_plan()).unwrap();
        let configuration = configuration_for(&candidate);
        let bound =
            FrozenBondDeploymentConfigurationBindingDocumentV2::bind(candidate, configuration)
                .unwrap();
        assert_eq!(bound.configuration_hash, bound.configuration.digest());
        assert!(!bound.funded);
        assert!(!bound.signed);
        assert!(!bound.confirmed);
        assert!(!bound.identities_frozen);
        assert!(!bound.activated);
        let encoded = serde_json::to_vec(&bound).unwrap();
        let decoded: FrozenBondDeploymentConfigurationBindingDocumentV2 =
            serde_json::from_slice(&encoded).unwrap();
        decoded.verify().unwrap();

        let mut wrong_asset = decoded.clone();
        wrong_asset.configuration.bond_asset_id[0] ^= 1;
        wrong_asset.configuration_hash = wrong_asset.configuration.digest();
        assert!(wrong_asset.verify().is_err());
        let mut wrong_deployment = decoded.clone();
        wrong_deployment.configuration.bond_deployment_commitment[0] ^= 1;
        wrong_deployment.configuration_hash = wrong_deployment.configuration.digest();
        assert!(wrong_deployment.verify().is_err());
        let mut wrong_inventory = decoded.clone();
        wrong_inventory.configuration.bond_inventory_script_sha256[0] ^= 1;
        wrong_inventory.configuration_hash = wrong_inventory.configuration.digest();
        assert!(wrong_inventory.verify().is_err());
        let mut wrong_queue = decoded.clone();
        wrong_queue
            .configuration
            .bond_redemption_queue_script_sha256[0] ^= 1;
        wrong_queue.configuration_hash = wrong_queue.configuration.digest();
        assert!(wrong_queue.verify().is_err());
        let mut wrong_burn = decoded.clone();
        wrong_burn
            .configuration
            .destroyed_reissuance_token_script_sha256[0] ^= 1;
        wrong_burn.configuration_hash = wrong_burn.configuration.digest();
        assert!(wrong_burn.verify().is_err());
        let mut wrong_authority = decoded.clone();
        wrong_authority.configuration.base.state_authority_asset_id[0] ^= 1;
        wrong_authority.configuration_hash = wrong_authority.configuration.digest();
        assert!(wrong_authority.verify().is_err());
        let mut wrong_usdd = decoded.clone();
        wrong_usdd.configuration.base.usdd_asset_id[0] ^= 1;
        wrong_usdd.configuration_hash = wrong_usdd.configuration.digest();
        assert!(wrong_usdd.verify().is_err());
        let mut false_claim = decoded;
        false_claim.identities_frozen = true;
        assert_eq!(
            false_claim.verify(),
            Err(DeploymentCandidateErrorV2::InvalidCandidate)
        );
    }
}
