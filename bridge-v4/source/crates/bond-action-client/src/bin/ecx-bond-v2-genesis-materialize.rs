//! Materialize the exact finite-V18 genesis state and predecessor singleton.
//!
//! Unlike the historical activation candidate exporter, this tool derives the
//! forced/deposit/bond inboxes, matcher head, availability head, order-receipt
//! root, bond state, and funding state from one validated physical
//! `FrozenConfigurationV2`.  Its three-leaf Taproot topology is exactly
//! `Branch(transition, Branch(activation, finite_state_node))`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ecx_proof_core::{bond_public_state_root_v2, CovenantPublicStateV2};
use ecx_protocol_core::{ExchangeStateV2, FrozenConfigurationV2, Hash32};
use elements::hashes::{sha256, Hash};
use ecx_elements_settlement::finite_genesis::derive_finite_genesis_script;
use serde::{Deserialize, Serialize};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterializationSpec {
    initialization: Initialization,
    initialization_commitment_hex: String,
    state_creation_sidechain_height: u64,
    prior_parent_mtp: u64,
    genesis_mark_price_atoms: u64,
    genesis_availability_root_hex: String,
    order_receipts_genesis_root_hex: String,
    public_state_domain_sha256_hex: String,
    state_node_domain_sha256_hex: String,
    transition_journal_domain_sha256_hex: String,
    transition_cmr_hex: String,
    incremental_activation_cmr_hex: String,
    keyless_internal_key_hex: String,
}

/// Structural copy of the guest's V2 record; ancestry authentication is a
/// separate guest/native obligation, never established by this offline tool.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialization {
    version: u8,
    child_genesis: [u8;32],
    height: u32,
    block_internal: [u8;32],
    parent_mtp: u64,
}
impl Initialization {
    fn commitment(&self) -> Result<Hash32,String> {
        if self.version != 2 || self.height == 0 || self.parent_mtp == 0
            || self.parent_mtp > u32::MAX as u64 || self.child_genesis == [0;32]
            || self.block_internal == [0;32] {
            return Err("invalid V2 initialization record".into());
        }
        let tag=sha256::Hash::hash(b"ECX/alpha-genesis-initialization/v2").to_byte_array();
        let mut bytes=Vec::from(tag); bytes.extend_from_slice(&tag);
        bytes.push(self.version); bytes.extend_from_slice(&self.child_genesis);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.block_internal);
        bytes.extend_from_slice(&self.parent_mtp.to_be_bytes());
        Ok(sha256::Hash::hash(&bytes).to_byte_array())
    }
}

#[derive(Debug, Serialize)]
struct Materialization {
    schema: &'static str,
    initialization: Initialization,
    initialization_commitment_hex: String,
    configuration_hash_hex: String,
    state_creation_sidechain_height: u64,
    prior_parent_mtp: u64,
    private_state_root_hex: String,
    covenant_state_hash_hex: String,
    bond_state_root_hex: String,
    funding_state_root_hex: String,
    forced_inbox_root_hex: String,
    deposit_inbox_root_hex: String,
    bond_inbox_root_hex: String,
    bond_inbox_outcome_root_hex: String,
    state_node_hex: String,
    taproot_merkle_root_hex: String,
    state_script_hex: String,
    state_script_sha256_hex: String,
    transition_control_block_hex: String,
    incremental_activation_control_block_hex: String,
    transition_cmr_hex: String,
    incremental_activation_cmr_hex: String,
    finite_state: ExchangeStateV2,
    covenant_public_state: CovenantPublicStateV2,
}

fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{} must be a nonempty regular file no larger than {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn hash32(value: &str, label: &str) -> Result<Hash32, String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    let hash: Hash32 = bytes
        .try_into()
        .map_err(|_| format!("{label} must encode exactly 32 bytes"))?;
    if hash == [0; 32] {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(hash)
}

fn materialize(
    configuration: FrozenConfigurationV2,
    spec: MaterializationSpec,
) -> Result<Materialization, String> {
    configuration
        .validate()
        .map_err(|error| format!("configuration rejected: {error}"))?;
    if spec.state_creation_sidechain_height == 0
        || spec.prior_parent_mtp == 0
        || spec.genesis_mark_price_atoms == 0
    {
        return Err("genesis height, parent MTP, and mark price must be nonzero".to_owned());
    }

    let configuration_hash = configuration.digest();
    let initialization_commitment=spec.initialization.commitment()?;
    if initialization_commitment != hash32(&spec.initialization_commitment_hex,"initialization commitment")?
        || u64::from(spec.initialization.height) >= spec.state_creation_sidechain_height
        || spec.state_creation_sidechain_height > u32::MAX as u64
        || spec.initialization.parent_mtp > spec.prior_parent_mtp
        || spec.prior_parent_mtp > u32::MAX as u64 {
        return Err("initialization commitment or height/parent MTP order mismatch".into());
    }
    let availability_root = hash32(
        &spec.genesis_availability_root_hex,
        "genesis availability root",
    )?;
    let order_receipts_root = hash32(
        &spec.order_receipts_genesis_root_hex,
        "order receipts genesis root",
    )?;
    let public_state_domain = hash32(&spec.public_state_domain_sha256_hex, "public state domain")?;
    let state_node_domain = hash32(&spec.state_node_domain_sha256_hex, "state node domain")?;
    let journal_domain = hash32(
        &spec.transition_journal_domain_sha256_hex,
        "transition journal domain",
    )?;
    let transition_cmr = hash32(&spec.transition_cmr_hex, "transition CMR")?;
    let activation_cmr = hash32(
        &spec.incremental_activation_cmr_hex,
        "incremental activation CMR",
    )?;
    let internal_key_bytes = hash32(&spec.keyless_internal_key_hex, "keyless internal key")?;
    if transition_cmr == activation_cmr
        || public_state_domain == state_node_domain
        || public_state_domain == journal_domain
        || state_node_domain == journal_domain
    {
        return Err("state domains and covenant CMRs must be pairwise distinct".to_owned());
    }

    let finite_state = ecx_protocol_core::genesis_v2::derive_empty_genesis_v2(
        &configuration, u64::from(spec.initialization.height), spec.initialization.parent_mtp,
        spec.genesis_mark_price_atoms, order_receipts_root,
    )?;
    let bond_inbox_outcome_root = finite_state.bond_inbox_outcome_root;
    let bond_state_root = bond_public_state_root_v2(&finite_state.bond);
    let funding_state_root = finite_state.funding.root();
    let covenant_public_state = CovenantPublicStateV2::derive_empty_genesis(
        &configuration, u64::from(spec.initialization.height), spec.initialization.parent_mtp,
        spec.genesis_mark_price_atoms, order_receipts_root, availability_root,
    )?;
    let covenant_state_hash = covenant_public_state.state_hash(public_state_domain);
    let derived_script = derive_finite_genesis_script(
        covenant_state_hash, state_node_domain, transition_cmr, activation_cmr,
        internal_key_bytes,
    )?;
    let state_script = &derived_script.script;
    let state_script_sha256 = sha256::Hash::hash(state_script.as_bytes()).to_byte_array();

    Ok(Materialization {
        schema: "ECX_BOND_V2_FINITE_GENESIS_MATERIALIZATION_V2",
        initialization: spec.initialization,
        initialization_commitment_hex: hex::encode(initialization_commitment),
        configuration_hash_hex: hex::encode(configuration_hash),
        state_creation_sidechain_height: spec.state_creation_sidechain_height,
        prior_parent_mtp: spec.prior_parent_mtp,
        private_state_root_hex: hex::encode(finite_state.state_root()),
        covenant_state_hash_hex: hex::encode(covenant_state_hash),
        bond_state_root_hex: hex::encode(bond_state_root),
        funding_state_root_hex: hex::encode(funding_state_root),
        forced_inbox_root_hex: hex::encode(finite_state.base.forced_inbox.head_root),
        deposit_inbox_root_hex: hex::encode(finite_state.base.deposit_inbox.head_root),
        bond_inbox_root_hex: hex::encode(finite_state.bond_inbox.head_root),
        bond_inbox_outcome_root_hex: hex::encode(bond_inbox_outcome_root),
        state_node_hex: hex::encode(derived_script.state_node),
        taproot_merkle_root_hex: hex::encode(derived_script.merkle_root),
        state_script_hex: hex::encode(state_script.as_bytes()),
        state_script_sha256_hex: hex::encode(state_script_sha256),
        transition_control_block_hex: hex::encode(derived_script.transition_control),
        incremental_activation_control_block_hex: hex::encode(derived_script.activation_control),
        transition_cmr_hex: spec.transition_cmr_hex,
        incremental_activation_cmr_hex: spec.incremental_activation_cmr_hex,
        finite_state,
        covenant_public_state,
    })
}

fn run(configuration_path: &Path, spec_path: &Path, output: &Path) -> Result<(), String> {
    let configuration: FrozenConfigurationV2 =
        serde_json::from_slice(&read_regular(configuration_path)?)
            .map_err(|error| format!("invalid FrozenConfigurationV2 JSON: {error}"))?;
    let spec: MaterializationSpec = serde_json::from_slice(&read_regular(spec_path)?)
        .map_err(|error| format!("invalid genesis materialization specification: {error}"))?;
    let materialization = materialize(configuration, spec)?;
    let mut bytes = serde_json::to_vec_pretty(&materialization)
        .map_err(|error| format!("cannot encode genesis materialization: {error}"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("cannot create-new {}: {error}", output.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {}: {error}", output.display()))
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(configuration), Some(spec), Some(output), None) = (
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) else {
        eprintln!(
            "usage: ecx-bond-v2-genesis-materialize \
<frozen-configuration-v2.json> <materialization-spec.json> <create-new-output.json>"
        );
        std::process::exit(2);
    };
    if let Err(error) = run(&configuration, &spec, &output) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
pub(crate) fn materialize_test_json(
    configuration: FrozenConfigurationV2, spec: serde_json::Value,
) -> serde_json::Value {
    serde_json::to_value(materialize(configuration,
        serde_json::from_value(spec).expect("materializer test spec")).expect("materializer test output")).unwrap()
}

#[cfg(test)]
pub(crate) fn check_creation_independence(configuration: FrozenConfigurationV2) {
    // Reuse the library's validated fixture, not a claimed production profile.
    let initial = Initialization {
        version: 2, child_genesis: [1;32], height: 39,
        block_internal: [2;32], parent_mtp: 1_700_000_000,
    };
    // Independent hashlib tagged-SHA256 vector, shared with guest tests.
    assert_eq!(hex::encode(initial.commitment().unwrap()),
        "6665079f802e65cd66b1047b36bf906a95fe025e0eb6763561156a022a2a3d9c");
    let spec = |height, mtp| MaterializationSpec {
        initialization: initial.clone(),
        initialization_commitment_hex: hex::encode(initial.commitment().unwrap()),
        state_creation_sidechain_height: height, prior_parent_mtp: mtp,
        genesis_mark_price_atoms: 3_000_000_000,
        genesis_availability_root_hex: hex::encode([3;32]),
        order_receipts_genesis_root_hex: hex::encode([4;32]),
        public_state_domain_sha256_hex: hex::encode([5;32]),
        state_node_domain_sha256_hex: hex::encode([6;32]),
        transition_journal_domain_sha256_hex: hex::encode([7;32]),
        transition_cmr_hex: hex::encode([8;32]),
        incremental_activation_cmr_hex: hex::encode([9;32]),
        keyless_internal_key_hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
    };
    let first = materialize(configuration.clone(), spec(40, 1_700_000_000)).unwrap();
    // Same synthetic vector is checked by the native genesis derivation test.
    assert_eq!(first.configuration_hash_hex,
        "3df93f4bcb331b1ecf1784bcff2a7ac6e9835f4f1ca03f9c30f92e6ac7a67528");
    assert_eq!(first.private_state_root_hex,
        "2a3138979463a11b1a1f32eddf87f178def27eb245cd6e395543e40391ef61c7");
    assert_eq!(first.bond_state_root_hex,
        "42d03521b322730cb12768b4e9092962969aa07f262da8306f2cd5561862881e");
    assert_eq!(first.covenant_state_hash_hex,
        "f4c6825dab61df693292077a9d84b93e586f4693cbafbbe5bd7b2a7f7d88208f");
    assert_eq!(first.state_script_hex,
        "5120156fa2e4f41f964e2331da133c3517d68dd70f6e85c66e5764f769b17909733a");
    assert_eq!(first.funding_state_root_hex,
        "ae301bba06a2b3ccf1d4fd7c05a2f36fc476e4dd064c0bb30e1fdd857c7550c2");
    let later = materialize(configuration.clone(), spec(45, 1_700_000_100)).unwrap();
    let mut first = serde_json::to_value(first).unwrap();
    let mut later = serde_json::to_value(later).unwrap();
    for key in ["state_creation_sidechain_height", "prior_parent_mtp"] {
        assert_ne!(first[key], later[key]);
        first.as_object_mut().unwrap().remove(key);
        later.as_object_mut().unwrap().remove(key);
    }
    // Includes actual finite/public state, Taproot script and control blocks.
    assert_eq!(first, later);
    assert!(materialize(configuration.clone(), spec(39, 1_700_000_000)).is_err());
    assert!(materialize(configuration.clone(), spec(40, 1_699_999_999)).is_err());
    let mut changed = spec(40, 1_700_000_000);
    changed.initialization.block_internal[0] ^= 1;
    assert!(materialize(configuration, changed).is_err());
}

#[cfg(test)]
mod tests {
    #[test]
    fn source_freezes_the_three_branch_predecessor_topology() {
        // This guards the consensus-relevant builder depths independently of
        // any deployment fixture or release identity.
        let source = include_str!("../../../elements-settlement/src/finite_genesis.rs");
        assert!(source.contains("add_leaf_with_ver(1, transition_script"));
        assert!(source.contains("add_leaf_with_ver(2, activation_script"));
        assert!(source.contains("add_hidden(2"));
    }
}
