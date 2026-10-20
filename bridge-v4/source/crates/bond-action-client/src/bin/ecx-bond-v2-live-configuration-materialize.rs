//! Materialize one deployment-bound V18 configuration from authenticated
//! Truthcoin replay input and the exact physical/covenant deployment records.
//!
//! This closes the historical gap where an otherwise complete physical
//! deployment still depended on a hand-edited test configuration.  The source
//! authentication record is copied from the replay guest input, while every
//! Elements asset and covenant identity is independently cross-checked.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ecx_bond_action_client::FrozenBondDeploymentGenesisDocumentV2;
use ecx_protocol_core::{
    bond_inbox_redemption_staging_descriptor_commitment_v2,
    usdd_checkpoint_authority_configuration_hash, AvailabilityConfigV1,
    CentralMatcherConfigV1, FrozenConfigurationV1, FrozenConfigurationV2, HybridOracleConfigV1,
    RiskParams, TruthcoinAnchorDeploymentV1, TruthcoinAuthenticationConfigV1, UsddCheckpointConfigV1, XOnlyKey,
    AVAILABILITY_CUSTODIAN_COUNT, AVAILABILITY_RECOVERY_THRESHOLD, BOND_INBOX_INCLUSION_BLOCKS_V2,
    BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
    BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
    BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
    BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
    BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2, BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2,
    BOND_REDEMPTION_DELAY_PARENT_BLOCKS, BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2, ECX_USDD_MARKET,
    FORCED_INCLUSION_BLOCKS_V2, MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2,
    MAX_AVAILABILITY_WITNESS_BYTES, MAX_BOND_INBOX_BUNDLE_BYTES_V2,
    MAX_CONVERSION_LEG_PROOF_BYTES_V2, MAX_TRANSITION_ACTIONS, PRICE_SCALE,
    RECURSIVE_PROOF_MARKER_BYTES_V2, USDD_MAX_CHECKPOINT_AGE_SECONDS,
};
use ecx_truthcoin_replay::{verify_replay_structure, ReplayInputV1, ReviewedNativeBootstrapV1};
use ecx_witness_availability::{availability_scheme_hash, custody_receipt_codec_hash_v1};
use elements::AssetId;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct MatcherKeyDocument {
    version: u16,
    role: String,
    secret_key_hex: String,
    public_key_xonly: String,
}

#[derive(Debug, Deserialize)]
struct CompiledProgramIdentity {
    cmr: String,
}

#[derive(Debug, Deserialize)]
struct FiniteSimplicityManifest {
    programs: BTreeMap<String, CompiledProgramIdentity>,
}

#[derive(Debug, Deserialize)]
struct FixedCovenantIdentity {
    cmr_hex: String,
    script_sha256_hex: String,
}

#[derive(Debug, Deserialize)]
struct FixedCovenantsDocument {
    programs: BTreeMap<String, FixedCovenantIdentity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    #[serde(default)]
    reviewed_bootstrap: Option<BootstrapExpectations>,
    chain_id_hex: String,
    policy_asset_id: String,
    truthcoin_anchor_authority_asset_id: String,
    truthcoin_anchor_script_tree_configuration_hash_hex: String,
    expected_truthcoin_program_id_hex: String,
    usdd_ethereum_light_client_configuration_hash_hex: String,
    usdd_checkpoint_authority_asset_id: String,
    usdd_checkpoint_authority_amount: u64,
    usdd_checkpoint_authority_script_tree_configuration_hash_hex: String,
    custodian_registry_hash_hex: String,
    matcher_genesis_receipt_hash_hex: String,
    forced_action_domain_hex: String,
    deposit_inbox_domain_hex: String,
    bond_inbox_domain_hex: String,
    oracle_schedule_origin_mtp: u64,
    oracle_epoch_length_seconds: u64,
    oracle_maximum_anchor_age_seconds: u64,
    oracle_maximum_snapshot_age_seconds: u64,
    oracle_minimum_lmsr_b: u64,
    oracle_minimum_sample_count: u32,
    oracle_base_lmsr_weight_ppm: u32,
    oracle_maximum_lmsr_weight_ppm: u32,
    oracle_initial_anchor_band_bps: u32,
    oracle_maximum_anchor_band_bps: u32,
    oracle_risk_haircut_bps: u32,
    oracle_boundary_guard_ppb: u32,
    oracle_maximum_unanchored_deviation_bps: u32,
    maximum_conversion_age_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapExpectations {
    commitment_hex: String,
    authentication_hash_hex: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    settlement_verified: bool,
    proof_ready: bool,
    reviewed_bootstrap_commitment_hex: Option<String>,
    schema: &'static str,
    configuration_hash_hex: String,
    chain_id_hex: String,
    truthcoin_authentication_hash_hex: String,
    truthcoin_program_id_hex: String,
    matcher_public_key_xonly_hex: String,
    bond_asset_id_consensus_hex: String,
    policy_asset_id_consensus_hex: String,
    usdd_asset_id_consensus_hex: String,
    state_authority_asset_id_consensus_hex: String,
    direct_native_truthcoin_price: bool,
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{label} {} must be a nonempty regular file no larger than {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {label} {}: {error}", path.display()))
}

fn parse_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, String> {
    serde_json::from_slice(&read_regular(path, label)?)
        .map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn hash32(value: &str, label: &str) -> Result<[u8; 32], String> {
    let decoded = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    let value: [u8; 32] = decoded
        .try_into()
        .map_err(|_| format!("{label} must encode exactly 32 bytes"))?;
    if value == [0; 32] {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(value)
}

fn displayed_asset(value: &str, label: &str) -> Result<[u8; 32], String> {
    AssetId::from_str(value)
        .map(|asset| asset.into_inner().to_byte_array())
        .map_err(|error| format!("invalid {label}: {error}"))
}

fn matcher_public_key(document: &MatcherKeyDocument) -> Result<[u8; 32], String> {
    if document.version != 1
        || document.role != "central_single_signer"
        || document.secret_key_hex.len() != 64
    {
        return Err("matcher key document has an unsupported identity schema".to_owned());
    }
    let secret = SecretKey::from_slice(
        &hex::decode(&document.secret_key_hex)
            .map_err(|error| format!("invalid matcher secret key: {error}"))?,
    )
    .map_err(|error| format!("invalid matcher secret key: {error}"))?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
    let bytes = public.serialize();
    if hex::encode(bytes) != document.public_key_xonly {
        return Err("matcher public key does not correspond to the protected secret".to_owned());
    }
    Ok(bytes)
}

fn derive_usdd_authority(asset: [u8; 32], amount: u64, script: [u8; 32], policy: [u8; 32]) -> Result<[u8; 32], String> {
    if asset == [0; 32] || asset == policy || amount == 0 || script == [0; 32] {
        return Err("USDD checkpoint authority requires a nonzero distinct asset, amount and script".to_owned());
    }
    Ok(usdd_checkpoint_authority_configuration_hash(asset, amount, script, policy))
}

fn program<'a>(
    manifest: &'a FiniteSimplicityManifest,
    name: &str,
) -> Result<&'a CompiledProgramIdentity, String> {
    manifest
        .programs
        .get(name)
        .ok_or_else(|| format!("finite Simplicity manifest is missing {name}"))
}

fn covenant<'a>(
    document: &'a FixedCovenantsDocument,
    name: &str,
) -> Result<&'a FixedCovenantIdentity, String> {
    document
        .programs
        .get(name)
        .ok_or_else(|| format!("fixed-covenant materialization is missing {name}"))
}

fn create_new_json<T: Serialize>(path: &Path, value: &T, label: &str) -> Result<(), String> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot encode {label}: {error}"))?;
    encoded.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("cannot create-new {label} {}: {error}", path.display()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {label} {}: {error}", path.display()))
}

fn materialize(
    candidate: FrozenBondDeploymentGenesisDocumentV2,
    replay: ReplayInputV1,
    key: MatcherKeyDocument,
    finite: FiniteSimplicityManifest,
    fixed: FixedCovenantsDocument,
    spec: Spec,
    bootstrap: Option<ReviewedNativeBootstrapV1>,
) -> Result<(FrozenConfigurationV2, Summary), String> {
    candidate
        .verify()
        .map_err(|error| format!("physical deployment candidate rejected: {error}"))?;
    let bootstrap_pins = bootstrap_expectations(spec.reviewed_bootstrap.as_ref(), bootstrap.is_some())?;
    if let Some((pin, authentication)) = bootstrap_pins {
        // Configuration binds source policy, not a settled observation. Import
        // and authenticate the reviewed starting state without requiring future
        // settlement. The witness/proof route still executes production replay.
        bootstrap.as_ref().expect("paired bootstrap checked")
            .import(pin, authentication)
            .map_err(|error| format!("Truthcoin bootstrap import rejected: {error}"))?;
        require_authentication_pin(replay.authentication.digest(), authentication)?;
    } else {
        verify_replay_structure(&replay)
            .map_err(|error| format!("Truthcoin replay input rejected: {error}"))?;
    }
    construct_configuration(candidate, replay.authentication, key, finite, fixed, spec, bootstrap_pins)
}

// Deterministic configuration construction consumes source identity/policy, not
// a market outcome or replay transactions. Keep replay qualification in the
// witness/proof workflow: separating these responsibilities is not a broadcast gate
// bypass, and this private helper alone establishes no source qualification.
fn construct_configuration(
    candidate: FrozenBondDeploymentGenesisDocumentV2,
    authentication: TruthcoinAuthenticationConfigV1,
    key: MatcherKeyDocument,
    finite: FiniteSimplicityManifest,
    fixed: FixedCovenantsDocument,
    spec: Spec,
    bootstrap_pins: Option<([u8; 32], [u8; 32])>,
) -> Result<(FrozenConfigurationV2, Summary), String> {
    candidate.verify()
        .map_err(|error| format!("physical deployment candidate rejected: {error}"))?;
    authentication
        .validate()
        .map_err(|error| format!("Truthcoin replay authentication rejected: {error}"))?;

    let expected_truthcoin_program = hash32(
        &spec.expected_truthcoin_program_id_hex,
        "expected Truthcoin replay program id",
    )?;
    if authentication.source_proof_program_id != expected_truthcoin_program {
        return Err("Truthcoin replay input uses a different SP1 program id".to_owned());
    }

    let inventory = covenant(&fixed, "bond_inventory")?;
    let redemption = covenant(&fixed, "bond_redemption_queue")?;
    let collateral = covenant(&fixed, "collateral_vault")?;
    let insurance = covenant(&fixed, "insurance_reserve")?;
    if hash32(&inventory.script_sha256_hex, "inventory script hash")?
        != candidate.frozen_asset.inventory_vault_script_sha256
        || hash32(
            &redemption.script_sha256_hex,
            "redemption queue script hash",
        )? != candidate.frozen_asset.redemption_queue_script_sha256
        || hash32(&inventory.cmr_hex, "inventory CMR")?
            != hash32(
                &program(&finite, "bond_inventory_v2")?.cmr,
                "finite inventory CMR",
            )?
        || hash32(&redemption.cmr_hex, "redemption CMR")?
            != hash32(
                &program(&finite, "bond_redemption_queue_v2")?.cmr,
                "finite redemption CMR",
            )?
    {
        return Err("physical candidate and finite covenant materialization disagree".to_owned());
    }

    let process_cmr = hash32(
        &program(&finite, "bond_inbox_staging_process_v2")?.cmr,
        "staging process CMR",
    )?;
    let refund_cmr = hash32(
        &program(&finite, "bond_inbox_staging_refund_v2")?.cmr,
        "staging refund CMR",
    )?;
    let staging_template = bond_inbox_redemption_staging_descriptor_commitment_v2(
        BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
        BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
        BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
        process_cmr,
        refund_cmr,
    )
    .map_err(|error| format!("cannot derive staging descriptor: {error}"))?;

    let policy = displayed_asset(&spec.policy_asset_id, "policy asset id")?;
    let usdd_authority_asset = displayed_asset(
        &spec.usdd_checkpoint_authority_asset_id,
        "USDD checkpoint authority asset id",
    )?;
    let usdd_authority_configuration = derive_usdd_authority(
        usdd_authority_asset,
        spec.usdd_checkpoint_authority_amount,
        hash32(
            &spec.usdd_checkpoint_authority_script_tree_configuration_hash_hex,
            "USDD checkpoint authority script-tree configuration",
        )?,
        policy,
    )?;
    let matcher_public = matcher_public_key(&key)?;
    let chain_id = hash32(&spec.chain_id_hex, "chain id")?;
    let configuration = FrozenConfigurationV2 {
        version: FrozenConfigurationV2::DIRECT_PRICE_VERSION,
        base: FrozenConfigurationV1 {
            version: FrozenConfigurationV1::VERSION,
            chain_id,
            market: ECX_USDD_MARKET,
            ecx_asset_id: policy,
            usdd_asset_id: candidate.expected_usdd_asset_id,
            policy_asset_id: policy,
            state_authority_asset_id: candidate.expected_state_authority_asset_id,
            usdd_checkpoint: UsddCheckpointConfigV1 {
                version: UsddCheckpointConfigV1::VERSION,
                ethereum_light_client_configuration_hash: hash32(
                    &spec.usdd_ethereum_light_client_configuration_hash_hex,
                    "USDD Ethereum light-client configuration",
                )?,
                authority_configuration_hash: usdd_authority_configuration,
                maximum_checkpoint_age_seconds: USDD_MAX_CHECKPOINT_AGE_SECONDS,
            },
            risk: RiskParams::default(),
            availability: AvailabilityConfigV1 {
                version: AvailabilityConfigV1::VERSION,
                scheme_hash: availability_scheme_hash(),
                custodian_registry_hash: hash32(
                    &spec.custodian_registry_hash_hex,
                    "custodian registry",
                )?,
                recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
                custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
                maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
            },
            truthcoin_authentication: authentication.clone(),
            truthcoin_anchor_deployment: TruthcoinAnchorDeploymentV1 {
                version: TruthcoinAnchorDeploymentV1::VERSION,
                authority_asset_id: displayed_asset(
                    &spec.truthcoin_anchor_authority_asset_id,
                    "Truthcoin anchor authority asset id",
                )?,
                authority_amount: 1,
                script_tree_configuration_hash: hash32(
                    &spec.truthcoin_anchor_script_tree_configuration_hash_hex,
                    "Truthcoin anchor script-tree configuration",
                )?,
            },
            oracle: HybridOracleConfigV1 {
                version: HybridOracleConfigV1::VERSION,
                truthcoin_chain_id: authentication.truthcoin_chain_id,
                truthcoin_branch_id: authentication.truthcoin_branch_id,
                btc_usd_template_hash: authentication.btc_usd_template_hash,
                lmsr_math_commitment: authentication.lmsr_math_commitment,
                schedule_origin_mtp: spec.oracle_schedule_origin_mtp,
                epoch_length_seconds: spec.oracle_epoch_length_seconds,
                minimum_source_confirmations: authentication.minimum_bitcoin_confirmations,
                maximum_anchor_age_seconds: spec.oracle_maximum_anchor_age_seconds,
                maximum_snapshot_age_seconds: spec.oracle_maximum_snapshot_age_seconds,
                minimum_lmsr_b: spec.oracle_minimum_lmsr_b,
                minimum_sample_count: spec.oracle_minimum_sample_count,
                base_lmsr_weight_ppm: spec.oracle_base_lmsr_weight_ppm,
                maximum_lmsr_weight_ppm: spec.oracle_maximum_lmsr_weight_ppm,
                initial_anchor_band_bps: spec.oracle_initial_anchor_band_bps,
                maximum_anchor_band_bps: spec.oracle_maximum_anchor_band_bps,
                risk_haircut_bps: spec.oracle_risk_haircut_bps,
                boundary_guard_ppb: spec.oracle_boundary_guard_ppb,
                maximum_unanchored_deviation_bps: spec.oracle_maximum_unanchored_deviation_bps,
                ecx_satoshis_per_coin: PRICE_SCALE,
                usdd_usd_price_units: PRICE_SCALE,
            },
            matcher: CentralMatcherConfigV1 {
                version: CentralMatcherConfigV1::VERSION,
                key_epoch: 0,
                signer: XOnlyKey(matcher_public),
                genesis_sequence: 0,
                genesis_receipt_hash: hash32(
                    &spec.matcher_genesis_receipt_hash_hex,
                    "matcher genesis receipt",
                )?,
                forced_inclusion_blocks: FORCED_INCLUSION_BLOCKS_V2,
            },
            forced_action_domain: hash32(&spec.forced_action_domain_hex, "forced-action domain")?,
            deposit_inbox_domain: hash32(&spec.deposit_inbox_domain_hex, "deposit-inbox domain")?,
            collateral_vault_script_sha256: hash32(
                &collateral.script_sha256_hex,
                "collateral-vault script hash",
            )?,
            maximum_transition_actions: MAX_TRANSITION_ACTIONS,
        },
        collateral_vault_covenant_cmr: hash32(&collateral.cmr_hex, "collateral-vault CMR")?,
        bond_asset_id: candidate.verified_deployment.bond_asset_id,
        bond_deployment_commitment: candidate.verified_deployment.deployment_commitment,
        bond_inventory_script_sha256: candidate.frozen_asset.inventory_vault_script_sha256,
        bond_redemption_queue_script_sha256: candidate.frozen_asset.redemption_queue_script_sha256,
        bond_inbox_redemption_staging_template_commitment: staging_template,
        bond_inbox_redemption_staging_renderer_domain:
            BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
        bond_inbox_redemption_staging_internal_key:
            BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
        bond_inbox_redemption_staging_tapleaf_version:
            BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
        bond_inbox_redemption_staging_process_cmr: process_cmr,
        bond_inbox_redemption_staging_refund_cmr: refund_cmr,
        bond_inbox_refund_minimum_parent_blocks: BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2,
        insurance_reserve_script_sha256: hash32(
            &insurance.script_sha256_hex,
            "insurance-reserve script hash",
        )?,
        insurance_reserve_covenant_cmr: hash32(&insurance.cmr_hex, "insurance-reserve CMR")?,
        destroyed_reissuance_token_script_sha256: candidate
            .frozen_asset
            .reissuance_token_burn_script_sha256,
        bond_inbox_domain: hash32(&spec.bond_inbox_domain_hex, "bond-inbox domain")?,
        bond_inbox_custody_receipt_codec_hash: custody_receipt_codec_hash_v1(),
        bond_inbox_inclusion_blocks: BOND_INBOX_INCLUSION_BLOCKS_V2,
        bond_inbox_max_bundle_bytes: MAX_BOND_INBOX_BUNDLE_BYTES_V2,
        bond_inbox_max_entries_per_sidechain_block: BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
        bond_inbox_max_unique_source_witness_bytes_per_sidechain_block:
            BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
        bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block:
            BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
        bond_inbox_max_pending_entries_per_transition:
            BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
        bond_inbox_max_consumed_entries_per_transition:
            BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
        bond_redemption_max_queue_entries: BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2,
        matcher_execution_inclusion_parent_blocks: MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2,
        // Version 6 reserves these exact wire slots as canonical absence.
        // Ethereum USDT custody remains bound separately in the base USDD
        // checkpoint configuration; these are not redemption credentials.
        ecx_btc_conversion_program_id: [0; 32],
        usdd_usd_conversion_program_id: [0; 32],
        ecx_btc_redemption_covenant_commitment: [0; 32],
        ecx_btc_source_checkpoint_commitment: [0; 32],
        usdd_usd_redemption_covenant_commitment: [0; 32],
        usdd_usd_source_checkpoint_commitment: [0; 32],
        maximum_conversion_age_seconds: spec.maximum_conversion_age_seconds,
        maximum_conversion_proof_bytes: MAX_CONVERSION_LEG_PROOF_BYTES_V2,
        recursive_proof_marker_bytes: RECURSIVE_PROOF_MARKER_BYTES_V2,
        fixed_supply_atoms: candidate.verified_deployment.fixed_supply_atoms,
        redemption_delay_parent_blocks: BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
    };
    configuration
        .validate()
        .map_err(|error| format!("live V18 configuration rejected: {error}"))?;
    if !configuration.base.uses_direct_native_truthcoin_price() {
        return Err(
            "live V18 configuration did not select the direct-native Truthcoin lane".to_owned(),
        );
    }
    let summary = Summary {
        settlement_verified: false,
        proof_ready: false,
        schema: "ECX_BOND_V2_LIVE_CONFIGURATION_MATERIALIZATION_V1",
        configuration_hash_hex: hex::encode(configuration.digest()),
        chain_id_hex: hex::encode(chain_id),
        truthcoin_authentication_hash_hex: hex::encode(
            configuration.base.truthcoin_authentication.digest(),
        ),
        truthcoin_program_id_hex: hex::encode(expected_truthcoin_program),
        matcher_public_key_xonly_hex: hex::encode(matcher_public),
        bond_asset_id_consensus_hex: hex::encode(configuration.bond_asset_id),
        policy_asset_id_consensus_hex: hex::encode(policy),
        usdd_asset_id_consensus_hex: hex::encode(configuration.base.usdd_asset_id),
        state_authority_asset_id_consensus_hex: hex::encode(
            configuration.base.state_authority_asset_id,
        ),
        direct_native_truthcoin_price: true,
        reviewed_bootstrap_commitment_hex: bootstrap_pins.map(|(pin, _)| hex::encode(pin)),
    };
    Ok((configuration, summary))
}

fn require_authentication_pin(actual: [u8; 32], expected: [u8; 32]) -> Result<(), String> {
    if expected == [0; 32] || actual != expected {
        return Err("Truthcoin authentication does not match reviewed bootstrap pin".into());
    }
    Ok(())
}

fn bootstrap_expectations(expected: Option<&BootstrapExpectations>, supplied: bool) -> Result<Option<([u8; 32], [u8; 32])>, String> {
    match (expected, supplied) {
        (None, false) => Ok(None),
        (Some(expected), true) => {
            if !cfg!(feature = "truthcoin-alpha-one-day-period") {
                return Err("reviewed bootstrap requires the Alpha one-day feature".into());
            }
            Ok(Some((hash32(&expected.commitment_hex, "reviewed bootstrap commitment")?,
                     hash32(&expected.authentication_hash_hex, "expected authentication hash")?)))
        }
        _ => Err("bootstrap document and independent specification pins must be supplied together".into()),
    }
}

fn run(paths: &[PathBuf]) -> Result<(), String> {
    if paths.len() != 8 && paths.len() != 9 { return Err("internal argument-count error".into()); }
    let bootstrap = paths.get(8).map(|path| parse_json(path, "reviewed bootstrap")).transpose()?;
    let [candidate, replay, key, finite, fixed, spec, output, summary] = &paths[..8] else {
        return Err("internal argument-count error".to_owned());
    };
    if output.exists() || summary.exists() {
        return Err("refusing to overwrite a live configuration output".to_owned());
    }
    let (configuration, summary_value) = materialize(
        parse_json(candidate, "physical deployment candidate")?,
        parse_json(replay, "Truthcoin replay input")?,
        parse_json(key, "matcher key")?,
        parse_json(finite, "finite Simplicity manifest")?,
        parse_json(fixed, "fixed-covenant materialization")?,
        parse_json(spec, "live configuration specification")?,
        bootstrap,
    )?;
    create_new_json(output, &configuration, "live V18 configuration")?;
    create_new_json(summary, &summary_value, "live V18 configuration summary")
}

fn main() {
    let paths: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if paths.len() != 8 && paths.len() != 9 {
        eprintln!("Optional ninth argument: <reviewed-bootstrap.json>; requires spec.reviewed_bootstrap commitment_hex/authentication_hash_hex and the Alpha feature.");
        eprintln!(
            "usage: ecx-bond-v2-live-configuration-materialize \\\n+<candidate.json> <truthcoin-replay-input.json> <matcher-key.json> \\\n+<finite-simplicity-manifest.json> <fixed-covenants.json> <spec.json> \\\n+<create-new-configuration.json> <create-new-summary.json>"
        );
        std::process::exit(2);
    }
    if let Err(error) = run(&paths) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_preparation_preserves_authentication_pin() {
        assert!(require_authentication_pin([1; 32], [1; 32]).is_ok());
        assert!(require_authentication_pin([2; 32], [1; 32]).is_err());
        assert!(require_authentication_pin([0; 32], [0; 32]).is_err());
    }

    #[test]
    fn bootstrap_route_requires_paired_nonzero_external_pins() {
        let pins = BootstrapExpectations { commitment_hex: "01".repeat(32), authentication_hash_hex: "02".repeat(32) };
        assert!(bootstrap_expectations(None, false).unwrap().is_none());
        assert!(bootstrap_expectations(None, true).is_err());
        assert!(bootstrap_expectations(Some(&pins), false).is_err());
        let result = bootstrap_expectations(Some(&pins), true);
        if cfg!(feature = "truthcoin-alpha-one-day-period") {
            assert_eq!(result.unwrap(), Some(([1;32], [2;32])));
        } else { assert!(result.is_err()); }
        let zero = BootstrapExpectations { commitment_hex: "00".repeat(32), authentication_hash_hex: pins.authentication_hash_hex };
        assert!(bootstrap_expectations(Some(&zero), true).is_err());
    }

    #[test]
    fn authority_commitment_binds_every_input_and_rejects_invalid_roles() {
        let expected = derive_usdd_authority([1; 32], 7, [2; 32], [3; 32]).unwrap();
        let mut bytes = vec![1; 32];
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&[3; 32]);
        assert_eq!(expected, ecx_protocol_core::tagged_hash("ECX/usdd-checkpoint-authority/v1", &bytes));
        for changed in [
            derive_usdd_authority([4; 32], 7, [2; 32], [3; 32]),
            derive_usdd_authority([1; 32], 8, [2; 32], [3; 32]),
            derive_usdd_authority([1; 32], 7, [4; 32], [3; 32]),
            derive_usdd_authority([1; 32], 7, [2; 32], [4; 32]),
        ] { assert_ne!(expected, changed.unwrap()); }
        assert!(derive_usdd_authority([0; 32], 7, [2; 32], [3; 32]).is_err());
        assert!(derive_usdd_authority([3; 32], 7, [2; 32], [3; 32]).is_err());
        assert!(derive_usdd_authority([1; 32], 0, [2; 32], [3; 32]).is_err());
        assert!(derive_usdd_authority([1; 32], 7, [0; 32], [3; 32]).is_err());
    }

    #[test]
    fn displayed_policy_asset_is_converted_to_consensus_order() {
        assert_eq!(
            hex::encode(
                displayed_asset(
                    "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
                    "test asset",
                )
                .unwrap()
            ),
            "230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2"
        );
    }
}
