//! Apply the physical-chain and compiled-covenant identities to a complete
//! V18 configuration template, then validate and persist the exact result.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ecx_protocol_core::{
    bond_inbox_redemption_staging_descriptor_commitment_v2, FrozenConfigurationV2,
    BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
    BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
    BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
};
use elements::AssetId;
use serde::{Deserialize, Serialize};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlay {
    chain_id_hex: String,
    ecx_asset_id: String,
    usdd_asset_id: String,
    policy_asset_id: String,
    state_authority_asset_id: String,
    collateral_vault_covenant_cmr_hex: String,
    collateral_vault_script_sha256_hex: String,
    insurance_reserve_covenant_cmr_hex: String,
    insurance_reserve_script_sha256_hex: String,
    staging_process_cmr_hex: String,
    staging_refund_cmr_hex: String,
    ecx_btc_conversion_program_id_hex: String,
    usdd_usd_conversion_program_id_hex: String,
    ecx_btc_redemption_covenant_commitment_hex: String,
    ecx_btc_source_checkpoint_commitment_hex: String,
    usdd_usd_redemption_covenant_commitment_hex: String,
    usdd_usd_source_checkpoint_commitment_hex: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    schema: &'static str,
    configuration_hash_hex: String,
    chain_id_hex: String,
    ecx_asset_id_consensus_hex: String,
    usdd_asset_id_consensus_hex: String,
    policy_asset_id_consensus_hex: String,
    state_authority_asset_id_consensus_hex: String,
    staging_template_commitment_hex: String,
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

fn hash32(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{label} must encode exactly 32 bytes"))?;
    if hash == [0; 32] {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(hash)
}

fn asset(value: &str, label: &str) -> Result<[u8; 32], String> {
    AssetId::from_str(value)
        .map(|asset| asset.into_inner().to_byte_array())
        .map_err(|error| format!("invalid {label}: {error}"))
}

fn create_new_json<T: Serialize>(path: &Path, value: &T, label: &str) -> Result<(), String> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot encode {label}: {error}"))?;
    encoded.push(b'\n');
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("cannot create-new {label} {}: {error}", path.display()))?;
    output
        .write_all(&encoded)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("cannot persist {label} {}: {error}", path.display()))
}

fn materialize(
    mut configuration: FrozenConfigurationV2,
    overlay: Overlay,
) -> Result<(FrozenConfigurationV2, Summary), String> {
    configuration.base.chain_id = hash32(&overlay.chain_id_hex, "chain id")?;
    configuration.base.ecx_asset_id = asset(&overlay.ecx_asset_id, "ECX asset id")?;
    configuration.base.usdd_asset_id = asset(&overlay.usdd_asset_id, "USDD asset id")?;
    configuration.base.policy_asset_id = asset(&overlay.policy_asset_id, "policy asset id")?;
    configuration.base.state_authority_asset_id = asset(
        &overlay.state_authority_asset_id,
        "state-authority asset id",
    )?;
    configuration.collateral_vault_covenant_cmr = hash32(
        &overlay.collateral_vault_covenant_cmr_hex,
        "collateral-vault covenant CMR",
    )?;
    configuration.base.collateral_vault_script_sha256 = hash32(
        &overlay.collateral_vault_script_sha256_hex,
        "collateral-vault script hash",
    )?;
    configuration.insurance_reserve_covenant_cmr = hash32(
        &overlay.insurance_reserve_covenant_cmr_hex,
        "insurance-reserve covenant CMR",
    )?;
    configuration.insurance_reserve_script_sha256 = hash32(
        &overlay.insurance_reserve_script_sha256_hex,
        "insurance-reserve script hash",
    )?;
    configuration.bond_inbox_redemption_staging_renderer_domain =
        BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2;
    configuration.bond_inbox_redemption_staging_internal_key =
        BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2;
    configuration.bond_inbox_redemption_staging_tapleaf_version =
        BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2;
    configuration.bond_inbox_redemption_staging_process_cmr =
        hash32(&overlay.staging_process_cmr_hex, "staging process CMR")?;
    configuration.bond_inbox_redemption_staging_refund_cmr =
        hash32(&overlay.staging_refund_cmr_hex, "staging refund CMR")?;
    configuration.bond_inbox_redemption_staging_template_commitment =
        bond_inbox_redemption_staging_descriptor_commitment_v2(
            configuration.bond_inbox_redemption_staging_renderer_domain,
            configuration.bond_inbox_redemption_staging_tapleaf_version,
            configuration.bond_inbox_redemption_staging_internal_key,
            configuration.bond_inbox_redemption_staging_process_cmr,
            configuration.bond_inbox_redemption_staging_refund_cmr,
        )
        .map_err(|error| format!("cannot derive staging descriptor commitment: {error}"))?;
    configuration.ecx_btc_conversion_program_id = hash32(
        &overlay.ecx_btc_conversion_program_id_hex,
        "ECX/BTC conversion program id",
    )?;
    configuration.usdd_usd_conversion_program_id = hash32(
        &overlay.usdd_usd_conversion_program_id_hex,
        "USDD/USD conversion program id",
    )?;
    configuration.ecx_btc_redemption_covenant_commitment = hash32(
        &overlay.ecx_btc_redemption_covenant_commitment_hex,
        "ECX/BTC redemption covenant commitment",
    )?;
    configuration.ecx_btc_source_checkpoint_commitment = hash32(
        &overlay.ecx_btc_source_checkpoint_commitment_hex,
        "ECX/BTC source checkpoint commitment",
    )?;
    configuration.usdd_usd_redemption_covenant_commitment = hash32(
        &overlay.usdd_usd_redemption_covenant_commitment_hex,
        "USDD/USD redemption covenant commitment",
    )?;
    configuration.usdd_usd_source_checkpoint_commitment = hash32(
        &overlay.usdd_usd_source_checkpoint_commitment_hex,
        "USDD/USD source checkpoint commitment",
    )?;
    configuration
        .validate()
        .map_err(|error| format!("materialized V18 template rejected: {error}"))?;
    let summary = Summary {
        schema: "ECX_BOND_V2_FROZEN_TEMPLATE_MATERIALIZATION_V1",
        configuration_hash_hex: hex::encode(configuration.digest()),
        chain_id_hex: hex::encode(configuration.base.chain_id),
        ecx_asset_id_consensus_hex: hex::encode(configuration.base.ecx_asset_id),
        usdd_asset_id_consensus_hex: hex::encode(configuration.base.usdd_asset_id),
        policy_asset_id_consensus_hex: hex::encode(configuration.base.policy_asset_id),
        state_authority_asset_id_consensus_hex: hex::encode(
            configuration.base.state_authority_asset_id,
        ),
        staging_template_commitment_hex: hex::encode(
            configuration.bond_inbox_redemption_staging_template_commitment,
        ),
    };
    Ok((configuration, summary))
}

fn run(template: &Path, overlay: &Path, output: &Path, summary: &Path) -> Result<(), String> {
    if output.exists() || summary.exists() {
        return Err("refusing to overwrite a configuration materialization output".to_owned());
    }
    let template: FrozenConfigurationV2 =
        serde_json::from_slice(&read_regular(template, "V18 template")?)
            .map_err(|error| format!("invalid V18 template JSON: {error}"))?;
    let overlay: Overlay = serde_json::from_slice(&read_regular(overlay, "identity overlay")?)
        .map_err(|error| format!("invalid identity overlay JSON: {error}"))?;
    let (configuration, materialization) = materialize(template, overlay)?;
    create_new_json(output, &configuration, "materialized V18 template")?;
    create_new_json(summary, &materialization, "V18 template summary")
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(template), Some(overlay), Some(output), Some(summary), None) = (
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) else {
        eprintln!(
            "usage: ecx-bond-v2-frozen-template-materialize \\\n+<template.json> <overlay.json> <create-new-configuration.json> <create-new-summary.json>"
        );
        std::process::exit(2);
    };
    if let Err(error) = run(&template, &overlay, &output, &summary) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displayed_asset_ids_are_converted_to_consensus_byte_order() {
        let displayed = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23";
        let parsed = asset(displayed, "asset").unwrap();
        assert_eq!(
            hex::encode(parsed),
            "230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2"
        );
        assert!(hash32(&"00".repeat(32), "hash").is_err());
    }
}
