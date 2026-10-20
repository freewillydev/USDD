//! Materialize the exact incremental-successor and matcher configurations for
//! one validated finite V18 deployment.
//!
//! The finite configuration digest is deliberately reused as the order
//! signature domain. This binds successor orders to the physical asset,
//! covenant, oracle, risk, and matcher identities already frozen for the
//! deployment without introducing an arbitrary operator-selected hash.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ecx_protocol_core::{
    FrozenConfigurationV2, IncrementalAccountingBoundsV2,
    IncrementalEmptyActivationConfigurationV2, IncrementalSuccessorConfigurationV2, RiskParams,
    SuccessorCentralMatcherConfigV2, INCREMENTAL_EMPTY_ACTIVATION_VERSION_V2,
    INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
};
use serde::{Deserialize, Serialize};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

fn successor_accounting_bounds() -> IncrementalAccountingBoundsV2 {
    IncrementalAccountingBoundsV2 {
        maximum_abs_trader_collateral_atoms: 1_000_000,
        maximum_total_controlled_atoms: 10_000_000,
        maximum_abs_position_atoms: 1_000_000,
        maximum_open_interest_atoms: 10_000_000,
        // No operator-selected market-price ceiling. Keep the canonical
        // positive-u64 Price representation and checked arithmetic intact.
        // Bounds remain committed by the successor configuration digest.
        maximum_price_atoms: u64::MAX,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatcherKeyDocument {
    version: u16,
    role: String,
    secret_key_hex: String,
    public_key_xonly: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    schema: &'static str,
    finite_configuration_hash_hex: String,
    order_configuration_hash_hex: String,
    successor_matcher_configuration_hash_hex: String,
    successor_configuration_hash_hex: String,
    incremental_activation_configuration_hash_hex: String,
    matcher_public_key_xonly_hex: String,
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

fn parse_hash(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{label} must encode exactly 32 bytes"))?;
    if hash == [0; 32] {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(hash)
}

fn matcher_public_key(key: &MatcherKeyDocument) -> Result<[u8; 32], String> {
    if key.version != 1 || key.role != "central_single_signer" || key.secret_key_hex.len() != 64 {
        return Err("matcher key document has an unsupported identity schema".to_owned());
    }
    let secret = secp256k1::SecretKey::from_slice(
        &hex::decode(&key.secret_key_hex)
            .map_err(|error| format!("invalid matcher secret key: {error}"))?,
    )
    .map_err(|error| format!("invalid matcher secret key: {error}"))?;
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret);
    let (public, _) = secp256k1::XOnlyPublicKey::from_keypair(&keypair);
    let public_bytes = public.serialize();
    if hex::encode(public_bytes) != key.public_key_xonly {
        return Err("matcher public key does not correspond to the protected secret".to_owned());
    }
    Ok(public_bytes)
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
    frozen: FrozenConfigurationV2,
    key: MatcherKeyDocument,
    genesis_receipt_hash: [u8; 32],
) -> Result<
    (
        SuccessorCentralMatcherConfigV2,
        IncrementalSuccessorConfigurationV2,
        Summary,
    ),
    String,
> {
    frozen
        .validate()
        .map_err(|error| format!("finite V18 configuration rejected: {error}"))?;
    let public_bytes = matcher_public_key(&key)?;

    let matcher = SuccessorCentralMatcherConfigV2 {
        version: SuccessorCentralMatcherConfigV2::VERSION,
        key_epoch: 0,
        signer: ecx_protocol_core::XOnlyKey(public_bytes),
        genesis_sequence: 0,
        genesis_receipt_hash,
        forced_inclusion_blocks: frozen.base.matcher.forced_inclusion_blocks,
    };
    matcher
        .validate()
        .map_err(|error| format!("successor matcher configuration rejected: {error}"))?;
    let finite_hash = frozen.digest();
    let successor = IncrementalSuccessorConfigurationV2 {
        version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
        chain_id: frozen.base.chain_id,
        market: frozen.base.market,
        order_configuration_hash: finite_hash,
        successor_matcher_configuration_hash: matcher.digest(),
        risk_params: RiskParams::default(),
        accounting_bounds: successor_accounting_bounds(),
        maximum_trader_updates: 64,
        maximum_order_operations: 64,
        maximum_nullifier_updates_per_kind: 64,
    };
    successor
        .validate()
        .map_err(|error| format!("successor configuration rejected: {error}"))?;
    let successor_hash = successor
        .digest()
        .map_err(|error| format!("cannot digest successor configuration: {error}"))?;
    let activation = IncrementalEmptyActivationConfigurationV2 {
        version: INCREMENTAL_EMPTY_ACTIVATION_VERSION_V2,
        finite_v18_configuration_hash: finite_hash,
        successor,
    };
    activation
        .validate()
        .map_err(|error| format!("incremental activation configuration rejected: {error}"))?;
    let summary = Summary {
        schema: "ECX_BOND_V2_SUCCESSOR_CONFIGURATION_MATERIALIZATION_V1",
        finite_configuration_hash_hex: hex::encode(finite_hash),
        order_configuration_hash_hex: hex::encode(successor.order_configuration_hash),
        successor_matcher_configuration_hash_hex: hex::encode(matcher.digest()),
        successor_configuration_hash_hex: hex::encode(successor_hash),
        incremental_activation_configuration_hash_hex: hex::encode(
            activation
                .digest()
                .map_err(|error| format!("cannot digest activation configuration: {error}"))?,
        ),
        matcher_public_key_xonly_hex: hex::encode(public_bytes),
    };
    Ok((matcher, successor, summary))
}

fn run(
    frozen_path: &Path,
    matcher_key_path: &Path,
    genesis_receipt_hash_hex: &str,
    matcher_output: &Path,
    successor_output: &Path,
    summary_output: &Path,
) -> Result<(), String> {
    for output in [matcher_output, successor_output, summary_output] {
        if output.exists() {
            return Err(format!(
                "refusing to overwrite existing output {}",
                output.display()
            ));
        }
    }
    let frozen: FrozenConfigurationV2 =
        serde_json::from_slice(&read_regular(frozen_path, "finite V18 configuration")?)
            .map_err(|error| format!("invalid finite V18 configuration JSON: {error}"))?;
    let key: MatcherKeyDocument =
        serde_json::from_slice(&read_regular(matcher_key_path, "matcher key")?)
            .map_err(|error| format!("invalid matcher key JSON: {error}"))?;
    let genesis_receipt_hash = parse_hash(genesis_receipt_hash_hex, "genesis receipt hash")?;
    let (matcher, successor, summary) = materialize(frozen, key, genesis_receipt_hash)?;
    create_new_json(matcher_output, &matcher, "matcher configuration")?;
    create_new_json(successor_output, &successor, "successor configuration")?;
    create_new_json(summary_output, &summary, "successor configuration summary")
}

fn usage() -> ! {
    eprintln!(
        "usage: ecx-bond-v2-successor-configuration-materialize \\\n+<frozen-v18.json> <matcher-key.json> <genesis-receipt-hash-hex> \\\n+<create-new-matcher.json> <create-new-successor.json> <create-new-summary.json>"
    );
    std::process::exit(2);
}

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let (
        Some(frozen),
        Some(key),
        Some(genesis),
        Some(matcher),
        Some(successor),
        Some(summary),
        None,
    ) = (
        arguments.next().map(PathBuf::from),
        arguments.next().map(PathBuf::from),
        arguments.next(),
        arguments.next().map(PathBuf::from),
        arguments.next().map(PathBuf::from),
        arguments.next().map(PathBuf::from),
        arguments.next(),
    )
    else {
        usage();
    };
    let Some(genesis) = genesis.to_str() else {
        eprintln!("genesis receipt hash is not valid UTF-8");
        std::process::exit(2);
    };
    if let Err(error) = run(&frozen, &key, genesis, &matcher, &successor, &summary) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_artificial_price_cap_and_thirty_usdd_is_representable() {
        let bounds = successor_accounting_bounds();
        bounds.validate().unwrap();
        assert_eq!(bounds.maximum_price_atoms, u64::MAX);
        let chosen_mark =
            ecx_protocol_core::Price::new(30 * ecx_protocol_core::PRICE_SCALE).unwrap();
        assert_eq!(chosen_mark.get(), 3_000_000_000);
        assert!(chosen_mark.get() <= bounds.maximum_price_atoms);
        ecx_protocol_core::Price::new(u64::MAX).unwrap();
        bounds.maximum_reachable_abs_q_numerator().unwrap();
    }

    #[test]
    fn numeric_safety_checks_are_not_disabled() {
        assert!(ecx_protocol_core::Price::new(0).is_err());
        let mut invalid = successor_accounting_bounds();
        invalid.maximum_price_atoms = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = successor_accounting_bounds();
        invalid.maximum_abs_trader_collateral_atoms = u128::MAX;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn full_width_price_bound_survives_typed_json_round_trip() {
        let bounds = successor_accounting_bounds();
        let encoded = serde_json::to_string(&bounds).unwrap();
        assert!(encoded.contains("18446744073709551615"));
        let decoded: IncrementalAccountingBoundsV2 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, bounds);
        decoded.validate().unwrap();
    }

    #[test]
    fn canonical_empty_state_accepts_thirty_and_full_width_price() {
        // Synthetic unit fixture only: these identities do not stand in for
        // the missing frozen Alpha configuration, checkpoint, or genesis.
        let configuration = IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [0x11; 32],
            market: ecx_protocol_core::ECX_USDD_MARKET,
            order_configuration_hash: [0x22; 32],
            successor_matcher_configuration_hash: [0x23; 32],
            risk_params: RiskParams::default(),
            accounting_bounds: successor_accounting_bounds(),
            maximum_trader_updates: 64,
            maximum_order_operations: 64,
            maximum_nullifier_updates_per_kind: 64,
        };
        for mark in [30 * ecx_protocol_core::PRICE_SCALE, u64::MAX] {
            let state = ecx_protocol_core::IncrementalPublicStateV2::canonical_empty(
                configuration,
                1,
                1_700_000_000,
                mark,
                mark,
                mark,
            )
            .unwrap();
            assert_eq!(state.mark_price_atoms, mark);
            state.validate(configuration).unwrap();
            let encoded = serde_json::to_string(&state).unwrap();
            let decoded: ecx_protocol_core::IncrementalPublicStateV2 =
                serde_json::from_str(&encoded).unwrap();
            assert_eq!(state, decoded);
            assert_eq!(
                state.state_root(configuration).unwrap(),
                decoded.state_root(configuration).unwrap()
            );
        }
    }

    #[test]
    fn bad_key_document_fails_closed_before_materialization() {
        let key = MatcherKeyDocument {
            version: 1,
            role: "central_single_signer".to_owned(),
            secret_key_hex: "01".repeat(32),
            public_key_xonly: "02".repeat(32),
        };
        assert!(matcher_public_key(&key).is_err());
        assert!(parse_hash(&"00".repeat(32), "test hash").is_err());
    }
}
