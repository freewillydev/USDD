//! Offline create-new writer for the unsigned physical bond V2 candidate.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use ecx_bond_action_client::{
    compose_frozen_bond_deployment_genesis_document_v2, FrozenBondDeploymentGenesisPlanV2,
};

const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_PLAN_BYTES {
        return Err(format!(
            "input must be a nonempty regular file no larger than {MAX_PLAN_BYTES} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn run(input: &Path, output: &Path) -> Result<(), String> {
    let encoded = read_regular_file(input)?;
    let plan: FrozenBondDeploymentGenesisPlanV2 = serde_json::from_slice(&encoded)
        .map_err(|error| format!("invalid deployment plan JSON: {error}"))?;
    let document = compose_frozen_bond_deployment_genesis_document_v2(plan)
        .map_err(|error| format!("candidate rejected: {error}"))?;
    let mut output_bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("cannot encode candidate: {error}"))?;
    output_bytes.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(output)
        .map_err(|error| format!("cannot create-new {}: {error}", output.display()))?;
    file.write_all(&output_bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {}: {error}", output.display()))?;
    Ok(())
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let Some(input) = arguments.next() else {
        eprintln!("usage: ecx-bond-v2-deployment-candidate <plan.json> <create-new-output.json>");
        std::process::exit(2);
    };
    let Some(output) = arguments.next() else {
        eprintln!("usage: ecx-bond-v2-deployment-candidate <plan.json> <create-new-output.json>");
        std::process::exit(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: ecx-bond-v2-deployment-candidate <plan.json> <create-new-output.json>");
        std::process::exit(2);
    }
    if let Err(error) = run(&input, &output) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_bond_action_client::{
        FrozenBondDeploymentGenesisDocumentV2, DEPLOYMENT_CANDIDATE_STATUS_V2,
    };
    use ecx_elements_settlement::{
        BOND_FIXED_SUPPLY_ATOMS_V2, BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2,
    };
    use elements::confidential::{AssetBlindingFactor, Value, ValueBlindingFactor};
    use elements::hashes::Hash;
    use elements::opcodes;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
    use elements::{AssetId, OutPoint, Script, TxIn, TxOut, TxOutSecrets, Txid};
    use rand::thread_rng;

    const KEY_ONE: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];
    const KEY_TWO: [u8; 32] = [
        0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c,
        0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70,
        0x9e, 0xe5,
    ];
    const KEY_THREE: [u8; 32] = [
        0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52,
        0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0,
        0x36, 0xf9,
    ];

    fn p2tr(key: [u8; 32]) -> Script {
        let mut bytes = vec![0x51, 0x20];
        bytes.extend_from_slice(&key);
        Script::from(bytes)
    }

    fn plan() -> FrozenBondDeploymentGenesisPlanV2 {
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
        let asset = derived.issuance_ids().0;
        let inventory_script = p2tr(KEY_ONE);
        let inventory_abf = AssetBlindingFactor::from_slice(&[0x31; 32]).unwrap();
        let inventory_vbf = ValueBlindingFactor::from_slice(&[0x32; 32]).unwrap();
        let issuance_vbf = ValueBlindingFactor::last(
            &Secp256k1::new(),
            BOND_FIXED_SUPPLY_ATOMS_V2,
            AssetBlindingFactor::zero(),
            &[TxOutSecrets::new(
                asset,
                inventory_abf,
                BOND_FIXED_SUPPLY_ATOMS_V2,
                inventory_vbf,
            )
            .value_blind_inputs()],
            &[],
        );
        let mut issuance_vbf_bytes = [0; 32];
        issuance_vbf_bytes.copy_from_slice(issuance_vbf.into_inner().as_ref());
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let receiver_secret = SecretKey::new(&mut rng);
        let ephemeral_secret = SecretKey::new(&mut rng);
        let inventory = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            inventory_script.clone(),
            PublicKey::from_secret_key(&secp, &receiver_secret),
            ephemeral_secret,
            TxOutSecrets::new(
                asset,
                AssetBlindingFactor::from_slice(&[0x31; 32]).unwrap(),
                BOND_FIXED_SUPPLY_ATOMS_V2,
                ValueBlindingFactor::from_slice(&[0x32; 32]).unwrap(),
            ),
            &[TxOutSecrets::new(
                asset,
                AssetBlindingFactor::zero(),
                BOND_FIXED_SUPPLY_ATOMS_V2,
                ValueBlindingFactor::zero(),
            )],
        )
        .unwrap();
        FrozenBondDeploymentGenesisPlanV2 {
            issuance_input: input,
            issuance_contract_entropy: entropy,
            deployment_additional_inputs: vec![],
            deployment_additional_explicit_outputs: vec![],
            inventory_output: inventory,
            inventory_asset_blinding_factor: [0x31; 32],
            inventory_value_blinding_factor: [0x32; 32],
            issuance_value_blinding_factor: issuance_vbf_bytes,
            issuance_blinding_secret: [0x33; 32],
            inventory_vault_script: inventory_script,
            redemption_queue_script: Script::from(vec![0x51, 0x42]),
            reissuance_token_burn_script: Script::from(vec![opcodes::all::OP_RETURN.into_u8()]),
            state_authority_asset_id: AssetId::from_byte_array([0xb0; 32])
                .into_inner()
                .to_byte_array(),
            state_authority_source_script: p2tr(KEY_TWO),
            genesis_state_script: p2tr(KEY_THREE),
            usdd_asset_id: [0xb1; 32],
            genesis_additional_inputs: vec![],
            genesis_additional_explicit_outputs: vec![],
        }
    }

    #[test]
    fn create_new_cli_boundary_refuses_overwrite_and_emits_nonactivating_document() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plan.json");
        let output = directory.path().join("candidate.json");
        fs::write(&input, serde_json::to_vec(&plan()).unwrap()).unwrap();
        run(&input, &output).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let document: FrozenBondDeploymentGenesisDocumentV2 =
            serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(document.status, DEPLOYMENT_CANDIDATE_STATUS_V2);
        document.verify().unwrap();
        assert!(run(&input, &output).is_err());
    }
}
