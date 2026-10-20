//! Create-new builder for the private unsigned physical deployment plan.
//!
//! The input contains private blinding material. Keep both input and output
//! private; neither document is activation, confirmation, or proof evidence.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ecx_bond_action_client::{
    compose_frozen_bond_deployment_genesis_document_v2, FrozenBondDeploymentGenesisPlanV2,
};
use ecx_elements_settlement::BOND_FIXED_SUPPLY_ATOMS_V2;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use elements::{encode, AssetId, OutPoint, Script, Transaction, TxIn, TxOut, TxOutSecrets, Txid};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

const MAX_SPEC_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentPlanSpecV2 {
    issuance_previous_txid: String,
    issuance_previous_vout: u32,
    issuance_previous_transaction_hex: String,
    issuance_contract_entropy_hex: String,
    deployment_sponsor_previous_txid: String,
    deployment_sponsor_previous_vout: u32,
    deployment_sponsor_previous_transaction_hex: String,
    genesis_sponsor_previous_txid: String,
    genesis_sponsor_previous_vout: u32,
    genesis_sponsor_previous_transaction_hex: String,
    policy_asset_id: String,
    deployment_fee_atoms: u64,
    genesis_fee_atoms: u64,
    deployment_change_script_hex: Option<String>,
    genesis_change_script_hex: Option<String>,
    inventory_vault_script_hex: String,
    inventory_receiver_blinding_pubkey_hex: String,
    inventory_ephemeral_secret_hex: String,
    inventory_asset_blinding_factor_hex: String,
    inventory_value_blinding_factor_hex: String,
    issuance_blinding_secret_hex: String,
    redemption_queue_script_hex: String,
    state_authority_asset_id: String,
    state_authority_source_script_hex: String,
    genesis_state_script_hex: String,
    usdd_asset_id: String,
}

fn hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must encode exactly 32 bytes"))
}

fn script(value: &str, label: &str) -> Result<Script, String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    if bytes.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(Script::from(bytes))
}

fn txin(txid: &str, vout: u32, label: &str) -> Result<TxIn, String> {
    let txid = Txid::from_str(txid).map_err(|error| format!("invalid {label}: {error}"))?;
    Ok(TxIn {
        previous_output: OutPoint::new(txid, vout),
        ..TxIn::default()
    })
}

fn explicit_fee(asset: AssetId, atoms: u64) -> Result<TxOut, String> {
    if atoms == 0 {
        return Err("fee atoms must be nonzero".to_owned());
    }
    Ok(TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(atoms),
        nonce: Nonce::Null,
        script_pubkey: Script::new(),
        witness: Default::default(),
    })
}

fn known_witness_script(script: &Script) -> bool {
    script.is_v0_p2wpkh()
        || script.is_v0_p2wsh()
        || (script.is_v1_p2tr()
            && elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&script.as_bytes()[2..]).is_ok())
}

/// Bind supplied previous-transaction bytes to the selected outpoint. This is
/// not evidence of active-chain inclusion, confirmations, ownership, or an
/// unspent output; those checks must be repeated before any later signing.
fn previous_output(input: &TxIn, transaction_hex: &str, label: &str) -> Result<TxOut, String> {
    if transaction_hex.is_empty() || transaction_hex.len() > MAX_SPEC_BYTES as usize {
        return Err(format!(
            "{label} previous transaction is empty or too large"
        ));
    }
    let bytes = hex::decode(transaction_hex)
        .map_err(|error| format!("invalid {label} previous transaction hex: {error}"))?;
    let transaction: Transaction = encode::deserialize(&bytes)
        .map_err(|error| format!("invalid {label} previous transaction: {error}"))?;
    if encode::serialize(&transaction) != bytes {
        return Err(format!("{label} previous transaction is not canonical"));
    }
    if transaction.txid() != input.previous_output.txid {
        return Err(format!("{label} previous transaction txid mismatch"));
    }
    let output = transaction
        .output
        .get(input.previous_output.vout as usize)
        .ok_or_else(|| format!("{label} previous vout does not exist"))?;
    if output.asset.explicit().is_none()
        || output.value.explicit().is_none()
        || output.nonce != Nonce::Null
        || output.witness != Default::default()
    {
        return Err(format!(
            "{label} requires an explicit, unblinded previous output"
        ));
    }
    // Legacy/P2SH inputs require scriptSig construction that can change the
    // candidate txid. Only native witness inputs are supported by this plan.
    if !known_witness_script(&output.script_pubkey) {
        return Err(format!(
            "{label} requires a supported native witness previous output"
        ));
    }
    Ok(output.clone())
}

fn sponsor_outputs(
    previous: &TxOut,
    policy_asset: AssetId,
    fee_atoms: u64,
    change_script_hex: Option<&str>,
    label: &str,
) -> Result<Vec<TxOut>, String> {
    if previous.asset.explicit() != Some(policy_asset) {
        return Err(format!("{label} sponsor does not contain the policy asset"));
    }
    let atoms = previous
        .value
        .explicit()
        .ok_or_else(|| format!("{label} sponsor value must be explicit"))?;
    let change_atoms = atoms
        .checked_sub(fee_atoms)
        .ok_or_else(|| format!("{label} sponsor is insufficient for the explicit fee"))?;
    let mut outputs = vec![explicit_fee(policy_asset, fee_atoms)?];
    match (change_atoms, change_script_hex) {
        (0, None) => {}
        (0, Some(_)) => return Err(format!("{label} exact-fee sponsor must not specify change")),
        (_, None) => return Err(format!("{label} sponsor surplus requires a change script")),
        (_, Some(value)) => {
            let change_script = script(value, &format!("{label} change script"))?;
            if !known_witness_script(&change_script) {
                return Err(format!(
                    "{label} change script must be a supported native witness script"
                ));
            }
            outputs.push(TxOut {
                asset: Asset::Explicit(policy_asset),
                value: Value::Explicit(change_atoms),
                nonce: Nonce::Null,
                script_pubkey: change_script,
                witness: Default::default(),
            });
        }
    }
    Ok(outputs)
}

fn build_plan(spec: DeploymentPlanSpecV2) -> Result<FrozenBondDeploymentGenesisPlanV2, String> {
    let issuance_input = txin(
        &spec.issuance_previous_txid,
        spec.issuance_previous_vout,
        "issuance previous txid",
    )?;
    let deployment_sponsor = txin(
        &spec.deployment_sponsor_previous_txid,
        spec.deployment_sponsor_previous_vout,
        "deployment sponsor previous txid",
    )?;
    let genesis_sponsor = txin(
        &spec.genesis_sponsor_previous_txid,
        spec.genesis_sponsor_previous_vout,
        "genesis sponsor previous txid",
    )?;
    let mut selected = BTreeSet::new();
    for input in [&issuance_input, &deployment_sponsor, &genesis_sponsor] {
        if input.previous_output == OutPoint::default() || !selected.insert(input.previous_output) {
            return Err(
                "issuance and both sponsors must use distinct non-null outpoints".to_owned(),
            );
        }
    }
    let policy_asset = AssetId::from_str(&spec.policy_asset_id)
        .map_err(|error| format!("invalid policy asset id: {error}"))?;
    let state_authority = AssetId::from_str(&spec.state_authority_asset_id)
        .map_err(|error| format!("invalid state authority asset id: {error}"))?;
    let usdd = AssetId::from_str(&spec.usdd_asset_id)
        .map_err(|error| format!("invalid USDD asset id: {error}"))?;
    if [state_authority, usdd].contains(&policy_asset) {
        return Err("policy asset must differ from the state-authority and USDD assets".to_owned());
    }
    let issuance_previous = previous_output(
        &issuance_input,
        &spec.issuance_previous_transaction_hex,
        "issuance",
    )?;
    if issuance_previous.asset.explicit() != Some(state_authority)
        || issuance_previous.value.explicit() != Some(1)
    {
        return Err(
            "issuance previous output must contain exactly one state-authority atom".to_owned(),
        );
    }
    let deployment_previous = previous_output(
        &deployment_sponsor,
        &spec.deployment_sponsor_previous_transaction_hex,
        "deployment sponsor",
    )?;
    let genesis_previous = previous_output(
        &genesis_sponsor,
        &spec.genesis_sponsor_previous_transaction_hex,
        "genesis sponsor",
    )?;
    let deployment_outputs = sponsor_outputs(
        &deployment_previous,
        policy_asset,
        spec.deployment_fee_atoms,
        spec.deployment_change_script_hex.as_deref(),
        "deployment",
    )?;
    let genesis_outputs = sponsor_outputs(
        &genesis_previous,
        policy_asset,
        spec.genesis_fee_atoms,
        spec.genesis_change_script_hex.as_deref(),
        "genesis",
    )?;
    let entropy = hex32(
        &spec.issuance_contract_entropy_hex,
        "issuance contract entropy",
    )?;

    let mut issuance_for_asset = issuance_input.clone();
    issuance_for_asset.asset_issuance.asset_entropy = entropy;
    issuance_for_asset.asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2);
    issuance_for_asset.asset_issuance.inflation_keys = Value::Null;
    let bond_asset = issuance_for_asset.issuance_ids().0;

    let inventory_script = script(&spec.inventory_vault_script_hex, "inventory vault script")?;
    let receiver = PublicKey::from_slice(
        &hex::decode(&spec.inventory_receiver_blinding_pubkey_hex)
            .map_err(|error| format!("invalid inventory receiver blinding pubkey: {error}"))?,
    )
    .map_err(|error| format!("invalid inventory receiver blinding pubkey: {error}"))?;
    let ephemeral = SecretKey::from_slice(&hex32(
        &spec.inventory_ephemeral_secret_hex,
        "inventory ephemeral secret",
    )?)
    .map_err(|error| format!("invalid inventory ephemeral secret: {error}"))?;
    let abf_bytes = hex32(
        &spec.inventory_asset_blinding_factor_hex,
        "inventory asset blinding factor",
    )?;
    let vbf_bytes = hex32(
        &spec.inventory_value_blinding_factor_hex,
        "inventory value blinding factor",
    )?;
    let abf = AssetBlindingFactor::from_slice(&abf_bytes)
        .map_err(|error| format!("invalid inventory asset blinding factor: {error}"))?;
    let vbf = ValueBlindingFactor::from_slice(&vbf_bytes)
        .map_err(|error| format!("invalid inventory value blinding factor: {error}"))?;
    if abf_bytes == [0; 32] || vbf_bytes == [0; 32] || abf_bytes == vbf_bytes {
        return Err("inventory blinders must be nonzero and distinct".to_owned());
    }
    let inventory_secrets = TxOutSecrets::new(bond_asset, abf, BOND_FIXED_SUPPLY_ATOMS_V2, vbf);
    let issuance_vbf = ValueBlindingFactor::last(
        &Secp256k1::new(),
        BOND_FIXED_SUPPLY_ATOMS_V2,
        AssetBlindingFactor::zero(),
        &[inventory_secrets.value_blind_inputs()],
        &[],
    );
    let mut issuance_vbf_bytes = [0; 32];
    issuance_vbf_bytes.copy_from_slice(issuance_vbf.into_inner().as_ref());
    let issuance_secret = hex32(
        &spec.issuance_blinding_secret_hex,
        "issuance blinding secret",
    )?;
    let issuance_secret_key = SecretKey::from_slice(&issuance_secret)
        .map_err(|error| format!("invalid issuance blinding secret: {error}"))?;
    issuance_for_asset
        .blind_issuances_with_bfs(
            &Secp256k1::new(),
            issuance_vbf,
            ValueBlindingFactor::zero(),
            issuance_secret_key,
            issuance_secret_key,
        )
        .map_err(|error| format!("cannot blind issuance pseudo-input: {error}"))?;
    issuance_for_asset.asset_issuance.inflation_keys = Value::Explicit(1);
    let (final_bond_asset, token_asset) = issuance_for_asset.issuance_ids();
    if final_bond_asset != bond_asset {
        return Err("confidential issuance changed the derived bond asset id".to_owned());
    }
    let input_secrets = [
        TxOutSecrets::new(
            state_authority,
            AssetBlindingFactor::zero(),
            1,
            ValueBlindingFactor::zero(),
        ),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            BOND_FIXED_SUPPLY_ATOMS_V2,
            issuance_vbf,
        ),
        TxOutSecrets::new(
            token_asset,
            AssetBlindingFactor::zero(),
            1,
            ValueBlindingFactor::zero(),
        ),
        TxOutSecrets::new(
            policy_asset,
            AssetBlindingFactor::zero(),
            deployment_previous
                .value
                .explicit()
                .expect("checked previous output"),
            ValueBlindingFactor::zero(),
        ),
    ];
    let inventory_output = TxOut::with_txout_secrets(
        &mut thread_rng(),
        &Secp256k1::new(),
        inventory_script.clone(),
        receiver,
        ephemeral,
        inventory_secrets,
        &input_secrets,
    )
    .map_err(|error| format!("cannot construct confidential inventory output: {error}"))?;

    let plan = FrozenBondDeploymentGenesisPlanV2 {
        issuance_input,
        issuance_contract_entropy: entropy,
        deployment_additional_inputs: vec![deployment_sponsor],
        deployment_additional_explicit_outputs: deployment_outputs,
        inventory_output,
        inventory_asset_blinding_factor: abf_bytes,
        inventory_value_blinding_factor: vbf_bytes,
        issuance_value_blinding_factor: issuance_vbf_bytes,
        issuance_blinding_secret: issuance_secret,
        inventory_vault_script: inventory_script,
        redemption_queue_script: script(
            &spec.redemption_queue_script_hex,
            "redemption queue script",
        )?,
        reissuance_token_burn_script: Script::from(vec![
            elements::opcodes::all::OP_RETURN.into_u8()
        ]),
        state_authority_asset_id: state_authority.into_inner().to_byte_array(),
        state_authority_source_script: script(
            &spec.state_authority_source_script_hex,
            "state authority source script",
        )?,
        genesis_state_script: script(&spec.genesis_state_script_hex, "genesis state script")?,
        usdd_asset_id: usdd.into_inner().to_byte_array(),
        genesis_additional_inputs: vec![genesis_sponsor],
        genesis_additional_explicit_outputs: genesis_outputs,
    };
    // Run the real conservation/range/surjection checks for both unsigned
    // transactions against the byte-bound prevouts, not assumed fee amounts.
    let candidate = compose_frozen_bond_deployment_genesis_document_v2(plan.clone())
        .map_err(|error| format!("invalid deployment/genesis candidate: {error}"))?;
    let deployment: Transaction = encode::deserialize(&candidate.deployment.transaction)
        .map_err(|error| format!("cannot decode composed deployment: {error}"))?;
    deployment
        .verify_tx_amt_proofs(&Secp256k1::new(), &[issuance_previous, deployment_previous])
        .map_err(|error| format!("deployment amount proofs rejected: {error}"))?;
    let genesis: Transaction = encode::deserialize(&candidate.genesis_transaction)
        .map_err(|error| format!("cannot decode composed genesis: {error}"))?;
    genesis
        .verify_tx_amt_proofs(
            &Secp256k1::new(),
            &[
                deployment.output[candidate.state_authority_source_output_index as usize].clone(),
                genesis_previous,
            ],
        )
        .map_err(|error| format!("genesis amount proofs rejected: {error}"))?;
    Ok(plan)
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_SPEC_BYTES {
        return Err(format!(
            "input must be a nonempty regular file no larger than {MAX_SPEC_BYTES} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn run(input: &Path, output: &Path) -> Result<(), String> {
    let spec: DeploymentPlanSpecV2 = serde_json::from_slice(&read_regular_file(input)?)
        .map_err(|error| format!("invalid deployment plan specification: {error}"))?;
    let plan = build_plan(spec)?;
    let mut encoded = serde_json::to_vec_pretty(&plan)
        .map_err(|error| format!("cannot encode deployment plan: {error}"))?;
    encoded.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(output)
        .map_err(|error| format!("cannot create-new {}: {error}", output.display()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist {}: {error}", output.display()))
}

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(input), Some(output), None) = (arguments.next(), arguments.next(), arguments.next())
    else {
        eprintln!("usage: ecx-bond-v2-deployment-plan <private-spec.json> <create-new-plan.json>");
        std::process::exit(2);
    };
    if let Err(error) = run(&input, &output) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_bond_action_client::compose_frozen_bond_deployment_genesis_document_v2;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};

    fn key_hex(value: u8) -> String {
        let secret = SecretKey::from_slice(&[value; 32]).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &secret).to_string()
    }

    fn p2tr(byte: u8) -> String {
        format!("5120{}", hex::encode([byte; 32]))
    }

    fn p2wpkh(byte: u8) -> String {
        format!("0014{}", hex::encode([byte; 20]))
    }

    // Synthetic byte-bound records exercise construction only. They are not
    // wallet UTXOs, private-chain receipts, or live Alpha funding evidence.
    fn synthetic_previous(asset: u8, atoms: u64, tag: u8) -> Transaction {
        Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![txin(&hex::encode([tag; 32]), 0, "synthetic").unwrap()],
            output: vec![TxOut {
                asset: Asset::Explicit(AssetId::from_slice(&[asset; 32]).unwrap()),
                value: Value::Explicit(atoms),
                nonce: Nonce::Null,
                script_pubkey: script(&p2wpkh(tag), "synthetic").unwrap(),
                witness: Default::default(),
            }],
        }
    }

    fn spec() -> DeploymentPlanSpecV2 {
        let issuance = synthetic_previous(12, 1, 1);
        let deployment = synthetic_previous(5, 100_000, 3);
        let genesis = synthetic_previous(5, 100_000, 4);
        DeploymentPlanSpecV2 {
            issuance_previous_txid: issuance.txid().to_string(),
            issuance_previous_vout: 0,
            issuance_previous_transaction_hex: hex::encode(encode::serialize(&issuance)),
            issuance_contract_entropy_hex: hex::encode([2; 32]),
            deployment_sponsor_previous_txid: deployment.txid().to_string(),
            deployment_sponsor_previous_vout: 0,
            deployment_sponsor_previous_transaction_hex: hex::encode(encode::serialize(
                &deployment,
            )),
            genesis_sponsor_previous_txid: genesis.txid().to_string(),
            genesis_sponsor_previous_vout: 0,
            genesis_sponsor_previous_transaction_hex: hex::encode(encode::serialize(&genesis)),
            policy_asset_id: hex::encode([5; 32]),
            deployment_fee_atoms: 100_000,
            genesis_fee_atoms: 100_000,
            deployment_change_script_hex: None,
            genesis_change_script_hex: None,
            inventory_vault_script_hex: p2tr(6),
            inventory_receiver_blinding_pubkey_hex: key_hex(7),
            inventory_ephemeral_secret_hex: hex::encode([8; 32]),
            inventory_asset_blinding_factor_hex: hex::encode([9; 32]),
            inventory_value_blinding_factor_hex: hex::encode([10; 32]),
            issuance_blinding_secret_hex: hex::encode([16; 32]),
            redemption_queue_script_hex: p2tr(11),
            state_authority_asset_id: hex::encode([12; 32]),
            state_authority_source_script_hex: p2tr(13),
            genesis_state_script_hex: p2tr(14),
            usdd_asset_id: hex::encode([15; 32]),
        }
    }

    fn mutate_previous(
        spec: &mut DeploymentPlanSpecV2,
        role: &str,
        change: impl FnOnce(&mut Transaction),
    ) {
        let (txid, bytes) = match role {
            "issuance" => (
                &mut spec.issuance_previous_txid,
                &mut spec.issuance_previous_transaction_hex,
            ),
            "deployment" => (
                &mut spec.deployment_sponsor_previous_txid,
                &mut spec.deployment_sponsor_previous_transaction_hex,
            ),
            "genesis" => (
                &mut spec.genesis_sponsor_previous_txid,
                &mut spec.genesis_sponsor_previous_transaction_hex,
            ),
            _ => panic!("unknown synthetic role"),
        };
        let mut transaction: Transaction =
            encode::deserialize(&hex::decode(&*bytes).unwrap()).unwrap();
        change(&mut transaction);
        *txid = transaction.txid().to_string();
        *bytes = hex::encode(encode::serialize(&transaction));
    }

    fn candidate_transaction_and_previous_outputs() -> (
        FrozenBondDeploymentGenesisPlanV2,
        elements::Transaction,
        [TxOut; 2],
    ) {
        let plan = build_plan(spec()).unwrap();
        let candidate = compose_frozen_bond_deployment_genesis_document_v2(plan.clone()).unwrap();
        let transaction = elements::encode::deserialize(&candidate.deployment.transaction).unwrap();
        let previous_outputs = [
            TxOut {
                asset: Asset::Explicit(AssetId::from_slice(&[12; 32]).unwrap()),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::new(),
                witness: Default::default(),
            },
            TxOut {
                asset: Asset::Explicit(AssetId::from_slice(&[5; 32]).unwrap()),
                value: Value::Explicit(100_000),
                nonce: Nonce::Null,
                script_pubkey: Script::new(),
                witness: Default::default(),
            },
        ];
        (plan, transaction, previous_outputs)
    }

    #[test]
    fn concise_spec_builds_a_verified_create_new_plan() {
        let (_plan, transaction, previous_outputs) = candidate_transaction_and_previous_outputs();
        transaction
            .verify_tx_amt_proofs(&Secp256k1::new(), &previous_outputs)
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("spec.json");
        let output = directory.path().join("plan.json");
        fs::write(&input, serde_json::to_vec(&spec()).unwrap()).unwrap();
        run(&input, &output).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(run(&input, &output).is_err());
        let decoded: FrozenBondDeploymentGenesisPlanV2 =
            serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        compose_frozen_bond_deployment_genesis_document_v2(decoded).unwrap();
    }

    #[test]
    fn explicit_issuance_cannot_balance_the_blinded_full_supply_inventory() {
        let (_, mut transaction, previous_outputs) = candidate_transaction_and_previous_outputs();
        transaction.input[0].asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2);
        transaction.input[0].witness.amount_rangeproof = None;
        assert!(transaction
            .verify_tx_amt_proofs(&Secp256k1::new(), &previous_outputs)
            .is_err());
    }

    #[test]
    fn confidential_issuance_requires_its_exact_opening_and_rangeproof() {
        let (mut plan, _, _) = candidate_transaction_and_previous_outputs();
        plan.issuance_value_blinding_factor[0] ^= 1;
        assert!(compose_frozen_bond_deployment_genesis_document_v2(plan).is_err());

        let mut candidate =
            compose_frozen_bond_deployment_genesis_document_v2(build_plan(spec()).unwrap())
                .unwrap();
        let mut transaction: elements::Transaction =
            elements::encode::deserialize(&candidate.deployment.transaction).unwrap();
        transaction.input[0].witness.amount_rangeproof = None;
        candidate.deployment.transaction = elements::encode::serialize(&transaction);
        assert!(ecx_elements_settlement::verify_frozen_bond_deployment_v2(
            &candidate.deployment,
            &candidate.frozen_asset,
        )
        .is_err());
    }

    #[test]
    fn inventory_surjection_proof_is_bound_to_the_complete_input_domain() {
        let (_, transaction, mut previous_outputs) = candidate_transaction_and_previous_outputs();
        previous_outputs[1].asset = Asset::Explicit(AssetId::from_slice(&[17; 32]).unwrap());
        assert!(transaction
            .verify_tx_amt_proofs(&Secp256k1::new(), &previous_outputs)
            .is_err());
    }

    #[test]
    fn both_sponsor_surpluses_are_returned_and_real_amount_proofs_verify() {
        let mut spec = spec();
        mutate_previous(&mut spec, "deployment", |tx| {
            tx.output[0].value = Value::Explicit(150_000)
        });
        mutate_previous(&mut spec, "genesis", |tx| {
            tx.output[0].value = Value::Explicit(250_000)
        });
        spec.deployment_change_script_hex = Some(p2wpkh(18));
        spec.genesis_change_script_hex = Some(p2wpkh(19));
        let plan = build_plan(spec.clone()).unwrap();
        for (outputs, change, expected_script) in [
            (
                &plan.deployment_additional_explicit_outputs,
                50_000,
                p2wpkh(18),
            ),
            (
                &plan.genesis_additional_explicit_outputs,
                150_000,
                p2wpkh(19),
            ),
        ] {
            assert_eq!(outputs.len(), 2);
            assert_eq!(outputs[0].value.explicit(), Some(100_000));
            assert!(outputs[0].script_pubkey.is_empty());
            assert_eq!(outputs[1].value.explicit(), Some(change));
            assert_eq!(
                hex::encode(outputs[1].script_pubkey.as_bytes()),
                expected_script
            );
        }
        let document = compose_frozen_bond_deployment_genesis_document_v2(plan.clone()).unwrap();
        let deployment: Transaction =
            encode::deserialize(&document.deployment.transaction).unwrap();
        let genesis: Transaction = encode::deserialize(&document.genesis_transaction).unwrap();
        let issuance_prev: Transaction =
            encode::deserialize(&hex::decode(spec.issuance_previous_transaction_hex).unwrap())
                .unwrap();
        let deployment_prev: Transaction = encode::deserialize(
            &hex::decode(spec.deployment_sponsor_previous_transaction_hex).unwrap(),
        )
        .unwrap();
        let genesis_prev: Transaction = encode::deserialize(
            &hex::decode(spec.genesis_sponsor_previous_transaction_hex).unwrap(),
        )
        .unwrap();
        deployment
            .verify_tx_amt_proofs(
                &Secp256k1::new(),
                &[
                    issuance_prev.output[0].clone(),
                    deployment_prev.output[0].clone(),
                ],
            )
            .unwrap();
        genesis
            .verify_tx_amt_proofs(
                &Secp256k1::new(),
                &[deployment.output[2].clone(), genesis_prev.output[0].clone()],
            )
            .unwrap();
        assert_eq!(
            genesis.input[0].previous_output,
            OutPoint::new(deployment.txid(), 2)
        );
        assert_eq!(genesis.output[0].value.explicit(), Some(1));
        assert!(!document.funded && !document.signed && !document.confirmed);
        assert!(!document.activated && !document.identities_frozen && !document.mempool_accepted);
        // Dropping even one atom of requested change is a real imbalance.
        let mut tampered = deployment;
        tampered.output[4].value = Value::Explicit(49_999);
        assert!(tampered
            .verify_tx_amt_proofs(
                &Secp256k1::new(),
                &[
                    issuance_prev.output[0].clone(),
                    deployment_prev.output[0].clone()
                ]
            )
            .is_err());
    }

    #[test]
    fn missing_or_mismatched_previous_transactions_fail_closed() {
        for field in [
            "issuance_previous_transaction_hex",
            "deployment_sponsor_previous_transaction_hex",
            "genesis_sponsor_previous_transaction_hex",
        ] {
            let mut value = serde_json::to_value(spec()).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<DeploymentPlanSpecV2>(value).is_err(),
                "{field}"
            );
            for invalid in ["", "00", "not hex"] {
                let mut value = serde_json::to_value(spec()).unwrap();
                value[field] = invalid.into();
                assert!(
                    build_plan(serde_json::from_value(value).unwrap()).is_err(),
                    "{field}"
                );
            }
        }
        for field in [
            "issuance_previous_txid",
            "deployment_sponsor_previous_txid",
            "genesis_sponsor_previous_txid",
        ] {
            let mut value = serde_json::to_value(spec()).unwrap();
            value[field] = hex::encode([99; 32]).into();
            assert!(build_plan(serde_json::from_value(value).unwrap())
                .unwrap_err()
                .contains("txid mismatch"));
        }
    }

    #[test]
    fn previous_vout_bounds_and_trailing_bytes_are_checked() {
        for field in [
            "issuance_previous_vout",
            "deployment_sponsor_previous_vout",
            "genesis_sponsor_previous_vout",
        ] {
            let mut value = serde_json::to_value(spec()).unwrap();
            value[field] = u32::MAX.into();
            assert!(build_plan(serde_json::from_value(value).unwrap())
                .unwrap_err()
                .contains("vout does not exist"));
        }
        for field in [
            "issuance_previous_transaction_hex",
            "deployment_sponsor_previous_transaction_hex",
            "genesis_sponsor_previous_transaction_hex",
        ] {
            let mut value = serde_json::to_value(spec()).unwrap();
            value[field] = format!("{}00", value[field].as_str().unwrap()).into();
            assert!(build_plan(serde_json::from_value(value).unwrap()).is_err());
        }
    }

    #[test]
    fn surplus_cannot_be_silently_lost_or_moved_into_the_fee() {
        for role in ["deployment", "genesis"] {
            let mut spec = spec();
            mutate_previous(&mut spec, role, |tx| {
                tx.output[0].value = Value::Explicit(100_001)
            });
            assert!(build_plan(spec)
                .unwrap_err()
                .contains("surplus requires a change script"));
        }
    }

    #[test]
    fn zero_and_insufficient_fees_are_rejected_for_both_transactions() {
        for field in ["deployment_fee_atoms", "genesis_fee_atoms"] {
            for (amount, message) in [(0, "fee atoms must be nonzero"), (100_001, "insufficient")] {
                let mut value = serde_json::to_value(spec()).unwrap();
                value[field] = amount.into();
                assert!(build_plan(serde_json::from_value(value).unwrap())
                    .unwrap_err()
                    .contains(message));
            }
        }
    }

    #[test]
    fn unused_or_unspendable_change_scripts_are_rejected() {
        for field in ["deployment_change_script_hex", "genesis_change_script_hex"] {
            let mut value = serde_json::to_value(spec()).unwrap();
            value[field] = p2wpkh(18).into();
            assert!(build_plan(serde_json::from_value(value).unwrap())
                .unwrap_err()
                .contains("must not specify change"));
            let fee_field = if field.starts_with("deployment") {
                "deployment_fee_atoms"
            } else {
                "genesis_fee_atoms"
            };
            for invalid in [
                String::new(),
                "6a".to_owned(),
                "51".to_owned(),
                format!("5220{}", hex::encode([0; 32])),
                format!("5120{}", "ff".repeat(32)),
            ] {
                let mut value = serde_json::to_value(spec()).unwrap();
                value[fee_field] = 99_000.into();
                value[field] = invalid.into();
                assert!(build_plan(serde_json::from_value(value).unwrap()).is_err());
            }
        }
    }

    #[test]
    fn non_witness_or_blinded_previous_outputs_are_rejected() {
        for role in ["issuance", "deployment", "genesis"] {
            for invalid in [
                "",
                "6a",
                "51",
                "a914010101010101010101010101010101010101010187",
            ] {
                let mut spec = spec();
                mutate_previous(&mut spec, role, |tx| {
                    tx.output[0].script_pubkey = Script::from(hex::decode(invalid).unwrap())
                });
                assert!(build_plan(spec).unwrap_err().contains("native witness"));
            }
            let mut spec = spec();
            mutate_previous(&mut spec, role, |tx| {
                tx.output[0].nonce = Nonce::Confidential(PublicKey::from_str(&key_hex(7)).unwrap())
            });
            assert!(build_plan(spec)
                .unwrap_err()
                .contains("explicit, unblinded"));
        }
        let confidential = build_plan(spec()).unwrap().inventory_output;
        let mut spec = spec();
        mutate_previous(&mut spec, "deployment", |tx| tx.output[0] = confidential);
        assert!(build_plan(spec)
            .unwrap_err()
            .contains("explicit, unblinded"));
    }

    #[test]
    fn wrong_assets_and_non_singleton_authority_are_rejected() {
        for role in ["issuance", "deployment", "genesis"] {
            let mut spec = spec();
            mutate_previous(&mut spec, role, |tx| {
                tx.output[0].asset = Asset::Explicit(AssetId::from_slice(&[77; 32]).unwrap())
            });
            assert!(build_plan(spec).is_err());
        }
        for atoms in [0, 2, 100_000] {
            let mut spec = spec();
            mutate_previous(&mut spec, "issuance", |tx| {
                tx.output[0].value = Value::Explicit(atoms)
            });
            assert!(build_plan(spec)
                .unwrap_err()
                .contains("exactly one state-authority atom"));
        }
    }

    #[test]
    fn a_sponsor_cannot_be_reused_between_deployment_and_genesis() {
        let mut spec = spec();
        spec.genesis_sponsor_previous_txid = spec.deployment_sponsor_previous_txid.clone();
        spec.genesis_sponsor_previous_vout = spec.deployment_sponsor_previous_vout;
        spec.genesis_sponsor_previous_transaction_hex =
            spec.deployment_sponsor_previous_transaction_hex.clone();
        assert!(build_plan(spec)
            .unwrap_err()
            .contains("distinct non-null outpoints"));
    }

    #[test]
    fn policy_asset_aliases_and_issuance_sponsor_aliases_are_rejected() {
        for field in ["state_authority_asset_id", "usdd_asset_id"] {
            let mut value = serde_json::to_value(spec()).unwrap();
            value[field] = value["policy_asset_id"].clone();
            assert!(build_plan(serde_json::from_value(value).unwrap())
                .unwrap_err()
                .contains("policy asset must differ"));
        }
        let mut spec = spec();
        spec.deployment_sponsor_previous_txid = spec.issuance_previous_txid.clone();
        spec.deployment_sponsor_previous_vout = spec.issuance_previous_vout;
        assert!(build_plan(spec)
            .unwrap_err()
            .contains("distinct non-null outpoints"));
    }

    #[test]
    fn invalid_funding_does_not_create_an_output_file() {
        let mut spec = spec();
        spec.genesis_fee_atoms += 1;
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("spec.json");
        let output = directory.path().join("plan.json");
        fs::write(&input, serde_json::to_vec(&spec).unwrap()).unwrap();
        assert!(run(&input, &output).is_err());
        assert!(!output.exists());
    }
}
