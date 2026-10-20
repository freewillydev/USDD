//! Version-separated public issuance relation. This does not authorize inputs
//! or replace native transaction validation, and does not accept V2 openings.
use super::*;

pub const PUBLIC_DEPLOYMENT_VERSION: u8 = 3;

/// Construct an unsigned public deployment from an unissued transaction
/// template. Inventory and burn slots must already exist; their scripts are
/// checked against the frozen asset record. Sponsor inputs/outputs are retained.
/// The caller must independently fund and natively validate the transaction.
pub fn compose_public_bond_deployment(
    mut tx: Transaction,
    issuance_input_index: u32,
    inventory_output_index: u32,
    burn_output_index: u32,
    contract_entropy: Hash32,
    frozen_asset: &FrozenBondAssetV2,
) -> Result<(FrozenBondDeploymentV2, VerifiedFrozenBondDeploymentV2), SettlementError> {
    if contract_entropy == [0; 32]
        || inventory_output_index == burn_output_index
        || tx.input.iter().any(|input| input.has_issuance()
            || input.is_pegin() || !input.script_sig.is_empty()
            || !input.witness.script_witness.is_empty())
        || !explicit_creations::has_only_explicit_creations(&tx)
    {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let input = tx.input.get_mut(issuance_input_index as usize)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    input.asset_issuance.asset_entropy = contract_entropy;
    input.asset_issuance.asset_blinding_nonce = elements::secp256k1_zkp::ZERO_TWEAK;
    input.asset_issuance.amount = Value::Explicit(FrozenBondAssetV2::FIXED_SUPPLY_ATOMS);
    input.asset_issuance.inflation_keys = Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2);
    let (asset, token) = input.issuance_ids();
    let inventory = tx.output.get_mut(inventory_output_index as usize)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    inventory.asset = Asset::Explicit(asset);
    inventory.value = Value::Explicit(FrozenBondAssetV2::FIXED_SUPPLY_ATOMS);
    let burn = tx.output.get_mut(burn_output_index as usize)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    burn.asset = Asset::Explicit(token);
    burn.value = Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2);
    let deployment = FrozenBondDeploymentV2 {
        version: PUBLIC_DEPLOYMENT_VERSION,
        transaction: elements::encode::serialize(&tx),
        issuance_input_index,
        inventory_output_index,
        inventory_asset_blinding_factor: [0; 32],
        inventory_value_blinding_factor: [0; 32],
        issuance_value_blinding_factor: [0; 32],
        reissuance_token_burn_output_index: burn_output_index,
    };
    let verified = verify_public_bond_deployment(&deployment, frozen_asset)?;
    Ok((deployment, verified))
}

pub fn verify_public_bond_deployment(
    deployment: &FrozenBondDeploymentV2,
    frozen_asset: &FrozenBondAssetV2,
) -> Result<VerifiedFrozenBondDeploymentV2, SettlementError> {
    if deployment.version != PUBLIC_DEPLOYMENT_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    if deployment.inventory_asset_blinding_factor != [0; 32]
        || deployment.inventory_value_blinding_factor != [0; 32]
        || deployment.issuance_value_blinding_factor != [0; 32]
    {
        return Err(SettlementError::InvalidBondDeployment);
    }
    frozen_asset.validate()?;
    let tx = decode_transaction(&deployment.transaction)?;
    if !explicit_creations::has_only_explicit_creations(&tx)
        || tx.input.iter().any(|input| input.is_pegin())
        || tx.input.iter().filter(|input| input.has_issuance()).count() != 1
    {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let input = tx.input.get(deployment.issuance_input_index as usize)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    if input.asset_issuance.asset_blinding_nonce != elements::secp256k1_zkp::ZERO_TWEAK
        || input.asset_issuance.amount != Value::Explicit(FrozenBondAssetV2::FIXED_SUPPLY_ATOMS)
        || input.asset_issuance.inflation_keys != Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2)
    {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let (asset, token) = input.issuance_ids();
    let bond_asset_id = asset.into_inner().to_byte_array();
    let reissuance_token_asset_id = token.into_inner().to_byte_array();
    if bond_asset_id != frozen_asset.asset_id || bond_asset_id == reissuance_token_asset_id
        || deployment.inventory_output_index == deployment.reissuance_token_burn_output_index
    {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let inventory = tx.output.get(deployment.inventory_output_index as usize)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    if explicit_output_amount(inventory, bond_asset_id) != Some(FrozenBondAssetV2::FIXED_SUPPLY_ATOMS)
        || script_sha256(inventory) != frozen_asset.inventory_vault_script_sha256
    {
        return Err(SettlementError::InvalidBondOpening);
    }
    let burn = tx.output.get(deployment.reissuance_token_burn_output_index as usize)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    if explicit_output_amount(burn, reissuance_token_asset_id) != Some(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2)
        || script_sha256(burn) != frozen_asset.reissuance_token_burn_script_sha256
        || !is_provably_unspendable_script(burn.script_pubkey.as_bytes())
    {
        return Err(SettlementError::BondReissuanceTokenNotDestroyed);
    }
    for (index, output) in tx.output.iter().enumerate() {
        if output.asset == Asset::Explicit(asset) && index != deployment.inventory_output_index as usize
            || output.asset == Asset::Explicit(token) && index != deployment.reissuance_token_burn_output_index as usize
        {
            return Err(SettlementError::InvalidBondDeployment);
        }
    }
    let transaction_id = tx.txid().to_byte_array();
    let mut verified = VerifiedFrozenBondDeploymentV2 {
        transaction_id,
        issuance_previous_txid: input.previous_output.txid.to_byte_array(),
        issuance_previous_vout: input.previous_output.vout,
        bond_asset_id,
        reissuance_token_asset_id,
        inventory_output_index: deployment.inventory_output_index,
        reissuance_token_burn_output_index: deployment.reissuance_token_burn_output_index,
        fixed_supply_atoms: FrozenBondAssetV2::FIXED_SUPPLY_ATOMS,
        deployment_commitment: [0; 32],
    };
    let bytes = encode_public_deployment_commitment(&verified,
        &frozen_asset.inventory_vault_script_sha256,
        &frozen_asset.reissuance_token_burn_script_sha256);
    verified.deployment_commitment = sha256_tagged("ECX/frozen-bond-deployment/v3", &bytes);
    Ok(verified)
}

// Encoding only; kept private so it cannot manufacture a verified relation.
fn encode_public_deployment_commitment(
    value: &VerifiedFrozenBondDeploymentV2, inventory_script: &Hash32, burn_script: &Hash32,
) -> Vec<u8> {
    let mut bytes = vec![PUBLIC_DEPLOYMENT_VERSION];
    bytes.extend_from_slice(&value.transaction_id);
    bytes.extend_from_slice(&value.issuance_previous_txid);
    bytes.extend_from_slice(&value.issuance_previous_vout.to_be_bytes());
    bytes.extend_from_slice(&value.bond_asset_id);
    bytes.extend_from_slice(&value.reissuance_token_asset_id);
    bytes.extend_from_slice(&FrozenBondAssetV2::FIXED_SUPPLY_ATOMS.to_be_bytes());
    bytes.extend_from_slice(&value.inventory_output_index.to_be_bytes());
    bytes.extend_from_slice(&value.reissuance_token_burn_output_index.to_be_bytes());
    bytes.extend_from_slice(inventory_script);
    bytes.extend_from_slice(burn_script);
    bytes
}

#[cfg(test)]
mod commitment_vector_tests {
    use super::*;

    #[test]
    fn native_public_commitment_vector() {
        let sequence = |start: u8| std::array::from_fn(|i| start + i as u8);
        let value = VerifiedFrozenBondDeploymentV2 {
            transaction_id: sequence(0), issuance_previous_txid: sequence(32),
            issuance_previous_vout: 0x01020304, bond_asset_id: sequence(64),
            reissuance_token_asset_id: sequence(96), inventory_output_index: 0x05060708,
            reissuance_token_burn_output_index: 0x090a0b0c,
            fixed_supply_atoms: FrozenBondAssetV2::FIXED_SUPPLY_ATOMS,
            deployment_commitment: [0; 32],
        };
        let bytes = encode_public_deployment_commitment(&value, &sequence(128), &sequence(160));
        assert_eq!(bytes.len(), 213);
        assert_eq!(hex::encode(&bytes), concat!(
            "03000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f01020304",
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            "000775f05a07400005060708090a0b0c",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"));
        assert_eq!(hex::encode(sha256_tagged("ECX/frozen-bond-deployment/v3", &bytes)),
            "d6f052787853cd42b3d7838d424ea45f59d14b3bce3373c33fb3f871f919b1bf");
    }
}
