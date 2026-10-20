//! Offline structural manifest projection, never deployment/finality evidence.
use ecx_conversion_foundation_v2::usdd_usd::verify_usdd_manifest_identity_v2;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read};

const MAX_BYTES: usize = 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn project(bytes: &[u8]) -> Result<serde_json::Value, String> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("manifest length outside permitted bounds".into());
    }
    let identity = verify_usdd_manifest_identity_v2(bytes)
        .map_err(|error| format!("canonical manifest rejected: {error}"))?;
    Ok(serde_json::json!({
        "schema": "USDD_MANIFEST_BINDING_EXPORT_V1",
        "manifest_sha256": hex(&Sha256::digest(bytes)),
        "manifest_bytes": bytes.len(),
        "ethereum_chain_id": identity.ethereum_chain_id,
        "usdd_ethereum_light_client_configuration_hash_hex": hex(&identity.ethereum_light_client_configuration_hash),
        "vault_address_hex": hex(&identity.vault_address),
        "reserve_token_address_hex": hex(&identity.reserve_token_address),
        "usdd_asset_id_manifest_hex": hex(&identity.usdd_asset_id),
        "elements_genesis_hash_manifest_hex": hex(&identity.elements_genesis_hash),
        "vault_runtime_code_hash_hex": hex(&identity.vault_runtime_code_hash),
        "deployment_verified": false,
        "bootstrap_finality_verified": false,
        "guest_compatibility_verified": false,
        "proof_ready": false
    }))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: usdd-manifest-binding-export CANONICAL_MANIFEST_BINARY".into());
    }
    let file = File::open(&args[0]).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    println!("{}", serde_json::to_string_pretty(&project(&bytes)?)
        .map_err(|error| error.to_string())?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_oversized_and_fabricated_manifests() {
        assert!(project(&[]).is_err());
        assert!(project(&vec![0; MAX_BYTES + 1]).is_err());
        assert!(project(&[0; 1024]).is_err());
        assert!(project(b"{\"proofReady\":true}").is_err());
    }
}
