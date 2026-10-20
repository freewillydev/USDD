use anyhow::{bail, Context};
use elements::{
    hashes::{sha256, Hash},
    secp256k1_zkp::{Secp256k1, XOnlyPublicKey},
    taproot::{LeafVersion, TaprootBuilder},
    Script,
};
use serde::{Deserialize, Serialize};
use std::{env, fs};

const KEYLESS_INTERNAL_KEY: &str =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const STATE_NODE_TAG: &str = "f076ba95e639debfd54278b05cfdd853e66bbabf8f10b72be02cd6a1ad37e950";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    program_cmr: String,
    state_commitment: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    program_cmr: String,
    state_commitment: String,
    state_node: String,
    merkle_root: String,
    state_script_hex: String,
    state_script_sha256: String,
    control_block_hex: String,
    internal_key: String,
    leaf_version: u8,
}

fn bytes32(value: &str, name: &str) -> anyhow::Result<[u8; 32]> {
    let value = hex::decode(value).with_context(|| format!("invalid {name} hex"))?;
    if value.len() != 32 {
        bail!("{name} must be 32 bytes")
    };
    Ok(value.try_into().expect("checked length"))
}

fn render(input: Input) -> anyhow::Result<Output> {
    let cmr = bytes32(&input.program_cmr, "program CMR")?;
    let state = bytes32(&input.state_commitment, "state commitment")?;
    let tag = bytes32(STATE_NODE_TAG, "state-node tag")?;
    let mut preimage = [0u8; 96];
    preimage[..32].copy_from_slice(&tag);
    preimage[32..64].copy_from_slice(&tag);
    preimage[64..].copy_from_slice(&state);
    let state_node = sha256::Hash::hash(&preimage);
    let leaf_version = LeafVersion::from_u8(0xbe).context("invalid Simplicity leaf version")?;
    let cmr_script = Script::from(cmr.to_vec());
    let internal_key = XOnlyPublicKey::from_slice(&bytes32(KEYLESS_INTERNAL_KEY, "internal key")?)
        .context("invalid keyless internal key")?;
    let secp = Secp256k1::verification_only();
    let spend = TaprootBuilder::new()
        .add_leaf_with_ver(1, cmr_script.clone(), leaf_version)?
        .add_hidden(1, state_node)?
        .finalize(&secp, internal_key)?;
    let control = spend
        .control_block(&(cmr_script.clone(), leaf_version))
        .context("transition leaf control block is absent")?;
    if !control.verify_taproot_commitment(&secp, &spend.output_key(), &cmr_script) {
        bail!("constructed control block failed self-verification")
    }
    let script = Script::new_v1_p2tr(&secp, internal_key, spend.merkle_root());
    Ok(Output {
        program_cmr: input.program_cmr,
        state_commitment: input.state_commitment,
        state_node: state_node.to_string(),
        merkle_root: spend
            .merkle_root()
            .context("missing merkle root")?
            .to_string(),
        state_script_hex: hex::encode(script.as_bytes()),
        state_script_sha256: sha256::Hash::hash(script.as_bytes()).to_string(),
        control_block_hex: hex::encode(control.serialize()),
        internal_key: KEYLESS_INTERNAL_KEY.into(),
        leaf_version: 0xbe,
    })
}

fn main() -> anyhow::Result<()> {
    let path = env::args()
        .nth(1)
        .context("usage: ecx-prediction-market-deployment INPUT_JSON")?;
    let input: Input = serde_json::from_slice(&fs::read(path)?)?;
    println!("{}", serde_json::to_string_pretty(&render(input)?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renders_a_self_authenticated_depth_one_simplicity_tree() {
        let out = render(Input {
            program_cmr: "11".repeat(32),
            state_commitment: "22".repeat(32),
        })
        .unwrap();
        assert_eq!(out.state_script_hex.len(), 68);
        assert_eq!(out.control_block_hex.len(), 130);
        assert_ne!(out.state_node, out.state_commitment);
    }
}
