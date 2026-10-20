//! Offline check of the captured native tip's parent inclusion. No state writes.
use ecx_truthcoin_replay::{verify_truthcoin_checkpoint_inclusion, CoinbaseInclusionV1, MainchainHeaderV1};
use sha2::{Digest, Sha256};
use ecx_truthcoin_replay::{CanonicalStateSnapshotV1, ReviewedNativeBootstrapV1,
    StateMachineCheckpointV1, TruthcoinBip300CheckpointStateV1, Bip300CtipV1};

fn hash32(text: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut result = [0; 32];
    if text.len() != 64 { return Err("invalid hash length".into()); }
    for (i, byte) in result.iter_mut().enumerate() { *byte = u8::from_str_radix(&text[i*2..i*2+2], 16)?; }
    Ok(result)
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected bitcoin-replay.json path")?;
    let bytes = std::fs::read(path)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != "00c1f402a48c424dccb02ad05c3251b774e354b6b008af31a95e645d33ca06db" {
        return Err("captured parent evidence hash mismatch".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let headers: Vec<MainchainHeaderV1> = serde_json::from_value(value["mainchain_headers"].clone())?;
    let inclusions: Vec<CoinbaseInclusionV1> = serde_json::from_value(value["coinbase_inclusions"].clone())?;
    let header = headers.iter().find(|h| h.height == 996717).ok_or("missing parent")?;
    let inclusion = inclusions.iter().find(|h| h.height == 996717).ok_or("missing inclusion")?;
    let expected = "d666deb13569dd47a0c06dbc806c8e86d21f50258cc28f5e17923aa47c108528";
    let found = verify_truthcoin_checkpoint_inclusion(header, inclusion)?.ok_or("missing M7")?;
    if hex::encode(found) != expected { return Err("native checkpoint tip mismatch".into()); }
    let mut parent_hash = Sha256::digest(Sha256::digest(&header.consensus_header)).to_vec();
    parent_hash.reverse();
    if hex::encode(&parent_hash) != "0000000000000000fcd2fe77ec33bf86cf02007006ede86db8aa0f85e8ead521" {
        return Err("parent hash mismatch".into());
    }
    let timestamp = u32::from_le_bytes(header.consensus_header[68..72].try_into()?);
    if timestamp != 1788307897 { return Err("native snapshot clock mismatch".into()); }
    let mut altered = inclusion.clone();
    altered.merkle_siblings[0][0] ^= 1;
    if verify_truthcoin_checkpoint_inclusion(header, &altered).is_ok() {
        return Err("altered Merkle branch was accepted".into());
    }
    // Optional draft materialization uses only the previously inspected native
    // bytes. Authentication remains explicitly unavailable until the guest is
    // finalized; a zero digest ensures this draft cannot pass import.
    if let Some(snapshot_path) = std::env::args().nth(2) {
        use std::io::Write;
        let output_path = std::env::args().nth(3).ok_or("missing NEW draft output path")?;
        if std::env::args().count() != 4 { return Err("unexpected arguments".into()); }
        let state_bytes = std::fs::read(snapshot_path)?;
        if hex::encode(Sha256::digest(&state_bytes)) != "fa854f4331c3cc66fff2c86afd54f92ec4f4851943208662bce9b48636f528a0" {
            return Err("canonical native snapshot hash mismatch".into());
        }
        let snapshot = CanonicalStateSnapshotV1::decode(&state_bytes)?;
        let mut times = Vec::new();
        let mut previous_hash = None;
        for height in header.height-10..=header.height {
            let h = headers.iter().find(|h| h.height == height).ok_or("missing MTP header")?;
            if h.consensus_header.len() != 80 { return Err("invalid header size".into()); }
            if let Some(previous) = previous_hash {
                if h.consensus_header[4..36] != previous { return Err("MTP header linkage mismatch".into()); }
            }
            previous_hash = Some(<[u8;32]>::from(Sha256::digest(Sha256::digest(&h.consensus_header))));
            times.push(u32::from_le_bytes(h.consensus_header[68..72].try_into()?));
        }
        times.sort_unstable();
        let mut ctip_txid = hash32("753231a3a2b72b5d92034e93245d3f023522a36e0b808a0ed23c2786c65a8773")?;
        ctip_txid.reverse(); // Bitcoin consensus byte order, not display order.
        let draft = ReviewedNativeBootstrapV1 {
            version: 2,
            native_capture_sha256: hash32("ff30db2e431336d84391a100cf641b5afe4d456453d84081548939d22354efcc")?,
            checkpoint: StateMachineCheckpointV1 {
                version: 1, trusted_start: None, authentication_config_hash: [0;32],
                market_template_hash: hash32("974866e2f18868140ee8eed313f2e1a68dd35aa6572d2a087e93a07b25487911")?,
                sidechain_tip_hash: found, sidechain_tip_height: 13,
                replayed_state_root: snapshot.root()?, state_bytes,
            },
            parent: header.clone(), inclusion: inclusion.clone(), parent_mtp: u64::from(times[5]),
            bip300: TruthcoinBip300CheckpointStateV1 {
                version: 1, truthcoin_slot_active: true,
                ctip: Some(Bip300CtipV1 { txid: ctip_txid, vout: 0, value_sats: 24_120_000, sequence_number: 2 }),
            },
        };
        if draft.import(draft.commitment(), [0;32]).is_ok() { return Err("draft incorrectly importable".into()); }
        let artifact = serde_json::json!({
            "qualification":"DRAFT: no authenticated configuration; historical CTIP sequence/activation require reviewed trust binding",
            "bootstrap":draft, "proposed_bootstrap_commitment":hex::encode(draft.commitment()),
            "parent_evidence_sha256":digest, "proof_ready":false
        });
        let encoded = serde_json::to_vec_pretty(&artifact)?;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&output_path)?;
        file.write_all(&encoded)?; file.sync_all()?;
        if std::fs::read(&output_path)? != encoded { return Err("draft readback mismatch".into()); }
        eprintln!("draft_sha256={} proposed_pin={} mtp={}", hex::encode(Sha256::digest(&encoded)), hex::encode(draft.commitment()), times[5]);
    }
    println!("{}", serde_json::json!({
        "parent_evidence_sha256": digest, "parent_height": header.height,
        "parent_hash": hex::encode(parent_hash), "native_tip": expected,
        "native_clock_matches_parent_timestamp": true,
        "coinbase_merkle_and_slot13_m7_verified": true,
        "altered_merkle_branch_rejected": true,
        "ctip_verified": false, "bootstrap_ready": false,
        "restriction": "Inclusion evidence only; reviewed trust-root binding and CTIP authentication remain required."
    }));
    Ok(())
}
