//! Offline structural inspection only. Does not authorize a trusted checkpoint.
use ecx_truthcoin_replay::{CanonicalStateEntryV1, CanonicalStateSnapshotV1,
    TRUTHCOIN_STATE_DATABASE_NAMES};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture { format: String, qualification: String, missing_tables: Vec<String>,
    raw_bytes: usize, tables: Vec<Table> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table { name: String, entries: Vec<Entry> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry { key_hex: String, value_hex: String }

fn unhex(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("noncanonical hex".into());
    }
    (0..s.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&s[i..i+2], 16)?)).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn canonicalize(bytes: &[u8], expected: &str) -> Result<(CanonicalStateSnapshotV1, serde_json::Value), Box<dyn Error>> {
    if bytes.len() > 128 * 1024 * 1024 || hex(&Sha256::digest(bytes)) != expected {
        return Err("capture hash or size mismatch".into());
    }
    let capture: Capture = serde_json::from_slice(bytes)?;
    if capture.format != "native-truthcoin-raw-state-capture-v1"
        || capture.qualification != "unreviewed; not a canonical checkpoint or proof"
        || capture.missing_tables != ["market_transition_undo", "mainchain_timestamp_undo"] {
        return Err("unexpected capture schema or missing table set".into());
    }
    let mut snapshot = CanonicalStateSnapshotV1::empty();
    let mut seen = BTreeSet::new();
    let mut raw = 0usize;
    for table in capture.tables {
        let id = TRUTHCOIN_STATE_DATABASE_NAMES.iter().position(|n| *n == table.name)
            .ok_or("unknown table")?;
        if !seen.insert(id) || capture.missing_tables.contains(&table.name) {
            return Err("duplicate or contradictory table".into());
        }
        for entry in table.entries {
            let key = unhex(&entry.key_hex)?;
            let value = unhex(&entry.value_hex)?;
            raw = raw.checked_add(key.len()).and_then(|v| v.checked_add(value.len()))
                .ok_or("size overflow")?;
            snapshot.tables[id].entries.push(CanonicalStateEntryV1 { key, value });
        }
    }
    if seen.len() != 35 || raw != capture.raw_bytes { return Err("incomplete capture".into()); }
    snapshot.validate()?;
    let singleton = |name: &str| -> Result<&[u8], Box<dyn Error>> {
        let id = TRUTHCOIN_STATE_DATABASE_NAMES.iter().position(|n| *n == name).unwrap();
        let entries = &snapshot.tables[id].entries;
        if entries.len() != 1 || entries[0].key != [0x69] { return Err("invalid singleton".into()); }
        Ok(&entries[0].value)
    };
    let tip = singleton("tip")?;
    if tip.len() != 32 { return Err("invalid tip".into()); }
    let height = u32::from_le_bytes(singleton("height")?.try_into()?);
    let timestamp = u64::from_le_bytes(singleton("mainchain_timestamp")?.try_into()?);
    let encoded = snapshot.encode()?;
    if CanonicalStateSnapshotV1::decode(&encoded)? != snapshot { return Err("roundtrip mismatch".into()); }
    let report = serde_json::json!({"capture_sha256":expected,"native_height":height,
        "native_tip_hex":hex(tip),"native_timestamp":timestamp,"raw_bytes_preserved":raw,
        "structural_roundtrip":true,"provisional_canonical_bytes":encoded.len(),
        "provisional_canonical_sha256":hex(&Sha256::digest(&encoded)),
        "proof_ready":false,"oracle_history_complete":false,
        "restriction":"Missing history tables are empty only for structural inspection; do not use with the existing oracle extractor. A reviewed bootstrap must bind the floor and prevent pre-floor rollback and historical sample claims."});
    Ok((snapshot, report))
}

#[cfg(test)]
fn inspect(bytes: &[u8], expected: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(canonicalize(bytes, expected)?.1)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && args.len() != 4 { return Err("usage: inspect CAPTURE EXPECTED_SHA256 [NEW_CANONICAL_OUTPUT]".into()); }
    let bytes = std::fs::read(&args[1])?;
    let (snapshot, report) = canonicalize(&bytes, &args[2])?;
    if let Some(path) = args.get(3) {
        use std::io::Write;
        let encoded = snapshot.encode()?;
        let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        output.write_all(&encoded)?;
        output.sync_all()?;
        if std::fs::read(path)? != encoded { return Err("output readback mismatch".into()); }
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_unpinned_capture_and_noncanonical_hex() {
        assert!(inspect(b"{}", &"0".repeat(64)).is_err());
        assert!(unhex("0A").is_err());
        assert!(unhex("0").is_err());
        assert_eq!(unhex("0069ff").unwrap(), [0, 105, 255]);
    }
}
