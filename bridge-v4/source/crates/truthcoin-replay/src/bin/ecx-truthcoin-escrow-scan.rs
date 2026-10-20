//! Offline, bounded-per-block discovery. Not a replacement for consensus replay.
use bitcoin::{consensus::{deserialize, serialize}, Block, OutPoint};
use serde::{Deserialize, Deserializer, de::{Visitor, SeqAccess, Error}};
use sha2::{Digest, Sha256};
use std::{fmt, fs::File, io::{BufReader, Read}};

#[derive(Deserialize)]
struct Export {
    schema: String,
    checkpoint_height: u64,
    tip_height: u64,
    #[serde(deserialize_with = "scan")]
    blocks: Scan,
}
#[derive(Deserialize)]
struct Record { height: u64, block_hash_display: String, serialized_block: Vec<u8> }
struct Scan { count: u64, first: u64, last: u64, events: Vec<serde_json::Value> }
fn scan<'de, D: Deserializer<'de>>(d: D) -> Result<Scan, D::Error> {
    struct Scanner;
    impl<'de> Visitor<'de> for Scanner {
        type Value = Scan;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("complete block array") }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Scan, A::Error> {
            let mut out = Scan { count: 0, first: 0, last: 0, events: vec![] };
            let mut previous_hash = None;
            let mut tracked: Option<OutPoint> = None;
            while let Some(r) = a.next_element::<Record>()? {
                let b: Block = deserialize(&r.serialized_block).map_err(A::Error::custom)?;
                if serialize(&b) != r.serialized_block || b.block_hash().to_string() != r.block_hash_display
                    || !b.check_merkle_root() || b.txdata.is_empty()
                    || b.txdata.iter().enumerate().any(|(i,t)| t.is_coinbase() != (i == 0))
                    || previous_hash.is_some_and(|p| p != b.header.prev_blockhash)
                    || (out.count != 0 && r.height != out.last + 1)
                { return Err(A::Error::custom("block identity/merkle/continuity mismatch")); }
                if out.count == 0 { out.first = r.height; }
                out.count += 1; out.last = r.height; previous_hash = Some(b.block_hash());
                for t in &b.txdata {
                    let targets: Vec<_> = t.output.iter().enumerate()
                        .filter(|(_,o)| o.script_pubkey.as_bytes() == [0xb4, 0x01, 13, 0x51]).collect();
                    let spends = tracked.is_some_and(|p| t.input.iter().any(|i| i.previous_output == p));
                    if targets.len() > 1 { return Err(A::Error::custom("duplicate escrow outputs")); }
                    if targets.is_empty() && !spends { continue; }
                    let prior = tracked.map(|p| p.to_string());
                    let next = targets.first().map(|(v,_)| OutPoint { txid: t.compute_txid(), vout: *v as u32 });
                    out.events.push(serde_json::json!({
                        "height": r.height, "block_hash": r.block_hash_display,
                        "txid": t.compute_txid().to_string(), "prior_tracked": prior,
                        "spends_prior_tracked": spends, "new_outpoint": next.map(|p|p.to_string()),
                        "value_atoms": targets.first().map(|(_,o)|o.value.to_sat()),
                        "inputs": t.input.iter().map(|i|i.previous_output.to_string()).collect::<Vec<_>>()
                    }));
                    tracked = next;
                }
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Scanner)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected saved full-block export")?;
    let mut file = File::open(&path)?;
    let mut hash = Sha256::new(); let mut buffer = [0; 65536];
    loop { let n = file.read(&mut buffer)?; if n == 0 { break; } hash.update(&buffer[..n]); }
    let digest: String = hash.finalize().iter().map(|b|format!("{b:02x}")).collect();
    if digest != "9f3b080d45ba4be08030dc333be7cf8d78a15583051407c2a780f49555f244dc" {
        return Err("full-block export hash mismatch".into());
    }
    let export: Export = serde_json::from_reader(BufReader::new(File::open(path)?))?;
    if export.schema != "ecx-truthcoin-alpha-bitcoin-full-block-export-v1"
        || export.checkpoint_height != export.blocks.first || export.tip_height != export.blocks.last
        || export.blocks.count != export.tip_height - export.checkpoint_height + 1 {
        return Err("export range mismatch".into());
    }
    println!("{}", serde_json::json!({"export_sha256": digest,
        "blocks_verified": export.blocks.count, "events": export.blocks.events,
        "restriction": "Discovery only: initial CTIP, activation state, sequence number and canonical trust-root review are not established by this scan."}));
    Ok(())
}
