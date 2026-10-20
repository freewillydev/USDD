use bitcoin::opcodes::Opcode;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::transaction::Version;
use bitcoin::{absolute, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use ecx_full_consensus_validator_v2::script_v2::*;
use ecx_full_consensus_validator_v2::{
    verify_bitcoin_transaction_structure_v2, BitcoinScriptVerifierV2, FullBitcoinScriptVerifierV2,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

const FROZEN_CORE_SCRIPT_SHA256: &str =
    "195d1ae4c1701ffa4e4b0ac14ba2b451da0e73fb22292656cd0f2196a78010db";
const FROZEN_EXECUTABLE_ROWS: usize = 1_207;
const FROZEN_NON_WITNESS_ROWS: usize = 1_077;
const FROZEN_CORE_TX_VALID_SHA256: &str =
    "a85d479081d6fd93188377e27fdfa099fa1a6aefdae565d0f473003c855d1e90";
const FROZEN_CORE_TX_INVALID_SHA256: &str =
    "0c02ce44ff3a880458f9569a25589315a07f924fcaadac828613d4615776ca52";
const FROZEN_TX_VALID_ROWS: usize = 120;
const FROZEN_TX_INVALID_ROWS: usize = 93;
const FROZEN_BIP341_WALLET_SHA256: &str =
    "403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f";
const FROZEN_TAPROOT_GENERATED_CORPUS_SHA256: &str =
    "3ffc161be6c53e2209897a082e9e0ca2461c1c19d6b89fce9338a30d6e3dc3db";
const FROZEN_TAPROOT_GENERATED_ROWS: usize = 2_751;
const FROZEN_TAPROOT_GENERATED_FAILURES: usize = 2_484;

fn decode_hex(token: &str) -> Result<Vec<u8>, String> {
    let hex = token
        .strip_prefix("0x")
        .ok_or_else(|| "missing hex prefix".to_owned())?;
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd hex token {token}"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|_| format!("invalid hex token {token}"))
        })
        .collect()
}

fn decode_bare_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd bare hex".to_owned());
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|_| "invalid bare hex".to_owned())
        })
        .collect()
}

fn opcode_byte(token: &str) -> Option<u8> {
    let canonical = match token {
        "FALSE" => return Some(0x00),
        "TRUE" => return Some(0x51),
        "1NEGATE" => return Some(0x4f),
        "NOP2" | "CHECKLOCKTIMEVERIFY" => "CLTV",
        "NOP3" | "CHECKSEQUENCEVERIFY" => "CSV",
        "INVALIDOPCODE" => return Some(0xff),
        token => token.strip_prefix("OP_").unwrap_or(token),
    };
    (0u16..=255).find_map(|code| {
        let code = code as u8;
        let display = Opcode::from(code).to_string();
        (display.strip_prefix("OP_") == Some(canonical)).then_some(code)
    })
}

fn append_push(output: &mut Vec<u8>, bytes: Vec<u8>) -> Result<(), String> {
    let push =
        PushBytesBuf::try_from(bytes).map_err(|_| "assembly push exceeds 4GiB".to_owned())?;
    output.extend_from_slice(Builder::new().push_slice(push).into_script().as_bytes());
    Ok(())
}

fn parse_core_script_assembly(assembly: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    for token in assembly.split_whitespace() {
        if token.starts_with("0x") {
            output.extend_from_slice(&decode_hex(token)?);
            continue;
        }
        if token.len() >= 2 && token.starts_with('\'') && token.ends_with('\'') {
            append_push(&mut output, token.as_bytes()[1..token.len() - 1].to_vec())?;
            continue;
        }
        if let Ok(number) = token.parse::<i64>() {
            output.extend_from_slice(Builder::new().push_int(number).into_script().as_bytes());
            continue;
        }
        let opcode = opcode_byte(token).ok_or_else(|| format!("unknown opcode token {token}"))?;
        output.push(opcode);
    }
    Ok(output)
}

fn frozen_corpus_path() -> Option<PathBuf> {
    std::env::var_os("BITCOIN_CORE_SOURCE")
        .map(PathBuf::from)
        .map(|source| source.join("src/test/data/script_tests.json"))
}

fn script_flags(flags: &str) -> Result<u32, String> {
    flags
        .split(',')
        .filter(|flag| !flag.is_empty())
        .try_fold(0u32, |mask, flag| {
            let value = match flag {
                "NONE" => 0,
                "P2SH" => SCRIPT_VERIFY_P2SH_V2,
                "STRICTENC" => SCRIPT_VERIFY_STRICTENC_V2,
                "DERSIG" => SCRIPT_VERIFY_DERSIG_V2,
                "LOW_S" => SCRIPT_VERIFY_LOW_S_V2,
                "NULLDUMMY" => SCRIPT_VERIFY_NULLDUMMY_V2,
                "SIGPUSHONLY" => SCRIPT_VERIFY_SIGPUSHONLY_V2,
                "MINIMALDATA" => SCRIPT_VERIFY_MINIMALDATA_V2,
                "DISCOURAGE_UPGRADABLE_NOPS" => SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS_V2,
                "CLEANSTACK" => SCRIPT_VERIFY_CLEANSTACK_V2,
                "CHECKLOCKTIMEVERIFY" => SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2,
                "CHECKSEQUENCEVERIFY" => SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2,
                "WITNESS" => SCRIPT_VERIFY_WITNESS_V2,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_V2
                }
                "MINIMALIF" => SCRIPT_VERIFY_MINIMALIF_V2,
                "NULLFAIL" => SCRIPT_VERIFY_NULLFAIL_V2,
                "WITNESS_PUBKEYTYPE" => SCRIPT_VERIFY_WITNESS_PUBKEYTYPE_V2,
                "CONST_SCRIPTCODE" => SCRIPT_VERIFY_CONST_SCRIPTCODE_V2,
                "TAPROOT" => SCRIPT_VERIFY_TAPROOT_V2,
                unknown => return Err(format!("unknown script flag {unknown}")),
            };
            Ok(mask | value)
        })
}

const ALL_FROZEN_SCRIPT_FLAGS: u32 = SCRIPT_VERIFY_P2SH_V2
    | SCRIPT_VERIFY_STRICTENC_V2
    | SCRIPT_VERIFY_DERSIG_V2
    | SCRIPT_VERIFY_LOW_S_V2
    | SCRIPT_VERIFY_NULLDUMMY_V2
    | SCRIPT_VERIFY_SIGPUSHONLY_V2
    | SCRIPT_VERIFY_MINIMALDATA_V2
    | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS_V2
    | SCRIPT_VERIFY_CLEANSTACK_V2
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2
    | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2
    | SCRIPT_VERIFY_WITNESS_V2
    | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_V2
    | SCRIPT_VERIFY_MINIMALIF_V2
    | SCRIPT_VERIFY_NULLFAIL_V2
    | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE_V2
    | SCRIPT_VERIFY_CONST_SCRIPTCODE_V2;

fn frozen_transaction_corpus_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("BITCOIN_CORE_SOURCE")
        .map(PathBuf::from)
        .map(|source| source.join("src/test/data").join(name))
}

fn frozen_generated_taproot_files() -> Option<Vec<(String, PathBuf)>> {
    let root = PathBuf::from(std::env::var_os("BITCOIN_TAPROOT_CORPUS")?);
    let mut files = Vec::new();
    for directory in fs::read_dir(&root).ok()? {
        let directory = directory.ok()?;
        if !directory.file_type().ok()?.is_dir() {
            continue;
        }
        for file in fs::read_dir(directory.path()).ok()? {
            let file = file.ok()?;
            if !file.file_type().ok()?.is_file() {
                continue;
            }
            let relative = file.path().strip_prefix(&root).ok()?.to_path_buf();
            let relative = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            files.push((relative, file.path()));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Some(files)
}

fn transaction_row_parts(row: &Value) -> Option<(&Vec<Value>, &str, &str)> {
    let fields = row.as_array()?;
    if fields.len() != 3 {
        return None;
    }
    Some((
        fields[0].as_array()?,
        fields[1].as_str()?,
        fields[2].as_str()?,
    ))
}

fn transaction_and_prevouts(
    inputs: &[Value],
    transaction_hex: &str,
) -> Result<(Transaction, Vec<TxOut>), String> {
    let bytes = decode_bare_hex(transaction_hex)?;
    let transaction: Transaction = bitcoin::consensus::deserialize(&bytes)
        .map_err(|error| format!("transaction decode: {error}"))?;
    let mut prevouts = HashMap::new();
    for input in inputs {
        let fields = input
            .as_array()
            .ok_or_else(|| "prevout row is not an array".to_owned())?;
        if !(3..=4).contains(&fields.len()) {
            return Err("prevout row length".to_owned());
        }
        let txid = bitcoin::Txid::from_str(
            fields[0]
                .as_str()
                .ok_or_else(|| "prevout txid".to_owned())?,
        )
        .map_err(|error| format!("prevout txid: {error}"))?;
        let raw_vout = fields[1]
            .as_i64()
            .ok_or_else(|| "prevout index".to_owned())?;
        let vout = raw_vout as u32;
        let script = parse_core_script_assembly(
            fields[2]
                .as_str()
                .ok_or_else(|| "prevout script".to_owned())?,
        )?;
        let value = match fields.get(3) {
            Some(value) => u64::try_from(value.as_i64().ok_or_else(|| "prevout value".to_owned())?)
                .map_err(|_| "negative prevout value".to_owned())?,
            None => 0,
        };
        prevouts.insert(
            OutPoint { txid, vout },
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(script),
            },
        );
    }
    let ordered = transaction
        .input
        .iter()
        .map(|input| {
            prevouts
                .get(&input.previous_output)
                .cloned()
                .ok_or_else(|| format!("missing prevout {}", input.previous_output))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((transaction, ordered))
}

fn verify_input_detailed(
    transaction: &Transaction,
    input_index: usize,
    previous_outputs: &[TxOut],
    flags: u32,
) -> Result<(), ScriptPrimitiveErrorV2> {
    let input = transaction
        .input
        .get(input_index)
        .ok_or(ScriptPrimitiveErrorV2::InvalidStack)?;
    if flags & SCRIPT_VERIFY_SIGPUSHONLY_V2 != 0
        && !script_is_push_only_v2(input.script_sig.as_bytes())?
    {
        return Err(ScriptPrimitiveErrorV2::BadOpcode);
    }
    let checker = LegacyEcdsaCheckerV2::new(
        transaction,
        input_index,
        flags & (SCRIPT_VERIFY_DERSIG_V2 | SCRIPT_VERIFY_LOW_S_V2 | SCRIPT_VERIFY_STRICTENC_V2)
            != 0,
        flags & SCRIPT_VERIFY_STRICTENC_V2 != 0,
        flags & SCRIPT_VERIFY_LOW_S_V2 != 0,
        flags & SCRIPT_VERIFY_CONST_SCRIPTCODE_V2 != 0,
    );
    verify_script_input_v2(
        transaction,
        input_index,
        previous_outputs,
        ScriptLockContextV2 {
            alpha_drivechain: false,
            transaction_version: transaction.version.0 as u32,
            transaction_lock_time: transaction.lock_time.to_consensus_u32(),
            input_sequence: input.sequence.to_consensus_u32(),
            check_lock_time_verify: flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2 != 0,
            check_sequence_verify: flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2 != 0,
            null_fail: flags & SCRIPT_VERIFY_NULLFAIL_V2 != 0,
            null_dummy: flags & SCRIPT_VERIFY_NULLDUMMY_V2 != 0,
            discourage_upgradable_nops: flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS_V2 != 0,
            const_script_code: flags & SCRIPT_VERIFY_CONST_SCRIPTCODE_V2 != 0,
            witness_v0: false,
        },
        &checker,
        LegacyScriptFlagsV2 {
            require_minimal_push: flags & SCRIPT_VERIFY_MINIMALDATA_V2 != 0,
            require_minimal_if: flags & SCRIPT_VERIFY_MINIMALIF_V2 != 0,
            verify_p2sh: flags & SCRIPT_VERIFY_P2SH_V2 != 0,
            clean_stack: flags & SCRIPT_VERIFY_CLEANSTACK_V2 != 0,
            verify_witness: flags & SCRIPT_VERIFY_WITNESS_V2 != 0,
            verify_taproot: flags & SCRIPT_VERIFY_TAPROOT_V2 != 0,
            witness_pubkey_type: flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE_V2 != 0,
            discourage_upgradable_witness_program: flags
                & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_V2
                != 0,
            strict_der: flags
                & (SCRIPT_VERIFY_DERSIG_V2 | SCRIPT_VERIFY_LOW_S_V2 | SCRIPT_VERIFY_STRICTENC_V2)
                != 0,
            strict_encoding: flags & SCRIPT_VERIFY_STRICTENC_V2 != 0,
            low_s: flags & SCRIPT_VERIFY_LOW_S_V2 != 0,
        },
    )
}

fn core_transaction_pair(
    script_sig: Vec<u8>,
    script_pubkey: Vec<u8>,
    value_atoms: u64,
    witness_items: &[Vec<u8>],
) -> (Transaction, TxOut) {
    let spent_output = TxOut {
        value: Amount::from_sat(value_atoms),
        script_pubkey: ScriptBuf::from_bytes(script_pubkey),
    };
    let credit = Transaction {
        version: Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![spent_output.clone()],
    };
    let mut witness = Witness::new();
    for item in witness_items {
        witness.push(item);
    }
    let spend = Transaction {
        version: Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: credit.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_atoms),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    (spend, spent_output)
}

#[test]
#[ignore = "requires the hash-pinned BITCOIN_CORE_SOURCE corpus; run explicitly with --ignored"]
fn frozen_core_assembly_adapter_covers_every_executable_script_row() {
    let path = frozen_corpus_path().expect("BITCOIN_CORE_SOURCE is required for this corpus test");
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        FROZEN_CORE_SCRIPT_SHA256
    );
    let corpus: Value = serde_json::from_slice(&bytes).unwrap();
    let rows = corpus.as_array().unwrap();
    let mut executable_rows = 0usize;
    let mut unsupported = BTreeSet::new();
    for row in rows {
        let Some(fields) = row.as_array() else {
            continue;
        };
        let offset = usize::from(fields.first().is_some_and(Value::is_array));
        if fields.len() < offset + 4 || !(0..4).all(|index| fields[offset + index].is_string()) {
            continue;
        }
        executable_rows += 1;
        for script_index in [offset, offset + 1] {
            let assembly = fields[script_index].as_str().unwrap();
            if let Err(error) = parse_core_script_assembly(assembly) {
                unsupported.insert(error);
            }
        }
    }
    assert_eq!(executable_rows, FROZEN_EXECUTABLE_ROWS);
    assert!(
        unsupported.is_empty(),
        "unsupported frozen assembly: {unsupported:#?}"
    );
}

#[test]
#[ignore = "requires the hash-pinned BITCOIN_CORE_SOURCE corpus; run explicitly with --ignored"]
fn frozen_core_non_witness_rows_match_accept_reject_result() {
    let path = frozen_corpus_path().expect("BITCOIN_CORE_SOURCE is required for this corpus test");
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        FROZEN_CORE_SCRIPT_SHA256
    );
    let corpus: Value = serde_json::from_slice(&bytes).unwrap();
    let mut checked = 0usize;
    let mut mismatches = Vec::new();
    for (row_index, row) in corpus.as_array().unwrap().iter().enumerate() {
        let Some(fields) = row.as_array() else {
            continue;
        };
        if fields.first().is_some_and(Value::is_array)
            || fields.len() < 4
            || !(0..4).all(|index| fields[index].is_string())
        {
            continue;
        }
        let script_sig = parse_core_script_assembly(fields[0].as_str().unwrap()).unwrap();
        let script_pubkey = parse_core_script_assembly(fields[1].as_str().unwrap()).unwrap();
        let flags_text = fields[2].as_str().unwrap();
        if flags_text.split(',').any(|flag| flag == "WITNESS") {
            continue;
        }
        let flags = script_flags(flags_text).unwrap();
        let expected_ok = fields[3].as_str().unwrap() == "OK";
        let (transaction, spent_output) = core_transaction_pair(script_sig, script_pubkey, 0, &[]);
        let actual_ok = FullBitcoinScriptVerifierV2
            .verify_input(&transaction, 0, std::slice::from_ref(&spent_output), flags)
            .is_ok();
        checked += 1;
        if actual_ok != expected_ok {
            mismatches.push((row_index, fields[3].as_str().unwrap().to_owned(), actual_ok));
        }
    }
    assert_eq!(checked, FROZEN_NON_WITNESS_ROWS);
    assert!(
        mismatches.is_empty(),
        "{} Core non-witness mismatches; first 30: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(30)]
    );
}

#[test]
#[ignore = "requires the hash-pinned BITCOIN_CORE_SOURCE corpus; run explicitly with --ignored"]
fn frozen_core_all_script_rows_match_accept_reject_result() {
    let path = frozen_corpus_path().expect("BITCOIN_CORE_SOURCE is required for this corpus test");
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        FROZEN_CORE_SCRIPT_SHA256
    );
    let corpus: Value = serde_json::from_slice(&bytes).unwrap();
    let mut checked = 0usize;
    let mut mismatches = Vec::new();
    for (row_index, row) in corpus.as_array().unwrap().iter().enumerate() {
        let Some(fields) = row.as_array() else {
            continue;
        };
        let offset = usize::from(fields.first().is_some_and(Value::is_array));
        if fields.len() < offset + 4 || !(0..4).all(|index| fields[offset + index].is_string()) {
            continue;
        }
        let script_sig = parse_core_script_assembly(fields[offset].as_str().unwrap()).unwrap();
        let script_pubkey =
            parse_core_script_assembly(fields[offset + 1].as_str().unwrap()).unwrap();
        let flags = script_flags(fields[offset + 2].as_str().unwrap()).unwrap();
        let expected_ok = fields[offset + 3].as_str().unwrap() == "OK";
        let (witness_items, value_atoms) = if offset == 1 {
            let witness = fields[0].as_array().unwrap();
            let amount = witness.last().unwrap().as_f64().unwrap();
            let atoms = (amount * 100_000_000.0).round() as u64;
            let items = witness[..witness.len() - 1]
                .iter()
                .map(|item| decode_hex(&format!("0x{}", item.as_str().unwrap())).unwrap())
                .collect::<Vec<_>>();
            (items, atoms)
        } else {
            (Vec::new(), 0)
        };
        let (transaction, spent_output) =
            core_transaction_pair(script_sig, script_pubkey, value_atoms, &witness_items);
        let actual_ok = FullBitcoinScriptVerifierV2
            .verify_input(&transaction, 0, std::slice::from_ref(&spent_output), flags)
            .is_ok();
        checked += 1;
        if actual_ok != expected_ok {
            mismatches.push((
                row_index,
                fields[offset + 3].as_str().unwrap().to_owned(),
                actual_ok,
            ));
        }
    }
    assert_eq!(checked, FROZEN_EXECUTABLE_ROWS);
    assert!(
        mismatches.is_empty(),
        "{} Core full-script mismatches; first 40: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(40)]
    );
}

#[test]
#[ignore = "requires the hash-pinned BITCOIN_CORE_SOURCE corpus; run explicitly with --ignored"]
fn frozen_core_valid_transaction_rows_match_structure_and_scripts() {
    let path = frozen_transaction_corpus_path("tx_valid.json")
        .expect("BITCOIN_CORE_SOURCE is required for this corpus test");
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        FROZEN_CORE_TX_VALID_SHA256
    );
    let corpus: Value = serde_json::from_slice(&bytes).unwrap();
    let mut checked = 0usize;
    let mut mismatches = Vec::new();
    for (row_index, row) in corpus.as_array().unwrap().iter().enumerate() {
        let Some((inputs, transaction_hex, excluded_flags)) = transaction_row_parts(row) else {
            continue;
        };
        let (transaction, prevouts) = transaction_and_prevouts(inputs, transaction_hex).unwrap();
        let excluded = script_flags(excluded_flags).unwrap();
        let flags = ALL_FROZEN_SCRIPT_FLAGS & !excluded;
        let structure_ok = verify_bitcoin_transaction_structure_v2(&transaction).is_ok();
        let errors = (0..transaction.input.len())
            .filter_map(|input_index| {
                verify_input_detailed(&transaction, input_index, &prevouts, flags)
                    .err()
                    .map(|error| (input_index, error))
            })
            .collect::<Vec<_>>();
        let scripts_ok = structure_ok && errors.is_empty();
        checked += 1;
        if !scripts_ok {
            mismatches.push((row_index, structure_ok, excluded_flags.to_owned(), errors));
        }
    }
    assert_eq!(checked, FROZEN_TX_VALID_ROWS);
    assert!(
        mismatches.is_empty(),
        "{} Core valid-transaction mismatches; first 30: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(30)]
    );
}

#[test]
#[ignore = "requires the hash-pinned BITCOIN_CORE_SOURCE corpus; run explicitly with --ignored"]
fn frozen_core_invalid_transaction_rows_match_structure_or_scripts() {
    let path = frozen_transaction_corpus_path("tx_invalid.json")
        .expect("BITCOIN_CORE_SOURCE is required for this corpus test");
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        FROZEN_CORE_TX_INVALID_SHA256
    );
    let corpus: Value = serde_json::from_slice(&bytes).unwrap();
    let mut checked = 0usize;
    let mut mismatches = Vec::new();
    for (row_index, row) in corpus.as_array().unwrap().iter().enumerate() {
        let Some((inputs, transaction_hex, flags_text)) = transaction_row_parts(row) else {
            continue;
        };
        let (transaction, prevouts) = transaction_and_prevouts(inputs, transaction_hex).unwrap();
        let structure_ok = verify_bitcoin_transaction_structure_v2(&transaction).is_ok();
        let actual_invalid = if flags_text == "BADTX" {
            !structure_ok
        } else {
            let flags = script_flags(flags_text).unwrap();
            structure_ok
                && (0..transaction.input.len()).any(|input_index| {
                    FullBitcoinScriptVerifierV2
                        .verify_input(&transaction, input_index, &prevouts, flags)
                        .is_err()
                })
        };
        checked += 1;
        if !actual_invalid {
            mismatches.push((row_index, structure_ok, flags_text.to_owned()));
        }
    }
    assert_eq!(checked, FROZEN_TX_INVALID_ROWS);
    assert!(
        mismatches.is_empty(),
        "{} Core invalid-transaction mismatches; first 30: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(30)]
    );
}

#[test]
#[ignore = "requires the hash-pinned BITCOIN_CORE_SOURCE corpus; run explicitly with --ignored"]
fn frozen_bip341_fully_signed_wallet_vector_verifies_every_input() {
    let path = frozen_transaction_corpus_path("bip341_wallet_vectors.json")
        .expect("BITCOIN_CORE_SOURCE is required for this corpus test");
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        FROZEN_BIP341_WALLET_SHA256
    );
    let corpus: Value = serde_json::from_slice(&bytes).unwrap();
    let vector = &corpus["keyPathSpending"][0];
    let transaction_hex = vector["auxiliary"]["fullySignedTx"].as_str().unwrap();
    let transaction: Transaction =
        bitcoin::consensus::deserialize(&decode_bare_hex(transaction_hex).unwrap()).unwrap();
    let prevouts = vector["given"]["utxosSpent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|utxo| TxOut {
            value: Amount::from_sat(utxo["amountSats"].as_u64().unwrap()),
            script_pubkey: ScriptBuf::from_bytes(
                decode_bare_hex(utxo["scriptPubKey"].as_str().unwrap()).unwrap(),
            ),
        })
        .collect::<Vec<_>>();
    assert_eq!(transaction.input.len(), prevouts.len());
    verify_bitcoin_transaction_structure_v2(&transaction).unwrap();
    let flags = ALL_FROZEN_SCRIPT_FLAGS | SCRIPT_VERIFY_TAPROOT_V2;
    for input_index in 0..transaction.input.len() {
        verify_input_detailed(&transaction, input_index, &prevouts, flags)
            .unwrap_or_else(|error| panic!("BIP341 input {input_index}: {error:?}"));
    }
}

fn apply_generated_spend_mutation(
    base: &Transaction,
    input_index: usize,
    mutation: &Value,
) -> Transaction {
    let mut transaction = base.clone();
    let input = &mut transaction.input[input_index];
    if let Some(script_sig) = mutation.get("scriptSig") {
        input.script_sig =
            ScriptBuf::from_bytes(decode_bare_hex(script_sig.as_str().unwrap()).unwrap());
    }
    if let Some(witness) = mutation.get("witness") {
        let mut decoded = Witness::new();
        for item in witness.as_array().unwrap() {
            decoded.push(decode_bare_hex(item.as_str().unwrap()).unwrap());
        }
        input.witness = decoded;
    }
    transaction
}

#[test]
#[ignore = "requires the hash-pinned BITCOIN_TAPROOT_CORPUS; run explicitly with --ignored"]
fn generated_core_taproot_spending_corpus_matches_all_outcomes() {
    let files = frozen_generated_taproot_files()
        .expect("BITCOIN_TAPROOT_CORPUS is required for this corpus test");
    let mut corpus_hash = Sha256::new();
    let mut rows = 0usize;
    let mut failures = 0usize;
    let mut mismatches = Vec::new();
    for (relative, path) in &files {
        let bytes = fs::read(path).unwrap();
        corpus_hash.update(u32::try_from(relative.len()).unwrap().to_be_bytes());
        corpus_hash.update(relative.as_bytes());
        corpus_hash.update(u64::try_from(bytes.len()).unwrap().to_be_bytes());
        corpus_hash.update(&bytes);
        let text = std::str::from_utf8(&bytes).unwrap().trim();
        let row: Value = serde_json::from_str(text.trim_end_matches(',')).unwrap();
        let transaction: Transaction =
            bitcoin::consensus::deserialize(&decode_bare_hex(row["tx"].as_str().unwrap()).unwrap())
                .unwrap();
        let previous_outputs = row["prevouts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|output| {
                bitcoin::consensus::deserialize(&decode_bare_hex(output.as_str().unwrap()).unwrap())
                    .unwrap()
            })
            .collect::<Vec<TxOut>>();
        let input_index = row["index"].as_u64().unwrap() as usize;
        let flags = script_flags(row["flags"].as_str().unwrap()).unwrap();
        let comment = row["comment"].as_str().unwrap().to_owned();
        let success = apply_generated_spend_mutation(&transaction, input_index, &row["success"]);
        if let Err(error) = verify_input_detailed(&success, input_index, &previous_outputs, flags) {
            mismatches.push((relative.clone(), comment.clone(), "success", error));
        }
        if let Some(failure) = row.get("failure") {
            failures += 1;
            let failure = apply_generated_spend_mutation(&transaction, input_index, failure);
            if verify_input_detailed(&failure, input_index, &previous_outputs, flags).is_ok() {
                mismatches.push((
                    relative.clone(),
                    comment.clone(),
                    "failure",
                    ScriptPrimitiveErrorV2::Verify,
                ));
            }
        }
        rows += 1;
    }
    assert_eq!(rows, FROZEN_TAPROOT_GENERATED_ROWS);
    assert_eq!(failures, FROZEN_TAPROOT_GENERATED_FAILURES);
    assert_eq!(
        format!("{:x}", corpus_hash.finalize()),
        FROZEN_TAPROOT_GENERATED_CORPUS_SHA256
    );
    if !mismatches.is_empty() {
        let mut grouped = std::collections::BTreeMap::new();
        for (_, comment, outcome, error) in &mismatches {
            *grouped
                .entry((comment.clone(), *outcome, format!("{error:?}")))
                .or_insert(0usize) += 1;
        }
        eprintln!("generated Taproot mismatch groups:");
        for (key, count) in grouped {
            eprintln!("{count}\t{key:?}");
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} generated Taproot mismatches; first 30: {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(30)]
    );
}
