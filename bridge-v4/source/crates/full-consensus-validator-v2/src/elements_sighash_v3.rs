//! Raw-byte Elements ECDSA sighashes derived from native SignatureHash.
//! Script execution must supply the executed script suffix; legacy callers
//! additionally remove the signature push before invoking this function.
use elements::{Transaction, Script, TxOut, EcdsaSighashType};
use elements::confidential::Value;
use elements::encode::{serialize, VarInt};
use elements::hashes::{sha256d, Hash};
use elements::sighash::SighashCache;
use crate::script_v2::{remove_code_separators_v2, ScriptPrimitiveErrorV2};

fn hash(bytes: &[u8]) -> [u8;32] { sha256d::Hash::hash(bytes).to_byte_array() }
fn proofs(output: &TxOut, bytes: &mut Vec<u8>) {
    // Native order differs from normal output-witness serialization.
    let range = output.witness.rangeproof.as_ref().map(|p| p.serialize()).unwrap_or_default();
    let surjection = output.witness.surjection_proof.as_ref().map(|p| p.serialize()).unwrap_or_default();
    bytes.extend(serialize(&range)); bytes.extend(serialize(&surjection));
}

pub fn elements_ecdsa_sighash_v3(
    tx: &Transaction, index: usize, script: &[u8], value: Option<Value>,
    raw_type: u8, rangeproof_active: bool,
) -> Result<[u8;32], ScriptPrimitiveErrorV2> {
    if index >= tx.input.len() { return Err(ScriptPrimitiveErrorV2::InvalidStack); }
    let base = raw_type & 0x1f;
    let single = base == 3; let none = base == 2; let anyone = raw_type & 0x80 != 0;
    let rangeproof = rangeproof_active && raw_type & 0x40 != 0;
    let mut bytes = Vec::new();
    if let Some(value) = value {
        // Select only branching semantics through the enum, then preserve the
        // original byte in the final 32-bit sighash field below.
        let normalized = (if single {3} else if none {2} else {1}) | (raw_type & 0x80);
        SighashCache::new(tx).encode_segwitv0_signing_data_to(&mut bytes, index,
            &Script::from(script.to_vec()), value, EcdsaSighashType::from_u32(normalized.into()))
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        let tail = bytes.len().checked_sub(8).ok_or(ScriptPrimitiveErrorV2::Signature)?;
        bytes.truncate(tail); // Re-append locktime after optional rangeproof hash.
        if rangeproof {
            let mut proof_bytes = Vec::new();
            let proof_hash = if none || (single && index >= tx.output.len()) { [0;32] }
                else {
                    if single { proofs(&tx.output[index], &mut proof_bytes); }
                    else { for output in &tx.output { proofs(output, &mut proof_bytes); } }
                    hash(&proof_bytes)
                };
            bytes.extend(proof_hash);
        }
    } else {
        if single && index >= tx.output.len() {
            let mut one = [0;32]; one[0] = 1; return Ok(one);
        }
        let cleaned = Script::from(remove_code_separators_v2(script)?);
        let empty = Script::new();
        bytes.extend(serialize(&tx.version));
        bytes.extend(serialize(&VarInt(if anyone {1} else {tx.input.len() as u64})));
        for (i,input) in tx.input.iter().enumerate() {
            if anyone && i != index { continue; }
            // Native serializer writes the bare prevout, not TxIn's wire flags.
            bytes.extend(serialize(&input.previous_output));
            bytes.extend(serialize(if i == index {&cleaned} else {&empty}));
            bytes.extend(serialize(&(if i != index && (single || none) {0} else {input.sequence.0})));
            if input.has_issuance() { bytes.extend(serialize(&input.asset_issuance)); }
        }
        let count = if none {0} else if single {index+1} else {tx.output.len()};
        bytes.extend(serialize(&VarInt(count as u64)));
        for (i,output) in tx.output.iter().take(count).enumerate() {
            if single && i != index { bytes.extend(serialize(&TxOut::default())); }
            else { bytes.extend(serialize(output)); if rangeproof { proofs(output,&mut bytes); } }
        }
    }
    bytes.extend(serialize(&tx.lock_time));
    bytes.extend(u32::from(raw_type).to_le_bytes());
    Ok(hash(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{TxIn, LockTime};
    #[test]
    fn matches_native_elements_sighash_vectors() {
        let corpus = include_str!("../test-vectors/native-elements-sighash.txt");
        assert_eq!(hex::encode(elements::hashes::sha256::Hash::hash(corpus.as_bytes()).to_byte_array()),
            "ea964be664cc62514b056792bf17dee40480519615dac40df3646c2c9df70d46");
        let mut count = 0;
        for line in corpus.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(),8);
            let tx: Transaction = elements::encode::deserialize(&hex::decode(fields[1]).unwrap()).unwrap();
            let script = hex::decode(fields[2]).unwrap();
            let index = fields[3].parse().unwrap();
            let value = if fields[4]=="1" {Some(Value::Explicit(10))} else {None};
            let range = fields[5]=="1";
            let raw = fields[6].parse().unwrap();
            let actual = elements_ecdsa_sighash_v3(&tx,index,&script,value,raw,range).unwrap();
            assert_eq!(hex::encode(actual),fields[7],"variant={} index={index} witness={} range={range} raw={raw}",fields[0],fields[4]);
            count += 1;
        }
        assert_eq!(count,8192);
    }
    #[test]
    fn standard_types_match_dependency_and_raw_bits_are_preserved() {
        let tx = Transaction {version:2,lock_time:LockTime::ZERO,
            input:vec![TxIn::default(),TxIn::default()],output:vec![TxOut::default(),TxOut::default()]};
        let script = Script::from(vec![0x51]);
        for index in 0..2 { for value in [None,Some(Value::Explicit(10))] {
            for raw in [1u8,2,3,0x81,0x82,0x83] {
                let kind = EcdsaSighashType::from_u32(raw.into());
                let expected = if let Some(v) = value {
                    SighashCache::new(&tx).segwitv0_sighash(index,&script,v,kind).to_byte_array()
                } else {SighashCache::new(&tx).legacy_sighash(index,&script,kind).to_byte_array()};
                assert_eq!(elements_ecdsa_sighash_v3(&tx,index,script.as_bytes(),value,raw,false).unwrap(),expected);
            }
            let mut hashes = std::collections::HashSet::new();
            for raw in 0..=255u8 {
                let digest = elements_ecdsa_sighash_v3(&tx,index,script.as_bytes(),value,raw,false).unwrap();
                assert!(hashes.insert(digest),"raw type {raw} was collapsed");
                let active = elements_ecdsa_sighash_v3(&tx,index,script.as_bytes(),value,raw,true).unwrap();
                // Legacy NONE serializes no outputs, hence no rangeproof data.
                if raw & 0x40 == 0 || (value.is_none() && raw & 0x1f == 2) {assert_eq!(digest,active);}
                else {assert_ne!(digest,active);}
            }
        }}
    }
    #[test]
    fn single_missing_output_and_invalid_index() {
        let tx = Transaction {version:2,lock_time:LockTime::ZERO,input:vec![TxIn::default()],output:vec![]};
        let mut one = [0;32]; one[0] = 1;
        for raw in [3,0x23,0x43,0x83,0xc3] {
            assert_eq!(elements_ecdsa_sighash_v3(&tx,0,&[],None,raw,true).unwrap(),one);
            assert_ne!(elements_ecdsa_sighash_v3(&tx,0,&[],Some(Value::Explicit(0)),raw,true).unwrap(),one);
        }
        assert!(elements_ecdsa_sighash_v3(&tx,1,&[],None,1,false).is_err());
    }
}
