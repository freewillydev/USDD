//! Native context-free checks. Does not validate scripts, UTXOs or issuance.
use elements::{Transaction, confidential::Value};
use bitcoin::script::Instruction;
use super::native_child_block_v3::ALPHA_MAX_BLOCK_WEIGHT;

pub const MAX_MONEY: u64 = 2_100_000_000_000_000;
pub const MAX_DEPOSITS: usize = 64;
pub const MAX_LEGACY_SIGOPS: usize = 80_000 / 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError { Empty, Size, Amount, DuplicateInput, Coinbase, NullInput, Deposits, Sigops }

pub fn check_transaction(tx: &Transaction) -> Result<(), TransactionError> {
    if tx.input.is_empty() || tx.output.is_empty() { return Err(TransactionError::Empty); }
    // Elements weight = 4*base + witness, size = base + witness.
    let base = (tx.weight() - tx.size()) / 3;
    if base > ALPHA_MAX_BLOCK_WEIGHT / 4 { return Err(TransactionError::Size); }
    let mut total = 0u64;
    for output in &tx.output {
        if let Value::Explicit(value) = output.value {
            total = total.checked_add(value).ok_or(TransactionError::Amount)?;
            if value > MAX_MONEY || total > MAX_MONEY { return Err(TransactionError::Amount); }
        }
    }
    let mut inputs = std::collections::HashSet::new();
    for input in &tx.input {
        if !inputs.insert(input.previous_output) { return Err(TransactionError::DuplicateInput); }
    }
    if tx.is_coinbase() {
        if !(2..=100).contains(&tx.input[0].script_sig.len()) || tx.output.iter().any(|o| o.is_fee()) {
            return Err(TransactionError::Coinbase);
        }
    } else if tx.input.iter().any(|i| i.previous_output.is_null()) { return Err(TransactionError::NullInput); }
    Ok(())
}

fn legacy_sigops(script: &[u8]) -> usize {
    let mut count = 0;
    // Native GetOp stops at a malformed push; it does not count pushed bytes.
    for instruction in bitcoin::Script::from_bytes(script).instructions() {
        match instruction {
            Ok(Instruction::Op(op)) => count += match op.to_u8() {
                0xac | 0xad | 0xc1 | 0xc2 => 1,
                0xae | 0xaf => 20,
                _ => 0,
            },
            Ok(_) => {},
            Err(_) => break,
        }
    }
    count
}

pub fn check_block_transactions(txs: &[Transaction]) -> Result<(), TransactionError> {
    let mut deposits = 0usize;
    let mut sigops = 0usize;
    for tx in txs {
        check_transaction(tx)?;
        for input in &tx.input {
            deposits += usize::from(input.is_pegin);
            sigops += legacy_sigops(input.script_sig.as_bytes());
        }
        for output in &tx.output { sigops += legacy_sigops(output.script_pubkey.as_bytes()); }
        if deposits > MAX_DEPOSITS { return Err(TransactionError::Deposits); }
        if sigops > MAX_LEGACY_SIGOPS { return Err(TransactionError::Sigops); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{TxIn,TxOut,Script,LockTime};
    fn tx() -> Transaction {
        let mut input = TxIn::default(); input.previous_output.vout = 0;
        Transaction { version:2,lock_time:LockTime::ZERO,input:vec![input],output:vec![TxOut::default()] }
    }
    #[test]
    fn duplicate_and_null_inputs_rejected() {
        let mut t = tx(); assert_eq!(check_transaction(&t),Ok(()));
        t.input.push(t.input[0].clone());
        assert_eq!(check_transaction(&t),Err(TransactionError::DuplicateInput));
        t.input[1] = TxIn::default();
        assert_eq!(check_transaction(&t),Err(TransactionError::NullInput));
    }
    #[test]
    fn explicit_totals_include_all_assets_and_signed_overflow() {
        let mut t = tx(); t.output[0].value = Value::Explicit(MAX_MONEY);
        assert_eq!(check_transaction(&t),Ok(()));
        let mut extra = TxOut::default(); extra.value = Value::Explicit(1); t.output.push(extra);
        assert_eq!(check_transaction(&t),Err(TransactionError::Amount));
        t.output.truncate(1); t.output[0].value = Value::Explicit(u64::MAX);
        assert_eq!(check_transaction(&t),Err(TransactionError::Amount));
    }
    #[test]
    fn coinbase_script_bounds() {
        let mut t = tx(); t.input[0] = TxIn::default();
        for n in [0,1,101] { t.input[0].script_sig = Script::from(vec![0;n]);
            assert_eq!(check_transaction(&t),Err(TransactionError::Coinbase)); }
        for n in [2,100] { t.input[0].script_sig = Script::from(vec![0;n]);
            assert_eq!(check_transaction(&t),Ok(())); }
        t.output[0].asset = elements::confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC);
        t.output[0].value = Value::Explicit(0);
        assert_eq!(check_transaction(&t),Err(TransactionError::Coinbase));
    }
    #[test]
    fn empty_vectors_and_oversized_base_rejected() {
        let mut t = tx(); t.input.clear();
        assert_eq!(check_transaction(&t),Err(TransactionError::Empty));
        let mut t = tx(); t.output.clear();
        assert_eq!(check_transaction(&t),Err(TransactionError::Empty));
        let mut t = tx(); t.output[0].script_pubkey = Script::from(vec![0;1_500_000]);
        assert_eq!(check_transaction(&t),Err(TransactionError::Size));
        let mut t = tx(); t.input[0].witness.script_witness = vec![vec![0;1_500_000]];
        // Witness size is accounted separately in block weight, not base size.
        assert_eq!(check_transaction(&t),Ok(()));
    }
    #[test]
    fn elements_sigops_ignore_pushes_and_stop_at_bad_push() {
        assert_eq!(legacy_sigops(&[0xac,0xad,0xc1,0xc2,0xae,0xaf]),44);
        assert_eq!(legacy_sigops(&[1,0xac,0xac]),1);
        assert_eq!(legacy_sigops(&[0xac,0x4c,5,0xac]),1);
    }
    #[test]
    fn block_resource_boundaries() {
        let mut t = tx(); t.input[0].is_pegin = true;
        assert_eq!(check_block_transactions(&vec![t.clone();64]),Ok(()));
        assert_eq!(check_block_transactions(&vec![t;65]),Err(TransactionError::Deposits));
        let mut t = tx(); t.output[0].script_pubkey = Script::from(vec![0xac;20_000]);
        assert_eq!(check_block_transactions(&[t.clone()]),Ok(()));
        t.output[0].script_pubkey = Script::from(vec![0xac;20_001]);
        assert_eq!(check_block_transactions(&[t]),Err(TransactionError::Sigops));
    }
}
