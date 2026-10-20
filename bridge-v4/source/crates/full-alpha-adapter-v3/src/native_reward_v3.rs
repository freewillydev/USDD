//! Native Elements-mode block reward accounting. Parameters must be bound to
//! authenticated chain configuration; this predicate alone authenticates none.
use elements::{Transaction, AssetId, confidential::{Asset, Value}};
use std::collections::BTreeMap;
const MAX_MONEY: u64 = 2_100_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardParameters {
    pub subsidy_asset: AssetId,
    pub genesis_subsidy: u64,
    pub halving_interval: u32,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RewardError { Parameters, Shape, Amount, Coinbase }

pub fn verify_reward(txs: &[Transaction], height: u32, params: RewardParameters) -> Result<(),RewardError> {
    if params.halving_interval == 0 || params.genesis_subsidy > MAX_MONEY { return Err(RewardError::Parameters); }
    let coinbase = txs.first().filter(|tx| tx.is_coinbase()).ok_or(RewardError::Shape)?;
    if txs.iter().skip(1).any(Transaction::is_coinbase) { return Err(RewardError::Shape); }
    let mut remaining = BTreeMap::<AssetId,u64>::new();
    for tx in txs.iter().skip(1) {
        for out in tx.output.iter().filter(|out| out.is_fee()) {
            let (Asset::Explicit(asset),Value::Explicit(value)) = (out.asset,out.value) else { return Err(RewardError::Amount); };
            let total = remaining.entry(asset).or_default();
            *total = total.checked_add(value).filter(|v| *v <= MAX_MONEY).ok_or(RewardError::Amount)?;
        }
    }
    let halvings = height / params.halving_interval;
    let subsidy = if halvings >= 64 {0} else {params.genesis_subsidy >> halvings};
    let total = remaining.entry(params.subsidy_asset).or_default();
    *total = total.checked_add(subsidy).filter(|v| *v <= MAX_MONEY).ok_or(RewardError::Amount)?;
    for out in &coinbase.output {
        if !out.witness.is_empty() { return Err(RewardError::Coinbase); }
        let (Asset::Explicit(asset),Value::Explicit(value)) = (out.asset,out.value) else { return Err(RewardError::Coinbase); };
        let script = out.script_pubkey.as_bytes();
        let unspendable = script.is_empty() || script.first() == Some(&0x6a) || script.len() > 10_000;
        if value > MAX_MONEY || (value == 0 && !unspendable) { return Err(RewardError::Coinbase); }
        let total = remaining.entry(asset).or_default();
        *total = total.checked_sub(value).ok_or(RewardError::Coinbase)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{TxIn,TxOut,Script,LockTime};
    fn asset(n:u8)->AssetId { AssetId::from_slice(&[n;32]).unwrap() }
    fn fixture(value:u64)->(Vec<Transaction>,RewardParameters) {
        let tx = Transaction {version:2,lock_time:LockTime::ZERO,input:vec![TxIn::default()],
            output:vec![TxOut {asset:Asset::Explicit(asset(1)),value:Value::Explicit(value),script_pubkey:Script::from(vec![0x51]),..TxOut::default()}]};
        (vec![tx],RewardParameters {subsidy_asset:asset(1),genesis_subsidy:100,halving_interval:10})
    }
    #[test]
    fn multi_transaction_fees_cannot_cross_assets_or_be_claimed_twice() {
        let (mut txs,p)=fixture(107);
        let fee = |id,value| TxOut {asset:Asset::Explicit(asset(id)),value:Value::Explicit(value),..TxOut::default()};
        let payment = |outputs| {
            let mut input=TxIn::default(); input.previous_output.vout=0;
            Transaction {version:2,lock_time:LockTime::ZERO,input:vec![input],output:outputs}
        };
        txs.push(payment(vec![fee(1,3),fee(2,11)]));
        txs.push(payment(vec![fee(1,4)]));
        let mut second=fee(2,11); second.script_pubkey=Script::from(vec![0x51]);
        txs[0].output.push(second);
        assert_eq!(verify_reward(&txs,0,p),Ok(()));
        txs[0].output[0].value=Value::Explicit(108);
        // Leaving asset 2 unclaimed cannot compensate an asset 1 overpayment.
        txs[0].output[1].value=Value::Explicit(10);
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Coinbase));
        txs[0].output[0].value=Value::Explicit(107);
        let duplicate=txs[0].output[0].clone(); txs[0].output.push(duplicate);
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Coinbase));
        txs[0].output.pop();
        // Ordinary outputs do not constitute fees even with explicit amounts.
        txs[1].output[0].script_pubkey=Script::from(vec![0x51]);
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Coinbase));
    }
    #[test]
    fn fee_and_subsidy_overflow_and_bad_parameters_rejected() {
        let (mut txs,mut p)=fixture(1);
        let mut input=TxIn::default(); input.previous_output.vout=0;
        let fee=TxOut {asset:Asset::Explicit(asset(1)),value:Value::Explicit(MAX_MONEY),..TxOut::default()};
        txs.push(Transaction {version:2,lock_time:LockTime::ZERO,input:vec![input],output:vec![fee.clone()]});
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Amount));
        p.genesis_subsidy=0;
        assert_eq!(verify_reward(&txs,0,p),Ok(()));
        txs[1].output.push(fee);
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Amount));
        txs[1].output.truncate(1); txs[1].output[0].value=Value::Explicit(u64::MAX);
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Amount));
        p.halving_interval=0;
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Parameters));
        p.halving_interval=1; p.genesis_subsidy=MAX_MONEY+1;
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Parameters));
    }
    #[test]
    fn subsidy_edges_and_asset_separation() {
        let (mut txs,p)=fixture(50);
        assert_eq!(verify_reward(&txs,10,p),Ok(()));
        txs[0].output[0].value=Value::Explicit(51);
        assert_eq!(verify_reward(&txs,10,p),Err(RewardError::Coinbase));
        txs[0].output[0].value=Value::Explicit(1);
        txs[0].output[0].asset=Asset::Explicit(asset(2));
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Coinbase));
        txs[0].output[0].value=Value::Explicit(0);
        assert_eq!(verify_reward(&txs,640,p),Err(RewardError::Coinbase));
        txs[0].output[0].script_pubkey=Script::from(vec![0x6a]);
        assert_eq!(verify_reward(&txs,640,p),Ok(()));
        txs[0].output[0].asset=Asset::Null;
        assert_eq!(verify_reward(&txs,0,p),Err(RewardError::Coinbase));
    }
}
