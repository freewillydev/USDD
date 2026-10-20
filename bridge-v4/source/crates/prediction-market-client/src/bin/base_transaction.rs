use anyhow::{bail, Context, Result};
use clap::Parser;
use elements::{
    confidential::{Asset, Nonce, Value},
    encode, AssetId, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};
use serde::Deserialize;
use std::{fs, path::PathBuf, str::FromStr};

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    spec: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Spec {
    state_txid: String,
    state_vout: u32,
    sponsor_txid: String,
    sponsor_vout: u32,
    vault_txid: String,
    vault_vout: u32,
    policy_asset: String,
    collateral_asset: String,
    state_authority_asset: String,
    state_script_hex: String,
    sponsor_change_script_hex: String,
    vault_script_hex: String,
    payout_script_hex: Option<String>,
    collateral_funding_txid: Option<String>,
    collateral_funding_vout: Option<u32>,
    sponsor_input_units: u64,
    fee_units: u64,
    current_collateral_units: u64,
    collateral_funding_units: u64,
    collateral_change_units: u64,
    next_collateral_units: u64,
    payout_units: u64,
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    if args.output.exists() {
        bail!("refusing to overwrite base transaction output")
    }
    let spec: Spec =
        serde_json::from_slice(&fs::read(&args.spec)?).context("invalid base transaction spec")?;
    let tx = build(&spec)?;
    fs::write(&args.output, hex::encode(encode::serialize(&tx)))?;
    println!("txid={}", tx.txid());
    Ok(())
}

fn build(s: &Spec) -> Result<Transaction> {
    if s.fee_units == 0 || s.sponsor_input_units <= s.fee_units {
        bail!("fee sponsor must fund a nonzero fee and change")
    }
    if (s.payout_units > 0 || s.collateral_change_units > 0) && s.payout_script_hex.is_none()
        || s.payout_units == 0 && s.collateral_change_units == 0 && s.payout_script_hex.is_some()
        || s.payout_units > 0 && s.collateral_change_units > 0
    {
        bail!("payout/change script and exactly one nonzero collateral return must agree")
    }
    let funded = s.collateral_funding_txid.is_some()
        || s.collateral_funding_vout.is_some()
        || s.collateral_funding_units > 0;
    if funded
        != (s.collateral_funding_txid.is_some()
            && s.collateral_funding_vout.is_some()
            && s.collateral_funding_units > 0)
    {
        bail!("collateral funding outpoint and amount must be complete")
    }
    if s.current_collateral_units
        .checked_add(s.collateral_funding_units)
        != s.next_collateral_units
            .checked_add(s.payout_units)
            .and_then(|v| v.checked_add(s.collateral_change_units))
    {
        bail!("collateral inputs and outputs do not conserve value")
    }
    let policy = asset(&s.policy_asset, "policy asset")?;
    let collateral = asset(&s.collateral_asset, "collateral asset")?;
    let authority = asset(&s.state_authority_asset, "state authority asset")?;
    let mut output = vec![
        out(authority, 1, script(&s.state_script_hex, "state script")?),
        out(
            policy,
            s.sponsor_input_units - s.fee_units,
            script(&s.sponsor_change_script_hex, "change script")?,
        ),
        out(policy, s.fee_units, Script::new()),
        out(
            collateral,
            s.next_collateral_units,
            script(&s.vault_script_hex, "vault script")?,
        ),
    ];
    if let Some(value) = &s.payout_script_hex {
        output.push(out(
            collateral,
            s.payout_units.max(s.collateral_change_units),
            script(value, "payout script")?,
        ));
    }
    Ok(Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: {
            let mut inputs = vec![
                input(&s.state_txid, s.state_vout)?,
                input(&s.sponsor_txid, s.sponsor_vout)?,
                input(&s.vault_txid, s.vault_vout)?,
            ];
            if let (Some(txid), Some(vout)) =
                (&s.collateral_funding_txid, s.collateral_funding_vout)
            {
                inputs.push(input(txid, vout)?)
            }
            inputs
        },
        output,
    })
}
fn input(value: &str, vout: u32) -> Result<TxIn> {
    Ok(TxIn {
        previous_output: OutPoint::new(Txid::from_str(value)?, vout),
        ..TxIn::default()
    })
}
fn out(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: Default::default(),
    }
}
fn asset(value: &str, label: &str) -> Result<AssetId> {
    AssetId::from_str(value).with_context(|| format!("invalid {label}"))
}
fn script(value: &str, label: &str) -> Result<Script> {
    let bytes = hex::decode(value).with_context(|| format!("invalid {label}"))?;
    if bytes.is_empty() {
        bail!("{label} must not be empty")
    }
    Ok(Script::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u8) -> String {
        hex::encode([n; 32])
    }
    fn spec() -> Spec {
        Spec {
            state_txid: id(1),
            state_vout: 0,
            sponsor_txid: id(2),
            sponsor_vout: 1,
            vault_txid: id(3),
            vault_vout: 3,
            policy_asset: id(4),
            collateral_asset: id(5),
            state_authority_asset: id(6),
            state_script_hex: "51".into(),
            sponsor_change_script_hex: "52".into(),
            vault_script_hex: "53".into(),
            payout_script_hex: Some("54".into()),
            collateral_funding_txid: None,
            collateral_funding_vout: None,
            sponsor_input_units: 1000,
            fee_units: 10,
            current_collateral_units: 2025,
            collateral_funding_units: 0,
            collateral_change_units: 0,
            next_collateral_units: 2000,
            payout_units: 25,
        }
    }
    #[test]
    fn preserves_covenant_input_and_output_indexes() {
        let tx = build(&spec()).unwrap();
        assert_eq!(tx.input.len(), 3);
        assert_eq!(tx.output.len(), 5);
        assert_eq!(tx.output[0].value, Value::Explicit(1));
        assert_eq!(tx.output[1].value, Value::Explicit(990));
        assert_eq!(tx.output[2].script_pubkey, Script::new());
        assert_eq!(tx.output[3].value, Value::Explicit(2000));
        assert_eq!(tx.output[4].value, Value::Explicit(25));
    }
    #[test]
    fn rejects_unpaired_payout() {
        let mut value = spec();
        value.payout_script_hex = None;
        assert!(build(&value).is_err());
    }
    #[test]
    fn adds_a_buy_funding_input_and_signed_change_output() {
        let mut value = spec();
        value.payout_units = 0;
        value.current_collateral_units = 2000;
        value.next_collateral_units = 2025;
        value.collateral_funding_txid = Some(id(7));
        value.collateral_funding_vout = Some(2);
        value.collateral_funding_units = 100;
        value.collateral_change_units = 75;
        let tx = build(&value).unwrap();
        assert_eq!(tx.input.len(), 4);
        assert_eq!(tx.output[4].value, Value::Explicit(75));
    }
}
