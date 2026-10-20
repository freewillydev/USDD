//! Explicit-only creation check shared by public deployment preparation.
//! This is not full transaction validation or an activation-height policy.
//! Historical input commitments still require normal cryptographic validation.

use elements::{confidential::{Asset, Nonce, Value}, Transaction};

pub fn has_only_explicit_creations(tx: &Transaction) -> bool {
    tx.output.iter().all(|out| {
        matches!(out.asset, Asset::Explicit(_))
            && matches!(out.value, Value::Explicit(_))
            && out.nonce == Nonce::Null
            && out.witness.rangeproof.is_none()
            && out.witness.surjection_proof.is_none()
    }) && tx.input.iter().all(|input| {
        matches!(input.asset_issuance.amount, Value::Null | Value::Explicit(_))
            && matches!(input.asset_issuance.inflation_keys, Value::Null | Value::Explicit(_))
            && input.witness.amount_rangeproof.is_none()
            && input.witness.inflation_keys_rangeproof.is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{AssetId, LockTime, TxIn, TxOut};

    #[test]
    fn public_outputs_and_issuance_require_no_openings() {
        let mut tx = Transaction {
            version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                asset: Asset::Explicit(AssetId::from_byte_array([1; 32])),
                value: Value::Explicit(10),
                ..TxOut::default()
            }],
        };
        assert!(has_only_explicit_creations(&tx));
        tx.input[0].asset_issuance.amount = Value::Explicit(10);
        tx.input[0].asset_issuance.inflation_keys = Value::Explicit(1);
        assert!(has_only_explicit_creations(&tx));
        tx.output[0].value = Value::Null;
        assert!(!has_only_explicit_creations(&tx));
        tx.output[0].value = Value::Explicit(10);
        tx.output[0].asset = Asset::Null;
        assert!(!has_only_explicit_creations(&tx));
        let asset_id = AssetId::from_byte_array([1; 32]);
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let asset = Asset::new_confidential(
            &secp, asset_id, elements::confidential::AssetBlindingFactor::zero(),
        );
        tx.output[0].asset = asset;
        assert!(!has_only_explicit_creations(&tx));
        tx.output[0].asset = Asset::Explicit(asset_id);
        let committed_value = Value::new_confidential(
            &secp, 10, asset.commitment().unwrap(),
            elements::confidential::ValueBlindingFactor::from_slice(&[1; 32]).unwrap(),
        );
        tx.output[0].value = committed_value;
        assert!(!has_only_explicit_creations(&tx));
        tx.output[0].value = Value::Explicit(10);
        tx.input[0].asset_issuance.amount = committed_value;
        assert!(!has_only_explicit_creations(&tx));
        tx.input[0].asset_issuance.amount = Value::Explicit(10);
        tx.input[0].asset_issuance.inflation_keys = committed_value;
        assert!(!has_only_explicit_creations(&tx));
    }
}
