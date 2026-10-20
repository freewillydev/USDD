//! Native HasOnlyExplicitCreations parity. Historical input commitments are
//! deliberately outside this predicate; their openings still require verification.
use elements::{Transaction, confidential::{Asset, Value, Nonce}};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCreationPolicyV1 {
    /// None preserves legacy creation rules. No activation height is defaulted.
    pub explicit_only_height: Option<u32>,
}

impl NativeCreationPolicyV1 {
    pub fn commitment(self) -> [u8; 32] {
        let mut bytes = vec![1];
        match self.explicit_only_height {
            None => bytes.push(0),
            Some(height) => { bytes.push(1); bytes.extend_from_slice(&height.to_be_bytes()); }
        }
        crate::tagged_hash("ECX/alpha-native-creation-policy/v1", &bytes)
    }

    pub fn permits(self, height: u32, tx: &Transaction) -> bool {
        !self.explicit_only_height.is_some_and(|activation| height >= activation)
            || has_only_explicit_creations(tx)
    }
}

/// New policy encoding; V1 remains byte-for-byte unchanged. Selection must be
/// made from a frozen execution policy and an authenticated child height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCreationPolicyV2 {
    pub creation: NativeCreationPolicyV1,
    pub explicit_reissuance_height: Option<u32>,
}

impl NativeCreationPolicyV2 {
    pub fn commitment(self) -> Result<[u8; 32], &'static str> {
        if let Some(reissuance) = self.explicit_reissuance_height {
            if !self.creation.explicit_only_height.is_some_and(|h| h <= reissuance) {
                return Err("explicit reissuance requires explicit-only creation rules");
            }
        }
        let mut bytes = vec![2];
        bytes.extend_from_slice(&self.creation.commitment());
        match self.explicit_reissuance_height {
            None => bytes.push(0),
            Some(height) => { bytes.push(1); bytes.extend_from_slice(&height.to_be_bytes()); }
        }
        Ok(crate::tagged_hash("ECX/alpha-native-creation-policy/v2", &bytes))
    }

    pub fn reissuance_rules(self, authenticated_height: u32)
        -> Result<ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3, &'static str>
    {
        use ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3;
        self.commitment()?;
        Ok(if self.explicit_reissuance_height.is_some_and(|h| authenticated_height >= h) {
            ElementsReissuanceRulesV3::ExplicitV1
        } else {
            ElementsReissuanceRulesV3::Legacy
        })
    }
}

pub fn has_only_explicit_creations(tx: &Transaction) -> bool {
    tx.output.iter().all(|output| {
        matches!(output.asset, Asset::Explicit(_))
            && matches!(output.value, Value::Explicit(_))
            && matches!(output.nonce, Nonce::Null)
            && output.witness.rangeproof.is_none()
            && output.witness.surjection_proof.is_none()
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
    #[test]
    fn reissuance_activation_is_separate_validated_and_versioned() {
        use ecx_full_consensus_validator_v2::elements_v2::ElementsReissuanceRulesV3 as Rules;
        let creation = NativeCreationPolicyV1 { explicit_only_height: Some(100) };
        let disabled = NativeCreationPolicyV2 { creation, explicit_reissuance_height: None };
        let active = NativeCreationPolicyV2 { creation, explicit_reissuance_height: Some(120) };
        assert_eq!(disabled.reissuance_rules(u32::MAX), Ok(Rules::Legacy));
        assert_eq!(active.reissuance_rules(119), Ok(Rules::Legacy));
        assert_eq!(active.reissuance_rules(120), Ok(Rules::ExplicitV1));
        assert_eq!(active.reissuance_rules(121), Ok(Rules::ExplicitV1));
        assert_ne!(disabled.commitment().unwrap(), creation.commitment());
        assert_ne!(disabled.commitment(), active.commitment());
        assert_ne!(active.commitment(), NativeCreationPolicyV2 {
            explicit_reissuance_height: Some(121), ..active }.commitment());
        for explicit_only_height in [None, Some(121)] {
            let bad = NativeCreationPolicyV2 {
                creation: NativeCreationPolicyV1 { explicit_only_height }, ..active };
            assert!(bad.commitment().is_err());
            assert!(bad.reissuance_rules(120).is_err());
        }
        // The old binary format is not extended or reinterpreted in place.
        assert_eq!(bincode::serialize(&creation).unwrap(), vec![1, 100, 0, 0, 0]);
        assert!(bincode::deserialize::<NativeCreationPolicyV2>(
            &bincode::serialize(&creation).unwrap()).is_err());
    }
    // Optional same-byte native consumer check; synthetic vectors only.
    fn native_parity(tx: &Transaction) {
        let Some(binary) = std::env::var_os("ECX_NATIVE_AMOUNT_TEST") else { return };
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut bytes = elements::encode::serialize(tx);
        let previous = elements::TxOut { asset: Asset::Explicit(elements::AssetId::LIQUID_BTC),
            value: Value::Explicit(1), ..Default::default() };
        bytes.extend(elements::encode::serialize(&vec![previous; tx.input.len()]));
        let wire = bytes.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let mut child = Command::new(binary)
            .args(["--run_test=blind_tests/shared_amount_kernel_stdin", "--log_level=error", "--report_level=no"])
            .env("ECX_AMOUNT_KERNEL_STDIN", "1")
            .env("ECX_CREATION_ONLY", "1")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap();
        writeln!(child.stdin.take().unwrap(), "{wire}").unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "native synthetic parity harness failed: {:?} {} {}", result.status, String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
        let expected = format!("EXPLICIT_CREATIONS {}", u8::from(has_only_explicit_creations(tx)));
        assert!(String::from_utf8(result.stdout).unwrap().lines().any(|line| line == expected), "native creation predicate disagrees");
    }
    #[test]
    fn historical_confidential_spends_require_balanced_input_blinders() {
        use elements::{TxOut, TxOutSecrets, Script, TxIn, LockTime};
        use elements::confidential::{AssetBlindingFactor as ABF, ValueBlindingFactor as VBF};
        use elements::secp256k1_zkp::{Secp256k1, SecretKey, PublicKey};
        use ecx_full_consensus_validator_v2::elements_v2::{
            verify_ordinary_elements_confidential_transaction_v2 as verify,
            ElementsStateErrorV2,
        };
        let secp = Secp256k1::new();
        let mut rng = elements::secp256k1_zkp::rand::thread_rng();
        let asset = elements::AssetId::LIQUID_BTC;
        let explicit = |amount| TxOut { asset: Asset::Explicit(asset), value: Value::Explicit(amount),
            nonce: Nonce::Null, script_pubkey: Script::from(vec![0x51]), witness: Default::default() };
        let funding = TxOutSecrets::new(asset, ABF::zero(), 100, VBF::zero());
        let first = TxOutSecrets::new(asset, ABF::from_slice(&[3;32]).unwrap(), 40,
            VBF::from_slice(&[4;32]).unwrap());
        let second_abf = ABF::from_slice(&[5;32]).unwrap();
        let second = TxOutSecrets::new(asset, second_abf, 60, VBF::last(&secp, 60, second_abf,
            &[funding.value_blind_inputs()], &[first.value_blind_inputs()]));
        let receiver = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[6;32]).unwrap());
        let mut outputs = Vec::new();
        for secrets in [first, second] {
            outputs.push(TxOut::with_txout_secrets(&mut rng, &secp, Script::from(vec![0x51]),
                receiver, SecretKey::from_slice(&[7;32]).unwrap(), secrets, &[funding]).unwrap());
        }
        // Establish a valid historical amount/proof kernel, not arbitrary commitments.
        let issuance = Transaction { version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn::default()], output: outputs.clone() };
        verify(&issuance, &[explicit(100)]).unwrap();
        let policy = NativeCreationPolicyV1 { explicit_only_height: Some(100) };
        assert!(!policy.permits(100, &issuance));
        let mut spend = Transaction { version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn::default()], output: vec![explicit(40)] };
        assert!(policy.permits(100, &spend));
        assert_eq!(verify(&spend, &outputs[..1]), Err(ElementsStateErrorV2::ConfidentialConsensus));
        // Spending the complete balanced set can remove confidentiality without
        // relaxing the tally. This is not proof that arbitrary wallet subsets can.
        spend.input.push(TxIn::default());
        spend.output[0] = explicit(100);
        assert!(policy.permits(100, &spend));
        verify(&spend, &outputs).unwrap();
    }
    #[test]
    fn confidential_creation_components_reject_individually() {
        use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
        use elements::secp256k1_zkp::{Secp256k1, SecretKey, PublicKey};
        let secp = Secp256k1::new();
        let asset = Asset::Explicit(elements::AssetId::LIQUID_BTC);
        let confidential_asset = Asset::new_confidential(&secp, elements::AssetId::LIQUID_BTC,
            AssetBlindingFactor::from_slice(&[3; 32]).unwrap());
        let confidential_value = Value::new_confidential(&secp, 1,
            confidential_asset.into_asset_gen(&secp).unwrap(),
            ValueBlindingFactor::from_slice(&[4; 32]).unwrap());
        let nonce = Nonce::Confidential(PublicKey::from_secret_key(&secp,
            &SecretKey::from_slice(&[5; 32]).unwrap()));
        let mut base = Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()], output: vec![elements::TxOut::default()] };
        // Issuance must use an ordinary outpoint, not the default coinbase
        // sentinel whose all-one index suppresses issuance during decoding.
        base.input[0].previous_output.vout = 0;
        base.output[0].asset = asset;
        base.output[0].value = Value::Explicit(1);
        let policy = NativeCreationPolicyV1 { explicit_only_height: Some(100) };
        assert!(policy.permits(100, &base));
        native_parity(&base);
        for mutation in 0..5 {
            let mut tx = base.clone();
            match mutation {
                0 => tx.output[0].asset = confidential_asset,
                1 => tx.output[0].value = confidential_value,
                2 => tx.output[0].nonce = nonce,
                3 => tx.input[0].asset_issuance.amount = confidential_value,
                _ => tx.input[0].asset_issuance.inflation_keys = confidential_value,
            }
            assert!(policy.permits(99, &tx));
            assert!(!policy.permits(100, &tx), "mutation {mutation}");
            native_parity(&tx);
        }
        // Generate real proof objects rather than dummy/non-decodable bytes.
        let mut rng = elements::secp256k1_zkp::rand::thread_rng();
        let secret = SecretKey::from_slice(&[5; 32]).unwrap();
        let input = elements::TxOutSecrets::new(elements::AssetId::LIQUID_BTC,
            AssetBlindingFactor::zero(), 1, ValueBlindingFactor::zero());
        let output = elements::TxOut::with_txout_secrets(&mut rng, &secp,
            elements::Script::from(vec![0x51]), PublicKey::from_secret_key(&secp, &secret),
            SecretKey::from_slice(&[6; 32]).unwrap(),
            elements::TxOutSecrets::new(elements::AssetId::LIQUID_BTC,
                AssetBlindingFactor::from_slice(&[3; 32]).unwrap(), 1,
                ValueBlindingFactor::from_slice(&[4; 32]).unwrap()), &[input]).unwrap();
        assert!(output.witness.rangeproof.is_some());
        assert!(output.witness.surjection_proof.is_some());
        for mutation in 0..4 {
            let mut tx = base.clone();
            match mutation {
                0 => tx.output[0].witness.rangeproof = output.witness.rangeproof.clone(),
                1 => tx.output[0].witness.surjection_proof = output.witness.surjection_proof.clone(),
                2 => tx.input[0].witness.amount_rangeproof = output.witness.rangeproof.clone(),
                _ => tx.input[0].witness.inflation_keys_rangeproof = output.witness.rangeproof.clone(),
            }
            assert!(policy.permits(99, &tx));
            assert!(!policy.permits(100, &tx), "proof mutation {mutation}");
            native_parity(&tx);
        }
    }
    #[test]
    fn activation_and_commitment_are_distinct() {
        let mut tx = Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()], output: vec![elements::TxOut::default()] };
        tx.input[0].previous_output.vout = 0;
        let policy = NativeCreationPolicyV1 { explicit_only_height: Some(100) };
        // Null output asset/value are not explicit creations.
        assert!(policy.permits(99, &tx));
        assert!(!policy.permits(100, &tx));
        assert!(!policy.permits(101, &tx));
        // Native wire decoding already forbids null output values; this
        // in-memory negative is not a decodable shared predicate vector.
        let legacy = NativeCreationPolicyV1 { explicit_only_height: None };
        assert!(legacy.permits(u32::MAX, &tx));
        assert_ne!(legacy.commitment(), policy.commitment());
        assert_ne!(policy.commitment(), NativeCreationPolicyV1 {
            explicit_only_height: Some(101) }.commitment());
        tx.output[0].asset = Asset::Explicit(elements::AssetId::LIQUID_BTC);
        tx.output[0].value = Value::Explicit(1);
        assert!(policy.permits(100, &tx));
        // Script witnesses are not forbidden; prior outputs are checked elsewhere.
        tx.input[0].witness.script_witness = vec![vec![1, 2, 3]];
        assert!(policy.permits(100, &tx));
        native_parity(&tx);
        tx.input[0].asset_issuance.amount = Value::Explicit(2);
        tx.input[0].asset_issuance.inflation_keys = Value::Explicit(1);
        assert!(policy.permits(100, &tx));
        native_parity(&tx);
    }
}
