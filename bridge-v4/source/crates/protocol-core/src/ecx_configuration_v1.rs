//! Economic domain for direct ECX settlement. No proof or deployment authority
//! is established by constructing this value; the successor must pin its hash.
use crate::codec::{put_u64, CanonicalEncode};
use crate::ecx_cash_account_v1::EcxAccountDomainV1;
use crate::hash::{canonical_hash, Hash32};
use crate::incremental_state_v2::IncrementalAccountingBoundsV2;
use crate::risk::RiskParams;
use crate::types::{MarketId, XOnlyKey};
use crate::ProtocolError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EcxConfigurationV1 {
    pub chain_id: Hash32,
    pub market: MarketId,
    pub collateral_asset: Hash32,
    pub clearing_account: XOnlyKey,
    /// Loss-bearing fee reserve, distinct from realized-P&L clearing.
    pub insurance_account: XOnlyKey,
    /// Precision of conservative valuation only; never rounds stored claims.
    pub cash_valuation_scale: u64,
    pub risk: RiskParams,
    pub bounds: IncrementalAccountingBoundsV2,
}

impl EcxConfigurationV1 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.chain_id == [0; 32]
            || self.collateral_asset == [0; 32]
            || self.cash_valuation_scale == 0
            || self.insurance_account == self.clearing_account
            // V1 reuses the fixed-policy eight-hour accumulator. Do not sign
            // an economic domain promising a different funding cap.
            || self.risk.max_abs_funding_rate_ppm
                != crate::funding_v2::FUNDING_RATE_CAP_PPM as u32
        {
            return Err(ProtocolError::InvalidBondState);
        }
        secp256k1::XOnlyPublicKey::from_slice(&self.clearing_account.0)
            .map_err(|_| ProtocolError::InvalidBondState)?;
        secp256k1::XOnlyPublicKey::from_slice(&self.insurance_account.0)
            .map_err(|_| ProtocolError::InvalidBondState)?;
        self.market.validate()?;
        self.risk.validate()?;
        self.bounds.validate()
    }

    pub fn digest(self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash(
            "ECX/linear-ecx-settlement-configuration/v1",
            &self,
        ))
    }

    pub fn account_domain(self) -> Result<EcxAccountDomainV1, ProtocolError> {
        Ok(EcxAccountDomainV1 {
            chain_id: self.chain_id,
            market: self.market,
            configuration_hash: self.digest()?,
            collateral_asset: self.collateral_asset,
        })
    }
}

impl CanonicalEncode for EcxConfigurationV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(1);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        out.extend_from_slice(&self.collateral_asset);
        out.extend_from_slice(&self.clearing_account.0);
        out.extend_from_slice(&self.insurance_account.0);
        put_u64(out, self.cash_valuation_scale);
        self.risk.encode_to(out);
        self.bounds.encode_to(out);
    }
}

/// Outer proof composition bindings. Children consume the economic hash, not
/// this outer digest; neither a child nor the outer guest embeds its own ID.
/// The covenant must pin this digest. Nonzero IDs are not build qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EcxSuccessorBindingsV1 {
    pub economic_configuration_hash: Hash32,
    pub oracle_configuration_hash: Hash32,
    pub matcher_configuration_hash: Hash32,
    pub funding_oracle_program_id: Hash32,
    pub account_execution_program_id: Hash32,
    pub vault_policy_hash: Hash32,
}

impl EcxSuccessorBindingsV1 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        if [
            self.economic_configuration_hash,
            self.oracle_configuration_hash,
            self.matcher_configuration_hash,
            self.funding_oracle_program_id,
            self.account_execution_program_id,
            self.vault_policy_hash,
        ]
        .contains(&[0; 32])
            || self.funding_oracle_program_id == self.account_execution_program_id
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    pub fn digest(self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash(
            "ECX/linear-ecx-successor-bindings/v1",
            &self,
        ))
    }

    /// Check the opened economics against the pinned outer configuration.
    /// Callers still must verify actual receipts under the role-specific IDs.
    pub fn account_domain(
        self,
        economics: EcxConfigurationV1,
    ) -> Result<EcxAccountDomainV1, ProtocolError> {
        self.validate()?;
        let domain = economics.account_domain()?;
        if domain.configuration_hash != self.economic_configuration_hash {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(domain)
    }
}

impl CanonicalEncode for EcxSuccessorBindingsV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(1);
        for hash in [
            self.economic_configuration_hash,
            self.oracle_configuration_hash,
            self.matcher_configuration_hash,
            self.funding_oracle_program_id,
            self.account_execution_program_id,
            self.vault_policy_hash,
        ] {
            out.extend_from_slice(&hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_binds_ecx_economics_and_derives_signing_domain() {
        let key = secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
        let pair = secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &key);
        let configuration = EcxConfigurationV1 {
            chain_id: [1; 32],
            market: crate::types::ECX_USDD_MARKET,
            collateral_asset: [2; 32],
            clearing_account: XOnlyKey(pair.x_only_public_key().0.serialize()),
            insurance_account: XOnlyKey(secp256k1::Keypair::from_secret_key(
                &secp256k1::Secp256k1::new(),
                &secp256k1::SecretKey::from_slice(&[8; 32]).unwrap(),
            ).x_only_public_key().0.serialize()),
            cash_valuation_scale: 1_000_000,
            risk: RiskParams::default(),
            bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
                maximum_total_controlled_atoms: 100_000_000_000_000,
                maximum_abs_position_atoms: 10_000_000_000,
                maximum_open_interest_atoms: 100_000_000_000,
                maximum_price_atoms: 1_000_000_000_000,
            },
        };
        let hash = configuration.digest().unwrap();
        let domain = configuration.account_domain().unwrap();
        assert_eq!(domain.configuration_hash, hash);
        assert_eq!(domain.collateral_asset, configuration.collateral_asset);
        let bindings = EcxSuccessorBindingsV1 {
            economic_configuration_hash: hash,
            oracle_configuration_hash: [3; 32],
            matcher_configuration_hash: [4; 32],
            funding_oracle_program_id: [5; 32],
            account_execution_program_id: [6; 32],
            vault_policy_hash: [7; 32],
        };
        assert_eq!(bindings.account_domain(configuration).unwrap(), domain);
        let binding_hash = bindings.digest().unwrap();
        let mut bytes = vec![1];
        bytes.extend_from_slice(&hash);
        for byte in 3..=7 {
            bytes.extend_from_slice(&[byte; 32]);
        }
        let mut encoded = Vec::new();
        bindings.encode_to(&mut encoded);
        assert_eq!(encoded.len(), 193);
        assert_eq!(encoded, bytes);
        assert_eq!(
            binding_hash,
            crate::hash::tagged_hash("ECX/linear-ecx-successor-bindings/v1", &bytes)
        );
        for index in 0..6 {
            let mut altered = bindings;
            let fields = [
                &mut altered.economic_configuration_hash,
                &mut altered.oracle_configuration_hash,
                &mut altered.matcher_configuration_hash,
                &mut altered.funding_oracle_program_id,
                &mut altered.account_execution_program_id,
                &mut altered.vault_policy_hash,
            ];
            fields[index][0] ^= 128;
            assert_ne!(altered.digest().unwrap(), binding_hash);
        }
        let mut substituted = bindings;
        std::mem::swap(
            &mut substituted.funding_oracle_program_id,
            &mut substituted.account_execution_program_id,
        );
        assert_ne!(substituted.digest().unwrap(), binding_hash);
        substituted.funding_oracle_program_id = substituted.account_execution_program_id;
        assert!(substituted.digest().is_err());
        let mut changed = configuration;
        changed.cash_valuation_scale += 1;
        assert_ne!(changed.digest().unwrap(), hash);
        assert!(bindings.account_domain(changed).is_err());
        changed = configuration;
        changed.risk.taker_fee_bps += 1;
        assert_ne!(changed.digest().unwrap(), hash);
        for cap in [0, 9_999, 10_001, 1_000_000] {
            changed = configuration;
            changed.risk.max_abs_funding_rate_ppm = cap;
            assert!(changed.risk.validate().is_ok());
            assert!(changed.digest().is_err());
            assert!(bindings.account_domain(changed).is_err());
        }
        changed = configuration;
        changed.collateral_asset[0] ^= 1;
        assert_ne!(changed.digest().unwrap(), hash);
        changed = configuration;
        changed.cash_valuation_scale = 0;
        assert!(changed.account_domain().is_err());
        changed = configuration;
        changed.clearing_account = XOnlyKey([255; 32]);
        assert!(changed.digest().is_err());
        changed = configuration;
        changed.chain_id = [0; 32];
        assert!(changed.digest().is_err());
        changed = configuration;
        changed.insurance_account = configuration.clearing_account;
        assert!(changed.digest().is_err());
        changed.insurance_account = XOnlyKey([255; 32]);
        assert!(changed.digest().is_err());
        changed.insurance_account = XOnlyKey(secp256k1::Keypair::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[9; 32]).unwrap(),
        ).x_only_public_key().0.serialize());
        assert_ne!(changed.digest().unwrap(), hash);
        assert!(bindings.account_domain(changed).is_err());
    }
}
