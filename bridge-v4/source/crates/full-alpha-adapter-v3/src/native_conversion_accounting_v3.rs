//! Accounting projection for the Alpha conversion integration. This is not a
//! conversion receipt: redemption authority, finality and freshness remain
//! mandatory in the enclosing relation. No independent supply claims accepted.
use crate::child_execution_state_v3::ChildExecutionCheckpointV3;
use ecx_full_consensus_validator_v2::{Hash32, elements_v2::ElementsEconomicClassificationV2};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionAccountingErrorV3 { Configuration, Checkpoint, EmptySupply, Overflow, InsufficientReserve }

/// Accounting component of the future source configuration, not the complete
/// child consensus configuration or a redemption-availability certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionAccountingBindingV3 {
    pub child_genesis_internal: Hash32,
    pub child_configuration_commitment: Hash32,
    pub classification: ElementsEconomicClassificationV2,
    pub quote_atoms_per_whole_base: u64,
}

impl ConversionAccountingBindingV3 {
    pub fn commitment(&self) -> Result<Hash32, ConversionAccountingErrorV3> {
        let c = self.classification;
        let identities = [self.child_genesis_internal, self.child_configuration_commitment,
            c.base_asset_id, c.policy_asset_id, c.redemption_inventory_script_sha256,
            c.reserve_script_sha256];
        if identities.contains(&[0;32]) || self.quote_atoms_per_whole_base == 0
            || c.base_asset_id == c.policy_asset_id
            || c.redemption_inventory_script_sha256 == c.reserve_script_sha256 {
            return Err(ConversionAccountingErrorV3::Configuration);
        }
        let mut bytes = vec![3];
        for identity in identities { bytes.extend_from_slice(&identity); }
        bytes.extend_from_slice(&self.quote_atoms_per_whole_base.to_be_bytes());
        Ok(crate::tagged_hash("ECX/alpha-conversion-accounting-binding/v3", &bytes))
    }

    /// Expected commitment must come from the enclosing frozen source profile,
    /// not be computed from the same untrusted witness at the call site.
    pub fn require_frozen(&self, expected: Hash32) -> Result<(), ConversionAccountingErrorV3> {
        if expected == [0;32] || self.commitment()? != expected {
            return Err(ConversionAccountingErrorV3::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversionAccountingV3 {
    pub child_checkpoint_commitment: Hash32,
    pub base_asset_internal: Hash32,
    pub quote_asset_internal: Hash32,
    pub quote_atoms_per_whole_base: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
    pub required_reserve_quote_atoms: u128,
}

pub(crate) fn derive_accounting(checkpoint: &ChildExecutionCheckpointV3,
    classification: ElementsEconomicClassificationV2, quote: u64,
) -> Result<ConversionAccountingV3, ConversionAccountingErrorV3> {
    use ConversionAccountingErrorV3::*;
    if quote == 0 || [classification.base_asset_id, classification.policy_asset_id,
        classification.redemption_inventory_script_sha256, classification.reserve_script_sha256]
        .contains(&[0;32])
        || classification.base_asset_id == classification.policy_asset_id
        || classification.redemption_inventory_script_sha256 == classification.reserve_script_sha256 {
        return Err(Configuration);
    }
    let commitment = checkpoint.commitment().map_err(|_| Checkpoint)?;
    let totals = checkpoint.roots.economic_root.aggregate;
    let required = required_reserve(totals.outstanding_base_atoms, quote)?;
    if totals.redeemable_reserve_quote_atoms < required { return Err(InsufficientReserve); }
    Ok(ConversionAccountingV3 {
        child_checkpoint_commitment: commitment,
        base_asset_internal: classification.base_asset_id,
        quote_asset_internal: classification.policy_asset_id,
        quote_atoms_per_whole_base: quote,
        outstanding_base_atoms: totals.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: totals.redeemable_reserve_quote_atoms,
        required_reserve_quote_atoms: required,
    })
}

fn required_reserve(supply: u128, quote: u64) -> Result<u128, ConversionAccountingErrorV3> {
    if supply == 0 { return Err(ConversionAccountingErrorV3::EmptySupply); }
    if quote == 0 { return Err(ConversionAccountingErrorV3::Configuration); }
    let product = supply.checked_mul(u128::from(quote))
        .ok_or(ConversionAccountingErrorV3::Overflow)?;
    // Round upward without overflowing product + scale - 1.
    const SCALE: u128 = 100_000_000;
    Ok(product / SCALE + u128::from(product % SCALE != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_accounting_binds_every_identity_and_quote() {
        let binding = ConversionAccountingBindingV3 {
            child_genesis_internal: [1;32], child_configuration_commitment: [2;32],
            classification: ElementsEconomicClassificationV2 {
                base_asset_id: [3;32], policy_asset_id: [4;32],
                redemption_inventory_script_sha256: [5;32], reserve_script_sha256: [6;32],
            },
            quote_atoms_per_whole_base: 0x0102030405060708,
        };
        let frozen = binding.commitment().unwrap();
        let mut wire = vec![3];
        for value in 1..=6 { wire.extend_from_slice(&[value;32]); }
        wire.extend_from_slice(&[1,2,3,4,5,6,7,8]);
        assert_eq!(wire.len(),201);
        assert_eq!(frozen,crate::tagged_hash("ECX/alpha-conversion-accounting-binding/v3",&wire));
        assert_eq!(binding.require_frozen(frozen),Ok(()));
        assert_eq!(binding.require_frozen([0;32]),Err(ConversionAccountingErrorV3::Configuration));
        for field in 0..7 {
            let mut changed = binding;
            match field {
                0 => changed.child_genesis_internal = [99;32],
                1 => changed.child_configuration_commitment = [99;32],
                2 => changed.classification.base_asset_id = [99;32],
                3 => changed.classification.policy_asset_id = [99;32],
                4 => changed.classification.redemption_inventory_script_sha256 = [99;32],
                5 => changed.classification.reserve_script_sha256 = [99;32],
                _ => changed.quote_atoms_per_whole_base += 1,
            }
            assert_ne!(changed.commitment().unwrap(),frozen);
            assert_eq!(changed.require_frozen(frozen),Err(ConversionAccountingErrorV3::Configuration));
        }
        let mut invalid = binding;
        invalid.quote_atoms_per_whole_base = 0;
        assert_eq!(invalid.commitment(),Err(ConversionAccountingErrorV3::Configuration));
    }

    #[test]
    fn checkpoint_totals_are_projected_and_underfunding_rejected() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        // Synthetic state preimage, not an authenticated chain checkpoint.
        let mut checkpoint = ChildExecutionCheckpointV3 {
            genesis_internal: [1;32], configuration_commitment: [2;32],
            tip_internal: [3;32], height: 1, history_commitment: [4;32],
            spent_claims_root: crate::native_claims_v3::empty_root(),
            withdrawals: crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator::empty(),
            roots: ElementsTransactionStateRootsV2 {
                utxo_root: ElementsSparseUtxoNodeV2 { hash: [5;32], aggregate: ElementsUtxoAggregateV2 { count: 2 } },
                economic_root: ElementsSparseEconomicNodeV2 { hash: [6;32], aggregate: ElementsEconomicAggregateV2 {
                    count: 2, outstanding_base_atoms: 100_000_001, redeemable_reserve_quote_atoms: 2,
                } },
            },
        };
        let classification = ElementsEconomicClassificationV2 {
            base_asset_id: [7;32], policy_asset_id: [8;32],
            redemption_inventory_script_sha256: [9;32], reserve_script_sha256: [10;32],
        };
        let result = derive_accounting(&checkpoint,classification,1).unwrap();
        assert_eq!(result.child_checkpoint_commitment,checkpoint.commitment().unwrap());
        assert_eq!(result.outstanding_base_atoms,100_000_001);
        assert_eq!(result.required_reserve_quote_atoms,2);
        assert_eq!(result.redeemable_reserve_quote_atoms,2);
        checkpoint.roots.economic_root.aggregate.redeemable_reserve_quote_atoms = 1;
        assert_eq!(derive_accounting(&checkpoint,classification,1),Err(ConversionAccountingErrorV3::InsufficientReserve));
        checkpoint.roots.economic_root.aggregate.redeemable_reserve_quote_atoms = 3;
        assert_ne!(derive_accounting(&checkpoint,classification,1).unwrap().child_checkpoint_commitment,
            result.child_checkpoint_commitment);
        let mut wrong = classification; wrong.policy_asset_id = wrong.base_asset_id;
        assert_eq!(derive_accounting(&checkpoint,wrong,1),Err(ConversionAccountingErrorV3::Configuration));
        checkpoint.configuration_commitment = [0;32];
        assert_eq!(derive_accounting(&checkpoint,classification,1),Err(ConversionAccountingErrorV3::Checkpoint));
    }

    #[test]
    fn reserve_rounding_and_bounds() {
        assert_eq!(required_reserve(1,1),Ok(1));
        assert_eq!(required_reserve(100_000_000,1),Ok(1));
        assert_eq!(required_reserve(100_000_001,1),Ok(2));
        assert_eq!(required_reserve(u128::MAX,1),Ok(u128::MAX/100_000_000+1));
        assert_eq!(required_reserve(u128::MAX,2),Err(ConversionAccountingErrorV3::Overflow));
        assert_eq!(required_reserve(0,1),Err(ConversionAccountingErrorV3::EmptySupply));
        assert_eq!(required_reserve(1,0),Err(ConversionAccountingErrorV3::Configuration));
    }
}
