//! Compose parent-bound child execution into a conversion projection.
//!
//! Totals come only from `ParentBoundCheckedChildState::conversion_accounting`.
//! Independent witness supply/reserve claims are rejected. This is not a
//! conversion receipt, program identity, or proof-ready status.

use super::conversion_parent_link_v3::AlphaConversionLinkErrorV3;
use super::native_child_block_v3::ParentBoundCheckedChildState;
use super::native_conversion_accounting_v3::{
    ConversionAccountingBindingV3, ConversionAccountingErrorV3, ConversionAccountingV3,
};
use ecx_full_consensus_validator_v2::Hash32;

/// Distinct from the 0xa3 parent adapter journal and 0xa4 parent-link journal.
pub const ALPHA_CHILD_CONVERSION_PROJECTION_VERSION_V3: u8 = 0xa5;
pub const ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3: usize = 285;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionCompositionErrorV3 {
    Binding,
    Accounting(ConversionAccountingErrorV3),
}

impl From<AlphaConversionLinkErrorV3> for ConversionCompositionErrorV3 {
    fn from(_: AlphaConversionLinkErrorV3) -> Self {
        Self::Binding
    }
}

impl From<ConversionAccountingErrorV3> for ConversionCompositionErrorV3 {
    fn from(error: ConversionAccountingErrorV3) -> Self {
        Self::Accounting(error)
    }
}

/// Fixed projection consumed by the ECX/BTC conversion relation.
/// Parent fields are copied from the verified parent-link journal; economic
/// fields are copied from child-execution accounting, never from a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlphaChildConversionProjectionV3 {
    pub parent_binding_commitment: Hash32,
    pub parent_block_hash_internal: Hash32,
    pub parent_predecessor_hash_internal: Hash32,
    pub m7_critical_hash_internal: Hash32,
    pub child_checkpoint_commitment: Hash32,
    pub base_asset_internal: Hash32,
    pub quote_asset_internal: Hash32,
    pub parent_height: u32,
    pub quote_atoms_per_whole_base: u64,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
    pub required_reserve_quote_atoms: u128,
}

impl AlphaChildConversionProjectionV3 {
    pub fn canonical_bytes(self) -> Result<[u8; ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3], ConversionCompositionErrorV3> {
        self.validate()?;
        let mut bytes = [0u8; ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3];
        bytes[0] = ALPHA_CHILD_CONVERSION_PROJECTION_VERSION_V3;
        let mut cursor = 1;
        for hash in [
            self.parent_binding_commitment,
            self.parent_block_hash_internal,
            self.parent_predecessor_hash_internal,
            self.m7_critical_hash_internal,
            self.child_checkpoint_commitment,
            self.base_asset_internal,
            self.quote_asset_internal,
        ] {
            bytes[cursor..cursor + 32].copy_from_slice(&hash);
            cursor += 32;
        }
        bytes[cursor..cursor + 4].copy_from_slice(&self.parent_height.to_be_bytes());
        cursor += 4;
        bytes[cursor..cursor + 8].copy_from_slice(&self.quote_atoms_per_whole_base.to_be_bytes());
        cursor += 8;
        bytes[cursor..cursor + 16].copy_from_slice(&self.outstanding_base_atoms.to_be_bytes());
        cursor += 16;
        bytes[cursor..cursor + 16].copy_from_slice(&self.redeemable_reserve_quote_atoms.to_be_bytes());
        cursor += 16;
        bytes[cursor..cursor + 16].copy_from_slice(&self.required_reserve_quote_atoms.to_be_bytes());
        cursor += 16;
        debug_assert_eq!(cursor, bytes.len());
        Ok(bytes)
    }

    pub fn validate(self) -> Result<(), ConversionCompositionErrorV3> {
        if self.parent_height == 0
            || self.quote_atoms_per_whole_base == 0
            || self.outstanding_base_atoms == 0
            || self.redeemable_reserve_quote_atoms == 0
            || self.required_reserve_quote_atoms == 0
            || self.base_asset_internal == self.quote_asset_internal
            || [
                self.parent_binding_commitment,
                self.parent_block_hash_internal,
                self.parent_predecessor_hash_internal,
                self.m7_critical_hash_internal,
                self.child_checkpoint_commitment,
                self.base_asset_internal,
                self.quote_asset_internal,
            ]
            .contains(&[0; 32])
        {
            return Err(ConversionCompositionErrorV3::Binding);
        }
        Ok(())
    }
}

pub fn decode_alpha_child_conversion_projection_v3(
    bytes: &[u8],
) -> Result<AlphaChildConversionProjectionV3, ConversionCompositionErrorV3> {
    if bytes.len() != ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3
        || bytes.first().copied() != Some(ALPHA_CHILD_CONVERSION_PROJECTION_VERSION_V3)
    {
        return Err(ConversionCompositionErrorV3::Binding);
    }
    let hash_at = |offset: usize| -> Hash32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[offset..offset + 32]);
        out
    };
    let projection = AlphaChildConversionProjectionV3 {
        parent_binding_commitment: hash_at(1),
        parent_block_hash_internal: hash_at(33),
        parent_predecessor_hash_internal: hash_at(65),
        m7_critical_hash_internal: hash_at(97),
        child_checkpoint_commitment: hash_at(129),
        base_asset_internal: hash_at(161),
        quote_asset_internal: hash_at(193),
        parent_height: u32::from_be_bytes(bytes[225..229].try_into().expect("u32")),
        quote_atoms_per_whole_base: u64::from_be_bytes(bytes[229..237].try_into().expect("u64")),
        outstanding_base_atoms: u128::from_be_bytes(bytes[237..253].try_into().expect("u128")),
        redeemable_reserve_quote_atoms: u128::from_be_bytes(bytes[253..269].try_into().expect("u128")),
        required_reserve_quote_atoms: u128::from_be_bytes(bytes[269..285].try_into().expect("u128")),
    };
    projection.validate()?;
    Ok(projection)
}

fn projection_from_parent_and_accounting(
    parent: &super::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3,
    accounting: ConversionAccountingV3,
) -> Result<AlphaChildConversionProjectionV3, ConversionCompositionErrorV3> {
    let projection = AlphaChildConversionProjectionV3 {
        parent_binding_commitment: parent.binding_commitment,
        parent_block_hash_internal: parent.parent_block_hash_internal,
        parent_predecessor_hash_internal: parent.parent_predecessor_hash_internal,
        m7_critical_hash_internal: parent.m7_critical_hash_internal,
        child_checkpoint_commitment: accounting.child_checkpoint_commitment,
        base_asset_internal: accounting.base_asset_internal,
        quote_asset_internal: accounting.quote_asset_internal,
        parent_height: parent.parent_height,
        quote_atoms_per_whole_base: accounting.quote_atoms_per_whole_base,
        outstanding_base_atoms: accounting.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: accounting.redeemable_reserve_quote_atoms,
        required_reserve_quote_atoms: accounting.required_reserve_quote_atoms,
    };
    projection.validate()?;
    Ok(projection)
}

/// Bind verified parent-link public values to child-execution accounting.
/// `frozen_parent_binding` and `frozen_accounting_binding` must come from the
/// enclosing source profile, not from this witness.
pub fn project_parent_bound_child_conversion_v3(
    executed: &ParentBoundCheckedChildState,
    frozen_parent_binding: Hash32,
    accounting_binding: &ConversionAccountingBindingV3,
    frozen_accounting_binding: Hash32,
) -> Result<AlphaChildConversionProjectionV3, ConversionCompositionErrorV3> {
    executed
        .parent()
        .require_frozen_binding(frozen_parent_binding)?;
    let accounting = executed.conversion_accounting(accounting_binding, frozen_accounting_binding)?;
    projection_from_parent_and_accounting(executed.parent(), accounting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_conversion_accounting_v3::ConversionAccountingV3;
    use crate::conversion_parent_link_v3::AlphaConversionParentLinkPublicValuesV3;

    fn parent_values() -> AlphaConversionParentLinkPublicValuesV3 {
        AlphaConversionParentLinkPublicValuesV3 {
            binding_commitment: [1; 32],
            parent_statement_commitment: [2; 32],
            parent_predecessor_state_commitment: [3; 32],
            parent_terminal_state_commitment: [4; 32],
            parent_block_hash_internal: [5; 32],
            parent_height: 64,
            parent_predecessor_hash_internal: [6; 32],
            m7_critical_hash_internal: [7; 32],
            m7_coinbase_vout: 0,
        }
    }

    fn accounting() -> ConversionAccountingV3 {
        ConversionAccountingV3 {
            child_checkpoint_commitment: [8; 32],
            base_asset_internal: [9; 32],
            quote_asset_internal: [10; 32],
            quote_atoms_per_whole_base: 1,
            outstanding_base_atoms: 100_000_001,
            redeemable_reserve_quote_atoms: 2,
            required_reserve_quote_atoms: 2,
        }
    }

    fn projection() -> AlphaChildConversionProjectionV3 {
        projection_from_parent_and_accounting(&parent_values(), accounting()).unwrap()
    }

    #[test]
    fn projection_wire_is_285_bytes_and_rejects_parent_link_version() {
        let encoded = projection().canonical_bytes().unwrap();
        assert_eq!(encoded.len(), ALPHA_CHILD_CONVERSION_PROJECTION_BYTES_V3);
        assert_eq!(encoded[0], ALPHA_CHILD_CONVERSION_PROJECTION_VERSION_V3);
        assert_eq!(
            decode_alpha_child_conversion_projection_v3(&encoded).unwrap(),
            projection()
        );
        let mut as_parent_link = encoded;
        as_parent_link[0] = 0xa4;
        assert_eq!(
            decode_alpha_child_conversion_projection_v3(&as_parent_link),
            Err(ConversionCompositionErrorV3::Binding)
        );
        let mut short = encoded.to_vec();
        short.pop();
        assert_eq!(
            decode_alpha_child_conversion_projection_v3(&short),
            Err(ConversionCompositionErrorV3::Binding)
        );
    }

    #[test]
    fn projection_rejects_empty_supply_and_zero_identities() {
        let mut empty = projection();
        empty.outstanding_base_atoms = 0;
        assert_eq!(
            empty.canonical_bytes(),
            Err(ConversionCompositionErrorV3::Binding)
        );
        let mut zero_parent = projection();
        zero_parent.parent_block_hash_internal = [0; 32];
        assert_eq!(
            zero_parent.validate(),
            Err(ConversionCompositionErrorV3::Binding)
        );
        let mut same_assets = projection();
        same_assets.quote_asset_internal = same_assets.base_asset_internal;
        assert_eq!(
            same_assets.validate(),
            Err(ConversionCompositionErrorV3::Binding)
        );
    }

    #[test]
    fn every_parent_and_economic_field_is_in_the_wire() {
        let encoded = projection().canonical_bytes().unwrap();
        assert_eq!(&encoded[1..33], &[1; 32]);
        assert_eq!(&encoded[33..65], &[5; 32]);
        assert_eq!(&encoded[65..97], &[6; 32]);
        assert_eq!(&encoded[97..129], &[7; 32]);
        assert_eq!(&encoded[129..161], &[8; 32]);
        assert_eq!(&encoded[161..193], &[9; 32]);
        assert_eq!(&encoded[193..225], &[10; 32]);
        assert_eq!(&encoded[225..229], &64u32.to_be_bytes());
        assert_eq!(&encoded[229..237], &1u64.to_be_bytes());
        assert_eq!(&encoded[237..253], &100_000_001u128.to_be_bytes());
        let mut changed = projection();
        changed.parent_height += 1;
        assert_ne!(changed.canonical_bytes().unwrap(), encoded);
        changed = projection();
        changed.outstanding_base_atoms += 1;
        assert_ne!(changed.canonical_bytes().unwrap(), encoded);
    }
}
