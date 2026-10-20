//! Lifetime-safe insurance-bond state and FIFO queue for the incremental successor.
//!
//! V18 remains frozen with `u64` queue sequence numbers. These types use fresh
//! domains and `u128` head/tail/sequence fields so a reachable successor state
//! cannot halt merely because the historical sequence wire is exhausted.

use crate::bond::{
    capital_mode_for, maximum_redeemable_share_atoms, redemption_usdd_atoms,
    subscription_share_atoms, target_reserve_125, CapitalModeV2, SubscriptionOutcomeV2,
    BOND_FIXED_SUPPLY_ATOMS, BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
};
use crate::codec::{put_u128, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::canonical_hash;
use crate::{Hash32, ProtocolError};

pub const SUCCESSOR_BOND_PROTOCOL_VERSION_V2: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondPublicStateV2 {
    pub version: u8,
    pub bond_asset_id: Hash32,
    pub deployment_commitment: Hash32,
    pub inventory_covenant_hash: Hash32,
    pub insurance_reserve: u128,
    pub issued_share_atoms: u64,
    pub outstanding_share_atoms: u64,
    pub inventory_share_atoms: u64,
    pub full_bound_deficit: u128,
    pub target_reserve: u128,
    pub legacy_fee_pool: u128,
    pub redemption_queue_root: Hash32,
    pub redemption_head: u128,
    pub redemption_tail: u128,
    pub queued_redemption_share_atoms: u64,
    pub capital_mode: CapitalModeV2,
}

impl SuccessorBondPublicStateV2 {
    pub const ENCODED_LEN: usize = 258;

    pub fn validate(self) -> Result<Self, ProtocolError> {
        let conserved_supply = self
            .outstanding_share_atoms
            .checked_add(self.inventory_share_atoms)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let expected_target = target_reserve_125(self.full_bound_deficit)?;
        let expected_mode = capital_mode_for(self.insurance_reserve, self.full_bound_deficit)?;
        let empty_queue = self.redemption_head == self.redemption_tail;
        if self.version != SUCCESSOR_BOND_PROTOCOL_VERSION_V2
            || self.bond_asset_id == [0; 32]
            || self.deployment_commitment == [0; 32]
            || self.inventory_covenant_hash == [0; 32]
            || self.redemption_queue_root == [0; 32]
            || self.issued_share_atoms != BOND_FIXED_SUPPLY_ATOMS
            || conserved_supply != self.issued_share_atoms
            || self.queued_redemption_share_atoms > self.outstanding_share_atoms
            || self.redemption_head > self.redemption_tail
            || empty_queue != (self.queued_redemption_share_atoms == 0)
            || self.insurance_reserve > i128::MAX as u128
            || self.full_bound_deficit > i128::MAX as u128
            || self.target_reserve != expected_target
            || self.target_reserve > i128::MAX as u128
            || self.legacy_fee_pool != 0
            || self.capital_mode != expected_mode
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let state = Self {
            version: decoder.u8()?,
            bond_asset_id: decoder.take()?,
            deployment_commitment: decoder.take()?,
            inventory_covenant_hash: decoder.take()?,
            insurance_reserve: u128::from_be_bytes(decoder.take()?),
            issued_share_atoms: decoder.u64()?,
            outstanding_share_atoms: decoder.u64()?,
            inventory_share_atoms: decoder.u64()?,
            full_bound_deficit: u128::from_be_bytes(decoder.take()?),
            target_reserve: u128::from_be_bytes(decoder.take()?),
            legacy_fee_pool: u128::from_be_bytes(decoder.take()?),
            redemption_queue_root: decoder.take()?,
            redemption_head: u128::from_be_bytes(decoder.take()?),
            redemption_tail: u128::from_be_bytes(decoder.take()?),
            queued_redemption_share_atoms: decoder.u64()?,
            capital_mode: CapitalModeV2::try_from(decoder.u8()?)?,
        };
        decoder.finish()?;
        state.validate()
    }
}

impl CanonicalEncode for SuccessorBondPublicStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.bond_asset_id);
        out.extend_from_slice(&self.deployment_commitment);
        out.extend_from_slice(&self.inventory_covenant_hash);
        put_u128(out, self.insurance_reserve);
        put_u64(out, self.issued_share_atoms);
        put_u64(out, self.outstanding_share_atoms);
        put_u64(out, self.inventory_share_atoms);
        put_u128(out, self.full_bound_deficit);
        put_u128(out, self.target_reserve);
        put_u128(out, self.legacy_fee_pool);
        out.extend_from_slice(&self.redemption_queue_root);
        put_u128(out, self.redemption_head);
        put_u128(out, self.redemption_tail);
        put_u64(out, self.queued_redemption_share_atoms);
        put_u8(out, self.capital_mode as u8);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorRedemptionQueueEntryV2 {
    pub version: u8,
    pub sequence: u128,
    pub request_id: Hash32,
    pub claimant_commitment: Hash32,
    pub destination_script_hash: Hash32,
    pub requested_share_atoms: u64,
    pub remaining_share_atoms: u64,
    pub enqueued_parent_height: u64,
    pub unlock_parent_height: u64,
}

impl SuccessorRedemptionQueueEntryV2 {
    pub const ENCODED_LEN: usize = 145;

    pub fn new(
        sequence: u128,
        request_id: Hash32,
        claimant_commitment: Hash32,
        destination_script_hash: Hash32,
        requested_share_atoms: u64,
        enqueued_parent_height: u64,
    ) -> Result<Self, ProtocolError> {
        Self {
            version: SUCCESSOR_BOND_PROTOCOL_VERSION_V2,
            sequence,
            request_id,
            claimant_commitment,
            destination_script_hash,
            requested_share_atoms,
            remaining_share_atoms: requested_share_atoms,
            enqueued_parent_height,
            unlock_parent_height: enqueued_parent_height
                .checked_add(BOND_REDEMPTION_DELAY_PARENT_BLOCKS)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
        }
        .validate()
    }

    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.version != SUCCESSOR_BOND_PROTOCOL_VERSION_V2
            || self.request_id == [0; 32]
            || self.claimant_commitment == [0; 32]
            || self.destination_script_hash == [0; 32]
            || self.requested_share_atoms == 0
            || self.remaining_share_atoms == 0
            || self.remaining_share_atoms > self.requested_share_atoms
            || self.unlock_parent_height
                != self
                    .enqueued_parent_height
                    .checked_add(BOND_REDEMPTION_DELAY_PARENT_BLOCKS)
                    .ok_or(ProtocolError::ArithmeticOverflow)?
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(self)
    }

    pub fn is_unlocked(self, parent_height: u64) -> bool {
        parent_height >= self.unlock_parent_height
    }
}

impl CanonicalEncode for SuccessorRedemptionQueueEntryV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u128(out, self.sequence);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.claimant_commitment);
        out.extend_from_slice(&self.destination_script_hash);
        put_u64(out, self.requested_share_atoms);
        put_u64(out, self.remaining_share_atoms);
        put_u64(out, self.enqueued_parent_height);
        put_u64(out, self.unlock_parent_height);
    }
}

pub fn successor_redemption_queue_root_v2(
    entries: &[SuccessorRedemptionQueueEntryV2],
) -> Result<Hash32, ProtocolError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    let mut previous = None;
    for entry in entries {
        entry.validate()?;
        if previous.is_some_and(|sequence| sequence >= entry.sequence) {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        previous = Some(entry.sequence);
        entry.encode_to(&mut bytes);
    }
    Ok(canonical_hash(
        "ECX/successor-redemption-queue/v2-u128",
        &RawCanonical(&bytes),
    ))
}

struct RawCanonical<'a>(&'a [u8]);
impl CanonicalEncode for RawCanonical<'_> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessorRedemptionOutcomeV2 {
    pub sequence: u128,
    pub redeemed_share_atoms: u64,
    pub paid_usdd_atoms: u128,
    pub remaining_entry_share_atoms: u64,
    pub insurance_reserve_after: u128,
    pub outstanding_share_atoms_after: u64,
    pub inventory_share_atoms_after: u64,
    pub queued_redemption_share_atoms_after: u64,
    pub redemption_head_after: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessorRedemptionCancellationV2 {
    pub sequence: u128,
    pub released_share_atoms: u64,
    pub queued_redemption_share_atoms_after: u64,
    pub redemption_head_after: u128,
}

pub fn apply_successor_subscription_v2(
    state: SuccessorBondPublicStateV2,
    contribution_usdd_atoms: u128,
) -> Result<SubscriptionOutcomeV2, ProtocolError> {
    state.validate()?;
    let issued = subscription_share_atoms(
        contribution_usdd_atoms,
        state.insurance_reserve,
        state.outstanding_share_atoms,
    )?;
    if issued > state.inventory_share_atoms {
        return Err(ProtocolError::ConservationViolation);
    }
    Ok(SubscriptionOutcomeV2 {
        contributed_usdd_atoms: contribution_usdd_atoms,
        issued_share_atoms: issued,
        insurance_reserve_after: state
            .insurance_reserve
            .checked_add(contribution_usdd_atoms)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        outstanding_share_atoms_after: state
            .outstanding_share_atoms
            .checked_add(issued)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        inventory_share_atoms_after: state.inventory_share_atoms - issued,
    })
}

pub fn plan_successor_fifo_redemption_v2(
    state: SuccessorBondPublicStateV2,
    entry: SuccessorRedemptionQueueEntryV2,
    parent_height: u64,
) -> Result<Option<SuccessorRedemptionOutcomeV2>, ProtocolError> {
    state.validate()?;
    entry.validate()?;
    if entry.sequence != state.redemption_head
        || entry.remaining_share_atoms > state.queued_redemption_share_atoms
        || !entry.is_unlocked(parent_height)
    {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    if state.insurance_reserve <= state.target_reserve {
        return Ok(None);
    }
    let capacity = (state.insurance_reserve - state.target_reserve).min(u128::from(u64::MAX));
    let safe = maximum_redeemable_share_atoms(
        capacity,
        state.insurance_reserve,
        state.outstanding_share_atoms,
    )?;
    let redeemed = entry.remaining_share_atoms.min(safe);
    if redeemed == 0 {
        return Ok(None);
    }
    let paid = redemption_usdd_atoms(
        redeemed,
        state.insurance_reserve,
        state.outstanding_share_atoms,
    )?;
    if paid == 0 {
        return Ok(None);
    }
    let reserve_after = state.insurance_reserve - paid;
    if reserve_after < state.target_reserve {
        return Err(ProtocolError::InsufficientCollateral);
    }
    let remaining = entry.remaining_share_atoms - redeemed;
    Ok(Some(SuccessorRedemptionOutcomeV2 {
        sequence: entry.sequence,
        redeemed_share_atoms: redeemed,
        paid_usdd_atoms: paid,
        remaining_entry_share_atoms: remaining,
        insurance_reserve_after: reserve_after,
        outstanding_share_atoms_after: state.outstanding_share_atoms - redeemed,
        inventory_share_atoms_after: state
            .inventory_share_atoms
            .checked_add(redeemed)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        queued_redemption_share_atoms_after: state.queued_redemption_share_atoms - redeemed,
        redemption_head_after: if remaining == 0 {
            state
                .redemption_head
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?
        } else {
            state.redemption_head
        },
    }))
}

pub fn plan_successor_redemption_cancellation_v2(
    state: SuccessorBondPublicStateV2,
    entry: SuccessorRedemptionQueueEntryV2,
) -> Result<SuccessorRedemptionCancellationV2, ProtocolError> {
    state.validate()?;
    entry.validate()?;
    if entry.sequence < state.redemption_head
        || entry.sequence >= state.redemption_tail
        || entry.remaining_share_atoms > state.queued_redemption_share_atoms
    {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    Ok(SuccessorRedemptionCancellationV2 {
        sequence: entry.sequence,
        released_share_atoms: entry.remaining_share_atoms,
        queued_redemption_share_atoms_after: state.queued_redemption_share_atoms
            - entry.remaining_share_atoms,
        redemption_head_after: if entry.sequence == state.redemption_head {
            state
                .redemption_head
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?
        } else {
            state.redemption_head
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorRedemptionExecutionV2 {
    pub version: u8,
    pub sequence: u128,
    pub request_id: Hash32,
    pub redeemed_share_atoms: u64,
    pub paid_usdd_atoms: u128,
    pub queue_input_opening_commitment: Hash32,
    pub usdd_output_opening_commitment: Hash32,
    pub inventory_output_opening_commitment: Hash32,
    pub queue_remainder_output_opening_commitment: Hash32,
}

impl SuccessorRedemptionExecutionV2 {
    pub const VERSION: u8 = 2;
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.request_id == [0; 32]
            || self.redeemed_share_atoms == 0
            || self.paid_usdd_atoms == 0
            || self.queue_input_opening_commitment == [0; 32]
            || self.usdd_output_opening_commitment == [0; 32]
            || self.inventory_output_opening_commitment == [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successor_queue_and_state_preserve_high_u128_sequences() {
        let sequence = (1u128 << 96) + 7;
        let entry =
            SuccessorRedemptionQueueEntryV2::new(sequence, [1; 32], [2; 32], [3; 32], 5, 100)
                .unwrap();
        assert_eq!(entry.sequence, sequence);
        assert_eq!(entry.canonical_bytes().len(), 145);
        assert_ne!(
            successor_redemption_queue_root_v2(&[entry]).unwrap(),
            [0; 32]
        );
    }
}
