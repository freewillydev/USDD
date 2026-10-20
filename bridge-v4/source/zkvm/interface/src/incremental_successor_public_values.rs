use sha2::{Digest, Sha256};
use std::fmt;

pub const INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2: u32 = 23;
pub const INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2: usize =
    4 + (40 * 32) + (12 * 8) + (15 * 16) + 7;
const BOND_FIXED_SUPPLY_ATOMS_V2: u64 = 2_100_000_000_000_000;
const BOND_SHARE_SCALE_V2: u128 = 100_000_000;
const FUNDING_EPOCH_SECONDS_V2: u64 = 28_800;

/// Consensus-side representation of the incremental successor proof output.
///
/// This deliberately duplicates the byte-level contract from `proof-core`
/// instead of depending on the prover crate. A node/interface decoder must be
/// able to reject malformed or semantically impossible public values without
/// importing any guest implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncrementalSuccessorPublicValuesV2 {
    pub configuration_hash: [u8; 32],
    pub previous_state_root: [u8; 32],
    pub next_state_root: [u8; 32],
    pub transition_txid_consensus: [u8; 32],
    pub prior_exchange_header_root: [u8; 32],
    pub prior_parent_block_hash: [u8; 32],
    pub risk_extrema_root: [u8; 32],
    pub child_availability_root: [u8; 32],
    pub custodian_registry_hash: [u8; 32],
    pub settlement_action_root: [u8; 32],
    pub combined_settlement_root: [u8; 32],
    pub settlement_configuration_hash: [u8; 32],
    pub v18_configuration_hash: [u8; 32],
    pub chain_id: [u8; 32],
    pub bond_asset_id: [u8; 32],
    pub bond_deployment_commitment: [u8; 32],
    pub bond_inventory_covenant_hash: [u8; 32],
    pub bond_state_root: [u8; 32],
    pub funding_state_root: [u8; 32],
    pub redemption_queue_root: [u8; 32],
    pub oracle_certificate_hash: [u8; 32],
    pub matcher_execution_receipt_batch_root: [u8; 32],
    pub next_bond_inbox_head_root: [u8; 32],
    pub next_bond_inbox_processed_root: [u8; 32],
    pub next_bond_inbox_outcome_root: [u8; 32],
    pub previous_inbox_state_hash: [u8; 32],
    pub next_inbox_state_hash: [u8; 32],
    pub recovered_inbox_candidate_root: [u8; 32],
    pub trader_update_transcript_root: [u8; 32],
    pub trader_update_leaf_projection_root: [u8; 32],
    pub trader_economic_mutation_root: [u8; 32],
    pub action_composition_root: [u8; 32],
    pub previous_deposit_inbox_state_hash: [u8; 32],
    pub next_deposit_inbox_state_hash: [u8; 32],
    pub previous_deposit_inbox_head_root: [u8; 32],
    pub next_deposit_inbox_head_root: [u8; 32],
    pub previous_forced_inbox_state_hash: [u8; 32],
    pub next_forced_inbox_state_hash: [u8; 32],
    pub previous_forced_inbox_head_root: [u8; 32],
    pub next_forced_inbox_head_root: [u8; 32],
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub sidechain_height: u64,
    pub mark_price_atoms: u64,
    pub price_lower_atoms: u64,
    pub price_upper_atoms: u64,
    pub issued_share_atoms: u64,
    pub outstanding_share_atoms: u64,
    pub inventory_share_atoms: u64,
    pub queued_redemption_share_atoms: u64,
    pub funding_epoch: u64,
    pub oracle_valid_through_parent_mtp: u64,
    pub global_funding_index_numerator: i128,
    pub lower_deficit_atoms: u128,
    pub upper_deficit_atoms: u128,
    pub full_range_deficit_atoms: u128,
    pub target_reserve_atoms: u128,
    pub insurance_reserve_atoms: u128,
    pub controlled_usdd_atoms: u128,
    pub matcher_sequence: u128,
    pub nav_per_whole_share_usdd_atoms: u128,
    pub coverage_bps: u128,
    pub redemption_head: u128,
    pub redemption_tail: u128,
    pub bond_inbox_entry_count: u128,
    pub bond_inbox_processed_cursor: u128,
    pub bond_inbox_outcome_count: u128,
    pub funding_rate_ppm: i32,
    pub capital_mode: u8,
    pub oracle_mode: u8,
    pub operationally_safe: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncrementalSuccessorPublicValuesError {
    WrongLength,
    UnsupportedVersion,
    ZeroIdentity,
    InvalidParentContext,
    InvalidPriceRange,
    InvalidDeficit,
    InvalidTargetReserve,
    InvalidBondSupply,
    InvalidNav,
    InvalidCoverage,
    InvalidRedemptionQueue,
    InvalidBondInbox,
    InvalidFunding,
    InvalidCapitalMode,
    NonCanonicalBoolean,
}

impl fmt::Display for IncrementalSuccessorPublicValuesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid ECX incremental successor public values: {self:?}"
        )
    }
}

impl std::error::Error for IncrementalSuccessorPublicValuesError {}

impl IncrementalSuccessorPublicValuesV2 {
    pub fn encode(&self) -> [u8; INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2] {
        let mut output = [0_u8; INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2];
        output[0..4].copy_from_slice(&INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        let hashes = [
            self.configuration_hash,
            self.previous_state_root,
            self.next_state_root,
            self.transition_txid_consensus,
            self.prior_exchange_header_root,
            self.prior_parent_block_hash,
            self.risk_extrema_root,
            self.child_availability_root,
            self.custodian_registry_hash,
            self.settlement_action_root,
            self.combined_settlement_root,
            self.settlement_configuration_hash,
            self.v18_configuration_hash,
            self.chain_id,
            self.bond_asset_id,
            self.bond_deployment_commitment,
            self.bond_inventory_covenant_hash,
            self.bond_state_root,
            self.funding_state_root,
            self.redemption_queue_root,
            self.oracle_certificate_hash,
            self.matcher_execution_receipt_batch_root,
            self.next_bond_inbox_head_root,
            self.next_bond_inbox_processed_root,
            self.next_bond_inbox_outcome_root,
            self.previous_inbox_state_hash,
            self.next_inbox_state_hash,
            self.recovered_inbox_candidate_root,
            self.trader_update_transcript_root,
            self.trader_update_leaf_projection_root,
            self.trader_economic_mutation_root,
            self.action_composition_root,
            self.previous_deposit_inbox_state_hash,
            self.next_deposit_inbox_state_hash,
            self.previous_deposit_inbox_head_root,
            self.next_deposit_inbox_head_root,
            self.previous_forced_inbox_state_hash,
            self.next_forced_inbox_state_hash,
            self.previous_forced_inbox_head_root,
            self.next_forced_inbox_head_root,
        ];
        for (index, hash) in hashes.iter().enumerate() {
            let start = 4 + (index * 32);
            output[start..start + 32].copy_from_slice(hash);
        }
        let unsigned = [
            self.prior_parent_height,
            self.prior_parent_mtp,
            self.sidechain_height,
            self.mark_price_atoms,
            self.price_lower_atoms,
            self.price_upper_atoms,
            self.issued_share_atoms,
            self.outstanding_share_atoms,
            self.inventory_share_atoms,
            self.queued_redemption_share_atoms,
            self.funding_epoch,
            self.oracle_valid_through_parent_mtp,
        ];
        let mut cursor = 4 + (40 * 32);
        for value in unsigned {
            output[cursor..cursor + 8].copy_from_slice(&value.to_be_bytes());
            cursor += 8;
        }
        output[cursor..cursor + 16]
            .copy_from_slice(&self.global_funding_index_numerator.to_be_bytes());
        cursor += 16;
        for value in [
            self.lower_deficit_atoms,
            self.upper_deficit_atoms,
            self.full_range_deficit_atoms,
            self.target_reserve_atoms,
            self.insurance_reserve_atoms,
            self.controlled_usdd_atoms,
            self.matcher_sequence,
            self.nav_per_whole_share_usdd_atoms,
            self.coverage_bps,
            self.redemption_head,
            self.redemption_tail,
            self.bond_inbox_entry_count,
            self.bond_inbox_processed_cursor,
            self.bond_inbox_outcome_count,
        ] {
            output[cursor..cursor + 16].copy_from_slice(&value.to_be_bytes());
            cursor += 16;
        }
        output[cursor..cursor + 4].copy_from_slice(&self.funding_rate_ppm.to_be_bytes());
        cursor += 4;
        output[cursor] = self.capital_mode;
        output[cursor + 1] = self.oracle_mode;
        output[cursor + 2] = u8::from(self.operationally_safe);
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IncrementalSuccessorPublicValuesError> {
        use IncrementalSuccessorPublicValuesError as Error;

        if bytes.len() != INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN_V2 {
            return Err(Error::WrongLength);
        }
        if u32::from_be_bytes(bytes[0..4].try_into().expect("four-byte version"))
            != INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_VERSION_V2
        {
            return Err(Error::UnsupportedVersion);
        }
        let mut hashes = [[0_u8; 32]; 40];
        for (index, hash) in hashes.iter_mut().enumerate() {
            let start = 4 + (index * 32);
            hash.copy_from_slice(&bytes[start..start + 32]);
        }
        if hashes.contains(&[0; 32]) {
            return Err(Error::ZeroIdentity);
        }

        let mut cursor = 4 + (40 * 32);
        let mut unsigned = [0_u64; 12];
        for value in &mut unsigned {
            *value = u64::from_be_bytes(
                bytes[cursor..cursor + 8]
                    .try_into()
                    .expect("eight-byte value"),
            );
            cursor += 8;
        }
        if unsigned[0] == 0 || unsigned[1] == 0 || unsigned[2] == 0 {
            return Err(Error::InvalidParentContext);
        }
        if unsigned[3] == 0
            || unsigned[4] == 0
            || unsigned[5] == 0
            || unsigned[4] > unsigned[3]
            || unsigned[3] > unsigned[5]
        {
            return Err(Error::InvalidPriceRange);
        }

        let global_funding_index_numerator = i128::from_be_bytes(
            bytes[cursor..cursor + 16]
                .try_into()
                .expect("sixteen-byte funding index"),
        );
        cursor += 16;
        let mut wide = [0_u128; 14];
        for value in &mut wide {
            *value = u128::from_be_bytes(
                bytes[cursor..cursor + 16]
                    .try_into()
                    .expect("sixteen-byte value"),
            );
            cursor += 16;
        }
        if wide[2] != wide[0].max(wide[1]) {
            return Err(Error::InvalidDeficit);
        }
        let quotient = wide[2] / 4;
        let remainder = wide[2] % 4;
        let expected_target = quotient
            .checked_mul(5)
            .and_then(|value| value.checked_add((remainder * 5).div_ceil(4)))
            .ok_or(Error::InvalidTargetReserve)?;
        if wide[3] != expected_target {
            return Err(Error::InvalidTargetReserve);
        }
        if wide[2] > i128::MAX as u128 || wide[3] > i128::MAX as u128 || wide[4] > i128::MAX as u128 {
            return Err(Error::InvalidDeficit);
        }
        if unsigned[6] != BOND_FIXED_SUPPLY_ATOMS_V2
            || unsigned[7].checked_add(unsigned[8]) != Some(unsigned[6])
        {
            return Err(Error::InvalidBondSupply);
        }
        let expected_nav = if unsigned[7] == 0 {
            0
        } else {
            wide[4]
                .checked_mul(BOND_SHARE_SCALE_V2)
                .ok_or(Error::InvalidNav)?
                / u128::from(unsigned[7])
        };
        if wide[7] != expected_nav {
            return Err(Error::InvalidNav);
        }
        let expected_coverage = if wide[2] == 0 {
            12_500
        } else {
            mul_u128_u64_div(wide[4], 10_000, wide[2]).ok_or(Error::InvalidCoverage)?
        };
        if wide[8] != expected_coverage {
            return Err(Error::InvalidCoverage);
        }
        if wide[9] > wide[10]
            || unsigned[9] > unsigned[7]
            || (wide[9] == wide[10]) != (unsigned[9] == 0)
        {
            return Err(Error::InvalidRedemptionQueue);
        }
        if wide[12] > wide[11] {
            return Err(Error::InvalidBondInbox);
        }
        let funding_rate_ppm = i32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .expect("four-byte funding rate"),
        );
        if unsigned[10] != unsigned[1] / FUNDING_EPOCH_SECONDS_V2
            || unsigned[11] == 0
            || funding_rate_ppm.unsigned_abs() > 10_000
        {
            return Err(Error::InvalidFunding);
        }
        let capital_mode = bytes[cursor + 4];
        let expected_mode = if wide[4] >= wide[3] {
            0
        } else if wide[4] >= wide[2] {
            1
        } else {
            2
        };
        if capital_mode != expected_mode {
            return Err(Error::InvalidCapitalMode);
        }
        let oracle_mode = bytes[cursor + 5];
        if oracle_mode > 3 {
            return Err(Error::InvalidFunding);
        }
        let operationally_safe = match bytes[cursor + 6] {
            0 => false,
            1 => true,
            _ => return Err(Error::NonCanonicalBoolean),
        };

        Ok(Self {
            configuration_hash: hashes[0],
            previous_state_root: hashes[1],
            next_state_root: hashes[2],
            transition_txid_consensus: hashes[3],
            prior_exchange_header_root: hashes[4],
            prior_parent_block_hash: hashes[5],
            risk_extrema_root: hashes[6],
            child_availability_root: hashes[7],
            custodian_registry_hash: hashes[8],
            settlement_action_root: hashes[9],
            combined_settlement_root: hashes[10],
            settlement_configuration_hash: hashes[11],
            v18_configuration_hash: hashes[12],
            chain_id: hashes[13],
            bond_asset_id: hashes[14],
            bond_deployment_commitment: hashes[15],
            bond_inventory_covenant_hash: hashes[16],
            bond_state_root: hashes[17],
            funding_state_root: hashes[18],
            redemption_queue_root: hashes[19],
            oracle_certificate_hash: hashes[20],
            matcher_execution_receipt_batch_root: hashes[21],
            next_bond_inbox_head_root: hashes[22],
            next_bond_inbox_processed_root: hashes[23],
            next_bond_inbox_outcome_root: hashes[24],
            previous_inbox_state_hash: hashes[25],
            next_inbox_state_hash: hashes[26],
            recovered_inbox_candidate_root: hashes[27],
            trader_update_transcript_root: hashes[28],
            trader_update_leaf_projection_root: hashes[29],
            trader_economic_mutation_root: hashes[30],
            action_composition_root: hashes[31],
            previous_deposit_inbox_state_hash: hashes[32],
            next_deposit_inbox_state_hash: hashes[33],
            previous_deposit_inbox_head_root: hashes[34],
            next_deposit_inbox_head_root: hashes[35],
            previous_forced_inbox_state_hash: hashes[36],
            next_forced_inbox_state_hash: hashes[37],
            previous_forced_inbox_head_root: hashes[38],
            next_forced_inbox_head_root: hashes[39],
            prior_parent_height: unsigned[0],
            prior_parent_mtp: unsigned[1],
            sidechain_height: unsigned[2],
            mark_price_atoms: unsigned[3],
            price_lower_atoms: unsigned[4],
            price_upper_atoms: unsigned[5],
            issued_share_atoms: unsigned[6],
            outstanding_share_atoms: unsigned[7],
            inventory_share_atoms: unsigned[8],
            queued_redemption_share_atoms: unsigned[9],
            funding_epoch: unsigned[10],
            oracle_valid_through_parent_mtp: unsigned[11],
            global_funding_index_numerator,
            lower_deficit_atoms: wide[0],
            upper_deficit_atoms: wide[1],
            full_range_deficit_atoms: wide[2],
            target_reserve_atoms: wide[3],
            insurance_reserve_atoms: wide[4],
            controlled_usdd_atoms: wide[5],
            matcher_sequence: wide[6],
            nav_per_whole_share_usdd_atoms: wide[7],
            coverage_bps: wide[8],
            redemption_head: wide[9],
            redemption_tail: wide[10],
            bond_inbox_entry_count: wide[11],
            bond_inbox_processed_cursor: wide[12],
            bond_inbox_outcome_count: wide[13],
            funding_rate_ppm,
            capital_mode,
            oracle_mode,
            operationally_safe,
        })
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

/// Overflow-safe `floor(value * multiplier / divisor)` without a wider host
/// integer. This mirrors the frozen V2 capital projection arithmetic.
fn mul_u128_u64_div(value: u128, multiplier: u64, divisor: u128) -> Option<u128> {
    if divisor == 0 {
        return None;
    }
    fn add_remainders(left: u128, right: u128, divisor: u128) -> (u128, u128) {
        if left >= divisor - right {
            (left - (divisor - right), 1)
        } else {
            (left + right, 0)
        }
    }
    let value_quotient = value / divisor;
    let value_remainder = value % divisor;
    let mut quotient = 0u128;
    let mut remainder = 0u128;
    for bit in (0..u64::BITS).rev() {
        let (next_remainder, carry) = add_remainders(remainder, remainder, divisor);
        remainder = next_remainder;
        quotient = quotient.checked_mul(2)?.checked_add(carry)?;
        if (multiplier >> bit) & 1 == 1 {
            let (next_remainder, carry) = add_remainders(remainder, value_remainder, divisor);
            remainder = next_remainder;
            quotient = quotient.checked_add(value_quotient)?.checked_add(carry)?;
        }
    }
    Some(quotient)
}
