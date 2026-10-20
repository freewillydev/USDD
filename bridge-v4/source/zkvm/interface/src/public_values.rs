use sha2::{Digest, Sha256};
use std::fmt;

pub const PUBLIC_VALUES_V3_VERSION: u32 = 3;
pub const PUBLIC_VALUES_V3_LEN: usize = 276;
pub const PUBLIC_VALUES_V4_VERSION: u32 = 4;
pub const PUBLIC_VALUES_V4_LEN: usize = 609;
pub const PUBLIC_VALUES_V5_VERSION: u32 = 5;
pub const PUBLIC_VALUES_V5_LEN: usize = 850;
pub const BOND_FIXED_SUPPLY_ATOMS_V2: u64 = 2_100_000_000_000_000;
pub const BOND_SHARE_SCALE_V2: u128 = 100_000_000;
pub const BOND_TARGET_COVERAGE_BPS_V2: u128 = 12_500;
pub const MAX_ABS_FUNDING_RATE_PPM_V2: u32 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicValuesError {
    WrongLength,
    UnsupportedVersion,
    InvalidCapitalMode,
    InvalidPriceRange,
    ZeroIdentity,
    InvalidParentContext,
    InvalidCapitalAccounting,
    InvalidRedemptionQueue,
    InvalidFundingRate,
    InvalidOracleMode,
    StaleOracle,
    InvalidBondInbox,
    InvalidExecutionSequence,
}

impl fmt::Display for PublicValuesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid ECX public values: {self:?}")
    }
}

impl std::error::Error for PublicValuesError {}

/// Independent consensus-side encoder for the exact bytes committed by the
/// SP1 transition guest. All integers use big-endian encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicValuesV3 {
    pub transition_journal_domain_sha256: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub current_state_hash: [u8; 32],
    pub next_state_hash: [u8; 32],
    pub transition_txid_consensus: [u8; 32],
    pub prior_exchange_header_root: [u8; 32],
    pub prior_parent_block_hash: [u8; 32],
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub transition_journal_hash: [u8; 32],
}

impl PublicValuesV3 {
    pub fn encode(&self) -> [u8; PUBLIC_VALUES_V3_LEN] {
        let mut output = [0_u8; PUBLIC_VALUES_V3_LEN];
        output[0..32].copy_from_slice(&self.transition_journal_domain_sha256);
        output[32..36].copy_from_slice(&PUBLIC_VALUES_V3_VERSION.to_be_bytes());
        output[36..68].copy_from_slice(&self.configuration_hash);
        output[68..100].copy_from_slice(&self.current_state_hash);
        output[100..132].copy_from_slice(&self.next_state_hash);
        output[132..164].copy_from_slice(&self.transition_txid_consensus);
        output[164..196].copy_from_slice(&self.prior_exchange_header_root);
        output[196..228].copy_from_slice(&self.prior_parent_block_hash);
        output[228..236].copy_from_slice(&self.prior_parent_height.to_be_bytes());
        output[236..244].copy_from_slice(&self.prior_parent_mtp.to_be_bytes());
        output[244..276].copy_from_slice(&self.transition_journal_hash);
        output
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

/// Independent consensus-side encoder for the insurance-bond transition
/// program. V3 remains byte-for-byte unchanged. The aggregate capital fields
/// below are deliberately public; no account, order, position, subscription,
/// redemption, or transfer amount is exposed by this record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicValuesV4 {
    pub transition_journal_domain_sha256: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub current_state_hash: [u8; 32],
    pub next_state_hash: [u8; 32],
    pub transition_txid_consensus: [u8; 32],
    pub prior_exchange_header_root: [u8; 32],
    pub prior_parent_block_hash: [u8; 32],
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub transition_journal_hash: [u8; 32],
    pub bond_asset_id: [u8; 32],
    pub bond_deployment_commitment: [u8; 32],
    pub bond_state_root: [u8; 32],
    pub redemption_queue_root: [u8; 32],
    pub funding_state_root: [u8; 32],
    pub conversion_legs_commitment: [u8; 32],
    pub insurance_reserve: u128,
    pub outstanding_share_atoms: u64,
    pub nav_per_whole_share_usdd_atoms: u128,
    pub full_bound_deficit: u128,
    pub target_reserve: u128,
    pub coverage_bps: u128,
    pub capital_mode: u8,
    pub authenticated_min_price: u64,
    pub authenticated_max_price: u64,
    pub funding_epoch: u64,
    pub funding_rate_ppm: i32,
    pub redemption_head: u64,
    pub redemption_tail: u64,
    pub queued_redemption_share_atoms: u64,
}

impl PublicValuesV4 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicValuesError> {
        if bytes.len() != PUBLIC_VALUES_V4_LEN {
            return Err(PublicValuesError::WrongLength);
        }
        let version = u32::from_be_bytes(bytes[32..36].try_into().expect("fixed four bytes"));
        if version != PUBLIC_VALUES_V4_VERSION {
            return Err(PublicValuesError::UnsupportedVersion);
        }
        let capital_mode = bytes[556];
        if capital_mode > 2 {
            return Err(PublicValuesError::InvalidCapitalMode);
        }
        let authenticated_min_price =
            u64::from_be_bytes(bytes[557..565].try_into().expect("fixed eight bytes"));
        let authenticated_max_price =
            u64::from_be_bytes(bytes[565..573].try_into().expect("fixed eight bytes"));
        if authenticated_min_price == 0 || authenticated_max_price <= authenticated_min_price {
            return Err(PublicValuesError::InvalidPriceRange);
        }
        let hash = |range: core::ops::Range<usize>| -> [u8; 32] {
            bytes[range].try_into().expect("fixed 32-byte range")
        };
        let decoded = Self {
            transition_journal_domain_sha256: hash(0..32),
            configuration_hash: hash(36..68),
            current_state_hash: hash(68..100),
            next_state_hash: hash(100..132),
            transition_txid_consensus: hash(132..164),
            prior_exchange_header_root: hash(164..196),
            prior_parent_block_hash: hash(196..228),
            prior_parent_height: u64::from_be_bytes(
                bytes[228..236].try_into().expect("fixed eight bytes"),
            ),
            prior_parent_mtp: u64::from_be_bytes(
                bytes[236..244].try_into().expect("fixed eight bytes"),
            ),
            transition_journal_hash: hash(244..276),
            bond_asset_id: hash(276..308),
            bond_deployment_commitment: hash(308..340),
            bond_state_root: hash(340..372),
            redemption_queue_root: hash(372..404),
            funding_state_root: hash(404..436),
            conversion_legs_commitment: hash(436..468),
            insurance_reserve: u128::from_be_bytes(
                bytes[468..484].try_into().expect("fixed 16 bytes"),
            ),
            outstanding_share_atoms: u64::from_be_bytes(
                bytes[484..492].try_into().expect("fixed eight bytes"),
            ),
            nav_per_whole_share_usdd_atoms: u128::from_be_bytes(
                bytes[492..508].try_into().expect("fixed 16 bytes"),
            ),
            full_bound_deficit: u128::from_be_bytes(
                bytes[508..524].try_into().expect("fixed 16 bytes"),
            ),
            target_reserve: u128::from_be_bytes(
                bytes[524..540].try_into().expect("fixed 16 bytes"),
            ),
            coverage_bps: u128::from_be_bytes(bytes[540..556].try_into().expect("fixed 16 bytes")),
            capital_mode,
            authenticated_min_price,
            authenticated_max_price,
            funding_epoch: u64::from_be_bytes(
                bytes[573..581].try_into().expect("fixed eight bytes"),
            ),
            funding_rate_ppm: i32::from_be_bytes(
                bytes[581..585].try_into().expect("fixed four bytes"),
            ),
            redemption_head: u64::from_be_bytes(
                bytes[585..593].try_into().expect("fixed eight bytes"),
            ),
            redemption_tail: u64::from_be_bytes(
                bytes[593..601].try_into().expect("fixed eight bytes"),
            ),
            queued_redemption_share_atoms: u64::from_be_bytes(
                bytes[601..609].try_into().expect("fixed eight bytes"),
            ),
        };
        decoded.validate_semantics()?;
        Ok(decoded)
    }

    /// Independently validate every aggregate used by the node's public
    /// capital projection. These checks intentionally duplicate the proof
    /// statement instead of trusting a well-shaped byte string.
    pub fn validate_semantics(&self) -> Result<(), PublicValuesError> {
        let identities = [
            self.transition_journal_domain_sha256,
            self.configuration_hash,
            self.current_state_hash,
            self.next_state_hash,
            self.transition_txid_consensus,
            self.prior_exchange_header_root,
            self.prior_parent_block_hash,
            self.transition_journal_hash,
            self.bond_asset_id,
            self.bond_deployment_commitment,
            self.bond_state_root,
            self.redemption_queue_root,
            self.funding_state_root,
            self.conversion_legs_commitment,
        ];
        if identities.contains(&[0; 32]) {
            return Err(PublicValuesError::ZeroIdentity);
        }
        if self.prior_parent_height == 0 || self.prior_parent_mtp == 0 {
            return Err(PublicValuesError::InvalidParentContext);
        }
        if self.insurance_reserve > i128::MAX as u128
            || self.full_bound_deficit > i128::MAX as u128
            || self.outstanding_share_atoms > BOND_FIXED_SUPPLY_ATOMS_V2
        {
            return Err(PublicValuesError::InvalidCapitalAccounting);
        }
        let target = target_reserve_125(self.full_bound_deficit)
            .ok_or(PublicValuesError::InvalidCapitalAccounting)?;
        if target > i128::MAX as u128 {
            return Err(PublicValuesError::InvalidCapitalAccounting);
        }
        let coverage = coverage_bps(self.insurance_reserve, self.full_bound_deficit)
            .ok_or(PublicValuesError::InvalidCapitalAccounting)?;
        let mode = if self.insurance_reserve >= target {
            0
        } else if self.insurance_reserve >= self.full_bound_deficit {
            1
        } else {
            2
        };
        let nav = if self.outstanding_share_atoms == 0 {
            0
        } else {
            self.insurance_reserve
                .checked_mul(BOND_SHARE_SCALE_V2)
                .ok_or(PublicValuesError::InvalidCapitalAccounting)?
                / u128::from(self.outstanding_share_atoms)
        };
        if self.target_reserve != target
            || self.coverage_bps != coverage
            || self.capital_mode != mode
            || self.nav_per_whole_share_usdd_atoms != nav
        {
            return Err(PublicValuesError::InvalidCapitalAccounting);
        }
        let empty_queue = self.redemption_head == self.redemption_tail;
        if self.redemption_head > self.redemption_tail
            || self.queued_redemption_share_atoms > self.outstanding_share_atoms
            || empty_queue != (self.queued_redemption_share_atoms == 0)
        {
            return Err(PublicValuesError::InvalidRedemptionQueue);
        }
        if self.funding_rate_ppm.unsigned_abs() > MAX_ABS_FUNDING_RATE_PPM_V2 {
            return Err(PublicValuesError::InvalidFundingRate);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; PUBLIC_VALUES_V4_LEN] {
        let mut output = [0_u8; PUBLIC_VALUES_V4_LEN];
        let mut cursor = 0usize;
        macro_rules! put {
            ($bytes:expr) => {{
                let bytes = $bytes;
                let end = cursor + bytes.len();
                output[cursor..end].copy_from_slice(bytes);
                cursor = end;
            }};
        }

        put!(&self.transition_journal_domain_sha256);
        put!(&PUBLIC_VALUES_V4_VERSION.to_be_bytes());
        put!(&self.configuration_hash);
        put!(&self.current_state_hash);
        put!(&self.next_state_hash);
        put!(&self.transition_txid_consensus);
        put!(&self.prior_exchange_header_root);
        put!(&self.prior_parent_block_hash);
        put!(&self.prior_parent_height.to_be_bytes());
        put!(&self.prior_parent_mtp.to_be_bytes());
        put!(&self.transition_journal_hash);
        put!(&self.bond_asset_id);
        put!(&self.bond_deployment_commitment);
        put!(&self.bond_state_root);
        put!(&self.redemption_queue_root);
        put!(&self.funding_state_root);
        put!(&self.conversion_legs_commitment);
        put!(&self.insurance_reserve.to_be_bytes());
        put!(&self.outstanding_share_atoms.to_be_bytes());
        put!(&self.nav_per_whole_share_usdd_atoms.to_be_bytes());
        put!(&self.full_bound_deficit.to_be_bytes());
        put!(&self.target_reserve.to_be_bytes());
        put!(&self.coverage_bps.to_be_bytes());
        put!(&[self.capital_mode]);
        put!(&self.authenticated_min_price.to_be_bytes());
        put!(&self.authenticated_max_price.to_be_bytes());
        put!(&self.funding_epoch.to_be_bytes());
        put!(&self.funding_rate_ppm.to_be_bytes());
        put!(&self.redemption_head.to_be_bytes());
        put!(&self.redemption_tail.to_be_bytes());
        put!(&self.queued_redemption_share_atoms.to_be_bytes());
        debug_assert_eq!(cursor, PUBLIC_VALUES_V4_LEN);
        output
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

/// Live insurance-bond statement. PublicValuesV4 above is retained only as a
/// disjoint pre-freeze regression schema; it is not accepted by the V2
/// singleton. The first 609 bytes keep the aggregate capital layout while V5
/// adds authenticated oracle, availability, inbox and matcher-execution state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicValuesV5 {
    pub transition_journal_domain_sha256: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub current_state_hash: [u8; 32],
    pub next_state_hash: [u8; 32],
    pub transition_txid_consensus: [u8; 32],
    pub prior_exchange_header_root: [u8; 32],
    pub prior_parent_block_hash: [u8; 32],
    pub prior_parent_height: u64,
    pub prior_parent_mtp: u64,
    pub transition_journal_hash: [u8; 32],
    pub bond_asset_id: [u8; 32],
    pub bond_deployment_commitment: [u8; 32],
    pub bond_state_root: [u8; 32],
    pub redemption_queue_root: [u8; 32],
    pub funding_state_root: [u8; 32],
    pub conversion_legs_commitment: [u8; 32],
    pub insurance_reserve: u128,
    pub outstanding_share_atoms: u64,
    pub nav_per_whole_share_usdd_atoms: u128,
    pub full_bound_deficit: u128,
    pub target_reserve: u128,
    pub coverage_bps: u128,
    pub capital_mode: u8,
    pub authenticated_min_price: u64,
    pub authenticated_max_price: u64,
    pub funding_epoch: u64,
    pub funding_rate_ppm: i32,
    pub redemption_head: u64,
    pub redemption_tail: u64,
    pub queued_redemption_share_atoms: u64,
    pub oracle_certificate_hash: [u8; 32],
    pub oracle_valid_through_mtp: u64,
    pub oracle_mode: u8,
    pub next_encrypted_availability_root: [u8; 32],
    pub bond_inbox_head_root: [u8; 32],
    pub bond_inbox_entry_count: u64,
    pub bond_inbox_processed_root: [u8; 32],
    pub bond_inbox_cursor: u64,
    pub bond_inbox_outcome_root: [u8; 32],
    pub bond_inbox_outcome_count: u64,
    pub matcher_execution_receipt_batch_root: [u8; 32],
    pub previous_matcher_execution_sequence: u64,
    pub next_matcher_execution_sequence: u64,
}

impl PublicValuesV5 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicValuesError> {
        if bytes.len() != PUBLIC_VALUES_V5_LEN {
            return Err(PublicValuesError::WrongLength);
        }
        if u32::from_be_bytes(bytes[32..36].try_into().expect("fixed four bytes"))
            != PUBLIC_VALUES_V5_VERSION
        {
            return Err(PublicValuesError::UnsupportedVersion);
        }
        let hash = |range: core::ops::Range<usize>| -> [u8; 32] {
            bytes[range].try_into().expect("fixed 32-byte range")
        };
        let decoded = Self {
            transition_journal_domain_sha256: hash(0..32),
            configuration_hash: hash(36..68),
            current_state_hash: hash(68..100),
            next_state_hash: hash(100..132),
            transition_txid_consensus: hash(132..164),
            prior_exchange_header_root: hash(164..196),
            prior_parent_block_hash: hash(196..228),
            prior_parent_height: u64::from_be_bytes(bytes[228..236].try_into().unwrap()),
            prior_parent_mtp: u64::from_be_bytes(bytes[236..244].try_into().unwrap()),
            transition_journal_hash: hash(244..276),
            bond_asset_id: hash(276..308),
            bond_deployment_commitment: hash(308..340),
            bond_state_root: hash(340..372),
            redemption_queue_root: hash(372..404),
            funding_state_root: hash(404..436),
            conversion_legs_commitment: hash(436..468),
            insurance_reserve: u128::from_be_bytes(bytes[468..484].try_into().unwrap()),
            outstanding_share_atoms: u64::from_be_bytes(bytes[484..492].try_into().unwrap()),
            nav_per_whole_share_usdd_atoms: u128::from_be_bytes(
                bytes[492..508].try_into().unwrap(),
            ),
            full_bound_deficit: u128::from_be_bytes(bytes[508..524].try_into().unwrap()),
            target_reserve: u128::from_be_bytes(bytes[524..540].try_into().unwrap()),
            coverage_bps: u128::from_be_bytes(bytes[540..556].try_into().unwrap()),
            capital_mode: bytes[556],
            authenticated_min_price: u64::from_be_bytes(bytes[557..565].try_into().unwrap()),
            authenticated_max_price: u64::from_be_bytes(bytes[565..573].try_into().unwrap()),
            funding_epoch: u64::from_be_bytes(bytes[573..581].try_into().unwrap()),
            funding_rate_ppm: i32::from_be_bytes(bytes[581..585].try_into().unwrap()),
            redemption_head: u64::from_be_bytes(bytes[585..593].try_into().unwrap()),
            redemption_tail: u64::from_be_bytes(bytes[593..601].try_into().unwrap()),
            queued_redemption_share_atoms: u64::from_be_bytes(bytes[601..609].try_into().unwrap()),
            oracle_certificate_hash: hash(609..641),
            oracle_valid_through_mtp: u64::from_be_bytes(bytes[641..649].try_into().unwrap()),
            oracle_mode: bytes[649],
            next_encrypted_availability_root: hash(650..682),
            bond_inbox_head_root: hash(682..714),
            bond_inbox_entry_count: u64::from_be_bytes(bytes[714..722].try_into().unwrap()),
            bond_inbox_processed_root: hash(722..754),
            bond_inbox_cursor: u64::from_be_bytes(bytes[754..762].try_into().unwrap()),
            bond_inbox_outcome_root: hash(762..794),
            bond_inbox_outcome_count: u64::from_be_bytes(bytes[794..802].try_into().unwrap()),
            matcher_execution_receipt_batch_root: hash(802..834),
            previous_matcher_execution_sequence: u64::from_be_bytes(
                bytes[834..842].try_into().unwrap(),
            ),
            next_matcher_execution_sequence: u64::from_be_bytes(
                bytes[842..850].try_into().unwrap(),
            ),
        };
        decoded.validate_semantics()?;
        Ok(decoded)
    }

    pub fn validate_semantics(&self) -> Result<(), PublicValuesError> {
        let capital = PublicValuesV4 {
            transition_journal_domain_sha256: self.transition_journal_domain_sha256,
            configuration_hash: self.configuration_hash,
            current_state_hash: self.current_state_hash,
            next_state_hash: self.next_state_hash,
            transition_txid_consensus: self.transition_txid_consensus,
            prior_exchange_header_root: self.prior_exchange_header_root,
            prior_parent_block_hash: self.prior_parent_block_hash,
            prior_parent_height: self.prior_parent_height,
            prior_parent_mtp: self.prior_parent_mtp,
            transition_journal_hash: self.transition_journal_hash,
            bond_asset_id: self.bond_asset_id,
            bond_deployment_commitment: self.bond_deployment_commitment,
            bond_state_root: self.bond_state_root,
            redemption_queue_root: self.redemption_queue_root,
            funding_state_root: self.funding_state_root,
            conversion_legs_commitment: self.conversion_legs_commitment,
            insurance_reserve: self.insurance_reserve,
            outstanding_share_atoms: self.outstanding_share_atoms,
            nav_per_whole_share_usdd_atoms: self.nav_per_whole_share_usdd_atoms,
            full_bound_deficit: self.full_bound_deficit,
            target_reserve: self.target_reserve,
            coverage_bps: self.coverage_bps,
            capital_mode: self.capital_mode,
            authenticated_min_price: self.authenticated_min_price,
            authenticated_max_price: self.authenticated_max_price,
            funding_epoch: self.funding_epoch,
            funding_rate_ppm: self.funding_rate_ppm,
            redemption_head: self.redemption_head,
            redemption_tail: self.redemption_tail,
            queued_redemption_share_atoms: self.queued_redemption_share_atoms,
        };
        capital.validate_semantics()?;
        let appended_identities = [
            self.oracle_certificate_hash,
            self.next_encrypted_availability_root,
            self.bond_inbox_head_root,
            self.bond_inbox_processed_root,
            self.bond_inbox_outcome_root,
            self.matcher_execution_receipt_batch_root,
        ];
        if appended_identities.contains(&[0; 32]) {
            return Err(PublicValuesError::ZeroIdentity);
        }
        if self.oracle_mode > 3 {
            return Err(PublicValuesError::InvalidOracleMode);
        }
        if self.oracle_valid_through_mtp < self.prior_parent_mtp {
            return Err(PublicValuesError::StaleOracle);
        }
        if self.bond_inbox_cursor > self.bond_inbox_entry_count
            || self.bond_inbox_outcome_count != self.bond_inbox_cursor
            || (self.bond_inbox_cursor == self.bond_inbox_entry_count
                && self.bond_inbox_head_root != self.bond_inbox_processed_root)
        {
            return Err(PublicValuesError::InvalidBondInbox);
        }
        if self.next_matcher_execution_sequence < self.previous_matcher_execution_sequence {
            return Err(PublicValuesError::InvalidExecutionSequence);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; PUBLIC_VALUES_V5_LEN] {
        let mut output = [0_u8; PUBLIC_VALUES_V5_LEN];
        let mut cursor = 0usize;
        macro_rules! put {
            ($bytes:expr) => {{
                let bytes = $bytes;
                let end = cursor + bytes.len();
                output[cursor..end].copy_from_slice(bytes);
                cursor = end;
            }};
        }
        put!(&self.transition_journal_domain_sha256);
        put!(&PUBLIC_VALUES_V5_VERSION.to_be_bytes());
        put!(&self.configuration_hash);
        put!(&self.current_state_hash);
        put!(&self.next_state_hash);
        put!(&self.transition_txid_consensus);
        put!(&self.prior_exchange_header_root);
        put!(&self.prior_parent_block_hash);
        put!(&self.prior_parent_height.to_be_bytes());
        put!(&self.prior_parent_mtp.to_be_bytes());
        put!(&self.transition_journal_hash);
        put!(&self.bond_asset_id);
        put!(&self.bond_deployment_commitment);
        put!(&self.bond_state_root);
        put!(&self.redemption_queue_root);
        put!(&self.funding_state_root);
        put!(&self.conversion_legs_commitment);
        put!(&self.insurance_reserve.to_be_bytes());
        put!(&self.outstanding_share_atoms.to_be_bytes());
        put!(&self.nav_per_whole_share_usdd_atoms.to_be_bytes());
        put!(&self.full_bound_deficit.to_be_bytes());
        put!(&self.target_reserve.to_be_bytes());
        put!(&self.coverage_bps.to_be_bytes());
        put!(&[self.capital_mode]);
        put!(&self.authenticated_min_price.to_be_bytes());
        put!(&self.authenticated_max_price.to_be_bytes());
        put!(&self.funding_epoch.to_be_bytes());
        put!(&self.funding_rate_ppm.to_be_bytes());
        put!(&self.redemption_head.to_be_bytes());
        put!(&self.redemption_tail.to_be_bytes());
        put!(&self.queued_redemption_share_atoms.to_be_bytes());
        put!(&self.oracle_certificate_hash);
        put!(&self.oracle_valid_through_mtp.to_be_bytes());
        put!(&[self.oracle_mode]);
        put!(&self.next_encrypted_availability_root);
        put!(&self.bond_inbox_head_root);
        put!(&self.bond_inbox_entry_count.to_be_bytes());
        put!(&self.bond_inbox_processed_root);
        put!(&self.bond_inbox_cursor.to_be_bytes());
        put!(&self.bond_inbox_outcome_root);
        put!(&self.bond_inbox_outcome_count.to_be_bytes());
        put!(&self.matcher_execution_receipt_batch_root);
        put!(&self.previous_matcher_execution_sequence.to_be_bytes());
        put!(&self.next_matcher_execution_sequence.to_be_bytes());
        debug_assert_eq!(cursor, PUBLIC_VALUES_V5_LEN);
        output
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

fn target_reserve_125(deficit: u128) -> Option<u128> {
    let quarter = deficit / 4;
    deficit
        .checked_add(quarter)?
        .checked_add(u128::from(deficit % 4 != 0))
}

fn coverage_bps(reserve: u128, deficit: u128) -> Option<u128> {
    if deficit == 0 {
        return Some(BOND_TARGET_COVERAGE_BPS_V2);
    }
    mul_u128_u64_div(reserve, 10_000, deficit)
}

/// Overflow-safe `floor(value * multiplier / divisor)`, matching the V2
/// protocol arithmetic without requiring a 256-bit host integer.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vector() -> PublicValuesV3 {
        PublicValuesV3 {
            transition_journal_domain_sha256: [0x11; 32],
            configuration_hash: [0x22; 32],
            current_state_hash: [0x33; 32],
            next_state_hash: [0x44; 32],
            transition_txid_consensus: [0x55; 32],
            prior_exchange_header_root: [0x66; 32],
            prior_parent_block_hash: [0x88; 32],
            prior_parent_height: 0x0102_0304_0506_0708,
            prior_parent_mtp: 0x1112_1314_1516_1718,
            transition_journal_hash: [0x77; 32],
        }
    }

    fn v5_vector() -> PublicValuesV5 {
        PublicValuesV5 {
            transition_journal_domain_sha256: [1; 32],
            configuration_hash: [2; 32],
            current_state_hash: [3; 32],
            next_state_hash: [4; 32],
            transition_txid_consensus: [5; 32],
            prior_exchange_header_root: [6; 32],
            prior_parent_block_hash: [7; 32],
            prior_parent_height: 8,
            prior_parent_mtp: 9,
            transition_journal_hash: [10; 32],
            bond_asset_id: [11; 32],
            bond_deployment_commitment: [12; 32],
            bond_state_root: [13; 32],
            redemption_queue_root: [14; 32],
            funding_state_root: [15; 32],
            conversion_legs_commitment: [16; 32],
            insurance_reserve: 1_000,
            outstanding_share_atoms: 100,
            nav_per_whole_share_usdd_atoms: 1_000_000_000,
            full_bound_deficit: 800,
            target_reserve: 1_000,
            coverage_bps: 12_500,
            capital_mode: 0,
            authenticated_min_price: 22,
            authenticated_max_price: 23,
            funding_epoch: 24,
            funding_rate_ppm: -25,
            redemption_head: 26,
            redemption_tail: 27,
            queued_redemption_share_atoms: 28,
            oracle_certificate_hash: [17; 32],
            oracle_valid_through_mtp: 30,
            oracle_mode: 0,
            next_encrypted_availability_root: [18; 32],
            bond_inbox_head_root: [19; 32],
            bond_inbox_entry_count: 4,
            bond_inbox_processed_root: [20; 32],
            bond_inbox_cursor: 3,
            bond_inbox_outcome_root: [21; 32],
            bond_inbox_outcome_count: 3,
            matcher_execution_receipt_batch_root: [22; 32],
            previous_matcher_execution_sequence: 5,
            next_matcher_execution_sequence: 6,
        }
    }

    #[test]
    fn v3_offsets_and_endianness_are_frozen() {
        let encoded = vector().encode();
        assert_eq!(encoded.len(), 276);
        assert_eq!(&encoded[0..32], &[0x11; 32]);
        assert_eq!(&encoded[32..36], &[0, 0, 0, 3]);
        assert_eq!(&encoded[36..68], &[0x22; 32]);
        assert_eq!(&encoded[68..100], &[0x33; 32]);
        assert_eq!(&encoded[100..132], &[0x44; 32]);
        assert_eq!(&encoded[132..164], &[0x55; 32]);
        assert_eq!(&encoded[164..196], &[0x66; 32]);
        assert_eq!(&encoded[196..228], &[0x88; 32]);
        assert_eq!(&encoded[228..236], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            &encoded[236..244],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
        assert_eq!(&encoded[244..276], &[0x77; 32]);
    }

    #[test]
    fn v3_sha256_vector_is_frozen() {
        assert_eq!(
            vector().sha256(),
            [
                0xfb, 0x85, 0xa9, 0x88, 0x84, 0x4e, 0xcf, 0x71, 0xcd, 0x64, 0x63, 0x63, 0x80, 0x9d,
                0xd8, 0x64, 0x1e, 0x26, 0x69, 0xbd, 0x28, 0x0d, 0x21, 0xfa, 0x7a, 0x38, 0xd9, 0xaa,
                0xe3, 0xc2, 0x21, 0xc4,
            ]
        );
    }

    #[test]
    fn v4_is_additive_and_has_frozen_offsets() {
        let values = PublicValuesV4 {
            transition_journal_domain_sha256: [0x01; 32],
            configuration_hash: [0x02; 32],
            current_state_hash: [0x03; 32],
            next_state_hash: [0x04; 32],
            transition_txid_consensus: [0x05; 32],
            prior_exchange_header_root: [0x06; 32],
            prior_parent_block_hash: [0x07; 32],
            prior_parent_height: 8,
            prior_parent_mtp: 9,
            transition_journal_hash: [0x0a; 32],
            bond_asset_id: [0x0b; 32],
            bond_deployment_commitment: [0x0c; 32],
            bond_state_root: [0x0d; 32],
            redemption_queue_root: [0x0e; 32],
            funding_state_root: [0x0f; 32],
            conversion_legs_commitment: [0x10; 32],
            insurance_reserve: 1_000,
            outstanding_share_atoms: 100,
            nav_per_whole_share_usdd_atoms: 1_000_000_000,
            full_bound_deficit: 800,
            target_reserve: 1_000,
            coverage_bps: 12_500,
            capital_mode: 0,
            authenticated_min_price: 22,
            authenticated_max_price: 23,
            funding_epoch: 24,
            funding_rate_ppm: -25,
            redemption_head: 26,
            redemption_tail: 27,
            queued_redemption_share_atoms: 28,
        };
        let encoded = values.encode();
        assert_eq!(encoded.len(), PUBLIC_VALUES_V4_LEN);
        assert_eq!(&encoded[32..36], &[0, 0, 0, 4]);
        assert_eq!(&encoded[276..308], &[0x0b; 32]);
        assert_eq!(&encoded[404..436], &[0x0f; 32]);
        assert_eq!(&encoded[436..468], &[0x10; 32]);
        assert_eq!(&encoded[468..484], &1_000u128.to_be_bytes());
        assert_eq!(&encoded[484..492], &100u64.to_be_bytes());
        assert_eq!(encoded[556], 0);
        assert_eq!(&encoded[557..565], &22u64.to_be_bytes());
        assert_eq!(&encoded[565..573], &23u64.to_be_bytes());
        assert_eq!(&encoded[573..581], &24u64.to_be_bytes());
        assert_eq!(&encoded[581..585], &(-25i32).to_be_bytes());
        assert_eq!(&encoded[601..609], &28u64.to_be_bytes());
        assert_eq!(
            values.sha256(),
            [
                0xaa, 0x2d, 0x0f, 0x9e, 0x1f, 0xbe, 0xe0, 0xcc, 0x38, 0x1d, 0x82, 0x1c, 0xd9, 0x82,
                0x75, 0x83, 0xbd, 0xdb, 0x04, 0x3c, 0x7b, 0x96, 0x4a, 0xb5, 0xe1, 0x04, 0x1e, 0x49,
                0x20, 0x63, 0x23, 0x15,
            ]
        );
        assert_eq!(PublicValuesV4::decode(&encoded), Ok(values));
    }

    #[test]
    fn v4_decoder_rejects_noncanonical_shape() {
        let valid = PublicValuesV4 {
            transition_journal_domain_sha256: [1; 32],
            configuration_hash: [2; 32],
            current_state_hash: [3; 32],
            next_state_hash: [4; 32],
            transition_txid_consensus: [5; 32],
            prior_exchange_header_root: [6; 32],
            prior_parent_block_hash: [7; 32],
            prior_parent_height: 8,
            prior_parent_mtp: 9,
            transition_journal_hash: [10; 32],
            bond_asset_id: [11; 32],
            bond_deployment_commitment: [12; 32],
            bond_state_root: [13; 32],
            redemption_queue_root: [14; 32],
            funding_state_root: [15; 32],
            conversion_legs_commitment: [16; 32],
            insurance_reserve: 1_000,
            outstanding_share_atoms: 100,
            nav_per_whole_share_usdd_atoms: 1_000_000_000,
            full_bound_deficit: 800,
            target_reserve: 1_000,
            coverage_bps: 12_500,
            capital_mode: 0,
            authenticated_min_price: 23,
            authenticated_max_price: 24,
            funding_epoch: 25,
            funding_rate_ppm: 26,
            redemption_head: 27,
            redemption_tail: 28,
            queued_redemption_share_atoms: 29,
        }
        .encode();
        let mut encoded = valid;
        encoded[32..36].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::UnsupportedVersion)
        );
        encoded[32..36].copy_from_slice(&PUBLIC_VALUES_V4_VERSION.to_be_bytes());
        encoded[556] = 3;
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::InvalidCapitalMode)
        );

        let mut encoded = valid;
        encoded[..32].fill(0);
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::ZeroIdentity)
        );

        let mut encoded = valid;
        encoded[228..236].fill(0);
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::InvalidParentContext)
        );

        for range in [492..508, 524..540, 540..556] {
            let mut encoded = valid;
            encoded[range].fill(0);
            assert_eq!(
                PublicValuesV4::decode(&encoded),
                Err(PublicValuesError::InvalidCapitalAccounting)
            );
        }

        let mut encoded = valid;
        encoded[484..492].copy_from_slice(&(BOND_FIXED_SUPPLY_ATOMS_V2 + 1).to_be_bytes());
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::InvalidCapitalAccounting)
        );

        let mut encoded = valid;
        encoded[556] = 1;
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::InvalidCapitalAccounting)
        );

        let mut encoded = valid;
        encoded[585..593].copy_from_slice(&29u64.to_be_bytes());
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::InvalidRedemptionQueue)
        );

        let mut encoded = valid;
        encoded[601..609].fill(0);
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::InvalidRedemptionQueue)
        );

        let mut encoded = valid;
        encoded[581..585].copy_from_slice(&10_001i32.to_be_bytes());
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::InvalidFundingRate)
        );
    }

    #[test]
    fn public_values_v5_exact_layout_is_frozen() {
        let values = v5_vector();
        let encoded = values.encode();
        assert_eq!(encoded.len(), PUBLIC_VALUES_V5_LEN);
        assert_eq!(&encoded[32..36], &PUBLIC_VALUES_V5_VERSION.to_be_bytes());
        assert_eq!(&encoded[436..468], &[16; 32]);
        assert_eq!(&encoded[609..641], &[17; 32]);
        assert_eq!(&encoded[641..649], &30u64.to_be_bytes());
        assert_eq!(encoded[649], 0);
        assert_eq!(&encoded[650..682], &[18; 32]);
        assert_eq!(&encoded[682..714], &[19; 32]);
        assert_eq!(&encoded[714..722], &4u64.to_be_bytes());
        assert_eq!(&encoded[722..754], &[20; 32]);
        assert_eq!(&encoded[754..762], &3u64.to_be_bytes());
        assert_eq!(&encoded[762..794], &[21; 32]);
        assert_eq!(&encoded[794..802], &3u64.to_be_bytes());
        assert_eq!(&encoded[802..834], &[22; 32]);
        assert_eq!(&encoded[834..842], &5u64.to_be_bytes());
        assert_eq!(&encoded[842..850], &6u64.to_be_bytes());
        assert_eq!(PublicValuesV5::decode(&encoded), Ok(values));
        assert_eq!(
            PublicValuesV4::decode(&encoded),
            Err(PublicValuesError::WrongLength)
        );
        assert_eq!(
            values.sha256(),
            [
                0x72, 0x5b, 0x6a, 0x96, 0xe2, 0x16, 0x9f, 0x13, 0x17, 0xb8, 0x7e, 0xa9, 0x87, 0x86,
                0x2c, 0x91, 0xa6, 0x61, 0x6c, 0x52, 0x81, 0xe0, 0xef, 0x76, 0x6e, 0xaf, 0xe5, 0x75,
                0xee, 0x6b, 0xc2, 0x4b,
            ]
        );
    }

    #[test]
    fn public_values_v5_rejects_mutated_appended_semantics() {
        let valid = v5_vector().encode();
        for (offset, replacement, expected) in [
            (649usize, vec![4], PublicValuesError::InvalidOracleMode),
            (
                641,
                8u64.to_be_bytes().to_vec(),
                PublicValuesError::StaleOracle,
            ),
            (
                754,
                5u64.to_be_bytes().to_vec(),
                PublicValuesError::InvalidBondInbox,
            ),
            (
                794,
                2u64.to_be_bytes().to_vec(),
                PublicValuesError::InvalidBondInbox,
            ),
            (
                842,
                4u64.to_be_bytes().to_vec(),
                PublicValuesError::InvalidExecutionSequence,
            ),
        ] {
            let mut candidate = valid;
            candidate[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert_eq!(PublicValuesV5::decode(&candidate), Err(expected));
        }
        assert_eq!(
            PublicValuesV5::decode(&valid[..PUBLIC_VALUES_V5_LEN - 1]),
            Err(PublicValuesError::WrongLength)
        );
    }

    #[test]
    fn v4_zero_outstanding_and_zero_deficit_use_finite_canonical_values() {
        let encoded = PublicValuesV4 {
            transition_journal_domain_sha256: [1; 32],
            configuration_hash: [2; 32],
            current_state_hash: [3; 32],
            next_state_hash: [4; 32],
            transition_txid_consensus: [5; 32],
            prior_exchange_header_root: [6; 32],
            prior_parent_block_hash: [7; 32],
            prior_parent_height: 8,
            prior_parent_mtp: 9,
            transition_journal_hash: [10; 32],
            bond_asset_id: [11; 32],
            bond_deployment_commitment: [12; 32],
            bond_state_root: [13; 32],
            redemption_queue_root: [14; 32],
            funding_state_root: [15; 32],
            conversion_legs_commitment: [16; 32],
            insurance_reserve: 1_000,
            outstanding_share_atoms: 0,
            nav_per_whole_share_usdd_atoms: 0,
            full_bound_deficit: 0,
            target_reserve: 0,
            coverage_bps: BOND_TARGET_COVERAGE_BPS_V2,
            capital_mode: 0,
            authenticated_min_price: 23,
            authenticated_max_price: 24,
            funding_epoch: 25,
            funding_rate_ppm: 0,
            redemption_head: 27,
            redemption_tail: 27,
            queued_redemption_share_atoms: 0,
        }
        .encode();
        let mut values = PublicValuesV4::decode(&encoded)
            .expect("zero outstanding uses zero NAV even with accrued reserve");
        values.nav_per_whole_share_usdd_atoms = 1;
        assert_eq!(
            PublicValuesV4::decode(&values.encode()),
            Err(PublicValuesError::InvalidCapitalAccounting)
        );
    }
}
