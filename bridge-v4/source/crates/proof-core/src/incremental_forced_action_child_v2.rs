//! Recursive child authenticating the complete forced-action inbox suffix.

use bincode::Options;
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    successor_forced_action_batch_root_v2, successor_forced_inbox_state_hash_v2,
    successor_withdrawal_batch_root_v2, Hash32, IncrementalSuccessorConfigurationV2, ProtocolError,
    SuccessorForcedActionV2, SuccessorForcedInboxStateV2, SuccessorForcedInboxTransitionV2,
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, SuccessorSignedWithdrawalRequestV2,
    MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1, MAX_COMBINED_SAME_DEADLINE_APPENDS_V1,
    MAX_COMBINED_UNCONSUMED_INBOX_ENTRIES_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const INCREMENTAL_FORCED_ACTION_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 2;
pub const INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2: usize =
    4 + (10 * 32) + (4 * 16) + (3 * 8) + 2;
/// Exact fixed-int bincode size of a maximum 448-entry pending suffix when
/// every entry uses the largest forced-action variant (a signed IOC).
pub const INCREMENTAL_FORCED_ACTION_REACHABLE_ENCODING_CEILING_V2: usize = 164_921;
pub const MAX_INCREMENTAL_FORCED_ACTION_CHILD_INPUT_BYTES_V2: usize = 1024 * 1024;
const _: () = assert!(
    INCREMENTAL_FORCED_ACTION_REACHABLE_ENCODING_CEILING_V2
        < MAX_INCREMENTAL_FORCED_ACTION_CHILD_INPUT_BYTES_V2
);
pub const FORCED_INCLUSION_BLOCKS_INCREMENTAL_V2: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalForcedActionConfigurationV2 {
    pub successor: IncrementalSuccessorConfigurationV2,
    pub v18_configuration_hash: Hash32,
    pub forced_action_domain: Hash32,
    pub forced_inclusion_blocks: u32,
}

impl IncrementalForcedActionConfigurationV2 {
    pub fn validate(self) -> Result<(), IncrementalForcedActionChildErrorV2> {
        self.successor.validate()?;
        if self.v18_configuration_hash == [0; 32]
            || self.forced_action_domain == [0; 32]
            || self.v18_configuration_hash == self.forced_action_domain
            || self.forced_inclusion_blocks != FORCED_INCLUSION_BLOCKS_INCREMENTAL_V2
        {
            return Err(IncrementalForcedActionChildErrorV2::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalForcedActionChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalForcedActionConfigurationV2,
    pub current_parent_height: u64,
    pub previous_state: SuccessorForcedInboxStateV2,
    pub next_state: SuccessorForcedInboxStateV2,
    pub transition: SuccessorForcedInboxTransitionV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalForcedActionChildPublicValuesV2 {
    pub successor_configuration_hash: Hash32,
    pub v18_configuration_hash: Hash32,
    pub previous_state_hash: Hash32,
    pub next_state_hash: Hash32,
    pub previous_head_root: Hash32,
    pub next_head_root: Hash32,
    pub consumed_entry_batch_root: Hash32,
    pub forced_withdrawal_root: Hash32,
    pub forced_cancel_root: Hash32,
    pub forced_reduce_only_ioc_root: Hash32,
    pub previous_cursor: u128,
    pub next_cursor: u128,
    pub previous_entry_count: u128,
    pub next_entry_count: u128,
    pub consumed_count: u64,
    pub pending_count: u64,
    pub current_parent_height: u64,
    pub had_overdue_action: bool,
    pub escape_only: bool,
}

impl IncrementalForcedActionChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(
            &INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes(),
        );
        for value in [
            self.successor_configuration_hash,
            self.v18_configuration_hash,
            self.previous_state_hash,
            self.next_state_hash,
            self.previous_head_root,
            self.next_head_root,
            self.consumed_entry_batch_root,
            self.forced_withdrawal_root,
            self.forced_cancel_root,
            self.forced_reduce_only_ioc_root,
        ] {
            out.extend_from_slice(&value);
        }
        for value in [
            self.previous_cursor,
            self.next_cursor,
            self.previous_entry_count,
            self.next_entry_count,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.consumed_count,
            self.pending_count,
            self.current_parent_height,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.push(u8::from(self.had_overdue_action));
        out.push(u8::from(self.escape_only));
        debug_assert_eq!(
            out.len(),
            INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalForcedActionChildProjectionV2 {
    pub successor_configuration_hash: Hash32,
    pub v18_configuration_hash: Hash32,
    pub previous_state_hash: Hash32,
    pub next_state_hash: Hash32,
    pub previous_head_root: Hash32,
    pub next_head_root: Hash32,
    pub consumed_entry_batch_root: Hash32,
    pub forced_withdrawal_root: Hash32,
    pub forced_cancel_root: Hash32,
    pub forced_reduce_only_ioc_root: Hash32,
    pub previous_cursor: u128,
    pub next_cursor: u128,
    pub previous_entry_count: u128,
    pub next_entry_count: u128,
    pub consumed_count: u64,
    pub pending_count: u64,
    pub current_parent_height: u64,
    pub had_overdue_action: bool,
    pub escape_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalForcedActionChildErrorV2 {
    #[error("unsupported incremental forced-action child version")]
    UnsupportedVersion,
    #[error("invalid incremental forced-action configuration")]
    InvalidConfiguration,
    #[error("incremental forced-action child input exceeds its runtime cap")]
    InputTooLarge,
    #[error("incremental forced-action child input encoding failed")]
    InputEncoding,
    #[error("incremental forced-action transition rejected: {0}")]
    Protocol(#[from] ProtocolError),
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn action_root<T: CanonicalEncode>(tag: &[u8], actions: &[T]) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(actions.len() as u64).to_be_bytes());
    for action in actions {
        let encoded = action.canonical_bytes();
        bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    tagged_hash(tag, &bytes)
}

pub fn incremental_successor_forced_cancel_root_v2(
    actions: &[SuccessorSignedCancelOrderV2],
) -> Hash32 {
    action_root(b"ECX/incremental-forced-cancel-root/v2-u128", actions)
}

pub fn incremental_successor_forced_reduce_only_ioc_root_v2(
    actions: &[SuccessorSignedLimitOrderV2],
) -> Hash32 {
    action_root(
        b"ECX/incremental-forced-reduce-only-ioc-root/v2-u128",
        actions,
    )
}

pub fn decode_incremental_forced_action_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalForcedActionChildProjectionV2, IncrementalForcedActionChildErrorV2> {
    if bytes.len() != INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalForcedActionChildErrorV2::UnsupportedVersion);
    }
    let hash = |index: usize| -> Result<Hash32, IncrementalForcedActionChildErrorV2> {
        let start = 4 + index * 32;
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalForcedActionChildErrorV2::UnsupportedVersion)
    };
    let u128_at = |index: usize| -> Result<u128, IncrementalForcedActionChildErrorV2> {
        let start = 4 + 10 * 32 + index * 16;
        Ok(u128::from_be_bytes(
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| IncrementalForcedActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let u64_at = |index: usize| -> Result<u64, IncrementalForcedActionChildErrorV2> {
        let start = 4 + 10 * 32 + 4 * 16 + index * 8;
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalForcedActionChildErrorV2::UnsupportedVersion)?,
        ))
    };
    let had_overdue_action = bytes[INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 2];
    let escape_only = bytes[INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2 - 1];
    if had_overdue_action > 1 || escape_only > 1 {
        return Err(IncrementalForcedActionChildErrorV2::UnsupportedVersion);
    }
    Ok(IncrementalForcedActionChildProjectionV2 {
        successor_configuration_hash: hash(0)?,
        v18_configuration_hash: hash(1)?,
        previous_state_hash: hash(2)?,
        next_state_hash: hash(3)?,
        previous_head_root: hash(4)?,
        next_head_root: hash(5)?,
        consumed_entry_batch_root: hash(6)?,
        forced_withdrawal_root: hash(7)?,
        forced_cancel_root: hash(8)?,
        forced_reduce_only_ioc_root: hash(9)?,
        previous_cursor: u128_at(0)?,
        next_cursor: u128_at(1)?,
        previous_entry_count: u128_at(2)?,
        next_entry_count: u128_at(3)?,
        consumed_count: u64_at(0)?,
        pending_count: u64_at(1)?,
        current_parent_height: u64_at(2)?,
        had_overdue_action: had_overdue_action == 1,
        escape_only: escape_only == 1,
    })
}

pub fn execute_incremental_forced_action_child_v2(
    input: &IncrementalForcedActionChildInputV2,
) -> Result<IncrementalForcedActionChildPublicValuesV2, IncrementalForcedActionChildErrorV2> {
    if input.version != INCREMENTAL_FORCED_ACTION_CHILD_VERSION_V2 {
        return Err(IncrementalForcedActionChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalForcedActionChildErrorV2::InputEncoding)?;
    let next_unconsumed = input
        .next_state
        .entry_count
        .checked_sub(input.next_state.cursor)
        .ok_or(ProtocolError::InvalidForcedInbox)?;
    if encoded.len() > MAX_INCREMENTAL_FORCED_ACTION_CHILD_INPUT_BYTES_V2 {
        return Err(IncrementalForcedActionChildErrorV2::InputTooLarge);
    }
    if input.transition.pending_entries.len() > MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1 {
        return Err(ProtocolError::InvalidForcedInbox.into());
    }
    let maximum_order_work = u32::from(input.configuration.successor.maximum_order_operations);
    let mut tranche_parent_height = None;
    let mut tranche_order_work = 0u32;
    for entry in &input.transition.pending_entries {
        if tranche_parent_height != Some(entry.enqueued_parent_height) {
            tranche_parent_height = Some(entry.enqueued_parent_height);
            tranche_order_work = 0;
        }
        let work = match &entry.action {
            SuccessorForcedActionV2::Cancel(_) => 1,
            SuccessorForcedActionV2::ReduceOnlyIoc(_) => maximum_order_work,
            SuccessorForcedActionV2::Withdraw(_) => 0,
        };
        tranche_order_work = tranche_order_work
            .checked_add(work)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if tranche_order_work > maximum_order_work {
            return Err(ProtocolError::InvalidForcedInbox.into());
        }
    }
    if input.previous_state.cursor < input.previous_state.entry_count {
        let oldest_parent_height = input
            .transition
            .pending_entries
            .first()
            .ok_or(ProtocolError::InvalidForcedInbox)?
            .enqueued_parent_height;
        let oldest_tranche_count = input
            .transition
            .pending_entries
            .iter()
            .take_while(|entry| entry.enqueued_parent_height == oldest_parent_height)
            .count();
        if usize::try_from(input.transition.consumed_count)
            .map_err(|_| ProtocolError::ArithmeticOverflow)?
            < oldest_tranche_count
        {
            return Err(ProtocolError::ForcedActionDeadline.into());
        }
    }
    for parent_height in input
        .transition
        .pending_entries
        .iter()
        .filter(|entry| entry.index >= input.previous_state.entry_count)
        .map(|entry| entry.enqueued_parent_height)
    {
        if input
            .transition
            .pending_entries
            .iter()
            .filter(|entry| {
                entry.index >= input.previous_state.entry_count
                    && entry.enqueued_parent_height == parent_height
            })
            .count()
            > MAX_COMBINED_SAME_DEADLINE_APPENDS_V1
        {
            return Err(ProtocolError::InvalidForcedInbox.into());
        }
    }
    if input.previous_state.entry_count == 0
        && input.previous_state
            != SuccessorForcedInboxStateV2::genesis(
                input.configuration.forced_action_domain,
                input.configuration.successor.chain_id,
            )?
    {
        return Err(ProtocolError::InvalidForcedInbox.into());
    }
    let outcome = input.transition.verify(
        input.configuration.successor.chain_id,
        input.previous_state,
        input.next_state,
        input.current_parent_height,
        input.configuration.forced_inclusion_blocks,
    )?;
    let catch_up_tranche = outcome.first_unconsumed_overdue;
    if next_unconsumed > u128::from(MAX_COMBINED_UNCONSUMED_INBOX_ENTRIES_V1) && !catch_up_tranche {
        return Err(ProtocolError::InvalidForcedInbox.into());
    }
    let consumed = input.transition.consumed()?;
    let mut withdrawals = Vec::<SuccessorSignedWithdrawalRequestV2>::new();
    let mut cancellations = Vec::<SuccessorSignedCancelOrderV2>::new();
    let mut iocs = Vec::<SuccessorSignedLimitOrderV2>::new();
    for entry in consumed {
        match &entry.action {
            SuccessorForcedActionV2::Withdraw(value) => withdrawals.push(value.clone()),
            SuccessorForcedActionV2::Cancel(value) => {
                if value.cancel.chain_id != input.configuration.successor.chain_id
                    || value.cancel.market != input.configuration.successor.market
                    || !value.cancel.is_live_at(entry.enqueued_sidechain_height)
                {
                    return Err(ProtocolError::InvalidForcedAction.into());
                }
                cancellations.push(value.clone());
            }
            SuccessorForcedActionV2::ReduceOnlyIoc(value) => {
                if value.order.chain_id != input.configuration.successor.chain_id
                    || value.order.market != input.configuration.successor.market
                    || !value.order.is_live_at(entry.enqueued_sidechain_height)
                {
                    return Err(ProtocolError::InvalidForcedAction.into());
                }
                iocs.push(value.clone());
            }
        }
    }
    Ok(IncrementalForcedActionChildPublicValuesV2 {
        successor_configuration_hash: input.configuration.successor.digest()?,
        v18_configuration_hash: input.configuration.v18_configuration_hash,
        previous_state_hash: successor_forced_inbox_state_hash_v2(input.previous_state),
        next_state_hash: successor_forced_inbox_state_hash_v2(input.next_state),
        previous_head_root: input.previous_state.head_root,
        next_head_root: input.next_state.head_root,
        consumed_entry_batch_root: successor_forced_action_batch_root_v2(consumed),
        forced_withdrawal_root: successor_withdrawal_batch_root_v2(&withdrawals),
        forced_cancel_root: incremental_successor_forced_cancel_root_v2(&cancellations),
        forced_reduce_only_ioc_root: incremental_successor_forced_reduce_only_ioc_root_v2(&iocs),
        previous_cursor: input.previous_state.cursor,
        next_cursor: input.next_state.cursor,
        previous_entry_count: input.previous_state.entry_count,
        next_entry_count: input.next_state.entry_count,
        consumed_count: u64::try_from(consumed.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        pending_count: u64::try_from(input.transition.pending_entries.len())
            .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        current_parent_height: input.current_parent_height,
        had_overdue_action: outcome.had_overdue_action,
        escape_only: outcome.had_overdue_action || outcome.first_unconsumed_overdue,
    })
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;
    use ecx_protocol_core::{
        IncrementalAccountingBoundsV2, OrderFlags, Price, Quantity, RiskParams, Side,
        SuccessorCancelOrderV2, SuccessorForcedActionEntryV2, SuccessorLimitOrderV2,
        SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2,
        SuccessorSignedWithdrawalRequestV2, SuccessorWithdrawalRequestV2, TimeInForce, XOnlyKey,
        ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2, MAX_TRANSITION_ACTIONS,
    };

    fn configuration() -> IncrementalForcedActionConfigurationV2 {
        IncrementalForcedActionConfigurationV2 {
            successor: IncrementalSuccessorConfigurationV2 {
                version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
                chain_id: [0x11; 32],
                market: ECX_USDD_MARKET,
                order_configuration_hash: [0x22; 32],
                successor_matcher_configuration_hash: [0x23; 32],
                risk_params: RiskParams::default(),
                accounting_bounds: IncrementalAccountingBoundsV2 {
                    maximum_abs_trader_collateral_atoms: 1_000_000,
                    maximum_total_controlled_atoms: 10_000_000,
                    maximum_abs_position_atoms: 1_000_000,
                    maximum_open_interest_atoms: 10_000_000,
                    maximum_price_atoms: 1_000_000_000,
                },
                maximum_trader_updates: 64,
                maximum_order_operations: 64,
                maximum_nullifier_updates_per_kind: 64,
            },
            v18_configuration_hash: [0x91; 32],
            forced_action_domain: [0x92; 32],
            forced_inclusion_blocks: FORCED_INCLUSION_BLOCKS_INCREMENTAL_V2,
        }
    }

    #[test]
    fn forced_withdrawal_prefix_is_exact_and_deadline_bound() {
        let configuration = configuration();
        let previous = SuccessorForcedInboxStateV2::genesis(
            configuration.forced_action_domain,
            configuration.successor.chain_id,
        )
        .unwrap();
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        let request = SuccessorSignedWithdrawalRequestV2::sign(
            SuccessorWithdrawalRequestV2 {
                version: SuccessorWithdrawalRequestV2::VERSION,
                chain_id: configuration.successor.chain_id,
                trader: XOnlyKey(public.serialize()),
                nonce: 0,
                amount: 25,
                destination_script_hash: [0x44; 32],
                requested_height: 1,
                not_before_height: 1,
            },
            &secret,
        )
        .unwrap();
        let entry = SuccessorForcedActionEntryV2 {
            version: SuccessorForcedActionEntryV2::VERSION,
            chain_id: configuration.successor.chain_id,
            index: 0,
            previous_root: previous.head_root,
            enqueued_sidechain_height: 1,
            enqueued_parent_height: 10,
            source_txid: [0x55; 32],
            source_vout: 0,
            action: SuccessorForcedActionV2::Withdraw(request.clone()),
        };
        let next = SuccessorForcedInboxStateV2 {
            head_root: entry.next_root(),
            entry_count: 1,
            processed_root: entry.next_root(),
            cursor: 1,
        };
        let input = IncrementalForcedActionChildInputV2 {
            version: INCREMENTAL_FORCED_ACTION_CHILD_VERSION_V2,
            configuration,
            current_parent_height: 16,
            previous_state: previous,
            next_state: next,
            transition: SuccessorForcedInboxTransitionV2 {
                pending_entries: vec![entry],
                consumed_count: 1,
            },
        };
        let values = execute_incremental_forced_action_child_v2(&input).unwrap();
        assert_eq!(
            values.forced_withdrawal_root,
            successor_withdrawal_batch_root_v2(&[request])
        );
        assert_eq!(values.consumed_count, 1);
        assert!(values.had_overdue_action);
        assert!(values.escape_only);
        assert_eq!(
            decode_incremental_forced_action_projection_v2(&values.encode())
                .unwrap()
                .next_state_hash,
            values.next_state_hash
        );

        let mut omitted = input;
        omitted.transition.consumed_count = 0;
        assert!(execute_incremental_forced_action_child_v2(&omitted).is_err());
    }

    #[test]
    fn forced_action_public_values_layout_is_exact() {
        let values = IncrementalForcedActionChildPublicValuesV2 {
            successor_configuration_hash: [1; 32],
            v18_configuration_hash: [2; 32],
            previous_state_hash: [3; 32],
            next_state_hash: [4; 32],
            previous_head_root: [5; 32],
            next_head_root: [6; 32],
            consumed_entry_batch_root: [7; 32],
            forced_withdrawal_root: [8; 32],
            forced_cancel_root: [9; 32],
            forced_reduce_only_ioc_root: [10; 32],
            previous_cursor: 11,
            next_cursor: 12,
            previous_entry_count: 13,
            next_entry_count: 14,
            consumed_count: 15,
            pending_count: 16,
            current_parent_height: 17,
            had_overdue_action: true,
            escape_only: true,
        };
        assert_eq!(
            values.encode().len(),
            INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        );
        assert_eq!(
            decode_incremental_forced_action_projection_v2(&values.encode())
                .unwrap()
                .forced_cancel_root,
            [9; 32]
        );
        let mut noncanonical = values.encode();
        let last = noncanonical.len() - 1;
        noncanonical[last] = 2;
        assert_eq!(
            decode_incremental_forced_action_projection_v2(&noncanonical),
            Err(IncrementalForcedActionChildErrorV2::UnsupportedVersion)
        );
        noncanonical[last] = 1;
        noncanonical[last - 1] = 2;
        assert_eq!(
            decode_incremental_forced_action_projection_v2(&noncanonical),
            Err(IncrementalForcedActionChildErrorV2::UnsupportedVersion)
        );
    }

    #[test]
    fn successor_maximum_pending_suffix_is_accepted_and_fits_decoder_cap() {
        let configuration = configuration();
        let previous = SuccessorForcedInboxStateV2::genesis(
            configuration.forced_action_domain,
            configuration.successor.chain_id,
        )
        .unwrap();
        let secret = SecretKey::from_slice(&[9; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut root = previous.head_root;
        let mut processed_root = root;
        let consumed_count = usize::try_from(MAX_TRANSITION_ACTIONS).unwrap();
        let mut pending_entries = Vec::with_capacity(MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1);
        for index in 0..MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1 {
            let group = index;
            let order = SuccessorSignedLimitOrderV2::sign(
                SuccessorLimitOrderV2 {
                    version: SuccessorLimitOrderV2::VERSION,
                    chain_id: configuration.successor.chain_id,
                    market: configuration.successor.market,
                    trader: XOnlyKey(public.serialize()),
                    side: Side::Sell,
                    time_in_force: TimeInForce::ImmediateOrCancel,
                    flags: OrderFlags::REDUCE_ONLY,
                    limit_price: Price::new(100).unwrap(),
                    quantity: Quantity::new(1).unwrap(),
                    client_order_id: (index as u128).to_be_bytes(),
                    max_fee_bps: 5,
                    nonce: (1u128 << 96) + u128::try_from(index).unwrap(),
                    valid_from_height: 1,
                    expires_at_height: u64::MAX,
                },
                &secret,
            )
            .unwrap();
            let mut source_txid = [0u8; 32];
            source_txid[24..].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
            let entry = SuccessorForcedActionEntryV2 {
                version: SuccessorForcedActionEntryV2::VERSION,
                chain_id: configuration.successor.chain_id,
                index: u128::try_from(index).unwrap(),
                previous_root: root,
                enqueued_sidechain_height: u64::try_from(group + 1).unwrap(),
                enqueued_parent_height: u64::try_from(group + 20).unwrap(),
                source_txid,
                source_vout: 0,
                action: SuccessorForcedActionV2::ReduceOnlyIoc(order),
            };
            root = entry.next_root();
            if index + 1 == consumed_count {
                processed_root = root;
            }
            pending_entries.push(entry);
        }
        let next = SuccessorForcedInboxStateV2 {
            head_root: root,
            entry_count: u128::try_from(pending_entries.len()).unwrap(),
            processed_root,
            cursor: u128::try_from(consumed_count).unwrap(),
        };
        let input = IncrementalForcedActionChildInputV2 {
            version: INCREMENTAL_FORCED_ACTION_CHILD_VERSION_V2,
            configuration,
            current_parent_height: 1_000,
            previous_state: previous,
            next_state: next,
            transition: SuccessorForcedInboxTransitionV2 {
                pending_entries,
                consumed_count: u32::try_from(consumed_count).unwrap(),
            },
        };
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .serialize(&input)
            .unwrap();
        let options = bincode::DefaultOptions::new().with_fixint_encoding();
        let ioc_len = options
            .serialized_size(&input.transition.pending_entries[0].action)
            .unwrap();
        let cancel = SuccessorForcedActionV2::Cancel(
            SuccessorSignedCancelOrderV2::sign(
                SuccessorCancelOrderV2 {
                    version: SuccessorCancelOrderV2::VERSION,
                    chain_id: configuration.successor.chain_id,
                    market: configuration.successor.market,
                    trader: XOnlyKey(public.serialize()),
                    order_id: [0x31; 32],
                    nonce: 1u128 << 96,
                    valid_from_height: 1,
                    expires_at_height: u64::MAX,
                },
                &secret,
            )
            .unwrap(),
        );
        let withdrawal = SuccessorForcedActionV2::Withdraw(
            SuccessorSignedWithdrawalRequestV2::sign(
                SuccessorWithdrawalRequestV2 {
                    version: SuccessorWithdrawalRequestV2::VERSION,
                    chain_id: configuration.successor.chain_id,
                    trader: XOnlyKey(public.serialize()),
                    nonce: 1u128 << 96,
                    amount: 1,
                    destination_script_hash: [0x32; 32],
                    requested_height: 1,
                    not_before_height: 1,
                },
                &secret,
            )
            .unwrap(),
        );
        assert!(ioc_len >= options.serialized_size(&cancel).unwrap());
        assert!(ioc_len >= options.serialized_size(&withdrawal).unwrap());
        assert_eq!(
            encoded.len(),
            INCREMENTAL_FORCED_ACTION_REACHABLE_ENCODING_CEILING_V2
        );
        assert!(execute_incremental_forced_action_child_v2(&input).is_ok());

        let mut undersized_catch_up = input.clone();
        undersized_catch_up.transition.consumed_count = 0;
        undersized_catch_up.next_state.cursor = 0;
        undersized_catch_up.next_state.processed_root = previous.processed_root;
        assert_eq!(
            execute_incremental_forced_action_child_v2(&undersized_catch_up),
            Err(IncrementalForcedActionChildErrorV2::Protocol(
                ProtocolError::ForcedActionDeadline
            ))
        );

        let mut non_overdue_large_backlog = input.clone();
        non_overdue_large_backlog.current_parent_height = 20;
        assert_eq!(
            execute_incremental_forced_action_child_v2(&non_overdue_large_backlog),
            Err(IncrementalForcedActionChildErrorV2::Protocol(
                ProtocolError::InvalidForcedInbox
            ))
        );

        let first_entry = input.transition.pending_entries[0].clone();
        let prior_pending_state = SuccessorForcedInboxStateV2 {
            head_root: first_entry.next_root(),
            entry_count: 1,
            processed_root: previous.processed_root,
            cursor: 0,
        };
        let mut skipped_oldest_tranche = input.clone();
        skipped_oldest_tranche.current_parent_height = 20;
        skipped_oldest_tranche.previous_state = prior_pending_state;
        skipped_oldest_tranche.next_state = prior_pending_state;
        skipped_oldest_tranche.transition.pending_entries = vec![first_entry];
        skipped_oldest_tranche.transition.consumed_count = 0;
        assert_eq!(
            execute_incremental_forced_action_child_v2(&skipped_oldest_tranche),
            Err(IncrementalForcedActionChildErrorV2::Protocol(
                ProtocolError::ForcedActionDeadline
            ))
        );

        let mut overweight_ioc_tranche = input.clone();
        overweight_ioc_tranche
            .transition
            .pending_entries
            .truncate(2);
        let mut group_root = previous.head_root;
        for entry in &mut overweight_ioc_tranche.transition.pending_entries {
            entry.enqueued_parent_height = 20;
            entry.previous_root = group_root;
            group_root = entry.next_root();
        }
        overweight_ioc_tranche.next_state = SuccessorForcedInboxStateV2 {
            head_root: group_root,
            entry_count: 2,
            processed_root: group_root,
            cursor: 2,
        };
        overweight_ioc_tranche.transition.consumed_count = 2;
        assert!(matches!(
            execute_incremental_forced_action_child_v2(&overweight_ioc_tranche),
            Err(IncrementalForcedActionChildErrorV2::Protocol(
                ProtocolError::InvalidForcedInbox
            ))
        ));

        let mut too_many_same_deadline = input;
        for entry in &mut too_many_same_deadline.transition.pending_entries[..9] {
            entry.enqueued_parent_height = 20;
        }
        assert!(execute_incremental_forced_action_child_v2(&too_many_same_deadline).is_err());
    }
}
