//! Additive V2 exchange state. V1 state hashes and encodings remain unchanged.

use crate::bond::BondPublicStateV2;
use crate::bond_inbox_v2::BondInboxStateV2;
use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode};
use crate::funding_v2::FundingStateV2;
use crate::hash::{canonical_hash, Hash32};
use crate::state::ExchangeState;
use crate::types::XOnlyKey;
use crate::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExchangeStateV2 {
    pub version: u8,
    pub base: ExchangeState,
    pub bond: BondPublicStateV2,
    pub funding: FundingStateV2,
    /// Last committed fill-only execution-receipt sequence. It is distinct
    /// from the V1 matcher command cursor and advances exactly once per
    /// ordinary fill.
    pub matcher_execution_sequence: u64,
    /// Sidechain height of this singleton state. The next transition uses it
    /// to prove every ordinary execution was admitted after this state, so a
    /// successful ECX transition cannot be skipped.
    pub last_transition_sidechain_height: u64,
    /// Dedicated active-branch projection of the confidential bond inbox.
    pub bond_inbox: BondInboxStateV2,
    /// Append-only accepted/rejected processing transcript. Exactly one
    /// outcome is committed per consumed inbox entry.
    pub bond_inbox_outcome_root: Hash32,
    pub bond_inbox_outcome_count: u64,
    /// Private active-order risk commitments, keyed by canonical order id.
    pub active_order_risk_root: Hash32,
    /// Private per-position selected margin, keyed by trader.
    pub position_risk_root: Hash32,
}

impl ExchangeStateV2 {
    pub const VERSION: u8 = 2;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.base.protocol_version != ExchangeState::VERSION
            || self.base.insurance_fund.0 < 0
            || u128::try_from(self.base.insurance_fund.0)
                .map_err(|_| ProtocolError::InvalidBondState)?
                != self.bond.insurance_reserve
            || self.base.fee_pool.0 != 0
            || self.last_transition_sidechain_height == 0
            || self.last_transition_sidechain_height != self.base.last_processed_height
            || self.bond_inbox_outcome_root == [0; 32]
            || self.bond_inbox_outcome_count != self.bond_inbox.cursor
            || self.active_order_risk_root == [0; 32]
            || self.position_risk_root == [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        }
        self.base.validate()?;
        self.bond.validate()?;
        self.funding.validate()?;
        self.bond_inbox.validate()?;
        Ok(())
    }

    pub fn state_root(&self) -> Hash32 {
        canonical_hash("ECX/exchange-state/v9-expired-unavailable-v2", self)
    }

    pub fn sequence(&self) -> u64 {
        self.base.sequence
    }
}

impl CanonicalEncode for ExchangeStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.base.encode_to(out);
        self.bond.encode_to(out);
        self.funding.encode_to(out);
        put_u64(out, self.matcher_execution_sequence);
        put_u64(out, self.last_transition_sidechain_height);
        self.bond_inbox.encode_to(out);
        out.extend_from_slice(&self.bond_inbox_outcome_root);
        put_u64(out, self.bond_inbox_outcome_count);
        out.extend_from_slice(&self.active_order_risk_root);
        out.extend_from_slice(&self.position_risk_root);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PositionRiskLeafV2 {
    pub version: u8,
    pub trader: XOnlyKey,
    pub selected_initial_margin_bps: u32,
    pub salt: Hash32,
}

impl PositionRiskLeafV2 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || !crate::risk_v2::ALLOWED_INITIAL_MARGIN_BPS_V2
                .contains(&self.selected_initial_margin_bps)
            || self.salt == [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Hash32 {
        canonical_hash("ECX/private-position-risk-leaf/v2", self)
    }
}

impl CanonicalEncode for PositionRiskLeafV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.trader.encode_to(out);
        put_u32(out, self.selected_initial_margin_bps);
        out.extend_from_slice(&self.salt);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateCommitmentV2 {
    pub version: u8,
    pub sequence: u64,
    pub root: Hash32,
}

impl StateCommitmentV2 {
    pub fn from_state(state: &ExchangeStateV2) -> Result<Self, ProtocolError> {
        state.validate()?;
        Ok(Self {
            version: ExchangeStateV2::VERSION,
            sequence: state.sequence(),
            root: state.state_root(),
        })
    }
}

impl CanonicalEncode for StateCommitmentV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.sequence);
        out.extend_from_slice(&self.root);
    }
}
