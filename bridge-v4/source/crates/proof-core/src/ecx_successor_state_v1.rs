//! Distinct ECX successor-state commitment. This is not a USDD V2 encoding.
//! An enclosing covenant must authenticate the expected digest. Constructing
//! or opening this state does not establish parent consensus or spend authority.
use crate::{ecx_execution_v1::verify_ecx_vault_ledger_v1, proof_v2::ProofErrorV2};
use ecx_protocol_core::{
    ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1}, Hash32,
};
use sha2::{Digest, Sha256};

/// One-sided OI from a complete authenticated ledger, with balanced positions.
/// The caller must check ledger membership/completeness separately.
pub fn ecx_ledger_open_interest(
    accounts: &[(&ecx_protocol_core::TraderLeafV2,
        &ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1)],
) -> Result<u128, ProofErrorV2> {
    let invalid = || ProofErrorV2::BindingMismatch("ECX ledger position balance");
    let (mut longs, mut shorts) = (0u128, 0u128);
    for (position, _) in accounts {
        let size = position.position_size_atoms;
        let total = if size >= 0 { &mut longs } else { &mut shorts };
        *total = total.checked_add(u128::from(size.unsigned_abs())).ok_or_else(invalid)?;
    }
    if longs != shorts { return Err(invalid()); }
    Ok(longs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxSuccessorStateV1 {
    pub bindings_hash: Hash32,
    /// Commits positions, physical cash and exact fractional claims together.
    pub accounts_root: Hash32,
    pub orders_root: Hash32,
    pub funding_root: Hash32,
    pub funding_index: i128,
    /// One-sided base quantity, not funding's quote-notional threshold.
    pub open_interest: u128,
    pub matcher_sequence: u128,
    pub matcher_receipt_hash: Hash32,
    pub sidechain_height: u64,
    pub parent_hash: Hash32,
    pub parent_height: u64,
    pub parent_mtp: u64,
    /// Amount is ECX atoms, never quote-valued USDD accounting cash.
    pub controlled_ecx_atoms: u64,
    pub vault_script_sha256: Hash32,
}

impl EcxSuccessorStateV1 {
    /// Prepare a sequence-bound admission for matcher signing. This returns no
    /// accepted successor: only `admit_order` verifies the receipt and advances
    /// the cursor. The enclosing relation must authenticate the expected state
    /// and oracle bounds; the funding index and height come from that state.
    #[allow(clippy::too_many_arguments)]
    pub fn order_admission_execution(
        &self, expected_state: Hash32, bindings: EcxSuccessorBindingsV1,
        economics: EcxConfigurationV1,
        signed: ecx_protocol_core::ecx_order_v1::SignedEcxOrderV1,
        account: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        absence_siblings: &[Hash32],
        source_orders: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
        low: ecx_protocol_core::types::Price, high: ecx_protocol_core::types::Price,
    ) -> Result<(ecx_protocol_core::ecx_order_index_v1::EcxIndexedAdmissionV1, Hash32), ProofErrorV2> {
        if self.digest()? != expected_state || self.bindings_hash != bindings.digest()? {
            return Err(ProofErrorV2::BindingMismatch("ECX admission committed state"));
        }
        let domain = bindings.account_domain(economics)?;
        let sequence = self.matcher_sequence.checked_add(1)
            .ok_or(ProofErrorV2::BindingMismatch("ECX admission sequence overflow"))?;
        let update = ecx_protocol_core::ecx_order_index_v1::stage_ecx_indexed_admission(
            self.accounts_root, self.orders_root, economics, signed, account,
            absence_siblings, self.sidechain_height, source_orders, low, high,
            self.funding_index, sequence)?;
        let mut bytes = vec![2];
        bytes.extend_from_slice(&expected_state);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&update.order.commitment(domain)?);
        bytes.extend_from_slice(&update.accounts_root);
        bytes.extend_from_slice(&update.orders_root);
        bytes.extend_from_slice(&low.get().to_be_bytes());
        bytes.extend_from_slice(&high.get().to_be_bytes());
        let hash = ecx_protocol_core::hash::tagged_hash("ECX/ecx-order-admission/v2", &bytes);
        Ok((update, hash))
    }

    /// Consume both owner nonce and matcher cursor atomically. A valid matcher
    /// signature cannot choose a different priority or replay an old admission.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_order(
        &self, expected_state: Hash32, bindings: EcxSuccessorBindingsV1,
        economics: EcxConfigurationV1,
        matcher: &ecx_protocol_core::successor_matcher_v2::SuccessorCentralMatcherConfigV2,
        receipt: &ecx_protocol_core::ecx_matcher_v1::EcxMatcherExecutionReceiptV1,
        signed: ecx_protocol_core::ecx_order_v1::SignedEcxOrderV1,
        account: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        absence_siblings: &[Hash32],
        source_orders: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
        low: ecx_protocol_core::types::Price, high: ecx_protocol_core::types::Price,
    ) -> Result<Self, ProofErrorV2> {
        let (update, execution_hash) = self.order_admission_execution(
            expected_state, bindings, economics, signed, account,
            absence_siblings, source_orders, low, high)?;
        let sequence = update.order.received_sequence;
        let receipt_hash = receipt.verify(bindings, economics, matcher,
            self.matcher_sequence, self.matcher_receipt_hash, (sequence, execution_hash))?;
        let mut next = self.clone();
        next.accounts_root = update.accounts_root;
        next.orders_root = update.orders_root;
        next.matcher_sequence = sequence;
        next.matcher_receipt_hash = receipt_hash;
        next.encode()?;
        Ok(next)
    }

    /// Evaluate an authenticated target at a supplied mark using only the
    /// committed maintenance rate, funding index and complete cash opening.
    /// This does not authenticate the mark or authorize a liquidation: the
    /// enclosing oracle relation must establish the applicable observation
    /// and interval policy before consuming an Insufficient result.
    pub fn liquidation_target_margin(
        &self, expected_state: Hash32, bindings: EcxSuccessorBindingsV1,
        economics: EcxConfigurationV1,
        target: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        mark: ecx_protocol_core::types::Price,
    ) -> Result<ecx_protocol_core::ecx_cash_account_v1::EcxMarginStatusV1, ProofErrorV2> {
        use ecx_protocol_core::ecx_cash_account_v1::ecx_account_root;
        if self.digest()? != expected_state || self.bindings_hash != bindings.digest()? {
            return Err(ProofErrorV2::BindingMismatch("ECX liquidation committed state"));
        }
        let domain = bindings.account_domain(economics)?;
        if target.position.position_size_atoms == 0
            || target.position.trader == economics.clearing_account
            || target.position.trader == economics.insurance_account
            || ecx_account_root(domain, target.position, target.cash,
                economics.bounds, target.siblings)? != self.accounts_root
        {
            return Err(ProofErrorV2::BindingMismatch("ECX liquidation target opening"));
        }
        Ok(target.cash.margin_at_mark(target.position, economics.cash_valuation_scale,
            mark, self.funding_index, economics.risk.maintenance_margin_bps,
            economics.bounds)?)
    }

    /// Apply owner-authorized cancellation to a pinned, already prepared state.
    /// Both roots change atomically; cash, funding, market cursor, vault and
    /// clock remain unchanged. The enclosing native relation must authenticate
    /// the expected state and commit the returned state in its successor.
    /// No oracle is needed merely to remove an order; later withdrawals still
    /// independently enforce their current valuation and reservation checks.
    #[allow(clippy::too_many_arguments)]
    pub fn cancel_order(
        &self, expected_state: Hash32, bindings: EcxSuccessorBindingsV1,
        economics: EcxConfigurationV1,
        signed: &ecx_protocol_core::ecx_cancel_v1::SignedEcxCancelV1,
        account: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        order: &ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2,
        order_siblings: &[Hash32],
    ) -> Result<Self, ProofErrorV2> {
        if self.digest()? != expected_state || self.bindings_hash != bindings.digest()? {
            return Err(ProofErrorV2::BindingMismatch("ECX cancellation committed state"));
        }
        // Checks the selected economics against the outer bindings, not just
        // against the domain claimed by the cancellation signature.
        bindings.account_domain(economics)?;
        let update = ecx_protocol_core::ecx_cancel_v1::stage_ecx_cancel_v1(
            self.accounts_root, self.orders_root, economics, signed, account,
            order, order_siblings, self.sidechain_height)?;
        let mut next = self.clone();
        next.accounts_root = update.accounts_root;
        next.orders_root = update.orders_root;
        next.encode()?;
        Ok(next)
    }

    /// Exact-width decoder for host/guest exchange; old journals, trailing
    /// bytes and noncanonical identity openings are rejected before use.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofErrorV2> {
        let invalid = || ProofErrorV2::BindingMismatch("ECX successor state encoding");
        if bytes.len() != 310 || &bytes[..6] != b"ECXSS1" { return Err(invalid()); }
        let mut offset = 6;
        fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
            // Caller has checked the fixed schema length before any reads.
            let mut result = [0; N];
            result.copy_from_slice(&bytes[*offset..*offset + N]);
            *offset += N;
            result
        }
        let state = Self {
            bindings_hash: take(bytes, &mut offset),
            accounts_root: take(bytes, &mut offset),
            orders_root: take(bytes, &mut offset),
            funding_root: take(bytes, &mut offset),
            funding_index: i128::from_be_bytes(take(bytes, &mut offset)),
            open_interest: u128::from_be_bytes(take(bytes, &mut offset)),
            matcher_sequence: u128::from_be_bytes(take(bytes, &mut offset)),
            matcher_receipt_hash: take(bytes, &mut offset),
            sidechain_height: u64::from_be_bytes(take(bytes, &mut offset)),
            parent_hash: take(bytes, &mut offset),
            parent_height: u64::from_be_bytes(take(bytes, &mut offset)),
            parent_mtp: u64::from_be_bytes(take(bytes, &mut offset)),
            controlled_ecx_atoms: u64::from_be_bytes(take(bytes, &mut offset)),
            vault_script_sha256: take(bytes, &mut offset),
        };
        if state.encode()? != bytes { return Err(invalid()); }
        Ok(state)
    }

    /// Derive the local match opening from a pinned state, not independent
    /// host-supplied roots/index/cursor. This binds an execution context at
    /// this state's height; it does not advance height or prove ancestry.
    /// The enclosing verifier separately authenticates the source outpoint
    /// and selected continuation policy against its checked transaction.
    pub fn match_opening(
        &self, expected_state: Hash32, bindings: EcxSuccessorBindingsV1,
        funding: &ecx_protocol_core::funding_v2::FundingStateV2,
        source: elements::OutPoint, successor_script: Hash32,
    ) -> Result<Hash32, ProofErrorV2> {
        if self.digest()? != expected_state || bindings.digest()? != self.bindings_hash
            || funding.root() != self.funding_root
        {
            return Err(ProofErrorV2::BindingMismatch("ECX match committed state"));
        }
        crate::ecx_execution_v1::ecx_match_prior_commitment_v2(
            bindings, funding, self.funding_index, self.open_interest,
            self.accounts_root, self.orders_root,
            (self.matcher_sequence, self.matcher_receipt_hash), self.sidechain_height,
            ecx_truthcoin_proof::ParentChainContextV1 {
                block_hash: self.parent_hash, height: self.parent_height,
                median_time_past: self.parent_mtp,
            }, source, self.vault_script_sha256, successor_script,
        )
    }

    /// No transaction id is encoded: the state may be committed by the very
    /// transaction whose signing proof consumes it. Authenticate the source
    /// outpoint separately through the checked predecessor/UTXO opening.
    pub fn encode(&self) -> Result<Vec<u8>, ProofErrorV2> {
        if [self.bindings_hash, self.accounts_root, self.orders_root,
            self.funding_root, self.parent_hash, self.vault_script_sha256]
            .contains(&[0; 32])
        {
            return Err(ProofErrorV2::BindingMismatch("ECX successor state identity"));
        }
        let mut out = b"ECXSS1".to_vec();
        for h in [self.bindings_hash, self.accounts_root, self.orders_root, self.funding_root] {
            out.extend_from_slice(&h);
        }
        out.extend_from_slice(&self.funding_index.to_be_bytes());
        out.extend_from_slice(&self.open_interest.to_be_bytes());
        out.extend_from_slice(&self.matcher_sequence.to_be_bytes());
        out.extend_from_slice(&self.matcher_receipt_hash);
        out.extend_from_slice(&self.sidechain_height.to_be_bytes());
        out.extend_from_slice(&self.parent_hash);
        out.extend_from_slice(&self.parent_height.to_be_bytes());
        out.extend_from_slice(&self.parent_mtp.to_be_bytes());
        out.extend_from_slice(&self.controlled_ecx_atoms.to_be_bytes());
        out.extend_from_slice(&self.vault_script_sha256);
        Ok(out)
    }

    pub fn digest(&self) -> Result<Hash32, ProofErrorV2> {
        let mut hash = Sha256::new();
        hash.update(Sha256::digest(b"ECX/successor-state/v1"));
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }

    /// Checks backing against the complete committed ledger, not just the
    /// accounts changed by a trade. Inclusion and covenant execution remain
    /// duties of the enclosing native/recursive successor verifier.
    pub fn verify_vault(
        &self, expected_state: Hash32, bindings: EcxSuccessorBindingsV1,
        economics: EcxConfigurationV1,
        accounts: &[(&ecx_protocol_core::TraderLeafV2,
            &ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1)],
        output: &elements::TxOut,
    ) -> Result<(), ProofErrorV2> {
        if self.digest()? != expected_state || bindings.digest()? != self.bindings_hash
            || output.value != elements::confidential::Value::Explicit(self.controlled_ecx_atoms)
            || ecx_ledger_open_interest(accounts)? != self.open_interest
        {
            return Err(ProofErrorV2::BindingMismatch("ECX successor state opening"));
        }
        verify_ecx_vault_ledger_v1(self.accounts_root, self.vault_script_sha256,
            bindings.account_domain(economics)?, economics.bounds, accounts, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_has_distinct_fixed_encoding_and_binds_physical_backing() {
        let state = EcxSuccessorStateV1 {
            bindings_hash: [1;32], accounts_root: [2;32], orders_root: [3;32],
            funding_root: [4;32], funding_index: -5, open_interest: 6,
            matcher_sequence: 7, matcher_receipt_hash: [8;32], sidechain_height: 9,
            parent_hash: [10;32], parent_height: 11, parent_mtp: 12,
            controlled_ecx_atoms: 13, vault_script_sha256: [14;32],
        };
        let bytes = state.encode().unwrap();
        assert_eq!(bytes.len(), 310);
        assert_eq!(&bytes[..6], b"ECXSS1");
        // Independent layout, including the signed funding index and native
        // u64 parent height. Offsets are part of this version's wire contract.
        let mut expected = b"ECXSS1".to_vec();
        for byte in 1..=4 { expected.extend_from_slice(&[byte;32]); }
        expected.extend_from_slice(&(-5i128).to_be_bytes());
        expected.extend_from_slice(&6u128.to_be_bytes());
        expected.extend_from_slice(&7u128.to_be_bytes());
        expected.extend_from_slice(&[8;32]);
        expected.extend_from_slice(&9u64.to_be_bytes());
        expected.extend_from_slice(&[10;32]);
        for value in [11u64, 12, 13] { expected.extend_from_slice(&value.to_be_bytes()); }
        expected.extend_from_slice(&[14;32]);
        assert_eq!(bytes, expected);
        assert_eq!(EcxSuccessorStateV1::decode(&bytes).unwrap(), state);
        for length in 0..bytes.len() {
            assert!(EcxSuccessorStateV1::decode(&bytes[..length]).is_err());
        }
        let mut malformed = bytes.clone();
        malformed.push(0);
        assert!(EcxSuccessorStateV1::decode(&malformed).is_err());
        malformed = bytes.clone();
        malformed[5] = b'2';
        assert!(EcxSuccessorStateV1::decode(&malformed).is_err());
        malformed = bytes.clone();
        malformed[6..38].fill(0);
        assert!(EcxSuccessorStateV1::decode(&malformed).is_err());
        let original = state.digest().unwrap();
        let mut preimage = Sha256::digest(b"ECX/successor-state/v1").to_vec();
        preimage.extend_from_slice(&expected);
        assert_eq!(original, <Hash32>::from(Sha256::digest(&preimage)));
        let mut changed = state.clone();
        changed.controlled_ecx_atoms += 1;
        assert_ne!(changed.digest().unwrap(), original);
        changed = state.clone();
        changed.funding_index += 1;
        assert_ne!(changed.digest().unwrap(), original);
        changed.vault_script_sha256 = [0;32];
        assert!(changed.digest().is_err());
    }
}
