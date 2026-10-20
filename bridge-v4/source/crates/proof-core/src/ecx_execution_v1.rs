//! Oracle-derived ECX matches and existing-account top-ups with explicit
//! transaction/ledger backing checks. These relations do not authenticate
//! prior state, UTXO inclusion, spend authorization or book priority.
use crate::{
    proof_v2::{
        verify_ecx_authenticated_funding_source_v1, AuthenticatedFundingSourceV2, ProofErrorV2,
    },
    ConversionLegConsensusProofV2,
};
use ecx_protocol_core::{
    advance_exact_funding_index_v2,
    ecx_cash_account_v1::EcxAccountOpeningV1,
    ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1},
    ecx_matcher_v1::{stage_ecx_matcher_authorized_match, EcxMatcherExecutionReceiptV1},
    ecx_order_index_v1::{
        EcxExecutionContextV1, EcxIndexedMatchV1, EcxIndexedOrderOpeningV1, EcxMatchFeeWitnessV1,
    },
    funding_v2::{advance_funding_timestamped_v2, FundingStateV2, TimestampedFundingObservationV2},
    successor_matcher_v2::SuccessorCentralMatcherConfigV2,
    FrozenConfigurationV2, Hash32, OracleMode, Price, Quantity,
};
use ecx_truthcoin_proof::{
    ConsensusProofVerifier, ParentChainContextV1, TruthcoinConsensusProofV1,
};

pub struct EcxOracleMatchResultV1 {
    /// Derived post-match state at this execution context, not proof of a
    /// block advance or of predecessor inclusion.
    pub next_state: crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    pub execution: EcxIndexedMatchV1,
    pub matcher_receipt_hash: Hash32,
    pub funding_state: FundingStateV2,
    pub funding_index: i128,
    pub source: AuthenticatedFundingSourceV2,
}

/// Shared funding advancement for matches and non-trading withdrawals. The
/// caller authenticates the source and complete prior ledger before use.
/// Current observations cannot alter funding for the already elapsed epoch.
fn advance_ecx_funding_for_ledger_v1(
    previous: &FundingStateV2, previous_index: i128,
    source: &AuthenticatedFundingSourceV2, parent: ParentChainContextV1,
    accounts: &[(&ecx_protocol_core::TraderLeafV2,
        &ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1)],
    observations: &[TimestampedFundingObservationV2],
) -> Result<(FundingStateV2, i128), ProofErrorV2> {
    let mark = Price::new(source.mark_price_atoms)?;
    let notional = accounts.iter()
        .filter(|(position, _)| position.position_size_atoms > 0)
        .try_fold(0u128, |total, (position, _)| {
            let amount = ecx_protocol_core::risk::notional(
                mark, position.position_size_atoms.unsigned_abs())?;
            let value = u128::try_from(amount.0)
                .map_err(|_| ecx_protocol_core::ProtocolError::ArithmeticOverflow)?;
            total.checked_add(value)
                .ok_or(ecx_protocol_core::ProtocolError::ArithmeticOverflow)
        })?;
    let (state, rate) = advance_funding_timestamped_v2(previous,
        parent.median_time_past, mark,
        Price::new(source.liquidation_low_atoms)?,
        Price::new(source.liquidation_high_atoms)?,
        source.oracle_valid_through_mtp, observations, notional)?;
    Ok((state, advance_exact_funding_index_v2(previous_index, mark.get(), rate)?))
}

/// Mandatory collateral opening for ordinary matches. Source outpoint and
/// both script hashes must be obtained from authenticated covenant state,
/// not accepted merely because a witness supplies them.
#[derive(Clone, Copy)]
pub struct EcxTradingVaultWitnessV1<'a> {
    pub source_outpoint: elements::OutPoint,
    pub source_transaction: &'a elements::Transaction,
    pub successor_transaction: &'a elements::Transaction,
    pub successor_vout: u32,
    pub source_script_sha256: Hash32,
    pub successor_script_sha256: Hash32,
    pub prior_accounts: &'a [(&'a ecx_protocol_core::TraderLeafV2,
        &'a ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1)],
    pub successor_accounts: &'a [(&'a ecx_protocol_core::TraderLeafV2,
        &'a ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1)],
}

/// Bind a complete ECX ledger to an explicit Elements vault output. The
/// enclosing successor must authenticate the output's outpoint/inclusion and
/// obtain the expected script hash and account root from committed state.
/// This does not authorize a spend or establish that an output is unspent.
pub fn verify_ecx_vault_ledger_v1(
    expected_accounts_root: Hash32,
    expected_script_sha256: Hash32,
    domain: ecx_protocol_core::ecx_cash_account_v1::EcxAccountDomainV1,
    bounds: ecx_protocol_core::IncrementalAccountingBoundsV2,
    accounts: &[(&ecx_protocol_core::TraderLeafV2,
        &ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1)],
    output: &elements::TxOut,
) -> Result<(), ProofErrorV2> {
    use elements::confidential::{Asset, Nonce, Value};
    use sha2::{Digest, Sha256};
    let script_hash: Hash32 = Sha256::digest(output.script_pubkey.as_bytes()).into();
    if domain.collateral_asset == [0; 32]
        || expected_script_sha256 == [0; 32]
        || output.script_pubkey.is_empty()
        || script_hash != expected_script_sha256
        || output.asset != Asset::Explicit(elements::AssetId::from_byte_array(domain.collateral_asset))
        || output.nonce != Nonce::Null
        || !output.witness.is_empty()
    {
        return Err(ProofErrorV2::BindingMismatch("ECX explicit vault output"));
    }
    let Value::Explicit(atoms) = output.value else {
        return Err(ProofErrorV2::BindingMismatch("ECX explicit vault amount"));
    };
    ecx_protocol_core::ecx_cash_account_v1::verify_ecx_complete_ledger_v1(
        expected_accounts_root, domain, bounds, accounts, atoms,
    )?;
    Ok(())
}

/// Select an ordinary-trading vault continuation. Both returned outputs must
/// additionally pass `verify_ecx_vault_ledger_v1` against the corresponding
/// committed roots and script policies. Fees must be sponsored separately:
/// trading redistributes claims but cannot reduce physical backing.
/// The caller authenticates the prior outpoint and chain inclusion; this
/// local transaction relation supplies neither inclusion nor spend authority.
pub fn ecx_trading_vault_outputs_v1<'a>(
    expected_source: elements::OutPoint,
    source: &'a elements::Transaction,
    successor: &'a elements::Transaction,
    successor_vout: u32,
) -> Result<(&'a elements::TxOut, &'a elements::TxOut), ProofErrorV2> {
    let invalid = || ProofErrorV2::BindingMismatch("ECX trading vault continuity");
    if expected_source.is_null() || source.txid() != expected_source.txid {
        return Err(invalid());
    }
    let before = source.output.get(expected_source.vout as usize).ok_or_else(invalid)?;
    let after = successor.output.get(successor_vout as usize).ok_or_else(invalid)?;
    let mut spends = successor.input.iter()
        .filter(|input| input.previous_output == expected_source);
    let spend = spends.next().ok_or_else(invalid)?;
    if spends.next().is_some() || spend.has_issuance() || spend.is_pegin {
        return Err(invalid());
    }
    use elements::confidential::{Asset, Value};
    if !matches!(before.asset, Asset::Explicit(_))
        || !matches!(before.value, Value::Explicit(_))
        || before.asset != after.asset || before.value != after.value
    {
        return Err(invalid());
    }
    Ok((before, after))
}

/// Signed cancellation with unchanged physical backing and vault policy.
/// The caller authenticates the prior state/outpoint and native inclusion.
/// No oracle is required to remove an order; no cash or funding is transferred.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_cancellation_v1(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
    economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
    signed: &ecx_protocol_core::ecx_cancel_v1::SignedEcxCancelV1,
    account: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
    order: &ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2,
    order_siblings: &[Hash32],
    vault: &EcxTradingVaultWitnessV1<'_>,
) -> Result<crate::ecx_successor_state_v1::EcxSuccessorStateV1, ProofErrorV2> {
    if vault.source_outpoint != expected_outpoint
        || vault.source_script_sha256 != prior.vault_script_sha256
        || vault.successor_script_sha256 != prior.vault_script_sha256
    { return Err(ProofErrorV2::BindingMismatch("ECX cancellation vault policy")); }
    let (before, after) = ecx_trading_vault_outputs_v1(expected_outpoint,
        vault.source_transaction, vault.successor_transaction, vault.successor_vout)?;
    prior.verify_vault(expected_state, bindings, economics, vault.prior_accounts, before)?;
    let next = prior.cancel_order(expected_state, bindings, economics, signed,
        account, order, order_siblings)?;
    next.verify_vault(next.digest()?, bindings, economics, vault.successor_accounts, after)?;
    Ok(next)
}

/// Transaction relation for an existing-account ECX top-up. The enclosing
/// verifier must bind the recipient and amount to an authorized deposit,
/// authenticate both source UTXOs and apply the before/after ledger checks.
/// Consuming each distinct outpoint once prevents intra-transaction reuse;
/// cross-transaction replay is rejected by the chain's UTXO rules, not here.
/// The entire deposit is credited; network fees require separate funding.
pub fn ecx_top_up_vault_outputs_v1<'a>(
    source_outpoint: elements::OutPoint,
    source: &'a elements::Transaction,
    deposit_outpoint: elements::OutPoint,
    deposit: &'a elements::Transaction,
    successor: &'a elements::Transaction,
    successor_vout: u32,
    collateral_asset: Hash32,
    credited_atoms: u64,
) -> Result<(&'a elements::TxOut, &'a elements::TxOut), ProofErrorV2> {
    use elements::confidential::{Asset, Nonce, Value};
    let invalid = || ProofErrorV2::BindingMismatch("ECX top-up vault continuity");
    if collateral_asset == [0; 32] || credited_atoms == 0
        || source_outpoint.is_null() || deposit_outpoint.is_null()
        || source_outpoint == deposit_outpoint
        || source.txid() != source_outpoint.txid
        || deposit.txid() != deposit_outpoint.txid
    { return Err(invalid()); }
    let before = source.output.get(source_outpoint.vout as usize).ok_or_else(invalid)?;
    let funding = deposit.output.get(deposit_outpoint.vout as usize).ok_or_else(invalid)?;
    let after = successor.output.get(successor_vout as usize).ok_or_else(invalid)?;
    for outpoint in [source_outpoint, deposit_outpoint] {
        let mut inputs = successor.input.iter().filter(|i| i.previous_output == outpoint);
        let input = inputs.next().ok_or_else(invalid)?;
        if inputs.next().is_some() || input.has_issuance() || input.is_pegin {
            return Err(invalid());
        }
    }
    let asset = Asset::Explicit(elements::AssetId::from_byte_array(collateral_asset));
    for output in [before, funding, after] {
        if output.asset != asset || output.nonce != Nonce::Null
            || !output.witness.is_empty() || output.script_pubkey.is_empty()
        { return Err(invalid()); }
    }
    let Value::Explicit(previous_atoms) = before.value else { return Err(invalid()); };
    if funding.value != Value::Explicit(credited_atoms)
        || after.value != Value::Explicit(previous_atoms.checked_add(credited_atoms).ok_or_else(invalid)?)
    { return Err(invalid()); }
    Ok((before, after))
}

/// Physical relation for one ECX withdrawal. Source/successor scripts and
/// complete ledgers require separate checks. This does not establish signature,
/// maturity, UTXO provenance or order-risk authorization. Fees are sponsored
/// separately; neither the recipient nor remaining backing pays them here.
pub fn ecx_withdrawal_vault_outputs_v1<'a>(
    source_outpoint: elements::OutPoint,
    source: &'a elements::Transaction,
    successor: &'a elements::Transaction,
    successor_vout: u32,
    recipient_vout: u32,
    collateral_asset: Hash32,
    recipient_script_sha256: Hash32,
    atoms: u64,
) -> Result<(&'a elements::TxOut, &'a elements::TxOut), ProofErrorV2> {
    use elements::confidential::{Asset, Nonce, Value};
    use sha2::{Digest, Sha256};
    let invalid = || ProofErrorV2::BindingMismatch("ECX withdrawal vault continuity");
    if source_outpoint.is_null() || source.txid() != source_outpoint.txid
        || successor_vout == recipient_vout || atoms == 0
        || collateral_asset == [0; 32] || recipient_script_sha256 == [0; 32]
    { return Err(invalid()); }
    let before = source.output.get(source_outpoint.vout as usize).ok_or_else(invalid)?;
    let after = successor.output.get(successor_vout as usize).ok_or_else(invalid)?;
    let recipient = successor.output.get(recipient_vout as usize).ok_or_else(invalid)?;
    let mut inputs = successor.input.iter().filter(|i| i.previous_output == source_outpoint);
    let input = inputs.next().ok_or_else(invalid)?;
    if inputs.next().is_some() || input.has_issuance() || input.is_pegin {
        return Err(invalid());
    }
    let asset = Asset::Explicit(elements::AssetId::from_byte_array(collateral_asset));
    for output in [before, after, recipient] {
        if output.asset != asset || output.nonce != Nonce::Null
            || !output.witness.is_empty() || output.script_pubkey.is_empty()
        { return Err(invalid()); }
    }
    let Value::Explicit(previous_atoms) = before.value else { return Err(invalid()); };
    let script_hash: Hash32 = Sha256::digest(recipient.script_pubkey.as_bytes()).into();
    if recipient.value != Value::Explicit(atoms) || script_hash != recipient_script_sha256
        || after.value != Value::Explicit(previous_atoms.checked_sub(atoms).ok_or_else(invalid)?)
    { return Err(invalid()); }
    Ok((before, after))
}

/// Atomically verify a signed account debit and its physical vault/recipient
/// relation. Expected roots/scripts, height and valuation must be authenticated
/// by the enclosing successor. Complete-book fee reservation is enforced here;
/// outstanding-order position risk and source UTXO provenance
/// remain outer obligations; this is not acceptance. Signed not-before is
/// enforced; the current ECX configuration specifies no additional waiting delay.
pub fn verify_ecx_account_withdrawal_v1(
    source_root: Hash32,
    economics: EcxConfigurationV1,
    signed: &ecx_protocol_core::ecx_withdrawal_v1::SignedEcxWithdrawalV1,
    account: EcxAccountOpeningV1<'_>,
    height: u64,
    low: Price,
    high: Price,
    funding: i128,
    vault: &EcxTradingVaultWitnessV1<'_>,
    recipient_vout: u32,
    orders: ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1<'_>,
) -> Result<ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalAccountUpdateV1, ProofErrorV2> {
    let domain = economics.account_domain()?;
    let update = ecx_protocol_core::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
        source_root, economics, signed, account, height, low, high, funding, orders,
    )?;
    let (before, after) = ecx_withdrawal_vault_outputs_v1(
        vault.source_outpoint, vault.source_transaction, vault.successor_transaction,
        vault.successor_vout, recipient_vout, domain.collateral_asset,
        signed.request.destination_script_hash, signed.request.amount,
    )?;
    verify_ecx_vault_ledger_v1(source_root, vault.source_script_sha256,
        domain, economics.bounds, vault.prior_accounts, before)?;
    verify_ecx_vault_ledger_v1(update.accounts_root, vault.successor_script_sha256,
        domain, economics.bounds, vault.successor_accounts, after)?;
    Ok(update)
}

/// Shared non-trading risk preparation. Checks the committed complete ledger
/// before deriving funding; no caller-selected price or funding index is used.
/// The enclosing native transition still authenticates the expected state and
/// source outpoint. This does not authorize any account mutation.
#[allow(clippy::too_many_arguments)]
fn prepare_ecx_oracle_risk_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: EcxSuccessorBindingsV1, economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2, verifier: &V,
    previous_funding: &FundingStateV2,
    vault: &EcxTradingVaultWitnessV1<'_>,
) -> Result<(AuthenticatedFundingSourceV2, FundingStateV2, i128), ProofErrorV2> {
    let invalid = || ProofErrorV2::BindingMismatch("ECX risk committed state");
    if prior.digest()? != expected_state || prior.bindings_hash != bindings.digest()?
        || prior.funding_root != previous_funding.root()
        || vault.source_outpoint != expected_outpoint
        || vault.source_transaction.txid() != expected_outpoint.txid
        || vault.source_script_sha256 != prior.vault_script_sha256
    { return Err(invalid()); }
    let before = vault.source_transaction.output.get(expected_outpoint.vout as usize)
        .ok_or_else(invalid)?;
    prior.verify_vault(expected_state, bindings, economics, vault.prior_accounts, before)?;
    let parent = ParentChainContextV1 { block_hash: prior.parent_hash,
        height: prior.parent_height, median_time_past: prior.parent_mtp };
    let source = verify_ecx_authenticated_funding_source_v1(bindings, economics,
        configuration, parent, truthcoin, ecx_btc, usdd_usd, verifier)?;
    if source.oracle_mode != OracleMode::Normal {
        return Err(ProofErrorV2::BindingMismatch("ECX normal risk oracle mode"));
    }
    let (funding, index) = advance_ecx_funding_for_ledger_v1(previous_funding,
        prior.funding_index, &source, parent, vault.prior_accounts, &[])?;
    Ok((source, funding, index))
}

/// Prepare admission using authenticated price bounds and freshly derived
/// funding. This is not authorization: the matcher must sign the execution
/// derived from this prepared state, and native inclusion remains external.
#[allow(clippy::too_many_arguments)]
pub fn prepare_ecx_oracle_admission_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: EcxSuccessorBindingsV1, economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2, truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2, usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V, previous_funding: &FundingStateV2,
    vault: &EcxTradingVaultWitnessV1<'_>,
) -> Result<(crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    FundingStateV2, Price, Price), ProofErrorV2> {
    if vault.successor_script_sha256 != prior.vault_script_sha256 {
        return Err(ProofErrorV2::BindingMismatch("ECX admission vault policy"));
    }
    ecx_trading_vault_outputs_v1(expected_outpoint, vault.source_transaction,
        vault.successor_transaction, vault.successor_vout)?;
    let (source, funding, index) = prepare_ecx_oracle_risk_v1(expected_state,
        prior, expected_outpoint, bindings, economics, configuration, truthcoin,
        ecx_btc, usdd_usd, verifier, previous_funding, vault)?;
    let mut prepared = prior.clone();
    prepared.funding_root = funding.root();
    prepared.funding_index = index;
    Ok((prepared, funding, Price::new(source.authenticated_min_price_atoms)?,
        Price::new(source.authenticated_max_price_atoms)?))
}

/// Join owner/matcher authorization, authenticated risk and unchanged ECX
/// backing. The enclosing native relation pins the predecessor and both UTXOs.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_oracle_admission_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: EcxSuccessorBindingsV1, economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2, truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2, usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V, previous_funding: &FundingStateV2,
    matcher: &SuccessorCentralMatcherConfigV2, receipt: &EcxMatcherExecutionReceiptV1,
    signed: ecx_protocol_core::ecx_order_v1::SignedEcxOrderV1,
    account: EcxAccountOpeningV1<'_>, absence_siblings: &[Hash32],
    records: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
    vault: &EcxTradingVaultWitnessV1<'_>,
) -> Result<(crate::ecx_successor_state_v1::EcxSuccessorStateV1, FundingStateV2), ProofErrorV2> {
    let (prepared, funding, low, high) = prepare_ecx_oracle_admission_v1(
        expected_state, prior, expected_outpoint, bindings, economics, configuration,
        truthcoin, ecx_btc, usdd_usd, verifier, previous_funding, vault)?;
    let next = prepared.admit_order(prepared.digest()?, bindings, economics,
        matcher, receipt, signed, account, absence_siblings, records, low, high)?;
    let after = &vault.successor_transaction.output[vault.successor_vout as usize];
    next.verify_vault(next.digest()?, bindings, economics, vault.successor_accounts, after)?;
    Ok((next, funding))
}

/// Authenticated pointwise target assessment at the actual oracle mark, with
/// freshly derived funding. Not interval liquidation permission: the final
/// liquidation relation must also enforce its authenticated band, counterparties,
/// fees, order priority and atomic successor roots. Healthy targets are reported,
/// never implicitly admitted. No state or funding commitment is changed here.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_oracle_target_margin_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: EcxSuccessorBindingsV1, economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2, verifier: &V,
    previous_funding: &FundingStateV2,
    target: EcxAccountOpeningV1<'_>, vault: &EcxTradingVaultWitnessV1<'_>,
) -> Result<(ecx_protocol_core::ecx_cash_account_v1::EcxMarginStatusV1,
    AuthenticatedFundingSourceV2, FundingStateV2, i128), ProofErrorV2> {
    let (source, funding, index) = prepare_ecx_oracle_risk_v1(expected_state,
        prior, expected_outpoint, bindings, economics, configuration,
        truthcoin, ecx_btc, usdd_usd, verifier, previous_funding, vault)?;
    let mut prepared = prior.clone();
    prepared.funding_root = funding.root();
    prepared.funding_index = index;
    let margin = prepared.liquidation_target_margin(prepared.digest()?, bindings,
        economics, target, Price::new(source.mark_price_atoms)?)?;
    Ok((margin, source, funding, index))
}

/// Sufficient interval-deficit evidence using only authenticated oracle bounds.
/// False means not proven (including conservative rounding ambiguity), not
/// necessarily healthy. This does not execute liquidation or authorize a spend;
/// the final relation must additionally verify maker fills, fees and atomic roots.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_oracle_target_deficit_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: EcxSuccessorBindingsV1, economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2, verifier: &V,
    previous_funding: &FundingStateV2,
    target: EcxAccountOpeningV1<'_>, vault: &EcxTradingVaultWitnessV1<'_>,
) -> Result<(bool, AuthenticatedFundingSourceV2, FundingStateV2, i128), ProofErrorV2> {
    let position = target.position;
    let cash = target.cash;
    // Reuse state, complete-ledger, account membership, role, source and funding
    // authentication. Callers cannot substitute a price band or funding index.
    let (_, source, funding, index) = verify_ecx_oracle_target_margin_v1(
        expected_state, prior, expected_outpoint, bindings, economics,
        configuration, truthcoin, ecx_btc, usdd_usd, verifier,
        previous_funding, target, vault)?;
    let deficit = cash.proves_deficit_over_interval(position,
        economics.cash_valuation_scale, Price::new(source.liquidation_low_atoms)?,
        Price::new(source.liquidation_high_atoms)?, index,
        economics.risk.maintenance_margin_bps, economics.bounds)?;
    Ok((deficit, source, funding, index))
}

/// Join authenticated interval deficit, price-time fills, netted cash and vault
/// roots. No caller-selected settlement price, band or funding index is accepted.
/// This is an internal state relation, not native inclusion or recursive spend
/// authorization; the enclosing relation must authenticate its state/outpoint.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_oracle_liquidation_batch_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: EcxSuccessorBindingsV1, economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2, truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2, usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V, previous_funding: &FundingStateV2,
    target: EcxAccountOpeningV1<'_>, makers: &[EcxAccountOpeningV1<'_>],
    clearing: EcxAccountOpeningV1<'_>, insurance: EcxAccountOpeningV1<'_>,
    orders: &[(&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2, &[Hash32])],
    source_orders: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
    fills: &[(Hash32, u64)], vault: &EcxTradingVaultWitnessV1<'_>,
) -> Result<(crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    FundingStateV2, ecx_protocol_core::ecx_order_v1::EcxLiquidationBatchV1), ProofErrorV2> {
    if vault.successor_script_sha256 != prior.vault_script_sha256 {
        return Err(ProofErrorV2::BindingMismatch("ECX liquidation vault policy"));
    }
    let (_, after) = ecx_trading_vault_outputs_v1(expected_outpoint,
        vault.source_transaction, vault.successor_transaction, vault.successor_vout)?;
    let (deficit, source, funding, index) = verify_ecx_oracle_target_deficit_v1(
        expected_state, prior, expected_outpoint, bindings, economics, configuration,
        truthcoin, ecx_btc, usdd_usd, verifier, previous_funding,
        EcxAccountOpeningV1 { position: target.position, cash: target.cash,
            siblings: target.siblings }, vault)?;
    if !deficit {
        return Err(ProofErrorV2::BindingMismatch("ECX liquidation deficit not proven"));
    }
    let (accounts_root, orders_root, batch) =
        ecx_protocol_core::ecx_order_index_v1::stage_ecx_indexed_liquidation_batch_v1(
            prior.accounts_root, prior.orders_root, economics, vault.prior_accounts,
            prior.controlled_ecx_atoms, target, makers, clearing, insurance, orders,
            source_orders, fills, prior.sidechain_height,
            Price::new(source.mark_price_atoms)?, Price::new(source.liquidation_low_atoms)?,
            Price::new(source.liquidation_high_atoms)?, index)?;
    let mut next = prior.clone();
    next.accounts_root = accounts_root;
    next.orders_root = orders_root;
    next.funding_root = funding.root();
    next.funding_index = index;
    next.open_interest = crate::ecx_successor_state_v1::ecx_ledger_open_interest(
        vault.successor_accounts)?;
    next.verify_vault(next.digest()?, bindings, economics, vault.successor_accounts, after)?;
    Ok((next, funding, batch))
}

/// State-bound ordinary withdrawal with authenticated oracle and derived funding.
/// The native caller must pin the prepared state/outpoint to its checked context,
/// enforce outstanding-order position reservations, and prove transaction/script
/// execution and final vault membership. This relation alone is not acceptance.
/// Withdrawal preserves vault policy and matcher/order state; it adds no trade
/// observation and must not advance the matcher cursor.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_oracle_withdrawal_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    prior: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    expected_outpoint: elements::OutPoint,
    bindings: EcxSuccessorBindingsV1, economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2, verifier: &V,
    previous_funding: &FundingStateV2,
    signed: &ecx_protocol_core::ecx_withdrawal_v1::SignedEcxWithdrawalV1,
    account: EcxAccountOpeningV1<'_>,
    vault: &EcxTradingVaultWitnessV1<'_>, recipient_vout: u32,
    records: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
) -> Result<(crate::ecx_successor_state_v1::EcxSuccessorStateV1, FundingStateV2), ProofErrorV2> {
    let invalid = || ProofErrorV2::BindingMismatch("ECX withdrawal committed state");
    if vault.successor_script_sha256 != prior.vault_script_sha256 {
        return Err(invalid());
    }
    let (source, funding_state, funding_index) = prepare_ecx_oracle_risk_v1(
        expected_state, prior, expected_outpoint, bindings, economics,
        configuration, truthcoin, ecx_btc, usdd_usd, verifier, previous_funding, vault)?;
    let update = verify_ecx_account_withdrawal_v1(prior.accounts_root, economics,
        signed, account, prior.sidechain_height,
        Price::new(source.authenticated_min_price_atoms)?,
        Price::new(source.authenticated_max_price_atoms)?, funding_index, vault,
        recipient_vout, ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 {
            root: prior.orders_root, records })?;
    let mut next = prior.clone();
    next.accounts_root = update.accounts_root;
    next.funding_root = funding_state.root();
    next.funding_index = funding_index;
    next.controlled_ecx_atoms = prior.controlled_ecx_atoms.checked_sub(signed.request.amount)
        .ok_or_else(invalid)?;
    let after = vault.successor_transaction.output.get(vault.successor_vout as usize)
        .ok_or_else(invalid)?;
    next.verify_vault(next.digest()?, bindings, economics, vault.successor_accounts, after)?;
    Ok((next, funding_state))
}

/// Compact, domain-separated explicit ECX deposit marker. The economic hash
/// commits chain, market and collateral asset. Excluding the source txid avoids
/// self-reference; the consuming transaction later binds the full outpoint.
pub fn ecx_deposit_marker_script_v1(
    economics: EcxConfigurationV1, recipient: Hash32, vout: u32, atoms: u64,
) -> Result<elements::Script, ProofErrorV2> {
    use sha2::{Digest, Sha256};
    let domain = economics.account_domain()?;
    if recipient == [0; 32] || atoms == 0 {
        return Err(ProofErrorV2::BindingMismatch("ECX deposit marker"));
    }
    let mut hash = Sha256::new();
    hash.update(b"ECX/explicit-deposit-marker/v1");
    hash.update(domain.configuration_hash);
    hash.update(recipient);
    hash.update(vout.to_be_bytes());
    hash.update(atoms.to_be_bytes());
    // OP_RETURN, minimal push of 37 bytes: ECXE, version 1, SHA256 commitment.
    let mut script = vec![0x6a, 37, b'E', b'C', b'X', b'E', 1];
    script.extend_from_slice(&hash.finalize());
    Ok(elements::Script::from(script))
}

/// Compose the existing-account update with both physical ledger checks.
/// Expected recipient, prior root, outpoints and policies must be authenticated
/// by the enclosing deposit covenant; this function does not verify signatures
/// or inclusion. The successor root is computed, never accepted from a witness.
pub fn verify_ecx_account_top_up_v1(
    prior_root: Hash32,
    expected_recipient: Hash32,
    economics: EcxConfigurationV1,
    account: EcxAccountOpeningV1<'_>,
    vault: &EcxTradingVaultWitnessV1<'_>,
    deposit_outpoint: elements::OutPoint,
    deposit_transaction: &elements::Transaction,
    atoms: u64,
) -> Result<(Hash32, ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1), ProofErrorV2> {
    if expected_recipient == [0; 32] || account.position.key() != expected_recipient {
        return Err(ProofErrorV2::BindingMismatch("ECX deposit recipient"));
    }
    let domain = economics.account_domain()?;
    let marker = ecx_deposit_marker_script_v1(economics, expected_recipient, deposit_outpoint.vout, atoms)?;
    // V1 permits one ECXE deposit per funding transaction, not a caller-selected
    // marker among conflicting recipients. Count the whole reserved family,
    // including unknown versions and nonminimal pushes; exact equality below
    // then enforces the canonical supported encoding.
    let mut markers = deposit_transaction.output.iter().filter(|o| {
        use elements::script::Instruction;
        let mut instructions = o.script_pubkey.instructions();
        matches!(instructions.next(), Some(Ok(Instruction::Op(op)))
            if op == elements::opcodes::all::OP_RETURN)
            && matches!(instructions.next(), Some(Ok(Instruction::PushBytes(bytes)))
                if bytes.starts_with(b"ECXE"))
    });
    let output = markers.next().ok_or(ProofErrorV2::BindingMismatch("ECX deposit marker"))?;
    if markers.next().is_some()
        || output.script_pubkey != marker
        || output.asset != elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array(domain.collateral_asset))
        || output.value != elements::confidential::Value::Explicit(0)
        || output.nonce != elements::confidential::Nonce::Null || !output.witness.is_empty()
    { return Err(ProofErrorV2::BindingMismatch("ECX deposit marker")); }
    let (root, cash) = ecx_protocol_core::ecx_cash_account_v1::stage_ecx_account_top_up_v1(
        prior_root, economics, account, atoms,
    )?;
    let (before, after) = ecx_top_up_vault_outputs_v1(
        vault.source_outpoint, vault.source_transaction, deposit_outpoint,
        deposit_transaction, vault.successor_transaction, vault.successor_vout,
        domain.collateral_asset, atoms,
    )?;
    verify_ecx_vault_ledger_v1(prior_root, vault.source_script_sha256, domain,
        economics.bounds, vault.prior_accounts, before)?;
    verify_ecx_vault_ledger_v1(root, vault.successor_script_sha256, domain,
        economics.bounds, vault.successor_accounts, after)?;
    Ok((root, cash))
}

/// Commitment opened by the enclosing successor proof. Its expected value
/// must come from authenticated prior state and the selected parent context,
/// not be supplied alongside an untrusted opening by the witness producer.
/// V2 additionally pins the source vault and both script policies. It never
/// commits the successor txid (which may contain the proof being generated).
/// Callers must derive these pins from authenticated state/configuration.
pub fn ecx_match_prior_commitment_v2(
    bindings: EcxSuccessorBindingsV1, funding: &FundingStateV2,
    funding_index: i128, open_interest: u128, accounts: Hash32, orders: Hash32,
    cursor: (u128, Hash32), height: u64, parent: ParentChainContextV1,
    source_vault: elements::OutPoint, source_script: Hash32, successor_script: Hash32,
) -> Result<Hash32, ProofErrorV2> {
    use sha2::{Digest, Sha256};
    if source_vault.is_null() || source_script == [0; 32] || successor_script == [0; 32] {
        return Err(ProofErrorV2::BindingMismatch("ECX match vault pins"));
    }
    let mut hash = Sha256::new();
    hash.update(Sha256::digest(b"ECX/match-prior-opening/v2"));
    hash.update(bindings.digest()?);
    hash.update(funding.root());
    hash.update(funding_index.to_be_bytes());
    hash.update(open_interest.to_be_bytes());
    hash.update(accounts);
    hash.update(orders);
    hash.update(cursor.0.to_be_bytes());
    hash.update(cursor.1);
    hash.update(height.to_be_bytes());
    hash.update(parent.block_hash);
    hash.update(parent.height.to_be_bytes());
    hash.update(parent.median_time_past.to_be_bytes());
    hash.update(elements::encode::serialize(&source_vault));
    hash.update(source_script);
    hash.update(successor_script);
    Ok(hash.finalize().into())
}

/// Execute against one pinned ECX state rather than independently supplied
/// roots and execution context. The enclosing covenant must authenticate
/// `expected_state` and the source outpoint; this does not prove inclusion.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecx_committed_match_v1<V: ConsensusProofVerifier>(
    expected_state: Hash32,
    state: &crate::ecx_successor_state_v1::EcxSuccessorStateV1,
    vault: &EcxTradingVaultWitnessV1<'_>,
    bindings: EcxSuccessorBindingsV1,
    economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V,
    previous_funding: &FundingStateV2,
    matcher: &SuccessorCentralMatcherConfigV2,
    receipt: &EcxMatcherExecutionReceiptV1,
    maker: EcxIndexedOrderOpeningV1<'_>,
    taker: EcxIndexedOrderOpeningV1<'_>,
    clearing: EcxAccountOpeningV1<'_>,
    quantity: u64,
    fees: Option<EcxMatchFeeWitnessV1<'_>>,
    source_orders: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
) -> Result<EcxOracleMatchResultV1, ProofErrorV2> {
    let opening = state.match_opening(expected_state, bindings, previous_funding,
        vault.source_outpoint, vault.successor_script_sha256)?;
    let (before, _) = ecx_trading_vault_outputs_v1(vault.source_outpoint,
        vault.source_transaction, vault.successor_transaction, vault.successor_vout)?;
    if vault.source_script_sha256 != state.vault_script_sha256
        || before.value != elements::confidential::Value::Explicit(state.controlled_ecx_atoms)
    {
        return Err(ProofErrorV2::BindingMismatch("ECX committed match vault"));
    }
    verify_ecx_oracle_match_v1(opening, vault, bindings, economics, configuration,
        ParentChainContextV1 { block_hash: state.parent_hash,
            height: state.parent_height, median_time_past: state.parent_mtp },
        truthcoin, ecx_btc, usdd_usd, verifier, previous_funding,
        state.funding_index, state.open_interest, state.accounts_root,
        state.orders_root, matcher, (state.matcher_sequence, state.matcher_receipt_hash),
        receipt, maker, taker, clearing, state.sidechain_height, quantity, fees, source_orders)
}

/// Compose recursive oracle checking, derived funding and matcher-authorized
/// execution. The enclosing successor MUST authenticate the supplied prior
/// roots, funding state/index, pre-fill OI, matcher cursor, height and parent.
/// This handles one ordinary match in Normal mode; it is not a batch, forced
/// inclusion, liquidation, reduce-only or complete successor verifier.
pub fn verify_ecx_oracle_match_v1<V: ConsensusProofVerifier>(
    expected_prior_commitment: Hash32,
    vault: &EcxTradingVaultWitnessV1<'_>,
    bindings: EcxSuccessorBindingsV1,
    economics: EcxConfigurationV1,
    configuration: &FrozenConfigurationV2,
    parent: ParentChainContextV1,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V,
    previous_funding: &FundingStateV2,
    previous_funding_index: i128,
    open_interest_before_fills: u128,
    accounts_root: Hash32,
    orders_root: Hash32,
    matcher: &SuccessorCentralMatcherConfigV2,
    previous_cursor: (u128, Hash32),
    receipt: &EcxMatcherExecutionReceiptV1,
    maker: EcxIndexedOrderOpeningV1<'_>,
    taker: EcxIndexedOrderOpeningV1<'_>,
    clearing: EcxAccountOpeningV1<'_>,
    height: u64,
    quantity: u64,
    fees: Option<EcxMatchFeeWitnessV1<'_>>,
    source_orders: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
) -> Result<EcxOracleMatchResultV1, ProofErrorV2> {
    if expected_prior_commitment != ecx_match_prior_commitment_v2(
        bindings, previous_funding, previous_funding_index, open_interest_before_fills,
        accounts_root, orders_root, previous_cursor, height, parent,
        vault.source_outpoint, vault.source_script_sha256, vault.successor_script_sha256,
    )? {
        return Err(ProofErrorV2::BindingMismatch("ECX match prior opening"));
    }
    if crate::ecx_successor_state_v1::ecx_ledger_open_interest(vault.prior_accounts)?
        != open_interest_before_fills
    {
        return Err(ProofErrorV2::BindingMismatch("ECX prior open interest"));
    }
    crate::ecx_successor_state_v1::ecx_ledger_open_interest(vault.successor_accounts)?;
    let source = verify_ecx_authenticated_funding_source_v1(
        bindings,
        economics,
        configuration,
        parent,
        truthcoin,
        ecx_btc,
        usdd_usd,
        verifier,
    )?;
    if source.oracle_mode != OracleMode::Normal {
        return Err(ProofErrorV2::BindingMismatch(
            "ECX ordinary match oracle mode",
        ));
    }
    let mark = Price::new(source.mark_price_atoms)?;
    let advance = |observations: &[TimestampedFundingObservationV2]| {
        advance_ecx_funding_for_ledger_v1(previous_funding, previous_funding_index,
            &source, parent, vault.prior_accounts, observations)
    };
    // Discard the preliminary root; the final root includes the verified fill.
    let (_, funding_index) = advance(&[])?;
    let execution_price = maker.order.signed.order.limit_price;
    let (priority_before, _) = ecx_trading_vault_outputs_v1(
        vault.source_outpoint, vault.source_transaction,
        vault.successor_transaction, vault.successor_vout,
    )?;
    let elements::confidential::Value::Explicit(priority_backing) = priority_before.value else {
        return Err(ProofErrorV2::BindingMismatch("ECX prior backing"));
    };
    ecx_protocol_core::ecx_order_index_v1::verify_ecx_best_maker_v1(
        accounts_root, orders_root, economics, vault.prior_accounts,
        priority_backing, source_orders, maker.order, taker.order, height,
    )?;
    let (execution, matcher_receipt_hash) = stage_ecx_matcher_authorized_match(
        accounts_root,
        orders_root,
        bindings,
        economics,
        matcher,
        previous_cursor,
        receipt,
        maker,
        taker,
        clearing,
        height,
        quantity,
        mark,
        funding_index,
        Price::new(source.authenticated_min_price_atoms)?,
        Price::new(source.authenticated_max_price_atoms)?,
        EcxExecutionContextV1 {
            parent_hash: parent.block_hash,
            parent_height: parent.height,
            parent_mtp: parent.median_time_past,
            match_sequence: receipt.sequence,
        },
        fees,
        source_orders,
    )?;
    let observation = TimestampedFundingObservationV2::new(
        execution_price,
        Quantity::new(quantity)?,
        parent.median_time_past,
    )?;
    let (funding_state, final_index) = advance(&[observation])?;
    if final_index != funding_index {
        return Err(ProofErrorV2::BindingMismatch(
            "ECX funding execution causality",
        ));
    }
    let (before, after) = ecx_trading_vault_outputs_v1(
        vault.source_outpoint, vault.source_transaction,
        vault.successor_transaction, vault.successor_vout,
    )?;
    let domain = bindings.account_domain(economics)?;
    verify_ecx_vault_ledger_v1(
        accounts_root, vault.source_script_sha256, domain, economics.bounds,
        vault.prior_accounts, before,
    )?;
    // Never accept a witness-selected post root: use the actual match result.
    verify_ecx_vault_ledger_v1(
        execution.accounts.root, vault.successor_script_sha256, domain, economics.bounds,
        vault.successor_accounts, after,
    )?;
    let elements::confidential::Value::Explicit(controlled_ecx_atoms) = after.value else {
        return Err(ProofErrorV2::BindingMismatch("ECX successor backing"));
    };
    let next_state = crate::ecx_successor_state_v1::EcxSuccessorStateV1 {
        bindings_hash: bindings.digest()?,
        accounts_root: execution.accounts.root,
        orders_root: execution.orders_root,
        funding_root: funding_state.root(),
        funding_index,
        open_interest: crate::ecx_successor_state_v1::ecx_ledger_open_interest(vault.successor_accounts)?,
        matcher_sequence: receipt.sequence,
        matcher_receipt_hash,
        sidechain_height: height,
        parent_hash: parent.block_hash,
        parent_height: parent.height,
        parent_mtp: parent.median_time_past,
        controlled_ecx_atoms,
        vault_script_sha256: vault.successor_script_sha256,
    };
    next_state.digest()?;
    Ok(EcxOracleMatchResultV1 {
        next_state,
        execution,
        matcher_receipt_hash,
        funding_state,
        funding_index,
        source,
    })
}
