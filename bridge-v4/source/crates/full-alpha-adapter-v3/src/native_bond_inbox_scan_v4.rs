//! Complete marker discovery matching native ScriptContainsMagic.
//! Discovery is not signature, custody, source-transaction or consensus
//! verification. In particular malformed magic-bearing outputs are not skipped.
use elements::Transaction;
use elements::hashes::{sha256, Hash};
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "native_bond_inbox_test_configuration.rs"]
mod test_configuration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanError { Limit, Index, MultipleMarkers, ExtraReturnOutput, NonCanonicalFiniteMarker, SourceForm, InconsistentSource, Context, Authentication }

/// Unverified encoding context. Hashing this does not authenticate its values.
pub struct EntryContext {
    pub count: u64,
    pub previous_root: [u8; 32],
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub block_hash: [u8; 32],
}

/// Native finite 700-byte entry encoding. This is deliberately only an encoder:
/// callers must validate marker signatures, custody and parent deadlines before
/// using its result to advance an authenticated checkpoint.
pub fn encode_finite_entry(context: &EntryContext, marker: &LocatedMarker<'_>, facts: &SourceFacts)
    -> Result<[u8; 700], ScanError> {
    if context.count == u64::MAX || context.previous_root == [0; 32]
        || context.sidechain_height == 0 || context.parent_height == 0
        || context.block_hash == [0; 32] {
        return Err(ScanError::Context);
    }
    let payload = marker.finite_payload()?;
    let mut bytes = Vec::with_capacity(700);
    bytes.push(1);
    bytes.extend_from_slice(&context.count.to_be_bytes());
    bytes.extend_from_slice(&context.previous_root);
    bytes.extend_from_slice(&context.sidechain_height.to_be_bytes());
    bytes.extend_from_slice(&context.parent_height.to_be_bytes());
    bytes.extend_from_slice(&context.block_hash);
    bytes.extend_from_slice(&facts.txid);
    bytes.extend_from_slice(&facts.wtxid);
    bytes.extend_from_slice(&facts.transaction_len.to_be_bytes());
    bytes.extend_from_slice(&facts.witness_sha256);
    bytes.extend_from_slice(&facts.witness_len.to_be_bytes());
    bytes.extend_from_slice(&marker.transaction_index.to_be_bytes());
    bytes.extend_from_slice(&marker.output_index.to_be_bytes());
    bytes.extend_from_slice(&payload[4..]);
    bytes.try_into().map_err(|_| ScanError::Index)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFacts {
    pub txid: [u8; 32],
    pub wtxid: [u8; 32],
    pub transaction_len: u32,
    pub witness_sha256: [u8; 32],
    pub witness_len: u32,
}

/// Successor lifetime counters are not finite-profile counters with a cast.
#[derive(Clone, Debug)]
pub struct SuccessorEntryContext {
    pub count: u128,
    pub previous_root: [u8; 32],
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub block_hash: [u8; 32],
}

/// Validate the successor wrapper and independently reproduce the native
/// 708-byte entry. This does not admit a source: custody, staging covenant,
/// transaction consensus and authenticated membership remain caller duties.
pub fn validated_successor_entry(
    context: &SuccessorEntryContext, located: &LocatedMarker<'_>, facts: &SourceFacts,
    chain_id: [u8; 32], configuration_hash: [u8; 32],
    availability: ecx_protocol_core::availability::AvailabilityConfigV1,
    inclusion_blocks: u32, refund_minimum: u32,
) -> Result<ecx_protocol_core::successor_bond_inbox_v2::SuccessorBondInboxEntryV2, ScanError> {
    use ecx_protocol_core::{codec::CanonicalEncode,
        successor_bond_action_v2::SuccessorBondInboxMarkerV2,
        successor_bond_inbox_v2::SuccessorBondInboxEntryV2};
    if context.count == u128::MAX || context.previous_root == [0; 32]
        || context.sidechain_height == 0 || context.parent_height == 0
        || context.block_hash == [0; 32] || inclusion_blocks == 0
        || refund_minimum < inclusion_blocks {
        return Err(ScanError::Context);
    }
    context.parent_height.checked_add(u64::from(inclusion_blocks))
        .ok_or(ScanError::Context)?;
    // The push envelope is shared; the payload decoder enforces version 3
    // and its successor-specific signature/availability domains.
    let payload = located.finite_payload()?;
    let marker = SuccessorBondInboxMarkerV2::decode_payload(payload, 65536)
        .map_err(|_| ScanError::Authentication)?;
    if marker.chain_id != chain_id || marker.configuration_hash != configuration_hash {
        return Err(ScanError::Authentication);
    }
    marker.verify_wrapper_signature().map_err(|_| ScanError::Authentication)?;
    let entry = SuccessorBondInboxEntryV2 {
        version: SuccessorBondInboxEntryV2::VERSION, index: context.count,
        previous_root: context.previous_root, observed_sidechain_height: context.sidechain_height,
        observed_parent_height: context.parent_height, source_block_hash: context.block_hash,
        source_txid: facts.txid, source_wtxid: facts.wtxid,
        source_transaction_len: facts.transaction_len, source_witness_sha256: facts.witness_sha256,
        source_witness_len: facts.witness_len, source_tx_index: located.transaction_index,
        marker_vout: located.output_index, marker,
    };
    entry.validate(availability, 65536, refund_minimum).map_err(|_| ScanError::Authentication)?;
    let mut native = Vec::with_capacity(708);
    native.push(2);
    native.extend_from_slice(&context.count.to_be_bytes());
    native.extend_from_slice(&context.previous_root);
    native.extend_from_slice(&context.sidechain_height.to_be_bytes());
    native.extend_from_slice(&context.parent_height.to_be_bytes());
    native.extend_from_slice(&context.block_hash);
    native.extend_from_slice(&facts.txid);
    native.extend_from_slice(&facts.wtxid);
    native.extend_from_slice(&facts.transaction_len.to_be_bytes());
    native.extend_from_slice(&facts.witness_sha256);
    native.extend_from_slice(&facts.witness_len.to_be_bytes());
    native.extend_from_slice(&located.transaction_index.to_be_bytes());
    native.extend_from_slice(&located.output_index.to_be_bytes());
    native.extend_from_slice(&payload[4..]);
    if native.len() != 708 || native != entry.canonical_bytes() {
        return Err(ScanError::InconsistentSource);
    }
    Ok(entry)
}

/// Verify all finite source payloads before returning the resulting inbox
/// entries. The caller must authenticate the block/header/context and ordinary
/// transaction consensus first; this function does not turn supplied block
/// bytes into an authenticated child checkpoint.
pub fn verify_finite_block_sources(
    transactions: &[Transaction], context: &EntryContext,
    configuration: &ecx_protocol_core::configuration_v2::FrozenConfigurationV2,
    registry: &[ecx_witness_availability::CustodianPublic],
) -> Result<Vec<ecx_protocol_core::bond_inbox_v2::BondInboxEntryV2>, ScanError> {
    configuration.validate().map_err(|_| ScanError::Context)?;
    // Native predecessor checks apply even when the block has no ECXB output.
    // This is structural validation, not authentication of the supplied context.
    if context.previous_root == [0; 32] || context.sidechain_height == 0
        || context.parent_height == 0 || context.block_hash == [0; 32] {
        return Err(ScanError::Context);
    }
    let facts = block_source_facts(transactions)?;
    let markers = scan_markers(transactions, configuration.bond_inbox_max_entries_per_sidechain_block)?;
    if facts.len() != markers.len() { return Err(ScanError::InconsistentSource); }
    let mut next = EntryContext { count: context.count, previous_root: context.previous_root,
        sidechain_height: context.sidechain_height, parent_height: context.parent_height,
        block_hash: context.block_hash };
    let mut entries = Vec::with_capacity(markers.len());
    for (located, (index, facts)) in markers.iter().zip(&facts) {
        if located.transaction_index != *index { return Err(ScanError::InconsistentSource); }
        let tx = &transactions[*index as usize];
        verify_marker_envelope(tx, located.output_index,
            elements::AssetId::from_byte_array(configuration.base.policy_asset_id))?;
        let entry = validated_finite_entry(&next, located, facts,
            configuration.base.chain_id, configuration.digest(), configuration.base.availability,
            configuration.bond_inbox_inclusion_blocks, configuration.bond_inbox_refund_minimum_parent_blocks)?;
        verify_custody_source(tx, &entry.marker, configuration.base.availability, registry)?;
        let (bundle, receipts) = custody_annex(tx)?;
        ecx_elements_settlement::verify_bond_inbox_source_transaction_v2(
            &entry, &elements::encode::serialize(tx), bundle, &receipts, configuration,
        ).map_err(|_| ScanError::Authentication)?;
        next.previous_root = entry.next_root();
        next.count = next.count.checked_add(1).ok_or(ScanError::Limit)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Bind native source facts to the protocol entry and enforce its signature,
/// availability, non-staging authorization and parent-height constraints.
/// This is NOT source admission: custody signatures, staging covenants and
/// authenticated block membership must also be verified by the caller.
pub fn validated_finite_entry(
    context: &EntryContext, located: &LocatedMarker<'_>, facts: &SourceFacts,
    chain_id: [u8; 32], configuration_hash: [u8; 32],
    availability: ecx_protocol_core::availability::AvailabilityConfigV1,
    inclusion_blocks: u32, refund_minimum: u32,
) -> Result<ecx_protocol_core::bond_inbox_v2::BondInboxEntryV2, ScanError> {
    use ecx_protocol_core::{bond_inbox_v2::BondInboxEntryV2, codec::CanonicalEncode};
    let marker = located.verify_finite_wrapper(chain_id, configuration_hash, availability)?;
    verify_parent_deadlines(&marker, context.parent_height, inclusion_blocks, refund_minimum)?;
    let entry = BondInboxEntryV2 {
        version: 1, index: context.count, previous_root: context.previous_root,
        observed_sidechain_height: context.sidechain_height,
        observed_parent_height: context.parent_height, source_block_hash: context.block_hash,
        source_txid: facts.txid, source_wtxid: facts.wtxid,
        source_transaction_len: facts.transaction_len,
        source_witness_sha256: facts.witness_sha256, source_witness_len: facts.witness_len,
        source_tx_index: located.transaction_index, marker_vout: located.output_index, marker,
    };
    entry.validate(availability, 65536, refund_minimum).map_err(|_| ScanError::Authentication)?;
    // Independent native layout must agree before using protocol commitment roots.
    if entry.canonical_bytes().as_slice() != encode_finite_entry(context, located, facts)? {
        return Err(ScanError::InconsistentSource);
    }
    Ok(entry)
}

/// Native output-envelope gate. Policy asset must come from the authenticated
/// chain configuration, not from the transaction being checked.
pub fn verify_marker_envelope(tx: &Transaction, output_index: u32,
    policy_asset: elements::AssetId) -> Result<(), ScanError> {
    let output = tx.output.get(output_index as usize).ok_or(ScanError::Index)?;
    if output.asset != elements::confidential::Asset::Explicit(policy_asset)
        || output.value != elements::confidential::Value::Explicit(0)
        || output.nonce != elements::confidential::Nonce::Null
        || output.witness.surjection_proof.is_some()
        || output.witness.rangeproof.is_some() {
        return Err(ScanError::SourceForm);
    }
    Ok(())
}

/// Heights must be supplied by authenticated parent replay. This enforces the
/// native overflow/refund boundary; it does not authenticate that replay.
pub fn verify_parent_deadlines(marker: &ecx_protocol_core::bond_inbox_v2::BondInboxMarkerV2,
    parent_height: u64, inclusion_blocks: u32, refund_minimum: u32) -> Result<u64, ScanError> {
    use ecx_protocol_core::bond_inbox_v2::BondInboxActionKindV2;
    if parent_height == 0 || inclusion_blocks == 0 || refund_minimum < inclusion_blocks {
        return Err(ScanError::Context);
    }
    let deadline = parent_height.checked_add(u64::from(inclusion_blocks))
        .ok_or(ScanError::Context)?;
    if marker.kind == BondInboxActionKindV2::RedemptionEnqueue
        && marker.refund_not_before_parent_height < parent_height
            .checked_add(u64::from(refund_minimum)).ok_or(ScanError::Context)? {
        return Err(ScanError::Context);
    }
    Ok(deadline)
}

/// Extract the uniquely positioned native custody annex. Returned receipts
/// still require cryptographic verification against the frozen registry.
pub fn custody_annex(tx: &Transaction) -> Result<(&[u8], Vec<ecx_protocol_core::bond_inbox_v2::BondInboxCustodyReceiptV2>), ScanError> {
    let input = tx.input.first().ok_or(ScanError::SourceForm)?;
    let witness = &input.witness;
    if !input.script_sig.is_empty() || witness.amount_rangeproof.is_some()
        || witness.inflation_keys_rangeproof.is_some() || !witness.pegin_witness.is_empty()
        || witness.script_witness.len() != 2 || witness.script_witness[0].len() != 64
        || tx.input.iter().skip(1).any(|i| i.witness.script_witness.last()
            .is_some_and(|last| last.first() == Some(&0x50))) {
        return Err(ScanError::SourceForm);
    }
    let annex = &witness.script_witness[1];
    if annex.len() < 15 || &annex[..10] != b"\x50ECXBIN2\0\x01" {
        return Err(ScanError::SourceForm);
    }
    let length = u32::from_be_bytes(annex[10..14].try_into().unwrap()) as usize;
    let count = annex[14] as usize;
    if length == 0 || length > 65536 || !(3..=5).contains(&count) {
        return Err(ScanError::SourceForm);
    }
    let bundle = annex.get(15..15 + length).ok_or(ScanError::SourceForm)?;
    let mut cursor = 15 + length;
    let mut previous = 0;
    let mut receipts = Vec::with_capacity(count);
    for _ in 0..count {
        if annex.get(cursor..cursor + 2) != Some(&[0, 138][..]) {
            return Err(ScanError::SourceForm);
        }
        cursor += 2;
        let receipt = annex.get(cursor..cursor + 138).ok_or(ScanError::SourceForm)?;
        cursor += 138;
        if receipt[0] != 1 || receipt[73] <= previous || receipt[73] > 5 {
            return Err(ScanError::SourceForm);
        }
        previous = receipt[73];
        receipts.push(ecx_protocol_core::bond_inbox_v2::BondInboxCustodyReceiptV2 {
            custodian_index: previous - 1, exact_receipt_bytes: receipt.to_vec(),
        });
    }
    if cursor != annex.len() { return Err(ScanError::SourceForm); }
    Ok((bundle, receipts))
}

/// Check exact annex commitments AND actual Ed25519 custody signatures.
/// The transaction's ordinary key-path spend must separately pass consensus
/// script verification; this function does not authenticate that spend.
pub fn verify_custody_source(
    tx: &Transaction,
    marker: &ecx_protocol_core::bond_inbox_v2::BondInboxMarkerV2,
    availability: ecx_protocol_core::availability::AvailabilityConfigV1,
    registry: &[ecx_witness_availability::CustodianPublic],
) -> Result<(), ScanError> {
    let (bytes, receipts) = custody_annex(tx)?;
    ecx_protocol_core::bond_inbox_v2::verify_bond_inbox_source_witness_commitments_v2(
        marker, availability, bytes, &receipts,
    ).map_err(|_| ScanError::Authentication)?;
    verify_custody_signatures(bytes, &receipts, availability, registry)
}

fn verify_custody_signatures(
    bytes: &[u8], receipts: &[ecx_protocol_core::bond_inbox_v2::BondInboxCustodyReceiptV2],
    availability: ecx_protocol_core::availability::AvailabilityConfigV1,
    registry: &[ecx_witness_availability::CustodianPublic],
) -> Result<(), ScanError> {
    use ecx_witness_availability::{WitnessBundle, CustodyReceiptV1,
        custodian_registry_hash, verify_custody_receipts};
    if custodian_registry_hash(registry).map_err(|_| ScanError::Authentication)?
        != availability.custodian_registry_hash {
        return Err(ScanError::Authentication);
    }
    let bundle = WitnessBundle::decode(bytes).map_err(|_| ScanError::Authentication)?;
    let embedded = bundle.custodians.iter().map(|c| c.public).collect::<Vec<_>>();
    if embedded != registry { return Err(ScanError::Authentication); }
    let receipts = receipts.iter().map(|r| CustodyReceiptV1::decode_canonical(&r.exact_receipt_bytes))
        .collect::<Result<Vec<_>, _>>().map_err(|_| ScanError::Authentication)?;
    verify_custody_receipts(&bundle, &receipts).map_err(|_| ScanError::Authentication)
}

/// Admit every successor source in consensus order, including real custody
/// signatures and staging covenant checks. Block and input authentication must
/// already have succeeded. No partial result is returned on a failed source.
pub fn verify_successor_block_sources(
    transactions: &[Transaction], context: &SuccessorEntryContext,
    configuration: &ecx_protocol_core::configuration_v2::FrozenConfigurationV2,
    registry: &[ecx_witness_availability::CustodianPublic],
) -> Result<Vec<ecx_protocol_core::successor_bond_inbox_v2::SuccessorBondInboxEntryV2>, ScanError> {
    configuration.validate().map_err(|_| ScanError::Context)?;
    if context.previous_root == [0; 32] || context.sidechain_height == 0
        || context.parent_height == 0 || context.block_hash == [0; 32] {
        return Err(ScanError::Context);
    }
    let facts = block_source_facts(transactions)?;
    let markers = scan_markers(transactions, configuration.bond_inbox_max_entries_per_sidechain_block)?;
    if facts.len() != markers.len() { return Err(ScanError::InconsistentSource); }
    let mut next = context.clone();
    let mut entries = Vec::with_capacity(markers.len());
    for (located, (index, facts)) in markers.iter().zip(&facts) {
        if located.transaction_index != *index { return Err(ScanError::InconsistentSource); }
        let tx = &transactions[*index as usize];
        verify_marker_envelope(tx, located.output_index,
            elements::AssetId::from_byte_array(configuration.base.policy_asset_id))?;
        let entry = validated_successor_entry(&next, located, facts,
            configuration.base.chain_id, configuration.digest(), configuration.base.availability,
            configuration.bond_inbox_inclusion_blocks, configuration.bond_inbox_refund_minimum_parent_blocks)?;
        let (bundle, receipts) = custody_annex(tx)?;
        ecx_protocol_core::successor_bond_inbox_v2::verify_successor_bond_inbox_source_witness_commitments_v2(
            &entry.marker, configuration.base.availability, bundle, &receipts,
        ).map_err(|_| ScanError::Authentication)?;
        verify_custody_signatures(bundle, &receipts, configuration.base.availability, registry)?;
        ecx_elements_settlement::verify_successor_bond_inbox_source_transaction_v2(
            &entry, &elements::encode::serialize(tx), bundle, &receipts, configuration,
        ).map_err(|_| ScanError::Authentication)?;
        next.previous_root = entry.next_root();
        next.count = next.count.checked_add(1).ok_or(ScanError::Limit)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Collect native wire-order source facts and enforce the deduplicated block
/// caps. These facts are NOT a receipt of marker/custody/signature validity.
pub fn block_source_facts(transactions: &[Transaction])
    -> Result<Vec<(u32, SourceFacts)>, ScanError> {
    let markers = scan_markers(transactions, 8)?;
    let mut unique = BTreeMap::new();
    let mut transaction_total = 0u32;
    let mut witness_total = 0u32;
    let mut result = Vec::new();
    for marker in markers {
        marker.finite_payload()?;
        let tx = &transactions[marker.transaction_index as usize];
        let (transaction, witness) = source_bytes(tx)?;
        let facts = SourceFacts {
            txid: tx.txid().to_byte_array(),
            wtxid: tx.wtxid().to_byte_array(),
            transaction_len: u32::try_from(transaction.len()).map_err(|_| ScanError::Limit)?,
            witness_sha256: sha256::Hash::hash(&witness).to_byte_array(),
            witness_len: u32::try_from(witness.len()).map_err(|_| ScanError::Limit)?,
        };
        if let Some(previous) = unique.get(&facts.wtxid) {
            if previous != &facts { return Err(ScanError::InconsistentSource); }
        } else {
            transaction_total = transaction_total.checked_add(facts.transaction_len).ok_or(ScanError::Limit)?;
            witness_total = witness_total.checked_add(facts.witness_len).ok_or(ScanError::Limit)?;
            if transaction_total > 768 * 1024 || witness_total > 576 * 1024 {
                return Err(ScanError::Limit);
            }
            unique.insert(facts.wtxid, facts.clone());
        }
        result.push((marker.transaction_index, facts));
    }
    Ok(result)
}

/// Exact source bytes for the native per-block byte limits and commitments.
/// This checks only source shape, not marker signatures or source authorization.
/// Witness encoding follows CTxWitness: input witnesses then output witnesses,
/// without vector counts around either collection. Output proofs are retained.
pub fn source_bytes(tx: &Transaction) -> Result<(Vec<u8>, Vec<u8>), ScanError> {
    if tx.is_coinbase() || tx.input.is_empty() || tx.output.is_empty()
        || !tx.has_witness() || tx.input.iter().any(|i| i.is_pegin || i.has_issuance()) {
        return Err(ScanError::SourceForm);
    }
    let transaction = elements::encode::serialize(tx);
    let mut witness = Vec::new();
    for input in &tx.input { witness.extend(elements::encode::serialize(&input.witness)); }
    for output in &tx.output { witness.extend(elements::encode::serialize(&output.witness)); }
    // Native frozen relay-profile limits, not a configurable relaxation.
    if transaction.len() > 768 * 1024 || witness.len() > 576 * 1024 {
        return Err(ScanError::Limit);
    }
    Ok((transaction, witness))
}

#[derive(Debug)]
pub struct LocatedMarker<'a> {
    pub transaction_index: u32,
    pub output_index: u32,
    pub script: &'a [u8],
}

fn contains_magic(script: &[u8]) -> bool {
    script.first() == Some(&0x6a) && script[1..].windows(4).any(|w| w == b"ECXB")
}

/// Every output is inspected in consensus order. The native source rule allows
/// exactly one marker per source transaction. The caller must independently
/// pin the limit and authenticate the entire transaction list to the block.
pub fn scan_markers(transactions: &[Transaction], maximum: u32)
    -> Result<Vec<LocatedMarker<'_>>, ScanError> {
    let mut found = Vec::new();
    for (tx_index, tx) in transactions.iter().enumerate() {
        let mut in_transaction = false;
        for (output_index, output) in tx.output.iter().enumerate() {
            let script = output.script_pubkey.as_bytes();
            if !contains_magic(script) { continue; }
            if in_transaction { return Err(ScanError::MultipleMarkers); }
            if found.len() >= maximum as usize { return Err(ScanError::Limit); }
            found.push(LocatedMarker {
                transaction_index: u32::try_from(tx_index).map_err(|_| ScanError::Index)?,
                output_index: u32::try_from(output_index).map_err(|_| ScanError::Index)?, script,
            });
            in_transaction = true;
        }
        // Native source validation parses every OP_RETURN as a canonical
        // marker, then requires exactly one marker. Do not skip unrelated
        // OP_RETURN outputs once this transaction is an inbox source.
        if in_transaction && tx.output.iter()
            .filter(|output| output.script_pubkey.as_bytes().first() == Some(&0x6a))
            .count() != 1 {
            return Err(ScanError::ExtraReturnOutput);
        }
    }
    Ok(found)
}

impl LocatedMarker<'_> {
    /// Verify the wrapper and frozen public identities using the shared
    /// protocol codec. Availability claims are not actual custody receipts:
    /// source witness/custody and staging authorization still need verification.
    pub fn verify_finite_wrapper(
        &self, chain_id: [u8; 32], configuration_hash: [u8; 32],
        availability: ecx_protocol_core::availability::AvailabilityConfigV1,
    ) -> Result<ecx_protocol_core::bond_inbox_v2::BondInboxMarkerV2, ScanError> {
        let marker = ecx_protocol_core::bond_inbox_v2::BondInboxMarkerV2::decode_payload(
            self.finite_payload()?, 64 * 1024,
        ).map_err(|_| ScanError::Authentication)?;
        if marker.chain_id != chain_id || marker.configuration_hash != configuration_hash {
            return Err(ScanError::Authentication);
        }
        marker.verify_availability_claim(availability, 64 * 1024)
            .map_err(|_| ScanError::Authentication)?;
        marker.verify_wrapper_signature().map_err(|_| ScanError::Authentication)?;
        Ok(marker)
    }

    /// Finite profile only: exact OP_RETURN OP_PUSHDATA2, 503-byte payload,
    /// ECXB magic, no trailing bytes. Incremental markers need their own codec.
    pub fn finite_payload(&self) -> Result<&[u8], ScanError> {
        if self.script.len() != 507 || self.script[..4] != [0x6a, 0x4d, 0xf7, 0x01]
            || &self.script[4..8] != b"ECXB" {
            return Err(ScanError::NonCanonicalFiniteMarker);
        }
        Ok(&self.script[4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_empty_genesis_preserves_alpha_initial_state_and_bindings() {
        use ecx_protocol_core::genesis_v2::derive_empty_genesis_v2;
        let configuration = test_configuration::configuration();
        let state = derive_empty_genesis_v2(&configuration, 80, 1_000_000, 3_000_000_000, [19; 32]).unwrap();
        assert_eq!(state.base.sequence, 0);
        assert_eq!(state.base.last_processed_height, 80);
        assert_eq!(state.last_transition_sidechain_height, 80);
        assert_eq!(state.base.mark_price, ecx_protocol_core::Price::new(3_000_000_000).unwrap());
        assert_eq!(state.bond.outstanding_share_atoms, 0);
        assert_eq!(state.bond.inventory_share_atoms, ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS);
        assert_eq!(state.bond_inbox.head_root, state.bond_inbox.processed_root);
        assert_eq!(state.bond_inbox_outcome_count, 0);
        let root = state.state_root();
        for (height, time, price, order_root) in [
            (81, 1_000_000, 3_000_000_000, [19; 32]),
            (80, 1_000_001, 3_000_000_000, [19; 32]),
            (80, 1_000_000, 3_000_000_001, [19; 32]),
            (80, 1_000_000, 3_000_000_000, [20; 32]),
        ] {
            assert_ne!(root, derive_empty_genesis_v2(&configuration, height, time, price, order_root).unwrap().state_root());
        }
        for (height, time, price, order_root) in [
            (0, 1_000_000, 3_000_000_000, [19; 32]),
            (80, 0, 3_000_000_000, [19; 32]),
            (80, 1_000_000, 0, [19; 32]),
            (80, 1_000_000, 3_000_000_000, [0; 32]),
        ] {
            assert!(derive_empty_genesis_v2(&configuration, height, time, price, order_root).is_err());
        }
    }

    fn tx(scripts: Vec<Vec<u8>>) -> Transaction {
        Transaction { version: 2, lock_time: elements::LockTime::ZERO, input: vec![],
            output: scripts.into_iter().map(|script| elements::TxOut {
                script_pubkey: elements::Script::from(script), ..Default::default()
            }).collect() }
    }
    fn marker() -> Vec<u8> {
        let mut bytes = vec![0x6a, 0x4d, 0xf7, 0x01];
        bytes.extend_from_slice(b"ECXB"); bytes.resize(507, 0); bytes
    }
    #[test]
    fn exact_native_discovery_includes_malformed_magic() {
        let transactions = vec![tx(vec![vec![0x51], marker()]), tx(vec![vec![0x6a, 0xff, b'E', b'C', b'X', b'B']])];
        let found = scan_markers(&transactions, 2).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!((found[0].transaction_index, found[0].output_index), (0, 1));
        assert_eq!(found[0].finite_payload().unwrap().len(), 503);
        assert!(found[1].finite_payload().is_err());
        assert!(scan_markers(&transactions, 1).is_err());
        assert!(scan_markers(&[tx(vec![marker(), marker()])], 2).is_err());
        assert!(scan_markers(&[tx(vec![b"ECXB".to_vec()])], 0).unwrap().is_empty());
        let mut trailing = marker(); trailing.push(0);
        let transactions = [tx(vec![trailing])];
        assert!(scan_markers(&transactions, 1).unwrap()[0].finite_payload().is_err());
    }

    #[test]
    fn source_rejects_unrelated_return_outputs_in_either_order() {
        for scripts in [vec![marker(), vec![0x6a]], vec![vec![0x6a, 0x01, 0x00], marker()]] {
            assert_eq!(scan_markers(&[tx(scripts)], 8).unwrap_err(), ScanError::ExtraReturnOutput);
        }
        // Transactions with no ECXB marker are outside inbox-source validation.
        assert!(scan_markers(&[tx(vec![vec![0x6a], vec![0x6a, 0x00]])], 0).unwrap().is_empty());
    }

    #[test]
    fn source_witness_has_no_outer_vector_counts() {
        let mut transaction = tx(vec![marker()]);
        assert_eq!(source_bytes(&transaction).unwrap_err(), ScanError::SourceForm);
        let mut input = elements::TxIn::default();
        input.previous_output.vout = 0;
        transaction.input.push(input);
        assert_eq!(source_bytes(&transaction).unwrap_err(), ScanError::SourceForm);
        transaction.input[0].witness.script_witness = vec![vec![0xab, 0xcd]];
        let (bytes, witness) = source_bytes(&transaction).unwrap();
        // issuance proofs, script stack, pegin stack, then two output proofs.
        assert_eq!(witness, vec![0, 0, 1, 2, 0xab, 0xcd, 0, 0, 0]);
        assert!(bytes.ends_with(&witness));
        transaction.input[0].is_pegin = true;
        assert_eq!(source_bytes(&transaction).unwrap_err(), ScanError::SourceForm);
    }

    #[test]
    fn block_caps_deduplicate_sources_but_keep_occurrences() {
        let mut transaction = tx(vec![marker()]);
        let mut input = elements::TxIn::default();
        input.previous_output.vout = 0;
        input.witness.script_witness = vec![vec![0xab; 300 * 1024]];
        transaction.input.push(input);
        let repeated = block_source_facts(&[transaction.clone(), transaction.clone()]).unwrap();
        assert_eq!(repeated.len(), 2);
        assert_eq!(repeated[0].1, repeated[1].1);
        assert_eq!(repeated[1].0, 1);
        let mut different = transaction.clone();
        different.input[0].witness.script_witness[0][0] ^= 1;
        assert_eq!(block_source_facts(&[transaction, different]).unwrap_err(), ScanError::Limit);
    }

    #[test]
    fn finite_entry_matches_native_field_offsets() {
        let script = marker();
        let marker = LocatedMarker { transaction_index: 7, output_index: 9, script: &script };
        let mut context = EntryContext { count: 12, previous_root: [1; 32],
            sidechain_height: 13, parent_height: 14, block_hash: [2; 32] };
        let facts = SourceFacts { txid: [3; 32], wtxid: [4; 32], transaction_len: 701,
            witness_sha256: [5; 32], witness_len: 60 };
        let encoded = encode_finite_entry(&context, &marker, &facts).unwrap();
        let mut expected = vec![1];
        expected.extend_from_slice(&12u64.to_be_bytes());
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&13u64.to_be_bytes());
        expected.extend_from_slice(&14u64.to_be_bytes());
        for byte in [2, 3, 4] { expected.extend_from_slice(&[byte; 32]); }
        expected.extend_from_slice(&701u32.to_be_bytes());
        expected.extend_from_slice(&[5; 32]);
        for n in [60u32, 7, 9] { expected.extend_from_slice(&n.to_be_bytes()); }
        assert_eq!(expected.len(), 201);
        expected.extend_from_slice(&script[8..]);
        assert_eq!(encoded.as_slice(), expected);
        context.count = u64::MAX;
        assert_eq!(encode_finite_entry(&context, &marker, &facts), Err(ScanError::Context));
    }

    fn signed_marker_fixture() -> (ecx_protocol_core::bond_inbox_v2::BondInboxMarkerV2,
        ecx_protocol_core::availability::AvailabilityConfigV1) {
        use ecx_protocol_core::{bond_inbox_v2::{BondInboxMarkerV2, BondInboxActionKindV2},
            availability::AvailabilityConfigV1, Signature64, types::XOnlyKey};
        use bitcoin::secp256k1::{SecretKey, Secp256k1, Keypair, XOnlyPublicKey};
        let key = SecretKey::from_slice(&[11; 32]).unwrap(); // Synthetic test key only.
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &key);
        let signer = XOnlyPublicKey::from_keypair(&pair).0.serialize();
        let availability = AvailabilityConfigV1 { version: 1, scheme_hash: [3; 32],
            custodian_registry_hash: [4; 32], recovery_threshold: 3, custodian_count: 5,
            maximum_witness_bytes: 16 * 1024 * 1024 };
        let mut value = BondInboxMarkerV2 { version: 1, kind: BondInboxActionKindV2::Subscription,
            chain_id: [1; 32], configuration_hash: [2; 32], signer: XOnlyKey(signer),
            action_id: [5; 32], staging_intent_id: [0; 32], staging_vout: u32::MAX,
            refund_script_sha256: [0; 32], refund_not_before_parent_height: 0,
            payload_commitment: [6; 32], availability_scheme_hash: [3; 32],
            availability_custodian_registry_hash: [4; 32], availability_bundle_root: [7; 32],
            availability_context: [0; 32], availability_receipt_root: [8; 32],
            availability_bundle_len: 1000, availability_receipt_bitmap: 7,
            source_authorization_commitment: [9; 32], signature: Signature64([0; 64]) };
        value.availability_context = value.expected_availability_context();
        value = value.sign(&key).unwrap();
        (value, availability)
    }

    #[test]
    fn native_parent_deadlines_reject_overflow_and_early_refund() {
        let (mut value, _) = signed_marker_fixture();
        assert_eq!(verify_parent_deadlines(&value, 100, 6, 12), Ok(106));
        assert_eq!(verify_parent_deadlines(&value, u64::MAX - 5, 6, 12), Err(ScanError::Context));
        value.kind = ecx_protocol_core::bond_inbox_v2::BondInboxActionKindV2::RedemptionEnqueue;
        value.refund_not_before_parent_height = 112;
        assert_eq!(verify_parent_deadlines(&value, 100, 6, 12), Ok(106));
        value.refund_not_before_parent_height = 111;
        assert_eq!(verify_parent_deadlines(&value, 100, 6, 12), Err(ScanError::Context));
        value.refund_not_before_parent_height = u64::MAX;
        assert_eq!(verify_parent_deadlines(&value, u64::MAX - 6, 6, 12), Err(ScanError::Context));
    }

    #[test]
    fn successor_entry_retains_wide_counter_and_rejects_finite_wrapper() {
        use ecx_protocol_core::{codec::CanonicalEncode,
            successor_bond_action_v2::SuccessorBondInboxMarkerV2,
            successor_bond_inbox_v2::successor_bond_inbox_no_staging_source_authorization_commitment_v2};
        let (finite, availability) = signed_marker_fixture();
        // Synthetic fixture only; recompute every domain-bound value and sign
        // with the test key. No historical receipt is converted or relabelled.
        let mut json = serde_json::to_value(finite).unwrap();
        json["version"] = serde_json::json!(SuccessorBondInboxMarkerV2::VERSION);
        let mut successor: SuccessorBondInboxMarkerV2 = serde_json::from_value(json).unwrap();
        successor.source_authorization_commitment =
            successor_bond_inbox_no_staging_source_authorization_commitment_v2(
                successor.chain_id, successor.configuration_hash, successor.signer,
                successor.action_id, 9).unwrap();
        successor.availability_context = successor.expected_availability_context();
        successor = successor.sign(&bitcoin::secp256k1::SecretKey::from_slice(&[11; 32]).unwrap()).unwrap();
        let mut script = vec![0x6a, 0x4d, 0xf7, 0x01];
        script.extend(successor.payload_bytes(65536).unwrap());
        let located = LocatedMarker { transaction_index: 7, output_index: 9, script: &script };
        let mut context = SuccessorEntryContext { count: u64::MAX as u128 + 42,
            previous_root: [1; 32], sidechain_height: 13, parent_height: 14, block_hash: [2; 32] };
        let facts = SourceFacts { txid: [3; 32], wtxid: [4; 32], transaction_len: 900,
            witness_sha256: [5; 32], witness_len: 60 };
        let validate = |context: &SuccessorEntryContext, located: &LocatedMarker<'_>| {
            validated_successor_entry(context, located, &facts, [1; 32], [2; 32], availability, 6, 12)
        };
        let entry = validate(&context, &located).unwrap();
        let bytes = entry.canonical_bytes();
        assert_eq!(bytes.len(), 708);
        assert_eq!(&bytes[1..17], &context.count.to_be_bytes());
        assert_eq!(entry.index, context.count);
        assert!(located.verify_finite_wrapper([1; 32], [2; 32], availability).is_err());
        let mut finite_script = vec![0x6a, 0x4d, 0xf7, 0x01];
        finite_script.extend(finite.payload_bytes(65536).unwrap());
        assert!(validate(&context, &LocatedMarker { script: &finite_script, ..located }).is_err());
        context.count += 1;
        assert_ne!(entry.next_root(), validate(&context, &located).unwrap().next_root());
        context.count = u128::MAX;
        assert_eq!(validate(&context, &located), Err(ScanError::Context));
        context.count = 0;
        context.parent_height = u64::MAX - 5;
        assert_eq!(validate(&context, &located), Err(ScanError::Context));
    }

    #[test]
    fn marker_envelope_requires_zero_policy_asset_output() {
        let mut transaction = tx(vec![marker()]);
        let asset = elements::AssetId::from_byte_array([42; 32]);
        transaction.output[0].asset = elements::confidential::Asset::Explicit(asset);
        transaction.output[0].value = elements::confidential::Value::Explicit(0);
        assert_eq!(verify_marker_envelope(&transaction, 0, asset), Ok(()));
        assert_eq!(verify_marker_envelope(&transaction, 1, asset), Err(ScanError::Index));
        assert_eq!(verify_marker_envelope(&transaction, 0, elements::AssetId::from_byte_array([43; 32])), Err(ScanError::SourceForm));
        transaction.output[0].value = elements::confidential::Value::Explicit(1);
        assert_eq!(verify_marker_envelope(&transaction, 0, asset), Err(ScanError::SourceForm));
    }

    #[test]
    fn finite_entry_binds_authorization_to_output_locator() {
        use ecx_protocol_core::bond_inbox_v2::bond_inbox_no_staging_source_authorization_commitment_v2;
        let (mut value, availability) = signed_marker_fixture();
        value.source_authorization_commitment = bond_inbox_no_staging_source_authorization_commitment_v2(
            value.chain_id, value.configuration_hash, value.signer, value.action_id, 0).unwrap();
        value.availability_context = value.expected_availability_context();
        value = value.sign(&bitcoin::secp256k1::SecretKey::from_slice(&[11; 32]).unwrap()).unwrap();
        let mut script = vec![0x6a, 0x4d, 0xf7, 0x01];
        script.extend(value.payload_bytes(65536).unwrap());
        let mut located = LocatedMarker { transaction_index: 0, output_index: 0, script: &script };
        let context = EntryContext { count: 0, previous_root: [12; 32], sidechain_height: 1,
            parent_height: 100, block_hash: [13; 32] };
        let facts = SourceFacts { txid: [14; 32], wtxid: [15; 32], transaction_len: 1000,
            witness_sha256: [16; 32], witness_len: 100 };
        let entry = validated_finite_entry(&context, &located, &facts, [1; 32], [2; 32], availability, 6, 12).unwrap();
        assert_eq!(entry.deadline(6).unwrap(), 106);
        located.output_index = 1;
        assert!(validated_finite_entry(&context, &located, &facts, [1; 32], [2; 32], availability, 6, 12).is_err());
    }

    #[test]
    fn signed_wrapper_rejects_wrong_bindings_and_signature() {
        let (value, availability) = signed_marker_fixture();
        let mut script = vec![0x6a, 0x4d, 0xf7, 0x01];
        script.extend(value.payload_bytes(65536).unwrap());
        let located = LocatedMarker { transaction_index: 0, output_index: 0, script: &script };
        assert!(located.verify_finite_wrapper([1; 32], [2; 32], availability).is_ok());
        assert!(located.verify_finite_wrapper([10; 32], [2; 32], availability).is_err());
        assert!(located.verify_finite_wrapper([1; 32], [10; 32], availability).is_err());
        let mut wrong_registry = availability;
        wrong_registry.custodian_registry_hash = [10; 32];
        assert!(located.verify_finite_wrapper([1; 32], [2; 32], wrong_registry).is_err());
        script[506] ^= 1;
        let altered = LocatedMarker { transaction_index: 0, output_index: 0, script: &script };
        assert!(altered.verify_finite_wrapper([1; 32], [2; 32], availability).is_err());
    }

    #[test]
    fn custody_annex_requires_exact_eof_and_unique_placement() {
        let mut annex = b"\x50ECXBIN2\0\x01".to_vec();
        annex.extend_from_slice(&1u32.to_be_bytes());
        annex.extend_from_slice(&[3, 0xab]);
        for index in 1..=3 {
            annex.extend_from_slice(&[0, 138]);
            let mut receipt = vec![0; 138]; receipt[0] = 1; receipt[73] = index;
            annex.extend(receipt);
        }
        let mut transaction = tx(vec![marker()]);
        let mut input = elements::TxIn::default();
        input.witness.script_witness = vec![vec![0; 64], annex.clone()];
        transaction.input.push(input);
        let (bundle, receipts) = custody_annex(&transaction).unwrap();
        assert_eq!(bundle, &[0xab]);
        assert_eq!(receipts.iter().map(|r| r.custodian_index).collect::<Vec<_>>(), vec![0, 1, 2]);
        for length in 0..annex.len() {
            transaction.input[0].witness.script_witness[1] = annex[..length].to_vec();
            assert!(custody_annex(&transaction).is_err());
        }
        transaction.input[0].witness.script_witness[1] = annex.clone();
        transaction.input[0].witness.script_witness[1].push(0);
        assert!(custody_annex(&transaction).is_err());
        transaction.input[0].witness.script_witness[1] = annex;
        transaction.input.push(transaction.input[0].clone());
        assert!(custody_annex(&transaction).is_err());
    }

    #[test]
    fn combined_source_admission_checks_real_signatures_and_root_continuity() {
        use ecx_witness_availability::{CustodianSecrets, create_bundle, custodian_registry_hash};
        use ecx_protocol_core::bond_inbox_v2::{BondInboxCustodyReceiptV2,
            bond_inbox_availability_bundle_root_v2, canonical_bond_inbox_custody_receipts_v2,
            bond_inbox_no_staging_source_authorization_commitment_v2};
        let secrets = (1..=5).map(|i| CustodianSecrets::generate(i).unwrap()).collect::<Vec<_>>();
        let registry = secrets.iter().map(|s| s.public()).collect::<Vec<_>>();
        let mut configuration = test_configuration::configuration();
        configuration.base.availability.custodian_registry_hash = custodian_registry_hash(&registry).unwrap();
        let make_source = |action: u8, corrupt_receipt: bool| {
            let (mut marker, _) = signed_marker_fixture();
            marker.chain_id = configuration.base.chain_id;
            marker.configuration_hash = configuration.digest();
            marker.action_id = [action; 32];
            marker.availability_scheme_hash = configuration.base.availability.scheme_hash;
            marker.availability_custodian_registry_hash = configuration.base.availability.custodian_registry_hash;
            marker.source_authorization_commitment = bond_inbox_no_staging_source_authorization_commitment_v2(
                marker.chain_id, marker.configuration_hash, marker.signer, marker.action_id, 0).unwrap();
            marker.availability_context = marker.expected_availability_context();
            let bundle = create_bundle(marker.availability_context, b"synthetic combined admission", &registry).unwrap();
            let bytes = bundle.encode().unwrap();
            marker.availability_bundle_len = bytes.len() as u32;
            marker.availability_bundle_root = bond_inbox_availability_bundle_root_v2(&bytes).unwrap();
            let mut receipts = secrets[..3].iter().enumerate().map(|(i, s)| BondInboxCustodyReceiptV2 {
                custodian_index: i as u8,
                exact_receipt_bytes: s.custody_receipt(&bundle).unwrap().encode_canonical().unwrap().to_vec(),
            }).collect::<Vec<_>>();
            if corrupt_receipt { receipts[0].exact_receipt_bytes[137] ^= 1; }
            (marker.availability_receipt_root, marker.availability_receipt_bitmap) =
                canonical_bond_inbox_custody_receipts_v2(&marker, &receipts).unwrap();
            marker = marker.sign(&bitcoin::secp256k1::SecretKey::from_slice(&[11; 32]).unwrap()).unwrap();
            let mut script = vec![0x6a, 0x4d, 0xf7, 0x01];
            script.extend(marker.payload_bytes(65536).unwrap());
            let mut transaction = tx(vec![script]);
            transaction.output[0].asset = elements::confidential::Asset::Explicit(
                elements::AssetId::from_byte_array(configuration.base.policy_asset_id));
            transaction.output[0].value = elements::confidential::Value::Explicit(0);
            let mut input = elements::TxIn::default();
            input.previous_output = elements::OutPoint::new(elements::Txid::from_byte_array([action; 32]), 0);
            // Input signature is intentionally not a consensus fixture: this helper
            // authenticates source admission after ordinary transaction validation.
            input.witness.script_witness = vec![vec![0; 64],
                ecx_elements_settlement::bond_inbox_source_annex_v2(&bytes, &receipts).unwrap()];
            transaction.input.push(input);
            transaction
        };
        let context = EntryContext { count: 7, previous_root: [12; 32],
            sidechain_height: 10, parent_height: 100, block_hash: [13; 32] };
        assert!(verify_finite_block_sources(&[], &context, &configuration, &registry).unwrap().is_empty());
        for field in 0..4 {
            let mut invalid = EntryContext { count: context.count,
                previous_root: context.previous_root, sidechain_height: context.sidechain_height,
                parent_height: context.parent_height, block_hash: context.block_hash };
            match field {
                0 => invalid.previous_root = [0; 32],
                1 => invalid.sidechain_height = 0,
                2 => invalid.parent_height = 0,
                _ => invalid.block_hash = [0; 32],
            }
            assert_eq!(verify_finite_block_sources(&[], &invalid, &configuration, &registry),
                Err(ScanError::Context));
        }
        let transactions = vec![make_source(21, false), make_source(22, false)];
        let entries = verify_finite_block_sources(&transactions, &context, &configuration, &registry).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index, 7);
        assert_eq!(entries[1].index, 8);
        assert_eq!(entries[1].previous_root, entries[0].next_root());
        assert_eq!(entries[1].source_tx_index, 1);
        // Project the verified source scan into the next evaluator checkpoint.
        // These synthetic capital identities are not a genesis proof fixture.
        let projection = crate::child_execution_state_v4::CapitalProjectionV4 {
            proof_profile: 0, exchange_state_root: [1; 32],
            configuration_hash: configuration.digest(), asset_id: [2; 32],
            deployment_commitment: [3; 32], transition_program_id: [4; 32],
            transition_cmr: [5; 32], covenant_state_hash: [6; 32],
            covenant_inbox_root: [7; 32], covenant_inbox_count: 5,
            node_inbox_root: context.previous_root, node_inbox_count: 7,
        };
        let append = |p: &crate::child_execution_state_v4::CapitalProjectionV4, txs: &[Transaction]| {
            p.append_finite_block_sources(txs, context.sidechain_height, context.parent_height,
                context.block_hash, &configuration, &registry)
        };
        let next = append(&projection, &transactions).unwrap();
        let mut expected = projection.clone();
        expected.node_inbox_count = 9;
        expected.node_inbox_root = entries[1].next_root();
        assert_eq!(next, expected);
        assert_eq!(append(&projection, &[]).unwrap(), projection);
        assert!(append(&projection, &[make_source(23, true)]).is_err());
        assert_eq!(projection.node_inbox_count, 7); // Failure cannot partially mutate state.
        let mut changed = projection.clone();
        changed.proof_profile = 1;
        assert!(append(&changed, &[]).is_err());
        changed = projection.clone(); changed.configuration_hash[0] ^= 1;
        assert!(append(&changed, &[]).is_err());
        changed = projection.clone(); changed.node_inbox_count = u64::MAX as u128;
        assert!(append(&changed, &transactions).is_err());
        assert!(projection.append_finite_block_sources(&[], 0, context.parent_height,
            context.block_hash, &configuration, &registry).is_err());
        let mut wrong_configuration = configuration.clone();
        wrong_configuration.base.chain_id[0] ^= 1;
        assert!(verify_finite_block_sources(&transactions, &context, &wrong_configuration, &registry).is_err());
        assert!(verify_finite_block_sources(&transactions, &context, &configuration, &registry[..3]).is_err());
        // All outer commitments and the wrapper signature have been recomputed;
        // rejection must still occur for the invalid custodian signature.
        assert!(verify_finite_block_sources(&[make_source(23, true)], &context, &configuration, &registry).is_err());
    }

    #[test]
    fn successor_source_admission_checks_real_signatures_and_wide_continuity() {
        use ecx_witness_availability::{CustodianSecrets, create_bundle, custodian_registry_hash};
        use ecx_protocol_core::bond_inbox_v2::BondInboxCustodyReceiptV2;
        use ecx_protocol_core::successor_bond_inbox_v2::{
            successor_bond_inbox_availability_bundle_root_v2, canonical_successor_bond_inbox_custody_receipts_v2,
            successor_bond_inbox_no_staging_source_authorization_commitment_v2};
        let secrets = (1..=5).map(|i| CustodianSecrets::generate(i).unwrap()).collect::<Vec<_>>();
        let registry = secrets.iter().map(|s| s.public()).collect::<Vec<_>>();
        let mut configuration = test_configuration::configuration();
        configuration.base.availability.custodian_registry_hash = custodian_registry_hash(&registry).unwrap();
        let make_source = |action: u8, corrupt_receipt: bool| {
            let (finite, _) = signed_marker_fixture();
            let mut json = serde_json::to_value(finite).unwrap();
            json["version"] = serde_json::json!(3);
            let mut marker: ecx_protocol_core::successor_bond_action_v2::SuccessorBondInboxMarkerV2 =
                serde_json::from_value(json).unwrap();
            marker.chain_id = configuration.base.chain_id;
            marker.configuration_hash = configuration.digest();
            marker.action_id = [action; 32];
            marker.availability_scheme_hash = configuration.base.availability.scheme_hash;
            marker.availability_custodian_registry_hash = configuration.base.availability.custodian_registry_hash;
            marker.source_authorization_commitment = successor_bond_inbox_no_staging_source_authorization_commitment_v2(
                marker.chain_id, marker.configuration_hash, marker.signer, marker.action_id, 0).unwrap();
            marker.availability_context = marker.expected_availability_context();
            let bundle = create_bundle(marker.availability_context, b"synthetic combined admission", &registry).unwrap();
            let bytes = bundle.encode().unwrap();
            marker.availability_bundle_len = bytes.len() as u32;
            marker.availability_bundle_root = successor_bond_inbox_availability_bundle_root_v2(&bytes).unwrap();
            let mut receipts = secrets[..3].iter().enumerate().map(|(i, s)| BondInboxCustodyReceiptV2 {
                custodian_index: i as u8,
                exact_receipt_bytes: s.custody_receipt(&bundle).unwrap().encode_canonical().unwrap().to_vec(),
            }).collect::<Vec<_>>();
            if corrupt_receipt { receipts[0].exact_receipt_bytes[137] ^= 1; }
            (marker.availability_receipt_root, marker.availability_receipt_bitmap) =
                canonical_successor_bond_inbox_custody_receipts_v2(&marker, &receipts).unwrap();
            marker = marker.sign(&bitcoin::secp256k1::SecretKey::from_slice(&[11; 32]).unwrap()).unwrap();
            let mut script = vec![0x6a, 0x4d, 0xf7, 0x01];
            script.extend(marker.payload_bytes(65536).unwrap());
            let mut transaction = tx(vec![script]);
            transaction.output[0].asset = elements::confidential::Asset::Explicit(
                elements::AssetId::from_byte_array(configuration.base.policy_asset_id));
            transaction.output[0].value = elements::confidential::Value::Explicit(0);
            let mut input = elements::TxIn::default();
            input.previous_output = elements::OutPoint::new(elements::Txid::from_byte_array([action; 32]), 0);
            // Input signature is intentionally not a consensus fixture: this helper
            // authenticates source admission after ordinary transaction validation.
            input.witness.script_witness = vec![vec![0; 64],
                ecx_elements_settlement::bond_inbox_source_annex_v2(&bytes, &receipts).unwrap()];
            transaction.input.push(input);
            transaction
        };
        let context = SuccessorEntryContext { count: u64::MAX as u128 + 7, previous_root: [12; 32],
            sidechain_height: 10, parent_height: 100, block_hash: [13; 32] };
        assert!(verify_successor_block_sources(&[], &context, &configuration, &registry).unwrap().is_empty());
        for field in 0..4 {
            let mut invalid = SuccessorEntryContext { count: context.count,
                previous_root: context.previous_root, sidechain_height: context.sidechain_height,
                parent_height: context.parent_height, block_hash: context.block_hash };
            match field {
                0 => invalid.previous_root = [0; 32],
                1 => invalid.sidechain_height = 0,
                2 => invalid.parent_height = 0,
                _ => invalid.block_hash = [0; 32],
            }
            assert_eq!(verify_successor_block_sources(&[], &invalid, &configuration, &registry),
                Err(ScanError::Context));
        }
        let transactions = vec![make_source(21, false), make_source(22, false)];
        let entries = verify_successor_block_sources(&transactions, &context, &configuration, &registry).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index, u64::MAX as u128 + 7);
        assert_eq!(entries[1].index, u64::MAX as u128 + 8);
        assert_eq!(entries[1].previous_root, entries[0].next_root());
        assert_eq!(entries[1].source_tx_index, 1);
        // Project the verified source scan into the next evaluator checkpoint.
        // These synthetic capital identities are not a genesis proof fixture.
        let projection = crate::child_execution_state_v4::CapitalProjectionV4 {
            proof_profile: 1, exchange_state_root: [1; 32],
            configuration_hash: [91; 32], asset_id: [2; 32],
            deployment_commitment: [3; 32], transition_program_id: [4; 32],
            transition_cmr: [5; 32], covenant_state_hash: [6; 32],
            covenant_inbox_root: [7; 32], covenant_inbox_count: 5,
            node_inbox_root: context.previous_root, node_inbox_count: u64::MAX as u128 + 7,
        };
        let append = |p: &crate::child_execution_state_v4::CapitalProjectionV4, txs: &[Transaction]| {
            p.append_successor_block_sources(txs, context.sidechain_height, context.parent_height,
                context.block_hash, &configuration, [91; 32], &registry)
        };
        let next = append(&projection, &transactions).unwrap();
        let mut expected = projection.clone();
        expected.node_inbox_count = u64::MAX as u128 + 9;
        expected.node_inbox_root = entries[1].next_root();
        assert_eq!(next, expected);
        assert_eq!(append(&projection, &[]).unwrap(), projection);
        assert!(append(&projection, &[make_source(23, true)]).is_err());
        assert_eq!(projection.node_inbox_count, u64::MAX as u128 + 7); // Failure cannot partially mutate state.
        let mut changed = projection.clone();
        changed.proof_profile = 0;
        assert!(append(&changed, &[]).is_err());
        changed = projection.clone(); changed.configuration_hash[0] ^= 1;
        assert!(append(&changed, &[]).is_err());
        changed = projection.clone(); changed.node_inbox_count = u128::MAX;
        assert!(append(&changed, &transactions).is_err());
        assert!(projection.append_successor_block_sources(&[], 0, context.parent_height,
            context.block_hash, &configuration, [91; 32], &registry).is_err());
        let mut wrong_configuration = configuration.clone();
        wrong_configuration.base.chain_id[0] ^= 1;
        assert!(verify_successor_block_sources(&transactions, &context, &wrong_configuration, &registry).is_err());
        assert!(verify_successor_block_sources(&transactions, &context, &configuration, &registry[..3]).is_err());
        // All outer commitments and the wrapper signature have been recomputed;
        // rejection must still occur for the invalid custodian signature.
        assert!(verify_successor_block_sources(&[make_source(23, true)], &context, &configuration, &registry).is_err());
    }

    #[test]
    fn actual_custody_signatures_are_verified() {
        use ecx_witness_availability::{CustodianSecrets, create_bundle, custodian_registry_hash};
        use ecx_protocol_core::bond_inbox_v2::{BondInboxCustodyReceiptV2,
            bond_inbox_availability_bundle_root_v2, canonical_bond_inbox_custody_receipts_v2};
        let secrets = (1..=5).map(|i| CustodianSecrets::generate(i).unwrap()).collect::<Vec<_>>();
        let registry = secrets.iter().map(|s| s.public()).collect::<Vec<_>>();
        let (mut marker, mut availability) = signed_marker_fixture();
        availability.custodian_registry_hash = custodian_registry_hash(&registry).unwrap();
        marker.availability_custodian_registry_hash = availability.custodian_registry_hash;
        marker.availability_context = marker.expected_availability_context();
        let bundle = create_bundle(marker.availability_context, b"synthetic custody test", &registry).unwrap();
        let bytes = bundle.encode().unwrap();
        marker.availability_bundle_len = bytes.len() as u32;
        marker.availability_bundle_root = bond_inbox_availability_bundle_root_v2(&bytes).unwrap();
        let mut receipts = secrets[..3].iter().enumerate().map(|(i, s)| BondInboxCustodyReceiptV2 {
            custodian_index: i as u8,
            exact_receipt_bytes: s.custody_receipt(&bundle).unwrap().encode_canonical().unwrap().to_vec(),
        }).collect::<Vec<_>>();
        let make_tx = |receipts: &[BondInboxCustodyReceiptV2]| {
            let mut annex = b"\x50ECXBIN2\0\x01".to_vec();
            annex.extend_from_slice(&(bytes.len() as u32).to_be_bytes()); annex.push(3);
            annex.extend_from_slice(&bytes);
            for receipt in receipts { annex.extend_from_slice(&[0, 138]); annex.extend_from_slice(&receipt.exact_receipt_bytes); }
            let mut transaction = tx(vec![]);
            let mut input = elements::TxIn::default();
            input.witness.script_witness = vec![vec![0; 64], annex];
            transaction.input.push(input); transaction
        };
        (marker.availability_receipt_root, marker.availability_receipt_bitmap) =
            canonical_bond_inbox_custody_receipts_v2(&marker, &receipts).unwrap();
        assert!(verify_custody_source(&make_tx(&receipts), &marker, availability, &registry).is_ok());
        // Recommit the altered receipt so failure must reach cryptographic
        // verification, rather than only the outer receipt-root comparison.
        receipts[0].exact_receipt_bytes[137] ^= 1;
        (marker.availability_receipt_root, marker.availability_receipt_bitmap) =
            canonical_bond_inbox_custody_receipts_v2(&marker, &receipts).unwrap();
        assert!(verify_custody_source(&make_tx(&receipts), &marker, availability, &registry).is_err());
    }
}
