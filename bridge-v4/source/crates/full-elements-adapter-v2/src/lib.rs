//! Final recursive adapter from a reviewed complete Elements checkpoint and
//! conversion-grade transition receipts to the exact conversion statement.

use bincode::Options;
use ecx_conversion_foundation_v2::ecx_btc::{
    ecx_btc_covenant_commitment_v2, ecx_btc_source_checkpoint_commitment_v2,
    encode_full_elements_statement_v2, EcxBtcConversionWitnessV2, FullElementsStatementV2,
    ECX_BTC_FULL_ELEMENTS_STATEMENT_VERSION_V2,
};
use ecx_full_consensus_validator_v2::checkpoint_elements_v2::{
    decode_reviewed_elements_checkpoint_input_v2, execute_reviewed_elements_checkpoint_v2,
    ReviewedElementsCheckpointPublicValuesV2,
};
use ecx_full_consensus_validator_v2::full_elements_v2::{
    decode_elements_consensus_configuration_v2,
    decode_full_elements_conversion_transition_public_values_v2,
    FullElementsConversionTransitionPublicValuesV2,
};
use ecx_full_consensus_validator_v2::patched_elements_v2::PatchedElementsBlockV2;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unreleased breaking relation revision: every transition must carry and
/// connect the authenticated BMM and child MTP/DynaFed frontiers. Rebuild the
/// checkpoint, transition, and adapter guests/program IDs.
pub const FULL_ELEMENTS_ADAPTER_INPUT_VERSION_V2: u8 = 3;
pub const MAX_FULL_ELEMENTS_ADAPTER_INPUT_BYTES_V2: usize = 640 * 1024 * 1024;
pub const MAX_FULL_ELEMENTS_TRANSITION_RECEIPTS_V2: usize = 8_192;
pub const MAX_FULL_ELEMENTS_RECEIPT_MARKER_BYTES_V2: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursiveElementsReceiptBindingV2 {
    pub public_values: Vec<u8>,
    pub proof_marker: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullElementsAdapterInputV2 {
    pub version: u8,
    /// Exact witness also consumed by the outer conversion relation.
    pub conversion_witness: EcxBtcConversionWitnessV2,
    pub checkpoint_receipt: RecursiveElementsReceiptBindingV2,
    /// Exactly one conversion-grade receipt for every successor Elements block.
    pub transition_receipts: Vec<RecursiveElementsReceiptBindingV2>,
}

pub trait FullElementsReceiptVerifierV2 {
    fn verify(
        &self,
        program_id: [u8; 32],
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), FullElementsAdapterErrorV2>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FullElementsAdapterErrorV2 {
    #[error("unsupported full-Elements adapter version")]
    UnsupportedVersion,
    #[error("full-Elements adapter input is noncanonical or oversized")]
    NonCanonicalInput,
    #[error("reviewed Elements checkpoint preimage or receipt is invalid")]
    Checkpoint,
    #[error("recursive Elements transition receipt chain is invalid")]
    TransitionChain,
    #[error("conversion statement does not match full Elements validation")]
    Statement,
    #[error("recursive receipt rejected")]
    Receipt,
}

pub fn encode_full_elements_adapter_input_v2(
    input: &FullElementsAdapterInputV2,
) -> Result<Vec<u8>, FullElementsAdapterErrorV2> {
    validate_shape(input)?;
    canonical_options()
        .serialize(input)
        .map_err(|_| FullElementsAdapterErrorV2::NonCanonicalInput)
}

pub fn decode_full_elements_adapter_input_v2(
    bytes: &[u8],
) -> Result<FullElementsAdapterInputV2, FullElementsAdapterErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_FULL_ELEMENTS_ADAPTER_INPUT_BYTES_V2 {
        return Err(FullElementsAdapterErrorV2::NonCanonicalInput);
    }
    let input: FullElementsAdapterInputV2 = canonical_options()
        .deserialize(bytes)
        .map_err(|_| FullElementsAdapterErrorV2::NonCanonicalInput)?;
    validate_shape(&input)?;
    if encode_full_elements_adapter_input_v2(&input)? != bytes {
        return Err(FullElementsAdapterErrorV2::NonCanonicalInput);
    }
    Ok(input)
}

pub fn execute_full_elements_adapter_v2<V: FullElementsReceiptVerifierV2>(
    input: &FullElementsAdapterInputV2,
    verifier: &V,
) -> Result<FullElementsStatementV2, FullElementsAdapterErrorV2> {
    validate_shape(input)?;
    let witness = &input.conversion_witness;
    let checkpoint = &witness.source_checkpoint;
    let checkpoint_commitment = ecx_btc_source_checkpoint_commitment_v2(checkpoint)
        .map_err(|_| FullElementsAdapterErrorV2::Checkpoint)?;
    let covenant_commitment = ecx_btc_covenant_commitment_v2(&witness.covenant_deployment)
        .map_err(|_| FullElementsAdapterErrorV2::Statement)?;
    let configuration = decode_elements_consensus_configuration_v2(
        &checkpoint.elements_consensus_configuration_preimage,
    )
    .map_err(|_| FullElementsAdapterErrorV2::Checkpoint)?;
    if configuration
        .commitment()
        .map_err(|_| FullElementsAdapterErrorV2::Checkpoint)?
        != checkpoint.elements_consensus_configuration_commitment
        || configuration.classification.base_asset_id != checkpoint.base_asset_id
        || configuration.classification.policy_asset_id != checkpoint.policy_asset_id
        || configuration.quote_atoms_per_whole_base != checkpoint.quote_atoms_per_whole_base
        || configuration.covenant_commitment != covenant_commitment
    {
        return Err(FullElementsAdapterErrorV2::Checkpoint);
    }

    let checkpoint_input =
        decode_reviewed_elements_checkpoint_input_v2(&checkpoint.elements.complete_state_preimage)
            .map_err(|_| FullElementsAdapterErrorV2::Checkpoint)?;
    let checkpoint_values = execute_reviewed_elements_checkpoint_v2(&checkpoint_input)
        .map_err(|_| FullElementsAdapterErrorV2::Checkpoint)?;
    if checkpoint_input.source_configuration_commitment
        != checkpoint.elements_consensus_configuration_commitment
        || checkpoint_input.classification.base_asset_id != checkpoint.base_asset_id
        || checkpoint_input.classification.policy_asset_id != checkpoint.policy_asset_id
        || checkpoint_input.classification != configuration.classification
        || checkpoint_input.child_genesis_hash != configuration.child_genesis
        || checkpoint_input.header_state.dynamic_epoch_length != configuration.dynamic_epoch_length
        || checkpoint_input.exchange_renderer != configuration.renderer
        || checkpoint_input.state_authority_asset_id != configuration.state_authority_asset_id
        || checkpoint_input.state_authority_value != configuration.state_authority_value
        || checkpoint_input.exchange_state.configuration_hash
            != configuration.finite_configuration_hash
        || checkpoint_values.block_hash_internal != checkpoint.elements.block_hash_internal
        || checkpoint_values.height != u64::from(checkpoint.elements.height)
        || checkpoint_values.state_root != checkpoint.elements.state_root
        || checkpoint_values.utxo_root != checkpoint.elements.utxo_root
        || input.checkpoint_receipt.public_values != checkpoint_values.canonical_bytes()
    {
        return Err(FullElementsAdapterErrorV2::Checkpoint);
    }
    verifier.verify(
        checkpoint.full_elements_checkpoint_program_id,
        &input.checkpoint_receipt.public_values,
        &input.checkpoint_receipt.proof_marker,
    )?;

    let terminal = verify_transition_receipt_chain_v2(
        checkpoint_values,
        covenant_commitment,
        checkpoint.full_elements_transition_program_id,
        &witness.elements_material.blocks,
        &input.transition_receipts,
        verifier,
    )?;
    let supplied = &witness.full_elements_statement;
    let expected = FullElementsStatementV2 {
        version: ECX_BTC_FULL_ELEMENTS_STATEMENT_VERSION_V2,
        source_checkpoint_commitment: checkpoint_commitment,
        covenant_commitment,
        exact_material_commitment: supplied.exact_material_commitment,
        bmm_edge_commitment: supplied.bmm_edge_commitment,
        prior_state_root: checkpoint_values.state_root,
        prior_utxo_root: checkpoint_values.utxo_root,
        next_state_root: terminal.economic.next_state_root,
        next_utxo_root: terminal.economic.next_utxo_root,
        source_tip_hash_internal: terminal.economic.block_hash,
        source_tip_height: terminal.economic.source_tip_height,
        source_tip_mtp: terminal.economic.source_tip_mtp,
        base_asset_id: checkpoint.base_asset_id,
        policy_asset_id: checkpoint.policy_asset_id,
        quote_atoms_per_whole_base: checkpoint.quote_atoms_per_whole_base,
        outstanding_base_atoms: terminal.economic.outstanding_base_atoms,
        redeemable_reserve_quote_atoms: terminal.economic.redeemable_reserve_quote_atoms,
        redemption_enabled: true,
        complete_utxo_replay_valid: true,
        confidential_openings_valid: true,
        asset_conservation_valid: true,
        simplicity_covenant_valid: true,
        issuance_and_reissuance_valid: true,
        pause_timelock_governance_valid: true,
        all_outputs_classified: true,
    };
    if supplied != &expected {
        return Err(FullElementsAdapterErrorV2::Statement);
    }
    encode_full_elements_statement_v2(&expected)
        .map_err(|_| FullElementsAdapterErrorV2::Statement)?;
    Ok(expected)
}

pub fn verify_transition_receipt_chain_v2<V: FullElementsReceiptVerifierV2>(
    checkpoint: ReviewedElementsCheckpointPublicValuesV2,
    covenant_commitment: [u8; 32],
    transition_program_id: [u8; 32],
    exact_blocks: &[Vec<u8>],
    receipts: &[RecursiveElementsReceiptBindingV2],
    verifier: &V,
) -> Result<FullElementsConversionTransitionPublicValuesV2, FullElementsAdapterErrorV2> {
    if receipts.is_empty() || receipts.len() != exact_blocks.len() {
        return Err(FullElementsAdapterErrorV2::TransitionChain);
    }
    let mut previous: Option<FullElementsConversionTransitionPublicValuesV2> = None;
    for (index, (block_bytes, receipt)) in exact_blocks.iter().zip(receipts).enumerate() {
        let current =
            decode_full_elements_conversion_transition_public_values_v2(&receipt.public_values)
                .map_err(|_| FullElementsAdapterErrorV2::TransitionChain)?;
        // These are patched V18 blocks, not upstream rust-elements blocks.
        // Keep this decoder identical to the transition relation's wire format.
        let block = PatchedElementsBlockV2::decode(block_bytes)
            .map_err(|_| FullElementsAdapterErrorV2::TransitionChain)?;
        let block_hash = block
            .header
            .block_hash()
            .map_err(|_| FullElementsAdapterErrorV2::TransitionChain)?;
        let critical_hash = block
            .header
            .bmm_critical_hash()
            .map_err(|_| FullElementsAdapterErrorV2::TransitionChain)?;
        if block
            .encode()
            .map_err(|_| FullElementsAdapterErrorV2::TransitionChain)?
            != *block_bytes
            || current.economic.source_configuration_commitment
                != checkpoint.source_configuration_commitment
            || current.covenant_commitment != covenant_commitment
            || current.economic.block_hash != block_hash
            || current.economic.bmm_critical_hash != critical_hash
            || current.economic.source_tip_height != u64::from(block.header.height)
            || receipt.proof_marker.is_empty()
            || receipt.proof_marker.len() > MAX_FULL_ELEMENTS_RECEIPT_MARKER_BYTES_V2
        {
            return Err(FullElementsAdapterErrorV2::TransitionChain);
        }
        let connects = if let Some(prior) = previous {
            current.economic.previous_state_root == prior.economic.next_state_root
                && current.economic.previous_utxo_root == prior.economic.next_utxo_root
                && current.economic.previous_economic_root == prior.economic.next_economic_root
                && current.economic.previous_exchange_state_root
                    == prior.economic.next_exchange_state_root
                && current.economic.previous_parent_bmm_state_commitment
                    == prior.economic.next_parent_bmm_state_commitment
                && current.economic.previous_header_state_commitment
                    == prior.economic.next_header_state_commitment
                && block.header.previous_block_hash == prior.economic.block_hash
                && prior.economic.source_tip_height.checked_add(1)
                    == Some(current.economic.source_tip_height)
        } else {
            current.economic.previous_state_root == checkpoint.state_root
                && current.economic.previous_utxo_root == checkpoint.utxo_root
                && current.economic.previous_economic_root == checkpoint.economic_root
                && current.economic.previous_exchange_state_root == checkpoint.exchange_state_root
                && current.economic.previous_parent_bmm_state_commitment
                    == checkpoint.parent_bmm_state_commitment
                && current.economic.previous_header_state_commitment
                    == checkpoint.header_state_commitment
                && block.header.previous_block_hash == checkpoint.block_hash_internal
                && checkpoint.height.checked_add(1) == Some(current.economic.source_tip_height)
                && index == 0
        };
        if !connects {
            return Err(FullElementsAdapterErrorV2::TransitionChain);
        }
        verifier.verify(
            transition_program_id,
            &receipt.public_values,
            &receipt.proof_marker,
        )?;
        previous = Some(current);
    }
    previous.ok_or(FullElementsAdapterErrorV2::TransitionChain)
}

fn validate_shape(input: &FullElementsAdapterInputV2) -> Result<(), FullElementsAdapterErrorV2> {
    if input.version != FULL_ELEMENTS_ADAPTER_INPUT_VERSION_V2 {
        return Err(FullElementsAdapterErrorV2::UnsupportedVersion);
    }
    if input.transition_receipts.is_empty()
        || input.transition_receipts.len() > MAX_FULL_ELEMENTS_TRANSITION_RECEIPTS_V2
        || input.transition_receipts.len()
            != input.conversion_witness.elements_material.blocks.len()
        || input.checkpoint_receipt.proof_marker.is_empty()
        || input.checkpoint_receipt.proof_marker.len() > MAX_FULL_ELEMENTS_RECEIPT_MARKER_BYTES_V2
        || input.transition_receipts.iter().any(|receipt| {
            receipt.public_values.is_empty()
                || receipt.proof_marker.is_empty()
                || receipt.proof_marker.len() > MAX_FULL_ELEMENTS_RECEIPT_MARKER_BYTES_V2
        })
    {
        return Err(FullElementsAdapterErrorV2::NonCanonicalInput);
    }
    Ok(())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_full_consensus_validator_v2::full_elements_v2::{
        FullElementsEconomicTransitionPublicValuesV2,
        FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_VERSION_V2,
    };
    use ecx_full_consensus_validator_v2::patched_elements_v2::{
        PatchedElementsHeaderV2, BMM_PROOF_HF_MASK_V2, DEPOSIT_INBOX_HF_MASK_V2,
        DYNAFED_HF_MASK_V2, EXCHANGE_STATE_HF_MASK_V2, FORCED_INBOX_HF_MASK_V2,
        INBOX_CURSOR_HF_MASK_V2, WITHDRAWAL_BUNDLE_HF_MASK_V2,
    };
    use elements::dynafed::Params;
    use std::cell::Cell;

    // Native adapter-relation fixtures only: this stand-in is deliberately not
    // evidence of a valid SP1 receipt or full block execution.
    struct CountingVerifier(Cell<usize>);

    impl FullElementsReceiptVerifierV2 for CountingVerifier {
        fn verify(
            &self,
            _program_id: [u8; 32],
            _public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), FullElementsAdapterErrorV2> {
            if proof_marker != [0xa5] {
                return Err(FullElementsAdapterErrorV2::Receipt);
            }
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    fn block(height: u32, previous_block_hash: [u8; 32]) -> PatchedElementsBlockV2 {
        PatchedElementsBlockV2 {
            header: PatchedElementsHeaderV2 {
                wire_version: DYNAFED_HF_MASK_V2
                    | BMM_PROOF_HF_MASK_V2
                    | WITHDRAWAL_BUNDLE_HF_MASK_V2
                    | EXCHANGE_STATE_HF_MASK_V2
                    | FORCED_INBOX_HF_MASK_V2
                    | DEPOSIT_INBOX_HF_MASK_V2
                    | INBOX_CURSOR_HF_MASK_V2
                    | 7,
                previous_block_hash,
                transaction_merkle_root: [1; 32],
                withdrawal_bundle_hash: Some([2; 32]),
                bmm_proof_hash: Some([3; 32]),
                time: height,
                height,
                current_dynafed_parameters: Params::Null,
                proposed_dynafed_parameters: Params::Null,
                exchange_state_root: Some([4; 32]),
                forced_inbox_root: Some([5; 32]),
                deposit_inbox_root: Some([6; 32]),
                ecx_parent_height: Some(100),
                forced_processed_cursor: Some(7),
                deposit_processed_cursor: Some(8),
                source_backlog_oldest_parent_height: Some(90),
                signblock_witness: vec![],
            },
            transactions: vec![],
            bmm_proof: Some(vec![1]),
        }
    }

    fn checkpoint(configuration: [u8; 32]) -> ReviewedElementsCheckpointPublicValuesV2 {
        ReviewedElementsCheckpointPublicValuesV2 {
            version: ecx_full_consensus_validator_v2::checkpoint_elements_v2::REVIEWED_ELEMENTS_CHECKPOINT_PUBLIC_VALUES_VERSION_V2,
            source_configuration_commitment: configuration,
            block_hash_internal: [1; 32],
            state_root: [2; 32],
            utxo_root: [3; 32],
            economic_root: [4; 32],
            exchange_state_root: [5; 32],
            parent_bmm_state_commitment: [6; 32],
            header_state_commitment: [40; 32],
            height: 40,
            mtp: 39,
            outstanding_base_atoms: 100,
            redeemable_reserve_quote_atoms: 200,
        }
    }

    fn transition(
        block: &PatchedElementsBlockV2,
        configuration: [u8; 32],
        covenant: [u8; 32],
        previous: ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]),
        next: ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    ) -> RecursiveElementsReceiptBindingV2 {
        let public = FullElementsConversionTransitionPublicValuesV2 {
            economic: FullElementsEconomicTransitionPublicValuesV2 {
                version: FULL_ELEMENTS_ECONOMIC_TRANSITION_PUBLIC_VALUES_VERSION_V2,
                source_configuration_commitment: configuration,
                block_hash: block.header.block_hash().unwrap(),
                bmm_critical_hash: block.header.bmm_critical_hash().unwrap(),
                previous_state_root: previous.0,
                next_state_root: next.0,
                previous_utxo_root: previous.1,
                next_utxo_root: next.1,
                previous_economic_root: previous.2,
                next_economic_root: next.2,
                previous_exchange_state_root: previous.3,
                next_exchange_state_root: next.3,
                previous_parent_bmm_state_commitment: previous.4,
                next_parent_bmm_state_commitment: next.4,
                previous_header_state_commitment: [(block.header.height - 1) as u8; 32],
                next_header_state_commitment: [block.header.height as u8; 32],
                source_tip_height: u64::from(block.header.height),
                source_tip_mtp: u64::from(block.header.time),
                outstanding_base_atoms: 100,
                redeemable_reserve_quote_atoms: 200,
            },
            covenant_commitment: covenant,
            redemption_capability_commitment: [8; 32],
        };
        RecursiveElementsReceiptBindingV2 {
            public_values: public.canonical_bytes().to_vec(),
            proof_marker: vec![0xa5],
        }
    }

    struct ChainFixture {
        checkpoint: ReviewedElementsCheckpointPublicValuesV2,
        covenant: [u8; 32],
        program_id: [u8; 32],
        blocks: Vec<Vec<u8>>,
        receipts: Vec<RecursiveElementsReceiptBindingV2>,
    }

    impl ChainFixture {
        fn new() -> Self {
            let configuration = [9; 32];
            let covenant = [10; 32];
            let checkpoint = checkpoint(configuration);
            let first_block = block(41, checkpoint.block_hash_internal);
            let second_block = block(42, first_block.header.block_hash().unwrap());
            let first_next = ([11; 32], [12; 32], [13; 32], [14; 32], [23; 32]);
            let second_next = ([15; 32], [16; 32], [17; 32], [18; 32], [24; 32]);
            let receipts = vec![
                transition(
                    &first_block,
                    configuration,
                    covenant,
                    (
                        checkpoint.state_root,
                        checkpoint.utxo_root,
                        checkpoint.economic_root,
                        checkpoint.exchange_state_root,
                        checkpoint.parent_bmm_state_commitment,
                    ),
                    first_next,
                ),
                transition(
                    &second_block,
                    configuration,
                    covenant,
                    first_next,
                    second_next,
                ),
            ];
            Self {
                checkpoint,
                covenant,
                program_id: [19; 32],
                blocks: vec![
                    first_block.encode().unwrap(),
                    second_block.encode().unwrap(),
                ],
                receipts,
            }
        }

        fn verify<V: FullElementsReceiptVerifierV2>(
            &self,
            verifier: &V,
        ) -> Result<FullElementsConversionTransitionPublicValuesV2, FullElementsAdapterErrorV2>
        {
            verify_transition_receipt_chain_v2(
                self.checkpoint,
                self.covenant,
                self.program_id,
                &self.blocks,
                &self.receipts,
                verifier,
            )
        }

        fn rewrite_journal(
            &mut self,
            index: usize,
            mutate: impl FnOnce(&mut FullElementsConversionTransitionPublicValuesV2),
        ) {
            let mut public = decode_full_elements_conversion_transition_public_values_v2(
                &self.receipts[index].public_values,
            )
            .unwrap();
            mutate(&mut public);
            self.receipts[index].public_values = public.canonical_bytes().to_vec();
        }
    }

    #[test]
    fn transition_chain_rejects_bmm_checkpoint_and_recursive_frontier_substitutions() {
        let valid = ChainFixture::new();
        let verifier = CountingVerifier(Cell::new(0));
        let terminal = valid.verify(&verifier).unwrap();
        assert_eq!(terminal.economic.next_parent_bmm_state_commitment, [24; 32]);
        assert_eq!(verifier.0.get(), 2);

        // Each mutation leaves every economic root, child hash and height
        // untouched. A permissive receipt stand-in isolates continuity checks.
        for (index, previous, verified_prefix) in [(0, true, 0), (0, false, 1), (1, true, 1)] {
            let mut changed = ChainFixture::new();
            changed.rewrite_journal(index, |journal| {
                if previous {
                    journal.economic.previous_parent_bmm_state_commitment = [99; 32];
                } else {
                    journal.economic.next_parent_bmm_state_commitment = [99; 32];
                }
            });
            let verifier = CountingVerifier(Cell::new(0));
            assert_eq!(
                changed.verify(&verifier),
                Err(FullElementsAdapterErrorV2::TransitionChain)
            );
            assert_eq!(verifier.0.get(), verified_prefix);
        }
        let mut changed = ChainFixture::new();
        changed.checkpoint.parent_bmm_state_commitment = [99; 32];
        let verifier = CountingVerifier(Cell::new(0));
        assert_eq!(
            changed.verify(&verifier),
            Err(FullElementsAdapterErrorV2::TransitionChain)
        );
        assert_eq!(verifier.0.get(), 0);
    }

    #[test]
    fn transition_chain_rejects_child_mtp_dynafed_frontier_substitutions() {
        for (index, previous, verified_prefix) in [(0, true, 0), (0, false, 1), (1, true, 1)] {
            let mut changed = ChainFixture::new();
            changed.rewrite_journal(index, |journal| {
                if previous {
                    journal.economic.previous_header_state_commitment = [99; 32];
                } else {
                    journal.economic.next_header_state_commitment = [99; 32];
                }
            });
            let verifier = CountingVerifier(Cell::new(0));
            assert_eq!(
                changed.verify(&verifier),
                Err(FullElementsAdapterErrorV2::TransitionChain)
            );
            assert_eq!(verifier.0.get(), verified_prefix);
        }
        let mut changed = ChainFixture::new();
        changed.checkpoint.header_state_commitment = [99; 32];
        let verifier = CountingVerifier(Cell::new(0));
        assert_eq!(
            changed.verify(&verifier),
            Err(FullElementsAdapterErrorV2::TransitionChain)
        );
        assert_eq!(verifier.0.get(), 0);
    }

    #[test]
    fn connected_bmm_substitutions_still_require_exact_receipt_verification() {
        // This exact-byte native stand-in checks the recursive verifier call's
        // binding; actual SP1 proof verification remains a separate release gate.
        struct ExactVerifier<'a> {
            fixture: &'a ChainFixture,
            verified: Cell<usize>,
        }
        impl FullElementsReceiptVerifierV2 for ExactVerifier<'_> {
            fn verify(
                &self,
                program_id: [u8; 32],
                public_values: &[u8],
                proof_marker: &[u8],
            ) -> Result<(), FullElementsAdapterErrorV2> {
                let expected = self
                    .fixture
                    .receipts
                    .get(self.verified.get())
                    .ok_or(FullElementsAdapterErrorV2::Receipt)?;
                if program_id != self.fixture.program_id
                    || public_values != expected.public_values
                    || proof_marker != expected.proof_marker
                {
                    return Err(FullElementsAdapterErrorV2::Receipt);
                }
                self.verified.set(self.verified.get() + 1);
                Ok(())
            }
        }
        let valid = ChainFixture::new();
        let verifier = ExactVerifier {
            fixture: &valid,
            verified: Cell::new(0),
        };
        valid.verify(&verifier).unwrap();
        assert_eq!(verifier.verified.get(), 2);

        let mut coordinated = ChainFixture::new();
        coordinated.rewrite_journal(0, |journal| {
            journal.economic.next_parent_bmm_state_commitment = [99; 32]
        });
        coordinated.rewrite_journal(1, |journal| {
            journal.economic.previous_parent_bmm_state_commitment = [99; 32]
        });
        let verifier = ExactVerifier {
            fixture: &valid,
            verified: Cell::new(0),
        };
        assert_eq!(
            coordinated.verify(&verifier),
            Err(FullElementsAdapterErrorV2::Receipt)
        );
        assert_eq!(verifier.verified.get(), 0);

        let mut terminal = ChainFixture::new();
        terminal.rewrite_journal(1, |journal| {
            journal.economic.next_parent_bmm_state_commitment = [99; 32]
        });
        let verifier = ExactVerifier {
            fixture: &valid,
            verified: Cell::new(0),
        };
        assert_eq!(
            terminal.verify(&verifier),
            Err(FullElementsAdapterErrorV2::Receipt)
        );
        assert_eq!(verifier.verified.get(), 1);
    }

    #[test]
    fn transition_chain_uses_patched_codec_and_rejects_child_parent_substitution() {
        let valid = ChainFixture::new();
        valid.verify(&CountingVerifier(Cell::new(0))).unwrap();
        for index in [0, 1] {
            let mut changed = ChainFixture::new();
            let mut block = PatchedElementsBlockV2::decode(&changed.blocks[index]).unwrap();
            block.header.previous_block_hash = [99; 32];
            changed.blocks[index] = block.encode().unwrap();
            // Keep the receipt's block identity exact so rejection is due to
            // checkpoint/predecessor linkage, not the trivial hash mismatch.
            changed.rewrite_journal(index, |journal| {
                journal.economic.block_hash = block.header.block_hash().unwrap();
                journal.economic.bmm_critical_hash = block.header.bmm_critical_hash().unwrap();
            });
            let verifier = CountingVerifier(Cell::new(0));
            assert_eq!(
                changed.verify(&verifier),
                Err(FullElementsAdapterErrorV2::TransitionChain)
            );
            assert_eq!(verifier.0.get(), index);
        }
        let mut wrong_critical = ChainFixture::new();
        wrong_critical.rewrite_journal(0, |journal| journal.economic.bmm_critical_hash = [99; 32]);
        assert_eq!(
            wrong_critical.verify(&CountingVerifier(Cell::new(0))),
            Err(FullElementsAdapterErrorV2::TransitionChain)
        );

        let mut trailing = ChainFixture::new();
        trailing.blocks[0].push(0);
        assert_eq!(
            trailing.verify(&CountingVerifier(Cell::new(0))),
            Err(FullElementsAdapterErrorV2::TransitionChain)
        );

        // A canonical upstream header is deliberately not an alternate Alpha
        // format. The patched decoder must reject it instead of guessing.
        use elements::hashes::Hash as _;
        let upstream = elements::Block {
            header: elements::BlockHeader {
                version: 1,
                prev_blockhash: elements::BlockHash::from_byte_array([1; 32]),
                merkle_root: elements::TxMerkleNode::all_zeros(),
                time: 41,
                height: 41,
                ext: elements::BlockExtData::Proof {
                    challenge: elements::Script::new(),
                    solution: elements::Script::new(),
                },
            },
            txdata: vec![],
        };
        let mut wrong_format = ChainFixture::new();
        wrong_format.blocks[0] = elements::encode::serialize(&upstream);
        let verifier = CountingVerifier(Cell::new(0));
        assert_eq!(
            wrong_format.verify(&verifier),
            Err(FullElementsAdapterErrorV2::TransitionChain)
        );
        assert_eq!(verifier.0.get(), 0);
    }

    #[test]
    fn transition_chain_rejects_legacy_journals_before_verifying_receipts() {
        let valid = ChainFixture::new();
        valid.verify(&CountingVerifier(Cell::new(0))).unwrap();
        for version in [1, 2] {
            for remove_frontiers in [true, false] {
                let mut changed = ChainFixture::new();
                let journal = &mut changed.receipts[0].public_values;
                journal[0] = version;
                if remove_frontiers {
                    if version == 1 {
                        journal.drain(353..481); // No BMM or child-header frontier.
                        assert_eq!(journal.len(), 465);
                    } else {
                        journal.drain(417..481); // No child-header frontier.
                        assert_eq!(journal.len(), 529);
                    }
                } else {
                    assert_eq!(journal.len(), 593);
                }
                let verifier = CountingVerifier(Cell::new(0));
                assert_eq!(
                    changed.verify(&verifier),
                    Err(FullElementsAdapterErrorV2::TransitionChain)
                );
                assert_eq!(verifier.0.get(), 0);
            }
        }
    }

    #[test]
    fn transition_chain_accepts_exact_sequence_and_rejects_every_substitution_class() {
        let configuration = [9; 32];
        let covenant = [10; 32];
        let checkpoint = checkpoint(configuration);
        let first_block = block(41, checkpoint.block_hash_internal);
        let second_block = block(42, first_block.header.block_hash().unwrap());
        let first_next = ([11; 32], [12; 32], [13; 32], [14; 32], [23; 32]);
        let second_next = ([15; 32], [16; 32], [17; 32], [18; 32], [24; 32]);
        let first = transition(
            &first_block,
            configuration,
            covenant,
            (
                checkpoint.state_root,
                checkpoint.utxo_root,
                checkpoint.economic_root,
                checkpoint.exchange_state_root,
                checkpoint.parent_bmm_state_commitment,
            ),
            first_next,
        );
        let second = transition(
            &second_block,
            configuration,
            covenant,
            first_next,
            second_next,
        );
        let blocks = vec![
            first_block.encode().unwrap(),
            second_block.encode().unwrap(),
        ];
        let verifier = CountingVerifier(Cell::new(0));
        let terminal = verify_transition_receipt_chain_v2(
            checkpoint,
            covenant,
            [19; 32],
            &blocks,
            &[first.clone(), second.clone()],
            &verifier,
        )
        .unwrap();
        assert_eq!(terminal.economic.next_state_root, second_next.0);
        assert_eq!(
            terminal.economic.next_parent_bmm_state_commitment,
            second_next.4
        );
        assert_eq!(verifier.0.get(), 2);

        let reject = |receipts: Vec<RecursiveElementsReceiptBindingV2>, exact: Vec<Vec<u8>>| {
            assert_eq!(
                verify_transition_receipt_chain_v2(
                    checkpoint,
                    covenant,
                    [19; 32],
                    &exact,
                    &receipts,
                    &CountingVerifier(Cell::new(0)),
                ),
                Err(FullElementsAdapterErrorV2::TransitionChain)
            );
        };
        reject(vec![second.clone()], vec![blocks[1].clone()]);

        let wrong_configuration = transition(
            &first_block,
            [20; 32],
            covenant,
            (
                checkpoint.state_root,
                checkpoint.utxo_root,
                checkpoint.economic_root,
                checkpoint.exchange_state_root,
                checkpoint.parent_bmm_state_commitment,
            ),
            first_next,
        );
        reject(vec![wrong_configuration, second.clone()], blocks.clone());

        let wrong_covenant = transition(
            &first_block,
            configuration,
            [21; 32],
            (
                checkpoint.state_root,
                checkpoint.utxo_root,
                checkpoint.economic_root,
                checkpoint.exchange_state_root,
                checkpoint.parent_bmm_state_commitment,
            ),
            first_next,
        );
        reject(vec![wrong_covenant, second.clone()], blocks.clone());

        let wrong_root = transition(
            &second_block,
            configuration,
            covenant,
            (
                [22; 32],
                first_next.1,
                first_next.2,
                first_next.3,
                first_next.4,
            ),
            second_next,
        );
        reject(vec![first.clone(), wrong_root], blocks.clone());

        let wrong_block = block(42, first_block.header.block_hash().unwrap());
        let mut wrong_block_bytes = wrong_block.encode().unwrap();
        wrong_block_bytes[0] ^= 1;
        reject(
            vec![first, second],
            vec![blocks[0].clone(), wrong_block_bytes],
        );
    }
}
