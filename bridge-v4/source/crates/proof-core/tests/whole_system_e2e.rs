//! Whole available-system ECX/USDD happy path.
//!
//! This test composes the production-shaped Rust protocol surfaces in one data
//! flow. The final header adapter is deliberately named `prototype_*`: this
//! repository contains a reference Elements overlay, not a running patched
//! Elements/Truthcoin network, SP1 prover, Simplicity jet, or parent-chain
//! enforcer hook. The parent leg authenticates only the exact Elements critical
//! header against its BIP301 commitment. ECX/PXST semantics are checked on the
//! child chain; miners see only opaque BIP300/BIP301 commitment hashes.

#[path = "support/ecx_oracle_match.rs"]
mod ecx_oracle_match;
#[path = "support/oracle_context.rs"]
mod oracle_context;
use oracle_context::V2TestAuthenticatedContext;

use bincode::Options;
use ecx_elements_settlement::{
    bond_inbox_redemption_staging_script_v2, bond_inbox_source_annex_v2,
    elements_transaction_witness_bytes_v2, verify_bond_inbox_source_transaction_v2,
    verify_frozen_bond_deployment_v2, verify_transition_settlement,
    verify_transition_settlement_v2, verify_truthcoin_anchor_settlement,
    verify_usdd_checkpoint_settlement, BondInputOpeningV2, BondInputRoleV2, BondOutputOpeningV2,
    BondOutputRoleV2, BondSettlementActionV2, CollateralInputOpeningV1, CollateralInputOpeningV2,
    CollateralInputRoleV2, CollateralOutputOpeningV1, CollateralOutputOpeningV2,
    CollateralOutputRoleV1, CollateralOutputRoleV2, FrozenBondAssetV2, FrozenBondDeploymentV2,
    TransitionSettlementV1, TransitionSettlementV2, TruthcoinAnchorAuthorityScriptsV1,
    TruthcoinAnchorSettlementV1, UsddCheckpointAuthorityScriptsV1, UsddCheckpointSettlementV1,
    WithdrawalBundleEnvelopeV1, BOND_DEPLOYMENT_VERSION, BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2,
    TRANSITION_SETTLEMENT_V2_VERSION, TRANSITION_SETTLEMENT_VERSION,
    TRUTHCOIN_ANCHOR_SETTLEMENT_VERSION, USDD_CHECKPOINT_SETTLEMENT_VERSION,
    WITHDRAWAL_BUNDLE_ENVELOPE_VERSION,
};
use ecx_matcher::{
    command_commitment, CentralMatcherSigner, EngineCommand, EngineConfig, Journal,
    OrderStatus as MatcherOrderStatus, Side as MatcherSide, SubmitOrderRequest,
    TimeInForce as MatcherTimeInForce, MARKET,
};
use ecx_parent_enforcer::{
    bitcoin_double_sha256, verify_miner_header_commitment, HeaderOnlyChildContextV1,
    LocallyValidatedBmmCommitmentV1, ParentEnforcerConfigV1, PARENT_ENFORCER_ADAPTER_VERSION,
    REQUIRED_ECX_WITHDRAWAL_HEADER_MASK,
};
use ecx_proof_core::{
    bitcoin_header_hash_internal_v2, bond_public_state_root_v2,
    canonical_availability_recovery_payload, canonical_availability_recovery_payload_v2,
    compose_funding_parent_chain_v2, derive_authenticated_price_range_v2,
    execute_incremental_bond_action_child_v2, execute_incremental_source_transaction_child_v2,
    execute_proof, execute_proof_v2, execute_proof_v2_with_consensus_verifier,
    execute_proof_with_truthcoin_verifier, incremental_bond_trader_mutation_event_id_v2,
    redemption_cancel_bond_return_opening_commitment_v2,
    redemption_cancel_queue_input_opening_commitment_v2,
    redemption_enqueue_bond_input_opening_commitment_v2,
    redemption_enqueue_queue_output_opening_commitment_v2,
    redemption_execute_inventory_output_opening_commitment_v2,
    redemption_execute_queue_input_opening_commitment_v2,
    redemption_execute_queue_remainder_output_opening_commitment_v2,
    redemption_execute_usdd_output_opening_commitment_v2,
    subscription_bond_output_opening_commitment_v2, subscription_usdd_output_opening_commitment_v2,
    transition_availability_context, transition_availability_context_v2,
    verify_authenticated_conversion_legs_v2, BondInboxEntryRecoveryEvidenceV2,
    BondInboxSourceTransactionEvidenceV2, ConversionLegConsensusProofV2, ConversionLegKindV2,
    ConversionLegPublicValuesV2, CovenantPublicStateV1, CovenantPublicStateV2,
    FundingParentChainWitnessV2, IncrementalBondActionChildInputV2,
    IncrementalBondReadOnlyActionEventV2, IncrementalSourceTransactionChildInputV2, ProofBindingV1,
    ProofBindingV2, ProofError, ProofErrorV2, ProofInputV1, ProofInputV2, COVENANT_STATE_VERSION,
    COVENANT_STATE_VERSION_V2, MAX_PROOF_INPUT_BYTES, PROOF_BINDING_VERSION,
    PROOF_BINDING_VERSION_V2, PUBLIC_VALUES_V5_LEN,
};
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::risk::{apply_fill, notional};
use ecx_protocol_core::{
    active_order_risk_root_v2, advance_funding_timestamped_v2, bond_action_root_v2,
    bond_inbox_availability_bundle_root_v2, bond_inbox_custody_receipt_binding_digest_v2,
    bond_inbox_no_staging_source_authorization_commitment_v2, bond_inbox_outcome_genesis_root_v2,
    bond_inbox_outcome_next_root_v2, bond_inbox_redemption_staging_descriptor_commitment_v2,
    bond_inbox_source_witness_sha256_v2, bond_inbox_staging_source_authorization_commitment_v2,
    canonical_bond_inbox_custody_receipts_v2, canonical_empty_sparse_root_v2,
    canonical_successor_bond_inbox_custody_receipts_v2, capital_mode_for,
    central_matcher_receipt_batch_root, creates_directional_risk, deposit_batch_root,
    deposit_event_batch_root, derive_hybrid_quote, equity, forced_action_batch_root,
    full_range_deficit, is_liquidatable, liquidation_batch_root, matcher_order_command_hash,
    next_order_receipts_root, order_risk_root_v2, plan_fifo_redemption,
    plan_redemption_cancellation, position_risk_root_v2, redemption_queue_root_v2,
    risk_params_hash, successor_bond_inbox_availability_bundle_root_v2,
    successor_bond_inbox_no_staging_source_authorization_commitment_v2, tagged_hash,
    target_reserve_125, trading_fee, transition_batch_hash, transition_envelope_hash,
    usdd_checkpoint_authority_configuration_hash, verify_child_withdrawal_state_commitment,
    verify_truthcoin_anchor_successor, withdrawal_batch_root, AccountLeaf, Amount,
    AnchorOutpointV1, AuthenticatedChildCheckpointV1, AvailabilityConfigV1,
    BondInboxAvailablePayloadV2, BondInboxConsumedEvidenceV2, BondInboxCustodyReceiptV2,
    BondInboxEntryV2, BondInboxMarkerV2, BondInboxProcessedDispositionV2,
    BondInboxProcessedOutcomeV2, BondInboxRedemptionStagingRendererInputV2, BondInboxStateV2,
    BondInboxTransitionV2, BondInboxUserActionV2, BondPublicStateV2, BondSubscriptionV2,
    CapitalModeV2, CentralMatcherConfigV1, CentralMatcherReceiptV1, DepositInboxStateV1,
    DepositInboxTransitionV1, ExchangeState, ExchangeStateV2, ForcedInboxStateV1,
    ForcedInboxTransitionV1, FrozenConfigurationV1, FrozenConfigurationV2, FundingStateV2, Hash32,
    HybridOracleConfigV1, IncrementalAccountingBoundsV2, IncrementalTraderEconomicMutationV2,
    IncrementalTraderMutationChainV2, IncrementalTraderMutationKindV2, Int256V2,
    LiquidationMatchV1, MatchedOrderPair, MatcherCommandKind, MatcherExecutionReceiptV2,
    MatcherReceiptBodyV1, OpenOrderLeaf, OracleMode, OrderFlags, OrderPlacement,
    OrderRiskCommitmentV2, Position, PositionLeaf, PositionRiskLeafV2, Price, Quantity,
    RedemptionCancellationV2Action, RedemptionEnqueueV2, RedemptionExecutionV2, RiskParams, Side,
    Signature64, SignedBondSubscriptionV2, SignedLimitOrder, SignedRedemptionCancellationV2,
    SignedRedemptionEnqueueV2, SignedWithdrawalRequest, SparseStateDomainV2, StateRoots,
    SuccessorBondInboxConsumedDispositionV2, SuccessorBondInboxConsumedOutcomeV2,
    SuccessorBondInboxEntryV2, SuccessorBondInboxMarkerV2, SuccessorBondInboxUserActionV2,
    SuccessorBondPublicStateV2, SuccessorBondSubscriptionV2, SuccessorSignedBondSubscriptionV2,
    TimeInForce, TimestampedFundingObservationV2, TradeMatch, TraderLeafV2,
    TraderStateBatchLeafUpdateV2, TraderStateBatchProofV2, TraderStateReadBatchProofV2,
    TransitionEnvelopeV4, TransitionPublicInputs, TransitionPublicInputsV2, TransitionWitness,
    TransitionWitnessV2, TruthcoinAnchorDeploymentV1, TruthcoinAnchorStateV1,
    TruthcoinAnchorUpdateV1, TruthcoinAnchorV1, TruthcoinAuthenticationConfigV1,
    TruthcoinLmsrSnapshotV1, UsddCheckpointConfigV1, UsddCheckpointUpdateV1,
    UsddEthereumCheckpointV1, WithdrawalRequest, WithdrawalStateAnchorV1, XOnlyKey,
    AVAILABILITY_CUSTODIAN_COUNT, AVAILABILITY_RECOVERY_THRESHOLD, BMM_SLOT,
    BOND_FIXED_SUPPLY_ATOMS, BOND_INBOX_INCLUSION_BLOCKS_V2, BOND_INBOX_MARKER_VERSION,
    BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
    BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
    BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
    BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
    BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
    BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2, BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2,
    BOND_PROTOCOL_VERSION_V2, BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2, ECX_USDD_MARKET,
    FUNDING_BUCKET_SECONDS, MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2,
    MAX_AVAILABILITY_WITNESS_BYTES, MAX_BOND_INBOX_BUNDLE_BYTES_V2, PRICE_SCALE,
    RECURSIVE_PROOF_MARKER_BYTES_V2,
};
use ecx_stress_harness::MOCK_USDD_ASSET_ID;
use ecx_truthcoin_proof::{
    native_decision_id_hash, native_lmsr_state_root, native_market_id_hash,
    pinned_truthcoin_chain_id, probability_to_ppb, sp1_deferred_proof_marker,
    upstream_binary_lmsr_probability, ConsensusProofVerificationError, ConsensusProofVerifier,
    TruthcoinConsensusProofV1, TruthcoinSourcePublicValuesV1,
    TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256, TRUTHCOIN_LMSR_MATH_COMMITMENT,
    TRUTHCOIN_SIDECHAIN_NUMBER, TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
    TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
};
use ecx_witness_availability::{
    availability_scheme_hash, create_bundle_with_encryption_witness, custodian_registry_hash,
    custody_receipt_codec_hash_v1, recover_witness, CustodianSecrets,
};

const V18_CONFIGURATION_DIGEST_DOMAIN: &str =
    "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2";
const V18_CONFIGURATION_LEN: usize = 1_977;
const V18_CONFIGURATION_DIGEST_HEX: &str =
    "ec2c8cdb6a538079fb7a1b6688476c03476e7ecf2bd0114ab49a1a6a246ade1e";
const V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_DIGEST_HEX: &str =
    "2d9707163de748c2e613b7e1d3999ec1daa37997f00e3b9924e4e24be32570b2";

fn configuration_fixture_field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .unwrap_or_else(|| panic!("missing configuration fixture field {name}"))
}

#[test]
fn v18_configuration_fixture_is_exact_and_v17_is_historical() {
    let v18 = include_str!("../../../Testing/v18-config-v2-fixture.txt");
    let v18_bytes = hex::decode(configuration_fixture_field(
        v18,
        "ECX_V18_CONFIGURATION_HEX=",
    ))
    .unwrap();
    assert_eq!(
        configuration_fixture_field(v18, "ECX_V18_CONFIGURATION_LEN=")
            .parse::<usize>()
            .unwrap(),
        V18_CONFIGURATION_LEN
    );
    assert_eq!(v18_bytes.len(), V18_CONFIGURATION_LEN);
    assert_eq!(&v18_bytes[..2], &[5, 3]);
    assert_eq!(
        hex::encode(tagged_hash(V18_CONFIGURATION_DIGEST_DOMAIN, &v18_bytes)),
        V18_CONFIGURATION_DIGEST_HEX
    );
    assert_eq!(
        configuration_fixture_field(v18, "ECX_V18_CONFIGURATION_DIGEST="),
        V18_CONFIGURATION_DIGEST_HEX
    );

    let v17 = include_str!("../../../Testing/v17-config-v2-fixture.txt");
    let v17_bytes = hex::decode(configuration_fixture_field(
        v17,
        "ECX_V17_CONFIGURATION_HEX=",
    ))
    .unwrap();
    assert_eq!(&v17_bytes[..2], &[4, 3]);
    assert_ne!(v17_bytes.len(), V18_CONFIGURATION_LEN);
    assert_ne!(
        hex::encode(tagged_hash(V18_CONFIGURATION_DIGEST_DOMAIN, &v17_bytes)),
        V18_CONFIGURATION_DIGEST_HEX
    );

    // Confidential issuance repairs the Elements value-balance relation but
    // necessarily changes the deployment txid/commitment carried by the
    // configuration. Keep the original V18 vector immutable and bind the
    // repaired source-local construction under an explicitly candidate-only
    // fixture until its guest/node/Simplicity identities are regenerated.
    let confidential_issuance_candidate =
        include_str!("../../../Testing/v18-config-v2-confidential-issuance-candidate.txt");
    let candidate_bytes = hex::decode(configuration_fixture_field(
        confidential_issuance_candidate,
        "ECX_V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_HEX=",
    ))
    .unwrap();
    assert_eq!(
        configuration_fixture_field(
            confidential_issuance_candidate,
            "ECX_V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_LEN=",
        )
        .parse::<usize>()
        .unwrap(),
        V18_CONFIGURATION_LEN
    );
    assert_eq!(candidate_bytes.len(), V18_CONFIGURATION_LEN);
    assert_eq!(&candidate_bytes[..2], &[5, 3]);
    assert_eq!(
        hex::encode(tagged_hash(
            V18_CONFIGURATION_DIGEST_DOMAIN,
            &candidate_bytes
        )),
        V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_DIGEST_HEX
    );
    assert_eq!(
        configuration_fixture_field(
            confidential_issuance_candidate,
            "ECX_V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_DIGEST=",
        ),
        V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_DIGEST_HEX
    );
    assert_ne!(candidate_bytes, v18_bytes);
}
use elements::confidential::{Asset as ConfidentialAsset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{
    PublicKey as ZkpPublicKey, Secp256k1 as ZkpSecp256k1, SecretKey as ZkpSecretKey,
};
use elements::{
    encode as elements_encode, AssetId, OutPoint, Script, Transaction, TxIn, TxOut, TxOutSecrets,
};
use rand::{rngs::StdRng, SeedableRng};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::fs;

const CHAIN_ID: [u8; 32] = [0x19; 32];
const SIDECHAIN_HEIGHT: u64 = 100;
const PARENT_HEIGHT: u64 = 900_000;
const PARENT_MTP: u64 = 1_150;
const PARENT_BLOCK_HASH: [u8; 32] = [0x30; 32];
const WITHDRAWAL_OUTPOINT_TXID: [u8; 32] = [0x84; 32];
const EXISTING_WITHDRAWAL_COMMITMENT: [u8; 32] = [
    0xeb, 0x27, 0x7e, 0x8d, 0xef, 0x8f, 0x54, 0xfc, 0xe6, 0x4d, 0x76, 0x62, 0xc2, 0xac, 0xed, 0x5e,
    0x92, 0xb3, 0x9c, 0x9d, 0xd3, 0x3b, 0x7d, 0xad, 0x6f, 0xef, 0x84, 0xf3, 0x0c, 0xfd, 0x64, 0x03,
];

/// Test-only stand-in for the separately reviewed Truthcoin full-replay
/// verifier. This authenticates exact bytes for composition testing; it is not
/// a production proof system and is deliberately never selected by
/// `execute_proof`'s fail-closed entrypoint.
#[derive(Debug, Clone, Copy)]
struct TestDigestVerifier;

impl ConsensusProofVerifier for TestDigestVerifier {
    fn verify(
        &self,
        program_id: [u8; 32],
        public_values: &[u8],
        proof: &[u8],
    ) -> Result<(), ConsensusProofVerificationError> {
        if proof == test_truthcoin_proof(program_id, public_values) {
            Ok(())
        } else {
            Err(ConsensusProofVerificationError)
        }
    }
}

/// Source-local stand-in for recursive SP1 verification. It accepts only the
/// exact program/public-values deferred marker used by the production child
/// composition boundary; it is not a cryptographic proof verifier.
#[derive(Debug, Clone, Copy)]
struct DeferredMarkerVerifier;

impl ConsensusProofVerifier for DeferredMarkerVerifier {
    fn verify(
        &self,
        program_id: [u8; 32],
        public_values: &[u8],
        proof: &[u8],
    ) -> Result<(), ConsensusProofVerificationError> {
        if proof == sp1_deferred_proof_marker(program_id, public_values) {
            Ok(())
        } else {
            Err(ConsensusProofVerificationError)
        }
    }
}

fn test_truthcoin_proof(program_id: [u8; 32], public_values: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(program_id.len() + public_values.len());
    bytes.extend_from_slice(&program_id);
    bytes.extend_from_slice(public_values);
    Sha256::digest(bytes).to_vec()
}

#[test]
fn whole_available_system_happy_path_and_tamper_rejection() {
    // Live Truthcoin binding for SP1 transition export (ECX_DUMP_PROOF_INPUT).
    let live_mode = std::env::var("ECX_DUMP_PROOF_INPUT").is_ok();
    let (live_replay, live_pv, live_pid): (
        Option<ecx_truthcoin_replay::ReplayInputV1>,
        Option<TruthcoinSourcePublicValuesV1>,
        Option<[u8; 32]>,
    ) = if live_mode {
        let wit = fs::read(std::env::var("ECX_TRUTHCOIN_WITNESS").expect("ECX_TRUTHCOIN_WITNESS"))
            .unwrap();
        let pv_bytes =
            fs::read(std::env::var("ECX_TRUTHCOIN_PV").expect("ECX_TRUTHCOIN_PV")).unwrap();
        let mut pid = [0u8; 32];
        let raw = hex::decode(
            std::env::var("ECX_TRUTHCOIN_PROGRAM_ID")
                .expect("ECX_TRUTHCOIN_PROGRAM_ID")
                .trim(),
        )
        .unwrap();
        assert_eq!(raw.len(), 32);
        pid.copy_from_slice(&raw);
        let replay: ecx_truthcoin_replay::ReplayInputV1 = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&wit)
            .expect("ReplayInputV1");
        let out = ecx_truthcoin_replay::execute_production_replay(&replay).expect("replay");
        let live = out.public_values;
        assert_eq!(
            ecx_truthcoin_proof::source_public_values_bytes(&live),
            pv_bytes
        );
        (Some(replay), Some(live), Some(pid))
    } else {
        (None, None, None)
    };
    // Shadow parent context for the whole happy-path construction when live.
    let parent_height = live_pv
        .as_ref()
        .map(|p| p.observed_parent_height)
        .unwrap_or(PARENT_HEIGHT);
    let parent_mtp = live_pv
        .as_ref()
        .map(|p| p.observed_parent_mtp)
        .unwrap_or(PARENT_MTP);
    let parent_block_hash = live_pv
        .as_ref()
        .map(|p| p.observed_parent_block_hash)
        .unwrap_or(PARENT_BLOCK_HASH);

    let vault_script = collateral_vault_script();
    let (matcher_secret, matcher_key) = identity(7);
    let matcher = CentralMatcherConfigV1 {
        version: CentralMatcherConfigV1::VERSION,
        key_epoch: 0,
        signer: matcher_key,
        genesis_sequence: 0,
        genesis_receipt_hash: [0x31; 32],
        forced_inclusion_blocks: 6,
    };
    let oracle = oracle_config();
    let truthcoin_authentication = truthcoin_authentication_config(&oracle);
    let availability_custodians = (1_u8..=AVAILABILITY_CUSTODIAN_COUNT)
        .map(|index| CustodianSecrets::new(index, [0x90 + index; 32], [0xa0 + index; 32]).unwrap())
        .collect::<Vec<_>>();
    let availability_public = availability_custodians
        .iter()
        .map(CustodianSecrets::public)
        .collect::<Vec<_>>();
    let availability = AvailabilityConfigV1 {
        version: AvailabilityConfigV1::VERSION,
        scheme_hash: availability_scheme_hash(),
        custodian_registry_hash: custodian_registry_hash(&availability_public).unwrap(),
        recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
        custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
        maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
    };
    let mut configuration = FrozenConfigurationV1 {
        version: FrozenConfigurationV1::VERSION,
        chain_id: CHAIN_ID,
        market: ECX_USDD_MARKET,
        ecx_asset_id: [0x41; 32],
        usdd_asset_id: MOCK_USDD_ASSET_ID,
        policy_asset_id: [0x43; 32],
        state_authority_asset_id: [0x44; 32],
        usdd_checkpoint: UsddCheckpointConfigV1 {
            version: UsddCheckpointConfigV1::VERSION,
            ethereum_light_client_configuration_hash: [0x78; 32],
            authority_configuration_hash: usdd_checkpoint_authority_configuration_hash(
                [0x7a; 32], 1, [0x7b; 32], [0x43; 32],
            ),
            maximum_checkpoint_age_seconds: ecx_protocol_core::USDD_MAX_CHECKPOINT_AGE_SECONDS,
        },
        risk: RiskParams::default(),
        availability,
        truthcoin_authentication,
        truthcoin_anchor_deployment: TruthcoinAnchorDeploymentV1 {
            version: TruthcoinAnchorDeploymentV1::VERSION,
            authority_asset_id: [0x76; 32],
            authority_amount: 1,
            // Test-only until the reviewed Taproot/Simplicity tree is frozen.
            script_tree_configuration_hash: [0x77; 32],
        },
        oracle: oracle.clone(),
        matcher: matcher.clone(),
        forced_action_domain: [0x45; 32],
        deposit_inbox_domain: [0x46; 32],
        collateral_vault_script_sha256: Sha256::digest(vault_script.as_bytes()).into(),
        maximum_transition_actions: 64,
    };
    if let Some(ref replay) = live_replay {
        configuration.truthcoin_authentication = replay.authentication.clone();
        configuration.oracle.truthcoin_chain_id =
            configuration.truthcoin_authentication.truthcoin_chain_id;
        configuration.oracle.truthcoin_branch_id =
            configuration.truthcoin_authentication.truthcoin_branch_id;
        configuration.oracle.btc_usd_template_hash =
            configuration.truthcoin_authentication.btc_usd_template_hash;
        configuration.oracle.lmsr_math_commitment =
            configuration.truthcoin_authentication.lmsr_math_commitment;
        // Keep oracle finality requirement <= auth finality.
        configuration.oracle.minimum_source_confirmations =
            configuration.oracle.minimum_source_confirmations.min(
                configuration
                    .truthcoin_authentication
                    .minimum_bitcoin_confirmations,
            );
        // Widen oracle age windows so live mocktime MTP does not immediately halt.
        configuration.oracle.maximum_anchor_age_seconds =
            configuration.oracle.maximum_anchor_age_seconds.max(
                parent_mtp
                    .saturating_sub(
                        live_pv
                            .as_ref()
                            .map(|p| p.anchor.finalized_at_mtp)
                            .unwrap_or(0),
                    )
                    .saturating_add(86_400),
            );
        configuration.oracle.maximum_snapshot_age_seconds =
            configuration.oracle.maximum_snapshot_age_seconds.max(
                parent_mtp
                    .saturating_sub(
                        live_pv
                            .as_ref()
                            .map(|p| p.lmsr_snapshot.source_mtp)
                            .unwrap_or(0),
                    )
                    .saturating_add(86_400),
            );
        // Production-period schedule (TRUTHCOIN_PERIOD_SECONDS).
        const TRUTHCOIN_PERIOD_SECONDS: u64 = 7_862_400;
        configuration.oracle.epoch_length_seconds = TRUTHCOIN_PERIOD_SECONDS;
        if let Some(ref live) = live_pv {
            configuration.oracle.schedule_origin_mtp =
                live.anchor.observation_end_mtp.saturating_sub(
                    live.anchor
                        .epoch
                        .saturating_add(1)
                        .saturating_mul(TRUTHCOIN_PERIOD_SECONDS),
                );
            configuration.oracle.minimum_sample_count = configuration
                .oracle
                .minimum_sample_count
                .min(live.lmsr_snapshot.sample_count.max(1));
            configuration.oracle.minimum_lmsr_b = configuration
                .oracle
                .minimum_lmsr_b
                .min(live.lmsr_snapshot.lmsr_b.max(1));
        }
        configuration.oracle.minimum_source_confirmations =
            configuration.oracle.minimum_source_confirmations.max(1);
        configuration.oracle.maximum_unanchored_deviation_bps = 10_000;
        configuration.oracle.maximum_anchor_band_bps = 9_999;
    }
    configuration.validate().unwrap();
    if !live_mode {
        exercise_mock_usdd_checkpoint(&configuration);
    }

    // A finalized Truthcoin decision anchors the interval. The canonical,
    // fastest current Truthcoin slot supplies the LMSR path between decisions.
    let truthcoin_consensus_proof = if let (Some(live), Some(pid)) = (live_pv.as_ref(), live_pid) {
        let pv_bytes = ecx_truthcoin_proof::source_public_values_bytes(live);
        let marker = ecx_truthcoin_proof::sp1_deferred_proof_marker(pid, &pv_bytes);
        TruthcoinConsensusProofV1 {
            version: TruthcoinConsensusProofV1::VERSION,
            public_values: (*live).clone(),
            proof: marker.to_vec(),
        }
    } else {
        truthcoin_source_proof(
            &configuration.truthcoin_authentication,
            &configuration.oracle,
        )
    };
    let quote = derive_hybrid_quote(
        &configuration.oracle,
        &truthcoin_consensus_proof.public_values.anchor,
        &truthcoin_consensus_proof.public_values.lmsr_snapshot,
        parent_mtp,
    )
    .expect("canonical Truthcoin/LMSR quote");
    if !live_mode {
        assert_eq!(quote.oracle_mode, OracleMode::Normal);
        assert!(quote.btc_usd_index > quote.btc_usd_anchor);
        assert!(quote.btc_usd_index < quote.btc_usd_fast);
    } else {
        eprintln!(
            "live dump quote mode={:?} index={} anchor={} fast={}",
            quote.oracle_mode,
            quote.btc_usd_index.get(),
            quote.btc_usd_anchor.get(),
            quote.btc_usd_fast.get()
        );
    }
    let active_truthcoin_anchor = rolling_truthcoin_anchor(
        &configuration,
        &truthcoin_consensus_proof.public_values,
        quote.certificate_hash(),
    );
    assert_eq!(
        active_truthcoin_anchor.oracle_certificate_commitment,
        quote.certificate_hash()
    );

    let (maker_secret, maker) = identity(11);
    let (taker_secret, taker) = identity(12);
    let (withdrawer_secret, withdrawer) = identity(13);
    let maker_order = signed_order(
        &maker_secret,
        Side::Sell,
        quote.ecx_usdd_index,
        5,
        0,
        TimeInForce::GoodTilHeight,
        [0x51; 16],
    );
    let taker_order = signed_order(
        &taker_secret,
        Side::Buy,
        Price::new(quote.ecx_usdd_index.get() + 1).unwrap(),
        2,
        0,
        TimeInForce::ImmediateOrCancel,
        [0x52; 16],
    );

    // The actual deterministic matcher, central signer, and atomic journal are
    // composed exactly as the live API composes them.
    let engine_config = EngineConfig {
        demo_mode: false,
        chain_height: SIDECHAIN_HEIGHT,
        ..EngineConfig::default()
    };
    let matcher_signer = CentralMatcherSigner::new(
        matcher.clone(),
        matcher_secret,
        CHAIN_ID,
        SIDECHAIN_HEIGHT,
        parent_height,
        parent_mtp,
        0,
    )
    .unwrap();
    let journal_directory = tempfile::tempdir().unwrap();
    let journal_path = journal_directory.path().join("central-matcher.jsonl");
    let (mut journal, mut engine) = Journal::open(
        &journal_path,
        engine_config.clone(),
        matcher.clone(),
        CHAIN_ID,
    )
    .unwrap();
    let maker_request = matcher_request(&maker_order);
    let maker_command = EngineCommand::Submit {
        request: maker_request.clone(),
        received_at_ms: 1_000,
    };
    let maker_commitment = command_commitment(&maker_command, CHAIN_ID).unwrap();
    let maker_sequence = journal.next_sequence().unwrap();
    let mut staged = engine.clone();
    let maker_result = staged
        .submit_sequenced(maker_request, 1_000, maker_sequence)
        .unwrap();
    let maker_receipt = matcher_signer
        .issue(
            &maker_commitment,
            maker_sequence,
            journal.head_receipt_hash(),
        )
        .unwrap();
    journal.append(&maker_command, &maker_receipt).unwrap();
    engine = staged;
    assert_eq!(maker_result.outcome.status, MatcherOrderStatus::Resting);
    let taker_request = matcher_request(&taker_order);
    let taker_command = EngineCommand::Submit {
        request: taker_request.clone(),
        received_at_ms: 1_001,
    };
    let taker_commitment = command_commitment(&taker_command, CHAIN_ID).unwrap();
    let taker_sequence = journal.next_sequence().unwrap();
    let mut staged = engine.clone();
    let taker_result = staged
        .submit_sequenced(taker_request.clone(), 1_001, taker_sequence)
        .unwrap();
    let taker_receipt = matcher_signer
        .issue(
            &taker_commitment,
            taker_sequence,
            journal.head_receipt_hash(),
        )
        .unwrap();
    journal.append(&taker_command, &taker_receipt).unwrap();
    engine = staged;
    assert_eq!(taker_result.outcome.status, MatcherOrderStatus::Filled);
    assert_eq!(taker_result.outcome.trades.len(), 1);
    let matcher_trade = taker_result.outcome.trades[0].clone();
    assert_eq!(
        matcher_trade.price_ticks,
        maker_order.order.limit_price.get()
    );
    assert_eq!(matcher_trade.quantity_lots, 2);
    assert_eq!(engine.orderbook(10).asks[0].quantity_lots, 3);

    // One central signer, not a committee or quorum, assigned both priorities.
    maker_receipt.verify(&matcher).unwrap();
    taker_receipt.verify(&matcher).unwrap();
    assert_eq!(
        maker_receipt.body.command_hash,
        maker_commitment.command_hash
    );
    assert_eq!(
        maker_receipt.body.availability_root,
        maker_commitment.availability_root
    );
    assert_eq!(
        taker_receipt.body.command_hash,
        taker_commitment.command_hash
    );
    assert_eq!(
        taker_receipt.body.availability_root,
        taker_commitment.availability_root
    );

    // A real journal reopen restores FIFO/book state. An idempotent retry finds
    // the original receipt and cannot execute the fill twice.
    drop(journal);
    drop(engine);
    let (replayed_journal, mut replayed_engine) =
        Journal::open(&journal_path, engine_config, matcher.clone(), CHAIN_ID).unwrap();
    assert_eq!(replayed_journal.head_sequence(), taker_sequence);
    assert_eq!(replayed_engine.orderbook(10).asks[0].quantity_lots, 3);
    let retry = replayed_engine
        .submit_sequenced(
            taker_request,
            1_002,
            replayed_journal.next_sequence().unwrap(),
        )
        .unwrap();
    assert!(retry.outcome.duplicate);
    assert!(retry.events.is_empty());
    assert_eq!(replayed_engine.recent_trades(10).len(), 1);
    assert_eq!(
        replayed_journal
            .receipt_for_command(&taker_commitment.command_hash)
            .unwrap()
            .receipt_hash(),
        taker_receipt.receipt_hash()
    );
    let receipts = vec![maker_receipt.clone(), taker_receipt.clone()];

    let maker_fee = trading_fee(
        maker_order.order.limit_price,
        Quantity::new(matcher_trade.quantity_lots).unwrap(),
        configuration.risk.maker_fee_bps,
    )
    .unwrap();
    let taker_fee = trading_fee(
        maker_order.order.limit_price,
        Quantity::new(matcher_trade.quantity_lots).unwrap(),
        configuration.risk.taker_fee_bps as i32,
    )
    .unwrap();
    let fills = vec![MatchedOrderPair {
        maker_order: maker_order.clone(),
        taker_order: taker_order.clone(),
        trade: TradeMatch {
            // Consensus priority is the taker's signed ingress-receipt
            // sequence. The matcher's UI event counter is not a trust root.
            sequence: taker_receipt.body.global_sequence,
            maker_order_id: maker_order.order_id(),
            taker_order_id: taker_order.order_id(),
            maker,
            taker,
            maker_side: Side::Sell,
            price: maker_order.order.limit_price,
            quantity: Quantity::new(matcher_trade.quantity_lots).unwrap(),
            maker_fee,
            taker_fee,
        },
    }];
    let placements = vec![OrderPlacement {
        order: maker_order.clone(),
        received_sequence: maker_receipt.body.global_sequence,
        salt: [0x71; 32],
    }];
    let withdrawal_script = withdrawal_destination_script();
    let withdrawal = SignedWithdrawalRequest::sign(
        WithdrawalRequest {
            version: WithdrawalRequest::VERSION,
            chain_id: CHAIN_ID,
            trader: withdrawer,
            nonce: 0,
            amount: 100,
            destination_script_hash: Sha256::digest(withdrawal_script.as_bytes()).into(),
            requested_height: 95,
            not_before_height: SIDECHAIN_HEIGHT,
        },
        &withdrawer_secret,
    )
    .unwrap();
    withdrawal.verify().unwrap();
    let withdrawals = vec![withdrawal];
    let deposits = vec![];
    let cancellations = vec![];

    // Private leaves use fresh salts. Only roots cross the proof boundary.
    let previous_accounts = vec![
        account(maker, 0, 1_000_000, 1),
        account(taker, 0, 1_000_000, 2),
        account(withdrawer, 0, 1_000_000, 3),
    ];
    let next_accounts = vec![
        account(maker, 1, 1_000_000 - maker_fee.0, 4),
        account(taker, 1, 1_000_000 - taker_fee.0, 5),
        account(withdrawer, 1, 999_900, 6),
    ];
    let previous_positions = vec![flat_position(maker, 7), flat_position(taker, 8)];
    let next_positions = vec![
        position(maker, -2, maker_order.order.limit_price, 9),
        position(taker, 2, maker_order.order.limit_price, 10),
    ];
    let previous_open_orders = vec![];
    let next_open_orders = vec![OpenOrderLeaf {
        version: OpenOrderLeaf::VERSION,
        order_id: maker_order.order_id(),
        trader: maker,
        market: ECX_USDD_MARKET,
        side: Side::Sell,
        limit_price: maker_order.order.limit_price,
        remaining_quantity: Quantity::new(3).unwrap(),
        received_sequence: maker_receipt.body.global_sequence,
        expires_at_height: maker_order.order.expires_at_height,
        salt: [0x7b; 32],
    }];
    assert_ne!(
        previous_accounts[0].commitment(),
        next_accounts[0].commitment()
    );

    let matcher_receipt_batch_root = central_matcher_receipt_batch_root(&receipts);
    let oracle_certificate_hash = quote.certificate_hash();
    let forced_action_batch_root = forced_action_batch_root(&[]);
    let liquidations = vec![];
    let liquidation_batch_root = liquidation_batch_root(&liquidations);
    let deposit_event_batch_root = deposit_event_batch_root(&[]);
    let transition_settlement = build_transition_settlement(
        &configuration,
        &withdrawals,
        &vault_script,
        &withdrawal_script,
    );
    let verified_settlement = verify_transition_settlement(
        &transition_settlement,
        &withdrawals,
        configuration.usdd_asset_id,
        configuration.collateral_vault_script_sha256,
    )
    .unwrap();
    let collateral_settlement_root = verified_settlement.settlement_root;
    assert_eq!(
        configuration.availability.scheme_hash,
        availability_scheme_hash()
    );
    assert_eq!(
        configuration.availability.custodian_registry_hash,
        custodian_registry_hash(&availability_public).unwrap()
    );
    // Temporary nonzero value breaks construction ordering only. The final
    // bundle below is built from an availability-neutral transition and all
    // availability-derived roots are then replaced before verification.
    let next_encrypted_availability_root = [0x5a; 32];
    let operation_batch_hash = transition_batch_hash(
        &deposits,
        &withdrawals,
        &placements,
        &cancellations,
        &fills,
        &liquidations,
    );
    let batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root,
        oracle_certificate_hash,
        oracle_mode: quote.oracle_mode,
        matcher_receipt_batch_root,
        collateral_settlement_root,
        forced_action_batch_root,
        escape_only: false,
        encrypted_availability_root: next_encrypted_availability_root,
    });
    let forced_inbox =
        ForcedInboxStateV1::genesis(configuration.forced_action_domain, CHAIN_ID).unwrap();
    let deposit_inbox =
        DepositInboxStateV1::genesis(configuration.deposit_inbox_domain, CHAIN_ID).unwrap();
    let previous_receipts_root = tagged_hash("ECX/e2e-order-receipts-genesis/v1", b"genesis");
    let previous_roots = StateRoots::from_private_state(
        &previous_accounts,
        &previous_positions,
        &previous_open_orders,
        &[],
        &[],
        previous_receipts_root,
    )
    .unwrap();
    let next_roots = StateRoots::from_private_state(
        &next_accounts,
        &next_positions,
        &next_open_orders,
        &[],
        &[withdrawals[0].request.request_id()],
        next_order_receipts_root(previous_receipts_root, batch_hash),
    )
    .unwrap();
    let previous_state = ExchangeState {
        protocol_version: ExchangeState::VERSION,
        chain_id: CHAIN_ID,
        market: ECX_USDD_MARKET,
        sequence: 40,
        last_processed_height: SIDECHAIN_HEIGHT - 1,
        mark_price: quote.ecx_usdd_index,
        funding_index: 0,
        total_deposits: Amount(3_000_000),
        total_withdrawals: Amount(0),
        insurance_fund: Amount(0),
        fee_pool: Amount(0),
        matcher_sequence: matcher.genesis_sequence,
        matcher_receipt_hash: matcher.genesis_receipt_hash,
        forced_inbox,
        deposit_inbox,
        roots: previous_roots,
    };
    let next_state = ExchangeState {
        protocol_version: ExchangeState::VERSION,
        chain_id: CHAIN_ID,
        market: ECX_USDD_MARKET,
        sequence: 41,
        last_processed_height: SIDECHAIN_HEIGHT,
        mark_price: quote.ecx_usdd_index,
        funding_index: 0,
        total_deposits: Amount(3_000_000),
        total_withdrawals: Amount(100),
        insurance_fund: Amount(0),
        fee_pool: Amount(maker_fee.0 + taker_fee.0),
        matcher_sequence: taker_receipt.body.global_sequence,
        matcher_receipt_hash: taker_receipt.receipt_hash(),
        forced_inbox,
        deposit_inbox,
        roots: next_roots,
    };
    let mut transition = TransitionWitness {
        public: TransitionPublicInputs {
            protocol_version: TransitionPublicInputs::VERSION,
            chain_id: CHAIN_ID,
            market: ECX_USDD_MARKET,
            sidechain_height: SIDECHAIN_HEIGHT,
            parent_height,
            forced_inclusion_blocks: configuration.matcher.forced_inclusion_blocks,
            previous_state_root: previous_state.state_root(),
            previous_sequence: previous_state.sequence,
            next_state_root: next_state.state_root(),
            next_sequence: next_state.sequence,
            batch_hash,
            deposit_batch_root: deposit_batch_root(&deposits),
            deposit_event_batch_root,
            withdrawal_batch_root: withdrawal_batch_root(&withdrawals),
            collateral_settlement_root,
            liquidation_batch_root,
            existing_withdrawal_commitment: EXISTING_WITHDRAWAL_COMMITMENT,
            oracle_certificate_hash,
            oracle_mode: quote.oracle_mode,
            matcher_receipt_batch_root,
            forced_action_batch_root,
            escape_only: false,
            encrypted_availability_root: next_encrypted_availability_root,
            mark_price: quote.ecx_usdd_index,
            liquidation_low: quote.ecx_usdd_low,
            liquidation_high: quote.ecx_usdd_high,
            funding_rate_ppm: 0,
            risk_params_hash: risk_params_hash(configuration.risk),
        },
        risk_params: configuration.risk,
        previous_state,
        next_state,
        previous_accounts,
        next_accounts,
        previous_positions,
        next_positions,
        previous_open_orders,
        next_open_orders,
        previous_deposit_nullifiers: vec![],
        previous_withdrawal_nullifiers: vec![],
        deposit_inbox: DepositInboxTransitionV1 {
            pending_entries: vec![],
            consumed_count: 0,
        },
        forced_inbox: ForcedInboxTransitionV1 {
            pending_entries: vec![],
            consumed_count: 0,
        },
        deposits,
        withdrawals,
        placements,
        cancellations,
        fills,
        liquidations,
    };

    let recovery_payload = canonical_availability_recovery_payload(
        &configuration,
        &transition,
        &[],
        &transition_settlement,
    )
    .unwrap();
    let availability_context = transition_availability_context(&transition.public);
    let (availability_bundle, availability_encryption_witness) =
        create_bundle_with_encryption_witness(
            availability_context,
            &recovery_payload,
            &availability_public,
        )
        .unwrap();
    let recovery_contributions = availability_custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.attest(&availability_bundle).unwrap())
        .collect::<Vec<_>>();
    let recovered = recover_witness(&availability_bundle, &recovery_contributions).unwrap();
    assert_eq!(recovered.as_bytes(), recovery_payload);
    let availability_custody_receipts = availability_custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.custody_receipt(&availability_bundle).unwrap())
        .collect::<Vec<_>>();

    let next_encrypted_availability_root = availability_bundle.root().unwrap();
    let final_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root,
        oracle_certificate_hash,
        oracle_mode: quote.oracle_mode,
        matcher_receipt_batch_root,
        collateral_settlement_root,
        forced_action_batch_root,
        escape_only: false,
        encrypted_availability_root: next_encrypted_availability_root,
    });
    transition.next_state.roots = StateRoots::from_private_state(
        &transition.next_accounts,
        &transition.next_positions,
        &transition.next_open_orders,
        &[],
        &[transition.withdrawals[0].request.request_id()],
        next_order_receipts_root(previous_receipts_root, final_batch_hash),
    )
    .unwrap();
    transition.public.batch_hash = final_batch_hash;
    transition.public.next_state_root = transition.next_state.state_root();
    transition.public.encrypted_availability_root = next_encrypted_availability_root;
    assert_eq!(
        canonical_availability_recovery_payload(
            &configuration,
            &transition,
            &[],
            &transition_settlement,
        )
        .unwrap(),
        recovery_payload,
        "availability-derived fields are neutralized without changing plaintext",
    );
    let mut alternate_derived_fields = transition.clone();
    alternate_derived_fields.public.batch_hash = [0x61; 32];
    alternate_derived_fields.public.next_state_root = [0x62; 32];
    alternate_derived_fields.public.encrypted_availability_root = [0x63; 32];
    alternate_derived_fields.next_state.roots.order_receipts = [0x64; 32];
    assert_eq!(
        canonical_availability_recovery_payload(
            &configuration,
            &alternate_derived_fields,
            &[],
            &transition_settlement,
        )
        .unwrap(),
        recovery_payload,
    );

    let state_domain: [u8; 32] = Sha256::digest(b"ECX/e2e-state-domain/v1").into();
    let journal_domain: [u8; 32] = Sha256::digest(b"ECX/e2e-journal-domain/v1").into();
    let encrypted_availability_root = tagged_hash(
        "ECX/e2e-encrypted-availability/v1",
        &[
            maker_receipt.body.availability_root,
            taker_receipt.body.availability_root,
        ]
        .concat(),
    );
    let forced_inbox_root = forced_inbox.head_root;
    let current_public_state = CovenantPublicStateV1 {
        version: COVENANT_STATE_VERSION,
        sequence: transition.previous_state.sequence,
        private_state_root: transition.previous_state.state_root(),
        encrypted_availability_root,
        forced_action_inbox_root: forced_inbox_root,
        deposit_inbox_root: deposit_inbox.head_root,
        configuration_hash: configuration.digest(),
    };
    let next_public_state = CovenantPublicStateV1 {
        version: COVENANT_STATE_VERSION,
        sequence: transition.next_state.sequence,
        private_state_root: transition.next_state.state_root(),
        encrypted_availability_root: next_encrypted_availability_root,
        forced_action_inbox_root: forced_inbox_root,
        deposit_inbox_root: deposit_inbox.head_root,
        configuration_hash: configuration.digest(),
    };

    let child_genesis = [0x81; 32];
    let previous_state_txid = [0x82; 32];
    let previous_output =
        prototype_state_output(current_public_state.state_hash(state_domain), [0x83; 32]);
    let prior_exchange_header_root =
        prototype_state_utxo_root(child_genesis, previous_state_txid, 0, &previous_output);
    let transition_tx: Transaction =
        elements_encode::deserialize(&transition_settlement.transaction).unwrap();
    let transition_txid = transition_tx.txid().to_byte_array();
    let proof_input = ProofInputV1 {
        binding: ProofBindingV1 {
            version: PROOF_BINDING_VERSION,
            transition_txid_consensus: transition_txid,
            prior_exchange_header_root,
            prior_parent_block_hash: parent_block_hash,
            prior_parent_height: parent_height,
            prior_parent_mtp: parent_mtp,
            public_state_domain_sha256: state_domain,
            transition_journal_domain_sha256: journal_domain,
            current: current_public_state,
            next: next_public_state,
        },
        configuration,
        truthcoin_consensus_proof,
        matcher_receipts: receipts,
        deposit_openings: vec![],
        transition_settlement,
        transition,
        availability_bundle: availability_bundle.encode().unwrap(),
        availability_custody_receipts,
        availability_encryption_witness,
    };
    if let Ok(dump_path) = std::env::var("ECX_DUMP_PROOF_INPUT") {
        struct DeferredV {
            program_id: [u8; 32],
            public_values: Vec<u8>,
        }
        impl ConsensusProofVerifier for DeferredV {
            fn verify(
                &self,
                program_id: [u8; 32],
                public_values: &[u8],
                proof_marker: &[u8],
            ) -> Result<(), ConsensusProofVerificationError> {
                if program_id != self.program_id
                    || public_values != self.public_values.as_slice()
                    || proof_marker
                        != ecx_truthcoin_proof::sp1_deferred_proof_marker(program_id, public_values)
                {
                    return Err(ConsensusProofVerificationError);
                }
                Ok(())
            }
        }
        let pid = live_pid.expect("live pid required for dump");
        let pv_bytes = ecx_truthcoin_proof::source_public_values_bytes(
            live_pv.as_ref().expect("live pv required for dump"),
        );
        let v = DeferredV {
            program_id: pid,
            public_values: pv_bytes,
        };
        // Disputed/ReduceOnly quotes reject non-reduce-only risk. For dump export,
        // strip placements/fills/liquidations and rebuild a no-risk commit transition.
        let mut proof_input = proof_input;
        if !matches!(
            proof_input.transition.public.oracle_mode,
            OracleMode::Normal
        ) {
            // Disputed allows withdrawals but forbids non-reduce-only risk.
            eprintln!(
                "live dump: stripping risk ops for {:?}",
                proof_input.transition.public.oracle_mode
            );
            proof_input.transition.placements.clear();
            proof_input.transition.fills.clear();
            proof_input.transition.liquidations.clear();
            proof_input.transition.cancellations.clear();
            proof_input.matcher_receipts.clear();
            // Flat positions (no trade). Keep withdrawal on withdrawer account.
            proof_input.transition.next_positions =
                proof_input.transition.previous_positions.clone();
            proof_input.transition.previous_open_orders = vec![];
            proof_input.transition.next_open_orders = vec![];
            let maker_acc = proof_input.transition.previous_accounts[0].clone();
            let taker_acc = proof_input.transition.previous_accounts[1].clone();
            let next_withdrawer = proof_input.transition.next_accounts[2].clone();
            proof_input.transition.next_accounts = vec![maker_acc, taker_acc, next_withdrawer];

            let prev_receipts = tagged_hash("ECX/e2e-order-receipts-genesis/v1", b"genesis");
            let previous_roots = StateRoots::from_private_state(
                &proof_input.transition.previous_accounts,
                &proof_input.transition.previous_positions,
                &proof_input.transition.previous_open_orders,
                &proof_input.transition.previous_deposit_nullifiers,
                &proof_input.transition.previous_withdrawal_nullifiers,
                prev_receipts,
            )
            .unwrap();
            proof_input.transition.previous_state.roots = previous_roots;
            proof_input.transition.previous_state.fee_pool = Amount(0);
            proof_input.transition.previous_state.matcher_sequence =
                proof_input.configuration.matcher.genesis_sequence;
            proof_input.transition.previous_state.matcher_receipt_hash =
                proof_input.configuration.matcher.genesis_receipt_hash;

            // Public fields needed before availability context / batch hash.
            proof_input.transition.public.funding_rate_ppm = 0;
            proof_input.transition.public.matcher_receipt_batch_root =
                central_matcher_receipt_batch_root(&proof_input.matcher_receipts);
            proof_input.transition.public.liquidation_batch_root =
                ecx_protocol_core::liquidation_batch_root(&proof_input.transition.liquidations);
            proof_input.transition.public.deposit_batch_root =
                deposit_batch_root(&proof_input.transition.deposits);
            proof_input.transition.public.withdrawal_batch_root =
                withdrawal_batch_root(&proof_input.transition.withdrawals);
            proof_input.transition.public.deposit_event_batch_root =
                ecx_protocol_core::deposit_event_batch_root(&[]);

            // Provisional next state (roots filled after final batch_hash).
            let mut next = proof_input.transition.previous_state.clone();
            next.sequence = proof_input.transition.previous_state.sequence + 1;
            next.total_withdrawals = Amount(100);
            next.fee_pool = Amount(0);
            next.last_processed_height = SIDECHAIN_HEIGHT;
            next.matcher_sequence = proof_input.transition.previous_state.matcher_sequence;
            next.matcher_receipt_hash = proof_input.transition.previous_state.matcher_receipt_hash;
            proof_input.transition.next_state = next;
            proof_input.transition.public.previous_sequence =
                proof_input.transition.previous_state.sequence;
            proof_input.transition.public.next_sequence =
                proof_input.transition.next_state.sequence;
            proof_input.transition.public.previous_state_root =
                proof_input.transition.previous_state.state_root();
            // Temporary next root; refreshed after next.roots set.
            proof_input.transition.public.next_state_root =
                proof_input.transition.next_state.state_root();

            // Availability first with temporary batch/enc roots, then finalize.
            proof_input.transition.public.encrypted_availability_root = [0x5a; 32];
            let op0 = transition_batch_hash(
                &proof_input.transition.deposits,
                &proof_input.transition.withdrawals,
                &proof_input.transition.placements,
                &proof_input.transition.cancellations,
                &proof_input.transition.fills,
                &proof_input.transition.liquidations,
            );
            proof_input.transition.public.batch_hash =
                transition_envelope_hash(&TransitionEnvelopeV4 {
                    operation_batch_hash: op0,
                    deposit_event_batch_root: proof_input
                        .transition
                        .public
                        .deposit_event_batch_root,
                    oracle_certificate_hash: proof_input.transition.public.oracle_certificate_hash,
                    oracle_mode: proof_input.transition.public.oracle_mode,
                    matcher_receipt_batch_root: proof_input
                        .transition
                        .public
                        .matcher_receipt_batch_root,
                    collateral_settlement_root: proof_input
                        .transition
                        .public
                        .collateral_settlement_root,
                    forced_action_batch_root: proof_input
                        .transition
                        .public
                        .forced_action_batch_root,
                    escape_only: false,
                    encrypted_availability_root: [0x5a; 32],
                });

            let recovery_payload = canonical_availability_recovery_payload(
                &proof_input.configuration,
                &proof_input.transition,
                &[],
                &proof_input.transition_settlement,
            )
            .expect("recovery payload");
            let availability_context =
                transition_availability_context(&proof_input.transition.public);
            let (availability_bundle, _availability_encryption_witness) =
                create_bundle_with_encryption_witness(
                    availability_context,
                    &recovery_payload,
                    &availability_public,
                )
                .expect("availability bundle");
            let enc_root = availability_bundle.root().unwrap();
            proof_input.transition.public.encrypted_availability_root = enc_root;

            // Final batch_hash with real enc root — order_receipts must use THIS hash.
            let op = transition_batch_hash(
                &proof_input.transition.deposits,
                &proof_input.transition.withdrawals,
                &proof_input.transition.placements,
                &proof_input.transition.cancellations,
                &proof_input.transition.fills,
                &proof_input.transition.liquidations,
            );
            let final_batch = transition_envelope_hash(&TransitionEnvelopeV4 {
                operation_batch_hash: op,
                deposit_event_batch_root: proof_input.transition.public.deposit_event_batch_root,
                oracle_certificate_hash: proof_input.transition.public.oracle_certificate_hash,
                oracle_mode: proof_input.transition.public.oracle_mode,
                matcher_receipt_batch_root: proof_input
                    .transition
                    .public
                    .matcher_receipt_batch_root,
                collateral_settlement_root: proof_input
                    .transition
                    .public
                    .collateral_settlement_root,
                forced_action_batch_root: proof_input.transition.public.forced_action_batch_root,
                escape_only: false,
                encrypted_availability_root: enc_root,
            });
            proof_input.transition.public.batch_hash = final_batch;

            let expected_receipts = next_order_receipts_root(prev_receipts, final_batch);
            let next_wd = [proof_input.transition.withdrawals[0].request.request_id()];
            let next_roots = StateRoots::from_private_state(
                &proof_input.transition.next_accounts,
                &proof_input.transition.next_positions,
                &proof_input.transition.next_open_orders,
                &proof_input.transition.previous_deposit_nullifiers,
                &next_wd,
                expected_receipts,
            )
            .unwrap();
            proof_input.transition.next_state.roots = next_roots;
            proof_input.transition.public.next_state_root =
                proof_input.transition.next_state.state_root();
            // Re-root previous after any previous_state field tweaks.
            proof_input.transition.public.previous_state_root =
                proof_input.transition.previous_state.state_root();

            // Rebuild availability once more with final public roots (context may bind them).
            let recovery_payload = canonical_availability_recovery_payload(
                &proof_input.configuration,
                &proof_input.transition,
                &[],
                &proof_input.transition_settlement,
            )
            .expect("recovery payload final");
            let availability_context =
                transition_availability_context(&proof_input.transition.public);
            let (availability_bundle, availability_encryption_witness) =
                create_bundle_with_encryption_witness(
                    availability_context,
                    &recovery_payload,
                    &availability_public,
                )
                .expect("availability bundle final");
            let enc_root = availability_bundle.root().unwrap();
            // If enc root changed, fix batch_hash + next receipts again.
            if enc_root != proof_input.transition.public.encrypted_availability_root {
                proof_input.transition.public.encrypted_availability_root = enc_root;
                let op = transition_batch_hash(
                    &proof_input.transition.deposits,
                    &proof_input.transition.withdrawals,
                    &proof_input.transition.placements,
                    &proof_input.transition.cancellations,
                    &proof_input.transition.fills,
                    &proof_input.transition.liquidations,
                );
                let final_batch = transition_envelope_hash(&TransitionEnvelopeV4 {
                    operation_batch_hash: op,
                    deposit_event_batch_root: proof_input
                        .transition
                        .public
                        .deposit_event_batch_root,
                    oracle_certificate_hash: proof_input.transition.public.oracle_certificate_hash,
                    oracle_mode: proof_input.transition.public.oracle_mode,
                    matcher_receipt_batch_root: proof_input
                        .transition
                        .public
                        .matcher_receipt_batch_root,
                    collateral_settlement_root: proof_input
                        .transition
                        .public
                        .collateral_settlement_root,
                    forced_action_batch_root: proof_input
                        .transition
                        .public
                        .forced_action_batch_root,
                    escape_only: false,
                    encrypted_availability_root: enc_root,
                });
                proof_input.transition.public.batch_hash = final_batch;
                let expected_receipts = next_order_receipts_root(prev_receipts, final_batch);
                let next_wd = [proof_input.transition.withdrawals[0].request.request_id()];
                proof_input.transition.next_state.roots = StateRoots::from_private_state(
                    &proof_input.transition.next_accounts,
                    &proof_input.transition.next_positions,
                    &proof_input.transition.next_open_orders,
                    &proof_input.transition.previous_deposit_nullifiers,
                    &next_wd,
                    expected_receipts,
                )
                .unwrap();
                proof_input.transition.public.next_state_root =
                    proof_input.transition.next_state.state_root();
            } else {
                proof_input.transition.public.encrypted_availability_root = enc_root;
            }

            proof_input.availability_bundle = availability_bundle.encode().unwrap();
            proof_input.availability_encryption_witness = availability_encryption_witness;
            proof_input.availability_custody_receipts = availability_custodians
                .iter()
                .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
                .map(|custodian| custodian.custody_receipt(&availability_bundle).unwrap())
                .collect::<Vec<_>>();

            // Covenant binding mirrors private state + final availability.
            let prev_enc = proof_input.binding.current.encrypted_availability_root;
            proof_input.binding.current = CovenantPublicStateV1 {
                version: COVENANT_STATE_VERSION,
                sequence: proof_input.transition.previous_state.sequence,
                private_state_root: proof_input.transition.previous_state.state_root(),
                encrypted_availability_root: prev_enc,
                forced_action_inbox_root: proof_input.binding.current.forced_action_inbox_root,
                deposit_inbox_root: proof_input.binding.current.deposit_inbox_root,
                configuration_hash: proof_input.configuration.digest(),
            };
            proof_input.binding.next = CovenantPublicStateV1 {
                version: COVENANT_STATE_VERSION,
                sequence: proof_input.transition.next_state.sequence,
                private_state_root: proof_input.transition.next_state.state_root(),
                encrypted_availability_root: proof_input
                    .transition
                    .public
                    .encrypted_availability_root,
                forced_action_inbox_root: proof_input.binding.next.forced_action_inbox_root,
                deposit_inbox_root: proof_input.binding.next.deposit_inbox_root,
                configuration_hash: proof_input.configuration.digest(),
            };
        }
        let res = execute_proof_with_truthcoin_verifier(&proof_input, &v)
            .expect("live-bound ProofInput host execute");
        eprintln!(
            "live-bound host execute OK pv_len={}",
            res.public_values.len()
        );
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_PROOF_INPUT_BYTES as u64)
            .serialize(&proof_input)
            .expect("serialize ProofInputV1");
        fs::write(&dump_path, &encoded).expect("write dump");
        eprintln!("dumped ProofInputV1 {} bytes to {dump_path}", encoded.len());
        // In dump mode, skip the synthetic TestDigestVerifier path assertions that
        // re-run with the live-bound input's different oracle surface.
        return;
    }
    assert!(execute_proof(&proof_input).is_err());
    let proof = execute_proof_with_truthcoin_verifier(&proof_input, &TestDigestVerifier)
        .expect("whole private transition verifies with authenticated test source");
    assert_eq!(
        proof.transition_journal.existing_withdrawal_commitment,
        EXISTING_WITHDRAWAL_COMMITMENT
    );
    assert_eq!(
        proof.transition_journal.next_state_root,
        proof_input.transition.next_state.state_root()
    );
    assert!(!contains_subslice(&proof.public_values, &maker.0));
    assert!(!contains_subslice(&proof.public_values, &taker.0));

    let mut arbitrary_availability_root = proof_input.clone();
    arbitrary_availability_root
        .binding
        .next
        .encrypted_availability_root = [0x66; 32];
    arbitrary_availability_root
        .transition
        .public
        .encrypted_availability_root = [0x66; 32];
    assert!(matches!(
        execute_proof_with_truthcoin_verifier(&arbitrary_availability_root, &TestDigestVerifier),
        Err(ProofError::BindingMismatch("availability bundle root"))
    ));

    let mut insufficient_custody = proof_input.clone();
    insufficient_custody
        .availability_custody_receipts
        .truncate(2);
    assert!(matches!(
        execute_proof_with_truthcoin_verifier(&insufficient_custody, &TestDigestVerifier),
        Err(ProofError::Availability(message)) if message.contains("at least three")
    ));

    // A second, perfectly canonical and decryptable bundle over arbitrary
    // same-length bytes cannot become an accepted root for this transition.
    let garbage_payload = vec![0x55; recovery_payload.len()];
    let (garbage_bundle, garbage_encryption_witness) = create_bundle_with_encryption_witness(
        transition_availability_context(&proof_input.transition.public),
        &garbage_payload,
        &availability_public,
    )
    .unwrap();
    let garbage_root = garbage_bundle.root().unwrap();
    let mut garbage_availability = proof_input.clone();
    garbage_availability.availability_bundle = garbage_bundle.encode().unwrap();
    garbage_availability.availability_custody_receipts = availability_custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.custody_receipt(&garbage_bundle).unwrap())
        .collect();
    garbage_availability.availability_encryption_witness = garbage_encryption_witness;
    garbage_availability
        .binding
        .next
        .encrypted_availability_root = garbage_root;
    garbage_availability
        .transition
        .public
        .encrypted_availability_root = garbage_root;
    assert!(matches!(
        execute_proof_with_truthcoin_verifier(&garbage_availability, &TestDigestVerifier),
        Err(ProofError::Availability(message))
            if message.contains("recovery payload does not match transition")
    ));

    let (wrong_context_bundle, wrong_context_witness) =
        create_bundle_with_encryption_witness([0xab; 32], &recovery_payload, &availability_public)
            .unwrap();
    let wrong_context_root = wrong_context_bundle.root().unwrap();
    let mut wrong_context = proof_input.clone();
    wrong_context.availability_bundle = wrong_context_bundle.encode().unwrap();
    wrong_context.availability_encryption_witness = wrong_context_witness;
    wrong_context.binding.next.encrypted_availability_root = wrong_context_root;
    wrong_context.transition.public.encrypted_availability_root = wrong_context_root;
    assert!(matches!(
        execute_proof_with_truthcoin_verifier(&wrong_context, &TestDigestVerifier),
        Err(ProofError::BindingMismatch("availability context"))
    ));

    let wrong_registry_secrets = (1_u8..=AVAILABILITY_CUSTODIAN_COUNT)
        .map(|index| CustodianSecrets::new(index, [0xb0 + index; 32], [0xc0 + index; 32]).unwrap())
        .collect::<Vec<_>>();
    let wrong_registry_public = wrong_registry_secrets
        .iter()
        .map(CustodianSecrets::public)
        .collect::<Vec<_>>();
    let (wrong_registry_bundle, wrong_registry_witness) = create_bundle_with_encryption_witness(
        transition_availability_context(&proof_input.transition.public),
        &recovery_payload,
        &wrong_registry_public,
    )
    .unwrap();
    let wrong_registry_root = wrong_registry_bundle.root().unwrap();
    let mut wrong_registry = proof_input.clone();
    wrong_registry.availability_bundle = wrong_registry_bundle.encode().unwrap();
    wrong_registry.availability_encryption_witness = wrong_registry_witness;
    wrong_registry.binding.next.encrypted_availability_root = wrong_registry_root;
    wrong_registry.transition.public.encrypted_availability_root = wrong_registry_root;
    assert!(matches!(
        execute_proof_with_truthcoin_verifier(&wrong_registry, &TestDigestVerifier),
        Err(ProofError::BindingMismatch(
            "availability custodian registry"
        ))
    ));

    let mut noncanonical_bundle = proof_input.clone();
    noncanonical_bundle.availability_bundle.push(0);
    assert!(matches!(
        execute_proof_with_truthcoin_verifier(&noncanonical_bundle, &TestDigestVerifier),
        Err(ProofError::Availability(_))
    ));

    // The reference Elements overlay keeps the legacy header as an exact
    // prefix. The miner authenticates only the complete critical-header
    // preimage against the slot-24 BIP301 record. It does not receive the M6,
    // Truthcoin transcript, transition proof, PXST preimage, or private state.
    let successor_output = prototype_state_output(
        proof_input.binding.next.state_hash(state_domain),
        proof.public_values_sha256,
    );
    let successor_header_root =
        prototype_state_utxo_root(child_genesis, transition_txid, 0, &successor_output);
    let source_parent_height = u32::try_from(PARENT_HEIGHT).unwrap();
    let successor_forced_root = proof_input.binding.next.forced_action_inbox_root;
    let successor_deposit_root = proof_input.binding.next.deposit_inbox_root;

    let checkpoint_height = u32::try_from(SIDECHAIN_HEIGHT).unwrap();
    let previous_child_block_hash = [0x85; 32];
    assert_eq!(
        prototype_withdrawal_inputs_commitment(WITHDRAWAL_OUTPOINT_TXID, 1, checkpoint_height),
        EXISTING_WITHDRAWAL_COMMITMENT,
    );
    let withdrawal_anchor = WithdrawalStateAnchorV1 {
        version: WithdrawalStateAnchorV1::VERSION,
        slot: BMM_SLOT,
        child_genesis_hash: child_genesis,
        checkpoint_height,
        previous_child_block_hash,
        existing_withdrawal_commitment: EXISTING_WITHDRAWAL_COMMITMENT,
        exchange_state_root: successor_header_root,
    };
    let mut fee_script = vec![0x6a, 0x08];
    fee_script.extend_from_slice(&1_u64.to_be_bytes());
    let mut withdrawal_commitment_script = vec![0x6a, 0x20];
    withdrawal_commitment_script.extend_from_slice(&EXISTING_WITHDRAWAL_COMMITMENT);
    let parent_m6_outputs = [
        (0, fee_script),
        (0, withdrawal_commitment_script),
        (99, withdrawal_script.as_bytes().to_vec()),
        (0, withdrawal_anchor.op_return_script().unwrap().to_vec()),
    ];
    let child_checkpoint = AuthenticatedChildCheckpointV1 {
        slot: BMM_SLOT,
        child_genesis_hash: child_genesis,
        checkpoint_height,
        previous_child_block_hash,
        exchange_state_root: successor_header_root,
    };
    let child_m6_scripts = parent_m6_outputs
        .iter()
        .map(|(_, script)| script.clone())
        .collect::<Vec<_>>();
    verify_child_withdrawal_state_commitment(
        &child_checkpoint,
        EXISTING_WITHDRAWAL_COMMITMENT,
        &child_m6_scripts,
    )
    .unwrap();
    let mut malformed_child_m6_scripts = child_m6_scripts.clone();
    *malformed_child_m6_scripts[3].last_mut().unwrap() ^= 1;
    assert!(verify_child_withdrawal_state_commitment(
        &child_checkpoint,
        EXISTING_WITHDRAWAL_COMMITMENT,
        &malformed_child_m6_scripts,
    )
    .is_err());
    let parent_m6 = prototype_child_blinded_m6(&parent_m6_outputs);
    let parent_m6id = bitcoin_double_sha256(&parent_m6);
    let m6_envelope = WithdrawalBundleEnvelopeV1 {
        version: WITHDRAWAL_BUNDLE_ENVELOPE_VERSION,
        checkpoint_height,
        checkpoint_block_hash: [0x86; 32],
        m6_no_witness: parent_m6,
    };
    let m6_envelope_script = m6_envelope.coinbase_script().unwrap();
    m6_envelope
        .verify_coinbase_script(&m6_envelope_script, parent_m6id)
        .unwrap();
    let mut substituted_m6_envelope = m6_envelope_script.clone();
    *substituted_m6_envelope.last_mut().unwrap() ^= 1;
    assert!(m6_envelope
        .verify_coinbase_script(&substituted_m6_envelope, parent_m6id)
        .is_err());

    let header_version = REQUIRED_ECX_WITHDRAWAL_HEADER_MASK | 3;
    let mut legacy_elements_bmm_header = vec![0x55; 200];
    legacy_elements_bmm_header[0..4].copy_from_slice(&header_version.to_le_bytes());
    legacy_elements_bmm_header[4..36].copy_from_slice(&previous_child_block_hash);
    legacy_elements_bmm_header[68..100].copy_from_slice(&parent_m6id);
    // GetBmmCriticalHash clears only this existing field. Withdrawal and all
    // additive ECX commitments remain in the exact serialized preimage.
    legacy_elements_bmm_header[100..132].fill(0);
    let extended_header = prototype_append_header_state_suffix(
        &legacy_elements_bmm_header,
        successor_header_root,
        successor_forced_root,
        successor_deposit_root,
        source_parent_height,
    );
    assert_eq!(
        &extended_header[..legacy_elements_bmm_header.len()],
        legacy_elements_bmm_header.as_slice()
    );
    let mut expected_suffix = Vec::with_capacity(100);
    expected_suffix.extend_from_slice(&successor_header_root);
    expected_suffix.extend_from_slice(&successor_forced_root);
    expected_suffix.extend_from_slice(&successor_deposit_root);
    expected_suffix.extend_from_slice(&source_parent_height.to_le_bytes());
    assert_eq!(
        extended_header.len(),
        legacy_elements_bmm_header.len() + 100
    );
    assert_eq!(
        &extended_header[legacy_elements_bmm_header.len()..],
        expected_suffix.as_slice()
    );
    let parent_config = ParentEnforcerConfigV1 {
        version: PARENT_ENFORCER_ADAPTER_VERSION,
        sidechain_slot: BMM_SLOT,
        child_genesis_hash: child_genesis,
    };
    let parent_checkpoint = HeaderOnlyChildContextV1 {
        version: PARENT_ENFORCER_ADAPTER_VERSION,
        child_genesis_hash: child_genesis,
        checkpoint_height,
        previous_child_block_hash,
        expected_header_version: header_version,
        critical_header_len: u32::try_from(extended_header.len()).unwrap(),
    };
    let parent_bmm = LocallyValidatedBmmCommitmentV1 {
        version: PARENT_ENFORCER_ADAPTER_VERSION,
        sidechain_slot: BMM_SLOT,
        critical_hash: bitcoin_double_sha256(&extended_header),
        approving_parent_block_hash: parent_block_hash,
        approving_parent_height: source_parent_height,
    };
    let parent_approval = verify_miner_header_commitment(
        &parent_config,
        &parent_bmm,
        &parent_checkpoint,
        &extended_header,
    )
    .unwrap();
    assert_eq!(parent_approval.withdrawal_bundle_hash, parent_m6id);

    // Cross-layer tampering fails at the layer that authenticates it.
    let mut bad_receipt = maker_receipt;
    bad_receipt.body.command_hash[0] ^= 1;
    assert!(bad_receipt.verify(&matcher).is_err());

    let mut bad_oracle = proof_input.clone();
    bad_oracle
        .truthcoin_consensus_proof
        .public_values
        .lmsr_snapshot
        .yes_probability_ppb -= 1;
    assert!(execute_proof_with_truthcoin_verifier(&bad_oracle, &TestDigestVerifier).is_err());

    let mut bad_private_leaf = proof_input.clone();
    bad_private_leaf.transition.next_accounts[0].collateral.0 += 1;
    assert!(execute_proof_with_truthcoin_verifier(&bad_private_leaf, &TestDigestVerifier).is_err());

    let mut bad_settlement = proof_input.clone();
    bad_settlement.transition_settlement.collateral_outputs[0].amount += 1;
    assert!(execute_proof_with_truthcoin_verifier(&bad_settlement, &TestDigestVerifier).is_err());

    let suffix_start = legacy_elements_bmm_header.len();
    for mutated_field_offset in [0, 32, 64, 96] {
        let mut bad_header = extended_header.clone();
        bad_header[suffix_start + mutated_field_offset] ^= 1;
        assert!(verify_miner_header_commitment(
            &parent_config,
            &parent_bmm,
            &parent_checkpoint,
            &bad_header,
        )
        .is_err());
    }

    let mut bad_checkpoint = parent_checkpoint;
    bad_checkpoint.previous_child_block_hash[0] ^= 1;
    assert!(verify_miner_header_commitment(
        &parent_config,
        &parent_bmm,
        &bad_checkpoint,
        &extended_header,
    )
    .is_err());
    // BIP300 separately compares the opaque approved bundle hash to the final
    // M6. The ECX-specific miner interface never parses that transaction.
    let mut bad_parent_m6 = prototype_child_blinded_m6(&parent_m6_outputs);
    *bad_parent_m6.last_mut().unwrap() ^= 1;
    assert_ne!(
        bitcoin_double_sha256(&bad_parent_m6),
        parent_approval.withdrawal_bundle_hash
    );

    // This uses a deterministic digest verifier only as a non-cryptographic
    // stand-in for all three recursive SP1 receipts. Every other V2 relation
    // is the production relation: authenticated source public values, unified
    // confidential settlement, persistent risk roots, canonical recovery
    // payload encryption, and the exact 850-byte V5 public-values boundary.
    exercise_complete_v2_proof_relation(
        &proof_input,
        &maker_secret,
        &availability_custodians,
        &availability_public,
    );
}

struct V2SubscriptionInboxFixture {
    previous_state: BondInboxStateV2,
    next_state: BondInboxStateV2,
    previous_outcome_root: Hash32,
    next_outcome_root: Hash32,
    transition: BondInboxTransitionV2,
    outcomes: Vec<BondInboxProcessedOutcomeV2>,
    source_evidence: Vec<BondInboxSourceTransactionEvidenceV2>,
}

struct V2RecoveredInboxFixture {
    next_state: BondInboxStateV2,
    next_outcome_root: Hash32,
    transition: BondInboxTransitionV2,
    outcomes: Vec<BondInboxProcessedOutcomeV2>,
    source_evidence: Vec<BondInboxSourceTransactionEvidenceV2>,
    entry: BondInboxEntryV2,
    source_transaction: Vec<u8>,
}

/// Admit and recover one arbitrary action through the real encrypted
/// inbox/source-transaction lane, optionally with its exact staging output.
/// This is independent of the recursive
/// `TestDigestVerifier`: custody signatures, Shamir recovery contributions,
/// annex parsing and source binding are all verified by their production Rust
/// relations.
#[allow(clippy::too_many_arguments)]
fn build_v2_recovered_inbox_source(
    configuration: &FrozenConfigurationV2,
    previous_state: BondInboxStateV2,
    previous_outcome_root: Hash32,
    action: BondInboxUserActionV2,
    signer_secret: &SecretKey,
    custodians: &[CustodianSecrets],
    public: &[ecx_witness_availability::CustodianPublic],
    observed_sidechain_height: u64,
    observed_parent_height: u64,
    staging: Option<(TxOut, Hash32, Hash32, u64)>,
) -> V2RecoveredInboxFixture {
    let marker_vout = u32::from(staging.is_some());
    let source_authorization_commitment = match &staging {
        Some((staging_output, staging_intent_id, refund_script_sha256, refund_height)) => {
            bond_inbox_staging_source_authorization_commitment_v2(
                &elements_encode::serialize(staging_output),
                *staging_intent_id,
                *refund_script_sha256,
                *refund_height,
            )
            .unwrap()
        }
        None => bond_inbox_no_staging_source_authorization_commitment_v2(
            configuration.base.chain_id,
            configuration.digest(),
            action.signer(),
            action.action_id(),
            marker_vout,
        )
        .unwrap(),
    };
    let payload = BondInboxAvailablePayloadV2 {
        commitment_blinding: [0xb3; 32],
        canonical_signed_action: action.canonical_signed_bytes(),
        settlement_witness_commitment: action.settlement_witness_commitment(),
        source_authorization_commitment,
    };
    let payload_commitment = BondInboxAvailablePayloadV2::commitment(
        action.kind(),
        payload.commitment_blinding,
        &payload.canonical_signed_action,
        payload.settlement_witness_commitment,
        source_authorization_commitment,
    );
    let mut marker = BondInboxMarkerV2 {
        version: BOND_INBOX_MARKER_VERSION,
        kind: action.kind(),
        chain_id: configuration.base.chain_id,
        configuration_hash: configuration.digest(),
        signer: action.signer(),
        action_id: action.action_id(),
        staging_intent_id: staging.as_ref().map_or([0; 32], |value| value.1),
        staging_vout: staging.as_ref().map_or(u32::MAX, |_| 0),
        refund_script_sha256: staging.as_ref().map_or([0; 32], |value| value.2),
        refund_not_before_parent_height: staging.as_ref().map_or(0, |value| value.3),
        payload_commitment,
        availability_scheme_hash: configuration.base.availability.scheme_hash,
        availability_custodian_registry_hash: configuration
            .base
            .availability
            .custodian_registry_hash,
        availability_bundle_root: [0xb4; 32],
        availability_context: [0; 32],
        availability_receipt_root: [0xb5; 32],
        availability_bundle_len: 1,
        availability_receipt_bitmap: 0b111,
        source_authorization_commitment,
        signature: Signature64([0; 64]),
    };
    marker.availability_context = marker.expected_availability_context();
    let (bundle, _) = create_bundle_with_encryption_witness(
        marker.availability_context,
        &payload.canonical_bytes(),
        public,
    )
    .unwrap();
    let canonical_encrypted_bundle = bundle.encode().unwrap();
    let recovery_contributions = custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.attest(&bundle).unwrap())
        .collect::<Vec<_>>();
    let custody_receipts = custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.custody_receipt(&bundle).unwrap())
        .map(|receipt| BondInboxCustodyReceiptV2 {
            custodian_index: receipt.custodian_index - 1,
            exact_receipt_bytes: receipt.encode_canonical().unwrap().to_vec(),
        })
        .collect::<Vec<_>>();
    marker.availability_bundle_root =
        bond_inbox_availability_bundle_root_v2(&canonical_encrypted_bundle).unwrap();
    marker.availability_bundle_len = u32::try_from(canonical_encrypted_bundle.len()).unwrap();
    let (receipt_root, receipt_bitmap) =
        canonical_bond_inbox_custody_receipts_v2(&marker, &custody_receipts).unwrap();
    marker.availability_receipt_root = receipt_root;
    marker.availability_receipt_bitmap = receipt_bitmap;
    marker = marker.sign(signer_secret).unwrap();

    let marker_payload = marker
        .payload_bytes(configuration.bond_inbox_max_bundle_bytes)
        .unwrap();
    let mut marker_script = vec![elements::opcodes::all::OP_RETURN.into_u8()];
    marker_script.push(elements::opcodes::all::OP_PUSHDATA2.into_u8());
    marker_script.extend_from_slice(&u16::try_from(marker_payload.len()).unwrap().to_le_bytes());
    marker_script.extend_from_slice(&marker_payload);
    let mut input = TxIn {
        previous_output: OutPoint::new(elements::Txid::from_byte_array([0xb6; 32]), 0),
        ..TxIn::default()
    };
    input.witness.script_witness = vec![
        vec![0xb7; 64],
        bond_inbox_source_annex_v2(&canonical_encrypted_bundle, &custody_receipts).unwrap(),
    ];
    let marker_output = TxOut {
        asset: ConfidentialAsset::Explicit(AssetId::from_byte_array(
            configuration.base.policy_asset_id,
        )),
        value: Value::Explicit(0),
        nonce: Nonce::Null,
        script_pubkey: Script::from(marker_script),
        witness: Default::default(),
    };
    let output = match staging {
        Some((staging_output, ..)) => vec![staging_output, marker_output],
        None => vec![marker_output],
    };
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![input],
        output,
    };
    let source_transaction = elements_encode::serialize(&transaction);
    let exact_witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
    let entry = BondInboxEntryV2 {
        version: BondInboxEntryV2::VERSION,
        index: previous_state.entry_count,
        previous_root: previous_state.head_root,
        observed_sidechain_height,
        observed_parent_height,
        source_block_hash: tagged_hash("ECX/test-v18-inbox-source-block/v2", &action.action_id()),
        source_txid: transaction.txid().to_byte_array(),
        source_wtxid: transaction.wtxid().to_byte_array(),
        source_transaction_len: u32::try_from(source_transaction.len()).unwrap(),
        source_witness_sha256: bond_inbox_source_witness_sha256_v2(&exact_witness).unwrap(),
        source_witness_len: u32::try_from(exact_witness.len()).unwrap(),
        source_tx_index: 0,
        marker_vout,
        marker,
    };
    entry
        .validate(
            configuration.base.availability,
            configuration.bond_inbox_max_bundle_bytes,
            configuration.bond_inbox_refund_minimum_parent_blocks,
        )
        .unwrap();
    verify_bond_inbox_source_transaction_v2(
        &entry,
        &source_transaction,
        &canonical_encrypted_bundle,
        &custody_receipts,
        configuration,
    )
    .unwrap();
    let next_root = entry.next_root();
    let next_state = BondInboxStateV2 {
        head_root: next_root,
        entry_count: entry.index + 1,
        processed_root: next_root,
        cursor: entry.index + 1,
    };
    let outcome = BondInboxProcessedOutcomeV2 {
        version: BondInboxProcessedOutcomeV2::VERSION,
        entry_index: entry.index,
        entry_hash: entry.entry_hash(),
        marker_kind: entry.marker.kind,
        marker_action_id: entry.marker.action_id,
        disposition: BondInboxProcessedDispositionV2::Accepted,
    };
    let next_outcome_root =
        bond_inbox_outcome_next_root_v2(previous_outcome_root, &outcome).unwrap();
    let recovery_evidence = BondInboxEntryRecoveryEvidenceV2 {
        entry_index: entry.index,
        canonical_encrypted_bundle,
        custody_receipts,
        recovery_contributions,
    };
    V2RecoveredInboxFixture {
        next_state,
        next_outcome_root,
        transition: BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: entry.entry_hash(),
                payload,
            }],
        },
        outcomes: vec![outcome],
        source_evidence: vec![BondInboxSourceTransactionEvidenceV2 {
            source_wtxid: entry.source_wtxid,
            source_transaction: source_transaction.clone(),
            entries: vec![recovery_evidence],
        }],
        entry,
        source_transaction,
    }
}

struct V2EnqueueInboxFixture {
    recovered: V2RecoveredInboxFixture,
    signed: SignedRedemptionEnqueueV2,
    destination_script_sha256: Hash32,
    staging_script_sha256: Hash32,
    staging_asset_blinding_factor: Hash32,
    staging_value_blinding_factor: Hash32,
}

#[allow(clippy::too_many_arguments)]
fn build_v2_enqueue_inbox_source(
    configuration: &FrozenConfigurationV2,
    previous_state: BondInboxStateV2,
    previous_outcome_root: Hash32,
    signer_secret: &SecretKey,
    account_nonce: u64,
    requested_share_atoms: u64,
    custodians: &[CustodianSecrets],
    public: &[ecx_witness_availability::CustodianPublic],
    observed_sidechain_height: u64,
    observed_parent_height: u64,
) -> V2EnqueueInboxFixture {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    let keypair = Keypair::from_secret_key(&Secp256k1::new(), signer_secret);
    let (signer, _) = XOnlyPublicKey::from_keypair(&keypair);
    let claimant = XOnlyKey(signer.serialize());
    let holder_script = Script::from(vec![0x51, 0x73]);
    let destination_script = Script::from(vec![0x51, 0x74]);
    let holder_script_sha256: Hash32 = Sha256::digest(holder_script.as_bytes()).into();
    let destination_script_sha256: Hash32 = Sha256::digest(destination_script.as_bytes()).into();
    let refund_not_before_parent_height = observed_parent_height
        .checked_add(u64::from(
            configuration.bond_inbox_refund_minimum_parent_blocks,
        ))
        .unwrap();
    let mut action = RedemptionEnqueueV2 {
        version: RedemptionEnqueueV2::VERSION,
        chain_id: configuration.base.chain_id,
        configuration_hash: configuration.digest(),
        claimant,
        account_nonce,
        requested_share_atoms,
        destination_script_hash: destination_script_sha256,
        holder_script_sha256,
        intent_salt: [0xb8; 32],
        refund_script_sha256: holder_script_sha256,
        refund_not_before_parent_height,
        bond_input_opening_commitment: [0; 32],
        queue_output_opening_commitment: [0; 32],
    };
    let staging_intent_id = action.stable_intent_id();
    let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
        chain_id: action.chain_id,
        configuration_hash: action.configuration_hash,
        marker_signer: claimant,
        stable_intent_id: staging_intent_id,
        staging_vout: 0,
        refund_script_sha256: action.refund_script_sha256,
        refund_not_before_parent_height,
    };
    let staging_script =
        bond_inbox_redemption_staging_script_v2(configuration, renderer_input).unwrap();
    let staging_script_sha256: Hash32 = Sha256::digest(staging_script.as_bytes()).into();
    let claimant_commitment = action.claimant_commitment();
    let staging_asset_blinding_factor = [0xb9; 32];
    let staging_value_blinding_factor = [0xba; 32];
    let provisional_input = BondInputOpeningV2 {
        input_index: 2,
        previous_transaction: vec![],
        previous_vout: 0,
        amount: requested_share_atoms,
        asset_blinding_factor: staging_asset_blinding_factor,
        value_blinding_factor: staging_value_blinding_factor,
        role: BondInputRoleV2::StagedRedemptionEnqueue {
            redemption_id: [0; 32],
            staging_intent_id,
            claimant: claimant_commitment,
            staging_script_sha256,
            source_txid: [0; 32],
            source_vout: 0,
        },
    };
    let provisional_output = BondOutputOpeningV2 {
        output_index: 3,
        amount: requested_share_atoms,
        asset_blinding_factor: [0xbb; 32],
        value_blinding_factor: [0xbc; 32],
        role: BondOutputRoleV2::QueuedRedemptionEntry {
            redemption_id: [0; 32],
            staging_intent_id,
            claimant: claimant_commitment,
            destination_script_sha256,
        },
    };
    action.bond_input_opening_commitment =
        redemption_enqueue_bond_input_opening_commitment_v2(&provisional_input, configuration)
            .unwrap();
    action.queue_output_opening_commitment =
        redemption_enqueue_queue_output_opening_commitment_v2(&provisional_output, configuration)
            .unwrap();
    let signed = SignedRedemptionEnqueueV2::sign(action, signer_secret).unwrap();
    signed.verify().unwrap();

    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let staging_abf = AssetBlindingFactor::from_slice(&staging_asset_blinding_factor).unwrap();
    let staging_vbf = ValueBlindingFactor::from_slice(&staging_value_blinding_factor).unwrap();
    let staging_secrets =
        TxOutSecrets::new(bond_asset, staging_abf, requested_share_atoms, staging_vbf);
    let mut rng = StdRng::from_seed([0xbd; 32]);
    let zkp = ZkpSecp256k1::new();
    let staging_output = TxOut::with_txout_secrets(
        &mut rng,
        &zkp,
        staging_script,
        ZkpPublicKey::from_secret_key(&zkp, &ZkpSecretKey::from_slice(&[0xbe; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xbf; 32]).unwrap(),
        staging_secrets,
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            requested_share_atoms,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let recovered = build_v2_recovered_inbox_source(
        configuration,
        previous_state,
        previous_outcome_root,
        BondInboxUserActionV2::RedemptionEnqueue(signed.clone()),
        signer_secret,
        custodians,
        public,
        observed_sidechain_height,
        observed_parent_height,
        Some((
            staging_output,
            staging_intent_id,
            holder_script_sha256,
            refund_not_before_parent_height,
        )),
    );
    V2EnqueueInboxFixture {
        recovered,
        signed,
        destination_script_sha256,
        staging_script_sha256,
        staging_asset_blinding_factor,
        staging_value_blinding_factor,
    }
}

/// Build a genuine V1 encrypted availability bundle, three exact Ed25519
/// custody receipts and three signed Shamir recovery contributions, then bind
/// them to one canonical Elements key-path annex source transaction. The
/// transaction's 64-byte key-path item is fixture material because this test
/// has no active UTXO set; every inbox/recovery cryptographic relation itself
/// is real and is rechecked by `verify_proof_input_v2`.
fn build_v2_subscription_inbox_source(
    configuration: &FrozenConfigurationV2,
    signed_subscription: &SignedBondSubscriptionV2,
    signer_secret: &SecretKey,
    custodians: &[CustodianSecrets],
    public: &[ecx_witness_availability::CustodianPublic],
    transition_sidechain_height: u64,
    observed_parent_height: u64,
) -> V2SubscriptionInboxFixture {
    let action = BondInboxUserActionV2::Subscription(signed_subscription.clone());
    let marker_vout = 0u32;
    let source_authorization_commitment = bond_inbox_no_staging_source_authorization_commitment_v2(
        configuration.base.chain_id,
        configuration.digest(),
        action.signer(),
        action.action_id(),
        marker_vout,
    )
    .unwrap();
    let payload = BondInboxAvailablePayloadV2 {
        commitment_blinding: [0xdc; 32],
        canonical_signed_action: action.canonical_signed_bytes(),
        settlement_witness_commitment: action.settlement_witness_commitment(),
        source_authorization_commitment,
    };
    let payload_commitment = BondInboxAvailablePayloadV2::commitment(
        action.kind(),
        payload.commitment_blinding,
        &payload.canonical_signed_action,
        payload.settlement_witness_commitment,
        source_authorization_commitment,
    );
    let mut marker = BondInboxMarkerV2 {
        version: BOND_INBOX_MARKER_VERSION,
        kind: action.kind(),
        chain_id: configuration.base.chain_id,
        configuration_hash: configuration.digest(),
        signer: action.signer(),
        action_id: action.action_id(),
        staging_intent_id: [0; 32],
        staging_vout: u32::MAX,
        refund_script_sha256: [0; 32],
        refund_not_before_parent_height: 0,
        payload_commitment,
        availability_scheme_hash: configuration.base.availability.scheme_hash,
        availability_custodian_registry_hash: configuration
            .base
            .availability
            .custodian_registry_hash,
        availability_bundle_root: [0x41; 32],
        availability_context: [0; 32],
        availability_receipt_root: [0x42; 32],
        availability_bundle_len: 1,
        availability_receipt_bitmap: 0b111,
        source_authorization_commitment,
        signature: Signature64([0; 64]),
    };
    marker.availability_context = marker.expected_availability_context();
    let (bundle, _) = create_bundle_with_encryption_witness(
        marker.availability_context,
        &payload.canonical_bytes(),
        public,
    )
    .unwrap();
    let canonical_encrypted_bundle = bundle.encode().unwrap();
    let recovery_contributions = custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.attest(&bundle).unwrap())
        .collect::<Vec<_>>();
    let custody_receipts_v1 = custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.custody_receipt(&bundle).unwrap())
        .collect::<Vec<_>>();
    let custody_receipts = custody_receipts_v1
        .iter()
        .map(|receipt| BondInboxCustodyReceiptV2 {
            custodian_index: receipt.custodian_index - 1,
            exact_receipt_bytes: receipt.encode_canonical().unwrap().to_vec(),
        })
        .collect::<Vec<_>>();
    marker.availability_bundle_root =
        bond_inbox_availability_bundle_root_v2(&canonical_encrypted_bundle).unwrap();
    marker.availability_bundle_len = u32::try_from(canonical_encrypted_bundle.len()).unwrap();
    let (receipt_root, receipt_bitmap) =
        canonical_bond_inbox_custody_receipts_v2(&marker, &custody_receipts).unwrap();
    marker.availability_receipt_root = receipt_root;
    marker.availability_receipt_bitmap = receipt_bitmap;
    marker = marker.sign(signer_secret).unwrap();
    for receipt in &custody_receipts {
        assert_ne!(
            bond_inbox_custody_receipt_binding_digest_v2(&marker, receipt.custodian_index).unwrap(),
            [0; 32]
        );
    }

    let marker_payload = marker
        .payload_bytes(configuration.bond_inbox_max_bundle_bytes)
        .unwrap();
    let mut marker_script = vec![elements::opcodes::all::OP_RETURN.into_u8()];
    marker_script.push(elements::opcodes::all::OP_PUSHDATA2.into_u8());
    marker_script.extend_from_slice(&u16::try_from(marker_payload.len()).unwrap().to_le_bytes());
    marker_script.extend_from_slice(&marker_payload);
    let mut input = TxIn {
        previous_output: OutPoint::new(elements::Txid::from_byte_array([0xdd; 32]), 0),
        ..TxIn::default()
    };
    input.witness.script_witness = vec![
        vec![0x31; 64],
        bond_inbox_source_annex_v2(&canonical_encrypted_bundle, &custody_receipts).unwrap(),
    ];
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![input],
        output: vec![TxOut {
            asset: ConfidentialAsset::Explicit(AssetId::from_byte_array(
                configuration.base.policy_asset_id,
            )),
            value: Value::Explicit(0),
            nonce: Nonce::Null,
            script_pubkey: Script::from(marker_script),
            witness: Default::default(),
        }],
    };
    let source_transaction = elements_encode::serialize(&transaction);
    let exact_witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
    let previous_state = BondInboxStateV2::genesis(
        configuration.bond_inbox_domain,
        configuration.base.chain_id,
        configuration.digest(),
    )
    .unwrap();
    let entry = BondInboxEntryV2 {
        version: BondInboxEntryV2::VERSION,
        index: 0,
        previous_root: previous_state.head_root,
        observed_sidechain_height: transition_sidechain_height - 1,
        observed_parent_height,
        source_block_hash: [0xde; 32],
        source_txid: transaction.txid().to_byte_array(),
        source_wtxid: transaction.wtxid().to_byte_array(),
        source_transaction_len: u32::try_from(source_transaction.len()).unwrap(),
        source_witness_sha256: bond_inbox_source_witness_sha256_v2(&exact_witness).unwrap(),
        source_witness_len: u32::try_from(exact_witness.len()).unwrap(),
        source_tx_index: 0,
        marker_vout,
        marker,
    };
    entry
        .validate(
            configuration.base.availability,
            configuration.bond_inbox_max_bundle_bytes,
            configuration.bond_inbox_refund_minimum_parent_blocks,
        )
        .unwrap();
    let next_root = entry.next_root();
    let next_state = BondInboxStateV2 {
        head_root: next_root,
        entry_count: 1,
        processed_root: next_root,
        cursor: 1,
    };
    let previous_outcome_root = bond_inbox_outcome_genesis_root_v2(
        configuration.bond_inbox_domain,
        configuration.base.chain_id,
        configuration.digest(),
    )
    .unwrap();
    let outcome = BondInboxProcessedOutcomeV2 {
        version: BondInboxProcessedOutcomeV2::VERSION,
        entry_index: entry.index,
        entry_hash: entry.entry_hash(),
        marker_kind: entry.marker.kind,
        marker_action_id: entry.marker.action_id,
        disposition: BondInboxProcessedDispositionV2::Accepted,
    };
    let next_outcome_root =
        bond_inbox_outcome_next_root_v2(previous_outcome_root, &outcome).unwrap();
    V2SubscriptionInboxFixture {
        previous_state,
        next_state,
        previous_outcome_root,
        next_outcome_root,
        transition: BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![BondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: entry.entry_hash(),
                payload,
            }],
        },
        outcomes: vec![outcome],
        source_evidence: vec![BondInboxSourceTransactionEvidenceV2 {
            source_wtxid: entry.source_wtxid,
            source_transaction,
            entries: vec![BondInboxEntryRecoveryEvidenceV2 {
                entry_index: entry.index,
                canonical_encrypted_bundle,
                custody_receipts,
                recovery_contributions,
            }],
        }],
    }
}

struct V2ExpiredUnavailableInboxFixture {
    next_state: BondInboxStateV2,
    next_outcome_root: Hash32,
    transition: BondInboxTransitionV2,
    outcomes: Vec<BondInboxProcessedOutcomeV2>,
}

/// Construct a node-admissible redemption-enqueue source transaction consumed
/// by the public `ExpiredUnavailable` disposition at its +6 inclusion
/// deadline. Private recovery shares are intentionally absent from the outer
/// proof input. The encrypted bundle and exact custody receipts are still
/// built and checked here to prove this entry entered the authenticated lane;
/// its staging output remains locked until the separately signed +12 refund.
#[allow(clippy::too_many_arguments)]
fn build_v2_expired_unavailable_inbox_source(
    configuration: &FrozenConfigurationV2,
    previous_state: BondInboxStateV2,
    previous_outcome_root: Hash32,
    signer_secret: &SecretKey,
    custodians: &[CustodianSecrets],
    public: &[ecx_witness_availability::CustodianPublic],
    observed_sidechain_height: u64,
    observed_parent_height: u64,
    refund_not_before_parent_height: u64,
) -> V2ExpiredUnavailableInboxFixture {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, signer_secret);
    let (signer, _) = XOnlyPublicKey::from_keypair(&keypair);
    let signer = XOnlyKey(signer.serialize());
    let refund_script = Script::from(vec![0x51, 0x75]);
    let destination_script = Script::from(vec![0x51, 0x76]);
    let refund_script_sha256: Hash32 = Sha256::digest(refund_script.as_bytes()).into();
    let destination_script_sha256: Hash32 = Sha256::digest(destination_script.as_bytes()).into();
    let mut action = RedemptionEnqueueV2 {
        version: RedemptionEnqueueV2::VERSION,
        chain_id: configuration.base.chain_id,
        configuration_hash: configuration.digest(),
        claimant: signer,
        account_nonce: 77,
        requested_share_atoms: 25,
        destination_script_hash: destination_script_sha256,
        holder_script_sha256: refund_script_sha256,
        intent_salt: [0x81; 32],
        refund_script_sha256,
        refund_not_before_parent_height,
        // Escape processing never consumes the staging output. These still
        // must be nonzero because the signed action is canonical and valid.
        bond_input_opening_commitment: [0x82; 32],
        queue_output_opening_commitment: [0x83; 32],
    };
    // Make this fixture distinct when testing -1/exact/+1 boundaries while
    // retaining a valid signed action and source transaction for each case.
    action.intent_salt[0] ^= u8::try_from(refund_not_before_parent_height & 0xff).unwrap();
    let signed = SignedRedemptionEnqueueV2::sign(action, signer_secret).unwrap();
    let user_action = BondInboxUserActionV2::RedemptionEnqueue(signed.clone());
    let staging_vout = 0u32;
    let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
        chain_id: signed.action.chain_id,
        configuration_hash: signed.action.configuration_hash,
        marker_signer: signed.action.claimant,
        stable_intent_id: signed.action.stable_intent_id(),
        staging_vout,
        refund_script_sha256: signed.action.refund_script_sha256,
        refund_not_before_parent_height: signed.action.refund_not_before_parent_height,
    };

    let mut rng = StdRng::from_seed([0x84; 32]);
    let zkp = ZkpSecp256k1::new();
    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let staging = TxOut::with_txout_secrets(
        &mut rng,
        &zkp,
        bond_inbox_redemption_staging_script_v2(configuration, renderer_input).unwrap(),
        ZkpPublicKey::from_secret_key(&zkp, &ZkpSecretKey::from_slice(&[0x85; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x86; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0x87; 32]).unwrap(),
            signed.action.requested_share_atoms,
            ValueBlindingFactor::from_slice(&[0x88; 32]).unwrap(),
        ),
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            signed.action.requested_share_atoms,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let marker_vout = 1u32;
    let source_authorization_commitment = bond_inbox_staging_source_authorization_commitment_v2(
        &elements_encode::serialize(&staging),
        signed.action.stable_intent_id(),
        refund_script_sha256,
        refund_not_before_parent_height,
    )
    .unwrap();
    let payload = BondInboxAvailablePayloadV2 {
        commitment_blinding: [0x89; 32],
        canonical_signed_action: user_action.canonical_signed_bytes(),
        settlement_witness_commitment: user_action.settlement_witness_commitment(),
        source_authorization_commitment,
    };
    let payload_commitment = BondInboxAvailablePayloadV2::commitment(
        user_action.kind(),
        payload.commitment_blinding,
        &payload.canonical_signed_action,
        payload.settlement_witness_commitment,
        source_authorization_commitment,
    );
    let mut marker = BondInboxMarkerV2 {
        version: BOND_INBOX_MARKER_VERSION,
        kind: user_action.kind(),
        chain_id: configuration.base.chain_id,
        configuration_hash: configuration.digest(),
        signer,
        action_id: user_action.action_id(),
        staging_intent_id: signed.action.stable_intent_id(),
        staging_vout,
        refund_script_sha256,
        refund_not_before_parent_height,
        payload_commitment,
        availability_scheme_hash: configuration.base.availability.scheme_hash,
        availability_custodian_registry_hash: configuration
            .base
            .availability
            .custodian_registry_hash,
        availability_bundle_root: [0x8a; 32],
        availability_context: [0; 32],
        availability_receipt_root: [0x8b; 32],
        availability_bundle_len: 1,
        availability_receipt_bitmap: 0b111,
        source_authorization_commitment,
        signature: Signature64([0; 64]),
    };
    marker.availability_context = marker.expected_availability_context();
    let (bundle, _) = create_bundle_with_encryption_witness(
        marker.availability_context,
        &payload.canonical_bytes(),
        public,
    )
    .unwrap();
    let canonical_encrypted_bundle = bundle.encode().unwrap();
    let custody_receipts = custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.custody_receipt(&bundle).unwrap())
        .map(|receipt| BondInboxCustodyReceiptV2 {
            custodian_index: receipt.custodian_index - 1,
            exact_receipt_bytes: receipt.encode_canonical().unwrap().to_vec(),
        })
        .collect::<Vec<_>>();
    marker.availability_bundle_root =
        bond_inbox_availability_bundle_root_v2(&canonical_encrypted_bundle).unwrap();
    marker.availability_bundle_len = u32::try_from(canonical_encrypted_bundle.len()).unwrap();
    let (receipt_root, receipt_bitmap) =
        canonical_bond_inbox_custody_receipts_v2(&marker, &custody_receipts).unwrap();
    marker.availability_receipt_root = receipt_root;
    marker.availability_receipt_bitmap = receipt_bitmap;
    marker = marker.sign(signer_secret).unwrap();

    let marker_payload = marker
        .payload_bytes(configuration.bond_inbox_max_bundle_bytes)
        .unwrap();
    let mut marker_script = vec![elements::opcodes::all::OP_RETURN.into_u8()];
    marker_script.push(elements::opcodes::all::OP_PUSHDATA2.into_u8());
    marker_script.extend_from_slice(&u16::try_from(marker_payload.len()).unwrap().to_le_bytes());
    marker_script.extend_from_slice(&marker_payload);
    let mut source_input = TxIn {
        previous_output: OutPoint::new(elements::Txid::from_byte_array([0x8c; 32]), 0),
        ..TxIn::default()
    };
    source_input.witness.script_witness = vec![
        vec![0x8d; 64],
        bond_inbox_source_annex_v2(&canonical_encrypted_bundle, &custody_receipts).unwrap(),
    ];
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![source_input],
        output: vec![
            staging,
            TxOut {
                asset: ConfidentialAsset::Explicit(AssetId::from_byte_array(
                    configuration.base.policy_asset_id,
                )),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: Script::from(marker_script),
                witness: Default::default(),
            },
        ],
    };
    let source_transaction = elements_encode::serialize(&transaction);
    let exact_witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
    let entry = BondInboxEntryV2 {
        version: BondInboxEntryV2::VERSION,
        index: previous_state.entry_count,
        previous_root: previous_state.head_root,
        observed_sidechain_height,
        observed_parent_height,
        source_block_hash: [0x8e; 32],
        source_txid: transaction.txid().to_byte_array(),
        source_wtxid: transaction.wtxid().to_byte_array(),
        source_transaction_len: u32::try_from(source_transaction.len()).unwrap(),
        source_witness_sha256: bond_inbox_source_witness_sha256_v2(&exact_witness).unwrap(),
        source_witness_len: u32::try_from(exact_witness.len()).unwrap(),
        source_tx_index: 0,
        marker_vout,
        marker,
    };
    entry
        .validate(
            configuration.base.availability,
            configuration.bond_inbox_max_bundle_bytes,
            configuration.bond_inbox_refund_minimum_parent_blocks,
        )
        .unwrap();
    verify_bond_inbox_source_transaction_v2(
        &entry,
        &source_transaction,
        &canonical_encrypted_bundle,
        &custody_receipts,
        configuration,
    )
    .unwrap();

    let next_root = entry.next_root();
    let next_state = BondInboxStateV2 {
        head_root: next_root,
        entry_count: entry.index + 1,
        processed_root: next_root,
        cursor: entry.index + 1,
    };
    let outcome = BondInboxProcessedOutcomeV2 {
        version: BondInboxProcessedOutcomeV2::VERSION,
        entry_index: entry.index,
        entry_hash: entry.entry_hash(),
        marker_kind: entry.marker.kind,
        marker_action_id: entry.marker.action_id,
        disposition: BondInboxProcessedDispositionV2::ExpiredUnavailable,
    };
    let next_outcome_root =
        bond_inbox_outcome_next_root_v2(previous_outcome_root, &outcome).unwrap();
    V2ExpiredUnavailableInboxFixture {
        next_state,
        next_outcome_root,
        transition: BondInboxTransitionV2 {
            pending_entries: vec![entry],
            consumed_evidence: vec![BondInboxConsumedEvidenceV2::ExpiredUnavailable {
                source_entry_hash: entry.entry_hash(),
            }],
        },
        outcomes: vec![outcome],
    }
}

fn exercise_complete_v2_proof_relation(
    v1: &ProofInputV1,
    maker_secret: &SecretKey,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) {
    let inventory_script = Script::from(vec![0x51, 0x70]);
    let queue_script = Script::from(vec![0x51, 0x71]);
    let insurance_script = Script::from(vec![0x51, 0x72]);
    let destroyed_reissuance_script =
        Script::from(vec![elements::opcodes::all::OP_RETURN.into_u8()]);
    let (_deployment, frozen_bond_asset, verified_deployment) = build_v2_frozen_bond_deployment(
        &inventory_script,
        &queue_script,
        &destroyed_reissuance_script,
    );
    let staging_internal_key = BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2;
    let staging_process_cmr = [0xd9; 32];
    let staging_refund_cmr = [0xda; 32];
    let configuration = FrozenConfigurationV2 {
        version: FrozenConfigurationV2::VERSION,
        base: v1.configuration.clone(),
        collateral_vault_covenant_cmr: [0xd0; 32],
        bond_asset_id: verified_deployment.bond_asset_id,
        bond_deployment_commitment: verified_deployment.deployment_commitment,
        bond_inventory_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        bond_redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        bond_inbox_redemption_staging_template_commitment:
            bond_inbox_redemption_staging_descriptor_commitment_v2(
                BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
                staging_internal_key,
                staging_process_cmr,
                staging_refund_cmr,
            )
            .unwrap(),
        bond_inbox_redemption_staging_renderer_domain:
            BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
        bond_inbox_redemption_staging_internal_key: staging_internal_key,
        bond_inbox_redemption_staging_tapleaf_version:
            BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
        bond_inbox_redemption_staging_process_cmr: staging_process_cmr,
        bond_inbox_redemption_staging_refund_cmr: staging_refund_cmr,
        bond_inbox_refund_minimum_parent_blocks: BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2,
        insurance_reserve_script_sha256: Sha256::digest(insurance_script.as_bytes()).into(),
        insurance_reserve_covenant_cmr: [0xd1; 32],
        destroyed_reissuance_token_script_sha256: Sha256::digest(
            destroyed_reissuance_script.as_bytes(),
        )
        .into(),
        bond_inbox_domain: [0xdb; 32],
        bond_inbox_custody_receipt_codec_hash: custody_receipt_codec_hash_v1(),
        bond_inbox_inclusion_blocks: BOND_INBOX_INCLUSION_BLOCKS_V2,
        bond_inbox_max_bundle_bytes: MAX_BOND_INBOX_BUNDLE_BYTES_V2,
        bond_inbox_max_entries_per_sidechain_block: BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
        bond_inbox_max_unique_source_witness_bytes_per_sidechain_block:
            BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
        bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block:
            BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
        bond_inbox_max_pending_entries_per_transition:
            BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
        bond_inbox_max_consumed_entries_per_transition:
            BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
        bond_redemption_max_queue_entries: BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2,
        matcher_execution_inclusion_parent_blocks: MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2,
        ecx_btc_conversion_program_id: [0xd3; 32],
        usdd_usd_conversion_program_id: [0xd4; 32],
        ecx_btc_redemption_covenant_commitment: [0xd5; 32],
        ecx_btc_source_checkpoint_commitment: [0xd6; 32],
        usdd_usd_redemption_covenant_commitment: [0xd7; 32],
        usdd_usd_source_checkpoint_commitment: [0xd8; 32],
        maximum_conversion_age_seconds: 3_600,
        maximum_conversion_proof_bytes: 1_024,
        recursive_proof_marker_bytes: RECURSIVE_PROOF_MARKER_BYTES_V2,
        fixed_supply_atoms: BOND_FIXED_SUPPLY_ATOMS,
        redemption_delay_parent_blocks: ecx_protocol_core::BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
    };
    configuration.validate().unwrap();
    let configuration_bytes = configuration.canonical_bytes();
    // V6 changes only the version, direct-price lane, and six absent oracle
    // identities. It does not remove Ethereum custody/checkpoint bindings.
    let mut direct = configuration.clone();
    direct.version = FrozenConfigurationV2::DIRECT_PRICE_VERSION;
    direct.base.policy_asset_id = direct.base.ecx_asset_id;
    direct.base.oracle.ecx_satoshis_per_coin = 100_000_000;
    direct.base.oracle.usdd_usd_price_units = 100_000_000;
    direct.ecx_btc_conversion_program_id = [0; 32];
    direct.usdd_usd_conversion_program_id = [0; 32];
    direct.ecx_btc_redemption_covenant_commitment = [0; 32];
    direct.ecx_btc_source_checkpoint_commitment = [0; 32];
    direct.usdd_usd_redemption_covenant_commitment = [0; 32];
    direct.usdd_usd_source_checkpoint_commitment = [0; 32];
    direct.validate().unwrap();
    let mut expected_direct = configuration_bytes.clone();
    expected_direct[0] = 6;
    expected_direct.copy_within(50..82, 114);
    for offset in [1031, 1039] {
        expected_direct[offset..offset + 8].copy_from_slice(&100_000_000u64.to_be_bytes());
    }
    expected_direct[1753..1945].fill(0);
    assert_eq!(direct.canonical_bytes(), expected_direct);
    assert_eq!(direct.digest(), tagged_hash(V18_CONFIGURATION_DIGEST_DOMAIN, &expected_direct));
    assert_ne!(direct.digest(), configuration.digest());
    let mut wrong_version = direct.clone();
    wrong_version.version = FrozenConfigurationV2::VERSION;
    assert!(wrong_version.validate().is_err());
    assert_eq!(configuration_bytes.len(), V18_CONFIGURATION_LEN);
    assert_eq!(
        hex::encode(&configuration_bytes),
        configuration_fixture_field(
            include_str!("../../../Testing/v18-config-v2-confidential-issuance-candidate.txt"),
            "ECX_V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_HEX=",
        )
    );
    assert_eq!(
        hex::encode(configuration.digest()),
        V18_CONFIDENTIAL_ISSUANCE_CANDIDATE_CONFIGURATION_DIGEST_HEX
    );
    let recursive_source_program_id = configuration
        .base
        .truthcoin_authentication
        .source_proof_program_id;

    let mut colliding_reserve_covenant = configuration.clone();
    colliding_reserve_covenant.insurance_reserve_covenant_cmr = recursive_source_program_id;
    assert!(colliding_reserve_covenant.validate().is_err());

    let mut colliding_collateral_covenant = configuration.clone();
    colliding_collateral_covenant.collateral_vault_covenant_cmr = recursive_source_program_id;
    assert!(colliding_collateral_covenant.validate().is_err());

    let mut colliding_staging_process = configuration.clone();
    colliding_staging_process.bond_inbox_redemption_staging_process_cmr =
        recursive_source_program_id;
    colliding_staging_process.bond_inbox_redemption_staging_template_commitment =
        bond_inbox_redemption_staging_descriptor_commitment_v2(
            colliding_staging_process.bond_inbox_redemption_staging_renderer_domain,
            colliding_staging_process.bond_inbox_redemption_staging_tapleaf_version,
            colliding_staging_process.bond_inbox_redemption_staging_internal_key,
            colliding_staging_process.bond_inbox_redemption_staging_process_cmr,
            colliding_staging_process.bond_inbox_redemption_staging_refund_cmr,
        )
        .unwrap();
    assert!(colliding_staging_process.validate().is_err());

    let mut colliding_staging_refund = configuration.clone();
    colliding_staging_refund.bond_inbox_redemption_staging_refund_cmr = recursive_source_program_id;
    colliding_staging_refund.bond_inbox_redemption_staging_template_commitment =
        bond_inbox_redemption_staging_descriptor_commitment_v2(
            colliding_staging_refund.bond_inbox_redemption_staging_renderer_domain,
            colliding_staging_refund.bond_inbox_redemption_staging_tapleaf_version,
            colliding_staging_refund.bond_inbox_redemption_staging_internal_key,
            colliding_staging_refund.bond_inbox_redemption_staging_process_cmr,
            colliding_staging_refund.bond_inbox_redemption_staging_refund_cmr,
        )
        .unwrap();
    assert!(colliding_staging_refund.validate().is_err());

    assert_eq!(frozen_bond_asset.asset_id, configuration.bond_asset_id);
    let configuration_hash = configuration.digest();

    let conversion_public =
        |kind, base_asset_id, quote_unit_id, covenant, checkpoint, quote_atoms, source_height| {
            ConversionLegPublicValuesV2 {
                version: ecx_proof_core::CONVERSION_LEG_PUBLIC_VALUES_VERSION_V2,
                kind,
                observed_parent_block_hash: v1.binding.prior_parent_block_hash,
                observed_parent_height: v1.binding.prior_parent_height,
                observed_parent_mtp: v1.binding.prior_parent_mtp,
                source_height,
                source_mtp: v1.binding.prior_parent_mtp - 1,
                valid_until_mtp: v1.binding.prior_parent_mtp + 60,
                base_asset_id,
                quote_unit_id,
                redemption_covenant_commitment: covenant,
                source_checkpoint_commitment: checkpoint,
                source_state_root: tagged_hash(
                    "ECX/test-conversion-source-state/v2",
                    &[kind as u8],
                ),
                quote_atoms_per_whole_base: quote_atoms,
                outstanding_base_atoms: u128::from(PRICE_SCALE),
                redeemable_reserve_quote_atoms: u128::from(quote_atoms),
                redemption_enabled: true,
            }
        };
    let ecx_btc_public = conversion_public(
        ConversionLegKindV2::EcxBtc,
        configuration.base.ecx_asset_id,
        configuration.base.policy_asset_id,
        configuration.ecx_btc_redemption_covenant_commitment,
        configuration.ecx_btc_source_checkpoint_commitment,
        configuration.base.oracle.ecx_satoshis_per_coin,
        v1.binding.prior_parent_height,
    );
    let usdd_usd_public = conversion_public(
        ConversionLegKindV2::UsddUsd,
        configuration.base.usdd_asset_id,
        configuration
            .base
            .usdd_checkpoint
            .ethereum_light_client_configuration_hash,
        configuration.usdd_usd_redemption_covenant_commitment,
        configuration.usdd_usd_source_checkpoint_commitment,
        configuration.base.oracle.usdd_usd_price_units,
        25_000_000,
    );
    let ecx_btc_conversion_proof = ConversionLegConsensusProofV2 {
        proof: test_truthcoin_proof(
            configuration.ecx_btc_conversion_program_id,
            &ecx_btc_public.canonical_bytes(),
        ),
        public_values: ecx_btc_public,
    };
    let usdd_usd_conversion_proof = ConversionLegConsensusProofV2 {
        proof: test_truthcoin_proof(
            configuration.usdd_usd_conversion_program_id,
            &usdd_usd_public.canonical_bytes(),
        ),
        public_values: usdd_usd_public,
    };
    let conversions = verify_authenticated_conversion_legs_v2(
        &configuration,
        v1.binding.prior_parent_block_hash,
        v1.binding.prior_parent_height,
        v1.binding.prior_parent_mtp,
        &ecx_btc_conversion_proof,
        &usdd_usd_conversion_proof,
        &TestDigestVerifier,
    )
    .unwrap();
    let scalar = &v1.truthcoin_consensus_proof.public_values.lmsr_snapshot;
    let (minimum, maximum, range_commitment) = derive_authenticated_price_range_v2(
        &configuration,
        scalar.scalar_lower_bound.get(),
        scalar.scalar_upper_bound.get(),
        conversions,
    )
    .unwrap();

    // This is an actual first subscription, not a V2 wrapper around a no-op.
    // The exact confidential openings are committed by the signed action and
    // the same transaction is checked again by the unified settlement gate.
    const SUBSCRIPTION_ATOMS: u64 = 400;
    let subscription_trader = v1.transition.previous_accounts[0].trader;
    let (transition_settlement, verified_settlement, signed_subscription) =
        build_v2_subscription_settlement(
            &configuration,
            &inventory_script,
            &queue_script,
            &insurance_script,
            &destroyed_reissuance_script,
            subscription_trader,
            v1.transition.previous_accounts[0].account_nonce,
            SUBSCRIPTION_ATOMS,
            maker_secret,
        );
    let inbox = build_v2_subscription_inbox_source(
        &configuration,
        &signed_subscription,
        maker_secret,
        availability_custodians,
        availability_public,
        v1.transition.public.sidechain_height,
        v1.binding.prior_parent_height,
    );

    // Carry one live resting order and its exact signed leverage selection.
    // There are no new matcher commands in this transition.
    let resting_order = v1.transition.next_open_orders[0].clone();
    let carried_risk = OrderRiskCommitmentV2::sign(
        configuration_hash,
        resting_order.order_id,
        resting_order.trader,
        2_000,
        maker_secret,
    )
    .unwrap();
    let active_risk = vec![carried_risk.clone()];
    let active_risk_root = active_order_risk_root_v2(&active_risk).unwrap();
    let mut position_risk = v1
        .transition
        .previous_positions
        .iter()
        .enumerate()
        .map(|(index, position)| PositionRiskLeafV2 {
            version: PositionRiskLeafV2::VERSION,
            trader: position.trader,
            selected_initial_margin_bps: configuration.base.risk.initial_margin_bps,
            salt: [0xe0 + u8::try_from(index).unwrap(); 32],
        })
        .collect::<Vec<_>>();
    position_risk.push(PositionRiskLeafV2 {
        version: PositionRiskLeafV2::VERSION,
        trader: v1.transition.previous_accounts[2].trader,
        selected_initial_margin_bps: configuration.base.risk.initial_margin_bps,
        salt: [0xe2; 32],
    });
    let position_risk_root = position_risk_root_v2(&position_risk).unwrap();

    let mut base = v1.transition.clone();
    base.previous_accounts = v1.transition.previous_accounts.clone();
    base.next_accounts = base.previous_accounts.clone();
    let subscribed_account = base
        .next_accounts
        .iter_mut()
        .find(|account| account.trader == subscription_trader)
        .unwrap();
    subscribed_account.account_nonce += 1;
    subscribed_account.collateral = subscribed_account
        .collateral
        .checked_sub(Amount(i128::from(SUBSCRIPTION_ATOMS)))
        .unwrap();
    base.previous_positions = v1.transition.previous_positions.clone();
    base.previous_positions.push(flat_position(
        v1.transition.previous_accounts[2].trader,
        0xdf,
    ));
    base.next_positions = base.previous_positions.clone();
    base.previous_open_orders = vec![resting_order.clone()];
    base.next_open_orders = base.previous_open_orders.clone();
    base.previous_deposit_nullifiers.clear();
    base.previous_withdrawal_nullifiers.clear();
    base.deposits.clear();
    base.withdrawals.clear();
    base.placements.clear();
    base.cancellations.clear();
    base.fills.clear();
    base.liquidations.clear();
    base.deposit_inbox = DepositInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    base.forced_inbox = ForcedInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    let previous_receipt = &v1.matcher_receipts[0];
    base.previous_state = v1.transition.previous_state.clone();
    base.previous_state.fee_pool = Amount(0);
    base.previous_state.insurance_fund = Amount(0);
    base.previous_state.total_withdrawals = Amount(0);
    base.previous_state.matcher_sequence = previous_receipt.body.global_sequence;
    base.previous_state.matcher_receipt_hash = previous_receipt.receipt_hash();
    base.previous_state.roots = StateRoots::from_private_state(
        &base.previous_accounts,
        &base.previous_positions,
        &base.previous_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        v1.transition.previous_state.roots.order_receipts,
    )
    .unwrap();

    let operation_batch_hash = transition_batch_hash(&[], &[], &[], &[], &[], &[]);
    let temporary_availability_root = [0xee; 32];
    let matcher_root = central_matcher_receipt_batch_root(&[]);
    let forced_root = forced_action_batch_root(&[]);
    let deposit_root = deposit_batch_root(&[]);
    let deposit_event_root = deposit_event_batch_root(&[]);
    let withdrawal_root = withdrawal_batch_root(&[]);
    let liquidation_root = liquidation_batch_root(&[]);
    let temporary_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root: deposit_event_root,
        oracle_certificate_hash: base.public.oracle_certificate_hash,
        oracle_mode: base.public.oracle_mode,
        matcher_receipt_batch_root: matcher_root,
        collateral_settlement_root: verified_settlement.combined_settlement_root,
        forced_action_batch_root: forced_root,
        escape_only: false,
        encrypted_availability_root: temporary_availability_root,
    });
    base.next_state = base.previous_state.clone();
    base.next_state.sequence += 1;
    base.next_state.last_processed_height = base.public.sidechain_height;
    base.next_state.mark_price = base.public.mark_price;
    base.next_state.funding_index = base.previous_state.funding_index;
    base.next_state.insurance_fund = Amount(i128::from(SUBSCRIPTION_ATOMS));
    base.next_state.roots = StateRoots::from_private_state(
        &base.next_accounts,
        &base.next_positions,
        &base.next_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        next_order_receipts_root(
            base.previous_state.roots.order_receipts,
            temporary_batch_hash,
        ),
    )
    .unwrap();
    base.public.previous_state_root = base.previous_state.state_root();
    base.public.previous_sequence = base.previous_state.sequence;
    base.public.next_state_root = base.next_state.state_root();
    base.public.next_sequence = base.next_state.sequence;
    base.public.batch_hash = temporary_batch_hash;
    base.public.deposit_batch_root = deposit_root;
    base.public.deposit_event_batch_root = deposit_event_root;
    base.public.withdrawal_batch_root = withdrawal_root;
    base.public.collateral_settlement_root = verified_settlement.combined_settlement_root;
    base.public.liquidation_batch_root = liquidation_root;
    base.public.matcher_receipt_batch_root = matcher_root;
    base.public.forced_action_batch_root = forced_root;
    base.public.escape_only = false;
    base.public.encrypted_availability_root = temporary_availability_root;
    base.public.funding_rate_ppm = 0;

    let oracle_valid_through_mtp = v1
        .truthcoin_consensus_proof
        .public_values
        .anchor
        .finalized_at_mtp
        .checked_add(configuration.base.oracle.maximum_anchor_age_seconds)
        .unwrap()
        .min(
            v1.truthcoin_consensus_proof
                .public_values
                .lmsr_snapshot
                .source_mtp
                .checked_add(configuration.base.oracle.maximum_snapshot_age_seconds)
                .unwrap(),
        );
    let previous_funding = FundingStateV2::genesis_with_band(
        v1.binding.prior_parent_mtp - 1,
        base.public.mark_price,
        base.public.liquidation_low,
        base.public.liquidation_high,
        oracle_valid_through_mtp,
        0,
    )
    .unwrap();
    let (next_funding, funding_rate) = advance_funding_timestamped_v2(
        &previous_funding,
        v1.binding.prior_parent_mtp,
        base.public.mark_price,
        base.public.liquidation_low,
        base.public.liquidation_high,
        oracle_valid_through_mtp,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(funding_rate, 0);
    let queue_root = redemption_queue_root_v2(&[]);
    let previous_bond = BondPublicStateV2 {
        version: BOND_PROTOCOL_VERSION_V2,
        bond_asset_id: configuration.bond_asset_id,
        deployment_commitment: configuration.bond_deployment_commitment,
        inventory_covenant_hash: configuration.bond_inventory_script_sha256,
        insurance_reserve: 0,
        issued_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
        outstanding_share_atoms: 0,
        inventory_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
        full_bound_deficit: 0,
        target_reserve: 0,
        legacy_fee_pool: 0,
        redemption_queue_root: queue_root,
        redemption_head: 0,
        redemption_tail: 0,
        queued_redemption_share_atoms: 0,
        capital_mode: CapitalModeV2::Normal,
    }
    .validate()
    .unwrap();
    let next_bond = BondPublicStateV2 {
        insurance_reserve: u128::from(SUBSCRIPTION_ATOMS),
        outstanding_share_atoms: SUBSCRIPTION_ATOMS,
        inventory_share_atoms: BOND_FIXED_SUPPLY_ATOMS - SUBSCRIPTION_ATOMS,
        ..previous_bond
    }
    .validate()
    .unwrap();

    // Recompose the same economics under fresh successor action, marker,
    // entry, queue and outcome domains. No V18 signature or u64 queue identity
    // is reinterpreted as a successor authorization.
    {
        // The incremental bond-action child independently recomposes the exact
        // authenticated subscription, trader debit, bond state and settlement
        // role. The trader sibling will prove this opened chain against its sparse
        // root; this fixture tests the action child with that exact typed opening.
        let accounting_bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000,
            maximum_total_controlled_atoms: 100_000,
            maximum_abs_position_atoms: 10_000,
            maximum_open_interest_atoms: 100_000,
            maximum_price_atoms: 10_000_000_000,
        };
        let old_trader = TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: subscription_trader,
            account_nonce: u128::from(signed_subscription.action.account_nonce),
            collateral_atoms: 1_000,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: configuration.base.risk.initial_margin_bps,
            order_generation: 0,
            salt: [0x31; 32],
        };
        old_trader.validate(accounting_bounds).unwrap();
        let historical_entry = inbox.transition.pending_entries[0];
        let successor_signed_subscription = SuccessorSignedBondSubscriptionV2::sign(
            SuccessorBondSubscriptionV2 {
                version: SuccessorBondSubscriptionV2::VERSION,
                chain_id: signed_subscription.action.chain_id,
                configuration_hash: signed_subscription.action.configuration_hash,
                trader: signed_subscription.action.trader,
                account_nonce: u128::from(signed_subscription.action.account_nonce),
                contribution_usdd_atoms: signed_subscription.action.contribution_usdd_atoms,
                issued_share_atoms: signed_subscription.action.issued_share_atoms,
                bond_recipient_script_sha256: signed_subscription
                    .action
                    .bond_recipient_script_sha256,
                usdd_output_opening_commitment: signed_subscription
                    .action
                    .usdd_output_opening_commitment,
                bond_output_opening_commitment: signed_subscription
                    .action
                    .bond_output_opening_commitment,
            },
            maker_secret,
        )
        .unwrap();
        let successor_action =
            SuccessorBondInboxUserActionV2::Subscription(successor_signed_subscription.clone());
        let marker_vout = 0;
        let source_authorization_commitment =
            successor_bond_inbox_no_staging_source_authorization_commitment_v2(
                configuration.base.chain_id,
                configuration.digest(),
                successor_action.signer(),
                successor_action.action_id(),
                marker_vout,
            )
            .unwrap();
        let successor_available_payload = ecx_protocol_core::SuccessorBondInboxAvailablePayloadV2 {
            commitment_blinding: [0xc1; 32],
            canonical_signed_action: successor_action.canonical_signed_bytes(),
            settlement_witness_commitment: successor_action.settlement_witness_commitment(),
            source_authorization_commitment,
        };
        let successor_payload_commitment =
            ecx_protocol_core::SuccessorBondInboxAvailablePayloadV2::commitment(
                successor_action.kind(),
                successor_available_payload.commitment_blinding,
                &successor_available_payload.canonical_signed_action,
                successor_available_payload.settlement_witness_commitment,
                successor_available_payload.source_authorization_commitment,
            );
        let mut successor_marker = SuccessorBondInboxMarkerV2 {
            version: SuccessorBondInboxMarkerV2::VERSION,
            kind: historical_entry.marker.kind,
            chain_id: historical_entry.marker.chain_id,
            configuration_hash: historical_entry.marker.configuration_hash,
            signer: historical_entry.marker.signer,
            action_id: successor_action.action_id(),
            staging_intent_id: historical_entry.marker.staging_intent_id,
            staging_vout: historical_entry.marker.staging_vout,
            refund_script_sha256: historical_entry.marker.refund_script_sha256,
            refund_not_before_parent_height: historical_entry
                .marker
                .refund_not_before_parent_height,
            payload_commitment: successor_payload_commitment,
            availability_scheme_hash: historical_entry.marker.availability_scheme_hash,
            availability_custodian_registry_hash: historical_entry
                .marker
                .availability_custodian_registry_hash,
            availability_bundle_root: [1; 32],
            availability_context: [0; 32],
            availability_receipt_root: [1; 32],
            availability_bundle_len: 1,
            availability_receipt_bitmap: 0b111,
            source_authorization_commitment,
            signature: Signature64([0; 64]),
        };
        successor_marker.availability_context = successor_marker.expected_availability_context();
        let (successor_bundle, _) = create_bundle_with_encryption_witness(
            successor_marker.availability_context,
            &successor_available_payload.canonical_bytes(),
            availability_public,
        )
        .unwrap();
        let canonical_encrypted_bundle = successor_bundle.encode().unwrap();
        let recovery_contributions = availability_custodians
            .iter()
            .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
            .map(|custodian| custodian.attest(&successor_bundle).unwrap())
            .collect::<Vec<_>>();
        let custody_receipts = availability_custodians
            .iter()
            .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
            .map(|custodian| custodian.custody_receipt(&successor_bundle).unwrap())
            .map(|receipt| BondInboxCustodyReceiptV2 {
                custodian_index: receipt.custodian_index - 1,
                exact_receipt_bytes: receipt.encode_canonical().unwrap().to_vec(),
            })
            .collect::<Vec<_>>();
        successor_marker.availability_bundle_root =
            successor_bond_inbox_availability_bundle_root_v2(&canonical_encrypted_bundle).unwrap();
        successor_marker.availability_bundle_len =
            u32::try_from(canonical_encrypted_bundle.len()).unwrap();
        let (receipt_root, receipt_bitmap) = canonical_successor_bond_inbox_custody_receipts_v2(
            &successor_marker,
            &custody_receipts,
        )
        .unwrap();
        successor_marker.availability_receipt_root = receipt_root;
        successor_marker.availability_receipt_bitmap = receipt_bitmap;
        successor_marker = successor_marker.sign(maker_secret).unwrap();

        let marker_payload = successor_marker
            .payload_bytes(configuration.bond_inbox_max_bundle_bytes)
            .unwrap();
        let mut marker_script = vec![elements::opcodes::all::OP_RETURN.into_u8()];
        marker_script.push(elements::opcodes::all::OP_PUSHDATA2.into_u8());
        marker_script
            .extend_from_slice(&u16::try_from(marker_payload.len()).unwrap().to_le_bytes());
        marker_script.extend_from_slice(&marker_payload);
        let mut successor_source_transaction: Transaction =
            elements_encode::deserialize(&inbox.source_evidence[0].source_transaction).unwrap();
        successor_source_transaction.output[usize::try_from(marker_vout).unwrap()].script_pubkey =
            Script::from(marker_script);
        successor_source_transaction.input[0].witness.script_witness[1] =
            bond_inbox_source_annex_v2(&canonical_encrypted_bundle, &custody_receipts).unwrap();
        let successor_source_transaction_bytes =
            elements_encode::serialize(&successor_source_transaction);
        let successor_exact_witness =
            elements_transaction_witness_bytes_v2(&successor_source_transaction_bytes).unwrap();
        let source_entry = SuccessorBondInboxEntryV2 {
            version: SuccessorBondInboxEntryV2::VERSION,
            index: (u128::from(u64::MAX) + 1) + u128::from(historical_entry.index),
            previous_root: historical_entry.previous_root,
            observed_sidechain_height: historical_entry.observed_sidechain_height,
            observed_parent_height: historical_entry.observed_parent_height,
            source_block_hash: historical_entry.source_block_hash,
            source_txid: successor_source_transaction.txid().to_byte_array(),
            source_wtxid: successor_source_transaction.wtxid().to_byte_array(),
            source_transaction_len: u32::try_from(successor_source_transaction_bytes.len())
                .unwrap(),
            source_witness_sha256: Sha256::digest(&successor_exact_witness).into(),
            source_witness_len: u32::try_from(successor_exact_witness.len()).unwrap(),
            source_tx_index: historical_entry.source_tx_index,
            marker_vout,
            marker: successor_marker,
        };
        source_entry
            .validate(
                configuration.base.availability,
                configuration.bond_inbox_max_bundle_bytes,
                configuration.bond_inbox_refund_minimum_parent_blocks,
            )
            .unwrap();
        let source_child_input = IncrementalSourceTransactionChildInputV2 {
            version: ecx_proof_core::INCREMENTAL_SOURCE_TRANSACTION_CHILD_VERSION_V2,
            configuration: configuration.clone(),
            entry: source_entry,
            source_transaction: successor_source_transaction_bytes,
            canonical_encrypted_bundle,
            custody_receipts,
        };
        let source_child_values =
            execute_incremental_source_transaction_child_v2(&source_child_input).unwrap();
        assert_eq!(source_child_values.entry_hash, source_entry.entry_hash());
        assert!(source_child_values.entry_hash != historical_entry.entry_hash());
        assert!(source_entry.index > u128::from(u64::MAX));
        let mut substituted_source_child = source_child_input.clone();
        substituted_source_child.source_transaction[0] ^= 1;
        assert!(
            execute_incremental_source_transaction_child_v2(&substituted_source_child).is_err()
        );

        // Recursively authenticate that exact transaction projection, recover
        // the fresh successor payload from 3-of-5 custody evidence, and advance
        // the u128 inbox state through the aggregate child relation.
        let source_transaction_program_id = [0xc2; 32];
        let source_transaction_public_values = source_child_values.encode();
        let source_transaction_proof_marker = sp1_deferred_proof_marker(
            source_transaction_program_id,
            &source_transaction_public_values,
        );
        let source_transaction_bundle_context =
            ecx_proof_core::incremental_source_transaction_bundle_context_v2(
                source_transaction_program_id,
                &source_transaction_public_values,
                source_transaction_proof_marker,
                configuration.base.availability.custodian_registry_hash,
            )
            .unwrap();
        let source_transaction_child_witness = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&source_child_input)
            .unwrap();
        let (source_transaction_bundle, _) = create_bundle_with_encryption_witness(
            source_transaction_bundle_context,
            &source_transaction_child_witness,
            availability_public,
        )
        .unwrap();
        let source_transaction_receipts = availability_custodians
            .iter()
            .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
            .map(|custodian| {
                custodian
                    .custody_receipt(&source_transaction_bundle)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let previous_successor_inbox = ecx_protocol_core::SuccessorBondInboxStateV2 {
            head_root: source_entry.previous_root,
            entry_count: source_entry.index,
            processed_root: source_entry.previous_root,
            cursor: source_entry.index,
        };
        let next_successor_inbox = ecx_protocol_core::SuccessorBondInboxStateV2 {
            head_root: source_entry.next_root(),
            entry_count: source_entry.index + 1,
            processed_root: source_entry.next_root(),
            cursor: source_entry.index + 1,
        };
        let successor_consumed_evidence =
            ecx_protocol_core::SuccessorBondInboxConsumedEvidenceV2::Recovered {
                source_entry_hash: source_entry.entry_hash(),
                payload: successor_available_payload.clone(),
            };
        let successor_inbox_transition = ecx_protocol_core::SuccessorBondInboxTransitionV2 {
            pending_entries: vec![source_entry],
            consumed_evidence: vec![successor_consumed_evidence],
        };
        let successor_recovery_evidence =
            ecx_proof_core::proof_v2::SuccessorBondInboxEntryRecoveryEvidenceV2 {
                entry_index: source_entry.index,
                canonical_encrypted_bundle: source_child_input.canonical_encrypted_bundle.clone(),
                custody_receipts: source_child_input.custody_receipts.clone(),
                recovery_contributions,
            };
        let compact_custodians = availability_public
            .iter()
            .map(|custodian| ecx_proof_core::IncrementalCustodianPublicV2 {
                index: custodian.index,
                encryption_public_key: custodian.encryption_public_key,
                attestation_public_key: custodian.attestation_public_key,
            })
            .collect::<Vec<_>>();
        let inbox_child_input = ecx_proof_core::IncrementalInboxSourceChildInputV2 {
            version: ecx_proof_core::INCREMENTAL_INBOX_SOURCE_CHILD_VERSION_V2,
            configuration: configuration.clone(),
            chain_id: configuration.base.chain_id,
            configuration_hash: configuration.digest(),
            previous_state: previous_successor_inbox,
            next_state: next_successor_inbox,
            parent_height: source_entry.observed_parent_height + 1,
            transition_sidechain_height: source_entry.observed_sidechain_height + 1,
            transition: successor_inbox_transition,
            source_transaction_program_id,
            source_transaction_custodians: compact_custodians,
            source_evidence: vec![ecx_proof_core::IncrementalInboxSourceReceiptEvidenceV2 {
                source_wtxid: source_entry.source_wtxid,
                source_receipt: ecx_proof_core::IncrementalSourceTransactionReceiptV2 {
                    program_id: source_transaction_program_id,
                    public_values: source_transaction_public_values,
                    proof_marker: source_transaction_proof_marker,
                    bundle_root: source_transaction_bundle.root().unwrap(),
                    bundle_context: source_transaction_bundle_context,
                    child_witness_len: source_transaction_bundle.witness_len,
                    custody_receipts: source_transaction_receipts,
                },
                entry: successor_recovery_evidence,
            }],
        };
        let inbox_child_values =
            ecx_proof_core::execute_incremental_inbox_source_child_v2_with_consensus_verifier(
                &inbox_child_input,
                &DeferredMarkerVerifier,
            )
            .unwrap();
        assert_eq!(inbox_child_values.previous_cursor, source_entry.index);
        assert_eq!(inbox_child_values.next_cursor, source_entry.index + 1);
        assert_eq!(inbox_child_values.consumed_count, 1);
        let mut substituted_inbox_receipt = inbox_child_input.clone();
        substituted_inbox_receipt.source_evidence[0]
            .source_receipt
            .public_values[4] ^= 1;
        assert!(
            ecx_proof_core::execute_incremental_inbox_source_child_v2_with_consensus_verifier(
                &substituted_inbox_receipt,
                &DeferredMarkerVerifier,
            )
            .is_err()
        );
        let successor_empty_queue_root =
            ecx_protocol_core::successor_redemption_queue_root_v2(&[]).unwrap();
        let successor_previous_bond = SuccessorBondPublicStateV2 {
            version: ecx_protocol_core::SUCCESSOR_BOND_PROTOCOL_VERSION_V2,
            bond_asset_id: previous_bond.bond_asset_id,
            deployment_commitment: previous_bond.deployment_commitment,
            inventory_covenant_hash: previous_bond.inventory_covenant_hash,
            insurance_reserve: previous_bond.insurance_reserve,
            issued_share_atoms: previous_bond.issued_share_atoms,
            outstanding_share_atoms: previous_bond.outstanding_share_atoms,
            inventory_share_atoms: previous_bond.inventory_share_atoms,
            full_bound_deficit: previous_bond.full_bound_deficit,
            target_reserve: previous_bond.target_reserve,
            legacy_fee_pool: previous_bond.legacy_fee_pool,
            redemption_queue_root: successor_empty_queue_root,
            redemption_head: u128::from(previous_bond.redemption_head),
            redemption_tail: u128::from(previous_bond.redemption_tail),
            queued_redemption_share_atoms: previous_bond.queued_redemption_share_atoms,
            capital_mode: previous_bond.capital_mode,
        }
        .validate()
        .unwrap();
        let successor_next_bond = SuccessorBondPublicStateV2 {
            insurance_reserve: next_bond.insurance_reserve,
            outstanding_share_atoms: next_bond.outstanding_share_atoms,
            inventory_share_atoms: next_bond.inventory_share_atoms,
            ..successor_previous_bond
        }
        .validate()
        .unwrap();
        let mutation_event_id = incremental_bond_trader_mutation_event_id_v2(
            source_entry.entry_hash(),
            successor_signed_subscription.action.action_id(),
        )
        .unwrap();
        let mutation = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::BondSubscription,
            action_id: mutation_event_id,
            exact_cash_delta_numerator: Int256V2::from_i128(
                -i128::from(SUBSCRIPTION_ATOMS)
                    * i128::from(ecx_protocol_core::EXACT_ACCOUNTING_DENOMINATOR_V2),
            ),
            position_size_delta_atoms: 0,
            signed_cost_basis_delta_numerator: Int256V2::ZERO,
            funding_checkpoint_after: None,
            account_nonce_increment: 1,
            order_generation_increment: 0,
            selected_initial_margin_bps_after: None,
        };
        let mut new_trader = old_trader.clone();
        new_trader.collateral_atoms -= i128::from(SUBSCRIPTION_ATOMS);
        new_trader.account_nonce += 1;
        new_trader.salt = [0x32; 32];
        let settlement_action = BondSettlementActionV2::Subscription {
            subscription_id: successor_signed_subscription.action.subscription_id(),
            usdd_contribution_amount: SUBSCRIPTION_ATOMS,
            bond_share_amount: SUBSCRIPTION_ATOMS,
            recipient_script_sha256: signed_subscription.action.bond_recipient_script_sha256,
        };
        let consumed = SuccessorBondInboxConsumedOutcomeV2 {
            entry_index: source_entry.index,
            entry_hash: source_entry.entry_hash(),
            marker_kind: source_entry.marker.kind,
            marker_action_id: source_entry.marker.action_id,
            source_parent_height: source_entry.observed_parent_height,
            disposition: SuccessorBondInboxConsumedDispositionV2::Action(Ok(successor_action)),
        };
        let previous_successor_outcome_root =
            ecx_protocol_core::successor_bond_inbox_outcome_genesis_root_v2(
                configuration.bond_inbox_domain,
                configuration.base.chain_id,
                configuration.digest(),
            )
            .unwrap();
        let accepted_successor_outcome =
            ecx_protocol_core::SuccessorBondInboxProcessedOutcomeV2::accepted(&consumed);
        let next_successor_outcome_root =
            ecx_protocol_core::successor_bond_inbox_outcome_next_root_v2(
                previous_successor_outcome_root,
                &accepted_successor_outcome,
            )
            .unwrap();
        let incremental_bond_input = IncrementalBondActionChildInputV2 {
            version: ecx_proof_core::INCREMENTAL_BOND_ACTION_CHILD_VERSION_V2,
            configuration: configuration.clone(),
            chain_id: configuration.base.chain_id,
            accounting_bounds,
            previous_bond: successor_previous_bond,
            next_bond: successor_next_bond,
            previous_queue: vec![],
            next_queue: vec![],
            parent_height: inbox_child_values.parent_height,
            insurance_reserve_before_bond_actions: 0,
            consumed_outcomes: vec![consumed],
            consumed_entries: vec![source_entry],
            previous_outcome_root: previous_successor_outcome_root,
            previous_outcome_count: 0,
            next_outcome_root: next_successor_outcome_root,
            next_outcome_count: 1,
            redemption_executions: vec![],
            settlement_actions: vec![settlement_action],
            trader_mutation_chains: vec![IncrementalTraderMutationChainV2 {
                trader: subscription_trader,
                old_leaf: old_trader,
                mutations: vec![mutation],
                final_salt: new_trader.salt,
                expected_new_leaf: new_trader,
            }],
            previous_trader_root: canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
            trader_reads: None,
            read_only_action_events: vec![],
        };
        let incremental_bond_values =
            execute_incremental_bond_action_child_v2(&incremental_bond_input).unwrap();
        assert_eq!(
            incremental_bond_values.insurance_reserve_after,
            u128::from(SUBSCRIPTION_ATOMS)
        );
        assert_eq!(
            incremental_bond_values.recovered_candidate_root,
            inbox_child_values.recovered_candidate_root
        );
        let mut wrong_settlement_action = incremental_bond_input.clone();
        let BondSettlementActionV2::Subscription {
            usdd_contribution_amount,
            ..
        } = &mut wrong_settlement_action.settlement_actions[0]
        else {
            unreachable!();
        };
        *usdd_contribution_amount += 1;
        assert!(execute_incremental_bond_action_child_v2(&wrong_settlement_action).is_err());
        let mut wrong_trader_debit = incremental_bond_input.clone();
        wrong_trader_debit.trader_mutation_chains[0].mutations[0].account_nonce_increment = 0;
        assert!(execute_incremental_bond_action_child_v2(&wrong_trader_debit).is_err());

        // A stale signed nonce is a deterministic rejection with no trader-tree
        // update. It is authenticated by a typed predecessor membership proof,
        // not by smuggling a no-op sparse update into the trader child.
        let mut stale_nonce_leaf = incremental_bond_input.trader_mutation_chains[0]
            .old_leaf
            .clone();
        stale_nonce_leaf.account_nonce += 9;
        stale_nonce_leaf.salt = [0x35; 32];
        let insertion = TraderStateBatchProofV2::for_canonical_empty_root(
            vec![TraderStateBatchLeafUpdateV2 {
                trader: stale_nonce_leaf.trader,
                old_leaf: None,
                new_leaf: Some(stale_nonce_leaf.clone()),
            }],
            accounting_bounds,
        )
        .unwrap();
        let authenticated_trader_root = insertion
            .verify(
                canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
                accounting_bounds,
                1,
            )
            .unwrap();
        let stale_processed = ecx_protocol_core::SuccessorBondInboxProcessedOutcomeV2::rejected(
            &incremental_bond_input.consumed_outcomes[0],
            ecx_protocol_core::BondInboxRejectionV2::InvalidNonce,
        );
        let stale_next_outcome_root = ecx_protocol_core::successor_bond_inbox_outcome_next_root_v2(
            incremental_bond_input.previous_outcome_root,
            &stale_processed,
        )
        .unwrap();
        let stale_nonce_input = IncrementalBondActionChildInputV2 {
            next_bond: successor_previous_bond,
            next_outcome_root: stale_next_outcome_root,
            settlement_actions: vec![],
            trader_mutation_chains: vec![],
            previous_trader_root: authenticated_trader_root,
            trader_reads: Some(TraderStateReadBatchProofV2 {
                leaves: vec![stale_nonce_leaf.clone()],
                frontier: insertion.frontier,
            }),
            read_only_action_events: vec![IncrementalBondReadOnlyActionEventV2 {
                event_id: mutation_event_id,
                trader: subscription_trader.0,
                leaf: stale_nonce_leaf,
            }],
            ..incremental_bond_input.clone()
        };
        let stale_nonce_values =
            execute_incremental_bond_action_child_v2(&stale_nonce_input).unwrap();
        assert_eq!(stale_nonce_values.accepted_action_count, 0);
        assert_eq!(stale_nonce_values.insurance_reserve_after, 0);
        let mut substituted_read = stale_nonce_input;
        substituted_read.read_only_action_events[0]
            .leaf
            .account_nonce = u128::from(signed_subscription.action.account_nonce);
        assert!(execute_incremental_bond_action_child_v2(&substituted_read).is_err());
    }

    let previous_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: base.previous_state.clone(),
        bond: previous_bond,
        funding: previous_funding,
        matcher_execution_sequence: 0,
        last_transition_sidechain_height: base.previous_state.last_processed_height,
        bond_inbox: inbox.previous_state,
        bond_inbox_outcome_root: inbox.previous_outcome_root,
        bond_inbox_outcome_count: 0,
        active_order_risk_root: active_risk_root,
        position_risk_root,
    };
    let next_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: base.next_state.clone(),
        bond: next_bond,
        funding: next_funding,
        matcher_execution_sequence: 0,
        last_transition_sidechain_height: base.next_state.last_processed_height,
        bond_inbox: inbox.next_state,
        bond_inbox_outcome_root: inbox.next_outcome_root,
        bond_inbox_outcome_count: 1,
        active_order_risk_root: active_risk_root,
        position_risk_root,
    };
    let mut transition = TransitionWitnessV2 {
        public: TransitionPublicInputsV2 {
            protocol_version: TransitionPublicInputsV2::VERSION,
            configuration_hash,
            parent_mtp: v1.binding.prior_parent_mtp,
            oracle_valid_through_mtp,
            insurance_reserve_before_bond_actions: 0,
            authenticated_min_price: Price::new(minimum).unwrap(),
            authenticated_max_price: Price::new(maximum).unwrap(),
            authenticated_price_range_commitment: range_commitment,
            previous_state_root: previous_state.state_root(),
            next_state_root: next_state.state_root(),
            bond_action_root: [1; 32],
            order_risk_root: order_risk_root_v2(&[]),
            funding_state_root: next_state.funding.root(),
            matcher_execution_receipt_batch_root:
                ecx_protocol_core::matcher_execution_receipt_batch_root_v2(&[]),
            previous_matcher_execution_sequence: 0,
            next_matcher_execution_sequence: 0,
            base_public_digest: base.public.digest(),
        },
        configuration: configuration.clone(),
        previous_state,
        next_state,
        bond_inbox: inbox.transition,
        bond_inbox_outcomes: inbox.outcomes,
        base,
        matcher_execution_receipts: vec![],
        previous_redemption_queue: vec![],
        next_redemption_queue: vec![],
        subscriptions: vec![signed_subscription],
        recapitalization_contributions: vec![],
        redemption_enqueues: vec![],
        redemption_executions: vec![],
        redemption_cancellations: vec![],
        order_risk_commitments: vec![],
        previous_active_order_risk_commitments: active_risk.clone(),
        next_active_order_risk_commitments: active_risk,
        previous_position_risk: position_risk.clone(),
        next_position_risk: position_risk,
    };
    transition.public.bond_action_root = bond_action_root_v2(&transition);

    let current_availability_root = v1.binding.current.encrypted_availability_root;
    let current = CovenantPublicStateV2 {
        version: COVENANT_STATE_VERSION_V2,
        sequence: transition.previous_state.sequence(),
        private_state_root: transition.previous_state.state_root(),
        encrypted_availability_root: current_availability_root,
        forced_action_inbox_root: transition.previous_state.base.forced_inbox.head_root,
        deposit_inbox_root: transition.previous_state.base.deposit_inbox.head_root,
        configuration_hash,
        bond_state_root: bond_public_state_root_v2(&transition.previous_state.bond),
        funding_state_root: transition.previous_state.funding.root(),
        active_order_risk_root: transition.previous_state.active_order_risk_root,
        position_risk_root: transition.previous_state.position_risk_root,
        bond_inbox_head_root: transition.previous_state.bond_inbox.head_root,
        bond_inbox_entry_count: transition.previous_state.bond_inbox.entry_count,
        bond_inbox_processed_root: transition.previous_state.bond_inbox.processed_root,
        bond_inbox_cursor: transition.previous_state.bond_inbox.cursor,
        bond_inbox_outcome_root: transition.previous_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: transition.previous_state.bond_inbox_outcome_count,
        matcher_execution_sequence: transition.previous_state.matcher_execution_sequence,
        last_transition_sidechain_height: transition
            .previous_state
            .last_transition_sidechain_height,
    };
    let next = CovenantPublicStateV2 {
        version: COVENANT_STATE_VERSION_V2,
        sequence: transition.next_state.sequence(),
        private_state_root: transition.next_state.state_root(),
        encrypted_availability_root: temporary_availability_root,
        forced_action_inbox_root: transition.next_state.base.forced_inbox.head_root,
        deposit_inbox_root: transition.next_state.base.deposit_inbox.head_root,
        configuration_hash,
        bond_state_root: bond_public_state_root_v2(&transition.next_state.bond),
        funding_state_root: transition.next_state.funding.root(),
        active_order_risk_root: transition.next_state.active_order_risk_root,
        position_risk_root: transition.next_state.position_risk_root,
        bond_inbox_head_root: transition.next_state.bond_inbox.head_root,
        bond_inbox_entry_count: transition.next_state.bond_inbox.entry_count,
        bond_inbox_processed_root: transition.next_state.bond_inbox.processed_root,
        bond_inbox_cursor: transition.next_state.bond_inbox.cursor,
        bond_inbox_outcome_root: transition.next_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: transition.next_state.bond_inbox_outcome_count,
        matcher_execution_sequence: transition.next_state.matcher_execution_sequence,
        last_transition_sidechain_height: transition.next_state.last_transition_sidechain_height,
    };
    let mut input = ProofInputV2 {
        binding: ProofBindingV2 {
            version: PROOF_BINDING_VERSION_V2,
            transition_txid_consensus: verified_settlement.transition_txid,
            prior_exchange_header_root: v1.binding.prior_exchange_header_root,
            prior_parent_block_hash: v1.binding.prior_parent_block_hash,
            prior_parent_height: v1.binding.prior_parent_height,
            prior_parent_mtp: v1.binding.prior_parent_mtp,
            public_state_domain_sha256: Sha256::digest(b"ECX/e2e-state-domain/v2").into(),
            transition_journal_domain_sha256: Sha256::digest(b"ECX/e2e-journal-domain/v2").into(),
            current,
            next,
        },
        configuration,
        truthcoin_consensus_proof: v1.truthcoin_consensus_proof.clone(),
        ecx_btc_conversion_proof,
        usdd_usd_conversion_proof,
        matcher_receipts: vec![],
        bond_inbox_source_evidence: inbox.source_evidence,
        funding_parent_chain: FundingParentChainWitnessV2::empty(),
        deposit_openings: vec![],
        transition_settlement,
        transition,
        availability_bundle: vec![],
        availability_custody_receipts: vec![],
        availability_encryption_witness: v1.availability_encryption_witness.clone(),
    };
    refresh_v2_availability(&mut input, availability_custodians, availability_public);

    // ECX adapter qualification with the same synthetic recursive verifier as
    // this fixture. This is binding/rejection evidence, not a real SP1 proof.
    {
        use ecx_protocol_core::ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1};
        let key = |byte| XOnlyKey(Keypair::from_secret_key(
            &Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap(),
        ).x_only_public_key().0.serialize());
        let economics = EcxConfigurationV1 {
            chain_id: input.configuration.base.chain_id,
            market: input.configuration.base.market,
            collateral_asset: input.configuration.base.ecx_asset_id,
            clearing_account: key(7), insurance_account: key(8),
            cash_valuation_scale: 1_000_000,
            risk: ecx_protocol_core::risk::RiskParams::default(),
            bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 10_000,
                maximum_total_controlled_atoms: 100_000,
                maximum_abs_position_atoms: 10_000,
                maximum_open_interest_atoms: 100_000,
                maximum_price_atoms: 10_000_000_000,
            },
        };
        let bindings = EcxSuccessorBindingsV1 {
            economic_configuration_hash: economics.digest().unwrap(),
            oracle_configuration_hash: input.configuration.digest(),
            matcher_configuration_hash: [21; 32],
            funding_oracle_program_id: [22; 32],
            account_execution_program_id: [23; 32], vault_policy_hash: [24; 32],
        };
        let parent = ecx_truthcoin_proof::ParentChainContextV1 {
            block_hash: input.binding.prior_parent_block_hash,
            height: input.binding.prior_parent_height,
            median_time_past: input.binding.prior_parent_mtp,
        };
        let verify = |bindings, economics, proof: &TruthcoinConsensusProofV1| {
            ecx_proof_core::proof_v2::verify_ecx_authenticated_funding_source_v1(
                bindings, economics, &input.configuration, parent, proof,
                &input.ecx_btc_conversion_proof, &input.usdd_usd_conversion_proof,
                &TestDigestVerifier,
            )
        };
        let source = verify(bindings, economics, &input.truthcoin_consensus_proof).unwrap();
        ecx_oracle_match::exercise(
            &input.configuration, parent, &input.truthcoin_consensus_proof,
            &input.ecx_btc_conversion_proof, &input.usdd_usd_conversion_proof,
            &TestDigestVerifier,
        );
        assert_eq!(source, ecx_proof_core::proof_v2::verify_authenticated_funding_source_v2(
            &input.configuration, parent, &input.truthcoin_consensus_proof,
            &input.ecx_btc_conversion_proof, &input.usdd_usd_conversion_proof,
            &TestDigestVerifier,
        ).unwrap());
        let mut wrong = bindings;
        wrong.oracle_configuration_hash[0] ^= 1;
        assert!(verify(wrong, economics, &input.truthcoin_consensus_proof).is_err());
        let mut foreign = economics;
        foreign.chain_id[0] ^= 1;
        wrong = bindings;
        wrong.economic_configuration_hash = foreign.digest().unwrap();
        assert!(verify(wrong, foreign, &input.truthcoin_consensus_proof).is_err());
        let mut damaged = input.truthcoin_consensus_proof.clone();
        damaged.proof[0] ^= 1;
        assert!(verify(bindings, economics, &damaged).is_err());
        assert!(ecx_proof_core::proof_v2::verify_ecx_authenticated_funding_source_v1(
            bindings, economics, &input.configuration, parent, &input.truthcoin_consensus_proof,
            &input.ecx_btc_conversion_proof, &input.usdd_usd_conversion_proof,
            &ecx_truthcoin_proof::DenyAllConsensusProofs,
        ).is_err());
    }

    assert!(
        execute_proof_v2(&input).is_err(),
        "production entrypoint fails closed"
    );
    let result = execute_proof_v2_with_consensus_verifier(&input, &TestDigestVerifier)
        .expect("complete non-cryptographic V2 proof relation");
    assert_eq!(result.public_values.len(), PUBLIC_VALUES_V5_LEN);
    assert_eq!(
        result.transition_journal.configuration_hash,
        configuration_hash
    );
    assert_eq!(
        result.transition_journal.insurance_reserve,
        u128::from(SUBSCRIPTION_ATOMS)
    );
    assert_eq!(
        result.transition_journal.outstanding_share_atoms,
        SUBSCRIPTION_ATOMS
    );

    // Advance the exact V2 singleton once more and consume a separately
    // admitted redemption enqueue at its frozen inclusion deadline. This
    // is a complete outer proof relation with its own settlement txid, next
    // state, outcome root, encrypted recovery bundle and V5 public values.
    // TestDigestVerifier authenticates only deterministic test digests for the
    // three recursive proof seams; it is not a cryptographic SP1 verifier.
    let expired = build_v2_expired_unavailable_followup(
        &input,
        &inventory_script,
        &queue_script,
        &destroyed_reissuance_script,
        maker_secret,
        availability_custodians,
        availability_public,
        0,
    );
    let expired_result = execute_proof_v2_with_consensus_verifier(&expired, &TestDigestVerifier)
        .expect("sequential expired-unavailable V2 relation");
    assert_eq!(expired_result.public_values.len(), PUBLIC_VALUES_V5_LEN);
    assert_eq!(
        expired.transition.next_state.bond, input.transition.next_state.bond,
        "expiry has no reserve/supply/queue effect"
    );
    assert_eq!(
        expired.transition.base.next_accounts, input.transition.base.next_accounts,
        "expiry consumes no account nonce"
    );
    assert_eq!(expired.bond_inbox_source_evidence.len(), 0);

    let early_expiry = build_v2_expired_unavailable_followup(
        &input,
        &inventory_script,
        &queue_script,
        &destroyed_reissuance_script,
        maker_secret,
        availability_custodians,
        availability_public,
        1,
    );
    assert!(matches!(
        execute_proof_v2_with_consensus_verifier(&early_expiry, &TestDigestVerifier),
        Err(ProofErrorV2::Transition(_))
    ));
    let late_expiry = build_v2_expired_unavailable_followup(
        &input,
        &inventory_script,
        &queue_script,
        &destroyed_reissuance_script,
        maker_secret,
        availability_custodians,
        availability_public,
        -1,
    );
    execute_proof_v2_with_consensus_verifier(&late_expiry, &TestDigestVerifier)
        .expect("expired-unavailable remains valid after boundary");

    let mut substituted_expired_entry = expired.clone();
    let BondInboxConsumedEvidenceV2::ExpiredUnavailable { source_entry_hash } =
        &mut substituted_expired_entry
            .transition
            .bond_inbox
            .consumed_evidence[0]
    else {
        panic!("expiry fixture must carry exact source entry hash")
    };
    source_entry_hash[0] ^= 1;
    refresh_v2_availability(
        &mut substituted_expired_entry,
        availability_custodians,
        availability_public,
    );
    assert!(matches!(
        execute_proof_v2_with_consensus_verifier(&substituted_expired_entry, &TestDigestVerifier,),
        Err(ProofErrorV2::Transition(_))
    ));

    // The outer relation rejects every substitution at the encrypted source
    // boundary. These calls still use TestDigestVerifier for the three
    // recursive proof seams, but the bundle AEAD, exact receipt signatures,
    // threshold-recovery certificate, annex/transaction projection and
    // recovered action comparison below are their real production checks.
    let mut substituted_source_transaction = input.clone();
    substituted_source_transaction.bond_inbox_source_evidence[0].source_transaction[0] ^= 1;
    assert!(execute_proof_v2_with_consensus_verifier(
        &substituted_source_transaction,
        &TestDigestVerifier,
    )
    .is_err());

    let mut substituted_encrypted_bundle = input.clone();
    substituted_encrypted_bundle.bond_inbox_source_evidence[0].entries[0]
        .canonical_encrypted_bundle[0] ^= 1;
    refresh_v2_availability(
        &mut substituted_encrypted_bundle,
        availability_custodians,
        availability_public,
    );
    assert!(execute_proof_v2_with_consensus_verifier(
        &substituted_encrypted_bundle,
        &TestDigestVerifier,
    )
    .is_err());

    let mut substituted_receipt = input.clone();
    substituted_receipt.bond_inbox_source_evidence[0].entries[0].custody_receipts[0]
        .exact_receipt_bytes[137] ^= 1;
    refresh_v2_availability(
        &mut substituted_receipt,
        availability_custodians,
        availability_public,
    );
    assert!(
        execute_proof_v2_with_consensus_verifier(&substituted_receipt, &TestDigestVerifier)
            .is_err()
    );

    let mut missing_recovery_share = input.clone();
    missing_recovery_share.bond_inbox_source_evidence[0].entries[0]
        .recovery_contributions
        .pop();
    refresh_v2_availability(
        &mut missing_recovery_share,
        availability_custodians,
        availability_public,
    );
    assert!(
        execute_proof_v2_with_consensus_verifier(&missing_recovery_share, &TestDigestVerifier)
            .is_err()
    );

    let mut substituted_recovered_action = input.clone();
    let BondInboxConsumedEvidenceV2::Recovered { payload, .. } = &mut substituted_recovered_action
        .transition
        .bond_inbox
        .consumed_evidence[0]
    else {
        panic!("subscription fixture must use recovered inbox evidence")
    };
    payload.commitment_blinding[0] ^= 1;
    refresh_v2_availability(
        &mut substituted_recovered_action,
        availability_custodians,
        availability_public,
    );
    assert!(execute_proof_v2_with_consensus_verifier(
        &substituted_recovered_action,
        &TestDigestVerifier,
    )
    .is_err());

    exercise_non_cryptographic_v2_insurance_lifecycle_composition(
        &input,
        &inventory_script,
        &queue_script,
        &insurance_script,
        &destroyed_reissuance_script,
        maker_secret,
        availability_custodians,
        availability_public,
    );

    let mut bad_conversion = input.clone();
    bad_conversion
        .usdd_usd_conversion_proof
        .public_values
        .source_state_root[0] ^= 1;
    refresh_v2_availability(
        &mut bad_conversion,
        availability_custodians,
        availability_public,
    );
    assert!(matches!(
        execute_proof_v2_with_consensus_verifier(&bad_conversion, &TestDigestVerifier),
        Err(ProofErrorV2::Conversion(_))
    ));

    let mut bad_settlement = input.clone();
    bad_settlement.transition_settlement.bond_outputs[0].amount -= 1;
    refresh_v2_availability(
        &mut bad_settlement,
        availability_custodians,
        availability_public,
    );
    assert!(matches!(
        execute_proof_v2_with_consensus_verifier(&bad_settlement, &TestDigestVerifier),
        Err(ProofErrorV2::Settlement(_))
    ));

    let mut swapped_resting_leverage = input.clone();
    let replacement = OrderRiskCommitmentV2::sign(
        configuration_hash,
        resting_order.order_id,
        resting_order.trader,
        5_000,
        maker_secret,
    )
    .unwrap();
    swapped_resting_leverage
        .transition
        .next_active_order_risk_commitments = vec![replacement];
    swapped_resting_leverage
        .transition
        .next_state
        .active_order_risk_root = active_order_risk_root_v2(
        &swapped_resting_leverage
            .transition
            .next_active_order_risk_commitments,
    )
    .unwrap();
    refresh_v2_availability(
        &mut swapped_resting_leverage,
        availability_custodians,
        availability_public,
    );
    assert!(matches!(
        execute_proof_v2_with_consensus_verifier(&swapped_resting_leverage, &TestDigestVerifier),
        Err(ProofErrorV2::Transition(_))
    ));
}

/// Build the immediately following outer V2 transition with one authenticated
/// enqueue consumed as unavailable at its exact +6 inclusion deadline. The parent
/// tip is unchanged (multiple sidechain transitions can share it), while the
/// singleton sidechain height, state sequence, inbox cursor, outcome root,
/// settlement txid and encrypted recovery root all advance exactly once.
#[allow(clippy::too_many_arguments)]
fn build_v2_expired_unavailable_followup(
    previous: &ProofInputV2,
    inventory_script: &Script,
    queue_script: &Script,
    destroyed_reissuance_script: &Script,
    signer_secret: &SecretKey,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
    process_deadline_offset: i64,
) -> ProofInputV2 {
    let configuration = previous.configuration.clone();
    let parent_height = previous.binding.prior_parent_height;
    let process_deadline_parent_height = if process_deadline_offset < 0 {
        parent_height
            .checked_sub(process_deadline_offset.unsigned_abs())
            .unwrap()
    } else {
        parent_height
            .checked_add(u64::try_from(process_deadline_offset).unwrap())
            .unwrap()
    };
    let observed_parent_height = process_deadline_parent_height
        .checked_sub(u64::from(configuration.bond_inbox_inclusion_blocks))
        .unwrap();
    let refund_not_before_parent_height = observed_parent_height
        .checked_add(u64::from(
            configuration.bond_inbox_refund_minimum_parent_blocks,
        ))
        .unwrap();
    let previous_state = previous.transition.next_state.clone();
    let sidechain_height = previous_state.last_transition_sidechain_height + 1;
    let inbox = build_v2_expired_unavailable_inbox_source(
        &configuration,
        previous_state.bond_inbox,
        previous_state.bond_inbox_outcome_root,
        signer_secret,
        availability_custodians,
        availability_public,
        previous_state.last_transition_sidechain_height,
        observed_parent_height,
        refund_not_before_parent_height,
    );
    assert_eq!(
        inbox.transition.pending_entries[0]
            .deadline(configuration.bond_inbox_inclusion_blocks)
            .unwrap(),
        process_deadline_parent_height
    );
    assert_eq!(
        inbox.transition.pending_entries[0]
            .marker
            .refund_not_before_parent_height,
        refund_not_before_parent_height
    );
    assert!(refund_not_before_parent_height > process_deadline_parent_height);
    let (transition_settlement, verified_settlement) = build_v2_noop_settlement(
        &configuration,
        inventory_script,
        queue_script,
        &Script::from(vec![0x51, 0x72]),
        destroyed_reissuance_script,
        u64::try_from(previous_state.bond.insurance_reserve).unwrap(),
        previous_state.bond.inventory_share_atoms,
    );

    let mut base = previous.transition.base.clone();
    base.previous_state = previous_state.base.clone();
    base.previous_accounts = previous.transition.base.next_accounts.clone();
    base.next_accounts = base.previous_accounts.clone();
    base.previous_positions = previous.transition.base.next_positions.clone();
    base.next_positions = base.previous_positions.clone();
    base.previous_open_orders = previous.transition.base.next_open_orders.clone();
    base.next_open_orders = base.previous_open_orders.clone();
    base.deposits.clear();
    base.withdrawals.clear();
    base.placements.clear();
    base.cancellations.clear();
    base.fills.clear();
    base.liquidations.clear();
    base.deposit_inbox = DepositInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    base.forced_inbox = ForcedInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };

    let operation_batch_hash = transition_batch_hash(&[], &[], &[], &[], &[], &[]);
    let temporary_availability_root = [0x90; 32];
    let matcher_root = central_matcher_receipt_batch_root(&[]);
    let forced_root = forced_action_batch_root(&[]);
    let deposit_root = deposit_batch_root(&[]);
    let deposit_event_root = deposit_event_batch_root(&[]);
    let withdrawal_root = withdrawal_batch_root(&[]);
    let liquidation_root = liquidation_batch_root(&[]);
    let temporary_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root: deposit_event_root,
        oracle_certificate_hash: base.public.oracle_certificate_hash,
        oracle_mode: base.public.oracle_mode,
        matcher_receipt_batch_root: matcher_root,
        collateral_settlement_root: verified_settlement.combined_settlement_root,
        forced_action_batch_root: forced_root,
        escape_only: false,
        encrypted_availability_root: temporary_availability_root,
    });
    base.next_state = base.previous_state.clone();
    base.next_state.sequence += 1;
    base.next_state.last_processed_height = sidechain_height;
    let (next_funding, funding_rate) = advance_funding_timestamped_v2(
        &previous_state.funding,
        previous.binding.prior_parent_mtp,
        base.public.mark_price,
        base.public.liquidation_low,
        base.public.liquidation_high,
        previous.transition.public.oracle_valid_through_mtp,
        &[],
        0,
    )
    .unwrap();
    base.next_state.funding_index = base
        .previous_state
        .funding_index
        .checked_add(i128::from(funding_rate))
        .unwrap();
    base.next_state.roots = StateRoots::from_private_state(
        &base.next_accounts,
        &base.next_positions,
        &base.next_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        next_order_receipts_root(
            base.previous_state.roots.order_receipts,
            temporary_batch_hash,
        ),
    )
    .unwrap();
    base.public.sidechain_height = sidechain_height;
    base.public.parent_height = parent_height;
    base.public.previous_state_root = base.previous_state.state_root();
    base.public.previous_sequence = base.previous_state.sequence;
    base.public.next_state_root = base.next_state.state_root();
    base.public.next_sequence = base.next_state.sequence;
    base.public.batch_hash = temporary_batch_hash;
    base.public.deposit_batch_root = deposit_root;
    base.public.deposit_event_batch_root = deposit_event_root;
    base.public.withdrawal_batch_root = withdrawal_root;
    base.public.collateral_settlement_root = verified_settlement.combined_settlement_root;
    base.public.liquidation_batch_root = liquidation_root;
    base.public.matcher_receipt_batch_root = matcher_root;
    base.public.forced_action_batch_root = forced_root;
    base.public.escape_only = false;
    base.public.encrypted_availability_root = temporary_availability_root;
    base.public.funding_rate_ppm = funding_rate;

    let next_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: base.next_state.clone(),
        bond: previous_state.bond,
        funding: next_funding,
        matcher_execution_sequence: previous_state.matcher_execution_sequence,
        last_transition_sidechain_height: sidechain_height,
        bond_inbox: inbox.next_state,
        bond_inbox_outcome_root: inbox.next_outcome_root,
        bond_inbox_outcome_count: previous_state.bond_inbox_outcome_count + 1,
        active_order_risk_root: previous_state.active_order_risk_root,
        position_risk_root: previous_state.position_risk_root,
    };
    let mut transition = TransitionWitnessV2 {
        public: TransitionPublicInputsV2 {
            protocol_version: TransitionPublicInputsV2::VERSION,
            configuration_hash: configuration.digest(),
            parent_mtp: previous.binding.prior_parent_mtp,
            oracle_valid_through_mtp: previous.transition.public.oracle_valid_through_mtp,
            insurance_reserve_before_bond_actions: previous_state.bond.insurance_reserve,
            authenticated_min_price: previous.transition.public.authenticated_min_price,
            authenticated_max_price: previous.transition.public.authenticated_max_price,
            authenticated_price_range_commitment: previous
                .transition
                .public
                .authenticated_price_range_commitment,
            previous_state_root: previous_state.state_root(),
            next_state_root: next_state.state_root(),
            bond_action_root: [0x91; 32],
            order_risk_root: order_risk_root_v2(&[]),
            funding_state_root: next_state.funding.root(),
            matcher_execution_receipt_batch_root:
                ecx_protocol_core::matcher_execution_receipt_batch_root_v2(&[]),
            previous_matcher_execution_sequence: previous_state.matcher_execution_sequence,
            next_matcher_execution_sequence: next_state.matcher_execution_sequence,
            base_public_digest: base.public.digest(),
        },
        configuration: configuration.clone(),
        previous_state,
        next_state,
        bond_inbox: inbox.transition,
        bond_inbox_outcomes: inbox.outcomes,
        base,
        matcher_execution_receipts: vec![],
        previous_redemption_queue: previous.transition.next_redemption_queue.clone(),
        next_redemption_queue: previous.transition.next_redemption_queue.clone(),
        subscriptions: vec![],
        recapitalization_contributions: vec![],
        redemption_enqueues: vec![],
        redemption_executions: vec![],
        redemption_cancellations: vec![],
        order_risk_commitments: vec![],
        previous_active_order_risk_commitments: previous
            .transition
            .next_active_order_risk_commitments
            .clone(),
        next_active_order_risk_commitments: previous
            .transition
            .next_active_order_risk_commitments
            .clone(),
        previous_position_risk: previous.transition.next_position_risk.clone(),
        next_position_risk: previous.transition.next_position_risk.clone(),
    };
    transition.public.bond_action_root = bond_action_root_v2(&transition);

    let current = previous.binding.next.clone();
    let next = CovenantPublicStateV2 {
        version: COVENANT_STATE_VERSION_V2,
        sequence: transition.next_state.sequence(),
        private_state_root: transition.next_state.state_root(),
        encrypted_availability_root: temporary_availability_root,
        forced_action_inbox_root: transition.next_state.base.forced_inbox.head_root,
        deposit_inbox_root: transition.next_state.base.deposit_inbox.head_root,
        configuration_hash: configuration.digest(),
        bond_state_root: bond_public_state_root_v2(&transition.next_state.bond),
        funding_state_root: transition.next_state.funding.root(),
        active_order_risk_root: transition.next_state.active_order_risk_root,
        position_risk_root: transition.next_state.position_risk_root,
        bond_inbox_head_root: transition.next_state.bond_inbox.head_root,
        bond_inbox_entry_count: transition.next_state.bond_inbox.entry_count,
        bond_inbox_processed_root: transition.next_state.bond_inbox.processed_root,
        bond_inbox_cursor: transition.next_state.bond_inbox.cursor,
        bond_inbox_outcome_root: transition.next_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: transition.next_state.bond_inbox_outcome_count,
        matcher_execution_sequence: transition.next_state.matcher_execution_sequence,
        last_transition_sidechain_height: transition.next_state.last_transition_sidechain_height,
    };
    let mut input = ProofInputV2 {
        binding: ProofBindingV2 {
            version: PROOF_BINDING_VERSION_V2,
            transition_txid_consensus: verified_settlement.transition_txid,
            prior_exchange_header_root: tagged_hash(
                "ECX/test-sequential-prior-header/v2",
                &previous.binding.next.private_state_root,
            ),
            prior_parent_block_hash: previous.binding.prior_parent_block_hash,
            prior_parent_height: parent_height,
            prior_parent_mtp: previous.binding.prior_parent_mtp,
            public_state_domain_sha256: previous.binding.public_state_domain_sha256,
            transition_journal_domain_sha256: previous.binding.transition_journal_domain_sha256,
            current,
            next,
        },
        configuration,
        truthcoin_consensus_proof: previous.truthcoin_consensus_proof.clone(),
        ecx_btc_conversion_proof: previous.ecx_btc_conversion_proof.clone(),
        usdd_usd_conversion_proof: previous.usdd_usd_conversion_proof.clone(),
        matcher_receipts: vec![],
        bond_inbox_source_evidence: vec![],
        funding_parent_chain: FundingParentChainWitnessV2::empty(),
        deposit_openings: vec![],
        transition_settlement,
        transition,
        availability_bundle: vec![],
        availability_custody_receipts: vec![],
        availability_encryption_witness: previous.availability_encryption_witness.clone(),
    };
    refresh_v2_availability(&mut input, availability_custodians, availability_public);
    input
}


fn v2_test_full_bound_deficit(
    accounts: &[AccountLeaf],
    positions: &[PositionLeaf],
    minimum: Price,
    maximum: Price,
    risk: RiskParams,
) -> u128 {
    let endpoint = |price: Price| {
        positions
            .iter()
            .map(|position| {
                let account = accounts
                    .iter()
                    .find(|account| account.trader == position.trader)
                    .unwrap();
                let quote = u128::try_from(
                    notional(price, position.position.size.unsigned_abs())
                        .unwrap()
                        .0,
                )
                .unwrap();
                let worst_funding = quote
                    .checked_mul(u128::from(risk.max_abs_funding_rate_ppm))
                    .unwrap()
                    .div_ceil(1_000_000);
                equity(account.collateral, &position.position, price)
                    .unwrap()
                    .0
                    .checked_sub(i128::try_from(worst_funding).unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    full_range_deficit(&endpoint(minimum), &endpoint(maximum)).unwrap()
}

fn v2_test_trade_parent_headers() -> Vec<[u8; 80]> {
    // Bitcoin mainnet blocks 1..=11 are used only as a compact, immutable
    // consecutive-PoW fixture. Heights are local witness indices; no claim is
    // made that this source-local composition ran against mainnet.
    const HEADERS: [&str; 11] = [
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
        "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
        "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
        "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
        "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
        "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
        "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53",
        "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565",
        "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8",
    ];
    HEADERS
        .iter()
        .map(|encoded| hex::decode(encoded).unwrap().try_into().unwrap())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn build_v2_opposing_fill_followup(
    previous: &ProofInputV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    holder_secret: &SecretKey,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) -> ProofInputV2 {
    const TRADE_PARENT_MTP: u64 = 1_231_471_789;
    let configuration = previous.configuration.clone();
    let raw_headers = v2_test_trade_parent_headers();
    let parent_hash = bitcoin_header_hash_internal_v2(raw_headers.last().unwrap());
    let parent_height = previous.binding.prior_parent_height + 1;
    let source =
        v2_test_authenticated_context(previous, parent_hash, parent_height, TRADE_PARENT_MTP);
    ecx_oracle_match::exercise(
        &configuration,
        ecx_truthcoin_proof::ParentChainContextV1 {
            block_hash: parent_hash, height: parent_height, median_time_past: TRADE_PARENT_MTP,
        },
        &source.truthcoin, &source.ecx_btc, &source.usdd_usd, &TestDigestVerifier,
    );
    let previous_state = previous.transition.next_state.clone();
    let sidechain_height = previous_state.last_transition_sidechain_height + 1;
    let old_maker_leaf = previous
        .transition
        .base
        .next_open_orders
        .first()
        .expect("subscription successor carries one authenticated maker")
        .clone();
    let old_maker = signed_order(
        holder_secret,
        Side::Sell,
        old_maker_leaf.limit_price,
        5,
        0,
        TimeInForce::GoodTilHeight,
        [0x51; 16],
    );
    assert_eq!(old_maker.order_id(), old_maker_leaf.order_id);
    assert_eq!(old_maker_leaf.remaining_quantity, Quantity::new(3).unwrap());
    let (taker_secret, taker_key) = identity(12);
    let (liquidity_secret, liquidity_key) = identity(13);
    let taker_before = previous
        .transition
        .base
        .next_accounts
        .iter()
        .find(|account| account.trader == taker_key)
        .unwrap();

    let maker_first_quantity = old_maker_leaf.remaining_quantity.get();
    let maker_first_fee = trading_fee(
        old_maker_leaf.limit_price,
        old_maker_leaf.remaining_quantity,
        configuration.base.risk.maker_fee_bps,
    )
    .unwrap();
    let taker_first_fee = trading_fee(
        old_maker_leaf.limit_price,
        old_maker_leaf.remaining_quantity,
        i32::try_from(configuration.base.risk.taker_fee_bps).unwrap(),
    )
    .unwrap();
    assert_eq!(maker_first_fee, Amount(0));

    let candidate = |second_quantity: u64| {
        let taker_second_fee = trading_fee(
            old_maker_leaf.limit_price,
            Quantity::new(second_quantity).unwrap(),
            i32::try_from(configuration.base.risk.taker_fee_bps).unwrap(),
        )
        .unwrap();
        let fee_credit = u128::try_from(taker_first_fee.0 + taker_second_fee.0).unwrap();
        let total_quantity = maker_first_quantity + second_quantity;
        let mut accounts = previous.transition.base.next_accounts.clone();
        let taker = accounts
            .iter_mut()
            .find(|account| account.trader == taker_key)
            .unwrap();
        taker.collateral = taker
            .collateral
            .checked_sub(Amount(i128::try_from(fee_credit).unwrap()))
            .unwrap();
        taker.account_nonce += 1;
        accounts
            .iter_mut()
            .find(|account| account.trader == liquidity_key)
            .unwrap()
            .account_nonce += 1;
        let positions = vec![
            position(
                old_maker.order.trader,
                -i64::try_from(maker_first_quantity).unwrap(),
                old_maker_leaf.limit_price,
                0x61,
            ),
            position(
                taker_key,
                i64::try_from(total_quantity).unwrap(),
                old_maker_leaf.limit_price,
                0x62,
            ),
            position(
                liquidity_key,
                -i64::try_from(second_quantity).unwrap(),
                old_maker_leaf.limit_price,
                0x63,
            ),
        ];
        let deficit = v2_test_full_bound_deficit(
            &accounts,
            &positions,
            source.authenticated_min_price,
            source.authenticated_max_price,
            configuration.base.risk,
        );
        let reserve = previous_state
            .bond
            .insurance_reserve
            .checked_add(fee_credit)
            .unwrap();
        let target = target_reserve_125(deficit).unwrap();
        (
            accounts,
            positions,
            taker_second_fee,
            reserve,
            deficit,
            target,
        )
    };
    let mut low = 1u64;
    let mut high = 20_000_000u64;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let (_, _, _, reserve, _, target) = candidate(middle);
        if target <= reserve {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    // Per-position integer PnL rounding must also conserve exactly at the
    // authenticated mark. Select the nearest covered quantity whose split
    // maker legs cancel the combined taker leg without a one-atom remainder.
    let second_quantity = (0..=1_000u64)
        .find_map(|offset| {
            let quantity = low.checked_sub(offset)?;
            let (_, positions, _, reserve, _, target) = candidate(quantity);
            let pnl = positions
                .iter()
                .map(|leaf| equity(Amount(0), &leaf.position, source.mark).unwrap().0)
                .sum::<i128>();
            (reserve >= target && reserve - target < 100 && pnl == 0).then_some(quantity)
        })
        .expect("covered opposing fills with exact integer-PnL conservation");
    let (next_accounts, next_positions, taker_second_fee, reserve_after, deficit, target) =
        candidate(second_quantity);
    assert!(reserve_after >= target);
    assert!(reserve_after - target < 100);
    let fee_credit =
        u64::try_from(u128::try_from(taker_first_fee.0 + taker_second_fee.0).unwrap()).unwrap();
    assert!(fee_credit > 0);

    let liquidity_order = signed_order(
        &liquidity_secret,
        Side::Sell,
        old_maker_leaf.limit_price,
        second_quantity,
        0,
        TimeInForce::GoodTilHeight,
        [0x91; 16],
    );
    let total_quantity = maker_first_quantity + second_quantity;
    let taker_order = signed_order(
        &taker_secret,
        Side::Buy,
        old_maker_leaf.limit_price,
        total_quantity,
        taker_before.account_nonce,
        TimeInForce::ImmediateOrCancel,
        [0x92; 16],
    );
    let (matcher_secret, _) = identity(7);
    let placement_sequence = previous_state.base.matcher_sequence + 1;
    let placement_receipt = CentralMatcherReceiptV1::sign(
        MatcherReceiptBodyV1 {
            version: MatcherReceiptBodyV1::VERSION,
            chain_id: configuration.base.chain_id,
            market: ECX_USDD_MARKET,
            matcher_config_hash: configuration.base.matcher.digest(),
            matcher_key_epoch: configuration.base.matcher.key_epoch,
            global_sequence: placement_sequence,
            previous_receipt_hash: previous_state.base.matcher_receipt_hash,
            command_kind: MatcherCommandKind::Place,
            command_hash: matcher_order_command_hash(&liquidity_order),
            observed_sidechain_height: previous_state.last_transition_sidechain_height,
            observed_parent_height: parent_height,
            observed_parent_mtp: TRADE_PARENT_MTP,
            forced_inbox_cursor: previous_state.base.forced_inbox.cursor,
            availability_root: [0x93; 32],
        },
        &matcher_secret,
        &configuration.base.matcher,
    )
    .unwrap();
    let taker_sequence = placement_sequence + 1;
    let taker_receipt = CentralMatcherReceiptV1::sign(
        MatcherReceiptBodyV1 {
            version: MatcherReceiptBodyV1::VERSION,
            chain_id: configuration.base.chain_id,
            market: ECX_USDD_MARKET,
            matcher_config_hash: configuration.base.matcher.digest(),
            matcher_key_epoch: configuration.base.matcher.key_epoch,
            global_sequence: taker_sequence,
            previous_receipt_hash: placement_receipt.receipt_hash(),
            command_kind: MatcherCommandKind::Place,
            command_hash: matcher_order_command_hash(&taker_order),
            observed_sidechain_height: previous_state.last_transition_sidechain_height,
            observed_parent_height: parent_height,
            observed_parent_mtp: TRADE_PARENT_MTP,
            forced_inbox_cursor: previous_state.base.forced_inbox.cursor,
            availability_root: [0x94; 32],
        },
        &matcher_secret,
        &configuration.base.matcher,
    )
    .unwrap();
    let fills = vec![
        MatchedOrderPair {
            maker_order: old_maker.clone(),
            taker_order: taker_order.clone(),
            trade: TradeMatch {
                sequence: taker_sequence,
                maker_order_id: old_maker.order_id(),
                taker_order_id: taker_order.order_id(),
                maker: old_maker.order.trader,
                taker: taker_key,
                maker_side: Side::Sell,
                price: old_maker_leaf.limit_price,
                quantity: Quantity::new(maker_first_quantity).unwrap(),
                maker_fee: maker_first_fee,
                taker_fee: taker_first_fee,
            },
        },
        MatchedOrderPair {
            maker_order: liquidity_order.clone(),
            taker_order: taker_order.clone(),
            trade: TradeMatch {
                sequence: taker_sequence,
                maker_order_id: liquidity_order.order_id(),
                taker_order_id: taker_order.order_id(),
                maker: liquidity_key,
                taker: taker_key,
                maker_side: Side::Sell,
                price: old_maker_leaf.limit_price,
                quantity: Quantity::new(second_quantity).unwrap(),
                maker_fee: Amount(0),
                taker_fee: taker_second_fee,
            },
        },
    ];
    let first_execution = MatcherExecutionReceiptV2::issue(
        &configuration.base.matcher,
        &matcher_secret,
        configuration.base.chain_id,
        &fills[0].maker_order,
        &fills[0].taker_order,
        &fills[0].trade,
        previous_state.matcher_execution_sequence + 1,
        &taker_receipt,
        parent_hash,
    )
    .unwrap();
    let second_execution = MatcherExecutionReceiptV2::issue(
        &configuration.base.matcher,
        &matcher_secret,
        configuration.base.chain_id,
        &fills[1].maker_order,
        &fills[1].taker_order,
        &fills[1].trade,
        previous_state.matcher_execution_sequence + 2,
        &taker_receipt,
        parent_hash,
    )
    .unwrap();
    let matcher_execution_receipts = vec![first_execution, second_execution];
    let funding_parent_chain = compose_funding_parent_chain_v2(
        parent_height - 10,
        &raw_headers,
        parent_hash,
        parent_height,
        TRADE_PARENT_MTP,
        &matcher_execution_receipts,
        configuration.matcher_execution_inclusion_parent_blocks,
    )
    .unwrap();
    let observations = fills
        .iter()
        .map(|pair| {
            TimestampedFundingObservationV2::new(
                pair.trade.price,
                pair.trade.quantity,
                TRADE_PARENT_MTP,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let (next_funding, funding_rate) = advance_funding_timestamped_v2(
        &previous_state.funding,
        TRADE_PARENT_MTP,
        source.mark,
        source.liquidation_low,
        source.liquidation_high,
        source.oracle_valid_through_mtp,
        &observations,
        0,
    )
    .unwrap();
    assert_eq!(funding_rate, 0);

    let (transition_settlement, verified_settlement) = build_v2_reserve_credit_settlement(
        &configuration,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        u64::try_from(previous_state.bond.insurance_reserve).unwrap(),
        fee_credit,
        previous_state.bond.inventory_share_atoms,
    );
    let mut base = previous.transition.base.clone();
    base.previous_state = previous_state.base.clone();
    base.previous_accounts = previous.transition.base.next_accounts.clone();
    base.next_accounts = next_accounts;
    base.previous_positions = previous.transition.base.next_positions.clone();
    base.next_positions = next_positions;
    base.previous_open_orders = previous.transition.base.next_open_orders.clone();
    base.next_open_orders = vec![];
    base.previous_deposit_nullifiers = previous.transition.base.previous_deposit_nullifiers.clone();
    base.previous_withdrawal_nullifiers = previous
        .transition
        .base
        .previous_withdrawal_nullifiers
        .clone();
    base.deposit_inbox = DepositInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    base.forced_inbox = ForcedInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    base.deposits.clear();
    base.withdrawals.clear();
    base.placements = vec![OrderPlacement {
        order: liquidity_order.clone(),
        received_sequence: placement_sequence,
        salt: [0x95; 32],
    }];
    base.cancellations.clear();
    base.fills = fills;
    base.liquidations.clear();
    let matcher_receipts = vec![placement_receipt, taker_receipt];
    let temporary_availability_root = [0x96; 32];
    let operation_batch_hash =
        transition_batch_hash(&[], &[], &base.placements, &[], &base.fills, &[]);
    let matcher_root = central_matcher_receipt_batch_root(&matcher_receipts);
    let forced_root = forced_action_batch_root(&[]);
    let temporary_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root: deposit_event_batch_root(&[]),
        oracle_certificate_hash: source.oracle_certificate_hash,
        oracle_mode: OracleMode::Normal,
        matcher_receipt_batch_root: matcher_root,
        collateral_settlement_root: verified_settlement.combined_settlement_root,
        forced_action_batch_root: forced_root,
        escape_only: false,
        encrypted_availability_root: temporary_availability_root,
    });
    base.next_state = base.previous_state.clone();
    base.next_state.sequence += 1;
    base.next_state.last_processed_height = sidechain_height;
    base.next_state.mark_price = source.mark;
    base.next_state.funding_index = base.previous_state.funding_index;
    base.next_state.insurance_fund = Amount(i128::try_from(reserve_after).unwrap());
    base.next_state.matcher_sequence = taker_sequence;
    base.next_state.matcher_receipt_hash = matcher_receipts.last().unwrap().receipt_hash();
    base.next_state.roots = StateRoots::from_private_state(
        &base.next_accounts,
        &base.next_positions,
        &base.next_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        next_order_receipts_root(
            base.previous_state.roots.order_receipts,
            temporary_batch_hash,
        ),
    )
    .unwrap();
    base.public.sidechain_height = sidechain_height;
    base.public.parent_height = parent_height;
    base.public.previous_state_root = base.previous_state.state_root();
    base.public.previous_sequence = base.previous_state.sequence;
    base.public.next_state_root = base.next_state.state_root();
    base.public.next_sequence = base.next_state.sequence;
    base.public.batch_hash = temporary_batch_hash;
    base.public.deposit_batch_root = deposit_batch_root(&[]);
    base.public.deposit_event_batch_root = deposit_event_batch_root(&[]);
    base.public.withdrawal_batch_root = withdrawal_batch_root(&[]);
    base.public.collateral_settlement_root = verified_settlement.combined_settlement_root;
    base.public.liquidation_batch_root = liquidation_batch_root(&[]);
    base.public.matcher_receipt_batch_root = matcher_root;
    base.public.forced_action_batch_root = forced_root;
    base.public.escape_only = false;
    base.public.encrypted_availability_root = temporary_availability_root;
    base.public.oracle_certificate_hash = source.oracle_certificate_hash;
    base.public.oracle_mode = OracleMode::Normal;
    base.public.mark_price = source.mark;
    base.public.liquidation_low = source.liquidation_low;
    base.public.liquidation_high = source.liquidation_high;
    base.public.funding_rate_ppm = funding_rate;

    let mut next_bond = previous_state.bond;
    next_bond.insurance_reserve = reserve_after;
    next_bond.full_bound_deficit = deficit;
    next_bond.target_reserve = target;
    next_bond.capital_mode = capital_mode_for(reserve_after, deficit).unwrap();
    next_bond.validate().unwrap();
    assert_eq!(next_bond.capital_mode, CapitalModeV2::Normal);
    let previous_active = previous
        .transition
        .next_active_order_risk_commitments
        .clone();
    let old_maker_risk = previous_active.first().unwrap().clone();
    let liquidity_risk = OrderRiskCommitmentV2::sign(
        configuration.digest(),
        liquidity_order.order_id(),
        liquidity_key,
        configuration.base.risk.initial_margin_bps,
        &liquidity_secret,
    )
    .unwrap();
    let taker_risk = OrderRiskCommitmentV2::sign(
        configuration.digest(),
        taker_order.order_id(),
        taker_key,
        configuration.base.risk.initial_margin_bps,
        &taker_secret,
    )
    .unwrap();
    let order_risk_commitments = vec![old_maker_risk.clone(), liquidity_risk, taker_risk];
    let mut next_position_risk = previous.transition.next_position_risk.clone();
    for risk in &mut next_position_risk {
        if risk.trader == old_maker.order.trader {
            risk.selected_initial_margin_bps = old_maker_risk.selected_initial_margin_bps;
        }
    }
    let next_position_risk_root = position_risk_root_v2(&next_position_risk).unwrap();
    let next_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: base.next_state.clone(),
        bond: next_bond,
        funding: next_funding,
        matcher_execution_sequence: previous_state.matcher_execution_sequence + 2,
        last_transition_sidechain_height: sidechain_height,
        bond_inbox: previous_state.bond_inbox,
        bond_inbox_outcome_root: previous_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: previous_state.bond_inbox_outcome_count,
        active_order_risk_root: active_order_risk_root_v2(&[]).unwrap(),
        position_risk_root: next_position_risk_root,
    };
    let mut transition = TransitionWitnessV2 {
        public: TransitionPublicInputsV2 {
            protocol_version: TransitionPublicInputsV2::VERSION,
            configuration_hash: configuration.digest(),
            parent_mtp: TRADE_PARENT_MTP,
            oracle_valid_through_mtp: source.oracle_valid_through_mtp,
            insurance_reserve_before_bond_actions: reserve_after,
            authenticated_min_price: source.authenticated_min_price,
            authenticated_max_price: source.authenticated_max_price,
            authenticated_price_range_commitment: source.authenticated_price_range_commitment,
            previous_state_root: previous_state.state_root(),
            next_state_root: next_state.state_root(),
            bond_action_root: [0x97; 32],
            order_risk_root: order_risk_root_v2(&order_risk_commitments),
            funding_state_root: next_state.funding.root(),
            matcher_execution_receipt_batch_root:
                ecx_protocol_core::matcher_execution_receipt_batch_root_v2(
                    &matcher_execution_receipts,
                ),
            previous_matcher_execution_sequence: previous_state.matcher_execution_sequence,
            next_matcher_execution_sequence: next_state.matcher_execution_sequence,
            base_public_digest: base.public.digest(),
        },
        configuration: configuration.clone(),
        previous_state,
        next_state,
        bond_inbox: BondInboxTransitionV2 {
            pending_entries: vec![],
            consumed_evidence: vec![],
        },
        bond_inbox_outcomes: vec![],
        base,
        matcher_execution_receipts,
        previous_redemption_queue: previous.transition.next_redemption_queue.clone(),
        next_redemption_queue: previous.transition.next_redemption_queue.clone(),
        subscriptions: vec![],
        recapitalization_contributions: vec![],
        redemption_enqueues: vec![],
        redemption_executions: vec![],
        redemption_cancellations: vec![],
        order_risk_commitments,
        previous_active_order_risk_commitments: previous_active,
        next_active_order_risk_commitments: vec![],
        previous_position_risk: previous.transition.next_position_risk.clone(),
        next_position_risk,
    };
    transition.public.bond_action_root = bond_action_root_v2(&transition);
    let current = previous.binding.next.clone();
    let next = CovenantPublicStateV2 {
        version: COVENANT_STATE_VERSION_V2,
        sequence: transition.next_state.sequence(),
        private_state_root: transition.next_state.state_root(),
        encrypted_availability_root: temporary_availability_root,
        forced_action_inbox_root: transition.next_state.base.forced_inbox.head_root,
        deposit_inbox_root: transition.next_state.base.deposit_inbox.head_root,
        configuration_hash: configuration.digest(),
        bond_state_root: bond_public_state_root_v2(&transition.next_state.bond),
        funding_state_root: transition.next_state.funding.root(),
        active_order_risk_root: transition.next_state.active_order_risk_root,
        position_risk_root: transition.next_state.position_risk_root,
        bond_inbox_head_root: transition.next_state.bond_inbox.head_root,
        bond_inbox_entry_count: transition.next_state.bond_inbox.entry_count,
        bond_inbox_processed_root: transition.next_state.bond_inbox.processed_root,
        bond_inbox_cursor: transition.next_state.bond_inbox.cursor,
        bond_inbox_outcome_root: transition.next_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: transition.next_state.bond_inbox_outcome_count,
        matcher_execution_sequence: transition.next_state.matcher_execution_sequence,
        last_transition_sidechain_height: transition.next_state.last_transition_sidechain_height,
    };
    let mut input = ProofInputV2 {
        binding: ProofBindingV2 {
            version: PROOF_BINDING_VERSION_V2,
            transition_txid_consensus: verified_settlement.transition_txid,
            prior_exchange_header_root: tagged_hash(
                "ECX/test-v18-trade-prior-header/v2",
                &previous.binding.next.private_state_root,
            ),
            prior_parent_block_hash: parent_hash,
            prior_parent_height: parent_height,
            prior_parent_mtp: TRADE_PARENT_MTP,
            public_state_domain_sha256: previous.binding.public_state_domain_sha256,
            transition_journal_domain_sha256: previous.binding.transition_journal_domain_sha256,
            current,
            next,
        },
        configuration,
        truthcoin_consensus_proof: source.truthcoin,
        ecx_btc_conversion_proof: source.ecx_btc,
        usdd_usd_conversion_proof: source.usdd_usd,
        matcher_receipts,
        bond_inbox_source_evidence: vec![],
        funding_parent_chain,
        deposit_openings: vec![],
        transition_settlement,
        transition,
        availability_bundle: vec![],
        availability_custody_receipts: vec![],
        availability_encryption_witness: previous.availability_encryption_witness.clone(),
    };
    refresh_v2_availability(&mut input, availability_custodians, availability_public);
    input
}

/// Refresh deterministic source-public-values fixtures for a later parent
/// context. The digest receipts produced here are test-only and are accepted
/// only by `TestDigestVerifier`; no cryptographic proof is manufactured.
fn v2_test_authenticated_context(
    previous: &ProofInputV2,
    parent_hash: Hash32,
    parent_height: u64,
    parent_mtp: u64,
) -> V2TestAuthenticatedContext {
    v2_test_authenticated_context_with_anchor(
        previous,
        parent_hash,
        parent_height,
        parent_mtp,
        None,
    )
}

/// As above, with an optional later finalized Truthcoin anchor price. The
/// resulting recursive receipt remains a deterministic `TestDigestVerifier`
/// fixture and is not a cryptographic source proof.
fn v2_test_authenticated_context_with_anchor(
    previous: &ProofInputV2,
    parent_hash: Hash32,
    parent_height: u64,
    parent_mtp: u64,
    anchor_btc_usd_price: Option<Price>,
) -> V2TestAuthenticatedContext {
    oracle_context::context_with_anchor(
        &previous.configuration, &previous.truthcoin_consensus_proof,
        &previous.ecx_btc_conversion_proof, &previous.usdd_usd_conversion_proof,
        parent_hash, parent_height, parent_mtp, anchor_btc_usd_price,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_v2_hourly_funding_followup(
    previous: &ProofInputV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
    parent_hash: Hash32,
    parent_height: u64,
    parent_mtp: u64,
) -> ProofInputV2 {
    let configuration = previous.configuration.clone();
    let source = v2_test_authenticated_context(previous, parent_hash, parent_height, parent_mtp);
    let previous_state = previous.transition.next_state.clone();
    let sidechain_height = previous_state.last_transition_sidechain_height + 1;
    let (transition_settlement, verified_settlement) = build_v2_noop_settlement(
        &configuration,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        u64::try_from(previous_state.bond.insurance_reserve).unwrap(),
        previous_state.bond.inventory_share_atoms,
    );

    let mut base = previous.transition.base.clone();
    base.previous_state = previous_state.base.clone();
    base.previous_accounts = previous.transition.base.next_accounts.clone();
    base.next_accounts = base.previous_accounts.clone();
    base.previous_positions = previous.transition.base.next_positions.clone();
    base.next_positions = base.previous_positions.clone();
    base.previous_open_orders = previous.transition.base.next_open_orders.clone();
    base.next_open_orders = base.previous_open_orders.clone();
    base.deposits.clear();
    base.withdrawals.clear();
    base.placements.clear();
    base.cancellations.clear();
    base.fills.clear();
    base.liquidations.clear();
    base.deposit_inbox = DepositInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    base.forced_inbox = ForcedInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };

    let open_interest_notional = previous
        .transition
        .base
        .next_positions
        .iter()
        .filter(|position| position.position.size > 0)
        .try_fold(0u128, |total, position| {
            let value = notional(
                previous_state.funding.last_oracle_mark,
                position.position.size.unsigned_abs(),
            )?;
            total
                .checked_add(u128::try_from(value.0).unwrap())
                .ok_or(ecx_protocol_core::ProtocolError::ArithmeticOverflow)
        })
        .unwrap();
    let (next_funding, funding_rate) = advance_funding_timestamped_v2(
        &previous_state.funding,
        parent_mtp,
        source.mark,
        source.liquidation_low,
        source.liquidation_high,
        source.oracle_valid_through_mtp,
        &[],
        open_interest_notional,
    )
    .unwrap();
    assert_eq!(funding_rate, 0);
    let temporary_availability_root = [0xa1; 32];
    let operation_batch_hash = transition_batch_hash(&[], &[], &[], &[], &[], &[]);
    let matcher_root = central_matcher_receipt_batch_root(&[]);
    let forced_root = forced_action_batch_root(&[]);
    let deposit_root = deposit_batch_root(&[]);
    let deposit_event_root = deposit_event_batch_root(&[]);
    let withdrawal_root = withdrawal_batch_root(&[]);
    let liquidation_root = liquidation_batch_root(&[]);
    let temporary_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root: deposit_event_root,
        oracle_certificate_hash: source.oracle_certificate_hash,
        oracle_mode: OracleMode::Normal,
        matcher_receipt_batch_root: matcher_root,
        collateral_settlement_root: verified_settlement.combined_settlement_root,
        forced_action_batch_root: forced_root,
        escape_only: false,
        encrypted_availability_root: temporary_availability_root,
    });
    base.next_state = base.previous_state.clone();
    base.next_state.sequence += 1;
    base.next_state.last_processed_height = sidechain_height;
    base.next_state.mark_price = source.mark;
    base.next_state.funding_index = base.previous_state.funding_index;
    base.next_state.roots = StateRoots::from_private_state(
        &base.next_accounts,
        &base.next_positions,
        &base.next_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        next_order_receipts_root(
            base.previous_state.roots.order_receipts,
            temporary_batch_hash,
        ),
    )
    .unwrap();
    base.public.sidechain_height = sidechain_height;
    base.public.parent_height = parent_height;
    base.public.previous_state_root = base.previous_state.state_root();
    base.public.previous_sequence = base.previous_state.sequence;
    base.public.next_state_root = base.next_state.state_root();
    base.public.next_sequence = base.next_state.sequence;
    base.public.batch_hash = temporary_batch_hash;
    base.public.deposit_batch_root = deposit_root;
    base.public.deposit_event_batch_root = deposit_event_root;
    base.public.withdrawal_batch_root = withdrawal_root;
    base.public.collateral_settlement_root = verified_settlement.combined_settlement_root;
    base.public.liquidation_batch_root = liquidation_root;
    base.public.matcher_receipt_batch_root = matcher_root;
    base.public.forced_action_batch_root = forced_root;
    base.public.escape_only = false;
    base.public.encrypted_availability_root = temporary_availability_root;
    base.public.oracle_certificate_hash = source.oracle_certificate_hash;
    base.public.oracle_mode = OracleMode::Normal;
    base.public.mark_price = source.mark;
    base.public.liquidation_low = source.liquidation_low;
    base.public.liquidation_high = source.liquidation_high;
    base.public.funding_rate_ppm = funding_rate;

    let next_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: base.next_state.clone(),
        bond: previous_state.bond,
        funding: next_funding,
        matcher_execution_sequence: previous_state.matcher_execution_sequence,
        last_transition_sidechain_height: sidechain_height,
        bond_inbox: previous_state.bond_inbox,
        bond_inbox_outcome_root: previous_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: previous_state.bond_inbox_outcome_count,
        active_order_risk_root: previous_state.active_order_risk_root,
        position_risk_root: previous_state.position_risk_root,
    };
    let mut transition = TransitionWitnessV2 {
        public: TransitionPublicInputsV2 {
            protocol_version: TransitionPublicInputsV2::VERSION,
            configuration_hash: configuration.digest(),
            parent_mtp,
            oracle_valid_through_mtp: source.oracle_valid_through_mtp,
            insurance_reserve_before_bond_actions: previous_state.bond.insurance_reserve,
            authenticated_min_price: source.authenticated_min_price,
            authenticated_max_price: source.authenticated_max_price,
            authenticated_price_range_commitment: source.authenticated_price_range_commitment,
            previous_state_root: previous_state.state_root(),
            next_state_root: next_state.state_root(),
            bond_action_root: [0xa2; 32],
            order_risk_root: order_risk_root_v2(&[]),
            funding_state_root: next_state.funding.root(),
            matcher_execution_receipt_batch_root:
                ecx_protocol_core::matcher_execution_receipt_batch_root_v2(&[]),
            previous_matcher_execution_sequence: previous_state.matcher_execution_sequence,
            next_matcher_execution_sequence: next_state.matcher_execution_sequence,
            base_public_digest: base.public.digest(),
        },
        configuration: configuration.clone(),
        previous_state,
        next_state,
        bond_inbox: BondInboxTransitionV2 {
            pending_entries: vec![],
            consumed_evidence: vec![],
        },
        bond_inbox_outcomes: vec![],
        base,
        matcher_execution_receipts: vec![],
        previous_redemption_queue: previous.transition.next_redemption_queue.clone(),
        next_redemption_queue: previous.transition.next_redemption_queue.clone(),
        subscriptions: vec![],
        recapitalization_contributions: vec![],
        redemption_enqueues: vec![],
        redemption_executions: vec![],
        redemption_cancellations: vec![],
        order_risk_commitments: vec![],
        previous_active_order_risk_commitments: previous
            .transition
            .next_active_order_risk_commitments
            .clone(),
        next_active_order_risk_commitments: previous
            .transition
            .next_active_order_risk_commitments
            .clone(),
        previous_position_risk: previous.transition.next_position_risk.clone(),
        next_position_risk: previous.transition.next_position_risk.clone(),
    };
    transition.public.bond_action_root = bond_action_root_v2(&transition);

    let current = previous.binding.next.clone();
    let next = CovenantPublicStateV2 {
        version: COVENANT_STATE_VERSION_V2,
        sequence: transition.next_state.sequence(),
        private_state_root: transition.next_state.state_root(),
        encrypted_availability_root: temporary_availability_root,
        forced_action_inbox_root: transition.next_state.base.forced_inbox.head_root,
        deposit_inbox_root: transition.next_state.base.deposit_inbox.head_root,
        configuration_hash: configuration.digest(),
        bond_state_root: bond_public_state_root_v2(&transition.next_state.bond),
        funding_state_root: transition.next_state.funding.root(),
        active_order_risk_root: transition.next_state.active_order_risk_root,
        position_risk_root: transition.next_state.position_risk_root,
        bond_inbox_head_root: transition.next_state.bond_inbox.head_root,
        bond_inbox_entry_count: transition.next_state.bond_inbox.entry_count,
        bond_inbox_processed_root: transition.next_state.bond_inbox.processed_root,
        bond_inbox_cursor: transition.next_state.bond_inbox.cursor,
        bond_inbox_outcome_root: transition.next_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: transition.next_state.bond_inbox_outcome_count,
        matcher_execution_sequence: transition.next_state.matcher_execution_sequence,
        last_transition_sidechain_height: transition.next_state.last_transition_sidechain_height,
    };
    let mut input = ProofInputV2 {
        binding: ProofBindingV2 {
            version: PROOF_BINDING_VERSION_V2,
            transition_txid_consensus: verified_settlement.transition_txid,
            prior_exchange_header_root: tagged_hash(
                "ECX/test-v18-hourly-prior-header/v2",
                &previous.binding.next.private_state_root,
            ),
            prior_parent_block_hash: parent_hash,
            prior_parent_height: parent_height,
            prior_parent_mtp: parent_mtp,
            public_state_domain_sha256: previous.binding.public_state_domain_sha256,
            transition_journal_domain_sha256: previous.binding.transition_journal_domain_sha256,
            current,
            next,
        },
        configuration,
        truthcoin_consensus_proof: source.truthcoin,
        ecx_btc_conversion_proof: source.ecx_btc,
        usdd_usd_conversion_proof: source.usdd_usd,
        matcher_receipts: vec![],
        bond_inbox_source_evidence: vec![],
        funding_parent_chain: FundingParentChainWitnessV2::empty(),
        deposit_openings: vec![],
        transition_settlement,
        transition,
        availability_bundle: vec![],
        availability_custody_receipts: vec![],
        availability_encryption_witness: previous.availability_encryption_witness.clone(),
    };
    refresh_v2_availability(&mut input, availability_custodians, availability_public);
    input
}

/// Close the large opposing legs against a newly authenticated reduce-only
/// resting maker after a fresh, lower finalized Truthcoin anchor makes the
/// long fail maintenance at the operational low. The source receipt is still
/// only a deterministic `TestDigestVerifier` fixture; every transition,
/// signature, risk, funding and confidential-settlement relation is the
/// production Rust relation.
#[allow(clippy::too_many_arguments)]
fn build_v2_liquidation_followup(
    previous: &ProofInputV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) -> ProofInputV2 {
    let configuration = previous.configuration.clone();
    let previous_state = previous.transition.next_state.clone();
    let parent_height = previous.binding.prior_parent_height + 1;
    let parent_mtp = previous.binding.prior_parent_mtp + 1;
    let parent_hash = tagged_hash(
        "ECX/test-v18-liquidation-parent/v2",
        &previous.binding.prior_parent_block_hash,
    );
    let sidechain_height = previous_state.last_transition_sidechain_height + 1;
    let (maker_secret, maker_key) = identity(13);
    let (_, target_key) = identity(12);
    let maker_position_leaf = previous
        .transition
        .base
        .next_positions
        .iter()
        .find(|position| position.trader == maker_key)
        .unwrap();
    let target_position_leaf = previous
        .transition
        .base
        .next_positions
        .iter()
        .find(|position| position.trader == target_key)
        .unwrap();
    assert!(maker_position_leaf.position.size < 0);
    assert!(target_position_leaf.position.size > 0);
    let target_account_before = previous
        .transition
        .base
        .next_accounts
        .iter()
        .find(|account| account.trader == target_key)
        .unwrap();
    // Find the least severe later finalized anchor (highest price) that still
    // produces an exact maintenance breach. This keeps the liquidation
    // minimal and leaves a deterministic but strictly partial redemption
    // capacity for the subsequent FIFO phase.
    let mut anchor_low = 50_000 * PRICE_SCALE;
    let mut anchor_high = 60_000 * PRICE_SCALE;
    while anchor_low < anchor_high {
        let middle = anchor_low + (anchor_high - anchor_low).div_ceil(2);
        let candidate = v2_test_authenticated_context_with_anchor(
            previous,
            parent_hash,
            parent_height,
            parent_mtp,
            Some(Price::new(middle).unwrap()),
        );
        if is_liquidatable(
            target_account_before.collateral,
            &target_position_leaf.position,
            candidate.liquidation_low,
            configuration.base.risk,
        )
        .unwrap()
        {
            anchor_low = middle;
        } else {
            anchor_high = middle - 1;
        }
    }
    let source = v2_test_authenticated_context_with_anchor(
        previous,
        parent_hash,
        parent_height,
        parent_mtp,
        Some(Price::new(anchor_low).unwrap()),
    );
    assert!(is_liquidatable(
        target_account_before.collateral,
        &target_position_leaf.position,
        source.liquidation_low,
        configuration.base.risk,
    )
    .unwrap());

    let maximum_liquidation_quantity = maker_position_leaf.position.size.unsigned_abs();
    let liquidation_restores_safety = |quantity: u64| {
        let quantity = Quantity::new(quantity).unwrap();
        let outcome = apply_fill(
            target_position_leaf.position,
            Side::Sell,
            quantity,
            Price::new(maker_position_leaf.position.entry_price).unwrap(),
        )
        .unwrap();
        let desired_penalty = trading_fee(
            Price::new(maker_position_leaf.position.entry_price).unwrap(),
            quantity,
            i32::try_from(configuration.base.risk.liquidation_fee_bps).unwrap(),
        )
        .unwrap();
        let collateral = target_account_before
            .collateral
            .checked_add(outcome.realized_pnl)
            .unwrap();
        let penalty = Amount(desired_penalty.0.min(collateral.0.max(0)));
        !is_liquidatable(
            collateral.checked_sub(penalty).unwrap(),
            &outcome.position,
            source.liquidation_low,
            configuration.base.risk,
        )
        .unwrap()
    };
    let mut quantity_low = 1u64;
    let mut quantity_high = maximum_liquidation_quantity;
    assert!(liquidation_restores_safety(quantity_high));
    while quantity_low < quantity_high {
        let middle = quantity_low + (quantity_high - quantity_low) / 2;
        if liquidation_restores_safety(middle) {
            quantity_high = middle;
        } else {
            quantity_low = middle + 1;
        }
    }
    let liquidation_quantity = Quantity::new(
        quantity_low
            .checked_add(100)
            .filter(|quantity| *quantity <= maximum_liquidation_quantity)
            .unwrap(),
    )
    .unwrap();
    let maker_account = previous
        .transition
        .base
        .next_accounts
        .iter()
        .find(|account| account.trader == maker_key)
        .unwrap();
    let maker_order = SignedLimitOrder::sign(
        ecx_protocol_core::LimitOrder {
            version: ecx_protocol_core::LimitOrder::VERSION,
            chain_id: configuration.base.chain_id,
            market: ECX_USDD_MARKET,
            trader: maker_key,
            side: Side::Buy,
            time_in_force: TimeInForce::GoodTilHeight,
            flags: OrderFlags::REDUCE_ONLY,
            limit_price: Price::new(maker_position_leaf.position.entry_price).unwrap(),
            quantity: liquidation_quantity,
            client_order_id: [0xa3; 16],
            max_fee_bps: 20,
            nonce: maker_account.account_nonce,
            valid_from_height: 1,
            expires_at_height: sidechain_height + 20,
        },
        &maker_secret,
    )
    .unwrap();
    let placement_sequence = previous_state.base.matcher_sequence + 1;
    let (matcher_secret, _) = identity(7);
    let placement_receipt = CentralMatcherReceiptV1::sign(
        MatcherReceiptBodyV1 {
            version: MatcherReceiptBodyV1::VERSION,
            chain_id: configuration.base.chain_id,
            market: ECX_USDD_MARKET,
            matcher_config_hash: configuration.base.matcher.digest(),
            matcher_key_epoch: configuration.base.matcher.key_epoch,
            global_sequence: placement_sequence,
            previous_receipt_hash: previous_state.base.matcher_receipt_hash,
            command_kind: MatcherCommandKind::Place,
            command_hash: matcher_order_command_hash(&maker_order),
            observed_sidechain_height: previous_state.last_transition_sidechain_height,
            observed_parent_height: parent_height,
            observed_parent_mtp: parent_mtp,
            forced_inbox_cursor: previous_state.base.forced_inbox.cursor,
            availability_root: [0xa4; 32],
        },
        &matcher_secret,
        &configuration.base.matcher,
    )
    .unwrap();
    let liquidation_match = LiquidationMatchV1 {
        target: target_key,
        maker_order: maker_order.clone(),
        quantity: liquidation_quantity,
    };

    let maker_outcome = apply_fill(
        maker_position_leaf.position,
        Side::Buy,
        liquidation_quantity,
        maker_order.order.limit_price,
    )
    .unwrap();
    let target_outcome = apply_fill(
        target_position_leaf.position,
        Side::Sell,
        liquidation_quantity,
        maker_order.order.limit_price,
    )
    .unwrap();
    assert!(
        maker_outcome.position.size.unsigned_abs()
            < maker_position_leaf.position.size.unsigned_abs()
    );
    assert!(
        target_outcome.position.size.unsigned_abs()
            < target_position_leaf.position.size.unsigned_abs()
    );
    assert_eq!(maker_outcome.realized_pnl, Amount(0));
    assert_eq!(target_outcome.realized_pnl, Amount(0));
    let maker_fee = trading_fee(
        maker_order.order.limit_price,
        liquidation_quantity,
        configuration.base.risk.maker_fee_bps,
    )
    .unwrap();
    assert_eq!(maker_fee, Amount(0));
    let desired_penalty = trading_fee(
        maker_order.order.limit_price,
        liquidation_quantity,
        i32::try_from(configuration.base.risk.liquidation_fee_bps).unwrap(),
    )
    .unwrap();
    let target_collateral = previous
        .transition
        .base
        .next_accounts
        .iter()
        .find(|account| account.trader == target_key)
        .unwrap()
        .collateral
        .checked_add(target_outcome.realized_pnl)
        .unwrap();
    let penalty = Amount(desired_penalty.0.min(target_collateral.0.max(0)));
    assert!(penalty.0 > 0);
    assert_eq!(
        Amount((-target_collateral.checked_sub(penalty).unwrap().0).max(0)),
        Amount(0)
    );
    let penalty_atoms = u64::try_from(penalty.0).unwrap();

    let mut next_accounts = previous.transition.base.next_accounts.clone();
    let maker_next = next_accounts
        .iter_mut()
        .find(|account| account.trader == maker_key)
        .unwrap();
    maker_next.account_nonce += 1;
    maker_next.collateral = maker_next
        .collateral
        .checked_add(maker_outcome.realized_pnl)
        .unwrap()
        .checked_sub(maker_fee)
        .unwrap();
    maker_next.cumulative_realized_pnl = maker_next
        .cumulative_realized_pnl
        .checked_add(maker_outcome.realized_pnl)
        .unwrap();
    let target_next = next_accounts
        .iter_mut()
        .find(|account| account.trader == target_key)
        .unwrap();
    target_next.collateral = target_next
        .collateral
        .checked_add(target_outcome.realized_pnl)
        .unwrap()
        .checked_sub(penalty)
        .unwrap();
    target_next.cumulative_realized_pnl = target_next
        .cumulative_realized_pnl
        .checked_add(target_outcome.realized_pnl)
        .unwrap();
    let mut next_positions = previous.transition.base.next_positions.clone();
    next_positions
        .iter_mut()
        .find(|position| position.trader == maker_key)
        .unwrap()
        .position = maker_outcome.position;
    next_positions
        .iter_mut()
        .find(|position| position.trader == target_key)
        .unwrap()
        .position = target_outcome.position;

    let open_interest_notional = previous
        .transition
        .base
        .next_positions
        .iter()
        .filter(|position| position.position.size > 0)
        .try_fold(0u128, |total, position| {
            let value = notional(
                previous_state.funding.last_oracle_mark,
                position.position.size.unsigned_abs(),
            )?;
            total
                .checked_add(u128::try_from(value.0).unwrap())
                .ok_or(ecx_protocol_core::ProtocolError::ArithmeticOverflow)
        })
        .unwrap();
    let observation = TimestampedFundingObservationV2::new(
        maker_order.order.limit_price,
        liquidation_quantity,
        parent_mtp,
    )
    .unwrap();
    let (next_funding, funding_rate) = advance_funding_timestamped_v2(
        &previous_state.funding,
        parent_mtp,
        source.mark,
        source.liquidation_low,
        source.liquidation_high,
        source.oracle_valid_through_mtp,
        &[observation],
        open_interest_notional,
    )
    .unwrap();
    assert_eq!(funding_rate, 0);
    let reserve_after = previous_state
        .bond
        .insurance_reserve
        .checked_add(u128::from(penalty_atoms))
        .unwrap();
    let (transition_settlement, verified_settlement) = build_v2_reserve_credit_settlement(
        &configuration,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        u64::try_from(previous_state.bond.insurance_reserve).unwrap(),
        penalty_atoms,
        previous_state.bond.inventory_share_atoms,
    );

    let mut base = previous.transition.base.clone();
    base.previous_state = previous_state.base.clone();
    base.previous_accounts = previous.transition.base.next_accounts.clone();
    base.next_accounts = next_accounts;
    base.previous_positions = previous.transition.base.next_positions.clone();
    base.next_positions = next_positions;
    base.previous_open_orders = previous.transition.base.next_open_orders.clone();
    base.next_open_orders.clear();
    base.deposits.clear();
    base.withdrawals.clear();
    base.placements = vec![OrderPlacement {
        order: maker_order.clone(),
        received_sequence: placement_sequence,
        salt: [0xa5; 32],
    }];
    base.cancellations.clear();
    base.fills.clear();
    base.liquidations = vec![liquidation_match];
    base.deposit_inbox = DepositInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    base.forced_inbox = ForcedInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    let matcher_receipts = vec![placement_receipt];
    let temporary_availability_root = [0xa6; 32];
    let operation_batch_hash =
        transition_batch_hash(&[], &[], &base.placements, &[], &[], &base.liquidations);
    let matcher_root = central_matcher_receipt_batch_root(&matcher_receipts);
    let forced_root = forced_action_batch_root(&[]);
    let temporary_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root: deposit_event_batch_root(&[]),
        oracle_certificate_hash: source.oracle_certificate_hash,
        oracle_mode: OracleMode::Normal,
        matcher_receipt_batch_root: matcher_root,
        collateral_settlement_root: verified_settlement.combined_settlement_root,
        forced_action_batch_root: forced_root,
        escape_only: false,
        encrypted_availability_root: temporary_availability_root,
    });
    base.next_state = base.previous_state.clone();
    base.next_state.sequence += 1;
    base.next_state.last_processed_height = sidechain_height;
    base.next_state.mark_price = source.mark;
    base.next_state.funding_index = base
        .previous_state
        .funding_index
        .checked_add(i128::from(funding_rate))
        .unwrap();
    base.next_state.insurance_fund = Amount(i128::try_from(reserve_after).unwrap());
    base.next_state.matcher_sequence = placement_sequence;
    base.next_state.matcher_receipt_hash = matcher_receipts.last().unwrap().receipt_hash();
    base.next_state.roots = StateRoots::from_private_state(
        &base.next_accounts,
        &base.next_positions,
        &base.next_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        next_order_receipts_root(
            base.previous_state.roots.order_receipts,
            temporary_batch_hash,
        ),
    )
    .unwrap();
    base.public.sidechain_height = sidechain_height;
    base.public.parent_height = parent_height;
    base.public.previous_state_root = base.previous_state.state_root();
    base.public.previous_sequence = base.previous_state.sequence;
    base.public.next_state_root = base.next_state.state_root();
    base.public.next_sequence = base.next_state.sequence;
    base.public.batch_hash = temporary_batch_hash;
    base.public.deposit_batch_root = deposit_batch_root(&[]);
    base.public.deposit_event_batch_root = deposit_event_batch_root(&[]);
    base.public.withdrawal_batch_root = withdrawal_batch_root(&[]);
    base.public.collateral_settlement_root = verified_settlement.combined_settlement_root;
    base.public.liquidation_batch_root = liquidation_batch_root(&base.liquidations);
    base.public.matcher_receipt_batch_root = matcher_root;
    base.public.forced_action_batch_root = forced_root;
    base.public.escape_only = false;
    base.public.encrypted_availability_root = temporary_availability_root;
    base.public.oracle_certificate_hash = source.oracle_certificate_hash;
    base.public.oracle_mode = OracleMode::Normal;
    base.public.mark_price = source.mark;
    base.public.liquidation_low = source.liquidation_low;
    base.public.liquidation_high = source.liquidation_high;
    base.public.funding_rate_ppm = funding_rate;

    let deficit = v2_test_full_bound_deficit(
        &base.next_accounts,
        &base.next_positions,
        source.authenticated_min_price,
        source.authenticated_max_price,
        configuration.base.risk,
    );
    let mut next_bond = previous_state.bond;
    next_bond.insurance_reserve = reserve_after;
    next_bond.full_bound_deficit = deficit;
    next_bond.target_reserve = target_reserve_125(deficit).unwrap();
    next_bond.capital_mode = capital_mode_for(reserve_after, deficit).unwrap();
    next_bond.validate().unwrap();
    assert_eq!(next_bond.capital_mode, CapitalModeV2::Normal);
    let selected_margin_bps = previous
        .transition
        .next_position_risk
        .iter()
        .find(|risk| risk.trader == maker_key)
        .unwrap()
        .selected_initial_margin_bps;
    let order_risk_commitments = vec![OrderRiskCommitmentV2::sign(
        configuration.digest(),
        maker_order.order_id(),
        maker_key,
        selected_margin_bps,
        &maker_secret,
    )
    .unwrap()];
    let next_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: base.next_state.clone(),
        bond: next_bond,
        funding: next_funding,
        matcher_execution_sequence: previous_state.matcher_execution_sequence,
        last_transition_sidechain_height: sidechain_height,
        bond_inbox: previous_state.bond_inbox,
        bond_inbox_outcome_root: previous_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: previous_state.bond_inbox_outcome_count,
        active_order_risk_root: active_order_risk_root_v2(&[]).unwrap(),
        position_risk_root: previous_state.position_risk_root,
    };
    let mut transition = TransitionWitnessV2 {
        public: TransitionPublicInputsV2 {
            protocol_version: TransitionPublicInputsV2::VERSION,
            configuration_hash: configuration.digest(),
            parent_mtp,
            oracle_valid_through_mtp: source.oracle_valid_through_mtp,
            insurance_reserve_before_bond_actions: reserve_after,
            authenticated_min_price: source.authenticated_min_price,
            authenticated_max_price: source.authenticated_max_price,
            authenticated_price_range_commitment: source.authenticated_price_range_commitment,
            previous_state_root: previous_state.state_root(),
            next_state_root: next_state.state_root(),
            bond_action_root: [0xa7; 32],
            order_risk_root: order_risk_root_v2(&order_risk_commitments),
            funding_state_root: next_state.funding.root(),
            matcher_execution_receipt_batch_root:
                ecx_protocol_core::matcher_execution_receipt_batch_root_v2(&[]),
            previous_matcher_execution_sequence: previous_state.matcher_execution_sequence,
            next_matcher_execution_sequence: previous_state.matcher_execution_sequence,
            base_public_digest: base.public.digest(),
        },
        configuration: configuration.clone(),
        previous_state,
        next_state,
        bond_inbox: BondInboxTransitionV2 {
            pending_entries: vec![],
            consumed_evidence: vec![],
        },
        bond_inbox_outcomes: vec![],
        base,
        matcher_execution_receipts: vec![],
        previous_redemption_queue: previous.transition.next_redemption_queue.clone(),
        next_redemption_queue: previous.transition.next_redemption_queue.clone(),
        subscriptions: vec![],
        recapitalization_contributions: vec![],
        redemption_enqueues: vec![],
        redemption_executions: vec![],
        redemption_cancellations: vec![],
        order_risk_commitments,
        previous_active_order_risk_commitments: previous
            .transition
            .next_active_order_risk_commitments
            .clone(),
        next_active_order_risk_commitments: vec![],
        previous_position_risk: previous.transition.next_position_risk.clone(),
        next_position_risk: previous.transition.next_position_risk.clone(),
    };
    transition.public.bond_action_root = bond_action_root_v2(&transition);
    let current = previous.binding.next.clone();
    let next = CovenantPublicStateV2 {
        version: COVENANT_STATE_VERSION_V2,
        sequence: transition.next_state.sequence(),
        private_state_root: transition.next_state.state_root(),
        encrypted_availability_root: temporary_availability_root,
        forced_action_inbox_root: transition.next_state.base.forced_inbox.head_root,
        deposit_inbox_root: transition.next_state.base.deposit_inbox.head_root,
        configuration_hash: configuration.digest(),
        bond_state_root: bond_public_state_root_v2(&transition.next_state.bond),
        funding_state_root: transition.next_state.funding.root(),
        active_order_risk_root: transition.next_state.active_order_risk_root,
        position_risk_root: transition.next_state.position_risk_root,
        bond_inbox_head_root: transition.next_state.bond_inbox.head_root,
        bond_inbox_entry_count: transition.next_state.bond_inbox.entry_count,
        bond_inbox_processed_root: transition.next_state.bond_inbox.processed_root,
        bond_inbox_cursor: transition.next_state.bond_inbox.cursor,
        bond_inbox_outcome_root: transition.next_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: transition.next_state.bond_inbox_outcome_count,
        matcher_execution_sequence: transition.next_state.matcher_execution_sequence,
        last_transition_sidechain_height: transition.next_state.last_transition_sidechain_height,
    };
    let mut input = ProofInputV2 {
        binding: ProofBindingV2 {
            version: PROOF_BINDING_VERSION_V2,
            transition_txid_consensus: verified_settlement.transition_txid,
            prior_exchange_header_root: tagged_hash(
                "ECX/test-v18-liquidation-prior-header/v2",
                &previous.binding.next.private_state_root,
            ),
            prior_parent_block_hash: parent_hash,
            prior_parent_height: parent_height,
            prior_parent_mtp: parent_mtp,
            public_state_domain_sha256: previous.binding.public_state_domain_sha256,
            transition_journal_domain_sha256: previous.binding.transition_journal_domain_sha256,
            current,
            next,
        },
        configuration,
        truthcoin_consensus_proof: source.truthcoin,
        ecx_btc_conversion_proof: source.ecx_btc,
        usdd_usd_conversion_proof: source.usdd_usd,
        matcher_receipts,
        bond_inbox_source_evidence: vec![],
        funding_parent_chain: FundingParentChainWitnessV2::empty(),
        deposit_openings: vec![],
        transition_settlement,
        transition,
        availability_bundle: vec![],
        availability_custody_receipts: vec![],
        availability_encryption_witness: previous.availability_encryption_witness.clone(),
    };
    refresh_v2_availability(&mut input, availability_custodians, availability_public);
    input
}

struct V2BondPhase {
    parent_hash: Hash32,
    parent_height: u64,
    parent_mtp: u64,
    transition_settlement: TransitionSettlementV2,
    verified_settlement: ecx_elements_settlement::VerifiedTransitionSettlementV2,
    bond_inbox: BondInboxTransitionV2,
    bond_inbox_outcomes: Vec<BondInboxProcessedOutcomeV2>,
    bond_inbox_source_evidence: Vec<BondInboxSourceTransactionEvidenceV2>,
    next_bond_inbox: BondInboxStateV2,
    next_bond_inbox_outcome_root: Hash32,
    next_bond_inbox_outcome_count: u64,
    next_bond: BondPublicStateV2,
    next_redemption_queue: Vec<ecx_protocol_core::RedemptionQueueEntryV2>,
    redemption_enqueues: Vec<SignedRedemptionEnqueueV2>,
    redemption_executions: Vec<RedemptionExecutionV2>,
    redemption_cancellations: Vec<SignedRedemptionCancellationV2>,
    next_accounts: Vec<AccountLeaf>,
    prior_header_domain: &'static str,
}

#[allow(clippy::too_many_arguments)]
fn build_v2_bond_phase_followup(
    previous: &ProofInputV2,
    phase: V2BondPhase,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) -> ProofInputV2 {
    let configuration = previous.configuration.clone();
    let previous_state = previous.transition.next_state.clone();
    let source = v2_test_authenticated_context(
        previous,
        phase.parent_hash,
        phase.parent_height,
        phase.parent_mtp,
    );
    let sidechain_height = previous_state.last_transition_sidechain_height + 1;
    let open_interest_notional = previous
        .transition
        .base
        .next_positions
        .iter()
        .filter(|position| position.position.size > 0)
        .try_fold(0u128, |total, position| {
            let value = notional(
                previous_state.funding.last_oracle_mark,
                position.position.size.unsigned_abs(),
            )?;
            total
                .checked_add(u128::try_from(value.0).unwrap())
                .ok_or(ecx_protocol_core::ProtocolError::ArithmeticOverflow)
        })
        .unwrap();
    let (next_funding, funding_rate) = advance_funding_timestamped_v2(
        &previous_state.funding,
        phase.parent_mtp,
        source.mark,
        source.liquidation_low,
        source.liquidation_high,
        source.oracle_valid_through_mtp,
        &[],
        open_interest_notional,
    )
    .unwrap();
    assert_eq!(funding_rate, 0);
    let paid_usdd_atoms = phase
        .redemption_executions
        .iter()
        .try_fold(0u128, |total, execution| {
            total.checked_add(execution.paid_usdd_atoms)
        })
        .unwrap();

    let mut base = previous.transition.base.clone();
    base.previous_state = previous_state.base.clone();
    base.previous_accounts = previous.transition.base.next_accounts.clone();
    base.next_accounts = phase.next_accounts;
    base.previous_positions = previous.transition.base.next_positions.clone();
    base.next_positions = base.previous_positions.clone();
    base.previous_open_orders = previous.transition.base.next_open_orders.clone();
    base.next_open_orders = base.previous_open_orders.clone();
    base.deposits.clear();
    base.withdrawals.clear();
    base.placements.clear();
    base.cancellations.clear();
    base.fills.clear();
    base.liquidations.clear();
    base.deposit_inbox = DepositInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    base.forced_inbox = ForcedInboxTransitionV1 {
        pending_entries: vec![],
        consumed_count: 0,
    };
    let temporary_availability_root = [0xd9; 32];
    let operation_batch_hash = transition_batch_hash(&[], &[], &[], &[], &[], &[]);
    let matcher_root = central_matcher_receipt_batch_root(&[]);
    let forced_root = forced_action_batch_root(&[]);
    let temporary_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root: deposit_event_batch_root(&[]),
        oracle_certificate_hash: source.oracle_certificate_hash,
        oracle_mode: OracleMode::Normal,
        matcher_receipt_batch_root: matcher_root,
        collateral_settlement_root: phase.verified_settlement.combined_settlement_root,
        forced_action_batch_root: forced_root,
        escape_only: false,
        encrypted_availability_root: temporary_availability_root,
    });
    base.next_state = base.previous_state.clone();
    base.next_state.sequence += 1;
    base.next_state.last_processed_height = sidechain_height;
    base.next_state.mark_price = source.mark;
    base.next_state.funding_index = base
        .previous_state
        .funding_index
        .checked_add(i128::from(funding_rate))
        .unwrap();
    base.next_state.insurance_fund =
        Amount(i128::try_from(phase.next_bond.insurance_reserve).unwrap());
    base.next_state.total_withdrawals = base
        .previous_state
        .total_withdrawals
        .checked_add(Amount(i128::try_from(paid_usdd_atoms).unwrap()))
        .unwrap();
    base.next_state.roots = StateRoots::from_private_state(
        &base.next_accounts,
        &base.next_positions,
        &base.next_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        next_order_receipts_root(
            base.previous_state.roots.order_receipts,
            temporary_batch_hash,
        ),
    )
    .unwrap();
    base.public.sidechain_height = sidechain_height;
    base.public.parent_height = phase.parent_height;
    base.public.previous_state_root = base.previous_state.state_root();
    base.public.previous_sequence = base.previous_state.sequence;
    base.public.next_state_root = base.next_state.state_root();
    base.public.next_sequence = base.next_state.sequence;
    base.public.batch_hash = temporary_batch_hash;
    base.public.deposit_batch_root = deposit_batch_root(&[]);
    base.public.deposit_event_batch_root = deposit_event_batch_root(&[]);
    base.public.withdrawal_batch_root = withdrawal_batch_root(&[]);
    base.public.collateral_settlement_root = phase.verified_settlement.combined_settlement_root;
    base.public.liquidation_batch_root = liquidation_batch_root(&[]);
    base.public.matcher_receipt_batch_root = matcher_root;
    base.public.forced_action_batch_root = forced_root;
    base.public.escape_only = false;
    base.public.encrypted_availability_root = temporary_availability_root;
    base.public.oracle_certificate_hash = source.oracle_certificate_hash;
    base.public.oracle_mode = OracleMode::Normal;
    base.public.mark_price = source.mark;
    base.public.liquidation_low = source.liquidation_low;
    base.public.liquidation_high = source.liquidation_high;
    base.public.funding_rate_ppm = funding_rate;

    let next_state = ExchangeStateV2 {
        version: ExchangeStateV2::VERSION,
        base: base.next_state.clone(),
        bond: phase.next_bond,
        funding: next_funding,
        matcher_execution_sequence: previous_state.matcher_execution_sequence,
        last_transition_sidechain_height: sidechain_height,
        bond_inbox: phase.next_bond_inbox,
        bond_inbox_outcome_root: phase.next_bond_inbox_outcome_root,
        bond_inbox_outcome_count: phase.next_bond_inbox_outcome_count,
        active_order_risk_root: previous_state.active_order_risk_root,
        position_risk_root: previous_state.position_risk_root,
    };
    let mut transition = TransitionWitnessV2 {
        public: TransitionPublicInputsV2 {
            protocol_version: TransitionPublicInputsV2::VERSION,
            configuration_hash: configuration.digest(),
            parent_mtp: phase.parent_mtp,
            oracle_valid_through_mtp: source.oracle_valid_through_mtp,
            insurance_reserve_before_bond_actions: previous_state.bond.insurance_reserve,
            authenticated_min_price: source.authenticated_min_price,
            authenticated_max_price: source.authenticated_max_price,
            authenticated_price_range_commitment: source.authenticated_price_range_commitment,
            previous_state_root: previous_state.state_root(),
            next_state_root: next_state.state_root(),
            bond_action_root: [0xda; 32],
            order_risk_root: order_risk_root_v2(&[]),
            funding_state_root: next_state.funding.root(),
            matcher_execution_receipt_batch_root:
                ecx_protocol_core::matcher_execution_receipt_batch_root_v2(&[]),
            previous_matcher_execution_sequence: previous_state.matcher_execution_sequence,
            next_matcher_execution_sequence: previous_state.matcher_execution_sequence,
            base_public_digest: base.public.digest(),
        },
        configuration: configuration.clone(),
        previous_state,
        next_state,
        bond_inbox: phase.bond_inbox,
        bond_inbox_outcomes: phase.bond_inbox_outcomes,
        base,
        matcher_execution_receipts: vec![],
        previous_redemption_queue: previous.transition.next_redemption_queue.clone(),
        next_redemption_queue: phase.next_redemption_queue,
        subscriptions: vec![],
        recapitalization_contributions: vec![],
        redemption_enqueues: phase.redemption_enqueues,
        redemption_executions: phase.redemption_executions,
        redemption_cancellations: phase.redemption_cancellations,
        order_risk_commitments: vec![],
        previous_active_order_risk_commitments: previous
            .transition
            .next_active_order_risk_commitments
            .clone(),
        next_active_order_risk_commitments: previous
            .transition
            .next_active_order_risk_commitments
            .clone(),
        previous_position_risk: previous.transition.next_position_risk.clone(),
        next_position_risk: previous.transition.next_position_risk.clone(),
    };
    transition.public.bond_action_root = bond_action_root_v2(&transition);
    let current = previous.binding.next.clone();
    let next = CovenantPublicStateV2 {
        version: COVENANT_STATE_VERSION_V2,
        sequence: transition.next_state.sequence(),
        private_state_root: transition.next_state.state_root(),
        encrypted_availability_root: temporary_availability_root,
        forced_action_inbox_root: transition.next_state.base.forced_inbox.head_root,
        deposit_inbox_root: transition.next_state.base.deposit_inbox.head_root,
        configuration_hash: configuration.digest(),
        bond_state_root: bond_public_state_root_v2(&transition.next_state.bond),
        funding_state_root: transition.next_state.funding.root(),
        active_order_risk_root: transition.next_state.active_order_risk_root,
        position_risk_root: transition.next_state.position_risk_root,
        bond_inbox_head_root: transition.next_state.bond_inbox.head_root,
        bond_inbox_entry_count: transition.next_state.bond_inbox.entry_count,
        bond_inbox_processed_root: transition.next_state.bond_inbox.processed_root,
        bond_inbox_cursor: transition.next_state.bond_inbox.cursor,
        bond_inbox_outcome_root: transition.next_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: transition.next_state.bond_inbox_outcome_count,
        matcher_execution_sequence: transition.next_state.matcher_execution_sequence,
        last_transition_sidechain_height: transition.next_state.last_transition_sidechain_height,
    };
    let mut input = ProofInputV2 {
        binding: ProofBindingV2 {
            version: PROOF_BINDING_VERSION_V2,
            transition_txid_consensus: phase.verified_settlement.transition_txid,
            prior_exchange_header_root: tagged_hash(
                phase.prior_header_domain,
                &previous.binding.next.private_state_root,
            ),
            prior_parent_block_hash: phase.parent_hash,
            prior_parent_height: phase.parent_height,
            prior_parent_mtp: phase.parent_mtp,
            public_state_domain_sha256: previous.binding.public_state_domain_sha256,
            transition_journal_domain_sha256: previous.binding.transition_journal_domain_sha256,
            current,
            next,
        },
        configuration,
        truthcoin_consensus_proof: source.truthcoin,
        ecx_btc_conversion_proof: source.ecx_btc,
        usdd_usd_conversion_proof: source.usdd_usd,
        matcher_receipts: vec![],
        bond_inbox_source_evidence: phase.bond_inbox_source_evidence,
        funding_parent_chain: FundingParentChainWitnessV2::empty(),
        deposit_openings: vec![],
        transition_settlement: phase.transition_settlement,
        transition,
        availability_bundle: vec![],
        availability_custody_receipts: vec![],
        availability_encryption_witness: previous.availability_encryption_witness.clone(),
    };
    refresh_v2_availability(&mut input, availability_custodians, availability_public);
    input
}

#[allow(clippy::too_many_arguments)]
fn build_v2_redemption_enqueue_followup(
    previous: &ProofInputV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    holder_secret: &SecretKey,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) -> ProofInputV2 {
    const REQUESTED_SHARES: u64 = 100;
    let configuration = &previous.configuration;
    let previous_state = &previous.transition.next_state;
    let parent_height = previous.binding.prior_parent_height + 1;
    let parent_mtp = previous.binding.prior_parent_mtp + 1;
    let parent_hash = tagged_hash(
        "ECX/test-v18-enqueue-parent/v2",
        &previous.binding.prior_parent_block_hash,
    );
    let claimant = identity(11).1;
    let account_nonce = previous
        .transition
        .base
        .next_accounts
        .iter()
        .find(|account| account.trader == claimant)
        .unwrap()
        .account_nonce;
    let inbox = build_v2_enqueue_inbox_source(
        configuration,
        previous_state.bond_inbox,
        previous_state.bond_inbox_outcome_root,
        holder_secret,
        account_nonce,
        REQUESTED_SHARES,
        availability_custodians,
        availability_public,
        previous_state.last_transition_sidechain_height,
        parent_height,
    );
    let entry = inbox
        .signed
        .action
        .queue_entry(
            previous_state.bond.redemption_tail,
            inbox.recovered.entry.entry_hash(),
            parent_height,
        )
        .unwrap();
    let next_queue = vec![entry];
    let mut next_bond = previous_state.bond;
    next_bond.redemption_tail += 1;
    next_bond.redemption_head = entry.sequence;
    next_bond.queued_redemption_share_atoms = next_bond
        .queued_redemption_share_atoms
        .checked_add(entry.remaining_share_atoms)
        .unwrap();
    next_bond.redemption_queue_root = redemption_queue_root_v2(&next_queue);
    next_bond.validate().unwrap();
    assert_eq!(next_bond.capital_mode, CapitalModeV2::Normal);
    let mut next_accounts = previous.transition.base.next_accounts.clone();
    next_accounts
        .iter_mut()
        .find(|account| account.trader == claimant)
        .unwrap()
        .account_nonce += 1;
    let (transition_settlement, verified_settlement) = build_v2_enqueue_settlement(
        configuration,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        &inbox,
        entry,
        u64::try_from(previous_state.bond.insurance_reserve).unwrap(),
        previous_state.bond.inventory_share_atoms,
    );
    build_v2_bond_phase_followup(
        previous,
        V2BondPhase {
            parent_hash,
            parent_height,
            parent_mtp,
            transition_settlement,
            verified_settlement,
            bond_inbox: inbox.recovered.transition,
            bond_inbox_outcomes: inbox.recovered.outcomes,
            bond_inbox_source_evidence: inbox.recovered.source_evidence,
            next_bond_inbox: inbox.recovered.next_state,
            next_bond_inbox_outcome_root: inbox.recovered.next_outcome_root,
            next_bond_inbox_outcome_count: previous_state.bond_inbox_outcome_count + 1,
            next_bond,
            next_redemption_queue: next_queue,
            redemption_enqueues: vec![inbox.signed],
            redemption_executions: vec![],
            redemption_cancellations: vec![],
            next_accounts,
            prior_header_domain: "ECX/test-v18-enqueue-prior-header/v2",
        },
        availability_custodians,
        availability_public,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_v2_redemption_execution_followup(
    previous: &ProofInputV2,
    enqueue_settlement: &TransitionSettlementV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    parent_height: u64,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) -> ProofInputV2 {
    let previous_state = &previous.transition.next_state;
    let entry = previous.transition.next_redemption_queue[0];
    let parent_mtp = previous.binding.prior_parent_mtp + 1;
    let parent_hash = tagged_hash(
        "ECX/test-v18-redemption-execute-parent/v2",
        &[
            previous.binding.prior_parent_block_hash.as_slice(),
            &parent_height.to_be_bytes(),
        ]
        .concat(),
    );
    let outcome = plan_fifo_redemption(previous_state.bond, entry, entry.unlock_parent_height)
        .unwrap()
        .unwrap();
    assert!(outcome.redeemed_share_atoms > 0);
    assert!(outcome.remaining_entry_share_atoms > 0);
    let (transition_settlement, verified_settlement, execution) =
        build_v2_redemption_execution_settlement(
            &previous.configuration,
            inventory_script,
            queue_script,
            insurance_script,
            destroyed_reissuance_script,
            enqueue_settlement,
            previous_state.bond,
            entry,
            outcome,
        );
    let mut remaining = entry;
    remaining.remaining_share_atoms = outcome.remaining_entry_share_atoms;
    let next_queue = vec![remaining];
    let mut next_bond = previous_state.bond;
    next_bond.insurance_reserve = outcome.insurance_reserve_after;
    next_bond.outstanding_share_atoms = outcome.outstanding_share_atoms_after;
    next_bond.inventory_share_atoms = outcome.inventory_share_atoms_after;
    next_bond.queued_redemption_share_atoms = outcome.queued_redemption_share_atoms_after;
    next_bond.redemption_head = remaining.sequence;
    next_bond.redemption_queue_root = redemption_queue_root_v2(&next_queue);
    next_bond.capital_mode =
        capital_mode_for(next_bond.insurance_reserve, next_bond.full_bound_deficit).unwrap();
    next_bond.validate().unwrap();
    build_v2_bond_phase_followup(
        previous,
        V2BondPhase {
            parent_hash,
            parent_height,
            parent_mtp,
            transition_settlement,
            verified_settlement,
            bond_inbox: BondInboxTransitionV2 {
                pending_entries: vec![],
                consumed_evidence: vec![],
            },
            bond_inbox_outcomes: vec![],
            bond_inbox_source_evidence: vec![],
            next_bond_inbox: previous_state.bond_inbox,
            next_bond_inbox_outcome_root: previous_state.bond_inbox_outcome_root,
            next_bond_inbox_outcome_count: previous_state.bond_inbox_outcome_count,
            next_bond,
            next_redemption_queue: next_queue,
            redemption_enqueues: vec![],
            redemption_executions: vec![execution],
            redemption_cancellations: vec![],
            next_accounts: previous.transition.base.next_accounts.clone(),
            prior_header_domain: "ECX/test-v18-redemption-execute-prior-header/v2",
        },
        availability_custodians,
        availability_public,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_v2_redemption_cancellation_followup(
    previous: &ProofInputV2,
    execution_settlement: &TransitionSettlementV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    holder_secret: &SecretKey,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) -> ProofInputV2 {
    let previous_state = &previous.transition.next_state;
    let entry = previous.transition.next_redemption_queue[0];
    let parent_height = previous.binding.prior_parent_height + 1;
    let parent_mtp = previous.binding.prior_parent_mtp + 1;
    let parent_hash = tagged_hash(
        "ECX/test-v18-redemption-cancel-parent/v2",
        &previous.binding.prior_parent_block_hash,
    );
    let (transition_settlement, verified_settlement, signed) =
        build_v2_redemption_cancellation_settlement(
            &previous.configuration,
            inventory_script,
            queue_script,
            insurance_script,
            destroyed_reissuance_script,
            execution_settlement,
            previous_state.bond,
            entry,
            holder_secret,
        );
    let outcome = plan_redemption_cancellation(previous_state.bond, entry).unwrap();
    assert_eq!(outcome.released_share_atoms, entry.remaining_share_atoms);
    let mut next_bond = previous_state.bond;
    next_bond.queued_redemption_share_atoms = outcome.queued_redemption_share_atoms_after;
    next_bond.redemption_head = next_bond.redemption_tail;
    next_bond.redemption_queue_root = redemption_queue_root_v2(&[]);
    next_bond.validate().unwrap();
    let inbox = build_v2_recovered_inbox_source(
        &previous.configuration,
        previous_state.bond_inbox,
        previous_state.bond_inbox_outcome_root,
        BondInboxUserActionV2::RedemptionCancellation(signed.clone()),
        holder_secret,
        availability_custodians,
        availability_public,
        previous_state.last_transition_sidechain_height,
        parent_height,
        None,
    );
    build_v2_bond_phase_followup(
        previous,
        V2BondPhase {
            parent_hash,
            parent_height,
            parent_mtp,
            transition_settlement,
            verified_settlement,
            bond_inbox: inbox.transition,
            bond_inbox_outcomes: inbox.outcomes,
            bond_inbox_source_evidence: inbox.source_evidence,
            next_bond_inbox: inbox.next_state,
            next_bond_inbox_outcome_root: inbox.next_outcome_root,
            next_bond_inbox_outcome_count: previous_state.bond_inbox_outcome_count + 1,
            next_bond,
            next_redemption_queue: vec![],
            redemption_enqueues: vec![],
            redemption_executions: vec![],
            redemption_cancellations: vec![signed],
            next_accounts: previous.transition.base.next_accounts.clone(),
            prior_header_domain: "ECX/test-v18-redemption-cancel-prior-header/v2",
        },
        availability_custodians,
        availability_public,
    )
}

/// Re-run the recursive bond-action statement against one already-valid V18
/// lifecycle phase. This covers authenticated enqueue, mature partial
/// execution and signed cancellation without treating test digests as proofs.
#[cfg(any())]
fn assert_incremental_bond_action_phase(input: &ProofInputV2) {
    let transition = &input.transition;
    let bounds = IncrementalAccountingBoundsV2 {
        maximum_abs_trader_collateral_atoms: 10_000_000,
        maximum_total_controlled_atoms: 100_000_000,
        maximum_abs_position_atoms: 10_000_000,
        maximum_open_interest_atoms: 100_000_000,
        maximum_price_atoms: 10_000_000_000,
    };
    let mut consumed = Vec::new();
    let mut settlement_actions = Vec::new();
    let mut mutation_chains = Vec::new();
    for entry in &transition.bond_inbox.pending_entries {
        let action = transition
            .redemption_enqueues
            .iter()
            .find(|signed| signed.action.action_id() == entry.marker.action_id)
            .map(|signed| BondInboxUserActionV2::RedemptionEnqueue(signed.clone()))
            .or_else(|| {
                transition
                    .redemption_cancellations
                    .iter()
                    .find(|signed| signed.action.action_id() == entry.marker.action_id)
                    .map(|signed| BondInboxUserActionV2::RedemptionCancellation(signed.clone()))
            })
            .expect("accepted lifecycle inbox action");
        consumed.push(BondInboxConsumedOutcomeV2 {
            entry_index: entry.index,
            entry_hash: entry.entry_hash(),
            marker_kind: entry.marker.kind,
            marker_action_id: entry.marker.action_id,
            source_parent_height: entry.observed_parent_height,
            disposition: BondInboxConsumedDispositionV2::Action(Ok(action.clone())),
        });
        match action {
            BondInboxUserActionV2::RedemptionEnqueue(signed) => {
                let queued = signed
                    .action
                    .queue_entry(
                        transition.previous_state.bond.redemption_tail,
                        entry.entry_hash(),
                        entry.observed_parent_height,
                    )
                    .unwrap();
                let script = bond_inbox_redemption_staging_script_v2(
                    &input.configuration,
                    BondInboxRedemptionStagingRendererInputV2 {
                        chain_id: input.configuration.base.chain_id,
                        configuration_hash: input.configuration.digest(),
                        marker_signer: entry.marker.signer,
                        stable_intent_id: entry.marker.staging_intent_id,
                        staging_vout: entry.marker.staging_vout,
                        refund_script_sha256: entry.marker.refund_script_sha256,
                        refund_not_before_parent_height: entry
                            .marker
                            .refund_not_before_parent_height,
                    },
                )
                .unwrap();
                settlement_actions.push(BondSettlementActionV2::EnqueueRedemption {
                    redemption_id: queued.request_id,
                    staging_intent_id: signed.action.stable_intent_id(),
                    claimant: signed.action.claimant.0,
                    bond_share_amount: signed.action.requested_share_atoms,
                    staging_script_sha256: Sha256::digest(script.as_bytes()).into(),
                    source_txid: entry.source_txid,
                    source_vout: entry.marker.staging_vout,
                    source_authorization_commitment: entry.marker.source_authorization_commitment,
                    refund_script_sha256: signed.action.refund_script_sha256,
                    refund_not_before_parent_height: signed.action.refund_not_before_parent_height,
                    destination_script_sha256: signed.action.destination_script_hash,
                });
                let previous_account = transition
                    .base
                    .previous_accounts
                    .iter()
                    .find(|account| account.trader == signed.action.claimant)
                    .unwrap();
                let old_leaf = TraderLeafV2 {
                    version: TraderLeafV2::VERSION,
                    trader: previous_account.trader,
                    account_nonce: u128::from(previous_account.account_nonce),
                    collateral_atoms: previous_account.collateral.0,
                    cash_residual_numerator: 0,
                    position_size_atoms: 0,
                    signed_cost_basis_numerator: Int256V2::ZERO,
                    last_funding_index_numerator: 0,
                    selected_initial_margin_bps: input.configuration.base.risk.initial_margin_bps,
                    order_generation: 0,
                    salt: [0x91; 32],
                };
                let event_id = incremental_bond_trader_mutation_event_id_v2(
                    entry.entry_hash(),
                    signed.action.action_id(),
                )
                .unwrap();
                let mutation = IncrementalTraderEconomicMutationV2 {
                    kind: IncrementalTraderMutationKindV2::BondRedemptionEnqueue,
                    action_id: event_id,
                    exact_cash_delta_numerator: Int256V2::ZERO,
                    position_size_delta_atoms: 0,
                    signed_cost_basis_delta_numerator: Int256V2::ZERO,
                    funding_checkpoint_after: None,
                    account_nonce_increment: 1,
                    order_generation_increment: 0,
                    selected_initial_margin_bps_after: None,
                };
                let mut new_leaf = old_leaf.clone();
                new_leaf.account_nonce += 1;
                new_leaf.salt = [0x92; 32];
                mutation_chains.push(IncrementalTraderMutationChainV2 {
                    trader: old_leaf.trader,
                    old_leaf,
                    mutations: vec![mutation],
                    final_salt: new_leaf.salt,
                    expected_new_leaf: new_leaf,
                });
            }
            BondInboxUserActionV2::RedemptionCancellation(signed) => {
                let queued = transition
                    .previous_redemption_queue
                    .iter()
                    .find(|queued| {
                        queued.sequence == signed.action.sequence
                            && queued.request_id == signed.action.request_id
                    })
                    .unwrap();
                settlement_actions.push(BondSettlementActionV2::CancelRedemption {
                    redemption_id: queued.request_id,
                    claimant: signed.action.claimant.0,
                    bond_share_amount: queued.remaining_share_atoms,
                    recipient_script_sha256: signed.action.bond_recipient_script_sha256,
                    cancellation_id: signed.action.cancellation_id(),
                });
            }
            _ => unreachable!(),
        }
    }
    for execution in &transition.redemption_executions {
        let queued = transition.previous_redemption_queue[0];
        settlement_actions.push(BondSettlementActionV2::ExecuteRedemption {
            redemption_id: queued.request_id,
            claimant: queued.claimant_commitment,
            queued_share_amount: queued.remaining_share_atoms,
            redeemed_share_amount: execution.redeemed_share_atoms,
            remainder_share_amount: queued.remaining_share_atoms - execution.redeemed_share_atoms,
            usdd_payment_amount: u64::try_from(execution.paid_usdd_atoms).unwrap(),
            destination_script_sha256: queued.destination_script_hash,
        });
    }
    let child_input = IncrementalBondActionChildInputV2 {
        version: ecx_proof_core::INCREMENTAL_BOND_ACTION_CHILD_VERSION_V2,
        configuration: input.configuration.clone(),
        chain_id: input.configuration.base.chain_id,
        accounting_bounds: bounds,
        previous_bond: transition.previous_state.bond,
        next_bond: transition.next_state.bond,
        previous_queue: transition.previous_redemption_queue.clone(),
        next_queue: transition.next_redemption_queue.clone(),
        parent_height: input.binding.prior_parent_height,
        insurance_reserve_before_bond_actions: transition
            .public
            .insurance_reserve_before_bond_actions,
        consumed_outcomes: consumed,
        consumed_entries: transition.bond_inbox.pending_entries.clone(),
        previous_outcome_root: transition.previous_state.bond_inbox_outcome_root,
        previous_outcome_count: transition.previous_state.bond_inbox_outcome_count,
        next_outcome_root: transition.next_state.bond_inbox_outcome_root,
        next_outcome_count: transition.next_state.bond_inbox_outcome_count,
        redemption_executions: transition.redemption_executions.clone(),
        settlement_actions,
        trader_mutation_chains: mutation_chains,
        previous_trader_root: canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
        trader_reads: None,
        read_only_action_events: vec![],
    };
    execute_incremental_bond_action_child_v2(&child_input)
        .expect("incremental bond child matches finite lifecycle phase");
    let mut missing_settlement_role = child_input.clone();
    missing_settlement_role.settlement_actions.pop();
    assert!(execute_incremental_bond_action_child_v2(&missing_settlement_role).is_err());
    let mut substituted_outcome_accumulator = child_input;
    substituted_outcome_accumulator.next_outcome_root[0] ^= 1;
    assert!(execute_incremental_bond_action_child_v2(&substituted_outcome_accumulator).is_err());
}

/// One state-threaded, source-local lifecycle composition. Recursive receipts
/// remain deterministic test digests, so this deliberately is not presented
/// as a cryptographic E2E or production proof. Unlike isolated unit selectors,
/// each phase consumes the state produced by the phase before it.
#[allow(clippy::too_many_arguments)]
fn exercise_non_cryptographic_v2_insurance_lifecycle_composition(
    seed: &ProofInputV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    holder_secret: &SecretKey,
    availability_custodians: &[CustodianSecrets],
    availability_public: &[ecx_witness_availability::CustodianPublic],
) {
    assert_eq!(seed.transition.next_state.bond.insurance_reserve, 400);
    assert_eq!(seed.transition.next_state.bond.outstanding_share_atoms, 400);
    assert_eq!(
        seed.transition.next_state.bond.inventory_share_atoms + 400,
        BOND_FIXED_SUPPLY_ATOMS
    );

    let trade = build_v2_opposing_fill_followup(
        seed,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        holder_secret,
        availability_custodians,
        availability_public,
    );
    let trade_result = execute_proof_v2_with_consensus_verifier(&trade, &TestDigestVerifier)
        .expect("state-threaded non-cryptographic opposing-fill V18 relation");
    assert_eq!(trade_result.public_values.len(), PUBLIC_VALUES_V5_LEN);
    assert_eq!(trade.binding.current, seed.binding.next);
    assert_eq!(trade.transition.previous_state, seed.transition.next_state);
    assert_eq!(trade.transition.base.fills.len(), 2);
    let taker = identity(12).1;
    let taker_before = seed
        .transition
        .base
        .next_positions
        .iter()
        .find(|position| position.trader == taker)
        .unwrap()
        .position;
    let taker_after = trade
        .transition
        .base
        .next_positions
        .iter()
        .find(|position| position.trader == taker)
        .unwrap()
        .position;
    assert!(creates_directional_risk(taker_before, taker_after));
    assert!(
        trade.transition.next_state.bond.insurance_reserve
            > seed.transition.next_state.bond.insurance_reserve
    );
    let mut tampered_trade = trade.clone();
    tampered_trade.transition.matcher_execution_receipts[0]
        .body
        .quantity = Quantity::new(
        tampered_trade.transition.matcher_execution_receipts[0]
            .body
            .quantity
            .get()
            + 1,
    )
    .unwrap();
    refresh_v2_availability(
        &mut tampered_trade,
        availability_custodians,
        availability_public,
    );
    assert!(
        execute_proof_v2_with_consensus_verifier(&tampered_trade, &TestDigestVerifier).is_err()
    );

    // The outer proof relation is exercised once per state step. These eight
    // source-local transitions advance the authenticated parent MTP by one
    // hour each and consume the exact singleton emitted by the preceding
    // transition. `TestDigestVerifier` authenticates only deterministic test
    // digests at the three recursive seams; it is explicitly not a
    // cryptographic proof verifier.
    let mut threaded = trade;
    let initial_parent_mtp = threaded.binding.prior_parent_mtp;
    let initial_parent_height = threaded.binding.prior_parent_height;
    let mut funding_settlements = 0u32;
    for hour in 1..=8u64 {
        let parent_mtp = initial_parent_mtp + hour * FUNDING_BUCKET_SECONDS;
        let parent_height = initial_parent_height + hour;
        let parent_hash = tagged_hash(
            "ECX/test-v18-hourly-parent/v2",
            &[
                threaded.binding.prior_parent_block_hash.as_slice(),
                &hour.to_be_bytes(),
            ]
            .concat(),
        );
        let next = build_v2_hourly_funding_followup(
            &threaded,
            inventory_script,
            queue_script,
            insurance_script,
            destroyed_reissuance_script,
            availability_custodians,
            availability_public,
            parent_hash,
            parent_height,
            parent_mtp,
        );
        let result = execute_proof_v2_with_consensus_verifier(&next, &TestDigestVerifier)
            .expect("state-threaded non-cryptographic hourly V18 relation");
        assert_eq!(result.public_values.len(), PUBLIC_VALUES_V5_LEN);
        assert_eq!(next.binding.current, threaded.binding.next);
        assert_eq!(
            next.transition.previous_state,
            threaded.transition.next_state
        );
        if next.transition.next_state.funding.last_settled_epoch
            != threaded.transition.next_state.funding.last_settled_epoch
        {
            funding_settlements += 1;
        }
        threaded = next;
    }
    assert_eq!(funding_settlements, 1);
    // The frozen test oracle is fresh for only 30 seconds. Consequently these
    // hourly transitions cannot honestly claim a complete 3,600-second sample
    // in every bucket, and the deterministic settled rate is exactly zero.
    assert_eq!(threaded.transition.base.public.funding_rate_ppm, 0);

    let mut tampered_hour = threaded.clone();
    tampered_hour.binding.prior_parent_mtp += 1;
    assert!(execute_proof_v2_with_consensus_verifier(&tampered_hour, &TestDigestVerifier).is_err());

    let liquidated = build_v2_liquidation_followup(
        &threaded,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        availability_custodians,
        availability_public,
    );
    let liquidation_result =
        execute_proof_v2_with_consensus_verifier(&liquidated, &TestDigestVerifier)
            .expect("state-threaded non-cryptographic liquidation V18 relation");
    assert_eq!(liquidation_result.public_values.len(), PUBLIC_VALUES_V5_LEN);
    assert_eq!(liquidated.binding.current, threaded.binding.next);
    assert_eq!(
        liquidated.transition.previous_state,
        threaded.transition.next_state
    );
    assert_eq!(liquidated.transition.base.liquidations.len(), 1);
    assert!(
        liquidated.transition.next_state.bond.insurance_reserve
            > threaded.transition.next_state.bond.insurance_reserve
    );
    let mut tampered_liquidation = liquidated.clone();
    tampered_liquidation.transition.base.liquidations[0].quantity = Quantity::new(
        tampered_liquidation.transition.base.liquidations[0]
            .quantity
            .get()
            + 1,
    )
    .unwrap();
    refresh_v2_availability(
        &mut tampered_liquidation,
        availability_custodians,
        availability_public,
    );
    assert!(
        execute_proof_v2_with_consensus_verifier(&tampered_liquidation, &TestDigestVerifier)
            .is_err()
    );
    let enqueued = build_v2_redemption_enqueue_followup(
        &liquidated,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        holder_secret,
        availability_custodians,
        availability_public,
    );
    let enqueue_result = execute_proof_v2_with_consensus_verifier(&enqueued, &TestDigestVerifier)
        .expect("state-threaded non-cryptographic recovered-enqueue V18 relation");
    assert_eq!(enqueue_result.public_values.len(), PUBLIC_VALUES_V5_LEN);
    assert_eq!(enqueued.binding.current, liquidated.binding.next);
    assert_eq!(
        enqueued.transition.previous_state,
        liquidated.transition.next_state
    );
    assert_eq!(enqueued.transition.next_redemption_queue.len(), 1);
    assert_eq!(
        enqueued.transition.next_redemption_queue[0].remaining_share_atoms,
        100
    );
    assert_eq!(enqueued.bond_inbox_source_evidence.len(), 1);
    #[cfg(any())]
    assert_incremental_bond_action_phase(&enqueued);
    let queued_entry = enqueued.transition.next_redemption_queue[0];
    let planned_at_maturity = plan_fifo_redemption(
        enqueued.transition.next_state.bond,
        queued_entry,
        queued_entry.unlock_parent_height,
    )
    .unwrap()
    .unwrap();
    assert_eq!(planned_at_maturity.redeemed_share_atoms, 2);
    assert_eq!(planned_at_maturity.paid_usdd_atoms, 14);
    assert_eq!(planned_at_maturity.remaining_entry_share_atoms, 98);
    let mut tampered_enqueue = enqueued.clone();
    tampered_enqueue.bond_inbox_source_evidence[0].entries[0].canonical_encrypted_bundle[0] ^= 1;
    assert!(
        execute_proof_v2_with_consensus_verifier(&tampered_enqueue, &TestDigestVerifier).is_err()
    );

    // The queue head is still locked at +1007. The next outer transition
    // lands exactly on the +1008 parent-block boundary and realizes the
    // deterministic partial plan through one exact unified settlement.
    assert!(plan_fifo_redemption(
        enqueued.transition.next_state.bond,
        queued_entry,
        queued_entry.unlock_parent_height - 1,
    )
    .is_err());
    let early_execution = build_v2_redemption_execution_followup(
        &enqueued,
        &enqueued.transition_settlement,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        queued_entry.unlock_parent_height - 1,
        availability_custodians,
        availability_public,
    );
    assert!(
        execute_proof_v2_with_consensus_verifier(&early_execution, &TestDigestVerifier).is_err()
    );
    let executed = build_v2_redemption_execution_followup(
        &enqueued,
        &enqueued.transition_settlement,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        queued_entry.unlock_parent_height,
        availability_custodians,
        availability_public,
    );
    let execution_result = execute_proof_v2_with_consensus_verifier(&executed, &TestDigestVerifier)
        .expect("state-threaded non-cryptographic partial-redemption V18 relation");
    assert_eq!(execution_result.public_values.len(), PUBLIC_VALUES_V5_LEN);
    assert_eq!(executed.binding.current, enqueued.binding.next);
    assert_eq!(
        executed.binding.prior_parent_height,
        queued_entry.unlock_parent_height
    );
    assert_eq!(executed.transition.redemption_executions.len(), 1);
    #[cfg(any())]
    assert_incremental_bond_action_phase(&executed);
    assert_eq!(
        executed.transition.next_redemption_queue[0].remaining_share_atoms,
        98
    );
    let mut tampered_execution = executed.clone();
    tampered_execution.transition.redemption_executions[0].paid_usdd_atoms += 1;
    refresh_v2_availability(
        &mut tampered_execution,
        availability_custodians,
        availability_public,
    );
    assert!(
        execute_proof_v2_with_consensus_verifier(&tampered_execution, &TestDigestVerifier).is_err()
    );

    let cancelled = build_v2_redemption_cancellation_followup(
        &executed,
        &executed.transition_settlement,
        inventory_script,
        queue_script,
        insurance_script,
        destroyed_reissuance_script,
        holder_secret,
        availability_custodians,
        availability_public,
    );
    let cancellation_result =
        execute_proof_v2_with_consensus_verifier(&cancelled, &TestDigestVerifier)
            .expect("state-threaded non-cryptographic signed-cancellation V18 relation");
    assert_eq!(
        cancellation_result.public_values.len(),
        PUBLIC_VALUES_V5_LEN
    );
    assert_eq!(cancelled.binding.current, executed.binding.next);
    assert_eq!(cancelled.transition.redemption_cancellations.len(), 1);
    #[cfg(any())]
    assert_incremental_bond_action_phase(&cancelled);
    assert!(cancelled.transition.next_redemption_queue.is_empty());
    assert_eq!(
        cancelled
            .transition
            .next_state
            .bond
            .queued_redemption_share_atoms,
        0
    );
    assert_eq!(cancelled.bond_inbox_source_evidence.len(), 1);
    let mut tampered_cancellation = cancelled.clone();
    tampered_cancellation.transition.redemption_cancellations[0]
        .signature
        .0[0] ^= 1;
    refresh_v2_availability(
        &mut tampered_cancellation,
        availability_custodians,
        availability_public,
    );
    assert!(
        execute_proof_v2_with_consensus_verifier(&tampered_cancellation, &TestDigestVerifier)
            .is_err()
    );
}

fn refresh_v2_availability(
    input: &mut ProofInputV2,
    custodians: &[CustodianSecrets],
    public: &[ecx_witness_availability::CustodianPublic],
) {
    let recovery_payload = canonical_availability_recovery_payload_v2(input).unwrap();
    let context = transition_availability_context_v2(&input.transition);
    let (bundle, encryption_witness) =
        create_bundle_with_encryption_witness(context, &recovery_payload, public).unwrap();
    let root = bundle.root().unwrap();
    let base = &mut input.transition.base;
    let operation_batch_hash = transition_batch_hash(
        &base.deposits,
        &base.withdrawals,
        &base.placements,
        &base.cancellations,
        &base.fills,
        &base.liquidations,
    );
    let final_batch_hash = transition_envelope_hash(&TransitionEnvelopeV4 {
        operation_batch_hash,
        deposit_event_batch_root: base.public.deposit_event_batch_root,
        oracle_certificate_hash: base.public.oracle_certificate_hash,
        oracle_mode: base.public.oracle_mode,
        matcher_receipt_batch_root: base.public.matcher_receipt_batch_root,
        collateral_settlement_root: base.public.collateral_settlement_root,
        forced_action_batch_root: base.public.forced_action_batch_root,
        escape_only: base.public.escape_only,
        encrypted_availability_root: root,
    });
    base.next_state.roots = StateRoots::from_private_state(
        &base.next_accounts,
        &base.next_positions,
        &base.next_open_orders,
        &base.previous_deposit_nullifiers,
        &base.previous_withdrawal_nullifiers,
        next_order_receipts_root(base.previous_state.roots.order_receipts, final_batch_hash),
    )
    .unwrap();
    base.public.batch_hash = final_batch_hash;
    base.public.next_state_root = base.next_state.state_root();
    base.public.encrypted_availability_root = root;
    input.transition.next_state.base = base.next_state.clone();
    input.transition.public.next_state_root = input.transition.next_state.state_root();
    input.transition.public.base_public_digest = base.public.digest();
    input.binding.next.sequence = input.transition.next_state.sequence();
    input.binding.next.private_state_root = input.transition.next_state.state_root();
    input.binding.next.encrypted_availability_root = root;
    input.binding.next.bond_state_root =
        bond_public_state_root_v2(&input.transition.next_state.bond);
    input.binding.next.funding_state_root = input.transition.next_state.funding.root();
    input.binding.next.active_order_risk_root = input.transition.next_state.active_order_risk_root;
    input.binding.next.position_risk_root = input.transition.next_state.position_risk_root;
    assert_eq!(
        canonical_availability_recovery_payload_v2(input).unwrap(),
        recovery_payload,
        "all availability-derived V2 fields are neutralized",
    );
    input.availability_bundle = bundle.encode().unwrap();
    input.availability_custody_receipts = custodians
        .iter()
        .take(usize::from(AVAILABILITY_RECOVERY_THRESHOLD))
        .map(|custodian| custodian.custody_receipt(&bundle).unwrap())
        .collect();
    input.availability_encryption_witness = encryption_witness;
}

fn build_v2_frozen_bond_deployment(
    inventory_script: &Script,
    queue_script: &Script,
    destroyed_reissuance_script: &Script,
) -> (
    FrozenBondDeploymentV2,
    FrozenBondAssetV2,
    ecx_elements_settlement::VerifiedFrozenBondDeploymentV2,
) {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    let mut issuance_input = TxIn {
        previous_output: OutPoint::new(elements::Txid::from_byte_array([0x91; 32]), 2),
        ..Default::default()
    };
    issuance_input.asset_issuance.asset_entropy = [0x92; 32];
    issuance_input.asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS);
    issuance_input.asset_issuance.inflation_keys = Value::Null;
    let bond_asset_id = issuance_input.issuance_ids().0;
    let inventory_abf = AssetBlindingFactor::from_slice(&[0x93; 32]).unwrap();
    let inventory_vbf = ValueBlindingFactor::from_slice(&[0x94; 32]).unwrap();
    let issuance_vbf = ValueBlindingFactor::last(
        &ZkpSecp256k1::new(),
        BOND_FIXED_SUPPLY_ATOMS,
        AssetBlindingFactor::zero(),
        &[TxOutSecrets::new(
            bond_asset_id,
            inventory_abf,
            BOND_FIXED_SUPPLY_ATOMS,
            inventory_vbf,
        )
        .value_blind_inputs()],
        &[],
    );
    issuance_input
        .blind_issuances_with_bfs(
            &ZkpSecp256k1::new(),
            issuance_vbf,
            ValueBlindingFactor::zero(),
            ZkpSecretKey::from_slice(&[0x98; 32]).unwrap(),
            ZkpSecretKey::from_slice(&[0x98; 32]).unwrap(),
        )
        .unwrap();
    issuance_input.asset_issuance.inflation_keys =
        Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2);
    let (bond_asset, reissuance_token_asset) = issuance_input.issuance_ids();
    let bond_asset_bytes = bond_asset.into_inner().to_byte_array();
    let reissuance_token_asset_bytes = reissuance_token_asset.into_inner().to_byte_array();
    assert_eq!(bond_asset_id, bond_asset);
    let reissuance_token_asset_id = AssetId::from_byte_array(reissuance_token_asset_bytes);
    let mut rng = StdRng::from_seed([0x95; 32]);
    let secp = ZkpSecp256k1::new();
    let inventory_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x96; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x97; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset_id,
            inventory_abf,
            BOND_FIXED_SUPPLY_ATOMS,
            inventory_vbf,
        ),
        &[TxOutSecrets::new(
            bond_asset_id,
            AssetBlindingFactor::zero(),
            BOND_FIXED_SUPPLY_ATOMS,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![issuance_input],
        output: vec![
            inventory_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(reissuance_token_asset_id),
                value: Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2),
                nonce: Nonce::Null,
                script_pubkey: destroyed_reissuance_script.clone(),
                witness: Default::default(),
            },
        ],
    };
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: bond_asset_bytes,
        inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        reissuance_token_burn_script_sha256: Sha256::digest(destroyed_reissuance_script.as_bytes())
            .into(),
    };
    let deployment = FrozenBondDeploymentV2 {
        version: BOND_DEPLOYMENT_VERSION,
        transaction: elements_encode::serialize(&transaction),
        issuance_input_index: 0,
        inventory_output_index: 0,
        inventory_asset_blinding_factor: [0x93; 32],
        inventory_value_blinding_factor: [0x94; 32],
        issuance_value_blinding_factor: {
            let mut bytes = [0; 32];
            bytes.copy_from_slice(issuance_vbf.into_inner().as_ref());
            bytes
        },
        reissuance_token_burn_output_index: 1,
    };
    let verified = verify_frozen_bond_deployment_v2(&deployment, &frozen).unwrap();
    assert_eq!(verified.fixed_supply_atoms, BOND_FIXED_SUPPLY_ATOMS);
    (deployment, frozen, verified)
}

#[allow(clippy::too_many_arguments)]
fn build_v2_subscription_settlement(
    configuration: &FrozenConfigurationV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    trader: XOnlyKey,
    account_nonce: u64,
    contribution: u64,
    trader_secret: &SecretKey,
) -> (
    TransitionSettlementV2,
    ecx_elements_settlement::VerifiedTransitionSettlementV2,
    SignedBondSubscriptionV2,
) {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    assert!(contribution > 0 && contribution < 1_000);
    let mut rng = StdRng::from_seed([0xa9; 32]);
    let secp = ZkpSecp256k1::new();
    let usdd_asset = AssetId::from_byte_array(configuration.base.usdd_asset_id);
    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let holder_script = Script::from(vec![0x51, 0x73]);
    let holder_script_sha256: Hash32 = Sha256::digest(holder_script.as_bytes()).into();

    // Stable business IDs deliberately exclude opening commitments. That
    // lets the exact roles be constructed first without a hash fixed point;
    // the final Schnorr signature still covers both opening commitments.
    let mut action = BondSubscriptionV2 {
        version: BondSubscriptionV2::VERSION,
        chain_id: configuration.base.chain_id,
        configuration_hash: configuration.digest(),
        trader,
        account_nonce,
        contribution_usdd_atoms: contribution,
        issued_share_atoms: contribution,
        bond_recipient_script_sha256: holder_script_sha256,
        usdd_output_opening_commitment: [0; 32],
        bond_output_opening_commitment: [0; 32],
    };
    let subscription_id = action.subscription_id();

    let collateral_input_abf = AssetBlindingFactor::from_slice(&[0xaa; 32]).unwrap();
    let collateral_input_vbf = ValueBlindingFactor::from_slice(&[0xab; 32]).unwrap();
    let collateral_input_secrets = TxOutSecrets::new(
        usdd_asset,
        collateral_input_abf,
        1_000,
        collateral_input_vbf,
    );
    let collateral_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        collateral_vault_script(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xac; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xad; 32]).unwrap(),
        collateral_input_secrets,
        &[TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let collateral_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![collateral_previous_output],
    };

    let inventory_input_abf = AssetBlindingFactor::from_slice(&[0xae; 32]).unwrap();
    let inventory_input_vbf = ValueBlindingFactor::from_slice(&[0xaf; 32]).unwrap();
    let inventory_input_secrets = TxOutSecrets::new(
        bond_asset,
        inventory_input_abf,
        BOND_FIXED_SUPPLY_ATOMS,
        inventory_input_vbf,
    );
    let inventory_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xb0; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xb1; 32]).unwrap(),
        inventory_input_secrets,
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            BOND_FIXED_SUPPLY_ATOMS,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let inventory_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![inventory_previous_output],
    };

    let collateral_change_abf = AssetBlindingFactor::from_slice(&[0xb2; 32]).unwrap();
    let collateral_change_vbf = ValueBlindingFactor::from_slice(&[0xb3; 32]).unwrap();
    let collateral_change = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        collateral_vault_script(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xb4; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xb5; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            collateral_change_abf,
            1_000 - contribution,
            collateral_change_vbf,
        ),
        &[collateral_input_secrets],
    )
    .unwrap();
    let subscription_usdd_abf = AssetBlindingFactor::from_slice(&[0xb6; 32]).unwrap();
    let subscription_usdd_vbf = ValueBlindingFactor::from_slice(&[0xb7; 32]).unwrap();
    let subscription_usdd_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xb8; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xb9; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            subscription_usdd_abf,
            contribution,
            subscription_usdd_vbf,
        ),
        &[collateral_input_secrets],
    )
    .unwrap();
    let inventory_change_abf = AssetBlindingFactor::from_slice(&[0xba; 32]).unwrap();
    let inventory_change_vbf = ValueBlindingFactor::from_slice(&[0xbb; 32]).unwrap();
    let inventory_change = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xbc; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xbd; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            inventory_change_abf,
            BOND_FIXED_SUPPLY_ATOMS - contribution,
            inventory_change_vbf,
        ),
        &[inventory_input_secrets],
    )
    .unwrap();
    let subscription_bond_abf = AssetBlindingFactor::from_slice(&[0xbe; 32]).unwrap();
    let subscription_bond_vbf = ValueBlindingFactor::from_slice(&[0xbf; 32]).unwrap();
    let subscription_bond_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        holder_script,
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xc0; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xc1; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            subscription_bond_abf,
            contribution,
            subscription_bond_vbf,
        ),
        &[inventory_input_secrets],
    )
    .unwrap();

    let state_asset = AssetId::from_byte_array(configuration.base.state_authority_asset_id);
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xc2; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xc3; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(collateral_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(inventory_previous_transaction.txid(), 0),
                ..Default::default()
            },
        ],
        output: vec![
            TxOut {
                asset: ConfidentialAsset::Explicit(state_asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(999),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut::new_fee(1, policy_asset),
            collateral_change,
            subscription_usdd_output,
            inventory_change,
            subscription_bond_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: cursor_marker_script(0, 0),
                witness: Default::default(),
            },
        ],
    };

    let subscription_usdd_opening = CollateralOutputOpeningV2 {
        output_index: 4,
        amount: contribution,
        asset_blinding_factor: [0xb6; 32],
        value_blinding_factor: [0xb7; 32],
        role: CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id },
    };
    let subscription_bond_opening = BondOutputOpeningV2 {
        output_index: 6,
        amount: contribution,
        asset_blinding_factor: [0xbe; 32],
        value_blinding_factor: [0xbf; 32],
        role: BondOutputRoleV2::Subscription {
            subscription_id,
            recipient_script_sha256: holder_script_sha256,
        },
    };
    action.usdd_output_opening_commitment =
        subscription_usdd_output_opening_commitment_v2(&subscription_usdd_opening, configuration)
            .unwrap();
    action.bond_output_opening_commitment =
        subscription_bond_output_opening_commitment_v2(&subscription_bond_opening, configuration)
            .unwrap();
    let signed = SignedBondSubscriptionV2::sign(action, trader_secret).unwrap();

    let settlement = TransitionSettlementV2 {
        version: TRANSITION_SETTLEMENT_V2_VERSION,
        transaction: elements_encode::serialize(&transaction),
        collateral_inputs: vec![CollateralInputOpeningV2 {
            input_index: 2,
            previous_transaction: elements_encode::serialize(&collateral_previous_transaction),
            previous_vout: 0,
            amount: 1_000,
            asset_blinding_factor: [0xaa; 32],
            value_blinding_factor: [0xab; 32],
            role: CollateralInputRoleV2::CollateralVault,
        }],
        collateral_outputs: vec![
            CollateralOutputOpeningV2 {
                output_index: 3,
                amount: 1_000 - contribution,
                asset_blinding_factor: [0xb2; 32],
                value_blinding_factor: [0xb3; 32],
                role: CollateralOutputRoleV2::CollateralVaultChange,
            },
            subscription_usdd_opening,
        ],
        bond_inputs: vec![BondInputOpeningV2 {
            input_index: 3,
            previous_transaction: elements_encode::serialize(&inventory_previous_transaction),
            previous_vout: 0,
            amount: BOND_FIXED_SUPPLY_ATOMS,
            asset_blinding_factor: [0xae; 32],
            value_blinding_factor: [0xaf; 32],
            role: BondInputRoleV2::InventoryVault,
        }],
        bond_outputs: vec![
            BondOutputOpeningV2 {
                output_index: 5,
                amount: BOND_FIXED_SUPPLY_ATOMS - contribution,
                asset_blinding_factor: [0xba; 32],
                value_blinding_factor: [0xbb; 32],
                role: BondOutputRoleV2::InventoryVaultChange,
            },
            subscription_bond_opening,
        ],
    };
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: configuration.bond_asset_id,
        inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        reissuance_token_burn_script_sha256: Sha256::digest(destroyed_reissuance_script.as_bytes())
            .into(),
    };
    let verified = verify_transition_settlement_v2(
        &settlement,
        &[],
        &[BondSettlementActionV2::Subscription {
            subscription_id,
            usdd_contribution_amount: contribution,
            bond_share_amount: contribution,
            recipient_script_sha256: holder_script_sha256,
        }],
        configuration.base.usdd_asset_id,
        configuration.base.collateral_vault_script_sha256,
        configuration.insurance_reserve_script_sha256,
        &frozen,
    )
    .unwrap();
    (settlement, verified, signed)
}

fn build_v2_noop_settlement(
    configuration: &FrozenConfigurationV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    insurance_reserve: u64,
    inventory_share_atoms: u64,
) -> (
    TransitionSettlementV2,
    ecx_elements_settlement::VerifiedTransitionSettlementV2,
) {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    let mut rng = StdRng::from_seed([0xd9; 32]);
    let secp = ZkpSecp256k1::new();
    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let usdd_asset = AssetId::from_byte_array(configuration.base.usdd_asset_id);
    let inventory_abf = AssetBlindingFactor::from_slice(&[0xda; 32]).unwrap();
    let inventory_vbf = ValueBlindingFactor::from_slice(&[0xdb; 32]).unwrap();
    let inventory_secrets = TxOutSecrets::new(
        bond_asset,
        inventory_abf,
        inventory_share_atoms,
        inventory_vbf,
    );
    let inventory_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xdc; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xdd; 32]).unwrap(),
        inventory_secrets,
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            inventory_share_atoms,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![inventory_previous_output],
    };
    let inventory_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xe0; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xe1; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0xe2; 32]).unwrap(),
            inventory_share_atoms,
            ValueBlindingFactor::from_slice(&[0xe3; 32]).unwrap(),
        ),
        &[inventory_secrets],
    )
    .unwrap();
    assert!(insurance_reserve > 0);
    let insurance_input_secrets = TxOutSecrets::new(
        usdd_asset,
        AssetBlindingFactor::from_slice(&[0x11; 32]).unwrap(),
        insurance_reserve,
        ValueBlindingFactor::from_slice(&[0x12; 32]).unwrap(),
    );
    let insurance_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x13; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x14; 32]).unwrap(),
        insurance_input_secrets,
        &[TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::zero(),
            insurance_reserve,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let insurance_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![insurance_previous_output],
    };
    let insurance_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x15; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x16; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::from_slice(&[0x17; 32]).unwrap(),
            insurance_reserve,
            ValueBlindingFactor::from_slice(&[0x18; 32]).unwrap(),
        ),
        &[insurance_input_secrets],
    )
    .unwrap();
    let state_asset = AssetId::from_byte_array(configuration.base.state_authority_asset_id);
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xde; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xdf; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(insurance_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(previous_transaction.txid(), 0),
                ..Default::default()
            },
        ],
        output: vec![
            TxOut {
                asset: ConfidentialAsset::Explicit(state_asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(999),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut::new_fee(1, policy_asset),
            insurance_output,
            inventory_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: cursor_marker_script(0, 0),
                witness: Default::default(),
            },
        ],
    };
    let settlement = TransitionSettlementV2 {
        version: TRANSITION_SETTLEMENT_V2_VERSION,
        transaction: elements_encode::serialize(&transaction),
        collateral_inputs: vec![CollateralInputOpeningV2 {
            input_index: 2,
            previous_transaction: elements_encode::serialize(&insurance_previous_transaction),
            previous_vout: 0,
            amount: insurance_reserve,
            asset_blinding_factor: [0x11; 32],
            value_blinding_factor: [0x12; 32],
            role: CollateralInputRoleV2::InsuranceReserve,
        }],
        collateral_outputs: vec![CollateralOutputOpeningV2 {
            output_index: 3,
            amount: insurance_reserve,
            asset_blinding_factor: [0x17; 32],
            value_blinding_factor: [0x18; 32],
            role: CollateralOutputRoleV2::InsuranceReserveChange,
        }],
        bond_inputs: vec![BondInputOpeningV2 {
            input_index: 3,
            previous_transaction: elements_encode::serialize(&previous_transaction),
            previous_vout: 0,
            amount: inventory_share_atoms,
            asset_blinding_factor: [0xda; 32],
            value_blinding_factor: [0xdb; 32],
            role: BondInputRoleV2::InventoryVault,
        }],
        bond_outputs: vec![BondOutputOpeningV2 {
            output_index: 4,
            amount: inventory_share_atoms,
            asset_blinding_factor: [0xe2; 32],
            value_blinding_factor: [0xe3; 32],
            role: BondOutputRoleV2::InventoryVaultChange,
        }],
    };
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: configuration.bond_asset_id,
        inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        reissuance_token_burn_script_sha256: Sha256::digest(destroyed_reissuance_script.as_bytes())
            .into(),
    };
    let verified = verify_transition_settlement_v2(
        &settlement,
        &[],
        &[],
        configuration.base.usdd_asset_id,
        configuration.base.collateral_vault_script_sha256,
        configuration.insurance_reserve_script_sha256,
        &frozen,
    )
    .unwrap();
    (settlement, verified)
}

#[allow(clippy::too_many_arguments)]
fn build_v2_enqueue_settlement(
    configuration: &FrozenConfigurationV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    inbox: &V2EnqueueInboxFixture,
    entry: ecx_protocol_core::RedemptionQueueEntryV2,
    insurance_reserve: u64,
    inventory_share_atoms: u64,
) -> (
    TransitionSettlementV2,
    ecx_elements_settlement::VerifiedTransitionSettlementV2,
) {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    let mut rng = StdRng::from_seed([0xc4; 32]);
    let secp = ZkpSecp256k1::new();
    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let usdd_asset = AssetId::from_byte_array(configuration.base.usdd_asset_id);
    let reserve_secrets = TxOutSecrets::new(
        usdd_asset,
        AssetBlindingFactor::from_slice(&[0xc5; 32]).unwrap(),
        insurance_reserve,
        ValueBlindingFactor::from_slice(&[0xc6; 32]).unwrap(),
    );
    let reserve_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xc7; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xc8; 32]).unwrap(),
        reserve_secrets,
        &[TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::zero(),
            insurance_reserve,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let reserve_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![reserve_previous_output],
    };
    let inventory_secrets = TxOutSecrets::new(
        bond_asset,
        AssetBlindingFactor::from_slice(&[0xc9; 32]).unwrap(),
        inventory_share_atoms,
        ValueBlindingFactor::from_slice(&[0xca; 32]).unwrap(),
    );
    let inventory_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xcb; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xcc; 32]).unwrap(),
        inventory_secrets,
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            inventory_share_atoms,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let inventory_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![inventory_previous_output],
    };
    let staging_secrets = TxOutSecrets::new(
        bond_asset,
        AssetBlindingFactor::from_slice(&inbox.staging_asset_blinding_factor).unwrap(),
        inbox.signed.action.requested_share_atoms,
        ValueBlindingFactor::from_slice(&inbox.staging_value_blinding_factor).unwrap(),
    );
    let queue_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        queue_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xcd; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xce; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0xbb; 32]).unwrap(),
            entry.remaining_share_atoms,
            ValueBlindingFactor::from_slice(&[0xbc; 32]).unwrap(),
        ),
        &[staging_secrets],
    )
    .unwrap();
    let reserve_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xcf; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xd0; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::from_slice(&[0xd1; 32]).unwrap(),
            insurance_reserve,
            ValueBlindingFactor::from_slice(&[0xd2; 32]).unwrap(),
        ),
        &[reserve_secrets],
    )
    .unwrap();
    let inventory_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xd3; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xd4; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0xd5; 32]).unwrap(),
            inventory_share_atoms,
            ValueBlindingFactor::from_slice(&[0xd6; 32]).unwrap(),
        ),
        &[inventory_secrets],
    )
    .unwrap();
    let source_tx: Transaction =
        elements_encode::deserialize(&inbox.recovered.source_transaction).unwrap();
    let state_asset = AssetId::from_byte_array(configuration.base.state_authority_asset_id);
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xd7; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xd8; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(source_tx.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(reserve_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(inventory_previous_transaction.txid(), 0),
                ..Default::default()
            },
        ],
        output: vec![
            TxOut {
                asset: ConfidentialAsset::Explicit(state_asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(999),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut::new_fee(1, policy_asset),
            queue_output,
            reserve_output,
            inventory_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: cursor_marker_script(0, 0),
                witness: Default::default(),
            },
        ],
    };
    let claimant = inbox.signed.action.claimant_commitment();
    let input_opening = BondInputOpeningV2 {
        input_index: 2,
        previous_transaction: inbox.recovered.source_transaction.clone(),
        previous_vout: 0,
        amount: entry.remaining_share_atoms,
        asset_blinding_factor: inbox.staging_asset_blinding_factor,
        value_blinding_factor: inbox.staging_value_blinding_factor,
        role: BondInputRoleV2::StagedRedemptionEnqueue {
            redemption_id: entry.request_id,
            staging_intent_id: inbox.signed.action.stable_intent_id(),
            claimant,
            staging_script_sha256: inbox.staging_script_sha256,
            source_txid: source_tx.txid().to_byte_array(),
            source_vout: 0,
        },
    };
    let output_opening = BondOutputOpeningV2 {
        output_index: 3,
        amount: entry.remaining_share_atoms,
        asset_blinding_factor: [0xbb; 32],
        value_blinding_factor: [0xbc; 32],
        role: BondOutputRoleV2::QueuedRedemptionEntry {
            redemption_id: entry.request_id,
            staging_intent_id: inbox.signed.action.stable_intent_id(),
            claimant,
            destination_script_sha256: inbox.destination_script_sha256,
        },
    };
    assert_eq!(
        redemption_enqueue_bond_input_opening_commitment_v2(&input_opening, configuration).unwrap(),
        inbox.signed.action.bond_input_opening_commitment
    );
    assert_eq!(
        redemption_enqueue_queue_output_opening_commitment_v2(&output_opening, configuration)
            .unwrap(),
        inbox.signed.action.queue_output_opening_commitment
    );
    let settlement = TransitionSettlementV2 {
        version: TRANSITION_SETTLEMENT_V2_VERSION,
        transaction: elements_encode::serialize(&transaction),
        collateral_inputs: vec![CollateralInputOpeningV2 {
            input_index: 3,
            previous_transaction: elements_encode::serialize(&reserve_previous_transaction),
            previous_vout: 0,
            amount: insurance_reserve,
            asset_blinding_factor: [0xc5; 32],
            value_blinding_factor: [0xc6; 32],
            role: CollateralInputRoleV2::InsuranceReserve,
        }],
        collateral_outputs: vec![CollateralOutputOpeningV2 {
            output_index: 4,
            amount: insurance_reserve,
            asset_blinding_factor: [0xd1; 32],
            value_blinding_factor: [0xd2; 32],
            role: CollateralOutputRoleV2::InsuranceReserveChange,
        }],
        bond_inputs: vec![
            input_opening,
            BondInputOpeningV2 {
                input_index: 4,
                previous_transaction: elements_encode::serialize(&inventory_previous_transaction),
                previous_vout: 0,
                amount: inventory_share_atoms,
                asset_blinding_factor: [0xc9; 32],
                value_blinding_factor: [0xca; 32],
                role: BondInputRoleV2::InventoryVault,
            },
        ],
        bond_outputs: vec![
            output_opening,
            BondOutputOpeningV2 {
                output_index: 5,
                amount: inventory_share_atoms,
                asset_blinding_factor: [0xd5; 32],
                value_blinding_factor: [0xd6; 32],
                role: BondOutputRoleV2::InventoryVaultChange,
            },
        ],
    };
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: configuration.bond_asset_id,
        inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        reissuance_token_burn_script_sha256: Sha256::digest(destroyed_reissuance_script.as_bytes())
            .into(),
    };
    let verified = verify_transition_settlement_v2(
        &settlement,
        &[],
        &[BondSettlementActionV2::EnqueueRedemption {
            redemption_id: entry.request_id,
            staging_intent_id: inbox.signed.action.stable_intent_id(),
            claimant,
            bond_share_amount: entry.remaining_share_atoms,
            staging_script_sha256: inbox.staging_script_sha256,
            source_txid: source_tx.txid().to_byte_array(),
            source_vout: 0,
            source_authorization_commitment: inbox
                .recovered
                .entry
                .marker
                .source_authorization_commitment,
            refund_script_sha256: inbox.signed.action.refund_script_sha256,
            refund_not_before_parent_height: inbox.signed.action.refund_not_before_parent_height,
            destination_script_sha256: inbox.destination_script_sha256,
        }],
        configuration.base.usdd_asset_id,
        configuration.base.collateral_vault_script_sha256,
        configuration.insurance_reserve_script_sha256,
        &frozen,
    )
    .unwrap();
    (settlement, verified)
}

#[allow(clippy::too_many_arguments)]
fn build_v2_redemption_execution_settlement(
    configuration: &FrozenConfigurationV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    enqueue_settlement: &TransitionSettlementV2,
    state_before: BondPublicStateV2,
    entry: ecx_protocol_core::RedemptionQueueEntryV2,
    outcome: ecx_protocol_core::RedemptionOutcomeV2,
) -> (
    TransitionSettlementV2,
    ecx_elements_settlement::VerifiedTransitionSettlementV2,
    RedemptionExecutionV2,
) {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    let reserve_before = u64::try_from(state_before.insurance_reserve).unwrap();
    let reserve_after = u64::try_from(outcome.insurance_reserve_after).unwrap();
    let payment = u64::try_from(outcome.paid_usdd_atoms).unwrap();
    let mut rng = StdRng::from_seed([0xdb; 32]);
    let secp = ZkpSecp256k1::new();
    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let usdd_asset = AssetId::from_byte_array(configuration.base.usdd_asset_id);
    let reserve_secrets = TxOutSecrets::new(
        usdd_asset,
        AssetBlindingFactor::from_slice(&[0xdc; 32]).unwrap(),
        reserve_before,
        ValueBlindingFactor::from_slice(&[0xdd; 32]).unwrap(),
    );
    let reserve_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xde; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xdf; 32]).unwrap(),
        reserve_secrets,
        &[TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::zero(),
            reserve_before,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let reserve_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![reserve_previous_output],
    };
    let inventory_before = state_before.inventory_share_atoms;
    let inventory_secrets = TxOutSecrets::new(
        bond_asset,
        AssetBlindingFactor::from_slice(&[0xe0; 32]).unwrap(),
        inventory_before,
        ValueBlindingFactor::from_slice(&[0xe1; 32]).unwrap(),
    );
    let inventory_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xe2; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xe3; 32]).unwrap(),
        inventory_secrets,
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            inventory_before,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let inventory_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![inventory_previous_output],
    };
    let queue_input_secrets = TxOutSecrets::new(
        bond_asset,
        AssetBlindingFactor::from_slice(&[0xbb; 32]).unwrap(),
        entry.remaining_share_atoms,
        ValueBlindingFactor::from_slice(&[0xbc; 32]).unwrap(),
    );
    let destination_script = Script::from(vec![0x51, 0x74]);
    let destination_script_sha256: Hash32 = Sha256::digest(destination_script.as_bytes()).into();
    assert_eq!(destination_script_sha256, entry.destination_script_hash);
    let payment_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        destination_script,
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xe4; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xe5; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::from_slice(&[0xe6; 32]).unwrap(),
            payment,
            ValueBlindingFactor::from_slice(&[0xe7; 32]).unwrap(),
        ),
        &[reserve_secrets],
    )
    .unwrap();
    let reserve_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xe8; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xe9; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::from_slice(&[0xea; 32]).unwrap(),
            reserve_after,
            ValueBlindingFactor::from_slice(&[0xeb; 32]).unwrap(),
        ),
        &[reserve_secrets],
    )
    .unwrap();
    let inventory_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xec; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xed; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0xee; 32]).unwrap(),
            inventory_before,
            ValueBlindingFactor::from_slice(&[0xef; 32]).unwrap(),
        ),
        &[inventory_secrets, queue_input_secrets],
    )
    .unwrap();
    let inventory_return_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xf0; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xf1; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0xf2; 32]).unwrap(),
            outcome.redeemed_share_atoms,
            ValueBlindingFactor::from_slice(&[0xf3; 32]).unwrap(),
        ),
        &[inventory_secrets, queue_input_secrets],
    )
    .unwrap();
    let remainder_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        queue_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0xf4; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0xf5; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0xf6; 32]).unwrap(),
            outcome.remaining_entry_share_atoms,
            ValueBlindingFactor::from_slice(&[0xf7; 32]).unwrap(),
        ),
        &[inventory_secrets, queue_input_secrets],
    )
    .unwrap();
    let enqueue_transaction: Transaction =
        elements_encode::deserialize(&enqueue_settlement.transaction).unwrap();
    let state_asset = AssetId::from_byte_array(configuration.base.state_authority_asset_id);
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xf8; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0xf9; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(reserve_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(inventory_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(enqueue_transaction.txid(), 3),
                ..Default::default()
            },
        ],
        output: vec![
            TxOut {
                asset: ConfidentialAsset::Explicit(state_asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(999),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut::new_fee(1, policy_asset),
            payment_output,
            reserve_output,
            inventory_output,
            inventory_return_output,
            remainder_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: cursor_marker_script(0, 0),
                witness: Default::default(),
            },
        ],
    };
    let queue_input_opening = BondInputOpeningV2 {
        input_index: 4,
        previous_transaction: enqueue_settlement.transaction.clone(),
        previous_vout: 3,
        amount: entry.remaining_share_atoms,
        asset_blinding_factor: [0xbb; 32],
        value_blinding_factor: [0xbc; 32],
        role: BondInputRoleV2::QueuedRedemption {
            redemption_id: entry.request_id,
        },
    };
    let payment_opening = CollateralOutputOpeningV2 {
        output_index: 3,
        amount: payment,
        asset_blinding_factor: [0xe6; 32],
        value_blinding_factor: [0xe7; 32],
        role: CollateralOutputRoleV2::BondRedemptionPayment {
            redemption_id: entry.request_id,
            recipient_script_sha256: entry.destination_script_hash,
        },
    };
    let inventory_return_opening = BondOutputOpeningV2 {
        output_index: 6,
        amount: outcome.redeemed_share_atoms,
        asset_blinding_factor: [0xf2; 32],
        value_blinding_factor: [0xf3; 32],
        role: BondOutputRoleV2::RedemptionInventoryReturn {
            redemption_id: entry.request_id,
        },
    };
    let remainder_opening = BondOutputOpeningV2 {
        output_index: 7,
        amount: outcome.remaining_entry_share_atoms,
        asset_blinding_factor: [0xf6; 32],
        value_blinding_factor: [0xf7; 32],
        role: BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder {
            redemption_id: entry.request_id,
            claimant: entry.claimant_commitment,
            destination_script_sha256: entry.destination_script_hash,
        },
    };
    let execution = RedemptionExecutionV2 {
        version: RedemptionExecutionV2::VERSION,
        sequence: entry.sequence,
        request_id: entry.request_id,
        redeemed_share_atoms: outcome.redeemed_share_atoms,
        paid_usdd_atoms: outcome.paid_usdd_atoms,
        queue_input_opening_commitment: redemption_execute_queue_input_opening_commitment_v2(
            &queue_input_opening,
            configuration,
        )
        .unwrap(),
        usdd_output_opening_commitment: redemption_execute_usdd_output_opening_commitment_v2(
            &payment_opening,
            configuration,
        )
        .unwrap(),
        inventory_output_opening_commitment:
            redemption_execute_inventory_output_opening_commitment_v2(
                &inventory_return_opening,
                configuration,
            )
            .unwrap(),
        queue_remainder_output_opening_commitment:
            redemption_execute_queue_remainder_output_opening_commitment_v2(
                &remainder_opening,
                configuration,
            )
            .unwrap(),
    };
    execution.validate().unwrap();
    let settlement = TransitionSettlementV2 {
        version: TRANSITION_SETTLEMENT_V2_VERSION,
        transaction: elements_encode::serialize(&transaction),
        collateral_inputs: vec![CollateralInputOpeningV2 {
            input_index: 2,
            previous_transaction: elements_encode::serialize(&reserve_previous_transaction),
            previous_vout: 0,
            amount: reserve_before,
            asset_blinding_factor: [0xdc; 32],
            value_blinding_factor: [0xdd; 32],
            role: CollateralInputRoleV2::InsuranceReserve,
        }],
        collateral_outputs: vec![
            payment_opening,
            CollateralOutputOpeningV2 {
                output_index: 4,
                amount: reserve_after,
                asset_blinding_factor: [0xea; 32],
                value_blinding_factor: [0xeb; 32],
                role: CollateralOutputRoleV2::InsuranceReserveChange,
            },
        ],
        bond_inputs: vec![
            BondInputOpeningV2 {
                input_index: 3,
                previous_transaction: elements_encode::serialize(&inventory_previous_transaction),
                previous_vout: 0,
                amount: inventory_before,
                asset_blinding_factor: [0xe0; 32],
                value_blinding_factor: [0xe1; 32],
                role: BondInputRoleV2::InventoryVault,
            },
            queue_input_opening,
        ],
        bond_outputs: vec![
            BondOutputOpeningV2 {
                output_index: 5,
                amount: inventory_before,
                asset_blinding_factor: [0xee; 32],
                value_blinding_factor: [0xef; 32],
                role: BondOutputRoleV2::InventoryVaultChange,
            },
            inventory_return_opening,
            remainder_opening,
        ],
    };
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: configuration.bond_asset_id,
        inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        reissuance_token_burn_script_sha256: Sha256::digest(destroyed_reissuance_script.as_bytes())
            .into(),
    };
    let verified = verify_transition_settlement_v2(
        &settlement,
        &[],
        &[BondSettlementActionV2::ExecuteRedemption {
            redemption_id: entry.request_id,
            claimant: entry.claimant_commitment,
            queued_share_amount: entry.remaining_share_atoms,
            redeemed_share_amount: outcome.redeemed_share_atoms,
            remainder_share_amount: outcome.remaining_entry_share_atoms,
            usdd_payment_amount: payment,
            destination_script_sha256: entry.destination_script_hash,
        }],
        configuration.base.usdd_asset_id,
        configuration.base.collateral_vault_script_sha256,
        configuration.insurance_reserve_script_sha256,
        &frozen,
    )
    .unwrap();
    (settlement, verified, execution)
}

#[allow(clippy::too_many_arguments)]
fn build_v2_redemption_cancellation_settlement(
    configuration: &FrozenConfigurationV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    execution_settlement: &TransitionSettlementV2,
    state_before: BondPublicStateV2,
    entry: ecx_protocol_core::RedemptionQueueEntryV2,
    holder_secret: &SecretKey,
) -> (
    TransitionSettlementV2,
    ecx_elements_settlement::VerifiedTransitionSettlementV2,
    SignedRedemptionCancellationV2,
) {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    let keypair = Keypair::from_secret_key(&Secp256k1::new(), holder_secret);
    let (claimant, _) = XOnlyPublicKey::from_keypair(&keypair);
    let claimant = XOnlyKey(claimant.serialize());
    let recipient_script = Script::from(vec![0x51, 0x73]);
    let recipient_script_sha256: Hash32 = Sha256::digest(recipient_script.as_bytes()).into();
    let mut cancellation = RedemptionCancellationV2Action {
        version: RedemptionCancellationV2Action::VERSION,
        chain_id: configuration.base.chain_id,
        configuration_hash: configuration.digest(),
        claimant,
        sequence: entry.sequence,
        request_id: entry.request_id,
        bond_recipient_script_sha256: recipient_script_sha256,
        queue_input_opening_commitment: [0; 32],
        bond_return_output_opening_commitment: [0; 32],
    };
    let cancellation_id = cancellation.cancellation_id();
    let queue_input_opening = BondInputOpeningV2 {
        input_index: 4,
        previous_transaction: execution_settlement.transaction.clone(),
        previous_vout: 7,
        amount: entry.remaining_share_atoms,
        asset_blinding_factor: [0xf6; 32],
        value_blinding_factor: [0xf7; 32],
        role: BondInputRoleV2::QueuedRedemption {
            redemption_id: entry.request_id,
        },
    };
    let return_opening = BondOutputOpeningV2 {
        output_index: 5,
        amount: entry.remaining_share_atoms,
        asset_blinding_factor: [0x21; 32],
        value_blinding_factor: [0x22; 32],
        role: BondOutputRoleV2::CancelledRedemptionReturn {
            redemption_id: entry.request_id,
            claimant: entry.claimant_commitment,
            recipient_script_sha256,
            cancellation_id,
        },
    };
    cancellation.queue_input_opening_commitment =
        redemption_cancel_queue_input_opening_commitment_v2(&queue_input_opening, configuration)
            .unwrap();
    cancellation.bond_return_output_opening_commitment =
        redemption_cancel_bond_return_opening_commitment_v2(&return_opening, configuration)
            .unwrap();
    let signed = SignedRedemptionCancellationV2::sign(cancellation, holder_secret).unwrap();
    signed.verify().unwrap();

    let reserve = u64::try_from(state_before.insurance_reserve).unwrap();
    let inventory = state_before.inventory_share_atoms;
    let mut rng = StdRng::from_seed([0x23; 32]);
    let secp = ZkpSecp256k1::new();
    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let usdd_asset = AssetId::from_byte_array(configuration.base.usdd_asset_id);
    let reserve_secrets = TxOutSecrets::new(
        usdd_asset,
        AssetBlindingFactor::from_slice(&[0x24; 32]).unwrap(),
        reserve,
        ValueBlindingFactor::from_slice(&[0x25; 32]).unwrap(),
    );
    let reserve_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x26; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x27; 32]).unwrap(),
        reserve_secrets,
        &[TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::zero(),
            reserve,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let reserve_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![reserve_previous_output],
    };
    let inventory_secrets = TxOutSecrets::new(
        bond_asset,
        AssetBlindingFactor::from_slice(&[0x28; 32]).unwrap(),
        inventory,
        ValueBlindingFactor::from_slice(&[0x29; 32]).unwrap(),
    );
    let inventory_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x2a; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x2b; 32]).unwrap(),
        inventory_secrets,
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            inventory,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let inventory_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![inventory_previous_output],
    };
    let queue_input_secrets = TxOutSecrets::new(
        bond_asset,
        AssetBlindingFactor::from_slice(&[0xf6; 32]).unwrap(),
        entry.remaining_share_atoms,
        ValueBlindingFactor::from_slice(&[0xf7; 32]).unwrap(),
    );
    let reserve_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x2c; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x2d; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::from_slice(&[0x2e; 32]).unwrap(),
            reserve,
            ValueBlindingFactor::from_slice(&[0x2f; 32]).unwrap(),
        ),
        &[reserve_secrets],
    )
    .unwrap();
    let inventory_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x30; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x31; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0x32; 32]).unwrap(),
            inventory,
            ValueBlindingFactor::from_slice(&[0x33; 32]).unwrap(),
        ),
        &[inventory_secrets, queue_input_secrets],
    )
    .unwrap();
    let return_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        recipient_script,
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x34; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x35; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0x21; 32]).unwrap(),
            entry.remaining_share_atoms,
            ValueBlindingFactor::from_slice(&[0x22; 32]).unwrap(),
        ),
        &[inventory_secrets, queue_input_secrets],
    )
    .unwrap();
    let execution_transaction: Transaction =
        elements_encode::deserialize(&execution_settlement.transaction).unwrap();
    let state_asset = AssetId::from_byte_array(configuration.base.state_authority_asset_id);
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0x36; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0x37; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(reserve_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(inventory_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(execution_transaction.txid(), 7),
                ..Default::default()
            },
        ],
        output: vec![
            TxOut {
                asset: ConfidentialAsset::Explicit(state_asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(999),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut::new_fee(1, policy_asset),
            reserve_output,
            inventory_output,
            return_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: cursor_marker_script(0, 0),
                witness: Default::default(),
            },
        ],
    };
    let settlement = TransitionSettlementV2 {
        version: TRANSITION_SETTLEMENT_V2_VERSION,
        transaction: elements_encode::serialize(&transaction),
        collateral_inputs: vec![CollateralInputOpeningV2 {
            input_index: 2,
            previous_transaction: elements_encode::serialize(&reserve_previous_transaction),
            previous_vout: 0,
            amount: reserve,
            asset_blinding_factor: [0x24; 32],
            value_blinding_factor: [0x25; 32],
            role: CollateralInputRoleV2::InsuranceReserve,
        }],
        collateral_outputs: vec![CollateralOutputOpeningV2 {
            output_index: 3,
            amount: reserve,
            asset_blinding_factor: [0x2e; 32],
            value_blinding_factor: [0x2f; 32],
            role: CollateralOutputRoleV2::InsuranceReserveChange,
        }],
        bond_inputs: vec![
            BondInputOpeningV2 {
                input_index: 3,
                previous_transaction: elements_encode::serialize(&inventory_previous_transaction),
                previous_vout: 0,
                amount: inventory,
                asset_blinding_factor: [0x28; 32],
                value_blinding_factor: [0x29; 32],
                role: BondInputRoleV2::InventoryVault,
            },
            queue_input_opening,
        ],
        bond_outputs: vec![
            BondOutputOpeningV2 {
                output_index: 4,
                amount: inventory,
                asset_blinding_factor: [0x32; 32],
                value_blinding_factor: [0x33; 32],
                role: BondOutputRoleV2::InventoryVaultChange,
            },
            return_opening,
        ],
    };
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: configuration.bond_asset_id,
        inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        reissuance_token_burn_script_sha256: Sha256::digest(destroyed_reissuance_script.as_bytes())
            .into(),
    };
    let verified = verify_transition_settlement_v2(
        &settlement,
        &[],
        &[BondSettlementActionV2::CancelRedemption {
            redemption_id: entry.request_id,
            claimant: entry.claimant_commitment,
            bond_share_amount: entry.remaining_share_atoms,
            recipient_script_sha256,
            cancellation_id,
        }],
        configuration.base.usdd_asset_id,
        configuration.base.collateral_vault_script_sha256,
        configuration.insurance_reserve_script_sha256,
        &frozen,
    )
    .unwrap();
    (settlement, verified, signed)
}

/// Exact confidential movement of base-transition fee/penalty revenue from
/// the collateral vault into the loss-bearing insurance reserve. This helper
/// never invents a proof: it constructs an Elements transaction and asks the
/// production settlement verifier to open every confidential input/output.
#[allow(clippy::too_many_arguments)]
fn build_v2_reserve_credit_settlement(
    configuration: &FrozenConfigurationV2,
    inventory_script: &Script,
    queue_script: &Script,
    insurance_script: &Script,
    destroyed_reissuance_script: &Script,
    insurance_reserve_before: u64,
    insurance_credit: u64,
    inventory_share_atoms: u64,
) -> (
    TransitionSettlementV2,
    ecx_elements_settlement::VerifiedTransitionSettlementV2,
) {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    assert!(insurance_reserve_before > 0);
    assert!(insurance_credit > 0);
    let insurance_reserve_after = insurance_reserve_before
        .checked_add(insurance_credit)
        .unwrap();
    let mut rng = StdRng::from_seed([0x29; 32]);
    let secp = ZkpSecp256k1::new();
    let bond_asset = AssetId::from_byte_array(configuration.bond_asset_id);
    let usdd_asset = AssetId::from_byte_array(configuration.base.usdd_asset_id);

    let reserve_secrets = TxOutSecrets::new(
        usdd_asset,
        AssetBlindingFactor::from_slice(&[0x2a; 32]).unwrap(),
        insurance_reserve_before,
        ValueBlindingFactor::from_slice(&[0x2b; 32]).unwrap(),
    );
    let reserve_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x2c; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x2d; 32]).unwrap(),
        reserve_secrets,
        &[TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::zero(),
            insurance_reserve_before,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let reserve_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![reserve_previous_output],
    };
    let vault_secrets = TxOutSecrets::new(
        usdd_asset,
        AssetBlindingFactor::from_slice(&[0x2e; 32]).unwrap(),
        insurance_credit,
        ValueBlindingFactor::from_slice(&[0x2f; 32]).unwrap(),
    );
    let vault_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        collateral_vault_script(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x30; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x31; 32]).unwrap(),
        vault_secrets,
        &[TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::zero(),
            insurance_credit,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let vault_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![vault_previous_output],
    };
    let reserve_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        insurance_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x32; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x33; 32]).unwrap(),
        TxOutSecrets::new(
            usdd_asset,
            AssetBlindingFactor::from_slice(&[0x34; 32]).unwrap(),
            insurance_reserve_after,
            ValueBlindingFactor::from_slice(&[0x35; 32]).unwrap(),
        ),
        &[reserve_secrets, vault_secrets],
    )
    .unwrap();

    let inventory_secrets = TxOutSecrets::new(
        bond_asset,
        AssetBlindingFactor::from_slice(&[0x36; 32]).unwrap(),
        inventory_share_atoms,
        ValueBlindingFactor::from_slice(&[0x37; 32]).unwrap(),
    );
    let inventory_previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x38; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x39; 32]).unwrap(),
        inventory_secrets,
        &[TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::zero(),
            inventory_share_atoms,
            ValueBlindingFactor::zero(),
        )],
    )
    .unwrap();
    let inventory_previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![inventory_previous_output],
    };
    let inventory_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        inventory_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[0x3a; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[0x3b; 32]).unwrap(),
        TxOutSecrets::new(
            bond_asset,
            AssetBlindingFactor::from_slice(&[0x3c; 32]).unwrap(),
            inventory_share_atoms,
            ValueBlindingFactor::from_slice(&[0x3d; 32]).unwrap(),
        ),
        &[inventory_secrets],
    )
    .unwrap();

    let state_asset = AssetId::from_byte_array(configuration.base.state_authority_asset_id);
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0x3e; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(elements::Txid::from_byte_array([0x3f; 32]), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(reserve_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(vault_previous_transaction.txid(), 0),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(inventory_previous_transaction.txid(), 0),
                ..Default::default()
            },
        ],
        output: vec![
            TxOut {
                asset: ConfidentialAsset::Explicit(state_asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(999),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut::new_fee(1, policy_asset),
            reserve_output,
            inventory_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: cursor_marker_script(0, 0),
                witness: Default::default(),
            },
        ],
    };
    let settlement = TransitionSettlementV2 {
        version: TRANSITION_SETTLEMENT_V2_VERSION,
        transaction: elements_encode::serialize(&transaction),
        collateral_inputs: vec![
            CollateralInputOpeningV2 {
                input_index: 2,
                previous_transaction: elements_encode::serialize(&reserve_previous_transaction),
                previous_vout: 0,
                amount: insurance_reserve_before,
                asset_blinding_factor: [0x2a; 32],
                value_blinding_factor: [0x2b; 32],
                role: CollateralInputRoleV2::InsuranceReserve,
            },
            CollateralInputOpeningV2 {
                input_index: 3,
                previous_transaction: elements_encode::serialize(&vault_previous_transaction),
                previous_vout: 0,
                amount: insurance_credit,
                asset_blinding_factor: [0x2e; 32],
                value_blinding_factor: [0x2f; 32],
                role: CollateralInputRoleV2::CollateralVault,
            },
        ],
        collateral_outputs: vec![CollateralOutputOpeningV2 {
            output_index: 3,
            amount: insurance_reserve_after,
            asset_blinding_factor: [0x34; 32],
            value_blinding_factor: [0x35; 32],
            role: CollateralOutputRoleV2::InsuranceReserveChange,
        }],
        bond_inputs: vec![BondInputOpeningV2 {
            input_index: 4,
            previous_transaction: elements_encode::serialize(&inventory_previous_transaction),
            previous_vout: 0,
            amount: inventory_share_atoms,
            asset_blinding_factor: [0x36; 32],
            value_blinding_factor: [0x37; 32],
            role: BondInputRoleV2::InventoryVault,
        }],
        bond_outputs: vec![BondOutputOpeningV2 {
            output_index: 4,
            amount: inventory_share_atoms,
            asset_blinding_factor: [0x3c; 32],
            value_blinding_factor: [0x3d; 32],
            role: BondOutputRoleV2::InventoryVaultChange,
        }],
    };
    let frozen = FrozenBondAssetV2 {
        version: FrozenBondAssetV2::VERSION,
        asset_id: configuration.bond_asset_id,
        inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
        redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
        reissuance_token_burn_script_sha256: Sha256::digest(destroyed_reissuance_script.as_bytes())
            .into(),
    };
    let verified = verify_transition_settlement_v2(
        &settlement,
        &[],
        &[],
        configuration.base.usdd_asset_id,
        configuration.base.collateral_vault_script_sha256,
        configuration.insurance_reserve_script_sha256,
        &frozen,
    )
    .unwrap();
    (settlement, verified)
}

fn identity(byte: u8) -> (SecretKey, XOnlyKey) {
    let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
    (secret, XOnlyKey(public.serialize()))
}

fn signed_order(
    secret: &SecretKey,
    side: Side,
    limit_price: Price,
    quantity: u64,
    nonce: u64,
    time_in_force: TimeInForce,
    client_order_id: [u8; 16],
) -> SignedLimitOrder {
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
    let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
    SignedLimitOrder::sign(
        ecx_protocol_core::LimitOrder {
            version: ecx_protocol_core::LimitOrder::VERSION,
            chain_id: CHAIN_ID,
            market: ECX_USDD_MARKET,
            trader: XOnlyKey(public.serialize()),
            side,
            time_in_force,
            flags: OrderFlags::NONE,
            limit_price,
            quantity: Quantity::new(quantity).unwrap(),
            client_order_id,
            max_fee_bps: 20,
            nonce,
            valid_from_height: 1,
            expires_at_height: 200,
        },
        secret,
    )
    .unwrap()
}

fn matcher_request(order: &SignedLimitOrder) -> SubmitOrderRequest {
    SubmitOrderRequest {
        client_order_id: hex::encode(order.order.client_order_id),
        chain_id: hex::encode(order.order.chain_id),
        trader: hex::encode(order.order.trader.0),
        market: MARKET.to_owned(),
        side: match order.order.side {
            Side::Buy => MatcherSide::Buy,
            Side::Sell => MatcherSide::Sell,
        },
        limit_price_ticks: order.order.limit_price.get(),
        quantity_lots: order.order.quantity.get(),
        time_in_force: match order.order.time_in_force {
            TimeInForce::GoodTilHeight => MatcherTimeInForce::Gtc,
            TimeInForce::ImmediateOrCancel => MatcherTimeInForce::Ioc,
            TimeInForce::FillOrKill => MatcherTimeInForce::Fok,
        },
        post_only: order.order.flags.contains(OrderFlags::POST_ONLY),
        reduce_only: order.order.flags.contains(OrderFlags::REDUCE_ONLY),
        max_fee_bps: order.order.max_fee_bps,
        nonce: order.order.nonce,
        valid_from_height: order.order.valid_from_height,
        expires_at_height: order.order.expires_at_height,
        signature: hex::encode(order.signature.0),
    }
}

fn collateral_vault_script() -> Script {
    let mut bytes = vec![0x51, 0x20];
    bytes.extend_from_slice(&[0xa1; 32]);
    Script::from(bytes)
}

fn withdrawal_destination_script() -> Script {
    let mut bytes = vec![0x51, 0x20];
    bytes.extend_from_slice(&[0xb2; 32]);
    Script::from(bytes)
}

fn cursor_marker_script(forced_cursor: u64, deposit_cursor: u64) -> Script {
    let mut payload = b"ECXC".to_vec();
    payload.push(1);
    payload.extend_from_slice(&forced_cursor.to_le_bytes());
    payload.extend_from_slice(&deposit_cursor.to_le_bytes());
    let mut bytes = vec![
        elements::opcodes::all::OP_RETURN.into_u8(),
        payload.len() as u8,
    ];
    bytes.extend_from_slice(&payload);
    Script::from(bytes)
}

fn build_transition_settlement(
    configuration: &FrozenConfigurationV1,
    withdrawals: &[SignedWithdrawalRequest],
    vault_script: &Script,
    withdrawal_script: &Script,
) -> TransitionSettlementV1 {
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};

    assert_eq!(withdrawals.len(), 1);
    let mut rng = StdRng::from_seed([0xc1; 32]);
    let secp = ZkpSecp256k1::new();
    let usdd_asset = AssetId::from_byte_array(configuration.usdd_asset_id);
    let previous_abf = AssetBlindingFactor::from_slice(&[1; 32]).unwrap();
    let previous_vbf = ValueBlindingFactor::from_slice(&[2; 32]).unwrap();
    let previous_secrets = TxOutSecrets::new(usdd_asset, previous_abf, 1_000, previous_vbf);
    let initial_domain = TxOutSecrets::new(
        usdd_asset,
        AssetBlindingFactor::zero(),
        1_000,
        ValueBlindingFactor::zero(),
    );
    let previous_receiver_secret = ZkpSecretKey::from_slice(&[8; 32]).unwrap();
    let previous_receiver = ZkpPublicKey::from_secret_key(&secp, &previous_receiver_secret);
    let previous_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        vault_script.clone(),
        previous_receiver,
        ZkpSecretKey::from_slice(&[9; 32]).unwrap(),
        previous_secrets,
        &[initial_domain],
    )
    .unwrap();
    let previous_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![previous_output],
    };

    let withdrawal_abf = AssetBlindingFactor::from_slice(&[3; 32]).unwrap();
    let withdrawal_vbf = ValueBlindingFactor::from_slice(&[4; 32]).unwrap();
    let withdrawal_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        withdrawal_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[10; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[11; 32]).unwrap(),
        TxOutSecrets::new(usdd_asset, withdrawal_abf, 100, withdrawal_vbf),
        &[previous_secrets],
    )
    .unwrap();
    let change_abf = AssetBlindingFactor::from_slice(&[5; 32]).unwrap();
    let change_vbf = ValueBlindingFactor::from_slice(&[6; 32]).unwrap();
    let change_output = TxOut::with_txout_secrets(
        &mut rng,
        &secp,
        vault_script.clone(),
        ZkpPublicKey::from_secret_key(&secp, &ZkpSecretKey::from_slice(&[12; 32]).unwrap()),
        ZkpSecretKey::from_slice(&[13; 32]).unwrap(),
        TxOutSecrets::new(usdd_asset, change_abf, 900, change_vbf),
        &[previous_secrets],
    )
    .unwrap();

    let singleton_input = TxIn {
        previous_output: OutPoint::new(elements::Txid::from_byte_array([0x91; 32]), 0),
        ..Default::default()
    };
    let sponsor_input = TxIn {
        previous_output: OutPoint::new(elements::Txid::from_byte_array([0x92; 32]), 0),
        ..Default::default()
    };
    let collateral_input = TxIn {
        previous_output: OutPoint::new(previous_transaction.txid(), 0),
        ..Default::default()
    };
    let state_asset = AssetId::from_byte_array(configuration.state_authority_asset_id);
    let policy_asset = AssetId::from_byte_array(configuration.policy_asset_id);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![singleton_input, sponsor_input, collateral_input],
        output: vec![
            TxOut {
                asset: ConfidentialAsset::Explicit(state_asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(999),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            TxOut::new_fee(1, policy_asset),
            withdrawal_output,
            change_output,
            TxOut {
                asset: ConfidentialAsset::Explicit(policy_asset),
                value: Value::Explicit(0),
                nonce: Nonce::Null,
                script_pubkey: cursor_marker_script(0, 0),
                witness: Default::default(),
            },
        ],
    };
    TransitionSettlementV1 {
        version: TRANSITION_SETTLEMENT_VERSION,
        transaction: elements_encode::serialize(&transaction),
        collateral_inputs: vec![CollateralInputOpeningV1 {
            input_index: 2,
            previous_transaction: elements_encode::serialize(&previous_transaction),
            previous_vout: 0,
            amount: 1_000,
            asset_blinding_factor: [1; 32],
            value_blinding_factor: [2; 32],
        }],
        collateral_outputs: vec![
            CollateralOutputOpeningV1 {
                output_index: 3,
                amount: 100,
                asset_blinding_factor: [3; 32],
                value_blinding_factor: [4; 32],
                role: CollateralOutputRoleV1::Withdrawal {
                    request_id: withdrawals[0].request.request_id(),
                },
            },
            CollateralOutputOpeningV1 {
                output_index: 4,
                amount: 900,
                asset_blinding_factor: [5; 32],
                value_blinding_factor: [6; 32],
                role: CollateralOutputRoleV1::VaultChange,
            },
        ],
    }
}

fn oracle_config() -> HybridOracleConfigV1 {
    let genesis_sidechain_block_hash = [20; 32];
    HybridOracleConfigV1 {
        version: HybridOracleConfigV1::VERSION,
        truthcoin_chain_id: pinned_truthcoin_chain_id(genesis_sidechain_block_hash),
        truthcoin_branch_id: [2; 32],
        btc_usd_template_hash: [3; 32],
        lmsr_math_commitment: TRUTHCOIN_LMSR_MATH_COMMITMENT,
        schedule_origin_mtp: 1_000,
        epoch_length_seconds: 100,
        minimum_source_confirmations: 6,
        maximum_anchor_age_seconds: 1_000,
        maximum_snapshot_age_seconds: 30,
        minimum_lmsr_b: 1_000,
        minimum_sample_count: 3,
        base_lmsr_weight_ppm: 0,
        maximum_lmsr_weight_ppm: 1_000_000,
        initial_anchor_band_bps: 100,
        maximum_anchor_band_bps: 2_000,
        risk_haircut_bps: 100,
        boundary_guard_ppb: 10_000,
        maximum_unanchored_deviation_bps: 5_000,
        ecx_satoshis_per_coin: 1_000,
        usdd_usd_price_units: PRICE_SCALE,
    }
}

fn truthcoin_authentication_config(
    oracle: &HybridOracleConfigV1,
) -> TruthcoinAuthenticationConfigV1 {
    let config = TruthcoinAuthenticationConfigV1 {
        version: TruthcoinAuthenticationConfigV1::VERSION,
        source_git_commit_sha1: TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
        consensus_source_manifest_sha256: TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
        source_patch_manifest_sha256: TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
        sidechain_number: TRUTHCOIN_SIDECHAIN_NUMBER,
        bitcoin_checkpoint_hash: [0x2f; 32],
        bitcoin_checkpoint_height: PARENT_HEIGHT - 100,
        bip300_checkpoint_state_hash: [0x30; 32],
        genesis_sidechain_block_hash: [20; 32],
        truthcoin_chain_id: oracle.truthcoin_chain_id,
        truthcoin_branch_id: oracle.truthcoin_branch_id,
        btc_usd_template_hash: oracle.btc_usd_template_hash,
        lmsr_math_commitment: oracle.lmsr_math_commitment,
        source_proof_program_id: [0x2d; 32],
        selection_rule_hash: [0x2e; 32],
        minimum_bitcoin_confirmations: 6,
        maximum_proof_bytes: 1_024,
    };
    config.validate().unwrap();
    config
}

fn truthcoin_source_proof(
    authentication: &TruthcoinAuthenticationConfigV1,
    oracle: &HybridOracleConfigV1,
) -> TruthcoinConsensusProofV1 {
    let anchor_decision_id_native = [0x80, 0, 1];
    let lmsr_decision_id_native = [0x81, 0, 1];
    let lmsr_market_id_native = [1, 2, 3, 4, 5, 6];
    let lmsr_liquidity_base_sats = 10_000;
    let lmsr_beta = lmsr_liquidity_base_sats as f64 / libm::log(2.0);
    let lmsr_shares = [0, 15_849];
    let lmsr_probability = upstream_binary_lmsr_probability(lmsr_shares, lmsr_beta).unwrap();

    let anchor = TruthcoinAnchorV1 {
        version: TruthcoinAnchorV1::VERSION,
        truthcoin_chain_id: oracle.truthcoin_chain_id,
        branch_id: oracle.truthcoin_branch_id,
        template_hash: oracle.btc_usd_template_hash,
        epoch: 0,
        decision_id: native_decision_id_hash(oracle.truthcoin_chain_id, anchor_decision_id_native),
        slot_id: oracle.canonical_slot_id(0).unwrap(),
        source_block_hash: [6; 32],
        source_state_root: [7; 32],
        source_height: 10,
        source_mtp: 1_095,
        source_confirmations: 6,
        observation_end_mtp: 1_100,
        finalized_at_mtp: 1_100,
        btc_usd_price: Price::new(60_000 * PRICE_SCALE).unwrap(),
    };
    let lmsr_snapshot = TruthcoinLmsrSnapshotV1 {
        version: TruthcoinLmsrSnapshotV1::VERSION,
        truthcoin_chain_id: oracle.truthcoin_chain_id,
        branch_id: oracle.truthcoin_branch_id,
        template_hash: oracle.btc_usd_template_hash,
        epoch: 1,
        decision_id: native_decision_id_hash(oracle.truthcoin_chain_id, lmsr_decision_id_native),
        market_id: native_market_id_hash(oracle.truthcoin_chain_id, lmsr_market_id_native),
        slot_id: oracle.canonical_slot_id(1).unwrap(),
        registry_root: [10; 32],
        selection_proof_root: [11; 32],
        source_block_hash: [12; 32],
        source_state_root: [13; 32],
        source_height: 20,
        source_mtp: 1_140,
        source_confirmations: 6,
        epoch_start_mtp: 1_100,
        resolves_at_mtp: 1_200,
        scalar_lower_bound: Price::new(50_000 * PRICE_SCALE).unwrap(),
        scalar_upper_bound: Price::new(70_000 * PRICE_SCALE).unwrap(),
        lmsr_b: lmsr_beta.floor() as u64,
        yes_probability_ppb: probability_to_ppb(lmsr_probability).unwrap(),
        sample_window_root: [14; 32],
        sample_count: 5,
        lmsr_state_root: native_lmsr_state_root(
            lmsr_market_id_native,
            lmsr_liquidity_base_sats,
            lmsr_beta.to_bits(),
            lmsr_shares,
        ),
        saturated: false,
    };
    let public_values = TruthcoinSourcePublicValuesV1 {
        version: TruthcoinSourcePublicValuesV1::VERSION,
        authentication_config_hash: authentication.digest(),
        source_git_commit_sha1: authentication.source_git_commit_sha1,
        consensus_source_manifest_sha256: authentication.consensus_source_manifest_sha256,
        sidechain_number: authentication.sidechain_number,
        observed_parent_block_hash: PARENT_BLOCK_HASH,
        observed_parent_height: PARENT_HEIGHT,
        observed_parent_mtp: PARENT_MTP,
        bitcoin_checkpoint_hash: authentication.bitcoin_checkpoint_hash,
        bitcoin_checkpoint_height: authentication.bitcoin_checkpoint_height,
        bitcoin_tip_hash: PARENT_BLOCK_HASH,
        bitcoin_tip_height: PARENT_HEIGHT,
        sidechain_genesis_hash: authentication.genesis_sidechain_block_hash,
        sidechain_tip_hash: [0x32; 32],
        sidechain_tip_height: 20,
        sidechain_tip_mtp: 1_140,
        source_confirmations: 6,
        canonical_chain_root: [0x33; 32],
        replay_transcript_root: [0x34; 32],
        replayed_state_root: [0x35; 32],
        selection_rule_hash: authentication.selection_rule_hash,
        anchor_decision_id_native,
        lmsr_decision_id_native,
        lmsr_market_id_native,
        lmsr_market_creation_txid: [0x36; 32],
        lmsr_market_created_height: 15,
        lmsr_market_first_eligible_height: 15,
        lmsr_liquidity_base_sats,
        lmsr_beta_f64_bits: lmsr_beta.to_bits(),
        lmsr_shares,
        lmsr_selected_outcome_index: 1,
        lmsr_probability_f64_bits: lmsr_probability.to_bits(),
        anchor,
        lmsr_snapshot,
    };
    let proof = test_truthcoin_proof(
        authentication.source_proof_program_id,
        &public_values.canonical_bytes(),
    );
    TruthcoinConsensusProofV1 {
        version: TruthcoinConsensusProofV1::VERSION,
        public_values,
        proof,
    }
}

/// Exercises the Elements spend-and-recreate source lane used by the exchange:
/// bootstrap -> authenticated Truthcoin market update -> Bitcoin-only heartbeat.
fn rolling_truthcoin_anchor(
    configuration: &FrozenConfigurationV1,
    public_values: &TruthcoinSourcePublicValuesV1,
    oracle_certificate_commitment: [u8; 32],
) -> TruthcoinAnchorStateV1 {
    let authentication = &configuration.truthcoin_authentication;
    let mut bootstrap = TruthcoinAnchorStateV1 {
        version: TruthcoinAnchorStateV1::VERSION,
        configuration_hash: configuration.truthcoin_anchor_configuration_hash(),
        sequence: 0,
        bitcoin_checkpoint_hash: authentication.bitcoin_checkpoint_hash,
        bitcoin_checkpoint_height: authentication.bitcoin_checkpoint_height,
        bitcoin_checkpoint_mtp: 1_000,
        bitcoin_checkpoint_chainwork: [0x20; 32],
        truthcoin_genesis_hash: authentication.genesis_sidechain_block_hash,
        truthcoin_tip_hash: authentication.genesis_sidechain_block_hash,
        truthcoin_tip_height: 0,
        truthcoin_tip_parent_bitcoin_hash: authentication.bitcoin_checkpoint_hash,
        canonical_path_root: [0x21; 32],
        replay_transcript_root: [0x22; 32],
        complete_state_root: [0x23; 32],
        decision_registry_root: [0x24; 32],
        market_registry_root: [0x25; 32],
        lmsr_state_root: [0x26; 32],
        sample_window_root: [0x27; 32],
        selected_anchor_commitment: [0x28; 32],
        selected_fast_market_commitment: [0x29; 32],
        oracle_certificate_commitment: [0x2a; 32],
        last_update_elements_height: SIDECHAIN_HEIGHT - 2,
        source_data_available_through_height: authentication.bitcoin_checkpoint_height,
        cumulative_update_root: [0x2b; 32],
        last_update_proof_commitment: [0; 32],
    };
    bootstrap.validate().unwrap();

    let bootstrap_authority_transaction = anchor_authority_creation(&bootstrap, configuration);

    let mut market_update = TruthcoinAnchorUpdateV1 {
        version: TruthcoinAnchorUpdateV1::VERSION,
        prior_authority_outpoint: AnchorOutpointV1 {
            txid: bootstrap_authority_transaction.txid().to_byte_array(),
            vout: 0,
        },
        successor_transaction_id: [0x71; 32],
        successor_authority_output_index: 0,
        update_public_values_hash: public_values.digest(),
    };
    let mut market_state = bootstrap.clone();
    market_state.sequence = 1;
    market_state.bitcoin_checkpoint_hash = public_values.bitcoin_tip_hash;
    market_state.bitcoin_checkpoint_height = public_values.bitcoin_tip_height;
    market_state.bitcoin_checkpoint_mtp = public_values.observed_parent_mtp;
    market_state.bitcoin_checkpoint_chainwork = [0x40; 32];
    market_state.truthcoin_tip_hash = public_values.sidechain_tip_hash;
    market_state.truthcoin_tip_height = public_values.sidechain_tip_height;
    market_state.truthcoin_tip_parent_bitcoin_hash = public_values.bitcoin_tip_hash;
    market_state.canonical_path_root = public_values.canonical_chain_root;
    market_state.replay_transcript_root = public_values.replay_transcript_root;
    market_state.complete_state_root = public_values.replayed_state_root;
    market_state.decision_registry_root = public_values.anchor.source_state_root;
    market_state.market_registry_root = public_values.lmsr_snapshot.registry_root;
    market_state.lmsr_state_root = public_values.lmsr_snapshot.lmsr_state_root;
    market_state.sample_window_root = public_values.lmsr_snapshot.sample_window_root;
    market_state.selected_anchor_commitment = public_values.anchor.digest();
    market_state.selected_fast_market_commitment = public_values.lmsr_snapshot.digest();
    market_state.oracle_certificate_commitment = oracle_certificate_commitment;
    market_state.last_update_elements_height = SIDECHAIN_HEIGHT - 1;
    market_state.source_data_available_through_height = public_values.bitcoin_tip_height;
    market_state.last_update_proof_commitment = market_update.update_public_values_hash;
    market_state.cumulative_update_root =
        ecx_protocol_core::truthcoin_anchor_history_root(&bootstrap, &market_state, &market_update);
    verify_truthcoin_anchor_successor(&bootstrap, &market_state, &market_update).unwrap();
    let market_authority_transaction = verify_anchor_elements_update(
        &bootstrap_authority_transaction,
        &bootstrap,
        &market_state,
        &mut market_update,
        0x31,
        configuration,
    );

    let mut heartbeat = TruthcoinAnchorUpdateV1 {
        version: TruthcoinAnchorUpdateV1::VERSION,
        prior_authority_outpoint: AnchorOutpointV1 {
            txid: market_update.successor_transaction_id,
            vout: 0,
        },
        successor_transaction_id: [0x72; 32],
        successor_authority_output_index: 0,
        update_public_values_hash: [0x73; 32],
    };
    bootstrap = market_state.clone();
    let mut active = bootstrap.clone();
    active.sequence += 1;
    active.bitcoin_checkpoint_hash = [0x74; 32];
    active.bitcoin_checkpoint_height += 1;
    active.bitcoin_checkpoint_mtp += 1;
    active.bitcoin_checkpoint_chainwork = [0x41; 32];
    active.canonical_path_root = [0x75; 32];
    active.last_update_elements_height = SIDECHAIN_HEIGHT;
    active.source_data_available_through_height += 1;
    active.last_update_proof_commitment = heartbeat.update_public_values_hash;
    active.cumulative_update_root =
        ecx_protocol_core::truthcoin_anchor_history_root(&bootstrap, &active, &heartbeat);
    verify_truthcoin_anchor_successor(&bootstrap, &active, &heartbeat).unwrap();
    verify_anchor_elements_update(
        &market_authority_transaction,
        &bootstrap,
        &active,
        &mut heartbeat,
        0x32,
        configuration,
    );
    active
}

fn exercise_mock_usdd_checkpoint(configuration: &FrozenConfigurationV1) {
    let authority_asset = [0x7a; 32];
    let tree_hash = [0x7b; 32];
    let prior = UsddEthereumCheckpointV1 {
        version: 1,
        configuration_hash: configuration.usdd_checkpoint.digest(),
        sequence: 0,
        light_client_digest: [0x81; 32],
        finalized_beacon_slot: 1_000,
        finalized_beacon_root: [0x82; 32],
        finalized_execution_block_hash: [0x83; 32],
        finalized_execution_state_root: [0x84; 32],
        finalized_execution_block_number: 2_000,
        finalized_execution_timestamp: PARENT_MTP - 300,
        accepted_parent_mtp: PARENT_MTP - 240,
        prior_checkpoint_commitment: [0; 32],
        update_proof_commitment: [0x85; 32],
    };
    let successor = UsddEthereumCheckpointV1 {
        sequence: 1,
        light_client_digest: [0x86; 32],
        finalized_beacon_slot: 1_032,
        finalized_beacon_root: [0x87; 32],
        finalized_execution_block_hash: [0x88; 32],
        finalized_execution_state_root: [0x89; 32],
        finalized_execution_block_number: 2_020,
        finalized_execution_timestamp: PARENT_MTP - 60,
        accepted_parent_mtp: PARENT_MTP,
        prior_checkpoint_commitment: prior.commitment(),
        update_proof_commitment: [0x8a; 32],
        ..prior
    };
    let prior_script = anchor_state_script_bytes(prior.commitment());
    let successor_script = anchor_state_script_bytes(successor.commitment());
    let sponsor_script = Script::from(vec![0x51, 0x7c]);
    let prior_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![explicit_anchor_output(
            authority_asset,
            1,
            prior_script.clone(),
        )],
    };
    let sponsor_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![explicit_anchor_output(
            configuration.policy_asset_id,
            1_000,
            sponsor_script.clone(),
        )],
    };
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(prior_transaction.txid(), 0),
                ..TxIn::default()
            },
            TxIn {
                previous_output: OutPoint::new(sponsor_transaction.txid(), 0),
                ..TxIn::default()
            },
        ],
        output: vec![
            explicit_anchor_output(authority_asset, 1, successor_script.clone()),
            explicit_anchor_output(configuration.policy_asset_id, 900, sponsor_script.clone()),
            explicit_anchor_output(configuration.policy_asset_id, 100, Script::new()),
        ],
    };
    let update = UsddCheckpointUpdateV1 {
        version: 1,
        prior_authority_outpoint: AnchorOutpointV1 {
            txid: prior_transaction.txid().to_byte_array(),
            vout: 0,
        },
        successor_transaction_id: transaction.txid().to_byte_array(),
        successor_authority_output_index: 0,
    };
    let scripts = UsddCheckpointAuthorityScriptsV1 {
        prior_state_commitment: prior.commitment(),
        prior_script_sha256: Sha256::digest(prior_script.as_bytes()).into(),
        successor_state_commitment: successor.commitment(),
        successor_script_sha256: Sha256::digest(successor_script.as_bytes()).into(),
        sponsor_change_script_sha256: Sha256::digest(sponsor_script.as_bytes()).into(),
    };
    verify_usdd_checkpoint_settlement(
        &UsddCheckpointSettlementV1 {
            version: USDD_CHECKPOINT_SETTLEMENT_VERSION,
            transaction: elements_encode::serialize(&transaction),
            prior_authority_transaction: elements_encode::serialize(&prior_transaction),
            sponsor_previous_transaction: elements_encode::serialize(&sponsor_transaction),
            sponsor_previous_vout: 0,
        },
        &prior,
        &successor,
        &update,
        &scripts,
        &configuration.usdd_checkpoint,
        authority_asset,
        1,
        tree_hash,
        configuration.policy_asset_id,
        PARENT_MTP,
    )
    .unwrap();
    assert!(successor.is_current(&configuration.usdd_checkpoint, PARENT_MTP));
}

fn anchor_state_script_bytes(commitment: Hash32) -> Script {
    let mut bytes = vec![0x51, 0x20];
    bytes.extend_from_slice(&commitment);
    Script::from(bytes)
}

fn anchor_authority_creation(
    state: &TruthcoinAnchorStateV1,
    configuration: &FrozenConfigurationV1,
) -> Transaction {
    Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![explicit_anchor_output(
            configuration.truthcoin_anchor_deployment.authority_asset_id,
            configuration.truthcoin_anchor_deployment.authority_amount,
            anchor_state_script(state),
        )],
    }
}

fn verify_anchor_elements_update(
    prior_transaction: &Transaction,
    prior: &TruthcoinAnchorStateV1,
    successor: &TruthcoinAnchorStateV1,
    update: &mut TruthcoinAnchorUpdateV1,
    sponsor_tag: u8,
    configuration: &FrozenConfigurationV1,
) -> Transaction {
    let sponsor_script = Script::from(vec![0x51, sponsor_tag]);
    let sponsor_transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![explicit_anchor_output(
            configuration.policy_asset_id,
            1_000,
            sponsor_script.clone(),
        )],
    };
    let prior_script = anchor_state_script(prior);
    let successor_script = anchor_state_script(successor);
    let transaction = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(prior_transaction.txid(), 0),
                ..TxIn::default()
            },
            TxIn {
                previous_output: OutPoint::new(sponsor_transaction.txid(), 0),
                ..TxIn::default()
            },
        ],
        output: vec![
            explicit_anchor_output(
                configuration.truthcoin_anchor_deployment.authority_asset_id,
                configuration.truthcoin_anchor_deployment.authority_amount,
                successor_script.clone(),
            ),
            explicit_anchor_output(configuration.policy_asset_id, 900, sponsor_script.clone()),
            explicit_anchor_output(configuration.policy_asset_id, 100, Script::new()),
        ],
    };
    update.successor_transaction_id = transaction.txid().to_byte_array();
    let scripts = TruthcoinAnchorAuthorityScriptsV1 {
        prior_state_commitment: prior.commitment(),
        prior_script_sha256: Sha256::digest(prior_script.as_bytes()).into(),
        successor_state_commitment: successor.commitment(),
        successor_script_sha256: Sha256::digest(successor_script.as_bytes()).into(),
        sponsor_change_script_sha256: Sha256::digest(sponsor_script.as_bytes()).into(),
    };
    let settlement = TruthcoinAnchorSettlementV1 {
        version: TRUTHCOIN_ANCHOR_SETTLEMENT_VERSION,
        transaction: elements_encode::serialize(&transaction),
        prior_authority_transaction: elements_encode::serialize(prior_transaction),
        sponsor_previous_transaction: elements_encode::serialize(&sponsor_transaction),
        sponsor_previous_vout: 0,
    };
    verify_truthcoin_anchor_settlement(
        &settlement,
        prior,
        successor,
        update,
        &scripts,
        &configuration.truthcoin_authentication,
        &configuration.truthcoin_anchor_deployment,
        configuration.policy_asset_id,
    )
    .unwrap();
    transaction
}

fn anchor_state_script(state: &TruthcoinAnchorStateV1) -> Script {
    let mut bytes = vec![0x51, 0x20];
    bytes.extend_from_slice(&state.commitment());
    Script::from(bytes)
}

fn explicit_anchor_output(asset: Hash32, amount: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: ConfidentialAsset::Explicit(AssetId::from_byte_array(asset)),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey,
        witness: Default::default(),
    }
}

fn account(trader: XOnlyKey, nonce: u64, collateral: i128, salt: u8) -> AccountLeaf {
    AccountLeaf {
        version: AccountLeaf::VERSION,
        trader,
        account_nonce: nonce,
        collateral: Amount(collateral),
        cumulative_realized_pnl: Amount(0),
        salt: [salt; 32],
    }
}

fn flat_position(trader: XOnlyKey, salt: u8) -> PositionLeaf {
    PositionLeaf {
        version: PositionLeaf::VERSION,
        trader,
        market: ECX_USDD_MARKET,
        position: Position::FLAT,
        isolated_margin: Amount(0),
        salt: [salt; 32],
    }
}

fn position(trader: XOnlyKey, size: i64, entry_price: Price, salt: u8) -> PositionLeaf {
    PositionLeaf {
        position: Position {
            size,
            entry_price: entry_price.get(),
            last_funding_index: 0,
        },
        salt: [salt; 32],
        ..flat_position(trader, salt)
    }
}

// Prototype adapter matching node-overlay/reference::ComputeStateUtxoRoot.
fn prototype_state_utxo_root(
    child_genesis: [u8; 32],
    transaction_id_consensus: [u8; 32],
    vout: u32,
    output_consensus_bytes: &[u8],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(32 + 32 + 4 + 32);
    payload.extend_from_slice(&child_genesis);
    payload.extend_from_slice(&transaction_id_consensus);
    payload.extend_from_slice(&vout.to_le_bytes());
    payload.extend_from_slice(&Sha256::digest(output_consensus_bytes));
    tagged_hash("ECX/header-state/v1", &payload)
}

fn prototype_state_output(state_hash: [u8; 32], proof_hash: [u8; 32]) -> Vec<u8> {
    let mut output = b"prototype-elements-ctxout-v1".to_vec();
    output.extend_from_slice(&state_hash);
    output.extend_from_slice(&proof_hash);
    output
}

// Prototype adapter matching node-overlay/reference::AppendHeaderStateSuffix.
fn prototype_append_header_state_suffix(
    legacy_header: &[u8],
    root: [u8; 32],
    forced_inbox_root: [u8; 32],
    deposit_inbox_root: [u8; 32],
    source_parent_height: u32,
) -> Vec<u8> {
    let mut header = legacy_header.to_vec();
    header.extend_from_slice(&root);
    header.extend_from_slice(&forced_inbox_root);
    header.extend_from_slice(&deposit_inbox_root);
    header.extend_from_slice(&source_parent_height.to_le_bytes());
    header
}

// Exact inputless four-output blinded M6 encoding emitted and semantically
// validated by the Elements side. Parent miners receive only its BIP300 hash.
fn prototype_child_blinded_m6(outputs: &[(u64, Vec<u8>); 4]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2_i32.to_le_bytes());
    bytes.push(0); // vin count
    bytes.push(4); // vout count
    for (value, script) in outputs {
        bytes.extend_from_slice(&value.to_le_bytes());
        assert!(script.len() < 0xfd);
        bytes.push(script.len() as u8);
        bytes.extend_from_slice(script);
    }
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

fn prototype_withdrawal_inputs_commitment(
    withdrawal_txid: [u8; 32],
    withdrawal_vout: u32,
    checkpoint_height: u32,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(1 + 2 * (32 + 4));
    bytes.push(2);
    bytes.extend_from_slice(&withdrawal_txid);
    bytes.extend_from_slice(&withdrawal_vout.to_le_bytes());
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&checkpoint_height.to_le_bytes());
    bitcoin_double_sha256(&bytes)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
