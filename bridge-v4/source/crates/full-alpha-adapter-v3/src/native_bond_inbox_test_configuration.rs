// Synthetic test-only configuration; no value here is a production binding.
use ecx_protocol_core::*;
use ecx_protocol_core::{oracle::{HybridOracleConfigV1, PPM_DENOMINATOR}, risk::RiskParams, availability::AvailabilityConfigV1};
use elements::secp256k1_zkp::{SecretKey, Secp256k1};
    pub(super) fn configuration() -> FrozenConfigurationV2 {
        let matcher_secret = SecretKey::from_slice(&[31; 32]).unwrap();
        let matcher_keypair =
            elements::secp256k1_zkp::Keypair::from_secret_key(&Secp256k1::new(), &matcher_secret);
        let (matcher_xonly, _) =
            elements::secp256k1_zkp::XOnlyPublicKey::from_keypair(&matcher_keypair);
        let base = FrozenConfigurationV1 {
            version: FrozenConfigurationV1::VERSION,
            chain_id: [1; 32],
            market: ecx_protocol_core::ECX_USDD_MARKET,
            ecx_asset_id: [2; 32],
            usdd_asset_id: [3; 32],
            policy_asset_id: [4; 32],
            state_authority_asset_id: [5; 32],
            usdd_checkpoint: UsddCheckpointConfigV1 {
                version: UsddCheckpointConfigV1::VERSION,
                ethereum_light_client_configuration_hash: [24; 32],
                authority_configuration_hash: [25; 32],
                maximum_checkpoint_age_seconds: USDD_MAX_CHECKPOINT_AGE_SECONDS,
            },
            risk: RiskParams::default(),
            availability: AvailabilityConfigV1 {
                version: AvailabilityConfigV1::VERSION,
                scheme_hash: ecx_protocol_core::AVAILABILITY_SCHEME_HASH_V1,
                custodian_registry_hash: [20; 32],
                recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
                custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
                maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
            },
            truthcoin_authentication: truthcoin_anchor_authentication(),
            truthcoin_anchor_deployment: TruthcoinAnchorDeploymentV1 {
                version: TruthcoinAnchorDeploymentV1::VERSION,
                authority_asset_id: [21; 32],
                authority_amount: 1,
                script_tree_configuration_hash: [22; 32],
            },
            oracle: HybridOracleConfigV1 {
                version: 1,
                truthcoin_chain_id: [6; 32],
                truthcoin_branch_id: [7; 32],
                btc_usd_template_hash: [8; 32],
                lmsr_math_commitment: [9; 32],
                schedule_origin_mtp: 1,
                epoch_length_seconds: 600,
                minimum_source_confirmations: 6,
                maximum_anchor_age_seconds: 3_600,
                maximum_snapshot_age_seconds: 120,
                minimum_lmsr_b: 1_000,
                minimum_sample_count: 3,
                base_lmsr_weight_ppm: 0,
                maximum_lmsr_weight_ppm: PPM_DENOMINATOR as u32,
                initial_anchor_band_bps: 100,
                maximum_anchor_band_bps: 2_000,
                risk_haircut_bps: 100,
                boundary_guard_ppb: 10_000,
                maximum_unanchored_deviation_bps: 5_000,
                ecx_satoshis_per_coin: 1_000,
                usdd_usd_price_units: ecx_protocol_core::PRICE_SCALE,
            },
            matcher: CentralMatcherConfigV1 {
                version: CentralMatcherConfigV1::VERSION,
                key_epoch: 0,
                signer: XOnlyKey(matcher_xonly.serialize()),
                genesis_sequence: 0,
                genesis_receipt_hash: [10; 32],
                forced_inclusion_blocks: 6,
            },
            forced_action_domain: [11; 32],
            deposit_inbox_domain: [12; 32],
            collateral_vault_script_sha256: [13; 32],
            maximum_transition_actions: MAX_TRANSITION_ACTIONS,
        };
        let internal_key = ecx_protocol_core::BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2;
        let process_cmr = [30; 32];
        let refund_cmr = [32; 32];
        let staging_template = bond_inbox_redemption_staging_descriptor_commitment_v2(
            ecx_protocol_core::BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            internal_key,
            process_cmr,
            refund_cmr,
        )
        .unwrap();
        let configuration = FrozenConfigurationV2 {
            version: FrozenConfigurationV2::VERSION,
            base,
            collateral_vault_covenant_cmr: [55; 32],
            bond_asset_id: [40; 32],
            bond_deployment_commitment: [41; 32],
            bond_inventory_script_sha256: [42; 32],
            bond_redemption_queue_script_sha256: [43; 32],
            bond_inbox_redemption_staging_template_commitment: staging_template,
            bond_inbox_redemption_staging_renderer_domain:
                ecx_protocol_core::BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            bond_inbox_redemption_staging_internal_key: internal_key,
            bond_inbox_redemption_staging_tapleaf_version:
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            bond_inbox_redemption_staging_process_cmr: process_cmr,
            bond_inbox_redemption_staging_refund_cmr: refund_cmr,
            bond_inbox_refund_minimum_parent_blocks: BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2,
            insurance_reserve_script_sha256: [44; 32],
            insurance_reserve_covenant_cmr: [54; 32],
            destroyed_reissuance_token_script_sha256: [45; 32],
            bond_inbox_domain: [46; 32],
            bond_inbox_custody_receipt_codec_hash: [47; 32],
            bond_inbox_inclusion_blocks: BOND_INBOX_INCLUSION_BLOCKS_V2,
            bond_inbox_max_bundle_bytes: MAX_BOND_INBOX_BUNDLE_BYTES_V2,
            bond_inbox_max_entries_per_sidechain_block:
                BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
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
            ecx_btc_conversion_program_id: [48; 32],
            usdd_usd_conversion_program_id: [49; 32],
            ecx_btc_redemption_covenant_commitment: [50; 32],
            ecx_btc_source_checkpoint_commitment: [51; 32],
            usdd_usd_redemption_covenant_commitment: [52; 32],
            usdd_usd_source_checkpoint_commitment: [53; 32],
            maximum_conversion_age_seconds: 3_600,
            maximum_conversion_proof_bytes: 1_024,
            recursive_proof_marker_bytes: RECURSIVE_PROOF_MARKER_BYTES_V2,
            fixed_supply_atoms: BOND_FIXED_SUPPLY_ATOMS,
            redemption_delay_parent_blocks: BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
        };
        configuration.validate().unwrap();
        configuration
    }

    fn truthcoin_anchor_authentication() -> TruthcoinAuthenticationConfigV1 {
        TruthcoinAuthenticationConfigV1 {
            version: TruthcoinAuthenticationConfigV1::VERSION,
            source_git_commit_sha1: [1; 20],
            consensus_source_manifest_sha256: [18; 32],
            source_patch_manifest_sha256: [19; 32],
            sidechain_number: 13,
            bitcoin_checkpoint_hash: [16; 32],
            bitcoin_checkpoint_height: 100,
            bip300_checkpoint_state_hash: [24; 32],
            genesis_sidechain_block_hash: [17; 32],
            truthcoin_chain_id: [6; 32],
            truthcoin_branch_id: [7; 32],
            btc_usd_template_hash: [8; 32],
            lmsr_math_commitment: [9; 32],
            source_proof_program_id: [14; 32],
            selection_rule_hash: [15; 32],
            minimum_bitcoin_confirmations: 6,
            maximum_proof_bytes: 1_024,
        }
    }
