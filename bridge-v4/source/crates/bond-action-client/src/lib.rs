//! Fail-closed signer for proof-enforced ECX v2 insurance-bond actions.
//!
//! The transition producer is a liveness component, not an authority. This
//! client independently pins the active Elements context and recomputes every
//! proof-consumed action/opening commitment before a local BIP340 signature is
//! released. It never turns an unsigned intent into a standalone transfer.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]

pub mod deployment_v2;
pub use deployment_v2::*;

use std::{fs, net::IpAddr, path::Path, str::FromStr, time::Duration};

use ecx_elements_settlement::{
    bond_inbox_redemption_staging_script_sha256_v2, elements_transaction_witness_bytes_v2,
    logical_allocation_commitment_v2, verify_bond_inbox_source_transaction_v2, BondInputOpeningV2,
    BondInputRoleV2, BondOutputOpeningV2, BondOutputRoleV2, CollateralOutputOpeningV2,
    CollateralOutputRoleV2, LogicalAllocationKindV2,
};
use ecx_matcher::{
    model::{CapitalMode, CapitalSnapshotV2, HealthView},
    ElementsConsensusContextV2, ElementsRpcClient, V2IdentityPins,
};
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    bond_inbox_availability_bundle_root_v2,
    bond_inbox_no_staging_source_authorization_commitment_v2, bond_inbox_source_witness_sha256_v2,
    bond_inbox_staging_source_authorization_commitment_v2,
    canonical_bond_inbox_custody_receipts_v2, subscription_share_atoms, tagged_hash,
    verify_bond_inbox_source_witness_commitments_v2, AvailabilityConfigV1,
    BondInboxAvailablePayloadV2, BondInboxCustodyReceiptV2, BondInboxEntryV2, BondInboxMarkerV2,
    BondInboxRedemptionStagingRendererInputV2, BondInboxUserActionV2, BondSubscriptionV2,
    FrozenConfigurationV2, Hash32, InsuranceRecapitalizationContributionV2,
    RedemptionCancellationV2Action, RedemptionEnqueueV2, Signature64, SignedBondSubscriptionV2,
    SignedInsuranceRecapitalizationContributionV2, SignedRedemptionCancellationV2,
    SignedRedemptionEnqueueV2, XOnlyKey, AVAILABILITY_CUSTODIAN_COUNT,
    AVAILABILITY_RECOVERY_THRESHOLD, BOND_FIXED_SUPPLY_ATOMS, MAX_AVAILABILITY_WITNESS_BYTES,
    MAX_BOND_INBOX_BUNDLE_BYTES_V2,
};
use ecx_witness_availability::{
    availability_scheme_hash, custodian_registry_hash, custody_receipt_codec_hash_v1,
    verify_bundle_encryption, verify_custody_receipts, AvailabilityEncryptionWitnessV1,
    CustodyReceiptV1, WitnessBundle,
};
use elements::{hashes::Hash as _, AssetId};
use rand::{rngs::OsRng, RngCore};
use reqwest::{Client, Url};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use secp256k1_zkp::{
    Generator, PedersenCommitment, RangeProof, Secp256k1 as ZkpSecp256k1, SurjectionProof,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// Incompatible V18 producer contract. Version 3 requires the complete frozen
/// configuration preimage in status before preparation/signing and removes
/// the producer-selected static staging script from the action profile.
const API_VERSION: u16 = 3;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PREPARATION_BLOCK_LIFETIME: u64 = 6;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration is missing or invalid: {0}")]
    Configuration(String),
    #[error("private key is invalid: {0}")]
    Key(String),
    #[error("authenticated node preflight failed: {0}")]
    Node(String),
    #[error("authenticated matcher preflight failed: {0}")]
    Matcher(String),
    #[error("transition producer is unavailable: {0}")]
    ProducerUnavailable(String),
    #[error("transition producer is not ready: {0}")]
    ProducerNotReady(String),
    #[error("producer preparation does not match the signed intent: {0}")]
    Preparation(String),
    #[error("active chain changed while preparing the action")]
    StaleContext,
    #[error("canonical action signing failed: {0}")]
    Signing(String),
    #[error("producer rejected the signed action: {0}")]
    Rejected(String),
    #[error("producer claimed a broadcast without independently verifiable evidence")]
    UnverifiedBroadcast,
    #[error("Elements wallet transfer failed: {0}")]
    Wallet(String),
    #[error("confidential bond transfer transaction differs from the requested payment")]
    TransferMismatch,
    #[error("confidential bond transfer was rejected by mempool policy: {0}")]
    MempoolRejected(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Configuration(_) => "bond_client_configuration",
            Self::Key(_) => "bond_signing_key",
            Self::Node(_) => "elements_context_unavailable",
            Self::Matcher(_) => "matcher_capital_unavailable",
            Self::ProducerUnavailable(_) => "transition_producer_unavailable",
            Self::ProducerNotReady(_) => "transition_producer_not_ready",
            Self::Preparation(_) => "producer_preparation_mismatch",
            Self::StaleContext => "active_context_changed",
            Self::Signing(_) => "canonical_action_signing_failed",
            Self::Rejected(_) => "transition_producer_rejected",
            Self::UnverifiedBroadcast => "unverified_broadcast_claim",
            Self::Wallet(_) => "elements_wallet_unavailable",
            Self::TransferMismatch => "bond_transfer_mismatch",
            Self::MempoolRejected(_) => "bond_transfer_mempool_rejected",
        }
    }

    pub fn stage(&self) -> &'static str {
        match self {
            Self::Configuration(_) | Self::Key(_) => "local_wallet",
            Self::Node(_) | Self::Matcher(_) => "authenticated_preflight",
            Self::ProducerUnavailable(_) | Self::ProducerNotReady(_) => "producer_preflight",
            Self::Preparation(_) | Self::StaleContext => "preparation",
            Self::Signing(_) => "signing",
            Self::Rejected(_) | Self::UnverifiedBroadcast => "submission",
            Self::Wallet(_) => "wallet",
            Self::TransferMismatch | Self::MempoolRejected(_) => "broadcast_preflight",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Node(_)
                | Self::Matcher(_)
                | Self::ProducerUnavailable(_)
                | Self::ProducerNotReady(_)
                | Self::StaleContext
                | Self::Rejected(_)
                | Self::Wallet(_)
        )
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    matcher_url: Url,
    producer_url: Url,
    elements_rpc: ElementsRpcClient,
    wallet_rpc: WalletRpc,
    expected_chain_id: Hash32,
    expected_configuration_hash: Hash32,
    expected_bond_asset_id: Hash32,
    expected_deployment_commitment: Hash32,
    expected_transition_program_id: Hash32,
    expected_simplicity_transition_cmr: Hash32,
    recipient_script_sha256: Hash32,
    holder_script_sha256: Hash32,
    usdd_destination_script_sha256: Hash32,
    http: Client,
}

impl ClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        matcher_url: &str,
        producer_url: &str,
        elements_rpc_url: &str,
        elements_rpc_user: Option<String>,
        elements_rpc_password: Option<String>,
        expected_chain_id: &str,
        expected_configuration_hash: &str,
        expected_bond_asset_id: &str,
        expected_deployment_commitment: &str,
        expected_transition_program_id: &str,
        expected_simplicity_transition_cmr: &str,
        recipient_script_sha256: &str,
        holder_script_sha256: &str,
        usdd_destination_script_sha256: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let matcher_url = endpoint(matcher_url, "matcher")?;
        let producer_url = endpoint(producer_url, "transition producer")?;
        let elements_rpc = ElementsRpcClient::new(
            elements_rpc_url,
            elements_rpc_user.clone(),
            elements_rpc_password.clone(),
        )
        .map_err(|error| Error::Configuration(error.to_string()))?;
        let wallet_rpc = WalletRpc::new(
            elements_rpc_url,
            elements_rpc_user.clone(),
            elements_rpc_password.clone(),
            timeout,
        )?;
        let expected_chain_id = hash32(expected_chain_id, "expected chain id")?;
        let expected_configuration_hash = hash32(
            expected_configuration_hash,
            "expected v2 configuration hash",
        )?;
        let expected_bond_asset_id = hash32(expected_bond_asset_id, "expected bond asset id")?;
        let expected_deployment_commitment = hash32(
            expected_deployment_commitment,
            "expected bond deployment commitment",
        )?;
        let expected_transition_program_id = hash32(
            expected_transition_program_id,
            "expected v2 transition program id",
        )?;
        let expected_simplicity_transition_cmr = hash32(
            expected_simplicity_transition_cmr,
            "expected Simplicity transition CMR",
        )?;
        let recipient_script_sha256 =
            hash32(recipient_script_sha256, "bond recipient script SHA256")?;
        let holder_script_sha256 = hash32(holder_script_sha256, "bond holder script SHA256")?;
        let usdd_destination_script_sha256 = hash32(
            usdd_destination_script_sha256,
            "USDD destination script SHA256",
        )?;
        for (name, value) in [
            ("expected chain id", expected_chain_id),
            (
                "expected v2 configuration hash",
                expected_configuration_hash,
            ),
            ("expected bond asset id", expected_bond_asset_id),
            (
                "expected bond deployment commitment",
                expected_deployment_commitment,
            ),
            (
                "expected v2 transition program id",
                expected_transition_program_id,
            ),
            (
                "expected Simplicity transition CMR",
                expected_simplicity_transition_cmr,
            ),
            ("bond recipient script SHA256", recipient_script_sha256),
            ("bond holder script SHA256", holder_script_sha256),
            (
                "USDD destination script SHA256",
                usdd_destination_script_sha256,
            ),
        ] {
            if value == [0; 32] {
                return Err(Error::Configuration(format!("{name} must be nonzero")));
            }
        }
        let elements_rpc = elements_rpc
            .with_v2_identity_pins(V2IdentityPins {
                configuration_hash: expected_configuration_hash,
                bond_asset_id: expected_bond_asset_id,
                bond_deployment_commitment: expected_deployment_commitment,
                transition_program_id: expected_transition_program_id,
                transition_cmr: expected_simplicity_transition_cmr,
            })
            .map_err(|error| Error::Configuration(error.to_string()))?;
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| Error::Configuration(error.to_string()))?;
        Ok(Self {
            matcher_url,
            producer_url,
            elements_rpc,
            wallet_rpc,
            expected_chain_id,
            expected_configuration_hash,
            expected_bond_asset_id,
            expected_deployment_commitment,
            expected_transition_program_id,
            expected_simplicity_transition_cmr,
            recipient_script_sha256,
            holder_script_sha256,
            usdd_destination_script_sha256,
            http,
        })
    }
}

#[derive(Clone)]
pub struct BondActionClient {
    config: ClientConfig,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientStatus {
    pub ready: bool,
    pub code: String,
    pub message: String,
    pub chain_id: String,
    pub sidechain_height: u64,
    pub exchange_state_root: String,
    pub capital_mode: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ActionReceipt {
    pub accepted: bool,
    /// Proof-managed actions report `broadcast` only after local raw-
    /// transaction verification, mempool policy acceptance, node broadcast,
    /// and a positive mempool lookup.
    pub disposition: String,
    pub action_id: String,
    pub producer_receipt: String,
    pub txid: String,
    pub wtxid: String,
    /// The absolute source-action deadline is assigned only when the node
    /// admits this mempool transaction to an active-chain block. A broadcast
    /// receipt must therefore leave it unset rather than guess a height.
    pub process_deadline_parent_height: Option<u64>,
    /// Frozen rule used once the source entry exists: observed parent height
    /// plus this many blocks.
    pub process_deadline_parent_blocks: u32,
    pub refund_available_parent_height: Option<u64>,
    /// A mempool broadcast does not advance the proof-consumed inbox cursor.
    pub consensus_cursor_advanced: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TransferReceipt {
    pub accepted: bool,
    pub disposition: String,
    pub txid: String,
}

#[derive(Debug, Clone)]
struct AuthenticatedPreflight {
    capital: CapitalSnapshotV2,
    context: ElementsConsensusContextV2,
}

#[derive(Debug, Clone, Copy)]
struct PreparedSigningContext<'a> {
    preflight: &'a AuthenticatedPreflight,
    profile: &'a BondActionProfileV2,
    configuration: &'a FrozenConfigurationV2,
    source: &'a BondInboxSourcePreparationV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerStatusV1 {
    pub version: u16,
    pub ready: bool,
    pub private_local: bool,
    pub chain_id: Hash32,
    pub context: ElementsConsensusContextV2,
    pub proof_backend: String,
    pub transition_program_id: Hash32,
    pub transition_cmr: Hash32,
    pub proof_inputs_ready: bool,
    pub covenant_frozen: bool,
    pub wallet_ready: bool,
    pub broadcaster_ready: bool,
    /// Full frozen configuration preimage required before any local user or
    /// marker signature is released. Producer declarations never select a
    /// script/asset identity; the client validates and hashes this value
    /// against the node-pinned configuration hash first.
    pub configuration: FrozenConfigurationV2,
    /// Exact proof-side allocation identities used by the local signer. The
    /// configuration hash and bond asset are independently pinned by the
    /// patched node; a producer can at worst make an invalid action, never
    /// relax the proof relation.
    pub action_profile: BondActionProfileV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondActionProfileV2 {
    pub version: u8,
    pub configuration_hash: Hash32,
    pub usdd_asset_id: Hash32,
    pub bond_asset_id: Hash32,
    pub insurance_reserve_script_sha256: Hash32,
    pub redemption_queue_script_sha256: Hash32,
    pub redemption_staging_template_commitment: Hash32,
    pub redemption_staging_renderer_domain: Hash32,
    pub refund_minimum_parent_blocks: u32,
    pub availability_scheme_hash: Hash32,
    pub availability_custodian_registry_hash: Hash32,
    pub custody_receipt_codec_hash: Hash32,
    pub maximum_bundle_bytes: u32,
}

impl BondActionProfileV2 {
    pub const VERSION: u8 = 2;

    fn from_configuration(configuration: &FrozenConfigurationV2) -> Self {
        Self {
            version: Self::VERSION,
            configuration_hash: configuration.digest(),
            usdd_asset_id: configuration.base.usdd_asset_id,
            bond_asset_id: configuration.bond_asset_id,
            insurance_reserve_script_sha256: configuration.insurance_reserve_script_sha256,
            redemption_queue_script_sha256: configuration.bond_redemption_queue_script_sha256,
            redemption_staging_template_commitment: configuration
                .bond_inbox_redemption_staging_template_commitment,
            redemption_staging_renderer_domain: configuration
                .bond_inbox_redemption_staging_renderer_domain,
            refund_minimum_parent_blocks: configuration.bond_inbox_refund_minimum_parent_blocks,
            availability_scheme_hash: configuration.base.availability.scheme_hash,
            availability_custodian_registry_hash: configuration
                .base
                .availability
                .custodian_registry_hash,
            custody_receipt_codec_hash: configuration.bond_inbox_custody_receipt_codec_hash,
            maximum_bundle_bytes: configuration.bond_inbox_max_bundle_bytes,
        }
    }

    fn validate_against(&self, capital: &CapitalSnapshotV2) -> Result<(), Error> {
        if self.version != Self::VERSION
            || self.configuration_hash != capital.configuration_hash
            || self.bond_asset_id != capital.bond_asset_id
            || self.usdd_asset_id == [0; 32]
            || self.insurance_reserve_script_sha256 == [0; 32]
            || self.redemption_queue_script_sha256 == [0; 32]
            || self.redemption_staging_template_commitment == [0; 32]
            || self.redemption_staging_renderer_domain == [0; 32]
            || self.refund_minimum_parent_blocks == 0
            || self.availability_scheme_hash != availability_scheme_hash()
            || self.availability_custodian_registry_hash == [0; 32]
            || self.custody_receipt_codec_hash != custody_receipt_codec_hash_v1()
            || self.maximum_bundle_bytes != MAX_BOND_INBOX_BUNDLE_BYTES_V2
        {
            return Err(Error::ProducerNotReady(
                "producer action profile is not bound to the node-pinned v2 configuration".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BondIntentV1 {
    Subscription {
        contribution_usdd_atoms: u64,
        recipient_script_sha256: Hash32,
    },
    EnqueueRedemption {
        bond_share_atoms: u64,
        destination_script_sha256: Hash32,
        holder_script_sha256: Hash32,
    },
    CancelRedemption {
        request_id: Hash32,
        recipient_script_sha256: Hash32,
    },
    /// Non-dilutive recovery capital. This deliberately issues no bond shares.
    InsuranceRecapitalization { contribution_usdd_atoms: u64 },
}

fn validate_intent_capital_mode(mode: CapitalMode, intent: &BondIntentV1) -> Result<(), Error> {
    match intent {
        BondIntentV1::EnqueueRedemption { .. } if mode != CapitalMode::Normal => {
            Err(Error::Preparation(
                "redemption enqueue requires authenticated normal capital mode".into(),
            ))
        }
        BondIntentV1::CancelRedemption { .. } if mode == CapitalMode::Recovery => {
            Err(Error::Preparation(
                "recapitalization-only mode permits subscriptions but not redemption cancellation"
                    .into(),
            ))
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequestV1 {
    pub version: u16,
    pub expected_chain_id: Hash32,
    pub observed_context: ElementsConsensusContextV2,
    pub signer: XOnlyKey,
    pub intent: BondIntentV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreparedActionV1 {
    Subscription {
        action: BondSubscriptionV2,
        usdd_output: CollateralOutputOpeningV2,
        bond_output: BondOutputOpeningV2,
    },
    EnqueueRedemption {
        action: RedemptionEnqueueV2,
        bond_input: BondInputOpeningV2,
        queue_output: BondOutputOpeningV2,
    },
    CancelRedemption {
        action: RedemptionCancellationV2Action,
        queue_input: BondInputOpeningV2,
        bond_return_output: BondOutputOpeningV2,
    },
    InsuranceRecapitalization {
        action: InsuranceRecapitalizationContributionV2,
        insurance_output: CollateralOutputOpeningV2,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondActionV1 {
    pub version: u16,
    pub preparation_id: Hash32,
    pub expected_chain_id: Hash32,
    pub observed_context: ElementsConsensusContextV2,
    pub expires_at_sidechain_height: u64,
    pub settlement_template_sha256: Hash32,
    pub source: BondInboxSourcePreparationV2,
    pub prepared: PreparedActionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondInboxSourcePreparationV2 {
    pub marker_vout: u32,
    /// Enqueue-only confidential staging output, in exact Elements consensus
    /// TxOut encoding. Other actions require an empty vector and u32::MAX.
    pub staging_vout: u32,
    pub exact_serialized_staging_txout: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignedActionV1 {
    Subscription {
        signed: SignedBondSubscriptionV2,
    },
    EnqueueRedemption {
        signed: SignedRedemptionEnqueueV2,
    },
    CancelRedemption {
        signed: SignedRedemptionCancellationV2,
    },
    InsuranceRecapitalization {
        signed: SignedInsuranceRecapitalizationContributionV2,
    },
}

impl SignedActionV1 {
    fn action_id(&self) -> Hash32 {
        match self {
            Self::Subscription { signed } => signed.action.action_id(),
            Self::EnqueueRedemption { signed } => signed.action.action_id(),
            Self::CancelRedemption { signed } => signed.action.action_id(),
            Self::InsuranceRecapitalization { signed } => signed.action.action_id(),
        }
    }

    fn as_inbox_action(&self) -> BondInboxUserActionV2 {
        match self {
            Self::Subscription { signed } => BondInboxUserActionV2::Subscription(signed.clone()),
            Self::EnqueueRedemption { signed } => {
                BondInboxUserActionV2::RedemptionEnqueue(signed.clone())
            }
            Self::CancelRedemption { signed } => {
                BondInboxUserActionV2::RedemptionCancellation(signed.clone())
            }
            Self::InsuranceRecapitalization { signed } => {
                BondInboxUserActionV2::InsuranceRecapitalizationContribution(signed.clone())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionSubmissionV1 {
    pub version: u16,
    pub preparation_id: Hash32,
    pub expected_chain_id: Hash32,
    pub observed_context: ElementsConsensusContextV2,
    pub settlement_template_sha256: Hash32,
    pub signed_action: SignedActionV1,
    pub marker: BondInboxMarkerV2,
    pub canonical_encrypted_bundle: Vec<u8>,
    pub custody_receipts: Vec<BondInboxCustodyReceiptV2>,
    pub availability_encryption_witness: AvailabilityEncryptionWitnessV1,
    pub source: BondInboxSourcePreparationV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityPrepareRequestV2 {
    pub version: u16,
    pub preparation_id: Hash32,
    pub application_context: Hash32,
    pub exact_private_payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityPrepareResponseV2 {
    pub version: u16,
    pub canonical_encrypted_bundle: Vec<u8>,
    pub encryption_witness: AvailabilityEncryptionWitnessV1,
    /// Exact fixed-width V1 custody receipts. At least three distinct
    /// custodians must have persisted and validated their shares.
    pub custody_receipts: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProducerActionReceiptV1 {
    pub version: u16,
    pub accepted: bool,
    pub disposition: String,
    pub action_id: Hash32,
    pub producer_receipt: Hash32,
    pub raw_transaction_hex: String,
    /// Full frozen configuration is independently validated and hashed by the
    /// client before any transaction is sent to the node.
    pub configuration: FrozenConfigurationV2,
}

struct PreparedInboxMaterialV2 {
    marker: BondInboxMarkerV2,
    canonical_encrypted_bundle: Vec<u8>,
    custody_receipts: Vec<BondInboxCustodyReceiptV2>,
    encryption_witness: AvailabilityEncryptionWitnessV1,
}

struct VerifiedSourcePackageV2 {
    txid: String,
    wtxid: String,
}

impl BondActionClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub async fn status(&self) -> Result<ClientStatus, Error> {
        let preflight = self.preflight().await?;
        self.require_producer_ready(&preflight).await?;
        Ok(ClientStatus {
            ready: true,
            code: "ready".into(),
            message: "authenticated v2 transition producer is ready".into(),
            chain_id: hex::encode(self.config.expected_chain_id),
            sidechain_height: preflight.context.sidechain_height,
            exchange_state_root: hex::encode(preflight.context.exchange_state_root),
            capital_mode: capital_mode_name(preflight.capital.mode).into(),
        })
    }

    pub async fn transfer_status(&self) -> Result<ClientStatus, Error> {
        let preflight = self.preflight().await?;
        let wallet: Value = self
            .config
            .wallet_rpc
            .call("getwalletinfo", json!([]))
            .await?;
        if !wallet.is_object() {
            return Err(Error::Wallet("wallet is unavailable".into()));
        }
        Ok(ClientStatus {
            ready: true,
            code: "ready".into(),
            message: "authenticated confidential bond transfer wallet is ready".into(),
            chain_id: hex::encode(self.config.expected_chain_id),
            sidechain_height: preflight.context.sidechain_height,
            exchange_state_root: hex::encode(preflight.context.exchange_state_root),
            capital_mode: capital_mode_name(preflight.capital.mode).into(),
        })
    }

    pub async fn subscribe(
        &self,
        key_file: &Path,
        contribution_usdd_atoms: u64,
    ) -> Result<ActionReceipt, Error> {
        if contribution_usdd_atoms == 0 {
            return Err(Error::Configuration(
                "subscription amount must be positive".into(),
            ));
        }
        self.perform(
            key_file,
            BondIntentV1::Subscription {
                contribution_usdd_atoms,
                recipient_script_sha256: self.config.recipient_script_sha256,
            },
        )
        .await
    }

    pub async fn enqueue_redemption(
        &self,
        key_file: &Path,
        bond_share_atoms: u64,
    ) -> Result<ActionReceipt, Error> {
        if bond_share_atoms == 0 {
            return Err(Error::Configuration(
                "redemption amount must be positive".into(),
            ));
        }
        self.perform(
            key_file,
            BondIntentV1::EnqueueRedemption {
                bond_share_atoms,
                destination_script_sha256: self.config.usdd_destination_script_sha256,
                holder_script_sha256: self.config.holder_script_sha256,
            },
        )
        .await
    }

    pub async fn cancel_redemption(
        &self,
        key_file: &Path,
        request_id: Hash32,
    ) -> Result<ActionReceipt, Error> {
        if request_id == [0; 32] {
            return Err(Error::Configuration(
                "redemption request id must be nonzero".into(),
            ));
        }
        self.perform(
            key_file,
            BondIntentV1::CancelRedemption {
                request_id,
                recipient_script_sha256: self.config.recipient_script_sha256,
            },
        )
        .await
    }

    pub async fn recapitalize_insurance(
        &self,
        key_file: &Path,
        contribution_usdd_atoms: u64,
    ) -> Result<ActionReceipt, Error> {
        if contribution_usdd_atoms == 0 {
            return Err(Error::Configuration(
                "recapitalization amount must be positive".into(),
            ));
        }
        self.perform(
            key_file,
            BondIntentV1::InsuranceRecapitalization {
                contribution_usdd_atoms,
            },
        )
        .await
    }

    /// Broadcast an ordinary confidential Elements transfer of the frozen
    /// bond asset. It deliberately bypasses the ECX proof/action producer: a
    /// holder-to-holder transfer does not mutate aggregate ECX capital state.
    pub async fn transfer(
        &self,
        destination: &str,
        bond_share_atoms: u64,
    ) -> Result<TransferReceipt, Error> {
        if bond_share_atoms == 0
            || bond_share_atoms > BOND_FIXED_SUPPLY_ATOMS
            || destination.is_empty()
            || destination.len() > 256
        {
            return Err(Error::Configuration(
                "transfer requires a positive amount and bounded destination".into(),
            ));
        }
        if destination.chars().any(char::is_whitespace) {
            return Err(Error::Configuration(
                "destination must not contain whitespace".into(),
            ));
        }
        // The same authenticated identity checks used before action signing
        // prevent an asset-id substitution even though this lane needs no ECX
        // transition proof.
        self.preflight().await?;
        let wallet: Value = self
            .config
            .wallet_rpc
            .call("getwalletinfo", json!([]))
            .await?;
        if !wallet.is_object() {
            return Err(Error::Wallet("wallet is unavailable".into()));
        }
        let address: Value = self
            .config
            .wallet_rpc
            .call("validateaddress", json!([destination]))
            .await?;
        let script = address
            .get("scriptPubKey")
            .and_then(Value::as_str)
            .filter(|script| canonical_hex(script) && !script.is_empty())
            .ok_or_else(|| Error::Wallet("destination script is unavailable".into()))?;
        let blinding_pubkey = address
            .get("confidential_key")
            .and_then(Value::as_str)
            .filter(|key| key.len() == 66 && canonical_hex(key))
            .ok_or_else(|| {
                Error::Wallet("destination is not a valid confidential Elements address".into())
            })?;
        if address.get("isvalid").and_then(Value::as_bool) != Some(true) {
            return Err(Error::Wallet(
                "destination is not a valid confidential Elements address".into(),
            ));
        }
        let amount = atoms_json_number(bond_share_atoms)?;
        let asset_hex = hex::encode(self.config.expected_bond_asset_id);
        let funded = prepare_transfer_pset(
            &self.config.wallet_rpc,
            destination,
            script,
            blinding_pubkey,
            &asset_hex,
            amount,
            bond_share_atoms,
        )
        .await?;
        let (processed, commitments) = process_transfer_pset(
            &self.config.wallet_rpc,
            &funded,
            script,
            blinding_pubkey,
            &asset_hex,
            bond_share_atoms,
        )
        .await?;
        let (signed_hex, decoded_signed) =
            finalize_transfer_pset(&self.config.wallet_rpc, &processed, script, &commitments)
                .await?;
        let accepted: Vec<MempoolAcceptance> = self
            .config
            .wallet_rpc
            .call("testmempoolaccept", json!([[signed_hex]]))
            .await?;
        if accepted.len() != 1 || !accepted[0].allowed {
            return Err(Error::MempoolRejected(
                accepted
                    .first()
                    .and_then(|entry| entry.reject_reason.clone())
                    .unwrap_or_else(|| "missing acceptance result".into()),
            ));
        }
        let txid: String = self
            .config
            .wallet_rpc
            .call("sendrawtransaction", json!([signed_hex]))
            .await?;
        if txid != decoded_signed.txid || !canonical_txid(&txid) {
            return Err(Error::TransferMismatch);
        }
        let mempool: Value = self
            .config
            .wallet_rpc
            .call("getmempoolentry", json!([txid]))
            .await?;
        if !mempool.is_object() {
            return Err(Error::TransferMismatch);
        }
        Ok(TransferReceipt {
            accepted: true,
            disposition: "broadcast".into(),
            txid,
        })
    }

    async fn perform(&self, key_file: &Path, intent: BondIntentV1) -> Result<ActionReceipt, Error> {
        let secret = load_key(key_file)?;
        let signer = signer(&secret);
        let before = self.preflight().await?;
        // Reject mode-ineligible intents before contacting the producer. No
        // account nonce can be assigned/consumed and no source transaction can
        // be constructed or broadcast on this path.
        validate_intent_capital_mode(before.capital.mode, &intent)?;
        let producer_status = self.require_producer_ready(&before).await?;
        let locally_derived_profile =
            BondActionProfileV2::from_configuration(&producer_status.configuration);
        let request = PrepareRequestV1 {
            version: API_VERSION,
            expected_chain_id: self.config.expected_chain_id,
            observed_context: before.context.clone(),
            signer,
            intent: intent.clone(),
        };
        let prepared: PreparedBondActionV1 = self
            .post("/v3/bond/actions/prepare", &request)
            .await
            .map_err(|error| Error::ProducerUnavailable(error.to_string()))?;

        let after_context = self
            .config
            .elements_rpc
            .consensus_context_after(&before.context)
            .await
            .map_err(|error| Error::Node(error.to_string()))?;
        if after_context != before.context || prepared.observed_context != before.context {
            return Err(Error::StaleContext);
        }
        self.validate_preparation_envelope(&prepared, &before)?;
        let signed_action = self.sign_prepared(
            &intent,
            &prepared.prepared,
            PreparedSigningContext {
                preflight: &before,
                profile: &locally_derived_profile,
                configuration: &producer_status.configuration,
                source: &prepared.source,
            },
            &secret,
        )?;
        let local_action_id = signed_action.action_id();
        let inbox_action = signed_action.as_inbox_action();
        let inbox_material = self
            .prepare_inbox_material(
                prepared.preparation_id,
                &prepared.source,
                &inbox_action,
                &locally_derived_profile,
                &secret,
            )
            .await?;
        let submission = SignedActionSubmissionV1 {
            version: API_VERSION,
            preparation_id: prepared.preparation_id,
            expected_chain_id: self.config.expected_chain_id,
            observed_context: before.context.clone(),
            settlement_template_sha256: prepared.settlement_template_sha256,
            signed_action,
            marker: inbox_material.marker,
            canonical_encrypted_bundle: inbox_material.canonical_encrypted_bundle,
            custody_receipts: inbox_material.custody_receipts,
            availability_encryption_witness: inbox_material.encryption_witness,
            source: prepared.source.clone(),
        };
        let receipt: ProducerActionReceiptV1 = self
            .post("/v3/bond/actions/submit", &submission)
            .await
            .map_err(|error| Error::Rejected(error.to_string()))?;
        if receipt.version != API_VERSION
            || !receipt.accepted
            || receipt.action_id != local_action_id
            || receipt.producer_receipt == [0; 32]
        {
            return Err(Error::Rejected(
                "receipt is not bound to the locally signed action".into(),
            ));
        }
        if receipt.disposition != "source_transaction_ready" {
            return Err(Error::UnverifiedBroadcast);
        }
        self.validate_frozen_configuration(&receipt.configuration, &locally_derived_profile)?;
        if receipt.configuration != producer_status.configuration {
            return Err(Error::UnverifiedBroadcast);
        }
        let current = self
            .config
            .elements_rpc
            .consensus_context_after(&before.context)
            .await
            .map_err(|error| Error::Node(error.to_string()))?;
        if current != before.context {
            return Err(Error::StaleContext);
        }
        let verified = verify_source_transaction_package(
            &receipt.raw_transaction_hex,
            &submission,
            &receipt.configuration,
            &before,
        )?;
        let txid = verified.txid;
        let wtxid = verified.wtxid;
        self.broadcast_verified_raw_transaction(&receipt.raw_transaction_hex, &txid)
            .await?;
        Ok(ActionReceipt {
            accepted: true,
            disposition: "broadcast".into(),
            action_id: hex::encode(local_action_id),
            producer_receipt: hex::encode(receipt.producer_receipt),
            txid,
            wtxid,
            process_deadline_parent_height: None,
            process_deadline_parent_blocks: receipt.configuration.bond_inbox_inclusion_blocks,
            refund_available_parent_height: match inbox_action {
                BondInboxUserActionV2::RedemptionEnqueue(value) => {
                    Some(value.action.refund_not_before_parent_height)
                }
                _ => None,
            },
            consensus_cursor_advanced: false,
        })
    }

    async fn preflight(&self) -> Result<AuthenticatedPreflight, Error> {
        let context = self
            .config
            .elements_rpc
            .consensus_context()
            .await
            .map_err(|error| Error::Node(error.to_string()))?;
        let health: HealthView = self
            .get_from(&self.config.matcher_url, "/health")
            .await
            .map_err(|error| Error::Matcher(error.to_string()))?;
        let capital: CapitalSnapshotV2 = self
            .get_from(&self.config.matcher_url, "/v2/capital")
            .await
            .map_err(|error| Error::Matcher(error.to_string()))?;
        let expected_chain = hex::encode(self.config.expected_chain_id);
        if health.status != "ok"
            || health.chain_id != expected_chain
            || health.chain_height != context.sidechain_height
            || !health.capital_controls_v2
            || !health.capital_authenticated
            || health.capital_mode != Some(capital.mode)
        {
            return Err(Error::Matcher(
                "health is not bound to the expected chain and authenticated v2 capital".into(),
            ));
        }
        capital
            .validate_for_exchange_root(context.exchange_state_root)
            .map_err(|error| Error::Matcher(error.to_string()))?;
        if capital.configuration_hash != self.config.expected_configuration_hash
            || capital.bond_asset_id != self.config.expected_bond_asset_id
            || capital.bond_deployment_commitment != self.config.expected_deployment_commitment
            || capital.transition_program_id != self.config.expected_transition_program_id
            || capital.transition_cmr != self.config.expected_simplicity_transition_cmr
        {
            return Err(Error::Matcher(
                "node-authenticated v2 identities differ from the wallet's frozen pins".into(),
            ));
        }
        if context.capital_snapshot.as_ref() != Some(&capital) {
            return Err(Error::Matcher(
                "matcher capital does not equal the patched node projection".into(),
            ));
        }
        Ok(AuthenticatedPreflight { capital, context })
    }

    async fn require_producer_ready(
        &self,
        preflight: &AuthenticatedPreflight,
    ) -> Result<ProducerStatusV1, Error> {
        let status: ProducerStatusV1 = self
            .get_from(&self.config.producer_url, "/v3/bond/status")
            .await
            .map_err(|error| Error::ProducerUnavailable(error.to_string()))?;
        if status.version != API_VERSION
            || !status.ready
            || !status.private_local
            || status.chain_id != self.config.expected_chain_id
            || status.context != preflight.context
            || status.proof_backend != "sp1-groth16"
            || status.transition_program_id != preflight.capital.transition_program_id
            || status.transition_cmr != preflight.capital.transition_cmr
            || !status.proof_inputs_ready
            || !status.covenant_frozen
            || !status.wallet_ready
            || !status.broadcaster_ready
        {
            return Err(Error::ProducerNotReady(
                "producer did not attest every private v2 proof/covenant/wallet gate at the active node context"
                    .into(),
            ));
        }
        self.validate_frozen_configuration(
            &status.configuration,
            &BondActionProfileV2::from_configuration(&status.configuration),
        )?;
        let local_profile = BondActionProfileV2::from_configuration(&status.configuration);
        if status.action_profile != local_profile {
            return Err(Error::ProducerNotReady(
                "producer profile differs from locally derived frozen configuration".into(),
            ));
        }
        local_profile.validate_against(&preflight.capital)?;
        Ok(status)
    }

    fn validate_preparation_envelope(
        &self,
        prepared: &PreparedBondActionV1,
        preflight: &AuthenticatedPreflight,
    ) -> Result<(), Error> {
        if prepared.version != API_VERSION
            || prepared.preparation_id == [0; 32]
            || prepared.expected_chain_id != self.config.expected_chain_id
            || prepared.settlement_template_sha256 == [0; 32]
            || prepared.expires_at_sidechain_height < preflight.context.sidechain_height
            || prepared.expires_at_sidechain_height
                > preflight
                    .context
                    .sidechain_height
                    .saturating_add(MAX_PREPARATION_BLOCK_LIFETIME)
        {
            return Err(Error::Preparation(
                "invalid version, identity, or expiration".into(),
            ));
        }
        Ok(())
    }

    fn sign_prepared(
        &self,
        intent: &BondIntentV1,
        prepared: &PreparedActionV1,
        signing: PreparedSigningContext<'_>,
        secret: &SecretKey,
    ) -> Result<SignedActionV1, Error> {
        let PreparedSigningContext {
            preflight,
            profile,
            configuration,
            source,
        } = signing;
        match (intent, prepared) {
            (
                BondIntentV1::Subscription {
                    contribution_usdd_atoms,
                    recipient_script_sha256,
                },
                PreparedActionV1::Subscription {
                    action,
                    usdd_output,
                    bond_output,
                },
            ) => {
                require_private_opening_factors(
                    (
                        usdd_output.asset_blinding_factor,
                        usdd_output.value_blinding_factor,
                    ),
                    (
                        bond_output.asset_blinding_factor,
                        bond_output.value_blinding_factor,
                    ),
                )?;
                let expected_shares = subscription_share_atoms(
                    u128::from(*contribution_usdd_atoms),
                    preflight.capital.insurance_reserve_quote_units,
                    preflight.capital.outstanding_bond_units,
                )
                .map_err(|error| Error::Preparation(error.to_string()))?;
                let inventory = BOND_FIXED_SUPPLY_ATOMS
                    .checked_sub(preflight.capital.outstanding_bond_units)
                    .ok_or_else(|| Error::Preparation("bond supply exceeds fixed cap".into()))?;
                if expected_shares > inventory
                    || action.version != BondSubscriptionV2::VERSION
                    || action.chain_id != self.config.expected_chain_id
                    || action.configuration_hash != self.config.expected_configuration_hash
                    || action.trader != signer(secret)
                    || action.contribution_usdd_atoms != *contribution_usdd_atoms
                    || action.issued_share_atoms != expected_shares
                    || action.bond_recipient_script_sha256 != *recipient_script_sha256
                {
                    return Err(Error::Preparation(
                        "subscription economics or signer differ from the requested intent".into(),
                    ));
                }
                let id = action.subscription_id();
                if usdd_output.amount != *contribution_usdd_atoms
                    || !matches!(
                        usdd_output.role,
                        CollateralOutputRoleV2::BondSubscriptionContribution {
                            subscription_id
                        } if subscription_id == id
                    )
                    || bond_output.amount != expected_shares
                    || !matches!(
                        bond_output.role,
                        BondOutputRoleV2::Subscription {
                            subscription_id,
                            recipient_script_sha256: recipient
                        } if subscription_id == id && recipient == *recipient_script_sha256
                    )
                    || subscription_usdd_output_commitment(usdd_output, profile)
                        .map_err(|error| Error::Preparation(error.to_string()))?
                        != action.usdd_output_opening_commitment
                    || subscription_bond_output_commitment(bond_output, profile)
                        .map_err(|error| Error::Preparation(error.to_string()))?
                        != action.bond_output_opening_commitment
                {
                    return Err(Error::Preparation(
                        "subscription confidential openings are not exactly proof-bound".into(),
                    ));
                }
                let signed = SignedBondSubscriptionV2::sign(action.clone(), secret)
                    .map_err(|error| Error::Signing(error.to_string()))?;
                signed
                    .verify()
                    .map_err(|error| Error::Signing(error.to_string()))?;
                Ok(SignedActionV1::Subscription { signed })
            }
            (
                BondIntentV1::EnqueueRedemption {
                    bond_share_atoms,
                    destination_script_sha256,
                    holder_script_sha256,
                },
                PreparedActionV1::EnqueueRedemption {
                    action,
                    bond_input,
                    queue_output,
                },
            ) => {
                require_private_opening_factors(
                    (
                        bond_input.asset_blinding_factor,
                        bond_input.value_blinding_factor,
                    ),
                    (
                        queue_output.asset_blinding_factor,
                        queue_output.value_blinding_factor,
                    ),
                )?;
                // The transition producer does not choose how long the
                // holder's staged bond output remains locked.  Allow the
                // complete frozen inclusion window for the source transaction
                // to land, then the exact frozen unilateral-refund delay from
                // that latest admissible parent.  A source included later is
                // deliberately not admitted to the proof inbox and reaches
                // this same absolute refund height instead.
                let expected_refund_not_before_parent_height = preflight
                    .context
                    .parent_height
                    .checked_add(u64::from(configuration.bond_inbox_inclusion_blocks))
                    .and_then(|height| {
                        height.checked_add(u64::from(profile.refund_minimum_parent_blocks))
                    })
                    .ok_or_else(|| {
                        Error::Preparation(
                            "deterministic redemption refund height overflows".into(),
                        )
                    })?;
                if preflight.capital.mode != CapitalMode::Normal
                    || action.version != RedemptionEnqueueV2::VERSION
                    || action.chain_id != self.config.expected_chain_id
                    || action.configuration_hash != self.config.expected_configuration_hash
                    || action.claimant != signer(secret)
                    || action.requested_share_atoms != *bond_share_atoms
                    || action.refund_not_before_parent_height
                        != expected_refund_not_before_parent_height
                    || action.destination_script_hash != *destination_script_sha256
                    || action.holder_script_sha256 != *holder_script_sha256
                {
                    return Err(Error::Preparation(
                        "redemption enqueue is not permitted, has a producer-selected refund deadline, or differs from the requested intent".into(),
                    ));
                }
                let stable_intent_id = action.stable_intent_id();
                let claimant = action.claimant_commitment();
                let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
                    chain_id: action.chain_id,
                    configuration_hash: action.configuration_hash,
                    marker_signer: action.claimant,
                    stable_intent_id,
                    staging_vout: source.staging_vout,
                    refund_script_sha256: action.refund_script_sha256,
                    refund_not_before_parent_height: action.refund_not_before_parent_height,
                };
                let exact_staging_script =
                    bond_inbox_redemption_staging_script_sha256_v2(configuration, renderer_input)
                        .map_err(|error| Error::Preparation(error.to_string()))?;
                let prepared_staging: elements::TxOut = elements::encode::deserialize(
                    &source.exact_serialized_staging_txout,
                )
                .map_err(|_| {
                    Error::Preparation(
                        "producer supplied a malformed staging TxOut before signature".into(),
                    )
                })?;
                if elements::encode::serialize(&prepared_staging)
                    != source.exact_serialized_staging_txout
                    || !prepared_staging.asset.is_confidential()
                    || !prepared_staging.value.is_confidential()
                    || !prepared_staging.nonce.is_confidential()
                    || elements::hashes::sha256::Hash::hash(
                        prepared_staging.script_pubkey.as_bytes(),
                    )
                    .to_byte_array()
                        != exact_staging_script
                {
                    return Err(Error::Preparation(
                        "prepared staging TxOut is not the locally rendered per-intent V18 script"
                            .into(),
                    ));
                }
                if bond_input.amount != *bond_share_atoms
                    || !matches!(
                        bond_input.role,
                        BondInputRoleV2::StagedRedemptionEnqueue {
                            staging_intent_id,
                            claimant: input_claimant,
                            staging_script_sha256,
                            ..
                        } if staging_intent_id == stable_intent_id
                            && input_claimant == claimant
                            && staging_script_sha256 == exact_staging_script
                    )
                    || queue_output.amount != *bond_share_atoms
                    || !matches!(
                        queue_output.role,
                        BondOutputRoleV2::QueuedRedemptionEntry {
                            staging_intent_id,
                            claimant: output_claimant,
                            destination_script_sha256: destination,
                            ..
                        } if staging_intent_id == stable_intent_id
                            && output_claimant == claimant
                            && destination == *destination_script_sha256
                    )
                    || redemption_enqueue_bond_input_commitment(bond_input, profile)
                        .map_err(|error| Error::Preparation(error.to_string()))?
                        != action.bond_input_opening_commitment
                    || redemption_enqueue_queue_output_commitment(queue_output, profile)
                        .map_err(|error| Error::Preparation(error.to_string()))?
                        != action.queue_output_opening_commitment
                {
                    return Err(Error::Preparation(
                        "redemption confidential openings are not exactly proof-bound".into(),
                    ));
                }
                let signed = SignedRedemptionEnqueueV2::sign(action.clone(), secret)
                    .map_err(|error| Error::Signing(error.to_string()))?;
                signed
                    .verify()
                    .map_err(|error| Error::Signing(error.to_string()))?;
                Ok(SignedActionV1::EnqueueRedemption { signed })
            }
            (
                BondIntentV1::CancelRedemption {
                    request_id,
                    recipient_script_sha256,
                },
                PreparedActionV1::CancelRedemption {
                    action,
                    queue_input,
                    bond_return_output,
                },
            ) => {
                require_private_opening_factors(
                    (
                        queue_input.asset_blinding_factor,
                        queue_input.value_blinding_factor,
                    ),
                    (
                        bond_return_output.asset_blinding_factor,
                        bond_return_output.value_blinding_factor,
                    ),
                )?;
                if preflight.capital.mode == CapitalMode::Recovery
                    || action.version != RedemptionCancellationV2Action::VERSION
                    || action.chain_id != self.config.expected_chain_id
                    || action.configuration_hash != self.config.expected_configuration_hash
                    || action.claimant != signer(secret)
                    || action.request_id != *request_id
                    || action.bond_recipient_script_sha256 != *recipient_script_sha256
                    || queue_input.amount == 0
                    || queue_input.amount != bond_return_output.amount
                    || !matches!(
                        queue_input.role,
                        BondInputRoleV2::QueuedRedemption { redemption_id } if redemption_id == *request_id
                    )
                    || redemption_cancel_queue_input_commitment(queue_input, profile)
                        .map_err(|error| Error::Preparation(error.to_string()))?
                        != action.queue_input_opening_commitment
                    || redemption_cancel_bond_return_commitment(bond_return_output, profile)
                        .map_err(|error| Error::Preparation(error.to_string()))?
                        != action.bond_return_output_opening_commitment
                {
                    return Err(Error::Preparation(
                        "cancellation is not permitted in recapitalization-only mode or its confidential openings are not exactly proof-bound"
                            .into(),
                    ));
                }
                // Proof/settlement additionally validate the role's claimant,
                // destination, and signed-cancellation binding. This signer
                // rejects every other output role before releasing a key use.
                let claimant = tagged_hash("ECX/bond-claimant/v2", &action.claimant.0);
                let expected_cancellation_id = action.cancellation_id();
                if !matches!(
                    bond_return_output.role,
                    BondOutputRoleV2::CancelledRedemptionReturn {
                        redemption_id,
                        claimant: output_claimant,
                        recipient_script_sha256: recipient,
                        cancellation_id,
                    } if redemption_id == *request_id
                        && output_claimant == claimant
                        && recipient == *recipient_script_sha256
                        && cancellation_id == expected_cancellation_id
                ) {
                    return Err(Error::Preparation(
                        "cancellation return is not bound to the claimant and recipient".into(),
                    ));
                }
                let signed = SignedRedemptionCancellationV2::sign(action.clone(), secret)
                    .map_err(|error| Error::Signing(error.to_string()))?;
                signed
                    .verify()
                    .map_err(|error| Error::Signing(error.to_string()))?;
                Ok(SignedActionV1::CancelRedemption { signed })
            }
            (
                BondIntentV1::InsuranceRecapitalization {
                    contribution_usdd_atoms,
                },
                PreparedActionV1::InsuranceRecapitalization {
                    action,
                    insurance_output,
                },
            ) => {
                require_one_private_opening_factors((
                    insurance_output.asset_blinding_factor,
                    insurance_output.value_blinding_factor,
                ))?;
                if action.version != InsuranceRecapitalizationContributionV2::VERSION
                    || action.chain_id != self.config.expected_chain_id
                    || action.configuration_hash != self.config.expected_configuration_hash
                    || action.contributor != signer(secret)
                    || action.contribution_usdd_atoms != *contribution_usdd_atoms
                    || action.issued_share_atoms != 0
                    || action.bond_output_opening_commitment != [0; 32]
                    || insurance_output.amount != *contribution_usdd_atoms
                    || !matches!(
                        insurance_output.role,
                        CollateralOutputRoleV2::InsuranceRecapitalizationContribution {
                            contribution_id
                        } if contribution_id == action.contribution_id()
                    )
                    || recapitalization_usdd_output_commitment(insurance_output, profile)
                        .map_err(|error| Error::Preparation(error.to_string()))?
                        != action.insurance_output_opening_commitment
                {
                    return Err(Error::Preparation(
                        "non-dilutive recapitalization economics or insurance opening mismatch"
                            .into(),
                    ));
                }
                let signed =
                    SignedInsuranceRecapitalizationContributionV2::sign(action.clone(), secret)
                        .map_err(|error| Error::Signing(error.to_string()))?;
                signed
                    .verify()
                    .map_err(|error| Error::Signing(error.to_string()))?;
                Ok(SignedActionV1::InsuranceRecapitalization { signed })
            }
            _ => Err(Error::Preparation(
                "producer returned a different action kind".into(),
            )),
        }
    }

    async fn prepare_inbox_material(
        &self,
        preparation_id: Hash32,
        source: &BondInboxSourcePreparationV2,
        action: &BondInboxUserActionV2,
        profile: &BondActionProfileV2,
        secret: &SecretKey,
    ) -> Result<PreparedInboxMaterialV2, Error> {
        if source.marker_vout == u32::MAX {
            return Err(Error::Preparation(
                "bond inbox marker output index is missing".into(),
            ));
        }
        let (staging_intent_id, refund_script_sha256, refund_height, source_authorization) =
            match action {
                BondInboxUserActionV2::RedemptionEnqueue(value) => {
                    if source.staging_vout == u32::MAX
                        || source.staging_vout == source.marker_vout
                        || source.exact_serialized_staging_txout.is_empty()
                        || source.exact_serialized_staging_txout.len()
                            > usize::try_from(profile.maximum_bundle_bytes).unwrap_or(usize::MAX)
                    {
                        return Err(Error::Preparation(
                            "enqueue source does not contain one exact confidential staging output"
                                .into(),
                        ));
                    }
                    let stable_intent_id = value.action.stable_intent_id();
                    let source_authorization =
                        bond_inbox_staging_source_authorization_commitment_v2(
                            &source.exact_serialized_staging_txout,
                            stable_intent_id,
                            value.action.refund_script_sha256,
                            value.action.refund_not_before_parent_height,
                        )
                        .map_err(|error| Error::Preparation(error.to_string()))?;
                    (
                        stable_intent_id,
                        value.action.refund_script_sha256,
                        value.action.refund_not_before_parent_height,
                        source_authorization,
                    )
                }
                _ => {
                    if source.staging_vout != u32::MAX
                        || !source.exact_serialized_staging_txout.is_empty()
                    {
                        return Err(Error::Preparation(
                            "non-enqueue action supplied a staging output".into(),
                        ));
                    }
                    let source_authorization =
                        bond_inbox_no_staging_source_authorization_commitment_v2(
                            self.config.expected_chain_id,
                            self.config.expected_configuration_hash,
                            action.signer(),
                            action.action_id(),
                            source.marker_vout,
                        )
                        .map_err(|error| Error::Preparation(error.to_string()))?;
                    ([0; 32], [0; 32], 0, source_authorization)
                }
            };

        let mut commitment_blinding = [0_u8; 32];
        while commitment_blinding == [0; 32] {
            OsRng.fill_bytes(&mut commitment_blinding);
        }
        let canonical_signed_action = action.canonical_signed_bytes();
        let settlement_witness_commitment = action.settlement_witness_commitment();
        let payload_commitment = BondInboxAvailablePayloadV2::commitment(
            action.kind(),
            commitment_blinding,
            &canonical_signed_action,
            settlement_witness_commitment,
            source_authorization,
        );
        let payload = BondInboxAvailablePayloadV2 {
            commitment_blinding,
            canonical_signed_action,
            settlement_witness_commitment,
            source_authorization_commitment: source_authorization,
        };
        let exact_private_payload = payload.canonical_bytes();
        if exact_private_payload.len() > usize::try_from(profile.maximum_bundle_bytes).unwrap_or(0)
        {
            return Err(Error::Preparation(
                "canonical bond action exceeds the frozen inbox bundle bound".into(),
            ));
        }
        let mut marker = BondInboxMarkerV2 {
            version: BondInboxMarkerV2::VERSION,
            kind: action.kind(),
            chain_id: self.config.expected_chain_id,
            configuration_hash: self.config.expected_configuration_hash,
            signer: action.signer(),
            action_id: action.action_id(),
            staging_intent_id,
            staging_vout: source.staging_vout,
            refund_script_sha256,
            refund_not_before_parent_height: refund_height,
            payload_commitment,
            availability_scheme_hash: profile.availability_scheme_hash,
            availability_custodian_registry_hash: profile.availability_custodian_registry_hash,
            availability_bundle_root: [1; 32],
            availability_context: [0; 32],
            availability_receipt_root: [1; 32],
            availability_bundle_len: 1,
            availability_receipt_bitmap: 0,
            source_authorization_commitment: source_authorization,
            signature: Signature64([0; 64]),
        };
        marker.availability_context = marker.expected_availability_context();
        let availability_request = AvailabilityPrepareRequestV2 {
            version: API_VERSION,
            preparation_id,
            application_context: marker.availability_context,
            exact_private_payload: exact_private_payload.clone(),
        };
        let availability: AvailabilityPrepareResponseV2 = self
            .post("/v3/bond/actions/availability", &availability_request)
            .await
            .map_err(|error| Error::ProducerUnavailable(error.to_string()))?;
        if availability.version != API_VERSION
            || availability.canonical_encrypted_bundle.is_empty()
            || availability.canonical_encrypted_bundle.len()
                > usize::try_from(profile.maximum_bundle_bytes).unwrap_or(0)
        {
            return Err(Error::Preparation(
                "producer returned a malformed encrypted availability bundle".into(),
            ));
        }
        let bundle = WitnessBundle::decode(&availability.canonical_encrypted_bundle)
            .map_err(|error| Error::Preparation(error.to_string()))?;
        if bundle.context != marker.availability_context
            || bundle
                .encode()
                .map_err(|error| Error::Preparation(error.to_string()))?
                != availability.canonical_encrypted_bundle
        {
            return Err(Error::Preparation(
                "encrypted bundle does not bind the exact action context".into(),
            ));
        }
        verify_bundle_encryption(
            &bundle,
            &availability.encryption_witness,
            &exact_private_payload,
        )
        .map_err(|error| Error::Preparation(error.to_string()))?;
        let registry = bundle
            .custodians
            .iter()
            .map(|entry| entry.public)
            .collect::<Vec<_>>();
        if custodian_registry_hash(&registry)
            .map_err(|error| Error::Preparation(error.to_string()))?
            != profile.availability_custodian_registry_hash
        {
            return Err(Error::Preparation(
                "encrypted bundle substituted the frozen custodian registry".into(),
            ));
        }
        let mut decoded_receipts = Vec::with_capacity(availability.custody_receipts.len());
        let mut custody_receipts = Vec::with_capacity(availability.custody_receipts.len());
        let mut previous_index = 0_u8;
        for exact in &availability.custody_receipts {
            let receipt = CustodyReceiptV1::decode_canonical(exact)
                .map_err(|error| Error::Preparation(error.to_string()))?;
            if receipt.custodian_index <= previous_index {
                return Err(Error::Preparation(
                    "custody receipts are not in strict frozen-registry order".into(),
                ));
            }
            previous_index = receipt.custodian_index;
            decoded_receipts.push(receipt.clone());
            custody_receipts.push(BondInboxCustodyReceiptV2 {
                custodian_index: receipt.custodian_index - 1,
                exact_receipt_bytes: exact.clone(),
            });
        }
        verify_custody_receipts(&bundle, &decoded_receipts)
            .map_err(|error| Error::Preparation(error.to_string()))?;
        marker.availability_bundle_root =
            bond_inbox_availability_bundle_root_v2(&availability.canonical_encrypted_bundle)
                .map_err(|error| Error::Preparation(error.to_string()))?;
        marker.availability_bundle_len =
            u32::try_from(availability.canonical_encrypted_bundle.len())
                .map_err(|_| Error::Preparation("encrypted bundle length overflow".into()))?;
        let (receipt_root, receipt_bitmap) =
            canonical_bond_inbox_custody_receipts_v2(&marker, &custody_receipts)
                .map_err(|error| Error::Preparation(error.to_string()))?;
        marker.availability_receipt_root = receipt_root;
        marker.availability_receipt_bitmap = receipt_bitmap;
        let availability_config = AvailabilityConfigV1 {
            version: AvailabilityConfigV1::VERSION,
            scheme_hash: profile.availability_scheme_hash,
            custodian_registry_hash: profile.availability_custodian_registry_hash,
            recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
            custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
            maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
        };
        verify_bond_inbox_source_witness_commitments_v2(
            &marker,
            availability_config,
            &availability.canonical_encrypted_bundle,
            &custody_receipts,
        )
        .map_err(|error| Error::Preparation(error.to_string()))?;
        marker = marker
            .sign(secret)
            .map_err(|error| Error::Signing(error.to_string()))?;
        marker
            .verify_wrapper_signature()
            .map_err(|error| Error::Signing(error.to_string()))?;
        Ok(PreparedInboxMaterialV2 {
            marker,
            canonical_encrypted_bundle: availability.canonical_encrypted_bundle,
            custody_receipts,
            encryption_witness: availability.encryption_witness,
        })
    }

    fn validate_frozen_configuration(
        &self,
        configuration: &FrozenConfigurationV2,
        profile: &BondActionProfileV2,
    ) -> Result<(), Error> {
        configuration
            .validate()
            .map_err(|error| Error::Preparation(error.to_string()))?;
        if configuration.digest() != self.config.expected_configuration_hash
            || configuration.base.chain_id != self.config.expected_chain_id
            || configuration.bond_asset_id != self.config.expected_bond_asset_id
            || configuration.bond_deployment_commitment
                != self.config.expected_deployment_commitment
            || configuration.base.usdd_asset_id != profile.usdd_asset_id
            || configuration.insurance_reserve_script_sha256
                != profile.insurance_reserve_script_sha256
            || configuration.bond_redemption_queue_script_sha256
                != profile.redemption_queue_script_sha256
            || configuration.bond_inbox_redemption_staging_template_commitment
                != profile.redemption_staging_template_commitment
            || configuration.bond_inbox_redemption_staging_renderer_domain
                != profile.redemption_staging_renderer_domain
            || configuration.bond_inbox_refund_minimum_parent_blocks
                != profile.refund_minimum_parent_blocks
            || configuration.base.availability.scheme_hash != profile.availability_scheme_hash
            || configuration.base.availability.custodian_registry_hash
                != profile.availability_custodian_registry_hash
            || configuration.bond_inbox_custody_receipt_codec_hash
                != profile.custody_receipt_codec_hash
            || configuration.bond_inbox_max_bundle_bytes != profile.maximum_bundle_bytes
        {
            return Err(Error::Preparation(
                "source transaction substituted a frozen v2 configuration identity".into(),
            ));
        }
        Ok(())
    }

    async fn broadcast_verified_raw_transaction(
        &self,
        raw_transaction_hex: &str,
        expected_txid: &str,
    ) -> Result<(), Error> {
        let accepted: Vec<MempoolAcceptance> = self
            .config
            .wallet_rpc
            .call("testmempoolaccept", json!([[raw_transaction_hex]]))
            .await?;
        if accepted.len() != 1 || !accepted[0].allowed {
            return Err(Error::MempoolRejected(
                accepted
                    .first()
                    .and_then(|entry| entry.reject_reason.clone())
                    .unwrap_or_else(|| "missing acceptance result".into()),
            ));
        }
        let txid: String = self
            .config
            .wallet_rpc
            .call("sendrawtransaction", json!([raw_transaction_hex]))
            .await?;
        if txid != expected_txid || !canonical_txid(&txid) {
            return Err(Error::TransferMismatch);
        }
        let mempool: Value = self
            .config
            .wallet_rpc
            .call("getmempoolentry", json!([txid]))
            .await?;
        if !mempool.is_object() {
            return Err(Error::TransferMismatch);
        }
        Ok(())
    }

    async fn get_from<T: DeserializeOwned>(&self, base: &Url, path: &str) -> Result<T, Error> {
        let url = base
            .join(path)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        decode_response(self.config.http.get(url).send().await).await
    }

    async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let url = self
            .config
            .producer_url
            .join(path)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        decode_response(self.config.http.post(url).json(body).send().await).await
    }
}

fn verify_source_transaction_package(
    raw_transaction_hex: &str,
    submission: &SignedActionSubmissionV1,
    configuration: &FrozenConfigurationV2,
    preflight: &AuthenticatedPreflight,
) -> Result<VerifiedSourcePackageV2, Error> {
    if raw_transaction_hex.is_empty()
        || raw_transaction_hex.len() % 2 != 0
        || !canonical_hex(raw_transaction_hex)
    {
        return Err(Error::UnverifiedBroadcast);
    }
    let raw = hex::decode(raw_transaction_hex).map_err(|_| Error::UnverifiedBroadcast)?;
    let transaction: elements::Transaction =
        elements::encode::deserialize(&raw).map_err(|_| Error::UnverifiedBroadcast)?;
    if elements::encode::serialize(&transaction) != raw {
        return Err(Error::UnverifiedBroadcast);
    }
    let witness = elements_transaction_witness_bytes_v2(&raw)
        .map_err(|error| Error::Preparation(error.to_string()))?;
    let source_txid = transaction.txid().to_byte_array();
    let source_wtxid = transaction.wtxid().to_byte_array();
    let entry = BondInboxEntryV2 {
        version: BondInboxEntryV2::VERSION,
        index: preflight
            .capital
            .bond_inbox
            .node_verified_source_entry_count,
        previous_root: preflight.capital.bond_inbox.node_verified_source_head_root,
        observed_sidechain_height: preflight.context.sidechain_height,
        observed_parent_height: preflight.context.parent_height,
        source_block_hash: preflight.context.sidechain_block_hash,
        source_txid,
        source_wtxid,
        source_transaction_len: u32::try_from(raw.len()).map_err(|_| Error::UnverifiedBroadcast)?,
        source_witness_sha256: bond_inbox_source_witness_sha256_v2(&witness)
            .map_err(|_| Error::UnverifiedBroadcast)?,
        source_witness_len: u32::try_from(witness.len()).map_err(|_| Error::UnverifiedBroadcast)?,
        source_tx_index: 0,
        marker_vout: submission.source.marker_vout,
        marker: submission.marker,
    };
    let verified = verify_bond_inbox_source_transaction_v2(
        &entry,
        &raw,
        &submission.canonical_encrypted_bundle,
        &submission.custody_receipts,
        configuration,
    )
    .map_err(|error| Error::Preparation(error.to_string()))?;
    if verified.txid != source_txid
        || verified.wtxid != source_wtxid
        || verified.exact_witness_sha256 != entry.source_witness_sha256
    {
        return Err(Error::UnverifiedBroadcast);
    }
    let is_enqueue = matches!(
        submission.signed_action,
        SignedActionV1::EnqueueRedemption { .. }
    );
    if is_enqueue {
        let expected_staging_hash =
            elements::hashes::sha256::Hash::hash(&submission.source.exact_serialized_staging_txout)
                .to_byte_array();
        if verified.staging_vout != Some(submission.source.staging_vout)
            || verified.staging_txout_sha256 != Some(expected_staging_hash)
            || verified.staging_script_sha256.is_none()
        {
            return Err(Error::UnverifiedBroadcast);
        }
    } else if verified.staging_vout.is_some()
        || verified.staging_txout_sha256.is_some()
        || verified.staging_script_sha256.is_some()
    {
        return Err(Error::UnverifiedBroadcast);
    }
    Ok(VerifiedSourcePackageV2 {
        txid: transaction.txid().to_string(),
        wtxid: transaction.wtxid().to_string(),
    })
}

async fn decode_response<T: DeserializeOwned>(
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<T, Error> {
    let mut response = result.map_err(|error| Error::ProducerUnavailable(error.to_string()))?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(Error::ProducerUnavailable("response is oversized".into()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Error::ProducerUnavailable(error.to_string()))?
    {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
            return Err(Error::ProducerUnavailable("response is oversized".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(Error::ProducerUnavailable(message));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| Error::ProducerUnavailable(format!("malformed response: {error}")))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TraderKey {
    version: u16,
    role: String,
    secret_key_hex: String,
}

fn load_key(path: &Path) -> Result<SecretKey, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| Error::Key(error.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err(Error::Key(
            "key must be a small regular non-symlink file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Key(
                "key permissions must be 0600 or stricter".into(),
            ));
        }
    }
    let document: TraderKey =
        serde_json::from_slice(&fs::read(path).map_err(|error| Error::Key(error.to_string()))?)
            .map_err(|error| Error::Key(error.to_string()))?;
    if document.version != 1 || document.role != "ecx_trader" {
        return Err(Error::Key("unexpected key role or version".into()));
    }
    let bytes: [u8; 32] = hex::decode(document.secret_key_hex)
        .map_err(|error| Error::Key(error.to_string()))?
        .try_into()
        .map_err(|_| Error::Key("secret key must be 32 bytes".into()))?;
    SecretKey::from_slice(&bytes).map_err(|error| Error::Key(error.to_string()))
}

fn signer(secret: &SecretKey) -> XOnlyKey {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret);
    let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
    XOnlyKey(public.serialize())
}

/// Reject producer-provided factors that would make a proof-valid action
/// trivially linkable. The complete transition verifier independently checks
/// nonzero/non-reuse across every protected V2 opening; this local check runs
/// before the client releases its BIP340 signature.
fn require_private_opening_factors(
    first: ([u8; 32], [u8; 32]),
    second: ([u8; 32], [u8; 32]),
) -> Result<(), Error> {
    if first.0 == [0; 32]
        || first.1 == [0; 32]
        || second.0 == [0; 32]
        || second.1 == [0; 32]
        || first.0 == second.0
        || first.1 == second.1
    {
        return Err(Error::Preparation(
            "confidential openings use a zero or repeated blinding factor".into(),
        ));
    }
    Ok(())
}

fn require_one_private_opening_factors(first: ([u8; 32], [u8; 32])) -> Result<(), Error> {
    if first.0 == [0; 32] || first.1 == [0; 32] || first.0 == first.1 {
        return Err(Error::Preparation(
            "confidential opening uses a zero or repeated blinding factor".into(),
        ));
    }
    Ok(())
}

fn subscription_usdd_output_commitment(
    value: &CollateralOutputOpeningV2,
    profile: &BondActionProfileV2,
) -> Result<Hash32, ecx_elements_settlement::SettlementError> {
    let stable_id = match value.role {
        CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id } => subscription_id,
        _ => return Err(ecx_elements_settlement::SettlementError::BondActionMismatch),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::SubscriptionInsuranceOutput,
        stable_id,
        profile.usdd_asset_id,
        value.amount,
        profile.insurance_reserve_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
}

fn subscription_bond_output_commitment(
    value: &BondOutputOpeningV2,
    profile: &BondActionProfileV2,
) -> Result<Hash32, ecx_elements_settlement::SettlementError> {
    let (stable_id, script) = match value.role {
        BondOutputRoleV2::Subscription {
            subscription_id,
            recipient_script_sha256,
        } => (subscription_id, recipient_script_sha256),
        _ => return Err(ecx_elements_settlement::SettlementError::BondActionMismatch),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::SubscriptionBondOutput,
        stable_id,
        profile.bond_asset_id,
        value.amount,
        script,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
}

fn recapitalization_usdd_output_commitment(
    value: &CollateralOutputOpeningV2,
    profile: &BondActionProfileV2,
) -> Result<Hash32, ecx_elements_settlement::SettlementError> {
    let stable_id = match value.role {
        CollateralOutputRoleV2::InsuranceRecapitalizationContribution { contribution_id } => {
            contribution_id
        }
        _ => return Err(ecx_elements_settlement::SettlementError::BondActionMismatch),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::RecapitalizationInsuranceOutput,
        stable_id,
        profile.usdd_asset_id,
        value.amount,
        profile.insurance_reserve_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
}

fn redemption_enqueue_bond_input_commitment(
    value: &BondInputOpeningV2,
    profile: &BondActionProfileV2,
) -> Result<Hash32, ecx_elements_settlement::SettlementError> {
    let (stable_id, script) = match value.role {
        BondInputRoleV2::StagedRedemptionEnqueue {
            staging_intent_id,
            staging_script_sha256,
            ..
        } => (staging_intent_id, staging_script_sha256),
        _ => return Err(ecx_elements_settlement::SettlementError::BondActionMismatch),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::EnqueueStagingBondInput,
        stable_id,
        profile.bond_asset_id,
        value.amount,
        script,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
}

fn redemption_enqueue_queue_output_commitment(
    value: &BondOutputOpeningV2,
    profile: &BondActionProfileV2,
) -> Result<Hash32, ecx_elements_settlement::SettlementError> {
    let stable_id = match value.role {
        BondOutputRoleV2::QueuedRedemptionEntry {
            staging_intent_id, ..
        } => staging_intent_id,
        _ => return Err(ecx_elements_settlement::SettlementError::BondActionMismatch),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::EnqueueQueueBondOutput,
        stable_id,
        profile.bond_asset_id,
        value.amount,
        profile.redemption_queue_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
}

fn redemption_cancel_queue_input_commitment(
    value: &BondInputOpeningV2,
    profile: &BondActionProfileV2,
) -> Result<Hash32, ecx_elements_settlement::SettlementError> {
    let stable_id = match value.role {
        BondInputRoleV2::QueuedRedemption { redemption_id } => redemption_id,
        _ => return Err(ecx_elements_settlement::SettlementError::BondActionMismatch),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::CancellationQueueBondInput,
        stable_id,
        profile.bond_asset_id,
        value.amount,
        profile.redemption_queue_script_sha256,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
}

fn redemption_cancel_bond_return_commitment(
    value: &BondOutputOpeningV2,
    profile: &BondActionProfileV2,
) -> Result<Hash32, ecx_elements_settlement::SettlementError> {
    let (stable_id, script) = match value.role {
        BondOutputRoleV2::CancelledRedemptionReturn {
            cancellation_id,
            recipient_script_sha256,
            ..
        } => (cancellation_id, recipient_script_sha256),
        _ => return Err(ecx_elements_settlement::SettlementError::BondActionMismatch),
    };
    logical_allocation_commitment_v2(
        LogicalAllocationKindV2::CancellationBondReturnOutput,
        stable_id,
        profile.bond_asset_id,
        value.amount,
        script,
        value.asset_blinding_factor,
        value.value_blinding_factor,
    )
}

fn endpoint(value: &str, name: &str) -> Result<Url, Error> {
    let mut url = Url::parse(value)
        .map_err(|error| Error::Configuration(format!("invalid {name} URL: {error}")))?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Configuration(format!(
            "{name} URL must not contain credentials, query, or fragment"
        )));
    }
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
        || url.host_str() == Some("localhost");
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(Error::Configuration(format!(
            "{name} must use HTTPS unless it is loopback-only"
        )));
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

pub fn hash32(value: &str, name: &str) -> Result<Hash32, Error> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Configuration(format!(
            "{name} must be 32-byte lowercase hex"
        )));
    }
    hex::decode(value)
        .map_err(|error| Error::Configuration(error.to_string()))?
        .try_into()
        .map_err(|_| Error::Configuration(format!("{name} must be 32 bytes")))
}

fn capital_mode_name(mode: CapitalMode) -> &'static str {
    match mode {
        CapitalMode::Normal => "normal",
        CapitalMode::ReduceOnly => "reduce_only",
        CapitalMode::Recovery => "recovery",
    }
}

#[derive(Clone)]
struct WalletRpc {
    endpoint: Url,
    username: Option<String>,
    password: Option<String>,
    client: Client,
}

impl WalletRpc {
    fn new(
        endpoint_value: &str,
        username: Option<String>,
        password: Option<String>,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let endpoint = endpoint(endpoint_value, "Elements wallet RPC")?;
        if username.is_some() != password.is_some() {
            return Err(Error::Configuration(
                "Elements RPC username and password must be supplied together".into(),
            ));
        }
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| Error::Configuration(error.to_string()))?;
        Ok(Self {
            endpoint,
            username,
            password,
            client,
        })
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, Error> {
        let mut request = self.client.post(self.endpoint.clone()).json(&json!({
            "jsonrpc": "2.0",
            "id": "ecx-bond-wallet",
            "method": method,
            "params": params,
        }));
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request = request.basic_auth(username, Some(password));
        }
        let response: RpcResponse<T> = decode_wallet_response(request.send().await).await?;
        if response.id != "ecx-bond-wallet"
            || response
                .jsonrpc
                .as_deref()
                .is_some_and(|version| version != "2.0")
        {
            return Err(Error::Wallet("mismatched RPC response envelope".into()));
        }
        if let Some(error) = response.error {
            return Err(Error::Wallet(format!(
                "{method} failed ({}): {}",
                error.code, error.message
            )));
        }
        response
            .result
            .ok_or_else(|| Error::Wallet(format!("{method} returned no result")))
    }
}

async fn decode_wallet_response<T: DeserializeOwned>(
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<RpcResponse<T>, Error> {
    let mut response = result.map_err(|error| Error::Wallet(error.to_string()))?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(Error::Wallet(format!(
            "RPC returned HTTP {} or an oversized response",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Error::Wallet(error.to_string()))?
    {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
            return Err(Error::Wallet("RPC response is oversized".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|error| Error::Wallet(error.to_string()))
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    #[serde(default)]
    jsonrpc: Option<String>,
    id: String,
    result: Option<T>,
    error: Option<RpcFailure>,
}

#[derive(Deserialize)]
struct RpcFailure {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct FundedPset {
    psbt: String,
}

#[derive(Deserialize)]
struct ProcessedPset {
    psbt: String,
    complete: bool,
}

#[derive(Deserialize)]
struct FinalizedPset {
    #[serde(default)]
    hex: Option<String>,
    complete: bool,
}

#[derive(Deserialize)]
struct MempoolAcceptance {
    allowed: bool,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}

#[derive(Deserialize)]
struct DecodedPset {
    psbt_version: u32,
    input_count: u64,
    output_count: u64,
    outputs: Vec<DecodedPsetOutput>,
}

#[derive(Deserialize)]
struct DecodedPsetOutput {
    #[serde(default)]
    amount: Option<Value>,
    #[serde(default)]
    script: Option<DecodedScript>,
    #[serde(default)]
    asset: Option<String>,
    #[serde(default)]
    value_commitment: Option<String>,
    #[serde(default)]
    asset_commitment: Option<String>,
    #[serde(default)]
    blinding_pubkey: Option<String>,
    #[serde(default)]
    blind_value_proof: Option<String>,
    #[serde(default)]
    blind_asset_proof: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PaymentCommitments {
    asset: String,
    value: String,
}

#[derive(Deserialize)]
struct DecodedTransaction {
    txid: String,
}

#[derive(Deserialize)]
struct DecodedScript {
    hex: String,
}

async fn prepare_transfer_pset(
    wallet: &WalletRpc,
    destination: &str,
    script: &str,
    blinding_pubkey: &str,
    asset: &str,
    amount: serde_json::Number,
    amount_atoms: u64,
) -> Result<String, Error> {
    let mut output = Map::new();
    output.insert(destination.to_owned(), Value::Number(amount));
    output.insert("asset".into(), Value::String(asset.to_owned()));
    let funded: FundedPset = wallet
        .call(
            "walletcreatefundedpsbt",
            json!([
                [],
                [Value::Object(output)],
                0,
                { "include_explicit": true },
                false,
                2
            ]),
        )
        .await?;
    require_pset_text(&funded.psbt)?;
    let decoded: DecodedPset = wallet.call("decodepsbt", json!([funded.psbt])).await?;
    require_funded_pset_payment(&decoded, script, blinding_pubkey, asset, amount_atoms)?;
    Ok(funded.psbt)
}

async fn process_transfer_pset(
    wallet: &WalletRpc,
    funded: &str,
    script: &str,
    blinding_pubkey: &str,
    asset: &str,
    amount_atoms: u64,
) -> Result<(String, PaymentCommitments), Error> {
    let processed: ProcessedPset = wallet
        .call(
            "walletprocesspsbt",
            json!([funded, true, "ALL", false, true]),
        )
        .await?;
    if !processed.complete {
        return Err(Error::Wallet(
            "wallet did not completely sign the transfer PSET".into(),
        ));
    }
    require_pset_text(&processed.psbt)?;
    let decoded: DecodedPset = wallet.call("decodepsbt", json!([processed.psbt])).await?;
    let commitments =
        require_processed_pset_payment(&decoded, script, blinding_pubkey, asset, amount_atoms)?;
    Ok((processed.psbt, commitments))
}

async fn finalize_transfer_pset(
    wallet: &WalletRpc,
    processed: &str,
    script: &str,
    expected: &PaymentCommitments,
) -> Result<(String, DecodedTransaction), Error> {
    let finalized: FinalizedPset = wallet
        .call("finalizepsbt", json!([processed, true]))
        .await?;
    let raw = finalized
        .hex
        .filter(|value| finalized.complete && canonical_hex(value) && !value.is_empty())
        .ok_or_else(|| Error::Wallet("wallet did not finalize the signed transfer PSET".into()))?;
    let decoded = decode_finalized_transaction(&raw, script, expected)?;
    Ok((raw, decoded))
}

fn require_pset_text(pset: &str) -> Result<(), Error> {
    if pset.is_empty()
        || pset.len() > MAX_RESPONSE_BYTES
        || pset.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric() && byte != b'+' && byte != b'/' && byte != b'='
        })
    {
        return Err(Error::TransferMismatch);
    }
    Ok(())
}

fn pset_payment<'a>(
    decoded: &'a DecodedPset,
    script: &str,
) -> Result<&'a DecodedPsetOutput, Error> {
    if decoded.psbt_version != 2
        || decoded.input_count == 0
        || decoded.output_count as usize != decoded.outputs.len()
    {
        return Err(Error::TransferMismatch);
    }
    let matching: Vec<&DecodedPsetOutput> = decoded
        .outputs
        .iter()
        .filter(|output| {
            output
                .script
                .as_ref()
                .is_some_and(|value| value.hex == script)
        })
        .collect();
    if matching.len() != 1 {
        return Err(Error::TransferMismatch);
    }
    Ok(matching[0])
}

fn require_exact_pset_fields(
    output: &DecodedPsetOutput,
    blinding_pubkey: &str,
    asset: &str,
    amount_atoms: u64,
) -> Result<(), Error> {
    if output.asset.as_deref() != Some(asset)
        || output.blinding_pubkey.as_deref() != Some(blinding_pubkey)
        || output
            .amount
            .as_ref()
            .and_then(json_amount_atoms)
            .filter(|amount| *amount == amount_atoms)
            .is_none()
    {
        return Err(Error::TransferMismatch);
    }
    Ok(())
}

fn require_funded_pset_payment(
    decoded: &DecodedPset,
    script: &str,
    blinding_pubkey: &str,
    asset: &str,
    amount_atoms: u64,
) -> Result<(), Error> {
    let output = pset_payment(decoded, script)?;
    require_exact_pset_fields(output, blinding_pubkey, asset, amount_atoms)?;
    if output.status.as_deref() != Some("needs blinding")
        || output.value_commitment.is_some()
        || output.asset_commitment.is_some()
        || output.blind_value_proof.is_some()
        || output.blind_asset_proof.is_some()
    {
        return Err(Error::TransferMismatch);
    }
    Ok(())
}

fn require_processed_pset_payment(
    decoded: &DecodedPset,
    script: &str,
    blinding_pubkey: &str,
    asset: &str,
    amount_atoms: u64,
) -> Result<PaymentCommitments, Error> {
    let output = pset_payment(decoded, script)?;
    require_exact_pset_fields(output, blinding_pubkey, asset, amount_atoms)?;
    if output.status.is_some() {
        return Err(Error::TransferMismatch);
    }
    let asset_commitment = output
        .asset_commitment
        .as_deref()
        .filter(|value| value.len() == 66 && canonical_hex(value))
        .ok_or(Error::TransferMismatch)?;
    let value_commitment = output
        .value_commitment
        .as_deref()
        .filter(|value| value.len() == 66 && canonical_hex(value))
        .ok_or(Error::TransferMismatch)?;
    let value_proof = output
        .blind_value_proof
        .as_deref()
        .filter(|value| canonical_hex(value) && !value.is_empty())
        .ok_or(Error::TransferMismatch)?;
    let asset_proof = output
        .blind_asset_proof
        .as_deref()
        .filter(|value| canonical_hex(value) && !value.is_empty())
        .ok_or(Error::TransferMismatch)?;
    // Wallet RPC does not reveal raw blinders. Equal commitments elsewhere in
    // the same PSET are nevertheless direct evidence that the protected
    // payment commitment was reused, so fail before signing/finalization.
    if decoded
        .outputs
        .iter()
        .filter(|candidate| candidate.asset_commitment.as_deref() == Some(asset_commitment))
        .count()
        != 1
        || decoded
            .outputs
            .iter()
            .filter(|candidate| candidate.value_commitment.as_deref() == Some(value_commitment))
            .count()
            != 1
    {
        return Err(Error::TransferMismatch);
    }
    verify_explicit_payment_proofs(
        asset,
        amount_atoms,
        asset_commitment,
        value_commitment,
        asset_proof,
        value_proof,
    )?;
    Ok(PaymentCommitments {
        asset: asset_commitment.to_owned(),
        value: value_commitment.to_owned(),
    })
}

fn verify_explicit_payment_proofs(
    asset: &str,
    amount_atoms: u64,
    asset_commitment: &str,
    value_commitment: &str,
    asset_proof: &str,
    value_proof: &str,
) -> Result<(), Error> {
    let asset_id = AssetId::from_str(asset).map_err(|_| Error::TransferMismatch)?;
    let committed_asset =
        Generator::from_slice(&hex::decode(asset_commitment).map_err(|_| Error::TransferMismatch)?)
            .map_err(|_| Error::TransferMismatch)?;
    let committed_value = PedersenCommitment::from_slice(
        &hex::decode(value_commitment).map_err(|_| Error::TransferMismatch)?,
    )
    .map_err(|_| Error::TransferMismatch)?;
    let value_proof =
        RangeProof::from_slice(&hex::decode(value_proof).map_err(|_| Error::TransferMismatch)?)
            .map_err(|_| Error::TransferMismatch)?;
    let asset_proof = SurjectionProof::from_slice(
        &hex::decode(asset_proof).map_err(|_| Error::TransferMismatch)?,
    )
    .map_err(|_| Error::TransferMismatch)?;
    let signing = ZkpSecp256k1::signing_only();
    let explicit_asset = Generator::new_unblinded(&signing, asset_id.into_tag());
    let zero_value_commitment = PedersenCommitment::new(
        &signing,
        amount_atoms,
        secp256k1_zkp::ZERO_TWEAK,
        committed_asset,
    );
    if committed_asset.serialize() == explicit_asset.serialize()
        || committed_value.serialize() == zero_value_commitment.serialize()
    {
        return Err(Error::TransferMismatch);
    }
    let secp = ZkpSecp256k1::verification_only();
    let range = value_proof
        .verify(&secp, committed_value, &[], committed_asset)
        .map_err(|_| Error::TransferMismatch)?;
    let exact_end = amount_atoms.checked_add(1).ok_or(Error::TransferMismatch)?;
    if range.start != amount_atoms
        || range.end != exact_end
        || !asset_proof.verify(&secp, committed_asset, &[explicit_asset])
    {
        return Err(Error::TransferMismatch);
    }
    Ok(())
}

fn decode_finalized_transaction(
    raw: &str,
    script: &str,
    expected: &PaymentCommitments,
) -> Result<DecodedTransaction, Error> {
    let raw_bytes = hex::decode(raw).map_err(|_| Error::TransferMismatch)?;
    let transaction: elements::Transaction =
        elements::encode::deserialize(&raw_bytes).map_err(|_| Error::TransferMismatch)?;
    if transaction.input.is_empty() {
        return Err(Error::TransferMismatch);
    }
    let matching: Vec<&elements::TxOut> = transaction
        .output
        .iter()
        .filter(|output| hex::encode(output.script_pubkey.as_bytes()) == script)
        .collect();
    if matching.len() != 1 {
        return Err(Error::TransferMismatch);
    }
    let output = matching[0];
    let actual_asset = match output.asset {
        elements::confidential::Asset::Confidential(value) => value.to_string(),
        _ => return Err(Error::TransferMismatch),
    };
    let actual_value = match output.value {
        elements::confidential::Value::Confidential(value) => value.to_string(),
        _ => return Err(Error::TransferMismatch),
    };
    if actual_asset != expected.asset || actual_value != expected.value {
        return Err(Error::TransferMismatch);
    }
    Ok(DecodedTransaction {
        txid: transaction.txid().to_string(),
    })
}

fn atoms_json_number(atoms: u64) -> Result<serde_json::Number, Error> {
    let text = format!("{}.{:08}", atoms / 100_000_000, atoms % 100_000_000);
    serde_json::Number::from_str(&text)
        .map_err(|_| Error::Configuration("amount cannot be encoded exactly".into()))
}

fn json_amount_atoms(value: &Value) -> Option<u64> {
    let text = value.to_string();
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    if whole.starts_with('-') || fraction.len() > 8 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    let fraction: u64 = format!("{fraction:0<8}").parse().ok()?;
    whole.checked_mul(100_000_000)?.checked_add(fraction)
}

fn canonical_hex(value: &str) -> bool {
    value.len() % 2 == 0
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_txid(value: &str) -> bool {
    value.len() == 64 && canonical_hex(value)
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "bin/ecx-bond-v2-genesis-materialize.rs"]
mod genesis_materializer_test_bridge;

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use secp256k1_zkp::{SecretKey as ZkpSecretKey, Tweak, ZERO_TWEAK};

    use super::*;

    const DESTINATION: &str = "el1qqmockconfidentialdestination";
    const SCRIPT: &str = "00141111111111111111111111111111111111111111";
    const BLINDING_KEY: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ASSET: &str = "abababababababababababababababababababababababababababababababab";

    pub(crate) fn frozen_configuration_fixture() -> FrozenConfigurationV2 {
        use ecx_protocol_core::{
            bond_inbox_redemption_staging_descriptor_commitment_v2, AvailabilityConfigV1,
            CentralMatcherConfigV1, FrozenConfigurationV1, HybridOracleConfigV1, RiskParams,
            TruthcoinAnchorDeploymentV1, TruthcoinAuthenticationConfigV1, UsddCheckpointConfigV1,
            BOND_INBOX_INCLUSION_BLOCKS_V2, BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
            BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
            BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
            BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
            BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
            BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
            BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2, BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
            BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2, ECX_USDD_MARKET,
            MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2, MAX_TRANSITION_ACTIONS, PRICE_SCALE,
            RECURSIVE_PROOF_MARKER_BYTES_V2, USDD_MAX_CHECKPOINT_AGE_SECONDS,
        };

        let matcher_secret = SecretKey::from_slice(&[31; 32]).expect("matcher secret");
        let matcher_keypair = Keypair::from_secret_key(&Secp256k1::new(), &matcher_secret);
        let (matcher_signer, _) = XOnlyPublicKey::from_keypair(&matcher_keypair);
        let process_cmr = [0x30; 32];
        let refund_cmr = [0x32; 32];
        let staging_template = bond_inbox_redemption_staging_descriptor_commitment_v2(
            BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
            process_cmr,
            refund_cmr,
        )
        .expect("V18 staging descriptor");
        let configuration = FrozenConfigurationV2 {
            version: FrozenConfigurationV2::VERSION,
            base: FrozenConfigurationV1 {
                version: FrozenConfigurationV1::VERSION,
                chain_id: [0xcc; 32],
                market: ECX_USDD_MARKET,
                ecx_asset_id: [0x61; 32],
                usdd_asset_id: [0x65; 32],
                policy_asset_id: [0x62; 32],
                state_authority_asset_id: [0x63; 32],
                usdd_checkpoint: UsddCheckpointConfigV1 {
                    version: UsddCheckpointConfigV1::VERSION,
                    ethereum_light_client_configuration_hash: [0x24; 32],
                    authority_configuration_hash: [0x25; 32],
                    maximum_checkpoint_age_seconds: USDD_MAX_CHECKPOINT_AGE_SECONDS,
                },
                risk: RiskParams::default(),
                availability: AvailabilityConfigV1 {
                    version: AvailabilityConfigV1::VERSION,
                    scheme_hash: availability_scheme_hash(),
                    custodian_registry_hash: [0x6a; 32],
                    recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
                    custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
                    maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
                },
                truthcoin_authentication: TruthcoinAuthenticationConfigV1 {
                    version: TruthcoinAuthenticationConfigV1::VERSION,
                    source_git_commit_sha1: [1; 20],
                    consensus_source_manifest_sha256: [0x18; 32],
                    source_patch_manifest_sha256: [0x23; 32],
                    sidechain_number: 13,
                    bitcoin_checkpoint_hash: [0x16; 32],
                    bitcoin_checkpoint_height: 100,
                    bip300_checkpoint_state_hash: [0x24; 32],
                    genesis_sidechain_block_hash: [0x17; 32],
                    truthcoin_chain_id: [6; 32],
                    truthcoin_branch_id: [7; 32],
                    btc_usd_template_hash: [8; 32],
                    lmsr_math_commitment: [9; 32],
                    source_proof_program_id: [0x14; 32],
                    selection_rule_hash: [0x15; 32],
                    minimum_bitcoin_confirmations: 6,
                    maximum_proof_bytes: 1_024,
                },
                truthcoin_anchor_deployment: TruthcoinAnchorDeploymentV1 {
                    version: TruthcoinAnchorDeploymentV1::VERSION,
                    authority_asset_id: [0x21; 32],
                    authority_amount: 1,
                    script_tree_configuration_hash: [0x22; 32],
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
                    maximum_lmsr_weight_ppm: 1_000_000,
                    initial_anchor_band_bps: 100,
                    maximum_anchor_band_bps: 2_000,
                    risk_haircut_bps: 100,
                    boundary_guard_ppb: 10_000,
                    maximum_unanchored_deviation_bps: 5_000,
                    ecx_satoshis_per_coin: 1_000,
                    usdd_usd_price_units: PRICE_SCALE,
                },
                matcher: CentralMatcherConfigV1 {
                    version: CentralMatcherConfigV1::VERSION,
                    key_epoch: 0,
                    signer: XOnlyKey(matcher_signer.serialize()),
                    genesis_sequence: 0,
                    genesis_receipt_hash: [0x10; 32],
                    forced_inclusion_blocks: 6,
                },
                forced_action_domain: [0x11; 32],
                deposit_inbox_domain: [0x12; 32],
                collateral_vault_script_sha256: [0x64; 32],
                maximum_transition_actions: MAX_TRANSITION_ACTIONS,
            },
            collateral_vault_covenant_cmr: [0xd0; 32],
            bond_asset_id: [0x77; 32],
            bond_deployment_commitment: [0x88; 32],
            bond_inventory_script_sha256: [0x70; 32],
            bond_redemption_queue_script_sha256: [0x68; 32],
            bond_inbox_redemption_staging_template_commitment: staging_template,
            bond_inbox_redemption_staging_renderer_domain:
                BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            bond_inbox_redemption_staging_internal_key:
                BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2,
            bond_inbox_redemption_staging_tapleaf_version:
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            bond_inbox_redemption_staging_process_cmr: process_cmr,
            bond_inbox_redemption_staging_refund_cmr: refund_cmr,
            bond_inbox_refund_minimum_parent_blocks: BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2,
            insurance_reserve_script_sha256: [0x67; 32],
            insurance_reserve_covenant_cmr: [0xd1; 32],
            destroyed_reissuance_token_script_sha256: [0x45; 32],
            bond_inbox_domain: [0x46; 32],
            bond_inbox_custody_receipt_codec_hash: custody_receipt_codec_hash_v1(),
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
            ecx_btc_conversion_program_id: [0x48; 32],
            usdd_usd_conversion_program_id: [0x49; 32],
            ecx_btc_redemption_covenant_commitment: [0x50; 32],
            ecx_btc_source_checkpoint_commitment: [0x51; 32],
            usdd_usd_redemption_covenant_commitment: [0x52; 32],
            usdd_usd_source_checkpoint_commitment: [0x53; 32],
            maximum_conversion_age_seconds: 3_600,
            maximum_conversion_proof_bytes: 1_024,
            recursive_proof_marker_bytes: RECURSIVE_PROOF_MARKER_BYTES_V2,
            fixed_supply_atoms: BOND_FIXED_SUPPLY_ATOMS,
            redemption_delay_parent_blocks: BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
        };
        configuration.validate().expect("valid V18 client fixture");
        configuration
    }

    fn configuration_hash_fixture() -> Hash32 {
        frozen_configuration_fixture().digest()
    }

    #[test]
    fn actual_genesis_materializer_preserves_checkpoint_state_on_later_creation() {
        crate::genesis_materializer_test_bridge::check_creation_independence(
            frozen_configuration_fixture(),
        );
    }

    fn action_profile_fixture() -> BondActionProfileV2 {
        BondActionProfileV2::from_configuration(&frozen_configuration_fixture())
    }

    fn sign_prepared_fixture(
        client: &BondActionClient,
        intent: &BondIntentV1,
        prepared: &PreparedBondActionV1,
        preflight: &AuthenticatedPreflight,
        secret: &SecretKey,
    ) -> Result<SignedActionV1, Error> {
        let configuration = frozen_configuration_fixture();
        let profile = BondActionProfileV2::from_configuration(&configuration);
        client.sign_prepared(
            intent,
            &prepared.prepared,
            PreparedSigningContext {
                preflight,
                profile: &profile,
                configuration: &configuration,
                source: &prepared.source,
            },
            secret,
        )
    }

    #[derive(Clone)]
    struct MockRpcState {
        steps: Arc<Mutex<VecDeque<MockRpcStep>>>,
        mismatch: Arc<Mutex<Option<String>>>,
    }

    struct MockRpcStep {
        method: &'static str,
        result: Value,
    }

    async fn mock_wallet_rpc(
        State(state): State<MockRpcState>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let step = state
            .steps
            .lock()
            .expect("mock RPC lock")
            .pop_front()
            .expect("unexpected wallet RPC call");
        let actual = request.get("method").and_then(Value::as_str).unwrap_or("");
        if actual != step.method {
            *state.mismatch.lock().expect("mock mismatch lock") = Some(format!(
                "expected wallet method {}, received {actual}",
                step.method
            ));
        }
        Json(json!({
            "jsonrpc": "2.0",
            "id": "ecx-bond-wallet",
            "result": step.result,
            "error": null
        }))
    }

    async fn mock_wallet(steps: Vec<MockRpcStep>) -> (WalletRpc, MockRpcState) {
        let state = MockRpcState {
            steps: Arc::new(Mutex::new(steps.into())),
            mismatch: Arc::new(Mutex::new(None)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock wallet RPC");
        let address = listener.local_addr().expect("mock wallet address");
        let app = Router::new()
            .route("/", post(mock_wallet_rpc))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock wallet RPC");
        });
        let wallet = WalletRpc::new(
            &format!("http://{address}"),
            None,
            None,
            Duration::from_secs(2),
        )
        .expect("mock wallet client");
        (wallet, state)
    }

    fn assert_mock_consumed(state: &MockRpcState) {
        assert!(
            state.steps.lock().expect("mock RPC lock").is_empty(),
            "not all expected wallet calls were consumed"
        );
        assert_eq!(*state.mismatch.lock().expect("mock mismatch lock"), None);
    }

    fn pset_output(amount_atoms: u64, asset: &str, status: Option<&str>) -> Value {
        let mut output = json!({
            "amount": Value::Number(atoms_json_number(amount_atoms).expect("amount")),
            "script": { "hex": SCRIPT },
            "asset": asset,
            "blinding_pubkey": BLINDING_KEY
        });
        if let Some(status) = status {
            output
                .as_object_mut()
                .expect("output object")
                .insert("status".into(), Value::String(status.into()));
        }
        output
    }

    fn decoded_pset(output: Value) -> Value {
        json!({
            "psbt_version": 2,
            "input_count": 1,
            "output_count": 1,
            "outputs": [output]
        })
    }

    fn exact_payment_proofs(amount_atoms: u64) -> (PaymentCommitments, String, String) {
        let asset_blinder = Tweak::from_slice(&[1_u8; 32]).expect("asset blinder");
        let value_blinder = Tweak::from_slice(&[2_u8; 32]).expect("value blinder");
        payment_proofs_with_blinders(amount_atoms, asset_blinder, value_blinder)
    }

    fn payment_proofs_with_blinders(
        amount_atoms: u64,
        asset_blinder: Tweak,
        value_blinder: Tweak,
    ) -> (PaymentCommitments, String, String) {
        let secp = ZkpSecp256k1::new();
        let asset = AssetId::from_str(ASSET).expect("asset id");
        let tag = asset.into_tag();
        let committed_asset = Generator::new_blinded(&secp, tag, asset_blinder);
        let committed_value =
            PedersenCommitment::new(&secp, amount_atoms, value_blinder, committed_asset);
        let range_proof = RangeProof::new(
            &secp,
            amount_atoms,
            committed_value,
            amount_atoms,
            value_blinder,
            &[],
            &[],
            ZkpSecretKey::from_slice(&[3_u8; 32]).expect("proof nonce"),
            -1,
            0,
            committed_asset,
        )
        .expect("exact value proof");
        let explicit_asset = Generator::new_unblinded(&secp, tag);
        let mut rng = StdRng::seed_from_u64(7);
        let asset_proof = SurjectionProof::new(
            &secp,
            &mut rng,
            tag,
            asset_blinder,
            &[(explicit_asset, tag, ZERO_TWEAK)],
        )
        .expect("exact asset proof");
        (
            PaymentCommitments {
                asset: hex::encode(committed_asset.serialize()),
                value: hex::encode(committed_value.serialize()),
            },
            hex::encode(asset_proof.serialize()),
            hex::encode(range_proof.serialize()),
        )
    }

    fn finalized_transaction(
        script: &str,
        commitments: &PaymentCommitments,
    ) -> elements::Transaction {
        let asset = Generator::from_slice(&hex::decode(&commitments.asset).expect("asset hex"))
            .expect("asset commitment");
        let value =
            PedersenCommitment::from_slice(&hex::decode(&commitments.value).expect("value hex"))
                .expect("value commitment");
        elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()],
            output: vec![elements::TxOut {
                asset: elements::confidential::Asset::Confidential(asset),
                value: elements::confidential::Value::Confidential(value),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: elements::Script::from(hex::decode(script).expect("script hex")),
                witness: elements::TxOutWitness::default(),
            }],
        }
    }

    async fn serve_router(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP fixture");
        let address = listener.local_addr().expect("HTTP fixture address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve HTTP fixture");
        });
        format!("http://{address}")
    }

    fn capital_fixture() -> CapitalSnapshotV2 {
        CapitalSnapshotV2 {
            version: CapitalSnapshotV2::VERSION,
            exchange_state_root: [0x22; 32],
            configuration_hash: configuration_hash_fixture(),
            bond_asset_id: [0x77; 32],
            bond_deployment_commitment: [0x88; 32],
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
            covenant_state_hash: [0xa1; 32],
            bond_state_root: [0xa2; 32],
            funding_state_root: [0xa3; 32],
            insurance_reserve_quote_units: 125,
            outstanding_bond_units: 100,
            nav_quote_units_per_bond: 125_000_000,
            deficit_quote_units: 100,
            target_reserve_quote_units: 125,
            coverage_bps: 12_500,
            mode: CapitalMode::Normal,
            minimum_authenticated_price: 1,
            maximum_authenticated_price: 10,
            funding_epoch: 7,
            funding_rate_ppm: 0,
            redemption_queue_root: [0xbb; 32],
            redemption_head: 0,
            redemption_tail: 0,
            queued_redemption_bond_units: 0,
            oracle: ecx_matcher::OracleSnapshotV2 {
                certificate_hash: [0xa4; 32],
                valid_through_parent_mtp: 2_000,
                mode: ecx_matcher::OracleModeV2::Normal,
            },
            encrypted_availability_root: [0xa5; 32],
            bond_inbox: ecx_matcher::BondInboxSnapshotV2 {
                head_root: [0xa6; 32],
                entry_count: 0,
                processed_root: [0xa6; 32],
                processed_cursor: 0,
                outcome_root: [0xa7; 32],
                outcome_count: 0,
                node_verified_source_head_root: [0xa6; 32],
                node_verified_source_entry_count: 0,
            },
            matcher_execution: ecx_matcher::MatcherExecutionSnapshotV2 {
                receipt_batch_root: [0xa8; 32],
                previous_sequence: 0,
                sequence: 0,
            },
            last_transition_sidechain_height: 9,
            legacy_fee_pool_quote_units: 0,
        }
    }

    fn context_fixture() -> ElementsConsensusContextV2 {
        ElementsConsensusContextV2 {
            sidechain_height: 10,
            sidechain_block_hash: [0x11; 32],
            exchange_state_root: [0x22; 32],
            forced_inbox_head_root: [0x33; 32],
            forced_inbox_entry_count: 0,
            forced_inbox_processed_cursor: 0,
            deposit_inbox_head_root: [0x44; 32],
            deposit_inbox_entry_count: 0,
            deposit_inbox_processed_cursor: 0,
            parent_height: 100,
            parent_mtp: 1_000,
            parent_block_hash: [0x55; 32],
            source_parent_height: 100,
            capital_snapshot: Some(capital_fixture()),
        }
    }

    fn producer_status_fixture() -> ProducerStatusV1 {
        ProducerStatusV1 {
            version: API_VERSION,
            ready: true,
            private_local: true,
            chain_id: [0xcc; 32],
            context: context_fixture(),
            proof_backend: "sp1-groth16".into(),
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
            proof_inputs_ready: true,
            covenant_frozen: true,
            wallet_ready: true,
            broadcaster_ready: true,
            configuration: frozen_configuration_fixture(),
            action_profile: action_profile_fixture(),
        }
    }

    fn client_config_fixture(producer_url: &str) -> ClientConfig {
        ClientConfig::new(
            "http://127.0.0.1:1",
            producer_url,
            "http://127.0.0.1:3",
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(1),
        )
        .expect("bond client fixture")
    }

    fn node_context_json() -> Value {
        json!({
            "sidechainheight": 10,
            "sidechainblockhash": "11".repeat(32),
            "exchangestateroot": "22".repeat(32),
            "forcedinbox": {
                "headroot": "33".repeat(32),
                "entrycount": 0,
                "nextindex": 0,
                "processedcursor": 0
            },
            "depositinbox": {
                "headroot": "44".repeat(32),
                "entrycount": 0,
                "nextindex": 0,
                "processedcursor": 0
            },
            "bmm": {
                "authenticated": true,
                "parentheight": 100,
                "parentmtp": 1_000,
                "parentblockhash": "55".repeat(32)
            },
            "sourceparentheight": 100,
            "sourcebacklogoldestparentheight": 0,
            "capital": {
                "version": CapitalSnapshotV2::VERSION,
                "proofprofile": "finite-v18",
                "exchangestateroot": "22".repeat(32),
                "configurationhash": hex::encode(configuration_hash_fixture()),
                "bondactionconfigurationhash": hex::encode(configuration_hash_fixture()),
                "bondassetid": "77".repeat(32),
                "bonddeploymentcommitment": "88".repeat(32),
                "transitionprogramid": "99".repeat(32),
                "transitioncmr": "aa".repeat(32),
                "covenantstatehash": "a1".repeat(32),
                "bondstateroot": "a2".repeat(32),
                "fundingstateroot": "a3".repeat(32),
                "bondinventorycovenanthash": "a9".repeat(32),
                "insurancereservequoteunits": 125,
                "issuedbondunits": ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS,
                "outstandingbondunits": 100,
                "inventorybondunits": ecx_protocol_core::BOND_FIXED_SUPPLY_ATOMS - 100,
                "navquoteunitsperbond": 125_000_000,
                "deficitquoteunits": 100,
                "targetreservequoteunits": 125,
                "coveragebps": 12_500,
                "controlledquoteunits": 125,
                "mode": "Normal",
                "minimumauthenticatedprice": 1,
                "maximumauthenticatedprice": 10,
                "fundingepoch": 7,
                "fundingrateppm": 0,
                "globalfundingindexnumerator": 0,
                "redemptionqueueroot": "bb".repeat(32),
                "redemptionhead": 0,
                "redemptiontail": 0,
                "queuedredemptionbondunits": 0,
                "oracle": {
                    "certificatehash": "a4".repeat(32),
                    "validthroughparentmtp": 2_000,
                    "mode": "Normal"
                },
                "encryptedavailabilityroot": "a5".repeat(32),
                "bondinbox": {
                    "headroot": "a6".repeat(32),
                    "entrycount": 0,
                    "processedroot": "a6".repeat(32),
                    "processedcursor": 0,
                    "outcomeroot": "a7".repeat(32),
                    "outcomecount": 0,
                    "nodeverifiedsourceheadroot": "a6".repeat(32),
                    "nodeverifiedsourceentrycount": 0
                },
                "matcherexecution": {
                    "receiptbatchroot": "a8".repeat(32),
                    "previoussequence": 0,
                    "sequence": 0
                },
                "lasttransitionsidechainheight": 9,
                "operationallysafe": true,
                "legacyfeepoolquoteunits": 0
            }
        })
    }

    async fn mock_node_rpc(Json(request): Json<Value>) -> Json<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let result = match request.get("method").and_then(Value::as_str) {
            Some("getecxconsensuscontext") => node_context_json(),
            _ => Value::Null,
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
            "error": null
        }))
    }

    fn health_fixture() -> HealthView {
        HealthView {
            status: "ok".into(),
            market: "ECX/USDD".into(),
            mode: "live".into(),
            chain_height: 10,
            sequence: 0,
            privacy: "confidential".into(),
            matcher_mode: "primary".into(),
            matcher_signer: "test".into(),
            chain_id: "cc".repeat(32),
            matcher_sequence: 0,
            matcher_receipt_hash: "00".repeat(32),
            capital_controls_v2: true,
            capital_mode: Some(CapitalMode::Normal),
            capital_authenticated: true,
        }
    }

    fn reduce_only_capital_fixture() -> CapitalSnapshotV2 {
        let mut capital = capital_fixture();
        capital.insurance_reserve_quote_units = 110;
        capital.nav_quote_units_per_bond = 110_000_000;
        capital.coverage_bps = 11_000;
        capital.mode = CapitalMode::ReduceOnly;
        capital
    }

    fn reduce_only_node_context_json() -> Value {
        let mut context = node_context_json();
        context["capital"]["insurancereservequoteunits"] = json!(110);
        context["capital"]["navquoteunitsperbond"] = json!(110_000_000);
        context["capital"]["coveragebps"] = json!(11_000);
        context["capital"]["mode"] = json!("ReduceOnly");
        context
    }

    async fn mock_reduce_only_node_rpc(Json(request): Json<Value>) -> Json<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let result = match request.get("method").and_then(Value::as_str) {
            Some("getecxconsensuscontext") => reduce_only_node_context_json(),
            _ => Value::Null,
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
            "error": null
        }))
    }

    #[derive(Clone)]
    struct MockProducerState {
        prepared: PreparedBondActionV1,
        expected_action: BondSubscriptionV2,
    }

    async fn mock_prepare(
        State(state): State<MockProducerState>,
        Json(request): Json<PrepareRequestV1>,
    ) -> Json<PreparedBondActionV1> {
        assert_eq!(request.version, API_VERSION);
        assert_eq!(request.expected_chain_id, [0xcc; 32]);
        assert_eq!(request.observed_context, context_fixture());
        assert_eq!(request.signer, state.expected_action.trader);
        assert!(matches!(
            request.intent,
            BondIntentV1::Subscription {
                contribution_usdd_atoms: 100,
                recipient_script_sha256
            } if recipient_script_sha256 == [0xdd; 32]
        ));
        Json(state.prepared)
    }

    fn subscription_preparation(secret: &SecretKey) -> (PreparedBondActionV1, BondSubscriptionV2) {
        let mut action = BondSubscriptionV2 {
            version: BondSubscriptionV2::VERSION,
            chain_id: [0xcc; 32],
            configuration_hash: configuration_hash_fixture(),
            trader: signer(secret),
            account_nonce: 9,
            contribution_usdd_atoms: 100,
            issued_share_atoms: 80,
            bond_recipient_script_sha256: [0xdd; 32],
            usdd_output_opening_commitment: [0; 32],
            bond_output_opening_commitment: [0; 32],
        };
        let subscription_id = action.subscription_id();
        let usdd_output = CollateralOutputOpeningV2 {
            output_index: 3,
            amount: 100,
            asset_blinding_factor: [1; 32],
            value_blinding_factor: [2; 32],
            role: CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id },
        };
        let bond_output = BondOutputOpeningV2 {
            output_index: 4,
            amount: 80,
            asset_blinding_factor: [3; 32],
            value_blinding_factor: [4; 32],
            role: BondOutputRoleV2::Subscription {
                subscription_id,
                recipient_script_sha256: [0xdd; 32],
            },
        };
        action.usdd_output_opening_commitment =
            subscription_usdd_output_commitment(&usdd_output, &action_profile_fixture())
                .expect("USDD opening commitment");
        action.bond_output_opening_commitment =
            subscription_bond_output_commitment(&bond_output, &action_profile_fixture())
                .expect("bond opening commitment");
        (
            PreparedBondActionV1 {
                version: API_VERSION,
                preparation_id: [0xf2; 32],
                expected_chain_id: [0xcc; 32],
                observed_context: context_fixture(),
                expires_at_sidechain_height: 15,
                settlement_template_sha256: [0xf1; 32],
                source: BondInboxSourcePreparationV2 {
                    marker_vout: 1,
                    staging_vout: u32::MAX,
                    exact_serialized_staging_txout: Vec::new(),
                },
                prepared: PreparedActionV1::Subscription {
                    action: action.clone(),
                    usdd_output,
                    bond_output,
                },
            },
            action,
        )
    }

    fn enqueue_preparation(secret: &SecretKey) -> PreparedBondActionV1 {
        use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
        use elements::secp256k1_zkp::{
            PublicKey as ElementsPublicKey, SecretKey as ElementsSecret,
        };
        use elements::TxOutSecrets;

        let configuration = frozen_configuration_fixture();
        let profile = BondActionProfileV2::from_configuration(&configuration);
        let claimant = signer(secret);
        let destination_script_sha256 = [0x91; 32];
        let holder_script_sha256 = [0x92; 32];
        let mut action = RedemptionEnqueueV2 {
            version: RedemptionEnqueueV2::VERSION,
            chain_id: configuration.base.chain_id,
            configuration_hash: configuration.digest(),
            claimant,
            account_nonce: 11,
            requested_share_atoms: 100,
            destination_script_hash: destination_script_sha256,
            holder_script_sha256,
            intent_salt: [0x93; 32],
            refund_script_sha256: holder_script_sha256,
            // parent 100 + frozen inclusion window 6 + refund window 12
            refund_not_before_parent_height: 118,
            bond_input_opening_commitment: [0; 32],
            queue_output_opening_commitment: [0; 32],
        };
        let stable_intent_id = action.stable_intent_id();
        let staging_vout = 2;
        let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
            chain_id: action.chain_id,
            configuration_hash: action.configuration_hash,
            marker_signer: action.claimant,
            stable_intent_id,
            staging_vout,
            refund_script_sha256: action.refund_script_sha256,
            refund_not_before_parent_height: action.refund_not_before_parent_height,
        };
        let staging_script = ecx_elements_settlement::bond_inbox_redemption_staging_script_v2(
            &configuration,
            renderer_input,
        )
        .unwrap();
        let staging_script_sha256 =
            bond_inbox_redemption_staging_script_sha256_v2(&configuration, renderer_input).unwrap();
        let asset_id = AssetId::from_byte_array(configuration.bond_asset_id);
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(18);
        let receiver_secret = ElementsSecret::from_slice(&[0x41; 32]).unwrap();
        let receiver_public = ElementsPublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = ElementsSecret::from_slice(&[0x42; 32]).unwrap();
        let staging_txout = elements::TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            staging_script,
            receiver_public,
            ephemeral_secret,
            TxOutSecrets::new(
                asset_id,
                AssetBlindingFactor::from_slice(&[0x43; 32]).unwrap(),
                100,
                ValueBlindingFactor::from_slice(&[0x44; 32]).unwrap(),
            ),
            &[TxOutSecrets::new(
                asset_id,
                AssetBlindingFactor::zero(),
                100,
                ValueBlindingFactor::zero(),
            )],
        )
        .unwrap();
        let claimant_commitment = action.claimant_commitment();
        let bond_input = BondInputOpeningV2 {
            input_index: 2,
            previous_transaction: vec![0xa0],
            previous_vout: staging_vout,
            amount: 100,
            asset_blinding_factor: [0x43; 32],
            value_blinding_factor: [0x44; 32],
            role: BondInputRoleV2::StagedRedemptionEnqueue {
                redemption_id: [0x94; 32],
                staging_intent_id: stable_intent_id,
                claimant: claimant_commitment,
                staging_script_sha256,
                source_txid: [0x95; 32],
                source_vout: staging_vout,
            },
        };
        let queue_output = BondOutputOpeningV2 {
            output_index: 3,
            amount: 100,
            asset_blinding_factor: [0x45; 32],
            value_blinding_factor: [0x46; 32],
            role: BondOutputRoleV2::QueuedRedemptionEntry {
                redemption_id: [0x94; 32],
                staging_intent_id: stable_intent_id,
                claimant: claimant_commitment,
                destination_script_sha256,
            },
        };
        action.bond_input_opening_commitment =
            redemption_enqueue_bond_input_commitment(&bond_input, &profile).unwrap();
        action.queue_output_opening_commitment =
            redemption_enqueue_queue_output_commitment(&queue_output, &profile).unwrap();
        PreparedBondActionV1 {
            version: API_VERSION,
            preparation_id: [0x96; 32],
            expected_chain_id: configuration.base.chain_id,
            observed_context: context_fixture(),
            expires_at_sidechain_height: 15,
            settlement_template_sha256: [0x97; 32],
            source: BondInboxSourcePreparationV2 {
                marker_vout: 1,
                staging_vout,
                exact_serialized_staging_txout: elements::encode::serialize(&staging_txout),
            },
            prepared: PreparedActionV1::EnqueueRedemption {
                action,
                bond_input,
                queue_output,
            },
        }
    }

    fn recapitalization_preparation(
        secret: &SecretKey,
    ) -> (
        PreparedBondActionV1,
        InsuranceRecapitalizationContributionV2,
    ) {
        let mut action = InsuranceRecapitalizationContributionV2 {
            version: InsuranceRecapitalizationContributionV2::VERSION,
            chain_id: [0xcc; 32],
            configuration_hash: configuration_hash_fixture(),
            contributor: signer(secret),
            account_nonce: 10,
            contribution_usdd_atoms: 100,
            insurance_output_opening_commitment: [0; 32],
            issued_share_atoms: 0,
            bond_output_opening_commitment: [0; 32],
        };
        let insurance_output = CollateralOutputOpeningV2 {
            output_index: 3,
            amount: 100,
            asset_blinding_factor: [5; 32],
            value_blinding_factor: [6; 32],
            role: CollateralOutputRoleV2::InsuranceRecapitalizationContribution {
                contribution_id: action.contribution_id(),
            },
        };
        action.insurance_output_opening_commitment =
            recapitalization_usdd_output_commitment(&insurance_output, &action_profile_fixture())
                .expect("recapitalization opening commitment");
        (
            PreparedBondActionV1 {
                version: API_VERSION,
                preparation_id: [0xf3; 32],
                expected_chain_id: [0xcc; 32],
                observed_context: context_fixture(),
                expires_at_sidechain_height: 15,
                settlement_template_sha256: [0xf4; 32],
                source: BondInboxSourcePreparationV2 {
                    marker_vout: 1,
                    staging_vout: u32::MAX,
                    exact_serialized_staging_txout: Vec::new(),
                },
                prepared: PreparedActionV1::InsuranceRecapitalization {
                    action: action.clone(),
                    insurance_output,
                },
            },
            action,
        )
    }

    #[test]
    fn urls_and_hashes_are_fail_closed() {
        assert!(endpoint("http://127.0.0.1:8088", "matcher").is_ok());
        assert!(endpoint("http://example.com", "matcher").is_err());
        assert!(endpoint("https://example.com/?token=x", "matcher").is_err());
        assert!(hash32(&"ab".repeat(32), "hash").is_ok());
        assert!(hash32(&"AB".repeat(32), "hash").is_err());
        assert!(hash32(&"00".repeat(32), "hash").is_ok());
    }

    #[test]
    fn errors_have_stable_machine_classification() {
        let error = Error::ProducerUnavailable("offline".into());
        assert_eq!(error.code(), "transition_producer_unavailable");
        assert_eq!(error.stage(), "producer_preflight");
        assert!(error.retryable());
        assert!(!Error::UnverifiedBroadcast.retryable());
    }

    async fn require_status_fixture(status: ProducerStatusV1) -> Result<ProducerStatusV1, Error> {
        let producer_url = serve_router(Router::new().route(
            "/v3/bond/status",
            get(move || {
                let status = status.clone();
                async move { Json(status) }
            }),
        ))
        .await;
        BondActionClient::new(client_config_fixture(&producer_url))
            .require_producer_ready(&AuthenticatedPreflight {
                capital: capital_fixture(),
                context: context_fixture(),
            })
            .await
    }

    #[tokio::test]
    async fn v18_status_requires_api_v3_full_configuration_and_local_profile_before_prepare() {
        require_status_fixture(producer_status_fixture())
            .await
            .expect("canonical V18 pre-sign status");

        let mut old_api = producer_status_fixture();
        old_api.version = 2;
        assert!(matches!(
            require_status_fixture(old_api).await,
            Err(Error::ProducerNotReady(_))
        ));

        let mut late_substitution = producer_status_fixture();
        late_substitution
            .configuration
            .maximum_conversion_age_seconds += 1;
        late_substitution.action_profile =
            BondActionProfileV2::from_configuration(&late_substitution.configuration);
        assert!(matches!(
            require_status_fixture(late_substitution).await,
            Err(Error::Preparation(_))
        ));

        let mut known_key_bypass = producer_status_fixture();
        let secret = SecretKey::from_slice(&[44; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        known_key_bypass
            .configuration
            .bond_inbox_redemption_staging_internal_key =
            XOnlyPublicKey::from_keypair(&keypair).0.serialize();
        known_key_bypass.action_profile =
            BondActionProfileV2::from_configuration(&known_key_bypass.configuration);
        assert!(matches!(
            require_status_fixture(known_key_bypass).await,
            Err(Error::Preparation(_))
        ));

        let mut substituted_template = producer_status_fixture();
        substituted_template
            .configuration
            .bond_inbox_redemption_staging_template_commitment[0] ^= 1;
        substituted_template.action_profile =
            BondActionProfileV2::from_configuration(&substituted_template.configuration);
        assert!(matches!(
            require_status_fixture(substituted_template).await,
            Err(Error::Preparation(_))
        ));

        let mut producer_profile = producer_status_fixture();
        producer_profile
            .action_profile
            .redemption_staging_renderer_domain[0] ^= 1;
        assert!(matches!(
            require_status_fixture(producer_profile).await,
            Err(Error::ProducerNotReady(_))
        ));
    }

    #[tokio::test]
    async fn malicious_profile_is_rejected_before_prepare_submit_or_signature_release() {
        let node_url = serve_router(Router::new().route("/", post(mock_node_rpc))).await;
        let matcher_url = serve_router(
            Router::new()
                .route("/health", get(|| async { Json(health_fixture()) }))
                .route("/v2/capital", get(|| async { Json(capital_fixture()) })),
        )
        .await;
        let mut status = producer_status_fixture();
        status.action_profile.redemption_staging_template_commitment[0] ^= 1;
        let prepare_calls = Arc::new(AtomicUsize::new(0));
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let prepare_counter = Arc::clone(&prepare_calls);
        let submit_counter = Arc::clone(&submit_calls);
        let producer_url = serve_router(
            Router::new()
                .route(
                    "/v3/bond/status",
                    get(move || {
                        let status = status.clone();
                        async move { Json(status) }
                    }),
                )
                .route(
                    "/v3/bond/actions/prepare",
                    post(move || {
                        let counter = Arc::clone(&prepare_counter);
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            Json(json!({"unexpected": true}))
                        }
                    }),
                )
                .route(
                    "/v3/bond/actions/submit",
                    post(move || {
                        let counter = Arc::clone(&submit_counter);
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            Json(json!({"unexpected": true}))
                        }
                    }),
                ),
        )
        .await;
        let config = ClientConfig::new(
            &matcher_url,
            &producer_url,
            &node_url,
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(2),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("trader-key.json");
        fs::write(
            &key_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "role": "ecx_trader",
                "secret_key_hex": hex::encode([7_u8; 32]),
            }))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            BondActionClient::new(config)
                .subscribe(&key_path, 100)
                .await,
            Err(Error::ProducerNotReady(_))
        ));
        assert_eq!(prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(submit_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn v18_enqueue_signs_only_the_local_script_and_deterministic_refund_deadline() {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let prepared = enqueue_preparation(&secret);
        let intent = BondIntentV1::EnqueueRedemption {
            bond_share_atoms: 100,
            destination_script_sha256: [0x91; 32],
            holder_script_sha256: [0x92; 32],
        };
        let client = BondActionClient::new(client_config_fixture("http://127.0.0.1:2"));
        let preflight = AuthenticatedPreflight {
            capital: capital_fixture(),
            context: context_fixture(),
        };
        assert!(matches!(
            sign_prepared_fixture(&client, &intent, &prepared, &preflight, &secret),
            Ok(SignedActionV1::EnqueueRedemption { .. })
        ));

        let mut producer_delayed = prepared.clone();
        let PreparedActionV1::EnqueueRedemption { action, .. } = &mut producer_delayed.prepared
        else {
            panic!("enqueue fixture changed variant");
        };
        action.refund_not_before_parent_height += 1;
        assert!(matches!(
            sign_prepared_fixture(&client, &intent, &producer_delayed, &preflight, &secret),
            Err(Error::Preparation(message))
                if message.contains("producer-selected refund deadline")
        ));

        let mut substituted = prepared;
        let mut output: elements::TxOut =
            elements::encode::deserialize(&substituted.source.exact_serialized_staging_txout)
                .unwrap();
        output.script_pubkey = elements::Script::from(vec![0x51]);
        substituted.source.exact_serialized_staging_txout = elements::encode::serialize(&output);
        assert!(matches!(
            sign_prepared_fixture(&client, &intent, &substituted, &preflight, &secret),
            Err(Error::Preparation(message))
                if message.contains("locally rendered per-intent V18 script")
        ));
    }

    #[test]
    fn reduce_only_mode_allows_cancellation_but_rejects_enqueue() {
        let enqueue = BondIntentV1::EnqueueRedemption {
            bond_share_atoms: 1,
            destination_script_sha256: [1; 32],
            holder_script_sha256: [2; 32],
        };
        let cancellation = BondIntentV1::CancelRedemption {
            request_id: [3; 32],
            recipient_script_sha256: [4; 32],
        };
        assert!(matches!(
            validate_intent_capital_mode(CapitalMode::ReduceOnly, &enqueue),
            Err(Error::Preparation(_))
        ));
        validate_intent_capital_mode(CapitalMode::ReduceOnly, &cancellation)
            .expect("reduce-only cancellation remains permitted");
    }

    #[tokio::test]
    async fn reduce_only_enqueue_rejects_before_producer_nonce_or_broadcast() {
        let node_url =
            serve_router(Router::new().route("/", post(mock_reduce_only_node_rpc))).await;
        let matcher_url = serve_router(
            Router::new()
                .route(
                    "/health",
                    get(|| async {
                        let mut health = health_fixture();
                        health.capital_mode = Some(CapitalMode::ReduceOnly);
                        Json(health)
                    }),
                )
                .route(
                    "/v2/capital",
                    get(|| async { Json(reduce_only_capital_fixture()) }),
                ),
        )
        .await;
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&producer_calls);
        let producer_url = serve_router(Router::new().route(
            "/v3/bond/status",
            get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"unexpected": true}))
                }
            }),
        ))
        .await;

        let config = ClientConfig::new(
            &matcher_url,
            &producer_url,
            &node_url,
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(2),
        )
        .expect("bond client fixture");
        let directory = tempfile::tempdir().expect("key directory");
        let key_path = directory.path().join("trader-key.json");
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("trader secret");
        fs::write(
            &key_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "role": "ecx_trader",
                "secret_key_hex": hex::encode(secret.secret_bytes())
            }))
            .expect("key JSON"),
        )
        .expect("write key fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .expect("restrict key fixture");
        }

        let result = BondActionClient::new(config)
            .enqueue_redemption(&key_path, 1)
            .await;
        assert!(matches!(result, Err(Error::Preparation(_))));
        assert_eq!(producer_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bond_amount_json_preserves_every_atom_at_fixed_supply_scale() {
        for atoms in [1, 99_999_999, 100_000_001, BOND_FIXED_SUPPLY_ATOMS] {
            let encoded = atoms_json_number(atoms).expect("exact amount");
            assert_eq!(json_amount_atoms(&Value::Number(encoded)), Some(atoms));
        }
    }

    #[test]
    fn explicit_pset_proofs_bind_exact_asset_and_amount() {
        let amount = 125_000_000;
        let (commitments, asset_proof, value_proof) = exact_payment_proofs(amount);
        verify_explicit_payment_proofs(
            ASSET,
            amount,
            &commitments.asset,
            &commitments.value,
            &asset_proof,
            &value_proof,
        )
        .expect("exact payment proofs verify");
        assert!(matches!(
            verify_explicit_payment_proofs(
                ASSET,
                amount + 1,
                &commitments.asset,
                &commitments.value,
                &asset_proof,
                &value_proof,
            ),
            Err(Error::TransferMismatch)
        ));
    }

    #[test]
    fn explicit_pset_proofs_reject_zero_asset_and_value_blinders() {
        let amount = 125_000_000;
        let (commitments, asset_proof, value_proof) = exact_payment_proofs(amount);
        let signing = ZkpSecp256k1::signing_only();
        let asset = AssetId::from_str(ASSET).expect("asset id");
        let explicit_asset = Generator::new_unblinded(&signing, asset.into_tag());
        assert!(matches!(
            verify_explicit_payment_proofs(
                ASSET,
                amount,
                &hex::encode(explicit_asset.serialize()),
                &commitments.value,
                &asset_proof,
                &value_proof,
            ),
            Err(Error::TransferMismatch)
        ));

        let committed_asset =
            Generator::from_slice(&hex::decode(&commitments.asset).expect("asset commitment"))
                .expect("asset generator");
        let zero_value = PedersenCommitment::new(&signing, amount, ZERO_TWEAK, committed_asset);
        assert!(matches!(
            verify_explicit_payment_proofs(
                ASSET,
                amount,
                &commitments.asset,
                &hex::encode(zero_value.serialize()),
                &asset_proof,
                &value_proof,
            ),
            Err(Error::TransferMismatch)
        ));
    }

    #[test]
    fn processed_pset_rejects_reused_payment_commitments() {
        let amount = 125_000_000;
        let (commitments, asset_proof, value_proof) = exact_payment_proofs(amount);
        let mut payment = pset_output(amount, ASSET, None);
        let payment_fields = payment.as_object_mut().expect("payment output");
        payment_fields.insert(
            "asset_commitment".into(),
            Value::String(commitments.asset.clone()),
        );
        payment_fields.insert(
            "value_commitment".into(),
            Value::String(commitments.value.clone()),
        );
        payment_fields.insert("blind_asset_proof".into(), Value::String(asset_proof));
        payment_fields.insert("blind_value_proof".into(), Value::String(value_proof));
        let mut reused = payment.clone();
        reused["script"]["hex"] =
            Value::String("00142222222222222222222222222222222222222222".into());
        let decoded: DecodedPset = serde_json::from_value(json!({
            "psbt_version": 2,
            "input_count": 1,
            "output_count": 2,
            "outputs": [payment, reused]
        }))
        .expect("decoded PSET fixture");
        assert!(matches!(
            require_processed_pset_payment(&decoded, SCRIPT, BLINDING_KEY, ASSET, amount),
            Err(Error::TransferMismatch)
        ));
    }

    #[tokio::test]
    async fn funding_rpc_target_mutation_is_rejected_before_blinding() {
        let mut mutated = pset_output(100_000_001, ASSET, Some("needs blinding"));
        mutated["script"]["hex"] = Value::String(SCRIPT.into());
        let (wallet, state) = mock_wallet(vec![
            MockRpcStep {
                method: "walletcreatefundedpsbt",
                result: json!({ "psbt": "cHNldA==", "fee": 0.0001, "changepos": -1 }),
            },
            MockRpcStep {
                method: "decodepsbt",
                result: decoded_pset(mutated),
            },
        ])
        .await;
        let result = prepare_transfer_pset(
            &wallet,
            DESTINATION,
            SCRIPT,
            BLINDING_KEY,
            ASSET,
            atoms_json_number(100_000_000).expect("amount"),
            100_000_000,
        )
        .await;
        assert!(matches!(result, Err(Error::TransferMismatch)));
        assert_mock_consumed(&state);
    }

    #[tokio::test]
    async fn blinding_rpc_target_mutation_is_rejected_before_finalization() {
        let mutated = pset_output(100_000_001, ASSET, None);
        let (wallet, state) = mock_wallet(vec![
            MockRpcStep {
                method: "walletprocesspsbt",
                result: json!({ "psbt": "cHNldDI=", "complete": true }),
            },
            MockRpcStep {
                method: "decodepsbt",
                result: decoded_pset(mutated),
            },
        ])
        .await;
        let result = process_transfer_pset(
            &wallet,
            "cHNldA==",
            SCRIPT,
            BLINDING_KEY,
            ASSET,
            100_000_000,
        )
        .await;
        assert!(matches!(result, Err(Error::TransferMismatch)));
        assert_mock_consumed(&state);
    }

    #[tokio::test]
    async fn finalized_rpc_target_mutation_is_rejected_before_mempool() {
        let amount = 100_000_000;
        let (expected, _, _) = exact_payment_proofs(amount);
        let (mutated, _, _) = exact_payment_proofs(amount + 1);
        let transaction = finalized_transaction(SCRIPT, &mutated);
        let raw = hex::encode(elements::encode::serialize(&transaction));
        let (wallet, state) = mock_wallet(vec![MockRpcStep {
            method: "finalizepsbt",
            result: json!({ "hex": raw, "complete": true }),
        }])
        .await;
        let result = finalize_transfer_pset(&wallet, "cHNldDI=", SCRIPT, &expected).await;
        assert!(matches!(result, Err(Error::TransferMismatch)));
        assert_mock_consumed(&state);
    }

    #[tokio::test]
    async fn full_action_path_fails_closed_without_authenticated_availability() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("trader secret");
        let (prepared, expected_action) = subscription_preparation(&secret);

        let node_url = serve_router(Router::new().route("/", post(mock_node_rpc))).await;
        let matcher_url = serve_router(
            Router::new()
                .route("/health", get(|| async { Json(health_fixture()) }))
                .route("/v2/capital", get(|| async { Json(capital_fixture()) })),
        )
        .await;
        let producer_status = ProducerStatusV1 {
            version: API_VERSION,
            ready: true,
            private_local: true,
            chain_id: [0xcc; 32],
            context: context_fixture(),
            proof_backend: "sp1-groth16".into(),
            transition_program_id: [0x99; 32],
            transition_cmr: [0xaa; 32],
            proof_inputs_ready: true,
            covenant_frozen: true,
            wallet_ready: true,
            broadcaster_ready: true,
            configuration: frozen_configuration_fixture(),
            action_profile: action_profile_fixture(),
        };
        let producer_state = MockProducerState {
            prepared,
            expected_action,
        };
        let producer_url = serve_router(
            Router::new()
                .route(
                    "/v3/bond/status",
                    get(move || {
                        let status = producer_status.clone();
                        async move { Json(status) }
                    }),
                )
                .route("/v3/bond/actions/prepare", post(mock_prepare))
                .with_state(producer_state),
        )
        .await;

        let config = ClientConfig::new(
            &matcher_url,
            &producer_url,
            &node_url,
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(2),
        )
        .expect("bond client fixture");
        let directory = tempfile::tempdir().expect("key directory");
        let key_path = directory.path().join("trader-key.json");
        fs::write(
            &key_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "role": "ecx_trader",
                "secret_key_hex": hex::encode(secret.secret_bytes())
            }))
            .expect("key JSON"),
        )
        .expect("write key fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .expect("restrict key fixture");
        }

        let result = BondActionClient::new(config)
            .subscribe(&key_path, 100)
            .await;
        assert!(
            matches!(result, Err(Error::ProducerUnavailable(_))),
            "unexpected fail-closed result: {result:?}"
        );
    }

    #[test]
    fn preparation_with_mutated_opening_is_rejected_before_signing() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("trader secret");
        let (mut prepared, _) = subscription_preparation(&secret);
        let PreparedActionV1::Subscription { bond_output, .. } = &mut prepared.prepared else {
            panic!("subscription fixture changed kind");
        };
        bond_output.amount += 1;
        let preflight = AuthenticatedPreflight {
            capital: capital_fixture(),
            context: context_fixture(),
        };
        let config = ClientConfig::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:2",
            "http://127.0.0.1:3",
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(1),
        )
        .expect("bond client fixture");
        let result = sign_prepared_fixture(
            &BondActionClient::new(config),
            &BondIntentV1::Subscription {
                contribution_usdd_atoms: 100,
                recipient_script_sha256: [0xdd; 32],
            },
            &prepared,
            &preflight,
            &secret,
        );
        assert!(matches!(result, Err(Error::Preparation(_))));
    }

    #[test]
    fn preparation_rejects_zero_and_repeated_blinding_factors_before_signing() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("trader secret");
        let (prepared, _) = subscription_preparation(&secret);
        let preflight = AuthenticatedPreflight {
            capital: capital_fixture(),
            context: context_fixture(),
        };
        let config = ClientConfig::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:2",
            "http://127.0.0.1:3",
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(1),
        )
        .expect("bond client fixture");
        let client = BondActionClient::new(config);
        let intent = BondIntentV1::Subscription {
            contribution_usdd_atoms: 100,
            recipient_script_sha256: [0xdd; 32],
        };

        let mut zero = prepared.clone();
        let PreparedActionV1::Subscription {
            action,
            bond_output,
            ..
        } = &mut zero.prepared
        else {
            panic!("subscription fixture changed kind");
        };
        bond_output.asset_blinding_factor = [0; 32];
        let _ = action;
        assert!(matches!(
            sign_prepared_fixture(
                &client,
                &intent,
                &zero,
                &preflight,
                &secret,
            ),
            Err(Error::Preparation(message)) if message.contains("zero or repeated blinding factor")
        ));

        let mut repeated = prepared.clone();
        let PreparedActionV1::Subscription {
            action,
            usdd_output,
            bond_output,
        } = &mut repeated.prepared
        else {
            panic!("subscription fixture changed kind");
        };
        bond_output.value_blinding_factor = usdd_output.value_blinding_factor;
        let _ = action;
        assert!(matches!(
            sign_prepared_fixture(
                &client,
                &intent,
                &repeated,
                &preflight,
                &secret,
            ),
            Err(Error::Preparation(message)) if message.contains("zero or repeated blinding factor")
        ));
    }

    #[test]
    fn first_subscription_is_one_to_one_despite_pre_subscription_revenue() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("trader secret");
        let (mut prepared, _) = subscription_preparation(&secret);
        let PreparedActionV1::Subscription {
            action,
            usdd_output,
            bond_output,
        } = &mut prepared.prepared
        else {
            panic!("subscription fixture changed kind");
        };

        // Revenue may have reached the reserve before the first share was
        // subscribed. The protocol nevertheless prices that first subscription
        // at exactly one bond atom per contributed USDD atom.
        action.issued_share_atoms = action.contribution_usdd_atoms;
        bond_output.amount = action.contribution_usdd_atoms;
        let subscription_id = action.subscription_id();
        usdd_output.role = CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id };
        bond_output.role = BondOutputRoleV2::Subscription {
            subscription_id,
            recipient_script_sha256: action.bond_recipient_script_sha256,
        };
        action.usdd_output_opening_commitment =
            subscription_usdd_output_commitment(usdd_output, &action_profile_fixture())
                .expect("USDD opening commitment");
        action.bond_output_opening_commitment =
            subscription_bond_output_commitment(bond_output, &action_profile_fixture())
                .expect("bond opening commitment");

        let mut capital = capital_fixture();
        capital.insurance_reserve_quote_units = 1_000_000;
        capital.outstanding_bond_units = 0;
        let preflight = AuthenticatedPreflight {
            capital,
            context: context_fixture(),
        };
        let config = ClientConfig::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:2",
            "http://127.0.0.1:3",
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(1),
        )
        .expect("bond client fixture");

        let result = sign_prepared_fixture(
            &BondActionClient::new(config),
            &BondIntentV1::Subscription {
                contribution_usdd_atoms: 100,
                recipient_script_sha256: [0xdd; 32],
            },
            &prepared,
            &preflight,
            &secret,
        );
        assert!(matches!(result, Ok(SignedActionV1::Subscription { .. })));
    }

    #[test]
    fn recapitalization_is_signed_only_as_exact_non_dilutive_insurance() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("trader secret");
        let (prepared, expected) = recapitalization_preparation(&secret);
        let preflight = AuthenticatedPreflight {
            capital: capital_fixture(),
            context: context_fixture(),
        };
        let config = ClientConfig::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:2",
            "http://127.0.0.1:3",
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(1),
        )
        .expect("bond client fixture");
        let result = sign_prepared_fixture(
            &BondActionClient::new(config),
            &BondIntentV1::InsuranceRecapitalization {
                contribution_usdd_atoms: 100,
            },
            &prepared,
            &preflight,
            &secret,
        )
        .expect("exact recapitalization must sign");
        let SignedActionV1::InsuranceRecapitalization { signed } = result else {
            panic!("recapitalization fixture changed action kind");
        };
        assert_eq!(signed.action, expected);
        assert_eq!(signed.action.issued_share_atoms, 0);
        assert_eq!(signed.action.bond_output_opening_commitment, [0; 32]);
        signed.verify().expect("recapitalization signature");
    }

    #[test]
    fn recapitalization_rejects_share_issuance_or_profile_substitution() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("trader secret");
        let (mut prepared, _) = recapitalization_preparation(&secret);
        let PreparedActionV1::InsuranceRecapitalization { action, .. } = &mut prepared.prepared
        else {
            panic!("recapitalization fixture changed action kind");
        };
        action.issued_share_atoms = 1;
        let preflight = AuthenticatedPreflight {
            capital: capital_fixture(),
            context: context_fixture(),
        };
        let config = ClientConfig::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:2",
            "http://127.0.0.1:3",
            None,
            None,
            &"cc".repeat(32),
            &hex::encode(configuration_hash_fixture()),
            &"77".repeat(32),
            &"88".repeat(32),
            &"99".repeat(32),
            &"aa".repeat(32),
            &"dd".repeat(32),
            &"ee".repeat(32),
            &"ff".repeat(32),
            Duration::from_secs(1),
        )
        .expect("bond client fixture");
        assert!(matches!(
            sign_prepared_fixture(
                &BondActionClient::new(config),
                &BondIntentV1::InsuranceRecapitalization {
                    contribution_usdd_atoms: 100,
                },
                &prepared,
                &preflight,
                &secret,
            ),
            Err(Error::Preparation(_))
        ));

        let mut substituted = action_profile_fixture();
        substituted.insurance_reserve_script_sha256 = [0; 32];
        assert!(matches!(
            substituted.validate_against(&preflight.capital),
            Err(Error::ProducerNotReady(_))
        ));
    }

    include!("selected_ten_test.rs");
}
