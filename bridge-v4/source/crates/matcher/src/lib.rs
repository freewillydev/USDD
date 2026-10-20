//! ECX/USDD signed central-limit order book.
//!
//! The matcher is deliberately deterministic: integer price/size units,
//! maker-price execution, and FIFO queues at each price. Commands can be
//! replayed from the append-only journal to recover exactly the same book.

pub mod api;
pub mod engine;
pub mod journal;
pub mod model;
pub mod rpc;
pub mod sequencer;
pub mod successor_api;
pub mod successor_grant_service;
pub mod successor_journal;
pub mod successor_runtime;
pub mod successor_snapshot_composer;
pub mod successor_trader_archive;

pub use api::{ACCOUNT_VIEW_NONCE_BYTES, AppState, account_view_signing_digest, router};
pub use engine::{Engine, EngineConfig, EngineError};
pub use journal::{Journal, JournalEntryV1, MatcherBackupManifestV1};
pub use model::*;
pub use rpc::{
    ElementsConsensusContextV1, ElementsConsensusContextV2, ElementsRpcClient,
    SuccessorElementsConsensusContextV2, V2IdentityPins,
};
pub use sequencer::{
    CentralMatcherSigner, CommandCommitment, MatcherConsensusContextV1,
    SuccessorCentralMatcherSignerV2, SuccessorCommandCommitmentV2,
    SuccessorMatcherConsensusContextV2, SuccessorMatcherHeadV2, command_commitment,
    command_commitment_with_context, command_commitment_with_context_v2, matcher_public_key,
    successor_cancel_command_commitment_v2, successor_order_command_commitment_v2,
};
pub use successor_api::*;
pub use successor_grant_service::*;
pub use successor_journal::{
    PreparedSuccessorJournalAppendV2, SuccessorMatcherJournalCommandV2,
    SuccessorMatcherJournalEntryV2, SuccessorMatcherJournalV2,
};
pub use successor_runtime::*;
pub use successor_snapshot_composer::*;
pub use successor_trader_archive::*;
