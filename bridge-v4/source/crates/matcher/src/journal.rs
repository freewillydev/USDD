use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ecx_protocol_core::{
    CentralMatcherConfigV1, CentralMatcherReceiptV1, Hash32, MatcherExecutionReceiptV2,
    MatcherExecutionRelationV2, Signature64, tagged_hash,
    verify_matcher_execution_receipt_batch_v2,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    CentralMatcherSigner, ElementsConsensusContextV1, ElementsConsensusContextV2, Engine,
    EngineCommand, EngineConfig, MatcherConsensusContextV1, command_commitment,
    command_commitment_with_context, command_commitment_with_context_v2,
    model::StagedMatcherExecutionV2, sequencer::verify_snapshot_signature,
};

pub const MAX_JOURNAL_ENTRY_BYTES: usize = 64 * 1024;
pub const DEFAULT_COMPACT_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_IDEMPOTENCY_RECEIPTS: u64 = 100_000;
pub const MAX_RETAINED_IDEMPOTENCY_RECEIPTS: u64 = 1_000_000;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_EXECUTION_ARCHIVE_RECORD_BYTES: usize = MAX_JOURNAL_ENTRY_BYTES;
const SNAPSHOT_MAGIC: &[u8; 4] = b"ECXS";
const EXECUTION_ARCHIVE_MAGIC: &[u8; 4] = b"ECXA";
const BACKUP_MANIFEST: &str = "backup-manifest.json";
const BACKUP_JOURNAL: &str = "matcher.jsonl";
const BACKUP_EXECUTION_ARCHIVE: &str = "matcher.jsonl.execution-archive";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatcherBackupManifestV1 {
    pub version: u8,
    pub chain_id: Hash32,
    pub matcher_config_hash: Hash32,
    pub head_sequence: u64,
    pub head_receipt_hash: Hash32,
    #[serde(default)]
    pub head_execution_sequence: u64,
    #[serde(default)]
    pub head_execution_history_hash: Hash32,
    #[serde(default)]
    pub retained_execution_previous_sequence: u64,
    #[serde(default)]
    pub retained_execution_previous_history_hash: Hash32,
    pub journal_sha256: Hash32,
    pub snapshot_sha256: Option<Hash32>,
    #[serde(default)]
    pub execution_archive_sha256: Option<Hash32>,
    #[serde(default)]
    pub execution_archive_genesis_hash: Hash32,
    #[serde(default)]
    pub execution_archive_head_hash: Hash32,
    #[serde(default)]
    pub execution_archive_record_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionArchiveCommitmentV1 {
    genesis_hash: Hash32,
    head_hash: Hash32,
    record_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionArchivePrepareV1 {
    command_hash: Hash32,
    admission_receipt: CentralMatcherReceiptV1,
    execution_receipts: Vec<MatcherExecutionReceiptV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
enum ExecutionArchivePayloadV1 {
    Prepare(Box<ExecutionArchivePrepareV1>),
    Commit { prepare_record_hash: Hash32 },
    Abort { prepare_record_hash: Hash32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionArchiveRecordV1 {
    version: u8,
    ordinal: u64,
    previous_record_hash: Hash32,
    payload: ExecutionArchivePayloadV1,
}

impl ExecutionArchiveRecordV1 {
    const VERSION: u8 = 1;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPayloadV1 {
    version: u8,
    chain_id: Hash32,
    matcher_config_hash: Hash32,
    engine: Engine,
    head_sequence: u64,
    head_receipt_hash: Hash32,
    receipts_by_command: Vec<(Hash32, CentralMatcherReceiptV1)>,
    last_elements_context: Option<ElementsConsensusContextV1>,
    last_receipt_context: Option<MatcherConsensusContextV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPayloadV2 {
    version: u8,
    chain_id: Hash32,
    matcher_config_hash: Hash32,
    engine: Engine,
    head_sequence: u64,
    head_receipt_hash: Hash32,
    receipts_by_command: Vec<(Hash32, CentralMatcherReceiptV1)>,
    last_elements_context: Option<ElementsConsensusContextV2>,
    last_receipt_context: Option<MatcherConsensusContextV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPayloadV3 {
    version: u8,
    chain_id: Hash32,
    matcher_config_hash: Hash32,
    engine: Engine,
    head_sequence: u64,
    head_receipt_hash: Hash32,
    receipts_by_command: Vec<(Hash32, CentralMatcherReceiptV1)>,
    head_execution_sequence: u64,
    head_execution_history_hash: Hash32,
    execution_receipts_by_command: Vec<(Hash32, Vec<MatcherExecutionReceiptV2>)>,
    last_elements_context: Option<ElementsConsensusContextV2>,
    last_receipt_context: Option<MatcherConsensusContextV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPayloadV4 {
    version: u8,
    chain_id: Hash32,
    matcher_config_hash: Hash32,
    engine: Engine,
    head_sequence: u64,
    head_receipt_hash: Hash32,
    receipts_by_command: Vec<(Hash32, CentralMatcherReceiptV1)>,
    retained_execution_previous_sequence: u64,
    retained_execution_previous_history_hash: Hash32,
    head_execution_sequence: u64,
    head_execution_history_hash: Hash32,
    execution_receipts_by_command: Vec<(Hash32, Vec<MatcherExecutionReceiptV2>)>,
    last_elements_context: Option<ElementsConsensusContextV2>,
    last_receipt_context: Option<MatcherConsensusContextV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPayloadV5 {
    version: u8,
    chain_id: Hash32,
    matcher_config_hash: Hash32,
    engine: Engine,
    head_sequence: u64,
    head_receipt_hash: Hash32,
    receipts_by_command: Vec<(Hash32, CentralMatcherReceiptV1)>,
    execution_archive: ExecutionArchiveCommitmentV1,
    retained_execution_previous_sequence: u64,
    retained_execution_previous_history_hash: Hash32,
    head_execution_sequence: u64,
    head_execution_history_hash: Hash32,
    execution_receipts_by_command: Vec<(Hash32, Vec<MatcherExecutionReceiptV2>)>,
    last_elements_context: Option<ElementsConsensusContextV2>,
    last_receipt_context: Option<MatcherConsensusContextV1>,
}

#[derive(Clone, Debug)]
struct LoadedSnapshot {
    chain_id: Hash32,
    matcher_config_hash: Hash32,
    engine: Engine,
    head_sequence: u64,
    head_receipt_hash: Hash32,
    receipts_by_command: Vec<(Hash32, CentralMatcherReceiptV1)>,
    retained_execution_previous_sequence: u64,
    retained_execution_previous_history_hash: Hash32,
    head_execution_sequence: u64,
    head_execution_history_hash: Hash32,
    execution_receipts_by_command: Vec<(Hash32, Vec<MatcherExecutionReceiptV2>)>,
    execution_archive: Option<ExecutionArchiveCommitmentV1>,
    last_elements_context: Option<ElementsConsensusContextV2>,
    last_receipt_context: Option<MatcherConsensusContextV1>,
}

/// One atomic, newline-delimited durability record. The command and its sole
/// matcher signature are fsynced together so replay cannot observe one without
/// the other.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntryV1 {
    pub version: u8,
    pub command: EngineCommand,
    pub receipt: CentralMatcherReceiptV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elements_context: Option<ElementsConsensusContextV1>,
}

impl JournalEntryV1 {
    pub const LEGACY_VERSION: u8 = 1;
    pub const VERSION: u8 = 2;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntryV2 {
    version: u8,
    command: EngineCommand,
    receipt: CentralMatcherReceiptV1,
    elements_context: ElementsConsensusContextV2,
}

impl JournalEntryV2 {
    const VERSION: u8 = 3;
}

/// Atomic V2 proof record. The command admission and every exact fill receipt
/// are written and fsynced as one line before the staged engine becomes live.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntryV3 {
    version: u8,
    command: EngineCommand,
    receipt: CentralMatcherReceiptV1,
    elements_context: ElementsConsensusContextV2,
    execution_receipts: Vec<MatcherExecutionReceiptV2>,
}

impl JournalEntryV3 {
    const VERSION: u8 = 4;
}

// These values are immediately replay-validated and then dropped. Keeping
// both frozen wire versions inline avoids adding a heap-allocation-dependent
// representation seam to journal decoding.
#[allow(clippy::large_enum_variant)]
enum DecodedJournalEntry {
    V1(JournalEntryV1),
    V2(JournalEntryV2),
    V3(JournalEntryV3),
}

impl DecodedJournalEntry {
    fn command(&self) -> &EngineCommand {
        match self {
            Self::V1(entry) => &entry.command,
            Self::V2(entry) => &entry.command,
            Self::V3(entry) => &entry.command,
        }
    }

    fn receipt(&self) -> &CentralMatcherReceiptV1 {
        match self {
            Self::V1(entry) => &entry.receipt,
            Self::V2(entry) => &entry.receipt,
            Self::V3(entry) => &entry.receipt,
        }
    }

    fn elements_context_v2(&self) -> Option<ElementsConsensusContextV2> {
        match self {
            Self::V1(entry) => entry.elements_context.clone().map(Into::into),
            Self::V2(entry) => Some(entry.elements_context.clone()),
            Self::V3(entry) => Some(entry.elements_context.clone()),
        }
    }

    fn execution_receipts(&self) -> &[MatcherExecutionReceiptV2] {
        match self {
            Self::V1(_) | Self::V2(_) => &[],
            Self::V3(entry) => &entry.execution_receipts,
        }
    }
}

pub struct Journal {
    path: PathBuf,
    file: File,
    execution_archive_path: PathBuf,
    execution_archive_file: File,
    execution_archive_genesis_hash: Hash32,
    execution_archive_head_hash: Hash32,
    execution_archive_record_count: u64,
    matcher_config: CentralMatcherConfigV1,
    chain_id: Hash32,
    head_sequence: u64,
    head_receipt_hash: Hash32,
    receipts_by_command: HashMap<Hash32, CentralMatcherReceiptV1>,
    retained_execution_previous_sequence: u64,
    retained_execution_previous_history_hash: Hash32,
    head_execution_sequence: u64,
    head_execution_history_hash: Hash32,
    execution_receipts_by_command: HashMap<Hash32, Vec<MatcherExecutionReceiptV2>>,
    last_elements_context: Option<ElementsConsensusContextV2>,
    last_receipt_context: Option<MatcherConsensusContextV1>,
    poisoned: bool,
}

impl Journal {
    pub fn open(
        path: impl AsRef<Path>,
        engine_config: EngineConfig,
        matcher_config: CentralMatcherConfigV1,
        chain_id: Hash32,
    ) -> Result<(Self, Engine)> {
        engine_config
            .validate()
            .context("invalid matcher engine configuration")?;
        matcher_config
            .validate()
            .context("invalid central matcher journal configuration")?;
        if chain_id == [0; 32] {
            bail!("matcher journal chain id must be nonzero");
        }
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating journal directory {}", parent.display()))?;
        }

        let startup_height = engine_config.chain_height;
        let has_existing_journal = path.exists();
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("opening matcher journal {}", path.display()))?;
        file.try_lock_exclusive().with_context(|| {
            format!(
                "locking matcher journal {} (another matcher may already be running)",
                path.display()
            )
        })?;
        validate_private_permissions(&path)?;
        if !has_existing_journal {
            sync_parent_directory(&path)?;
        }

        let snapshot = load_snapshot(&path, &engine_config, &matcher_config, chain_id)?;
        let snapshot_head = snapshot.as_ref().map(|value| {
            (
                value.head_sequence,
                value.head_receipt_hash,
                value.last_receipt_context,
                value.last_elements_context.clone(),
                value.head_execution_sequence,
                value.head_execution_history_hash,
                value.retained_execution_previous_sequence,
                value.retained_execution_previous_history_hash,
            )
        });
        let mut engine = if let Some(value) = snapshot.as_ref() {
            value.engine.clone()
        } else {
            let mut replay_config = engine_config.clone();
            if has_existing_journal {
                replay_config.chain_height = 0;
            }
            Engine::new(replay_config)
        };
        let mut head_sequence = snapshot_head
            .as_ref()
            .map_or(matcher_config.genesis_sequence, |value| value.0);
        let mut head_receipt_hash = snapshot_head
            .as_ref()
            .map_or(matcher_config.genesis_receipt_hash, |value| value.1);
        let mut receipts_by_command = HashMap::new();
        let execution_genesis = execution_history_genesis(chain_id, matcher_config.digest());
        let retained_execution_previous_sequence =
            snapshot_head.as_ref().map_or(0, |value| value.6);
        let retained_execution_previous_history_hash = snapshot_head
            .as_ref()
            .map_or(execution_genesis, |value| value.7);
        let mut head_execution_sequence = snapshot_head.as_ref().map_or(0, |value| value.4);
        let mut head_execution_history_hash = snapshot_head
            .as_ref()
            .map_or(execution_genesis, |value| value.5);
        let mut execution_receipts_by_command = HashMap::new();
        if let Some(value) = snapshot.as_ref() {
            for (command_hash, receipt) in &value.receipts_by_command {
                receipt
                    .verify(&matcher_config)
                    .context("snapshot contains an invalid matcher receipt")?;
                if receipt.body.chain_id != chain_id
                    || receipt.body.matcher_config_hash != matcher_config.digest()
                    || receipt.body.command_hash != *command_hash
                    || receipt.body.global_sequence > value.head_sequence
                    || receipts_by_command
                        .insert(*command_hash, receipt.clone())
                        .is_some()
                {
                    bail!("snapshot receipt index is invalid");
                }
            }
            let mut all_execution_receipts = Vec::new();
            for (command_hash, receipts) in &value.execution_receipts_by_command {
                let admission = receipts_by_command
                    .get(command_hash)
                    .context("snapshot execution receipt is missing its taker admission")?;
                if receipts.is_empty()
                    || execution_receipts_by_command
                        .insert(*command_hash, receipts.clone())
                        .is_some()
                    || receipts.iter().any(|receipt| {
                        receipt.body.taker_admission_receipt_hash != admission.receipt_hash()
                            || receipt.body.admission_sequence != admission.body.global_sequence
                            || receipt.body.observed_sidechain_height
                                != admission.body.observed_sidechain_height
                            || receipt.body.execution_parent.height
                                != admission.body.observed_parent_height
                            || receipt.body.execution_parent.median_time_past
                                != admission.body.observed_parent_mtp
                    })
                {
                    bail!("snapshot execution receipt index is invalid");
                }
                all_execution_receipts.extend(receipts.iter().cloned());
            }
            all_execution_receipts.sort_by_key(|receipt| receipt.body.match_sequence);
            if value.retained_execution_previous_sequence > value.head_execution_sequence
                || (value.retained_execution_previous_sequence == 0
                    && value.retained_execution_previous_history_hash != execution_genesis)
                || (value.retained_execution_previous_sequence != 0
                    && value.retained_execution_previous_history_hash == [0; 32])
            {
                bail!("snapshot retained execution checkpoint is invalid");
            }
            let mut cursor = value.retained_execution_previous_sequence;
            let mut history = value.retained_execution_previous_history_hash;
            for receipt in &all_execution_receipts {
                receipt
                    .verify(&matcher_config)
                    .context("snapshot contains an invalid execution receipt")?;
                cursor = cursor
                    .checked_add(1)
                    .context("snapshot execution sequence overflow")?;
                if receipt.body.chain_id != chain_id || receipt.body.match_sequence != cursor {
                    bail!("snapshot execution receipt sequence is invalid");
                }
                history = execution_history_next(history, receipt);
            }
            if cursor != value.head_execution_sequence
                || history != value.head_execution_history_hash
            {
                bail!("snapshot execution receipt history is invalid");
            }
        }
        let mut last_elements_context = snapshot_head.as_ref().and_then(|value| value.3.clone());
        let mut last_receipt_context = snapshot_head.as_ref().and_then(|value| value.2);
        let mut reader = BufReader::new(
            file.try_clone()
                .with_context(|| format!("cloning matcher journal {}", path.display()))?,
        );
        let mut line_number = 0usize;
        let mut full_prefix: Option<bool> = None;
        let mut replay_sequence = head_sequence;
        let mut replay_hash = head_receipt_hash;
        let mut replay_receipt_context = last_receipt_context;
        let mut replay_elements_context = last_elements_context.clone();
        let mut replay_execution_sequence = head_execution_sequence;
        let mut replay_execution_history_hash = head_execution_history_hash;
        let mut seen_commands = HashSet::new();
        while let Some(line) = read_bounded_record(&mut reader, line_number.saturating_add(1))? {
            line_number = line_number.saturating_add(1);
            let entry = decode_journal_entry(&line).with_context(|| {
                format!("decoding matcher journal line {line_number} (refusing partial recovery)")
            })?;
            let entry_receipt = entry.receipt();
            if full_prefix.is_none() {
                let is_full_prefix = snapshot_head.is_some()
                    && snapshot_head.as_ref().unwrap().0 > matcher_config.genesis_sequence
                    && entry_receipt.body.global_sequence
                        == matcher_config.genesis_sequence.saturating_add(1);
                full_prefix = Some(is_full_prefix);
                if is_full_prefix {
                    replay_sequence = matcher_config.genesis_sequence;
                    replay_hash = matcher_config.genesis_receipt_hash;
                    replay_receipt_context = None;
                    replay_elements_context = None;
                    replay_execution_sequence = 0;
                    replay_execution_history_hash = execution_genesis;
                } else if entry_receipt.body.global_sequence != replay_sequence.saturating_add(1) {
                    bail!("matcher journal does not begin at the snapshot successor");
                }
            }
            let commitment = validate_decoded_entry(
                &matcher_config,
                chain_id,
                replay_sequence,
                replay_hash,
                &entry,
            )
            .with_context(|| format!("validating matcher journal line {line_number}"))?;
            let receipt_context = receipt_context(entry_receipt)?;
            let entry_elements_context = entry.elements_context_v2();
            validate_context_progression(
                replay_receipt_context.as_ref(),
                replay_elements_context.as_ref(),
                receipt_context,
                entry_elements_context.as_ref(),
            )
            .with_context(|| format!("validating matcher context at journal line {line_number}"))?;
            if !seen_commands.insert(commitment.command_hash) {
                bail!("duplicate matcher command at journal line {line_number}");
            }
            replay_sequence = entry_receipt.body.global_sequence;
            replay_hash = entry_receipt.receipt_hash();
            replay_receipt_context = Some(receipt_context);
            if let Some(context) = entry_elements_context {
                replay_elements_context = Some(context);
            }

            let covered_by_snapshot = full_prefix == Some(true)
                && snapshot_head
                    .as_ref()
                    .is_some_and(|value| replay_sequence <= value.0);
            if covered_by_snapshot {
                (replay_execution_sequence, replay_execution_history_hash) =
                    validate_execution_receipts(
                        &matcher_config,
                        chain_id,
                        replay_execution_sequence,
                        replay_execution_history_hash,
                        &entry,
                        None,
                    )
                    .with_context(|| {
                        format!("validating matcher executions at journal line {line_number}")
                    })?;
                if snapshot_head
                    .as_ref()
                    .is_some_and(|value| replay_sequence == value.0)
                    && (replay_hash != snapshot_head.as_ref().unwrap().1
                        || replay_receipt_context != snapshot_head.as_ref().unwrap().2
                        || replay_elements_context != snapshot_head.as_ref().unwrap().3
                        || replay_execution_sequence != snapshot_head.as_ref().unwrap().4
                        || replay_execution_history_hash != snapshot_head.as_ref().unwrap().5)
                {
                    bail!("matcher journal prefix disagrees with the signed snapshot head");
                }
                continue;
            }
            if receipts_by_command.contains_key(&commitment.command_hash) {
                bail!("duplicate matcher command at journal line {line_number}");
            }
            engine
                .advance_chain_height(entry_receipt.body.observed_sidechain_height)
                .with_context(|| {
                    format!("advancing active height at matcher journal line {line_number}")
                })?;
            let (_, executions) = engine
                .replay_sequenced_with_executions(
                    entry.command().clone(),
                    entry_receipt.body.global_sequence,
                )
                .with_context(|| format!("replaying matcher journal line {line_number}"))?;
            (replay_execution_sequence, replay_execution_history_hash) =
                validate_execution_receipts(
                    &matcher_config,
                    chain_id,
                    replay_execution_sequence,
                    replay_execution_history_hash,
                    &entry,
                    Some(&executions),
                )
                .with_context(|| {
                    format!("validating matcher executions at journal line {line_number}")
                })?;
            head_sequence = replay_sequence;
            head_receipt_hash = replay_hash;
            last_receipt_context = replay_receipt_context;
            last_elements_context = replay_elements_context.clone();
            receipts_by_command.insert(commitment.command_hash, entry_receipt.clone());
            if !entry.execution_receipts().is_empty() {
                execution_receipts_by_command
                    .insert(commitment.command_hash, entry.execution_receipts().to_vec());
            }
            head_execution_sequence = replay_execution_sequence;
            head_execution_history_hash = replay_execution_history_hash;
        }

        if full_prefix == Some(true)
            && snapshot_head
                .as_ref()
                .is_some_and(|value| replay_sequence < value.0)
        {
            bail!("matcher journal prefix ends before the signed snapshot head");
        }

        if startup_height != 0 {
            engine
                .advance_chain_height(startup_height)
                .context("reconciling matcher journal with startup sidechain height")?;
        }

        let (execution_archive_path, execution_archive_file, execution_archive) =
            open_and_reconcile_execution_archive(
                &path,
                &matcher_config,
                chain_id,
                snapshot.as_ref().and_then(|value| value.execution_archive),
                retained_execution_previous_sequence,
                retained_execution_previous_history_hash,
                head_execution_sequence,
                head_execution_history_hash,
                &execution_receipts_by_command,
                &receipts_by_command,
            )?;

        Ok((
            Self {
                path,
                file,
                execution_archive_path,
                execution_archive_file,
                execution_archive_genesis_hash: execution_archive.genesis_hash,
                execution_archive_head_hash: execution_archive.head_hash,
                execution_archive_record_count: execution_archive.record_count,
                matcher_config,
                chain_id,
                head_sequence,
                head_receipt_hash,
                receipts_by_command,
                retained_execution_previous_sequence,
                retained_execution_previous_history_hash,
                head_execution_sequence,
                head_execution_history_hash,
                execution_receipts_by_command,
                last_elements_context,
                last_receipt_context,
                poisoned: false,
            },
            engine,
        ))
    }

    pub fn append(
        &mut self,
        command: &EngineCommand,
        receipt: &CentralMatcherReceiptV1,
    ) -> Result<()> {
        self.append_decoded(DecodedJournalEntry::V1(JournalEntryV1 {
            version: JournalEntryV1::LEGACY_VERSION,
            command: command.clone(),
            receipt: receipt.clone(),
            elements_context: None,
        }))
    }

    pub fn append_with_context(
        &mut self,
        command: &EngineCommand,
        receipt: &CentralMatcherReceiptV1,
        elements_context: &ElementsConsensusContextV2,
    ) -> Result<()> {
        self.append_decoded(DecodedJournalEntry::V2(JournalEntryV2 {
            version: JournalEntryV2::VERSION,
            command: command.clone(),
            receipt: receipt.clone(),
            elements_context: elements_context.clone(),
        }))
    }

    pub(crate) fn append_with_execution_receipts(
        &mut self,
        command: &EngineCommand,
        receipt: &CentralMatcherReceiptV1,
        elements_context: &ElementsConsensusContextV2,
        executions: &[StagedMatcherExecutionV2],
        execution_receipts: &[MatcherExecutionReceiptV2],
    ) -> Result<()> {
        self.append_decoded_with_executions(
            DecodedJournalEntry::V3(JournalEntryV3 {
                version: JournalEntryV3::VERSION,
                command: command.clone(),
                receipt: receipt.clone(),
                elements_context: elements_context.clone(),
                execution_receipts: execution_receipts.to_vec(),
            }),
            Some(executions),
        )
    }

    fn append_decoded(&mut self, entry: DecodedJournalEntry) -> Result<()> {
        self.append_decoded_with_executions(entry, None)
    }

    fn append_decoded_with_executions(
        &mut self,
        entry: DecodedJournalEntry,
        executions: Option<&[StagedMatcherExecutionV2]>,
    ) -> Result<()> {
        if self.poisoned {
            bail!("matcher journal is poisoned after an earlier durability failure");
        }
        let commitment = validate_decoded_entry(
            &self.matcher_config,
            self.chain_id,
            self.head_sequence,
            self.head_receipt_hash,
            &entry,
        )?;
        if self
            .receipts_by_command
            .contains_key(&commitment.command_hash)
        {
            bail!("matcher command is already durable");
        }
        let receipt = entry.receipt();
        let next_receipt_context = receipt_context(receipt)?;
        let elements_context = entry.elements_context_v2();
        validate_context_progression(
            self.last_receipt_context.as_ref(),
            self.last_elements_context.as_ref(),
            next_receipt_context,
            elements_context.as_ref(),
        )?;
        let (next_execution_sequence, next_execution_history_hash) = validate_execution_receipts(
            &self.matcher_config,
            self.chain_id,
            self.head_execution_sequence,
            self.head_execution_history_hash,
            &entry,
            executions,
        )?;
        let bytes = match &entry {
            DecodedJournalEntry::V1(entry) => serde_json::to_vec(entry),
            DecodedJournalEntry::V2(entry) => serde_json::to_vec(entry),
            DecodedJournalEntry::V3(entry) => serde_json::to_vec(entry),
        }
        .context("encoding matcher journal entry")?;
        if bytes.len() > MAX_JOURNAL_ENTRY_BYTES {
            bail!("matcher journal entry exceeds the {MAX_JOURNAL_ENTRY_BYTES}-byte bound");
        }
        let archive_prepare_hash = if entry.execution_receipts().is_empty() {
            None
        } else {
            let prepare = ExecutionArchivePrepareV1 {
                command_hash: commitment.command_hash,
                admission_receipt: receipt.clone(),
                execution_receipts: entry.execution_receipts().to_vec(),
            };
            let mut archive = ExecutionArchiveCommitmentV1 {
                genesis_hash: self.execution_archive_genesis_hash,
                head_hash: self.execution_archive_head_hash,
                record_count: self.execution_archive_record_count,
            };
            match append_execution_archive_payload(
                &mut self.execution_archive_file,
                &self.execution_archive_path,
                &mut archive,
                ExecutionArchivePayloadV1::Prepare(Box::new(prepare)),
            ) {
                Ok(hash) => {
                    self.execution_archive_head_hash = archive.head_hash;
                    self.execution_archive_record_count = archive.record_count;
                    Some(hash)
                }
                Err(error) => {
                    self.poisoned = true;
                    return Err(error).context(
                        "durably preparing private execution archive before journal mutation",
                    );
                }
            }
        };
        let durability = self
            .file
            .write_all(&bytes)
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_data());
        if let Err(error) = durability {
            self.poisoned = true;
            return Err(error).with_context(|| {
                format!("durably appending matcher journal {}", self.path.display())
            });
        }
        if let Some(prepare_record_hash) = archive_prepare_hash {
            let mut archive = ExecutionArchiveCommitmentV1 {
                genesis_hash: self.execution_archive_genesis_hash,
                head_hash: self.execution_archive_head_hash,
                record_count: self.execution_archive_record_count,
            };
            if let Err(error) = append_execution_archive_payload(
                &mut self.execution_archive_file,
                &self.execution_archive_path,
                &mut archive,
                ExecutionArchivePayloadV1::Commit {
                    prepare_record_hash,
                },
            ) {
                self.poisoned = true;
                return Err(error)
                    .context("committing private execution archive after durable journal append");
            }
            self.execution_archive_head_hash = archive.head_hash;
            self.execution_archive_record_count = archive.record_count;
        }
        self.head_sequence = receipt.body.global_sequence;
        self.head_receipt_hash = receipt.receipt_hash();
        self.last_receipt_context = Some(next_receipt_context);
        if let Some(context) = elements_context {
            self.last_elements_context = Some(context);
        }
        self.receipts_by_command
            .insert(commitment.command_hash, receipt.clone());
        self.head_execution_sequence = next_execution_sequence;
        self.head_execution_history_hash = next_execution_history_hash;
        if !entry.execution_receipts().is_empty() {
            self.execution_receipts_by_command
                .insert(commitment.command_hash, entry.execution_receipts().to_vec());
        }
        Ok(())
    }

    pub fn next_sequence(&self) -> Result<u64> {
        if self.poisoned {
            bail!("matcher journal is poisoned after an earlier durability failure");
        }
        self.head_sequence
            .checked_add(1)
            .context("central matcher sequence overflow")
    }

    pub fn should_compact(&self, maximum_journal_bytes: u64) -> Result<bool> {
        if maximum_journal_bytes == 0 {
            bail!("matcher journal compaction threshold must be nonzero");
        }
        Ok(self
            .file
            .metadata()
            .context("reading matcher journal size")?
            .len()
            >= maximum_journal_bytes)
    }

    pub fn compact(
        &mut self,
        engine: &mut Engine,
        signer: &CentralMatcherSigner,
        retained_idempotency_receipts: u64,
    ) -> Result<()> {
        if self.poisoned {
            bail!("matcher journal is poisoned after an earlier durability failure");
        }
        if retained_idempotency_receipts == 0
            || retained_idempotency_receipts > MAX_RETAINED_IDEMPOTENCY_RECEIPTS
        {
            bail!(
                "matcher snapshot idempotency retention is outside the supported 1..={MAX_RETAINED_IDEMPOTENCY_RECEIPTS} range"
            );
        }
        if signer.config() != &self.matcher_config || signer.chain_id() != self.chain_id {
            bail!("matcher snapshot signer differs from the active journal");
        }
        let minimum_sequence = self
            .head_sequence
            .saturating_sub(retained_idempotency_receipts.saturating_sub(1));
        let mut snapshot_engine = engine.clone();
        snapshot_engine.compact_idempotency(minimum_sequence);
        snapshot_engine
            .validate_restored(snapshot_engine.config())
            .context("validating matcher engine before snapshot")?;
        let authenticated_consumed_sequence = self
            .last_elements_context
            .as_ref()
            .and_then(|context| context.capital_snapshot.as_ref())
            .map_or(self.retained_execution_previous_sequence, |capital| {
                capital.matcher_execution.sequence
            });
        if authenticated_consumed_sequence > self.head_execution_sequence {
            bail!("authenticated node execution cursor is ahead of the durable matcher history");
        }
        let archive_commitment = ExecutionArchiveCommitmentV1 {
            genesis_hash: self.execution_archive_genesis_hash,
            head_hash: self.execution_archive_head_hash,
            record_count: self.execution_archive_record_count,
        };
        let mut retained_batches = Vec::new();
        let archive_scan = scan_execution_archive(
            &self.execution_archive_path,
            &self.matcher_config,
            self.chain_id,
            Some(archive_commitment),
            authenticated_consumed_sequence,
            |batch| {
                if let Some(suffix) =
                    execution_archive_suffix_batch(batch, authenticated_consumed_sequence)
                {
                    retained_batches.push(suffix);
                }
                Ok(())
            },
        )?;
        let retained_execution_previous_history_hash = archive_scan
            .checkpoint_history_hash
            .context("authenticated execution cursor is outside execution archive history")?;
        if archive_scan.pending_prepare.is_some()
            || archive_scan.commitment != archive_commitment
            || archive_scan.logical_execution_sequence != self.head_execution_sequence
            || archive_scan.logical_execution_history_hash != self.head_execution_history_hash
        {
            bail!("execution archive changed or disagrees with the durable matcher head");
        }
        let mut retained_execution_receipts = retained_batches
            .iter()
            .map(|batch| (batch.command_hash, batch.execution_receipts.clone()))
            .collect::<Vec<_>>();
        let execution_commands = retained_execution_receipts
            .iter()
            .map(|(hash, _)| *hash)
            .collect::<HashSet<_>>();
        let mut receipts_by_command = self
            .receipts_by_command
            .iter()
            .filter(|(hash, receipt)| {
                receipt.body.global_sequence >= minimum_sequence
                    || execution_commands.contains(*hash)
            })
            .map(|(hash, receipt)| (*hash, receipt.clone()))
            .collect::<Vec<_>>();
        for batch in &retained_batches {
            if !receipts_by_command
                .iter()
                .any(|(hash, _)| hash == &batch.command_hash)
            {
                receipts_by_command.push((batch.command_hash, batch.admission_receipt.clone()));
            }
        }
        receipts_by_command.sort_by_key(|(hash, receipt)| (receipt.body.global_sequence, *hash));
        retained_execution_receipts.sort_by_key(|(hash, receipts)| {
            (
                receipts
                    .first()
                    .map_or(u64::MAX, |receipt| receipt.body.match_sequence),
                *hash,
            )
        });
        let payload = SnapshotPayloadV5 {
            version: 5,
            chain_id: self.chain_id,
            matcher_config_hash: self.matcher_config.digest(),
            engine: snapshot_engine,
            head_sequence: self.head_sequence,
            head_receipt_hash: self.head_receipt_hash,
            receipts_by_command: receipts_by_command.clone(),
            execution_archive: archive_commitment,
            retained_execution_previous_sequence: authenticated_consumed_sequence,
            retained_execution_previous_history_hash,
            head_execution_sequence: self.head_execution_sequence,
            head_execution_history_hash: self.head_execution_history_hash,
            execution_receipts_by_command: retained_execution_receipts.clone(),
            last_elements_context: self.last_elements_context.clone(),
            last_receipt_context: self.last_receipt_context,
        };
        let payload_bytes = bincode::serialize(&payload).context("encoding matcher snapshot")?;
        if payload_bytes.len() > MAX_SNAPSHOT_BYTES {
            bail!("matcher snapshot exceeds the bounded snapshot size");
        }
        let signature = signer.sign_snapshot(&payload_bytes)?;
        let snapshot_path = snapshot_path(&self.path);
        let temporary_path = snapshot_temporary_path(&self.path);
        let durability = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.create(true).truncate(true).write(true);
            #[cfg(unix)]
            {
                options.mode(0o600);
            }
            let mut temporary = options.open(&temporary_path).with_context(|| {
                format!("creating matcher snapshot {}", temporary_path.display())
            })?;
            set_private_permissions(&temporary_path)?;
            temporary.write_all(SNAPSHOT_MAGIC)?;
            temporary.write_all(&[5])?;
            temporary.write_all(&(payload_bytes.len() as u64).to_be_bytes())?;
            temporary.write_all(&payload_bytes)?;
            temporary.write_all(&signature.0)?;
            temporary.flush()?;
            temporary.sync_all()?;
            fs::rename(&temporary_path, &snapshot_path).with_context(|| {
                format!("installing matcher snapshot {}", snapshot_path.display())
            })?;
            sync_parent_directory(&snapshot_path)?;
            self.file.set_len(0)?;
            self.file.sync_data()?;
            sync_parent_directory(&self.path)?;
            Ok(())
        })();
        if let Err(error) = durability {
            self.poisoned = true;
            return Err(error).context("durably compacting matcher journal");
        }
        engine.compact_idempotency(minimum_sequence);
        self.receipts_by_command = receipts_by_command.into_iter().collect();
        self.execution_receipts_by_command = retained_execution_receipts.into_iter().collect();
        self.retained_execution_previous_sequence = authenticated_consumed_sequence;
        self.retained_execution_previous_history_hash = retained_execution_previous_history_hash;
        Ok(())
    }

    pub fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    pub fn head_receipt_hash(&self) -> Hash32 {
        self.head_receipt_hash
    }

    pub fn head_execution_sequence(&self) -> u64 {
        self.head_execution_sequence
    }

    pub fn head_execution_history_hash(&self) -> Hash32 {
        self.head_execution_history_hash
    }

    pub fn retained_execution_previous_sequence(&self) -> u64 {
        self.retained_execution_previous_sequence
    }

    fn execution_archive_commitment(&self) -> ExecutionArchiveCommitmentV1 {
        ExecutionArchiveCommitmentV1 {
            genesis_hash: self.execution_archive_genesis_hash,
            head_hash: self.execution_archive_head_hash,
            record_count: self.execution_archive_record_count,
        }
    }

    fn rehydrate_execution_suffix(&mut self, previous_sequence: u64) -> Result<()> {
        let expected_archive = self.execution_archive_commitment();
        let mut batches = Vec::new();
        let scan = scan_execution_archive(
            &self.execution_archive_path,
            &self.matcher_config,
            self.chain_id,
            Some(expected_archive),
            previous_sequence,
            |batch| {
                if let Some(suffix) = execution_archive_suffix_batch(batch, previous_sequence) {
                    batches.push(suffix);
                }
                Ok(())
            },
        )?;
        let checkpoint_history = scan
            .checkpoint_history_hash
            .context("proof-verified execution cursor is outside execution archive history")?;
        if scan.pending_prepare.is_some()
            || scan.commitment != expected_archive
            || scan.logical_execution_sequence != self.head_execution_sequence
            || scan.logical_execution_history_hash != self.head_execution_history_hash
        {
            bail!("private execution archive differs from the durable matcher head");
        }
        self.execution_receipts_by_command = batches
            .iter()
            .map(|batch| (batch.command_hash, batch.execution_receipts.clone()))
            .collect();
        for batch in batches {
            self.receipts_by_command
                .insert(batch.command_hash, batch.admission_receipt);
        }
        self.retained_execution_previous_sequence = previous_sequence;
        self.retained_execution_previous_history_hash = checkpoint_history;
        Ok(())
    }

    /// Reconcile the local private receipt history with the proof-verified
    /// active-tip cursor. A producer acknowledgement is never sufficient.
    pub fn validate_authenticated_execution_cursor(
        &mut self,
        context: &ElementsConsensusContextV2,
    ) -> Result<()> {
        if let Some(capital) = &context.capital_snapshot {
            let consumed = capital.matcher_execution.sequence;
            if consumed > self.head_execution_sequence {
                bail!("proof-verified node execution cursor is ahead of durable matcher history");
            }
            if consumed < self.retained_execution_previous_sequence {
                self.rehydrate_execution_suffix(consumed)
                    .context("rehydrating private execution receipts after active-tip rollback")?;
            }
        } else if self.retained_execution_previous_sequence != 0 {
            bail!("Elements omitted v2 capital state after execution receipts were pruned");
        }
        Ok(())
    }

    pub fn receipt_for_command(&self, command_hash: &Hash32) -> Option<CentralMatcherReceiptV1> {
        self.receipts_by_command.get(command_hash).cloned()
    }

    pub fn receipt_for_sequence(&self, sequence: u64) -> Option<CentralMatcherReceiptV1> {
        self.receipts_by_command
            .values()
            .find(|receipt| receipt.body.global_sequence == sequence)
            .cloned()
    }

    pub fn execution_receipts_for_command(
        &self,
        command_hash: &Hash32,
    ) -> Vec<MatcherExecutionReceiptV2> {
        self.execution_receipts_by_command
            .get(command_hash)
            .cloned()
            .unwrap_or_default()
    }

    pub fn execution_receipts_after(
        &self,
        previous_sequence: u64,
        limit: usize,
    ) -> Result<Vec<MatcherExecutionReceiptV2>> {
        if limit == 0 || limit > MAX_RETAINED_IDEMPOTENCY_RECEIPTS as usize {
            bail!("execution receipt query limit is outside the supported range");
        }
        if previous_sequence > self.head_execution_sequence {
            bail!("execution receipt cursor is ahead of the durable matcher head");
        }
        let expected_archive = self.execution_archive_commitment();
        let mut receipts = Vec::new();
        let scan = scan_execution_archive(
            &self.execution_archive_path,
            &self.matcher_config,
            self.chain_id,
            Some(expected_archive),
            previous_sequence,
            |batch| {
                if receipts.len() < limit {
                    receipts.extend(
                        batch
                            .execution_receipts
                            .iter()
                            .filter(|receipt| receipt.body.match_sequence > previous_sequence)
                            .take(limit - receipts.len())
                            .cloned(),
                    );
                }
                Ok(())
            },
        )?;
        if scan.checkpoint_history_hash.is_none()
            || scan.pending_prepare.is_some()
            || scan.commitment != expected_archive
            || scan.logical_execution_sequence != self.head_execution_sequence
            || scan.logical_execution_history_hash != self.head_execution_history_hash
        {
            bail!("private execution archive differs from the durable matcher head");
        }
        let expected_first = if receipts.is_empty() {
            None
        } else {
            Some(
                previous_sequence
                    .checked_add(1)
                    .context("execution receipt query cursor overflow")?,
            )
        };
        if receipts
            .first()
            .zip(expected_first)
            .is_some_and(|(receipt, expected)| receipt.body.match_sequence != expected)
            || receipts.windows(2).any(|pair| {
                pair[0]
                    .body
                    .match_sequence
                    .checked_add(1)
                    .is_none_or(|expected| pair[1].body.match_sequence != expected)
            })
        {
            bail!("durable execution receipt index is not contiguous");
        }
        Ok(receipts)
    }

    pub fn admission_receipts_for_executions(
        &self,
        executions: &[MatcherExecutionReceiptV2],
    ) -> Result<Vec<CentralMatcherReceiptV1>> {
        let required = executions
            .iter()
            .map(|execution| execution.body.taker_admission_receipt_hash)
            .collect::<HashSet<_>>();
        let expected_archive = self.execution_archive_commitment();
        let mut admissions = Vec::new();
        let scan = scan_execution_archive(
            &self.execution_archive_path,
            &self.matcher_config,
            self.chain_id,
            Some(expected_archive),
            0,
            |batch| {
                if required.contains(&batch.admission_receipt.receipt_hash()) {
                    admissions.push(batch.admission_receipt.clone());
                }
                Ok(())
            },
        )?;
        if scan.pending_prepare.is_some()
            || scan.commitment != expected_archive
            || scan.logical_execution_sequence != self.head_execution_sequence
            || scan.logical_execution_history_hash != self.head_execution_history_hash
        {
            bail!("private execution archive differs from the durable matcher head");
        }
        admissions.sort_by_key(|receipt| receipt.body.global_sequence);
        admissions.dedup_by_key(|receipt| receipt.receipt_hash());
        if admissions.len() != required.len() {
            bail!("execution receipt admission is outside the durable receipt index");
        }
        Ok(admissions)
    }

    pub fn matcher_config(&self) -> &CentralMatcherConfigV1 {
        &self.matcher_config
    }

    pub fn chain_id(&self) -> Hash32 {
        self.chain_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_elements_context(&self) -> Option<&ElementsConsensusContextV2> {
        self.last_elements_context.as_ref()
    }

    /// Create one offline, mutually consistent snapshot-plus-tail backup while
    /// this Journal holds the exclusive source lock.
    pub fn backup_to(&mut self, destination: impl AsRef<Path>) -> Result<MatcherBackupManifestV1> {
        if self.poisoned {
            bail!("matcher journal is poisoned after an earlier durability failure");
        }
        let destination = destination.as_ref();
        fs::create_dir(destination).with_context(|| {
            format!(
                "creating new matcher backup directory {}",
                destination.display()
            )
        })?;
        set_private_directory(destination)?;
        self.file
            .sync_all()
            .context("syncing matcher journal before backup")?;
        self.execution_archive_file
            .sync_all()
            .context("syncing private execution archive before backup")?;
        let journal_destination = destination.join(BACKUP_JOURNAL);
        copy_private_file(&self.path, &journal_destination)?;
        let archive_destination = destination.join(BACKUP_EXECUTION_ARCHIVE);
        copy_private_file(&self.execution_archive_path, &archive_destination)?;
        let source_snapshot = snapshot_path(&self.path);
        let snapshot_sha256 = if source_snapshot.exists() {
            let destination_snapshot = snapshot_path(&journal_destination);
            copy_private_file(&source_snapshot, &destination_snapshot)?;
            Some(sha256_file(&destination_snapshot)?)
        } else {
            None
        };
        let manifest = MatcherBackupManifestV1 {
            version: 2,
            chain_id: self.chain_id,
            matcher_config_hash: self.matcher_config.digest(),
            head_sequence: self.head_sequence,
            head_receipt_hash: self.head_receipt_hash,
            head_execution_sequence: self.head_execution_sequence,
            head_execution_history_hash: self.head_execution_history_hash,
            retained_execution_previous_sequence: self.retained_execution_previous_sequence,
            retained_execution_previous_history_hash: self.retained_execution_previous_history_hash,
            journal_sha256: sha256_file(&journal_destination)?,
            snapshot_sha256,
            execution_archive_sha256: Some(sha256_file(&archive_destination)?),
            execution_archive_genesis_hash: self.execution_archive_genesis_hash,
            execution_archive_head_hash: self.execution_archive_head_hash,
            execution_archive_record_count: self.execution_archive_record_count,
        };
        let manifest_path = destination.join(BACKUP_MANIFEST);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut output = options.open(&manifest_path).with_context(|| {
            format!(
                "creating matcher backup manifest {}",
                manifest_path.display()
            )
        })?;
        serde_json::to_writer_pretty(&mut output, &manifest)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        sync_parent_directory(&manifest_path)?;
        Ok(manifest)
    }

    /// Reopen and fully replay a backup only after its immutable file hashes
    /// and frozen chain/matcher identities agree with the supplied config.
    pub fn open_backup(
        directory: impl AsRef<Path>,
        engine_config: EngineConfig,
        matcher_config: CentralMatcherConfigV1,
        chain_id: Hash32,
    ) -> Result<(Self, Engine, MatcherBackupManifestV1)> {
        let directory = directory.as_ref();
        let manifest_path = directory.join(BACKUP_MANIFEST);
        validate_private_permissions(&manifest_path)?;
        let bytes = fs::read(&manifest_path).with_context(|| {
            format!(
                "reading matcher backup manifest {}",
                manifest_path.display()
            )
        })?;
        if bytes.len() > 4096 {
            bail!("matcher backup manifest exceeds 4096 bytes");
        }
        let manifest: MatcherBackupManifestV1 =
            serde_json::from_slice(&bytes).context("decoding matcher backup manifest")?;
        if !matches!(manifest.version, 1 | 2)
            || manifest.chain_id != chain_id
            || manifest.matcher_config_hash != matcher_config.digest()
        {
            bail!("matcher backup identity differs from the requested deployment");
        }
        let journal_path = directory.join(BACKUP_JOURNAL);
        if sha256_file(&journal_path)? != manifest.journal_sha256 {
            bail!("matcher backup journal hash mismatch");
        }
        let backup_snapshot = snapshot_path(&journal_path);
        match (manifest.snapshot_sha256, backup_snapshot.exists()) {
            (Some(expected), true) if sha256_file(&backup_snapshot)? == expected => {}
            (None, false) => {}
            _ => bail!("matcher backup snapshot presence or hash mismatch"),
        }
        let backup_archive = execution_archive_path(&journal_path);
        match (manifest.version, manifest.execution_archive_sha256) {
            (2, Some(expected))
                if backup_archive.exists() && sha256_file(&backup_archive)? == expected => {}
            (1, None) if !backup_archive.exists() => {}
            _ => bail!("matcher backup execution archive presence or hash mismatch"),
        }
        let (journal, engine) = Self::open(journal_path, engine_config, matcher_config, chain_id)?;
        if journal.head_sequence != manifest.head_sequence
            || journal.head_receipt_hash != manifest.head_receipt_hash
            || !manifest_execution_head_matches(&journal, &manifest)
        {
            bail!("matcher backup replay head differs from its manifest");
        }
        Ok((journal, engine, manifest))
    }

    /// Materialize a verified backup at a fresh journal path, then reopen and
    /// replay the restored pair before reporting success.
    pub fn restore_backup_to(
        directory: impl AsRef<Path>,
        destination_journal: impl AsRef<Path>,
        engine_config: EngineConfig,
        matcher_config: CentralMatcherConfigV1,
        chain_id: Hash32,
    ) -> Result<(Self, Engine, MatcherBackupManifestV1)> {
        let directory = directory.as_ref();
        let destination_journal = destination_journal.as_ref();
        let destination_snapshot = snapshot_path(destination_journal);
        let destination_archive = execution_archive_path(destination_journal);
        if destination_journal.exists()
            || destination_snapshot.exists()
            || destination_archive.exists()
        {
            bail!("refusing to overwrite an existing matcher restore target");
        }
        let (verified, _, manifest) = Self::open_backup(
            directory,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )?;
        drop(verified);
        if let Some(parent) = destination_journal.parent() {
            fs::create_dir_all(parent)?;
        }
        copy_private_file(&directory.join(BACKUP_JOURNAL), destination_journal)?;
        if manifest.snapshot_sha256.is_some() {
            copy_private_file(
                &snapshot_path(&directory.join(BACKUP_JOURNAL)),
                &destination_snapshot,
            )?;
        }
        if manifest.execution_archive_sha256.is_some() {
            copy_private_file(
                &execution_archive_path(&directory.join(BACKUP_JOURNAL)),
                &destination_archive,
            )?;
        }
        sync_parent_directory(destination_journal)?;
        let (journal, engine) =
            Self::open(destination_journal, engine_config, matcher_config, chain_id)?;
        if journal.head_sequence != manifest.head_sequence
            || journal.head_receipt_hash != manifest.head_receipt_hash
            || !manifest_execution_head_matches(&journal, &manifest)
        {
            bail!("restored matcher journal head differs from verified backup");
        }
        Ok((journal, engine, manifest))
    }
}

#[derive(Debug)]
struct ExecutionArchiveScan {
    commitment: ExecutionArchiveCommitmentV1,
    logical_execution_sequence: u64,
    logical_execution_history_hash: Hash32,
    checkpoint_history_hash: Option<Hash32>,
    pending_prepare: Option<(Hash32, ExecutionArchivePrepareV1)>,
}

fn execution_archive_genesis(chain_id: Hash32, matcher_config_hash: Hash32) -> Hash32 {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&chain_id);
    bytes.extend_from_slice(&matcher_config_hash);
    tagged_hash("ECX/matcher-execution-archive-genesis/v1", &bytes)
}

fn execution_archive_record_hash(record_bytes: &[u8]) -> Hash32 {
    tagged_hash("ECX/matcher-execution-archive-record/v1", record_bytes)
}

fn validate_execution_archive_prepare(
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
    previous_sequence: u64,
    previous_history_hash: Hash32,
    prepare: &ExecutionArchivePrepareV1,
) -> Result<(u64, Hash32)> {
    if prepare.execution_receipts.is_empty() {
        bail!("execution archive prepare contains no execution receipts");
    }
    prepare
        .admission_receipt
        .verify(matcher_config)
        .context("execution archive contains an invalid taker admission")?;
    if prepare.admission_receipt.body.chain_id != chain_id
        || prepare.admission_receipt.body.matcher_config_hash != matcher_config.digest()
        || prepare.admission_receipt.body.command_hash != prepare.command_hash
    {
        bail!("execution archive taker admission identity is invalid");
    }
    let admission_hash = prepare.admission_receipt.receipt_hash();
    let mut next = previous_sequence;
    let mut history = previous_history_hash;
    for receipt in &prepare.execution_receipts {
        receipt
            .verify(matcher_config)
            .context("execution archive contains an invalid execution receipt")?;
        next = next
            .checked_add(1)
            .context("execution archive sequence overflow")?;
        if receipt.body.chain_id != chain_id
            || receipt.body.match_sequence != next
            || receipt.body.taker_admission_receipt_hash != admission_hash
            || receipt.body.admission_sequence != prepare.admission_receipt.body.global_sequence
            || receipt.body.observed_sidechain_height
                != prepare.admission_receipt.body.observed_sidechain_height
            || receipt.body.execution_parent.height
                != prepare.admission_receipt.body.observed_parent_height
            || receipt.body.execution_parent.median_time_past
                != prepare.admission_receipt.body.observed_parent_mtp
        {
            bail!("execution archive receipt context or sequence is invalid");
        }
        history = execution_history_next(history, receipt);
    }
    Ok((next, history))
}

fn read_execution_archive_record(
    input: &mut File,
    path: &Path,
) -> Result<Option<(ExecutionArchiveRecordV1, Hash32)>> {
    let mut magic = [0_u8; 4];
    let first = input
        .read(&mut magic[..1])
        .with_context(|| format!("reading execution archive {}", path.display()))?;
    if first == 0 {
        return Ok(None);
    }
    input
        .read_exact(&mut magic[1..])
        .with_context(|| format!("partial execution archive header in {}", path.display()))?;
    if &magic != EXECUTION_ARCHIVE_MAGIC {
        bail!("execution archive record magic is invalid");
    }
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .with_context(|| format!("partial execution archive length in {}", path.display()))?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .context("execution archive record length overflow")?;
    if length == 0 || length > MAX_EXECUTION_ARCHIVE_RECORD_BYTES {
        bail!("execution archive record length is outside the frozen bound");
    }
    let mut bytes = vec![0_u8; length];
    input
        .read_exact(&mut bytes)
        .with_context(|| format!("partial execution archive payload in {}", path.display()))?;
    let mut stored_hash = [0_u8; 32];
    input
        .read_exact(&mut stored_hash)
        .with_context(|| format!("partial execution archive hash in {}", path.display()))?;
    let computed_hash = execution_archive_record_hash(&bytes);
    if stored_hash != computed_hash {
        bail!("execution archive record hash mismatch");
    }
    let record: ExecutionArchiveRecordV1 =
        bincode::deserialize(&bytes).context("decoding execution archive record")?;
    Ok(Some((record, computed_hash)))
}

fn scan_execution_archive<F>(
    path: &Path,
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
    expected_prefix: Option<ExecutionArchiveCommitmentV1>,
    checkpoint_sequence: u64,
    mut on_committed: F,
) -> Result<ExecutionArchiveScan>
where
    F: FnMut(&ExecutionArchivePrepareV1) -> Result<()>,
{
    validate_regular_file(path)?;
    let genesis_hash = execution_archive_genesis(chain_id, matcher_config.digest());
    if expected_prefix.is_some_and(|expected| expected.genesis_hash != genesis_hash) {
        bail!("signed snapshot execution archive genesis differs from this deployment");
    }
    let mut input = File::open(path)
        .with_context(|| format!("opening execution archive {}", path.display()))?;
    let mut head_hash = genesis_hash;
    let mut record_count = 0_u64;
    let mut logical_sequence = 0_u64;
    let mut logical_history = execution_history_genesis(chain_id, matcher_config.digest());
    let mut checkpoint_history = (checkpoint_sequence == 0).then_some(logical_history);
    let mut pending: Option<(Hash32, ExecutionArchivePrepareV1)> = None;
    let mut expected_prefix_pending = false;
    if let Some(expected) = expected_prefix
        && expected.record_count == 0
        && expected.head_hash != genesis_hash
    {
        bail!("signed snapshot execution archive empty head is invalid");
    }

    while let Some((record, record_hash)) = read_execution_archive_record(&mut input, path)? {
        record_count = record_count
            .checked_add(1)
            .context("execution archive record count overflow")?;
        if record.version != ExecutionArchiveRecordV1::VERSION
            || record.ordinal != record_count
            || record.previous_record_hash != head_hash
        {
            bail!("execution archive physical hash chain is invalid");
        }
        head_hash = record_hash;
        match record.payload {
            ExecutionArchivePayloadV1::Prepare(prepare) => {
                if pending.replace((record_hash, *prepare)).is_some() {
                    bail!("execution archive prepare lacks a commit or abort record");
                }
            }
            ExecutionArchivePayloadV1::Commit {
                prepare_record_hash,
            } => {
                let (pending_hash, prepare) = pending
                    .take()
                    .context("execution archive commit has no preceding prepare")?;
                if pending_hash != prepare_record_hash {
                    bail!("execution archive commit references a different prepare");
                }
                let (next_sequence, next_history) = validate_execution_archive_prepare(
                    matcher_config,
                    chain_id,
                    logical_sequence,
                    logical_history,
                    &prepare,
                )?;
                if logical_sequence < checkpoint_sequence && next_sequence > checkpoint_sequence {
                    let mut sequence = logical_sequence;
                    let mut history = logical_history;
                    for receipt in &prepare.execution_receipts {
                        sequence = sequence
                            .checked_add(1)
                            .context("execution archive checkpoint sequence overflow")?;
                        history = execution_history_next(history, receipt);
                        if sequence == checkpoint_sequence {
                            checkpoint_history = Some(history);
                            break;
                        }
                    }
                }
                logical_sequence = next_sequence;
                logical_history = next_history;
                if logical_sequence == checkpoint_sequence {
                    checkpoint_history = Some(logical_history);
                }
                on_committed(&prepare)?;
            }
            ExecutionArchivePayloadV1::Abort {
                prepare_record_hash,
            } => {
                let (pending_hash, _) = pending
                    .take()
                    .context("execution archive abort has no preceding prepare")?;
                if pending_hash != prepare_record_hash {
                    bail!("execution archive abort references a different prepare");
                }
            }
        }
        if expected_prefix.is_some_and(|expected| expected.record_count == record_count) {
            let expected = expected_prefix.unwrap();
            if expected.head_hash != head_hash {
                bail!("execution archive disagrees with its signed snapshot prefix");
            }
            expected_prefix_pending = pending.is_some();
        }
    }
    if let Some(expected) = expected_prefix {
        if record_count < expected.record_count {
            bail!("execution archive is truncated before its signed snapshot prefix");
        }
        if expected_prefix_pending {
            bail!("signed snapshot commits an unresolved execution archive prepare");
        }
    }
    Ok(ExecutionArchiveScan {
        commitment: ExecutionArchiveCommitmentV1 {
            genesis_hash,
            head_hash,
            record_count,
        },
        logical_execution_sequence: logical_sequence,
        logical_execution_history_hash: logical_history,
        checkpoint_history_hash: checkpoint_history,
        pending_prepare: pending,
    })
}

fn append_execution_archive_payload(
    file: &mut File,
    path: &Path,
    commitment: &mut ExecutionArchiveCommitmentV1,
    payload: ExecutionArchivePayloadV1,
) -> Result<Hash32> {
    let ordinal = commitment
        .record_count
        .checked_add(1)
        .context("execution archive record count overflow")?;
    let record = ExecutionArchiveRecordV1 {
        version: ExecutionArchiveRecordV1::VERSION,
        ordinal,
        previous_record_hash: commitment.head_hash,
        payload,
    };
    let bytes = bincode::serialize(&record).context("encoding execution archive record")?;
    if bytes.is_empty() || bytes.len() > MAX_EXECUTION_ARCHIVE_RECORD_BYTES {
        bail!("execution archive record exceeds the frozen size bound");
    }
    let record_hash = execution_archive_record_hash(&bytes);
    let length = u32::try_from(bytes.len()).context("execution archive record length overflow")?;
    file.write_all(EXECUTION_ARCHIVE_MAGIC)
        .and_then(|_| file.write_all(&length.to_be_bytes()))
        .and_then(|_| file.write_all(&bytes))
        .and_then(|_| file.write_all(&record_hash))
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_data())
        .with_context(|| format!("durably appending execution archive {}", path.display()))?;
    commitment.head_hash = record_hash;
    commitment.record_count = ordinal;
    Ok(record_hash)
}

fn sorted_hot_execution_batches(
    executions: &HashMap<Hash32, Vec<MatcherExecutionReceiptV2>>,
    admissions: &HashMap<Hash32, CentralMatcherReceiptV1>,
) -> Result<Vec<ExecutionArchivePrepareV1>> {
    let mut batches = executions
        .iter()
        .map(|(command_hash, receipts)| {
            let admission_receipt = admissions
                .get(command_hash)
                .cloned()
                .context("durable execution batch is missing its taker admission")?;
            Ok(ExecutionArchivePrepareV1 {
                command_hash: *command_hash,
                admission_receipt,
                execution_receipts: receipts.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    batches.sort_by_key(|batch| {
        (
            batch
                .execution_receipts
                .first()
                .map_or(u64::MAX, |receipt| receipt.body.match_sequence),
            batch.command_hash,
        )
    });
    Ok(batches)
}

fn execution_archive_suffix_batch(
    batch: &ExecutionArchivePrepareV1,
    previous_sequence: u64,
) -> Option<ExecutionArchivePrepareV1> {
    let execution_receipts = batch
        .execution_receipts
        .iter()
        .filter(|receipt| receipt.body.match_sequence > previous_sequence)
        .cloned()
        .collect::<Vec<_>>();
    (!execution_receipts.is_empty()).then(|| ExecutionArchivePrepareV1 {
        command_hash: batch.command_hash,
        admission_receipt: batch.admission_receipt.clone(),
        execution_receipts,
    })
}

#[allow(clippy::too_many_arguments)]
fn open_and_reconcile_execution_archive(
    journal_path: &Path,
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
    expected_prefix: Option<ExecutionArchiveCommitmentV1>,
    retained_previous_sequence: u64,
    retained_previous_history_hash: Hash32,
    head_execution_sequence: u64,
    head_execution_history_hash: Hash32,
    executions: &HashMap<Hash32, Vec<MatcherExecutionReceiptV2>>,
    admissions: &HashMap<Hash32, CentralMatcherReceiptV1>,
) -> Result<(PathBuf, File, ExecutionArchiveCommitmentV1)> {
    let path = execution_archive_path(journal_path);
    let existed = path.exists();
    if expected_prefix.is_some() && !existed {
        bail!("signed matcher snapshot execution archive is missing");
    }
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&path)
        .with_context(|| format!("opening private execution archive {}", path.display()))?;
    validate_private_permissions(&path)?;
    if !existed {
        sync_parent_directory(&path)?;
    }

    let expected_batches = sorted_hot_execution_batches(executions, admissions)?;
    let mut archived_hot = Vec::new();
    let mut scan = scan_execution_archive(
        &path,
        matcher_config,
        chain_id,
        expected_prefix,
        retained_previous_sequence,
        |batch| {
            if let Some(suffix) = execution_archive_suffix_batch(batch, retained_previous_sequence)
            {
                archived_hot.push(suffix);
            }
            Ok(())
        },
    )?;
    if scan.logical_execution_sequence > head_execution_sequence {
        bail!("execution archive contains a committed batch beyond the durable matcher head");
    }

    if let Some((prepare_hash, pending)) = scan.pending_prepare.clone() {
        let is_durable_successor = expected_batches.iter().any(|batch| {
            batch == &pending
                && batch.execution_receipts.first().is_some_and(|receipt| {
                    receipt.body.match_sequence == scan.logical_execution_sequence.saturating_add(1)
                })
        });
        let payload = if is_durable_successor {
            ExecutionArchivePayloadV1::Commit {
                prepare_record_hash: prepare_hash,
            }
        } else {
            ExecutionArchivePayloadV1::Abort {
                prepare_record_hash: prepare_hash,
            }
        };
        append_execution_archive_payload(&mut file, &path, &mut scan.commitment, payload)
            .context("resolving trailing execution archive prepare before service")?;
    }

    loop {
        archived_hot.clear();
        scan = scan_execution_archive(
            &path,
            matcher_config,
            chain_id,
            expected_prefix,
            retained_previous_sequence,
            |batch| {
                if let Some(suffix) =
                    execution_archive_suffix_batch(batch, retained_previous_sequence)
                {
                    archived_hot.push(suffix);
                }
                Ok(())
            },
        )?;
        if scan.pending_prepare.is_some() {
            bail!("execution archive prepare remains unresolved after recovery");
        }
        if scan.logical_execution_sequence >= head_execution_sequence {
            break;
        }
        let next_sequence = scan
            .logical_execution_sequence
            .checked_add(1)
            .context("execution archive sequence overflow")?;
        let batch = expected_batches
            .iter()
            .find(|batch| {
                batch
                    .execution_receipts
                    .first()
                    .is_some_and(|receipt| receipt.body.match_sequence == next_sequence)
            })
            .cloned()
            .context(
                "execution archive is missing durable history outside the recoverable hot suffix",
            )?;
        let prepare_hash = append_execution_archive_payload(
            &mut file,
            &path,
            &mut scan.commitment,
            ExecutionArchivePayloadV1::Prepare(Box::new(batch)),
        )?;
        append_execution_archive_payload(
            &mut file,
            &path,
            &mut scan.commitment,
            ExecutionArchivePayloadV1::Commit {
                prepare_record_hash: prepare_hash,
            },
        )?;
    }

    archived_hot.clear();
    scan = scan_execution_archive(
        &path,
        matcher_config,
        chain_id,
        expected_prefix,
        retained_previous_sequence,
        |batch| {
            if let Some(suffix) = execution_archive_suffix_batch(batch, retained_previous_sequence)
            {
                archived_hot.push(suffix);
            }
            Ok(())
        },
    )?;
    if scan.pending_prepare.is_some()
        || scan.logical_execution_sequence != head_execution_sequence
        || scan.logical_execution_history_hash != head_execution_history_hash
        || scan.checkpoint_history_hash != Some(retained_previous_history_hash)
        || archived_hot != expected_batches
    {
        bail!("execution archive does not exactly reproduce the durable matcher history");
    }
    Ok((path, file, scan.commitment))
}

fn manifest_execution_head_matches(journal: &Journal, manifest: &MatcherBackupManifestV1) -> bool {
    let archive_matches = if manifest.version == 1 {
        true
    } else {
        manifest.execution_archive_genesis_hash == journal.execution_archive_genesis_hash
            && manifest.execution_archive_head_hash == journal.execution_archive_head_hash
            && manifest.execution_archive_record_count == journal.execution_archive_record_count
    };
    let retained_checkpoint_matches = if manifest.retained_execution_previous_sequence == 0
        && manifest.retained_execution_previous_history_hash == [0; 32]
    {
        // Frozen manifests predate safe receipt pruning. They can identify an
        // unpruned history, whose in-memory base hash is the nonzero genesis.
        journal.retained_execution_previous_sequence == 0
    } else {
        journal.retained_execution_previous_sequence
            == manifest.retained_execution_previous_sequence
            && journal.retained_execution_previous_history_hash
                == manifest.retained_execution_previous_history_hash
    };
    if manifest.head_execution_sequence == 0 && manifest.head_execution_history_hash == [0; 32] {
        // These serde-default values identify a frozen legacy V1 manifest,
        // which predates the execution history commitment. It is compatible
        // only with a journal that also has no V2 executions.
        journal.head_execution_sequence == 0 && retained_checkpoint_matches && archive_matches
    } else {
        journal.head_execution_sequence == manifest.head_execution_sequence
            && journal.head_execution_history_hash == manifest.head_execution_history_hash
            && retained_checkpoint_matches
            && archive_matches
    }
}

fn copy_private_file(source: &Path, destination: &Path) -> Result<()> {
    validate_regular_file(source)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut input = File::open(source)
        .with_context(|| format!("opening matcher backup source {}", source.display()))?;
    let mut output = options
        .open(destination)
        .with_context(|| format!("creating matcher backup file {}", destination.display()))?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<Hash32> {
    validate_regular_file(path)?;
    let mut input = File::open(path)
        .with_context(|| format!("opening matcher backup file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn validate_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading matcher backup file metadata {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!(
            "matcher backup path {} is not a regular file",
            path.display()
        );
    }
    validate_private_permissions(path)
}

fn snapshot_path(journal_path: &Path) -> PathBuf {
    let mut value = journal_path.as_os_str().to_os_string();
    value.push(".snapshot");
    PathBuf::from(value)
}

fn snapshot_temporary_path(journal_path: &Path) -> PathBuf {
    let mut value = journal_path.as_os_str().to_os_string();
    value.push(".snapshot.tmp");
    PathBuf::from(value)
}

fn execution_archive_path(journal_path: &Path) -> PathBuf {
    let mut value = journal_path.as_os_str().to_os_string();
    value.push(".execution-archive");
    PathBuf::from(value)
}

fn load_snapshot(
    journal_path: &Path,
    engine_config: &EngineConfig,
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
) -> Result<Option<LoadedSnapshot>> {
    let path = snapshot_path(journal_path);
    if !path.exists() {
        return Ok(None);
    }
    validate_private_permissions(&path)?;
    let metadata = fs::metadata(&path)
        .with_context(|| format!("reading matcher snapshot metadata {}", path.display()))?;
    if metadata.len() > (MAX_SNAPSHOT_BYTES + 77) as u64 {
        bail!("matcher snapshot exceeds the bounded snapshot size");
    }
    let bytes =
        fs::read(&path).with_context(|| format!("reading matcher snapshot {}", path.display()))?;
    if bytes.len() < 4 + 1 + 8 + 64 || &bytes[..4] != SNAPSHOT_MAGIC {
        bail!("matcher snapshot envelope is invalid");
    }
    let envelope_version = bytes[4];
    if !matches!(envelope_version, 1..=5) {
        bail!("unsupported matcher snapshot envelope version");
    }
    let payload_length = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
    let payload_length =
        usize::try_from(payload_length).context("matcher snapshot length overflow")?;
    if payload_length > MAX_SNAPSHOT_BYTES || bytes.len() != 13 + payload_length + 64 {
        bail!("matcher snapshot length is invalid");
    }
    let payload_bytes = &bytes[13..13 + payload_length];
    let signature = Signature64(bytes[13 + payload_length..].try_into().unwrap());
    verify_snapshot_signature(matcher_config.signer.0, payload_bytes, signature)?;
    let payload = match envelope_version {
        1 => {
            let payload: SnapshotPayloadV1 = bincode::deserialize(payload_bytes)
                .context("decoding frozen v1 matcher snapshot payload")?;
            if payload.version != 1 {
                bail!("v1 matcher snapshot envelope contains a non-v1 payload");
            }
            if let Some(context) = &payload.last_elements_context {
                context.validate()?;
            }
            LoadedSnapshot {
                chain_id: payload.chain_id,
                matcher_config_hash: payload.matcher_config_hash,
                engine: payload.engine,
                head_sequence: payload.head_sequence,
                head_receipt_hash: payload.head_receipt_hash,
                receipts_by_command: payload.receipts_by_command,
                retained_execution_previous_sequence: 0,
                retained_execution_previous_history_hash: execution_history_genesis(
                    chain_id,
                    matcher_config.digest(),
                ),
                head_execution_sequence: 0,
                head_execution_history_hash: execution_history_genesis(
                    chain_id,
                    matcher_config.digest(),
                ),
                execution_receipts_by_command: Vec::new(),
                execution_archive: None,
                last_elements_context: payload.last_elements_context.map(Into::into),
                last_receipt_context: payload.last_receipt_context,
            }
        }
        2 => {
            let payload: SnapshotPayloadV2 = bincode::deserialize(payload_bytes)
                .context("decoding v2 matcher snapshot payload")?;
            if payload.version != 2 {
                bail!("v2 matcher snapshot envelope contains a non-v2 payload");
            }
            if let Some(context) = &payload.last_elements_context {
                context.validate()?;
            }
            LoadedSnapshot {
                chain_id: payload.chain_id,
                matcher_config_hash: payload.matcher_config_hash,
                engine: payload.engine,
                head_sequence: payload.head_sequence,
                head_receipt_hash: payload.head_receipt_hash,
                receipts_by_command: payload.receipts_by_command,
                retained_execution_previous_sequence: 0,
                retained_execution_previous_history_hash: execution_history_genesis(
                    chain_id,
                    matcher_config.digest(),
                ),
                head_execution_sequence: 0,
                head_execution_history_hash: execution_history_genesis(
                    chain_id,
                    matcher_config.digest(),
                ),
                execution_receipts_by_command: Vec::new(),
                execution_archive: None,
                last_elements_context: payload.last_elements_context,
                last_receipt_context: payload.last_receipt_context,
            }
        }
        3 => {
            let payload: SnapshotPayloadV3 = bincode::deserialize(payload_bytes)
                .context("decoding v3 matcher snapshot payload")?;
            if payload.version != 3 {
                bail!("v3 matcher snapshot envelope contains a non-v3 payload");
            }
            if let Some(context) = &payload.last_elements_context {
                context.validate()?;
            }
            LoadedSnapshot {
                chain_id: payload.chain_id,
                matcher_config_hash: payload.matcher_config_hash,
                engine: payload.engine,
                head_sequence: payload.head_sequence,
                head_receipt_hash: payload.head_receipt_hash,
                receipts_by_command: payload.receipts_by_command,
                retained_execution_previous_sequence: 0,
                retained_execution_previous_history_hash: execution_history_genesis(
                    chain_id,
                    matcher_config.digest(),
                ),
                head_execution_sequence: payload.head_execution_sequence,
                head_execution_history_hash: payload.head_execution_history_hash,
                execution_receipts_by_command: payload.execution_receipts_by_command,
                execution_archive: None,
                last_elements_context: payload.last_elements_context,
                last_receipt_context: payload.last_receipt_context,
            }
        }
        4 => {
            let payload: SnapshotPayloadV4 = bincode::deserialize(payload_bytes)
                .context("decoding v4 matcher snapshot payload")?;
            if payload.version != 4 {
                bail!("v4 matcher snapshot envelope contains a non-v4 payload");
            }
            if let Some(context) = &payload.last_elements_context {
                context.validate()?;
            }
            LoadedSnapshot {
                chain_id: payload.chain_id,
                matcher_config_hash: payload.matcher_config_hash,
                engine: payload.engine,
                head_sequence: payload.head_sequence,
                head_receipt_hash: payload.head_receipt_hash,
                receipts_by_command: payload.receipts_by_command,
                retained_execution_previous_sequence: payload.retained_execution_previous_sequence,
                retained_execution_previous_history_hash: payload
                    .retained_execution_previous_history_hash,
                head_execution_sequence: payload.head_execution_sequence,
                head_execution_history_hash: payload.head_execution_history_hash,
                execution_receipts_by_command: payload.execution_receipts_by_command,
                execution_archive: None,
                last_elements_context: payload.last_elements_context,
                last_receipt_context: payload.last_receipt_context,
            }
        }
        5 => {
            let payload: SnapshotPayloadV5 = bincode::deserialize(payload_bytes)
                .context("decoding v5 matcher snapshot payload")?;
            if payload.version != 5 {
                bail!("v5 matcher snapshot envelope contains a non-v5 payload");
            }
            if let Some(context) = &payload.last_elements_context {
                context.validate()?;
            }
            LoadedSnapshot {
                chain_id: payload.chain_id,
                matcher_config_hash: payload.matcher_config_hash,
                engine: payload.engine,
                head_sequence: payload.head_sequence,
                head_receipt_hash: payload.head_receipt_hash,
                receipts_by_command: payload.receipts_by_command,
                retained_execution_previous_sequence: payload.retained_execution_previous_sequence,
                retained_execution_previous_history_hash: payload
                    .retained_execution_previous_history_hash,
                head_execution_sequence: payload.head_execution_sequence,
                head_execution_history_hash: payload.head_execution_history_hash,
                execution_receipts_by_command: payload.execution_receipts_by_command,
                execution_archive: Some(payload.execution_archive),
                last_elements_context: payload.last_elements_context,
                last_receipt_context: payload.last_receipt_context,
            }
        }
        _ => unreachable!("snapshot envelope version checked above"),
    };
    if payload.chain_id != chain_id
        || payload.matcher_config_hash != matcher_config.digest()
        || payload.head_sequence < matcher_config.genesis_sequence
    {
        bail!("matcher snapshot identity or receipt head is invalid");
    }
    payload
        .engine
        .validate_restored(engine_config)
        .context("validating restored matcher snapshot")?;
    if payload.engine.chain_height()
        != payload
            .last_receipt_context
            .map_or(payload.engine.chain_height(), |context| {
                context.sidechain_height
            })
    {
        bail!("matcher snapshot engine height disagrees with its receipt context");
    }
    Ok(Some(payload))
}

fn validate_entry(
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
    previous_sequence: u64,
    previous_receipt_hash: Hash32,
    entry: &JournalEntryV1,
) -> Result<crate::CommandCommitment> {
    let commitment = match (entry.version, entry.elements_context.as_ref()) {
        (JournalEntryV1::LEGACY_VERSION, None) => command_commitment(&entry.command, chain_id)?,
        (JournalEntryV1::VERSION, Some(context)) => {
            command_commitment_with_context(&entry.command, chain_id, context)?
        }
        (JournalEntryV1::LEGACY_VERSION, Some(_)) => {
            bail!("legacy matcher journal entry must not contain an Elements context")
        }
        (JournalEntryV1::VERSION, None) => {
            bail!("v2 matcher journal entry is missing its Elements context")
        }
        _ => bail!("unsupported matcher journal entry version"),
    };
    validate_receipt_binding(
        matcher_config,
        chain_id,
        previous_sequence,
        previous_receipt_hash,
        &entry.receipt,
        &commitment,
        entry
            .elements_context
            .as_ref()
            .map(ElementsConsensusContextV1::matcher_context)
            .transpose()?,
    )?;
    Ok(commitment)
}

fn decode_journal_entry(bytes: &[u8]) -> Result<DecodedJournalEntry> {
    #[derive(Deserialize)]
    struct VersionProbe {
        version: u8,
    }
    let version = serde_json::from_slice::<VersionProbe>(bytes)
        .context("decoding matcher journal version")?
        .version;
    match version {
        JournalEntryV1::LEGACY_VERSION | JournalEntryV1::VERSION => serde_json::from_slice(bytes)
            .map(DecodedJournalEntry::V1)
            .context("decoding frozen v1 matcher journal entry"),
        JournalEntryV2::VERSION => serde_json::from_slice(bytes)
            .map(DecodedJournalEntry::V2)
            .context("decoding v2 matcher journal entry"),
        JournalEntryV3::VERSION => serde_json::from_slice(bytes)
            .map(DecodedJournalEntry::V3)
            .context("decoding v3 matcher execution journal entry"),
        _ => bail!("unsupported matcher journal entry version"),
    }
}

fn validate_decoded_entry(
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
    previous_sequence: u64,
    previous_receipt_hash: Hash32,
    entry: &DecodedJournalEntry,
) -> Result<crate::CommandCommitment> {
    match entry {
        DecodedJournalEntry::V1(entry) => validate_entry(
            matcher_config,
            chain_id,
            previous_sequence,
            previous_receipt_hash,
            entry,
        ),
        DecodedJournalEntry::V2(entry) => {
            if entry.version != JournalEntryV2::VERSION {
                bail!("unsupported v2 matcher journal entry version");
            }
            let commitment = command_commitment_with_context_v2(
                &entry.command,
                chain_id,
                &entry.elements_context,
            )?;
            validate_receipt_binding(
                matcher_config,
                chain_id,
                previous_sequence,
                previous_receipt_hash,
                &entry.receipt,
                &commitment,
                Some(entry.elements_context.matcher_context()?),
            )?;
            Ok(commitment)
        }
        DecodedJournalEntry::V3(entry) => {
            if entry.version != JournalEntryV3::VERSION {
                bail!("unsupported v3 matcher journal entry version");
            }
            let commitment = command_commitment_with_context_v2(
                &entry.command,
                chain_id,
                &entry.elements_context,
            )?;
            validate_receipt_binding(
                matcher_config,
                chain_id,
                previous_sequence,
                previous_receipt_hash,
                &entry.receipt,
                &commitment,
                Some(entry.elements_context.matcher_context()?),
            )?;
            Ok(commitment)
        }
    }
}

fn execution_history_genesis(chain_id: Hash32, matcher_config_hash: Hash32) -> Hash32 {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&chain_id);
    bytes.extend_from_slice(&matcher_config_hash);
    tagged_hash("ECX/matcher-execution-history-genesis/v2", &bytes)
}

fn execution_history_next(previous: Hash32, receipt: &MatcherExecutionReceiptV2) -> Hash32 {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&previous);
    bytes.extend_from_slice(&receipt.receipt_hash());
    tagged_hash("ECX/matcher-execution-history-next/v2", &bytes)
}

fn validate_execution_receipts(
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
    previous_sequence: u64,
    previous_history_hash: Hash32,
    entry: &DecodedJournalEntry,
    executions: Option<&[StagedMatcherExecutionV2]>,
) -> Result<(u64, Hash32)> {
    let receipts = entry.execution_receipts();
    match (entry, executions) {
        (DecodedJournalEntry::V3(_), Some(executions)) => {
            let relations = executions
                .iter()
                .map(|execution| MatcherExecutionRelationV2 {
                    maker: &execution.maker,
                    taker: &execution.taker,
                    trade: &execution.trade,
                    taker_admission: entry.receipt(),
                })
                .collect::<Vec<_>>();
            let (_, next) = verify_matcher_execution_receipt_batch_v2(
                matcher_config,
                chain_id,
                previous_sequence,
                &relations,
                receipts,
            )
            .context("execution receipts do not match exact staged fills")?;
            let history = receipts
                .iter()
                .fold(previous_history_hash, execution_history_next);
            Ok((next, history))
        }
        (DecodedJournalEntry::V3(_), None) => {
            // Snapshot-covered replay lacks the pre-command book needed to
            // reconstruct exact fills, but still authenticates every signed
            // receipt, admission binding, cursor, context and history hash.
            let mut next = previous_sequence;
            let mut history = previous_history_hash;
            for receipt in receipts {
                receipt
                    .verify(matcher_config)
                    .context("invalid durable execution receipt signature")?;
                next = next.checked_add(1).context("execution sequence overflow")?;
                if receipt.body.chain_id != chain_id
                    || receipt.body.match_sequence != next
                    || receipt.body.taker_admission_receipt_hash != entry.receipt().receipt_hash()
                    || receipt.body.admission_sequence != entry.receipt().body.global_sequence
                    || receipt.body.observed_sidechain_height
                        != entry.receipt().body.observed_sidechain_height
                    || receipt.body.execution_parent.height
                        != entry.receipt().body.observed_parent_height
                    || receipt.body.execution_parent.median_time_past
                        != entry.receipt().body.observed_parent_mtp
                {
                    bail!("durable execution receipt context or sequence is invalid");
                }
                history = execution_history_next(history, receipt);
            }
            Ok((next, history))
        }
        (DecodedJournalEntry::V1(_) | DecodedJournalEntry::V2(_), None) => {
            if receipts.is_empty() {
                Ok((previous_sequence, previous_history_hash))
            } else {
                bail!("legacy journal entry contains V2 execution receipts")
            }
        }
        (DecodedJournalEntry::V1(_) | DecodedJournalEntry::V2(_), Some(executions)) => {
            if executions.is_empty() {
                Ok((previous_sequence, previous_history_hash))
            } else {
                bail!("legacy journal entry cannot be paired with staged V2 executions")
            }
        }
    }
}

fn validate_receipt_binding(
    matcher_config: &CentralMatcherConfigV1,
    chain_id: Hash32,
    previous_sequence: u64,
    previous_receipt_hash: Hash32,
    receipt: &CentralMatcherReceiptV1,
    commitment: &crate::CommandCommitment,
    elements_context: Option<MatcherConsensusContextV1>,
) -> Result<()> {
    receipt
        .verify(matcher_config)
        .context("invalid central matcher signature")?;
    let expected_sequence = previous_sequence
        .checked_add(1)
        .context("central matcher sequence overflow")?;
    if receipt.body.chain_id != chain_id
        || receipt.body.global_sequence != expected_sequence
        || receipt.body.previous_receipt_hash != previous_receipt_hash
    {
        bail!("matcher receipt does not extend the durable receipt chain");
    }
    if receipt.body.command_kind != commitment.command_kind
        || receipt.body.command_hash != commitment.command_hash
        || receipt.body.availability_root != commitment.availability_root
    {
        bail!("matcher receipt does not commit to its journal command");
    }
    if elements_context.is_some_and(|expected| {
        receipt.body.observed_sidechain_height != expected.sidechain_height
            || receipt.body.observed_parent_height != expected.parent_height
            || receipt.body.observed_parent_mtp != expected.parent_mtp
            || receipt.body.forced_inbox_cursor != expected.forced_inbox_cursor
    }) {
        bail!("matcher receipt does not commit to its Elements context");
    }
    Ok(())
}

fn receipt_context(receipt: &CentralMatcherReceiptV1) -> Result<MatcherConsensusContextV1> {
    MatcherConsensusContextV1 {
        sidechain_height: receipt.body.observed_sidechain_height,
        parent_height: receipt.body.observed_parent_height,
        parent_mtp: receipt.body.observed_parent_mtp,
        forced_inbox_cursor: receipt.body.forced_inbox_cursor,
    }
    .validate()
}

fn validate_context_progression(
    previous_receipt: Option<&MatcherConsensusContextV1>,
    previous_elements: Option<&ElementsConsensusContextV2>,
    current_receipt: MatcherConsensusContextV1,
    current_elements: Option<&ElementsConsensusContextV2>,
) -> Result<()> {
    if let Some(previous) = previous_receipt {
        if current_receipt.sidechain_height < previous.sidechain_height
            || current_receipt.parent_height < previous.parent_height
            || current_receipt.parent_mtp < previous.parent_mtp
            || current_receipt.forced_inbox_cursor < previous.forced_inbox_cursor
        {
            bail!("matcher receipt consensus context regressed");
        }
        if current_receipt.sidechain_height == previous.sidechain_height
            && current_receipt != *previous
        {
            bail!("matcher receipt consensus context changed at the same sidechain height");
        }
        if current_receipt.parent_height == previous.parent_height
            && current_receipt.parent_mtp != previous.parent_mtp
        {
            bail!("matcher receipt parent MTP changed at the same parent height");
        }
    }

    match (previous_elements, current_elements) {
        (Some(previous), Some(current)) => current.validate_successor_of(previous)?,
        (Some(_), None) => bail!("matcher journal downgraded after full Elements context binding"),
        _ => {}
    }
    Ok(())
}

fn read_bounded_record<R: BufRead>(reader: &mut R, line_number: usize) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .with_context(|| format!("reading matcher journal line {line_number}"))?;
        if buffer.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            bail!("unterminated matcher journal line {line_number} (refusing partial recovery)");
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(buffer.len());
        if line.len().saturating_add(take) > MAX_JOURNAL_ENTRY_BYTES {
            bail!(
                "matcher journal line {line_number} exceeds the {MAX_JOURNAL_ENTRY_BYTES}-byte bound"
            );
        }
        line.extend_from_slice(&buffer[..take]);
        let consumed = take + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            if line.is_empty() {
                bail!("empty matcher journal line {line_number}");
            }
            return Ok(Some(line));
        }
    }
}

#[cfg(unix)]
fn validate_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .with_context(|| format!("reading matcher journal permissions {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "matcher journal {} permissions must not grant group/other access (mode {mode:o})",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting private permissions on {}", path.display()))
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "setting private directory permissions on {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn validate_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing matcher journal directory {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        CentralMatcherConfigV1, MatcherExecutionReceiptV2, OrderRiskCommitmentV2, SignedLimitOrder,
        XOnlyKey,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use tempfile::tempdir;

    use super::*;
    use crate::{
        BondInboxSnapshotV2, CapitalMode, CapitalSnapshotV2, CentralMatcherSigner, MARKET,
        MatcherExecutionSnapshotV2, OracleModeV2, OracleSnapshotV2, Side, SubmitOrderRequest,
        SubmitOrderRequestV2, TimeInForce, command_commitment, engine::protocol_limit_order,
        matcher_public_key,
    };

    fn order(trader: &str, client_id: &str, side: Side, price: u64) -> SubmitOrderRequest {
        SubmitOrderRequest {
            client_order_id: client_id.into(),
            chain_id: "demo-chain".into(),
            trader: trader.into(),
            market: MARKET.into(),
            side,
            limit_price_ticks: price,
            quantity_lots: 5,
            time_in_force: TimeInForce::Gtc,
            post_only: false,
            reduce_only: false,
            max_fee_bps: 25,
            nonce: 1,
            valid_from_height: 0,
            expires_at_height: 1_000,
            signature: String::new(),
        }
    }

    fn signer() -> (CentralMatcherConfigV1, CentralMatcherSigner, Hash32) {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let chain_id = [9; 32];
        let config = CentralMatcherConfigV1 {
            version: 1,
            key_epoch: 0,
            signer: XOnlyKey(matcher_public_key(&secret).serialize()),
            genesis_sequence: 0,
            genesis_receipt_hash: [8; 32],
            forced_inclusion_blocks: 6,
        };
        let signer =
            CentralMatcherSigner::new(config.clone(), secret, chain_id, 100, 900_000, 1_000, 0)
                .unwrap();
        (config, signer, chain_id)
    }

    fn elements_context(height: u64, hash_byte: u8, root_byte: u8) -> ElementsConsensusContextV2 {
        ElementsConsensusContextV2 {
            sidechain_height: height,
            sidechain_block_hash: [hash_byte; 32],
            exchange_state_root: [root_byte; 32],
            forced_inbox_head_root: [0x31; 32],
            forced_inbox_entry_count: 0,
            forced_inbox_processed_cursor: 0,
            deposit_inbox_head_root: [0x41; 32],
            deposit_inbox_entry_count: 0,
            deposit_inbox_processed_cursor: 0,
            parent_height: 900_000,
            parent_mtp: 1_700_000_000,
            parent_block_hash: [0x51; 32],
            source_parent_height: 900_000,
            capital_snapshot: None,
        }
    }

    fn capital_snapshot(exchange_state_root: Hash32, execution_sequence: u64) -> CapitalSnapshotV2 {
        CapitalSnapshotV2 {
            version: CapitalSnapshotV2::VERSION,
            exchange_state_root,
            configuration_hash: [0x71; 32],
            bond_asset_id: [0x72; 32],
            bond_deployment_commitment: [0x73; 32],
            transition_program_id: [0x74; 32],
            transition_cmr: [0x75; 32],
            covenant_state_hash: [0x76; 32],
            bond_state_root: [0x77; 32],
            funding_state_root: [0x78; 32],
            insurance_reserve_quote_units: 125,
            outstanding_bond_units: 100,
            nav_quote_units_per_bond: 125_000_000,
            deficit_quote_units: 100,
            target_reserve_quote_units: 125,
            coverage_bps: 12_500,
            mode: CapitalMode::Normal,
            minimum_authenticated_price: 1,
            maximum_authenticated_price: 10,
            funding_epoch: 1,
            funding_rate_ppm: 0,
            redemption_queue_root: [0x79; 32],
            redemption_head: 0,
            redemption_tail: 0,
            queued_redemption_bond_units: 0,
            oracle: OracleSnapshotV2 {
                certificate_hash: [0x7a; 32],
                valid_through_parent_mtp: 1_700_000_100,
                mode: OracleModeV2::Normal,
            },
            encrypted_availability_root: [0x7b; 32],
            bond_inbox: BondInboxSnapshotV2 {
                head_root: [0x7c; 32],
                entry_count: 0,
                processed_root: [0x7d; 32],
                processed_cursor: 0,
                outcome_root: [0x7e; 32],
                outcome_count: 0,
                node_verified_source_head_root: [0x7c; 32],
                node_verified_source_entry_count: 0,
            },
            matcher_execution: MatcherExecutionSnapshotV2 {
                receipt_batch_root: [0x7f; 32],
                previous_sequence: 0,
                sequence: execution_sequence,
            },
            last_transition_sidechain_height: 100,
            legacy_fee_pool_quote_units: 0,
        }
    }

    fn signed_v2_order(
        secret_byte: u8,
        client_byte: u8,
        side: Side,
        price: u64,
        quantity: u64,
        nonce: u64,
    ) -> SubmitOrderRequestV2 {
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (trader, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut order = SubmitOrderRequest {
            client_order_id: hex::encode([client_byte; 16]),
            chain_id: hex::encode([9; 32]),
            trader: hex::encode(trader.serialize()),
            market: MARKET.into(),
            side,
            limit_price_ticks: price,
            quantity_lots: quantity,
            time_in_force: TimeInForce::Gtc,
            post_only: false,
            reduce_only: false,
            max_fee_bps: 25,
            nonce,
            valid_from_height: 90,
            expires_at_height: 110,
            signature: String::new(),
        };
        let signed =
            SignedLimitOrder::sign(protocol_limit_order(&order).unwrap(), &secret).unwrap();
        order.signature = hex::encode(signed.signature.0);
        let configuration_hash = [0x71; 32];
        let risk = OrderRiskCommitmentV2::sign(
            configuration_hash,
            signed.order_id(),
            signed.order.trader,
            1_000,
            &secret,
        )
        .unwrap();
        SubmitOrderRequestV2 {
            order,
            configuration_hash: hex::encode(configuration_hash),
            initial_margin_bps: 1_000,
            risk_commitment_signature: hex::encode(risk.signature.0),
        }
    }

    fn append_v2_order(
        journal: &mut Journal,
        engine: &mut Engine,
        signer: &CentralMatcherSigner,
        context: &ElementsConsensusContextV2,
        request: SubmitOrderRequestV2,
        received_at_ms: u64,
    ) -> (Hash32, Vec<MatcherExecutionReceiptV2>) {
        let command = EngineCommand::SubmitV2 {
            request: request.clone(),
            received_at_ms,
        };
        let command_hash = command_commitment_with_context_v2(&command, signer.chain_id(), context)
            .unwrap()
            .command_hash;
        let sequence = journal.next_sequence().unwrap();
        let mut staged = engine.clone();
        let mutation = staged
            .submit_sequenced_v2(request, received_at_ms, sequence)
            .unwrap();
        let commitment =
            command_commitment_with_context_v2(&command, signer.chain_id(), context).unwrap();
        let admission = signer
            .issue_at(
                &commitment,
                sequence,
                journal.head_receipt_hash(),
                context.matcher_context().unwrap(),
            )
            .unwrap();
        let previous_execution_sequence = journal.head_execution_sequence();
        let execution_receipts = mutation
            .executions_v2
            .iter()
            .enumerate()
            .map(|(index, execution)| {
                signer
                    .issue_execution_v2(
                        execution,
                        previous_execution_sequence + u64::try_from(index).unwrap() + 1,
                        &admission,
                        context,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        journal
            .append_with_execution_receipts(
                &command,
                &admission,
                context,
                &mutation.executions_v2,
                &execution_receipts,
            )
            .unwrap();
        *engine = staged;
        (command_hash, execution_receipts)
    }

    #[test]
    fn v2_multi_fill_receipts_are_atomic_restart_safe_private_and_tamper_evident() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: false,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let context = elements_context(100, 0x11, 0x21);
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();

        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(21, 0x21, Side::Sell, 101, 2, 1),
            10,
        );
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(22, 0x22, Side::Sell, 102, 3, 1),
            11,
        );
        let (taker_command_hash, execution_receipts) = append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(23, 0x23, Side::Buy, 102, 5, 1),
            12,
        );
        assert_eq!(execution_receipts.len(), 2);
        assert_eq!(execution_receipts[0].body.match_sequence, 1);
        assert_eq!(execution_receipts[1].body.match_sequence, 2);
        assert_eq!(execution_receipts[0].body.admission_sequence, 3);
        assert_eq!(execution_receipts[1].body.admission_sequence, 3);
        assert_eq!(execution_receipts[0].body.quantity.get(), 2);
        assert_eq!(execution_receipts[1].body.quantity.get(), 3);
        assert_eq!(journal.head_execution_sequence(), 2);
        assert_eq!(
            journal.execution_receipts_after(0, 10).unwrap(),
            execution_receipts
        );
        assert_eq!(
            journal.execution_receipts_after(0, 1).unwrap(),
            execution_receipts[..1]
        );
        assert_eq!(
            journal.execution_receipts_after(1, 10).unwrap(),
            execution_receipts[1..]
        );
        let admissions = journal
            .admission_receipts_for_executions(&execution_receipts)
            .unwrap();
        assert_eq!(admissions.len(), 1);
        assert_eq!(admissions[0].body.global_sequence, 3);
        assert_eq!(
            journal.execution_receipts_for_command(&taker_command_hash),
            execution_receipts
        );

        // Preserve the exact atomic journal before compaction for independent
        // omission and signature-tamper recovery mutations.
        let raw_journal = fs::read(&path).unwrap();
        let expected_history = journal.head_execution_history_hash();
        let expected_trades = engine.recent_trades(10);
        drop(journal);

        let (mut restarted_journal, mut restarted_engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        assert_eq!(restarted_journal.head_execution_sequence(), 2);
        assert_eq!(
            restarted_journal.head_execution_history_hash(),
            expected_history
        );
        assert_eq!(restarted_engine.recent_trades(10), expected_trades);

        // Advance the admission head once, then compact with a retention of
        // one. The older taker admission is nevertheless retained because it
        // is required to prove the durable execution receipts.
        append_v2_order(
            &mut restarted_journal,
            &mut restarted_engine,
            &signer,
            &context,
            signed_v2_order(24, 0x24, Side::Buy, 90, 1, 1),
            13,
        );
        restarted_journal
            .compact(&mut restarted_engine, &signer, 1)
            .unwrap();
        drop(restarted_journal);
        let (snapshotted, snapshotted_engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        let persisted = snapshotted.execution_receipts_after(0, 10).unwrap();
        assert_eq!(persisted, execution_receipts);
        assert_eq!(
            snapshotted
                .admission_receipts_for_executions(&persisted)
                .unwrap()[0]
                .body
                .global_sequence,
            3
        );
        assert_eq!(snapshotted_engine.recent_trades(10), expected_trades);
        drop(snapshotted);

        let omission_path = directory.path().join("omitted.jsonl");
        let mut lines = String::from_utf8(raw_journal.clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut omitted: JournalEntryV3 = serde_json::from_str(&lines[2]).unwrap();
        omitted.execution_receipts.pop();
        lines[2] = serde_json::to_string(&omitted).unwrap();
        fs::write(&omission_path, format!("{}\n", lines.join("\n"))).unwrap();
        make_private(&omission_path);
        assert!(
            Journal::open(
                &omission_path,
                engine_config.clone(),
                matcher_config.clone(),
                chain_id,
            )
            .is_err()
        );

        let tamper_path = directory.path().join("tampered.jsonl");
        let mut lines = String::from_utf8(raw_journal)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut tampered: JournalEntryV3 = serde_json::from_str(&lines[2]).unwrap();
        tampered.execution_receipts[1].body.match_sequence = 9;
        lines[2] = serde_json::to_string(&tampered).unwrap();
        fs::write(&tamper_path, format!("{}\n", lines.join("\n"))).unwrap();
        make_private(&tamper_path);
        assert!(Journal::open(&tamper_path, engine_config, matcher_config, chain_id).is_err());
    }

    #[test]
    fn proof_verified_cursor_compacts_hot_history_and_deep_rollback_rehydrates_byte_exact() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: false,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let context = elements_context(100, 0x11, 0x21);
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(21, 0x21, Side::Sell, 101, 2, 1),
            10,
        );
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(22, 0x22, Side::Sell, 102, 3, 1),
            11,
        );
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(23, 0x23, Side::Buy, 102, 5, 1),
            12,
        );
        let expected_head_history = journal.head_execution_history_hash();
        let expected_receipts = journal.execution_receipts_after(0, 10).unwrap();
        let expected_admissions = journal
            .admission_receipts_for_executions(&expected_receipts)
            .unwrap();
        assert_eq!(journal.head_execution_sequence(), 2);

        // Only a later active-tip context carrying the proof-verified PV5
        // cursor authorizes deletion. A producer acknowledgement is absent.
        let mut consumed_context = elements_context(101, 0x12, 0x21);
        consumed_context.capital_snapshot = Some(capital_snapshot([0x21; 32], 2));
        engine.advance_chain_height(101).unwrap();
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &consumed_context,
            signed_v2_order(24, 0x24, Side::Buy, 90, 1, 1),
            13,
        );
        journal.compact(&mut engine, &signer, 1).unwrap();
        assert_eq!(journal.retained_execution_previous_sequence(), 2);
        assert_eq!(
            journal.execution_receipts_after(0, 10).unwrap(),
            expected_receipts
        );
        assert!(journal.execution_receipts_after(2, 10).unwrap().is_empty());
        drop(journal);

        let (mut restarted, _) = Journal::open(
            &path,
            EngineConfig {
                chain_height: 101,
                ..engine_config
            },
            matcher_config,
            chain_id,
        )
        .unwrap();
        assert_eq!(restarted.retained_execution_previous_sequence(), 2);
        assert_eq!(restarted.head_execution_sequence(), 2);
        assert_eq!(
            restarted.head_execution_history_hash(),
            expected_head_history
        );
        let recovered = restarted.execution_receipts_after(0, 10).unwrap();
        assert_eq!(recovered, expected_receipts);
        assert_eq!(
            restarted
                .admission_receipts_for_executions(&recovered)
                .unwrap(),
            expected_admissions
        );
        restarted
            .validate_authenticated_execution_cursor(&consumed_context)
            .unwrap();
        let mut rolled_back = consumed_context;
        rolled_back
            .capital_snapshot
            .as_mut()
            .unwrap()
            .matcher_execution
            .sequence = 0;
        restarted
            .validate_authenticated_execution_cursor(&rolled_back)
            .unwrap();
        assert_eq!(restarted.retained_execution_previous_sequence(), 0);
        let rehydrated = restarted.execution_receipts_after(0, 10).unwrap();
        assert_eq!(rehydrated, expected_receipts);
        assert_eq!(
            restarted
                .admission_receipts_for_executions(&rehydrated)
                .unwrap(),
            expected_admissions
        );
    }

    #[test]
    fn execution_archive_recovers_missing_commit_and_aborts_unreferenced_prepare() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: false,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let context = elements_context(100, 0x11, 0x21);
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(21, 0x21, Side::Sell, 101, 1, 1),
            10,
        );
        let (command_hash, expected) = append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(22, 0x22, Side::Buy, 101, 1, 1),
            11,
        );
        let archive_path = execution_archive_path(&path);
        drop(journal);

        // Model a crash after the journal fsync but before the archive commit
        // marker: retain the complete prepare frame, never a partial frame.
        let archive_bytes = fs::read(&archive_path).unwrap();
        let prepare_length = u32::from_be_bytes(archive_bytes[4..8].try_into().unwrap()) as usize;
        let prepare_frame_length = 4 + 4 + prepare_length + 32;
        fs::write(&archive_path, &archive_bytes[..prepare_frame_length]).unwrap();
        make_private(&archive_path);
        let (mut recovered, recovered_engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        assert_eq!(recovered_engine.recent_trades(10), engine.recent_trades(10));
        assert_eq!(recovered.execution_receipts_after(0, 10).unwrap(), expected);

        // A complete prepare without a journal command is explicitly aborted
        // on restart. It cannot become a logical execution merely by residing
        // in the append-only archive.
        let admission = recovered.receipt_for_command(&command_hash).unwrap();
        let prepare = ExecutionArchivePrepareV1 {
            command_hash,
            admission_receipt: admission,
            execution_receipts: expected.clone(),
        };
        let mut commitment = recovered.execution_archive_commitment();
        append_execution_archive_payload(
            &mut recovered.execution_archive_file,
            &recovered.execution_archive_path,
            &mut commitment,
            ExecutionArchivePayloadV1::Prepare(Box::new(prepare)),
        )
        .unwrap();
        recovered.execution_archive_head_hash = commitment.head_hash;
        recovered.execution_archive_record_count = commitment.record_count;
        let count_before_restart = commitment.record_count;
        drop(recovered);
        let (recovered_again, _) =
            Journal::open(&path, engine_config, matcher_config, chain_id).unwrap();
        assert_eq!(
            recovered_again.execution_receipts_after(0, 10).unwrap(),
            expected
        );
        assert_eq!(
            recovered_again.execution_archive_record_count,
            count_before_restart + 1
        );
    }

    #[test]
    fn execution_archive_corruption_and_partial_frame_fail_closed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: false,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let context = elements_context(100, 0x11, 0x21);
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(21, 0x21, Side::Sell, 101, 1, 1),
            10,
        );
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &context,
            signed_v2_order(22, 0x22, Side::Buy, 101, 1, 1),
            11,
        );
        let mut consumed = elements_context(101, 0x12, 0x21);
        consumed.capital_snapshot = Some(capital_snapshot([0x21; 32], 1));
        engine.advance_chain_height(101).unwrap();
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &consumed,
            signed_v2_order(23, 0x23, Side::Buy, 90, 1, 1),
            12,
        );
        journal.compact(&mut engine, &signer, 1).unwrap();
        let archive_path = execution_archive_path(&path);
        drop(journal);
        let reopen_engine_config = EngineConfig {
            chain_height: 101,
            ..engine_config
        };

        let original = fs::read(&archive_path).unwrap();
        let mut corrupted = original.clone();
        corrupted[12] ^= 1;
        fs::write(&archive_path, corrupted).unwrap();
        make_private(&archive_path);
        assert!(
            Journal::open(
                &path,
                reopen_engine_config.clone(),
                matcher_config.clone(),
                chain_id,
            )
            .is_err()
        );

        fs::write(&archive_path, &original).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&archive_path)
            .unwrap()
            .write_all(&EXECUTION_ARCHIVE_MAGIC[..2])
            .unwrap();
        make_private(&archive_path);
        let error = Journal::open(&path, reopen_engine_config, matcher_config, chain_id)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("execution archive"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn execution_archive_snapshot_growth_is_bounded_by_the_hot_suffix() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: false,
            chain_height: 100,
            recent_trade_limit: 1,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, mut engine) =
            Journal::open(&path, engine_config, matcher_config, chain_id).unwrap();
        journal.compact(&mut engine, &signer, 1).unwrap();
        let baseline_snapshot_size = fs::metadata(snapshot_path(&path)).unwrap().len();
        let context = elements_context(100, 0x11, 0x21);
        for nonce in 1_u8..=24 {
            append_v2_order(
                &mut journal,
                &mut engine,
                &signer,
                &context,
                signed_v2_order(21, nonce, Side::Sell, 101, 1, u64::from(nonce)),
                10 + u64::from(nonce) * 2,
            );
            append_v2_order(
                &mut journal,
                &mut engine,
                &signer,
                &context,
                signed_v2_order(22, nonce + 64, Side::Buy, 101, 1, u64::from(nonce)),
                11 + u64::from(nonce) * 2,
            );
        }
        assert_eq!(journal.head_execution_sequence(), 24);
        let mut consumed = elements_context(101, 0x12, 0x21);
        consumed.capital_snapshot = Some(capital_snapshot([0x21; 32], 24));
        engine.advance_chain_height(101).unwrap();
        append_v2_order(
            &mut journal,
            &mut engine,
            &signer,
            &consumed,
            signed_v2_order(23, 0xfe, Side::Buy, 90, 1, 1),
            100,
        );
        journal.compact(&mut engine, &signer, 1).unwrap();
        assert_eq!(journal.retained_execution_previous_sequence(), 24);
        assert!(journal.execution_receipts_by_command.is_empty());
        let archive_size = fs::metadata(execution_archive_path(&path)).unwrap().len();
        let snapshot_size = fs::metadata(snapshot_path(&path)).unwrap().len();
        assert!(archive_size > 12 * 1_000);
        assert!(snapshot_size <= baseline_snapshot_size + 16 * 1024);
        assert!(snapshot_size < MAX_SNAPSHOT_BYTES as u64);
    }

    #[test]
    fn replay_recovers_exact_book_trade_history_and_receipt_head() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();

        let sell = order("demo-seller", "sell", Side::Sell, 101);
        let sell_command = EngineCommand::Submit {
            request: sell.clone(),
            received_at_ms: 10,
        };
        let sell_commitment = command_commitment(&sell_command, chain_id).unwrap();
        let sell_receipt = signer
            .issue(
                &sell_commitment,
                journal.next_sequence().unwrap(),
                journal.head_receipt_hash(),
            )
            .unwrap();
        engine.submit_sequenced(sell, 10, 1).unwrap();
        journal.append(&sell_command, &sell_receipt).unwrap();

        let mut buy = order("demo-buyer", "buy", Side::Buy, 101);
        buy.quantity_lots = 3;
        let buy_command = EngineCommand::Submit {
            request: buy.clone(),
            received_at_ms: 11,
        };
        let buy_commitment = command_commitment(&buy_command, chain_id).unwrap();
        let buy_receipt = signer
            .issue(
                &buy_commitment,
                journal.next_sequence().unwrap(),
                journal.head_receipt_hash(),
            )
            .unwrap();
        engine.submit_sequenced(buy, 11, 2).unwrap();
        journal.append(&buy_command, &buy_receipt).unwrap();

        let expected_book = engine.orderbook(10);
        let expected_trades = engine.recent_trades(10);
        let expected_head = journal.head_receipt_hash();
        journal.compact(&mut engine, &signer, 100).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        assert!(snapshot_path(&path).exists());
        drop(journal);

        let (replayed_journal, replayed) =
            Journal::open(&path, engine_config, matcher_config, chain_id).unwrap();
        assert_eq!(replayed.orderbook(10), expected_book);
        assert_eq!(replayed.recent_trades(10), expected_trades);
        assert_eq!(replayed.account("demo-buyer"), engine.account("demo-buyer"));
        assert_eq!(replayed_journal.head_sequence(), 2);
        assert_eq!(replayed_journal.head_receipt_hash(), expected_head);
    }

    #[test]
    fn signed_snapshot_recovers_if_crash_precedes_journal_truncation_and_rejects_tamper() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        let request = order("demo-seller", "first", Side::Sell, 101);
        let command = EngineCommand::Submit {
            request: request.clone(),
            received_at_ms: 10,
        };
        let commitment = command_commitment(&command, chain_id).unwrap();
        let receipt = signer
            .issue(&commitment, 1, journal.head_receipt_hash())
            .unwrap();
        engine.submit_sequenced(request, 10, 1).unwrap();
        journal.append(&command, &receipt).unwrap();
        let full_journal = fs::read(&path).unwrap();
        let expected_book = engine.orderbook(10);
        journal.compact(&mut engine, &signer, 1).unwrap();
        drop(journal);

        // This is the durable state if the snapshot rename completed but the
        // process died before truncating the old journal.
        fs::write(&path, &full_journal).unwrap();
        make_private(&path);
        let (recovered_journal, recovered_engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        assert_eq!(recovered_engine.orderbook(10), expected_book);
        assert_eq!(recovered_journal.head_sequence(), 1);
        assert_eq!(
            recovered_journal.receipt_for_command(&commitment.command_hash),
            Some(receipt)
        );
        drop(recovered_journal);

        let snapshot = snapshot_path(&path);
        let mut bytes = fs::read(&snapshot).unwrap();
        bytes[20] ^= 1;
        fs::write(&snapshot, bytes).unwrap();
        make_private(&snapshot);
        assert!(Journal::open(&path, engine_config, matcher_config, chain_id).is_err());
    }

    #[test]
    fn v5_snapshot_payload_is_never_accepted_under_v1_envelope() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        journal.compact(&mut engine, &signer, 100).unwrap();
        drop(journal);

        let snapshot = snapshot_path(&path);
        let mut bytes = fs::read(&snapshot).unwrap();
        assert_eq!(bytes[4], 5);
        bytes[4] = 1;
        fs::write(&snapshot, bytes).unwrap();
        make_private(&snapshot);

        let error = match Journal::open(&path, engine_config, matcher_config, chain_id) {
            Ok(_) => panic!("v5 payload was silently accepted as v1"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("v1 matcher snapshot envelope contains a non-v1 payload")
                || message.contains("decoding frozen v1 matcher snapshot payload"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn replay_restores_same_height_admission_usage() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            max_commands_per_height: 2,
            max_commands_per_trader_per_height: 1,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        let request = order("demo-seller", "first", Side::Sell, 101);
        let command = EngineCommand::Submit {
            request: request.clone(),
            received_at_ms: 10,
        };
        let commitment = command_commitment(&command, chain_id).unwrap();
        let receipt = signer
            .issue(&commitment, 1, journal.head_receipt_hash())
            .unwrap();
        engine.submit_sequenced(request, 10, 1).unwrap();
        journal.append(&command, &receipt).unwrap();
        drop(journal);

        let (_, mut replayed) =
            Journal::open(&path, engine_config, matcher_config, chain_id).unwrap();
        let mut second = order("demo-seller", "second", Side::Sell, 102);
        second.nonce = 2;
        assert_eq!(
            replayed.submit_sequenced(second, 11, 2).unwrap_err(),
            crate::EngineError::AdmissionQuota
        );
    }

    #[test]
    fn replay_rejects_a_receipt_that_no_longer_matches_the_command() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, _) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        let command = EngineCommand::Submit {
            request: order("demo-seller", "sell", Side::Sell, 101),
            received_at_ms: 10,
        };
        let commitment = command_commitment(&command, chain_id).unwrap();
        let receipt = signer
            .issue(&commitment, 1, journal.head_receipt_hash())
            .unwrap();
        journal.append(&command, &receipt).unwrap();
        drop(journal);

        let contents = fs::read_to_string(&path).unwrap();
        let mut entry: JournalEntryV1 = serde_json::from_str(contents.trim()).unwrap();
        if let EngineCommand::Submit { request, .. } = &mut entry.command {
            request.limit_price_ticks += 1;
        }
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        assert!(Journal::open(&path, engine_config, matcher_config, chain_id).is_err());
    }

    #[test]
    fn journal_allows_only_one_writer_process() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let (matcher_config, _, chain_id) = signer();
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (first, _) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        let conflict = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        );
        assert!(conflict.is_err());
        drop(first);
        assert!(Journal::open(&path, engine_config, matcher_config, chain_id).is_ok());
    }

    #[test]
    fn replay_rejects_oversized_or_unterminated_records() {
        let directory = tempdir().unwrap();
        let (matcher_config, _, chain_id) = signer();
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };

        let oversized = directory.path().join("oversized.jsonl");
        fs::write(&oversized, vec![b'x'; MAX_JOURNAL_ENTRY_BYTES + 2]).unwrap();
        make_private(&oversized);
        let error = Journal::open(
            &oversized,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("exceeds"), "unexpected error: {error}");

        let unterminated = directory.path().join("unterminated.jsonl");
        fs::write(&unterminated, b"{}").unwrap();
        make_private(&unterminated);
        let error = Journal::open(&unterminated, engine_config, matcher_config, chain_id)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("unterminated"), "unexpected error: {error}");
    }

    #[test]
    fn v2_journal_binds_and_recovers_the_full_elements_context() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, _) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        let context = elements_context(100, 0x11, 0x21);
        let command = EngineCommand::Submit {
            request: order("demo-seller", "sell", Side::Sell, 101),
            received_at_ms: 10,
        };
        let commitment = command_commitment_with_context_v2(&command, chain_id, &context).unwrap();
        let receipt = signer
            .issue_at(
                &commitment,
                journal.next_sequence().unwrap(),
                journal.head_receipt_hash(),
                context.matcher_context().unwrap(),
            )
            .unwrap();
        journal
            .append_with_context(&command, &receipt, &context)
            .unwrap();
        assert_eq!(journal.last_elements_context(), Some(&context));
        drop(journal);

        let (replayed, _) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        assert_eq!(replayed.last_elements_context(), Some(&context));
        drop(replayed);

        let contents = fs::read_to_string(&path).unwrap();
        let mut entry: JournalEntryV2 = serde_json::from_str(contents.trim()).unwrap();
        entry.elements_context.exchange_state_root[0] ^= 1;
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        assert!(Journal::open(&path, engine_config, matcher_config, chain_id).is_err());
    }

    #[test]
    fn offline_backup_is_locked_hashed_replay_verified_and_non_overwriting() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("matcher.jsonl");
        let backup = directory.path().join("backup-1");
        let engine_config = EngineConfig {
            demo_mode: true,
            chain_height: 100,
            ..EngineConfig::default()
        };
        let (matcher_config, signer, chain_id) = signer();
        let (mut journal, mut engine) = Journal::open(
            &path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        journal.compact(&mut engine, &signer, 100).unwrap();
        let manifest = journal.backup_to(&backup).unwrap();
        assert_eq!(manifest.head_sequence, journal.head_sequence());
        assert!(manifest.snapshot_sha256.is_some());
        assert!(journal.backup_to(&backup).is_err());

        let (verified, restored, verified_manifest) = Journal::open_backup(
            &backup,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        assert_eq!(verified_manifest, manifest);
        assert_eq!(verified.head_sequence(), journal.head_sequence());
        assert_eq!(restored.config(), engine.config());
        assert_eq!(restored.sequence(), engine.sequence());
        assert_eq!(restored.orderbook(10), engine.orderbook(10));
        drop(verified);

        let restored_path = directory.path().join("restored/matcher.jsonl");
        let (materialized, _, restored_manifest) = Journal::restore_backup_to(
            &backup,
            &restored_path,
            engine_config.clone(),
            matcher_config.clone(),
            chain_id,
        )
        .unwrap();
        assert_eq!(restored_manifest, manifest);
        assert_eq!(
            materialized.head_receipt_hash(),
            journal.head_receipt_hash()
        );
        drop(materialized);
        assert!(
            Journal::restore_backup_to(
                &backup,
                &restored_path,
                engine_config.clone(),
                matcher_config.clone(),
                chain_id,
            )
            .is_err()
        );

        let wrong_chain = [0x42; 32];
        assert!(
            Journal::open_backup(
                &backup,
                engine_config.clone(),
                matcher_config.clone(),
                wrong_chain,
            )
            .is_err()
        );
        let backup_archive = backup.join(BACKUP_EXECUTION_ARCHIVE);
        let archive_bytes = fs::read(&backup_archive).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&backup_archive)
            .unwrap()
            .write_all(b"tamper")
            .unwrap();
        assert!(
            Journal::open_backup(
                &backup,
                engine_config.clone(),
                matcher_config.clone(),
                chain_id,
            )
            .is_err()
        );
        fs::write(&backup_archive, archive_bytes).unwrap();
        make_private(&backup_archive);
        let backup_journal = backup.join(BACKUP_JOURNAL);
        OpenOptions::new()
            .append(true)
            .open(&backup_journal)
            .unwrap()
            .write_all(b"tamper\n")
            .unwrap();
        assert!(Journal::open_backup(&backup, engine_config, matcher_config, chain_id).is_err());
    }

    #[cfg(unix)]
    fn make_private(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn make_private(_path: &Path) {}
}
