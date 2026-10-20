//! Append-only durability for the lifetime-safe successor matcher receipt chain.
//!
//! This file format is deliberately disjoint from the V1 matcher journal. It
//! stores the exact canonical signed command bytes and recoverable context,
//! then replays every signature, command commitment, context field, sequence
//! link and record hash before returning a durable head.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ecx_protocol_core::{
    Hash32, SuccessorCentralMatcherConfigV2, SuccessorCentralMatcherReceiptV2,
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, tagged_hash,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    SuccessorCentralMatcherSignerV2, SuccessorMatcherConsensusContextV2, SuccessorMatcherHeadV2,
    successor_cancel_command_commitment_v2, successor_order_command_commitment_v2,
};

const MAGIC: &[u8; 8] = b"ECXSMJ2\0";
const FILE_VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 32 + 32 + SuccessorMatcherHeadV2::ENCODED_LEN;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_RECOVERABLE_CONTEXT_BYTES: usize = 60 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum SuccessorJournalCommandV2 {
    Place(Vec<u8>),
    Cancel(Vec<u8>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessorMatcherJournalCommandV2 {
    Place(SuccessorSignedLimitOrderV2),
    Cancel(SuccessorSignedCancelOrderV2),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorMatcherJournalEntryV2 {
    pub ordinal: u128,
    pub command: SuccessorMatcherJournalCommandV2,
    pub recoverable_context: Vec<u8>,
    pub consensus_context: SuccessorMatcherConsensusContextV2,
    pub receipt: SuccessorCentralMatcherReceiptV2,
    pub next_head: SuccessorMatcherHeadV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessorJournalRecordV2 {
    version: u8,
    ordinal: u128,
    previous_record_hash: Hash32,
    command: SuccessorJournalCommandV2,
    recoverable_context: Vec<u8>,
    consensus_context: SuccessorMatcherConsensusContextV2,
    receipt: SuccessorCentralMatcherReceiptV2,
    next_head: SuccessorMatcherHeadV2,
}

impl SuccessorJournalRecordV2 {
    const VERSION: u8 = 1;

    fn typed_entry(&self) -> Result<SuccessorMatcherJournalEntryV2> {
        let command = match &self.command {
            SuccessorJournalCommandV2::Place(bytes) => SuccessorMatcherJournalCommandV2::Place(
                SuccessorSignedLimitOrderV2::decode_fixed(bytes)
                    .context("decoding durable successor order")?,
            ),
            SuccessorJournalCommandV2::Cancel(bytes) => SuccessorMatcherJournalCommandV2::Cancel(
                SuccessorSignedCancelOrderV2::decode_fixed(bytes)
                    .context("decoding durable successor cancellation")?,
            ),
        };
        Ok(SuccessorMatcherJournalEntryV2 {
            ordinal: self.ordinal,
            command,
            recoverable_context: self.recoverable_context.clone(),
            consensus_context: self.consensus_context,
            receipt: self.receipt.clone(),
            next_head: self.next_head,
        })
    }
}

/// Opaque, head-bound admission prepared before the matching-state mutation is
/// durably published. Callers stage and fully validate their proof-shaped
/// state using `receipt()`, commit this record, then perform an infallible
/// in-memory swap. A crash after commit is recovered by `replay_entries`.
pub struct PreparedSuccessorJournalAppendV2 {
    record: SuccessorJournalRecordV2,
}

impl PreparedSuccessorJournalAppendV2 {
    pub fn receipt(&self) -> &SuccessorCentralMatcherReceiptV2 {
        &self.record.receipt
    }

    pub fn next_head(&self) -> SuccessorMatcherHeadV2 {
        self.record.next_head
    }
}

pub struct SuccessorMatcherJournalV2 {
    path: PathBuf,
    file: File,
    config: SuccessorCentralMatcherConfigV2,
    chain_id: Hash32,
    head: SuccessorMatcherHeadV2,
    record_count: u128,
    record_hash: Hash32,
}

impl SuccessorMatcherJournalV2 {
    pub fn open(
        path: impl AsRef<Path>,
        config: SuccessorCentralMatcherConfigV2,
        chain_id: Hash32,
    ) -> Result<Self> {
        config
            .validate()
            .context("invalid successor matcher journal configuration")?;
        if chain_id == [0; 32] {
            bail!("successor matcher journal chain id must be nonzero");
        }
        let path = path.as_ref().to_path_buf();
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("successor matcher journal path must not be a symlink");
        }
        let file = if path.exists() {
            OpenOptions::new()
                .read(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("opening successor matcher journal {}", path.display()))?
        } else {
            let mut options = OpenOptions::new();
            options.read(true).append(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut created = options.open(&path).with_context(|| {
                format!("creating successor matcher journal {}", path.display())
            })?;
            created
                .write_all(&journal_header(&config, chain_id)?)
                .context("writing successor matcher journal header")?;
            created
                .sync_all()
                .context("syncing new successor matcher journal")?;
            created
        };
        file.try_lock_exclusive()
            .context("successor matcher journal is already open by another writer")?;

        let head = SuccessorMatcherHeadV2 {
            sequence: config.genesis_sequence,
            receipt_hash: config.genesis_receipt_hash,
        }
        .validate()?;
        let record_hash = journal_genesis_hash(&config, chain_id, head)?;
        let mut journal = Self {
            path,
            file,
            config,
            chain_id,
            head,
            record_count: 0,
            record_hash,
        };
        journal.replay()?;
        Ok(journal)
    }

    pub fn head(&self) -> SuccessorMatcherHeadV2 {
        self.head
    }

    pub fn record_count(&self) -> u128 {
        self.record_count
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config(&self) -> &SuccessorCentralMatcherConfigV2 {
        &self.config
    }

    pub fn chain_id(&self) -> Hash32 {
        self.chain_id
    }

    pub fn append_place(
        &mut self,
        signer: &SuccessorCentralMatcherSignerV2,
        order: &SuccessorSignedLimitOrderV2,
        recoverable_context: &[u8],
        consensus_context: SuccessorMatcherConsensusContextV2,
    ) -> Result<SuccessorCentralMatcherReceiptV2> {
        let prepared = self.prepare_place(signer, order, recoverable_context, consensus_context)?;
        self.commit_prepared(prepared)
    }

    pub fn prepare_place(
        &self,
        signer: &SuccessorCentralMatcherSignerV2,
        order: &SuccessorSignedLimitOrderV2,
        recoverable_context: &[u8],
        consensus_context: SuccessorMatcherConsensusContextV2,
    ) -> Result<PreparedSuccessorJournalAppendV2> {
        self.check_signer(signer)?;
        if recoverable_context.len() > MAX_RECOVERABLE_CONTEXT_BYTES {
            bail!("successor matcher recoverable context exceeds the journal limit");
        }
        let commitment =
            successor_order_command_commitment_v2(order, self.chain_id, recoverable_context)?;
        let (receipt, next_head) = signer.issue(&commitment, self.head, consensus_context)?;
        let record = SuccessorJournalRecordV2 {
            version: SuccessorJournalRecordV2::VERSION,
            ordinal: self.record_count,
            previous_record_hash: self.record_hash,
            command: SuccessorJournalCommandV2::Place(
                ecx_protocol_core::codec::CanonicalEncode::canonical_bytes(order),
            ),
            recoverable_context: recoverable_context.to_vec(),
            consensus_context,
            receipt,
            next_head,
        };
        verify_record(
            &record,
            &self.config,
            self.chain_id,
            self.record_count,
            self.record_hash,
            self.head,
        )?;
        Ok(PreparedSuccessorJournalAppendV2 { record })
    }

    pub fn append_cancel(
        &mut self,
        signer: &SuccessorCentralMatcherSignerV2,
        cancel: &SuccessorSignedCancelOrderV2,
        recoverable_context: &[u8],
        consensus_context: SuccessorMatcherConsensusContextV2,
    ) -> Result<SuccessorCentralMatcherReceiptV2> {
        let prepared =
            self.prepare_cancel(signer, cancel, recoverable_context, consensus_context)?;
        self.commit_prepared(prepared)
    }

    pub fn prepare_cancel(
        &self,
        signer: &SuccessorCentralMatcherSignerV2,
        cancel: &SuccessorSignedCancelOrderV2,
        recoverable_context: &[u8],
        consensus_context: SuccessorMatcherConsensusContextV2,
    ) -> Result<PreparedSuccessorJournalAppendV2> {
        self.check_signer(signer)?;
        if recoverable_context.len() > MAX_RECOVERABLE_CONTEXT_BYTES {
            bail!("successor matcher recoverable context exceeds the journal limit");
        }
        let commitment =
            successor_cancel_command_commitment_v2(cancel, self.chain_id, recoverable_context)?;
        let (receipt, next_head) = signer.issue(&commitment, self.head, consensus_context)?;
        let record = SuccessorJournalRecordV2 {
            version: SuccessorJournalRecordV2::VERSION,
            ordinal: self.record_count,
            previous_record_hash: self.record_hash,
            command: SuccessorJournalCommandV2::Cancel(
                ecx_protocol_core::codec::CanonicalEncode::canonical_bytes(cancel),
            ),
            recoverable_context: recoverable_context.to_vec(),
            consensus_context,
            receipt,
            next_head,
        };
        verify_record(
            &record,
            &self.config,
            self.chain_id,
            self.record_count,
            self.record_hash,
            self.head,
        )?;
        Ok(PreparedSuccessorJournalAppendV2 { record })
    }

    pub fn commit_prepared(
        &mut self,
        prepared: PreparedSuccessorJournalAppendV2,
    ) -> Result<SuccessorCentralMatcherReceiptV2> {
        let receipt = prepared.record.receipt.clone();
        self.append_record(prepared.record)?;
        Ok(receipt)
    }

    /// Streams exact typed entries from the identity-bound journal. Every
    /// record is reverified before it reaches the callback; no unbounded
    /// command vector is accumulated in memory.
    pub fn replay_entries(
        &self,
        mut apply: impl FnMut(SuccessorMatcherJournalEntryV2) -> Result<()>,
    ) -> Result<()> {
        self.scan_records(|record| apply(record.typed_entry()?))?;
        Ok(())
    }

    fn check_signer(&self, signer: &SuccessorCentralMatcherSignerV2) -> Result<()> {
        if signer.config() != &self.config || signer.chain_id() != self.chain_id {
            bail!("successor matcher signer differs from the durable journal identity");
        }
        Ok(())
    }

    fn append_record(&mut self, record: SuccessorJournalRecordV2) -> Result<()> {
        if record.recoverable_context.len() > MAX_RECOVERABLE_CONTEXT_BYTES {
            bail!("successor matcher recoverable context exceeds the journal limit");
        }
        verify_record(
            &record,
            &self.config,
            self.chain_id,
            self.record_count,
            self.record_hash,
            self.head,
        )?;
        let bytes = bincode::serialize(&record).context("encoding successor matcher record")?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            bail!("successor matcher record exceeds the journal limit");
        }
        let length = u32::try_from(bytes.len()).context("successor matcher record is too large")?;
        self.file
            .write_all(&length.to_be_bytes())
            .and_then(|_| self.file.write_all(&bytes))
            .context("appending successor matcher record")?;
        self.file
            .sync_data()
            .context("syncing successor matcher record")?;
        self.record_hash = record_hash(&bytes);
        self.record_count = self
            .record_count
            .checked_add(1)
            .context("successor matcher record count overflow")?;
        self.head = record.next_head;
        Ok(())
    }

    fn replay(&mut self) -> Result<()> {
        let (head, record_count, record_hash) = self.scan_records(|_| Ok(()))?;
        self.head = head;
        self.record_count = record_count;
        self.record_hash = record_hash;
        Ok(())
    }

    fn scan_records(
        &self,
        mut apply: impl FnMut(&SuccessorJournalRecordV2) -> Result<()>,
    ) -> Result<(SuccessorMatcherHeadV2, u128, Hash32)> {
        let mut reader = self
            .file
            .try_clone()
            .context("cloning successor matcher journal for replay")?;
        reader.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_BYTES];
        reader
            .read_exact(&mut header)
            .context("reading successor matcher journal header")?;
        if header.as_slice() != journal_header(&self.config, self.chain_id)? {
            bail!("successor matcher journal header has the wrong version or identity");
        }
        let mut head = SuccessorMatcherHeadV2 {
            sequence: self.config.genesis_sequence,
            receipt_hash: self.config.genesis_receipt_hash,
        }
        .validate()?;
        let mut record_count = 0u128;
        let mut current_record_hash = journal_genesis_hash(&self.config, self.chain_id, head)?;
        loop {
            let mut length_bytes = [0u8; 4];
            let read = reader
                .read(&mut length_bytes)
                .context("reading successor matcher record length")?;
            if read == 0 {
                break;
            }
            if read != length_bytes.len() {
                bail!("truncated successor matcher record length");
            }
            let length = usize::try_from(u32::from_be_bytes(length_bytes))?;
            if length == 0 || length > MAX_RECORD_BYTES {
                bail!("invalid successor matcher record length");
            }
            let mut bytes = vec![0u8; length];
            reader
                .read_exact(&mut bytes)
                .context("truncated successor matcher record")?;
            let record: SuccessorJournalRecordV2 =
                bincode::deserialize(&bytes).context("decoding successor matcher record")?;
            if record.recoverable_context.len() > MAX_RECOVERABLE_CONTEXT_BYTES {
                bail!("successor matcher recoverable context exceeds the journal limit");
            }
            verify_record(
                &record,
                &self.config,
                self.chain_id,
                record_count,
                current_record_hash,
                head,
            )?;
            apply(&record)?;
            current_record_hash = record_hash(&bytes);
            record_count = record_count
                .checked_add(1)
                .context("successor matcher record count overflow")?;
            head = record.next_head;
        }
        Ok((head, record_count, current_record_hash))
    }
}

fn verify_record(
    record: &SuccessorJournalRecordV2,
    config: &SuccessorCentralMatcherConfigV2,
    chain_id: Hash32,
    expected_ordinal: u128,
    expected_previous_record_hash: Hash32,
    previous_head: SuccessorMatcherHeadV2,
) -> Result<()> {
    if record.version != SuccessorJournalRecordV2::VERSION
        || record.ordinal != expected_ordinal
        || record.previous_record_hash != expected_previous_record_hash
    {
        bail!("successor matcher journal record chain is invalid");
    }
    let commitment = match &record.command {
        SuccessorJournalCommandV2::Place(bytes) => {
            let order = SuccessorSignedLimitOrderV2::decode_fixed(bytes)
                .context("decoding durable successor order")?;
            successor_order_command_commitment_v2(&order, chain_id, &record.recoverable_context)?
        }
        SuccessorJournalCommandV2::Cancel(bytes) => {
            let cancel = SuccessorSignedCancelOrderV2::decode_fixed(bytes)
                .context("decoding durable successor cancellation")?;
            successor_cancel_command_commitment_v2(&cancel, chain_id, &record.recoverable_context)?
        }
    };
    record
        .receipt
        .verify(config)
        .context("verifying durable successor matcher receipt")?;
    let expected_sequence = previous_head
        .sequence
        .checked_add(1)
        .context("successor matcher sequence overflow during replay")?;
    if expected_sequence == u128::MAX
        || commitment.command_kind != record.receipt.body.command_kind
        || commitment.command_hash != record.receipt.body.command_hash
        || commitment.availability_root != record.receipt.body.availability_root
        || record.receipt.body.chain_id != chain_id
        || record.receipt.body.global_sequence != expected_sequence
        || record.receipt.body.previous_receipt_hash != previous_head.receipt_hash
        || record.receipt.body.observed_sidechain_height
            != record.consensus_context.sidechain_height
        || record.receipt.body.observed_parent_height != record.consensus_context.parent_height
        || record.receipt.body.observed_parent_mtp != record.consensus_context.parent_mtp
        || record.receipt.body.forced_inbox_cursor != record.consensus_context.forced_inbox_cursor
        || record.next_head.sequence != expected_sequence
        || record.next_head.receipt_hash != record.receipt.receipt_hash()
    {
        bail!("successor matcher journal record does not match its command, context, or head");
    }
    record.consensus_context.validate()?;
    record.next_head.validate()?;
    Ok(())
}

fn journal_genesis_hash(
    config: &SuccessorCentralMatcherConfigV2,
    chain_id: Hash32,
    head: SuccessorMatcherHeadV2,
) -> Result<Hash32> {
    let mut payload = Vec::with_capacity(32 + 32 + SuccessorMatcherHeadV2::ENCODED_LEN);
    payload.extend_from_slice(&chain_id);
    payload.extend_from_slice(&config.digest());
    payload.extend_from_slice(&head.encode_fixed()?);
    Ok(tagged_hash(
        "ECX/incremental-matcher-journal-genesis/v1-u128",
        &payload,
    ))
}

fn journal_header(
    config: &SuccessorCentralMatcherConfigV2,
    chain_id: Hash32,
) -> Result<[u8; HEADER_BYTES]> {
    let head = SuccessorMatcherHeadV2 {
        sequence: config.genesis_sequence,
        receipt_hash: config.genesis_receipt_hash,
    }
    .validate()?;
    let mut header = [0u8; HEADER_BYTES];
    let mut offset = 0;
    header[offset..offset + MAGIC.len()].copy_from_slice(MAGIC);
    offset += MAGIC.len();
    header[offset] = FILE_VERSION;
    offset += 1;
    header[offset..offset + 32].copy_from_slice(&chain_id);
    offset += 32;
    header[offset..offset + 32].copy_from_slice(&config.digest());
    offset += 32;
    header[offset..].copy_from_slice(&head.encode_fixed()?);
    Ok(header)
}

fn record_hash(bytes: &[u8]) -> Hash32 {
    tagged_hash("ECX/incremental-matcher-journal-record/v1-u128", bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ecx_protocol_core::{
        OrderFlags, Price, Quantity, Side, SuccessorCancelOrderV2, SuccessorLimitOrderV2,
        TimeInForce, XOnlyKey,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use tempfile::tempdir;

    use super::*;

    fn identity(secret_byte: u8) -> (SecretKey, XOnlyKey) {
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        (secret, XOnlyKey(public.serialize()))
    }

    fn fixture() -> (
        SuccessorCentralMatcherSignerV2,
        SuccessorCentralMatcherConfigV2,
        Hash32,
        SecretKey,
        XOnlyKey,
    ) {
        let (matcher_secret, matcher_key) = identity(51);
        let (trader_secret, trader_key) = identity(52);
        let config = SuccessorCentralMatcherConfigV2 {
            version: SuccessorCentralMatcherConfigV2::VERSION,
            key_epoch: 7,
            signer: matcher_key,
            genesis_sequence: (1u128 << 96) + 100,
            genesis_receipt_hash: [9; 32],
            forced_inclusion_blocks: 6,
        };
        let chain_id = [7; 32];
        let signer =
            SuccessorCentralMatcherSignerV2::new(config.clone(), matcher_secret, chain_id).unwrap();
        (signer, config, chain_id, trader_secret, trader_key)
    }

    fn order(
        secret: &SecretKey,
        trader: XOnlyKey,
        chain_id: Hash32,
    ) -> SuccessorSignedLimitOrderV2 {
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id,
                market: ecx_protocol_core::ECX_USDD_MARKET,
                trader,
                side: Side::Buy,
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                limit_price: Price::new(100_000_000).unwrap(),
                quantity: Quantity::new(4).unwrap(),
                client_order_id: [4; 16],
                max_fee_bps: 5,
                nonce: (1u128 << 104) + 1,
                valid_from_height: 10,
                expires_at_height: 20,
            },
            secret,
        )
        .unwrap()
    }

    fn context() -> SuccessorMatcherConsensusContextV2 {
        SuccessorMatcherConsensusContextV2 {
            sidechain_height: 10,
            parent_height: 900_000,
            parent_mtp: 1_800_000_000,
            forced_inbox_cursor: (1u128 << 112) + 3,
        }
    }

    #[test]
    fn successor_journal_replays_exact_high_bit_receipt_chain() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("successor.matcher");
        let (signer, config, chain_id, trader_secret, trader) = fixture();
        let signed_order = order(&trader_secret, trader, chain_id);
        let final_head;
        {
            let mut journal =
                SuccessorMatcherJournalV2::open(&path, config.clone(), chain_id).unwrap();
            let place = journal
                .append_place(&signer, &signed_order, b"node-context-1", context())
                .unwrap();
            assert_eq!(place.body.global_sequence, config.genesis_sequence + 1);
            let cancel = SuccessorSignedCancelOrderV2::sign(
                SuccessorCancelOrderV2 {
                    version: SuccessorCancelOrderV2::VERSION,
                    chain_id,
                    market: ecx_protocol_core::ECX_USDD_MARKET,
                    trader,
                    order_id: signed_order.order_id(),
                    nonce: signed_order.order.nonce + 1,
                    valid_from_height: 10,
                    expires_at_height: 20,
                },
                &trader_secret,
            )
            .unwrap();
            let cancellation = journal
                .append_cancel(&signer, &cancel, b"node-context-2", context())
                .unwrap();
            assert_eq!(
                cancellation.body.global_sequence,
                config.genesis_sequence + 2
            );
            assert_eq!(journal.record_count(), 2);
            final_head = journal.head();
        }
        let reopened = SuccessorMatcherJournalV2::open(&path, config, chain_id).unwrap();
        assert_eq!(reopened.record_count(), 2);
        assert_eq!(reopened.head(), final_head);
    }

    #[test]
    fn successor_journal_rejects_tamper_truncation_and_wrong_identity() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("successor.matcher");
        let (signer, config, chain_id, trader_secret, trader) = fixture();
        {
            let mut journal =
                SuccessorMatcherJournalV2::open(&path, config.clone(), chain_id).unwrap();
            journal
                .append_place(
                    &signer,
                    &order(&trader_secret, trader, chain_id),
                    b"node-context",
                    context(),
                )
                .unwrap();
        }
        let original = fs::read(&path).unwrap();

        let tampered_path = temporary.path().join("tampered.matcher");
        let mut tampered = original.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        fs::write(&tampered_path, tampered).unwrap();
        assert!(SuccessorMatcherJournalV2::open(&tampered_path, config.clone(), chain_id).is_err());

        let truncated_path = temporary.path().join("truncated.matcher");
        fs::write(&truncated_path, &original[..original.len() - 1]).unwrap();
        assert!(
            SuccessorMatcherJournalV2::open(&truncated_path, config.clone(), chain_id).is_err()
        );
        assert!(SuccessorMatcherJournalV2::open(&path, config, [8; 32]).is_err());
    }

    #[test]
    fn successor_journal_binds_empty_file_identity_and_header_bytes() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("empty.matcher");
        let (_, config, chain_id, _, _) = fixture();
        {
            let journal = SuccessorMatcherJournalV2::open(&path, config.clone(), chain_id).unwrap();
            assert_eq!(journal.record_count(), 0);
            assert_eq!(fs::metadata(&path).unwrap().len() as usize, HEADER_BYTES);
        }
        assert!(SuccessorMatcherJournalV2::open(&path, config.clone(), [8; 32]).is_err());

        let mut changed_config = config.clone();
        changed_config.key_epoch += 1;
        assert!(SuccessorMatcherJournalV2::open(&path, changed_config, chain_id).is_err());

        let header = fs::read(&path).unwrap();
        for index in [0, MAGIC.len(), MAGIC.len() + 1, HEADER_BYTES - 1] {
            let changed_path = temporary.path().join(format!("header-{index}.matcher"));
            let mut changed = header.clone();
            changed[index] ^= 1;
            fs::write(&changed_path, changed).unwrap();
            assert!(
                SuccessorMatcherJournalV2::open(&changed_path, config.clone(), chain_id).is_err()
            );
        }
    }

    #[test]
    fn successor_journal_prepare_stage_commit_and_streaming_replay_are_exact() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("prepared.matcher");
        let (signer, config, chain_id, trader_secret, trader) = fixture();
        let signed_order = order(&trader_secret, trader, chain_id);
        let mut journal = SuccessorMatcherJournalV2::open(&path, config.clone(), chain_id).unwrap();

        let prepared = journal
            .prepare_place(&signer, &signed_order, b"recoverable", context())
            .unwrap();
        let stale = journal
            .prepare_place(&signer, &signed_order, b"recoverable", context())
            .unwrap();
        assert_eq!(
            prepared.receipt().body.global_sequence,
            config.genesis_sequence + 1
        );
        assert_eq!(prepared.next_head().sequence, config.genesis_sequence + 1);
        assert_eq!(journal.record_count(), 0);
        assert_eq!(fs::metadata(&path).unwrap().len() as usize, HEADER_BYTES);

        let receipt = journal.commit_prepared(prepared).unwrap();
        let committed_len = fs::metadata(&path).unwrap().len();
        assert_eq!(receipt.body.global_sequence, config.genesis_sequence + 1);
        assert!(journal.commit_prepared(stale).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), committed_len);
        assert_eq!(journal.record_count(), 1);

        let mut entries = Vec::new();
        journal
            .replay_entries(|entry| {
                entries.push(entry);
                Ok(())
            })
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ordinal, 0);
        assert_eq!(entries[0].recoverable_context, b"recoverable");
        assert_eq!(entries[0].receipt, receipt);
        assert_eq!(entries[0].next_head, journal.head());
        assert_eq!(
            entries[0].command,
            SuccessorMatcherJournalCommandV2::Place(signed_order)
        );
    }
}
