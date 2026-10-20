//! Node-bound operational archive for successor trader-state openings.
//!
//! The archive is not consensus state.  It retains the private opened trader
//! leaves needed by the grant service, but every checkpoint is independently
//! bound to a node-accepted incremental public-state root.  Bootstrap is only
//! possible with an empty trader tree.  Thereafter a checkpoint advances only
//! through an exact typed trader batch from the previously retained state to
//! the newly authenticated state.  Other child roots are accepted only through
//! the complete public-state preimage whose root the node already accepted.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ecx_protocol_core::{
    IncrementalPublicStateV2, IncrementalSuccessorConfigurationV2, IncrementalTraderStateArchiveV2,
    TraderStateBatchProofV2, XOnlyKey,
};
use serde::{Deserialize, Serialize};

use crate::{SuccessorElementsConsensusContextV2, SuccessorTraderStateSnapshotV2};

const MAX_ARCHIVE_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorTraderArchiveCheckpointV2 {
    pub version: u8,
    pub context: SuccessorElementsConsensusContextV2,
    pub state: IncrementalPublicStateV2,
    pub archive: IncrementalTraderStateArchiveV2,
}

impl SuccessorTraderArchiveCheckpointV2 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self, configuration: IncrementalSuccessorConfigurationV2) -> Result<()> {
        if self.version != Self::VERSION {
            bail!("invalid successor trader-archive checkpoint version");
        }
        validate_state_context(configuration, self.state, &self.context)?;
        self.archive
            .validate(configuration.accounting_bounds)
            .context("invalid retained successor trader archive")?;
        if self.archive.root() != self.state.trader_root {
            bail!("retained trader archive does not reconstruct the public trader root");
        }
        Ok(())
    }

    pub fn trader_snapshot(
        &self,
        configuration: IncrementalSuccessorConfigurationV2,
        trader: XOnlyKey,
    ) -> Result<SuccessorTraderStateSnapshotV2> {
        self.validate(configuration)?;
        let trader_read = self
            .archive
            .trader_read_proof(trader, configuration.accounting_bounds)
            .context("trader is absent from the authenticated successor archive")?;
        Ok(SuccessorTraderStateSnapshotV2 {
            version: SuccessorTraderStateSnapshotV2::VERSION,
            exchange_state_root: self.context.exchange_state_root,
            trader,
            state: self.state,
            trader_read,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorTraderArchiveTransitionV2 {
    pub version: u8,
    /// Active-chain locator of the retained predecessor.  This is operational
    /// lookup metadata, not part of the recursive proof statement.
    pub previous_sidechain_block_hash: ecx_protocol_core::Hash32,
    pub previous_state: IncrementalPublicStateV2,
    pub next_state: IncrementalPublicStateV2,
    /// Must be absent exactly when the trader root is unchanged.
    pub trader_batch: Option<TraderStateBatchProofV2>,
}

impl SuccessorTraderArchiveTransitionV2 {
    pub const VERSION: u8 = 1;
}

pub fn bootstrap_successor_trader_archive(
    configuration: IncrementalSuccessorConfigurationV2,
    context: SuccessorElementsConsensusContextV2,
    state: IncrementalPublicStateV2,
) -> Result<SuccessorTraderArchiveCheckpointV2> {
    configuration
        .validate()
        .context("invalid incremental-successor configuration")?;
    validate_state_context(configuration, state, &context)?;
    let archive = IncrementalTraderStateArchiveV2::canonical_empty(configuration.accounting_bounds)
        .context("constructing canonical empty trader archive")?;
    if state.trader_root != archive.root() {
        bail!("successor trader archive can bootstrap only from an empty trader root");
    }
    let checkpoint = SuccessorTraderArchiveCheckpointV2 {
        version: SuccessorTraderArchiveCheckpointV2::VERSION,
        context,
        state,
        archive,
    };
    checkpoint.validate(configuration)?;
    Ok(checkpoint)
}

pub fn advance_successor_trader_archive(
    configuration: IncrementalSuccessorConfigurationV2,
    previous: &SuccessorTraderArchiveCheckpointV2,
    next_context: SuccessorElementsConsensusContextV2,
    transition: SuccessorTraderArchiveTransitionV2,
) -> Result<SuccessorTraderArchiveCheckpointV2> {
    previous.validate(configuration)?;
    if transition.version != SuccessorTraderArchiveTransitionV2::VERSION
        || transition.previous_sidechain_block_hash != previous.context.sidechain_block_hash
        || transition.previous_state != previous.state
    {
        bail!("successor trader-archive transition does not extend the retained state");
    }
    next_context
        .validate_successor_of(&previous.context)
        .context("node successor context does not extend the retained checkpoint")?;
    if next_context.sidechain_height == previous.context.sidechain_height {
        bail!("successor trader archive cannot append a duplicate sidechain height");
    }
    validate_state_context(configuration, transition.next_state, &next_context)?;

    let root_changed = transition.previous_state.trader_root != transition.next_state.trader_root;
    if root_changed != transition.trader_batch.is_some() {
        bail!("trader batch presence does not match the public trader-root change");
    }
    let mut archive = previous.archive.clone();
    if let Some(batch) = &transition.trader_batch {
        archive
            .apply_verified_batch(
                batch,
                configuration.accounting_bounds,
                usize::from(configuration.maximum_trader_updates),
            )
            .context("invalid successor trader-state update batch")?;
    }
    if archive.root() != transition.next_state.trader_root {
        bail!("successor trader batch does not reconstruct the accepted next trader root");
    }

    let checkpoint = SuccessorTraderArchiveCheckpointV2 {
        version: SuccessorTraderArchiveCheckpointV2::VERSION,
        context: next_context,
        state: transition.next_state,
        archive,
    };
    checkpoint.validate(configuration)?;
    Ok(checkpoint)
}

pub fn successor_trader_archive_checkpoint_filename(
    sidechain_height: u64,
    sidechain_block_hash: ecx_protocol_core::Hash32,
) -> String {
    format!(
        "checkpoint-{sidechain_height:020}-{}.json",
        hex::encode(sidechain_block_hash)
    )
}

pub fn write_new_successor_trader_archive_checkpoint(
    directory: &Path,
    configuration: IncrementalSuccessorConfigurationV2,
    checkpoint: &SuccessorTraderArchiveCheckpointV2,
) -> Result<PathBuf> {
    validate_private_archive_directory(directory)?;
    checkpoint.validate(configuration)?;
    let bytes =
        serde_json::to_vec(checkpoint).context("encoding successor trader-archive checkpoint")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ARCHIVE_CHECKPOINT_BYTES {
        bail!("successor trader-archive checkpoint exceeds the operational file bound");
    }
    let final_path = directory.join(successor_trader_archive_checkpoint_filename(
        checkpoint.context.sidechain_height,
        checkpoint.context.sidechain_block_hash,
    ));
    let temporary_path = directory.join(format!(
        ".checkpoint-{}-{}.tmp",
        std::process::id(),
        hex::encode(checkpoint.context.sidechain_block_hash),
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temporary = options
        .open(&temporary_path)
        .with_context(|| format!("create temporary checkpoint {}", temporary_path.display()))?;
    let result = (|| -> Result<()> {
        temporary.write_all(&bytes)?;
        temporary.sync_all()?;
        std::fs::hard_link(&temporary_path, &final_path)
            .with_context(|| format!("install create-new checkpoint {}", final_path.display()))?;
        sync_directory(directory)?;
        Ok(())
    })();
    drop(temporary);
    let _ = std::fs::remove_file(&temporary_path);
    result?;
    Ok(final_path)
}

pub fn read_successor_trader_archive_checkpoint(
    directory: &Path,
    configuration: IncrementalSuccessorConfigurationV2,
    sidechain_height: u64,
    sidechain_block_hash: ecx_protocol_core::Hash32,
) -> Result<SuccessorTraderArchiveCheckpointV2> {
    validate_private_archive_directory(directory)?;
    let path = directory.join(successor_trader_archive_checkpoint_filename(
        sidechain_height,
        sidechain_block_hash,
    ));
    let bytes = read_private_regular_file(&path, MAX_ARCHIVE_CHECKPOINT_BYTES)?;
    let checkpoint: SuccessorTraderArchiveCheckpointV2 = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding successor trader archive {}", path.display()))?;
    checkpoint.validate(configuration)?;
    if checkpoint.context.sidechain_height != sidechain_height
        || checkpoint.context.sidechain_block_hash != sidechain_block_hash
    {
        bail!("successor trader archive filename does not match its authenticated context");
    }
    Ok(checkpoint)
}

pub fn write_new_successor_trader_snapshot(
    directory: &Path,
    configuration: IncrementalSuccessorConfigurationV2,
    snapshot: &SuccessorTraderStateSnapshotV2,
) -> Result<PathBuf> {
    validate_private_archive_directory(directory)?;
    snapshot
        .state
        .validate(configuration)
        .context("invalid trader snapshot public-state preimage")?;
    if snapshot.version != SuccessorTraderStateSnapshotV2::VERSION
        || snapshot.state.state_root(configuration)? != snapshot.exchange_state_root
        || snapshot.trader_read.leaves.len() != 1
        || snapshot.trader_read.leaves[0].trader != snapshot.trader
    {
        bail!("successor trader snapshot does not reconstruct its named state and trader");
    }
    snapshot
        .trader_read
        .verify(snapshot.state.trader_root, configuration.accounting_bounds)
        .context("invalid successor trader snapshot membership proof")?;
    let bytes = serde_json::to_vec(snapshot).context("encoding successor trader snapshot")?;
    let path = directory.join(crate::successor_trader_snapshot_filename(
        snapshot.exchange_state_root,
        snapshot.trader,
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("create new trader snapshot {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_directory(directory)?;
    Ok(path)
}

fn validate_private_archive_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect trader archive directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("trader archive store must be a regular non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("trader archive store permissions are broader than 0700");
        }
    }
    Ok(())
}

fn read_private_regular_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let before =
        std::fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        bail!(
            "{} must be a bounded regular non-symlink file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            bail!("{} permissions are broader than 0600", path.display());
        }
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("inspect open {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("{} changed while being opened", path.display());
        }
    }
    let capacity = usize::try_from(after.len()).context("archive file size does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        bail!("{} has an invalid size", path.display());
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    Ok(())
}

fn validate_state_context(
    configuration: IncrementalSuccessorConfigurationV2,
    state: IncrementalPublicStateV2,
    context: &SuccessorElementsConsensusContextV2,
) -> Result<()> {
    configuration
        .validate()
        .context("invalid incremental-successor configuration")?;
    context
        .validate()
        .context("invalid node-authenticated successor context")?;
    state
        .validate(configuration)
        .context("invalid incremental public-state preimage")?;
    if context.successor_configuration_hash != configuration.digest()?
        || state.state_root(configuration)? != context.exchange_state_root
        || state.sidechain_height != context.sidechain_height
        || state.parent_median_time_past != context.parent_mtp
        || state.matcher_sequence != context.matcher_execution_sequence
    {
        bail!("incremental public state does not reconstruct the authenticated node context");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ecx_protocol_core::{
        BOND_FIXED_SUPPLY_ATOMS, ECX_USDD_MARKET, INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
        IncrementalAccountingBoundsV2, Int256V2, RiskParams, TraderLeafV2,
        TraderStateBatchLeafUpdateV2, TraderStateBatchProofV2,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;
    use crate::CapitalMode;

    fn configuration() -> IncrementalSuccessorConfigurationV2 {
        IncrementalSuccessorConfigurationV2 {
            version: INCREMENTAL_SUCCESSOR_CONFIGURATION_VERSION_V2,
            chain_id: [7; 32],
            market: ECX_USDD_MARKET,
            order_configuration_hash: [3; 32],
            successor_matcher_configuration_hash: [4; 32],
            risk_params: RiskParams::default(),
            accounting_bounds: IncrementalAccountingBoundsV2 {
                maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
                maximum_total_controlled_atoms: u128::from(BOND_FIXED_SUPPLY_ATOMS),
                maximum_abs_position_atoms: 10_000_000_000,
                maximum_open_interest_atoms: 20_000_000_000,
                maximum_price_atoms: 10_000_000_000,
            },
            maximum_trader_updates: 64,
            maximum_order_operations: 64,
            maximum_nullifier_updates_per_kind: 64,
        }
    }

    fn context(
        configuration: IncrementalSuccessorConfigurationV2,
        state: IncrementalPublicStateV2,
        block_byte: u8,
    ) -> SuccessorElementsConsensusContextV2 {
        SuccessorElementsConsensusContextV2 {
            sidechain_height: state.sidechain_height,
            sidechain_block_hash: [block_byte; 32],
            exchange_state_root: state.state_root(configuration).unwrap(),
            parent_height: state.sidechain_height + 100,
            parent_mtp: state.parent_median_time_past,
            parent_block_hash: [block_byte.wrapping_add(1); 32],
            source_parent_height: state.sidechain_height + 100,
            forced_inbox_processed_cursor: 0,
            successor_configuration_hash: configuration.digest().unwrap(),
            bond_action_configuration_hash: [8; 32],
            bond_asset_id: [9; 32],
            bond_deployment_commitment: [10; 32],
            transition_program_id: [11; 32],
            transition_cmr: [12; 32],
            capital_mode: CapitalMode::Normal,
            matcher_execution_previous_sequence: state.matcher_sequence,
            matcher_execution_sequence: state.matcher_sequence,
            last_transition_sidechain_height: state.sidechain_height,
        }
    }

    fn trader_leaf() -> TraderLeafV2 {
        let secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: XOnlyKey(public.serialize()),
            account_nonce: 1,
            collateral_atoms: 0,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 1,
            salt: [33; 32],
        }
    }

    #[test]
    fn successor_trader_archive_bootstraps_advances_and_extracts_exact_opening() {
        let configuration = configuration();
        let state =
            IncrementalPublicStateV2::canonical_empty(configuration, 10, 1_000, 5, 1, 10).unwrap();
        let first_context = context(configuration, state, 20);
        let first = bootstrap_successor_trader_archive(configuration, first_context, state)
            .expect("empty authenticated state bootstraps");

        let leaf = trader_leaf();
        let batch = TraderStateBatchProofV2::for_canonical_empty_root(
            vec![TraderStateBatchLeafUpdateV2 {
                trader: leaf.trader,
                old_leaf: None,
                new_leaf: Some(leaf.clone()),
            }],
            configuration.accounting_bounds,
        )
        .unwrap();
        let mut next_state = state;
        next_state.sidechain_height += 1;
        next_state.parent_median_time_past += 1;
        next_state.trader_root = batch
            .verify(
                state.trader_root,
                configuration.accounting_bounds,
                usize::from(configuration.maximum_trader_updates),
            )
            .unwrap();
        let next_context = context(configuration, next_state, 21);
        let next = advance_successor_trader_archive(
            configuration,
            &first,
            next_context,
            SuccessorTraderArchiveTransitionV2 {
                version: SuccessorTraderArchiveTransitionV2::VERSION,
                previous_sidechain_block_hash: first.context.sidechain_block_hash,
                previous_state: state,
                next_state,
                trader_batch: Some(batch),
            },
        )
        .expect("typed update advances to the authenticated state");
        let snapshot = next
            .trader_snapshot(configuration, leaf.trader)
            .expect("present trader opens");
        snapshot
            .trader_read
            .verify(next_state.trader_root, configuration.accounting_bounds)
            .unwrap();
        assert_eq!(snapshot.trader_read.leaves, vec![leaf]);
    }

    #[test]
    fn successor_trader_archive_rejects_substitution_skip_and_corruption() {
        let configuration = configuration();
        let state =
            IncrementalPublicStateV2::canonical_empty(configuration, 10, 1_000, 5, 1, 10).unwrap();
        let first = bootstrap_successor_trader_archive(
            configuration,
            context(configuration, state, 20),
            state,
        )
        .unwrap();
        let mut next_state = state;
        next_state.sidechain_height += 1;
        next_state.parent_median_time_past += 1;
        let next_context = context(configuration, next_state, 21);

        let mut wrong_previous = state;
        wrong_previous.mark_price_atoms += 1;
        assert!(
            advance_successor_trader_archive(
                configuration,
                &first,
                next_context.clone(),
                SuccessorTraderArchiveTransitionV2 {
                    version: SuccessorTraderArchiveTransitionV2::VERSION,
                    previous_sidechain_block_hash: first.context.sidechain_block_hash,
                    previous_state: wrong_previous,
                    next_state,
                    trader_batch: None,
                },
            )
            .is_err()
        );

        let mut skipped_context = next_context.clone();
        skipped_context.sidechain_height += 1;
        skipped_context.last_transition_sidechain_height += 1;
        assert!(
            advance_successor_trader_archive(
                configuration,
                &first,
                skipped_context,
                SuccessorTraderArchiveTransitionV2 {
                    version: SuccessorTraderArchiveTransitionV2::VERSION,
                    previous_sidechain_block_hash: first.context.sidechain_block_hash,
                    previous_state: state,
                    next_state,
                    trader_batch: None,
                },
            )
            .is_err()
        );

        let mut corrupted = first;
        corrupted.state.trader_root.hash[0] ^= 1;
        assert!(corrupted.validate(configuration).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn successor_trader_archive_checkpoint_is_create_new_private_and_tamper_evident() {
        use std::os::unix::fs::PermissionsExt;

        let configuration = configuration();
        let state =
            IncrementalPublicStateV2::canonical_empty(configuration, 10, 1_000, 5, 1, 10).unwrap();
        let checkpoint = bootstrap_successor_trader_archive(
            configuration,
            context(configuration, state, 20),
            state,
        )
        .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = write_new_successor_trader_archive_checkpoint(
            temporary.path(),
            configuration,
            &checkpoint,
        )
        .unwrap();
        assert_eq!(
            read_successor_trader_archive_checkpoint(
                temporary.path(),
                configuration,
                checkpoint.context.sidechain_height,
                checkpoint.context.sidechain_block_hash,
            )
            .unwrap(),
            checkpoint
        );
        assert!(
            write_new_successor_trader_archive_checkpoint(
                temporary.path(),
                configuration,
                &checkpoint,
            )
            .is_err()
        );
        let mut bytes = std::fs::read(&path).unwrap();
        let mutation_index = bytes.len() / 2;
        bytes[mutation_index] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(
            read_successor_trader_archive_checkpoint(
                temporary.path(),
                configuration,
                checkpoint.context.sidechain_height,
                checkpoint.context.sidechain_block_hash,
            )
            .is_err()
        );
    }
}
