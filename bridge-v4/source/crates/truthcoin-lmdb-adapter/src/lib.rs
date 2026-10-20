//! Native differential bridge between the pinned Truthcoin 0.17 LMDB state
//! and ECX's canonical patched 37-table checkpoint.
//!
//! This crate does not define consensus and is not linked into the proof guest.
//! It reads or writes all named databases in one LMDB transaction so the
//! unmodified upstream engine can be compared against the deterministic guest
//! backend after every transition and reorganization.

use std::path::Path;

use ecx_truthcoin_replay::{
    CanonicalStateEntryV1, CanonicalStateSnapshotV1, CanonicalStateTableV1,
    TRUTHCOIN_STATE_DATABASE_NAMES,
};
use heed::{types::Bytes, Env, EnvOpenOptions};
use thiserror::Error;

pub const TRUTHCOIN_LMDB_ADAPTER_VERSION: u8 = 1;
pub const TRUTHCOIN_LMDB_MAX_DATABASES: u32 = 64;
pub const DEFAULT_LMDB_MAP_SIZE: usize = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("LMDB operation failed: {0}")]
    Lmdb(#[from] heed::Error),
    #[error("missing pinned Truthcoin state database `{0}`")]
    MissingDatabase(&'static str),
    #[error("canonical Truthcoin checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("refusing to import into a nonempty Truthcoin state database `{0}`")]
    NonemptyDatabase(&'static str),
    #[error("Truthcoin lifecycle checkpoint `{0}` is not byte-identical")]
    LifecycleMismatch(&'static str),
    #[error("Truthcoin connect checkpoint did not change consensus state")]
    LifecycleDidNotAdvance,
}

/// Open an existing Truthcoin environment. LMDB's API requires an unsafe open
/// because it cannot prove filesystem and process invariants; callers must not
/// concurrently replace or truncate the directory.
pub fn open_existing(path: &Path) -> Result<Env, AdapterError> {
    let mut options = EnvOpenOptions::new();
    options.max_dbs(TRUTHCOIN_LMDB_MAX_DATABASES);
    // SAFETY: no raw pointers escape. The returned Env owns its mapping, and
    // callers are required not to replace/truncate `path` while it is open.
    Ok(unsafe { options.open(path)? })
}

/// Open or create an environment suitable for atomic checkpoint import.
pub fn open_for_import(path: &Path, map_size: usize) -> Result<Env, AdapterError> {
    let mut options = EnvOpenOptions::new();
    options
        .max_dbs(TRUTHCOIN_LMDB_MAX_DATABASES)
        .map_size(map_size);
    // SAFETY: same ownership and filesystem precondition as `open_existing`.
    Ok(unsafe { options.open(path)? })
}

/// Export one transactionally consistent view of every pinned state database.
/// Iteration uses LMDB's bytewise key order and the exact stored codec bytes.
pub fn export_snapshot(env: &Env) -> Result<CanonicalStateSnapshotV1, AdapterError> {
    let rtxn = env.read_txn()?;
    let mut tables = Vec::with_capacity(TRUTHCOIN_STATE_DATABASE_NAMES.len());
    for (database_id, name) in TRUTHCOIN_STATE_DATABASE_NAMES.iter().enumerate() {
        let database = env
            .open_database::<Bytes, Bytes>(&rtxn, Some(name))?
            .ok_or(AdapterError::MissingDatabase(name))?;
        let mut entries = Vec::new();
        let iterator = database.iter(&rtxn)?;
        for result in iterator {
            let (key, value) = result?;
            entries.push(CanonicalStateEntryV1 {
                key: key.to_vec(),
                value: value.to_vec(),
            });
        }
        tables.push(CanonicalStateTableV1 {
            database_id: database_id as u8,
            entries,
        });
    }
    let snapshot = CanonicalStateSnapshotV1 {
        version: CanonicalStateSnapshotV1::VERSION,
        tables,
    };
    snapshot
        .validate()
        .map_err(|_| AdapterError::InvalidCheckpoint)?;
    Ok(snapshot)
}

pub fn export_checkpoint_bytes(env: &Env) -> Result<Vec<u8>, AdapterError> {
    export_snapshot(env)?
        .encode()
        .map_err(|_| AdapterError::InvalidCheckpoint)
}

/// Import a complete checkpoint into empty state databases in one atomic LMDB
/// write transaction. Refusing nonempty tables prevents accidental rollback or
/// replacement of a live node's state.
pub fn import_snapshot(env: &Env, snapshot: &CanonicalStateSnapshotV1) -> Result<(), AdapterError> {
    snapshot
        .validate()
        .map_err(|_| AdapterError::InvalidCheckpoint)?;
    let mut wtxn = env.write_txn()?;
    for (table, name) in snapshot.tables.iter().zip(TRUTHCOIN_STATE_DATABASE_NAMES) {
        let database = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(name))?;
        if database.first(&wtxn)?.is_some() {
            return Err(AdapterError::NonemptyDatabase(name));
        }
        for entry in &table.entries {
            database.put(&mut wtxn, &entry.key, &entry.value)?;
        }
    }
    wtxn.commit()?;
    Ok(())
}

pub fn import_checkpoint_bytes(env: &Env, bytes: &[u8]) -> Result<(), AdapterError> {
    let snapshot =
        CanonicalStateSnapshotV1::decode(bytes).map_err(|_| AdapterError::InvalidCheckpoint)?;
    import_snapshot(env, &snapshot)
}

/// Return every pinned database whose exact ordered codec-byte contents differ.
pub fn differing_database_names(
    left: &CanonicalStateSnapshotV1,
    right: &CanonicalStateSnapshotV1,
) -> Result<Vec<&'static str>, AdapterError> {
    left.validate()
        .and_then(|_| right.validate())
        .map_err(|_| AdapterError::InvalidCheckpoint)?;
    Ok(left
        .tables
        .iter()
        .zip(&right.tables)
        .zip(TRUTHCOIN_STATE_DATABASE_NAMES)
        .filter_map(|((left, right), name)| (left != right).then_some(name))
        .collect())
}

/// Verify the four-checkpoint differential invariant used for every native
/// upstream lifecycle vector. A rollback must reproduce the exact initial
/// canonical bytes, and replaying the same block must reproduce the exact
/// connected bytes. Requiring the connected state to differ prevents an empty
/// or accidentally skipped fixture from producing a vacuous pass.
pub fn verify_lifecycle_checkpoint_bytes(
    initial: &[u8],
    connected: &[u8],
    disconnected: &[u8],
    reconnected: &[u8],
) -> Result<(), AdapterError> {
    for bytes in [initial, connected, disconnected, reconnected] {
        CanonicalStateSnapshotV1::decode(bytes).map_err(|_| AdapterError::InvalidCheckpoint)?;
    }
    if initial == connected {
        return Err(AdapterError::LifecycleDidNotAdvance);
    }
    if initial != disconnected {
        return Err(AdapterError::LifecycleMismatch("initial/disconnected"));
    }
    if connected != reconnected {
        return Err(AdapterError::LifecycleMismatch("connected/reconnected"));
    }
    Ok(())
}

/// Verify two distinct valid successors of the same parent across a complete
/// branch switch. Both rollbacks must reproduce the parent exactly and both
/// branches must reproduce their own checkpoint exactly when revisited.
pub fn verify_fork_lifecycle_checkpoint_bytes(
    parent: &[u8],
    branch_a: &[u8],
    rollback_a: &[u8],
    branch_b: &[u8],
    rollback_b: &[u8],
    replay_a: &[u8],
    replay_b: &[u8],
) -> Result<(), AdapterError> {
    for bytes in [
        parent, branch_a, rollback_a, branch_b, rollback_b, replay_a, replay_b,
    ] {
        CanonicalStateSnapshotV1::decode(bytes).map_err(|_| AdapterError::InvalidCheckpoint)?;
    }
    if parent == branch_a || parent == branch_b || branch_a == branch_b {
        return Err(AdapterError::LifecycleDidNotAdvance);
    }
    if parent != rollback_a || parent != rollback_b {
        return Err(AdapterError::LifecycleMismatch("fork parent rollback"));
    }
    if branch_a != replay_a {
        return Err(AdapterError::LifecycleMismatch("branch A replay"));
    }
    if branch_b != replay_b {
        return Err(AdapterError::LifecycleMismatch("branch B replay"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecx_truthcoin_replay::CanonicalStateStoreV1;

    #[test]
    fn all_patched_tables_round_trip_exact_codec_bytes() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = open_for_import(source_dir.path(), 64 * 1024 * 1024).unwrap();
        let mut store = CanonicalStateStoreV1::new();
        for database_id in 0..TRUTHCOIN_STATE_DATABASE_NAMES.len() as u8 {
            store
                .put(
                    database_id,
                    vec![database_id, 0],
                    vec![database_id.wrapping_add(1)],
                )
                .unwrap();
        }
        import_snapshot(&source, store.snapshot()).unwrap();
        let exported = export_snapshot(&source).unwrap();
        assert_eq!(exported, *store.snapshot());
        assert_eq!(exported.root().unwrap(), store.root().unwrap());
    }

    #[test]
    fn import_is_atomic_and_refuses_live_state_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let env = open_for_import(directory.path(), 64 * 1024 * 1024).unwrap();
        let mut store = CanonicalStateStoreV1::new();
        store.put(0, vec![1], vec![2]).unwrap();
        import_snapshot(&env, store.snapshot()).unwrap();

        let mut replacement = CanonicalStateStoreV1::new();
        replacement.put(1, vec![3], vec![4]).unwrap();
        assert!(matches!(
            import_snapshot(&env, replacement.snapshot()),
            Err(AdapterError::NonemptyDatabase("reputation"))
        ));
        assert_eq!(export_snapshot(&env).unwrap(), *store.snapshot());
    }

    #[test]
    fn export_fails_if_any_pinned_database_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let env = open_for_import(directory.path(), 64 * 1024 * 1024).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        env.create_database::<Bytes, Bytes>(&mut wtxn, Some("reputation"))
            .unwrap();
        wtxn.commit().unwrap();
        assert!(matches!(
            export_snapshot(&env),
            Err(AdapterError::MissingDatabase("period_decisions"))
        ));
    }

    #[test]
    fn checkpoint_diff_reports_exact_changed_tables() {
        let left = CanonicalStateStoreV1::new();
        let mut right = CanonicalStateStoreV1::new();
        right.put(18, vec![1], vec![2]).unwrap();
        right.put(19, vec![3], vec![4]).unwrap();
        assert_eq!(
            differing_database_names(left.snapshot(), right.snapshot()).unwrap(),
            vec!["mainchain_timestamp", "genesis_timestamp"]
        );
    }

    #[test]
    fn lifecycle_requires_exact_rollback_and_replay_bytes() {
        let initial = CanonicalStateStoreV1::new().snapshot().encode().unwrap();
        let mut connected_store = CanonicalStateStoreV1::new();
        connected_store.put(16, vec![1], vec![2]).unwrap();
        let connected = connected_store.snapshot().encode().unwrap();

        verify_lifecycle_checkpoint_bytes(&initial, &connected, &initial, &connected).unwrap();
        assert!(matches!(
            verify_lifecycle_checkpoint_bytes(&initial, &initial, &initial, &initial),
            Err(AdapterError::LifecycleDidNotAdvance)
        ));

        let mut bad_rollback = CanonicalStateStoreV1::new();
        bad_rollback.put(18, vec![3], vec![4]).unwrap();
        let bad_rollback = bad_rollback.snapshot().encode().unwrap();
        assert!(matches!(
            verify_lifecycle_checkpoint_bytes(&initial, &connected, &bad_rollback, &connected),
            Err(AdapterError::LifecycleMismatch("initial/disconnected"))
        ));

        let mut bad_replay = connected_store;
        bad_replay.put(19, vec![5], vec![6]).unwrap();
        let bad_replay = bad_replay.snapshot().encode().unwrap();
        assert!(matches!(
            verify_lifecycle_checkpoint_bytes(&initial, &connected, &initial, &bad_replay),
            Err(AdapterError::LifecycleMismatch("connected/reconnected"))
        ));
    }

    #[test]
    fn fork_lifecycle_requires_distinct_reproducible_branches() {
        fn checkpoint(marker: Option<(u8, u8)>) -> Vec<u8> {
            let mut store = CanonicalStateStoreV1::new();
            if let Some((key, value)) = marker {
                store.put(5, vec![key], vec![value]).unwrap();
            }
            store.export().unwrap()
        }
        let parent = checkpoint(None);
        let branch_a = checkpoint(Some((1, 10)));
        let branch_b = checkpoint(Some((2, 20)));
        verify_fork_lifecycle_checkpoint_bytes(
            &parent, &branch_a, &parent, &branch_b, &parent, &branch_a, &branch_b,
        )
        .unwrap();
        assert!(matches!(
            verify_fork_lifecycle_checkpoint_bytes(
                &parent, &branch_a, &parent, &branch_a, &parent, &branch_a, &branch_a,
            ),
            Err(AdapterError::LifecycleDidNotAdvance)
        ));
    }
}
