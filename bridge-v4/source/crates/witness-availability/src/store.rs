use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    error::{AvailabilityError, Result},
    format::{WitnessBundle, MAX_BUNDLE_BYTES},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    AlreadyPresent,
}

pub const MAX_STORE_BUNDLES: usize = 1_000_000;
pub const MAX_STORE_BYTES: u64 = 16 * 1024 * 1024 * 1_000_000;
const STORE_LOCK_NAME: &str = ".ecx-store.lock";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StoreAuditV1 {
    pub version: u8,
    pub bundle_count: u64,
    pub total_bytes: u64,
    pub inventory_sha256: [u8; 32],
}

#[derive(Debug)]
pub struct BundleStore {
    directory: PathBuf,
    _lock: File,
}

impl BundleStore {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref();
        if directory.exists() {
            let metadata = fs::symlink_metadata(directory)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AvailabilityError::CorruptStore);
            }
        } else {
            fs::create_dir_all(directory)?;
            set_directory_permissions(directory)?;
        }
        validate_directory_permissions(directory)?;
        let canonical = fs::canonicalize(directory)?;
        let lock_path = canonical.join(STORE_LOCK_NAME);
        let mut lock_options = OpenOptions::new();
        lock_options.create(true).read(true).write(true);
        set_file_mode(&mut lock_options);
        let lock = lock_options.open(&lock_path)?;
        validate_private_file(&lock_path)?;
        lock.try_lock_exclusive()
            .map_err(|_| AvailabilityError::StoreLocked)?;
        File::open(&canonical)?.sync_all()?;
        Ok(Self {
            directory: canonical,
            _lock: lock,
        })
    }

    pub fn put(&self, bundle: &WitnessBundle) -> Result<([u8; 32], PutOutcome)> {
        bundle.validate()?;
        let bytes = bundle.encode()?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(AvailabilityError::TooLarge);
        }
        let root = bundle.root()?;
        let destination = self.path_for(&root);
        if destination.exists() {
            self.verify_existing(&destination, &root, &bytes)?;
            return Ok((root, PutOutcome::AlreadyPresent));
        }

        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let temporary = self
            .directory
            .join(format!(".upload-{}", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        set_file_mode(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);

        let outcome = match fs::hard_link(&temporary, &destination) {
            Ok(()) => PutOutcome::Created,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify_existing(&destination, &root, &bytes)?;
                PutOutcome::AlreadyPresent
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(error.into());
            }
        };
        fs::remove_file(&temporary)?;
        File::open(&self.directory)?.sync_all()?;
        Ok((root, outcome))
    }

    pub fn get(&self, root: &[u8; 32]) -> Result<WitnessBundle> {
        let path = self.path_for(root);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AvailabilityError::NotFound);
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_BUNDLE_BYTES as u64
        {
            return Err(AvailabilityError::CorruptStore);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take((MAX_BUNDLE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(AvailabilityError::CorruptStore);
        }
        let bundle = WitnessBundle::decode(&bytes).map_err(|_| AvailabilityError::CorruptStore)?;
        let actual = bundle.root().map_err(|_| AvailabilityError::CorruptStore)?;
        if !bool::from(actual.ct_eq(root)) {
            return Err(AvailabilityError::CorruptStore);
        }
        Ok(bundle)
    }

    /// Prove at startup that this store can create, sync, read back, unlink,
    /// and directory-sync a fresh file in the configured failure domain.
    pub fn durability_probe(&self) -> Result<()> {
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let payload = [0x45, 0x43, 0x58, 0x57, 1, 0xa5, 0x5a];
        let path = self
            .directory
            .join(format!(".readiness-{}", hex::encode(random)));
        let result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            set_file_mode(&mut options);
            let mut output = options.open(&path)?;
            output.write_all(&payload)?;
            output.sync_all()?;
            drop(output);
            let mut observed = Vec::with_capacity(payload.len());
            File::open(&path)?.take(64).read_to_end(&mut observed)?;
            if observed != payload {
                return Err(AvailabilityError::CorruptStore);
            }
            fs::remove_file(&path)?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result
    }

    pub fn audit(&self) -> Result<StoreAuditV1> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(AvailabilityError::CorruptStore)?;
            if name == STORE_LOCK_NAME {
                validate_private_file(&entry.path())?;
                continue;
            }
            if entries.len() >= MAX_STORE_BUNDLES {
                return Err(AvailabilityError::StoreLimit);
            }
            let encoded_root = name
                .strip_suffix(".ecxw")
                .ok_or(AvailabilityError::CorruptStore)?;
            let root = Self::parse_root_hex(encoded_root)?;
            entries.push((root, entry.path()));
        }
        entries.sort_by_key(|(root, _)| *root);
        let mut total_bytes = 0_u64;
        let mut inventory = Sha256::new();
        inventory.update(b"ECX/witness-store-inventory/v1");
        inventory.update((entries.len() as u64).to_be_bytes());
        for (root, path) in &entries {
            validate_private_file(path)?;
            let length = fs::metadata(path)?.len();
            total_bytes = total_bytes
                .checked_add(length)
                .ok_or(AvailabilityError::StoreLimit)?;
            if total_bytes > MAX_STORE_BYTES {
                return Err(AvailabilityError::StoreLimit);
            }
            self.get(root)?;
            inventory.update(root);
            inventory.update(length.to_be_bytes());
        }
        Ok(StoreAuditV1 {
            version: 1,
            bundle_count: entries.len() as u64,
            total_bytes,
            inventory_sha256: inventory.finalize().into(),
        })
    }

    pub fn parse_root_hex(value: &str) -> Result<[u8; 32]> {
        if value.len() != 64
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(AvailabilityError::Canonical(
                "root must be 64 lowercase hexadecimal characters",
            ));
        }
        let decoded = hex::decode(value)
            .map_err(|_| AvailabilityError::Canonical("root hexadecimal encoding"))?;
        decoded
            .try_into()
            .map_err(|_| AvailabilityError::Canonical("root length"))
    }

    fn path_for(&self, root: &[u8; 32]) -> PathBuf {
        self.directory.join(format!("{}.ecxw", hex::encode(root)))
    }

    fn verify_existing(&self, path: &Path, root: &[u8; 32], expected: &[u8]) -> Result<()> {
        let existing = self.get(root)?;
        let actual = existing.encode()?;
        if actual.len() != expected.len() || !bool::from(actual.ct_eq(expected)) {
            return Err(AvailabilityError::CorruptStore);
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AvailabilityError::CorruptStore);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn validate_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AvailabilityError::CorruptStore);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AvailabilityError::CorruptStore);
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AvailabilityError::CorruptStore);
    }
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_file_mode(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_bundle, CustodianSecrets};

    fn bundle() -> WitnessBundle {
        let keys: Vec<_> = (1..=5)
            .map(|i| CustodianSecrets::generate(i).unwrap())
            .collect();
        let public: Vec<_> = keys.iter().map(CustodianSecrets::public).collect();
        create_bundle([3; 32], b"durable private state", &public).unwrap()
    }

    #[test]
    fn content_addressed_put_is_durable_and_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let store = BundleStore::open(temporary.path().join("bundles")).unwrap();
        let bundle = bundle();
        let (root, first) = store.put(&bundle).unwrap();
        assert_eq!(first, PutOutcome::Created);
        assert_eq!(store.get(&root).unwrap(), bundle);
        assert_eq!(store.put(&bundle).unwrap().1, PutOutcome::AlreadyPresent);
    }

    #[test]
    fn startup_durability_probe_is_clean_and_fails_when_store_disappears() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("bundles");
        let store = BundleStore::open(&path).unwrap();
        store.durability_probe().unwrap();
        let names: Vec<_> = fs::read_dir(&path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [STORE_LOCK_NAME]);
        fs::remove_file(path.join(STORE_LOCK_NAME)).unwrap();
        fs::remove_dir(&path).unwrap();
        assert!(store.durability_probe().is_err());
    }

    #[test]
    fn store_is_single_writer_and_offline_audit_commits_every_bundle() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("bundles");
        let store = BundleStore::open(&path).unwrap();
        assert!(matches!(
            BundleStore::open(&path),
            Err(AvailabilityError::StoreLocked)
        ));
        let first = bundle();
        let first_root = store.put(&first).unwrap().0;
        let second = bundle();
        let second_root = store.put(&second).unwrap().0;
        let audit = store.audit().unwrap();
        assert_eq!(audit.version, 1);
        assert_eq!(audit.bundle_count, 2);
        assert!(audit.total_bytes > 0);
        assert_ne!(audit.inventory_sha256, [0; 32]);

        let mut roots = [first_root, second_root];
        roots.sort();
        let mut expected = Sha256::new();
        expected.update(b"ECX/witness-store-inventory/v1");
        expected.update(2_u64.to_be_bytes());
        for root in roots {
            expected.update(root);
            expected.update(
                fs::metadata(store.path_for(&root))
                    .unwrap()
                    .len()
                    .to_be_bytes(),
            );
        }
        assert_eq!(
            audit.inventory_sha256,
            <[u8; 32]>::from(expected.finalize())
        );

        fs::write(path.join("foreign-file"), b"not a bundle").unwrap();
        assert!(matches!(
            store.audit(),
            Err(AvailabilityError::CorruptStore)
        ));
        fs::remove_file(path.join("foreign-file")).unwrap();
        let first_path = store.path_for(&first_root);
        let mut bytes = fs::read(&first_path).unwrap();
        bytes[0] ^= 1;
        fs::write(&first_path, bytes).unwrap();
        assert!(matches!(
            store.audit(),
            Err(AvailabilityError::CorruptStore)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn existing_store_with_broad_permissions_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("loose");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            BundleStore::open(path),
            Err(AvailabilityError::CorruptStore)
        ));
    }

    #[test]
    fn root_parser_is_canonical() {
        assert!(BundleStore::parse_root_hex(&"ab".repeat(32)).is_ok());
        assert!(BundleStore::parse_root_hex(&"AB".repeat(32)).is_err());
        assert!(BundleStore::parse_root_hex("../bundle").is_err());
    }
}
