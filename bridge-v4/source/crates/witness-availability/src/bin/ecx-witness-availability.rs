use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use ecx_witness_availability::{
    custodian_registry_hash, AvailabilityService, BundleStore, CustodianPublic, CustodianSecrets,
    ServiceConfig, CUSTODIAN_COUNT,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_KEY_FILE_BYTES: usize = 4_096;

#[derive(Parser)]
#[command(name = "ecx-witness-availability")]
#[command(about = "ECX encrypted witness storage and recovery-custodian service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new custodian key file with mode 0600 and print public keys.
    Keygen {
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5))]
        index: u8,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate five protected key files and emit their canonical public registry.
    Registry {
        #[arg(long)]
        output: PathBuf,
        #[arg(required = true, num_args = 5)]
        key_files: Vec<PathBuf>,
    },
    /// Exclusively lock and verify every bundle in an existing offline store.
    Audit {
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Serve a content-addressed replica, optionally with one custodian identity.
    Serve {
        #[arg(long)]
        store_dir: PathBuf,
        #[arg(long)]
        upload_token_file: PathBuf,
        #[arg(long)]
        read_token_file: PathBuf,
        #[arg(long)]
        recovery_token_file: PathBuf,
        #[arg(long)]
        custodian_key_file: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        /// Required for a non-loopback bind; deploy behind authenticated TLS/mTLS.
        #[arg(long)]
        allow_non_loopback: bool,
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    version: u16,
    custodian_index: u8,
    encryption_secret_hex: String,
    attestation_secret_hex: String,
}

#[derive(Serialize)]
struct PublicKeyOutput {
    custodian_index: u8,
    encryption_public_key: String,
    attestation_public_key: String,
}

#[derive(Serialize)]
struct RegistryOutput {
    schema: &'static str,
    registry_hex: String,
    registry_hash_hex: String,
    custodians: Vec<PublicKeyOutput>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match Cli::parse().command {
        Command::Keygen { index, output } => keygen(index, &output),
        Command::Registry { output, key_files } => registry(&key_files, &output),
        Command::Audit { store_dir } => {
            let metadata = fs::symlink_metadata(&store_dir)
                .with_context(|| format!("read store directory {}", store_dir.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("audit store must already exist as a directory");
            }
            let store = BundleStore::open(&store_dir).context("open and lock audit store")?;
            let audit = store.audit().context("audit witness store")?;
            println!("{}", serde_json::to_string_pretty(&audit)?);
            Ok(())
        }
        Command::Serve {
            store_dir,
            upload_token_file,
            read_token_file,
            recovery_token_file,
            custodian_key_file,
            listen,
            allow_non_loopback,
        } => {
            if !ip_is_loopback(listen.ip()) && !allow_non_loopback {
                bail!(
                    "refusing a non-loopback bind without --allow-non-loopback; terminate TLS/mTLS before this service"
                );
            }
            let upload_token = trim_line_endings(
                read_protected_file(&upload_token_file, MAX_KEY_FILE_BYTES)
                    .context("read upload token file")?,
            );
            let read_token = trim_line_endings(
                read_protected_file(&read_token_file, MAX_KEY_FILE_BYTES)
                    .context("read retrieval token file")?,
            );
            let recovery_token = trim_line_endings(
                read_protected_file(&recovery_token_file, MAX_KEY_FILE_BYTES)
                    .context("read recovery token file")?,
            );
            let custodian = custodian_key_file
                .as_deref()
                .map(load_key)
                .transpose()?
                .map(Arc::new);
            let store = Arc::new(BundleStore::open(&store_dir).context("open bundle store")?);
            let config = ServiceConfig::new(
                store,
                custodian,
                upload_token.to_vec(),
                read_token.to_vec(),
                recovery_token.to_vec(),
            )?;
            let listener = TcpListener::bind(listen).await.context("bind listener")?;
            tracing::info!(address = %listen, "witness availability service listening");
            AvailabilityService::new(config)
                .serve(listener)
                .await
                .context("serve availability API")
        }
    }
}

fn keygen(index: u8, output: &Path) -> anyhow::Result<()> {
    if output.exists() {
        bail!(
            "refusing to overwrite existing key file {}",
            output.display()
        );
    }
    let secrets = CustodianSecrets::generate(index)?;
    let (encryption, attestation) = secrets.provisioning_bytes();
    let document = KeyDocument {
        version: 1,
        custodian_index: index,
        encryption_secret_hex: hex::encode(encryption),
        attestation_secret_hex: hex::encode(attestation),
    };
    let mut encoded = Zeroizing::new(serde_json::to_vec_pretty(&document)?);
    encoded.push(b'\n');
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    set_private_file_mode(&mut options);
    let mut file = options
        .open(output)
        .with_context(|| format!("create {}", output.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;

    let public = secrets.public();
    println!(
        "{}",
        serde_json::to_string_pretty(&PublicKeyOutput {
            custodian_index: public.index,
            encryption_public_key: hex::encode(public.encryption_public_key),
            attestation_public_key: hex::encode(public.attestation_public_key),
        })?
    );
    Ok(())
}

fn registry(key_files: &[PathBuf], output: &Path) -> anyhow::Result<()> {
    if key_files.len() != CUSTODIAN_COUNT {
        bail!("registry requires exactly {CUSTODIAN_COUNT} custodian key files");
    }
    if output.exists() {
        bail!(
            "refusing to overwrite existing registry file {}",
            output.display()
        );
    }

    let mut custodians = key_files
        .iter()
        .map(|path| load_key(path).map(|secrets| secrets.public()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    custodians.sort_unstable_by_key(|custodian| custodian.index);
    let registry_hash =
        custodian_registry_hash(&custodians).context("validate canonical custodian registry")?;
    let registry_bytes = encode_registry(&custodians);
    let document = RegistryOutput {
        schema: "ECX_WITNESS_CUSTODIAN_REGISTRY_V1",
        registry_hex: hex::encode(registry_bytes),
        registry_hash_hex: hex::encode(registry_hash),
        custodians: custodians
            .into_iter()
            .map(|public| PublicKeyOutput {
                custodian_index: public.index,
                encryption_public_key: hex::encode(public.encryption_public_key),
                attestation_public_key: hex::encode(public.attestation_public_key),
            })
            .collect(),
    };
    let mut encoded = serde_json::to_vec_pretty(&document)?;
    encoded.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .with_context(|| format!("create {}", output.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    Ok(())
}

fn encode_registry(custodians: &[CustodianPublic]) -> Vec<u8> {
    let mut output = Vec::with_capacity(CUSTODIAN_COUNT * 65);
    for custodian in custodians {
        output.push(custodian.index);
        output.extend_from_slice(&custodian.encryption_public_key);
        output.extend_from_slice(&custodian.attestation_public_key);
    }
    output
}

fn load_key(path: &Path) -> anyhow::Result<CustodianSecrets> {
    let bytes = read_protected_file(path, MAX_KEY_FILE_BYTES)?;
    let document: KeyDocument =
        serde_json::from_slice(&bytes).context("parse custodian key file")?;
    if document.version != 1 {
        bail!("unsupported custodian key file version");
    }
    let encryption = decode_secret(&document.encryption_secret_hex, "encryption_secret_hex")?;
    let attestation = decode_secret(&document.attestation_secret_hex, "attestation_secret_hex")?;
    CustodianSecrets::new(document.custodian_index, encryption, attestation)
        .context("validate custodian keys")
}

fn decode_secret(value: &str, field: &'static str) -> anyhow::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{field} must contain exactly 64 hexadecimal characters");
    }
    let decoded = Zeroizing::new(hex::decode(value).with_context(|| format!("decode {field}"))?);
    decoded
        .as_slice()
        .try_into()
        .with_context(|| format!("decode {field} length"))
}

fn read_protected_file(path: &Path, maximum: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect protected file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("protected file must be a regular non-symlink file");
    }
    check_private_permissions(&metadata)?;
    if metadata.len() > maximum as u64 {
        bail!("protected file exceeds {maximum} bytes");
    }
    let mut output = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > maximum {
        bail!("protected file exceeds {maximum} bytes");
    }
    Ok(output)
}

fn trim_line_endings(mut value: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        value.pop();
    }
    value
}

fn ip_is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

#[cfg(unix)]
fn set_private_file_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn check_private_permissions(metadata: &fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("protected file permissions must not grant group or other access");
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_metadata: &fs::Metadata) -> anyhow::Result<()> {
    Ok(())
}
