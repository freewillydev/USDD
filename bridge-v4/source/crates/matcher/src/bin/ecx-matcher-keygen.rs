use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use clap::Parser;
use ecx_matcher::matcher_public_key;
use secp256k1::{SecretKey, rand::rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Parser)]
#[command(name = "ecx-matcher-keygen")]
#[command(about = "Create a protected central-matcher BIP340 identity")]
struct Args {
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct MatcherKeyDocument {
    version: u16,
    role: String,
    secret_key_hex: String,
    public_key_xonly: String,
}

#[derive(Debug, Serialize)]
struct PublicIdentity<'a> {
    version: u16,
    role: &'a str,
    public_key_xonly: &'a str,
}

fn generate(output: &Path) -> anyhow::Result<String> {
    if output.exists() {
        bail!(
            "refusing to overwrite existing matcher key {}",
            output.display()
        );
    }
    let secret = SecretKey::new(&mut OsRng);
    let public = hex::encode(matcher_public_key(&secret).serialize());
    let mut document = MatcherKeyDocument {
        version: 1,
        role: "central_single_signer".to_owned(),
        secret_key_hex: hex::encode(secret.secret_bytes()),
        public_key_xonly: public.clone(),
    };
    let mut encoded = Zeroizing::new(serde_json::to_vec_pretty(&document)?);
    encoded.push(b'\n');
    document.zeroize();

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .with_context(|| format!("create protected matcher key {}", output.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    Ok(public)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let public = generate(&args.output)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&PublicIdentity {
            version: 1,
            role: "central_single_signer",
            public_key_xonly: &public,
        })?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_valid_private_identity_and_refuses_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("matcher.json");
        let public = generate(&path).unwrap();
        let document: MatcherKeyDocument =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let secret =
            SecretKey::from_slice(&hex::decode(&document.secret_key_hex).unwrap()).unwrap();
        assert_eq!(public, hex::encode(matcher_public_key(&secret).serialize()));
        assert_eq!(document.public_key_xonly, public);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(
            generate(&path)
                .unwrap_err()
                .to_string()
                .contains("refusing to overwrite")
        );
    }
}
