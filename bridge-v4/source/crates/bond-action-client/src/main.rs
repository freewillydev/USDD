use std::{path::PathBuf, process::ExitCode, time::Duration};

use clap::{Parser, Subcommand};
use ecx_bond_action_client::{hash32, BondActionClient, ClientConfig, Error};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(about = "Fail-closed signer for ECX v2 proof-enforced bond actions")]
struct Args {
    #[arg(long, env = "ECX_MATCHER_URL", default_value = "http://127.0.0.1:8088")]
    matcher_url: String,
    #[arg(long, env = "ECX_TRANSITION_PRODUCER_URL")]
    transition_producer_url: String,
    #[arg(long, env = "ECX_ELEMENTS_RPC_URL")]
    elements_rpc_url: String,
    #[arg(long, env = "ECX_ELEMENTS_RPC_USER")]
    elements_rpc_user: Option<String>,
    #[arg(long, env = "ECX_ELEMENTS_RPC_PASSWORD", hide_env_values = true)]
    elements_rpc_password: Option<String>,
    #[arg(long, env = "ECX_BOND_EXPECTED_CHAIN_ID")]
    expected_chain_id: String,
    #[arg(long, env = "ECX_BOND_EXPECTED_CONFIGURATION_HASH")]
    expected_configuration_hash: String,
    #[arg(long, env = "ECX_BOND_EXPECTED_ASSET_ID")]
    expected_bond_asset_id: String,
    #[arg(long, env = "ECX_BOND_EXPECTED_DEPLOYMENT_COMMITMENT")]
    expected_deployment_commitment: String,
    #[arg(long, env = "ECX_BOND_EXPECTED_TRANSITION_PROGRAM_ID")]
    expected_transition_program_id: String,
    #[arg(long, env = "ECX_BOND_EXPECTED_SIMPLICITY_TRANSITION_CMR")]
    expected_simplicity_transition_cmr: String,
    #[arg(long, env = "ECX_BOND_RECIPIENT_SCRIPT_SHA256")]
    bond_recipient_script_sha256: String,
    #[arg(long, env = "ECX_BOND_HOLDER_SCRIPT_SHA256")]
    bond_holder_script_sha256: String,
    #[arg(long, env = "ECX_USDD_DESTINATION_SCRIPT_SHA256")]
    usdd_destination_script_sha256: String,
    #[arg(long, env = "ECX_BOND_ACTION_TIMEOUT_SECONDS", default_value_t = 15)]
    timeout_seconds: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status,
    TransferStatus,
    Subscribe {
        #[arg(long, env = "ECX_TRADER_SECRET_KEY_FILE")]
        key_file: PathBuf,
        #[arg(long)]
        contribution_usdd_atoms: u64,
    },
    RecapitalizeInsurance {
        #[arg(long, env = "ECX_TRADER_SECRET_KEY_FILE")]
        key_file: PathBuf,
        #[arg(long)]
        contribution_usdd_atoms: u64,
    },
    EnqueueRedemption {
        #[arg(long, env = "ECX_TRADER_SECRET_KEY_FILE")]
        key_file: PathBuf,
        #[arg(long)]
        bond_share_atoms: u64,
    },
    CancelRedemption {
        #[arg(long, env = "ECX_TRADER_SECRET_KEY_FILE")]
        key_file: PathBuf,
        #[arg(long)]
        request_id: String,
    },
    Transfer {
        #[arg(long)]
        destination: String,
        #[arg(long)]
        bond_share_atoms: u64,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string(&value).expect("serializable output")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({
                    "accepted": false,
                    "ready": false,
                    "code": error.code(),
                    "stage": error.stage(),
                    "retryable": error.retryable(),
                    "error": error.to_string(),
                })
            );
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<serde_json::Value, Error> {
    let args = Args::parse();
    let config = ClientConfig::new(
        &args.matcher_url,
        &args.transition_producer_url,
        &args.elements_rpc_url,
        args.elements_rpc_user,
        args.elements_rpc_password,
        &args.expected_chain_id,
        &args.expected_configuration_hash,
        &args.expected_bond_asset_id,
        &args.expected_deployment_commitment,
        &args.expected_transition_program_id,
        &args.expected_simplicity_transition_cmr,
        &args.bond_recipient_script_sha256,
        &args.bond_holder_script_sha256,
        &args.usdd_destination_script_sha256,
        Duration::from_secs(args.timeout_seconds.clamp(1, 60)),
    )?;
    let client = BondActionClient::new(config);
    match args.command {
        Command::Status => serde_json::to_value(client.status().await?)
            .map_err(|error| Error::Configuration(error.to_string())),
        Command::TransferStatus => serde_json::to_value(client.transfer_status().await?)
            .map_err(|error| Error::Configuration(error.to_string())),
        Command::Subscribe {
            key_file,
            contribution_usdd_atoms,
        } => serde_json::to_value(client.subscribe(&key_file, contribution_usdd_atoms).await?)
            .map_err(|error| Error::Configuration(error.to_string())),
        Command::EnqueueRedemption {
            key_file,
            bond_share_atoms,
        } => serde_json::to_value(
            client
                .enqueue_redemption(&key_file, bond_share_atoms)
                .await?,
        )
        .map_err(|error| Error::Configuration(error.to_string())),
        Command::RecapitalizeInsurance {
            key_file,
            contribution_usdd_atoms,
        } => serde_json::to_value(
            client
                .recapitalize_insurance(&key_file, contribution_usdd_atoms)
                .await?,
        )
        .map_err(|error| Error::Configuration(error.to_string())),
        Command::CancelRedemption {
            key_file,
            request_id,
        } => {
            let request_id = hash32(&request_id, "redemption request id")?;
            serde_json::to_value(client.cancel_redemption(&key_file, request_id).await?)
                .map_err(|error| Error::Configuration(error.to_string()))
        }
        Command::Transfer {
            destination,
            bond_share_atoms,
        } => serde_json::to_value(client.transfer(&destination, bond_share_atoms).await?)
            .map_err(|error| Error::Configuration(error.to_string())),
    }
}
