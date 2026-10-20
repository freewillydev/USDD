use std::time::Duration;

use clap::Parser;
use ecx_truthcoin_keeper::{canonical_json_sha256, HttpTruthcoinRpc, TruthcoinRpc};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "ecx-truthcoin-schema")]
#[command(about = "Print the canonical hash of a Truthcoin node's OpenAPI schema")]
struct Args {
    #[arg(long, env = "ECX_TRUTHCOIN_RPC_URL")]
    rpc_url: String,
    #[arg(long, default_value_t = 30)]
    timeout_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.timeout_seconds == 0 || args.timeout_seconds > 300 {
        return Err("timeout_seconds must be in 1..=300".into());
    }
    let rpc = HttpTruthcoinRpc::new(args.rpc_url, Duration::from_secs(args.timeout_seconds))?;
    let schema = rpc.call("openapi_schema", json!([])).await?;
    println!("{}", hex::encode(canonical_json_sha256(&schema)));
    Ok(())
}
