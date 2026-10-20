use clap::Parser;
use ecx_forced_action_client::ElementsRpc;
use std::time::Duration;

#[derive(Parser)]
#[command(about = "Fund, wallet-sign, verify, and broadcast a canonical ECXF action")]
struct Args {
    #[arg(long, env = "ECX_ELEMENTS_RPC_URL")]
    rpc_url: String,
    #[arg(long, env = "ECX_ELEMENTS_RPC_USER")]
    rpc_user: Option<String>,
    #[arg(long, env = "ECX_ELEMENTS_RPC_PASSWORD", hide_env_values = true)]
    rpc_password: Option<String>,
    #[arg(long)]
    payload_hex: String,
    #[arg(long)]
    expected_chain_id_hex: String,
    #[arg(long, default_value_t = 15)]
    timeout_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let payload = hex::decode(args.payload_hex)?;
    let chain_id_bytes = hex::decode(args.expected_chain_id_hex)?;
    let expected_chain_id =
        <[u8; 32]>::try_from(chain_id_bytes).map_err(|_| "expected chain ID must be 32 bytes")?;
    let rpc = ElementsRpc::new(
        &args.rpc_url,
        args.rpc_user,
        args.rpc_password,
        Duration::from_secs(args.timeout_seconds),
    )?;
    let receipt = rpc
        .broadcast_forced_action(&payload, expected_chain_id)
        .await?;
    println!("{}", receipt.txid);
    Ok(())
}
