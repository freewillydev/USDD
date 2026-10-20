use std::path::PathBuf;

use clap::Parser;
use ecx_truthcoin_keeper::load_keeper_config;

#[derive(Debug, Parser)]
#[command(name = "ecx-truthcoin-template-hash")]
#[command(about = "Print the source-proof commitment for a keeper template")]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load_keeper_config(&args.config)?;
    println!("{}", hex::encode(config.market.source_template_hash()));
    Ok(())
}
