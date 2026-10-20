use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ecx_truthcoin_keeper::{
    ensure_canonical_market, load_keeper_config, preflight_canonical_market, HttpTruthcoinRpc,
    KeeperAction, KeeperError, KeeperStateLock, KeeperStateV1,
};

#[derive(Debug, Parser)]
#[command(name = "ecx-truthcoin-keeper")]
#[command(about = "Submit missing canonical Truthcoin scalar-price markets")]
struct Args {
    #[arg(long, env = "ECX_TRUTHCOIN_KEEPER_CONFIG")]
    config: PathBuf,
    #[arg(long, env = "ECX_TRUTHCOIN_KEEPER_STATE")]
    state: Option<PathBuf>,
    #[arg(long, default_value_t = 30)]
    interval_seconds: u64,
    #[arg(long)]
    once: bool,
    /// Validate the live node and canonical market set without spending wallet funds.
    #[arg(long, conflicts_with = "once")]
    preflight: bool,
    /// In preflight mode, exit nonzero unless every required current/look-ahead market exists.
    #[arg(long, requires = "preflight")]
    require_existing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollFailureDisposition {
    Retry,
    Exit,
}

fn poll_failure_disposition(once: bool, error: &KeeperError) -> PollFailureDisposition {
    if once || !error.is_retryable_availability_failure() {
        PollFailureDisposition::Exit
    } else {
        PollFailureDisposition::Retry
    }
}

fn preflight_satisfies_readiness(action: &KeeperAction) -> bool {
    matches!(action, KeeperAction::Existing { .. })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !args.once && args.interval_seconds == 0 {
        return Err("interval_seconds must be nonzero unless --once is used".into());
    }
    let config = load_keeper_config(&args.config)?;
    let rpc = HttpTruthcoinRpc::new(
        config.truthcoin_rpc_url.clone(),
        Duration::from_secs(config.request_timeout_seconds),
    )?;
    if args.preflight {
        let action = preflight_canonical_market(&config, &rpc).await?;
        if args.require_existing && !preflight_satisfies_readiness(&action) {
            if let KeeperAction::Missing {
                period,
                identity_hash,
            } = &action
            {
                return Err(format!(
                    "required canonical Truthcoin market is missing: period={period} identity={}",
                    hex::encode(identity_hash)
                )
                .into());
            }
            return Err("strict Truthcoin preflight did not observe a canonical market".into());
        }
        match action {
            KeeperAction::Existing {
                period, market_id, ..
            } => {
                eprintln!("Truthcoin preflight passed: canonical market exists for period={period} market={market_id}");
            }
            KeeperAction::Missing {
                period,
                identity_hash,
            } => {
                eprintln!("Truthcoin preflight passed: canonical market is missing for period={period} identity={}", hex::encode(identity_hash));
            }
            KeeperAction::Pending(_) | KeeperAction::Submitted(_) => {
                return Err("read-only preflight attempted a state-changing action".into());
            }
        }
        return Ok(());
    }
    let state_path = args
        .state
        .as_ref()
        .ok_or("--state is required unless --preflight is used")?;
    let _state_lock = KeeperStateLock::acquire(state_path)?;
    let mut state = KeeperStateV1::load(state_path)?;

    loop {
        let action = match ensure_canonical_market(&config, &rpc, state.pending.as_ref()).await {
            Ok(action) => action,
            Err(error)
                if poll_failure_disposition(args.once, &error) == PollFailureDisposition::Retry =>
            {
                eprintln!(
                    "Truthcoin market poll failed closed; retrying in {} seconds: {error}",
                    args.interval_seconds
                );
                tokio::time::sleep(Duration::from_secs(args.interval_seconds)).await;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        match &action {
            KeeperAction::Existing {
                period, market_id, ..
            } => {
                state.pending = None;
                eprintln!("canonical Truthcoin market exists: period={period} market={market_id}");
            }
            KeeperAction::Pending(pending) => {
                state.pending = Some(pending.clone());
                eprintln!(
                    "canonical Truthcoin market submission pending: period={} txid={}",
                    pending.period, pending.txid
                );
            }
            KeeperAction::Submitted(pending) => {
                state.pending = Some(pending.clone());
                eprintln!(
                    "submitted canonical Truthcoin market: period={} txid={} market={}",
                    pending.period, pending.txid, pending.market_id
                );
            }
            KeeperAction::Missing { .. } => {
                return Err("market creation unexpectedly disabled".into());
            }
        }
        state.save_atomic(state_path)?;
        if args.once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(args.interval_seconds)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuous_mode_retries_only_availability_failures() {
        let retryable = KeeperError::Rpc {
            code: -28,
            message: "node warming up".into(),
        };
        assert_eq!(
            poll_failure_disposition(false, &retryable),
            PollFailureDisposition::Retry
        );
        assert_eq!(
            poll_failure_disposition(true, &retryable),
            PollFailureDisposition::Exit
        );
        let permanent = [
            KeeperError::SchemaMismatch {
                expected: "aa".into(),
                observed: "bb".into(),
            },
            KeeperError::MalformedRpcResponse,
            KeeperError::ConfirmedSubmissionMissingMarket {
                txid: "tx".into(),
                period: 1,
            },
            KeeperError::TestingModeRejected,
            KeeperError::RpcResponseTooLarge,
            KeeperError::Rpc {
                code: -6,
                message: "insufficient funds".into(),
            },
        ];
        for error in permanent {
            assert_eq!(
                poll_failure_disposition(false, &error),
                PollFailureDisposition::Exit
            );
        }
    }

    #[test]
    fn strict_preflight_requires_existing_market_and_cli_pairing() {
        let existing = KeeperAction::Existing {
            period: 7,
            market_id: "11".repeat(6),
            decision_id: "870001".into(),
        };
        let missing = KeeperAction::Missing {
            period: 7,
            identity_hash: [9; 32],
        };
        assert!(preflight_satisfies_readiness(&existing));
        assert!(!preflight_satisfies_readiness(&missing));
        assert!(Args::try_parse_from([
            "keeper",
            "--config",
            "keeper.json",
            "--preflight",
            "--require-existing",
        ])
        .is_ok());
        assert!(
            Args::try_parse_from(["keeper", "--config", "keeper.json", "--require-existing",])
                .is_err()
        );
    }
}
