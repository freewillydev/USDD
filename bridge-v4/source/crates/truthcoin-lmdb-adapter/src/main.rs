use std::{env, fs, path::Path, process::ExitCode};

use ecx_truthcoin_lmdb_adapter::{
    differing_database_names, export_checkpoint_bytes, import_checkpoint_bytes, open_existing,
    open_for_import, verify_fork_lifecycle_checkpoint_bytes, verify_lifecycle_checkpoint_bytes,
    DEFAULT_LMDB_MAP_SIZE,
};
use ecx_truthcoin_replay::{
    apply_truthcoin_block_transition, extract_truthcoin_oracle_candidates,
    revert_truthcoin_block_transition, CanonicalBlockContextV1, CanonicalStateSnapshotV1,
    CanonicalStateStoreV1, TruthcoinBlockV1, TruthcoinBodyV1,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ecx-truthcoin-lmdb-adapter: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, lmdb_path, checkpoint_path] if command == "export" => {
            let env = open_existing(Path::new(lmdb_path))?;
            let bytes = export_checkpoint_bytes(&env)?;
            fs::write(checkpoint_path, bytes)?;
        }
        [command, checkpoint_path, lmdb_path] if command == "import" => {
            fs::create_dir_all(lmdb_path)?;
            let bytes = fs::read(checkpoint_path)?;
            let env = open_for_import(Path::new(lmdb_path), DEFAULT_LMDB_MAP_SIZE)?;
            import_checkpoint_bytes(&env, &bytes)?;
        }
        [command, lmdb_path, checkpoint_path] if command == "verify" => {
            let expected = fs::read(checkpoint_path)?;
            let env = open_existing(Path::new(lmdb_path))?;
            let actual = export_checkpoint_bytes(&env)?;
            if actual != expected {
                return Err("LMDB state does not equal the canonical checkpoint".into());
            }
        }
        [command, left_path, right_path] if command == "diff" => {
            let left = CanonicalStateSnapshotV1::decode(&fs::read(left_path)?)?;
            let right = CanonicalStateSnapshotV1::decode(&fs::read(right_path)?)?;
            for name in differing_database_names(&left, &right)? {
                println!("{name}");
            }
        }
        [command, parent_path, output_path, height, timestamp, header_path]
            if command == "replay-voted-finalization" =>
        {
            let height = height.parse::<u32>()?;
            let timestamp = timestamp.parse::<u64>()?;
            let parent = fs::read(parent_path)?;
            let mut store = CanonicalStateStoreV1::import(&parent)?;
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height: u64::from(height),
                bmm_main_height: u64::from(height),
                header_borsh: fs::read(header_path)?,
                body: TruthcoinBodyV1 {
                    coinbase_borsh: 0_u32.to_le_bytes().to_vec(),
                    transactions_borsh: Vec::new(),
                    authorizations_borsh: 0_u32.to_le_bytes().to_vec(),
                    actor_proofs_borsh: 0_u32.to_le_bytes().to_vec(),
                },
            };
            let context = CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: block.height,
                bmm_main_block_hash: [1; 32],
                bmm_main_height: block.bmm_main_height,
                bmm_main_timestamp: timestamp,
                bmm_main_mtp: timestamp,
            };
            let undo = apply_truthcoin_block_transition(&mut store, &block, context)?;
            let successor = store.export()?;
            revert_truthcoin_block_transition(&mut store, &undo)?;
            if store.export()? != parent {
                return Err("ECX voted-finalization rollback did not reproduce parent".into());
            }
            apply_truthcoin_block_transition(&mut store, &block, context)?;
            if store.export()? != successor {
                return Err("ECX voted-finalization replay did not reproduce successor".into());
            }
            fs::write(output_path, successor)?;
        }
        [command, parent_path, output_path, height, timestamp, prefix]
            if command == "replay-amplify" =>
        {
            let height = height.parse::<u32>()?;
            let timestamp = timestamp.parse::<u64>()?;
            let parent = fs::read(parent_path)?;
            let mut store = CanonicalStateStoreV1::import(&parent)?;
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height: u64::from(height),
                bmm_main_height: u64::from(height),
                header_borsh: fs::read(format!("{prefix}.amplify.header.borsh"))?,
                body: TruthcoinBodyV1 {
                    coinbase_borsh: fs::read(format!("{prefix}.amplify.coinbase.borsh"))?,
                    transactions_borsh: vec![fs::read(format!("{prefix}.amplify.tx.borsh"))?],
                    authorizations_borsh: fs::read(format!(
                        "{prefix}.amplify.authorizations.borsh"
                    ))?,
                    actor_proofs_borsh: fs::read(format!("{prefix}.amplify.actor-proofs.borsh"))?,
                },
            };
            let context = CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: block.height,
                bmm_main_block_hash: [1; 32],
                bmm_main_height: block.bmm_main_height,
                bmm_main_timestamp: timestamp,
                bmm_main_mtp: timestamp,
            };
            let undo = apply_truthcoin_block_transition(&mut store, &block, context)?;
            let successor = store.export()?;
            revert_truthcoin_block_transition(&mut store, &undo)?;
            if store.export()? != parent {
                return Err("ECX AmplifyBeta rollback did not reproduce parent".into());
            }
            apply_truthcoin_block_transition(&mut store, &block, context)?;
            if store.export()? != successor {
                return Err("ECX AmplifyBeta replay did not reproduce successor".into());
            }
            fs::write(output_path, successor)?;
        }
        [command, parent_path, output_path, height, timestamp, prefix]
            if command == "replay-mixed" =>
        {
            let height = height.parse::<u32>()?;
            let timestamp = timestamp.parse::<u64>()?;
            let parent = fs::read(parent_path)?;
            let mut store = CanonicalStateStoreV1::import(&parent)?;
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height: u64::from(height),
                bmm_main_height: u64::from(height),
                header_borsh: fs::read(format!("{prefix}.mixed.header.borsh"))?,
                body: TruthcoinBodyV1 {
                    coinbase_borsh: fs::read(format!("{prefix}.mixed.coinbase.borsh"))?,
                    transactions_borsh: vec![
                        fs::read(format!("{prefix}.mixed.tx0.borsh"))?,
                        fs::read(format!("{prefix}.mixed.tx1.borsh"))?,
                    ],
                    authorizations_borsh: fs::read(format!("{prefix}.mixed.authorizations.borsh"))?,
                    actor_proofs_borsh: fs::read(format!("{prefix}.mixed.actor-proofs.borsh"))?,
                },
            };
            let context = CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: block.height,
                bmm_main_block_hash: [1; 32],
                bmm_main_height: block.bmm_main_height,
                bmm_main_timestamp: timestamp,
                bmm_main_mtp: timestamp,
            };
            let undo = apply_truthcoin_block_transition(&mut store, &block, context)?;
            let successor = store.export()?;
            revert_truthcoin_block_transition(&mut store, &undo)?;
            if store.export()? != parent {
                return Err("ECX mixed-block rollback did not reproduce parent".into());
            }
            apply_truthcoin_block_transition(&mut store, &block, context)?;
            if store.export()? != successor {
                return Err("ECX mixed-block replay did not reproduce successor".into());
            }
            fs::write(output_path, successor)?;
        }
        [command, parent_path, output_path, height, timestamp, prefix]
            if command == "replay-slippage" =>
        {
            let height = height.parse::<u32>()?;
            let timestamp = timestamp.parse::<u64>()?;
            let parent = fs::read(parent_path)?;
            let mut store = CanonicalStateStoreV1::import(&parent)?;
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height: u64::from(height),
                bmm_main_height: u64::from(height),
                header_borsh: fs::read(format!("{prefix}.slippage.header.borsh"))?,
                body: TruthcoinBodyV1 {
                    coinbase_borsh: fs::read(format!("{prefix}.slippage.coinbase.borsh"))?,
                    transactions_borsh: vec![fs::read(format!("{prefix}.slippage.tx.borsh"))?],
                    authorizations_borsh: fs::read(format!(
                        "{prefix}.slippage.authorizations.borsh"
                    ))?,
                    actor_proofs_borsh: fs::read(format!("{prefix}.slippage.actor-proofs.borsh"))?,
                },
            };
            let context = CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: block.height,
                bmm_main_block_hash: [1; 32],
                bmm_main_height: block.bmm_main_height,
                bmm_main_timestamp: timestamp,
                bmm_main_mtp: timestamp,
            };
            let undo = apply_truthcoin_block_transition(&mut store, &block, context)?;
            let successor = store.export()?;
            revert_truthcoin_block_transition(&mut store, &undo)?;
            if store.export()? != parent {
                return Err("ECX slippage-skip rollback did not reproduce parent".into());
            }
            apply_truthcoin_block_transition(&mut store, &block, context)?;
            if store.export()? != successor {
                return Err("ECX slippage-skip replay did not reproduce successor".into());
            }
            fs::write(output_path, successor)?;
        }
        [command, parent_path, output_path, height, timestamp, prefix]
            if command == "replay-standard-market" =>
        {
            let height = height.parse::<u32>()?;
            let timestamp = timestamp.parse::<u64>()?;
            let parent = fs::read(parent_path)?;
            let mut store = CanonicalStateStoreV1::import(&parent)?;
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height: u64::from(height),
                bmm_main_height: u64::from(height),
                header_borsh: fs::read(format!("{prefix}.standard-market.header.borsh"))?,
                body: TruthcoinBodyV1 {
                    coinbase_borsh: fs::read(format!("{prefix}.standard-market.coinbase.borsh"))?,
                    transactions_borsh: vec![fs::read(format!(
                        "{prefix}.standard-market.tx.borsh"
                    ))?],
                    authorizations_borsh: fs::read(format!(
                        "{prefix}.standard-market.authorizations.borsh"
                    ))?,
                    actor_proofs_borsh: fs::read(format!(
                        "{prefix}.standard-market.actor-proofs.borsh"
                    ))?,
                },
            };
            let context = CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: block.height,
                bmm_main_block_hash: [1; 32],
                bmm_main_height: block.bmm_main_height,
                bmm_main_timestamp: timestamp,
                bmm_main_mtp: timestamp,
            };
            let undo = apply_truthcoin_block_transition(&mut store, &block, context)?;
            let successor = store.export()?;
            revert_truthcoin_block_transition(&mut store, &undo)?;
            if store.export()? != parent {
                return Err("ECX standard-market rollback did not reproduce parent".into());
            }
            apply_truthcoin_block_transition(&mut store, &block, context)?;
            if store.export()? != successor {
                return Err("ECX standard-market replay did not reproduce successor".into());
            }
            fs::write(output_path, successor)?;
        }
        [command, parent_path, output_path, prefix] if command == "replay-multi-epoch" => {
            let parent = fs::read(parent_path)?;
            let mut store = CanonicalStateStoreV1::import(&parent)?;
            let mut blocks = Vec::new();
            let mut contexts = Vec::new();
            let mut undos = Vec::new();
            for height in 0..=4_u64 {
                let block = TruthcoinBlockV1 {
                    version: TruthcoinBlockV1::VERSION,
                    height,
                    bmm_main_height: height,
                    header_borsh: fs::read(format!("{prefix}.multi-epoch-{height}.header.borsh"))?,
                    body: TruthcoinBodyV1 {
                        coinbase_borsh: 0_u32.to_le_bytes().to_vec(),
                        transactions_borsh: Vec::new(),
                        authorizations_borsh: 0_u32.to_le_bytes().to_vec(),
                        actor_proofs_borsh: 0_u32.to_le_bytes().to_vec(),
                    },
                };
                let timestamp = 1_000 + height * 13 * 24 * 60 * 60;
                let context = CanonicalBlockContextV1 {
                    sidechain_block_hash: block.block_hash(),
                    sidechain_height: height,
                    bmm_main_block_hash: [1; 32],
                    bmm_main_height: height,
                    bmm_main_timestamp: timestamp,
                    bmm_main_mtp: timestamp,
                };
                undos.push(apply_truthcoin_block_transition(
                    &mut store, &block, context,
                )?);
                blocks.push(block);
                contexts.push(context);
            }
            let successor = store.export()?;
            for undo in undos.iter().rev() {
                revert_truthcoin_block_transition(&mut store, undo)?;
            }
            if store.export()? != parent {
                return Err("ECX multi-epoch rollback did not reproduce parent".into());
            }
            for (block, context) in blocks.iter().zip(contexts) {
                apply_truthcoin_block_transition(&mut store, block, context)?;
            }
            if store.export()? != successor {
                return Err("ECX multi-epoch replay did not reproduce successor".into());
            }
            fs::write(output_path, successor)?;
        }
        [command, parent_path, output_path, prefix, branch]
            if command == "replay-multi-epoch-branch" && (branch == "a" || branch == "b") =>
        {
            let parent = fs::read(parent_path)?;
            let mut store = CanonicalStateStoreV1::import(&parent)?;
            let mut blocks = Vec::new();
            let mut contexts = Vec::new();
            let mut undos = Vec::new();
            for height in 2..=3_u64 {
                let block = TruthcoinBlockV1 {
                    version: TruthcoinBlockV1::VERSION,
                    height,
                    bmm_main_height: height,
                    header_borsh: fs::read(format!(
                        "{prefix}.multi-fork-{branch}-{height}.header.borsh"
                    ))?,
                    body: TruthcoinBodyV1 {
                        coinbase_borsh: fs::read(format!(
                            "{prefix}.multi-fork-{branch}-{height}.coinbase.borsh"
                        ))?,
                        transactions_borsh: Vec::new(),
                        authorizations_borsh: 0_u32.to_le_bytes().to_vec(),
                        actor_proofs_borsh: 0_u32.to_le_bytes().to_vec(),
                    },
                };
                let timestamp = 1_000 + height * 13 * 24 * 60 * 60;
                let context = CanonicalBlockContextV1 {
                    sidechain_block_hash: block.block_hash(),
                    sidechain_height: height,
                    bmm_main_block_hash: [1; 32],
                    bmm_main_height: height,
                    bmm_main_timestamp: timestamp,
                    bmm_main_mtp: timestamp,
                };
                undos.push(apply_truthcoin_block_transition(
                    &mut store, &block, context,
                )?);
                blocks.push(block);
                contexts.push(context);
            }
            let successor = store.export()?;
            for undo in undos.iter().rev() {
                revert_truthcoin_block_transition(&mut store, undo)?;
            }
            if store.export()? != parent {
                return Err("ECX multi-epoch branch rollback did not reproduce parent".into());
            }
            for (block, context) in blocks.iter().zip(contexts) {
                apply_truthcoin_block_transition(&mut store, block, context)?;
            }
            if store.export()? != successor {
                return Err("ECX multi-epoch branch replay did not reproduce successor".into());
            }
            fs::write(output_path, successor)?;
        }
        [command, checkpoint_path, output_path, timestamp, prefix]
            if command == "extract-standard-market" =>
        {
            let timestamp = timestamp.parse::<u64>()?;
            let store = CanonicalStateStoreV1::import(&fs::read(checkpoint_path)?)?;
            let block = TruthcoinBlockV1 {
                version: TruthcoinBlockV1::VERSION,
                height: 1,
                bmm_main_height: 1,
                header_borsh: fs::read(format!("{prefix}.standard-market.header.borsh"))?,
                body: TruthcoinBodyV1 {
                    coinbase_borsh: fs::read(format!("{prefix}.standard-market.coinbase.borsh"))?,
                    transactions_borsh: vec![fs::read(format!(
                        "{prefix}.standard-market.tx.borsh"
                    ))?],
                    authorizations_borsh: fs::read(format!(
                        "{prefix}.standard-market.authorizations.borsh"
                    ))?,
                    actor_proofs_borsh: fs::read(format!(
                        "{prefix}.standard-market.actor-proofs.borsh"
                    ))?,
                },
            };
            let genesis_hash: [u8; 32] = block
                .header_borsh
                .get(33..65)
                .ok_or("standard market header has no side parent")?
                .try_into()?;
            let template = ecx_truthcoin_proof::TruthcoinMarketTemplateCommitmentV1 {
                version: ecx_truthcoin_proof::TruthcoinMarketTemplateCommitmentV1::VERSION,
                market_title_template: "ECX BTC/USD period {period}".into(),
                market_description_template: "Canonical BTC/USD forecast for period {period}"
                    .into(),
                decision_header_template: "BTC/USD at canonical close".into(),
                decision_description_template: "ECX canonical Truthcoin BTC/USD scalar".into(),
                decision_tags: vec!["ecx-oracle-v1".into(), "btc-usd".into()],
                scalar_min_f64_bits: 10_000_f64.to_bits(),
                scalar_max_f64_bits: 250_000_f64.to_bits(),
                scalar_increment_f64_bits: 1_f64.to_bits(),
                minimum_liquidity_sats: 10_000_000,
                trading_fee_ppm: 10_000,
                tx_pow_hash_selector: 0,
                tx_pow_ordering: 0,
                tx_pow_difficulty: 0,
            };
            let authentication = ecx_protocol_core::TruthcoinAuthenticationConfigV1 {
                version: ecx_protocol_core::TruthcoinAuthenticationConfigV1::VERSION,
                source_git_commit_sha1: ecx_truthcoin_proof::TRUTHCOIN_SOURCE_GIT_COMMIT_SHA1,
                consensus_source_manifest_sha256:
                    ecx_truthcoin_proof::TRUTHCOIN_CONSENSUS_SOURCE_MANIFEST_SHA256,
                source_patch_manifest_sha256:
                    ecx_truthcoin_proof::TRUTHCOIN_SOURCE_PATCH_MANIFEST_SHA256,
                sidechain_number: ecx_truthcoin_proof::TRUTHCOIN_SIDECHAIN_NUMBER,
                bitcoin_checkpoint_hash: [2; 32],
                bitcoin_checkpoint_height: 1,
                bip300_checkpoint_state_hash: [12; 32],
                genesis_sidechain_block_hash: genesis_hash,
                truthcoin_chain_id: ecx_truthcoin_proof::pinned_truthcoin_chain_id(genesis_hash),
                truthcoin_branch_id: [3; 32],
                btc_usd_template_hash: template.digest(),
                lmsr_math_commitment: ecx_truthcoin_proof::TRUTHCOIN_LMSR_MATH_COMMITMENT,
                source_proof_program_id: [4; 32],
                selection_rule_hash: [5; 32],
                minimum_bitcoin_confirmations: 1,
                maximum_proof_bytes: 1_024,
            };
            let context = CanonicalBlockContextV1 {
                sidechain_block_hash: block.block_hash(),
                sidechain_height: block.height,
                bmm_main_block_hash: [1; 32],
                bmm_main_height: block.bmm_main_height,
                bmm_main_timestamp: timestamp,
                bmm_main_mtp: timestamp,
            };
            let output = extract_truthcoin_oracle_candidates(
                &authentication,
                &template,
                &store,
                &[block],
                &[context],
                1,
            )?;
            fs::write(output_path, serde_json::to_vec_pretty(&output)?)?;
        }
        [command, initial, connected, disconnected, reconnected] if command == "lifecycle" => {
            verify_lifecycle_checkpoint_bytes(
                &fs::read(initial)?,
                &fs::read(connected)?,
                &fs::read(disconnected)?,
                &fs::read(reconnected)?,
            )?;
        }
        [command, parent, branch_a, rollback_a, branch_b, rollback_b, replay_a, replay_b]
            if command == "fork-lifecycle" =>
        {
            verify_fork_lifecycle_checkpoint_bytes(
                &fs::read(parent)?,
                &fs::read(branch_a)?,
                &fs::read(rollback_a)?,
                &fs::read(branch_b)?,
                &fs::read(rollback_b)?,
                &fs::read(replay_a)?,
                &fs::read(replay_b)?,
            )?;
        }
        _ => {
            return Err(
                "usage: ecx-truthcoin-lmdb-adapter <export LMDB CHECKPOINT | import CHECKPOINT LMDB | verify LMDB CHECKPOINT | diff LEFT.tcst RIGHT.tcst | replay-voted-finalization PARENT.tcst OUTPUT.tcst HEIGHT TIMESTAMP HEADER.borsh | replay-amplify PARENT.tcst OUTPUT.tcst HEIGHT TIMESTAMP RECORD_PREFIX | replay-mixed PARENT.tcst OUTPUT.tcst HEIGHT TIMESTAMP RECORD_PREFIX | replay-slippage PARENT.tcst OUTPUT.tcst HEIGHT TIMESTAMP RECORD_PREFIX | replay-standard-market PARENT.tcst OUTPUT.tcst HEIGHT TIMESTAMP RECORD_PREFIX | replay-multi-epoch PARENT.tcst OUTPUT.tcst RECORD_PREFIX | extract-standard-market CHECKPOINT OUTPUT.json TIMESTAMP RECORD_PREFIX | lifecycle INITIAL.tcst CONNECTED.tcst DISCONNECTED.tcst RECONNECTED.tcst | fork-lifecycle PARENT.tcst A.tcst ROLLBACK_A.tcst B.tcst ROLLBACK_B.tcst REPLAY_A.tcst REPLAY_B.tcst>"
                    .into(),
            );
        }
    }
    Ok(())
}
