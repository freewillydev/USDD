// Copy into `truthcoin-dc/lib/examples/` when reproducing the pinned upstream
// LMDB bridge validation. This fixture initializes `State` and exercises an
// empty-block connect/disconnect/reconnect lifecycle. It performs no proof
// generation or setup.

use std::{env, fs, path::PathBuf};

use bitcoin::hashes::Hash as _;
use hashlink::LinkedHashMap;
use truthcoin_dc::{
    archive::Archive,
    state::{
        decisions::{DecisionId, DecisionType},
        State,
    },
    types::{
        proto::mainchain::{BlockEvent, BlockInfo, Deposit, TwoWayPegData},
        BitcoinOutputContent, Body, FilledOutput, FilledOutputContent, Header,
        Output, OutputContent,
    },
    wallet::{CreateMarketInput, Wallet},
};

fn deterministic_signing_key(
    seed: &[u8; 64],
    index: u32,
) -> Result<truthcoin_dc::authorization::SigningKey, Box<dyn std::error::Error>>
{
    use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
    let master = Xpriv::new_master(bitcoin::NetworkKind::Test, seed)?;
    let path = DerivationPath::master()
        .child(ChildNumber::Hardened { index: 0 })
        .child(ChildNumber::Normal { index });
    let child = master.derive_priv(&bitcoin::key::Secp256k1::new(), &path)?;
    Ok(child.private_key.secret_bytes().into())
}

fn next_header(
    state: &State,
    env: &sneed::Env,
    body: &Body,
) -> Result<Header, Box<dyn std::error::Error>> {
    let rotxn = env.read_txn()?;
    let prev_side_hash = state.try_get_tip(&rotxn)?;
    rotxn.commit()?;
    Ok(Header {
        merkle_root: Body::compute_merkle_root(
            &body.coinbase,
            &body.transactions,
        ),
        prev_side_hash,
        prev_main_hash: bitcoin::BlockHash::all_zeros(),
    })
}

fn assert_block_rejected(
    state: &State,
    archive: &Archive,
    env: &sneed::Env,
    header: &Header,
    body: &Body,
    timestamp: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rwtxn = env.write_txn()?;
    if state
        .apply_block(archive, &mut rwtxn, header, body, timestamp)
        .is_ok()
    {
        return Err("malformed authorization block was accepted".into());
    }
    rwtxn.abort();
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or("missing command")?;
    let path = PathBuf::from(arguments.next().ok_or("missing LMDB path")?);
    let record_path =
        PathBuf::from(arguments.next().ok_or("missing record path")?);
    fs::create_dir_all(&path)?;
    let mut options = heed::EnvOpenOptions::new();
    options
        .map_size(64 * 1024 * 1024)
        .max_dbs(State::NUM_DBS + Archive::NUM_DBS);
    // SAFETY: this one-shot fixture owns the temporary directory for its full
    // lifetime and no other process replaces it.
    let env = unsafe { sneed::Env::open(&options, &path)? };
    let state = State::new(&env, None)?;
    let archive = Archive::new(&env)?;
    match command.as_str() {
        "init" => {}
        "market-init"
        | "categorical-market-init"
        | "standard-market-init"
        | "standard-market-underpay-init" => {
            let standard = command != "market-init";
            let categorical = command == "categorical-market-init";
            let standard = standard && !categorical;
            let wallet_path = path.with_extension("wallet");
            let wallet = Wallet::new(&wallet_path)?;
            wallet.set_seed(&[7; 64])?;
            let address = wallet.get_new_address()?;
            let voter_two_wallet =
                Wallet::new(&path.with_extension("voter-two-wallet"))?;
            voter_two_wallet.set_seed(&[8; 64])?;
            let voter_two = voter_two_wallet.get_new_address()?;

            let genesis_body = Body::new(
                Vec::new(),
                vec![Output::new(
                    address,
                    OutputContent::Bitcoin(BitcoinOutputContent(
                        bitcoin::Amount::ZERO,
                    )),
                )],
            );
            let genesis_header = next_header(&state, &env, &genesis_body)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &genesis_header, &genesis_body, 1_000)?;
            archive.put_header(&mut rwtxn, &genesis_header)?;
            archive.put_body(&mut rwtxn, genesis_header.hash(), &genesis_body)?;
            rwtxn.commit()?;

            let deposit_outpoint = bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([9; 32]),
                vout: 0,
            };
            let deposit_output = FilledOutput {
                address,
                content: FilledOutputContent::Bitcoin(BitcoinOutputContent(
                    bitcoin::Amount::from_sat(20_000_000),
                )),
                memo: Vec::new(),
            };
            let voter_two_outpoint = bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([10; 32]),
                vout: 0,
            };
            let voter_two_output = FilledOutput {
                address: voter_two,
                content: FilledOutputContent::Bitcoin(BitcoinOutputContent(
                    bitcoin::Amount::from_sat(2_000_000),
                )),
                memo: Vec::new(),
            };
            let voter_one_fee_outpoint = bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([11; 32]),
                vout: 0,
            };
            let voter_one_fee_output = FilledOutput {
                address,
                content: FilledOutputContent::Bitcoin(BitcoinOutputContent(
                    bitcoin::Amount::from_sat(2_000_000),
                )),
                memo: Vec::new(),
            };
            let mut block_info = LinkedHashMap::new();
            block_info.insert(
                bitcoin::BlockHash::from_byte_array([8; 32]),
                BlockInfo {
                    bmm_commitment: None,
                    events: vec![
                        BlockEvent::Deposit(Deposit {
                            tx_index: 0,
                            outpoint: deposit_outpoint,
                            output: deposit_output.clone(),
                        }),
                        BlockEvent::Deposit(Deposit {
                            tx_index: 1,
                            outpoint: voter_two_outpoint,
                            output: voter_two_output.clone(),
                        }),
                        BlockEvent::Deposit(Deposit {
                            tx_index: 2,
                            outpoint: voter_one_fee_outpoint,
                            output: voter_one_fee_output.clone(),
                        }),
                    ],
                },
            );
            let mut rwtxn = env.write_txn()?;
            state.connect_two_way_peg_data(&mut rwtxn, &TwoWayPegData { block_info })?;
            rwtxn.commit()?;
            wallet.put_utxos(&std::collections::HashMap::from([
                (
                    truthcoin_dc::types::OutPoint::Deposit(deposit_outpoint),
                    deposit_output,
                ),
                (
                    truthcoin_dc::types::OutPoint::Deposit(
                        voter_one_fee_outpoint,
                    ),
                    voter_one_fee_output,
                ),
            ]))?;
            voter_two_wallet.put_utxos(&std::collections::HashMap::from([(
                truthcoin_dc::types::OutPoint::Deposit(voter_two_outpoint),
                voter_two_output,
            )]))?;

            let decision_id = if standard {
                DecisionId::new(true, 1, 0)?
            } else {
                DecisionId::new(false, 0, 0)?
            };
            let listing_fee = if standard {
                let rotxn = env.read_txn()?;
                let fee = state
                    .decisions()
                    .fee_for_decision_id(&rotxn, decision_id)?;
                rotxn.commit()?;
                if fee != 2_500 {
                    return Err(format!(
                        "unexpected standard slot listing fee: {fee}"
                    )
                    .into());
                }
                fee
            } else {
                0
            };
            let claim = truthcoin_dc::types::ClaimDecisionPayload {
                decision_type: if categorical {
                    DecisionType::Category {
                        options: vec![
                            "Up".into(),
                            "Flat".into(),
                            "Down".into(),
                        ],
                    }
                } else {
                    DecisionType::Scaled {
                        min: 10_000.0,
                        max: 250_000.0,
                        increment: 1.0,
                    }
                },
                decisions: vec![truthcoin_dc::types::DecisionClaimEntry {
                    decision_id_bytes: decision_id.as_bytes(),
                    header: "BTC/USD at canonical close".into(),
                    description: "ECX canonical Truthcoin BTC/USD scalar".into(),
                    option_0_label: None,
                    option_1_label: None,
                    option_labels: categorical.then_some(vec![
                        "Up".into(),
                        "Flat".into(),
                        "Down".into(),
                    ]),
                    tags: Some(vec!["ecx-oracle-v1".into(), "btc-usd".into()]),
                }],
            };
            let (transaction, market_id) = wallet.create_market(
                CreateMarketInput {
                    title: if categorical {
                        "ECX BTC direction categorical".into()
                    } else {
                        format!(
                            "ECX BTC/USD period {}",
                            decision_id.period_index()
                        )
                    },
                    description: format!(
                        "Canonical BTC/USD forecast for period {}",
                        decision_id.period_index()
                    ),
                    dimensions: if categorical {
                        format!("[[{}]]", decision_id.to_hex())
                    } else {
                        format!("[{}]", decision_id.to_hex())
                    },
                    beta: None,
                    trading_fee: Some(0.01),
                    initial_liquidity: Some(10_000_000),
                    category_option_counts: categorical.then_some(vec![3]),
                    tx_pow_hash_selector: Some(0),
                    tx_pow_ordering: Some(0),
                    tx_pow_difficulty: Some(0),
                    new_claims: vec![claim],
                },
                bitcoin::Amount::from_sat(if command
                    == "standard-market-underpay-init"
                {
                    // create_market also burns the deterministic market
                    // storage fee into bitcoin_fee(). Leave the total fee one
                    // sat below the 2,500-sat listing requirement.
                    listing_fee
                        - truthcoin_dc::math::markets::market_storage_fee(2)
                        - 1
                } else {
                    1_000 + listing_fee
                }),
            )?;
            let body = Body::new(vec![wallet.authorize(transaction)?], Vec::new());
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path,
                serde_json::to_vec(&(
                    header,
                    body,
                    1_100u64,
                    market_id,
                    listing_fee,
                ))?,
            )?;
        }
        "market-connect" | "categorical-market-connect" | "standard-market-connect" => {
            let (header, body, timestamp, _, _): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(record_path)?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "standard-market-wire" => {
            let (header, body, timestamp, market_id, listing_fee): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(&record_path)?)?;
            let rotxn = env.read_txn()?;
            let market = state
                .markets()
                .get_market(&rotxn, &market_id)?
                .ok_or("standard market missing")?;
            rotxn.commit()?;
            let beta = market.liquidity_base_sats as f64
                / libm::log(market.shares().len() as f64);
            let prices = market.current_prices(beta).to_vec();
            let transaction = body
                .transactions
                .first()
                .ok_or("standard market transaction missing")?;
            fs::write(
                record_path.with_extension("standard-market.header.borsh"),
                borsh::to_vec(&header)?,
            )?;
            fs::write(
                record_path.with_extension("standard-market.tx.borsh"),
                borsh::to_vec(transaction)?,
            )?;
            fs::write(
                record_path.with_extension("standard-market.coinbase.borsh"),
                borsh::to_vec(&body.coinbase)?,
            )?;
            fs::write(
                record_path.with_extension("standard-market.authorizations.borsh"),
                borsh::to_vec(&body.authorizations)?,
            )?;
            fs::write(
                record_path.with_extension("standard-market.actor-proofs.borsh"),
                borsh::to_vec(&body.actor_proofs)?,
            )?;
            fs::write(
                record_path.with_extension("standard-market.query.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "timestamp": timestamp,
                    "listing_fee_sats": listing_fee,
                    "market_id": hex::encode(market_id.0),
                    "creation_txid": hex::encode(transaction.txid().as_slice()),
                    "created_at_height": market.created_at_height,
                    "last_updated_height": market.last_updated_height,
                    "liquidity_base_sats": market.liquidity_base_sats,
                    "trading_fee_bits": market.trading_fee().to_bits(),
                    "shares": market.shares().to_vec(),
                    "beta_bits": beta.to_bits(),
                    "probability_bits": prices.iter().map(|price| price.to_bits()).collect::<Vec<_>>(),
                    "tx_pow_hash_selector": market.tx_pow_hash_selector,
                    "tx_pow_ordering": market.tx_pow_ordering,
                    "tx_pow_difficulty": market.tx_pow_difficulty,
                }))?,
            )?;
        }
        "standard-market-underpay-connect" => {
            let (header, body, timestamp, _, listing_fee): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(record_path)?)?;
            if listing_fee != 2_500 {
                return Err("underpayment fixture did not bind the canonical listing fee".into());
            }
            let mut rwtxn = env.write_txn()?;
            if state
                .apply_block(&archive, &mut rwtxn, &header, &body, timestamp)
                .is_ok()
            {
                return Err("standard listing-fee underpayment was accepted".into());
            }
            rwtxn.abort();
        }
        "market-bad-signature-connect"
        | "market-missing-authorization-connect"
        | "market-surplus-authorization-connect" => {
            let (header, mut body, timestamp, _, _): (
                Header,
                Body,
                u64,
                truthcoin_dc::state::markets::MarketId,
                u64,
            ) = serde_json::from_slice(&fs::read(record_path)?)?;
            match command.as_str() {
                "market-bad-signature-connect" => {
                    let authorization = body
                        .authorizations
                        .first_mut()
                        .ok_or("market fixture has no authorization")?;
                    let mut bytes = authorization.signature.0.to_bytes();
                    bytes[0] ^= 1;
                    authorization.signature = hex::encode(bytes).parse()?;
                }
                "market-missing-authorization-connect" => {
                    body.authorizations.pop();
                }
                "market-surplus-authorization-connect" => {
                    let extra = body
                        .authorizations
                        .first()
                        .cloned()
                        .ok_or("market fixture has no authorization")?;
                    body.authorizations.push(extra);
                }
                _ => unreachable!(),
            }
            assert_block_rejected(
                &state,
                &archive,
                &env,
                &header,
                &body,
                timestamp,
            )?;
        }
        "market-double-apply-connect" => {
            let (_, body, timestamp, _, _): (
                Header,
                Body,
                u64,
                truthcoin_dc::state::markets::MarketId,
                u64,
            ) = serde_json::from_slice(&fs::read(record_path)?)?;
            // Rebind the already-consumed transaction body to the current tip
            // so rejection proves UTXO replay protection rather than merely a
            // stale prev-side-header check.
            let replay_header = next_header(&state, &env, &body)?;
            assert_block_rejected(
                &state,
                &archive,
                &env,
                &replay_header,
                &body,
                timestamp + 1,
            )?;
        }
        "standard-market-fresh-duplicate-connect" => {
            let (_, _, _, expected_market_id, _): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(record_path)?)?;
            let wallet = Wallet::new(&path.with_extension("wallet"))?;
            let rotxn = env.read_txn()?;
            let market = state
                .markets()
                .get_market(&rotxn, &expected_market_id)?
                .ok_or("standard market missing before duplicate attempt")?;
            let creator = market.creator_address;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([creator]),
            )?;
            rotxn.commit()?;
            wallet.put_utxos(&utxos)?;
            let decision_id = DecisionId::new(true, 1, 0)?;
            let (transaction, duplicate_market_id) = wallet.create_market(
                CreateMarketInput {
                    title: format!("ECX BTC/USD period {}", decision_id.period_index()),
                    description: format!(
                        "Canonical BTC/USD forecast for period {}",
                        decision_id.period_index()
                    ),
                    dimensions: format!("[{}]", decision_id.to_hex()),
                    beta: None,
                    trading_fee: Some(0.01),
                    initial_liquidity: Some(10_000_000),
                    category_option_counts: None,
                    tx_pow_hash_selector: Some(0),
                    tx_pow_ordering: Some(0),
                    tx_pow_difficulty: Some(0),
                    new_claims: Vec::new(),
                },
                bitcoin::Amount::from_sat(1_000),
            )?;
            if duplicate_market_id != expected_market_id {
                return Err("fresh-input transaction did not reproduce the existing market ID".into());
            }
            let body = Body::new(vec![wallet.authorize(transaction)?], Vec::new());
            let header = next_header(&state, &env, &body)?;
            assert_block_rejected(&state, &archive, &env, &header, &body, 1_101)?;
        }
        "market-disconnect" | "categorical-market-disconnect" | "standard-market-disconnect" => {
            let (header, body, _, _, _): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(record_path)?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "amplify-prepare" => {
            let (_, _, _, market_id, _): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(&record_path)?)?;
            let wallet = Wallet::new(&path.with_extension("amplify-wallet"))?;
            wallet.set_seed(&[7; 64])?;
            let rotxn = env.read_txn()?;
            let author = state
                .markets()
                .get_market(&rotxn, &market_id)?
                .ok_or("amplify fixture market missing")?
                .creator_address;
            rotxn.commit()?;
            if wallet.get_new_address()? != author {
                return Err("amplify wallet did not derive market author".into());
            }
            let funding_outpoint = bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([12; 32]),
                vout: 0,
            };
            let funding_output = FilledOutput {
                address: author,
                content: FilledOutputContent::Bitcoin(BitcoinOutputContent(
                    bitcoin::Amount::from_sat(1_000_000),
                )),
                memo: Vec::new(),
            };
            let mut block_info = LinkedHashMap::new();
            block_info.insert(
                bitcoin::BlockHash::from_byte_array([13; 32]),
                BlockInfo {
                    bmm_commitment: None,
                    events: vec![BlockEvent::Deposit(Deposit {
                        tx_index: 0,
                        outpoint: funding_outpoint,
                        output: funding_output.clone(),
                    })],
                },
            );
            let mut rwtxn = env.write_txn()?;
            state.connect_two_way_peg_data(&mut rwtxn, &TwoWayPegData { block_info })?;
            rwtxn.commit()?;
            wallet.put_utxos(&std::collections::HashMap::from([(
                truthcoin_dc::types::OutPoint::Deposit(funding_outpoint),
                funding_output,
            )]))?;
            let rotxn = env.read_txn()?;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([author]),
            )?;
            rotxn.commit()?;
            wallet.put_utxos(&utxos)?;
            let transaction = wallet.amplify_beta(market_id, 500_000, author)?;
            let body = Body::new(vec![wallet.authorize(transaction)?], Vec::new());
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("amplify.json"),
                serde_json::to_vec(&(header, body, 1_175u64))?,
            )?;
        }
        "amplify-connect" => {
            let (header, body, timestamp): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("amplify.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "amplify-wire" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("amplify.json"))?,
            )?;
            let transaction = body.transactions.first().ok_or("amplify transaction missing")?;
            fs::write(record_path.with_extension("amplify.header.borsh"), borsh::to_vec(&header)?)?;
            fs::write(record_path.with_extension("amplify.tx.borsh"), borsh::to_vec(transaction)?)?;
            fs::write(record_path.with_extension("amplify.coinbase.borsh"), borsh::to_vec(&body.coinbase)?)?;
            fs::write(record_path.with_extension("amplify.authorizations.borsh"), borsh::to_vec(&body.authorizations)?)?;
            fs::write(record_path.with_extension("amplify.actor-proofs.borsh"), borsh::to_vec(&body.actor_proofs)?)?;
        }
        "amplify-disconnect" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("amplify.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "mixed-prepare" => {
            let (market_header, _, _, market_id, _): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(&record_path)?)?;
            let (_, amplify_body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("amplify.json"))?,
            )?;
            let trader_wallet = Wallet::new(&path.with_extension("voter-two-wallet"))?;
            let trader = trader_wallet.voter_address()?;
            let rotxn = env.read_txn()?;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([trader]),
            )?;
            rotxn.commit()?;
            trader_wallet.put_utxos(&utxos)?;
            let trade = trader_wallet.trade(
                market_id,
                0,
                25_000,
                trader,
                2_000_000,
                None,
                market_header.hash(),
            )?;
            let trade_body = Body::new(vec![trader_wallet.authorize(trade)?], Vec::new());
            let mut body = amplify_body;
            body.transactions.extend(trade_body.transactions);
            body.authorizations.extend(trade_body.authorizations);
            body.actor_proofs.extend(trade_body.actor_proofs);
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("mixed.json"),
                serde_json::to_vec(&(header, body, 1_175u64))?,
            )?;
        }
        "mixed-connect" => {
            let (header, body, timestamp): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("mixed.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "mixed-disconnect" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("mixed.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "mixed-wire" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("mixed.json"))?,
            )?;
            if body.transactions.len() != 2 {
                return Err("mixed fixture must contain exactly two transactions".into());
            }
            fs::write(record_path.with_extension("mixed.header.borsh"), borsh::to_vec(&header)?)?;
            fs::write(record_path.with_extension("mixed.tx0.borsh"), borsh::to_vec(&body.transactions[0])?)?;
            fs::write(record_path.with_extension("mixed.tx1.borsh"), borsh::to_vec(&body.transactions[1])?)?;
            fs::write(record_path.with_extension("mixed.coinbase.borsh"), borsh::to_vec(&body.coinbase)?)?;
            fs::write(record_path.with_extension("mixed.authorizations.borsh"), borsh::to_vec(&body.authorizations)?)?;
            fs::write(record_path.with_extension("mixed.actor-proofs.borsh"), borsh::to_vec(&body.actor_proofs)?)?;
        }
        "trade-prepare" => {
            let (market_header, _, _, market_id, _): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(&record_path)?)?;
            let wallet_path = path.with_extension("trade-wallet");
            let wallet = Wallet::new(&wallet_path)?;
            wallet.set_seed(&[7; 64])?;
            let first_address = wallet.get_new_address()?;
            let trader = wallet.get_new_address()?;
            let rotxn = env.read_txn()?;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([first_address, trader]),
            )?;
            rotxn.commit()?;
            wallet.put_utxos(&utxos)?;
            let transaction = wallet.trade(
                market_id,
                0,
                25_000,
                trader,
                2_000_000,
                None,
                market_header.hash(),
            )?;
            let body = Body::new(vec![wallet.authorize(transaction)?], Vec::new());
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("trade.json"),
                serde_json::to_vec(&(header, body, 1_200u64))?,
            )?;

            let fork_wallet = Wallet::new(&path.with_extension("fork-wallet"))?;
            fork_wallet.set_seed(&[7; 64])?;
            let _ = fork_wallet.get_new_address()?;
            let fork_trader = fork_wallet.get_new_address()?;
            fork_wallet.put_utxos(&utxos)?;
            let fork_transaction = fork_wallet.trade(
                market_id,
                1,
                40_000,
                fork_trader,
                2_000_000,
                None,
                market_header.hash(),
            )?;
            let fork_body = Body::new(
                vec![fork_wallet.authorize(fork_transaction)?],
                Vec::new(),
            );
            let fork_header = next_header(&state, &env, &fork_body)?;
            fs::write(
                record_path.with_extension("fork.json"),
                serde_json::to_vec(&(fork_header, fork_body, 1_201u64))?,
            )?;
        }
        "slippage-prepare" => {
            let (market_header, _, _, market_id, _): (Header, Body, u64, truthcoin_dc::state::markets::MarketId, u64) =
                serde_json::from_slice(&fs::read(&record_path)?)?;
            let wallet = Wallet::new(&path.with_extension("voter-two-wallet"))?;
            let trader = wallet.voter_address()?;
            let rotxn = env.read_txn()?;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([trader]),
            )?;
            rotxn.commit()?;
            wallet.put_utxos(&utxos)?;
            let transaction = wallet.trade(
                market_id,
                0,
                1_000_000,
                trader,
                1_000,
                None,
                market_header.hash(),
            )?;
            let body = Body::new(vec![wallet.authorize(transaction)?], Vec::new());
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("slippage.json"),
                serde_json::to_vec(&(header, body, 1_175u64))?,
            )?;
        }
        "slippage-connect" => {
            let (header, body, timestamp): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("slippage.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "slippage-disconnect" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("slippage.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "slippage-wire" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("slippage.json"))?,
            )?;
            fs::write(record_path.with_extension("slippage.header.borsh"), borsh::to_vec(&header)?)?;
            fs::write(record_path.with_extension("slippage.tx.borsh"), borsh::to_vec(body.transactions.first().ok_or("slippage transaction missing")?)?)?;
            fs::write(record_path.with_extension("slippage.coinbase.borsh"), borsh::to_vec(&body.coinbase)?)?;
            fs::write(record_path.with_extension("slippage.authorizations.borsh"), borsh::to_vec(&body.authorizations)?)?;
            fs::write(record_path.with_extension("slippage.actor-proofs.borsh"), borsh::to_vec(&body.actor_proofs)?)?;
        }
        "trade-connect" => {
            let (header, body, timestamp): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("trade.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "trade-disconnect" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("trade.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "trade-wire" => {
            let (header, body, timestamp): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("trade.json"))?,
            )?;
            let transaction = body
                .transactions
                .first()
                .ok_or("trade fixture transaction missing")?;
            fs::write(
                record_path.with_extension("trade.header.borsh"),
                borsh::to_vec(&header)?,
            )?;
            fs::write(
                record_path.with_extension("trade.tx.borsh"),
                borsh::to_vec(transaction)?,
            )?;
            fs::write(
                record_path.with_extension("trade.coinbase.borsh"),
                borsh::to_vec(&body.coinbase)?,
            )?;
            fs::write(
                record_path.with_extension("trade.authorizations.borsh"),
                borsh::to_vec(&body.authorizations)?,
            )?;
            fs::write(
                record_path.with_extension("trade.actor-proofs.borsh"),
                borsh::to_vec(&body.actor_proofs)?,
            )?;
            fs::write(
                record_path.with_extension("trade.meta.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "timestamp": timestamp,
                    "transaction_id": hex::encode(transaction.txid().as_slice()),
                }))?,
            )?;
        }
        "sell-prepare" => {
            let (buy_header, buy_body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("trade.json"))?,
            )?;
            let buy_transaction = buy_body
                .transactions
                .first()
                .ok_or("buy fixture transaction missing")?;
            let Some(truthcoin_dc::types::TxData::Trade {
                market_id,
                outcome_index,
                shares,
                trader,
                ..
            }) = &buy_transaction.data
            else {
                return Err("buy fixture transaction is not a trade".into());
            };
            if *shares <= 0 {
                return Err("sell fixture parent is not a buy".into());
            }
            let wallet = Wallet::new(&path.with_extension("trade-wallet"))?;
            let rotxn = env.read_txn()?;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([*trader]),
            )?;
            rotxn.commit()?;
            let stale = wallet
                .get_utxos()?
                .into_keys()
                .filter(|outpoint| !utxos.contains_key(outpoint))
                .map(|outpoint| (outpoint, truthcoin_dc::types::InPoint::Redistribution))
                .collect::<Vec<_>>();
            wallet.spend_utxos(&stale)?;
            wallet.put_utxos(&utxos)?;
            let transaction = wallet.trade(
                *market_id,
                *outcome_index as usize,
                -(*shares / 2),
                *trader,
                0,
                None,
                buy_header.hash(),
            )?;
            let body = Body::new(vec![wallet.authorize(transaction)?], Vec::new());
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("sell.json"),
                serde_json::to_vec(&(header, body, 1_300u64))?,
            )?;
        }
        "sell-connect" => {
            let (header, body, timestamp): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("sell.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "sell-disconnect" => {
            let (header, body, _): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("sell.json"))?,
            )?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "sell-wire" => {
            let (header, body, timestamp): (Header, Body, u64) = serde_json::from_slice(
                &fs::read(record_path.with_extension("sell.json"))?,
            )?;
            let transaction = body
                .transactions
                .first()
                .ok_or("sell fixture transaction missing")?;
            fs::write(record_path.with_extension("sell.header.borsh"), borsh::to_vec(&header)?)?;
            fs::write(record_path.with_extension("sell.tx.borsh"), borsh::to_vec(transaction)?)?;
            fs::write(record_path.with_extension("sell.coinbase.borsh"), borsh::to_vec(&body.coinbase)?)?;
            fs::write(record_path.with_extension("sell.authorizations.borsh"), borsh::to_vec(&body.authorizations)?)?;
            fs::write(record_path.with_extension("sell.actor-proofs.borsh"), borsh::to_vec(&body.actor_proofs)?)?;
            fs::write(
                record_path.with_extension("sell.meta.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "timestamp": timestamp,
                    "transaction_id": hex::encode(transaction.txid().as_slice()),
                }))?,
            )?;
        }
        "fork-connect" => {
            let (header, body, timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("fork.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "fork-disconnect" => {
            let (header, body, _): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("fork.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "reputation-prepare" => {
            let sender_wallet = Wallet::new(&path.with_extension("vote-wallet"))?;
            sender_wallet.set_seed(&[7; 64])?;
            let sender = sender_wallet.get_new_address()?;
            let receiver_wallet =
                Wallet::new(&path.with_extension("voter-two-wallet"))?;
            receiver_wallet.set_seed(&[8; 64])?;
            let receiver = receiver_wallet.voter_address()?;
            let rotxn = env.read_txn()?;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([sender]),
            )?;
            rotxn.commit()?;
            sender_wallet.put_utxos(&utxos)?;
            let transaction = sender_wallet.transfer_reputation(
                receiver,
                0.4,
                bitcoin::Amount::from_sat(1_000),
                Some(b"ECX two-voter distribution".to_vec()),
            )?;
            let body = Body::new(
                vec![sender_wallet.authorize(transaction)?],
                Vec::new(),
            );
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("reputation.json"),
                serde_json::to_vec(&(header, body, 1_250u64))?,
            )?;
        }
        "reputation-connect" => {
            let (header, body, timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("reputation.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "reputation-disconnect" => {
            let (header, body, _): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("reputation.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "actor-ballot-prepare" => {
            let actor_key = deterministic_signing_key(&[7; 64], 0)?;
            let sponsor_key = deterministic_signing_key(&[8; 64], 0)?;
            let actor = truthcoin_dc::authorization::get_address(
                &actor_key.verifying_key().into(),
            );
            let sponsor = truthcoin_dc::authorization::get_address(
                &sponsor_key.verifying_key().into(),
            );
            let sponsor_outpoint = truthcoin_dc::types::OutPoint::Deposit(
                bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([10; 32]),
                    vout: 0,
                },
            );
            let decision_id = DecisionId::new(false, 0, 0)?;
            let mut transaction = truthcoin_dc::types::Transaction::new(
                vec![sponsor_outpoint],
                vec![Output::new(
                    sponsor,
                    OutputContent::Bitcoin(BitcoinOutputContent(
                        bitcoin::Amount::from_sat(1_999_000),
                    )),
                )],
            );
            transaction.data = Some(truthcoin_dc::types::TxData::SubmitBallot {
                voter: actor,
                votes: vec![truthcoin_dc::types::BallotItem {
                    decision_id_bytes: decision_id.as_bytes(),
                    vote_value: 0.6,
                }],
                voting_period: decision_id.voting_period(),
            });
            let actor_signature =
                truthcoin_dc::authorization::sign_tx(&actor_key, &transaction)?;
            let mut authorized = truthcoin_dc::authorization::authorize(
                &[(sponsor, &sponsor_key)],
                transaction,
            )?;
            authorized.actor_proof = Some(truthcoin_dc::authorization::Authorization {
                verifying_key: actor_key.verifying_key().into(),
                signature: actor_signature,
            });
            let body = Body::new(vec![authorized], Vec::new());
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("actor-ballot.json"),
                serde_json::to_vec(&(header, body, 1_300u64))?,
            )?;
        }
        "actor-ballot-connect" => {
            let (header, body, timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("actor-ballot.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "actor-ballot-disconnect" => {
            let (header, body, _): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("actor-ballot.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "actor-ballot-missing-proof-connect"
        | "actor-ballot-bad-proof-connect"
        | "actor-ballot-wrong-actor-connect" => {
            let (header, mut body, timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("actor-ballot.json"),
                )?)?;
            match command.as_str() {
                "actor-ballot-missing-proof-connect" => {
                    body.actor_proofs[0] = None;
                }
                "actor-ballot-bad-proof-connect" => {
                    let proof = body.actor_proofs[0]
                        .as_mut()
                        .ok_or("actor fixture has no actor proof")?;
                    let mut bytes = proof.signature.0.to_bytes();
                    bytes[0] ^= 1;
                    proof.signature = hex::encode(bytes).parse()?;
                }
                "actor-ballot-wrong-actor-connect" => {
                    let sponsor_key = deterministic_signing_key(&[8; 64], 0)?;
                    let proof = body.actor_proofs[0]
                        .as_mut()
                        .ok_or("actor fixture has no actor proof")?;
                    proof.verifying_key = sponsor_key.verifying_key().into();
                }
                _ => unreachable!(),
            }
            assert_block_rejected(
                &state,
                &archive,
                &env,
                &header,
                &body,
                timestamp,
            )?;
        }
        "multi-vote-prepare"
        | "abstain-vote-prepare"
        | "default-vote-prepare"
        | "categorical-vote-prepare" => {
            let first_wallet =
                Wallet::new(&path.with_extension("multi-vote-one-wallet"))?;
            first_wallet.set_seed(&[7; 64])?;
            let first_voter = first_wallet.voter_address()?;
            let second_wallet =
                Wallet::new(&path.with_extension("multi-vote-two-wallet"))?;
            second_wallet.set_seed(&[8; 64])?;
            let second_voter = second_wallet.voter_address()?;
            let rotxn = env.read_txn()?;
            let first_utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([first_voter]),
            )?;
            let second_utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([second_voter]),
            )?;
            rotxn.commit()?;
            first_wallet.put_utxos(&first_utxos)?;
            second_wallet.put_utxos(&second_utxos)?;
            let decision_id = DecisionId::new(false, 0, 0)?;
            let first = first_wallet.submit_ballot(
                vec![truthcoin_dc::types::BallotItem {
                    decision_id_bytes: decision_id.as_bytes(),
                    vote_value: if command == "categorical-vote-prepare" {
                        0.0
                    } else {
                        0.25
                    },
                }],
                decision_id.voting_period(),
                bitcoin::Amount::from_sat(1_000),
            )?;
            let second_vote = if command == "abstain-vote-prepare" {
                truthcoin_dc::validation::VoteValidator::ABSTAIN_WIRE_VALUE
            } else if command == "categorical-vote-prepare" {
                2.0
            } else {
                0.75
            };
            let second = second_wallet.submit_ballot(
                vec![truthcoin_dc::types::BallotItem {
                    decision_id_bytes: decision_id.as_bytes(),
                    vote_value: second_vote,
                }],
                decision_id.voting_period(),
                bitcoin::Amount::from_sat(1_000),
            )?;
            let mut transactions = vec![first_wallet.authorize(first)?];
            if command != "default-vote-prepare" {
                transactions.push(second_wallet.authorize(second)?);
            }
            let body = Body::new(transactions, Vec::new());
            let header = next_header(&state, &env, &body)?;
            let suffix = match command.as_str() {
                "multi-vote-prepare" => "multi-vote.json",
                "abstain-vote-prepare" => "abstain-vote.json",
                "default-vote-prepare" => "default-vote.json",
                "categorical-vote-prepare" => "categorical-vote.json",
                _ => unreachable!(),
            };
            fs::write(
                record_path.with_extension(suffix),
                serde_json::to_vec(&(header, body, 1_300u64))?,
            )?;
        }
        "multi-vote-connect"
        | "abstain-vote-connect"
        | "default-vote-connect"
        | "categorical-vote-connect" => {
            let suffix = match command.as_str() {
                "multi-vote-connect" => "multi-vote.json",
                "abstain-vote-connect" => "abstain-vote.json",
                "default-vote-connect" => "default-vote.json",
                "categorical-vote-connect" => "categorical-vote.json",
                _ => unreachable!(),
            };
            let (header, body, timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension(suffix),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "multi-vote-disconnect"
        | "abstain-vote-disconnect"
        | "default-vote-disconnect"
        | "categorical-vote-disconnect" => {
            let suffix = match command.as_str() {
                "multi-vote-disconnect" => "multi-vote.json",
                "abstain-vote-disconnect" => "abstain-vote.json",
                "default-vote-disconnect" => "default-vote.json",
                "categorical-vote-disconnect" => "categorical-vote.json",
                _ => unreachable!(),
            };
            let (header, body, _): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension(suffix),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "vote-prepare" => {
            let wallet = Wallet::new(&path.with_extension("vote-wallet"))?;
            wallet.set_seed(&[7; 64])?;
            let voter = wallet.get_new_address()?;
            let second_address = wallet.get_new_address()?;
            let rotxn = env.read_txn()?;
            let utxos = state.get_utxos_by_addresses(
                &rotxn,
                &std::collections::HashSet::from([voter, second_address]),
            )?;
            rotxn.commit()?;
            wallet.put_utxos(&utxos)?;
            let decision_id = DecisionId::new(false, 0, 0)?;
            let transaction = wallet.submit_ballot(
                vec![truthcoin_dc::types::BallotItem {
                    decision_id_bytes: decision_id.as_bytes(),
                    vote_value: 0.75,
                }],
                decision_id.voting_period(),
                bitcoin::Amount::from_sat(1_000),
            )?;
            let body = Body::new(vec![wallet.authorize(transaction)?], Vec::new());
            let header = next_header(&state, &env, &body)?;
            fs::write(
                record_path.with_extension("vote.json"),
                serde_json::to_vec(&(header, body, 1_300u64))?,
            )?;
        }
        "vote-connect" => {
            let (header, body, timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("vote.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "vote-disconnect" => {
            let (header, body, _): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("vote.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "finalize-prepare" => {
            let body = Body::new(Vec::new(), Vec::new());
            let header = next_header(&state, &env, &body)?;
            let timestamp = 1_000u64
                .checked_add(truthcoin_dc::types::SECONDS_PER_QUARTER)
                .and_then(|value| value.checked_add(1))
                .ok_or("finalization timestamp overflow")?;
            fs::write(
                record_path.with_extension("finalize.json"),
                serde_json::to_vec(&(header, body, timestamp))?,
            )?;
        }
        "finalize-connect" => {
            let (header, body, timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("finalize.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
            archive.put_header(&mut rwtxn, &header)?;
            archive.put_body(&mut rwtxn, header.hash(), &body)?;
            rwtxn.commit()?;
        }
        "finalize-wire" => {
            let (header, _, _): (Header, Body, u64) = serde_json::from_slice(&fs::read(
                record_path.with_extension("finalize.json"),
            )?)?;
            fs::write(
                record_path.with_extension("finalize.header.borsh"),
                borsh::to_vec(&header)?,
            )?;
        }
        "finalize-disconnect" => {
            let (header, body, _): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(
                    record_path.with_extension("finalize.json"),
                )?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "multi-epoch-connect" => {
            let mut blocks = Vec::new();
            for height in 0..=4_u64 {
                let body = Body::new(Vec::new(), Vec::new());
                let header = next_header(&state, &env, &body)?;
                let timestamp = 1_000 + height * 13 * 24 * 60 * 60;
                let mut rwtxn = env.write_txn()?;
                state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
                archive.put_header(&mut rwtxn, &header)?;
                archive.put_body(&mut rwtxn, header.hash(), &body)?;
                rwtxn.commit()?;
                fs::write(
                    record_path.with_extension(format!("multi-epoch-{height}.header.borsh")),
                    borsh::to_vec(&header)?,
                )?;
                blocks.push((header, body, timestamp));
            }
            fs::write(
                record_path.with_extension("multi-epoch.json"),
                serde_json::to_vec(&blocks)?,
            )?;
        }
        "multi-epoch-disconnect" => {
            let blocks: Vec<(Header, Body, u64)> = serde_json::from_slice(&fs::read(
                record_path.with_extension("multi-epoch.json"),
            )?)?;
            for (header, body, _) in blocks.iter().rev() {
                let mut rwtxn = env.write_txn()?;
                state.disconnect_tip(&mut rwtxn, header, body)?;
                rwtxn.commit()?;
            }
        }
        "multi-epoch-reconnect" => {
            let blocks: Vec<(Header, Body, u64)> = serde_json::from_slice(&fs::read(
                record_path.with_extension("multi-epoch.json"),
            )?)?;
            for (header, body, timestamp) in blocks {
                let mut rwtxn = env.write_txn()?;
                state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
                rwtxn.commit()?;
            }
        }
        "multi-epoch-fork-common-connect" => {
            let mut blocks = Vec::new();
            for height in 0..=1_u64 {
                let body = Body::new(Vec::new(), Vec::new());
                let header = next_header(&state, &env, &body)?;
                let timestamp = 1_000 + height * 13 * 24 * 60 * 60;
                let mut rwtxn = env.write_txn()?;
                state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
                archive.put_header(&mut rwtxn, &header)?;
                archive.put_body(&mut rwtxn, header.hash(), &body)?;
                rwtxn.commit()?;
                fs::write(
                    record_path.with_extension(format!("multi-fork-common-{height}.header.borsh")),
                    borsh::to_vec(&header)?,
                )?;
                fs::write(
                    record_path.with_extension(format!("multi-fork-common-{height}.coinbase.borsh")),
                    borsh::to_vec(&body.coinbase)?,
                )?;
                blocks.push((header, body, timestamp));
            }
            fs::write(
                record_path.with_extension("multi-fork-common.json"),
                serde_json::to_vec(&blocks)?,
            )?;
        }
        "multi-epoch-fork-a-connect" | "multi-epoch-fork-b-connect" => {
            let branch = if command.ends_with("a-connect") { "a" } else { "b" };
            let seed = if branch == "a" { [21; 64] } else { [22; 64] };
            let wallet = Wallet::new(&path.with_extension(format!("multi-fork-{branch}-wallet")))?;
            wallet.set_seed(&seed)?;
            let address = wallet.get_new_address()?;
            let mut blocks = Vec::new();
            for height in 2..=3_u64 {
                let coinbase = if height == 2 {
                    vec![Output::new(
                        address,
                        OutputContent::Bitcoin(BitcoinOutputContent(bitcoin::Amount::ZERO)),
                    )]
                } else {
                    Vec::new()
                };
                let body = Body::new(Vec::new(), coinbase);
                let header = next_header(&state, &env, &body)?;
                let timestamp = 1_000 + height * 13 * 24 * 60 * 60;
                let mut rwtxn = env.write_txn()?;
                state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
                archive.put_header(&mut rwtxn, &header)?;
                archive.put_body(&mut rwtxn, header.hash(), &body)?;
                rwtxn.commit()?;
                fs::write(
                    record_path.with_extension(format!("multi-fork-{branch}-{height}.header.borsh")),
                    borsh::to_vec(&header)?,
                )?;
                fs::write(
                    record_path.with_extension(format!("multi-fork-{branch}-{height}.coinbase.borsh")),
                    borsh::to_vec(&body.coinbase)?,
                )?;
                blocks.push((header, body, timestamp));
            }
            fs::write(
                record_path.with_extension(format!("multi-fork-{branch}.json")),
                serde_json::to_vec(&blocks)?,
            )?;
        }
        "multi-epoch-fork-a-disconnect" | "multi-epoch-fork-b-disconnect" => {
            let branch = if command.contains("-a-") { "a" } else { "b" };
            let blocks: Vec<(Header, Body, u64)> = serde_json::from_slice(&fs::read(
                record_path.with_extension(format!("multi-fork-{branch}.json")),
            )?)?;
            for (header, body, _) in blocks.iter().rev() {
                let mut rwtxn = env.write_txn()?;
                state.disconnect_tip(&mut rwtxn, header, body)?;
                rwtxn.commit()?;
            }
        }
        "multi-epoch-fork-a-reconnect" | "multi-epoch-fork-b-reconnect" => {
            let branch = if command.contains("-a-") { "a" } else { "b" };
            let blocks: Vec<(Header, Body, u64)> = serde_json::from_slice(&fs::read(
                record_path.with_extension(format!("multi-fork-{branch}.json")),
            )?)?;
            for (header, body, timestamp) in blocks {
                let mut rwtxn = env.write_txn()?;
                state.apply_block(&archive, &mut rwtxn, &header, &body, timestamp)?;
                rwtxn.commit()?;
            }
        }
        "connect" => {
            let rotxn = env.read_txn()?;
            let prev_side_hash = state.try_get_tip(&rotxn)?;
            rotxn.commit()?;
            let body = Body::new(Vec::new(), Vec::new());
            let header = Header {
                merkle_root: Body::compute_merkle_root(
                    &body.coinbase,
                    &body.transactions,
                ),
                prev_side_hash,
                prev_main_hash: bitcoin::BlockHash::all_zeros(),
            };
            let mainchain_timestamp = if prev_side_hash.is_none() { 1_000 } else { 1_100 };
            let mut rwtxn = env.write_txn()?;
            state.apply_block(
                &archive,
                &mut rwtxn,
                &header,
                &body,
                mainchain_timestamp,
            )?;
            rwtxn.commit()?;
            fs::write(
                record_path,
                serde_json::to_vec(&(header, body, mainchain_timestamp))?,
            )?;
        }
        "disconnect" => {
            let (header, body, _): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(record_path)?)?;
            let mut rwtxn = env.write_txn()?;
            state.disconnect_tip(&mut rwtxn, &header, &body)?;
            rwtxn.commit()?;
        }
        "reconnect" => {
            let (header, body, mainchain_timestamp): (Header, Body, u64) =
                serde_json::from_slice(&fs::read(record_path)?)?;
            let mut rwtxn = env.write_txn()?;
            state.apply_block(
                &archive,
                &mut rwtxn,
                &header,
                &body,
                mainchain_timestamp,
            )?;
            rwtxn.commit()?;
        }
        _ => return Err("expected a supported ECX native fixture command".into()),
    }
    Ok(())
}
