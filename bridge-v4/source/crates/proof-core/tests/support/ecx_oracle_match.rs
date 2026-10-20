//! Signed ECX execution composed with the enclosing test's oracle fixture.
//! Recursive proofs and opaque sparse subtrees are synthetic, not production
//! authentication of prior state or evidence of real vault backing.
use ecx_proof_core::{
    ecx_execution_v1::verify_ecx_oracle_match_v1,
    proof_v2::verify_ecx_authenticated_funding_source_v1, ConversionLegConsensusProofV2,
};
use ecx_protocol_core::{
    ecx_cash_account_v1::{
        ecx_account_commitment, settle_ecx_execution_fee, verify_ecx_cash_conservation,
        EcxAccountOpeningV1, EcxCashAccountV1,
    },
    ecx_collateral::EcxCollateralAtoms,
    ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1},
    ecx_matcher_v1::EcxMatcherExecutionReceiptV1,
    ecx_order_index_v1::{
        order_leaf, stage_ecx_committed_match, EcxExecutionContextV1, EcxIndexedOrderOpeningV1,
        EcxMatchFeeWitnessV1,
    },
    ecx_order_v1::{stage_ecx_match, EcxAdmittedOrderV2, SignedEcxOrderV1},
    funding_v2::{advance_funding_timestamped_v2, FundingStateV2, TimestampedFundingObservationV2},
    hash::tagged_hash,
    incremental_state_v2::Int256V2,
    order::{OrderFlags, Side, TimeInForce},
    risk::RiskParams,
    successor_matcher_v2::SuccessorCentralMatcherConfigV2,
    FrozenConfigurationV2, Hash32, IncrementalAccountingBoundsV2, Price, Quantity,
    SuccessorLimitOrderV2, TraderLeafV2, XOnlyKey,
};
use ecx_truthcoin_proof::{
    ConsensusProofVerifier, DenyAllConsensusProofs, ParentChainContextV1, TruthcoinConsensusProofV1,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};

// Independent sparse construction, including successive replacement paths.
fn tree(
    entries: &[(Hash32, Hash32)],
    depth: usize,
    target: Hash32,
    path: &mut Vec<Hash32>,
    tag: &str,
) -> Hash32 {
    if entries.is_empty() {
        if tag == "ECX/ecx-account-tree-node/v1" {
            static EMPTY: std::sync::OnceLock<Vec<Hash32>> = std::sync::OnceLock::new();
            return EMPTY.get_or_init(|| (0..=256).map(|height|
                ecx_protocol_core::ecx_cash_account_v1::ecx_empty_account_subtree_v1(height).unwrap()
            ).collect())[256 - depth];
        }
        assert_eq!(tag, "ECX/ecx-order-index-node/v1");
        static EMPTY_ORDERS: std::sync::OnceLock<Vec<Hash32>> = std::sync::OnceLock::new();
        return EMPTY_ORDERS.get_or_init(|| {
            let mut hashes = vec![tagged_hash("ECX/ecx-order-index-empty/v1", &[])];
            for height in 1u16..=256 {
                let child = hashes[usize::from(height - 1)];
                let mut encoded = vec![1];
                encoded.extend_from_slice(&height.to_be_bytes());
                encoded.extend_from_slice(&child);
                encoded.extend_from_slice(&child);
                hashes.push(tagged_hash("ECX/ecx-order-index-node/v1", &encoded));
            }
            hashes
        })[256 - depth];
    }
    if depth == 256 {
        assert_eq!(entries.len(), 1);
        return entries[0].1;
    }
    let right_bit = |key: Hash32| key[depth / 8] & (1 << (7 - depth % 8)) != 0;
    let (left, right): (Vec<_>, Vec<_>) = entries
        .iter()
        .copied()
        .partition(|(key, _)| !right_bit(*key));
    let mut ignored = Vec::new();
    let (l, r) = if right_bit(target) {
        (
            tree(&left, depth + 1, target, &mut ignored, tag),
            tree(&right, depth + 1, target, path, tag),
        )
    } else {
        (
            tree(&left, depth + 1, target, path, tag),
            tree(&right, depth + 1, target, &mut ignored, tag),
        )
    };
    path.push(if right_bit(target) { l } else { r });
    let mut bytes = vec![1];
    bytes.extend_from_slice(&((256 - depth) as u16).to_be_bytes());
    bytes.extend_from_slice(&l);
    bytes.extend_from_slice(&r);
    tagged_hash(tag, &bytes)
}

pub fn exercise<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2,
    parent: ParentChainContextV1,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V,
) {
    for height in [17, 146] {
        // Explicit opt-in fixture export; contains synthetic source transcripts,
        // not live proofs or private keys. Export once per test process.
        if std::env::var_os("ECX_EXPORT_ORACLE_TEST_SEED").is_some() {
            static EXPORT: std::sync::Once = std::sync::Once::new();
            EXPORT.call_once(|| {
                let bytes = bincode::serialize(&(configuration, truthcoin, ecx_btc, usdd_usd)).unwrap();
                println!("ECX_ORACLE_TEST_SEED={}", hex::encode(bytes));
            });
        }
        let mut consumed = 0;
        exercise_with_withdrawal(configuration, parent, truthcoin, ecx_btc, usdd_usd,
        verifier, height, &mut |input| {
            consumed += 1;
            let state = input.execute(verifier).unwrap().0;
            assert_eq!(state.sidechain_height, height);
            assert_eq!(state.parent_hash, parent.block_hash);
            assert_eq!(state.parent_height, parent.height);
            assert_eq!(state.parent_mtp, parent.median_time_past);
            assert_eq!(input.signed.request.not_before_height, height);
        });
        assert_eq!(consumed, 2);
    }
}

/// Reuse the same oracle-backed lifecycle at a caller-selected child height.
/// The caller must supply oracle inputs for its authenticated parent context;
/// this hook never rewrites their parent commitments or receipt bytes.
pub fn exercise_with_withdrawal<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2,
    parent: ParentChainContextV1,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V,
    withdrawal_height: u64,
    consume: &mut impl FnMut(&ecx_proof_core::ecx_withdrawal_input_v1::EcxWithdrawalInputV1),
) {
    assert!(withdrawal_height > 2);
    for close in [false, true] {
        exercise_case(
            configuration,
            parent,
            truthcoin,
            ecx_btc,
            usdd_usd,
            verifier,
            close,
            withdrawal_height,
            consume,
            &mut |_| {},
            2,
            &mut |_| {},
        );
    }
}

/// Export signed admission from the same oracle-backed fixture, without
/// replacing any authenticated context. Proof receipts remain synthetic.
pub fn exercise_with_admission<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2,
    parent: ParentChainContextV1,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V,
    consume: &mut impl FnMut(&ecx_proof_core::ecx_admission_input_v1::EcxAdmissionInputV1),
) {
    for close in [false, true] {
        exercise_case(configuration, parent, truthcoin, ecx_btc, usdd_usd,
            verifier, close, 17, &mut |_| {}, consume, 17, &mut |_| {});
    }
}

pub struct LiquidationFixture<'a> {
    pub owned: &'a ecx_proof_core::ecx_liquidation_input_v1::EcxLiquidationInputV1,
    pub prior: &'a ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
    pub next: &'a ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
    pub bindings: EcxSuccessorBindingsV1,
    pub economics: EcxConfigurationV1,
    pub funding: &'a FundingStateV2,
    pub target: EcxAccountOpeningV1<'a>,
    pub makers: &'a [EcxAccountOpeningV1<'a>],
    pub clearing: EcxAccountOpeningV1<'a>,
    pub insurance: EcxAccountOpeningV1<'a>,
    pub orders: &'a [(&'a EcxAdmittedOrderV2, &'a [Hash32])],
    pub source_orders: &'a [&'a EcxAdmittedOrderV2],
    pub fills: &'a [(Hash32, u64)],
    pub vault: &'a ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'a>,
}

pub fn exercise_with_liquidation<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2, parent: ParentChainContextV1,
    truthcoin: &TruthcoinConsensusProofV1, ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2, verifier: &V,
    consume: &mut impl FnMut(&LiquidationFixture<'_>),
) {
    exercise_case(configuration, parent, truthcoin, ecx_btc, usdd_usd,
        verifier, true, 17, &mut |_| {}, &mut |_| {}, 17, consume);
}

fn exercise_case<V: ConsensusProofVerifier>(
    configuration: &FrozenConfigurationV2,
    parent: ParentChainContextV1,
    truthcoin: &TruthcoinConsensusProofV1,
    ecx_btc: &ConversionLegConsensusProofV2,
    usdd_usd: &ConversionLegConsensusProofV2,
    verifier: &V,
    close: bool,
    withdrawal_height: u64,
    consume: &mut impl FnMut(&ecx_proof_core::ecx_withdrawal_input_v1::EcxWithdrawalInputV1),
    consume_admission: &mut impl FnMut(&ecx_proof_core::ecx_admission_input_v1::EcxAdmissionInputV1),
    admission_height: u64,
    consume_liquidation: &mut impl FnMut(&LiquidationFixture<'_>),
) {
    let secret = |byte| SecretKey::from_slice(&[byte; 32]).unwrap();
    let key = |byte| {
        XOnlyKey(
            Keypair::from_secret_key(&Secp256k1::new(), &secret(byte))
                .x_only_public_key()
                .0
                .serialize(),
        )
    };
    let bounds = IncrementalAccountingBoundsV2 {
        maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
        maximum_total_controlled_atoms: 100_000_000_000_000,
        maximum_abs_position_atoms: 10_000_000_000,
        maximum_open_interest_atoms: 100_000_000_000,
        maximum_price_atoms: 1_000_000_000_000,
    };
    let economics = EcxConfigurationV1 {
        chain_id: configuration.base.chain_id,
        market: configuration.base.market,
        collateral_asset: configuration.base.ecx_asset_id,
        clearing_account: key(9),
        insurance_account: key(10),
        cash_valuation_scale: 1_000_000,
        risk: RiskParams::default(),
        bounds,
    };
    let matcher = SuccessorCentralMatcherConfigV2 {
        version: 2,
        key_epoch: 1,
        signer: key(11),
        genesis_sequence: 8,
        genesis_receipt_hash: [19; 32],
        forced_inclusion_blocks: 1,
    };
    let bindings = EcxSuccessorBindingsV1 {
        economic_configuration_hash: economics.digest().unwrap(),
        oracle_configuration_hash: configuration.digest(),
        matcher_configuration_hash: matcher.digest(),
        // Structural roles, NOT qualified guest identities.
        funding_oracle_program_id: [22; 32],
        account_execution_program_id: [23; 32],
        vault_policy_hash: [24; 32],
    };
    let source = verify_ecx_authenticated_funding_source_v1(
        bindings,
        economics,
        configuration,
        parent,
        truthcoin,
        ecx_btc,
        usdd_usd,
        verifier,
    )
    .unwrap();
    let mark = Price::new(source.mark_price_atoms).unwrap();
    let low = Price::new(source.authenticated_min_price_atoms).unwrap();
    let high = Price::new(source.authenticated_max_price_atoms).unwrap();
    let domain = economics.account_domain().unwrap();
    let position = |byte| TraderLeafV2 {
        version: TraderLeafV2::VERSION,
        trader: key(byte),
        account_nonce: 0,
        collateral_atoms: 0,
        cash_residual_numerator: 0,
        position_size_atoms: 0,
        signed_cost_basis_numerator: Int256V2::ZERO,
        last_funding_index_numerator: 0,
        selected_initial_margin_bps: 1000,
        order_generation: 0,
        salt: [4; 32],
    };
    const QUANTITY: u64 = 100_000_000;
    const BALANCE: u64 = 1_000_000_000_000;
    let admit = |byte, side| {
        let mut p = position(byte);
        if close {
            // Synthetic preexisting opposing positions, with a real nonzero
            // realized payoff at the oracle mark. Prior-state authentication
            // remains the enclosing successor's responsibility.
            assert!(source.mark_price_atoms >= 2);
            let delta = if byte == 7 {
                QUANTITY as i64
            } else {
                -(QUANTITY as i64)
            };
            assert_eq!(
                p.apply_trade_for_ecx_settlement(delta, source.mark_price_atoms / 2, 0, bounds)
                    .unwrap(),
                Int256V2::ZERO
            );
        }
        EcxAdmittedOrderV2::admit(
            SignedEcxOrderV1::sign(
                domain,
                SuccessorLimitOrderV2 {
                    version: 2,
                    chain_id: domain.chain_id,
                    market: domain.market,
                    trader: p.trader,
                    side,
                    time_in_force: TimeInForce::GoodTilHeight,
                    flags: OrderFlags::from_bits(0).unwrap(),
                    limit_price: mark,
                    quantity: Quantity::new(QUANTITY).unwrap(),
                    client_order_id: [0; 16],
                    max_fee_bps: 5,
                    nonce: 0,
                    valid_from_height: 0,
                    expires_at_height: 100,
                },
                &secret(byte),
            )
            .unwrap(),
            domain,
            &p,
            1,
            bounds, u128::from(byte),
        )
        .unwrap()
    };
    let (maker, maker_position) = admit(7, if close { Side::Sell } else { Side::Buy });
    let (taker, taker_position) = admit(8, if close { Side::Buy } else { Side::Sell });
    let clearing = position(9);
    let insurance = position(10);
    let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(BALANCE));
    let funding_low = Price::new(source.liquidation_low_atoms).unwrap();
    let funding_high = Price::new(source.liquidation_high_atoms).unwrap();
    let mut previous = FundingStateV2::genesis_with_band(
        parent.median_time_past,
        mark,
        funding_low,
        funding_high,
        source.oracle_valid_through_mtp,
        0,
    )
    .unwrap();
    let rollover = close && parent.median_time_past >= 28_800;
    if rollover {
        use ecx_protocol_core::funding_v2::{FUNDING_BUCKET_SECONDS, FUNDING_EPOCH_SECONDS};
        let start = (parent.median_time_past / FUNDING_EPOCH_SECONDS - 1) * FUNDING_EPOCH_SECONDS;
        previous = FundingStateV2::genesis_with_band(
            start,
            mark,
            funding_low,
            funding_high,
            source.oracle_valid_through_mtp,
            0,
        )
        .unwrap();
        let premium = Price::new(mark.get() + (mark.get() / 50).max(1)).unwrap();
        for hour in 1..=8 {
            let mtp = start + hour * FUNDING_BUCKET_SECONDS - 1;
            let observation = TimestampedFundingObservationV2::new(
                premium,
                Quantity::new(QUANTITY).unwrap(),
                mtp,
            )
            .unwrap();
            previous = advance_funding_timestamped_v2(
                &previous,
                mtp,
                mark,
                funding_low,
                funding_high,
                source.oracle_valid_through_mtp,
                &[observation],
                0,
            )
            .unwrap()
            .0;
        }
    }
    let expected_rate = advance_funding_timestamped_v2(
        &previous,
        parent.median_time_past,
        mark,
        funding_low,
        funding_high,
        source.oracle_valid_through_mtp,
        &[],
        0,
    )
    .unwrap()
    .1;
    assert_eq!(expected_rate, if rollover { 10_000 } else { 0 });
    let expected_index =
        ecx_protocol_core::advance_exact_funding_index_v2(0, mark.get(), expected_rate).unwrap();
    let trade = stage_ecx_match(
        domain,
        &maker,
        &taker,
        &maker_position,
        &taker_position,
        &cash,
        &cash,
        economics.clearing_account,
        &cash,
        2,
        QUANTITY,
        mark,
        expected_index,
        bounds,
    )
    .unwrap();
    if close {
        assert_eq!(trade.maker_position.position_size_atoms, 0);
        assert_eq!(trade.taker_position.position_size_atoms, 0);
        assert_ne!(trade.maker_cash, cash);
        assert_ne!(trade.taker_cash, cash);
        assert_eq!(trade.clearing_cash, cash);
    }
    let leaf = |p: &TraderLeafV2, c: &EcxCashAccountV1| {
        (
            p.key(),
            ecx_account_commitment(domain, p, c, bounds).unwrap(),
        )
    };
    let mut leaves = vec![
        leaf(&maker_position, &cash),
        leaf(&taker_position, &cash),
        leaf(&clearing, &cash),
        leaf(&insurance, &cash),
    ];
    let account_path = |leaves: &[(Hash32, Hash32)], key| {
        let mut path = Vec::new();
        let root = tree(leaves, 0, key, &mut path, "ECX/ecx-account-tree-node/v1");
        (root, path)
    };
    let (accounts_root, mp) = account_path(&leaves, maker_position.key());
    let ledger = [(&maker_position, &cash), (&taker_position, &cash),
        (&clearing, &cash), (&insurance, &cash)];
    let top_up = |root| ecx_protocol_core::ecx_cash_account_v1::stage_ecx_account_top_up_v1(
        root, economics, EcxAccountOpeningV1 {
            position: &maker_position, cash: &cash, siblings: &mp,
        }, 7,
    );
    let (funded_root, funded_cash) = top_up(accounts_root).unwrap();
    let mut funded_leaves = leaves.clone();
    funded_leaves[0] = leaf(&maker_position, &funded_cash);
    assert_eq!(funded_root, account_path(&funded_leaves, maker_position.key()).0);
    assert_eq!(funded_cash.balance().0, BALANCE + 7);
    // The same predecessor opening cannot credit an already-updated root.
    assert!(top_up(funded_root).is_err());
    let funded_ledger = [(&maker_position, &funded_cash), (&taker_position, &cash),
        (&clearing, &cash), (&insurance, &cash)];
    ecx_protocol_core::ecx_cash_account_v1::verify_ecx_complete_ledger_v1(
        funded_root, domain, bounds, &funded_ledger, 4 * BALANCE + 7,
    ).unwrap();
    assert!(ecx_protocol_core::ecx_cash_account_v1::verify_ecx_complete_ledger_v1(
        funded_root, domain, bounds, &funded_ledger, 4 * BALANCE,
    ).is_err());
    // Synthetic vault output: these bytes test binding, not chain inclusion
    // or qualification of the script's spend program.
    let vault_script = elements::Script::from(vec![0x51, 0x20].into_iter()
        .chain([17u8; 32]).collect::<Vec<_>>());
    let vault_script_hash: Hash32 = {
        use sha2::{Digest, Sha256};
        Sha256::digest(vault_script.as_bytes()).into()
    };
    let vault = |amount| elements::TxOut {
        asset: elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array(domain.collateral_asset)),
        value: elements::confidential::Value::Explicit(amount),
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: vault_script.clone(),
        witness: Default::default(),
    };
    let mut deposit_marker = vault(0);
    deposit_marker.script_pubkey = ecx_proof_core::ecx_execution_v1::ecx_deposit_marker_script_v1(
        economics, maker_position.key(), 1, 7,
    ).unwrap();
    for (recipient, vout, amount) in [(taker_position.key(), 1, 7),
        (maker_position.key(), 0, 7), (maker_position.key(), 1, 8)] {
        assert_ne!(deposit_marker.script_pubkey,
            ecx_proof_core::ecx_execution_v1::ecx_deposit_marker_script_v1(
                economics, recipient, vout, amount,
            ).unwrap());
    }
    for mutation in 0..3 {
        let mut other = economics;
        match mutation {
            0 => other.chain_id[0] ^= 1,
            1 => other.collateral_asset[0] ^= 1,
            2 => other.cash_valuation_scale += 1,
            _ => unreachable!(),
        }
        assert_ne!(deposit_marker.script_pubkey,
            ecx_proof_core::ecx_execution_v1::ecx_deposit_marker_script_v1(
                other, maker_position.key(), 1, 7,
            ).unwrap());
    }
    let deposit_source = elements::Transaction {
        version: 2, lock_time: elements::LockTime::ZERO, input: vec![],
        output: vec![vault(4 * BALANCE), vault(7), deposit_marker],
    };
    let prior_vault = elements::OutPoint { txid: deposit_source.txid(), vout: 0 };
    let deposit_coin = elements::OutPoint { txid: deposit_source.txid(), vout: 1 };
    let deposit_spend = elements::Transaction {
        version: 2, lock_time: elements::LockTime::ZERO,
        input: [prior_vault, deposit_coin].into_iter().map(|previous_output|
            elements::TxIn { previous_output, ..Default::default() }).collect(),
        output: vec![vault(4 * BALANCE + 7)],
    };
    let check_deposit = |tx: &elements::Transaction, coin, amount| {
        let (before, after) = ecx_proof_core::ecx_execution_v1::ecx_top_up_vault_outputs_v1(
            prior_vault, &deposit_source, coin, &deposit_source, tx, 0,
            domain.collateral_asset, amount,
        )?;
        ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
            accounts_root, vault_script_hash, domain, bounds, &ledger, before,
        )?;
        ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
            funded_root, vault_script_hash, domain, bounds, &funded_ledger, after,
        )
    };
    check_deposit(&deposit_spend, deposit_coin, 7).unwrap();
    let deposit_vault = ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1 {
        source_outpoint: prior_vault, source_transaction: &deposit_source,
        successor_transaction: &deposit_spend, successor_vout: 0,
        source_script_sha256: vault_script_hash, successor_script_sha256: vault_script_hash,
        prior_accounts: &ledger, successor_accounts: &funded_ledger,
    };
    let joined_deposit = |recipient, witness: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>| {
        ecx_proof_core::ecx_execution_v1::verify_ecx_account_top_up_v1(
            accounts_root, recipient, economics,
            EcxAccountOpeningV1 { position: &maker_position, cash: &cash, siblings: &mp },
            witness, deposit_coin, &deposit_source, 7,
        )
    };
    let (credited_root, credited_cash) = joined_deposit(maker_position.key(), &deposit_vault).unwrap();
    assert_eq!((credited_root, credited_cash.clone()), (funded_root, funded_cash.clone()));
    assert!(joined_deposit(taker_position.key(), &deposit_vault).is_err());
    let stale_deposit = ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1 {
        successor_accounts: &ledger, ..deposit_vault
    };
    assert!(joined_deposit(maker_position.key(), &stale_deposit).is_err());
    for mutation in 0..7 {
        let mut wrong_source = deposit_source.clone();
        match mutation {
            0 => { wrong_source.output.pop(); }
            1 => wrong_source.output.push(wrong_source.output[2].clone()),
            2 => wrong_source.output[2].value = elements::confidential::Value::Explicit(1),
            3 => wrong_source.output[2].script_pubkey =
                ecx_proof_core::ecx_execution_v1::ecx_deposit_marker_script_v1(
                    economics, taker_position.key(), 1, 7,
                ).unwrap(),
            4 => {
                let mut conflicting = wrong_source.output[2].clone();
                conflicting.script_pubkey =
                    ecx_proof_core::ecx_execution_v1::ecx_deposit_marker_script_v1(
                        economics, taker_position.key(), 1, 7,
                    ).unwrap();
                wrong_source.output.push(conflicting);
            }
            5 | 6 => {
                let mut conflicting = wrong_source.output[2].clone();
                let mut bytes = conflicting.script_pubkey.as_bytes().to_vec();
                if mutation == 5 {
                    bytes[6] = 2; // Unsupported ECXE version remains conflicting.
                } else {
                    bytes.insert(1, 0x4c); // Nonminimal OP_PUSHDATA1.
                }
                conflicting.script_pubkey = elements::Script::from(bytes);
                wrong_source.output.push(conflicting);
            }
            _ => unreachable!(),
        }
        let result = ecx_proof_core::ecx_execution_v1::verify_ecx_account_top_up_v1(
            accounts_root, maker_position.key(), economics,
            EcxAccountOpeningV1 { position: &maker_position, cash: &cash, siblings: &mp },
            &deposit_vault, deposit_coin, &wrong_source, 7,
        );
        assert!(matches!(result, Err(ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch("ECX deposit marker"))));
    }
    assert!(check_deposit(&deposit_spend, prior_vault, 7).is_err());
    assert!(check_deposit(&deposit_spend, deposit_coin, 6).is_err());
    for mutation in 0..5 {
        let mut wrong = deposit_spend.clone();
        match mutation {
            0 => { wrong.input.pop(); }
            1 => wrong.input.push(wrong.input[1].clone()),
            2 => wrong.input[1].is_pegin = true,
            3 => wrong.output[0].value = elements::confidential::Value::Explicit(4 * BALANCE + 6),
            4 => wrong.output[0].asset = elements::confidential::Asset::Null,
            _ => unreachable!(),
        }
        assert!(check_deposit(&wrong, deposit_coin, 7).is_err());
    }
    let verify_ledger = |entries: &[(&TraderLeafV2, &EcxCashAccountV1)], amount| {
        ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
            accounts_root, vault_script_hash, domain, bounds, entries, &vault(amount),
        )
    };
    verify_ledger(&ledger, 4 * BALANCE).unwrap();
    let mut reordered = ledger;
    reordered.reverse();
    verify_ledger(&reordered, 4 * BALANCE).unwrap();
    assert!(verify_ledger(&ledger[..3], 3 * BALANCE).is_err());
    assert!(verify_ledger(&[ledger[0], ledger[0], ledger[2], ledger[3]], 4 * BALANCE).is_err());
    assert!(verify_ledger(&ledger, 4 * BALANCE - 1).is_err());
    for field in 0..3 {
        let mut wrong = vault(4 * BALANCE);
        match field {
            0 => wrong.asset = elements::confidential::Asset::Null,
            1 => wrong.value = elements::confidential::Value::Null,
            2 => wrong.script_pubkey = elements::Script::new(),
            _ => unreachable!(),
        }
        assert!(ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
            accounts_root, vault_script_hash, domain, bounds, &ledger, &wrong,
        ).is_err());
    }
    // Continue from the verified deposit result, including its actual vault
    // output. Do not restart trading from the pre-deposit fixture balances.
    let accounts_root = credited_root;
    let ledger = [(&maker_position, &credited_cash), (&taker_position, &cash),
        (&clearing, &cash), (&insurance, &cash)];
    leaves = funded_leaves;
    let (independent_root, mp) = account_path(&leaves, maker_position.key());
    assert_eq!(accounts_root, independent_root);
    let trade = stage_ecx_match(domain, &maker, &taker, &maker_position, &taker_position,
        &credited_cash, &cash, economics.clearing_account, &cash, 2, QUANTITY,
        mark, expected_index, bounds).unwrap();
    let trading_backing = 4 * BALANCE + 7;
    leaves[0] = leaf(&trade.maker_position, &trade.maker_cash);
    let (_, tp) = account_path(&leaves, taker_position.key());
    leaves[1] = leaf(&trade.taker_position, &trade.taker_cash);
    let (_, cp) = account_path(&leaves, clearing.key());
    leaves[2] = leaf(&clearing, &trade.clearing_cash);
    let (_, mfp) = account_path(&leaves, maker_position.key());
    let (maker_paid, intermediate_insurance) = settle_ecx_execution_fee(
        &trade.maker_cash,
        &cash,
        mark,
        Quantity::new(QUANTITY).unwrap(),
        0,
        5,
        mark,
    )
    .unwrap();
    leaves[0] = leaf(&trade.maker_position, &maker_paid);
    let (_, ip) = account_path(&leaves, insurance.key());
    leaves[3] = leaf(&insurance, &intermediate_insurance);
    let (_, tfp) = account_path(&leaves, taker_position.key());
    let (taker_paid, insurance_paid) = settle_ecx_execution_fee(
        &trade.taker_cash,
        &intermediate_insurance,
        mark,
        Quantity::new(QUANTITY).unwrap(),
        5,
        5,
        mark,
    )
    .unwrap();
    leaves[1] = leaf(&trade.taker_position, &taker_paid);
    let (_, ifp) = account_path(&leaves, insurance.key());
    leaves[3] = leaf(&insurance, &insurance_paid);
    let (expected_accounts, _) = account_path(&leaves, insurance.key());
    let mid = maker.signed.order_id().unwrap();
    let tid = taker.signed.order_id().unwrap();
    let mut orders = vec![
        (mid, order_leaf(domain, mid, Some(&maker)).unwrap()),
        (tid, order_leaf(domain, tid, Some(&taker)).unwrap()),
    ];
    let mut mop = Vec::new();
    let tag = "ECX/ecx-order-index-node/v1";
    let orders_root = tree(&orders, 0, mid, &mut mop, tag);
    use ecx_protocol_core::ecx_order_index_v1::verify_ecx_best_maker_v1;
    let select = |root, book: &[&EcxAdmittedOrderV2], chosen: &EcxAdmittedOrderV2| {
        verify_ecx_best_maker_v1(accounts_root, root, economics, &ledger,
            trading_backing, book, chosen, &taker, 2)
    };
    select(orders_root, &[&maker, &taker], &maker).unwrap();
    assert!(select(orders_root, &[&maker], &maker).is_err());
    assert!(select(orders_root, &[&maker, &taker], &taker).is_err());
    // Authenticate an additional, smaller resting order at the same price.
    // Earlier admission must win even though it cannot fill the full taker.
    let mut competitor = maker.clone();
    let mut terms = competitor.signed.order.clone();
    terms.client_order_id = [42; 16];
    competitor.signed = SignedEcxOrderV1::sign(domain, terms, &secret(7)).unwrap();
    competitor.remaining = 1;
    competitor.received_sequence = maker.received_sequence - 1;
    let cid = competitor.signed.order_id().unwrap();
    let mut competing_entries = orders.clone();
    competing_entries.push((cid, order_leaf(domain, cid, Some(&competitor)).unwrap()));
    let competing_root = tree(&competing_entries, 0, cid, &mut Vec::new(), tag);
    let competing_book = [&maker, &taker, &competitor];
    if taker_position.position_size_atoms != 0 {
        use ecx_protocol_core::ecx_order_v1::stage_ecx_liquidation_fill_v1;
        let fill = stage_ecx_liquidation_fill_v1(economics, &maker, &maker_position,
            &taker_position, 2, QUANTITY, expected_index).unwrap();
        assert_eq!(fill.maker_position, trade.maker_position);
        assert_eq!(fill.target_position, trade.taker_position);
        assert!(fill.maker_order.is_none());
        assert_eq!(fill.target_position.position_size_atoms, 0);
        // Settle the liabilities derived from the actual signed fill, not
        // hand-selected P&L. All four physical balances and denominator-specific
        // fractional claims must still equal the original vault backing.
        use ecx_protocol_core::ecx_cash_account_v1::{
            settle_liquidation_batch_cash, verify_ecx_cash_conservation,
        };
        let (target_cash, clearing_cash, insurance_cash, cover, maker_cash) =
            settle_liquidation_batch_cash(&cash, &cash, &cash,
                fill.target_quote_pnl, fill.target_quote_penalty, mark,
                &[(&credited_cash, fill.maker_quote_pnl, fill.maker_quote_fee, mark)])
                .unwrap();
        assert_eq!(cover, 0);
        assert_eq!(maker_cash.len(), 1);
        use ecx_protocol_core::ecx_order_v1::stage_ecx_liquidation_batch_v1;
        let batch = stage_ecx_liquidation_batch_v1(economics, &taker_position, &cash,
            &[(&maker_position, &credited_cash)], &[&maker],
            &[(mid, QUANTITY / 2), (mid, QUANTITY / 2)], &cash, &cash,
            2, mark, expected_index).unwrap();
        assert_eq!(batch.target_position, fill.target_position);
        // Fee rounding is per fill, so a split need not equal one large fill.
        // Independently derive both liabilities, then settle their exact sum.
        let half = stage_ecx_liquidation_fill_v1(economics, &maker, &maker_position,
            &taker_position, 2, QUANTITY / 2, expected_index).unwrap();
        let rest = stage_ecx_liquidation_fill_v1(economics, half.maker_order.as_ref().unwrap(),
            &half.maker_position, &half.target_position, 2, QUANTITY / 2, expected_index).unwrap();
        let (split_target, split_clearing, split_insurance, _, split_makers) =
            settle_liquidation_batch_cash(&cash, &cash, &cash,
                half.target_quote_pnl.checked_add(rest.target_quote_pnl).unwrap(),
                half.target_quote_penalty.checked_add(rest.target_quote_penalty).unwrap(), mark,
                &[(&credited_cash, half.maker_quote_pnl.checked_add(rest.maker_quote_pnl).unwrap(),
                    half.maker_quote_fee.checked_add(rest.maker_quote_fee).unwrap(), mark)]).unwrap();
        assert_eq!(batch.target_cash, split_target);
        assert_eq!(batch.clearing_cash, split_clearing);
        assert_eq!(batch.insurance_cash, split_insurance);
        assert_eq!(batch.makers, vec![(rest.maker_position, split_makers[0].clone())]);
        verify_ecx_cash_conservation(&[batch.target_cash.clone(), batch.clearing_cash.clone(),
            batch.insurance_cash.clone(), batch.makers[0].1.clone()], trading_backing).unwrap();
        assert_eq!(batch.orders, vec![(mid, None)]);
        use ecx_protocol_core::ecx_order_index_v1::stage_ecx_priority_liquidation_batch_v1;
        let priority_batch = |root, book: &[&EcxAdmittedOrderV2],
                              touched: &[&EcxAdmittedOrderV2], fills: &[(Hash32, u64)]| {
            stage_ecx_priority_liquidation_batch_v1(accounts_root, root, economics,
                &ledger, trading_backing, book, &taker_position,
                &[(&maker_position, &credited_cash)], touched, fills,
                2, mark, mark, mark, expected_index)
        };
        assert_eq!(priority_batch(orders_root, &[&maker, &taker], &[&maker],
            &[(mid, QUANTITY / 2), (mid, QUANTITY / 2)]).unwrap(), batch);
        // A smaller earlier order is not bypassed. Its actual exhaustion allows
        // the next order, without settling cash or finalizing the target twice.
        assert!(matches!(priority_batch(competing_root, &competing_book, &[&maker],
            &[(mid, QUANTITY)]), Err(ecx_protocol_core::ProtocolError::PriceTimePriorityViolation)));
        let ordered = priority_batch(competing_root, &competing_book, &[&competitor, &maker],
            &[(cid, 1), (mid, QUANTITY - 1)]).unwrap();
        assert_eq!(ordered.target_position.position_size_atoms, 0);
        assert!(ordered.orders[0].1.is_none());
        assert_eq!(ordered.orders[1].1.as_ref().unwrap().remaining, 1);
        assert!(matches!(priority_batch(competing_root, &competing_book, &[&competitor],
            &[(cid, 1), (cid, 1)]), Err(ecx_protocol_core::ProtocolError::IncompatibleOrders)));
        assert!(priority_batch(competing_root, &[&maker, &taker], &[&maker],
            &[(mid, QUANTITY)]).is_err());
        let mut partial_head = competitor.clone();
        partial_head.remaining = QUANTITY / 2;
        let partial_book = [&maker, &taker, &partial_head];
        let mut partial_entries = orders.clone();
        partial_entries.push((cid, order_leaf(domain, cid, Some(&partial_head)).unwrap()));
        let partial_root = tree(&partial_entries, 0, cid, &mut Vec::new(), tag);
        // Checking only the first fill would accept this invalid second fill.
        assert!(matches!(priority_batch(partial_root, &partial_book, &[&partial_head, &maker],
            &[(cid, QUANTITY / 4), (mid, QUANTITY / 4)]),
            Err(ecx_protocol_core::ProtocolError::PriceTimePriorityViolation)));
        priority_batch(partial_root, &partial_book, &[&partial_head, &maker],
            &[(cid, QUANTITY / 4), (cid, QUANTITY / 4), (mid, QUANTITY / 2)]).unwrap();
        let mut finalized = batch.target_position.clone();
        finalized.account_nonce += 1;
        finalized.order_generation += 1;
        let mut batch_leaves = vec![leaf(&maker_position, &credited_cash),
            leaf(&taker_position, &cash), leaf(&clearing, &cash), leaf(&insurance, &cash)];
        let (_, bp_target) = account_path(&batch_leaves, taker_position.key());
        batch_leaves[1] = leaf(&finalized, &batch.target_cash);
        let (_, bp_maker) = account_path(&batch_leaves, maker_position.key());
        batch_leaves[0] = leaf(&batch.makers[0].0, &batch.makers[0].1);
        let (_, bp_clearing) = account_path(&batch_leaves, clearing.key());
        batch_leaves[2] = leaf(&clearing, &batch.clearing_cash);
        let (_, bp_insurance) = account_path(&batch_leaves, insurance.key());
        batch_leaves[3] = leaf(&insurance, &batch.insurance_cash);
        let expected_batch_root = account_path(&batch_leaves, insurance.key()).0;
        let run_batch = |path: &[Hash32]| {
            ecx_protocol_core::ecx_order_index_v1::stage_ecx_indexed_liquidation_batch_v1(
                accounts_root, orders_root, economics, &ledger, trading_backing,
                EcxAccountOpeningV1 { position: &taker_position, cash: &cash, siblings: path },
                &[EcxAccountOpeningV1 { position: &maker_position, cash: &credited_cash, siblings: &bp_maker }],
                EcxAccountOpeningV1 { position: &clearing, cash: &cash, siblings: &bp_clearing },
                EcxAccountOpeningV1 { position: &insurance, cash: &cash, siblings: &bp_insurance },
                &[(&maker, &mop)], &[&maker, &taker], &[(mid, QUANTITY / 2), (mid, QUANTITY / 2)],
                2, mark, mark, mark, expected_index)
        };
        let (batch_root, batch_book, committed_batch) = run_batch(&bp_target).unwrap();
        assert_eq!(batch_root, expected_batch_root);
        assert_eq!(committed_batch.target_position, finalized);
        assert_eq!(committed_batch.makers, batch.makers);
        let mut bad_path = bp_target.clone();
        bad_path[0][0] ^= 1;
        assert!(run_batch(&bad_path).is_err());
        use ecx_protocol_core::ecx_order_index_v1::verify_ecx_post_liquidation_reserve_v1;
        let remaining_entries = vec![(tid, order_leaf(domain, tid, Some(&taker)).unwrap())];
        let remaining_root = tree(&remaining_entries, 0, tid, &mut Vec::new(), tag);
        assert_eq!(batch_book, remaining_root);
        verify_ecx_post_liquidation_reserve_v1(orders_root, remaining_root,
            &[&maker, &taker], economics, &batch, 2, mark, mark, expected_index).unwrap();
        assert!(verify_ecx_post_liquidation_reserve_v1(orders_root, orders_root,
            &[&maker, &taker], economics, &batch, 2, mark, mark, expected_index).is_err());
        assert!(verify_ecx_post_liquidation_reserve_v1(orders_root, remaining_root,
            &[&maker], economics, &batch, 2, mark, mark, expected_index).is_err());
        let mut duplicate = batch.clone();
        duplicate.orders.push(duplicate.orders[0].clone());
        assert!(verify_ecx_post_liquidation_reserve_v1(orders_root, remaining_root,
            &[&maker, &taker], economics, &duplicate, 2, mark, mark, expected_index).is_err());
        assert!(stage_ecx_liquidation_batch_v1(economics, &taker_position, &cash,
            &[(&maker_position, &credited_cash), (&maker_position, &credited_cash)],
            &[&maker], &[(mid, QUANTITY)], &cash, &cash, 2, mark, expected_index).is_err());
        assert!(stage_ecx_liquidation_batch_v1(economics, &taker_position, &cash,
            &[(&maker_position, &credited_cash)], &[&maker],
            &[(mid, QUANTITY), (mid, 1)], &cash, &cash, 2, mark, expected_index).is_err());
        // Two distinct signed orders owned by one maker still settle one account.
        let mut other = maker.clone();
        let mut other_terms = other.signed.order.clone();
        other_terms.client_order_id = [91; 16];
        other.signed = SignedEcxOrderV1::sign(domain, other_terms, &secret(7)).unwrap();
        let other_id = other.signed.order_id().unwrap();
        let multi = stage_ecx_liquidation_batch_v1(economics, &taker_position, &cash,
            &[(&maker_position, &credited_cash)], &[&maker, &other],
            &[(mid, QUANTITY / 2), (other_id, QUANTITY / 2)], &cash, &cash,
            2, mark, expected_index).unwrap();
        assert_eq!(multi.makers, batch.makers);
        assert_eq!(multi.target_cash, batch.target_cash);
        assert_eq!(multi.insurance_cash, batch.insurance_cash);
        assert!(multi.orders.iter().all(|(_, order)| order.as_ref().unwrap().remaining == QUANTITY / 2));
        let mut second_position = maker_position.clone();
        second_position.trader = position(11).trader;
        let mut second_order = other.clone();
        let mut second_terms = second_order.signed.order.clone();
        second_terms.trader = second_position.trader;
        second_order.signed = SignedEcxOrderV1::sign(domain, second_terms, &secret(11)).unwrap();
        let second_id = second_order.signed.order_id().unwrap();
        // After reducing a smaller maker to flat, its remaining reduce-only
        // order ceases to compete. Selection must use the updated position.
        let small_position = |byte| {
            let mut p = position(byte);
            p.apply_trade_for_ecx_settlement((QUANTITY / 2) as i64,
                source.mark_price_atoms / 2, 0, bounds).unwrap();
            p.account_nonce = maker_position.account_nonce;
            p
        };
        let small_maker = small_position(7);
        let small_second = small_position(11);
        let mut reducing = maker.clone();
        let mut reducing_terms = reducing.signed.order.clone();
        reducing_terms.flags = OrderFlags::REDUCE_ONLY;
        reducing.signed = SignedEcxOrderV1::sign(domain, reducing_terms, &secret(7)).unwrap();
        let reducing_id = reducing.signed.order_id().unwrap();
        let mut later = second_order.clone();
        later.received_sequence = maker.received_sequence + 1;
        let reduce_book = [&reducing, &later, &taker];
        let reduce_entries: Vec<_> = reduce_book.iter().map(|o| {
            let id = o.signed.order_id().unwrap();
            (id, order_leaf(domain, id, Some(o)).unwrap())
        }).collect();
        let reduce_root = tree(&reduce_entries, 0, reducing_id, &mut Vec::new(), tag);
        let reduce_ledger = [(&small_maker, &credited_cash), (&small_second, &cash),
            (&taker_position, &cash), (&clearing, &cash), (&insurance, &cash)];
        let reduce_leaves: Vec<_> = reduce_ledger.iter().map(|(p, c)| leaf(p, c)).collect();
        let reduce_accounts_root = account_path(&reduce_leaves, small_maker.key()).0;
        let reduce_batch = |fills: &[(Hash32, u64)]| {
            stage_ecx_priority_liquidation_batch_v1(reduce_accounts_root, reduce_root,
                economics, &reduce_ledger, trading_backing + BALANCE, &reduce_book,
                &taker_position, &[(&small_maker, &credited_cash), (&small_second, &cash)],
                &[&reducing, &later], fills, 2, mark, mark, mark, expected_index)
        };
        let reduced = reduce_batch(&[(reducing_id, QUANTITY / 2), (second_id, QUANTITY / 2)]).unwrap();
        assert!(reduced.makers.iter().all(|(p, _)| p.position_size_atoms == 0));
        assert_eq!(reduced.orders[0].1.as_ref().unwrap().remaining, QUANTITY / 2);
        assert!(matches!(reduce_batch(&[(reducing_id, QUANTITY / 2), (reducing_id, 1)]),
            Err(ecx_protocol_core::ProtocolError::PriceTimePriorityViolation)));
        assert!(matches!(reduce_batch(&[(second_id, QUANTITY / 2), (reducing_id, QUANTITY / 2)]),
            Err(ecx_protocol_core::ProtocolError::PriceTimePriorityViolation)));
        let distinct = stage_ecx_liquidation_batch_v1(economics, &taker_position, &cash,
            &[(&maker_position, &credited_cash), (&second_position, &cash)],
            &[&maker, &second_order], &[(mid, QUANTITY / 2), (second_id, QUANTITY / 2)],
            &cash, &cash, 2, mark, expected_index).unwrap();
        assert_eq!(distinct.target_position, fill.target_position);
        assert_eq!(distinct.makers.len(), 2);
        verify_ecx_cash_conservation(&[distinct.target_cash, distinct.clearing_cash,
            distinct.insurance_cash, distinct.makers[0].1.clone(),
            distinct.makers[1].1.clone()], trading_backing + BALANCE).unwrap();
        verify_ecx_cash_conservation(&[target_cash.clone(), clearing_cash.clone(),
            insurance_cash.clone(), maker_cash[0].clone()], trading_backing).unwrap();
        // Dropping a fee recipient cannot be accepted as the successor ledger.
        assert!(verify_ecx_cash_conservation(&[target_cash.clone(), clearing_cash.clone(),
            maker_cash[0].clone()], trading_backing).is_err());
        // Independently reconstruct sequential account openings and final roots.
        // This single-fill composition is not the enclosing liquidation authorization.
        use ecx_protocol_core::ecx_order_index_v1::stage_ecx_indexed_liquidation_fill_v1;
        let mut liquidation_leaves = vec![leaf(&maker_position, &credited_cash),
            leaf(&taker_position, &cash), leaf(&clearing, &cash), leaf(&insurance, &cash)];
        let (source_root, target_path) = account_path(&liquidation_leaves, taker_position.key());
        assert_eq!(source_root, accounts_root);
        liquidation_leaves[1] = leaf(&fill.target_position, &target_cash);
        let (_, maker_path) = account_path(&liquidation_leaves, maker_position.key());
        liquidation_leaves[0] = leaf(&fill.maker_position, &maker_cash[0]);
        let (_, clearing_path) = account_path(&liquidation_leaves, clearing.key());
        liquidation_leaves[2] = leaf(&clearing, &clearing_cash);
        let (_, insurance_path) = account_path(&liquidation_leaves, insurance.key());
        liquidation_leaves[3] = leaf(&insurance, &insurance_cash);
        let (expected_root, _) = account_path(&liquidation_leaves, insurance.key());
        let run_indexed = |target_siblings: &[Hash32]| {
            stage_ecx_indexed_liquidation_fill_v1(accounts_root, orders_root, economics,
                EcxAccountOpeningV1 { position: &taker_position, cash: &cash, siblings: target_siblings },
                EcxIndexedOrderOpeningV1 { order: &maker,
                    account: EcxAccountOpeningV1 { position: &maker_position,
                        cash: &credited_cash, siblings: &maker_path }, order_siblings: &mop },
                EcxAccountOpeningV1 { position: &clearing, cash: &cash, siblings: &clearing_path },
                EcxAccountOpeningV1 { position: &insurance, cash: &cash, siblings: &insurance_path },
                2, QUANTITY, mark, expected_index)
        };
        let indexed = run_indexed(&target_path).unwrap();
        assert_eq!(indexed.accounts_root, expected_root);
        let remaining = vec![(tid, order_leaf(domain, tid, Some(&taker)).unwrap())];
        assert_eq!(indexed.orders_root, tree(&remaining, 0, tid, &mut Vec::new(), tag));
        assert_eq!(indexed.fill, fill);
        assert_eq!(indexed.target_cash, target_cash);
        assert_eq!(indexed.insurance_cash, insurance_cash);
        let mut wrong_path = target_path.clone();
        wrong_path[0][0] ^= 1;
        assert!(run_indexed(&wrong_path).is_err());
        use ecx_protocol_core::ecx_order_index_v1::{
            finalize_ecx_liquidation_target_v1, ecx_outstanding_orders_v1,
        };
        let (_, final_target_path) = account_path(&liquidation_leaves, taker_position.key());
        let (final_root, final_target) = finalize_ecx_liquidation_target_v1(
            indexed.accounts_root, economics, EcxAccountOpeningV1 {
                position: &indexed.fill.target_position, cash: &indexed.target_cash,
                siblings: &final_target_path,
            }).unwrap();
        assert_eq!(final_target.account_nonce, taker_position.account_nonce + 1);
        assert_eq!(final_target.order_generation, taker_position.order_generation + 1);
        let mut expected_target = indexed.fill.target_position.clone();
        expected_target.account_nonce += 1;
        expected_target.order_generation += 1;
        assert_eq!(final_target, expected_target);
        liquidation_leaves[1] = leaf(&final_target, &indexed.target_cash);
        assert_eq!(final_root, account_path(&liquidation_leaves, final_target.key()).0);
        assert_eq!(ecx_outstanding_orders_v1(indexed.orders_root, domain, &[&taker],
            &indexed.fill.target_position, 2, bounds).unwrap().len(), 1);
        assert!(ecx_outstanding_orders_v1(indexed.orders_root, domain, &[&taker],
            &final_target, 2, bounds).unwrap().is_empty());
        assert!(taker.fill(domain, &final_target, 2, QUANTITY, mark, false, 5, bounds).is_err());
        // A pre-finalization opening cannot be replayed against the new root.
        assert!(finalize_ecx_liquidation_target_v1(final_root, economics,
            EcxAccountOpeningV1 { position: &indexed.fill.target_position,
                cash: &indexed.target_cash, siblings: &final_target_path }).is_err());
        assert!(stage_ecx_liquidation_fill_v1(economics, &maker, &maker_position,
            &taker_position, 2, QUANTITY + 1, expected_index).is_err());
        assert!(stage_ecx_liquidation_fill_v1(economics, &maker, &maker_position,
            &maker_position, 2, QUANTITY, expected_index).is_err());
        use ecx_protocol_core::ecx_order_index_v1::verify_ecx_best_liquidation_maker_v1;
        let liquidation = |book: &[&EcxAdmittedOrderV2], chosen: &EcxAdmittedOrderV2,
                           target: &TraderLeafV2| {
            verify_ecx_best_liquidation_maker_v1(accounts_root, competing_root,
                economics, &ledger, trading_backing, book, chosen, target, 2, mark, mark)
        };
        assert_eq!(liquidation(&competing_book, &competitor, &taker_position).unwrap(), mark);
        // Selection must exclude the same reserved identities as fill execution.
        // A correctly authenticated order does not make clearing a legal maker.
        let mut reserved_position = clearing.clone();
        reserved_position.account_nonce = 1;
        let mut reserved_order = competitor.clone();
        let mut terms = reserved_order.signed.order.clone();
        terms.trader = clearing.trader;
        terms.nonce = 0;
        reserved_order.signed = SignedEcxOrderV1::sign(domain, terms, &secret(9)).unwrap();
        let rid = reserved_order.signed.order_id().unwrap();
        let reserved_entries = vec![(rid, order_leaf(domain, rid, Some(&reserved_order)).unwrap())];
        let reserved_book_root = tree(&reserved_entries, 0, rid, &mut Vec::new(), tag);
        let reserved_leaves = vec![leaf(&maker_position, &credited_cash),
            leaf(&taker_position, &cash), leaf(&reserved_position, &cash), leaf(&insurance, &cash)];
        let reserved_root = account_path(&reserved_leaves, reserved_position.key()).0;
        let reserved_ledger = [(&maker_position, &credited_cash), (&taker_position, &cash),
            (&reserved_position, &cash), (&insurance, &cash)];
        assert!(verify_ecx_best_liquidation_maker_v1(reserved_root, reserved_book_root,
            economics, &reserved_ledger, trading_backing, &[&reserved_order], &reserved_order,
            &taker_position, 2, mark, mark).is_err());
        assert!(liquidation(&competing_book, &maker, &taker_position).is_err());
        assert!(liquidation(&[&maker, &taker], &maker, &taker_position).is_err());
        let mut substituted = taker_position.clone();
        substituted.position_size_atoms = -substituted.position_size_atoms;
        assert!(liquidation(&competing_book, &competitor, &substituted).is_err());
        // Reverse target direction: its own orders are not counterparties.
        assert_eq!(liquidation(&competing_book, &taker, &maker_position).unwrap(), mark);
        for (target, chosen) in [(&maker_position, &taker), (&taker_position, &competitor)] {
            let outside = Price::new(if target.position_size_atoms > 0 {
                mark.get().checked_add(1).unwrap()
            } else { mark.get().checked_sub(1).unwrap() }).unwrap();
            assert!(verify_ecx_best_liquidation_maker_v1(accounts_root, competing_root,
                economics, &ledger, trading_backing, &competing_book, chosen, target,
                2, outside, outside).is_err());
        }
    }
    assert!(select(competing_root, &competing_book, &maker).is_err());
    select(competing_root, &competing_book, &competitor).unwrap();
    assert!(select(competing_root, &[&maker, &taker], &maker).is_err());
    // Fully authenticate each alternate book: an expired/future order cannot
    // block trading, but inclusive time boundaries retain its priority.
    for (valid_from, expires_at, eligible) in
        [(0, 1, false), (3, 100, false), (0, 2, true), (2, 100, true)]
    {
        let mut timed = competitor.clone();
        let mut terms = timed.signed.order.clone();
        terms.valid_from_height = valid_from;
        terms.expires_at_height = expires_at;
        timed.signed = SignedEcxOrderV1::sign(domain, terms, &secret(7)).unwrap();
        let key = timed.signed.order_id().unwrap();
        let mut entries = orders.clone();
        entries.push((key, order_leaf(domain, key, Some(&timed)).unwrap()));
        let root = tree(&entries, 0, key, &mut Vec::new(), tag);
        let book = [&maker, &taker, &timed];
        assert_eq!(select(root, &book, &timed).is_ok(), eligible);
        assert_eq!(select(root, &book, &maker).is_ok(), !eligible);
        // Eligibility never permits omitting the authenticated record.
        assert!(select(root, &[&maker, &taker], &maker).is_err());
    }
    let mut forged_position = maker_position.clone();
    forged_position.order_generation += 1;
    let forged_ledger = [(&forged_position, &credited_cash), (&taker_position, &cash),
        (&clearing, &cash), (&insurance, &cash)];
    assert!(verify_ecx_best_maker_v1(accounts_root, competing_root, economics,
        &forged_ledger, trading_backing, &competing_book, &maker, &taker, 2).is_err());
    use ecx_protocol_core::ecx_order_index_v1::verify_ecx_complete_order_book_v1;
    verify_ecx_complete_order_book_v1(orders_root, domain, &[&maker, &taker]).unwrap();
    verify_ecx_complete_order_book_v1(orders_root, domain, &[&taker, &maker]).unwrap();
    assert!(verify_ecx_complete_order_book_v1(orders_root, domain, &[&maker]).is_err());
    assert!(verify_ecx_complete_order_book_v1(orders_root, domain, &[&maker, &taker, &maker]).is_err());
    let mut altered_order = maker.clone();
    altered_order.generation += 1;
    assert!(verify_ecx_complete_order_book_v1(orders_root, domain, &[&altered_order, &taker]).is_err());
    let mut altered_order = maker.clone();
    altered_order.remaining = 0;
    assert!(verify_ecx_complete_order_book_v1(orders_root, domain, &[&altered_order, &taker]).is_err());
    let mut altered_order = maker.clone();
    altered_order.remaining -= 1;
    assert!(verify_ecx_complete_order_book_v1(orders_root, domain, &[&altered_order, &taker]).is_err());
    let mut wrong_domain = domain;
    wrong_domain.configuration_hash[0] ^= 1;
    assert!(verify_ecx_complete_order_book_v1(orders_root, wrong_domain, &[&maker, &taker]).is_err());
    orders[0].1 = order_leaf(domain, mid, None).unwrap();
    let mut top = Vec::new();
    tree(&orders, 0, tid, &mut top, tag);
    orders[1].1 = order_leaf(domain, tid, None).unwrap();
    let expected_orders = tree(&orders, 0, tid, &mut Vec::new(), tag);
    verify_ecx_complete_order_book_v1(expected_orders, domain, &[]).unwrap();
    assert!(verify_ecx_complete_order_book_v1(orders_root, domain, &[]).is_err());
    let openings = || {
        (
            EcxIndexedOrderOpeningV1 {
                order: &maker,
                order_siblings: &mop,
                account: EcxAccountOpeningV1 {
                    position: &maker_position,
                    cash: &credited_cash,
                    siblings: &mp,
                },
            },
            EcxIndexedOrderOpeningV1 {
                order: &taker,
                order_siblings: &top,
                account: EcxAccountOpeningV1 {
                    position: &taker_position,
                    cash: &cash,
                    siblings: &tp,
                },
            },
            EcxAccountOpeningV1 {
                position: &clearing,
                cash: &cash,
                siblings: &cp,
            },
            EcxMatchFeeWitnessV1 {
                insurance: EcxAccountOpeningV1 {
                    position: &insurance,
                    cash: &cash,
                    siblings: &ip,
                },
                maker_siblings: &mfp,
                taker_siblings: &tfp,
                final_insurance_siblings: &ifp,
            },
        )
    };
    let context = EcxExecutionContextV1 {
        parent_hash: parent.block_hash,
        parent_height: parent.height,
        parent_mtp: parent.median_time_past,
        match_sequence: 9,
    };
    let (m, t, c, f) = openings();
    let (expected_execution, execution_hash) = stage_ecx_committed_match(
        accounts_root,
        orders_root,
        economics,
        m,
        t,
        c,
        2,
        QUANTITY,
        mark,
        expected_index,
        low,
        high,
        context,
        Some(f),
        &[&maker, &taker],
    )
    .unwrap();
    let receipt = EcxMatcherExecutionReceiptV1::sign(
        economics,
        &matcher,
        9,
        matcher.genesis_receipt_hash,
        execution_hash,
        &secret(11),
    )
    .unwrap();
    let source_tx = deposit_spend.clone();
    let outpoint = elements::OutPoint { txid: source_tx.txid(), vout: 0 };
    let successor_tx = elements::Transaction {
        version: 2, lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn { previous_output: outpoint, ..Default::default() }],
        output: vec![vault(trading_backing)],
    };
    let expected_trade = &expected_execution.accounts.trade;
    let expected_ledger = [
        (&expected_trade.maker_position, &expected_trade.maker_cash),
        (&expected_trade.taker_position, &expected_trade.taker_cash),
        (&clearing, &expected_trade.clearing_cash), (&insurance, &insurance_paid),
    ];
    let vault_witness = ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1 {
        source_outpoint: outpoint, source_transaction: &source_tx,
        successor_transaction: &successor_tx, successor_vout: 0,
        source_script_sha256: vault_script_hash, successor_script_sha256: vault_script_hash,
        prior_accounts: &ledger, successor_accounts: &expected_ledger,
    };
    // Synthetic authenticated-state stand-in for this fixture, not a proof
    // that the prior root is present in a real covenant output.
    let elements::confidential::Value::Explicit(backing) = source_tx.output[0].value
        else { panic!("fixture requires explicit ECX backing") };
    let prior_oi = if close { u128::from(QUANTITY) } else { 0 };
    assert_eq!(ecx_proof_core::ecx_successor_state_v1::ecx_ledger_open_interest(
        &ledger).unwrap(), prior_oi);
    assert_eq!(ecx_proof_core::ecx_successor_state_v1::ecx_ledger_open_interest(
        &expected_ledger).unwrap(), if close { 0 } else { u128::from(QUANTITY) });
    let mut unbalanced_position = maker_position.clone();
    unbalanced_position.position_size_atoms += 1;
    let mut unbalanced_ledger = ledger;
    unbalanced_ledger[0].0 = &unbalanced_position;
    assert!(ecx_proof_core::ecx_successor_state_v1::ecx_ledger_open_interest(
        &unbalanced_ledger).is_err());
    let prior_state = ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1 {
        bindings_hash: bindings.digest().unwrap(), accounts_root, orders_root,
        funding_root: previous.root(), funding_index: 0, open_interest: prior_oi,
        matcher_sequence: 8, matcher_receipt_hash: matcher.genesis_receipt_hash,
        sidechain_height: 2, parent_hash: parent.block_hash,
        parent_height: parent.height, parent_mtp: parent.median_time_past,
        controlled_ecx_atoms: backing, vault_script_sha256: vault_script_hash,
    };
    let state_digest = prior_state.digest().unwrap();
    if close {
      for liquidation_quantity in [QUANTITY, QUANTITY / 2] {
        // A separate authenticated predecessor: the short has no cash and its
        // original cash is in insurance. This is a test state, not a deposit
        // or an authorized transfer from the healthy predecessor above.
        let empty = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(0));
        let insured = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(2 * BALANCE));
        let liquidation_ledger = [(&maker_position, &credited_cash),
            (&taker_position, &empty), (&clearing, &cash), (&insurance, &insured)];
        let mut leaves = vec![leaf(&maker_position, &credited_cash),
            leaf(&taker_position, &empty), leaf(&clearing, &cash), leaf(&insurance, &insured)];
        let (root, target_path) = account_path(&leaves, taker_position.key());
        let mut prior = prior_state.clone();
        prior.accounts_root = root;
        prior.sidechain_height = admission_height;
        let staged = ecx_protocol_core::ecx_order_v1::stage_ecx_liquidation_batch_v1(
            economics, &taker_position, &empty, &[(&maker_position, &credited_cash)],
            &[&maker], &[(mid, liquidation_quantity)], &cash, &insured, admission_height, mark, expected_index).unwrap();
        let mut finalized = staged.target_position.clone();
        finalized.account_nonce += 1;
        finalized.order_generation += 1;
        leaves[1] = leaf(&finalized, &staged.target_cash);
        let (_, maker_path) = account_path(&leaves, maker_position.key());
        leaves[0] = leaf(&staged.makers[0].0, &staged.makers[0].1);
        let (_, clearing_path) = account_path(&leaves, clearing.key());
        leaves[2] = leaf(&clearing, &staged.clearing_cash);
        let (_, insurance_path) = account_path(&leaves, insurance.key());
        leaves[3] = leaf(&insurance, &staged.insurance_cash);
        let final_root = account_path(&leaves, insurance.key()).0;
        let next_ledger = [(&staged.makers[0].0, &staged.makers[0].1),
            (&finalized, &staged.target_cash), (&clearing, &staged.clearing_cash),
            (&insurance, &staged.insurance_cash)];
        let mut liquidation_vault = vault_witness;
        liquidation_vault.prior_accounts = &liquidation_ledger;
        liquidation_vault.successor_accounts = &next_ledger;
        let run_liquidation = |vault: &_| ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_liquidation_batch_v1(
            prior.digest().unwrap(), &prior, outpoint, bindings, economics, configuration,
            truthcoin, ecx_btc, usdd_usd, verifier, &previous,
            EcxAccountOpeningV1 { position: &taker_position, cash: &empty, siblings: &target_path },
            &[EcxAccountOpeningV1 { position: &maker_position, cash: &credited_cash, siblings: &maker_path }],
            EcxAccountOpeningV1 { position: &clearing, cash: &cash, siblings: &clearing_path },
            EcxAccountOpeningV1 { position: &insurance, cash: &insured, siblings: &insurance_path },
            &[(&maker, &mop)], &[&maker, &taker], &[(mid, liquidation_quantity)], vault);
        let (next, _, result) = run_liquidation(&liquidation_vault).unwrap();
        assert_eq!(next.accounts_root, final_root);
        assert_eq!(next.controlled_ecx_atoms, prior.controlled_ecx_atoms);
        assert_eq!(next.open_interest, u128::from(QUANTITY - liquidation_quantity));
        assert_eq!(result.target_position.position_size_atoms,
            -((QUANTITY - liquidation_quantity) as i64));
        assert_eq!(result.target_position.account_nonce, taker_position.account_nonce + 1);
        assert_eq!(result.target_position.order_generation, taker_position.order_generation + 1);
        if liquidation_quantity < QUANTITY {
            assert_eq!(result.orders[0].1.as_ref().unwrap().remaining,
                QUANTITY - liquidation_quantity);
            assert_ne!(next.orders_root, prior.orders_root);
            // Isolate the successor reserve check: the surviving maker has
            // exposure and an authenticated remainder, not free collateral.
            let mut unfunded = result.clone();
            unfunded.makers[0].1 = empty.clone();
            assert!(matches!(
                ecx_protocol_core::ecx_order_index_v1::verify_ecx_post_liquidation_reserve_v1(
                    prior.orders_root, next.orders_root, &[&maker, &taker],
                    economics, &unfunded, admission_height, funding_low, funding_high, expected_index),
                Err(ecx_protocol_core::ProtocolError::InsufficientCollateral)));
            let mut forged_remainder = result.clone();
            forged_remainder.orders[0].1.as_mut().unwrap().remaining += 1;
            assert!(ecx_protocol_core::ecx_order_index_v1::verify_ecx_post_liquidation_reserve_v1(
                prior.orders_root, next.orders_root, &[&maker, &taker], economics,
                &forged_remainder, admission_height, funding_low, funding_high, expected_index).is_err());
        } else {
            assert!(result.orders[0].1.is_none());
        }
        assert_eq!(result.target_position, finalized);
        assert_eq!(result.target_cash, staged.target_cash);
        assert_eq!(result.insurance_cash, staged.insurance_cash);
        assert!(result.insurance_cover_atoms > 0);
        assert_eq!(next.matcher_sequence, prior.matcher_sequence);
        use ecx_protocol_core::codec::CanonicalEncode;
        use ecx_proof_core::{ecx_liquidation_input_v1::EcxLiquidationInputV1,
            ecx_match_input_v1::EcxOwnedAccountV1};
        let account = |position: &TraderLeafV2, cash: &EcxCashAccountV1, path: &[Hash32]|
            EcxOwnedAccountV1 { position: position.clone(), cash_bytes: cash.canonical_bytes(),
                siblings: path.to_vec() };
        let owned = EcxLiquidationInputV1 {
            expected_state: prior.digest().unwrap(), state_bytes: prior.encode().unwrap(),
            bindings, economics, configuration: configuration.clone(), truthcoin: truthcoin.clone(),
            ecx_btc: ecx_btc.clone(), usdd_usd: usdd_usd.clone(), funding: previous.clone(),
            target: account(&taker_position, &empty, &target_path),
            makers: vec![account(&maker_position, &credited_cash, &maker_path)],
            clearing: account(&clearing, &cash, &clearing_path),
            insurance: account(&insurance, &insured, &insurance_path),
            orders: vec![(maker.clone(), mop.clone())], source_orders: vec![maker.clone(), taker.clone()],
            fills: vec![(mid, liquidation_quantity)], source_outpoint_bytes: elements::encode::serialize(&outpoint),
            source_transaction_bytes: elements::encode::serialize(&source_tx),
            successor_transaction_bytes: elements::encode::serialize(&successor_tx),
            successor_vout: 0, successor_script_sha256: vault_script_hash,
            prior_accounts: liquidation_ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
            successor_accounts: next_ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
        };
        let bytes = owned.encode().unwrap();
        let decoded = EcxLiquidationInputV1::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.execute(verifier).unwrap().0, next);
        assert!(decoded.execute(&DenyAllConsensusProofs).is_err());
        for bytes in [bytes[..bytes.len()-1].to_vec(), [bytes.as_slice(), &[0]].concat(),
            [b"ECXAD1".as_slice(), &bytes[6..]].concat()] {
            assert!(EcxLiquidationInputV1::decode(&bytes).is_err());
        }
        for mutation in 0..6 {
            let mut bad = decoded.clone();
            match mutation {
                0 => bad.expected_state[0] ^= 1,
                1 => bad.target.cash_bytes.clear(),
                2 => bad.source_orders.clear(),
                3 => bad.makers.clear(),
                4 => bad.successor_accounts = bad.prior_accounts.clone(),
                _ => bad.orders[0].1[0][0] ^= 1,
            }
            assert!(bad.execute(verifier).is_err(), "owned liquidation mutation {mutation}");
        }
        consume_liquidation(&LiquidationFixture {
            owned: &decoded,
            prior: &prior, next: &next, bindings, economics, funding: &previous,
            target: EcxAccountOpeningV1 { position: &taker_position, cash: &empty, siblings: &target_path },
            makers: &[EcxAccountOpeningV1 { position: &maker_position, cash: &credited_cash, siblings: &maker_path }],
            clearing: EcxAccountOpeningV1 { position: &clearing, cash: &cash, siblings: &clearing_path },
            insurance: EcxAccountOpeningV1 { position: &insurance, cash: &insured, siblings: &insurance_path },
            orders: &[(&maker, &mop)], source_orders: &[&maker, &taker],
            fills: &[(mid, liquidation_quantity)], vault: &liquidation_vault,
        });
        let mut wrong_ledger = liquidation_vault;
        wrong_ledger.successor_accounts = &liquidation_ledger;
        assert!(run_liquidation(&wrong_ledger).is_err());
        let mut missing_backing = successor_tx.clone();
        missing_backing.output[0].value = elements::confidential::Value::Explicit(backing - 1);
        let mut wrong_vault = liquidation_vault;
        wrong_vault.successor_transaction = &missing_backing;
        assert!(run_liquidation(&wrong_vault).is_err());
      }
    }
    // Admission is a separate branch from this same funded predecessor.
    // Oracle receipts are synthetic here; owner and matcher signatures are real.
    {
        let mut prior_state = prior_state.clone();
        prior_state.sidechain_height = admission_height;
        let state_digest = prior_state.digest().unwrap();
        use ecx_proof_core::ecx_execution_v1::{prepare_ecx_oracle_admission_v1,
            verify_ecx_oracle_admission_v1};
        let mut order = maker.signed.order.clone();
        order.nonce = maker_position.account_nonce;
        order.client_order_id = [42; 16];
        let signed = SignedEcxOrderV1::sign(domain, order, &secret(7)).unwrap();
        let new_id = signed.order_id().unwrap();
        let entries = vec![(mid, order_leaf(domain, mid, Some(&maker)).unwrap()),
            (tid, order_leaf(domain, tid, Some(&taker)).unwrap()),
            (new_id, order_leaf(domain, new_id, None).unwrap())];
        let mut absence = Vec::new();
        assert_eq!(tree(&entries, 0, signed.order_id().unwrap(), &mut absence, tag), orders_root);
        let opening = || EcxAccountOpeningV1 { position: &maker_position,
            cash: &credited_cash, siblings: &mp };
        let (prepared, funding, low, high) = prepare_ecx_oracle_admission_v1(
            state_digest, &prior_state, outpoint, bindings, economics, configuration,
            truthcoin, ecx_btc, usdd_usd, verifier, &previous, &vault_witness).unwrap();
        let (update, execution) = prepared.order_admission_execution(prepared.digest().unwrap(),
            bindings, economics, signed.clone(), opening(), &absence,
            &[&maker, &taker], low, high).unwrap();
        let admission_receipt = EcxMatcherExecutionReceiptV1::sign(economics, &matcher,
            9, matcher.genesis_receipt_hash, execution, &secret(11)).unwrap();
        let mut next_ledger = ledger;
        next_ledger[0].0 = &update.position;
        let mut admission_vault = vault_witness;
        admission_vault.successor_accounts = &next_ledger;
        let execute = |receipt: &EcxMatcherExecutionReceiptV1, vault: &_| {
            verify_ecx_oracle_admission_v1(state_digest, &prior_state, outpoint,
                bindings, economics, configuration, truthcoin, ecx_btc, usdd_usd,
                verifier, &previous, &matcher, receipt, signed.clone(), opening(),
                &absence, &[&maker, &taker], vault)
        };
        let (next, actual_funding) = execute(&admission_receipt, &admission_vault).unwrap();
        assert_eq!(next.accounts_root, update.accounts_root);
        assert_eq!(next.orders_root, update.orders_root);
        assert_eq!(next.matcher_sequence, 9);
        assert_eq!(next.controlled_ecx_atoms, backing);
        assert_eq!(actual_funding.root(), funding.root());
        use ecx_protocol_core::codec::CanonicalEncode;
        use ecx_proof_core::{ecx_admission_input_v1::EcxAdmissionInputV1,
            ecx_match_input_v1::EcxOwnedAccountV1};
        let owned = EcxAdmissionInputV1 {
            expected_state: state_digest, state_bytes: prior_state.encode().unwrap(),
            bindings, economics, configuration: configuration.clone(), truthcoin: truthcoin.clone(),
            ecx_btc: ecx_btc.clone(), usdd_usd: usdd_usd.clone(), funding: previous.clone(),
            signed: signed.clone(), matcher: matcher.clone(), receipt: admission_receipt.clone(),
            absence_siblings: absence.clone(),
            account: EcxOwnedAccountV1 { position: maker_position.clone(),
                cash_bytes: credited_cash.canonical_bytes(), siblings: mp.clone() },
            orders: vec![maker.clone(), taker.clone()],
            source_outpoint_bytes: elements::encode::serialize(&outpoint),
            source_transaction_bytes: elements::encode::serialize(&source_tx),
            successor_transaction_bytes: elements::encode::serialize(&successor_tx),
            successor_vout: 0, successor_script_sha256: vault_script_hash,
            prior_accounts: ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
            successor_accounts: next_ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
        };
        let bytes = owned.encode().unwrap();
        let decoded = EcxAdmissionInputV1::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.execute(verifier).unwrap(), (next.clone(), actual_funding));
        consume_admission(&decoded);
        assert!(decoded.execute(&DenyAllConsensusProofs).is_err());
        for mutant in [bytes[..bytes.len()-1].to_vec(), [bytes.as_slice(), &[0]].concat(),
            [b"ECXWI2".as_slice(), &bytes[6..]].concat()] {
            assert!(EcxAdmissionInputV1::decode(&mutant).is_err());
        }
        let mut bad = decoded.clone();
        bad.expected_state[0] ^= 1;
        assert!(bad.execute(verifier).is_err());
        let mut bad = decoded.clone();
        bad.orders.pop();
        assert!(bad.execute(verifier).is_err());
        let mut bad = decoded;
        bad.account.cash_bytes.clear();
        assert!(bad.execute(verifier).is_err());
        let mut bad_receipt = admission_receipt.clone();
        bad_receipt.signature.0[0] ^= 1;
        assert!(execute(&bad_receipt, &admission_vault).is_err());
        admission_vault.successor_accounts = &ledger;
        assert!(execute(&admission_receipt, &admission_vault).is_err());
    }
    prior_state.verify_vault(state_digest, bindings, economics, &ledger,
        &source_tx.output[0]).unwrap();
    let mut substituted_state = prior_state.clone();
    substituted_state.controlled_ecx_atoms += 1;
    assert!(substituted_state.verify_vault(state_digest, bindings, economics,
        &ledger, &source_tx.output[0]).is_err());
    // Even a coherently changed expected state cannot manufacture backing.
    assert!(substituted_state.verify_vault(substituted_state.digest().unwrap(),
        bindings, economics, &ledger, &source_tx.output[0]).is_err());
    assert!(prior_state.verify_vault(state_digest, bindings, economics,
        &ledger[..ledger.len() - 1], &source_tx.output[0]).is_err());
    let prior_commitment = prior_state.match_opening(state_digest, bindings,
        &previous, outpoint, vault_script_hash).unwrap();
    let mut wrong_funding = previous.clone();
    wrong_funding.last_parent_mtp ^= 1;
    assert!(prior_state.match_opening(state_digest, bindings, &wrong_funding,
        outpoint, vault_script_hash).is_err());
    let mut wrong_state = prior_state.clone();
    wrong_state.accounts_root[0] ^= 1;
    assert!(wrong_state.match_opening(state_digest, bindings, &previous,
        outpoint, vault_script_hash).is_err());
    // Independently assemble the preimage: consensus outpoints use raw txid
    // bytes and little-endian vout, not the display-hex transaction ID.
    use elements::hashes::Hash as _;
    use sha2::Digest as _;
    let mut preimage = sha2::Sha256::digest(b"ECX/match-prior-opening/v2").to_vec();
    preimage.extend_from_slice(&bindings.digest().unwrap());
    preimage.extend_from_slice(&previous.root());
    preimage.extend_from_slice(&0i128.to_be_bytes());
    preimage.extend_from_slice(&prior_oi.to_be_bytes());
    preimage.extend_from_slice(&accounts_root);
    preimage.extend_from_slice(&orders_root);
    preimage.extend_from_slice(&8u128.to_be_bytes());
    preimage.extend_from_slice(&matcher.genesis_receipt_hash);
    preimage.extend_from_slice(&2u64.to_be_bytes());
    preimage.extend_from_slice(&parent.block_hash);
    preimage.extend_from_slice(&parent.height.to_be_bytes());
    preimage.extend_from_slice(&parent.median_time_past.to_be_bytes());
    preimage.extend_from_slice(&outpoint.txid.to_byte_array());
    preimage.extend_from_slice(&outpoint.vout.to_le_bytes());
    preimage.extend_from_slice(&vault_script_hash);
    preimage.extend_from_slice(&vault_script_hash);
    let independent: Hash32 = sha2::Sha256::digest(&preimage).into();
    assert_eq!(prior_commitment, independent);
    // Freeze the expected predecessor once; never recompute it from a
    // mutated witness. Each committed opening must fail at the boundary.
    for field in 0..16 {
        let mut selected_vault = vault_witness;
        let mut b = bindings;
        let mut funding = previous.clone();
        let mut index = 0;
        let mut oi = prior_oi;
        let mut accounts = accounts_root;
        let mut orders = orders_root;
        let mut cursor = (8, matcher.genesis_receipt_hash);
        let mut height = 2;
        let mut selected_parent = parent;
        match field {
            0 => b.oracle_configuration_hash[0] ^= 1,
            1 => funding.last_parent_mtp ^= 1,
            2 => index = 1,
            3 => oi = 1,
            4 => accounts[0] ^= 1,
            5 => orders[0] ^= 1,
            6 => cursor.0 = 2,
            7 => cursor.1[0] ^= 1,
            8 => height = 3,
            9 => selected_parent.block_hash[0] ^= 1,
            10 => selected_parent.height ^= 1,
            11 => selected_parent.median_time_past ^= 1,
            12 => selected_vault.source_outpoint.vout ^= 1,
            13 => selected_vault.source_outpoint.txid = successor_tx.txid(),
            14 => selected_vault.source_script_sha256[0] ^= 1,
            15 => selected_vault.successor_script_sha256[0] ^= 1,
            _ => unreachable!(),
        }
        let (m, t, c, f) = openings();
        let rejected = verify_ecx_oracle_match_v1(
            prior_commitment, &selected_vault, b, economics, configuration, selected_parent,
            truthcoin, ecx_btc, usdd_usd, verifier, &funding, index, oi,
            accounts, orders, &matcher, cursor, &receipt, m, t, c, height,
            QUANTITY, Some(f), &[&maker, &taker],
        );
        assert!(matches!(rejected,
            Err(ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
                "ECX match prior opening"
            ))
        ), "prior opening field {field} escaped commitment check");
    }
    macro_rules! run {
        ($b:expr, $p:expr, $proof:expr, $v:expr, $index:expr, $root:expr, $cursor:expr, $r:expr, $qty:expr, $fees:expr) => {{
            let (m, t, c, f) = openings();
            verify_ecx_oracle_match_v1(
                prior_commitment,
                &vault_witness,
                $b,
                economics,
                configuration,
                $p,
                $proof,
                ecx_btc,
                usdd_usd,
                $v,
                &previous,
                $index,
                prior_oi,
                $root,
                orders_root,
                &matcher,
                $cursor,
                $r,
                m,
                t,
                c,
                2,
                $qty,
                if $fees { Some(f) } else { None },
                &[&maker, &taker],
            )
        }};
    }
    let cursor = (8, matcher.genesis_receipt_hash);
    let result = run!(
        bindings,
        parent,
        truthcoin,
        verifier,
        0,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY,
        true
    )
    .unwrap();
    assert_eq!(result.execution, expected_execution);
    {
        use ecx_protocol_core::codec::CanonicalEncode;
        use ecx_proof_core::ecx_match_input_v1::*;
        let owned_account = |a: EcxAccountOpeningV1<'_>| EcxOwnedAccountV1 {
            position: a.position.clone(), cash_bytes: a.cash.canonical_bytes(),
            siblings: a.siblings.to_vec(),
        };
        let owned_order = |o: EcxIndexedOrderOpeningV1<'_>| EcxOwnedOrderV1 {
            order: o.order.clone(), account: owned_account(o.account),
            siblings: o.order_siblings.to_vec(),
        };
        let (m, t, c, f) = openings();
        let input = EcxMatchInputV1 {
            source_orders: vec![maker.clone(), taker.clone()],
            expected_state: state_digest, state_bytes: prior_state.encode().unwrap(),
            bindings, economics, configuration: configuration.clone(),
            truthcoin: truthcoin.clone(), ecx_btc: ecx_btc.clone(), usdd_usd: usdd_usd.clone(),
            funding: previous.clone(), matcher: matcher.clone(), receipt: receipt.clone(),
            maker: owned_order(m), taker: owned_order(t), clearing: owned_account(c),
            fees: Some(EcxOwnedFeesV1 { insurance: owned_account(f.insurance),
                maker_siblings: f.maker_siblings.to_vec(), taker_siblings: f.taker_siblings.to_vec(),
                final_insurance_siblings: f.final_insurance_siblings.to_vec() }),
            quantity: QUANTITY,
            source_outpoint_bytes: elements::encode::serialize(&vault_witness.source_outpoint),
            source_transaction_bytes: elements::encode::serialize(vault_witness.source_transaction),
            successor_transaction_bytes: elements::encode::serialize(vault_witness.successor_transaction),
            successor_vout: vault_witness.successor_vout,
            successor_script_sha256: vault_witness.successor_script_sha256,
            prior_accounts: ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
            successor_accounts: expected_ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
        };
        let bytes = input.encode().unwrap();
        let decoded = EcxMatchInputV1::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.execute(verifier).unwrap().next_state, result.next_state);
        let mut legacy = bytes.clone();
        legacy[..6].copy_from_slice(b"ECXMI1");
        assert!(EcxMatchInputV1::decode(&legacy).is_err());
        legacy[..6].copy_from_slice(b"ECXMI2");
        assert!(EcxMatchInputV1::decode(&legacy).is_err());
        for mutation in 0..3 {
            let mut bad = decoded.clone();
            match mutation {
                0 => { bad.source_orders.pop(); },
                1 => { bad.source_orders.push(bad.source_orders[0].clone()); },
                _ => { bad.source_orders.clear(); },
            }
            // Decode is not validation: execute must reject the substituted
            // book even though maker/taker membership proofs remain intact.
            let encoded = bad.encode().unwrap();
            assert!(EcxMatchInputV1::decode(&encoded).unwrap().execute(verifier).is_err());
        }
        let mut expected_journal = b"ECXMJ1".to_vec();
        expected_journal.extend_from_slice(&state_digest);
        expected_journal.extend_from_slice(&elements::encode::serialize(&vault_witness.source_outpoint));
        expected_journal.extend_from_slice(&result.next_state.encode().unwrap());
        assert_eq!(expected_journal.len(), 384);
        assert_eq!(decoded.execute_journal(verifier).unwrap(), expected_journal);
        // Transcript-only consumer test: the journal was produced by the
        // real local relation above, but this is not an SP1 receipt.
        struct ExactMatchReceipt<'a>(Hash32, &'a [u8]);
        impl ConsensusProofVerifier for ExactMatchReceipt<'_> {
            fn verify(&self, program: Hash32, journal: &[u8], proof: &[u8])
                -> Result<(), ecx_truthcoin_proof::ConsensusProofVerificationError> {
                if program == self.0 && journal == self.1 && proof == b"fixture-match-receipt" {
                    Ok(())
                } else { Err(ecx_truthcoin_proof::ConsensusProofVerificationError) }
            }
        }
        let receipt_verifier = ExactMatchReceipt(bindings.account_execution_program_id, &expected_journal);
        let consume = |journal: &[u8], proof: &[u8], state, outpoint, selected_bindings| {
            EcxMatchJournalV1::verify_receipt(journal, proof, &receipt_verifier,
                state, &prior_state, outpoint, selected_bindings)
        };
        let verified = consume(&expected_journal, b"fixture-match-receipt", state_digest,
            vault_witness.source_outpoint, bindings).unwrap();
        assert_eq!(verified.next_state, result.next_state);
        assert!(consume(&expected_journal, b"wrong", state_digest,
            vault_witness.source_outpoint, bindings).is_err());
        assert!(EcxMatchJournalV1::verify_receipt(&expected_journal, b"fixture-match-receipt",
            &DenyAllConsensusProofs, state_digest, &prior_state,
            vault_witness.source_outpoint, bindings).is_err());
        let mut changed_outpoint = vault_witness.source_outpoint;
        changed_outpoint.vout += 1;
        assert!(consume(&expected_journal, b"fixture-match-receipt", state_digest,
            changed_outpoint, bindings).is_err());
        let mut changed_state = state_digest;
        changed_state[0] ^= 1;
        assert!(consume(&expected_journal, b"fixture-match-receipt", changed_state,
            vault_witness.source_outpoint, bindings).is_err());
        let mut changed_bindings = bindings;
        changed_bindings.account_execution_program_id = bindings.funding_oracle_program_id;
        assert!(consume(&expected_journal, b"fixture-match-receipt", state_digest,
            vault_witness.source_outpoint, changed_bindings).is_err());
        for offset in 0..expected_journal.len() {
            let mut changed = expected_journal.clone();
            changed[offset] ^= 1;
            assert!(consume(&changed, b"fixture-match-receipt", state_digest,
                vault_witness.source_outpoint, bindings).is_err());
            assert!(EcxMatchJournalV1::decode(&expected_journal[..offset]).is_err());
        }
        let mut trailing = expected_journal.clone();
        trailing.push(0);
        assert!(EcxMatchJournalV1::decode(&trailing).is_err());
        assert!(decoded.execute_journal(&DenyAllConsensusProofs).is_err());
        assert!(decoded.execute(&DenyAllConsensusProofs).is_err());
        let mut bad = bytes.clone();
        bad[5] = b'4';
        assert!(EcxMatchInputV1::decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(EcxMatchInputV1::decode(&bad).is_err());
        assert!(EcxMatchInputV1::decode(&bytes[..bytes.len()-1]).is_err());
        let mut bad = input.clone();
        bad.maker.account.cash_bytes.push(0);
        assert!(bad.execute(verifier).is_err());
        let mut bad = input;
        bad.expected_state[0] ^= 1;
        assert!(bad.execute(verifier).is_err());
    }
    // The state-consuming boundary must reproduce the checked match and
    // reject a coherent but unbacked state, not only malformed hashes.
    for mutation in 0..4 {
        let mut selected = prior_state.clone();
        let mut selected_digest = state_digest;
        match mutation {
            1 => selected.accounts_root[0] ^= 1,
            2 => {
                selected.controlled_ecx_atoms += 1;
                selected_digest = selected.digest().unwrap();
            },
            3 => {
                selected.vault_script_sha256[0] ^= 1;
                selected_digest = selected.digest().unwrap();
            },
            _ => {},
        }
        let (m, t, c, f) = openings();
        let committed = ecx_proof_core::ecx_execution_v1::verify_ecx_committed_match_v1(
            selected_digest, &selected, &vault_witness, bindings, economics,
            configuration, truthcoin, ecx_btc, usdd_usd, verifier, &previous,
            &matcher, &receipt, m, t, c, QUANTITY, Some(f), &[&maker, &taker]);
        if mutation == 0 {
            let committed = committed.unwrap();
            assert_eq!(committed.next_state, result.next_state);
            assert_eq!(committed.execution, result.execution);
        } else {
            let expected_error = if mutation == 1 {
                "ECX match committed state"
            } else {
                "ECX committed match vault"
            };
            assert!(matches!(committed,
                Err(ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(message))
                    if message == expected_error), "committed state mutation {mutation}");
        }
    }
    // Exercise the mandatory checks through the match entrypoint itself.
    for stale_ledger in [false, true] {
        let mut bad_vault = vault_witness;
        if stale_ledger {
            bad_vault.successor_accounts = &ledger;
        } else {
            bad_vault.successor_script_sha256[0] ^= 1;
        }
        let (m, t, c, f) = openings();
        assert!(verify_ecx_oracle_match_v1(
            prior_commitment, &bad_vault, bindings, economics, configuration, parent,
            truthcoin, ecx_btc, usdd_usd, verifier, &previous, 0, prior_oi,
            accounts_root, orders_root, &matcher, cursor, &receipt, m, t, c, 2,
            QUANTITY, Some(f), &[&maker, &taker],
        ).is_err());
    }
    assert_eq!(result.execution.accounts.root, expected_accounts);
    assert_eq!(result.execution.orders_root, expected_orders);
    assert_eq!(result.source, source);
    assert_eq!(result.funding_index, expected_index);
    assert_eq!(result.matcher_receipt_hash, receipt.digest());
    assert_eq!(result.execution.accounts.trade.maker_cash, maker_paid);
    assert_eq!(result.execution.accounts.trade.taker_cash, taker_paid);
    assert_eq!(
        result.execution.insurance_cash,
        Some(insurance_paid.clone())
    );
    let post_trade = &result.execution.accounts.trade;
    if !close {
        // Sequential arithmetic continuation, not a second authenticated
        // oracle receipt: consume the actual opening result, admit fresh
        // opposing orders, settle funding and close both positions.
        let closing_price = Price::new(mark.get().checked_add(1).unwrap()).unwrap();
        let closing_funding = expected_index.checked_add(1).unwrap();
        let admit_close = |p: &TraderLeafV2, byte, side| {
            let signed = SignedEcxOrderV1::sign(domain, SuccessorLimitOrderV2 {
                version: 2, chain_id: domain.chain_id, market: domain.market,
                trader: p.trader, side, time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::from_bits(0).unwrap(), limit_price: closing_price,
                quantity: Quantity::new(QUANTITY).unwrap(), client_order_id: [1;16],
                max_fee_bps: 5, nonce: p.account_nonce,
                valid_from_height: 3, expires_at_height: 100,
            }, &secret(byte)).unwrap();
            let admitted = EcxAdmittedOrderV2::admit(signed.clone(), domain, p, 3, bounds, 1).unwrap();
            assert!(EcxAdmittedOrderV2::admit(signed, domain, &admitted.1, 3, bounds, 1).is_err());
            admitted
        };
        let (close_maker, next_maker) = admit_close(&post_trade.maker_position, 7, Side::Sell);
        let (close_taker, next_taker) = admit_close(&post_trade.taker_position, 8, Side::Buy);
        let closed = stage_ecx_match(domain, &close_maker, &close_taker,
            &next_maker, &next_taker, &post_trade.maker_cash, &post_trade.taker_cash,
            economics.clearing_account, &post_trade.clearing_cash, 3, QUANTITY,
            closing_price, closing_funding, bounds).unwrap();
        assert_eq!(closed.maker_position.position_size_atoms, 0);
        assert_eq!(closed.taker_position.position_size_atoms, 0);
        assert_eq!(closed.maker_position.signed_cost_basis_numerator, Int256V2::ZERO);
        assert_eq!(closed.taker_position.signed_cost_basis_numerator, Int256V2::ZERO);
        // Flat leaves canonically reset their funding index. Independently
        // calculate the liability so normalization cannot hide skipped funding.
        assert_eq!(closed.maker_position.last_funding_index_numerator, 0);
        assert_eq!(closed.taker_position.last_funding_index_numerator, 0);
        let liability = |p: &TraderLeafV2| {
            let realized = Int256V2::checked_product_i64_i128(
                p.position_size_atoms, i128::from(closing_price.get())).unwrap()
                .checked_mul_u64(ecx_protocol_core::incremental_state_v2::FUNDING_INDEX_DENOMINATOR_V2).unwrap()
                .checked_sub(p.signed_cost_basis_numerator).unwrap();
            let funding = Int256V2::checked_product_i64_i128(p.position_size_atoms,
                closing_funding - p.last_funding_index_numerator).unwrap();
            assert_ne!(funding, Int256V2::ZERO);
            realized.checked_sub(funding).unwrap()
        };
        let (expected_maker, intermediate_clearing) =
            ecx_protocol_core::ecx_cash_account_v1::settle_account_pnl(
                &post_trade.maker_cash, &post_trade.clearing_cash,
                liability(&next_maker), closing_price).unwrap();
        let (expected_taker, expected_clearing) =
            ecx_protocol_core::ecx_cash_account_v1::settle_account_pnl(
                &post_trade.taker_cash, &intermediate_clearing,
                liability(&next_taker), closing_price).unwrap();
        assert_eq!(closed.maker_cash, expected_maker);
        assert_eq!(closed.taker_cash, expected_taker);
        assert_eq!(closed.clearing_cash, expected_clearing);
        assert!(closed.maker_order.is_none() && closed.taker_order.is_none());
        let (closed_maker_cash, intermediate_reserve) = settle_ecx_execution_fee(
            &closed.maker_cash, &insurance_paid, closing_price,
            Quantity::new(QUANTITY).unwrap(), 0, 5, closing_price).unwrap();
        let (closed_taker_cash, closed_reserve) = settle_ecx_execution_fee(
            &closed.taker_cash, &intermediate_reserve, closing_price,
            Quantity::new(QUANTITY).unwrap(), 5, 5, closing_price).unwrap();
        let closed_ledger = [(&closed.maker_position, &closed_maker_cash),
            (&closed.taker_position, &closed_taker_cash),
            (&clearing, &closed.clearing_cash), (&insurance, &closed_reserve)];
        let closed_leaves: Vec<_> = closed_ledger.iter().map(|(p,c)| leaf(p,c)).collect();
        let (closed_root, _) = account_path(&closed_leaves, closed.maker_position.key());
        ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
            closed_root, vault_script_hash, domain, bounds, &closed_ledger,
            &vault(trading_backing)).unwrap();
        assert_ne!(closed_root, result.execution.accounts.root);
        // Continue the same account state through signed withdrawal. The
        // closing transaction spends the opening vault, and withdrawal spends
        // that exact closing output, not an independently supplied balance.
        let close_tx = elements::Transaction {
            version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint { txid: successor_tx.txid(), vout: 0 },
                ..Default::default()
            }], output: vec![vault(trading_backing)],
        };
        ecx_proof_core::ecx_execution_v1::ecx_trading_vault_outputs_v1(
            close_tx.input[0].previous_output, &successor_tx, &close_tx, 0).unwrap();
        let mut recipient = vault(1);
        recipient.script_pubkey = elements::Script::from(vec![0x52]);
        let signed = ecx_protocol_core::ecx_withdrawal_v1::SignedEcxWithdrawalV1::sign(
            domain, ecx_protocol_core::successor_action_v2::SuccessorWithdrawalRequestV2 {
                version: 2, chain_id: domain.chain_id, trader: closed.maker_position.trader,
                nonce: closed.maker_position.account_nonce, amount: 1,
                destination_script_hash: <sha2::Sha256 as sha2::Digest>::digest(
                    recipient.script_pubkey.as_bytes()).into(),
                requested_height: 3, not_before_height: 147,
            }, &secret(7)).unwrap();
        let (_, path) = account_path(&closed_leaves, closed.maker_position.key());
        let opening = || EcxAccountOpeningV1 { position: &closed.maker_position,
            cash: &closed_maker_cash, siblings: &path };
        let update = ecx_protocol_core::ecx_withdrawal_v1::stage_ecx_withdrawal_account_v1(
            closed_root, economics, &signed, opening(), 147,
            closing_price, closing_price, closing_funding,
            ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root: expected_orders, records: &[] }).unwrap();
        let final_ledger = [(&update.position, &update.cash),
            (&closed.taker_position, &closed_taker_cash),
            (&clearing, &closed.clearing_cash), (&insurance, &closed_reserve)];
        let final_leaves: Vec<_> = final_ledger.iter().map(|(p,c)| leaf(p,c)).collect();
        assert_eq!(update.accounts_root, account_path(&final_leaves, update.position.key()).0);
        let withdrawal_tx = elements::Transaction {
            version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint { txid: close_tx.txid(), vout: 0 },
                ..Default::default()
            }], output: vec![vault(trading_backing - 1), recipient],
        };
        let witness = ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1 {
            source_outpoint: withdrawal_tx.input[0].previous_output,
            source_transaction: &close_tx, successor_transaction: &withdrawal_tx,
            successor_vout: 0, source_script_sha256: vault_script_hash,
            successor_script_sha256: vault_script_hash,
            prior_accounts: &closed_ledger, successor_accounts: &final_ledger,
        };
        let verify = |root, height, witness: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>| {
            ecx_proof_core::ecx_execution_v1::verify_ecx_account_withdrawal_v1(
                root, economics, &signed, opening(), height,
                closing_price, closing_price, closing_funding, witness, 1,
                ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root: expected_orders, records: &[] })
        };
        assert_eq!(verify(closed_root, 147, &witness).unwrap(), update);
        // A caller cannot omit the book merely because the physical debit,
        // signature and vault ledger are otherwise valid.
        assert!(ecx_proof_core::ecx_execution_v1::verify_ecx_account_withdrawal_v1(
            closed_root, economics, &signed, opening(), 147,
            closing_price, closing_price, closing_funding, &witness, 1,
            ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 {
                root: orders_root, records: &[],
            }).is_err());
        // Attack the combined signed-debit/ledger/physical relation after the
        // same funded position has closed, not just the output helper. Equal
        // nominal amounts in a different asset are not ECX backing or payout.
        for mutation in 0..8 {
            let mut tx = withdrawal_tx.clone();
            let mut altered = witness;
            match mutation {
                0 | 1 => {
                    let mut asset = domain.collateral_asset;
                    asset[0] ^= 1;
                    tx.output[mutation].asset = elements::confidential::Asset::Explicit(
                        elements::AssetId::from_byte_array(asset));
                }
                2 => tx.output[1].script_pubkey = elements::Script::from(vec![0x53]),
                3 => tx.input.push(tx.input[0].clone()),
                4 => tx.output[0].value = elements::confidential::Value::Explicit(trading_backing),
                5 => tx.output[1].value = elements::confidential::Value::Explicit(2),
                6 => altered.successor_accounts = &closed_ledger,
                _ => tx.output[0].script_pubkey = elements::Script::from(vec![0x53]),
            }
            altered.successor_transaction = &tx;
            assert!(verify(closed_root, 147, &altered).is_err(),
                "sequential ECX withdrawal mutation {mutation}");
        }
        assert!(verify(result.execution.accounts.root, 147, &witness).is_err());
        assert!(verify(update.accounts_root, 147, &witness).is_err());
        assert!(verify(closed_root, 146, &witness).is_err());
        let mut stale_source = witness;
        stale_source.source_transaction = &successor_tx;
        assert!(verify(closed_root, 147, &stale_source).is_err());
        // A fresh admitted order cannot be executed against the old account
        // nonce, even when the owner and economic domain are unchanged.
        assert!(stage_ecx_match(domain, &close_maker, &close_taker,
            &post_trade.maker_position, &next_taker,
            &post_trade.maker_cash, &post_trade.taker_cash,
            economics.clearing_account, &post_trade.clearing_cash,
            3, QUANTITY, closing_price, closing_funding, bounds).is_err());
    }
    let post_ledger = [
        (&post_trade.maker_position, &post_trade.maker_cash),
        (&post_trade.taker_position, &post_trade.taker_cash),
        (&clearing, &post_trade.clearing_cash),
        (&insurance, &insurance_paid),
    ];
    let verify_post = |root, entries: &[(&TraderLeafV2, &EcxCashAccountV1)], amount| {
        ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
            root, vault_script_hash, domain, bounds, entries, &vault(amount),
        )
    };
    verify_post(result.execution.accounts.root, &post_ledger, trading_backing).unwrap();
    // Bind both ledger checks to the outputs of the actual local transaction
    // relation, rather than independently supplied equal-sized vaults.
    let (before, after) = ecx_proof_core::ecx_execution_v1::ecx_trading_vault_outputs_v1(
        outpoint, &source_tx, &successor_tx, 0,
    ).unwrap();
    ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
        accounts_root, vault_script_hash, domain, bounds, &ledger, before,
    ).unwrap();
    ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
        result.execution.accounts.root, vault_script_hash, domain, bounds, &post_ledger, after,
    ).unwrap();
    for mutation in 0..7 {
        let mut src = source_tx.clone();
        let mut next = successor_tx.clone();
        let mut vout = 0;
        match mutation {
            0 => src.version += 1,
            1 => next.input.clear(),
            2 => next.input.push(next.input[0].clone()),
            3 => next.input[0].previous_output.vout = 1,
            4 => next.input[0].is_pegin = true,
            5 => next.output[0].value = elements::confidential::Value::Explicit(4 * BALANCE - 1),
            _ => vout = 1,
        }
        assert!(ecx_proof_core::ecx_execution_v1::ecx_trading_vault_outputs_v1(
            outpoint, &src, &next, vout,
        ).is_err(), "vault continuity mutation {mutation}");
    }
    // Conservation of an unbound list is insufficient: require the actual
    // recomputed post-fee root, not the predecessor or a selected subset.
    assert!(verify_post(accounts_root, &post_ledger, trading_backing).is_err());
    assert!(verify_post(result.execution.accounts.root, &post_ledger[..3], trading_backing).is_err());
    assert!(verify_post(result.execution.accounts.root, &post_ledger, trading_backing + 1).is_err());
    assert!(verify_post(result.execution.accounts.root, &post_ledger, 4 * BALANCE).is_err());
    // Join signed account staging to a physical withdrawal from the actual
    // post-trade vault. This synthetic relation is not chain spend authority.
    use ecx_protocol_core::ecx_withdrawal_v1::{
        SignedEcxWithdrawalV1, stage_ecx_withdrawal_account_v1,
    };
    let mut recipient = vault(1);
    recipient.script_pubkey = elements::Script::from(vec![0x52]);
    let recipient_hash = <sha2::Sha256 as sha2::Digest>::digest(recipient.script_pubkey.as_bytes()).into();
    let withdrawal = SignedEcxWithdrawalV1::sign(domain,
        ecx_protocol_core::successor_action_v2::SuccessorWithdrawalRequestV2 {
            version: 2, chain_id: domain.chain_id, trader: post_trade.maker_position.trader,
            nonce: post_trade.maker_position.account_nonce, amount: 1,
            destination_script_hash: recipient_hash, requested_height: 2, not_before_height: withdrawal_height,
        }, &secret(7)).unwrap();
    let withdrawal_leaves: Vec<_> = post_ledger.iter().map(|(p, c)| leaf(p, c)).collect();
    let (withdrawal_root, withdrawal_path) = account_path(&withdrawal_leaves, post_trade.maker_position.key());
    assert_eq!(withdrawal_root, result.execution.accounts.root);
    let stage = |root, position: &TraderLeafV2, cash: &EcxCashAccountV1, height| {
        stage_ecx_withdrawal_account_v1(root, economics, &withdrawal,
            EcxAccountOpeningV1 { position, cash, siblings: &withdrawal_path },
            height, low, high, expected_index,
            ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root: result.execution.orders_root, records: &[] })
    };
    assert!(stage(withdrawal_root, &post_trade.maker_position, &maker_paid, withdrawal_height - 1).is_err());
    assert!(stage(accounts_root, &post_trade.maker_position, &maker_paid, withdrawal_height).is_err());
    let update = stage(withdrawal_root, &post_trade.maker_position, &maker_paid, withdrawal_height).unwrap();
    let mut expected_position = post_trade.maker_position.clone();
    expected_position.account_nonce += 1;
    assert_eq!(update.position, expected_position);
    let mut expected_leaves = withdrawal_leaves;
    expected_leaves[0] = leaf(&expected_position, &update.cash);
    assert_eq!(update.accounts_root, account_path(&expected_leaves, expected_position.key()).0);
    assert!(stage(update.accounts_root, &update.position, &update.cash, withdrawal_height).is_err());
    let withdrawal_outpoint = elements::OutPoint { txid: successor_tx.txid(), vout: 0 };
    let withdrawal_tx = elements::Transaction {
        version: 2, lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn { previous_output: withdrawal_outpoint, ..Default::default() }],
        output: vec![vault(trading_backing - 1), recipient],
    };
    let physical = |src: &elements::Transaction, tx: &elements::Transaction, recipient_vout, amount| {
        ecx_proof_core::ecx_execution_v1::ecx_withdrawal_vault_outputs_v1(
            withdrawal_outpoint, src, tx, 0, recipient_vout, domain.collateral_asset,
            withdrawal.request.destination_script_hash, amount,
        ).map(|_| ())
    };
    physical(&successor_tx, &withdrawal_tx, 1, withdrawal.request.amount).unwrap();
    let final_ledger = [
        (&update.position, &update.cash),
        (&post_trade.taker_position, &post_trade.taker_cash),
        (&clearing, &post_trade.clearing_cash), (&insurance, &insurance_paid),
    ];
    let withdrawal_vault = ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1 {
        source_outpoint: withdrawal_outpoint, source_transaction: &successor_tx,
        successor_transaction: &withdrawal_tx, successor_vout: 0,
        source_script_sha256: vault_script_hash, successor_script_sha256: vault_script_hash,
        prior_accounts: &post_ledger, successor_accounts: &final_ledger,
    };
    let verify_withdrawal = |vault: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>| {
        ecx_proof_core::ecx_execution_v1::verify_ecx_account_withdrawal_v1(
            withdrawal_root, economics, &withdrawal,
            EcxAccountOpeningV1 { position: &post_trade.maker_position, cash: &maker_paid, siblings: &withdrawal_path },
            withdrawal_height, low, high, expected_index, vault, 1,
            ecx_protocol_core::ecx_withdrawal_v1::EcxWithdrawalOrdersV1 { root: result.execution.orders_root, records: &[] },
        )
    };
    assert_eq!(verify_withdrawal(&withdrawal_vault).unwrap(), update);
    // Reuse the verified match's oracle receipts, funding state and ledger.
    // The selected height is a prepared opening, not native inclusion evidence.
    let mut withdrawal_state = result.next_state.clone();
    withdrawal_state.sidechain_height = withdrawal_height;
    {
        let assess = |expected, funding: &FundingStateV2| {
            ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_target_margin_v1(
                expected, &withdrawal_state, withdrawal_outpoint, bindings, economics,
                configuration, truthcoin, ecx_btc, usdd_usd, verifier, funding,
                EcxAccountOpeningV1 { position: &post_trade.maker_position,
                    cash: &maker_paid, siblings: &withdrawal_path }, &withdrawal_vault)
        };
        let assessment = assess(withdrawal_state.digest().unwrap(), &result.funding_state);
        let assess_band = |expected, funding: &FundingStateV2| {
            ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_target_deficit_v1(
                expected, &withdrawal_state, withdrawal_outpoint, bindings, economics,
                configuration, truthcoin, ecx_btc, usdd_usd, verifier, funding,
                EcxAccountOpeningV1 { position: &post_trade.maker_position,
                    cash: &maker_paid, siblings: &withdrawal_path }, &withdrawal_vault)
        };
        let band_assessment = assess_band(withdrawal_state.digest().unwrap(), &result.funding_state);
        if post_trade.maker_position.position_size_atoms == 0 {
            assert!(assessment.is_err());
            assert!(band_assessment.is_err());
        } else {
            let (margin, source, funding, index) = assessment.unwrap();
            let (deficit, band_source, band_funding, band_index) = band_assessment.unwrap();
            assert_eq!(band_source, source);
            assert_eq!(band_funding, funding);
            assert_eq!(band_index, index);
            // A valid oracle and authenticated funded target are not permission
            // to liquidate. Reject before inspecting any proposed maker fills.
            assert!(!deficit, "this funded fixture must not prove interval deficit");
            let liquidation_tx = elements::Transaction {
                version: 2, lock_time: elements::LockTime::ZERO,
                input: vec![elements::TxIn { previous_output: withdrawal_outpoint,
                    ..Default::default() }],
                output: vec![vault(trading_backing)],
            };
            let liquidation_vault = ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1 {
                source_outpoint: withdrawal_outpoint, source_transaction: &successor_tx,
                successor_transaction: &liquidation_tx, successor_vout: 0,
                source_script_sha256: vault_script_hash, successor_script_sha256: vault_script_hash,
                prior_accounts: &post_ledger, successor_accounts: &post_ledger,
            };
            let rejected = ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_liquidation_batch_v1(
                withdrawal_state.digest().unwrap(), &withdrawal_state, withdrawal_outpoint,
                bindings, economics, configuration, truthcoin, ecx_btc, usdd_usd, verifier,
                &result.funding_state,
                EcxAccountOpeningV1 { position: &post_trade.maker_position,
                    cash: &maker_paid, siblings: &withdrawal_path }, &[],
                EcxAccountOpeningV1 { position: &clearing, cash: &post_trade.clearing_cash, siblings: &[] },
                EcxAccountOpeningV1 { position: &insurance, cash: &insurance_paid, siblings: &[] },
                &[], &[], &[], &liquidation_vault);
            assert!(matches!(rejected, Err(ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
                "ECX liquidation deficit not proven"))));
            assert_eq!(deficit, maker_paid.proves_deficit_over_interval(
                &post_trade.maker_position, economics.cash_valuation_scale,
                Price::new(source.liquidation_low_atoms).unwrap(),
                Price::new(source.liquidation_high_atoms).unwrap(), index,
                economics.risk.maintenance_margin_bps, economics.bounds).unwrap());
            assert_eq!(source, result.source);
            assert_eq!(index, expected_index);
            assert_eq!(funding.root(), result.funding_state.root());
            assert_eq!(margin, maker_paid.margin_at_mark(&post_trade.maker_position,
                economics.cash_valuation_scale, Price::new(source.mark_price_atoms).unwrap(),
                index, economics.risk.maintenance_margin_bps, economics.bounds).unwrap());
        }
        assert!(assess([0; 32], &result.funding_state).is_err());
        assert!(assess_band([0; 32], &result.funding_state).is_err());
        let mut wrong_funding = result.funding_state.clone();
        wrong_funding.last_parent_mtp += 1;
        assert!(assess(withdrawal_state.digest().unwrap(), &wrong_funding).is_err());
        assert!(assess_band(withdrawal_state.digest().unwrap(), &wrong_funding).is_err());
        assert!(ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_target_margin_v1(
            withdrawal_state.digest().unwrap(), &withdrawal_state, withdrawal_outpoint,
            bindings, economics, configuration, truthcoin, ecx_btc, usdd_usd,
            &DenyAllConsensusProofs, &result.funding_state,
            EcxAccountOpeningV1 { position: &post_trade.maker_position,
                cash: &maker_paid, siblings: &withdrawal_path }, &withdrawal_vault).is_err());
    }
    let verify_bound = |state: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        expected, source_outpoint, funding: &FundingStateV2| {
        ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_withdrawal_v1(
            expected, state, source_outpoint, bindings, economics, configuration,
            truthcoin, ecx_btc, usdd_usd, verifier, funding, &withdrawal,
            EcxAccountOpeningV1 { position: &post_trade.maker_position,
                cash: &maker_paid, siblings: &withdrawal_path },
            &withdrawal_vault, 1, &[])
    };
    let (bound_next, bound_funding) = verify_bound(&withdrawal_state,
        withdrawal_state.digest().unwrap(), withdrawal_outpoint, &result.funding_state).unwrap();
    let mut expected_state = withdrawal_state.clone();
    expected_state.accounts_root = update.accounts_root;
    expected_state.controlled_ecx_atoms -= 1;
    assert_eq!(bound_next, expected_state);
    assert_eq!(bound_funding.root(), result.funding_state.root());
    {
        use ecx_protocol_core::codec::CanonicalEncode;
        use ecx_proof_core::ecx_match_input_v1::{EcxOwnedAccountV1, EcxMatchInputV1};
        use ecx_proof_core::ecx_withdrawal_input_v1::EcxWithdrawalInputV1;
        let input = EcxWithdrawalInputV1 {
            expected_state: withdrawal_state.digest().unwrap(),
            state_bytes: withdrawal_state.encode().unwrap(), bindings, economics,
            configuration: configuration.clone(), truthcoin: truthcoin.clone(),
            ecx_btc: ecx_btc.clone(), usdd_usd: usdd_usd.clone(),
            funding: result.funding_state.clone(), signed: withdrawal.clone(),
            account: EcxOwnedAccountV1 { position: post_trade.maker_position.clone(),
                cash_bytes: maker_paid.canonical_bytes(), siblings: withdrawal_path.clone() },
            orders: vec![],
            source_outpoint_bytes: elements::encode::serialize(&withdrawal_outpoint),
            source_transaction_bytes: elements::encode::serialize(&successor_tx),
            successor_transaction_bytes: elements::encode::serialize(&withdrawal_tx),
            successor_vout: 0, recipient_vout: 1,
            successor_script_sha256: vault_script_hash,
            prior_accounts: post_ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
            successor_accounts: final_ledger.iter().map(|(p,c)| ((*p).clone(), c.canonical_bytes())).collect(),
        };
        let encoded = input.encode().unwrap();
        let decoded = EcxWithdrawalInputV1::decode(&encoded).unwrap();
        let mut legacy = encoded.clone();
        legacy[..6].copy_from_slice(b"ECXWI1");
        assert!(EcxWithdrawalInputV1::decode(&legacy).is_err());
        assert_eq!(decoded.encode().unwrap(), encoded);
        let (next, funding) = decoded.execute(verifier).unwrap();
        assert_eq!(next, bound_next);
        assert_eq!(funding, bound_funding);
        consume(&decoded);
        // The native consumer uses this borrowed boundary. Verify that it
        // receives the exact opening, not a separately reconstructed fixture,
        // and that its rejection cannot be swallowed by the transport.
        let mut calls = 0;
        let rejected: Result<(), ecx_proof_core::proof_v2::ProofErrorV2> =
            decoded.with_decoded_witness(|state, point, account, vault, orders| {
                calls += 1;
                assert_eq!(state, &withdrawal_state);
                assert_eq!(point, withdrawal_outpoint);
                assert_eq!(account.position, &post_trade.maker_position);
                assert_eq!(account.cash, &maker_paid);
                assert_eq!(vault.source_transaction, &successor_tx);
                assert_eq!(vault.successor_transaction, &withdrawal_tx);
                assert!(orders.is_empty());
                Err(ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
                    "native consumer rejection"))
            });
        assert_eq!(calls, 1);
        assert!(matches!(rejected, Err(
            ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
                "native consumer rejection"))));
        for mutation in 0..6 {
            let mut wrong = decoded.clone();
            match mutation {
                0 => wrong.state_bytes.push(0),
                1 => wrong.source_outpoint_bytes.push(0),
                2 => wrong.source_transaction_bytes.push(0),
                3 => wrong.account.cash_bytes.push(0),
                4 => wrong.prior_accounts[0].1.push(0),
                _ => wrong.successor_accounts[0].1.push(0),
            }
            let mut invoked = false;
            assert!(wrong.with_decoded_witness(|_, _, _, _, _| {
                invoked = true;
                Ok(())
            }).is_err(), "noncanonical borrowed withdrawal {mutation}");
            assert!(!invoked, "consumer saw noncanonical opening {mutation}");
        }
        assert!(decoded.execute(&DenyAllConsensusProofs).is_err());
        assert!(EcxMatchInputV1::decode(&encoded).is_err());
        for mutation in 0..4 {
            let mut bytes = encoded.clone();
            match mutation {
                0 => bytes.push(0),
                1 => { bytes.pop(); },
                2 => bytes[5] = b'3',
                _ => bytes[..6].copy_from_slice(b"ECXMI1"),
            }
            assert!(EcxWithdrawalInputV1::decode(&bytes).is_err());
        }
        for mutation in 0..5 {
            let mut wrong = decoded.clone();
            match mutation {
                0 => wrong.expected_state[0] ^= 1,
                1 => wrong.signed.signature.0[0] ^= 1,
                2 => wrong.recipient_vout = 0,
                3 => wrong.successor_accounts = wrong.prior_accounts.clone(),
                _ => wrong.successor_transaction_bytes.push(0),
            }
            assert!(wrong.execute(verifier).is_err(), "withdrawal transport {mutation}");
        }
    }
    // Test authentication at the withdrawal entry point itself, not merely
    // at the match that produced this ledger. Rehashing a substituted opening
    // must not turn an unauthenticated parent or receipt into withdrawal power.
    macro_rules! withdrawal_oracle {
        ($state:expr, $truth:expr, $btc:expr, $usd:expr, $verifier:expr) => {
            ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_withdrawal_v1(
                $state.digest().unwrap(), $state, withdrawal_outpoint,
                bindings, economics, configuration, $truth, $btc, $usd,
                $verifier, &result.funding_state, &withdrawal,
                EcxAccountOpeningV1 { position: &post_trade.maker_position,
                    cash: &maker_paid, siblings: &withdrawal_path },
                &withdrawal_vault, 1, &[])
        };
    }
    assert!(withdrawal_oracle!(&withdrawal_state, truthcoin, ecx_btc, usdd_usd,
        &DenyAllConsensusProofs).is_err());
    let mut damaged_truthcoin = truthcoin.clone();
    damaged_truthcoin.proof[0] ^= 1;
    assert!(withdrawal_oracle!(&withdrawal_state, &damaged_truthcoin,
        ecx_btc, usdd_usd, verifier).is_err());
    for field in 0..3 {
        let mut wrong_parent = withdrawal_state.clone();
        match field {
            0 => wrong_parent.parent_hash[0] ^= 1,
            1 => wrong_parent.parent_height += 1,
            _ => wrong_parent.parent_mtp += 1,
        }
        assert!(withdrawal_oracle!(&wrong_parent, truthcoin, ecx_btc,
            usdd_usd, verifier).is_err(), "withdrawal parent binding {field}");
    }
    // This also checks canonical absence for a native conversion lane: bytes
    // on an unused conversion proof must not be silently ignored.
    let mut damaged_btc = ecx_btc.clone();
    damaged_btc.proof.push(1);
    assert!(withdrawal_oracle!(&withdrawal_state, truthcoin, &damaged_btc,
        usdd_usd, verifier).is_err());
    let mut damaged_usd = usdd_usd.clone();
    damaged_usd.proof.push(1);
    assert!(withdrawal_oracle!(&withdrawal_state, truthcoin, ecx_btc,
        &damaged_usd, verifier).is_err());
    assert!(withdrawal_oracle!(&withdrawal_state, truthcoin, usdd_usd,
        ecx_btc, verifier).is_err());
    assert!(verify_bound(&withdrawal_state, [0; 32], withdrawal_outpoint,
        &result.funding_state).is_err());
    assert!(verify_bound(&withdrawal_state, withdrawal_state.digest().unwrap(), outpoint,
        &result.funding_state).is_err());
    for field in 0..5 {
        let mut wrong = withdrawal_state.clone();
        match field {
            0 => wrong.orders_root[0] ^= 1,
            1 => wrong.funding_root[0] ^= 1,
            2 => wrong.accounts_root[0] ^= 1,
            3 => wrong.controlled_ecx_atoms += 1,
            _ => wrong.vault_script_sha256[0] ^= 1,
        }
        assert!(verify_bound(&wrong, wrong.digest().unwrap(), withdrawal_outpoint,
            &result.funding_state).is_err(), "withdrawal state binding {field}");
    }
    let mut wrong_vault = withdrawal_vault;
    wrong_vault.successor_accounts = &post_ledger;
    assert!(verify_withdrawal(&wrong_vault).is_err());
    wrong_vault = withdrawal_vault;
    wrong_vault.source_script_sha256[0] ^= 1;
    assert!(verify_withdrawal(&wrong_vault).is_err());
    let mut wrong_tx = withdrawal_tx.clone();
    wrong_tx.output[1].value = elements::confidential::Value::Explicit(2);
    wrong_vault = withdrawal_vault;
    wrong_vault.successor_transaction = &wrong_tx;
    assert!(verify_withdrawal(&wrong_vault).is_err());
    ecx_proof_core::ecx_execution_v1::verify_ecx_vault_ledger_v1(
        update.accounts_root, vault_script_hash, domain, bounds, &final_ledger, &withdrawal_tx.output[0],
    ).unwrap();
    for mutation in 0..10 {
        let mut src = successor_tx.clone();
        let mut tx = withdrawal_tx.clone();
        let mut recipient_vout = 1;
        let mut amount = withdrawal.request.amount;
        match mutation {
            0 => tx.output[1].value = elements::confidential::Value::Explicit(2),
            1 => tx.output[0].value = elements::confidential::Value::Explicit(trading_backing),
            2 => tx.output[1].script_pubkey = elements::Script::from(vec![0x53]),
            3 => recipient_vout = 0,
            4 => tx.input.clear(),
            5 => tx.input.push(tx.input[0].clone()),
            6 => tx.input[0].is_pegin = true,
            7 => src.version += 1,
            8 => amount = 0,
            _ => amount = u64::MAX,
        }
        assert!(physical(&src, &tx, recipient_vout, amount).is_err(), "withdrawal mutation {mutation}");
    }
    let withdrawn = update.cash;
    assert_eq!(withdrawn.balance().0 + 1, maker_paid.balance().0);
    assert_eq!(withdrawn.outstanding_claims(), maker_paid.outstanding_claims());
    verify_ecx_cash_conservation(&[withdrawn, taker_paid.clone(),
        post_trade.clearing_cash.clone(), insurance_paid.clone()], trading_backing - 1).unwrap();
    verify_ecx_cash_conservation(
        &[
            maker_paid,
            taker_paid,
            result.execution.accounts.trade.clearing_cash.clone(),
            insurance_paid.clone(),
        ],
        trading_backing,
    )
    .unwrap();
    let advance = |obs: &[TimestampedFundingObservationV2]| {
        advance_funding_timestamped_v2(
            &previous,
            parent.median_time_past,
            mark,
            Price::new(source.liquidation_low_atoms).unwrap(),
            Price::new(source.liquidation_high_atoms).unwrap(),
            source.oracle_valid_through_mtp,
            obs,
            if close { u128::try_from(ecx_protocol_core::risk::notional(
                mark, QUANTITY).unwrap().0).unwrap() } else { 0 },
        )
        .unwrap()
    };
    let (expected_funding, rate) = advance(&[TimestampedFundingObservationV2::new(
        mark,
        Quantity::new(QUANTITY).unwrap(),
        parent.median_time_past,
    )
    .unwrap()]);
    assert_eq!(rate, expected_rate);
    assert_eq!(result.funding_state, expected_funding);
    let expected_state = ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1 {
        bindings_hash: bindings.digest().unwrap(),
        accounts_root: expected_accounts, orders_root: expected_orders,
        funding_root: expected_funding.root(), funding_index: expected_index,
        open_interest: if close { 0 } else { u128::from(QUANTITY) },
        matcher_sequence: receipt.sequence, matcher_receipt_hash: receipt.digest(),
        sidechain_height: 2, parent_hash: parent.block_hash,
        parent_height: parent.height, parent_mtp: parent.median_time_past,
        controlled_ecx_atoms: backing, vault_script_sha256: vault_script_hash,
    };
    assert_eq!(result.next_state, expected_state);
    let next_digest = result.next_state.digest().unwrap();
    result.next_state.verify_vault(next_digest, bindings, economics,
        &expected_ledger, &vault_witness.successor_transaction.output[vault_witness.successor_vout as usize]).unwrap();
    assert_eq!(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1::decode(
        &result.next_state.encode().unwrap()).unwrap().digest().unwrap(), next_digest);
    assert_ne!(result.funding_state.root(), advance(&[]).0.root());
    let mut wrong = bindings;
    wrong.oracle_configuration_hash[0] ^= 1;
    assert!(run!(
        wrong,
        parent,
        truthcoin,
        verifier,
        0,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY,
        true
    )
    .is_err());
    let mut wrong_parent = parent;
    wrong_parent.block_hash[0] ^= 1;
    assert!(run!(
        bindings,
        wrong_parent,
        truthcoin,
        verifier,
        0,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY,
        true
    )
    .is_err());
    let mut damaged = truthcoin.clone();
    damaged.proof[0] ^= 1;
    assert!(run!(
        bindings,
        parent,
        &damaged,
        verifier,
        0,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY,
        true
    )
    .is_err());
    assert!(run!(
        bindings,
        parent,
        truthcoin,
        &DenyAllConsensusProofs,
        0,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY,
        true
    )
    .is_err());
    let mut altered = receipt.clone();
    altered.signature.0[0] ^= 1;
    assert!(run!(
        bindings,
        parent,
        truthcoin,
        verifier,
        0,
        accounts_root,
        cursor,
        &altered,
        QUANTITY,
        true
    )
    .is_err());
    assert!(run!(
        bindings,
        parent,
        truthcoin,
        verifier,
        1,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY,
        true
    )
    .is_err());
    assert!(run!(
        bindings,
        parent,
        truthcoin,
        verifier,
        0,
        expected_accounts,
        cursor,
        &receipt,
        QUANTITY,
        true
    )
    .is_err());
    assert!(run!(
        bindings,
        parent,
        truthcoin,
        verifier,
        0,
        accounts_root,
        (2, receipt.digest()),
        &receipt,
        QUANTITY,
        true
    )
    .is_err());
    assert!(run!(
        bindings,
        parent,
        truthcoin,
        verifier,
        0,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY / 2,
        true
    )
    .is_err());
    assert!(run!(
        bindings,
        parent,
        truthcoin,
        verifier,
        0,
        accounts_root,
        cursor,
        &receipt,
        QUANTITY,
        false
    )
    .is_err());
}
