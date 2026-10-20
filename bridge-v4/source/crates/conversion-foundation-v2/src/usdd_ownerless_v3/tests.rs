//! Synthetic trie fixtures exercise genuine keccak/RLP/MPT authentication.
//! They are not Sepolia finality proofs, live deployments, or production pins.

use super::*;
use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{
    proof::{ProofNodes, ProofRetainer},
    HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH,
};

fn word(n: u64) -> [u8; 32] {
    accounting::U256::from_u64(n).0
}
fn path(key: impl AsRef<[u8]>) -> Nibbles {
    Nibbles::unpack(keccak256(key).as_slice())
}

fn configuration() -> UsddOwnerlessSourceConfigurationV3 {
    let identity = |n: u8| OwnerlessContractIdentityV3 {
        address: [n; 20],
        runtime_code_hash: [n + 10; 32],
    };
    UsddOwnerlessSourceConfigurationV3 {
        version: 3,
        ethereum_chain_id: 11_155_111,
        ethereum_light_client_configuration_hash: [1; 32],
        usdd_asset_id: [2; 32],
        elements_genesis_hash: [3; 32],
        custody_id: [4; 32],
        vault: identity(10),
        reserve_token: identity(11),
        relay: identity(12),
        redemption_verifier: identity(13),
        price_contract: identity(14),
        relay_verifier_configuration_hash: [30; 32],
        terminal_vault_policy_hash: [31; 32],
        ownerless_layout_commitment: ownerless_layout_commitment_v3(),
        reserve_balance_mapping_slot: word(9),
        price_storage_key: word(7),
        reserve_token_decimals: 6,
        usdd_decimals: 8,
        quote_decimals: 8,
    }
}

#[test]
fn integrated_accounting_matches_original_pinned_source() {
    let module = include_str!("../usdd_ownerless_accounting_v2.rs");
    let body = module.lines().skip(3).collect::<Vec<_>>().join("\n");
    let original = format!("#![no_std]\n{}\n", body.trim_end_matches('\n'));
    let actual = Sha256::digest(original.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        actual,
        "976d3449ed92b7e9116e1f29fb22af0dbdf8bcf5d337d534a0fc63ca50dfabb1"
    );
    let layout = ownerless_layout_commitment_v3()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        layout,
        "e6e55d4f737e06514531a19618fdfad8a72bffffe5c65af771ae2b02cdfcdbec"
    );
}

fn trie(mut leaves: Vec<(Nibbles, Vec<u8>)>, targets: Vec<Nibbles>) -> ([u8; 32], ProofNodes) {
    leaves.sort_by_key(|(key, _)| *key);
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
    for (key, value) in leaves {
        builder.add_leaf(key, &value);
    }
    let root = builder.root().0;
    (root, builder.take_proof_nodes())
}

fn nodes(proofs: &ProofNodes, target: Nibbles) -> Vec<Vec<u8>> {
    proofs
        .matching_nodes_sorted(&target)
        .into_iter()
        .map(|(_, bytes)| bytes.to_vec())
        .collect()
}

fn storage(values: &[([u8; 32], [u8; 32])]) -> ([u8; 32], Vec<EthereumStorageMptWitnessV2>) {
    let (root, proofs) = trie(
        values
            .iter()
            .filter(|(_, value)| *value != [0; 32])
            .map(|(key, value)| (path(key), alloy_rlp::encode(U256::from_be_bytes(*value))))
            .collect(),
        values.iter().map(|(key, _)| path(key)).collect(),
    );
    (
        root,
        values
            .iter()
            .map(|(key, value)| EthereumStorageMptWitnessV2 {
                storage_key: *key,
                value_be: *value,
                present: *value != [0; 32],
                proof_nodes: nodes(&proofs, path(key)),
            })
            .collect(),
    )
}

fn vault_words(c: &UsddOwnerlessSourceConfigurationV3) -> [[u8; 32]; 9] {
    let mut nonces = word(20);
    nonces[16..24].copy_from_slice(&10u64.to_be_bytes());
    [
        nonces,
        word(20),
        word(2),
        word(130),
        word(3),
        word(30),
        word(100),
        word(1),
        accounting::relay_binding_v2(&c.accounting_configuration()),
    ]
}

fn ethereum_fixture(
    c: &UsddOwnerlessSourceConfigurationV3,
    values: [[u8; 32]; 9],
    reserve: [u8; 32],
    quote: [u8; 32],
) -> (
    accounting::FinalizedAnchorV2,
    UsddOwnerlessEthereumWitnessV3,
) {
    let vault_values: Vec<_> = OWNERLESS_VAULT_SLOTS_V3
        .into_iter()
        .zip(values)
        .map(|(slot, value)| (word(slot), value))
        .collect();
    let (vault_root, vault_storage) = storage(&vault_values);
    let (token_root, token_storage) = storage(&[(
        c.accounting_configuration().token_vault_balance_storage_key,
        reserve,
    )]);
    let (price_root, price_storage) = storage(&[(c.price_storage_key, quote)]);
    let roots = [
        vault_root,
        token_root,
        EMPTY_ROOT_HASH.0,
        EMPTY_ROOT_HASH.0,
        price_root,
    ];
    let accounts: Vec<_> = c
        .identities()
        .into_iter()
        .zip(roots)
        .map(|(identity, storage_root)| {
            let account = TrieAccount {
                nonce: 1,
                balance: U256::ZERO,
                storage_root: B256::new(storage_root),
                code_hash: B256::new(identity.runtime_code_hash),
            };
            (identity, storage_root, alloy_rlp::encode(account))
        })
        .collect();
    let (state_root, account_proofs) = trie(
        accounts
            .iter()
            .map(|(identity, _, rlp)| (path(identity.address), rlp.clone()))
            .collect(),
        accounts
            .iter()
            .map(|(identity, _, _)| path(identity.address))
            .collect(),
    );
    let accounts = accounts
        .into_iter()
        .map(|(identity, storage_root, _)| EthereumAccountMptWitnessV2 {
            address: identity.address,
            nonce: 1,
            balance_be: [0; 32],
            storage_root,
            code_hash: identity.runtime_code_hash,
            proof_nodes: nodes(&account_proofs, path(identity.address)),
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    (
        accounting::FinalizedAnchorV2 {
            chain_id: c.ethereum_chain_id,
            execution_block_hash: [71; 32],
            execution_state_root: state_root,
            execution_block_number: 100,
            execution_timestamp: 200,
        },
        UsddOwnerlessEthereumWitnessV3 {
            accounts,
            vault_storage: vault_storage.try_into().unwrap(),
            reserve_balance: token_storage[0].clone(),
            reserve_usd_quote: price_storage[0].clone(),
        },
    )
}

#[test]
fn genuine_mpt_authenticates_all_accounts_and_conservative_backing() {
    let c = configuration();
    let (anchor, w) = ethereum_fixture(&c, vault_words(&c), word(200), word(100_000_000));
    let (report, quote) = authenticate_ownerless_mpt(&c, anchor, &w).unwrap();
    assert_eq!(report.reserve_usdt6.0, word(200));
    assert_eq!(report.accounted_custody_usdt6.0, word(155));
    assert_eq!(report.other_obligations_usdt6.0, word(55));
    assert_eq!(report.minted_redemption_backing_usdt6.0, word(100));
    assert_eq!(report.unallocated_surplus_usdt6.0, word(45));
    assert_eq!(quote, 100_000_000);
}

#[test]
fn wrong_account_role_code_or_finalized_root_rejected() {
    let c = configuration();
    let (anchor, w) = ethereum_fixture(&c, vault_words(&c), word(200), word(100_000_000));
    for i in 0..5 {
        let mut bad = w.clone();
        bad.accounts[i].code_hash[0] ^= 1;
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        bad.accounts[i].address[0] ^= 1;
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        bad.accounts[i].storage_root[0] ^= 1;
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        bad.accounts[i].proof_nodes.clear();
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        bad.accounts[i].proof_nodes.push(vec![0x80]);
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
    }
    let mut bad = anchor;
    bad.execution_state_root[0] ^= 1;
    assert!(authenticate_ownerless_mpt(&c, bad, &w).is_err());
    let mut bad = anchor;
    bad.chain_id += 1;
    assert!(authenticate_ownerless_mpt(&c, bad, &w).is_err());
    let mut bad = anchor;
    bad.execution_block_hash = [0; 32];
    assert!(authenticate_ownerless_mpt(&c, bad, &w).is_err());
}

#[test]
fn every_exact_slot_value_and_proof_is_authenticated() {
    let c = configuration();
    let (anchor, w) = ethereum_fixture(&c, vault_words(&c), word(200), word(100_000_000));
    for i in 0..9 {
        let mut bad = w.clone();
        bad.vault_storage[i].storage_key[31] ^= 1;
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        bad.vault_storage[i].value_be[31] ^= 1;
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        bad.vault_storage[i].proof_nodes.clear();
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        bad.vault_storage[i].proof_nodes.push(vec![0x80]);
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
    }
    for is_balance in [true, false] {
        let mut bad = w.clone();
        let storage = if is_balance {
            &mut bad.reserve_balance
        } else {
            &mut bad.reserve_usd_quote
        };
        storage.storage_key[0] ^= 1;
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
        let mut bad = w.clone();
        let storage = if is_balance {
            &mut bad.reserve_balance
        } else {
            &mut bad.reserve_usd_quote
        };
        storage.value_be[31] ^= 1;
        assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
    }
}

#[test]
fn authenticated_invalid_accounting_not_accepted_as_backing() {
    let c = configuration();
    let good = vault_words(&c);
    let cases = [
        (0, [255; 32], "NonCanonicalNoncePadding"),
        (3, word(131), "CommittedPartitionMismatch"),
        (7, word(0), "ReentrancyState"),
        (8, word(0), "RelayNotInitialized"),
        (8, [255; 32], "RelayBindingMismatch"),
        (1, [255; 32], "ArithmeticOverflow"),
        (
            1,
            word(accounting::MAX_ACCOUNTED_CUSTODY_USDT6),
            "AccountedCustodyAboveCap",
        ),
    ];
    for (index, value, expected) in cases {
        let mut values = good;
        values[index] = value;
        let (anchor, w) = ethereum_fixture(&c, values, word(200), word(100_000_000));
        assert_eq!(
            authenticate_ownerless_mpt(&c, anchor, &w),
            Err(OwnerlessSourceErrorV3::AccountingRejected(
                expected.to_owned()
            ))
        );
    }
    let (anchor, w) = ethereum_fixture(&c, good, word(154), word(100_000_000));
    assert_eq!(
        authenticate_ownerless_mpt(&c, anchor, &w),
        Err(OwnerlessSourceErrorV3::AccountingRejected(
            "Insolvent".into()
        ))
    );
}

#[test]
fn zero_is_proven_noninclusion_not_a_missing_proof_or_surplus() {
    let c = configuration();
    let mut values = vault_words(&c);
    values[3] = word(30);
    values[6] = word(0);
    let (anchor, w) = ethereum_fixture(&c, values, word(200), word(100_000_000));
    assert!(!w.vault_storage[6].present);
    assert!(!w.vault_storage[6].proof_nodes.is_empty());
    let (report, _) = authenticate_ownerless_mpt(&c, anchor, &w).unwrap();
    assert_eq!(report.minted_redemption_backing_usdt6.0, word(0));
    assert_eq!(report.unallocated_surplus_usdt6.0, word(145));
    let mut bad = w.clone();
    bad.vault_storage[6].proof_nodes.clear();
    assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
    let mut bad = w;
    bad.vault_storage[6].present = true;
    assert!(authenticate_ownerless_mpt(&c, anchor, &bad).is_err());
}

#[test]
fn unminted_token_empty_storage_trie_authenticates_zero_custody() {
    let c = configuration();
    let mut values = [[0; 32]; 9];
    values[7] = word(1); // Idle reentrancy lock remains mandatory.
    values[8] = accounting::relay_binding_v2(&c.accounting_configuration());
    let (anchor, mut ethereum) = ethereum_fixture(&c, values, word(0), word(100_000_000));
    assert_eq!(ethereum.accounts[1].storage_root, EMPTY_ROOT_HASH.0);
    // EIP-1186 represents this legitimate non-inclusion with no trie nodes.
    ethereum.reserve_balance.proof_nodes.clear();
    let (report, _) = authenticate_ownerless_mpt(&c, anchor, &ethereum).unwrap();
    assert_eq!(report.reserve_usdt6.0, word(0));
    assert_eq!(report.accounted_custody_usdt6.0, word(0));
    assert_eq!(report.minted_redemption_backing_usdt6.0, word(0));
    let input = UsddOwnerlessSourceInputV3 {
        version: 3, frozen_configuration: c.clone(), ethereum,
        finality: SepoliaFinalityFoundationWitness {
            manifest: vec![1], prior_controller_state: vec![1],
            expected_finalized_state: vec![1], finality_proof_cbor: vec![1],
        },
    };
    let bytes = input.canonical_bytes().unwrap();
    assert_eq!(UsddOwnerlessSourceInputV3::decode_exact(&bytes).unwrap(), input);
    // Envelope admission never bypasses the actual beacon finality relation.
    assert!(execute_usdd_ownerless_source_v3(&input).is_err());
    let mut bad = input;
    bad.ethereum.reserve_balance.present = true;
    bad.ethereum.reserve_balance.value_be = word(1);
    assert!(authenticate_ownerless_mpt(&c, anchor, &bad.ethereum).is_err());
    bad.ethereum.accounts[1].proof_nodes.clear();
    assert!(bad.validate_envelope().is_err());
}

#[test]
fn width_precision_identity_layout_and_version_boundaries() {
    let c = configuration();
    for field in 0..5 {
        let mut bad = c.clone();
        match field {
            0 => bad.version = 1,
            1 => bad.reserve_token_decimals = 18,
            2 => bad.usdd_decimals = 6,
            3 => bad.quote_decimals = 6,
            _ => bad.ownerless_layout_commitment[0] ^= 1,
        }
        assert!(bad.validate().is_err());
    }
    let mut bad = c.clone();
    bad.relay.address = bad.vault.address;
    assert!(bad.validate().is_err());
    let mut bad = c.clone();
    bad.custody_id = [0; 32];
    assert!(bad.validate().is_err());
    let mut changed = c.clone();
    changed.custody_id[0] ^= 1;
    assert_ne!(c.commitment().unwrap(), changed.commitment().unwrap());
    let (anchor, w) = ethereum_fixture(&c, vault_words(&c), [255; 32], word(100_000_000));
    let (report, _) = authenticate_ownerless_mpt(&c, anchor, &w).unwrap();
    assert_eq!(report.reserve_usdt6.0, [255; 32]);
    assert_eq!(report.minted_redemption_backing_usdt6.0, word(100));
    let (anchor, w) = ethereum_fixture(&c, vault_words(&c), word(200), [255; 32]);
    assert!(matches!(
        authenticate_ownerless_mpt(&c, anchor, &w),
        Err(OwnerlessSourceErrorV3::Ethereum(
            EthereumMptErrorV2::IntegerOverflow
        ))
    ));
    let (anchor, w) = ethereum_fixture(&c, vault_words(&c), word(200), word(0));
    assert_eq!(
        authenticate_ownerless_mpt(&c, anchor, &w),
        Err(OwnerlessSourceErrorV3::InvalidQuote)
    );
}

#[test]
fn canonical_envelope_cannot_skip_finality_or_smuggle_extra_bytes() {
    let c = configuration();
    let (_, ethereum) = ethereum_fixture(&c, vault_words(&c), word(200), word(100_000_000));
    let input = UsddOwnerlessSourceInputV3 {
        version: 3,
        frozen_configuration: c,
        ethereum,
        finality: SepoliaFinalityFoundationWitness {
            manifest: vec![1],
            prior_controller_state: vec![1],
            expected_finalized_state: vec![1],
            finality_proof_cbor: vec![1],
        },
    };
    let bytes = input.canonical_bytes().unwrap();
    assert_eq!(
        UsddOwnerlessSourceInputV3::decode_exact(&bytes).unwrap(),
        input
    );
    assert!(execute_usdd_ownerless_source_v3(&input).is_err());
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(UsddOwnerlessSourceInputV3::decode_exact(&bad).is_err());
    assert!(UsddOwnerlessSourceInputV3::decode_exact(&bytes[..bytes.len() - 1]).is_err());
    let mut bad = input.clone();
    bad.version = 1;
    assert!(bad.canonical_bytes().is_err());
    let mut bad = input.clone();
    bad.finality.finality_proof_cbor.clear();
    assert!(execute_usdd_ownerless_source_v3(&bad).is_err());
    let mut bad = input;
    bad.ethereum.accounts[0].proof_nodes = vec![vec![0; MAX_MPT_NODE_BYTES_V2 + 1]];
    assert!(bad.validate_envelope().is_err());
    assert!(validate_nodes(&[vec![0x80], vec![0x80]], true).is_err());
}

#[test]
fn ownerless_wire_fixture() {
    // Encoding parity only: these synthetic identities/context are never live pins.
    let c = configuration();
    let pv = UsddOwnerlessSourcePublicValuesV3 {
        version: 3,
        frozen_configuration_commitment: c.commitment().unwrap(),
        protocol_manifest_commitment: [40; 32],
        update_proof_commitment: [41; 32],
        prior_light_client_digest: [42; 32],
        prior_finalized_beacon_slot: 43,
        prior_finalized_beacon_root: [44; 32],
        prior_finalized_execution_state_root: [45; 32],
        finalized_beacon_slot: 46,
        finalized_beacon_root: [47; 32],
        finalized_execution_block_hash: [48; 32],
        finalized_execution_state_root: [49; 32],
        execution_block_number: 50,
        execution_block_timestamp: 51,
        light_client_digest: [52; 32],
        next_intent_nonce: 20,
        next_committed_deposit_nonce: 10,
        reserve_usdt6: word(200),
        accounted_custody_usdt6: word(155),
        pending_principal_usdt6: word(20),
        pending_bounty_usdt6: word(2),
        committed_principal_usdt6: word(130),
        committed_bounty_usdt6: word(3),
        unresolved_committed_usdt6: word(30),
        mint_acknowledged_usdt6: word(100),
        other_obligations_usdt6: word(55),
        minted_redemption_backing_usdt6: word(100),
        unallocated_surplus_usdt6: word(45),
        quote_atoms_per_whole_reserve_token: 100_000_000,
        reserve_token_decimals: 6,
        usdd_decimals: 8,
        quote_decimals: 8,
    };
    let config = c.canonical_bytes().unwrap();
    let public = pv.canonical_bytes();
    assert_eq!(config.len(), 560);
    assert_eq!(public.len(), 732);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!("OWNERLESS_CONFIG_HEX={}", hex(&config));
    println!("OWNERLESS_PV_HEX={}", hex(&public));
    println!(
        "OWNERLESS_LAYOUT_HASH={}",
        hex(&ownerless_layout_commitment_v3())
    );
}
