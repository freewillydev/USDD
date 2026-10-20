//! Snapshot coin reconstruction, not chain authentication. The caller must
//! authenticate the source transaction's block (including witness commitment),
//! height and preceding median time before committing the returned leaf.
use ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2;
use elements::{encode, OutPoint, Transaction};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotExport {
    pub version: u32, pub proof_ready: bool, pub network: String,
    pub genesis: String, pub blockhash: String, pub height: u32,
    pub headers: Vec<String>, pub coins: Vec<ExportCoin>,
    #[serde(default)]
    pub internal_records: Option<Vec<ExportCoin>>,
    pub spent_claim_keys: Vec<String>, pub coin_source_blocks: Vec<ExportSource>,
    pub withdrawals: ExportWithdrawals,
    pub capital_snapshot: Option<String>, pub drivechain_anchor: Option<String>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportCoin { pub outpoint: String, pub output: String, pub height: u32, pub coinbase: bool }
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSource { pub height: u32, pub block: String }
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportWithdrawals { pub count: u64, pub root: String, pub frontier: Vec<String> }

fn export_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("noncanonical export hex");
    }
    value.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        Ok((digit(pair[0]) << 4) | digit(pair[1]))
    }).collect()
}

impl SnapshotExport {
    /// Validate native database metadata against the supplied checkpoint header
    /// and transaction-output inventory. This checks consistency, not provenance:
    /// the caller must independently authenticate the tip and pegged asset.
    /// Internal records must never be inserted into the transaction UTXO tree.
    pub fn validate_internal_records(&self, pegged_asset: elements::AssetId)
        -> Result<Option<OutPoint>, &'static str> {
        use crate::native_header_v3::NativeHeader;
        if self.proof_ready { return Err("unqualified export readiness"); }
        let records = match (self.version, &self.internal_records) {
            (1, None) => return Ok(None),
            (2, Some(records)) => records,
            _ => return Err("internal record version"),
        };
        let raw = export_hex(self.headers.last().ok_or("missing tip header")?)?;
        let header = NativeHeader::decode(&raw, true).map_err(|_| "tip header encoding")?;
        let mut tip: [u8;32] = export_hex(&self.blockhash)?.try_into().map_err(|_| "tip length")?;
        tip.reverse();
        let context = header.prior_exchange_context(tip, self.height)
            .map_err(|_| "internal record tip")?;
        let Some(context) = context else {
            return if records.is_empty() && self.capital_snapshot.is_none() { Ok(None) }
                else { Err("inactive internal records") };
        };
        if records.len() != 3 { return Err("internal record coverage"); }
        let keys = [
            "e31f7fb1e9489bfb9f6a73c10f80ecdcce1f276fbdf0cf85c02e3bcf174dc041",
            "c3fd019db845c81a68a561f5ab67d92c3ab2505cb2c8212f02511e07e8c2f2a1",
            "0cc4c302121a9d75c8a0e520253c1740520a6d6f4d03db6947a99565175d6586",
        ].map(|s| OutPoint { txid: s.parse().expect("constant txid"), vout: 0 });
        let markers: [&[u8];3] = [b"ecx-state-v1", b"ecx-forced-v1", b"ecx-deposit-v1"];
        let mut seen = [false;3];
        let mut state = None;
        for record in records {
            let outpoint: OutPoint = encode::deserialize(&export_hex(&record.outpoint)?)
                .map_err(|_| "internal outpoint")?;
            let role = keys.iter().position(|k| *k == outpoint).ok_or("unknown internal record")?;
            if seen[role] || record.coinbase || record.height > self.height {
                return Err("internal record metadata");
            }
            seen[role] = true;
            let output: elements::TxOut = encode::deserialize(&export_hex(&record.output)?)
                .map_err(|_| "internal output")?;
            if output.asset != elements::confidential::Asset::Explicit(pegged_asset)
                || output.value != elements::confidential::Value::Explicit(0)
                || output.nonce != elements::confidential::Nonce::Null {
                return Err("internal output envelope");
            }
            let script = output.script_pubkey.as_bytes();
            let len = 1 + markers[role].len() + if role == 0 { 68 } else { 40 };
            let prefix = if len > 75 { vec![0x4c, len as u8] } else { vec![len as u8] };
            if script.len() != prefix.len() + len + 2 || !script.starts_with(&prefix)
                || script[script.len()-2..] != [0x75,0x00] {
                return Err("internal script");
            }
            let payload = &script[prefix.len()..script.len()-2];
            if payload[0] as usize != markers[role].len()
                || &payload[1..1+markers[role].len()] != markers[role] {
                return Err("internal marker");
            }
            let data = &payload[1+markers[role].len()..];
            if role == 0 {
                let tracked: OutPoint = encode::deserialize(&data[..36]).map_err(|_| "tracked outpoint")?;
                if keys.contains(&tracked) || tracked.is_null() || data[36..] != context.exchange {
                    return Err("exchange tracker binding");
                }
                let tracked_bytes = encode::serialize(&tracked);
                let mut matches = 0;
                for coin in &self.coins {
                    if export_hex(&coin.outpoint)? == tracked_bytes { matches += 1; }
                }
                if matches != 1 { return Err("tracked output coverage"); }
                if let Some(capital) = self.capital_projection()? {
                    if capital.exchange_state_root != context.exchange { return Err("capital tracker binding"); }
                }
                state = Some(tracked);
            } else {
                let (root, cursor) = if role == 1 { (context.forced, context.forced_cursor) }
                    else { (context.deposit, context.deposit_cursor) };
                let count = u64::from_le_bytes(data[32..].try_into().unwrap());
                if data[..32] != root || count < cursor { return Err("inbox tracker binding"); }
            }
        }
        for coin in &self.coins {
            let outpoint: OutPoint = encode::deserialize(&export_hex(&coin.outpoint)?)
                .map_err(|_| "coin outpoint")?;
            if keys.contains(&outpoint) { return Err("internal record in coins"); }
        }
        Ok(state)
    }

    /// Convert the preserved native anchor to the versioned guest encoding.
    /// This establishes shape and endpoint agreement, NOT authentication.
    pub fn full_parent_anchor(&self) -> Result<Option<crate::native_bmm_anchor_v1::NativeBmmAnchorV1>, &'static str> {
        let endpoint = self.parent_endpoint()?;
        let Some(raw) = &self.drivechain_anchor else { return Ok(None); };
        let mut bytes = export_hex(raw)?;
        // Native uint256 hashes retain internal order. Native work uint256s
        // and arithmetic integers are LE; canonical guest work/integers are BE.
        for range in [65..97, 97..129, 129..133, 133..137, 137..145] {
            bytes[range].reverse();
        }
        let anchor = crate::native_bmm_anchor_v1::NativeBmmAnchorV1::from_canonical_bytes(&bytes)
            .ok_or("invalid full native anchor")?;
        if Some(anchor.parent_endpoint()) != endpoint { return Err("anchor endpoint mismatch"); }
        Ok(Some(anchor))
    }

    /// Extract evaluator fields from native capital snapshot version 4. This
    /// does NOT validate the omitted financial fields or authenticate state.
    /// Review must retain the complete raw snapshot, not just this projection.
    pub fn capital_projection(&self) -> Result<Option<crate::child_execution_state_v4::CapitalProjectionV4>, &'static str> {
        use crate::child_execution_state_v4::CapitalProjectionV4;
        let Some(raw) = &self.capital_snapshot else { return Ok(None); };
        if raw.len() > 4096 { return Err("capital size"); }
        let bytes = export_hex(raw)?;
        struct Reader<'a>(&'a [u8]);
        impl Reader<'_> {
            fn take<const N: usize>(&mut self) -> Result<[u8;N], &'static str> {
                if self.0.len() < N { return Err("capital truncated"); }
                let result = self.0[..N].try_into().unwrap(); self.0 = &self.0[N..]; Ok(result)
            }
        }
        let mut r = Reader(&bytes);
        if u16::from_le_bytes(r.take()?) != 4 { return Err("capital version"); }
        let proof_profile = r.take::<1>()?[0];
        let exchange_state_root = r.take()?;
        let configuration_hash = r.take()?;
        let asset_id = r.take()?;
        let deployment_commitment = r.take()?;
        let transition_program_id = r.take()?;
        let transition_cmr = r.take()?;
        let covenant_state_hash = r.take()?;
        // Native uint256 serialization retains raw bytes. No display reversal.
        r.take::<96>()?; // bond, funding, inventory covenant roots
        r.take::<16>()?; // insurance
        r.take::<24>()?; // issued, outstanding, inventory shares
        r.take::<64>()?; // NAV, deficit, target, coverage
        r.take::<1>()?;  // capital mode
        r.take::<16>()?; // controlled USDD
        r.take::<28>()?; // price min/max, epoch, signed funding rate
        r.take::<16>()?; // funding index
        r.take::<72>()?; // redemption root, wide head/tail, queued shares
        r.take::<41>()?; // oracle certificate, valid-through MTP, mode
        r.take::<32>()?; // availability root
        let covenant_inbox_root = r.take()?;
        let covenant_inbox_count = u128::from_be_bytes(r.take()?);
        r.take::<96>()?; // processed root/cursor, outcome root/count
        let node_inbox_root = r.take()?;
        let node_inbox_count = u128::from_be_bytes(r.take()?);
        r.take::<64>()?; // matcher root and two wide sequences
        r.take::<25>()?; // transition height, safety flag, legacy fee pool
        if !r.0.is_empty() { return Err("capital trailing bytes"); }
        let projection = CapitalProjectionV4 { proof_profile, exchange_state_root,
            configuration_hash, asset_id, deployment_commitment, transition_program_id,
            transition_cmr, covenant_state_hash, covenant_inbox_root, covenant_inbox_count,
            node_inbox_root, node_inbox_count };
        projection.commitment().map_err(|_| "capital projection inconsistent")?;
        Ok(Some(projection))
    }

    /// Decode the native parent (P), not mining-block (Q), endpoint. This only
    /// checks native wire sanity; an independently reviewed checkpoint must
    /// authenticate ownership, ancestry and completeness before use.
    pub fn parent_endpoint(&self) -> Result<Option<[u8;80]>, &'static str> {
        let Some(raw) = &self.drivechain_anchor else {
            return if self.height == 0 { Ok(None) } else { Err("missing non-genesis anchor") };
        };
        if self.height == 0 || raw.len() != 290 { return Err("anchor extent"); }
        let bytes = export_hex(raw)?;
        if bytes[0] != 1 { return Err("anchor version"); }
        for part in bytes[1..129].chunks_exact(32) {
            if part.iter().all(|b| *b == 0) { return Err("null anchor identity or work"); }
        }
        let ph = u32::from_le_bytes(bytes[129..133].try_into().unwrap());
        let qh = u32::from_le_bytes(bytes[133..137].try_into().unwrap());
        let mtp = u64::from_le_bytes(bytes[137..145].try_into().unwrap());
        if ph.checked_add(1) != Some(qh) || mtp > u32::MAX as u64
            || bytes[97..129].iter().rev().cmp(bytes[65..97].iter().rev()) != std::cmp::Ordering::Greater {
            return Err("anchor height work or clock");
        }
        let mut endpoint = [0;80];
        for i in 0..32 { endpoint[i] = bytes[32-i]; endpoint[48+i] = bytes[96-i]; }
        endpoint[32..40].copy_from_slice(&u64::from(ph).to_be_bytes());
        endpoint[40..48].copy_from_slice(&mtp.to_be_bytes());
        Ok(Some(endpoint))
    }

    /// Validate internal accumulator consistency, not provenance or completeness.
    pub fn withdrawal_accumulator(&self) -> Result<crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator, &'static str> {
        use crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator;
        let digest = |s: &str| -> Result<[u8;32], &'static str> {
            if s.len() != 64 { return Err("withdrawal digest length"); }
            export_hex(s)?.try_into().map_err(|_| "withdrawal digest length")
        };
        if self.withdrawals.frontier.len() != 64 { return Err("withdrawal frontier length"); }
        let mut frontier = [[0;32];64];
        for (out, value) in frontier.iter_mut().zip(&self.withdrawals.frontier) { *out = digest(value)?; }
        // Native exporter uses raw digest order, unlike displayed block hashes.
        let accumulator = WithdrawalAccumulator { count: self.withdrawals.count,
            root: digest(&self.withdrawals.root)?, frontier };
        if !accumulator.is_sane() { return Err("withdrawal accumulator mismatch"); }
        Ok(accumulator)
    }

    /// Derive the Alpha claim-set root; snapshot completeness requires review.
    pub fn spent_claim_root(&self) -> Result<[u8;32], &'static str> {
        if self.spent_claim_keys.len() > 100_000 { return Err("claim count limit"); }
        let claims = self.spent_claim_keys.iter().map(|s| {
            if s.len() != 136 { return Err("claim length"); }
            export_hex(s)?.try_into().map_err(|_| "claim length")
        }).collect::<Result<Vec<[u8;68]>, &'static str>>()?;
        crate::native_claims_v3::root_from_native_claims(&claims)
    }

    /// Only reconstructs coins. Remaining checkpoint components are retained
    /// in this object and MUST be independently qualified before checkpoint use.
    pub fn reconstruct_coins(&self, network: &str, genesis: [u8;32], tip: [u8;32], height: u32,
        deployments: crate::child_deployments_v3::ChildDeploymentConfigurationV3,
        frozen_deployments: [u8;32],
    ) -> Result<Vec<ElementsUtxoLeafV2>, &'static str> {
        if self.version != 1 || self.internal_records.is_some() { return Err("export version"); }
        self.reconstruct_transaction_coins(network, genesis, tip, height, deployments, frozen_deployments)
    }

    /// V2 separates metadata from transaction-backed leaves. All records stay
    /// available in the export; this does not authenticate inbox totals or the
    /// checkpoint itself. Pegged asset and deployment pins must be reviewed.
    pub fn reconstruct_coins_v2(&self, network: &str, genesis: [u8;32], tip: [u8;32], height: u32,
        deployments: crate::child_deployments_v3::ChildDeploymentConfigurationV3,
        frozen_deployments: [u8;32], pegged_asset: elements::AssetId,
    ) -> Result<Vec<ElementsUtxoLeafV2>, &'static str> {
        if self.version != 2 { return Err("export version"); }
        let coins = self.reconstruct_transaction_coins(network, genesis, tip, height, deployments, frozen_deployments)?;
        self.validate_internal_records(pegged_asset)?;
        Ok(coins)
    }

    fn reconstruct_transaction_coins(&self, network: &str, genesis: [u8;32], tip: [u8;32], height: u32,
        deployments: crate::child_deployments_v3::ChildDeploymentConfigurationV3,
        frozen_deployments: [u8;32],
    ) -> Result<Vec<ElementsUtxoLeafV2>, &'static str> {
        let display_hash = |s: &str| -> Result<[u8;32], &'static str> {
            let mut bytes: [u8;32] = export_hex(s)?.try_into().map_err(|_| "hash length")?;
            bytes.reverse(); Ok(bytes)
        };
        if self.proof_ready || self.network != network || network.is_empty()
            || self.height != height || display_hash(&self.genesis)? != genesis
            || display_hash(&self.blockhash)? != tip { return Err("export identity"); }
        if self.headers.len() > 10_000 || self.coins.len() > 100_000 || self.coin_source_blocks.len() > 10_000 {
            return Err("export count limit");
        }
        let raw_size = self.headers.iter().map(String::len)
            .chain(self.coins.iter().flat_map(|c| [c.outpoint.len(), c.output.len()]))
            .chain(self.coin_source_blocks.iter().map(|b| b.block.len()))
            .try_fold(0usize, |sum, n| sum.checked_add(n)).ok_or("export size overflow")?;
        if raw_size > 128 * 1024 * 1024 { return Err("export size limit"); }
        let headers = self.headers.iter().map(|s| export_hex(s)).collect::<Result<Vec<_>, _>>()?;
        let contexts = source_contexts(&headers, genesis, tip, height, deployments, frozen_deployments)?;
        let mut sources = std::collections::BTreeMap::new();
        for source in &self.coin_source_blocks {
            if sources.insert(source.height, export_hex(&source.block)?).is_some() { return Err("duplicate source height"); }
        }
        let coins = self.coins.iter().map(|coin| Ok(SnapshotCoin {
            outpoint: export_hex(&coin.outpoint)?.try_into().map_err(|_| "outpoint length")?,
            output: export_hex(&coin.output)?, height: coin.height, coinbase: coin.coinbase,
        })).collect::<Result<Vec<_>, &'static str>>()?;
        import_coins(&coins, &sources, &contexts)
    }
}

pub struct SnapshotCoin {
    pub outpoint: [u8; 36],
    pub output: Vec<u8>,
    pub height: u32,
    pub coinbase: bool,
}

/// Values supplied by independently reviewed header history, not inferred from
/// the untrusted source block. This type alone is not authentication evidence.
pub struct ReviewedSourceContext {
    pub hash: [u8; 32],
    pub preceding_mtp: u32,
    pub segwit_active: bool,
}

/// Derive creation clocks and witness rules from the complete native header
/// chain committed by a reviewed tip. Pins must come from checkpoint review,
/// never be copied from the same untrusted export being checked here.
pub fn source_contexts(
    headers: &[Vec<u8>], genesis: [u8;32], tip: [u8;32], height: u32,
    deployments: crate::child_deployments_v3::ChildDeploymentConfigurationV3,
    frozen_deployments: [u8;32],
) -> Result<std::collections::BTreeMap<u32, ReviewedSourceContext>, &'static str> {
    use elements::hashes::Hash;
    if genesis == [0;32] || tip == [0;32] || height >= 10_000
        || headers.len() != height as usize + 1 { return Err("header extent"); }
    if frozen_deployments == [0;32]
        || deployments.commitment().map_err(|_| "deployment parameters")? != frozen_deployments {
        return Err("deployment commitment");
    }
    let mut result = std::collections::BTreeMap::new();
    let mut previous = [0;32];
    let mut times = Vec::with_capacity(headers.len());
    for (index, raw) in headers.iter().enumerate() {
        let header = crate::native_header_v3::NativeHeader::decode(raw, true).map_err(|_| "header encoding")?;
        if header.base.height != index as u32 || header.base.prev_blockhash.to_byte_array() != previous {
            return Err("header linkage");
        }
        let hash = header.hash_internal().map_err(|_| "header hash")?;
        if (index == 0 && hash != genesis) || (index == height as usize && hash != tip) {
            return Err("reviewed header identity");
        }
        // Native genesis coins have no predecessor; subsequent clocks use
        // exactly the preceding (at most) eleven block timestamps.
        let mut window = times[times.len().saturating_sub(11)..].to_vec();
        window.sort_unstable();
        let preceding_mtp = if window.is_empty() { 0 } else { window[window.len()/2] };
        result.insert(index as u32, ReviewedSourceContext { hash, preceding_mtp,
            segwit_active: deployments.buried.at_height(index as u32).map_err(|_| "deployment height")?.segwit });
        times.push(header.base.time);
        previous = hash;
    }
    Ok(result)
}

/// Import the complete exported coin set. Source bodies must match reviewed
/// history; snapshot completeness still requires independent review evidence.
pub fn import_coins(
    coins: &[SnapshotCoin],
    sources: &std::collections::BTreeMap<u32, Vec<u8>>,
    contexts: &std::collections::BTreeMap<u32, ReviewedSourceContext>,
) -> Result<Vec<ElementsUtxoLeafV2>, &'static str> {
    use std::collections::{BTreeMap, HashSet};
    if coins.len() > 100_000 { return Err("coin limit"); }
    let mut grouped = BTreeMap::<u32, Vec<&SnapshotCoin>>::new();
    for coin in coins { grouped.entry(coin.height).or_default().push(coin); }
    if grouped.len() != sources.len() || grouped.keys().any(|height| !sources.contains_key(height)) {
        return Err("source block set");
    }
    let mut leaves = Vec::with_capacity(coins.len());
    let mut outpoints = HashSet::new();
    for (height, group) in grouped {
        let context = contexts.get(&height).ok_or("missing reviewed source context")?;
        let block = check_source_block(&sources[&height], context.hash, height, context.segwit_active)?;
        let transactions: std::collections::HashMap<_, _> = block.txdata.iter().map(|tx| (tx.txid(), tx)).collect();
        for coin in group {
            if !outpoints.insert(coin.outpoint) { return Err("duplicate coin"); }
            let point: OutPoint = encode::deserialize(&coin.outpoint).map_err(|_| "outpoint encoding")?;
            let tx = transactions.get(&point.txid).ok_or("missing source transaction")?;
            leaves.push(reconstruct_coin(&coin.outpoint, &coin.output, tx, height,
                context.preceding_mtp, coin.coinbase)?);
        }
    }
    Ok(leaves)
}

/// Compute both execution roots from one set, verifying every economic opening
/// and role using the caller's independently frozen classification.
pub fn execution_roots(
    coins: &[ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicLeafV2],
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2,
) -> Result<ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionStateRootsV2, &'static str> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    if classification.base_asset_id == [0;32] || classification.policy_asset_id == [0;32]
        || classification.base_asset_id == classification.policy_asset_id
        || classification.redemption_inventory_script_sha256 == [0;32]
        || classification.reserve_script_sha256 == [0;32]
        || classification.redemption_inventory_script_sha256 == classification.reserve_script_sha256 {
        return Err("economic classification");
    }
    if coins.len() > 100_000 { return Err("coin limit"); }
    let mut entries = Vec::with_capacity(coins.len());
    for coin in coins {
        entries.push((elements_sparse_utxo_key_v2(coin.utxo.outpoint),
            verify_elements_economic_leaf_v2(coin, classification).map_err(|_| "economic opening or role")?));
    }
    entries.sort_unstable_by_key(|entry| entry.0);
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) { return Err("duplicate coin"); }
    let mut empty = vec![canonical_empty_elements_economic_leaf_v2()];
    for level in 0..256 {
        empty.push(elements_sparse_economic_parent_v2(empty[level], empty[level]).map_err(|_| "empty economic root")?);
    }
    fn subtree(entries: &[([u8;32], ElementsSparseEconomicNodeV2)], depth: usize,
        empty: &[ElementsSparseEconomicNodeV2]) -> Result<ElementsSparseEconomicNodeV2, &'static str> {
        if entries.is_empty() { return Ok(empty[256 - depth]); }
        if depth == 256 { return Ok(entries[0].1); }
        let split = entries.partition_point(|entry| entry.0[depth / 8] & (1 << (7 - depth % 8)) == 0);
        elements_sparse_economic_parent_v2(subtree(&entries[..split], depth + 1, empty)?,
            subtree(&entries[split..], depth + 1, empty)?).map_err(|_| "economic overflow")
    }
    Ok(ElementsTransactionStateRootsV2 {
        utxo_root: utxo_root(&coins.iter().map(|coin| coin.utxo.clone()).collect::<Vec<_>>())?,
        economic_root: subtree(&entries, 0, &empty)?,
    })
}

/// Rebuild custody and UTXO roots from the same reviewed coin set. All coins,
/// including native ECX and unrelated assets, must be included. Only the
/// independently bound custody asset contributes to custody supply. This does
/// not establish completeness, source authentication or issuance legitimacy.
pub fn custody_execution_roots_v3(
    coins: &[ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicLeafV2],
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsCustodyClassificationV3,
) -> Result<ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyRootsV3, &'static str> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    classification.commitment().map_err(|_|"custody classification")?;
    if coins.len()>100_000 { return Err("coin limit"); }
    let mut entries=Vec::with_capacity(coins.len());
    for coin in coins {
        entries.push((elements_sparse_utxo_key_v2(coin.utxo.outpoint),
            verify_elements_custody_leaf_v3(coin,classification).map_err(|_|"custody opening or role")?));
    }
    entries.sort_unstable_by_key(|entry|entry.0);
    if entries.windows(2).any(|pair|pair[0].0==pair[1].0) { return Err("duplicate coin"); }
    let mut empty=vec![empty_elements_custody_leaf_v3()];
    for level in 0..256 {
        empty.push(elements_custody_parent_v3(empty[level],empty[level]).map_err(|_|"empty custody root")?);
    }
    fn subtree(entries:&[([u8;32],ElementsSparseCustodyNodeV3)],depth:usize,
        empty:&[ElementsSparseCustodyNodeV3])->Result<ElementsSparseCustodyNodeV3,&'static str> {
        if entries.is_empty() { return Ok(empty[256-depth]); }
        if depth==256 { return Ok(entries[0].1); }
        let split=entries.partition_point(|entry|entry.0[depth/8] & (1 << (7-depth%8))==0);
        elements_custody_parent_v3(subtree(&entries[..split],depth+1,empty)?,
            subtree(&entries[split..],depth+1,empty)?).map_err(|_|"custody overflow")
    }
    Ok(ElementsTransactionCustodyRootsV3 {
        utxo_root:utxo_root(&coins.iter().map(|coin|coin.utxo.clone()).collect::<Vec<_>>())?,
        custody_root:subtree(&entries,0,&empty)?,
    })
}

/// Rebuild the native execution UTXO root from the complete reconstructed set.
/// Completeness and provenance must be established by the checkpoint review;
/// this function cannot detect an omitted coin without an external commitment.
pub fn utxo_root(coins: &[ElementsUtxoLeafV2]) -> Result<
    ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoNodeV2, &'static str> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    if coins.len() > 100_000 { return Err("coin limit"); }
    let mut entries: Vec<_> = coins.iter().map(|coin|
        (elements_sparse_utxo_key_v2(coin.outpoint), elements_utxo_leaf_node_v2(coin))).collect();
    entries.sort_unstable_by_key(|entry| entry.0);
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) { return Err("duplicate coin"); }
    let mut empty = vec![canonical_empty_elements_utxo_leaf_v2()];
    for level in 0..256 {
        empty.push(elements_sparse_utxo_parent_v2(empty[level], empty[level]).map_err(|_| "empty root")?);
    }
    fn subtree(entries: &[([u8;32], ElementsSparseUtxoNodeV2)], depth: usize,
        empty: &[ElementsSparseUtxoNodeV2]) -> Result<ElementsSparseUtxoNodeV2, &'static str> {
        if entries.is_empty() { return Ok(empty[256 - depth]); }
        if depth == 256 { return Ok(entries[0].1); }
        let split = entries.partition_point(|entry| entry.0[depth / 8] & (1 << (7 - depth % 8)) == 0);
        elements_sparse_utxo_parent_v2(subtree(&entries[..split], depth + 1, empty)?,
            subtree(&entries[split..], depth + 1, empty)?).map_err(|_| "aggregate overflow")
    }
    subtree(&entries, 0, &empty)
}

/// Bind source transaction bytes and witnesses to an independently trusted
/// native header hash. This does not establish that the block is on the active
/// chain: the caller must obtain that hash and deployment flag from the reviewed
/// checkpoint's header history, not from this source block itself.
pub fn check_source_block(raw: &[u8], expected_hash: [u8; 32], height: u32,
    segwit_active: bool) -> Result<elements::Block, &'static str> {
    use ecx_full_consensus_validator_v2::elements_v2::elements_transaction_merkle_root_v2;
    let native = crate::native_block_wire_v3::NativeBlock::decode(raw).map_err(|_| "block encoding")?;
    native.check_alpha_bmm_lane().map_err(|_| "historical BMM lane")?;
    if expected_hash == [0; 32] || native.header.hash_internal().map_err(|_| "header hash")? != expected_hash
        || native.header.base.height != height { return Err("source header mismatch"); }
    if native.weight().map_err(|_| "weight encoding")? > crate::native_child_block_v3::ALPHA_MAX_BLOCK_WEIGHT {
        return Err("block weight");
    }
    let block = elements::Block { header: native.header.base, txdata: native.transactions };
    if block.txdata.is_empty() || !block.txdata[0].is_coinbase()
        || block.txdata.iter().skip(1).any(Transaction::is_coinbase) { return Err("coinbase placement"); }
    let mut ids = std::collections::HashSet::new();
    if block.txdata.iter().any(|tx| !ids.insert(tx.txid())) { return Err("duplicate transaction"); }
    if elements_transaction_merkle_root_v2(&block.txdata).map_err(|_| "transaction tree")? != block.header.merkle_root {
        return Err("transaction commitment");
    }
    crate::native_child_witness_v3::verify_witness_commitment(&block, segwit_active)
        .map_err(|_| "witness commitment")?;
    Ok(block)
}

pub fn reconstruct_coin(
    outpoint_bytes: &[u8], output_bytes: &[u8], source: &Transaction,
    creation_height: u32, creation_parent_mtp: u32, coinbase: bool,
) -> Result<ElementsUtxoLeafV2, &'static str> {
    // Native outpoints are precisely txid-internal || little-endian u32.
    if outpoint_bytes.len() != 36 { return Err("outpoint length"); }
    let outpoint: OutPoint = encode::deserialize(outpoint_bytes).map_err(|_| "outpoint encoding")?;
    if encode::serialize(&outpoint) != outpoint_bytes { return Err("noncanonical outpoint"); }
    if source.txid() != outpoint.txid { return Err("source transaction mismatch"); }
    if source.is_coinbase() != coinbase { return Err("coinbase mismatch"); }
    let output = source.output.get(outpoint.vout as usize).ok_or("output index")?;
    // Native TxOutCompression persists asset/value/script, not nonce. The RPC
    // serializes that database representation using ordinary TxOut encoding.
    // Compare it canonically, but retain the full original nonce and witnesses
    // in the authenticated execution leaf below.
    let mut persisted = output.clone();
    persisted.nonce = elements::confidential::Nonce::Null;
    if encode::serialize(&persisted) != output_bytes { return Err("output mismatch"); }
    Ok(ElementsUtxoLeafV2 {
        outpoint, output: output.clone(), creation_height, creation_parent_mtp, coinbase,
        created_by_issuance: source.input.iter().any(elements::TxIn::has_issuance),
        created_by_pegin: source.input.iter().any(elements::TxIn::is_pegin),
    })
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn economic_roots_verify_amount_and_role() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        use elements::hashes::Hash;
        let classification = ElementsEconomicClassificationV2 { base_asset_id: [1;32], policy_asset_id: [2;32],
            redemption_inventory_script_sha256: [3;32], reserve_script_sha256: [4;32] };
        let mut output = elements::TxOut::default();
        output.asset = elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array([1;32]));
        output.value = elements::confidential::Value::Explicit(30);
        output.script_pubkey = elements::Script::from(vec![0x51]);
        let coin = ElementsEconomicLeafV2 {
            utxo: ElementsUtxoLeafV2 { outpoint: OutPoint::default(), output, creation_height: 1,
                creation_parent_mtp: 100, coinbase: false, created_by_issuance: false, created_by_pegin: false },
            asset_id: [1;32], amount: 30, asset_blinding_factor: [0;32], value_blinding_factor: [0;32],
            role: ElementsLiveEconomicRoleV2::OutstandingBase };
        let result = execution_roots(&[coin.clone()], classification).unwrap();
        assert_eq!(result.utxo_root.aggregate.count, 1);
        assert_eq!(result.economic_root.aggregate.count, 1);
        assert_eq!(result.economic_root.aggregate.outstanding_base_atoms, 30);
        let mut siblings = Vec::new(); let mut node = canonical_empty_elements_economic_leaf_v2();
        for _ in 0..256 { siblings.push(node); node = elements_sparse_economic_parent_v2(node, node).unwrap(); }
        assert_eq!(result.economic_root, elements_sparse_economic_root_from_path_v2(coin.utxo.outpoint,
            verify_elements_economic_leaf_v2(&coin, classification).unwrap(), &ElementsSparseEconomicPathV2 { siblings }).unwrap());
        assert_eq!(execution_roots(&[], classification).unwrap().economic_root, node);
        let mut changed = coin.clone(); changed.amount += 1;
        assert!(execution_roots(&[changed], classification).is_err());
        let mut changed = coin.clone(); changed.role = ElementsLiveEconomicRoleV2::Irrelevant;
        assert!(execution_roots(&[changed], classification).is_err());
        assert!(execution_roots(&[coin.clone(), coin], classification).is_err());
        let mut invalid = classification; invalid.base_asset_id = [0;32];
        assert!(execution_roots(&[], invalid).is_err());
    }
    #[test] fn custody_snapshot_separates_assets_and_matches_mutation_root() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        let policy=ElementsCustodyClassificationV3 {native_pegged_asset_id:[2;32],custody_asset_id:[1;32]};
        let make_coin=|asset,amount,vout,role| ElementsEconomicLeafV2 {
            utxo:ElementsUtxoLeafV2 {
                outpoint:OutPoint {vout,..OutPoint::default()},
                output:elements::TxOut {
                    asset:elements::confidential::Asset::Explicit(elements::AssetId::from_byte_array(asset)),
                    value:elements::confidential::Value::Explicit(amount),
                    script_pubkey:elements::Script::from(vec![0x51]),..Default::default()},
                creation_height:1,creation_parent_mtp:100,coinbase:false,
                created_by_issuance:false,created_by_pegin:false},
            asset_id:asset,amount,asset_blinding_factor:[0;32],value_blinding_factor:[0;32],role,
        };
        let usdd=make_coin([1;32],30,0,ElementsLiveEconomicRoleV2::OutstandingBase);
        let ecx=make_coin([2;32],900,1,ElementsLiveEconomicRoleV2::Irrelevant);
        let roots=custody_execution_roots_v3(&[usdd.clone(),ecx.clone()],policy).unwrap();
        assert_eq!(roots.utxo_root.aggregate.count,2);
        assert_eq!(roots.custody_root.count,2);
        assert_eq!(roots.custody_root.custody_supply_atoms,30);
        let checkpoint=crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3 {
            genesis_internal:[3;32],configuration_commitment:[4;32],tip_internal:[5;32],height:1,
            history_commitment:[6;32],classification:policy,roots,spent_claims_root:crate::native_claims_v3::empty_root(),
            withdrawals:crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator::empty(),
        };
        let frozen=checkpoint.commitment().unwrap();
        checkpoint.require_imported_coins(frozen,&[usdd.clone(),ecx.clone()]).unwrap();
        assert!(checkpoint.require_imported_coins(frozen,&[usdd.clone()]).is_err());
        assert!(checkpoint.require_imported_coins(frozen,&[ecx.clone()]).is_err());
        assert!(checkpoint.require_imported_coins([0;32],&[usdd.clone(),ecx.clone()]).is_err());
        assert_eq!(roots,custody_execution_roots_v3(&[ecx.clone(),usdd.clone()],policy).unwrap());
        let mut empty=empty_elements_custody_leaf_v3();let mut siblings=Vec::new();
        for _ in 0..256 {siblings.push(empty);empty=elements_custody_parent_v3(empty,empty).unwrap();}
        let insert=ElementsSparseCustodyMutationV3 {outpoint:usdd.utxo.outpoint,old_leaf:None,
            new_leaf:Some(usdd.clone()),siblings};
        assert_eq!(custody_execution_roots_v3(&[usdd.clone()],policy).unwrap().custody_root,
            apply_elements_custody_mutation_v3(empty,&insert,policy).unwrap());
        assert_eq!(custody_execution_roots_v3(&[],policy).unwrap().custody_root,empty);
        assert!(custody_execution_roots_v3(&[usdd.clone(),usdd.clone()],policy).is_err());
        let mut bad=usdd.clone();bad.amount+=1;
        assert!(custody_execution_roots_v3(&[bad],policy).is_err());
        let mut bad=ecx.clone();bad.role=ElementsLiveEconomicRoleV2::OutstandingBase;
        assert!(custody_execution_roots_v3(&[bad],policy).is_err());
        let mut bad=usdd;bad.role=ElementsLiveEconomicRoleV2::RedemptionInventory;
        assert!(custody_execution_roots_v3(&[bad],policy).is_err());
        let invalid=ElementsCustodyClassificationV3 {custody_asset_id:[2;32],..policy};
        assert!(custody_execution_roots_v3(&[],invalid).is_err());
    }
    #[test] fn snapshot_utxo_root_matches_path_verifier() {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        let coin = ElementsUtxoLeafV2 { outpoint: OutPoint::default(), output: elements::TxOut::default(),
            creation_height: 5, creation_parent_mtp: 100, coinbase: false,
            created_by_issuance: false, created_by_pegin: false };
        let mut siblings = Vec::new();
        let mut node = canonical_empty_elements_utxo_leaf_v2();
        for _ in 0..256 { siblings.push(node); node = elements_sparse_utxo_parent_v2(node, node).unwrap(); }
        assert_eq!(utxo_root(&[]).unwrap(), node);
        let expected = elements_sparse_utxo_root_from_path_v2(coin.outpoint,
            elements_utxo_leaf_node_v2(&coin), &ElementsSparseUtxoPathV2 { siblings }).unwrap();
        assert_eq!(utxo_root(&[coin.clone()]).unwrap(), expected);
        assert!(utxo_root(&[coin.clone(), coin.clone()]).is_err());
        let mut other = coin.clone(); other.outpoint.vout = 1;
        let both = utxo_root(&[coin.clone(), other.clone()]).unwrap();
        assert_eq!(both.aggregate.count, 2);
        assert_eq!(both, utxo_root(&[other, coin.clone()]).unwrap());
        let mut altered = coin; altered.creation_parent_mtp += 1;
        assert_ne!(utxo_root(&[altered]).unwrap(), expected);
    }
    #[test] fn source_block_requires_external_identity_and_witness_commitment() {
        use elements::hashes::Hash;
        use crate::{native_header_v3::NativeHeader, native_block_wire_v3::NativeBlock};
        let tx = Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()], output: vec![elements::TxOut::default()] };
        let root = ecx_full_consensus_validator_v2::elements_v2::elements_transaction_merkle_root_v2(&[tx.clone()]).unwrap();
        let mut native = NativeBlock { header: NativeHeader {
            base: elements::BlockHeader { version: 1, prev_blockhash: elements::BlockHash::all_zeros(),
                merkle_root: root, time: 100, height: 5,
                ext: elements::BlockExtData::Proof { challenge: elements::Script::new(), solution: elements::Script::new() } },
            withdrawal: [0;32], bmm_proof: [0;32], exchange: [0;32], forced: [0;32], deposit: [0;32],
            parent_height: 0, forced_cursor: 0, deposit_cursor: 0, oldest_backlog_height: 0,
        }, transactions: vec![tx], bmm_proof: vec![] };
        let hash = native.header.hash_internal().unwrap();
        {
            use crate::child_deployments_v3::*;
            let deployment = ElementsVersionbitsV3 { bit: 2, start: 0, timeout: 7,
                min_activation_height: 0, period: 4, threshold: 3 };
            let config = ChildDeploymentConfigurationV3 {
                buried: BuriedDeploymentsV3 { height_in_coinbase: 0, strict_der: 0, cltv: 0, csv: 0, segwit: 2 },
                taproot: deployment, dynafed: deployment, simplicity: deployment,
                bip16_exception_internal: [0;32], usdd_sp1_annex: false,
            };
            let frozen = config.commitment().unwrap();
            let mut header = native.header.clone();
            let mut headers = Vec::new();
            let mut hashes = Vec::new();
            for height in 0..13 {
                header.base.height = height;
                header.base.time = 100 + height;
                headers.push(header.encode(false, true).unwrap());
                let hash = header.hash_internal().unwrap(); hashes.push(hash);
                header.base.prev_blockhash = elements::BlockHash::from_byte_array(hash);
            }
            let contexts = source_contexts(&headers, hashes[0], hashes[12], 12, config, frozen).unwrap();
            assert_eq!(contexts[&0].preceding_mtp, 0);
            assert_eq!(contexts[&1].preceding_mtp, 100);
            assert_eq!(contexts[&2].preceding_mtp, 101);
            assert_eq!(contexts[&12].preceding_mtp, 106);
            assert!(!contexts[&1].segwit_active);
            assert!(contexts[&2].segwit_active);
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let display = |mut hash: [u8;32]| { hash.reverse(); hex(&hash) };
            let json = serde_json::json!({
                "version": 1, "proof_ready": false, "network": "fixture",
                "genesis": display(hashes[0]), "blockhash": display(hashes[12]), "height": 12,
                "headers": headers.iter().map(|h| hex(h)).collect::<Vec<_>>(),
                "coins": [], "spent_claim_keys": [], "coin_source_blocks": [],
                "withdrawals": { "count": 0, "root": "00".repeat(32), "frontier": [] },
                "capital_snapshot": null, "drivechain_anchor": null,
            });
            let export: SnapshotExport = serde_json::from_value(json.clone()).unwrap();
            assert!(export.validate_internal_records(elements::AssetId::LIQUID_BTC).unwrap().is_none());
            let mut v2 = json.clone();
            v2["version"] = serde_json::json!(2);
            assert!(serde_json::from_value::<SnapshotExport>(v2.clone()).unwrap()
                .validate_internal_records(elements::AssetId::LIQUID_BTC).is_err());
            v2["internal_records"] = serde_json::json!([]);
            let v2: SnapshotExport = serde_json::from_value(v2).unwrap();
            assert!(v2.validate_internal_records(elements::AssetId::LIQUID_BTC).unwrap().is_none());
            assert!(v2.reconstruct_coins_v2("fixture", hashes[0], hashes[12], 12, config, frozen, elements::AssetId::LIQUID_BTC).unwrap().is_empty());
            assert!(v2.reconstruct_coins("fixture", hashes[0], hashes[12], 12, config, frozen).is_err());
            assert!(v2.reconstruct_coins_v2("wrong-network", hashes[0], hashes[12], 12, config, frozen, elements::AssetId::LIQUID_BTC).is_err());
            assert!(v2.reconstruct_coins_v2("fixture", hashes[0], hashes[12], 12, config, [0;32], elements::AssetId::LIQUID_BTC).is_err());
            assert!(export.reconstruct_coins_v2("fixture", hashes[0], hashes[12], 12, config, frozen, elements::AssetId::LIQUID_BTC).is_err());
            assert!(export.reconstruct_coins("fixture", hashes[0], hashes[12], 12, config, frozen).unwrap().is_empty());
            assert!(export.reconstruct_coins("wrong-network", hashes[0], hashes[12], 12, config, frozen).is_err());
            let mut unknown = json.clone(); unknown["unexpected"] = serde_json::json!(true);
            assert!(serde_json::from_value::<SnapshotExport>(unknown).is_err());
            let mut malformed = json; malformed["headers"][0] = serde_json::json!("GG");
            assert!(serde_json::from_value::<SnapshotExport>(malformed).unwrap()
                .reconstruct_coins("fixture", hashes[0], hashes[12], 12, config, frozen).is_err());
            assert!(source_contexts(&headers, [1;32], hashes[12], 12, config, frozen).is_err());
            assert!(source_contexts(&headers, hashes[0], [1;32], 12, config, frozen).is_err());
            assert!(source_contexts(&headers, hashes[0], hashes[12], 12, config, [0;32]).is_err());
            headers.swap(2,3);
            assert!(source_contexts(&headers, hashes[0], hashes[12], 12, config, frozen).is_err());
        }
        let raw = native.encode().unwrap();
        assert!(check_source_block(&raw, hash, 5, true).is_ok());
        let coin = SnapshotCoin {
            outpoint: encode::serialize(&OutPoint::new(native.transactions[0].txid(), 0)).try_into().unwrap(),
            output: encode::serialize(&native.transactions[0].output[0]), height: 5, coinbase: true,
        };
        let mut sources = std::collections::BTreeMap::from([(5, raw.clone())]);
        let contexts = std::collections::BTreeMap::from([(5, ReviewedSourceContext {
            hash, preceding_mtp: 99, segwit_active: true,
        })]);
        let leaves = import_coins(std::slice::from_ref(&coin), &sources, &contexts).unwrap();
        assert_eq!(leaves[0].creation_parent_mtp, 99);
        assert_eq!(utxo_root(&leaves).unwrap().aggregate.count, 1);
        assert!(import_coins(std::slice::from_ref(&coin), &sources, &Default::default()).is_err());
        assert!(import_coins(std::slice::from_ref(&coin), &Default::default(), &contexts).is_err());
        sources.insert(6, raw.clone());
        assert!(import_coins(std::slice::from_ref(&coin), &sources, &contexts).is_err());
        sources.remove(&6);
        let duplicate = SnapshotCoin { outpoint: coin.outpoint, output: coin.output.clone(), height: 5, coinbase: true };
        assert_eq!(import_coins(&[coin, duplicate], &sources, &contexts).unwrap_err(), "duplicate coin");
        assert!(check_source_block(&raw, [0;32], 5, true).is_err());
        assert!(check_source_block(&raw, hash, 6, true).is_err());
        let mut trailing = raw.clone(); trailing.push(0);
        assert!(check_source_block(&trailing, hash, 5, true).is_err());
        // Witness changes leave both txid and native header unchanged.
        native.transactions[0].input[0].witness.script_witness = vec![vec![0;32]];
        assert_eq!(native.header.hash_internal().unwrap(), hash);
        assert_eq!(check_source_block(&native.encode().unwrap(), hash, 5, true).unwrap_err(), "witness commitment");
        native.transactions[0].input[0].witness.script_witness.clear();
        native.transactions[0].output[0].script_pubkey = elements::Script::from(vec![0x51]);
        assert_eq!(check_source_block(&native.encode().unwrap(), hash, 5, true).unwrap_err(), "transaction commitment");
    }
    #[test] fn stored_nonce_is_omitted_but_source_nonce_is_retained() {
        let mut tx = Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()], output: vec![elements::TxOut::default()] };
        tx.output[0].nonce = elements::confidential::Nonce::Confidential(
            elements::secp256k1_zkp::PublicKey::from_slice(&hex::decode(
                "03b22af004840add6a63080089ff46777e06dfe5dc7f41178881fe5727a7873231").unwrap()).unwrap());
        let point = encode::serialize(&OutPoint::new(tx.txid(), 0));
        let mut persisted = tx.output[0].clone();
        persisted.nonce = elements::confidential::Nonce::Null;
        let bytes = encode::serialize(&persisted);
        let leaf = reconstruct_coin(&point, &bytes, &tx, 22, 100, tx.is_coinbase()).unwrap();
        assert_eq!(leaf.output, tx.output[0]);
        assert_ne!(leaf.output.nonce, persisted.nonce);
        assert!(reconstruct_coin(&point, &encode::serialize(&tx.output[0]), &tx,
            22, 100, tx.is_coinbase()).is_err());
        persisted.script_pubkey = elements::Script::from(vec![0x51]);
        assert!(reconstruct_coin(&point, &encode::serialize(&persisted), &tx,
            22, 100, tx.is_coinbase()).is_err());
    }
    #[test] fn source_bytes_and_classification_are_checked() {
        let tx = Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()], output: vec![elements::TxOut::default()] };
        let point = encode::serialize(&OutPoint::new(tx.txid(), 0));
        let output = encode::serialize(&tx.output[0]);
        let coinbase = tx.is_coinbase();
        let leaf = reconstruct_coin(&point, &output, &tx, 5, 100, coinbase).unwrap();
        assert_eq!(leaf.output, tx.output[0]);
        assert_eq!(leaf.creation_height, 5);
        assert_eq!(leaf.creation_parent_mtp, 100);
        assert!(reconstruct_coin(&point[..35], &output, &tx, 5, 100, coinbase).is_err());
        let mut wrong = point.clone(); wrong[0] ^= 1;
        assert!(reconstruct_coin(&wrong, &output, &tx, 5, 100, coinbase).is_err());
        assert!(reconstruct_coin(&point, &output, &tx, 5, 100, !coinbase).is_err());
        let mut trailing = output.clone(); trailing.push(0);
        assert!(reconstruct_coin(&point, &trailing, &tx, 5, 100, coinbase).is_err());
        let invalid = encode::serialize(&OutPoint::new(tx.txid(), 1));
        assert!(reconstruct_coin(&invalid, &output, &tx, 5, 100, coinbase).is_err());
    }
}
