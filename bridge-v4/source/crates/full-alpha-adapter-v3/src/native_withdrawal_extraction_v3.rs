//! Native generic withdrawal extraction, not custody authorization.
//! The complete transaction list must be authenticated by child validation.
//! Generic indexing accepts any nonzero asset/vault; the economic consumer must
//! additionally bind the deployed asset and vault. Noncanonical lookalikes are
//! ignored exactly as in native ExtractEthereumWithdrawals.
use bitcoin::hashes::{sha256, Hash};
use elements::{confidential, Transaction};
use ecx_full_consensus_validator_v2::Hash32;
use super::native_withdrawal_accumulator_v3::{WithdrawalAccumulator, AccumulatorError};

const BURN_DOMAIN: Hash32 = [0x58,0x11,0xf3,0xff,0x8b,0x8f,0x31,0xfb,0x49,0xff,0xb9,0x1a,0xfa,0xb1,0x31,0x97,0xc3,0xd7,0x2e,0x92,0x65,0x49,0xae,0x29,0xdb,0xda,0x46,0xc6,0x99,0x8a,0x3e,0x45];
const LEAF_DOMAIN: Hash32 = [0xa2,0x04,0x23,0x80,0x92,0x68,0x79,0x09,0x8c,0x0f,0x42,0x3f,0x49,0xe3,0xa0,0x7a,0x12,0x48,0xed,0x08,0x53,0x57,0x93,0xa4,0xa1,0xc4,0xaf,0xe6,0x2d,0x99,0x88,0x69];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalClaim {
    pub asset_display: Hash32,
    pub vault: Hash32,
    pub burn_txid_display: Hash32,
    pub vout: u32,
    pub burn_id: Hash32,
    pub index: u64,
    pub amount_micro: u64,
    pub recipient: [u8;20],
    pub leaf: Hash32,
}

/// Exact V1 root-marker preimage fields, in contract/display byte order.
/// Encoding does not authenticate these identities, roots, or their approval.
/// Consumer validation and builder canonicality are deliberately separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsddRootTransitionV1 {
    pub parent_genesis_display: Hash32,
    pub elements_genesis_display: Hash32,
    pub asset_display: Hash32,
    pub vault: Hash32,
    pub prior_count: u64,
    pub prior_root: Hash32,
    pub next_count: u64,
    pub next_root: Hash32,
}

impl UsddRootTransitionV1 {
    pub fn preimage(&self) -> [u8; 241] {
        let mut out = [0; 241];
        out[..32].copy_from_slice(&sha256::Hash::hash(b"USDD_M6_APPROVED_ROOT_V1").to_byte_array());
        out[32] = 24;
        for (offset, value) in [(33, self.parent_genesis_display),
            (65, self.elements_genesis_display), (97, self.asset_display),
            (129, self.vault), (169, self.prior_root), (209, self.next_root)] {
            out[offset..offset + 32].copy_from_slice(&value);
        }
        out[161..169].copy_from_slice(&self.prior_count.to_be_bytes());
        out[201..209].copy_from_slice(&self.next_count.to_be_bytes());
        out
    }

    pub fn commitment(&self) -> Hash32 {
        sha256::Hash::hash(&self.preimage()).to_byte_array()
    }

    /// Check a claim introduced by this batch. The caller must independently
    /// authenticate this root transition and the supplied deployment identities.
    pub fn verify_introduced_claim(
        &self, transaction: &Transaction, genesis_internal: Hash32,
        first_index: u64, vout: u32, expected_parent_display: Hash32,
        expected_asset_display: Hash32, expected_vault: Hash32, siblings: &[Hash32],
    ) -> Result<WithdrawalClaim, AccumulatorError> {
        let mut genesis_display = genesis_internal; genesis_display.reverse();
        if expected_parent_display == [0;32]
            || self.parent_genesis_display != expected_parent_display
            || self.elements_genesis_display != genesis_display
            || self.asset_display != expected_asset_display || self.vault != expected_vault
            || self.next_count <= self.prior_count {
            return Err(AccumulatorError::Malformed);
        }
        let claim = verify_custody_withdrawal_inclusion(transaction, genesis_internal,
            first_index, vout, expected_asset_display, expected_vault,
            self.next_count, self.next_root, siblings)?;
        if claim.index < self.prior_count { return Err(AccumulatorError::Malformed); }
        Ok(claim)
    }
}

/// Decode the canonical USDD accumulator marker in a two-output M6.
/// This is a format check, not BIP300 approval or authentication of the marker's
/// preimage. The enclosing parent replay must authorize this exact transaction.
pub fn usdd_m6_root_marker(transaction: &bitcoin::Transaction, slot: u8)
    -> Result<Hash32, AccumulatorError> {
    if transaction.input.len() != 1 || transaction.output.len() != 2
        || transaction.is_coinbase()
        || transaction.output[0].script_pubkey.as_bytes() != [0xb4, 1, slot, 0x51]
    { return Err(AccumulatorError::Malformed); }
    let marker = transaction.output[1].script_pubkey.as_bytes();
    if marker.len() != 41 || &marker[..9] != b"\x6a\x27USDDM6\x01" {
        return Err(AccumulatorError::Malformed);
    }
    let commitment: Hash32 = marker[9..].try_into().unwrap();
    if commitment == [0;32] { return Err(AccumulatorError::NullIdentity); }
    Ok(commitment)
}

pub fn extract_withdrawals(
    transactions: &[Transaction], genesis_internal: Hash32, first_index: u64,
) -> Result<Vec<WithdrawalClaim>, AccumulatorError> {
    if genesis_internal == [0;32] { return Err(AccumulatorError::NullIdentity); }
    let mut genesis = genesis_internal; genesis.reverse();
    let mut claims = Vec::new();
    for tx in transactions {
        let mut txid = tx.txid().to_byte_array(); txid.reverse();
        for (vout, output) in tx.output.iter().enumerate() {
            let script = output.script_pubkey.as_bytes();
            if script.len() != 67 || &script[..7] != b"\x6a\x41USDD\x01" { continue; }
            let (confidential::Asset::Explicit(asset), confidential::Value::Explicit(value), confidential::Nonce::Null) =
                (output.asset, output.value, output.nonce) else { continue; };
            let mut asset = asset.into_inner().to_byte_array(); asset.reverse();
            if asset == [0;32] || value == 0 || value > i64::MAX as u64 { continue; }
            let amount = u64::from_be_bytes(script[59..67].try_into().unwrap());
            if amount == 0 || amount > 20_000_000_000_000 || amount.checked_mul(100) != Some(value) { continue; }
            let index = first_index.checked_add(claims.len().try_into().map_err(|_| AccumulatorError::Overflow)?).ok_or(AccumulatorError::Overflow)?;
            let vault: Hash32 = script[7..39].try_into().unwrap();
            let recipient: [u8;20] = script[39..59].try_into().unwrap();
            if vault == [0;32] || recipient == [0;20] { continue; }
            let vout = u32::try_from(vout).map_err(|_| AccumulatorError::Overflow)?;
            let mut preimage = BURN_DOMAIN.to_vec();
            preimage.extend_from_slice(&genesis); preimage.extend_from_slice(&txid); preimage.extend_from_slice(&vout.to_be_bytes());
            let burn_id = sha256::Hash::hash(&preimage).to_byte_array();
            let mut preimage = vec![0]; preimage.extend_from_slice(&LEAF_DOMAIN);
            preimage.extend_from_slice(&1u32.to_be_bytes());
            for h in [genesis, asset, vault, burn_id] { preimage.extend_from_slice(&h); }
            preimage.extend_from_slice(&index.to_be_bytes()); preimage.extend_from_slice(&amount.to_be_bytes()); preimage.extend_from_slice(&recipient);
            let leaf = sha256::Hash::hash(&preimage).to_byte_array();
            claims.push(WithdrawalClaim { asset_display: asset, vault, burn_txid_display: txid, vout, burn_id, index, amount_micro: amount, recipient, leaf });
        }
    }
    Ok(claims)
}

pub fn apply_withdrawals(transactions: &[Transaction], genesis_internal: Hash32, previous: &WithdrawalAccumulator)
    -> Result<(WithdrawalAccumulator, Vec<WithdrawalClaim>), AccumulatorError> {
    if !previous.is_sane() { return Err(AccumulatorError::Malformed); }
    let claims = extract_withdrawals(transactions, genesis_internal, previous.count)?;
    let mut next = previous.clone();
    for claim in &claims { next.append(claim.leaf)?; }
    Ok((next, claims))
}

/// Re-derive a custody claim from exact transaction bytes and check its native
/// accumulator inclusion. The caller must authenticate the transaction's
/// position/first index, deployment identities and approved root/count through
/// the enclosing consensus relation. This helper does not establish approval.
pub fn verify_custody_withdrawal_inclusion(
    transaction: &Transaction, genesis_internal: Hash32, first_index: u64,
    vout: u32, expected_asset_display: Hash32, expected_vault: Hash32,
    count: u64, root: Hash32, siblings: &[Hash32],
) -> Result<WithdrawalClaim, AccumulatorError> {
    if expected_asset_display == [0;32] || expected_vault == [0;32] {
        return Err(AccumulatorError::NullIdentity);
    }
    let claim = extract_withdrawals(std::slice::from_ref(transaction), genesis_internal, first_index)?
        .into_iter().find(|claim| claim.vout == vout)
        .ok_or(AccumulatorError::Malformed)?;
    if claim.asset_display != expected_asset_display || claim.vault != expected_vault {
        return Err(AccumulatorError::Malformed);
    }
    super::native_withdrawal_accumulator_v3::verify_withdrawal_membership(
        claim.leaf, claim.index, count, root, siblings,
    )?;
    Ok(claim)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn bytes(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
    #[test]
    fn root_preimage_is_packed_and_binds_every_field() {
        let root = UsddRootTransitionV1 {
            parent_genesis_display: [1;32], elements_genesis_display: [2;32],
            asset_display: [3;32], vault: [4;32],
            prior_count: 0x0102030405060708, prior_root: [5;32],
            next_count: 0x1112131415161718, next_root: [6;32],
        };
        let mut expected = bytes("0621633c45a9c03ea66059a6ae5a530aa8cb8a6bc3ed5fd94cdd932a71579444");
        expected.push(24);
        for value in 1..=4 { expected.extend_from_slice(&[value;32]); }
        expected.extend_from_slice(&[1,2,3,4,5,6,7,8]);
        expected.extend_from_slice(&[5;32]);
        expected.extend_from_slice(&[17,18,19,20,21,22,23,24]);
        expected.extend_from_slice(&[6;32]);
        assert_eq!(root.preimage().as_slice(), expected);
        assert_eq!(root.commitment(), sha256::Hash::hash(&expected).to_byte_array());
        for offset in [33,65,97,129,161,169,201,209] {
            let mut changed = expected.clone(); changed[offset] ^= 1;
            assert_ne!(root.commitment(), sha256::Hash::hash(&changed).to_byte_array());
        }
    }
    #[test]
    fn native_m6_root_fixture_and_format_substitutions() {
        let raw = bytes("02000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201000700000000ffffffff02272300000000000004b40118510100000000000000296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e8fc8717e3f7974186b36700000000");
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(usdd_m6_root_marker(&tx,24).unwrap().as_slice(), bytes("dd6833a6a2db112477ab453d2886af0c9154de56f5e8fc8717e3f7974186b367"));
        assert!(usdd_m6_root_marker(&tx,25).is_err());
        let mut bad = tx.clone(); bad.output.swap(0,1);
        assert!(usdd_m6_root_marker(&bad,24).is_err());
        bad = tx.clone(); bad.output.push(tx.output[1].clone());
        assert!(usdd_m6_root_marker(&bad,24).is_err());
        bad = tx.clone();
        let mut script = vec![0x6a,0x4c,39]; script.extend_from_slice(&tx.output[1].script_pubkey.as_bytes()[2..]);
        bad.output[1].script_pubkey = bitcoin::ScriptBuf::from_bytes(script);
        assert!(usdd_m6_root_marker(&bad,24).is_err());
        bad = tx.clone();
        let mut script = tx.output[1].script_pubkey.as_bytes().to_vec(); script[8] = 2;
        bad.output[1].script_pubkey = bitcoin::ScriptBuf::from_bytes(script);
        assert!(usdd_m6_root_marker(&bad,24).is_err());
    }
    pub(crate) fn fixture() -> (Transaction, Hash32) {
        let raw = bytes("0200000000000201ffeeddccbbaa99887766554433221100ffeeddccbbaa00998877665544332211010000000004a19ba000436a415553444401101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000000000000000000beef00000000000bdb2801ffeeddccbbaa99887766554433221100ffeeddccbbaa009988776655443322110100000000054afb0000436a415553444401101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f111122223333444455556666777788889999aaaa00000000000d8cc000000000");
        let mut genesis: Hash32 = bytes("3336884b616fb495e5faedc77be45bf2951b9d7d0887aaafd2f54873a8ddb1d6").try_into().unwrap(); genesis.reverse();
        (elements::encode::deserialize(&raw).unwrap(), genesis)
    }
    #[test]
    fn exact_native_transaction_and_claim_vectors() {
        let (tx, genesis) = fixture();
        let (next, claims) = apply_withdrawals(&[tx],genesis,&WithdrawalAccumulator::empty()).unwrap();
        assert_eq!(claims.len(),2); assert_eq!(next.count,2);
        assert_eq!(claims[0].burn_txid_display.as_slice(), bytes("f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab2"));
        assert_eq!(claims[0].leaf.as_slice(),bytes("8a4be6c5cc7da678d45e2b6beea0f2cd65bb6afc4d0ef7542ab2ccf12110c13f"));
        assert_eq!(claims[1].leaf.as_slice(),bytes("411d36323ee653bda6c17167e4321e2437ae288a42e7786bed84832ba7baa7ec"));
        assert_eq!((claims[0].index, claims[1].index, claims[1].vout),(0,1,1));
    }
    #[test]
    fn invalid_amount_and_nonminimal_script_are_ignored() {
        let (mut tx, genesis) = fixture();
        tx.output[0].value = confidential::Value::Explicit(1);
        assert_eq!(extract_withdrawals(&[tx.clone()],genesis,7).unwrap()[0].index,7);
        let raw = tx.output[1].script_pubkey.as_bytes();
        let mut alias = vec![0x6a,0x4c,65]; alias.extend_from_slice(&raw[2..]);
        tx.output[1].script_pubkey = elements::Script::from(alias);
        assert!(extract_withdrawals(&[tx],genesis,0).unwrap().is_empty());
    }
    #[test]
    fn custody_v2_payload_is_not_a_native_v1_accumulator_claim() {
        let (mut tx, genesis) = fixture();
        // USDDVaultV2's payload has the same length but version 2 and a
        // custody ID, not the native version-1 vault identifier. Never
        // relabel it to obtain a native accumulator inclusion witness.
        for output in &mut tx.output {
            let mut script = output.script_pubkey.as_bytes().to_vec();
            assert_eq!(&script[..7], b"\x6a\x41USDD\x01");
            script[6] = 2;
            output.script_pubkey = elements::Script::from(script);
        }
        let previous = WithdrawalAccumulator::empty();
        let (next, claims) = apply_withdrawals(&[tx.clone()], genesis, &previous).unwrap();
        assert!(claims.is_empty());
        assert_eq!(next.count, previous.count);
        assert_eq!(next.root, previous.root);
        assert!(verify_custody_withdrawal_inclusion(&tx, genesis, 0, 0,
            [1;32], [2;32], 1, [3;32], &[[0;32];64]).is_err());
    }
    #[test]
    fn claim_index_overflow_fails() {
        let (tx,genesis) = fixture();
        assert_eq!(extract_withdrawals(&[tx],genesis,u64::MAX),Err(AccumulatorError::Overflow));
    }

    #[test]
    fn custody_inclusion_rederives_claim_and_rejects_wrong_deployment() {
        use bitcoin::hashes::{sha256, Hash};
        let (tx, genesis) = fixture();
        let (state, claims) = apply_withdrawals(&[tx.clone()], genesis, &WithdrawalAccumulator::empty()).unwrap();
        let mut empty = sha256::Hash::hash(&[0]).to_byte_array();
        let mut path = vec![claims[1].leaf];
        for level in 0..63 {
            let mut bytes = vec![1]; bytes.extend_from_slice(&empty); bytes.extend_from_slice(&empty);
            empty = sha256::Hash::hash(&bytes).to_byte_array();
            path.push(empty);
            assert_eq!(path.len(), level + 2);
        }
        let verify = |transaction: &Transaction, asset, vault, first, output| verify_custody_withdrawal_inclusion(
            transaction, genesis, first, output, asset, vault, state.count, state.root, &path,
        );
        let c = &claims[0];
        let mut genesis_display = genesis; genesis_display.reverse();
        let root = UsddRootTransitionV1 {
            parent_genesis_display: [1;32], elements_genesis_display: genesis_display,
            asset_display: c.asset_display, vault: c.vault, prior_count: 0,
            prior_root: WithdrawalAccumulator::empty().root,
            next_count: state.count, next_root: state.root,
        };
        let check_batch = |r: &UsddRootTransitionV1| r.verify_introduced_claim(
            &tx, genesis, 0, 0, [1;32], c.asset_display, c.vault, &path);
        assert_eq!(check_batch(&root).unwrap(), *c);
        // The same valid membership must not redeem against a later batch.
        let mut later = root.clone(); later.prior_count = 1;
        assert!(check_batch(&later).is_err());
        for field in 0..4 {
            let mut bad = root.clone();
            match field {
                0 => bad.parent_genesis_display[0] ^= 1,
                1 => bad.elements_genesis_display[0] ^= 1,
                2 => bad.asset_display[0] ^= 1,
                _ => bad.vault[0] ^= 1,
            }
            assert!(check_batch(&bad).is_err());
        }
        assert_eq!(verify(&tx, c.asset_display, c.vault, 0, 0).unwrap(), *c);
        assert!(verify(&tx, [9;32], c.vault, 0, 0).is_err());
        assert!(verify(&tx, c.asset_display, [9;32], 0, 0).is_err());
        assert!(verify(&tx, c.asset_display, c.vault, 1, 0).is_err());
        assert!(verify(&tx, c.asset_display, c.vault, 0, 2).is_err());
        let mut changed = tx.clone();
        let mut script = changed.output[0].script_pubkey.as_bytes().to_vec();
        script[39] ^= 1;
        changed.output[0].script_pubkey = elements::Script::from(script);
        assert!(verify(&changed, c.asset_display, c.vault, 0, 0).is_err());
        changed = tx.clone(); changed.output[0].value = confidential::Value::Explicit(1);
        assert!(verify(&changed, c.asset_display, c.vault, 0, 0).is_err());
    }
}
