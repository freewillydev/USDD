//! Native deposit witness, recipient, balance and atomic spent-claim transition.
//! Parent authentication and frozen configuration remain enclosing-block duties.

use crate::conversion_parent_link_v3::AuthenticatedAlphaDepositV3;
use elements::{confidential::{Asset, Value}, AssetId, Script, TxOut};
use bitcoin::hashes::Hash as _;
use ecx_full_consensus_validator_v2::bip300_v2::Bip300DepositV2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeDepositOutputErrorV3 {
    #[error("native Alpha deposit witness does not match the authenticated M5 effect")]
    Witness,
    #[error("deposit address is invalid or belongs to another child address profile")]
    Address,
    #[error("deposit recipient must receive exactly the full explicit pegged amount once")]
    Recipient,
    #[error("native deposit sponsor inputs or confidential balance are invalid")]
    Balance,
}

/// Inputs to the native deposit kernel. All configuration values must originate
/// in the frozen child configuration, not transaction-controlled overrides.
pub struct NativeDepositKernelV3<'a> {
    pub deposit: &'a AuthenticatedAlphaDepositV3,
    pub pegged_asset: AssetId,
    pub parent_genesis_internal: [u8;32],
    pub address_params: &'a elements::AddressParams,
}

/// Deposit component only; the enclosing reviewed configuration must commit
/// this hash alongside its other consensus and program settings.
pub fn deposit_configuration_commitment_v3(
    asset: AssetId, parent_genesis: [u8;32],
    params: &elements::AddressParams, minimum_depth: u32,
) -> Option<[u8;32]> {
    let asset = asset.into_inner().to_byte_array();
    if asset == [0;32] || parent_genesis == [0;32] { return None; }
    let mut bytes = vec![3];
    bytes.extend_from_slice(&asset);
    bytes.extend_from_slice(&parent_genesis);
    bytes.extend_from_slice(&minimum_depth.max(1).to_be_bytes());
    bytes.extend_from_slice(&[params.p2pkh_prefix,params.p2sh_prefix,params.blinded_prefix]);
    for hrp in [params.bech_hrp.as_str(),params.blech_hrp.as_str()] {
        bytes.extend_from_slice(&u32::try_from(hrp.len()).ok()?.to_be_bytes());
        bytes.extend_from_slice(hrp.as_bytes());
    }
    Some(crate::tagged_hash("ECX/alpha-native-deposit-configuration/v3", &bytes))
}
impl ecx_full_consensus_validator_v2::elements_v2::NativeDepositKernelVerifierV3
    for NativeDepositKernelV3<'_> {
    fn verify_kernel(&self, transaction: &elements::Transaction, sponsors: &[TxOut])
        -> Result<TxOut,ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
        use ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2;
        let previous=verify_native_deposit_kernel_v3(self.deposit,transaction,sponsors,
            self.pegged_asset,self.parent_genesis_internal,self.address_params)
            .map_err(|_|ElementsStateErrorV2::DrivechainDeposit)?;
        let index=transaction.input.iter().position(|input|input.is_pegin)
            .ok_or(ElementsStateErrorV2::DrivechainDeposit)?;
        Ok(previous[index].clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeDepositStateErrorV3 {
    Transaction(ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2),
    Claim(crate::native_claims_v3::ClaimError),
}

/// Atomic native transaction and spent-claim transition. The enclosing block
/// executor must authenticate both predecessor roots, frozen configuration,
/// parent ancestry and required confirmation depth. No partial root is returned
/// if either transaction execution or absence authentication fails.
#[allow(clippy::too_many_arguments)]
pub fn apply_native_deposit_and_claim_v3<V: ecx_full_consensus_validator_v2::elements_v2::ElementsInputVerifierV2>(
    transaction: &elements::Transaction,
    context: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionSpendContextV2,
    initial: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionStateRootsV2,
    claims_root: [u8;32], claim_path: &[[u8;32]],
    utxo: &ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionUtxoWitnessV2,
    economic: &ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionEconomicWitnessV2,
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2,
    input_verifier: &V, kernel: &NativeDepositKernelV3<'_>,
    policy: ecx_full_consensus_validator_v2::elements_v2::NativeElementsLockPolicyV3,
) -> Result<(ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionStateRootsV2,[u8;32]),NativeDepositStateErrorV3> {
    let roots=ecx_full_consensus_validator_v2::elements_v2::apply_native_deposit_state_v3(
        transaction,context,initial,utxo,economic,classification,input_verifier,kernel,policy)
        .map_err(NativeDepositStateErrorV3::Transaction)?;
    let input=transaction.input.iter().find(|input|input.is_pegin)
        .ok_or(NativeDepositStateErrorV3::Transaction(
            ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2::DrivechainDeposit))?;
    let next_claims=crate::native_claims_v3::insert(claims_root,input.previous_output,claim_path)
        .map_err(NativeDepositStateErrorV3::Claim)?;
    Ok((roots,next_claims))
}

/// Custody accounting variant preserves native asset authentication and the
/// spent-claim insertion. Confirmation and frozen parent bindings are still
/// mandatory at the enclosing block boundary, as in the legacy counterpart.
#[allow(clippy::too_many_arguments)]
pub fn apply_native_deposit_and_custody_claim_v3<V: ecx_full_consensus_validator_v2::elements_v2::ElementsInputVerifierV2>(
    transaction: &elements::Transaction,
    context: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionSpendContextV2,
    initial: ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyRootsV3,
    claims_root: [u8;32], claim_path: &[[u8;32]],
    utxo: &ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionUtxoWitnessV2,
    custody: &ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyWitnessV3,
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsCustodyClassificationV3,
    input_verifier: &V, kernel: &NativeDepositKernelV3<'_>,
    policy: ecx_full_consensus_validator_v2::elements_v2::NativeElementsLockPolicyV3,
) -> Result<(ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionCustodyRootsV3,[u8;32]),NativeDepositStateErrorV3> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    classification.commitment().map_err(NativeDepositStateErrorV3::Transaction)?;
    if kernel.pegged_asset.into_inner().to_byte_array() != classification.native_pegged_asset_id {
        return Err(NativeDepositStateErrorV3::Transaction(ElementsStateErrorV2::DrivechainDeposit));
    }
    let roots = apply_native_deposit_custody_state_v3(transaction, context, initial,
        utxo, custody, classification, input_verifier, kernel, policy)
        .map_err(NativeDepositStateErrorV3::Transaction)?;
    let input = transaction.input.iter().find(|input| input.is_pegin)
        .ok_or(NativeDepositStateErrorV3::Transaction(ElementsStateErrorV2::DrivechainDeposit))?;
    let next_claims = crate::native_claims_v3::insert(claims_root, input.previous_output, claim_path)
        .map_err(NativeDepositStateErrorV3::Claim)?;
    Ok((roots, next_claims))
}

/// Native witness/recipient plus asset conservation. Sponsor prevouts must be
/// authenticated against the predecessor UTXO root, in non-peg-in input order.
/// Returns the complete input-order prevout vector for signature verification.
/// Claim insertion, confirmations, signatures and UTXO mutations remain the
/// enclosing transaction executor's obligations.
pub fn verify_native_deposit_kernel_v3(
    deposit: &AuthenticatedAlphaDepositV3,
    transaction: &elements::Transaction,
    sponsor_prevouts: &[TxOut],
    pegged_asset: AssetId,
    parent_genesis_internal: [u8;32],
    address_params: &elements::AddressParams,
) -> Result<Vec<TxOut>, NativeDepositOutputErrorV3> {
    verify_native_deposit_witness_and_outputs_v3(deposit, transaction, pegged_asset,
        parent_genesis_internal, address_params)?;
    check_balance(transaction, sponsor_prevouts, pegged_asset, deposit.deposit().value_sat)
}

fn check_balance(transaction: &elements::Transaction, sponsors: &[TxOut],
    asset: AssetId, amount: u64) -> Result<Vec<TxOut>, NativeDepositOutputErrorV3> {
    use elements::confidential::Nonce;
    let error=NativeDepositOutputErrorV3::Balance;
    if transaction.input.iter().filter(|input|input.is_pegin).count()!=1
        || transaction.input.iter().any(|input|input.has_issuance())
        || sponsors.len()+1!=transaction.input.len() { return Err(error); }
    let mut sponsors=sponsors.iter();
    let mut previous=Vec::with_capacity(transaction.input.len());
    for input in &transaction.input {
        previous.push(if input.is_pegin {
            TxOut { asset:Asset::Explicit(asset), value:Value::Explicit(amount),
                nonce:Nonce::Null, script_pubkey:Script::from(vec![0x51]),
                witness:Default::default() }
        } else { sponsors.next().ok_or(error)?.clone() });
    }
    for output in &transaction.output {
        if output.script_pubkey.is_empty() &&
            (!matches!(output.asset,Asset::Explicit(_)) || !matches!(output.value,Value::Explicit(_))
                || output.nonce!=Nonce::Null || !output.witness.is_empty()) { return Err(error); }
    }
    transaction.verify_tx_amt_proofs(&elements::secp256k1_zkp::Secp256k1::new(),&previous)
        .map_err(|_|error)?;
    Ok(previous)
}

/// Verify the native eight-item witness and exact recipient rule together.
/// Does not establish confirmation depth, absence of a prior claim, sponsor
/// authorization, ordinary UTXO validity or confidential asset conservation.
pub fn verify_native_deposit_witness_and_outputs_v3(
    deposit: &AuthenticatedAlphaDepositV3,
    transaction: &elements::Transaction,
    pegged_asset: AssetId,
    parent_genesis_internal: [u8; 32],
    address_params: &elements::AddressParams,
) -> Result<(), NativeDepositOutputErrorV3> {
    let mut pegins = transaction.input.iter().filter(|input| input.is_pegin);
    let input = pegins.next().ok_or(NativeDepositOutputErrorV3::Witness)?;
    if pegins.next().is_some() { return Err(NativeDepositOutputErrorV3::Witness); }
    check_witness(deposit.deposit(), input, pegged_asset, parent_genesis_internal)?;
    verify_native_deposit_recipient_v3(deposit, &transaction.output, pegged_asset, address_params)
}

fn check_witness(
    deposit: &Bip300DepositV2,
    input: &elements::TxIn,
    asset: AssetId,
    genesis: [u8; 32],
) -> Result<(), NativeDepositOutputErrorV3> {
    let stack = &input.witness.pegin_witness;
    let error = NativeDepositOutputErrorV3::Witness;
    if !input.is_pegin || input.has_issuance()
        || input.previous_output.txid.to_byte_array() != deposit.outpoint.outpoint.txid.to_byte_array()
        || input.previous_output.vout != deposit.outpoint.outpoint.vout
        || deposit.value_sat == 0 || deposit.value_sat > 21_000_000 * 100_000_000
        || stack.len() != 8
    { return Err(error); }
    if stack[0] != deposit.value_sat.to_le_bytes()
        || stack[1] != asset.into_inner().to_byte_array()
        || stack[2] != genesis
        || stack[3] != [0x51]
        || stack[4] != b"drivechain-deposit-v2"
        || stack[5] != deposit.outpoint.outpoint.txid.to_byte_array()
        || stack[6] != deposit.block_hash.to_byte_array()
        || stack[7] != deposit.address
        || stack[7].is_empty() || stack[7].len() > 128
    { return Err(error); }
    Ok(())
}

/// Address parameters and pegged asset must be derived from the independently
/// frozen child configuration; this helper cannot authenticate that configuration.
pub fn verify_native_deposit_recipient_v3(
    deposit: &AuthenticatedAlphaDepositV3,
    outputs: &[TxOut],
    pegged_asset: AssetId,
    address_params: &elements::AddressParams,
) -> Result<(), NativeDepositOutputErrorV3> {
    let text = std::str::from_utf8(&deposit.deposit().address)
        .map_err(|_| NativeDepositOutputErrorV3::Address)?;
    let script = native_deposit_address_script_v3(text, address_params)?;
    check_recipient(outputs, pegged_asset, &script, deposit.deposit().value_sat)
}

/// Decode with the supplied profile rather than the three built-in Elements
/// networks. `Address::parse_with_params` requires a static profile, although
/// decoding a script does not: keep the profile borrowed so owned guest inputs
/// need no leaked allocation. The same checksum/version/length decoders used by
/// rust-elements validate the witness encodings. Base58 prefixes are checked
/// before constructing the corresponding script, including the inner prefix
/// and compressed public key of a confidential address.
fn native_deposit_address_script_v3(
    text: &str, params: &elements::AddressParams,
) -> Result<Script, NativeDepositOutputErrorV3> {
    use elements::{opcodes::all, script::Builder};
    let error = NativeDepositOutputErrorV3::Address;
    // A native deposit's committed address field is limited to 128 bytes.
    if text.is_empty() || text.len() > 128 { return Err(error); }
    let prefix = text.rsplit_once('1').map_or(text, |(prefix, _)| prefix);
    let blinded = prefix.eq_ignore_ascii_case(params.blech_hrp.as_str());
    let explicit = prefix.eq_ignore_ascii_case(params.bech_hrp.as_str());
    if blinded || explicit {
        let (version, data) = if blinded {
            let decoded = elements::blech32::decode::SegwitHrpstring::new(text)
                .map_err(|_| error)?;
            if decoded.hrp() != params.blech_hrp { return Err(error); }
            (decoded.witness_version().to_u8(), decoded.byte_iter().collect::<Vec<u8>>())
        } else {
            let decoded = bitcoin::bech32::primitives::decode::SegwitHrpstring::new(text)
                .map_err(|_| error)?;
            if decoded.hrp() != params.bech_hrp { return Err(error); }
            (decoded.witness_version().to_u8(), decoded.byte_iter().collect::<Vec<u8>>())
        };
        let program = if blinded {
            if data.len() < 33 { return Err(error); }
            let (key, program) = data.split_at(33);
            elements::secp256k1_zkp::PublicKey::from_slice(key).map_err(|_| error)?;
            program
        } else { data.as_slice() };
        return Ok(Builder::new().push_int(i64::from(version)).push_slice(program).into_script());
    }
    let data = bitcoin::base58::decode_check(text).map_err(|_| error)?;
    let (outer_prefix, rest) = data.split_first().ok_or(error)?;
    let (prefix, hash) = if *outer_prefix == params.blinded_prefix {
        if rest.len() != 54 { return Err(error); }
        let (prefix, key_and_hash) = rest.split_first().ok_or(error)?;
        let (key, hash) = key_and_hash.split_at(33);
        elements::secp256k1_zkp::PublicKey::from_slice(key).map_err(|_| error)?;
        (*prefix, hash)
    } else {
        if rest.len() != 20 { return Err(error); }
        (*outer_prefix, rest)
    };
    let builder = if prefix == params.p2pkh_prefix {
        Builder::new().push_opcode(all::OP_DUP).push_opcode(all::OP_HASH160)
            .push_slice(hash).push_opcode(all::OP_EQUALVERIFY).push_opcode(all::OP_CHECKSIG)
    } else if prefix == params.p2sh_prefix {
        Builder::new().push_opcode(all::OP_HASH160).push_slice(hash).push_opcode(all::OP_EQUAL)
    } else { return Err(error); };
    Ok(builder.into_script())
}

fn check_recipient(
    outputs: &[TxOut], asset: AssetId, script: &Script, amount: u64,
) -> Result<(), NativeDepositOutputErrorV3> {
    let error = NativeDepositOutputErrorV3::Recipient;
    if amount == 0 { return Err(error); }
    let mut matching = outputs.iter().filter(|output| &output.script_pubkey == script);
    let output = matching.next().ok_or(error)?;
    if matching.next().is_some()
        || output.asset != Asset::Explicit(asset)
        || output.value != Value::Explicit(amount)
        || output.nonce.is_confidential()
    {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // These are encoding parameters from the Alpha node's identity, not a
    // receiving address or an implicit production configuration.
    const ALPHA_ADDRESS_TEST_PARAMS: elements::AddressParams = elements::AddressParams {
        p2pkh_prefix: 68, p2sh_prefix: 13, blinded_prefix: 6,
        bech_hrp: bitcoin::bech32::Hrp::parse_unchecked("elements"),
        blech_hrp: bitcoin::bech32::Hrp::parse_unchecked("elementsl"),
    };

    #[test]
    fn owned_custom_profile_decodes_all_address_forms_to_the_same_script() {
        let key = elements::secp256k1_zkp::PublicKey::from_secret_key(
            &elements::secp256k1_zkp::Secp256k1::new(),
            &elements::secp256k1_zkp::SecretKey::from_slice(&[1;32]).unwrap());
        let scripts = [
            [&[0x76,0xa9,0x14][..], &[7;20], &[0x88,0xac]].concat(),
            [&[0xa9,0x14][..], &[7;20], &[0x87]].concat(),
            [&[0,20][..], &[7;20]].concat(),
            [&[0,32][..], &[7;32]].concat(),
            [&[0x51,32][..], &[7;32]].concat(),
        ];
        // `owned` deliberately does not have static lifetime.
        let owned = ALPHA_ADDRESS_TEST_PARAMS.clone();
        for bytes in scripts {
            let script = Script::from(bytes);
            for blinder in [None, Some(key)] {
                let address = elements::Address::from_script(
                    &script, blinder, &ALPHA_ADDRESS_TEST_PARAMS).unwrap();
                let text = address.to_string();
                assert_eq!(native_deposit_address_script_v3(&text, &owned), Ok(script.clone()));
                assert_eq!(elements::Address::parse_with_params(&text, &ALPHA_ADDRESS_TEST_PARAMS)
                    .unwrap().script_pubkey(), script);
                assert!(native_deposit_address_script_v3(
                    &text, &elements::AddressParams::ELEMENTS).is_err());
                assert!(native_deposit_address_script_v3(
                    &text, &elements::AddressParams::LIQUID).is_err());
                let mut corrupted = text.into_bytes();
                let last = corrupted.last_mut().unwrap();
                *last = if *last == b'q' { b'p' } else { b'q' };
                assert!(native_deposit_address_script_v3(
                    std::str::from_utf8(&corrupted).unwrap(), &owned).is_err());
            }
        }
    }

    #[test]
    fn custom_profile_rejects_wrong_prefixes_and_invalid_blinding_keys() {
        let owned = ALPHA_ADDRESS_TEST_PARAMS.clone();
        let script = Script::from([&[0,20][..], &[7;20]].concat());
        let address = elements::Address::from_script(&script, None, &ALPHA_ADDRESS_TEST_PARAMS)
            .unwrap().to_string();
        assert_eq!(native_deposit_address_script_v3(&address.to_ascii_uppercase(), &owned), Ok(script));
        let mut mixed = address.clone().into_bytes();
        mixed[0] = mixed[0].to_ascii_uppercase();
        assert!(native_deposit_address_script_v3(std::str::from_utf8(&mixed).unwrap(), &owned).is_err());
        let mut wrong_hrp = owned.clone();
        wrong_hrp.bech_hrp = bitcoin::bech32::Hrp::parse("other").unwrap();
        assert!(native_deposit_address_script_v3(&address, &wrong_hrp).is_err());
        // Valid Base58 checksums do not compensate for another profile, an
        // invalid inner prefix, or an invalid compressed blinding key.
        let plain = [&[owned.p2pkh_prefix][..], &[7;20]].concat();
        let mut wrong_prefix = owned.clone();
        wrong_prefix.p2pkh_prefix ^= 1;
        assert!(native_deposit_address_script_v3(
            &bitcoin::base58::encode_check(&plain), &wrong_prefix).is_err());
        let mut confidential = [&[owned.blinded_prefix, owned.p2pkh_prefix][..], &[0;33], &[7;20]].concat();
        assert!(native_deposit_address_script_v3(
            &bitcoin::base58::encode_check(&confidential), &owned).is_err());
        let key = elements::secp256k1_zkp::PublicKey::from_secret_key(
            &elements::secp256k1_zkp::Secp256k1::new(),
            &elements::secp256k1_zkp::SecretKey::from_slice(&[1;32]).unwrap());
        confidential[2..35].copy_from_slice(&key.serialize());
        confidential[1] ^= 1;
        assert!(native_deposit_address_script_v3(
            &bitcoin::base58::encode_check(&confidential), &owned).is_err());
        assert!(native_deposit_address_script_v3("", &owned).is_err());
        assert!(native_deposit_address_script_v3(&"x".repeat(129), &owned).is_err());
    }

    #[test]
    fn deposit_configuration_binds_every_parameter() {
        use super::*;
        let asset = AssetId::from_slice(&[7;32]).unwrap();
        let params = elements::AddressParams::ELEMENTS;
        let commit = |asset, genesis, params: &elements::AddressParams, depth|
            deposit_configuration_commitment_v3(asset,genesis,params,depth);
        let frozen = commit(asset,[8;32],&params,1).unwrap();
        assert_eq!(commit(asset,[8;32],&params,0),Some(frozen));
        assert_ne!(commit(asset,[9;32],&params,1),Some(frozen));
        assert_ne!(commit(AssetId::from_slice(&[9;32]).unwrap(),[8;32],&params,1),Some(frozen));
        assert_ne!(commit(asset,[8;32],&params,2),Some(frozen));
        for field in 0..5 {
            let mut changed = params.clone();
            match field {
                0 => changed.p2pkh_prefix ^= 1,
                1 => changed.p2sh_prefix ^= 1,
                2 => changed.blinded_prefix ^= 1,
                3 => changed.bech_hrp = elements::AddressParams::LIQUID.bech_hrp,
                _ => changed.blech_hrp = elements::AddressParams::LIQUID.blech_hrp,
            }
            assert_ne!(commit(asset,[8;32],&changed,1),Some(frozen));
        }
        assert_eq!(commit(asset,[0;32],&params,1),None);
        assert_eq!(commit(AssetId::from_slice(&[0;32]).unwrap(),[8;32],&params,1),None);
    }
    use super::*;
    use elements::confidential::Nonce;

    #[test]
    fn sponsors_pay_fees_without_creating_value_and_input_order_is_preserved() {
        let asset=AssetId::from_slice(&[1;32]).unwrap();
        let recipient=TxOut {asset:Asset::Explicit(asset),value:Value::Explicit(1000),
            nonce:Nonce::Null,script_pubkey:Script::from(vec![0x51]),witness:Default::default()};
        let sponsor=TxOut {value:Value::Explicit(10),..recipient.clone()};
        let fee=TxOut {script_pubkey:Script::new(),..sponsor.clone()};
        let pegin=elements::TxIn {is_pegin:true,..Default::default()};
        let mut tx=elements::Transaction {version:2,lock_time:elements::LockTime::ZERO,
            input:vec![elements::TxIn::default(),pegin],output:vec![recipient.clone(),fee]};
        let previous=check_balance(&tx,&[sponsor.clone()],asset,1000).unwrap();
        assert_eq!(previous[0],sponsor);
        assert_eq!(previous[1].value,Value::Explicit(1000));
        assert!(check_balance(&tx,&[],asset,1000).is_err());
        let mut wrong=sponsor.clone();wrong.value=Value::Explicit(9);
        assert!(check_balance(&tx,&[wrong],asset,1000).is_err());
        let mut wrong=sponsor.clone();wrong.asset=Asset::Explicit(AssetId::from_slice(&[2;32]).unwrap());
        assert!(check_balance(&tx,&[wrong],asset,1000).is_err());
        tx.output[0].value=Value::Explicit(1001);
        assert!(check_balance(&tx,&[sponsor.clone()],asset,1000).is_err());
        tx.output[0]=recipient;
        tx.input.swap(0,1);
        let previous=check_balance(&tx,&[sponsor],asset,1000).unwrap();
        assert_eq!(previous[0].value,Value::Explicit(1000));
        assert_eq!(previous[1].value,Value::Explicit(10));
    }

    #[test]
    fn witness_binds_every_native_field_and_rejects_other_formats() {
        use ecx_full_consensus_validator_v2::bip300_v2::Bip300CtipV2;
        let asset = AssetId::from_slice(&[1;32]).unwrap();
        let genesis = [2;32];
        let txid = bitcoin::Txid::from_byte_array([3;32]);
        let deposit = Bip300DepositV2 {
            slot: 24, prior_ctip: None,
            outpoint: Bip300CtipV2 { outpoint: bitcoin::OutPoint { txid, vout: 2 }, value_sat: 1000, sequence: 0 },
            block_hash: bitcoin::BlockHash::from_byte_array([4;32]),
            block_height: 1_000_000, value_sat: 1000, address: b"test-address".to_vec(),
        };
        let mut input = elements::TxIn::default();
        input.is_pegin = true;
        input.previous_output = elements::OutPoint { txid: elements::Txid::from_byte_array([3;32]), vout: 2 };
        input.witness.pegin_witness = vec![
            1000u64.to_le_bytes().to_vec(), vec![1;32], genesis.to_vec(), vec![0x51],
            b"drivechain-deposit-v2".to_vec(), vec![3;32], vec![4;32], b"test-address".to_vec(),
        ];
        assert_eq!(check_witness(&deposit, &input, asset, genesis), Ok(()));
        for index in 0..8 {
            let mut changed = input.clone();
            changed.witness.pegin_witness[index][0] ^= 1;
            assert!(check_witness(&deposit, &changed, asset, genesis).is_err(), "field {index}");
        }
        for size in [6, 11] {
            let mut changed = input.clone();
            changed.witness.pegin_witness.resize(size, vec![]);
            assert!(check_witness(&deposit, &changed, asset, genesis).is_err());
        }
        input.previous_output.vout = 0;
        assert!(check_witness(&deposit, &input, asset, genesis).is_err());
    }

    #[test]
    fn full_deposit_is_not_reduced_by_fees_and_sponsor_outputs_are_allowed() {
        let asset = AssetId::from_slice(&[1;32]).unwrap();
        let script = Script::from(vec![0x51]);
        let recipient = TxOut {
            asset: Asset::Explicit(asset), value: Value::Explicit(1000),
            nonce: Nonce::Null, script_pubkey: script.clone(), witness: Default::default(),
        };
        assert_eq!(check_recipient(&[recipient.clone()], asset, &script, 1000), Ok(()));
        let fee = TxOut { value: Value::Explicit(10), script_pubkey: Script::new(), ..recipient.clone() };
        assert_eq!(check_recipient(&[recipient.clone(), fee], asset, &script, 1000), Ok(()));
        let reduced = TxOut { value: Value::Explicit(990), ..recipient.clone() };
        assert!(check_recipient(&[reduced], asset, &script, 1000).is_err());
        assert!(check_recipient(&[recipient.clone(), recipient.clone()], asset, &script, 1000).is_err());
        assert!(check_recipient(&[], asset, &script, 1000).is_err());
        let wrong_asset = TxOut { asset: Asset::Explicit(AssetId::from_slice(&[2;32]).unwrap()), ..recipient };
        assert!(check_recipient(&[wrong_asset], asset, &script, 1000).is_err());
    }
}
