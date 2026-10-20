//! Transaction-derived Truthcoin authority journal.
//! Renders state scripts but does not qualify the CMR or authenticate replay.
//! The enclosing guest must verify successor source
//! fields; the leaf must match the journal against actual transaction jets.
use super::*;
use elements::Script;
use ecx_protocol_core::truthcoin_authority_journal::{InputBinding, TruthcoinAuthorityJournalV1};

pub struct AuthorityScript {
    pub script: Script,
    pub control_block: Vec<u8>,
    pub state_node: Hash32,
}

/// Exact leaf-plus-state topology, with the fixed keyless Truthcoin domain/key.
/// The CMR must come from the qualified authority compiler; this function does
/// not establish the provenance or behavior of the supplied program.
pub fn render_authority_script(
    state: &TruthcoinAnchorStateV1, authority_cmr: Hash32,
) -> Result<AuthorityScript, String> {
    use ecx_protocol_core::truthcoin_authority_policy::{STATE_DOMAIN, KEYLESS_INTERNAL_KEY};
    use elements::hashes::sha256;
    use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
    use elements::taproot::{LeafVersion, TaprootBuilder};
    state.validate().map_err(|e| e.to_string())?;
    if authority_cmr == [0;32] { return Err("missing authority CMR".into()); }
    let mut preimage = Sha256::digest(STATE_DOMAIN).to_vec();
    preimage.extend_from_slice(&state.configuration_hash);
    preimage.extend_from_slice(&state.commitment());
    let state_node = sha256::Hash::hash(&preimage);
    let leaf = Script::from(authority_cmr.to_vec());
    let version = LeafVersion::from_u8(0xbe).map_err(|e| e.to_string())?;
    let key = XOnlyPublicKey::from_slice(&KEYLESS_INTERNAL_KEY).map_err(|e| e.to_string())?;
    let secp = Secp256k1::verification_only();
    let spend = TaprootBuilder::new()
        .add_leaf_with_ver(1, leaf.clone(), version).map_err(|e| e.to_string())?
        .add_hidden(1, state_node).map_err(|e| e.to_string())?
        .finalize(&secp, key).map_err(|_| "invalid authority tree")?;
    let root = spend.merkle_root().ok_or("missing authority root")?;
    let control = spend.control_block(&(leaf.clone(), version)).ok_or("missing authority control")?;
    if !control.verify_taproot_commitment(&secp, &spend.output_key(), &leaf) {
        return Err("authority control verification failed".into());
    }
    Ok(AuthorityScript { script: Script::new_v1_p2tr(&secp, key, Some(root)),
        control_block: control.serialize(), state_node: state_node.to_byte_array() })
}

/// Derive descriptors instead of accepting caller-selected script hashes.
pub fn rendered_scripts(
    prior: &TruthcoinAnchorStateV1, successor: &TruthcoinAnchorStateV1,
    authority_cmr: Hash32, sponsor_script: &Script,
) -> Result<TruthcoinAnchorAuthorityScriptsV1, String> {
    let old = render_authority_script(prior, authority_cmr)?;
    let new = render_authority_script(successor, authority_cmr)?;
    Ok(TruthcoinAnchorAuthorityScriptsV1 {
        prior_state_commitment: prior.commitment(),
        successor_state_commitment: successor.commitment(),
        prior_script_sha256: Sha256::digest(old.script.as_bytes()).into(),
        successor_script_sha256: Sha256::digest(new.script.as_bytes()).into(),
        sponsor_change_script_sha256: Sha256::digest(sponsor_script.as_bytes()).into(),
    })
}

/// Derive every transaction field from the exact checked raw transactions.
/// No descriptor hashes are accepted from the witness on this path.
/// Requires a replay-derived successor and qualified CMR from the enclosing
/// verifier; it does not turn caller-selected states into authenticated states.
#[allow(clippy::too_many_arguments)]
pub fn rendered_settlement_journal(
    settlement: &TruthcoinAnchorSettlementV1,
    prior: &TruthcoinAnchorStateV1,
    successor: &TruthcoinAnchorStateV1,
    update: &TruthcoinAnchorUpdateV1,
    authority_cmr: Hash32,
    authentication: &TruthcoinAuthenticationConfigV1,
    deployment: &TruthcoinAnchorDeploymentV1,
    policy_asset_id: Hash32,
) -> Result<TruthcoinAuthorityJournalV1, SettlementError> {
    let sponsor = decode_transaction(&settlement.sponsor_previous_transaction)?;
    let output = sponsor.output.get(settlement.sponsor_previous_vout as usize)
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    let scripts = rendered_scripts(prior, successor, authority_cmr, &output.script_pubkey)
        .map_err(|_| SettlementError::InvalidTruthcoinAuthority)?;
    settlement_journal(settlement, prior, successor, update, &scripts,
        authentication, deployment, policy_asset_id)
}

/// Lower-level descriptor-based checks, not renderer qualification.
/// The parent endpoint is the successor's verified observation endpoint, NOT
/// the prior authority state's older checkpoint or a future inclusion block.
#[allow(clippy::too_many_arguments)]
pub fn settlement_journal(
    settlement: &TruthcoinAnchorSettlementV1,
    prior: &TruthcoinAnchorStateV1,
    successor: &TruthcoinAnchorStateV1,
    update: &TruthcoinAnchorUpdateV1,
    scripts: &TruthcoinAnchorAuthorityScriptsV1,
    authentication: &TruthcoinAuthenticationConfigV1,
    deployment: &TruthcoinAnchorDeploymentV1,
    policy_asset_id: Hash32,
) -> Result<TruthcoinAuthorityJournalV1, SettlementError> {
    let verified = verify_truthcoin_anchor_settlement(settlement, prior, successor,
        update, scripts, authentication, deployment, policy_asset_id)?;
    let previous = decode_transaction(&settlement.prior_authority_transaction)?;
    let sponsor = decode_transaction(&settlement.sponsor_previous_transaction)?;
    let authority_output = previous.output.get(update.prior_authority_outpoint.vout as usize)
        .ok_or(SettlementError::TruthcoinAnchorLinkage)?;
    let sponsor_output = sponsor.output.get(settlement.sponsor_previous_vout as usize)
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    Ok(TruthcoinAuthorityJournalV1 {
        configuration_hash: successor.configuration_hash,
        prior_commitment: prior.commitment(),
        next_commitment: successor.commitment(),
        transaction_id: verified.transaction_id,
        authority: InputBinding {
            txid: previous.txid().to_byte_array(),
            vout: update.prior_authority_outpoint.vout,
            script_hash: script_sha256(authority_output),
            asset: deployment.authority_asset_id,
            amount: deployment.authority_amount,
        },
        sponsor: InputBinding {
            txid: sponsor.txid().to_byte_array(),
            vout: settlement.sponsor_previous_vout,
            script_hash: script_sha256(sponsor_output),
            asset: policy_asset_id,
            amount: explicit_output_amount(sponsor_output, policy_asset_id)
                .ok_or(SettlementError::InvalidTruthcoinSponsor)?,
        },
        prior_parent_hash: successor.bitcoin_checkpoint_hash,
        prior_parent_height: successor.bitcoin_checkpoint_height,
        prior_parent_mtp: successor.bitcoin_checkpoint_mtp,
        prior_parent_chainwork: successor.bitcoin_checkpoint_chainwork,
    })
}
