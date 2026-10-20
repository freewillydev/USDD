use anyhow::{Context, Result, bail};
use ecx_protocol_core::codec::CanonicalEncode;
use ecx_protocol_core::{
    CentralMatcherConfigV1, CentralMatcherReceiptV1, Hash32, MatcherCommandKind,
    MatcherExecutionReceiptV2, MatcherReceiptBodyV1, Signature64, SuccessorCentralMatcherConfigV2,
    SuccessorCentralMatcherReceiptV2, SuccessorMatcherCommandKindV2, SuccessorMatcherReceiptBodyV2,
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, matcher_cancel_command_hash,
    matcher_order_command_hash, successor_matcher_cancel_command_hash_v2,
    successor_matcher_order_command_hash_v2, tagged_hash,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};

use crate::{
    ElementsConsensusContextV1, ElementsConsensusContextV2, EngineCommand,
    engine::{protocol_order_risk_commitment, protocol_signed_cancel, protocol_signed_order},
    model::StagedMatcherExecutionV2,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandCommitment {
    pub chain_id: Hash32,
    pub command_kind: MatcherCommandKind,
    pub command_hash: Hash32,
    pub availability_root: Hash32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatcherConsensusContextV1 {
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub parent_mtp: u64,
    /// Complete node-observed forced inbox count. Requiring the proved cursor
    /// to reach this value prevents the matcher from issuing new priority while
    /// ignoring an already visible forced command.
    pub forced_inbox_cursor: u64,
}

/// Node-authenticated context signed by the lifetime-safe successor matcher.
/// The forced cursor is deliberately `u128`; narrowing it to the active V1
/// node projection is a separate, checked migration boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorMatcherConsensusContextV2 {
    pub sidechain_height: u64,
    pub parent_height: u64,
    pub parent_mtp: u64,
    pub forced_inbox_cursor: u128,
}

impl SuccessorMatcherConsensusContextV2 {
    pub fn validate(self) -> Result<Self> {
        if self.sidechain_height == 0 || self.parent_height == 0 || self.parent_mtp == 0 {
            bail!("successor matcher consensus context heights and MTP must be nonzero");
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccessorCommandCommitmentV2 {
    pub chain_id: Hash32,
    pub command_kind: SuccessorMatcherCommandKindV2,
    pub command_hash: Hash32,
    pub availability_root: Hash32,
}

/// Durable head of the disjoint successor receipt chain. It can begin above
/// `u64::MAX`; V1 journal state is never silently reinterpreted as this head.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorMatcherHeadV2 {
    pub sequence: u128,
    pub receipt_hash: Hash32,
}

impl SuccessorMatcherHeadV2 {
    pub const ENCODED_LEN: usize = 48;

    pub fn validate(self) -> Result<Self> {
        if self.sequence == u128::MAX || self.receipt_hash == [0; 32] {
            bail!("invalid successor matcher durable head");
        }
        Ok(self)
    }

    pub fn encode_fixed(self) -> Result<[u8; Self::ENCODED_LEN]> {
        let value = self.validate()?;
        let mut encoded = [0u8; Self::ENCODED_LEN];
        encoded[..16].copy_from_slice(&value.sequence.to_be_bytes());
        encoded[16..].copy_from_slice(&value.receipt_hash);
        Ok(encoded)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            bail!("successor matcher durable head must be exactly 48 bytes");
        }
        let mut sequence = [0u8; 16];
        sequence.copy_from_slice(&bytes[..16]);
        let mut receipt_hash = [0u8; 32];
        receipt_hash.copy_from_slice(&bytes[16..]);
        Self {
            sequence: u128::from_be_bytes(sequence),
            receipt_hash,
        }
        .validate()
    }
}

/// Additive lifetime-safe sequencer. Matching and publication remain outside
/// this component; callers must durably commit the returned receipt and head
/// atomically with the corresponding engine mutation before exposing either.
#[derive(Clone)]
pub struct SuccessorCentralMatcherSignerV2 {
    config: SuccessorCentralMatcherConfigV2,
    secret_key: SecretKey,
    chain_id: Hash32,
}

impl SuccessorCentralMatcherSignerV2 {
    pub fn new(
        config: SuccessorCentralMatcherConfigV2,
        secret_key: SecretKey,
        chain_id: Hash32,
    ) -> Result<Self> {
        config
            .validate()
            .context("invalid successor central matcher configuration")?;
        if chain_id == [0; 32] {
            bail!("successor central matcher chain id must be nonzero");
        }
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret_key);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        if public_key.serialize() != config.signer.0 {
            bail!("successor matcher secret key does not match the configured signer");
        }
        Ok(Self {
            config,
            secret_key,
            chain_id,
        })
    }

    pub fn config(&self) -> &SuccessorCentralMatcherConfigV2 {
        &self.config
    }

    pub fn chain_id(&self) -> Hash32 {
        self.chain_id
    }

    pub fn issue(
        &self,
        command: &SuccessorCommandCommitmentV2,
        previous: SuccessorMatcherHeadV2,
        context: SuccessorMatcherConsensusContextV2,
    ) -> Result<(SuccessorCentralMatcherReceiptV2, SuccessorMatcherHeadV2)> {
        let previous = previous.validate()?;
        let context = context.validate()?;
        if command.chain_id != self.chain_id || command.availability_root == [0; 32] {
            bail!("successor matcher command belongs to a different chain or has no availability");
        }
        let sequence = previous
            .sequence
            .checked_add(1)
            .context("successor matcher sequence overflow")?;
        if sequence == u128::MAX {
            bail!("successor matcher sequence exhausted");
        }
        let receipt = SuccessorCentralMatcherReceiptV2::sign(
            SuccessorMatcherReceiptBodyV2 {
                version: SuccessorMatcherReceiptBodyV2::VERSION,
                chain_id: self.chain_id,
                market: ecx_protocol_core::ECX_USDD_MARKET,
                matcher_config_hash: self.config.digest(),
                matcher_key_epoch: self.config.key_epoch,
                global_sequence: sequence,
                previous_receipt_hash: previous.receipt_hash,
                command_kind: command.command_kind,
                command_hash: command.command_hash,
                observed_sidechain_height: context.sidechain_height,
                observed_parent_height: context.parent_height,
                observed_parent_mtp: context.parent_mtp,
                forced_inbox_cursor: context.forced_inbox_cursor,
                availability_root: command.availability_root,
            },
            &self.secret_key,
            &self.config,
        )?;
        let next = SuccessorMatcherHeadV2 {
            sequence,
            receipt_hash: receipt.receipt_hash(),
        };
        Ok((receipt, next))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_execution(
        &self,
        maker: &SuccessorSignedLimitOrderV2,
        taker: &SuccessorSignedLimitOrderV2,
        trade: &ecx_protocol_core::SuccessorTradeMatchV2,
        match_sequence: u128,
        taker_admission: &SuccessorCentralMatcherReceiptV2,
        execution_parent_block_hash: Hash32,
    ) -> Result<ecx_protocol_core::SuccessorMatcherExecutionReceiptV2> {
        ecx_protocol_core::SuccessorMatcherExecutionReceiptV2::issue(
            &self.config,
            &self.secret_key,
            self.chain_id,
            maker,
            taker,
            trade,
            match_sequence,
            taker_admission,
            execution_parent_block_hash,
        )
        .context("issuing exact successor matcher execution receipt")
    }
}

fn successor_command_availability_root_v2(
    command_bytes: &[u8],
    recoverable_context: &[u8],
) -> Result<Hash32> {
    let command_len =
        u32::try_from(command_bytes.len()).context("successor matcher command is too large")?;
    let context_len = u32::try_from(recoverable_context.len())
        .context("successor matcher recoverable context is too large")?;
    let mut encoded = Vec::with_capacity(command_bytes.len() + recoverable_context.len() + 8);
    encoded.extend_from_slice(&command_len.to_be_bytes());
    encoded.extend_from_slice(command_bytes);
    encoded.extend_from_slice(&context_len.to_be_bytes());
    encoded.extend_from_slice(recoverable_context);
    Ok(tagged_hash(
        "ECX/incremental-central-matcher-availability/v1-u128",
        &encoded,
    ))
}

pub fn successor_order_command_commitment_v2(
    order: &SuccessorSignedLimitOrderV2,
    expected_chain_id: Hash32,
    recoverable_context: &[u8],
) -> Result<SuccessorCommandCommitmentV2> {
    order.verify().context("invalid successor trader order")?;
    if order.order.chain_id != expected_chain_id {
        bail!("successor signed order chain id does not match this matcher");
    }
    let bytes = order.canonical_bytes();
    Ok(SuccessorCommandCommitmentV2 {
        chain_id: order.order.chain_id,
        command_kind: SuccessorMatcherCommandKindV2::Place,
        command_hash: successor_matcher_order_command_hash_v2(order),
        availability_root: successor_command_availability_root_v2(&bytes, recoverable_context)?,
    })
}

pub fn successor_cancel_command_commitment_v2(
    cancel: &SuccessorSignedCancelOrderV2,
    expected_chain_id: Hash32,
    recoverable_context: &[u8],
) -> Result<SuccessorCommandCommitmentV2> {
    cancel
        .verify()
        .context("invalid successor trader cancellation")?;
    if cancel.cancel.chain_id != expected_chain_id {
        bail!("successor signed cancellation chain id does not match this matcher");
    }
    let bytes = cancel.canonical_bytes();
    Ok(SuccessorCommandCommitmentV2 {
        chain_id: cancel.cancel.chain_id,
        command_kind: SuccessorMatcherCommandKindV2::Cancel,
        command_hash: successor_matcher_cancel_command_hash_v2(cancel),
        availability_root: successor_command_availability_root_v2(&bytes, recoverable_context)?,
    })
}

impl MatcherConsensusContextV1 {
    pub fn validate(self) -> Result<Self> {
        if self.sidechain_height == 0 || self.parent_height == 0 || self.parent_mtp == 0 {
            bail!("matcher consensus context heights and MTP must be nonzero");
        }
        Ok(self)
    }
}

/// The sole configured sequencing signer. It assigns priority but cannot sign
/// trader commands or make an invalid state transition pass the proof.
#[derive(Clone)]
pub struct CentralMatcherSigner {
    config: CentralMatcherConfigV1,
    secret_key: SecretKey,
    chain_id: Hash32,
    default_context: MatcherConsensusContextV1,
}

impl CentralMatcherSigner {
    pub fn new(
        config: CentralMatcherConfigV1,
        secret_key: SecretKey,
        chain_id: Hash32,
        observed_sidechain_height: u64,
        observed_parent_height: u64,
        observed_parent_mtp: u64,
        forced_inbox_cursor: u64,
    ) -> Result<Self> {
        config
            .validate()
            .context("invalid central matcher configuration")?;
        if chain_id == [0; 32] {
            bail!("central matcher chain id must be nonzero");
        }
        let default_context = MatcherConsensusContextV1 {
            sidechain_height: observed_sidechain_height,
            parent_height: observed_parent_height,
            parent_mtp: observed_parent_mtp,
            forced_inbox_cursor,
        }
        .validate()?;
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret_key);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        if public_key.serialize() != config.signer.0 {
            bail!("central matcher secret key does not match the configured signer");
        }
        Ok(Self {
            config,
            secret_key,
            chain_id,
            default_context,
        })
    }

    pub fn config(&self) -> &CentralMatcherConfigV1 {
        &self.config
    }

    pub fn chain_id(&self) -> Hash32 {
        self.chain_id
    }

    pub(crate) fn default_context(&self) -> MatcherConsensusContextV1 {
        self.default_context
    }

    pub fn issue(
        &self,
        command: &CommandCommitment,
        global_sequence: u64,
        previous_receipt_hash: Hash32,
    ) -> Result<CentralMatcherReceiptV1> {
        self.issue_at(
            command,
            global_sequence,
            previous_receipt_hash,
            self.default_context,
        )
    }

    pub fn issue_at(
        &self,
        command: &CommandCommitment,
        global_sequence: u64,
        previous_receipt_hash: Hash32,
        context: MatcherConsensusContextV1,
    ) -> Result<CentralMatcherReceiptV1> {
        let context = context.validate()?;
        if command.chain_id != self.chain_id {
            bail!("matcher command belongs to a different chain");
        }
        let receipt = CentralMatcherReceiptV1::sign(
            MatcherReceiptBodyV1 {
                version: MatcherReceiptBodyV1::VERSION,
                chain_id: self.chain_id,
                market: ecx_protocol_core::ECX_USDD_MARKET,
                matcher_config_hash: self.config.digest(),
                matcher_key_epoch: self.config.key_epoch,
                global_sequence,
                previous_receipt_hash,
                command_kind: command.command_kind,
                command_hash: command.command_hash,
                observed_sidechain_height: context.sidechain_height,
                observed_parent_height: context.parent_height,
                observed_parent_mtp: context.parent_mtp,
                forced_inbox_cursor: context.forced_inbox_cursor,
                availability_root: command.availability_root,
            },
            &self.secret_key,
            &self.config,
        )?;
        Ok(receipt)
    }

    pub(crate) fn sign_snapshot(&self, payload: &[u8]) -> Result<Signature64> {
        let digest = tagged_hash("ECX/matcher-snapshot/v1", payload);
        let message = Message::from_digest_slice(&digest).context("invalid snapshot digest")?;
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &self.secret_key);
        Ok(Signature64(
            *Secp256k1::new()
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .as_ref(),
        ))
    }

    pub(crate) fn issue_execution_v2(
        &self,
        execution: &StagedMatcherExecutionV2,
        match_sequence: u64,
        taker_admission: &CentralMatcherReceiptV1,
        context: &ElementsConsensusContextV2,
    ) -> Result<MatcherExecutionReceiptV2> {
        context.validate()?;
        if taker_admission.body.observed_sidechain_height != context.sidechain_height
            || taker_admission.body.observed_parent_height != context.parent_height
            || taker_admission.body.observed_parent_mtp != context.parent_mtp
        {
            bail!("taker admission receipt differs from the authenticated Elements context");
        }
        MatcherExecutionReceiptV2::issue(
            &self.config,
            &self.secret_key,
            self.chain_id,
            &execution.maker,
            &execution.taker,
            &execution.trade,
            match_sequence,
            taker_admission,
            context.parent_block_hash,
        )
        .context("issuing exact V2 matcher execution receipt")
    }
}

pub(crate) fn verify_snapshot_signature(
    signer: [u8; 32],
    payload: &[u8],
    signature: Signature64,
) -> Result<()> {
    let digest = tagged_hash("ECX/matcher-snapshot/v1", payload);
    let message = Message::from_digest_slice(&digest).context("invalid snapshot digest")?;
    let public_key = XOnlyPublicKey::from_slice(&signer).context("invalid snapshot signer")?;
    let signature = schnorr::Signature::from_slice(&signature.0)
        .context("invalid matcher snapshot signature")?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public_key)
        .context("matcher snapshot signature verification failed")
}

/// Commits the exact journal payload and, on the production path, the exact
/// protocol-core signed command consumed by the proof.
pub fn command_commitment(
    command: &EngineCommand,
    expected_chain_id: Hash32,
) -> Result<CommandCommitment> {
    let encoded = serde_json::to_vec(command).context("encoding matcher command")?;
    let availability_root = tagged_hash("ECX/central-matcher-availability/v1", &encoded);

    let (chain_id, command_kind, command_hash) = match command {
        EngineCommand::Submit { request, .. } if !request.trader.starts_with("demo-") => {
            let signed = protocol_signed_order(request).context("decoding signed order")?;
            signed.verify().context("invalid trader order signature")?;
            (
                signed.order.chain_id,
                MatcherCommandKind::Place,
                matcher_order_command_hash(&signed),
            )
        }
        EngineCommand::Cancel {
            order_id, request, ..
        } if !request.trader.starts_with("demo-") => {
            let signed =
                protocol_signed_cancel(order_id, request).context("decoding signed cancel")?;
            signed.verify().context("invalid trader cancel signature")?;
            (
                signed.cancel.chain_id,
                MatcherCommandKind::Cancel,
                matcher_cancel_command_hash(&signed),
            )
        }
        EngineCommand::Submit { request, .. } => {
            let request_bytes =
                serde_json::to_vec(request).context("encoding demo matcher order")?;
            (
                expected_chain_id,
                MatcherCommandKind::Place,
                tagged_hash("ECX/demo-matcher-place-command/v1", &request_bytes),
            )
        }
        EngineCommand::Cancel {
            order_id, request, ..
        } => {
            let request_bytes =
                serde_json::to_vec(&(order_id, request)).context("encoding demo matcher cancel")?;
            (
                expected_chain_id,
                MatcherCommandKind::Cancel,
                tagged_hash("ECX/demo-matcher-cancel-command/v1", &request_bytes),
            )
        }
        EngineCommand::SubmitV2 { request, .. } => {
            protocol_order_risk_commitment(request).context("decoding v2 order risk commitment")?;
            let signed = protocol_signed_order(&request.order).context("decoding signed order")?;
            signed.verify().context("invalid trader order signature")?;
            (
                signed.order.chain_id,
                MatcherCommandKind::Place,
                matcher_order_command_hash(&signed),
            )
        }
    };
    if chain_id != expected_chain_id {
        bail!("signed command chain id does not match this matcher");
    }
    Ok(CommandCommitment {
        chain_id,
        command_kind,
        command_hash,
        availability_root,
    })
}

/// Commits the exact command together with the complete active Elements
/// consensus context. The resulting root is signed in the matcher receipt and
/// persisted beside the command, allowing restart recovery to detect an
/// offline same-height reorg or root substitution.
pub fn command_commitment_with_context(
    command: &EngineCommand,
    expected_chain_id: Hash32,
    context: &ElementsConsensusContextV1,
) -> Result<CommandCommitment> {
    context.validate()?;
    let mut commitment = command_commitment(command, expected_chain_id)?;
    let command_bytes = serde_json::to_vec(command).context("encoding matcher command")?;
    let command_len = u32::try_from(command_bytes.len()).context("matcher command is too large")?;
    let mut encoded = Vec::with_capacity(command_bytes.len() + 224);
    encoded.extend_from_slice(&command_len.to_be_bytes());
    encoded.extend_from_slice(&command_bytes);
    encoded.extend_from_slice(&context.sidechain_height.to_be_bytes());
    encoded.extend_from_slice(&context.sidechain_block_hash);
    encoded.extend_from_slice(&context.exchange_state_root);
    encoded.extend_from_slice(&context.forced_inbox_head_root);
    encoded.extend_from_slice(&context.forced_inbox_entry_count.to_be_bytes());
    encoded.extend_from_slice(&context.deposit_inbox_head_root);
    encoded.extend_from_slice(&context.deposit_inbox_entry_count.to_be_bytes());
    encoded.extend_from_slice(&context.parent_height.to_be_bytes());
    encoded.extend_from_slice(&context.parent_mtp.to_be_bytes());
    encoded.extend_from_slice(&context.parent_block_hash);
    encoded.extend_from_slice(&context.source_parent_height.to_be_bytes());
    commitment.availability_root = tagged_hash("ECX/central-matcher-availability/v2", &encoded);
    Ok(commitment)
}

/// V2 availability commitment. The distinct domain and explicit optional
/// capital tag prevent a V2 context from being interpreted as the frozen V1
/// byte layout.
pub fn command_commitment_with_context_v2(
    command: &EngineCommand,
    expected_chain_id: Hash32,
    context: &ElementsConsensusContextV2,
) -> Result<CommandCommitment> {
    context.validate()?;
    let mut commitment = command_commitment(command, expected_chain_id)?;
    let command_bytes = serde_json::to_vec(command).context("encoding matcher command")?;
    let command_len = u32::try_from(command_bytes.len()).context("matcher command is too large")?;
    let mut encoded = Vec::with_capacity(command_bytes.len() + 320);
    encoded.extend_from_slice(&command_len.to_be_bytes());
    encoded.extend_from_slice(&command_bytes);
    encoded.extend_from_slice(&context.sidechain_height.to_be_bytes());
    encoded.extend_from_slice(&context.sidechain_block_hash);
    encoded.extend_from_slice(&context.exchange_state_root);
    encoded.extend_from_slice(&context.forced_inbox_head_root);
    encoded.extend_from_slice(&context.forced_inbox_entry_count.to_be_bytes());
    encoded.extend_from_slice(&context.forced_inbox_processed_cursor.to_be_bytes());
    encoded.extend_from_slice(&context.deposit_inbox_head_root);
    encoded.extend_from_slice(&context.deposit_inbox_entry_count.to_be_bytes());
    encoded.extend_from_slice(&context.deposit_inbox_processed_cursor.to_be_bytes());
    encoded.extend_from_slice(&context.parent_height.to_be_bytes());
    encoded.extend_from_slice(&context.parent_mtp.to_be_bytes());
    encoded.extend_from_slice(&context.parent_block_hash);
    encoded.extend_from_slice(&context.source_parent_height.to_be_bytes());
    match &context.capital_snapshot {
        None => encoded.push(0),
        Some(capital) => {
            encoded.push(1);
            let capital_bytes =
                serde_json::to_vec(capital).context("encoding v2 capital snapshot")?;
            let capital_len =
                u32::try_from(capital_bytes.len()).context("v2 capital snapshot is too large")?;
            encoded.extend_from_slice(&capital_len.to_be_bytes());
            encoded.extend_from_slice(&capital_bytes);
        }
    }
    commitment.availability_root = tagged_hash("ECX/central-matcher-availability/v3", &encoded);
    Ok(commitment)
}

pub fn matcher_public_key(secret_key: &SecretKey) -> XOnlyPublicKey {
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret_key);
    XOnlyPublicKey::from_keypair(&keypair).0
}

#[cfg(test)]
mod successor_tests {
    use ecx_protocol_core::{
        OrderFlags, Price, Quantity, Side, SuccessorCancelOrderV2, SuccessorLimitOrderV2,
        TimeInForce, XOnlyKey,
    };

    use super::*;

    fn trader_key() -> (SecretKey, XOnlyKey) {
        let secret = SecretKey::from_slice(&[41; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        (secret, XOnlyKey(public.serialize()))
    }

    fn matcher() -> (
        SuccessorCentralMatcherSignerV2,
        SuccessorCentralMatcherConfigV2,
        Hash32,
    ) {
        let secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let signer = matcher_public_key(&secret);
        let chain_id = [7; 32];
        let config = SuccessorCentralMatcherConfigV2 {
            version: SuccessorCentralMatcherConfigV2::VERSION,
            key_epoch: 3,
            signer: XOnlyKey(signer.serialize()),
            genesis_sequence: (1u128 << 96) + 9,
            genesis_receipt_hash: [8; 32],
            forced_inclusion_blocks: 6,
        };
        (
            SuccessorCentralMatcherSignerV2::new(config.clone(), secret, chain_id).unwrap(),
            config,
            chain_id,
        )
    }

    fn signed_order(
        secret: &SecretKey,
        trader: XOnlyKey,
        chain_id: Hash32,
        nonce: u128,
    ) -> SuccessorSignedLimitOrderV2 {
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id,
                market: ecx_protocol_core::ECX_USDD_MARKET,
                trader,
                side: Side::Buy,
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                limit_price: Price::new(100_000_000).unwrap(),
                quantity: Quantity::new(5).unwrap(),
                client_order_id: [3; 16],
                max_fee_bps: 5,
                nonce,
                valid_from_height: 100,
                expires_at_height: 200,
            },
            secret,
        )
        .unwrap()
    }

    #[test]
    fn successor_sequencer_signs_and_chains_full_u128_context() {
        let (signer, config, chain_id) = matcher();
        let (trader_secret, trader) = trader_key();
        let order = signed_order(&trader_secret, trader, chain_id, (1u128 << 104) + 17);
        let commitment =
            successor_order_command_commitment_v2(&order, chain_id, b"recoverable-node-context-v1")
                .unwrap();
        let previous = SuccessorMatcherHeadV2 {
            sequence: config.genesis_sequence,
            receipt_hash: config.genesis_receipt_hash,
        };
        assert_eq!(
            SuccessorMatcherHeadV2::decode_fixed(&previous.encode_fixed().unwrap()).unwrap(),
            previous
        );
        assert!(
            SuccessorMatcherHeadV2::decode_fixed(&previous.encode_fixed().unwrap()[..47]).is_err()
        );
        let context = SuccessorMatcherConsensusContextV2 {
            sidechain_height: 101,
            parent_height: 900_001,
            parent_mtp: 1_800_000_000,
            forced_inbox_cursor: (1u128 << 112) + 4,
        };
        let (place_receipt, place_head) = signer.issue(&commitment, previous, context).unwrap();
        place_receipt.verify(&config).unwrap();
        assert_eq!(place_head.sequence, previous.sequence + 1);
        assert_eq!(place_receipt.body.global_sequence, place_head.sequence);
        assert_eq!(
            place_receipt.body.forced_inbox_cursor,
            context.forced_inbox_cursor
        );
        assert_eq!(
            place_receipt.body.previous_receipt_hash,
            previous.receipt_hash
        );

        let cancel = SuccessorSignedCancelOrderV2::sign(
            SuccessorCancelOrderV2 {
                version: SuccessorCancelOrderV2::VERSION,
                chain_id,
                market: ecx_protocol_core::ECX_USDD_MARKET,
                trader,
                order_id: order.order_id(),
                nonce: order.order.nonce + 1,
                valid_from_height: 101,
                expires_at_height: 201,
            },
            &trader_secret,
        )
        .unwrap();
        let cancel_commitment = successor_cancel_command_commitment_v2(
            &cancel,
            chain_id,
            b"recoverable-node-context-v2",
        )
        .unwrap();
        let (cancel_receipt, cancel_head) = signer
            .issue(&cancel_commitment, place_head, context)
            .unwrap();
        cancel_receipt.verify(&config).unwrap();
        assert_eq!(cancel_head.sequence, place_head.sequence + 1);
        assert_eq!(
            cancel_receipt.body.previous_receipt_hash,
            place_head.receipt_hash
        );
        assert_eq!(
            cancel_receipt.body.command_kind,
            SuccessorMatcherCommandKindV2::Cancel
        );
    }

    #[test]
    fn successor_sequencer_rejects_substitution_and_exhaustion() {
        let (signer, config, chain_id) = matcher();
        let (trader_secret, trader) = trader_key();
        let order = signed_order(&trader_secret, trader, chain_id, (1u128 << 100) + 1);
        let first = successor_order_command_commitment_v2(&order, chain_id, b"context-a").unwrap();
        let second = successor_order_command_commitment_v2(&order, chain_id, b"context-b").unwrap();
        assert_ne!(first.availability_root, second.availability_root);
        assert!(successor_order_command_commitment_v2(&order, [9; 32], b"context-a").is_err());

        let context = SuccessorMatcherConsensusContextV2 {
            sidechain_height: 1,
            parent_height: 1,
            parent_mtp: 1,
            forced_inbox_cursor: 1,
        };
        assert!(
            signer
                .issue(
                    &first,
                    SuccessorMatcherHeadV2 {
                        sequence: u128::MAX - 1,
                        receipt_hash: config.genesis_receipt_hash,
                    },
                    context,
                )
                .is_err()
        );

        let mut tampered = order.clone();
        tampered.order.nonce += 1;
        assert!(successor_order_command_commitment_v2(&tampered, chain_id, b"context-a").is_err());
    }
}
