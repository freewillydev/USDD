//! Lifetime-safe central-matcher admission receipts for the incremental
//! successor. The active V1 matcher types and signature domains are unchanged.

use std::collections::BTreeSet;

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::{put_u128, put_u32, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::matcher_receipt::MAX_FORCED_INCLUSION_BLOCKS;
use crate::merkle::ordered_root;
use crate::order::Signature64;
use crate::successor_action_v2::{
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, SuccessorTradeMatchV2,
};
use crate::types::{MarketId, Price, Quantity, XOnlyKey, ECX_USDD_MARKET};
use crate::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorCentralMatcherConfigV2 {
    pub version: u8,
    pub key_epoch: u64,
    pub signer: XOnlyKey,
    pub genesis_sequence: u128,
    pub genesis_receipt_hash: Hash32,
    pub forced_inclusion_blocks: u32,
}

impl SuccessorCentralMatcherConfigV2 {
    pub const VERSION: u8 = 2;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.signer.0 == [0; 32]
            || XOnlyPublicKey::from_slice(&self.signer.0).is_err()
            || self.genesis_sequence == u128::MAX
            || self.genesis_receipt_hash == [0; 32]
            || self.forced_inclusion_blocks == 0
            || self.forced_inclusion_blocks > MAX_FORCED_INCLUSION_BLOCKS
        {
            return Err(ProtocolError::InvalidCentralMatcherConfiguration);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/incremental-central-matcher-config/v2-u128", self)
    }
}

impl CanonicalEncode for SuccessorCentralMatcherConfigV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.key_epoch);
        self.signer.encode_to(out);
        put_u128(out, self.genesis_sequence);
        out.extend_from_slice(&self.genesis_receipt_hash);
        put_u32(out, self.forced_inclusion_blocks);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SuccessorMatcherCommandKindV2 {
    Place = 0,
    Cancel = 1,
}

impl CanonicalEncode for SuccessorMatcherCommandKindV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorMatcherReceiptBodyV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub matcher_config_hash: Hash32,
    pub matcher_key_epoch: u64,
    pub global_sequence: u128,
    pub previous_receipt_hash: Hash32,
    pub command_kind: SuccessorMatcherCommandKindV2,
    pub command_hash: Hash32,
    pub observed_sidechain_height: u64,
    pub observed_parent_height: u64,
    pub observed_parent_mtp: u64,
    pub forced_inbox_cursor: u128,
    pub availability_root: Hash32,
}

impl SuccessorMatcherReceiptBodyV2 {
    pub const VERSION: u8 = 1;

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/incremental-central-matcher-receipt-body/v2-u128", self)
    }
}

impl CanonicalEncode for SuccessorMatcherReceiptBodyV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        out.extend_from_slice(&self.matcher_config_hash);
        put_u64(out, self.matcher_key_epoch);
        put_u128(out, self.global_sequence);
        out.extend_from_slice(&self.previous_receipt_hash);
        self.command_kind.encode_to(out);
        out.extend_from_slice(&self.command_hash);
        put_u64(out, self.observed_sidechain_height);
        put_u64(out, self.observed_parent_height);
        put_u64(out, self.observed_parent_mtp);
        put_u128(out, self.forced_inbox_cursor);
        out.extend_from_slice(&self.availability_root);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorCentralMatcherReceiptV2 {
    pub body: SuccessorMatcherReceiptBodyV2,
    pub signature: Signature64,
}

impl SuccessorCentralMatcherReceiptV2 {
    pub fn sign(
        body: SuccessorMatcherReceiptBodyV2,
        secret_key: &SecretKey,
        config: &SuccessorCentralMatcherConfigV2,
    ) -> Result<Self, ProtocolError> {
        config.validate()?;
        validate_body(&body, config)?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        if public_key.serialize() != config.signer.0 {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let message = Message::from_digest_slice(&body.signing_digest())
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(Self {
            body,
            signature: Signature64(*signature.as_ref()),
        })
    }

    pub fn verify(&self, config: &SuccessorCentralMatcherConfigV2) -> Result<(), ProtocolError> {
        config.validate()?;
        validate_body(&self.body, config)?;
        let message = Message::from_digest_slice(&self.body.signing_digest())
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let public_key = XOnlyPublicKey::from_slice(&config.signer.0)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &public_key)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)
    }

    pub fn receipt_hash(&self) -> Hash32 {
        canonical_hash("ECX/incremental-central-matcher-receipt/v2-u128", self)
    }
}

impl CanonicalEncode for SuccessorCentralMatcherReceiptV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.body.encode_to(out);
        self.signature.encode_to(out);
    }
}

fn validate_body(
    body: &SuccessorMatcherReceiptBodyV2,
    config: &SuccessorCentralMatcherConfigV2,
) -> Result<(), ProtocolError> {
    body.market.validate()?;
    if body.version != SuccessorMatcherReceiptBodyV2::VERSION
        || body.chain_id == [0; 32]
        || body.market != ECX_USDD_MARKET
        || body.matcher_config_hash != config.digest()
        || body.matcher_key_epoch != config.key_epoch
        || body.global_sequence == 0
        || body.command_hash == [0; 32]
        || body.availability_root == [0; 32]
        || body.observed_sidechain_height == 0
        || body.observed_parent_height == 0
        || body.observed_parent_mtp == 0
    {
        return Err(ProtocolError::InvalidMatcherReceipt);
    }
    Ok(())
}

pub fn successor_matcher_order_command_hash_v2(order: &SuccessorSignedLimitOrderV2) -> Hash32 {
    canonical_hash("ECX/incremental-matcher-place-command/v2-u128", order)
}

pub fn successor_matcher_cancel_command_hash_v2(cancel: &SuccessorSignedCancelOrderV2) -> Hash32 {
    canonical_hash("ECX/incremental-matcher-cancel-command/v2-u128", cancel)
}

pub fn successor_central_matcher_receipt_batch_root_v2(
    receipts: &[SuccessorCentralMatcherReceiptV2],
) -> Hash32 {
    let hashes = receipts
        .iter()
        .map(SuccessorCentralMatcherReceiptV2::receipt_hash)
        .collect::<Vec<_>>();
    ordered_root(
        "ECX/incremental-central-matcher-receipt-batch/v2-u128",
        &hashes,
    )
}

pub fn verify_successor_central_matcher_receipt_chain_v2(
    config: &SuccessorCentralMatcherConfigV2,
    expected_chain_id: Hash32,
    previous_sequence: u128,
    previous_receipt_hash: Hash32,
    receipts: &[SuccessorCentralMatcherReceiptV2],
) -> Result<(u128, Hash32), ProtocolError> {
    config.validate()?;
    let mut sequence = previous_sequence;
    let mut receipt_hash = previous_receipt_hash;
    for receipt in receipts {
        receipt.verify(config)?;
        sequence = sequence
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if receipt.body.chain_id != expected_chain_id
            || receipt.body.global_sequence != sequence
            || receipt.body.previous_receipt_hash != receipt_hash
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        receipt_hash = receipt.receipt_hash();
    }
    Ok((sequence, receipt_hash))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorMatcherExecutionParentV2 {
    pub block_hash: Hash32,
    pub height: u64,
    pub median_time_past: u64,
}

impl SuccessorMatcherExecutionParentV2 {
    fn validate(self) -> Result<(), ProtocolError> {
        if self.block_hash == [0; 32] || self.height == 0 || self.median_time_past == 0 {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        Ok(())
    }
}

impl CanonicalEncode for SuccessorMatcherExecutionParentV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.block_hash);
        put_u64(out, self.height);
        put_u64(out, self.median_time_past);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorMatcherExecutionReceiptBodyV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub matcher_config_hash: Hash32,
    pub matcher_key_epoch: u64,
    pub taker_admission_receipt_hash: Hash32,
    pub match_id: Hash32,
    pub maker_order_id: Hash32,
    pub taker_order_id: Hash32,
    pub admission_sequence: u128,
    pub match_sequence: u128,
    pub price: Price,
    pub quantity: Quantity,
    pub observed_sidechain_height: u64,
    pub execution_parent: SuccessorMatcherExecutionParentV2,
}

impl SuccessorMatcherExecutionReceiptBodyV2 {
    pub const VERSION: u8 = 1;

    fn validate(&self) -> Result<(), ProtocolError> {
        self.market.validate()?;
        Price::new(self.price.get())?;
        Quantity::new(self.quantity.get())?;
        self.execution_parent.validate()?;
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.market != ECX_USDD_MARKET
            || self.matcher_config_hash == [0; 32]
            || self.taker_admission_receipt_hash == [0; 32]
            || self.match_id == [0; 32]
            || self.maker_order_id == [0; 32]
            || self.taker_order_id == [0; 32]
            || self.admission_sequence == 0
            || self.match_sequence == 0
            || self.observed_sidechain_height == 0
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        Ok(())
    }

    fn signing_digest(&self) -> Hash32 {
        canonical_hash(
            "ECX/incremental-central-matcher-execution-body/v2-u128",
            self,
        )
    }
}

impl CanonicalEncode for SuccessorMatcherExecutionReceiptBodyV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        out.extend_from_slice(&self.matcher_config_hash);
        put_u64(out, self.matcher_key_epoch);
        out.extend_from_slice(&self.taker_admission_receipt_hash);
        out.extend_from_slice(&self.match_id);
        out.extend_from_slice(&self.maker_order_id);
        out.extend_from_slice(&self.taker_order_id);
        put_u128(out, self.admission_sequence);
        put_u128(out, self.match_sequence);
        self.price.encode_to(out);
        self.quantity.encode_to(out);
        put_u64(out, self.observed_sidechain_height);
        self.execution_parent.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorMatcherExecutionReceiptV2 {
    pub body: SuccessorMatcherExecutionReceiptBodyV2,
    pub signature: Signature64,
}

impl SuccessorMatcherExecutionReceiptV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        config: &SuccessorCentralMatcherConfigV2,
        secret_key: &SecretKey,
        expected_chain_id: Hash32,
        maker: &SuccessorSignedLimitOrderV2,
        taker: &SuccessorSignedLimitOrderV2,
        trade: &SuccessorTradeMatchV2,
        match_sequence: u128,
        taker_admission: &SuccessorCentralMatcherReceiptV2,
        execution_parent_block_hash: Hash32,
    ) -> Result<Self, ProtocolError> {
        config.validate()?;
        taker_admission.verify(config)?;
        trade.validate_orders(maker, taker, taker_admission.body.observed_sidechain_height)?;
        if expected_chain_id == [0; 32]
            || maker.order.chain_id != expected_chain_id
            || taker.order.chain_id != expected_chain_id
            || taker_admission.body.chain_id != expected_chain_id
            || taker_admission.body.command_kind != SuccessorMatcherCommandKindV2::Place
            || taker_admission.body.command_hash != successor_matcher_order_command_hash_v2(taker)
            || taker_admission.body.global_sequence != trade.sequence
            || match_sequence == 0
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        let body = SuccessorMatcherExecutionReceiptBodyV2 {
            version: SuccessorMatcherExecutionReceiptBodyV2::VERSION,
            chain_id: expected_chain_id,
            market: maker.order.market,
            matcher_config_hash: config.digest(),
            matcher_key_epoch: config.key_epoch,
            taker_admission_receipt_hash: taker_admission.receipt_hash(),
            match_id: trade.match_id(),
            maker_order_id: trade.maker_order_id,
            taker_order_id: trade.taker_order_id,
            admission_sequence: taker_admission.body.global_sequence,
            match_sequence,
            price: trade.price,
            quantity: trade.quantity,
            observed_sidechain_height: taker_admission.body.observed_sidechain_height,
            execution_parent: SuccessorMatcherExecutionParentV2 {
                block_hash: execution_parent_block_hash,
                height: taker_admission.body.observed_parent_height,
                median_time_past: taker_admission.body.observed_parent_mtp,
            },
        };
        Self::sign_body(body, secret_key, config)
    }

    fn sign_body(
        body: SuccessorMatcherExecutionReceiptBodyV2,
        secret_key: &SecretKey,
        config: &SuccessorCentralMatcherConfigV2,
    ) -> Result<Self, ProtocolError> {
        config.validate()?;
        body.validate()?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        if body.matcher_config_hash != config.digest()
            || body.matcher_key_epoch != config.key_epoch
            || public_key.serialize() != config.signer.0
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        let message = Message::from_digest_slice(&body.signing_digest())
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(Self {
            body,
            signature: Signature64(*signature.as_ref()),
        })
    }

    pub fn receipt_hash(&self) -> Hash32 {
        canonical_hash(
            "ECX/incremental-central-matcher-execution-receipt/v2-u128",
            self,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_match(
        &self,
        config: &SuccessorCentralMatcherConfigV2,
        expected_chain_id: Hash32,
        maker: &SuccessorSignedLimitOrderV2,
        taker: &SuccessorSignedLimitOrderV2,
        trade: &SuccessorTradeMatchV2,
        taker_admission: &SuccessorCentralMatcherReceiptV2,
    ) -> Result<(), ProtocolError> {
        config.validate()?;
        self.body.validate()?;
        taker_admission.verify(config)?;
        trade.validate_orders(maker, taker, self.body.observed_sidechain_height)?;
        let message = Message::from_digest_slice(&self.body.signing_digest())
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let key = XOnlyPublicKey::from_slice(&config.signer.0)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &key)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        if self.body.matcher_config_hash != config.digest()
            || self.body.matcher_key_epoch != config.key_epoch
            || self.body.chain_id != expected_chain_id
            || self.body.market != maker.order.market
            || self.body.market != taker.order.market
            || self.body.match_id != trade.match_id()
            || self.body.maker_order_id != trade.maker_order_id
            || self.body.taker_order_id != trade.taker_order_id
            || self.body.price != trade.price
            || self.body.quantity != trade.quantity
            || self.body.admission_sequence != trade.sequence
            || self.body.taker_admission_receipt_hash != taker_admission.receipt_hash()
            || taker_admission.body.command_kind != SuccessorMatcherCommandKindV2::Place
            || taker_admission.body.command_hash != successor_matcher_order_command_hash_v2(taker)
            || taker_admission.body.global_sequence != trade.sequence
            || self.body.observed_sidechain_height != taker_admission.body.observed_sidechain_height
            || self.body.execution_parent.height != taker_admission.body.observed_parent_height
            || self.body.execution_parent.median_time_past
                != taker_admission.body.observed_parent_mtp
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        Ok(())
    }
}

impl CanonicalEncode for SuccessorMatcherExecutionReceiptV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.body.encode_to(out);
        self.signature.encode_to(out);
    }
}

pub struct SuccessorMatcherExecutionRelationV2<'a> {
    pub maker: &'a SuccessorSignedLimitOrderV2,
    pub taker: &'a SuccessorSignedLimitOrderV2,
    pub trade: &'a SuccessorTradeMatchV2,
    pub taker_admission: &'a SuccessorCentralMatcherReceiptV2,
}

pub fn successor_matcher_execution_receipt_batch_root_v2(
    receipts: &[SuccessorMatcherExecutionReceiptV2],
) -> Hash32 {
    ordered_root(
        "ECX/incremental-central-matcher-execution-batch/v2-u128",
        &receipts
            .iter()
            .map(SuccessorMatcherExecutionReceiptV2::receipt_hash)
            .collect::<Vec<_>>(),
    )
}

pub fn verify_successor_matcher_execution_receipt_batch_v2(
    config: &SuccessorCentralMatcherConfigV2,
    expected_chain_id: Hash32,
    previous_match_sequence: u128,
    relations: &[SuccessorMatcherExecutionRelationV2<'_>],
    receipts: &[SuccessorMatcherExecutionReceiptV2],
) -> Result<(Hash32, u128), ProtocolError> {
    if relations.len() != receipts.len() {
        return Err(ProtocolError::InvalidMatcherReceipt);
    }
    let mut next = previous_match_sequence;
    let mut match_ids = BTreeSet::new();
    let mut receipt_hashes = BTreeSet::new();
    for (relation, receipt) in relations.iter().zip(receipts) {
        receipt.verify_match(
            config,
            expected_chain_id,
            relation.maker,
            relation.taker,
            relation.trade,
            relation.taker_admission,
        )?;
        next = next
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if receipt.body.match_sequence != next
            || !match_ids.insert(receipt.body.match_id)
            || !receipt_hashes.insert(receipt.receipt_hash())
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
    }
    Ok((
        successor_matcher_execution_receipt_batch_root_v2(receipts),
        next,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::{OrderFlags, Side, TimeInForce};
    use crate::successor_action_v2::{SuccessorLimitOrderV2, SuccessorSignedLimitOrderV2};
    use crate::types::{Amount, Price, Quantity};

    fn signer() -> (SuccessorCentralMatcherConfigV2, SecretKey) {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        (
            SuccessorCentralMatcherConfigV2 {
                version: SuccessorCentralMatcherConfigV2::VERSION,
                key_epoch: 3,
                signer: XOnlyKey(public.serialize()),
                genesis_sequence: (1u128 << 96) + 10,
                genesis_receipt_hash: [6; 32],
                forced_inclusion_blocks: 6,
            },
            secret,
        )
    }

    fn order(secret: &SecretKey, nonce: u128) -> SuccessorSignedLimitOrderV2 {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                version: SuccessorLimitOrderV2::VERSION,
                chain_id: [42; 32],
                market: ECX_USDD_MARKET,
                trader: XOnlyKey(public.serialize()),
                side: Side::Buy,
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                limit_price: Price::new(100_000_000).unwrap(),
                quantity: Quantity::new(3).unwrap(),
                client_order_id: [5; 16],
                max_fee_bps: 5,
                nonce,
                valid_from_height: 1,
                expires_at_height: 100,
            },
            secret,
        )
        .unwrap()
    }

    fn receipt(
        config: &SuccessorCentralMatcherConfigV2,
        secret: &SecretKey,
        sequence: u128,
        previous: Hash32,
    ) -> SuccessorCentralMatcherReceiptV2 {
        let signed = order(secret, sequence);
        SuccessorCentralMatcherReceiptV2::sign(
            SuccessorMatcherReceiptBodyV2 {
                version: SuccessorMatcherReceiptBodyV2::VERSION,
                chain_id: [42; 32],
                market: ECX_USDD_MARKET,
                matcher_config_hash: config.digest(),
                matcher_key_epoch: config.key_epoch,
                global_sequence: sequence,
                previous_receipt_hash: previous,
                command_kind: SuccessorMatcherCommandKindV2::Place,
                command_hash: successor_matcher_order_command_hash_v2(&signed),
                observed_sidechain_height: 10,
                observed_parent_height: 100,
                observed_parent_mtp: 1_000,
                forced_inbox_cursor: (1u128 << 96) + 4,
                availability_root: [9; 32],
            },
            secret,
            config,
        )
        .unwrap()
    }

    #[test]
    fn successor_matcher_chain_binds_u128_sequence_cursor_and_v1_separation() {
        let (config, secret) = signer();
        let first = receipt(
            &config,
            &secret,
            config.genesis_sequence + 1,
            config.genesis_receipt_hash,
        );
        let second = receipt(
            &config,
            &secret,
            config.genesis_sequence + 2,
            first.receipt_hash(),
        );
        assert_eq!(
            verify_successor_central_matcher_receipt_chain_v2(
                &config,
                [42; 32],
                config.genesis_sequence,
                config.genesis_receipt_hash,
                &[first.clone(), second.clone()],
            )
            .unwrap(),
            (config.genesis_sequence + 2, second.receipt_hash())
        );
        let mut high_sequence_mutation = first.clone();
        high_sequence_mutation.body.global_sequence ^= 1u128 << 96;
        assert_eq!(
            high_sequence_mutation.verify(&config),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        let mut high_cursor_mutation = first;
        high_cursor_mutation.body.forced_inbox_cursor ^= 1u128 << 96;
        assert_eq!(
            high_cursor_mutation.verify(&config),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        assert_ne!(
            config.digest(),
            canonical_hash("ECX/central-matcher-config/v1", &config)
        );
    }

    #[test]
    fn successor_execution_receipts_bind_u128_admission_and_match_sequences() {
        let (config, matcher_secret) = signer();
        let maker_secret = SecretKey::from_slice(&[8; 32]).unwrap();
        let taker_secret = SecretKey::from_slice(&[9; 32]).unwrap();
        let mut maker = order(&maker_secret, (1u128 << 96) + 20);
        let mut taker = order(&taker_secret, (1u128 << 96) + 21);
        maker.order.side = Side::Buy;
        maker.order.limit_price = Price::new(100_000_000).unwrap();
        maker = SuccessorSignedLimitOrderV2::sign(maker.order, &maker_secret).unwrap();
        taker.order.side = Side::Sell;
        taker.order.limit_price = Price::new(90_000_000).unwrap();
        taker = SuccessorSignedLimitOrderV2::sign(taker.order, &taker_secret).unwrap();
        let admission_sequence = (1u128 << 96) + 22;
        let admission = SuccessorCentralMatcherReceiptV2::sign(
            SuccessorMatcherReceiptBodyV2 {
                version: SuccessorMatcherReceiptBodyV2::VERSION,
                chain_id: [42; 32],
                market: ECX_USDD_MARKET,
                matcher_config_hash: config.digest(),
                matcher_key_epoch: config.key_epoch,
                global_sequence: admission_sequence,
                previous_receipt_hash: config.genesis_receipt_hash,
                command_kind: SuccessorMatcherCommandKindV2::Place,
                command_hash: successor_matcher_order_command_hash_v2(&taker),
                observed_sidechain_height: 10,
                observed_parent_height: 100,
                observed_parent_mtp: 1_000,
                forced_inbox_cursor: (1u128 << 96) + 4,
                availability_root: [9; 32],
            },
            &matcher_secret,
            &config,
        )
        .unwrap();
        let trade = SuccessorTradeMatchV2 {
            sequence: admission_sequence,
            maker_order_id: maker.order_id(),
            taker_order_id: taker.order_id(),
            maker: maker.order.trader,
            taker: taker.order.trader,
            maker_side: Side::Buy,
            price: maker.order.limit_price,
            quantity: Quantity::new(2).unwrap(),
            maker_fee: Amount(0),
            taker_fee: Amount(1),
        };
        let previous_match_sequence = (1u128 << 96) + 40;
        let receipt = SuccessorMatcherExecutionReceiptV2::issue(
            &config,
            &matcher_secret,
            [42; 32],
            &maker,
            &taker,
            &trade,
            previous_match_sequence + 1,
            &admission,
            [11; 32],
        )
        .unwrap();
        let relation = SuccessorMatcherExecutionRelationV2 {
            maker: &maker,
            taker: &taker,
            trade: &trade,
            taker_admission: &admission,
        };
        assert_eq!(
            verify_successor_matcher_execution_receipt_batch_v2(
                &config,
                [42; 32],
                previous_match_sequence,
                &[relation],
                std::slice::from_ref(&receipt),
            )
            .unwrap()
            .1,
            previous_match_sequence + 1
        );
        let mut mutated = receipt;
        mutated.body.match_sequence ^= 1u128 << 96;
        assert_eq!(
            mutated.verify_match(&config, [42; 32], &maker, &taker, &trade, &admission),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
    }
}
