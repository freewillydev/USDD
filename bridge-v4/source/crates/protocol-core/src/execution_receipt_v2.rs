//! V2 matcher execution receipts used to timestamp funding observations.
//!
//! A V1 matcher receipt authenticates admission and priority for a signed
//! command. It does not authenticate the fills produced while processing that
//! command. This disjoint V2 receipt signs the exact proof-consumed match and
//! the node-observed parent context in which the matcher executed it. Funding
//! must bucket an ordinary fill by this committed parent MTP, never by a later
//! transition's inclusion time.

use std::collections::BTreeSet;

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::{put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::matcher_receipt::{
    matcher_order_command_hash, CentralMatcherConfigV1, CentralMatcherReceiptV1, MatcherCommandKind,
};
use crate::merkle::ordered_root;
use crate::order::{Signature64, SignedLimitOrder, TradeMatch};
use crate::types::{MarketId, Price, Quantity, ECX_USDD_MARKET};
use crate::ProtocolError;

/// Exact parent-chain observation used when the central matcher executed a
/// fill. The block hash is retained so a host/node integration can prove that
/// the signed timestamp belongs to the authenticated parent ancestry.
///
/// The V2 outer proof must supply one bounded canonical-header witness from
/// ten blocks before the earliest execution parent through its prior-parent
/// tip, validate 80-byte headers and links, bind that tip to `ProofBindingV2`,
/// recompute each locator's 11-header MTP window, and enforce the frozen
/// matcher-inclusion depth. This core type deliberately does not pretend that
/// a matcher signature authenticates Bitcoin ancestry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MatcherExecutionParentV2 {
    pub block_hash: Hash32,
    pub height: u64,
    pub median_time_past: u64,
}

impl MatcherExecutionParentV2 {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.block_hash == [0; 32] || self.height == 0 || self.median_time_past == 0 {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        Ok(self)
    }
}

impl CanonicalEncode for MatcherExecutionParentV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.block_hash);
        put_u64(out, self.height);
        put_u64(out, self.median_time_past);
    }
}

/// Signed match body. `match_id` commits the complete [`TradeMatch`], including
/// maker/taker identities, side and derived fees. The repeated order ids,
/// sequence, price and quantity make the consensus-relevant funding tuple
/// explicit and independently mutation-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MatcherExecutionReceiptBodyV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub matcher_config_hash: Hash32,
    pub matcher_key_epoch: u64,
    /// Hash of the V1 receipt that admitted the exact taker command.
    pub taker_admission_receipt_hash: Hash32,
    pub match_id: Hash32,
    pub maker_order_id: Hash32,
    pub taker_order_id: Hash32,
    /// Global sequence of the V1 receipt that admitted the taker command.
    /// One taker admission can legitimately produce several fills.
    pub admission_sequence: u64,
    /// Exactly contiguous per-fill sequence assigned from the dedicated V2
    /// execution-receipt cursor. It is deliberately distinct both from
    /// `admission_sequence` and from the matcher's internal event sequence,
    /// which may have gaps for non-fill events.
    pub match_sequence: u64,
    pub price: Price,
    pub quantity: Quantity,
    pub observed_sidechain_height: u64,
    pub execution_parent: MatcherExecutionParentV2,
}

impl MatcherExecutionReceiptBodyV2 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
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

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/central-matcher-execution-body/v2", self)
    }
}

impl CanonicalEncode for MatcherExecutionReceiptBodyV2 {
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
        put_u64(out, self.admission_sequence);
        put_u64(out, self.match_sequence);
        self.price.encode_to(out);
        self.quantity.encode_to(out);
        put_u64(out, self.observed_sidechain_height);
        self.execution_parent.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MatcherExecutionReceiptV2 {
    pub body: MatcherExecutionReceiptBodyV2,
    pub signature: Signature64,
}

impl MatcherExecutionReceiptV2 {
    /// Issue a receipt only for a fully signed, internally consistent matched
    /// pair and its exact taker-admission receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        config: &CentralMatcherConfigV1,
        secret_key: &SecretKey,
        expected_chain_id: Hash32,
        maker: &SignedLimitOrder,
        taker: &SignedLimitOrder,
        trade: &TradeMatch,
        match_sequence: u64,
        taker_admission: &CentralMatcherReceiptV1,
        execution_parent_block_hash: Hash32,
    ) -> Result<Self, ProtocolError> {
        config.validate()?;
        maker.verify()?;
        taker.verify()?;
        taker_admission.verify(config)?;
        trade.validate_orders(maker, taker, taker_admission.body.observed_sidechain_height)?;
        if expected_chain_id == [0; 32]
            || maker.order.chain_id != expected_chain_id
            || taker.order.chain_id != expected_chain_id
            || taker_admission.body.chain_id != expected_chain_id
            || taker_admission.body.command_kind != MatcherCommandKind::Place
            || taker_admission.body.command_hash != matcher_order_command_hash(taker)
            || taker_admission.body.global_sequence != trade.sequence
            || match_sequence == 0
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        let body = MatcherExecutionReceiptBodyV2 {
            version: MatcherExecutionReceiptBodyV2::VERSION,
            chain_id: expected_chain_id,
            market: trade_market(maker, taker)?,
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
            execution_parent: MatcherExecutionParentV2 {
                block_hash: execution_parent_block_hash,
                height: taker_admission.body.observed_parent_height,
                median_time_past: taker_admission.body.observed_parent_mtp,
            },
        };
        Self::sign_body(body, secret_key, config)
    }

    fn sign_body(
        body: MatcherExecutionReceiptBodyV2,
        secret_key: &SecretKey,
        config: &CentralMatcherConfigV1,
    ) -> Result<Self, ProtocolError> {
        config.validate()?;
        body.validate()?;
        if body.matcher_config_hash != config.digest() || body.matcher_key_epoch != config.key_epoch
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
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

    pub fn receipt_hash(&self) -> Hash32 {
        canonical_hash("ECX/central-matcher-execution-receipt/v2", self)
    }

    pub fn verify(&self, config: &CentralMatcherConfigV1) -> Result<(), ProtocolError> {
        config.validate()?;
        self.body.validate()?;
        if self.body.matcher_config_hash != config.digest()
            || self.body.matcher_key_epoch != config.key_epoch
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        let message = Message::from_digest_slice(&self.body.signing_digest())
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let key = XOnlyPublicKey::from_slice(&config.signer.0)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &key)
            .map_err(|_| ProtocolError::InvalidMatcherReceipt)
    }

    /// Verify the signed receipt against the exact proof-consumed execution.
    ///
    /// This relation is sufficient for protocol-core to derive a funding
    /// observation from the receipt. The outer proof must additionally call
    /// [`Self::verify_match`] with the exact V1 admission receipt and
    /// authenticate `execution_parent` against its bounded Bitcoin headers.
    pub fn verify_execution(
        &self,
        config: &CentralMatcherConfigV1,
        expected_chain_id: Hash32,
        maker: &SignedLimitOrder,
        taker: &SignedLimitOrder,
        trade: &TradeMatch,
    ) -> Result<(), ProtocolError> {
        self.verify(config)?;
        trade.validate_orders(maker, taker, self.body.observed_sidechain_height)?;
        if self.body.chain_id != expected_chain_id
            || maker.order.chain_id != expected_chain_id
            || taker.order.chain_id != expected_chain_id
            || self.body.market != maker.order.market
            || self.body.market != taker.order.market
            || self.body.match_id != trade.match_id()
            || self.body.maker_order_id != trade.maker_order_id
            || self.body.taker_order_id != trade.taker_order_id
            || self.body.admission_sequence != trade.sequence
            || self.body.price != trade.price
            || self.body.quantity != trade.quantity
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        Ok(())
    }

    /// Verify the exact match/admission relation. Parent-chain ancestry is a
    /// separate outer-proof/node obligation; a matcher signature alone cannot
    /// prove that `execution_parent.block_hash` is in the active Bitcoin chain.
    pub fn verify_match(
        &self,
        config: &CentralMatcherConfigV1,
        expected_chain_id: Hash32,
        maker: &SignedLimitOrder,
        taker: &SignedLimitOrder,
        trade: &TradeMatch,
        taker_admission: &CentralMatcherReceiptV1,
    ) -> Result<(), ProtocolError> {
        self.verify_execution(config, expected_chain_id, maker, taker, trade)?;
        taker_admission.verify(config)?;
        if self.body.taker_admission_receipt_hash != taker_admission.receipt_hash()
            || taker_admission.body.chain_id != expected_chain_id
            || taker_admission.body.command_kind != MatcherCommandKind::Place
            || taker_admission.body.command_hash != matcher_order_command_hash(taker)
            || self.body.observed_sidechain_height != taker_admission.body.observed_sidechain_height
            || self.body.execution_parent.height != taker_admission.body.observed_parent_height
            || self.body.execution_parent.median_time_past
                != taker_admission.body.observed_parent_mtp
            || self.body.admission_sequence != taker_admission.body.global_sequence
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        Ok(())
    }
}

/// Exact proof-side relation for one ordinary matcher execution.
///
/// Permissionless liquidation matches are intentionally not represented here:
/// their timestamp is the transition's authenticated prior-parent MTP rather
/// than a central matcher assertion.
#[derive(Debug, Clone, Copy)]
pub struct MatcherExecutionRelationV2<'a> {
    pub maker: &'a SignedLimitOrder,
    pub taker: &'a SignedLimitOrder,
    pub trade: &'a TradeMatch,
    pub taker_admission: &'a CentralMatcherReceiptV1,
}

/// Exact match relation available inside protocol-core before the outer proof
/// binds the V1 taker-admission receipt and Bitcoin parent-header witness.
#[derive(Debug, Clone, Copy)]
pub struct MatcherExecutionV2<'a> {
    pub maker: &'a SignedLimitOrder,
    pub taker: &'a SignedLimitOrder,
    pub trade: &'a TradeMatch,
}

pub fn verify_matcher_execution_batch_v2(
    config: &CentralMatcherConfigV1,
    expected_chain_id: Hash32,
    previous_match_sequence: u64,
    executions: &[MatcherExecutionV2<'_>],
    receipts: &[MatcherExecutionReceiptV2],
) -> Result<(Hash32, u64), ProtocolError> {
    if executions.len() != receipts.len() {
        return Err(ProtocolError::InvalidMatcherReceipt);
    }
    let mut next_match_sequence = previous_match_sequence;
    let mut match_ids = BTreeSet::new();
    let mut receipt_hashes = BTreeSet::new();
    let mut previous_context: Option<(u64, u64, u64)> = None;
    for (execution, receipt) in executions.iter().zip(receipts) {
        receipt.verify_execution(
            config,
            expected_chain_id,
            execution.maker,
            execution.taker,
            execution.trade,
        )?;
        next_match_sequence = next_match_sequence
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let context = (
            receipt.body.observed_sidechain_height,
            receipt.body.execution_parent.height,
            receipt.body.execution_parent.median_time_past,
        );
        if previous_context.is_some_and(|previous| {
            context.0 < previous.0 || context.1 < previous.1 || context.2 < previous.2
        }) || receipt.body.match_sequence != next_match_sequence
            || !match_ids.insert(receipt.body.match_id)
            || !receipt_hashes.insert(receipt.receipt_hash())
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        previous_context = Some(context);
    }
    Ok((
        matcher_execution_receipt_batch_root_v2(receipts),
        next_match_sequence,
    ))
}

/// Verify an exact, ordered, one-to-one set of ordinary fills and execution
/// receipts. The receipt order itself is consensus-significant: per-fill match
/// sequences must be exactly contiguous with the state-carried cursor, so no
/// fill can be duplicated, omitted, or reordered while advancing that cursor.
pub fn verify_matcher_execution_receipt_batch_v2(
    config: &CentralMatcherConfigV1,
    expected_chain_id: Hash32,
    previous_match_sequence: u64,
    relations: &[MatcherExecutionRelationV2<'_>],
    receipts: &[MatcherExecutionReceiptV2],
) -> Result<(Hash32, u64), ProtocolError> {
    if relations.len() != receipts.len() {
        return Err(ProtocolError::InvalidMatcherReceipt);
    }
    for (relation, receipt) in relations.iter().zip(receipts) {
        receipt.verify_match(
            config,
            expected_chain_id,
            relation.maker,
            relation.taker,
            relation.trade,
            relation.taker_admission,
        )?;
    }
    let executions = relations
        .iter()
        .map(|relation| MatcherExecutionV2 {
            maker: relation.maker,
            taker: relation.taker,
            trade: relation.trade,
        })
        .collect::<Vec<_>>();
    verify_matcher_execution_batch_v2(
        config,
        expected_chain_id,
        previous_match_sequence,
        &executions,
        receipts,
    )
}

impl CanonicalEncode for MatcherExecutionReceiptV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.body.encode_to(out);
        self.signature.encode_to(out);
    }
}

pub fn matcher_execution_receipt_batch_root_v2(receipts: &[MatcherExecutionReceiptV2]) -> Hash32 {
    ordered_root(
        "ECX/central-matcher-execution-receipt-batch/v2",
        &receipts
            .iter()
            .map(MatcherExecutionReceiptV2::receipt_hash)
            .collect::<Vec<_>>(),
    )
}

fn trade_market(
    maker: &SignedLimitOrder,
    taker: &SignedLimitOrder,
) -> Result<MarketId, ProtocolError> {
    if maker.order.market != taker.order.market || maker.order.market != ECX_USDD_MARKET {
        return Err(ProtocolError::InvalidMatcherReceipt);
    }
    Ok(maker.order.market)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher_receipt::{MatcherCommandKind, MatcherReceiptBodyV1};
    use crate::order::{LimitOrder, OrderFlags, Side, TimeInForce};
    use crate::types::{Amount, XOnlyKey, PRICE_SCALE};

    fn key(secret: &SecretKey) -> XOnlyKey {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        XOnlyKey(public.serialize())
    }

    fn order(secret: &SecretKey, chain_id: Hash32, side: Side, nonce: u64) -> SignedLimitOrder {
        SignedLimitOrder::sign(
            LimitOrder {
                version: LimitOrder::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader: key(secret),
                side,
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                limit_price: Price::new(100 * PRICE_SCALE).unwrap(),
                quantity: Quantity::new(25).unwrap(),
                client_order_id: [nonce as u8; 16],
                max_fee_bps: 25,
                nonce,
                valid_from_height: 1,
                expires_at_height: 500,
            },
            secret,
        )
        .unwrap()
    }

    fn fixture() -> (
        CentralMatcherConfigV1,
        SecretKey,
        SignedLimitOrder,
        SignedLimitOrder,
        TradeMatch,
        CentralMatcherReceiptV1,
        MatcherExecutionReceiptV2,
    ) {
        let matcher_secret = SecretKey::from_slice(&[41; 32]).unwrap();
        let maker_secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let taker_secret = SecretKey::from_slice(&[43; 32]).unwrap();
        let chain_id = [44; 32];
        let config = CentralMatcherConfigV1 {
            version: CentralMatcherConfigV1::VERSION,
            key_epoch: 7,
            signer: key(&matcher_secret),
            genesis_sequence: 10,
            genesis_receipt_hash: [45; 32],
            forced_inclusion_blocks: 6,
        };
        let maker = order(&maker_secret, chain_id, Side::Sell, 1);
        let taker = order(&taker_secret, chain_id, Side::Buy, 2);
        let trade = TradeMatch {
            // Existing TradeMatch sequencing remains the taker's admission
            // sequence; the V2 receipt carries per-fill ordering separately.
            sequence: 11,
            maker_order_id: maker.order_id(),
            taker_order_id: taker.order_id(),
            maker: maker.order.trader,
            taker: taker.order.trader,
            maker_side: Side::Sell,
            price: maker.order.limit_price,
            quantity: Quantity::new(10).unwrap(),
            maker_fee: Amount(0),
            taker_fee: Amount(5),
        };
        let admission = CentralMatcherReceiptV1::sign(
            MatcherReceiptBodyV1 {
                version: MatcherReceiptBodyV1::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                matcher_config_hash: config.digest(),
                matcher_key_epoch: config.key_epoch,
                global_sequence: 11,
                previous_receipt_hash: config.genesis_receipt_hash,
                command_kind: MatcherCommandKind::Place,
                command_hash: matcher_order_command_hash(&taker),
                observed_sidechain_height: 100,
                observed_parent_height: 900,
                observed_parent_mtp: 1_700_000_000,
                forced_inbox_cursor: 0,
                availability_root: [46; 32],
            },
            &matcher_secret,
            &config,
        )
        .unwrap();
        let execution = MatcherExecutionReceiptV2::issue(
            &config,
            &matcher_secret,
            chain_id,
            &maker,
            &taker,
            &trade,
            18,
            &admission,
            [47; 32],
        )
        .unwrap();
        (
            config,
            matcher_secret,
            maker,
            taker,
            trade,
            admission,
            execution,
        )
    }

    #[test]
    fn exact_match_and_admission_are_authenticated() {
        let (config, _, maker, taker, trade, admission, execution) = fixture();
        execution
            .verify_match(&config, [44; 32], &maker, &taker, &trade, &admission)
            .unwrap();
        assert_eq!(execution.body.admission_sequence, 11);
        assert_eq!(execution.body.match_sequence, 18);
        assert_ne!(execution.receipt_hash(), [0; 32]);
    }

    #[test]
    fn every_funding_and_time_field_is_signature_bound() {
        let (config, _, maker, taker, trade, admission, execution) = fixture();
        let mutations: [fn(&mut MatcherExecutionReceiptV2); 11] = [
            |receipt| receipt.body.match_id[0] ^= 1,
            |receipt| receipt.body.maker_order_id[0] ^= 1,
            |receipt| receipt.body.taker_order_id[0] ^= 1,
            |receipt| receipt.body.admission_sequence += 1,
            |receipt| receipt.body.match_sequence += 1,
            |receipt| receipt.body.price = Price::new(receipt.body.price.get() + 1).unwrap(),
            |receipt| {
                receipt.body.quantity = Quantity::new(receipt.body.quantity.get() + 1).unwrap()
            },
            |receipt| receipt.body.taker_admission_receipt_hash[0] ^= 1,
            |receipt| receipt.body.execution_parent.block_hash[0] ^= 1,
            |receipt| receipt.body.execution_parent.height += 1,
            |receipt| receipt.body.execution_parent.median_time_past += 1,
        ];
        for mutate in mutations {
            let mut changed = execution.clone();
            mutate(&mut changed);
            assert_eq!(
                changed.verify_match(&config, [44; 32], &maker, &taker, &trade, &admission),
                Err(ProtocolError::InvalidMatcherReceipt)
            );
        }
    }

    #[test]
    fn a_place_receipt_for_another_taker_cannot_authorize_the_match() {
        let (config, matcher_secret, maker, taker, trade, mut admission, _) = fixture();
        admission.body.command_hash[0] ^= 1;
        admission =
            CentralMatcherReceiptV1::sign(admission.body, &matcher_secret, &config).unwrap();
        assert_eq!(
            MatcherExecutionReceiptV2::issue(
                &config,
                &matcher_secret,
                [44; 32],
                &maker,
                &taker,
                &trade,
                18,
                &admission,
                [47; 32],
            ),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
    }

    #[test]
    fn batch_is_exact_unique_and_strictly_execution_ordered() {
        let (config, matcher_secret, maker, taker, first_trade, admission, first) = fixture();
        let mut second_trade = first_trade.clone();
        second_trade.quantity = Quantity::new(5).unwrap();
        let second = MatcherExecutionReceiptV2::issue(
            &config,
            &matcher_secret,
            [44; 32],
            &maker,
            &taker,
            &second_trade,
            19,
            &admission,
            [47; 32],
        )
        .unwrap();
        assert_eq!(
            first.body.admission_sequence,
            second.body.admission_sequence
        );
        let relations = [
            MatcherExecutionRelationV2 {
                maker: &maker,
                taker: &taker,
                trade: &first_trade,
                taker_admission: &admission,
            },
            MatcherExecutionRelationV2 {
                maker: &maker,
                taker: &taker,
                trade: &second_trade,
                taker_admission: &admission,
            },
        ];
        let receipts = [first.clone(), second.clone()];
        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(
                &config,
                [44; 32],
                17,
                &relations,
                &receipts,
            )
            .unwrap(),
            (matcher_execution_receipt_batch_root_v2(&receipts), 19)
        );

        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(
                &config,
                [44; 32],
                17,
                &relations,
                &receipts[..1],
            ),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(
                &config,
                [44; 32],
                17,
                &relations,
                &[second.clone(), first.clone()],
            ),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(
                &config,
                [44; 32],
                17,
                &relations,
                &[first.clone(), first],
            ),
            Err(ProtocolError::InvalidMatcherReceipt)
        );

        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(&config, [44; 32], 18, &relations, &receipts,),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        let mut gap = receipts.clone();
        gap[1].body.match_sequence += 1;
        gap[1] =
            MatcherExecutionReceiptV2::sign_body(gap[1].body.clone(), &matcher_secret, &config)
                .unwrap();
        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(&config, [44; 32], 17, &relations, &gap,),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        let context_mutations: [fn(&mut MatcherExecutionReceiptV2); 3] = [
            |receipt: &mut MatcherExecutionReceiptV2| receipt.body.observed_sidechain_height -= 1,
            |receipt: &mut MatcherExecutionReceiptV2| receipt.body.execution_parent.height -= 1,
            |receipt: &mut MatcherExecutionReceiptV2| {
                receipt.body.execution_parent.median_time_past -= 1
            },
        ];
        for mutate in context_mutations {
            let mut inverted = receipts.clone();
            mutate(&mut inverted[1]);
            inverted[1] = MatcherExecutionReceiptV2::sign_body(
                inverted[1].body.clone(),
                &matcher_secret,
                &config,
            )
            .unwrap();
            assert_eq!(
                verify_matcher_execution_receipt_batch_v2(
                    &config, [44; 32], 17, &relations, &inverted,
                ),
                Err(ProtocolError::InvalidMatcherReceipt)
            );
        }
        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(&config, [44; 32], 19, &[], &[]),
            Ok((matcher_execution_receipt_batch_root_v2(&[]), 19))
        );
        assert_eq!(
            verify_matcher_execution_receipt_batch_v2(
                &config,
                [44; 32],
                u64::MAX,
                &relations[..1],
                &receipts[..1],
            ),
            Err(ProtocolError::ArithmeticOverflow)
        );
    }

    #[test]
    fn admission_and_match_sequences_are_distinct_and_independently_bound() {
        let (config, matcher_secret, maker, taker, trade, admission, execution) = fixture();
        assert_ne!(
            execution.body.admission_sequence,
            execution.body.match_sequence
        );

        let mut wrong_trade_sequence = trade.clone();
        wrong_trade_sequence.sequence += 1;
        assert_eq!(
            MatcherExecutionReceiptV2::issue(
                &config,
                &matcher_secret,
                [44; 32],
                &maker,
                &taker,
                &wrong_trade_sequence,
                19,
                &admission,
                [47; 32],
            ),
            Err(ProtocolError::InvalidMatcherReceipt)
        );

        let mut wrong_admission = admission.clone();
        wrong_admission.body.global_sequence += 1;
        wrong_admission =
            CentralMatcherReceiptV1::sign(wrong_admission.body, &matcher_secret, &config).unwrap();
        assert_eq!(
            MatcherExecutionReceiptV2::issue(
                &config,
                &matcher_secret,
                [44; 32],
                &maker,
                &taker,
                &trade,
                19,
                &wrong_admission,
                [47; 32],
            ),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
    }
}
