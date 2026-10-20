//! Single-signer central matcher sequencing receipts.
//!
//! The configured matcher may assign global order priority, but it is not a
//! custody or state-validity authority. Traders still sign every command and
//! the transition proof still checks matching, balances, risk, and state roots.

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::merkle::ordered_root;
use crate::order::{Signature64, SignedCancelOrder, SignedLimitOrder};
use crate::types::{MarketId, XOnlyKey, ECX_USDD_MARKET};
use crate::ProtocolError;

/// Absolute consensus ceiling. Production deployment freezes a much shorter
/// six-parent-block deadline, but no valid configuration may create an
/// effectively unbounded forced-action backlog window.
pub const MAX_FORCED_INCLUSION_BLOCKS: u32 = 144;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CentralMatcherConfigV1 {
    pub version: u8,
    pub key_epoch: u64,
    pub signer: XOnlyKey,
    pub genesis_sequence: u64,
    pub genesis_receipt_hash: Hash32,
    pub forced_inclusion_blocks: u32,
}

impl CentralMatcherConfigV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.signer.0 == [0; 32]
            || XOnlyPublicKey::from_slice(&self.signer.0).is_err()
            || self.genesis_sequence == u64::MAX
            || self.genesis_receipt_hash == [0; 32]
            || self.forced_inclusion_blocks == 0
            || self.forced_inclusion_blocks > MAX_FORCED_INCLUSION_BLOCKS
        {
            return Err(ProtocolError::InvalidCentralMatcherConfiguration);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/central-matcher-config/v1", self)
    }
}

impl CanonicalEncode for CentralMatcherConfigV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.key_epoch);
        self.signer.encode_to(out);
        put_u64(out, self.genesis_sequence);
        out.extend_from_slice(&self.genesis_receipt_hash);
        put_u32(out, self.forced_inclusion_blocks);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MatcherCommandKind {
    Place = 0,
    Cancel = 1,
}

impl CanonicalEncode for MatcherCommandKind {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MatcherReceiptBodyV1 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub matcher_config_hash: Hash32,
    pub matcher_key_epoch: u64,
    pub global_sequence: u64,
    pub previous_receipt_hash: Hash32,
    pub command_kind: MatcherCommandKind,
    pub command_hash: Hash32,
    /// Active sidechain height used for order live/expiry checks.
    pub observed_sidechain_height: u64,
    pub observed_parent_height: u64,
    pub observed_parent_mtp: u64,
    pub forced_inbox_cursor: u64,
    /// Commitment to the durably persisted command payload.
    pub availability_root: Hash32,
}

impl MatcherReceiptBodyV1 {
    pub const VERSION: u8 = 2;

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/central-matcher-receipt-body/v2", self)
    }
}

impl CanonicalEncode for MatcherReceiptBodyV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        out.extend_from_slice(&self.matcher_config_hash);
        put_u64(out, self.matcher_key_epoch);
        put_u64(out, self.global_sequence);
        out.extend_from_slice(&self.previous_receipt_hash);
        self.command_kind.encode_to(out);
        out.extend_from_slice(&self.command_hash);
        put_u64(out, self.observed_sidechain_height);
        put_u64(out, self.observed_parent_height);
        put_u64(out, self.observed_parent_mtp);
        put_u64(out, self.forced_inbox_cursor);
        out.extend_from_slice(&self.availability_root);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CentralMatcherReceiptV1 {
    pub body: MatcherReceiptBodyV1,
    pub signature: Signature64,
}

impl CentralMatcherReceiptV1 {
    pub fn sign(
        body: MatcherReceiptBodyV1,
        secret_key: &SecretKey,
        config: &CentralMatcherConfigV1,
    ) -> Result<Self, ProtocolError> {
        config.validate()?;
        if body.version != MatcherReceiptBodyV1::VERSION
            || body.matcher_config_hash != config.digest()
            || body.matcher_key_epoch != config.key_epoch
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
        canonical_hash("ECX/central-matcher-receipt/v1", self)
    }

    pub fn verify(&self, config: &CentralMatcherConfigV1) -> Result<(), ProtocolError> {
        config.validate()?;
        if self.body.version != MatcherReceiptBodyV1::VERSION
            || self.body.market != ECX_USDD_MARKET
            || self.body.matcher_config_hash != config.digest()
            || self.body.matcher_key_epoch != config.key_epoch
            || self.body.global_sequence == 0
            || self.body.command_hash == [0; 32]
            || self.body.availability_root == [0; 32]
            || self.body.observed_sidechain_height == 0
            || self.body.observed_parent_height == 0
            || self.body.observed_parent_mtp == 0
        {
            return Err(ProtocolError::InvalidMatcherReceipt);
        }
        self.body.market.validate()?;
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
}

impl CanonicalEncode for CentralMatcherReceiptV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.body.encode_to(out);
        self.signature.encode_to(out);
    }
}

pub fn matcher_order_command_hash(order: &SignedLimitOrder) -> Hash32 {
    canonical_hash("ECX/matcher-place-command/v1", order)
}

pub fn matcher_cancel_command_hash(cancel: &SignedCancelOrder) -> Hash32 {
    canonical_hash("ECX/matcher-cancel-command/v1", cancel)
}

pub fn central_matcher_receipt_batch_root(receipts: &[CentralMatcherReceiptV1]) -> Hash32 {
    let hashes: Vec<Hash32> = receipts
        .iter()
        .map(CentralMatcherReceiptV1::receipt_hash)
        .collect();
    ordered_root("ECX/central-matcher-receipt-batch/v1", &hashes)
}

pub fn verify_central_matcher_receipt_chain(
    config: &CentralMatcherConfigV1,
    expected_chain_id: Hash32,
    previous_sequence: u64,
    previous_receipt_hash: Hash32,
    receipts: &[CentralMatcherReceiptV1],
) -> Result<(u64, Hash32), ProtocolError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> (CentralMatcherConfigV1, SecretKey) {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        (
            CentralMatcherConfigV1 {
                version: 1,
                key_epoch: 3,
                signer: XOnlyKey(public.serialize()),
                genesis_sequence: 10,
                genesis_receipt_hash: [6; 32],
                forced_inclusion_blocks: 6,
            },
            secret,
        )
    }

    fn receipt(
        config: &CentralMatcherConfigV1,
        secret: &SecretKey,
        sequence: u64,
        previous: Hash32,
    ) -> CentralMatcherReceiptV1 {
        CentralMatcherReceiptV1::sign(
            MatcherReceiptBodyV1 {
                version: MatcherReceiptBodyV1::VERSION,
                chain_id: [42; 32],
                market: ECX_USDD_MARKET,
                matcher_config_hash: config.digest(),
                matcher_key_epoch: config.key_epoch,
                global_sequence: sequence,
                previous_receipt_hash: previous,
                command_kind: MatcherCommandKind::Place,
                command_hash: [8; 32],
                observed_sidechain_height: 10,
                observed_parent_height: 100,
                observed_parent_mtp: 1_000,
                forced_inbox_cursor: 4,
                availability_root: [9; 32],
            },
            secret,
            config,
        )
        .unwrap()
    }

    #[test]
    fn single_matcher_receipt_chain_verifies() {
        let (config, secret) = signer();
        let first = receipt(&config, &secret, 11, config.genesis_receipt_hash);
        let second = receipt(&config, &secret, 12, first.receipt_hash());
        let result = verify_central_matcher_receipt_chain(
            &config,
            [42; 32],
            config.genesis_sequence,
            config.genesis_receipt_hash,
            &[first, second.clone()],
        )
        .unwrap();
        assert_eq!(result, (12, second.receipt_hash()));
    }

    #[test]
    fn forced_inclusion_window_has_an_absolute_ceiling() {
        let (mut config, _) = signer();
        config.forced_inclusion_blocks = MAX_FORCED_INCLUSION_BLOCKS + 1;
        assert_eq!(
            config.validate(),
            Err(ProtocolError::InvalidCentralMatcherConfiguration)
        );
    }

    #[test]
    fn wrong_signer_or_mutated_body_is_rejected() {
        let (config, secret) = signer();
        let receipt = receipt(&config, &secret, 11, config.genesis_receipt_hash);
        let (other_config, _) = {
            let other = SecretKey::from_slice(&[8; 32]).unwrap();
            let keypair = Keypair::from_secret_key(&Secp256k1::new(), &other);
            let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
            (
                CentralMatcherConfigV1 {
                    signer: XOnlyKey(public.serialize()),
                    ..config.clone()
                },
                other,
            )
        };
        assert_eq!(
            receipt.verify(&other_config),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        let mut mutated = receipt;
        mutated.body.global_sequence += 1;
        assert_eq!(
            mutated.verify(&config),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
    }

    #[test]
    fn gap_or_wrong_previous_hash_is_rejected() {
        let (config, secret) = signer();
        let wrong = receipt(&config, &secret, 12, config.genesis_receipt_hash);
        assert_eq!(
            verify_central_matcher_receipt_chain(
                &config,
                [42; 32],
                config.genesis_sequence,
                config.genesis_receipt_hash,
                &[wrong],
            ),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
    }
}
