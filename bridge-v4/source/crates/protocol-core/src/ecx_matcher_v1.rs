//! Matcher attestations for the ECX execution relation, not oracle proofs.
//! Consumers must recompute execution and authenticate the previous cursor.
use crate::ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1};
use crate::hash::{tagged_hash, Hash32};
use crate::order::Signature64;
use crate::successor_matcher_v2::SuccessorCentralMatcherConfigV2;
use crate::ProtocolError;
use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

/// Recompute signed fills, fees, margin and Merkle replacements before accepting
/// matcher authorization. Source roots/cursor and oracle context still require
/// authentication by the enclosing successor; this is not a complete proof.
pub fn stage_ecx_matcher_authorized_match(
    accounts_root: Hash32,
    orders_root: Hash32,
    bindings: EcxSuccessorBindingsV1,
    economics: EcxConfigurationV1,
    matcher: &SuccessorCentralMatcherConfigV2,
    previous_cursor: (u128, Hash32),
    receipt: &EcxMatcherExecutionReceiptV1,
    maker: crate::ecx_order_index_v1::EcxIndexedOrderOpeningV1<'_>,
    taker: crate::ecx_order_index_v1::EcxIndexedOrderOpeningV1<'_>,
    clearing: crate::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
    height: u64,
    quantity: u64,
    settlement_price: crate::types::Price,
    funding: i128,
    low: crate::types::Price,
    high: crate::types::Price,
    context: crate::ecx_order_index_v1::EcxExecutionContextV1,
    fees: Option<crate::ecx_order_index_v1::EcxMatchFeeWitnessV1<'_>>,
    source_orders: &[&crate::ecx_order_v1::EcxAdmittedOrderV2],
) -> Result<(crate::ecx_order_index_v1::EcxIndexedMatchV1, Hash32), ProtocolError> {
    bindings.account_domain(economics)?;
    let (result, execution_hash) = crate::ecx_order_index_v1::stage_ecx_committed_match(
        accounts_root,
        orders_root,
        economics,
        maker,
        taker,
        clearing,
        height,
        quantity,
        settlement_price,
        funding,
        low,
        high,
        context,
        fees,
        source_orders,
    )?;
    let receipt_hash = receipt.verify(
        bindings,
        economics,
        matcher,
        previous_cursor.0,
        previous_cursor.1,
        (context.match_sequence, execution_hash),
    )?;
    Ok((result, receipt_hash))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EcxMatcherExecutionReceiptV1 {
    pub economic_hash: Hash32,
    pub matcher_hash: Hash32,
    pub sequence: u128,
    pub previous_receipt: Hash32,
    pub execution_hash: Hash32,
    pub signature: Signature64,
}

impl EcxMatcherExecutionReceiptV1 {
    fn body(&self) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&self.economic_hash);
        bytes.extend_from_slice(&self.matcher_hash);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.previous_receipt);
        bytes.extend_from_slice(&self.execution_hash);
        bytes
    }

    fn signing_digest(&self) -> Hash32 {
        tagged_hash("ECX/ecx-matcher-execution/v1", &self.body())
    }

    pub fn digest(&self) -> Hash32 {
        let mut bytes = self.body();
        bytes.extend_from_slice(&self.signature.0);
        tagged_hash("ECX/ecx-matcher-execution-receipt/v1", &bytes)
    }

    /// Sign a computed execution commitment. This does not compute or prove
    /// execution, book priority, forced inclusion or parent-chain inclusion.
    pub fn sign(
        economics: EcxConfigurationV1,
        matcher: &SuccessorCentralMatcherConfigV2,
        sequence: u128,
        previous_receipt: Hash32,
        execution_hash: Hash32,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        matcher.validate()?;
        let secp = Secp256k1::new();
        let pair = Keypair::from_secret_key(&secp, key);
        if pair.x_only_public_key().0.serialize() != matcher.signer.0
            || sequence <= matcher.genesis_sequence
            || previous_receipt == [0; 32]
            || execution_hash == [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let mut receipt = Self {
            economic_hash: economics.digest()?,
            matcher_hash: matcher.digest(),
            sequence,
            previous_receipt,
            execution_hash,
            signature: Signature64([0; 64]),
        };
        receipt.signature = Signature64(
            *secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(receipt.signing_digest()), &pair)
                .as_ref(),
        );
        Ok(receipt)
    }

    /// Verify against opened, outer-pinned policies and a freshly recomputed
    /// execution hash. The supplied cursor must come from authenticated state;
    /// callers cannot establish continuity by selecting an arbitrary cursor.
    pub fn verify(
        &self,
        bindings: EcxSuccessorBindingsV1,
        economics: EcxConfigurationV1,
        matcher: &SuccessorCentralMatcherConfigV2,
        previous_sequence: u128,
        previous_receipt: Hash32,
        execution: (u128, Hash32),
    ) -> Result<Hash32, ProtocolError> {
        let (execution_sequence, execution_hash) = execution;
        let domain = bindings.account_domain(economics)?;
        matcher.validate()?;
        if bindings.matcher_configuration_hash != matcher.digest()
            || self.matcher_hash != matcher.digest()
            || self.economic_hash != domain.configuration_hash
            || self.execution_hash != execution_hash
            || execution_hash == [0; 32]
            || self.sequence != execution_sequence
            || previous_receipt == [0; 32]
            || self.previous_receipt != previous_receipt
            || previous_sequence < matcher.genesis_sequence
            || previous_sequence.checked_add(1) != Some(self.sequence)
            || (previous_sequence == matcher.genesis_sequence
                && previous_receipt != matcher.genesis_receipt_hash)
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let key = XOnlyPublicKey::from_slice(&matcher.signer.0)
            .map_err(|_| ProtocolError::InvalidBondState)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidBondState)?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(self.signing_digest()),
                &key,
            )
            .map_err(|_| ProtocolError::InvalidBondState)?;
        Ok(self.digest())
    }
}
