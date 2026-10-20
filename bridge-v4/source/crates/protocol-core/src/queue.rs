use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::{canonical_hash, Hash32};
use crate::order::Signature64;
use crate::types::XOnlyKey;
use crate::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DepositRequest {
    pub version: u8,
    pub chain_id: Hash32,
    pub deposit_txid: Hash32,
    pub deposit_vout: u32,
    pub usdd_asset_id: Hash32,
    pub trader: XOnlyKey,
    pub amount: u64,
    pub observed_height: u64,
}

impl DepositRequest {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.amount == 0 {
            return Err(ProtocolError::InvalidQuantity);
        }
        Ok(())
    }

    pub fn request_id(&self) -> Hash32 {
        canonical_hash("ECX/deposit-request/v1", self)
    }
}

impl CanonicalEncode for DepositRequest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.deposit_txid);
        put_u32(out, self.deposit_vout);
        out.extend_from_slice(&self.usdd_asset_id);
        self.trader.encode_to(out);
        put_u64(out, self.amount);
        put_u64(out, self.observed_height);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WithdrawalRequest {
    pub version: u8,
    pub chain_id: Hash32,
    pub trader: XOnlyKey,
    pub nonce: u64,
    pub amount: u64,
    /// Hash of the complete destination script, not a truncated address string.
    pub destination_script_hash: Hash32,
    pub requested_height: u64,
    pub not_before_height: u64,
}

impl WithdrawalRequest {
    pub const VERSION: u8 = 1;
    pub const ENCODED_LEN: usize = 129;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.amount == 0 {
            return Err(ProtocolError::InvalidQuantity);
        }
        if self.not_before_height < self.requested_height {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/withdrawal-request/v1", self)
    }

    pub fn request_id(&self) -> Hash32 {
        canonical_hash("ECX/withdrawal-id/v1", self)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let request = Self {
            version: decoder.u8()?,
            chain_id: decoder.take()?,
            trader: XOnlyKey(decoder.take()?),
            nonce: decoder.u64()?,
            amount: decoder.u64()?,
            destination_script_hash: decoder.take()?,
            requested_height: decoder.u64()?,
            not_before_height: decoder.u64()?,
        };
        decoder.finish()?;
        request.validate()?;
        Ok(request)
    }
}

impl CanonicalEncode for WithdrawalRequest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.trader.encode_to(out);
        put_u64(out, self.nonce);
        put_u64(out, self.amount);
        out.extend_from_slice(&self.destination_script_hash);
        put_u64(out, self.requested_height);
        put_u64(out, self.not_before_height);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedWithdrawalRequest {
    pub request: WithdrawalRequest,
    pub signature: Signature64,
}

impl SignedWithdrawalRequest {
    pub const ENCODED_LEN: usize = WithdrawalRequest::ENCODED_LEN + 64;

    pub fn sign(request: WithdrawalRequest, secret_key: &SecretKey) -> Result<Self, ProtocolError> {
        request.validate()?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        if request.trader.0 != xonly.serialize() {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let message = Message::from_digest_slice(&request.signing_digest())
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(Self {
            request,
            signature: Signature64(*signature.as_ref()),
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.request.validate()?;
        let key = XOnlyPublicKey::from_slice(&self.request.trader.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let message = Message::from_digest_slice(&self.request.signing_digest())
            .map_err(|_| ProtocolError::InvalidSignature)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &key)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let request = WithdrawalRequest::decode_fixed(&bytes[..WithdrawalRequest::ENCODED_LEN])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[WithdrawalRequest::ENCODED_LEN..]);
        Ok(Self {
            request,
            signature: Signature64(signature),
        })
    }
}

impl CanonicalEncode for SignedWithdrawalRequest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.request.encode_to(out);
        self.signature.encode_to(out);
    }
}
