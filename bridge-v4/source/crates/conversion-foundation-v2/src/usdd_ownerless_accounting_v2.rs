// Pinned source-internal copy. Original lib.rs SHA-256:
// 976d3449ed92b7e9116e1f29fb22af0dbdf8bcf5d337d534a0fc63ca50dfabb1
// Only the crate-level no_std attribute was removed for module integration.
//! Engineering-only, explicit ownerless-vault adapter. This is NOT an Ethereum
//! finality/MPT verifier, a redemption proof verifier, or a proof-ready flag.
//! The caller must freeze/review `ConfigurationV2`, verify the checkpoint, and
//! supply a genuine `AuthenticatedEthereumStateV2` implementation. This crate
//! supplies no implementation of that trust boundary, permissive or otherwise.
//! No generic pause/governance slots are invented for contracts lacking them.

use sha2::{Digest, Sha256};

pub type Hash32 = [u8; 32];
pub type Address20 = [u8; 20];
pub const ADAPTER_VERSION: u32 = 2;
pub const MAX_ACCOUNTED_CUSTODY_USDT6: u64 = 1_000_000_000_000_000;

/// Solidity uint256 in canonical 32-byte big-endian storage-word order.
/// No truncation to u128/u64 is allowed in accounting arithmetic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub const ZERO: Self = Self([0; 32]);
    pub const MAX: Self = Self([255; 32]);
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut bytes = [0; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = u16::from(self.0[i]) + u16::from(rhs.0[i]) + carry;
            bytes[i] = sum as u8;
            carry = sum >> 8;
        }
        (carry == 0).then_some(Self(bytes))
    }
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        let mut bytes = [0; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let difference = i16::from(self.0[i]) - i16::from(rhs.0[i]) - borrow;
            bytes[i] = difference as u8;
            borrow = i16::from(difference < 0);
        }
        (borrow == 0).then_some(Self(bytes))
    }
}

/// Exact solc 0.8.30 storage layout of the copied USDDVaultV2 source closure.
/// `compile-layout.mjs` independently checks these named slots and offsets.
pub mod layout {
    pub const PACKED_NONCES: u64 = 0;
    pub const PENDING_ESCROW: u64 = 1;
    pub const PENDING_BOUNTY: u64 = 2;
    pub const COMMITTED_LIABILITY: u64 = 3;
    pub const COMMITTED_BOUNTY: u64 = 4;
    pub const UNRESOLVED_COMMITTED: u64 = 5;
    pub const MINT_ACKNOWLEDGED: u64 = 6;
    pub const REENTRANCY_LOCK: u64 = 19;
    pub const RELAY_BINDING: u64 = 20;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedAnchorV2 {
    pub chain_id: u64,
    pub execution_block_hash: Hash32,
    pub execution_state_root: Hash32,
    pub execution_block_number: u64,
    pub execution_timestamp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractIdentityV2 {
    pub address: Address20,
    /// Ethereum EXTCODEHASH of the actual immutable-patched deployed runtime,
    /// NOT SHA-256 of a compiler runtime template.
    pub runtime_code_hash: Hash32,
}

/// Trusted/frozen configuration input, NOT a self-authenticating manifest.
/// All identities must be tied by a reviewed deployed-code/constructor binding.
/// In particular the vault's immutable USDT, relay, and redemption-verifier
/// addresses and identity getters must match these pinned identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationV2 {
    pub version: u32,
    pub chain_id: u64,
    pub vault: ContractIdentityV2,
    pub token: ContractIdentityV2,
    pub relay: ContractIdentityV2,
    pub redemption_verifier: ContractIdentityV2,
    pub relay_verifier_config_hash: Hash32,
    pub terminal_vault_policy_hash: Hash32,
    /// Full raw Solidity storage key for token.balanceOf(vault). The token's
    /// exact reviewed code/layout must establish this mapping. It is NOT a
    /// caller-chosen witness key, an account trie hash, or a default zero slot.
    /// Proxy tokens require an additional authenticated implementation binding
    /// and cannot be treated as immutable solely by pinning proxy codehash.
    pub token_vault_balance_storage_key: Hash32,
}

/// SECURITY BOUNDARY: the implementation must authenticate account inclusion
/// (including the runtime code hash) and exact storage values under *this*
/// verified finalized anchor, including non-inclusion proofs for zero words.
/// A missing/failed proof must return None, never silently produce zero.
/// Merely forwarding JSON-RPC values or deserializing a host claim is invalid.
/// Implementations with caches must include anchor + address + key in cache keys.
pub trait AuthenticatedEthereumStateV2 {
    fn anchor(&self) -> FinalizedAnchorV2;
    fn account_code_hash(&self, address: Address20) -> Option<Hash32>;
    fn storage_word(&self, address: Address20, raw_storage_key: Hash32) -> Option<Hash32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedNoncesV2 {
    pub next_intent_nonce: u64,
    pub next_committed_deposit_nonce: u64,
}

pub fn decode_nonces_v2(word: Hash32) -> Result<PackedNoncesV2, ErrorV2> {
    // Solidity offsets count from the low/right end of the 32-byte word.
    if word[..16].iter().any(|byte| *byte != 0) {
        return Err(ErrorV2::NonCanonicalNoncePadding);
    }
    let next_intent_nonce = u64::from_be_bytes(word[24..32].try_into().unwrap());
    let next_committed_deposit_nonce = u64::from_be_bytes(word[16..24].try_into().unwrap());
    if next_committed_deposit_nonce > next_intent_nonce {
        return Err(ErrorV2::NonceOrder);
    }
    Ok(PackedNoncesV2 {
        next_intent_nonce,
        next_committed_deposit_nonce,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountingReportV2 {
    pub version: u32,
    pub anchor: FinalizedAnchorV2,
    pub nonces: PackedNoncesV2,
    pub reserve_usdt6: U256,
    pub accounted_custody_usdt6: U256,
    pub pending_principal_usdt6: U256,
    pub pending_bounty_usdt6: U256,
    pub committed_principal_usdt6: U256,
    pub committed_bounty_usdt6: U256,
    pub unresolved_committed_usdt6: U256,
    pub mint_acknowledged_usdt6: U256,
    pub other_obligations_usdt6: U256,
    /// Conservative minted-redemption backing, never pending principal,
    /// unresolved principal, a bounty, or unsolicited faucet surplus.
    pub minted_redemption_backing_usdt6: U256,
    pub unallocated_surplus_usdt6: U256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorV2 {
    InvalidConfiguration,
    InvalidAnchor,
    AnchorMismatch,
    MissingAccountProof,
    CodeIdentityMismatch,
    MissingStorageProof,
    NonCanonicalNoncePadding,
    NonceOrder,
    ReentrancyState,
    RelayNotInitialized,
    RelayBindingMismatch,
    ArithmeticOverflow,
    CommittedPartitionMismatch,
    AccountedCustodyAboveCap,
    Insolvent,
    MintOutstandingNotCovered,
}

/// Exactly sha256(abi.encodePacked(relay.codehash, verifierConfig, policy)).
pub fn relay_binding_v2(config: &ConfigurationV2) -> Hash32 {
    let mut h = Sha256::new();
    h.update(config.relay.runtime_code_hash);
    h.update(config.relay_verifier_config_hash);
    h.update(config.terminal_vault_policy_hash);
    h.finalize().into()
}

/// Evaluate only source-specific accounting against an externally authenticated
/// snapshot. `required_mint_outstanding_usdt6` must be derived from an authentic
/// Elements checkpoint using an exact, reviewed scale; it is not raw USDD atoms.
/// This function does not authenticate that Elements input or certify redemption
/// liveness, relay freshness, burn validity, price, or end-to-end proof readiness.
pub fn evaluate_ownerless_vault_v2<S: AuthenticatedEthereumStateV2>(
    config: &ConfigurationV2,
    expected_anchor: FinalizedAnchorV2,
    state: &S,
    required_mint_outstanding_usdt6: U256,
) -> Result<AccountingReportV2, ErrorV2> {
    validate_configuration(config)?;
    if expected_anchor.chain_id != config.chain_id
        || expected_anchor.execution_block_hash == [0; 32]
        || expected_anchor.execution_state_root == [0; 32]
        || expected_anchor.execution_block_number == 0
        || expected_anchor.execution_timestamp == 0
    {
        return Err(ErrorV2::InvalidAnchor);
    }
    if state.anchor() != expected_anchor {
        return Err(ErrorV2::AnchorMismatch);
    }
    for identity in [
        config.vault,
        config.token,
        config.relay,
        config.redemption_verifier,
    ] {
        let code = state
            .account_code_hash(identity.address)
            .ok_or(ErrorV2::MissingAccountProof)?;
        if code != identity.runtime_code_hash {
            return Err(ErrorV2::CodeIdentityMismatch);
        }
    }
    let read = |slot: u64| -> Result<Hash32, ErrorV2> {
        state
            .storage_word(config.vault.address, U256::from_u64(slot).0)
            .ok_or(ErrorV2::MissingStorageProof)
    };
    let nonces = decode_nonces_v2(read(layout::PACKED_NONCES)?)?;
    if U256(read(layout::REENTRANCY_LOCK)?) != U256::from_u64(1) {
        return Err(ErrorV2::ReentrancyState);
    }
    let relay_binding = read(layout::RELAY_BINDING)?;
    if relay_binding == [0; 32] {
        return Err(ErrorV2::RelayNotInitialized);
    }
    if relay_binding != relay_binding_v2(config) {
        return Err(ErrorV2::RelayBindingMismatch);
    }
    let pending = U256(read(layout::PENDING_ESCROW)?);
    let pending_bounty = U256(read(layout::PENDING_BOUNTY)?);
    let committed = U256(read(layout::COMMITTED_LIABILITY)?);
    let committed_bounty = U256(read(layout::COMMITTED_BOUNTY)?);
    let unresolved = U256(read(layout::UNRESOLVED_COMMITTED)?);
    let mint_ack = U256(read(layout::MINT_ACKNOWLEDGED)?);
    let add = |a: U256, b: U256| a.checked_add(b).ok_or(ErrorV2::ArithmeticOverflow);
    if add(unresolved, mint_ack)? != committed {
        return Err(ErrorV2::CommittedPartitionMismatch);
    }
    let accounted = add(
        add(add(pending, pending_bounty)?, committed)?,
        committed_bounty,
    )?;
    if accounted > U256::from_u64(MAX_ACCOUNTED_CUSTODY_USDT6) {
        return Err(ErrorV2::AccountedCustodyAboveCap);
    }
    let reserve = U256(
        state
            .storage_word(config.token.address, config.token_vault_balance_storage_key)
            .ok_or(ErrorV2::MissingStorageProof)?,
    );
    if reserve < accounted {
        return Err(ErrorV2::Insolvent);
    }
    let other_obligations = add(
        add(add(pending, pending_bounty)?, unresolved)?,
        committed_bounty,
    )?;
    let freely_available = reserve
        .checked_sub(other_obligations)
        .ok_or(ErrorV2::Insolvent)?;
    let backing = core::cmp::min(mint_ack, freely_available);
    if required_mint_outstanding_usdt6 > backing {
        return Err(ErrorV2::MintOutstandingNotCovered);
    }
    Ok(AccountingReportV2 {
        version: ADAPTER_VERSION,
        anchor: expected_anchor,
        nonces,
        reserve_usdt6: reserve,
        accounted_custody_usdt6: accounted,
        pending_principal_usdt6: pending,
        pending_bounty_usdt6: pending_bounty,
        committed_principal_usdt6: committed,
        committed_bounty_usdt6: committed_bounty,
        unresolved_committed_usdt6: unresolved,
        mint_acknowledged_usdt6: mint_ack,
        other_obligations_usdt6: other_obligations,
        minted_redemption_backing_usdt6: backing,
        unallocated_surplus_usdt6: reserve.checked_sub(accounted).ok_or(ErrorV2::Insolvent)?,
    })
}

fn validate_configuration(config: &ConfigurationV2) -> Result<(), ErrorV2> {
    if config.version != ADAPTER_VERSION
        || config.chain_id == 0
        || config.relay_verifier_config_hash == [0; 32]
        || config.terminal_vault_policy_hash == [0; 32]
    {
        return Err(ErrorV2::InvalidConfiguration);
    }
    let identities = [
        config.vault,
        config.token,
        config.relay,
        config.redemption_verifier,
    ];
    for (i, identity) in identities.iter().enumerate() {
        if identity.address == [0; 20]
            || identity.runtime_code_hash == [0; 32]
            || identities[..i]
                .iter()
                .any(|other| other.address == identity.address)
        {
            return Err(ErrorV2::InvalidConfiguration);
        }
    }
    Ok(())
}

