//! Authenticated state primitives for the full Elements consensus relation.
//!
//! Confidential outputs do not expose values that can be safely accumulated
//! in public state. This tree therefore commits the exact consensus `TxOut`
//! bytes and a checked leaf count. Asset/value conservation is a mandatory
//! transaction relation built over authenticated openings and proofs, not a
//! host-supplied aggregate in this accumulator.

use crate::bip300_v2::{apply_bip300_block_v2, Bip300AllSlotStateV2};
use crate::script_v2::{
    remove_exact_signature_pushes_v2, valid_defined_sighash_type_v2,
    valid_strict_der_signature_encoding_v2, verify_script_components_with_checkers_v2,
    LegacyScriptFlagsV2, ScriptLockContextV2, ScriptPrimitiveErrorV2, ScriptSignatureCheckerV2,
};
use crate::{
    apply_bitcoin_block_utxos_v2, median_time_past_v2, verify_bitcoin_block_foundation_v2,
    verify_next_header_context_v2, BitcoinBlockSpendContextV2,
    BitcoinBlockUtxoWitnessV2, BitcoinPowContextV2, FullBitcoinScriptVerifierV2, SparseUtxoNodeV2,
    BITCOIN_MAX_BLOCK_WEIGHT_V2,
};
use bitcoin::consensus::encode::deserialize as bitcoin_deserialize;
use bitcoin::Block as BitcoinBlock;
use elements::confidential::{Asset, Nonce, Value};
use elements::encode::serialize;
use elements::hashes::Hash as _;
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::Secp256k1;
use elements::secp256k1_zkp::{ecdsa, schnorr, Message, PublicKey, XOnlyPublicKey};
use elements::sighash::SighashCache as ElementsSighashCache;
use elements::sighash::{Annex as ElementsAnnex, Prevouts as ElementsPrevouts};
use elements::taproot::ControlBlock as ElementsControlBlock;
use elements::{Block, BlockHash, OutPoint, Transaction, TxMerkleNode, TxOut};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::str::FromStr;
use thiserror::Error;

pub type ElementsHash32V2 = [u8; 32];
pub const ELEMENTS_SPARSE_UTXO_DEPTH_V2: usize = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsUtxoAggregateV2 {
    pub count: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseUtxoNodeV2 {
    pub hash: ElementsHash32V2,
    pub aggregate: ElementsUtxoAggregateV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsUtxoLeafV2 {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub creation_height: u32,
    pub creation_parent_mtp: u32,
    pub coinbase: bool,
    /// Exact source classification needed for peg-in and issuance rules.
    pub created_by_issuance: bool,
    pub created_by_pegin: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseUtxoPathV2 {
    /// Leaf-to-root siblings in leaf-first order. Exactly 256 are canonical.
    pub siblings: Vec<ElementsSparseUtxoNodeV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseUtxoMutationV2 {
    pub outpoint: OutPoint,
    pub old_leaf: Option<ElementsUtxoLeafV2>,
    pub new_leaf: Option<ElementsUtxoLeafV2>,
    pub path: ElementsSparseUtxoPathV2,
}

/// Economic projection committed alongside the exact UTXO accumulator.  This
/// is a separate root so introducing authenticated confidential totals cannot
/// reinterpret historical count-only UTXO roots.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsEconomicAggregateV2 {
    pub count: u128,
    pub outstanding_base_atoms: u128,
    pub redeemable_reserve_quote_atoms: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseEconomicNodeV2 {
    pub hash: ElementsHash32V2,
    pub aggregate: ElementsEconomicAggregateV2,
}

/// Exhaustive role of a spendable output in the authenticated economic state.
/// Burn and fee are transition-only roles and therefore cannot occur in this
/// live-UTXO tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ElementsLiveEconomicRoleV2 {
    OutstandingBase,
    RedeemableReserve,
    RedemptionInventory,
    Irrelevant,
}

/// Frozen identities needed to derive, rather than trust, each economic role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsEconomicClassificationV2 {
    pub base_asset_id: ElementsHash32V2,
    pub policy_asset_id: ElementsHash32V2,
    pub redemption_inventory_script_sha256: ElementsHash32V2,
    pub reserve_script_sha256: ElementsHash32V2,
}

/// Ethereum-backed custody accounting. Native peg-ins and custody supply have
/// different asset identities; no Elements output is classified as a reserve.
/// This is not interchangeable with the legacy conversion classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsCustodyClassificationV3 {
    pub native_pegged_asset_id: ElementsHash32V2,
    pub custody_asset_id: ElementsHash32V2,
}

impl ElementsCustodyClassificationV3 {
    pub fn commitment(&self) -> Result<ElementsHash32V2, ElementsStateErrorV2> {
        if self.native_pegged_asset_id == [0; 32] || self.custody_asset_id == [0; 32]
            || self.native_pegged_asset_id == self.custody_asset_id {
            return Err(ElementsStateErrorV2::InvalidEconomicOpening);
        }
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.native_pegged_asset_id);
        bytes.extend_from_slice(&self.custody_asset_id);
        Ok(tagged_hash("ECX/elements-custody-classification/v3", &bytes))
    }
}

/// Separate type prevents passing custody totals as conversion reserves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseCustodyNodeV3 {
    pub hash: ElementsHash32V2,
    pub count: u128,
    pub custody_supply_atoms: u128,
}

/// Verify an opening using the same cryptographic checks as legacy economic
/// leaves, but commit a distinct accounting domain and frozen two-asset policy.
/// The input role is only a compatibility container: OutstandingBase means
/// custody supply here, and every other asset must be Irrelevant. No inventory
/// or local-reserve role is accepted. Not yet wired into a child executor.
pub fn verify_elements_custody_leaf_v3(
    leaf: &ElementsEconomicLeafV2,
    classification: ElementsCustodyClassificationV3,
) -> Result<ElementsSparseCustodyNodeV3, ElementsStateErrorV2> {
    let policy = classification.commitment()?;
    verify_elements_economic_opening_v2(leaf)?;
    let custody = leaf.asset_id == classification.custody_asset_id;
    let role = if custody { ElementsLiveEconomicRoleV2::OutstandingBase }
        else { ElementsLiveEconomicRoleV2::Irrelevant };
    let checked = economic_leaf_node_v2(leaf, role)?;
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&policy);
    bytes.extend_from_slice(&checked.hash);
    Ok(ElementsSparseCustodyNodeV3 {
        hash: tagged_hash("ECX/elements-custody-leaf/v3", &bytes),
        count: 1,
        custody_supply_atoms: if custody { u128::from(leaf.amount) } else { 0 },
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseCustodyMutationV3 {
    pub outpoint: OutPoint,
    pub old_leaf: Option<ElementsEconomicLeafV2>,
    pub new_leaf: Option<ElementsEconomicLeafV2>,
    /// Leaf-to-root siblings, exactly 256 entries.
    pub siblings: Vec<ElementsSparseCustodyNodeV3>,
}

pub fn empty_elements_custody_leaf_v3() -> ElementsSparseCustodyNodeV3 {
    ElementsSparseCustodyNodeV3 {
        hash: tagged_hash("ECX/elements-custody-empty/v3", &[]),
        count: 0, custody_supply_atoms: 0,
    }
}

pub fn elements_custody_parent_v3(
    left: ElementsSparseCustodyNodeV3, right: ElementsSparseCustodyNodeV3,
) -> Result<ElementsSparseCustodyNodeV3, ElementsStateErrorV2> {
    let count = left.count.checked_add(right.count)
        .ok_or(ElementsStateErrorV2::AggregateOverflow)?;
    let custody_supply_atoms = left.custody_supply_atoms.checked_add(right.custody_supply_atoms)
        .ok_or(ElementsStateErrorV2::AggregateOverflow)?;
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&left.hash); bytes.extend_from_slice(&right.hash);
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&custody_supply_atoms.to_be_bytes());
    Ok(ElementsSparseCustodyNodeV3 {
        hash: tagged_hash("ECX/elements-custody-node/v3", &bytes), count, custody_supply_atoms,
    })
}

pub fn elements_custody_root_from_path_v3(
    outpoint: OutPoint, leaf: ElementsSparseCustodyNodeV3,
    siblings: &[ElementsSparseCustodyNodeV3],
) -> Result<ElementsSparseCustodyNodeV3, ElementsStateErrorV2> {
    if siblings.len() != ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
        return Err(ElementsStateErrorV2::NonCanonicalPath);
    }
    let key = elements_sparse_utxo_key_v2(outpoint);
    siblings.iter().copied().enumerate().try_fold(leaf, |current, (level, sibling)| {
        if key_bit_from_leaf_level(key, level) { elements_custody_parent_v3(sibling, current) }
        else { elements_custody_parent_v3(current, sibling) }
    })
}

/// Authenticates both membership/nonmembership and totals against the supplied
/// frozen root. The enclosing executor must pair this with the same UTXO update
/// and authenticate issuance/burn authorization; this alone is not execution.
pub fn apply_elements_custody_mutation_v3(
    current: ElementsSparseCustodyNodeV3, mutation: &ElementsSparseCustodyMutationV3,
    policy: ElementsCustodyClassificationV3,
) -> Result<ElementsSparseCustodyNodeV3, ElementsStateErrorV2> {
    policy.commitment()?;
    let empty = empty_elements_custody_leaf_v3();
    let (old, new) = match (&mutation.old_leaf, &mutation.new_leaf) {
        (None, Some(leaf)) if leaf.utxo.outpoint == mutation.outpoint =>
            (empty, verify_elements_custody_leaf_v3(leaf, policy)?),
        (Some(leaf), None) if leaf.utxo.outpoint == mutation.outpoint =>
            (verify_elements_custody_leaf_v3(leaf, policy)?, empty),
        (None, Some(_)) | (Some(_), None) => return Err(ElementsStateErrorV2::OutpointMismatch),
        _ => return Err(ElementsStateErrorV2::InvalidMutation),
    };
    if elements_custody_root_from_path_v3(mutation.outpoint, old, &mutation.siblings)? != current {
        return Err(ElementsStateErrorV2::RootMismatch);
    }
    elements_custody_root_from_path_v3(mutation.outpoint, new, &mutation.siblings)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsEconomicLeafV2 {
    pub utxo: ElementsUtxoLeafV2,
    pub asset_id: ElementsHash32V2,
    pub amount: u64,
    pub asset_blinding_factor: ElementsHash32V2,
    pub value_blinding_factor: ElementsHash32V2,
    pub role: ElementsLiveEconomicRoleV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseEconomicPathV2 {
    pub siblings: Vec<ElementsSparseEconomicNodeV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSparseEconomicMutationV2 {
    pub outpoint: OutPoint,
    pub old_leaf: Option<ElementsEconomicLeafV2>,
    pub new_leaf: Option<ElementsEconomicLeafV2>,
    pub path: ElementsSparseEconomicPathV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsTransactionUtxoWitnessV2 {
    /// Exact non-peg-in input order. Peg-ins authenticate a mainchain outpoint
    /// and therefore do not delete an Elements UTXO.
    pub spends: Vec<ElementsSparseUtxoMutationV2>,
    /// Exact spendable-output order; fee and provably-unspendable outputs are
    /// deliberately absent from the UTXO set.
    pub creates: Vec<ElementsSparseUtxoMutationV2>,
}

/// One-to-one economic projection for every spend/delete and create/insert in
/// `ElementsTransactionUtxoWitnessV2`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsTransactionEconomicWitnessV2 {
    pub spends: Vec<ElementsSparseEconomicMutationV2>,
    pub creates: Vec<ElementsSparseEconomicMutationV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsTransactionStateRootsV2 {
    pub utxo_root: ElementsSparseUtxoNodeV2,
    pub economic_root: ElementsSparseEconomicNodeV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsTransactionSpendContextV2 {
    pub height: u32,
    pub parent_mtp: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ElementsTransactionKernelWitnessV2 {
    Coinbase,
    Ordinary,
    Issuance,
    DrivechainDeposit(Box<DrivechainDepositStatementV2>),
    NativeDrivechainDeposit,
}

/// Concrete native deposit relation must authenticate the deposit, exact
/// witness/recipient and amount proofs. The returned pseudo-prevout is only
/// for the single peg-in; ordinary sponsor prevouts cannot be substituted.
pub trait NativeDepositKernelVerifierV3 {
    fn verify_kernel(&self, transaction: &Transaction, sponsors: &[TxOut])
        -> Result<TxOut, ElementsStateErrorV2>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ElementsStateErrorV2 {
    #[error("Elements sparse path is not canonical")]
    NonCanonicalPath,
    #[error("Elements sparse mutation is not an insert or delete")]
    InvalidMutation,
    #[error("Elements sparse mutation outpoint differs from its leaf")]
    OutpointMismatch,
    #[error("Elements sparse prior root does not authenticate the leaf")]
    RootMismatch,
    #[error("Elements UTXO aggregate overflow")]
    AggregateOverflow,
    #[error("Elements economic opening or role classification is invalid")]
    InvalidEconomicOpening,
    #[error("ordinary Elements confidential kernel does not accept issuance or peg-ins")]
    UnsupportedValueSource,
    #[error("Elements fee output is not canonical")]
    NonCanonicalFeeOutput,
    #[error("Elements confidential proof or asset/value balance failed")]
    ConfidentialConsensus,
    #[error("Elements reissuance token authorization failed")]
    ReissuanceAuthorization,
    #[error("drivechain deposit statement or recursive receipt is invalid")]
    DrivechainDeposit,
    #[error("Elements transaction UTXO witness or kernel classification is invalid")]
    TransactionWitness,
    #[error("Elements transaction absolute lock time is not yet satisfied")]
    AbsoluteLockTime,
    #[error("Elements transaction relative sequence lock is not yet satisfied")]
    RelativeLockTime,
    #[error("Elements input authorization failed")]
    AuthorizationConsensus,
    #[error("Elements block structure or commitment failed")]
    BlockConsensus,
    #[error("Elements contextual header or block authorization failed")]
    HeaderConsensus,
}

/// Mandatory Elements authorization boundary. A production implementation
/// must execute the exact activated legacy/Simplicity program and environment;
/// there is intentionally no success-by-default implementation.
pub trait ElementsInputVerifierV2 {
    fn verify_input(
        &self,
        transaction: &Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
    ) -> Result<(), ElementsStateErrorV2>;
}

struct ElementsEcdsaCheckerV2<'a> {
    transaction: &'a Transaction,
    input_index: usize,
    spent_value: Option<Value>,
    /// Encoding policy is checked here, not by the generic script dispatcher.
    /// Native block verification does not select LOW_S.
    low_s: bool,
    strict_der: bool,
    strict_encoding: bool,
    rangeproof_active: bool,
}

impl ScriptSignatureCheckerV2 for ElementsEcdsaCheckerV2<'_> {
    fn check_ecdsa_signature(
        &self,
        signature_with_hash_type: &[u8],
        public_key: &[u8],
        script_code: &[u8],
        _code_separator_position: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        if signature_with_hash_type.is_empty() {
            return Ok(false);
        }
        let (&raw_hash_type, der) = signature_with_hash_type
            .split_last()
            .ok_or(ScriptPrimitiveErrorV2::Signature)?;
        if (self.strict_der || self.low_s || self.strict_encoding)
            && !valid_strict_der_signature_encoding_v2(signature_with_hash_type) {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let defined_type = if self.rangeproof_active { raw_hash_type & !0x40 } else { raw_hash_type };
        if self.strict_encoding && !valid_defined_sighash_type_v2(defined_type) {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        // Native CPubKey verification uses the historical lax parser even
        // after the script layer has checked strict DER encoding.
        let signature = match ecdsa::Signature::from_der_lax(der) {
            Ok(signature) => signature,
            Err(_) => return Ok(false),
        };
        let mut normalized = signature;
        normalized.normalize_s();
        if self.low_s && normalized != signature {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        if self.strict_encoding && !matches!(public_key, [0x02 | 0x03, ..] if public_key.len() == 33)
            && !matches!(public_key, [0x04, ..] if public_key.len() == 65)
        {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let public_key = match PublicKey::from_slice(public_key) {
            Ok(key) => key,
            Err(_) => return Ok(false),
        };
        let cleaned;
        let signing_script = if self.spent_value.is_some() {
            script_code
        } else {
            cleaned =
                remove_exact_signature_pushes_v2(script_code, signature_with_hash_type)?;
            &cleaned
        };
        let digest = crate::elements_sighash_v3::elements_ecdsa_sighash_v3(
            self.transaction, self.input_index, signing_script, self.spent_value,
            raw_hash_type, self.rangeproof_active,
        )?;
        let message = Message::from_digest(digest);
        Ok(Secp256k1::verification_only()
            .verify_ecdsa(&message, &normalized, &public_key)
            .is_ok())
    }
}

/// Concrete transaction authorization for legacy, P2SH, native witness-v0,
/// and P2SH-wrapped witness-v0 Elements inputs. Taproot/Simplicity remains
/// fail-closed until its Elements genesis-bound sighash and Simplicity machine
/// are wired into this verifier.
pub struct FullElementsInputVerifierV2 {
    pub genesis_hash: BlockHash,
    rules: ElementsInputRulesV3,
}

mod bound_input_verifier {
    pub trait Sealed {}
    impl Sealed for super::FullElementsInputVerifierV2 {}
    impl<S: super::ElementsSimplicityExecutorV2> Sealed
        for super::FullElementsInputVerifierWithSimplicityV2<'_, S> {}
}

/// Exposes the actual dispatcher's execution selections, not caller assertions.
/// This does not certify completeness of its script engines or annex support.
pub trait BoundElementsInputVerifierV3:
    ElementsInputVerifierV2 + bound_input_verifier::Sealed
{
    fn execution_binding(&self) -> (BlockHash, ElementsInputRulesV3);
}

impl BoundElementsInputVerifierV3 for FullElementsInputVerifierV2 {
    fn execution_binding(&self) -> (BlockHash, ElementsInputRulesV3) {
        (self.genesis_hash, self.rules)
    }
}

impl<S: ElementsSimplicityExecutorV2> BoundElementsInputVerifierV3
    for FullElementsInputVerifierWithSimplicityV2<'_, S>
{
    fn execution_binding(&self) -> (BlockHash, ElementsInputRulesV3) {
        self.base.execution_binding()
    }
}

/// Execution selections only, not evidence of activation. A proof entry point
/// must derive these from its authenticated configuration and chain history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElementsInputRulesV3 {
    pub script: LegacyScriptFlagsV2,
    pub cltv: bool,
    pub csv: bool,
    pub null_fail: bool,
    pub null_dummy: bool,
    pub discourage_upgradable_nops: bool,
    pub const_script_code: bool,
    pub rangeproof_active: bool,
    pub simplicity_active: bool,
    pub native_execution: bool,
}

/// Exact authenticated input passed to the native Simplicity evaluator. The
/// executor must deserialize `program`, require its CMR to equal
/// `committed_cmr`, consume the exact witness, enforce its resource budget and
/// evaluate against this transaction/genesis/block environment. Returning Ok
/// without those checks is consensus-invalid.
pub struct ElementsSimplicityExecutionV2<'a> {
    pub transaction: &'a Transaction,
    pub input_index: usize,
    pub previous_outputs: &'a [TxOut],
    pub genesis_hash: BlockHash,
    pub committed_cmr: ElementsHash32V2,
    pub program: &'a [u8],
    pub witness: &'a [u8],
    pub annex: Option<&'a [u8]>,
}

pub trait ElementsSimplicityExecutorV2 {
    fn execute(
        &self,
        input: &ElementsSimplicityExecutionV2<'_>,
    ) -> Result<(), ElementsStateErrorV2>;
}

pub const ELEMENTS_SIMPLICITY_EXECUTION_PUBLIC_VALUES_VERSION_V2: u8 = 1;
pub const ELEMENTS_SIMPLICITY_EXECUTION_PUBLIC_VALUES_BYTES_V2: usize = 33;
pub const MAX_ELEMENTS_SIMPLICITY_PROGRAM_BYTES_V2: usize = 16 * 1024 * 1024;
pub const MAX_ELEMENTS_SIMPLICITY_WITNESS_BYTES_V2: usize = 16 * 1024 * 1024;
pub const MAX_ELEMENTS_SIMPLICITY_ANNEX_BYTES_V2: usize = 16 * 1024 * 1024;
pub const MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2: usize = 65_536;
pub const MAX_ELEMENTS_SIMPLICITY_PROOF_MARKER_BYTES_V2: usize = 256;

/// Exact public statement emitted by a separately frozen native Simplicity
/// evaluator. The commitment binds the complete Elements execution
/// environment, not merely the program CMR or witness bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSimplicityExecutionPublicValuesV2 {
    pub version: u8,
    pub execution_commitment: ElementsHash32V2,
}

impl ElementsSimplicityExecutionPublicValuesV2 {
    pub fn canonical_bytes(self) -> [u8; ELEMENTS_SIMPLICITY_EXECUTION_PUBLIC_VALUES_BYTES_V2] {
        let mut bytes = [0_u8; ELEMENTS_SIMPLICITY_EXECUTION_PUBLIC_VALUES_BYTES_V2];
        bytes[0] = self.version;
        bytes[1..].copy_from_slice(&self.execution_commitment);
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsSimplicityReceiptBindingV2 {
    pub public_values: Vec<u8>,
    pub proof_marker: Vec<u8>,
}

pub trait ElementsSimplicityReceiptVerifierV2 {
    fn verify(
        &self,
        program_id: ElementsHash32V2,
        public_values: &[u8],
        proof_marker: &[u8],
    ) -> Result<(), ElementsStateErrorV2>;
}

/// Receipt-backed executor used by the recursive full-Elements relation. Each
/// script-path call consumes exactly one receipt in transaction/input order.
/// This keeps the outer relation stable while the separately identified
/// native evaluator and catalogue are frozen.
pub struct ProofCarryingElementsSimplicityExecutorV2<'a, V> {
    pub evaluator_program_id: ElementsHash32V2,
    pub receipts: &'a [ElementsSimplicityReceiptBindingV2],
    pub verifier: &'a V,
    next_receipt: Cell<usize>,
}

impl<'a, V> ProofCarryingElementsSimplicityExecutorV2<'a, V> {
    pub fn new(
        evaluator_program_id: ElementsHash32V2,
        receipts: &'a [ElementsSimplicityReceiptBindingV2],
        verifier: &'a V,
    ) -> Result<Self, ElementsStateErrorV2> {
        if evaluator_program_id == [0; 32]
            || receipts.len() > MAX_ELEMENTS_SIMPLICITY_RECEIPTS_V2
            || receipts.iter().any(|receipt| {
                receipt.public_values.len() != ELEMENTS_SIMPLICITY_EXECUTION_PUBLIC_VALUES_BYTES_V2
                    || receipt.proof_marker.is_empty()
                    || receipt.proof_marker.len() > MAX_ELEMENTS_SIMPLICITY_PROOF_MARKER_BYTES_V2
            })
        {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        Ok(Self {
            evaluator_program_id,
            receipts,
            verifier,
            next_receipt: Cell::new(0),
        })
    }

    pub fn require_all_receipts_consumed(&self) -> Result<(), ElementsStateErrorV2> {
        if self.next_receipt.get() != self.receipts.len() {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        Ok(())
    }
}

impl<V: ElementsSimplicityReceiptVerifierV2> ElementsSimplicityExecutorV2
    for ProofCarryingElementsSimplicityExecutorV2<'_, V>
{
    fn execute(
        &self,
        input: &ElementsSimplicityExecutionV2<'_>,
    ) -> Result<(), ElementsStateErrorV2> {
        let public_values = elements_simplicity_execution_public_values_v2(input)?;
        let receipt_index = self.next_receipt.get();
        let receipt = self
            .receipts
            .get(receipt_index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        if receipt.public_values != public_values.canonical_bytes() {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        self.verifier.verify(
            self.evaluator_program_id,
            &receipt.public_values,
            &receipt.proof_marker,
        )?;
        self.next_receipt.set(receipt_index + 1);
        Ok(())
    }
}

pub fn elements_simplicity_execution_public_values_v2(
    input: &ElementsSimplicityExecutionV2<'_>,
) -> Result<ElementsSimplicityExecutionPublicValuesV2, ElementsStateErrorV2> {
    if input.input_index >= input.transaction.input.len()
        || input.previous_outputs.len() != input.transaction.input.len()
        || input.committed_cmr == [0; 32]
        || input.program.is_empty()
        || input.program.len() > MAX_ELEMENTS_SIMPLICITY_PROGRAM_BYTES_V2
        || input.witness.len() > MAX_ELEMENTS_SIMPLICITY_WITNESS_BYTES_V2
        || input
            .annex
            .is_some_and(|annex| annex.len() > MAX_ELEMENTS_SIMPLICITY_ANNEX_BYTES_V2)
    {
        return Err(ElementsStateErrorV2::AuthorizationConsensus);
    }
    let transaction = elements::encode::serialize(input.transaction);
    let previous_outputs = elements::encode::serialize(&input.previous_outputs.to_vec());
    let mut preimage = Vec::with_capacity(
        128 + transaction.len()
            + previous_outputs.len()
            + input.program.len()
            + input.witness.len()
            + input.annex.map_or(0, <[u8]>::len),
    );
    preimage.extend_from_slice(b"ECX/elements-simplicity-execution/v2");
    preimage.extend_from_slice(input.genesis_hash.as_byte_array());
    preimage.extend_from_slice(&(input.input_index as u64).to_be_bytes());
    append_bounded_bytes_v2(&mut preimage, &transaction)?;
    append_bounded_bytes_v2(&mut preimage, &previous_outputs)?;
    preimage.extend_from_slice(&input.committed_cmr);
    append_bounded_bytes_v2(&mut preimage, input.program)?;
    append_bounded_bytes_v2(&mut preimage, input.witness)?;
    match input.annex {
        Some(annex) => {
            preimage.push(1);
            append_bounded_bytes_v2(&mut preimage, annex)?;
        }
        None => preimage.push(0),
    }
    Ok(ElementsSimplicityExecutionPublicValuesV2 {
        version: ELEMENTS_SIMPLICITY_EXECUTION_PUBLIC_VALUES_VERSION_V2,
        execution_commitment: crate::sha256_bytes(&preimage),
    })
}

fn append_bounded_bytes_v2(
    destination: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), ElementsStateErrorV2> {
    let length =
        u64::try_from(bytes.len()).map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(bytes);
    Ok(())
}

/// Concrete script dispatcher with an explicitly installed Simplicity
/// evaluator. `FullElementsInputVerifierV2` remains fail-closed for script
/// paths, so a caller cannot accidentally enable a digest-only substitute.
pub struct FullElementsInputVerifierWithSimplicityV2<'a, S> {
    pub base: FullElementsInputVerifierV2,
    pub simplicity: &'a S,
}

impl<S: ElementsSimplicityExecutorV2> FullElementsInputVerifierWithSimplicityV2<'_, S> {
    fn verify_tapsimplicity_path(
        &self,
        transaction: &Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
    ) -> Result<(), ElementsStateErrorV2> {
        let input = transaction
            .input
            .get(input_index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        let previous = previous_outputs
            .get(input_index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        if !input.script_sig.is_empty() {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        let output_script = previous.script_pubkey.as_bytes();
        if output_script.len() != 34 || output_script[0] != 0x51 || output_script[1] != 0x20 {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        let stack = &input.witness.script_witness;
        let annex = stack
            .last()
            .filter(|item| item.first() == Some(&0x50))
            .map(Vec::as_slice);
        let without_annex = if annex.is_some() {
            &stack[..stack.len() - 1]
        } else {
            stack.as_slice()
        };
        let [witness, program, cmr, control_bytes] = without_annex else {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        };
        if cmr.len() != 32 || program.is_empty() {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        let control = ElementsControlBlock::from_slice(control_bytes)
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?;
        if control.leaf_version.as_u8() != 0xbe {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        let output_key = XOnlyPublicKey::from_slice(&output_script[2..])
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?
            .dangerous_assume_tweaked();
        let cmr_script = elements::Script::from(cmr.clone());
        if !control.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            &output_key,
            &cmr_script,
        ) {
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        self.simplicity.execute(&ElementsSimplicityExecutionV2 {
            transaction,
            input_index,
            previous_outputs,
            genesis_hash: self.base.genesis_hash,
            committed_cmr: cmr
                .as_slice()
                .try_into()
                .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?,
            program,
            witness,
            annex,
        })
    }
}

impl<S: ElementsSimplicityExecutorV2> ElementsInputVerifierV2
    for FullElementsInputVerifierWithSimplicityV2<'_, S>
{
    fn verify_input(
        &self,
        transaction: &Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
    ) -> Result<(), ElementsStateErrorV2> {
        let previous = previous_outputs
            .get(input_index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        let script = previous.script_pubkey.as_bytes();
        let witness = transaction
            .input
            .get(input_index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?
            .witness
            .script_witness
            .as_slice();
        let without_annex = witness.len().saturating_sub(usize::from(
            witness.last().and_then(|item| item.first()) == Some(&0x50),
        ));
        if self.base.rules.simplicity_active && self.base.rules.script.verify_witness && self.base.rules.script.verify_taproot
            && script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 && without_annex >= 2 {
            self.verify_tapsimplicity_path(transaction, input_index, previous_outputs)
        } else {
            self.base
                .verify_input(transaction, input_index, previous_outputs)
        }
    }
}

impl FullElementsInputVerifierV2 {
    /// Script flags for native CElementsDrivechainParams/GetBlockScriptFlags.
    /// The caller must authenticate the Alpha identity and child height; this
    /// function does not infer a network from untrusted transaction bytes.
    /// Simplicity authorization still requires the receipt-aware verifier.
    pub fn native_alpha_rules(child_height: u32) -> ElementsInputRulesV3 {
        ElementsInputRulesV3 {
            script: LegacyScriptFlagsV2 {
                verify_p2sh: true, verify_witness: true, verify_taproot: true,
                strict_der: child_height >= 1, ..Default::default()
            },
            cltv: child_height >= 1, csv: child_height >= 1,
            null_dummy: true, null_fail: false,
            discourage_upgradable_nops: false, const_script_code: false,
            rangeproof_active: false, simplicity_active: true, native_execution: true,
        }
    }

    pub fn new(genesis_hash: BlockHash) -> Self {
        // Preserve historical callers until they explicitly supply chain rules.
        Self::with_rules(genesis_hash, ElementsInputRulesV3 {
            script: LegacyScriptFlagsV2 {
                require_minimal_push:true, require_minimal_if:true, verify_p2sh:true,
                clean_stack:true, verify_witness:true, verify_taproot:true,
                witness_pubkey_type:true, discourage_upgradable_witness_program:true,
                strict_der:true, strict_encoding:true, low_s:true,
            },
            cltv:true, csv:true, null_fail:true, null_dummy:true,
            discourage_upgradable_nops:true, const_script_code:true,
            rangeproof_active:false, simplicity_active:true, native_execution:false,
        })
    }

    pub fn with_rules(genesis_hash: BlockHash, rules: ElementsInputRulesV3) -> Self {
        Self { genesis_hash, rules }
    }

    fn verify_taproot_key_path(
        &self,
        transaction: &Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
        output_key: &[u8],
        witness: &[Vec<u8>],
    ) -> Result<(), ElementsStateErrorV2> {
        let (signature_bytes, annex) = match witness {
            [signature] => (signature.as_slice(), None),
            [signature, annex] if annex.first() == Some(&0x50) => {
                (signature.as_slice(), Some(annex.as_slice()))
            }
            _ => return Err(ElementsStateErrorV2::AuthorizationConsensus),
        };
        let (signature_bytes, hash_type) = match signature_bytes {
            bytes if bytes.len() == 64 => (bytes, elements::SchnorrSighashType::Default),
            bytes if bytes.len() == 65 => {
                let (&raw, signature) = bytes
                    .split_last()
                    .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
                let hash_type = elements::SchnorrSighashType::from_u8(raw)
                    .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
                if hash_type == elements::SchnorrSighashType::Default {
                    return Err(ElementsStateErrorV2::AuthorizationConsensus);
                }
                (signature, hash_type)
            }
            _ => return Err(ElementsStateErrorV2::AuthorizationConsensus),
        };
        let signature = schnorr::Signature::from_slice(signature_bytes)
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?;
        let output_key = XOnlyPublicKey::from_slice(output_key)
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?;
        let annex = annex
            .map(ElementsAnnex::new)
            .transpose()
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?;
        let digest = ElementsSighashCache::new(transaction)
            .taproot_sighash(
                input_index,
                &ElementsPrevouts::All(previous_outputs),
                annex,
                None,
                hash_type,
                self.genesis_hash,
            )
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?
            .to_byte_array();
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &Message::from_digest(digest), &output_key)
            .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)
    }
}

impl ElementsInputVerifierV2 for FullElementsInputVerifierV2 {
    fn verify_input(
        &self,
        transaction: &Transaction,
        input_index: usize,
        previous_outputs: &[TxOut],
    ) -> Result<(), ElementsStateErrorV2> {
        let input = transaction
            .input
            .get(input_index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        let previous = previous_outputs
            .get(input_index)
            .ok_or(ElementsStateErrorV2::AuthorizationConsensus)?;
        let witness: Vec<Vec<u8>> = input.witness.script_witness.clone();
        let script_pubkey = previous.script_pubkey.as_bytes();
        if self.rules.script.verify_witness && self.rules.script.verify_taproot
            && script_pubkey.len() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20 {
            if !input.script_sig.is_empty() {
                return Err(ElementsStateErrorV2::AuthorizationConsensus);
            }
            let without_annex = witness.len().saturating_sub(usize::from(
                witness.last().and_then(|item| item.first()) == Some(&0x50),
            ));
            if without_annex == 1 {
                return self.verify_taproot_key_path(
                    transaction,
                    input_index,
                    previous_outputs,
                    &script_pubkey[2..],
                    &witness,
                );
            }
            // Before Simplicity activation, 0xbe is an upgradeable leaf.
            // Native consensus still authenticates its script/control commitment
            // but does not evaluate the future language or impose its stack shape.
            if without_annex >= 2 && !self.rules.simplicity_active && self.rules.native_execution {
                let control = ElementsControlBlock::from_slice(&witness[without_annex - 1])
                    .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?;
                if control.leaf_version.as_u8() == 0xbe {
                    let key = XOnlyPublicKey::from_slice(&script_pubkey[2..])
                        .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?
                        .dangerous_assume_tweaked();
                    let script = elements::Script::from(witness[without_annex - 2].clone());
                    if control.verify_taproot_commitment(&Secp256k1::verification_only(),&key,&script) {
                        return Ok(());
                    }
                }
            }
            return Err(ElementsStateErrorV2::AuthorizationConsensus);
        }
        let legacy = ElementsEcdsaCheckerV2 {
            transaction,
            input_index,
            spent_value: None,
            low_s: self.rules.script.low_s,
            strict_der: self.rules.script.strict_der,
            strict_encoding: self.rules.script.strict_encoding,
            rangeproof_active: self.rules.rangeproof_active,
        };
        let witness_v0 = ElementsEcdsaCheckerV2 {
            transaction,
            input_index,
            spent_value: Some(previous.value),
            low_s: self.rules.script.low_s,
            strict_der: self.rules.script.strict_der,
            strict_encoding: self.rules.script.strict_encoding,
            rangeproof_active: self.rules.rangeproof_active,
        };
        let execute = if self.rules.native_execution {
            crate::script_v2::verify_native_script_components_v3
        } else { verify_script_components_with_checkers_v2 };
        execute(
            input.script_sig.as_bytes(),
            script_pubkey,
            &witness,
            ScriptLockContextV2 {
                alpha_drivechain: false,
                transaction_version: transaction.version,
                transaction_lock_time: transaction.lock_time.to_consensus_u32(),
                input_sequence: input.sequence.to_consensus_u32(),
                check_lock_time_verify: self.rules.cltv,
                check_sequence_verify: self.rules.csv,
                null_fail: self.rules.null_fail,
                null_dummy: self.rules.null_dummy,
                discourage_upgradable_nops: self.rules.discourage_upgradable_nops,
                const_script_code: self.rules.const_script_code,
                witness_v0: false,
            },
            &legacy,
            &witness_v0,
            self.rules.script,
        )
        .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)
    }
}

pub const ELEMENTS_MAX_BLOCK_WEIGHT_V2: usize = 4_000_000;
pub const ELEMENTS_MAX_FUTURE_BLOCK_SECONDS_V2: u64 = 2 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsHeaderConsensusContextV2 {
    pub previous_block_hash: BlockHash,
    pub next_height: u32,
    pub previous_11_times: Vec<u32>,
    pub authenticated_adjusted_time: u64,
    /// `Some` means DynaFed is active and this exact representation is the
    /// authenticated expected current entry for the next block. `None` means
    /// the legacy challenge remains active.
    pub expected_current_dynafed_params: Option<elements::dynafed::Params>,
    /// Authenticated full entry underlying `expected_current_dynafed_params`.
    /// Required in DynaFed mode even when the header uses compact encoding.
    pub expected_full_current_dynafed_params: Option<elements::dynafed::FullParams>,
    pub legacy_signblock_challenge: elements::Script,
    pub legacy_signblock_witness_limit: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsDynafedEpochHistoryV2 {
    pub epoch_length: u32,
    /// Consecutive authenticated headers beginning at the active epoch start.
    /// At a transition boundary this is the complete preceding epoch.
    pub headers: Vec<elements::BlockHeader>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsDerivedDynafedParametersV2 {
    pub expected_current: elements::dynafed::Params,
    pub expected_full_current: elements::dynafed::FullParams,
}

pub trait ElementsBlockAuthorizationVerifierV2 {
    fn verify_legacy_proof(
        &self,
        header: &elements::BlockHeader,
        challenge: &elements::Script,
        solution: &elements::Script,
    ) -> Result<(), ElementsStateErrorV2>;

    fn verify_dynafed_proof(
        &self,
        header: &elements::BlockHeader,
        challenge: &elements::Script,
        witness: &[Vec<u8>],
    ) -> Result<(), ElementsStateErrorV2>;
}

pub fn derive_expected_dynafed_parameters_v2(
    history: &ElementsDynafedEpochHistoryV2,
    next_height: u32,
) -> Result<ElementsDerivedDynafedParametersV2, ElementsStateErrorV2> {
    derive_expected_dynafed_parameters_with_hashes_v3(history,next_height,
        &history.headers.iter().map(|h| h.block_hash()).collect::<Vec<_>>())
}

/// Shared epoch parameter derivation for exact header representations. Hashes
/// MUST be derived from the retained native headers by the calling adapter;
/// this helper does not authenticate arbitrary caller-supplied hash values.
pub fn derive_expected_dynafed_parameters_with_hashes_v3(
    history: &ElementsDynafedEpochHistoryV2,
    next_height: u32,
    exact_header_hashes: &[BlockHash],
) -> Result<ElementsDerivedDynafedParametersV2, ElementsStateErrorV2> {
    if exact_header_hashes.len() != history.headers.len() {
        return Err(ElementsStateErrorV2::HeaderConsensus);
    }
    if history.epoch_length == 0 || history.headers.is_empty() {
        return Err(ElementsStateErrorV2::HeaderConsensus);
    }
    let epoch_age = next_height % history.epoch_length;
    let expected_length = if epoch_age == 0 {
        history.epoch_length
    } else {
        epoch_age
    };
    let expected_start = next_height
        .checked_sub(expected_length)
        .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
    if history.headers.len()
        != usize::try_from(expected_length).map_err(|_| ElementsStateErrorV2::HeaderConsensus)?
        || history.headers[0].height != expected_start
        || history.headers.last().map(|header| header.height) != next_height.checked_sub(1)
    {
        return Err(ElementsStateErrorV2::HeaderConsensus);
    }
    for (index,pair) in history.headers.windows(2).enumerate() {
        if pair[0].height.checked_add(1) != Some(pair[1].height) || pair[1].prev_blockhash != exact_header_hashes[index] {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
    }

    let first_current = match &history.headers[0].ext {
        elements::BlockExtData::Dynafed { current, .. } => current,
        _ => return Err(ElementsStateErrorV2::HeaderConsensus),
    };
    let full_current = first_current
        .full()
        .cloned()
        .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
    let full_params = elements::dynafed::Params::Full(full_current.clone());
    let compact_params = full_current.clone().into_compact();
    for (index, header) in history.headers.iter().enumerate() {
        let current = match &header.ext {
            elements::BlockExtData::Dynafed { current, .. } => current,
            _ => return Err(ElementsStateErrorV2::HeaderConsensus),
        };
        let expected = if index == 0 {
            &full_params
        } else {
            &compact_params
        };
        if current != expected || current.calculate_root() != full_params.calculate_root() {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
    }

    if epoch_age == 0 {
        // Native NextBlockIsParameterTransition: overflow-safe ceil(4*N/5).
        let threshold = history.epoch_length - history.epoch_length / 5;
        let mut tallies = std::collections::BTreeMap::<[u8; 32], (u32, usize)>::new();
        for (index, header) in history.headers.iter().enumerate().rev() {
            let proposal = match &header.ext {
                elements::BlockExtData::Dynafed { proposed, .. } => proposed,
                _ => return Err(ElementsStateErrorV2::HeaderConsensus),
            };
            if proposal.is_null() {
                continue;
            }
            let root = proposal.calculate_root().to_byte_array();
            let entry = tallies.entry(root).or_insert((0, index));
            entry.0 = entry
                .0
                .checked_add(1)
                .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
            if entry.0 >= threshold {
                let winning = match &history.headers[entry.1].ext {
                    elements::BlockExtData::Dynafed { proposed, .. } => proposed.clone(),
                    _ => return Err(ElementsStateErrorV2::HeaderConsensus),
                };
                let winning_full = history
                    .headers
                    .iter()
                    .filter_map(|candidate| match &candidate.ext {
                        elements::BlockExtData::Dynafed { proposed, .. }
                            if proposed.calculate_root() == winning.calculate_root() =>
                        {
                            proposed.full().cloned()
                        }
                        _ => None,
                    })
                    .next()
                    .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
                return Ok(ElementsDerivedDynafedParametersV2 {
                    expected_current: winning,
                    expected_full_current: winning_full,
                });
            }
        }
        Ok(ElementsDerivedDynafedParametersV2 {
            expected_current: full_params,
            expected_full_current: full_current,
        })
    } else {
        Ok(ElementsDerivedDynafedParametersV2 {
            expected_current: compact_params,
            expected_full_current: full_current,
        })
    }
}

pub fn verify_elements_contextual_dynafed_header_from_history_v2<
    V: ElementsBlockAuthorizationVerifierV2,
>(
    block: &Block,
    history: &ElementsDynafedEpochHistoryV2,
    previous_11_times: Vec<u32>,
    authenticated_adjusted_time: u64,
    authorization_verifier: &V,
) -> Result<(), ElementsStateErrorV2> {
    let previous = history
        .headers
        .last()
        .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
    let next_height = previous
        .height
        .checked_add(1)
        .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
    let derived = derive_expected_dynafed_parameters_v2(history, next_height)?;
    verify_elements_contextual_header_v2(
        block,
        &ElementsHeaderConsensusContextV2 {
            previous_block_hash: previous.block_hash(),
            next_height,
            previous_11_times,
            authenticated_adjusted_time,
            expected_current_dynafed_params: Some(derived.expected_current),
            expected_full_current_dynafed_params: Some(derived.expected_full_current),
            legacy_signblock_challenge: elements::Script::new(),
            legacy_signblock_witness_limit: 0,
        },
        authorization_verifier,
    )
}

pub fn elements_transaction_merkle_root_v2(
    transactions: &[Transaction],
) -> Result<TxMerkleNode, ElementsStateErrorV2> {
    if transactions.is_empty() {
        return Err(ElementsStateErrorV2::BlockConsensus);
    }
    let mut layer = transactions
        .iter()
        .map(|transaction| transaction.txid().to_byte_array())
        .collect::<Vec<_>>();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().ok_or(ElementsStateErrorV2::BlockConsensus)?);
        }
        layer = layer
            .chunks_exact(2)
            .map(|pair| {
                let mut payload = [0u8; 64];
                payload[..32].copy_from_slice(&pair[0]);
                payload[32..].copy_from_slice(&pair[1]);
                elements::hashes::sha256d::Hash::hash(&payload).to_byte_array()
            })
            .collect();
    }
    Ok(TxMerkleNode::from_byte_array(layer[0]))
}

/// Context-independent Elements block foundation. Header authorization,
/// DynaFed transitions and the BMM parent edge are contextual relations layered
/// above this exact decoding/commitment boundary.
pub fn verify_elements_block_foundation_v2(
    raw_block: &[u8],
    expected_previous_block: BlockHash,
    expected_height: u32,
    maximum_weight: usize,
) -> Result<Block, ElementsStateErrorV2> {
    if raw_block.is_empty() || maximum_weight == 0 || maximum_weight > ELEMENTS_MAX_BLOCK_WEIGHT_V2
    {
        return Err(ElementsStateErrorV2::BlockConsensus);
    }
    let block: Block = elements::encode::deserialize(raw_block)
        .map_err(|_| ElementsStateErrorV2::BlockConsensus)?;
    if block.header.prev_blockhash != expected_previous_block
        || block.header.height != expected_height
        || block.txdata.is_empty()
        || block.weight() > maximum_weight
        || !block.txdata[0].is_coinbase()
        || block.txdata.iter().skip(1).any(Transaction::is_coinbase)
        || elements_transaction_merkle_root_v2(&block.txdata)? != block.header.merkle_root
    {
        return Err(ElementsStateErrorV2::BlockConsensus);
    }
    let mut transaction_ids = std::collections::HashSet::with_capacity(block.txdata.len());
    if block
        .txdata
        .iter()
        .any(|transaction| !transaction_ids.insert(transaction.txid()))
    {
        return Err(ElementsStateErrorV2::BlockConsensus);
    }
    Ok(block)
}

pub fn verify_elements_contextual_header_v2<V: ElementsBlockAuthorizationVerifierV2>(
    block: &Block,
    context: &ElementsHeaderConsensusContextV2,
    authorization_verifier: &V,
) -> Result<(), ElementsStateErrorV2> {
    verify_elements_contextual_header_with_history(block, context, authorization_verifier, 11)
}

/// Native early-chain counterpart. The timestamps, deployment parameters and
/// signer challenge must still come from authenticated predecessor state.
/// Genesis is intentionally handled by a separate frozen genesis relation.
pub fn verify_elements_contextual_header_native_v3<V: ElementsBlockAuthorizationVerifierV2>(
    block: &Block,
    context: &ElementsHeaderConsensusContextV2,
    authorization_verifier: &V,
) -> Result<(), ElementsStateErrorV2> {
    verify_elements_contextual_header_with_history(block, context, authorization_verifier,
        context.next_height.min(11) as usize)
}

fn verify_elements_contextual_header_with_history<V: ElementsBlockAuthorizationVerifierV2>(
    block: &Block,
    context: &ElementsHeaderConsensusContextV2,
    authorization_verifier: &V,
    history_count: usize,
) -> Result<(), ElementsStateErrorV2> {
    if history_count == 0 || context.previous_11_times.len() != history_count
        || block.header.prev_blockhash != context.previous_block_hash
        || block.header.height != context.next_height
    {
        return Err(ElementsStateErrorV2::HeaderConsensus);
    }
    let mut times = context.previous_11_times.clone();
    times.sort_unstable();
    let median = times[history_count / 2];
    let future_limit = context
        .authenticated_adjusted_time
        .checked_add(ELEMENTS_MAX_FUTURE_BLOCK_SECONDS_V2)
        .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
    if block.header.time <= median || u64::from(block.header.time) > future_limit {
        return Err(ElementsStateErrorV2::HeaderConsensus);
    }

    match (&context.expected_current_dynafed_params, &block.header.ext) {
        (
            Some(expected_current),
            elements::BlockExtData::Dynafed {
                current,
                proposed,
                signblock_witness,
            },
        ) => {
            const RESERVED_DYNAFED_VERSION_MASK: u32 =
                (1 << 23) | (1 << 24) | (1 << 25) | (1 << 26);
            let expected_full = context
                .expected_full_current_dynafed_params
                .as_ref()
                .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
            let expected_full_params = elements::dynafed::Params::Full(expected_full.clone());
            if expected_current.is_null()
                || current != expected_current
                || current.calculate_root() != expected_full_params.calculate_root()
                || block.header.version & RESERVED_DYNAFED_VERSION_MASK != 0
                || serialize(signblock_witness).len()
                    > usize::try_from(
                        current
                            .signblock_witness_limit()
                            .ok_or(ElementsStateErrorV2::HeaderConsensus)?,
                    )
                    .map_err(|_| ElementsStateErrorV2::HeaderConsensus)?
            {
                return Err(ElementsStateErrorV2::HeaderConsensus);
            }
            if !proposed.is_null() {
                if proposed.signblockscript() != current.signblockscript()
                    && !proposed
                        .signblockscript()
                        .is_some_and(elements::Script::is_witness_program)
                {
                    return Err(ElementsStateErrorV2::HeaderConsensus);
                }
                let proposed_full = proposed
                    .full()
                    .ok_or(ElementsStateErrorV2::HeaderConsensus)?;
                let proposed_full_params = elements::dynafed::Params::Full(proposed_full.clone());
                // Fedpeg and extension-space proposal changes require their
                // complete PAK/witness-program relation. Until that relation
                // is composed, reject rather than authenticate only the
                // signblock subset.
                if proposed_full_params.fedpeg_program() != expected_full_params.fedpeg_program()
                    || proposed_full_params.fedpegscript() != expected_full_params.fedpegscript()
                    || proposed_full_params.extension_space()
                        != expected_full_params.extension_space()
                {
                    return Err(ElementsStateErrorV2::HeaderConsensus);
                }
            }
            authorization_verifier
                .verify_dynafed_proof(
                    &block.header,
                    current
                        .signblockscript()
                        .ok_or(ElementsStateErrorV2::HeaderConsensus)?,
                    signblock_witness,
                )
                .map_err(|_| ElementsStateErrorV2::HeaderConsensus)?;
        }
        (
            None,
            elements::BlockExtData::Proof {
                challenge,
                solution,
            },
        ) => {
            if context.expected_full_current_dynafed_params.is_some()
                || challenge != &context.legacy_signblock_challenge
                || solution.len()
                    > usize::try_from(context.legacy_signblock_witness_limit)
                        .map_err(|_| ElementsStateErrorV2::HeaderConsensus)?
            {
                return Err(ElementsStateErrorV2::HeaderConsensus);
            }
            authorization_verifier
                .verify_legacy_proof(&block.header, challenge, solution)
                .map_err(|_| ElementsStateErrorV2::HeaderConsensus)?;
        }
        _ => return Err(ElementsStateErrorV2::HeaderConsensus),
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrivechainDepositStatementV2 {
    pub version: u8,
    pub mainchain_genesis: [u8; 32],
    pub sidechain_genesis: [u8; 32],
    pub sidechain_slot: u8,
    /// 1=Elements regtest, 2=Liquid, 3=Liquid testnet.
    pub sidechain_address_profile: u8,
    pub pegged_asset: [u8; 32],
    pub mainchain_txid: [u8; 32],
    pub mainchain_vout: u32,
    pub value_atoms: u64,
    pub destination_script: Vec<u8>,
    pub prior_ctip_txid: [u8; 32],
    pub prior_ctip_vout: u32,
    pub prior_ctip_value_atoms: u64,
    pub prior_sequence: u64,
    pub next_ctip_value_atoms: u64,
    pub next_sequence: u64,
    pub authenticated_parent_anchor: [u8; 32],
    pub prior_bip300_state_commitment: [u8; 32],
    /// State immediately after the block containing the deposit.
    pub deposit_block_bip300_state_commitment: [u8; 32],
    /// State at `authenticated_parent_anchor`, after every confirmation block.
    pub next_bip300_state_commitment: [u8; 32],
    pub bitcoin_consensus_parameters_commitment: [u8; 32],
    pub prior_bitcoin_utxo_root: SparseUtxoNodeV2,
    pub next_bitcoin_utxo_root: SparseUtxoNodeV2,
    pub pegin_witness_sha256: [u8; 32],
}

impl DrivechainDepositStatementV2 {
    pub fn validate(&self) -> Result<(), ElementsStateErrorV2> {
        if self.version != 1
            || self.mainchain_genesis == [0; 32]
            || self.sidechain_genesis == [0; 32]
            || self.pegged_asset == [0; 32]
            || !(1..=3).contains(&self.sidechain_address_profile)
            || self.mainchain_txid == [0; 32]
            || self.value_atoms == 0
            || self.destination_script.is_empty()
            || self.destination_script.len() > 10_000
            || self.authenticated_parent_anchor == [0; 32]
            || self.prior_bip300_state_commitment == [0; 32]
            || self.deposit_block_bip300_state_commitment == [0; 32]
            || self.next_bip300_state_commitment == [0; 32]
            || self.bitcoin_consensus_parameters_commitment == [0; 32]
            || self.prior_bitcoin_utxo_root.hash == [0; 32]
            || self.next_bitcoin_utxo_root.hash == [0; 32]
            || self.prior_bip300_state_commitment == self.next_bip300_state_commitment
            || self.pegin_witness_sha256 == [0; 32]
            || self.next_sequence
                != self
                    .prior_sequence
                    .checked_add(1)
                    .ok_or(ElementsStateErrorV2::DrivechainDeposit)?
            || self.next_ctip_value_atoms
                != self
                    .prior_ctip_value_atoms
                    .checked_add(self.value_atoms)
                    .ok_or(ElementsStateErrorV2::DrivechainDeposit)?
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        Ok(())
    }
}

/// Explicit execution profile committed by the recursive receipt. The program
/// is network agnostic; a receipt is specific to the frozen profile selected
/// by its deployment/checkpoint identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinConsensusExecutionParametersV2 {
    pub version: u8,
    pub bip34_active: bool,
    pub bip68_active: bool,
    pub active_script_flags: u32,
}

impl BitcoinConsensusExecutionParametersV2 {
    pub fn commitment(self) -> Result<[u8; 32], ElementsStateErrorV2> {
        if self.version != 1 || self.active_script_flags == 0 {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let mut preimage = b"ECX/bitcoin-consensus-execution-parameters/v1".to_vec();
        preimage.push(self.version);
        preimage.push(u8::from(self.bip34_active));
        preimage.push(u8::from(self.bip68_active));
        preimage.extend_from_slice(&self.active_script_flags.to_be_bytes());
        Ok(crate::sha256_bytes(&preimage))
    }
}

/// Mandatory recursive boundary. Implementations must verify the full Bitcoin
/// block/merkle/CTIP/BIP300 relation represented by the exact statement.
pub trait DrivechainDepositReceiptVerifierV2 {
    fn verify_deposit_statement(
        &self,
        statement: &DrivechainDepositStatementV2,
    ) -> Result<(), ElementsStateErrorV2>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullBitcoinDrivechainDepositEvidenceV2 {
    pub raw_deposit_block: Vec<u8>,
    pub pow_context: BitcoinPowContextV2,
    pub authenticated_adjusted_time: u64,
    pub prior_bip300_state: Bip300AllSlotStateV2,
    pub consensus_parameters: BitcoinConsensusExecutionParametersV2,
    pub prior_bitcoin_utxo_root: SparseUtxoNodeV2,
    pub deposit_utxo_witness: BitcoinBlockUtxoWitnessV2,
    /// Complete consecutive blocks after the deposit block through the anchor.
    pub confirmation_blocks: Vec<FullBitcoinBlockEvidenceStepV2>,
}

pub const MAX_DRIVECHAIN_CONFIRMATION_BLOCKS_V2: usize = 2_016;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullBitcoinBlockEvidenceStepV2 {
    pub raw_block: Vec<u8>,
    pub pow_context: BitcoinPowContextV2,
    pub authenticated_adjusted_time: u64,
    pub utxo_witness: BitcoinBlockUtxoWitnessV2,
}

#[derive(Clone, Debug)]
pub struct FullBitcoinDrivechainDepositVerifierV2 {
    pub evidence: FullBitcoinDrivechainDepositEvidenceV2,
    pub sidechain_genesis: [u8; 32],
    pub pegged_asset: [u8; 32],
    pub sidechain_address_profile: u8,
}

impl DrivechainDepositReceiptVerifierV2 for FullBitcoinDrivechainDepositVerifierV2 {
    fn verify_deposit_statement(
        &self,
        statement: &DrivechainDepositStatementV2,
    ) -> Result<(), ElementsStateErrorV2> {
        statement.validate()?;
        if statement.sidechain_genesis != self.sidechain_genesis
            || statement.pegged_asset != self.pegged_asset
            || statement.sidechain_address_profile != self.sidechain_address_profile
            || statement.mainchain_genesis
                != self
                    .evidence
                    .prior_bip300_state
                    .network_genesis
                    .to_byte_array()
            || statement.bitcoin_consensus_parameters_commitment
                != self.evidence.consensus_parameters.commitment()?
            || statement.prior_bitcoin_utxo_root != self.evidence.prior_bitcoin_utxo_root
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        if self.evidence.confirmation_blocks.len() > MAX_DRIVECHAIN_CONFIRMATION_BLOCKS_V2 {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let deposit_step = FullBitcoinBlockEvidenceStepV2 {
            raw_block: self.evidence.raw_deposit_block.clone(),
            pow_context: self.evidence.pow_context.clone(),
            authenticated_adjusted_time: self.evidence.authenticated_adjusted_time,
            utxo_witness: self.evidence.deposit_utxo_witness.clone(),
        };
        let (block, mut bitcoin_utxo_root) = verify_full_bitcoin_block_step_v2(
            &deposit_step,
            self.evidence.prior_bip300_state.network_genesis,
            self.evidence.prior_bip300_state.next_height,
            self.evidence.prior_bitcoin_utxo_root,
            self.evidence.consensus_parameters,
        )?;
        let prior_commitment = self
            .evidence
            .prior_bip300_state
            .commitment()
            .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
        let (mut next_state, effects) =
            apply_bip300_block_v2(&self.evidence.prior_bip300_state, &block)
                .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
        let deposit_commitment = next_state
            .commitment()
            .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
        if prior_commitment != statement.prior_bip300_state_commitment
            || deposit_commitment != statement.deposit_block_bip300_state_commitment
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let prior_slot = self
            .evidence
            .prior_bip300_state
            .active_slots
            .get(&statement.sidechain_slot)
            .ok_or(ElementsStateErrorV2::DrivechainDeposit)?;
        let prior_ctip = prior_slot
            .ctip
            .ok_or(ElementsStateErrorV2::DrivechainDeposit)?;
        if prior_ctip.outpoint.txid.to_byte_array() != statement.prior_ctip_txid
            || prior_ctip.outpoint.vout != statement.prior_ctip_vout
            || prior_ctip.value_sat != statement.prior_ctip_value_atoms
            || prior_ctip.sequence != statement.prior_sequence
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let matching = effects
            .deposits
            .iter()
            .filter(|deposit| {
                deposit.slot == statement.sidechain_slot
                    && deposit.outpoint.outpoint.txid.to_byte_array() == statement.mainchain_txid
                    && deposit.outpoint.outpoint.vout == statement.mainchain_vout
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let deposit = matching[0];
        if deposit.value_sat != statement.value_atoms
            || deposit.outpoint.value_sat != statement.next_ctip_value_atoms
            || deposit.outpoint.sequence != statement.next_sequence
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let address_text = std::str::from_utf8(&deposit.address)
            .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
        let address = elements::Address::from_str(address_text)
            .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
        let expected_params = match statement.sidechain_address_profile {
            1 => &elements::AddressParams::ELEMENTS,
            2 => &elements::AddressParams::LIQUID,
            3 => &elements::AddressParams::LIQUID_TESTNET,
            _ => return Err(ElementsStateErrorV2::DrivechainDeposit),
        };
        if address.params != expected_params
            || address.script_pubkey().as_bytes() != statement.destination_script.as_slice()
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let mut anchor = block.block_hash();
        for step in &self.evidence.confirmation_blocks {
            let (successor, successor_utxo_root) = verify_full_bitcoin_block_step_v2(
                step,
                self.evidence.prior_bip300_state.network_genesis,
                next_state.next_height,
                bitcoin_utxo_root,
                self.evidence.consensus_parameters,
            )?;
            (next_state, _) = apply_bip300_block_v2(&next_state, &successor)
                .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
            anchor = successor.block_hash();
            bitcoin_utxo_root = successor_utxo_root;
        }
        if next_state
            .commitment()
            .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?
            != statement.next_bip300_state_commitment
            || anchor.to_byte_array() != statement.authenticated_parent_anchor
            || bitcoin_utxo_root != statement.next_bitcoin_utxo_root
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        Ok(())
    }
}

/// Execute one complete, consecutive Bitcoin block step against an
/// authenticated contextual checkpoint and sparse UTXO root.
///
/// This is the shared consensus boundary for both the concrete drivechain
/// deposit verifier and the recursive full-Bitcoin guest.  It deliberately
/// returns the decoded block so the caller must replay BIP300/all-slot state
/// from the same bytes; a caller-provided block hash or state summary is not a
/// substitute for execution.
pub fn verify_full_bitcoin_block_step_v2(
    step: &FullBitcoinBlockEvidenceStepV2,
    genesis: bitcoin::BlockHash,
    expected_height: u32,
    prior_utxo_root: SparseUtxoNodeV2,
    consensus_parameters: BitcoinConsensusExecutionParametersV2,
) -> Result<(BitcoinBlock, SparseUtxoNodeV2), ElementsStateErrorV2> {
    let block: BitcoinBlock = bitcoin_deserialize(&step.raw_block)
        .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
    if step.pow_context.previous_height.checked_add(1) != Some(expected_height)
        || step.pow_context.previous_header.block_hash() != block.header.prev_blockhash
    {
        return Err(ElementsStateErrorV2::DrivechainDeposit);
    }
    // Alpha is the only parent chain. There is no network branch and no
    // challenge solution to supply.
    let _ = genesis;
    let target = verify_next_header_context_v2(
        &step.pow_context,
        block.header,
        step.authenticated_adjusted_time,
    )
    .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
    verify_bitcoin_block_foundation_v2(
        &step.raw_block,
        block.header.prev_blockhash,
        bitcoin::pow::Target::from_compact(target),
        BITCOIN_MAX_BLOCK_WEIGHT_V2,
    )
    .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
    let previous_block_mtp = median_time_past_v2(&step.pow_context.previous_11_times)
        .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
    let result = apply_bitcoin_block_utxos_v2(
        &block,
        BitcoinBlockSpendContextV2 {
            height: expected_height,
            previous_block_mtp,
            bip34_active: consensus_parameters.bip34_active,
            bip68_active: consensus_parameters.bip68_active,
        },
        prior_utxo_root,
        &step.utxo_witness,
        consensus_parameters.active_script_flags,
        &FullBitcoinScriptVerifierV2,
    )
    .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
    Ok((block, result.next_root))
}

pub fn verify_drivechain_deposit_elements_transaction_v2<V>(
    transaction: &Transaction,
    statement: &DrivechainDepositStatementV2,
    receipt_verifier: &V,
) -> Result<(), ElementsStateErrorV2>
where
    V: DrivechainDepositReceiptVerifierV2 + ?Sized,
{
    statement.validate()?;
    receipt_verifier.verify_deposit_statement(statement)?;
    if transaction.input.len() != 1 || transaction.output.is_empty() || transaction.output.len() > 2
    {
        return Err(ElementsStateErrorV2::DrivechainDeposit);
    }
    let input = &transaction.input[0];
    if !input.is_pegin()
        || input.has_issuance()
        || !input.script_sig.is_empty()
        || input.previous_output.txid.to_byte_array() != statement.mainchain_txid
        || input.previous_output.vout != statement.mainchain_vout
    {
        return Err(ElementsStateErrorV2::DrivechainDeposit);
    }
    let witness_hash = crate::sha256_bytes(&serialize(&input.witness.pegin_witness));
    if witness_hash != statement.pegin_witness_sha256 {
        return Err(ElementsStateErrorV2::DrivechainDeposit);
    }
    let expected_asset = elements::AssetId::from_slice(&statement.pegged_asset)
        .map_err(|_| ElementsStateErrorV2::DrivechainDeposit)?;
    let mut credit = None;
    let mut fee = 0u64;
    for output in &transaction.output {
        if output.asset != Asset::Explicit(expected_asset)
            || output.nonce != Nonce::Null
            || !output.witness.is_empty()
        {
            return Err(ElementsStateErrorV2::DrivechainDeposit);
        }
        let amount = match output.value {
            Value::Explicit(amount) => amount,
            _ => return Err(ElementsStateErrorV2::DrivechainDeposit),
        };
        if output.script_pubkey.is_empty() {
            fee = fee
                .checked_add(amount)
                .ok_or(ElementsStateErrorV2::DrivechainDeposit)?;
        } else {
            if credit.is_some()
                || output.script_pubkey.as_bytes() != statement.destination_script.as_slice()
            {
                return Err(ElementsStateErrorV2::DrivechainDeposit);
            }
            credit = Some(amount);
        }
    }
    let credited = credit.ok_or(ElementsStateErrorV2::DrivechainDeposit)?;
    if credited == 0
        || credited
            .checked_add(fee)
            .ok_or(ElementsStateErrorV2::DrivechainDeposit)?
            != statement.value_atoms
    {
        return Err(ElementsStateErrorV2::DrivechainDeposit);
    }
    Ok(())
}

/// Verify the complete confidential-transaction kernel for an ordinary
/// Elements transaction. Issuance and peg-in value sources are rejected until
/// their independent authorization relations are supplied; accepting them as
/// ordinary previous outputs would make balance verification unsound.
pub fn verify_ordinary_elements_confidential_transaction_v2(
    transaction: &Transaction,
    authenticated_previous_outputs: &[TxOut],
) -> Result<(), ElementsStateErrorV2> {
    if transaction
        .input
        .iter()
        .any(|input| input.has_issuance() || input.is_pegin())
    {
        return Err(ElementsStateErrorV2::UnsupportedValueSource);
    }
    for output in &transaction.output {
        if output.script_pubkey.is_empty()
            && (!matches!(output.asset, Asset::Explicit(_))
                || !matches!(output.value, Value::Explicit(_))
                || output.nonce != Nonce::Null
                || !output.witness.is_empty())
        {
            return Err(ElementsStateErrorV2::NonCanonicalFeeOutput);
        }
    }
    transaction
        .verify_tx_amt_proofs(&Secp256k1::new(), authenticated_previous_outputs)
        .map_err(|_| ElementsStateErrorV2::ConfidentialConsensus)
}

/// Verify confidential balance and proof rules for fresh asset issuances.
/// Reissuance and peg-in authorization are separate consensus relations and
/// remain rejected here. The issuance pseudo-input generators are derived from
/// the transaction itself exactly as Elements does.
pub fn verify_elements_transaction_with_initial_issuance_v2(
    transaction: &Transaction,
    authenticated_previous_outputs: &[TxOut],
) -> Result<(), ElementsStateErrorV2> {
    let secp = Secp256k1::new();
    let mut saw_issuance = false;
    for input in &transaction.input {
        if input.is_pegin()
            || (input.has_issuance()
                && input.asset_issuance.asset_blinding_nonce != elements::secp256k1_zkp::ZERO_TWEAK)
        {
            return Err(ElementsStateErrorV2::UnsupportedValueSource);
        }
        if !input.has_issuance() {
            continue;
        }
        saw_issuance = true;
        let (asset_id, token_id) = input.issuance_ids();
        for (value, proof, asset_id) in [
            (
                input.asset_issuance.amount,
                input.witness.amount_rangeproof.as_deref(),
                asset_id,
            ),
            (
                input.asset_issuance.inflation_keys,
                input.witness.inflation_keys_rangeproof.as_deref(),
                token_id,
            ),
        ] {
            match (value, proof) {
                (Value::Null, None) | (Value::Explicit(_), None) => {}
                (Value::Confidential(commitment), Some(rangeproof)) => {
                    let generator = elements::secp256k1_zkp::Generator::new_unblinded(
                        &secp,
                        asset_id.into_tag(),
                    );
                    rangeproof
                        .verify(&secp, commitment, &[], generator)
                        .map_err(|_| ElementsStateErrorV2::ConfidentialConsensus)?;
                }
                _ => return Err(ElementsStateErrorV2::ConfidentialConsensus),
            }
        }
    }
    if !saw_issuance {
        return Err(ElementsStateErrorV2::UnsupportedValueSource);
    }
    for output in &transaction.output {
        if output.script_pubkey.is_empty()
            && (!matches!(output.asset, Asset::Explicit(_))
                || !matches!(output.value, Value::Explicit(_))
                || output.nonce != Nonce::Null
                || !output.witness.is_empty())
        {
            return Err(ElementsStateErrorV2::NonCanonicalFeeOutput);
        }
    }
    transaction
        .verify_tx_amt_proofs(&secp, authenticated_previous_outputs)
        .map_err(|_| ElementsStateErrorV2::ConfidentialConsensus)
}

/// Verify initial issuances and token-authorized reissuances using the exact
/// authenticated previous output at each input. A reissuance discloses the
/// token asset blinder; the resulting generator must equal the spent prevout's
/// confidential asset commitment, and it may not mint inflation keys.
pub fn verify_elements_transaction_with_issuance_v2(
    transaction: &Transaction,
    authenticated_previous_outputs: &[TxOut],
) -> Result<(), ElementsStateErrorV2> {
    verify_elements_transaction_with_issuance_rules_v3(
        transaction, authenticated_previous_outputs, ElementsReissuanceRulesV3::Legacy,
    )
}

/// Amount-rule selection, not evidence of activation or script authorization.
/// Production callers must derive this from authenticated execution policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElementsReissuanceRulesV3 {
    Legacy,
    ExplicitV1,
}

pub fn verify_elements_transaction_with_issuance_rules_v3(
    transaction: &Transaction,
    authenticated_previous_outputs: &[TxOut],
    rules: ElementsReissuanceRulesV3,
) -> Result<(), ElementsStateErrorV2> {
    if authenticated_previous_outputs.len() != transaction.input.len() {
        return Err(ElementsStateErrorV2::ConfidentialConsensus);
    }
    let secp = Secp256k1::new();
    let mut saw_issuance = false;
    for (input_index, input) in transaction.input.iter().enumerate() {
        if input.is_pegin() {
            return Err(ElementsStateErrorV2::UnsupportedValueSource);
        }
        if !input.has_issuance() {
            continue;
        }
        saw_issuance = true;
        let reissuance =
            input.asset_issuance.asset_blinding_nonce != elements::secp256k1_zkp::ZERO_TWEAK;
        let (asset_id, token_id) = input.issuance_ids();
        if reissuance {
            if input.asset_issuance.inflation_keys != Value::Null
                || input.witness.inflation_keys_rangeproof.is_some()
            {
                return Err(ElementsStateErrorV2::ReissuanceAuthorization);
            }
            let previous = &authenticated_previous_outputs[input_index];
            if let Asset::Explicit(authority) = previous.asset {
                let mut marker = [0u8; 32];
                marker[0] = 1;
                if rules != ElementsReissuanceRulesV3::ExplicitV1
                    || transaction.version != 3
                    || input.asset_issuance.asset_blinding_nonce.as_ref() != &marker
                    || previous.value.explicit().is_none()
                    || input.asset_issuance.amount.explicit().is_none()
                    || authority != token_id
                {
                    return Err(ElementsStateErrorV2::ReissuanceAuthorization);
                }
            } else {
            let token_blinder = elements::confidential::AssetBlindingFactor::from_slice(
                input.asset_issuance.asset_blinding_nonce.as_ref(),
            )
            .map_err(|_| ElementsStateErrorV2::ReissuanceAuthorization)?;
            let expected = Asset::new_confidential(&secp, token_id, token_blinder);
            if authenticated_previous_outputs[input_index].asset != expected {
                return Err(ElementsStateErrorV2::ReissuanceAuthorization);
            }
            }
        }
        for (value, proof, proof_asset) in [
            (
                input.asset_issuance.amount,
                input.witness.amount_rangeproof.as_deref(),
                asset_id,
            ),
            (
                input.asset_issuance.inflation_keys,
                input.witness.inflation_keys_rangeproof.as_deref(),
                token_id,
            ),
        ] {
            match (value, proof) {
                (Value::Null, None) | (Value::Explicit(_), None) => {}
                (Value::Confidential(commitment), Some(rangeproof)) => {
                    let generator = elements::secp256k1_zkp::Generator::new_unblinded(
                        &secp,
                        proof_asset.into_tag(),
                    );
                    rangeproof
                        .verify(&secp, commitment, &[], generator)
                        .map_err(|_| ElementsStateErrorV2::ConfidentialConsensus)?;
                }
                _ => return Err(ElementsStateErrorV2::ConfidentialConsensus),
            }
        }
    }
    if !saw_issuance {
        return Err(ElementsStateErrorV2::UnsupportedValueSource);
    }
    for output in &transaction.output {
        if output.script_pubkey.is_empty()
            && (!matches!(output.asset, Asset::Explicit(_))
                || !matches!(output.value, Value::Explicit(_))
                || output.nonce != Nonce::Null
                || !output.witness.is_empty())
        {
            return Err(ElementsStateErrorV2::NonCanonicalFeeOutput);
        }
    }
    transaction
        .verify_tx_amt_proofs(&secp, authenticated_previous_outputs)
        .map_err(|_| ElementsStateErrorV2::ConfidentialConsensus)
}

/// Executes one complete Elements transaction against the authenticated UTXO
/// root. Authorization and value-source classification happen before any
/// mutation; accepted inputs and outputs then advance exact intermediate roots
/// in consensus order.
pub fn apply_elements_transaction_utxos_v2<V: ElementsInputVerifierV2>(
    transaction: &Transaction,
    context: ElementsTransactionSpendContextV2,
    initial_root: ElementsSparseUtxoNodeV2,
    witness: &ElementsTransactionUtxoWitnessV2,
    kernel: &ElementsTransactionKernelWitnessV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    apply_elements_transaction_utxos_with_lock_policy(
        transaction, context, initial_root, witness, kernel, input_verifier,
        deposit_verifier, None, None,
    )
}

/// Native Elements lock policy. Deployment state and cutoff must be derived
/// from authenticated child history, never chosen by the transaction witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeElementsLockPolicyV3 {
    pub csv_active: bool,
    pub absolute_time_cutoff: u32,
}

/// Reuses the exact UTXO/kernel/script relation with native sequence semantics.
/// This is not by itself complete block or native peg-in validation.
pub fn apply_elements_transaction_utxos_native_v3<V: ElementsInputVerifierV2>(
    transaction: &Transaction,
    context: ElementsTransactionSpendContextV2,
    initial_root: ElementsSparseUtxoNodeV2,
    witness: &ElementsTransactionUtxoWitnessV2,
    kernel: &ElementsTransactionKernelWitnessV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    policy: NativeElementsLockPolicyV3,
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    apply_elements_transaction_utxos_with_lock_policy(
        transaction, context, initial_root, witness, kernel, input_verifier,
        deposit_verifier, Some(policy), None,
    )
}

fn apply_elements_transaction_utxos_with_lock_policy<V: ElementsInputVerifierV2>(
    transaction: &Transaction,
    context: ElementsTransactionSpendContextV2,
    initial_root: ElementsSparseUtxoNodeV2,
    witness: &ElementsTransactionUtxoWitnessV2,
    kernel: &ElementsTransactionKernelWitnessV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    policy: Option<NativeElementsLockPolicyV3>,
    native_deposit: Option<&dyn NativeDepositKernelVerifierV3>,
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    apply_elements_transaction_utxos_with_rules(transaction, context, initial_root,
        witness, kernel, input_verifier, deposit_verifier, policy, native_deposit,
        ElementsReissuanceRulesV3::Legacy)
}

#[allow(clippy::too_many_arguments)]
fn apply_elements_transaction_utxos_with_rules<V: ElementsInputVerifierV2>(
    transaction: &Transaction,
    context: ElementsTransactionSpendContextV2,
    initial_root: ElementsSparseUtxoNodeV2,
    witness: &ElementsTransactionUtxoWitnessV2,
    kernel: &ElementsTransactionKernelWitnessV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    policy: Option<NativeElementsLockPolicyV3>,
    native_deposit: Option<&dyn NativeDepositKernelVerifierV3>,
    reissuance: ElementsReissuanceRulesV3,
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    let coinbase = transaction.is_coinbase();
    if coinbase {
        if !matches!(kernel, ElementsTransactionKernelWitnessV2::Coinbase)
            || !witness.spends.is_empty()
        {
            return Err(ElementsStateErrorV2::TransactionWitness);
        }
    } else if transaction.input.is_empty()
        || witness.spends.len()
            != transaction
                .input
                .iter()
                .filter(|input| !input.is_pegin())
                .count()
    {
        return Err(ElementsStateErrorV2::TransactionWitness);
    }

    let mut previous_outputs = Vec::with_capacity(witness.spends.len());
    if !coinbase {
        let mut spends = witness.spends.iter();
        for input in &transaction.input {
            if input.is_pegin() {
                continue;
            }
            let mutation = spends
                .next()
                .ok_or(ElementsStateErrorV2::TransactionWitness)?;
            let old_leaf = mutation
                .old_leaf
                .as_ref()
                .ok_or(ElementsStateErrorV2::TransactionWitness)?;
            if mutation.new_leaf.is_some()
                || mutation.outpoint != input.previous_output
                || old_leaf.outpoint != input.previous_output
            {
                return Err(ElementsStateErrorV2::TransactionWitness);
            }
            previous_outputs.push(old_leaf.output.clone());
            if policy.is_some() {
                verify_native_coinbase_maturity(old_leaf, context.height)?;
            }
        }
        if spends.next().is_some() {
            return Err(ElementsStateErrorV2::TransactionWitness);
        }
        verify_elements_transaction_locks_with_policy(transaction, &witness.spends, context, policy)?;
    }

    match kernel {
        ElementsTransactionKernelWitnessV2::Coinbase => {
            if !coinbase
                || transaction
                    .input
                    .iter()
                    .any(|input| input.is_pegin() || input.has_issuance())
            {
                return Err(ElementsStateErrorV2::TransactionWitness);
            }
        }
        ElementsTransactionKernelWitnessV2::Ordinary => {
            if coinbase {
                return Err(ElementsStateErrorV2::TransactionWitness);
            }
            verify_ordinary_elements_confidential_transaction_v2(transaction, &previous_outputs)?;
        }
        ElementsTransactionKernelWitnessV2::Issuance => {
            if coinbase || !transaction.input.iter().any(elements::TxIn::has_issuance) {
                return Err(ElementsStateErrorV2::TransactionWitness);
            }
            verify_elements_transaction_with_issuance_rules_v3(transaction, &previous_outputs, reissuance)?;
        }
        ElementsTransactionKernelWitnessV2::DrivechainDeposit(statement) => {
            if coinbase {
                return Err(ElementsStateErrorV2::TransactionWitness);
            }
            let verifier = deposit_verifier.ok_or(ElementsStateErrorV2::DrivechainDeposit)?;
            verify_drivechain_deposit_elements_transaction_v2(transaction, statement, verifier)?;
        }
        ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit => {
            if coinbase || policy.is_none()
                || transaction.input.iter().filter(|input|input.is_pegin()).count()!=1
                || transaction.input.iter().any(|input|input.has_issuance()) {
                return Err(ElementsStateErrorV2::DrivechainDeposit);
            }
            let pseudo = native_deposit.ok_or(ElementsStateErrorV2::DrivechainDeposit)?
                .verify_kernel(transaction,&previous_outputs)?;
            let mut sponsors=previous_outputs.into_iter();
            previous_outputs=transaction.input.iter().map(|input| {
                if input.is_pegin() { Ok(pseudo.clone()) }
                else { sponsors.next().ok_or(ElementsStateErrorV2::TransactionWitness) }
            }).collect::<Result<Vec<_>,_>>()?;
        }
    }

    if !coinbase {
        for input_index in 0..transaction.input.len() {
            if !transaction.input[input_index].is_pegin() {
                input_verifier
                    .verify_input(transaction, input_index, &previous_outputs)
                    .map_err(|_| ElementsStateErrorV2::AuthorizationConsensus)?;
            }
        }
    }

    let mut root = initial_root;
    for mutation in &witness.spends {
        root = apply_elements_sparse_utxo_mutation_v2(root, mutation)?;
    }

    let created_by_issuance = transaction.input.iter().any(elements::TxIn::has_issuance);
    let created_by_pegin = transaction.input.iter().any(elements::TxIn::is_pegin);
    let transaction_id = transaction.txid();
    let mut create_index = 0usize;
    for (output_index, output) in transaction.output.iter().enumerate() {
        if output.is_fee() || output.script_pubkey.is_provably_unspendable() {
            continue;
        }
        let mutation = witness
            .creates
            .get(create_index)
            .ok_or(ElementsStateErrorV2::TransactionWitness)?;
        create_index = create_index
            .checked_add(1)
            .ok_or(ElementsStateErrorV2::AggregateOverflow)?;
        let outpoint = OutPoint {
            txid: transaction_id,
            vout: u32::try_from(output_index)
                .map_err(|_| ElementsStateErrorV2::TransactionWitness)?,
        };
        let leaf = mutation
            .new_leaf
            .as_ref()
            .ok_or(ElementsStateErrorV2::TransactionWitness)?;
        if mutation.old_leaf.is_some()
            || mutation.outpoint != outpoint
            || leaf.outpoint != outpoint
            || leaf.output != *output
            || leaf.creation_height != context.height
            || leaf.creation_parent_mtp != context.parent_mtp
            || leaf.coinbase != coinbase
            || leaf.created_by_issuance != created_by_issuance
            || leaf.created_by_pegin != created_by_pegin
        {
            return Err(ElementsStateErrorV2::TransactionWitness);
        }
        root = apply_elements_sparse_utxo_mutation_v2(root, mutation)?;
    }
    if create_index != witness.creates.len() {
        return Err(ElementsStateErrorV2::TransactionWitness);
    }
    Ok(root)
}

/// Elements block-acceptance lock rules over authenticated creation height and
/// parent MTP. Relative locks are active for version >=2 transactions; peg-in
/// inputs have no child UTXO creation context and therefore must disable BIP68.
pub fn verify_elements_transaction_locks_v2(
    transaction: &Transaction,
    spends: &[ElementsSparseUtxoMutationV2],
    context: ElementsTransactionSpendContextV2,
) -> Result<(), ElementsStateErrorV2> {
    verify_elements_transaction_locks_with_policy(transaction, spends, context, None)
}

pub fn verify_elements_transaction_locks_native_v3(
    transaction: &Transaction,
    spends: &[ElementsSparseUtxoMutationV2],
    context: ElementsTransactionSpendContextV2,
    policy: NativeElementsLockPolicyV3,
) -> Result<(), ElementsStateErrorV2> {
    verify_elements_transaction_locks_with_policy(transaction, spends, context, Some(policy))
}

fn verify_elements_transaction_locks_with_policy(
    transaction: &Transaction,
    spends: &[ElementsSparseUtxoMutationV2],
    context: ElementsTransactionSpendContextV2,
    policy: Option<NativeElementsLockPolicyV3>,
) -> Result<(), ElementsStateErrorV2> {
    let lock_time = transaction.lock_time.to_consensus_u32();
    if lock_time != 0
        && transaction
            .input
            .iter()
            .any(|input| !input.sequence.is_final())
    {
        const LOCKTIME_THRESHOLD: u32 = 500_000_000;
        let comparison = if lock_time < LOCKTIME_THRESHOLD {
            context.height
        } else {
            policy.map_or(context.parent_mtp, |p| p.absolute_time_cutoff)
        };
        if lock_time >= comparison {
            return Err(ElementsStateErrorV2::AbsoluteLockTime);
        }
    }

    if transaction.version < 2 || policy.is_some_and(|p| !p.csv_active) {
        return Ok(());
    }
    let mut spends = spends.iter();
    for input in &transaction.input {
        let sequence = input.sequence.to_consensus_u32();
        const DISABLE_FLAG: u32 = 1 << 31;
        const TYPE_FLAG: u32 = 1 << 22;
        const VALUE_MASK: u32 = 0x0000_ffff;
        if input.is_pegin() {
            if policy.is_none() && sequence & DISABLE_FLAG == 0 {
                return Err(ElementsStateErrorV2::RelativeLockTime);
            }
            continue;
        }
        let mutation = spends
            .next()
            .ok_or(ElementsStateErrorV2::TransactionWitness)?;
        if sequence & DISABLE_FLAG != 0 {
            continue;
        }
        let old_leaf = mutation
            .old_leaf
            .as_ref()
            .ok_or(ElementsStateErrorV2::TransactionWitness)?;
        let relative = sequence & VALUE_MASK;
        if sequence & TYPE_FLAG == 0 {
            let required_height = old_leaf
                .creation_height
                .checked_add(relative)
                .ok_or(ElementsStateErrorV2::RelativeLockTime)?;
            if context.height < required_height {
                return Err(ElementsStateErrorV2::RelativeLockTime);
            }
        } else {
            let relative_seconds = relative
                .checked_shl(9)
                .ok_or(ElementsStateErrorV2::RelativeLockTime)?;
            let required_mtp = old_leaf
                .creation_parent_mtp
                .checked_add(relative_seconds)
                .ok_or(ElementsStateErrorV2::RelativeLockTime)?;
            if context.parent_mtp < required_mtp {
                return Err(ElementsStateErrorV2::RelativeLockTime);
            }
        }
    }
    if spends.next().is_some() {
        return Err(ElementsStateErrorV2::TransactionWitness);
    }
    Ok(())
}

/// Atomically advances the exact UTXO root and its exhaustive economic
/// projection. Every live UTXO mutation must have one matching economic
/// mutation, preventing an omitted confidential output from disappearing from
/// the derived supply or reserve totals.
#[allow(clippy::too_many_arguments)]
pub fn apply_elements_transaction_state_v2<V: ElementsInputVerifierV2>(
    transaction: &Transaction,
    context: ElementsTransactionSpendContextV2,
    initial_utxo_root: ElementsSparseUtxoNodeV2,
    initial_economic_root: ElementsSparseEconomicNodeV2,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    economic_witness: &ElementsTransactionEconomicWitnessV2,
    classification: ElementsEconomicClassificationV2,
    kernel: &ElementsTransactionKernelWitnessV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
) -> Result<ElementsTransactionStateRootsV2, ElementsStateErrorV2> {
    let utxo_root = apply_elements_transaction_utxos_v2(
        transaction,
        context,
        initial_utxo_root,
        utxo_witness,
        kernel,
        input_verifier,
        deposit_verifier,
    )?;
    let economic_root = apply_elements_transaction_economic_projection_v2(
        utxo_root,
        initial_economic_root,
        utxo_witness,
        economic_witness,
        classification,
    )?;
    Ok(ElementsTransactionStateRootsV2 {
        utxo_root,
        economic_root,
    })
}

fn verify_native_coinbase_maturity(leaf: &ElementsUtxoLeafV2, height: u32) -> Result<(), ElementsStateErrorV2> {
    // Native consensus/consensus.h: COINBASE_MATURITY = 100. This is not
    // the independently configured parent-chain peg-in confirmation rule.
    let depth = height.checked_sub(leaf.creation_height).ok_or(ElementsStateErrorV2::TransactionWitness)?;
    if leaf.coinbase && depth < 100 { return Err(ElementsStateErrorV2::TransactionWitness); }
    Ok(())
}

#[cfg(test)]
mod native_maturity_tests {
    use super::*;
    #[test]
    fn exact_maturity_and_future_provenance() {
        let mut leaf = ElementsUtxoLeafV2 {outpoint:OutPoint::null(),output:TxOut::default(),
            creation_height:50,creation_parent_mtp:0,coinbase:true,
            created_by_issuance:false,created_by_pegin:false};
        assert!(verify_native_coinbase_maturity(&leaf,149).is_err());
        assert_eq!(verify_native_coinbase_maturity(&leaf,150),Ok(()));
        assert!(verify_native_coinbase_maturity(&leaf,49).is_err());
        leaf.coinbase=false;
        assert_eq!(verify_native_coinbase_maturity(&leaf,50),Ok(()));
    }
}

/// Execute the native deposit kernel with full input-order signature prevouts,
/// ordinary-input UTXO deletions and atomic economic projection. Confirmation
/// and spent-claim state must be bound by the enclosing authenticated executor.
pub fn apply_native_deposit_state_v3<V: ElementsInputVerifierV2>(
    transaction: &Transaction,
    context: ElementsTransactionSpendContextV2,
    initial: ElementsTransactionStateRootsV2,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    economic_witness: &ElementsTransactionEconomicWitnessV2,
    classification: ElementsEconomicClassificationV2,
    input_verifier: &V,
    deposit_verifier: &dyn NativeDepositKernelVerifierV3,
    policy: NativeElementsLockPolicyV3,
) -> Result<ElementsTransactionStateRootsV2, ElementsStateErrorV2> {
    let utxo_root=apply_elements_transaction_utxos_with_lock_policy(transaction,context,
        initial.utxo_root,utxo_witness,&ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit,
        input_verifier,None,Some(policy),Some(deposit_verifier))?;
    let economic_root=apply_elements_transaction_economic_projection_v2(utxo_root,
        initial.economic_root,utxo_witness,economic_witness,classification)?;
    Ok(ElementsTransactionStateRootsV2 {utxo_root,economic_root})
}

/// Native deposit counterpart for separately accounted custody supply.
/// The enclosing authenticated deposit kernel must be bound to the policy's
/// native pegged asset; it must never substitute the custody token for ECX.
#[allow(clippy::too_many_arguments)]
pub fn apply_native_deposit_custody_state_v3<V: ElementsInputVerifierV2>(
    transaction: &Transaction, context: ElementsTransactionSpendContextV2,
    initial: ElementsTransactionCustodyRootsV3,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    custody_witness: &ElementsTransactionCustodyWitnessV3,
    classification: ElementsCustodyClassificationV3, input_verifier: &V,
    deposit_verifier: &dyn NativeDepositKernelVerifierV3,
    policy: NativeElementsLockPolicyV3,
) -> Result<ElementsTransactionCustodyRootsV3, ElementsStateErrorV2> {
    let utxo_root = apply_elements_transaction_utxos_with_lock_policy(transaction, context,
        initial.utxo_root, utxo_witness, &ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit,
        input_verifier, None, Some(policy), Some(deposit_verifier))?;
    let custody_root = apply_elements_transaction_custody_projection_v3(utxo_root,
        initial.custody_root, utxo_witness, custody_witness, classification)?;
    Ok(ElementsTransactionCustodyRootsV3 { utxo_root, custody_root })
}

/// Native-policy counterpart of the atomic UTXO/economic projection update.
/// The deposit and script verifier obligations are unchanged.
pub fn apply_elements_transaction_state_native_v3<V: ElementsInputVerifierV2>(
    transaction: &Transaction,
    context: ElementsTransactionSpendContextV2,
    initial_utxo_root: ElementsSparseUtxoNodeV2,
    initial_economic_root: ElementsSparseEconomicNodeV2,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    economic_witness: &ElementsTransactionEconomicWitnessV2,
    classification: ElementsEconomicClassificationV2,
    kernel: &ElementsTransactionKernelWitnessV2,
    input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    policy: NativeElementsLockPolicyV3,
) -> Result<ElementsTransactionStateRootsV2, ElementsStateErrorV2> {
    let utxo_root = apply_elements_transaction_utxos_native_v3(transaction,context,
        initial_utxo_root,utxo_witness,kernel,input_verifier,deposit_verifier,policy)?;
    let economic_root = apply_elements_transaction_economic_projection_v2(utxo_root,
        initial_economic_root,utxo_witness,economic_witness,classification)?;
    Ok(ElementsTransactionStateRootsV2 {utxo_root,economic_root})
}

/// Advance only the economic projection after the exact transaction/UTXO
/// relation has produced `next_utxo_root`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsTransactionCustodyWitnessV3 {
    pub spends: Vec<ElementsSparseCustodyMutationV3>,
    pub creates: Vec<ElementsSparseCustodyMutationV3>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsTransactionCustodyRootsV3 {
    pub utxo_root: ElementsSparseUtxoNodeV2,
    pub custody_root: ElementsSparseCustodyNodeV3,
}

/// Supply projection is atomic with the native transaction verifier. Frozen
/// deposit configuration and issuance authority remain enclosing obligations.
#[allow(clippy::too_many_arguments)]
pub fn apply_elements_transaction_custody_native_v3<V: ElementsInputVerifierV2>(
    transaction: &Transaction, context: ElementsTransactionSpendContextV2,
    initial: ElementsTransactionCustodyRootsV3,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    custody_witness: &ElementsTransactionCustodyWitnessV3,
    classification: ElementsCustodyClassificationV3,
    kernel: &ElementsTransactionKernelWitnessV2, input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    policy: NativeElementsLockPolicyV3,
) -> Result<ElementsTransactionCustodyRootsV3, ElementsStateErrorV2> {
    apply_elements_transaction_custody_native_v4(transaction, context, initial,
        utxo_witness, custody_witness, classification, kernel, input_verifier,
        deposit_verifier, policy, ElementsReissuanceRulesV3::Legacy)
}

/// The caller must derive `reissuance` from its frozen policy and authenticated
/// height. It is not part of the transaction or its untrusted kernel witness.
#[allow(clippy::too_many_arguments)]
pub fn apply_elements_transaction_custody_native_v4<V: ElementsInputVerifierV2>(
    transaction: &Transaction, context: ElementsTransactionSpendContextV2,
    initial: ElementsTransactionCustodyRootsV3,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    custody_witness: &ElementsTransactionCustodyWitnessV3,
    classification: ElementsCustodyClassificationV3,
    kernel: &ElementsTransactionKernelWitnessV2, input_verifier: &V,
    deposit_verifier: Option<&dyn DrivechainDepositReceiptVerifierV2>,
    policy: NativeElementsLockPolicyV3,
    reissuance: ElementsReissuanceRulesV3,
) -> Result<ElementsTransactionCustodyRootsV3, ElementsStateErrorV2> {
    let utxo_root = apply_elements_transaction_utxos_with_rules(transaction, context,
        initial.utxo_root, utxo_witness, kernel, input_verifier, deposit_verifier,
        Some(policy), None, reissuance)?;
    let custody_root = apply_elements_transaction_custody_projection_v3(utxo_root,
        initial.custody_root, utxo_witness, custody_witness, classification)?;
    Ok(ElementsTransactionCustodyRootsV3 { utxo_root, custody_root })
}

/// Requires an already verified UTXO transition. Every old/new output and its
/// provenance must match byte-for-byte, in execution order, including assets
/// unrelated to custody. This function alone is not a transaction verifier.
pub fn apply_elements_transaction_custody_projection_v3(
    next_utxo_root: ElementsSparseUtxoNodeV2,
    initial: ElementsSparseCustodyNodeV3,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    custody_witness: &ElementsTransactionCustodyWitnessV3,
    policy: ElementsCustodyClassificationV3,
) -> Result<ElementsSparseCustodyNodeV3, ElementsStateErrorV2> {
    policy.commitment()?;
    if utxo_witness.spends.len() != custody_witness.spends.len()
        || utxo_witness.creates.len() != custody_witness.creates.len() {
        return Err(ElementsStateErrorV2::TransactionWitness);
    }
    for (utxo, custody) in utxo_witness.spends.iter().zip(&custody_witness.spends)
        .chain(utxo_witness.creates.iter().zip(&custody_witness.creates)) {
        if utxo.outpoint != custody.outpoint
            || utxo.old_leaf.as_ref() != custody.old_leaf.as_ref().map(|leaf| &leaf.utxo)
            || utxo.new_leaf.as_ref() != custody.new_leaf.as_ref().map(|leaf| &leaf.utxo) {
            return Err(ElementsStateErrorV2::TransactionWitness);
        }
    }
    let mut root = initial;
    for mutation in custody_witness.spends.iter().chain(&custody_witness.creates) {
        root = apply_elements_custody_mutation_v3(root, mutation, policy)?;
    }
    if root.count != next_utxo_root.aggregate.count {
        return Err(ElementsStateErrorV2::TransactionWitness);
    }
    Ok(root)
}

/// Advance the legacy economic projection after verified UTXO execution.
pub fn apply_elements_transaction_economic_projection_v2(
    next_utxo_root: ElementsSparseUtxoNodeV2,
    initial_economic_root: ElementsSparseEconomicNodeV2,
    utxo_witness: &ElementsTransactionUtxoWitnessV2,
    economic_witness: &ElementsTransactionEconomicWitnessV2,
    classification: ElementsEconomicClassificationV2,
) -> Result<ElementsSparseEconomicNodeV2, ElementsStateErrorV2> {
    if utxo_witness.spends.len() != economic_witness.spends.len()
        || utxo_witness.creates.len() != economic_witness.creates.len()
    {
        return Err(ElementsStateErrorV2::TransactionWitness);
    }
    for (utxo, economic) in utxo_witness
        .spends
        .iter()
        .zip(&economic_witness.spends)
        .chain(utxo_witness.creates.iter().zip(&economic_witness.creates))
    {
        if utxo.outpoint != economic.outpoint
            || utxo.old_leaf.as_ref() != economic.old_leaf.as_ref().map(|leaf| &leaf.utxo)
            || utxo.new_leaf.as_ref() != economic.new_leaf.as_ref().map(|leaf| &leaf.utxo)
        {
            return Err(ElementsStateErrorV2::TransactionWitness);
        }
    }

    let mut economic_root = initial_economic_root;
    for mutation in economic_witness
        .spends
        .iter()
        .chain(&economic_witness.creates)
    {
        economic_root =
            apply_elements_sparse_economic_mutation_v2(economic_root, mutation, classification)?;
    }
    if economic_root.aggregate.count != next_utxo_root.aggregate.count {
        return Err(ElementsStateErrorV2::TransactionWitness);
    }
    Ok(economic_root)
}

fn tagged_hash(tag: &str, payload: &[u8]) -> ElementsHash32V2 {
    let tag_hash = crate::sha256_bytes(tag.as_bytes());
    let mut preimage = Vec::with_capacity(64 + payload.len());
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(payload);
    crate::sha256_bytes(&preimage)
}

pub fn elements_sparse_utxo_key_v2(outpoint: OutPoint) -> ElementsHash32V2 {
    tagged_hash("ECX/full-elements-utxo-key/v2", &serialize(&outpoint))
}

pub fn canonical_empty_elements_utxo_leaf_v2() -> ElementsSparseUtxoNodeV2 {
    ElementsSparseUtxoNodeV2 {
        hash: tagged_hash("ECX/full-elements-utxo-empty-leaf/v2", &[]),
        aggregate: ElementsUtxoAggregateV2::default(),
    }
}

pub fn canonical_empty_elements_utxo_root_v2(
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    let mut root = canonical_empty_elements_utxo_leaf_v2();
    for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
        root = elements_sparse_utxo_parent_v2(root, root)?;
    }
    Ok(root)
}

pub fn elements_utxo_leaf_node_v2(leaf: &ElementsUtxoLeafV2) -> ElementsSparseUtxoNodeV2 {
    let mut payload = serialize(&leaf.outpoint);
    payload.extend_from_slice(&serialize(&leaf.output));
    payload.extend_from_slice(&leaf.creation_height.to_be_bytes());
    payload.extend_from_slice(&leaf.creation_parent_mtp.to_be_bytes());
    payload.push(u8::from(leaf.coinbase));
    payload.push(u8::from(leaf.created_by_issuance));
    payload.push(u8::from(leaf.created_by_pegin));
    ElementsSparseUtxoNodeV2 {
        hash: tagged_hash("ECX/full-elements-utxo-leaf/v2", &payload),
        aggregate: ElementsUtxoAggregateV2 { count: 1 },
    }
}

pub fn canonical_empty_elements_economic_leaf_v2() -> ElementsSparseEconomicNodeV2 {
    ElementsSparseEconomicNodeV2 {
        hash: tagged_hash("ECX/full-elements-economic-empty-leaf/v2", &[]),
        aggregate: ElementsEconomicAggregateV2::default(),
    }
}

pub fn canonical_empty_elements_economic_root_v2(
) -> Result<ElementsSparseEconomicNodeV2, ElementsStateErrorV2> {
    let mut root = canonical_empty_elements_economic_leaf_v2();
    for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
        root = elements_sparse_economic_parent_v2(root, root)?;
    }
    Ok(root)
}

/// Verify the exact explicit value or confidential commitment/range proof and
/// derive its sole canonical live-state role from frozen asset and covenant
/// identities. Explicit outputs have the unique all-zero opening.
pub fn verify_elements_economic_leaf_v2(
    leaf: &ElementsEconomicLeafV2,
    classification: ElementsEconomicClassificationV2,
) -> Result<ElementsSparseEconomicNodeV2, ElementsStateErrorV2> {
    if classification.base_asset_id == [0; 32]
        || classification.policy_asset_id == [0; 32]
        || classification.base_asset_id == classification.policy_asset_id
        || classification.redemption_inventory_script_sha256 == [0; 32]
        || classification.reserve_script_sha256 == [0; 32]
        || classification.redemption_inventory_script_sha256 == classification.reserve_script_sha256
        || leaf.amount == 0
    {
        return Err(ElementsStateErrorV2::InvalidEconomicOpening);
    }
    verify_elements_economic_opening_v2(leaf)?;
    let script_sha256 = crate::sha256_bytes(leaf.utxo.output.script_pubkey.as_bytes());
    let derived_role = if leaf.asset_id == classification.base_asset_id {
        if script_sha256 == classification.redemption_inventory_script_sha256 {
            ElementsLiveEconomicRoleV2::RedemptionInventory
        } else {
            ElementsLiveEconomicRoleV2::OutstandingBase
        }
    } else if leaf.asset_id == classification.policy_asset_id
        && script_sha256 == classification.reserve_script_sha256
    {
        ElementsLiveEconomicRoleV2::RedeemableReserve
    } else {
        ElementsLiveEconomicRoleV2::Irrelevant
    };
    economic_leaf_node_v2(leaf, derived_role)
}

/// Shared cryptographic opening check; it does not select an accounting asset.
fn verify_elements_economic_opening_v2(
    leaf: &ElementsEconomicLeafV2,
) -> Result<(), ElementsStateErrorV2> {
    if leaf.amount == 0 { return Err(ElementsStateErrorV2::InvalidEconomicOpening); }
    let asset_id = elements::AssetId::from_byte_array(leaf.asset_id);
    match (leaf.utxo.output.asset, leaf.utxo.output.value) {
        (Asset::Explicit(output_asset), Value::Explicit(output_amount)) => {
            if output_asset != asset_id
                || output_amount != leaf.amount
                || leaf.utxo.output.nonce != Nonce::Null
                || leaf.asset_blinding_factor != [0; 32]
                || leaf.value_blinding_factor != [0; 32]
                || !leaf.utxo.output.witness.is_empty()
            {
                return Err(ElementsStateErrorV2::InvalidEconomicOpening);
            }
        }
        (Asset::Confidential(_), Value::Confidential(_)) => {
            if leaf.asset_blinding_factor == [0; 32]
                || leaf.value_blinding_factor == [0; 32]
                || leaf.asset_blinding_factor == leaf.value_blinding_factor
            {
                return Err(ElementsStateErrorV2::InvalidEconomicOpening);
            }
            let secp = Secp256k1::new();
            let asset_blinding_factor = elements::confidential::AssetBlindingFactor::from_slice(
                &leaf.asset_blinding_factor,
            )
            .map_err(|_| ElementsStateErrorV2::InvalidEconomicOpening)?;
            let value_blinding_factor = elements::confidential::ValueBlindingFactor::from_slice(
                &leaf.value_blinding_factor,
            )
            .map_err(|_| ElementsStateErrorV2::InvalidEconomicOpening)?;
            let expected_asset = Asset::new_confidential(&secp, asset_id, asset_blinding_factor);
            let asset_generator = expected_asset
                .commitment()
                .ok_or(ElementsStateErrorV2::InvalidEconomicOpening)?;
            let expected_value =
                Value::new_confidential(&secp, leaf.amount, asset_generator, value_blinding_factor);
            if leaf.utxo.output.asset != expected_asset
                || leaf.utxo.output.value != expected_value
                || !matches!(leaf.utxo.output.nonce, Nonce::Confidential(_))
            {
                return Err(ElementsStateErrorV2::InvalidEconomicOpening);
            }
            let rangeproof = leaf
                .utxo
                .output
                .witness
                .rangeproof
                .as_ref()
                .ok_or(ElementsStateErrorV2::InvalidEconomicOpening)?;
            let range = rangeproof
                .verify(
                    &secp,
                    expected_value
                        .commitment()
                        .ok_or(ElementsStateErrorV2::InvalidEconomicOpening)?,
                    leaf.utxo.output.script_pubkey.as_bytes(),
                    asset_generator,
                )
                .map_err(|_| ElementsStateErrorV2::InvalidEconomicOpening)?;
            if leaf.amount < range.start || leaf.amount >= range.end {
                return Err(ElementsStateErrorV2::InvalidEconomicOpening);
            }
        }
        _ => return Err(ElementsStateErrorV2::InvalidEconomicOpening),
    }

    Ok(())
}

fn economic_leaf_node_v2(
    leaf: &ElementsEconomicLeafV2,
    derived_role: ElementsLiveEconomicRoleV2,
) -> Result<ElementsSparseEconomicNodeV2, ElementsStateErrorV2> {
    if leaf.role != derived_role {
        return Err(ElementsStateErrorV2::InvalidEconomicOpening);
    }

    let mut payload = Vec::with_capacity(32 + 32 + 8 + 32 + 32 + 1);
    payload.extend_from_slice(&elements_utxo_leaf_node_v2(&leaf.utxo).hash);
    payload.extend_from_slice(&leaf.asset_id);
    payload.extend_from_slice(&leaf.amount.to_be_bytes());
    payload.extend_from_slice(&leaf.asset_blinding_factor);
    payload.extend_from_slice(&leaf.value_blinding_factor);
    payload.push(match leaf.role {
        ElementsLiveEconomicRoleV2::OutstandingBase => 1,
        ElementsLiveEconomicRoleV2::RedeemableReserve => 2,
        ElementsLiveEconomicRoleV2::RedemptionInventory => 3,
        ElementsLiveEconomicRoleV2::Irrelevant => 6,
    });
    let amount = u128::from(leaf.amount);
    Ok(ElementsSparseEconomicNodeV2 {
        hash: tagged_hash("ECX/full-elements-economic-leaf/v2", &payload),
        aggregate: ElementsEconomicAggregateV2 {
            count: 1,
            outstanding_base_atoms: if matches!(
                leaf.role,
                ElementsLiveEconomicRoleV2::OutstandingBase
            ) {
                amount
            } else {
                0
            },
            redeemable_reserve_quote_atoms: if matches!(
                leaf.role,
                ElementsLiveEconomicRoleV2::RedeemableReserve
            ) {
                amount
            } else {
                0
            },
        },
    })
}

pub fn elements_sparse_economic_parent_v2(
    left: ElementsSparseEconomicNodeV2,
    right: ElementsSparseEconomicNodeV2,
) -> Result<ElementsSparseEconomicNodeV2, ElementsStateErrorV2> {
    let aggregate = ElementsEconomicAggregateV2 {
        count: left
            .aggregate
            .count
            .checked_add(right.aggregate.count)
            .ok_or(ElementsStateErrorV2::AggregateOverflow)?,
        outstanding_base_atoms: left
            .aggregate
            .outstanding_base_atoms
            .checked_add(right.aggregate.outstanding_base_atoms)
            .ok_or(ElementsStateErrorV2::AggregateOverflow)?,
        redeemable_reserve_quote_atoms: left
            .aggregate
            .redeemable_reserve_quote_atoms
            .checked_add(right.aggregate.redeemable_reserve_quote_atoms)
            .ok_or(ElementsStateErrorV2::AggregateOverflow)?,
    };
    let mut payload = Vec::with_capacity(112);
    payload.extend_from_slice(&left.hash);
    payload.extend_from_slice(&right.hash);
    payload.extend_from_slice(&aggregate.count.to_be_bytes());
    payload.extend_from_slice(&aggregate.outstanding_base_atoms.to_be_bytes());
    payload.extend_from_slice(&aggregate.redeemable_reserve_quote_atoms.to_be_bytes());
    Ok(ElementsSparseEconomicNodeV2 {
        hash: tagged_hash("ECX/full-elements-economic-node/v2", &payload),
        aggregate,
    })
}

pub fn elements_sparse_utxo_parent_v2(
    left: ElementsSparseUtxoNodeV2,
    right: ElementsSparseUtxoNodeV2,
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    let count = left
        .aggregate
        .count
        .checked_add(right.aggregate.count)
        .ok_or(ElementsStateErrorV2::AggregateOverflow)?;
    let mut payload = Vec::with_capacity(80);
    payload.extend_from_slice(&left.hash);
    payload.extend_from_slice(&right.hash);
    payload.extend_from_slice(&count.to_be_bytes());
    Ok(ElementsSparseUtxoNodeV2 {
        hash: tagged_hash("ECX/full-elements-utxo-node/v2", &payload),
        aggregate: ElementsUtxoAggregateV2 { count },
    })
}

fn key_bit_from_leaf_level(key: ElementsHash32V2, leaf_level: usize) -> bool {
    let root_bit = ELEMENTS_SPARSE_UTXO_DEPTH_V2 - 1 - leaf_level;
    let byte = root_bit / 8;
    let bit_in_byte = 7 - (root_bit % 8);
    (key[byte] >> bit_in_byte) & 1 == 1
}

pub fn elements_sparse_utxo_root_from_path_v2(
    outpoint: OutPoint,
    leaf: ElementsSparseUtxoNodeV2,
    path: &ElementsSparseUtxoPathV2,
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    if path.siblings.len() != ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
        return Err(ElementsStateErrorV2::NonCanonicalPath);
    }
    let key = elements_sparse_utxo_key_v2(outpoint);
    path.siblings
        .iter()
        .copied()
        .enumerate()
        .try_fold(leaf, |current, (level, sibling)| {
            if key_bit_from_leaf_level(key, level) {
                elements_sparse_utxo_parent_v2(sibling, current)
            } else {
                elements_sparse_utxo_parent_v2(current, sibling)
            }
        })
}

pub fn elements_sparse_economic_root_from_path_v2(
    outpoint: OutPoint,
    leaf: ElementsSparseEconomicNodeV2,
    path: &ElementsSparseEconomicPathV2,
) -> Result<ElementsSparseEconomicNodeV2, ElementsStateErrorV2> {
    if path.siblings.len() != ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
        return Err(ElementsStateErrorV2::NonCanonicalPath);
    }
    let key = elements_sparse_utxo_key_v2(outpoint);
    path.siblings
        .iter()
        .copied()
        .enumerate()
        .try_fold(leaf, |current, (level, sibling)| {
            if key_bit_from_leaf_level(key, level) {
                elements_sparse_economic_parent_v2(sibling, current)
            } else {
                elements_sparse_economic_parent_v2(current, sibling)
            }
        })
}

pub fn apply_elements_sparse_economic_mutation_v2(
    current_root: ElementsSparseEconomicNodeV2,
    mutation: &ElementsSparseEconomicMutationV2,
    classification: ElementsEconomicClassificationV2,
) -> Result<ElementsSparseEconomicNodeV2, ElementsStateErrorV2> {
    let empty = canonical_empty_elements_economic_leaf_v2();
    let (old, new) = match (&mutation.old_leaf, &mutation.new_leaf) {
        (None, Some(new_leaf)) if new_leaf.utxo.outpoint == mutation.outpoint => (
            empty,
            verify_elements_economic_leaf_v2(new_leaf, classification)?,
        ),
        (Some(old_leaf), None) if old_leaf.utxo.outpoint == mutation.outpoint => (
            verify_elements_economic_leaf_v2(old_leaf, classification)?,
            empty,
        ),
        (None, Some(_)) | (Some(_), None) => return Err(ElementsStateErrorV2::OutpointMismatch),
        _ => return Err(ElementsStateErrorV2::InvalidMutation),
    };
    if elements_sparse_economic_root_from_path_v2(mutation.outpoint, old, &mutation.path)?
        != current_root
    {
        return Err(ElementsStateErrorV2::RootMismatch);
    }
    elements_sparse_economic_root_from_path_v2(mutation.outpoint, new, &mutation.path)
}

pub fn apply_elements_sparse_utxo_mutation_v2(
    current_root: ElementsSparseUtxoNodeV2,
    mutation: &ElementsSparseUtxoMutationV2,
) -> Result<ElementsSparseUtxoNodeV2, ElementsStateErrorV2> {
    let empty = canonical_empty_elements_utxo_leaf_v2();
    let (old, new) = match (&mutation.old_leaf, &mutation.new_leaf) {
        (None, Some(new_leaf)) if new_leaf.outpoint == mutation.outpoint => {
            (empty, elements_utxo_leaf_node_v2(new_leaf))
        }
        (Some(old_leaf), None) if old_leaf.outpoint == mutation.outpoint => {
            (elements_utxo_leaf_node_v2(old_leaf), empty)
        }
        (None, Some(_)) | (Some(_), None) => return Err(ElementsStateErrorV2::OutpointMismatch),
        _ => return Err(ElementsStateErrorV2::InvalidMutation),
    };
    if elements_sparse_utxo_root_from_path_v2(mutation.outpoint, old, &mutation.path)?
        != current_root
    {
        return Err(ElementsStateErrorV2::RootMismatch);
    }
    elements_sparse_utxo_root_from_path_v2(mutation.outpoint, new, &mutation.path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::secp256k1_zkp::{PublicKey, SecretKey};
    use elements::{AssetId, LockTime, Script, Sequence, Transaction, TxIn, TxOutSecrets, Txid};
    use rand::thread_rng;
    use std::cell::Cell;

    #[test]
    fn elements_absolute_and_bip68_locks_use_authenticated_height_and_mtp() {
        let asset = AssetId::from_slice(&[7; 32]).unwrap();
        let old_leaf = ElementsUtxoLeafV2 {
            outpoint: OutPoint::default(),
            output: TxOut {
                asset: Asset::Explicit(asset),
                value: Value::Explicit(1),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            creation_height: 100,
            creation_parent_mtp: 1_700_000_000,
            coinbase: false,
            created_by_issuance: false,
            created_by_pegin: false,
        };
        let spend = ElementsSparseUtxoMutationV2 {
            outpoint: old_leaf.outpoint,
            old_leaf: Some(old_leaf),
            new_leaf: None,
            path: ElementsSparseUtxoPathV2 { siblings: vec![] },
        };
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::from_consensus(200),
            input: vec![TxIn {
                previous_output: spend.outpoint,
                sequence: Sequence(u32::MAX - 1),
                ..Default::default()
            }],
            output: vec![],
        };
        assert_eq!(
            verify_elements_transaction_locks_v2(
                &transaction,
                std::slice::from_ref(&spend),
                ElementsTransactionSpendContextV2 {
                    height: 200,
                    parent_mtp: 1_700_001_000,
                },
            ),
            Err(ElementsStateErrorV2::AbsoluteLockTime)
        );
        transaction.lock_time = LockTime::from_consensus(199);
        assert!(verify_elements_transaction_locks_v2(
            &transaction,
            std::slice::from_ref(&spend),
            ElementsTransactionSpendContextV2 {
                height: 200,
                parent_mtp: 1_700_001_000,
            },
        )
        .is_ok());

        transaction.lock_time = LockTime::ZERO;
        transaction.input[0].sequence = Sequence(5);
        assert_eq!(
            verify_elements_transaction_locks_v2(
                &transaction,
                std::slice::from_ref(&spend),
                ElementsTransactionSpendContextV2 {
                    height: 104,
                    parent_mtp: 1_700_010_000,
                },
            ),
            Err(ElementsStateErrorV2::RelativeLockTime)
        );
        assert!(verify_elements_transaction_locks_v2(
            &transaction,
            std::slice::from_ref(&spend),
            ElementsTransactionSpendContextV2 {
                height: 105,
                parent_mtp: 1_700_010_000,
            },
        )
        .is_ok());

        transaction.input[0].sequence = Sequence((1 << 22) | 2);
        assert_eq!(
            verify_elements_transaction_locks_v2(
                &transaction,
                std::slice::from_ref(&spend),
                ElementsTransactionSpendContextV2 {
                    height: 200,
                    parent_mtp: 1_700_001_023,
                },
            ),
            Err(ElementsStateErrorV2::RelativeLockTime)
        );
        assert!(verify_elements_transaction_locks_v2(
            &transaction,
            &[spend],
            ElementsTransactionSpendContextV2 {
                height: 200,
                parent_mtp: 1_700_001_024,
            },
        )
        .is_ok());
    }

    struct ExactTestDepositVerifier {
        expected: DrivechainDepositStatementV2,
    }

    impl DrivechainDepositReceiptVerifierV2 for ExactTestDepositVerifier {
        fn verify_deposit_statement(
            &self,
            statement: &DrivechainDepositStatementV2,
        ) -> Result<(), ElementsStateErrorV2> {
            if statement == &self.expected {
                Ok(())
            } else {
                Err(ElementsStateErrorV2::DrivechainDeposit)
            }
        }
    }

    struct TestElementsInputVerifier {
        reject: bool,
    }

    impl ElementsInputVerifierV2 for TestElementsInputVerifier {
        fn verify_input(
            &self,
            _transaction: &Transaction,
            _input_index: usize,
            _previous_outputs: &[TxOut],
        ) -> Result<(), ElementsStateErrorV2> {
            if self.reject {
                Err(ElementsStateErrorV2::AuthorizationConsensus)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn elements_checker_normalizes_high_s_only_when_low_s_is_not_required() {
        let transaction = Transaction { version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn::default()], output: vec![] };
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[23; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret).serialize();
        let script = Script::from(vec![0x51]);
        // Exercise both legacy and witness-v0 digest paths.
        for value in [None, Some(Value::Explicit(10))] {
            let digest = match value {
                None => ElementsSighashCache::new(&transaction)
                    .legacy_sighash(0, &script, elements::EcdsaSighashType::All).to_byte_array(),
                Some(value) => ElementsSighashCache::new(&transaction)
                    .segwitv0_sighash(0, &script, value, elements::EcdsaSighashType::All).to_byte_array(),
            };
            let low = secp.sign_ecdsa(&Message::from_digest(digest), &secret);
            let mut compact = low.serialize_compact();
            // secp256k1 group order minus the low-S scalar yields its high-S twin.
            let order = [0xffu8,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
                0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
                0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41];
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let difference = i16::from(order[i]) - i16::from(compact[32+i]) - borrow;
                compact[32+i] = difference as u8;
                borrow = i16::from(difference < 0);
            }
            assert_eq!(borrow, 0);
            let high = ecdsa::Signature::from_compact(&compact).unwrap();
            assert_ne!(low, high);
            let mut normalized = high;
            normalized.normalize_s();
            assert_eq!(normalized, low);
            for (signature, is_high) in [(low,false),(high,true)] {
                let mut encoded = signature.serialize_der().to_vec(); encoded.push(1);
                let consensus = ElementsEcdsaCheckerV2 {transaction: &transaction,
                    input_index:0,spent_value:value,low_s:false,strict_der:true,
                    strict_encoding:false,rangeproof_active:false};
                assert_eq!(consensus.check_ecdsa_signature(&encoded,&public,script.as_bytes(),0),Ok(true));
                let policy = ElementsEcdsaCheckerV2 {low_s:true,..consensus};
                let result = policy.check_ecdsa_signature(&encoded,&public,script.as_bytes(),0);
                if is_high { assert_eq!(result,Err(ScriptPrimitiveErrorV2::Signature)); }
                else { assert_eq!(result,Ok(true)); }
                let wrong_public = PublicKey::from_secret_key(&secp,
                    &SecretKey::from_slice(&[24;32]).unwrap()).serialize();
                assert_eq!(consensus.check_ecdsa_signature(&encoded,&wrong_public,script.as_bytes(),0),Ok(false));
                // Native historical DER parser ignores trailing bytes within
                // the signature, but DERSIG must reject that encoding.
                let mut historical = signature.serialize_der().to_vec();
                historical.extend_from_slice(&[0x00, 0x01]);
                let lax = ElementsEcdsaCheckerV2 {strict_der:false,..consensus};
                assert_eq!(lax.check_ecdsa_signature(&historical,&public,script.as_bytes(),0),Ok(true));
                assert_eq!(consensus.check_ecdsa_signature(&historical,&public,script.as_bytes(),0),
                    Err(ScriptPrimitiveErrorV2::Signature));
                // Malformed cryptographic signatures are false, not a script
                // encoding error, when no DER/LOW_S rule is selected.
                assert_eq!(lax.check_ecdsa_signature(&[0x00,0x01],&public,script.as_bytes(),0),Ok(false));
                let low_s_only = ElementsEcdsaCheckerV2 {low_s:true,..lax};
                assert_eq!(low_s_only.check_ecdsa_signature(&historical,&public,script.as_bytes(),0),
                    Err(ScriptPrimitiveErrorV2::Signature));
            }
        }
    }

    #[test]
    fn concrete_elements_verifier_obeys_selected_block_rules() {
        let transaction = Transaction {version:2, lock_time:elements::LockTime::ZERO,
            input:vec![elements::TxIn::default()], output:vec![]};
        let genesis = BlockHash::from_byte_array([9;32]);
        let rules = ElementsInputRulesV3 {
            script:LegacyScriptFlagsV2::default(), cltv:false, csv:false,
            null_fail:false, null_dummy:false, discourage_upgradable_nops:false,
            const_script_code:false, rangeproof_active:false, simplicity_active:false, native_execution:true,
        };
        let run = |script:Vec<u8>, selected| {
            let previous = TxOut {script_pubkey:elements::Script::from(script),
                value:Value::Explicit(10), ..TxOut::default()};
            FullElementsInputVerifierV2::with_rules(genesis,selected)
                .verify_input(&transaction,0,&[previous])
        };
        // Before activation CLTV/CSV are NOPs; after activation these inputs
        // fail against the actual transaction locktime/final sequence.
        for (opcode, selected) in [(0xb1,ElementsInputRulesV3 {cltv:true,..rules}),
            (0xb2,ElementsInputRulesV3 {csv:true,..rules})] {
            let script = vec![0x51,opcode,0x75,0x51];
            assert_eq!(run(script.clone(),rules),Ok(()));
            assert_eq!(run(script,selected),Err(ElementsStateErrorV2::AuthorizationConsensus));
        }
        assert_eq!(run(vec![0x4c,1,1],rules),Ok(())); // Nonminimal OP_1 push.
        assert_eq!(run(vec![0x4c,1,1],ElementsInputRulesV3 {
            script:LegacyScriptFlagsV2 {require_minimal_push:true,..rules.script},..rules}),
            Err(ElementsStateErrorV2::AuthorizationConsensus));
        assert_eq!(run(vec![0x51,0x51],rules),Ok(())); // Consensus permits extra stack item.
        assert_eq!(run(vec![0x51,0x51],ElementsInputRulesV3 {
            script:LegacyScriptFlagsV2 {clean_stack:true,..rules.script},..rules}),
            Err(ElementsStateErrorV2::AuthorizationConsensus));
        let mut taproot = vec![0x51,0x20]; taproot.extend_from_slice(&[1;32]);
        assert_eq!(run(taproot.clone(),rules),Ok(()));
        let witness = ElementsInputRulesV3 {script:LegacyScriptFlagsV2 {
            verify_witness:true,verify_p2sh:true,..rules.script},..rules};
        assert_eq!(run(taproot.clone(),witness),Ok(())); // Unknown version before Taproot.
        assert_eq!(run(taproot,ElementsInputRulesV3 {script:LegacyScriptFlagsV2 {
            verify_taproot:true,..witness.script},..witness}),
            Err(ElementsStateErrorV2::AuthorizationConsensus)); // Empty witness after activation.
    }

    #[test]
    fn elements_checker_preserves_raw_sighash_and_selects_encoding_rules() {
        let transaction = Transaction { version: 2, lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn::default()], output: vec![elements::TxOut::default()] };
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[23;32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret).serialize();
        let script = [0x51];
        for value in [None, Some(Value::Explicit(10))] {
            for rangeproof_active in [false, true] {
                for raw in 0..=255u8 {
                    let digest = crate::elements_sighash_v3::elements_ecdsa_sighash_v3(
                        &transaction, 0, &script, value, raw, rangeproof_active).unwrap();
                    let mut signature = secp.sign_ecdsa(&Message::from_digest(digest), &secret)
                        .serialize_der().to_vec();
                    signature.push(raw);
                    let checker = ElementsEcdsaCheckerV2 { transaction:&transaction,
                        input_index:0, spent_value:value, low_s:false, strict_der:true,
                        strict_encoding:false, rangeproof_active };
                    assert_eq!(checker.check_ecdsa_signature(&signature,&public,&script,0), Ok(true));
                    let strict = ElementsEcdsaCheckerV2 {strict_encoding:true,..checker};
                    let defined = valid_defined_sighash_type_v2(
                        if rangeproof_active {raw & !0x40} else {raw});
                    assert_eq!(strict.check_ecdsa_signature(&signature,&public,&script,0),
                        if defined {Ok(true)} else {Err(ScriptPrimitiveErrorV2::Signature)});
                    assert_eq!(checker.check_ecdsa_signature(&signature,&[0;33],&script,0),Ok(false));
                }
            }
        }
    }

    #[test]
    fn concrete_elements_input_verifier_executes_legacy_witness_v0_and_taproot_key_path() {
        let verifier = FullElementsInputVerifierV2::new(BlockHash::from_byte_array([9; 32]));
        let asset = AssetId::from_slice(&[7; 32]).unwrap();
        let previous_output = |script_pubkey: Script| TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(10),
            nonce: Nonce::Null,
            script_pubkey,
            witness: Default::default(),
        };
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };

        let legacy = previous_output(Script::from(vec![0x51]));
        verifier.verify_input(&transaction, 0, &[legacy]).unwrap();

        let witness_script = vec![0x51];
        let witness_hash = crate::sha256_bytes(&witness_script);
        let mut witness_program = vec![0x00, 0x20];
        witness_program.extend_from_slice(&witness_hash);
        transaction.input[0].witness.script_witness = vec![witness_script];
        let witness_output = previous_output(Script::from(witness_program));
        verifier
            .verify_input(&transaction, 0, std::slice::from_ref(&witness_output))
            .unwrap();
        transaction.input[0].witness.script_witness[0][0] = 0x00;
        assert_eq!(
            verifier.verify_input(&transaction, 0, &[witness_output]),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret).serialize();
        let public_hash = elements::hashes::hash160::Hash::hash(&public).to_byte_array();
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&public_hash);
        let signed_previous = previous_output(Script::from(p2wpkh));
        let mut script_code = vec![0x76, 0xa9, 0x14];
        script_code.extend_from_slice(&public_hash);
        script_code.extend_from_slice(&[0x88, 0xac]);
        let digest = ElementsSighashCache::new(&transaction)
            .segwitv0_sighash(
                0,
                &Script::from(script_code),
                signed_previous.value,
                elements::EcdsaSighashType::All,
            )
            .to_byte_array();
        let mut signature = secp
            .sign_ecdsa(&Message::from_digest(digest), &secret)
            .serialize_der()
            .to_vec();
        signature.push(elements::EcdsaSighashType::All.as_u32() as u8);
        transaction.input[0].witness.script_witness = vec![signature, public.to_vec()];
        verifier
            .verify_input(&transaction, 0, std::slice::from_ref(&signed_previous))
            .unwrap();
        transaction.input[0].witness.script_witness[0][5] ^= 1;
        assert_eq!(
            verifier.verify_input(&transaction, 0, &[signed_previous]),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );

        let keypair = elements::secp256k1_zkp::Keypair::from_secret_key(&secp, &secret);
        let (taproot_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut taproot_program = vec![0x51, 0x20];
        taproot_program.extend_from_slice(&taproot_key.serialize());
        let taproot_output = previous_output(Script::from(taproot_program));
        transaction.input[0].witness.script_witness.clear();
        let taproot_digest = ElementsSighashCache::new(&transaction)
            .taproot_key_spend_signature_hash(
                0,
                &ElementsPrevouts::All(std::slice::from_ref(&taproot_output)),
                elements::SchnorrSighashType::Default,
                verifier.genesis_hash,
            )
            .unwrap()
            .to_byte_array();
        let taproot_signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(taproot_digest), &keypair);
        transaction.input[0].witness.script_witness = vec![taproot_signature.as_ref().to_vec()];
        verifier
            .verify_input(&transaction, 0, std::slice::from_ref(&taproot_output))
            .unwrap();
        transaction.input[0].witness.script_witness[0][0] ^= 1;
        assert_eq!(
            verifier.verify_input(&transaction, 0, &[taproot_output]),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );
    }

    struct RecordingSimplicityExecutor {
        calls: Cell<usize>,
    }

    impl ElementsSimplicityExecutorV2 for RecordingSimplicityExecutor {
        fn execute(
            &self,
            input: &ElementsSimplicityExecutionV2<'_>,
        ) -> Result<(), ElementsStateErrorV2> {
            if input.input_index != 0
                || input.committed_cmr != [0x41; 32]
                || input.program != [0x42, 0x43]
                || input.witness != [0x44, 0x45, 0x46]
                || input.annex != Some([0x50, 0x47, 0x48].as_slice())
                || input.previous_outputs.len() != 1
                || input.genesis_hash != BlockHash::from_byte_array([0x49; 32])
            {
                return Err(ElementsStateErrorV2::AuthorizationConsensus);
            }
            self.calls.set(self.calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn tapsimplicity_path_authenticates_exact_cmr_control_shape_and_executor_input() {
        use elements::taproot::{LeafVersion as ElementsLeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x31; 32]).unwrap();
        let keypair = elements::secp256k1_zkp::Keypair::from_secret_key(&secp, &secret);
        let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let leaf_version = ElementsLeafVersion::from_u8(0xbe).unwrap();
        let cmr_script = Script::from(vec![0x41; 32]);
        let spend = TaprootBuilder::new()
            .add_leaf_with_ver(0, cmr_script.clone(), leaf_version)
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let control = spend
            .control_block(&(cmr_script.clone(), leaf_version))
            .unwrap()
            .serialize();
        let asset = AssetId::from_slice(&[0x32; 32]).unwrap();
        let previous = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Script::new_v1_p2tr(&secp, internal_key, spend.merkle_root()),
            witness: Default::default(),
        };
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };
        transaction.input[0].witness.script_witness = vec![
            vec![0x44, 0x45, 0x46],
            vec![0x42, 0x43],
            vec![0x41; 32],
            control,
            vec![0x50, 0x47, 0x48],
        ];
        let executor = RecordingSimplicityExecutor {
            calls: Cell::new(0),
        };
        let verifier = FullElementsInputVerifierWithSimplicityV2 {
            base: FullElementsInputVerifierV2::new(BlockHash::from_byte_array([0x49; 32])),
            simplicity: &executor,
        };
        verifier
            .verify_input(&transaction, 0, std::slice::from_ref(&previous))
            .unwrap();
        assert_eq!(executor.calls.get(), 1);
        let mut inactive_rules = verifier.base.rules;
        inactive_rules.native_execution = true;
        inactive_rules.simplicity_active = false;
        let inactive = FullElementsInputVerifierWithSimplicityV2 {
            base: FullElementsInputVerifierV2::with_rules(verifier.base.genesis_hash,inactive_rules),
            simplicity: &executor,
        };
        // The same authenticated 0xbe leaf is not evaluated before activation.
        inactive.verify_input(&transaction,0,std::slice::from_ref(&previous)).unwrap();
        let mut future_stack = transaction.clone();
        future_stack.input[0].witness.script_witness.remove(0);
        inactive.verify_input(&future_stack,0,std::slice::from_ref(&previous)).unwrap();
        assert_eq!(executor.calls.get(),1);
        assert_eq!(verifier.verify_input(&future_stack,0,std::slice::from_ref(&previous)),
            Err(ElementsStateErrorV2::AuthorizationConsensus));
        let mut invalid_commitment = transaction.clone();
        invalid_commitment.input[0].witness.script_witness[2][0] ^= 1;
        assert_eq!(inactive.verify_input(&invalid_commitment,0,std::slice::from_ref(&previous)),
            Err(ElementsStateErrorV2::AuthorizationConsensus));
        assert_eq!(executor.calls.get(),1);
        assert_eq!(
            verifier
                .base
                .verify_input(&transaction, 0, std::slice::from_ref(&previous)),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );

        struct ExactReceiptVerifier;
        impl ElementsSimplicityReceiptVerifierV2 for ExactReceiptVerifier {
            fn verify(
                &self,
                program_id: ElementsHash32V2,
                public_values: &[u8],
                proof_marker: &[u8],
            ) -> Result<(), ElementsStateErrorV2> {
                if program_id != [0x51; 32]
                    || public_values.len() != ELEMENTS_SIMPLICITY_EXECUTION_PUBLIC_VALUES_BYTES_V2
                    || proof_marker != [0x77, 0x78]
                {
                    return Err(ElementsStateErrorV2::AuthorizationConsensus);
                }
                Ok(())
            }
        }
        let execution = ElementsSimplicityExecutionV2 {
            transaction: &transaction,
            input_index: 0,
            previous_outputs: std::slice::from_ref(&previous),
            genesis_hash: BlockHash::from_byte_array([0x49; 32]),
            committed_cmr: [0x41; 32],
            program: &[0x42, 0x43],
            witness: &[0x44, 0x45, 0x46],
            annex: Some(&[0x50, 0x47, 0x48]),
        };
        let execution_values = elements_simplicity_execution_public_values_v2(&execution).unwrap();
        let receipt = ElementsSimplicityReceiptBindingV2 {
            public_values: execution_values.canonical_bytes().to_vec(),
            proof_marker: vec![0x77, 0x78],
        };
        let receipt_verifier = ExactReceiptVerifier;
        let proof_executor = ProofCarryingElementsSimplicityExecutorV2::new(
            [0x51; 32],
            std::slice::from_ref(&receipt),
            &receipt_verifier,
        )
        .unwrap();
        let proof_input_verifier = FullElementsInputVerifierWithSimplicityV2 {
            base: FullElementsInputVerifierV2::new(BlockHash::from_byte_array([0x49; 32])),
            simplicity: &proof_executor,
        };
        proof_input_verifier
            .verify_input(&transaction, 0, std::slice::from_ref(&previous))
            .unwrap();
        proof_executor.require_all_receipts_consumed().unwrap();
        assert_eq!(
            proof_input_verifier.verify_input(&transaction, 0, std::slice::from_ref(&previous),),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );
        let mut changed_execution = execution;
        changed_execution.witness = &[0x44, 0x45, 0x47];
        assert_ne!(
            elements_simplicity_execution_public_values_v2(&changed_execution).unwrap(),
            execution_values
        );

        let mut wrong_cmr = transaction.clone();
        wrong_cmr.input[0].witness.script_witness[2][0] ^= 1;
        assert_eq!(
            verifier.verify_input(&wrong_cmr, 0, std::slice::from_ref(&previous)),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );
        let mut wrong_control = transaction.clone();
        wrong_control.input[0].witness.script_witness[3][1] ^= 1;
        assert_eq!(
            verifier.verify_input(&wrong_control, 0, std::slice::from_ref(&previous)),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );
        let mut wrong_shape = transaction.clone();
        wrong_shape.input[0].witness.script_witness.remove(1);
        assert_eq!(
            verifier.verify_input(&wrong_shape, 0, std::slice::from_ref(&previous)),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );
        let mut wrong_program = transaction.clone();
        wrong_program.input[0].witness.script_witness[1][0] ^= 1;
        assert_eq!(
            verifier.verify_input(&wrong_program, 0, std::slice::from_ref(&previous)),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );
        let mut wrong_annex = transaction;
        wrong_annex.input[0].witness.script_witness[4][1] ^= 1;
        assert_eq!(
            verifier.verify_input(&wrong_annex, 0, &[previous]),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );
        assert_eq!(executor.calls.get(), 1);
    }

    struct TestBlockAuthorizationVerifier {
        reject: bool,
    }

    impl ElementsBlockAuthorizationVerifierV2 for TestBlockAuthorizationVerifier {
        fn verify_legacy_proof(
            &self,
            _header: &elements::BlockHeader,
            _challenge: &Script,
            _solution: &Script,
        ) -> Result<(), ElementsStateErrorV2> {
            if self.reject {
                Err(ElementsStateErrorV2::HeaderConsensus)
            } else {
                Ok(())
            }
        }

        fn verify_dynafed_proof(
            &self,
            _header: &elements::BlockHeader,
            _challenge: &Script,
            _witness: &[Vec<u8>],
        ) -> Result<(), ElementsStateErrorV2> {
            if self.reject {
                Err(ElementsStateErrorV2::HeaderConsensus)
            } else {
                Ok(())
            }
        }
    }
    use std::str::FromStr;

    #[test]
    fn native_deposit_engine_preserves_sponsor_indices_and_authenticates_spends() {
        // This fixture tests engine composition, not parent-receipt validity.
        struct Kernel(TxOut);
        impl NativeDepositKernelVerifierV3 for Kernel {
            fn verify_kernel(&self, tx:&Transaction, sponsors:&[TxOut]) -> Result<TxOut,ElementsStateErrorV2> {
                if sponsors.len()!=1 { return Err(ElementsStateErrorV2::DrivechainDeposit); }
                let inputs=tx.input.iter().map(|i|if i.is_pegin(){self.0.clone()}else{sponsors[0].clone()}).collect::<Vec<_>>();
                tx.verify_tx_amt_proofs(&Secp256k1::new(),&inputs)
                    .map_err(|_|ElementsStateErrorV2::ConfidentialConsensus)?;
                Ok(self.0.clone())
            }
        }
        struct Signature { index:usize, sponsor:TxOut, reject:bool }
        impl ElementsInputVerifierV2 for Signature {
            fn verify_input(&self, _tx:&Transaction,index:usize,previous:&[TxOut])->Result<(),ElementsStateErrorV2> {
                if self.reject || index!=self.index || previous.len()!=2 || previous[index]!=self.sponsor {
                    return Err(ElementsStateErrorV2::AuthorizationConsensus);
                }
                Ok(())
            }
        }
        let asset=AssetId::from_slice(&[1;32]).unwrap();
        let output=TxOut {asset:Asset::Explicit(asset),value:Value::Explicit(1000),nonce:Nonce::Null,
            script_pubkey:Script::from(vec![0x51]),witness:Default::default()};
        let sponsor=TxOut {value:Value::Explicit(10),..output.clone()};
        let sponsor_outpoint=OutPoint::new(Txid::from_byte_array([2;32]),1);
        let sponsor_leaf=ElementsUtxoLeafV2 {outpoint:sponsor_outpoint,output:sponsor.clone(),creation_height:1,
            creation_parent_mtp:1,coinbase:false,created_by_issuance:false,created_by_pegin:false};
        let empty=canonical_empty_elements_utxo_root_v2().unwrap();
        let seed=ElementsSparseUtxoMutationV2 {outpoint:sponsor_outpoint,old_leaf:None,new_leaf:Some(sponsor_leaf.clone()),path:empty_path()};
        let initial=apply_elements_sparse_utxo_mutation_v2(empty,&seed).unwrap();
        for pegin_first in [true,false] {
            let mut inputs=vec![TxIn {is_pegin:true,previous_output:OutPoint::new(Txid::from_byte_array([3;32]),0),..Default::default()},
                TxIn {previous_output:sponsor_outpoint,..Default::default()}];
            if !pegin_first {inputs.swap(0,1);}
            let tx=Transaction {version:2,lock_time:LockTime::ZERO,input:inputs,
                output:vec![output.clone(),TxOut {script_pubkey:Script::new(),..sponsor.clone()}]};
            let outpoint=OutPoint::new(tx.txid(),0);
            let witness=ElementsTransactionUtxoWitnessV2 {
                spends:vec![ElementsSparseUtxoMutationV2 {outpoint:sponsor_outpoint,old_leaf:Some(sponsor_leaf.clone()),new_leaf:None,path:empty_path()}],
                creates:vec![ElementsSparseUtxoMutationV2 {outpoint,old_leaf:None,new_leaf:Some(ElementsUtxoLeafV2 {
                    outpoint,output:output.clone(),creation_height:9,creation_parent_mtp:90,coinbase:false,
                    created_by_issuance:false,created_by_pegin:true}),path:empty_path()}]};
            let expected=apply_elements_sparse_utxo_mutation_v2(empty,&witness.creates[0]).unwrap();
            let run=|root,witness:&ElementsTransactionUtxoWitnessV2,reject| {
                apply_elements_transaction_utxos_with_lock_policy(&tx,
                    ElementsTransactionSpendContextV2 {height:9,parent_mtp:90},root,witness,
                    &ElementsTransactionKernelWitnessV2::NativeDrivechainDeposit,
                    &Signature {index:usize::from(pegin_first),sponsor:sponsor.clone(),reject},None,
                    Some(NativeElementsLockPolicyV3 {csv_active:true,absolute_time_cutoff:90}),Some(&Kernel(output.clone())))
            };
            assert_eq!(run(initial,&witness,false),Ok(expected));
            assert_eq!(run(initial,&witness,true),Err(ElementsStateErrorV2::AuthorizationConsensus));
            assert!(run(empty,&witness,false).is_err());
            let mut wrong=witness.clone();wrong.creates[0].new_leaf.as_mut().unwrap().created_by_pegin=false;
            assert!(run(initial,&wrong,false).is_err());
            let mut wrong=witness.clone();wrong.spends[0].old_leaf.as_mut().unwrap().output.value=Value::Explicit(11);
            assert!(run(initial,&wrong,false).is_err());
        }
    }

    fn empty_path() -> ElementsSparseUtxoPathV2 {
        let mut siblings = Vec::with_capacity(ELEMENTS_SPARSE_UTXO_DEPTH_V2);
        let mut node = canonical_empty_elements_utxo_leaf_v2();
        for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
            siblings.push(node);
            node = elements_sparse_utxo_parent_v2(node, node).unwrap();
        }
        ElementsSparseUtxoPathV2 { siblings }
    }

    fn empty_economic_path() -> ElementsSparseEconomicPathV2 {
        let mut siblings = Vec::with_capacity(ELEMENTS_SPARSE_UTXO_DEPTH_V2);
        let mut node = canonical_empty_elements_economic_leaf_v2();
        for _ in 0..ELEMENTS_SPARSE_UTXO_DEPTH_V2 {
            siblings.push(node);
            node = elements_sparse_economic_parent_v2(node, node).unwrap();
        }
        ElementsSparseEconomicPathV2 { siblings }
    }

    fn leaf() -> ElementsUtxoLeafV2 {
        ElementsUtxoLeafV2 {
            outpoint: OutPoint {
                txid: Txid::from_str(
                    "0101010101010101010101010101010101010101010101010101010101010101",
                )
                .unwrap(),
                vout: 7,
            },
            output: TxOut {
                asset: Asset::Explicit(AssetId::from_slice(&[2; 32]).unwrap()),
                value: Value::Explicit(42),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: Default::default(),
            },
            creation_height: 11,
            creation_parent_mtp: 22,
            coinbase: false,
            created_by_issuance: true,
            created_by_pegin: false,
        }
    }

    fn confidential_economic_leaf(
        asset_byte: u8,
        amount: u64,
        script: Script,
        role: ElementsLiveEconomicRoleV2,
    ) -> ElementsEconomicLeafV2 {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let asset = AssetId::from_slice(&[asset_byte; 32]).unwrap();
        let asset_blinding_factor = [3; 32];
        let value_blinding_factor = [4; 32];
        let secrets = TxOutSecrets::new(
            asset,
            AssetBlindingFactor::from_slice(&asset_blinding_factor).unwrap(),
            amount,
            ValueBlindingFactor::from_slice(&value_blinding_factor).unwrap(),
        );
        let input_secrets = TxOutSecrets::new(
            asset,
            AssetBlindingFactor::zero(),
            amount,
            ValueBlindingFactor::zero(),
        );
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral = SecretKey::new(&mut rng);
        let output = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            script,
            receiver,
            ephemeral,
            secrets,
            &[input_secrets],
        )
        .unwrap();
        ElementsEconomicLeafV2 {
            utxo: ElementsUtxoLeafV2 {
                outpoint: OutPoint {
                    txid: Txid::from_str(
                        "0202020202020202020202020202020202020202020202020202020202020202",
                    )
                    .unwrap(),
                    vout: 0,
                },
                output,
                creation_height: 50,
                creation_parent_mtp: 60,
                coinbase: false,
                created_by_issuance: true,
                created_by_pegin: false,
            },
            asset_id: [asset_byte; 32],
            amount,
            asset_blinding_factor,
            value_blinding_factor,
            role,
        }
    }

    #[test]
    fn custody_accounting_separates_native_asset_and_rejects_local_reserves() {
        let policy = ElementsCustodyClassificationV3 {
            native_pegged_asset_id: [10;32], custody_asset_id: [9;32],
        };
        let leaf = confidential_economic_leaf(9, 100, Script::from(vec![0x51]),
            ElementsLiveEconomicRoleV2::OutstandingBase);
        let checked = verify_elements_custody_leaf_v3(&leaf, policy).unwrap();
        assert_eq!(checked.custody_supply_atoms, 100);
        let native = confidential_economic_leaf(10, 250, Script::from(vec![0x51]),
            ElementsLiveEconomicRoleV2::Irrelevant);
        assert_eq!(verify_elements_custody_leaf_v3(&native, policy).unwrap().custody_supply_atoms, 0);
        for role in [ElementsLiveEconomicRoleV2::RedeemableReserve,
            ElementsLiveEconomicRoleV2::RedemptionInventory, ElementsLiveEconomicRoleV2::Irrelevant] {
            let mut changed = leaf.clone(); changed.role = role;
            assert!(verify_elements_custody_leaf_v3(&changed, policy).is_err());
        }
        let mut changed = leaf.clone(); changed.amount += 1;
        assert!(verify_elements_custody_leaf_v3(&changed, policy).is_err());
        changed = leaf.clone(); changed.utxo.output.witness.rangeproof = None;
        assert!(verify_elements_custody_leaf_v3(&changed, policy).is_err());
        for asset in [[0;32], [10;32], [11;32]] {
            let changed = ElementsCustodyClassificationV3 { custody_asset_id: asset, ..policy };
            assert!(verify_elements_custody_leaf_v3(&leaf, changed).is_err());
        }
        let changed = ElementsCustodyClassificationV3 { native_pegged_asset_id: [11;32], ..policy };
        assert_ne!(checked.hash, verify_elements_custody_leaf_v3(&leaf, changed).unwrap().hash);
        let mut explicit = leaf.clone();
        explicit.utxo.output.asset = Asset::Explicit(AssetId::from_slice(&[9;32]).unwrap());
        explicit.utxo.output.value = Value::Explicit(100);
        explicit.utxo.output.nonce = Nonce::Null;
        explicit.utxo.output.witness = Default::default();
        explicit.asset_blinding_factor = [0;32]; explicit.value_blinding_factor = [0;32];
        assert_eq!(verify_elements_custody_leaf_v3(&explicit, policy).unwrap().custody_supply_atoms, 100);
        explicit.value_blinding_factor = [1;32];
        assert!(verify_elements_custody_leaf_v3(&explicit, policy).is_err());
    }

    #[test]
    fn custody_tree_authenticates_insert_delete_totals_and_policy() {
        let policy = ElementsCustodyClassificationV3 {
            native_pegged_asset_id: [10;32], custody_asset_id: [9;32],
        };
        let leaf = confidential_economic_leaf(9, 100, Script::from(vec![0x51]),
            ElementsLiveEconomicRoleV2::OutstandingBase);
        let mut empty = empty_elements_custody_leaf_v3();
        let mut siblings = Vec::new();
        for _ in 0..256 {
            siblings.push(empty); empty = elements_custody_parent_v3(empty, empty).unwrap();
        }
        let insert = ElementsSparseCustodyMutationV3 {
            outpoint: leaf.utxo.outpoint, old_leaf: None, new_leaf: Some(leaf.clone()), siblings,
        };
        let full = apply_elements_custody_mutation_v3(empty, &insert, policy).unwrap();
        assert_eq!((full.count, full.custody_supply_atoms), (1, 100));
        let utxo_mutation = ElementsSparseUtxoMutationV2 {
            outpoint: leaf.utxo.outpoint, old_leaf: None, new_leaf: Some(leaf.utxo.clone()),
            path: empty_path(),
        };
        let next_utxo = elements_sparse_utxo_root_from_path_v2(leaf.utxo.outpoint,
            elements_utxo_leaf_node_v2(&leaf.utxo), &utxo_mutation.path).unwrap();
        let utxos = ElementsTransactionUtxoWitnessV2 { spends: vec![], creates: vec![utxo_mutation] };
        let custody = ElementsTransactionCustodyWitnessV3 { spends: vec![], creates: vec![insert.clone()] };
        assert_eq!(apply_elements_transaction_custody_projection_v3(next_utxo, empty,
            &utxos, &custody, policy).unwrap(), full);
        for variant in 0..4 {
            let mut changed = custody.clone();
            match variant {
                0 => changed.creates.clear(),
                1 => changed.creates[0].new_leaf.as_mut().unwrap().utxo.creation_height += 1,
                2 => changed.creates[0].new_leaf.as_mut().unwrap().utxo.coinbase = true,
                _ => { let mutation = changed.creates.remove(0); changed.spends.push(mutation); },
            }
            assert!(apply_elements_transaction_custody_projection_v3(next_utxo, empty,
                &utxos, &changed, policy).is_err());
        }
        let mut wrong_count = next_utxo; wrong_count.aggregate.count += 1;
        assert!(apply_elements_transaction_custody_projection_v3(wrong_count, empty,
            &utxos, &custody, policy).is_err());
        let delete = ElementsSparseCustodyMutationV3 {
            old_leaf: Some(leaf.clone()), new_leaf: None, ..insert.clone()
        };
        assert_eq!(apply_elements_custody_mutation_v3(full, &delete, policy).unwrap(), empty);
        assert!(apply_elements_custody_mutation_v3(full, &insert, policy).is_err());
        assert!(apply_elements_custody_mutation_v3(empty, &delete, policy).is_err());
        let changed_policy = ElementsCustodyClassificationV3 {
            native_pegged_asset_id: [11;32], ..policy
        };
        assert!(apply_elements_custody_mutation_v3(full, &delete, changed_policy).is_err());
        for variant in 0..6 {
            let mut changed = delete.clone();
            match variant {
                0 => { changed.siblings.pop(); },
                1 => changed.siblings[0].hash[0] ^= 1,
                2 => changed.siblings[0].custody_supply_atoms += 1,
                3 => changed.siblings[0].count += 1,
                4 => changed.outpoint.vout += 1,
                _ => changed.new_leaf = Some(leaf.clone()),
            }
            assert!(apply_elements_custody_mutation_v3(full, &changed, policy).is_err());
        }
        let mut overflow = full; overflow.count = u128::MAX;
        assert_eq!(elements_custody_parent_v3(overflow, full), Err(ElementsStateErrorV2::AggregateOverflow));
        overflow = full; overflow.custody_supply_atoms = u128::MAX;
        assert_eq!(elements_custody_parent_v3(overflow, full), Err(ElementsStateErrorV2::AggregateOverflow));
    }

    #[test]
    fn economic_tree_derives_totals_and_rejects_forged_openings_or_roles() {
        let inventory_script = Script::from(vec![0x52]);
        let reserve_script = Script::from(vec![0x53]);
        let classification = ElementsEconomicClassificationV2 {
            base_asset_id: [9; 32],
            policy_asset_id: [10; 32],
            redemption_inventory_script_sha256: crate::sha256_bytes(inventory_script.as_bytes()),
            reserve_script_sha256: crate::sha256_bytes(reserve_script.as_bytes()),
        };
        let leaf = confidential_economic_leaf(
            9,
            100,
            Script::from(vec![0x51]),
            ElementsLiveEconomicRoleV2::OutstandingBase,
        );
        let path = empty_economic_path();
        let empty_root = elements_sparse_economic_root_from_path_v2(
            leaf.utxo.outpoint,
            canonical_empty_elements_economic_leaf_v2(),
            &path,
        )
        .unwrap();
        let mutation = ElementsSparseEconomicMutationV2 {
            outpoint: leaf.utxo.outpoint,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
            path,
        };
        let inserted =
            apply_elements_sparse_economic_mutation_v2(empty_root, &mutation, classification)
                .unwrap();
        assert_eq!(inserted.aggregate.count, 1);
        assert_eq!(inserted.aggregate.outstanding_base_atoms, 100);
        assert_eq!(inserted.aggregate.redeemable_reserve_quote_atoms, 0);

        let mut forged_amount = leaf.clone();
        forged_amount.amount += 1;
        let forged = ElementsSparseEconomicMutationV2 {
            new_leaf: Some(forged_amount),
            ..mutation.clone()
        };
        assert_eq!(
            apply_elements_sparse_economic_mutation_v2(empty_root, &forged, classification),
            Err(ElementsStateErrorV2::InvalidEconomicOpening)
        );

        let mut forged_role = leaf;
        forged_role.role = ElementsLiveEconomicRoleV2::RedemptionInventory;
        let forged = ElementsSparseEconomicMutationV2 {
            new_leaf: Some(forged_role),
            ..mutation
        };
        assert_eq!(
            apply_elements_sparse_economic_mutation_v2(empty_root, &forged, classification),
            Err(ElementsStateErrorV2::InvalidEconomicOpening)
        );

        let reserve = confidential_economic_leaf(
            10,
            250,
            reserve_script,
            ElementsLiveEconomicRoleV2::RedeemableReserve,
        );
        let verified = verify_elements_economic_leaf_v2(&reserve, classification).unwrap();
        assert_eq!(verified.aggregate.outstanding_base_atoms, 0);
        assert_eq!(verified.aggregate.redeemable_reserve_quote_atoms, 250);
    }

    #[test]
    fn transaction_state_requires_one_economic_opening_for_every_live_utxo() {
        let asset = AssetId::from_slice(&[9; 32]).unwrap();
        let output = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(100),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![output.clone()],
        };
        assert!(transaction.is_coinbase());
        let outpoint = OutPoint {
            txid: transaction.txid(),
            vout: 0,
        };
        let utxo_leaf = ElementsUtxoLeafV2 {
            outpoint,
            output,
            creation_height: 50,
            creation_parent_mtp: 60,
            coinbase: true,
            created_by_issuance: false,
            created_by_pegin: false,
        };
        let economic_leaf = ElementsEconomicLeafV2 {
            utxo: utxo_leaf.clone(),
            asset_id: [9; 32],
            amount: 100,
            asset_blinding_factor: [0; 32],
            value_blinding_factor: [0; 32],
            role: ElementsLiveEconomicRoleV2::OutstandingBase,
        };
        let utxo_path = empty_path();
        let economic_path = empty_economic_path();
        let initial_utxo_root = elements_sparse_utxo_root_from_path_v2(
            outpoint,
            canonical_empty_elements_utxo_leaf_v2(),
            &utxo_path,
        )
        .unwrap();
        let initial_economic_root = elements_sparse_economic_root_from_path_v2(
            outpoint,
            canonical_empty_elements_economic_leaf_v2(),
            &economic_path,
        )
        .unwrap();
        let utxo_witness = ElementsTransactionUtxoWitnessV2 {
            spends: vec![],
            creates: vec![ElementsSparseUtxoMutationV2 {
                outpoint,
                old_leaf: None,
                new_leaf: Some(utxo_leaf),
                path: utxo_path,
            }],
        };
        let economic_witness = ElementsTransactionEconomicWitnessV2 {
            spends: vec![],
            creates: vec![ElementsSparseEconomicMutationV2 {
                outpoint,
                old_leaf: None,
                new_leaf: Some(economic_leaf),
                path: economic_path,
            }],
        };
        let classification = ElementsEconomicClassificationV2 {
            base_asset_id: [9; 32],
            policy_asset_id: [10; 32],
            redemption_inventory_script_sha256: crate::sha256_bytes(&[0x52]),
            reserve_script_sha256: crate::sha256_bytes(&[0x53]),
        };
        let roots = apply_elements_transaction_state_v2(
            &transaction,
            ElementsTransactionSpendContextV2 {
                height: 50,
                parent_mtp: 60,
            },
            initial_utxo_root,
            initial_economic_root,
            &utxo_witness,
            &economic_witness,
            classification,
            &ElementsTransactionKernelWitnessV2::Coinbase,
            &TestElementsInputVerifier { reject: false },
            None,
        )
        .unwrap();
        assert_eq!(roots.utxo_root.aggregate.count, 1);
        assert_eq!(roots.economic_root.aggregate.count, 1);
        assert_eq!(roots.economic_root.aggregate.outstanding_base_atoms, 100);

        let omitted = ElementsTransactionEconomicWitnessV2 {
            spends: vec![],
            creates: vec![],
        };
        for csv_active in [false, true] {
            let policy = NativeElementsLockPolicyV3 {
                csv_active,
                absolute_time_cutoff: 60,
            };
            let native = |economic| apply_elements_transaction_state_native_v3(
                &transaction,
                ElementsTransactionSpendContextV2 { height: 50, parent_mtp: 60 },
                initial_utxo_root,
                initial_economic_root,
                &utxo_witness,
                economic,
                classification,
                &ElementsTransactionKernelWitnessV2::Coinbase,
                &TestElementsInputVerifier { reject: false },
                None,
                policy,
            );
            assert_eq!(native(&economic_witness), Ok(roots));
            assert_eq!(native(&omitted), Err(ElementsStateErrorV2::TransactionWitness));
        }
        assert_eq!(
            apply_elements_transaction_state_v2(
                &transaction,
                ElementsTransactionSpendContextV2 {
                    height: 50,
                    parent_mtp: 60,
                },
                initial_utxo_root,
                initial_economic_root,
                &utxo_witness,
                &omitted,
                classification,
                &ElementsTransactionKernelWitnessV2::Coinbase,
                &TestElementsInputVerifier { reject: false },
                None,
            ),
            Err(ElementsStateErrorV2::TransactionWitness)
        );
    }

    #[test]
    fn native_custody_burn_requires_authorization_and_exact_supply_deletion() {
        let asset = AssetId::from_slice(&[9;32]).unwrap();
        let outpoint = OutPoint { txid: Txid::from_slice(&[7;32]).unwrap(), vout: 0 };
        let output = TxOut { asset: Asset::Explicit(asset), value: Value::Explicit(100),
            nonce: Nonce::Null, script_pubkey: Script::from(vec![0x51]), witness: Default::default() };
        let utxo = ElementsUtxoLeafV2 { outpoint, output: output.clone(), creation_height: 1,
            creation_parent_mtp: 1, coinbase: false, created_by_issuance: true, created_by_pegin: false };
        let leaf = ElementsEconomicLeafV2 { utxo: utxo.clone(), asset_id: [9;32], amount: 100,
            asset_blinding_factor: [0;32], value_blinding_factor: [0;32],
            role: ElementsLiveEconomicRoleV2::OutstandingBase };
        let classification = ElementsCustodyClassificationV3 {
            native_pegged_asset_id: [10;32], custody_asset_id: [9;32] };
        let mut empty = empty_elements_custody_leaf_v3();
        let mut siblings = Vec::new();
        for _ in 0..256 { siblings.push(empty); empty = elements_custody_parent_v3(empty, empty).unwrap(); }
        let custody_root = elements_custody_root_from_path_v3(outpoint,
            verify_elements_custody_leaf_v3(&leaf, classification).unwrap(), &siblings).unwrap();
        let path = empty_path();
        let utxo_root = elements_sparse_utxo_root_from_path_v2(outpoint,
            elements_utxo_leaf_node_v2(&utxo), &path).unwrap();
        let utxos = ElementsTransactionUtxoWitnessV2 { spends: vec![ElementsSparseUtxoMutationV2 {
            outpoint, old_leaf: Some(utxo), new_leaf: None, path }], creates: vec![] };
        let custody = ElementsTransactionCustodyWitnessV3 { spends: vec![ElementsSparseCustodyMutationV3 {
            outpoint, old_leaf: Some(leaf), new_leaf: None, siblings }], creates: vec![] };
        // Ordinary provably unspendable burn; this does NOT test the custody
        // redemption envelope, M6 approval or Ethereum release authorization.
        let transaction = Transaction { version: 2, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: outpoint, ..TxIn::default() }],
            output: vec![TxOut { script_pubkey: Script::from(vec![0x6a]), ..output }] };
        let run = |tx: &Transaction, witness: &ElementsTransactionCustodyWitnessV3, reject| {
            apply_elements_transaction_custody_native_v3(tx,
                ElementsTransactionSpendContextV2 { height: 50, parent_mtp: 60 },
                ElementsTransactionCustodyRootsV3 { utxo_root, custody_root }, &utxos, witness,
                classification, &ElementsTransactionKernelWitnessV2::Ordinary,
                &TestElementsInputVerifier { reject }, None,
                NativeElementsLockPolicyV3 { csv_active: true, absolute_time_cutoff: 60 })
        };
        let result = run(&transaction, &custody, false).unwrap();
        assert_eq!(result.utxo_root.aggregate.count, 0);
        assert_eq!(result.custody_root, empty);
        assert!(run(&transaction, &custody, true).is_err());
        let omitted = ElementsTransactionCustodyWitnessV3 { spends: vec![], creates: vec![] };
        assert!(run(&transaction, &omitted, false).is_err());
        let mut altered = transaction.clone(); altered.output[0].value = Value::Explicit(101);
        assert!(run(&altered, &custody, false).is_err());
        altered = transaction.clone(); altered.input[0].previous_output.vout = 1;
        assert!(run(&altered, &custody, false).is_err());
    }

    #[test]
    fn exact_confidential_output_and_provenance_are_authenticated() {
        let leaf = leaf();
        let path = empty_path();
        let empty_root = elements_sparse_utxo_root_from_path_v2(
            leaf.outpoint,
            canonical_empty_elements_utxo_leaf_v2(),
            &path,
        )
        .unwrap();
        let mutation = ElementsSparseUtxoMutationV2 {
            outpoint: leaf.outpoint,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
            path,
        };
        let inserted = apply_elements_sparse_utxo_mutation_v2(empty_root, &mutation).unwrap();
        assert_eq!(inserted.aggregate.count, 1);

        let mut changed = leaf;
        changed.created_by_issuance = false;
        let bad = ElementsSparseUtxoMutationV2 {
            new_leaf: Some(changed),
            ..mutation
        };
        assert_ne!(
            apply_elements_sparse_utxo_mutation_v2(empty_root, &bad).unwrap(),
            inserted
        );
    }

    #[test]
    fn path_shape_outpoint_and_old_root_fail_closed() {
        let leaf = leaf();
        let mut path = empty_path();
        path.siblings.pop();
        let mutation = ElementsSparseUtxoMutationV2 {
            outpoint: leaf.outpoint,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
            path,
        };
        assert_eq!(
            apply_elements_sparse_utxo_mutation_v2(
                canonical_empty_elements_utxo_leaf_v2(),
                &mutation
            ),
            Err(ElementsStateErrorV2::NonCanonicalPath)
        );

        let mut mismatch = mutation;
        mismatch.path = empty_path();
        mismatch.outpoint.vout += 1;
        assert_eq!(
            apply_elements_sparse_utxo_mutation_v2(
                canonical_empty_elements_utxo_leaf_v2(),
                &mismatch
            ),
            Err(ElementsStateErrorV2::OutpointMismatch)
        );
    }

    #[test]
    fn elements_block_foundation_binds_decode_link_height_merkle_and_coinbase() {
        let previous = BlockHash::from_byte_array([81; 32]);
        let coinbase = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                asset: Asset::Null,
                value: Value::Null,
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x6a]),
                witness: Default::default(),
            }],
        };
        let merkle_root =
            elements_transaction_merkle_root_v2(std::slice::from_ref(&coinbase)).unwrap();
        let block = Block {
            header: elements::BlockHeader {
                version: 1,
                prev_blockhash: previous,
                merkle_root,
                time: 100,
                height: 7,
                ext: elements::BlockExtData::Proof {
                    challenge: Script::new(),
                    solution: Script::new(),
                },
            },
            txdata: vec![coinbase],
        };
        let raw = serialize(&block);
        assert_eq!(
            verify_elements_block_foundation_v2(&raw, previous, 7, ELEMENTS_MAX_BLOCK_WEIGHT_V2,),
            Ok(block.clone())
        );

        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(
            verify_elements_block_foundation_v2(
                &trailing,
                previous,
                7,
                ELEMENTS_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(ElementsStateErrorV2::BlockConsensus)
        );
        let mut wrong_merkle = block.clone();
        wrong_merkle.header.merkle_root = TxMerkleNode::from_byte_array([82; 32]);
        assert_eq!(
            verify_elements_block_foundation_v2(
                &serialize(&wrong_merkle),
                previous,
                7,
                ELEMENTS_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(ElementsStateErrorV2::BlockConsensus)
        );
        assert_eq!(
            verify_elements_block_foundation_v2(
                &raw,
                BlockHash::from_byte_array([83; 32]),
                7,
                ELEMENTS_MAX_BLOCK_WEIGHT_V2,
            ),
            Err(ElementsStateErrorV2::BlockConsensus)
        );
        assert_eq!(
            verify_elements_block_foundation_v2(&raw, previous, 8, ELEMENTS_MAX_BLOCK_WEIGHT_V2,),
            Err(ElementsStateErrorV2::BlockConsensus)
        );
        assert_eq!(
            verify_elements_block_foundation_v2(&raw, previous, 7, 1),
            Err(ElementsStateErrorV2::BlockConsensus)
        );

        let legacy_context = ElementsHeaderConsensusContextV2 {
            previous_block_hash: previous,
            next_height: 7,
            previous_11_times: vec![90; 11],
            authenticated_adjusted_time: 100,
            expected_current_dynafed_params: None,
            expected_full_current_dynafed_params: None,
            legacy_signblock_challenge: Script::new(),
            legacy_signblock_witness_limit: 100,
        };
        let mut early = legacy_context.clone();
        early.previous_11_times = vec![90; 7];
        assert_eq!(verify_elements_contextual_header_native_v3(&block,&early,
            &TestBlockAuthorizationVerifier {reject:false}),Ok(()));
        assert!(verify_elements_contextual_header_v2(&block,&early,
            &TestBlockAuthorizationVerifier {reject:false}).is_err());
        assert!(verify_elements_contextual_header_native_v3(&block,&early,
            &TestBlockAuthorizationVerifier {reject:true}).is_err());
        early.legacy_signblock_challenge = Script::from(vec![0x51]);
        assert!(verify_elements_contextual_header_native_v3(&block,&early,
            &TestBlockAuthorizationVerifier {reject:false}).is_err());
        early.legacy_signblock_challenge = Script::new();
        early.previous_11_times.pop();
        assert!(verify_elements_contextual_header_native_v3(&block,&early,
            &TestBlockAuthorizationVerifier {reject:false}).is_err());
        verify_elements_contextual_header_v2(
            &block,
            &legacy_context,
            &TestBlockAuthorizationVerifier { reject: false },
        )
        .unwrap();
        assert_eq!(
            verify_elements_contextual_header_v2(
                &block,
                &legacy_context,
                &TestBlockAuthorizationVerifier { reject: true },
            ),
            Err(ElementsStateErrorV2::HeaderConsensus)
        );
        let mut stale = block.clone();
        stale.header.time = 90;
        assert_eq!(
            verify_elements_contextual_header_v2(
                &stale,
                &legacy_context,
                &TestBlockAuthorizationVerifier { reject: false },
            ),
            Err(ElementsStateErrorV2::HeaderConsensus)
        );

        let dynafed_full = elements::dynafed::FullParams::new(
            Script::from(vec![0x51]),
            100,
            bitcoin::ScriptBuf::new(),
            vec![],
            vec![],
        );
        let dynafed_params = elements::dynafed::Params::Full(dynafed_full.clone());
        let mut dynafed_block = block.clone();
        dynafed_block.header.ext = elements::BlockExtData::Dynafed {
            current: dynafed_params.clone(),
            proposed: elements::dynafed::Params::Null,
            signblock_witness: vec![vec![1]],
        };
        let dynafed_context = ElementsHeaderConsensusContextV2 {
            expected_current_dynafed_params: Some(dynafed_params.clone()),
            expected_full_current_dynafed_params: Some(dynafed_full.clone()),
            ..legacy_context.clone()
        };
        verify_elements_contextual_header_v2(
            &dynafed_block,
            &dynafed_context,
            &TestBlockAuthorizationVerifier { reject: false },
        )
        .unwrap();
        let mut wrong_current = dynafed_block.clone();
        if let elements::BlockExtData::Dynafed { current, .. } = &mut wrong_current.header.ext {
            *current = elements::dynafed::Params::Null;
        }
        assert_eq!(
            verify_elements_contextual_header_v2(
                &wrong_current,
                &dynafed_context,
                &TestBlockAuthorizationVerifier { reject: false },
            ),
            Err(ElementsStateErrorV2::HeaderConsensus)
        );
        let mut reserved_version = dynafed_block;
        reserved_version.header.version |= 1 << 23;
        assert_eq!(
            verify_elements_contextual_header_v2(
                &reserved_version,
                &dynafed_context,
                &TestBlockAuthorizationVerifier { reject: false },
            ),
            Err(ElementsStateErrorV2::HeaderConsensus)
        );

        let new_signblock = Script::from({
            let mut bytes = vec![0x00, 0x20];
            bytes.extend_from_slice(&[91; 32]);
            bytes
        });
        let winning_full = elements::dynafed::FullParams::new(
            new_signblock,
            100,
            bitcoin::ScriptBuf::new(),
            vec![],
            vec![],
        );
        let winning_params = elements::dynafed::Params::Full(winning_full.clone());
        let compact_current = dynafed_full.clone().into_compact();
        let mut epoch_headers = Vec::new();
        let mut previous_hash = BlockHash::from_byte_array([92; 32]);
        for offset in 0..5u32 {
            let header = elements::BlockHeader {
                version: 1,
                prev_blockhash: previous_hash,
                merkle_root: TxMerkleNode::from_byte_array([offset as u8; 32]),
                time: 190 + offset,
                height: 5 + offset,
                ext: elements::BlockExtData::Dynafed {
                    current: if offset == 0 {
                        dynafed_params.clone()
                    } else {
                        compact_current.clone()
                    },
                    proposed: if offset < 4 {
                        winning_params.clone()
                    } else {
                        elements::dynafed::Params::Null
                    },
                    signblock_witness: vec![vec![1]],
                },
            };
            previous_hash = header.block_hash();
            epoch_headers.push(header);
        }
        let history = ElementsDynafedEpochHistoryV2 {
            epoch_length: 5,
            headers: epoch_headers,
        };
        let derived = derive_expected_dynafed_parameters_v2(&history, 10).unwrap();
        assert_eq!(derived.expected_current, winning_params);
        assert_eq!(derived.expected_full_current, winning_full);

        let mut transition_block = block.clone();
        transition_block.header.prev_blockhash = previous_hash;
        transition_block.header.height = 10;
        transition_block.header.time = 200;
        transition_block.header.ext = elements::BlockExtData::Dynafed {
            current: derived.expected_current,
            proposed: elements::dynafed::Params::Null,
            signblock_witness: vec![vec![1]],
        };
        verify_elements_contextual_dynafed_header_from_history_v2(
            &transition_block,
            &history,
            vec![190; 11],
            200,
            &TestBlockAuthorizationVerifier { reject: false },
        )
        .unwrap();

        let mut insufficient_votes = history.clone();
        if let elements::BlockExtData::Dynafed { proposed, .. } =
            &mut insufficient_votes.headers[0].ext
        {
            *proposed = elements::dynafed::Params::Null;
        }
        for index in 1..insufficient_votes.headers.len() {
            insufficient_votes.headers[index].prev_blockhash =
                insufficient_votes.headers[index - 1].block_hash();
        }
        let no_transition = derive_expected_dynafed_parameters_v2(&insufficient_votes, 10).unwrap();
        assert_eq!(no_transition.expected_current, dynafed_params);
        assert_eq!(no_transition.expected_full_current, dynafed_full);

        let header_10 = elements::BlockHeader {
            version: 1,
            prev_blockhash: previous_hash,
            merkle_root: TxMerkleNode::from_byte_array([94; 32]),
            time: 200,
            height: 10,
            ext: elements::BlockExtData::Dynafed {
                current: winning_params.clone(),
                proposed: elements::dynafed::Params::Null,
                signblock_witness: vec![vec![1]],
            },
        };
        let header_11 = elements::BlockHeader {
            version: 1,
            prev_blockhash: header_10.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([95; 32]),
            time: 201,
            height: 11,
            ext: elements::BlockExtData::Dynafed {
                current: winning_full.clone().into_compact(),
                proposed: elements::dynafed::Params::Null,
                signblock_witness: vec![vec![1]],
            },
        };
        let within_epoch = derive_expected_dynafed_parameters_v2(
            &ElementsDynafedEpochHistoryV2 {
                epoch_length: 5,
                headers: vec![header_10, header_11],
            },
            12,
        )
        .unwrap();
        assert_eq!(
            within_epoch.expected_current,
            winning_full.clone().into_compact()
        );
        assert_eq!(within_epoch.expected_full_current, winning_full);
        let mut broken_history = history;
        broken_history.headers[3].prev_blockhash = BlockHash::from_byte_array([93; 32]);
        assert_eq!(
            derive_expected_dynafed_parameters_v2(&broken_history, 10),
            Err(ElementsStateErrorV2::HeaderConsensus)
        );
    }

    #[test]
    fn ordinary_transaction_kernel_checks_balance_fee_shape_and_value_sources() {
        let asset = AssetId::from_slice(&[7; 32]).unwrap();
        let previous = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(100),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    value: Value::Explicit(90),
                    ..previous.clone()
                },
                TxOut {
                    asset: Asset::Explicit(asset),
                    value: Value::Explicit(10),
                    nonce: Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: Default::default(),
                },
            ],
        };
        verify_ordinary_elements_confidential_transaction_v2(
            &transaction,
            std::slice::from_ref(&previous),
        )
        .unwrap();

        transaction.output[0].value = Value::Explicit(91);
        assert_eq!(
            verify_ordinary_elements_confidential_transaction_v2(
                &transaction,
                std::slice::from_ref(&previous),
            ),
            Err(ElementsStateErrorV2::ConfidentialConsensus)
        );
        transaction.output[0].value = Value::Explicit(90);
        transaction.output[1].nonce = Nonce::Confidential(
            elements::secp256k1_zkp::PublicKey::from_slice(&[
                2, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
                0x5b, 0x16, 0xf8, 0x17, 0x98,
            ])
            .unwrap(),
        );
        assert_eq!(
            verify_ordinary_elements_confidential_transaction_v2(
                &transaction,
                std::slice::from_ref(&previous),
            ),
            Err(ElementsStateErrorV2::NonCanonicalFeeOutput)
        );

        transaction.output[1].nonce = Nonce::Null;
        transaction.input[0].is_pegin = true;
        assert_eq!(
            verify_ordinary_elements_confidential_transaction_v2(&transaction, &[previous]),
            Err(ElementsStateErrorV2::UnsupportedValueSource)
        );
    }

    #[test]
    fn ordinary_transaction_kernel_verifies_real_range_and_surjection_proofs() {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let asset = AssetId::from_slice(&[9; 32]).unwrap();
        let previous = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(100),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral = SecretKey::new(&mut rng);
        let input_secrets = TxOutSecrets::new(
            asset,
            AssetBlindingFactor::zero(),
            100,
            ValueBlindingFactor::zero(),
        );
        let output_abf = AssetBlindingFactor::from_slice(&[3; 32]).unwrap();
        let output_vbf = ValueBlindingFactor::last(
            &secp,
            100,
            output_abf,
            &[input_secrets.value_blind_inputs()],
            &[],
        );
        let output_secrets = TxOutSecrets::new(asset, output_abf, 100, output_vbf);
        let confidential = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            Script::from(vec![0x51, 0x51]),
            receiver,
            ephemeral,
            output_secrets,
            &[input_secrets],
        )
        .unwrap();
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![confidential],
        };
        verify_ordinary_elements_confidential_transaction_v2(
            &transaction,
            std::slice::from_ref(&previous),
        )
        .unwrap();

        let original_proof = transaction.output[0].witness.rangeproof.take().unwrap();
        let mut proof = elements::secp256k1_zkp::RangeProof::serialize(&original_proof);
        let mutation_index = proof.len() / 2;
        proof[mutation_index] ^= 1;
        transaction.output[0].witness.rangeproof = Some(Box::new(
            elements::secp256k1_zkp::RangeProof::from_slice(&proof).unwrap(),
        ));
        assert_eq!(
            verify_ordinary_elements_confidential_transaction_v2(&transaction, &[previous]),
            Err(ElementsStateErrorV2::ConfidentialConsensus)
        );
    }

    #[test]
    fn transaction_executor_binds_kernel_authorization_provenance_and_intermediate_roots() {
        let asset = AssetId::from_slice(&[71; 32]).unwrap();
        let previous_outpoint = OutPoint::new(Txid::from_byte_array([72; 32]), 0);
        let previous_output = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(100),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let previous_leaf = ElementsUtxoLeafV2 {
            outpoint: previous_outpoint,
            output: previous_output.clone(),
            creation_height: 4,
            creation_parent_mtp: 40,
            coinbase: false,
            created_by_issuance: false,
            created_by_pegin: false,
        };
        let path = empty_path();
        let empty_root = elements_sparse_utxo_root_from_path_v2(
            previous_outpoint,
            canonical_empty_elements_utxo_leaf_v2(),
            &path,
        )
        .unwrap();
        let initial_root = apply_elements_sparse_utxo_mutation_v2(
            empty_root,
            &ElementsSparseUtxoMutationV2 {
                outpoint: previous_outpoint,
                old_leaf: None,
                new_leaf: Some(previous_leaf.clone()),
                path: path.clone(),
            },
        )
        .unwrap();

        let input = TxIn {
            previous_output: previous_outpoint,
            ..TxIn::default()
        };
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![
                TxOut {
                    asset: Asset::Explicit(asset),
                    value: Value::Explicit(90),
                    nonce: Nonce::Null,
                    script_pubkey: Script::from(vec![0x51, 0x51]),
                    witness: Default::default(),
                },
                TxOut {
                    asset: Asset::Explicit(asset),
                    value: Value::Explicit(10),
                    nonce: Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: Default::default(),
                },
            ],
        };
        let created_outpoint = OutPoint::new(transaction.txid(), 0);
        let created_leaf = ElementsUtxoLeafV2 {
            outpoint: created_outpoint,
            output: transaction.output[0].clone(),
            creation_height: 5,
            creation_parent_mtp: 50,
            coinbase: false,
            created_by_issuance: false,
            created_by_pegin: false,
        };
        let witness = ElementsTransactionUtxoWitnessV2 {
            spends: vec![ElementsSparseUtxoMutationV2 {
                outpoint: previous_outpoint,
                old_leaf: Some(previous_leaf),
                new_leaf: None,
                path: path.clone(),
            }],
            creates: vec![ElementsSparseUtxoMutationV2 {
                outpoint: created_outpoint,
                old_leaf: None,
                new_leaf: Some(created_leaf.clone()),
                path: path.clone(),
            }],
        };
        let expected_root =
            apply_elements_sparse_utxo_mutation_v2(empty_root, &witness.creates[0]).unwrap();
        let context = ElementsTransactionSpendContextV2 {
            height: 5,
            parent_mtp: 50,
        };
        assert_eq!(
            apply_elements_transaction_utxos_v2(
                &transaction,
                context,
                initial_root,
                &witness,
                &ElementsTransactionKernelWitnessV2::Ordinary,
                &TestElementsInputVerifier { reject: false },
                None,
            ),
            Ok(expected_root)
        );

        let mut wrong_provenance = witness.clone();
        wrong_provenance.creates[0]
            .new_leaf
            .as_mut()
            .unwrap()
            .created_by_issuance = true;
        assert_eq!(
            apply_elements_transaction_utxos_v2(
                &transaction,
                context,
                initial_root,
                &wrong_provenance,
                &ElementsTransactionKernelWitnessV2::Ordinary,
                &TestElementsInputVerifier { reject: false },
                None,
            ),
            Err(ElementsStateErrorV2::TransactionWitness)
        );
        assert_eq!(
            apply_elements_transaction_utxos_v2(
                &transaction,
                context,
                initial_root,
                &witness,
                &ElementsTransactionKernelWitnessV2::Issuance,
                &TestElementsInputVerifier { reject: false },
                None,
            ),
            Err(ElementsStateErrorV2::TransactionWitness)
        );
        assert_eq!(
            apply_elements_transaction_utxos_v2(
                &transaction,
                context,
                initial_root,
                &witness,
                &ElementsTransactionKernelWitnessV2::Ordinary,
                &TestElementsInputVerifier { reject: true },
                None,
            ),
            Err(ElementsStateErrorV2::AuthorizationConsensus)
        );

        let mut incorrectly_inserted_fee = witness;
        incorrectly_inserted_fee
            .creates
            .push(ElementsSparseUtxoMutationV2 {
                outpoint: OutPoint::new(transaction.txid(), 1),
                old_leaf: None,
                new_leaf: Some(ElementsUtxoLeafV2 {
                    outpoint: OutPoint::new(transaction.txid(), 1),
                    output: transaction.output[1].clone(),
                    creation_height: 5,
                    creation_parent_mtp: 50,
                    coinbase: false,
                    created_by_issuance: false,
                    created_by_pegin: false,
                }),
                path,
            });
        assert_eq!(
            apply_elements_transaction_utxos_v2(
                &transaction,
                context,
                initial_root,
                &incorrectly_inserted_fee,
                &ElementsTransactionKernelWitnessV2::Ordinary,
                &TestElementsInputVerifier { reject: false },
                None,
            ),
            Err(ElementsStateErrorV2::TransactionWitness)
        );
    }

    #[test]
    fn initial_issuance_derives_asset_and_balances_while_reissuance_rejects() {
        let policy = AssetId::from_slice(&[11; 32]).unwrap();
        let previous = TxOut {
            asset: Asset::Explicit(policy),
            value: Value::Explicit(100),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let mut input = TxIn::default();
        input.asset_issuance.asset_entropy = [12; 32];
        input.asset_issuance.amount = Value::Explicit(1_000);
        let issued_asset = input.issuance_ids().0;
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![
                TxOut {
                    asset: Asset::Explicit(issued_asset),
                    value: Value::Explicit(1_000),
                    nonce: Nonce::Null,
                    script_pubkey: Script::from(vec![0x51, 0x52]),
                    witness: Default::default(),
                },
                TxOut {
                    value: Value::Explicit(90),
                    ..previous.clone()
                },
                TxOut {
                    asset: Asset::Explicit(policy),
                    value: Value::Explicit(10),
                    nonce: Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: Default::default(),
                },
            ],
        };
        verify_elements_transaction_with_initial_issuance_v2(
            &transaction,
            std::slice::from_ref(&previous),
        )
        .unwrap();

        transaction.output[0].value = Value::Explicit(999);
        assert_eq!(
            verify_elements_transaction_with_initial_issuance_v2(
                &transaction,
                std::slice::from_ref(&previous),
            ),
            Err(ElementsStateErrorV2::ConfidentialConsensus)
        );
        transaction.output[0].value = Value::Explicit(1_000);
        transaction.input[0].asset_issuance.asset_blinding_nonce =
            elements::secp256k1_zkp::Tweak::from_slice(&[1; 32]).unwrap();
        assert_eq!(
            verify_elements_transaction_with_initial_issuance_v2(&transaction, &[previous]),
            Err(ElementsStateErrorV2::UnsupportedValueSource)
        );
    }

    #[test]
    fn explicit_v3_reissuance_is_not_supported_by_legacy_custody_kernel() {
        // Reproduction of the V3 controller's public authority shape, not
        // covenant/script authorization. Preserve legacy rejection until a
        // separately committed rule explicitly selects the new amount path.
        let mut input = TxIn::default();
        input.previous_output = elements::OutPoint {
            txid: elements::Txid::from_slice(&[19; 32]).unwrap(), vout: 0,
        };
        input.asset_issuance.asset_entropy = [21; 32];
        let mut marker = [0u8; 32];
        marker[0] = 1;
        input.asset_issuance.asset_blinding_nonce =
            elements::secp256k1_zkp::Tweak::from_slice(&marker).unwrap();
        input.asset_issuance.amount = Value::Explicit(1_000);
        let (asset, token) = input.issuance_ids();
        let output = |asset, value| TxOut {
            asset: Asset::Explicit(asset), value: Value::Explicit(value),
            nonce: Nonce::Null, script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let previous = output(token, 1);
        let transaction = Transaction { version: 3, lock_time: LockTime::ZERO,
            input: vec![input], output: vec![output(asset, 1_000), output(token, 1)] };
        let raw = elements::encode::serialize(&transaction);
        let decoded: Transaction = elements::encode::deserialize(&raw).unwrap();
        assert_eq!(verify_elements_transaction_with_issuance_v2(&decoded, &[previous.clone()]),
            Err(ElementsStateErrorV2::ReissuanceAuthorization));
        let check = |tx: &Transaction, prev: &TxOut| {
            verify_elements_transaction_with_issuance_rules_v3(
                tx, &[prev.clone()], ElementsReissuanceRulesV3::ExplicitV1)
        };
        assert_eq!(check(&decoded, &previous), Ok(()));
        let mut wrong = decoded.clone();
        wrong.version = 2;
        assert_eq!(check(&wrong, &previous), Err(ElementsStateErrorV2::ReissuanceAuthorization));
        wrong.version = 4;
        assert_eq!(check(&wrong, &previous), Err(ElementsStateErrorV2::ReissuanceAuthorization));
        let mut wrong = decoded.clone();
        wrong.input[0].asset_issuance.asset_blinding_nonce =
            elements::secp256k1_zkp::Tweak::from_slice(&[2; 32]).unwrap();
        assert_eq!(check(&wrong, &previous), Err(ElementsStateErrorV2::ReissuanceAuthorization));
        let mut wrong_previous = previous.clone();
        wrong_previous.asset = Asset::Explicit(asset);
        assert_eq!(check(&decoded, &wrong_previous), Err(ElementsStateErrorV2::ReissuanceAuthorization));
        let mut wrong = decoded.clone();
        wrong.input[0].asset_issuance.inflation_keys = Value::Explicit(1);
        assert_eq!(check(&wrong, &previous), Err(ElementsStateErrorV2::ReissuanceAuthorization));
        let mut wrong = decoded.clone();
        wrong.output[0].value = Value::Explicit(1_001);
        assert_eq!(check(&wrong, &previous), Err(ElementsStateErrorV2::ConfidentialConsensus));
        let mut wrong = decoded.clone();
        wrong.output[1].value = Value::Explicit(2);
        assert_eq!(check(&wrong, &previous), Err(ElementsStateErrorV2::ConfidentialConsensus));
    }

    #[test]
    fn reissuance_requires_exact_authenticated_blinded_token_prevout() {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let entropy = [21; 32];
        let token_blinder = AssetBlindingFactor::from_slice(&[22; 32]).unwrap();
        let mut input = TxIn::default();
        input.asset_issuance.asset_entropy = entropy;
        input.asset_issuance.asset_blinding_nonce = token_blinder.into_inner();
        input.asset_issuance.amount = Value::Explicit(1_000);
        let (issued_asset, token_asset) = input.issuance_ids();
        let token_input_secrets =
            TxOutSecrets::new(token_asset, token_blinder, 1, ValueBlindingFactor::zero());
        let issuance_pseudo_input = TxOutSecrets::new(
            issued_asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        );
        let token_output_abf = AssetBlindingFactor::from_slice(&[24; 32]).unwrap();
        let token_output_vbf = ValueBlindingFactor::last(
            &secp,
            1,
            token_output_abf,
            &[token_input_secrets.value_blind_inputs()],
            &[],
        );
        let token_output_secrets =
            TxOutSecrets::new(token_asset, token_output_abf, 1, token_output_vbf);
        let previous_token = TxOut {
            asset: Asset::new_confidential(&secp, token_asset, token_blinder),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let receiver_secret = SecretKey::new(&mut rng);
        let ephemeral_secret = SecretKey::new(&mut rng);
        let token_output = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            Script::from(vec![0x51, 0x53]),
            PublicKey::from_secret_key(&secp, &receiver_secret),
            ephemeral_secret,
            token_output_secrets,
            &[token_input_secrets, issuance_pseudo_input],
        )
        .unwrap();
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![
                TxOut {
                    asset: Asset::Explicit(issued_asset),
                    value: Value::Explicit(1_000),
                    nonce: Nonce::Null,
                    script_pubkey: Script::from(vec![0x51, 0x54]),
                    witness: Default::default(),
                },
                token_output,
            ],
        };
        verify_elements_transaction_with_issuance_v2(
            &transaction,
            std::slice::from_ref(&previous_token),
        )
        .unwrap();

        let mut substituted = previous_token.clone();
        substituted.asset = Asset::new_confidential(
            &secp,
            token_asset,
            AssetBlindingFactor::from_slice(&[23; 32]).unwrap(),
        );
        assert_eq!(
            verify_elements_transaction_with_issuance_v2(&transaction, &[substituted]),
            Err(ElementsStateErrorV2::ReissuanceAuthorization)
        );
        transaction.input[0].asset_issuance.inflation_keys = Value::Explicit(1);
        assert_eq!(
            verify_elements_transaction_with_issuance_v2(&transaction, &[previous_token]),
            Err(ElementsStateErrorV2::ReissuanceAuthorization)
        );
    }

    #[test]
    fn drivechain_deposit_requires_recursive_statement_and_exact_elements_credit() {
        let asset = AssetId::from_slice(&[31; 32]).unwrap();
        let mainchain_txid =
            Txid::from_str("2020202020202020202020202020202020202020202020202020202020202020")
                .unwrap();
        let mut input = TxIn {
            previous_output: OutPoint::new(mainchain_txid, 3),
            is_pegin: true,
            ..TxIn::default()
        };
        input.witness.pegin_witness = vec![b"exact-network-bound-drivechain-evidence".to_vec()];
        let witness_hash = crate::sha256_bytes(&serialize(&input.witness.pegin_witness));
        let statement = DrivechainDepositStatementV2 {
            version: 1,
            mainchain_genesis: [1; 32],
            sidechain_genesis: [2; 32],
            sidechain_slot: 24,
            sidechain_address_profile: 1,
            pegged_asset: [31; 32],
            mainchain_txid: mainchain_txid.to_byte_array(),
            mainchain_vout: 3,
            value_atoms: 1_000,
            destination_script: vec![0x51, 0x61],
            prior_ctip_txid: [3; 32],
            prior_ctip_vout: 0,
            prior_ctip_value_atoms: 9_000,
            prior_sequence: 7,
            next_ctip_value_atoms: 10_000,
            next_sequence: 8,
            authenticated_parent_anchor: [4; 32],
            prior_bip300_state_commitment: [5; 32],
            deposit_block_bip300_state_commitment: [6; 32],
            next_bip300_state_commitment: [6; 32],
            bitcoin_consensus_parameters_commitment: [7; 32],
            prior_bitcoin_utxo_root: SparseUtxoNodeV2 {
                hash: [8; 32],
                aggregate: Default::default(),
            },
            next_bitcoin_utxo_root: SparseUtxoNodeV2 {
                hash: [9; 32],
                aggregate: Default::default(),
            },
            pegin_witness_sha256: witness_hash,
        };
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![
                TxOut {
                    asset: Asset::Explicit(asset),
                    value: Value::Explicit(990),
                    nonce: Nonce::Null,
                    script_pubkey: Script::from(statement.destination_script.clone()),
                    witness: Default::default(),
                },
                TxOut {
                    asset: Asset::Explicit(asset),
                    value: Value::Explicit(10),
                    nonce: Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: Default::default(),
                },
            ],
        };
        let verifier = ExactTestDepositVerifier {
            expected: statement.clone(),
        };
        verify_drivechain_deposit_elements_transaction_v2(&transaction, &statement, &verifier)
            .unwrap();

        transaction.output[0].value = Value::Explicit(989);
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(&transaction, &statement, &verifier,),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );
        transaction.output[0].value = Value::Explicit(990);
        let mut substituted = statement.clone();
        substituted.authenticated_parent_anchor[0] ^= 1;
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(
                &transaction,
                &substituted,
                &verifier,
            ),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );
    }

    #[test]
    fn concrete_bitcoin_deposit_verifier_derives_ctip_and_network_bound_statement() {
        use crate::bip300_v2::{Bip300ActiveSlotV2, Bip300CtipV2};
        use crate::script_v2::{
            SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2,
            SCRIPT_VERIFY_DERSIG_V2, SCRIPT_VERIFY_NULLDUMMY_V2, SCRIPT_VERIFY_P2SH_V2,
            SCRIPT_VERIFY_TAPROOT_V2, SCRIPT_VERIFY_WITNESS_V2,
        };
        use crate::{
            apply_sparse_utxo_mutation_v2, bitcoin_utxo_leaf_node_v2, canonical_empty_utxo_leaf_v2,
            sparse_utxo_key_v2, sparse_utxo_parent_v2, BitcoinTransactionUtxoWitnessV2,
            BitcoinUtxoLeafV2, SparseUtxoMutationV2, SparseUtxoPathV2, SPARSE_UTXO_DEPTH_V2,
        };
        use bitcoin::absolute;
        use bitcoin::block::{Header, Version as BlockVersion};
        use bitcoin::hashes::Hash as _;
        use bitcoin::opcodes::all::OP_RETURN;
        use bitcoin::pow::{CompactTarget, Target};
        use bitcoin::script::Builder;
        use bitcoin::transaction::Version as BitcoinTxVersion;
        use bitcoin::{
            Amount as BitcoinAmount, Block, BlockHash, OutPoint as BitcoinOutPoint,
            ScriptBuf as BitcoinScript, Sequence, Transaction as BitcoinTransaction,
            TxIn as BitcoinTxIn, TxMerkleNode, TxOut as BitcoinTxOut, Txid as BitcoinTxid, Witness,
        };

        fn empty_utxo_tree() -> (SparseUtxoNodeV2, SparseUtxoPathV2) {
            let mut node = canonical_empty_utxo_leaf_v2();
            let mut siblings = Vec::with_capacity(SPARSE_UTXO_DEPTH_V2);
            for _ in 0..SPARSE_UTXO_DEPTH_V2 {
                siblings.push(node);
                node = sparse_utxo_parent_v2(node, node).unwrap();
            }
            (node, SparseUtxoPathV2 { siblings })
        }

        fn key_bit(key: [u8; 32], leaf_level: usize) -> bool {
            let root_bit = SPARSE_UTXO_DEPTH_V2 - 1 - leaf_level;
            let byte = root_bit / 8;
            let bit_in_byte = 7 - (root_bit % 8);
            (key[byte] >> bit_in_byte) & 1 == 1
        }

        fn path_against_single(
            target: BitcoinOutPoint,
            existing: &BitcoinUtxoLeafV2,
        ) -> SparseUtxoPathV2 {
            let target_key = sparse_utxo_key_v2(target);
            let existing_key = sparse_utxo_key_v2(existing.outpoint);
            let divergence_level = (0..SPARSE_UTXO_DEPTH_V2)
                .filter(|level| key_bit(target_key, *level) != key_bit(existing_key, *level))
                .max()
                .expect("distinct outpoints must have distinct sparse keys");
            let mut existing_node = bitcoin_utxo_leaf_node_v2(existing).unwrap();
            let mut empty_node = canonical_empty_utxo_leaf_v2();
            let mut siblings = Vec::with_capacity(SPARSE_UTXO_DEPTH_V2);
            for level in 0..SPARSE_UTXO_DEPTH_V2 {
                if level == divergence_level {
                    siblings.push(existing_node);
                } else {
                    siblings.push(empty_node);
                }
                existing_node = if key_bit(existing_key, level) {
                    sparse_utxo_parent_v2(empty_node, existing_node).unwrap()
                } else {
                    sparse_utxo_parent_v2(existing_node, empty_node).unwrap()
                };
                empty_node = sparse_utxo_parent_v2(empty_node, empty_node).unwrap();
            }
            SparseUtxoPathV2 { siblings }
        }

        let bits = CompactTarget::from_consensus(0x207fffff);
        let previous_header = Header {
            version: BlockVersion::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 0,
        };
        let prior_outpoint = BitcoinOutPoint {
            txid: BitcoinTxid::from_byte_array([41; 32]),
            vout: 0,
        };
        let funding_outpoint = BitcoinOutPoint {
            txid: BitcoinTxid::from_byte_array([45; 32]),
            vout: 0,
        };
        let address_text = "ert1q9263y9nqf2kwjl7hrhsgewefq7859w93z5n8x8";
        let address = elements::Address::from_str(address_text).unwrap();
        let coinbase = BitcoinTransaction {
            version: BitcoinTxVersion::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![BitcoinTxIn {
                previous_output: BitcoinOutPoint::null(),
                script_sig: BitcoinScript::from_bytes(vec![0x51, 0]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![BitcoinTxOut {
                value: BitcoinAmount::ZERO,
                script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
            }],
        };
        let address_push =
            bitcoin::script::PushBytesBuf::try_from(address_text.as_bytes().to_vec()).unwrap();
        let deposit_tx = BitcoinTransaction {
            version: BitcoinTxVersion::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                BitcoinTxIn {
                    previous_output: prior_outpoint,
                    script_sig: BitcoinScript::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                BitcoinTxIn {
                    previous_output: funding_outpoint,
                    script_sig: BitcoinScript::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![
                BitcoinTxOut {
                    value: BitcoinAmount::from_sat(10_000),
                    script_pubkey: BitcoinScript::from_bytes(vec![0xb4, 1, 24, 0x51]),
                },
                BitcoinTxOut {
                    value: BitcoinAmount::ZERO,
                    script_pubkey: Builder::new()
                        .push_opcode(OP_RETURN)
                        .push_slice(address_push)
                        .into_script(),
                },
            ],
        };
        let deposit_txid = deposit_tx.compute_txid();
        let prior_leaf = BitcoinUtxoLeafV2 {
            outpoint: prior_outpoint,
            output: BitcoinTxOut {
                value: BitcoinAmount::from_sat(9_000),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
            creation_height: 0,
            creation_parent_mtp: 0,
            coinbase: false,
        };
        let funding_leaf = BitcoinUtxoLeafV2 {
            outpoint: funding_outpoint,
            output: BitcoinTxOut {
                value: BitcoinAmount::from_sat(1_000),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
            creation_height: 0,
            creation_parent_mtp: 0,
            coinbase: false,
        };
        let (empty_root, bitcoin_empty_path) = empty_utxo_tree();
        let prior_insert = SparseUtxoMutationV2 {
            outpoint: prior_outpoint,
            old_leaf: None,
            new_leaf: Some(prior_leaf.clone()),
            path: bitcoin_empty_path.clone(),
        };
        let prior_only_root = apply_sparse_utxo_mutation_v2(empty_root, &prior_insert).unwrap();
        let funding_insert = SparseUtxoMutationV2 {
            outpoint: funding_outpoint,
            old_leaf: None,
            new_leaf: Some(funding_leaf.clone()),
            path: path_against_single(funding_outpoint, &prior_leaf),
        };
        let prior_bitcoin_utxo_root =
            apply_sparse_utxo_mutation_v2(prior_only_root, &funding_insert).unwrap();
        let mut block = Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: previous_header.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 2,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase, deposit_tx.clone()],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        while block.header.validate_pow(target).is_err() {
            block.header.nonce += 1;
        }

        let mut prior_state = Bip300AllSlotStateV2::before_genesis(
            BlockHash::from_byte_array([1; 32]),
            crate::bip300_v2::BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2,
        )
        .unwrap();
        prior_state.next_height = 1;
        prior_state.tip_hash = Some(previous_header.block_hash());
        prior_state.active_slots.insert(
            24,
            Bip300ActiveSlotV2 {
                proposal_hash: [42; 32],
                activation_height: 0,
                ctip: Some(Bip300CtipV2 {
                    outpoint: prior_outpoint,
                    value_sat: 9_000,
                    sequence: 7,
                }),
                next_treasury_sequence: 8,
                pending_m6ids: vec![],
            },
        );
        let (next_state, _) = apply_bip300_block_v2(&prior_state, &block).unwrap();
        let child_coinbase = BitcoinTransaction {
            version: BitcoinTxVersion::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![BitcoinTxIn {
                previous_output: BitcoinOutPoint::null(),
                script_sig: BitcoinScript::from_bytes(vec![0x52, 0]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![BitcoinTxOut {
                value: BitcoinAmount::ZERO,
                script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
            }],
        };
        let mut confirmation = Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: block.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 3,
                bits,
                nonce: 0,
            },
            txdata: vec![child_coinbase],
        };
        confirmation.header.merkle_root = confirmation.compute_merkle_root().unwrap();
        while confirmation.header.validate_pow(target).is_err() {
            confirmation.header.nonce += 1;
        }
        let (anchor_state, _) = apply_bip300_block_v2(&next_state, &confirmation).unwrap();
        let pegged_asset = [43; 32];
        let consensus_parameters = BitcoinConsensusExecutionParametersV2 {
            version: 1,
            bip34_active: true,
            bip68_active: true,
            active_script_flags: SCRIPT_VERIFY_P2SH_V2
                | SCRIPT_VERIFY_DERSIG_V2
                | SCRIPT_VERIFY_NULLDUMMY_V2
                | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY_V2
                | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY_V2
                | SCRIPT_VERIFY_WITNESS_V2
                | SCRIPT_VERIFY_TAPROOT_V2,
        };
        let created_outpoint = BitcoinOutPoint {
            txid: deposit_txid,
            vout: 0,
        };
        let created_leaf = BitcoinUtxoLeafV2 {
            outpoint: created_outpoint,
            output: deposit_tx.output[0].clone(),
            creation_height: 1,
            creation_parent_mtp: 1,
            coinbase: false,
        };
        let deposit_utxo_witness = BitcoinBlockUtxoWitnessV2 {
            transactions: vec![
                BitcoinTransactionUtxoWitnessV2 {
                    spends: vec![],
                    creates: vec![],
                },
                BitcoinTransactionUtxoWitnessV2 {
                    spends: vec![
                        SparseUtxoMutationV2 {
                            outpoint: prior_outpoint,
                            old_leaf: Some(prior_leaf.clone()),
                            new_leaf: None,
                            path: path_against_single(prior_outpoint, &funding_leaf),
                        },
                        SparseUtxoMutationV2 {
                            outpoint: funding_outpoint,
                            old_leaf: Some(funding_leaf.clone()),
                            new_leaf: None,
                            path: bitcoin_empty_path.clone(),
                        },
                    ],
                    creates: vec![SparseUtxoMutationV2 {
                        outpoint: created_outpoint,
                        old_leaf: None,
                        new_leaf: Some(created_leaf.clone()),
                        path: bitcoin_empty_path.clone(),
                    }],
                },
            ],
        };
        let next_bitcoin_utxo_root = apply_sparse_utxo_mutation_v2(
            empty_root,
            &deposit_utxo_witness.transactions[1].creates[0],
        )
        .unwrap();
        let pegin_witness = vec![b"exact-concrete-deposit-evidence".to_vec()];
        let witness_hash = crate::sha256_bytes(&serialize(&pegin_witness));
        let statement = DrivechainDepositStatementV2 {
            version: 1,
            mainchain_genesis: [1; 32],
            sidechain_genesis: [44; 32],
            sidechain_slot: 24,
            sidechain_address_profile: 1,
            pegged_asset,
            mainchain_txid: deposit_txid.to_byte_array(),
            mainchain_vout: 0,
            value_atoms: 1_000,
            destination_script: address.script_pubkey().into_bytes(),
            prior_ctip_txid: prior_outpoint.txid.to_byte_array(),
            prior_ctip_vout: 0,
            prior_ctip_value_atoms: 9_000,
            prior_sequence: 7,
            next_ctip_value_atoms: 10_000,
            next_sequence: 8,
            authenticated_parent_anchor: confirmation.block_hash().to_byte_array(),
            prior_bip300_state_commitment: prior_state.commitment().unwrap(),
            deposit_block_bip300_state_commitment: next_state.commitment().unwrap(),
            next_bip300_state_commitment: anchor_state.commitment().unwrap(),
            bitcoin_consensus_parameters_commitment: consensus_parameters.commitment().unwrap(),
            prior_bitcoin_utxo_root,
            next_bitcoin_utxo_root,
            pegin_witness_sha256: witness_hash,
        };
        let verifier = FullBitcoinDrivechainDepositVerifierV2 {
            evidence: FullBitcoinDrivechainDepositEvidenceV2 {
                raw_deposit_block: bitcoin::consensus::serialize(&block),
                pow_context: BitcoinPowContextV2 {
                    previous_height: 0,
                    previous_header,
                    previous_11_times: vec![1; 11],
                    retarget_epoch_start_time: 1,
                },
                authenticated_adjusted_time: 2,
                prior_bip300_state: prior_state,
                consensus_parameters,
                prior_bitcoin_utxo_root,
                deposit_utxo_witness,
                confirmation_blocks: vec![FullBitcoinBlockEvidenceStepV2 {
                    raw_block: bitcoin::consensus::serialize(&confirmation),
                    pow_context: BitcoinPowContextV2 {
                        previous_height: 1,
                        previous_header: block.header,
                        previous_11_times: {
                            let mut times = vec![1; 10];
                            times.push(2);
                            times
                        },
                        retarget_epoch_start_time: 1,
                    },
                    authenticated_adjusted_time: 3,
                    utxo_witness: BitcoinBlockUtxoWitnessV2 {
                        transactions: vec![BitcoinTransactionUtxoWitnessV2 {
                            spends: vec![],
                            creates: vec![],
                        }],
                    },
                }],
            },
            sidechain_genesis: [44; 32],
            pegged_asset,
            sidechain_address_profile: 1,
        };
        let elements_asset = AssetId::from_slice(&pegged_asset).unwrap();
        let mut elements_input = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(deposit_txid.to_byte_array()), 0),
            is_pegin: true,
            ..TxIn::default()
        };
        elements_input.witness.pegin_witness = pegin_witness;
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![elements_input],
            output: vec![TxOut {
                asset: Asset::Explicit(elements_asset),
                value: Value::Explicit(1_000),
                nonce: Nonce::Null,
                script_pubkey: address.script_pubkey(),
                witness: Default::default(),
            }],
        };
        let deposit_step = FullBitcoinBlockEvidenceStepV2 {
            raw_block: verifier.evidence.raw_deposit_block.clone(),
            pow_context: verifier.evidence.pow_context.clone(),
            authenticated_adjusted_time: verifier.evidence.authenticated_adjusted_time,
            utxo_witness: verifier.evidence.deposit_utxo_witness.clone(),
        };
        apply_bitcoin_block_utxos_v2(
            &block,
            BitcoinBlockSpendContextV2 {
                height: 1,
                previous_block_mtp: 1,
                bip34_active: true,
                bip68_active: true,
            },
            prior_bitcoin_utxo_root,
            &deposit_step.utxo_witness,
            consensus_parameters.active_script_flags,
            &FullBitcoinScriptVerifierV2,
        )
        .unwrap();
        let (_, deposit_root) = verify_full_bitcoin_block_step_v2(
            &deposit_step,
            verifier.evidence.prior_bip300_state.network_genesis,
            1,
            prior_bitcoin_utxo_root,
            consensus_parameters,
        )
        .unwrap();
        let (_, confirmation_root) = verify_full_bitcoin_block_step_v2(
            &verifier.evidence.confirmation_blocks[0],
            verifier.evidence.prior_bip300_state.network_genesis,
            2,
            deposit_root,
            consensus_parameters,
        )
        .unwrap();
        assert_eq!(confirmation_root, next_bitcoin_utxo_root);
        verify_drivechain_deposit_elements_transaction_v2(&transaction, &statement, &verifier)
            .unwrap();
        let elements_path = empty_path();
        let elements_outpoint = OutPoint::new(transaction.txid(), 0);
        let empty_elements_root = elements_sparse_utxo_root_from_path_v2(
            elements_outpoint,
            canonical_empty_elements_utxo_leaf_v2(),
            &elements_path,
        )
        .unwrap();
        let elements_deposit_witness = ElementsTransactionUtxoWitnessV2 {
            spends: vec![],
            creates: vec![ElementsSparseUtxoMutationV2 {
                outpoint: elements_outpoint,
                old_leaf: None,
                new_leaf: Some(ElementsUtxoLeafV2 {
                    outpoint: elements_outpoint,
                    output: transaction.output[0].clone(),
                    creation_height: 9,
                    creation_parent_mtp: 90,
                    coinbase: false,
                    created_by_issuance: false,
                    created_by_pegin: true,
                }),
                path: elements_path,
            }],
        };
        let expected_elements_root = apply_elements_sparse_utxo_mutation_v2(
            empty_elements_root,
            &elements_deposit_witness.creates[0],
        )
        .unwrap();
        assert_eq!(
            apply_elements_transaction_utxos_v2(
                &transaction,
                ElementsTransactionSpendContextV2 {
                    height: 9,
                    parent_mtp: 90,
                },
                empty_elements_root,
                &elements_deposit_witness,
                &ElementsTransactionKernelWitnessV2::DrivechainDeposit(
                    Box::new(statement.clone(),)
                ),
                &TestElementsInputVerifier { reject: true },
                Some(&verifier),
            ),
            Ok(expected_elements_root)
        );

        let mut wrong_network = statement.clone();
        wrong_network.mainchain_genesis[0] ^= 1;
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(
                &transaction,
                &wrong_network,
                &verifier,
            ),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );
        let mut broken_confirmation = verifier.clone();
        broken_confirmation.evidence.confirmation_blocks[0]
            .pow_context
            .previous_height = 0;
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(
                &transaction,
                &statement,
                &broken_confirmation,
            ),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );

        let mut wrong_utxo_root = statement.clone();
        wrong_utxo_root.next_bitcoin_utxo_root.hash[0] ^= 1;
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(
                &transaction,
                &wrong_utxo_root,
                &verifier,
            ),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );

        let mut wrong_profile = verifier.clone();
        wrong_profile
            .evidence
            .consensus_parameters
            .active_script_flags ^= SCRIPT_VERIFY_TAPROOT_V2;
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(
                &transaction,
                &statement,
                &wrong_profile,
            ),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );

        let mut altered_time_provenance = verifier.clone();
        altered_time_provenance
            .evidence
            .deposit_utxo_witness
            .transactions[1]
            .spends[0]
            .old_leaf
            .as_mut()
            .unwrap()
            .creation_parent_mtp += 1;
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(
                &transaction,
                &statement,
                &altered_time_provenance,
            ),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );

        let mut missing_confirmation_utxo = verifier.clone();
        missing_confirmation_utxo.evidence.confirmation_blocks[0]
            .utxo_witness
            .transactions
            .clear();
        assert_eq!(
            verify_drivechain_deposit_elements_transaction_v2(
                &transaction,
                &statement,
                &missing_confirmation_utxo,
            ),
            Err(ElementsStateErrorV2::DrivechainDeposit)
        );
    }
}
