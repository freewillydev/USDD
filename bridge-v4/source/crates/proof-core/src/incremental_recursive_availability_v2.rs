//! Compact availability boundary for recursively verified successor classes.
//!
//! The outer successor carries only fixed child public values, deferred-proof
//! markers, bundle roots and custody receipts. Full child witnesses remain in
//! independently recoverable encrypted bundles addressed by those roots.

use std::collections::BTreeSet;

use ecx_truthcoin_proof::{
    sp1_deferred_proof_marker, ConsensusProofVerificationError, ConsensusProofVerifier,
};
use ecx_witness_availability::{
    custodian_registry_hash, verify_custody_receipts_compact, CustodianPublic, CustodyReceiptV1,
    CUSTODY_RECEIPT_CANONICAL_LEN, RECOVERY_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::Hash32;

pub const INCREMENTAL_CHILD_AVAILABILITY_VERSION_V2: u8 = 7;
pub const INCREMENTAL_CHILD_CLASS_COUNT_V2: usize = 12;
pub const MAX_INCREMENTAL_CHILD_PUBLIC_VALUES_BYTES_V2: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum IncrementalChildClassV2 {
    Trader = 0,
    Deficit = 1,
    Risk = 2,
    Order = 3,
    Nullifiers = 4,
    FundingOracle = 5,
    Settlement = 6,
    InboxSource = 7,
    BondActions = 8,
    EconomicActions = 9,
    AccountActions = 10,
    ForcedActions = 11,
}

impl IncrementalChildClassV2 {
    const ALL: [Self; INCREMENTAL_CHILD_CLASS_COUNT_V2] = [
        Self::Trader,
        Self::Deficit,
        Self::Risk,
        Self::Order,
        Self::Nullifiers,
        Self::FundingOracle,
        Self::Settlement,
        Self::InboxSource,
        Self::BondActions,
        Self::EconomicActions,
        Self::AccountActions,
        Self::ForcedActions,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// Return the executable reachable-input ceiling for one recursively recovered
/// child class.  The class order is consensus-significant and matches the
/// twelve-entry matrices in `incremental_recovery_budget_v2`.
pub fn incremental_child_witness_ceiling_v2(
    class: IncrementalChildClassV2,
) -> Result<u64, IncrementalChildAvailabilityErrorV2> {
    let index = class.index();
    let reachable = crate::INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2[index]
        .ok_or(IncrementalChildAvailabilityErrorV2::InvalidShape)?;
    let decoder = crate::INCREMENTAL_CHILD_INPUT_CEILINGS_V2[index];
    if reachable == 0
        || reachable >= decoder
        || decoder > ecx_witness_availability::MAX_WITNESS_BYTES
    {
        return Err(IncrementalChildAvailabilityErrorV2::InvalidShape);
    }
    u64::try_from(reachable).map_err(|_| IncrementalChildAvailabilityErrorV2::InvalidShape)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalCustodianPublicV2 {
    pub index: u8,
    pub encryption_public_key: Hash32,
    pub attestation_public_key: Hash32,
}

impl From<IncrementalCustodianPublicV2> for CustodianPublic {
    fn from(value: IncrementalCustodianPublicV2) -> Self {
        Self {
            index: value.index,
            encryption_public_key: value.encryption_public_key,
            attestation_public_key: value.attestation_public_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalChildAvailabilityV2 {
    pub version: u8,
    pub class: IncrementalChildClassV2,
    pub program_id: Hash32,
    pub public_values: Vec<u8>,
    pub proof_marker: Hash32,
    pub bundle_root: Hash32,
    pub bundle_context: Hash32,
    pub child_witness_len: u64,
    pub custody_receipts: Vec<CustodyReceiptV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalChildAvailabilityErrorV2 {
    #[error("invalid recursive child shape")]
    InvalidShape,
    #[error("recursive child proof is not authenticated")]
    InvalidProof,
    #[error("recursive child availability is not authenticated")]
    InvalidAvailability,
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn incremental_child_bundle_context_v2(
    class: IncrementalChildClassV2,
    program_id: Hash32,
    public_values: &[u8],
    proof_marker: Hash32,
    custodian_registry_hash: Hash32,
) -> Result<Hash32, IncrementalChildAvailabilityErrorV2> {
    if program_id == [0; 32]
        || proof_marker == [0; 32]
        || custodian_registry_hash == [0; 32]
        || public_values.is_empty()
        || public_values.len() > MAX_INCREMENTAL_CHILD_PUBLIC_VALUES_BYTES_V2
    {
        return Err(IncrementalChildAvailabilityErrorV2::InvalidShape);
    }
    let mut bytes = Vec::with_capacity(102 + public_values.len());
    bytes.push(INCREMENTAL_CHILD_AVAILABILITY_VERSION_V2);
    bytes.push(class as u8);
    bytes.extend_from_slice(&program_id);
    bytes.extend_from_slice(&(public_values.len() as u32).to_be_bytes());
    bytes.extend_from_slice(public_values);
    bytes.extend_from_slice(&proof_marker);
    bytes.extend_from_slice(&custodian_registry_hash);
    Ok(tagged_hash(
        b"ECX/incremental-child-bundle-context/v7-forced-action-composition",
        &bytes,
    ))
}

fn compact_descriptor_bytes(
    descriptor: &IncrementalChildAvailabilityV2,
) -> Result<Vec<u8>, IncrementalChildAvailabilityErrorV2> {
    let mut out = Vec::with_capacity(
        143 + descriptor.public_values.len()
            + descriptor.custody_receipts.len() * CUSTODY_RECEIPT_CANONICAL_LEN,
    );
    out.push(descriptor.version);
    out.push(descriptor.class as u8);
    out.extend_from_slice(&descriptor.program_id);
    out.extend_from_slice(&(descriptor.public_values.len() as u32).to_be_bytes());
    out.extend_from_slice(&descriptor.public_values);
    out.extend_from_slice(&descriptor.proof_marker);
    out.extend_from_slice(&descriptor.bundle_root);
    out.extend_from_slice(&descriptor.bundle_context);
    out.extend_from_slice(&descriptor.child_witness_len.to_be_bytes());
    out.push(
        u8::try_from(descriptor.custody_receipts.len())
            .map_err(|_| IncrementalChildAvailabilityErrorV2::InvalidShape)?,
    );
    for receipt in &descriptor.custody_receipts {
        out.extend_from_slice(
            &receipt
                .encode_canonical()
                .map_err(|_| IncrementalChildAvailabilityErrorV2::InvalidAvailability)?,
        );
    }
    Ok(out)
}

/// Verify the exact twelve child classes, their deferred proofs, and compact
/// threshold custody statements for independently recoverable witness bundles.
pub fn verify_incremental_child_availability_v2<V: ConsensusProofVerifier>(
    descriptors: &[IncrementalChildAvailabilityV2],
    registry: &[IncrementalCustodianPublicV2],
    expected_registry_hash: Hash32,
    verifier: &V,
) -> Result<Hash32, IncrementalChildAvailabilityErrorV2> {
    if descriptors.len() != INCREMENTAL_CHILD_CLASS_COUNT_V2
        || registry.len() != ecx_witness_availability::CUSTODIAN_COUNT
    {
        return Err(IncrementalChildAvailabilityErrorV2::InvalidShape);
    }
    let registry = registry
        .iter()
        .copied()
        .map(CustodianPublic::from)
        .collect::<Vec<_>>();
    if custodian_registry_hash(&registry)
        .map_err(|_| IncrementalChildAvailabilityErrorV2::InvalidAvailability)?
        != expected_registry_hash
    {
        return Err(IncrementalChildAvailabilityErrorV2::InvalidAvailability);
    }
    let mut program_ids = BTreeSet::new();
    let mut compact = Vec::new();
    for (descriptor, expected_class) in descriptors.iter().zip(IncrementalChildClassV2::ALL) {
        let child_witness_ceiling = incremental_child_witness_ceiling_v2(descriptor.class)?;
        if descriptor.version != INCREMENTAL_CHILD_AVAILABILITY_VERSION_V2
            || descriptor.class != expected_class
            || descriptor.program_id == [0; 32]
            || !program_ids.insert(descriptor.program_id)
            || descriptor.public_values.is_empty()
            || descriptor.public_values.len() > MAX_INCREMENTAL_CHILD_PUBLIC_VALUES_BYTES_V2
            || descriptor.proof_marker
                != sp1_deferred_proof_marker(descriptor.program_id, &descriptor.public_values)
            || descriptor.child_witness_len == 0
            || descriptor.child_witness_len > child_witness_ceiling
            || descriptor.custody_receipts.len() != RECOVERY_THRESHOLD
        {
            return Err(IncrementalChildAvailabilityErrorV2::InvalidShape);
        }
        verifier
            .verify(
                descriptor.program_id,
                &descriptor.public_values,
                &descriptor.proof_marker,
            )
            .map_err(|_: ConsensusProofVerificationError| {
                IncrementalChildAvailabilityErrorV2::InvalidProof
            })?;
        let expected_context = incremental_child_bundle_context_v2(
            descriptor.class,
            descriptor.program_id,
            &descriptor.public_values,
            descriptor.proof_marker,
            expected_registry_hash,
        )?;
        if descriptor.bundle_context != expected_context {
            return Err(IncrementalChildAvailabilityErrorV2::InvalidAvailability);
        }
        verify_custody_receipts_compact(
            descriptor.bundle_root,
            descriptor.bundle_context,
            descriptor.child_witness_len,
            &registry,
            &descriptor.custody_receipts,
        )
        .map_err(|_| IncrementalChildAvailabilityErrorV2::InvalidAvailability)?;
        compact.extend_from_slice(&compact_descriptor_bytes(descriptor)?);
    }
    Ok(tagged_hash(
        b"ECX/incremental-child-availability-root/v3-forced-action-class",
        &compact,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use ecx_truthcoin_proof::ConsensusProofVerificationError;
    use ecx_witness_availability::{create_bundle, custodian_registry_hash, CustodianSecrets};

    use super::*;

    pub(crate) struct MarkerVerifier;

    impl ConsensusProofVerifier for MarkerVerifier {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), ConsensusProofVerificationError> {
            if proof_marker == sp1_deferred_proof_marker(program_id, public_values) {
                Ok(())
            } else {
                Err(ConsensusProofVerificationError)
            }
        }
    }

    pub(crate) fn fixture() -> (
        Vec<IncrementalChildAvailabilityV2>,
        Vec<IncrementalCustodianPublicV2>,
        Hash32,
    ) {
        fixture_with_child_public_values(
            None, None, None, None, None, None, None, None, None, None, None, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fixture_with_child_public_values(
        settlement_public_values: Option<Vec<u8>>,
        inbox_source_public_values: Option<Vec<u8>>,
        trader_public_values: Option<Vec<u8>>,
        deficit_public_values: Option<Vec<u8>>,
        risk_public_values: Option<Vec<u8>>,
        nullifier_public_values: Option<Vec<u8>>,
        order_public_values: Option<Vec<u8>>,
        funding_oracle_public_values: Option<Vec<u8>>,
        bond_action_public_values: Option<Vec<u8>>,
        economic_action_public_values: Option<Vec<u8>>,
        account_action_public_values: Option<Vec<u8>>,
        forced_action_public_values: Option<Vec<u8>>,
    ) -> (
        Vec<IncrementalChildAvailabilityV2>,
        Vec<IncrementalCustodianPublicV2>,
        Hash32,
    ) {
        let secrets = (1..=5)
            .map(|index| CustodianSecrets::generate(index).unwrap())
            .collect::<Vec<_>>();
        let public = secrets
            .iter()
            .map(CustodianSecrets::public)
            .collect::<Vec<_>>();
        let registry_hash = custodian_registry_hash(&public).unwrap();
        let compact_registry = public
            .iter()
            .map(|value| IncrementalCustodianPublicV2 {
                index: value.index,
                encryption_public_key: value.encryption_public_key,
                attestation_public_key: value.attestation_public_key,
            })
            .collect::<Vec<_>>();
        let descriptors = IncrementalChildClassV2::ALL
            .into_iter()
            .enumerate()
            .map(|(index, class)| {
                let program_id = [u8::try_from(index + 1).unwrap(); 32];
                let public_values = match class {
                    IncrementalChildClassV2::Trader => trader_public_values.clone(),
                    IncrementalChildClassV2::Deficit => deficit_public_values.clone(),
                    IncrementalChildClassV2::Risk => risk_public_values.clone(),
                    IncrementalChildClassV2::Nullifiers => nullifier_public_values.clone(),
                    IncrementalChildClassV2::Order => order_public_values.clone(),
                    IncrementalChildClassV2::FundingOracle => funding_oracle_public_values.clone(),
                    IncrementalChildClassV2::Settlement => settlement_public_values.clone(),
                    IncrementalChildClassV2::InboxSource => inbox_source_public_values.clone(),
                    IncrementalChildClassV2::BondActions => bond_action_public_values.clone(),
                    IncrementalChildClassV2::EconomicActions => {
                        economic_action_public_values.clone()
                    }
                    IncrementalChildClassV2::AccountActions => account_action_public_values.clone(),
                    IncrementalChildClassV2::ForcedActions => forced_action_public_values.clone(),
                }
                .unwrap_or_else(|| vec![0xa0 + u8::try_from(index).unwrap(); 64]);
                let proof_marker = sp1_deferred_proof_marker(program_id, &public_values);
                let context = incremental_child_bundle_context_v2(
                    class,
                    program_id,
                    &public_values,
                    proof_marker,
                    registry_hash,
                )
                .unwrap();
                let child_witness = vec![0x40 + u8::try_from(index).unwrap(); 96];
                let bundle = create_bundle(context, &child_witness, &public).unwrap();
                let receipts = secrets[..RECOVERY_THRESHOLD]
                    .iter()
                    .map(|secret| secret.custody_receipt(&bundle).unwrap())
                    .collect();
                IncrementalChildAvailabilityV2 {
                    version: INCREMENTAL_CHILD_AVAILABILITY_VERSION_V2,
                    class,
                    program_id,
                    public_values,
                    proof_marker,
                    bundle_root: bundle.root().unwrap(),
                    bundle_context: context,
                    child_witness_len: bundle.witness_len,
                    custody_receipts: receipts,
                }
            })
            .collect();
        (descriptors, compact_registry, registry_hash)
    }

    #[test]
    fn twelve_recursive_classes_require_exact_proofs_and_compact_custody() {
        let (descriptors, registry, registry_hash) = fixture();
        let root = verify_incremental_child_availability_v2(
            &descriptors,
            &registry,
            registry_hash,
            &MarkerVerifier,
        )
        .unwrap();
        assert_ne!(root, [0; 32]);
        assert!(
            descriptors
                .iter()
                .map(compact_descriptor_bytes)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
                < 32 * 1024
        );
    }

    #[test]
    fn every_child_descriptor_enforces_its_reachable_witness_ceiling() {
        for class in IncrementalChildClassV2::ALL {
            let index = class.index();
            let ceiling = incremental_child_witness_ceiling_v2(class).unwrap();
            assert_eq!(
                ceiling,
                u64::try_from(
                    crate::INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2[index].unwrap()
                )
                .unwrap()
            );
            assert!(
                ceiling < u64::try_from(crate::INCREMENTAL_CHILD_INPUT_CEILINGS_V2[index]).unwrap()
            );
        }

        let (mut descriptors, registry, registry_hash) = fixture();
        let class = descriptors[0].class;
        descriptors[0].child_witness_len = incremental_child_witness_ceiling_v2(class)
            .unwrap()
            .checked_add(1)
            .unwrap();
        assert_eq!(
            verify_incremental_child_availability_v2(
                &descriptors,
                &registry,
                registry_hash,
                &MarkerVerifier,
            ),
            Err(IncrementalChildAvailabilityErrorV2::InvalidShape)
        );

        let (mut descriptors, registry, registry_hash) = fixture();
        descriptors[0].child_witness_len = 0;
        assert_eq!(
            verify_incremental_child_availability_v2(
                &descriptors,
                &registry,
                registry_hash,
                &MarkerVerifier,
            ),
            Err(IncrementalChildAvailabilityErrorV2::InvalidShape)
        );
    }

    #[test]
    fn child_substitution_missing_class_and_receipt_mutation_fail_closed() {
        let (descriptors, registry, registry_hash) = fixture();
        assert!(verify_incremental_child_availability_v2(
            &descriptors[..5],
            &registry,
            registry_hash,
            &MarkerVerifier,
        )
        .is_err());

        let mut program_alias = descriptors.clone();
        program_alias[1].program_id = program_alias[0].program_id;
        assert!(verify_incremental_child_availability_v2(
            &program_alias,
            &registry,
            registry_hash,
            &MarkerVerifier,
        )
        .is_err());

        let mut root_mutation = descriptors;
        root_mutation[4].bundle_root[0] ^= 1;
        assert!(verify_incremental_child_availability_v2(
            &root_mutation,
            &registry,
            registry_hash,
            &MarkerVerifier,
        )
        .is_err());
    }
}
