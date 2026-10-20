//! Native authenticated source plus current covenant probe execution.
//! Final conversion composition requires the independently pinned policy. Initial
//! output linkage and inclusion at a frozen deployment checkpoint are checked;
//! receipt-authenticated checkpoint ancestry and exact pool outpoint tracing
//! through the authenticated transaction bodies are required.
use super::*;
use ecx_full_alpha_adapter_v3::{
    AlphaRecursiveReceiptBindingV3, FullAlphaReceiptVerifierV3, FullAlphaStatementV3,
    child_execution_state_v3::ChildExecutionCheckpointV3,
    native_conversion_accounting_v3::ConversionAccountingBindingV3,
    native_conversion_source_v3::{verify_native_conversion_source_receipt_v3,
        NativeConversionSourceBindingV3, NativeConversionSourcePublicValuesV3},
    native_redemption_deployment_v3::{verify_native_redemption_membership_v3,
        verify_initial_redemption_outputs_v3},
};

/// All expected commitments are supplied by the independently frozen enclosing
/// configuration. A witness must not choose this policy or the receipt verifier.
pub struct NativeRedemptionPolicyV3<'a> {
    pub source_program: [u8;32],
    pub source_commitment: [u8;32],
    pub covenant_commitment: [u8;32],
    pub source: &'a NativeConversionSourceBindingV3,
    pub public_pool: &'a public_pool::FrozenPublicPoolProgramV3,
    /// Independently reviewed native deployment checkpoint, not a hash supplied
    /// by the redemption witness. Receipt ancestry is verified below.
    pub deployment_checkpoint: [u8;32],
    /// Ordered reviewed policy preimages for the receipt ancestry chain. The
    /// final configuration encoder must commit the whole list, not just its tip.
    pub checkpoint_lineage: &'a [NativeConversionSourceBindingV3],
}

pub struct NativeRedemptionEvidenceV3<'a> {
    pub source_receipt: &'a AlphaRecursiveReceiptBindingV3,
    pub observation: &'a FullAlphaStatementV3,
    pub successor: &'a ChildExecutionCheckpointV3,
    pub accounting: &'a ConversionAccountingBindingV3,
    pub deployment: &'a EcxBtcCovenantDeploymentV2,
    pub deployment_checkpoint: &'a ChildExecutionCheckpointV3,
    pub checkpoint_lineage: &'a [ecx_full_alpha_adapter_v3::native_checkpoint_lineage_v3::NativeCheckpointLineageStepV3<'a>],
    /// Every ancestry step's block, followed by the current source block. Bodies
    /// must match receipt-authenticated tips and transaction Merkle roots.
    pub lineage_blocks: &'a [Vec<u8>],
    /// Initial outputs are distinct from the current successor outputs below.
    /// Their openings are checked against the exact frozen deployment bytes.
    pub initial_inventory: &'a AuthenticatedEconomicLeafV2,
    pub initial_reserve: &'a AuthenticatedEconomicLeafV2,
    pub inventory: &'a AuthenticatedEconomicLeafV2,
    pub reserve: &'a AuthenticatedEconomicLeafV2,
    pub probe: RedemptionProbeV3<'a>,
}

impl NativeRedemptionPolicyV3<'_> {
    /// Canonical whole-policy commitment. The outer verifier must pin this
    /// independently; computing it from a witness is not authentication.
    pub fn commitment(&self) -> Result<[u8;32], RedemptionCapabilityErrorV2> {
        use elements::hashes::{sha256,Hash};
        use RedemptionCapabilityErrorV2::Configuration;
        if self.source.commitment().map_err(|_| Configuration)? != self.source_commitment
            || !ecx_full_alpha_adapter_v3::alpha_sp1_program_id_is_canonical_v3(self.source_program)
            || [self.covenant_commitment,self.deployment_checkpoint,self.public_pool.program_sha256].contains(&[0;32])
            || self.checkpoint_lineage.len() > ecx_full_alpha_adapter_v3::native_checkpoint_lineage_v3::MAX_NATIVE_CHECKPOINT_LINEAGE_STEPS_V3
            || self.public_pool.parameters.child_genesis != self.source.parent.child_genesis_hash_internal {
            return Err(Configuration);
        }
        let scripts=self.public_pool.parameters.scripts(self.public_pool.compiled_cmr)
            .map_err(|_| Configuration)?;
        let mut bytes=vec![3];
        for hash in [self.source_program,self.source_commitment,self.covenant_commitment,
            self.deployment_checkpoint,self.public_pool.compiled_cmr,self.public_pool.program_sha256,
            scripts.inventory_role,scripts.reserve_role] { bytes.extend_from_slice(&hash); }
        bytes.extend_from_slice(&scripts.internal_key.serialize());
        bytes.extend_from_slice(&(self.checkpoint_lineage.len() as u32).to_be_bytes());
        for binding in self.checkpoint_lineage {
            bytes.extend_from_slice(&binding.commitment().map_err(|_| Configuration)?);
        }
        let tag=sha256::Hash::hash(b"ECX/alpha-native-redemption-policy/v3").to_byte_array();
        let mut preimage=Vec::with_capacity(64+bytes.len());
        preimage.extend_from_slice(&tag);preimage.extend_from_slice(&tag);preimage.extend_from_slice(&bytes);
        Ok(sha256::Hash::hash(&preimage).to_byte_array())
    }
}

/// Verify actual current-output membership and execute a concrete redemption
/// probe. No legacy checkpoint/configuration or exchange-root projection is used.
/// Return value authenticates source accounting, not a final conversion success.
pub fn execute_native_redemption_probe_v3(
    expected_policy: [u8;32],
    policy: &NativeRedemptionPolicyV3<'_>,
    evidence: &NativeRedemptionEvidenceV3<'_>,
    source_verifier: &impl FullAlphaReceiptVerifierV3,
    simplicity_verifier: &impl ElementsSimplicityReceiptVerifierV2,
) -> Result<NativeConversionSourcePublicValuesV3, RedemptionCapabilityErrorV2> {
    use RedemptionCapabilityErrorV2::*;
    if expected_policy == [0;32] || policy.commitment()? != expected_policy
        || policy.covenant_commitment == [0;32]
        || ecx_btc_covenant_commitment_v2(evidence.deployment).map_err(|_| Configuration)?
            != policy.covenant_commitment
        || evidence.probe.simplicity_program_bytes != evidence.deployment.simplicity_program_bytes {
        return Err(Configuration);
    }
    let source = verify_native_conversion_source_receipt_v3(evidence.source_receipt,
        policy.source_program, policy.source_commitment, policy.source,
        evidence.observation, evidence.successor, evidence.accounting, source_verifier)
        .map_err(|_| Configuration)?;
    ecx_full_alpha_adapter_v3::native_checkpoint_lineage_v3::verify_native_checkpoint_lineage_v3(
        policy.source_program, policy.deployment_checkpoint, policy.source.predecessor_checkpoint,
        policy.checkpoint_lineage, evidence.checkpoint_lineage, policy.source,
        evidence.accounting, source_verifier).map_err(|_| Configuration)?;
    if policy.deployment_checkpoint == [0;32]
        || evidence.deployment_checkpoint.height > evidence.successor.height {
        return Err(Configuration);
    }
    let authenticate_initial = |value: &AuthenticatedEconomicLeafV2| {
        let leaf=value.leaf.decode().map_err(|_| Membership)?;
        verify_native_redemption_membership_v3(evidence.deployment_checkpoint,
            policy.deployment_checkpoint, evidence.accounting, source.accounting_binding,
            &leaf, &value.utxo_path, &value.economic_path).map_err(|_| Membership)?;
        Ok::<_,RedemptionCapabilityErrorV2>(leaf)
    };
    let initial_inventory = authenticate_initial(evidence.initial_inventory)?;
    let initial_reserve = authenticate_initial(evidence.initial_reserve)?;
    verify_initial_redemption_outputs_v3(&evidence.deployment.deployment_transaction,
        &initial_inventory, &initial_reserve, evidence.accounting.classification)
        .map_err(|_| Configuration)?;
    for (leaf, expected) in [
        (&initial_inventory, evidence.deployment.redemption_inventory_outpoint),
        (&initial_reserve, evidence.deployment.reserve_outpoint),
    ] {
        if !matches!(leaf.utxo.output.asset, elements::confidential::Asset::Explicit(_))
            || !matches!(leaf.utxo.output.value, elements::confidential::Value::Explicit(_)) {
            return Err(Configuration);
        }
        if leaf.utxo.outpoint.txid.to_byte_array() != expected.txid_internal
            || leaf.utxo.outpoint.vout != expected.vout {
            return Err(Configuration);
        }
    }
    // Bind source accounting to the authenticated journal. The public covenant
    // itself is witness-free; its program and role controls are frozen by policy.
    if evidence.probe.public_values != evidence.source_receipt.public_values {
        return Err(Configuration);
    }
    let authenticate = |value: &AuthenticatedEconomicLeafV2| {
        let leaf = value.leaf.decode().map_err(|_| Membership)?;
        verify_native_redemption_membership_v3(evidence.successor,
            source.child.next_checkpoint, evidence.accounting, source.accounting_binding,
            &leaf, &value.utxo_path, &value.economic_path).map_err(|_| Membership)?;
        Ok::<_, RedemptionCapabilityErrorV2>(leaf)
    };
    let inventory = authenticate(evidence.inventory)?;
    let reserve = authenticate(evidence.reserve)?;
    require_tracked_pool_backing(inventory.amount, reserve.amount, &source.accounting)?;
    let checkpoints: Vec<_>=evidence.checkpoint_lineage.iter().map(|s|s.successor)
        .chain(std::iter::once(evidence.successor)).collect();
    super::native_pool_lineage::trace_pool_lineage(evidence.deployment_checkpoint,&checkpoints,
        evidence.lineage_blocks,&initial_inventory,&initial_reserve,&inventory,&reserve)?;
    execute_redemption_probe_with_policy_v3(&evidence.probe, &RedemptionProbeContextV3 {
        classification: evidence.accounting.classification,
        quote_atoms_per_whole_base: source.accounting.quote_atoms_per_whole_base,
        simplicity_evaluator_program_id: policy.source.simplicity_evaluator_program_id,
        child_genesis: evidence.successor.genesis_internal,
        outstanding_base_atoms: source.accounting.outstanding_base_atoms,
        source_tip_height: u64::from(evidence.successor.height),
        // Transaction lock MTP is the authenticated child's chain MTP. Parent
        // observation MTP is used for source freshness, not substituted here.
        source_tip_mtp: source.child_mtp,
    }, inventory, reserve, simplicity_verifier, Some(policy.public_pool))?;
    Ok(source)
}

/// Native version of the final ECX/BTC relation, retaining the outer transition's
/// exact 275-byte journal ABI. This is not the legacy projection: its source
/// checkpoint field commits the WHOLE native policy, and its state root is the
/// complete native child checkpoint commitment. A distinct, qualified final
/// guest program ID must authenticate these semantics in the outer profile.
///
/// Both verifiers must perform real cryptographic verification. A configured
/// caller pins `expected_policy` independently. A generic guest may instead prove
/// a witness-selected policy only if its outer consumer independently pins the
/// emitted source-checkpoint commitment; self-commitment is not policy review.
/// No final public values are returned on a failed source,
/// lineage, membership, backing, or Simplicity execution check.
pub fn execute_native_conversion_v3(
    expected_policy: [u8;32],
    policy: &NativeRedemptionPolicyV3<'_>,
    evidence: &NativeRedemptionEvidenceV3<'_>,
    source_verifier: &impl FullAlphaReceiptVerifierV3,
    simplicity_verifier: &impl ElementsSimplicityReceiptVerifierV2,
) -> Result<ecx_conversion_foundation_v2::ecx_btc::EcxBtcConversionPublicValuesV2,
    RedemptionCapabilityErrorV2> {
    let source=execute_native_redemption_probe_v3(expected_policy,policy,evidence,
        source_verifier,simplicity_verifier)?;
    let valid_until_mtp=source.child_mtp.checked_add(policy.source.maximum_child_age_seconds)
        .ok_or(RedemptionCapabilityErrorV2::Configuration)?;
    // The source verifier authenticated the exact observation and successor
    // preimages, including MTP freshness. Retain an explicit emission guard.
    if source.child_mtp > source.observation_mtp || valid_until_mtp < source.observation_mtp {
        return Err(RedemptionCapabilityErrorV2::Configuration);
    }
    Ok(ecx_conversion_foundation_v2::ecx_btc::EcxBtcConversionPublicValuesV2 {
        observed_parent_block_hash:evidence.observation.terminal_tip_hash_internal,
        observed_parent_height:u64::from(evidence.observation.terminal_selected_height),
        observed_parent_mtp:source.observation_mtp,
        source_height:u64::from(evidence.successor.height),
        source_mtp:source.child_mtp,
        valid_until_mtp,
        base_asset_id:source.accounting.base_asset_internal,
        quote_unit_id:source.accounting.quote_asset_internal,
        redemption_covenant_commitment:policy.covenant_commitment,
        source_checkpoint_commitment:expected_policy,
        source_state_root:source.child.next_checkpoint,
        quote_atoms_per_whole_base:source.accounting.quote_atoms_per_whole_base,
        outstanding_base_atoms:source.accounting.outstanding_base_atoms,
        redeemable_reserve_quote_atoms:source.accounting.redeemable_reserve_quote_atoms,
        redemption_enabled:true,
    })
}

/// Aggregate script classification alone cannot establish that all reported
/// backing is in the permissionless pool pair whose ancestry we trace. Bind the
/// complete reported reserve to that pair and ensure the inventory can receive
/// all outstanding atoms without overflowing Elements' explicit value encoding.
fn require_tracked_pool_backing(
    inventory: u64,
    reserve: u64,
    accounting: &ecx_full_alpha_adapter_v3::native_conversion_accounting_v3::ConversionAccountingV3,
) -> Result<(), RedemptionCapabilityErrorV2> {
    use RedemptionCapabilityErrorV2::Economics;
    let supply=u64::try_from(accounting.outstanding_base_atoms).map_err(|_| Economics)?;
    // The covenant rounds each payout up. For any positive integer partition
    // of supply, sum(ceil(piece * quote / scale)) <= supply * ceil(quote / scale).
    // One-atom redemptions attain this bound. Aggregate ceil(supply * rate)
    // alone can therefore underfund a permissionless sequence.
    let quote=u128::from(accounting.quote_atoms_per_whole_base);
    let per_atom=quote / BASE_ASSET_ATOMS_PER_WHOLE
        + u128::from(quote % BASE_ASSET_ATOMS_PER_WHOLE != 0);
    let fragmented_required=u128::from(supply).checked_mul(per_atom).ok_or(Economics)?;
    if supply == 0 || accounting.required_reserve_quote_atoms == 0
        || quote == 0 || u128::from(reserve) < fragmented_required
        || u128::from(reserve) != accounting.redeemable_reserve_quote_atoms
        || u128::from(reserve) < accounting.required_reserve_quote_atoms
        || inventory.checked_add(supply).is_none() {
        return Err(Economics);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_backing_must_be_in_the_tracked_pool() {
        use ecx_full_alpha_adapter_v3::native_conversion_accounting_v3::ConversionAccountingV3;
        let accounting=ConversionAccountingV3 {child_checkpoint_commitment:[1;32],
            base_asset_internal:[2;32],quote_asset_internal:[3;32],quote_atoms_per_whole_base:100_000_000,
            outstanding_base_atoms:100,redeemable_reserve_quote_atoms:120,required_reserve_quote_atoms:100};
        assert!(require_tracked_pool_backing(10,120,&accounting).is_ok());
        // A successful one-atom probe would not prove full backing here.
        assert!(require_tracked_pool_backing(10,1,&accounting).is_err());
        assert!(require_tracked_pool_backing(10,119,&accounting).is_err());
        assert!(require_tracked_pool_backing(10,121,&accounting).is_err());
        assert!(require_tracked_pool_backing(u64::MAX-99,120,&accounting).is_err());
        assert!(require_tracked_pool_backing(u64::MAX-100,120,&accounting).is_ok());
        assert!(require_tracked_pool_backing(0,120,&ConversionAccountingV3 {
            outstanding_base_atoms:0,..accounting}).is_err());
        assert!(require_tracked_pool_backing(0,120,&ConversionAccountingV3 {
            outstanding_base_atoms:u128::from(u64::MAX)+1,..accounting}).is_err());
        assert!(require_tracked_pool_backing(0,120,&ConversionAccountingV3 {
            required_reserve_quote_atoms:121,..accounting}).is_err());
    }
    #[test]
    fn fractional_quotes_cover_permissionless_fragmentation() {
        use ecx_full_alpha_adapter_v3::native_conversion_accounting_v3::ConversionAccountingV3;
        // Ten base atoms at 1.5 quote atoms each need 15 in a single redemption,
        // but ten one-atom redemptions pay 20 under the actual ceiling rule.
        let accounting=ConversionAccountingV3 {child_checkpoint_commitment:[1;32],
            base_asset_internal:[2;32],quote_asset_internal:[3;32],quote_atoms_per_whole_base:150_000_000,
            outstanding_base_atoms:10,redeemable_reserve_quote_atoms:15,required_reserve_quote_atoms:15};
        assert!(require_tracked_pool_backing(0,15,&accounting).is_err());
        let backed=ConversionAccountingV3 {redeemable_reserve_quote_atoms:20,..accounting};
        assert!(require_tracked_pool_backing(0,20,&backed).is_ok());
        // Every ordered partition of ten atoms: repeatedly rounded withdrawals
        // preserve enough reserve for all remaining one-atom redemptions.
        for cuts in 0u16..512 {
            let mut piece=0u64;let mut remaining=10u64;let mut reserve=20u64;
            for atom in 0..10 {
                piece+=1;
                if atom==9 || cuts & (1<<atom)!=0 {
                    let payout=(piece*3+1)/2;
                    reserve-=payout;remaining-=piece;piece=0;
                    assert!(reserve >= remaining*2);
                }
            }
        }
        // No artificial rate cap: integral rates have no fragmentation premium.
        assert!(require_tracked_pool_backing(0,1000,&ConversionAccountingV3 {
            quote_atoms_per_whole_base:10_000_000_000,redeemable_reserve_quote_atoms:1000,
            required_reserve_quote_atoms:1000,..accounting}).is_ok());
    }
    #[test]
    fn whole_policy_commits_pool_and_ordered_lineage() {
        use ecx_full_alpha_adapter_v3::{AlphaRecursiveBindingV3,
            conversion_parent_link_v3::AlphaConversionLinkBindingV3,
            native_conversion_source_v3::NativeSourceClockPolicyV3};
        let source=NativeConversionSourceBindingV3 {
            child_execution_program_id:[1;32],
            parent:AlphaConversionLinkBindingV3 {
                parent:AlphaRecursiveBindingV3 {source_configuration_commitment:[5;32],
                    reviewed_checkpoint_input_commitment:[6;32],checkpoint_program_id:[2;32],
                    transition_program_id:[3;32]},
                child_consensus_configuration_commitment:[7;32],child_genesis_hash_internal:[8;32],
                child_checkpoint_hash_internal:[9;32],child_checkpoint_height:20,
                slot24_proposal_hash:[10;32],slot24_activation_height:1_000_000,
            },
            predecessor_checkpoint:[11;32],execution_policy:[12;32],
            simplicity_evaluator_program_id:[4;32],deposit_configuration:[13;32],
            accounting_binding:[14;32],clock_policy:NativeSourceClockPolicyV3::ParentObservationMtp,
            minimum_parent_confirmations:1,maximum_child_age_seconds:1123200,
        };
        let pool=public_pool::FrozenPublicPoolProgramV3 {
            parameters:public_pool::PublicPoolParametersV3 {child_genesis:[8;32],base_asset:[15;32],
                quote_asset:[16;32],quote_atoms_per_whole_base:100_000_000},
            compiled_cmr:[17;32],program_sha256:[18;32],
        };
        let mut second=source.clone();second.predecessor_checkpoint=[19;32];
        let lineage=[source.clone(),second.clone()];
        let reversed=[second,source.clone()];
        let policy=NativeRedemptionPolicyV3 {source_program:[20;32],source_commitment:source.commitment().unwrap(),
            covenant_commitment:[21;32],source:&source,public_pool:&pool,deployment_checkpoint:[22;32],
            checkpoint_lineage:&lineage};
        let original=policy.commitment().unwrap();
        // Exercise the owned guest-policy transport, not merely the borrowed
        // native API. All ordered source bindings must survive serialization.
        let owned=crate::native_conversion_wire::NativeConversionPolicyInputV3 {
            source_program:policy.source_program,source_commitment:policy.source_commitment,
            covenant_commitment:policy.covenant_commitment,source:source.clone(),
            public_pool:pool.clone(),deployment_checkpoint:policy.deployment_checkpoint,
            checkpoint_lineage:lineage.to_vec(),
        };
        let options=|| bincode::DefaultOptions::new().with_fixint_encoding()
            .with_big_endian().reject_trailing_bytes();
        let encoded=options().serialize(&owned).unwrap();
        let decoded:crate::native_conversion_wire::NativeConversionPolicyInputV3=
            options().deserialize(&encoded).unwrap();
        assert_eq!(decoded.as_policy().commitment().unwrap(),original);
        assert_eq!(options().serialize(&decoded).unwrap(),encoded);
        for end in 0..encoded.len() {
            assert!(options().deserialize::<crate::native_conversion_wire::NativeConversionPolicyInputV3>(&encoded[..end]).is_err());
        }
        let mut trailing=encoded.clone();trailing.push(0);
        assert!(options().deserialize::<crate::native_conversion_wire::NativeConversionPolicyInputV3>(&trailing).is_err());
        let mut reordered=decoded.clone();reordered.checkpoint_lineage.reverse();
        assert_ne!(reordered.as_policy().commitment().unwrap(),original);
        let mut substituted=decoded;substituted.public_pool.program_sha256=[25;32];
        assert_ne!(substituted.as_policy().commitment().unwrap(),original);
        assert_eq!(original,policy.commitment().unwrap());
        assert_ne!(original,NativeRedemptionPolicyV3 {checkpoint_lineage:&reversed,..policy}.commitment().unwrap());
        assert_ne!(original,NativeRedemptionPolicyV3 {checkpoint_lineage:&[],..policy}.commitment().unwrap());
        assert_ne!(original,NativeRedemptionPolicyV3 {deployment_checkpoint:[23;32],..policy}.commitment().unwrap());
        assert!(NativeRedemptionPolicyV3 {source_commitment:[24;32],..policy}.commitment().is_err());
        assert!(NativeRedemptionPolicyV3 {source_program:[0;32],..policy}.commitment().is_err());
        let altered_pool=public_pool::FrozenPublicPoolProgramV3 {
            parameters:public_pool::PublicPoolParametersV3 {quote_atoms_per_whole_base:100_000_001,..pool.parameters.clone()},
            compiled_cmr:pool.compiled_cmr,program_sha256:pool.program_sha256,
        };
        assert_ne!(original,NativeRedemptionPolicyV3 {public_pool:&altered_pool,..policy}.commitment().unwrap());
    }
}
