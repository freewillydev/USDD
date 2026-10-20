//! Distinct custody checkpoint. A commitment is not authentication: the caller
//! must freeze a reviewed checkpoint or verify the producing execution receipt.
use ecx_full_consensus_validator_v2::{Hash32, elements_v2::*};
use crate::child_execution_state_v3::{CheckpointError, child_history_commitment};
use crate::native_header_v3::NativeHeader;
use crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildCustodyCheckpointV3 {
    pub genesis_internal: Hash32,
    pub configuration_commitment: Hash32,
    pub tip_internal: Hash32,
    pub height: u32,
    pub history_commitment: Hash32,
    pub classification: ElementsCustodyClassificationV3,
    pub roots: ElementsTransactionCustodyRootsV3,
    pub spent_claims_root: Hash32,
    pub withdrawals: WithdrawalAccumulator,
}

impl ChildCustodyCheckpointV3 {
    /// Check a complete reconstructed coin set against the independently
    /// frozen checkpoint. Source-block provenance must be verified before
    /// calling this; equality alone does not authenticate those source blocks.
    pub fn require_imported_coins(&self,expected:Hash32,coins:&[ElementsEconomicLeafV2])
        ->Result<(),CheckpointError> {
        self.require_frozen(expected)?;
        let roots=crate::checkpoint_coin_import_v3::custody_execution_roots_v3(coins,self.classification)
            .map_err(|_|CheckpointError::Accumulator)?;
        if roots!=self.roots { return Err(CheckpointError::Accumulator); }
        Ok(())
    }
    /// Fixed-width fields, internal hash order, big-endian integer totals.
    /// The domain is distinct from legacy economic checkpoints even at v3.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        if [self.genesis_internal,self.configuration_commitment,self.tip_internal,
            self.history_commitment,self.spent_claims_root,self.roots.utxo_root.hash,
            self.roots.custody_root.hash].contains(&[0;32]) {
            return Err(CheckpointError::Identity);
        }
        self.classification.commitment().map_err(|_|CheckpointError::Identity)?;
        if self.height==u32::MAX || (self.height==0 && self.tip_internal!=self.genesis_internal) {
            return Err(CheckpointError::Height);
        }
        if !self.withdrawals.is_sane()
            || self.roots.utxo_root.aggregate.count!=self.roots.custody_root.count
            || (self.roots.custody_root.count==0 && self.roots.custody_root.custody_supply_atoms!=0) {
            return Err(CheckpointError::Accumulator);
        }
        let mut bytes=vec![3];
        for hash in [self.genesis_internal,self.configuration_commitment,self.tip_internal,
            self.history_commitment,self.classification.native_pegged_asset_id,
            self.classification.custody_asset_id] { bytes.extend_from_slice(&hash); }
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.roots.utxo_root.hash);
        bytes.extend_from_slice(&self.roots.utxo_root.aggregate.count.to_be_bytes());
        bytes.extend_from_slice(&self.roots.custody_root.hash);
        bytes.extend_from_slice(&self.roots.custody_root.count.to_be_bytes());
        bytes.extend_from_slice(&self.roots.custody_root.custody_supply_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.spent_claims_root);
        bytes.extend_from_slice(&self.withdrawals.count.to_be_bytes());
        bytes.extend_from_slice(&self.withdrawals.root);
        for hash in self.withdrawals.frontier { bytes.extend_from_slice(&hash); }
        Ok(bytes)
    }
    pub fn commitment(&self)->Result<Hash32,CheckpointError> {
        Ok(crate::tagged_hash("ECX/alpha-child-custody-checkpoint/v3",&self.canonical_bytes()?))
    }
    pub fn require_frozen(&self, expected:Hash32)->Result<(),CheckpointError> {
        if expected==[0;32] || self.commitment()?!=expected {
            return Err(CheckpointError::FrozenCommitment);
        }
        Ok(())
    }
    pub fn checked_mtp_history(&self,headers:&[NativeHeader])->Result<Vec<NativeHeader>,CheckpointError> {
        let needed=self.height.checked_add(1).ok_or(CheckpointError::Height)?.min(11) as usize;
        let tip=headers.last().ok_or(CheckpointError::History)?;
        if headers.len()<needed || tip.base.height!=self.height
            || tip.hash_internal().map_err(|_|CheckpointError::History)?!=self.tip_internal
            || child_history_commitment(headers)?!=self.history_commitment {
            return Err(CheckpointError::History);
        }
        if headers[0].base.height==0
            && headers[0].hash_internal().map_err(|_|CheckpointError::History)?!=self.genesis_internal {
            return Err(CheckpointError::History);
        }
        Ok(headers[headers.len()-needed..].to_vec())
    }
}

/// Full custody execution checkpoint. Capital must be independently verified
/// by the enclosing execution relation; hashing a supplied projection is not
/// transition verification. This format never aliases the legacy reserve lane.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildCustodyExecutionCheckpointV4 {
    pub execution: ChildCustodyCheckpointV3,
    pub capital: Option<crate::child_execution_state_v4::CapitalProjectionV4>,
    pub bmm_endpoint: Option<Vec<u8>>,
}

/// Version-distinct full-anchor checkpoint. The V4 projection is retained for
/// evaluator compatibility, but cannot substitute for this commitment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildCustodyExecutionCheckpointV5 {
    pub projection: ChildCustodyExecutionCheckpointV4,
    pub full_anchor: Option<Vec<u8>>,
}
impl ChildCustodyExecutionCheckpointV5 {
    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        use crate::native_bmm_anchor_v1::NativeBmmAnchorV1;
        let mut bytes=vec![5];bytes.extend_from_slice(&self.projection.commitment()?);
        match &self.full_anchor {
            None if self.projection.execution.height==0 => bytes.push(0),
            Some(raw) if self.projection.execution.height>0 => {
                let anchor=NativeBmmAnchorV1::from_canonical_bytes(raw).ok_or(CheckpointError::Identity)?;
                if self.projection.bmm_endpoint.as_deref()!=Some(anchor.parent_endpoint().as_slice()) {
                    return Err(CheckpointError::Identity);
                }
                bytes.push(1);bytes.extend_from_slice(raw);
            },
            _ => return Err(CheckpointError::Identity),
        }
        Ok(crate::tagged_hash("ECX/alpha-child-custody-execution-checkpoint/v5",&bytes))
    }
    /// Authenticate the frozen predecessor, then ordering and selected ancestry.
    /// Current anchor must come from verified P/Q execution, never raw parsing.
    pub fn require_next_anchor(&self, frozen:Hash32,
        current:&crate::native_bmm_anchor_v1::NativeBmmAnchorV1, headers:&[[u8;80]])
        -> Result<(),CheckpointError> {
        if frozen==[0;32] || self.commitment()?!=frozen { return Err(CheckpointError::FrozenCommitment); }
        match &self.full_anchor {
            None if headers.is_empty() => Ok(()),
            Some(raw) => {
                let prior=crate::native_bmm_anchor_v1::NativeBmmAnchorV1::from_canonical_bytes(raw)
                    .ok_or(CheckpointError::Identity)?;
                if current.follows_with_ancestry(&prior,headers) {Ok(())}else{Err(CheckpointError::Identity)}
            },
            _ => Err(CheckpointError::Identity),
        }
    }
}

impl ChildCustodyExecutionCheckpointV4 {
    pub fn commitment(&self) -> Result<Hash32, CheckpointError> {
        let mut bytes = vec![4];
        bytes.extend_from_slice(&self.execution.commitment()?);
        bytes.push(u8::from(self.capital.is_some()));
        bytes.extend_from_slice(&match &self.capital {
            Some(capital) => capital.commitment()?, None => [0;32],
        });
        match &self.bmm_endpoint {
            None if self.execution.height == 0 => bytes.push(0),
            Some(endpoint) if self.execution.height > 0 && endpoint.len() == 80
                && endpoint[..32] != [0;32] && endpoint[48..] != [0;32] => {
                bytes.push(1);
                bytes.extend_from_slice(endpoint);
            }
            _ => return Err(CheckpointError::Identity),
        }
        Ok(crate::tagged_hash("ECX/alpha-child-custody-execution-checkpoint/v4", &bytes))
    }
    pub fn require_frozen(&self, expected: Hash32) -> Result<(), CheckpointError> {
        if expected == [0;32] || self.commitment()? != expected {
            return Err(CheckpointError::FrozenCommitment);
        }
        Ok(())
    }
    pub fn evaluator_anchor_commitment(&self, frozen: Hash32) -> Result<Hash32, CheckpointError> {
        self.require_frozen(frozen)?;
        ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::alpha_prior_anchor_commitment_v4(
            self.bmm_endpoint.as_deref()).map_err(|_| CheckpointError::Identity)
    }
    pub fn checked_header(&self, frozen: Hash32, header: &NativeHeader)
        -> Result<Option<crate::native_header_v3::PriorExchangeContext>, CheckpointError> {
        self.require_frozen(frozen)?;
        let context = header.prior_exchange_context(self.execution.tip_internal, self.execution.height)
            .map_err(|_| CheckpointError::History)?;
        if let Some(capital) = &self.capital {
            if header.base.version & crate::native_header_v3::EXCHANGE == 0
                || header.exchange != capital.exchange_state_root {
                return Err(CheckpointError::Identity);
            }
        }
        Ok(context)
    }
    /// Attach only the endpoint authenticated for the exact executed child.
    /// Caller must separately verify capital genesis/transitions and inbox scans.
    pub fn join_executed_parent<P: crate::FullAlphaReceiptVerifierV3>(
        execution: ChildCustodyCheckpointV3,
        capital: Option<crate::child_execution_state_v4::CapitalProjectionV4>,
        executed: &crate::native_child_block_v3::ParentBoundCheckedCustodyStateV3,
        parent: &crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
        frozen_parent_binding: Hash32, verifier: &P,
    ) -> Result<Self, CheckpointError> {
        if executed.child().next_checkpoint() != Some(&execution) {
            return Err(CheckpointError::Identity);
        }
        let (statement, endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
            parent, frozen_parent_binding, verifier).map_err(|_| CheckpointError::Identity)?;
        if &statement != executed.parent() { return Err(CheckpointError::Identity); }
        let result = Self { execution, capital, bmm_endpoint: Some(endpoint.to_vec()) };
        result.checked_header(result.commitment()?, &executed.child().foundation().native_header)?;
        Ok(result)
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn custody_checkpoint_commits_distinct_assets_and_every_total() {
        let cp=ChildCustodyCheckpointV3 {
            genesis_internal:[1;32],configuration_commitment:[2;32],tip_internal:[3;32],
            height:7,history_commitment:[4;32],spent_claims_root:[5;32],
            classification:ElementsCustodyClassificationV3 {native_pegged_asset_id:[6;32],custody_asset_id:[7;32]},
            roots:ElementsTransactionCustodyRootsV3 {
                utxo_root:ElementsSparseUtxoNodeV2 {hash:[8;32],aggregate:ElementsUtxoAggregateV2 {count:2}},
                custody_root:ElementsSparseCustodyNodeV3 {hash:[9;32],count:2,custody_supply_atoms:30},
            },withdrawals:WithdrawalAccumulator::empty(),
        };
        let frozen=cp.commitment().unwrap();
        let mut endpoint = vec![1;80];
        endpoint[32..40].copy_from_slice(&9u64.to_be_bytes());
        endpoint[40..48].copy_from_slice(&10u64.to_be_bytes());
        let full = ChildCustodyExecutionCheckpointV4 {
            execution: cp.clone(), capital: None, bmm_endpoint: Some(endpoint),
        };
        let full_hash = full.commitment().unwrap();
        // V5 cannot reinterpret an 80-byte endpoint or a V4 commitment.
        use crate::native_bmm_anchor_v1::NativeBmmAnchorV1;
        let mut raw_anchor=[1;145];
        raw_anchor[65..129].fill(0);raw_anchor[96]=10;raw_anchor[128]=11;
        raw_anchor[129..133].copy_from_slice(&9u32.to_be_bytes());
        raw_anchor[133..137].copy_from_slice(&10u32.to_be_bytes());
        raw_anchor[137..145].copy_from_slice(&10u64.to_be_bytes());
        let prior=NativeBmmAnchorV1::from_canonical_bytes(&raw_anchor).unwrap();
        let mut projection=full.clone();projection.bmm_endpoint=Some(prior.parent_endpoint().to_vec());
        let anchored=ChildCustodyExecutionCheckpointV5 {projection,full_anchor:Some(raw_anchor.to_vec())};
        let anchored_hash=anchored.commitment().unwrap();
        assert_ne!(anchored_hash,anchored.projection.commitment().unwrap());
        assert!(anchored.require_next_anchor(anchored_hash,&prior,&[]).is_err());
        raw_anchor[96]=11;raw_anchor[128]=12;
        raw_anchor[129..133].copy_from_slice(&10u32.to_be_bytes());
        raw_anchor[133..137].copy_from_slice(&11u32.to_be_bytes());
        let next=NativeBmmAnchorV1::from_canonical_bytes(&raw_anchor).unwrap();
        anchored.require_next_anchor(anchored_hash,&next,&[]).unwrap();
        assert!(anchored.require_next_anchor(full_hash,&next,&[]).is_err());
        let mut bad=anchored.clone();bad.full_anchor=Some(vec![1;80]);assert!(bad.commitment().is_err());
        let mut bad=anchored.clone();bad.projection.bmm_endpoint.as_mut().unwrap()[0]^=1;
        assert!(bad.commitment().is_err());
        let mut bad=anchored.clone();bad.full_anchor=None;assert!(bad.commitment().is_err());
        full.require_frozen(full_hash).unwrap();
        full.evaluator_anchor_commitment(full_hash).unwrap();
        assert!(full.require_frozen(frozen).is_err());
        let mut with_capital = full.clone();
        with_capital.capital = Some(crate::child_execution_state_v4::CapitalProjectionV4 {
            proof_profile: 0, exchange_state_root: [11;32], configuration_hash: [12;32],
            asset_id: [13;32], deployment_commitment: [14;32], transition_program_id: [15;32],
            transition_cmr: [16;32], covenant_state_hash: [17;32],
            covenant_inbox_root: [18;32], covenant_inbox_count: 2,
            node_inbox_root: [19;32], node_inbox_count: 3,
        });
        let capital_hash = with_capital.commitment().unwrap();
        assert_ne!(capital_hash, full_hash);
        assert!(full.require_frozen(capital_hash).is_err());
        with_capital.capital.as_mut().unwrap().node_inbox_count += 1;
        assert!(with_capital.require_frozen(capital_hash).is_err());
        with_capital.capital.as_mut().unwrap().node_inbox_count = 1;
        assert!(with_capital.commitment().is_err());
        for offset in [0,32,40,48,79] {
            let mut changed = full.clone();
            changed.bmm_endpoint.as_mut().unwrap()[offset] ^= 1;
            assert!(changed.require_frozen(full_hash).is_err());
        }
        let mut bad = full.clone(); bad.bmm_endpoint = None;
        assert!(bad.commitment().is_err());
        let mut bad = full.clone(); bad.bmm_endpoint.as_mut().unwrap().pop();
        assert!(bad.commitment().is_err());
        let mut genesis = full.clone();
        genesis.execution.height = 0;
        genesis.execution.tip_internal = genesis.execution.genesis_internal;
        assert!(genesis.commitment().is_err());
        genesis.bmm_endpoint = None;
        genesis.evaluator_anchor_commitment(genesis.commitment().unwrap()).unwrap();
        assert_eq!(cp.canonical_bytes().unwrap().len(),2429);
        cp.require_frozen(frozen).unwrap();
        for field in 0..12 {
            let mut changed=cp.clone();
            match field {
                0=>changed.classification.native_pegged_asset_id[0]^=1,
                1=>changed.classification.custody_asset_id[0]^=1,
                2=>changed.roots.utxo_root.hash[0]^=1,
                3=>changed.roots.custody_root.hash[0]^=1,
                4=>changed.roots.custody_root.custody_supply_atoms+=1,
                5=>changed.spent_claims_root[0]^=1,
                6=>changed.history_commitment[0]^=1,
                7=>changed.configuration_commitment[0]^=1,
                8=>changed.tip_internal[0]^=1,
                9=>changed.height+=1,
                10=>changed.genesis_internal[0]^=1,
                _=>{changed.roots.utxo_root.aggregate.count+=1;changed.roots.custody_root.count+=1;},
            }
            assert!(changed.require_frozen(frozen).is_err());
        }
        let mut bad=cp.clone();bad.classification.custody_asset_id=bad.classification.native_pegged_asset_id;
        assert!(bad.commitment().is_err());
        let mut bad=cp.clone();bad.roots.custody_root.count+=1;
        assert!(bad.commitment().is_err());
        for field in 0..3 {
            let mut bad=cp.clone();
            match field {
                0=>bad.withdrawals.count+=1,
                1=>bad.withdrawals.root[0]^=1,
                _=>bad.withdrawals.frontier[0][0]^=1,
            }
            assert!(bad.require_frozen(frozen).is_err());
        }
        let mut bad=cp.clone();bad.roots.custody_root.count=0;bad.roots.utxo_root.aggregate.count=0;
        assert!(bad.commitment().is_err());
        assert!(cp.require_frozen([0;32]).is_err());
    }
}
