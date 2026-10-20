//! Native buried deployment semantics. These settings require an authenticated
//! configuration; this codec alone does not freeze or authenticate them.
//! DynaFed, Taproot and Simplicity use different deployment machinery.

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuriedDeploymentsV3 {
    pub height_in_coinbase: i32,
    pub strict_der: i32,
    pub cltv: i32,
    pub csv: i32,
    pub segwit: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuriedFlagsV3 {
    pub height_in_coinbase: bool,
    pub strict_der: bool,
    pub cltv: bool,
    pub csv: bool,
    pub segwit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeHeightOverflow;

/// Effective native deployment parameters, after per-deployment period and
/// threshold overrides. Elements interprets start/timeout as heights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsVersionbitsV3 {
    pub bit: u8,
    pub start: i64,
    pub timeout: i64,
    pub min_activation_height: i32,
    pub period: u32,
    pub threshold: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentStateV3 { Defined, Started, LockedIn, Active, Failed }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentErrorV3 { Parameters, History, FrozenCommitment }

/// Deployment component of the future complete child configuration. Its
/// commitment is not a replacement for reward, asset, bootstrap or program
/// identities in that complete configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildDeploymentConfigurationV3 {
    pub buried: BuriedDeploymentsV3,
    pub taproot: ElementsVersionbitsV3,
    pub dynafed: ElementsVersionbitsV3,
    pub simplicity: ElementsVersionbitsV3,
    /// Native null hash means no BIP16 exception.
    pub bip16_exception_internal: [u8;32],
    pub usdd_sp1_annex: bool,
}

impl ChildDeploymentConfigurationV3 {
    /// Custody checkpoints authenticate their own domain and asset totals;
    /// never fabricate legacy economic roots to derive deployment rules.
    pub fn checked_custody_candidate_rules(self, frozen_deployments:[u8;32],
        checkpoint:&crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3,
        frozen_checkpoint:[u8;32], history:&[crate::native_header_v3::NativeHeader],
        candidate:&crate::native_header_v3::NativeHeader,
    ) -> Result<NativeBlockScriptRulesV3,DeploymentErrorV3> {
        use elements::hashes::Hash;
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_|DeploymentErrorV3::FrozenCommitment)?;
        checkpoint.checked_mtp_history(history).map_err(|_|DeploymentErrorV3::History)?;
        let height=checkpoint.height.checked_add(1).ok_or(DeploymentErrorV3::History)?;
        if candidate.base.height!=height || candidate.base.prev_blockhash.to_byte_array()!=checkpoint.tip_internal {
            return Err(DeploymentErrorV3::History);
        }
        self.rules_from_checked_history(frozen_deployments,history,height,
            checkpoint.genesis_internal,checkpoint.history_commitment,
            candidate.hash_internal().map_err(|_|DeploymentErrorV3::History)?)
    }
    /// Derive the BIP16 exception decision from the candidate itself and bind
    /// its predecessor/height to the same checkpoint used for deployment state.
    /// Header authorization and full transaction execution remain mandatory in
    /// the enclosing relation; this method does not establish either.
    pub fn checked_candidate_rules(self, frozen_deployments:[u8;32],
        checkpoint:&crate::child_execution_state_v3::ChildExecutionCheckpointV3,
        frozen_checkpoint:[u8;32], history:&[crate::native_header_v3::NativeHeader],
        candidate:&crate::native_header_v3::NativeHeader,
    ) -> Result<NativeBlockScriptRulesV3,DeploymentErrorV3> {
        use elements::hashes::Hash;
        if candidate.base.height != checkpoint.height.checked_add(1).ok_or(DeploymentErrorV3::History)?
            || candidate.base.prev_blockhash.to_byte_array() != checkpoint.tip_internal {
            return Err(DeploymentErrorV3::History);
        }
        let candidate_hash = candidate.hash_internal().map_err(|_|DeploymentErrorV3::History)?;
        self.checked_rules(frozen_deployments,checkpoint,frozen_checkpoint,history,candidate_hash)
    }

    pub fn commitment(self) -> Result<[u8;32],DeploymentErrorV3> {
        let mut bytes = self.buried.canonical_bytes().to_vec();
        for deployment in [self.taproot,self.dynafed,self.simplicity] {
            bytes.extend(deployment.canonical_bytes()?);
        }
        bytes.extend(self.bip16_exception_internal);
        bytes.push(u8::from(self.usdd_sp1_annex));
        Ok(crate::tagged_hash("ECX/alpha-child-deployments/v3",&bytes))
    }

    /// Freeze both the configuration component and predecessor history.
    /// `candidate_hash` must be derived from the actual candidate by the
    /// enclosing relation; it is used only for the native BIP16 exception.
    pub fn checked_rules(self, frozen_deployments:[u8;32],
        checkpoint:&crate::child_execution_state_v3::ChildExecutionCheckpointV3,
        frozen_checkpoint:[u8;32], history:&[crate::native_header_v3::NativeHeader],
        candidate_hash:[u8;32],
    ) -> Result<NativeBlockScriptRulesV3,DeploymentErrorV3> {
        if frozen_deployments == [0;32] || self.commitment()? != frozen_deployments {
            return Err(DeploymentErrorV3::FrozenCommitment);
        }
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_|DeploymentErrorV3::FrozenCommitment)?;
        checkpoint.checked_mtp_history(history).map_err(|_|DeploymentErrorV3::History)?;
        self.rules_from_checked_history(frozen_deployments,history,
            checkpoint.height.checked_add(1).ok_or(DeploymentErrorV3::History)?,
            checkpoint.genesis_internal,checkpoint.history_commitment,candidate_hash)
    }

    // Private: callers must authenticate the checkpoint and its history first.
    fn rules_from_checked_history(self,frozen_deployments:[u8;32],
        history:&[crate::native_header_v3::NativeHeader],height:u32,
        genesis:[u8;32],history_commitment:[u8;32],candidate_hash:[u8;32],
    )->Result<NativeBlockScriptRulesV3,DeploymentErrorV3> {
        if frozen_deployments==[0;32] || self.commitment()?!=frozen_deployments {
            return Err(DeploymentErrorV3::FrozenCommitment);
        }
        if candidate_hash == [0;32] { return Err(DeploymentErrorV3::History); }
        let buried = self.buried.at_height(height).map_err(|_|DeploymentErrorV3::History)?;
        let active = |deployment:ElementsVersionbitsV3| deployment.state_after_history(history,
            genesis,history_commitment)
            .map(|state|state == DeploymentStateV3::Active);
        Ok(buried.block_script_rules(candidate_hash == self.bip16_exception_internal,
            true,active(self.taproot)?,active(self.dynafed)?,active(self.simplicity)?,self.usdd_sp1_annex))
    }
}

impl ElementsVersionbitsV3 {
    pub fn canonical_bytes(self) -> Result<Vec<u8>, DeploymentErrorV3> {
        if self.bit > 28 || self.start < -2 || self.period == 0
            || self.period > i32::MAX as u32 || self.threshold > self.period {
            return Err(DeploymentErrorV3::Parameters);
        }
        let mut bytes = vec![3,self.bit];
        bytes.extend(self.start.to_be_bytes()); bytes.extend(self.timeout.to_be_bytes());
        bytes.extend(self.min_activation_height.to_be_bytes());
        bytes.extend(self.period.to_be_bytes()); bytes.extend(self.threshold.to_be_bytes());
        Ok(bytes)
    }

    fn state_from_versions(self, versions: &[u32]) -> Result<DeploymentStateV3, DeploymentErrorV3> {
        use DeploymentStateV3::*;
        self.canonical_bytes()?;
        if versions.len() > i32::MAX as usize { return Err(DeploymentErrorV3::History); }
        if self.start == -1 { return Ok(Active); }
        if self.start == -2 { return Ok(Failed); }
        let mut state = Defined;
        // Ignore the incomplete terminal period, exactly as native alignment
        // to predecessor height = a multiple of period minus one.
        for (index, period) in versions.chunks_exact(self.period as usize).enumerate() {
            let next_height = (index + 1) * self.period as usize;
            let height = (next_height - 1) as i64;
            state = match state {
                Defined if height >= self.start => Started,
                Started => {
                    let count = period.iter().filter(|version|
                        **version & 0xe0000000 == 0x20000000
                        && **version & (1u32 << self.bit) != 0).count();
                    // Native checks threshold before timeout; a successful
                    // period locks in even at or beyond the timeout height.
                    if count >= self.threshold as usize { LockedIn }
                    else if height >= self.timeout { Failed } else { Started }
                },
                LockedIn if next_height as i64 >= i64::from(self.min_activation_height) => Active,
                other => other,
            };
        }
        Ok(state)
    }

    /// Full genesis-to-predecessor history authenticated by an independently
    /// frozen history commitment. Hash equality is not historical consensus
    /// qualification; that remains the checkpoint producer's obligation.
    pub fn state_after_history(self, headers: &[crate::native_header_v3::NativeHeader],
        genesis: [u8;32], frozen_history: [u8;32],
    ) -> Result<DeploymentStateV3, DeploymentErrorV3> {
        let first = headers.first().ok_or(DeploymentErrorV3::History)?;
        if first.base.height != 0 || genesis == [0;32]
            || first.hash_internal().map_err(|_| DeploymentErrorV3::History)? != genesis {
            return Err(DeploymentErrorV3::History);
        }
        if frozen_history == [0;32] || crate::child_execution_state_v3::child_history_commitment(headers)
            .map_err(|_| DeploymentErrorV3::History)? != frozen_history {
            return Err(DeploymentErrorV3::FrozenCommitment);
        }
        self.state_from_versions(&headers.iter().map(|h|h.base.version).collect::<Vec<_>>())
    }
}

/// Native block-consensus selections, not mempool standardness policy.
/// Versionbits states and the BIP16 exception decision must come from verified
/// chain history/configuration; accepting these inputs does not authenticate them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBlockScriptRulesV3 {
    pub p2sh: bool,
    pub witness: bool,
    pub strict_der: bool,
    pub cltv: bool,
    pub csv: bool,
    pub null_dummy: bool,
    pub taproot: bool,
    pub sighash_rangeproof: bool,
    pub simplicity: bool,
    pub usdd_sp1_annex: bool,
}

impl BuriedFlagsV3 {
    /// Mirrors native GetBlockScriptFlags. In particular WITNESS follows P2SH,
    /// while the buried Segwit activation selects NULLDUMMY, not WITNESS.
    pub fn block_script_rules(
        self,
        is_bip16_exception: bool,
        elements_mode: bool,
        taproot_active: bool,
        dynafed_active: bool,
        simplicity_active: bool,
        enable_usdd_sp1_annex: bool,
    ) -> NativeBlockScriptRulesV3 {
        NativeBlockScriptRulesV3 {
            p2sh: !is_bip16_exception,
            witness: !is_bip16_exception,
            strict_der: self.strict_der,
            cltv: self.cltv,
            csv: self.csv,
            null_dummy: self.segwit,
            taproot: taproot_active,
            sighash_rangeproof: elements_mode && dynafed_active,
            simplicity: elements_mode && simplicity_active,
            usdd_sp1_annex: enable_usdd_sp1_annex,
        }
    }
}

impl NativeBlockScriptRulesV3 {
    /// Rules for the base Elements input evaluator. This does not install a
    /// Simplicity executor or USDD annex verifier, authenticate deployment
    /// inputs, or qualify unsupported Taproot script paths.
    pub fn base_input_rules(self) -> ecx_full_consensus_validator_v2::elements_v2::ElementsInputRulesV3 {
        use ecx_full_consensus_validator_v2::{elements_v2::ElementsInputRulesV3,
            script_v2::LegacyScriptFlagsV2};
        ElementsInputRulesV3 {
            script: LegacyScriptFlagsV2 {
                verify_p2sh:self.p2sh, verify_witness:self.witness,
                strict_der:self.strict_der, verify_taproot:self.taproot,
                ..LegacyScriptFlagsV2::default()
            },
            cltv:self.cltv, csv:self.csv, null_dummy:self.null_dummy,
            null_fail:false, discourage_upgradable_nops:false, const_script_code:false,
            rangeproof_active:self.sighash_rangeproof, simplicity_active:self.simplicity, native_execution:true,
        }
    }
}

impl BuriedDeploymentsV3 {
    /// Exactly DeploymentActiveAt/After for a nonnegative native candidate
    /// height. Retain signed configured heights, including INT_MAX, rather than
    /// mapping a configuration sentinel to a different consensus comparison.
    pub fn at_height(self, height: u32) -> Result<BuriedFlagsV3, NativeHeightOverflow> {
        let height = i32::try_from(height).map_err(|_| NativeHeightOverflow)?;
        Ok(BuriedFlagsV3 {
            height_in_coinbase: height >= self.height_in_coinbase,
            strict_der: height >= self.strict_der,
            cltv: height >= self.cltv,
            csv: height >= self.csv,
            segwit: height >= self.segwit,
        })
    }

    /// Version followed by five signed 32-bit big-endian native heights.
    pub fn canonical_bytes(self) -> [u8; 21] {
        let mut bytes = [0; 21]; bytes[0] = 3;
        for (i, height) in [self.height_in_coinbase,self.strict_der,self.cltv,self.csv,self.segwit]
            .into_iter().enumerate() {
            bytes[1+i*4..5+i*4].copy_from_slice(&height.to_be_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn elements_versionbits_height_period_threshold_and_timeout_rules() {
        use DeploymentStateV3::*;
        let deployment = ElementsVersionbitsV3 {bit:2,start:0,timeout:7,
            min_activation_height:0,period:4,threshold:3};
        let config = ChildDeploymentConfigurationV3 {
            buried:BuriedDeploymentsV3 {height_in_coinbase:0,strict_der:0,cltv:0,csv:0,segwit:0},
            taproot:deployment,dynafed:deployment,simplicity:deployment,
            bip16_exception_internal:[0;32],usdd_sp1_annex:false,
        };
        for changed in [ChildDeploymentConfigurationV3 {usdd_sp1_annex:true,..config},
            ChildDeploymentConfigurationV3 {bip16_exception_internal:[1;32],..config},
            ChildDeploymentConfigurationV3 {taproot:ElementsVersionbitsV3 {start:-1,..deployment},..config},
            ChildDeploymentConfigurationV3 {dynafed:ElementsVersionbitsV3 {threshold:2,..deployment},..config},
            ChildDeploymentConfigurationV3 {simplicity:ElementsVersionbitsV3 {period:5,..deployment},..config},
            ChildDeploymentConfigurationV3 {buried:BuriedDeploymentsV3 {csv:9,..config.buried},..config}] {
            assert_ne!(config.commitment().unwrap(),changed.commitment().unwrap());
        }
        let yes = 0x20000004;
        let mut versions = vec![yes;12];
        for (length, expected) in [(0,Defined),(3,Defined),(4,Started),(7,Started),
            (8,LockedIn),(11,LockedIn),(12,Active)] {
            assert_eq!(deployment.state_from_versions(&versions[..length]),Ok(expected));
        }
        // Threshold takes precedence over timeout at height 7.
        versions[4] = 0x00000004; // Set bit without versionbits top mask does not count.
        assert_eq!(deployment.state_from_versions(&versions[..8]),Ok(LockedIn));
        versions[5] = 0x60000004;
        assert_eq!(deployment.state_from_versions(&versions),Ok(Failed));
        versions.fill(yes);
        let delayed = ElementsVersionbitsV3 {min_activation_height:13,..deployment};
        assert_eq!(delayed.state_from_versions(&versions),Ok(LockedIn));
        versions.resize(16,yes);
        assert_eq!(delayed.state_from_versions(&versions),Ok(Active));
        let late = ElementsVersionbitsV3 {start:4,timeout:0,..deployment};
        assert_eq!(late.state_from_versions(&versions[..4]),Ok(Defined));
        assert_eq!(late.state_from_versions(&versions[..8]),Ok(Started));
        for (start, expected) in [(-1,Active),(-2,Failed)] {
            assert_eq!(ElementsVersionbitsV3 {start,..deployment}.state_from_versions(&[]),Ok(expected));
        }
        assert_eq!(ElementsVersionbitsV3 {period:0,..deployment}.canonical_bytes(),Err(DeploymentErrorV3::Parameters));
        assert_eq!(ElementsVersionbitsV3 {bit:29,..deployment}.canonical_bytes(),Err(DeploymentErrorV3::Parameters));
        for altered in [ElementsVersionbitsV3 {bit:3,..deployment},
            ElementsVersionbitsV3 {start:1,..deployment},ElementsVersionbitsV3 {timeout:8,..deployment},
            ElementsVersionbitsV3 {min_activation_height:1,..deployment},
            ElementsVersionbitsV3 {period:5,..deployment},ElementsVersionbitsV3 {threshold:2,..deployment}] {
            assert_ne!(deployment.canonical_bytes().unwrap(),altered.canonical_bytes().unwrap());
        }
    }

    #[test]
    fn versionbits_rejects_unfrozen_or_truncated_header_history() {
        use elements::{BlockHeader,BlockHash,TxMerkleNode,BlockExtData,Script};
        use elements::hashes::Hash;
        let mut history = Vec::new();
        let mut previous = BlockHash::all_zeros();
        for height in 0..12 {
            let header = crate::native_header_v3::NativeHeader::from_standard(BlockHeader {
                version:0x20000004,prev_blockhash:previous,merkle_root:TxMerkleNode::all_zeros(),
                time:1_700_000_000+height,height,
                ext:BlockExtData::Proof {challenge:Script::from(vec![0x51]),solution:Script::new()},
            });
            previous = BlockHash::from_byte_array(header.hash_internal().unwrap());
            history.push(header);
        }
        let deployment = ElementsVersionbitsV3 {bit:2,start:0,timeout:7,
            min_activation_height:0,period:4,threshold:3};
        let genesis = history[0].hash_internal().unwrap();
        let commitment = crate::child_execution_state_v3::child_history_commitment(&history).unwrap();
        // Exercise the public configuration/history boundary, not only the
        // isolated versionbits calculator. These are synthetic test roots.
        use ecx_full_consensus_validator_v2::elements_v2::*;
        let config = ChildDeploymentConfigurationV3 {
            buried:BuriedDeploymentsV3 {height_in_coinbase:0,strict_der:12,cltv:13,csv:0,segwit:0},
            taproot:deployment,dynafed:deployment,simplicity:deployment,
            bip16_exception_internal:[9;32],usdd_sp1_annex:false,
        };
        let checkpoint = crate::child_execution_state_v3::ChildExecutionCheckpointV3 {
            genesis_internal:genesis,configuration_commitment:[2;32],
            tip_internal:history[11].hash_internal().unwrap(),height:11,history_commitment:commitment,
            spent_claims_root: crate::native_claims_v3::empty_root(),
            roots:ElementsTransactionStateRootsV2 {
                utxo_root:ElementsSparseUtxoNodeV2 {hash:[3;32],aggregate:ElementsUtxoAggregateV2 {count:0}},
                economic_root:ElementsSparseEconomicNodeV2 {hash:[4;32],aggregate:ElementsEconomicAggregateV2 {
                    count:0,outstanding_base_atoms:0,redeemable_reserve_quote_atoms:0}},
            },
            withdrawals:crate::native_withdrawal_accumulator_v3::WithdrawalAccumulator::empty(),
        };
        let frozen = checkpoint.commitment().unwrap();
        let frozen_config = config.commitment().unwrap();
        let mut candidate = history[11].clone();
        candidate.base.height = 12;
        candidate.base.prev_blockhash = BlockHash::from_byte_array(checkpoint.tip_internal);
        candidate.base.time += 1;
        let candidate_rules = config.checked_candidate_rules(frozen_config,&checkpoint,frozen,&history,&candidate).unwrap();
        assert!(candidate_rules.p2sh && candidate_rules.taproot && candidate_rules.strict_der);
        let custody=crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3 {
            genesis_internal:genesis,configuration_commitment:[2;32],
            tip_internal:checkpoint.tip_internal,height:11,history_commitment:commitment,
            spent_claims_root:checkpoint.spent_claims_root,withdrawals:checkpoint.withdrawals.clone(),
            classification:ElementsCustodyClassificationV3 {native_pegged_asset_id:[6;32],custody_asset_id:[7;32]},
            roots:ElementsTransactionCustodyRootsV3 {utxo_root:checkpoint.roots.utxo_root,
                custody_root:ElementsSparseCustodyNodeV3 {hash:[8;32],count:0,custody_supply_atoms:0}},
        };
        let custody_hash=custody.commitment().unwrap();
        assert_eq!(config.checked_custody_candidate_rules(frozen_config,&custody,custody_hash,&history,&candidate).unwrap(),candidate_rules);
        for bad in [frozen,[0;32]] {
            assert_eq!(config.checked_custody_candidate_rules(frozen_config,&custody,bad,&history,&candidate),Err(DeploymentErrorV3::FrozenCommitment));
        }
        assert!(config.checked_custody_candidate_rules([0;32],&custody,custody_hash,&history,&candidate).is_err());
        assert!(config.checked_custody_candidate_rules(frozen_config,&custody,custody_hash,&history[..11],&candidate).is_err());
        let mut changed=custody.clone();changed.classification.custody_asset_id=[10;32];
        assert!(config.checked_custody_candidate_rules(frozen_config,&changed,custody_hash,&history,&candidate).is_err());
        let mut wrong=candidate.clone();wrong.base.height+=1;
        assert!(config.checked_custody_candidate_rules(frozen_config,&custody,custody_hash,&history,&wrong).is_err());
        wrong=candidate.clone();wrong.base.prev_blockhash=BlockHash::all_zeros();
        assert!(config.checked_custody_candidate_rules(frozen_config,&custody,custody_hash,&history,&wrong).is_err());
        let exception_config = ChildDeploymentConfigurationV3 {
            bip16_exception_internal:candidate.hash_internal().unwrap(),..config
        };
        let exception_rules = exception_config.checked_candidate_rules(exception_config.commitment().unwrap(),
            &checkpoint,frozen,&history,&candidate).unwrap();
        assert!(!exception_rules.p2sh && !exception_rules.witness);
        candidate.base.height += 1;
        assert_eq!(config.checked_candidate_rules(frozen_config,&checkpoint,frozen,&history,&candidate),Err(DeploymentErrorV3::History));
        candidate.base.height -= 1;
        candidate.base.prev_blockhash = BlockHash::all_zeros();
        assert_eq!(config.checked_candidate_rules(frozen_config,&checkpoint,frozen,&history,&candidate),Err(DeploymentErrorV3::History));
        let rules = config.checked_rules(frozen_config,&checkpoint,frozen,&history,[8;32]).unwrap();
        assert!(rules.strict_der && rules.csv && rules.taproot && rules.sighash_rangeproof && rules.simplicity);
        assert!(!rules.cltv && !rules.usdd_sp1_annex);
        assert!(rules.p2sh && rules.witness);
        let exception = config.checked_rules(frozen_config,&checkpoint,frozen,&history,[9;32]).unwrap();
        assert!(!exception.p2sh && !exception.witness);
        assert_eq!(config.checked_rules([0;32],&checkpoint,frozen,&history,[8;32]),Err(DeploymentErrorV3::FrozenCommitment));
        assert_eq!(config.checked_rules(frozen_config,&checkpoint,[0;32],&history,[8;32]),Err(DeploymentErrorV3::FrozenCommitment));
        assert_eq!(config.checked_rules(frozen_config,&checkpoint,frozen,&history,[0;32]),Err(DeploymentErrorV3::History));
        assert_eq!(config.checked_rules(frozen_config,&checkpoint,frozen,&history[..11],[8;32]),Err(DeploymentErrorV3::History));
        let changed = ChildDeploymentConfigurationV3 {usdd_sp1_annex:true,..config};
        assert_eq!(changed.checked_rules(frozen_config,&checkpoint,frozen,&history,[8;32]),Err(DeploymentErrorV3::FrozenCommitment));
        let mut changed_checkpoint = checkpoint.clone();
        changed_checkpoint.configuration_commitment[0] ^= 1;
        assert_eq!(config.checked_rules(frozen_config,&changed_checkpoint,frozen,&history,[8;32]),Err(DeploymentErrorV3::FrozenCommitment));
        assert_eq!(deployment.state_after_history(&history,genesis,commitment),Ok(DeploymentStateV3::Active));
        assert_eq!(deployment.state_after_history(&history[1..],genesis,commitment),Err(DeploymentErrorV3::History));
        assert_eq!(deployment.state_after_history(&history[..11],genesis,commitment),Err(DeploymentErrorV3::FrozenCommitment));
        assert_eq!(deployment.state_after_history(&history,genesis,[0;32]),Err(DeploymentErrorV3::FrozenCommitment));
        history[11].base.version ^= 4;
        assert_eq!(deployment.state_after_history(&history,genesis,commitment),Err(DeploymentErrorV3::FrozenCommitment));
    }

    #[test]
    fn block_flags_follow_native_deployments_not_standardness_policy() {
        // Exhaust all independent selectors; no policy flags are inferred.
        for mask in 0u16..1024 {
            let bit = |n: u32| mask & (1u16 << n) != 0;
            let buried = BuriedFlagsV3 { height_in_coinbase: false,
                strict_der: bit(0), cltv: bit(1), csv: bit(2), segwit: bit(3) };
            let rules = buried.block_script_rules(bit(4),bit(5),bit(6),bit(7),bit(8),bit(9));
            assert_eq!(rules.p2sh,!bit(4));
            assert_eq!(rules.witness,!bit(4));
            assert_eq!(rules.strict_der,bit(0));
            assert_eq!(rules.cltv,bit(1));
            assert_eq!(rules.csv,bit(2));
            assert_eq!(rules.null_dummy,bit(3));
            assert_eq!(rules.taproot,bit(6));
            assert_eq!(rules.sighash_rangeproof,bit(5) && bit(7));
            assert_eq!(rules.simplicity,bit(5) && bit(8));
            assert_eq!(rules.usdd_sp1_annex,bit(9));
            let input = rules.base_input_rules();
            assert_eq!(input.script.verify_p2sh,rules.p2sh);
            assert_eq!(input.script.verify_witness,rules.witness);
            assert_eq!(input.script.verify_taproot,rules.taproot);
            assert_eq!(input.script.strict_der,rules.strict_der);
            assert_eq!(input.cltv,rules.cltv);
            assert_eq!(input.csv,rules.csv);
            assert_eq!(input.null_dummy,rules.null_dummy);
            assert_eq!(input.rangeproof_active,rules.sighash_rangeproof);
            assert_eq!(input.simplicity_active,rules.simplicity);
            assert!(input.native_execution);
            assert!(!input.script.low_s && !input.script.strict_encoding
                && !input.script.require_minimal_push && !input.script.require_minimal_if
                && !input.script.clean_stack && !input.script.witness_pubkey_type
                && !input.script.discourage_upgradable_witness_program
                && !input.null_fail && !input.discourage_upgradable_nops && !input.const_script_code);
        }
    }
    #[test]
    fn native_boundaries_and_signed_codec() {
        let rules = BuriedDeploymentsV3 {height_in_coinbase:0,strict_der:1,cltv:7,csv:8,segwit:i32::MAX};
        assert_eq!(rules.at_height(0).unwrap(),BuriedFlagsV3 {
            height_in_coinbase:true,strict_der:false,cltv:false,csv:false,segwit:false});
        assert!(rules.at_height(1).unwrap().strict_der);
        assert!(!rules.at_height(6).unwrap().cltv);
        assert!(rules.at_height(7).unwrap().cltv);
        assert!(!rules.at_height(7).unwrap().csv);
        assert!(rules.at_height(8).unwrap().csv);
        assert!(!rules.at_height(i32::MAX as u32-1).unwrap().segwit);
        assert!(rules.at_height(i32::MAX as u32).unwrap().segwit);
        assert_eq!(rules.at_height(i32::MAX as u32+1),Err(NativeHeightOverflow));
        let negative = BuriedDeploymentsV3 {csv:-1,..rules};
        assert!(negative.at_height(0).unwrap().csv);
        assert_eq!(&negative.canonical_bytes()[13..17],&[255;4]);
        assert_eq!(&rules.canonical_bytes()[17..21],&i32::MAX.to_be_bytes());
        for field in 0..5 {
            let mut altered = rules;
            match field {0=>altered.height_in_coinbase+=1,1=>altered.strict_der+=1,
                2=>altered.cltv+=1,3=>altered.csv+=1,_=>altered.segwit-=1}
            assert_ne!(rules.canonical_bytes(),altered.canonical_bytes());
        }
    }
}
