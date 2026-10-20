//! Deterministic public-pool compiler parameters and script materialization.
//! This does not establish that a supplied CMR implements the reviewed covenant.
//! The compiler/bytecode qualification gate must independently establish that.
use elements::{hashes::{sha256, Hash}, secp256k1_zkp::{Secp256k1, XOnlyPublicKey},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder}, Script};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPoolParametersV3 {
    pub child_genesis: [u8;32],
    pub base_asset: [u8;32],
    pub quote_asset: [u8;32],
    pub quote_atoms_per_whole_base: u64,
}

pub struct PublicPoolScriptsV3 {
    pub internal_key: XOnlyPublicKey,
    pub inventory_role: [u8;32],
    pub reserve_role: [u8;32],
    pub inventory_script: Script,
    pub reserve_script: Script,
    pub inventory_control: ControlBlock,
    pub reserve_control: ControlBlock,
}

/// Selected by the independently reviewed enclosing configuration, never by
/// the redemption witness. Hash pinning does not replace compiler qualification.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPublicPoolProgramV3 {
    pub parameters: PublicPoolParametersV3,
    pub compiled_cmr: [u8;32],
    pub program_sha256: [u8;32],
}

impl FrozenPublicPoolProgramV3 {
    pub fn validate(&self, program: &[u8], context: &crate::RedemptionProbeContextV3)
        -> Result<PublicPoolScriptsV3, &'static str> {
        if program.is_empty() || self.program_sha256 == [0;32]
            || sha256::Hash::hash(program).to_byte_array() != self.program_sha256
            || self.parameters.child_genesis != context.child_genesis
            || self.parameters.base_asset != context.classification.base_asset_id
            || self.parameters.quote_asset != context.classification.policy_asset_id
            || self.parameters.quote_atoms_per_whole_base != context.quote_atoms_per_whole_base {
            return Err("public pool program/context mismatch");
        }
        let scripts=self.parameters.scripts(self.compiled_cmr)?;
        if sha256::Hash::hash(scripts.inventory_script.as_bytes()).to_byte_array()
                != context.classification.redemption_inventory_script_sha256
            || sha256::Hash::hash(scripts.reserve_script.as_bytes()).to_byte_array()
                != context.classification.reserve_script_sha256 {
            return Err("public pool classification mismatch");
        }
        Ok(scripts)
    }
}

fn tagged(tag: &[u8], payload: &[u8]) -> [u8;32] {
    let tag = sha256::Hash::hash(tag).to_byte_array();
    let mut bytes = Vec::with_capacity(64+payload.len());
    bytes.extend_from_slice(&tag); bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(payload);
    sha256::Hash::hash(&bytes).to_byte_array()
}

/// Hash-to-x-coordinate by first valid lift, NOT scalar multiplication by a
/// hash (which would expose a private key). Counter is canonical u32 little-endian.
/// No caller-supplied key or random seed can introduce an operator key path.
pub fn public_pool_internal_key_v3() -> Result<XOnlyPublicKey, &'static str> {
    for counter in 0u32..1024 {
        let candidate = tagged(b"ECX/public-pool/keyless-internal-key/v3", &counter.to_le_bytes());
        if let Ok(key) = XOnlyPublicKey::from_slice(&candidate) { return Ok(key); }
    }
    Err("keyless point derivation exhausted")
}

impl PublicPoolParametersV3 {
    /// Network, asset order and fixed quote are bound into distinct role nodes.
    /// They are hidden hash commitments, not additional spendable script leaves.
    pub fn roles(&self) -> Result<([u8;32], [u8;32]), &'static str> {
        if self.child_genesis == [0;32] || self.base_asset == [0;32]
            || self.quote_asset == [0;32] || self.base_asset == self.quote_asset
            || self.quote_atoms_per_whole_base == 0 { return Err("invalid pool parameters"); }
        let mut payload = Vec::with_capacity(104);
        payload.extend_from_slice(&self.child_genesis);
        payload.extend_from_slice(&self.base_asset);
        payload.extend_from_slice(&self.quote_asset);
        payload.extend_from_slice(&self.quote_atoms_per_whole_base.to_le_bytes());
        let inventory = tagged(b"ECX/public-pool/inventory-role/v3", &payload);
        let reserve = tagged(b"ECX/public-pool/reserve-role/v3", &payload);
        if inventory == reserve { return Err("role collision"); }
        Ok((inventory,reserve))
    }

    pub fn scripts(&self, compiled_cmr: [u8;32]) -> Result<PublicPoolScriptsV3, &'static str> {
        if compiled_cmr == [0;32] { return Err("missing compiled CMR"); }
        let (inventory_role,reserve_role) = self.roles()?;
        let internal_key = public_pool_internal_key_v3()?;
        let secp = Secp256k1::verification_only();
        let leaf = Script::from(compiled_cmr.to_vec());
        let version = LeafVersion::from_u8(0xbe).map_err(|_| "leaf version")?;
        let materialize = |role| {
            let spend = TaprootBuilder::new().add_leaf_with_ver(1,leaf.clone(),version)
                .map_err(|_| "leaf")?.add_hidden(1,sha256::Hash::from_byte_array(role))
                .map_err(|_| "role")?.finalize(&secp,internal_key).map_err(|_| "tree")?;
            let control = spend.control_block(&(leaf.clone(),version)).ok_or("control")?;
            if !control.verify_taproot_commitment(&secp,&spend.output_key(),&leaf) {
                return Err("control verification");
            }
            Ok((Script::new_v1_p2tr(&secp,internal_key,spend.merkle_root()),control))
        };
        let (inventory_script,inventory_control) = materialize(inventory_role)?;
        let (reserve_script,reserve_control) = materialize(reserve_role)?;
        if inventory_script == reserve_script { return Err("script collision"); }
        Ok(PublicPoolScriptsV3 {internal_key,inventory_role,reserve_role,
            inventory_script,reserve_script,inventory_control,reserve_control})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn params() -> PublicPoolParametersV3 { PublicPoolParametersV3 {
        child_genesis:[1;32],base_asset:[2;32],quote_asset:[3;32],quote_atoms_per_whole_base:100_000_000,
    } }
    #[test]
    fn deterministic_keyless_roles_and_scripts() {
        let p=params(); let a=p.scripts([4;32]).unwrap(); let b=p.scripts([4;32]).unwrap();
        assert_eq!(a.internal_key,b.internal_key);
        assert_ne!(a.internal_key.to_string(),"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert_eq!(a.inventory_script,b.inventory_script);
        assert_ne!(a.inventory_script,a.reserve_script);
        assert_eq!(a.inventory_control.serialize().len(),65);
        assert_eq!(a.reserve_control.serialize().len(),65);
        assert_ne!(p.scripts([5;32]).unwrap().inventory_script,a.inventory_script);
    }
    #[test]
    fn every_policy_input_changes_both_roles() {
        let p=params(); let original=p.roles().unwrap();
        for field in 0..4 {
            let mut changed=p.clone();
            match field {0=>changed.child_genesis=[9;32],1=>changed.base_asset=[9;32],
                2=>changed.quote_asset=[9;32],_=>changed.quote_atoms_per_whole_base+=1}
            let roles=changed.roles().unwrap();
            assert_ne!(roles.0,original.0); assert_ne!(roles.1,original.1);
        }
    }
    #[test]
    fn frozen_program_rejects_substitution_and_context_changes() {
        let p=params();
        let program=b"synthetic program: hash binding only";
        let scripts=p.scripts([4;32]).unwrap();
        let mut context=crate::RedemptionProbeContextV3 {
            classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2 {
                base_asset_id:p.base_asset, policy_asset_id:p.quote_asset,
                redemption_inventory_script_sha256:sha256::Hash::hash(scripts.inventory_script.as_bytes()).to_byte_array(),
                reserve_script_sha256:sha256::Hash::hash(scripts.reserve_script.as_bytes()).to_byte_array(),
            },
            quote_atoms_per_whole_base:p.quote_atoms_per_whole_base,
            child_genesis:p.child_genesis, simplicity_evaluator_program_id:[8;32],
            outstanding_base_atoms:1, source_tip_height:1, source_tip_mtp:1,
        };
        let mut policy=FrozenPublicPoolProgramV3 {parameters:p,compiled_cmr:[4;32],
            program_sha256:sha256::Hash::hash(program).to_byte_array()};
        assert!(policy.validate(program,&context).is_ok());
        assert!(policy.validate(b"substituted",&context).is_err());
        assert!(policy.validate(b"",&context).is_err());
        context.child_genesis[0]^=1;
        assert!(policy.validate(program,&context).is_err());
        context.child_genesis=policy.parameters.child_genesis;
        context.quote_atoms_per_whole_base+=1;
        assert!(policy.validate(program,&context).is_err());
        context.quote_atoms_per_whole_base=policy.parameters.quote_atoms_per_whole_base;
        policy.compiled_cmr=[5;32];
        assert!(policy.validate(program,&context).is_err());
        policy.compiled_cmr=[4;32];
        std::mem::swap(&mut context.classification.redemption_inventory_script_sha256,
            &mut context.classification.reserve_script_sha256);
        assert!(policy.validate(program,&context).is_err());
    }
    #[test]
    fn reject_invalid_parameters() {
        for field in 0..5 {
            let mut p=params();
            match field {0=>p.child_genesis=[0;32],1=>p.base_asset=[0;32],2=>p.quote_asset=[0;32],
                3=>p.quote_asset=p.base_asset,_=>p.quote_atoms_per_whole_base=0}
            assert!(p.scripts([4;32]).is_err());
        }
        assert!(params().scripts([0;32]).is_err());
    }
}
