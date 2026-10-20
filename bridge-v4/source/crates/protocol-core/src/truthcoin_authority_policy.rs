//! Source-policy commitment for a keyless Truthcoin authority lane.
//!
//! This is not a proof, renderer, deployment record or release approval. Final
//! program IDs/CMRs must be qualified downstream, not included in source closure
//! inputs (which would create a configuration/program hash cycle). Oracle age
//! limits belong to the oracle configuration, not Ethereum's 13-day policy.
use crate::tagged_hash;
use sha2::{Digest, Sha256};

pub const STATE_DOMAIN: &[u8] = b"ECX_TRUTHCOIN_ANCHOR_STATE_NODE_V1";
pub const EXECUTION_DOMAIN: &[u8] = b"ECX_TRUTHCOIN_ANCHOR_EXECUTION_V1";
pub const KEYLESS_INTERNAL_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TruthcoinAuthoritySourcePolicyV1 {
    pub covenant_source_sha256: [u8; 32],
    pub compiler_source_closure_sha256: [u8; 32],
    pub catalogue_sha256: [u8; 32],
    pub projection_source_closure_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError { MissingSourceBinding, InvalidConfiguration, ProgramRole }

impl TruthcoinAuthoritySourcePolicyV1 {
    pub const ENCODED_LEN: usize = 227;

    /// Parameters for the generic keyless authority leaf. The outer authority
    /// program is downstream of this source policy, not the source replay ID.
    /// This validates bindings, not compilation, deployment or proof readiness.
    pub fn compiler_arguments(
        &self,
        authentication: &crate::oracle::TruthcoinAuthenticationConfigV1,
        deployment: &crate::truthcoin_anchor::TruthcoinAnchorDeploymentV1,
        policy_asset: [u8; 32],
        authority_program_id: [u8; 32],
    ) -> Result<String, PolicyError> {
        authentication.validate().map_err(|_| PolicyError::InvalidConfiguration)?;
        deployment.validate(policy_asset).map_err(|_| PolicyError::InvalidConfiguration)?;
        if policy_asset == [0; 32]
            || deployment.script_tree_configuration_hash != self.commitment()?
        { return Err(PolicyError::InvalidConfiguration); }
        if authority_program_id == [0; 32]
            || authority_program_id == authentication.source_proof_program_id
        { return Err(PolicyError::ProgramRole); }
        let mut fields = Vec::new();
        for (name, value) in [
            ("STATE_NODE_DOMAIN_SHA256", Sha256::digest(STATE_DOMAIN).into()),
            ("EXECUTION_DOMAIN_SHA256", Sha256::digest(EXECUTION_DOMAIN).into()),
            ("CONFIGURATION_HASH", crate::truthcoin_anchor::truthcoin_anchor_configuration_hash(
                authentication, deployment, policy_asset)),
            ("KEYLESS_INTERNAL_KEY", KEYLESS_INTERNAL_KEY),
            ("AUTHORITY_ASSET", deployment.authority_asset_id),
            ("POLICY_ASSET", policy_asset),
            ("PROJECTION_PROGRAM_ID", authority_program_id),
        ] {
            let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
            fields.push(format!("  \"{name}\": {{\"type\":\"u256\",\"value\":\"0x{hex}\"}}"));
        }
        fields.push("  \"TAPLEAF_VERSION\": {\"type\":\"u8\",\"value\":\"190\"}".into());
        fields.push(format!("  \"AUTHORITY_AMOUNT\": {{\"type\":\"u64\",\"value\":\"{}\"}}", deployment.authority_amount));
        Ok(format!("{{\n{}\n}}\n", fields.join(",\n")))
    }

    /// Version, four source hashes, two fixed domain hashes, NUMS key,
    /// Simplicity leaf version, and topology version (leaf plus state node).
    pub fn canonical_bytes(&self) -> Result<[u8; Self::ENCODED_LEN], PolicyError> {
        let sources = [self.covenant_source_sha256, self.compiler_source_closure_sha256,
            self.catalogue_sha256, self.projection_source_closure_sha256];
        if sources.contains(&[0; 32]) { return Err(PolicyError::MissingSourceBinding); }
        let mut out = [0; Self::ENCODED_LEN];
        out[0] = 1;
        for (i, source) in sources.iter().enumerate() {
            out[1 + i * 32..33 + i * 32].copy_from_slice(source);
        }
        out[129..161].copy_from_slice(&Sha256::digest(STATE_DOMAIN));
        out[161..193].copy_from_slice(&Sha256::digest(EXECUTION_DOMAIN));
        out[193..225].copy_from_slice(&KEYLESS_INTERNAL_KEY);
        out[225] = 0xbe;
        out[226] = 1;
        Ok(out)
    }

    pub fn commitment(&self) -> Result<[u8; 32], PolicyError> {
        Ok(tagged_hash("ECX/truthcoin-anchor-authority-source-policy/v1", &self.canonical_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> TruthcoinAuthoritySourcePolicyV1 {
        TruthcoinAuthoritySourcePolicyV1 { covenant_source_sha256: [1; 32],
            compiler_source_closure_sha256: [2; 32], catalogue_sha256: [3; 32],
            projection_source_closure_sha256: [4; 32] }
    }
    #[test]
    fn exact_encoding_and_role_separation() {
        let policy = fixture();
        let mut expected = vec![1];
        for n in 1..=4 { expected.extend_from_slice(&[n; 32]); }
        expected.extend_from_slice(&Sha256::digest(STATE_DOMAIN));
        expected.extend_from_slice(&Sha256::digest(EXECUTION_DOMAIN));
        expected.extend_from_slice(&KEYLESS_INTERNAL_KEY);
        expected.extend_from_slice(&[0xbe, 1]);
        assert_eq!(policy.canonical_bytes().unwrap().as_slice(), expected);
        let tag = Sha256::digest(b"ECX/truthcoin-anchor-authority-source-policy/v1");
        let mut h = Sha256::new(); h.update(tag); h.update(tag); h.update(&expected);
        assert_eq!(policy.commitment().unwrap(), <[u8; 32]>::from(h.finalize()));
        assert_ne!(Sha256::digest(STATE_DOMAIN), Sha256::digest(b"ECX_USDD_DEX_CHECKPOINT_STATE_NODE_V1"));
        assert_ne!(Sha256::digest(EXECUTION_DOMAIN), Sha256::digest(b"ECX_USDD_DEX_CHECKPOINT_EXECUTION_V1"));
        assert_ne!(policy.commitment().unwrap(), tagged_hash("ECX/usdd-checkpoint-authority-source-policy/v1", &expected));
    }
    #[test]
    fn every_source_is_required_and_committed() {
        for i in 0..4 {
            let mut p = fixture();
            fn select(p: &mut TruthcoinAuthoritySourcePolicyV1, i: usize) -> &mut [u8; 32] { match i {
                0 => &mut p.covenant_source_sha256,
                1 => &mut p.compiler_source_closure_sha256,
                2 => &mut p.catalogue_sha256,
                _ => &mut p.projection_source_closure_sha256,
            } }
            select(&mut p, i)[0] ^= 0x80;
            assert_ne!(p.commitment().unwrap(), fixture().commitment().unwrap());
            *select(&mut p, i) = [0; 32];
            assert_eq!(p.commitment(), Err(PolicyError::MissingSourceBinding));
        }
    }
}
