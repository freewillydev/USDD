//! Full native P/Q anchor. Ordering is necessary, not ancestry authentication.
//! This new encoding must not be substituted for the legacy 80-byte P endpoint.
use crate::{Hash32, FullAlphaReceiptVerifierV3};
use crate::conversion_parent_link_v3::{AlphaConversionParentLinkInputV3,
    AlphaConversionParentLinkPublicValuesV3, AlphaConversionLinkErrorV3,
    execute_alpha_conversion_parent_link_v3};
use bitcoin::hashes::Hash as _;

/// Hashes use internal byte order; work is unsigned big endian.
/// Fields remain private so a decoded anchor cannot skip shape validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBmmAnchorV1 {
    parent_hash: Hash32, mining_hash: Hash32,
    parent_work: Hash32, mining_work: Hash32,
    parent_height: u32, mining_height: u32, parent_mtp: u64,
}

impl NativeBmmAnchorV1 {
    pub const BYTES: usize = 145;

    pub fn parent_endpoint(&self) -> [u8;80] {
        let mut out=[0;80];let mut display=self.parent_hash;display.reverse();
        out[..32].copy_from_slice(&display);
        out[32..40].copy_from_slice(&u64::from(self.parent_height).to_be_bytes());
        out[40..48].copy_from_slice(&self.parent_mtp.to_be_bytes());
        out[48..].copy_from_slice(&self.parent_work);out
    }

    fn sane(&self) -> bool {
        ![self.parent_hash,self.mining_hash,self.parent_work,self.mining_work].contains(&[0;32])
            && self.parent_height.checked_add(1) == Some(self.mining_height)
            && self.mining_work > self.parent_work
            && self.parent_mtp <= u64::from(u32::MAX)
    }

    /// Equivalent to native DrivechainAnchor::Follows for sane anchors.
    /// Does NOT establish common-chain ancestry for a gap.
    pub fn follows_ordering(&self, prior: &Self) -> bool {
        if !self.sane() || !prior.sane() || self.parent_height < prior.mining_height { return false; }
        if self.parent_height == prior.mining_height {
            return self.parent_hash == prior.mining_hash && self.parent_work == prior.mining_work;
        }
        self.parent_work > prior.mining_work
    }

    /// Check selected-chain ancestry from prior Q through current P. Both
    /// anchors MUST already be independently authenticated by the caller.
    /// Receipt sequence alone is insufficient: frontier selection can reorg.
    /// Headers exclude prior Q and include current P. No PoW shortcut is
    /// implied: current P's complete consensus authentication is separate.
    pub fn follows_with_ancestry(&self, prior: &Self, headers: &[[u8;80]]) -> bool {
        if !self.follows_ordering(prior) { return false; }
        if u64::try_from(headers.len()).ok()
            != Some(u64::from(self.parent_height - prior.mining_height)) { return false; }
        let mut tip = prior.mining_hash;
        for header in headers {
            if header[4..36] != tip { return false; }
            tip = bitcoin::hashes::sha256d::Hash::hash(header).to_byte_array();
        }
        tip == self.parent_hash
    }

    /// Distinct canonical wire: version, P hash, Q hash, P work, Q work,
    /// BE u32 P height, BE u32 Q height, BE u64 P MTP.
    pub fn canonical_bytes(&self) -> [u8;Self::BYTES] {
        let mut out = [0;Self::BYTES]; out[0]=1;
        out[1..33].copy_from_slice(&self.parent_hash);
        out[33..65].copy_from_slice(&self.mining_hash);
        out[65..97].copy_from_slice(&self.parent_work);
        out[97..129].copy_from_slice(&self.mining_work);
        out[129..133].copy_from_slice(&self.parent_height.to_be_bytes());
        out[133..137].copy_from_slice(&self.mining_height.to_be_bytes());
        out[137..145].copy_from_slice(&self.parent_mtp.to_be_bytes()); out
    }

    /// Parsing establishes shape only. Caller must freeze/authenticate bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len()!=Self::BYTES || bytes[0]!=1 { return None; }
        let anchor = Self {
            parent_hash: bytes[1..33].try_into().ok()?, mining_hash: bytes[33..65].try_into().ok()?,
            parent_work: bytes[65..97].try_into().ok()?, mining_work: bytes[97..129].try_into().ok()?,
            parent_height: u32::from_be_bytes(bytes[129..133].try_into().ok()?),
            mining_height: u32::from_be_bytes(bytes[133..137].try_into().ok()?),
            parent_mtp: u64::from_be_bytes(bytes[137..145].try_into().ok()?),
        };
        anchor.sane().then_some(anchor)
    }

    /// Derive full anchor only after verifying exact selected P→Q/M7 receipts.
    pub fn authenticate<V: FullAlphaReceiptVerifierV3>(input: &AlphaConversionParentLinkInputV3,
        frozen_binding: Hash32, verifier: &V)
        -> Result<(AlphaConversionParentLinkPublicValuesV3,Self), AlphaConversionLinkErrorV3> {
        if frozen_binding == [0;32] || input.binding.commitment()? != frozen_binding {
            return Err(AlphaConversionLinkErrorV3::Binding);
        }
        let statement = execute_alpha_conversion_parent_link_v3(input,verifier)?;
        let p = &input.terminal_parent_predecessor;
        let q = &input.parent.terminal_selected_state;
        let anchor = Self {
            parent_hash:p.tip.block_hash.to_byte_array(), mining_hash:q.tip.block_hash.to_byte_array(),
            parent_work:p.tip.chainwork_be, mining_work:q.tip.chainwork_be,
            parent_height:p.tip.height, mining_height:q.tip.height,
            parent_mtp:u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                &p.pow_context.previous_11_times).map_err(|_|AlphaConversionLinkErrorV3::ParentBranch)?),
        };
        if !anchor.sane() { return Err(AlphaConversionLinkErrorV3::ParentBranch); }
        Ok((statement,anchor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn work(n:u8)->Hash32 { let mut w=[0;32];w[31]=n;w }
    fn prior()->NativeBmmAnchorV1 { NativeBmmAnchorV1 {
        parent_hash:[1;32],mining_hash:[2;32],parent_work:work(10),mining_work:work(11),
        parent_height:100,mining_height:101,parent_mtp:123,
    }}
    #[test]
    fn native_ordering_and_substitutions() {
        let p=prior();
        let mut next=NativeBmmAnchorV1 {parent_hash:p.mining_hash,mining_hash:[3;32],
            parent_work:p.mining_work,mining_work:work(12),parent_height:101,mining_height:102,parent_mtp:124};
        assert!(next.follows_ordering(&p));
        assert!(!p.follows_ordering(&p)); assert!(!p.follows_ordering(&next));
        next.parent_hash=[9;32]; assert!(!next.follows_ordering(&p));
        next.parent_hash=p.mining_hash;next.parent_work=work(10);assert!(!next.follows_ordering(&p));
        next.parent_height=103;next.mining_height=104;next.parent_work=work(12);next.mining_work=work(13);
        assert!(next.follows_ordering(&p)); // Still requires independent ancestry.
        next.parent_work=p.mining_work;assert!(!next.follows_ordering(&p));
    }
    #[test]
    fn canonical_shape_rejects_legacy_and_invalid_anchors() {
        let p=prior();let bytes=p.canonical_bytes();
        assert_eq!(NativeBmmAnchorV1::from_canonical_bytes(&bytes),Some(p.clone()));
        assert!(NativeBmmAnchorV1::from_canonical_bytes(&[1;80]).is_none());
        for index in [0,133,137] { let mut b=bytes;b[index]=255;
            assert!(NativeBmmAnchorV1::from_canonical_bytes(&b).is_none()); }
        for range in [1..33,33..65,65..97,97..129] {let mut b=bytes;b[range].fill(0);
            assert!(NativeBmmAnchorV1::from_canonical_bytes(&b).is_none());}
        let mut overflow=p;overflow.parent_height=u32::MAX;overflow.mining_height=0;
        assert!(!overflow.sane());
        let mut trailing=bytes.to_vec();trailing.push(0);
        assert!(NativeBmmAnchorV1::from_canonical_bytes(&trailing).is_none());
    }

    #[test]
    fn ancestry_requires_exact_selected_hash_chain() {
        let p=prior();
        let mut next=NativeBmmAnchorV1 {parent_hash:p.mining_hash,mining_hash:[3;32],
            parent_work:p.mining_work,mining_work:work(12),parent_height:101,mining_height:102,parent_mtp:124};
        assert!(next.follows_with_ancestry(&p,&[]));
        let mut h1=[0;80];h1[4..36].copy_from_slice(&p.mining_hash);
        let hash1=bitcoin::hashes::sha256d::Hash::hash(&h1).to_byte_array();
        let mut h2=[0;80];h2[4..36].copy_from_slice(&hash1);
        next.parent_hash=bitcoin::hashes::sha256d::Hash::hash(&h2).to_byte_array();
        next.parent_height=103;next.mining_height=104;
        next.parent_work=work(13);next.mining_work=work(14);
        assert!(next.follows_with_ancestry(&p,&[h1,h2]));
        assert!(!next.follows_with_ancestry(&p,&[]));
        assert!(!next.follows_with_ancestry(&p,&[h2]));
        assert!(!next.follows_with_ancestry(&p,&[h2,h1]));
        let mut altered=h1;altered[40]^=1;
        assert!(!next.follows_with_ancestry(&p,&[altered,h2]));
        let mut fork=p.clone();fork.mining_hash=[9;32];
        assert!(!next.follows_with_ancestry(&fork,&[h1,h2]));
        next.parent_hash[0]^=1;assert!(!next.follows_with_ancestry(&p,&[h1,h2]));
    }
}
