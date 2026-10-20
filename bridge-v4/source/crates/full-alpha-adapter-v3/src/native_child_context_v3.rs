//! Native child contextual rules over a history supplied by the caller.
//! The complete history/flags/observation clock must be authenticated by the
//! final recursive state relation. This module alone does not authenticate them.
use elements::{Block, BlockHeader};
use bitcoin::hashes::Hash;
use super::native_header_v3::NativeHeader;

pub struct ChildContext {
    /// Oldest first: exactly min(next_height, 11) predecessor headers.
    pub previous_headers: Vec<NativeHeader>,
    pub observation_time: u64,
    pub csv_active: bool,
    pub height_in_coinbase_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError { History, Time, Nonfinal, CoinbaseHeight }

/// Frozen deployment inputs needed for the native legacy-to-DynaFed conversion.
/// None may be inferred from a candidate's self-declared proposed parameters.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDynafedBootstrap {
    pub legacy_challenge: elements::Script,
    pub maximum_signature_size: u32,
    pub fedpeg_script: Vec<u8>,
    pub start_p2wsh: bool,
    pub first_extension_space: Vec<Vec<u8>>,
}

impl NativeDynafedBootstrap {
    /// Matches ComputeNextBlockFullCurrentParameters' legacy script conversion.
    /// Deployment activation height and epoch selection must be checked separately.
    pub fn full_parameters(&self) -> elements::dynafed::FullParams {
        fn p2wsh(script: &[u8]) -> Vec<u8> {
            let mut program=vec![0,32];
            program.extend_from_slice(&bitcoin::hashes::sha256::Hash::hash(script).to_byte_array());
            program
        }
        let signblock=elements::Script::from(p2wsh(self.legacy_challenge.as_bytes()));
        let redeem=p2wsh(&self.fedpeg_script);
        let fedpeg_program=if self.start_p2wsh {redeem} else {
            let mut program=vec![0xa9,20];
            program.extend_from_slice(&bitcoin::hashes::hash160::Hash::hash(&redeem).to_byte_array());
            program.push(0x87); program
        };
        elements::dynafed::FullParams::new(signblock,self.maximum_signature_size,
            bitcoin::ScriptBuf::from_bytes(fedpeg_program),self.fedpeg_script.clone(),
            self.first_extension_space.clone())
    }
}

/// Native parameter selection, including legacy conversion and the Elements
/// always-active genesis exception. History must already be consensus-qualified
/// by the recursive predecessor relation; linkage alone is not authentication.
/// Supply exactly the preceding epoch (at a boundary), or the current epoch
/// prefix otherwise, including genesis when that epoch starts at zero.
pub fn select_native_dynafed_parameters(
    headers:&[NativeHeader], epoch_length:u32, next_height:u32,
    elements_always_active:bool, bootstrap:&NativeDynafedBootstrap,
) -> Result<ecx_full_consensus_validator_v2::elements_v2::ElementsDerivedDynafedParametersV2,
    ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    use elements::{BlockExtData, dynafed::Params};
    let error=ElementsStateErrorV2::HeaderConsensus;
    if epoch_length==0 || next_height==0 {return Err(error);}
    let age=next_height%epoch_length;
    let count=if age==0 {epoch_length} else {age};
    let start=next_height.checked_sub(count).ok_or(ElementsStateErrorV2::HeaderConsensus)?;
    if headers.len()!=count as usize {return Err(error);}
    for (index,header) in headers.iter().enumerate() {
        if header.base.height!=start+index as u32 {return Err(error);}
        // Hash even the tip so malformed native representations cannot escape.
        header.hash_internal().map_err(|_|ElementsStateErrorV2::HeaderConsensus)?;
        if index>0 && header.base.prev_blockhash.to_byte_array()!=headers[index-1]
            .hash_internal().map_err(|_|ElementsStateErrorV2::HeaderConsensus)? {return Err(error);}
    }
    let mut winner=None;
    if age==0 {
        let threshold=epoch_length-epoch_length/5;
        let mut votes=std::collections::BTreeMap::<[u8;32],u32>::new();
        for header in headers.iter().rev() {
            if let BlockExtData::Dynafed {proposed,..}=&header.base.ext {
                if proposed.is_null() {continue;}
                let tally=votes.entry(proposed.calculate_root().to_byte_array()).or_default();
                *tally+=1;
                if *tally>=threshold {
                    winner=Some(proposed.full().cloned().ok_or(ElementsStateErrorV2::HeaderConsensus)?);
                    break;
                }
            }
        }
    }
    let full=if let Some(winner)=winner {winner} else {
        let selected=if elements_always_active && start==0 && next_height>1 {1} else {0};
        match &headers.get(selected).ok_or(ElementsStateErrorV2::HeaderConsensus)?.base.ext {
            BlockExtData::Proof {challenge,..} => {
                // The challenge comes from the selected authenticated ancestor,
                // not from the candidate or an unrelated configured script.
                if challenge!=&bootstrap.legacy_challenge {return Err(error);}
                bootstrap.full_parameters()
            },
            BlockExtData::Dynafed {current,..} => current.full().cloned()
                .ok_or(ElementsStateErrorV2::HeaderConsensus)?,
        }
    };
    let previous_legacy=matches!(headers.last().unwrap().base.ext,BlockExtData::Proof {..});
    Ok(ElementsDerivedDynafedParametersV2 {
        expected_current:if age==0 || previous_legacy {Params::Full(full.clone())}
            else {full.clone().into_compact()},
        expected_full_current:full,
    })
}

/// Full-state authorization adapter for an authenticated DynaFed epoch.
/// Startup-capable variant. Activation height and deployment settings must be
/// authenticated by the final recursive relation, never selected by a witness.
pub struct NativeDeploymentAuthorization<'a> {
    pub headers: &'a [NativeHeader],
    pub epoch_length: u32,
    pub dynafed_activation_height: u32,
    pub elements_always_active: bool,
    pub bootstrap: &'a NativeDynafedBootstrap,
}

impl super::native_header_signature_v3::NativeHeaderAuthorization for NativeDeploymentAuthorization<'_> {
    fn authorize(&self, header:&NativeHeader,
        context:&ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2)
        -> Result<(),ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        if header.base.height < self.dynafed_activation_height {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
        let tip=self.headers.last().ok_or(ElementsStateErrorV2::HeaderConsensus)?;
        let tip_hash=tip.hash_internal().map_err(|_|ElementsStateErrorV2::HeaderConsensus)?;
        if header.base.prev_blockhash.to_byte_array()!=tip_hash
            || context.previous_block_hash.to_byte_array()!=tip_hash
            || context.next_height!=header.base.height {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
        let derived=select_native_dynafed_parameters(self.headers,self.epoch_length,
            header.base.height,self.elements_always_active,self.bootstrap)?;
        if context.expected_current_dynafed_params.as_ref()!=Some(&derived.expected_current)
            || context.expected_full_current_dynafed_params.as_ref()!=Some(&derived.expected_full_current) {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
        super::native_header_signature_v3::NativeHeaderScriptVerifier.authorize(header,context)
    }
}

/// Full-state authorization adapter for an authenticated DynaFed epoch.
/// Supplying history does not itself prove its deployment or source authenticity.
pub struct NativeEpochAuthorization<'a> {
    pub headers: &'a [NativeHeader],
    pub epoch_length: u32,
}

impl super::native_header_signature_v3::NativeHeaderAuthorization for NativeEpochAuthorization<'_> {
    fn authorize(&self, header: &NativeHeader,
        context: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2)
        -> Result<(),ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
        use ecx_full_consensus_validator_v2::elements_v2::*;
        let tip = self.headers.last().ok_or(ElementsStateErrorV2::HeaderConsensus)?;
        let tip_hash = tip.hash_internal().map_err(|_| ElementsStateErrorV2::HeaderConsensus)?;
        if header.base.prev_blockhash.to_byte_array() != tip_hash
            || context.previous_block_hash.to_byte_array() != tip_hash
            || context.next_height != header.base.height {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
        let derived = derive_native_dynafed_parameters(self.headers,self.epoch_length,header.base.height)?;
        if context.expected_current_dynafed_params.as_ref() != Some(&derived.expected_current)
            || context.expected_full_current_dynafed_params.as_ref() != Some(&derived.expected_full_current) {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
        super::native_header_signature_v3::NativeHeaderScriptVerifier.authorize(header,context)
    }
}

/// Derive DynaFed parameters without replacing native epoch history by lossy
/// upstream hashes. Authentication of the epoch and its configured length is
/// still an obligation of the recursive predecessor state.
pub fn derive_native_dynafed_parameters(
    headers: &[NativeHeader], epoch_length: u32, next_height: u32,
) -> Result<ecx_full_consensus_validator_v2::elements_v2::ElementsDerivedDynafedParametersV2,
    ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    let hashes = headers.iter().map(|header| header.hash_internal()
        .map(elements::BlockHash::from_byte_array)
        .map_err(|_| ElementsStateErrorV2::HeaderConsensus))
        .collect::<Result<Vec<_>,_>>()?;
    derive_expected_dynafed_parameters_with_hashes_v3(&ElementsDynafedEpochHistoryV2 {
        epoch_length, headers:headers.iter().map(|header| header.base.clone()).collect(),
    },next_height,&hashes)
}

/// Bind the header authorization verifier to the exact history used by child
/// transaction finality. Signer/deployment parameters remain a recursive-state
/// obligation; this does not make caller-provided parameters authoritative.
pub fn verify_header_authorization<V: ecx_full_consensus_validator_v2::elements_v2::ElementsBlockAuthorizationVerifierV2>(
    block: &Block, context: &ChildContext,
    authorization: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2,
    verifier: &V,
) -> Result<(), ecx_full_consensus_validator_v2::elements_v2::ElementsStateErrorV2> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    verify_child_context(block,context).map_err(|_| ElementsStateErrorV2::HeaderConsensus)?;
    let times: Vec<_> = context.previous_headers.iter().map(|header| header.base.time).collect();
    if authorization.previous_11_times != times
        || authorization.authenticated_adjusted_time != context.observation_time {
        return Err(ElementsStateErrorV2::HeaderConsensus);
    }
    verify_elements_contextual_header_native_v3(block,authorization,verifier)
}

/// Derive the UTXO spend context and native lock policy from the same checked
/// history, avoiding a separate caller-selected cutoff for each transaction.
pub fn derive_spend_rules(block: &Block, context: &ChildContext) -> Result<(
    ecx_full_consensus_validator_v2::elements_v2::ElementsTransactionSpendContextV2,
    ecx_full_consensus_validator_v2::elements_v2::NativeElementsLockPolicyV3,
), ContextError> {
    use ecx_full_consensus_validator_v2::elements_v2::*;
    let median = verify_child_context(block,context)?;
    Ok((ElementsTransactionSpendContextV2 {height:block.header.height,parent_mtp:median},
        NativeElementsLockPolicyV3 {csv_active:context.csv_active,
            absolute_time_cutoff:if context.csv_active {median} else {block.header.time}}))
}

pub fn verify_child_context(block: &Block, context: &ChildContext) -> Result<u32, ContextError> {
    let height = block.header.height;
    // Genesis requires a separate frozen genesis relation, not a fabricated predecessor.
    if height == 0 || context.previous_headers.len() != (height as usize).min(11) {
        return Err(ContextError::History);
    }
    let first_height = height - context.previous_headers.len() as u32;
    for (index, header) in context.previous_headers.iter().enumerate() {
        if header.base.height != first_height + index as u32 { return Err(ContextError::History); }
        if index > 0 && header.base.prev_blockhash.to_byte_array() != context.previous_headers[index - 1].hash_internal().map_err(|_| ContextError::History)? {
            return Err(ContextError::History);
        }
    }
    if context.previous_headers.last().unwrap().hash_internal().map_err(|_| ContextError::History)? != block.header.prev_blockhash.to_byte_array() {
        return Err(ContextError::History);
    }
    let mut times: Vec<_> = context.previous_headers.iter().map(|h| h.base.time).collect();
    times.sort_unstable();
    let median = times[times.len()/2];
    let limit = context.observation_time.checked_add(7200).ok_or(ContextError::Time)?;
    if block.header.time <= median || u64::from(block.header.time) > limit { return Err(ContextError::Time); }
    let cutoff = if context.csv_active { median } else { block.header.time };
    for tx in &block.txdata {
        let lock = tx.lock_time.to_consensus_u32();
        let comparison = if lock < 500_000_000 { height } else { cutoff };
        if lock != 0 && lock >= comparison && tx.input.iter().any(|i| !i.sequence.is_final()) {
            return Err(ContextError::Nonfinal);
        }
    }
    if context.height_in_coinbase_active {
        let coinbase = block.txdata.first().filter(|tx| tx.is_coinbase()).ok_or(ContextError::CoinbaseHeight)?;
        let prefix = elements::script::Builder::new().push_int(i64::from(height)).into_script();
        if !coinbase.input[0].script_sig.as_bytes().starts_with(prefix.as_bytes()) {
            return Err(ContextError::CoinbaseHeight);
        }
    }
    Ok(median)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use elements::{BlockHash,TxMerkleNode,BlockExtData,Script,Transaction,TxIn,TxOut,LockTime,Sequence};
    fn fixture(height: u32) -> (Block,ChildContext) {
        let mut headers = Vec::<BlockHeader>::new();
        for h in height.saturating_sub(11)..height {
            let prev = headers.last().map(|p| p.block_hash()).unwrap_or(BlockHash::all_zeros());
            headers.push(BlockHeader {version:4,prev_blockhash:prev,merkle_root:TxMerkleNode::all_zeros(),
                time:500_000_100+h,height:h,ext:BlockExtData::Proof {challenge:Script::new(),solution:Script::new()}});
        }
        let mut header = headers.last().unwrap().clone();
        header.prev_blockhash = header.block_hash(); header.height = height; header.time += 10;
        let mut script = elements::script::Builder::new().push_int(i64::from(height)).into_script().into_bytes();
        script.push(0);
        let cb = Transaction {version:2,lock_time:LockTime::ZERO,
            input:vec![TxIn {script_sig:Script::from(script),..TxIn::default()}],output:vec![TxOut::default()]};
        (Block {header,txdata:vec![cb]},ChildContext {previous_headers:headers.into_iter().map(NativeHeader::from_standard).collect(),observation_time:500_001_000,
            csv_active:true,height_in_coinbase_active:true})
    }
    #[test]
    fn deployment_authorization_checks_first_dynafed_witness() {
        use super::super::native_header_signature_v3::NativeHeaderAuthorization;
        use ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2;
        use elements::dynafed::Params;
        let (_,context)=fixture(1);
        let mut headers=context.previous_headers;
        headers[0].base.ext=BlockExtData::Proof {challenge:Script::from(vec![0x51]),solution:Script::new()};
        let bootstrap=NativeDynafedBootstrap {legacy_challenge:Script::from(vec![0x51]),
            maximum_signature_size:100,fedpeg_script:vec![0x52],start_p2wsh:true,first_extension_space:vec![]};
        let full=bootstrap.full_parameters();
        let mut candidate=headers[0].clone();
        candidate.base.height=1; candidate.base.time+=10;
        candidate.base.prev_blockhash=BlockHash::from_byte_array(headers[0].hash_internal().unwrap());
        candidate.base.ext=BlockExtData::Dynafed {current:Params::Full(full.clone()),
            proposed:Params::Null,signblock_witness:vec![vec![0x51]]};
        let auth=ElementsHeaderConsensusContextV2 {
            previous_block_hash:candidate.base.prev_blockhash,next_height:1,
            previous_11_times:vec![headers[0].base.time],authenticated_adjusted_time:500_001_000,
            expected_current_dynafed_params:Some(Params::Full(full.clone())),
            expected_full_current_dynafed_params:Some(full),legacy_signblock_challenge:Script::new(),
            legacy_signblock_witness_limit:100,
        };
        let verifier=NativeDeploymentAuthorization {headers:&headers,epoch_length:5,
            dynafed_activation_height:1,elements_always_active:true,bootstrap:&bootstrap};
        assert!(verifier.authorize(&candidate,&auth).is_ok());
        if let BlockExtData::Dynafed {signblock_witness,..}=&mut candidate.base.ext {
            *signblock_witness=vec![vec![0x52]];
        }
        assert!(verifier.authorize(&candidate,&auth).is_err());
        if let BlockExtData::Dynafed {signblock_witness,..}=&mut candidate.base.ext {signblock_witness.clear();}
        assert!(verifier.authorize(&candidate,&auth).is_err());
    }
    #[test]
    fn native_startup_selection_and_first_epoch_exception() {
        use elements::dynafed::Params;
        let bootstrap=NativeDynafedBootstrap {legacy_challenge:Script::new(),
            maximum_signature_size:123,fedpeg_script:vec![0x52],start_p2wsh:true,
            first_extension_space:vec![]};
        let full=bootstrap.full_parameters();
        let (_,context)=fixture(4);
        let mut headers=context.previous_headers;
        // A legacy predecessor requires full parameters even mid-epoch.
        let first=select_native_dynafed_parameters(&headers[..1],5,1,true,&bootstrap).unwrap();
        assert_eq!(first.expected_current,Params::Full(full.clone()));
        assert_eq!(select_native_dynafed_parameters(&headers,5,4,false,&bootstrap).unwrap().expected_current,
            Params::Full(full.clone()));
        // Always-active Elements stores full parameters at height one, not genesis.
        let alternate=elements::dynafed::FullParams::new(Script::from(vec![0x51]),77,
            bitcoin::ScriptBuf::new(),vec![],vec![]);
        for index in 1..headers.len() {
            headers[index].base.ext=BlockExtData::Dynafed {
                current:if index==1 {Params::Full(alternate.clone())} else {alternate.clone().into_compact()},
                proposed:Params::Null,signblock_witness:vec![]};
            headers[index].base.prev_blockhash=BlockHash::from_byte_array(headers[index-1].hash_internal().unwrap());
        }
        assert_eq!(select_native_dynafed_parameters(&headers,5,4,true,&bootstrap).unwrap().expected_current,
            alternate.clone().into_compact());
        assert_eq!(select_native_dynafed_parameters(&headers,5,4,false,&bootstrap).unwrap().expected_current,
            full.into_compact());
        // Boundary votes take precedence over the legacy epoch-start fallback.
        let proposal=elements::dynafed::FullParams::new(Script::from(vec![0x52]),88,
            bitcoin::ScriptBuf::new(),vec![],vec![]);
        for header in &mut headers[1..] {
            if let BlockExtData::Dynafed {proposed,..}=&mut header.base.ext {*proposed=Params::Full(proposal.clone());}
        }
        for index in 1..headers.len() {
            headers[index].base.prev_blockhash=BlockHash::from_byte_array(headers[index-1].hash_internal().unwrap());
        }
        // Three of four is below ceil(80%); preserve the selected height-one entry.
        assert_eq!(select_native_dynafed_parameters(&headers,4,4,true,&bootstrap).unwrap().expected_current,
            Params::Full(alternate));
        let mut fifth=headers.last().unwrap().clone();
        fifth.base.height=4;
        fifth.base.prev_blockhash=BlockHash::from_byte_array(headers.last().unwrap().hash_internal().unwrap());
        let mut voting=headers.clone(); voting.push(fifth);
        assert_eq!(select_native_dynafed_parameters(&voting,5,5,true,&bootstrap).unwrap().expected_current,
            Params::Full(proposal));
        assert!(select_native_dynafed_parameters(&headers,0,4,true,&bootstrap).is_err());
        assert!(select_native_dynafed_parameters(&headers[1..],5,4,true,&bootstrap).is_err());
        headers[2].base.time^=1;
        assert!(select_native_dynafed_parameters(&headers,5,4,true,&bootstrap).is_err());
    }
    #[test]
    fn bootstrap_matches_native_cpp_wire_and_roots() {
        #[derive(serde::Deserialize)]
        struct Vector { name:String, wire:String, root:String }
        #[derive(serde::Deserialize)]
        struct Corpus { bootstrap:Vec<Vector> }
        fn hex(bytes:&[u8])->String { bytes.iter().map(|b|format!("{b:02x}")).collect() }
        let corpus:Corpus=serde_json::from_str(include_str!("../test-vectors/native-header-wire.json")).unwrap();
        assert_eq!(corpus.bootstrap.len(),8);
        for wrapped in 0..2 {
            for variant in 0..4 {
                let name=format!("{wrapped}-{variant}");
                let vector=corpus.bootstrap.iter().find(|v|v.name==name).unwrap();
                let bootstrap=NativeDynafedBootstrap {
                    legacy_challenge:Script::from(if variant==1 {vec![]} else {vec![0x51]}),
                    maximum_signature_size:123,
                    fedpeg_script:if variant==2 {vec![]} else {vec![0x52]},
                    start_p2wsh:wrapped==0,
                    first_extension_space:if variant==3 {vec![]} else {vec![vec![1,2],vec![3]]},
                };
                let params=elements::dynafed::Params::Full(bootstrap.full_parameters());
                assert_eq!(hex(&elements::encode::serialize(&params)),vector.wire,"wire {name}");
                assert_eq!(hex(&params.calculate_root().to_byte_array()),vector.root,"root {name}");
            }
        }
    }
    #[test]
    fn legacy_bootstrap_preserves_scripts_limits_and_extensions() {
        let mut bootstrap=NativeDynafedBootstrap {
            legacy_challenge:Script::from(vec![0x51]),maximum_signature_size:123,
            fedpeg_script:vec![0x52],start_p2wsh:true,first_extension_space:vec![vec![1,2],vec![3]],
        };
        let full=elements::dynafed::Params::Full(bootstrap.full_parameters());
        let signblock=full.signblockscript().unwrap().as_bytes();
        assert_eq!(&signblock[..2],&[0,32]);
        assert_eq!(&signblock[2..],&bitcoin::hashes::sha256::Hash::hash(&[0x51]).to_byte_array());
        assert_eq!(full.signblock_witness_limit(),Some(123));
        let direct=full.fedpeg_program().unwrap().as_bytes().to_vec();
        assert_eq!(&direct[..2],&[0,32]);
        assert_eq!(&direct[2..],&bitcoin::hashes::sha256::Hash::hash(&[0x52]).to_byte_array());
        bootstrap.start_p2wsh=false;
        let wrapped=elements::dynafed::Params::Full(bootstrap.full_parameters());
        let bytes=wrapped.fedpeg_program().unwrap().as_bytes();
        assert_eq!(&bytes[..2],&[0xa9,20]); assert_eq!(bytes[22],0x87);
        assert_eq!(&bytes[2..22],&bitcoin::hashes::hash160::Hash::hash(&direct).to_byte_array());
        assert_ne!(wrapped.calculate_root(),full.calculate_root());
        bootstrap.first_extension_space.push(vec![4]);
        assert_ne!(elements::dynafed::Params::Full(bootstrap.full_parameters()).calculate_root(),wrapped.calculate_root());
    }
    #[test]
    fn dynafed_votes_require_ceiling_four_fifths() {
        use elements::dynafed::{FullParams,Params};
        let full = FullParams::new(Script::from(vec![0x51]),100,bitcoin::ScriptBuf::new(),vec![],vec![]);
        let proposal = FullParams::new(Script::from(vec![0x52]),100,bitcoin::ScriptBuf::new(),vec![],vec![]);
        for length in 1..=16u32 {
            let threshold = length-length/5;
            for votes in [threshold-1,threshold] {
                let (block,_) = fixture(1);
                let mut headers:Vec<NativeHeader> = vec![];
                for offset in 0..length {
                    let mut header = NativeHeader::from_standard(block.header.clone());
                    header.base.height = length+offset;
                    header.base.version |= super::super::native_header_v3::EXCHANGE;
                    header.exchange = [offset as u8+1;32];
                    if let Some(previous) = headers.last() { header.base.prev_blockhash=BlockHash::from_byte_array(previous.hash_internal().unwrap()); }
                    header.base.ext = BlockExtData::Dynafed {
                        current:if offset==0 {Params::Full(full.clone())} else {full.clone().into_compact()},
                        proposed:if offset<votes {Params::Full(proposal.clone())} else {Params::Null},
                        signblock_witness:vec![],
                    };
                    headers.push(header);
                }
                let derived=derive_native_dynafed_parameters(&headers,length,length*2).unwrap();
                assert_eq!(derived.expected_current,Params::Full(if votes>=threshold {proposal.clone()} else {full.clone()}),"length={length},votes={votes}");
            }
        }
    }
    #[test]
    fn dynafed_epoch_derivation_retains_native_links() {
        use elements::dynafed::{FullParams,Params};
        let full = FullParams::new(Script::from(vec![0x51]),100,bitcoin::ScriptBuf::new(),vec![],vec![]);
        let (_,context) = fixture(5);
        let mut headers = context.previous_headers;
        for index in 0..headers.len() {
            if index > 0 { headers[index].base.prev_blockhash = BlockHash::from_byte_array(headers[index-1].hash_internal().unwrap()); }
            headers[index].base.version |= super::super::native_header_v3::EXCHANGE;
            headers[index].exchange = [index as u8+1;32];
            headers[index].base.ext = BlockExtData::Dynafed {
                current:if index == 0 {Params::Full(full.clone())} else {full.clone().into_compact()},
                proposed:Params::Null,signblock_witness:vec![],
            };
        }
        let derived = derive_native_dynafed_parameters(&headers,5,5).unwrap();
        assert_eq!(derived.expected_current,Params::Full(full.clone()));
        assert_eq!(derived.expected_full_current,full.clone());
        use super::super::native_header_signature_v3::NativeHeaderAuthorization;
        use ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2;
        let mut candidate = headers.last().unwrap().clone();
        candidate.base.prev_blockhash = BlockHash::from_byte_array(candidate.hash_internal().unwrap());
        candidate.base.height = 5; candidate.base.time += 10;
        candidate.base.ext = BlockExtData::Dynafed {current:Params::Full(full.clone()),proposed:Params::Null,signblock_witness:vec![]};
        let auth = ElementsHeaderConsensusContextV2 {
            previous_block_hash:candidate.base.prev_blockhash,next_height:5,
            previous_11_times:headers.iter().map(|h| h.base.time).collect(),
            authenticated_adjusted_time:500_001_000,
            expected_current_dynafed_params:Some(Params::Full(full.clone())),
            expected_full_current_dynafed_params:Some(full.clone()),
            legacy_signblock_challenge:Script::new(),legacy_signblock_witness_limit:100,
        };
        let verifier = NativeEpochAuthorization {headers:&headers,epoch_length:5};
        assert!(verifier.authorize(&candidate,&auth).is_ok());
        let bootstrap=NativeDynafedBootstrap {legacy_challenge:Script::new(),
            maximum_signature_size:100,fedpeg_script:vec![],start_p2wsh:true,first_extension_space:vec![]};
        let mut deployment=NativeDeploymentAuthorization {headers:&headers,epoch_length:5,
            dynafed_activation_height:1,elements_always_active:false,bootstrap:&bootstrap};
        assert!(deployment.authorize(&candidate,&auth).is_ok());
        deployment.dynafed_activation_height=6;
        assert!(deployment.authorize(&candidate,&auth).is_err());
        deployment.dynafed_activation_height=1;
        let mut wrong = auth.clone(); wrong.expected_current_dynafed_params=Some(full.clone().into_compact());
        assert!(verifier.authorize(&candidate,&wrong).is_err());
        assert!(deployment.authorize(&candidate,&wrong).is_err());
        let mut wrong = candidate.clone(); wrong.base.prev_blockhash=headers.last().unwrap().base.block_hash();
        assert!(verifier.authorize(&wrong,&auth).is_err());
        assert!(deployment.authorize(&wrong,&auth).is_err());
        let mut other_history = headers.clone(); other_history.last_mut().unwrap().exchange[0] ^= 1;
        assert!(NativeEpochAuthorization {headers:&other_history,epoch_length:5}.authorize(&candidate,&auth).is_err());
        let mid = derive_native_dynafed_parameters(&headers[..3],5,3).unwrap();
        assert_eq!(mid.expected_current,full.into_compact());
        for index in 0..headers.len()-1 {
            headers[index].exchange[0] ^= 1;
            assert!(derive_native_dynafed_parameters(&headers,5,5).is_err());
            headers[index].exchange[0] ^= 1;
        }
        assert!(derive_native_dynafed_parameters(&headers,0,5).is_err());
        assert!(derive_native_dynafed_parameters(&headers[..4],5,5).is_err());
    }
    #[test]
    fn native_history_binds_extensions_at_every_predecessor() {
        let (mut block,mut context) = fixture(12);
        for index in 0..context.previous_headers.len() {
            let previous = if index > 0 {
                Some(BlockHash::from_byte_array(context.previous_headers[index-1].hash_internal().unwrap()))
            } else { None };
            let header = &mut context.previous_headers[index];
            header.base.version |= super::super::native_header_v3::EXCHANGE;
            header.exchange = [index as u8+1;32];
            if let Some(previous) = previous { header.base.prev_blockhash = previous; }
        }
        block.header.prev_blockhash = BlockHash::from_byte_array(context.previous_headers.last().unwrap().hash_internal().unwrap());
        assert!(verify_child_context(&block,&context).is_ok());
        for index in 0..context.previous_headers.len() {
            context.previous_headers[index].exchange[0] ^= 1;
            assert_eq!(verify_child_context(&block,&context),Err(ContextError::History));
            context.previous_headers[index].exchange[0] ^= 1;
        }
        // A tip linked to the upstream projection cannot authenticate this chain.
        block.header.prev_blockhash = context.previous_headers.last().unwrap().base.block_hash();
        assert_eq!(verify_child_context(&block,&context),Err(ContextError::History));
    }
    #[test]
    fn spend_rules_share_checked_history_and_activation_cutoff() {
        let (b,mut c) = fixture(12);
        let median = verify_child_context(&b,&c).unwrap();
        for active in [true,false] {
            c.csv_active = active;
            let (spend,policy) = derive_spend_rules(&b,&c).unwrap();
            assert_eq!(spend.height,b.header.height);
            assert_eq!(spend.parent_mtp,median);
            assert_eq!(policy.csv_active,active);
            assert_eq!(policy.absolute_time_cutoff,if active {median} else {b.header.time});
        }
        c.previous_headers[0].base.time ^= 1;
        assert!(matches!(derive_spend_rules(&b,&c),Err(ContextError::History)));
    }
    #[test]
    fn early_chain_and_full_history_medians() {
        for h in [1,2,10,11,12,128] {
            let (b,c) = fixture(h);
            let start = h.saturating_sub(11);
            assert_eq!(verify_child_context(&b,&c),Ok(500_000_100+start+h.min(11)/2));
        }
        let (b,mut c) = fixture(12); c.previous_headers.remove(0);
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::History));
    }
    #[test]
    fn broken_history_and_tip_rejected() {
        let (b,mut c) = fixture(12); c.previous_headers[0].base.time ^= 1;
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::History));
        let (mut b,c) = fixture(12); b.header.prev_blockhash = BlockHash::all_zeros();
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::History));
    }
    #[test]
    fn time_boundaries() {
        let (mut b,mut c) = fixture(12); let median = verify_child_context(&b,&c).unwrap();
        b.header.time = median;
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::Time));
        b.header.time = (c.observation_time+7200) as u32;
        assert!(verify_child_context(&b,&c).is_ok());
        b.header.time += 1;
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::Time));
        c.observation_time = u64::MAX;
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::Time));
    }
    #[test]
    fn finality_uses_strict_cutoff_and_final_sequence_override() {
        let (mut b,mut c) = fixture(12); let median = verify_child_context(&b,&c).unwrap();
        b.txdata[0].input[0].sequence = Sequence::from_consensus(0);
        b.txdata[0].lock_time = LockTime::from_consensus(median);
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::Nonfinal));
        c.csv_active = false; assert!(verify_child_context(&b,&c).is_ok());
        b.txdata[0].lock_time = LockTime::from_consensus(12);
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::Nonfinal));
        b.txdata[0].lock_time = LockTime::from_consensus(11);
        assert!(verify_child_context(&b,&c).is_ok());
        b.txdata[0].lock_time = LockTime::from_consensus(u32::MAX);
        b.txdata[0].input[0].sequence = Sequence::MAX;
        assert!(verify_child_context(&b,&c).is_ok());
    }
    #[test]
    fn exact_coinbase_height_not_numeric_alias() {
        let (mut b,mut c) = fixture(12);
        b.txdata[0].input[0].script_sig = Script::from(vec![1,12]);
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::CoinbaseHeight));
        c.height_in_coinbase_active = false;
        assert!(verify_child_context(&b,&c).is_ok());
        let (mut b,c) = fixture(128);
        b.txdata[0].input[0].script_sig = Script::from(vec![1,128]);
        assert_eq!(verify_child_context(&b,&c),Err(ContextError::CoinbaseHeight));
    }
}
