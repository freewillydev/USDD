//! Version-1 path transport primitive, not yet a complete transition codec.
//! Defaults are implicit. Non-default nodes use canonical first-use indexes;
//! new nodes carry a hash and minimal unsigned LEB128 aggregate fields.
use crate::*;
use std::collections::BTreeMap;

const MAX_NODES: usize = 262_144;
const MAX_PATHS: usize = 131_072;
const MAX_BYTES: usize = 16*1024*1024;
type Key = (Hash32,u128,u128);
fn key(n: SparseUtxoNodeV2)->Key {(n.hash,n.aggregate.count,n.aggregate.value_atoms)}
fn put(mut n:u128, out:&mut Vec<u8>) {
    loop {let b=(n&127) as u8;n >>=7;out.push(b|if n==0 {0}else{128});if n==0 {break}}
}
fn take(input:&mut &[u8])->Result<u128,FullValidatorPrimitiveErrorV2> {
    let mut n=0;
    for i in 0..19 {
        let (&b,rest)=input.split_first().ok_or(FullValidatorPrimitiveErrorV2::NonCanonicalPath)?;
        *input=rest;
        if i==18 && b>3 {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
        n|=u128::from(b&127)<<(7*i);
        if b&128==0 {
            if i>0 && b==0 {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
            return Ok(n)
        }
    }
    Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)
}

/// Stateful dictionary is scoped to exactly one transport. Any failed call
/// poisons it; callers cannot resume after consuming malformed input.
pub struct PathCodec {
    defaults:Vec<SparseUtxoNodeV2>, nodes:Vec<SparseUtxoNodeV2>,
    indexes:BTreeMap<Key,usize>, paths:usize, bytes:usize, failed:bool,
}
impl PathCodec {
    pub fn new()->Self {
        let mut defaults=vec![canonical_empty_utxo_leaf_v2()];
        for i in 1..256 {defaults.push(sparse_utxo_parent_v2(defaults[i-1],defaults[i-1]).unwrap())}
        Self{defaults,nodes:vec![],indexes:BTreeMap::new(),paths:0,bytes:0,failed:false}
    }
    fn add(&mut self,n:SparseUtxoNodeV2)->Result<(),FullValidatorPrimitiveErrorV2> {
        if self.nodes.len()>=MAX_NODES || self.indexes.contains_key(&key(n)) {
            return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)
        }
        self.indexes.insert(key(n),self.nodes.len());self.nodes.push(n);Ok(())
    }
    fn account(&mut self,bytes:usize)->Result<(),FullValidatorPrimitiveErrorV2> {
        self.paths+=1;self.bytes=self.bytes.checked_add(bytes).ok_or(FullValidatorPrimitiveErrorV2::ResourceLimit)?;
        if self.paths>MAX_PATHS || self.bytes>MAX_BYTES {return Err(FullValidatorPrimitiveErrorV2::ResourceLimit)}
        Ok(())
    }
    pub fn encode(&mut self,path:&SparseUtxoPathV2)->Result<Vec<u8>,FullValidatorPrimitiveErrorV2> {
        if self.failed {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
        self.failed=true;
        if path.siblings.len()!=256 {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
        let mut out=vec![0u8;32];
        for (level,&node) in path.siblings.iter().enumerate() {
            if node==self.defaults[level] {continue}
            out[level/8]|=1<<(level%8);
            if let Some(&index)=self.indexes.get(&key(node)) {put(index as u128,&mut out)}
            else {
                put(self.nodes.len() as u128,&mut out);out.extend(node.hash);
                put(node.aggregate.count,&mut out);put(node.aggregate.value_atoms,&mut out);self.add(node)?;
            }
        }
        self.account(out.len())?;self.failed=false;Ok(out)
    }
    pub fn decode(&mut self,input:&mut &[u8])->Result<SparseUtxoPathV2,FullValidatorPrimitiveErrorV2> {
        if self.failed {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
        self.failed=true;
        let start=input.len();
        if start<32 {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
        let bitmap: [u8;32]=input[..32].try_into().unwrap();*input=&input[32..];
        let mut siblings=self.defaults.clone();
        for level in 0..256 {
            if bitmap[level/8]&(1<<(level%8))==0 {continue}
            let index=usize::try_from(take(input)?).map_err(|_|FullValidatorPrimitiveErrorV2::NonCanonicalPath)?;
            let node=if index<self.nodes.len() {self.nodes[index]} else {
                if index!=self.nodes.len() || input.len()<32 {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
                let hash=input[..32].try_into().unwrap();*input=&input[32..];
                let node=SparseUtxoNodeV2{hash,aggregate:UtxoAggregateV2{count:take(input)?,value_atoms:take(input)?}};
                self.add(node)?;node
            };
            if node==self.defaults[level] {return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
            siblings[level]=node;
        }
        self.account(start-input.len())?;self.failed=false;Ok(SparseUtxoPathV2{siblings})
    }
}

/// Bounded FIFO mutation transport. This is not a complete transition frame.
/// Each call authenticates the reconstructed mutation against its input root.
pub struct FifoMutationCodec { inner:PathCodec, cursor:usize }
impl FifoMutationCodec {
    pub fn new()->Self {Self{inner:PathCodec::new(),cursor:0}}
    fn insert(&mut self,n:SparseUtxoNodeV2) {
        if self.inner.indexes.contains_key(&key(n)){return}
        let slot=if self.inner.nodes.len()<MAX_NODES {
            self.inner.nodes.push(n);self.inner.nodes.len()-1
        }else{
            let slot=self.cursor;self.inner.indexes.remove(&key(self.inner.nodes[slot]));
            self.inner.nodes[slot]=n;self.cursor=(self.cursor+1)%MAX_NODES;slot
        };
        self.inner.indexes.insert(key(n),slot);
    }
    fn finish(&mut self,root:SparseUtxoNodeV2,m:&SparseUtxoMutationV2,bytes:usize)->Result<SparseUtxoNodeV2,FullValidatorPrimitiveErrorV2>{
        // Retain only the 64 cache candidates while doing the required folds.
        // Never insert provisional nodes from an unauthenticated mutation.
        let mut derived = [[canonical_empty_utxo_leaf_v2(); 32]; 2];
        let result=apply_sparse_utxo_mutation_observed_v2(root,m,|is_new,level,node| {
            if level>=224 { derived[usize::from(is_new)][level-224]=node; }
        })?;
        self.inner.account(bytes)?;
        for level in 224..256 {
            for n in [derived[0][level-224],derived[1][level-224]] {
                if n!=self.inner.defaults[level] { self.insert(n); }
            }
        }
        self.inner.failed=false;Ok(result)
    }
    pub fn encode(&mut self,root:SparseUtxoNodeV2,m:&SparseUtxoMutationV2)->Result<(Vec<u8>,SparseUtxoNodeV2),FullValidatorPrimitiveErrorV2>{
        if self.inner.failed{return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}self.inner.failed=true;
        if m.path.siblings.len()!=256{return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
        let mut bytes=vec![0;32];
        for (level,&n) in m.path.siblings.iter().enumerate(){
            if n==self.inner.defaults[level]{continue}bytes[level/8]|=1<<(level%8);
            if let Some(&slot)=self.inner.indexes.get(&key(n)){put(slot as u128+1,&mut bytes);}
            else{put(0,&mut bytes);bytes.extend(n.hash);put(n.aggregate.count,&mut bytes);put(n.aggregate.value_atoms,&mut bytes);self.insert(n);}
        }
        let result=self.finish(root,m,bytes.len())?;Ok((bytes,result))
    }
    pub fn decode(&mut self,root:SparseUtxoNodeV2,outpoint:OutPoint,old_leaf:Option<BitcoinUtxoLeafV2>,new_leaf:Option<BitcoinUtxoLeafV2>,input:&mut &[u8])->Result<(SparseUtxoMutationV2,SparseUtxoNodeV2),FullValidatorPrimitiveErrorV2>{
        if self.inner.failed{return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}self.inner.failed=true;
        let start=input.len();if start<32{return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
        let bitmap:[u8;32]=input[..32].try_into().unwrap();*input=&input[32..];
        let mut siblings=self.inner.defaults.clone();
        for level in 0..256{
            if bitmap[level/8]&(1<<(level%8))==0{continue}
            let token=take(input)?;
            let n=if token==0{
                if input.len()<32{return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}
                let hash=input[..32].try_into().unwrap();*input=&input[32..];
                let n=SparseUtxoNodeV2{hash,aggregate:UtxoAggregateV2{count:take(input)?,value_atoms:take(input)?}};
                if self.inner.indexes.contains_key(&key(n)){return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}self.insert(n);n
            }else{
                let slot=usize::try_from(token-1).map_err(|_|FullValidatorPrimitiveErrorV2::NonCanonicalPath)?;
                *self.inner.nodes.get(slot).ok_or(FullValidatorPrimitiveErrorV2::NonCanonicalPath)?
            };
            if n==self.inner.defaults[level]{return Err(FullValidatorPrimitiveErrorV2::NonCanonicalPath)}siblings[level]=n;
        }
        let m=SparseUtxoMutationV2{outpoint,old_leaf,new_leaf,path:SparseUtxoPathV2{siblings}};
        let result=self.finish(root,&m,start-input.len())?;Ok((m,result))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn fifo_eviction_and_authenticated_failure() {
        let mut codec=FifoMutationCodec::new();
        for i in 0..=MAX_NODES {
            let mut hash=[0;32];hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
            codec.insert(SparseUtxoNodeV2{hash,aggregate:UtxoAggregateV2{count:1,value_atoms:1}});
        }
        assert_eq!(codec.inner.nodes.len(),MAX_NODES);assert_eq!(codec.inner.indexes.len(),MAX_NODES);
        assert!(!codec.inner.indexes.contains_key(&([0;32],1,1)));assert_eq!(codec.cursor,1);
        let mut path=SparseUtxoPathV2{siblings:codec.inner.defaults.clone()};
        path.siblings[0]=codec.inner.nodes[0];
        let point=OutPoint::null();
        let m=SparseUtxoMutationV2{outpoint:point,old_leaf:None,new_leaf:Some(BitcoinUtxoLeafV2{
            outpoint:point,output:bitcoin::TxOut{value:bitcoin::Amount::from_sat(1),script_pubkey:bitcoin::ScriptBuf::new()},
            creation_height:1,creation_parent_mtp:1,coinbase:false}),path};
        let root=sparse_utxo_root_from_path_v2(point,canonical_empty_utxo_leaf_v2(),&m.path).unwrap();
        let (raw,expected)=FifoMutationCodec::new().encode(root,&m).unwrap();
        let (decoded,actual)=FifoMutationCodec::new().decode(root,point,None,m.new_leaf.clone(),&mut raw.as_slice()).unwrap();
        assert_eq!(decoded,m);assert_eq!(actual,expected);
        for length in 0..raw.len(){
            let mut decoder=FifoMutationCodec::new();
            assert!(decoder.decode(root,point,None,m.new_leaf.clone(),&mut &raw[..length]).is_err());assert!(decoder.inner.failed);
        }
        let mut decoder=FifoMutationCodec::new();let mut wrong=root;wrong.hash[0]^=1;
        assert_eq!(decoder.decode(wrong,point,None,m.new_leaf.clone(),&mut raw.as_slice()).unwrap_err(),FullValidatorPrimitiveErrorV2::RootMismatch);
        assert!(decoder.decode(root,point,None,m.new_leaf.clone(),&mut raw.as_slice()).is_err());
    }
    fn rejects(raw: &[u8]) {
        let mut decoder=PathCodec::new();
        assert!(decoder.decode(&mut &raw[..]).is_err());
        assert!(decoder.decode(&mut &[0u8;32][..]).is_err());
    }
    #[test] fn varint_boundaries_and_overflow() {
        for n in [0,1,127,128,16383,16384,u64::MAX as u128,u128::MAX] {
            let mut bytes=vec![];put(n,&mut bytes);
            let mut input=bytes.as_slice();assert_eq!(take(&mut input).unwrap(),n);assert!(input.is_empty());
            for len in 0..bytes.len() {assert!(take(&mut &bytes[..len]).is_err());}
        }
        for bytes in [vec![128,0],vec![255;19],{let mut b=vec![128;18];b.push(4);b}] {
            assert!(take(&mut bytes.as_slice()).is_err());
        }
    }
    #[test] fn malformed_literals_references_and_truncation() {
        let mut encoder=PathCodec::new();
        let mut path=SparseUtxoPathV2{siblings:encoder.defaults.clone()};
        path.siblings[0]=SparseUtxoNodeV2{hash:[42;32],aggregate:UtxoAggregateV2{count:1,value_atoms:128}};
        let bytes=encoder.encode(&path).unwrap();
        for len in 0..bytes.len() {rejects(&bytes[..len]);}
        let mut forward=bytes.clone();forward[32]=1;rejects(&forward);
        let mut explicit_default=vec![0;32];explicit_default[0]=1;explicit_default.push(0);
        explicit_default.extend(encoder.defaults[0].hash);explicit_default.extend([0,0]);rejects(&explicit_default);
        let mut duplicate=bytes.clone();duplicate[0]=3;
        duplicate.push(1);duplicate.extend(&bytes[33..]);rejects(&duplicate);
        let mut overflow=bytes[..65].to_vec();overflow.extend([255;19]);rejects(&overflow);
        // A substituted valid reference is structurally decodable: root authentication,
        // not the transport codec, must reject it in the consensus consumer.
    }
    #[test] fn resource_edges_poison_both_directions() {
        for encode in [false,true] {
            for path_limit in [false,true] {
                let mut codec=PathCodec::new();
                if path_limit {codec.paths=MAX_PATHS-1;} else {codec.bytes=MAX_BYTES-32;}
                let path=SparseUtxoPathV2{siblings:codec.defaults.clone()};
                let call=|codec:&mut PathCodec| {
                    if encode {codec.encode(&path).map(|_|())}
                    else {codec.decode(&mut &[0u8;32][..]).map(|_|())}
                };
                assert!(call(&mut codec).is_ok());
                assert_eq!(call(&mut codec),Err(FullValidatorPrimitiveErrorV2::ResourceLimit));
                assert!(call(&mut codec).is_err());
            }
        }
        let mut codec=PathCodec::new();
        codec.nodes=vec![codec.defaults[0];MAX_NODES];
        let mut raw=vec![0;32];raw[0]=1;put(MAX_NODES as u128,&mut raw);
        raw.extend([42;32]);raw.extend([1,1]);
        assert!(codec.decode(&mut raw.as_slice()).is_err());assert!(codec.failed);
    }
    #[test] fn canonical_paths_and_poisoning() {
        let mut encoder=PathCodec::new();let mut decoder=PathCodec::new();
        let mut path=SparseUtxoPathV2{siblings:encoder.defaults.clone()};
        for i in 0..8 {
            path.siblings[i]=SparseUtxoNodeV2{hash:[i as u8;32],aggregate:UtxoAggregateV2{count:i as u128+1,value_atoms:u128::MAX-i as u128}};
            let bytes=encoder.encode(&path).unwrap();let mut input=bytes.as_slice();
            assert_eq!(decoder.decode(&mut input).unwrap(),path);assert!(input.is_empty());
        }
        for raw in [vec![],vec![0;31],{let mut x=vec![0;32];x[0]=1;x.extend([128,0]);x}] {
            let mut decoder=PathCodec::new();assert!(decoder.decode(&mut raw.as_slice()).is_err());
            assert!(decoder.decode(&mut [0u8;32].as_slice()).is_err());
        }
    }
}
