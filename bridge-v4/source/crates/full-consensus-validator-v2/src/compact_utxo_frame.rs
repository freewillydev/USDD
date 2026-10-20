//! Versioned bounded transaction witness frame. Consensus still runs through
//! the shared transaction verifier; decoded root linkage alone is insufficient.
use crate::*;
use crate::compact_utxo_paths::FifoMutationCodec;
const MAGIC:&[u8;8]=b"ACUTXO01";
pub const MAX_FRAME_BYTES:usize=16*1024*1024;
pub const MAX_TRANSACTION_MUTATIONS:usize=4096;
const MAX_TRANSACTIONS:usize=131072;
const MAX_OUTPUT_BYTES:usize=10032;
type Error=FullValidatorPrimitiveErrorV2;
fn number(out:&mut Vec<u8>,n:usize)->Result<(),Error>{
    out.extend(u32::try_from(n).map_err(|_|Error::ResourceLimit)?.to_le_bytes());Ok(())
}
fn bytes<'a>(input:&mut &'a [u8],n:usize)->Result<&'a [u8],Error>{
    if input.len()<n{return Err(Error::TransactionWitness)}let (a,b)=input.split_at(n);*input=b;Ok(a)
}
fn count(input:&mut &[u8])->Result<usize,Error>{Ok(u32::from_le_bytes(bytes(input,4)?.try_into().unwrap()) as usize)}

pub fn encode(root:SparseUtxoNodeV2,witness:&BitcoinBlockUtxoWitnessV2)->Result<Vec<u8>,Error>{
    if witness.transactions.is_empty()||witness.transactions.len()>MAX_TRANSACTIONS{return Err(Error::ResourceLimit)}
    let mut out=MAGIC.to_vec();number(&mut out,witness.transactions.len())?;
    let mut codec=FifoMutationCodec::new();let mut root=root;
    for tx in &witness.transactions {
        if tx.spends.len().checked_add(tx.creates.len()).ok_or(Error::ResourceLimit)?>MAX_TRANSACTION_MUTATIONS{return Err(Error::ResourceLimit)}
        number(&mut out,tx.spends.len())?;number(&mut out,tx.creates.len())?;
        for (spend,items) in [(true,&tx.spends),(false,&tx.creates)] {
            for m in items {
                let leaf=match (spend,&m.old_leaf,&m.new_leaf){(true,Some(l),None)|(false,None,Some(l))=>l,_=>return Err(Error::InvalidMutation)};
                out.extend(serialize(&m.outpoint));let output=serialize(&leaf.output);
                if output.len()>MAX_OUTPUT_BYTES{return Err(Error::ResourceLimit)}
                number(&mut out,output.len())?;out.extend(output);
                out.extend(leaf.creation_height.to_le_bytes());out.extend(leaf.creation_parent_mtp.to_le_bytes());out.push(u8::from(leaf.coinbase));
                let (path,next)=codec.encode(root,m)?;out.extend(path);root=next;
                if out.len()>MAX_FRAME_BYTES{return Err(Error::ResourceLimit)}
            }
            if out.len()>MAX_FRAME_BYTES{return Err(Error::ResourceLimit)}
        }
    }
    Ok(out)
}

pub struct TransactionDecoder<'a>{input:&'a [u8],remaining:usize,codec:FifoMutationCodec,root:SparseUtxoNodeV2,failed:bool}
impl<'a> TransactionDecoder<'a>{
    pub fn new(mut input:&'a [u8],root:SparseUtxoNodeV2)->Result<Self,Error>{
        if input.len()>MAX_FRAME_BYTES{return Err(Error::ResourceLimit)}
        if bytes(&mut input,8)?!=MAGIC{return Err(Error::TransactionWitness)}
        let remaining=count(&mut input)?;
        if remaining==0||remaining>MAX_TRANSACTIONS{return Err(Error::ResourceLimit)}
        Ok(Self{input,remaining,codec:FifoMutationCodec::new(),root,failed:false})
    }
    fn transaction(&mut self)->Result<BitcoinTransactionUtxoWitnessV2,Error>{
        let spends=count(&mut self.input)?;let creates=count(&mut self.input)?;
        if spends.checked_add(creates).ok_or(Error::ResourceLimit)?>MAX_TRANSACTION_MUTATIONS{return Err(Error::ResourceLimit)}
        let mut tx=BitcoinTransactionUtxoWitnessV2{spends:vec![],creates:vec![]};
        for (spend,n) in [(true,spends),(false,creates)] {
            for _ in 0..n {
                let outpoint=deserialize(bytes(&mut self.input,36)?).map_err(|_|Error::TransactionWitness)?;
                let len=count(&mut self.input)?;if len>MAX_OUTPUT_BYTES{return Err(Error::ResourceLimit)}
                let output:TxOut=deserialize(bytes(&mut self.input,len)?).map_err(|_|Error::TransactionWitness)?;
                let creation_height=count(&mut self.input)? as u32;let creation_parent_mtp=count(&mut self.input)? as u32;
                let coinbase=match bytes(&mut self.input,1)?[0]{0=>false,1=>true,_=>return Err(Error::TransactionWitness)};
                let leaf=BitcoinUtxoLeafV2{outpoint,output,creation_height,creation_parent_mtp,coinbase};
                let (old,new)=if spend{(Some(leaf),None)}else{(None,Some(leaf))};
                let (m,root)=self.codec.decode(self.root,outpoint,old,new,&mut self.input)?;self.root=root;
                if spend{tx.spends.push(m)}else{tx.creates.push(m)}
            }
        }
        self.remaining-=1;
        if self.remaining==0&&!self.input.is_empty(){return Err(Error::TransactionWitness)}
        Ok(tx)
    }
}
impl Iterator for TransactionDecoder<'_>{
    type Item=Result<BitcoinTransactionUtxoWitnessV2,Error>;
    fn next(&mut self)->Option<Self::Item>{
        if self.failed||self.remaining==0{return None}
        let result=self.transaction();if result.is_err(){self.failed=true}Some(result)
    }
}

// Fields and constructor stay private: callers cannot attach arbitrary roots
// to unverified witnesses, nor mutate a witness after authentication.
struct AuthenticatedTransaction {
    witness: BitcoinTransactionUtxoWitnessV2,
    before: SparseUtxoNodeV2,
    after: SparseUtxoNodeV2,
}
impl TransactionWitnessSource for AuthenticatedTransaction {
    fn witness(&self) -> &BitcoinTransactionUtxoWitnessV2 { &self.witness }
    fn authenticated_roots(&self) -> Option<(SparseUtxoNodeV2, SparseUtxoNodeV2)> {
        Some((self.before, self.after))
    }
}
struct AuthenticatedDecoder<'a>(TransactionDecoder<'a>);
impl Iterator for AuthenticatedDecoder<'_> {
    type Item = Result<AuthenticatedTransaction, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        let before = self.0.root;
        self.0.next().map(|result| result.map(|witness| AuthenticatedTransaction {
            witness, before, after: self.0.root,
        }))
    }
}

pub fn verify_alpha<V:BitcoinScriptVerifierV2>(block:&Block,context:BitcoinBlockSpendContextV2,root:SparseUtxoNodeV2,frame:&[u8],flags:u32,verifier:&V)->Result<BitcoinBlockUtxoResultV2,Error>{
    let stream=TransactionDecoder::new(frame,root)?;
    apply_block_utxos_from_transaction_stream(block,context,root,AuthenticatedDecoder(stream),flags,verifier,true)
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn strict_framing_and_limits(){
        let root=canonical_empty_utxo_leaf_v2();
        let witness=BitcoinBlockUtxoWitnessV2{transactions:vec![BitcoinTransactionUtxoWitnessV2{spends:vec![],creates:vec![]}]};
        let frame=encode(root,&witness).unwrap();
        assert_eq!(TransactionDecoder::new(&frame,root).unwrap().collect::<Result<Vec<_>,_>>().unwrap(),witness.transactions);
        for n in 0..frame.len(){
            match TransactionDecoder::new(&frame[..n],root){Err(_)=>{},Ok(mut d)=>{assert!(d.next().unwrap().is_err());assert!(d.next().is_none());}}
        }
        let mut extra=frame.clone();extra.push(0);
        assert!(TransactionDecoder::new(&extra,root).unwrap().next().unwrap().is_err());
        let mut large=frame.clone();large[12..16].copy_from_slice(&4097u32.to_le_bytes());
        assert_eq!(TransactionDecoder::new(&large,root).unwrap().next().unwrap().unwrap_err(),Error::ResourceLimit);
        let mut bad=frame.clone();bad[7]^=1;assert!(TransactionDecoder::new(&bad,root).is_err());
        assert!(TransactionDecoder::new(&vec![0;MAX_FRAME_BYTES+1],root).is_err());
    }
}
