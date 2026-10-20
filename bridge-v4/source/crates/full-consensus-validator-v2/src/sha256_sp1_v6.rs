//! SP1 v6 target-only SHA256. Symbols are supplied by the pinned guest runtime.
//! No host dependency or native hashing behavior is changed.
extern "C" {
    fn syscall_sha256_extend(words: *mut [u64;64]);
    fn syscall_sha256_compress(words: *mut [u64;64], state: *mut [u64;8]);
}

pub(crate) fn hash(input: &[u8]) -> [u8;32] {
    let mut state:[u64;8]=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let bit_len=u64::try_from(input.len()).unwrap().checked_mul(8).unwrap();
    let blocks=input.len().checked_add(9).unwrap().div_ceil(64);
    for block_index in 0..blocks {
        let mut block=[0u8;64];
        let start=block_index*64;
        let n=input.len().saturating_sub(start).min(64);
        if n>0 {block[..n].copy_from_slice(&input[start..start+n]);}
        if start<=input.len() && input.len()-start<64 {block[input.len()-start]=0x80;}
        if block_index+1==blocks {block[56..].copy_from_slice(&bit_len.to_be_bytes());}
        let mut words=[0u64;64];
        for (word,bytes) in words[..16].iter_mut().zip(block.chunks_exact(4)) {
            *word=u64::from(u32::from_be_bytes(bytes.try_into().unwrap()));
        }
        // SAFETY: both arrays are live, exclusively borrowed, nonoverlapping
        // and u64-aligned. V6 uses one zero-extended SHA32 word per u64 slot.
        // Extend initializes words16..63 before compress reads them.
        unsafe {
            syscall_sha256_extend(&mut words);
            syscall_sha256_compress(&mut words,&mut state);
        }
    }
    let mut out=[0u8;32];
    for (bytes,word) in out.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&u32::try_from(word).unwrap().to_be_bytes());
    }
    out
}
