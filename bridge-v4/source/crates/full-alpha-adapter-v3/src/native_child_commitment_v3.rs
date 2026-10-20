//! Native Alpha child coinbase commitment codec.
//!
//! This parses scripts only. Callers must authenticate the complete child block,
//! its transaction merkle root, and coinbase position/validity independently.
//! Success is NOT a child-consensus receipt or an economic conversion proof.
//! Mirrors ExtractDrivechainParentHashFromBlock in the native node: once a
//! successfully decoded OP_RETURN push uses ELMTP, nonminimal, trailing and
//! duplicate encodings must fail rather than being ignored.

use bitcoin::script::Instruction;
use bitcoin::Script;
use ecx_full_consensus_validator_v2::Hash32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentCommitmentError {
    Missing,
    Noncanonical,
    Duplicate,
}

/// Input must be the scripts of the independently authenticated coinbase.
/// Returned hash is uint256 internal byte order, matching native ELMTP bytes.
pub fn extract_parent_hash<'a>(
    scripts: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Hash32, ParentCommitmentError> {
    let mut found = None;
    for script in scripts {
        // Nonminimal pushes are decoded intentionally so reserved-tag aliases
        // are rejected below, including aliases beside a canonical output.
        let mut instructions = Script::from_bytes(script).instructions();
        if !matches!(instructions.next(), Some(Ok(Instruction::Op(op))) if op.to_u8() == 0x6a) {
            continue;
        }
        let Some(Ok(Instruction::PushBytes(payload))) = instructions.next() else {
            continue;
        };
        if !payload.as_bytes().starts_with(b"ELMTP") {
            continue;
        }
        if script.len() != 39 || script[1] != 37 || instructions.next().is_some() {
            return Err(ParentCommitmentError::Noncanonical);
        }
        if found.is_some() {
            return Err(ParentCommitmentError::Duplicate);
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&payload.as_bytes()[5..]);
        found = Some(hash);
    }
    found.ok_or(ParentCommitmentError::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical() -> Vec<u8> {
        let mut script = vec![0x6a, 37];
        script.extend_from_slice(b"ELMTP");
        script.extend(0u8..32);
        script
    }

    #[test]
    fn exact_internal_order_and_unrelated_outputs() {
        let script = canonical();
        let hash = extract_parent_hash([&[0x51][..], script.as_slice()]).unwrap();
        assert_eq!(hash, core::array::from_fn(|i| i as u8));
    }

    #[test]
    fn duplicates_rejected() {
        let script = canonical();
        assert_eq!(extract_parent_hash([script.as_slice(), script.as_slice()]), Err(ParentCommitmentError::Duplicate));
    }

    #[test]
    fn nonminimal_alias_rejected_even_beside_valid_output() {
        let script = canonical();
        for prefix in [vec![0x6a, 0x4c, 37], vec![0x6a, 0x4d, 37, 0], vec![0x6a, 0x4e, 37, 0, 0, 0]] {
            let mut alias = prefix;
            alias.extend_from_slice(&script[2..]);
            assert_eq!(extract_parent_hash([script.as_slice(), alias.as_slice()]), Err(ParentCommitmentError::Noncanonical));
            assert_eq!(extract_parent_hash([alias.as_slice(), script.as_slice()]), Err(ParentCommitmentError::Noncanonical));
        }
    }

    #[test]
    fn tagged_wrong_length_and_trailing_instructions_rejected() {
        let mut short = vec![0x6a, 5];
        short.extend_from_slice(b"ELMTP");
        let mut trailing = canonical();
        trailing.push(0);
        for bad in [short, trailing] {
            assert_eq!(extract_parent_hash([bad.as_slice()]), Err(ParentCommitmentError::Noncanonical));
        }
    }

    #[test]
    fn absent_or_undecodable_push_is_not_a_commitment() {
        assert_eq!(extract_parent_hash(core::iter::empty()), Err(ParentCommitmentError::Missing));
        for script in [vec![0x6a, 37, b'E'], vec![0x6a, 0x51], vec![0x51]] {
            assert_eq!(extract_parent_hash([script.as_slice()]), Err(ParentCommitmentError::Missing));
        }
    }
}
