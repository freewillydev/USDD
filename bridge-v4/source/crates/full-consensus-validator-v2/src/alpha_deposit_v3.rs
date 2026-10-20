//! Checkpoint-relative Alpha deposit execution, not an authenticated receipt.
//!
//! The enclosing adapter must authenticate BOTH state commitments against its
//! frozen Alpha receipt chain, check canonical inclusion/confirmation depth,
//! and bind the slot proposal, child genesis, asset and destination script.
//! Neither a supplied checkpoint nor this native result establishes those facts.

use crate::alpha_state_v3::{
    execute_alpha_executed_successor_with_effects_v3, AlphaBlockEvidenceStepV3,
    AlphaExecutedConsensusStateV3,
};
use crate::bip300_v2::Bip300DepositV2;
use crate::{FullValidatorPrimitiveErrorV2, Hash32};
use bitcoin::OutPoint;

/// Constructed only by complete execution; not deserializable witness data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedAlphaDepositV3 {
    predecessor_state_commitment: Hash32,
    successor_state_commitment: Hash32,
    deposit: Bip300DepositV2,
}

impl ExecutedAlphaDepositV3 {
    pub fn predecessor_state_commitment(&self) -> Hash32 {
        self.predecessor_state_commitment
    }
    pub fn successor_state_commitment(&self) -> Hash32 {
        self.successor_state_commitment
    }
    pub fn deposit(&self) -> &Bip300DepositV2 {
        &self.deposit
    }
}

/// Select one exact M5 effect from the same bytes that pass full Alpha block
/// execution. Expected commitments are independent adapter inputs, not trust
/// roots by themselves. No arbitrary Bitcoin/Signet rule selection is exposed.
pub fn execute_alpha_deposit_v3(
    predecessor: &AlphaExecutedConsensusStateV3,
    step: &AlphaBlockEvidenceStepV3,
    discovery_sequence: u128,
    expected_predecessor: Hash32,
    expected_successor: Hash32,
    slot: u8,
    outpoint: OutPoint,
) -> Result<ExecutedAlphaDepositV3, FullValidatorPrimitiveErrorV2> {
    let error = FullValidatorPrimitiveErrorV2::ExecutedState;
    if expected_predecessor == [0; 32] || expected_successor == [0; 32]
        || predecessor.commitment()? != expected_predecessor
    {
        return Err(error);
    }
    let (successor, effects) = execute_alpha_executed_successor_with_effects_v3(
        predecessor, step, discovery_sequence,
    )?;
    if successor.commitment()? != expected_successor {
        return Err(error);
    }
    let mut matching = effects.deposits.into_iter().filter(|deposit| {
        deposit.slot == slot && deposit.outpoint.outpoint == outpoint
    });
    let deposit = matching.next().ok_or(error)?;
    if matching.next().is_some() {
        return Err(error);
    }
    Ok(ExecutedAlphaDepositV3 {
        predecessor_state_commitment: expected_predecessor,
        successor_state_commitment: expected_successor,
        deposit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha_state_v3::tests::synthetic_state;
    use crate::BitcoinBlockUtxoWitnessV2;

    #[test]
    fn deposit_requires_bound_states_and_a_fully_executed_block() {
        // Shape-only fixture: this test does not claim a valid live deposit.
        let state = synthetic_state();
        let step = AlphaBlockEvidenceStepV3 {
            raw_block: vec![],
            authenticated_adjusted_time: 1_800_000_000,
            utxo_witness: BitcoinBlockUtxoWitnessV2 { transactions: vec![] },
        };
        let commitment = state.commitment().unwrap();
        for (prior, next) in [
            ([0; 32], commitment),
            (commitment, [0; 32]),
            ([2; 32], commitment),
            (commitment, commitment),
        ] {
            assert!(execute_alpha_deposit_v3(
                &state, &step, 1, prior, next, 24, OutPoint::null(),
            ).is_err());
        }
    }
}
