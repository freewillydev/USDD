//! Receipt-authenticated native checkpoint ancestry. This does not by itself
//! trace individual covenant outpoints or select production trust anchors.
use crate::{AlphaRecursiveReceiptBindingV3, FullAlphaReceiptVerifierV3, FullAlphaStatementV3,
    child_execution_state_v3::ChildExecutionCheckpointV3,
    native_conversion_accounting_v3::ConversionAccountingBindingV3,
    native_conversion_source_v3::{NativeConversionSourceBindingV3,
        verify_native_conversion_source_receipt_v3}};

pub const MAX_NATIVE_CHECKPOINT_LINEAGE_STEPS_V3: usize = 8192;

pub struct NativeCheckpointLineageStepV3<'a> {
    pub receipt: &'a AlphaRecursiveReceiptBindingV3,
    pub observation: &'a FullAlphaStatementV3,
    pub successor: &'a ChildExecutionCheckpointV3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCheckpointLineageErrorV3 { Shape, Binding, Receipt, Continuity }

/// Every entry in `reviewed_bindings` is a trusted configuration input, never
/// taken from the witness. The final enclosing configuration must commit this
/// ordered list. A hash-linked header list cannot substitute for these receipts.
/// The empty chain is valid only when the independently pinned endpoints agree.
pub fn verify_native_checkpoint_lineage_v3(
    source_program: [u8;32],
    initial: [u8;32],
    terminal: [u8;32],
    reviewed_bindings: &[NativeConversionSourceBindingV3],
    steps: &[NativeCheckpointLineageStepV3<'_>],
    terminal_policy: &NativeConversionSourceBindingV3,
    accounting: &ConversionAccountingBindingV3,
    verifier: &impl FullAlphaReceiptVerifierV3,
) -> Result<(), NativeCheckpointLineageErrorV3> {
    use NativeCheckpointLineageErrorV3::*;
    if initial == [0;32] || terminal == [0;32]
        || !crate::alpha_sp1_program_id_is_canonical_v3(source_program)
        || reviewed_bindings.len() != steps.len()
        || steps.len() > MAX_NATIVE_CHECKPOINT_LINEAGE_STEPS_V3 { return Err(Shape); }
    if terminal != terminal_policy.predecessor_checkpoint { return Err(Binding); }
    let mut current=initial;
    let mut previous_height=None;
    for (binding,step) in reviewed_bindings.iter().zip(steps) {
        if binding.predecessor_checkpoint != current
            || binding.child_execution_program_id != terminal_policy.child_execution_program_id
            || binding.execution_policy != terminal_policy.execution_policy
            || binding.simplicity_evaluator_program_id != terminal_policy.simplicity_evaluator_program_id
            || binding.deposit_configuration != terminal_policy.deposit_configuration
            || binding.accounting_binding != terminal_policy.accounting_binding
            || binding.clock_policy != terminal_policy.clock_policy {
            return Err(Binding);
        }
        let expected=binding.commitment().map_err(|_| Binding)?;
        let source=verify_native_conversion_source_receipt_v3(step.receipt,source_program,
            expected,binding,step.observation,step.successor,accounting,verifier)
            .map_err(|_| Receipt)?;
        if source.child.predecessor_checkpoint != current
            || source.child.next_checkpoint == current
            || previous_height.is_some_and(|height: u32| height.checked_add(1) != Some(step.successor.height)) {
            return Err(Continuity);
        }
        current=source.child.next_checkpoint;
        previous_height=Some(step.successor.height);
    }
    if current != terminal { return Err(Continuity); }
    Ok(())
}
