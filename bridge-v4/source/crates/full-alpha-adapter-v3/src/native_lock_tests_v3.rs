//! Synthetic native-lock compatibility regressions; not live proof evidence.
use ecx_full_consensus_validator_v2::elements_v2::*;
use elements::{Transaction,TxIn,TxOut,LockTime,Sequence,OutPoint};

fn fixture() -> (Transaction,ElementsSparseUtxoMutationV2,ElementsTransactionSpendContextV2) {
    let outpoint = OutPoint { vout:0,..OutPoint::default() };
    let leaf = ElementsUtxoLeafV2 {outpoint,output:TxOut::default(),creation_height:10,
        creation_parent_mtp:500_000_000,coinbase:false,created_by_issuance:false,created_by_pegin:false};
    let spend = ElementsSparseUtxoMutationV2 {outpoint,old_leaf:Some(leaf),new_leaf:None,
        path:ElementsSparseUtxoPathV2 {siblings:vec![]}};
    (Transaction {version:2,lock_time:LockTime::ZERO,
        input:vec![TxIn {previous_output:outpoint,sequence:Sequence(5),..TxIn::default()}],output:vec![]},
        spend,ElementsTransactionSpendContextV2 {height:15,parent_mtp:500_000_512})
}
fn policy(active:bool) -> NativeElementsLockPolicyV3 {
    NativeElementsLockPolicyV3 {csv_active:active,absolute_time_cutoff:500_000_512}
}
#[test]
fn native_pegin_skips_sequence_but_legacy_remains_strict() {
    let (mut tx,_,context) = fixture(); tx.input[0].is_pegin = true;
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,&[],context,policy(true)),Ok(()));
    assert_eq!(verify_elements_transaction_locks_v2(&tx,&[],context),Err(ElementsStateErrorV2::RelativeLockTime));
}
#[test]
fn native_height_and_time_edges_and_csv_activation() {
    let (mut tx,spend,mut context) = fixture();
    let spends = std::slice::from_ref(&spend);
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,spends,context,policy(true)),Ok(()));
    context.height = 14;
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,spends,context,policy(true)),Err(ElementsStateErrorV2::RelativeLockTime));
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,spends,context,policy(false)),Ok(()));
    tx.input[0].sequence = Sequence((1<<22)|1);
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,spends,context,policy(true)),Ok(()));
    context.parent_mtp -= 1;
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,spends,context,policy(true)),Err(ElementsStateErrorV2::RelativeLockTime));
    tx.version = 1;
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,spends,context,policy(true)),Ok(()));
    // Native transaction version is unsigned, including values with bit 31 set.
    tx.version = u32::MAX;
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,spends,context,policy(true)),Err(ElementsStateErrorV2::RelativeLockTime));
}
#[test]
fn native_absolute_time_cutoff_is_independent_of_relative_mtp() {
    let (mut tx,spend,context) = fixture();
    tx.lock_time = LockTime::from_consensus(500_000_513);
    tx.input[0].sequence = Sequence(1<<31);
    let p = NativeElementsLockPolicyV3 {csv_active:false,absolute_time_cutoff:500_000_514};
    assert_eq!(verify_elements_transaction_locks_native_v3(&tx,&[spend.clone()],context,p),Ok(()));
    assert_eq!(verify_elements_transaction_locks_v2(&tx,&[spend],context),Err(ElementsStateErrorV2::AbsoluteLockTime));
}
