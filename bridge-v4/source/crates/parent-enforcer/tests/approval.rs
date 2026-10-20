#![cfg(feature = "legacy-pxst-reference")]

use ecx_parent_enforcer::{
    bitcoin_double_sha256, verify_parent_miner_pxst_approval, withdrawal_inputs_commitment,
    ApprovalError, LegacyM6PolicyV1, LocallyValidatedBmmCommitmentV1,
    LocallyValidatedChildCheckpointV1, ParentEnforcerConfigV1, WithdrawalOutpointV1,
    MAX_CRITICAL_HEADER_BYTES, MAX_M6_BYTES, PARENT_ENFORCER_ADAPTER_VERSION,
    REQUIRED_ECX_WITHDRAWAL_HEADER_MASK,
};
use ecx_protocol_core::{ProtocolError, WithdrawalStateAnchorV1, BMM_SLOT};

const HEADER_LEN: usize = 300;

#[derive(Debug, Clone)]
struct TestOutput {
    value: u64,
    script: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Fixture {
    config: ParentEnforcerConfigV1,
    bmm: LocallyValidatedBmmCommitmentV1,
    checkpoint: LocallyValidatedChildCheckpointV1,
    policy: LegacyM6PolicyV1,
    header: Vec<u8>,
    outputs: [TestOutput; 4],
    m6: Vec<u8>,
    witness_encoded: bool,
}

impl Fixture {
    fn approve(&self) -> Result<ecx_parent_enforcer::ApprovedParentWithdrawalV1, ApprovalError> {
        verify_parent_miner_pxst_approval(
            &self.config,
            &self.bmm,
            &self.checkpoint,
            &self.header,
            &self.policy,
            &self.m6,
        )
    }

    fn rehash_header(&mut self) {
        self.bmm.critical_hash = bitcoin_double_sha256(&self.header);
    }

    fn rebuild_m6_and_header(&mut self) {
        self.m6 = serialize_m6(&self.outputs, self.witness_encoded);
        let no_witness = serialize_m6(&self.outputs, false);
        self.header[68..100].copy_from_slice(&bitcoin_double_sha256(&no_witness));
        self.rehash_header();
    }

    fn suffix_start(&self) -> usize {
        self.header.len() - 100
    }
}

fn make_fixture(witness_encoded: bool) -> Fixture {
    let child_genesis_hash = [0x01; 32];
    let previous_child_block_hash = [0x02; 32];
    let exchange_state_root = [0x04; 32];
    let forced_inbox_root = [0x05; 32];
    let deposit_inbox_root = [0x06; 32];
    let checkpoint_height = 42;
    let source_parent_height: u32 = 700_001;
    let withdrawal_outpoint = WithdrawalOutpointV1 {
        txid: [0x11; 32],
        vout: 7,
    };
    let withdrawal_commitment =
        withdrawal_inputs_commitment(withdrawal_outpoint, checkpoint_height);
    let pxst = WithdrawalStateAnchorV1 {
        version: 1,
        slot: BMM_SLOT,
        child_genesis_hash,
        checkpoint_height,
        previous_child_block_hash,
        existing_withdrawal_commitment: withdrawal_commitment,
        exchange_state_root,
    }
    .op_return_script()
    .unwrap()
    .to_vec();

    let mainchain_fee: u64 = 300;
    let mut fee_script = vec![0x6a, 0x08];
    fee_script.extend_from_slice(&mainchain_fee.to_be_bytes());
    let mut commitment_script = vec![0x6a, 0x20];
    commitment_script.extend_from_slice(&withdrawal_commitment);
    let mut payout_script = vec![0x00, 0x14];
    payout_script.extend_from_slice(&[0x77; 20]);
    let outputs = [
        TestOutput {
            value: 0,
            script: fee_script,
        },
        TestOutput {
            value: 0,
            script: commitment_script,
        },
        TestOutput {
            value: 50_000,
            script: payout_script.clone(),
        },
        TestOutput {
            value: 0,
            script: pxst,
        },
    ];
    let m6 = serialize_m6(&outputs, witness_encoded);
    let m6id = bitcoin_double_sha256(&serialize_m6(&outputs, false));

    let header_version = REQUIRED_ECX_WITHDRAWAL_HEADER_MASK | 3;
    let mut header = vec![0x77; HEADER_LEN];
    header[0..4].copy_from_slice(&header_version.to_le_bytes());
    header[4..36].copy_from_slice(&previous_child_block_hash);
    header[36..68].copy_from_slice(&[0x33; 32]);
    header[68..100].copy_from_slice(&m6id);
    header[100..132].fill(0); // exact GetBmmCriticalHash preimage
    let suffix_start = HEADER_LEN - 100;
    header[suffix_start..suffix_start + 32].copy_from_slice(&exchange_state_root);
    header[suffix_start + 32..suffix_start + 64].copy_from_slice(&forced_inbox_root);
    header[suffix_start + 64..suffix_start + 96].copy_from_slice(&deposit_inbox_root);
    header[suffix_start + 96..suffix_start + 100]
        .copy_from_slice(&source_parent_height.to_le_bytes());

    Fixture {
        config: ParentEnforcerConfigV1 {
            version: PARENT_ENFORCER_ADAPTER_VERSION,
            sidechain_slot: BMM_SLOT,
            child_genesis_hash,
        },
        bmm: LocallyValidatedBmmCommitmentV1 {
            version: PARENT_ENFORCER_ADAPTER_VERSION,
            sidechain_slot: BMM_SLOT,
            critical_hash: bitcoin_double_sha256(&header),
            approving_parent_block_hash: [0x99; 32],
            approving_parent_height: source_parent_height,
        },
        checkpoint: LocallyValidatedChildCheckpointV1 {
            version: PARENT_ENFORCER_ADAPTER_VERSION,
            child_genesis_hash,
            checkpoint_height,
            previous_child_block_hash,
            expected_exchange_state_root: exchange_state_root,
            expected_forced_inbox_root: forced_inbox_root,
            expected_deposit_inbox_root: deposit_inbox_root,
            expected_header_version: header_version,
            critical_header_len: HEADER_LEN as u32,
        },
        policy: LegacyM6PolicyV1 {
            version: 1,
            withdrawal_outpoint,
            expected_mainchain_fee_sats: mainchain_fee,
            expected_payout_sats: 50_000,
            expected_payout_script: payout_script,
        },
        header,
        outputs,
        m6,
        witness_encoded,
    }
}

fn serialize_m6(outputs: &[TestOutput; 4], witness_encoded: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2_i32.to_le_bytes());
    if witness_encoded {
        bytes.extend_from_slice(&[0, 1]);
    }
    bytes.push(0);
    bytes.push(4);
    for output in outputs {
        bytes.extend_from_slice(&output.value.to_le_bytes());
        assert!(output.script.len() < 0xfd);
        bytes.push(output.script.len() as u8);
        bytes.extend_from_slice(&output.script);
    }
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

fn marker_for(fixture: &Fixture, mutate: impl FnOnce(&mut WithdrawalStateAnchorV1)) -> Vec<u8> {
    let mut anchor = WithdrawalStateAnchorV1 {
        version: 1,
        slot: BMM_SLOT,
        child_genesis_hash: fixture.checkpoint.child_genesis_hash,
        checkpoint_height: fixture.checkpoint.checkpoint_height,
        previous_child_block_hash: fixture.checkpoint.previous_child_block_hash,
        existing_withdrawal_commitment: withdrawal_inputs_commitment(
            fixture.policy.withdrawal_outpoint,
            fixture.checkpoint.checkpoint_height,
        ),
        exchange_state_root: fixture.checkpoint.expected_exchange_state_root,
    };
    mutate(&mut anchor);
    anchor.op_return_script().unwrap().to_vec()
}

#[test]
fn approves_exact_witness_and_txid_encodings() {
    for witness_encoded in [false, true] {
        let fixture = make_fixture(witness_encoded);
        let approved = fixture.approve().unwrap();
        assert_eq!(approved.sidechain_slot, BMM_SLOT);
        assert_eq!(approved.critical_hash, fixture.bmm.critical_hash);
        assert_eq!(
            approved.approving_parent_block_hash,
            fixture.bmm.approving_parent_block_hash
        );
        assert_eq!(
            approved.exchange_state_root,
            fixture.checkpoint.expected_exchange_state_root
        );
        assert_eq!(
            approved.existing_withdrawal_commitment,
            withdrawal_inputs_commitment(
                fixture.policy.withdrawal_outpoint,
                fixture.checkpoint.checkpoint_height
            )
        );
    }
}

#[test]
fn rejects_wrong_local_versions_slot_genesis_and_zero_fields() {
    let mut fixture = make_fixture(false);
    fixture.config.version = 2;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::InvalidConfiguration("version"))
    );

    let mut fixture = make_fixture(false);
    fixture.bmm.sidechain_slot = 23;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::InvalidBmmRecord("slot"))
    );

    let mut fixture = make_fixture(false);
    fixture.checkpoint.child_genesis_hash[0] ^= 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::InvalidCheckpoint("child genesis"))
    );

    let mut fixture = make_fixture(false);
    fixture.bmm.approving_parent_block_hash = [0; 32];
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::InvalidBmmRecord("zero field"))
    );

    let mut fixture = make_fixture(false);
    fixture.checkpoint.checkpoint_height = 0;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::InvalidCheckpoint("zero field"))
    );
}

#[test]
fn rejects_unbounded_or_wrong_length_critical_header() {
    let mut fixture = make_fixture(false);
    fixture.header.truncate(200);
    assert_eq!(fixture.approve(), Err(ApprovalError::CriticalHeaderSize));

    let mut fixture = make_fixture(false);
    fixture.header.resize(MAX_CRITICAL_HEADER_BYTES + 1, 0);
    assert_eq!(fixture.approve(), Err(ApprovalError::CriticalHeaderSize));

    let mut fixture = make_fixture(false);
    fixture.checkpoint.critical_header_len += 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::CriticalHeaderMismatch("serialized length"))
    );
}

#[test]
fn rejects_header_version_previous_hash_and_uncleared_bmm_field() {
    let mut fixture = make_fixture(false);
    fixture.header[0] ^= 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::CriticalHeaderMismatch("version"))
    );

    let mut fixture = make_fixture(false);
    fixture.header[4] ^= 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::CriticalHeaderMismatch(
            "previous child block hash"
        ))
    );

    let mut fixture = make_fixture(false);
    fixture.header[100] = 1;
    fixture.rehash_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedCriticalHeader(
            "BMM proof is not cleared"
        ))
    );
}

#[test]
fn rejects_critical_hash_and_source_parent_height_mismatches() {
    let mut fixture = make_fixture(false);
    fixture.header[150] ^= 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::CriticalHeaderMismatch("BMM critical hash"))
    );

    let mut fixture = make_fixture(false);
    let start = fixture.suffix_start();
    fixture.header[start + 96..start + 100]
        .copy_from_slice(&(fixture.bmm.approving_parent_height + 1).to_le_bytes());
    fixture.rehash_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::CriticalHeaderMismatch("parent height"))
    );
}

#[test]
fn rejects_each_ecx_root_mismatch_and_zero_root() {
    for (offset, field) in [
        (0, "exchange state root"),
        (32, "forced inbox root"),
        (64, "deposit inbox root"),
    ] {
        let mut fixture = make_fixture(false);
        let start = fixture.suffix_start() + offset;
        fixture.header[start] ^= 1;
        fixture.rehash_header();
        assert_eq!(
            fixture.approve(),
            Err(ApprovalError::CriticalHeaderMismatch(field))
        );
    }

    let mut fixture = make_fixture(false);
    let start = fixture.suffix_start();
    fixture.header[start..start + 32].fill(0);
    fixture.rehash_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedCriticalHeader("zero ECX root"))
    );
}

#[test]
fn rejects_zero_or_wrong_withdrawal_m6id() {
    let mut fixture = make_fixture(false);
    fixture.header[68..100].fill(0);
    fixture.rehash_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedCriticalHeader(
            "zero withdrawal M6ID"
        ))
    );

    let mut fixture = make_fixture(false);
    fixture.header[68] ^= 1;
    fixture.rehash_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::CriticalHeaderMismatch("withdrawal M6ID"))
    );
}

#[test]
fn rejects_malformed_noncanonical_and_unbounded_m6() {
    let mut fixture = make_fixture(false);
    fixture.m6.truncate(5);
    assert_eq!(fixture.approve(), Err(ApprovalError::UnexpectedEnd));

    let mut fixture = make_fixture(false);
    fixture.m6 = vec![0; MAX_M6_BYTES + 1];
    assert_eq!(fixture.approve(), Err(ApprovalError::M6Size));

    let mut fixture = make_fixture(false);
    fixture.m6.extend_from_slice(&[0]);
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedM6("trailing bytes"))
    );

    let mut fixture = make_fixture(false);
    fixture.m6[0] = 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedM6("version"))
    );

    let mut fixture = make_fixture(false);
    fixture.m6[4] = 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedM6("non-empty inputs"))
    );

    let mut fixture = make_fixture(false);
    fixture.m6.splice(5..6, [0xfd, 4, 0]);
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::NonCanonicalCompactSize)
    );

    let mut fixture = make_fixture(false);
    fixture.m6[5] = 3;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedM6("output count"))
    );

    let mut fixture = make_fixture(false);
    fixture.m6[13] = 0x80;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedM6("negative output value"))
    );

    let mut fixture = make_fixture(false);
    fixture.m6.splice(14..15, [0xfd, 0x11, 0x27]);
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedM6("script size"))
    );

    let mut fixture = make_fixture(false);
    let last = fixture.m6.len() - 4;
    fixture.m6[last] = 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::MalformedM6("lock time"))
    );
}

#[test]
fn rejects_output_order_value_fee_payout_and_w_mismatches() {
    let mut fixture = make_fixture(false);
    fixture.outputs.swap(0, 1);
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch("fee output"))
    );

    let mut fixture = make_fixture(false);
    fixture.outputs[0].value = 1;
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch("fee output"))
    );

    let mut fixture = make_fixture(false);
    fixture.outputs[0].script[9] ^= 1;
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch("fee output"))
    );

    let mut fixture = make_fixture(false);
    fixture.outputs[1].script[2] ^= 1;
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch(
            "withdrawal commitment output"
        ))
    );

    let mut fixture = make_fixture(false);
    fixture.outputs[2].value += 1;
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch("payout output"))
    );

    let mut fixture = make_fixture(false);
    fixture.outputs[2].script.push(0x51);
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch("payout output"))
    );

    let mut fixture = make_fixture(false);
    fixture.outputs[3].value = 1;
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch("PXST output value"))
    );
}

#[test]
fn rejects_checkpoint_height_change_through_reconstructed_w() {
    let mut fixture = make_fixture(false);
    fixture.checkpoint.checkpoint_height += 1;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::LegacyM6Mismatch(
            "withdrawal commitment output"
        ))
    );
}

#[test]
fn rejects_pxst_genesis_previous_height_root_and_duplicate_namespace() {
    let cases: [fn(&mut WithdrawalStateAnchorV1); 4] = [
        |anchor| anchor.child_genesis_hash[0] ^= 1,
        |anchor| anchor.previous_child_block_hash[0] ^= 1,
        |anchor| anchor.checkpoint_height += 1,
        |anchor| anchor.exchange_state_root[0] ^= 1,
    ];
    for mutate in cases {
        let mut fixture = make_fixture(false);
        fixture.outputs[3].script = marker_for(&fixture, mutate);
        fixture.rebuild_m6_and_header();
        assert_eq!(
            fixture.approve(),
            Err(ApprovalError::Protocol(
                ProtocolError::WithdrawalStateApprovalMismatch
            ))
        );
    }

    let mut fixture = make_fixture(false);
    fixture.outputs[2].script = fixture.outputs[3].script.clone();
    fixture.policy.expected_payout_script = fixture.outputs[2].script.clone();
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::Protocol(
            ProtocolError::WithdrawalStateApprovalMismatch
        ))
    );
}

#[test]
fn rejects_noncanonical_pxst_and_legacy_policy_parameters() {
    let mut fixture = make_fixture(false);
    fixture.outputs[3].script.insert(1, 0x4c);
    fixture.rebuild_m6_and_header();
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::Protocol(
            ProtocolError::WithdrawalStateApprovalMismatch
        ))
    );

    let mut fixture = make_fixture(false);
    fixture.policy.version = 2;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::InvalidConfiguration(
            "legacy M6 policy version"
        ))
    );

    let mut fixture = make_fixture(false);
    fixture.policy.expected_payout_sats = 0;
    assert_eq!(
        fixture.approve(),
        Err(ApprovalError::InvalidConfiguration("payout value"))
    );
}

#[test]
fn w_is_bound_to_raw_txid_vout_and_checkpoint_height() {
    let fixture = make_fixture(false);
    let baseline = withdrawal_inputs_commitment(
        fixture.policy.withdrawal_outpoint,
        fixture.checkpoint.checkpoint_height,
    );
    assert_eq!(
        baseline,
        [
            0x22, 0xc1, 0x96, 0x89, 0x94, 0x86, 0x51, 0x37, 0xae, 0xfa, 0xfb, 0xdd, 0x79, 0x45,
            0x9b, 0xed, 0xd0, 0xd0, 0x5c, 0x2e, 0x17, 0x42, 0x21, 0x43, 0xef, 0xe8, 0xa5, 0xf7,
            0x15, 0x18, 0x59, 0x67,
        ]
    );
    let mut outpoint = fixture.policy.withdrawal_outpoint;
    outpoint.txid[0] ^= 1;
    assert_ne!(
        baseline,
        withdrawal_inputs_commitment(outpoint, fixture.checkpoint.checkpoint_height)
    );
    let mut outpoint = fixture.policy.withdrawal_outpoint;
    outpoint.vout += 1;
    assert_ne!(
        baseline,
        withdrawal_inputs_commitment(outpoint, fixture.checkpoint.checkpoint_height)
    );
    assert_ne!(
        baseline,
        withdrawal_inputs_commitment(
            fixture.policy.withdrawal_outpoint,
            fixture.checkpoint.checkpoint_height + 1
        )
    );
}
