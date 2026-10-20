use ecx_parent_enforcer::{
    bitcoin_double_sha256, verify_miner_header_commitment, ApprovalError, HeaderOnlyChildContextV1,
    LocallyValidatedBmmCommitmentV1, ParentEnforcerConfigV1, BMM_SLOT,
    PARENT_ENFORCER_ADAPTER_VERSION, REQUIRED_ECX_WITHDRAWAL_HEADER_MASK,
};

const HEADER_LEN: usize = 300;
const SUFFIX_LEN: usize = 100;

#[derive(Clone)]
struct Fixture {
    config: ParentEnforcerConfigV1,
    bmm: LocallyValidatedBmmCommitmentV1,
    context: HeaderOnlyChildContextV1,
    header: Vec<u8>,
}

impl Fixture {
    fn accept(&self) -> Result<ecx_parent_enforcer::AcceptedHeaderCommitmentV1, ApprovalError> {
        verify_miner_header_commitment(&self.config, &self.bmm, &self.context, &self.header)
    }

    fn recommit(&mut self) {
        self.bmm.critical_hash = bitcoin_double_sha256(&self.header);
    }
}

fn fixture() -> Fixture {
    let child_genesis_hash = [0x11; 32];
    let previous_child_block_hash = [0x12; 32];
    let withdrawal_bundle_hash = [0x13; 32];
    let exchange_state_root = [0x14; 32];
    let forced_inbox_root = [0x15; 32];
    let deposit_inbox_root = [0x16; 32];
    let approving_parent_height: u32 = 700_001;
    let header_version = REQUIRED_ECX_WITHDRAWAL_HEADER_MASK | 3;

    let mut header = vec![0x77; HEADER_LEN];
    header[0..4].copy_from_slice(&header_version.to_le_bytes());
    header[4..36].copy_from_slice(&previous_child_block_hash);
    header[68..100].copy_from_slice(&withdrawal_bundle_hash);
    header[100..132].fill(0);
    let suffix = HEADER_LEN - SUFFIX_LEN;
    header[suffix..suffix + 32].copy_from_slice(&exchange_state_root);
    header[suffix + 32..suffix + 64].copy_from_slice(&forced_inbox_root);
    header[suffix + 64..suffix + 96].copy_from_slice(&deposit_inbox_root);
    header[suffix + 96..].copy_from_slice(&approving_parent_height.to_le_bytes());

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
            approving_parent_block_hash: [0x17; 32],
            approving_parent_height,
        },
        context: HeaderOnlyChildContextV1 {
            version: PARENT_ENFORCER_ADAPTER_VERSION,
            child_genesis_hash,
            checkpoint_height: 42,
            previous_child_block_hash,
            expected_header_version: header_version,
            critical_header_len: HEADER_LEN as u32,
        },
        header,
    }
}

#[test]
fn accepts_only_the_bip301_committed_elements_header() {
    let fixture = fixture();
    let accepted = fixture.accept().unwrap();

    assert_eq!(accepted.critical_hash, fixture.bmm.critical_hash);
    assert_eq!(accepted.withdrawal_bundle_hash, [0x13; 32]);
}

#[test]
fn any_uncommitted_header_mutation_is_rejected() {
    for offset in [4, 68, 132, HEADER_LEN - 100, HEADER_LEN - 4] {
        let mut fixture = fixture();
        fixture.header[offset] ^= 1;
        assert!(matches!(
            fixture.accept(),
            Err(ApprovalError::CriticalHeaderMismatch(_))
        ));
    }
}

#[test]
fn miner_commits_to_state_bytes_without_interpreting_state_semantics() {
    let mut fixture = fixture();
    let original_critical_hash = fixture.bmm.critical_hash;
    let suffix = HEADER_LEN - SUFFIX_LEN;
    fixture.header[suffix] ^= 1;
    fixture.recommit();

    let accepted = fixture.accept().unwrap();
    assert_ne!(accepted.critical_hash, original_critical_hash);
    assert_eq!(accepted.withdrawal_bundle_hash, [0x13; 32]);
}

#[test]
fn semantic_ecx_invalidity_is_left_to_elements_consensus() {
    let mut fixture = fixture();
    let suffix = HEADER_LEN - SUFFIX_LEN;
    fixture.header[suffix..].fill(0);
    fixture.recommit();

    let accepted = fixture.accept().unwrap();
    assert_eq!(accepted.critical_hash, fixture.bmm.critical_hash);
    assert_eq!(accepted.withdrawal_bundle_hash, [0x13; 32]);
}

#[test]
fn rejects_noncanonical_header_context() {
    let mut bad_predecessor = fixture();
    bad_predecessor.context.previous_child_block_hash[0] ^= 1;
    assert_eq!(
        bad_predecessor.accept(),
        Err(ApprovalError::CriticalHeaderMismatch(
            "previous child block hash"
        ))
    );

    let mut bad_length = fixture();
    bad_length.context.critical_header_len -= 1;
    assert_eq!(
        bad_length.accept(),
        Err(ApprovalError::CriticalHeaderMismatch("serialized length"))
    );

    let mut bad_version = fixture();
    bad_version.context.expected_header_version ^= 1;
    assert_eq!(
        bad_version.accept(),
        Err(ApprovalError::CriticalHeaderMismatch("version"))
    );
}

#[test]
fn rejects_a_nonzero_bmm_proof_in_the_critical_preimage() {
    let mut fixture = fixture();
    fixture.header[100] = 1;
    fixture.recommit();
    assert_eq!(
        fixture.accept(),
        Err(ApprovalError::MalformedCriticalHeader(
            "BMM proof is not cleared"
        ))
    );
}
