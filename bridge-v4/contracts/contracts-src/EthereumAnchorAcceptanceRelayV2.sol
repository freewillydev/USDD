// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAnchorTransitionProofVerifierV2} from
    "./interfaces/IAnchorTransitionProofVerifierV2.sol";
import {IEthereumAnchorAcceptanceRelayV2} from
    "./interfaces/IEthereumAnchorAcceptanceRelayV2.sol";
import {IParentFinalityRelayV2} from "./interfaces/IParentFinalityRelayV2.sol";

/// @notice Ownerless canonical relay for the independent, keyless V11
///         Ethereum-anchor singleton.
/// @dev Inclusion, RPC observations and caller-supplied timestamps are never
///      sufficient. The pinned verifier must prove successful consensus
///      execution, exact full-witness inclusion and BMM binding.
contract EthereumAnchorAcceptanceRelayV2 is IEthereumAnchorAcceptanceRelayV2 {
    uint8 public constant REQUIRED_DRIVECHAIN_SLOT = 24;
    uint64 public constant ABSOLUTE_MAX_ANCHOR_AGE_SECONDS = 6 hours;
    uint64 public constant ABSOLUTE_MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS = 60 days;
    uint64 public constant ABSOLUTE_MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS = 1 hours;
    bool public constant PRODUCTION_READY = false;
    bytes32 public constant SECURITY_MODEL_ID =
        keccak256("USDD_V11_STRONG_RECURSIVE_ELEMENTS_ETHEREUM_ANCHOR_PROFILE");
    bytes32 public constant STATE_DOMAIN = keccak256("USDD_ETHEREUM_ANCHOR_CANONICAL_STATE_V2");
    bytes32 public constant TRANSITION_DOMAIN =
        keccak256("USDD_ETHEREUM_ANCHOR_ACCEPTANCE_TRANSITION_V2");
    bytes32 public constant RELAY_CONFIG_DOMAIN =
        keccak256("USDD_ETHEREUM_ANCHOR_ACCEPTANCE_RELAY_CONFIG_V2");

    struct RelayConfig {
        address proofVerifier;
        bytes32 proofVerifierCodehash;
        bytes32 proofProgramId;
        bytes32 proofConfigHash;
        address parentFinalityRelay;
        bytes32 parentFinalityRelayCodehash;
        bytes32 parentChainIdentity;
        bytes32 parentFinalityConfigHash;
        bytes32 weakSubjectivityPolicyHash;
        bytes32 catchupPolicyHash;
        bytes32 protocolCoreHash;
        bytes32 parentGenesisHash;
        bytes32 elementsGenesisHash;
        bytes32 anchorProgramConfigHash;
        CanonicalAnchorState bootstrapState;
        bytes32 bootstrapExecutionCheckpointHash;
        uint8 drivechainSlot;
        uint64 maxAnchorAgeSeconds;
        uint64 maxWeakSubjectivityPeriodSeconds;
        uint64 minimumRecoveryMarginSeconds;
        uint64 maxFutureTimestampDriftSeconds;
    }

    struct CanonicalAnchorState {
        bytes32 stateCommitment;
        bytes32 cumulativeTranscriptRoot;
        bytes32 lastCatchupOutputCommitment;
        bytes32 parentContextCommitment;
        bytes32 parentBlockHash;
        uint64 sequence;
        uint64 parentBlockHeight;
        uint64 parentMedianTimePast;
        uint256 parentChainwork;
        uint64 ethereumFinalizedSlot;
        uint64 ethereumFinalizedTimestamp;
        uint64 weakSubjectivityValidUntil;
    }

    struct StrongTransition {
        bool bootstrap;
        bytes32 claimedProofProgramId;
        bytes32 claimedProofConfigHash;
        bytes32 claimedParentChainIdentity;
        bytes32 claimedParentFinalityConfigHash;
        bytes32 claimedWeakSubjectivityPolicyHash;
        bytes32 claimedCatchupPolicyHash;
        bytes32 claimedProtocolCoreHash;
        bytes32 claimedParentGenesisHash;
        bytes32 claimedElementsGenesisHash;
        bytes32 claimedAnchorProgramConfigHash;
        CanonicalAnchorState source;
        CanonicalAnchorState successor;
        bytes32 sourceExecutionCheckpointHash;
        bytes32 successorExecutionCheckpointHash;
        bytes32 elementsBlockHash;
        bytes32 anchorTransactionId;
        bytes32 anchorExecutionCommitment;
        bytes32 elementsInclusionCommitment;
        bytes32 bmmInclusionCommitment;
        bytes32 parentBestChainCommitment;
    }

    IAnchorTransitionProofVerifierV2 public immutable PROOF_VERIFIER;
    bytes32 public immutable PROOF_VERIFIER_CODEHASH;
    bytes32 public immutable PROOF_PROGRAM_ID;
    bytes32 public immutable PROOF_CONFIG_HASH;
    IParentFinalityRelayV2 public immutable PARENT_FINALITY_RELAY;
    bytes32 public immutable PARENT_FINALITY_RELAY_CODEHASH;
    bytes32 public immutable PARENT_CHAIN_IDENTITY;
    bytes32 public immutable PARENT_FINALITY_CONFIG_HASH;
    bytes32 public immutable WEAK_SUBJECTIVITY_POLICY_HASH;
    bytes32 public immutable CATCHUP_POLICY_HASH;
    bytes32 public immutable PROTOCOL_CORE_HASH;
    bytes32 public immutable PARENT_GENESIS_HASH;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable ANCHOR_PROGRAM_CONFIG_HASH;
    bytes32 public immutable BOOTSTRAP_STATE_HASH;
    bytes32 public immutable BOOTSTRAP_EXECUTION_CHECKPOINT_HASH;
    uint8 public immutable DRIVECHAIN_SLOT;
    uint64 public immutable MAX_ANCHOR_AGE_SECONDS;
    uint64 public immutable MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS;
    uint64 public immutable MINIMUM_RECOVERY_MARGIN_SECONDS;
    uint64 public immutable MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS;
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    bool public initialized;
    uint64 public acceptedTransitionCount;
    mapping(bytes32 => bool) public acceptedProofStatements;
    mapping(bytes32 => bool) private _acceptedAnchors;
    CanonicalAnchorState private _canonicalState;
    bytes32 public currentExecutionCheckpointHash;
    uint64 public acceptedAt;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error InvalidConfiguration();
    error RuntimeIdentityChanged();
    error WrongStatementIdentity();
    error WrongBootstrapMode();
    error WrongSourceState();
    error WrongSourceExecutionCheckpoint();
    error InvalidSuccessor();
    error InvalidStrongCommitments();
    error ParentCheckpointNotFinalizedCanonical();
    error ProofStatementAlreadyAccepted();
    error ProofRejected();

    event EthereumAnchorAccepted(
        bytes32 indexed publicValuesHash,
        bytes32 indexed stateCommitment,
        bytes32 indexed executionCheckpointHash,
        uint64 sequence,
        uint64 ethereumFinalizedSlot,
        uint64 weakSubjectivityValidUntil,
        address submitter
    );

    constructor(RelayConfig memory c) {
        if (
            c.proofVerifier == address(0) || c.proofVerifierCodehash == bytes32(0)
                || c.proofProgramId == bytes32(0) || c.proofConfigHash == bytes32(0)
                || c.parentFinalityRelay == address(0)
                || c.parentFinalityRelayCodehash == bytes32(0)
                || c.parentChainIdentity == bytes32(0)
                || c.parentFinalityConfigHash == bytes32(0)
                || c.weakSubjectivityPolicyHash == bytes32(0)
                || c.catchupPolicyHash == bytes32(0) || c.protocolCoreHash == bytes32(0)
                || c.parentGenesisHash == bytes32(0) || c.elementsGenesisHash == bytes32(0)
                || c.anchorProgramConfigHash == bytes32(0)
                || c.bootstrapState.stateCommitment == bytes32(0)
                || c.bootstrapExecutionCheckpointHash == bytes32(0)
        ) revert ZeroIdentity();
        if (c.proofVerifier.code.length == 0) revert AddressHasNoCode(c.proofVerifier);
        if (c.parentFinalityRelay.code.length == 0) {
            revert AddressHasNoCode(c.parentFinalityRelay);
        }
        if (
            c.proofVerifier.codehash != c.proofVerifierCodehash
                || c.parentFinalityRelay.codehash != c.parentFinalityRelayCodehash
                || c.drivechainSlot != REQUIRED_DRIVECHAIN_SLOT || c.maxAnchorAgeSeconds == 0
                || c.maxAnchorAgeSeconds > ABSOLUTE_MAX_ANCHOR_AGE_SECONDS
                || c.minimumRecoveryMarginSeconds == 0
                || c.maxWeakSubjectivityPeriodSeconds
                    <= c.minimumRecoveryMarginSeconds + c.maxAnchorAgeSeconds
                || c.maxWeakSubjectivityPeriodSeconds
                    > ABSOLUTE_MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS
                || c.maxFutureTimestampDriftSeconds
                    > ABSOLUTE_MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS
        ) revert InvalidConfiguration();
        IAnchorTransitionProofVerifierV2 verifier =
            IAnchorTransitionProofVerifierV2(c.proofVerifier);
        IParentFinalityRelayV2 parent = IParentFinalityRelayV2(c.parentFinalityRelay);
        if (
            verifier.verifierProgramId() != c.proofProgramId
                || verifier.verifierConfigHash() != c.proofConfigHash
                || parent.parentChainIdentity() != c.parentChainIdentity
                || parent.finalityConfigHash() != c.parentFinalityConfigHash
        ) revert InvalidConfiguration();

        PROOF_VERIFIER = verifier;
        PROOF_VERIFIER_CODEHASH = c.proofVerifierCodehash;
        PROOF_PROGRAM_ID = c.proofProgramId;
        PROOF_CONFIG_HASH = c.proofConfigHash;
        PARENT_FINALITY_RELAY = parent;
        PARENT_FINALITY_RELAY_CODEHASH = c.parentFinalityRelayCodehash;
        PARENT_CHAIN_IDENTITY = c.parentChainIdentity;
        PARENT_FINALITY_CONFIG_HASH = c.parentFinalityConfigHash;
        WEAK_SUBJECTIVITY_POLICY_HASH = c.weakSubjectivityPolicyHash;
        CATCHUP_POLICY_HASH = c.catchupPolicyHash;
        PROTOCOL_CORE_HASH = c.protocolCoreHash;
        PARENT_GENESIS_HASH = c.parentGenesisHash;
        ELEMENTS_GENESIS_HASH = c.elementsGenesisHash;
        ANCHOR_PROGRAM_CONFIG_HASH = c.anchorProgramConfigHash;
        // This is the exact Rust `EthereumAnchorStateV2::commitment`, not a
        // second Solidity-local re-encoding of the bootstrap state.
        BOOTSTRAP_STATE_HASH = c.bootstrapState.stateCommitment;
        BOOTSTRAP_EXECUTION_CHECKPOINT_HASH = c.bootstrapExecutionCheckpointHash;
        DRIVECHAIN_SLOT = c.drivechainSlot;
        MAX_ANCHOR_AGE_SECONDS = c.maxAnchorAgeSeconds;
        MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS = c.maxWeakSubjectivityPeriodSeconds;
        MINIMUM_RECOVERY_MARGIN_SECONDS = c.minimumRecoveryMarginSeconds;
        MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS = c.maxFutureTimestampDriftSeconds;
        verifierProgramId = c.proofProgramId;
        verifierConfigHash = _configHash(c);
    }

    function securityModelId() external pure override returns (bytes32) {
        return SECURITY_MODEL_ID;
    }

    function canonicalStateHash(CanonicalAnchorState memory state) public pure returns (bytes32) {
        return sha256(abi.encode(STATE_DOMAIN, state));
    }

    function anchorSnapshot() external view override returns (AnchorSnapshot memory) {
        CanonicalAnchorState memory s = _canonicalState;
        return AnchorSnapshot({
            stateCommitment: s.stateCommitment,
            executionCheckpointHash: currentExecutionCheckpointHash,
            parentBlockHash: s.parentBlockHash,
            sequence: s.sequence,
            parentBlockHeight: s.parentBlockHeight,
            parentMedianTimePast: s.parentMedianTimePast,
            parentChainwork: s.parentChainwork,
            ethereumFinalizedSlot: s.ethereumFinalizedSlot,
            ethereumFinalizedTimestamp: s.ethereumFinalizedTimestamp,
            weakSubjectivityValidUntil: s.weakSubjectivityValidUntil,
            acceptedAt: acceptedAt
        });
    }

    function isAcceptedAnchor(bytes32 stateCommitment, bytes32 checkpoint, uint64 sequence)
        external
        view
        override
        returns (bool)
    {
        return _acceptedAnchors[_anchorKey(stateCommitment, checkpoint, sequence)];
    }

    function transitionPublicValuesHash(StrongTransition calldata t)
        public
        view
        returns (bytes32)
    {
        return sha256(
            abi.encode(
                TRANSITION_DOMAIN,
                block.chainid,
                address(this),
                DRIVECHAIN_SLOT,
                t.bootstrap,
                _identityHash(t),
                canonicalStateHash(t.source),
                canonicalStateHash(t.successor),
                _evidenceHash(t)
            )
        );
    }

    function advance(StrongTransition calldata t, bytes calldata proof) external {
        _requireLiveIdentities();
        _requireStatementIdentities(t);
        bool bootstrap = !initialized;
        if (t.bootstrap != bootstrap) revert WrongBootstrapMode();
        bytes32 sourceHash = canonicalStateHash(t.source);
        if (
            bootstrap
                ? t.source.stateCommitment != BOOTSTRAP_STATE_HASH
                : sourceHash != canonicalStateHash(_canonicalState)
        ) {
            revert WrongSourceState();
        }
        if (
            t.sourceExecutionCheckpointHash
                != (bootstrap ? BOOTSTRAP_EXECUTION_CHECKPOINT_HASH : currentExecutionCheckpointHash)
        ) revert WrongSourceExecutionCheckpoint();
        _validateSuccessor(t);
        _requireFinalizedParent(t.successor);
        bytes32 publicValuesHash = transitionPublicValuesHash(t);
        if (acceptedProofStatements[publicValuesHash]) revert ProofStatementAlreadyAccepted();
        if (!PROOF_VERIFIER.verifyProof(publicValuesHash, proof)) revert ProofRejected();

        acceptedProofStatements[publicValuesHash] = true;
        initialized = true;
        acceptedTransitionCount += 1;
        _canonicalState = t.successor;
        currentExecutionCheckpointHash = t.successorExecutionCheckpointHash;
        acceptedAt = _u64(block.timestamp);
        _acceptedAnchors[
            _anchorKey(
                t.successor.stateCommitment,
                t.successorExecutionCheckpointHash,
                t.successor.sequence
            )
        ] = true;
        emit EthereumAnchorAccepted(
            publicValuesHash,
            t.successor.stateCommitment,
            t.successorExecutionCheckpointHash,
            t.successor.sequence,
            t.successor.ethereumFinalizedSlot,
            t.successor.weakSubjectivityValidUntil,
            msg.sender
        );
    }

    function _validateSuccessor(StrongTransition calldata t) private view {
        CanonicalAnchorState calldata a = t.source;
        CanonicalAnchorState calldata b = t.successor;
        uint256 latest = block.timestamp + MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS;
        if (
            b.stateCommitment == bytes32(0) || b.stateCommitment == a.stateCommitment
                || b.cumulativeTranscriptRoot == bytes32(0)
                || b.lastCatchupOutputCommitment == bytes32(0)
                || b.parentContextCommitment == bytes32(0) || b.parentBlockHash == bytes32(0)
                || b.sequence != a.sequence + 1 || b.parentBlockHeight <= a.parentBlockHeight
                || b.parentChainwork <= a.parentChainwork
                || b.parentMedianTimePast < a.parentMedianTimePast
                || b.ethereumFinalizedSlot <= a.ethereumFinalizedSlot
                || b.ethereumFinalizedTimestamp <= a.ethereumFinalizedTimestamp
                || b.weakSubjectivityValidUntil <= b.ethereumFinalizedTimestamp
                || b.weakSubjectivityValidUntil - b.ethereumFinalizedTimestamp
                    > MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS
                || b.parentMedianTimePast > latest || b.ethereumFinalizedTimestamp > latest
                || _difference(b.parentMedianTimePast, b.ethereumFinalizedTimestamp)
                    > MAX_ANCHOR_AGE_SECONDS
                || b.weakSubjectivityValidUntil
                    <= block.timestamp + MINIMUM_RECOVERY_MARGIN_SECONDS
        ) revert InvalidSuccessor();
        if (
            t.sourceExecutionCheckpointHash == bytes32(0)
                || t.successorExecutionCheckpointHash == bytes32(0)
                || t.sourceExecutionCheckpointHash == t.successorExecutionCheckpointHash
                || t.elementsBlockHash == bytes32(0) || t.anchorTransactionId == bytes32(0)
                || t.anchorExecutionCommitment == bytes32(0)
                || t.elementsInclusionCommitment == bytes32(0)
                || t.bmmInclusionCommitment == bytes32(0)
                || t.parentBestChainCommitment == bytes32(0)
        ) revert InvalidStrongCommitments();
    }

    function _requireFinalizedParent(CanonicalAnchorState calldata s) private view {
        if (
            PARENT_FINALITY_RELAY.currentFinalizedHeight() < s.parentBlockHeight
                || !PARENT_FINALITY_RELAY.isFinalizedCanonical(
                    s.parentBlockHash,
                    s.parentBlockHeight,
                    s.parentMedianTimePast,
                    s.parentChainwork
                )
        ) revert ParentCheckpointNotFinalizedCanonical();
    }

    function _requireLiveIdentities() private view {
        if (
            address(PROOF_VERIFIER).codehash != PROOF_VERIFIER_CODEHASH
                || address(PARENT_FINALITY_RELAY).codehash != PARENT_FINALITY_RELAY_CODEHASH
                || PROOF_VERIFIER.verifierProgramId() != PROOF_PROGRAM_ID
                || PROOF_VERIFIER.verifierConfigHash() != PROOF_CONFIG_HASH
                || PARENT_FINALITY_RELAY.parentChainIdentity() != PARENT_CHAIN_IDENTITY
                || PARENT_FINALITY_RELAY.finalityConfigHash() != PARENT_FINALITY_CONFIG_HASH
        ) revert RuntimeIdentityChanged();
    }

    function _requireStatementIdentities(StrongTransition calldata t) private view {
        if (
            t.claimedProofProgramId != PROOF_PROGRAM_ID
                || t.claimedProofConfigHash != PROOF_CONFIG_HASH
                || t.claimedParentChainIdentity != PARENT_CHAIN_IDENTITY
                || t.claimedParentFinalityConfigHash != PARENT_FINALITY_CONFIG_HASH
                || t.claimedWeakSubjectivityPolicyHash != WEAK_SUBJECTIVITY_POLICY_HASH
                || t.claimedCatchupPolicyHash != CATCHUP_POLICY_HASH
                || t.claimedProtocolCoreHash != PROTOCOL_CORE_HASH
                || t.claimedParentGenesisHash != PARENT_GENESIS_HASH
                || t.claimedElementsGenesisHash != ELEMENTS_GENESIS_HASH
                || t.claimedAnchorProgramConfigHash != ANCHOR_PROGRAM_CONFIG_HASH
        ) revert WrongStatementIdentity();
    }

    function _identityHash(StrongTransition calldata t) private pure returns (bytes32) {
        return sha256(
            abi.encode(
                t.claimedProofProgramId,
                t.claimedProofConfigHash,
                t.claimedParentChainIdentity,
                t.claimedParentFinalityConfigHash,
                t.claimedWeakSubjectivityPolicyHash,
                t.claimedCatchupPolicyHash,
                t.claimedProtocolCoreHash,
                t.claimedParentGenesisHash,
                t.claimedElementsGenesisHash,
                t.claimedAnchorProgramConfigHash
            )
        );
    }

    function _evidenceHash(StrongTransition calldata t) private pure returns (bytes32) {
        return sha256(
            abi.encode(
                t.sourceExecutionCheckpointHash,
                t.successorExecutionCheckpointHash,
                t.elementsBlockHash,
                t.anchorTransactionId,
                t.anchorExecutionCommitment,
                t.elementsInclusionCommitment,
                t.bmmInclusionCommitment,
                t.parentBestChainCommitment
            )
        );
    }

    function _configHash(RelayConfig memory c) private view returns (bytes32) {
        return sha256(abi.encode(RELAY_CONFIG_DOMAIN, block.chainid, address(this), c));
    }

    function _anchorKey(bytes32 state, bytes32 checkpoint, uint64 sequence)
        private
        pure
        returns (bytes32)
    {
        return sha256(abi.encode(state, checkpoint, sequence));
    }

    function _difference(uint64 a, uint64 b) private pure returns (uint64) {
        return a >= b ? a - b : b - a;
    }

    function _u64(uint256 value) private pure returns (uint64) {
        if (value > type(uint64).max) revert InvalidSuccessor();
        return uint64(value);
    }
}
