// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IControllerAcceptanceRelayV2} from "./interfaces/IControllerAcceptanceRelayV2.sol";
import {IControllerTransitionProofVerifierV2} from
    "./interfaces/IControllerTransitionProofVerifierV2.sol";
import {IParentFinalityRelayV2} from "./interfaces/IParentFinalityRelayV2.sol";
import {IEthereumAnchorAcceptanceRelayV2} from
    "./interfaces/IEthereumAnchorAcceptanceRelayV2.sol";

/// @title ControllerAcceptanceRelayV2
/// @notice Ownerless, immutable relay for proof-authenticated canonical Elements
///         controller transitions.
/// @dev The relay has no administrator, setter, proxy, pause, arbitrary call
///      target, or unproved initialization path. The first accepted statement
///      must start at the exact frozen bootstrap-source commitment. Every later
///      statement must start at the exact canonical state currently stored.
///
/// @custom:security-status BLOCKED
/// A deployment of this contract is NOT production-ready until an independently
/// audited verifier exists whose proof guest establishes the complete strong
/// statement documented by IControllerTransitionProofVerifierV2. Test mocks,
/// raw BMM proofs, watcher attestations, and execution-only proofs are forbidden
/// production verifier implementations.
contract ControllerAcceptanceRelayV2 is IControllerAcceptanceRelayV2 {
    uint8 public constant REQUIRED_DRIVECHAIN_SLOT = 24;
    uint64 public constant ABSOLUTE_MAX_ADMISSION_AGE_SECONDS = 6 hours;
    uint64 public constant ABSOLUTE_MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS = 60 days;
    uint64 public constant ABSOLUTE_MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS = 1 hours;
    bool public constant PRODUCTION_READY = false;
    bytes32 public constant SECURITY_STATUS =
        keccak256("BLOCKED_UNTIL_STRONG_CONTROLLER_ACCEPTANCE_GUEST_AND_VERIFIER_ARE_AUDITED");
    bytes32 public constant SECURITY_MODEL_ID =
        keccak256("USDD_V11_STRONG_RECURSIVE_ELEMENTS_CONTROLLER_EXECUTION_PROFILE");
    bytes32 public constant TRANSITION_PUBLIC_VALUES_DOMAIN =
        keccak256("USDD_CONTROLLER_ACCEPTANCE_TRANSITION_V2");
    bytes32 public constant CANONICAL_STATE_DOMAIN =
        keccak256("USDD_CONTROLLER_CANONICAL_STATE_V2");
    bytes32 public constant RELAY_VERIFIER_CONFIG_DOMAIN =
        keccak256("USDD_CONTROLLER_ACCEPTANCE_RELAY_CONFIG_V2");

    function securityModelId() external pure override returns (bytes32) {
        return SECURITY_MODEL_ID;
    }

    struct RelayConfig {
        address proofVerifier;
        bytes32 proofVerifierCodehash;
        bytes32 proofProgramId;
        bytes32 proofConfigHash;
        address parentFinalityRelay;
        bytes32 parentFinalityRelayCodehash;
        bytes32 parentChainIdentity;
        bytes32 parentFinalityConfigHash;
        address ethereumAnchorAcceptanceRelay;
        bytes32 ethereumAnchorAcceptanceRelayCodehash;
        bytes32 ethereumAnchorSecurityModelId;
        bytes32 ethereumAnchorVerifierProgramId;
        bytes32 ethereumAnchorVerifierConfigHash;
        bytes32 weakSubjectivityPolicyHash;
        bytes32 protocolCoreHash;
        bytes32 parentGenesisHash;
        bytes32 elementsGenesisHash;
        bytes32 controllerProgramConfigHash;
        /// @dev Exact `TerminalVaultPolicyV2::policy_hash` over the deployed
        ///      vault address, immutable-patched runtime code hash, storage
        ///      layout identity, protocol/vault IDs and Ethereum domain. This
        ///      post-deployment policy binding is deliberately distinct from
        ///      the predeployment protocol/vault identity projection.
        bytes32 inboundVaultConfigHash;
        bytes32 usddAssetId;
        bytes32 bootstrapSourceHash;
        /// @dev Exact `ControllerExecutionCheckpointV2::checkpoint_hash` for
        ///      the frozen authority-lock and fee-reserve outputs. Kept separate from
        ///      `bootstrapSourceHash` to avoid a transaction-ID/state-output
        ///      commitment cycle.
        bytes32 bootstrapExecutionCheckpointHash;
        uint8 drivechainSlot;
        uint64 maxControllerAdmissionAgeSeconds;
        /// @dev Outer bound only. The proof guest derives the exact deadline
        ///      from authenticated Ethereum consensus state under
        ///      `weakSubjectivityPolicyHash`.
        uint64 maxWeakSubjectivityPeriodSeconds;
        uint64 minimumRecoveryMarginSeconds;
        uint64 maxFutureTimestampDriftSeconds;
    }

    /// @dev Canonical fields authenticated by the proof. Ethereum-local relay
    ///      acceptance time and the derived admission lease are deliberately
    ///      absent.
    struct CanonicalControllerState {
        bytes32 controllerStateHash;
        bytes32 cumulativeResolutionRoot;
        bytes32 parentBlockHash;
        uint64 controllerSequence;
        uint64 resolutionCount;
        uint64 nextResolutionNonce;
        uint64 parentBlockHeight;
        uint64 parentMedianTimePast;
        uint256 parentChainwork;
        uint64 ethereumFinalizedSlot;
        uint64 ethereumFinalizedTimestamp;
        uint64 weakSubjectivityValidUntil;
    }

    /// @dev Each nonzero commitment is part of the public statement proved by
    ///      the verifier. They prevent the relay API from accidentally
    ///      degrading to a proof of a state hash without execution, inclusion,
    ///      BMM, or best-chain semantics.
    struct StrongTransition {
        bool bootstrap;
        bytes32 claimedProofProgramId;
        bytes32 claimedProofConfigHash;
        bytes32 claimedParentChainIdentity;
        bytes32 claimedParentFinalityConfigHash;
        bytes32 claimedWeakSubjectivityPolicyHash;
        bytes32 claimedProtocolCoreHash;
        bytes32 claimedParentGenesisHash;
        bytes32 claimedElementsGenesisHash;
        bytes32 claimedControllerProgramConfigHash;
        bytes32 claimedInboundVaultConfigHash;
        bytes32 claimedUsddAssetId;
        CanonicalControllerState source;
        CanonicalControllerState successor;
        bytes32 sourceExecutionCheckpointHash;
        bytes32 successorExecutionCheckpointHash;
        bytes32 elementsBlockHash;
        uint64 elementsBlockHeight;
        bytes32 controllerTransactionId;
        bytes32 controllerExecutionCommitment;
        bytes32 dispositionsCommitment;
        bytes32 elementsInclusionCommitment;
        bytes32 bmmInclusionCommitment;
        /// @dev Commits the parent header-chain witness used by the proof. It
        ///      does not itself establish greatest-work canonicality; the
        ///      pinned IParentFinalityRelayV2 performs that independent check.
        bytes32 parentBestChainCommitment;
        bytes32 acceptedAnchorStateCommitment;
        bytes32 acceptedAnchorExecutionCheckpointHash;
        uint64 acceptedAnchorSequence;
    }

    IControllerTransitionProofVerifierV2 public immutable PROOF_VERIFIER;
    bytes32 public immutable PROOF_VERIFIER_CODEHASH;
    bytes32 public immutable PROOF_PROGRAM_ID;
    bytes32 public immutable PROOF_CONFIG_HASH;
    IParentFinalityRelayV2 public immutable PARENT_FINALITY_RELAY;
    bytes32 public immutable PARENT_FINALITY_RELAY_CODEHASH;
    bytes32 public immutable PARENT_CHAIN_IDENTITY;
    bytes32 public immutable PARENT_FINALITY_CONFIG_HASH;
    IEthereumAnchorAcceptanceRelayV2 public immutable ETHEREUM_ANCHOR_ACCEPTANCE_RELAY;
    bytes32 public immutable ETHEREUM_ANCHOR_ACCEPTANCE_RELAY_CODEHASH;
    bytes32 public immutable ETHEREUM_ANCHOR_SECURITY_MODEL_ID;
    bytes32 public immutable ETHEREUM_ANCHOR_VERIFIER_PROGRAM_ID;
    bytes32 public immutable ETHEREUM_ANCHOR_VERIFIER_CONFIG_HASH;
    bytes32 public immutable WEAK_SUBJECTIVITY_POLICY_HASH;
    bytes32 public immutable PROTOCOL_CORE_HASH;
    bytes32 public immutable PARENT_GENESIS_HASH;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable CONTROLLER_PROGRAM_CONFIG_HASH;
    bytes32 public immutable INBOUND_VAULT_CONFIG_HASH;
    bytes32 public immutable USDD_ASSET_ID;
    bytes32 public immutable BOOTSTRAP_SOURCE_HASH;
    bytes32 public immutable BOOTSTRAP_EXECUTION_CHECKPOINT_HASH;
    uint8 public immutable DRIVECHAIN_SLOT;
    uint64 public immutable MAX_CONTROLLER_ADMISSION_AGE_SECONDS;
    uint64 public immutable MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS;
    uint64 public immutable MINIMUM_RECOVERY_MARGIN_SECONDS;
    uint64 public immutable MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS;

    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    bool public initialized;
    uint64 public acceptedTransitionCount;
    bytes32 public currentExecutionCheckpointHash;
    bytes32 public currentAcceptedAnchorStateCommitment;
    bytes32 public currentAcceptedAnchorExecutionCheckpointHash;
    uint64 public currentAcceptedAnchorSequence;
    mapping(bytes32 publicValuesHash => bool accepted) public acceptedProofStatements;
    ControllerSnapshot private _controllerSnapshot;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error InvalidConfiguration();
    error ProofVerifierCodeChanged(bytes32 expected, bytes32 actual);
    error ProofVerifierIdentityChanged();
    error ParentFinalityRelayCodeChanged(bytes32 expected, bytes32 actual);
    error ParentFinalityRelayIdentityChanged();
    error EthereumAnchorRelayIdentityChanged();
    error EthereumAnchorNotAccepted();
    error ParentCheckpointNotFinalizedCanonical();
    error WrongStatementIdentity();
    error WrongBootstrapMode(bool expected, bool actual);
    error WrongSourceState(bytes32 expected, bytes32 actual);
    error WrongSourceExecutionCheckpoint(bytes32 expected, bytes32 actual);
    error InvalidSuccessorState();
    error InvalidResolutionTransition();
    error InvalidParentTransition();
    error InvalidEthereumFinalityTransition();
    error InvalidWeakSubjectivityDeadline(uint64 expected, uint64 actual);
    error InvalidStrongStatementCommitments();
    error InvalidLease();
    error ProofStatementAlreadyAccepted(bytes32 publicValuesHash);
    error ControllerTransitionProofRejected(bytes32 publicValuesHash);

    event ControllerTransitionAccepted(
        bytes32 indexed publicValuesHash,
        bytes32 indexed priorControllerStateHash,
        bytes32 indexed nextControllerStateHash,
        bytes32 priorExecutionCheckpointHash,
        bytes32 nextExecutionCheckpointHash,
        uint64 nextControllerSequence,
        uint64 nextResolutionCount,
        uint64 admissionValidUntil,
        address submitter
    );

    constructor(RelayConfig memory config) {
        if (
            config.proofVerifier == address(0) || config.proofVerifierCodehash == bytes32(0)
                || config.proofProgramId == bytes32(0) || config.proofConfigHash == bytes32(0)
                || config.parentFinalityRelay == address(0)
                || config.parentFinalityRelayCodehash == bytes32(0)
                || config.parentChainIdentity == bytes32(0)
                || config.parentFinalityConfigHash == bytes32(0)
                || config.ethereumAnchorAcceptanceRelay == address(0)
                || config.ethereumAnchorAcceptanceRelayCodehash == bytes32(0)
                || config.ethereumAnchorSecurityModelId == bytes32(0)
                || config.ethereumAnchorVerifierProgramId == bytes32(0)
                || config.ethereumAnchorVerifierConfigHash == bytes32(0)
                || config.weakSubjectivityPolicyHash == bytes32(0)
                || config.protocolCoreHash == bytes32(0) || config.parentGenesisHash == bytes32(0)
                || config.elementsGenesisHash == bytes32(0)
                || config.controllerProgramConfigHash == bytes32(0)
                || config.inboundVaultConfigHash == bytes32(0) || config.usddAssetId == bytes32(0)
                || config.bootstrapSourceHash == bytes32(0)
                || config.bootstrapExecutionCheckpointHash == bytes32(0)
        ) revert ZeroIdentity();
        if (config.proofVerifier.code.length == 0) {
            revert AddressHasNoCode(config.proofVerifier);
        }
        if (config.parentFinalityRelay.code.length == 0) {
            revert AddressHasNoCode(config.parentFinalityRelay);
        }
        if (config.ethereumAnchorAcceptanceRelay.code.length == 0) {
            revert AddressHasNoCode(config.ethereumAnchorAcceptanceRelay);
        }
        if (config.proofVerifier.codehash != config.proofVerifierCodehash) {
            revert InvalidConfiguration();
        }
        if (config.parentFinalityRelay.codehash != config.parentFinalityRelayCodehash) {
            revert InvalidConfiguration();
        }
        if (
            config.ethereumAnchorAcceptanceRelay.codehash
                != config.ethereumAnchorAcceptanceRelayCodehash
        ) revert InvalidConfiguration();
        if (
            config.drivechainSlot != REQUIRED_DRIVECHAIN_SLOT
                || config.maxControllerAdmissionAgeSeconds == 0
                || config.maxControllerAdmissionAgeSeconds
                    > ABSOLUTE_MAX_ADMISSION_AGE_SECONDS
                || config.maxWeakSubjectivityPeriodSeconds
                    <= config.minimumRecoveryMarginSeconds
                        + config.maxControllerAdmissionAgeSeconds
                || config.maxWeakSubjectivityPeriodSeconds
                    > ABSOLUTE_MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS
                || config.minimumRecoveryMarginSeconds == 0
                || config.maxFutureTimestampDriftSeconds
                    > ABSOLUTE_MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS
        ) revert InvalidConfiguration();

        IControllerTransitionProofVerifierV2 proofVerifier =
            IControllerTransitionProofVerifierV2(config.proofVerifier);
        if (
            proofVerifier.verifierProgramId() != config.proofProgramId
                || proofVerifier.verifierConfigHash() != config.proofConfigHash
        ) revert InvalidConfiguration();
        IParentFinalityRelayV2 parentFinalityRelay =
            IParentFinalityRelayV2(config.parentFinalityRelay);
        IEthereumAnchorAcceptanceRelayV2 anchorRelay =
            IEthereumAnchorAcceptanceRelayV2(config.ethereumAnchorAcceptanceRelay);
        if (
            parentFinalityRelay.parentChainIdentity() != config.parentChainIdentity
                || parentFinalityRelay.finalityConfigHash()
                    != config.parentFinalityConfigHash
                || anchorRelay.securityModelId() != config.ethereumAnchorSecurityModelId
                || anchorRelay.verifierProgramId()
                    != config.ethereumAnchorVerifierProgramId
                || anchorRelay.verifierConfigHash()
                    != config.ethereumAnchorVerifierConfigHash
        ) revert InvalidConfiguration();

        PROOF_VERIFIER = proofVerifier;
        PROOF_VERIFIER_CODEHASH = config.proofVerifierCodehash;
        PROOF_PROGRAM_ID = config.proofProgramId;
        PROOF_CONFIG_HASH = config.proofConfigHash;
        PARENT_FINALITY_RELAY = parentFinalityRelay;
        PARENT_FINALITY_RELAY_CODEHASH = config.parentFinalityRelayCodehash;
        PARENT_CHAIN_IDENTITY = config.parentChainIdentity;
        PARENT_FINALITY_CONFIG_HASH = config.parentFinalityConfigHash;
        ETHEREUM_ANCHOR_ACCEPTANCE_RELAY = anchorRelay;
        ETHEREUM_ANCHOR_ACCEPTANCE_RELAY_CODEHASH =
            config.ethereumAnchorAcceptanceRelayCodehash;
        ETHEREUM_ANCHOR_SECURITY_MODEL_ID = config.ethereumAnchorSecurityModelId;
        ETHEREUM_ANCHOR_VERIFIER_PROGRAM_ID = config.ethereumAnchorVerifierProgramId;
        ETHEREUM_ANCHOR_VERIFIER_CONFIG_HASH = config.ethereumAnchorVerifierConfigHash;
        WEAK_SUBJECTIVITY_POLICY_HASH = config.weakSubjectivityPolicyHash;
        PROTOCOL_CORE_HASH = config.protocolCoreHash;
        PARENT_GENESIS_HASH = config.parentGenesisHash;
        ELEMENTS_GENESIS_HASH = config.elementsGenesisHash;
        CONTROLLER_PROGRAM_CONFIG_HASH = config.controllerProgramConfigHash;
        INBOUND_VAULT_CONFIG_HASH = config.inboundVaultConfigHash;
        USDD_ASSET_ID = config.usddAssetId;
        BOOTSTRAP_SOURCE_HASH = config.bootstrapSourceHash;
        BOOTSTRAP_EXECUTION_CHECKPOINT_HASH = config.bootstrapExecutionCheckpointHash;
        DRIVECHAIN_SLOT = config.drivechainSlot;
        MAX_CONTROLLER_ADMISSION_AGE_SECONDS = config.maxControllerAdmissionAgeSeconds;
        MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS =
            config.maxWeakSubjectivityPeriodSeconds;
        MINIMUM_RECOVERY_MARGIN_SECONDS = config.minimumRecoveryMarginSeconds;
        MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS = config.maxFutureTimestampDriftSeconds;

        verifierProgramId = config.proofProgramId;
        verifierConfigHash = _relayVerifierConfigHash(config);
    }

    /// @notice Latest proof-accepted canonical controller snapshot.
    /// @dev Before proof-gated bootstrap this returns the all-zero snapshot, so
    ///      USDDInboundVaultV2 rejects admissions and resolution claims.
    function controllerSnapshot() external view override returns (ControllerSnapshot memory) {
        return _controllerSnapshot;
    }

    function inboundVaultPolicyHash() external view override returns (bytes32) {
        return INBOUND_VAULT_CONFIG_HASH;
    }

    function canonicalStateHash(CanonicalControllerState memory state)
        public
        pure
        returns (bytes32)
    {
        return sha256(abi.encode(CANONICAL_STATE_DOMAIN, state));
    }

    function transitionPublicValuesHash(StrongTransition calldata transition)
        public
        view
        returns (bytes32)
    {
        bytes32 identityClaimsHash = _identityClaimsHash(transition);
        bytes32 sourceHash = canonicalStateHash(transition.source);
        bytes32 successorHash = canonicalStateHash(transition.successor);
        bytes32 evidenceHash = _strongEvidenceHash(transition);
        return sha256(
            abi.encode(
                TRANSITION_PUBLIC_VALUES_DOMAIN,
                block.chainid,
                address(this),
                DRIVECHAIN_SLOT,
                transition.bootstrap,
                identityClaimsHash,
                sourceHash,
                successorHash,
                evidenceHash
            )
        );
    }

    /// @notice Permissionlessly accepts one exact adjacent strong controller
    ///         transition after proof verification.
    function advance(StrongTransition calldata transition, bytes calldata proof) external {
        _requireVerifierIdentity();
        _requireParentFinalityIdentity();
        _requireEthereumAnchorIdentity();
        _requireStatementIdentity(transition);

        bool expectedBootstrap = !initialized;
        if (transition.bootstrap != expectedBootstrap) {
            revert WrongBootstrapMode(expectedBootstrap, transition.bootstrap);
        }

        bytes32 sourceHash = canonicalStateHash(transition.source);
        bytes32 expectedSourceHash =
            expectedBootstrap ? BOOTSTRAP_SOURCE_HASH : _storedCanonicalStateHash();
        if (sourceHash != expectedSourceHash) {
            revert WrongSourceState(expectedSourceHash, sourceHash);
        }
        bytes32 expectedExecutionCheckpointHash = expectedBootstrap
            ? BOOTSTRAP_EXECUTION_CHECKPOINT_HASH
            : currentExecutionCheckpointHash;
        if (
            transition.sourceExecutionCheckpointHash
                != expectedExecutionCheckpointHash
        ) {
            revert WrongSourceExecutionCheckpoint(
                expectedExecutionCheckpointHash,
                transition.sourceExecutionCheckpointHash
            );
        }

        _validateStrongCommitments(transition);
        _validateSuccessor(transition.source, transition.successor);
        _requireCanonicalParentCheckpoint(transition.successor);
        if (
            transition.acceptedAnchorSequence < currentAcceptedAnchorSequence
                || (
                    initialized
                        && transition.acceptedAnchorSequence == currentAcceptedAnchorSequence
                        && (
                            transition.acceptedAnchorStateCommitment
                                != currentAcceptedAnchorStateCommitment
                                || transition.acceptedAnchorExecutionCheckpointHash
                                    != currentAcceptedAnchorExecutionCheckpointHash
                        )
                )
        ) revert EthereumAnchorNotAccepted();
        if (
            !ETHEREUM_ANCHOR_ACCEPTANCE_RELAY.isAcceptedAnchor(
                transition.acceptedAnchorStateCommitment,
                transition.acceptedAnchorExecutionCheckpointHash,
                transition.acceptedAnchorSequence
            )
        ) revert EthereumAnchorNotAccepted();

        bytes32 publicValuesHash = transitionPublicValuesHash(transition);
        if (acceptedProofStatements[publicValuesHash]) {
            revert ProofStatementAlreadyAccepted(publicValuesHash);
        }
        if (!PROOF_VERIFIER.verifyProof(publicValuesHash, proof)) {
            revert ControllerTransitionProofRejected(publicValuesHash);
        }

        uint64 acceptedAt = _safeUint64(block.timestamp);
        uint64 admissionValidUntil = _deriveAdmissionValidUntil(transition.successor);

        acceptedProofStatements[publicValuesHash] = true;
        initialized = true;
        acceptedTransitionCount += 1;
        currentExecutionCheckpointHash =
            transition.successorExecutionCheckpointHash;
        currentAcceptedAnchorStateCommitment = transition.acceptedAnchorStateCommitment;
        currentAcceptedAnchorExecutionCheckpointHash =
            transition.acceptedAnchorExecutionCheckpointHash;
        currentAcceptedAnchorSequence = transition.acceptedAnchorSequence;
        _controllerSnapshot = ControllerSnapshot({
            controllerStateHash: transition.successor.controllerStateHash,
            cumulativeResolutionRoot: transition.successor.cumulativeResolutionRoot,
            parentBlockHash: transition.successor.parentBlockHash,
            controllerSequence: transition.successor.controllerSequence,
            resolutionCount: transition.successor.resolutionCount,
            nextResolutionNonce: transition.successor.nextResolutionNonce,
            parentBlockHeight: transition.successor.parentBlockHeight,
            parentMedianTimePast: transition.successor.parentMedianTimePast,
            parentChainwork: transition.successor.parentChainwork,
            ethereumFinalizedSlot: transition.successor.ethereumFinalizedSlot,
            ethereumFinalizedTimestamp: transition.successor.ethereumFinalizedTimestamp,
            weakSubjectivityValidUntil: transition.successor.weakSubjectivityValidUntil,
            acceptedAnchorStateCommitment: transition.acceptedAnchorStateCommitment,
            acceptedAnchorExecutionCheckpointHash: transition.acceptedAnchorExecutionCheckpointHash,
            acceptedAnchorSequence: transition.acceptedAnchorSequence,
            acceptedAt: acceptedAt,
            admissionValidUntil: admissionValidUntil
        });

        _emitTransitionAccepted(transition, publicValuesHash, admissionValidUntil);
    }

    function _emitTransitionAccepted(
        StrongTransition calldata transition,
        bytes32 publicValuesHash,
        uint64 admissionValidUntil
    ) private {
        emit ControllerTransitionAccepted(
            publicValuesHash,
            transition.source.controllerStateHash,
            transition.successor.controllerStateHash,
            transition.sourceExecutionCheckpointHash,
            transition.successorExecutionCheckpointHash,
            transition.successor.controllerSequence,
            transition.successor.resolutionCount,
            admissionValidUntil,
            msg.sender
        );
    }

    function _requireVerifierIdentity() private view {
        bytes32 currentCodehash = address(PROOF_VERIFIER).codehash;
        if (currentCodehash != PROOF_VERIFIER_CODEHASH) {
            revert ProofVerifierCodeChanged(PROOF_VERIFIER_CODEHASH, currentCodehash);
        }
        if (
            PROOF_VERIFIER.verifierProgramId() != PROOF_PROGRAM_ID
                || PROOF_VERIFIER.verifierConfigHash() != PROOF_CONFIG_HASH
        ) revert ProofVerifierIdentityChanged();
    }

    function _requireStatementIdentity(StrongTransition calldata transition) private view {
        if (
            transition.claimedProofProgramId != PROOF_PROGRAM_ID
                || transition.claimedProofConfigHash != PROOF_CONFIG_HASH
                || transition.claimedParentChainIdentity != PARENT_CHAIN_IDENTITY
                || transition.claimedParentFinalityConfigHash
                    != PARENT_FINALITY_CONFIG_HASH
                || transition.claimedWeakSubjectivityPolicyHash
                    != WEAK_SUBJECTIVITY_POLICY_HASH
                || transition.claimedProtocolCoreHash != PROTOCOL_CORE_HASH
                || transition.claimedParentGenesisHash != PARENT_GENESIS_HASH
                || transition.claimedElementsGenesisHash != ELEMENTS_GENESIS_HASH
                || transition.claimedControllerProgramConfigHash
                    != CONTROLLER_PROGRAM_CONFIG_HASH
                || transition.claimedInboundVaultConfigHash != INBOUND_VAULT_CONFIG_HASH
                || transition.claimedUsddAssetId != USDD_ASSET_ID
        ) revert WrongStatementIdentity();
    }

    function _requireParentFinalityIdentity() private view {
        bytes32 currentCodehash = address(PARENT_FINALITY_RELAY).codehash;
        if (currentCodehash != PARENT_FINALITY_RELAY_CODEHASH) {
            revert ParentFinalityRelayCodeChanged(
                PARENT_FINALITY_RELAY_CODEHASH, currentCodehash
            );
        }
        if (
            PARENT_FINALITY_RELAY.parentChainIdentity() != PARENT_CHAIN_IDENTITY
                || PARENT_FINALITY_RELAY.finalityConfigHash()
                    != PARENT_FINALITY_CONFIG_HASH
        ) revert ParentFinalityRelayIdentityChanged();
    }

    function _requireEthereumAnchorIdentity() private view {
        if (
            address(ETHEREUM_ANCHOR_ACCEPTANCE_RELAY).codehash
                != ETHEREUM_ANCHOR_ACCEPTANCE_RELAY_CODEHASH
                || ETHEREUM_ANCHOR_ACCEPTANCE_RELAY.securityModelId()
                    != ETHEREUM_ANCHOR_SECURITY_MODEL_ID
                || ETHEREUM_ANCHOR_ACCEPTANCE_RELAY.verifierProgramId()
                    != ETHEREUM_ANCHOR_VERIFIER_PROGRAM_ID
                || ETHEREUM_ANCHOR_ACCEPTANCE_RELAY.verifierConfigHash()
                    != ETHEREUM_ANCHOR_VERIFIER_CONFIG_HASH
        ) revert EthereumAnchorRelayIdentityChanged();
    }

    function _requireCanonicalParentCheckpoint(CanonicalControllerState calldata successor)
        private
        view
    {
        if (
            PARENT_FINALITY_RELAY.currentFinalizedHeight() < successor.parentBlockHeight
                || !PARENT_FINALITY_RELAY.isFinalizedCanonical(
                    successor.parentBlockHash,
                    successor.parentBlockHeight,
                    successor.parentMedianTimePast,
                    successor.parentChainwork
                )
        ) revert ParentCheckpointNotFinalizedCanonical();
    }

    function _validateStrongCommitments(StrongTransition calldata transition) private pure {
        if (
            transition.elementsBlockHash == bytes32(0) || transition.elementsBlockHeight == 0
                || transition.controllerTransactionId == bytes32(0)
                || transition.sourceExecutionCheckpointHash == bytes32(0)
                || transition.successorExecutionCheckpointHash == bytes32(0)
                || transition.successorExecutionCheckpointHash
                    == transition.sourceExecutionCheckpointHash
                || transition.controllerExecutionCommitment == bytes32(0)
                || transition.dispositionsCommitment == bytes32(0)
                || transition.elementsInclusionCommitment == bytes32(0)
                || transition.bmmInclusionCommitment == bytes32(0)
                || transition.parentBestChainCommitment == bytes32(0)
                || transition.acceptedAnchorStateCommitment == bytes32(0)
                || transition.acceptedAnchorExecutionCheckpointHash == bytes32(0)
                || transition.acceptedAnchorSequence == 0
        ) revert InvalidStrongStatementCommitments();
    }

    function _identityClaimsHash(StrongTransition calldata transition)
        private
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encode(
                transition.claimedProofProgramId,
                transition.claimedProofConfigHash,
                transition.claimedParentChainIdentity,
                transition.claimedParentFinalityConfigHash,
                transition.claimedWeakSubjectivityPolicyHash,
                transition.claimedProtocolCoreHash,
                transition.claimedParentGenesisHash,
                transition.claimedElementsGenesisHash,
                transition.claimedControllerProgramConfigHash,
                transition.claimedInboundVaultConfigHash,
                transition.claimedUsddAssetId
            )
        );
    }

    function _relayVerifierConfigHash(RelayConfig memory config)
        private
        view
        returns (bytes32)
    {
        bytes32 proofBoundaryHash = sha256(
            abi.encode(
                config.proofVerifier,
                config.proofVerifierCodehash,
                config.proofProgramId,
                config.proofConfigHash
            )
        );
        bytes32 parentBoundaryHash = sha256(
            abi.encode(
                config.parentFinalityRelay,
                config.parentFinalityRelayCodehash,
                config.parentChainIdentity,
                config.parentFinalityConfigHash,
                config.weakSubjectivityPolicyHash
            )
        );
        bytes32 anchorBoundaryHash = sha256(
            abi.encode(
                config.ethereumAnchorAcceptanceRelay,
                config.ethereumAnchorAcceptanceRelayCodehash,
                config.ethereumAnchorSecurityModelId,
                config.ethereumAnchorVerifierProgramId,
                config.ethereumAnchorVerifierConfigHash
            )
        );
        bytes32 protocolIdentitiesHash = sha256(
            abi.encode(
                config.protocolCoreHash,
                config.parentGenesisHash,
                config.elementsGenesisHash,
                config.controllerProgramConfigHash,
                config.inboundVaultConfigHash,
                config.usddAssetId,
                config.bootstrapSourceHash,
                config.bootstrapExecutionCheckpointHash,
                config.drivechainSlot
            )
        );
        bytes32 policyBoundsHash = sha256(
            abi.encode(
                config.maxControllerAdmissionAgeSeconds,
                config.maxWeakSubjectivityPeriodSeconds,
                config.minimumRecoveryMarginSeconds,
                config.maxFutureTimestampDriftSeconds
            )
        );
        return sha256(
            abi.encode(
                RELAY_VERIFIER_CONFIG_DOMAIN,
                block.chainid,
                address(this),
                proofBoundaryHash,
                parentBoundaryHash,
                anchorBoundaryHash,
                protocolIdentitiesHash,
                policyBoundsHash
            )
        );
    }

    function _strongEvidenceHash(StrongTransition calldata transition)
        private
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encode(
                transition.elementsBlockHash,
                transition.elementsBlockHeight,
                transition.controllerTransactionId,
                transition.sourceExecutionCheckpointHash,
                transition.successorExecutionCheckpointHash,
                transition.controllerExecutionCommitment,
                transition.dispositionsCommitment,
                transition.elementsInclusionCommitment,
                transition.bmmInclusionCommitment,
                transition.parentBestChainCommitment,
                transition.acceptedAnchorStateCommitment,
                transition.acceptedAnchorExecutionCheckpointHash,
                transition.acceptedAnchorSequence
            )
        );
    }

    function _validateSuccessor(
        CanonicalControllerState calldata source,
        CanonicalControllerState calldata successor
    ) private view {
        if (
            successor.controllerStateHash == bytes32(0)
                || successor.controllerStateHash == source.controllerStateHash
                || successor.parentBlockHash == bytes32(0)
                || successor.controllerSequence <= source.controllerSequence
                || successor.resolutionCount > successor.controllerSequence
                || successor.parentMedianTimePast == 0 || successor.parentChainwork == 0
                || successor.ethereumFinalizedSlot == 0
                || successor.ethereumFinalizedTimestamp == 0
        ) revert InvalidSuccessorState();

        uint64 sequenceDelta = successor.controllerSequence - source.controllerSequence;
        uint64 resolutionDelta;
        uint64 nonceDelta;
        if (
            successor.resolutionCount < source.resolutionCount
                || successor.nextResolutionNonce < source.nextResolutionNonce
        ) revert InvalidResolutionTransition();
        resolutionDelta = successor.resolutionCount - source.resolutionCount;
        nonceDelta = successor.nextResolutionNonce - source.nextResolutionNonce;
        if (
            resolutionDelta > sequenceDelta || nonceDelta != resolutionDelta
                || (
                    resolutionDelta == 0
                        && successor.cumulativeResolutionRoot
                            != source.cumulativeResolutionRoot
                )
                || (
                    resolutionDelta > 0
                        && (
                            successor.cumulativeResolutionRoot == bytes32(0)
                                || successor.cumulativeResolutionRoot
                                    == source.cumulativeResolutionRoot
                        )
                )
        ) revert InvalidResolutionTransition();

        if (
            successor.parentBlockHeight <= source.parentBlockHeight
                || successor.parentChainwork <= source.parentChainwork
                || successor.parentMedianTimePast < source.parentMedianTimePast
                || successor.parentBlockHash == source.parentBlockHash
        ) revert InvalidParentTransition();

        if (
            successor.ethereumFinalizedSlot < source.ethereumFinalizedSlot
                || successor.ethereumFinalizedTimestamp < source.ethereumFinalizedTimestamp
                || _absoluteDifference(
                    successor.ethereumFinalizedTimestamp, successor.parentMedianTimePast
                ) > MAX_CONTROLLER_ADMISSION_AGE_SECONDS
        ) revert InvalidEthereumFinalityTransition();

        if (
            successor.weakSubjectivityValidUntil
                <= successor.ethereumFinalizedTimestamp
                || successor.weakSubjectivityValidUntil
                    - successor.ethereumFinalizedTimestamp
                    > MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS
        ) {
            revert InvalidWeakSubjectivityDeadline(
                _checkedAdd(
                    successor.ethereumFinalizedTimestamp,
                    MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS
                ),
                successor.weakSubjectivityValidUntil
            );
        }

        uint256 latestAllowed = block.timestamp + MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS;
        if (
            successor.parentMedianTimePast > latestAllowed
                || successor.ethereumFinalizedTimestamp > latestAllowed
        ) revert InvalidEthereumFinalityTransition();
    }

    function _deriveAdmissionValidUntil(CanonicalControllerState calldata state)
        private
        view
        returns (uint64)
    {
        uint64 parentExpiry =
            _checkedAdd(state.parentMedianTimePast, MAX_CONTROLLER_ADMISSION_AGE_SECONDS);
        uint64 ethereumExpiry =
            _checkedAdd(state.ethereumFinalizedTimestamp, MAX_CONTROLLER_ADMISSION_AGE_SECONDS);
        if (state.weakSubjectivityValidUntil <= MINIMUM_RECOVERY_MARGIN_SECONDS) {
            revert InvalidLease();
        }
        uint64 weakSubjectivityExpiry =
            state.weakSubjectivityValidUntil - MINIMUM_RECOVERY_MARGIN_SECONDS;
        uint64 validUntil = _min(parentExpiry, _min(ethereumExpiry, weakSubjectivityExpiry));
        if (validUntil <= block.timestamp) revert InvalidLease();
        return validUntil;
    }

    function _storedCanonicalStateHash() private view returns (bytes32) {
        ControllerSnapshot memory snapshot = _controllerSnapshot;
        return canonicalStateHash(
            CanonicalControllerState({
                controllerStateHash: snapshot.controllerStateHash,
                cumulativeResolutionRoot: snapshot.cumulativeResolutionRoot,
                parentBlockHash: snapshot.parentBlockHash,
                controllerSequence: snapshot.controllerSequence,
                resolutionCount: snapshot.resolutionCount,
                nextResolutionNonce: snapshot.nextResolutionNonce,
                parentBlockHeight: snapshot.parentBlockHeight,
                parentMedianTimePast: snapshot.parentMedianTimePast,
                parentChainwork: snapshot.parentChainwork,
                ethereumFinalizedSlot: snapshot.ethereumFinalizedSlot,
                ethereumFinalizedTimestamp: snapshot.ethereumFinalizedTimestamp,
                weakSubjectivityValidUntil: snapshot.weakSubjectivityValidUntil
            })
        );
    }

    function _checkedAdd(uint64 left, uint64 right) private pure returns (uint64 result) {
        uint256 wide = uint256(left) + right;
        if (wide > type(uint64).max) revert InvalidLease();
        result = uint64(wide);
    }

    function _safeUint64(uint256 value) private pure returns (uint64) {
        if (value > type(uint64).max) revert InvalidLease();
        return uint64(value);
    }

    function _min(uint64 left, uint64 right) private pure returns (uint64) {
        return left < right ? left : right;
    }

    function _absoluteDifference(uint64 left, uint64 right) private pure returns (uint64) {
        return left >= right ? left - right : right - left;
    }
}
