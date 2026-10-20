// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IControllerAcceptanceRelayV4} from "./interfaces/IControllerAcceptanceRelayV4.sol";
import {IControllerPolicyProofVerifierV4} from "./interfaces/IControllerPolicyProofVerifierV4.sol";
import {IParentFinalityRelayV2} from "./interfaces/IParentFinalityRelayV2.sol";
import {IEthereumAnchorAcceptanceRelayV2} from "./interfaces/IEthereumAnchorAcceptanceRelayV2.sol";
import {ControllerAcceptanceStateCodecV4} from "./ControllerAcceptanceStateCodecV4.sol";

/// @notice Undeployed no-expiry strong-execution relay candidate.
/// @dev No owner, setter, or unproved initialization. A matching acceptance
/// guest must bind ALL public statement fields, including the anchor and
/// canonical replay endpoint, to verified receipts. Existing V2/prebroadcast
/// guests cannot authorize this contract. Interface reuse below is limited to
/// getter/membership calls, NOT reuse of a legacy deadline-bearing journal.
contract ControllerAcceptanceRelayV4 is IControllerAcceptanceRelayV4 {
    bool public constant PRODUCTION_READY = false;
    bytes32 public constant override securityModelId =
        keccak256("USDD_V4_NO_EXPIRY_STRONG_MINED_EXECUTION");
    bytes32 public constant STATEMENT_DOMAIN =
        keccak256("USDD_V4_RELAY_TRANSITION");

    struct Boundary {
        address target;
        bytes32 codehash;
        bytes32 programId;
        bytes32 configHash;
    }
    struct Config {
        Boundary proof;
        Boundary parent; // programId is parentChainIdentity for this boundary.
        Boundary anchor;
        bytes32 anchorSecurityModel;
        bytes32 controllerConfigurationHash;
        bytes32 vaultPolicyHash;
        bytes32 bootstrapPublicStateHash;
        uint64 admissionAgeSeconds;
        // Downstream of compiled spending leaves; never a bootstrap input.
        bytes32 acceptancePolicyHash;
    }
    struct Transition {
        AcceptanceState source;
        AcceptanceState successor;
        bytes32 executionCommitment;
        bytes32 elementsBlockHash;
        uint64 elementsBlockHeight;
        bytes32 transactionId;
        // Must be opened by the guest to the exact authenticated replay tip.
        bytes32 canonicalTipContextCommitment;
        bytes32 canonicalTipBlockHash;
        uint64 canonicalTipHeight;
        uint64 canonicalTipMedianTimePast;
        uint256 canonicalTipChainwork;
        bytes32 acceptedAnchorStateCommitment;
        bytes32 acceptedAnchorExecutionCheckpointHash;
        uint64 acceptedAnchorSequence;
    }

    Config private config;
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;
    bool public initialized;
    ControllerSnapshot private snapshot;
    mapping(bytes32 => bool) public acceptedStatements;
    error InvalidBoundary();
    error InvalidTransition();
    error UnauthenticatedContext();
    error ProofRejected();
    event Accepted(bytes32 indexed statement, bytes32 indexed checkpoint, uint64 sequence);

    constructor(Config memory selected) {
        if (selected.controllerConfigurationHash == 0 || selected.vaultPolicyHash == 0
            || selected.bootstrapPublicStateHash == 0 || selected.anchorSecurityModel == 0
            || selected.admissionAgeSeconds == 0 || selected.admissionAgeSeconds > 6 hours
            || selected.acceptancePolicyHash == 0)
            revert InvalidBoundary();
        config = selected;
        _checkBoundaries();
        verifierProgramId = selected.proof.programId;
        verifierConfigHash = sha256(abi.encode(securityModelId, block.chainid, address(this), selected));
    }

    function inboundVaultPolicyHash() external view returns (bytes32) { return config.vaultPolicyHash; }
    function acceptancePolicyHash() external view returns (bytes32) { return config.acceptancePolicyHash; }
    function controllerSnapshot() external view returns (ControllerSnapshot memory) { return snapshot; }
    function publicStateHash(AcceptanceState memory state) public pure returns (bytes32) {
        return sha256(ControllerAcceptanceStateCodecV4.encode(state));
    }
    function transitionPublicValuesHash(Transition calldata t) public view returns (bytes32) {
        // This postdeployment domain cannot feed back into the bootstrap state.
        return sha256(abi.encode(STATEMENT_DOMAIN, block.chainid, address(this),
            verifierConfigHash, publicStateHash(t.source), publicStateHash(t.successor),
            t.executionCommitment, t.elementsBlockHash, t.elementsBlockHeight, t.transactionId,
            t.canonicalTipContextCommitment, t.canonicalTipBlockHash, t.canonicalTipHeight,
            t.canonicalTipMedianTimePast, t.canonicalTipChainwork, t.acceptedAnchorStateCommitment,
            t.acceptedAnchorExecutionCheckpointHash, t.acceptedAnchorSequence));
    }

    function advance(Transition calldata t, bytes calldata proof) external {
        _checkBoundaries();
        if (publicStateHash(t.source) != (initialized
            ? publicStateHash(snapshot.state) : config.bootstrapPublicStateHash)) revert InvalidTransition();
        _validate(t);
        IParentFinalityRelayV2 parent = IParentFinalityRelayV2(config.parent.target);
        if (parent.currentFinalizedHeight() < t.successor.parentBlockHeight
            || !parent.isFinalizedCanonical(t.successor.parentBlockHash,
                t.successor.parentBlockHeight, t.successor.parentMedianTimePast,
                uint256(t.successor.parentChainwork))) revert UnauthenticatedContext();
        // Checking only the earlier transaction clock would leave a competing
        // confirmation suffix unauthenticated. The guest must bind this exact
        // tuple to canonicalTipContextCommitment and its final replay journal.
        if (parent.currentFinalizedHeight() < t.canonicalTipHeight
            || t.canonicalTipHeight < t.successor.parentBlockHeight
            || !parent.isFinalizedCanonical(t.canonicalTipBlockHash, t.canonicalTipHeight,
                t.canonicalTipMedianTimePast, t.canonicalTipChainwork)) revert UnauthenticatedContext();
        if (!IEthereumAnchorAcceptanceRelayV2(config.anchor.target).isAcceptedAnchor(
            t.acceptedAnchorStateCommitment, t.acceptedAnchorExecutionCheckpointHash,
            t.acceptedAnchorSequence)) revert UnauthenticatedContext();
        bytes32 statement = transitionPublicValuesHash(t);
        if (acceptedStatements[statement]
            || !IControllerPolicyProofVerifierV4(config.proof.target).verifyProof(statement, config.acceptancePolicyHash, proof))
            revert ProofRejected();
        // Old accepted resolutions remain consumable; only NEW admissions use
        // this lease. A delayed valid update is not rejected for an expired lease.
        uint64 clock = t.successor.parentMedianTimePast < t.successor.ethereumFinalizedTimestamp
            ? t.successor.parentMedianTimePast : t.successor.ethereumFinalizedTimestamp;
        uint64 lease = clock + config.admissionAgeSeconds;
        if (block.timestamp > type(uint64).max) revert InvalidTransition();
        acceptedStatements[statement] = true;
        initialized = true;
        snapshot = ControllerSnapshot(t.successor, t.acceptedAnchorStateCommitment,
            t.acceptedAnchorExecutionCheckpointHash, t.acceptedAnchorSequence,
            uint64(block.timestamp), lease);
        emit Accepted(statement, t.successor.checkpointHash, t.successor.controllerSequence);
    }

    function _validate(Transition calldata t) private view {
        AcceptanceState calldata a = t.source;
        AcceptanceState calldata b = t.successor;
        if (b.checkpointHash == 0 || b.checkpointHash == a.checkpointHash
            || b.controllerStateHash == 0 || b.controllerStateHash == a.controllerStateHash
            || b.cumulativeResolutionRoot == 0 || b.controllerSequence != a.controllerSequence + 1
            || b.resolutionCount > b.controllerSequence || b.nextResolutionNonce != b.resolutionCount
            || a.nextResolutionNonce != a.resolutionCount || b.resolutionCount < a.resolutionCount
            || b.resolutionCount - a.resolutionCount > 1
            || ((b.resolutionCount == a.resolutionCount) != (b.cumulativeResolutionRoot == a.cumulativeResolutionRoot))
            || b.parentBlockHash == 0 || b.parentBlockHash == a.parentBlockHash
            || b.parentBlockHeight <= a.parentBlockHeight
            || uint256(b.parentChainwork) <= uint256(a.parentChainwork)
            || b.parentMedianTimePast == 0 || b.parentMedianTimePast < a.parentMedianTimePast
            || b.ethereumFinalizedSlot == 0 || b.ethereumFinalizedSlot < a.ethereumFinalizedSlot
            || b.ethereumFinalizedTimestamp == 0 || b.ethereumFinalizedTimestamp < a.ethereumFinalizedTimestamp
            || b.parentMedianTimePast > block.timestamp || b.ethereumFinalizedTimestamp > block.timestamp
            || t.executionCommitment == 0 || t.elementsBlockHash == 0 || t.elementsBlockHeight == 0
            || t.transactionId == 0 || t.canonicalTipContextCommitment == 0
            || t.acceptedAnchorStateCommitment == 0 || t.acceptedAnchorExecutionCheckpointHash == 0
            || t.acceptedAnchorSequence == 0 || t.acceptedAnchorSequence < snapshot.acceptedAnchorSequence)
            revert InvalidTransition();
        if (initialized && t.acceptedAnchorSequence == snapshot.acceptedAnchorSequence
            && (t.acceptedAnchorStateCommitment != snapshot.acceptedAnchorStateCommitment
                || t.acceptedAnchorExecutionCheckpointHash != snapshot.acceptedAnchorExecutionCheckpointHash))
            revert UnauthenticatedContext();
    }

    function _code(Boundary memory b) private view {
        if (b.target.code.length == 0 || b.codehash == 0 || b.target.codehash != b.codehash
            || b.programId == 0 || b.configHash == 0) revert InvalidBoundary();
    }
    function _checkBoundaries() private view {
        _code(config.proof); _code(config.parent); _code(config.anchor);
        IControllerPolicyProofVerifierV4 p = IControllerPolicyProofVerifierV4(config.proof.target);
        IParentFinalityRelayV2 f = IParentFinalityRelayV2(config.parent.target);
        IEthereumAnchorAcceptanceRelayV2 a = IEthereumAnchorAcceptanceRelayV2(config.anchor.target);
        if (p.verifierProgramId() != config.proof.programId || p.verifierConfigHash() != config.proof.configHash
            || f.parentChainIdentity() != config.parent.programId || f.finalityConfigHash() != config.parent.configHash
            || a.securityModelId() != config.anchorSecurityModel || a.verifierProgramId() != config.anchor.programId
            || a.verifierConfigHash() != config.anchor.configHash) revert InvalidBoundary();
    }
}
