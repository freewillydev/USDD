// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBip300RedemptionVerifier} from "./interfaces/IBip300RedemptionVerifier.sol";
import {ISuccinctBip300ProofVerifier} from "./interfaces/ISuccinctBip300ProofVerifier.sol";

/// @title EcashSlot24RelayV1
/// @notice Ownerless, proof-native relay for the single Elements Drivechain
///         slot used by USDD. It accepts heartbeat transitions and any number
///         of finalized M6 approvals committed by a depth-64 append-only tree.
contract EcashSlot24RelayV1 is IBip300RedemptionVerifier {
    uint8 public constant DRIVECHAIN_SLOT = 24;
    uint32 public constant ABSOLUTE_MAX_BLOCKS_PER_PROOF = 30_000;
    uint32 public constant ABSOLUTE_MAX_SEGMENT_BLOCKS = 256;
    uint32 public constant ABSOLUTE_MAX_SEGMENT_BYTES = 32 * 1024 * 1024;
    uint32 public constant ABSOLUTE_MAX_STATE_BYTES = 64 * 1024 * 1024;
    uint64 public constant MAX_FUTURE_PARENT_TIME = 2 hours;
    uint8 public constant APPROVAL_TREE_DEPTH = 64;

    bytes32 public constant RELAY_PROGRAM_DOMAIN = keccak256("USDD_ECASH_SLOT24_RELAY_PROGRAM_V1");
    bytes32 public constant RELAY_CONFIG_DOMAIN = keccak256("USDD_ECASH_SLOT24_RELAY_CONFIG_V1");
    bytes32 public constant TRANSITION_PUBLIC_VALUES_DOMAIN =
        keccak256("USDD_ECASH_SLOT24_TRANSITION_V1");
    bytes32 public constant APPROVAL_EMPTY_DOMAIN = sha256("USDD_ECASH_APPROVAL_EMPTY_V1");
    bytes32 public constant APPROVAL_LEAF_DOMAIN = sha256("USDD_ECASH_APPROVAL_LEAF_V1");
    bytes32 public constant APPROVAL_NODE_DOMAIN = sha256("USDD_ECASH_APPROVAL_NODE_V1");
    bytes32 public constant APPROVED_REDEMPTION_STATE_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATE_V1");
    bytes32 public constant APPROVED_REDEMPTION_STATEMENT_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATEMENT_V1");

    struct RelayConfig {
        address proofVerifier;
        bytes32 proofVerifierCodehash;
        bytes32 segmentProgramId;
        bytes32 foldProgramId;
        bytes32 foldProgramVKeyBn254;
        bytes32 proofConfigHash;
        bytes32 parentGenesisHash;
        bytes32 elementsGenesisHash;
        bytes32 usddAssetId;
        bytes32 vaultId;
        bytes32 genesisStateCommitment;
        uint256 genesisChainwork;
        uint64 genesisMedianTimePast;
        uint32 finalityDepth;
        uint32 maxSegmentBlocks;
        uint32 maxBlocksPerProof;
        uint32 maxSegmentBytes;
        uint32 maxStateBytes;
    }

    /// @dev Exact Solidity counterpart of the final recursive fold journal.
    struct Transition {
        bytes32 configHash;
        bytes32 priorStateCommitment;
        bytes32 nextStateCommitment;
        bytes32 priorTipHash;
        bytes32 nextTipHash;
        uint64 priorHeight;
        uint64 nextHeight;
        uint64 priorMedianTimePast;
        uint64 nextMedianTimePast;
        uint256 priorChainwork;
        uint256 nextChainwork;
        uint32 blockCount;
        bytes32 priorOrderedBlockTranscript;
        bytes32 nextOrderedBlockTranscript;
        uint64 maximumParentBlockTime;
        uint64 priorApprovalCount;
        bytes32 priorApprovalRoot;
        uint64 nextApprovalCount;
        bytes32 nextApprovalRoot;
        uint64 priorFinalizedClaimCount;
        bytes32 priorFinalizedClaimRoot;
        uint64 nextFinalizedClaimCount;
        bytes32 nextFinalizedClaimRoot;
        address rewardRecipient;
    }

    struct ApprovalEvent {
        bytes32 m6id;
        bytes32 vaultId;
        uint64 priorClaimCount;
        bytes32 priorClaimRoot;
        uint64 nextClaimCount;
        bytes32 nextClaimRoot;
        bytes32 inclusionBlockHash;
        uint64 inclusionHeight;
        bytes32 finalizationTipHash;
        uint64 finalizationHeight;
        uint64 finalizationMedianTimePast;
        uint256 finalizationChainwork;
    }

    struct ApprovalRecord {
        bytes32 vaultId;
        bytes32 priorClaimRoot;
        bytes32 nextClaimRoot;
        bytes32 bitcoinBlockHash;
        uint256 bitcoinChainwork;
        uint64 priorClaimCount;
        uint64 nextClaimCount;
        uint64 bitcoinHeight;
        uint64 bitcoinMedianTimePast;
        bool finalized;
    }

    struct TransitionRecord {
        bytes32 approvalRoot;
        uint64 priorApprovalCount;
        uint64 nextApprovalCount;
        address rewardRecipient;
        bool accepted;
    }

    struct VaultApprovalProof {
        bytes32 vaultId;
        bytes32 currentStateHash;
        uint64 currentSequence;
        uint64 currentClaimCount;
        bytes32 currentClaimRoot;
        bytes32 currentM6id;
        bytes32 currentBitcoinTipHash;
        uint64 currentBitcoinHeight;
        uint64 currentBitcoinMedianTimePast;
        uint256 currentBitcoinChainwork;
        uint64 nextSequence;
        bytes32 approvalM6id;
    }

    ISuccinctBip300ProofVerifier public immutable PROOF_VERIFIER;
    bytes32 public immutable PROOF_VERIFIER_CODEHASH;
    bytes32 public immutable SEGMENT_PROGRAM_ID;
    bytes32 public immutable FOLD_PROGRAM_ID;
    bytes32 public immutable FOLD_PROGRAM_VKEY_BN254;
    bytes32 public immutable PROOF_CONFIG_HASH;
    bytes32 public immutable ECASH_PROOF_CONFIG_HASH;
    bytes32 public immutable PARENT_GENESIS_HASH;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable USDD_ASSET_ID;
    bytes32 public immutable VAULT_ID;
    uint32 public immutable FINALITY_DEPTH;
    uint32 public immutable MAX_SEGMENT_BLOCKS;
    uint32 public immutable MAX_BLOCKS_PER_PROOF;
    uint32 public immutable MAX_SEGMENT_BYTES;
    uint32 public immutable MAX_STATE_BYTES;
    bytes32 public immutable GENESIS_STATE_COMMITMENT;

    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    bytes32 public stateCommitment;
    bytes32 public finalizedTip;
    uint64 public finalizedHeight;
    uint64 public finalizedMedianTimePast;
    uint256 public finalizedChainwork;
    bytes32 public orderedBlockTranscript;
    uint64 public finalizedApprovalCount;
    bytes32 public finalizedApprovalRoot;
    uint64 public finalizedClaimCount;
    bytes32 public finalizedClaimRoot;

    mapping(bytes32 transitionId => TransitionRecord record) public transitions;
    mapping(bytes32 m6id => ApprovalRecord record) public approvals;
    mapping(bytes32 m6id => address recipient) public proofRewardRecipient;
    mapping(bytes32 publicValuesHash => bool accepted) public acceptedProofStatements;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error InvalidConfiguration();
    error InvalidTransition();
    error StaleTransition();
    error ProofVerifierCodeChanged(bytes32 expected, bytes32 actual);
    error ProofVerifierIdentityChanged();
    error ProofStatementAlreadyAccepted(bytes32 statement);
    error SuccinctProofRejected(bytes32 publicValuesHash);
    error UnknownTransition(bytes32 transitionId);
    error ApprovalIndexOutOfRange(uint64 index);
    error InvalidApprovalProof();
    error M6AlreadyAccepted(bytes32 m6id);

    event Slot24TransitionAccepted(
        bytes32 indexed transitionId,
        bytes32 indexed nextStateCommitment,
        bytes32 indexed nextTipHash,
        uint64 nextHeight,
        uint32 blockCount,
        uint64 newApprovalCount,
        address rewardRecipient,
        address submitter
    );
    event M6ApprovalRegistered(
        bytes32 indexed m6id,
        bytes32 indexed transitionId,
        uint64 indexed approvalIndex,
        bytes32 nextClaimRoot,
        uint64 nextClaimCount,
        address rewardRecipient,
        address registrar
    );

    constructor(RelayConfig memory config) {
        if (
            config.proofVerifier == address(0) || config.proofVerifierCodehash == bytes32(0)
                || config.segmentProgramId == bytes32(0) || config.foldProgramId == bytes32(0)
                || config.foldProgramVKeyBn254 == bytes32(0) || config.proofConfigHash == bytes32(0)
                || config.parentGenesisHash == bytes32(0) || config.elementsGenesisHash == bytes32(0)
                || config.usddAssetId == bytes32(0) || config.vaultId == bytes32(0)
                || config.genesisStateCommitment == bytes32(0) || config.genesisChainwork == 0
                || config.genesisMedianTimePast == 0
        ) revert ZeroIdentity();
        if (config.proofVerifier.code.length == 0) revert AddressHasNoCode(config.proofVerifier);
        if (
            config.proofVerifier.codehash != config.proofVerifierCodehash || config.finalityDepth == 0
                || block.chainid > type(uint64).max || config.maxSegmentBlocks == 0
                || config.maxSegmentBlocks > ABSOLUTE_MAX_SEGMENT_BLOCKS
                || config.maxBlocksPerProof < config.maxSegmentBlocks
                || config.maxBlocksPerProof > ABSOLUTE_MAX_BLOCKS_PER_PROOF
                || config.maxSegmentBytes == 0
                || config.maxSegmentBytes > ABSOLUTE_MAX_SEGMENT_BYTES
                || config.maxStateBytes == 0 || config.maxStateBytes > ABSOLUTE_MAX_STATE_BYTES
        ) revert InvalidConfiguration();
        ISuccinctBip300ProofVerifier verifier =
            ISuccinctBip300ProofVerifier(config.proofVerifier);
        if (
            verifier.verifierProgramId() != config.foldProgramVKeyBn254
                || verifier.verifierConfigHash() != config.proofConfigHash
        ) revert InvalidConfiguration();

        PROOF_VERIFIER = verifier;
        PROOF_VERIFIER_CODEHASH = config.proofVerifierCodehash;
        SEGMENT_PROGRAM_ID = config.segmentProgramId;
        FOLD_PROGRAM_ID = config.foldProgramId;
        FOLD_PROGRAM_VKEY_BN254 = config.foldProgramVKeyBn254;
        PROOF_CONFIG_HASH = config.proofConfigHash;
        ECASH_PROOF_CONFIG_HASH = deriveEcashProofConfigHash(
            config, uint64(block.chainid), address(this)
        );
        PARENT_GENESIS_HASH = config.parentGenesisHash;
        ELEMENTS_GENESIS_HASH = config.elementsGenesisHash;
        USDD_ASSET_ID = config.usddAssetId;
        VAULT_ID = config.vaultId;
        FINALITY_DEPTH = config.finalityDepth;
        MAX_SEGMENT_BLOCKS = config.maxSegmentBlocks;
        MAX_BLOCKS_PER_PROOF = config.maxBlocksPerProof;
        MAX_SEGMENT_BYTES = config.maxSegmentBytes;
        MAX_STATE_BYTES = config.maxStateBytes;
        GENESIS_STATE_COMMITMENT = config.genesisStateCommitment;
        verifierProgramId = sha256(
            abi.encode(
                RELAY_PROGRAM_DOMAIN, config.foldProgramId, config.foldProgramVKeyBn254
            )
        );
        verifierConfigHash = sha256(abi.encode(RELAY_CONFIG_DOMAIN, block.chainid, config));

        stateCommitment = config.genesisStateCommitment;
        finalizedTip = config.parentGenesisHash;
        finalizedMedianTimePast = config.genesisMedianTimePast;
        finalizedChainwork = config.genesisChainwork;
        finalizedApprovalRoot = emptyApprovalRoot();
        finalizedClaimRoot = emptyClaimRoot();
    }

    /// @notice Canonical Rust `EcashProofConfig` hash. Deriving it here binds
    ///         every proof to this exact EVM chain and relay deployment rather
    ///         than trusting an opaque constructor-supplied digest.
    function deriveEcashProofConfigHash(
        RelayConfig memory config,
        uint64 ethereumChainId,
        address relayAddress
    ) public pure returns (bytes32) {
        bytes memory encoded = abi.encodePacked(
            "ECASHCF1",
            uint16(2),
            ethereumChainId,
            relayAddress,
            config.parentGenesisHash,
            config.elementsGenesisHash,
            config.usddAssetId,
            config.vaultId
        );
        encoded = bytes.concat(
            encoded,
            abi.encodePacked(
                config.segmentProgramId,
                config.foldProgramId,
                config.proofConfigHash,
                config.finalityDepth,
                config.maxSegmentBlocks,
                config.maxBlocksPerProof,
                config.maxSegmentBytes,
                config.maxStateBytes
            )
        );
        return sha256(encoded);
    }

    function transitionPublicValuesHash(Transition calldata transition)
        public
        pure
        returns (bytes32)
    {
        // Exact SHA-256 of the ECASH_FOLD_V1 public journal. All fields are
        // fixed-width, so encodePacked is unambiguous and matches the Rust
        // canonical codec byte-for-byte (schema integers are big-endian).
        bytes memory journal = abi.encodePacked(
            "USDD_ECASH_FOLD_JOURNAL_V1",
            "ECASHOU1",
            uint16(2),
            transition.configHash,
            transition.priorStateCommitment,
            transition.nextStateCommitment,
            transition.priorTipHash,
            transition.nextTipHash
        );
        journal = bytes.concat(
            journal,
            abi.encodePacked(
                transition.priorHeight,
                transition.nextHeight,
                transition.priorMedianTimePast,
                transition.nextMedianTimePast,
                transition.priorChainwork,
                transition.nextChainwork,
                transition.blockCount,
                transition.priorOrderedBlockTranscript,
                transition.nextOrderedBlockTranscript
            )
        );
        journal = bytes.concat(
            journal,
            abi.encodePacked(
                transition.maximumParentBlockTime,
                transition.priorApprovalCount,
                transition.priorApprovalRoot,
                transition.nextApprovalCount,
                transition.nextApprovalRoot,
                transition.priorFinalizedClaimCount,
                transition.priorFinalizedClaimRoot,
                transition.nextFinalizedClaimCount,
                transition.nextFinalizedClaimRoot,
                transition.rewardRecipient
            )
        );
        return sha256(journal);
    }

    function submitTransition(Transition calldata transition, bytes calldata proof) external {
        _validateTransition(transition);
        bytes32 actual = address(PROOF_VERIFIER).codehash;
        if (actual != PROOF_VERIFIER_CODEHASH) {
            revert ProofVerifierCodeChanged(PROOF_VERIFIER_CODEHASH, actual);
        }
        if (
            PROOF_VERIFIER.verifierProgramId() != FOLD_PROGRAM_VKEY_BN254
                || PROOF_VERIFIER.verifierConfigHash() != PROOF_CONFIG_HASH
        ) revert ProofVerifierIdentityChanged();
        bytes32 statement = transitionPublicValuesHash(transition);
        if (acceptedProofStatements[statement]) revert ProofStatementAlreadyAccepted(statement);
        if (!PROOF_VERIFIER.verifyProof(statement, proof)) {
            revert SuccinctProofRejected(statement);
        }

        acceptedProofStatements[statement] = true;
        transitions[statement] = TransitionRecord({
            approvalRoot: transition.nextApprovalRoot,
            priorApprovalCount: transition.priorApprovalCount,
            nextApprovalCount: transition.nextApprovalCount,
            rewardRecipient: transition.rewardRecipient,
            accepted: true
        });
        stateCommitment = transition.nextStateCommitment;
        finalizedTip = transition.nextTipHash;
        finalizedHeight = transition.nextHeight;
        finalizedMedianTimePast = transition.nextMedianTimePast;
        finalizedChainwork = transition.nextChainwork;
        orderedBlockTranscript = transition.nextOrderedBlockTranscript;
        finalizedApprovalCount = transition.nextApprovalCount;
        finalizedApprovalRoot = transition.nextApprovalRoot;
        finalizedClaimCount = transition.nextFinalizedClaimCount;
        finalizedClaimRoot = transition.nextFinalizedClaimRoot;

        emit Slot24TransitionAccepted(
            statement,
            transition.nextStateCommitment,
            transition.nextTipHash,
            transition.nextHeight,
            transition.blockCount,
            transition.nextApprovalCount - transition.priorApprovalCount,
            transition.rewardRecipient,
            msg.sender
        );
    }

    function registerApproval(
        bytes32 transitionId,
        ApprovalEvent calldata approval,
        uint64 approvalIndex,
        bytes32[APPROVAL_TREE_DEPTH] calldata siblings
    ) external {
        TransitionRecord storage transition = transitions[transitionId];
        if (!transition.accepted) revert UnknownTransition(transitionId);
        if (
            approvalIndex < transition.priorApprovalCount
                || approvalIndex >= transition.nextApprovalCount
        ) revert ApprovalIndexOutOfRange(approvalIndex);
        if (approval.vaultId != VAULT_ID) revert InvalidApprovalProof();
        if (
            approval.finalizationHeight < approval.inclusionHeight
                || approval.finalizationHeight - approval.inclusionHeight + 1 < FINALITY_DEPTH
                || approval.nextClaimCount <= approval.priorClaimCount
                || approval.nextClaimRoot == approval.priorClaimRoot
                || approval.finalizationChainwork == 0
        ) revert InvalidApprovalProof();
        if (approvals[approval.m6id].finalized) revert M6AlreadyAccepted(approval.m6id);
        bytes32 node = hashApprovalEvent(approval);
        for (uint256 level; level < APPROVAL_TREE_DEPTH; ++level) {
            node = ((approvalIndex >> level) & 1) == 0
                ? hashApprovalNode(node, siblings[level])
                : hashApprovalNode(siblings[level], node);
        }
        if (node != transition.approvalRoot) revert InvalidApprovalProof();

        approvals[approval.m6id] = ApprovalRecord({
            vaultId: approval.vaultId,
            priorClaimRoot: approval.priorClaimRoot,
            nextClaimRoot: approval.nextClaimRoot,
            bitcoinBlockHash: approval.finalizationTipHash,
            bitcoinChainwork: approval.finalizationChainwork,
            priorClaimCount: approval.priorClaimCount,
            nextClaimCount: approval.nextClaimCount,
            bitcoinHeight: approval.finalizationHeight,
            bitcoinMedianTimePast: approval.finalizationMedianTimePast,
            finalized: true
        });
        proofRewardRecipient[approval.m6id] = transition.rewardRecipient;
        emit M6ApprovalRegistered(
            approval.m6id,
            transitionId,
            approvalIndex,
            approval.nextClaimRoot,
            approval.nextClaimCount,
            transition.rewardRecipient,
            msg.sender
        );
    }

    function isM6Validated(bytes32 m6id) external view returns (bool) {
        return approvals[m6id].finalized;
    }

    function verify(bytes32 statement, bytes calldata approvalProof)
        external
        view
        override
        returns (bool)
    {
        if (approvalProof.length != 12 * 32) return false;
        VaultApprovalProof memory proof = abi.decode(approvalProof, (VaultApprovalProof));
        ApprovalRecord storage approval = approvals[proof.approvalM6id];
        bytes32 semanticCurrentRoot = proof.currentClaimCount == 0 && proof.currentClaimRoot == bytes32(0)
            ? emptyClaimRoot()
            : proof.currentClaimRoot;
        if (
            !approval.finalized || approval.vaultId != proof.vaultId
                || approval.priorClaimCount != proof.currentClaimCount
                || approval.priorClaimRoot != semanticCurrentRoot
                || proof.nextSequence != proof.currentSequence + 1
        ) return false;
        bytes32 currentContentsHash = _stateContentsHash(
            proof.currentSequence,
            proof.currentClaimCount,
            proof.currentClaimRoot,
            proof.currentM6id,
            proof.currentBitcoinTipHash,
            proof.currentBitcoinHeight,
            proof.currentBitcoinMedianTimePast,
            proof.currentBitcoinChainwork
        );
        bytes32 nextContentsHash = _stateContentsHash(
            proof.nextSequence,
            approval.nextClaimCount,
            approval.nextClaimRoot,
            proof.approvalM6id,
            approval.bitcoinBlockHash,
            approval.bitcoinHeight,
            approval.bitcoinMedianTimePast,
            approval.bitcoinChainwork
        );
        bytes32 nextStateHash = sha256(
            abi.encodePacked(APPROVED_REDEMPTION_STATE_DOMAIN, proof.currentStateHash, nextContentsHash)
        );
        bytes32 expected = sha256(
            abi.encodePacked(
                APPROVED_REDEMPTION_STATEMENT_DOMAIN,
                block.chainid,
                msg.sender,
                proof.vaultId,
                verifierProgramId,
                verifierConfigHash,
                ELEMENTS_GENESIS_HASH,
                USDD_ASSET_ID,
                proof.currentStateHash,
                currentContentsHash,
                nextStateHash,
                nextContentsHash
            )
        );
        return expected == statement;
    }

    function hashApprovalEvent(ApprovalEvent calldata approval) public pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                "USDD_ECASH_APPROVAL_LEAF_V1",
                approval.m6id,
                approval.vaultId,
                approval.priorClaimCount,
                approval.priorClaimRoot,
                approval.nextClaimCount,
                approval.nextClaimRoot,
                approval.inclusionBlockHash,
                approval.inclusionHeight,
                approval.finalizationTipHash,
                approval.finalizationHeight,
                approval.finalizationMedianTimePast,
                approval.finalizationChainwork
            )
        );
    }

    function hashApprovalNode(bytes32 left, bytes32 right) public pure returns (bytes32) {
        return sha256(abi.encodePacked("USDD_ECASH_APPROVAL_NODE_V1", left, right));
    }

    function emptyApprovalRoot() public pure returns (bytes32 node) {
        node = APPROVAL_EMPTY_DOMAIN;
        for (uint256 level; level < APPROVAL_TREE_DEPTH; ++level) {
            node = hashApprovalNode(node, node);
        }
    }

    function emptyClaimRoot() public pure returns (bytes32 node) {
        node = sha256(hex"00");
        for (uint256 level; level < 64; ++level) {
            node = sha256(abi.encodePacked(hex"01", node, node));
        }
    }

    function _validateTransition(Transition calldata transition) private view {
        if (
            transition.priorStateCommitment != stateCommitment
                || transition.priorTipHash != finalizedTip
                || transition.priorHeight != finalizedHeight
                || transition.priorMedianTimePast != finalizedMedianTimePast
                || transition.priorChainwork != finalizedChainwork
                || transition.priorOrderedBlockTranscript != orderedBlockTranscript
                || transition.priorApprovalCount != finalizedApprovalCount
                || transition.priorApprovalRoot != finalizedApprovalRoot
                || transition.priorFinalizedClaimCount != finalizedClaimCount
                || transition.priorFinalizedClaimRoot != finalizedClaimRoot
        ) revert StaleTransition();
        if (
            transition.configHash != ECASH_PROOF_CONFIG_HASH
                || transition.nextStateCommitment == bytes32(0)
                || transition.nextTipHash == bytes32(0) || transition.nextChainwork <= transition.priorChainwork
                || transition.nextMedianTimePast < transition.priorMedianTimePast
                || transition.nextOrderedBlockTranscript == bytes32(0)
                || transition.nextApprovalRoot == bytes32(0)
                || transition.nextFinalizedClaimRoot == bytes32(0)
                || transition.rewardRecipient == address(0)
        ) revert InvalidTransition();
        if (
            transition.blockCount == 0 || transition.blockCount > MAX_BLOCKS_PER_PROOF
                || transition.nextHeight <= transition.priorHeight
                || transition.nextHeight - transition.priorHeight != transition.blockCount
                || transition.nextApprovalCount < transition.priorApprovalCount
                || transition.nextFinalizedClaimCount < transition.priorFinalizedClaimCount
                || transition.maximumParentBlockTime > block.timestamp + MAX_FUTURE_PARENT_TIME
        ) revert InvalidTransition();
        if (
            transition.nextApprovalCount == transition.priorApprovalCount
                && transition.nextApprovalRoot != transition.priorApprovalRoot
        ) revert InvalidTransition();
        if (
            transition.nextFinalizedClaimCount == transition.priorFinalizedClaimCount
                && transition.nextFinalizedClaimRoot != transition.priorFinalizedClaimRoot
        ) revert InvalidTransition();
    }

    function _stateContentsHash(
        uint64 sequence,
        uint64 claimCount,
        bytes32 claimRoot,
        bytes32 m6id,
        bytes32 bitcoinTipHash,
        uint64 bitcoinHeight,
        uint64 bitcoinMedianTimePast,
        uint256 bitcoinChainwork
    ) private pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                sequence,
                claimCount,
                claimRoot,
                m6id,
                bitcoinTipHash,
                bitcoinHeight,
                bitcoinMedianTimePast,
                bitcoinChainwork
            )
        );
    }
}
