// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBip300RedemptionVerifier} from "./interfaces/IBip300RedemptionVerifier.sol";
import {ISuccinctBip300ProofVerifier} from "./interfaces/ISuccinctBip300ProofVerifier.sol";

/// @title SuccinctBitcoinBip300RelayV1
/// @notice Proof-native, ownerless eCash/BIP300 relay for long permissionless catch-up transitions.
/// @dev This contract deliberately stores only a commitment to the complete
///      consensus state. The immutable proof program is responsible for applying
///      every intervening block and exposing one finalized USDD M6 transition.
///      A transition may cover up to 30,000 blocks, approximately six months at
///      a ten-minute target with margin. Proof generation is off chain and has no
///      authority: the pinned verifier and public values decide acceptance.
contract SuccinctBitcoinBip300RelayV1 is IBip300RedemptionVerifier {
    uint32 public constant ABSOLUTE_MAX_BLOCKS_PER_PROOF = 30_000;
    uint8 public constant REQUIRED_DRIVECHAIN_SLOT = 24;

    bytes32 public constant EMPTY_APPROVED_CLAIM_ROOT =
        0xc13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db;
    bytes32 public constant RELAY_PROGRAM_DOMAIN =
        keccak256("USDD_SUCCINCT_BIP300_RELAY_PROGRAM_V1");
    bytes32 public constant RELAY_CONFIG_DOMAIN =
        keccak256("USDD_SUCCINCT_BIP300_RELAY_CONFIG_V1");
    bytes32 public constant TRANSITION_PUBLIC_VALUES_DOMAIN =
        keccak256("USDD_SUCCINCT_BIP300_TRANSITION_V1");
    bytes32 public constant APPROVED_REDEMPTION_STATE_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATE_V1");
    bytes32 public constant APPROVED_REDEMPTION_STATEMENT_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATEMENT_V1");

    struct RelayConfig {
        address proofVerifier;
        bytes32 proofVerifierCodehash;
        bytes32 proofProgramId;
        bytes32 proofConfigHash;
        bytes32 parentGenesisHash;
        bytes32 elementsGenesisHash;
        bytes32 usddAssetId;
        uint8 drivechainSlot;
        bytes32 initialStateCommitment;
        bytes32 initialFinalizedTip;
        uint64 initialFinalizedHeight;
        uint64 initialMedianTimePast;
        uint256 initialChainwork;
        bytes32 initialCtipTxid;
        uint32 initialCtipVout;
        uint64 initialCtipValue;
        uint32 finalityDepth;
        uint32 maxBlocksPerProof;
    }

    /// @dev All fields are public inputs to the succinct proof. `nextStateCommitment`
    ///      commits the complete all-slot state after applying exactly `blockCount`
    ///      consecutive blocks from `priorStateCommitment`. `rewardRecipient` is
    ///      proof-bound so copying a proof cannot steal its bounty.
    struct SuccinctM6Transition {
        bytes32 priorStateCommitment;
        bytes32 nextStateCommitment;
        bytes32 priorFinalizedTip;
        bytes32 nextFinalizedTip;
        uint64 priorFinalizedHeight;
        uint64 nextFinalizedHeight;
        uint64 nextMedianTimePast;
        uint256 priorChainwork;
        uint256 nextChainwork;
        bytes32 nextCtipTxid;
        uint32 nextCtipVout;
        uint64 nextCtipValue;
        uint32 blockCount;
        bytes32 orderedBlockDataCommitment;
        uint32 usddM6Count;
        bytes32 m6id;
        bytes32 m6BlockHash;
        uint64 m6BlockHeight;
        bytes32 vaultId;
        uint64 priorClaimCount;
        bytes32 priorClaimRoot;
        uint64 nextClaimCount;
        bytes32 nextClaimRoot;
        address rewardRecipient;
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
    bytes32 public immutable PROOF_PROGRAM_ID;
    bytes32 public immutable PROOF_CONFIG_HASH;
    bytes32 public immutable PARENT_GENESIS_HASH;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable USDD_ASSET_ID;
    uint8 public immutable DRIVECHAIN_SLOT;
    uint32 public immutable FINALITY_DEPTH;
    uint32 public immutable MAX_BLOCKS_PER_PROOF;

    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    bytes32 public stateCommitment;
    bytes32 public finalizedTip;
    uint64 public finalizedHeight;
    uint64 public finalizedMedianTimePast;
    uint256 public finalizedChainwork;
    bytes32 public ctipTxid;
    uint32 public ctipVout;
    uint64 public ctipValue;
    uint64 public approvedClaimCount;
    bytes32 public approvedClaimRoot;

    mapping(bytes32 m6id => ApprovalRecord record) public approvals;
    mapping(bytes32 m6id => address recipient) public proofRewardRecipient;
    mapping(bytes32 publicValuesHash => bool accepted) public acceptedProofStatements;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error ProofVerifierCodeChanged(bytes32 expected, bytes32 actual);
    error ProofVerifierIdentityChanged();
    error InvalidConfiguration();
    error InvalidTransition();
    error StaleTransition();
    error M6AlreadyAccepted(bytes32 m6id);
    error ProofStatementAlreadyAccepted(bytes32 statement);
    error SuccinctProofRejected(bytes32 publicValuesHash);

    event SuccinctM6TransitionAccepted(
        bytes32 indexed m6id,
        bytes32 indexed nextStateCommitment,
        bytes32 indexed nextFinalizedTip,
        uint64 nextFinalizedHeight,
        uint32 blockCount,
        bytes32 nextClaimRoot,
        uint64 nextClaimCount,
        address rewardRecipient,
        address submitter
    );

    constructor(RelayConfig memory config) {
        if (
            config.proofVerifier == address(0) || config.proofVerifierCodehash == bytes32(0)
                || config.proofProgramId == bytes32(0) || config.proofConfigHash == bytes32(0)
                || config.parentGenesisHash == bytes32(0) || config.elementsGenesisHash == bytes32(0)
                || config.usddAssetId == bytes32(0) || config.initialStateCommitment == bytes32(0)
                || config.initialFinalizedTip == bytes32(0) || config.initialChainwork == 0
                || config.initialCtipTxid == bytes32(0) || config.initialCtipValue == 0
        ) revert ZeroIdentity();
        if (config.proofVerifier.code.length == 0) revert AddressHasNoCode(config.proofVerifier);
        if (config.proofVerifier.codehash != config.proofVerifierCodehash) {
            revert InvalidConfiguration();
        }
        if (
            config.drivechainSlot != REQUIRED_DRIVECHAIN_SLOT || config.finalityDepth == 0
                || config.maxBlocksPerProof == 0
                || config.maxBlocksPerProof > ABSOLUTE_MAX_BLOCKS_PER_PROOF
        ) revert InvalidConfiguration();

        ISuccinctBip300ProofVerifier proofVerifier =
            ISuccinctBip300ProofVerifier(config.proofVerifier);
        if (
            proofVerifier.verifierProgramId() != config.proofProgramId
                || proofVerifier.verifierConfigHash() != config.proofConfigHash
        ) revert InvalidConfiguration();

        PROOF_VERIFIER = proofVerifier;
        PROOF_VERIFIER_CODEHASH = config.proofVerifierCodehash;
        PROOF_PROGRAM_ID = config.proofProgramId;
        PROOF_CONFIG_HASH = config.proofConfigHash;
        PARENT_GENESIS_HASH = config.parentGenesisHash;
        ELEMENTS_GENESIS_HASH = config.elementsGenesisHash;
        USDD_ASSET_ID = config.usddAssetId;
        DRIVECHAIN_SLOT = config.drivechainSlot;
        FINALITY_DEPTH = config.finalityDepth;
        MAX_BLOCKS_PER_PROOF = config.maxBlocksPerProof;

        verifierProgramId = sha256(abi.encode(RELAY_PROGRAM_DOMAIN, config.proofProgramId));
        verifierConfigHash = sha256(abi.encode(RELAY_CONFIG_DOMAIN, block.chainid, config));

        stateCommitment = config.initialStateCommitment;
        finalizedTip = config.initialFinalizedTip;
        finalizedHeight = config.initialFinalizedHeight;
        finalizedMedianTimePast = config.initialMedianTimePast;
        finalizedChainwork = config.initialChainwork;
        ctipTxid = config.initialCtipTxid;
        ctipVout = config.initialCtipVout;
        ctipValue = config.initialCtipValue;
        approvedClaimRoot = EMPTY_APPROVED_CLAIM_ROOT;
    }

    /// @notice Canonical proof public-values commitment, including the prover reward address.
    function transitionPublicValuesHash(SuccinctM6Transition calldata transition)
        public
        view
        returns (bytes32)
    {
        return sha256(
            abi.encode(
                TRANSITION_PUBLIC_VALUES_DOMAIN,
                block.chainid,
                address(this),
                verifierProgramId,
                verifierConfigHash,
                PROOF_PROGRAM_ID,
                PROOF_CONFIG_HASH,
                PARENT_GENESIS_HASH,
                ELEMENTS_GENESIS_HASH,
                USDD_ASSET_ID,
                DRIVECHAIN_SLOT,
                FINALITY_DEPTH,
                transition
            )
        );
    }

    /// @notice Advances up to MAX_BLOCKS_PER_PROOF consecutive eCash blocks and exposes one finalized M6.
    function submitSuccinctM6Proof(SuccinctM6Transition calldata transition, bytes calldata proof)
        external
    {
        _validateTransition(transition);
        bytes32 currentCodehash = address(PROOF_VERIFIER).codehash;
        if (currentCodehash != PROOF_VERIFIER_CODEHASH) {
            revert ProofVerifierCodeChanged(PROOF_VERIFIER_CODEHASH, currentCodehash);
        }
        if (
            PROOF_VERIFIER.verifierProgramId() != PROOF_PROGRAM_ID
                || PROOF_VERIFIER.verifierConfigHash() != PROOF_CONFIG_HASH
        ) revert ProofVerifierIdentityChanged();

        bytes32 publicValuesHash = transitionPublicValuesHash(transition);
        if (acceptedProofStatements[publicValuesHash]) {
            revert ProofStatementAlreadyAccepted(publicValuesHash);
        }
        if (!PROOF_VERIFIER.verifyProof(publicValuesHash, proof)) {
            revert SuccinctProofRejected(publicValuesHash);
        }

        acceptedProofStatements[publicValuesHash] = true;
        stateCommitment = transition.nextStateCommitment;
        finalizedTip = transition.nextFinalizedTip;
        finalizedHeight = transition.nextFinalizedHeight;
        finalizedMedianTimePast = transition.nextMedianTimePast;
        finalizedChainwork = transition.nextChainwork;
        ctipTxid = transition.nextCtipTxid;
        ctipVout = transition.nextCtipVout;
        ctipValue = transition.nextCtipValue;
        approvedClaimCount = transition.nextClaimCount;
        approvedClaimRoot = transition.nextClaimRoot;

        approvals[transition.m6id] = ApprovalRecord({
            vaultId: transition.vaultId,
            priorClaimRoot: transition.priorClaimRoot,
            nextClaimRoot: transition.nextClaimRoot,
            bitcoinBlockHash: transition.nextFinalizedTip,
            bitcoinChainwork: transition.nextChainwork,
            priorClaimCount: transition.priorClaimCount,
            nextClaimCount: transition.nextClaimCount,
            bitcoinHeight: transition.nextFinalizedHeight,
            bitcoinMedianTimePast: transition.nextMedianTimePast,
            finalized: true
        });
        proofRewardRecipient[transition.m6id] = transition.rewardRecipient;

        emit SuccinctM6TransitionAccepted(
            transition.m6id,
            transition.nextStateCommitment,
            transition.nextFinalizedTip,
            transition.nextFinalizedHeight,
            transition.blockCount,
            transition.nextClaimRoot,
            transition.nextClaimCount,
            transition.rewardRecipient,
            msg.sender
        );
    }

    function isM6Validated(bytes32 m6id) external view returns (bool) {
        return approvals[m6id].finalized;
    }

    /// @inheritdoc IBip300RedemptionVerifier
    function verify(bytes32 statement, bytes calldata approvalProof) external view override returns (bool) {
        if (approvalProof.length != 12 * 32) return false;
        VaultApprovalProof memory proof = abi.decode(approvalProof, (VaultApprovalProof));
        ApprovalRecord storage approval = approvals[proof.approvalM6id];
        bytes32 semanticCurrentRoot = proof.currentClaimCount == 0 && proof.currentClaimRoot == bytes32(0)
            ? EMPTY_APPROVED_CLAIM_ROOT
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

    function _validateTransition(SuccinctM6Transition calldata transition) private view {
        if (
            transition.priorStateCommitment != stateCommitment
                || transition.priorFinalizedTip != finalizedTip
                || transition.priorFinalizedHeight != finalizedHeight
                || transition.priorChainwork != finalizedChainwork
        ) revert StaleTransition();
        if (
            transition.nextStateCommitment == bytes32(0) || transition.nextFinalizedTip == bytes32(0)
                || transition.nextCtipTxid == bytes32(0) || transition.nextCtipValue == 0
                || transition.orderedBlockDataCommitment == bytes32(0)
                || transition.m6id == bytes32(0) || transition.m6BlockHash == bytes32(0)
                || transition.vaultId == bytes32(0) || transition.nextClaimRoot == bytes32(0)
                || transition.rewardRecipient == address(0)
        ) revert InvalidTransition();
        if (approvals[transition.m6id].finalized) revert M6AlreadyAccepted(transition.m6id);
        if (
            transition.blockCount == 0 || transition.blockCount > MAX_BLOCKS_PER_PROOF
                || transition.usddM6Count != 1
                || transition.nextFinalizedHeight <= transition.priorFinalizedHeight
                || transition.nextFinalizedHeight - transition.priorFinalizedHeight
                    != transition.blockCount
                || transition.nextChainwork <= transition.priorChainwork
                || transition.nextMedianTimePast < finalizedMedianTimePast
                || transition.nextCtipVout != 0
        ) revert InvalidTransition();
        if (
            transition.m6BlockHeight <= transition.priorFinalizedHeight
                || transition.m6BlockHeight > transition.nextFinalizedHeight
                || transition.nextFinalizedHeight - transition.m6BlockHeight + 1 < FINALITY_DEPTH
        ) revert InvalidTransition();
        if (
            transition.priorClaimCount != approvedClaimCount
                || transition.priorClaimRoot != approvedClaimRoot
                || transition.nextClaimCount <= transition.priorClaimCount
                || transition.nextClaimRoot == transition.priorClaimRoot
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
