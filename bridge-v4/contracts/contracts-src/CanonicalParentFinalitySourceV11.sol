// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICanonicalParentFinalityReceiptV11} from
    "./interfaces/ICanonicalParentFinalityReceiptV11.sol";
import {IV11AllSlotReplayProofVerifier} from
    "./interfaces/IV11AllSlotReplayProofVerifier.sol";
import {V11CanonicalFinalityEncoding} from
    "./libraries/V11CanonicalFinalityEncoding.sol";
import {V11ParentObservationEncoding} from
    "./libraries/V11ParentObservationEncoding.sol";

/// @title CanonicalParentFinalitySourceV11
/// @notice Permissionless proof-gated, permanently retained parent-fork
///         observation source for the V11 UniqueGreatestWork policy.
/// @dev Configuration is constructor-only storage rather than Solidity
///      `immutable` bytecode substitution. That keeps the runtime code hash
///      independent of the profile commitment which itself commits to this
///      source's runtime code hash. There are no setters, owners, proxies,
///      arbitrary calls, pruning methods or administrative fork choices.
///
///      Every branch endpoint is authenticated by the exact V11 all-slot SP1
///      guest. Equal-work tips are retained and make receipts unavailable.
///      A unique best tip must remain unchanged for both disclosure windows
///      before a finalized candidate can receive a receipt. A later greater
///      fork below an already accepted controller cursor makes the next relay
///      call fail closed; neither contract rolls state backward.
contract CanonicalParentFinalitySourceV11 is
    ICanonicalParentFinalityReceiptV11
{
    uint32 public constant REQUIRED_MINIMUM_FINALITY_CONFIRMATIONS = 100;
    uint64 public constant MAX_DISCLOSURE_BLOCKS = 50_400;
    uint64 public constant MAX_DISCLOSURE_SECONDS = 60 days;
    uint256 public constant MAX_PROOF_BYTES = 32 * 1024 * 1024;
    uint256 private constant ANCESTRY_LEVELS = 32;

    bytes32 public constant EXACT_PARENT_GENESIS_HASH_DISPLAY =
        0x00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6;
    bytes32 public constant EXACT_PARENT_GENESIS_SERIALIZATION_HASH =
        0xc8abc5554d8a4e1134b27050f0a6a8fc616196bfdd381fb49f49fdea6a811675;
    uint32 public constant EXACT_PARENT_GENESIS_MTP = 1_598_918_400;
    uint256 public constant EXACT_PARENT_GENESIS_CHAINWORK = 0x49d414;

    bytes internal constant SOURCE_IDENTITY_DOMAIN =
        "USDD_V11_RETAINED_RANGE_SOURCE_IDENTITY";
    bytes internal constant FORK_AVAILABILITY_POLICY_DOMAIN =
        "USDD_V11_RETAINED_RANGE_POLICY";
    bytes internal constant FINALITY_CONFIGURATION_DOMAIN =
        "USDD_V11_CANONICAL_FINALITY_CONFIG";
    bytes internal constant SOURCE_INTERFACE_ID =
        "USDD_V11_CANONICAL_PARENT_FINALITY_RECEIPT_INTERFACE_V1";

    struct SourceConfig {
        address proofVerifier;
        bytes32 proofVerifierCodehash;
        bytes32 proofProgramId;
        bytes32 proofConfigurationHash;
        bytes32 allSlotReplayProfileCommitment;
        bytes32 initialAllSlotCheckpointCommitment;
        Checkpoint initialFinalizedCheckpoint;
        uint32 finalityConfirmations;
        uint64 minimumDisclosureBlocks;
        uint64 minimumDisclosureSeconds;
    }

    struct ParentNode {
        bytes32 parentHashDisplay;
        bytes32 replayCheckpointCommitment;
        bytes32 journalCommitment;
        uint256 cumulativeChainwork;
        uint64 observedAtBlock;
        uint64 observedAtTimestamp;
        uint32 blockHeight;
        uint32 medianTimePast;
        bool exists;
        bool isTip;
    }

    uint256 public DEPLOYMENT_CHAIN_ID;
    IV11AllSlotReplayProofVerifier public PROOF_VERIFIER;
    bytes32 public PROOF_VERIFIER_CODEHASH;
    bytes32 public PROOF_PROGRAM_ID;
    bytes32 public PROOF_CONFIGURATION_HASH;
    bytes32 public ALL_SLOT_REPLAY_PROFILE_COMMITMENT;
    bytes32 public INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT;
    Checkpoint private _initialFinalizedCheckpoint;
    uint32 public FINALITY_CONFIRMATIONS;
    uint64 public MINIMUM_DISCLOSURE_BLOCKS;
    uint64 public MINIMUM_DISCLOSURE_SECONDS;

    mapping(bytes32 blockHashDisplay => ParentNode node) public parentNodes;
    mapping(bytes32 blockHashDisplay => bytes32[32] ancestors) private
        _ancestors;
    mapping(uint256 chainwork => uint64 tipCount) public tipCountAtChainwork;

    bytes32 public uniqueBestTip;
    uint256 public bestTipChainwork;
    uint64 public uniqueBestSinceBlock;
    uint64 public uniqueBestSinceTimestamp;
    uint64 public observationCount;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error InvalidConfiguration();
    error ProofVerifierCodeChanged(bytes32 expected, bytes32 actual);
    error ProofVerifierIdentityChanged();
    error ProofTooLarge(uint256 actual, uint256 maximum);
    error ParentReplayProofRejected(bytes32 publicValuesHash);
    error UnknownSourceCheckpoint(bytes32 blockHashDisplay);
    error SourceCheckpointMismatch();
    error ObservationAlreadyExists(bytes32 blockHashDisplay);
    error InvalidFinalityRequest();
    error FinalityUnavailable();
    error EqualWorkAmbiguity(uint256 chainwork, uint64 tipCount);

    event ParentObservationAccepted(
        bytes32 indexed journalCommitment,
        bytes32 indexed sourceBlockHashDisplay,
        bytes32 indexed nextBlockHashDisplay,
        bytes32 sourceReplayCheckpointCommitment,
        bytes32 nextReplayCheckpointCommitment,
        uint32 nextBlockHeight,
        uint32 nextMedianTimePast,
        uint256 nextCumulativeChainwork,
        bool containsControllerCertificate
    );
    event BestWorkStateChanged(
        bytes32 indexed uniqueBestTip,
        uint256 bestTipChainwork,
        uint64 tipCount,
        uint64 stableSinceBlock,
        uint64 stableSinceTimestamp
    );

    constructor(SourceConfig memory config) {
        if (config.proofVerifier == address(0)) revert ZeroIdentity();
        if (config.proofVerifier.code.length == 0) {
            revert AddressHasNoCode(config.proofVerifier);
        }
        if (
            config.proofVerifierCodehash == bytes32(0)
                || config.proofProgramId == bytes32(0)
                || config.proofConfigurationHash == bytes32(0)
                || config.allSlotReplayProfileCommitment == bytes32(0)
                || config.initialAllSlotCheckpointCommitment == bytes32(0)
        ) revert ZeroIdentity();
        if (
            config.proofVerifier.codehash != config.proofVerifierCodehash
                || config.finalityConfirmations
                    < REQUIRED_MINIMUM_FINALITY_CONFIRMATIONS
                || config.minimumDisclosureBlocks == 0
                || config.minimumDisclosureBlocks > MAX_DISCLOSURE_BLOCKS
                || config.minimumDisclosureSeconds == 0
                || config.minimumDisclosureSeconds > MAX_DISCLOSURE_SECONDS
                || !_isExactGenesis(config.initialFinalizedCheckpoint)
        ) revert InvalidConfiguration();

        IV11AllSlotReplayProofVerifier verifier =
            IV11AllSlotReplayProofVerifier(config.proofVerifier);
        if (
            verifier.verifierProgramId() != config.proofProgramId
                || verifier.verifierConfigHash()
                    != config.proofConfigurationHash
                || verifier.allSlotReplayProfileCommitment()
                    != config.allSlotReplayProfileCommitment
                || verifier.exactParentGenesisSerializationHash()
                    != EXACT_PARENT_GENESIS_SERIALIZATION_HASH
                || verifier.initialAllSlotCheckpointCommitment()
                    != config.initialAllSlotCheckpointCommitment
        ) revert InvalidConfiguration();

        DEPLOYMENT_CHAIN_ID = block.chainid;
        PROOF_VERIFIER = verifier;
        PROOF_VERIFIER_CODEHASH = config.proofVerifierCodehash;
        PROOF_PROGRAM_ID = config.proofProgramId;
        PROOF_CONFIGURATION_HASH = config.proofConfigurationHash;
        ALL_SLOT_REPLAY_PROFILE_COMMITMENT =
            config.allSlotReplayProfileCommitment;
        INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT =
            config.initialAllSlotCheckpointCommitment;
        _initialFinalizedCheckpoint = config.initialFinalizedCheckpoint;
        FINALITY_CONFIRMATIONS = config.finalityConfirmations;
        MINIMUM_DISCLOSURE_BLOCKS = config.minimumDisclosureBlocks;
        MINIMUM_DISCLOSURE_SECONDS = config.minimumDisclosureSeconds;

        bytes32 genesis = config.initialFinalizedCheckpoint.blockHashDisplay;
        parentNodes[genesis] = ParentNode({
            parentHashDisplay: bytes32(0),
            replayCheckpointCommitment: config
                .initialAllSlotCheckpointCommitment,
            journalCommitment: bytes32(0),
            cumulativeChainwork: config
                .initialFinalizedCheckpoint
                .cumulativeChainwork,
            observedAtBlock: _toUint64(block.number),
            observedAtTimestamp: _toUint64(block.timestamp),
            blockHeight: 0,
            medianTimePast: config.initialFinalizedCheckpoint.medianTimePast,
            exists: true,
            isTip: true
        });
        tipCountAtChainwork[
            config.initialFinalizedCheckpoint.cumulativeChainwork
        ] = 1;
        uniqueBestTip = genesis;
        bestTipChainwork =
            config.initialFinalizedCheckpoint.cumulativeChainwork;
        uniqueBestSinceBlock = _toUint64(block.number);
        uniqueBestSinceTimestamp = _toUint64(block.timestamp);
    }

    function sourceIdentity() public view override returns (bytes32) {
        return sha256(
            abi.encodePacked(
                SOURCE_IDENTITY_DOMAIN,
                DEPLOYMENT_CHAIN_ID,
                address(PROOF_VERIFIER),
                PROOF_VERIFIER_CODEHASH,
                PROOF_PROGRAM_ID,
                PROOF_CONFIGURATION_HASH,
                EXACT_PARENT_GENESIS_SERIALIZATION_HASH,
                V11CanonicalFinalityEncoding.encodeCheckpoint(
                    _initialFinalizedCheckpoint
                ),
                forkAvailabilityPolicyHash()
            )
        );
    }

    function sourceInterfaceHash() public pure override returns (bytes32) {
        return sha256(SOURCE_INTERFACE_ID);
    }

    function forkAvailabilityPolicyHash() public view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                FORK_AVAILABILITY_POLICY_DOMAIN,
                FINALITY_CONFIRMATIONS,
                MINIMUM_DISCLOSURE_BLOCKS,
                MINIMUM_DISCLOSURE_SECONDS,
                uint8(1), // permanent retention
                uint8(1) // UniqueGreatestWork
            )
        );
    }

    function canonicalFinalityConfigurationHash()
        public
        view
        override
        returns (bytes32)
    {
        return sha256(
            abi.encodePacked(
                FINALITY_CONFIGURATION_DOMAIN,
                sourceIdentity(),
                address(this).codehash,
                sourceInterfaceHash(),
                forkAvailabilityPolicyHash(),
                V11CanonicalFinalityEncoding.encodeCheckpoint(
                    _initialFinalizedCheckpoint
                ),
                uint8(1)
            )
        );
    }

    function initialFinalizedCheckpoint()
        external
        view
        returns (Checkpoint memory)
    {
        return _initialFinalizedCheckpoint;
    }

    function parentReplayProfileCommitment()
        external
        view
        override
        returns (bytes32)
    {
        return ALL_SLOT_REPLAY_PROFILE_COMMITMENT;
    }

    function initialParentReplayCheckpointCommitment()
        external
        view
        override
        returns (bytes32)
    {
        return INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT;
    }

    /// @notice Register one proof-authenticated adjacent replay range.
    /// @dev The source accepts both no-certificate and certificate journals.
    ///      This is essential: a competing greatest-work branch cannot be made
    ///      invisible merely because it has no USDD controller event.
    function submitParentObservation(
        bytes calldata journalBytes,
        bytes calldata proof
    ) external {
        if (proof.length > MAX_PROOF_BYTES) {
            revert ProofTooLarge(proof.length, MAX_PROOF_BYTES);
        }
        _requireDependencyIdentities();
        V11ParentObservationEncoding.Observation memory observation =
            V11ParentObservationEncoding.decode(journalBytes);
        if (
            observation.profileCommitment
                != ALL_SLOT_REPLAY_PROFILE_COMMITMENT
        ) revert InvalidConfiguration();

        ParentNode storage source =
            parentNodes[
                observation.sourceParentCheckpoint.blockHashDisplay
            ];
        if (!source.exists) {
            revert UnknownSourceCheckpoint(
                observation.sourceParentCheckpoint.blockHashDisplay
            );
        }
        if (
            source.replayCheckpointCommitment
                != observation.sourceCheckpointCommitment
                || !_matches(
                    source, observation.sourceParentCheckpoint
                )
        ) revert SourceCheckpointMismatch();

        bytes32 nextHash =
            observation.nextParentCheckpoint.blockHashDisplay;
        if (parentNodes[nextHash].exists) {
            revert ObservationAlreadyExists(nextHash);
        }
        (bytes32 publicValuesHash, bytes32 journalCommitment) =
            V11ParentObservationEncoding.hashes(journalBytes);
        _requireProof(publicValuesHash, proof);
        _requireDependencyIdentities();

        ParentNode storage next = parentNodes[nextHash];
        next.parentHashDisplay =
            observation.sourceParentCheckpoint.blockHashDisplay;
        next.replayCheckpointCommitment =
            observation.nextCheckpointCommitment;
        next.journalCommitment = journalCommitment;
        next.cumulativeChainwork =
            observation.nextParentCheckpoint.cumulativeChainwork;
        next.observedAtBlock = _toUint64(block.number);
        next.observedAtTimestamp = _toUint64(block.timestamp);
        next.blockHeight = observation.nextParentCheckpoint.blockHeight;
        next.medianTimePast =
            observation.nextParentCheckpoint.medianTimePast;
        next.exists = true;
        next.isTip = true;
        _buildAncestry(nextHash, next.parentHashDisplay);
        _replaceTip(source, nextHash, next.cumulativeChainwork);
        observationCount += 1;

        emit ParentObservationAccepted(
            journalCommitment,
            next.parentHashDisplay,
            nextHash,
            observation.sourceCheckpointCommitment,
            observation.nextCheckpointCommitment,
            next.blockHeight,
            next.medianTimePast,
            next.cumulativeChainwork,
            observation.containsControllerCertificate
        );
    }

    function verifyRetainedCanonicalRange(RangeRequest calldata request)
        external
        view
        override
        returns (RangeReceipt memory receipt)
    {
        _requireDependencyIdentities();
        if (request.subject == bytes32(0)) {
            revert InvalidFinalityRequest();
        }
        _requireValidPrior(request.prior);

        ParentNode storage candidate =
            parentNodes[request.candidate.blockHashDisplay];
        ParentNode storage prior =
            parentNodes[request.prior.checkpoint.blockHashDisplay];
        if (
            !candidate.exists || !_matches(candidate, request.candidate)
                || request.candidate.blockHeight
                    <= request.prior.checkpoint.blockHeight
                || request.candidate.cumulativeChainwork
                    <= request.prior.checkpoint.cumulativeChainwork
                || !_isAncestor(
                    request.prior.checkpoint.blockHashDisplay,
                    request.candidate.blockHashDisplay
                )
        ) revert InvalidFinalityRequest();

        bytes32 best = uniqueBestTip;
        uint64 bestCount = tipCountAtChainwork[bestTipChainwork];
        if (best == bytes32(0) || bestCount != 1) {
            revert EqualWorkAmbiguity(bestTipChainwork, bestCount);
        }
        ParentNode storage head = parentNodes[best];
        if (
            block.number
                < uint256(candidate.observedAtBlock)
                    + MINIMUM_DISCLOSURE_BLOCKS
                || block.timestamp
                    < uint256(candidate.observedAtTimestamp)
                        + MINIMUM_DISCLOSURE_SECONDS
                || !_isAncestor(
                    request.candidate.blockHashDisplay, best
                )
                || uint256(head.blockHeight)
                    < uint256(request.candidate.blockHeight)
                        + FINALITY_CONFIRMATIONS - 1
        ) revert FinalityUnavailable();

        // Candidate height is a strictly increasing, deterministic epoch.
        // Returning the candidate itself is intentional: it is the greatest
        // retained finalized checkpoint requested by the caller, while `best`
        // supplies the descendant confirmations and unique-work authority.
        uint64 epoch = uint64(request.candidate.blockHeight);
        receipt = RangeReceipt({
            receiptId: V11CanonicalFinalityEncoding.receiptId(
                request.subject, epoch, request.candidate
            ),
            receiptEpoch: epoch,
            observedFinalizedHead: request.candidate
        });
        _requireDependencyIdentities();
    }

    function isRetainedAncestor(
        bytes32 ancestorHashDisplay,
        bytes32 descendantHashDisplay
    ) external view returns (bool) {
        return _isAncestor(ancestorHashDisplay, descendantHashDisplay);
    }

    function _requireValidPrior(Cursor calldata prior) private view {
        ParentNode storage node =
            parentNodes[prior.checkpoint.blockHashDisplay];
        if (!node.exists || !_matches(node, prior.checkpoint)) {
            revert InvalidFinalityRequest();
        }
        if (prior.receiptEpoch == 0) {
            if (
                prior.receiptId != bytes32(0)
                    || prior.checkpoint.blockHashDisplay
                        != _initialFinalizedCheckpoint.blockHashDisplay
            ) revert InvalidFinalityRequest();
        } else if (
            prior.receiptId == bytes32(0)
                || prior.receiptEpoch != prior.checkpoint.blockHeight
        ) {
            revert InvalidFinalityRequest();
        }
    }

    function _replaceTip(
        ParentNode storage source,
        bytes32 nextHash,
        uint256 nextWork
    ) private {
        if (source.isTip) {
            source.isTip = false;
            uint64 sourceCount =
                tipCountAtChainwork[source.cumulativeChainwork];
            if (sourceCount == 0) revert InvalidConfiguration();
            tipCountAtChainwork[source.cumulativeChainwork] =
                sourceCount - 1;
        }
        tipCountAtChainwork[nextWork] += 1;

        bytes32 previousUnique = uniqueBestTip;
        if (nextWork > bestTipChainwork) {
            bestTipChainwork = nextWork;
        }
        uint64 count = tipCountAtChainwork[bestTipChainwork];
        bytes32 nextUnique;
        if (count == 1) {
            if (nextWork == bestTipChainwork) {
                nextUnique = nextHash;
            } else if (
                previousUnique != bytes32(0)
                    && parentNodes[previousUnique].isTip
                    && parentNodes[previousUnique].cumulativeChainwork
                        == bestTipChainwork
            ) {
                nextUnique = previousUnique;
            }
        }
        uniqueBestTip = nextUnique;
        if (nextUnique != previousUnique) {
            uniqueBestSinceBlock = _toUint64(block.number);
            uniqueBestSinceTimestamp = _toUint64(block.timestamp);
            emit BestWorkStateChanged(
                nextUnique,
                bestTipChainwork,
                count,
                uniqueBestSinceBlock,
                uniqueBestSinceTimestamp
            );
        }
    }

    function _buildAncestry(bytes32 child, bytes32 parent) private {
        _ancestors[child][0] = parent;
        for (uint256 level = 1; level < ANCESTRY_LEVELS; ++level) {
            bytes32 half = _ancestors[child][level - 1];
            if (half == bytes32(0)) break;
            _ancestors[child][level] =
                _ancestors[half][level - 1];
        }
    }

    function _isAncestor(bytes32 ancestor, bytes32 descendant)
        private
        view
        returns (bool)
    {
        ParentNode storage ancestorNode = parentNodes[ancestor];
        ParentNode storage descendantNode = parentNodes[descendant];
        if (
            !ancestorNode.exists || !descendantNode.exists
                || ancestorNode.blockHeight > descendantNode.blockHeight
        ) return false;
        bytes32 cursor = descendant;
        uint32 targetHeight = ancestorNode.blockHeight;
        for (uint256 level = ANCESTRY_LEVELS; level > 0; --level) {
            bytes32 jump = _ancestors[cursor][level - 1];
            if (
                jump != bytes32(0)
                    && parentNodes[jump].blockHeight >= targetHeight
            ) {
                cursor = jump;
            }
        }
        return cursor == ancestor;
    }

    function _matches(ParentNode storage node, Checkpoint memory checkpoint)
        private
        view
        returns (bool)
    {
        return node.exists
            && node.blockHeight == checkpoint.blockHeight
            && node.medianTimePast == checkpoint.medianTimePast
            && node.cumulativeChainwork == checkpoint.cumulativeChainwork;
    }

    function _isExactGenesis(Checkpoint memory checkpoint)
        private
        pure
        returns (bool)
    {
        return checkpoint.blockHashDisplay
                == EXACT_PARENT_GENESIS_HASH_DISPLAY
            && checkpoint.blockHeight == 0
            && checkpoint.medianTimePast == EXACT_PARENT_GENESIS_MTP
            && checkpoint.cumulativeChainwork
                == EXACT_PARENT_GENESIS_CHAINWORK;
    }

    function _requireProof(
        bytes32 publicValuesHash,
        bytes calldata proof
    ) private view {
        (bool ok, bytes memory returned) =
            address(PROOF_VERIFIER).staticcall(
                abi.encodeCall(
                    IV11AllSlotReplayProofVerifier.verifyProof,
                    (publicValuesHash, proof)
                )
            );
        if (
            !ok || returned.length != 32
                || abi.decode(returned, (uint256)) != 1
        ) revert ParentReplayProofRejected(publicValuesHash);
    }

    function _requireDependencyIdentities() private view {
        bytes32 actualCodehash = address(PROOF_VERIFIER).codehash;
        if (actualCodehash != PROOF_VERIFIER_CODEHASH) {
            revert ProofVerifierCodeChanged(
                PROOF_VERIFIER_CODEHASH, actualCodehash
            );
        }
        if (
            block.chainid != DEPLOYMENT_CHAIN_ID
                || PROOF_VERIFIER.verifierProgramId()
                    != PROOF_PROGRAM_ID
                || PROOF_VERIFIER.verifierConfigHash()
                    != PROOF_CONFIGURATION_HASH
                || PROOF_VERIFIER.allSlotReplayProfileCommitment()
                    != ALL_SLOT_REPLAY_PROFILE_COMMITMENT
                || PROOF_VERIFIER.canonicalFinalityConfigurationHash()
                    != canonicalFinalityConfigurationHash()
                || PROOF_VERIFIER.exactParentGenesisSerializationHash()
                    != EXACT_PARENT_GENESIS_SERIALIZATION_HASH
                || PROOF_VERIFIER.initialAllSlotCheckpointCommitment()
                    != INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT
        ) revert ProofVerifierIdentityChanged();
    }

    function _toUint64(uint256 value) private pure returns (uint64) {
        if (value > type(uint64).max) revert InvalidConfiguration();
        return uint64(value);
    }
}
