// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBip300RedemptionVerifier} from "./interfaces/IBip300RedemptionVerifier.sol";

interface IBitcoinTransactionStreamFactsV1 {
    struct Facts {
        bytes32 txid;
        bytes32 transactionMerkleRoot;
        bytes32 trackedTxid;
        uint32 trackedVout;
        uint32 transactionIndex;
        uint32 transactionCount;
        bool isCoinbase;
        bool spendsTrackedOutpoint;
        bool createsSlotTreasury;
        bool complete;
        uint64 completedBlock;
    }

    function CONFIG_HASH() external view returns (bytes32);

    function completedFacts(bytes32 factId) external view returns (Facts memory);

    function parseSlot24M6(
        bytes calldata rawM6,
        bytes32 currentCtipTxid,
        uint32 currentCtipVout,
        uint64 currentCtipValue,
        bytes32 elementsGenesisHashDisplay
    ) external view returns (
        bytes32 txid,
        bytes32 m6id,
        bytes32 rootCommitment,
        uint64 nextCtipValue,
        uint8 kind
    );
}

/// @title BitcoinBip300RelayV1
/// @notice Ownerless, immutable-configuration Bitcoin/BIP300 relay for one active slot-24 sidechain.
/// @dev Headers may fork above the finalized tip. BIP300 state is applied only
///      after a block has FINALITY_DEPTH inclusive confirmations on the
///      greatest-work branch.
///      V1 deliberately rejects M1/M2 and requires slot 24 to be the sole active
///      sidechain: interpreting M4 for a changing multi-slot active set without
///      replaying every slot would be unsound. The resumable census authenticates
///      each exact position under the header txid root and performs a second
///      pass against the successor CTIP. Bitcoin CTIP increases (M5) and
///      noncanonical CTIP spends halt rather than advancing stale state.
contract BitcoinBip300RelayV1 is IBip300RedemptionVerifier {
    /// @dev This incomplete relay may authorize only valueless Sepolia test
    ///      deployments. A byte-identical deployment on Ethereum mainnet (or
    ///      any other chain) remains permanently fail closed.
    uint256 public constant SEPOLIA_CHAIN_ID = 11_155_111;
    uint8 public constant REQUIRED_DRIVECHAIN_SLOT = 24;
    uint32 private constant MAX_M6_BYTES = 4_096;
    uint32 public constant MAX_FUTURE_BLOCK_TIME = 7_200;
    /// @dev Direct transaction calls are deliberately bounded below Ethereum's
    ///      block gas limit. Larger stripped transactions use the immutable
    ///      BitcoinTransactionStreamV1 fact importer.
    uint32 private constant MAX_STREAMED_TRANSACTION_BYTES = 24_576;
    uint64 private constant STREAMED_CENSUS_EXPIRY_BLOCKS = 50_400;
    uint8 public constant MTP_WINDOW = 11;
    uint8 private constant MAX_ACCUMULATOR_M6_PER_FINALIZED_BLOCK = 1;

    // Machine-readable launch gates. These are deliberately false in this
    // candidate and are included in the immutable build artifact. The
    // production profile is the proof-of-work eCash parent, not Signet; BIP325
    // is consequently outside this relay's mainnet consensus surface.
    bool public constant SUPPORTS_COMPLETE_M5_M6_REPLAY = false;
    bool public constant SUPPORTS_DYNAMIC_ACTIVE_SLOTS = false;
    bool public constant CHECKPOINT_IS_CRYPTOGRAPHICALLY_DERIVED = false;
    bool public constant SUPPORTS_UNBOUNDED_PENDING_BUNDLES = false;
    bool public constant PROVES_FULL_BITCOIN_BLOCK_VALIDITY = false;
    bool public constant PRODUCTION_VERIFICATION_ENABLED = false;
    bool public constant REQUIRES_EXHAUSTIVE_TXID_MERKLE_RECONSTRUCTION = true;

    /// @notice Chain identity captured immutably by the creation transaction.
    uint256 public immutable DEPLOYMENT_CHAIN_ID;
    /// @notice True only for an actual Sepolia deployment of this candidate.
    /// @dev This is not a production launch gate and cannot be changed later.
    bool public immutable SEPOLIA_TESTNET_VERIFICATION_ENABLED;

    bytes4 private constant M1_TAG = 0xd5e0c4af;
    bytes4 private constant M2_TAG = 0xd6e1c5df;
    bytes4 private constant M3_TAG = 0xd45aa943;
    bytes4 private constant M4_TAG = 0xd77d1776;
    bytes4 private constant M7_TAG = 0xd1617368;
    uint8 private constant M6_KIND_USDD_ROOT = 1;
    uint8 private constant M6_KIND_NATIVE_WITHDRAWAL = 2;

    bytes32 public constant M6_ROOT_DOMAIN = sha256("USDD_M6_APPROVED_ROOT_V1");
    bytes32 public constant EMPTY_APPROVED_CLAIM_ROOT =
        0xc13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db;
    bytes32 public constant APPROVED_REDEMPTION_STATE_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATE_V1");
    bytes32 public constant APPROVED_REDEMPTION_STATEMENT_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATEMENT_V1");
    bytes32 public constant RELAY_CONFIG_DOMAIN =
        keccak256("USDD_BITCOIN_BIP300_RELAY_CONFIG_V1");
    bytes32 private constant STREAMED_CENSUS_DOMAIN =
        sha256("USDD_BITCOIN_STREAMED_TRANSACTION_CENSUS_V1");

    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;
    bytes32 public immutable BITCOIN_GENESIS_HASH;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable USDD_ASSET_ID;
    bytes32 public immutable CHECKPOINT_BLOCK_HASH;
    IBitcoinTransactionStreamFactsV1 private immutable TRANSACTION_STREAM;
    bytes32 private immutable TRANSACTION_STREAM_CODEHASH;
    uint8 public immutable DRIVECHAIN_SLOT;
    uint256 public immutable ACTIVE_SLOTS_BITMAP;
    uint32 public immutable FINALITY_DEPTH;
    uint32 public immutable MAX_HEADERS_PER_BATCH;
    uint32 public immutable RETARGET_INTERVAL;
    uint32 public immutable TARGET_TIMESPAN;
    uint256 public immutable POW_LIMIT;
    uint16 public immutable WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD;
    uint32 public immutable WITHDRAWAL_BUNDLE_MAX_AGE;
    uint16 public immutable MAX_PENDING_BUNDLES;

    struct RelayConfig {
        bytes32 programId;
        bytes32 bitcoinGenesisHash;
        bytes32 elementsGenesisHash;
        bytes32 usddAssetId;
        uint8 drivechainSlot;
        uint256 activeSlotsBitmap;
        bytes32 checkpointBlockHash;
        uint32 checkpointHeight;
        uint32[11] checkpointMtpTimestampsNewestFirst;
        uint32 checkpointBits;
        uint32 checkpointEpochStartTime;
        uint256 checkpointChainwork;
        bytes32 checkpointCtipTxid;
        uint32 checkpointCtipVout;
        uint64 checkpointCtipValue;
        uint32 finalityDepth;
        uint32 maxHeadersPerBatch;
        uint32 retargetInterval;
        uint32 targetTimespan;
        uint256 powLimit;
        uint16 withdrawalBundleInclusionThreshold;
        uint32 withdrawalBundleMaxAge;
        uint16 maxPendingBundles;
        address transactionStream;
        bytes32 transactionStreamCodehash;
        bytes32 transactionStreamConfigHash;
    }

    struct HeaderNode {
        bytes32 parent;
        bytes32 merkleRoot;
        uint256 chainwork;
        uint32 height;
        uint32 timestamp;
        uint32 medianTimePast;
        uint32 bits;
        uint32 epochStartTime;
        bool exists;
    }

    struct PendingBundle {
        bytes32 m6id;
        uint32 proposalHeight;
        uint16 voteCount;
    }

    struct RootTransition {
        bytes32 vaultId;
        uint64 priorClaimCount;
        bytes32 priorClaimRoot;
        uint64 nextClaimCount;
        bytes32 nextClaimRoot;
    }

    /// @dev Phase 1 authenticates every stripped transaction against the
    ///      header's txid root and finds the sole slot-24 CTIP transition.
    ///      Phase 2 replays the same committed vector against the successor
    ///      CTIP, closing same-block spend omission without one monolithic call.
    ///      `phase`: 0 absent, 1 census, 2 successor scan, 3 complete.
    struct StreamedCensus {
        bytes32 blockHash;
        bytes32 merkleRoot;
        bytes32 ctipTxidSnapshot;
        bytes32 coinbaseTxid;
        bytes32 candidateM6Txid;
        uint32 ctipVoutSnapshot;
        uint32 transactionCount;
        uint32 nextTransactionIndex;
        uint32 candidateM6Index;
        uint64 lastProgressBlock;
        uint8 phase;
    }

    struct StreamedFinalizedBlockProof {
        bytes32 censusId;
        bytes rawCoinbase;
        bytes rawM6;
        RootTransition transition;
    }

    struct TransactionFacts {
        bytes32 txid;
        bool isCoinbase;
        bool spendsCtip;
        bool createsSlot24Treasury;
    }

    struct InputScan {
        uint256 cursor;
        uint256 count;
        uint256 nullInputs;
        uint256 coinbaseScriptLength;
        bool spendsCtip;
    }

    struct ParsedM6 {
        bytes32 txid;
        bytes32 m6id;
        bytes32 rootCommitment;
        uint64 nextCtipValue;
        uint8 kind;
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

    mapping(bytes32 blockHash => HeaderNode node) public headers;
    mapping(bytes32 m6id => ApprovalRecord record) public approvals;
    /// @notice The sole accumulator M6 processed for a finalized parent block.
    /// @dev The complete transaction set rejects every additional slot-24
    ///      treasury touch, while this mapping makes the one-checkpoint
    ///      invariant explicit and replay-safe. Other slots remain unsupported.
    mapping(bytes32 blockHash => bytes32 displayM6id) public accumulatorM6ByFinalizedBlock;
    mapping(bytes32 censusId => StreamedCensus census) private _streamedCensuses;
    bytes32 public bestTip;
    bytes32 public finalizedTip;
    uint32 public finalizedHeight;
    bytes32 public ctipTxid;
    uint32 public ctipVout;
    uint64 public ctipValue;

    // Exact checkpoint block and ten ancestors, newest first. These slots are
    // written only by the constructor and are committed by verifierConfigHash.
    uint32[11] public checkpointMtpTimestampsNewestFirst;

    PendingBundle[] private _pendingBundles;
    uint8 private _previousVoteAction; // 0 none, 1 upvote, 2 alarm
    bytes32 private _previousUpvoteM6id;
    /// @notice Wire-order blinded M6ids already consumed by a finalized slot-24 M6.
    mapping(bytes32 m6id => bool consumed) public consumedSlot24M6ids;

    error ZeroIdentity();
    error UnsupportedSlot(uint8 supplied);
    error UnsupportedActiveSlotSet(uint256 supplied);
    error InvalidConfiguration();
    error InvalidCheckpointTarget();
    error HeaderBatchLength(uint256 supplied);
    error HeaderBatchTooLarge(uint256 supplied, uint256 maximum);
    error UnknownParent(bytes32 parent);
    error DuplicateHeader(bytes32 blockHash);
    error HeaderBelowFinalizedFork(bytes32 blockHash);
    error InvalidHeaderTime(uint32 supplied, uint32 minimumExclusive);
    error HeaderTooFarInFuture(uint32 supplied, uint256 maximum);
    error WrongDifficultyBits(uint32 expected, uint32 supplied);
    error InvalidProofOfWork(bytes32 blockHash, uint256 target);
    error ChainworkOverflow();
    error BlockNotNextFinalized(uint32 expected, uint32 supplied);
    error BlockNotOnBestBranch(bytes32 blockHash);
    error InsufficientFinality(uint32 bestHeight, uint32 blockHeight, uint32 requiredDepth);
    error M6TooLarge(uint256 supplied);
    error MalformedBitcoinTransaction();
    error NonCanonicalCompactSize();
    error FirstTransactionNotCoinbase();
    error MultipleCoinbaseTransactions();
    error MutatedTransactionMerkleTree();
    error UnsupportedCtipTransition(uint256 transactionIndex);
    error UnsupportedSidechainActivationMessage(bytes4 tag);
    error UnsupportedM3Slot(uint8 slot);
    error DuplicateM4();
    error InvalidM4();
    error DuplicatePendingM6id(bytes32 m6id);
    error ConsumedM6id(bytes32 m6id);
    error TooManyPendingBundles(uint256 maximum);
    error RepeatVoteTargetMissing(bytes32 m6id);
    error InvalidM6();
    error M6NotApproved(bytes32 m6id, uint16 voteCount);
    error WrongCtip();
    error InvalidRootTransition();
    error RootCommitmentMismatch();
    error ApprovalAlreadyExists(bytes32 m6id);
    error AccumulatorM6AlreadyProcessed(bytes32 blockHash, bytes32 displayM6id);
    error InvalidStreamedCensus();
    error StreamedCensusNotExpired();
    error TransactionStreamCodeChanged();

    event HeaderAccepted(bytes32 indexed blockHash, bytes32 indexed parent, uint32 height, uint256 chainwork);
    event BestTipChanged(bytes32 indexed previousTip, bytes32 indexed nextTip, uint32 height, uint256 chainwork);
    event BundleProposed(bytes32 indexed m6id, uint32 proposalHeight);
    event BundleVoteApplied(bytes32 indexed m6id, uint16 voteCount, uint32 height);
    event BundleExpired(bytes32 indexed m6id, uint32 height);
    event RedemptionRootApproved(
        bytes32 indexed m6id,
        bytes32 indexed vaultId,
        bytes32 indexed nextClaimRoot,
        uint64 nextClaimCount,
        bytes32 bitcoinBlockHash,
        uint32 bitcoinHeight
    );
    event NativeWithdrawalM6Processed(
        bytes32 indexed m6id,
        bytes32 indexed transactionId,
        bytes32 indexed bitcoinBlockHash,
        uint32 bitcoinHeight
    );
    event FinalizedBlockProcessed(bytes32 indexed blockHash, uint32 height);

    constructor(RelayConfig memory config) {
        DEPLOYMENT_CHAIN_ID = block.chainid;
        SEPOLIA_TESTNET_VERIFICATION_ENABLED = block.chainid == SEPOLIA_CHAIN_ID;
        if (
            config.programId == bytes32(0) || config.bitcoinGenesisHash == bytes32(0)
                || config.elementsGenesisHash == bytes32(0) || config.usddAssetId == bytes32(0)
                || config.checkpointBlockHash == bytes32(0) || config.checkpointChainwork == 0
                || config.checkpointCtipTxid == bytes32(0) || config.transactionStream == address(0)
                || config.transactionStreamCodehash == bytes32(0)
                || config.transactionStreamConfigHash == bytes32(0)
        ) revert ZeroIdentity();
        if (
            config.transactionStream.code.length == 0
                || config.transactionStream.codehash != config.transactionStreamCodehash
        ) revert InvalidConfiguration();
        IBitcoinTransactionStreamFactsV1 transactionStream =
            IBitcoinTransactionStreamFactsV1(config.transactionStream);
        if (transactionStream.CONFIG_HASH() != config.transactionStreamConfigHash) {
            revert InvalidConfiguration();
        }
        if (config.drivechainSlot != REQUIRED_DRIVECHAIN_SLOT) {
            revert UnsupportedSlot(config.drivechainSlot);
        }
        uint256 onlySlot = uint256(1) << config.drivechainSlot;
        if (config.activeSlotsBitmap != onlySlot) {
            revert UnsupportedActiveSlotSet(config.activeSlotsBitmap);
        }
        if (
            config.finalityDepth == 0 || config.maxHeadersPerBatch == 0
                || config.retargetInterval == 0 || config.targetTimespan == 0
                || config.powLimit == 0 || config.withdrawalBundleMaxAge == 0
                || config.maxPendingBundles == 0
                || config.withdrawalBundleInclusionThreshold >= type(uint16).max
                || config.checkpointCtipValue == 0
                || config.checkpointHeight < MTP_WINDOW - 1
                || config.checkpointEpochStartTime > config.checkpointMtpTimestampsNewestFirst[0]
        ) revert InvalidConfiguration();
        for (uint256 i; i < MTP_WINDOW; ++i) {
            if (config.checkpointMtpTimestampsNewestFirst[i] == 0) revert InvalidConfiguration();
        }
        uint256 checkpointTarget = _compactToTarget(config.checkpointBits);
        if (checkpointTarget == 0 || checkpointTarget > config.powLimit) revert InvalidCheckpointTarget();

        verifierProgramId = config.programId;
        BITCOIN_GENESIS_HASH = config.bitcoinGenesisHash;
        ELEMENTS_GENESIS_HASH = config.elementsGenesisHash;
        USDD_ASSET_ID = config.usddAssetId;
        CHECKPOINT_BLOCK_HASH = config.checkpointBlockHash;
        TRANSACTION_STREAM = transactionStream;
        TRANSACTION_STREAM_CODEHASH = config.transactionStreamCodehash;
        DRIVECHAIN_SLOT = config.drivechainSlot;
        ACTIVE_SLOTS_BITMAP = config.activeSlotsBitmap;
        FINALITY_DEPTH = config.finalityDepth;
        MAX_HEADERS_PER_BATCH = config.maxHeadersPerBatch;
        RETARGET_INTERVAL = config.retargetInterval;
        TARGET_TIMESPAN = config.targetTimespan;
        POW_LIMIT = config.powLimit;
        WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD = config.withdrawalBundleInclusionThreshold;
        WITHDRAWAL_BUNDLE_MAX_AGE = config.withdrawalBundleMaxAge;
        MAX_PENDING_BUNDLES = config.maxPendingBundles;

        // ABI encoding the whole fixed-layout struct is collision-free and keeps
        // every consensus and checkpoint identity inside the immutable digest.
        verifierConfigHash = sha256(abi.encode(RELAY_CONFIG_DOMAIN, config));

        for (uint256 i; i < MTP_WINDOW; ++i) {
            checkpointMtpTimestampsNewestFirst[i] = config.checkpointMtpTimestampsNewestFirst[i];
        }
        uint32 checkpointTime = config.checkpointMtpTimestampsNewestFirst[0];
        uint32 checkpointMedianTimePast = _checkpointMedian(config.checkpointMtpTimestampsNewestFirst);

        headers[config.checkpointBlockHash] = HeaderNode({
            parent: bytes32(0),
            merkleRoot: bytes32(0),
            chainwork: config.checkpointChainwork,
            height: config.checkpointHeight,
            timestamp: checkpointTime,
            medianTimePast: checkpointMedianTimePast,
            bits: config.checkpointBits,
            epochStartTime: config.checkpointEpochStartTime,
            exists: true
        });
        bestTip = config.checkpointBlockHash;
        finalizedTip = config.checkpointBlockHash;
        finalizedHeight = config.checkpointHeight;
        ctipTxid = config.checkpointCtipTxid;
        ctipVout = config.checkpointCtipVout;
        ctipValue = config.checkpointCtipValue;
    }

    /// @notice Adds 1..MAX_HEADERS_PER_BATCH exact 80-byte Bitcoin headers.
    function submitHeaders(bytes calldata rawHeaders) external {
        if (rawHeaders.length == 0 || rawHeaders.length % 80 != 0) {
            revert HeaderBatchLength(rawHeaders.length);
        }
        uint256 count = rawHeaders.length / 80;
        if (count > MAX_HEADERS_PER_BATCH) revert HeaderBatchTooLarge(count, MAX_HEADERS_PER_BATCH);
        for (uint256 i; i < count; ++i) {
            _submitHeader(rawHeaders, i * 80);
        }
    }

    /// @notice Returns the deterministic session identity for a root-bound
    ///         transaction census. A false count cannot poison the correct
    ///         session because the count is part of this key.
    function streamedCensusId(bytes32 blockHash, uint32 transactionCount)
        public
        view
        returns (bytes32)
    {
        HeaderNode storage node = headers[blockHash];
        return sha256(
            abi.encodePacked(
                STREAMED_CENSUS_DOMAIN,
                blockHash,
                node.merkleRoot,
                transactionCount,
                ctipTxid,
                ctipVout
            )
        );
    }

    /// @notice Advances the authenticated census by one stripped transaction.
    /// @param successorPass False for the complete first pass; true for the
    ///        complete successor-CTIP non-spend pass required when an M6 exists.
    /// @dev Each caller supplies the Bitcoin txid-Merkle branch at `index`.
    ///      The session is permissionless: a third party can only submit the
    ///      unique committed transaction for the exact next index, so it cannot
    ///      corrupt or redirect honest progress.
    function streamFinalizedTransaction(
        bytes32 blockHash,
        uint32 transactionCount,
        uint32 index,
        bool successorPass,
        bytes calldata strippedTransaction,
        bytes32[] calldata merkleBranch
    ) external returns (bytes32 censusId) {
        if (strippedTransaction.length > MAX_STREAMED_TRANSACTION_BYTES) {
            revert InvalidStreamedCensus();
        }
        StreamedCensus storage census;
        (censusId, census) =
            _prepareStreamedCensus(blockHash, transactionCount, index, successorPass);

        TransactionFacts memory facts = _transactionFactsForOutpoint(
            strippedTransaction,
            successorPass ? census.candidateM6Txid : census.ctipTxidSnapshot,
            successorPass ? 0 : census.ctipVoutSnapshot
        );
        _verifyTransactionMembership(
            facts.txid, index, transactionCount, merkleBranch, census.merkleRoot
        );
        _recordStreamedFacts(census, facts, index, successorPass);
    }

    /// @notice Imports an oversized transaction that the immutable byte-stream
    ///         component has fully hashed, canonically parsed, and position-bound.
    function streamFinalizedTransactionFact(
        bytes32 blockHash,
        uint32 transactionCount,
        uint32 index,
        bool successorPass,
        bytes32 factId
    ) external returns (bytes32 censusId) {
        if (address(TRANSACTION_STREAM).codehash != TRANSACTION_STREAM_CODEHASH) {
            revert TransactionStreamCodeChanged();
        }
        StreamedCensus storage census;
        (censusId, census) =
            _prepareStreamedCensus(blockHash, transactionCount, index, successorPass);
        IBitcoinTransactionStreamFactsV1.Facts memory imported =
            TRANSACTION_STREAM.completedFacts(factId);
        bytes32 trackedTxid = successorPass ? census.candidateM6Txid : census.ctipTxidSnapshot;
        uint32 trackedVout = successorPass ? 0 : census.ctipVoutSnapshot;
        if (
            !imported.complete || imported.transactionMerkleRoot != census.merkleRoot
                || imported.transactionIndex != index || imported.transactionCount != transactionCount
                || imported.trackedTxid != trackedTxid || imported.trackedVout != trackedVout
        ) revert InvalidStreamedCensus();
        TransactionFacts memory facts = TransactionFacts({
            txid: imported.txid,
            isCoinbase: imported.isCoinbase,
            spendsCtip: imported.spendsTrackedOutpoint,
            createsSlot24Treasury: imported.createsSlotTreasury
        });
        _recordStreamedFacts(census, facts, index, successorPass);
    }

    function _recordStreamedFacts(
        StreamedCensus storage census,
        TransactionFacts memory facts,
        uint32 index,
        bool successorPass
    ) private {
        if (successorPass) {
            if (facts.spendsCtip) revert UnsupportedCtipTransition(index);
        } else if (index == 0) {
            if (!facts.isCoinbase) revert FirstTransactionNotCoinbase();
            if (facts.createsSlot24Treasury) revert UnsupportedCtipTransition(0);
            census.coinbaseTxid = facts.txid;
        } else {
            if (facts.isCoinbase) revert MultipleCoinbaseTransactions();
            if (facts.spendsCtip || facts.createsSlot24Treasury) {
                if (!facts.spendsCtip || !facts.createsSlot24Treasury || census.candidateM6Index != 0) {
                    revert UnsupportedCtipTransition(index);
                }
                census.candidateM6Index = index;
                census.candidateM6Txid = facts.txid;
            }
        }

        unchecked {
            ++census.nextTransactionIndex;
        }
        if (census.nextTransactionIndex == census.transactionCount) {
            census.nextTransactionIndex = 0;
            if (census.phase == 1 && census.candidateM6Index != 0) {
                census.phase = 2;
            } else {
                census.phase = 3;
            }
        }
        census.lastProgressBlock = uint64(block.number);
    }

    function _prepareStreamedCensus(
        bytes32 blockHash,
        uint32 transactionCount,
        uint32 index,
        bool successorPass
    ) private returns (bytes32 censusId, StreamedCensus storage census) {
        if (transactionCount == 0) revert InvalidStreamedCensus();
        HeaderNode storage node = _requireNextFinalizable(blockHash);
        censusId = streamedCensusId(blockHash, transactionCount);
        census = _streamedCensuses[censusId];
        if (census.phase == 0) {
            if (index != 0 || successorPass) revert InvalidStreamedCensus();
            census.blockHash = blockHash;
            census.merkleRoot = node.merkleRoot;
            census.ctipTxidSnapshot = ctipTxid;
            census.ctipVoutSnapshot = ctipVout;
            census.transactionCount = transactionCount;
            census.phase = 1;
        } else if (
            census.blockHash != blockHash || census.merkleRoot != node.merkleRoot
                || census.ctipTxidSnapshot != ctipTxid || census.ctipVoutSnapshot != ctipVout
                || census.transactionCount != transactionCount
        ) revert InvalidStreamedCensus();
        if (
            census.phase != (successorPass ? 2 : 1) || index != census.nextTransactionIndex
        ) revert InvalidStreamedCensus();
    }

    /// @notice Reclaims an abandoned or obsolete partial census. The same
    ///         deterministic session can be rebuilt after deletion.
    function expireStreamedCensus(bytes32 censusId) external {
        StreamedCensus storage census = _streamedCensuses[censusId];
        if (census.phase == 0) revert InvalidStreamedCensus();
        HeaderNode storage node = headers[census.blockHash];
        bool obsolete = node.exists && node.height <= finalizedHeight;
        if (!obsolete && block.number <= census.lastProgressBlock + STREAMED_CENSUS_EXPIRY_BLOCKS) {
            revert StreamedCensusNotExpired();
        }
        delete _streamedCensuses[censusId];
    }

    /// @notice Applies one completed root-bound census in a small final call.
    /// @dev Only the coinbase and optional M6 are resupplied; their txids must
    ///      equal the positions authenticated by the complete streaming passes.
    function processStreamedFinalizedBlock(StreamedFinalizedBlockProof calldata proof) external {
        StreamedCensus storage census = _streamedCensuses[proof.censusId];
        if (census.phase != 3) revert InvalidStreamedCensus();
        HeaderNode storage node = _requireNextFinalizable(census.blockHash);
        if (
            census.merkleRoot != node.merkleRoot || census.ctipTxidSnapshot != ctipTxid
                || census.ctipVoutSnapshot != ctipVout
        ) revert InvalidStreamedCensus();

        if (proof.rawCoinbase.length > MAX_STREAMED_TRANSACTION_BYTES) {
            revert InvalidStreamedCensus();
        }
        TransactionFacts memory coinbaseFacts = _transactionFactsForOutpoint(
            proof.rawCoinbase, census.ctipTxidSnapshot, census.ctipVoutSnapshot
        );
        if (!coinbaseFacts.isCoinbase || coinbaseFacts.txid != census.coinbaseTxid) {
            revert InvalidStreamedCensus();
        }
        _processCoinbase(proof.rawCoinbase, node.height);
        _expireBundles(node.height);

        if (census.candidateM6Index == 0) {
            if (proof.rawM6.length != 0) revert InvalidStreamedCensus();
        } else {
            if (proof.rawM6.length > MAX_M6_BYTES) revert M6TooLarge(proof.rawM6.length);
            TransactionFacts memory m6Facts = _transactionFactsForOutpoint(
                proof.rawM6, census.ctipTxidSnapshot, census.ctipVoutSnapshot
            );
            if (
                m6Facts.txid != census.candidateM6Txid || !m6Facts.spendsCtip
                    || !m6Facts.createsSlot24Treasury
            ) revert InvalidStreamedCensus();
            _processM6(census.blockHash, node, proof.rawM6, proof.transition);
        }

        bytes32 blockHash = census.blockHash;
        delete _streamedCensuses[proof.censusId];
        finalizedTip = blockHash;
        finalizedHeight = node.height;
        emit FinalizedBlockProcessed(blockHash, node.height);
    }

    /// @inheritdoc IBip300RedemptionVerifier
    function verify(bytes32 statement, bytes calldata approvalProof) external view override returns (bool) {
        // This candidate can authorize only a valueless Sepolia test vault.
        // Production remains disabled: arbitrary checkpoint provenance,
        // complete ordered M5/M6 replay, and dynamic multi-slot state must be
        // implemented and independently audited in a separate mainnet build.
        if (
            !SEPOLIA_TESTNET_VERIFICATION_ENABLED || DEPLOYMENT_CHAIN_ID != SEPOLIA_CHAIN_ID
                || block.chainid != SEPOLIA_CHAIN_ID
        ) return false;
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

        bytes32 currentContentsHash = sha256(
            abi.encodePacked(
                proof.currentSequence,
                proof.currentClaimCount,
                proof.currentClaimRoot,
                proof.currentM6id,
                proof.currentBitcoinTipHash,
                proof.currentBitcoinHeight,
                proof.currentBitcoinMedianTimePast,
                proof.currentBitcoinChainwork
            )
        );
        bytes32 nextContentsHash = sha256(
            abi.encodePacked(
                proof.nextSequence,
                approval.nextClaimCount,
                approval.nextClaimRoot,
                proof.approvalM6id,
                approval.bitcoinBlockHash,
                approval.bitcoinHeight,
                approval.bitcoinMedianTimePast,
                approval.bitcoinChainwork
            )
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

    function pendingBundleCount() external view returns (uint256) {
        return _pendingBundles.length;
    }

    function pendingBundle(uint256 index) external view returns (PendingBundle memory) {
        return _pendingBundles[index];
    }

    function isAncestorOfBest(bytes32 blockHash) external view returns (bool) {
        HeaderNode storage node = headers[blockHash];
        if (!node.exists || headers[bestTip].height < node.height) return false;
        return _ancestor(bestTip, node.height) == blockHash;
    }

    function _transactionFactsForOutpoint(
        bytes calldata raw,
        bytes32 trackedTxid,
        uint32 trackedVout
    ) private view returns (TransactionFacts memory facts) {
        if (raw.length < 10) revert MalformedBitcoinTransaction();
        uint256 cursor = 4;
        bool segwit;
        if (uint8(raw[cursor]) == 0) {
            if (cursor + 1 >= raw.length || uint8(raw[cursor + 1]) != 1) {
                revert MalformedBitcoinTransaction();
            }
            segwit = true;
            cursor += 2;
        }
        uint256 inputStart = cursor;
        uint256 inputCount;
        (cursor, facts.isCoinbase, facts.spendsCtip, inputCount) =
            _parseTransactionInputs(raw, cursor, trackedTxid, trackedVout);
        (cursor, facts.createsSlot24Treasury) = _parseTransactionOutputs(raw, cursor);
        uint256 outputsEnd = cursor;
        if (segwit) cursor = _parseTransactionWitnesses(raw, cursor, inputCount);
        if (cursor + 4 != raw.length) revert MalformedBitcoinTransaction();
        if (segwit) {
            bytes memory stripped = new bytes(4 + (outputsEnd - inputStart) + 4);
            _copyInto(raw, 0, stripped, 0, 4);
            _copyInto(raw, inputStart, stripped, 4, outputsEnd - inputStart);
            _copyInto(raw, cursor, stripped, 4 + outputsEnd - inputStart, 4);
            facts.txid = _sha256d(stripped);
        } else {
            facts.txid = _sha256d(_copy(raw, 0, raw.length));
        }
    }

    function _parseTransactionInputs(
        bytes calldata raw,
        uint256 cursor,
        bytes32 trackedTxid,
        uint32 trackedVout
    )
        private
        view
        returns (uint256 nextCursor, bool isCoinbase, bool spendsCtip, uint256 inputCount)
    {
        InputScan memory scan;
        (scan.count, scan.cursor) = _compactSize(raw, cursor);
        if (scan.count == 0) revert MalformedBitcoinTransaction();
        for (uint256 i; i < scan.count; ++i) {
            bool nullPrevious;
            bool touchesCtip;
            uint256 scriptLength;
            (scan.cursor, nullPrevious, touchesCtip, scriptLength) =
                _parseTransactionInput(raw, scan.cursor, trackedTxid, trackedVout);
            if (nullPrevious) ++scan.nullInputs;
            scan.spendsCtip = scan.spendsCtip || touchesCtip;
            if (i == 0) scan.coinbaseScriptLength = scriptLength;
        }
        isCoinbase = scan.count == 1 && scan.nullInputs == 1;
        if (
            (!isCoinbase && scan.nullInputs != 0)
                || (isCoinbase && (scan.coinbaseScriptLength < 2 || scan.coinbaseScriptLength > 100))
        ) {
            revert MalformedBitcoinTransaction();
        }
        return (scan.cursor, isCoinbase, scan.spendsCtip, scan.count);
    }

    function _parseTransactionInput(
        bytes calldata raw,
        uint256 cursor,
        bytes32 trackedTxid,
        uint32 trackedVout
    )
        private
        view
        returns (uint256 nextCursor, bool nullPrevious, bool touchesCtip, uint256 scriptLength)
    {
        bytes32 previousTxid = _bytes32At(raw, cursor);
        uint32 previousVout = _le32(raw, cursor + 32);
        nullPrevious = previousTxid == bytes32(0) && previousVout == type(uint32).max;
        touchesCtip = previousTxid == trackedTxid && previousVout == trackedVout;
        cursor += 36;
        uint256 afterScriptLength;
        (scriptLength, afterScriptLength) = _compactSize(raw, cursor);
        cursor = afterScriptLength + scriptLength;
        if (cursor + 4 > raw.length) revert MalformedBitcoinTransaction();
        nextCursor = cursor + 4;
    }

    function _parseTransactionOutputs(bytes calldata raw, uint256 cursor)
        private
        view
        returns (uint256 nextCursor, bool createsSlot24Treasury)
    {
        (uint256 outputCount, uint256 afterOutputCount) = _compactSize(raw, cursor);
        if (outputCount == 0) revert MalformedBitcoinTransaction();
        cursor = afterOutputCount;
        for (uint256 i; i < outputCount; ++i) {
            if (cursor + 8 > raw.length) revert MalformedBitcoinTransaction();
            cursor += 8;
            (uint256 scriptLength, uint256 afterScriptLength) = _compactSize(raw, cursor);
            cursor = afterScriptLength;
            if (cursor + scriptLength > raw.length) revert MalformedBitcoinTransaction();
            if (
                scriptLength == 4 && uint8(raw[cursor]) == 0xb4 && uint8(raw[cursor + 1]) == 0x01
                    && uint8(raw[cursor + 2]) == DRIVECHAIN_SLOT && uint8(raw[cursor + 3]) == 0x51
            ) createsSlot24Treasury = true;
            cursor += scriptLength;
        }
        nextCursor = cursor;
    }

    function _parseTransactionWitnesses(bytes calldata raw, uint256 cursor, uint256 inputCount)
        private
        pure
        returns (uint256 nextCursor)
    {
        bool hasWitness;
        for (uint256 i; i < inputCount; ++i) {
            (uint256 itemCount, uint256 afterItemCount) = _compactSize(raw, cursor);
            cursor = afterItemCount;
            hasWitness = hasWitness || itemCount != 0;
            for (uint256 j; j < itemCount; ++j) {
                (uint256 itemLength, uint256 afterItemLength) = _compactSize(raw, cursor);
                cursor = afterItemLength + itemLength;
                if (cursor > raw.length) revert MalformedBitcoinTransaction();
            }
        }
        if (!hasWitness) revert MalformedBitcoinTransaction();
        nextCursor = cursor;
    }

    /// @dev Verifies one position in Bitcoin's duplicate-last txid tree while
    ///      rejecting the same equal-sibling mutation that Bitcoin Core rejects.
    ///      Requiring a canonical supplied duplicate for an absent odd sibling
    ///      binds the branch to `transactionCount`, rather than merely its depth.
    function _verifyTransactionMembership(
        bytes32 txid,
        uint32 index,
        uint32 transactionCount,
        bytes32[] calldata branch,
        bytes32 expectedRoot
    ) private pure {
        if (transactionCount == 0 || index >= transactionCount) revert InvalidStreamedCensus();
        uint256 width = transactionCount;
        uint256 cursor = index;
        uint256 depth;
        bytes32 node = txid;
        while (width > 1) {
            if (depth >= branch.length) revert InvalidStreamedCensus();
            bytes32 sibling = branch[depth];
            uint256 siblingIndex = cursor ^ 1;
            if (siblingIndex >= width) {
                if (sibling != node) revert InvalidStreamedCensus();
            } else if (sibling == node) {
                revert MutatedTransactionMerkleTree();
            }
            node = cursor & 1 == 0
                ? _sha256d(abi.encodePacked(node, sibling))
                : _sha256d(abi.encodePacked(sibling, node));
            cursor >>= 1;
            width = (width + 1) / 2;
            unchecked {
                ++depth;
            }
        }
        if (depth != branch.length || node != expectedRoot) revert InvalidStreamedCensus();
    }

    function _requireNextFinalizable(bytes32 blockHash)
        private
        view
        returns (HeaderNode storage node)
    {
        node = headers[blockHash];
        uint32 expectedHeight = finalizedHeight + 1;
        if (!node.exists || node.height != expectedHeight || node.parent != finalizedTip) {
            revert BlockNotNextFinalized(expectedHeight, node.height);
        }
        HeaderNode storage best = headers[bestTip];
        if (
            best.height < node.height
                || uint256(best.height) - uint256(node.height) + 1 < uint256(FINALITY_DEPTH)
        ) {
            revert InsufficientFinality(best.height, node.height, FINALITY_DEPTH);
        }
        if (_ancestor(bestTip, node.height) != blockHash) revert BlockNotOnBestBranch(blockHash);
    }

    function _submitHeader(bytes calldata raw, uint256 offset) private {
        bytes memory header = _copy(raw, offset, 80);
        bytes32 blockHash = _sha256d(header);
        if (headers[blockHash].exists) revert DuplicateHeader(blockHash);
        bytes32 parentHash = _bytes32At(raw, offset + 4);
        HeaderNode storage parent = headers[parentHash];
        if (!parent.exists) revert UnknownParent(parentHash);
        if (parent.height < finalizedHeight || _ancestor(parentHash, finalizedHeight) != finalizedTip) {
            revert HeaderBelowFinalizedFork(blockHash);
        }

        bytes32 merkleRoot = _bytes32At(raw, offset + 36);
        uint32 timestamp = _le32(raw, offset + 68);
        uint32 bits = _le32(raw, offset + 72);
        uint32 height = parent.height + 1;
        if (timestamp <= parent.medianTimePast) revert InvalidHeaderTime(timestamp, parent.medianTimePast);
        if (uint256(timestamp) > block.timestamp + MAX_FUTURE_BLOCK_TIME) {
            revert HeaderTooFarInFuture(timestamp, block.timestamp + MAX_FUTURE_BLOCK_TIME);
        }
        uint32 expectedBits = _expectedBits(parent, height);
        if (bits != expectedBits) revert WrongDifficultyBits(expectedBits, bits);
        uint256 target = _compactToTarget(bits);
        if (target == 0 || target > POW_LIMIT || _littleEndianUint(blockHash) > target) {
            revert InvalidProofOfWork(blockHash, target);
        }
        // Bitcoin Core GetBlockProof: (~target / (target + 1)) + 1.
        // Using maxUint as the numerator and then adding one rounds upward for
        // almost every target, overstating cumulative chainwork by one per
        // header and potentially changing fork choice on close competing tips.
        uint256 work = (type(uint256).max - target) / (target + 1) + 1;
        uint256 chainwork = parent.chainwork + work;
        if (chainwork <= parent.chainwork) revert ChainworkOverflow();
        uint32 mtp = _medianTime(parentHash, timestamp);
        uint32 epochStart = height % RETARGET_INTERVAL == 0 ? timestamp : parent.epochStartTime;
        headers[blockHash] = HeaderNode({
            parent: parentHash,
            merkleRoot: merkleRoot,
            chainwork: chainwork,
            height: height,
            timestamp: timestamp,
            medianTimePast: mtp,
            bits: bits,
            epochStartTime: epochStart,
            exists: true
        });
        emit HeaderAccepted(blockHash, parentHash, height, chainwork);

        HeaderNode storage currentBest = headers[bestTip];
        if (chainwork > currentBest.chainwork || (chainwork == currentBest.chainwork && blockHash < bestTip)) {
            bytes32 previous = bestTip;
            bestTip = blockHash;
            emit BestTipChanged(previous, blockHash, height, chainwork);
        }
    }

    function _processCoinbase(bytes calldata raw, uint32 height) private returns (bytes32 txid) {
        if (raw.length < 10) revert MalformedBitcoinTransaction();
        uint256 cursor = 4;
        bool segwit;
        if (uint8(raw[cursor]) == 0 && cursor + 1 < raw.length && uint8(raw[cursor + 1]) != 0) {
            segwit = true;
            cursor += 2;
        }
        uint256 inputStart = cursor;
        cursor = _coinbaseInputEnd(raw, cursor);
        bool sawM4;
        (cursor, sawM4) = _coinbaseOutputsEnd(raw, cursor, height);
        uint256 outputsEnd = cursor;

        if (segwit) cursor = _coinbaseWitnessEnd(raw, cursor);
        if (cursor + 4 != raw.length) revert MalformedBitcoinTransaction();
        uint256 locktimeOffset = cursor;
        bytes memory stripped = new bytes(4 + (outputsEnd - inputStart) + 4);
        _copyInto(raw, 0, stripped, 0, 4);
        _copyInto(raw, inputStart, stripped, 4, outputsEnd - inputStart);
        _copyInto(raw, locktimeOffset, stripped, 4 + outputsEnd - inputStart, 4);
        txid = _sha256d(stripped);
        if (!sawM4) {
            _previousVoteAction = 0;
            _previousUpvoteM6id = bytes32(0);
        }
    }

    function _coinbaseInputEnd(bytes calldata raw, uint256 cursor) private pure returns (uint256) {
        (uint256 inputCount, uint256 next) = _compactSize(raw, cursor);
        if (inputCount != 1) revert MalformedBitcoinTransaction();
        cursor = next;
        if (_bytes32At(raw, cursor) != bytes32(0) || _le32(raw, cursor + 32) != type(uint32).max) {
            revert MalformedBitcoinTransaction();
        }
        cursor += 36;
        (uint256 scriptLength, uint256 afterLength) = _compactSize(raw, cursor);
        cursor = afterLength + scriptLength;
        if (cursor + 4 > raw.length) revert MalformedBitcoinTransaction();
        return cursor + 4;
    }

    function _coinbaseOutputsEnd(bytes calldata raw, uint256 cursor, uint32 height)
        private
        returns (uint256 nextCursor, bool sawM4)
    {
        (uint256 outputCount, uint256 afterCount) = _compactSize(raw, cursor);
        return _parseCoinbaseOutputs(raw, afterCount, outputCount, height);
    }

    function _coinbaseWitnessEnd(bytes calldata raw, uint256 cursor) private pure returns (uint256) {
        (uint256 witnessItems, uint256 next) = _compactSize(raw, cursor);
        cursor = next;
        for (uint256 i; i < witnessItems; ++i) {
            (uint256 itemLength, uint256 afterLength) = _compactSize(raw, cursor);
            cursor = afterLength + itemLength;
            if (cursor > raw.length) revert MalformedBitcoinTransaction();
        }
        return cursor;
    }

    function _parseCoinbaseOutputs(bytes calldata raw, uint256 cursor, uint256 outputCount, uint32 height)
        private
        returns (uint256 nextCursor, bool sawM4)
    {
        for (uint256 i; i < outputCount; ++i) {
            if (cursor + 8 > raw.length) revert MalformedBitcoinTransaction();
            cursor += 8;
            (uint256 scriptLength, uint256 afterLength) = _compactSize(raw, cursor);
            cursor = afterLength;
            if (cursor + scriptLength > raw.length) revert MalformedBitcoinTransaction();
            if (_processCoinbaseScript(raw, cursor, scriptLength, height)) {
                if (sawM4) revert DuplicateM4();
                sawM4 = true;
            }
            cursor += scriptLength;
        }
        nextCursor = cursor;
    }

    /// @return isM4 True only for a valid, fully processed M4 message.
    function _processCoinbaseScript(bytes calldata raw, uint256 start, uint256 length, uint32 height)
        private
        returns (bool isM4)
    {
        (bool ok, uint256 dataStart, uint256 dataLength) = _opReturnData(raw, start, length);
        if (!ok || dataLength < 4) return false;
        bytes4 tag = _bytes4At(raw, dataStart);
        if ((tag == M1_TAG && dataLength >= 5) || (tag == M2_TAG && dataLength == 37)) {
            revert UnsupportedSidechainActivationMessage(tag);
        }
        if (tag == M3_TAG) {
            if (dataLength != 37) return false;
            uint8 slot = uint8(raw[dataStart + 4]);
            if (slot != DRIVECHAIN_SLOT) revert UnsupportedM3Slot(slot);
            bytes32 m6id = _bytes32At(raw, dataStart + 5);
            _propose(m6id, height);
            return false;
        }
        if (tag == M4_TAG) {
            if (dataLength < 5 || !_recognizedM4(raw, dataStart + 4, dataLength - 4)) return false;
            _applyM4(raw, dataStart + 4, dataLength - 4, height);
            return true;
        }
        // A BIP301 bid can buy selection of this opaque M7/h*, but it cannot
        // propose or vote for an M6id and must never create a redemption
        // approval. Only the distinct M3/M4/final-M6 path below can do that.
        if (tag == M7_TAG) return false;
        return false;
    }

    /// @dev Mirrors rust-bitcoin's non-minimal push instruction parsing: syntax
    ///      failures are ordinary coinbase data, while recognized messages with
    ///      the wrong active-slot vector length fail later in `_applyM4`.
    function _recognizedM4(bytes calldata raw, uint256 start, uint256 length) private pure returns (bool) {
        if (length == 0) return false;
        uint8 version = uint8(raw[start]);
        if (version == 0 || version == 3) return length == 1;
        if (version == 1) return true;
        if (version == 2) return (length - 1) % 2 == 0;
        return false;
    }

    function _propose(bytes32 m6id, uint32 height) private {
        if (consumedSlot24M6ids[m6id]) revert ConsumedM6id(m6id);
        for (uint256 i; i < _pendingBundles.length; ++i) {
            if (_pendingBundles[i].m6id == m6id) revert DuplicatePendingM6id(m6id);
        }
        if (_pendingBundles.length >= MAX_PENDING_BUNDLES) {
            revert TooManyPendingBundles(MAX_PENDING_BUNDLES);
        }
        _pendingBundles.push(PendingBundle({m6id: m6id, proposalHeight: height, voteCount: 1}));
        emit BundleProposed(m6id, height);
    }

    function _applyM4(bytes calldata raw, uint256 start, uint256 length, uint32 height) private {
        uint8 version = uint8(raw[start]);
        uint16 vote;
        if (version == 0) {
            if (length != 1) revert InvalidM4();
            _repeatPrevious(height);
            return;
        }
        if (version == 3) {
            if (length != 1) revert InvalidM4();
            _leadingBy50(height);
            return;
        }
        if (version == 1) {
            if (length != 2) revert InvalidM4(); // exactly one active sidechain
            uint8 compactVote = uint8(raw[start + 1]);
            vote = compactVote == 0xff ? type(uint16).max : compactVote == 0xfe ? 0xfffe : compactVote;
        } else if (version == 2) {
            if (length != 3) revert InvalidM4();
            vote = uint16(uint8(raw[start + 1])) | (uint16(uint8(raw[start + 2])) << 8);
            if (vote <= 253) revert InvalidM4();
        } else {
            revert InvalidM4();
        }
        if (vote == type(uint16).max) {
            _previousVoteAction = 0;
            _previousUpvoteM6id = bytes32(0);
        } else if (vote == 0xfffe) {
            _alarm(height);
        } else {
            if (vote >= _pendingBundles.length) revert InvalidM4();
            _upvote(vote, height);
        }
    }

    function _upvote(uint256 index, uint32 height) private {
        PendingBundle storage target = _pendingBundles[index];
        if (target.voteCount == type(uint16).max) {
            _previousVoteAction = 0;
            _previousUpvoteM6id = bytes32(0);
            return;
        }
        ++target.voteCount;
        for (uint256 i; i < _pendingBundles.length; ++i) {
            if (i != index && _pendingBundles[i].voteCount != 0) --_pendingBundles[i].voteCount;
        }
        _previousVoteAction = 1;
        _previousUpvoteM6id = target.m6id;
        emit BundleVoteApplied(target.m6id, target.voteCount, height);
    }

    function _alarm(uint32 height) private {
        bool changed;
        for (uint256 i; i < _pendingBundles.length; ++i) {
            if (_pendingBundles[i].voteCount != 0) {
                --_pendingBundles[i].voteCount;
                changed = true;
                emit BundleVoteApplied(_pendingBundles[i].m6id, _pendingBundles[i].voteCount, height);
            }
        }
        _previousVoteAction = changed ? 2 : 0;
        _previousUpvoteM6id = bytes32(0);
    }

    function _repeatPrevious(uint32 height) private {
        if (_previousVoteAction == 0) return;
        if (_previousVoteAction == 2) {
            _alarm(height);
            return;
        }
        for (uint256 i; i < _pendingBundles.length; ++i) {
            if (_pendingBundles[i].m6id == _previousUpvoteM6id) {
                _upvote(i, height);
                return;
            }
        }
        revert RepeatVoteTargetMissing(_previousUpvoteM6id);
    }

    function _leadingBy50(uint32 height) private {
        if (_pendingBundles.length == 0) {
            _previousVoteAction = 0;
            return;
        }
        uint256 leader;
        uint16 highest;
        uint16 second;
        for (uint256 i; i < _pendingBundles.length; ++i) {
            uint16 votes = _pendingBundles[i].voteCount;
            if (votes > highest) {
                second = highest;
                highest = votes;
                leader = i;
            } else if (votes > second) {
                second = votes;
            }
        }
        if (highest - second >= 50 && highest < type(uint16).max) {
            _upvote(leader, height);
        } else {
            _previousVoteAction = 0;
            _previousUpvoteM6id = bytes32(0);
        }
    }

    function _expireBundles(uint32 height) private {
        uint256 i;
        while (i < _pendingBundles.length) {
            if (height - _pendingBundles[i].proposalHeight > WITHDRAWAL_BUNDLE_MAX_AGE) {
                bytes32 expired = _pendingBundles[i].m6id;
                _removePending(i);
                emit BundleExpired(expired, height);
            } else {
                ++i;
            }
        }
    }

    function _processM6(
        bytes32 blockHash,
        HeaderNode storage node,
        bytes calldata rawM6,
        RootTransition calldata transition
    ) private {
        bytes32 existingM6id = accumulatorM6ByFinalizedBlock[blockHash];
        if (existingM6id != bytes32(0)) {
            revert AccumulatorM6AlreadyProcessed(blockHash, existingM6id);
        }
        ParsedM6 memory parsed = _parseM6(rawM6);
        uint16 voteCount = _pendingVoteCount(parsed.m6id);
        if (voteCount <= WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD) {
            revert M6NotApproved(parsed.m6id, voteCount);
        }
        if (consumedSlot24M6ids[parsed.m6id]) revert ConsumedM6id(parsed.m6id);
        consumedSlot24M6ids[parsed.m6id] = true;
        if (parsed.kind == M6_KIND_NATIVE_WITHDRAWAL) {
            _recordNativeWithdrawal(blockHash, node, parsed);
            return;
        }
        if (parsed.kind != M6_KIND_USDD_ROOT) revert InvalidM6();
        bytes32 displayM6id = _reverseBytes32(parsed.m6id);
        if (approvals[displayM6id].finalized) revert ApprovalAlreadyExists(displayM6id);
        if (
            transition.vaultId == bytes32(0) || transition.nextClaimRoot == bytes32(0)
                || transition.nextClaimCount <= transition.priorClaimCount
        ) revert InvalidRootTransition();
        if (
            (transition.priorClaimCount == 0
                && transition.priorClaimRoot != EMPTY_APPROVED_CLAIM_ROOT)
                || (transition.priorClaimCount != 0 && transition.priorClaimRoot == bytes32(0))
        ) revert InvalidRootTransition();
        bytes32 expectedCommitment = sha256(
            abi.encodePacked(
                M6_ROOT_DOMAIN,
                DRIVECHAIN_SLOT,
                BITCOIN_GENESIS_HASH,
                ELEMENTS_GENESIS_HASH,
                USDD_ASSET_ID,
                transition.vaultId,
                transition.priorClaimCount,
                transition.priorClaimRoot,
                transition.nextClaimCount,
                transition.nextClaimRoot
            )
        );
        if (parsed.rootCommitment != expectedCommitment) revert RootCommitmentMismatch();
        _recordApproval(blockHash, node, parsed, transition);
    }

    function _recordNativeWithdrawal(
        bytes32 blockHash,
        HeaderNode storage node,
        ParsedM6 memory parsed
    ) private {
        ctipTxid = parsed.txid;
        ctipVout = 0;
        ctipValue = parsed.nextCtipValue;
        _removeApprovedBundle(parsed.m6id);
        emit NativeWithdrawalM6Processed(
            _reverseBytes32(parsed.m6id),
            _reverseBytes32(parsed.txid),
            blockHash,
            node.height
        );
    }

    function _recordApproval(
        bytes32 blockHash,
        HeaderNode storage node,
        ParsedM6 memory parsed,
        RootTransition calldata transition
    ) private {
        bytes32 displayM6id = _reverseBytes32(parsed.m6id);
        approvals[displayM6id] = ApprovalRecord({
            vaultId: transition.vaultId,
            priorClaimRoot: transition.priorClaimRoot,
            nextClaimRoot: transition.nextClaimRoot,
            bitcoinBlockHash: _reverseBytes32(blockHash),
            bitcoinChainwork: node.chainwork,
            priorClaimCount: transition.priorClaimCount,
            nextClaimCount: transition.nextClaimCount,
            bitcoinHeight: node.height,
            bitcoinMedianTimePast: node.medianTimePast,
            finalized: true
        });
        accumulatorM6ByFinalizedBlock[blockHash] = displayM6id;
        ctipTxid = parsed.txid;
        ctipVout = 0;
        ctipValue = parsed.nextCtipValue;
        _removeApprovedBundle(parsed.m6id);
        emit RedemptionRootApproved(
            displayM6id,
            transition.vaultId,
            transition.nextClaimRoot,
            transition.nextClaimCount,
            blockHash,
            node.height
        );
    }

    function _parseM6(bytes calldata raw) private view returns (ParsedM6 memory parsed) {
        if (address(TRANSACTION_STREAM).codehash != TRANSACTION_STREAM_CODEHASH) {
            revert TransactionStreamCodeChanged();
        }
        (
            parsed.txid,
            parsed.m6id,
            parsed.rootCommitment,
            parsed.nextCtipValue,
            parsed.kind
        ) = TRANSACTION_STREAM.parseSlot24M6(
            raw,
            ctipTxid,
            ctipVout,
            ctipValue,
            ELEMENTS_GENESIS_HASH
        );
    }

    function _removeApprovedBundle(bytes32 m6id) private {
        for (uint256 i; i < _pendingBundles.length; ++i) {
            if (_pendingBundles[i].m6id == m6id) {
                _removePending(i);
                return;
            }
        }
        revert InvalidM6();
    }

    function _removePending(uint256 index) private {
        for (uint256 i = index; i + 1 < _pendingBundles.length; ++i) {
            _pendingBundles[i] = _pendingBundles[i + 1];
        }
        _pendingBundles.pop();
    }

    function _pendingVoteCount(bytes32 m6id) private view returns (uint16) {
        for (uint256 i; i < _pendingBundles.length; ++i) {
            if (_pendingBundles[i].m6id == m6id) return _pendingBundles[i].voteCount;
        }
        return 0;
    }

    function _expectedBits(HeaderNode storage parent, uint32 nextHeight) private view returns (uint32) {
        if (nextHeight % RETARGET_INTERVAL != 0) return parent.bits;
        uint256 oldTarget = _compactToTarget(parent.bits);
        uint256 elapsed = parent.timestamp > parent.epochStartTime ? parent.timestamp - parent.epochStartTime : 0;
        uint256 minimum = TARGET_TIMESPAN / 4;
        uint256 maximum = uint256(TARGET_TIMESPAN) * 4;
        if (elapsed < minimum) elapsed = minimum;
        if (elapsed > maximum) elapsed = maximum;
        uint256 nextTarget = _mulDiv(oldTarget, elapsed, TARGET_TIMESPAN);
        if (nextTarget > POW_LIMIT) nextTarget = POW_LIMIT;
        return _targetToCompact(nextTarget);
    }

    function _medianTime(bytes32 parentHash, uint32 timestamp) private view returns (uint32) {
        uint32[11] memory values;
        values[0] = timestamp;
        uint256 count = 1;
        bytes32 cursor = parentHash;
        while (count < 11 && cursor != bytes32(0)) {
            HeaderNode storage node = headers[cursor];
            values[count++] = node.timestamp;
            if (cursor == CHECKPOINT_BLOCK_HASH) {
                uint256 checkpointIndex = 1;
                while (count < MTP_WINDOW) {
                    values[count++] = checkpointMtpTimestampsNewestFirst[checkpointIndex++];
                }
                cursor = bytes32(0);
            } else {
                cursor = node.parent;
            }
        }
        return _median(values, count);
    }

    function _checkpointMedian(uint32[11] memory checkpointTimestamps) private pure returns (uint32) {
        uint32[11] memory values;
        for (uint256 i; i < MTP_WINDOW; ++i) values[i] = checkpointTimestamps[i];
        return _median(values, MTP_WINDOW);
    }

    function _median(uint32[11] memory values, uint256 count) private pure returns (uint32) {
        for (uint256 i = 1; i < count; ++i) {
            uint32 value = values[i];
            uint256 j = i;
            while (j != 0 && values[j - 1] > value) {
                values[j] = values[j - 1];
                --j;
            }
            values[j] = value;
        }
        return values[count / 2];
    }

    function _ancestor(bytes32 tip, uint32 height) private view returns (bytes32 cursor) {
        cursor = tip;
        HeaderNode storage node = headers[cursor];
        if (!node.exists || height > node.height) return bytes32(0);
        while (node.height > height) {
            cursor = node.parent;
            node = headers[cursor];
        }
    }

    function _opReturnData(bytes calldata raw, uint256 start, uint256 length)
        private
        pure
        returns (bool ok, uint256 dataStart, uint256 dataLength)
    {
        if (length < 2 || uint8(raw[start]) != 0x6a) return (false, 0, 0);
        uint8 opcode = uint8(raw[start + 1]);
        uint256 prefix = 2;
        if (opcode <= 75) {
            dataLength = opcode;
        } else if (opcode == 0x4c && length >= 3) {
            dataLength = uint8(raw[start + 2]);
            prefix = 3;
        } else if (opcode == 0x4d && length >= 4) {
            dataLength = uint16(uint8(raw[start + 2])) | (uint16(uint8(raw[start + 3])) << 8);
            prefix = 4;
        } else if (opcode == 0x4e && length >= 6) {
            dataLength = _le32(raw, start + 2);
            prefix = 6;
        } else {
            return (false, 0, 0);
        }
        if (prefix + dataLength != length) return (false, 0, 0);
        return (true, start + prefix, dataLength);
    }

    function _compactSize(bytes calldata raw, uint256 offset) private pure returns (uint256 value, uint256 next) {
        if (offset >= raw.length) revert MalformedBitcoinTransaction();
        uint8 first = uint8(raw[offset]);
        if (first < 0xfd) return (first, offset + 1);
        if (first == 0xfd) {
            if (offset + 3 > raw.length) revert MalformedBitcoinTransaction();
            value = uint16(uint8(raw[offset + 1])) | (uint16(uint8(raw[offset + 2])) << 8);
            if (value < 0xfd) revert NonCanonicalCompactSize();
            return (value, offset + 3);
        }
        if (first == 0xfe) {
            if (offset + 5 > raw.length) revert MalformedBitcoinTransaction();
            value = _le32(raw, offset + 1);
            if (value <= type(uint16).max) revert NonCanonicalCompactSize();
            return (value, offset + 5);
        }
        revert MalformedBitcoinTransaction(); // uint64 lengths exceed every V1 bound
    }

    function _compactToTarget(uint32 bits) private pure returns (uint256 target) {
        uint32 exponent = bits >> 24;
        uint32 mantissa = bits & 0x007fffff;
        if (mantissa == 0 || (bits & 0x00800000) != 0 || exponent > 32) return 0;
        if (exponent <= 3) target = uint256(mantissa) >> (8 * (3 - exponent));
        else target = uint256(mantissa) << (8 * (exponent - 3));
    }

    function _targetToCompact(uint256 target) private pure returns (uint32 compact) {
        if (target == 0) return 0;
        uint256 size;
        uint256 cursor = target;
        while (cursor != 0) {
            ++size;
            cursor >>= 8;
        }
        uint256 mantissa = size <= 3 ? target << (8 * (3 - size)) : target >> (8 * (size - 3));
        if ((mantissa & 0x00800000) != 0) {
            mantissa >>= 8;
            ++size;
        }
        compact = uint32((size << 24) | (mantissa & 0x007fffff));
    }

    function _mulDiv(uint256 x, uint256 y, uint256 denominator) private pure returns (uint256 result) {
        unchecked {
            uint256 prod0 = x * y;
            uint256 prod1;
            assembly ("memory-safe") {
                let mm := mulmod(x, y, not(0))
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }
            if (prod1 == 0) return prod0 / denominator;
            if (denominator <= prod1) revert InvalidConfiguration();
            uint256 remainder;
            assembly ("memory-safe") {
                remainder := mulmod(x, y, denominator)
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }
            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                denominator := div(denominator, twos)
                prod0 := div(prod0, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }
            prod0 |= prod1 * twos;
            uint256 inverse = (3 * denominator) ^ 2;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            result = prod0 * inverse;
        }
    }

    function _sha256d(bytes memory data) private pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(data)));
    }

    function _littleEndianUint(bytes32 value) private pure returns (uint256 result) {
        for (uint256 i; i < 32; ++i) result |= uint256(uint8(value[i])) << (8 * i);
    }

    function _reverseBytes32(bytes32 value) private pure returns (bytes32 reversed) {
        for (uint256 i; i < 32; ++i) {
            reversed |= bytes32(uint256(uint8(value[i])) << (i * 8));
        }
    }

    function _copy(bytes calldata source, uint256 start, uint256 length) private pure returns (bytes memory out) {
        if (start + length > source.length) revert MalformedBitcoinTransaction();
        out = new bytes(length);
        _copyInto(source, start, out, 0, length);
    }

    function _copyInto(bytes calldata source, uint256 sourceStart, bytes memory target, uint256 targetStart, uint256 length)
        private
        pure
    {
        if (sourceStart + length > source.length || targetStart + length > target.length) {
            revert MalformedBitcoinTransaction();
        }
        for (uint256 i; i < length; ++i) target[targetStart + i] = source[sourceStart + i];
    }

    function _bytes32At(bytes calldata raw, uint256 offset) private pure returns (bytes32 value) {
        if (offset + 32 > raw.length) revert MalformedBitcoinTransaction();
        for (uint256 i; i < 32; ++i) value |= bytes32(uint256(uint8(raw[offset + i])) << (248 - i * 8));
    }

    function _bytes6At(bytes calldata raw, uint256 offset) private pure returns (bytes6 value) {
        if (offset + 6 > raw.length) revert MalformedBitcoinTransaction();
        for (uint256 i; i < 6; ++i) {
            value |= bytes6(uint48(uint256(uint8(raw[offset + i])) << (40 - i * 8)));
        }
    }

    function _bytes4At(bytes calldata raw, uint256 offset) private pure returns (bytes4 value) {
        if (offset + 4 > raw.length) revert MalformedBitcoinTransaction();
        for (uint256 i; i < 4; ++i) {
            value |= bytes4(uint32(uint256(uint8(raw[offset + i])) << (24 - i * 8)));
        }
    }

    function _le32(bytes calldata raw, uint256 offset) private pure returns (uint32 value) {
        if (offset + 4 > raw.length) revert MalformedBitcoinTransaction();
        value = uint32(uint8(raw[offset])) | (uint32(uint8(raw[offset + 1])) << 8)
            | (uint32(uint8(raw[offset + 2])) << 16) | (uint32(uint8(raw[offset + 3])) << 24);
    }

    function _le64(bytes calldata raw, uint256 offset) private pure returns (uint64 value) {
        if (offset + 8 > raw.length) revert MalformedBitcoinTransaction();
        for (uint256 i; i < 8; ++i) {
            value |= uint64(uint256(uint8(raw[offset + i])) << (8 * i));
        }
    }
}
