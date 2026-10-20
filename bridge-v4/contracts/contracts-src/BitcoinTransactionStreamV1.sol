// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISha256CompressionV1 {
    function compress(bytes32 state, bytes calldata blockBytes) external view returns (bytes32);
}

/// @title BitcoinTransactionStreamV1
/// @notice Ownerless byte-within-transaction authenticator for Bitcoin txids and
///         the exact CTIP/treasury facts consumed by the USDD relay.
/// @dev Callers choose a chunking, commit it with a SHA-256 Merkle root, and then
///      permissionlessly supply the unique next chunk. The completed SHA-256d
///      must equal the txid already position-bound under the parent block root.
///      Chunking is therefore a transport detail and grants no authority.
contract BitcoinTransactionStreamV1 {
    uint8 public constant DRIVECHAIN_SLOT = 24;
    uint32 public constant MAX_CHUNK_BYTES = 1_024;
    uint64 public constant MAX_STRIPPED_TRANSACTION_BYTES = 4_000_000;
    uint64 public constant SESSION_EXPIRY_BLOCKS = 50_400;

    bytes32 public constant PROGRAM_ID = sha256("USDD_BITCOIN_TRANSACTION_STREAM_V1");
    bytes32 private constant SESSION_DOMAIN = sha256("USDD_BITCOIN_TRANSACTION_STREAM_SESSION_V1");
    bytes32 private constant FACT_DOMAIN = sha256("USDD_BITCOIN_TRANSACTION_STREAM_FACT_V1");
    bytes32 private constant CHUNK_LEAF_DOMAIN = sha256("USDD_BITCOIN_TRANSACTION_CHUNK_V1");
    bytes32 private constant SHA256_INITIAL_STATE =
        0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
    bytes6 private constant ROOT_MAGIC = 0x555344444d36; // ASCII "USDDM6"
    bytes4 private constant NATIVE_WITHDRAWAL_MAGIC = 0x454c5744; // ASCII "ELWD"
    uint8 private constant M6_KIND_USDD_ROOT = 1;
    uint8 private constant M6_KIND_NATIVE_WITHDRAWAL = 2;

    ISha256CompressionV1 public immutable COMPRESSOR;
    bytes32 public immutable COMPRESSOR_CODEHASH;
    bytes32 public immutable CONFIG_HASH;

    // Parser stages. Chunks are semantic tokens, except script bodies which may
    // be split into any number of nonempty chunks no larger than MAX_CHUNK_BYTES.
    uint8 private constant ST_VERSION = 1;
    uint8 private constant ST_INPUT_COUNT = 2;
    uint8 private constant ST_INPUT_OUTPOINT = 3;
    uint8 private constant ST_INPUT_SCRIPT_LENGTH = 4;
    uint8 private constant ST_INPUT_SCRIPT = 5;
    uint8 private constant ST_INPUT_SEQUENCE = 6;
    uint8 private constant ST_OUTPUT_COUNT = 7;
    uint8 private constant ST_OUTPUT_VALUE = 8;
    uint8 private constant ST_OUTPUT_SCRIPT_LENGTH = 9;
    uint8 private constant ST_OUTPUT_SCRIPT = 10;
    uint8 private constant ST_LOCKTIME = 11;
    uint8 private constant ST_COMPLETE = 12;

    struct BeginRequest {
        bytes32 expectedTxid;
        bytes32 transactionMerkleRoot;
        bytes32 chunkRoot;
        bytes32 trackedTxid;
        uint32 trackedVout;
        uint32 transactionIndex;
        uint32 transactionCount;
        uint32 chunkCount;
        uint64 totalLength;
    }

    struct Session {
        bytes32 expectedTxid;
        bytes32 transactionMerkleRoot;
        bytes32 chunkRoot;
        bytes32 trackedTxid;
        bytes32 shaState;
        bytes tail;
        uint64 totalLength;
        uint64 receivedLength;
        uint64 remainingItems;
        uint64 scriptRemaining;
        uint64 currentScriptLength;
        uint64 inputCount;
        uint64 nullInputCount;
        uint64 firstInputScriptLength;
        uint64 lastProgressBlock;
        uint32 trackedVout;
        uint32 transactionIndex;
        uint32 transactionCount;
        uint32 chunkCount;
        uint32 nextChunkIndex;
        uint8 stage;
        bool spendsTrackedOutpoint;
        bool createsSlotTreasury;
    }

    struct CompletedFacts {
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

    struct M6Layout {
        uint256 secondOutputStart;
        uint256 locktimeOffset;
        bytes32 rootCommitment;
        uint64 nextCtipValue;
        uint64 payoutTotal;
        uint8 outputCount;
        uint8 kind;
    }

    mapping(bytes32 sessionId => Session session) private _sessions;
    mapping(bytes32 sessionId => CompletedFacts facts) public completedFacts;

    error InvalidConfiguration();
    error InvalidSession();
    error InvalidChunk();
    error InvalidParserToken();
    error InvalidTransaction();
    error CompressorCodeChanged();
    error SessionNotExpired();

    event SessionStarted(bytes32 indexed sessionId, bytes32 indexed expectedTxid, bytes32 chunkRoot);
    event SessionAdvanced(bytes32 indexed sessionId, uint32 nextChunkIndex, uint64 receivedLength);
    event TransactionAuthenticated(
        bytes32 indexed factId,
        bytes32 indexed txid,
        uint32 transactionIndex,
        bool isCoinbase,
        bool spendsTrackedOutpoint,
        bool createsSlotTreasury
    );

    constructor(address compressor) {
        if (compressor == address(0) || compressor.code.length == 0) revert InvalidConfiguration();
        COMPRESSOR = ISha256CompressionV1(compressor);
        COMPRESSOR_CODEHASH = compressor.codehash;
        CONFIG_HASH = sha256(
            abi.encode(
                PROGRAM_ID,
                block.chainid,
                compressor,
                compressor.codehash,
                DRIVECHAIN_SLOT,
                MAX_CHUNK_BYTES,
                MAX_STRIPPED_TRANSACTION_BYTES,
                SESSION_EXPIRY_BLOCKS
            )
        );
    }

    function sessionId(BeginRequest calldata request) public view returns (bytes32) {
        return sha256(abi.encode(SESSION_DOMAIN, CONFIG_HASH, request));
    }

    function factId(BeginRequest calldata request) public view returns (bytes32) {
        return sha256(
            abi.encode(
                FACT_DOMAIN,
                CONFIG_HASH,
                request.expectedTxid,
                request.transactionMerkleRoot,
                request.trackedTxid,
                request.trackedVout,
                request.transactionIndex,
                request.transactionCount
            )
        );
    }

    /// @notice Parses the two exact slot-24 M6 subtypes accepted by the relay.
    /// @dev Kind 1 is the canonical USDD root transition. Kind 2 is the exact
    ///      three-output native Elements `ELWD` payout. This function reconstructs
    ///      the blinded legacy transaction byte-for-byte and returns its wire-order
    ///      SHA256d M6id; it does not apply miner voting state.
    function parseSlot24M6(
        bytes calldata raw,
        bytes32 currentCtipTxid,
        uint32 currentCtipVout,
        uint64 currentCtipValue,
        bytes32 elementsGenesisHashDisplay
    ) external pure returns (
        bytes32 txid,
        bytes32 m6id,
        bytes32 rootCommitment,
        uint64 nextCtipValue,
        uint8 kind
    ) {
        if (raw.length < 60 || elementsGenesisHashDisplay == bytes32(0)) {
            revert InvalidTransaction();
        }
        txid = _sha256d(_copyRaw(raw, 0, raw.length));
        uint256 outputsStart = _m6InputEnd(raw, currentCtipTxid, currentCtipVout);
        M6Layout memory layout =
            _m6Outputs(raw, outputsStart, elementsGenesisHashDisplay);
        if (
            layout.nextCtipValue > currentCtipValue
                || layout.payoutTotal > currentCtipValue - layout.nextCtipValue
        ) revert InvalidTransaction();
        uint64 fee = currentCtipValue - layout.nextCtipValue - layout.payoutTotal;
        m6id = _blindedM6id(
            raw,
            layout.secondOutputStart,
            layout.locktimeOffset,
            layout.outputCount,
            fee
        );

        // Both Elements builders fix every actual-transaction field that the
        // generic BIP300 blinding operation removes. Accepting an alternate
        // scriptSig or sequence under the same approved M6id would make the
        // typed codecs noncanonical even though the blinded identity matched.
        if (
            _le32(raw, 0) != 2 || outputsStart != 46 || uint8(raw[41]) != 0
                || _le32(raw, 42) != type(uint32).max
                || _le32(raw, layout.locktimeOffset) != 0
        ) revert InvalidTransaction();
        return (
            txid,
            m6id,
            layout.rootCommitment,
            layout.nextCtipValue,
            layout.kind
        );
    }

    function begin(BeginRequest calldata request, bytes32[] calldata transactionMerkleBranch)
        external
        returns (bytes32 id)
    {
        if (
            request.expectedTxid == bytes32(0) || request.transactionMerkleRoot == bytes32(0)
                || request.chunkRoot == bytes32(0) || request.transactionCount == 0
                || request.transactionIndex >= request.transactionCount || request.chunkCount == 0
                || request.totalLength < 10 || request.totalLength > MAX_STRIPPED_TRANSACTION_BYTES
                || request.chunkCount > request.totalLength
        ) revert InvalidConfiguration();
        _verifyMerkle(
            request.expectedTxid,
            request.transactionIndex,
            request.transactionCount,
            transactionMerkleBranch,
            request.transactionMerkleRoot
        );
        id = sessionId(request);
        if (_sessions[id].stage != 0 || completedFacts[factId(request)].complete) revert InvalidSession();
        Session storage stream = _sessions[id];
        stream.expectedTxid = request.expectedTxid;
        stream.transactionMerkleRoot = request.transactionMerkleRoot;
        stream.chunkRoot = request.chunkRoot;
        stream.trackedTxid = request.trackedTxid;
        stream.shaState = SHA256_INITIAL_STATE;
        stream.totalLength = request.totalLength;
        stream.lastProgressBlock = uint64(block.number);
        stream.trackedVout = request.trackedVout;
        stream.transactionIndex = request.transactionIndex;
        stream.transactionCount = request.transactionCount;
        stream.chunkCount = request.chunkCount;
        stream.stage = ST_VERSION;
        emit SessionStarted(id, request.expectedTxid, request.chunkRoot);
    }

    function append(bytes32 id, bytes calldata chunk, bytes32[] calldata chunkMerkleBranch) external {
        Session storage stream = _sessions[id];
        if (stream.stage == 0 || stream.stage == ST_COMPLETE) revert InvalidSession();
        if (chunk.length == 0 || chunk.length > MAX_CHUNK_BYTES) revert InvalidChunk();
        if (
            stream.nextChunkIndex >= stream.chunkCount
                || stream.receivedLength + chunk.length > stream.totalLength
        ) revert InvalidChunk();
        bytes32 leaf = sha256(
            abi.encodePacked(
                CHUNK_LEAF_DOMAIN,
                stream.nextChunkIndex,
                uint32(chunk.length),
                sha256(chunk)
            )
        );
        _verifyMerkle(
            leaf,
            stream.nextChunkIndex,
            stream.chunkCount,
            chunkMerkleBranch,
            stream.chunkRoot
        );
        _appendHash(stream, chunk);
        _parseToken(stream, chunk);
        stream.receivedLength += uint64(chunk.length);
        unchecked {
            ++stream.nextChunkIndex;
        }
        stream.lastProgressBlock = uint64(block.number);

        if (stream.nextChunkIndex == stream.chunkCount) _finish(id, stream);
        else emit SessionAdvanced(id, stream.nextChunkIndex, stream.receivedLength);
    }

    /// @notice Deletes an abandoned partial session after a fixed, immutable
    ///         delay. Completed facts are intentionally permanent and tiny.
    function expire(bytes32 id) external {
        Session storage stream = _sessions[id];
        if (stream.stage == 0) revert InvalidSession();
        if (block.number <= stream.lastProgressBlock + SESSION_EXPIRY_BLOCKS) {
            revert SessionNotExpired();
        }
        delete _sessions[id];
    }

    function expireCompleted(bytes32 id) external {
        CompletedFacts storage facts = completedFacts[id];
        if (!facts.complete) revert InvalidSession();
        if (block.number <= facts.completedBlock + SESSION_EXPIRY_BLOCKS) revert SessionNotExpired();
        delete completedFacts[id];
    }

    function sessionProgress(bytes32 id)
        external
        view
        returns (uint32 nextChunkIndex, uint32 chunkCount, uint64 receivedLength, uint8 stage)
    {
        Session storage stream = _sessions[id];
        return (stream.nextChunkIndex, stream.chunkCount, stream.receivedLength, stream.stage);
    }

    function _finish(bytes32 id, Session storage stream) private {
        if (
            stream.receivedLength != stream.totalLength || stream.stage != ST_COMPLETE
                || stream.tail.length >= 64
        ) revert InvalidTransaction();
        bool isCoinbase = stream.inputCount == 1 && stream.nullInputCount == 1;
        if (
            (!isCoinbase && stream.nullInputCount != 0)
                || (isCoinbase
                    && (stream.firstInputScriptLength < 2 || stream.firstInputScriptLength > 100))
        ) revert InvalidTransaction();

        bytes32 digest = _finalizeHash(stream);
        bytes32 txid = sha256(abi.encodePacked(digest));
        if (txid != stream.expectedTxid) revert InvalidTransaction();
        bytes32 completedId = sha256(
            abi.encode(
                FACT_DOMAIN,
                CONFIG_HASH,
                txid,
                stream.transactionMerkleRoot,
                stream.trackedTxid,
                stream.trackedVout,
                stream.transactionIndex,
                stream.transactionCount
            )
        );
        CompletedFacts memory facts = CompletedFacts({
            txid: txid,
            transactionMerkleRoot: stream.transactionMerkleRoot,
            trackedTxid: stream.trackedTxid,
            trackedVout: stream.trackedVout,
            transactionIndex: stream.transactionIndex,
            transactionCount: stream.transactionCount,
            isCoinbase: isCoinbase,
            spendsTrackedOutpoint: stream.spendsTrackedOutpoint,
            createsSlotTreasury: stream.createsSlotTreasury,
            complete: true,
            completedBlock: uint64(block.number)
        });
        delete _sessions[id];
        completedFacts[completedId] = facts;
        emit TransactionAuthenticated(
            completedId,
            txid,
            facts.transactionIndex,
            isCoinbase,
            facts.spendsTrackedOutpoint,
            facts.createsSlotTreasury
        );
    }

    function _appendHash(Session storage stream, bytes calldata chunk) private {
        _requireCompressor();
        bytes memory combined = bytes.concat(stream.tail, chunk);
        uint256 fullLength = combined.length - (combined.length % 64);
        bytes32 state = stream.shaState;
        for (uint256 cursor; cursor < fullLength; cursor += 64) {
            bytes memory blockBytes = new bytes(64);
            for (uint256 i; i < 64; ++i) blockBytes[i] = combined[cursor + i];
            state = COMPRESSOR.compress(state, blockBytes);
        }
        bytes memory tail = new bytes(combined.length - fullLength);
        for (uint256 i; i < tail.length; ++i) tail[i] = combined[fullLength + i];
        stream.shaState = state;
        stream.tail = tail;
    }

    function _finalizeHash(Session storage stream) private view returns (bytes32 state) {
        _requireCompressor();
        bytes memory tail = stream.tail;
        uint256 paddedLength = tail.length < 56 ? 64 : 128;
        bytes memory padded = new bytes(paddedLength);
        for (uint256 i; i < tail.length; ++i) padded[i] = tail[i];
        padded[tail.length] = 0x80;
        uint64 bitLength = stream.totalLength * 8;
        for (uint256 i; i < 8; ++i) {
            padded[paddedLength - 1 - i] = bytes1(uint8(bitLength >> (8 * i)));
        }
        state = stream.shaState;
        for (uint256 cursor; cursor < paddedLength; cursor += 64) {
            bytes memory blockBytes = new bytes(64);
            for (uint256 i; i < 64; ++i) blockBytes[i] = padded[cursor + i];
            state = COMPRESSOR.compress(state, blockBytes);
        }
    }

    function _m6InputEnd(bytes calldata raw, bytes32 ctipTxid, uint32 ctipVout)
        private
        pure
        returns (uint256 cursor)
    {
        cursor = 4;
        if (uint8(raw[cursor]) == 0) revert InvalidTransaction();
        (uint256 inputCount, uint256 next) = _compactSizeRaw(raw, cursor);
        if (inputCount != 1) revert InvalidTransaction();
        cursor = next;
        if (_bytes32At(raw, cursor) != ctipTxid || _le32(raw, cursor + 32) != ctipVout) {
            revert InvalidTransaction();
        }
        cursor += 36;
        (uint256 scriptLength, uint256 afterLength) = _compactSizeRaw(raw, cursor);
        cursor = afterLength + scriptLength;
        if (cursor + 4 > raw.length) revert InvalidTransaction();
        return cursor + 4;
    }

    function _m6Outputs(bytes calldata raw, uint256 cursor, bytes32 elementsGenesisHashDisplay)
        private
        pure
        returns (M6Layout memory layout)
    {
        (uint256 outputCount, uint256 next) = _compactSizeRaw(raw, cursor);
        if (outputCount != 2 && outputCount != 3) revert InvalidTransaction();
        layout.outputCount = uint8(outputCount);
        cursor = next;
        layout.nextCtipValue = _le64(raw, cursor);
        cursor += 8;
        (uint256 firstScriptLength, uint256 afterLength) = _compactSizeRaw(raw, cursor);
        cursor = afterLength;
        if (
            firstScriptLength != 4 || cursor + 4 > raw.length || uint8(raw[cursor]) != 0xb4
                || uint8(raw[cursor + 1]) != 0x01 || uint8(raw[cursor + 2]) != DRIVECHAIN_SLOT
                || uint8(raw[cursor + 3]) != 0x51
        ) revert InvalidTransaction();
        cursor += 4;

        layout.secondOutputStart = cursor;
        if (outputCount == 2) cursor = _rootPayoutEnd(raw, cursor, layout);
        else cursor = _nativePayoutsEnd(raw, cursor, elementsGenesisHashDisplay, layout);
        if (cursor + 4 != raw.length) revert InvalidTransaction();
        layout.locktimeOffset = cursor;
    }

    function _rootPayoutEnd(bytes calldata raw, uint256 cursor, M6Layout memory layout)
        private
        pure
        returns (uint256)
    {
        if (_le64(raw, cursor) != 1) revert InvalidTransaction();
        cursor += 8;
        (uint256 scriptLength, uint256 afterLength) = _compactSizeRaw(raw, cursor);
        cursor = afterLength;
        if (
            scriptLength != 41 || cursor + 41 > raw.length || uint8(raw[cursor]) != 0x6a
                || uint8(raw[cursor + 1]) != 0x27
                || _bytes6At(raw, cursor + 2) != ROOT_MAGIC || uint8(raw[cursor + 8]) != 1
        ) revert InvalidTransaction();
        layout.rootCommitment = _bytes32At(raw, cursor + 9);
        layout.payoutTotal = 1;
        layout.kind = M6_KIND_USDD_ROOT;
        return cursor + 41;
    }

    function _nativePayoutsEnd(
        bytes calldata raw,
        uint256 cursor,
        bytes32 elementsGenesisHashDisplay,
        M6Layout memory layout
    ) private pure returns (uint256) {
        if (_le64(raw, cursor) != 0) revert InvalidTransaction();
        cursor += 8;
        (uint256 referenceLength, uint256 afterReferenceLength) = _compactSizeRaw(raw, cursor);
        cursor = afterReferenceLength;
        if (
            referenceLength != 76 || cursor + 76 > raw.length
                || uint8(raw[cursor]) != 0x6a || uint8(raw[cursor + 1]) != 0x4a
                || _bytes4At(raw, cursor + 2) != NATIVE_WITHDRAWAL_MAGIC
                || uint8(raw[cursor + 6]) != 1
                || _bytes32At(raw, cursor + 7) != _reverseBytes32(elementsGenesisHashDisplay)
                || uint8(raw[cursor + 39]) != DRIVECHAIN_SLOT
                || _bytes32At(raw, cursor + 40) == bytes32(0)
                || _bytes4At(raw, cursor + 72) == bytes4(type(uint32).max)
        ) revert InvalidTransaction();
        cursor += 76;

        uint64 payout = _le64(raw, cursor);
        if (payout == 0 || payout > 2_100_000_000_000_000) revert InvalidTransaction();
        cursor += 8;
        (uint256 destinationLength, uint256 afterDestinationLength) = _compactSizeRaw(raw, cursor);
        cursor = afterDestinationLength;
        if (destinationLength == 0 || destinationLength > 128 || cursor + destinationLength > raw.length) {
            revert InvalidTransaction();
        }
        if (
            destinationLength == 4 && uint8(raw[cursor]) == 0xb4
                && uint8(raw[cursor + 1]) == 0x01
                && uint8(raw[cursor + 2]) == DRIVECHAIN_SLOT
                && uint8(raw[cursor + 3]) == 0x51
        ) revert InvalidTransaction();
        layout.payoutTotal = payout;
        layout.kind = M6_KIND_NATIVE_WITHDRAWAL;
        return cursor + destinationLength;
    }

    function _blindedM6id(
        bytes calldata raw,
        uint256 secondOutputStart,
        uint256 locktimeOffset,
        uint8 outputCount,
        uint64 fee
    ) private pure returns (bytes32) {
        bytes memory blinded = new bytes(29 + locktimeOffset - secondOutputStart);
        uint256 out;
        _copyIntoRaw(raw, 0, blinded, out, 4);
        out = 4;
        blinded[out++] = 0x00;
        blinded[out++] = bytes1(outputCount);
        out += 8;
        blinded[out++] = 0x0a;
        blinded[out++] = 0x6a;
        blinded[out++] = 0x08;
        for (uint256 i; i < 8; ++i) blinded[out++] = bytes1(uint8(fee >> (56 - i * 8)));
        uint256 suffixLength = locktimeOffset - secondOutputStart;
        _copyIntoRaw(raw, secondOutputStart, blinded, out, suffixLength);
        out += suffixLength;
        _copyIntoRaw(raw, locktimeOffset, blinded, out, 4);
        return _sha256d(blinded);
    }

    function _compactSizeRaw(bytes calldata raw, uint256 offset)
        private
        pure
        returns (uint256 value, uint256 next)
    {
        if (offset >= raw.length) revert InvalidTransaction();
        uint8 first = uint8(raw[offset]);
        if (first < 0xfd) return (first, offset + 1);
        if (first == 0xfd) {
            if (offset + 3 > raw.length) revert InvalidTransaction();
            value = uint16(uint8(raw[offset + 1])) | (uint16(uint8(raw[offset + 2])) << 8);
            if (value < 0xfd) revert InvalidTransaction();
            return (value, offset + 3);
        }
        if (first == 0xfe) {
            if (offset + 5 > raw.length) revert InvalidTransaction();
            value = _le32(raw, offset + 1);
            if (value <= type(uint16).max) revert InvalidTransaction();
            return (value, offset + 5);
        }
        revert InvalidTransaction();
    }

    function _copyRaw(bytes calldata source, uint256 start, uint256 length)
        private
        pure
        returns (bytes memory out)
    {
        if (start + length > source.length) revert InvalidTransaction();
        out = new bytes(length);
        _copyIntoRaw(source, start, out, 0, length);
    }

    function _copyIntoRaw(
        bytes calldata source,
        uint256 sourceStart,
        bytes memory target,
        uint256 targetStart,
        uint256 length
    ) private pure {
        if (sourceStart + length > source.length || targetStart + length > target.length) {
            revert InvalidTransaction();
        }
        assembly ("memory-safe") {
            calldatacopy(add(add(target, 32), targetStart), add(source.offset, sourceStart), length)
        }
    }

    function _reverseBytes32(bytes32 value) private pure returns (bytes32 reversed) {
        for (uint256 i; i < 32; ++i) {
            reversed |= bytes32(uint256(uint8(value[i])) << (i * 8));
        }
    }

    function _parseToken(Session storage stream, bytes calldata token) private {
        uint8 stage = stream.stage;
        if (stage == ST_VERSION) {
            if (token.length != 4) revert InvalidParserToken();
            stream.stage = ST_INPUT_COUNT;
        } else if (stage == ST_INPUT_COUNT) {
            uint64 count = _compactSizeToken(token);
            if (count == 0 || count > stream.totalLength) revert InvalidParserToken();
            stream.inputCount = count;
            stream.remainingItems = count;
            stream.stage = ST_INPUT_OUTPOINT;
        } else if (stage == ST_INPUT_OUTPOINT) {
            if (token.length != 36) revert InvalidParserToken();
            bytes32 previousTxid = _bytes32At(token, 0);
            uint32 previousVout = _le32(token, 32);
            if (previousTxid == bytes32(0) && previousVout == type(uint32).max) {
                ++stream.nullInputCount;
            } else if (previousTxid == stream.trackedTxid && previousVout == stream.trackedVout) {
                stream.spendsTrackedOutpoint = true;
            }
            stream.stage = ST_INPUT_SCRIPT_LENGTH;
        } else if (stage == ST_INPUT_SCRIPT_LENGTH) {
            uint64 length = _compactSizeToken(token);
            if (length > stream.totalLength) revert InvalidParserToken();
            if (stream.remainingItems == stream.inputCount) stream.firstInputScriptLength = length;
            stream.scriptRemaining = length;
            stream.stage = length == 0 ? ST_INPUT_SEQUENCE : ST_INPUT_SCRIPT;
        } else if (stage == ST_INPUT_SCRIPT) {
            _consumeScript(stream, token, false);
        } else if (stage == ST_INPUT_SEQUENCE) {
            if (token.length != 4 || stream.remainingItems == 0) revert InvalidParserToken();
            --stream.remainingItems;
            stream.stage = stream.remainingItems == 0 ? ST_OUTPUT_COUNT : ST_INPUT_OUTPOINT;
        } else if (stage == ST_OUTPUT_COUNT) {
            uint64 count = _compactSizeToken(token);
            if (count == 0 || count > stream.totalLength) revert InvalidParserToken();
            stream.remainingItems = count;
            stream.stage = ST_OUTPUT_VALUE;
        } else if (stage == ST_OUTPUT_VALUE) {
            if (token.length != 8) revert InvalidParserToken();
            stream.stage = ST_OUTPUT_SCRIPT_LENGTH;
        } else if (stage == ST_OUTPUT_SCRIPT_LENGTH) {
            uint64 length = _compactSizeToken(token);
            if (length > stream.totalLength) revert InvalidParserToken();
            stream.currentScriptLength = length;
            stream.scriptRemaining = length;
            if (length == 0) _finishOutput(stream);
            else stream.stage = ST_OUTPUT_SCRIPT;
        } else if (stage == ST_OUTPUT_SCRIPT) {
            _consumeScript(stream, token, true);
        } else if (stage == ST_LOCKTIME) {
            if (token.length != 4) revert InvalidParserToken();
            stream.stage = ST_COMPLETE;
        } else {
            revert InvalidParserToken();
        }
    }

    function _consumeScript(Session storage stream, bytes calldata token, bool output) private {
        if (token.length == 0 || token.length > stream.scriptRemaining) revert InvalidParserToken();
        if (output && stream.currentScriptLength == 4) {
            // Require the four-byte treasury candidate in one token. Callers
            // control chunking, so this loses no liveness and avoids ambiguity.
            if (token.length != 4) revert InvalidParserToken();
            if (
                uint8(token[0]) == 0xb4 && uint8(token[1]) == 0x01
                    && uint8(token[2]) == DRIVECHAIN_SLOT && uint8(token[3]) == 0x51
            ) stream.createsSlotTreasury = true;
        }
        stream.scriptRemaining -= uint64(token.length);
        if (stream.scriptRemaining != 0) return;
        if (output) _finishOutput(stream);
        else stream.stage = ST_INPUT_SEQUENCE;
    }

    function _finishOutput(Session storage stream) private {
        if (stream.remainingItems == 0) revert InvalidParserToken();
        --stream.remainingItems;
        stream.stage = stream.remainingItems == 0 ? ST_LOCKTIME : ST_OUTPUT_VALUE;
    }

    function _compactSizeToken(bytes calldata token) private pure returns (uint64 value) {
        if (token.length == 1) {
            value = uint8(token[0]);
            if (value >= 0xfd) revert InvalidParserToken();
            return value;
        }
        uint8 prefix = uint8(token[0]);
        if (token.length == 3 && prefix == 0xfd) {
            value = uint16(uint8(token[1])) | (uint16(uint8(token[2])) << 8);
            if (value < 0xfd) revert InvalidParserToken();
            return value;
        }
        if (token.length == 5 && prefix == 0xfe) {
            value = _le32(token, 1);
            if (value <= type(uint16).max) revert InvalidParserToken();
            return value;
        }
        if (token.length == 9 && prefix == 0xff) {
            value = _le64(token, 1);
            if (value <= type(uint32).max) revert InvalidParserToken();
            return value;
        }
        revert InvalidParserToken();
    }

    function _verifyMerkle(
        bytes32 leaf,
        uint32 index,
        uint32 count,
        bytes32[] calldata branch,
        bytes32 expectedRoot
    ) private pure {
        if (count == 0 || index >= count) revert InvalidChunk();
        uint256 width = count;
        uint256 cursor = index;
        uint256 depth;
        bytes32 node = leaf;
        while (width > 1) {
            if (depth >= branch.length) revert InvalidChunk();
            bytes32 sibling = branch[depth];
            uint256 siblingIndex = cursor ^ 1;
            if (siblingIndex >= width) {
                if (sibling != node) revert InvalidChunk();
            } else if (sibling == node) {
                revert InvalidChunk();
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
        if (depth != branch.length || node != expectedRoot) revert InvalidChunk();
    }

    function _requireCompressor() private view {
        if (address(COMPRESSOR).codehash != COMPRESSOR_CODEHASH) revert CompressorCodeChanged();
    }

    function _bytes32At(bytes calldata value, uint256 offset) private pure returns (bytes32 result) {
        if (offset + 32 > value.length) revert InvalidParserToken();
        assembly ("memory-safe") {
            result := calldataload(add(value.offset, offset))
        }
    }

    function _bytes6At(bytes calldata value, uint256 offset) private pure returns (bytes6 result) {
        if (offset + 6 > value.length) revert InvalidTransaction();
        assembly ("memory-safe") {
            result := calldataload(add(value.offset, offset))
        }
    }

    function _bytes4At(bytes calldata value, uint256 offset) private pure returns (bytes4 result) {
        if (offset + 4 > value.length) revert InvalidTransaction();
        assembly ("memory-safe") {
            result := calldataload(add(value.offset, offset))
        }
    }

    function _le32(bytes calldata value, uint256 offset) private pure returns (uint32) {
        if (offset + 4 > value.length) revert InvalidParserToken();
        return uint32(uint8(value[offset])) | (uint32(uint8(value[offset + 1])) << 8)
            | (uint32(uint8(value[offset + 2])) << 16) | (uint32(uint8(value[offset + 3])) << 24);
    }

    function _le64(bytes calldata value, uint256 offset) private pure returns (uint64 result) {
        if (offset + 8 > value.length) revert InvalidParserToken();
        for (uint256 i; i < 8; ++i) result |= uint64(uint8(value[offset + i])) << (8 * i);
    }

    function _sha256d(bytes memory value) private pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(value)));
    }
}
