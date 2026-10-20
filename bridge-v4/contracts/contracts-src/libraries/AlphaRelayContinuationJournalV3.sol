// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Codec only: callers must authenticate the receipt and pinned binding,
/// and compare acceptedCursor with stored state before accepting successorCursor.
library AlphaRelayContinuationJournalV3 {
    struct Journal {
        bytes32 acceptedCursor;
        bytes32 successorCursor;
        bytes32 alphaProfile;
        bytes32 sourceConfiguration;
        bytes32 checkpointInput;
        bytes32 checkpointProgram;
        bytes32 transitionProgram;
        bytes32 completeAlphaJournalSha256;
    }
    error InvalidJournal();
    struct ReorgJournal {
        Journal continuation;
        uint32 sharedHeight;
        bytes32 sharedHashInternal;
    }
    function le(bytes calldata data, uint256 offset, uint256 size) private pure returns (uint256 n) {
        for (uint256 i; i < size; ++i) n |= uint256(uint8(data[offset+i])) << (8*i);
    }
    function tagged(bytes32 tag, bytes memory payload) private pure returns (bytes32) {
        return sha256(abi.encodePacked(tag, tag, payload));
    }
    function decode(bytes calldata data) internal pure returns (Journal memory j) {
        if (data.length != 594 || uint8(data[0]) != 0xc4 || uint8(data[65]) != 0xa3)
            revert InvalidJournal();
        return decodeBody(data);
    }
    function decodeReorg(bytes calldata data) internal pure returns (ReorgJournal memory r) {
        if (data.length != 630 || uint8(data[0]) != 0xc5 || uint8(data[65]) != 0xa3)
            revert InvalidJournal();
        r.continuation = decodeBody(data);
        r.sharedHeight = uint32(bytes4(data[594:598]));
        r.sharedHashInternal = bytes32(data[598:630]);
        if (r.sharedHashInternal == bytes32(0) || r.sharedHeight > le(data,502,4))
            revert InvalidJournal();
    }
    function decodeBody(bytes calldata data) private pure returns (Journal memory j) {
        j.acceptedCursor = bytes32(data[1:33]);
        j.successorCursor = bytes32(data[33:65]);
        j.alphaProfile = bytes32(data[66:98]);
        j.sourceConfiguration = bytes32(data[98:130]);
        j.checkpointInput = bytes32(data[130:162]);
        j.checkpointProgram = bytes32(data[162:194]);
        j.transitionProgram = bytes32(data[194:226]);
        j.completeAlphaJournalSha256 = sha256(data[65:594]);
        if (j.acceptedCursor == bytes32(0) || j.successorCursor == bytes32(0)
            || j.acceptedCursor == j.successorCursor) revert InvalidJournal();
        // Match Rust's tagged commitment exactly, including its big-endian
        // cursor integers (the embedded Alpha journal uses little-endian).
        bytes32 binding = tagged(sha256("ECX/full-alpha-recursive-binding/v3"), data[65:226]);
        bytes32 successor = tagged(sha256("ECX/alpha-relay-cursor/v3"), abi.encodePacked(
            bytes1(0xc4), binding, data[374:406], data[438:470], data[470:502],
            uint32(le(data,502,4)), uint128(le(data,506,16))));
        if (successor != j.successorCursor) revert InvalidJournal();
    }
}
