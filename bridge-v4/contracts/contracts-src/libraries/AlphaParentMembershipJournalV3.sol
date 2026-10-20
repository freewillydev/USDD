// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Codec only. Decoding is NOT proof verification or chain selection.
/// @dev A relay must verify the SP1 receipt and pin the complete Alpha binding,
/// then authenticate the terminal state/frontier against its accepted chain.
library AlphaParentMembershipJournalV3 {
    uint256 internal constant LENGTH = 606;
    struct Journal {
        bytes32 alphaProfile;
        bytes32 sourceConfiguration;
        bytes32 checkpointInput;
        bytes32 checkpointProgram;
        bytes32 transitionProgram;
        bytes32 terminalState;
        bytes32 terminalFrontier;
        uint32 terminalHeight;
        uint128 terminalSequence;
        bytes32 terminalHashInternal;
        uint64 terminalMtp;
        uint256 terminalWork;
        uint32 minimumDescendants;
        bytes32 ancestorHashDisplay;
        uint32 ancestorHeight;
        uint32 ancestorMtp;
        uint256 ancestorWork;
        bytes32 completeAlphaJournalSha256;
    }
    error InvalidJournal();
    function le(bytes calldata data, uint256 offset, uint256 size) private pure returns (uint256 n) {
        for (uint256 i; i < size; ++i) n |= uint256(uint8(data[offset+i])) << (8*i);
    }
    function decode(bytes calldata data) internal pure returns (Journal memory j) {
        if (data.length != LENGTH || uint8(data[0]) != 0xc3 || uint8(data[1]) != 0xa3)
            revert InvalidJournal();
        j.alphaProfile = bytes32(data[2:34]);
        j.sourceConfiguration = bytes32(data[34:66]);
        j.checkpointInput = bytes32(data[66:98]);
        j.checkpointProgram = bytes32(data[98:130]);
        j.transitionProgram = bytes32(data[130:162]);
        j.terminalState = bytes32(data[310:342]);
        j.terminalFrontier = bytes32(data[374:406]);
        j.terminalHeight = uint32(le(data,438,4));
        j.terminalSequence = uint128(le(data,442,16));
        j.terminalHashInternal = bytes32(data[458:490]);
        j.terminalMtp = uint64(le(data,490,8));
        j.terminalWork = uint256(bytes32(data[498:530]));
        j.minimumDescendants = uint32(bytes4(data[530:534]));
        j.ancestorHashDisplay = bytes32(data[534:566]);
        j.ancestorHeight = uint32(bytes4(data[566:570]));
        j.ancestorMtp = uint32(bytes4(data[570:574]));
        j.ancestorWork = uint256(bytes32(data[574:606]));
        j.completeAlphaJournalSha256 = sha256(data[1:530]);
        if (j.minimumDescendants == 0 || j.ancestorHeight > j.terminalHeight
            || j.terminalHeight - j.ancestorHeight < j.minimumDescendants)
            revert InvalidJournal();
    }
}
