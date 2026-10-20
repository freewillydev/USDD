// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICanonicalParentFinalityReceiptV11} from
    "../interfaces/ICanonicalParentFinalityReceiptV11.sol";
import {V11MinerControllerEncoding} from "./V11MinerControllerEncoding.sol";

/// @title V11ParentObservationEncoding
/// @notice Exact parent-range projection of a proof-verified V11 all-slot
///         journal.
/// @dev The all-slot guest emits one canonical journal with either no
///      finalized controller certificate (271 bytes) or one certificate
///      (449 bytes). The finality source consumes both forms so a permissionless
///      observer can disclose a competing parent branch even when that branch
///      contains no USDD controller certificate.
library V11ParentObservationEncoding {
    uint64 internal constant MAX_SUCCESSFUL_SLOT24_M6IDS = 1 << 18;
    uint256 internal constant NO_EVENT_JOURNAL_ENCODED_LENGTH = 271;
    uint256 internal constant EVENT_PRESENT_JOURNAL_ENCODED_LENGTH = 449;

    bytes8 internal constant JOURNAL_MAGIC = bytes8("ECAJNL11");
    uint16 internal constant JOURNAL_SCHEMA = 1;
    bytes internal constant JOURNAL_DOMAIN =
        "USDD_ECASH_ALL_SLOT_JOURNAL_V11";

    struct Observation {
        bytes32 profileCommitment;
        bytes32 sourceCheckpointCommitment;
        bytes32 nextCheckpointCommitment;
        ICanonicalParentFinalityReceiptV11.Checkpoint sourceParentCheckpoint;
        ICanonicalParentFinalityReceiptV11.Checkpoint nextParentCheckpoint;
        uint32 blockCount;
        uint64 sourceSuccessfulSlot24M6idCount;
        uint64 nextSuccessfulSlot24M6idCount;
        bool containsControllerCertificate;
    }

    error InvalidObservation();
    error NoncanonicalObservationLength(uint256 actual);

    function decode(bytes calldata encoded)
        internal
        pure
        returns (Observation memory observation)
    {
        bool eventPresent;
        if (encoded.length == NO_EVENT_JOURNAL_ENCODED_LENGTH) {
            if (_u8(encoded, 270) != 0) revert InvalidObservation();
        } else if (encoded.length == EVENT_PRESENT_JOURNAL_ENCODED_LENGTH) {
            if (_u8(encoded, 270) != 1) revert InvalidObservation();
            // Reuse the complete controller-event validator rather than
            // accepting a valid prefix with a malformed event suffix.
            V11MinerControllerEncoding.decodeJournal(encoded);
            eventPresent = true;
        } else {
            revert NoncanonicalObservationLength(encoded.length);
        }

        if (
            bytes8(_load(encoded, 0)) != JOURNAL_MAGIC
                || _u16(encoded, 8) != JOURNAL_SCHEMA
        ) revert InvalidObservation();

        observation.profileCommitment = _load(encoded, 10);
        observation.sourceCheckpointCommitment = _load(encoded, 42);
        observation.nextCheckpointCommitment = _load(encoded, 74);
        observation.sourceParentCheckpoint = _checkpoint(encoded, 106);
        observation.nextParentCheckpoint = _checkpoint(encoded, 178);
        observation.blockCount = _u32(encoded, 250);
        observation.sourceSuccessfulSlot24M6idCount = _u64(encoded, 254);
        observation.nextSuccessfulSlot24M6idCount = _u64(encoded, 262);
        observation.containsControllerCertificate = eventPresent;

        ICanonicalParentFinalityReceiptV11.Checkpoint memory source =
            observation.sourceParentCheckpoint;
        ICanonicalParentFinalityReceiptV11.Checkpoint memory next =
            observation.nextParentCheckpoint;
        if (
            observation.profileCommitment == bytes32(0)
                || observation.sourceCheckpointCommitment == bytes32(0)
                || observation.nextCheckpointCommitment == bytes32(0)
                || observation.sourceCheckpointCommitment
                    == observation.nextCheckpointCommitment
                || !_validCheckpoint(source) || !_validCheckpoint(next)
                || observation.blockCount == 0
                || uint256(source.blockHeight) + observation.blockCount
                    != next.blockHeight
                || next.cumulativeChainwork <= source.cumulativeChainwork
                || next.medianTimePast < source.medianTimePast
                || observation.nextSuccessfulSlot24M6idCount
                    < observation.sourceSuccessfulSlot24M6idCount
                || observation.nextSuccessfulSlot24M6idCount
                    > MAX_SUCCESSFUL_SLOT24_M6IDS
        ) revert InvalidObservation();
    }

    function hashes(bytes calldata encoded)
        internal
        pure
        returns (bytes32 publicValuesHash, bytes32 journalCommitment)
    {
        // Decode first so an opaque verifier success cannot make a
        // noncanonical journal usable by the source.
        decode(encoded);
        publicValuesHash = sha256(encoded);
        journalCommitment =
            sha256(abi.encodePacked(JOURNAL_DOMAIN, encoded));
    }

    function _checkpoint(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (ICanonicalParentFinalityReceiptV11.Checkpoint memory checkpoint)
    {
        checkpoint = ICanonicalParentFinalityReceiptV11.Checkpoint({
            blockHashDisplay: _load(encoded, offset),
            blockHeight: _u32(encoded, offset + 32),
            medianTimePast: _u32(encoded, offset + 36),
            cumulativeChainwork: uint256(_load(encoded, offset + 40))
        });
    }

    function _validCheckpoint(
        ICanonicalParentFinalityReceiptV11.Checkpoint memory checkpoint
    ) private pure returns (bool) {
        return checkpoint.blockHashDisplay != bytes32(0)
            && checkpoint.medianTimePast != 0
            && checkpoint.cumulativeChainwork != 0;
    }

    function _load(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (bytes32 value)
    {
        assembly ("memory-safe") {
            value := calldataload(add(encoded.offset, offset))
        }
    }

    function _u8(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint8)
    {
        return uint8(bytes1(encoded[offset]));
    }

    function _u16(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint16 value)
    {
        value = uint16(uint8(encoded[offset])) << 8;
        value |= uint16(uint8(encoded[offset + 1]));
    }

    function _u32(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint32 value)
    {
        value = uint32(uint8(encoded[offset])) << 24;
        value |= uint32(uint8(encoded[offset + 1])) << 16;
        value |= uint32(uint8(encoded[offset + 2])) << 8;
        value |= uint32(uint8(encoded[offset + 3]));
    }

    function _u64(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint64 value)
    {
        for (uint256 i; i < 8; ++i) {
            value = (value << 8) | uint64(uint8(encoded[offset + i]));
        }
    }
}
