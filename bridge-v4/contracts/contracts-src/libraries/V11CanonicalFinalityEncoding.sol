// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICanonicalParentFinalityReceiptV11} from
    "../interfaces/ICanonicalParentFinalityReceiptV11.sol";

/// @title V11CanonicalFinalityEncoding
/// @notice Byte-exact SHA-256 codecs shared with the Rust V11 replay model.
/// @dev `abi.encodePacked` is intentional: Rust canonical integers are
///      fixed-width big-endian (`uint32`, `uint64`, `uint256`) and hashes are
///      exactly 32 bytes. `abi.encode` padding is incompatible.
library V11CanonicalFinalityEncoding {
    bytes internal constant SUBJECT_DOMAIN = "USDD_V11_CANONICAL_FINALITY_SUBJECT";
    bytes internal constant RECEIPT_DOMAIN = "USDD_V11_CANONICAL_FINALITY_RECEIPT";

    struct SubjectFields {
        bytes32 profileCommitment;
        bytes32 controllerDeploymentCommitment;
        bytes32 allSlotJournalCommitment;
        ICanonicalParentFinalityReceiptV11.Cursor prior;
        ICanonicalParentFinalityReceiptV11.Checkpoint candidate;
        bytes32 certificateCommitment;
        bytes32 approvedM6id;
        bytes32 inclusionBlockHash;
        uint32 inclusionHeight;
    }

    function subject(SubjectFields memory fields) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                SUBJECT_DOMAIN,
                fields.profileCommitment,
                fields.controllerDeploymentCommitment,
                fields.allSlotJournalCommitment,
                fields.prior.receiptId,
                fields.prior.receiptEpoch,
                encodeCheckpoint(fields.prior.checkpoint),
                encodeCheckpoint(fields.candidate),
                fields.certificateCommitment,
                fields.approvedM6id,
                fields.inclusionBlockHash,
                fields.inclusionHeight
            )
        );
    }

    function receiptId(
        bytes32 subjectHash,
        uint64 receiptEpoch,
        ICanonicalParentFinalityReceiptV11.Checkpoint memory observedFinalizedHead
    ) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                RECEIPT_DOMAIN,
                subjectHash,
                receiptEpoch,
                encodeCheckpoint(observedFinalizedHead)
            )
        );
    }

    function encodeCheckpoint(
        ICanonicalParentFinalityReceiptV11.Checkpoint memory checkpoint
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            checkpoint.blockHashDisplay,
            checkpoint.blockHeight,
            checkpoint.medianTimePast,
            checkpoint.cumulativeChainwork
        );
    }
}
