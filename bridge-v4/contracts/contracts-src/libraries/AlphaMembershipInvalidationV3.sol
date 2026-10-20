// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Height-indexed invalidation history, not a proof verifier.
/// @dev Call invalidateAbove only after authenticating the reorg and matching
/// its accepted cursor to stored state. Register membership at the current
/// epoch only after verifying its proof against the current Alpha journal.
/// A registration survives iff its epoch >= lastInvalidation(height).
/// Canonical membership and current minimum depth must be checked separately.
library AlphaMembershipInvalidationV3 {
    struct History {
        uint256 epoch;
        mapping(uint64 => uint256) invalidated;
    }

    // Sparse binary range tree over all uint32 heights. A suffix update and
    // a point query each visit at most 33 levels, independent of history size.
    function invalidateAbove(History storage h, uint32 sharedHeight) internal {
        uint256 next = ++h.epoch;
        uint64 left = (uint64(1) << 32) + uint64(sharedHeight) + 1;
        uint64 right = uint64(1) << 33;
        while (left < right) {
            if (left & 1 != 0) h.invalidated[left++] = next;
            if (right & 1 != 0) h.invalidated[--right] = next;
            left >>= 1;
            right >>= 1;
        }
    }

    function lastInvalidation(History storage h, uint32 height) internal view returns (uint256 latest) {
        for (uint64 node = (uint64(1) << 32) + uint64(height); node != 0; node >>= 1) {
            uint256 recorded = h.invalidated[node];
            if (recorded > latest) latest = recorded;
        }
    }
}
