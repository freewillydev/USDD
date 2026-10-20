// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title V11AuthenticatedConsumption
/// @notice Byte-exact depth-256 sparse-set primitive for V11 exactly-once
///         controller-certificate consumption.
/// @dev Sibling zero is adjacent to the leaf and sibling 255 is adjacent to
///      the root. Level zero consumes the least-significant key bit. Every
///      hash uses SHA-256 and the same fixed-width encoding as the Rust model.
library V11AuthenticatedConsumption {
    uint16 internal constant SCHEMA = 1;
    uint256 internal constant DEPTH = 256;

    uint8 internal constant CERTIFICATE_COMMITMENT_NAMESPACE = 1;
    uint8 internal constant CERTIFICATE_M6ID_NAMESPACE = 2;
    uint8 internal constant FINALITY_RECEIPT_NAMESPACE = 3;

    bytes internal constant STATE_DOMAIN = "USDD_V11_CONSUMPTION_SET_STATE";
    bytes internal constant KEY_DOMAIN = "USDD_V11_CONSUMPTION_SET_KEY";
    bytes internal constant EMPTY_LEAF_DOMAIN =
        "USDD_V11_CONSUMPTION_SET_EMPTY_LEAF";
    bytes internal constant OCCUPIED_LEAF_DOMAIN =
        "USDD_V11_CONSUMPTION_SET_OCCUPIED_LEAF";
    bytes internal constant NODE_DOMAIN = "USDD_V11_CONSUMPTION_SET_NODE";

    struct State {
        bytes32 root;
        uint64[3] counts;
    }

    error InvalidNamespace();
    error ZeroIdentifier();
    error InvalidProof();
    error CountOverflow();

    function empty() internal pure returns (State memory state) {
        state.root = emptyRoot();
    }

    function emptyRoot() internal pure returns (bytes32 root) {
        root = emptyLeaf();
        for (uint16 level; level < DEPTH; ++level) {
            root = nodeHash(level, root, root);
        }
    }

    function namespacedKey(uint8 namespace, bytes32 identifier)
        internal
        pure
        returns (bytes32)
    {
        _validateNamespace(namespace);
        if (identifier == bytes32(0)) revert ZeroIdentifier();
        return sha256(abi.encodePacked(KEY_DOMAIN, namespace, identifier));
    }

    function verifyAbsent(
        State memory state,
        uint8 namespace,
        bytes32 identifier,
        bytes32[256] memory siblings
    ) internal pure returns (bool) {
        bytes32 key = namespacedKey(namespace, identifier);
        return deriveRoot(key, emptyLeaf(), siblings) == state.root;
    }

    function verifyPresent(
        State memory state,
        uint8 namespace,
        bytes32 identifier,
        bytes32[256] memory siblings
    ) internal pure returns (bool) {
        bytes32 key = namespacedKey(namespace, identifier);
        return deriveRoot(key, occupiedLeaf(key), siblings) == state.root;
    }

    function insertAbsent(
        State memory state,
        uint8 namespace,
        bytes32 identifier,
        bytes32[256] memory siblings
    ) internal pure returns (State memory next) {
        bytes32 key = namespacedKey(namespace, identifier);
        if (deriveRoot(key, emptyLeaf(), siblings) != state.root) {
            revert InvalidProof();
        }
        uint256 countIndex = uint256(namespace) - 1;
        if (state.counts[countIndex] == type(uint64).max) {
            revert CountOverflow();
        }
        // Solidity memory structs are reference-like. `next = state` aliases
        // the same allocation and would mutate the source checkpoint while
        // constructing the successor. Copy every authenticated field so the
        // source/intermediate commitments remain immutable on success and
        // reusable after a reverted integration attempt.
        next.root = state.root;
        next.counts[0] = state.counts[0];
        next.counts[1] = state.counts[1];
        next.counts[2] = state.counts[2];
        next.root = deriveRoot(key, occupiedLeaf(key), siblings);
        next.counts[countIndex] += 1;
    }

    function stateCommitment(State memory state)
        internal
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encodePacked(
                STATE_DOMAIN,
                SCHEMA,
                state.root,
                state.counts[0],
                state.counts[1],
                state.counts[2]
            )
        );
    }

    function deriveRoot(
        bytes32 key,
        bytes32 leaf,
        bytes32[256] memory siblings
    ) internal pure returns (bytes32 root) {
        root = leaf;
        uint256 keyBits = uint256(key);
        for (uint16 level; level < DEPTH; ++level) {
            bytes32 sibling = siblings[level];
            if (((keyBits >> level) & 1) == 0) {
                root = nodeHash(level, root, sibling);
            } else {
                root = nodeHash(level, sibling, root);
            }
        }
    }

    function emptyLeaf() internal pure returns (bytes32) {
        return sha256(EMPTY_LEAF_DOMAIN);
    }

    function occupiedLeaf(bytes32 key) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(OCCUPIED_LEAF_DOMAIN, key));
    }

    function nodeHash(uint16 level, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(NODE_DOMAIN, level, left, right));
    }

    function _validateNamespace(uint8 namespace) private pure {
        if (
            namespace < CERTIFICATE_COMMITMENT_NAMESPACE
                || namespace > FINALITY_RECEIPT_NAMESPACE
        ) {
            revert InvalidNamespace();
        }
    }
}
