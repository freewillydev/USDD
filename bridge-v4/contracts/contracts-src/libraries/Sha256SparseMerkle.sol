// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Canonical SHA-256 membership for a 64-level approved-redemption tree.
/// @dev Leaves are addressed by their uint64 append index. Branch entries are
///      supplied bottom-up, so branch entry `level` is selected by index bit
///      `level`; this is equivalent to traversing index bits MSB-first from root.
library Sha256SparseMerkle {
    uint256 internal constant TREE_DEPTH = 64;

    function hashLeaf(
        bytes32 leafDomain,
        uint32 protocolVersion,
        bytes32 vaultId,
        bytes32 elementsGenesisHash,
        bytes32 usddAssetId,
        bytes32 redemptionId,
        uint64 claimIndex,
        uint64 amount,
        address recipient
    ) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                bytes1(0x00),
                leafDomain,
                protocolVersion,
                elementsGenesisHash,
                usddAssetId,
                vaultId,
                redemptionId,
                claimIndex,
                amount,
                recipient
            )
        );
    }

    function hashNode(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function computeRoot(bytes32 leaf, uint64 index, bytes32[64] calldata merkleBranch)
        internal
        pure
        returns (bytes32 node)
    {
        node = leaf;
        for (uint256 level; level < TREE_DEPTH; ++level) {
            bytes32 sibling = merkleBranch[level];
            if (((uint256(index) >> level) & 1) == 0) {
                node = hashNode(node, sibling);
            } else {
                node = hashNode(sibling, node);
            }
        }
    }

    function verify(bytes32 root, bytes32 leaf, uint64 index, bytes32[64] calldata merkleBranch)
        internal
        pure
        returns (bool)
    {
        return computeRoot(leaf, index, merkleBranch) == root;
    }
}
