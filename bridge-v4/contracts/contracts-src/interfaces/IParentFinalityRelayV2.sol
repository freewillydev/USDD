// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IParentFinalityRelayV2
/// @notice Immutable membership boundary for finalized canonical parent-chain
///         checkpoints used by ControllerAcceptanceRelayV2.
/// @dev A production implementation must retain membership for still-canonical
///      finalized ancestors. Returning true must authenticate the exact
///      (hash, height, MTP, chainwork) tuple under the pinned best-chain and
///      finality policy. A latest-tip-only API is insufficient because it makes
///      valid in-flight controller proofs griefable when the parent relay moves.
///      `blockHash` is always the conventional RPC/display-order Bitcoin hash.
///      An adapter for a source keyed by raw SHA256d/wire-order bytes must
///      convert exactly once at its private source boundary.
///
/// @custom:security-status BLOCKED
/// No existing USDD Bitcoin relay is implicitly a production implementation of
/// this interface. `BitcoinParentFinalityRelayV2` is an explicit testnet-only
/// adapter for the pinned V1 greatest-work header source. A production eCash
/// source identity, checkpoint audit, deployment and independent review remain
/// V11 launch gates.
interface IParentFinalityRelayV2 {
    function parentChainIdentity() external view returns (bytes32);

    function finalityConfigHash() external view returns (bytes32);

    function currentFinalizedHeight() external view returns (uint64);

    function isFinalizedCanonical(
        bytes32 blockHash,
        uint64 blockHeight,
        uint64 medianTimePast,
        uint256 chainwork
    ) external view returns (bool);
}
