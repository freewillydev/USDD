// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Immutable-code verification boundary for Bitcoin/BIP300-approved USDD redemptions.
/// @dev The implementation may maintain consensus-derived Bitcoin/BIP300 relay
///      state, but must be ownerless, permissionlessly advanceable, and have no
///      proxy or mutable configuration. `verifierProgramId` identifies the exact
///      verification program and storage-transition schema.
///      `verifierConfigHash` must commit every other consensus parameter, including
///      the Bitcoin network and bootstrap checkpoint, Drivechain slot, BIP300/M6
///      rules, bundle codec, proof system, verification keys or transparent
///      parameters, and public-input schema. The verifier must prove that the
///      statement's M6id was approved on the demonstrated Bitcoin chain and that
///      the M6 commits exactly to the prior/next accumulator count and root. It
///      does not assert full Elements block validity, burn validity, or the
///      correctness of the accumulator transition. Under USDD V1's explicitly
///      selected BIP300 miner-governed custody model, the finalized M6 is the
///      payout authorization boundary. A raw BIP301 M7 must never satisfy this
///      interface.
interface IBip300RedemptionVerifier {
    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function verify(bytes32 statement, bytes calldata approvalProof) external view returns (bool);
}
