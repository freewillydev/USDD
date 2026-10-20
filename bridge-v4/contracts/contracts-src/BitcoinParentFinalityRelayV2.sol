// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IParentFinalityRelayV2} from "./interfaces/IParentFinalityRelayV2.sol";

/// @dev Exact read-only surface exposed by the immutable Bitcoin/BIP300 header
///      relay used by the V11 testnet candidate.
interface IBitcoinHeaderFinalitySourceV1 {
    function DEPLOYMENT_CHAIN_ID() external view returns (uint256);

    function BITCOIN_GENESIS_HASH() external view returns (bytes32);

    function FINALITY_DEPTH() external view returns (uint32);

    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function finalizedHeight() external view returns (uint32);

    function headers(bytes32 blockHash)
        external
        view
        returns (
            bytes32 parent,
            bytes32 merkleRoot,
            uint256 chainwork,
            uint32 height,
            uint32 timestamp,
            uint32 medianTimePast,
            uint32 bits,
            uint32 epochStartTime,
            bool exists
        );

    function isAncestorOfBest(bytes32 blockHash) external view returns (bool);
}

/// @title BitcoinParentFinalityRelayV2
/// @notice Immutable exact-tuple adapter from the V1 greatest-work header relay
///         to the retained-ancestor API required by ControllerAcceptanceRelayV2.
/// @dev This contract does not accept headers, proofs, signatures, or caller
///      assertions. It pins one source contract, its deployed code, complete
///      verifier configuration, Bitcoin genesis, deployment chain, and finality
///      depth. A tuple is accepted only when the source stores every field
///      exactly, its height is already finalized, and it remains an ancestor of
///      the source's greatest-work tip.
///
///      The current V1 source is a Sepolia candidate with an independently
///      frozen checkpoint, not a production eCash-mainnet relay. This adapter
///      closes the V11 testnet historical-membership API gap; it does not turn
///      the source into a production-ready verifier.
contract BitcoinParentFinalityRelayV2 is IParentFinalityRelayV2 {
    bool public constant PRODUCTION_READY = false;
    bytes32 public constant SECURITY_STATUS =
        keccak256("V11_TESTNET_PARENT_FINALITY_ADAPTER; PRODUCTION_SOURCE_AND_AUDIT_REQUIRED");
    bytes32 public constant PARENT_CHAIN_ID_DOMAIN =
        keccak256("USDD_PARENT_CHAIN_ID_V2");
    bytes32 public constant FINALITY_CONFIG_DOMAIN =
        keccak256("USDD_PARENT_FINALITY_CONFIG_V2");

    struct SourceConfig {
        address headerRelay;
        bytes32 headerRelayCodehash;
        bytes32 headerRelayProgramId;
        bytes32 headerRelayConfigHash;
        bytes32 bitcoinGenesisHash;
        uint32 finalityDepth;
    }

    IBitcoinHeaderFinalitySourceV1 public immutable HEADER_RELAY;
    bytes32 public immutable HEADER_RELAY_CODEHASH;
    bytes32 public immutable HEADER_RELAY_PROGRAM_ID;
    bytes32 public immutable HEADER_RELAY_CONFIG_HASH;
    bytes32 public immutable BITCOIN_GENESIS_HASH;
    uint32 public immutable FINALITY_DEPTH;
    bytes32 public immutable override parentChainIdentity;
    bytes32 public immutable override finalityConfigHash;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error SourceConfigurationMismatch();
    error HeaderRelayCodeChanged(bytes32 expected, bytes32 actual);
    error HeaderRelayIdentityChanged();

    constructor(SourceConfig memory config) {
        if (config.headerRelay == address(0)) revert ZeroIdentity();
        if (config.headerRelay.code.length == 0) {
            revert AddressHasNoCode(config.headerRelay);
        }
        if (
            config.headerRelayCodehash == bytes32(0)
                || config.headerRelayProgramId == bytes32(0)
                || config.headerRelayConfigHash == bytes32(0)
                || config.bitcoinGenesisHash == bytes32(0) || config.finalityDepth == 0
        ) revert ZeroIdentity();
        if (config.headerRelay.codehash != config.headerRelayCodehash) {
            revert SourceConfigurationMismatch();
        }

        IBitcoinHeaderFinalitySourceV1 source =
            IBitcoinHeaderFinalitySourceV1(config.headerRelay);
        if (
            source.DEPLOYMENT_CHAIN_ID() != block.chainid
                || source.BITCOIN_GENESIS_HASH() != config.bitcoinGenesisHash
                || source.FINALITY_DEPTH() != config.finalityDepth
                || source.verifierProgramId() != config.headerRelayProgramId
                || source.verifierConfigHash() != config.headerRelayConfigHash
        ) revert SourceConfigurationMismatch();

        HEADER_RELAY = source;
        HEADER_RELAY_CODEHASH = config.headerRelayCodehash;
        HEADER_RELAY_PROGRAM_ID = config.headerRelayProgramId;
        HEADER_RELAY_CONFIG_HASH = config.headerRelayConfigHash;
        BITCOIN_GENESIS_HASH = config.bitcoinGenesisHash;
        FINALITY_DEPTH = config.finalityDepth;

        bytes32 chainIdentity = sha256(
            abi.encode(
                PARENT_CHAIN_ID_DOMAIN,
                block.chainid,
                config.headerRelay,
                config.headerRelayCodehash,
                config.headerRelayProgramId,
                config.headerRelayConfigHash,
                config.bitcoinGenesisHash
            )
        );
        parentChainIdentity = chainIdentity;
        finalityConfigHash = sha256(
            abi.encode(
                FINALITY_CONFIG_DOMAIN,
                chainIdentity,
                config.finalityDepth
            )
        );
    }

    function currentFinalizedHeight() external view override returns (uint64) {
        _requireSourceIdentity();
        return uint64(HEADER_RELAY.finalizedHeight());
    }

    function isFinalizedCanonical(
        bytes32 blockHash,
        uint64 blockHeight,
        uint64 medianTimePast,
        uint256 chainwork
    ) external view override returns (bool) {
        _requireSourceIdentity();
        if (
            blockHash == bytes32(0) || blockHeight > type(uint32).max
                || medianTimePast == 0 || medianTimePast > type(uint32).max
                || chainwork == 0
        ) return false;

        uint32 height = uint32(blockHeight);
        if (height > HEADER_RELAY.finalizedHeight()) return false;

        // V11 canonical controller state and its manifest use the ordinary
        // RPC/display byte order. BitcoinBip300RelayV1 deliberately keys
        // headers by the raw SHA256d bytes as they appear in the serialized
        // header and PoW arithmetic. Convert exactly once at this adapter
        // boundary; passing display order directly would make a real
        // non-palindromic checkpoint valid in only one of the two systems.
        bytes32 sourceBlockHash = _reverseBytes32(blockHash);
        (
            ,
            ,
            uint256 storedChainwork,
            uint32 storedHeight,
            ,
            uint32 storedMedianTimePast,
            ,
            ,
            bool exists
        ) = HEADER_RELAY.headers(sourceBlockHash);
        if (
            !exists || storedHeight != height
                || storedMedianTimePast != uint32(medianTimePast)
                || storedChainwork != chainwork
        ) return false;

        return HEADER_RELAY.isAncestorOfBest(sourceBlockHash);
    }

    function _requireSourceIdentity() private view {
        bytes32 actualCodehash = address(HEADER_RELAY).codehash;
        if (actualCodehash != HEADER_RELAY_CODEHASH) {
            revert HeaderRelayCodeChanged(HEADER_RELAY_CODEHASH, actualCodehash);
        }
        if (
            HEADER_RELAY.DEPLOYMENT_CHAIN_ID() != block.chainid
                || HEADER_RELAY.BITCOIN_GENESIS_HASH() != BITCOIN_GENESIS_HASH
                || HEADER_RELAY.FINALITY_DEPTH() != FINALITY_DEPTH
                || HEADER_RELAY.verifierProgramId() != HEADER_RELAY_PROGRAM_ID
            || HEADER_RELAY.verifierConfigHash() != HEADER_RELAY_CONFIG_HASH
        ) revert HeaderRelayIdentityChanged();
    }

    function _reverseBytes32(bytes32 value) private pure returns (bytes32 reversed) {
        for (uint256 i; i < 32; ++i) {
            reversed |= bytes32(uint256(uint8(value[i])) << (i * 8));
        }
    }
}
