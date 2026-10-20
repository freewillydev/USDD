// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IV11AllSlotReplayProofVerifier} from
    "./interfaces/IV11AllSlotReplayProofVerifier.sol";
import {IV11AllSlotProofVerificationComponent} from
    "./interfaces/IV11AllSlotProofVerificationComponent.sol";

/// @title ImmutableV11AllSlotReplayProofVerifier
/// @notice Ownerless, configuration-independent-runtime adapter for the V11
///         all-slot proof component.
/// @dev All configuration is constructor-only storage. Solidity `immutable`
///      variables are deliberately not used: the deployed runtime bytecode
///      must be identical for every configuration so the replay profile can
///      commit the runtime hash without a profile/finality fixed point.
contract ImmutableV11AllSlotReplayProofVerifier is
    IV11AllSlotReplayProofVerifier
{
    bytes32 public constant EXACT_PARENT_GENESIS_SERIALIZATION_HASH =
        0xc8abc5554d8a4e1134b27050f0a6a8fc616196bfdd381fb49f49fdea6a811675;
    bytes32 public constant ADAPTER_CONFIG_DOMAIN =
        sha256("USDD_V11_ALL_SLOT_PROOF_VERIFIER_CONFIG");
    bytes32 public constant COMPONENT_INTERFACE_HASH =
        sha256("USDD_V11_ALL_SLOT_PROOF_COMPONENT_INTERFACE_V1");
    uint32 public constant NO_CERTIFICATE_PUBLIC_VALUES_BYTES = 271;
    uint32 public constant CERTIFICATE_PUBLIC_VALUES_BYTES = 449;
    uint32 public constant GROTH16_PROOF_BYTES = 356;
    uint32 public constant MAXIMUM_PROOF_BYTES =
        CERTIFICATE_PUBLIC_VALUES_BYTES + GROTH16_PROOF_BYTES;

    struct VerifierConfig {
        address component;
        bytes32 componentCodehash;
        bytes32 programId;
        bytes32 allSlotReplayProfile;
        bytes32 canonicalFinalityConfiguration;
        bytes32 initialAllSlotCheckpoint;
    }

    address public COMPONENT;
    bytes32 public COMPONENT_CODEHASH;
    bytes32 public COMPONENT_CONFIG_HASH;
    bytes32 public COMPONENT_SEGMENT_PROGRAM_ID;
    bytes32 public COMPONENT_SEGMENT_PROGRAM_VKEY;
    bytes32 public COMPONENT_PROGRAM_VKEY;
    bytes32 public override verifierProgramId;
    bytes32 public override verifierConfigHash;
    bytes32 public override allSlotReplayProfileCommitment;
    bytes32 public override canonicalFinalityConfigurationHash;
    bytes32 public override initialAllSlotCheckpointCommitment;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error ComponentCodeChanged(bytes32 expected, bytes32 actual);
    error ComponentIdentityChanged();

    constructor(VerifierConfig memory config) {
        if (
            config.component == address(0)
                || config.componentCodehash == bytes32(0)
                || config.programId == bytes32(0)
                || config.allSlotReplayProfile == bytes32(0)
                || config.canonicalFinalityConfiguration == bytes32(0)
                || config.initialAllSlotCheckpoint == bytes32(0)
        ) revert ZeroIdentity();
        if (config.component.code.length == 0) {
            revert AddressHasNoCode(config.component);
        }
        if (config.component.codehash != config.componentCodehash) {
            revert ComponentCodeChanged(
                config.componentCodehash, config.component.codehash
            );
        }
        IV11AllSlotProofVerificationComponent component =
            IV11AllSlotProofVerificationComponent(config.component);
        bytes32 componentConfig = component.componentConfigHash();
        if (
            componentConfig == bytes32(0)
                || component.componentSegmentProgramId() == bytes32(0)
                || component.componentSegmentProgramVKey() == bytes32(0)
                || component.componentProgramVKey() == bytes32(0)
                || component.componentSegmentProgramId()
                    == config.programId
                || component.componentProgramId() != config.programId
        ) revert ComponentIdentityChanged();

        COMPONENT = config.component;
        COMPONENT_CODEHASH = config.componentCodehash;
        COMPONENT_CONFIG_HASH = componentConfig;
        COMPONENT_SEGMENT_PROGRAM_ID =
            component.componentSegmentProgramId();
        COMPONENT_SEGMENT_PROGRAM_VKEY =
            component.componentSegmentProgramVKey();
        COMPONENT_PROGRAM_VKEY = component.componentProgramVKey();
        verifierProgramId = config.programId;
        verifierConfigHash = _configHash(
            config.component,
            config.componentCodehash,
            componentConfig
        );
        allSlotReplayProfileCommitment =
            config.allSlotReplayProfile;
        canonicalFinalityConfigurationHash =
            config.canonicalFinalityConfiguration;
        initialAllSlotCheckpointCommitment =
            config.initialAllSlotCheckpoint;
    }

    function exactParentGenesisSerializationHash()
        external
        pure
        override
        returns (bytes32)
    {
        return EXACT_PARENT_GENESIS_SERIALIZATION_HASH;
    }

    function verifyProof(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (proof.length > MAXIMUM_PROOF_BYTES) return false;
        _requireComponentIdentity();
        (bool success, bytes memory returned) =
            COMPONENT.staticcall(
                abi.encodeCall(
                    IV11AllSlotProofVerificationComponent.verify,
                    (publicValuesHash, proof)
                )
            );
        if (
            !success || returned.length != 32
                || abi.decode(returned, (uint256)) != 1
        ) return false;
        _requireComponentIdentity();
        return true;
    }

    function _requireComponentIdentity() private view {
        bytes32 actualCodehash = COMPONENT.codehash;
        if (actualCodehash != COMPONENT_CODEHASH) {
            revert ComponentCodeChanged(
                COMPONENT_CODEHASH, actualCodehash
            );
        }
        IV11AllSlotProofVerificationComponent component =
            IV11AllSlotProofVerificationComponent(COMPONENT);
        if (
            component.componentSegmentProgramId()
                    != COMPONENT_SEGMENT_PROGRAM_ID
                || component.componentSegmentProgramVKey()
                    != COMPONENT_SEGMENT_PROGRAM_VKEY
                || component.componentProgramVKey()
                    != COMPONENT_PROGRAM_VKEY
                || component.componentProgramId() != verifierProgramId
                || component.componentConfigHash()
                    != COMPONENT_CONFIG_HASH
        ) revert ComponentIdentityChanged();
    }

    function _configHash(
        address component,
        bytes32 componentCodehash,
        bytes32 componentConfig
    ) private pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                ADAPTER_CONFIG_DOMAIN,
                component,
                componentCodehash,
                componentConfig,
                COMPONENT_INTERFACE_HASH,
                NO_CERTIFICATE_PUBLIC_VALUES_BYTES,
                CERTIFICATE_PUBLIC_VALUES_BYTES,
                GROTH16_PROOF_BYTES,
                MAXIMUM_PROOF_BYTES,
                uint8(1)
            )
        );
    }
}
