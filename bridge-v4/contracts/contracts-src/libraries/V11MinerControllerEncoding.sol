// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICanonicalParentFinalityReceiptV11} from
    "../interfaces/ICanonicalParentFinalityReceiptV11.sol";

/// @title V11MinerControllerEncoding
/// @notice Byte-exact codecs and local semantic checks shared with the Rust
///         V11 miner-approved controller-certificate reference model.
/// @dev This library defines the explicitly weaker miner-authority profile. It
///      must never be used as a verifier for the separate strong recursive
///      Elements-execution profile.
library V11MinerControllerEncoding {
    uint8 internal constant REQUIRED_DRIVECHAIN_SLOT = 24;
    uint16 internal constant M6_INCLUSION_THRESHOLD = 5;
    uint32 internal constant M6_FINALITY_CONFIRMATIONS = 100;
    uint64 internal constant MAX_SUCCESSFUL_SLOT24_M6IDS = 1 << 18;
    uint256 internal constant CERTIFICATE_ENCODED_LENGTH = 1_168;
    uint256 internal constant EVENT_PRESENT_JOURNAL_ENCODED_LENGTH = 449;

    bytes8 internal constant CERTIFICATE_MAGIC = bytes8("USDDCC2");
    uint16 internal constant CERTIFICATE_CODEC = 1;
    bytes32 internal constant CERTIFICATE_SECURITY_MODEL_ID =
        0x7ac67122d2dd491a8de4eb1b86651b39613b40ea18b549f950f49fdb7d8afc8a;
    bytes32 internal constant CERTIFICATE_DOMAIN =
        0x961dce75c2f2c124ff3fde9b647335d720522d28fd013d369522bfab1a74f230;
    bytes32 internal constant CANONICAL_STATE_DOMAIN =
        0xe281584855decfb59b5eb9ef5684dd6efeba00d8e479d8e009c9fed41ab2cc4a;

    bytes8 internal constant JOURNAL_MAGIC = bytes8("ECAJNL11");
    uint16 internal constant JOURNAL_SCHEMA = 1;
    bytes internal constant JOURNAL_DOMAIN =
        "USDD_ECASH_ALL_SLOT_JOURNAL_V11";

    bytes internal constant DEPLOYMENT_DOMAIN =
        "USDD_V11_CONTROLLER_DEPLOYMENT";
    uint16 internal constant DEPLOYMENT_SCHEMA = 1;
    bytes8 internal constant CHECKPOINT_MAGIC = bytes8("CCRPV11");
    uint16 internal constant CHECKPOINT_SCHEMA = 1;
    bytes internal constant CHECKPOINT_DOMAIN =
        "USDD_V11_CONTROLLER_CHECKPOINT";
    bytes internal constant ACCEPTANCE_DOMAIN =
        "USDD_V11_CONTROLLER_ACCEPTANCE";
    uint32 internal constant MAX_CHECKPOINT_BYTES = 4 * 1024;

    bytes internal constant CONSUMPTION_STATE_DOMAIN =
        "USDD_V11_CONSUMPTION_SET_STATE";
    bytes internal constant CONSUMPTION_KEY_DOMAIN =
        "USDD_V11_CONSUMPTION_SET_KEY";
    bytes internal constant CONSUMPTION_EMPTY_LEAF_DOMAIN =
        "USDD_V11_CONSUMPTION_SET_EMPTY_LEAF";
    bytes internal constant CONSUMPTION_OCCUPIED_LEAF_DOMAIN =
        "USDD_V11_CONSUMPTION_SET_OCCUPIED_LEAF";
    bytes internal constant CONSUMPTION_NODE_DOMAIN =
        "USDD_V11_CONSUMPTION_SET_NODE";

    struct Policy {
        uint64 maxControllerAdmissionAgeSeconds;
        uint64 maxWeakSubjectivityPeriodSeconds;
        uint64 maxControllerSequenceDelta;
        uint64 maxResolutionDelta;
    }

    struct IdentityClaims {
        bytes32 certificateRelayProgramId;
        bytes32 certificateRelayConfigurationHash;
        bytes32 parentChainIdentity;
        bytes32 parentFinalityConfigurationHash;
        bytes32 weakSubjectivityPolicyHash;
        bytes32 protocolCoreHash;
        bytes32 parentGenesisHash;
        bytes32 elementsGenesisHash;
        bytes32 controllerProgramConfigurationHash;
        bytes32 inboundVaultConfigurationHash;
        bytes32 usddAssetId;
    }

    struct CanonicalControllerState {
        bytes32 controllerStateHash;
        bytes32 cumulativeResolutionRoot;
        bytes32 parentBlockHash;
        uint64 controllerSequence;
        uint64 resolutionCount;
        uint64 nextResolutionNonce;
        uint64 parentBlockHeight;
        uint64 parentMedianTimePast;
        uint256 parentChainwork;
        uint64 ethereumFinalizedSlot;
        uint64 ethereumFinalizedTimestamp;
        uint64 weakSubjectivityValidUntil;
    }

    struct Audit {
        bytes32 firstElementsBlockHash;
        bytes32 lastElementsBlockHash;
        uint64 firstElementsBlockHeight;
        uint64 lastElementsBlockHeight;
        bytes32 terminalControllerTransactionId;
        bytes32 controllerHistoryCommitment;
        bytes32 elementsInclusionHistoryCommitment;
        bytes32 bmmHistoryCommitment;
        bytes32 executionAuditCommitment;
    }

    struct Certificate {
        bytes32 manifestId;
        uint256 ethereumChainId;
        address relayAddress;
        uint8 drivechainSlot;
        Policy policy;
        bool bootstrap;
        bytes32 expectedSourceStateHash;
        IdentityClaims identities;
        CanonicalControllerState source;
        CanonicalControllerState successor;
        Audit audit;
    }

    struct FinalizedCertificateEvent {
        bytes32 certificateCommitment;
        bytes32 approvedM6id;
        uint32 proposalHeight;
        uint16 approvalScore;
        bytes32 inclusionBlockHash;
        uint32 inclusionHeight;
        ICanonicalParentFinalityReceiptV11.Checkpoint finalizationCheckpoint;
    }

    struct Journal {
        bytes32 profileCommitment;
        bytes32 sourceCheckpointCommitment;
        bytes32 nextCheckpointCommitment;
        ICanonicalParentFinalityReceiptV11.Checkpoint sourceParentCheckpoint;
        ICanonicalParentFinalityReceiptV11.Checkpoint nextParentCheckpoint;
        uint32 blockCount;
        uint64 sourceSuccessfulSlot24M6idCount;
        uint64 nextSuccessfulSlot24M6idCount;
        FinalizedCertificateEvent acceptedCertificate;
    }

    struct DeploymentFields {
        bytes32 manifestId;
        uint256 ethereumChainId;
        address relayAddress;
        uint8 drivechainSlot;
        Policy policy;
        IdentityClaims identities;
        bytes32 initialControllerStateHash;
        bytes32 allSlotReplayProfileCommitment;
        bytes32 canonicalFinalityConfigurationHash;
        bytes32 initialAllSlotCheckpointCommitment;
    }

    error InvalidInitialState();
    error InvalidCertificate();
    error InvalidJournal();
    error NoncanonicalLength(uint256 expected, uint256 actual);

    function decodeCertificate(bytes calldata encoded)
        internal
        pure
        returns (Certificate memory certificate)
    {
        if (encoded.length != CERTIFICATE_ENCODED_LENGTH) {
            revert NoncanonicalLength(
                CERTIFICATE_ENCODED_LENGTH, encoded.length
            );
        }
        if (
            bytes8(_load(encoded, 0)) != CERTIFICATE_MAGIC
                || _u16(encoded, 8) != CERTIFICATE_CODEC
                || _load(encoded, 10) != CERTIFICATE_SECURITY_MODEL_ID
        ) revert InvalidCertificate();
        certificate.manifestId = _load(encoded, 42);
        certificate.ethereumChainId = uint256(_load(encoded, 74));
        certificate.relayAddress = _address(encoded, 106);
        certificate.drivechainSlot = _u8(encoded, 126);
        certificate.policy = Policy({
            maxControllerAdmissionAgeSeconds: _u64(encoded, 127),
            maxWeakSubjectivityPeriodSeconds: _u64(encoded, 135),
            maxControllerSequenceDelta: _u64(encoded, 143),
            maxResolutionDelta: _u64(encoded, 151)
        });
        uint8 bootstrapTag = _u8(encoded, 159);
        if (bootstrapTag > 1) revert InvalidCertificate();
        certificate.bootstrap = bootstrapTag == 1;
        certificate.expectedSourceStateHash = _load(encoded, 160);
        certificate.identities = _decodeIdentities(encoded, 192);
        certificate.source = _decodeState(encoded, 544);
        certificate.successor = _decodeState(encoded, 736);
        certificate.audit = Audit({
            firstElementsBlockHash: _load(encoded, 928),
            lastElementsBlockHash: _load(encoded, 960),
            firstElementsBlockHeight: _u64(encoded, 992),
            lastElementsBlockHeight: _u64(encoded, 1000),
            terminalControllerTransactionId: _load(encoded, 1008),
            controllerHistoryCommitment: _load(encoded, 1040),
            elementsInclusionHistoryCommitment: _load(encoded, 1072),
            bmmHistoryCommitment: _load(encoded, 1104),
            executionAuditCommitment: _load(encoded, 1136)
        });
    }

    function decodeJournal(bytes calldata encoded)
        internal
        pure
        returns (Journal memory journal)
    {
        if (encoded.length != EVENT_PRESENT_JOURNAL_ENCODED_LENGTH) {
            revert NoncanonicalLength(
                EVENT_PRESENT_JOURNAL_ENCODED_LENGTH, encoded.length
            );
        }
        if (
            bytes8(_load(encoded, 0)) != JOURNAL_MAGIC
                || _u16(encoded, 8) != JOURNAL_SCHEMA
                || _u8(encoded, 270) != 1
        ) revert InvalidJournal();
        journal.profileCommitment = _load(encoded, 10);
        journal.sourceCheckpointCommitment = _load(encoded, 42);
        journal.nextCheckpointCommitment = _load(encoded, 74);
        journal.sourceParentCheckpoint =
            _decodeCheckpoint(encoded, 106);
        journal.nextParentCheckpoint =
            _decodeCheckpoint(encoded, 178);
        journal.blockCount = _u32(encoded, 250);
        journal.sourceSuccessfulSlot24M6idCount =
            _u64(encoded, 254);
        journal.nextSuccessfulSlot24M6idCount = _u64(encoded, 262);
        journal.acceptedCertificate = FinalizedCertificateEvent({
            certificateCommitment: _load(encoded, 271),
            approvedM6id: _load(encoded, 303),
            proposalHeight: _u32(encoded, 335),
            approvalScore: _u16(encoded, 339),
            inclusionBlockHash: _load(encoded, 341),
            inclusionHeight: _u32(encoded, 373),
            finalizationCheckpoint: _decodeCheckpoint(encoded, 377)
        });
        validateJournal(journal);
    }

    function validateInitialState(
        Policy memory policy,
        CanonicalControllerState memory state
    ) internal pure {
        if (
            state.controllerStateHash == bytes32(0)
                || state.cumulativeResolutionRoot == bytes32(0)
                || state.parentBlockHash == bytes32(0)
                || state.parentChainwork == 0
                || state.resolutionCount > state.controllerSequence
                || state.nextResolutionNonce != state.resolutionCount
                || state.parentMedianTimePast == 0
                || state.ethereumFinalizedSlot == 0
                || state.ethereumFinalizedTimestamp == 0
                || _absoluteDifference(
                    state.ethereumFinalizedTimestamp,
                    state.parentMedianTimePast
                ) > policy.maxControllerAdmissionAgeSeconds
                || state.weakSubjectivityValidUntil
                    <= state.ethereumFinalizedTimestamp
                || state.weakSubjectivityValidUntil
                    - state.ethereumFinalizedTimestamp
                    > policy.maxWeakSubjectivityPeriodSeconds
        ) revert InvalidInitialState();
    }

    function validateCertificate(
        Certificate memory certificate,
        CanonicalControllerState memory storedState,
        bytes32 storedStateHash,
        bool expectedBootstrap
    ) internal pure {
        if (
            certificate.manifestId == bytes32(0)
                || certificate.ethereumChainId == 0
                || certificate.relayAddress == address(0)
                || certificate.drivechainSlot != REQUIRED_DRIVECHAIN_SLOT
                || !_validPolicy(certificate.policy)
                || certificate.bootstrap != expectedBootstrap
                || certificate.expectedSourceStateHash != storedStateHash
                || canonicalStateHash(certificate.source) != storedStateHash
                || !_sameState(certificate.source, storedState)
                || _anyZeroIdentities(certificate.identities)
        ) revert InvalidCertificate();

        _validateSuccessor(
            certificate.policy, certificate.source, certificate.successor
        );
        Audit memory audit = certificate.audit;
        if (
            audit.firstElementsBlockHeight == 0
                || audit.lastElementsBlockHeight
                    < audit.firstElementsBlockHeight
                || audit.firstElementsBlockHash == bytes32(0)
                || audit.lastElementsBlockHash == bytes32(0)
                || audit.terminalControllerTransactionId == bytes32(0)
                || audit.controllerHistoryCommitment == bytes32(0)
                || audit.elementsInclusionHistoryCommitment == bytes32(0)
                || audit.bmmHistoryCommitment == bytes32(0)
                || audit.executionAuditCommitment == bytes32(0)
        ) revert InvalidCertificate();
    }

    function validateJournal(Journal memory journal) internal pure {
        ICanonicalParentFinalityReceiptV11.Checkpoint memory source =
            journal.sourceParentCheckpoint;
        ICanonicalParentFinalityReceiptV11.Checkpoint memory next =
            journal.nextParentCheckpoint;
        FinalizedCertificateEvent memory accepted =
            journal.acceptedCertificate;
        if (
            journal.profileCommitment == bytes32(0)
                || journal.sourceCheckpointCommitment == bytes32(0)
                || journal.nextCheckpointCommitment == bytes32(0)
                || journal.sourceCheckpointCommitment
                    == journal.nextCheckpointCommitment
                || !_validCheckpoint(source) || !_validCheckpoint(next)
                || journal.blockCount == 0
                || uint256(source.blockHeight) + journal.blockCount
                    != next.blockHeight
                || next.cumulativeChainwork <= source.cumulativeChainwork
                || next.medianTimePast < source.medianTimePast
                || journal.nextSuccessfulSlot24M6idCount
                    < journal.sourceSuccessfulSlot24M6idCount
                || journal.nextSuccessfulSlot24M6idCount
                    > MAX_SUCCESSFUL_SLOT24_M6IDS
                || accepted.certificateCommitment == bytes32(0)
                || accepted.approvedM6id == bytes32(0)
                || accepted.inclusionBlockHash == bytes32(0)
                || accepted.approvalScore <= M6_INCLUSION_THRESHOLD
                || accepted.proposalHeight >= accepted.inclusionHeight
                || !_validCheckpoint(accepted.finalizationCheckpoint)
                || !_sameCheckpoint(accepted.finalizationCheckpoint, next)
                || accepted.finalizationCheckpoint.blockHeight
                    < accepted.inclusionHeight
                || uint256(accepted.finalizationCheckpoint.blockHeight)
                    - accepted.inclusionHeight + 1
                    < M6_FINALITY_CONFIRMATIONS
        ) revert InvalidJournal();
    }

    function validateEventAgainstCertificate(
        FinalizedCertificateEvent memory accepted,
        Certificate memory certificate
    ) internal pure {
        if (
            certificate.successor.parentBlockHeight
                >= accepted.proposalHeight
        ) revert InvalidCertificate();
    }

    function canonicalStateHash(CanonicalControllerState memory state)
        internal
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encode(
                CANONICAL_STATE_DOMAIN,
                state.controllerStateHash,
                state.cumulativeResolutionRoot,
                state.parentBlockHash,
                state.controllerSequence,
                state.resolutionCount,
                state.nextResolutionNonce,
                state.parentBlockHeight,
                state.parentMedianTimePast,
                state.parentChainwork,
                state.ethereumFinalizedSlot,
                state.ethereumFinalizedTimestamp,
                state.weakSubjectivityValidUntil
            )
        );
    }

    function encodeState(CanonicalControllerState memory state)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            state.controllerStateHash,
            state.cumulativeResolutionRoot,
            state.parentBlockHash,
            state.controllerSequence,
            state.resolutionCount,
            state.nextResolutionNonce,
            state.parentBlockHeight,
            state.parentMedianTimePast,
            state.parentChainwork,
            state.ethereumFinalizedSlot,
            state.ethereumFinalizedTimestamp,
            state.weakSubjectivityValidUntil
        );
    }

    function certificateBytes(Certificate memory certificate)
        internal
        pure
        returns (bytes memory encoded)
    {
        encoded = bytes.concat(
            abi.encodePacked(
                CERTIFICATE_MAGIC,
                CERTIFICATE_CODEC,
                CERTIFICATE_SECURITY_MODEL_ID,
                certificate.manifestId,
                certificate.ethereumChainId,
                certificate.relayAddress,
                certificate.drivechainSlot,
                certificate.policy.maxControllerAdmissionAgeSeconds,
                certificate.policy.maxWeakSubjectivityPeriodSeconds,
                certificate.policy.maxControllerSequenceDelta,
                certificate.policy.maxResolutionDelta,
                certificate.bootstrap ? uint8(1) : uint8(0),
                certificate.expectedSourceStateHash
            ),
            _encodeIdentities(certificate.identities),
            encodeState(certificate.source),
            encodeState(certificate.successor),
            _encodeAudit(certificate.audit)
        );
        if (encoded.length != CERTIFICATE_ENCODED_LENGTH) {
            revert NoncanonicalLength(
                CERTIFICATE_ENCODED_LENGTH, encoded.length
            );
        }
    }

    function certificateCommitment(Certificate memory certificate)
        internal
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encodePacked(CERTIFICATE_DOMAIN, certificateBytes(certificate))
        );
    }

    function certificateCommitment(bytes calldata encoded)
        internal
        pure
        returns (bytes32)
    {
        if (encoded.length != CERTIFICATE_ENCODED_LENGTH) {
            revert NoncanonicalLength(
                CERTIFICATE_ENCODED_LENGTH, encoded.length
            );
        }
        return sha256(abi.encodePacked(CERTIFICATE_DOMAIN, encoded));
    }

    function journalBytes(Journal memory journal)
        internal
        pure
        returns (bytes memory encoded)
    {
        validateJournal(journal);
        FinalizedCertificateEvent memory accepted =
            journal.acceptedCertificate;
        encoded = bytes.concat(
            abi.encodePacked(
                JOURNAL_MAGIC,
                JOURNAL_SCHEMA,
                journal.profileCommitment,
                journal.sourceCheckpointCommitment,
                journal.nextCheckpointCommitment
            ),
            _encodeCheckpoint(journal.sourceParentCheckpoint),
            _encodeCheckpoint(journal.nextParentCheckpoint),
            abi.encodePacked(
                journal.blockCount,
                journal.sourceSuccessfulSlot24M6idCount,
                journal.nextSuccessfulSlot24M6idCount,
                uint8(1),
                accepted.certificateCommitment,
                accepted.approvedM6id,
                accepted.proposalHeight,
                accepted.approvalScore,
                accepted.inclusionBlockHash,
                accepted.inclusionHeight
            ),
            _encodeCheckpoint(accepted.finalizationCheckpoint)
        );
        if (encoded.length != EVENT_PRESENT_JOURNAL_ENCODED_LENGTH) {
            revert NoncanonicalLength(
                EVENT_PRESENT_JOURNAL_ENCODED_LENGTH, encoded.length
            );
        }
    }

    function journalHashes(Journal memory journal)
        internal
        pure
        returns (bytes32 publicValuesHash, bytes32 journalCommitment)
    {
        bytes memory encoded = journalBytes(journal);
        publicValuesHash = sha256(encoded);
        journalCommitment =
            sha256(abi.encodePacked(JOURNAL_DOMAIN, encoded));
    }

    function journalHashes(bytes calldata encoded)
        internal
        pure
        returns (bytes32 publicValuesHash, bytes32 journalCommitment)
    {
        if (encoded.length != EVENT_PRESENT_JOURNAL_ENCODED_LENGTH) {
            revert NoncanonicalLength(
                EVENT_PRESENT_JOURNAL_ENCODED_LENGTH, encoded.length
            );
        }
        publicValuesHash = sha256(encoded);
        journalCommitment =
            sha256(abi.encodePacked(JOURNAL_DOMAIN, encoded));
    }

    function deploymentCommitment(DeploymentFields memory fields)
        internal
        pure
        returns (bytes32)
    {
        bytes memory preimage = abi.encodePacked(
            DEPLOYMENT_DOMAIN,
            DEPLOYMENT_SCHEMA,
            fields.manifestId,
            fields.ethereumChainId,
            fields.relayAddress,
            fields.drivechainSlot
        );
        preimage = bytes.concat(
            preimage,
            abi.encodePacked(
                fields.policy.maxControllerAdmissionAgeSeconds,
                fields.policy.maxWeakSubjectivityPeriodSeconds,
                fields.policy.maxControllerSequenceDelta,
                fields.policy.maxResolutionDelta
            ),
            _encodeIdentities(fields.identities)
        );
        preimage = bytes.concat(
            preimage,
            abi.encodePacked(
                fields.initialControllerStateHash,
                fields.allSlotReplayProfileCommitment,
                fields.canonicalFinalityConfigurationHash,
                fields.initialAllSlotCheckpointCommitment
            )
        );
        preimage = bytes.concat(
            preimage,
            abi.encodePacked(
                CHECKPOINT_MAGIC,
                CHECKPOINT_SCHEMA,
                CHECKPOINT_DOMAIN,
                ACCEPTANCE_DOMAIN,
                MAX_CHECKPOINT_BYTES
            )
        );
        preimage = bytes.concat(
            preimage,
            abi.encodePacked(
                CERTIFICATE_MAGIC,
                CERTIFICATE_CODEC,
                uint32(CERTIFICATE_ENCODED_LENGTH),
                CERTIFICATE_DOMAIN,
                CERTIFICATE_SECURITY_MODEL_ID
            )
        );
        preimage = bytes.concat(
            preimage,
            abi.encodePacked(
                uint16(1),
                uint16(256),
                uint8(3),
                uint8(1),
                uint8(2),
                uint8(3)
            )
        );
        return sha256(
            bytes.concat(
                preimage,
                CONSUMPTION_STATE_DOMAIN,
                CONSUMPTION_KEY_DOMAIN,
                CONSUMPTION_EMPTY_LEAF_DOMAIN,
                CONSUMPTION_OCCUPIED_LEAF_DOMAIN,
                CONSUMPTION_NODE_DOMAIN
            )
        );
    }

    function samePolicy(Policy memory left, Policy memory right)
        internal
        pure
        returns (bool)
    {
        return left.maxControllerAdmissionAgeSeconds
                == right.maxControllerAdmissionAgeSeconds
            && left.maxWeakSubjectivityPeriodSeconds
                == right.maxWeakSubjectivityPeriodSeconds
            && left.maxControllerSequenceDelta
                == right.maxControllerSequenceDelta
            && left.maxResolutionDelta == right.maxResolutionDelta;
    }

    function sameIdentities(
        IdentityClaims memory left,
        IdentityClaims memory right
    ) internal pure returns (bool) {
        return keccak256(_encodeIdentities(left))
            == keccak256(_encodeIdentities(right));
    }

    function sameState(
        CanonicalControllerState memory left,
        CanonicalControllerState memory right
    ) internal pure returns (bool) {
        return _sameState(left, right);
    }

    function sameCheckpoint(
        ICanonicalParentFinalityReceiptV11.Checkpoint memory left,
        ICanonicalParentFinalityReceiptV11.Checkpoint memory right
    ) internal pure returns (bool) {
        return _sameCheckpoint(left, right);
    }

    function validPolicy(Policy memory policy)
        internal
        pure
        returns (bool)
    {
        return _validPolicy(policy);
    }

    function validIdentities(IdentityClaims memory identities)
        internal
        pure
        returns (bool)
    {
        return !_anyZeroIdentities(identities);
    }

    function identityClaimsHash(IdentityClaims memory identities)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(_encodeIdentities(identities));
    }

    function _validateSuccessor(
        Policy memory policy,
        CanonicalControllerState memory source,
        CanonicalControllerState memory successor
    ) private pure {
        if (
            successor.controllerStateHash == bytes32(0)
                || successor.controllerStateHash
                    == source.controllerStateHash
                || successor.parentBlockHash == bytes32(0)
                || successor.controllerSequence <= source.controllerSequence
                || successor.resolutionCount > successor.controllerSequence
                || successor.parentMedianTimePast == 0
                || successor.parentChainwork == 0
                || successor.ethereumFinalizedSlot == 0
                || successor.ethereumFinalizedTimestamp == 0
        ) revert InvalidCertificate();

        uint64 sequenceDelta =
            successor.controllerSequence - source.controllerSequence;
        if (
            successor.resolutionCount < source.resolutionCount
                || successor.nextResolutionNonce < source.nextResolutionNonce
        ) revert InvalidCertificate();
        uint64 resolutionDelta =
            successor.resolutionCount - source.resolutionCount;
        uint64 nonceDelta =
            successor.nextResolutionNonce - source.nextResolutionNonce;
        if (
            sequenceDelta > policy.maxControllerSequenceDelta
                || resolutionDelta > sequenceDelta
                || resolutionDelta > policy.maxResolutionDelta
                || nonceDelta != resolutionDelta
                || (
                    resolutionDelta == 0
                        && successor.cumulativeResolutionRoot
                            != source.cumulativeResolutionRoot
                )
                || (
                    resolutionDelta > 0
                        && (
                            successor.cumulativeResolutionRoot == bytes32(0)
                                || successor.cumulativeResolutionRoot
                                    == source.cumulativeResolutionRoot
                        )
                )
                || successor.parentBlockHeight <= source.parentBlockHeight
                || successor.parentChainwork <= source.parentChainwork
                || successor.parentMedianTimePast
                    < source.parentMedianTimePast
                || successor.parentBlockHash == source.parentBlockHash
                || successor.ethereumFinalizedSlot
                    < source.ethereumFinalizedSlot
                || successor.ethereumFinalizedTimestamp
                    < source.ethereumFinalizedTimestamp
                || _absoluteDifference(
                    successor.ethereumFinalizedTimestamp,
                    successor.parentMedianTimePast
                ) > policy.maxControllerAdmissionAgeSeconds
                || successor.weakSubjectivityValidUntil
                    <= successor.ethereumFinalizedTimestamp
                || successor.weakSubjectivityValidUntil
                    - successor.ethereumFinalizedTimestamp
                    > policy.maxWeakSubjectivityPeriodSeconds
        ) revert InvalidCertificate();
    }

    function _encodeIdentities(IdentityClaims memory identities)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            identities.certificateRelayProgramId,
            identities.certificateRelayConfigurationHash,
            identities.parentChainIdentity,
            identities.parentFinalityConfigurationHash,
            identities.weakSubjectivityPolicyHash,
            identities.protocolCoreHash,
            identities.parentGenesisHash,
            identities.elementsGenesisHash,
            identities.controllerProgramConfigurationHash,
            identities.inboundVaultConfigurationHash,
            identities.usddAssetId
        );
    }

    function _encodeAudit(Audit memory audit)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            audit.firstElementsBlockHash,
            audit.lastElementsBlockHash,
            audit.firstElementsBlockHeight,
            audit.lastElementsBlockHeight,
            audit.terminalControllerTransactionId,
            audit.controllerHistoryCommitment,
            audit.elementsInclusionHistoryCommitment,
            audit.bmmHistoryCommitment,
            audit.executionAuditCommitment
        );
    }

    function _encodeCheckpoint(
        ICanonicalParentFinalityReceiptV11.Checkpoint memory checkpoint
    ) private pure returns (bytes memory) {
        return abi.encodePacked(
            checkpoint.blockHashDisplay,
            checkpoint.blockHeight,
            checkpoint.medianTimePast,
            checkpoint.cumulativeChainwork
        );
    }

    function _validPolicy(Policy memory policy)
        private
        pure
        returns (bool)
    {
        return policy.maxControllerAdmissionAgeSeconds != 0
            && policy.maxWeakSubjectivityPeriodSeconds != 0
            && policy.maxControllerSequenceDelta != 0
            && policy.maxResolutionDelta != 0
            && policy.maxResolutionDelta
                <= policy.maxControllerSequenceDelta;
    }

    function _anyZeroIdentities(IdentityClaims memory identities)
        private
        pure
        returns (bool)
    {
        return identities.certificateRelayProgramId == bytes32(0)
            || identities.certificateRelayConfigurationHash == bytes32(0)
            || identities.parentChainIdentity == bytes32(0)
            || identities.parentFinalityConfigurationHash == bytes32(0)
            || identities.weakSubjectivityPolicyHash == bytes32(0)
            || identities.protocolCoreHash == bytes32(0)
            || identities.parentGenesisHash == bytes32(0)
            || identities.elementsGenesisHash == bytes32(0)
            || identities.controllerProgramConfigurationHash == bytes32(0)
            || identities.inboundVaultConfigurationHash == bytes32(0)
            || identities.usddAssetId == bytes32(0);
    }

    function _validCheckpoint(
        ICanonicalParentFinalityReceiptV11.Checkpoint memory checkpoint
    ) private pure returns (bool) {
        return checkpoint.blockHashDisplay != bytes32(0)
            && checkpoint.medianTimePast != 0
            && checkpoint.cumulativeChainwork != 0;
    }

    function _sameCheckpoint(
        ICanonicalParentFinalityReceiptV11.Checkpoint memory left,
        ICanonicalParentFinalityReceiptV11.Checkpoint memory right
    ) private pure returns (bool) {
        return left.blockHashDisplay == right.blockHashDisplay
            && left.blockHeight == right.blockHeight
            && left.medianTimePast == right.medianTimePast
            && left.cumulativeChainwork == right.cumulativeChainwork;
    }

    function _sameState(
        CanonicalControllerState memory left,
        CanonicalControllerState memory right
    ) private pure returns (bool) {
        return keccak256(encodeState(left)) == keccak256(encodeState(right));
    }

    function _absoluteDifference(uint64 left, uint64 right)
        private
        pure
        returns (uint64)
    {
        return left >= right ? left - right : right - left;
    }

    function _decodeIdentities(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (IdentityClaims memory identities)
    {
        identities.certificateRelayProgramId = _load(encoded, offset);
        identities.certificateRelayConfigurationHash =
            _load(encoded, offset + 32);
        identities.parentChainIdentity = _load(encoded, offset + 64);
        identities.parentFinalityConfigurationHash =
            _load(encoded, offset + 96);
        identities.weakSubjectivityPolicyHash =
            _load(encoded, offset + 128);
        identities.protocolCoreHash = _load(encoded, offset + 160);
        identities.parentGenesisHash = _load(encoded, offset + 192);
        identities.elementsGenesisHash = _load(encoded, offset + 224);
        identities.controllerProgramConfigurationHash =
            _load(encoded, offset + 256);
        identities.inboundVaultConfigurationHash =
            _load(encoded, offset + 288);
        identities.usddAssetId = _load(encoded, offset + 320);
    }

    function _decodeState(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (CanonicalControllerState memory state)
    {
        state.controllerStateHash = _load(encoded, offset);
        state.cumulativeResolutionRoot = _load(encoded, offset + 32);
        state.parentBlockHash = _load(encoded, offset + 64);
        state.controllerSequence = _u64(encoded, offset + 96);
        state.resolutionCount = _u64(encoded, offset + 104);
        state.nextResolutionNonce = _u64(encoded, offset + 112);
        state.parentBlockHeight = _u64(encoded, offset + 120);
        state.parentMedianTimePast = _u64(encoded, offset + 128);
        state.parentChainwork = uint256(_load(encoded, offset + 136));
        state.ethereumFinalizedSlot = _u64(encoded, offset + 168);
        state.ethereumFinalizedTimestamp = _u64(encoded, offset + 176);
        state.weakSubjectivityValidUntil = _u64(encoded, offset + 184);
    }

    function _decodeCheckpoint(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (ICanonicalParentFinalityReceiptV11.Checkpoint memory checkpoint)
    {
        checkpoint.blockHashDisplay = _load(encoded, offset);
        checkpoint.blockHeight = _u32(encoded, offset + 32);
        checkpoint.medianTimePast = _u32(encoded, offset + 36);
        checkpoint.cumulativeChainwork =
            uint256(_load(encoded, offset + 40));
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

    function _address(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (address value)
    {
        value = address(uint160(uint256(_load(encoded, offset)) >> 96));
    }

    function _u8(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint8)
    {
        return uint8(uint256(_load(encoded, offset)) >> 248);
    }

    function _u16(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint16)
    {
        return uint16(uint256(_load(encoded, offset)) >> 240);
    }

    function _u32(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint32)
    {
        return uint32(uint256(_load(encoded, offset)) >> 224);
    }

    function _u64(bytes calldata encoded, uint256 offset)
        private
        pure
        returns (uint64)
    {
        return uint64(uint256(_load(encoded, offset)) >> 192);
    }
}
