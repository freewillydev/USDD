// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICanonicalParentFinalityReceiptV11} from
    "./interfaces/ICanonicalParentFinalityReceiptV11.sol";
import {IMinerApprovedControllerRelayV11} from
    "./interfaces/IMinerApprovedControllerRelayV11.sol";
import {IV11AllSlotReplayProofVerifier} from
    "./interfaces/IV11AllSlotReplayProofVerifier.sol";
import {V11AuthenticatedConsumption} from
    "./libraries/V11AuthenticatedConsumption.sol";
import {V11CanonicalFinalityEncoding} from
    "./libraries/V11CanonicalFinalityEncoding.sol";
import {V11MinerControllerEncoding} from
    "./libraries/V11MinerControllerEncoding.sol";

/// @title ControllerCertificateRelayV11
/// @notice Ownerless immutable relay for the explicitly miner-approved V11
///         controller-certificate profile.
/// @dev SECURITY BOUNDARY: this profile proves exact parent-chain M3/M4/M6
///      acceptance and live retained-range canonical finality for a fixed
///      controller certificate. It does not prove full Elements transaction
///      execution. The stronger recursive-Elements profile has a different
///      verifier interface, manifest, security model, and deployment.
///
/// The relay has no owner, setter, proxy, migration, pause, arbitrary call, or
/// caller-supplied finality receipt. One advance either commits the journal,
/// live finality cursor, controller endpoint, and all three exactly-once sparse
/// insertions together, or changes none of them.
contract ControllerCertificateRelayV11 is
    IMinerApprovedControllerRelayV11
{
    using V11AuthenticatedConsumption for
        V11AuthenticatedConsumption.State;

    bool public constant PRODUCTION_READY = false;
    uint8 public constant REQUIRED_DRIVECHAIN_SLOT = 24;
    bytes8 public constant RELAY_CONFIG_MAGIC = bytes8("USDDRV11");
    uint16 public constant RELAY_CONFIG_SCHEMA = 1;
    uint256 public constant RELAY_CONFIG_BYTES = 1_034;
    uint256 public constant MAX_PROOF_BYTES = 32 * 1024 * 1024;
    uint256 public constant SPARSE_PROOFS_BYTES = 3 * 256 * 32;
    uint64 public constant ABSOLUTE_MAX_ADMISSION_AGE_SECONDS = 6 hours;
    uint64 public constant ABSOLUTE_MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS =
        60 days;
    uint64 public constant ABSOLUTE_MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS =
        1 hours;
    bytes32 public constant SECURITY_MODEL_ID =
        0x7ac67122d2dd491a8de4eb1b86651b39613b40ea18b549f950f49fdb7d8afc8a;
    bytes32 public constant SECURITY_STATUS =
        keccak256(
            "V11_MINER_AUTHORITY_PROFILE; FREEZE_IDENTITIES_GUEST_FINALITY_SOURCE_AND_AUDITS_REQUIRED"
        );
    bytes32 public constant EXACT_PARENT_CHAIN_IDENTITY =
        0x940965345d979242258482c7fca86136e894fd66b3e897c9ed2ff1f231f13138;
    bytes32 public constant EXACT_PARENT_GENESIS_HASH =
        0x00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6;
    bytes32 public constant EXACT_PARENT_GENESIS_SERIALIZATION_HASH =
        0xc8abc5554d8a4e1134b27050f0a6a8fc616196bfdd381fb49f49fdea6a811675;
    uint32 public constant EXACT_PARENT_GENESIS_MEDIAN_TIME_PAST =
        1_598_918_400;
    uint256 public constant EXACT_PARENT_GENESIS_CHAINWORK = 0x49d414;

    bytes internal constant FINALITY_CONFIG_DOMAIN =
        "USDD_V11_CANONICAL_FINALITY_CONFIG";
    bytes32 internal constant RELAY_CONFIG_DOMAIN =
        keccak256("USDD_V11_MINER_CONTROLLER_RELAY_CONFIG");

    struct RelayConfig {
        address proofVerifier;
        bytes32 proofVerifierCodehash;
        bytes32 proofProgramId;
        bytes32 proofConfigHash;
        address canonicalFinalitySource;
        bytes32 canonicalFinalitySourceCodehash;
        bytes32 canonicalFinalitySourceIdentity;
        bytes32 canonicalFinalitySourceInterfaceHash;
        bytes32 forkAvailabilityPolicyHash;
        bytes32 allSlotReplayProfileCommitment;
        bytes32 initialAllSlotCheckpointCommitment;
        bytes32 manifestId;
        V11MinerControllerEncoding.Policy policy;
        V11MinerControllerEncoding.IdentityClaims identities;
        V11MinerControllerEncoding.CanonicalControllerState initialControllerState;
        ICanonicalParentFinalityReceiptV11.Checkpoint initialFinalityCheckpoint;
        uint64 minimumRecoveryMarginSeconds;
        uint64 maxFutureTimestampDriftSeconds;
    }

    struct ConsumptionAdvance {
        V11AuthenticatedConsumption.State source;
        V11AuthenticatedConsumption.State afterCertificate;
        V11AuthenticatedConsumption.State afterM6;
        V11AuthenticatedConsumption.State next;
        uint64 nextCount;
    }

    // These configuration words are written once in the constructor. The
    // ownerless contract exposes no code path that can alter them; storing
    // them in ordinary slots keeps the bytecode compatible with the pinned
    // Shanghai compiler without changing their logical immutability.
    IV11AllSlotReplayProofVerifier public PROOF_VERIFIER;
    bytes32 public PROOF_VERIFIER_CODEHASH;
    bytes32 public override verifierProgramId;
    bytes32 public PROOF_CONFIG_HASH;
    ICanonicalParentFinalityReceiptV11 public CANONICAL_FINALITY_SOURCE;
    bytes32 public CANONICAL_FINALITY_SOURCE_CODEHASH;
    bytes32 public CANONICAL_FINALITY_SOURCE_IDENTITY;
    bytes32 public CANONICAL_FINALITY_SOURCE_INTERFACE_HASH;
    bytes32 public CANONICAL_FINALITY_CONFIGURATION_HASH;
    bytes32 public FORK_AVAILABILITY_POLICY_HASH;
    bytes32 public ALL_SLOT_REPLAY_PROFILE_COMMITMENT;
    bytes32 public INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT;
    bytes32 public MANIFEST_ID;
    bytes32 public CONTROLLER_DEPLOYMENT_COMMITMENT;
    bytes32 public override verifierConfigHash;
    uint64 public MINIMUM_RECOVERY_MARGIN_SECONDS;
    uint64 public MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS;

    bytes32 public CERTIFICATE_IDENTITY_CLAIMS_HASH;
    bytes32 public INITIAL_CONTROLLER_STATE_HASH;

    bool public initialized;
    uint64 public acceptedCertificateCount;
    bytes32 public currentAllSlotCheckpointCommitment;

    V11MinerControllerEncoding.CanonicalControllerState private _storedState;
    V11MinerControllerEncoding.Policy private _policyConfig;
    bytes32 private _storedStateHash;
    V11AuthenticatedConsumption.State private _consumption;
    ICanonicalParentFinalityReceiptV11.Cursor private _finalityCursor;
    ControllerSnapshot private _controllerSnapshot;
    uint256 private _reentrancyLock = 1;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error InvalidConfiguration();
    error WrongSecurityProfile();
    error ProofVerifierCodeChanged(bytes32 expected, bytes32 actual);
    error ProofVerifierIdentityChanged();
    error FinalitySourceCodeChanged(bytes32 expected, bytes32 actual);
    error FinalitySourceIdentityChanged();
    error WrongJournalSource();
    error WrongCertificateDeployment();
    error CertificateCommitmentMismatch(bytes32 expected, bytes32 actual);
    error InvalidFinalityRequest();
    error InvalidFinalityResponse();
    error ParentReplayProofRejected(bytes32 publicValuesHash);
    error ProofTooLarge(uint256 supplied, uint256 maximum);
    error ConsumptionSummaryMismatch();
    error CounterOverflow();
    error InvalidLease();
    error ReentrantCall();

    event ConsumptionInserted(
        uint64 indexed acceptanceIndex,
        uint8 indexed namespace,
        bytes32 indexed identifier,
        bytes32 namespacedKey,
        bytes32 priorRoot,
        bytes32 nextRoot,
        uint64 nextNamespaceCount
    );

    event ControllerCertificateAccepted(
        bytes32 indexed acceptanceCommitment,
        bytes32 indexed certificateCommitment,
        bytes32 indexed approvedM6id,
        bytes32 journalCommitment,
        bytes32 finalitySubject,
        bytes32 finalityReceiptId,
        uint64 finalityReceiptEpoch,
        uint64 acceptedCertificateCount,
        address submitter
    );

    event ControllerCheckpointAdvanced(
        bytes32 indexed acceptanceCommitment,
        bytes32 sourceControllerStateHash,
        bytes32 successorControllerStateHash,
        bytes32 sourceAllSlotCheckpointCommitment,
        bytes32 nextAllSlotCheckpointCommitment,
        bytes32 sourceConsumptionRoot,
        bytes32 nextConsumptionRoot
    );

    event CanonicalFinalityObserved(
        bytes32 indexed acceptanceCommitment,
        ICanonicalParentFinalityReceiptV11.Checkpoint candidate,
        ICanonicalParentFinalityReceiptV11.Checkpoint observedFinalizedHead
    );

    constructor(bytes memory encodedConfig) {
        RelayConfig memory config = _decodeRelayConfig(encodedConfig);
        _validateConstructorConfig(config);
        bytes32 finalityConfigurationHash =
            _finalityConfigurationHash(config);
        _validateDependencyConfiguration(
            config, finalityConfigurationHash
        );
        bytes32 initialStateHash =
            V11MinerControllerEncoding.canonicalStateHash(
                config.initialControllerState
            );
        V11MinerControllerEncoding.validateInitialState(
            config.policy, config.initialControllerState
        );
        bytes32 deploymentCommitment = _deploymentCommitment(
            config, initialStateHash, finalityConfigurationHash
        );
        _storeFixedConfiguration(
            config,
            finalityConfigurationHash,
            initialStateHash,
            deploymentCommitment
        );
        _initializeReplayState(config, initialStateHash);
    }

    function _validateDependencyConfiguration(
        RelayConfig memory config,
        bytes32 finalityConfigurationHash
    ) private view {
        _validateProofVerifierConfiguration(
            config, finalityConfigurationHash
        );
        _validateFinalitySourceConfiguration(
            config, finalityConfigurationHash
        );
    }

    function _validateProofVerifierConfiguration(
        RelayConfig memory config,
        bytes32 finalityConfigurationHash
    ) private view {
        IV11AllSlotReplayProofVerifier proofVerifier =
            IV11AllSlotReplayProofVerifier(config.proofVerifier);
        if (
            proofVerifier.verifierProgramId() != config.proofProgramId
                || proofVerifier.verifierConfigHash()
                    != config.proofConfigHash
        ) revert InvalidConfiguration();
        if (
            proofVerifier.allSlotReplayProfileCommitment()
                    != config.allSlotReplayProfileCommitment
                || proofVerifier.canonicalFinalityConfigurationHash()
                    != finalityConfigurationHash
                || proofVerifier.exactParentGenesisSerializationHash()
                    != EXACT_PARENT_GENESIS_SERIALIZATION_HASH
                || proofVerifier.initialAllSlotCheckpointCommitment()
                    != config.initialAllSlotCheckpointCommitment
        ) revert InvalidConfiguration();
    }

    function _validateFinalitySourceConfiguration(
        RelayConfig memory config,
        bytes32 finalityConfigurationHash
    ) private view {
        ICanonicalParentFinalityReceiptV11 finalitySource =
            ICanonicalParentFinalityReceiptV11(
                config.canonicalFinalitySource
            );
        if (
            finalitySource.sourceIdentity()
                    != config.canonicalFinalitySourceIdentity
                || finalitySource.sourceInterfaceHash()
                    != config.canonicalFinalitySourceInterfaceHash
                || finalitySource.canonicalFinalityConfigurationHash()
                    != finalityConfigurationHash
                || finalitySource.parentReplayProfileCommitment()
                    != config.allSlotReplayProfileCommitment
                || finalitySource
                        .initialParentReplayCheckpointCommitment()
                    != config.initialAllSlotCheckpointCommitment
        ) revert InvalidConfiguration();
    }

    function _deploymentCommitment(
        RelayConfig memory config,
        bytes32 initialStateHash,
        bytes32 finalityConfigurationHash
    ) private view returns (bytes32) {
        V11MinerControllerEncoding.DeploymentFields memory fields;
        fields.manifestId = config.manifestId;
        fields.ethereumChainId = block.chainid;
        fields.relayAddress = address(this);
        fields.drivechainSlot = REQUIRED_DRIVECHAIN_SLOT;
        fields.policy = config.policy;
        fields.identities = config.identities;
        fields.initialControllerStateHash = initialStateHash;
        fields.allSlotReplayProfileCommitment =
            config.allSlotReplayProfileCommitment;
        fields.canonicalFinalityConfigurationHash =
            finalityConfigurationHash;
        fields.initialAllSlotCheckpointCommitment =
            config.initialAllSlotCheckpointCommitment;
        return V11MinerControllerEncoding.deploymentCommitment(fields);
    }

    function _storeFixedConfiguration(
        RelayConfig memory config,
        bytes32 finalityConfigurationHash,
        bytes32 initialStateHash,
        bytes32 deploymentCommitment
    ) private {
        PROOF_VERIFIER =
            IV11AllSlotReplayProofVerifier(config.proofVerifier);
        PROOF_VERIFIER_CODEHASH = config.proofVerifierCodehash;
        verifierProgramId = config.proofProgramId;
        PROOF_CONFIG_HASH = config.proofConfigHash;
        CANONICAL_FINALITY_SOURCE = ICanonicalParentFinalityReceiptV11(
            config.canonicalFinalitySource
        );
        CANONICAL_FINALITY_SOURCE_CODEHASH =
            config.canonicalFinalitySourceCodehash;
        CANONICAL_FINALITY_SOURCE_IDENTITY =
            config.canonicalFinalitySourceIdentity;
        CANONICAL_FINALITY_SOURCE_INTERFACE_HASH =
            config.canonicalFinalitySourceInterfaceHash;
        CANONICAL_FINALITY_CONFIGURATION_HASH = finalityConfigurationHash;
        FORK_AVAILABILITY_POLICY_HASH =
            config.forkAvailabilityPolicyHash;
        ALL_SLOT_REPLAY_PROFILE_COMMITMENT =
            config.allSlotReplayProfileCommitment;
        INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT =
            config.initialAllSlotCheckpointCommitment;
        MANIFEST_ID = config.manifestId;
        CONTROLLER_DEPLOYMENT_COMMITMENT = deploymentCommitment;
        MINIMUM_RECOVERY_MARGIN_SECONDS =
            config.minimumRecoveryMarginSeconds;
        MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS =
            config.maxFutureTimestampDriftSeconds;

        CERTIFICATE_IDENTITY_CLAIMS_HASH =
            V11MinerControllerEncoding.identityClaimsHash(
                config.identities
            );
        INITIAL_CONTROLLER_STATE_HASH = initialStateHash;

        verifierConfigHash = _relayConfigurationHash(
            config, deploymentCommitment, finalityConfigurationHash
        );
    }

    function _initializeReplayState(
        RelayConfig memory config,
        bytes32 initialStateHash
    ) private {
        _storedState = config.initialControllerState;
        _policyConfig = config.policy;
        _storedStateHash = initialStateHash;
        _consumption = V11AuthenticatedConsumption.empty();
        _finalityCursor = ICanonicalParentFinalityReceiptV11.Cursor({
            receiptId: bytes32(0),
            receiptEpoch: 0,
            checkpoint: config.initialFinalityCheckpoint
        });
        currentAllSlotCheckpointCommitment =
            config.initialAllSlotCheckpointCommitment;
    }

    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert ReentrantCall();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    function securityModelId() external pure override returns (bytes32) {
        return SECURITY_MODEL_ID;
    }

    function controllerSnapshot()
        external
        view
        override
        returns (ControllerSnapshot memory)
    {
        return _controllerSnapshot;
    }

    function storedControllerState()
        external
        view
        returns (V11MinerControllerEncoding.CanonicalControllerState memory)
    {
        return _storedState;
    }

    function storedControllerStateHash() external view returns (bytes32) {
        return _storedStateHash;
    }

    function certificatePolicy()
        external
        view
        returns (V11MinerControllerEncoding.Policy memory)
    {
        return _policyConfig;
    }

    function consumptionState()
        external
        view
        returns (bytes32 root, uint64[3] memory counts)
    {
        V11AuthenticatedConsumption.State memory state = _consumption;
        return (state.root, state.counts);
    }

    function finalityCursor()
        external
        view
        returns (ICanonicalParentFinalityReceiptV11.Cursor memory)
    {
        return _finalityCursor;
    }

    function stateDigest() external view returns (bytes32) {
        bytes32 finalityDigest = keccak256(
            abi.encode(
                _finalityCursor.receiptId,
                _finalityCursor.receiptEpoch,
                _finalityCursor.checkpoint.blockHashDisplay,
                _finalityCursor.checkpoint.blockHeight,
                _finalityCursor.checkpoint.medianTimePast,
                _finalityCursor.checkpoint.cumulativeChainwork
            )
        );
        bytes32 consumptionCommitment =
            V11AuthenticatedConsumption.stateCommitment(_consumption);
        return keccak256(
            abi.encode(
                initialized,
                acceptedCertificateCount,
                currentAllSlotCheckpointCommitment,
                _storedStateHash,
                consumptionCommitment,
                finalityDigest,
                _controllerSnapshot.acceptedAt,
                _controllerSnapshot.admissionValidUntil
            )
        );
    }

    /// @notice Permissionlessly accept one adjacent V11 miner-approved
    ///         certificate after exact parent replay and live finality checks.
    function advance(
        bytes calldata journalBytes,
        bytes calldata certificateBytes,
        bytes calldata sparseProofBytes,
        bytes calldata proof
    ) external nonReentrant {
        if (proof.length > MAX_PROOF_BYTES) {
            revert ProofTooLarge(proof.length, MAX_PROOF_BYTES);
        }
        if (sparseProofBytes.length != SPARSE_PROOFS_BYTES) {
            revert InvalidConfiguration();
        }
        _requireDependencyIdentities();

        V11MinerControllerEncoding.Journal memory journalMemory =
            V11MinerControllerEncoding.decodeJournal(journalBytes);
        V11MinerControllerEncoding.Certificate memory certificateMemory =
            V11MinerControllerEncoding.decodeCertificate(certificateBytes);
        _validateJournalSource(journalMemory);
        _validateCertificate(
            certificateMemory,
            journalMemory,
            V11MinerControllerEncoding.certificateCommitment(
                certificateBytes
            )
        );

        (bytes32 publicValuesHash, bytes32 journalCommitment) =
            V11MinerControllerEncoding.journalHashes(journalBytes);
        _requireProof(publicValuesHash, proof);

        ICanonicalParentFinalityReceiptV11.Cursor memory prior =
            _finalityCursor;
        V11CanonicalFinalityEncoding.SubjectFields memory subjectFields =
            V11CanonicalFinalityEncoding.SubjectFields({
                profileCommitment: ALL_SLOT_REPLAY_PROFILE_COMMITMENT,
                controllerDeploymentCommitment: CONTROLLER_DEPLOYMENT_COMMITMENT,
                allSlotJournalCommitment: journalCommitment,
                prior: prior,
                candidate: journalMemory
                    .acceptedCertificate
                    .finalizationCheckpoint,
                certificateCommitment: journalMemory
                    .acceptedCertificate
                    .certificateCommitment,
                approvedM6id: journalMemory
                    .acceptedCertificate
                    .approvedM6id,
                inclusionBlockHash: journalMemory
                    .acceptedCertificate
                    .inclusionBlockHash,
                inclusionHeight: journalMemory
                    .acceptedCertificate
                    .inclusionHeight
            });
        bytes32 subject = V11CanonicalFinalityEncoding.subject(subjectFields);
        ICanonicalParentFinalityReceiptV11.RangeReceipt memory receipt =
            _callLiveFinality(
                subject,
                prior,
                journalMemory.acceptedCertificate.finalizationCheckpoint
            );
        _validateFinalityResponse(
            subject,
            prior,
            journalMemory.acceptedCertificate.finalizationCheckpoint,
            journalMemory.acceptedCertificate.inclusionHeight,
            receipt
        );
        _requireDependencyIdentities();

        _commitAdvance(
            journalMemory,
            certificateMemory,
            sparseProofBytes,
            journalCommitment,
            subject,
            receipt
        );
    }

    function _commitAdvance(
        V11MinerControllerEncoding.Journal memory journal,
        V11MinerControllerEncoding.Certificate memory certificate,
        bytes calldata sparseProofBytes,
        bytes32 journalCommitment,
        bytes32 subject,
        ICanonicalParentFinalityReceiptV11.RangeReceipt memory receipt
    ) private {
        ConsumptionAdvance memory consumption = _consumeIdentifiers(
            journal, receipt.receiptId, sparseProofBytes
        );
        bytes32 sourceStateHash = _storedStateHash;
        bytes32 successorStateHash =
            V11MinerControllerEncoding.canonicalStateHash(
                certificate.successor
            );
        bytes32 acceptanceCommitment = _acceptanceCommitment(
            journalCommitment,
            subject,
            receipt.receiptId,
            sourceStateHash,
            successorStateHash,
            consumption.source,
            consumption.next
        );
        uint64 acceptedAt = _safeUint64(block.timestamp);
        uint64 admissionValidUntil =
            _deriveAdmissionValidUntil(certificate.successor);

        _emitConsumptionEvents(
            consumption.nextCount,
            journal,
            receipt.receiptId,
            consumption.source,
            consumption.afterCertificate,
            consumption.afterM6,
            consumption.next
        );

        initialized = true;
        acceptedCertificateCount = consumption.nextCount;
        currentAllSlotCheckpointCommitment =
            journal.nextCheckpointCommitment;
        _storedState = certificate.successor;
        _storedStateHash = successorStateHash;
        _consumption = consumption.next;
        _finalityCursor = ICanonicalParentFinalityReceiptV11.Cursor({
            receiptId: receipt.receiptId,
            receiptEpoch: receipt.receiptEpoch,
            checkpoint: journal.acceptedCertificate.finalizationCheckpoint
        });
        _controllerSnapshot = _snapshot(
            certificate.successor, acceptedAt, admissionValidUntil
        );

        _emitPrimaryAcceptance(
            acceptanceCommitment,
            journal,
            journalCommitment,
            subject,
            receipt,
            consumption.nextCount
        );
        _emitCheckpointAdvance(
            acceptanceCommitment,
            journal,
            sourceStateHash,
            successorStateHash,
            consumption
        );
        _emitFinalityObservation(
            acceptanceCommitment,
            journal,
            receipt
        );
    }

    function _emitPrimaryAcceptance(
        bytes32 acceptanceCommitment,
        V11MinerControllerEncoding.Journal memory journal,
        bytes32 journalCommitment,
        bytes32 subject,
        ICanonicalParentFinalityReceiptV11.RangeReceipt memory receipt,
        uint64 nextCount
    ) private {
        emit ControllerCertificateAccepted(
            acceptanceCommitment,
            journal.acceptedCertificate.certificateCommitment,
            journal.acceptedCertificate.approvedM6id,
            journalCommitment,
            subject,
            receipt.receiptId,
            receipt.receiptEpoch,
            nextCount,
            msg.sender
        );
    }

    function _emitCheckpointAdvance(
        bytes32 acceptanceCommitment,
        V11MinerControllerEncoding.Journal memory journal,
        bytes32 sourceStateHash,
        bytes32 successorStateHash,
        ConsumptionAdvance memory consumption
    ) private {
        emit ControllerCheckpointAdvanced(
            acceptanceCommitment,
            sourceStateHash,
            successorStateHash,
            journal.sourceCheckpointCommitment,
            journal.nextCheckpointCommitment,
            consumption.source.root,
            consumption.next.root
        );
    }

    function _emitFinalityObservation(
        bytes32 acceptanceCommitment,
        V11MinerControllerEncoding.Journal memory journal,
        ICanonicalParentFinalityReceiptV11.RangeReceipt memory receipt
    ) private {
        emit CanonicalFinalityObserved(
            acceptanceCommitment,
            journal.acceptedCertificate.finalizationCheckpoint,
            receipt.observedFinalizedHead
        );
    }

    function _consumeIdentifiers(
        V11MinerControllerEncoding.Journal memory journal,
        bytes32 receiptId,
        bytes calldata sparseProofBytes
    ) private view returns (ConsumptionAdvance memory consumption) {
        consumption.source = _consumption;
        consumption.afterCertificate = consumption.source.insertAbsent(
            1,
            journal.acceptedCertificate.certificateCommitment,
            _sparseProof(sparseProofBytes, 0)
        );
        consumption.afterM6 = consumption.afterCertificate.insertAbsent(
            2,
            journal.acceptedCertificate.approvedM6id,
            _sparseProof(sparseProofBytes, 1)
        );
        consumption.next = consumption.afterM6.insertAbsent(
            3, receiptId, _sparseProof(sparseProofBytes, 2)
        );
        if (acceptedCertificateCount == type(uint64).max) {
            revert CounterOverflow();
        }
        consumption.nextCount = acceptedCertificateCount + 1;
        if (
            consumption.next.counts[0] != consumption.nextCount
                || consumption.next.counts[1] != consumption.nextCount
                || consumption.next.counts[2] != consumption.nextCount
        ) revert ConsumptionSummaryMismatch();
    }

    function _validateConstructorConfig(RelayConfig memory config)
        private
        view
    {
        _validateDependencyAddresses(config);
        _validatePolicyBounds(config);
        _validateProtocolIdentities(config);
        _validateGenesisAnchor(config);
    }

    function _validateDependencyAddresses(RelayConfig memory config)
        private
        view
    {
        if (
            config.proofVerifier == address(0)
                || config.proofVerifierCodehash == bytes32(0)
                || config.proofProgramId == bytes32(0)
                || config.proofConfigHash == bytes32(0)
                || config.canonicalFinalitySource == address(0)
                || config.canonicalFinalitySourceCodehash == bytes32(0)
                || config.canonicalFinalitySourceIdentity == bytes32(0)
                || config.canonicalFinalitySourceInterfaceHash == bytes32(0)
                || config.forkAvailabilityPolicyHash == bytes32(0)
                || config.allSlotReplayProfileCommitment == bytes32(0)
                || config.initialAllSlotCheckpointCommitment == bytes32(0)
                || config.manifestId == bytes32(0)
        ) revert ZeroIdentity();
        if (config.proofVerifier.code.length == 0) {
            revert AddressHasNoCode(config.proofVerifier);
        }
        if (config.canonicalFinalitySource.code.length == 0) {
            revert AddressHasNoCode(config.canonicalFinalitySource);
        }
        if (
            config.proofVerifier.codehash != config.proofVerifierCodehash
                || config.canonicalFinalitySource.codehash
                    != config.canonicalFinalitySourceCodehash
        ) revert InvalidConfiguration();
    }

    function _validatePolicyBounds(RelayConfig memory config)
        private
        pure
    {
        if (
            !V11MinerControllerEncoding.validPolicy(config.policy)
                || config.policy.maxControllerAdmissionAgeSeconds
                    > ABSOLUTE_MAX_ADMISSION_AGE_SECONDS
                || config.policy.maxWeakSubjectivityPeriodSeconds
                    > ABSOLUTE_MAX_WEAK_SUBJECTIVITY_PERIOD_SECONDS
                || config.minimumRecoveryMarginSeconds == 0
                || config.policy.maxWeakSubjectivityPeriodSeconds
                    <= config.minimumRecoveryMarginSeconds
                        + config.policy.maxControllerAdmissionAgeSeconds
                || config.maxFutureTimestampDriftSeconds
                    > ABSOLUTE_MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS
        ) revert InvalidConfiguration();
    }

    function _validateProtocolIdentities(RelayConfig memory config)
        private
        pure
    {
        if (
            config.identities.certificateRelayProgramId
                    != config.proofProgramId
                || config.identities.certificateRelayConfigurationHash
                    != config.allSlotReplayProfileCommitment
                || config.identities.parentChainIdentity
                    != EXACT_PARENT_CHAIN_IDENTITY
        ) revert InvalidConfiguration();
        if (
            config.identities.parentFinalityConfigurationHash
                    != _finalityConfigurationHash(config)
                || config.identities.parentGenesisHash
                    != EXACT_PARENT_GENESIS_HASH
        ) revert InvalidConfiguration();
        if (
            config.identities.weakSubjectivityPolicyHash == bytes32(0)
                || config.identities.protocolCoreHash == bytes32(0)
                || config.identities.elementsGenesisHash == bytes32(0)
        ) revert InvalidConfiguration();
        if (
            config.identities.controllerProgramConfigurationHash
                    == bytes32(0)
                || config.identities.inboundVaultConfigurationHash
                    == bytes32(0)
                || config.identities.usddAssetId == bytes32(0)
        ) revert InvalidConfiguration();
    }

    function _validateGenesisAnchor(RelayConfig memory config)
        private
        pure
    {
        if (
            config.initialFinalityCheckpoint.blockHashDisplay
                    != EXACT_PARENT_GENESIS_HASH
                || config.initialFinalityCheckpoint.blockHeight != 0
                || config.initialFinalityCheckpoint.medianTimePast
                    != EXACT_PARENT_GENESIS_MEDIAN_TIME_PAST
                || config.initialFinalityCheckpoint.cumulativeChainwork
                    != EXACT_PARENT_GENESIS_CHAINWORK
        ) revert InvalidConfiguration();
    }

    function _acceptanceCommitment(
        bytes32 journalCommitment,
        bytes32 subject,
        bytes32 receiptId,
        bytes32 sourceStateHash,
        bytes32 successorStateHash,
        V11AuthenticatedConsumption.State memory sourceConsumption,
        V11AuthenticatedConsumption.State memory nextConsumption
    ) private view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                V11MinerControllerEncoding.ACCEPTANCE_DOMAIN,
                CONTROLLER_DEPLOYMENT_COMMITMENT,
                journalCommitment,
                subject,
                receiptId,
                sourceStateHash,
                successorStateHash,
                V11AuthenticatedConsumption.stateCommitment(
                    sourceConsumption
                ),
                V11AuthenticatedConsumption.stateCommitment(nextConsumption)
            )
        );
    }

    function _decodeRelayConfig(bytes memory encoded)
        private
        pure
        returns (RelayConfig memory config)
    {
        if (
            encoded.length != RELAY_CONFIG_BYTES
                || bytes8(_memoryWord(encoded, 0)) != RELAY_CONFIG_MAGIC
                || _memoryU16(encoded, 8) != RELAY_CONFIG_SCHEMA
        ) revert InvalidConfiguration();
        uint256 offset = 10;
        config.proofVerifier = _memoryAddress(encoded, offset);
        config.proofVerifierCodehash = _memoryWord(encoded, offset + 20);
        config.proofProgramId = _memoryWord(encoded, offset + 52);
        config.proofConfigHash = _memoryWord(encoded, offset + 84);
        config.canonicalFinalitySource =
            _memoryAddress(encoded, offset + 116);
        config.canonicalFinalitySourceCodehash =
            _memoryWord(encoded, offset + 136);
        config.canonicalFinalitySourceIdentity =
            _memoryWord(encoded, offset + 168);
        config.canonicalFinalitySourceInterfaceHash =
            _memoryWord(encoded, offset + 200);
        config.forkAvailabilityPolicyHash =
            _memoryWord(encoded, offset + 232);
        config.allSlotReplayProfileCommitment =
            _memoryWord(encoded, offset + 264);
        config.initialAllSlotCheckpointCommitment =
            _memoryWord(encoded, offset + 296);
        config.manifestId = _memoryWord(encoded, offset + 328);
        config.policy = V11MinerControllerEncoding.Policy({
            maxControllerAdmissionAgeSeconds: _memoryU64(
                encoded, offset + 360
            ),
            maxWeakSubjectivityPeriodSeconds: _memoryU64(
                encoded, offset + 368
            ),
            maxControllerSequenceDelta: _memoryU64(
                encoded, offset + 376
            ),
            maxResolutionDelta: _memoryU64(encoded, offset + 384)
        });
        config.identities =
            _decodeMemoryIdentities(encoded, offset + 392);
        config.initialControllerState =
            _decodeMemoryState(encoded, offset + 744);
        config.initialFinalityCheckpoint =
            _decodeMemoryCheckpoint(encoded, offset + 936);
        config.minimumRecoveryMarginSeconds =
            _memoryU64(encoded, offset + 1008);
        config.maxFutureTimestampDriftSeconds =
            _memoryU64(encoded, offset + 1016);
    }

    function _validateJournalSource(
        V11MinerControllerEncoding.Journal memory journal
    ) private view {
        V11MinerControllerEncoding.validateJournal(journal);
        if (
            journal.profileCommitment
                    != ALL_SLOT_REPLAY_PROFILE_COMMITMENT
                || journal.sourceCheckpointCommitment
                    != currentAllSlotCheckpointCommitment
                || !V11MinerControllerEncoding.sameCheckpoint(
                    journal.sourceParentCheckpoint,
                    _finalityCursor.checkpoint
                )
        ) revert WrongJournalSource();
    }

    function _validateCertificate(
        V11MinerControllerEncoding.Certificate memory certificate,
        V11MinerControllerEncoding.Journal memory journal,
        bytes32 commitment
    ) private view {
        if (
            certificate.manifestId != MANIFEST_ID
                || certificate.ethereumChainId != block.chainid
                || certificate.relayAddress != address(this)
                || certificate.drivechainSlot != REQUIRED_DRIVECHAIN_SLOT
                || !V11MinerControllerEncoding.samePolicy(
                    certificate.policy, _policy()
                )
                || !_identitiesMatch(certificate.identities)
        ) revert WrongCertificateDeployment();
        V11MinerControllerEncoding.validateCertificate(
            certificate,
            _storedState,
            _storedStateHash,
            acceptedCertificateCount == 0
        );
        if (
            commitment
                != journal.acceptedCertificate.certificateCommitment
        ) {
            revert CertificateCommitmentMismatch(
                journal.acceptedCertificate.certificateCommitment,
                commitment
            );
        }
        V11MinerControllerEncoding.validateEventAgainstCertificate(
            journal.acceptedCertificate, certificate
        );
    }

    function _requireProof(bytes32 publicValuesHash, bytes calldata proof)
        private
        view
    {
        (bool ok, bytes memory returned) = address(PROOF_VERIFIER).staticcall(
            abi.encodeCall(
                IV11AllSlotReplayProofVerifier.verifyProof,
                (publicValuesHash, proof)
            )
        );
        if (
            !ok || returned.length != 32
                || abi.decode(returned, (uint256)) != 1
        ) revert ParentReplayProofRejected(publicValuesHash);
    }

    function _callLiveFinality(
        bytes32 subject,
        ICanonicalParentFinalityReceiptV11.Cursor memory prior,
        ICanonicalParentFinalityReceiptV11.Checkpoint memory candidate
    )
        private
        view
        returns (ICanonicalParentFinalityReceiptV11.RangeReceipt memory receipt)
    {
        ICanonicalParentFinalityReceiptV11.RangeRequest memory request =
            ICanonicalParentFinalityReceiptV11.RangeRequest({
                subject: subject,
                prior: prior,
                candidate: candidate
            });
        (bool ok, bytes memory returned) =
            address(CANONICAL_FINALITY_SOURCE).staticcall(
                abi.encodeCall(
                    ICanonicalParentFinalityReceiptV11
                        .verifyRetainedCanonicalRange,
                    (request)
                )
            );
        if (!ok || returned.length != 192) {
            revert InvalidFinalityResponse();
        }
        receipt = abi.decode(
            returned, (ICanonicalParentFinalityReceiptV11.RangeReceipt)
        );
    }

    function _validateFinalityResponse(
        bytes32 subject,
        ICanonicalParentFinalityReceiptV11.Cursor memory prior,
        ICanonicalParentFinalityReceiptV11.Checkpoint memory candidate,
        uint32 inclusionHeight,
        ICanonicalParentFinalityReceiptV11.RangeReceipt memory receipt
    ) private pure {
        if (
            prior.checkpoint.blockHeight >= candidate.blockHeight
                || prior.checkpoint.cumulativeChainwork
                    >= candidate.cumulativeChainwork
                || inclusionHeight > candidate.blockHeight
        ) revert InvalidFinalityRequest();
        ICanonicalParentFinalityReceiptV11.Checkpoint memory head =
            receipt.observedFinalizedHead;
        if (
            receipt.receiptId == bytes32(0)
                || receipt.receiptEpoch <= prior.receiptEpoch
                || head.blockHashDisplay == bytes32(0)
                || head.medianTimePast == 0
                || head.cumulativeChainwork == 0
                || head.blockHeight < candidate.blockHeight
                || head.cumulativeChainwork < candidate.cumulativeChainwork
                || head.medianTimePast < candidate.medianTimePast
                || receipt.receiptId
                    != V11CanonicalFinalityEncoding.receiptId(
                        subject, receipt.receiptEpoch, head
                    )
        ) revert InvalidFinalityResponse();
    }

    function _requireDependencyIdentities() private view {
        bytes32 proofCodehash = address(PROOF_VERIFIER).codehash;
        if (proofCodehash != PROOF_VERIFIER_CODEHASH) {
            revert ProofVerifierCodeChanged(
                PROOF_VERIFIER_CODEHASH, proofCodehash
            );
        }
        if (
            PROOF_VERIFIER.verifierProgramId() != verifierProgramId
                || PROOF_VERIFIER.verifierConfigHash()
                    != PROOF_CONFIG_HASH
                || PROOF_VERIFIER.allSlotReplayProfileCommitment()
                    != ALL_SLOT_REPLAY_PROFILE_COMMITMENT
                || PROOF_VERIFIER.canonicalFinalityConfigurationHash()
                    != CANONICAL_FINALITY_CONFIGURATION_HASH
                || PROOF_VERIFIER.exactParentGenesisSerializationHash()
                    != EXACT_PARENT_GENESIS_SERIALIZATION_HASH
                || PROOF_VERIFIER.initialAllSlotCheckpointCommitment()
                    != INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT
        ) revert ProofVerifierIdentityChanged();

        bytes32 sourceCodehash =
            address(CANONICAL_FINALITY_SOURCE).codehash;
        if (sourceCodehash != CANONICAL_FINALITY_SOURCE_CODEHASH) {
            revert FinalitySourceCodeChanged(
                CANONICAL_FINALITY_SOURCE_CODEHASH, sourceCodehash
            );
        }
        if (
            CANONICAL_FINALITY_SOURCE.sourceIdentity()
                    != CANONICAL_FINALITY_SOURCE_IDENTITY
                || CANONICAL_FINALITY_SOURCE.sourceInterfaceHash()
                    != CANONICAL_FINALITY_SOURCE_INTERFACE_HASH
                || CANONICAL_FINALITY_SOURCE
                        .canonicalFinalityConfigurationHash()
                    != CANONICAL_FINALITY_CONFIGURATION_HASH
                || CANONICAL_FINALITY_SOURCE
                        .parentReplayProfileCommitment()
                    != ALL_SLOT_REPLAY_PROFILE_COMMITMENT
                || CANONICAL_FINALITY_SOURCE
                        .initialParentReplayCheckpointCommitment()
                    != INITIAL_ALL_SLOT_CHECKPOINT_COMMITMENT
        ) revert FinalitySourceIdentityChanged();
    }

    function _finalityConfigurationHash(RelayConfig memory config)
        private
        pure
        returns (bytes32)
    {
        bytes memory preimage = abi.encodePacked(
            FINALITY_CONFIG_DOMAIN,
            config.canonicalFinalitySourceIdentity,
            config.canonicalFinalitySourceCodehash,
            config.canonicalFinalitySourceInterfaceHash,
            config.forkAvailabilityPolicyHash
        );
        preimage = bytes.concat(
            preimage,
            abi.encodePacked(
                config.initialFinalityCheckpoint.blockHashDisplay,
                config.initialFinalityCheckpoint.blockHeight,
                config.initialFinalityCheckpoint.medianTimePast,
                config.initialFinalityCheckpoint.cumulativeChainwork,
                uint8(1)
            )
        );
        return sha256(preimage);
    }

    function _relayConfigurationHash(
        RelayConfig memory config,
        bytes32 deploymentCommitment,
        bytes32 finalityConfigurationHash
    ) private view returns (bytes32) {
        bytes32 proofBoundary = sha256(
            abi.encode(
                config.proofVerifier,
                config.proofVerifierCodehash,
                config.proofProgramId,
                config.proofConfigHash
            )
        );
        bytes32 finalityBoundary = sha256(
            abi.encode(
                config.canonicalFinalitySource,
                config.canonicalFinalitySourceCodehash,
                finalityConfigurationHash
            )
        );
        return sha256(
            abi.encode(
                RELAY_CONFIG_DOMAIN,
                block.chainid,
                address(this),
                deploymentCommitment,
                proofBoundary,
                finalityBoundary,
                config.minimumRecoveryMarginSeconds,
                config.maxFutureTimestampDriftSeconds,
                SECURITY_MODEL_ID
            )
        );
    }

    function _policy()
        private
        view
        returns (V11MinerControllerEncoding.Policy memory)
    {
        return _policyConfig;
    }

    function _identitiesMatch(
        V11MinerControllerEncoding.IdentityClaims memory identities
    ) private view returns (bool) {
        return V11MinerControllerEncoding.identityClaimsHash(identities)
            == CERTIFICATE_IDENTITY_CLAIMS_HASH;
    }

    function _deriveAdmissionValidUntil(
        V11MinerControllerEncoding.CanonicalControllerState memory state
    ) private view returns (uint64) {
        uint256 latestAllowed =
            block.timestamp + MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS;
        if (
            state.parentMedianTimePast > latestAllowed
                || state.ethereumFinalizedTimestamp > latestAllowed
                || state.weakSubjectivityValidUntil
                    <= MINIMUM_RECOVERY_MARGIN_SECONDS
        ) revert InvalidLease();
        uint64 parentExpiry = _checkedAdd(
            state.parentMedianTimePast,
            _policyConfig.maxControllerAdmissionAgeSeconds
        );
        uint64 ethereumExpiry = _checkedAdd(
            state.ethereumFinalizedTimestamp,
            _policyConfig.maxControllerAdmissionAgeSeconds
        );
        uint64 weakSubjectivityExpiry =
            state.weakSubjectivityValidUntil
                - MINIMUM_RECOVERY_MARGIN_SECONDS;
        uint64 validUntil =
            _min(parentExpiry, _min(ethereumExpiry, weakSubjectivityExpiry));
        if (validUntil <= block.timestamp) revert InvalidLease();
        return validUntil;
    }

    function _snapshot(
        V11MinerControllerEncoding.CanonicalControllerState memory state,
        uint64 acceptedAt,
        uint64 admissionValidUntil
    ) private pure returns (ControllerSnapshot memory) {
        return ControllerSnapshot({
            controllerStateHash: state.controllerStateHash,
            cumulativeResolutionRoot: state.cumulativeResolutionRoot,
            parentBlockHash: state.parentBlockHash,
            controllerSequence: state.controllerSequence,
            resolutionCount: state.resolutionCount,
            nextResolutionNonce: state.nextResolutionNonce,
            parentBlockHeight: state.parentBlockHeight,
            parentMedianTimePast: state.parentMedianTimePast,
            parentChainwork: state.parentChainwork,
            ethereumFinalizedSlot: state.ethereumFinalizedSlot,
            ethereumFinalizedTimestamp: state.ethereumFinalizedTimestamp,
            weakSubjectivityValidUntil: state.weakSubjectivityValidUntil,
            acceptedAt: acceptedAt,
            admissionValidUntil: admissionValidUntil
        });
    }

    function _emitConsumptionEvents(
        uint64 index,
        V11MinerControllerEncoding.Journal memory journal,
        bytes32 receiptId,
        V11AuthenticatedConsumption.State memory source,
        V11AuthenticatedConsumption.State memory afterCertificate,
        V11AuthenticatedConsumption.State memory afterM6,
        V11AuthenticatedConsumption.State memory next
    ) private {
        _emitConsumption(
            index,
            1,
            journal.acceptedCertificate.certificateCommitment,
            source,
            afterCertificate
        );
        _emitConsumption(
            index,
            2,
            journal.acceptedCertificate.approvedM6id,
            afterCertificate,
            afterM6
        );
        _emitConsumption(index, 3, receiptId, afterM6, next);
    }

    function _emitConsumption(
        uint64 index,
        uint8 namespace,
        bytes32 identifier,
        V11AuthenticatedConsumption.State memory prior,
        V11AuthenticatedConsumption.State memory next
    ) private {
        emit ConsumptionInserted(
            index,
            namespace,
            identifier,
            V11AuthenticatedConsumption.namespacedKey(
                namespace, identifier
            ),
            prior.root,
            next.root,
            next.counts[namespace - 1]
        );
    }

    function _checkedAdd(uint64 left, uint64 right)
        private
        pure
        returns (uint64 result)
    {
        uint256 wide = uint256(left) + right;
        if (wide > type(uint64).max) revert InvalidLease();
        result = uint64(wide);
    }

    function _safeUint64(uint256 value)
        private
        pure
        returns (uint64)
    {
        if (value > type(uint64).max) revert InvalidLease();
        return uint64(value);
    }

    function _min(uint64 left, uint64 right)
        private
        pure
        returns (uint64)
    {
        return left < right ? left : right;
    }

    function _sparseProof(bytes calldata encoded, uint256 proofIndex)
        private
        pure
        returns (bytes32[256] memory siblings)
    {
        uint256 base = proofIndex * 256 * 32;
        for (uint256 level; level < 256; ++level) {
            bytes32 sibling;
            assembly ("memory-safe") {
                sibling :=
                    calldataload(
                        add(encoded.offset, add(base, mul(level, 32)))
                    )
            }
            siblings[level] = sibling;
        }
    }

    function _decodeMemoryIdentities(bytes memory encoded, uint256 offset)
        private
        pure
        returns (V11MinerControllerEncoding.IdentityClaims memory identities)
    {
        identities.certificateRelayProgramId =
            _memoryWord(encoded, offset);
        identities.certificateRelayConfigurationHash =
            _memoryWord(encoded, offset + 32);
        identities.parentChainIdentity =
            _memoryWord(encoded, offset + 64);
        identities.parentFinalityConfigurationHash =
            _memoryWord(encoded, offset + 96);
        identities.weakSubjectivityPolicyHash =
            _memoryWord(encoded, offset + 128);
        identities.protocolCoreHash =
            _memoryWord(encoded, offset + 160);
        identities.parentGenesisHash =
            _memoryWord(encoded, offset + 192);
        identities.elementsGenesisHash =
            _memoryWord(encoded, offset + 224);
        identities.controllerProgramConfigurationHash =
            _memoryWord(encoded, offset + 256);
        identities.inboundVaultConfigurationHash =
            _memoryWord(encoded, offset + 288);
        identities.usddAssetId = _memoryWord(encoded, offset + 320);
    }

    function _decodeMemoryState(bytes memory encoded, uint256 offset)
        private
        pure
        returns (
            V11MinerControllerEncoding.CanonicalControllerState memory state
        )
    {
        state.controllerStateHash = _memoryWord(encoded, offset);
        state.cumulativeResolutionRoot =
            _memoryWord(encoded, offset + 32);
        state.parentBlockHash = _memoryWord(encoded, offset + 64);
        state.controllerSequence = _memoryU64(encoded, offset + 96);
        state.resolutionCount = _memoryU64(encoded, offset + 104);
        state.nextResolutionNonce = _memoryU64(encoded, offset + 112);
        state.parentBlockHeight = _memoryU64(encoded, offset + 120);
        state.parentMedianTimePast =
            _memoryU64(encoded, offset + 128);
        state.parentChainwork =
            uint256(_memoryWord(encoded, offset + 136));
        state.ethereumFinalizedSlot =
            _memoryU64(encoded, offset + 168);
        state.ethereumFinalizedTimestamp =
            _memoryU64(encoded, offset + 176);
        state.weakSubjectivityValidUntil =
            _memoryU64(encoded, offset + 184);
    }

    function _decodeMemoryCheckpoint(bytes memory encoded, uint256 offset)
        private
        pure
        returns (ICanonicalParentFinalityReceiptV11.Checkpoint memory checkpoint)
    {
        checkpoint.blockHashDisplay = _memoryWord(encoded, offset);
        checkpoint.blockHeight = _memoryU32(encoded, offset + 32);
        checkpoint.medianTimePast = _memoryU32(encoded, offset + 36);
        checkpoint.cumulativeChainwork =
            uint256(_memoryWord(encoded, offset + 40));
    }

    function _memoryWord(bytes memory encoded, uint256 offset)
        private
        pure
        returns (bytes32 value)
    {
        assembly ("memory-safe") {
            value := mload(add(add(encoded, 32), offset))
        }
    }

    function _memoryAddress(bytes memory encoded, uint256 offset)
        private
        pure
        returns (address value)
    {
        value =
            address(uint160(uint256(_memoryWord(encoded, offset)) >> 96));
    }

    function _memoryU16(bytes memory encoded, uint256 offset)
        private
        pure
        returns (uint16)
    {
        return uint16(uint256(_memoryWord(encoded, offset)) >> 240);
    }

    function _memoryU32(bytes memory encoded, uint256 offset)
        private
        pure
        returns (uint32)
    {
        return uint32(uint256(_memoryWord(encoded, offset)) >> 224);
    }

    function _memoryU64(bytes memory encoded, uint256 offset)
        private
        pure
        returns (uint64)
    {
        return uint64(uint256(_memoryWord(encoded, offset)) >> 192);
    }
}
