// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IControllerAcceptanceRelayV4} from "./interfaces/IControllerAcceptanceRelayV4.sol";
import {ExactSafeERC20} from "./libraries/ExactSafeERC20.sol";

/// @title USDDInboundVaultV4
/// @notice Ownerless, fail-closed escrow and inbound reserve state machine.
/// @dev Pending intents are reversible. Permanent deposits require a current,
///      proof-accepted snapshot from the immutable controller relay and resolve
///      exactly once as MINT or CANCEL. A committed deposit is never refundable
///      because time elapsed; CANCEL must be included in the relay's canonical
///      cumulative resolution root.
///
///      The relay that advances `controllerSnapshot()` is a separate mandatory
///      production component. Its address is constructor-pinned and its exact
///      code/config/policy is sealed once after deployment, without an owner or
///      caller-selected identity. It must prove valid controller execution,
///      Elements inclusion, BMM anchoring, and parent-chain finality. This vault
///      deliberately cannot replace, configure, or bypass that relay.
contract USDDInboundVaultV4 {
    using ExactSafeERC20 for address;

    // Deposit/resolution and terminal-policy wire formats remain V2; only the
    // relay/snapshot consumer is V4. Runtime and policy hashes must be refrozen.
    uint32 public constant PROTOCOL_VERSION = 2;
    bool public constant PRODUCTION_READY = false;
    bytes32 public constant SECURITY_STATUS =
        keccak256("BLOCKED_UNTIL_V4_IDENTITIES_RELAY_OUTBOUND_AND_AUDITS_ARE_FROZEN");
    bytes32 public constant REQUIRED_RELAY_SECURITY_MODEL_ID =
        keccak256("USDD_V4_NO_EXPIRY_STRONG_MINED_EXECUTION");
    uint256 public constant RESOLUTION_TREE_DEPTH = 64;
    uint256 public constant MAX_ELEMENTS_SCRIPT_LENGTH = 128;
    uint64 public constant MAX_INTENT_AMOUNT_USDT6 = 20_000_000e6;
    uint256 public constant MAX_ACCOUNTED_CUSTODY_USDT6 = 1_000_000_000e6;
    uint256 public constant ACTIVE_PRINCIPAL_LIABILITY_CAP_USDT6 = 1_000_000_000e6;
    uint64 public constant MIN_INTENT_LIFETIME_SECONDS = 1 hours;
    uint64 public constant MAX_INTENT_LIFETIME_SECONDS = 30 days;
    uint64 public constant MIN_COMMIT_LEASE_REMAINING_SECONDS = 30 minutes;
    uint64 public constant MAX_CONTROLLER_FRESHNESS_LEASE_SECONDS = 6 hours;
    uint64 public constant MAX_OUTSTANDING_COMMITTED = 64;

    bytes32 private constant PROTOCOL_ID_DOMAIN =
        keccak256("USDD_INBOUND_PROTOCOL_ID_V2");
    bytes32 private constant VAULT_DEPLOYMENT_HASH_DOMAIN =
        keccak256("USDD_INBOUND_VAULT_DEPLOYMENT_HASH_V2");
    bytes32 private constant VAULT_ID_DOMAIN = keccak256("USDD_INBOUND_VAULT_ID_V2");
    bytes8 private constant TERMINAL_VAULT_POLICY_MAGIC = bytes8("ETVPLCY2");
    uint16 private constant TERMINAL_VAULT_POLICY_ENCODING_SCHEMA = 2;
    bytes32 private constant INBOUND_VAULT_STORAGE_LAYOUT_IDENTITY =
        0x6c1156dbdf0e04a507f340b005bcc89bcedb92d2bee9b271e092d32f23d35ea6;
    bytes32 private constant INTENT_ID_DOMAIN = keccak256("USDD_DEPOSIT_INTENT_ID_V2");
    bytes32 private constant DEPOSIT_ID_DOMAIN = keccak256("USDD_COMMITTED_DEPOSIT_ID_V2");
    bytes32 private constant SNAPSHOT_ID_DOMAIN = keccak256("USDD_CONTROLLER_SNAPSHOT_ID_V4");
    bytes32 private constant CANCELLATION_REQUEST_DOMAIN =
        keccak256("USDD_CANCELLATION_REQUEST_ID_V2");
    bytes32 private constant RESOLUTION_ID_DOMAIN = keccak256("USDD_CONTROLLER_RESOLUTION_ID_V2");
    // SHA-256 of the exact ASCII labels frozen by ProtocolManifestV2.
    bytes32 private constant MINT_RESOLUTION_LEAF_DOMAIN =
        0x93e5c995696e627e01a2040e6faab7ae914878a4e21fcf6e6ffd5f753480e333;
    bytes32 private constant CANCEL_RESOLUTION_LEAF_DOMAIN =
        0x6630664fc8a787861157551fab519e51931d24c8aecf6114907de27586bf8aba;
    bytes32 private constant RESOLUTION_EMPTY_LEAF_DOMAIN =
        0xb714a1699e650f9474e2ba282d018b6d387c45534e0ccdee0070166860d63174;
    bytes32 private constant RESOLUTION_NODE_DOMAIN =
        0x8c490b522f86103aa97a5f9076e48753aadba21ae41c3e387484414152c417fa;

    enum IntentState {
        None,
        Pending,
        Refunded,
        Committed,
        CancelRequested,
        MintAcknowledged,
        Cancelled
    }

    enum ResolutionKind {
        None,
        Mint,
        Cancel
    }

    struct DeploymentConfig {
        address usdt;
        address controllerAcceptanceRelay;
        bytes32 relayVerifierProgramId;
        bytes32 ethereumExecutionGenesisHash;
        bytes32 inboundDomainId;
        bytes32 catchupPolicyHash;
        bytes32 elementsGenesisHash;
        bytes32 protocolCoreHash;
        bytes32 usddAssetId;
        uint64 resolutionBountyUSDT6;
    }

    struct Intent {
        address depositor;
        address refundRecipient;
        uint64 amountUSDT6;
        uint64 openedAt;
        uint64 expiresAt;
        uint64 intentNonce;
        uint64 depositNonce;
        bytes32 elementsScriptHash;
        bytes32 userSalt;
        bytes32 depositId;
        bytes32 commitSnapshotId;
        bytes32 cancellationRequestId;
        bytes32 resolutionId;
        IntentState state;
    }

    address public immutable USDT;
    IControllerAcceptanceRelayV4 private immutable _controllerAcceptanceRelay;
    bytes32 private immutable _relayVerifierProgramId;
    bytes32 private immutable _ethereumExecutionGenesisHash;
    bytes32 private immutable _inboundDomainId;
    bytes32 private immutable _catchupPolicyHash;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable PROTOCOL_CORE_HASH;
    bytes32 public immutable USDD_ASSET_ID;
    uint64 public immutable RESOLUTION_BOUNTY_USDT6;
    bytes32 public immutable PROTOCOL_ID;
    bytes32 public immutable VAULT_ID;

    uint64 public nextIntentNonce;
    uint64 public nextCommittedDepositNonce;
    uint256 public pendingEscrowUSDT6;
    uint256 public pendingResolutionBountyEscrowUSDT6;
    uint256 public committedLiabilityUSDT6;
    uint256 public resolutionBountyLiabilityUSDT6;
    uint256 public unresolvedCommittedUSDT6;
    uint256 public mintAcknowledgedLiabilityUSDT6;
    uint256 public totalIntentOpenedUSDT6;
    uint256 public totalUncommittedRefundedUSDT6;
    uint256 public totalResolutionBountyFundedUSDT6;
    uint256 public totalUncommittedBountyRefundedUSDT6;
    uint256 public totalResolutionBountyPaidUSDT6;
    uint256 public totalCommittedUSDT6;
    uint256 public totalMintAcknowledgedUSDT6;
    uint256 public totalCancellationRefundedUSDT6;

    mapping(bytes32 intentId => Intent intent) private _intents;
    mapping(uint64 intentNonce => bytes32 intentId) public intentIdByNonce;
    mapping(uint64 depositNonce => bytes32 depositId) public depositIdByNonce;
    mapping(bytes32 resolutionId => bool consumed) public consumedResolutionIds;

    uint256 private _reentrancyLock = 1;
    // Post-deployment, exactly-once relay binding. These slots deliberately
    // follow every pre-existing V2 state slot, so terminal deposit proofs keep
    // their original slot ordinals.
    bytes32 private _controllerRelayBindingHash;

    error ZeroAddress();
    error AddressHasNoCode(address target);
    error ZeroIdentifier();
    error SecurityModelMismatch(bytes32 expected, bytes32 reported);
    error VerifierProgramIdMismatch(bytes32 expected, bytes32 reported);
    error VerifierConfigHashMismatch(bytes32 expected, bytes32 reported);
    error VerifierCodeChanged(bytes32 expected, bytes32 actual);
    error VerifierBindingChanged(bytes32 expected, bytes32 actual);
    error ControllerRelayNotInitialized();
    error ControllerRelayAlreadyInitialized();
    error VaultPolicyMismatch(bytes32 expected, bytes32 reported);
    error UnsupportedEthereumChainId(uint256 chainId);
    error ZeroAmount();
    error InvalidResolutionBounty(uint64 supplied, uint256 maximum);
    error IntentAmountAboveMaximum(uint64 supplied, uint64 maximum);
    error InvalidElementsScriptLength(uint256 supplied);
    error InvalidIntentLifetime(uint64 supplied, uint64 minimum, uint64 maximum);
    error InvalidCommitment();
    error AccountedCustodyCapExceeded(uint256 attempted, uint256 cap);
    error PrincipalLiabilityCapExceeded(uint256 attempted, uint256 cap);
    error ReentrantCall();
    error UnknownIntent(bytes32 intentId);
    error WrongIntentState(bytes32 intentId, IntentState expected, IntentState actual);
    error IntentExpired(bytes32 intentId, uint64 expiresAt);
    error RefundNotAuthorized(address caller, address depositor, uint64 refundableAt);
    error OnlyDepositor(address caller, address depositor);
    error InvalidControllerSnapshot();
    error StaleControllerSnapshot(uint64 validUntil, uint256 minimumRequired);
    error RelayResolutionNonceAhead(
        uint64 relayNextResolutionNonce, uint64 nextDepositNonce
    );
    error OutstandingCommittedLimitReached(uint64 outstanding, uint64 maximum);
    error WrongResolutionIndex(uint64 expected, uint64 supplied);
    error ResolutionIndexNotAccepted(uint64 index, uint64 acceptedCount);
    error ResolutionAlreadyConsumed(bytes32 resolutionId);
    error InvalidResolutionBranch(bytes32 resolutionId);
    error AccountingInvariantViolated();
    error ReserveInsolvent(uint256 reserve, uint256 accountedCustody);

    event DepositIntentOpened(
        bytes32 indexed intentId,
        uint64 indexed intentNonce,
        address indexed depositor,
        address refundRecipient,
        uint64 amountUSDT6,
        uint64 resolutionBountyUSDT6,
        uint64 expiresAt,
        bytes32 elementsScriptHash,
        bytes elementsScript,
        bytes32 userSalt
    );

    event UncommittedIntentRefunded(
        bytes32 indexed intentId,
        address indexed refundRecipient,
        uint64 amountUSDT6,
        uint64 resolutionBountyUSDT6,
        address indexed executor
    );

    event PermanentDepositCommitted(
        bytes32 indexed depositId,
        uint64 indexed depositNonce,
        bytes32 indexed intentId,
        bytes32 snapshotId,
        uint64 amountUSDT6,
        uint64 resolutionBountyUSDT6,
        bytes32 elementsScriptHash,
        bytes32 controllerStateHash,
        uint64 controllerSequence,
        uint64 freshnessLeaseValidUntil
    );

    event CancellationRequested(
        bytes32 indexed cancellationRequestId,
        bytes32 indexed depositId,
        bytes32 indexed intentId,
        address requester
    );

    event MintAcknowledged(
        bytes32 indexed resolutionId,
        bytes32 indexed depositId,
        bytes32 indexed intentId,
        uint64 resolutionIndex,
        uint64 amountUSDT6,
        bytes32 controllerStateHash,
        uint64 controllerSequence,
        address submitter
    );

    event CanonicalCancellationRefunded(
        bytes32 indexed resolutionId,
        bytes32 indexed depositId,
        bytes32 indexed intentId,
        uint64 resolutionIndex,
        address refundRecipient,
        uint64 amountUSDT6,
        bytes32 controllerStateHash,
        uint64 controllerSequence,
        address submitter
    );

    event ResolutionBountyPaid(
        bytes32 indexed resolutionId,
        ResolutionKind indexed kind,
        address indexed recipient,
        uint64 amountUSDT6
    );


    constructor(DeploymentConfig memory config) {
        if (config.usdt == address(0) || config.controllerAcceptanceRelay == address(0)) {
            revert ZeroAddress();
        }
        if (config.usdt.code.length == 0) revert AddressHasNoCode(config.usdt);
        if (
            config.relayVerifierProgramId == bytes32(0)
                || config.ethereumExecutionGenesisHash == bytes32(0)
                || config.inboundDomainId == bytes32(0)
                || config.catchupPolicyHash == bytes32(0)
                || config.elementsGenesisHash == bytes32(0)
                || config.protocolCoreHash == bytes32(0)
                || config.usddAssetId == bytes32(0)
        ) {
            revert ZeroIdentifier();
        }
        if (
            config.resolutionBountyUSDT6 > MAX_ACCOUNTED_CUSTODY_USDT6
        ) {
            revert InvalidResolutionBounty(
                config.resolutionBountyUSDT6, MAX_ACCOUNTED_CUSTODY_USDT6
            );
        }
        if (block.chainid > type(uint64).max) {
            revert UnsupportedEthereumChainId(block.chainid);
        }

        IControllerAcceptanceRelayV4 relay =
            IControllerAcceptanceRelayV4(config.controllerAcceptanceRelay);

        USDT = config.usdt;
        _controllerAcceptanceRelay = relay;
        _relayVerifierProgramId = config.relayVerifierProgramId;
        _ethereumExecutionGenesisHash = config.ethereumExecutionGenesisHash;
        _inboundDomainId = config.inboundDomainId;
        _catchupPolicyHash = config.catchupPolicyHash;
        ELEMENTS_GENESIS_HASH = config.elementsGenesisHash;
        PROTOCOL_CORE_HASH = config.protocolCoreHash;
        USDD_ASSET_ID = config.usddAssetId;
        RESOLUTION_BOUNTY_USDT6 = config.resolutionBountyUSDT6;

        // These two identifiers must be computable before the relay and vault
        // are deployed because the Elements controller programs commit them.
        // Relay/verifier addresses and identities are intentionally excluded
        // here: the exact deployed relay and immutable-patched vault runtime
        // are bound later by TerminalVaultPolicyV2::policy_hash and the
        // manifest's inboundDeploymentHash. Including either relay identity in
        // this predeployment projection creates an impossible relay <-> vault
        // identity fixed point.
        bytes32 protocolId = sha256(
            abi.encodePacked(
                PROTOCOL_ID_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                config.elementsGenesisHash,
                config.protocolCoreHash,
                config.usddAssetId
            )
        );
        PROTOCOL_ID = protocolId;
        bytes32 deploymentHash = sha256(
            abi.encodePacked(
                VAULT_DEPLOYMENT_HASH_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                config.usdt,
                protocolId,
                _limitsHash(config.resolutionBountyUSDT6)
            )
        );
        VAULT_ID = sha256(
            abi.encodePacked(
                VAULT_ID_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                address(this),
                deploymentHash
            )
        );
    }

    /// @notice Permissionlessly seals the predicted relay after both deployed
    ///         runtimes exist.
    /// @dev This one-time storage binding breaks the otherwise impossible hash
    ///      fixed point: the relay commits the exact terminal vault policy,
    ///      while that policy commits this vault's immutable-patched runtime.
    ///      No caller chooses any identity; every value is read from the one
    ///      constructor-pinned relay address and checked against this vault.
    function initializeControllerRelayBinding() external nonReentrant {
        if (_controllerRelayBindingHash != bytes32(0)) {
            revert ControllerRelayAlreadyInitialized();
        }
        address relayAddress = address(_controllerAcceptanceRelay);
        if (relayAddress.code.length == 0) revert AddressHasNoCode(relayAddress);

        _requireLiveRelayStaticIdentity();
        bytes32 expectedPolicyHash = _terminalVaultPolicyHash();
        bytes32 reportedPolicyHash = _controllerAcceptanceRelay.inboundVaultPolicyHash();
        if (reportedPolicyHash != expectedPolicyHash) {
            revert VaultPolicyMismatch(expectedPolicyHash, reportedPolicyHash);
        }
        bytes32 verifierConfig = _controllerAcceptanceRelay.verifierConfigHash();
        if (verifierConfig == bytes32(0)) revert ZeroIdentifier();
        bytes32 relayCodehash = relayAddress.codehash;
        _controllerRelayBindingHash =
            sha256(abi.encodePacked(relayCodehash, verifierConfig, reportedPolicyHash));
    }

    function _terminalVaultPolicyHash() private view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                TERMINAL_VAULT_POLICY_MAGIC,
                TERMINAL_VAULT_POLICY_ENCODING_SCHEMA,
                uint64(block.chainid),
                _ethereumExecutionGenesisHash,
                _inboundDomainId,
                _catchupPolicyHash,
                PROTOCOL_ID,
                VAULT_ID,
                address(this),
                address(this).codehash,
                INBOUND_VAULT_STORAGE_LAYOUT_IDENTITY
            )
        );
    }

    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert ReentrantCall();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    /// @notice Locks exact USDT in reversible escrow without creating backing.
    function openIntent(
        uint64 amountUSDT6,
        bytes calldata elementsScript,
        bytes32 userSalt,
        address refundRecipient,
        uint64 expiresAt
    ) external nonReentrant returns (uint64 intentNonce, bytes32 intentId) {
        if (amountUSDT6 == 0) revert ZeroAmount();
        if (amountUSDT6 > MAX_INTENT_AMOUNT_USDT6) {
            revert IntentAmountAboveMaximum(amountUSDT6, MAX_INTENT_AMOUNT_USDT6);
        }
        if (refundRecipient == address(0)) revert ZeroAddress();
        if (elementsScript.length == 0 || elementsScript.length > MAX_ELEMENTS_SCRIPT_LENGTH) {
            revert InvalidElementsScriptLength(elementsScript.length);
        }

        uint256 now_ = block.timestamp;
        if (
            expiresAt < now_ + MIN_INTENT_LIFETIME_SECONDS
                || expiresAt > now_ + MAX_INTENT_LIFETIME_SECONDS
        ) {
            uint64 supplied = expiresAt > now_ ? uint64(expiresAt - now_) : 0;
            revert InvalidIntentLifetime(
                supplied, MIN_INTENT_LIFETIME_SECONDS, MAX_INTENT_LIFETIME_SECONDS
            );
        }

        uint256 fundedAmount = uint256(amountUSDT6) + RESOLUTION_BOUNTY_USDT6;
        uint256 newAccountedCustody = accountedCustodyUSDT6() + fundedAmount;
        if (newAccountedCustody > MAX_ACCOUNTED_CUSTODY_USDT6) {
            revert AccountedCustodyCapExceeded(
                newAccountedCustody, MAX_ACCOUNTED_CUSTODY_USDT6
            );
        }

        intentNonce = nextIntentNonce;
        nextIntentNonce = intentNonce + 1;
        bytes32 elementsScriptHash = sha256(elementsScript);
        intentId = _computeIntentId(
            intentNonce,
            msg.sender,
            refundRecipient,
            amountUSDT6,
            elementsScriptHash,
            userSalt,
            expiresAt
        );
        if (intentId == bytes32(0)) revert InvalidCommitment();

        USDT.pullExact(msg.sender, fundedAmount);

        _intents[intentId] = Intent({
            depositor: msg.sender,
            refundRecipient: refundRecipient,
            amountUSDT6: amountUSDT6,
            openedAt: uint64(now_),
            expiresAt: expiresAt,
            intentNonce: intentNonce,
            depositNonce: 0,
            elementsScriptHash: elementsScriptHash,
            userSalt: userSalt,
            depositId: bytes32(0),
            commitSnapshotId: bytes32(0),
            cancellationRequestId: bytes32(0),
            resolutionId: bytes32(0),
            state: IntentState.Pending
        });
        intentIdByNonce[intentNonce] = intentId;
        pendingEscrowUSDT6 += amountUSDT6;
        pendingResolutionBountyEscrowUSDT6 += RESOLUTION_BOUNTY_USDT6;
        totalIntentOpenedUSDT6 += amountUSDT6;
        totalResolutionBountyFundedUSDT6 += RESOLUTION_BOUNTY_USDT6;
        _requireAccountingAndSolvency();

        _emitIntentOpened(intentId, elementsScript);
    }

    /// @notice Refunds pending escrow. The depositor can execute immediately;
    ///         after expiry anyone can execute payment to the fixed recipient.
    function refundUncommittedIntent(bytes32 intentId) external nonReentrant {
        Intent storage intent = _knownIntent(intentId);
        _requireState(intentId, intent.state, IntentState.Pending);
        if (msg.sender != intent.depositor && block.timestamp < intent.expiresAt) {
            revert RefundNotAuthorized(msg.sender, intent.depositor, intent.expiresAt);
        }

        uint64 amount = intent.amountUSDT6;
        uint64 resolutionBounty = RESOLUTION_BOUNTY_USDT6;
        address recipient = intent.refundRecipient;
        intent.state = IntentState.Refunded;
        pendingEscrowUSDT6 -= amount;
        pendingResolutionBountyEscrowUSDT6 -= resolutionBounty;
        totalUncommittedRefundedUSDT6 += amount;
        totalUncommittedBountyRefundedUSDT6 += resolutionBounty;
        USDT.pushExact(recipient, uint256(amount) + resolutionBounty);
        _requireAccountingAndSolvency();
        emit UncommittedIntentRefunded(
            intentId, recipient, amount, resolutionBounty, msg.sender
        );
    }

    /// @notice Makes a pending intent permanent using the relay's shared,
    ///         proof-accepted freshness lease.
    /// @dev Only the depositor can cross this irreversible boundary.
    function commitIntent(bytes32 intentId)
        external
        nonReentrant
        returns (uint64 depositNonce, bytes32 depositId)
    {
        Intent storage intent = _knownIntent(intentId);
        _requireState(intentId, intent.state, IntentState.Pending);
        if (msg.sender != intent.depositor) revert OnlyDepositor(msg.sender, intent.depositor);
        if (block.timestamp >= intent.expiresAt) revert IntentExpired(intentId, intent.expiresAt);

        IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot =
            _currentSnapshotForAdmission();
        depositNonce = _nextDepositNonceForAdmission(snapshot.state.nextResolutionNonce);
        bytes32 acceptedSnapshotId = snapshotId(snapshot);

        nextCommittedDepositNonce = depositNonce + 1;
        bytes32 contentsHash = sha256(
            abi.encodePacked(
                depositNonce,
                intentId,
                intent.amountUSDT6,
                intent.elementsScriptHash,
                acceptedSnapshotId
            )
        );
        depositId = sha256(
            abi.encodePacked(
                DEPOSIT_ID_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                address(this),
                VAULT_ID,
                contentsHash
            )
        );
        if (depositId == bytes32(0)) revert InvalidCommitment();

        intent.depositNonce = depositNonce;
        intent.depositId = depositId;
        intent.commitSnapshotId = acceptedSnapshotId;
        intent.state = IntentState.Committed;
        depositIdByNonce[depositNonce] = depositId;

        uint64 amount = intent.amountUSDT6;
        uint256 newPrincipalLiability = committedLiabilityUSDT6 + amount;
        if (newPrincipalLiability > ACTIVE_PRINCIPAL_LIABILITY_CAP_USDT6) {
            revert PrincipalLiabilityCapExceeded(
                newPrincipalLiability, ACTIVE_PRINCIPAL_LIABILITY_CAP_USDT6
            );
        }
        pendingEscrowUSDT6 -= amount;
        pendingResolutionBountyEscrowUSDT6 -= RESOLUTION_BOUNTY_USDT6;
        committedLiabilityUSDT6 = newPrincipalLiability;
        resolutionBountyLiabilityUSDT6 += RESOLUTION_BOUNTY_USDT6;
        unresolvedCommittedUSDT6 += amount;
        totalCommittedUSDT6 += amount;
        _requireAccountingAndSolvency();

        _emitPermanentDepositCommitted(intentId, snapshot);
    }

    /// @notice Requests CANCEL. This never transfers principal.
    function requestCancellation(bytes32 intentId)
        external
        returns (bytes32 cancellationRequestId)
    {
        Intent storage intent = _knownIntent(intentId);
        _requireState(intentId, intent.state, IntentState.Committed);
        if (msg.sender != intent.depositor) revert OnlyDepositor(msg.sender, intent.depositor);

        cancellationRequestId = sha256(
            abi.encodePacked(
                CANCELLATION_REQUEST_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                address(this),
                VAULT_ID,
                intentId,
                intent.depositId,
                intent.depositNonce
            )
        );
        if (cancellationRequestId == bytes32(0)) revert InvalidCommitment();
        intent.cancellationRequestId = cancellationRequestId;
        intent.state = IntentState.CancelRequested;
        emit CancellationRequested(
            cancellationRequestId, intent.depositId, intentId, msg.sender
        );
    }

    /// @notice Acknowledges a canonical MINT leaf. Principal stays as backing.
    /// @dev MINT may win even after CANCEL was requested if it is the controller's
    ///      canonical resolution.
    function acknowledgeMint(
        bytes32 intentId,
        uint64 resolutionIndex,
        bytes32[64] calldata merkleBranch
    ) external nonReentrant returns (bytes32 acceptedResolutionId) {
        Intent storage intent = _knownIntent(intentId);
        if (
            intent.state != IntentState.Committed
                && intent.state != IntentState.CancelRequested
        ) {
            revert WrongIntentState(intentId, IntentState.Committed, intent.state);
        }
        IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot;
        (acceptedResolutionId, snapshot) =
            _consumeResolution(intentId, ResolutionKind.Mint, resolutionIndex, merkleBranch);
        consumedResolutionIds[acceptedResolutionId] = true;

        uint64 amount = intent.amountUSDT6;
        intent.resolutionId = acceptedResolutionId;
        intent.state = IntentState.MintAcknowledged;
        unresolvedCommittedUSDT6 -= amount;
        mintAcknowledgedLiabilityUSDT6 += amount;
        resolutionBountyLiabilityUSDT6 -= RESOLUTION_BOUNTY_USDT6;
        totalMintAcknowledgedUSDT6 += amount;
        totalResolutionBountyPaidUSDT6 += RESOLUTION_BOUNTY_USDT6;
        if (RESOLUTION_BOUNTY_USDT6 != 0) {
            USDT.pushExact(msg.sender, RESOLUTION_BOUNTY_USDT6);
        }
        _requireAccountingAndSolvency();

        emit MintAcknowledged(
            acceptedResolutionId,
            intent.depositId,
            intentId,
            resolutionIndex,
            amount,
            snapshot.state.controllerStateHash,
            snapshot.state.controllerSequence,
            msg.sender
        );
        emit ResolutionBountyPaid(
            acceptedResolutionId,
            ResolutionKind.Mint,
            msg.sender,
            RESOLUTION_BOUNTY_USDT6
        );
    }

    /// @notice Refunds committed principal only after canonical CANCEL inclusion.
    function finalizeCancellation(
        bytes32 intentId,
        uint64 resolutionIndex,
        bytes32[64] calldata merkleBranch
    ) external nonReentrant returns (bytes32 acceptedResolutionId) {
        Intent storage intent = _knownIntent(intentId);
        _requireState(intentId, intent.state, IntentState.CancelRequested);
        IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot;
        (acceptedResolutionId, snapshot) =
            _consumeResolution(intentId, ResolutionKind.Cancel, resolutionIndex, merkleBranch);
        consumedResolutionIds[acceptedResolutionId] = true;

        uint64 amount = intent.amountUSDT6;
        address recipient = intent.refundRecipient;
        intent.resolutionId = acceptedResolutionId;
        intent.state = IntentState.Cancelled;
        unresolvedCommittedUSDT6 -= amount;
        committedLiabilityUSDT6 -= amount;
        resolutionBountyLiabilityUSDT6 -= RESOLUTION_BOUNTY_USDT6;
        totalCancellationRefundedUSDT6 += amount;
        totalResolutionBountyPaidUSDT6 += RESOLUTION_BOUNTY_USDT6;

        USDT.pushExact(recipient, amount);
        if (RESOLUTION_BOUNTY_USDT6 != 0) {
            USDT.pushExact(msg.sender, RESOLUTION_BOUNTY_USDT6);
        }
        _requireAccountingAndSolvency();
        emit CanonicalCancellationRefunded(
            acceptedResolutionId,
            intent.depositId,
            intentId,
            resolutionIndex,
            recipient,
            amount,
            snapshot.state.controllerStateHash,
            snapshot.state.controllerSequence,
            msg.sender
        );
        emit ResolutionBountyPaid(
            acceptedResolutionId,
            ResolutionKind.Cancel,
            msg.sender,
            RESOLUTION_BOUNTY_USDT6
        );
    }

    function snapshotId(IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot)
        public
        view
        returns (bytes32)
    {
        bytes32 contentsHash = _snapshotContentsHash(snapshot);
        return sha256(
            abi.encodePacked(
                SNAPSHOT_ID_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                address(this),
                VAULT_ID,
                PROTOCOL_ID,
                contentsHash
            )
        );
    }

    function _snapshotContentsHash(
        IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot
    ) private pure returns (bytes32) {
        bytes32 controllerCommitment = sha256(
            abi.encodePacked(
                snapshot.state.checkpointHash,
                snapshot.state.controllerStateHash,
                snapshot.state.cumulativeResolutionRoot,
                snapshot.state.controllerSequence,
                snapshot.state.resolutionCount,
                snapshot.state.nextResolutionNonce
            )
        );
        bytes32 parentCommitment = sha256(
            abi.encodePacked(
                snapshot.state.parentBlockHash,
                snapshot.state.parentBlockHeight,
                snapshot.state.parentMedianTimePast,
                snapshot.state.parentChainwork
            )
        );
        bytes32 ethereumCommitment = sha256(
            abi.encodePacked(
                snapshot.state.ethereumFinalizedSlot, snapshot.state.ethereumFinalizedTimestamp
            )
        );
        bytes32 leaseCommitment = sha256(
            abi.encodePacked(
                snapshot.acceptedAt,
                snapshot.admissionValidUntil
            )
        );
        bytes32 anchorCommitment = sha256(
            abi.encodePacked(
                snapshot.acceptedAnchorStateCommitment,
                snapshot.acceptedAnchorExecutionCheckpointHash,
                snapshot.acceptedAnchorSequence
            )
        );
        return sha256(
            abi.encodePacked(
                controllerCommitment,
                parentCommitment,
                ethereumCommitment,
                leaseCommitment,
                anchorCommitment
            )
        );
    }

    function resolutionId(bytes32 intentId, ResolutionKind kind)
        public
        view
        returns (bytes32)
    {
        Intent storage intent = _knownIntent(intentId);
        if (kind != ResolutionKind.Mint && kind != ResolutionKind.Cancel) {
            revert InvalidControllerSnapshot();
        }
        bytes32 cancellationRequestId =
            kind == ResolutionKind.Cancel ? intent.cancellationRequestId : bytes32(0);
        if (kind == ResolutionKind.Cancel && cancellationRequestId == bytes32(0)) {
            revert InvalidControllerSnapshot();
        }
        return sha256(
            abi.encodePacked(
                RESOLUTION_ID_DOMAIN,
                PROTOCOL_VERSION,
                VAULT_ID,
                intent.depositId,
                kind,
                cancellationRequestId
            )
        );
    }

    function hashResolutionLeaf(
        bytes32 intentId,
        ResolutionKind kind,
        uint64 resolutionIndex
    ) public view returns (bytes32 leaf) {
        Intent storage intent = _knownIntent(intentId);
        bytes32 acceptedResolutionId = resolutionId(intentId, kind);
        bytes32 cancellationRequestId =
            kind == ResolutionKind.Cancel ? intent.cancellationRequestId : bytes32(0);
        bytes32 depositContentsHash = sha256(
            abi.encodePacked(
                intentId,
                intent.commitSnapshotId,
                intent.depositNonce,
                intent.amountUSDT6,
                intent.elementsScriptHash,
                cancellationRequestId
            )
        );
        bytes32 leafDomain =
            kind == ResolutionKind.Mint
                ? MINT_RESOLUTION_LEAF_DOMAIN
                : CANCEL_RESOLUTION_LEAF_DOMAIN;
        leaf = sha256(
            abi.encodePacked(
                bytes1(0x00),
                leafDomain,
                PROTOCOL_VERSION,
                VAULT_ID,
                PROTOCOL_ID,
                acceptedResolutionId,
                kind,
                resolutionIndex,
                depositContentsHash
            )
        );
    }

    function computeResolutionRoot(
        bytes32 leaf,
        uint64 index,
        bytes32[64] calldata merkleBranch
    ) external pure returns (bytes32) {
        return _computeResolutionRoot(leaf, index, merkleBranch);
    }

    function accountedCustodyUSDT6() public view returns (uint256) {
        return pendingEscrowUSDT6 + pendingResolutionBountyEscrowUSDT6
            + committedLiabilityUSDT6 + resolutionBountyLiabilityUSDT6;
    }

    function principalLiabilityUSDT6() external view returns (uint256) {
        return committedLiabilityUSDT6;
    }

    function reserveBalanceUSDT6() external view returns (uint256) {
        return ExactSafeERC20.balanceOf(USDT, address(this));
    }

    function intentState(bytes32 intentId) external view returns (IntentState) {
        return _intents[intentId].state;
    }

    function getIntent(bytes32 intentId) external view returns (Intent memory) {
        return _intents[intentId];
    }

    function _consumeResolution(
        bytes32 intentId,
        ResolutionKind kind,
        uint64 resolutionIndex,
        bytes32[64] calldata merkleBranch
    )
        private
        view
        returns (
            bytes32 acceptedResolutionId,
            IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot
        )
    {
        Intent storage intent = _knownIntent(intentId);
        if (resolutionIndex != intent.depositNonce) {
            revert WrongResolutionIndex(intent.depositNonce, resolutionIndex);
        }
        _requireRelayIdentity();
        snapshot = _controllerAcceptanceRelay.controllerSnapshot();
        if (
            snapshot.state.checkpointHash == bytes32(0)
                || snapshot.state.controllerStateHash == bytes32(0)
                || snapshot.state.cumulativeResolutionRoot == bytes32(0)
                || snapshot.state.parentBlockHash == bytes32(0)
                || snapshot.state.parentBlockHeight == 0
                || snapshot.state.parentMedianTimePast == 0 || snapshot.state.parentChainwork == 0
                || snapshot.state.ethereumFinalizedSlot == 0
                || snapshot.state.ethereumFinalizedTimestamp == 0
                || snapshot.state.ethereumFinalizedTimestamp > snapshot.acceptedAt
                || snapshot.acceptedAnchorStateCommitment == bytes32(0)
                || snapshot.acceptedAnchorExecutionCheckpointHash == bytes32(0)
                || snapshot.acceptedAnchorSequence == 0
                || snapshot.acceptedAt == 0
                || snapshot.state.nextResolutionNonce != snapshot.state.resolutionCount
                || snapshot.state.parentMedianTimePast > snapshot.acceptedAt
                || snapshot.state.resolutionCount > snapshot.state.controllerSequence
        ) {
            revert InvalidControllerSnapshot();
        }
        if (resolutionIndex >= snapshot.state.resolutionCount) {
            revert ResolutionIndexNotAccepted(resolutionIndex, snapshot.state.resolutionCount);
        }
        acceptedResolutionId = resolutionId(intentId, kind);
        if (consumedResolutionIds[acceptedResolutionId]) {
            revert ResolutionAlreadyConsumed(acceptedResolutionId);
        }
        bytes32 leaf = hashResolutionLeaf(intentId, kind, resolutionIndex);
        if (
            _computeResolutionRoot(leaf, resolutionIndex, merkleBranch)
                != snapshot.state.cumulativeResolutionRoot
        ) {
            revert InvalidResolutionBranch(acceptedResolutionId);
        }
    }

    function _currentSnapshotForAdmission()
        private
        view
        returns (IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot)
    {
        _requireRelayIdentity();
        snapshot = _controllerAcceptanceRelay.controllerSnapshot();
        uint256 now_ = block.timestamp;
        if (
            snapshot.state.checkpointHash == bytes32(0)
                || snapshot.state.controllerStateHash == bytes32(0)
                || snapshot.state.parentBlockHash == bytes32(0)
                || snapshot.state.parentBlockHeight == 0
                || snapshot.state.parentMedianTimePast == 0 || snapshot.state.parentChainwork == 0
                || snapshot.state.ethereumFinalizedSlot == 0
                || snapshot.state.ethereumFinalizedTimestamp == 0
                || snapshot.acceptedAnchorStateCommitment == bytes32(0)
                || snapshot.acceptedAnchorExecutionCheckpointHash == bytes32(0)
                || snapshot.acceptedAnchorSequence == 0
                || snapshot.state.nextResolutionNonce != snapshot.state.resolutionCount
                || snapshot.state.parentMedianTimePast > snapshot.acceptedAt
                || snapshot.state.resolutionCount > snapshot.state.controllerSequence
                || snapshot.state.ethereumFinalizedTimestamp > snapshot.acceptedAt
                || snapshot.acceptedAt > now_
                || snapshot.admissionValidUntil <= snapshot.acceptedAt
                || uint256(snapshot.admissionValidUntil) - snapshot.acceptedAt
                    > MAX_CONTROLLER_FRESHNESS_LEASE_SECONDS
                || _absoluteDifference(
                    snapshot.state.ethereumFinalizedTimestamp, snapshot.state.parentMedianTimePast
                ) > MAX_CONTROLLER_FRESHNESS_LEASE_SECONDS
                || snapshot.admissionValidUntil
                    > uint256(snapshot.state.parentMedianTimePast)
                        + MAX_CONTROLLER_FRESHNESS_LEASE_SECONDS
                || snapshot.admissionValidUntil
                    > uint256(snapshot.state.ethereumFinalizedTimestamp)
                        + MAX_CONTROLLER_FRESHNESS_LEASE_SECONDS
        ) {
            revert InvalidControllerSnapshot();
        }
        uint256 minimumRequired = now_ + MIN_COMMIT_LEASE_REMAINING_SECONDS;
        if (snapshot.admissionValidUntil < minimumRequired) {
            revert StaleControllerSnapshot(snapshot.admissionValidUntil, minimumRequired);
        }
    }

    function _nextDepositNonceForAdmission(uint64 relayNextResolutionNonce)
        private
        view
        returns (uint64 nextDepositNonce)
    {
        nextDepositNonce = nextCommittedDepositNonce;
        if (relayNextResolutionNonce > nextDepositNonce) {
            revert RelayResolutionNonceAhead(relayNextResolutionNonce, nextDepositNonce);
        }
        uint64 outstanding = nextDepositNonce - relayNextResolutionNonce;
        if (outstanding >= MAX_OUTSTANDING_COMMITTED) {
            revert OutstandingCommittedLimitReached(
                outstanding, MAX_OUTSTANDING_COMMITTED
            );
        }
    }

    function _requireRelayIdentity() private view {
        bytes32 expectedBinding = _controllerRelayBindingHash;
        if (expectedBinding == bytes32(0)) revert ControllerRelayNotInitialized();
        bytes32 actualCodehash = address(_controllerAcceptanceRelay).codehash;
        _requireLiveRelayStaticIdentity();
        bytes32 reportedConfigHash = _controllerAcceptanceRelay.verifierConfigHash();
        bytes32 reportedPolicyHash = _controllerAcceptanceRelay.inboundVaultPolicyHash();
        bytes32 actualBinding =
            sha256(abi.encodePacked(actualCodehash, reportedConfigHash, reportedPolicyHash));
        if (actualBinding != expectedBinding) {
            revert VerifierBindingChanged(expectedBinding, actualBinding);
        }
    }

    function _requireLiveRelayStaticIdentity() private view {
        bytes32 reportedSecurityModelId = _controllerAcceptanceRelay.securityModelId();
        if (reportedSecurityModelId != REQUIRED_RELAY_SECURITY_MODEL_ID) {
            revert SecurityModelMismatch(
                REQUIRED_RELAY_SECURITY_MODEL_ID, reportedSecurityModelId
            );
        }
        bytes32 reportedProgramId = _controllerAcceptanceRelay.verifierProgramId();
        if (reportedProgramId != _relayVerifierProgramId) {
            revert VerifierProgramIdMismatch(_relayVerifierProgramId, reportedProgramId);
        }
    }

    function _knownIntent(bytes32 intentId) private view returns (Intent storage intent) {
        intent = _intents[intentId];
        if (intent.state == IntentState.None) revert UnknownIntent(intentId);
    }

    function _computeIntentId(
        uint64 intentNonce,
        address depositor,
        address refundRecipient,
        uint64 amountUSDT6,
        bytes32 elementsScriptHash,
        bytes32 userSalt,
        uint64 expiresAt
    ) private view returns (bytes32) {
        bytes32 contentsHash = sha256(
            abi.encodePacked(
                intentNonce,
                depositor,
                refundRecipient,
                amountUSDT6,
                elementsScriptHash,
                userSalt,
                expiresAt
            )
        );
        return sha256(
            abi.encodePacked(
                INTENT_ID_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                address(this),
                VAULT_ID,
                contentsHash
            )
        );
    }

    function _requireState(bytes32 intentId, IntentState actual, IntentState expected)
        private
        pure
    {
        if (actual != expected) revert WrongIntentState(intentId, expected, actual);
    }

    function _requireAccountingAndSolvency() private view {
        if (
            committedLiabilityUSDT6
                != unresolvedCommittedUSDT6 + mintAcknowledgedLiabilityUSDT6
        ) {
            revert AccountingInvariantViolated();
        }
        uint256 accountedCustody = accountedCustodyUSDT6();
        uint256 reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        if (reserve < accountedCustody) {
            revert ReserveInsolvent(reserve, accountedCustody);
        }
    }

    function _limitsHash(uint64 resolutionBountyUSDT6) private pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                MAX_INTENT_AMOUNT_USDT6,
                MAX_ACCOUNTED_CUSTODY_USDT6,
                ACTIVE_PRINCIPAL_LIABILITY_CAP_USDT6,
                MIN_INTENT_LIFETIME_SECONDS,
                MAX_INTENT_LIFETIME_SECONDS,
                MIN_COMMIT_LEASE_REMAINING_SECONDS,
                MAX_CONTROLLER_FRESHNESS_LEASE_SECONDS,
                MAX_OUTSTANDING_COMMITTED,
                resolutionBountyUSDT6,
                RESOLUTION_TREE_DEPTH
            )
        );
    }

    function _absoluteDifference(uint64 left, uint64 right) private pure returns (uint64) {
        return left >= right ? left - right : right - left;
    }

    function _computeResolutionRoot(
        bytes32 leaf,
        uint64 index,
        bytes32[64] calldata merkleBranch
    ) private pure returns (bytes32 node) {
        node = leaf;
        for (uint256 level; level < RESOLUTION_TREE_DEPTH; ++level) {
            bytes32 sibling = merkleBranch[level];
            if (((uint256(index) >> level) & 1) == 0) {
                node = sha256(
                    abi.encodePacked(bytes1(0x01), RESOLUTION_NODE_DOMAIN, node, sibling)
                );
            } else {
                node = sha256(
                    abi.encodePacked(bytes1(0x01), RESOLUTION_NODE_DOMAIN, sibling, node)
                );
            }
        }
    }

    function _emitIntentOpened(bytes32 intentId, bytes calldata elementsScript) private {
        Intent storage intent = _intents[intentId];
        emit DepositIntentOpened(
            intentId,
            intent.intentNonce,
            intent.depositor,
            intent.refundRecipient,
            intent.amountUSDT6,
            RESOLUTION_BOUNTY_USDT6,
            intent.expiresAt,
            intent.elementsScriptHash,
            elementsScript,
            intent.userSalt
        );
    }

    function _emitPermanentDepositCommitted(
        bytes32 intentId,
        IControllerAcceptanceRelayV4.ControllerSnapshot memory snapshot
    ) private {
        Intent storage intent = _intents[intentId];
        emit PermanentDepositCommitted(
            intent.depositId,
            intent.depositNonce,
            intentId,
            intent.commitSnapshotId,
            intent.amountUSDT6,
            RESOLUTION_BOUNTY_USDT6,
            intent.elementsScriptHash,
            snapshot.state.controllerStateHash,
            snapshot.state.controllerSequence,
            snapshot.admissionValidUntil
        );
    }
}

