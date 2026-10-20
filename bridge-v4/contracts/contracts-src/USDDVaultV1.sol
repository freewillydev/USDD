// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBip300RedemptionVerifier} from "./interfaces/IBip300RedemptionVerifier.sol";
import {ExactSafeERC20} from "./libraries/ExactSafeERC20.sol";
import {Sha256SparseMerkle} from "./libraries/Sha256SparseMerkle.sol";

/// @title USDDVaultV1
/// @notice Ownerless Ethereum USDT reserve candidate for USDD issuance and redemption.
/// @dev Deposits announce an Elements mint destination. A redemption is payable
///      only after its leaf is included in a root whose exact bundle M6id has
///      received BIP300 approval on a proved Bitcoin chain. Approval is not proof
///      that the referenced Elements transaction or block was valid; accepting
///      the miner threshold as the withdrawal authority is the selected BIP300
///      security boundary. This contract has no owner, proxy, pause, sweep,
///      yield, or arbitrary-call path.
contract USDDVaultV1 {
    using ExactSafeERC20 for address;

    uint32 public constant PROTOCOL_VERSION = 1;
    uint256 public constant APPROVED_CLAIM_TREE_DEPTH = 64;
    uint256 public constant MAX_ELEMENTS_SCRIPT_LENGTH = 128;
    uint64 public constant MAX_DEPOSIT_AMOUNT_USDT6 = 20_000_000e6;
    uint64 public constant MAX_BURN_AMOUNT_USDT6 = 20_000_000e6;
    uint256 public constant ACTIVE_LIABILITY_CAP_USDT6 = 1_000_000_000e6;
    bytes32 public constant EMPTY_APPROVED_CLAIM_ROOT =
        0xc13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db;

    bytes32 public constant VAULT_ID_DOMAIN = keccak256("USDD_VAULT_ID_V1");
    bytes32 public constant DEPOSIT_ID_DOMAIN = keccak256("USDD_DEPOSIT_ID_V1");
    bytes32 public constant APPROVED_REDEMPTION_STATE_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATE_V1");
    bytes32 public constant APPROVED_REDEMPTION_STATEMENT_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_STATEMENT_V1");
    bytes32 public constant APPROVED_REDEMPTION_LEAF_DOMAIN =
        keccak256("USDD_BIP300_REDEMPTION_LEAF_V1");
    bytes32 public constant BURN_ID_DOMAIN =
        0x5811f3ff8b8f31fb49ffb91afab13197c3d72e926549ae29dbda46c6998a3e45;
    bytes4 public constant BURN_PAYLOAD_MAGIC = 0x55534444; // ASCII "USDD"
    uint8 public constant BURN_PAYLOAD_VERSION = 1;

    address public immutable USDT;
    IBip300RedemptionVerifier public immutable BIP300_REDEMPTION_VERIFIER;
    bytes32 public immutable BIP300_REDEMPTION_VERIFIER_CODEHASH;
    bytes32 public immutable BIP300_VERIFIER_PROGRAM_ID;
    bytes32 public immutable BIP300_VERIFIER_CONFIG_HASH;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable USDD_ASSET_ID;
    bytes32 public immutable VAULT_ID;
    uint256 public immutable MINIMUM_ACTIVATION_CHAINWORK;

    struct ApprovedRedemptionState {
        uint64 sequence;
        uint64 approvedClaimCount;
        bytes32 cumulativeApprovedClaimRoot;
        bytes32 approvedM6id;
        bytes32 bitcoinTipHash;
        uint64 bitcoinHeight;
        uint64 bitcoinMedianTimePast;
        uint256 bitcoinChainwork;
    }

    /// @dev The Elements outpoint identifies what miners approved. The vault does
    ///      not independently validate the burn transaction.
    struct RedemptionClaim {
        uint32 protocolVersion;
        bytes32 elementsGenesisHash;
        bytes32 usddAssetId;
        bytes32 vaultId;
        bytes32 burnTxid;
        uint32 burnVout;
        bytes32 burnId;
        uint64 amountUSDT6;
        address recipient;
    }

    ApprovedRedemptionState public approvedRedemptionState;
    bytes32 public approvedRedemptionStateHash;
    uint64 public nextDepositNonce;
    uint256 public principalLiabilityUSDT6;
    uint256 public totalDepositedUSDT6;
    uint256 public totalRedeemedUSDT6;

    mapping(uint64 nonce => bytes32 depositCommitment) public depositCommitmentByNonce;
    mapping(bytes32 burnId => bool spent) public spentBurnIds;
    mapping(bytes32 m6id => bool consumed) public consumedM6ids;

    uint256 private _reentrancyLock = 1;
    /// @notice Successful payouts cryptographically attributed to claims introduced by an exact M6.
    /// @dev Only `redeemForM6` increments this counter. Appended after all
    ///      pre-existing storage so the frozen V1 slots do not move.
    mapping(bytes32 m6id => uint256 count) public redemptionsPaidByM6id;
    mapping(bytes32 m6id => uint64 priorClaimCount) public priorClaimCountByM6id;
    mapping(bytes32 m6id => uint64 nextClaimCount) public nextClaimCountByM6id;
    mapping(bytes32 m6id => bytes32 claimRoot) public approvedClaimRootByM6id;
    mapping(bytes32 m6id => bytes32 stateHash) public approvedStateHashByM6id;

    error ZeroAddress();
    error AddressHasNoCode(address target);
    error ZeroIdentifier();
    error VerifierProgramIdMismatch(bytes32 expected, bytes32 reported);
    error VerifierConfigHashMismatch(bytes32 expected, bytes32 reported);
    error ZeroAmount();
    error DepositAmountAboveMaximum(uint64 supplied, uint64 maximum);
    error InvalidElementsScriptLength(uint256 supplied);
    error InvalidDepositCommitment();
    error LiabilityCapExceeded(uint256 attempted, uint256 cap);
    error ReentrantCall();
    error WrongStateSequence(uint64 expected, uint64 supplied);
    error NoNewApprovedClaims();
    error ApprovedClaimRootDidNotAdvance(bytes32 current);
    error M6idAlreadyConsumed(bytes32 m6id);
    error InvalidApprovedRedemptionState();
    error NonIncreasingBitcoinHeight(uint64 current, uint64 proposed);
    error DecreasingBitcoinMedianTimePast(uint64 current, uint64 proposed);
    error NonIncreasingBitcoinChainwork(uint256 current, uint256 proposed);
    error ActivationChainworkNotReached(uint256 proposed, uint256 minimum);
    error ApprovalProofRejected(bytes32 statement);
    error VerifierCodeChanged(bytes32 expected, bytes32 actual);
    error RedemptionRootNotActive();
    error WrongProtocolVersion(uint32 supplied);
    error WrongVaultId(bytes32 supplied);
    error WrongElementsGenesisHash(bytes32 supplied);
    error WrongUsddAssetId(bytes32 supplied);
    error WrongBurnId(bytes32 expected, bytes32 supplied);
    error InvalidRedemptionClaim();
    error ClaimIndexNotApproved(uint64 claimIndex, uint64 approvedClaimCount);
    error BurnAlreadySpent(bytes32 burnId);
    error InvalidApprovalBranch(bytes32 burnId);
    error UnknownAuthorizingM6(bytes32 m6id);
    error ClaimNotIntroducedByM6(bytes32 m6id, uint64 claimIndex, uint64 first, uint64 endExclusive);
    error LiabilityInsufficient(uint256 amount, uint256 liability);
    error ReserveInsolvent(uint256 reserve, uint256 liability);

    event DepositAccepted(
        bytes32 indexed depositId,
        uint64 indexed nonce,
        address indexed depositor,
        uint64 amountUSDT6,
        bytes32 elementsScriptHash,
        bytes elementsScript,
        bytes32 userSalt
    );

    event ApprovedRedemptionRootAdvanced(
        bytes32 indexed newStateHash,
        bytes32 indexed approvedM6id,
        bytes32 indexed cumulativeApprovedClaimRoot,
        uint64 sequence,
        uint64 approvedClaimCount,
        address submitter
    );

    event MinerApprovedRedemptionPaid(
        bytes32 indexed burnId,
        uint64 claimIndex,
        address indexed recipient,
        uint64 amountUSDT6,
        bytes32 indexed authorizingStateHash,
        address submitter
    );

    constructor(
        address usdt,
        address bip300RedemptionVerifier,
        bytes32 bip300VerifierProgramId,
        bytes32 bip300VerifierConfigHash,
        bytes32 elementsGenesisHash,
        bytes32 usddAssetId,
        uint256 minimumActivationChainwork
    ) {
        if (usdt == address(0) || bip300RedemptionVerifier == address(0)) revert ZeroAddress();
        if (usdt.code.length == 0) revert AddressHasNoCode(usdt);
        if (bip300RedemptionVerifier.code.length == 0) revert AddressHasNoCode(bip300RedemptionVerifier);
        if (
            bip300VerifierProgramId == bytes32(0) || bip300VerifierConfigHash == bytes32(0)
                || elementsGenesisHash == bytes32(0) || usddAssetId == bytes32(0)
                || minimumActivationChainwork == 0
        ) {
            revert ZeroIdentifier();
        }

        IBip300RedemptionVerifier verifier = IBip300RedemptionVerifier(bip300RedemptionVerifier);
        bytes32 reportedProgramId = verifier.verifierProgramId();
        if (reportedProgramId != bip300VerifierProgramId) {
            revert VerifierProgramIdMismatch(bip300VerifierProgramId, reportedProgramId);
        }
        bytes32 reportedConfigHash = verifier.verifierConfigHash();
        if (reportedConfigHash != bip300VerifierConfigHash) {
            revert VerifierConfigHashMismatch(bip300VerifierConfigHash, reportedConfigHash);
        }

        USDT = usdt;
        BIP300_REDEMPTION_VERIFIER = verifier;
        BIP300_REDEMPTION_VERIFIER_CODEHASH = bip300RedemptionVerifier.codehash;
        BIP300_VERIFIER_PROGRAM_ID = bip300VerifierProgramId;
        BIP300_VERIFIER_CONFIG_HASH = bip300VerifierConfigHash;
        ELEMENTS_GENESIS_HASH = elementsGenesisHash;
        USDD_ASSET_ID = usddAssetId;
        MINIMUM_ACTIVATION_CHAINWORK = minimumActivationChainwork;
        VAULT_ID = sha256(
            abi.encodePacked(
                VAULT_ID_DOMAIN,
                block.chainid,
                address(this),
                usdt,
                bip300RedemptionVerifier,
                bip300VerifierProgramId,
                bip300VerifierConfigHash,
                elementsGenesisHash,
                usddAssetId,
                ACTIVE_LIABILITY_CAP_USDT6,
                minimumActivationChainwork
            )
        );
    }

    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert ReentrantCall();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    /// @notice Locks exact USDT principal and announces its Elements destination.
    /// @dev Anyone may relay the event to the Elements minting path. Minting must
    ///      independently prove this finalized Ethereum deposit and deposit ID.
    function deposit(uint64 amountUSDT6, bytes calldata elementsScript, bytes32 userSalt)
        external
        nonReentrant
        returns (uint64 nonce, bytes32 depositId)
    {
        if (amountUSDT6 == 0) revert ZeroAmount();
        if (amountUSDT6 > MAX_DEPOSIT_AMOUNT_USDT6) {
            revert DepositAmountAboveMaximum(amountUSDT6, MAX_DEPOSIT_AMOUNT_USDT6);
        }
        if (elementsScript.length == 0 || elementsScript.length > MAX_ELEMENTS_SCRIPT_LENGTH) {
            revert InvalidElementsScriptLength(elementsScript.length);
        }

        uint256 newLiability = principalLiabilityUSDT6 + amountUSDT6;
        if (newLiability > ACTIVE_LIABILITY_CAP_USDT6) {
            revert LiabilityCapExceeded(newLiability, ACTIVE_LIABILITY_CAP_USDT6);
        }

        nonce = nextDepositNonce;
        nextDepositNonce = nonce + 1;
        bytes32 scriptHash = sha256(elementsScript);
        depositId = sha256(
            abi.encodePacked(
                DEPOSIT_ID_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                address(this),
                USDT,
                nonce,
                msg.sender,
                amountUSDT6,
                scriptHash,
                userSalt
            )
        );
        if (depositId == bytes32(0)) revert InvalidDepositCommitment();

        USDT.pullExact(msg.sender, amountUSDT6);

        depositCommitmentByNonce[nonce] = depositId;
        principalLiabilityUSDT6 = newLiability;
        totalDepositedUSDT6 += amountUSDT6;
        _requireSolvent(newLiability);

        emit DepositAccepted(depositId, nonce, msg.sender, amountUSDT6, scriptHash, elementsScript, userSalt);
    }

    /// @notice Returns the chained state hash and canonical BIP300 approval statement.
    function approvedRedemptionStatement(ApprovedRedemptionState calldata next)
        public
        view
        returns (bytes32 nextStateHash, bytes32 statement)
    {
        ApprovedRedemptionState memory current = approvedRedemptionState;
        bytes32 currentStateContentsHash = _hashStateContents(current);
        bytes32 nextStateContentsHash = _hashStateContents(next);
        nextStateHash = sha256(
            abi.encodePacked(
                APPROVED_REDEMPTION_STATE_DOMAIN, approvedRedemptionStateHash, nextStateContentsHash
            )
        );
        statement = sha256(
            abi.encodePacked(
                APPROVED_REDEMPTION_STATEMENT_DOMAIN,
                block.chainid,
                address(this),
                VAULT_ID,
                BIP300_VERIFIER_PROGRAM_ID,
                BIP300_VERIFIER_CONFIG_HASH,
                ELEMENTS_GENESIS_HASH,
                USDD_ASSET_ID,
                approvedRedemptionStateHash,
                currentStateContentsHash,
                nextStateHash,
                nextStateContentsHash
            )
        );
    }

    /// @notice Appends claims from one Bitcoin/BIP300-approved M6 bundle.
    /// @dev Submission is permissionless. The pinned verifier must prove Bitcoin
    ///      chain progression, M6 approval, and the exact M6id-to-accumulator
    ///      count/root commitment. It does not prove the accumulator transition,
    ///      individual burns, or general Elements consensus validity. A BIP301
    ///      M7 commitment, by itself or with confirmations, is never sufficient.
    function advanceApprovedRedemptionRoot(
        ApprovedRedemptionState calldata next,
        bytes calldata approvalProof
    ) external nonReentrant {
        _validateNextState(next);
        (bytes32 nextStateHash, bytes32 statement) = approvedRedemptionStatement(next);
        bytes32 currentVerifierCodehash = address(BIP300_REDEMPTION_VERIFIER).codehash;
        if (currentVerifierCodehash != BIP300_REDEMPTION_VERIFIER_CODEHASH) {
            revert VerifierCodeChanged(BIP300_REDEMPTION_VERIFIER_CODEHASH, currentVerifierCodehash);
        }
        bytes32 reportedProgramId = BIP300_REDEMPTION_VERIFIER.verifierProgramId();
        if (reportedProgramId != BIP300_VERIFIER_PROGRAM_ID) {
            revert VerifierProgramIdMismatch(BIP300_VERIFIER_PROGRAM_ID, reportedProgramId);
        }
        bytes32 reportedConfigHash = BIP300_REDEMPTION_VERIFIER.verifierConfigHash();
        if (reportedConfigHash != BIP300_VERIFIER_CONFIG_HASH) {
            revert VerifierConfigHashMismatch(BIP300_VERIFIER_CONFIG_HASH, reportedConfigHash);
        }
        if (!BIP300_REDEMPTION_VERIFIER.verify(statement, approvalProof)) {
            revert ApprovalProofRejected(statement);
        }

        consumedM6ids[next.approvedM6id] = true;
        priorClaimCountByM6id[next.approvedM6id] = approvedRedemptionState.approvedClaimCount;
        nextClaimCountByM6id[next.approvedM6id] = next.approvedClaimCount;
        approvedClaimRootByM6id[next.approvedM6id] = next.cumulativeApprovedClaimRoot;
        approvedStateHashByM6id[next.approvedM6id] = nextStateHash;
        approvedRedemptionState = next;
        approvedRedemptionStateHash = nextStateHash;

        emit ApprovedRedemptionRootAdvanced(
            nextStateHash,
            next.approvedM6id,
            next.cumulativeApprovedClaimRoot,
            next.sequence,
            next.approvedClaimCount,
            msg.sender
        );
    }

    /// @notice Pays the fixed recipient of a root-member Elements burn claim.
    /// @dev Anyone may submit the Merkle branch; the submitter cannot redirect
    ///      funds. The current verifier proves BIP300 approval, not Elements burn
    ///      validity. That limitation is disclosed but is not a separate proof
    ///      requirement under the selected miner-authorized withdrawal model.
    function redeem(RedemptionClaim calldata claim, uint64 claimIndex, bytes32[64] calldata merkleBranch)
        external
        nonReentrant
    {
        _redeem(
            claim,
            claimIndex,
            merkleBranch,
            approvedRedemptionState.cumulativeApprovedClaimRoot,
            approvedRedemptionState.approvedClaimCount,
            approvedRedemptionStateHash
        );
    }

    /// @notice Pays a claim against the historical root that first introduced it.
    /// @dev This exact M6 attribution is the only redemption path eligible to
    ///      mature a prover bounty. Claims from an older cumulative prefix cannot
    ///      unlock a later M6's reward.
    function redeemForM6(
        RedemptionClaim calldata claim,
        uint64 claimIndex,
        bytes32[64] calldata merkleBranch,
        bytes32 authorizingM6id
    ) external nonReentrant {
        uint64 endExclusive = nextClaimCountByM6id[authorizingM6id];
        if (endExclusive == 0) revert UnknownAuthorizingM6(authorizingM6id);
        uint64 first = priorClaimCountByM6id[authorizingM6id];
        if (claimIndex < first || claimIndex >= endExclusive) {
            revert ClaimNotIntroducedByM6(authorizingM6id, claimIndex, first, endExclusive);
        }
        _redeem(
            claim,
            claimIndex,
            merkleBranch,
            approvedClaimRootByM6id[authorizingM6id],
            endExclusive,
            approvedStateHashByM6id[authorizingM6id]
        );
        redemptionsPaidByM6id[authorizingM6id] += 1;
    }

    function _redeem(
        RedemptionClaim calldata claim,
        uint64 claimIndex,
        bytes32[64] calldata merkleBranch,
        bytes32 authorizingRoot,
        uint64 authorizingClaimCount,
        bytes32 authorizingStateHash
    ) private {
        if (approvedRedemptionStateHash == bytes32(0)) revert RedemptionRootNotActive();
        if (claim.protocolVersion != PROTOCOL_VERSION) revert WrongProtocolVersion(claim.protocolVersion);
        if (claim.elementsGenesisHash != ELEMENTS_GENESIS_HASH) {
            revert WrongElementsGenesisHash(claim.elementsGenesisHash);
        }
        if (claim.usddAssetId != USDD_ASSET_ID) revert WrongUsddAssetId(claim.usddAssetId);
        if (claim.vaultId != VAULT_ID) revert WrongVaultId(claim.vaultId);
        bytes32 expectedBurnId = computeBurnId(claim.burnTxid, claim.burnVout);
        if (claim.burnId != expectedBurnId) revert WrongBurnId(expectedBurnId, claim.burnId);
        if (
            claim.burnTxid == bytes32(0) || claim.burnId == bytes32(0) || claim.amountUSDT6 == 0
                || claim.amountUSDT6 > MAX_BURN_AMOUNT_USDT6 || claim.recipient == address(0)
                || claim.recipient == address(this)
        ) {
            revert InvalidRedemptionClaim();
        }
        if (claimIndex >= authorizingClaimCount) {
            revert ClaimIndexNotApproved(claimIndex, authorizingClaimCount);
        }
        if (spentBurnIds[claim.burnId]) revert BurnAlreadySpent(claim.burnId);
        if (claim.amountUSDT6 > principalLiabilityUSDT6) {
            revert LiabilityInsufficient(claim.amountUSDT6, principalLiabilityUSDT6);
        }

        bytes32 leaf = hashApprovedRedemptionLeaf(claim, claimIndex);
        if (
            !Sha256SparseMerkle.verify(
                authorizingRoot, leaf, claimIndex, merkleBranch
            )
        ) {
            revert InvalidApprovalBranch(claim.burnId);
        }

        _requireSolvent(principalLiabilityUSDT6);
        spentBurnIds[claim.burnId] = true;
        principalLiabilityUSDT6 -= claim.amountUSDT6;
        totalRedeemedUSDT6 += claim.amountUSDT6;
        USDT.pushExact(claim.recipient, claim.amountUSDT6);
        _requireSolvent(principalLiabilityUSDT6);

        emit MinerApprovedRedemptionPaid(
            claim.burnId,
            claimIndex,
            claim.recipient,
            claim.amountUSDT6,
            authorizingStateHash,
            msg.sender
        );
    }

    function hashApprovedRedemptionLeaf(RedemptionClaim calldata claim, uint64 claimIndex)
        public
        pure
        returns (bytes32)
    {
        return Sha256SparseMerkle.hashLeaf(
            APPROVED_REDEMPTION_LEAF_DOMAIN,
            claim.protocolVersion,
            claim.vaultId,
            claim.elementsGenesisHash,
            claim.usddAssetId,
            claim.burnId,
            claimIndex,
            claim.amountUSDT6,
            claim.recipient
        );
    }

    /// @notice Canonical identity of the Elements burn outpoint miners may approve.
    /// @dev `burnTxid` is the raw 32 bytes in canonical RPC/display hex order;
    ///      `burnVout` is encoded as four-byte big-endian by `abi.encodePacked`.
    function computeBurnId(bytes32 burnTxid, uint32 burnVout) public view returns (bytes32) {
        return sha256(abi.encodePacked(BURN_ID_DOMAIN, ELEMENTS_GENESIS_HASH, burnTxid, burnVout));
    }

    /// @notice Exact 65-byte Elements burn payload for an M6-approved redemption claim.
    function encodeBurnPayload(address recipient, uint64 amountUSDT6) external view returns (bytes memory) {
        if (
            recipient == address(0) || recipient == address(this) || amountUSDT6 == 0
                || amountUSDT6 > MAX_BURN_AMOUNT_USDT6
        ) revert InvalidRedemptionClaim();
        return abi.encodePacked(BURN_PAYLOAD_MAGIC, BURN_PAYLOAD_VERSION, VAULT_ID, recipient, amountUSDT6);
    }

    function reserveStatus()
        external
        view
        returns (uint256 reserve, uint256 liability, uint256 surplus, bool solvent)
    {
        reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        liability = principalLiabilityUSDT6;
        solvent = reserve >= liability;
        if (solvent) surplus = reserve - liability;
    }

    function _validateNextState(ApprovedRedemptionState calldata next) private view {
        uint64 expectedSequence = approvedRedemptionState.sequence + 1;
        if (next.sequence != expectedSequence) revert WrongStateSequence(expectedSequence, next.sequence);
        if (next.approvedClaimCount <= approvedRedemptionState.approvedClaimCount) {
            revert NoNewApprovedClaims();
        }
        if (next.cumulativeApprovedClaimRoot == approvedRedemptionState.cumulativeApprovedClaimRoot) {
            revert ApprovedClaimRootDidNotAdvance(approvedRedemptionState.cumulativeApprovedClaimRoot);
        }
        if (consumedM6ids[next.approvedM6id]) revert M6idAlreadyConsumed(next.approvedM6id);
        if (
            next.cumulativeApprovedClaimRoot == bytes32(0) || next.approvedM6id == bytes32(0)
                || next.bitcoinTipHash == bytes32(0)
        ) revert InvalidApprovedRedemptionState();

        ApprovedRedemptionState memory current = approvedRedemptionState;
        if (next.bitcoinHeight <= current.bitcoinHeight) {
            revert NonIncreasingBitcoinHeight(current.bitcoinHeight, next.bitcoinHeight);
        }
        if (next.bitcoinMedianTimePast < current.bitcoinMedianTimePast) {
            revert DecreasingBitcoinMedianTimePast(
                current.bitcoinMedianTimePast, next.bitcoinMedianTimePast
            );
        }
        if (next.bitcoinChainwork <= current.bitcoinChainwork) {
            revert NonIncreasingBitcoinChainwork(current.bitcoinChainwork, next.bitcoinChainwork);
        }
        if (
            approvedRedemptionStateHash == bytes32(0)
                && next.bitcoinChainwork < MINIMUM_ACTIVATION_CHAINWORK
        ) {
            revert ActivationChainworkNotReached(next.bitcoinChainwork, MINIMUM_ACTIVATION_CHAINWORK);
        }
    }

    function _requireSolvent(uint256 liability) private view {
        uint256 reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        if (reserve < liability) revert ReserveInsolvent(reserve, liability);
    }

    function _hashStateContents(ApprovedRedemptionState memory state_) private pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                state_.sequence,
                state_.approvedClaimCount,
                state_.cumulativeApprovedClaimRoot,
                state_.approvedM6id,
                state_.bitcoinTipHash,
                state_.bitcoinHeight,
                state_.bitcoinMedianTimePast,
                state_.bitcoinChainwork
            )
        );
    }
}
