// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {USDDInboundVaultV2} from "./USDDInboundVaultV2.sol";
import {IUSDDRedemptionProofVerifierV2} from "./interfaces/IUSDDRedemptionProofVerifierV2.sol";
import {ExactSafeERC20} from "./libraries/ExactSafeERC20.sol";

/// @title USDDVaultV2
/// @notice One ownerless reserve from refundable intent through proved payout.
/// @dev The immutable verifier proves the complete V11 Elements burn, exact
///      M3/M4/M6 result, BMM/parent history and finality. This contract binds
///      the payout, consumes each burn once, and reconciles the same liability
///      created by the inbound MINT. It has no privileged or arbitrary-call path.
contract USDDVaultV2 is USDDInboundVaultV2 {
    using ExactSafeERC20 for address;

    uint32 public constant REDEMPTION_PROTOCOL_VERSION = 2;
    uint64 public constant MAX_BURN_AMOUNT_USDT6 = 20_000_000e6;
    bytes32 public constant REQUIRED_REDEMPTION_SECURITY_MODEL_ID =
        keccak256("USDD_V11_STRONG_RECURSIVE_ELEMENTS_BURN_AND_M6_PROFILE");
    bytes32 private constant REDEMPTION_CUSTODY_ID_DOMAIN = keccak256("USDD_UNIFIED_CUSTODY_ID_V2");
    bytes32 private constant REDEMPTION_STATEMENT_DOMAIN = keccak256("USDD_STRONG_REDEMPTION_STATEMENT_V2");
    bytes32 private constant BURN_ID_DOMAIN = keccak256("USDD_BURN_ID_V2");
    bytes4 public constant BURN_PAYLOAD_MAGIC = 0x55534444;
    uint8 public constant BURN_PAYLOAD_VERSION = 2;

    struct RedemptionConfig {
        address redemptionProofVerifier;
        bytes32 redemptionSecurityModelId;
        bytes32 redemptionVerifierProgramId;
        bytes32 redemptionVerifierConfigHash;
    }

    struct RedemptionClaim {
        uint32 protocolVersion;
        bytes32 custodyId;
        bytes32 elementsGenesisHash;
        bytes32 usddAssetId;
        bytes32 burnTxid;
        uint32 burnVout;
        bytes32 burnId;
        uint64 amountUSDT6;
        address recipient;
        bytes32 approvedM6id;
        bytes32 elementsExecutionCheckpointCommitment;
        bytes32 parentReplayCheckpointCommitment;
    }

    IUSDDRedemptionProofVerifierV2 public immutable REDEMPTION_PROOF_VERIFIER;
    bytes32 public immutable REDEMPTION_PROOF_VERIFIER_CODEHASH;
    bytes32 public immutable REDEMPTION_SECURITY_MODEL_ID;
    bytes32 public immutable REDEMPTION_VERIFIER_PROGRAM_ID;
    bytes32 public immutable REDEMPTION_VERIFIER_CONFIG_HASH;
    bytes32 public immutable REDEMPTION_CUSTODY_ID;

    uint256 public totalRedeemedUSDT6;
    mapping(bytes32 burnId => bool spent) public spentBurnIds;
    mapping(bytes32 m6id => uint256 count) public redemptionsPaidByM6id;

    error RedemptionSecurityModelMismatch(bytes32 expected, bytes32 reported);
    error RedemptionVerifierProgramIdMismatch(bytes32 expected, bytes32 reported);
    error RedemptionVerifierConfigHashMismatch(bytes32 expected, bytes32 reported);
    error RedemptionVerifierCodeChanged(bytes32 expected, bytes32 actual);
    error RedemptionProofRejected(bytes32 statement);
    error InvalidRedemptionClaim();
    error WrongRedemptionDomain();
    error WrongBurnId(bytes32 expected, bytes32 supplied);
    error BurnAlreadySpent(bytes32 burnId);
    error MintAcknowledgedLiabilityInsufficient(uint256 amount, uint256 liability);

    event StrongRedemptionPaid(
        bytes32 indexed burnId,
        bytes32 indexed approvedM6id,
        address indexed recipient,
        uint64 amountUSDT6,
        bytes32 elementsExecutionCheckpointCommitment,
        bytes32 parentReplayCheckpointCommitment,
        address submitter
    );

    constructor(DeploymentConfig memory inbound, RedemptionConfig memory redemption)
        USDDInboundVaultV2(inbound)
    {
        address verifierAddress = redemption.redemptionProofVerifier;
        if (verifierAddress == address(0)) revert ZeroAddress();
        if (verifierAddress.code.length == 0) revert AddressHasNoCode(verifierAddress);
        if (
            redemption.redemptionSecurityModelId == bytes32(0)
                || redemption.redemptionVerifierProgramId == bytes32(0)
                || redemption.redemptionVerifierConfigHash == bytes32(0)
        ) revert ZeroIdentifier();
        if (redemption.redemptionSecurityModelId != REQUIRED_REDEMPTION_SECURITY_MODEL_ID) {
            revert RedemptionSecurityModelMismatch(REQUIRED_REDEMPTION_SECURITY_MODEL_ID, redemption.redemptionSecurityModelId);
        }
        IUSDDRedemptionProofVerifierV2 verifier = IUSDDRedemptionProofVerifierV2(verifierAddress);
        if (verifier.securityModelId() != redemption.redemptionSecurityModelId) {
            revert RedemptionSecurityModelMismatch(redemption.redemptionSecurityModelId, verifier.securityModelId());
        }
        if (verifier.verifierProgramId() != redemption.redemptionVerifierProgramId) {
            revert RedemptionVerifierProgramIdMismatch(redemption.redemptionVerifierProgramId, verifier.verifierProgramId());
        }
        if (verifier.verifierConfigHash() != redemption.redemptionVerifierConfigHash) {
            revert RedemptionVerifierConfigHashMismatch(redemption.redemptionVerifierConfigHash, verifier.verifierConfigHash());
        }
        REDEMPTION_PROOF_VERIFIER = verifier;
        REDEMPTION_PROOF_VERIFIER_CODEHASH = verifierAddress.codehash;
        REDEMPTION_SECURITY_MODEL_ID = redemption.redemptionSecurityModelId;
        REDEMPTION_VERIFIER_PROGRAM_ID = redemption.redemptionVerifierProgramId;
        REDEMPTION_VERIFIER_CONFIG_HASH = redemption.redemptionVerifierConfigHash;
        bytes32 deploymentHash = sha256(abi.encodePacked(verifierAddress, redemption.redemptionSecurityModelId, redemption.redemptionVerifierProgramId, redemption.redemptionVerifierConfigHash));
        REDEMPTION_CUSTODY_ID = sha256(abi.encodePacked(REDEMPTION_CUSTODY_ID_DOMAIN, REDEMPTION_PROTOCOL_VERSION, block.chainid, address(this), VAULT_ID, PROTOCOL_ID, ELEMENTS_GENESIS_HASH, USDD_ASSET_ID, deploymentHash));
    }

    /// @notice Pays one proof-authorized burn of already minted USDD.
    function redeem(RedemptionClaim calldata claim, bytes calldata proof) external nonReentrant {
        _validateClaim(claim);
        if (spentBurnIds[claim.burnId]) revert BurnAlreadySpent(claim.burnId);
        if (claim.amountUSDT6 > mintAcknowledgedLiabilityUSDT6) {
            revert MintAcknowledgedLiabilityInsufficient(claim.amountUSDT6, mintAcknowledgedLiabilityUSDT6);
        }
        bytes32 statement = redemptionStatement(claim);
        _requireRedemptionVerifierIdentity();
        if (!REDEMPTION_PROOF_VERIFIER.verify(statement, proof)) revert RedemptionProofRejected(statement);

        spentBurnIds[claim.burnId] = true;
        mintAcknowledgedLiabilityUSDT6 -= claim.amountUSDT6;
        committedLiabilityUSDT6 -= claim.amountUSDT6;
        totalRedeemedUSDT6 += claim.amountUSDT6;
        redemptionsPaidByM6id[claim.approvedM6id] += 1;
        USDT.pushExact(claim.recipient, claim.amountUSDT6);
        _requireUnifiedAccountingAndSolvency();
        emit StrongRedemptionPaid(claim.burnId, claim.approvedM6id, claim.recipient, claim.amountUSDT6, claim.elementsExecutionCheckpointCommitment, claim.parentReplayCheckpointCommitment, msg.sender);
    }

    function redemptionStatement(RedemptionClaim calldata claim) public view returns (bytes32) {
        bytes32 verifierIdentity = sha256(abi.encodePacked(REDEMPTION_SECURITY_MODEL_ID, REDEMPTION_VERIFIER_PROGRAM_ID, REDEMPTION_VERIFIER_CONFIG_HASH));
        bytes32 claimHash = sha256(abi.encodePacked(claim.protocolVersion, claim.custodyId, claim.elementsGenesisHash, claim.usddAssetId, claim.burnTxid, claim.burnVout, claim.burnId, claim.amountUSDT6, claim.recipient, claim.approvedM6id, claim.elementsExecutionCheckpointCommitment, claim.parentReplayCheckpointCommitment));
        return sha256(abi.encodePacked(REDEMPTION_STATEMENT_DOMAIN, REDEMPTION_PROTOCOL_VERSION, block.chainid, address(this), REDEMPTION_CUSTODY_ID, VAULT_ID, PROTOCOL_ID, verifierIdentity, claimHash));
    }

    function computeBurnId(bytes32 burnTxid, uint32 burnVout) public view returns (bytes32) {
        return sha256(abi.encodePacked(BURN_ID_DOMAIN, REDEMPTION_CUSTODY_ID, ELEMENTS_GENESIS_HASH, burnTxid, burnVout));
    }

    function encodeBurnPayload(address recipient, uint64 amountUSDT6) external view returns (bytes memory) {
        if (recipient == address(0) || recipient == address(this) || amountUSDT6 == 0 || amountUSDT6 > MAX_BURN_AMOUNT_USDT6) revert InvalidRedemptionClaim();
        return abi.encodePacked(BURN_PAYLOAD_MAGIC, BURN_PAYLOAD_VERSION, REDEMPTION_CUSTODY_ID, recipient, amountUSDT6);
    }

    function unifiedReserveStatus() external view returns (uint256 reserve, uint256 accountedCustody, uint256 mintAcknowledged, uint256 surplus, bool solvent) {
        reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        accountedCustody = accountedCustodyUSDT6();
        mintAcknowledged = mintAcknowledgedLiabilityUSDT6;
        solvent = reserve >= accountedCustody;
        if (solvent) surplus = reserve - accountedCustody;
    }

    function _validateClaim(RedemptionClaim calldata claim) private view {
        if (claim.protocolVersion != REDEMPTION_PROTOCOL_VERSION || claim.custodyId != REDEMPTION_CUSTODY_ID || claim.elementsGenesisHash != ELEMENTS_GENESIS_HASH || claim.usddAssetId != USDD_ASSET_ID) revert WrongRedemptionDomain();
        bytes32 expectedBurnId = computeBurnId(claim.burnTxid, claim.burnVout);
        if (claim.burnId != expectedBurnId) revert WrongBurnId(expectedBurnId, claim.burnId);
        if (claim.burnTxid == bytes32(0) || claim.burnId == bytes32(0) || claim.amountUSDT6 == 0 || claim.amountUSDT6 > MAX_BURN_AMOUNT_USDT6 || claim.recipient == address(0) || claim.recipient == address(this) || claim.approvedM6id == bytes32(0) || claim.elementsExecutionCheckpointCommitment == bytes32(0) || claim.parentReplayCheckpointCommitment == bytes32(0)) revert InvalidRedemptionClaim();
    }

    function _requireRedemptionVerifierIdentity() private view {
        bytes32 codehash = address(REDEMPTION_PROOF_VERIFIER).codehash;
        if (codehash != REDEMPTION_PROOF_VERIFIER_CODEHASH) revert RedemptionVerifierCodeChanged(REDEMPTION_PROOF_VERIFIER_CODEHASH, codehash);
        if (REDEMPTION_PROOF_VERIFIER.securityModelId() != REDEMPTION_SECURITY_MODEL_ID) revert RedemptionSecurityModelMismatch(REDEMPTION_SECURITY_MODEL_ID, REDEMPTION_PROOF_VERIFIER.securityModelId());
        if (REDEMPTION_PROOF_VERIFIER.verifierProgramId() != REDEMPTION_VERIFIER_PROGRAM_ID) revert RedemptionVerifierProgramIdMismatch(REDEMPTION_VERIFIER_PROGRAM_ID, REDEMPTION_PROOF_VERIFIER.verifierProgramId());
        if (REDEMPTION_PROOF_VERIFIER.verifierConfigHash() != REDEMPTION_VERIFIER_CONFIG_HASH) revert RedemptionVerifierConfigHashMismatch(REDEMPTION_VERIFIER_CONFIG_HASH, REDEMPTION_PROOF_VERIFIER.verifierConfigHash());
    }

    function _requireUnifiedAccountingAndSolvency() private view {
        if (committedLiabilityUSDT6 != unresolvedCommittedUSDT6 + mintAcknowledgedLiabilityUSDT6) {
            revert AccountingInvariantViolated();
        }
        uint256 accountedCustody = accountedCustodyUSDT6();
        uint256 reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        if (reserve < accountedCustody) revert ReserveInsolvent(reserve, accountedCustody);
    }
}
