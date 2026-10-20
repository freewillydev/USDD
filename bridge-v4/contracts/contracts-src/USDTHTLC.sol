// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ExactSafeERC20} from "./libraries/ExactSafeERC20.sol";

/// @title USDTHTLC
/// @notice Immutable, ownerless, single-swap USDT hash-time-locked escrow.
/// @dev This repository verifies the stock-solc EVM build only. A TRON/TVM
///      deployment requires a separate build and test with an exact supported
///      TRON-maintained compiler. Anyone may execute transitions, but funds can
///      only move between the fixed endpoints selected at deployment.
contract USDTHTLC {
    using ExactSafeERC20 for address;

    uint64 public constant MINIMUM_REFUND_GAP = 24 hours;

    enum State {
        Unfunded,
        Funded,
        Claimed,
        Refunded
    }

    address public immutable USDT;
    address public immutable FUNDER;
    address public immutable CLAIM_RECIPIENT;
    address public immutable REFUND_RECIPIENT;
    uint256 public immutable AMOUNT;
    bytes32 public immutable SECRET_HASH;
    uint32 public immutable ELEMENTS_REFUND_TIMESTAMP;
    uint64 public immutable REFUND_TIMESTAMP;

    State public state;
    uint256 private _reentrancyLock = 1;

    error ZeroAddress();
    error AddressHasNoCode(address target);
    error EndpointIsEscrow(address endpoint);
    error IdenticalRecipients(address recipient);
    error ZeroAmount();
    error InvalidSecretHash();
    error InvalidElementsRefundTimestamp(uint32 supplied, uint256 currentTime);
    error InvalidRefundTimestamp(uint64 supplied, uint256 currentTime);
    error UnsafeRefundOrder(uint32 elementsRefundTimestamp, uint64 externalRefundTimestamp, uint64 minimumGap);
    error InvalidState(State expected, State actual);
    error FundingWindowClosed(uint256 currentTime, uint32 refundTimestamp);
    error ClaimWindowClosed(uint256 currentTime, uint64 refundTimestamp);
    error RefundNotAvailable(uint256 currentTime, uint64 refundTimestamp);
    error InvalidSecret();
    error EscrowInsolvent(uint256 reserve, uint256 required);
    error ReentrantCall();

    event Funded(address indexed executor, address indexed funder, uint256 amount);
    event Claimed(address indexed executor, address indexed recipient, uint256 amount, bytes32 secret);
    event Refunded(address indexed executor, address indexed recipient, uint256 amount);

    constructor(
        address usdt,
        address funder,
        address claimRecipient,
        address refundRecipient,
        uint256 amount,
        bytes32 secretHash,
        uint32 elementsRefundTimestamp,
        uint64 refundTimestamp
    ) {
        if (usdt == address(0) || funder == address(0) || claimRecipient == address(0) || refundRecipient == address(0)) {
            revert ZeroAddress();
        }
        if (usdt.code.length == 0) revert AddressHasNoCode(usdt);
        if (funder == address(this)) revert EndpointIsEscrow(funder);
        if (claimRecipient == address(this)) revert EndpointIsEscrow(claimRecipient);
        if (refundRecipient == address(this)) revert EndpointIsEscrow(refundRecipient);
        if (claimRecipient == refundRecipient) revert IdenticalRecipients(claimRecipient);
        if (amount == 0) revert ZeroAmount();
        if (secretHash == bytes32(0)) revert InvalidSecretHash();
        if (elementsRefundTimestamp <= block.timestamp) {
            revert InvalidElementsRefundTimestamp(elementsRefundTimestamp, block.timestamp);
        }
        if (refundTimestamp <= block.timestamp) revert InvalidRefundTimestamp(refundTimestamp, block.timestamp);
        if (refundTimestamp < uint64(elementsRefundTimestamp) + MINIMUM_REFUND_GAP) {
            revert UnsafeRefundOrder(elementsRefundTimestamp, refundTimestamp, MINIMUM_REFUND_GAP);
        }

        USDT = usdt;
        FUNDER = funder;
        CLAIM_RECIPIENT = claimRecipient;
        REFUND_RECIPIENT = refundRecipient;
        AMOUNT = amount;
        SECRET_HASH = secretHash;
        ELEMENTS_REFUND_TIMESTAMP = elementsRefundTimestamp;
        REFUND_TIMESTAMP = refundTimestamp;
    }

    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert ReentrantCall();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    /// @notice Pulls the exact amount from the fixed funder after approval.
    /// @dev Execution is permissionless; the token source is not.
    function fund() external nonReentrant {
        if (state != State.Unfunded) revert InvalidState(State.Unfunded, state);
        if (block.timestamp >= ELEMENTS_REFUND_TIMESTAMP) {
            revert FundingWindowClosed(block.timestamp, ELEMENTS_REFUND_TIMESTAMP);
        }

        state = State.Funded;
        USDT.pullExact(FUNDER, AMOUNT);
        _requireSolvent();
        emit Funded(msg.sender, FUNDER, AMOUNT);
    }

    /// @notice Reveals the SHA-256 preimage and pays the fixed claim recipient.
    function claim(bytes32 secret) external nonReentrant {
        if (state != State.Funded) revert InvalidState(State.Funded, state);
        if (block.timestamp >= REFUND_TIMESTAMP) revert ClaimWindowClosed(block.timestamp, REFUND_TIMESTAMP);
        if (sha256(abi.encodePacked(secret)) != SECRET_HASH) revert InvalidSecret();

        _requireSolvent();
        state = State.Claimed;
        USDT.pushExact(CLAIM_RECIPIENT, AMOUNT);
        emit Claimed(msg.sender, CLAIM_RECIPIENT, AMOUNT, secret);
    }

    /// @notice Returns funds to the fixed refund recipient after expiry.
    function refund() external nonReentrant {
        if (state != State.Funded) revert InvalidState(State.Funded, state);
        if (block.timestamp < REFUND_TIMESTAMP) revert RefundNotAvailable(block.timestamp, REFUND_TIMESTAMP);

        _requireSolvent();
        state = State.Refunded;
        USDT.pushExact(REFUND_RECIPIENT, AMOUNT);
        emit Refunded(msg.sender, REFUND_RECIPIENT, AMOUNT);
    }

    function reserveBalance() external view returns (uint256) {
        return ExactSafeERC20.balanceOf(USDT, address(this));
    }

    function _requireSolvent() private view {
        uint256 reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        if (reserve < AMOUNT) revert EscrowInsolvent(reserve, AMOUNT);
    }
}
