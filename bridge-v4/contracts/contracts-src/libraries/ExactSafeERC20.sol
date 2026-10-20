// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice ERC-20 calls with strict sender and receiver balance-delta checks.
/// @dev Supports tokens that return either no value or a canonical `true`.
///      Fee-on-transfer, rebasing-during-call, false-returning, and malformed
///      tokens are rejected because they cannot preserve 1:1 accounting.
library ExactSafeERC20 {
    error TokenBalanceQueryFailed(address token, address account);
    error TokenCallFailed(address token, bytes4 selector);
    error TokenReturnedFalse(address token, bytes4 selector);
    error TokenReturnedMalformedData(address token, bytes4 selector);
    error SenderDeltaMismatch(address token, uint256 expected, uint256 beforeBalance, uint256 afterBalance);
    error ReceiverDeltaMismatch(address token, uint256 expected, uint256 beforeBalance, uint256 afterBalance);

    bytes4 private constant BALANCE_OF = 0x70a08231;
    bytes4 private constant TRANSFER = 0xa9059cbb;
    bytes4 private constant TRANSFER_FROM = 0x23b872dd;

    function balanceOf(address token, address account) internal view returns (uint256 balance) {
        (bool success, bytes memory result) = token.staticcall(abi.encodeWithSelector(BALANCE_OF, account));
        if (!success || result.length != 32) revert TokenBalanceQueryFailed(token, account);
        balance = abi.decode(result, (uint256));
    }

    function pullExact(address token, address from, uint256 amount) internal {
        uint256 senderBefore = balanceOf(token, from);
        uint256 receiverBefore = balanceOf(token, address(this));

        _callOptionalTrue(token, TRANSFER_FROM, abi.encodeWithSelector(TRANSFER_FROM, from, address(this), amount));

        uint256 senderAfter = balanceOf(token, from);
        uint256 receiverAfter = balanceOf(token, address(this));
        if (senderAfter > senderBefore || senderBefore - senderAfter != amount) {
            revert SenderDeltaMismatch(token, amount, senderBefore, senderAfter);
        }
        if (receiverAfter < receiverBefore || receiverAfter - receiverBefore != amount) {
            revert ReceiverDeltaMismatch(token, amount, receiverBefore, receiverAfter);
        }
    }

    function pushExact(address token, address to, uint256 amount) internal {
        uint256 senderBefore = balanceOf(token, address(this));
        uint256 receiverBefore = balanceOf(token, to);

        _callOptionalTrue(token, TRANSFER, abi.encodeWithSelector(TRANSFER, to, amount));

        uint256 senderAfter = balanceOf(token, address(this));
        uint256 receiverAfter = balanceOf(token, to);
        if (senderAfter > senderBefore || senderBefore - senderAfter != amount) {
            revert SenderDeltaMismatch(token, amount, senderBefore, senderAfter);
        }
        if (receiverAfter < receiverBefore || receiverAfter - receiverBefore != amount) {
            revert ReceiverDeltaMismatch(token, amount, receiverBefore, receiverAfter);
        }
    }

    function _callOptionalTrue(address token, bytes4 selector, bytes memory callData) private {
        (bool success, bytes memory result) = token.call(callData);
        if (!success) revert TokenCallFailed(token, selector);
        if (result.length == 0) return;
        if (result.length != 32) revert TokenReturnedMalformedData(token, selector);

        uint256 returned;
        assembly ("memory-safe") {
            returned := mload(add(result, 0x20))
        }
        if (returned != 1) revert TokenReturnedFalse(token, selector);
    }
}
