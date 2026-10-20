// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Legacy-style test token whose transfer methods return no data.
contract MockNoReturnUSDT {
    uint8 public constant decimals = 6;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address recipient, uint256 amount) external {
        _transfer(msg.sender, recipient, amount);
    }

    function transferFrom(address sender, address recipient, uint256 amount) external {
        uint256 approved = allowance[sender][msg.sender];
        require(approved >= amount, "allowance");
        allowance[sender][msg.sender] = approved - amount;
        _transfer(sender, recipient, amount);
    }

    function _transfer(address sender, address recipient, uint256 amount) private {
        uint256 senderBalance = balanceOf[sender];
        require(senderBalance >= amount, "balance");
        balanceOf[sender] = senderBalance - amount;
        balanceOf[recipient] += amount;
    }
}
