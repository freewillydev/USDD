// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Configurable six-decimal test token. Not for production.
contract MockUSDT {
    string public constant name = "Mock USDT";
    string public constant symbol = "mUSDT";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;
    uint16 public feeBps;
    bool public returnFalse;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
        totalSupply += amount;
        emit Transfer(address(0), recipient, amount);
    }

    function burn(address account, uint256 amount) external {
        require(balanceOf[account] >= amount, "balance");
        balanceOf[account] -= amount;
        totalSupply -= amount;
        emit Transfer(account, address(0), amount);
    }

    function setFeeBps(uint16 newFeeBps) external {
        require(newFeeBps <= 10_000, "fee");
        feeBps = newFeeBps;
    }

    function setReturnFalse(bool enabled) external {
        returnFalse = enabled;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return !returnFalse;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return !returnFalse;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
        uint256 approved = allowance[sender][msg.sender];
        if (approved != type(uint256).max) {
            require(approved >= amount, "allowance");
            allowance[sender][msg.sender] = approved - amount;
        }
        _transfer(sender, recipient, amount);
        return !returnFalse;
    }

    function _transfer(address sender, address recipient, uint256 amount) private {
        require(recipient != address(0), "recipient");
        uint256 senderBalance = balanceOf[sender];
        require(senderBalance >= amount, "balance");
        balanceOf[sender] = senderBalance - amount;

        uint256 fee = amount * feeBps / 10_000;
        uint256 received = amount - fee;
        balanceOf[recipient] += received;
        emit Transfer(sender, recipient, received);
        if (fee != 0) {
            totalSupply -= fee;
            emit Transfer(sender, address(0), fee);
        }
    }
}
