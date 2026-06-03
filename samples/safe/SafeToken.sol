// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title SafeToken
/// @notice Solidity >=0.8 checked arithmetic (reverts on overflow/underflow).
contract SafeToken {
    mapping(address => uint256) public balanceOf;

    constructor(uint256 initial) {
        balanceOf[msg.sender] = initial;
    }

    // SAFE: 0.8 reverts on underflow/overflow automatically.
    function transfer(address to, uint256 value) external {
        require(to != address(0), "zero address");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
    }
}
