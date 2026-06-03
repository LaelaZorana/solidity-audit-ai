// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/// @title OldToken
/// @notice Pre-0.8 arithmetic without SafeMath — silent overflow/underflow.
contract OldToken {
    mapping(address => uint256) public balanceOf;

    constructor(uint256 initial) {
        balanceOf[msg.sender] = initial;
    }

    // VULNERABLE: on Solidity <0.8 with no SafeMath, subtracting more than the
    // balance underflows to a huge number; addition can overflow.
    function transfer(address to, uint256 value) external {
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
    }
}
