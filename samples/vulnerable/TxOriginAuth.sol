// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title PhishableWallet
/// @notice Uses tx.origin for auth — vulnerable to phishing via a relay contract.
contract PhishableWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    // VULNERABLE: tx.origin can be the victim while msg.sender is an attacker
    // contract the victim was tricked into calling.
    function transferTo(address payable dest, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        dest.transfer(amount);
    }
}
