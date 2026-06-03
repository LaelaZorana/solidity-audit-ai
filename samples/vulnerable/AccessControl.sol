// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title UnguardedVault
/// @notice Sensitive functions lack access control.
contract UnguardedVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {}

    // VULNERABLE: anyone can change the owner.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // VULNERABLE: anyone can drain the contract.
    function withdrawAll(address payable to) external {
        to.transfer(address(this).balance);
    }
}
