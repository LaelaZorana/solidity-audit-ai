// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableBank
/// @notice Classic DAO-style reentrancy: external call before state update.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: sends ETH before zeroing the balance, so a malicious
    // fallback can re-enter withdraw() and drain the contract.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] -= amount; // state change AFTER external call
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}
