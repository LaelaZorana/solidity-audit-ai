// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title SafeBank
/// @notice Reentrancy-safe: checks-effects-interactions + a reentrancy guard.
contract SafeBank {
    mapping(address => uint256) public balances;

    uint256 private _locked = 1;
    modifier nonReentrant() {
        require(_locked == 1, "reentrant");
        _locked = 2;
        _;
        _locked = 1;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: state updated BEFORE the external call, and guarded.
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount; // effect first
        (bool ok, ) = msg.sender.call{value: amount}(""); // interaction last
        require(ok, "transfer failed");
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}
