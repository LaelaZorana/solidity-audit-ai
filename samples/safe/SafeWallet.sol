// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title SafeWallet
/// @notice Uses msg.sender for auth, access-controlled sensitive functions,
///         and checks low-level call results.
contract SafeWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    receive() external payable {}

    // SAFE: msg.sender auth + access control + checked call.
    function transferTo(address payable dest, uint256 amount) external onlyOwner {
        (bool ok, ) = dest.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // SAFE: guarded owner change.
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
    }
}
