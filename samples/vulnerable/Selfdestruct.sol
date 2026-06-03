// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Destructible
/// @notice Anyone can selfdestruct and sweep the balance.
contract Destructible {
    receive() external payable {}

    // VULNERABLE: no access control on selfdestruct.
    function kill(address payable drain) external {
        selfdestruct(drain);
    }
}
