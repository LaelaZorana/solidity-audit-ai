// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Proxy
/// @notice delegatecalls into a caller-supplied address.
contract Proxy {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: target is attacker-controlled; delegatecall runs arbitrary
    // code in this contract's storage context and can overwrite `owner`.
    function forward(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
