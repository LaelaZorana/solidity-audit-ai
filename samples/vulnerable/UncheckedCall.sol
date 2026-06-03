// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Payouts
/// @notice Ignores low-level call return values.
contract Payouts {
    mapping(address => uint256) public credits;

    function credit(address who) external payable {
        credits[who] += msg.value;
    }

    // VULNERABLE: the return value of call is discarded; a failed transfer is
    // treated as success and the credit is still cleared.
    function payout(address payable who) external {
        uint256 amount = credits[who];
        credits[who] = 0;
        who.call{value: amount}("");
    }

    // VULNERABLE: send() returns a bool that is ignored.
    function refund(address payable who, uint256 amount) external {
        who.send(amount);
    }
}
