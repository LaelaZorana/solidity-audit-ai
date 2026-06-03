// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title NaiveLottery
/// @notice Uses block properties for randomness.
contract NaiveLottery {
    address[] public players;

    function enter() external payable {
        require(msg.value == 0.1 ether, "wrong amount");
        players.push(msg.sender);
    }

    // VULNERABLE: block.timestamp and block.prevrandao are miner/validator
    // influenced — the winner can be predicted or manipulated.
    function pickWinner() external returns (address) {
        uint256 idx = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao))
        ) % players.length;
        address winner = players[idx];
        return winner;
    }
}
