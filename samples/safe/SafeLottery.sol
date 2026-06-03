// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IVRFCoordinator {
    function requestRandomWords(
        bytes32 keyHash,
        uint64 subId,
        uint16 confirmations,
        uint32 gasLimit,
        uint32 numWords
    ) external returns (uint256 requestId);
}

/// @title SafeLottery
/// @notice Uses a verifiable randomness oracle (Chainlink VRF-style), not block data.
contract SafeLottery {
    address public owner;
    address[] public players;
    IVRFCoordinator public coordinator;
    bytes32 public keyHash;
    uint64 public subId;

    constructor(address coord) {
        owner = msg.sender;
        coordinator = IVRFCoordinator(coord);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function enter() external payable {
        require(msg.value == 0.1 ether, "wrong amount");
        players.push(msg.sender);
    }

    // SAFE: randomness is requested from a VRF oracle.
    function requestWinner() external onlyOwner returns (uint256) {
        return coordinator.requestRandomWords(keyHash, subId, 3, 200000, 1);
    }
}
