// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnHashAnchor {
    address public owner;
    mapping(bytes32 => uint256) public anchored;

    event Anchored(bytes32 indexed root, uint256 leafCount, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function anchor(bytes32 root, uint256 leafCount) external onlyOwner {
        require(anchored[root] == 0, "already anchored");
        anchored[root] = block.timestamp;
        emit Anchored(root, leafCount, block.timestamp);
    }

    function verify(bytes32 root) external view returns (bool exists, uint256 timestamp) {
        uint256 ts = anchored[root];
        return (ts != 0, ts);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        owner = newOwner;
    }
}
