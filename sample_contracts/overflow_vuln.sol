// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6; // VULNERABILITY: No built-in overflow protection

contract TokenSale {
    mapping(address => uint256) public balances;
    uint256 constant PRICE_PER_TOKEN = 1 ether;

    // VULNERABILITY: Integer Overflow if user passes a massive _numTokens
    function buyTokens(uint256 _numTokens) public payable {
        require(msg.value == _numTokens * PRICE_PER_TOKEN, "Incorrect ETH sent");

        balances[msg.sender] += _numTokens;
    }

    function sellTokens(uint256 _numTokens) public {
        require(balances[msg.sender] >= _numTokens, "Insufficient tokens");

        balances[msg.sender] -= _numTokens;
        msg.sender.transfer(_numTokens * PRICE_PER_TOKEN);
    }
}