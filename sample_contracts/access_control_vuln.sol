// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// ACCESS CONTROL VULNERABILITY SAMPLE CONTRACTS
// Demonstrates various access control issues in smart contracts
// Used for security testing and demonstration purposes
// ============================================================

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title AdminPanel
 * @dev Demo contract with multiple access control vulnerabilities
 * 
 * SECURITY WARNING: This contract contains intentional 
 * vulnerabilities for educational testing.
 * 
 * Vulnerabilities include:
 * 1. Missing access modifiers
 * 2. Public functions that should be internal
 * 3. Missing require statements
 * 4. Inadequate role checks
 */
contract AdminPanel {
    // State variables
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public isAdmin;
    mapping(address => bool) public isModerator;
    mapping(address => bool) public isBlocked;
    
    uint256 public contractBalance;
    uint256 public admin_counter;
    uint256 public moderator_counter;
    
    mapping(address => uint256) public userBalances;
    mapping(address => uint256) public lastAccessTime;
    
    // Configuration
    bool public paused = false;
    bool public initialized = false;
    uint256 public constant MAX_ADMIN = 10;
    uint256 public constant MAX_TRANSFER = 100 ether;
    
    // Events
    event OwnershipTransferInitiated(address oldOwner, address newOwner);
    event OwnershipTransferred(address oldOwner, address newOwner);
    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);
    event ModeratorAdded(address indexed moderator);
    event UserBlocked(address indexed user);
    event ContractPaused();
    event ContractUnpaused();
    
    /**
     * @dev Constructor - sets deployer as initial owner
     */
    constructor() {
        owner = msg.sender;
        isAdmin[msg.sender] = true;
    }
    
    /**
     * @dev Initializer - VULNERABILITY: Missing access control
     */
    function initialize() public {
        // VULNERABILITY: Anyone can initialize!
        require(!initialized, "Already initialized");
        initialized = true;
    }
    
    /**
     * @dev Claim ownership - VULNERABILITY
     */
    function claimOwnership() public {
        // VULNERABILITY: No verification of msg.sender
        pendingOwner = msg.sender;
    }
    
    /**
     * @dev Accept ownership - VULNERABILITY
     */
    function acceptOwnership() public {
        // VULNERABILITY: Can be called by anyone
        require(pendingOwner != address(0), "No pending owner");
        
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        
        emit OwnershipTransferred(oldOwner, owner);
    }
    
    /**
     * @dev Add admin - MISSING ACCESS CONTROL
     */
    function addAdmin(address _newAdmin) public {
        // VULNERABILITY: No access control check!
        require(_newAdmin != address(0), "Invalid address");
        require(!isAdmin[_newAdmin], "Already admin");
        
        isAdmin[_newAdmin] = true;
        admin_counter++;
        
        emit AdminAdded(_newAdmin);
    }
    
    /**
     * @dev Remove admin - MISSING ACCESS CONTROL
     */
    function removeAdmin(address _admin) public {
        // VULNERABILITY: No access control!
        require(isAdmin[_admin], "Not an admin");
        
        isAdmin[_admin] = false;
        admin_counter--;
        
        emit AdminRemoved(_admin);
    }
    
    /**
     * @dev Add moderator - VULNERABILITY
     */
    function addModerator(address _newMod) public {
        // VULNERABILITY: No access control
        require(_newMod != address(0), "Invalid");
        
        isModerator[_newMod] = true;
        moderator_counter++;
        
        emit ModeratorAdded(_newMod);
    }
    
    /**
     * @dev Block user - MISSING ACCESS CONTROL
     */
    function blockUser(address _user) public {
        // VULNERABILITY: Anyone can block users!
        require(_user != address(0), "Invalid");
        
        isBlocked[_user] = true;
        
        emit UserBlocked(_user);
    }
    
    /**
     * @dev Unblock user - MISSING ACCESS CONTROL
     */
    function unblockUser(address _user) public {
        // VULNERABILITY: No access control
        isBlocked[_user] = false;
    }
    
    /**
     * @dev Withdraw funds - VULNERABILITY
     */
    function withdraw() public {
        // VULNERABILITY: Anyone can withdraw contract funds!
        require(msg.sender != address(0));
        
        payable(msg.sender).transfer(address(this).balance);
    }
    
    /**
     * @dev Withdraw specific amount - VULNERABILITY
     */
    function withdrawAmount(uint256 _amount) public {
        // VULNERABILITY: No proper access control
        require(_amount <= address(this).balance, "Insufficient balance");
        
        payable(msg.sender).transfer(_amount);
    }
    
    /**
     * @dev Emergency pause - MISSING ACCESS CONTROL
     */
    function emergencyPause() public {
        // VULNERABILITY: Anyone can pause!
        paused = true;
        
        emit ContractPaused();
    }
    
    /**
     * @dev Emergency unpause - MISSING ACCESS CONTROL
     */
    function emergencyUnpause() public {
        // VULNERABILITY: Anyone can unpause!
        paused = false;
        
        emit ContractUnpaused();
    }
    
    /**
     * @dev Update owner - VULNERABILITY
     */
    function updateOwner(address _newOwner) public {
        // VULNERABILITY: No access control
        owner = _newOwner;
    }
    
    /**
     * @dev Set contract balance - VULNERABILITY
     */
    function setContractBalance(uint256 _balance) public {
        // VULNERABILITY: No access control
        contractBalance = _balance;
    }
    
    /**
     * @dev Deposit - MISSING VALIDATION
     */
    function deposit() public payable {
        // VULNERABILITY: No pause check!
        userBalances[msg.sender] += msg.value;
    }
    
    /**
     * @dev Withdraw balance - VULNERABILITY
     */
    function withdrawBalance() public {
        // VULNERABILITY: No access control, no paused check
        require(userBalances[msg.sender] > 0, "No balance");
        
        uint256 amount = userBalances[msg.sender];
        userBalances[msg.sender] = 0;
        
        payable(msg.sender).transfer(amount);
    }
    
    /**
     * @dev Transfer to another user - VULNERABILITY
     */
    function transferTo(address _to, uint256 _amount) public {
        // VULNERABILITY: No access control, no paused check
        require(userBalances[msg.sender] >= _amount, "Insufficient");
        
        userBalances[msg.sender] -= _amount;
        userBalances[_to] += _amount;
    }
    
    /**
     * @dev Batch transfer - Same vulnerabilities
     */
    function batchTransfer(address[] memory _recipients, uint256 _amount) public {
        for (uint256 i = 0; i < _recipients.length; i++) {
            // VULNERABLE: Each transfer
            transferTo(_recipients[i], _amount);
        }
    }
    
    /**
     * @dev Update last access time - VULNERABILITY
     */
    function updateLastAccess() public {
        lastAccessTime[msg.sender] = block.timestamp;
    }
    
    /**
     * @dev Get user balance - MISSING ACCESS CONTROL
     */
    function getUserBalance(address _user) public view returns (uint256) {
        // VULNERABILITY: Anyone can query any user's balance!
        return userBalances[_user];
    }
    
    /**
     * @dev Mint tokens - VULNERABILITY
     */
    function mint(address _to, uint256 _amount) public {
        // VULNERABILITY: No access control at all!
        userBalances[_to] += _amount;
    }
    
    /**
     * @dev Burn tokens - VULNERABILITY
     */
    function burn(address _from, uint256 _amount) public {
        // VULNERABILITY: No access control!
        require(userBalances[_from] >= _amount, "Insufficient");
        userBalances[_from] -= _amount;
    }
    
    /**
     * @dev Upgrade contract - VULNERABILITY
     */
    function upgrade(address _newImplementation) public {
        // VULNERABILITY: No access control!
    }
    
    /**
     * @dev Destroy contract - VULNERABILITY
     */
    function destroy() public {
        // VULNERABILITY: Anyone can destroy!
        selfdestruct(payable(owner));
    }
    
    // Receive ETH
    receive() external payable {
        userBalances[msg.sender] += msg.value;
    }
    
    // Fallback
    fallback() external payable {}
}

/**
 * @title ProperAdminPanel
 * @dev CORRECT implementation with proper access controls
 */
contract ProperAdminPanel is Ownable, AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MODERATOR_ROLE = keccak256("MODERATOR_ROLE");
    
    mapping(address => bool) public isBlocked;
    bool public paused = false;
    
    event UserBlocked(address indexed user);
    event ContractPaused();
    event ContractUnpaused();
    
    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "Not admin");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }
    
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }
    
    function addAdmin(address _account) external onlyAdmin {
        grantRole(ADMIN_ROLE, _account);
    }
    
    function removeAdmin(address _account) external onlyAdmin {
        revokeRole(ADMIN_ROLE, _account);
    }
    
    function blockUser(address _user) external onlyAdmin {
        isBlocked[_user] = true;
        emit UserBlocked(_user);
    }
    
    function pause() external onlyAdmin {
        paused = true;
        emit ContractPaused();
    }
    
    function unpause() external onlyAdmin {
        paused = false;
        emit ContractUnpaused();
    }
    
    function withdraw() external onlyAdmin whenNotPaused {
        payable(owner).transfer(address(this).balance);
    }
    
    function deposit() external payable whenNotPaused {
        // deposit logic
    }
    
    receive() external payable whenNotPaused {}
}