// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// ============================================================
// INTEGER OVERFLOW/UNDERFLOW VULNERABILITY SAMPLE
// This contract demonstrates integer arithmetic vulnerabilities
// Used for security testing and demonstration purposes
// ============================================================

/**
 * @title TokenSale
 * @dev Token sale contract with overflow vulnerabilities
 * 
 * SECURITY WARNING: This contract contains intentional 
 * vulnerabilities for educational testing. DO NOT use in production.
 * 
 * Vulnerabilities:
 * 1. Integer overflow in arithmetic operations
 * 2. Division by zero potential
 * 3. Unchecked return values
 */
contract TokenSale {
    // Mapping of user addresses to token balances
    mapping(address => uint256) public balances;
    
    // Mapping of pending vesting schedules
    mapping(address => uint256) public vestingStart;
    mapping(address => uint256) public vestingAmount;
    mapping(address => uint256) public vestingDuration;
    
    // Total supply management
    uint256 public totalSupply;
    uint256 public tokenPrice = 1 ether;
    uint256 public constant MIN_PURCHASE = 0.01 ether;
    uint256 public constant MAX_PURCHASE = 100 ether;
    
    // Sale parameters
    uint256 public saleStartTime;
    uint256 public saleEndTime;
    uint256 public tokensSold;
    uint256 public maxTokens = 1000000 * 10**18;
    
    // Admin
    address public owner;
    
    // Events
    event TokensPurchased(address buyer, uint256 ethAmount, uint256 tokenAmount);
    event TokensSold(address seller, uint256 tokenAmount, uint256 ethAmount);
    event TokensTransferred(address from, address to, uint256 amount);
    event VestingStarted(address beneficiary, uint256 amount, uint256 duration);
    event AdminChanged(address oldAdmin, address newAdmin);
    
    // Constructor
    constructor() {
        owner = msg.sender;
        saleStartTime = block.timestamp;
        saleEndTime = saleStartTime + 30 days;
    }
    
    /**
     * @dev Buy tokens with ETH
     * 
     * VULNERABILITY: Integer overflow in multiplication
     * If _numTokens is very large, _numTokens * PRICE_PER_TOKEN can overflow
     */
    function buyTokens(uint256 _numTokens) public payable {
        require(block.timestamp >= saleStartTime, "Sale not started");
        require(block.timestamp <= saleEndTime, "Sale ended");
        require(_numTokens > 0, "Must buy positive amount");
        
        // VULNERABLE: No overflow check
        uint256 cost = _numTokens * tokenPrice;
        
        // VULNERABLE: Multiplication can overflow here
        require(msg.value >= cost, "Insufficient ETH sent");
        
        // Update balance - VULNERABLE to overflow
        balances[msg.sender] += _numTokens;
        tokensSold += _numTokens;
        
        emit TokensPurchased(msg.sender, msg.value, _numTokens);
        
        // Refund excess - VULNERABLE arithmetic
        uint256 refund = msg.value - cost;
        if (refund > 0) {
            payable(msg.sender).transfer(refund);
        }
    }
    
    /**
     * @dev Sell tokens for ETH
     * 
     * VULNERABILITY: Integer underflow in subtraction
     */
    function sellTokens(uint256 _numTokens) public {
        require(balances[msg.sender] >= _numTokens, "Insufficient balance");
        
        // VULNERABLE: Subtraction can underflow
        balances[msg.sender] -= _numTokens;
        
        // Calculate refund - VULNERABLE
        uint256 refund = _numTokens * tokenPrice;
        
        // Transfer ETH - VULNERABLE: Multiple issues
        payable(msg.sender).transfer(refund);
        
        tokensSold -= _numTokens;
        
        emit TokensSold(msg.sender, _numTokens, refund);
    }
    
    /**
     * @dev Batch transfer - OVERFLOW
     * 
     * Multiple overflows in single transaction
     */
    function batchTransfer(address[] memory _recipients, uint256 _numTokens) public {
        require(_recipients.length > 0, "No recipients");
        
        // VULNERABLE: Multiplication BEFORE check
        uint256 total = _recipients.length * _numTokens;
        
        require(balances[msg.sender] >= total, "Insufficient balance");
        
        // VULNERABLE: Loop with potential overflow
        for (uint256 i = 0; i < _recipients.length; i++) {
            // Each addition can overflow
            balances[_recipients[i]] += _numTokens;
            
            // Each subtraction can underflow
            balances[msg.sender] -= _numTokens;
            
            emit TokensTransferred(msg.sender, _recipients[i], _numTokens);
        }
    }
    
    /**
     * @dev Add to balance - OVERFLOW
     */
    function addBalance(address _user, uint256 _amount) public {
        // VULNERABLE: No bounds check
        balances[_user] += _amount;
    }
    
    /**
     * @dev Subtract from balance - UNDERFLOW
     */
    function subtractBalance(address _user, uint256 _amount) public {
        // VULNERABLE: Can underflow
        balances[_user] -= _amount;
    }
    
    /**
     * @dev Calculate total with potential overflow
     */
    function calculateTotal(address[] memory _users) public view returns (uint256) {
        uint256 total = 0;
        
        // VULNERABLE: Loop addition
        for (uint256 i = 0; i < _users.length; i++) {
            total += balances[_users[i]];
        }
        
        return total;
    }
    
    /**
     * @dev Issue airdrop - VULNERABLE to overflow
     */
    function airdrop(address[] memory _recipients, uint256 _amount) public {
        require(msg.sender == owner, "Only owner");
        
        // VULNERABLE: Each add can overflow
        for (uint256 i = 0; i < _recipients.length; i++) {
            balances[_recipients[i]] += _amount;
        }
    }
    
    /**
     * @dev Compound interest calculation - OVERFLOW
     */
    function calculateCompound(uint256 _principal, uint256 _rate, uint256 _time) public pure returns (uint256) {
        // VULNERABLE: Exponentiation overflow
        for (uint256 i = 0; i < _time; i++) {
            _principal = _principal * (100 + _rate) / 100;
        }
        return _principal;
    }
    
    /**
     * @dev Transfer with bonus - OVERFLOW
     */
    function transferWithBonus(address _to, uint256 _amount, uint256 _bonusPercent) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // VULNERABLE: Bonus calculation can overflow
        uint256 bonus = _amount * _bonusPercent / 100;
        uint256 total = _amount + bonus;
        
        // Both operations can overflow
        balances[msg.sender] -= _amount;
        balances[_to] += total;
    }
    
    /**
     * @dev Vesting schedule - UNDERFLOW
     */
    function startVesting(address _beneficiary, uint256 _amount, uint256 _duration) public {
        require(msg.sender == owner, "Only owner");
        
        // UNDERFLOW possible
        vestingAmount[_beneficiary] = _amount;
        vestingStart[_beneficiary] = block.timestamp;
        vestingDuration[_beneficiary] = _duration;
        
        emit VestingStarted(_beneficiary, _amount, _duration);
    }
    
    /**
     * @dev Claim vested tokens - UNDERFLOW
     */
    function claimVested() public {
        uint256 start = vestingStart[msg.sender];
        require(start > 0, "No vesting");
        
        uint256 duration = vestingDuration[msg.sender];
        uint256 amount = vestingAmount[msg.sender];
        
        // VULNERABLE: Time calculations
        uint256 vested = amount * (block.timestamp - start) / duration;
        
        // UNDERFLOW possible
        uint256 remaining = amount - vested;
        
        if (remaining > 0) {
            balances[msg.sender] += vested;
        }
    }
    
    /**
     * @dev Mint new tokens - OVERFLOW
     */
    function mint(uint256 _amount) public {
        require(msg.sender == owner, "Only owner");
        
        // VULNERABLE: Can overflow totalSupply
        totalSupply += _amount;
        balances[owner] += _amount;
    }
    
    /**
     * @dev Burn tokens - UNDERFLOW
     */
    function burn(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // UNDERFLOW
        balances[msg.sender] -= _amount;
        totalSupply -= _amount;
    }
    
    /**
     * @dev Batch mint - Multiple overflows
     */
    function batchMint(address[] memory _recipients, uint256 _amount) public {
        require(msg.sender == owner, "Only owner");
        
        // VULNERABLE
        for (uint256 i = 0; i < _recipients.length; i++) {
            balances[_recipients[i]] += _amount;
            totalSupply += _amount;
        }
    }
    
    /**
     * @dev Get rewards multiplier - OVERFLOW
     */
    function getRewardMultiplier(uint256 _amount, uint256 _multiplier) public pure returns (uint256) {
        // VULNERABLE
        return _amount * _multiplier;
    }
    
    /**
     * @dev Calculate fee - OVERFLOW
     */
    function calculateFee(uint256 _amount, uint256 _feePercent) public pure returns (uint256) {
        // VULNERABLE
        return _amount * _feePercent;
    }
    
    /**
     * @dev Update token price - OVERFLOW
     */
    function updatePrice(uint256 _newPrice) public {
        require(msg.sender == owner, "Only owner");
        
        // VULNERABLE: No bounds
        tokenPrice = _newPrice;
    }
    
    /**
     * @dev Emergency function to recover ETH
     */
    function emergencyWithdraw() public {
        require(msg.sender == owner, "Only owner");
        
        payable(owner).transfer(address(this).balance);
    }
    
    // Fallback to accept ETH
    receive() external payable {}
}

/**
 * @title SafeMathDemo
 * @dev CORRECT implementation showing proper overflow handling
 */
contract SafeMathDemo {
    using SafeMath for uint256;
    
    mapping(address => uint256) public balances;
    
    function addBalance(address _user, uint256 _amount) public {
        // Safe: Overflow protected
        balances[_user] = balances[_user].add(_amount);
    }
    
    function subBalance(address _user, uint256 _amount) public {
        // Safe: Underflow protected
        balances[_user] = balances[_user].sub(_amount);
    }
    
    function mulBalance(address _user, uint256 _multiplier) public view returns (uint256) {
        // Safe: Multiplication protected
        return balances[_user].mul(_multiplier);
    }
}

/**
 * @title OverflowToken
 * @dev Fixed token with SafeMath
 */
contract OverflowToken {
    using SafeMath for uint256;
    
    string public name = "Fixed Token";
    string public symbol = "FIX";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    function mint(address _to, uint256 _amount) public {
        balances[_to] = balances[_to].add(_amount);
        totalSupply = totalSupply.add(_amount);
    }
    
    function burn(uint256 _amount) public {
        balances[msg.sender] = balances[msg.sender].sub(_amount);
        totalSupply = totalSupply.sub(_amount);
    }
    
    function transfer(address _to, uint256 _amount) public returns (bool) {
        balances[msg.sender] = balances[msg.sender].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(msg.sender, _to, _amount);
        return true;
    }
    
    function approve(address _spender, uint256 _amount) public returns (bool) {
        allowance[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool) {
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_amount);
        balances[_from] = balances[_from].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(_from, _to, _amount);
        return true;
    }
}

/**
 * @title SafeMath library
 * @dev OpenZeppelin's SafeMath for reference
 */
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
    
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }
    
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }
    
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }
}