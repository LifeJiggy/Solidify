// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// DENIAL OF SERVICE (DoS) VULNERABILITY SAMPLE CONTRACTS
// Demonstrates DoS attack vectors in smart contracts
// Used for security testing and demonstration purposes
// ============================================================

/**
 * @title VulnerableAuction
 * @dev Auction contract with DoS vulnerabilities
 * 
 * SECURITY WARNING: This contract contains intentional 
 * vulnerabilities for educational testing.
 * 
 * Vulnerabilities:
 * 1. Unbounded loops
 * 2. External calls in loops
 * 3. Array length manipulation
 */
contract VulnerableAuction {
    
    struct Bid {
        address bidder;
        uint256 amount;
        uint256 timestamp;
    }
    
    // State variables
    address public owner;
    uint256 public auctionEndTime;
    address public highestBidder;
    uint256 public highestBid;
    bool public ended;
    
    // VULNERABLE: Dynamic array that can grow indefinitely
    Bid[] public allBids;
    mapping(address => uint256) public pendingReturns;
    mapping(address => Bid[]) public userBids;
    
    uint256 public bidCount;
    
    // Events
    event HighestBidIncreased(address bidder, uint256 amount);
    event AuctionEnded(address winner, uint256 amount);
    
    constructor(uint256 _duration) {
        owner = msg.sender;
        auctionEndTime = block.timestamp + _duration;
    }
    
    /**
     * @dev Place a bid - VULNERABLE to DoS
     */
    function bid() public payable {
        require(block.timestamp < auctionEndTime, "Auction ended");
        require(msg.value > highestBid, "Bid too low");
        
        // Store bid - VULNERABLE: unbounded array
        allBids.push(Bid(msg.sender, msg.value, block.timestamp));
        userBids[msg.sender].push(Bid(msg.sender, msg.value, block.timestamp));
        
        // Update highest bid
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
        bidCount++;
        
        emit HighestBidIncreased(msg.sender, msg.value);
    }
    
    /**
     * @dev Withdraw pending returns - VULNERABLE
     */
    function withdraw() public {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No pending returns");
        
        pendingReturns[msg.sender] = 0;
        
        // VULNERABLE: External call in loop could be exploited
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
    }
    
    /**
     * @dev End auction - VULNERABLE to unbounded loop
     */
    function endAuction() public {
        require(msg.sender == owner, "Not owner");
        require(!ended, "Already ended");
        
        ended = true;
        
        // VULNERABLE: Loop through all bids
        for (uint256 i = 0; i < allBids.length; i++) {
            // Process each bid
            if (allBids[i].amount > 0) {
                // Some processing
            }
        }
        
        emit AuctionEnded(highestBidder, highestBid);
    }
    
    /**
     * @dev Get all bidders - VULNERABLE
     */
    function getAllBidders() public view returns (address[] memory) {
        // VULNERABLE: Can return huge array
        address[] memory bidders = new address[](allBids.length);
        for (uint256 i = 0; i < allBids.length; i++) {
            bidders[i] = allBids[i].bidder;
        }
        return bidders;
    }
    
    /**
     * @dev Refund all - DoS vector
     */
    function refundAll() public {
        // VULNERABLE: Loop through all bids
        for (uint256 i = 0; i < allBids.length; i++) {
            address bidder = allBids[i].bidder;
            uint256 amount = allBids[i].amount;
            
            if (amount > 0) {
                pendingReturns[bidder] += amount;
                allBids[i].amount = 0;
            }
        }
    }
    
    receive() external payable {}
}

/**
 * @title VulnerableDistributor
 * @dev Token distributor with DoS vulnerability
 */
contract VulnerableDistributor {
    
    address public owner;
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Can be manipulated
    address[] public recipients;
    mapping(address => bool) public isRecipient;
    
    uint256 public totalDistributed;
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Add recipient - VULNERABLE
     */
    function addRecipient(address _recipient) public {
        require(msg.sender == owner, "Not owner");
        require(!isRecipient[_recipient], "Already recipient");
        
        recipients.push(_recipient);
        isRecipient[_recipient] = true;
    }
    
    /**
     * @dev Distribute tokens - VULNERABLE to gas limits
     */
    function distribute(uint256 _amount) public {
        require(msg.sender == owner, "Not owner");
        
        // VULNERABLE: Loop through all recipients
        for (uint256 i = 0; i < recipients.length; i++) {
            address recipient = recipients[i];
            
            // VULNERABLE: External call in loop
            (bool sent, ) = recipient.call{value: _amount}("");
            if (sent) {
                balances[recipient] += _amount;
                totalDistributed += _amount;
            }
        }
    }
    
    /**
     * @dev Get recipient count - DoS
     */
    function getRecipientCount() public view returns (uint256) {
        return recipients.length;
    }
    
    receive() external payable {}
}

/**
 * @title VulnerableVesting
 * @dev Vesting contract with DoS vulnerabilities
 */
contract VulnerableVesting {
    
    struct VestingSchedule {
        address beneficiary;
        uint256 amount;
        uint256 startTime;
        uint256 duration;
        uint256 released;
    }
    
    address public owner;
    
    // VULNERABLE: Dynamic array
    VestingSchedule[] public vestingSchedules;
    mapping(address => uint256[]) public beneficiaryScheduleIds;
    
    mapping(address => uint256) public totalVested;
    
    event VestingCreated(address beneficiary, uint256 amount, uint256 duration);
    event TokensReleased(address beneficiary, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Create vesting schedule - VULNERABLE
     */
    function createVesting(address _beneficiary, uint256 _amount, uint256 _duration) public {
        require(msg.sender == owner, "Not owner");
        
        // VULNERABLE: No limit on array size
        vestingSchedules.push(VestingSchedule(
            _beneficiary,
            _amount,
            block.timestamp,
            _duration,
            0
        ));
        
        uint256 scheduleId = vestingSchedules.length - 1;
        beneficiaryScheduleIds[_beneficiary].push(scheduleId);
        
        totalVested[_beneficiary] += _amount;
        
        emit VestingCreated(_beneficiary, _amount, _duration);
    }
    
    /**
     * @dev Release tokens for beneficiary - VULNERABLE
     */
    function release(address _beneficiary) public {
        // VULNERABLE: Loop through all schedules
        uint256 totalRelease = 0;
        
        for (uint256 i = 0; i < beneficiaryScheduleIds[_beneficiary].length; i++) {
            uint256 scheduleId = beneficiaryScheduleIds[_beneficiary][i];
            VestingSchedule storage schedule = vestingSchedules[scheduleId];
            
            uint256 vestedAmount = computeReleasable(schedule);
            if (vestedAmount > schedule.released) {
                uint256 releasable = vestedAmount - schedule.released;
                schedule.released += releasable;
                totalRelease += releasable;
            }
        }
        
        require(totalRelease > 0, "No tokens due");
        
        payable(_beneficiary).transfer(totalRelease);
        
        emit TokensReleased(_beneficiary, totalRelease);
    }
    
    /**
     * @dev Compute releasable amount
     */
    function computeReleasable(VestingSchedule storage schedule) internal view returns (uint256) {
        if (block.timestamp < schedule.startTime) {
            return 0;
        }
        
        uint256 timePassed = block.timestamp - schedule.startTime;
        if (timePassed >= schedule.duration) {
            return schedule.amount;
        }
        
        return (schedule.amount * timePassed) / schedule.duration;
    }
    
    /**
     * @dev Get vesting schedule count - DoS
     */
    function getScheduleCount() public view returns (uint256) {
        return vestingSchedules.length;
    }
    
    receive() external payable {}
}

/**
 * @title VulnerableICO
 * @dev ICO contract with DoS vulnerabilities
 */
contract VulnerableICO {
    
    address public owner;
    uint256 public icoStartTime;
    uint256 public icoEndTime;
    uint256 public tokenPrice = 1 ether;
    
    // VULNERABLE: Unbounded investor list
    address[] public investors;
    mapping(address => bool) public isInvestor;
    mapping(address => uint256) public investedAmount;
    
    uint256 public totalRaised;
    uint256 public tokenSold;
    
    event Invested(address investor, uint256 ethAmount, uint256 tokenAmount);
    
    constructor(uint256 _startTime, uint256 _duration) {
        owner = msg.sender;
        icoStartTime = _startTime;
        icoEndTime = _startTime + _duration;
    }
    
    /**
     * @dev Buy tokens - VULNERABLE
     */
    function buyTokens() public payable {
        require(block.timestamp >= icoStartTime, "Not started");
        require(block.timestamp <= icoEndTime, "Ended");
        require(msg.value >= 0.1 ether, "Minimum investment");
        
        uint256 tokenAmount = msg.value / tokenPrice;
        
        // VULNERABLE: Array can grow unbounded
        if (!isInvestor[msg.sender]) {
            investors.push(msg.sender);
            isInvestor[msg.sender] = true;
        }
        
        investedAmount[msg.sender] += msg.value;
        totalRaised += msg.value;
        tokenSold += tokenAmount;
        
        emit Invested(msg.sender, msg.value, tokenAmount);
    }
    
    /**
     * @dev Distribute bonus - VULNERABLE
     */
    function distributeBonus() public {
        require(msg.sender == owner, "Not owner");
        
        // VULNERABLE: Loop through all investors
        for (uint256 i = 0; i < investors.length; i++) {
            address investor = investors[i];
            uint256 investment = investedAmount[investor];
            
            // Calculate bonus
            if (investment > 10 ether) {
                // Send bonus
            }
        }
    }
    
    /**
     * @dev Refund all - DoS
     */
    function refundAll() public {
        require(msg.sender == owner, "Not owner");
        
        // VULNERABLE: Can run out of gas
        for (uint256 i = 0; i < investors.length; i++) {
            address investor = investors[i];
            uint256 amount = investedAmount[investor];
            
            if (amount > 0) {
                investedAmount[investor] = 0;
                payable(investor).transfer(amount);
            }
        }
    }
    
    /**
     * @dev Get investor count
     */
    function getInvestorCount() public view returns (uint256) {
        return investors.length;
    }
    
    receive() external payable {}
}

/**
 * @title VulnerablePaymentSplitter
 * @dev Payment splitter with DoS
 */
contract VulnerablePaymentSplitter {
    
    address public owner;
    
    // VULNERABLE: Payee list can grow
    address[] public payees;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public released;
    
    uint256 public totalReleased;
    
    event PayeeAdded(address payee, uint256 shares);
    event PaymentReleased(address payee, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Add payee - VULNERABLE
     */
    function addPayee(address _payee, uint256 _shares) public {
        require(msg.sender == owner, "Not owner");
        
        // VULNERABLE: No limit on payee count
        payees.push(_payee);
        shares[_payee] = _shares;
        
        emit PayeeAdded(_payee, _shares);
    }
    
    /**
     * @dev Release payment - VULNERABLE
     */
    function release(address _payee) public payable {
        require(shares[_payee] > 0, "Not a payee");
        
        uint256 totalReceived = address(this).balance + totalReleased;
        uint256 payment = (totalReceived * shares[_payee]) / 10000 - released[_payee];
        
        require(payment > 0, "No payment due");
        
        released[_payee] += payment;
        totalReleased += payment;
        
        payable(_payee).transfer(payment);
        
        emit PaymentReleased(_payee, payment);
    }
    
    /**
     * @dev Release to all - DoS
     */
    function releaseAll() public {
        // VULNERABLE: Loop can run out of gas
        for (uint256 i = 0; i < payees.length; i++) {
            release(payees[i]);
        }
    }
    
    /**
     * @dev Get payee count
     */
    function getPayeeCount() public view returns (uint256) {
        return payees.length;
    }
    
    receive() external payable {}
}

/**
 * @title FixedAuction
 * @dev CORRECT implementation with gas limits
 */
contract FixedAuction {
    
    struct Bid {
        address bidder;
        uint256 amount;
        uint256 timestamp;
    }
    
    address public owner;
    uint256 public auctionEndTime;
    address public highestBidder;
    uint256 public highestBid;
    bool public ended;
    
    // Limit bid count to prevent DoS
    uint256 public constant MAX_BIDS = 10000;
    
    // Use mapping instead of array
    mapping(address => uint256) public pendingReturns;
    mapping(address => Bid) public latestBid;
    uint256 public bidCount;
    
    event HighestBidIncreased(address bidder, uint256 amount);
    event AuctionEnded(address winner, uint256 amount);
    
    constructor(uint256 _duration) {
        owner = msg.sender;
        auctionEndTime = block.timestamp + _duration;
    }
    
    /**
     * @dev Place bid with protection
     */
    function bid() public payable {
        require(block.timestamp < auctionEndTime, "Auction ended");
        require(msg.value > highestBid, "Bid too low");
        require(bidCount < MAX_BIDS, "Max bids reached");
        
        // Update state before external call
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
        bidCount++;
        
        latestBid[msg.sender] = Bid(msg.sender, msg.value, block.timestamp);
        
        emit HighestBidIncreased(msg.sender, msg.value);
    }
    
    /**
     * @dev Withdraw - fixed
     */
    function withdraw() public {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No pending returns");
        
        pendingReturns[msg.sender] = 0;
        
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
    }
    
    /**
     * @dev End auction - bounded operations
     */
    function endAuction() public {
        require(msg.sender == owner, "Not owner");
        require(!ended, "Already ended");
        
        ended = true;
        emit AuctionEnded(highestBidder, highestBid);
    }
    
    receive() external payable {}
}

/**
 * @title FixedDistributor
 * @dev CORRECT implementation with pagination
 */
contract FixedDistributor {
    
    address public owner;
    uint256 public constant BATCH_SIZE = 50;
    
    struct Recipient {
        address addr;
        uint256 amount;
        bool distributed;
    }
    
    Recipient[] public recipients;
    uint256 public distributedCount;
    
    mapping(address => uint256) public balances;
    
    event RecipientAdded(address recipient, uint256 amount);
    event Distributed(uint256 startIndex, uint256 count);
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Add recipient with limit
     */
    function addRecipient(address _recipient, uint256 _amount) public {
        require(msg.sender == owner, "Not owner");
        
        recipients.push(Recipient(_recipient, _amount, false));
        emit RecipientAdded(_recipient, _amount);
    }
    
    /**
     * @dev Distribute in batches - DoS protected
     */
    function distribute(uint256 _startIndex) public {
        require(msg.sender == owner, "Not owner");
        
        uint256 endIndex = _startIndex + BATCH_SIZE;
        if (endIndex > recipients.length) {
            endIndex = recipients.length;
        }
        
        uint256 count = 0;
        for (uint256 i = _startIndex; i < endIndex; i++) {
            if (!recipients[i].distributed && recipients[i].amount > 0) {
                recipients[i].distributed = true;
                balances[recipients[i].addr] += recipients[i].amount;
                count++;
            }
        }
        
        distributedCount += count;
        emit Distributed(_startIndex, count);
    }
    
    /**
     * @dev Get remaining count
     */
    function getRemainingCount() public view returns (uint256) {
        return recipients.length - distributedCount;
    }
}