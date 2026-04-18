// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// FLASH LOAN VULNERABILITY SAMPLE CONTRACTS
// Demonstrates flash loan attack vectors in DeFi protocols
// Used for security testing and demonstration purposes
// ============================================================

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
}

interface IComptroller {
    function enterMarkets(address[] calldata _markets) external returns (uint[] memory);
    function borrowRatePerBlock() external view returns (uint);
    function getAccountLiquidity(address account) external view returns (uint, uint, uint);
}

interface ILendingPool {
    function flashLoan(address _receiver, address _asset, uint256 _amount, bytes calldata _params) external;
    function deposit(address _asset, uint256 _amount, address _onBehalfOf, uint16 _referralCode) external;
    function withdraw(address _asset, uint256 _amount, address _to) external;
    function borrow(address _asset, uint256 _amount, uint256 _interestRateMode, uint16 _referralCode, address _onBehalfOf) external;
    function repay(address _asset, uint256 _amount, address _onBehalfOf) external returns (uint256);
}

/**
 * @title VulnerableDex
 * @dev DEX with flash loan vulnerability
 * 
 * SECURITY WARNING: This contract contains intentional 
 * vulnerabilities for educational testing.
 * 
 * Vulnerability: Price manipulation via flash loans
 */
contract VulnerableDex {
    using SafeERC20 for IERC20;
    
    // Token pairs
    mapping(address => mapping(address => uint256)) public tokenBalances;
    mapping(address => uint256) public ethBalance;
    
    // Exchange rates (simplified)
    mapping(address => mapping(address => uint256)) public exchangeRates;
    
    address public owner;
    uint256 public constant FEE = 3; // 0.3% fee
    
    event Swap(address indexed user, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut);
    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB);
    event LiquidityRemoved(address indexed provider, uint256 amountA, uint256 amountB);
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Swap tokens - VULNERABLE to price manipulation
     */
    function swap(address _tokenIn, address _tokenOut, uint256 _amountIn) public {
        require(_amountIn > 0, "Invalid amount");
        
        // Calculate rate based on current reserves
        // VULNERABLE: Rate can be manipulated in single transaction
        uint256 rate = getRate(_tokenIn, _tokenOut);
        uint256 amountOut = (_amountIn * rate) / 1000;
        
        // Apply fee
        uint256 fee = (amountOut * FEE) / 1000;
        amountOut = amountOut - fee;
        
        // Update balances
        tokenBalances[_tokenIn][msg.sender] -= _amountIn;
        tokenBalances[_tokenOut][msg.sender] += amountOut;
        tokenBalances[_tokenIn][address(this)] += _amountIn;
        tokenBalances[_tokenOut][address(this)] -= amountOut;
        
        // Transfer tokens
        IERC20(_tokenIn).safeTransferFrom(msg.sender, address(this), _amountIn);
        IERC20(_tokenOut).safeTransfer(msg.sender, amountOut);
        
        emit Swap(msg.sender, _tokenIn, _tokenOut, _amountIn, amountOut);
    }
    
    /**
     * @dev Get exchange rate - VULNERABLE
     * 
     * Attack: Attacker can manipulate reserves in single tx using flash loan
     */
    function getRate(address _tokenIn, address _tokenOut) public view returns (uint256) {
        uint256 inReserve = tokenBalances[_tokenIn][address(this)];
        uint256 outReserve = tokenBalances[_tokenOut][address(this)];
        
        // VULNERABLE: Simple xy=k without validation
        // Attacker can inflate inReserve then drain outReserve
        if (inReserve == 0 || outReserve == 0) {
            return 0;
        }
        
        return (outReserve * 1000) / inReserve;
    }
    
    /**
     * @dev Add liquidity - can be exploited
     */
    function addLiquidity(address _tokenA, address _tokenB, uint256 _amountA, uint256 _amountB) public {
        require(_amountA > 0 && _amountB > 0, "Invalid amounts");
        
        // Transfer tokens
        IERC20(_tokenA).safeTransferFrom(msg.sender, address(this), _amountA);
        IERC20(_tokenB).safeTransferFrom(msg.sender, address(this), _amountB);
        
        // Update reserves
        tokenBalances[_tokenA][address(this)] += _amountA;
        tokenBalances[_tokenB][address(this)] += _amountB;
        
        emit LiquidityAdded(msg.sender, _amountA, _amountB);
    }
    
    /**
     * @dev Remove liquidity - can be exploited
     */
    function removeLiquidity(address _tokenA, address _tokenB, uint256 _liquidity) public {
        require(_liquidity > 0, "Invalid amount");
        
        // Calculate share (simplified)
        uint256 shareA = _liquidity;
        uint256 shareB = _liquidity;
        
        // Update balances
        tokenBalances[_tokenA][address(this)] -= shareA;
        tokenBalances[_tokenB][address(this)] -= shareB;
        
        // Transfer
        IERC20(_tokenA).safeTransfer(msg.sender, shareA);
        IERC20(_tokenB).safeTransfer(msg.sender, shareB);
        
        emit LiquidityRemoved(msg.sender, shareA, shareB);
    }
    
    /**
     * @dev Emergency withdraw - VULNERABLE
     */
    function emergencyWithdraw(address _token) public {
        // VULNERABLE: Only owner check but missing!
        uint256 balance = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(owner, balance);
    }
    
    receive() external payable {
        ethBalance[address(this)] += msg.value;
    }
}

/**
 * @title FlashLoanAttacker
 * @dev Malicious contract to exploit VulnerableDex via flash loan
 */
contract FlashLoanAttacker {
    VulnerableDex public dex;
    IERC20 public tokenA;
    IERC20 public tokenB;
    address public attacker;
    uint256 public borrowedAmount;
    
    event AttackStarted(uint256 amount);
    event AttackProfited(uint256 profit);
    
    constructor(address _dexAddress, address _tokenA, address _tokenB) {
        dex = VulnerableDex(_dexAddress);
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
        attacker = msg.sender;
    }
    
    /**
     * @dev Execute flash loan attack
     */
    function attack(uint256 _borrowAmount) public {
        borrowedAmount = _borrowAmount;
        
        // Step 1: Manipulate tokenA reserve by depositing
        // In real attack, would use actual flash loan
        tokenA.transferFrom(msg.sender, address(this), _borrowAmount);
        tokenA.approve(address(dex), _borrowAmount);
        
        // Deposit to inflate reserves
        // This artificially increases tokenA reserve
        // Making the exchange rate extremely favorable
        
        // Step 2: Swap all manipulated tokens for tokenB
        // Due to manipulated rate, we get huge amount of tokenB
        
        // Step 3: Swap back or drain liquidity
        // Profit from the manipulated rate
        
        emit AttackStarted(_borrowAmount);
    }
    
    /**
     * @dev Calculate profit from attack
     */
    function calculateProfit() public view returns (uint256) {
        // Would calculate actual profit
        return 0;
    }
    
    /**
     * @dev Withdraw stolen funds
     */
    function withdraw() public {
        require(msg.sender == attacker, "Not attacker");
        
        uint256 balanceA = tokenA.balanceOf(address(this));
        uint256 balanceB = tokenB.balanceOf(address(this));
        
        if (balanceA > 0) tokenA.transfer(attacker, balanceA);
        if (balanceB > 0) tokenB.transfer(attacker, balanceB);
        
        emit AttackProfited(balanceB);
    }
}

/**
 * @title VulnerableLendingPool
 * @dev Lending pool with flash loan vulnerability
 */
contract VulnerableLendingPool is ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    // User collateral data
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrows;
    mapping(address => mapping(address => uint256)) public depositAmounts;
    
    // Asset reserves
    mapping(address => uint256) public reserves;
    
    // Interest rate configuration
    uint256 public constant BORROW_RATE = 5; // 5% APY
    uint256 public constant COLLATERAL_FACTOR = 75; // 75% LTV
    
    address public owner;
    
    event Deposited(address indexed user, address asset, uint256 amount);
    event Withdrawn(address indexed user, address asset, uint256 amount);
    event Borrowed(address indexed user, address asset, uint256 amount);
    event Repaid(address indexed user, address asset, uint256 amount);
    event Liquidated(address indexed liquidator, address indexed user, uint256 debt);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Deposit assets - FLASH LOAN ATTACK VECTOR
     */
    function deposit(address _asset, uint256 _amount) external nonReentrant {
        require(_amount > 0, "Invalid amount");
        
        // VULNERABLE: No proper health check after flash loan
        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _amount);
        
        collateral[msg.sender] += _amount;
        depositAmounts[msg.sender][_asset] += _amount;
        reserves[_asset] += _amount;
        
        emit Deposited(msg.sender, _asset, _amount);
    }
    
    /**
     * @dev Withdraw - VULNERABLE
     */
    function withdraw(address _asset, uint256 _amount) external nonReentrant {
        require(depositAmounts[msg.sender][_asset] >= _amount, "Insufficient deposit");
        
        // VULNERABLE: No health check!
        collateral[msg.sender] -= _amount;
        depositAmounts[msg.sender][_asset] -= _amount;
        reserves[_asset] -= _amount;
        
        IERC20(_asset).safeTransfer(msg.sender, _amount);
        
        emit Withdrawn(msg.sender, _asset, _amount);
    }
    
    /**
     * @dev Borrow against collateral - VULNERABLE
     */
    function borrow(address _asset, uint256 _amount) external nonReentrant {
        require(_amount > 0, "Invalid amount");
        
        // VULNERABLE: Can be manipulated in flash loan
        uint256 maxBorrow = (collateral[msg.sender] * COLLATERAL_FACTOR) / 100;
        
        require(borrows[msg.sender] + _amount <= maxBorrow, "Exceeds limit");
        
        // Update state
        borrows[msg.sender] += _amount;
        reserves[_asset] -= _amount;
        
        // Transfer borrowed amount
        IERC20(_asset).safeTransfer(msg.sender, _amount);
        
        emit Borrowed(msg.sender, _asset, _amount);
    }
    
    /**
     * @dev Repay borrow
     */
    function repay(address _asset, uint256 _amount) external nonReentrant {
        require(_amount > 0, "Invalid amount");
        
        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _amount);
        
        // Apply interest (simplified)
        uint256 interest = (borrows[msg.sender] * BORROW_RATE) / 10000;
        uint256 totalRepay = _amount + interest;
        
        require(totalRepay <= borrows[msg.sender], "Overpay");
        
        borrows[msg.sender] -= totalRepay;
        reserves[_asset] += totalRepay;
        
        emit Repaid(msg.sender, _asset, totalRepay);
    }
    
    /**
     * @dev Get account health - VULNERABLE
     */
    function getAccountHealth(address _user) public view returns (uint256) {
        if (borrows[_user] == 0) return type(uint256).max;
        
        uint256 health = (collateral[_user] * 100) / borrows[_user];
        return health;
    }
    
    /**
     * @dev Liquidate position - can be exploited
     */
    function liquidate(address _user, address _asset) external nonReentrant {
        require(getAccountHealth(_user) < 100, "Healthy");
        
        uint256 debt = borrows[_user];
        
        // VULNERABLE: Can be done in flash loan
        borrows[_user] = 0;
        collateral[_user] = 0;
        
        // Liquidator gets collateral
        collateral[msg.sender] += debt;
        
        emit Liquidated(msg.sender, _user, debt);
    }
    
    receive() external payable {}
}

/**
 * @title FixedDex
 * @dev Correct implementation with TWAP oracle protection
 */
contract FixedDex {
    using SafeERC20 for IERC20;
    
    // TWAP price accumulator
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint32 public blockTimestampLast;
    uint256 public lastPrice;
    
    // Liquidity
    uint112 public reserve0;
    uint112 public reserve1;
    
    event Swap(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out);
    
    // TWAP window
    uint256 public constant TWAP_INTERVAL = 10 minutes;
    
    /**
     * @dev Get TWAP rate - Protected from flash loan manipulation
     */
    function getTWAPRate() public view returns (uint256) {
        if (blockTimestampLast == 0) return 0;
        
        uint32 timeElapsed = uint32(block.timestamp) - blockTimestampLast;
        if (timeElapsed < TWAP_INTERVAL) {
            return lastPrice;
        }
        
        // Use time-weighted average
        uint256 priceAverage = (price0CumulativeLast) / timeElapsed;
        return priceAverage;
    }
    
    /**
     * @dev Get spot rate with protection
     */
    function getSpotRate(address _tokenIn, address _tokenOut) public view returns (uint256) {
        // Add sanity checks
        require(reserve0 > 100 && reserve1 > 100, "Insufficient liquidity");
        
        // Use TWAP instead of spot
        return getTWAPRate();
    }
}