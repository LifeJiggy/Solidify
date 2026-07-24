from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional, Tuple, Set

from .skill_registry import Skill, SkillStatus

logger = logging.getLogger(__name__)

__all__ = ["register_skill", "detect", "FlashLoanDetector"]

FLASH_LOAN_CALLBACK_PATTERNS = {
    'aave_v2': [
        re.compile(r'function\s+executeOperation\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
        re.compile(r'function\s+CALLBACK\s*\(\s*\)', re.MULTILINE),
    ],
    'aave_v3': [
        re.compile(r'function\s+executeOperation\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
        re.compile(r'function\s+executeOperation\s*\(\s*address\[\]\s+assets', re.MULTILINE),
    ],
    'uniswap_v2': [
        re.compile(r'function\s+uniswapV2Call\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'uniswap_v3': [
        re.compile(r'function\s+uniswapV3FlashCallback\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'pancakeswap': [
        re.compile(r'function\s+pancakeCall\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'balancer': [
        re.compile(r'function\s+onFlashLoan\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'sushiswap': [
        re.compile(r'function\s+sushiSwapCall\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'dodo': [
        re.compile(r'function\s+DVMFlashLoanCall\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
        re.compile(r'function\s+DPPFlashLoanCall\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'compound': [
        re.compile(r'function\s+flashBorrow\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'iron_bank': [
        re.compile(r'function\s+onTokenTransfer\s*\([^)]*\)\s*(?:external|public)', re.MULTILINE),
    ],
    'erc3156': [
        re.compile(r'function\s+flashLoan\s*\(\s*address\s+receiver', re.MULTILINE),
        re.compile(r'function\s+flashFee\s*\(', re.MULTILINE),
        re.compile(r'function\s+maxFlashLoan\s*\(', re.MULTILINE),
    ],
}

FLASH_LOAN_PROVIDER_PATTERNS = [
    re.compile(r'IAAVE|ILendingPool|ILendingPoolAddressesProvider', re.MULTILINE),
    re.compile(r'IUniswapV2Router|IUniswapV2Factory|IUniswapV2Pair', re.MULTILINE),
    re.compile(r'IPancakeRouter|IPancakeFactory', re.MULTILINE),
    re.compile(r'IBalancerVault|IBalancerFlashLoan', re.MULTILINE),
    re.compile(r'ISushiSwap|IMasterChef', re.MULTILINE),
    re.compile(r'IDODO|IDVM|IDPP', re.MULTILINE),
    re.compile(r'ICompound|IComptroller', re.MULTILINE),
    re.compile(r'IERC3156|IERC3156FlashLender|IERC3156FlashBorrower', re.MULTILINE),
]

SINGLE_BLOCK_PRICE_PATTERNS = [
    re.compile(r'getReserves\s*\(\s*\)', re.MULTILINE),
    re.compile(r'getAmountOut\s*\(', re.MULTILINE),
    re.compile(r'getAmountIn\s*\(', re.MULTILINE),
    re.compile(r'quote\s*\(', re.MULTILINE),
    re.compile(r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)', re.MULTILINE),
    re.compile(r'address\s*\(\s*this\s*\)\.balance', re.MULTILINE),
]

SPOT_PRICE_PATTERNS = [
    re.compile(r'reserves?\s*\.\s*\w+\s*\(\s*\)', re.MULTILINE),
    re.compile(r'totalSupply\s*\(\s*\)', re.MULTILINE),
    re.compile(r'getBalance\s*\(\s*\)', re.MULTILINE),
    re.compile(r'pool\.token0|pool\.token1', re.MULTILINE),
    re.compile(r'reserve0|reserve1', re.MULTILINE),
]

TWAP_PATTERNS = [
    re.compile(r'pair\.cumulative0|pair\.cumulative1', re.MULTILINE),
    re.compile(r'cumulative\s*\[\s*0\s*\]|cumulative\s*\[\s*1\s*\]', re.MULTILINE),
    re.compile(r'TWAP|twap|time.?weighted', re.IGNORECASE),
    re.compile(r'block\.timestamp\s*-.*>=?\s*\d+', re.MULTILINE),
    re.compile(r'PERIOD|period|LOOKBACK|lookback', re.MULTILINE),
    re.compile(r'observationIndex|observationCardinality', re.MULTILINE),
]

ORACLE_PATTERNS = [
    re.compile(r'AggregatorV3Interface|IChainlink|latestAnswer|latestRoundData', re.MULTILINE),
    re.compile(r'IUniswapOracle|UniswapV2Oracle', re.MULTILINE),
    re.compile(r'IBandChain|BandProtocol', re.MULTILINE),
    re.compile(r'IPyth|PythNetwork', re.MULTILINE),
    re.compile(r'IWstETH|StETH', re.MULTILINE),
    re.compile(r'Chainlink|chainlink', re.IGNORECASE),
]

TIME_DELAY_PATTERNS = [
    re.compile(r'block\.timestamp\s*>=\s*\w+\s*\+\s*\d+', re.MULTILINE),
    re.compile(r'block\.timestamp\s*-\s*\w+\s*>=?\s*\d+', re.MULTILINE),
    re.compile(r'lastUpdate|lastPrice|lastCheck', re.MULTILINE),
    re.compile(r'TimelockController|Timelock', re.MULTILINE),
    re.compile(r'delay\s*>=?\s*\d+', re.MULTILINE),
    re.compile(r'MINIMUM_DELAY|MAXIMUM_DELAY', re.MULTILINE),
]

BALANCE_CHECK_PATTERNS = [
    re.compile(r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)', re.MULTILINE),
    re.compile(r'address\s*\(\s*this\s*\)\.balance', re.MULTILINE),
    re.compile(r'totalSupply\s*\(\s*\)', re.MULTILINE),
    re.compile(r'getBalance\s*\(\s*\)', re.MULTILINE),
]

LIQUIDITY_OP_PATTERNS = [
    re.compile(r'addLiquidity\w*\s*\(', re.MULTILINE),
    re.compile(r'removeLiquidity\w*\s*\(', re.MULTILINE),
    re.compile(r'mint\s*\(\s*(?:msg\.sender|address\s*\(\s*this\s*\))', re.MULTILINE),
    re.compile(r'burn\s*\(\s*(?:msg\.sender|address\s*\(\s*this\s*\))', re.MULTILINE),
    re.compile(r'swap\s*\(', re.MULTILINE),
    re.compile(r'swapExactTokens\w*\s*\(', re.MULTILINE),
]

FUNCTION_REGEX = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*'
    r'((?:public|external|internal|private)\s*)'
    r'((?:view|pure|payable|virtual|override|nonpayable)\s*)*'
    r'((?:\w+\s*)*)',
    re.MULTILINE
)


class FlashLoanDetector:
    def __init__(self):
        self.findings: List[Dict] = []
        self.code_lines: List[str] = []
        self.full_code: str = ''

    def detect(self, code: str, context: dict = None) -> List[Dict]:
        self.findings = []
        self.code_lines = code.split('\n')
        self.full_code = code
        context = context or {}

        self._find_flash_loan_callbacks(code)
        self._check_price_oracle_usage(code)
        self._has_time_delay_mechanism(code)
        self._analyze_defi_integrations(code)
        self._detect_single_block_liquidity_ops(code)
        self._detect_flash_loan_exploit_patterns(code)

        logger.info(f"Flash loan detector found {len(self.findings)} issues")
        return self.findings

    def _find_flash_loan_callbacks(self, code: str) -> List[Tuple[str, int, str]]:
        found_callbacks = []
        for provider, patterns in FLASH_LOAN_CALLBACK_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(code):
                    line_num = code[:match.start()].count('\n') + 1
                    func_match = re.search(r'function\s+(\w+)', match.group())
                    func_name = func_match.group(1) if func_match else 'unknown'
                    found_callbacks.append((provider, line_num, func_name))

                    self._analyze_callback_body(code, match.start(), provider, func_name, line_num)

        for pattern in FLASH_LOAN_PROVIDER_PATTERNS:
            for match in pattern.finditer(code):
                line_num = code[:match.start()].count('\n') + 1
                if not any(cb[0] in match.group() for cb in found_callbacks):
                    self.findings.append({
                        'type': 'flash_loan',
                        'category': 'flash_loan',
                        'severity': 'info',
                        'cwe_id': 'CWE-841',
                        'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                        'description': f'Flash loan provider interface detected: {match.group().strip()}. '
                                       f'Contract interacts with flash loan functionality.',
                        'location': {
                            'line': line_num,
                            'column': match.start() - code[:match.start()].rfind('\n'),
                            'match': match.group().strip(),
                        },
                        'remediation': 'Review flash loan callback for price manipulation and reentrancy risks.',
                        'confidence': 0.95,
                    })

        return found_callbacks

    def _analyze_callback_body(self, code: str, callback_start: int, provider: str,
                               func_name: str, line_num: int) -> None:
        brace_start = code.find('{', callback_start)
        if brace_start == -1:
            return

        brace_count = 0
        body_end = brace_start
        for ci, ch in enumerate(code[brace_start:], brace_start):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    body_end = ci
                    break

        callback_body = code[brace_start:body_end + 1]

        has_price_check = bool(SINGLE_BLOCK_PRICE_PATTERNS[0].search(callback_body))
        has_oracle = bool(ORACLE_PATTERNS[0].search(callback_body))
        has_balance_check = bool(BALANCE_CHECK_PATTERNS[0].search(callback_body))
        has_liquidity_op = any(p.search(callback_body) for p in LIQUIDITY_OP_PATTERNS)

        if has_liquidity_op and not has_oracle:
            severity = 'high'
            confidence = 0.85
            self.findings.append({
                'type': 'flash_loan',
                'category': 'flash_loan',
                'severity': severity,
                'cwe_id': 'CWE-841',
                'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                'description': f'Flash loan callback \'{func_name}\' ({provider}) performs liquidity operations '
                               f'without oracle validation. Price manipulation via flash loan possible.',
                'location': {
                    'line': line_num,
                    'column': 0,
                    'match': f'function {func_name}',
                },
                'remediation': 'Use TWAP oracle or Chainlink price feed within flash loan callback. '
                               'Validate prices against multiple sources.',
                'confidence': confidence,
            })

        if has_price_check and not has_oracle and not self._has_time_delay_mechanism(code):
            self.findings.append({
                'type': 'flash_loan',
                'category': 'flash_loan',
                'severity': 'high',
                'cwe_id': 'CWE-841',
                'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                'description': f'Flash loan callback \'{func_name}\' ({provider}) uses spot price from reserves. '
                               f'Single-block price manipulation via flash loan possible.',
                'location': {
                    'line': line_num,
                    'column': 0,
                    'match': f'function {func_name}',
                },
                'remediation': 'Replace getReserves() spot price with TWAP from Uniswap V3 or Chainlink oracle.',
                'confidence': 0.88,
            })

    def _check_price_oracle_usage(self, code: str) -> None:
        uses_spot_price = bool(SINGLE_BLOCK_PRICE_PATTERNS[0].search(code))
        uses_twap = bool(TWAP_PATTERNS[0].search(code))
        uses_chainlink = bool(ORACLE_PATTERNS[0].search(code))

        if uses_spot_price and not uses_twap and not uses_chainlink:
            for i, line in enumerate(self.code_lines, 1):
                for pattern in SINGLE_BLOCK_PRICE_PATTERNS:
                    for match in pattern.finditer(line):
                        self.findings.append({
                            'type': 'flash_loan',
                            'category': 'flash_loan',
                            'severity': 'high',
                            'cwe_id': 'CWE-841',
                            'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                            'description': f'Spot price usage detected: {match.group().strip()}. '
                                           f'No TWAP or external oracle found. Flash loan price manipulation possible.',
                            'location': {
                                'line': i,
                                'column': match.start() + 1,
                                'match': match.group().strip(),
                            },
                            'remediation': 'Integrate Chainlink price feed or implement TWAP with sufficient lookback period.',
                            'confidence': 0.85,
                        })

    def _has_time_delay_mechanism(self, code: str) -> bool:
        for pattern in TIME_DELAY_PATTERNS:
            if pattern.search(code):
                return True
        return False

    def _analyze_defi_integrations(self, code: str) -> None:
        dex_patterns = {
            'uniswap_v2': re.compile(r'IUniswapV2|UniswapV2', re.MULTILINE),
            'uniswap_v3': re.compile(r'IUniswapV3|UniswapV3', re.MULTILINE),
            'pancakeswap': re.compile(r'IPancake|PancakeSwap', re.MULTILINE),
            'sushiswap': re.compile(r'ISushi|SushiSwap', re.MULTILINE),
            'balancer': re.compile(r'IBalancer|BalancerVault', re.MULTILINE),
            'curve': re.compile(r'ICurve|CurvePool', re.MULTILINE),
            '1inch': re.compile(r'IAggregationRouter|1inch', re.MULTILINE),
        }

        found_dexes = []
        for dex_name, pattern in dex_patterns.items():
            if pattern.search(code):
                found_dexes.append(dex_name)

        if len(found_dexes) > 1:
            self.findings.append({
                'type': 'flash_loan',
                'category': 'flash_loan',
                'severity': 'medium',
                'cwe_id': 'CWE-841',
                'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                'description': f'Multiple DEX integrations detected: {", ".join(found_dexes)}. '
                               f'Cross-DEX price discrepancies exploitable via flash loans.',
                'location': {
                    'line': 1,
                    'column': 0,
                    'match': f'DEX integrations: {", ".join(found_dexes)}',
                },
                'remediation': 'Use consistent price oracle across all DEX interactions. Implement minimum output checks.',
                'confidence': 0.75,
            })

        has_flash_loan_provider = any(p.search(code) for p in FLASH_LOAN_PROVIDER_PATTERNS)
        if has_flash_loan_provider and found_dexes:
            self.findings.append({
                'type': 'flash_loan',
                'category': 'flash_loan',
                'severity': 'high',
                'cwe_id': 'CWE-841',
                'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                'description': f'Flash loan provider with DEX integration ({", ".join(found_dexes)}). '
                               f'Atomic flash loan + swap operations enable price manipulation.',
                'location': {
                    'line': 1,
                    'column': 0,
                    'match': 'Flash loan + DEX integration',
                },
                'remediation': 'Add slippage protection, use TWAP oracle, and validate output amounts.',
                'confidence': 0.82,
            })

    def _detect_single_block_liquidity_ops(self, code: str) -> None:
        for i, line in enumerate(self.code_lines, 1):
            for pattern in LIQUIDITY_OP_PATTERNS:
                for match in pattern.finditer(line):
                    has_validation = False
                    for j in range(max(0, i - 5), min(len(self.code_lines), i + 5)):
                        check_line = self.code_lines[j]
                        if 'require' in check_line or 'assert' in check_line:
                            has_validation = True
                            break

                    if not has_validation:
                        self.findings.append({
                            'type': 'flash_loan',
                            'category': 'flash_loan',
                            'severity': 'medium',
                            'cwe_id': 'CWE-841',
                            'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                            'description': f'Liquidity operation without validation: {match.group().strip()}. '
                                           f'Flash loan can exploit unvalidated liquidity operations.',
                            'location': {
                                'line': i,
                                'column': match.start() + 1,
                                'match': match.group().strip(),
                            },
                            'remediation': 'Add require() checks for minimum amounts and slippage tolerance.',
                            'confidence': 0.78,
                        })

    def _detect_flash_loan_exploit_patterns(self, code: str) -> None:
        borrow_and_swap = re.compile(
            r'flashLoan.*(?:swap|trade|exchange|convert)',
            re.DOTALL | re.MULTILINE
        )
        if borrow_and_swap.search(code):
            self.findings.append({
                'type': 'flash_loan',
                'category': 'flash_loan',
                'severity': 'high',
                'cwe_id': 'CWE-841',
                'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                'description': 'Flash loan followed by swap/trade operation detected. '
                               'Classic flash loan exploit pattern for price manipulation.',
                'location': {
                    'line': 1,
                    'column': 0,
                    'match': 'flashLoan + swap pattern',
                },
                'remediation': 'Use TWAP oracle, add slippage protection, validate prices before and after swap.',
                'confidence': 0.80,
            })

        balance_manipulation = re.compile(
            r'(?:balanceOf|\.balance)\s*(?:>=?|<=?|==)\s*\w+.*(?:require|assert|if)',
            re.DOTALL | re.MULTILINE
        )
        for i, line in enumerate(self.code_lines, 1):
            if balance_manipulation.search(line):
                self.findings.append({
                    'type': 'flash_loan',
                    'category': 'flash_loan',
                    'severity': 'high',
                    'cwe_id': 'CWE-841',
                    'cwe_name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
                    'description': f'Balance-based validation detected at line {i}. '
                                   f'Flash loans can manipulate balance checks.',
                    'location': {
                        'line': i,
                        'column': 0,
                        'match': line.strip(),
                    },
                    'remediation': 'Use share-based accounting instead of balance-based. Or use TWAP-weighted balances.',
                    'confidence': 0.82,
                })


def register_skill() -> Skill:
    return Skill(
        name="flash_loan_detector",
        category="flash_loan",
        severity="high",
        description="Detects flash loan attack vectors including single-block price manipulation, "
                    "missing oracle validation, and atomic transaction exploitation patterns.",
        cwe_id="CWE-841",
        cwe_name="Improper Restriction of Operations within the Bounds of a Memory Buffer",
        patterns=[r'flashLoan', r'uniswapV2Call', r'pancakeCall', r'AAVE', r'balancer', r'onFlashLoan'],
        sinks=['swap', 'trade', 'addLiquidity', 'removeLiquidity', 'borrow'],
        guards=['TWAP', 'Chainlink', 'time.delay', 'slippage.check'],
        remediation="Use time-weighted average prices (TWAP) instead of spot prices. "
                    "Add slippage protection and minimum output checks. "
                    "Validate prices against multiple oracle sources.",
        references=[
            "https://blog.openzeppelin.com/defi-attack-patterns",
            "https://consensys.net/diligence/blog/2020/05/flash-loan-attacks/",
            "https://medium.com/coinmonks/flash-loan-attack-explained",
        ],
        status=SkillStatus.ACTIVE,
        version="1.0.0",
        author="Solidify Security Team",
        tags={"flash-loan", "defi", "high", "web3", "solidity", "price-manipulation", "atomic-transaction"},
    )


def detect(code: str, context: dict = None) -> List[Dict]:
    detector = FlashLoanDetector()
    return detector.detect(code, context)


if __name__ == '__main__':
    sample_code = '''
pragma solidity ^0.7.0;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IUniswapV2Factory {
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}

contract VulnerableFlashLoan {
    IUniswapV2Factory public factory;
    address public token0;
    address public token1;

    constructor(address _factory, address _token0, address _token1) {
        factory = IUniswapV2Factory(_factory);
        token0 = _token0;
        token1 = _token1;
    }

    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        address pair = factory.getPair(token0, token1);
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();

        uint256 amount0Out = reserve0 - (reserve0 * 1000 / 1001);
        uint256 amount1Out = reserve1 - (reserve1 * 1000 / 1001);

        IUniswapV2Pair(pair).swap(amount0Out, amount1Out, address(this), "");
    }

    function calculateProfit() public view returns (uint256) {
        address pair = factory.getPair(token0, token1);
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();
        return (address(this).balance * reserve1) / reserve0;
    }
}

contract SafeFlashLoan {
    using TWAP for TWAP.Price;

    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        TWAP.Price memory price = TWAP.getPrice(token0, token1, 30 minutes);
        require(price.average > 0, "Invalid price");
        // Safe operations with TWAP price
    }
}
'''
    results = detect(sample_code)
    for r in results:
        print(f"[{r['severity'].upper()}] {r['description']}")
        print(f"  Location: Line {r['location']['line']}")
        print(f"  Confidence: {r['confidence']}")
        print()
