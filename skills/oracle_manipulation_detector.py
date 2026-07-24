from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional, Tuple, Set

from .skill_registry import Skill, SkillStatus

logger = logging.getLogger(__name__)

__all__ = ["register_skill", "detect", "OracleManipulationDetector"]

ORACLE_CALL_PATTERNS = {
    'chainlink': [
        re.compile(r'AggregatorV3Interface', re.MULTILINE),
        re.compile(r'\.latestRoundData\s*\(', re.MULTILINE),
        re.compile(r'\.latestAnswer\s*\(', re.MULTILINE),
        re.compile(r'\.decimals\s*\(\s*\)', re.MULTILINE),
        re.compile(r'getRoundData\s*\(', re.MULTILINE),
        re.compile(r'IChainlink|chainlink|Chainlink', re.IGNORECASE),
    ],
    'uniswap_v2': [
        re.compile(r'getReserves\s*\(\s*\)', re.MULTILINE),
        re.compile(r'getAmountOut\s*\(', re.MULTILINE),
        re.compile(r'getAmountIn\s*\(', re.MULTILINE),
        re.compile(r'reserve0|reserve1', re.MULTILINE),
        re.compile(r'IUniswapV2Pair|IUniswapV2Router', re.MULTILINE),
    ],
    'uniswap_v3': [
        re.compile(r'sqrtPriceX96|tickSpacing', re.MULTILINE),
        re.compile(r'observe\s*\(', re.MULTILINE),
        re.compile(r'cumulative\s*\[\s*0\s*\]|cumulative\s*\[\s*1\s*\]', re.MULTILINE),
        re.compile(r'IUniswapV3Pool|UniswapV3', re.MULTILINE),
        re.compile(r'observationIndex|observationCardinality', re.MULTILINE),
    ],
    'band': [
        re.compile(r'IBandRecipe|BandChain|BandProtocol', re.IGNORECASE),
        re.compile(r'referenceData|getRate', re.MULTILINE),
    ],
    'pyth': [
        re.compile(r'IPyth|PythNetwork|pyth', re.IGNORECASE),
        re.compile(r'getPrice\s*\(', re.MULTILINE),
        re.compile(r'getEmaPriceUnsafe\s*\(', re.MULTILINE),
    ],
    'wsteth': [
        re.compile(r'IWstETH|stETH|wstETH', re.IGNORECASE),
        re.compile(r'getStETH|getWstETH', re.MULTILINE),
    ],
    'spot_price': [
        re.compile(r'spotPrice|spot_price', re.IGNORECASE),
        re.compile(r'currentAnswer|getCurrentAnswer', re.MULTILINE),
        re.compile(r'getPrice\s*\(\s*\)', re.MULTILINE),
        re.compile(r'priceOf\s*\(\s*\)', re.MULTILINE),
    ],
}

TWAP_PATTERNS = [
    re.compile(r'TWAP|twap|time.?weighted', re.IGNORECASE),
    re.compile(r'cumulative.*(?:0|1)\s*\]', re.MULTILINE),
    re.compile(r'block\.timestamp\s*-.*>=?\s*\d+', re.MULTILINE),
    re.compile(r'PERIOD|period|LOOKBACK|lookback', re.MULTILINE),
    re.compile(r'observationIndex|observationCardinality', re.MULTILINE),
    re.compile(r'cardinality|cardinalityNext', re.MULTILINE),
]

STALENESS_CHECK_PATTERNS = [
    re.compile(r'block\.timestamp\s*-.*\w+\.\w+Time\s*>=?\s*\d+', re.MULTILINE),
    re.compile(r'block\.timestamp\s*-\s*\w+\.updatedAt\s*>=?\s*\d+', re.MULTILINE),
    re.compile(r'block\.timestamp\s*-\s*\w+\.lastUpdate\s*>=?\s*\d+', re.MULTILINE),
    re.compile(r'block\.timestamp\s*>=?\s*\w+\s*\+\s*\d+', re.MULTILINE),
    re.compile(r'updatedAt|lastUpdate|heartbeatDuration', re.MULTILINE),
    re.compile(r'MAX_STALENESS|STALENESS_THRESHOLD|HEARTBEAT', re.MULTILINE),
]

PRICE_FEED_VALIDATION = [
    re.compile(r'require\s*\(\s*\w+\s*!=\s*address\(0\)', re.MULTILINE),
    re.compile(r'require\s*\(\s*\w+\s*>\s*0\s*,', re.MULTILINE),
    re.compile(r'require\s*\(\s*\w+\s*<\s*\d+', re.MULTILINE),
    re.compile(r'assert\s*\(\s*\w+\s*!=\s*address\(0\)', re.MULTILINE),
    re.compile(r'if\s*\(\s*\w+\s*==\s*address\(0\)\s*\)\s*(?:revert|return)', re.MULTILINE),
]

BALANCE_OF_PATTERNS = [
    re.compile(r'balanceOf\s*\(\s*\w+\s*\)', re.MULTILINE),
    re.compile(r'totalSupply\s*\(\s*\)', re.MULTILINE),
    re.compile(r'getBalance\s*\(\s*\)', re.MULTILINE),
]

SINGLE_SOURCE_RISK = [
    re.compile(r'function\s+\w+\s*\([^)]*\)\s*(?:internal|private)\s*(?:view\s+|pure\s+)*\w*\s*\{[^}]*(?:latestAnswer|getReserves|getPrice)\s*\(', re.DOTALL),
    re.compile(r'return\s+(?:\w+\.)?(?:latestAnswer|getReserves|getPrice|balanceOf)\s*\(', re.MULTILINE),
]

MULTI_SOURCE_VALIDATION = [
    re.compile(r'require\s*\(\s*(?:\w+\.)?\w+\s*[><=!]+\s*(?:\w+\.)?\w+', re.MULTILINE),
    re.compile(r'median\s*\(|average\s*\(|mean\s*\(', re.MULTILINE),
    re.compile(r'STANDARD_DEVIATION|stddev|deviation', re.IGNORECASE),
]

FRONT_RUN_PATTERNS = [
    re.compile(r'pending\w+|mempool|sandwich', re.IGNORECASE),
    re.compile(r'commit.*reveal|hash.*reveal', re.IGNORECASE),
    re.compile(r'block\.number\s*-\s*\w+', re.MULTILINE),
]

FUNCTION_REGEX = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*'
    r'((?:public|external|internal|private)\s*)'
    r'((?:view|pure|payable|virtual|override|nonpayable)\s*)*'
    r'((?:\w+\s*)*)',
    re.MULTILINE
)

PRICE_COMPARISON_PATTERNS = [
    re.compile(r'if\s*\(\s*\w+\s*[><=!]+\s*\w+\s*\)', re.MULTILINE),
    re.compile(r'require\s*\(\s*\w+\s*[><=!]+\s*\w+', re.MULTILINE),
    re.compile(r'(?:min|max|clamp)\s*\(', re.MULTILINE),
]

ORACLE_ADDRESS_VALIDATION = [
    re.compile(r'oracles?\s*\[\s*\w+\s*\]', re.MULTILINE),
    re.compile(r'priceFeeds?\s*\[\s*\w+\s*\]', re.MULTILINE),
    re.compile(r'feeds?\s*\[\s*\w+\s*\]', re.MULTILINE),
]


class OracleManipulationDetector:
    def __init__(self):
        self.findings: List[Dict] = []
        self.code_lines: List[str] = []
        self.full_code: str = ''

    def detect(self, code: str, context: dict = None) -> List[Dict]:
        self.findings = []
        self.code_lines = code.split('\n')
        self.full_code = code
        context = context or {}

        self._find_oracle_calls(code)
        self._check_oracle_source_diversity(code)
        self._has_staleness_check(code)
        self._analyze_price_feeds(code)
        self._detect_spot_price_usage(code)
        self._detect_missing_price_bounds(code)
        self._detect_oracle_front_running(code)

        logger.info(f"Oracle manipulation detector found {len(self.findings)} issues")
        return self.findings

    def _find_oracle_calls(self, code: str) -> None:
        for oracle_type, patterns in ORACLE_CALL_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(code):
                    line_num = code[:match.start()].count('\n') + 1
                    self._analyze_oracle_usage(code, match, oracle_type, line_num)

    def _analyze_oracle_usage(self, code: str, match: re.Match, oracle_type: str, line_num: int) -> None:
        match_text = match.group().strip()

        if oracle_type in ('uniswap_v2', 'spot_price') and 'TWAP' not in code:
            has_staleness = self._has_staleness_check(code)
            if not has_staleness:
                self.findings.append({
                    'type': 'oracle_manipulation',
                    'category': 'oracle_manipulation',
                    'severity': 'high',
                    'cwe_id': 'CWE-754',
                    'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                    'description': f'Spot price oracle usage ({oracle_type}): {match_text}. '
                                   f'No staleness check or TWAP detected. Flash loan price manipulation possible.',
                    'location': {
                        'line': line_num,
                        'column': match.start() - code[:match.start()].rfind('\n'),
                        'match': match_text,
                    },
                    'remediation': 'Replace spot price with TWAP (time-weighted average price). '
                                   'Add staleness checks for oracle data.',
                    'confidence': 0.90,
                })

        if oracle_type == 'chainlink':
            has_staleness = self._has_staleness_check(code)
            has_price_validation = bool(PRICE_FEED_VALIDATION[0].search(code))

            if not has_staleness:
                self.findings.append({
                    'type': 'oracle_manipulation',
                    'category': 'oracle_manipulation',
                    'severity': 'medium',
                    'cwe_id': 'CWE-754',
                    'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                    'description': f'Chainlink oracle ({match_text}) used without staleness check. '
                                   f'Stale price data can lead to incorrect valuations.',
                    'location': {
                        'line': line_num,
                        'column': match.start() - code[:match.start()].rfind('\n'),
                        'match': match_text,
                    },
                    'remediation': 'Check block.timestamp - updatedAt < MAX_STALENESS. '
                                   'Validate round answer != 0.',
                    'confidence': 0.85,
                })

            if not has_price_validation:
                self.findings.append({
                    'type': 'oracle_manipulation',
                    'category': 'oracle_manipulation',
                    'severity': 'medium',
                    'cwe_id': 'CWE-754',
                    'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                    'description': f'Chainlink price feed ({match_text}) used without zero/zero-address validation. '
                                   f'Invalid oracle responses not handled.',
                    'location': {
                        'line': line_num,
                        'column': match.start() - code[:match.start()].rfind('\n'),
                        'match': match_text,
                    },
                    'remediation': 'Add require(price > 0) and require(priceFeed != address(0)). '
                                   'Check for stale rounds with answeredInRound < roundId.',
                    'confidence': 0.80,
                })

    def _check_oracle_source_diversity(self, code: str) -> None:
        source_types_found: Set[str] = set()
        for oracle_type, patterns in ORACLE_CALL_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(code):
                    source_types_found.add(oracle_type)
                    break

        external_oracles = source_types_found - {'spot_price', 'uniswap_v2'}
        if len(external_oracles) == 0 and len(source_types_found) > 0:
            self.findings.append({
                'type': 'oracle_manipulation',
                'category': 'oracle_manipulation',
                'severity': 'high',
                'cwe_id': 'CWE-754',
                'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                'description': f'Only internal/DEX price sources detected ({", ".join(source_types_found)}). '
                               f'No external oracle (Chainlink, Band, Pyth) found. Single-source price risk.',
                'location': {
                    'line': 1,
                    'column': 0,
                    'match': f'Oracle sources: {", ".join(source_types_found)}',
                },
                'remediation': 'Add Chainlink or Band Protocol as external price oracle. '
                               'Use median of multiple sources for critical price feeds.',
                'confidence': 0.88,
            })

        if len(external_oracles) == 1:
            if not bool(MULTI_SOURCE_VALIDATION[0].search(code)):
                self.findings.append({
                    'type': 'oracle_manipulation',
                    'category': 'oracle_manipulation',
                    'severity': 'medium',
                    'cwe_id': 'CWE-754',
                    'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                    'description': f'Single external oracle source: {", ".join(external_oracles)}. '
                                   f'No multi-source validation or median check detected.',
                    'location': {
                        'line': 1,
                        'column': 0,
                        'match': f'External oracle: {", ".join(external_oracles)}',
                    },
                    'remediation': 'Implement multi-oracle validation with median or weighted average. '
                                   'Add circuit breaker for large price deviations.',
                    'confidence': 0.82,
                })

    def _has_staleness_check(self, code: str) -> bool:
        for pattern in STALENESS_CHECK_PATTERNS:
            if pattern.search(code):
                return True
        return False

    def _analyze_price_feeds(self, code: str) -> None:
        functions = list(FUNCTION_REGEX.finditer(code))
        for func_match in functions:
            func_name = func_match.group(1)
            func_text = func_match.group(0)
            line_num = code[:func_match.start()].count('\n') + 1

            if 'view' not in func_text and 'pure' not in func_text:
                continue

            func_body = self._get_function_body(code, func_match)
            if not func_body:
                continue

            has_oracle_call = False
            for oracle_type, patterns in ORACLE_CALL_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(func_body):
                        has_oracle_call = True
                        break
                if has_oracle_call:
                    break

            if has_oracle_call:
                has_staleness = self._has_staleness_check(func_body)
                has_bounds = bool(PRICE_COMPARISON_PATTERNS[0].search(func_body))

                if not has_staleness and not has_bounds:
                    self.findings.append({
                        'type': 'oracle_manipulation',
                        'category': 'oracle_manipulation',
                        'severity': 'medium',
                        'cwe_id': 'CWE-754',
                        'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                        'description': f'Price feed function \'{func_name}\' lacks staleness check and price bounds. '
                                       f'Returns oracle data without validation.',
                        'location': {
                            'line': line_num,
                            'column': 0,
                            'match': f'function {func_name}',
                        },
                        'remediation': f'Add staleness check and price bounds to \'{func_name}\'. '
                                       f'Revert on stale or invalid oracle data.',
                        'confidence': 0.83,
                    })

    def _detect_spot_price_usage(self, code: str) -> None:
        for i, line in enumerate(self.code_lines, 1):
            for pattern in BALANCE_OF_PATTERNS:
                for match in pattern.finditer(line):
                    has_division = bool(re.search(r'/.+\w+\.\w+Of|Of.*/', line))
                    has_twap = bool(TWAP_PATTERNS[0].search(code))

                    if has_division and not has_twap:
                        self.findings.append({
                            'type': 'oracle_manipulation',
                            'category': 'oracle_manipulation',
                            'severity': 'high',
                            'cwe_id': 'CWE-754',
                            'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                            'description': f'Balance-based price calculation at line {i}: {line.strip()}. '
                                           f'Spot balance used for price derivation. Flash loan manipulation possible.',
                            'location': {
                                'line': i,
                                'column': match.start() + 1,
                                'match': line.strip(),
                            },
                            'remediation': 'Use TWAP or Chainlink oracle instead of balance-based price calculation.',
                            'confidence': 0.87,
                        })

    def _detect_missing_price_bounds(self, code: str) -> None:
        for i, line in enumerate(self.code_lines, 1):
            for pattern in ORACLE_CALL_PATTERNS['chainlink']:
                if pattern.search(line):
                    has_bounds = False
                    for j in range(max(0, i - 3), min(len(self.code_lines), i + 5)):
                        check_line = self.code_lines[j]
                        if 'require' in check_line and ('>' in check_line or '<' in check_line):
                            has_bounds = True
                            break
                        if 'MIN_PRICE' in check_line or 'MAX_PRICE' in check_line:
                            has_bounds = True
                            break

                    if not has_bounds:
                        self.findings.append({
                            'type': 'oracle_manipulation',
                            'category': 'oracle_manipulation',
                            'severity': 'medium',
                            'cwe_id': 'CWE-754',
                            'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                            'description': f'Oracle call at line {i} without price bounds validation: {line.strip()}. '
                                           f'Extreme price values not filtered.',
                            'location': {
                                'line': i,
                                'column': 0,
                                'match': line.strip(),
                            },
                            'remediation': 'Add MIN_PRICE/MAX_PRICE bounds checks. Use circuit breaker for extreme values.',
                            'confidence': 0.78,
                        })

    def _detect_oracle_front_running(self, code: str) -> None:
        has_pending = bool(FRONT_RUN_PATTERNS[0].search(code))
        has_commit_reveal = bool(FRONT_RUN_PATTERNS[1].search(code))

        if has_pending and not has_commit_reveal:
            self.findings.append({
                'type': 'oracle_manipulation',
                'category': 'oracle_manipulation',
                'severity': 'medium',
                'cwe_id': 'CWE-754',
                'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                'description': 'Pending transaction or mempool reference without commit-reveal scheme. '
                               'Oracle updates vulnerable to front-running.',
                'location': {
                    'line': 1,
                    'column': 0,
                    'match': 'Pending/mempool reference without commit-reveal',
                },
                'remediation': 'Use commit-reveal scheme for oracle updates. '
                               'Consider Flashbots or private mempools for sensitive transactions.',
                'confidence': 0.72,
            })

        for i, line in enumerate(self.code_lines, 1):
            if 'block.number' in line and ('price' in line.lower() or 'oracle' in line.lower()):
                self.findings.append({
                    'type': 'oracle_manipulation',
                    'category': 'oracle_manipulation',
                    'severity': 'low',
                    'cwe_id': 'CWE-754',
                    'cwe_name': 'Improper Check for Unusual or Exceptional Conditions',
                    'description': f'block.number used for price/oracle logic at line {i}. '
                                   f'Miner can manipulate block number for oracle front-running.',
                    'location': {
                        'line': i,
                        'column': 0,
                        'match': line.strip(),
                    },
                    'remediation': 'Use block.timestamp with TWAP instead of block.number for oracle timing.',
                    'confidence': 0.65,
                })

    def _get_function_body(self, code: str, func_match: re.Match) -> str:
        func_start = code.find('{', func_match.start())
        if func_start == -1:
            return ''
        brace_count = 0
        for ci, ch in enumerate(code[func_start:], func_start):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    return code[func_start:ci + 1]
        return code[func_start:]


def register_skill() -> Skill:
    return Skill(
        name="oracle_manipulation_detector",
        category="oracle_manipulation",
        severity="high",
        description="Detects oracle manipulation vulnerabilities including spot price usage, "
                    "missing TWAP, single-source oracle, stale price data, and oracle front-running vectors.",
        cwe_id="CWE-754",
        cwe_name="Improper Check for Unusual or Exceptional Conditions",
        patterns=[r'latestAnswer', r'latestRoundData', r'getReserves', r'getPrice', r'spotPrice', r'balanceOf'],
        sinks=['price', 'reserve', 'spot', 'balance', 'totalSupply'],
        guards=['TWAP', 'Chainlink', 'staleness.check', 'multi.oracle', 'price.bounds'],
        remediation="Use TWAP (time-weighted average price) with sufficient lookback period. "
                    "Integrate Chainlink or Band Protocol as external oracle. "
                    "Add staleness checks, price bounds, and multi-source validation.",
        references=[
            "https://blog.openzeppelin.com/defi-attack-patterns",
            "https://consensys.net/diligence/blog/2021/05/empirical-analysis-of-defi-oracles/",
            "https://medium.com/chainlink/defi-oracle-manipulation",
        ],
        status=SkillStatus.ACTIVE,
        version="1.0.0",
        author="Solidify Security Team",
        tags={"oracle", "price-manipulation", "defi", "high", "web3", "solidity", "twap", "chainlink"},
    )


def detect(code: str, context: dict = None) -> List[Dict]:
    detector = OracleManipulationDetector()
    return detector.detect(code, context)


if __name__ == '__main__':
    sample_code = '''
pragma solidity ^0.7.0;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IUniswapV2Factory {
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
    function decimals() external view returns (uint8);
}

contract VulnerableOracle {
    IUniswapV2Factory public factory;
    address public token0;
    address public token1;

    constructor(address _factory, address _token0, address _token1) {
        factory = IUniswapV2Factory(_factory);
        token0 = _token0;
        token1 = _token1;
    }

    function getPrice() public view returns (uint256) {
        address pair = factory.getPair(token0, token1);
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();
        return (reserve1 * 1e18) / reserve0;
    }

    function getTokenValue(uint256 amount) public view returns (uint256) {
        return (amount * balanceOf(token0)) / totalSupply();
    }
}

contract SafeOracle {
    AggregatorV3Interface public priceFeed;
    uint256 public constant MAX_STALENESS = 1 hours;
    uint256 public constant MIN_PRICE = 1e10;
    uint256 public constant MAX_PRICE = 1e30;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        require(updatedAt > 0, "Invalid round data");
        require(block.timestamp - updatedAt < MAX_STALENESS, "Stale price");
        require(answer > int256(MIN_PRICE), "Price too low");
        require(answer < int256(MAX_PRICE), "Price too high");
        require(answeredInRound >= roundId, "Stale round");

        return uint256(answer);
    }
}
'''
    results = detect(sample_code)
    for r in results:
        print(f"[{r['severity'].upper()}] {r['description']}")
        print(f"  Location: Line {r['location']['line']}")
        print(f"  Confidence: {r['confidence']}")
        print()
