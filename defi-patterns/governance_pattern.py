"""
DeFi Governance Protocol Security Analysis Module

This module provides comprehensive security analysis for governance smart contracts
including DAOs, token voting, timelocks, and proposal execution systems.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import logging
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GovernanceType(Enum):
    TOKEN_VOTING = "token_voting"
    QUAD_VOTING = "quad_voting"
    LIQUID_DEMOCRACY = "liquid_democracy"
    REPUBLICAN = "republican"
    DIRECT_DEMOCRACY = "direct_democracy"
    MULTISIG = "multisig"


class ProposalState(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    CANCELED = "canceled"
    DEFEATED = "defeated"
    SUCCEEDED = "succeeded"
    EXECUTED = "executed"
    EXPIRED = "expired"


class VulnerabilityType(Enum):
    CENTRALIZATION = "centralization"
    TIMELOCK_BYPASS = "timelock_bypass"
    PROPOSAL_MANIPULATION = "proposal_manipulation"
    VOTE_MANIPULATION = "vote_manipulation"
    EXECUTION_BYPASS = "execution_bypass"
    FRONT_RUNNING = "front_running"
    RUG_PULL = "rug_pull"
    VETO_POWER = "veto_power"


@dataclass
class Proposal:
    proposal_id: int
    proposer: str
    description: str
    targets: List[str]
    values: List[int]
    signatures: List[str]
    calldatas: List[bytes]
    state: ProposalState
    start_block: int
    end_block: int
    execution_time: int
    for_votes: int = 0
    against_votes: int = 0
    abstain_votes: int = 0
    quorum: int = 0
    
    def get_total_votes(self) -> int:
        return self.for_votes + self.against_votes + self.abstain_votes
    
    def get_participation_rate(self) -> float:
        if self.quorum == 0:
            return 0.0
        return (self.get_total_votes() / self.quorum) * 100
    
    def has_passed(self, voting_delay: int = 0) -> bool:
        return self.for_votes > self.against_votes and self.get_total_votes() >= self.quorum
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'proposal_id': self.proposal_id,
            'proposer': self.proposer,
            'description': self.description[:100],
            'state': self.state.value,
            'for_votes': self.for_votes,
            'against_votes': self.against_votes,
            'abstain_votes': self.abstain_votes,
            'total_votes': self.get_total_votes(),
            'quorum': self.quorum,
            'has_passed': self.has_passed()
        }


@dataclass
class GovernanceConfig:
    governance_type: GovernanceType
    token_address: str
    voting_period: int
    voting_delay: int
    proposal_threshold: int
    quorum: int
    timelock_delay: int
    guardian: Optional[str] = None
    executive: Optional[str] = None
    veto_enabled: bool = False
    
    def get_total_cycle_time(self) -> int:
        return self.voting_delay + self.voting_period + self.timelock_delay


@dataclass
class Voter:
    address: str
    weight: int
    delegated_to: Optional[str] = None
    votes: Dict[int, int] = field(default_factory=dict)
    has_voted: bool = False
    
    def delegate(self, to: str):
        self.delegated_to = to
    
    def cast_vote(self, proposal_id: int, support: int, weight: int):
        self.has_voted = True
        self.votes[proposal_id] = support * weight
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'weight': self.weight,
            'delegated_to': self.delegated_to,
            'has_voted': self.has_voted
        }


class GovernanceSecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0
    
    def detect_governance_type(self, source_code: str) -> GovernanceType:
        source_lower = source_code.lower()
        
        if 'multisig' in source_lower or 'gnosis' in source_lower:
            return GovernanceType.MULTISIG
        
        if 'quadratic' in source_lower or 'quad' in source_lower:
            return GovernanceType.QUAD_VOTING
        
        if 'delegate' in source_lower and 'vote' in source_lower:
            return GovernanceType.LIQUID_DEMOCRACY
        
        if 'proposal' in source_lower and 'execute' in source_lower:
            return GovernanceType.DIRECT_DEMOCRACY
        
        if 'token' in source_lower or 'vote' in source_lower:
            return GovernanceType.TOKEN_VOTING
        
        return GovernanceType.REPUBLICAN
    
    def analyze_timelock(self, source_code: str) -> Dict[str, Any]:
        has_timelock = bool(re.search(r'timelock|Timelock|delay', source_code, re.IGNORECASE))
        has_delay = bool(re.search(r'delay|Delay|eta', source_code, re.IGNORECASE))
        has_min_delay = bool(re.search(r'minDelay|min_delay|MIN_DELAY', source_code, re.IGNORECASE))
        has_max_delay = bool(re.search(r'maxDelay|max_delay|MAX_DELAY', source_code, re.IGNORECASE))
        
        return {
            'has_timelock': has_timelock,
            'has_delay': has_delay,
            'has_min_delay': has_min_delay,
            'has_max_delay': has_max_delay
        }
    
    def analyze_voting_mechanism(self, source_code: str) -> Dict[str, Any]:
        has_vote = bool(re.search(r'castVote|vote|voting', source_code, re.IGNORECASE))
        has_quorum = bool(re.search(r'quorum|threshold', source_code, re.IGNORECASE))
        has_delegation = bool(re.search(r'delegate|delegation', source_code, re.IGNORECASE))
        has_proposal = bool(re.search(r'propose|proposal', source_code, re.IGNORECASE))
        has_execution = bool(re.search(r'execute|executeProposal', source_code, re.IGNORECASE))
        
        return {
            'has_vote': has_vote,
            'has_quorum': has_quorum,
            'has_delegation': has_delegation,
            'has_proposal': has_proposal,
            'has_execution': has_execution
        }
    
    def check_timelock_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if not re.search(r'timelock|Timelock|delay', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.TIMELOCK_BYPASS.value,
                'severity': 'critical',
                'description': 'No timelock detected - proposals execute immediately'
            })
        
        if re.search(r'delay\s*=\s*0|delay\s*=\s*1', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.TIMELOCK_BYPASS.value,
                'severity': 'high',
                'description': 'Timelock delay can be zero or minimal'
            })
        
        if re.search(r'skipTimelock|bypassTimelock|ignoreDelay', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.TIMELOCK_BYPASS.value,
                'severity': 'critical',
                'description': 'Timelock can be bypassed'
            })
        
        return vulnerabilities
    
    def check_access_control_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'onlyOwner|owner.*propose', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.CENTRALIZATION.value,
                'severity': 'high',
                'description': 'Only owner can propose - centralized governance'
            })
        
        if re.search(r'admin.*execute|owner.*execute', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.EXECUTION_BYPASS.value,
                'severity': 'high',
                'description': 'Admin can execute without voting'
            })
        
        if re.search(r'guardian|veto', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.VETO_POWER.value,
                'severity': 'medium',
                'description': 'Guardian can veto any proposal'
            })
        
        return vulnerabilities
    
    def check_proposal_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if not re.search(r'proposalThreshold|proposal.threshold', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.PROPOSAL_MANIPULATION.value,
                'severity': 'medium',
                'description': 'No proposal threshold - anyone can create proposals'
            })
        
        if re.search(r'proposal.*length\s*<|proposal.*length\s*==', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.PROPOSAL_MANIPULATION.value,
                'severity': 'low',
                'description': 'Empty proposals may be allowed'
            })
        
        return vulnerabilities
    
    def check_vote_manipulation(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'block\.timestamp.*vote|vote.*block\.timestamp', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.VOTE_MANIPULATION.value,
                'severity': 'medium',
                'description': 'Vote can be influenced by timestamp'
            })
        
        if re.search(r'balance.*snapshot|balanceAt', source_code, re.IGNORECASE):
            if not re.search(r'checkpoint|record', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': VulnerabilityType.VOTE_MANIPULATION.value,
                    'severity': 'high',
                    'description': 'Vote weight can be flash loaned'
                })
        
        return vulnerabilities
    
    def check_emergency_powers(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'emergency|pause|shutdown', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.CENTRALIZATION.value,
                'severity': 'medium',
                'description': 'Emergency powers detected - can pause governance'
            })
        
        if re.search(r'selfdestruct|destroy|terminate', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.RUG_PULL.value,
                'severity': 'critical',
                'description': 'Contract can be self-destructed'
            })
        
        if re.search(r'withdraw.*owner|owner.*withdraw', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.RUG_PULL.value,
                'severity': 'high',
                'description': 'Owner can withdraw funds'
            })
        
        return vulnerabilities
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0
        }
        
        total_risk = sum(weights.get(v.get('severity', 'low'), 1.0) for v in vulnerabilities)
        self.risk_score = min(total_risk / 10, 10.0)
        
        return self.risk_score
    
    def generate_security_report(self, source_code: str) -> Dict[str, Any]:
        timelock_vulns = self.check_timelock_vulnerabilities(source_code)
        access_vulns = self.check_access_control_vulnerabilities(source_code)
        proposal_vulns = self.check_proposal_vulnerabilities(source_code)
        vote_vulns = self.check_vote_manipulation(source_code)
        emergency_vulns = self.check_emergency_powers(source_code)
        
        all_vulnerabilities = (timelock_vulns + access_vulns + proposal_vulns + 
                              vote_vulns + emergency_vulns)
        self.calculate_risk_score(all_vulnerabilities)
        
        return {
            'governance_type': self.detect_governance_type(source_code).value,
            'timelock': self.analyze_timelock(source_code),
            'voting_mechanism': self.analyze_voting_mechanism(source_code),
            'vulnerabilities': all_vulnerabilities,
            'risk_score': self.risk_score,
            'recommendations': self._generate_recommendations(all_vulnerabilities)
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        recommendations = []
        
        vuln_types = {v.get('type') for v in vulnerabilities}
        
        if VulnerabilityType.TIMELOCK_BYPASS.value in vuln_types:
            recommendations.append('Implement minimum timelock delay of 24-48 hours')
        
        if VulnerabilityType.CENTRALIZATION.value in vuln_types:
            recommendations.append('Decentralize governance with token-based voting')
        
        if VulnerabilityType.VOTE_MANIPULATION.value in vuln_types:
            recommendations.append('Use vote checkpointing to prevent flash loan attacks')
        
        if VulnerabilityType.RUG_PULL.value in vuln_types:
            recommendations.append('Remove or limit emergency withdrawal capabilities')
        
        return recommendations


class DAOTreasuryManager:
    def __init__(self):
        self.balances: Dict[str, int] = {}
        self.proposals: Dict[int, Proposal] = {}
        self.voters: Dict[str, Voter] = {}
    
    def create_proposal(self, proposer: str, description: str, targets: List[str]) -> int:
        proposal_id = len(self.proposals) + 1
        
        proposal = Proposal(
            proposal_id=proposal_id,
            proposer=proposer,
            description=description,
            targets=targets,
            values=[0] * len(targets),
            signatures=[''] * len(targets),
            calldatas=[b''] * len(targets),
            state=ProposalState.PENDING,
            start_block=0,
            end_block=0,
            execution_time=0
        )
        
        self.proposals[proposal_id] = proposal
        return proposal_id
    
    def cast_vote(self, voter: str, proposal_id: int, support: int, weight: int):
        if proposal_id not in self.proposals:
            return
        
        proposal = self.proposals[proposal_id]
        
        if support > 0:
            proposal.for_votes += weight
        elif support < 0:
            proposal.against_votes += weight
        else:
            proposal.abstain_votes += weight
    
    def execute_proposal(self, proposal_id: int) -> bool:
        if proposal_id not in self.proposals:
            return False
        
        proposal = self.proposals[proposal_id]
        
        if proposal.has_passed():
            proposal.state = ProposalState.EXECUTED
            return True
        
        return False
    
    def get_proposal_state(self, proposal_id: int) -> Optional[ProposalState]:
        if proposal_id in self.proposals:
            return self.proposals[proposal_id].state
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_proposals': len(self.proposals),
            'balances': self.balances,
            'proposals': {k: v.to_dict() for k, v in self.proposals.items()}
        }


class MultisigAnalyzer:
    def __init__(self):
        self.signers: List[str] = []
        self.threshold: int = 0
    
    def analyze_multisig(self, source_code: str) -> Dict[str, Any]:
        has_multisig = bool(re.search(r'multisig|MultiSig|signer', source_code, re.IGNORECASE))
        has_threshold = bool(re.search(r'threshold|required|quorum', source_code, re.IGNORECASE))
        has_execute = bool(re.search(r'execute|submitTransaction', source_code, re.IGNORECASE))
        
        return {
            'has_multisig': has_multisig,
            'has_threshold': has_threshold,
            'has_execute': has_execute
        }


def analyze_governance_contract(source_code: str) -> Dict[str, Any]:
    analyzer = GovernanceSecurityAnalyzer()
    return analyzer.generate_security_report(source_code)


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract GovernanceToken is ERC20Votes {
        function mint(address to, uint256 amount) external onlyOwner {
            _mint(to, amount);
        }
    }
    
    contract Timelock {
        uint256 public delay = 0;
        address public admin;
        
        function executeTransaction(address target, bytes calldata data) external payable {
            require(msg.sender == admin);
            (bool success,) = target.call{value: msg.value}(data);
            require(success);
        }
    }
    
    contract Governor {
        function propose(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) public {
            require(getVotes(msg.sender, block.number - 1) >= proposalThreshold);
        }
        
        function execute(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, bytes32 descriptionHash) public payable {
            for (uint i = 0; i < targets.length; i++) {
                (bool success,) = targets[i].call{value: values[i]}(calldatas[i]);
                require(success);
            }
        }
    }
    """
    
    result = analyze_governance_contract(sample)
    print(json.dumps(result, indent=2))