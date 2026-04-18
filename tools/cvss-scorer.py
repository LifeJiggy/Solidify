"""
CVSS Scoring Module for Vulnerability Severity Assessment

This module implements comprehensive CVSS (Common Vulnerability Scoring System)
scoring capabilities for security vulnerabilities with support for CVSS v3.1 and custom scoring.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import math
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CVSSVersion(Enum):
    V31 = "3.1"
    V30 = "3.0"
    V2 = "2.0"


class AttackVector(Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegeRequired(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class ConfidentialityImpact(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class IntegrityImpact(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class AvailabilityImpact(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class ExploitabilitySubscore(Enum):
    CRITICAL = 3.9
    HIGH = 2.3
    MEDIUM = 0.82
    LOW = 0.22
    NONE = 0.0


class ImpactSubscore(Enum):
    HIGH = 0.56
    MEDIUM = 0.22
    LOW = 0.0


@dataclass
class CVSSVector:
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privilege_required: PrivilegeRequired = PrivilegeRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: ConfidentialityImpact = ConfidentialityImpact.NONE
    integrity: IntegrityImpact = IntegrityImpact.NONE
    availability: AvailabilityImpact = AvailabilityImpact.NONE
    
    def to_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.attack_vector.value}/AC:{self.attack_complexity.value}/"
                f"PR:{self.privilege_required.value}/UI:{self.user_interaction.value}/"
                f"S:{self.scope.value}/C:{self.confidentiality.value}/"
                f"I:{self.integrity.value}/A:{self.availability.value}")
    
    @classmethod
    def from_string(cls, vector: str) -> 'CVSSVector':
        if not vector.startswith('CVSS:'):
            raise ValueError("Invalid CVSS vector format")
        
        new_vector = cls()
        
        parts = vector.replace('CVSS:', '').split('/')
        
        for part in parts:
            if ':' not in part:
                continue
                
            key, value = part.split(':')
            
            if key == 'AV':
                new_vector.attack_vector = AttackVector(value)
            elif key == 'AC':
                new_vector.attack_complexity = AttackComplexity(value)
            elif key == 'PR':
                new_vector.privilege_required = PrivilegeRequired(value)
            elif key == 'UI':
                new_vector.user_interaction = UserInteraction(value)
            elif key == 'S':
                new_vector.scope = Scope(value)
            elif key == 'C':
                new_vector.confidentiality = ConfidentialityImpact(value)
            elif key == 'I':
                new_vector.integrity = IntegrityImpact(value)
            elif key == 'A':
                new_vector.availability = AvailabilityImpact(value)
        
        return new_vector


@dataclass
class CVSSScore:
    vector: CVSSVector
    base_score: float
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    exploitability_subscore: float = 0.0
    impact_subscore: float = 0.0
    modified_base_score: float = 0.0
    
    def get_severity(self) -> str:
        if self.base_score >= 9.0:
            return "CRITICAL"
        elif self.base_score >= 7.0:
            return "HIGH"
        elif self.base_score >= 4.0:
            return "MEDIUM"
        elif self.base_score >= 0.1:
            return "LOW"
        else:
            return "NONE"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vector': self.vector.to_string(),
            'base_score': self.base_score,
            'severity': self.get_severity(),
            'temporal_score': self.temporal_score,
            'environmental_score': self.environmental_score,
            'exploitability_subscore': self.exploitability_subscore,
            'impact_subscore': self.impact_subscore
        }


class CVSSCalculator:
    def __init__(self):
        self.weighted_metrics = {
            AttackVector: {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
            AttackComplexity: {'L': 0.77, 'H': 0.44},
            PrivilegeRequired: {
                'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
                'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}
            },
            UserInteraction: {'N': 0.85, 'R': 0.62},
            Scope: {'U': 'unchanged', 'C': 'changed'},
            ConfidentialityImpact: {'N': 0.0, 'L': 0.22, 'H': 0.56},
            IntegrityImpact: {'N': 0.0, 'L': 0.22, 'H': 0.56},
            AvailabilityImpact: {'N': 0.0, 'L': 0.22, 'H': 0.56}
        }
    
    def calculate_exploitability(self, vector: CVSSVector) -> float:
        av_weight = self.weighted_metrics[AttackVector][vector.attack_vector.value]
        ac_weight = self.weighted_metrics[AttackComplexity][vector.attack_complexity.value]
        
        if vector.scope == Scope.UNCHANGED:
            pr_weight = self.weighted_metrics[PrivilegeRequired]['U'][vector.privilege_required.value]
        else:
            pr_weight = self.weighted_metrics[PrivilegeRequired]['C'][vector.privilege_required.value]
        
        ui_weight = self.weighted_metrics[UserInteraction][vector.user_interaction.value]
        
        return 8.22 * av_weight * ac_weight * pr_weight * ui_weight
    
    def calculate_impact(self, vector: CVSSVector) -> float:
        if vector.scope == Scope.UNCHANGED:
            c_weight = self.weighted_metrics[ConfidentialityImpact][vector.confidentiality.value]
            i_weight = self.weighted_metrics[IntegrityImpact][vector.integrity.value]
            a_weight = self.weighted_metrics[AvailabilityImpact][vector.availability.value]
            
            impact = 1 - ((1 - c_weight) * (1 - i_weight) * (1 - a_weight))
        else:
            c_weight = self.weighted_metrics[ConfidentialityImpact][vector.confidentiality.value]
            i_weight = self.weighted_metrics[IntegrityImpact][vector.integrity.value]
            a_weight = self.weighted_metrics[AvailabilityImpact][vector.availability.value]
            
            impact = min(1.08, 1 - ((1 - c_weight) * (1 - i_weight) * (1 - a_weight)))
        
        if vector.scope == Scope.CHANGED:
            impact *= 1.55
        
        return impact
    
    def calculate_base_score(self, vector: CVSSVector) -> float:
        exploitability = self.calculate_exploitability(vector)
        impact = self.calculate_impact(vector)
        
        if impact <= 0:
            return 0.0
        
        if vector.scope == Scope.UNCHANGED:
            base = min(10, impact + exploitability)
        else:
            base = min(10, 1.08 * (impact + exploitability))
        
        if base >= 0.1:
            return round(base, 1)
        else:
            return 0.0
    
    def calculate(self, vector: CVSSVector) -> CVSSScore:
        base_score = self.calculate_base_score(vector)
        exploitability = self.calculate_exploitability(vector)
        impact = self.calculate_impact(vector)
        
        return CVSSScore(
            vector=vector,
            base_score=base_score,
            exploitability_subscore=exploitability,
            impact_subscore=impact,
            modified_base_score=base_score
        )
    
    def calculate_from_string(self, vector_string: str) -> CVSSScore:
        vector = CVSSVector.from_string(vector_string)
        return self.calculate(vector)


class CVSSScorer:
    def __init__(self):
        self.calculator = CVSSCalculator()
        self.score_history: List[Dict[str, Any]] = []
    
    def score_vulnerability(self, vector_string: str) -> CVSSScore:
        score = self.calculator.calculate_from_string(vector_string)
        
        self.score_history.append({
            'timestamp': time.time(),
            'vector': vector_string,
            'score': score.base_score,
            'severity': score.get_severity()
        })
        
        return score
    
    def score_from_impact(self, impact_description: Dict[str, Any]) -> CVSSScore:
        vector = CVSSVector()
        
        if impact_description.get('remotely_exploitable'):
            vector.attack_vector = AttackVector.NETWORK
        elif impact_description.get('adjacent_network'):
            vector.attack_vector = AttackVector.ADJACENT
        elif impact_description.get('local_access'):
            vector.attack_vector = AttackVector.LOCAL
        else:
            vector.attack_vector = AttackVector.PHYSICAL
        
        if impact_description.get('complexity_low', True):
            vector.attack_complexity = AttackComplexity.LOW
        else:
            vector.attack_complexity = AttackComplexity.HIGH
        
        if impact_description.get('no_auth_required'):
            vector.privilege_required = PrivilegeRequired.NONE
        elif impact_description.get('low_privilege'):
            vector.privilege_required = PrivilegeRequired.LOW
        else:
            vector.privilege_required = PrivilegeRequired.HIGH
        
        if impact_description.get('no_user_interaction'):
            vector.user_interaction = UserInteraction.NONE
        else:
            vector.user_interaction = UserInteraction.REQUIRED
        
        if impact_description.get('scope_changed'):
            vector.scope = Scope.CHANGED
        else:
            vector.scope = Scope.UNCHANGED
        
        cimpact = impact_description.get('confidentiality', 'none')
        iimpact = impact_description.get('integrity', 'none')
        aimpact = impact_description.get('availability', 'none')
        
        vector.confidentiality = ConfidentialityImpact(cimpact[0].upper()) if cimpact else ConfidentialityImpact.NONE
        vector.integrity = IntegrityImpact(iimpact[0].upper()) if iimpact else IntegrityImpact.NONE
        vector.availability = AvailabilityImpact(aimpact[0].upper()) if aimpact else AvailabilityImpact.NONE
        
        return self.calculator.calculate(vector)
    
    def convert_cwe_to_cvss(self, cwe_id: str) -> Dict[str, Any]:
        cwe_database = {
            'CWE-20': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-22': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'CWE-78': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-79': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
            'CWE-89': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-94': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-119': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'CWE-200': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'CWE-264': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-284': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'CWE-287': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'CWE-306': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-310': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-330': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
            'CWE-362': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-400': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            'CWE-416': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CWE-434': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'CWE-502': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        }
        
        default_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
        
        vector_string = cwe_database.get(cwe_id, default_vector)
        return self.score_vulnerability(vector_string).to_dict()
    
    def get_average_score(self) -> float:
        if not self.score_history:
            return 0.0
        
        return sum(s['score'] for s in self.score_history) / len(self.score_history)
    
    def get_highest_severity(self) -> str:
        if not self.score_history:
            return "NONE"
        
        max_score = max(s['score'] for s in self.score_history)
        
        if max_score >= 9.0:
            return "CRITICAL"
        elif max_score >= 7.0:
            return "HIGH"
        elif max_score >= 4.0:
            return "MEDIUM"
        elif max_score >= 0.1:
            return "LOW"
        return "NONE"
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            'total_vulnerabilities': len(self.score_history),
            'average_score': self.get_average_score(),
            'highest_severity': self.get_highest_severity(),
            'scores': [s for s in self.score_history]
        }


def calculate_cvss(vector_string: str) -> Dict[str, Any]:
    scorer = CVSSScorer()
    return scorer.score_vulnerability(vector_string).to_dict()


def convert_cwe_to_cvss(cwe_id: str) -> Dict[str, Any]:
    scorer = CVSSScorer()
    return scorer.convert_cwe_to_cvss(cwe_id)


if __name__ == '__main__':
    result = calculate_cvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    print(json.dumps(result, indent=2))