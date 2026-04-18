"""
Bug Bounty Chain

Production-grade bug bounty program integration chain for vulnerability
discovery and reporting. Manages triage, severity scoring, and reward calculation.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BountyTier(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class BountyStatus(Enum):
    SUBMITTED = "submitted"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REJECTED = "rejected"
    CLOSED = "closed"


class AttackComplexity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class BountyReport:
    report_id: str
    contract_address: str
    vulnerability_type: str
    severity: BountyTier
    description: str
    impact: str
    steps_to_reproduce: List[str]
    proof_of_concept: Optional[str]
    affected_contracts: List[str]
    fixed: bool
    reward_paid: Optional[float]
    reporter: str
    submitted_at: str
    status: BountyStatus


@dataclass
class RewardCalculation:
    base_reward: float
    severity_multiplier: float
    impact_multiplier: float
    complexity_multiplier: float
    speed_bonus: float
    total_reward: float
    currency: str = "USDC"


@dataclass
class BountyMetrics:
    total_reports: int
    confirmed_vulnerabilities: int
    false_positives: int
    average_resolution_time_days: float
    total_rewards_paid: float
    by_severity: Dict[str, int]


class BountyChain:
    REWARD_TIERS = {
        BountyTier.CRITICAL: 50000,
        BountyTier.HIGH: 10000,
        BountyTier.MEDIUM: 2500,
        BountyTier.LOW: 500,
        BountyTier.INFORMATIONAL: 100,
    }

    IMPACT_MULTIPLIERS = {
        "critical": 2.0,
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5,
    }

    def __init__(self):
        self.reports: List[BountyReport] = []
        self.reward_pool: float = 0.0

    def submit_report(
        self,
        contract_address: str,
        vulnerability_type: str,
        severity: BountyTier,
        description: str,
        impact: str,
        steps_to_reproduce: List[str],
        proof_of_concept: Optional[str] = None,
        reporter: str = "anonymous",
    ) -> BountyReport:
        import hashlib

        report_id = hashlib.md5(
            f"{contract_address}{vulnerability_type}{datetime.utcnow()}".encode()
        ).hexdigest()[:12]

        report = BountyReport(
            report_id=report_id,
            contract_address=contract_address,
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            impact=impact,
            steps_to_reproduce=steps_to_reproduce,
            proof_of_concept=proof_of_concept,
            affected_contracts=[contract_address],
            fixed=False,
            reward_paid=None,
            reporter=reporter,
            submitted_at=datetime.utcnow().isoformat() + "Z",
            status=BountyStatus.SUBMITTED,
        )

        self.reports.append(report)
        logger.info(f"New bounty report submitted: {report_id}")

        return report

    def triage_report(self, report_id: str, confirmed: bool, notes: str = "") -> BountyReport:
        report = self._find_report(report_id)
        if not report:
            raise ValueError(f"Report not found: {report_id}")

        if confirmed:
            report.status = BountyStatus.CONFIRMED
            logger.info(f"Report {report_id} confirmed")
        else:
            report.status = BountyStatus.REJECTED
            logger.info(f"Report {report_id} rejected")

        return report

    def calculate_reward(
        self,
        report_id: str,
        impact_level: str = "medium",
        attack_complexity: AttackComplexity = AttackComplexity.MEDIUM,
        submitted_early: bool = False,
    ) -> RewardCalculation:
        report = self._find_report(report_id)
        if not report:
            raise ValueError(f"Report not found: {report_id}")

        base_reward = self.REWARD_TIERS.get(report.severity, 100)

        severity_multiplier = 1.0
        if report.severity == BountyTier.CRITICAL:
            severity_multiplier = 2.0
        elif report.severity == BountyTier.HIGH:
            severity_multiplier = 1.5

        impact_multiplier = self.IMPACT_MULTIPLIERS.get(impact_level, 1.0)

        complexity_multiplier = 1.0
        if attack_complexity == AttackComplexity.LOW:
            complexity_multiplier = 1.25
        elif attack_complexity == AttackComplexity.HIGH:
            complexity_multiplier = 0.75

        speed_bonus = 0.0
        if submitted_early:
            speed_bonus = base_reward * 0.1

        total = (
            base_reward *
            severity_multiplier *
            impact_multiplier *
            complexity_multiplier +
            speed_bonus
        )

        return RewardCalculation(
            base_reward=base_reward,
            severity_multiplier=severity_multiplier,
            impact_multiplier=impact_multiplier,
            complexity_multiplier=complexity_multiplier,
            speed_bonus=speed_bonus,
            total_reward=round(total, 2),
        )

    def resolve_report(
        self,
        report_id: str,
        reward_amount: float,
        fix_verified: bool = True,
    ) -> BountyReport:
        report = self._find_report(report_id)
        if not report:
            raise ValueError(f"Report not found: {report_id}")

        report.status = BountyStatus.RESOLVED if fix_verified else BountyStatus.CLOSED
        report.fixed = fix_verified
        report.reward_paid = reward_amount

        logger.info(f"Report {report_id} resolved with reward: {reward_amount}")

        return report

    def get_metrics(self) -> BountyMetrics:
        total = len(self.reports)
        confirmed = sum(1 for r in self.reports if r.status == BountyStatus.CONFIRMED)
        rejected = sum(1 for r in self.reports if r.status == BountyStatus.REJECTED)

        rewards = sum(r.reward_paid or 0 for r in self.reports)

        by_severity = {}
        for tier in BountyTier:
            count = sum(1 for r in self.reports if r.severity == tier)
            by_severity[tier.value] = count

        return BountyMetrics(
            total_reports=total,
            confirmed_vulnerabilities=confirmed,
            false_positives=rejected,
            average_resolution_time_days=7.5,
            total_rewards_paid=rewards,
            by_severity=by_severity,
        )

    def generate_report_summary(self, report_id: str) -> str:
        report = self._find_report(report_id)
        if not report:
            raise ValueError(f"Report not found: {report_id}")

        lines = []
        lines.append("=" * 50)
        lines.append(f"BUG BOUNTY REPORT #{report.report_id}")
        lines.append("=" * 50)
        lines.append("")
        lines.append(f"Contract: {report.contract_address}")
        lines.append(f"Severity: {report.severity.value.upper()}")
        lines.append(f"Type: {report.vulnerability_type}")
        lines.append(f"Status: {report.status.value}")
        lines.append(f"Reporter: {report.reporter}")
        lines.append(f"Submitted: {report.submitted_at}")
        lines.append("")
        lines.append("Description:")
        lines.append("-" * 30)
        lines.append(report.description)
        lines.append("")
        lines.append("Impact:")
        lines.append("-" * 30)
        lines.append(report.impact)
        lines.append("")
        lines.append("Steps to Reproduce:")
        lines.append("-" * 30)
        for i, step in enumerate(report.steps_to_reproduce, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append(f"Fixed: {'Yes' if report.fixed else 'No'}")
        lines.append(f"Reward Paid: ${report.reward_paid or 0}")
        lines.append("=" * 50)

        return "\n".join(lines)

    def export_reports(self, format: str = "json") -> str:
        import json

        if format == "json":
            data = []
            for report in self.reports:
                data.append({
                    "report_id": report.report_id,
                    "contract_address": report.contract_address,
                    "vulnerability_type": report.vulnerability_type,
                    "severity": report.severity.value,
                    "description": report.description,
                    "impact": report.impact,
                    "status": report.status.value,
                    "reward_paid": report.reward_paid,
                    "reporter": report.reporter,
                })
            return json.dumps(data, indent=2)

        return str(len(self.reports))

    def _find_report(self, report_id: str) -> Optional[BountyReport]:
        for report in self.reports:
            if report.report_id == report_id:
                return report
        return None

    def get_reports_by_severity(self, severity: BountyTier) -> List[BountyReport]:
        return [r for r in self.reports if r.severity == severity]

    def get_reports_by_status(self, status: BountyStatus) -> List[BountyReport]:
        return [r for r in self.reports if r.status == status]

    def get_unresolved_reports(self) -> List[BountyReport]:
        return [
            r for r in self.reports
            if r.status not in (BountyStatus.RESOLVED, BountyStatus.CLOSED)
        ]


def create_bounty_program(
    initial_pool: float = 100000,
) -> BountyChain:
    chain = BountyChain()
    chain.reward_pool = initial_pool
    return chain


__all__ = [
    "BountyChain",
    "BountyTier",
    "BountyStatus",
    "AttackComplexity",
    "BountyReport",
    "RewardCalculation",
    "BountyMetrics",
    "create_bounty_program",
]
