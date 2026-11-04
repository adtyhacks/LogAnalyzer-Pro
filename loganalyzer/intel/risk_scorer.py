"""Explainable risk-scoring engine with normalized 0-100 scores and risk factor breakdowns."""

from typing import List, Dict, Any, Tuple
from loganalyzer.config import RISK_WEIGHTS


class RiskScorer:
    """Calculates explainable incident risk scores normalized from 0 to 100."""

    def __init__(self, weights: Dict[str, int] = None):
        self.weights = weights or RISK_WEIGHTS

    def calculate_score(
        self,
        severity: str,
        affected_accounts: List[str],
        failure_count: int,
        has_suspicious_success: bool,
        is_public_ip: bool,
        technique_count: int,
        detection_count: int
    ) -> Tuple[float, List[str]]:
        """
        Calculates risk score (0-100) and returns human-readable contributing factor explanations.
        """
        score = 0.0
        factors = []

        # 1. Base score from highest severity
        sev_upper = severity.upper()
        if sev_upper == "CRITICAL":
            pts = self.weights.get("severity_critical", 40)
            score += pts
            factors.append(f"Base Severity: CRITICAL (+{pts} pts)")
        elif sev_upper == "HIGH":
            pts = self.weights.get("severity_high", 30)
            score += pts
            factors.append(f"Base Severity: HIGH (+{pts} pts)")
        elif sev_upper == "MEDIUM":
            pts = self.weights.get("severity_medium", 15)
            score += pts
            factors.append(f"Base Severity: MEDIUM (+{pts} pts)")
        else:
            pts = self.weights.get("severity_low", 5)
            score += pts
            factors.append(f"Base Severity: LOW (+{pts} pts)")

        # 2. Scope: Number of affected accounts
        acct_count = len(affected_accounts)
        if acct_count > 3:
            pts = self.weights.get("multiple_accounts", 20)
            score += pts
            factors.append(f"Broad Scope: Targeted {acct_count} distinct user accounts (+{pts} pts)")
        elif acct_count > 1:
            pts = int(self.weights.get("multiple_accounts", 20) * 0.5)
            score += pts
            factors.append(f"Multi-account Scope: Targeted {acct_count} accounts (+{pts} pts)")

        # 3. High failure frequency
        if failure_count >= 10:
            pts = self.weights.get("high_frequency_failures", 15)
            score += pts
            factors.append(f"High Failure Volume: {failure_count} authentication failures (+{pts} pts)")
        elif failure_count >= 5:
            pts = int(self.weights.get("high_frequency_failures", 15) * 0.6)
            score += pts
            factors.append(f"Repeated Failures: {failure_count} authentication failures (+{pts} pts)")

        # 4. Successful login following failures (Severe credential compromise indicator)
        if has_suspicious_success:
            pts = self.weights.get("suspicious_success_after_failure", 25)
            score += pts
            factors.append(f"Likely Compromise: Successful login followed repeated failures (+{pts} pts)")

        # 5. Public Internet origin
        if is_public_ip:
            pts = self.weights.get("public_ip_source", 10)
            score += pts
            factors.append(f"Perimeter Exposure: Originates from Public IP space (+{pts} pts)")

        # 6. Multi-technique correlation
        if technique_count > 1:
            pts = self.weights.get("multi_technique_correlation", 15)
            score += pts
            factors.append(f"Attack Chain: Multiple MITRE ATT&CK techniques correlated (+{pts} pts)")

        # 7. Multiple detections
        if detection_count > 2:
            extra = min(10, detection_count * 2)
            score += extra
            factors.append(f"Persistent Attack: Aggregated {detection_count} detection alerts (+{extra} pts)")

        # Normalize score strictly between 0 and 100
        final_score = round(min(100.0, max(0.0, score)), 1)
        return final_score, factors

    @staticmethod
    def map_score_to_severity(score: float) -> str:
        """Map numeric score (0-100) to standard severity level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 35:
            return "MEDIUM"
        return "LOW"
