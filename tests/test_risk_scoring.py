"""Automated tests for the risk-scoring engine."""

from loganalyzer.intel.risk_scorer import RiskScorer


def test_risk_score_normalization_and_factors():
    scorer = RiskScorer()

    # Low risk scenario
    score_low, factors_low = scorer.calculate_score(
        severity="LOW",
        affected_accounts=["user1"],
        failure_count=1,
        has_suspicious_success=False,
        is_public_ip=False,
        technique_count=1,
        detection_count=1
    )
    assert 0.0 <= score_low <= 100.0
    assert scorer.map_score_to_severity(score_low) == "LOW"
    assert len(factors_low) > 0

    # Critical risk scenario (multiple accounts, high failures, compromise, public IP, multi-technique)
    score_crit, factors_crit = scorer.calculate_score(
        severity="CRITICAL",
        affected_accounts=["admin", "root", "dev", "analyst"],
        failure_count=15,
        has_suspicious_success=True,
        is_public_ip=True,
        technique_count=3,
        detection_count=4
    )
    assert score_crit == 100.0  # Normalized cap
    assert scorer.map_score_to_severity(score_crit) == "CRITICAL"
    assert any("Compromise" in f for f in factors_crit)
    assert any("Public IP" in f or "Perimeter" in f for f in factors_crit)


def test_severity_threshold_mappings():
    scorer = RiskScorer()
    assert scorer.map_score_to_severity(90.0) == "CRITICAL"
    assert scorer.map_score_to_severity(70.0) == "HIGH"
    assert scorer.map_score_to_severity(45.0) == "MEDIUM"
    assert scorer.map_score_to_severity(20.0) == "LOW"
