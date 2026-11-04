"""Automated tests for MITRE ATT&CK mapping validation."""

from loganalyzer.intel.mitre_mapper import MitreMapper


def test_mitre_dataset_loading():
    mapper = MitreMapper()
    techniques = mapper.get_all_techniques()
    assert len(techniques) >= 5

    tech = mapper.get_technique("T1110.001")
    assert tech is not None
    assert tech["name"] == "Brute Force: Password Guessing"
    assert "Credential Access" in tech["tactic"]
    assert tech["url"].startswith("https://attack.mitre.org/")


def test_mitre_rule_mappings():
    mapper = MitreMapper()
    assert mapper.map_rule_to_technique("RULE_BRUTE_FORCE")["technique_id"] == "T1110.001"
    assert mapper.map_rule_to_technique("RULE_PASSWORD_SPRAY")["technique_id"] == "T1110.003"
    assert mapper.map_rule_to_technique("RULE_SUSPICIOUS_SUCCESS")["technique_id"] == "T1078"
    assert mapper.map_rule_to_technique("NON_EXISTENT_RULE") is None


def test_technique_validation():
    mapper = MitreMapper()
    assert mapper.is_valid_technique("T1110.001") is True
    assert mapper.is_valid_technique("T9999.999") is False
