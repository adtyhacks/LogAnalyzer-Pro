# LogAnalyzer Pro — Testing Guide

This document describes the automated testing suite and verification procedures for LogAnalyzer Pro.

---

## Test Architecture

LogAnalyzer Pro uses **Pytest** for comprehensive, deterministic automated testing across all layers of the application.

Tests are organized as follows:
- `tests/conftest.py`: Fixtures for isolated temporary SQLite databases and sample event streams.
- `tests/test_parsers.py`: Verifies parser normalization, edge cases, invalid logs, and format auto-detection.
- `tests/test_detection_rules.py`: Validates all 7 detection engine rules against controlled attack conditions.
- `tests/test_correlation.py`: Tests temporal event clustering, deduplication, and multi-alert incident synthesis.
- `tests/test_risk_scoring.py`: Tests explainable 0–100 risk scoring calculations and factor explanations.
- `tests/test_mitre_mapping.py`: Validates technique lookups and local MITRE knowledge base integrity.
- `tests/test_database.py`: Tests SQLite schema migrations, WAL mode, SHA-256 deduplication, and lifecycle transitions.
- `tests/test_reporting.py`: Verifies PDF security investigation report generation and CSV exports.

---

## Running Tests

### Standard Execution
Run the full test suite with verbose output:
```powershell
python -m pytest -v
```

### Run Specific Test Modules
```powershell
# Run only detection rules tests
python -m pytest tests/test_detection_rules.py -v

# Run only parser tests
python -m pytest tests/test_parsers.py -v

# Run only correlation tests
python -m pytest tests/test_correlation.py -v
```

---

## Test Execution Results

All 26 automated unit tests pass consistently:
- `test_parsers.py` (7 tests): **PASSED**
- `test_detection_rules.py` (7 tests): **PASSED**
- `test_correlation.py` (1 test): **PASSED**
- `test_risk_scoring.py` (2 tests): **PASSED**
- `test_mitre_mapping.py` (3 tests): **PASSED**
- `test_database.py` (4 tests): **PASSED**
- `test_reporting.py` (2 tests): **PASSED**

**Total: 26 passed, 0 failures.**
