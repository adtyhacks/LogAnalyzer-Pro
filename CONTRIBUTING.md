# Contributing to LogAnalyzer Pro

Thank you for your interest in contributing to **LogAnalyzer Pro**! We welcome contributions from cybersecurity engineers, developers, and researchers.

## Code of Conduct

Please uphold high professional standards, respectful communication, and collaborative security engineering practices.

## How to Contribute

### 1. Adding Detection Rules
- Create your rule in `loganalyzer/detection/rules/<rule_name>.py` inheriting from `BaseDetectionRule`.
- Define default configuration parameters and thresholds.
- Map the rule to a recognized MITRE ATT&CK Enterprise technique in `loganalyzer/intel/mitre_mapper.py` and `loganalyzer/intel/mitre_data.json`.
- Add comprehensive unit tests in `tests/test_detection_rules.py`.

### 2. Adding Parsers
- Add a new parser in `loganalyzer/parsers/` inheriting from `BaseLogParser`.
- Implement `parse_content` ensuring resilient timestamp normalization and invalid record tracking.
- Update `loganalyzer/parsers/factory.py` with file signature heuristics.
- Add parser tests in `tests/test_parsers.py`.

### 3. Submitting Pull Requests
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/awesome-detection`.
3. Ensure all tests pass: `python -m pytest -v`.
4. Commit your changes: `git commit -m "feat(detection): add kerberoasting heuristic"`.
5. Push to the branch: `git push origin feature/awesome-detection`.
6. Open a Pull Request detailing the problem statement, rule logic, and test coverage.

## Running Tests
Run the automated test suite locally:
```powershell
python -m pytest -v
```
