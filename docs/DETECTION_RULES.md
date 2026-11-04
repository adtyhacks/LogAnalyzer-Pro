# LogAnalyzer Pro — Detection Rules & Methodology

This document details the modular detection rules implemented in LogAnalyzer Pro, their detection logic, configurable thresholds, and corresponding MITRE ATT&CK Enterprise techniques.

---

## Detection Rules Matrix

| Rule ID | Rule Name | Severity | MITRE Technique | Tactic | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`RULE_BRUTE_FORCE`** | Brute-Force Authentication Attempt | `HIGH` | **T1110.001** | Credential Access | Rapid repeated login failures targeting a specific account or source IP. |
| **`RULE_PASSWORD_SPRAY`** | Password Spraying Attack | `HIGH` | **T1110.003** | Credential Access | Single source IP targeting $\ge 3$ distinct accounts to evade lockout policies. |
| **`RULE_SUSPICIOUS_SUCCESS`** | Suspicious Successful Login After Failures | `CRITICAL` | **T1078** | Valid Accounts | Successful authentication immediately preceded by multiple failed attempts. |
| **`RULE_MULTI_ACCOUNT_FAIL`** | Multiple Account Failures from Single IP | `MEDIUM` | **T1110.003** | Credential Access | Single source IP producing authentication failures across $\ge 4$ accounts. |
| **`RULE_SUSPICIOUS_LOGIN`** | Suspicious Privileged Account Login | `HIGH` | **T1078.003** | Valid Accounts | Direct successful login to high-privilege account (root, Administrator). |
| **`RULE_UNUSUAL_PATTERNS`** | Unusual High-Frequency Authentication Burst | `MEDIUM` | **T1499** | Impact / DoS | Velocity anomaly: $\ge 12$ authentication attempts in $\le 60$ seconds. |
| **`RULE_REPEATED_SUSPICIOUS_IP`** | Repeated Suspicious Source IP Activity | `HIGH` | **T1110.001** | Credential Access | Recurring failure bursts from the same IP across separated time waves. |

---

## Detailed Detection Methodologies

### 1. Brute-Force Authentication (`RULE_BRUTE_FORCE`)
- **Objective:** Detect repeated password guessing targeting an account.
- **Logic:** Evaluates a sliding temporal window of 10 minutes. If the count of failed login attempts for a `(source_ip, username)` tuple reaches or exceeds `threshold = 5`, a detection is triggered.
- **MITRE Mapping:** `T1110.001 - Brute Force: Password Guessing`.

### 2. Password Spraying (`RULE_PASSWORD_SPRAY`)
- **Objective:** Identify distributed attempts across multiple enterprise usernames.
- **Logic:** Groups failed authentications by `source_ip` within a 15-minute window. If the number of distinct target usernames is $\ge 3$ and average attempts per account is $\le 4$, the behavior is classified as a spray rather than a single-target brute-force.
- **MITRE Mapping:** `T1110.003 - Brute Force: Password Spraying`.

### 3. Suspicious Success After Repeated Failures (`RULE_SUSPICIOUS_SUCCESS`)
- **Objective:** Catch potential compromise where an attacker succeeds after brute-forcing.
- **Logic:** Scans chronologically for successful login events (`status = SUCCESS`). For each success, it inspects preceding transactions within 15 minutes for the same user or source IP. If $\ge 3$ failures preceded the success, a `CRITICAL` alert is generated.
- **MITRE Mapping:** `T1078 - Valid Accounts`.

### 4. Multiple Account Failures (`RULE_MULTI_ACCOUNT_FAIL`)
- **Objective:** Detect reconnaissance or broad enumeration where an external actor attempts access across varied accounts without triggering single-account thresholds.
- **Logic:** Flags $\ge 6$ failures across $\ge 4$ distinct usernames within 20 minutes.

### 5. Suspicious Privileged Account Login (`RULE_SUSPICIOUS_LOGIN`)
- **Objective:** Detect direct interactive access to high-value administrative credentials.
- **Logic:** Evaluates successful logins against configured privileged identities (`root`, `administrator`, `admin`, `system`, `sa`, `oracle`).
- **MITRE Mapping:** `T1078.003 - Valid Accounts: Local Accounts`.

### 6. Unusual Authentication Burst Rate (`RULE_UNUSUAL_PATTERNS`)
- **Objective:** Identify scripted attacks, automated credential stuffers, or Denial-of-Service attempts.
- **Logic:** Measures transaction velocity: $\ge 12$ attempts within a 60-second window from a single IP.
- **MITRE Mapping:** `T1499 - Endpoint Denial of Service`.

### 7. Repeated Suspicious IP Activity (`RULE_REPEATED_SUSPICIOUS_IP`)
- **Objective:** Track adversaries who conduct multi-wave attack campaigns separated by quiet periods.
- **Logic:** Clusters failed logins by temporal gaps ($>15$ minutes). If an IP produces $\ge 2$ distinct attack waves, it is flagged as a persistent threat.
