# SQL Injection Detection Lab Threat Model (STRIDE)

## 1. Executive Summary

This document evaluates the security posture and threat landscape of `sqlilab`, both as a detection engine and as an interactive educational database simulation environment.

## 2. STRIDE Assessment Matrix

| Threat Category | Target Component | Threat Description | Severity | Engineered Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Authentication Handler (`auth_login`) | Attacker injects `'--` or `' OR '1'='1` to bypass password verification and authenticate as admin. | **High** | Hardened handler uses parameterized query `(? , ?)` ensuring literal parameter evaluation; AST engine flags tautology and comment injection. |
| **Tampering** | Database Records (`users`, `accounts`) | Attacker injects stacked `UPDATE` or `DELETE` statements separated by semicolons. | **Critical** | AST analyzer identifies stacked statement delimiters; SQLite in-memory isolation prevents persistent tampering; hardened endpoint isolates parameters. |
| **Repudiation** | Audit Logs & Forensics | Attacker hides injection traces through comment splitting or Unicode/hex encoding. | **Medium** | Lexical normalizer, hex/char decoding detection rules, and SARIF v2.1.0 audit logging record exact matched payloads and CWE IDs. |
| **Information Disclosure** | Data Storage (`LabDatabase`) | In-band UNION SELECT or error disclosure reveals hashed passwords, customer balances, and database metadata. | **High** | Detection engine blocks queries matching UNION SELECT patterns and information_schema queries; hardened queries eliminate data leakage. |
| **Denial of Service** | Detection Engine & Database | 1. Heavy time-blind injection (`SLEEP(100)`).<br>2. ReDoS attack on regex matching engines. | **Medium** | 1. Detection engine detects latency payloads before DB dispatch.<br>2. Regexes evaluated in linear time with non-backtracking bounds verified by stress tests (<500ms for 20KB inputs). |
| **Elevation of Privilege** | System Environment | Out-of-band commands (`xp_cmdshell`, `INTO OUTFILE`) attempting host OS compromise. | **Critical** | Signatures immediately flag OS execution attempts; container runs rootless (`UID 10001:10001`) with read-only root filesystem. |

## 3. Defense-in-Depth Implementation Checklist

1. **Deterministic Parameterization**: Parameter binding is enforced in the hardened lab layer and recommended as primary remediation.
2. **Lexical Parity**: AST parsing validates quote and parenthesis balances before query routing.
3. **Least Privilege Containerization**: Container runs without root privileges (`no-new-privileges: true`, `read_only: true`).
4. **Static Analysis & SAST**: 100% strict type hints (`mypy`), zero lint/format warnings (`ruff`), zero security defects (`bandit`).
