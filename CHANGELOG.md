# Changelog

All notable changes to `sqlilab` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-07

### Added
- **Phase 1: Project Foundation & Configuration**
  - Modern `pyproject.toml` packaging with Hatchling.
  - Strict type hints (`mypy`), formatting (`ruff`), and security linting (`bandit`).
  - Runtime settings with environment variable prefix `SQLILAB_`.
- **Phase 2: Domain Taxonomy & Models**
  - `SQLiCategory` enumeration covering union, error, boolean blind, time blind, stacked, tautology, comment, and heuristic anomalies.
  - `ConfidenceLevel` rating model and `DetectionFinding` with CWE-89 mapping.
  - `QueryAuditResult` and dual-mode `LabQueryRequest`/`LabQueryResult` schemas.
- **Phase 3: Syntactic AST Analyzer**
  - AST-based tautology detector handling numeric and string comparisons (`' OR '1'='1`, `1=1`).
  - Comment injection breakout analyzer (`--`, `/* ... */`, `#`).
  - Stacked query identifier for semicolon delimiters.
  - Compound UNION SELECT detector.
  - Quote and parenthesis delimiter imbalance checks.
- **Phase 4: Multi-Vector Signature Engine**
  - XPath/XML error-based extraction (`EXTRACTVALUE`, `UPDATEXML`).
  - Time-based blind execution (`SLEEP`, `WAITFOR DELAY`, `pg_sleep`, `BENCHMARK`).
  - Boolean-blind substring/ASCII ordinal testing.
  - Out-of-band and system command execution (`xp_cmdshell`, `INTO OUTFILE`, `LOAD_FILE`).
  - Dynamic string obfuscation rules (`CHAR`, `UNHEX`).
- **Phase 5: Heuristic & Shannon Entropy Scorer**
  - Information-theoretic Shannon entropy calculator.
  - Special operator and delimiter density ratio metrics.
  - SQL keyword density calculator.
- **Phase 6: Consolidated Detection Engine**
  - Weighted risk scoring engine ($0.0 - 100.0$) categorizing inputs into `CLEAN`, `SUSPICIOUS`, and `MALICIOUS`.
  - Finding deduplication and composite confidence scoring.
- **Phase 7: Dual-Mode Defensive Laboratory**
  - In-memory SQLite database populated with `users`, `products`, and `accounts`.
  - `LabExecutor` with vulnerable (string interpolation) and hardened (parameterized prepared statements) modes.
- **Phase 8: Multi-Format Reporting**
  - `JSONReporter` for automated CI/CD parsing.
  - `MarkdownReporter` with executive summaries, status badges, and remediation advice.
  - `SARIFReporter` conforming to OASIS SARIF v2.1.0 for GitHub Code Scanning.
  - `ReporterFactory` instantiation layer.
- **Phase 9: Typer & Rich CLI Interface**
  - Commands: `audit`, `analyze`, `benchmark`, `lab`, and `version`.
- **Phase 10: FastAPI Microservice & Release**
  - REST API with `/health`, `/api/v1/detect`, `/api/v1/simulate`, and `/api/v1/rules`.
  - Multi-stage rootless `Dockerfile` (UID `10001:10001`) and `docker-compose.yml`.
  - GitHub Actions CI workflow with 90% coverage gate.
  - STRIDE Threat Model and Architecture documentation.
