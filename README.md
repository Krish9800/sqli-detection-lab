# SQLi Detection Lab (`sqlilab`)

[![CI & Security Assurance](https://github.com/cybersecurity-portfolio/sqli-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/cybersecurity-portfolio/sqli-detection-lab/actions)
[![Python 3.11 | 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue.svg)](http://mypy-lang.org/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

> **Enterprise-grade SQL Injection Detection Engine, Multi-Vector Signature Scanner, and Dual-Mode Defensive Laboratory.**

---

## 🛡️ Overview

`sqlilab` is a comprehensive defensive cybersecurity toolkit designed to detect, analyze, and remediate SQL Injection (CWE-89) vulnerabilities. It combines **lexical/AST syntax analysis**, a **multi-vector signature engine**, and **Shannon information entropy heuristics** into a consolidated risk-scoring pipeline.

Additionally, `sqlilab` embeds an **interactive in-memory database laboratory** demonstrating the stark contrast between vulnerable string-interpolated query handling and secure parameterized prepared statements.

---

## ✨ Key Capabilities

- **AST & Lexical Analyzer (`SQLASTAnalyzer`)**: Parses queries via `sqlparse` to detect boolean tautologies (`' OR '1'='1`), comment injection breakouts (`--`, `/* */`), stacked execution statements (`;`), compound UNION queries, and quote/parenthesis imbalances.
- **Multi-Vector Signatures (`SQLSignatureEngine`)**: Identifies error-based XPath (`EXTRACTVALUE`), time-based blind (`SLEEP()`, `WAITFOR DELAY`), boolean-blind substring extraction, out-of-band system commands (`xp_cmdshell`), metadata schema enumeration, and character reconstruction obfuscation (`CHAR()`, `UNHEX()`).
- **Heuristic & Entropy Scorer (`SQLHeuristicAnalyzer`)**: Computes Shannon information entropy ($H(X)$), special operator density ratios, and SQL keyword concentrations to spot encoded or packed payloads.
- **Dual-Mode Simulation Lab (`LabExecutor`)**: In-memory SQLite lab pre-seeded with `users`, `products`, and `accounts` supporting side-by-side exploitation (`mode="insecure"`) and containment (`mode="hardened"`).
- **Multi-Format Egress**: Exports audit verdicts to Rich terminal tables, structured JSON, GitHub Flavored Markdown, and **OASIS SARIF v2.1.0** for GitHub Code Scanning integration.
- **Interfaces**: Native **Typer/Rich CLI** (`sqlilab`) and high-throughput **FastAPI microservice**.

---

## 🚀 Quickstart & Installation

### Requirements
- Python $\ge 3.11$ (Tested on 3.11 and 3.12)
- Virtual environment recommended

### Installation from Source
```bash
git clone https://github.com/cybersecurity-portfolio/sqli-detection-lab.git
cd sqli-detection-lab
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## 💻 CLI Usage

The `sqlilab` CLI provides commands for auditing, batch file analysis, performance benchmarking, and lab simulation.

### 1. Single Query Audit
```bash
# Audit a single payload with terminal tables
sqlilab audit "' OR 1=1--"

# Export audit to Markdown or SARIF
sqlilab audit "1 UNION SELECT username, password FROM users--" --format markdown -o audit.md
sqlilab audit "1; DROP TABLE users;--" --format sarif -o results.sarif
```

### 2. Batch File Analysis
```bash
# Audit queries from an access log or query file
sqlilab analyze queries.sql

# Output batch results to JSON
sqlilab analyze queries.sql --format json -o batch_report.json
```

### 3. Built-in Detection Benchmark
```bash
sqlilab benchmark
```
*Evaluates true positive rates, accuracy, and average inspection latency against curated malicious and benign corpora.*

### 4. Interactive Simulation Lab
```bash
# Insecure mode: Demonstrates data dump
sqlilab lab "' OR '1'='1" --mode insecure --endpoint user_lookup

# Hardened mode: Demonstrates parameterized containment
sqlilab lab "' OR '1'='1" --mode hardened --endpoint user_lookup

# Authentication bypass simulation
sqlilab lab "admin'--" --mode insecure --endpoint auth_login
```

---

## 🌐 FastAPI Microservice

Launch the REST API server:
```bash
uvicorn sqlilab.api.app:app --host 0.0.0.0 --port 8080 --reload
```
Interactive OpenAPI documentation is available at `http://localhost:8080/docs`.

### Key Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status and version |
| `POST` | `/api/v1/detect` | Audit query/parameter string for SQLi |
| `POST` | `/api/v1/simulate` | Execute payload against simulated database lab |
| `GET` | `/api/v1/rules` | Enumerate registered signature detection rules |

#### Example Detection Request:
```bash
curl -X POST http://localhost:8080/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"input_text": "admin\" OR \"1\"=\"1"}'
```

---

## 🐳 Docker Deployment

A rootless, multi-stage Docker container runs under UID `10001:10001`:

```bash
# Build and run with Docker Compose
docker compose up -d --build

# Verify container health
curl http://localhost:8080/health
```

---

## 🧪 Quality Assurance & Security Gates

Run the complete test suite and security linters:

```bash
# Run pytest with 90%+ coverage gate
pytest --cov=sqlilab --cov-report=term-missing --cov-fail-under=90

# Enforce PEP 8 formatting and lint rules
ruff check .
ruff format --check .

# Strict static type checking
mypy src tests

# Static Application Security Testing (SAST)
bandit -r src/
```

---

## 📚 Documentation
- [System Architecture Specification](docs/architecture.md)
- [STRIDE Threat Model & Security Posture](docs/threat_model.md)
- [Changelog](CHANGELOG.md)

---

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.
