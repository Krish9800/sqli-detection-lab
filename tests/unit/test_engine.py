"""Unit tests for the consolidated SQL Injection Detection Engine."""

import pytest

from sqlilab.config.settings import Settings
from sqlilab.detector.engine import SQLiDetectionEngine


@pytest.fixture
def engine() -> SQLiDetectionEngine:
    """Fixture providing initialized SQLiDetectionEngine."""
    return SQLiDetectionEngine()


def test_engine_initialization() -> None:
    """Verify engine instantiates correctly with default and custom settings."""
    engine_default = SQLiDetectionEngine()
    assert engine_default.settings is not None
    assert engine_default.tokenizer is not None
    assert engine_default.signatures is not None
    assert engine_default.heuristics is not None

    custom_settings = Settings(tautology_strict_mode=False)
    engine_custom = SQLiDetectionEngine(settings=custom_settings)
    assert engine_custom.settings.tautology_strict_mode is False


def test_engine_empty_input(engine: SQLiDetectionEngine) -> None:
    """Verify empty and whitespace strings return clean verdicts."""
    result = engine.analyze("")
    assert result.is_malicious is False
    assert result.risk_score == 0.0
    assert result.risk_level == "CLEAN"
    assert len(result.findings) == 0
    assert result.token_count == 0

    result_ws = engine.analyze("   \t\n  ")
    assert result_ws.is_malicious is False
    assert result_ws.risk_score == 0.0


def test_engine_benign_queries(engine: SQLiDetectionEngine) -> None:
    """Verify safe inputs and standard queries are assessed as CLEAN."""
    benign_samples = [
        "john_doe",
        "42",
        "user@example.com",
        "SELECT id, name, email FROM users WHERE id = 105;",
        "SELECT * FROM products WHERE price < 50.0 ORDER BY name ASC;",
        "Searching for high performance laptops",
    ]
    for sample in benign_samples:
        result = engine.analyze(sample)
        assert result.is_malicious is False, f"False positive on: {sample}"
        assert result.risk_score < 30.0, f"Expected low score for {sample}, got {result.risk_score}"
        assert result.risk_level == "CLEAN"


def test_engine_tautology_payloads(engine: SQLiDetectionEngine) -> None:
    """Verify classic and string tautology injections are flagged as MALICIOUS."""
    tautologies = [
        "' OR 1=1--",
        "admin' OR '1'='1",
        "' OR 'a'='a",
        "105 OR 1=1",
    ]
    for payload in tautologies:
        result = engine.analyze(payload)
        assert result.is_malicious is True, f"Failed detection on: {payload}"
        assert result.risk_score >= 70.0
        assert result.risk_level == "MALICIOUS"
        assert len(result.findings) > 0


def test_engine_stacked_queries(engine: SQLiDetectionEngine) -> None:
    """Verify stacked query injection attempts are flagged as MALICIOUS."""
    payloads = [
        "1; DROP TABLE users;--",
        "10; INSERT INTO admin_users VALUES ('hacker', 'pwned');",
        "1; SHUTDOWN;",
    ]
    for payload in payloads:
        result = engine.analyze(payload)
        assert result.is_malicious is True
        assert result.risk_score >= 70.0
        assert result.risk_level == "MALICIOUS"
        assert any("STACKED" in f.finding_id for f in result.findings)


def test_engine_union_select(engine: SQLiDetectionEngine) -> None:
    """Verify UNION SELECT injections are flagged as MALICIOUS."""
    payloads = [
        "1 UNION SELECT null, username, password FROM users--",
        "-1 UNION ALL SELECT 1, 2, sqlite_version()--",
    ]
    for payload in payloads:
        result = engine.analyze(payload)
        assert result.is_malicious is True
        assert result.risk_score >= 70.0
        assert result.risk_level == "MALICIOUS"


def test_engine_time_blind_attacks(engine: SQLiDetectionEngine) -> None:
    """Verify time-based blind injections are flagged as MALICIOUS."""
    payloads = [
        "1' AND SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "1 AND (SELECT pg_sleep(5))",
        "1 AND BENCHMARK(10000000, MD5(1))",
    ]
    for payload in payloads:
        result = engine.analyze(payload)
        assert result.is_malicious is True
        assert result.risk_score >= 70.0
        assert result.risk_level == "MALICIOUS"


def test_engine_boolean_blind_attacks(engine: SQLiDetectionEngine) -> None:
    """Verify boolean blind substrings and character extraction are flagged as MALICIOUS."""
    payload = "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)) > 65"
    result = engine.analyze(payload)
    assert result.is_malicious is True
    assert result.risk_score >= 70.0
    assert result.risk_level == "MALICIOUS"


def test_engine_error_based_and_oob(engine: SQLiDetectionEngine) -> None:
    """Verify error-based XML and system command execution injections are flagged."""
    error_payload = "1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))"
    result_err = engine.analyze(error_payload)
    assert result_err.is_malicious is True
    assert result_err.risk_score >= 70.0

    oob_payload = "1; EXEC xp_cmdshell('whoami')--"
    result_oob = engine.analyze(oob_payload)
    assert result_oob.is_malicious is True
    assert result_oob.risk_score >= 70.0


def test_engine_suspicious_entropy_and_deduplication(engine: SQLiDetectionEngine) -> None:
    """Verify heuristic borderline anomaly and deduplication behavior."""
    # Input with odd symbols and moderate anomaly but no concrete signature
    borderline = "' ; = -- /* */ ~ ^"
    result = engine.analyze(borderline)
    assert result.risk_score >= 30.0
    assert result.risk_level in ("SUSPICIOUS", "MALICIOUS")

    # Verify deduplication works
    finding_ids = [f.finding_id for f in result.findings]
    assert len(finding_ids) == len(set(finding_ids))
