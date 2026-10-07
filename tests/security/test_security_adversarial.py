"""Adversarial security and evasion tests for the SQLi detection engine."""

import time

from sqlilab.detector.engine import SQLiDetectionEngine


def test_adversarial_case_variation_evasion() -> None:
    """Verify engine detects payloads utilizing randomized case variations."""
    engine = SQLiDetectionEngine()
    evasion_payloads = [
        "1 UnIoN sElEcT null, username, password FrOm users--",
        "' oR '1'='1",
        "1 AnD sLeEp(5)--",
        "1; DrOp TaBlE accounts;--",
    ]
    for payload in evasion_payloads:
        result = engine.analyze(payload)
        assert result.is_malicious is True, f"Failed case evasion on: {payload}"


def test_adversarial_inline_comment_evasion() -> None:
    """Verify engine detects payloads utilizing inline SQL comment obfuscation."""
    engine = SQLiDetectionEngine()
    evasion_payloads = [
        "1 UNION/**/SELECT/**/1,2,3--",
        "1/*comment*/UNION/*comment*/SELECT/*comment*/1,2,3",
        "'/**/OR/**/'1'='1",
    ]
    for payload in evasion_payloads:
        result = engine.analyze(payload)
        assert result.is_malicious is True, f"Failed comment evasion on: {payload}"


def test_adversarial_hex_and_character_encoding() -> None:
    """Verify engine detects dynamic string reconstitution using hex and char functions."""
    engine = SQLiDetectionEngine()
    payloads = [
        "1 UNION SELECT CHAR(97,100,109,105,110)--",
        "1 AND UNHEX('61646d696e') = 'admin'",
    ]
    for payload in payloads:
        result = engine.analyze(payload)
        assert result.is_malicious is True, f"Failed encoding evasion on: {payload}"


def test_security_redos_resilience() -> None:
    """Verify regex patterns do not exhibit catastrophic backtracking under stress."""
    engine = SQLiDetectionEngine()

    # Highly repetitive nested structures designed to stress regexes
    stress_payloads = [
        "'" + " " * 5000 + "OR" + " " * 5000 + "'1'='1'",
        "(" * 1000 + "1=1" + ")" * 1000,
        "A" * 20000,
        "/*" + "*" * 10000 + "*/",
    ]

    for payload in stress_payloads:
        start = time.perf_counter()
        result = engine.analyze(payload)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, f"ReDoS suspected: processing took {elapsed:.2f}s"
        assert result is not None
