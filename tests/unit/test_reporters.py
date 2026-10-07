"""Unit tests for sqlilab multi-format reporters (JSON, Markdown, SARIF)."""

import json

import pytest

from sqlilab.detector.engine import SQLiDetectionEngine
from sqlilab.models.finding import ConfidenceLevel, DetectionFinding, SQLiCategory
from sqlilab.models.query import QueryAuditResult
from sqlilab.reporters.factory import ReporterFactory
from sqlilab.reporters.json_reporter import JSONReporter
from sqlilab.reporters.markdown_reporter import MarkdownReporter
from sqlilab.reporters.sarif_reporter import SARIFReporter


@pytest.fixture
def sample_result() -> QueryAuditResult:
    """Fixture providing a realistic QueryAuditResult with findings."""
    engine = SQLiDetectionEngine()
    return engine.analyze("' OR 1=1--")


@pytest.fixture
def clean_result() -> QueryAuditResult:
    """Fixture providing a clean benign QueryAuditResult."""
    engine = SQLiDetectionEngine()
    return engine.analyze("SELECT id, name FROM users WHERE id = 10;")


def test_json_reporter_single_and_batch(
    sample_result: QueryAuditResult,
    clean_result: QueryAuditResult,
) -> None:
    """Verify JSON reporter outputs valid parseable JSON with expected schema."""
    reporter = JSONReporter()

    # Single result
    raw_single = reporter.generate(sample_result)
    parsed_single = json.loads(raw_single)
    assert parsed_single["is_malicious"] is True
    assert parsed_single["risk_score"] >= 70.0
    assert len(parsed_single["findings"]) > 0

    # Batch results
    raw_batch = reporter.generate_batch([sample_result, clean_result])
    parsed_batch = json.loads(raw_batch)
    assert isinstance(parsed_batch, list)
    assert len(parsed_batch) == 2
    assert parsed_batch[0]["is_malicious"] is True
    assert parsed_batch[1]["is_malicious"] is False


def test_markdown_reporter_single_and_batch(
    sample_result: QueryAuditResult,
    clean_result: QueryAuditResult,
) -> None:
    """Verify Markdown reporter renders tables, status badges, and remediation sections."""
    reporter = MarkdownReporter()

    # Malicious result with findings
    md_output = reporter.generate(sample_result)
    assert "# SQL Injection Audit Report" in md_output
    assert "CRITICAL / MALICIOUS" in md_output
    assert "| ID | Rule Name | Category |" in md_output
    assert "Remediation" in md_output

    # Clean result with no findings
    clean_md = reporter.generate(clean_result)
    assert "CLEAN / BENIGN" in clean_md
    assert "No SQL injection patterns" in clean_md

    # Suspicious result
    suspicious_result = QueryAuditResult(
        input_text="suspicious text",
        is_malicious=False,
        risk_score=45.0,
        risk_level="SUSPICIOUS",
        findings=[],
    )
    susp_md = reporter.generate(suspicious_result)
    assert "SUSPICIOUS" in susp_md

    # Batch output
    batch_md = reporter.generate_batch([sample_result, clean_result, suspicious_result])
    assert "# Batch SQL Injection Audit Report" in batch_md
    assert "| 1 |" in batch_md
    assert "| 2 |" in batch_md


def test_sarif_reporter_schema_and_levels(sample_result: QueryAuditResult) -> None:
    """Verify SARIF v2.1.0 schema compliance and confidence-to-level mapping."""
    reporter = SARIFReporter()

    # Inject diverse findings to exercise level mappings
    sample_result.findings.extend(
        [
            DetectionFinding(
                finding_id="FIND-MED-TEST",
                rule_name="Medium Finding Test",
                category=SQLiCategory.HEURISTIC_ANOMALY,
                confidence=ConfidenceLevel.MEDIUM,
                matched_payload="test",
                explanation="Medium test explanation",
            ),
            DetectionFinding(
                finding_id="FIND-LOW-TEST",
                rule_name="Low Finding Test",
                category=SQLiCategory.HEURISTIC_ANOMALY,
                confidence=ConfidenceLevel.LOW,
                matched_payload="test",
                explanation="Low test explanation",
            ),
        ]
    )

    sarif_raw = reporter.generate(sample_result)
    sarif = json.loads(sarif_raw)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "sqlilab"
    assert len(driver["rules"]) >= 3

    results = sarif["runs"][0]["results"]
    assert len(results) >= 3

    levels = {r["level"] for r in results}
    assert "error" in levels
    assert "warning" in levels
    assert "note" in levels


def test_reporter_factory() -> None:
    """Verify ReporterFactory creates corresponding reporters and handles invalid formats."""
    json_rep = ReporterFactory.create_reporter("json")
    assert isinstance(json_rep, JSONReporter)

    md_rep = ReporterFactory.create_reporter("markdown")
    assert isinstance(md_rep, MarkdownReporter)

    md_short = ReporterFactory.create_reporter("md")
    assert isinstance(md_short, MarkdownReporter)

    sarif_rep = ReporterFactory.create_reporter("sarif")
    assert isinstance(sarif_rep, SARIFReporter)

    with pytest.raises(ValueError, match="Unsupported report format"):
        ReporterFactory.create_reporter("xml")
