"""Unit tests for sqlilab domain models and validation."""

from sqlilab.models.finding import ConfidenceLevel, DetectionFinding, SQLiCategory
from sqlilab.models.query import LabQueryRequest, LabQueryResult, QueryAuditResult


def test_enums_serialization() -> None:
    """Test SQLiCategory and ConfidenceLevel enums."""
    assert SQLiCategory.UNION_BASED == "UNION_BASED"
    assert SQLiCategory.TAUTOLOGY == "TAUTOLOGY"
    assert ConfidenceLevel.CERTAIN == "CERTAIN"
    assert ConfidenceLevel.HIGH == "HIGH"


def test_detection_finding_instantiation() -> None:
    """Test DetectionFinding creation and default values."""
    finding = DetectionFinding(
        finding_id="FIND-SQLI-001",
        rule_name="Classic Tautology Detection",
        category=SQLiCategory.TAUTOLOGY,
        confidence=ConfidenceLevel.CERTAIN,
        matched_payload="' OR '1'='1",
        explanation="Injected expression evaluates always to true",
    )
    assert finding.finding_id == "FIND-SQLI-001"
    assert finding.cwe_id == "CWE-89"
    assert "parameterized queries" in finding.remediation


def test_query_audit_result_model() -> None:
    """Test QueryAuditResult risk categorization and serialization."""
    finding = DetectionFinding(
        finding_id="FIND-SQLI-002",
        rule_name="Union Select Probe",
        category=SQLiCategory.UNION_BASED,
        confidence=ConfidenceLevel.HIGH,
        matched_payload="UNION SELECT NULL, NULL",
        explanation="Union operator injected",
    )
    audit = QueryAuditResult(
        input_text="1 UNION SELECT NULL, NULL",
        is_malicious=True,
        risk_score=92.5,
        risk_level="MALICIOUS",
        findings=[finding],
        entropy=3.85,
        token_count=6,
    )
    assert audit.is_malicious is True
    assert audit.risk_score == 92.5
    assert len(audit.findings) == 1
    assert audit.analyzed_at is not None

    dumped = audit.model_dump()
    assert dumped["risk_level"] == "MALICIOUS"


def test_lab_query_models() -> None:
    """Test LabQueryRequest and LabQueryResult structures."""
    req = LabQueryRequest(param_value="admin'--", mode="insecure", endpoint="auth_login")
    assert req.param_value == "admin'--"
    assert req.mode == "insecure"

    res = LabQueryResult(
        raw_input="admin'--",
        mode="insecure",
        endpoint="auth_login",
        constructed_sql="SELECT * FROM users WHERE username = 'admin'--' AND pass = 'x'",
        executed_safely=False,
        rows_returned=[{"id": 1, "username": "admin"}],
        row_count=1,
    )
    assert res.row_count == 1
    assert res.executed_safely is False
