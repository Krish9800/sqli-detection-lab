"""API route handlers for sqlilab detection and lab execution."""

from fastapi import APIRouter, status

from sqlilab.api.schemas import (
    AuditRequest,
    HealthResponse,
    RuleDetail,
    RulesListResponse,
)
from sqlilab.config.settings import get_settings
from sqlilab.detector.engine import SQLiDetectionEngine
from sqlilab.detector.signatures import SQLSignatureEngine
from sqlilab.lab.database import LabDatabase
from sqlilab.lab.endpoints import LabExecutor
from sqlilab.models.query import LabQueryRequest, LabQueryResult, QueryAuditResult

router = APIRouter()
_detector = SQLiDetectionEngine()
_lab_db = LabDatabase()
_lab_executor = LabExecutor(database=_lab_db, detector=_detector)


@router.get("/health", response_model=HealthResponse, tags=["System"])
def get_health() -> HealthResponse:
    """Return system health status and active version."""
    settings = get_settings()
    return HealthResponse(status="healthy", version=settings.version)


@router.post(
    "/api/v1/detect",
    response_model=QueryAuditResult,
    status_code=status.HTTP_200_OK,
    tags=["Detection"],
)
def detect_sqli(payload: AuditRequest) -> QueryAuditResult:
    """Audit an arbitrary SQL query or input parameter for SQL injection vectors."""
    return _detector.analyze(payload.input_text)


@router.post(
    "/api/v1/simulate",
    response_model=LabQueryResult,
    status_code=status.HTTP_200_OK,
    tags=["Simulation Lab"],
)
def simulate_query(payload: LabQueryRequest) -> LabQueryResult:
    """Execute a simulated injection payload against the database lab."""
    return _lab_executor.execute_simulation(payload)


@router.get(
    "/api/v1/rules",
    response_model=RulesListResponse,
    tags=["Taxonomy"],
)
def list_rules() -> RulesListResponse:
    """List all registered signature rules with CVE/CWE and remediation guidance."""
    rule_details = [
        RuleDetail(
            rule_id=r.rule_id,
            name=r.name,
            category=r.category.value,
            confidence=r.confidence.value,
            cwe_id="CWE-89",
            explanation=r.explanation,
            remediation=r.remediation,
        )
        for r in SQLSignatureEngine.RULES
    ]
    return RulesListResponse(total_rules=len(rule_details), rules=rule_details)
