"""Consolidated SQL Injection Detection Engine orchestrating AST, signatures, and heuristics."""

from collections.abc import Sequence

from sqlilab.config.settings import Settings, get_settings
from sqlilab.detector.heuristics import SQLHeuristicAnalyzer
from sqlilab.detector.signatures import SQLSignatureEngine
from sqlilab.detector.tokenizer import SQLASTAnalyzer
from sqlilab.models.finding import ConfidenceLevel, DetectionFinding
from sqlilab.models.query import QueryAuditResult


class SQLiDetectionEngine:
    """Core detection orchestrator coordinating syntactic, signature, and heuristic analysis."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the detection engine and all subordinate analysis modules."""
        self.settings = settings or get_settings()
        self.tokenizer = SQLASTAnalyzer()
        self.signatures = SQLSignatureEngine()
        self.heuristics = SQLHeuristicAnalyzer()

    def analyze(self, input_text: str) -> QueryAuditResult:
        """Analyze an arbitrary SQL query or input parameter for SQL injection indicators.

        Args:
            input_text: The raw SQL query string or untrusted user input parameter.

        Returns:
            QueryAuditResult containing consolidated findings, risk metrics, and verdict.
        """
        stripped_input = input_text.strip()
        if not stripped_input:
            return QueryAuditResult(
                input_text=input_text,
                is_malicious=False,
                risk_score=0.0,
                risk_level="CLEAN",
                findings=[],
                entropy=0.0,
                token_count=0,
            )

        # 1. Syntactic / Lexical AST Analysis
        token_summary = self.tokenizer.extract_tokens(input_text)
        ast_findings = self.tokenizer.analyze(input_text)

        # 2. Multi-Vector Signature Scanning
        signature_findings = self.signatures.scan(input_text)

        # 3. Shannon Entropy & Heuristic Anomaly Scoring
        heuristic_metrics, heuristic_findings = self.heuristics.analyze(input_text)

        # 4. Consolidate & Deduplicate Findings
        combined_findings = ast_findings + signature_findings + heuristic_findings
        unique_findings = self._deduplicate_findings(combined_findings)

        # 5. Calculate Weighted Risk Score & Assign Qualitative Verdict
        risk_score = self._compute_risk_score(
            unique_findings,
            anomaly_score=heuristic_metrics.anomaly_score,
        )

        risk_level = self._categorize_risk_level(risk_score)
        is_malicious = risk_level == "MALICIOUS"

        return QueryAuditResult(
            input_text=input_text,
            is_malicious=is_malicious,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=unique_findings,
            entropy=heuristic_metrics.entropy,
            token_count=token_summary.total_tokens,
        )

    def _deduplicate_findings(
        self,
        findings: Sequence[DetectionFinding],
    ) -> list[DetectionFinding]:
        """Eliminate duplicate findings with the same finding_id preserving order."""
        seen_ids: set[str] = set()
        deduped: list[DetectionFinding] = []
        for finding in findings:
            if finding.finding_id not in seen_ids:
                seen_ids.add(finding.finding_id)
                deduped.append(finding)
        return deduped

    def _compute_risk_score(
        self,
        findings: Sequence[DetectionFinding],
        anomaly_score: float,
    ) -> float:
        """Compute consolidated risk score from 0.0 to 100.0 based on findings and heuristics."""
        if not findings and anomaly_score < 0.3:
            return round(anomaly_score * 10.0, 1)

        score = 0.0
        confidence_weights = {
            ConfidenceLevel.CERTAIN: 40.0,
            ConfidenceLevel.HIGH: 30.0,
            ConfidenceLevel.MEDIUM: 18.0,
            ConfidenceLevel.LOW: 10.0,
            ConfidenceLevel.INFORMATIONAL: 3.0,
        }

        has_certain = False
        has_high = False
        certain_or_high_count = 0

        for finding in findings:
            weight = confidence_weights.get(finding.confidence, 10.0)
            score += weight

            if finding.confidence == ConfidenceLevel.CERTAIN:
                has_certain = True
                certain_or_high_count += 1
            elif finding.confidence == ConfidenceLevel.HIGH:
                has_high = True
                certain_or_high_count += 1

        # Heuristic anomaly score adds up to 20 points
        score += anomaly_score * 20.0

        # Guarantee critical thresholds for definitive attacks
        if has_certain:
            score = max(score, 75.0)
        elif has_high and certain_or_high_count >= 1:
            score = max(score, 70.0)
        elif certain_or_high_count >= 2:
            score = max(score, 85.0)

        # Bound score between 0.0 and 100.0
        score = min(100.0, max(0.0, score))
        return round(score, 1)

    def _categorize_risk_level(self, score: float) -> str:
        """Classify numeric score into CLEAN, SUSPICIOUS, or MALICIOUS."""
        if score >= 70.0:
            return "MALICIOUS"
        if score >= 30.0:
            return "SUSPICIOUS"
        return "CLEAN"
