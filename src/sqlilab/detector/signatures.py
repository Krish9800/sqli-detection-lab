"""Multi-vector regular expression signature rules for SQL injection detection."""

from dataclasses import dataclass
import re
from typing import ClassVar

from sqlilab.models.finding import ConfidenceLevel, DetectionFinding, SQLiCategory


@dataclass(frozen=True)
class SignatureRule:
    """Detection signature definition mapping regex patterns to vulnerability taxonomies."""

    rule_id: str
    name: str
    category: SQLiCategory
    confidence: ConfidenceLevel
    pattern: re.Pattern[str]
    explanation: str
    remediation: str = "Utilize parameterized queries and strict input allowlists."


class SQLSignatureEngine:
    """Evaluates input strings against curated multi-vector SQLi signature rules."""

    RULES: ClassVar[list[SignatureRule]] = [
        # 1. Error-Based SQLi
        SignatureRule(
            rule_id="SIG-SQLI-ERR-01",
            name="XML/XPath Error Injection (ExtractValue / UpdateXML)",
            category=SQLiCategory.ERROR_BASED,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)\b(extractvalue|updatexml)\s*\("),
            explanation=(
                "Detected XPath error injection function used to exfiltrate database data "
                "via error messages."
            ),
        ),
        SignatureRule(
            rule_id="SIG-SQLI-ERR-02",
            name="Type Conversion Error Probe (CAST / CONVERT)",
            category=SQLiCategory.ERROR_BASED,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(
                r"(?i)\b(cast|convert)\s*\(.*?\b(as|using)\b\s*(int|integer|numeric|varchar|char)",
            ),
            explanation=(
                "Detected explicit cast to integer used to trigger syntax and conversion "
                "error disclosure."
            ),
        ),
        # 2. Time-Based Blind SQLi
        SignatureRule(
            rule_id="SIG-SQLI-TIME-01",
            name="MySQL/PostgreSQL Sleep Injection",
            category=SQLiCategory.TIME_BLIND,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)\b(sleep|pg_sleep)\s*\(\s*\d+\s*\)"),
            explanation=(
                "Detected sleep execution call used for inferential time-based blind data "
                "extraction."
            ),
        ),
        SignatureRule(
            rule_id="SIG-SQLI-TIME-02",
            name="MySQL Benchmark CPU Delay Injection",
            category=SQLiCategory.TIME_BLIND,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)\bbenchmark\s*\(\s*\d+\s*,\s*[\w\(\)]+\s*\)"),
            explanation=(
                "Detected MySQL BENCHMARK function invocation designed to cause execution delays."
            ),
        ),
        SignatureRule(
            rule_id="SIG-SQLI-TIME-03",
            name="MSSQL WaitFor Delay Injection",
            category=SQLiCategory.TIME_BLIND,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)\bwaitfor\s+delay\s+['\"][0-9:]+['\"]"),
            explanation=("Detected MSSQL WAITFOR DELAY command used in blind timing exfiltration."),
        ),
        # 3. Boolean-Based Blind SQLi Functions
        SignatureRule(
            rule_id="SIG-SQLI-BOOL-01",
            name="Blind Extraction Substring / ASCII Function Chain",
            category=SQLiCategory.BOOLEAN_BLIND,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(
                r"(?i)\b(ascii|ord|unicode)\s*\(\s*(substr|substring)\s*\(",
            ),
            explanation=(
                "Detected byte-by-byte character extraction functions standard in automated "
                "boolean-blind attacks."
            ),
        ),
        SignatureRule(
            rule_id="SIG-SQLI-BOOL-02",
            name="Conditional Branch Delay Injection",
            category=SQLiCategory.BOOLEAN_BLIND,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(
                r"(?i)\b(if|case)\s*\(.*?\b(sleep|benchmark|waitfor)\b",
            ),
            explanation=("Detected conditional IF/CASE branch evaluating to an execution delay."),
        ),
        # 4. Out-of-Band (OOB) and System Commands
        SignatureRule(
            rule_id="SIG-SQLI-OOB-01",
            name="MSSQL Operating System Command Execution (xp_cmdshell)",
            category=SQLiCategory.STACKED_QUERIES,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)\b(exec|execute)?\s*xp_cmdshell\b"),
            explanation=(
                "Detected critical MSSQL xp_cmdshell stored procedure call granting OS execution."
            ),
            remediation="Disable xp_cmdshell and restrict database service account OS privileges.",
        ),
        SignatureRule(
            rule_id="SIG-SQLI-OOB-02",
            name="MySQL Filesystem Write / Exfiltration (INTO OUTFILE)",
            category=SQLiCategory.STACKED_QUERIES,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)\binto\s+(outfile|dumpfile)\s+['\"]"),
            explanation=(
                "Detected direct filesystem write directive used to drop web shells or exfiltrate."
            ),
            remediation="Enforce secure-file-priv and drop FILE grant from database users.",
        ),
        SignatureRule(
            rule_id="SIG-SQLI-OOB-03",
            name="MySQL Filesystem Read Directive (LOAD_FILE)",
            category=SQLiCategory.ERROR_BASED,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(r"(?i)\bload_file\s*\(\s*['\"]"),
            explanation=(
                "Detected load_file function invocation attempting to read local server files."
            ),
        ),
        # 5. Metadata and Schema Probing
        SignatureRule(
            rule_id="SIG-SQLI-META-01",
            name="Information Schema Reconnaissance Probe",
            category=SQLiCategory.UNION_BASED,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(
                r"(?i)\bfrom\s+(information_schema\.(tables|columns|schemata)|sqlite_master|sys\.databases|sys\.tables)\b",
            ),
            explanation=(
                "Detected query targeting system catalog views to enumerate database metadata."
            ),
        ),
        # 6. Character and Encoding Obfuscation
        SignatureRule(
            rule_id="SIG-SQLI-ENC-01",
            name="Dynamic String Reconstruction (CHAR / CHR / UNHEX)",
            category=SQLiCategory.HEURISTIC_ANOMALY,
            confidence=ConfidenceLevel.MEDIUM,
            pattern=re.compile(
                r"(?i)\b(char|chr)\s*\(\s*\d+(\s*,\s*\d+){2,}\s*\)|\bunhex\s*\(",
            ),
            explanation=(
                "Detected ASCII code sequence concatenation utilized to bypass WAF quote filters."
            ),
        ),
    ]

    @classmethod
    def match_signatures(cls, input_text: str) -> list[DetectionFinding]:
        """Evaluate input string against all active signature rules."""
        findings: list[DetectionFinding] = []
        if not input_text or not input_text.strip():
            return findings

        clean = input_text.strip()
        for rule in cls.RULES:
            match = rule.pattern.search(clean)
            if match:
                findings.append(
                    DetectionFinding(
                        finding_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        confidence=rule.confidence,
                        cwe_id="CWE-89",
                        matched_payload=match.group(0),
                        explanation=rule.explanation,
                        remediation=rule.remediation,
                        ast_details={"pattern": rule.pattern.pattern},
                    )
                )

        return findings

    def scan(self, input_text: str) -> list[DetectionFinding]:
        """Instance method alias for match_signatures."""
        return self.match_signatures(input_text)
