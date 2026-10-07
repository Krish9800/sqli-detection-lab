"""Markdown report generator for sqlilab security audit results."""

from sqlilab.models.query import QueryAuditResult
from sqlilab.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Produces GitHub Flavored Markdown security reports."""

    def generate(self, result: QueryAuditResult) -> str:
        """Render a single audit result to a formatted Markdown report."""
        badge = (
            "🔴 **CRITICAL / MALICIOUS**"
            if result.is_malicious
            else (
                "🟡 **SUSPICIOUS**"
                if result.risk_level == "SUSPICIOUS"
                else "🟢 **CLEAN / BENIGN**"
            )
        )

        md_lines = [
            "# SQL Injection Audit Report",
            "",
            f"**Audit Status:** {badge}  ",
            f"**Risk Score:** `{result.risk_score:.1f}/100.0` ({result.risk_level})  ",
            f"**Shannon Entropy:** `{result.entropy:.2f}` bits/char  ",
            f"**Token Count:** `{result.token_count}`  ",
            f"**Analyzed At:** `{result.analyzed_at.isoformat()}`  ",
            "",
            "## Inspected Input",
            "```sql",
            result.input_text,
            "```",
            "",
            "## Findings Summary",
        ]

        if not result.findings:
            md_lines.extend(
                [
                    "",
                    "> No SQL injection patterns, syntax anomalies, or signatures were detected.",
                    "",
                ]
            )
        else:
            md_lines.extend(
                [
                    "",
                    "| ID | Rule Name | Category | Confidence | CWE | Matched Payload |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for f in result.findings:
                escaped_match = f.matched_payload.replace("|", "\\|").replace("\n", " ")
                md_lines.append(
                    f"| `{f.finding_id}` | {f.rule_name} | `{f.category.value}` "
                    f"| `{f.confidence.value}` | `{f.cwe_id}` | `{escaped_match}` |"
                )

            md_lines.extend(
                [
                    "",
                    "## Technical Explanations & Remediation",
                    "",
                ]
            )
            for f in result.findings:
                md_lines.extend(
                    [
                        f"### {f.rule_name} (`{f.finding_id}`)",
                        f"- **Explanation:** {f.explanation}",
                        f"- **Remediation:** {f.remediation}",
                        "",
                    ]
                )

        md_lines.extend(
            [
                "---",
                "*Generated automatically by SQLi-Detection-Lab Auditor.*",
            ]
        )
        return "\n".join(md_lines)

    def generate_batch(self, results: list[QueryAuditResult]) -> str:
        """Render multiple audit results into a consolidated Markdown document."""
        md_lines = [
            "# Batch SQL Injection Audit Report",
            "",
            f"**Total Queries Audited:** `{len(results)}`  ",
            f"**Malicious Queries Detected:** `{sum(1 for r in results if r.is_malicious)}`  ",
            "",
            "| # | Input Snippet | Verdict | Risk Score | Findings |",
            "| :- | :--- | :--- | :--- | :--- |",
        ]

        for i, r in enumerate(results, 1):
            snippet = r.input_text.replace("\n", " ")
            if len(snippet) > 40:
                snippet = snippet[:37] + "..."
            snippet = snippet.replace("|", "\\|")
            if r.is_malicious:
                status_icon = "🔴"
            elif r.risk_level == "SUSPICIOUS":
                status_icon = "🟡"
            else:
                status_icon = "🟢"

            md_lines.append(
                f"| {i} | `{snippet}` | {status_icon} `{r.risk_level}` "
                f"| `{r.risk_score:.1f}` | `{len(r.findings)}` |"
            )

        md_lines.extend(
            [
                "",
                "---",
                "*Generated automatically by SQLi-Detection-Lab Auditor.*",
            ]
        )
        return "\n".join(md_lines)
