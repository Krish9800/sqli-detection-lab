"""Command Line Interface for sqlilab security audit engine and simulation lab."""

from pathlib import Path
import time
from typing import Annotated

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from sqlilab.config.settings import get_settings
from sqlilab.detector.engine import SQLiDetectionEngine
from sqlilab.detector.signatures import SQLSignatureEngine
from sqlilab.lab.database import LabDatabase
from sqlilab.lab.endpoints import LabExecutor
from sqlilab.models.query import LabQueryRequest, QueryAuditResult
from sqlilab.reporters.factory import ReporterFactory

app = typer.Typer(
    name="sqlilab",
    help="Enterprise-Grade SQL Injection Detection Engine and Defensive Lab CLI.",
    add_completion=False,
)
console = Console()


@app.command(name="audit")
def audit(
    input_text: Annotated[
        str,
        typer.Argument(help="SQL query or untrusted input parameter to inspect"),
    ],
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, json, markdown, sarif"),
    ] = "table",
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional file path to write results"),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", "-s", help="Exit code 1 on SUSPICIOUS as well as MALICIOUS"),
    ] = False,
) -> None:
    """Audit a single SQL query or untrusted input string for SQL injection patterns."""
    engine = SQLiDetectionEngine()
    result = engine.analyze(input_text)

    if output_format.lower() == "table":
        _render_table_audit(result)
    else:
        try:
            reporter = ReporterFactory.create_reporter(output_format)
            rendered = reporter.generate(result)
            if output_file:
                output_file.write_text(rendered, encoding="utf-8")
                console.print(f"[bold green]Report saved to:[/] {output_file}")
            else:
                console.print(rendered)
        except ValueError as err:
            console.print(f"[bold red]Error:[/] {err}")
            raise typer.Exit(code=2) from err

    if result.is_malicious or (strict and result.risk_level == "SUSPICIOUS"):
        raise typer.Exit(code=1)


@app.command(name="analyze")
def analyze(
    file_path: Annotated[
        Path,
        typer.Argument(help="Path to text file containing SQL statements or queries"),
    ],
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, json, markdown, sarif"),
    ] = "table",
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional file path to write results"),
    ] = None,
) -> None:
    """Batch analyze SQL queries from a file line by line."""
    if not file_path.exists():
        console.print(f"[bold red]Error:[/] File '{file_path}' does not exist.")
        raise typer.Exit(code=2)

    content = file_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip()]

    if not lines:
        console.print("[yellow]Notice:[/] File is empty. Nothing to analyze.")
        return

    engine = SQLiDetectionEngine()
    results: list[QueryAuditResult] = [engine.analyze(line) for line in lines]

    if output_format.lower() == "table":
        table = Table(
            title=f"Batch SQLi Audit ({len(results)} items)",
            border_style="bright_blue",
        )
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Query Snippet", style="white")
        table.add_column("Verdict", justify="center")
        table.add_column("Risk Score", justify="right")
        table.add_column("Entropy", justify="right")
        table.add_column("Findings", justify="right")

        for idx, res in enumerate(results, 1):
            snippet = res.input_text.replace("\n", " ")
            if len(snippet) > 45:
                snippet = snippet[:42] + "..."
            status_style = (
                "[bold red]MALICIOUS[/]"
                if res.is_malicious
                else (
                    "[bold yellow]SUSPICIOUS[/]"
                    if res.risk_level == "SUSPICIOUS"
                    else "[bold green]CLEAN[/]"
                )
            )
            table.add_row(
                str(idx),
                snippet,
                status_style,
                f"{res.risk_score:.1f}",
                f"{res.entropy:.2f}",
                str(len(res.findings)),
            )

        console.print(table)
    else:
        try:
            reporter = ReporterFactory.create_reporter(output_format)
            rendered = reporter.generate_batch(results)
            if output_file:
                output_file.write_text(rendered, encoding="utf-8")
                console.print(f"[bold green]Batch report saved to:[/] {output_file}")
            else:
                console.print(rendered)
        except ValueError as err:
            console.print(f"[bold red]Error:[/] {err}")
            raise typer.Exit(code=2) from err

    if any(r.is_malicious for r in results):
        raise typer.Exit(code=1)


@app.command(name="benchmark")
def benchmark() -> None:
    """Run built-in benchmark against known attack vectors and benign queries."""
    malicious_corpus = [
        "' OR '1'='1",
        "admin'--",
        "1; DROP TABLE users;--",
        "1 UNION SELECT null, username, password FROM users--",
        "' OR SLEEP(5)--",
        "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)) > 64",
        "1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))",
        "1; EXEC xp_cmdshell('whoami')--",
        "105 OR 1=1",
        "' OR 'a'='a",
    ]

    benign_corpus = [
        "alice",
        "42",
        "security-lead@secops.local",
        "SELECT id, username, email FROM users WHERE id = 1;",
        "SELECT * FROM products WHERE price < 100.0 ORDER BY name ASC;",
        "Search query for wireless keyboard",
        "admin",
        "UPDATE accounts SET balance = balance + 10 WHERE id = 4;",
        "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= '2026-01-01';",
        "127.0.0.1",
    ]

    engine = SQLiDetectionEngine()
    start_time = time.perf_counter()

    tp = sum(1 for p in malicious_corpus if engine.analyze(p).is_malicious)
    fn = len(malicious_corpus) - tp

    fp = sum(1 for p in benign_corpus if engine.analyze(p).is_malicious)
    tn = len(benign_corpus) - fp

    elapsed = (time.perf_counter() - start_time) * 1000
    total = len(malicious_corpus) + len(benign_corpus)
    avg_latency = elapsed / total

    accuracy = (tp + tn) / total * 100.0
    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0

    table = Table(title="SQLi Detection Engine Benchmark Results", border_style="green")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Total Evaluated Queries", str(total))
    table.add_row("True Positives (TP)", f"[green]{tp}[/]")
    table.add_row("True Negatives (TN)", f"[green]{tn}[/]")
    table.add_row("False Positives (FP)", f"[red]{fp}[/]" if fp > 0 else "0")
    table.add_row("False Negatives (FN)", f"[red]{fn}[/]" if fn > 0 else "0")
    table.add_row("Accuracy", f"{accuracy:.1f}%")
    table.add_row("Precision", f"{precision:.1f}%")
    table.add_row("Recall (TPR)", f"{recall:.1f}%")
    table.add_row("Average Detection Latency", f"{avg_latency:.2f} ms/query")

    console.print(table)


@app.command(name="lab")
def lab(
    param_value: Annotated[
        str,
        typer.Argument(help="Untrusted parameter value to inject into simulated endpoint"),
    ],
    mode: Annotated[
        str,
        typer.Option("--mode", "-m", help="Execution mode: insecure or hardened"),
    ] = "insecure",
    endpoint: Annotated[
        str,
        typer.Option(
            "--endpoint",
            "-e",
            help="Target endpoint: user_lookup, product_search, auth_login",
        ),
    ] = "user_lookup",
) -> None:
    """Execute simulated query in vulnerable or hardened in-memory database lab."""
    db = LabDatabase()
    executor = LabExecutor(database=db)
    request = LabQueryRequest(param_value=param_value, mode=mode, endpoint=endpoint)
    res = executor.execute_simulation(request)

    safety_badge = (
        "[bold green]SAFE (Hardened)[/]"
        if res.executed_safely
        else "[bold red]VULNERABLE (Insecure)[/]"
    )
    console.print(
        Panel(
            f"[bold]Target Endpoint:[/] {res.endpoint}\n"
            f"[bold]Execution Mode:[/] {res.mode.upper()}\n"
            f"[bold]Safety Status:[/] {safety_badge}\n"
            f"[bold]Constructed SQL:[/] [cyan]{res.constructed_sql}[/]\n"
            f"[bold]Rows Leaked / Returned:[/] {res.row_count}\n"
            f"[bold]Database Error:[/] {res.error_message or 'None'}",
            title="Database Simulation Lab Execution",
            border_style="magenta",
        )
    )

    if res.rows_returned:
        table = Table(title="Returned Rows", border_style="cyan")
        headers = list(res.rows_returned[0].keys())
        for h in headers:
            table.add_column(h, style="white")
        for row in res.rows_returned:
            table.add_row(*[str(row[h]) for h in headers])
        console.print(table)


@app.command(name="version")
def version() -> None:
    """Display version and active signature rule engine metadata."""
    settings = get_settings()
    console.print(
        Panel(
            f"[bold cyan]{settings.app_name}[/]\n"
            f"Version: [bold green]{settings.version}[/]\n"
            f"Environment: [white]{settings.environment}[/]\n"
            f"Active Signature Rules: [bold yellow]{len(SQLSignatureEngine.RULES)}[/]\n"
            "Supported Formats: [white]Table, JSON, Markdown, SARIF v2.1.0[/]\n"
            "Dialects Inspected: [white]SQLite, MySQL, PostgreSQL, MSSQL, Oracle[/]",
            title="System Version",
            border_style="blue",
        )
    )


def _render_table_audit(result: QueryAuditResult) -> None:
    """Render a single QueryAuditResult in rich terminal panel and table."""
    status_badge = (
        "[bold red]MALICIOUS (SQLi Detected)[/]"
        if result.is_malicious
        else (
            "[bold yellow]SUSPICIOUS[/]"
            if result.risk_level == "SUSPICIOUS"
            else "[bold green]CLEAN (No SQLi Detected)[/]"
        )
    )

    console.print(
        Panel(
            f"[bold]Input String:[/] [white]{result.input_text}[/]\n"
            f"[bold]Verdict Status:[/] {status_badge}\n"
            f"[bold]Risk Score:[/] [bold magenta]{result.risk_score:.1f}/100.0[/] "
            f"({result.risk_level})\n"
            f"[bold]Shannon Entropy:[/] {result.entropy:.2f} bits/char\n"
            f"[bold]Lexical Tokens:[/] {result.token_count}",
            title="SQL Injection Detection Audit",
            border_style="red" if result.is_malicious else "green",
        )
    )

    if result.findings:
        table = Table(title="Triggered Detections & Anomalies", border_style="red")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Category", style="yellow")
        table.add_column("Confidence", style="bold red")
        table.add_column("Matched Payload", style="magenta")

        for f in result.findings:
            table.add_row(
                f.finding_id,
                f.rule_name,
                f.category.value,
                f.confidence.value,
                f.matched_payload,
            )
        console.print(table)


if __name__ == "__main__":
    app()
