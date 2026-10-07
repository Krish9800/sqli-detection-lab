"""Integration tests for the Typer and Rich CLI interface."""

from pathlib import Path

from typer.testing import CliRunner

from sqlilab.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """Verify version command outputs application name and rules count."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "SQL Injection Detection Lab" in result.stdout
    assert "Active Signature Rules" in result.stdout


def test_cli_audit_clean_input() -> None:
    """Verify audit command with benign input exits with code 0."""
    result = runner.invoke(app, ["audit", "SELECT id FROM users WHERE id = 10;"])
    assert result.exit_code == 0
    assert "CLEAN" in result.stdout


def test_cli_audit_malicious_input() -> None:
    """Verify audit command with malicious payload exits with code 1."""
    result = runner.invoke(app, ["audit", "' OR 1=1--"])
    assert result.exit_code == 1
    assert "MALICIOUS" in result.stdout


def test_cli_audit_json_output(tmp_path: Path) -> None:
    """Verify audit command with --format json and --output writes valid JSON."""
    out_file = tmp_path / "audit_result.json"
    result = runner.invoke(
        app,
        ["audit", "' OR 1=1--", "--format", "json", "-o", str(out_file)],
    )
    assert result.exit_code == 1
    assert out_file.exists()
    assert '"is_malicious": true' in out_file.read_text(encoding="utf-8")


def test_cli_audit_invalid_format() -> None:
    """Verify audit command with unsupported format returns exit code 2."""
    result = runner.invoke(app, ["audit", "test", "--format", "unknown_fmt"])
    assert result.exit_code == 2
    assert "Error:" in result.stdout


def test_cli_analyze_file(tmp_path: Path) -> None:
    """Verify analyze command processes a file containing queries."""
    query_file = tmp_path / "queries.sql"
    query_file.write_text(
        "SELECT id, name FROM users WHERE id = 5;\n' OR '1'='1\n1; DROP TABLE users;--\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["analyze", str(query_file)])
    assert result.exit_code == 1
    assert "Batch SQLi Audit" in result.stdout
    assert "MALICIOUS" in result.stdout


def test_cli_analyze_empty_and_missing_file(tmp_path: Path) -> None:
    """Verify analyze handles missing and empty files gracefully."""
    missing = tmp_path / "missing.sql"
    res_missing = runner.invoke(app, ["analyze", str(missing)])
    assert res_missing.exit_code == 2

    empty = tmp_path / "empty.sql"
    empty.write_text("", encoding="utf-8")
    res_empty = runner.invoke(app, ["analyze", str(empty)])
    assert res_empty.exit_code == 0
    assert "Notice:" in res_empty.stdout


def test_cli_analyze_with_output_file(tmp_path: Path) -> None:
    """Verify analyze command writes batch reports to file."""
    query_file = tmp_path / "queries.sql"
    query_file.write_text("SELECT 1;\nSELECT 2;\n", encoding="utf-8")
    out_file = tmp_path / "batch.md"

    result = runner.invoke(
        app,
        ["analyze", str(query_file), "--format", "markdown", "-o", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    assert "# Batch SQL Injection Audit Report" in out_file.read_text(encoding="utf-8")


def test_cli_benchmark() -> None:
    """Verify benchmark command executes successfully and calculates metrics."""
    result = runner.invoke(app, ["benchmark"])
    assert result.exit_code == 0
    assert "SQLi Detection Engine Benchmark Results" in result.stdout
    assert "Accuracy" in result.stdout
    assert "Precision" in result.stdout
    assert "Recall" in result.stdout


def test_cli_lab_simulation() -> None:
    """Verify lab command tests in-memory database in insecure and hardened modes."""
    # Insecure mode simulation
    res_insecure = runner.invoke(
        app,
        ["lab", "' OR '1'='1", "--mode", "insecure", "--endpoint", "user_lookup"],
    )
    assert res_insecure.exit_code == 0
    assert "VULNERABLE (Insecure)" in res_insecure.stdout
    assert "Rows Leaked / Returned: 4" in res_insecure.stdout

    # Hardened mode simulation
    res_hardened = runner.invoke(
        app,
        ["lab", "' OR '1'='1", "--mode", "hardened", "--endpoint", "user_lookup"],
    )
    assert res_hardened.exit_code == 0
    assert "SAFE (Hardened)" in res_hardened.stdout
    assert "Rows Leaked / Returned: 0" in res_hardened.stdout
