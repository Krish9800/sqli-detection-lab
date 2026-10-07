"""Laboratory endpoints simulating vulnerable and hardened query handlers."""

import sqlite3
from typing import Any

from sqlilab.detector.engine import SQLiDetectionEngine
from sqlilab.lab.database import LabDatabase
from sqlilab.models.query import LabQueryRequest, LabQueryResult


class LabExecutor:
    """Executes queries against simulated endpoints in insecure and hardened modes."""

    def __init__(
        self,
        database: LabDatabase | None = None,
        detector: SQLiDetectionEngine | None = None,
    ) -> None:
        """Initialize the lab execution harness with an in-memory database and detector."""
        self.db = database or LabDatabase()
        self.detector = detector or SQLiDetectionEngine()

    def execute_simulation(self, request: LabQueryRequest) -> LabQueryResult:
        """Execute a simulated parameter injection against the selected endpoint and mode.

        Args:
            request: LabQueryRequest containing parameter value, mode, and endpoint.

        Returns:
            LabQueryResult detailing constructed SQL, execution safety, and detection verdict.
        """
        verdict = self.detector.analyze(request.param_value)
        mode = request.mode.lower().strip()

        if mode == "hardened":
            return self._execute_hardened(request, verdict)
        return self._execute_insecure(request, verdict)

    def _execute_insecure(self, request: LabQueryRequest, verdict: Any) -> LabQueryResult:
        """Simulate vulnerable handler utilizing raw string interpolation without sanitization."""
        constructed_sql = ""
        param = request.param_value

        if request.endpoint == "user_lookup":
            # Deliberately vulnerable string interpolation for SQLi demonstration
            constructed_sql = (
                f"SELECT id, username, role, email FROM users WHERE username = '{param}'"  # nosec B608
            )
        elif request.endpoint == "product_search":
            constructed_sql = (
                f"SELECT id, name, description, price FROM products WHERE name LIKE '%{param}%'"  # nosec B608
            )
        elif request.endpoint == "auth_login":
            constructed_sql = (
                f"SELECT id, username, role FROM users WHERE username = '{param}' "  # nosec B608
                "AND password_hash = 'dummy_hash'"
            )
        else:
            constructed_sql = f"SELECT * FROM users WHERE username = '{param}'"  # nosec B608

        conn = self.db.get_connection()
        cursor = conn.cursor()
        error_msg: str | None = None
        rows: list[dict[str, Any]] = []

        try:
            # Multi-statement execution if semicolon is present
            if ";" in constructed_sql:
                cursor.executescript(constructed_sql)
                # When executescript runs, fetch results from the first statement if possible
                rows = []
            else:
                cursor.execute(constructed_sql)
                rows = [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            error_msg = str(e)

        return LabQueryResult(
            raw_input=request.param_value,
            mode="insecure",
            endpoint=request.endpoint,
            constructed_sql=constructed_sql,
            executed_safely=False,
            rows_returned=rows,
            row_count=len(rows),
            error_message=error_msg,
            detection_verdict=verdict,
        )

    def _execute_hardened(self, request: LabQueryRequest, verdict: Any) -> LabQueryResult:
        """Execute hardened handler utilizing prepared statements with bound parameters."""
        constructed_sql = ""
        params: tuple[Any, ...] = ()
        param = request.param_value

        if request.endpoint == "user_lookup":
            constructed_sql = "SELECT id, username, role, email FROM users WHERE username = ?"
            params = (param,)
        elif request.endpoint == "product_search":
            constructed_sql = "SELECT id, name, description, price FROM products WHERE name LIKE ?"
            params = (f"%{param}%",)
        elif request.endpoint == "auth_login":
            constructed_sql = (
                "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?"
            )
            params = (param, "dummy_hash")
        else:
            constructed_sql = "SELECT * FROM users WHERE username = ?"
            params = (param,)

        conn = self.db.get_connection()
        cursor = conn.cursor()
        error_msg: str | None = None
        rows: list[dict[str, Any]] = []

        try:
            cursor.execute(constructed_sql, params)
            rows = [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            error_msg = str(e)

        return LabQueryResult(
            raw_input=request.param_value,
            mode="hardened",
            endpoint=request.endpoint,
            constructed_sql=constructed_sql,
            executed_safely=True,
            rows_returned=rows,
            row_count=len(rows),
            error_message=error_msg,
            detection_verdict=verdict,
        )
