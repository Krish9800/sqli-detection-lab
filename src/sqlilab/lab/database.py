"""In-memory SQLite database environment pre-seeded for SQL injection simulations."""

import sqlite3
from typing import Any


class LabDatabase:
    """Manages an isolated in-memory SQLite database populated with test fixtures."""

    def __init__(self) -> None:
        """Initialize and seed the SQLite in-memory database."""
        self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self.reset_and_seed()

    def get_connection(self) -> sqlite3.Connection:
        """Return the active SQLite database connection."""
        return self._connection

    def reset_and_seed(self) -> None:
        """Wipe and re-seed all tables with standard lab entities."""
        cursor = self._connection.cursor()

        # Drop existing tables
        cursor.executescript(
            """
            DROP TABLE IF EXISTS accounts;
            DROP TABLE IF EXISTS products;
            DROP TABLE IF EXISTS users;
            """
        )

        # Create schema
        cursor.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL
            );

            CREATE TABLE products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL,
                stock INTEGER NOT NULL
            );

            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                balance REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )

        # Populate users
        users_data = [
            ("admin", "sha256$5e884898da2804", "admin", "admin@secops.local"),
            ("alice", "sha256$4b227777d4dd1f", "analyst", "alice@secops.local"),
            ("bob", "sha256$ef92b778bafe77", "engineer", "bob@secops.local"),
            ("charlie", "sha256$8c6976e5b54104", "auditor", "charlie@secops.local"),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            users_data,
        )

        # Populate products
        products_data = [
            ("Hardware Security Key", "FIDO2 authentication key", 55.00, 120),
            ("Packet Sniffer Device", "Dual-band USB packet monitor", 89.99, 45),
            ("Rubber Ducky Keystroke Injector", "Automated USB keyboard device", 69.95, 30),
            ("Network Tap Dual Gigabit", "Passive ethernet monitoring tap", 199.50, 15),
        ]
        cursor.executemany(
            "INSERT INTO products (name, description, price, stock) VALUES (?, ?, ?, ?)",
            products_data,
        )

        # Populate accounts
        accounts_data = [
            ("ACC-9001", 1, 95400.00),
            ("ACC-9002", 2, 4200.50),
            ("ACC-9003", 3, 12850.75),
            ("ACC-9004", 4, 3100.00),
        ]
        cursor.executemany(
            "INSERT INTO accounts (account_number, user_id, balance) VALUES (?, ?, ?)",
            accounts_data,
        )

        self._connection.commit()

    def execute_raw(self, sql: str) -> list[dict[str, Any]]:
        """Execute raw SQL statement and return rows as dictionary list."""
        cursor = self._connection.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        """Close database connection."""
        self._connection.close()
