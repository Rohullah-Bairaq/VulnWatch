"""SQLite connection helpers and the small VulnWatch schema."""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DEFAULT_DATABASE = Path(__file__).resolve().parents[2] / "data" / "vulnwatch.db"


def database_path() -> Path:
    """Return the configured database location, creating its parent folder."""
    path = Path(os.environ.get("VULNWATCH_DB_PATH", str(DEFAULT_DATABASE)))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """Open a connection that commits on success and always closes."""
    connection = sqlite3.connect(database_path(), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    """Create the application tables if this is the first run."""
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip_address TEXT NOT NULL UNIQUE,
                hostname TEXT,
                operating_system TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS cve_intelligence (
                cve_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                cvss_score REAL,
                severity TEXT NOT NULL DEFAULT 'Unknown',
                published_at TEXT,
                modified_at TEXT,
                nvd_url TEXT NOT NULL,
                imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                cvss_score REAL,
                severity TEXT NOT NULL DEFAULT 'Unknown'
                    CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Unknown')),
                asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
                status TEXT NOT NULL DEFAULT 'Open'
                    CHECK (status IN ('Open', 'In Progress', 'Resolved')),
                discovered_date TEXT NOT NULL,
                remediation_notes TEXT NOT NULL DEFAULT '',
                verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS asset_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL,
                service_name TEXT NOT NULL DEFAULT '',
                product TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                UNIQUE (asset_id, protocol, port)
            );
            """
        )


def row_dict(row: sqlite3.Row | None) -> dict | None:
    """Convert SQLite's row object into a normal dictionary."""
    return dict(row) if row is not None else None
