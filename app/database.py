"""SQLite 持久化：分析版本、原始规则与分析结果。"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = os.environ.get("PREFIX_DB_PATH", str(Path(__file__).resolve().parent.parent / "data" / "prefix.db"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db_path() -> str:
    return DB_PATH


def get_connection() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id           TEXT PRIMARY KEY,
                name         TEXT,
                content_hash TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                request_json TEXT NOT NULL,
                result_json  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rules (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
                rule_index INTEGER NOT NULL,
                rule_id    TEXT NOT NULL,
                cidr       TEXT NOT NULL,
                version    INTEGER NOT NULL,
                action     TEXT NOT NULL,
                priority   INTEGER NOT NULL,
                source     TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_rules_analysis ON rules(analysis_id);
            CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at);
            """
        )


def save_analysis(
    analysis_id: str,
    name: str | None,
    content_hash: str,
    request_payload: dict[str, Any],
    result: dict[str, Any],
) -> None:
    """在单个事务中保存分析版本及其规则。"""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO analyses (id, name, content_hash, created_at, request_json, result_json)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                analysis_id,
                name,
                content_hash,
                _now(),
                json.dumps(request_payload, ensure_ascii=False, sort_keys=True),
                json.dumps(result, ensure_ascii=False, sort_keys=True),
            ),
        )
        rows = [
            (
                analysis_id,
                r["index"],
                r["id"],
                r["cidr"],
                r["version"],
                r["action"],
                r["priority"],
                r["source"],
            )
            for r in result["rules"]
        ]
        conn.executemany(
            "INSERT INTO rules (analysis_id, rule_index, rule_id, cidr, version,"
            " action, priority, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )


def _row_to_meta(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "rule_count": json.loads(row["result_json"])["summary"]["rule_count"],
        "content_hash": row["content_hash"],
        "created_at": row["created_at"],
    }


def list_analyses(limit: int, offset: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name, content_hash, created_at, result_json FROM analyses"
            " ORDER BY created_at DESC, id ASC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    items = []
    for row in rows:
        meta = _row_to_meta(row)
        meta["summary"] = json.loads(row["result_json"])["summary"]
        items.append(meta)
    return items


def count_analyses() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]


def get_analysis(analysis_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        **_row_to_meta(row),
        "request": json.loads(row["request_json"]),
        "result": json.loads(row["result_json"]),
    }


def get_analysis_rules(analysis_id: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT rule_index, rule_id, cidr, version, action, priority, source"
            " FROM rules WHERE analysis_id = ? ORDER BY rule_index",
            (analysis_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def delete_analysis(analysis_id: str) -> bool:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
        return cur.rowcount > 0
