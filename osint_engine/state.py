"""Persistent SQLite + JSON checkpointing state manager for OSINT sessions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_session_id(subject: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in subject.lower()).strip("-")[:32]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{slug or 'investigation'}-{stamp}"


class SessionStore:
    """Manages persistent research state, deduplication, budgets, and checkpoints."""

    def __init__(self, session_dir: Path) -> None:
        self.session_dir = session_dir
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.session_dir / "state.db"
        self.checkpoint_path = self.session_dir / "checkpoint.json"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS searches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_hash TEXT UNIQUE NOT NULL,
                provider TEXT NOT NULL,
                query TEXT NOT NULL,
                status TEXT NOT NULL,
                result_count INTEGER DEFAULT 0,
                executed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                title TEXT DEFAULT '',
                source_type TEXT DEFAULT 'web',
                published_date TEXT DEFAULT '',
                accessed_at TEXT NOT NULL,
                collector TEXT NOT NULL,
                snippet TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                attributes_json TEXT DEFAULT '{}',
                discovered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rel_key TEXT UNIQUE NOT NULL,
                source_entity TEXT NOT NULL,
                relation TEXT NOT NULL,
                target_entity TEXT NOT NULL,
                evidence_url TEXT DEFAULT '',
                confidence TEXT DEFAULT 'MODERATE',
                discovered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_hash TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                claim TEXT NOT NULL,
                is_fact INTEGER DEFAULT 1,
                confidence TEXT NOT NULL,
                rationale TEXT DEFAULT '',
                source_urls_json TEXT DEFAULT '[]',
                published_date TEXT DEFAULT '',
                accessed_at TEXT NOT NULL,
                conflicts_with TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lead_key TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                collector TEXT NOT NULL,
                depth INTEGER DEFAULT 1,
                priority INTEGER DEFAULT 5,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        self.conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def has_searched(self, provider: str, query: str) -> bool:
        qh = hashlib.sha256(f"{provider}:{query.strip().lower()}".encode()).hexdigest()
        row = self.conn.execute("SELECT 1 FROM searches WHERE query_hash=?", (qh,)).fetchone()
        return row is not None

    def record_search(self, provider: str, query: str, status: str, result_count: int = 0) -> bool:
        qh = hashlib.sha256(f"{provider}:{query.strip().lower()}".encode()).hexdigest()
        try:
            self.conn.execute(
                "INSERT INTO searches(query_hash, provider, query, status, result_count, executed_at) VALUES (?, ?, ?, ?, ?, ?)",
                (qh, provider, query, status, result_count, utc_now()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def search_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS c FROM searches").fetchone()
        return int(row["c"]) if row else 0

    def add_source(
        self,
        url: str,
        *,
        title: str = "",
        source_type: str = "web",
        published_date: str = "",
        collector: str = "unknown",
        snippet: str = "",
    ) -> bool:
        uh = hashlib.sha256(url.strip().encode()).hexdigest()
        try:
            self.conn.execute(
                """
                INSERT INTO sources(url_hash, url, title, source_type, published_date, accessed_at, collector, snippet)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (uh, url.strip(), title, source_type, published_date, utc_now(), collector, snippet[:1000]),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def add_entity(self, name: str, entity_type: str, attributes: dict[str, Any] | None = None) -> bool:
        ek = f"{entity_type.lower()}::{name.strip().lower()}"
        try:
            self.conn.execute(
                "INSERT INTO entities(entity_key, name, entity_type, attributes_json, discovered_at) VALUES (?, ?, ?, ?, ?)",
                (ek, name.strip(), entity_type, json.dumps(attributes or {}), utc_now()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def add_relationship(
        self,
        source_entity: str,
        relation: str,
        target_entity: str,
        *,
        evidence_url: str = "",
        confidence: str = "MODERATE",
    ) -> bool:
        rk = f"{source_entity.lower()}::{relation.lower()}::{target_entity.lower()}"
        try:
            self.conn.execute(
                """
                INSERT INTO relationships(rel_key, source_entity, relation, target_entity, evidence_url, confidence, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (rk, source_entity, relation, target_entity, evidence_url, confidence, utc_now()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def add_finding(
        self,
        *,
        category: str,
        claim: str,
        confidence: str,
        source_urls: list[str],
        rationale: str = "",
        is_fact: bool = True,
        published_date: str = "",
        conflicts_with: str = "",
    ) -> bool:
        fh = hashlib.sha256(f"{category}:{claim.strip().lower()}".encode()).hexdigest()
        try:
            self.conn.execute(
                """
                INSERT INTO findings(
                    finding_hash, category, claim, is_fact, confidence, rationale,
                    source_urls_json, published_date, accessed_at, conflicts_with
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fh,
                    category,
                    claim.strip(),
                    1 if is_fact else 0,
                    confidence,
                    rationale,
                    json.dumps(sorted(set(source_urls))),
                    published_date,
                    utc_now(),
                    conflicts_with,
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def add_lead(self, target: str, collector: str, depth: int = 1, priority: int = 5) -> bool:
        lk = f"{collector.lower()}::{target.strip().lower()}"
        try:
            self.conn.execute(
                "INSERT INTO leads(lead_key, target, collector, depth, priority, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                (lk, target.strip(), collector, depth, priority, utc_now()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def next_leads(self, max_depth: int = 2, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM leads WHERE status='pending' AND depth <= ? ORDER BY priority ASC, id ASC LIMIT ?",
            (max_depth, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_lead(self, lead_id: int, status: str) -> None:
        self.conn.execute("UPDATE leads SET status=? WHERE id=?", (status, lead_id))
        self.conn.commit()

    def export_snapshot(self) -> dict[str, Any]:
        snapshot = {
            "exported_at": utc_now(),
            "meta": {
                r["key"]: json.loads(r["value"])
                for r in self.conn.execute("SELECT key, value FROM meta").fetchall()
            },
            "searches": [dict(r) for r in self.conn.execute("SELECT * FROM searches ORDER BY id").fetchall()],
            "sources": [dict(r) for r in self.conn.execute("SELECT * FROM sources ORDER BY id").fetchall()],
            "entities": [dict(r) for r in self.conn.execute("SELECT * FROM entities ORDER BY id").fetchall()],
            "relationships": [
                dict(r) for r in self.conn.execute("SELECT * FROM relationships ORDER BY id").fetchall()
            ],
            "findings": [dict(r) for r in self.conn.execute("SELECT * FROM findings ORDER BY id").fetchall()],
            "leads": [dict(r) for r in self.conn.execute("SELECT * FROM leads ORDER BY id").fetchall()],
        }
        self.checkpoint_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        return snapshot
