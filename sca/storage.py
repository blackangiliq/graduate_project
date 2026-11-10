"""SQLite storage.

  scans            scan history (for trends)
  llm_cache        cached LLM answers, so repeating a scan does not repeat the model calls
  feedback         the reviewer's verdict on a finding (true positive / false positive)
  rule_candidates  rules proposed by the AI, with their validation report and status

The database lives in <project>/data/sca.db by default. Set the SCA_DATA_DIR environment
variable to store it somewhere else.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .models import Finding, ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    duration_seconds REAL,
    files_scanned INTEGER,
    lines_scanned INTEGER,
    score INTEGER,
    grade TEXT,
    critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, info INTEGER,
    result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS llm_cache (
    key TEXT PRIMARY KEY,
    answer_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    fingerprint TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    rule_ids TEXT NOT NULL,
    cwe TEXT, language TEXT, file TEXT, snippet TEXT, title TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_candidates (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    data_json TEXT NOT NULL
);
"""
VERDICTS = ("tp", "fp")


def data_dir() -> Path:
    override = os.environ.get("SCA_DATA_DIR")
    path = Path(override) if override else Path(__file__).resolve().parent.parent / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Storage:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self.path = str(db_path or data_dir() / "sca.db")
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ scans
    def save_scan(self, result: ScanResult) -> int:
        counts = result.counts()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (target, started_at, duration_seconds, files_scanned, "
                "lines_scanned, score, grade, critical, high, medium, low, info, result_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result.target, result.started_at, result.duration_seconds,
                 result.files_scanned, result.lines_scanned, result.score, result.grade,
                 counts["critical"], counts["high"], counts["medium"], counts["low"],
                 counts["info"], json.dumps(result.to_dict(), ensure_ascii=False)))
            result.scan_id = int(cursor.lastrowid)
        return result.scan_id

    def list_scans(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, target, started_at, duration_seconds, files_scanned, lines_scanned,"
                " score, grade, critical, high, medium, low, info FROM scans "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def load_scan(self, scan_id: int) -> Optional[ScanResult]:
        with self._connect() as conn:
            row = conn.execute("SELECT result_json FROM scans WHERE id = ?",
                               (scan_id,)).fetchone()
        if not row:
            return None
        data = json.loads(row["result_json"])
        return ScanResult(
            target=data["target"], started_at=data.get("started_at", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
            files_scanned=data.get("files_scanned", 0),
            lines_scanned=data.get("lines_scanned", 0), languages=data.get("languages", {}),
            engines_used=data.get("engines_used", []),
            engine_notes=data.get("engine_notes", {}),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            score=data.get("score", 100), grade=data.get("grade", "A"),
            ai=data.get("ai", {}), scan_id=scan_id)

    def delete_scan(self, scan_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    # ------------------------------------------------------------------ LLM cache
    def cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT answer_json FROM llm_cache WHERE key = ?",
                               (key,)).fetchone()
        return json.loads(row["answer_json"]) if row else None

    def cache_put(self, key: str, answer: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO llm_cache (key, answer_json) VALUES (?, ?)",
                         (key, json.dumps(answer, ensure_ascii=False)))

    # ------------------------------------------------------------------ reviewer feedback
    def set_feedback(self, finding: Finding, verdict: str) -> None:
        """Record the reviewer's verdict: 'tp' (real) or 'fp' (false positive)."""
        if verdict not in VERDICTS:
            raise ValueError("verdict must be 'tp' or 'fp'")
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO feedback (fingerprint, verdict, rule_ids, cwe, language,"
                " file, snippet, title, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (finding.fingerprint, verdict, json.dumps(finding.rule_ids or [finding.rule_id]),
                 finding.cwe, finding.language, finding.file, finding.snippet, finding.title,
                 _now()))

    def clear_feedback(self, fingerprint: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM feedback WHERE fingerprint = ?", (fingerprint,))

    def feedback_rows(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM feedback ORDER BY created_at DESC").fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["rule_ids"] = json.loads(item["rule_ids"] or "[]")
            out.append(item)
        return out

    def feedback_map(self) -> Dict[str, str]:
        return {row["fingerprint"]: row["verdict"] for row in self.feedback_rows()}

    def rule_stats(self) -> Dict[str, Dict[str, int]]:
        """How often each rule was confirmed (tp) or dismissed (fp) by the reviewer."""
        stats: Dict[str, Dict[str, int]] = {}
        for row in self.feedback_rows():
            for rule_id in row["rule_ids"]:
                entry = stats.setdefault(rule_id, {"tp": 0, "fp": 0})
                entry[row["verdict"]] += 1
        return stats

    # ------------------------------------------------------------------ rule candidates
    def save_candidate(self, candidate: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO rule_candidates (id, status, created_at, data_json) "
                "VALUES (?, ?, ?, ?)",
                (candidate["id"], candidate["status"], candidate.get("created_at") or _now(),
                 json.dumps(candidate, ensure_ascii=False)))

    def get_candidate(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT data_json, status FROM rule_candidates WHERE id = ?",
                               (candidate_id,)).fetchone()
        if not row:
            return None
        candidate = json.loads(row["data_json"])
        candidate["status"] = row["status"]
        return candidate

    def list_candidates(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT data_json, status FROM rule_candidates"
        args: Tuple = ()
        if status:
            query += " WHERE status = ?"
            args = (status,)
        with self._connect() as conn:
            rows = conn.execute(query + " ORDER BY created_at DESC, id", args).fetchall()
        out = []
        for row in rows:
            candidate = json.loads(row["data_json"])
            candidate["status"] = row["status"]
            out.append(candidate)
        return out

    def set_candidate_status(self, candidate_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE rule_candidates SET status = ? WHERE id = ?",
                         (status, candidate_id))
