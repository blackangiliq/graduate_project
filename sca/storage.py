"""SQLite storage.

  scans            scan history (for trends)
  scan_evidence    compressed source snapshots and visible inventory of saved scans
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
import zlib
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
CREATE TABLE IF NOT EXISTS scan_evidence (
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS dynamic_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    package TEXT NOT NULL,
    serial TEXT NOT NULL,
    started_at TEXT NOT NULL,
    status TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    observation_count INTEGER NOT NULL,
    payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS dynamic_sessions_scan ON dynamic_sessions(scan_id, id);
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
MAX_ARCHIVE_EVIDENCE_BYTES = 128 << 20
MAX_DYNAMIC_SESSION_BYTES = 64 << 20
_EVIDENCE_NOTE = "archived evidence"


class _EvidenceError(ValueError):
    pass


def _encode_evidence(result: ScanResult) -> Optional[bytes]:
    """Versioned JSON only: no live paths, comparison state or executable serialization."""
    if not result.decoded_files and not result.visible_apis:
        return None
    from .decoded import validate_derivation

    def file_record(file):
        record = {"language": file.language, "origin": file.origin,
                  "source_line_count": file.source_line_count, "lines": file.lines}
        provenance = validate_derivation(file.derivation)
        if provenance:
            record["derivation"] = provenance
        return record

    data = {
        "version": 1,
        "decoded_files": {
            path: file_record(file)
            for path, file in result.decoded_files.items()},
        "visible_apis": result.visible_apis,
    }
    compressor = zlib.compressobj()
    compressed = bytearray()
    size = 0
    # Stream the JSON encoding so the byte limit also bounds serialization work.
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for text in encoder.iterencode(data):
        chunk = text.encode("utf-8")
        size += len(chunk)
        if size > MAX_ARCHIVE_EVIDENCE_BYTES:
            raise _EvidenceError("snapshot exceeds the archive size limit")
        compressed.extend(compressor.compress(chunk))
        if len(compressed) > MAX_ARCHIVE_EVIDENCE_BYTES:
            raise _EvidenceError("compressed snapshot exceeds the archive size limit")
    compressed.extend(compressor.flush())
    if len(compressed) > MAX_ARCHIVE_EVIDENCE_BYTES:
        raise _EvidenceError("compressed snapshot exceeds the archive size limit")
    return bytes(compressed)


def _decode_evidence(payload: bytes):
    """Bound decompression before parsing, then reconstruct only explicit snapshot fields."""
    from .decoded import DecodedFile, validate_derivation

    if not isinstance(payload, bytes) or len(payload) > MAX_ARCHIVE_EVIDENCE_BYTES:
        raise _EvidenceError("snapshot exceeds the archive size limit")
    inflater = zlib.decompressobj()
    raw = inflater.decompress(payload, MAX_ARCHIVE_EVIDENCE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_EVIDENCE_BYTES or inflater.unconsumed_tail:
        raise _EvidenceError("snapshot exceeds the archive size limit")
    if not inflater.eof or inflater.unused_data:
        raise _EvidenceError("snapshot compression is incomplete or invalid")
    data = json.loads(raw)
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise _EvidenceError("unsupported snapshot format")
    files, apis = data.get("decoded_files"), data.get("visible_apis")
    if not isinstance(files, dict) or not isinstance(apis, dict):
        raise _EvidenceError("invalid snapshot structure")
    previews = {}
    for path, file in files.items():
        if not isinstance(path, str) or not path or not isinstance(file, dict):
            raise _EvidenceError("invalid file snapshot")
        language, origin = file.get("language"), file.get("origin")
        count, lines = file.get("source_line_count"), file.get("lines")
        if (not isinstance(language, str) or not isinstance(origin, str)
                or type(count) is not int or not isinstance(lines, list)
                or count < len(lines) or not all(isinstance(line, str) for line in lines)):
            raise _EvidenceError("invalid file snapshot")
        derivation = validate_derivation(file.get("derivation", {}))
        previews[path] = DecodedFile(language, origin, count, tuple(lines), original=None,
                                     derivation=derivation)
    for field in ("keys", "endpoints", "hosts", "calls", "paths", "config", "env", "alerts"):
        rows = apis.get(field, [])
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise _EvidenceError("invalid inventory snapshot")
    for field in ("summary", "firebase", "truncated"):
        if not isinstance(apis.get(field, {}), dict):
            raise _EvidenceError("invalid inventory snapshot")
    return previews, apis


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
        try:
            evidence = _encode_evidence(result)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            evidence = None
            reason = str(exc) if isinstance(exc, _EvidenceError) else "invalid snapshot data"
            result.engine_notes[_EVIDENCE_NOTE] = "not saved: " + reason
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
            if evidence is not None:
                conn.execute("INSERT INTO scan_evidence (scan_id, payload) VALUES (?, ?)",
                             (result.scan_id, evidence))
        return result.scan_id

    def count_scans(self, search: str = "") -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM scans WHERE instr(lower(target), lower(?)) > 0",
                (search,)).fetchone()[0]

    def list_scans(self, limit: int = 100, *, search: str = "", offset: int = 0) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, target, started_at, duration_seconds, files_scanned, lines_scanned,"
                " score, grade, critical, high, medium, low, info FROM scans "
                "WHERE instr(lower(target), lower(?)) > 0 ORDER BY id DESC LIMIT ? OFFSET ?",
                (search, limit, offset)).fetchall()
        return [dict(row) for row in rows]

    def project_scores(self, target: str, limit: int = 200) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT started_at, score FROM scans WHERE target = ? "
                                "ORDER BY id DESC LIMIT ?", (target, limit)).fetchall()
        return [dict(row) for row in reversed(rows)]

    def load_scan(self, scan_id: int) -> Optional[ScanResult]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT s.result_json, LENGTH(e.payload) AS evidence_size, "
                "CASE WHEN LENGTH(e.payload) <= ? THEN e.payload END AS evidence_payload "
                "FROM scans AS s LEFT JOIN scan_evidence AS e ON e.scan_id = s.id WHERE s.id = ?",
                (MAX_ARCHIVE_EVIDENCE_BYTES, scan_id)).fetchone()
        if not row:
            return None
        data = json.loads(row["result_json"])
        result = ScanResult(
            target=data["target"], started_at=data.get("started_at", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
            files_scanned=data.get("files_scanned", 0),
            lines_scanned=data.get("lines_scanned", 0), languages=data.get("languages", {}),
            engines_used=data.get("engines_used", []),
            engine_notes=data.get("engine_notes", {}),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            score=data.get("score", 100), grade=data.get("grade", "A"),
            ai=data.get("ai", {}), app=data.get("app", {}), scan_id=scan_id)
        if row["evidence_size"] is not None:
            try:
                result.decoded_files, result.visible_apis = _decode_evidence(row["evidence_payload"])
            except (ValueError, TypeError, UnicodeError, RecursionError, zlib.error) as exc:
                reason = str(exc) if isinstance(exc, _EvidenceError) else "invalid snapshot data"
                result.engine_notes[_EVIDENCE_NOTE] = "unavailable: " + reason
        return result

    def delete_scan(self, scan_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM dynamic_sessions WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scan_evidence WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    def save_dynamic_session(self, scan_id: int, capture: dict) -> int:
        """Archive runtime evidence separately from static findings and AI inputs."""
        from .dynamic import validate_capture
        capture = validate_capture(capture)
        raw = json.dumps(capture, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_DYNAMIC_SESSION_BYTES:
            raise ValueError("Runtime session exceeds the archive size limit")
        with self._connect() as conn:
            if not conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone():
                raise ValueError("The associated static scan does not exist")
            cursor = conn.execute(
                "INSERT INTO dynamic_sessions (scan_id, session_id, package, serial, started_at, "
                "status, event_count, observation_count, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, str(capture.get("session_id", "")), str(capture.get("package", "")),
                 str(capture.get("serial", "")), str(capture.get("started_at", "")),
                 str(capture.get("status", "unknown")), len(capture.get("events", [])),
                 len(capture.get("observations", [])), zlib.compress(raw)))
            return int(cursor.lastrowid)

    def list_dynamic_sessions(self, scan_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        """Return compact session metadata; load evidence only when selected."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id AS capture_id, scan_id, session_id, package, serial, started_at, status, "
                "event_count, observation_count FROM dynamic_sessions WHERE scan_id = ? "
                "ORDER BY id DESC LIMIT ?", (scan_id, max(1, min(100, limit)))).fetchall()
        return [dict(row) for row in rows]

    def load_dynamic_session(self, capture_id: int, *, scan_id: int | None = None) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT scan_id, LENGTH(payload) AS payload_size, "
                "CASE WHEN LENGTH(payload) <= ? THEN payload END AS payload "
                "FROM dynamic_sessions WHERE id = ?",
                (MAX_DYNAMIC_SESSION_BYTES, capture_id)).fetchone()
        if row is None or (scan_id is not None and row["scan_id"] != scan_id):
            return None
        payload = row["payload"]
        if row["payload_size"] > MAX_DYNAMIC_SESSION_BYTES or payload is None:
            raise ValueError("Runtime session exceeds the archive size limit")
        inflater = zlib.decompressobj()
        raw = inflater.decompress(payload, MAX_DYNAMIC_SESSION_BYTES + 1)
        if (len(raw) > MAX_DYNAMIC_SESSION_BYTES or inflater.unconsumed_tail
                or not inflater.eof or inflater.unused_data):
            raise ValueError("Invalid or oversized runtime archive")
        from .dynamic import validate_capture
        capture = validate_capture(json.loads(raw))
        capture.update(capture_id=capture_id, scan_id=row["scan_id"])
        return capture

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
