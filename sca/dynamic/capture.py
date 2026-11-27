"""Bounded, real runtime observations from an explicitly selected Android process.

The event journal is the authoritative evidence. Runtime observation is deliberately
separate from vulnerability verdicts: a token or encryption key existing in memory
does not establish that it is exposed, live, unrestricted, or exploitable.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qsl, urlsplit

SCHEMA_VERSION = 1
AGENT = Path(__file__).parent / "agent" / "observer.bundle.js"
MAX_VALUE_CHARS = 262144
MAX_JOURNAL_BYTES = 16 << 20
MAX_REPORT_BYTES = 64 << 20
MAX_INVENTORY_BYTES = 32 << 20
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
_URL = re.compile(r"(?:https?|wss?)://[^\s<>\"'`\\\x00-\x1f]+", re.I)
_SENSITIVE = re.compile(r"authorization|cookie|api[-_]?key|token|secret|password|credential", re.I)
_LIMITATIONS = [
    "Only code executed during this capture is covered; startup alone does not exercise login or other screens.",
    "An observed key, token or endpoint is evidence of runtime use, not a vulnerability or proof of exploitability.",
    "Values are complete within the explicit event/value/journal budgets; omitted evidence is reported, never silently shortened.",
    "TLS validation and application integrity checks are unchanged. No pinning or root-detection bypass is performed.",
    "Flutter/native DNS and socket destinations may be visible without full URLs. Stripped or inlined TLS, QUIC and HTTP/2 header decoding are not covered.",
    "Only the selected process is instrumented; child processes and WebView renderer processes are outside this session.",
    "Native hooks cover the process architecture only; ARM translation on x86 does not guarantee access to translated native TLS or Dart code.",
    "Only readable complete decoded outputs and TLS chunks are classified; binary payloads and values split across chunks may not be reconstructed.",
    "Cipher.doFinal capture covers readable byte-array return values; output-buffer and ByteBuffer result variants are not reconstructed.",
    "Generated values may have no literal source location. Stack lines are runtime debug metadata, not asserted JADX source lines.",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CaptureOptions:
    package: str
    serial: str
    duration_seconds: float = 30
    spawn: bool = True
    frida_host: str = "127.0.0.1:37042"
    adb_path: str | None = None
    max_events: int = 10000
    stop_spawned_app: bool = True
    native_hooks: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.package, str) or not _PACKAGE.fullmatch(self.package):
            raise ValueError("A full Android package identifier is required")
        if not isinstance(self.serial, str) or not self.serial or len(self.serial) > 200 or re.search(r"[\s\x00-\x1f]", self.serial):
            raise ValueError("An explicit ADB serial without whitespace is required")
        if type(self.duration_seconds) not in (int, float) or not 1 <= self.duration_seconds <= 300:
            raise ValueError("Capture duration must be between 1 and 300 seconds")
        if type(self.max_events) is not int or not 1 <= self.max_events <= 10000:
            raise ValueError("Event limit must be between 1 and 10000")
        if type(self.spawn) is not bool or type(self.stop_spawned_app) is not bool or type(self.native_hooks) is not bool:
            raise ValueError("Spawn and cleanup choices must be booleans")
        if not isinstance(self.frida_host, str):
            raise ValueError("A loopback Frida host:port is required")
        host, separator, port = self.frida_host.rpartition(":")
        try:
            local = host == "localhost" or ipaddress.ip_address(host.strip("[]")).is_loopback
        except ValueError:
            local = False
        if not separator or not local or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Frida must use an explicit loopback host:port forwarded to the selected device")


def _valid_event(raw: Any) -> dict | None:
    if not isinstance(raw, dict) or raw.get("type") != "observation":
        return None
    value = raw.get("value")
    if not isinstance(value, str) or not value or len(value) > MAX_VALUE_CHARS:
        return None
    if raw.get("kind") not in {"url", "host", "connection", "header", "crypto_key", "decoded_text", "transport_text"}:
        return None
    # Reject objects which cannot be represented losslessly in the JSON journal.
    try:
        event = json.loads(json.dumps(raw, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError):
        return None
    if not isinstance(event.get("details", {}), dict) or not isinstance(event.get("stack", []), list):
        return None
    event["stack"] = [frame for frame in event.get("stack", []) if isinstance(frame, dict)][:64]
    return event


def evidence_lines(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Exactly the JSONL lines written by run_capture; values are not redacted."""
    return tuple(json.dumps(event, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                 for event in report.get("events", []))


def validate_capture(capture: Any) -> dict:
    """Validate a locally produced/imported report without trusting external paths.

    Imported reports remain reported observations; this function establishes shape,
    consistency and resource limits, not the authenticity of an external capture.
    """
    if not isinstance(capture, dict) or type(capture.get("schema_version")) is not int or capture["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Unsupported dynamic capture schema")
    try:
        serialized = json.dumps(capture, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(serialized.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError("Dynamic report exceeds its size budget")
        result = json.loads(serialized)
    except (TypeError, OverflowError, RecursionError) as exc:
        raise ValueError("Dynamic report must be finite JSON data") from exc
    for name in ("session_id", "package", "serial", "started_at", "ended_at", "status"):
        if not isinstance(result.get(name), str) or not result[name] or len(result[name]) > 250:
            raise ValueError(f"Invalid dynamic capture field: {name}")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", result["session_id"]):
        raise ValueError("Invalid dynamic session identifier")
    if not _PACKAGE.fullmatch(result["package"]):
        raise ValueError("Invalid Android package identifier")
    if result["status"] not in {"completed", "partial", "failed"}:
        raise ValueError("Invalid capture status")
    for name in ("events", "observations", "capabilities", "errors", "limitations"):
        if not isinstance(result.get(name), list):
            raise ValueError(f"Dynamic capture {name} must be an array")
    if len(result["events"]) > 10000 or len(result["observations"]) > 30000:
        raise ValueError("Dynamic capture contains too many records")
    ids = set()
    for event in result["events"]:
        if _valid_event(event) is None or type(event.get("id")) is not int or event["id"] < 1 or event["id"] in ids:
            raise ValueError("Invalid or duplicate dynamic event")
        if "session_id" in event and event["session_id"] != result["session_id"]:
            raise ValueError("Event belongs to a different session")
        ids.add(event["id"])
    evidence_file = f"_runtime/{result['session_id']}/events.jsonl"

    def evidence(item: Any) -> int:
        if not isinstance(item, dict) or item.get("file") != evidence_file or type(item.get("line")) is not int or not 1 <= item["line"] <= len(result["events"]):
            raise ValueError("Runtime evidence must reference a retained journal event")
        return result["events"][item["line"] - 1]["id"]

    for observation in result["observations"]:
        if not isinstance(observation, dict) or observation.get("kind") not in {"url", "host", "connection", "credential", "crypto_key"}:
            raise ValueError("Invalid runtime observation")
        if not isinstance(observation.get("value"), str) or not 1 <= len(observation["value"]) <= MAX_VALUE_CHARS:
            raise ValueError("Invalid observation value")
        if not isinstance(observation.get("event_ids"), list) or not observation["event_ids"] or any(type(event_id) is not int or event_id not in ids for event_id in observation["event_ids"]):
            raise ValueError("Observation must reference its retained event IDs")
        referenced = observation["event_ids"]
        if len(set(referenced)) != len(referenced) or evidence(observation.get("evidence")) != referenced[0]:
            raise ValueError("Observation event IDs and primary journal location disagree")
        evidence_locations = observation.get("evidence_locations", [])
        if not isinstance(evidence_locations, list) or [evidence(item) for item in evidence_locations] != referenced:
            raise ValueError("Observation event IDs and journal locations disagree")
        if type(observation.get("occurrence_count")) is not int or observation["occurrence_count"] != len(referenced):
            raise ValueError("Observation occurrence count disagrees with retained events")
        if not isinstance(observation.get("locations", []), list):
            raise ValueError("Observation source locations must be an array")
        for location in observation.get("locations", []):
            if not isinstance(location, dict) or not isinstance(location.get("file"), str) or type(location.get("line")) is not int or location["line"] < 1:
                raise ValueError("Invalid source location")
            path = location["file"].replace("\\", "/")
            if path.startswith("/") or ":" in path or ".." in path.split("/"):
                raise ValueError("Source location must be a relative decoded-file key")
            if location.get("relation") not in {"exact_literal", "class_method"} or type(location.get("verified")) is not bool:
                raise ValueError("Invalid source relationship")
            if location["relation"] == "class_method" and location["verified"]:
                raise ValueError("Class/method context is not an exact source location")
        if observation.get("vulnerability_confirmed") is not False:
            raise ValueError("Runtime observations must not assert unverified vulnerability verdicts")
    for capability in result["capabilities"]:
        if not isinstance(capability, dict) or not isinstance(capability.get("name"), str) or type(capability.get("available")) is not bool:
            raise ValueError("Invalid capability record")
    if any(not isinstance(item, (dict, str)) for item in result["errors"]) or any(not isinstance(item, str) for item in result["limitations"]):
        raise ValueError("Invalid error or coverage metadata")
    if not isinstance(result.get("artifacts", {}), dict):
        raise ValueError("Invalid artifact metadata")
    return result


def _secrets_in_text(value: str) -> list[tuple[str, str, str, str]]:
    # Reuse the existing provider/imported rules and public-fixture classification.
    from ..engines.secrets import scan_file
    from ..walker import SourceFile
    source = SourceFile(Path("runtime.txt"), "runtime.txt", "config", value, origin="runtime")
    scan_file(source)
    return [(secret, rule, title, severity) for _, rule, secret, title, severity in source.secret_hits]


def _json_credentials(value: str) -> Iterable[tuple[str, str]]:
    try:
        obj = json.loads(value)
    except (ValueError, TypeError, RecursionError):
        return
    pending = [(obj, 0)]
    visited = 0
    while pending and visited < 10000:
        current, depth = pending.pop()
        visited += 1
        if depth > 20:
            continue
        if isinstance(current, dict):
            for key, child in current.items():
                if isinstance(child, str) and child and _SENSITIVE.search(str(key)):
                    yield str(key), child
                if isinstance(child, (dict, list)):
                    pending.append((child, depth + 1))
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current if isinstance(child, (dict, list)))


def _is_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return parsed.scheme.lower() in {"http", "https", "ws", "wss"} and bool(parsed.hostname)
    except ValueError:
        return False


def _is_host(value: str) -> bool:
    """Reject NUL padding, unrelated native memory, controls and malformed names."""
    if not value or value != value.strip() or len(value) > 253 or "\ufffd" in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ascii_host = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return bool(ascii_host) and len(ascii_host) <= 253 and all(
        re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label)
        for label in ascii_host.split("."))


def _source_lines(file: Any) -> Iterable[str]:
    return file.get("lines", ()) if isinstance(file, dict) else getattr(file, "lines", ())


def _correlate(observations: list[dict], decoded_files: Mapping[str, Any], limitations: list[str]) -> None:
    """Match exact literals in retained source; never invent a decompiler line."""
    if not decoded_files or not observations:
        return
    by_value: dict[str, list[dict]] = {}
    for item in observations:
        value = item["value"]
        # Short tokens/IP bytes match too many unrelated source literals to be useful.
        if len(value) >= 6 and "\n" not in value and len(value) <= 16384:
            by_value.setdefault(value, []).append(item)
    values: list[str] = []
    characters = 0
    for value in sorted(by_value, key=len, reverse=True):
        if characters + len(value) > 500000:
            limitations.append("Exact source correlation exceeded its 500000-character search budget; remaining values retain runtime evidence only.")
            break
        values.append(value)
        characters += len(value)
    pattern = re.compile("|".join(re.escape(value) for value in values)) if values else None
    matching = set(values)
    clipped = False
    for filename, file in decoded_files.items():
        if not pattern:
            break
        for number, line in enumerate(_source_lines(file), 1):
            if not isinstance(line, str):
                continue
            if not pattern.search(line):
                continue
            # Alternation alone consumes nested host/token matches inside a URL.
            # Search each retained literal on candidate lines to preserve overlaps.
            for value in matching:
                offset = line.find(value)
                while offset >= 0:
                    for item in by_value[value]:
                        if len(item["locations"]) >= 50:
                            clipped = True
                            continue
                        item["locations"].append({"file": str(filename), "line": number,
                            "column": offset + 1, "end_column": offset + len(value) + 1,
                            "relation": "exact_literal", "verified": True,
                            "note": "Exact value occurs here; this alone does not establish which runtime call produced it."})
                    offset = line.find(value, offset + 1)
    if clipped:
        limitations.append("Source matches are limited to 50 locations per observation; runtime evidence remains complete.")
    # Class mapping is useful navigation context, but a Java debug line may differ
    # entirely from the generated JADX source line. Never label it an exact site.
    names = [(str(name).replace("\\", "/"), name) for name in decoded_files]
    for item in observations:
        if item["locations"]:
            continue
        for frame in item.get("stack", []):
            classname = str(frame.get("class_name", "")).split("$")[0]
            method = str(frame.get("method", ""))
            if not classname or not method or method.startswith("<"):
                continue
            suffixes = [classname.replace(".", "/") + extension for extension in (".java", ".kt")]
            candidates = [name for normalized, name in names if any(normalized.endswith(suffix) for suffix in suffixes)]
            if len(candidates) != 1:
                continue
            name = candidates[0]
            method_pattern = re.compile(r"\b" + re.escape(method) + r"\s*\(")
            for number, line in enumerate(_source_lines(decoded_files[name]), 1):
                if method_pattern.search(line) and ("{" in line or re.search(r"\b(public|private|protected|fun)\b", line)):
                    item["locations"].append({"file": str(name), "line": number, "column": 0, "end_column": 0,
                        "relation": "class_method", "verified": False,
                        "note": "Class/method navigation context only; the exact executed instruction is not mapped."})
                    break
            if item["locations"]:
                break


def analyze_events(events: Iterable[Mapping[str, Any]], decoded_files: Mapping[str, Any] | None = None,
                   *, session_id: str = "imported", limitations: list[str] | None = None) -> list[dict]:
    """Derive inventories from observed values, with raw-event provenance for every item."""
    warnings = limitations if limitations is not None else []
    observations: dict[tuple[str, str], dict] = {}
    secret_cache: dict[str, list[tuple[str, str, str, str]]] = {}
    for number, raw in enumerate(events, 1):
        event = _valid_event(dict(raw))
        if event is None:
            warnings.append(f"Event {number} was invalid or exceeded the explicit value budget.")
            continue
        value, kind = event["value"], event["kind"]
        evidence = {"file": f"_runtime/{session_id}/events.jsonl", "line": number}
        details = event.get("details", {})

        def add(item_kind: str, item_value: str, label: str, confidence: str = "observed", **extra: Any) -> None:
            key = item_kind, item_value
            if key in observations:
                item = observations[key]
                if event.get("id", number) not in item["event_ids"]:
                    item["event_ids"].append(event.get("id", number))
                    item["evidence_locations"].append(evidence)
                    item["occurrence_count"] += 1
                # Specific provider recognition enriches a semantic header candidate.
                if extra.get("rule_id"):
                    item["details"].update(extra)
                    item["label"] = label
                return
            observations[key] = {
                "id": hashlib.sha256((item_kind + "\0" + item_value).encode()).hexdigest()[:20],
                "kind": item_kind, "value": item_value, "label": label, "confidence": confidence,
                "event_ids": [event.get("id", number)], "locations": [], "evidence": evidence,
                "evidence_locations": [evidence], "occurrence_count": 1,
                "api": event.get("api", ""), "stack": event.get("stack", []),
                "timestamp": event.get("timestamp", ""), "pid": event.get("pid"), "tid": event.get("tid"),
                "details": {**details, **extra}, "vulnerability_confirmed": False,
            }

        if kind == "url" and _is_url(value):
            add("url", value, "Runtime URL")
        elif kind == "host":
            if _is_host(value):
                add("host", value, "Runtime host")
            else:
                warnings.append(f"Invalid host value in runtime event {number}; retained as raw evidence, excluded from host inventory.")
        elif kind == "connection":
            add("connection", value, "Socket destination (attempt)")
        elif kind == "crypto_key":
            add("crypto_key", value, "Runtime cryptographic key", encoding=details.get("encoding", "hex"),
                assessment="Key material was observed in process memory; key exposure or insecurity is not established.")
        elif kind == "header":
            add("credential", value, f"Runtime header: {details.get('name', 'credential')}", "candidate",
                assessment="Observed header value; authentication validity and exploitability are untested.")

        if kind in {"url", "decoded_text", "transport_text"}:
            for match in _URL.finditer(value):
                url = match.group(0)
                if _is_url(url):
                    add("url", url, "Runtime URL")
                    for name, parameter in parse_qsl(urlsplit(url).query, keep_blank_values=False):
                        if parameter and _SENSITIVE.search(name):
                            add("credential", parameter, f"Runtime URL parameter: {name}", "candidate",
                                parameter=name, derivation="URL percent-decoded parameter")
            for name, credential in _json_credentials(value):
                add("credential", credential, f"Runtime JSON field: {name}", "candidate", field=name)
        if kind == "transport_text":
            header_block, _, body = value.partition("\r\n\r\n")
            for line in header_block.splitlines()[1:]:
                name, separator, header_value = line.partition(":")
                if separator and _SENSITIVE.search(name):
                    add("credential", header_value.strip(), f"Runtime HTTP header: {name}", "candidate", header=name)
            if body:
                for name, credential in _json_credentials(body):
                    add("credential", credential, f"Runtime JSON field: {name}", "candidate", field=name)
            request = re.match(r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]\r?\n", value)
            host = re.search(r"(?im)^Host:\s*([^\r\n]+)", header_block)
            if request and host and request.group(1).startswith("/"):
                url = "https://" + host.group(1).strip() + request.group(1)
                if _is_url(url):
                    add("url", url, "Runtime HTTP request URL", derivation="TLS HTTP/1 request target + Host header")
        if kind not in {"host", "connection", "crypto_key"}:
            if value not in secret_cache:
                secret_cache[value] = _secrets_in_text(value)
            for secret, rule, title, severity in secret_cache[value]:
                add("credential", secret, title.replace("Hard-coded", "Observed"), "candidate",
                    rule_id=rule, static_rule_severity=severity,
                    assessment="Recognized credential format in runtime data; not proof of validity, exposure or exploitability.")
    result = list(observations.values())
    _correlate(result, decoded_files or {}, warnings)
    retained, total = [], 0
    for item in result:
        size = len(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        if total + size > MAX_INVENTORY_BYTES:
            warnings.append(f"Derived inventory budget {MAX_INVENTORY_BYTES} bytes reached; {len(result) - len(retained)} inventory entries omitted. Retained raw events remain complete.")
            break
        retained.append(item)
        total += size
    return retained


def _verify_forward(options: CaptureOptions) -> None:
    from .environment import find_adb
    adb = find_adb(options.adb_path)
    if not adb:
        raise RuntimeError("ADB is required to verify that the Frida forward belongs to the selected device")
    port = options.frida_host.rsplit(":", 1)[1]
    listed = subprocess.run([adb, "forward", "--list"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    expected = (options.serial, "tcp:" + port, "tcp:27042")
    if listed.returncode or not any(tuple(line.split()) == expected for line in listed.stdout.splitlines()):
        raise RuntimeError("Frida forwarding does not match the selected device and port; reconnect the selected Android lab")


def _frida_call(frida: Any, function: Callable[[], Any], timeout: float = 20) -> Any:
    """Frida's native asynchronous operations honor the current Cancellable."""
    cancellable = frida.Cancellable()
    timer = threading.Timer(timeout, cancellable.cancel)
    timer.daemon = True
    timer.start()
    try:
        with cancellable:
            result = function()
        if cancellable.is_cancelled:
            raise TimeoutError(f"Frida operation exceeded {timeout:g} seconds")
        return result
    except Exception as exc:
        if cancellable.is_cancelled:
            raise TimeoutError(f"Frida operation exceeded {timeout:g} seconds") from exc
        raise
    finally:
        timer.cancel()


def _agent_source(native_hooks: bool) -> str:
    """Configure the packaged Frida agent without invalidating byte-count headers."""
    source = AGENT.read_text(encoding="utf-8")
    enabled, disabled = "SCA_NATIVE_HOOKS_ENABLED_1", "SCA_NATIVE_HOOKS_ENABLED_0"
    if not native_hooks:
        if enabled not in source:
            raise RuntimeError("The observer bundle does not support native-hook configuration; rebuild the agent")
        source = source.replace(enabled, disabled)
    return source


def _running_pid(frida: Any, device: Any, package: str, options: CaptureOptions | None = None,
                 diagnostics: dict | None = None) -> int:
    """Resolve app identity independently of foreground/application-manager state.

    Android/Frida can report an application pid of zero while its process exists
    behind a permission dialog. A fallback requires three corroborating facts:
    exact pidof result, exact /proc cmdline, and the PID in Frida's process list.
    """
    metadata = diagnostics if diagnostics is not None else {}
    try:
        applications = _frida_call(frida, lambda: device.enumerate_applications(identifiers=[package]))
        matches = sorted({app.pid for app in applications if app.identifier == package and app.pid > 0})
        if len(matches) == 1:
            metadata.update(method="frida_application_identifier", pid=matches[0])
            return matches[0]
        metadata["application_pid_candidates"] = matches
    except Exception as exc:
        metadata["application_query_error"] = f"{type(exc).__name__}: {exc}"
    if options is not None:
        from .environment import find_adb
        adb = find_adb(options.adb_path)
        if adb:
            def read(args: list[str]) -> subprocess.CompletedProcess:
                return subprocess.run([adb, "-s", options.serial, "shell", *args], capture_output=True,
                    timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                listed = read(["pidof", package])
                candidates = [int(word) for word in listed.stdout.split() if re.fullmatch(rb"[1-9][0-9]{0,8}", word)] if listed.returncode == 0 else []
                matches = []
                for pid in sorted(set(candidates))[:32]:
                    command = read(["cat", f"/proc/{pid}/cmdline"])
                    # Native cmdline is NUL-separated argv, not a printable process
                    # label. Exact first-argument identity excludes :service children.
                    if command.returncode == 0 and command.stdout.split(b"\0", 1)[0] == package.encode("utf-8"):
                        matches.append(pid)
                processes = _frida_call(frida, device.enumerate_processes) if matches else []
                visible = {process.pid for process in processes}
                matches = [pid for pid in matches if pid in visible]
                metadata["verified_native_pid_candidates"] = matches
                if len(matches) == 1:
                    metadata.update(method="adb_pidof_proc_cmdline_and_frida_process", pid=matches[0])
                    return matches[0]
            except (OSError, subprocess.TimeoutExpired) as exc:
                metadata["native_process_query_error"] = f"{type(exc).__name__}: {exc}"
    raise RuntimeError("The selected Android package has no uniquely verified running process; launch it in the lab first")


def run_capture(options: CaptureOptions, output_dir: str | Path,
                decoded_files: Mapping[str, Any] | None = None,
                progress: Callable[[dict], None] | None = None) -> dict:
    """Capture startup/attached-process activity; never fabricate unavailable evidence.

    Caller must forward options.frida_host to options.serial and install the package.
    A dedicated test device/emulator is expected. The ordinary launcher fallback
    can start the selected application; device setup is handled by the caller.
    """
    session_id = uuid.uuid4().hex
    directory = Path(output_dir).resolve() / session_id
    directory.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "session_id": session_id,
        "package": options.package, "serial": options.serial, "options": asdict(options),
        "started_at": _now(), "ended_at": None, "status": "failed", "pid": None,
        "events": [], "observations": [], "capabilities": [], "errors": [],
        "limitations": list(_LIMITATIONS), "detached_reason": None,
        "coverage": {"profile": "startup" if options.spawn else "attached_process", "ui_exploration": False,
            "requested_seconds": options.duration_seconds, "observed_seconds": 0,
            "native_hooks_requested": options.native_hooks},
        "artifacts": {"events_file": str(directory / "events.jsonl"), "report_file": str(directory / "report.json")},
    }
    if not options.native_hooks:
        report["limitations"].append("Native DNS/socket/TLS observation hooks were explicitly disabled for this compatibility capture. Java observation remains enabled; the Frida Java bridge itself still uses native internals. This setting does not establish the cause of any previous crash.")
    lock = threading.Lock()
    detached = threading.Event()
    session = script = device = None
    resumed = False
    owns_spawn = False
    frida = None
    started = None
    closing = False
    size = 0
    limits: set[str] = set()
    journal = (directory / "events.jsonl").open("w", encoding="utf-8", newline="\n")

    def notify() -> None:
        if progress:
            try:
                progress({"session_id": session_id, "events": len(report["events"]),
                          "elapsed_seconds": round(time.monotonic() - started, 2) if started else 0,
                          "status": "capturing" if resumed else "starting"})
            except Exception:
                pass  # UI progress must never terminate or corrupt a capture.

    def on_message(message: dict, data: bytes | None) -> None:
        nonlocal size
        with lock:
            if closing:
                return
            if message.get("type") == "error":
                report["errors"].append({"stage": "agent", "message": message.get("description", "Agent error"),
                                         "stack": message.get("stack", "")})
                return
            if message.get("type") != "send":
                return
            raw = message.get("payload", {})
            if not isinstance(raw, dict):
                return
            if raw.get("type") == "capability":
                name = str(raw.get("name", "unknown"))
                item = {"name": name, "available": bool(raw.get("available")), "detail": str(raw.get("detail", ""))}
                report["capabilities"] = [entry for entry in report["capabilities"] if entry["name"] != name] + [item]
                if not item["available"] and name.startswith("hook_callback"):
                    error = {"stage": "hook", "api": name.partition(":")[2], "message": item["detail"]}
                    if error not in report["errors"]:
                        report["errors"].append(error)
                if not item["available"] and "limit" in name:
                    limits.add(item["detail"])
                return
            event = _valid_event(raw)
            if event is None:
                limits.add("An invalid or oversized event was rejected; rejected values are not represented as complete evidence.")
                return
            if len(report["events"]) >= options.max_events:
                limits.add(f"Event count limit {options.max_events} reached; later events omitted.")
                return
            event["id"] = len(report["events"]) + 1
            event["session_id"] = session_id
            encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            written = len(encoded.encode("utf-8")) + 1
            if size + written > MAX_JOURNAL_BYTES:
                limits.add(f"Journal limit {MAX_JOURNAL_BYTES} bytes reached; later events omitted.")
                return
            journal.write(encoded + "\n")
            journal.flush()
            size += written
            report["events"].append(event)

    def on_detached(reason: str, crash: Any = None) -> None:
        if not closing:
            report["detached_reason"] = str(reason)
            if crash is not None:
                report["errors"].append({"stage": "process", "message": str(crash)})
            detached.set()

    try:
        if not AGENT.is_file():
            raise RuntimeError("Compiled observer missing; run python -m sca.dynamic.build_agent after npm ci in sca/dynamic/agent")
        try:
            import frida
        except ImportError as exc:
            raise RuntimeError("Frida Python dependency missing; install requirements-dynamic.txt") from exc
        source = _agent_source(options.native_hooks)
        report["tool_versions"] = {"frida": frida.__version__,
            "agent_sha256": hashlib.sha256(AGENT.read_bytes()).hexdigest(),
            "configured_agent_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest()}
        _verify_forward(options)
        device = _frida_call(frida, lambda: frida.get_device_manager().add_remote_device(options.frida_host))
        if options.spawn:
            try:
                report["pid"] = _frida_call(frida, lambda: device.spawn([options.package]))
                owns_spawn = True
            except Exception as exc:
                report["errors"].append({"stage": "spawn", "type": type(exc).__name__, "message": str(exc)})
                from .environment import launch_target
                launch = launch_target(options.package, options.serial, options.adb_path)
                report["launch_fallback"] = launch
                if not launch.get("success"):
                    raise RuntimeError("Frida spawn and Android launcher fallback both failed") from exc
                report["process_resolution"] = {}
                report["pid"] = _running_pid(frida, device, options.package, options, report["process_resolution"])
                report["coverage"]["profile"] = "warm_launch_attach"
                report["limitations"].append("Frida spawn failed. Attached after an ordinary Android launch; initialization before attachment was not captured.")
        else:
            report["process_resolution"] = {}
            report["pid"] = _running_pid(frida, device, options.package, options, report["process_resolution"])
        session = _frida_call(frida, lambda: device.attach(report["pid"]))
        session.on("detached", on_detached)
        script = _frida_call(frida, lambda: session.create_script(source, name="sca-runtime-observer"))
        script.on("message", on_message)
        _frida_call(frida, script.load)
        if owns_spawn:
            _frida_call(frida, lambda: device.resume(report["pid"]))
        resumed = True
        started = time.monotonic()
        notify()
        while not detached.wait(min(0.25, max(0, options.duration_seconds - (time.monotonic() - started)))):
            if time.monotonic() - started >= options.duration_seconds:
                break
            notify()
        report["coverage"]["observed_seconds"] = round(time.monotonic() - started, 3)
        report["status"] = "partial" if detached.is_set() or report["errors"] or limits else "completed"
    except Exception as exc:
        report["errors"].append({"stage": "capture", "type": type(exc).__name__, "message": str(exc)})
        report["status"] = "partial" if resumed or report["events"] else "failed"
        if started:
            report["coverage"]["observed_seconds"] = round(time.monotonic() - started, 3)
    finally:
        # Stop recording before shutdown messages; intentional detach is not a crash.
        with lock:
            closing = True
            journal.close()
        if script is not None and not detached.is_set():
            try:
                _frida_call(frida, script.unload, timeout=5)
            except Exception:
                pass
        if session is not None:
            try:
                _frida_call(frida, session.detach, timeout=5)
            except Exception:
                pass
        if device is not None and owns_spawn and options.stop_spawned_app and report["pid"]:
            try:
                _frida_call(frida, lambda: device.kill(report["pid"]), timeout=5)
            except Exception:
                pass
        report["limitations"].extend(sorted(limits))
        if limits and report["status"] == "completed":
            report["status"] = "partial"
        report["ended_at"] = _now()
        try:
            prior_warning_count = len(report["limitations"])
            report["observations"] = analyze_events(report["events"], decoded_files,
                session_id=session_id, limitations=report["limitations"])
            if any("budget" in warning for warning in report["limitations"][prior_warning_count:]):
                report["status"] = "partial" if report["status"] != "failed" else "failed"
            if any(warning.startswith("Invalid host") for warning in report["limitations"][prior_warning_count:]):
                report["status"] = "partial"
        except Exception as exc:
            report["errors"].append({"stage": "analysis", "type": type(exc).__name__, "message": str(exc)})
            report["status"] = "partial" if report["events"] else "failed"
        (directory / "report.json").write_text(json.dumps(report, ensure_ascii=False, separators=(",", ":"), allow_nan=False), encoding="utf-8")
    return report
