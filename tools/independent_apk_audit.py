"""Independent static reference for a supplied APK corpus (no sca imports).

Uses Android SDK aapt2 for manifest/resource interpretation, the published DEX string
table format for literal strings, and direct byte searches for provider-format tokens.
Nothing in an APK is executed and no extracted address/credential is contacted.
The output is a candidate inventory, not proof that a credential works or a vulnerability
is exploitable. Exact values stay in the explicitly selected local output JSON.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import ipaddress
import re
import struct
import subprocess
import time
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


FORMATS = {
    "google-api-key": r"AIza[0-9A-Za-z_-]{35}",
    "aws-access-key-id": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "github-token": r"(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{70,100})",
    "stripe-secret-key": r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,200}",
    "slack-token": r"xox[baprs]-[A-Za-z0-9-]{10,200}",
    "sendgrid-key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "openai-shaped-key": r"(?:sk-[A-Za-z0-9]{48}|sk-(?:proj|svcacct)-[A-Za-z0-9_-]{80,200})",
    "private-key-marker": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}",
}
KEY_TEXT = [(kind, re.compile(r"(?<![A-Za-z0-9_])(" + pat + r")(?![A-Za-z0-9_])"))
            for kind, pat in FORMATS.items()]
KEY_BYTES = [(kind, re.compile(pat.encode("ascii"))) for kind, pat in FORMATS.items()]
URL = re.compile(r"(?:https?|wss?)://[^\s\x00-\x20<>\"'`\\]{3,4096}", re.I)
URL_BYTES = re.compile(rb"(?:https?|wss?)://[\x21-\x7e]{3,4096}", re.I)
RELATIVE = re.compile(r"(?:/|api/|v[1-9][0-9]*/)[A-Za-z0-9_./?=&{}%-]{1,500}\Z")
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")
PEM = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
                 rb"[\r\n]+([A-Za-z0-9+/=\r\n]{64,20000})-----END "
                 rb"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
QUOTED = re.compile(r'"(?:\\.|[^"\\])*"')
MAX_ENTRY_BYTES = 512 << 20
MAX_LOCATIONS = 100
SOURCE_DOCS = [
    "https://developer.android.com/tools/aapt2",
    "https://source.android.com/docs/core/runtime/dex-format",
]
DOC_HOSTS = ("github.com", "github.io", "w3.org", "w3c.org", "wikipedia.org", "ietf.org",
             "xml.org", "xmlpull.org", "apache.org", "opensource.org", "mozilla.org",
             "mozilla.com", "stackoverflow.com", "projectlombok.org", "jsoup.org", "slf4j.org",
             "developer.android.com", "developers.google.com", "cloud.google.com",
             "firebase.google.com", "support.google.com", "issuetracker.google.com",
             "android.googlesource.com", "cs.android.com", "bugs.chromium.org",
             "schemas.android.com", "schemas.microsoft.com", "ns.adobe.com", "ns.microsoft.com",
             "www.inkscape.org", "react.dev", "reactnative.dev", "docs.flutter.dev",
             "api.flutter.dev", "dart.dev", "docs.swmansion.com", "youtrack.jetbrains.com")


def address_category(item: dict) -> str:
    """Describe evidence, never label a literal URL as an observed network request."""
    value = item["value"]
    host = (urlsplit(value).hostname or "").lower()
    locations = item["locations"]
    metadata = re.compile(r"(?i)(?:public.suffix.list|changelog|changes|notices|licen[cs]e|readme|"
                          r"\.(?:proto|ttf|otf|woff2?|gif|png|jpe?g|svg|jks|cer|crt)$)")
    if locations and all(metadata.search(site.get("entry", "")) for site in locations):
        return "documentation_or_asset_metadata"
    if (host.startswith(("docs.", "developer.", "developers."))
            or any(host == h or host.endswith("." + h) for h in DOC_HOSTS)):
        return "documentation_or_namespace"
    if host == "www.googleapis.com" and urlsplit(value).path.startswith("/auth/"):
        return "oauth_scope_identifier"
    if host in {"example.com", "example.org", "example.net"} or host.startswith("example."):
        return "example_address"
    if "://" in value[value.find("://") + 3:]:
        return "concatenated_address_fragment"
    if any(marker in value for marker in ("%s", "%d", "${", "{", "}")):
        return "runtime_address_template"
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return "local_development_address"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}", host):
            return "unvalidated_address_fragment"
    return "literal_service_or_web_address"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def url_value(value: str) -> str | None:
    value = re.split(r"[<>\"'`\\]", value, 1)[0].rstrip(".,;!")
    for close, opening in ((")", "("), ("]", "["), ("}", "{")):
        while value.endswith(close) and value.count(close) > value.count(opening):
            value = value[:-1]
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
    except ValueError:
        return None
    if not host or not ("." in host or host == "localhost" or ":" in host):
        return None
    if any(ord(ch) < 33 for ch in host) or len(host) > 253:
        return None
    return value


def valid_key(kind: str, value: str) -> bool:
    if kind != "jwt":
        return True
    try:
        header, payload, _ = value.split(".")
        head = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
        body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return isinstance(head, dict) and isinstance(body, dict) and "alg" in head
    except (ValueError, UnicodeError):
        return False


class Inventory:
    def __init__(self, name: str):
        self.name = name
        self.keys: dict[tuple[str, str], dict] = {}
        self.urls: dict[str, dict] = {}
        self.paths: dict[str, dict] = {}
        self.manifests: list[dict] = []
        self.resources: list[dict] = []
        self.resource_xml: list[dict] = []
        self.pem_blocks: list[dict] = []
        self.entries: list[dict] = []
        self.apks: list[dict] = []
        self.limits: list[dict] = []
        self.stats = Counter()

    def add(self, bucket: dict, identity, value: str, location: dict, **fields) -> None:
        item = bucket.setdefault(identity, {"value": value, **fields, "occurrences": 0,
                                            "locations": []})
        item["occurrences"] += 1
        if len(item["locations"]) < MAX_LOCATIONS and location not in item["locations"]:
            item["locations"].append(location)

    def text(self, text: str, location: dict, *, source_bytes: bytes | None = None,
             byte_start: int = 0, include_paths: bool = False):
        def place(value: str, at: int) -> dict:
            out = dict(location)
            out["character_offset"] = at
            if source_bytes is not None:
                pos = source_bytes.find(value.encode("utf-8", "surrogatepass"))
                if pos >= 0:
                    out["byte_offset"] = byte_start + pos
            return out

        for kind, pattern in KEY_TEXT:
            for match in pattern.finditer(text):
                value = match[1]
                if valid_key(kind, value):
                    self.add(self.keys, (kind, value), value, place(value, match.start(1)),
                             kind=kind, status="format_candidate_not_remotely_validated")
        for match in URL.finditer(text):
            value = url_value(match[0])
            if value:
                self.add(self.urls, value, value, place(value, match.start()),
                         status="literal_address_not_runtime_endpoint_proof")
        if include_paths and RELATIVE.fullmatch(text.strip()):
            value = text.strip()
            self.add(self.paths, value, value, place(value, text.find(value)),
                     status="relative_path_candidate")

    def raw(self, data: bytes, location: dict, *, urls: bool):
        for match in PEM.finditer(data):
            try:
                decoded = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
            except ValueError:
                continue
            self.pem_blocks.append({"value": match[0].decode("ascii"),
                                    "location": {**location, "byte_offset": match.start()},
                                    "decoded_bytes": len(decoded), "starts_asn1_sequence": decoded[:1] == b"0",
                                    "status": "embedded_key_material_not_runtime_use_proof"})
        for kind, pattern in KEY_BYTES:
            for match in pattern.finditer(data):
                # Checking boundaries here preserves regex literal-prefix acceleration
                # on large native libraries, unlike a lookbehind at every byte.
                word = lambda byte: 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122 or byte == 95
                if ((match.start() and word(data[match.start() - 1]))
                        or (match.end() < len(data) and word(data[match.end()]))):
                    continue
                value = match[0].decode("ascii")
                if valid_key(kind, value):
                    self.add(self.keys, (kind, value), value,
                             {**location, "byte_offset": match.start(), "encoding": "ascii"},
                             kind=kind, status="format_candidate_not_remotely_validated")
        if urls:
            for match in URL_BYTES.finditer(data):
                value = url_value(match[0].decode("ascii"))
                if value:
                    self.add(self.urls, value, value,
                             {**location, "byte_offset": match.start(), "encoding": "ascii"},
                             status="raw_byte_address_candidate")

    def dex(self, data: bytes, location: dict):
        if len(data) < 112 or not data.startswith(b"dex\n"):
            self.limits.append({**location, "reason": "not_standard_dex"})
            return
        count, offset = struct.unpack_from("<II", data, 56)
        if count > 3_000_000 or offset + count * 4 > len(data):
            self.limits.append({**location, "reason": "invalid_dex_string_table"})
            return
        self.stats["dex_strings"] += count
        for index in range(count):
            start = struct.unpack_from("<I", data, offset + index * 4)[0]
            for _ in range(5):  # utf16_size ULEB128 is skipped; payload is NUL terminated.
                if start >= len(data):
                    break
                byte = data[start]
                start += 1
                if not byte & 128:
                    break
            end = data.find(b"\0", start)
            if end < 0 or end - start > 1 << 20:
                self.limits.append({**location, "reason": "invalid_or_large_dex_string",
                                    "string_index": index})
                continue
            raw = data[start:end]
            # ASCII token/address forms have identical encodings in UTF-8 and MUTF-8.
            if not any(marker in raw for marker in (b"://", b"AIza", b"AKIA", b"ASIA", b"gh",
                                                    b"sk-", b"sk_", b"rk_", b"xox", b"SG.",
                                                    b"PRIVATE KEY", b"eyJ")) \
                    and not raw.startswith((b"/", b"api/", b"v1/", b"v2/", b"v3/")):
                continue
            text = raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "replace")
            self.text(text, {**location, "origin": "dex_string_table", "string_index": index},
                      source_bytes=raw, byte_start=start, include_paths=True)

    def result(self):
        for item in self.urls.values():
            item["category"] = address_category(item)
        for item in self.keys.values():
            if item["kind"] == "private-key-marker":
                material = [block for block in self.pem_blocks if block["value"].startswith(item["value"])]
                item["status"] = ("private_key_header_with_material" if material
                                  else "header_marker_only_not_key_material")
                item["material_blocks"] = len(material)
            elif item["kind"] == "jwt":
                payload = item["value"].split(".")[1]
                claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                item["claim_names"] = list(claims)
                if set(claims) <= {"foo", "bar", "hello", "world"}:
                    item["status"] = "fixture_shaped_jwt_not_production_secret_proof"
        return {"name": self.name, "apks": self.apks,
                "keys": list(self.keys.values()), "urls": list(self.urls.values()),
                "paths": list(self.paths.values()), "manifest_facts": self.manifests,
                "named_resources": self.resources, "resource_xml": self.resource_xml,
                "pem_blocks": self.pem_blocks,
                "entries": self.entries,
                "limits": self.limits, "stats": dict(self.stats)}


def sdk_dump(exe: str, apk: Path, command: str, *args: str) -> str:
    proc = subprocess.run([exe, "dump", command, *args, str(apk)], capture_output=True,
                          timeout=90, encoding="utf-8", errors="replace")
    if proc.returncode:
        raise ValueError(f"aapt2 {command} returned {proc.returncode}")
    return proc.stdout


def sdk_xml(inv: Inventory, exe: str, apk: Path, entry: str) -> list[dict]:
    text = sdk_dump(exe, apk, "xmltree", "--file", entry)
    stack = []
    nodes = []
    for index, line in enumerate(text.splitlines(), 1):
        indent = len(line) - len(line.lstrip())
        element = re.match(r"\s*E: (\S+) \(line=(\d+)\)", line)
        if element:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            node = {"element": element[1], "original_xml_line": int(element[2]),
                    "aapt_output_line": index, "attributes": {}, "ancestors": [s[1]["element"] for s in stack]}
            stack.append((indent, node))
            nodes.append(node)
            continue
        attribute = re.match(r"\s*A: (.+?)(?:\(0x[0-9a-f]+\))?=(.*)$", line)
        if attribute and stack:
            name = attribute[1].replace("http://schemas.android.com/apk/res/android:", "android:")
            value = attribute[2]
            quoted = QUOTED.match(value)
            if quoted:
                try:
                    value = json.loads(quoted[0])
                except ValueError:
                    value = quoted[0][1:-1]
            stack[-1][1]["attributes"][name] = value
            inv.text(str(value), {"apk_member": apk.name, "entry": entry,
                                 "origin": "aapt2_xml", "aapt_output_line": index,
                                 "attribute": name})
    return nodes


def sdk_manifest(inv: Inventory, exe: str, apk: Path):
    nodes = sdk_xml(inv, exe, apk, "AndroidManifest.xml")
    inv.manifests.append({"apk_member": apk.name, "nodes": nodes})


def sdk_resources(inv: Inventory, exe: str, apk: Path):
    with zipfile.ZipFile(apk) as archive:
        if "resources.arsc" not in archive.namelist():
            return
    text = sdk_dump(exe, apk, "resources")
    name, resource_id = "", ""
    file_resources = {}
    for index, line in enumerate(text.splitlines(), 1):
        resource = re.match(r"\s*resource (0x[0-9a-f]+) (\S+)", line)
        if resource:
            resource_id, name = resource.groups()
        resource_file = re.search(r"\(file\) (\S+) type=XML", line)
        if resource_file:
            file_resources[resource_id] = (name, resource_file[1])
        for match in QUOTED.finditer(line):
            try:
                value = json.loads(match[0])
            except ValueError:
                value = match[0][1:-1]
            location = {"apk_member": apk.name, "entry": "resources.arsc",
                        "origin": "aapt2_resources", "aapt_output_line": index,
                        "resource_name": name, "resource_id": resource_id}
            inv.text(value, location, include_paths=True)
            if re.search(r"(?i)api.?key|token|secret|password|client.?id|server|base.?url|endpoint|firebase|google_app", name):
                inv.resources.append({"name": name, "value": value, "location": location,
                                      "status": "named_resource_not_necessarily_secret"})
    wanted = set()
    for manifest in inv.manifests:
        if manifest["apk_member"] != apk.name:
            continue
        for node in manifest["nodes"]:
            attrs = node["attributes"]
            for field in ("android:networkSecurityConfig", "android:fullBackupContent", "android:dataExtractionRules"):
                if field in attrs:
                    wanted.add(str(attrs[field]).lstrip("@"))
            if node["element"] == "meta-data" and attrs.get("android:name") == "android.support.FILE_PROVIDER_PATHS":
                wanted.add(str(attrs.get("android:resource", "")).lstrip("@"))
    # Include conventional names too, even if a resource was not referenced by a manifest.
    referenced = set(wanted)
    wanted.update(ident for ident, (name, _) in file_resources.items()
                  if re.search(r"network.*security|file.*paths|provider.*paths|backup.*rules|extraction.*rules", name))
    for ident in sorted(wanted):
        if ident not in file_resources:
            continue
        name, entry = file_resources[ident]
        try:
            nodes = sdk_xml(inv, exe, apk, entry)
        except (ValueError, subprocess.TimeoutExpired) as exc:
            inv.limits.append({"apk_member": apk.name, "entry": entry, "reason": str(exc)})
            continue
        inv.resource_xml.append({"apk_member": apk.name, "resource_id": ident,
                                 "resource_name": name, "entry": entry, "nodes": nodes,
                                 "referenced_from_manifest": ident in referenced})


def audit_app(folder: Path, aapt2: str) -> dict:
    inv = Inventory(folder.name)
    started = time.monotonic()
    for apk in sorted(folder.glob("*.apk")):
        inv.apks.append({"name": apk.name, "path": str(apk), "size": apk.stat().st_size,
                         "sha256": sha256(apk)})
        try:
            sdk_manifest(inv, aapt2, apk)
            sdk_resources(inv, aapt2, apk)
        except (ValueError, subprocess.TimeoutExpired) as exc:
            inv.limits.append({"apk_member": apk.name, "reason": str(exc)})
        with zipfile.ZipFile(apk) as archive:
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                inv.stats["zip_entries"] += 1
                inv.stats["declared_uncompressed_bytes"] += entry.file_size
                location = {"apk_member": apk.name, "entry": entry.filename}
                kind = ("dex" if entry.filename.endswith(".dex") else
                        "native" if entry.filename.endswith(".so") else
                        "resources" if entry.filename == "resources.arsc" else
                        "xml" if entry.filename.endswith(".xml") else
                        "asset" if entry.filename.startswith("assets/") else "other")
                inv.entries.append({**location, "bytes": entry.file_size, "kind": kind})
                if entry.file_size > MAX_ENTRY_BYTES:
                    inv.limits.append({**location, "reason": "entry_exceeds_512MiB"})
                    continue
                try:
                    data = archive.read(entry)
                except (RuntimeError, zipfile.BadZipFile, OSError):
                    inv.limits.append({**location, "reason": "zip_entry_read_failed"})
                    continue
                inv.stats["read_bytes"] += len(data)
                inv.raw(data, location, urls=kind not in {"dex", "resources", "xml"})
                if kind == "dex":
                    inv.dex(data, location)
                elif kind in {"resources", "xml"}:
                    for match in UTF16_RUN.finditer(data):
                        inv.text(match[0].decode("utf-16le"),
                                 {**location, "origin": "raw_utf16", "byte_offset": match.start(),
                                  "encoding": "utf-16le"})
                elif kind == "asset" and not data.startswith((b"\x89PNG", b"\xff\xd8", b"RIFF", b"PK\x03\x04")):
                    if len(data) <= 16 << 20 and b"\0" not in data[:8192]:
                        inv.text(data.decode("utf-8", "replace"),
                                 {**location, "origin": "text_asset"}, source_bytes=data)
    inv.stats["duration_seconds"] = round(time.monotonic() - started, 2)
    return inv.result()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--aapt2", required=True)
    parser.add_argument("--app", action="append", default=[])
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    out = {"version": 1, "method": "Independent SDK AAPT2 + raw bytes + DEX string table",
           "sources": SOURCE_DOCS, "scope": "Static literal candidates and structural facts; no network validation",
           "limits": {"max_entry_bytes": MAX_ENTRY_BYTES, "max_locations_per_value": MAX_LOCATIONS,
                      "dex_string_bytes": 1 << 20,
                      "note": "Does not reconstruct encrypted/runtime-generated values, prove code reachability, or prove vulnerabilities."},
           "apps": []}
    for folder in sorted(args.root.iterdir()):
        if not folder.is_dir() or not list(folder.glob("*.apk")) or (args.app and folder.name not in args.app):
            continue
        result = audit_app(folder, args.aapt2)
        out["apps"].append(result)
        temporary = args.output.with_suffix(".tmp")
        temporary.write_text(json.dumps(out, ensure_ascii=True, indent=2), encoding="utf-8")
        temporary.replace(args.output)
        print(json.dumps({"app": result["name"], "apks": len(result["apks"]),
                          "keys": len(result["keys"]), "urls": len(result["urls"]),
                          "paths": len(result["paths"]), "limits": len(result["limits"]),
                          "seconds": result["stats"]["duration_seconds"]}), flush=True)


if __name__ == "__main__":
    main()
