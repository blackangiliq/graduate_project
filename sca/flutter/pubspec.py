"""Pub dependencies of a Flutter or Dart project: pubspec.yaml, pubspec.lock and their audit.

Versions are ordered the way the pub tool orders them (package pub_semver), which differs from
SemVer 2.0.0: a pre-release sorts before its release (1.0.0-dev.29 < 1.0.0) and build metadata
sorts after the plain version (0.3.5 < 0.3.5+1 < 0.3.6), where SemVer treats builds as equal.
Advisory ranges use that plain order, so "fixed in 5.0.0" leaves 5.0.0-dev.1 affected. A
pubspec constraint adds pub's own rule: an exclusive maximum also excludes its pre-releases
("<2.0.0" rejects 2.0.0-beta).

The audit (engine "flutter") reports:
    FLUTTER-PUB-001  a version with a known vulnerability                        CWE-1395
    FLUTTER-PUB-002  a discontinued package, or one whose known vulnerability
                     has no fixed version                                        CWE-1104
    FLUTTER-PUB-003  a dependency fetched over git:// or http://                 CWE-494
    FLUTTER-PUB-004  dependency_overrides or an `any` constraint in an app       CWE-1357
    FLUTTER-PUB-005  a Flutter app without pubspec.lock                          CWE-1357
    FLUTTER-PUB-006  a git dependency that is not pinned to a commit or a tag    CWE-494
A finding points to the package's name line in pubspec.lock, or to its line in pubspec.yaml
when there is no lock or the lock does not list the package.

The advisory data (data/advisories.json and data/discontinued.json) is a curated snapshot of
2026-11-23: the GitHub advisory database (the records OSV and pub.dev also serve), advisories
published only in a package's own repository, and CVEs that no database maps to a pub
package. Nothing is downloaded at scan time.
"""
from __future__ import annotations

import functools
import itertools
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

import yaml
from yaml.composer import Composer
from yaml.constructor import SafeConstructor
from yaml.resolver import Resolver

from ..models import SEVERITY_RANK, Finding, normalize_severity
from ..walker import SourceFile

try:
    from yaml.cyaml import CParser
except ImportError:           # PyYAML built without libyaml
    CParser = None

DATA_DIR = Path(__file__).resolve().parent / "data"
ENGINE = "flutter"
MAX_TEXT = 2_000_000          # characters; a real pubspec.lock is far below 100 KB
MAX_NODES = 100_000           # YAML nodes; a lock of 256 packages has about 4,000
MAX_ENTRIES = 20_000          # dependencies, locked packages or assets read from one file
MAX_VERSION_TEXT = 128
INDEX_DEPTH = 4               # key levels whose line numbers are recorded
# pub.dev, its old address and its public mirrors (PUB_HOSTED_URL in China)
PUB_DEV_HOSTS = ("pub.dev", "pub.dartlang.org", "pub.flutter-io.cn", "pub-web.flutter-io.cn",
                 "mirrors.tuna.tsinghua.edu.cn", "mirror.sjtu.edu.cn",
                 "mirrors.cloud.tencent.com")
OTHER_REPOSITORY_CONFIDENCE = 0.5
UNREAD_CONFIDENCE = 0.3       # a package of an app package whose version could not be read
DEV_NOTE ="It is a dev dependency: it runs at build or test time and is not shipped in the app."
REPOSITORY_NOTE = ("It comes from the package repository at %s, not from pub.dev: this applies "
                   "only if that repository serves the pub.dev package.")

# ------------------------------------------------------------------ versions and constraints
_VERSION = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)"
                      r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
                      r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")
_COMPARISON = re.compile(r"[<>]=?")
_MAX_NUMBER = 2 ** 63 - 1     # pub keeps a larger all-digit identifier as text (int.tryParse)

Part = Union[int, str]


def _parts(text: Optional[str]) -> Tuple[Part, ...]:
    """Pre-release or build identifiers; an all-digit one is a number ("01" is 1)."""
    if not text:
        return ()
    out: List[Part] = []
    for part in text.split("."):
        number = int(part) if part.isascii() and part.isdigit() else -1
        out.append(number if 0 <= number <= _MAX_NUMBER else part)
    return tuple(out)


def _parts_key(parts: Tuple[Part, ...]) -> Tuple[Tuple[int, int, str], ...]:
    # numbers sort before words and compare as numbers; a missing part sorts first
    return tuple((0, part, "") if isinstance(part, int) else (1, 0, part) for part in parts)


@functools.total_ordering
@dataclass(frozen=True)
class Version:
    """A pub version: major.minor.patch, then an optional -pre-release and +build."""

    major: int
    minor: int
    patch: int
    pre: Tuple[Part, ...] = ()
    build: Tuple[Part, ...] = ()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self.sort_key() < other.sort_key()

    def __str__(self) -> str:
        """The canonical text, without leading zeros: 01.2.3-01 is 1.2.3-1."""
        text = "%d.%d.%d" % (self.major, self.minor, self.patch)
        if self.pre:
            text += "-" + ".".join(str(part) for part in self.pre)
        if self.build:
            text += "+" + ".".join(str(part) for part in self.build)
        return text

    def sort_key(self) -> Tuple[Any, ...]:
        """A pre-release sorts before its release, a build after the plain version."""
        return (self.major, self.minor, self.patch, 0 if self.pre else 1, _parts_key(self.pre),
                1 if self.build else 0, _parts_key(self.build))

    @property
    def is_prerelease(self) -> bool:
        return bool(self.pre)

    def next_breaking(self) -> "Version":
        """The first version a caret constraint excludes: ^1.2.3 -> 2.0.0, ^0.1.2 -> 0.2.0."""
        if self.major == 0:
            return Version(0, self.minor + 1, 0)
        return Version(self.major + 1, 0, 0)

    def first_prerelease(self) -> "Version":
        """The lowest version of this release: 2.0.0 -> 2.0.0-0."""
        return Version(self.major, self.minor, self.patch, (0,))


def _from_match(match: "re.Match[str]") -> Version:
    return Version(int(match.group(1)), int(match.group(2)), int(match.group(3)),
                   _parts(match.group(4)), _parts(match.group(5)))


def parse_version(text: Any) -> Optional[Version]:
    """The version written in `text` ("1.2.3", "1.0.0-dev.29", "0.3.5+1"), or None."""
    if isinstance(text, Version):
        return text
    if not isinstance(text, str) or len(text) > MAX_VERSION_TEXT:
        return None
    match = _VERSION.fullmatch(text.strip())
    return _from_match(match) if match else None


@dataclass(frozen=True)
class VersionRange:
    """The versions a pubspec constraint allows; a missing bound is open."""

    min: Optional[Version] = None
    max: Optional[Version] = None
    include_min: bool = False
    include_max: bool = False
    empty: bool = False          # the constraint allows no version at all ('>=2.0.0 <1.0.0')

    def allows(self, version: Version) -> bool:
        if self.empty:
            return False
        if self.min is not None and (version < self.min
                                     or (version == self.min and not self.include_min)):
            return False
        return (self.max is None or version < self.max
                or (version == self.max and self.include_max))

    @property
    def exact(self) -> Optional[Version]:
        """The only version a pinned constraint ("1.2.3") allows, else None."""
        if (not self.empty and self.min is not None and self.min == self.max
                and self.include_min and self.include_max):
            return self.min
        return None


def parse_constraint(text: Any) -> Optional[VersionRange]:
    """A pubspec version constraint read the way pub reads it: "any", "1.2.3", "^1.2.3",
    ">=1.2.3 <2.0.0", "<=5.1.4" ... None when the text is not a valid constraint.

    ^v allows v up to the next breaking version (^1.2.3 is >=1.2.3 <2.0.0, ^0.1.2 is
    >=0.1.2 <0.2.0), and an exclusive maximum that is a plain release also excludes its own
    pre-releases, unless the minimum is a pre-release of that same release.
    """
    if not isinstance(text, str) or len(text) > 4 * MAX_VERSION_TEXT:
        return None
    rest = text.strip()
    if rest == "any":
        return VersionRange()
    if rest.startswith("^"):
        match = _VERSION.fullmatch(rest[1:].strip())
        if not match:
            return None
        version = _from_match(match)
        return VersionRange(version, version.next_breaking().first_prerelease(), True, False)
    low: Optional[Version] = None
    high: Optional[Version] = None
    low_in = high_in = False
    while True:
        rest = rest.strip()
        if not rest:
            break
        operator = ""
        match = _VERSION.match(rest)
        if not match:
            op_match = _COMPARISON.match(rest)
            if not op_match:
                return None
            operator = op_match.group(0)
            rest = rest[op_match.end():].strip()
            match = _VERSION.match(rest)
            if not match:
                return None
        version = _from_match(match)
        rest = rest[match.end():]
        if operator in ("", ">", ">="):        # a bare version is both bounds, inclusive
            including = operator != ">"
            if low is None or version > low:
                low, low_in = version, including
            elif version == low and not including:
                low_in = False
        if operator in ("", "<", "<="):
            including = operator != "<"
            if high is None or version < high:
                high, high_in = version, including
            elif version == high and not including:
                high_in = False
    if low is None and high is None:
        return None
    if low is not None and high is not None and (
            low > high or (low == high and not (low_in and high_in))):
        return VersionRange(empty=True)
    if (high is not None and not high_in and not high.pre and not high.build
            and (low is None or not low.pre
                 or (low.major, low.minor, low.patch) != (high.major, high.minor, high.patch))):
        high = high.first_prerelease()     # "<2.0.0" also rejects 2.0.0-beta
    return VersionRange(low, high, low_in, high_in)


# An advisory range: (first affected version, None for "0"; the end version, None for none;
# True when the end version is affected itself, as last_affected is)
Interval = Tuple[Optional[Version], Optional[Version], bool]


def _interval(entry: Any) -> Optional[Interval]:
    """One range {introduced, fixed} or {introduced, last_affected}, or None when it is
    malformed. Introduced "0" means from the first version; no end means every later one."""
    if not isinstance(entry, Mapping):
        return None
    start = str(entry.get("introduced") or "0")
    fixed, last = entry.get("fixed"), entry.get("last_affected")
    if fixed and last:
        return None
    low = None if start == "0" else parse_version(start)
    end_text = fixed or last
    end = parse_version(end_text) if end_text else None
    if (start != "0" and low is None) or (end_text and end is None):
        return None
    return low, end, bool(last)


def _contains(interval: Interval, version: Version) -> bool:
    low, end, end_included = interval
    if low is not None and version < low:
        return False
    return end is None or version < end or (end_included and version == end)


def in_range(version: Union[str, Version], affected: Iterable[Mapping[str, Any]]) -> bool:
    """True when the version lies in one of the advisory ranges, written OSV style:
    {"introduced": "0", "fixed": "0.13.3"} (the fixed version excluded) or
    {"introduced": "1.4.1", "last_affected": "1.9.0"} (included). Plain pub order applies, so
    a range fixed in 5.0.0 includes 5.0.0-dev.1, unlike the pubspec constraint "<5.0.0"."""
    parsed = parse_version(version)
    if parsed is None:
        return False
    return any(interval is not None and _contains(interval, parsed)
               for interval in map(_interval, affected))


def _higher_low(a: Optional[Version], a_in: bool, b: Optional[Version], b_in: bool
                ) -> Tuple[Optional[Version], bool]:
    """The stricter of two lower bounds (None is open)."""
    if a is None or (b is not None and b > a):
        return b, b_in
    if b is None or a > b:
        return a, a_in
    return a, a_in and b_in


def _lower_high(a: Optional[Version], a_in: bool, b: Optional[Version], b_in: bool
                ) -> Tuple[Optional[Version], bool]:
    """The stricter of two upper bounds (None is open)."""
    if a is None or (b is not None and b < a):
        return b, b_in
    if b is None or a < b:
        return a, a_in
    return a, a_in and b_in


def _overlaps(window: VersionRange, interval: Interval) -> bool:
    """True when the constraint allows at least one version of the advisory range."""
    if window.empty:
        return False
    start, end, end_included = interval
    low, low_in = _higher_low(window.min, window.include_min, start, True)
    high, high_in = _lower_high(window.max, window.include_max, end, end_included)
    if low is None or high is None:
        return True
    return low < high or (low == high and low_in and high_in)


def _covers(interval: Interval, window: VersionRange) -> bool:
    """True when every version the constraint allows lies in the advisory range."""
    start, end, end_included = interval
    if window.empty or (start is not None and (window.min is None or window.min < start)):
        return False
    if end is None:
        return True
    if window.max is None or window.max > end:
        return False
    return not (window.max == end and window.include_max and not end_included)


def _range_text(interval: Interval) -> str:
    start, end, end_included = interval
    parts = [">= %s" % start] if start is not None else []
    if end is not None:
        parts.append("%s %s" % ("<=" if end_included else "<", end))
    return " and ".join(parts) or "every version"


# ------------------------------------------------------------------ advisory data
@dataclass
class Advisory:
    """One curated advisory for one package, in the shape of an OSV record."""

    id: str                          # GHSA id
    aliases: List[str]               # CVE and other ids of the same issue
    package: str
    affected: List[Dict[str, str]]   # [{introduced, fixed}] or [{introduced, last_affected}]
    severity: str                    # low | medium | high | critical
    cwes: List[str]                  # the weaknesses the advisory itself names (may be empty)
    summary: str
    url: str
    source: str                      # global-database | repository-advisory | cve-only

    @property
    def ids(self) -> List[str]:
        return [self.id] + self.aliases

    def affects(self, version: Union[str, Version]) -> bool:
        return in_range(version, self.affected)


@dataclass(frozen=True)
class Unmaintained:
    """A package pub.dev marks discontinued, or (discontinued False) one whose known
    vulnerability has no fixed version."""

    package: str
    reason: str
    replaced_by: str
    url: str
    discontinued: bool


def _read_json(name: str) -> Any:
    try:
        return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _strings(value: Any) -> List[str]:
    """The text items of a list (anything else is skipped, never converted)."""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value[:MAX_ENTRIES]
            if isinstance(item, str) and item.strip()]


def _advisory(raw: Any) -> Optional[Advisory]:
    """A record of advisories.json, or None when it is incomplete or a range is malformed."""
    if not isinstance(raw, dict) or not raw.get("id") or not raw.get("package"):
        return None
    affected = raw.get("affected")
    if not isinstance(affected, list) or not affected or any(
            _interval(entry) is None for entry in affected):
        return None
    return Advisory(id=str(raw["id"]), aliases=_strings(raw.get("aliases")),
                    package=str(raw["package"]), affected=[dict(entry) for entry in affected],
                    severity=normalize_severity(str(raw.get("severity") or "")),
                    cwes=_strings(raw.get("cwes")), summary=str(raw.get("summary") or ""),
                    url=str(raw.get("url") or ""), source=str(raw.get("source") or ""))


@functools.lru_cache(maxsize=None)
def _advisory_table() -> Dict[str, Tuple[Advisory, ...]]:
    table: Dict[str, List[Advisory]] = {}
    data = _read_json("advisories.json")
    for raw in data if isinstance(data, list) else []:
        advisory = _advisory(raw)
        if advisory is not None:
            table.setdefault(advisory.package, []).append(advisory)
    return {name: tuple(items) for name, items in table.items()}


@functools.lru_cache(maxsize=None)
def _unmaintained_table() -> Dict[str, Unmaintained]:
    data = _read_json("discontinued.json")
    table: Dict[str, Unmaintained] = {}
    for name, raw in (data.items() if isinstance(data, dict) else ()):
        if isinstance(raw, dict) and raw.get("reason"):
            table[str(name)] = Unmaintained(
                package=str(name), reason=str(raw["reason"]),
                replaced_by=str(raw.get("replaced_by") or ""), url=str(raw.get("url") or ""),
                discontinued=bool(raw.get("discontinued", True)))
    return table


def load_advisories() -> List[Advisory]:
    """Every advisory of data/advisories.json (the file is read once)."""
    return [advisory for items in _advisory_table().values() for advisory in items]


def advisories_for(package: str) -> List[Advisory]:
    """The advisories of one package, whatever the version."""
    return list(_advisory_table().get(package, ()))


def affecting_advisories(package: str, version: Union[str, Version]) -> List[Advisory]:
    """The advisories of a package that affect this version ([] when it cannot be read)."""
    return [advisory for advisory in advisories_for(package) if advisory.affects(version)]


def load_discontinued() -> Dict[str, Unmaintained]:
    """data/discontinued.json by package name (the file is read once)."""
    return dict(_unmaintained_table())


def _intervals(advisory: Advisory) -> List[Interval]:
    return [interval for interval in map(_interval, advisory.affected) if interval]


def _safe_version(package: str, floor: Optional[Version]) -> Optional[Version]:
    """The lowest fixed version at or above `floor` that no advisory of the package
    affects, or None when there is none."""
    ranges = [interval for advisory in advisories_for(package)
              for interval in _intervals(advisory)]
    fixes = sorted({end for _start, end, included in ranges
                    if end is not None and not included and (floor is None or end >= floor)})
    for candidate in fixes:
        if not any(_contains(interval, candidate) for interval in ranges):
            return candidate
    return None


# ------------------------------------------------------------------ pubspec.yaml and pubspec.lock
@dataclass
class Dependency:
    """One entry of dependencies, dev_dependencies or dependency_overrides in pubspec.yaml."""

    name: str
    section: str                 # dependencies | dev_dependencies | dependency_overrides
    source: str = "hosted"       # hosted | git | path | sdk
    constraint: str = ""         # as written; "" when none is given, which pub reads as any
    url: str = ""                # git repository, or a hosted repository other than pub.dev
    ref: str = ""                # git branch, tag or commit; "" means the default branch
    tag_pattern: str = ""        # git: the version comes from the tags matching this pattern
    path: str = ""               # path dependency, or the package folder in a git repository
    sdk: str = ""                # sdk dependency: "flutter"
    line: int = 0                # line of the package name in pubspec.yaml


@dataclass
class Asset:
    """An entry under flutter: assets: (a file, or a folder when it ends with /)."""

    path: str
    line: int = 0


@dataclass
class Pubspec:
    """What pubspec.yaml declares; `error` says why the file could not be read."""

    name: str = ""
    version: str = ""
    publish_to: str = ""
    sdk: str = ""                # environment: sdk constraint
    flutter_sdk: str = ""        # environment: flutter constraint
    is_flutter: bool = False     # depends on the Flutter SDK (dependencies: flutter: sdk: flutter)
    is_plugin: bool = False      # declares flutter: plugin:
    resolution: str = ""         # "workspace" for a member of a pub workspace
    dependencies: Dict[str, Dependency] = field(default_factory=dict)
    dev_dependencies: Dict[str, Dependency] = field(default_factory=dict)
    overrides: Dict[str, Dependency] = field(default_factory=dict)
    assets: List[Asset] = field(default_factory=list)
    ignored_advisories: List[str] = field(default_factory=list)
    lines: Dict[Tuple[Any, ...], int] = field(default_factory=dict)
    error: str = ""

    @property
    def is_app(self) -> bool:
        """An application rather than a package for others: `flutter create` writes
        publish_to: 'none' for an app, and a plugin is never one."""
        return self.publish_to.strip().lower() == "none" and not self.is_plugin

    def line_of(self, *path: Any) -> int:
        """1-based line of a key or list item, for example line_of("dependencies", "http") or
        line_of("flutter", "assets", 0); 0 when the file has no such entry."""
        return self.lines.get(tuple(path), 0)

    def declared(self) -> Dict[str, Dependency]:
        """The declaration pub resolves for each package: an override wins over dependencies,
        which win over dev_dependencies."""
        merged = dict(self.dev_dependencies)
        merged.update(self.dependencies)
        merged.update(self.overrides)
        return merged


@dataclass
class LockedPackage:
    """One entry of pubspec.lock: the version pub resolved and where it came from."""

    name: str
    version: str = ""
    source: str = ""             # hosted | git | path | sdk
    dependency: str = ""         # direct main | direct dev | direct overridden | transitive
    # hosted {name, sha256, url}; git {url, ref or tag-pattern, resolved-ref, path};
    # path {path, relative}; sdk "flutter" (scalar values only, nested ones are dropped)
    description: Any = None
    line: int = 0                # line of the package name

    def described(self, key: str) -> str:
        return _scalar(self.description.get(key)) if isinstance(self.description, dict) else ""

    @property
    def url(self) -> str:
        return self.described("url")

    @property
    def ref(self) -> str:
        return self.described("ref")

    @property
    def resolved_ref(self) -> str:
        return self.described("resolved-ref")

    @property
    def tag_pattern(self) -> str:
        return self.described("tag-pattern")


@dataclass
class Lock:
    """pubspec.lock; `sdks` holds the SDK constraints every package accepts, not the SDK used."""

    packages: Dict[str, LockedPackage] = field(default_factory=dict)
    sdks: Dict[str, str] = field(default_factory=dict)
    error: str = ""


def _scalar(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def _plain(value: Any) -> Any:
    """A YAML value reduced to data that is safe to keep and to write as JSON: a scalar, or
    a mapping of scalars (nested values dropped); None for anything else."""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {key: item for key, item in itertools.islice(value.items(), 50)
                if isinstance(key, str) and isinstance(item, (str, int, float, bool))}
    return None


def _yaml_error(exc: Exception) -> str:
    """A one-line reason, with the line number when the parser gives one."""
    if isinstance(exc, RecursionError):
        return "not valid YAML (nested too deeply)"
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or (str(exc).splitlines() or [""])[0]
    where = " at line %d" % (mark.line + 1) if mark is not None else ""
    return "not valid YAML%s (%s)" % (where, (problem or type(exc).__name__)[:200])


class _Limited:
    """Builds the node tree with PyYAML's own composer, which nests in Python: deeply nested
    input raises RecursionError, where libyaml's composer overflows the C stack and ends the
    process. It also stops after MAX_NODES nodes."""

    nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise yaml.YAMLError("more than %d YAML nodes" % MAX_NODES)
        return super().compose_node(parent, index)  # type: ignore[misc]


class _NoMerge:
    """pub reads YAML with package:yaml, which has no merge keys: "<<" is an ordinary key
    there, and here too. PyYAML would copy the merged pairs into every mapping that merges
    them, so a few levels of `<<: [*a, *a]` double the pairs at each level while the node
    count stays tiny (20 levels: a 629-byte file, 13 s and 600 MiB)."""

    def flatten_mapping(self, node: Any) -> None:
        for key_node, _ in node.value:
            if key_node.tag in (_MERGE_TAG, _VALUE_TAG):   # "<<" and "=" are plain strings
                key_node.tag = _STR_TAG


_MERGE_TAG = "tag:yaml.org,2002:merge"
_VALUE_TAG = "tag:yaml.org,2002:value"
_STR_TAG = "tag:yaml.org,2002:str"


class _PureLoader(_Limited, _NoMerge, yaml.SafeLoader):
    """yaml.safe_load's loader with the limits above and without merge keys."""


if CParser is not None:
    class _Loader(_Limited, _NoMerge, Composer, CParser, SafeConstructor, Resolver):
        """yaml.safe_load with libyaml's parser, a loop in C that is many times faster than
        the Python scanner on hostile input, the limited Python composer and no merge
        keys."""

        def __init__(self, stream: str) -> None:
            CParser.__init__(self, stream)
            Composer.__init__(self)
            SafeConstructor.__init__(self)
            Resolver.__init__(self)
else:
    _Loader = _PureLoader


def _load_yaml(text: str) -> Tuple[Any, Dict[Tuple[Any, ...], int], str]:
    """Parse YAML as yaml.safe_load does (but with "<<" as a plain key, as pub reads it) and
    record the line of every key and list item.
    Returns (data, lines, error), where error is "" when the text was read."""
    if len(text) > MAX_TEXT:
        return None, {}, "file too large (%d characters)" % len(text)
    loader = None
    try:
        loader = _Loader(text)        # the reader can already reject control characters
        node = loader.get_single_node()
        data = loader.construct_document(node) if node is not None else None
    except Exception as exc:      # hostile input: any parser failure becomes a message
        return None, {}, _yaml_error(exc)
    finally:
        if loader is not None:
            loader.dispose()
    return data, _index_lines(node), ""


def _index_lines(root: Optional[yaml.Node]) -> Dict[Tuple[Any, ...], int]:
    """Line of each mapping key and list item by its path from the root, for the first
    INDEX_DEPTH levels. A node shared through a YAML alias is indexed once."""
    lines: Dict[Tuple[Any, ...], int] = {}
    stack: List[Tuple[Optional[yaml.Node], Tuple[Any, ...]]] = [(root, ())]
    seen = set()
    while stack and len(lines) < MAX_ENTRIES * 4:
        node, path = stack.pop()
        if node is None or id(node) in seen or len(path) >= INDEX_DEPTH:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode):
                    lines[path + (key.value,)] = key.start_mark.line + 1
                    stack.append((value, path + (key.value,)))
        elif isinstance(node, yaml.SequenceNode):
            for index, item in enumerate(node.value):
                lines[path + (index,)] = item.start_mark.line + 1
                stack.append((item, path + (index,)))
    return lines


def _dependency(name: str, spec: Any, section: str, line: int) -> Dependency:
    dep = Dependency(name=name, section=section, line=line)
    if not isinstance(spec, dict):
        dep.constraint = _scalar(spec)
        return dep
    dep.constraint = _scalar(spec.get("version"))
    if "sdk" in spec:
        dep.source, dep.sdk = "sdk", _scalar(spec["sdk"])
    elif "git" in spec:
        dep.source = "git"
        git = spec["git"]
        if isinstance(git, dict):
            dep.url, dep.ref = _scalar(git.get("url")), _scalar(git.get("ref"))
            dep.path, dep.tag_pattern = _scalar(git.get("path")), _scalar(git.get("tag_pattern"))
        else:
            dep.url = _scalar(git)
    elif "path" in spec:
        dep.source, dep.path = "path", _scalar(spec["path"])
    elif "hosted" in spec:
        hosted = spec["hosted"]
        dep.url = _scalar(hosted.get("url")) if isinstance(hosted, dict) else _scalar(hosted)
    return dep


def _dependencies(data: Dict[Any, Any], section: str, lines: Dict[Tuple[Any, ...], int]
                  ) -> Dict[str, Dependency]:
    raw = data.get(section)
    out: Dict[str, Dependency] = {}
    for name, spec in (raw.items() if isinstance(raw, dict) else ()):
        if len(out) >= MAX_ENTRIES:
            break
        if isinstance(name, str) and name:
            out[name] = _dependency(name, spec, section, lines.get((section, name), 0))
    return out


def _assets(raw: Any, lines: Dict[Tuple[Any, ...], int]) -> List[Asset]:
    out: List[Asset] = []
    for index, item in enumerate(raw[:MAX_ENTRIES] if isinstance(raw, list) else []):
        path = _scalar(item.get("path")) if isinstance(item, dict) else _scalar(item)
        if path:     # an entry is a path, or {path: ..., flavors: [...]} since Flutter 3.22
            out.append(Asset(path, lines.get(("flutter", "assets", index), 0)))
    return out


def parse_pubspec(text: str) -> Pubspec:
    """Read pubspec.yaml: name, SDK constraints, dependencies, overrides and assets, each with
    its line. Never raises: a file that cannot be read gives a Pubspec with `error` set."""
    data, lines, error = _load_yaml(text)
    spec = Pubspec(lines=lines, error=error)
    if error:
        return spec
    if not isinstance(data, dict):
        spec.error = "pubspec.yaml does not hold a YAML mapping"
        return spec
    spec.name = _scalar(data.get("name"))
    spec.version = _scalar(data.get("version"))
    spec.publish_to = _scalar(data.get("publish_to"))
    spec.resolution = _scalar(data.get("resolution"))
    environment = data.get("environment")
    if isinstance(environment, dict):
        spec.sdk = _scalar(environment.get("sdk"))
        spec.flutter_sdk = _scalar(environment.get("flutter"))
    spec.dependencies = _dependencies(data, "dependencies", lines)
    spec.dev_dependencies = _dependencies(data, "dev_dependencies", lines)
    spec.overrides = _dependencies(data, "dependency_overrides", lines)
    flutter_dep = spec.dependencies.get("flutter")
    spec.is_flutter = bool(flutter_dep and flutter_dep.source == "sdk"
                           and flutter_dep.sdk == "flutter")
    section = data.get("flutter")
    if isinstance(section, dict):
        spec.is_plugin = "plugin" in section
        spec.assets = _assets(section.get("assets"), lines)
    spec.ignored_advisories = _strings(data.get("ignored_advisories"))
    return spec


def parse_lock(text: str) -> Lock:
    """Read pubspec.lock: every resolved package with its line, and the SDK constraints.
    Never raises: a file that cannot be read gives a Lock with `error` set."""
    data, lines, error = _load_yaml(text)
    lock = Lock(error=error)
    if error:
        return lock
    if not isinstance(data, dict):
        lock.error = "pubspec.lock does not hold a YAML mapping"
        return lock
    packages = data.get("packages")
    for name, entry in (packages.items() if isinstance(packages, dict) else ()):
        if len(lock.packages) >= MAX_ENTRIES:
            break
        if isinstance(name, str) and name and isinstance(entry, dict):
            lock.packages[name] = LockedPackage(
                name=name, version=_scalar(entry.get("version")),
                source=_scalar(entry.get("source")), dependency=_scalar(entry.get("dependency")),
                description=_plain(entry.get("description")),
                line=lines.get(("packages", name), 0))
    sdks = data.get("sdks")
    if isinstance(sdks, dict):
        lock.sdks = {key: _scalar(value) for key, value in itertools.islice(sdks.items(), 50)
                     if isinstance(key, str)}
    elif _scalar(data.get("sdk")):         # lockfiles of pub 1.14 to 1.18
        lock.sdks = {"dart": _scalar(data.get("sdk"))}
    return lock


# ------------------------------------------------------------------ audit
_LOOPBACK = re.compile(r"^(localhost|127(\.[0-9]+){3}|::1)$|\.localhost$", re.IGNORECASE)
_USERINFO = re.compile(r"(?<=://)[^/@\s]*@")
_COMMIT = re.compile(r"[0-9a-fA-F]{7,64}")
_TAG = re.compile(r"refs/tags/.+|v?[0-9]+\.[0-9]+(\.[0-9]+)?([-+][0-9A-Za-z.-]+)?")


def _short(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _join(items: List[str]) -> str:
    """"a", "a and b", "a, b and c"."""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _host(url: str) -> str:
    try:
        return (urlsplit(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _other_repository(url: str) -> str:
    """The host of a hosted package's repository when that is not pub.dev or one of its
    mirrors, else ""."""
    host = _host(url) if url else ""
    return "" if host in PUB_DEV_HOSTS else host


@dataclass
class _Spot:
    """Where a finding points: the file, the line, its masked text and the lines after it."""

    file: str
    line: int
    snippet: str
    context: str
    language: str


def _spot_in(sf: SourceFile, line: int, after: int, rel: str = "") -> _Spot:
    line = line if 1 <= line <= len(sf.lines) else 1
    return _Spot(rel or sf.rel, line, sf.line_text(line), sf.context(line, 0, after),
                 sf.language)


def _finding(rule_id: str, title: str, spot: _Spot, severity: str, cwe: str,
             confidence: float, description: str, fix: str) -> Finding:
    return Finding(rule_id=rule_id, title=title, file=spot.file, line=spot.line,
                   severity=severity, cwe=cwe, description=description, fix=fix,
                   confidence=confidence, engines=[ENGINE], snippet=spot.snippet,
                   context=spot.context, language=spot.language)


def _advisory_text(advisory: Advisory, matched: List[Interval]) -> str:
    facts = advisory.aliases + advisory.cwes + [
        "affected: " + ", ".join(_range_text(interval) for interval in matched)]
    return "%s (%s): %s %s" % (advisory.id, "; ".join(facts), advisory.summary, advisory.url)


@dataclass
class _Hit:
    """An advisory that matches, with the ranges that match."""

    advisory: Advisory
    matched: List[Interval]
    confidence: float
    whole: bool = False          # the range covers every version the constraint allows (or
                                 # every version at all when the version is unknown)


def _upgrade_advice(name: str, version: Optional[Version], window: Optional[VersionRange],
                    declared: Optional[str], transitive: bool, hits: List[_Hit]) -> str:
    """Which version to move to, and whether the constraint in pubspec.yaml allows it."""
    if version is None and window is None:
        fixed_in = []
        for hit in hits:
            advisory, matched = hit.advisory, hit.matched
            fixes = [str(end) for _start, end, included in matched
                     if end is not None and not included]
            fixed_in.append("%s is fixed in %s" % (advisory.id, _join(fixes)) if fixes
                            else "%s has no fixed version" % advisory.id)
        return ("Check which version of %s the app is built with and make sure it is a fixed "
                "one: %s." % (name, "; ".join(fixed_in)))
    target = _safe_version(name, version if version is not None else window.min)
    if target is None:
        return ("No fixed release of %s is listed: replace it, or apply the advisory's "
                "workaround until one is released." % name)
    if version is None:
        return ("Change the constraint of %s in pubspec.yaml to ^%s, so that no vulnerable "
                "version can be resolved, and commit pubspec.lock." % (name, target))
    advice = "Upgrade %s to %s or a later fixed release." % (name, target)
    allowed = parse_constraint(declared or "any") if declared is not None else None
    if allowed is not None and not allowed.allows(target):
        advice += (" Its constraint %s in pubspec.yaml does not allow that version: change it "
                   "to ^%s." % (declared or "any", target))
    if transitive:
        advice += (" It is a transitive dependency: run flutter pub upgrade, and upgrade the "
                   "package that holds it back if that is not enough.")
    return advice


def _vulnerable(name: str, spot: _Spot, *, version: Optional[Version] = None,
                constraint: Optional[str] = None, declared: Optional[str] = None,
                transitive: bool = False, ignored: Iterable[str] = (),
                notes: Iterable[str] = (), cap: float = 1.0,
                in_app: bool = False) -> Optional[Finding]:
    """FLUTTER-PUB-001 for one package. `version` is the version in use (pubspec.lock, an app
    package); without it, `constraint` is the constraint in pubspec.yaml ("" = any); with
    neither, the version is unknown. `declared` is the constraint an upgrade has to fit and
    `cap` limits the confidence. `in_app` marks a package found in an app package: when its
    version could not be read, the finding is only information (UNREAD_CONFIDENCE) unless an
    advisory affects every version."""
    advisories = advisories_for(name)
    if not advisories:
        return None
    window = None
    if version is None and constraint is not None:
        window = parse_constraint(constraint or "any")
        if window is None or window.empty:
            return None
        if window.exact is not None:
            version, declared, window = window.exact, constraint, None
    hits: List[_Hit] = []
    for advisory in advisories:
        intervals = _intervals(advisory)
        if version is not None:
            hit = _Hit(advisory, [i for i in intervals if _contains(i, version)], 0.9)
        elif window is not None:
            matched = [i for i in intervals if _overlaps(window, i)]
            whole = any(_covers(i, window) for i in matched)
            hit = _Hit(advisory, matched, 0.8 if whole else 0.35, whole)
        else:
            whole = any(start is None and end is None for start, end, _ in intervals)
            hit = _Hit(advisory, intervals, 0.35 if whole or not in_app else UNREAD_CONFIDENCE,
                       whole)
        if hit.matched:
            hit.confidence = min(hit.confidence, cap)
            hits.append(hit)
    if not hits:
        return None
    skipped = set(ignored)
    active = [hit for hit in hits if not skipped.intersection(hit.advisory.ids)]
    shown = active or hits
    confidence = max(hit.confidence for hit in shown)
    unread = in_app and version is None and window is None
    # an app whose package version is unknown is surely affected only by an advisory that
    # covers every version
    certain = [hit for hit in active if hit.whole] if unread else active
    severity = max((hit.advisory.severity for hit in certain), key=SEVERITY_RANK.__getitem__) \
        if certain else "info"
    count = "a known vulnerability" if len(shown) == 1 \
        else "%d known vulnerabilities" % len(shown)
    allowed = _short(constraint or "any")
    if unread and certain:
        title = "Vulnerable dependency: %s (every version is affected)" % name
        lead = ("The app contains %s. Its version could not be read from the app, but %s "
                "affects every version:" % (name, _join([hit.advisory.id for hit in certain])))
    elif unread:
        title = "Possibly vulnerable dependency: %s (version could not be read from the app)" \
            % name
        lead = ("The app contains %s, but its version could not be read from the app (release "
                "builds keep only package names). Some versions have %s:" % (name, count))
    elif version is not None:
        title = "Vulnerable dependency: %s %s" % (name, version)
        lead = "%s %s has %s:" % (name, version, count)
    elif window is not None and any(hit.whole for hit in shown):
        title = "Vulnerable dependency: %s %s" % (name, allowed)
        lead = "Every version of %s that the constraint %s allows has %s:" % (
            name, allowed, count)
    elif window is not None:
        title = "Dependency constraint allows a vulnerable version: %s %s" % (name, allowed)
        lead = ("The constraint %s allows versions of %s with %s; the version in use is "
                "unknown without pubspec.lock:" % (allowed, name, count))
    else:
        title = "Possibly vulnerable dependency: %s (version unknown)" % name
        lead = "The app contains %s, but its version is unknown. Some versions have %s:" % (
            name, count)
    text = [lead] + [_advisory_text(hit.advisory, hit.matched) for hit in shown]
    if len(active) < len(hits):
        text.append("pubspec.yaml lists %s under ignored_advisories." % _join(
            [hit.advisory.id for hit in hits if skipped.intersection(hit.advisory.ids)]))
    text.extend(note for note in notes if note)
    fix = _upgrade_advice(name, version, window, declared, transitive, shown)
    return _finding("FLUTTER-PUB-001", title, spot, severity, "CWE-1395", confidence,
                    " ".join(text), fix)


def _replacement(entry: Unmaintained) -> str:
    """The suggested replacement, followed while it is discontinued itself
    (flutter_sodium -> sodium_libs -> sodium)."""
    table = _unmaintained_table()
    name, seen = entry.replaced_by, {entry.package}
    while name in table and table[name].replaced_by and name not in seen:
        seen.add(name)
        name = table[name].replaced_by
    return name


def _unmaintained(name: str, spot: _Spot, notes: Iterable[str] = (), cap: float = 1.0
                  ) -> Optional[Finding]:
    """FLUTTER-PUB-002: the package is discontinued, or its vulnerability has no fix."""
    entry = _unmaintained_table().get(name)
    if entry is None:
        return None
    text = [entry.reason]
    if entry.replaced_by:
        text.append("Suggested replacement: %s." % entry.replaced_by)
    text.extend(item for item in [entry.url] + list(notes) if item)
    description = " ".join(text)
    replacement = _replacement(entry)
    if replacement:
        fix = "Replace %s with %s." % (name, replacement)
        if replacement != entry.replaced_by:
            fix += " (%s is discontinued as well.)" % entry.replaced_by
    elif entry.discontinued:
        fix = "Remove %s or replace it with a maintained package." % name
    else:
        fix = ("Replace %s with a maintained alternative, or apply the advisory's workaround "
               "until a fixed version is released." % name)
    title = ("Discontinued package: %s" if entry.discontinued
             else "Package with an unfixed vulnerability: %s") % name
    return _finding("FLUTTER-PUB-002", title, spot, "low", "CWE-1104", min(0.8, cap),
                    description, fix)


def _insecure_scheme(url: str) -> str:
    """"git" or "http" when the URL fetches code from another machine over an
    unauthenticated, unencrypted channel, else ""."""
    scheme, separator, _rest = url.strip().partition("://")
    if not separator or scheme.lower() not in ("git", "http"):
        return ""
    return "" if _LOOPBACK.search(_host(url)) else scheme.lower()


def _insecure_source(name: str, url: str, source: str, spot: _Spot) -> Optional[Finding]:
    """FLUTTER-PUB-003: the package is downloaded over git:// or http://."""
    scheme = _insecure_scheme(url)
    if not scheme:
        return None
    fix = ("Fetch it over https:// (or ssh) and pin a commit: git: {url: https://..., ref: "
           "<commit>}." if source == "git" else "Use the https:// address of the repository.")
    return _finding(
        "FLUTTER-PUB-003", "Dependency fetched over %s://: %s" % (scheme, _short(name)), spot,
        "high", "CWE-494", 0.85,
        "pub downloads %s from %s over an unauthenticated, unencrypted channel, so anyone on "
        "the network path can replace the code that is built into the app."
        % (_short(name), _short(_USERINFO.sub("", url.strip()), 200)), fix)


def _unpinned_git(name: str, ref: str, spot: _Spot, tag_pattern: str = "",
                  resolved: str = "") -> Optional[Finding]:
    """FLUTTER-PUB-006: a git dependency that follows a branch instead of a commit or a tag."""
    ref = ref.strip()
    if tag_pattern or _COMMIT.fullmatch(ref) or _TAG.fullmatch(ref):
        return None
    where = "the default branch" if ref in ("", "HEAD") else "the branch '%s'" % _short(ref)
    description = ("%s comes from git at %s, so each pub upgrade can pull in new commits that "
                   "nobody reviewed." % (_short(name), where))
    if resolved:
        description += (" pubspec.lock records commit %s, but the next upgrade can move it."
                        % _short(resolved, 12))
    return _finding("FLUTTER-PUB-006", "Git dependency not pinned to a commit: %s"
                    % _short(name), spot, "low", "CWE-494", 0.6, description,
                    "Set ref to a full commit hash or a release tag in pubspec.yaml.")


def _loosened(dep: Dependency, spot: _Spot, locked_version: str) -> Finding:
    """FLUTTER-PUB-004: an override, or a hosted dependency without a version constraint."""
    name = _short(dep.name)
    if dep.section == "dependency_overrides":
        return _finding(
            "FLUTTER-PUB-004", "Dependency override: %s" % name, spot, "low", "CWE-1357",
            0.7, "dependency_overrides forces %s on the whole dependency graph and ignores the "
            "constraints of every package that depends on it, so an incompatible or vulnerable "
            "version can be built into the app." % name,
            "Remove the override as soon as the packages that depend on %s allow a fixed "
            "version." % name)
    example = "^%s" % locked_version if parse_version(locked_version) else "^1.2.3"
    return _finding(
        "FLUTTER-PUB-004", "Unconstrained dependency: %s" % name, spot, "low", "CWE-1357",
        0.7, "%s has no version constraint (any), so pub accepts every future release of it, "
        "including a broken or compromised one." % name,
        "Give %s a caret constraint (%s: %s) and commit pubspec.lock." % (name, name, example))


def _no_lock(spot: _Spot) -> Finding:
    """FLUTTER-PUB-005: a Flutter app whose dependency versions are not locked."""
    return _finding(
        "FLUTTER-PUB-005", "Flutter app without pubspec.lock", spot, "info", "CWE-1357", 0.6,
        "The app does not lock its dependency versions: each flutter pub get can resolve other, "
        "unreviewed versions, and the versions that are built cannot be checked.",
        "Run flutter pub get and commit pubspec.lock with the app.")


class _Findings:
    """Collects findings, one per file, rule and line."""

    def __init__(self) -> None:
        self.items: List[Finding] = []
        self._keys = set()

    def add(self, finding: Optional[Finding]) -> None:
        if finding is None:
            return
        key = (finding.file, finding.rule_id, finding.line)
        if key not in self._keys:
            self._keys.add(key)
            self.items.append(finding)


def _hosted_terms(url: str, dev: bool) -> Tuple[float, List[str]]:
    """The confidence cap and the notes for a hosted package from this repository URL."""
    host = _other_repository(url)
    notes = [REPOSITORY_NOTE % _short(host)] if host else []
    if dev:
        notes.append(DEV_NOTE)
    return (OTHER_REPOSITORY_CONFIDENCE if host else 1.0), notes


def _audit_locked(found: _Findings, package: LockedPackage, dep: Optional[Dependency],
                  ignored: List[str], spot: _Spot) -> None:
    """The findings of one package that pubspec.lock lists."""
    source = package.source or "hosted"
    if source == "hosted":
        cap, notes = _hosted_terms(package.url, package.dependency == "direct dev")
        version = parse_version(package.version)
        declared = dep.constraint if dep is not None and dep.source == "hosted" else None
        found.add(_vulnerable(
            package.name, spot, version=version,
            constraint=declared if version is None else None, declared=declared,
            transitive=package.dependency == "transitive", ignored=ignored, notes=notes,
            cap=cap))
        found.add(_unmaintained(package.name, spot, notes, cap))
    if source in ("hosted", "git"):
        found.add(_insecure_source(package.name, package.url, source, spot))
    if source == "git":
        found.add(_unpinned_git(package.name, package.ref, spot,
                                package.tag_pattern or (dep.tag_pattern if dep else ""),
                                package.resolved_ref))


def _audit_declared(found: _Findings, dep: Dependency, ignored: List[str], spot: _Spot) -> None:
    """The findings of a pubspec.yaml dependency that pubspec.lock does not list."""
    if dep.source == "hosted":
        cap, notes = _hosted_terms(dep.url, dep.section == "dev_dependencies")
        found.add(_vulnerable(dep.name, spot, constraint=dep.constraint, ignored=ignored,
                              notes=notes, cap=cap))
        found.add(_unmaintained(dep.name, spot, notes, cap))
    if dep.source in ("hosted", "git"):
        found.add(_insecure_source(dep.name, dep.url, dep.source, spot))
    if dep.source == "git":
        found.add(_unpinned_git(dep.name, dep.ref, spot, dep.tag_pattern))


def audit_project(pubspec_sf: SourceFile, lock_sf: Optional[SourceFile] = None,
                  warnings: Optional[List[str]] = None, app: Optional[bool] = None
                  ) -> List[Finding]:
    """Findings for a project's pubspec.yaml and, when there is one, the pubspec.lock next to
    it (a member of a pub workspace has none: the lock of the workspace root is audited with
    the root's pubspec.yaml). A package the lock lists is reported on its name line in the
    lock, any other on its line in pubspec.yaml.
    `app` says whether the project is an application (the project loader can tell from
    lib/main.dart or the platform folders); None decides from pubspec.yaml (publish_to: none,
    not a plugin). A file that cannot be read adds a message to `warnings` (when given)
    instead of raising."""
    spec = parse_pubspec(pubspec_sf.text)
    lock = parse_lock(lock_sf.text) if lock_sf is not None else Lock()
    if warnings is not None:
        if spec.error:
            warnings.append("%s: %s" % (pubspec_sf.rel, spec.error))
        if lock_sf is not None and lock.error:
            warnings.append("%s: %s" % (lock_sf.rel, lock.error))
    locked = lock.packages if lock_sf is not None and not lock.error else {}
    declared = spec.declared()
    found = _Findings()
    for package in locked.values():
        _audit_locked(found, package, declared.get(package.name), spec.ignored_advisories,
                      _spot_in(lock_sf, package.line, 7))
    for dep in declared.values():
        if dep.name not in locked:
            _audit_declared(found, dep, spec.ignored_advisories,
                            _spot_in(pubspec_sf, dep.line, 3))
    if spec.is_app if app is None else app:
        # a member of a pub workspace is constrained and locked by the workspace root
        member = spec.resolution == "workspace"
        loose = list(spec.overrides.values()) + [
            dep for dep in list(spec.dependencies.values()) + list(spec.dev_dependencies.values())
            if dep.source == "hosted" and dep.constraint in ("", "any") and not member]
        for dep in loose:
            package = locked.get(dep.name)
            if package is not None:
                found.add(_loosened(dep, _spot_in(lock_sf, package.line, 7), package.version))
            else:
                found.add(_loosened(dep, _spot_in(pubspec_sf, dep.line, 3), ""))
        if lock_sf is None and spec.is_flutter and not member:
            found.add(_no_lock(_spot_in(pubspec_sf, spec.line_of("name"), 3)))
    return found.items


def audit_packages(packages: Iterable[Mapping[str, Any]], file_rel: str,
                   line_of: Callable[[str], int], sf: Optional[SourceFile] = None
                   ) -> List[Finding]:
    """Findings for the packages found inside an app package, given as [{name, version,
    source}]. A version that could not be read (release builds keep only package names) gives
    an info finding with confidence UNREAD_CONFIDENCE, unless an advisory affects every
    version (then the advisory's severity, confidence 0.35); git, path and sdk packages are
    not checked. `line_of(name)` is the package's line in `file_rel`; pass that file as `sf`
    so a finding shows the masked text of the line."""
    found = _Findings()
    seen = set()
    for item in packages:
        name = _scalar(item.get("name")) if isinstance(item, Mapping) else ""
        if not name or name in seen:
            continue
        seen.add(name)
        if (_scalar(item.get("source")).lower() or "hosted") != "hosted":
            continue
        version = _scalar(item.get("version"))
        line = line_of(name) or 1
        if sf is not None:
            spot = _spot_in(sf, line, 0, file_rel)
        else:
            spot = _Spot(file_rel, line, ("%s %s" % (_short(name), version[:40])).strip(), "",
                         "config")
        found.add(_vulnerable(name, spot, version=parse_version(version), in_app=True))
        found.add(_unmaintained(name, spot))
    return found.items
