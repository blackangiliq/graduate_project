"""What the loaders hand to the checks: one object per scanned app package or project.

    load_app(path)              an .apk/.aab/.apks file  -> MobileContext(kind="apk", ...)
    load_project(root, files)   a Flutter/Android folder -> MobileContext(kind="flutter-project", ...)
    analyze(ctx, by_rel)        the structural checks read it and return findings

For an app package every file of the scan is virtual: decoded from the package and kept in
memory (``files``). For a project the files come from the normal folder walk and ``files``
only holds placeholders for binary files a finding must point to (keystores).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:  # imported for type hints only
    from ..walker import SourceFile
    from .xmltree import XmlNode

APP_KINDS = ("apk", "aab", "apks", "xapk", "apkm")   # the kinds zipread.open_container returns
PROJECT_KINDS = ("flutter-project", "android-project")

# origin of a SourceFile (sca/walker.py): where its text came from
ORIGIN_DISK = ""                  # read from the scanned folder
ORIGIN_DECODED = "decoded"        # decoded from an app package (manifest, res/xml, assets)
ORIGIN_RECOVERED = "recovered"    # Dart source recovered from kernel_blob.bin (debug builds)
ORIGIN_DECOMPILED = "decompiled"  # Java written by jadx (optional tool)
ORIGIN_STRINGS = "strings"        # strings dump of a binary (libapp.so, classes.dex, other .so)
ORIGIN_SUMMARY = "summary"        # _sca/*.txt: facts written by the analyzer itself
ORIGIN_PLACEHOLDER = "placeholder"  # stands for a binary file on disk (a keystore)

# Which engines and measures use a file of each origin.
RULES_ORIGINS = (ORIGIN_DISK, ORIGIN_DECODED, ORIGIN_RECOVERED, ORIGIN_DECOMPILED)
SECRETS_ORIGINS = RULES_ORIGINS + (ORIGIN_STRINGS,)
KLOC_ORIGINS = RULES_ORIGINS                    # lines that count for the project score
AI_ORIGINS = RULES_ORIGINS                      # files the ML classifier and the LLM may see

SIGNING_FILE = "_sca/signing.txt"
BUILD_FILE = "_sca/build.txt"
PACKAGES_FILE = "_sca/packages.txt"


@dataclass
class MobileContext:
    """Everything the loaders found in one app package or project."""

    kind: str                                   # one of APP_KINDS or PROJECT_KINDS
    root: Path                                  # the app package file or the project folder
    files: List["SourceFile"] = field(default_factory=list)  # added to the scan's file list
    facts: Dict[str, Any] = field(default_factory=dict)      # JSON-safe; becomes ScanResult.app
    # --- Android ---
    manifests: List[Tuple[str, "XmlNode"]] = field(default_factory=list)  # (rel, root) release manifests
    # rels of the manifests above that belong to Android library modules (plugins): their
    # components and permissions are merged into the app, but their <application> attributes
    # and SDK levels are not the app's
    library_manifests: List[str] = field(default_factory=list)
    xml_resources: Dict[str, "XmlNode"] = field(default_factory=dict)    # rel -> res/xml document
    resource_files: Dict[str, str] = field(default_factory=dict)         # "@xml/name" -> rel
    gradle_files: List[str] = field(default_factory=list)                # app-level build.gradle(.kts)
    key_properties: List[str] = field(default_factory=list)
    keystores: List[str] = field(default_factory=list)                   # rel of placeholder files
    # --- iOS ---
    plists: List[str] = field(default_factory=list)                      # Info.plist files
    # --- Flutter / Dart ---
    pubspecs: List[Tuple[str, Optional[str]]] = field(default_factory=list)  # (pubspec.yaml, pubspec.lock or None)
    packages: List[Dict[str, Any]] = field(default_factory=list)         # [{name, version, source}] (apps)
    # --- decoded binaries (apps only; objects of the sca.flutter decoder modules) ---
    signing: Any = None               # signing.SigningInfo
    snapshot: Any = None              # snapshot.SnapshotInfo (release/profile builds)
    engine: Any = None                # snapshot.EngineInfo (from libflutter.so)
    kernel: Any = None                # kernel.KernelInfo (debug builds)
    dex: List[Any] = field(default_factory=list)                         # dex.DexFile objects
    strings_files: List[str] = field(default_factory=list)               # rel of strings dumps
    warnings: List[str] = field(default_factory=list)                    # decoder anomalies

    @property
    def is_app(self) -> bool:
        return self.kind in APP_KINDS

    @property
    def is_flutter(self) -> bool:
        return bool(self.facts.get("flutter"))

    def warn(self, message: str) -> None:
        """Record a decoder anomaly once (also shown in the report's app facts)."""
        if message and message not in self.warnings and len(self.warnings) < 100:
            self.warnings.append(message)
            self.facts.setdefault("warnings", [])
            if message not in self.facts["warnings"]:
                self.facts["warnings"].append(message)


def find_line(sf: "SourceFile", text: str, start: int = 1, occurrence: int = 1) -> int:
    """The 1-based line of the ``occurrence``-th line at or after ``start`` that contains
    ``text``; 0 if there is none."""
    seen = 0
    for number in range(max(1, start), len(sf.lines) + 1):
        if text in sf.lines[number - 1]:
            seen += 1
            if seen == occurrence:
                return number
    return 0
