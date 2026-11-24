"""Loads an Android app package for the analysis: an APK, an app bundle (.aab) or a set of
split APKs (.apks, .xapk, .apkm).

The package is decoded and read, never installed or run. Every part that holds text becomes
a virtual file of the scan, a SourceFile kept in memory whose origin tells the engines what
it is (sca/flutter/context.py):

    AndroidManifest.xml               the manifest, decoded from binary XML (protobuf XML in
                                      an app bundle), one attribute per line
    res/xml/<name>.xml                XML resources under their logical names, also when R8
                                      shortened the file names (res/8G.xml)
    res/values/strings.xml            the string resources, one per line
    assets/...                        text assets (.env files, JSON ...)
    dart/lib/<path>.dart              Dart source recovered from kernel_blob.bin (debug builds)
    lib/<abi>/libapp.so, classes.dex, lib/<abi>/<other>.so
                                      strings dumps of compiled code, one string per line
    jadx/<package path>/<Class>.java  Java decompiled by jadx (optional)
    _sca/signing.txt, _sca/build.txt, _sca/packages.txt
                                      facts written by the analyzer, so that findings about
                                      them have a file and a line

The facts (MobileContext.facts, later ScanResult.app) describe the app: package, versions,
SDK levels, Flutter build mode, engine and Dart versions, obfuscation, signing, packages.

An app package is untrusted. Each part is decoded on its own and a broken or hostile part
only adds a warning; entries are read into memory with size limits and never written to disk
under their own names. Lines of virtual files are shorter than 600 characters and hold no
control characters other than tab.
"""
from __future__ import annotations

import re
import shutil
import zlib
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..storage import data_dir
from ..walker import SourceFile, detect_language, strip_bidi
from . import aabproto, arsc, axml, dex, kernel, signing, snapshot, tools, zipread
from .context import (BUILD_FILE, ORIGIN_DECODED, ORIGIN_DECOMPILED, ORIGIN_RECOVERED,
                      ORIGIN_STRINGS, ORIGIN_SUMMARY, PACKAGES_FILE, SIGNING_FILE,
                      MobileContext)
from .xmltree import XML_HEADER, XmlNode

APP_SUFFIXES = (".apk", ".aab", ".apks", ".xapk", ".apkm")
ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")     # the ABI whose code is read

# caps against hostile packages
MAX_LINE = 599                    # longest line of a virtual file, in characters
MAX_TEXT = 64 << 20               # characters of decoded text kept from one app
MAX_XML_RESOURCES = 300
MAX_STRING_RESOURCES = 20_000
MAX_ASSETS = 2_000
MAX_ASSET_BYTES = 1 << 20
MAX_DEX_FILES = 100
MAX_DEX_LINES = 200_000           # lines of one DEX strings dump
MAX_LIBAPP_LINES = 200_000
MAX_LIB_LINES = 100_000           # lines of the strings dump of another native library
MAX_OTHER_LIBS = 10
# bytes read from one part for a decoder written in Python (real parts are far smaller)
MAX_XML_BYTES = 16 << 20          # AndroidManifest.xml or an XML resource (binary XML)
MAX_TABLE_BYTES = 64 << 20        # resources.arsc, resources.pb
MAX_DEX_BYTES = 128 << 20         # one DEX file
MAX_KERNEL_BYTES = 256 << 20      # kernel_blob.bin
MAX_LIB_BYTES = 128 << 20         # libapp.so, libflutter.so
MAX_OTHER_LIB_BYTES = 64 << 20    # another native library (only its strings are dumped)
MAX_SNAPSHOT_BYTES = 64 << 10     # the head of isolate_snapshot_data (only its header is read)
MAX_NOTICES_CHARS = 16 << 20      # NOTICES.Z inflated (and at most as many bytes read)
MAX_PACKAGES = 2_000
MAX_LISTED_SOURCES = 500          # recovered Dart files named in the facts
MAX_SIGNATURE_FILES = 16          # META-INF/*.RSA, *.DSA, *.EC read
MAX_SIGNATURE_BYTES = 1 << 20

KERNEL_BLOB = "assets/flutter_assets/kernel_blob.bin"
ISOLATE_SNAPSHOT = "assets/flutter_assets/isolate_snapshot_data"
NOTICES = ("assets/flutter_assets/NOTICES.Z", "assets/flutter_assets/NOTICES")
TEXT_EXTENSIONS = {".arb", ".cer", ".cfg", ".conf", ".config", ".crt", ".csv", ".dart",
                   ".env", ".htm", ".html", ".ini", ".js", ".json", ".key", ".md", ".mjs",
                   ".pem", ".plist", ".properties", ".rules", ".sh", ".sql", ".toml", ".txt",
                   ".xml", ".yaml", ".yml"}
# asset lists written by the Flutter tool, not by the app's developers
FLUTTER_GENERATED = {"AssetManifest.json", "AssetManifest.bin.json", "FontManifest.json",
                     "NativeAssetsManifest.json"}
# packages of the Flutter SDK: versioned with the SDK, not pub dependencies
SDK_PACKAGES = frozenset({
    "flutter", "flutter_driver", "flutter_localizations", "flutter_test", "flutter_web_plugins",
    "fuchsia_remote_debug_protocol", "integration_test", "sky_engine"})
# NOTICES.Z also lists the Flutter engine's own third-party code (the same in every app);
# these names are left out of the app's packages
ENGINE_NOTICES = frozenset({
    "accessibility", "angle", "benchmark", "boringssl", "brotli", "ceval", "colorama",
    "cpu_features", "dart", "dawn", "devtools", "engine", "equatable", "etc1", "etc_decoder",
    "expat", "fallback_root_certificates", "ffx_spd", "fiat", "flatbuffers", "freetype2",
    "fuchsia_sdk", "gif", "glfw", "glslang", "harfbuzz", "icu", "include", "inja", "io", "json",
    "khronos", "libcxx", "libcxxabi", "libjxl", "libpng", "libtess2", "libwebp", "libxml",
    "llvm_libc", "node_preamble", "observatory_pub_packages", "perfetto", "process_runner",
    "rapidjson", "re2", "root_certificates", "shaderc", "skcms", "skia", "spring_animation",
    "sqlite", "swiftshader", "tcmalloc", "test_shaders", "tonic", "txt", "volk", "vulkan",
    "vulkan_memory_allocator", "vulkanmemoryallocator", "web_locale_keymap", "web_test_fonts",
    "wuffs", "wycheproof_testvectors", "xxhash", "yapf", "yapf_diff", "zlib"})
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# characters a virtual file never holds: line breaks as str.splitlines() counts them and the
# other C0 controls except tab; lone surrogates become U+FFFD
_CONTROL = re.compile("[\x00-\x08\x0a-\x1f\x85\u2028\u2029]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_SPECIAL = re.compile("[\x00-\x08\x0a-\x1f\x85\u2028\u2029\ud800-\udfff]")
_UNSAFE_REL = re.compile(r'[\x00-\x1f\x7f#\\:*?"<>|]')
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9_.$-]")
_INT = re.compile(r"-?[0-9]{1,10}\Z")         # ASCII digits: int() takes no others
_PUB_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_PACKAGE_URI = re.compile(r"package:([a-z][a-z0-9_]{0,63})/")
_MAIN_URI = re.compile(r"package:([a-z][a-z0-9_]{0,63})/main\.dart\Z")
_BLANK_LINE = re.compile(r"\r?\n[ \t]*\r?\n")
_DEX_NAME = re.compile(r"classes([0-9]*)\.dex\Z")
_LIB = re.compile(r"lib/([^/]+)/([^/]+\.so)\Z")
_XML_RESOURCE = re.compile(r"res/(xml[^/]*)/([^/]+)\.xml\Z")
# DEX strings that are only names of types and prototypes, or binary data (Kotlin metadata)
_BINARY = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")
_DESCRIPTOR = re.compile(r"\[*(?:L[^;\s]+;|[ZBSCIJFDV])\Z")
_SHORTY = re.compile(r"[VZBSCIJFDL][ZBSCIJFDL]*\Z")
_SIGNATURE = re.compile(r"[\[(<]*L[\w$]+/[\w/$]*[;<][\w/$;<>\[*+\-:.]*\Z")
_PROTO = re.compile(r"\([^()\s]*\)\[*(?:L[^;\s]+;|[ZBSCIJFDV])\Z")
# GeneratedPluginRegistrant logs this for each plugin; R8 keeps the string
_REGISTRANT = re.compile(r"Error registering plugin ([a-z][a-z0-9_]{0,63}), ([\w.$]+)\Z")
_SIGNING_LABELS = (("v1", "v1 (JAR signing)"), ("v2", "v2 (APK Signature Scheme v2)"),
                   ("v3", "v3 (APK Signature Scheme v3)"),
                   ("v3.1", "v3.1 (APK Signature Scheme v3.1)"))


class AppError(ValueError):
    """The file is not an app package that can be read; the message is for the user."""


def is_app_package(path: Path) -> bool:
    """True for an existing file with an app package suffix and a ZIP signature."""
    path = Path(path)
    return path.suffix.lower() in APP_SUFFIXES and path.is_file() and zipread.is_zip(path)


def load_app(path: Path, use_tools: bool = False) -> MobileContext:
    """Decode an app package into virtual files and facts. use_tools also runs jadx and
    apksigner when they are installed. Raises AppError when the file is not a readable app
    package."""
    path = Path(path)
    try:
        container = zipread.open_container(path)
    except zipread.ZipError as exc:
        if not path.is_file():
            raise AppError("%s: %s" % (path.name, "not a file" if path.exists() else
                                       "no such file")) from None
        raise AppError("%s is not a readable app package: %s"
                       % (path.name, str(exc).split(": ", 1)[-1])) from None
    except Exception as exc:     # an I/O error or a bug in the reader
        raise AppError("%s is not a readable app package: %s" % (path.name, _reason(exc))) \
            from None
    with container:
        try:
            return _AppLoader(path, container).run(use_tools)
        except AppError:
            raise
        except Exception as exc:     # outside the guarded steps: a bug or an I/O error
            raise AppError("%s could not be analysed: %s" % (path.name, _reason(exc))) from None


def _reason(exc: BaseException) -> str:
    return "%s: %s" % (type(exc).__name__, str(exc)[:200])


# ------------------------------------------------------------------ text of virtual files
def clean_line(text: str) -> str:
    """A line without control characters (tab kept) and with lone surrogates replaced."""
    text = _CONTROL.sub("", text)
    return _SURROGATE.sub("\ufffd", text) if _SURROGATE.search(text) else text


def text_lines(text: str) -> List[str]:
    """Lines of a text for a virtual file: split as str.splitlines() does, cleaned, and lines
    longer than MAX_LINE split into pieces."""
    out: List[str] = []
    for line in text.splitlines():
        line = clean_line(line)
        if len(line) <= MAX_LINE:
            out.append(line)
        else:
            out.extend(line[i:i + MAX_LINE] for i in range(0, len(line), MAX_LINE))
    return out


def dump_lines(strings: Iterable[str], limit: int) -> List[str]:
    """Lines of a strings dump: one string per line; a string with line breaks or longer than
    MAX_LINE takes several lines; blank lines are dropped. At most limit lines."""
    out: List[str] = []
    for text in strings:
        if len(text) <= MAX_LINE and not _SPECIAL.search(text):
            if text.strip():
                out.append(text)
        else:
            out.extend(line for line in text_lines(text) if line.strip())
        if len(out) >= limit:
            return out[:limit]
    return out


def _xml_lines(text: str) -> List[str]:
    """Lines of rendered XML; a line too long is cut, so attribute lines stay where the
    tree says they are."""
    return [line if len(line) <= MAX_LINE else line[:MAX_LINE - 3] + "..."
            for line in text.splitlines()]


def _safe_rel(name: str) -> str:
    """A relative path made from a name in the package: no empty, "." or ".." parts, and no
    characters that file systems or the report's links do not take."""
    parts = [_UNSAFE_REL.sub("_", strip_bidi(part)) for part in name.split("/")
             if part not in ("", ".", "..")]
    return "/".join(parts) or "_"


def _int(value: Optional[str]) -> Optional[int]:
    return int(value) if value and _INT.match(value.strip()) else None


def _xml_escape(text: str, attribute: bool = False) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if attribute:
        text = text.replace('"', "&quot;")
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return clean_line(text)


def _string_lines(name: str, value: str) -> List[str]:
    """`<string name="...">...</string>` on one line, or over several lines (each shorter
    than MAX_LINE, never cut inside an entity) when the value is long."""
    line = '    <string name="%s">%s</string>' % (_xml_escape(name, True), _xml_escape(value))
    pieces, start = [], 0
    while len(line) - start > MAX_LINE:
        cut = start + MAX_LINE
        amp = line.rfind("&", cut - 6, cut)
        if amp > start and line.find(";", amp, cut) < 0:
            cut = amp
        pieces.append(line[start:cut])
        start = cut
    pieces.append(line[start:])
    return pieces


def _decode_text(data: bytes) -> Optional[str]:
    """Text of an asset, or None when it looks binary (a NUL in the first 4 KiB)."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8-sig", "replace")


def _keep_dex_string(text: str, types: Set[str]) -> bool:
    """False for DEX strings that are short, only name types and prototypes, hold binary data
    (Kotlin metadata) or are Kotlin source maps."""
    return (len(text) >= 6 and text not in types and not _DESCRIPTOR.match(text)
            and not _SHORTY.match(text) and not _SIGNATURE.match(text)
            and not _PROTO.match(text) and not _BINARY.search(text)
            and not text.startswith("SMAP\n"))


def _dex_order(name: str) -> int:
    match = _DEX_NAME.match(name)
    return int(match.group(1) or 1) if match else 0


def _abi_order(abi: str) -> Tuple[int, str]:
    return (ABI_ORDER.index(abi) if abi in ABI_ORDER else len(ABI_ORDER)), abi


def notice_names(text: str) -> List[str]:
    """Package names at the heads of the licence blocks of a Flutter NOTICES file (blocks are
    separated by a line of 80 dashes; a block starts with its package names, then a blank
    line), without the Flutter SDK and the engine's own third-party code. At most
    MAX_PACKAGES names, in the order of the file."""
    names: Dict[str, None] = {}         # a dict keeps the order and finds a name at once
    for block in text.split("-" * 80)[:20_000]:
        head = _BLANK_LINE.split(block.lstrip("\r\n"), 1)[0]
        for line in head.splitlines()[:50]:
            name = line.strip()
            if (name not in names and _PUB_NAME.match(name) and name not in ENGINE_NOTICES
                    and name not in SDK_PACKAGES):
                names[name] = None
                if len(names) >= MAX_PACKAGES:
                    return list(names)
    return list(names)


def _inflate(data: bytes, limit: int) -> str:
    """Text of a gzip or zlib stream (NOTICES.Z), at most limit characters."""
    inflater = zlib.decompressobj(32 + zlib.MAX_WBITS)
    return inflater.decompress(data, limit).decode("utf-8", "replace")


def _messages(data: memoryview, number: int) -> List[memoryview]:
    """The length-delimited fields with this number of a protobuf message."""
    return [value for field, wire, value in aabproto.iter_fields(data)
            if field == number and wire == aabproto.WIRE_BYTES]


def _proto_text(data: memoryview, number: int) -> str:
    found = _messages(data, number)
    return bytes(found[0]).decode("utf-8", "replace") if found else ""


def bundle_strings(data: bytes) -> Tuple[Dict[str, str], str]:
    """String resources of the default configuration in an app bundle's resources.pb
    (aapt.pb.ResourceTable: package 2 > type 3 with name 2 > entry 3 with name 2 >
    config_value 6 with config 1 and value 2 > item 4 > str 2, raw_str 3 or styled_str 4 >
    value 1). Returns the strings and an error ("" when the table was read)."""
    strings: Dict[str, str] = {}
    try:
        for package in _messages(memoryview(data), 2):
            for kind in _messages(package, 3):
                if _proto_text(kind, 2) != "string":
                    continue
                for entry in _messages(kind, 3):
                    name = _UNSAFE_NAME.sub("_", _proto_text(entry, 2)[:200])
                    for config_value in _messages(entry, 6):
                        if any(len(config) for config in _messages(config_value, 1)):
                            continue                    # not the default configuration
                        for value in _messages(config_value, 2):
                            for item in _messages(value, 4):
                                for number in (2, 3, 4):
                                    for string in _messages(item, number):
                                        strings.setdefault(name, _proto_text(string, 1))
                    if len(strings) >= MAX_STRING_RESOURCES:
                        return strings, ""
    except aabproto.ProtoError as exc:
        return strings, str(exc)
    return strings, ""


def _class_name(name: str, package: str) -> str:
    """A component's class name as the manifest gives it, made absolute."""
    if name.startswith("."):
        return package + name
    return name if "." in name else "%s.%s" % (package, name)


class DexSummary:
    """The decoded tables of a DEX file, without the file's bytes: what ctx.dex keeps when
    dex.DexFile cannot let its input go. It answers the calls the loader makes on a DexFile
    (name, version, size, sections, warnings, strings(), type_names(), class_defs())."""

    def __init__(self, parsed: dex.DexFile) -> None:
        self.name = parsed.name
        self.version = parsed.version
        self.size = parsed.size
        self.sections = parsed.sections
        self.warnings = list(parsed.warnings)
        self._strings = parsed.strings()
        self._types = parsed.type_names()
        self._classes = parsed.class_defs()

    def strings(self) -> List[str]:
        return self._strings

    def type_names(self) -> List[str]:
        return self._types

    def class_defs(self) -> List[Tuple[str, str, int]]:
        return self._classes


def _without_data(parsed: dex.DexFile) -> Any:
    """A parsed DEX file to keep in ctx.dex without its input bytes (up to MAX_DEX_BYTES
    each): the DexFile itself when it does not hold them or once it has released them, else
    a DexSummary."""
    release = getattr(parsed, "release", None)
    if callable(release):
        for table in (parsed.strings, parsed.type_names, parsed.class_defs):
            table()                     # decoded before the bytes go
        release()
        return parsed
    if not getattr(parsed, "_data", None):
        return parsed                   # parse_dex already let the bytes go
    return DexSummary(parsed)


# ------------------------------------------------------------------ the loader
class _AppLoader:
    """Decodes one opened app package into a MobileContext."""

    def __init__(self, path: Path, container: zipread.Container) -> None:
        self.path = path
        self.container = container
        kind = "apks" if container.kind in ("xapk", "apkm") else container.kind
        self.ctx = MobileContext(kind=kind, root=path)
        self.facts = self.ctx.facts
        self.files: List[SourceFile] = []
        self.rels: Set[str] = set()
        self.text_total = 0
        self.full = False
        # logical name (as in an installed APK) -> (archive, entry)
        self.parts: Dict[str, Tuple[zipread.ZipArchive, zipread.ZipEntry]] = {}
        self.base = dict(container.apks).get("base") or container.archive
        self.table: Optional[arsc.ResourceTable] = None
        self.libs: Dict[str, Dict[str, str]] = {}        # abi -> file name -> logical name
        self.abi = ""
        self.app_package = ""                           # Dart package of the app
        self.packages: Dict[str, Dict[str, str]] = {}
        self.notices: List[str] = []
        self.dart_channel = ""
        self.evidence = ""                              # why the build mode is what it is
        self.snapshot_note = ""                         # where a debug build's snapshot is
        self.verified_text = "not checked"

    def run(self, use_tools: bool) -> MobileContext:
        archive = self.container.archive
        self.facts.update(kind=self.ctx.kind, name=self.path.name, size_bytes=archive.size,
                          sha256=archive.sha256())
        self._index()
        if "AndroidManifest.xml" not in self.parts:
            raise AppError("%s is not an Android app package: it has no AndroidManifest.xml"
                           % self.path.name)
        for part, step in (("resources.arsc", self._resources),
                           ("AndroidManifest.xml", self._manifest),
                           ("res/xml", self._xml_resources),
                           ("res/values/strings.xml", self._strings),
                           ("assets", self._assets), ("Flutter", self._flutter),
                           ("DEX", self._dex), ("signing", self._signing),
                           ("native libraries", self._other_libs)):
            self._guard(part, step)
        if use_tools:
            self._guard("tools", self._tools)
        self._finish()
        self.ctx.files = self.files
        return self.ctx

    def _guard(self, part: str, step: Callable[[], None]) -> None:
        """Run one step; an error in a decoder becomes a warning and the rest goes on."""
        try:
            step()
        except Exception as exc:     # one broken part must not stop the analysis
            self.ctx.warn("%s: not decoded (%s: %s)" % (part, type(exc).__name__,
                                                        str(exc)[:200]))

    # -------------------------------------------------------------- package contents
    def _index(self) -> None:
        """Map the files of the package to the names they have in an installed APK: an app
        bundle's base module (base/manifest/, base/dex/, base/root/ ...); for a split set,
        the base APK and the native libraries of the splits."""
        if self.ctx.kind == "aab":
            archive = self.container.archive
            for name in archive.names():
                module, _, rest = name.partition("/")
                if module != "base" or not rest:
                    continue
                if rest == "manifest/AndroidManifest.xml":
                    logical = "AndroidManifest.xml"
                elif rest.startswith(("dex/", "root/")):
                    logical = rest.split("/", 1)[1]
                else:
                    logical = rest
                self.parts.setdefault(logical, (archive, archive.get(name)))
            for module in self.container.modules:
                if module != "base":
                    self.ctx.warn("%s: app bundle module %r is not analysed (only the base "
                                  "module is)" % (self.path.name, module))
            return
        for label, archive in self.container.apks:
            is_base = archive is self.base
            for name in archive.names():
                if is_base or name.startswith("lib/"):
                    self.parts.setdefault(name, (archive, archive.get(name)))
            if not is_base and not label.startswith("split_config."):
                self.ctx.warn("%s: %s is a feature split; only the base APK and the native "
                              "libraries of the splits are analysed" % (self.path.name, label))

    def _read(self, logical: str, limit: int, head: bool = False) -> Optional[bytes]:
        """At most limit bytes of a part (head: only its first bytes are wanted); None when
        the package does not hold it or it cannot be read (a warning)."""
        found = self.parts.get(logical)
        if found is None:
            return None
        archive, entry = found
        try:
            return archive.read(entry, limit, head)
        except zipread.ZipError as exc:
            self.ctx.warn(str(exc))
            return None

    def _add(self, rel: str, lines: List[str], origin: str, language: str,
             force: bool = False) -> Optional[SourceFile]:
        """Add a virtual file; None when the rel is taken or the text limit is reached."""
        if rel in self.rels:
            self.ctx.warn("%s: two parts of the package give this file; the first is kept" % rel)
            return None
        size = sum(len(line) + 1 for line in lines)
        if not force and self.text_total + size > MAX_TEXT:
            if not self.full:
                self.ctx.warn("the decoded text reached %d MiB; %s and later parts are left "
                              "out" % (MAX_TEXT >> 20, rel))
                self.full = True
            return None
        self.text_total += size
        text = "\n".join(lines) + "\n" if lines else ""
        source = SourceFile(Path(rel), rel, language, text, lines=list(lines), origin=origin)
        self.files.append(source)
        self.rels.add(rel)
        return source

    # -------------------------------------------------------------- Android parts
    def _resources(self) -> None:
        data = self._read("resources.arsc", MAX_TABLE_BYTES)
        if data is None:
            return
        self.table = arsc.parse_arsc(data)
        for warning in self.table.warnings:
            self.ctx.warn(warning)

    def _decode_xml(self, rel: str, data: bytes) -> Optional[axml.AxmlDocument]:
        try:
            if self.ctx.kind == "aab":
                doc = aabproto.decode_proto_xml(data)
            else:
                doc = axml.decode_axml(data, self.table.name_of if self.table else None)
        except axml.AxmlError as exc:               # aabproto.ProtoError included
            self.ctx.warn("%s: not decoded (%s)" % (rel, exc))
            return None
        for warning in doc.warnings:
            self.ctx.warn("%s: %s" % (rel, warning))
        return doc

    def _manifest(self) -> None:
        data = self._read("AndroidManifest.xml", MAX_XML_BYTES)
        doc = self._decode_xml("AndroidManifest.xml", data) if data is not None else None
        if doc is None:
            return
        self.ctx.manifests = [("AndroidManifest.xml", doc.root)]
        self._add("AndroidManifest.xml", _xml_lines(doc.text), ORIGIN_DECODED, "config")
        root = doc.root
        uses_sdk = root.find("uses-sdk")
        sdk = uses_sdk.get if uses_sdk is not None else (lambda name: None)
        self.facts.update(
            package=root.get("package") or "",
            version_name=root.get("android:versionName") or "",
            version_code=root.get("android:versionCode") or "",
            min_sdk=_int(sdk("android:minSdkVersion")),
            target_sdk=_int(sdk("android:targetSdkVersion")),
            compile_sdk=_int(root.get("android:compileSdkVersion")
                             or root.get("platformBuildVersionCode")))

    def _xml_resources(self) -> None:
        """Every XML resource of type xml as res/xml/<name>.xml (res/xml-<qualifiers>/ for
        other configurations), found through resources.arsc when the package has one, so
        that shortened file names get their logical names back."""
        found: List[Tuple[str, str, str, int]] = []     # rel, logical source, name, id
        if self.table is not None and self.table.packages:
            for entry in self.table.entries():
                if entry.type != "xml" or not entry.name:
                    continue
                for value in entry.values:
                    if value.data_type == arsc.TYPE_STRING and value.text.startswith("res/"):
                        folder = "xml-" + value.config if value.config else "xml"
                        found.append(("res/%s/%s.xml" % (folder, entry.name), value.text,
                                      "" if value.config else entry.name, entry.id))
        else:
            for name in sorted(self.parts):
                match = _XML_RESOURCE.match(name)
                if match:
                    found.append((_safe_rel(name), name,
                                  match.group(2) if match.group(1) == "xml" else "", 0))
        if len(found) > MAX_XML_RESOURCES:
            self.ctx.warn("%d XML resources; only the first %d are decoded"
                          % (len(found), MAX_XML_RESOURCES))
        # configurations of a resource can name the same file: it is decoded once
        decoded: Dict[str, Optional[Tuple[XmlNode, List[str]]]] = {}
        for rel, source, name, res_id in found[:MAX_XML_RESOURCES]:
            if rel in self.rels:
                continue
            if source not in self.parts:
                self.ctx.warn("%s: resources.arsc names %s, which the package does not hold"
                              % (rel, source))
                continue
            if source not in decoded:
                data = self._read(source, MAX_XML_BYTES)
                doc = self._decode_xml(rel, data) if data is not None else None
                decoded[source] = (doc.root, _xml_lines(doc.text)) if doc is not None else None
            document = decoded[source]
            if document is None or self._add(rel, document[1], ORIGIN_DECODED,
                                             "config") is None:
                continue
            self.ctx.xml_resources[rel] = document[0]
            if name:
                self.ctx.resource_files.setdefault("@xml/" + name, rel)
            if res_id:
                self.ctx.resource_files.setdefault("@0x%08x" % res_id, rel)

    def _strings(self) -> None:
        if self.table is not None:
            strings = self.table.strings()
        elif self.ctx.kind == "aab" and "resources.pb" in self.parts:
            data = self._read("resources.pb", MAX_TABLE_BYTES)
            strings, error = bundle_strings(data) if data is not None else ({}, "")
            if error:
                self.ctx.warn("resources.pb: %s" % error)
        else:
            return
        if not strings:
            return
        items = list(strings.items())
        if len(items) > MAX_STRING_RESOURCES:
            self.ctx.warn("%d string resources; only the first %d are listed"
                          % (len(items), MAX_STRING_RESOURCES))
        lines = [XML_HEADER, "<resources>"]
        for name, value in items[:MAX_STRING_RESOURCES]:
            lines.extend(_string_lines(name, value))
        lines.append("</resources>")
        self._add("res/values/strings.xml", lines, ORIGIN_DECODED, "config")

    def _assets(self) -> None:
        """Text assets (a text file extension or a .env name, at most MAX_ASSET_BYTES) under
        their own paths; NOTICES gives package names."""
        count = 0
        for name in sorted(self.parts):
            if not name.startswith("assets/"):
                continue
            if name in NOTICES:
                self._notices(name)
                continue
            base = name.rsplit("/", 1)[-1]
            if not (base.lower().startswith(".env")
                    or PurePosixPath(base).suffix.lower() in TEXT_EXTENSIONS):
                continue
            if name.startswith("assets/flutter_assets/") and base in FLUTTER_GENERATED:
                continue
            if self.parts[name][1].size > MAX_ASSET_BYTES:
                continue
            count += 1
            if count > MAX_ASSETS:
                self.ctx.warn("more than %d text assets; the rest are not read" % MAX_ASSETS)
                return
            data = self._read(name, MAX_ASSET_BYTES)
            text = _decode_text(data) if data is not None else None
            if text is None:
                continue
            rel = _safe_rel(name)
            self._add(rel, text_lines(text), ORIGIN_DECODED,
                      detect_language(Path(rel)) or "config")

    def _notices(self, name: str) -> None:
        data = self._read(name, MAX_NOTICES_CHARS, head=True)
        if data is None:
            return
        try:
            text = _inflate(data, MAX_NOTICES_CHARS) if name.endswith(".Z") else \
                data[:MAX_NOTICES_CHARS].decode("utf-8", "replace")
        except zlib.error as exc:
            self.ctx.warn("%s: not decoded (%s)" % (name, exc))
            return
        self.notices = notice_names(text)

    # -------------------------------------------------------------- Flutter
    def _flutter(self) -> None:
        for name in self.parts:
            match = _LIB.match(name)
            if match:
                self.libs.setdefault(match.group(1), {})[match.group(2)] = name
        abis = sorted(self.libs, key=_abi_order)
        self.facts["abis"] = abis
        self.abi = (next((abi for abi in abis if "libapp.so" in self.libs[abi]), "")
                    or next((abi for abi in abis if "libflutter.so" in self.libs[abi]), "")
                    or (abis[0] if abis else ""))
        if KERNEL_BLOB in self.parts:
            self._guard("kernel_blob.bin", self._kernel)
        if "libapp.so" in self.libs.get(self.abi, {}):
            self._guard("libapp.so", self._libapp)
        engine_abi = next((abi for abi in [self.abi] + abis
                           if "libflutter.so" in self.libs.get(abi, {})), "")
        if engine_abi:
            self._guard("libflutter.so", lambda: self._libflutter(engine_abi))

    def _kernel(self) -> None:
        data = self._read(KERNEL_BLOB, min(kernel.MAX_BLOB, MAX_KERNEL_BYTES))
        if data is None:
            return
        info = self.ctx.kernel = kernel.parse_kernel(data)
        del data
        for warning in info.warnings:
            self.ctx.warn(warning)
        self.app_package = info.main_package
        recovered: List[str] = []
        for source in kernel.app_sources(info):
            rel = _safe_rel("dart/lib/" + source.path)
            if not source.text or not source.path or rel in self.rels:
                continue
            if self._add(rel, text_lines(source.text), ORIGIN_RECOVERED, "dart"):
                recovered.append(rel)
        self.facts["dart_sources"] = {"recovered": len(recovered),
                                      "files": recovered[:MAX_LISTED_SOURCES]}
        for name, version in info.packages.items():
            self._package(name, version or "", "hosted" if version else "git", "kernel")
        data = self._read(ISOLATE_SNAPSHOT, MAX_SNAPSHOT_BYTES, head=True)
        header = snapshot.read_snapshot_header(data) if data else None
        if header is not None:
            self.facts["snapshot_hash"] = header.version_hash
            self.facts["snapshot_features"] = " ".join(header.features)
            self.snapshot_note = "JIT snapshot %s in isolate_snapshot_data" % (
                header.kind_name or header.kind)

    def _libapp(self) -> None:
        rel = "lib/%s/libapp.so" % self.abi
        data = self._read(rel, MAX_LIB_BYTES)
        if data is None:
            return
        info = self.ctx.snapshot = snapshot.analyze_libapp(data)
        del data
        for warning in info.warnings:
            self.ctx.warn(warning)
        if self._add(_safe_rel(rel), dump_lines(info.strings, MAX_LIBAPP_LINES), ORIGIN_STRINGS,
                     "config"):
            self.ctx.strings_files.append(_safe_rel(rel))
        if not self.facts.get("snapshot_hash"):
            self.facts["snapshot_hash"] = info.version_hash
            self.facts["snapshot_features"] = " ".join(info.features)
        names = [match.group(1) for match in map(_PACKAGE_URI.match, info.package_uris)
                 if match]
        if not self.app_package:            # the one package with a main.dart is the app
            mains = {match.group(1) for match in map(_MAIN_URI.match, info.package_uris)
                     if match and match.group(1) not in SDK_PACKAGES}
            self.app_package = mains.pop() if len(mains) == 1 else ""
        for name in dict.fromkeys(names):
            self._package(name, "", "hosted", "snapshot")

    def _libflutter(self, abi: str) -> None:
        data = self._read("lib/%s/libflutter.so" % abi, MAX_LIB_BYTES)
        if data is None:
            return
        info = self.ctx.engine = snapshot.analyze_libflutter(data)
        for warning in info.warnings:
            self.ctx.warn(warning)
        self.facts["dart_version"] = info.dart_version
        self.facts["engine_revision"] = info.engine_revision
        self.dart_channel = info.channel

    def _package(self, name: str, version: str, source: str, found_in: str) -> None:
        """Record a package the app was built with; the first source that names it wins."""
        if (name and name not in SDK_PACKAGES and name not in self.packages
                and len(self.packages) < MAX_PACKAGES):
            self.packages[name] = {"name": name, "version": version, "source": source,
                                   "found_in": found_in}

    # -------------------------------------------------------------- DEX
    def _dex(self) -> None:
        names = sorted((name for name in self.parts if _DEX_NAME.match(name)), key=_dex_order)
        if len(names) > MAX_DEX_FILES:
            self.ctx.warn("%d DEX files; only the first %d are read" % (len(names), MAX_DEX_FILES))
        plugins: Set[str] = set()
        for name in names[:MAX_DEX_FILES]:
            data = self._read(name, MAX_DEX_BYTES)
            if data is None:
                continue
            parsed = dex.parse_dex(data, name)
            del data
            for warning in parsed.warnings:
                self.ctx.warn(warning)
            parsed = _without_data(parsed)      # the DEX bytes are not kept for the scan
            self.ctx.dex.append(parsed)
            strings = parsed.strings()
            types = set(parsed.type_names())
            lines = dump_lines((text for text in strings if _keep_dex_string(text, types)),
                               MAX_DEX_LINES)
            if self._add(name, lines, ORIGIN_STRINGS, "config"):
                self.ctx.strings_files.append(name)
            for text in strings:
                match = _REGISTRANT.match(text) if text.startswith("Error registering") else None
                if match:
                    self._package(match.group(1), "", "hosted", "plugin")
                    plugins.add(match.group(2))
        if not self.ctx.dex:
            return
        plugins.update(dex.plugin_classes(self.ctx.dex))
        self.facts["plugins"] = sorted(plugins)
        self.facts["flutter_markers"] = dex.flutter_markers(self.ctx.dex)
        self.facts["dex"] = {"files": len(self.ctx.dex),
                             "classes": sum(len(d.class_defs()) for d in self.ctx.dex),
                             "strings": sum(len(d.strings()) for d in self.ctx.dex)}

    # -------------------------------------------------------------- signing
    def _signing(self) -> None:
        archive = self.base
        v1: Dict[str, bytes] = {}
        for entry in archive.entries:
            name = entry.name
            if (name.count("/") == 1 and name.upper().startswith("META-INF/")
                    and name.lower().endswith(signing.V1_EXTENSIONS) and name not in v1):
                if len(v1) == MAX_SIGNATURE_FILES:
                    self.ctx.warn("signing: more than %d signature files in META-INF; the rest "
                                  "are not read" % MAX_SIGNATURE_FILES)
                    break
                try:
                    v1[name] = archive.read(entry, MAX_SIGNATURE_BYTES)
                except zipread.ZipError as exc:
                    self.ctx.warn(str(exc))
        if archive.path:
            info = signing.read_signatures(archive.path, v1)
        else:                       # an APK inside a set: read in place, not copied
            with archive.open_raw() as raw:
                info = signing.read_signatures(raw, v1)
        self.ctx.signing = info
        for warning in info.warnings:
            self.ctx.warn(warning)
        self.facts["signing"] = {"schemes": list(info.schemes),
                                 "certificates": [cert.as_dict() for cert in info.signers],
                                 "verified": None}

    # -------------------------------------------------------------- other native code
    def _other_libs(self) -> None:
        """ASCII strings of the other native libraries of the ABI that is read."""
        names = sorted(name for name in self.libs.get(self.abi, {})
                       if name not in ("libapp.so", "libflutter.so")
                       and not name.startswith("libVkLayer"))
        if len(names) > MAX_OTHER_LIBS:
            self.ctx.warn("%d other native libraries; only the first %d are read"
                          % (len(names), MAX_OTHER_LIBS))
        for name in names[:MAX_OTHER_LIBS]:
            logical = self.libs[self.abi][name]
            data = self._read(logical, MAX_OTHER_LIB_BYTES)
            if data is None:
                continue
            strings = dict.fromkeys(snapshot.ascii_strings(data, limit=MAX_LIB_LINES))
            rel = _safe_rel(logical)
            if self._add(rel, dump_lines(strings, MAX_LIB_LINES), ORIGIN_STRINGS, "config"):
                self.ctx.strings_files.append(rel)

    # -------------------------------------------------------------- optional tools
    def _tools(self) -> None:
        notes = self.facts.setdefault("tools", {})
        work = data_dir() / "apps" / self.facts["sha256"][:12]
        available = tools.availability()
        if self.ctx.kind == "aab":
            notes["apksigner"] = "not run: apksigner reads APK files only"
            self.verified_text = "not checked (apksigner reads APK files only)"
        elif not available["apksigner"]:
            notes["apksigner"] = tools.NOT_INSTALLED["apksigner"]
            self.verified_text = "not checked (apksigner is not installed)"
        else:
            notes["apksigner"] = self._verify(work / "verify")
        if not available["jadx"]:
            notes["jadx"] = tools.NOT_INSTALLED["jadx"]
        else:
            notes["jadx"] = self._decompile(work)

    def _verify(self, folder: Path) -> str:
        """Verify the (base) APK's signature with apksigner, on a copy the analyzer made."""
        folder.mkdir(parents=True, exist_ok=True)
        copy = folder / "base.apk"
        try:
            if self.base.path:
                shutil.copyfile(self.base.path, copy)
            else:                   # an APK inside a set: copied in blocks
                with self.base.open_raw() as raw, open(copy, "wb") as out:
                    shutil.copyfileobj(raw, out, 1 << 20)
            verified, note = tools.apksigner_verify(copy)
        finally:
            shutil.rmtree(folder, ignore_errors=True)
        if isinstance(self.facts.get("signing"), dict):
            self.facts["signing"]["verified"] = verified
        if verified:
            self.verified_text = "yes"
        elif verified is False:
            reason = re.search(r"does not verify: (.*)\)\Z", note)
            self.verified_text = "no: %s" % (reason.group(1) if reason else note)
        else:
            self.verified_text = "not checked (%s)" % note
        return note

    def _wanted_classes(self) -> List[str]:
        """The manifest package (every class under it) and the classes of the application
        and of its components."""
        if not self.ctx.manifests:
            return []
        root = self.ctx.manifests[0][1]
        package = root.get("package") or ""
        wanted = {package + ".*"} if package else set()
        application = root.find("application")
        if application is not None:
            for node in [application] + [child for child in application.children
                                         if child.tag in COMPONENT_TAGS]:
                name = (node.get("android:name") or "").strip()
                if name and (package or "." in name.strip(".")):
                    wanted.add(_class_name(name, package))
        return sorted(wanted)

    def _decompile(self, work: Path) -> str:
        """Decompile the app's own classes with jadx and add them as Java files."""
        wanted = self._wanted_classes()
        exact = {name for name in wanted if not name.endswith(".*")}
        prefixes = tuple(name[:-1] for name in wanted if name.endswith(".*"))

        def defines_wanted(parsed: Any) -> bool:
            return any(java in exact or java.startswith(prefixes)
                       for java in (dex.descriptor_to_java(d) for d, _, _ in parsed.class_defs()))

        inputs = [parsed.name for parsed in self.ctx.dex if defines_wanted(parsed)]
        if not inputs:
            return "ok (no class of the app in the DEX files)"
        folder = work / "jadx-input"
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True, exist_ok=True)
        try:
            for name in inputs:
                data = self._read(name, MAX_DEX_BYTES)
                if data is not None:
                    (folder / name).write_bytes(data)
            files, note = tools.jadx_decompile(folder, work / "jadx", wanted)
        finally:
            shutil.rmtree(folder, ignore_errors=True)
        for path in files:
            rel = _safe_rel("jadx/" + path.relative_to(work / "jadx").as_posix())
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.ctx.warn("%s: not read (%s)" % (rel, exc))
                continue
            self._add(rel, text_lines(text), ORIGIN_DECOMPILED, "java")
        return note

    # -------------------------------------------------------------- facts and summaries
    def _finish(self) -> None:
        self._guard("facts", self._build_facts)
        for rel, lines in ((SIGNING_FILE, self._signing_lines),
                           (BUILD_FILE, self._build_lines),
                           (PACKAGES_FILE, self._package_lines)):
            self._guard(rel, lambda rel=rel, lines=lines: self._summary(rel, lines()))

    def _summary(self, rel: str, lines: List[str]) -> None:
        self._add(rel, [clean_line(line)[:MAX_LINE] for line in lines], ORIGIN_SUMMARY,
                  "config", force=True)
        archives = [self.container.archive] + [a for _, a in self.container.apks
                                               if a is not self.container.archive]
        for warning in self.container.warnings + [w for a in archives for w in a.warnings]:
            self.ctx.warn(warning)

    def _build_facts(self) -> None:
        facts, info = self.facts, self.ctx.snapshot
        kernel_present = KERNEL_BLOB in self.parts
        markers = facts.get("flutter_markers") or {}
        flutter = bool(kernel_present or any({"libapp.so", "libflutter.so"} & set(files)
                                             for files in self.libs.values())
                       or markers.get("flutter")
                       or any(name.startswith("assets/flutter_assets/") for name in self.parts))
        facts["flutter"] = flutter
        mode, self.evidence = "unknown", ""
        if kernel_present:
            mode = "debug"
            self.evidence = "kernel_blob.bin holds the Dart program (JIT debug build)"
        elif info is not None:
            mode = info.build_mode
            self.evidence = ('snapshot features start with "%s"' % info.features[0]
                             if info.features else "libapp.so has no Dart snapshot header")
        elif flutter:
            self.evidence = "the package holds neither kernel_blob.bin nor libapp.so"
        facts["build_mode"] = mode
        if flutter:
            for key in ("dart_version", "engine_revision", "snapshot_hash", "snapshot_features"):
                facts.setdefault(key, "")
            facts.setdefault("dart_sources", {"recovered": 0, "files": []})
            if kernel_present:
                facts["obfuscated"] = False
                facts["obfuscation_note"] = "debug build: the Dart source is in kernel_blob.bin"
            else:
                facts["obfuscated"] = info.obfuscation.obfuscated if info else None
                facts["obfuscation_note"] = info.obfuscation.note if info else "no libapp.so"
            facts["debug_symbols"] = bool(info and info.symbols_present)
        if not kernel_present and (info is None or info.obfuscation.obfuscated):
            # only when the code does not name its packages: NOTICES also lists
            # development packages, which are not in the app
            for name in self.notices:
                self._package(name, "", "hosted", "notices")
        self.packages.pop(self.app_package, None)
        self.ctx.packages = [self.packages[name] for name in sorted(self.packages)]
        facts["packages"] = [dict(item) for item in self.ctx.packages]

    def _signing_lines(self) -> List[str]:
        info = self.ctx.signing
        if info is None:
            return ["Signature schemes: unknown (the signatures could not be read)",
                    "Signature verified by apksigner: %s" % self.verified_text]
        lines = ["Signature schemes: %s" % (", ".join(info.schemes) or "none")]
        lines += ["%s: %s" % (label, "yes" if scheme in info.schemes else "no")
                  for scheme, label in _SIGNING_LABELS]
        for number, cert in enumerate(info.signers, 1):
            key = ("%s %d bits" % (cert.key_algorithm, cert.key_bits) if cert.key_bits
                   else cert.key_algorithm or "unknown")
            lines += ["Signer %d subject: %s" % (number, cert.subject),
                      "Signer %d issuer: %s" % (number, cert.issuer),
                      "Signer %d certificate SHA-256: %s" % (number, cert.sha256),
                      "Signer %d valid: %s to %s" % (number, cert.valid_from or "unknown",
                                                    cert.valid_to or "unknown"),
                      "Signer %d key: %s" % (number, key),
                      "Signer %d signature algorithm: %s" % (number, cert.signature_algorithm)]
        lines.append("Signature verified by apksigner: %s" % self.verified_text)
        return lines

    def _build_lines(self) -> List[str]:
        facts, info = self.facts, self.ctx.snapshot
        flutter = facts.get("flutter")
        lines = ["Flutter app: %s" % ("yes" if flutter else "no")]
        if flutter:
            lines += ["Build mode: %s" % facts.get("build_mode", "unknown"),
                      "Build mode evidence: %s" % (self.evidence or "unknown")]
        lines.append("ABIs: %s" % (", ".join(facts.get("abis") or []) or "none"))
        if not flutter:
            return lines
        version = facts.get("dart_version") or "unknown"
        if facts.get("dart_version") and self.dart_channel:
            version = "%s (%s)" % (version, self.dart_channel)
        if facts.get("build_mode") == "debug":
            obfuscation = "no (debug build: the Dart source is in kernel_blob.bin)"
        elif info is None:
            obfuscation = "unknown (no libapp.so)"
        elif info.obfuscation.obfuscated is None:
            obfuscation = "unknown (%s)" % (info.obfuscation.note or "not judged")
        else:
            obfuscation = "%s (%d package: URIs, %d short private names)" % (
                "yes" if info.obfuscation.obfuscated else "no",
                info.obfuscation.package_uri_count, info.obfuscation.short_private_names)
        kernel_info = self.ctx.kernel
        if kernel_info is not None:
            kernel_text = "%d sources" % len(kernel_info.sources)
        else:
            kernel_text = "not readable" if KERNEL_BLOB in self.parts else "not present"
        features = facts.get("snapshot_features") or "unknown"
        if self.snapshot_note:
            features += " (%s)" % self.snapshot_note
        lines += ["Dart version: %s" % version,
                  "Flutter engine revision: %s" % (facts.get("engine_revision") or "unknown"),
                  "Snapshot hash: %s" % (facts.get("snapshot_hash") or "unknown"),
                  "Snapshot features: %s" % features,
                  "Dart obfuscation: %s" % obfuscation,
                  "Debug symbols in libapp.so: %s" % (
                      "no libapp.so" if info is None else
                      "yes" if info.symbols_present else "no"),
                  "Dart kernel (kernel_blob.bin): %s" % kernel_text,
                  "Dart sources recovered: %d" % (facts.get("dart_sources") or {}).get(
                      "recovered", 0)]
        if kernel_info is not None:
            lines += ["Build path: %s" % path for path in kernel_info.build_paths[:20]]
        return lines

    def _package_lines(self) -> List[str]:
        return ["%s %s (%s)" % (item["name"], item["version"] or "unknown", item["found_in"])
                for item in self.ctx.packages]
