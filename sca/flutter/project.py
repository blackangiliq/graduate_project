"""Flutter and Android source projects: finds what the structural checks read in a scanned
folder (release manifests, XML resources, app-level Gradle files, key.properties, Info.plist
files, pubspec files, keystores) and the project's facts.

load_project() returns None for a folder that holds neither a Flutter app (a pubspec.yaml
that depends on the Flutter SDK) nor an Android module (src/main/AndroidManifest.xml next to
a build.gradle or build.gradle.kts). The files come from the normal folder walk; only
keystores, which the walk leaves out as binary files, are added as placeholder files so that
a finding can point to them.

The release manifests are those of src/main and of every other source set that a release
build merges (src/release, product flavors such as src/prod or src/prodRelease); debug,
profile and test source sets are only listed in the facts. Manifests of Android library
modules (plugins) are kept too and also listed in ctx.library_manifests: their components
are merged into the app, but their <application> attributes and SDK levels are not the app's.
"""
from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..walker import SKIP_DIRS, SourceFile
from . import pubspec
from .apk import AppError
from .context import ORIGIN_PLACEHOLDER, MobileContext
from .xmltree import XmlNode, parse_xml_text

MAX_PUBSPECS = 50
MAX_KEYSTORES = 50
MAX_WALK_FILES = 200_000          # files looked at when searching for keystores
KEYSTORE_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx")
KEY_PROPERTIES = ("key.properties", "keystore.properties")
PLATFORMS = ("android", "ios", "web", "macos", "linux", "windows")
DEBUG_SETS = ("debug", "profile")
BUILD_FILES = ("build.gradle", "build.gradle.kts")
KEYSTORE_TEXT = "Binary keystore file (%d bytes): it holds an app signing key."
TARGET_SDK_DEFAULT_NOTE = "not set: Android uses the minSdk level"

_MANIFEST = re.compile(r"(?:(.*)/)?src/([^/]+)/AndroidManifest\.xml\Z")
_XML_RESOURCE = re.compile(r"(?:(.*)/)?src/([^/]+)/res/(xml[^/]*)/([^/]+)\.xml\Z")
# source sets that are not in a release build: debug and profile builds, tests, and their
# combinations with product flavors (prodDebug, testProdRelease); every other source set
# (main, release, a flavor such as prod, prodRelease) is merged into some release build
_NOT_RELEASE_SET = re.compile(r"(?i)(?:debug|profile|test\w*|androidTest\w*|\w*Debug|\w*Profile)"
                              r"\Z")
_TEST_SET = re.compile(r"(?i)(?:test|androidTest)\w*\Z")
# a number in ASCII digits: str.isdigit() is also true for superscripts, which int() refuses
_ASCII_INT = re.compile(r"[0-9]{1,10}\Z")
# Gradle (Groovy and Kotlin DSL): strings are kept, comments dropped before values are read;
# a comment that is never closed runs to the end of the text
_GRADLE_TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*'
                           r'|/\*.*?(?:\*/|\Z)', re.S)
_GRADLE_STRING = r"""\s*(?:=\s*|\(\s*)?["']([^"'\n]+)["']"""
_GRADLE_VALUE = r"\s*(?:=\s*|\(\s*)?([A-Za-z0-9_.]+)"
_APPLICATION_ID = re.compile(r"(?<![\w.])applicationId" + _GRADLE_STRING)
_NAMESPACE = re.compile(r"(?<![\w.])namespace" + _GRADLE_STRING)
_VERSION_NAME = re.compile(r"(?<![\w.])versionName" + _GRADLE_STRING)
_VERSION_CODE = re.compile(r"(?<![\w.])versionCode" + _GRADLE_VALUE)
_MIN_SDK = re.compile(r"(?<![\w.])minSdk(?:Version)?" + _GRADLE_VALUE)
_TARGET_SDK = re.compile(r"(?<![\w.])targetSdk(?:Version)?" + _GRADLE_VALUE)
_COMPILE_SDK = re.compile(r"(?<![\w.])compileSdk(?:Version)?" + _GRADLE_VALUE)
_APPLICATION_PLUGIN = re.compile(r"com\.android\.application|\bapplicationId\b")
# the Android library plugin: apply plugin: 'com.android.library', id("com.android.library"),
# or a version catalog alias such as alias(libs.plugins.android.library)
_LIBRARY_PLUGIN = re.compile(r"com\.android\.library\b"
                             r"|\balias\s*\(\s*libs\.plugins\.android[._-]?library\s*\)", re.I)


def load_project(root: Path, files: List[SourceFile],
                 exclude_dirs: Sequence[str] = ()) -> Optional[MobileContext]:
    """The Flutter or Android project in a scanned folder, or None when there is none.
    files are the walked files of the scan; exclude_dirs are the folder names the scan
    skips (also skipped when searching for keystores). Each part is read on its own: one
    that cannot be read only adds a warning. Raises nothing but AppError."""
    try:
        return _load(Path(root), files, exclude_dirs)
    except Exception as exc:     # outside the guarded steps: a bug must not end the scan
        raise AppError("%s: the project could not be read (%s: %s)"
                       % (Path(root).name, type(exc).__name__, str(exc)[:200])) from None


def _load(root: Path, files: List[SourceFile],
          exclude_dirs: Sequence[str]) -> Optional[MobileContext]:
    by_rel = {source.rel: source for source in files}
    problems: List[str] = []
    specs = _pubspecs(by_rel, problems)
    manifests = _manifest_files(by_rel)
    modules = sorted({module for module, source_set in manifests.values() if source_set == "main"
                      and any(_join(module, name) in by_rel for name in BUILD_FILES)})
    flutter_specs = [rel for rel, spec in specs.items() if spec.is_flutter]
    if not flutter_specs and not modules:
        return None
    main_spec = min(flutter_specs, key=lambda rel: (rel.count("/"), not specs[rel].is_app, rel),
                    default="")
    project_dir = main_spec.rpartition("/")[0]
    kind = "flutter-project" if main_spec else "android-project"
    ctx = MobileContext(kind=kind, root=root)
    ctx.facts.update(kind=kind, flutter=bool(main_spec))
    for problem in problems:
        ctx.warn(problem)
    app_module = _join(project_dir, "android/app") if main_spec else ""
    _guard(ctx, "Android modules", lambda: _android(ctx, by_rel, manifests, app_module))
    _guard(ctx, "project files", lambda: _project_files(ctx, by_rel, specs))
    _guard(ctx, "keystores", lambda: _add_keystores(ctx, root, exclude_dirs))
    _guard(ctx, "facts", lambda: _facts(ctx, by_rel, specs, main_spec, project_dir))
    return ctx


def _guard(ctx: MobileContext, part: str, step: Callable[[], None]) -> None:
    """Run one step; an error becomes a warning and the rest goes on."""
    try:
        step()
    except Exception as exc:     # one broken part must not stop the analysis
        ctx.warn("%s: not read (%s: %s)" % (part, type(exc).__name__, str(exc)[:200]))


def _project_files(ctx: MobileContext, by_rel: Dict[str, SourceFile],
                   specs: Dict[str, pubspec.Pubspec]) -> None:
    ctx.key_properties = sorted(rel for rel in by_rel
                                if rel.rsplit("/", 1)[-1].lower() in KEY_PROPERTIES)
    ctx.plists = sorted(rel for rel in by_rel if rel.rsplit("/", 1)[-1] == "Info.plist"
                        and {"ios", "macos"} & set(rel.split("/")[:-1]))
    ctx.pubspecs = [(rel, _lock_for(rel, specs[rel], by_rel)) for rel in sorted(specs)]


def _add_keystores(ctx: MobileContext, root: Path, exclude_dirs: Sequence[str]) -> None:
    for rel, size in _keystores(root, exclude_dirs):
        ctx.files.append(SourceFile(Path(rel), rel, "config", KEYSTORE_TEXT % size + "\n",
                                    origin=ORIGIN_PLACEHOLDER))
        ctx.keystores.append(rel)


def _join(folder: str, name: str) -> str:
    return "%s/%s" % (folder, name) if folder else name


def _pubspecs(by_rel: Dict[str, SourceFile], problems: List[str]) -> Dict[str, pubspec.Pubspec]:
    rels = sorted(rel for rel in by_rel if rel.rsplit("/", 1)[-1] == "pubspec.yaml")
    specs: Dict[str, pubspec.Pubspec] = {}
    for rel in rels[:MAX_PUBSPECS]:
        try:
            specs[rel] = pubspec.parse_pubspec(by_rel[rel].text)
        except Exception as exc:     # parse_pubspec reports errors; a bug must not stop the rest
            problems.append("%s: not read (%s: %s)" % (rel, type(exc).__name__, str(exc)[:200]))
    return specs


def _lock_for(rel: str, spec: pubspec.Pubspec, by_rel: Dict[str, SourceFile]) -> Optional[str]:
    """pubspec.lock next to a pubspec.yaml; for a member of a pub workspace, the lock of the
    nearest folder above it."""
    folder = rel.rpartition("/")[0]
    lock = _join(folder, "pubspec.lock")
    if lock in by_rel:
        return lock
    while spec.resolution == "workspace" and folder:
        folder = folder.rpartition("/")[0]
        lock = _join(folder, "pubspec.lock")
        if lock in by_rel:
            return lock
    return None


def _manifest_files(by_rel: Dict[str, SourceFile]) -> Dict[str, Tuple[str, str]]:
    """AndroidManifest.xml files of Android source sets: rel -> (module folder, source set)."""
    found = {}
    for rel in sorted(by_rel):
        match = _MANIFEST.match(rel)
        if match:
            found[rel] = (match.group(1) or "", match.group(2))
    return found


def _parse(ctx: MobileContext, source: SourceFile) -> Optional[XmlNode]:
    root, error = parse_xml_text(source.text)
    if root is None:
        ctx.warn("%s: not parsed (%s)" % (source.rel, error))
    return root


def _android(ctx: MobileContext, by_rel: Dict[str, SourceFile],
             manifests: Dict[str, Tuple[str, str]], app_module: str) -> None:
    """Release manifests (src/main and every source set merged into a release build: release,
    product flavors such as src/prod), their modules' XML resources and app-level Gradle
    files. The Flutter app module (android/app) comes first, library modules (plugins) last;
    their manifests are also listed in ctx.library_manifests and their Gradle files are not
    app-level. In a module, src/main comes first."""
    codes = {rel: _code(by_rel[rel].text) for rel in sorted(
        {_join(module, name) for module, _ in manifests.values() for name in BUILD_FILES}
        & by_rel.keys())}
    libraries = {module for module, _ in manifests.values() if _is_library(module, codes)}

    def order(item: Tuple[str, Tuple[str, str]]) -> Tuple[bool, bool, str, bool, str]:
        rel, (module, source_set) = item
        return (module != app_module, module in libraries, _join(module, "src/"),
                source_set != "main", rel)

    release_modules: List[str] = []
    debug: List[str] = []
    for rel, (module, source_set) in sorted(manifests.items(), key=order):
        if _NOT_RELEASE_SET.match(source_set):
            if source_set in DEBUG_SETS or not _TEST_SET.match(source_set):
                debug.append(rel)
            continue
        root = _parse(ctx, by_rel[rel])
        if root is not None:
            ctx.manifests.append((rel, root))
            if module in libraries:
                ctx.library_manifests.append(rel)
        if module not in release_modules:
            release_modules.append(module)
    if debug:
        ctx.facts["debug_manifests"] = debug
    resources = sorted(((rel, match) for rel, match in ((rel, _XML_RESOURCE.match(rel))
                                                         for rel in by_rel) if match),
                       key=lambda item: (item[1].group(2) != "main", item[0]))
    for module in release_modules:
        for rel, match in resources:
            if (match.group(1) or "") != module or _NOT_RELEASE_SET.match(match.group(2)):
                continue
            root = _parse(ctx, by_rel[rel])
            if root is None:
                continue
            ctx.xml_resources[rel] = root
            if match.group(3) == "xml":
                ctx.resource_files.setdefault("@xml/" + match.group(4), rel)
    builds = [_join(module, name) for module in release_modules if module not in libraries
              for name in BUILD_FILES if _join(module, name) in codes]
    apps = [rel for rel in builds if _APPLICATION_PLUGIN.search(codes[rel])]
    ctx.gradle_files = apps or builds


def _is_library(module: str, codes: Dict[str, str]) -> bool:
    """True when the module's Gradle file applies the Android library plugin (and not the
    application plugin): a plugin or library, whose manifest is merged into an app."""
    texts = [codes[rel] for rel in (_join(module, name) for name in BUILD_FILES) if rel in codes]
    return (any(_LIBRARY_PLUGIN.search(text) for text in texts)
            and not any(_APPLICATION_PLUGIN.search(text) for text in texts))


def _library_package(ctx: MobileContext, by_rel: Dict[str, SourceFile]) -> str:
    """The namespace (or manifest package) of the first library module: the package of a
    project that holds libraries only."""
    libraries = set(ctx.library_manifests)
    for rel, root in ctx.manifests:
        match = _MANIFEST.match(rel) if rel in libraries else None
        if match is None:
            continue
        for name in BUILD_FILES:
            gradle = by_rel.get(_join(match.group(1) or "", name))
            found = _NAMESPACE.search(_code(gradle.text)) if gradle is not None else None
            if found:
                return found.group(1)
        if root.get("package"):
            return root.get("package") or ""
    return ""


def _code(text: str) -> str:
    """Gradle text without comments."""
    return _GRADLE_TOKEN.sub(lambda m: m.group() if m.group()[0] in "\"'" else " ", text)


def _keystores(root: Path, exclude_dirs: Sequence[str]) -> List[Tuple[str, int]]:
    """(rel, size) of keystore files under root, in a bounded walk that skips the folders
    the scan skips."""
    if not root.is_dir():
        return []
    skip = SKIP_DIRS | {name.strip().lower() for name in exclude_dirs if name.strip()}
    found: List[Tuple[str, int]] = []
    seen = 0
    for folder, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name.lower() not in skip)
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_WALK_FILES or len(found) >= MAX_KEYSTORES:
                return found
            if not name.lower().endswith(KEYSTORE_SUFFIXES):
                continue
            path = Path(folder) / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            found.append((path.relative_to(root).as_posix(), size))
    return found


def _facts(ctx: MobileContext, by_rel: Dict[str, SourceFile], specs: Dict[str, pubspec.Pubspec],
           main_spec: str, project_dir: str) -> None:
    facts = ctx.facts
    spec = specs.get(main_spec)
    facts.update(kind=ctx.kind, flutter=bool(spec))
    gradle = _code(by_rel[ctx.gradle_files[0]].text) if ctx.gradle_files else ""
    libraries = set(ctx.library_manifests)
    manifest = next((root for rel, root in ctx.manifests if rel not in libraries), None)

    def gradle_value(pattern: "re.Pattern[str]") -> str:
        match = pattern.search(gradle)
        return match.group(1) if match else ""

    facts["name"] = (spec.name if spec and spec.name else
                     PurePosixPath(project_dir).name or ctx.root.name)
    facts["package"] = (gradle_value(_APPLICATION_ID) or gradle_value(_NAMESPACE)
                        or (manifest.get("package") if manifest is not None else "")
                        or _library_package(ctx, by_rel) or (spec.name if spec else ""))
    version_name, _, version_code = (spec.version if spec else "").partition("+")
    if not version_name:
        version_name = gradle_value(_VERSION_NAME) or (
            manifest.get("android:versionName", "") if manifest is not None else "")
        code = gradle_value(_VERSION_CODE)
        version_code = code if _ASCII_INT.match(code) else (
            manifest.get("android:versionCode", "") if manifest is not None else "")
    facts["version_name"], facts["version_code"] = version_name, version_code
    uses_sdk = manifest.find("uses-sdk") if manifest is not None else None
    given: Dict[str, str] = {}
    for key, pattern, attribute in (("min_sdk", _MIN_SDK, "android:minSdkVersion"),
                                    ("target_sdk", _TARGET_SDK, "android:targetSdkVersion"),
                                    ("compile_sdk", _COMPILE_SDK, "")):
        value = given[key] = gradle_value(pattern) or (
            uses_sdk.get(attribute, "") if uses_sdk is not None and attribute else "")
        facts[key] = int(value) if _ASCII_INT.match(value) else None   # ASCII digits only
        if value and facts[key] is None and key != "compile_sdk":
            facts[key + "_note"] = value + (" (the Flutter SDK default)"
                                            if value.startswith("flutter.") else "")
    if not given["target_sdk"] and facts["min_sdk"] is not None:
        # no targetSdk anywhere: Android takes the minSdk level as the target
        facts["target_sdk"] = facts["min_sdk"]
        facts["target_sdk_note"] = TARGET_SDK_DEFAULT_NOTE
    if spec is None:
        facts["platforms"] = ["android"]
        return
    prefix = project_dir + "/" if project_dir else ""
    folders = {rel[len(prefix):].split("/", 1)[0] for rel in by_rel
               if rel.startswith(prefix) and "/" in rel[len(prefix):]}
    facts["platforms"] = [name for name in PLATFORMS if name in folders]
    lock_rel = dict(ctx.pubspecs).get(main_spec)
    lock = pubspec.parse_lock(by_rel[lock_rel].text) if lock_rel else None
    if lock is not None and lock.error:
        ctx.warn("%s: not parsed (%s)" % (lock_rel, lock.error))
    if spec.error:
        ctx.warn("%s: not parsed (%s)" % (main_spec, spec.error))
    facts["packages"] = [{"name": name, "version": item.version, "source": item.source,
                          "dependency": item.dependency}
                         for name, item in sorted((lock.packages if lock else {}).items())]
    facts["dart_sdk"] = spec.sdk or (lock.sdks.get("dart", "") if lock else "")
