"""Synthetic app packages for the tests of the Flutter / Android module (import it from a test
in this folder: `from flutter_kit import build_apk`).

build_apk() lays out an APK the way the Android and Flutter build tools do, using the
builders of the decoder modules: a binary XML manifest compiled from XML text (resource
references such as @xml/network_security_config become resource ids), resources.arsc with
the res/xml files under shortened names as R8 writes them (res/8G.xml), DEX files, the
Flutter code of the chosen build mode (kernel_blob.bin with Dart sources for a debug build;
libapp.so with an AOT snapshot for profile and release builds; libflutter.so with a Dart
version and an engine revision in every Flutter build), assets with a .env file, NOTICES.Z
and an APK signature with the Android debug certificate or a release certificate.

build_aab() lays the same parts out as an app bundle, split_apk() splits an APK into a base
APK and an ABI split, and build_apk_set() packs APKs into an .apks, .xapk or .apkm set.

The defaults make a small Flutter app with the weaknesses of samples/flutter_apk_probe:
backup and cleartext allowed, an exported receiver, a custom scheme and a web link without
autoVerify, a network security config that permits cleartext and trusts user CAs, a
FileProvider root-path, a .env asset and an AWS example key, a cleartext URL and SQL text in
the code, signed with the Android debug certificate. Nothing here is run.
"""
from __future__ import annotations

import gzip
import json
import re
import struct
from typing import Dict, List, Mapping, Optional, Sequence, Tuple, Union

from sca.flutter import aabproto, arsc, axml, dex, kernel, signing, snapshot, zipread
from sca.flutter.xmltree import XmlNode, parse_xml_text

PACKAGE = "com.example.kitapp"            # Android package of the default manifest
APP = "kit_app"                           # Dart package of the app
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"          # AWS documentation example key
CLEARTEXT_URL = "http://api.kit-probe.example/v1/login"
SQL_TEXT = "SELECT * FROM users WHERE name = '"
LOG_TOKEN = "token="
ENV_TEXT = "API_BASE_URL=http://api.kit-probe.example/v1\nAWS_ACCESS_KEY_ID=%s\n" % AWS_KEY
DART_VERSION = "3.12.2"
ENGINE_REVISION = "0cd610717bde95fd88343c64f81c11ba4e5c0010"
SKIA_REVISION = "e9ed4fc9f1544c58d8a9347c1fc9471d8dd7c465"
SNAPSHOT_HASH = "ace654289f5abc240509fc941453ebc5"
RELEASE_FEATURES = ("product", "no-code_comments", "no-dwarf_stack_traces_mode",
                    "dedup_instructions", "no-asan", "no-msan", "no-tsan", "no-shared_data",
                    "arm64", "android", "compressed-pointers")
PROFILE_FEATURES = ("release",) + RELEASE_FEATURES[1:]
PACKAGES = {"collection": "1.19.1", "http": "0.13.0"}      # http < 0.13.3 has an advisory
BUILD_FOLDER = "file:///C:/Users/dev/projects/%s" % APP     # where the debug build was made
PUB_CACHE = "file:///C:/Users/dev/AppData/Local/Pub/Cache/hosted/pub.dev"
DEBUG_DN = {"CN": "Android Debug", "O": "Android", "C": "US"}
RELEASE_DN = {"C": "SA", "O": "Example Org", "CN": "Kit Release"}     # keytool's RDN order
DEBUG_CERT = signing.build_certificate(DEBUG_DN, version=1)
RELEASE_CERT = signing.build_certificate(RELEASE_DN, serial=0x5EED)
ENGINE_NOTICES = ("abseil-cpp", "boringssl", "flutter", "skia")      # left out by the loader
ABIS = {"arm64-v8a": ("aarch64", 64), "armeabi-v7a": ("arm", 32), "x86_64": ("x86_64", 64),
        "x86": ("x86", 32)}

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.kitapp" android:versionCode="7" android:versionName="1.2.3"
    android:compileSdkVersion="36">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <application android:label="@string/app_name" android:icon="@mipmap/ic_launcher"
        android:allowBackup="true" android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true"
            android:launchMode="singleTop" android:taskAffinity="">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="kitapp" android:host="open" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="kit-probe.example"
                    android:pathPrefix="/open" />
            </intent-filter>
        </activity>
        <receiver android:name=".KitReceiver" android:exported="true">
            <intent-filter>
                <action android:name="com.example.kitapp.PING" />
            </intent-filter>
        </receiver>
        <provider android:name="androidx.core.content.FileProvider"
            android:authorities="com.example.kitapp.fileprovider" android:exported="false"
            android:grantUriPermissions="true">
            <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths" />
        </provider>
    </application>
</manifest>
"""
NETWORK_SECURITY_CONFIG = """<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""
FILE_PATHS = """<paths>
    <root-path name="device_root" path="" />
</paths>
"""
XML_RESOURCES = {"network_security_config": NETWORK_SECURITY_CONFIG, "file_paths": FILE_PATHS}
STRINGS = {"app_name": "Kit App"}
MAIN_DART = """import 'dart:io';

import 'package:flutter/material.dart';

const awsAccessKey = '%s';
const loginUrl = '%s';

class KitVaultService {
  HttpClient createTrustAllClient() {
    final client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true;
    return client;
  }

  String findUser(String name) => "%s" + name + "'";
}

void main() {
  print('%s' + awsAccessKey);
  runApp(const MaterialApp(home: Text('Kit')));
}
""" % (AWS_KEY, CLEARTEXT_URL, SQL_TEXT, LOG_TOKEN)

_REFERENCE = re.compile(r"@([a-z]+)/([A-Za-z0-9_.]+)\Z")
_SHORT = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_FLUTTER_CLASSES = [("Lio/flutter/embedding/engine/FlutterJNI;", "Ljava/lang/Object;"),
                    ("Lio/flutter/plugins/GeneratedPluginRegistrant;", "Ljava/lang/Object;")]

Entries = List[Tuple[str, bytes, int]]


# ------------------------------------------------------------------ the parts of an app
def resource_table(manifest: str, xml_resources: Mapping[str, str], strings: Mapping[str, str],
                   shorten: bool) -> Tuple[List[tuple], Dict[str, str], Dict[str, int]]:
    """(entries for arsc.build_arsc, xml name -> path in the APK, "@type/name" -> resource
    id). Every @type/name reference of the manifest and the XML resources gets an entry;
    the XML resources are stored under 2-character names when shorten is set, as R8 does."""
    entries: List[tuple] = []
    paths: Dict[str, str] = {}
    for index, name in enumerate(xml_resources):
        paths[name] = ("res/%s%s.xml" % (_SHORT[index // 62 % 62], _SHORT[index % 62])
                       if shorten else "res/xml/%s.xml" % name)
        entries.append(("xml", name, paths[name]))
    entries += [("string", name, value) for name, value in strings.items()]
    known = {(kind, name) for kind, name, _ in entries}
    for text in [manifest, *xml_resources.values()]:
        for kind, name in re.findall(r'"@([a-z]+)/([A-Za-z0-9_.]+)"', text):
            if (kind, name) not in known:
                known.add((kind, name))
                entries.append((kind, name, 0))
    ids: Dict[str, int] = {}
    type_ids: Dict[str, int] = {}
    counts: Dict[str, int] = {}
    for kind, name, _ in entries:
        type_id = type_ids.setdefault(kind, len(type_ids) + 1)
        ids["@%s/%s" % (kind, name)] = 0x7F000000 | type_id << 16 | counts.get(kind, 0)
        counts[kind] = counts.get(kind, 0) + 1
    return entries, paths, ids


def compile_xml(text: str, ids: Optional[Mapping[str, int]] = None, *,
                debuggable: bool = False) -> XmlNode:
    """The tree of an XML text with @type/name references replaced by "@0x7f..." ids from
    ids (others are kept), and android:debuggable="true" added to <application> when
    debuggable is set (the build tools add it to debug builds)."""
    root, error = parse_xml_text(text)
    if root is None:
        raise ValueError("invalid XML: " + error)
    for node in root.iter():
        for key, value in node.attrs.items():
            if ids and _REFERENCE.match(value) and value in ids:
                node.attrs[key] = "@0x%08x" % ids[value]
        if debuggable and node.tag == "application":
            node.attrs.setdefault("android:debuggable", "true")
    return root


def kernel_blob(dart_sources: Mapping[str, str], packages: Mapping[str, str],
                app: str = APP) -> bytes:
    """kernel_blob.bin of a debug build: the app's sources (path in lib -> text) built in
    BUILD_FOLDER, a Flutter SDK library and one library per pub package (name -> version)
    from the pub cache, with main() in package:<app>/main.dart."""
    folder = BUILD_FOLDER.replace(APP, app)
    sources = [("%s/lib/%s" % (folder, path), "package:%s/%s" % (app, path), text)
               for path, text in dart_sources.items()]
    sources.append(("file:///C:/flutter/packages/flutter/lib/material.dart",
                    "package:flutter/material.dart", "library material;\n"))
    for name, version in packages.items():
        sources.append(("%s/%s-%s/lib/%s.dart" % (PUB_CACHE, name, version, name),
                        "package:%s/%s.dart" % (name, name), "library %s;\n" % name))
    return kernel.build_kernel(sources, main="package:%s/main.dart" % app)


def snapshot_strings(extra: Sequence[str] = (), packages: Sequence[str] = (), *,
                     obfuscated: bool = False, app: str = APP) -> List[str]:
    """Strings of an app's AOT snapshot: the probe markers (AWS key, cleartext URL, SQL text,
    "token="), extra, filler names and private names (enough of both for the loader to judge
    obfuscation) and, unless obfuscated, the class names and the package: URIs of the app
    and of packages."""
    strings = [AWS_KEY, CLEARTEXT_URL, SQL_TEXT, LOG_TOKEN, "dart:core", "dart:io", *extra]
    strings += ["kitIdentifier%03d" % index for index in range(120)]
    if obfuscated:
        strings += ["_%s%s@%d" % (_SHORT[10 + index % 26], _SHORT[36 + index // 26 % 26],
                                  5048458 + index) for index in range(80)]
    else:
        strings += ["KitVaultService", "createTrustAllClient",
                    "package:%s/main.dart" % app, "package:%s/src/api.dart" % app]
        strings += ["package:%s/%s.dart" % (name, name) for name in packages]
        strings += ["_KitPageState%03d@444214061" % index for index in range(80)]
    return strings


def libapp(strings: Sequence[str], *, features: Sequence[str] = RELEASE_FEATURES,
           abi: str = "arm64-v8a", symbols: bool = False) -> bytes:
    """libapp.so: an ELF exporting the snapshot symbols of Dart 3.12 and older, the isolate
    snapshot holding strings; symbols adds .symtab and .debug_info sections (an unstripped
    build)."""
    arch, bits = ABIS[abi]
    vm = snapshot.build_snapshot_data(features, ["dart:core", "_vm@1", "Object", "String"],
                                      SNAPSHOT_HASH)
    isolate = snapshot.build_snapshot_data(features, strings, SNAPSHOT_HASH)
    code = b"\x1f\x20\x03\xd5" * 16
    table = {"_kDartVmSnapshotInstructions": code, "_kDartIsolateSnapshotInstructions": code,
             "_kDartVmSnapshotData": vm, "_kDartIsolateSnapshotData": isolate,
             "_kDartSnapshotBuildId": bytes(32)}
    return snapshot.build_elf(table, sections=[".symtab", (".debug_info", b"\x01")] if symbols
                              else (), arch=arch, bits=bits, build_id=b"\xb7\x18\x85\x09" * 4)


def libflutter(abi: str = "arm64-v8a") -> bytes:
    """libflutter.so with the Dart version string and, for arm64-v8a, code that loads
    "flutter_engine", the engine revision, "skia" and the Skia revision the way the engine's
    shader cache code does, so snapshot.analyze_libflutter finds ENGINE_REVISION."""
    arch, bits = ABIS[abi]
    target = {"arm64-v8a": "android_arm64", "armeabi-v7a": "android_arm",
              "x86_64": "android_x64", "x86": "android_ia32"}[abi]
    blob = (b"\x00%s (stable) (Tue Jun 9 01:11:39 2026 -0700) on \"%s\"\x00flutter_engine\x00"
            b"skia\x00%s\x00%s\x00" % (DART_VERSION.encode(), target.encode(),
                                       ENGINE_REVISION.encode(), SKIA_REVISION.encode()))

    def build(code: bytes) -> bytes:
        return snapshot.build_elf({"kEngineStrings": blob}, sections=[(".text", code)],
                                  arch=arch, bits=bits)

    if arch != "aarch64":
        return build(bytes(256))
    elf = snapshot.parse_elf(build(bytes(256)))
    base = elf.symbol("kEngineStrings").value
    where = [base + blob.index(text) for text in (b"flutter_engine", ENGINE_REVISION.encode(),
                                                 b"skia\x00", SKIA_REVISION.encode())]
    text_start = elf.section(".text").addr
    words: List[int] = []
    for target_address in where:                # adrp x1 / add x1, x1, #lo12 / bl ctor
        pc = text_start + 4 * len(words)
        page = ((target_address & ~0xFFF) - (pc & ~0xFFF)) >> 12
        words.append(0x90000000 | (page & 3) << 29 | ((page >> 2) & 0x7FFFF) << 5 | 1)
        words.append(0x91000000 | (target_address & 0xFFF) << 10 | 1 << 5 | 1)
        words.append(0x94000000 | ((text_start + 240 - (pc + 8)) >> 2) & 0x3FFFFFF)
    words.append(0xD65F03C0)                     # ret
    return build(struct.pack("<%dI" % len(words), *words).ljust(256, b"\x00"))


def notices(names: Sequence[str]) -> bytes:
    """NOTICES.Z: gzip text with one licence block per name, blocks separated by a line of
    80 dashes."""
    blocks = ["%s\n\nCopyright the %s authors. Licensed under the MIT license.\n" % (name, name)
              for name in names]
    return gzip.compress(("\n" + "-" * 80 + "\n").join(blocks).encode("utf-8"), mtime=0)


def dex_file(package: str = PACKAGE, *, flutter: bool = True, strings: Sequence[str] = (),
             classes: Sequence[Tuple[str, Optional[str]]] = (),
             plugins: Optional[Mapping[str, str]] = None) -> bytes:
    """classes.dex with MainActivity and KitReceiver of the package, the Flutter embedding
    classes (flutter), the plugins (pub package -> Java class) with the strings
    GeneratedPluginRegistrant logs for them, and more strings and classes."""
    folder = package.replace(".", "/")
    activity = "Lio/flutter/embedding/android/FlutterActivity;" if flutter else \
        "Landroid/app/Activity;"
    all_classes = [("L%s/MainActivity;" % folder, activity),
                   ("L%s/KitReceiver;" % folder, "Landroid/content/BroadcastReceiver;")]
    if flutter:
        all_classes += _FLUTTER_CLASSES
    all_strings = ["https://kit-probe.example/terms", *strings]
    for name, java in (plugins or {}).items():
        all_classes.append(("L%s;" % java.replace(".", "/"), "Ljava/lang/Object;"))
        all_strings.append("Error registering plugin %s, %s" % (name, java))
    return dex.build_dex(all_strings, all_classes + list(classes),
                         [("L%s/MainActivity;" % folder, "onCreate", "(Landroid/os/Bundle;)V")])


def _signed(entries: Entries, certificate: Union[str, bytes, None],
            schemes: Sequence[str]) -> bytes:
    """A ZIP of entries, signed with the schemes (v1, v2, v3) when a certificate is given."""
    cert = {"debug": DEBUG_CERT, "release": RELEASE_CERT}.get(certificate, certificate) \
        if certificate is not None else None
    entries = list(entries)
    if cert is not None and "v1" in schemes:
        key = signing.parse_certificate(cert).key_algorithm
        extension = {"DSA": "DSA", "EC": "EC"}.get(key, "RSA")
        entries += [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n", 8),
                    ("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n\r\n", 8),
                    ("META-INF/CERT." + extension, signing.build_pkcs7([cert]), 8)]
    data = zipread.build_zip(entries)
    pairs = []
    if cert is not None and "v2" in schemes:
        pairs.append((signing.V2_BLOCK_ID, signing.build_v2_block([cert])))
    if cert is not None and "v3" in schemes:
        pairs.append((signing.V3_BLOCK_ID, signing.build_v3_block([cert])))
    return signing.sign_zip(data, signing.build_signing_block(pairs)) if pairs else data


# ------------------------------------------------------------------ packages
def build_apk(*, mode: str = "release", manifest: str = MANIFEST,
              xml_resources: Optional[Mapping[str, str]] = None, shorten: Optional[bool] = None,
              strings: Optional[Mapping[str, str]] = None,
              dart_sources: Optional[Mapping[str, str]] = None,
              packages: Optional[Mapping[str, str]] = None,
              extra_strings: Sequence[str] = (), obfuscated: bool = False,
              symbols: bool = False, abis: Sequence[str] = ("arm64-v8a",),
              native_libs: Optional[Mapping[str, bytes]] = None,
              dex_strings: Sequence[str] = (),
              dex_classes: Sequence[Tuple[str, Optional[str]]] = (),
              plugins: Optional[Mapping[str, str]] = None, extra_dex: Sequence[bytes] = (),
              assets: Optional[Mapping[str, Union[str, bytes]]] = None,
              notice_names: Optional[Sequence[str]] = None,
              certificate: Union[str, bytes, None] = "debug", schemes: Sequence[str] = ("v2",),
              extra_entries: Sequence[Tuple[str, bytes]] = ()) -> bytes:
    """The bytes of a synthetic APK.

    mode            "debug" (kernel_blob.bin, isolate_snapshot_data, libflutter.so,
                    android:debuggable="true"), "profile" (libapp.so whose features start
                    with "release", debuggable as the Flutter template makes it), "release"
                    (libapp.so with "product" features) or "none" (a plain Android app: no
                    Flutter code, assets or NOTICES)
    manifest        AndroidManifest.xml as XML text; @type/name references become ids of
                    resources.arsc entries
    xml_resources   res/xml resources, name -> XML text (default: XML_RESOURCES, a network
                    security config and FileProvider paths)
    shorten         store the XML resources under 2-character names (res/00.xml ...) instead
                    of res/xml/<name>.xml; by default as the build does it (R8 shortens the
                    names in profile and release builds)
    strings         string resources, name -> value (default: STRINGS)
    dart_sources    debug: the app's Dart sources, path in lib -> text (default: main.dart
                    with the probe markers)
    packages        pub packages, name -> version (default: PACKAGES): pub-cache libraries in
                    the kernel (debug), package: URIs in the snapshot (profile/release, not
                    obfuscated) and blocks in NOTICES.Z
    extra_strings   profile/release: more strings for the snapshot
    obfuscated      profile/release: short private names and no package: URIs or class names
    symbols         profile/release: libapp.so keeps .symtab and .debug_info
    abis            ABIs that get libapp.so (profile/release) and libflutter.so
    native_libs     other native libraries of the first ABI, file name -> ELF bytes
    dex_strings, dex_classes, plugins
                    more strings and (descriptor, superclass) classes for classes.dex, and
                    Flutter plugins as pub package -> Java class (see dex_file)
    extra_dex       more DEX files: classes2.dex, classes3.dex ...
    assets          files under assets/, path -> text or bytes (default: a .env file at
                    flutter_assets/assets/.env for Flutter modes, none for "none")
    notice_names    package names for NOTICES.Z (default: ENGINE_NOTICES and the packages)
    certificate     "debug" (the Android debug certificate), "release", DER bytes, or None
                    for an unsigned APK
    schemes         signature schemes, any of "v1", "v2", "v3"
    extra_entries   more (name, data) entries, written as they are
    """
    if mode not in ("debug", "profile", "release", "none"):
        raise ValueError("unknown mode %r" % mode)
    flutter = mode != "none"
    xml_resources = XML_RESOURCES if xml_resources is None else xml_resources
    strings = STRINGS if strings is None else strings
    packages = PACKAGES if packages is None else packages
    shorten = mode in ("profile", "release") if shorten is None else shorten
    table, paths, ids = resource_table(manifest, xml_resources, strings, shorten)
    root = compile_xml(manifest, ids, debuggable=mode in ("debug", "profile"))
    entries: Entries = [("AndroidManifest.xml", axml.encode_axml(root), 8)]
    entries += [("classes.dex", dex_file(_package(root), flutter=flutter, strings=dex_strings,
                                         classes=dex_classes, plugins=plugins), 8)]
    entries += [("classes%d.dex" % (index + 2), data, 8) for index, data in enumerate(extra_dex)]
    entries += [(paths[name], axml.encode_axml(compile_xml(text, ids)), 8)
                for name, text in xml_resources.items()]
    entries.append(("resources.arsc", arsc.build_arsc(_package(root), table), 0))
    if assets is None:
        assets = {"flutter_assets/assets/.env": ENV_TEXT} if flutter else {}
    entries += [("assets/" + path, data.encode("utf-8") if isinstance(data, str) else data, 8)
                for path, data in assets.items()]
    if flutter:
        names = list(ENGINE_NOTICES) + list(packages) if notice_names is None else notice_names
        entries.append(("assets/flutter_assets/NOTICES.Z", notices(names), 8))
        entries += _flutter_code(mode, dart_sources, packages, extra_strings, obfuscated,
                                 symbols, abis)
    for name, data in (native_libs or {}).items():
        entries.append(("lib/%s/%s" % (abis[0], name), data, 0))
    entries += [(name, data, 8) for name, data in extra_entries]
    return _signed(entries, certificate, schemes)


def _package(root: XmlNode) -> str:
    return root.get("package") or PACKAGE


def _flutter_code(mode: str, dart_sources: Optional[Mapping[str, str]],
                  packages: Mapping[str, str], extra_strings: Sequence[str], obfuscated: bool,
                  symbols: bool, abis: Sequence[str]) -> Entries:
    entries: Entries = []
    if mode == "debug":
        sources = {"main.dart": MAIN_DART} if dart_sources is None else dart_sources
        entries += [("assets/flutter_assets/kernel_blob.bin", kernel_blob(sources, packages), 8),
                    ("assets/flutter_assets/isolate_snapshot_data",
                     snapshot.build_snapshot_data(["release"], [], SNAPSHOT_HASH, kind=1), 8),
                    ("assets/flutter_assets/vm_snapshot_data",
                     snapshot.build_snapshot_data(["release"], [], SNAPSHOT_HASH, kind=1), 8)]
    for abi in abis:
        if mode != "debug":
            features = PROFILE_FEATURES if mode == "profile" else RELEASE_FEATURES
            strings = snapshot_strings(extra_strings, list(packages), obfuscated=obfuscated)
            entries.append(("lib/%s/libapp.so" % abi,
                            libapp(strings, features=features, abi=abi, symbols=symbols), 0))
        entries.append(("lib/%s/libflutter.so" % abi, libflutter(abi), 0))
    return entries


def build_aab(*, mode: str = "release", manifest: str = MANIFEST,
              xml_resources: Optional[Mapping[str, str]] = None,
              strings: Optional[Mapping[str, str]] = None,
              packages: Optional[Mapping[str, str]] = None, obfuscated: bool = False,
              assets: Optional[Mapping[str, Union[str, bytes]]] = None,
              certificate: Union[str, bytes, None] = "debug",
              extra_entries: Sequence[Tuple[str, bytes]] = ()) -> bytes:
    """The bytes of a synthetic app bundle (.aab) with the parts build_apk makes for the
    same arguments, in the bundle layout: base/manifest/AndroidManifest.xml and
    base/res/xml/<name>.xml as protobuf XML (references stay names), base/resources.pb with
    the string resources, base/dex/, base/lib/, base/assets/, BundleConfig.pb and a JAR (v1)
    signature, as bundletool and the Gradle plugin write them."""
    xml_resources = XML_RESOURCES if xml_resources is None else xml_resources
    strings = STRINGS if strings is None else strings
    packages = PACKAGES if packages is None else packages
    root = compile_xml(manifest, debuggable=mode in ("debug", "profile"))
    entries: Entries = [("BundleConfig.pb", b"", 8),
                        ("base/manifest/AndroidManifest.xml", aabproto.encode_proto_xml(root), 8),
                        ("base/dex/classes.dex", dex_file(_package(root), flutter=mode != "none"),
                         8),
                        ("base/resources.pb", resources_pb(_package(root), strings), 8)]
    entries += [("base/res/xml/%s.xml" % name, aabproto.encode_proto_xml(compile_xml(text)), 8)
                for name, text in xml_resources.items()]
    if assets is None:
        assets = {"flutter_assets/assets/.env": ENV_TEXT} if mode != "none" else {}
    entries += [("base/assets/" + path, data.encode("utf-8") if isinstance(data, str) else data,
                 8) for path, data in assets.items()]
    if mode != "none":
        entries.append(("base/assets/flutter_assets/NOTICES.Z",
                        notices(list(ENGINE_NOTICES) + list(packages)), 8))
        for name, data, method in _flutter_code(mode, None, packages, (), obfuscated, False,
                                                ("arm64-v8a",)):
            entries.append(("base/" + name, data, method))
    entries += [(name, data, 8) for name, data in extra_entries]
    return _signed(entries, certificate, ("v1",))


def _pb(number: int, payload: bytes) -> bytes:
    """A length-delimited protobuf field."""
    def varint(value: int) -> bytes:
        out = bytearray()
        while value > 0x7F:
            out.append(value & 0x7F | 0x80)
            value >>= 7
        return bytes(out + bytes([value]))
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def resources_pb(package: str, strings: Mapping[str, str],
                 other_configs: Optional[Mapping[str, str]] = None) -> bytes:
    """base/resources.pb (aapt.pb.ResourceTable) holding the string resources in the default
    configuration, and other_configs (name -> value) in a non-default one."""
    entries = b""
    for name, value in strings.items():
        item = _pb(4, _pb(2, _pb(1, value.encode("utf-8"))))
        entries += _pb(3, _pb(2, name.encode("utf-8")) + _pb(6, _pb(1, b"") + _pb(2, item)))
    for name, value in (other_configs or {}).items():
        item = _pb(4, _pb(2, _pb(1, value.encode("utf-8"))))
        config = _pb(1, _pb(3, b"fr"))               # a Configuration with a locale
        entries += _pb(3, _pb(2, name.encode("utf-8")) + _pb(6, config + _pb(2, item)))
    kind = _pb(2, b"string") + entries
    return _pb(2, _pb(2, package.encode("utf-8")) + _pb(3, kind))


def split_apk(apk: bytes, *, certificate: Union[str, bytes, None] = "debug") -> Dict[str, bytes]:
    """An APK split the way bundletool splits it: {"base": everything but lib/,
    "split_config.<abi>": a split APK with a split manifest and lib/<abi>/ of each ABI}. The
    base is signed again (v2) with certificate."""
    archive = zipread.ZipArchive(apk, name="app.apk")
    package = "com.example.split"
    base: Entries = []
    splits: Dict[str, Entries] = {}
    for entry in archive.entries:
        data = archive.read(entry)
        if entry.name.startswith("lib/"):
            abi = entry.name.split("/")[1]
            splits.setdefault(abi, []).append((entry.name, data, 0))
        elif not entry.name.startswith("META-INF/"):
            base.append((entry.name, data, entry.method))
            if entry.name == "AndroidManifest.xml":
                package = axml.decode_axml(data).root.get("package") or package
    out = {"base": _signed(base, certificate, ("v2",))}
    for abi, entries in splits.items():
        config = "config.%s" % abi.replace("-", "_")
        root = XmlNode("manifest", {"xmlns:android": axml.ANDROID_URI, "package": package,
                                    "split": config},
                       [XmlNode("application", {"android:hasCode": "false"})])
        out["split_" + config] = _signed([("AndroidManifest.xml", axml.encode_axml(root), 8)]
                                         + entries, certificate, ("v2",))
    return out


def build_apk_set(apks: Mapping[str, bytes], *, layout: str = "apks",
                  package: str = PACKAGE) -> bytes:
    """A set of split APKs, labels ("base", "split_config.arm64_v8a", "split_<feature>") ->
    APK bytes, packed as bundletool writes an .apks (splits/base-master.apk,
    splits/base-arm64_v8a.apk, toc.pb), as an .xapk (<package>.apk, config.arm64_v8a.apk,
    manifest.json) or as an .apkm (base.apk, split_config.arm64_v8a.apk, info.json)."""
    entries: Entries = []
    for label, data in apks.items():
        config = label[len("split_config."):] if label.startswith("split_config.") else ""
        feature = label[len("split_"):] if label.startswith("split_") and not config else ""
        if layout == "apks":
            name = ("splits/base-master.apk" if label == "base" else
                    "splits/base-%s.apk" % config if config else
                    "splits/%s-master.apk" % feature)
        elif layout == "xapk":
            name = "%s.apk" % package if label == "base" else \
                ("config.%s.apk" % config if config else "%s.apk" % label)
        elif layout == "apkm":
            name = "%s.apk" % label
        else:
            raise ValueError("unknown layout %r" % layout)
        entries.append((name, data, 0))
    if layout == "apks":
        entries.append(("toc.pb", b"", 8))
    else:
        info = json.dumps({"package_name": package, "split_apks": sorted(apks)}).encode()
        entries.append(("manifest.json" if layout == "xapk" else "info.json", info, 8))
    return zipread.build_zip(entries)
