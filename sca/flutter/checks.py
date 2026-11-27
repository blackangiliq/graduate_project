"""Structural checks of Flutter and Android apps and projects (engine "flutter").

analyze(ctx, by_rel) reads what a loader put in a MobileContext (sca/flutter/context.py): the
release manifests with their network security configs and FileProvider paths, the app-level
Gradle files, key.properties, keystores, Info.plist files and pubspec.yaml / pubspec.lock of
a project; for an app package also the summaries _sca/build.txt, _sca/signing.txt and
_sca/packages.txt and the strings dump of libapp.so. It returns the findings and the engine
note, and fills the app facts permissions, components, flags, endpoints and
dependency_issues. refine() runs before the merge and contextualizes client API keys.

Where a finding points (samples/flutter_ground_truth.json relies on it):
- manifest and XML resources: the line of the offending attribute; for an implicit default
  the start tag of the element (<application); an exported component: its
  android:exported attribute, else its start tag; a custom-scheme link: the android:scheme
  of its <data>; a web link without autoVerify: the <intent-filter> start tag; a
  permission: the android:name of its <uses-permission>; a FileProvider path: the start
  tag of the path element;
- Gradle and key.properties: the offending line; a keystore: line 1 of its placeholder;
- Info.plist: the <key>NAME</key> line (the n-th one for a repeated key);
- pubspec: the lines pubspec.audit_project gives; a bundled asset: its line under
  flutter: assets:;
- app summaries: the line of the matching label; a strings dump: the line of the string.
Each check reports a distinct problem once and at most MAX_PER_FILE times per file; the
engine note says when that cap dropped findings. CHECKS lists every check with its English
and Arabic title for the dashboard guide and the documentation.
"""
from __future__ import annotations

import bisect
import fnmatch
import plistlib
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from ..cwe import canonical
from ..engines.secrets import PLACEHOLDER
from ..models import Finding
from ..walker import SourceFile, is_test_path
from . import pubspec
from .android import (ANDROID_URI, EXPOSE_APP_DATA, EXPOSE_FILESYSTEM, EXPOSE_NARROW_ROOT,
                      EXPOSE_PARENT,
                      GUARD_NONE, GUARD_STRONG, GUARD_UNDEFINED, GUARD_WEAK, LOOPBACK_HOSTS,
                      MAPS_KEY_METADATA, PRIVATE_KINDS, SOURCE_CONFIG, SOURCE_DEFAULT, STANDARD_SCHEMES,
                      WEB_SCHEMES, Component, FileProviderPaths, ManifestInfo,
                      NetworkSecurityConfig, backup_policy, cleartext_policy, is_dangerous,
                      is_normal, is_own_affinity, is_special, parse_bool, parse_int)
from .context import BUILD_FILE, PACKAGES_FILE, SIGNING_FILE, MobileContext
from .xmltree import XmlNode, parse_xml_text

ENGINE = "flutter"
MAX_PER_FILE = 50             # findings of one check in one file
MAX_ENDPOINTS = 200           # facts["endpoints"]
MAX_FACT_ITEMS = 300          # facts["permissions"] and facts["components"]
MAX_QUOTED_WARNINGS = 5       # decoder warnings quoted by FLUTTER-APP-009


@dataclass(frozen=True)
class Check:
    """One structural check with its default severity and confidence (a finding can lower
    them, for example for an implicit default)."""

    id: str
    title: str
    title_ar: str
    cwe: str
    severity: str
    confidence: float
    area: str        # a key of AREAS
    target: str      # a key of TARGETS: where the check runs


AREAS: Dict[str, Tuple[str, str]] = {
    "manifest": ("Android manifest", "ملف AndroidManifest.xml"),
    "network": ("Network security", "أمان الشبكة"),
    "gradle": ("Gradle build", "ملفات بناء Gradle"),
    "signing": ("App signing", "توقيع التطبيق"),
    "ios": ("iOS Info.plist", "ملف Info.plist في iOS"),
    "app": ("Flutter app build", "بناء تطبيق Flutter"),
    "dependencies": ("Dependencies", "الاعتماديات"),
}
TARGETS: Dict[str, Tuple[str, str]] = {
    "source": ("Source project", "المشروع المصدري"),
    "app": ("App package (APK / AAB)", "حزمة التطبيق (APK / AAB)"),
    "both": ("Source project and app package", "المشروع المصدري وحزمة التطبيق"),
}

CHECKS: Tuple[Check, ...] = (
    Check("ANDROID-MANIFEST-001", "App is debuggable (android:debuggable)",
          "التطبيق قابل للتصحيح (android:debuggable)",
          "CWE-489", "high", 0.95, "manifest", "both"),
    Check("ANDROID-MANIFEST-002", "App is marked test-only (android:testOnly)",
          "التطبيق مُعلَّم كنسخة اختبار فقط (android:testOnly)",
          "CWE-489", "medium", 0.9, "manifest", "both"),
    Check("ANDROID-MANIFEST-003", "App data can be backed up (android:allowBackup)",
          "يمكن نسخ بيانات التطبيق احتياطياً (android:allowBackup)",
          "CWE-530", "medium", 0.8, "manifest", "both"),
    Check("ANDROID-MANIFEST-004", "Cleartext HTTP allowed (android:usesCleartextTraffic)",
          "السماح باتصالات HTTP غير المشفّرة (android:usesCleartextTraffic)",
          "CWE-319", "medium", 0.85, "manifest", "both"),
    Check("ANDROID-MANIFEST-005", "Exported component without a permission",
          "مكوّن مُصدَّر (exported) دون صلاحية تحميه",
          "CWE-926", "medium", 0.75, "manifest", "both"),
    Check("ANDROID-MANIFEST-006", "Exported component guarded by a weak or undefined permission",
          "مكوّن مُصدَّر تحميه صلاحية ضعيفة أو غير معرَّفة",
          "CWE-732", "low", 0.6, "manifest", "both"),
    Check("ANDROID-MANIFEST-007", "Deep link with a custom URL scheme",
          "رابط عميق (deep link) بمخطط URL مخصص",
          "CWE-939", "low", 0.5, "manifest", "both"),
    Check("ANDROID-MANIFEST-008", "Web link without App Links verification (android:autoVerify)",
          "رابط ويب يفتح التطبيق دون تحقق App Links (android:autoVerify)",
          "CWE-939", "medium", 0.6, "manifest", "both"),
    Check("ANDROID-MANIFEST-009", "Dangerous or special access permission requested",
          "طلب صلاحية خطرة أو صلاحية وصول خاص",
          "CWE-250", "info", 0.9, "manifest", "both"),
    Check("ANDROID-MANIFEST-010", "Legacy external storage (android:requestLegacyExternalStorage)",
          "استخدام وضع التخزين الخارجي القديم (android:requestLegacyExternalStorage)",
          "CWE-922", "low", 0.7, "manifest", "both"),
    Check("ANDROID-MANIFEST-011", "Task hijacking exposure (taskAffinity, allowTaskReparenting)",
          "قابلية اختطاف المهام (taskAffinity أو allowTaskReparenting)",
          "CWE-1021", "low", 0.4, "manifest", "both"),
    Check("ANDROID-MANIFEST-012", "WebView Safe Browsing switched off (EnableSafeBrowsing)",
          "إيقاف التصفح الآمن (Safe Browsing) في WebView عبر EnableSafeBrowsing",
          "CWE-1188", "low", 0.8, "manifest", "both"),
    Check("ANDROID-MANIFEST-013", "Application disables native heap pointer tagging",
          "التطبيق يعطّل وسم مؤشرات الذاكرة الأصلية",
          "CWE-693", "low", 0.9, "manifest", "both"),
    Check("ANDROID-MANIFEST-014", "Application default disables GWP-ASan",
          "إعداد التطبيق يعطّل فحص الذاكرة باستخدام GWP-ASan",
          "CWE-693", "low", 0.9, "manifest", "both"),
    Check("ANDROID-MANIFEST-015", "Application default disables hardware memory tagging (MTE)",
          "إعداد التطبيق يعطّل وسم الذاكرة العتادي (MTE)",
          "CWE-693", "info", 0.9, "manifest", "both"),
    Check("ANDROID-SDK-001", "Runs on Android versions before 7.0 (minSdk below 24)",
          "يعمل على إصدارات Android أقدم من 7.0 (قيمة minSdk أقل من 24)",
          "CWE-693", "low", 0.7, "manifest", "both"),
    Check("ANDROID-SDK-002", "Targets an Android version before 9 (targetSdk below 28)",
          "يستهدف إصدار Android أقدم من 9 (قيمة targetSdk أقل من 28)",
          "CWE-693", "low", 0.7, "manifest", "both"),
    Check("ANDROID-FILEPROVIDER-001", "FileProvider shares a whole storage root",
          "مكوّن FileProvider يشارك جذر تخزين كاملاً",
          "CWE-552", "high", 0.8, "manifest", "both"),
    Check("ANDROID-NSC-001", "Network security config allows cleartext HTTP for all domains",
          "إعدادات أمان الشبكة تسمح باتصالات HTTP غير المشفّرة لكل النطاقات",
          "CWE-319", "high", 0.9, "network", "both"),
    Check("ANDROID-NSC-002", "Network security config allows cleartext HTTP for some domains",
          "إعدادات أمان الشبكة تسمح باتصالات HTTP غير المشفّرة لبعض النطاقات",
          "CWE-319", "medium", 0.7, "network", "both"),
    Check("ANDROID-NSC-003", "User-installed certificate authorities are trusted",
          "الوثوق بشهادات CA التي يثبّتها المستخدم",
          "CWE-295", "medium", 0.8, "network", "both"),
    Check("ANDROID-NSC-004", "Certificate pinning bypassed or expired",
          "تجاوز تثبيت الشهادات (pinning) أو انتهاء مدته",
          "CWE-295", "low", 0.6, "network", "both"),
    Check("ANDROID-GRADLE-001", "Release build signed with the debug key",
          "نسخة الإصدار موقَّعة بمفتاح التصحيح (debug)",
          "CWE-1188", "medium", 0.8, "gradle", "source"),
    Check("ANDROID-GRADLE-002", "Release build without code shrinking (minifyEnabled false)",
          "نسخة الإصدار دون تصغير الكود (minifyEnabled false)",
          "CWE-693", "low", 0.6, "gradle", "source"),
    Check("ANDROID-GRADLE-003", "Release build is debuggable",
          "نسخة الإصدار قابلة للتصحيح",
          "CWE-489", "high", 0.85, "gradle", "source"),
    Check("ANDROID-GRADLE-004", "Keystore password written in the Gradle build file",
          "كلمة مرور مخزن المفاتيح مكتوبة صراحةً في ملف Gradle",
          "CWE-798", "high", 0.85, "gradle", "source"),
    Check("ANDROID-SIGN-001", "App signed with the Android debug certificate",
          "التطبيق موقَّع بشهادة التصحيح (debug) الخاصة بـ Android",
          "CWE-1188", "high", 0.95, "signing", "app"),
    Check("ANDROID-SIGN-002", "APK signed only with the v1 (JAR) scheme",
          "ملف APK موقَّع بمخطط v1 (JAR) فقط",
          "CWE-347", "high", 0.85, "signing", "app"),
    Check("ANDROID-SIGN-003", "APK is not signed",
          "ملف APK غير موقَّع",
          "CWE-347", "medium", 0.9, "signing", "app"),
    Check("ANDROID-SIGN-004", "Weak signing certificate",
          "شهادة توقيع ضعيفة",
          "CWE-327", "medium", 0.8, "signing", "app"),
    Check("ANDROID-SIGN-010", "Keystore password in key.properties inside the project",
          "كلمة مرور مخزن المفاتيح في ملف key.properties داخل المشروع",
          "CWE-798", "high", 0.7, "signing", "source"),
    Check("ANDROID-SIGN-011", "Keystore file inside the project",
          "ملف مخزن مفاتيح (keystore) داخل المشروع",
          "CWE-798", "medium", 0.6, "signing", "source"),
    Check("IOS-PLIST-001", "App Transport Security turned off (NSAllowsArbitraryLoads)",
          "إيقاف App Transport Security (المفتاح NSAllowsArbitraryLoads)",
          "CWE-319", "high", 0.8, "ios", "source"),
    Check("IOS-PLIST-002", "App Transport Security weakened for web content, media or a domain",
          "إضعاف App Transport Security لمحتوى الويب أو الوسائط أو لنطاق محدد",
          "CWE-319", "medium", 0.7, "ios", "source"),
    Check("IOS-PLIST-003", "Exception domain accepts TLS 1.0 or 1.1",
          "نطاق مستثنى يقبل TLS 1.0 أو 1.1",
          "CWE-326", "medium", 0.75, "ios", "source"),
    Check("IOS-PLIST-004", "Custom URL scheme registered (CFBundleURLSchemes)",
          "تسجيل مخطط URL مخصص (CFBundleURLSchemes)",
          "CWE-939", "info", 0.8, "ios", "source"),
    Check("IOS-PLIST-005", "Documents folder shared with the user (UIFileSharingEnabled)",
          "مشاركة مجلد Documents مع المستخدم (UIFileSharingEnabled)",
          "CWE-552", "medium", 0.6, "ios", "source"),
    Check("FLUTTER-APP-001", "Debug build: the Dart source code ships in the app",
          "نسخة تصحيح (debug): كود Dart المصدري مضمَّن في التطبيق",
          "CWE-489", "high", 0.95, "app", "app"),
    Check("FLUTTER-APP-002", "Flutter profile build",
          "نسخة Flutter من نوع profile",
          "CWE-489", "medium", 0.85, "app", "app"),
    Check("FLUTTER-APP-003", "Release build without Dart obfuscation",
          "نسخة إصدار دون تمويه (obfuscation) كود Dart",
          "CWE-693", "low", 0.7, "app", "app"),
    Check("FLUTTER-APP-004", "Debug symbols left in libapp.so",
          "رموز التصحيح (symbols) متروكة في libapp.so",
          "CWE-215", "low", 0.85, "app", "app"),
    Check("FLUTTER-APP-005", "Paths of the build machine disclosed",
          "كشف مسارات جهاز البناء داخل التطبيق",
          "CWE-200", "low", 0.7, "app", "app"),
    Check("FLUTTER-APP-006", "Secrets file bundled as a Flutter asset",
          "ملف أسرار مضمَّن كأصل (asset) في تطبيق Flutter",
          "CWE-798", "medium", 0.75, "app", "both"),
    Check("FLUTTER-APP-007", "Cleartext HTTP endpoint in the compiled app",
          "عنوان HTTP غير مشفّر داخل التطبيق المُترجَم",
          "CWE-319", "medium", 0.6, "app", "app"),
    Check("FLUTTER-APP-008", "SQL string fragment requiring query review",
          "مقطع نص SQL يحتاج إلى مراجعة بناء الاستعلام",
          "CWE-89", "low", 0.45, "app", "app"),
    Check("FLUTTER-APP-009", "Malformed app package (anti-analysis tricks)",
          "حزمة تطبيق مشوَّهة البنية (حيل لإعاقة التحليل)",
          "CWE-693", "low", 0.6, "app", "app"),
    Check("FLUTTER-PUB-001", "Dependency with a known vulnerability",
          "اعتمادية فيها ثغرة معروفة",
          "CWE-1395", "high", 0.9, "dependencies", "both"),
    Check("FLUTTER-PUB-002", "Discontinued or unmaintained package",
          "حزمة متوقفة أو لم تعد تُصان",
          "CWE-1104", "low", 0.8, "dependencies", "both"),
    Check("FLUTTER-PUB-003", "Dependency fetched over git:// or http://",
          "اعتمادية تُجلب عبر git:// أو http://",
          "CWE-494", "high", 0.85, "dependencies", "source"),
    Check("FLUTTER-PUB-004", "Dependency override or dependency without a version constraint",
          "تجاوز اعتمادية (override) أو اعتمادية دون قيد على الإصدار",
          "CWE-1357", "low", 0.7, "dependencies", "source"),
    Check("FLUTTER-PUB-005", "Flutter app without pubspec.lock",
          "تطبيق Flutter دون ملف pubspec.lock",
          "CWE-1357", "info", 0.6, "dependencies", "source"),
    Check("FLUTTER-PUB-006", "Git dependency not pinned to a commit",
          "اعتمادية git غير مثبَّتة على commit محدد",
          "CWE-494", "low", 0.6, "dependencies", "source"),
)
BY_ID: Dict[str, Check] = {check.id: check for check in CHECKS}

# Dart networking (dart:io, package:http, dio) does its own TLS and never reads these settings.
DART_NOTE = ("Dart code (dart:io, package:http, dio) does not follow the network security "
             "config, so the Dart rules for http:// URLs and certificate checks cover that "
             "traffic.")
FIREBASE_NOTE = ("This Google API key comes from a Firebase configuration file: it identifies "
                 "the Firebase project and ships in every copy of the app, so it is not a "
                 "secret. Restrict it in the Google Cloud console (allowed apps and APIs) and "
                 "protect the data with Firebase security rules and App Check.")
FIREBASE_FIX = ("Restrict the key in the Google Cloud console and rely on Firebase security "
                "rules and App Check; move keys of paid APIs to a server.")
FIREBASE_FILES = ("google-services.json", "GoogleService-Info.plist", "firebase_options.dart",
                  "firebase-messaging-sw.js", "firebase-messaging-sw.ts")
_FIREBASE_STRING = re.compile(r'name="(?:google|firebase|gcm)_\w*"')   # google_api_key ...
_GOOGLE_KEY = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
MAPS_CLIENT_NOTE = ("The packaged manifest declares a Google Maps Android client key. "
                    "Its Google Cloud application and API restrictions require verification "
                    "by the project owner.")
MAPS_CLIENT_FIX = ("In Google Cloud, restrict the key to the Android package and signing "
                   "certificate and to the required Maps APIs.")
# the other values of a Firebase configuration, compiled into libapp.so next to the key
_FIREBASE_MARKERS = re.compile(r"firebaseio\.com|appspot\.com|firebasestorage\.app"
                               r"|messagingSenderId|googleapis")
# the Firebase web configuration in web/index.html
_WEB_FIREBASE_CONFIG = re.compile(r"\bfirebaseConfig\b")

# source sets that never go into a release build
_NOT_RELEASE = re.compile(r"(?i)^(debug|profile|test\w*|androidTest\w*|\w*Debug|\w*Profile)$")
_SOURCE_SET = re.compile(r"^(?:(?P<module>.+)/)?src/(?P<set>[^/]+)/AndroidManifest\.xml$")
_SECRET_ASSET = re.compile(
    r"(?i)^(?:\.env|[^/]+\.env"
    r"|\.env\.(?!(?:example|sample|template|dist|defaults?|schema)$)[\w.-]+"
    r"|[^/]+\.(?:p12|pfx|jks|keystore))$")
_KEY_PROPERTY = re.compile(r"^\s*(storePassword|keyPassword)\s*[=:]\s*(.*?)\s*$")
_USER_FOLDER = re.compile(r"(?i)(/Users/[^/]+|/home/[^/]+|/root/|"
                          r"\b[A-Z]:[/\\](?:Users|Documents and Settings)[/\\][^/\\]+)")
_SQL_OPEN_QUOTE = re.compile(
    r"(?i)^\s*(?:select|update|delete|insert|replace|with)\b.*"
    r"(?:\b(?:where|set|and|or|having|on|values)\b.*(?:=|\blike)\s*"
    r"|\bvalues\s*\((?:[^()]*,)?\s*)['\"]%?\s*$")
_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>\\^`{|}]+")
# hosts of XML namespaces, schemas, licences and SDK documentation: never app endpoints
_NOT_ENDPOINTS = frozenset({
    "www.w3.org", "w3.org", "schemas.android.com", "schemas.xmlsoap.org",
    "schemas.openxmlformats.org", "schemas.microsoft.com", "ns.adobe.com", "xmlpull.org",
    "www.xmlpull.org", "purl.org", "purl.oclc.org", "xml.org", "www.xml.org",
    "json-schema.org", "java.sun.com", "xmlns.com", "www.opengis.net", "ns.useplus.org",
    "iptc.org", "www.iptc.org", "cipa.jp", "xml.apache.org", "www.apache.org", "apache.org",
    "opensource.org", "www.opensource.org", "www.gnu.org", "gnu.org", "creativecommons.org",
    "www.mozilla.org", "mozilla.org", "unlicense.org", "www.unicode.org", "unicode.org",
    "dart.dev", "www.dartlang.org", "dartlang.org", "flutter.dev", "docs.flutter.dev",
    "api.flutter.dev", "pub.dev", "pub.dartlang.org", "xmlns.jcp.org", "xmlns.oracle.com",
    "www.color.org", "color.org", "www.aiim.org", "aiim.org", "ns.google.com",
    "ns.microsoft.com", "www.topografix.com", "topografix.com", "www.idpf.org",
    "docs.oasis-open.org", "www.oasis-open.org", "relaxng.org", "www.relaxng.org",
    "exslt.org", "www.wapforum.org", "www.openmobilealliance.org", "www.xfa.org",
    "www.npes.org", "www.ecma-international.org", "www.omg.org", "www.ietf.org",
    "tools.ietf.org", "www.rfc-editor.org", "www.iana.org"})
# schema hosts (schemas.android.com, schemas.microsoft.com ...) and document type and schema
# files (www.apple.com/DTDs/PropertyList-1.0.dtd)
_SPEC_HOST = re.compile(r"^schemas?\.")
_SPEC_PATH = re.compile(r"(?i)^/DTDs?/|\.(?:dtd|xsd|rng|rnc)$")
# issue links that the Flutter framework and the Dart SDK put in their error messages
_SDK_LINK = re.compile(r"(?i)^https?://github\.com/(?:flutter|dart-lang)/")
# decoder warnings that show a package bent on purpose (see sca/flutter/zipread.py, axml.py,
# aabproto.py, arsc.py, dex.py and signing.py)
_TAMPERING = re.compile(
    r"(?i)end of central directory|precede(?:s)? the (?:archive|first entry)|duplicate entry"
    r"|differ only in case|zip slip|absolute path|encryption flag|compression method"
    r"|stored entry with different|local header gives another name|overlap the data"
    r"|CRC mismatch|declares \d+ entries|resource id|attribute without a name"
    r"|string pool declares|outside the string pool|past the end of the string pool"
    r"|header size|not aligned|unknown chunk|unknown XML node|appended data"
    r"|after the last chunk|malformed chunk|impossible size|elements are not closed"
    r"|more than one (?:string pool|resource map)|root chunk has type|ZIP64"
    r"|does not end where|size fields disagree|holds pair|checksum in the header"
    r"|does not fit the pool|bytes after the end of the table")


# ------------------------------------------------------------------ public API
def analyze(ctx: MobileContext, by_rel: Mapping[str, SourceFile]) -> Tuple[List[Finding], str]:
    """Run the structural checks on one app package or project. Returns the findings and the
    engine note ("ok (...)"); fills ctx.facts permissions, components, flags, endpoints and
    dependency_issues. A part that cannot be read is named in the note and the other checks
    still run."""
    run = _Run(ctx, by_rel)
    modules = run.step("manifests", lambda: _modules(run)) or []
    for module in modules:
        run.step("manifest " + module.main.rel, lambda: _module_checks(run, module))
    if ctx.is_app:
        run.step("asset files", lambda: _app_assets(run))
        run.step("build summary", lambda: _build_checks(run))
        run.step("signing summary", lambda: _signing_checks(run))
        run.step("packages", lambda: _app_packages(run))
        run.step("libapp.so strings", lambda: _strings_checks(run))
        run.step("decoder warnings", lambda: _tampering_check(run))
    else:
        run.step("Gradle", lambda: _gradle_checks(run, modules))
        run.step("signing files", lambda: _signing_files(run))
        run.step("Info.plist", lambda: _plist_checks(run))
        run.step("pubspec", lambda: _pubspec_checks(run))
        run.step("endpoints", lambda: _project_endpoints(run))
    run.step("facts", lambda: _fill_facts(run, modules))
    return run.findings, run.note()


def refine(findings: Sequence[Finding], by_rel: Mapping[str, SourceFile],
           ctx: Optional[MobileContext] = None) -> int:
    """Downgrade hard-coded Google API keys (AIza...) found in Firebase configuration files
    (google-services.json, GoogleService-Info.plist, firebase_options.dart, the Firebase
    entries of res/values/strings.xml, web/firebase-messaging-sw.js and the firebaseConfig of
    web/index.html) to low severity and confidence 0.4: they identify a project and are not
    secrets. The same holds for the copy that firebase_options.dart leaves in the strings
    dump of libapp.so when the dump also holds the other Firebase values (database URL,
    storage bucket, messagingSenderId). In a compiled manifest, a known Maps SDK metadata
    value is an expected client key whose server-side restrictions are unknown. Returns
    the number of findings changed."""
    changed = 0
    firebase_dump: Dict[str, bool] = {}
    maps_values = _packaged_maps_values(ctx)
    for finding in findings:
        if canonical(finding.cwe) != "CWE-798" or FIREBASE_NOTE in finding.description \
                or MAPS_CLIENT_NOTE in finding.description:
            continue
        sf = by_rel.get(finding.file)
        text = sf.lines[finding.line - 1] if sf and 1 <= finding.line <= len(sf.lines) \
            else finding.snippet
        if not _GOOGLE_KEY.search(text):
            continue
        maps_value = maps_values.get((finding.file, finding.line))
        if finding.rule_id == "SECRET-GOOGLE-001" and maps_value \
                and _GOOGLE_KEY.findall(text) == [maps_value]:
            finding.severity = "low"
            finding.confidence = 0.6
            finding.description = MAPS_CLIENT_NOTE
            finding.fix = MAPS_CLIENT_FIX
            changed += 1
            continue
        name = posixpath.basename(finding.file)
        if name not in FIREBASE_FILES and not _firebase_place(finding.file, sf, text,
                                                              firebase_dump):
            continue
        finding.severity = "low"
        finding.confidence = 0.4
        finding.description = (FIREBASE_NOTE + " " + finding.description).strip()
        finding.fix = FIREBASE_FIX
        changed += 1
    return changed


def _packaged_maps_values(ctx: Optional[MobileContext]) -> Dict[Tuple[str, int], str]:
    """Literal values at the Maps SDK manifest metadata, indexed for contextual review."""
    values = {}
    if ctx is None or not ctx.is_app:
        return values
    for rel, root in ctx.manifests:
        if root is None:
            continue
        info = ManifestInfo.from_node(root)
        # Binary XML decoders normalize qualified names and render the namespace
        # declaration separately. A source declaration, when present, must agree.
        if root.get("xmlns:" + info.attr_prefix[:-1]) not in (None, ANDROID_URI):
            continue
        attr = info.attr_prefix + "value"
        for meta_name in MAPS_KEY_METADATA:
            entry = info.app_meta_data.get(meta_name)
            if entry is not None:
                _, node = entry
                value = node.get(attr) or ""
                if _GOOGLE_KEY.fullmatch(value):
                    values[rel, node.line_of(attr)] = value
    return values


def _firebase_place(rel: str, sf: Optional[SourceFile], text: str,
                    dumps: Dict[str, bool]) -> bool:
    """True when a Google API key on this line sits in a Firebase configuration that is not
    named by its file: a Firebase entry of res/values/strings.xml, the firebaseConfig of
    web/index.html, or the strings dump of libapp.so of an app that uses Firebase."""
    if rel.endswith("res/values/strings.xml"):
        return bool(_FIREBASE_STRING.search(text))
    if sf is None:
        return False
    if rel == "web/index.html" or rel.endswith("/web/index.html"):
        return bool(_WEB_FIREBASE_CONFIG.search(sf.text))
    if sf.origin == "strings" and posixpath.basename(rel) == "libapp.so":
        if rel not in dumps:
            dumps[rel] = bool(_FIREBASE_MARKERS.search(sf.text))
        return dumps[rel]
    return False


# ------------------------------------------------------------------ the run
class _Run:
    """The state of one analysis: the files, the findings so far and what went wrong."""

    def __init__(self, ctx: MobileContext, by_rel: Mapping[str, SourceFile]):
        self.ctx = ctx
        self.files: Dict[str, SourceFile] = {sf.rel: sf for sf in ctx.files}
        self.files.update(by_rel)
        self.findings: List[Finding] = []
        self.problems: List[str] = []
        self.dropped: Dict[Tuple[str, str], int] = {}
        # module -> (manifest reference, config) of the network security config it uses
        self.configs: Dict[str, Tuple[str, NetworkSecurityConfig]] = {}
        self._keys: set = set()
        self._counts: Dict[Tuple[str, str], int] = {}
        self._xml: Dict[str, Optional[XmlNode]] = {}

    def step(self, name: str, fn: Callable[[], Any]) -> Any:
        """Run one part of the analysis; a failure is named in the note, not raised."""
        try:
            return fn()
        except Exception as exc:  # a broken input must not stop the other checks
            self.problems.append("%s (%s)" % (name, str(exc)[:120] or type(exc).__name__))
            return None

    def add(self, check_id: str, sf: SourceFile, line: int, description: str, fix: str, *,
            title: str = "", severity: str = "", confidence: Optional[float] = None,
            key: Any = None) -> None:
        """Add a finding unless the same problem is already reported (same check, file and
        `key`, by default the line) or the check reached MAX_PER_FILE in this file."""
        check = BY_ID[check_id]
        line = line if 1 <= line <= len(sf.lines) else 1
        if not self.accept(check_id, sf.rel, line if key is None else key):
            return
        self.findings.append(Finding(
            rule_id=check.id, title=title or check.title, file=sf.rel, line=line,
            severity=severity or check.severity, cwe=check.cwe, description=description,
            fix=fix, confidence=check.confidence if confidence is None else confidence,
            engines=[ENGINE], snippet=sf.line_text(line), language=sf.language))

    def accept(self, check_id: str, rel: str, key: Any) -> bool:
        if (check_id, rel, key) in self._keys:
            return False
        self._keys.add((check_id, rel, key))
        count = self._counts.get((check_id, rel), 0)
        if count >= MAX_PER_FILE:
            self.dropped[(check_id, rel)] = self.dropped.get((check_id, rel), 0) + 1
            return False
        self._counts[(check_id, rel)] = count + 1
        return True

    def extend(self, findings: Sequence[Finding]) -> None:
        """Findings made elsewhere (the pub audit), under the same limits."""
        for finding in findings:
            if finding.file in self.files \
                    and self.accept(finding.rule_id, finding.file, finding.line):
                self.findings.append(finding)

    def xml(self, rel: str) -> Optional[XmlNode]:
        """The XML tree of a file: from the loader, else parsed from the file's text."""
        if rel in self.ctx.xml_resources:
            return self.ctx.xml_resources[rel]
        if rel not in self._xml:
            node = None
            sf = self.files.get(rel)
            if sf is not None:
                node, error = parse_xml_text(sf.text)
                if node is None:
                    self.problems.append("%s (%s)" % (rel, error))
            self._xml[rel] = node
        return self._xml[rel]

    def note(self) -> str:
        text = "ok (%d findings" % len(self.findings)
        if self.dropped:
            text += "; at most %d per file and check, %d more dropped: %s" % (
                MAX_PER_FILE, sum(self.dropped.values()),
                ", ".join("%s in %s" % key for key in sorted(self.dropped)))
        if self.problems:
            text += "; not checked: " + "; ".join(self.problems[:5])
        return text + ")"


def _short(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _short_permission(name: str) -> str:
    return name[len("android.permission."):] if name.startswith("android.permission.") \
        else name


def _line_index(text: str) -> Callable[[int], int]:
    """offset -> 1-based line, counting lines the way str.splitlines() does."""
    starts = [0]
    for line in text.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))

    def line_of(offset: int) -> int:
        low, high = 0, len(starts) - 1
        while low < high:
            middle = (low + high + 1) // 2
            if starts[middle] <= offset:
                low = middle
            else:
                high = middle - 1
        return low + 1
    return line_of


# ------------------------------------------------------------------ Android manifests
@dataclass
class _Manifest:
    rel: str
    sf: SourceFile
    info: ManifestInfo
    main: bool                    # the app package's manifest or src/main (else an overlay)
    installed_split: bool = False


@dataclass
class _Module:
    """An Android app module: its release manifests (main first) and its Gradle file."""

    name: str
    manifests: List[_Manifest] = field(default_factory=list)
    gradle: Optional["GradleBuild"] = None
    gradle_sf: Optional[SourceFile] = None
    library: bool = False         # a com.android.library module: merged into an app later

    @property
    def main(self) -> _Manifest:
        return next((m for m in self.manifests if m.main), self.manifests[0])

    @property
    def debuggable(self) -> bool:
        """The release build is debuggable: android:debuggable="true" in a release manifest
        or debuggable true in the release build type."""
        return parse_bool(self.attr("debuggable")) is True \
            or bool(self.gradle and self.gradle.debuggable)

    def effective(self, name: str) -> Optional[Tuple[str, _Manifest]]:
        """An <application> attribute after merging, with the manifest that sets it: a release
        overlay wins over src/main."""
        found = None
        for manifest in self.manifests:
            if manifest.installed_split:
                continue    # split components are additive, not release application overlays
            value = manifest.info.app_attr(name)
            if value is not None:
                found = (value, manifest)
            elif found is not None and manifest.info.drops_inherited_app_attr(name):
                found = None
        return found

    def attr(self, name: str) -> Optional[str]:
        found = self.effective(name)
        return found[0] if found else None

    def sdk(self, kind: str) -> Optional["SdkLevel"]:
        """(level, file, line) of minSdk ("min") or targetSdk ("target"): the Gradle literal
        of a project, else <uses-sdk> of the manifest."""
        if self.gradle is not None and self.gradle_sf is not None:
            value = self.gradle.min_sdk if kind == "min" else self.gradle.target_sdk
            if value is not None:
                return value[0], self.gradle_sf, value[1]
        info = self.main.info
        level = info.min_sdk if kind == "min" else info.target_sdk
        if level is None or info.uses_sdk is None:
            if kind == "target" and self.gradle is not None and not self.gradle.target_sdk_set:
                # Gradle sets no targetSdk: the Android Gradle plugin uses minSdk
                return self.sdk("min")
            return None
        attr = info.attr_prefix + ("minSdkVersion" if kind == "min" else "targetSdkVersion")
        return level, self.main.sf, info.uses_sdk.line_of(attr)

    @property
    def target_sdk(self) -> Optional[int]:
        found = self.sdk("target")
        return found[0] if found else None

    @property
    def target_from_min(self) -> bool:
        """targetSdk is not set anywhere, so it is minSdk (sdk("target") gives that)."""
        info = self.main.info
        return (self.gradle is not None and self.gradle.target_sdk is None
                and not self.gradle.target_sdk_set
                and (info.uses_sdk is None or info.target_sdk is None)
                and self.sdk("min") is not None)


def _source_set(rel: str) -> Tuple[str, str]:
    """(module folder, source set) of a manifest path; ("", "main") for an app package."""
    match = _SOURCE_SET.match(rel)
    return (match.group("module") or "", match.group("set")) if match else ("", "main")


def _modules(run: _Run) -> List[_Module]:
    """Group the release manifests by module. Debug and profile source sets are left out; a
    src/release overlay the loader did not hand over is read here."""
    entries: Dict[str, XmlNode] = {}
    for rel, root in run.ctx.manifests:
        if root is not None:
            entries.setdefault(rel, root)
    if not run.ctx.is_app:
        for rel in list(entries):
            module, source_set = _source_set(rel)
            overlay = (module + "/" if module else "") + "src/release/AndroidManifest.xml"
            if source_set == "main" and overlay not in entries and overlay in run.files:
                root = run.xml(overlay)
                if root is not None:
                    entries[overlay] = root
    libraries = set(getattr(run.ctx, "library_manifests", None) or [])
    modules: Dict[str, _Module] = {}
    for rel, root in entries.items():
        sf = run.files.get(rel)
        if sf is None:
            continue
        module, source_set = ("", "main") if run.ctx.is_app else _source_set(rel)
        if _NOT_RELEASE.match(source_set):
            continue
        group = modules.get(module)
        if group is None:
            group = modules[module] = _Module(module)
            if not run.ctx.is_app:
                group.gradle_sf, group.gradle = _module_gradle(run, module)
                group.library = bool(group.gradle and group.gradle.library)
        if rel in libraries:
            group.library = True
        if run.ctx.facts.get("base_missing"):
            group.library = True   # an isolated split cannot establish app-wide defaults
        hint = ""
        if group.gradle is not None:
            hint = group.gradle.application_id or group.gradle.namespace
        fact_package = str(run.ctx.facts.get("package") or "")
        if not hint and "." in fact_package:
            hint = fact_package
        split = run.ctx.is_app and rel.startswith("splits/")
        group.manifests.append(_Manifest(rel, sf, ManifestInfo.from_node(root, package_hint=hint),
                                         source_set == "main" and not split, split))
    for group in modules.values():
        group.manifests.sort(key=lambda m: not m.main)
    return [group for group in modules.values() if group.manifests]


def _module_gradle(run: _Run, module: str) -> Tuple[Optional[SourceFile], Optional["GradleBuild"]]:
    prefix = module + "/" if module else ""
    for name in ("build.gradle.kts", "build.gradle"):
        sf = run.files.get(prefix + name)
        if sf is not None:
            return sf, read_gradle(sf.text)
    return None, None


def _module_checks(run: _Run, module: _Module) -> None:
    """The manifest checks of one module. A library module (com.android.library) is merged
    into an app that sets its own application attributes and SDK levels, so only its
    components, permissions, links and network security config are checked."""
    _application_checks(run, module)
    for manifest in module.manifests:
        _permission_checks(run, manifest)
        _safe_browsing_check(run, manifest)
        for comp in manifest.info.components:
            _component_checks(run, module, manifest, comp)
    if not module.library:
        _sdk_checks(run, module)


def _application_checks(run: _Run, module: _Module) -> None:
    app = run.ctx.is_app
    main = module.main
    if module.library:
        if main.info.application is not None:
            _network_config(run, module)
            _app_affinity_check(run, module)
        return
    for name, check_id, text, fix in (
            ("debuggable", "ANDROID-MANIFEST-001",
             "android:debuggable=\"true\" lets anyone with the device attach a debugger to the "
             "app, run code in its process and read its private files (adb run-as).",
             "Remove android:debuggable from the manifest: release builds are not debuggable "
             "by default."),
            ("testOnly", "ANDROID-MANIFEST-002",
             "android:testOnly=\"true\" marks a test build that is not meant to be "
             "distributed; it can only be installed with adb install -t.",
             "Remove android:testOnly and ship a build of the release build type."),
            ("requestLegacyExternalStorage", "ANDROID-MANIFEST-010",
             "android:requestLegacyExternalStorage=\"true\" opts out of scoped storage on "
             "Android 10, so the app keeps files in shared external storage where other apps "
             "with storage permissions can read and change them.",
             "Remove the attribute and keep app files in app-specific storage "
             "(getApplicationSupportDirectory in Flutter).")):
        found = module.effective(name)
        if found and parse_bool(found[0]) is True:
            manifest = found[1]
            confidence = None
            if check_id == "ANDROID-MANIFEST-001" and not app:
                confidence = 0.9
            run.add(check_id, manifest.sf, manifest.info.app_line(name), text, fix,
                    confidence=confidence)
    if main.info.application is None:
        return
    _native_memory_checks(run, module)
    _backup_check(run, module)
    config = _network_config(run, module)
    _cleartext_check(run, module, config)
    _app_affinity_check(run, module)


def _native_memory_checks(run: _Run, module: _Module) -> None:
    """Report explicit application defaults. A compiled manifest can store an enum as 0."""
    for name, check_id, disabled, description, fix in (
        ("allowNativeHeapPointerTagging", "ANDROID-MANIFEST-013", "false",
         "The application opts out of heap pointer tagging on supported 64-bit devices. "
         "That removes a check for native code that drops or changes a pointer tag.",
         "Review native libraries for pointer manipulation and test with the default tagging enabled."),
        ("gwpAsanMode", "ANDROID-MANIFEST-014", "never",
         "Processes inheriting this setting disable GWP-ASan's sampling of native allocations, "
         "including the recoverable checks available by default on Android 14 and later.",
         "Remove the explicit opt-out or enable GWP-ASan after testing native dependencies."),
        ("memtagMode", "ANDROID-MANIFEST-015", "off",
         "The application explicitly selects off for processes inheriting its hardware memory "
         "tagging setting. MTE can check native heap accesses on supported Arm devices.",
         "Review the opt-out and test native libraries on an MTE-capable device."),
    ):
        found = module.effective(name)
        if found is not None:
            value, manifest = found
            if value.strip().lower() == disabled or parse_int(value) == 0:
                run.add(check_id, manifest.sf, manifest.info.app_line(name), description, fix)


def _backup_check(run: _Run, module: _Module) -> None:
    policy = backup_policy(module.attr)
    if not policy.allowed:
        return
    fix = ("Set android:allowBackup=\"false\", or add dataExtractionRules and "
           "fullBackupContent rules that leave out tokens, databases and other private files.")
    target = module.target_sdk
    if policy.d2d_open(target):
        found = module.effective("fullBackupContent")
        manifest = found[1] if found else module.main
        run.add("ANDROID-MANIFEST-003", manifest.sf,
                manifest.info.app_line("fullBackupContent" if found else ""),
                "The app targets API %d and limits its backups only with "
                "android:fullBackupContent. On Android 12 and later that setting does not "
                "restrict device-to-device transfer, which follows android:dataExtractionRules, "
                "so the app's private files, databases and shared preferences are copied to a "
                "new device without the exclusions." % target,
                "Add android:dataExtractionRules with the same exclusions for cloud-backup and "
                "device-transfer (or set android:allowBackup=\"false\").",
                severity="low", confidence=0.6)
        return
    if policy.rules:
        return
    if policy.explicit:
        manifest = module.effective("allowBackup")[1]
        run.add("ANDROID-MANIFEST-003", manifest.sf, manifest.info.app_line("allowBackup"),
                "android:allowBackup=\"true\" without backup rules lets Android copy the "
                "app's private files, databases and shared preferences into cloud backups "
                "and device-to-device transfers, so stored tokens and data leave the device.",
                fix)
        return
    main = module.main
    run.add("ANDROID-MANIFEST-003", main.sf, main.info.app_line(),
            "The manifest does not set android:allowBackup, so the platform default (true) "
            "applies: Android copies the app's private files, databases and shared "
            "preferences into backups. The Flutter app template leaves the attribute out.",
            fix, severity="low", confidence=0.6)


def _network_config(run: _Run, module: _Module) -> Optional[NetworkSecurityConfig]:
    """The network security config of a module (checked once per file), or None."""
    found = module.effective("networkSecurityConfig")
    if not found or not found[0].strip():
        return None
    resolved = _resource(run, found[1], found[0], "network-security-config")
    if resolved is None:
        return None
    rel, node = resolved
    config = NetworkSecurityConfig.from_node(node)
    run.configs[module.name] = (found[0].strip(), config)
    sf = run.files.get(rel)
    if sf is not None:
        _nsc_checks(run, sf, config, debuggable=module.debuggable and not module.library)
    return config


def _resource(run: _Run, manifest: _Manifest, ref: str, root_tag: str
              ) -> Optional[Tuple[str, XmlNode]]:
    """The XML resource a manifest reference ("@xml/name") points to: next to the manifest
    in a project, through the loader's resource map in an app package. An unresolved
    reference (@0x7f...) falls back to the only resource with the expected root element."""
    ref = ref.strip()
    def expected(node: XmlNode) -> bool:
        return node.tag == root_tag or (root_tag == "paths" and
                                        bool(FileProviderPaths.from_node(node).paths))
    match = re.fullmatch(r"@(?:[\w.]+:)?(\w+)/([\w.]+)", ref)
    candidates: List[str] = []
    if manifest.installed_split:
        folder = manifest.rel.rsplit("/", 1)[0] + "/"
        same_member = run.ctx.resource_files.get(folder + ref)
        if same_member:
            candidates.append(same_member)
    if match:
        kind, name = match.groups()
        if not run.ctx.is_app:
            folder = manifest.rel.rsplit("/", 1)[0] if "/" in manifest.rel else ""
            module, _set = _source_set(manifest.rel)
            for base in (folder, (module + "/" if module else "") + "src/main"):
                candidates.append("%s/res/%s/%s.xml" % (base, kind, name) if base
                                  else "res/%s/%s.xml" % (kind, name))
        mapped = run.ctx.resource_files.get("@%s/%s" % (kind, name))
        if mapped:
            candidates.append(mapped)
        candidates.append("res/%s/%s.xml" % (kind, name))
    for rel in dict.fromkeys(candidates):
        if rel in run.files or rel in run.ctx.xml_resources:
            node = run.xml(rel)
            if node is not None and expected(node):
                return rel, node
    if not match and run.ctx.is_app:
        only = [(rel, node) for rel, node in run.ctx.xml_resources.items()
                if node is not None and expected(node)]
        if len(only) == 1:
            return only[0]
    return None


def _nsc_checks(run: _Run, sf: SourceFile, config: NetworkSecurityConfig, *,
                debuggable: bool = False) -> None:
    if config.base is not None and config.base_cleartext is True:
        run.add("ANDROID-NSC-001", sf, config.base.line_of("cleartextTrafficPermitted"),
                "The network security config allows cleartext HTTP for every domain "
                "(base-config), so Android 7.0 and later let WebView, Java/Kotlin code and "
                "plugins send unencrypted traffic. " + DART_NOTE,
                "Set cleartextTrafficPermitted=\"false\" in base-config and allow cleartext "
                "only in a domain-config for a development host.")
    for domain in config.domains:
        source = domain.cleartext_source
        if domain.cleartext is not True or domain.loopback_only or source is None:
            continue
        names = ", ".join(_short(name, 60) for name in domain.names[:5]) or "its domains"
        if source is domain:
            line = domain.node.line_of("cleartextTrafficPermitted")
            inherited = ""
        elif source.loopback_only:
            # the enclosing domain-config only opens loopback hosts and is not reported, but
            # this nested one inherits its cleartextTrafficPermitted="true"
            line = domain.node.line
            inherited = (" (the nested domain-config inherits cleartextTrafficPermitted=\"true\" "
                         "from the enclosing one for %s)"
                         % (", ".join(_short(name, 60) for name in source.names[:3])))
        else:
            continue                   # reported on the domain-config that sets it
        run.add("ANDROID-NSC-002", sf, line,
                "The network security config allows cleartext HTTP for %s%s, so WebView, "
                "Java/Kotlin code and plugins can reach these hosts unencrypted. %s"
                % (names, inherited, DART_NOTE),
                "Serve these domains over HTTPS and remove cleartextTrafficPermitted=\"true\".")
    if debuggable:
        _debug_override_checks(run, sf, config)
    for anchor, domain in config.anchors():
        where = "the domains " + ", ".join(_short(name, 60) for name in domain.names[:5]) \
            if domain and domain.names else "every domain"
        if anchor.src.lower() == "user":
            run.add("ANDROID-NSC-003", sf, anchor.node.line_of("src"),
                    "The network security config trusts certificate authorities that the "
                    "user installs (src=\"user\") for %s, so a proxy or malware CA on the "
                    "device can read and change the TLS traffic of WebView, Java/Kotlin code "
                    "and plugins. %s" % (where, DART_NOTE),
                    "Trust only system CAs in release builds; put <certificates src=\"user\"/> "
                    "inside <debug-overrides> for testing.")
        if anchor.override_pins:
            run.add("ANDROID-NSC-004", sf, anchor.node.line_of("overridePins"),
                    "overridePins=\"true\" lets certificates of the %s CAs bypass certificate "
                    "pinning for %s. %s" % (anchor.src or "listed", where, DART_NOTE),
                    "Remove overridePins outside <debug-overrides>.")
    for domain in config.domains:
        if domain.pin_set is not None and domain.pin_set.expired():
            run.add("ANDROID-NSC-004", sf, domain.pin_set.node.line_of("expiration"),
                    "The pin-set expired on %s: Android no longer enforces these pins, so "
                    "any trusted CA is accepted for %s. %s" % (
                        domain.pin_set.expiration,
                        ", ".join(_short(name, 60) for name in domain.names[:5]) or "the domains",
                        DART_NOTE),
                    "Rotate the pins and set an expiration date in the future.")


def _debug_override_checks(run: _Run, sf: SourceFile, config: NetworkSecurityConfig) -> None:
    """<debug-overrides> applies whenever the app is debuggable (android:debuggable="true"),
    so in a debuggable release its trust anchors are added to every domain."""
    for anchor in config.debug_trust_anchors:
        if anchor.src.lower() == "user":
            run.add("ANDROID-NSC-003", sf, anchor.node.line_of("src"),
                    "The app is debuggable, so the <debug-overrides> of its network security "
                    "config apply: certificate authorities that the user installs "
                    "(src=\"user\") are trusted for every domain, and a proxy or malware CA on "
                    "the device can read and change the TLS traffic of WebView, Java/Kotlin "
                    "code and plugins. %s" % DART_NOTE,
                    "Ship a release build that is not debuggable (remove android:debuggable and "
                    "debuggable true from the release build type).")
        if anchor.override_pins:
            run.add("ANDROID-NSC-004", sf, anchor.node.line_of("overridePins"),
                    "The app is debuggable, so the <debug-overrides> of its network security "
                    "config apply: overridePins=\"true\" lets certificates of the %s CAs bypass "
                    "certificate pinning for every domain. %s" % (anchor.src or "listed",
                                                                 DART_NOTE),
                    "Ship a release build that is not debuggable.")


def _cleartext_check(run: _Run, module: _Module,
                     config: Optional[NetworkSecurityConfig]) -> None:
    found = module.effective("usesCleartextTraffic")
    fix = ("Remove android:usesCleartextTraffic (or set it to false) and use HTTPS; allow a "
           "development host in a network security config domain-config when needed.")
    if found and parse_bool(found[0]) is True:
        manifest = found[1]
        text = ("android:usesCleartextTraffic=\"true\" allows unencrypted HTTP for WebView, "
                "Java/Kotlin code and plugins. ")
        severity, confidence = "", None
        if (module.effective("networkSecurityConfig") or ("", None))[0].strip():
            minimum = module.sdk("min")
            if minimum and minimum[0] >= 24:
                text = ("android:usesCleartextTraffic=\"true\" is set, but the app also has a "
                        "network security config and runs only on Android 7.0 (API 24) and "
                        "later (minSdk %d), where the config replaces the attribute: the "
                        "attribute has no effect, and the config decides about cleartext "
                        "traffic. It still shows the intent to allow HTTP and applies again if "
                        "the config is removed. " % minimum[0])
                severity, confidence = "low", 0.6
            else:
                text += ("The app also has a network security config, which takes its place "
                         "on Android 7.0 and later. ")
        run.add("ANDROID-MANIFEST-004", manifest.sf,
                manifest.info.app_line("usesCleartextTraffic"), text + DART_NOTE, fix,
                severity=severity, confidence=confidence)
        return
    target = module.target_sdk
    policy = cleartext_policy(None if found is None else found[0], config, target)
    if found or policy.source != SOURCE_DEFAULT or not policy.permitted:
        return
    main = module.main
    run.add("ANDROID-MANIFEST-004", main.sf, main.info.app_line(),
            "The app targets API %d and sets no cleartext policy, so Android allows "
            "unencrypted HTTP by default (the default changed with targetSdk 28). %s"
            % (target, DART_NOTE),
            "Set android:usesCleartextTraffic=\"false\" or raise targetSdk to 28 or later.",
            severity="low", confidence=0.6)


def _app_affinity_check(run: _Run, module: _Module) -> None:
    for manifest in module.manifests:
        application = manifest.info.application
        if application is None:
            continue
        prefix = manifest.info.attr_prefix
        reparenting = parse_bool(application.get(prefix + "allowTaskReparenting"))
        affinity = application.get(prefix + "taskAffinity")
        _affinity_finding(run, manifest, application, "The application", reparenting,
                          affinity.strip() if affinity is not None else None)


def _affinity_finding(run: _Run, manifest: _Manifest, node: XmlNode, who: str,
                      reparenting: Optional[bool], affinity: Optional[str]) -> None:
    prefix = manifest.info.attr_prefix
    package = manifest.info.package
    fix = ("Remove android:allowTaskReparenting and set android:taskAffinity=\"\" on "
           "activities (as the Flutter template does) unless the app needs another task "
           "layout.")
    if reparenting:
        run.add("ANDROID-MANIFEST-011", manifest.sf, node.line_of(prefix + "allowTaskReparenting"),
                "%s sets android:allowTaskReparenting=\"true\": its activities can move into "
                "another task with the same affinity, the mechanism of task hijacking "
                "(StrandHogg) on Android versions before 11." % who, fix)
    elif affinity is not None and "." in package and not is_own_affinity(affinity, package):
        run.add("ANDROID-MANIFEST-011", manifest.sf, node.line_of(prefix + "taskAffinity"),
                "%s sets android:taskAffinity=\"%s\", which is not the app's own package "
                "(%s): its activities join the task of another app, which is how task "
                "hijacking places a screen over another app."
                % (who, _short(affinity), _short(package)), fix)


def _permission_checks(run: _Run, manifest: _Manifest) -> None:
    prefix = manifest.info.attr_prefix
    for requested in manifest.info.requested:
        name = requested.name
        dangerous, special = is_dangerous(name), is_special(name)
        if not (dangerous or special):
            continue
        short = _short_permission(name)
        if dangerous:
            title = "Dangerous permission requested: %s" % short
            text = ("The app requests the dangerous permission %s, which gives access to "
                    "private user data or device functions; a bug or a malicious library in "
                    "the app can misuse it." % name)
        else:
            title = "Special access permission requested: %s" % short
            text = ("The app requests %s, a special access permission that the user grants "
                    "in the system settings; it gives the app powers far beyond normal "
                    "permissions." % name)
        run.add("ANDROID-MANIFEST-009", manifest.sf, requested.node.line_of(prefix + "name"),
                text, "Request only the permissions the app's features need, and remove unused "
                "ones, including those that plugins add (tools:node=\"remove\").",
                title=title, key=name)


SAFE_BROWSING = "android.webkit.WebView.EnableSafeBrowsing"


def _safe_browsing_check(run: _Run, manifest: _Manifest) -> None:
    found = manifest.info.app_meta_data.get(SAFE_BROWSING)
    if not found or parse_bool(found[0]) is not False:
        return
    node = found[1]
    prefix = manifest.info.attr_prefix
    line = node.line_of(prefix + "value") if node.get(prefix + "value") is not None \
        else node.line
    run.add("ANDROID-MANIFEST-012", manifest.sf, line,
            "The manifest sets android.webkit.WebView.EnableSafeBrowsing to false, which "
            "switches Google Safe Browsing off for every WebView of the app (current WebView "
            "versions turn it on by default): pages known for phishing or malware load "
            "without a warning.",
            "Remove the meta-data entry so that WebViews keep Safe Browsing on.")


_KIND_NAMES = {"activity": "activity", "activity-alias": "activity alias",
               "service": "service", "receiver": "broadcast receiver",
               "provider": "content provider"}


def _component_checks(run: _Run, module: _Module, manifest: _Manifest,
                      comp: Component) -> None:
    if comp.kind == "activity":
        _affinity_finding(run, manifest, comp.node, "The activity " + _short(comp.name or "?"),
                          comp.allow_task_reparenting, comp.task_affinity)
    if comp.is_file_provider:
        # FileProvider refuses to run when exported: its risk is the paths it shares
        _file_provider_check(run, manifest, comp)
        return
    if not comp.exported(module.target_sdk):
        return
    if comp.kind in ("activity", "activity-alias"):
        _link_checks(run, manifest, comp)
        # the launcher is exported by design, and so is an activity that only opens links
        # (an OAuth redirect, a file opener; the link checks report that entry point) or only
        # receives shared content (a share target of the share sheet)
        if comp.launcher or (comp.filters and all(f.is_link or f.is_share
                                                  for f in comp.filters)):
            return
    if comp.kind == "receiver" and comp.filters and all(f.is_app_widget for f in comp.filters):
        return                         # a home screen widget: the launcher sends its updates
    if comp.kind == "provider":
        _provider_export(run, manifest, comp)
    else:
        _guard_check(run, manifest, comp)


def _export_text(comp: Component, what: str) -> str:
    """"The service X is exported <what>." plus a note when the export is a default."""
    kind = _KIND_NAMES.get(comp.kind, comp.kind)
    text = "The %s %s is exported %s" % (kind, _short(comp.name or "?"), what)
    if comp.exported_attr is None:
        text += (" It has no android:exported attribute, and its intent filter makes it "
                 "exported by default.")
    return text


def _guard_check(run: _Run, manifest: _Manifest, comp: Component) -> None:
    strength = manifest.info.guard_strength(comp.guard)
    if strength == GUARD_STRONG:
        return
    if strength != GUARD_NONE:
        _weak_guard(run, manifest, comp, comp.guard, "permission", strength)
        return
    kind = _KIND_NAMES.get(comp.kind, comp.kind)
    run.add("ANDROID-MANIFEST-005", manifest.sf, comp.line_of("exported"),
            _export_text(comp, "without a permission, so any app on the device can start it "
                               "and hand it data."),
            "Set android:exported=\"false\" unless other apps must use it, or protect it with a "
            "permission whose protectionLevel is signature.",
            title="Exported %s without a permission: %s" % (kind, _short(comp.name or "?")),
            key=("component", comp.name, comp.node.line))


def _weak_guard(run: _Run, manifest: _Manifest, comp: Component, permission: str, attr: str,
                strength: str) -> None:
    """ANDROID-MANIFEST-006 on the attribute that names the weak permission."""
    kind = _KIND_NAMES.get(comp.kind, comp.kind)
    if strength == GUARD_WEAK:
        resolved = manifest.info.resolve(permission)
        defined = manifest.info.defined.get(resolved)
        if defined:
            level = "protection level is %s" % (defined.protection_level or "normal")
        elif is_dangerous(resolved):
            level = "protection level is dangerous"
        elif is_special(resolved):
            level = "protection level lets the user grant it in the system settings"
        elif is_normal(resolved) or not resolved.startswith("android.permission."):
            level = "protection level is normal"
        else:
            level = ""
        why = ("and protected by %s, whose %s: any app can request and get it."
               % (_short(permission), level)) if level else (
            "and protected by %s, a platform permission that is not known to be signature "
            "level: other apps can probably request and get it." % _short(permission))
    else:
        why = ("and protected by %s, which neither this app nor Android defines: another app "
               "can define it first and grant it to itself." % _short(permission))
    line = comp.line_of(attr) if comp.attr(attr) is not None else \
        _app_permission_line(manifest) or comp.line_of("exported")
    run.add("ANDROID-MANIFEST-006", manifest.sf, line, _export_text(comp, why),
            "Define the permission in this app with android:protectionLevel=\"signature\", or "
            "stop exporting the component.",
            title="Exported %s with a weak permission: %s" % (kind, _short(comp.name or "?")),
            key=("component", comp.name, comp.node.line, line))


def _app_permission_line(manifest: _Manifest) -> int:
    application = manifest.info.application
    prefix = manifest.info.attr_prefix
    if application is not None and application.get(prefix + "permission") is not None:
        return application.line_of(prefix + "permission")
    return 0


def _provider_export(run: _Run, manifest: _Manifest, comp: Component) -> None:
    read, write = comp.provider_guards
    if comp.path_permissions and not (read or write):
        return                         # <path-permission> elements guard parts of it
    info = manifest.info
    strengths = {"read": info.guard_strength(read), "write": info.guard_strength(write)}
    open_ops = [op for op, strength in strengths.items() if strength == GUARD_NONE]
    if open_ops:
        access = {("read",): "read", ("write",): "change"}.get(tuple(open_ops),
                                                                  "read and change")
        run.add("ANDROID-MANIFEST-005", manifest.sf, comp.line_of("exported"),
                _export_text(comp, "without a %s permission, so any app on the device can %s "
                                   "its data." % (" or ".join(open_ops), access)),
                "Set android:exported=\"false\" unless other apps must use it, or set "
                "android:readPermission and android:writePermission to signature-level "
                "permissions.",
                title="Exported content provider without a permission: %s"
                % _short(comp.name or "?"),
                key=("component", comp.name, comp.node.line))
        return
    for op, permission, attr in (("read", read, "readPermission"),
                                 ("write", write, "writePermission")):
        if strengths[op] in (GUARD_WEAK, GUARD_UNDEFINED):
            if comp.attr(attr) is None:
                attr = "permission"
            _weak_guard(run, manifest, comp, permission, attr, strengths[op])


def _link_checks(run: _Run, manifest: _Manifest, comp: Component) -> None:
    prefix = manifest.info.attr_prefix
    kind = _KIND_NAMES.get(comp.kind, comp.kind)
    for intent_filter in comp.filters:
        if not intent_filter.is_link:
            continue
        for scheme in intent_filter.schemes:
            low = scheme.lower()
            if low in WEB_SCHEMES or low in STANDARD_SCHEMES:
                continue
            node = intent_filter.data_node_with_scheme(scheme) or intent_filter.node
            run.add("ANDROID-MANIFEST-007", manifest.sf, node.line_of(prefix + "scheme"),
                    "The %s %s opens links with the custom scheme %s://. Any app can register "
                    "the same scheme and receive these links, and any app or web page can send "
                    "them, so every value in such a link is untrusted input."
                    % (kind, _short(comp.name or "?"), _short(scheme, 40)),
                    "Use verified https App Links (android:autoVerify=\"true\") for sensitive "
                    "flows such as sign-in, and validate every parameter of the link.",
                    title="Deep link with a custom scheme: %s://" % _short(scheme, 40),
                    key=("scheme", comp.name, scheme))
        web = [s for s in intent_filter.schemes if s.lower() in WEB_SCHEMES]
        if web and intent_filter.browsable and not intent_filter.auto_verify:
            hosts = ", ".join(intent_filter.hosts[:5]) or "any host"
            run.add("ANDROID-MANIFEST-008", manifest.sf, intent_filter.node.line,
                    "The %s %s opens web links of %s without android:autoVerify=\"true\", so "
                    "Android does not check that the app owns the domain: another app can "
                    "claim the same links, and the user may be asked which app opens them."
                    % (kind, _short(comp.name or "?"), _short(hosts, 120)),
                    "Add android:autoVerify=\"true\" to the intent filter and publish "
                    "/.well-known/assetlinks.json on the domain.",
                    title="Web link without App Links verification: %s" % _short(hosts, 60))


def _file_provider_check(run: _Run, manifest: _Manifest, comp: Component) -> None:
    ref = comp.file_provider_paths
    if not ref:
        return
    resolved = _resource(run, manifest, ref, "paths")
    if resolved is None:
        return
    rel, node = resolved
    sf = run.files.get(rel)
    if sf is None:
        return
    fix = ("Share only dedicated folders that hold the files the app sends, for example "
           "<cache-path name=\"shared\" path=\"shared/\"/>.")
    provider = _short(comp.name or "?")
    for path in FileProviderPaths.from_node(node).too_wide():
        exposure = path.exposure
        shown = _short(path.path, 40)
        if exposure == EXPOSE_FILESYSTEM:
            run.add("ANDROID-FILEPROVIDER-001", sf, path.node.line,
                    "The FileProvider %s shares <root-path%s>, %s of the device's file "
                    "system: a content URI can then point to any file the app can read, "
                    "including its databases, shared preferences and tokens."
                    % (provider, " path=\"%s\"" % shown if path.path.strip() else "",
                       "the root" if not path.path.strip("/. ") else "a whole storage root"),
                    fix, title="FileProvider shares the file system root")
        elif exposure == EXPOSE_APP_DATA:
            run.add("ANDROID-FILEPROVIDER-001", sf, path.node.line,
                    "The FileProvider %s shares <root-path path=\"%s\">, an app's whole private "
                    "data folder: a content URI can then point to its databases, shared "
                    "preferences and tokens." % (provider, shown),
                    fix, title="FileProvider shares the app's private data folder")
        elif exposure == EXPOSE_NARROW_ROOT:
            run.add("ANDROID-FILEPROVIDER-001", sf, path.node.line,
                    "The FileProvider %s shares the folder /%s through <root-path>, an "
                    "undocumented element that maps an absolute path. The folder is narrow, "
                    "so only the files in it can be offered to other apps through content "
                    "URIs." % (provider, _short(path.path.strip().strip("/"), 40)),
                    "Use the documented path elements (cache-path, files-path, "
                    "external-files-path) with a dedicated folder instead of <root-path>.",
                    title="FileProvider shares a folder through <root-path>",
                    severity="low", confidence=0.5)
        elif exposure == EXPOSE_PARENT:
            private = path.kind in PRIVATE_KINDS
            run.add("ANDROID-FILEPROVIDER-001", sf, path.node.line,
                    "The FileProvider %s shares <%s path=\"%s\">, which climbs out of its root "
                    "folder with \"..\": FileProvider resolves the path, so it shares %s." % (
                        provider, path.kind, shown,
                        "the app's whole private data folder, with its databases, shared "
                        "preferences and tokens" if private else
                        "a parent folder of the app's external storage"),
                    fix, title="FileProvider path climbs out of its folder (..)",
                    severity="high" if private else "medium",
                    confidence=0.8 if private else 0.6)
        else:
            folder = "internal files folder" if path.kind == "files-path" \
                else "external storage"
            run.add("ANDROID-FILEPROVIDER-001", sf, path.node.line,
                    "The FileProvider %s shares the app's whole %s (<%s path=\"%s\">), so a "
                    "content URI can expose any file in it." % (
                        _short(comp.name or "?"), folder, path.kind, _short(path.path, 20)),
                    fix, title="FileProvider shares the whole %s" % folder,
                    severity="medium", confidence=0.6)


SdkLevel = Tuple[int, SourceFile, int]           # (level, file, line)


def _sdk_checks(run: _Run, module: _Module) -> None:
    _sdk_findings(run, module.sdk("min"), module.sdk("target"),
                  target_from_min=module.target_from_min)


def _sdk_findings(run: _Run, minimum: Optional[SdkLevel], target: Optional[SdkLevel], *,
                  target_from_min: bool = False) -> None:
    if minimum and minimum[0] < 24:
        level, sf, line = minimum
        run.add("ANDROID-SDK-001", sf, line,
                "minSdk %d lets the app run on Android versions before 7.0 (API 24), which "
                "have no network security config, trust user-installed CAs by default and no "
                "longer get security updates." % level,
                "Raise minSdk to 24 or later (Flutter's default, flutter.minSdkVersion).")
    if target and target[0] < 28:
        level, sf, line = target
        run.add("ANDROID-SDK-002", sf, line,
                "%stargetSdk %d keeps old platform behaviour: cleartext HTTP allowed by default, "
                "and newer protections for files, components and links switched off." % (
                    "The build sets no targetSdk, so the Android Gradle plugin uses minSdk: "
                    if target_from_min else "", level),
                "Target a current Android version (flutter.targetSdkVersion); Google Play also "
                "requires a recent targetSdk.")


# ------------------------------------------------------------------ Gradle
@dataclass
class GradleBuild:
    """What the checks need from an app-level build.gradle or build.gradle.kts."""

    application_id: str = ""
    namespace: str = ""
    min_sdk: Optional[Tuple[int, int]] = None          # (level, line); literals only
    target_sdk: Optional[Tuple[int, int]] = None
    target_sdk_set: bool = False                       # targetSdk is set, literal or not
    library: bool = False                              # applies com.android.library only
    debug_signing: List[Tuple[int, bool]] = field(default_factory=list)  # (line, a fallback)
    # line -> "defaultConfig" or "initWith" for debug signing that the release type inherits
    debug_signing_via: Dict[int, str] = field(default_factory=dict)
    no_minify: List[int] = field(default_factory=list)
    debuggable: List[int] = field(default_factory=list)
    passwords: List[Tuple[int, str]] = field(default_factory=list)       # (line, key)


_TOKEN = re.compile(r"//|/\*|\"\"\"|'''|\"|'")
# a named block: release { }, getByName("release") { }, getByName<ApplicationBuildType>(
# "release") { }, getByName("release").apply { }, buildTypes["release"] { }
_BLOCK = re.compile(
    r"""(?:\b(?:getByName|named|create|maybeCreate|register|getAt|findByName)\s*"""
    r"""(?:<[\w.?, ]{1,120}>\s*)?\(\s*["']([\w.-]+)["']\s*\)!{0,2}|\[\s*["']([\w.-]+)["']\s*\]"""
    r"""|\b([A-Za-z_]\w*))\s*(?:\.\s*(?:apply|also|run|let|configure)\s*)?\{""")
# the text in front of a block of the release build type outside a buildTypes block:
# buildTypes.release { }, buildTypes.getByName("release") { }, buildTypes["release"] { }
_BUILD_TYPES_PREFIX = re.compile(r"\bbuildTypes\s*\.?\s*$")
_DEBUG_SIGNING = re.compile(
    r"""\bsigningConfigs\s*(?:\.\s*(?:debug\b"""
    r"""|(?:getByName|named|getAt|findByName)\s*\(\s*["']debug["']\s*\))"""
    r"""|\[\s*["']debug["']\s*\])""")
_OTHER_SIGNING = re.compile(
    r"""\bsigningConfigs\s*(?:\.\s*(?!debug\b)\w+\b(?!\s*\(\s*["']debug)"""
    r"""|\[\s*["'](?!debug["']))""")
# any signingConfig setting of a build type (signingConfig x, signingConfig = x, setSigningConfig)
_SIGNING_CONFIG = re.compile(r"\b(?:set)?[Ss]igningConfig\b(?!s)")
# initWith debug / initWith(buildTypes.getByName("debug")): a copy of the debug build type
_INIT_WITH_DEBUG = re.compile(
    r"""\binitWith\s*\(?\s*(?:(?:android\s*\.\s*)?buildTypes\s*\.\s*)?"""
    r"""(?:debug\b|getByName\s*\(\s*["']debug["']\s*\))""")
_DEBUGGABLE_SET = re.compile(r"\b(?:set|is)?[Dd]ebuggable\s*(?:=\s*|\(\s*|\s+)\S")
# android.buildTypes.release.signingConfig = android.signingConfigs.debug (a statement)
_RELEASE_SIGNING_STATEMENT = re.compile(
    r"""\bbuildTypes\s*\.\s*(?:release|getByName\s*\(\s*["']release["']\s*\))\s*\.\s*"""
    r"""signingConfig\b\s*=?\s*(?P<value>[^\n;]*)""")
_NO_MINIFY = re.compile(r"\b(?:set|is)?[Mm]inifyEnabled\s*(?:=\s*|\(\s*)?false\b")
_DEBUGGABLE = re.compile(r"\b(?:set|is)?[Dd]ebuggable\s*(?:=\s*|\(\s*)?true\b")
_PASSWORD = re.compile(r"""\b(storePassword|keyPassword)\s*(?:=\s*|\(\s*)?(["'])([^"'\n]*)\2""")
_SDK = re.compile(r"\b(minSdk|minSdkVersion|targetSdk|targetSdkVersion)\s*(?:=\s*|\(\s*|\s+)"
                  r"([0-9]{1,3})\b")
_TARGET_SET = re.compile(r"\btargetSdk(?:Version|Preview)?\b(?!\s*[.)])")
_ID = re.compile(r"""\b(applicationId|namespace)\s*(?:=\s*|\(\s*|\s+)["']([\w.]+)["']""")
_LIBRARY_PLUGIN = re.compile(
    r"""["']com\.android\.library["']|\blibs\.plugins\.android\.library\b""")
_APP_PLUGIN = re.compile(
    r"""["']com\.android\.application["']|\blibs\.plugins\.android\.application\b""")
MAX_BLOCK_DEPTH = 64           # enclosing blocks followed up from a block
MAX_BUILD_TYPE_BLOCKS = 20     # release / defaultConfig blocks read per file


def _masks(text: str) -> Tuple[str, str]:
    """(code, skeleton) of a Groovy or Kotlin build script, both as long as the text: code
    has comments blanked, skeleton also the contents of strings. Line breaks are kept."""
    code, skeleton = list(text), list(text)

    def blank(chars: List[str], start: int, end: int) -> None:
        for i in range(start, min(end, len(chars))):
            if chars[i] not in "\r\n":
                chars[i] = " "
    pos = 0
    while True:
        match = _TOKEN.search(text, pos)
        if not match:
            break
        token, start = match.group(), match.start()
        if token == "//":
            end = text.find("\n", start)
            end = len(text) if end < 0 else end
            blank(code, start, end)
            blank(skeleton, start, end)
        elif token == "/*":
            end = text.find("*/", start + 2)
            end = len(text) if end < 0 else end + 2
            blank(code, start, end)
            blank(skeleton, start, end)
        elif len(token) == 3:
            end = text.find(token, start + 3)
            end = len(text) if end < 0 else end + 3
            blank(skeleton, start + 3, end - 3)
        else:
            end = start + 1
            while end < len(text) and text[end] not in (token, "\n"):
                end += 2 if text[end] == "\\" else 1
            blank(skeleton, start + 1, end)
            end = min(end + 1, len(text))
        pos = max(end, start + 1)
    return "".join(code), "".join(skeleton)


@dataclass
class _Block:
    name: str
    start: int                 # the offset of the block's name
    open: int                  # its opening brace
    close: int                 # its closing brace
    parent: int                # index of the enclosing named block, -1 at the top


def _blocks(code: str, skeleton: str) -> List[_Block]:
    """Every named block with its enclosing named block (an index, so that deeply nested
    input does not keep a list of all enclosing names per block)."""
    closing: Dict[int, int] = {}
    stack: List[int] = []
    for match in re.finditer(r"[{}]", skeleton):
        if match.group() == "{":
            stack.append(match.start())
        elif stack:
            closing[stack.pop()] = match.start()
    out: List[_Block] = []
    open_blocks: List[int] = []                  # indexes in `out` of the enclosing blocks
    for match in _BLOCK.finditer(code):
        brace = match.end() - 1
        if skeleton[brace] != "{" or brace not in closing:
            continue
        while open_blocks and out[open_blocks[-1]].close < brace:
            open_blocks.pop()
        out.append(_Block(match.group(1) or match.group(2) or match.group(3), match.start(),
                          brace, closing[brace], open_blocks[-1] if open_blocks else -1))
        open_blocks.append(len(out) - 1)
    return out


def _parents(blocks: Sequence[_Block], block: _Block) -> Iterator[_Block]:
    """The enclosing named blocks, innermost first (at most MAX_BLOCK_DEPTH)."""
    index = block.parent
    for _ in range(MAX_BLOCK_DEPTH):
        if index < 0:
            return
        yield blocks[index]
        index = blocks[index].parent


def _is_release_type(code: str, blocks: Sequence[_Block], block: _Block) -> bool:
    """A block of the release build type: release { } (or getByName("release") { } ...) in
    a buildTypes block, or after buildTypes. / buildTypes[...] outside one."""
    if block.name != "release":
        return False
    if block.parent >= 0 and blocks[block.parent].name == "buildTypes":
        return True
    return bool(_BUILD_TYPES_PREFIX.search(code[max(0, block.start - 100):block.start]))


def _outermost(blocks: Sequence[_Block], wanted: Callable[[_Block], bool]
               ) -> List[Tuple[int, int]]:
    """(open, close) of the wanted blocks that are not inside another wanted block, in
    order: they do not overlap, so a bisect finds the one around an offset."""
    out: List[Tuple[int, int]] = []
    for block in blocks:                       # blocks come in the order of their braces
        if wanted(block) and not (out and out[-1][0] < block.open < out[-1][1]):
            out.append((block.open, block.close))
    return out


def _inside(intervals: Sequence[Tuple[int, int]], offset: int) -> bool:
    index = bisect.bisect_right(intervals, (offset, 1 << 62)) - 1
    return index >= 0 and intervals[index][0] < offset < intervals[index][1]


def read_gradle(text: str) -> GradleBuild:
    """Read the release build type, the signing configs, the SDK levels and the ids of an
    app-level Gradle build file (Groovy or Kotlin DSL). Blocks are matched by braces with
    comments and strings skipped, so a brace in a string or a commented-out line does not
    count. Values that are not literals (flutter.minSdkVersion, properties) are left out.
    A release build type without a signingConfig of its own uses the one of defaultConfig,
    and initWith debug copies the debug build type (debug key, debuggable)."""
    build = GradleBuild()
    code, skeleton = _masks(text)
    line_of = _line_index(text)
    blocks = _blocks(code, skeleton)
    release_signed = False
    # a release block inside another one is not a build type: outermost ones only
    for start, end in _outermost(blocks, lambda b: _is_release_type(code, blocks, b)
                                 )[:MAX_BUILD_TYPE_BLOCKS]:
        body = code[start:end]
        debug = list(_DEBUG_SIGNING.finditer(body))
        fallback = bool(debug) and bool(_OTHER_SIGNING.search(body))
        build.debug_signing += [(line_of(start + m.start()), fallback) for m in debug]
        build.no_minify += [line_of(start + m.start()) for m in _NO_MINIFY.finditer(body)]
        build.debuggable += [line_of(start + m.start()) for m in _DEBUGGABLE.finditer(body)]
        signed = bool(_SIGNING_CONFIG.search(body))
        copy = _INIT_WITH_DEBUG.search(body)
        if copy:
            line = line_of(start + copy.start())
            if not signed:
                build.debug_signing.append((line, False))
                build.debug_signing_via[line] = "initWith"
            if not _DEBUGGABLE_SET.search(body):
                build.debuggable.append(line)
        release_signed = release_signed or signed or bool(copy)
    for match in _RELEASE_SIGNING_STATEMENT.finditer(code):
        release_signed = True
        value = match.group("value")
        if _DEBUG_SIGNING.search(value):
            build.debug_signing.append((line_of(match.start()),
                                        bool(_OTHER_SIGNING.search(value))))
    flavors = _outermost(blocks, lambda b: b.name == "productFlavors")
    defaults = _outermost(blocks, lambda b: b.name == "defaultConfig"
                          and not _inside(flavors, b.open))
    if not release_signed:
        # a release build type without its own signingConfig uses the one of defaultConfig;
        # product flavors with a signing config of their own replace it for their variants
        flavor_signing = any(_SIGNING_CONFIG.search(code, s, e) for s, e in flavors)
        for start, end in defaults[:MAX_BUILD_TYPE_BLOCKS]:
            body = code[start:end]
            fallback = flavor_signing or bool(_OTHER_SIGNING.search(body))
            for match in _DEBUG_SIGNING.finditer(body):
                line = line_of(start + match.start())
                build.debug_signing.append((line, fallback))
                build.debug_signing_via[line] = "defaultConfig"
    debug_configs = _outermost(blocks, lambda b: b.name == "debug" and b.parent >= 0
                               and blocks[b.parent].name == "signingConfigs")
    for match in _PASSWORD.finditer(code):
        value = match.group(3)
        if not value.strip() or "$" in value or _inside(debug_configs, match.start()):
            continue
        build.passwords.append((line_of(match.start()), match.group(1)))
    every_default = _outermost(blocks, lambda b: b.name == "defaultConfig")
    for match in _SDK.finditer(code):
        if every_default and not _inside(every_default, match.start()):
            continue
        entry = (int(match.group(2)), line_of(match.start()))
        if match.group(1).startswith("min") and build.min_sdk is None:
            build.min_sdk = entry
        elif match.group(1).startswith("target") and build.target_sdk is None:
            build.target_sdk = entry
        if build.min_sdk and build.target_sdk:
            break
    build.target_sdk_set = build.target_sdk is not None or bool(_TARGET_SET.search(code))
    for match in _ID.finditer(code):
        if match.group(1) == "applicationId" and not build.application_id:
            build.application_id = match.group(2)
        elif match.group(1) == "namespace" and not build.namespace:
            build.namespace = match.group(2)
        if build.application_id and build.namespace:
            break
    build.library = bool(_LIBRARY_PLUGIN.search(code)) and not _APP_PLUGIN.search(code)
    return build


def _gradle_checks(run: _Run, modules: Sequence[_Module]) -> None:
    builds: Dict[str, Tuple[SourceFile, GradleBuild]] = {}
    for module in modules:
        if module.gradle is not None and module.gradle_sf is not None:
            builds[module.gradle_sf.rel] = (module.gradle_sf, module.gradle)
    for rel in run.ctx.gradle_files:
        sf = run.files.get(rel)
        if sf is not None and rel not in builds:
            builds[rel] = (sf, read_gradle(sf.text))
    with_module = {m.gradle_sf.rel for m in modules if m.gradle_sf is not None}
    libraries = {m.gradle_sf.rel for m in modules if m.gradle_sf is not None and m.library}
    for rel, (sf, build) in builds.items():
        library = build.library or rel in libraries
        _gradle_findings(run, sf, build, library=library)
        if rel not in with_module and not library:   # no release manifest: no module checks
            _sdk_findings(run, (build.min_sdk[0], sf, build.min_sdk[1]) if build.min_sdk else None,
                          (build.target_sdk[0], sf, build.target_sdk[1]) if build.target_sdk
                          else None)


def _gradle_findings(run: _Run, sf: SourceFile, build: GradleBuild, *,
                     library: bool = False) -> None:
    """The findings of one Gradle file. The release build type of a library module does not
    make an app (it is not signed, and the app decides about shrinking and debugging), so
    only hard-coded passwords count there."""
    for line, key in build.passwords:
        run.add("ANDROID-GRADLE-004", sf, line,
                "The %s of a signing config is written in the build file, so everyone who "
                "has the source code or its history knows the password of the signing key."
                % key,
                "Read the passwords from key.properties or environment variables that are not "
                "committed, and change the exposed passwords.")
    if library:
        return
    for line, fallback in build.debug_signing:
        via = build.debug_signing_via.get(line, "")
        if via == "defaultConfig":
            text = ("defaultConfig uses the debug signing config, and the release build type "
                    "sets no signingConfig of its own, so it inherits it%s: the debug keystore "
                    "is created by the Android tools with a public password, so anyone can "
                    "sign an update that replaces the app." % (
                        " (unless a product flavor sets another one)" if fallback else ""))
        elif via == "initWith":
            text = ("The release build type starts as a copy of the debug build type "
                    "(initWith debug) and sets no signingConfig of its own, so it is signed "
                    "with the debug key, whose password is public.")
        elif fallback:
            text = ("The release build type falls back to the debug signing config when the "
                    "release key is not configured, so a release built on such a machine is "
                    "signed with the shared debug key, whose password is public.")
        else:
            text = ("The release build type is signed with the debug signing config. The debug "
                    "keystore is created by the Android tools with a public password, so anyone "
                    "can sign an update that replaces the app. The Flutter app template ships "
                    "this line (\"Signing with the debug keys for now\").")
        run.add("ANDROID-GRADLE-001", sf, line, text,
                "Create a release (upload) keystore, read its passwords from key.properties or "
                "environment variables kept out of version control, and use that signing "
                "config for the release build type.",
                confidence=0.6 if fallback else None)
    for line in build.no_minify:
        run.add("ANDROID-GRADLE-002", sf, line,
                "Code shrinking (R8) is switched off for the release build, so the Java and "
                "Kotlin names of the app and its plugins stay readable and unused code ships. "
                "The Flutter Gradle plugin turns shrinking on for release builds; this line "
                "turns it off.",
                "Remove the minifyEnabled false setting (or set it to true) and keep the R8 "
                "rules that plugins need.")
    for line in build.debuggable:
        run.add("ANDROID-GRADLE-003", sf, line,
                "The release build type is debuggable%s, so the shipped app accepts a debugger "
                "and adb run-as gives access to its private files." % (
                    " (initWith debug copies debuggable true from the debug build type)"
                    if "initWith" in sf.line_text(line) else ""),
                "Remove debuggable / isDebuggable from the release build type.")


# ------------------------------------------------------------------ signing files, Info.plist
def _signing_files(run: _Run) -> None:
    for rel in run.ctx.key_properties:
        sf = run.files.get(rel)
        if sf is None:
            continue
        ignored = _git_ignored(run, rel)
        for number, line in enumerate(sf.lines, 1):
            match = _KEY_PROPERTY.match(line)
            if not match or line.lstrip().startswith(("#", "!")):
                continue
            value = match.group(2).strip().strip("\"'")
            if not value or PLACEHOLDER.match(value):
                continue
            if ignored:
                run.add("ANDROID-SIGN-010", sf, number,
                        "key.properties holds the %s of the app's signing keystore inside the "
                        "project folder. It is kept out of version control by %s, so it is not "
                        "committed with the code, but it travels with copies and archives of "
                        "the project folder." % (match.group(1), ignored),
                        "Keep the file out of shared copies of the project, or read the "
                        "passwords from environment variables.",
                        severity="low")
                continue
            run.add("ANDROID-SIGN-010", sf, number,
                    "key.properties holds the %s of the app's signing keystore inside the "
                    "project folder; once it is committed or shared, everyone with the project "
                    "knows the password of the signing key." % match.group(1),
                    "Keep key.properties out of version control (the Flutter template's "
                    "android/.gitignore lists it), or read the passwords from environment "
                    "variables, and change exposed passwords.")
    for rel in run.ctx.keystores:
        sf = run.files.get(rel)
        if sf is None or posixpath.basename(rel).lower() == "debug.keystore":
            continue
        ignored = _git_ignored(run, rel)
        run.add("ANDROID-SIGN-011", sf, 1,
                "The keystore %s is stored inside the project. %s" % (rel, (
                    "It is kept out of version control by %s, but it travels with copies "
                    "and archives of the project folder." % ignored) if ignored else (
                    "If it is committed or shared, the app's signing key travels with the "
                    "source code.")),
                "Keep keystores outside the project and out of version control (Play App "
                "Signing can hold the app signing key).",
                title="Keystore file inside the project: %s" % posixpath.basename(rel),
                severity="low" if ignored else "")


MAX_GITIGNORE_BYTES = 256 * 1024


def _git_ignored(run: _Run, rel: str) -> str:
    """The .gitignore (its project path) that keeps `rel` out of version control: one in the
    file's folder or a parent folder up to the project root, read in git's order (a deeper
    file and a later line win, "!" re-includes). "" when none does."""
    parts = rel.split("/")
    verdict = ""
    for depth in range(len(parts)):              # the root's .gitignore first
        folder = "/".join(parts[:depth])
        ignore_rel = folder + "/.gitignore" if folder else ".gitignore"
        text = _project_text(run, ignore_rel)
        if not text:
            continue
        below = "/".join(parts[depth:])
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            if _ignore_matches(line[1:] if negate else line, below):
                verdict = "" if negate else ignore_rel
    return verdict


def _ignore_matches(pattern: str, path: str) -> bool:
    """A .gitignore pattern against a path relative to the .gitignore's folder (the common
    forms: name, *.ext, /anchored, dir/, **/name, a/b)."""
    directory = pattern.endswith("/")
    anchored = pattern.startswith("/")
    pattern = pattern.strip("/")
    if pattern.startswith("**/"):
        pattern, anchored = pattern[3:], False
    if not pattern:
        return False
    pattern = pattern.replace("**", "*")
    segments = path.split("/")
    folders = ["/".join(segments[:n]) for n in range(1, len(segments))]
    if "/" in pattern or anchored:
        targets = folders if directory else folders + [path]
        return any(fnmatch.fnmatchcase(target, pattern) for target in targets)
    names = segments[:-1] if directory else segments
    return any(fnmatch.fnmatchcase(name, pattern) for name in names)


def _project_text(run: _Run, rel: str) -> str:
    """The text of a small project file that the walk left out (.gitignore), "" if none."""
    sf = run.files.get(rel)
    if sf is not None:
        return sf.text
    if run.ctx.is_app:
        return ""
    try:
        path = Path(run.ctx.root) / rel
        if not path.is_file() or path.stat().st_size > MAX_GITIGNORE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in ("yes", "true", "1")


def _key_paths(value: Any, path: Tuple[Any, ...] = (), depth: int = 0
               ) -> Iterator[Tuple[Any, ...]]:
    """Every dictionary key of a plist as a path, in document order."""
    if depth > 50:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield path + (key,)
            yield from _key_paths(item, path + (key,), depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _key_paths(item, path + (index,), depth + 1)


class _Plist:
    """A parsed Info.plist with the line of each key (plistlib gives no line numbers: the
    n-th <key>NAME</key> line belongs to the n-th key NAME in document order)."""

    def __init__(self, sf: SourceFile):
        self.sf = sf
        self.data = plistlib.loads(sf.text.encode("utf-8"))
        self._occurrence: Dict[Tuple[Any, ...], int] = {}
        seen: Dict[str, int] = {}
        for path in _key_paths(self.data):
            name = str(path[-1])
            seen[name] = seen.get(name, 0) + 1
            self._occurrence[path] = seen[name]

    def line(self, *path: Any) -> int:
        name = str(path[-1])
        wanted = self._occurrence.get(tuple(path), 1)
        seen = 0
        for number, text in enumerate(self.sf.lines, 1):
            if "<key>%s</key>" % name in text:
                seen += 1
                if seen == wanted:
                    return number
        return 1


def _plist_checks(run: _Run) -> None:
    for rel in run.ctx.plists:
        sf = run.files.get(rel)
        if sf is None:
            continue
        try:
            plist = _Plist(sf)
        except Exception as exc:          # plistlib raises several types on bad input
            run.problems.append("%s (%s)" % (rel, str(exc)[:80] or type(exc).__name__))
            continue
        if isinstance(plist.data, dict):
            _ats_checks(run, plist)
            _plist_links_and_files(run, plist)


# keys that make iOS 10 and later ignore NSAllowsArbitraryLoads (Apple: "the value of
# NSAllowsArbitraryLoads is ignored ... if any of the following keys are present")
_ATS_OVERRIDES = ("NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia",
                  "NSAllowsLocalNetworking")


def _ats_checks(run: _Run, plist: _Plist) -> None:
    ats = plist.data.get("NSAppTransportSecurity")
    if not isinstance(ats, dict):
        return
    sf, top = plist.sf, "NSAppTransportSecurity"
    overrides = [key for key in _ATS_OVERRIDES if key in ats]
    arbitrary = _truthy(ats.get("NSAllowsArbitraryLoads"))
    if arbitrary and not overrides:
        run.add("IOS-PLIST-001", sf, plist.line(top, "NSAllowsArbitraryLoads"),
                "NSAllowsArbitraryLoads turns App Transport Security off: URLSession, WKWebView "
                "and native SDKs may use plain HTTP and weak TLS. Dart code (dart:io) does not "
                "use App Transport Security, so the Dart rules for http:// URLs cover it.",
                "Remove NSAllowsArbitraryLoads and add NSExceptionDomains entries only for "
                "hosts that cannot use HTTPS yet.")
    ignored = (" NSAllowsArbitraryLoads is also set, but iOS 10 and later ignore it because "
               "%s is present." % " / ".join(overrides)) if arbitrary and overrides else ""
    for key, what in (("NSAllowsArbitraryLoadsInWebContent", "web content (WKWebView)"),
                      ("NSAllowsArbitraryLoadsForMedia", "media (AVFoundation)")):
        if _truthy(ats.get(key)):
            run.add("IOS-PLIST-002", sf, plist.line(top, key),
                    "%s weakens App Transport Security for %s, so these connections can use "
                    "plain HTTP.%s" % (key, what, ignored),
                    "Serve the content over HTTPS and remove %s." % key)
            ignored = ""
    domains = ats.get("NSExceptionDomains")
    for domain, settings in (domains.items() if isinstance(domains, dict) else ()):
        if not isinstance(settings, dict):
            continue
        local = str(domain).strip().lower() in LOOPBACK_HOSTS
        for key in ("NSExceptionAllowsInsecureHTTPLoads",
                    "NSTemporaryExceptionAllowsInsecureHTTPLoads",
                    "NSThirdPartyExceptionAllowsInsecureHTTPLoads",
                    "NSTemporaryThirdPartyExceptionAllowsInsecureHTTPLoads"):
            if _truthy(settings.get(key)) and not local:
                run.add("IOS-PLIST-002", sf,
                        plist.line(top, "NSExceptionDomains", domain, key),
                        "%s allows plain HTTP to %s, so its traffic can be read and changed on "
                        "the network." % (key, _short(str(domain), 60)),
                        "Serve %s over HTTPS and remove the exception." % _short(str(domain), 60),
                        title="App Transport Security exception for %s" % _short(str(domain), 60))
        for key in ("NSExceptionMinimumTLSVersion", "NSTemporaryExceptionMinimumTLSVersion",
                    "NSThirdPartyExceptionMinimumTLSVersion",
                    "NSTemporaryThirdPartyExceptionMinimumTLSVersion"):
            version = str(settings.get(key) or "").strip()
            if version.lower() in ("tlsv1.0", "tlsv1.1"):
                run.add("IOS-PLIST-003", sf,
                        plist.line(top, "NSExceptionDomains", domain, key),
                        "The exception domain %s accepts %s, a TLS version with known weaknesses "
                        "that browsers and servers have retired." % (_short(str(domain), 60),
                                                                      version),
                        "Remove %s (the default minimum is TLS 1.2) and upgrade the server."
                        % key)


def _plist_links_and_files(run: _Run, plist: _Plist) -> None:
    sf = plist.sf
    url_types = plist.data.get("CFBundleURLTypes")
    for index, entry in enumerate(url_types if isinstance(url_types, list) else []):
        schemes = entry.get("CFBundleURLSchemes") if isinstance(entry, dict) else None
        names = [str(s).strip() for s in (schemes if isinstance(schemes, list) else [])
                 if str(s).strip() and str(s).strip().lower() not in WEB_SCHEMES]
        if not names:
            continue
        shown = ", ".join("%s://" % _short(name, 40) for name in names[:5])
        run.add("IOS-PLIST-004", sf, plist.line("CFBundleURLTypes", index, "CFBundleURLSchemes"),
                "The app registers the custom URL scheme %s. Any app can register the same "
                "scheme and receive these links, and any app or web page can send them, so "
                "every value in such a link is untrusted input." % shown,
                "Use Universal Links (associated domains) for sensitive flows such as sign-in, "
                "and validate every parameter of an incoming link.",
                title="Custom URL scheme registered: %s" % shown)
    if _truthy(plist.data.get("UIFileSharingEnabled")):
        files_app = _truthy(plist.data.get("LSSupportsOpeningDocumentsInPlace"))
        run.add("IOS-PLIST-005", sf, plist.line("UIFileSharingEnabled"),
                "UIFileSharingEnabled shares the app's Documents folder through Finder%s, so "
                "files the app keeps there (databases, downloads, Hive boxes in "
                "getApplicationDocumentsDirectory) can be copied off the device."
                % (" and the Files app" if files_app else ""),
                "Remove UIFileSharingEnabled, or keep private data in Application Support "
                "(getApplicationSupportDirectory in Flutter) instead of Documents.")


# ------------------------------------------------------------------ pubspec and assets
def _pubspec_checks(run: _Run) -> None:
    for pubspec_rel, lock_rel in run.ctx.pubspecs:
        sf = run.files.get(pubspec_rel)
        if sf is None:
            continue
        spec = pubspec.parse_pubspec(sf.text)
        folder = posixpath.dirname(pubspec_rel)
        prefix = folder + "/" if folder else ""
        if not lock_rel and prefix + "pubspec.lock" in run.files:
            lock_rel = prefix + "pubspec.lock"
        if spec.resolution == "workspace":
            lock_rel = None              # the workspace root's lock belongs to the root
        lock_sf = run.files.get(lock_rel) if lock_rel else None
        _asset_checks(run, sf, spec, prefix)
        warnings: List[str] = []
        found = pubspec.audit_project(sf, lock_sf, warnings,
                                      app=_is_app_folder(run, prefix, spec))
        run.problems.extend(warnings)
        run.extend(found)


def _is_app_folder(run: _Run, prefix: str, spec: Optional["pubspec.Pubspec"] = None
                   ) -> Optional[bool]:
    """True when the pubspec's folder holds an app (lib/main.dart or a platform folder);
    False for a plugin (flutter: plugin: in pubspec.yaml), whose android/ and ios/ folders
    hold the plugin's platform code; None lets the audit decide from pubspec.yaml."""
    if spec is not None and spec.is_plugin:
        return False
    markers = [prefix + "lib/main.dart"] + [prefix + name + "/" for name in
                                            ("android", "ios", "web", "macos", "windows",
                                             "linux")]
    for rel in run.files:
        if rel == markers[0] or rel.startswith(tuple(markers[1:])):
            return True
    return None


def _asset_checks(run: _Run, sf: SourceFile, spec: "pubspec.Pubspec", prefix: str) -> None:
    for asset in spec.assets:
        path = asset.path.strip()
        path = path[2:] if path.startswith("./") else path
        line = asset.line or spec.line_of("flutter", "assets") or 1
        if path.endswith("/"):
            folder = prefix + path
            names = sorted(rel[len(folder):] for rel in run.files
                           if rel.startswith(folder) and "/" not in rel[len(folder):]
                           and _SECRET_ASSET.match(rel[len(folder):]))
            if not names:
                continue
            listed = ", ".join(path + name for name in names[:5])
        elif _SECRET_ASSET.match(posixpath.basename(path)):
            listed = path
        else:
            continue
        run.add("FLUTTER-APP-006", sf, line,
                "%s is bundled as a Flutter asset, so it is packed into the app "
                "(assets/flutter_assets/) where anyone can extract it: keys and passwords in "
                "it are not secret." % _short(listed, 120),
                "Do not bundle files with secrets: keep secret keys on a server and put only "
                "values in the app that may be public.",
                title="Secrets file bundled as a Flutter asset: %s" % _short(listed, 60))


def _app_assets(run: _Run) -> None:
    for sf in run.ctx.files:
        rel = sf.rel
        if sf.origin == "decoded" and ("/assets/" in "/" + rel) \
                and _SECRET_ASSET.match(posixpath.basename(rel)):
            run.add("FLUTTER-APP-006", sf, 1,
                    "The app package contains %s, an asset that anyone can extract from the "
                    "package: keys and passwords in it are not secret." % _short(rel, 120),
                    "Do not bundle files with secrets: keep secret keys on a server and put "
                    "only values in the app that may be public.",
                    title="Secrets file bundled in the app: %s" % posixpath.basename(rel))


def _app_packages(run: _Run) -> None:
    sf = run.files.get(PACKAGES_FILE)
    packages = run.ctx.packages or run.ctx.facts.get("packages") or []
    if sf is None or not packages:
        return
    items = []
    for item in packages:
        if not isinstance(item, Mapping) or not item.get("name"):
            continue
        source = str(item.get("source") or "").lower()
        version = str(item.get("version") or "")
        items.append({"name": str(item["name"]),
                      "version": "" if version.lower() == "unknown" else version,
                      "source": source if source in ("git", "path", "sdk") else "hosted"})
    lines: Dict[str, int] = {}
    for number, text in enumerate(sf.lines, 1):
        parts = text.split()
        if parts:
            lines.setdefault(parts[0], number)
    run.extend(pubspec.audit_packages(items, PACKAGES_FILE, lambda name: lines.get(name, 0), sf))


# ------------------------------------------------------------------ app summaries
def _labels(sf: SourceFile) -> Dict[str, List[Tuple[str, int]]]:
    """"Label: value" lines of a summary: label -> [(value, line)]."""
    out: Dict[str, List[Tuple[str, int]]] = {}
    for number, text in enumerate(sf.lines, 1):
        label, sep, value = text.partition(":")
        if sep:
            out.setdefault(label.strip(), []).append((value.strip(), number))
    return out


def _build_checks(run: _Run) -> None:
    sf = run.files.get(BUILD_FILE)
    if sf is None:
        return
    labels = _labels(sf)

    def first(label: str) -> Tuple[str, int]:
        return labels.get(label, [("", 0)])[0]
    if first("Flutter app")[0].lower().startswith("no"):
        return
    mode, mode_line = first("Build mode")
    mode = (mode.split()[0].lower() if mode else str(run.ctx.facts.get("build_mode") or ""))
    kernel, kernel_line = first("Dart kernel (kernel_blob.bin)")
    count = re.match(r"([0-9]+)", kernel)
    kernel_present = bool(count and int(count.group(1)) > 0)
    if mode == "debug" or kernel_present:
        run.add("FLUTTER-APP-001", sf, kernel_line if kernel_present else mode_line,
                "The app is a debug build: assets/flutter_assets/kernel_blob.bin holds the "
                "app's Dart source code, which anyone can extract from the package, and the "
                "Dart VM runs in JIT mode with its debugging services.",
                "Ship release builds only (flutter build apk --release or flutter build "
                "appbundle).")
    elif mode == "profile":
        run.add("FLUTTER-APP-002", sf, mode_line,
                "The app is a Flutter profile build: it keeps the Dart VM service for "
                "profiling, and the Flutter Gradle plugin makes the profile build type debuggable "
                "and debug-signed like the debug one.",
                "Ship release builds only.")
    obfuscation, obfuscation_line = first("Dart obfuscation")
    if mode == "release" and obfuscation.lower().startswith("no"):
        run.add("FLUTTER-APP-003", sf, obfuscation_line,
                "The Dart code of this release build is not obfuscated: class, function and "
                "library names stay in libapp.so, which makes reverse engineering much easier.",
                "Build with flutter build --obfuscate --split-debug-info=<folder> and keep the "
                "symbol files private.")
    symbols, symbols_line = first("Debug symbols in libapp.so")
    if symbols.lower().startswith("yes"):
        run.add("FLUTTER-APP-004", sf, symbols_line,
                "libapp.so contains debug symbols, which map the compiled code back to Dart "
                "names and help reverse engineering.",
                "Build with --split-debug-info so that symbols go to separate files that are "
                "not shipped.")
    paths = [(value, line) for value, line in labels.get("Build path", [])
             if _USER_FOLDER.search(value)]
    if paths:
        run.add("FLUTTER-APP-005", sf, paths[0][1],
                "The app contains %d absolute path(s) of the machine that built it (such as %s), "
                "which reveal user names and the folder layout." % (len(paths),
                                                                    _short(paths[0][0], 100)),
                "Build release apps in a neutral folder (for example on CI); release builds "
                "keep package: URIs instead of file paths.")


_DEBUG_SUBJECT = {"CN": "Android Debug", "O": "Android", "C": "US"}


def _subject_parts(subject: str) -> Dict[str, str]:
    parts: Dict[str, str] = {}
    for match in re.finditer(r"(?:^|,)\s*([A-Za-z.0-9]+)=((?:\\.|[^,\\])*)", subject):
        parts.setdefault(match.group(1).upper(), match.group(2).strip())
    return parts


def _signing_checks(run: _Run) -> None:
    sf = run.files.get(SIGNING_FILE)
    if sf is None:
        return
    labels = _labels(sf)
    schemes_text, schemes_line = labels.get("Signature schemes", [("", 0)])[0]
    schemes = {s.strip().lower() for s in schemes_text.split(",") if s.strip()} - {"none"}
    schemes.discard("source-stamp")
    if schemes_line and run.ctx.kind != "aab":
        if not schemes:
            run.add("ANDROID-SIGN-003", sf, schemes_line,
                    "The APK has no signature: Android refuses to install it, and whoever "
                    "installs it cannot check where it comes from or whether it was changed.",
                    "Sign the APK with the release key (apksigner, or the release signing "
                    "config in Gradle).")
        elif schemes == {"v1"}:
            run.add("ANDROID-SIGN-002", sf, schemes_line,
                    "The APK is signed only with the v1 (JAR) scheme, which does not protect "
                    "the whole file: on Android 5.0 to 8.0 a v1-only APK can be changed without "
                    "breaking its signature (Janus, CVE-2017-13156).",
                    "Sign with APK Signature Scheme v2 or v3 (apksigner and current Android "
                    "Gradle plugins do so by default).")
    signing = run.ctx.facts.get("signing")
    certificates = signing.get("certificates") if isinstance(signing, Mapping) else None
    certificates = certificates if isinstance(certificates, list) else []
    for label, entries in labels.items():
        match = re.fullmatch(r"Signer ([0-9]+) subject", label)
        if not match:
            continue
        number = int(match.group(1))
        subject, line = entries[0]
        fact = certificates[number - 1] if 0 < number <= len(certificates) \
            and isinstance(certificates[number - 1], Mapping) else {}
        parts = _subject_parts(subject)
        debug = fact.get("debug") if "debug" in fact else \
            all(parts.get(k) == v for k, v in _DEBUG_SUBJECT.items())
        if debug and run.ctx.kind == "aab":
            run.add("ANDROID-SIGN-001", sf, line,
                    "The app bundle is signed with the Android debug certificate (CN=Android "
                    "Debug). A bundle's signature is the upload key of Play App Signing, and "
                    "Google Play rejects bundles signed with a debug certificate, so this "
                    "bundle cannot be published as it is; its key is generated by the Android "
                    "tools with a public password, so anyone can sign a bundle the same way. "
                    "The Flutter app template signs release builds with this key until a "
                    "release key is configured.",
                    "Create an upload key, sign release bundles with it and register it with "
                    "Play App Signing.")
        elif debug:
            run.add("ANDROID-SIGN-001", sf, line,
                    "The app is signed with the Android debug certificate (CN=Android Debug). "
                    "Its key is generated by the Android tools with a public password, so "
                    "anyone can sign a changed app that installs as an update of this one. "
                    "The Flutter app template signs release builds with this key until a "
                    "release key is configured.",
                    "Sign releases with your own private release key (Play App Signing can "
                    "keep the app signing key).")
        _weak_certificate(run, sf, labels, number)


def _weak_certificate(run: _Run, sf: SourceFile, labels: Dict[str, List[Tuple[str, int]]],
                      number: int) -> None:
    """ANDROID-SIGN-004 for a weak signing key (RSA below 2048 bits, DSA, EC below 224 bits).
    The certificate's own signature algorithm (MD5 or SHA-1 with RSA) is not reported:
    Android does not verify the signature of the signing certificate, only the signatures
    the key makes over the APK, which use the scheme's own digests."""
    key, key_line = labels.get("Signer %d key" % number, [("", 0)])[0]
    match = re.match(r"(?i)\s*(RSA|DSA|EC)\s+([0-9]+)", key)
    if not match or not key_line:
        return
    kind, bits = match.group(1).upper(), int(match.group(2))
    if kind == "DSA" or (kind == "RSA" and bits < 2048) or (kind == "EC" and bits < 224):
        if kind == "DSA":
            text = ("Signer %d signs the app with a DSA key (%d bits). DSA is deprecated for app "
                    "signing, and every DSA signature depends on a secret random value: one "
                    "weak value reveals the key." % (number, bits))
        else:
            text = ("Signer %d signs the app with an %s key of %d bits, shorter than current "
                    "guidance (RSA 2048, EC 256): breaking the key would let someone sign "
                    "updates that replace the app." % (number, kind, bits))
        run.add("ANDROID-SIGN-004", sf, key_line, text,
                "Create a signing key with RSA 2048 bits or more (or EC P-256) and rotate to "
                "it with APK Signature Scheme v3 (key rotation).")


# ------------------------------------------------------------------ strings and endpoints
def _endpoint(raw: str) -> Optional[Tuple[str, bool]]:
    """(url, cleartext) for a URL that names a real server, None for namespaces, licences,
    documentation, loopback and placeholder hosts."""
    url = raw.rstrip(".,;:)]!?*")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:.]+", host) or ("." not in host
                                                                and ":" not in host):
        return None
    if host in LOOPBACK_HOSTS or host.startswith("127.") or host in _NOT_ENDPOINTS \
            or _SPEC_HOST.match(host):
        return None
    if re.search(r"(?i)/licen[cs]e", parts.path) or _SDK_LINK.match(url) \
            or _SPEC_PATH.search(parts.path):
        return None
    # The Facebook SDK embeds this policy link in messages; it is not an API call.
    if host == "developers.facebook.com" and re.match(r"^/policy(?:/|$)", parts.path):
        return None
    return url[:300], parts.scheme.lower() in ("http", "ws")


def _libapp_dumps(run: _Run) -> List[SourceFile]:
    rels = list(run.ctx.strings_files) + [sf.rel for sf in run.ctx.files]
    return [run.files[rel] for rel in dict.fromkeys(rels)
            if rel in run.files and run.files[rel].origin == "strings"
            and posixpath.basename(rel) == "libapp.so"]


def _strings_checks(run: _Run) -> None:
    for sf in _libapp_dumps(run):
        for number, text in enumerate(sf.lines, 1):
            if "://" in text:
                for match in _URL.finditer(text):
                    found = _endpoint(match.group())
                    if found and found[1]:
                        run.add("FLUTTER-APP-007", sf, number,
                                "The compiled app contains the cleartext URL %s: traffic to it "
                                "can be read and changed on the network. Dart networking "
                                "(dart:io, package:http, dio) does not follow the Android network "
                                "security config or iOS App Transport Security."
                                % _short(found[0], 120),
                                "Use https:// (or wss://) for every endpoint.",
                                title="Cleartext URL in the compiled app: %s"
                                % _short(found[0], 60), key=found[0])
            if text.rstrip().endswith(("'", '"', "'%", '"%')) and _SQL_OPEN_QUOTE.match(text):
                run.add("FLUTTER-APP-008", sf, number,
                        "The compiled app contains the SQL string fragment \"%s\", ending "
                        "with an opening quote. This can indicate a dynamically assembled "
                        "query. Extracted strings alone do not establish execution, "
                        "untrusted input, or SQL injection." % _short(text.strip(), 120),
                        "Review the query call and input flow. If a value is concatenated "
                        "into executable SQL, use parameterized queries (rawQuery with ? "
                        "placeholders and an arguments list, or the query() helpers of sqflite).",
                        key=text.strip())


def _collect_endpoints(sources: Sequence[SourceFile]) -> List[Dict[str, Any]]:
    """facts["endpoints"]: the distinct server URLs of strings dumps and Dart code (comment
    lines of code left out)."""
    endpoints: Dict[str, Dict[str, Any]] = {}
    for sf in sources:
        code = sf.origin != "strings"
        for number, text in enumerate(sf.lines, 1):
            if "://" not in text or (code and sf.is_comment(number)):
                continue
            for match in _URL.finditer(text):
                found = _endpoint(match.group())
                if found and found[0] not in endpoints:
                    endpoints[found[0]] = {"url": found[0], "cleartext": found[1],
                                           "file": sf.rel}
                    if len(endpoints) >= MAX_ENDPOINTS:
                        return list(endpoints.values())
    return list(endpoints.values())


def _project_endpoints(run: _Run) -> None:
    sources = [sf for rel, sf in sorted(run.files.items())
               if sf.language == "dart" and not sf.origin and not is_test_path(rel)]
    run.ctx.facts["endpoints"] = _collect_endpoints(sources)


def _tampering_check(run: _Run) -> None:
    warnings = [w for w in dict.fromkeys(list(run.ctx.warnings)
                                         + list(run.ctx.facts.get("warnings") or []))
                if isinstance(w, str) and _TAMPERING.search(w)]
    if not warnings:
        return
    sf = run.files.get(BUILD_FILE) or run.files.get("AndroidManifest.xml")
    if sf is None:
        return
    line = next((n for n, text in enumerate(sf.lines, 1) if text.lower().startswith("warning")),
                1)
    quoted = "; ".join(_short(w, 160) for w in warnings[:MAX_QUOTED_WARNINGS])
    more = len(warnings) - MAX_QUOTED_WARNINGS
    run.add("FLUTTER-APP-009", sf, line,
            "The app package has structural anomalies that Android tolerates but analysis "
            "tools may not, a way to hide code from analysis: %s%s." % (
                quoted, " (and %d more)" % more if more > 0 else ""),
            "Rebuild the package with the standard tools; if it comes from someone else, treat "
            "the anomalies as a sign of tampering.")


# ------------------------------------------------------------------ facts
def _fill_facts(run: _Run, modules: Sequence[_Module]) -> None:
    facts = run.ctx.facts
    permissions: Dict[str, Dict[str, Any]] = {}
    components: List[Dict[str, Any]] = []
    for module in modules:
        target = module.target_sdk
        for manifest in module.manifests:
            for requested in manifest.info.requested:
                if requested.name not in permissions and len(permissions) < MAX_FACT_ITEMS:
                    permissions[requested.name] = {
                        "name": _short(requested.name, 200),
                        "dangerous": is_dangerous(requested.name) or is_special(requested.name)}
            for comp in manifest.info.components:
                if len(components) >= MAX_FACT_ITEMS:
                    break
                links = [_short(link, 200) for f in comp.filters if f.is_link
                         for link in f.links()]
                guard = comp.guard if comp.kind != "provider" \
                    else " / ".join(dict.fromkeys(p for p in comp.provider_guards if p))
                components.append({
                    "type": comp.kind, "name": _short(comp.name, 200),
                    "exported": comp.exported(target), "permission": _short(guard, 200),
                    "launcher": comp.launcher, "deep_links": links[:10]})
    facts["permissions"] = list(permissions.values())
    facts["components"] = components
    if modules:
        facts["flags"] = _flags(run, _primary(modules))
    if run.ctx.is_app:
        facts["endpoints"] = _collect_endpoints(
            _libapp_dumps(run) + [sf for sf in run.ctx.files if sf.origin == "recovered"])
    facts["dependency_issues"] = sum(1 for f in run.findings
                                     if f.rule_id.startswith("FLUTTER-PUB-"))


def _primary(modules: Sequence[_Module]) -> _Module:
    """The app module the facts describe: the Flutter app's android/app, else the first one
    that is not a library."""
    return next((m for m in modules if m.name == "android/app"),
                next((m for m in modules if not m.library), modules[0]))


def _flags(run: _Run, module: _Module) -> Dict[str, str]:
    """Short texts for the app facts: debuggable, allow_backup, cleartext,
    network_security_config."""
    debuggable = parse_bool(module.attr("debuggable")) is True \
        or bool(module.gradle and module.gradle.debuggable)
    backup = backup_policy(module.attr)
    if backup.allowed is None:
        allow_backup = "unknown (%s)" % _short(module.attr("allowBackup") or "", 40)
    elif not backup.allowed:
        allow_backup = "no"
    else:
        allow_backup = ("yes" if backup.explicit else "yes (default)") \
            + (", with backup rules" if backup.rules else "")
    reference, config = run.configs.get(module.name, ("", None))
    target = module.target_sdk
    policy = cleartext_policy(module.attr("usesCleartextTraffic"), config, target)
    if policy.permitted:
        cleartext = "allowed (%s)" % (policy.source if policy.source != SOURCE_DEFAULT
                                      else "default for targetSdk %d" % target)
    elif policy.domains:
        cleartext = "allowed for some domains (%s)" % SOURCE_CONFIG
    else:
        cleartext = "not allowed (%s)" % policy.source
    return {"debuggable": "yes" if debuggable else "no", "allow_backup": allow_backup,
            "cleartext": cleartext, "network_security_config": reference or "none"}
