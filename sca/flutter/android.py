"""Android manifest, network security config and FileProvider paths: what Android decides
from them, for the Flutter / Android checks and the app facts.

Everything here reads xmltree.XmlNode trees and does no I/O, so the same code serves a
manifest written in a source project (android/app/src/main/AndroidManifest.xml) and one
decoded from an app package (binary or protobuf XML rendered one attribute per line). The
platform rules it follows:
- a component without android:exported is exported when it has an intent filter; a
  provider only when targetSdk is 16 or lower;
- a component without its own permission takes the permission of <application> (an
  activity-alias does not: it needs its own), and a provider's read and write permissions
  fall back to its permission;
- a <permission> without android:protectionLevel is "normal", which any app is granted;
- app data is backed up unless android:allowBackup="false";
- a network security config replaces android:usesCleartextTraffic on Android 7.0 and later;
  without one, cleartext traffic is allowed by default only for targetSdk 27 and lower;
- FileProvider shares the canonical form of root + path, so ".." in a path climbs out of
  the root folder.
Elements that the manifest merger removes (tools:node="remove") are skipped.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .xmltree import XmlNode

ANDROID_URI = "http://schemas.android.com/apk/res/android"
TOOLS_URI = "http://schemas.android.com/tools"

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
ACTION_MAIN = "android.intent.action.MAIN"
ACTION_VIEW = "android.intent.action.VIEW"
CATEGORY_BROWSABLE = "android.intent.category.BROWSABLE"
SHARE_ACTIONS = ("android.intent.action.SEND", "android.intent.action.SEND_MULTIPLE")
APPWIDGET_ACTION = "android.appwidget.action.APPWIDGET_"
LAUNCHER_CATEGORIES = ("android.intent.category.LAUNCHER",
                       "android.intent.category.LEANBACK_LAUNCHER")
FILE_PROVIDER_CLASSES = ("androidx.core.content.FileProvider",
                         "android.support.v4.content.FileProvider")
FILE_PROVIDER_PATHS = "android.support.FILE_PROVIDER_PATHS"
WEB_SCHEMES = ("http", "https")
# schemes of standard handlers (documents, mail, phone, maps ...): an app that opens them is
# not claiming a link of its own
STANDARD_SCHEMES = frozenset({
    "content", "file", "mailto", "tel", "sms", "smsto", "mms", "mmsto", "geo", "market",
    "ftp", "rtsp", "data", "about", "javascript", "android.resource", "intent", "voicemail"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "10.0.2.2", "10.0.3.2", "::1", "[::1]",
                            "0.0.0.0", "ip6-localhost"})

# Runtime ("dangerous") permissions of the platform, Android 6.0 to 16.
DANGEROUS_PERMISSIONS = frozenset("android.permission." + name for name in (
    "READ_CALENDAR", "WRITE_CALENDAR",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "CAMERA",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS",
    "USE_SIP", "ACCEPT_HANDOVER",
    "BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "ACTIVITY_RECOGNITION",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "READ_MEDIA_VISUAL_USER_SELECTED",
    "ACCESS_MEDIA_LOCATION",
    "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES",
    "UWB_RANGING", "POST_NOTIFICATIONS")) | {"com.android.voicemail.permission.ADD_VOICEMAIL"}
DANGEROUS_PREFIXES = ("android.permission.health.",)      # Health Connect data permissions
# Special app access: the user grants these on a settings screen, not in a dialog.
SPECIAL_PERMISSIONS = frozenset("android.permission." + name for name in (
    "SYSTEM_ALERT_WINDOW", "WRITE_SETTINGS", "REQUEST_INSTALL_PACKAGES",
    "MANAGE_EXTERNAL_STORAGE", "PACKAGE_USAGE_STATS", "QUERY_ALL_PACKAGES",
    "SCHEDULE_EXACT_ALARM", "MANAGE_MEDIA", "USE_FULL_SCREEN_INTENT",
    "ACCESS_NOTIFICATION_POLICY", "MANAGE_ONGOING_CALLS"))
# Install-time ("normal") permissions any app is granted: as a guard they protect nothing.
NORMAL_PERMISSIONS = frozenset("android.permission." + name for name in (
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE",
    "CHANGE_NETWORK_STATE", "CHANGE_WIFI_MULTICAST_STATE", "BLUETOOTH", "BLUETOOTH_ADMIN",
    "NFC", "NFC_TRANSACTION_EVENT", "VIBRATE", "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED",
    "FOREGROUND_SERVICE", "USE_BIOMETRIC", "USE_FINGERPRINT", "SET_ALARM", "SET_WALLPAPER",
    "SET_WALLPAPER_HINTS", "EXPAND_STATUS_BAR", "GET_PACKAGE_SIZE",
    "KILL_BACKGROUND_PROCESSES", "MODIFY_AUDIO_SETTINGS", "REORDER_TASKS",
    "REQUEST_DELETE_PACKAGES", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "TRANSMIT_IR",
    "DISABLE_KEYGUARD", "READ_SYNC_SETTINGS", "WRITE_SYNC_SETTINGS", "READ_SYNC_STATS",
    "ACCESS_LOCATION_EXTRA_COMMANDS", "BROADCAST_STICKY", "CALL_COMPANION_APP",
    "REQUEST_COMPANION_RUN_IN_BACKGROUND", "REQUEST_COMPANION_USE_DATA_IN_BACKGROUND",
    "USE_EXACT_ALARM", "HIGH_SAMPLING_RATE_SENSORS", "MANAGE_OWN_CALLS",
    "READ_BASIC_PHONE_STATE", "RUN_USER_INITIATED_JOBS", "QUERY_ALL_PACKAGES",
    "HIDE_OVERLAY_WINDOWS", "UPDATE_PACKAGES_WITHOUT_USER_ACTION", "DETECT_SCREEN_CAPTURE",
    "ENFORCE_UPDATE_OWNERSHIP", "CREDENTIAL_MANAGER_SET_ORIGIN", "INSTALL_SHORTCUT",
    "UNINSTALL_SHORTCUT", "PERSISTENT_ACTIVITY", "RESTART_PACKAGES", "GET_TASKS"))
NORMAL_PREFIXES = ("android.permission.FOREGROUND_SERVICE_",)   # the typed foreground services
# Platform permissions at signature or privileged level (and the system's own guards): an
# app outside the platform cannot hold them, so they keep callers out. A platform permission
# not listed here (or matched by the BIND_ pattern) is taken as one that apps can obtain.
SIGNATURE_PERMISSIONS = frozenset("android.permission." + name for name in (
    "BROADCAST_SMS", "BROADCAST_WAP_PUSH", "BROADCAST_PACKAGE_REMOVED", "SEND_RESPOND_VIA_MESSAGE",
    "SEND_SMS_NO_CONFIRMATION", "MANAGE_DOCUMENTS", "ACCOUNT_MANAGER", "GLOBAL_SEARCH",
    "DUMP", "READ_LOGS", "INSTALL_PACKAGES", "DELETE_PACKAGES", "CLEAR_APP_CACHE",
    "CLEAR_APP_USER_DATA", "WRITE_SECURE_SETTINGS", "CHANGE_COMPONENT_ENABLED_STATE",
    "STATUS_BAR", "STATUS_BAR_SERVICE", "REBOOT", "DEVICE_POWER", "MASTER_CLEAR",
    "MODIFY_PHONE_STATE", "CALL_PRIVILEGED", "READ_PRIVILEGED_PHONE_STATE",
    "CAPTURE_AUDIO_OUTPUT", "CAPTURE_VIDEO_OUTPUT", "CAPTURE_SECURE_VIDEO_OUTPUT",
    "WRITE_MEDIA_STORAGE", "INTERACT_ACROSS_USERS", "INTERACT_ACROSS_USERS_FULL",
    "MANAGE_USERS", "CREATE_USERS", "GRANT_RUNTIME_PERMISSIONS", "REVOKE_RUNTIME_PERMISSIONS",
    "UPDATE_DEVICE_STATS", "UPDATE_APP_OPS_STATS", "SET_TIME", "SET_TIME_ZONE",
    "CONTROL_INCALL_EXPERIENCE", "START_VIEW_PERMISSION_USAGE", "START_VIEW_APP_FEATURES",
    "LAUNCH_MULTI_PANE_SETTINGS_DEEP_LINK", "PROVIDE_REMOTE_CREDENTIALS",
    "ACCESS_CONTENT_PROVIDERS_EXTERNALLY", "REQUEST_NOTIFICATION_ASSISTANT_SERVICE",
    "MANAGE_SLICE_PERMISSIONS", "TRIGGER_TIME_ZONE_RULES_CHECK", "PACKAGE_VERIFICATION_AGENT",
    "INTENT_FILTER_VERIFICATION_AGENT", "CONNECTIVITY_INTERNAL", "NETWORK_SETTINGS",
    "NETWORK_STACK", "MANAGE_NETWORK_POLICY", "SHUTDOWN", "STOP_APP_SWITCHES",
    "SET_ACTIVITY_WATCHER", "BACKUP", "CONFIRM_FULL_BACKUP", "ACCESS_CACHE_FILESYSTEM",
    "MOUNT_UNMOUNT_FILESYSTEMS", "MOUNT_FORMAT_FILESYSTEMS", "WRITE_APN_SETTINGS",
    "SET_PREFERRED_APPLICATIONS", "READ_FRAME_BUFFER", "INJECT_EVENTS", "MANAGE_APP_TOKENS",
    "INTERNAL_SYSTEM_WINDOW", "WRITE_GSERVICES", "ACCESS_CHECKIN_PROPERTIES",
    "BATTERY_STATS", "DIAGNOSTIC", "FACTORY_TEST", "HARDWARE_TEST", "LOCATION_HARDWARE",
    "MEDIA_CONTENT_CONTROL", "MODIFY_AUDIO_ROUTING", "READ_INPUT_STATE",
    "RECEIVE_EMERGENCY_BROADCAST", "SEND_DOWNLOAD_COMPLETED_INTENTS",
    "SET_ALWAYS_FINISH", "SET_ANIMATION_SCALE", "SET_DEBUG_APP", "SET_PROCESS_LIMIT",
    "SIGNAL_PERSISTENT_PROCESSES", "BRICK", "ACCESS_SURFACE_FLINGER", "ASEC_ACCESS",
    "RETRIEVE_WINDOW_CONTENT", "OBSERVE_GRANT_REVOKE_PERMISSIONS",
    "QUERY_USERS", "MANAGE_DEVICE_ADMINS", "PERFORM_CDMA_PROVISIONING",
    "PROVIDE_TRUST_AGENT", "LAUNCH_TRUST_AGENT_SETTINGS", "TETHER_PRIVILEGED",
    "UPDATE_LOCK", "READ_WIFI_CREDENTIAL", "MANAGE_FINGERPRINT", "MANAGE_BIOMETRIC",
    "ACCESS_NOTIFICATIONS", "MANAGE_NOTIFICATIONS"))
# Guard permissions that other apps cannot obtain although this app does not define them:
# Google Play services holds them at signature level.
KNOWN_SIGNATURE_PERMISSIONS = frozenset({
    "com.google.android.c2dm.permission.SEND",
    "com.google.android.gms.auth.api.phone.permission.SEND",
    "com.google.android.gms.permission.BIND_NETWORK_TASK_SERVICE",
})
_BIND_PERMISSION = re.compile(r"(^|\.)permission\.BIND_[A-Z0-9_]+$")
# build placeholders the manifest merger replaces with the application id
_PACKAGE_PLACEHOLDER = re.compile(r"\$\{(?:applicationId|packageName)\}")
_BASE_LEVELS = {"normal": 0, "dangerous": 1, "signature": 2, "signatureorsystem": 3,
                "internal": 4}

# strength of the permission that guards a component
GUARD_NONE = "none"              # no permission at all
GUARD_STRONG = "strong"          # signature level, or a system permission
GUARD_WEAK = "weak"              # normal or dangerous: any app can hold it
GUARD_UNDEFINED = "undefined"    # nobody defines it: another app can define it first


def is_dangerous(permission: str) -> bool:
    return permission in DANGEROUS_PERMISSIONS or permission.startswith(DANGEROUS_PREFIXES)


def is_special(permission: str) -> bool:
    return permission in SPECIAL_PERMISSIONS


def is_normal(permission: str) -> bool:
    """An install-time permission that the platform grants to any app that asks."""
    return permission in NORMAL_PERMISSIONS or permission.startswith(NORMAL_PREFIXES)


def parse_bool(value: Optional[str]) -> Optional[bool]:
    """"true"/"false" in any case; None for anything else (absent, a placeholder)."""
    text = (value or "").strip().lower()
    return True if text == "true" else False if text == "false" else None


def parse_int(value: Optional[str]) -> Optional[int]:
    text = (value or "").strip()
    if re.fullmatch(r"-?[0-9]{1,9}", text):
        return int(text)
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", text):
        return int(text, 16)
    return None


def protection_base(level: str) -> int:
    """The base protection level of an android:protectionLevel value ("signature|privileged",
    "0x12", "") as 0 normal, 1 dangerous, 2 signature, 3 signatureOrSystem, 4 internal.
    A missing level, or one with flags only, is normal, as Android reads it."""
    text = (level or "").strip()
    number = parse_int(text)
    if number is not None:
        return number & 0xF
    for part in text.split("|"):
        base = _BASE_LEVELS.get(part.strip().lower())
        if base is not None:
            return base
    return 0


def _prefixes(root: XmlNode) -> Tuple[str, str]:
    """The prefixes the document uses for the android and tools namespaces."""
    android, tools = "android", "tools"
    for key, value in root.attrs.items():
        if key.startswith("xmlns:"):
            if value == ANDROID_URI:
                android = key[6:]
            elif value == TOOLS_URI:
                tools = key[6:]
    return android + ":", tools + ":"


def _removed(node: XmlNode, tools: str) -> bool:
    return (node.get(tools + "node") or "").strip() in ("remove", "removeAll")


def full_class_name(name: str, package: str) -> str:
    """A component name as Android resolves it: ".Main" and "Main" are relative to the
    package; placeholders and full names are kept."""
    name = (name or "").strip()
    if not name or "$" in name[:2] or not package:
        return name
    if name.startswith("."):
        return package + name
    return name if "." in name else package + "." + name


# ------------------------------------------------------------------ manifest
@dataclass
class DataSpec:
    """One <data> element of an intent filter."""

    node: XmlNode
    scheme: str = ""
    host: str = ""
    port: str = ""
    paths: List[str] = field(default_factory=list)     # path, pathPrefix, pathPattern ...


@dataclass
class IntentFilter:
    """An <intent-filter>; its <data> elements combine (every scheme with every host)."""

    node: XmlNode
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data: List[DataSpec] = field(default_factory=list)
    auto_verify: bool = False

    @property
    def is_launcher(self) -> bool:
        return ACTION_MAIN in self.actions and any(c in self.categories
                                                   for c in LAUNCHER_CATEGORIES)

    @property
    def is_link(self) -> bool:
        """A VIEW filter with a scheme: a link from another app or a web page opens it."""
        return ACTION_VIEW in self.actions and any(spec.scheme for spec in self.data)

    @property
    def is_share(self) -> bool:
        """A share target: the filter only receives SEND / SEND_MULTIPLE from the share
        sheet."""
        return bool(self.actions) and all(action in SHARE_ACTIONS for action in self.actions)

    @property
    def is_app_widget(self) -> bool:
        """A home screen widget provider: the filter only handles the APPWIDGET_* broadcasts
        of the widget host."""
        return bool(self.actions) and all(action.startswith(APPWIDGET_ACTION)
                                          for action in self.actions)

    @property
    def browsable(self) -> bool:
        return CATEGORY_BROWSABLE in self.categories

    @property
    def schemes(self) -> List[str]:
        return list(dict.fromkeys(spec.scheme for spec in self.data if spec.scheme))

    @property
    def hosts(self) -> List[str]:
        return list(dict.fromkeys(spec.host + (":" + spec.port if spec.port else "")
                                  for spec in self.data if spec.host))

    def links(self, limit: int = 10) -> List[str]:
        """The links the filter accepts, as scheme://host/path ("*" marks a prefix)."""
        paths = [path for spec in self.data for path in spec.paths] or [""]
        out: List[str] = []
        for scheme in self.schemes:
            for host in self.hosts or [""]:
                for path in paths:
                    out.append("%s://%s%s" % (scheme, host, path) if host else scheme + ":")
        return list(dict.fromkeys(out))[:limit]

    def data_node_with_scheme(self, scheme: str) -> Optional[XmlNode]:
        return next((spec.node for spec in self.data if spec.scheme == scheme), None)


@dataclass
class Component:
    """An activity, activity-alias, service, receiver or provider of <application>."""

    kind: str
    name: str                                 # class name resolved against the package
    node: XmlNode
    exported_attr: Optional[bool] = None      # android:exported as written
    permission: str = ""                      # android:permission of the component
    read_permission: str = ""                 # providers
    write_permission: str = ""
    app_permission: str = ""                  # android:permission of <application>
    filters: List[IntentFilter] = field(default_factory=list)
    meta_data: Dict[str, str] = field(default_factory=dict)   # name -> value or resource
    task_affinity: Optional[str] = None
    allow_task_reparenting: Optional[bool] = None
    path_permissions: int = 0                 # <path-permission> children of a provider
    attr_prefix: str = "android:"

    @property
    def launcher(self) -> bool:
        return any(f.is_launcher for f in self.filters)

    def exported(self, target_sdk: Optional[int] = None) -> bool:
        """Whether other apps can use the component: the attribute when it is written,
        else Android's default (intent filters for activities, services and receivers;
        targetSdk 16 or lower for providers)."""
        if self.exported_attr is not None:
            return self.exported_attr
        if self.kind == "provider":
            return target_sdk is not None and target_sdk <= 16
        return bool(self.filters)

    @property
    def guard(self) -> str:
        """The permission a caller needs: the component's, else the application's. An
        activity-alias takes neither the application's nor its target's permission: Android
        lets an alias reach its activity without the original permission unless the alias
        declares one itself (ParsedActivityUtils.parseActivityOrAlias)."""
        if self.kind == "activity-alias":
            return self.permission
        return self.permission or self.app_permission

    @property
    def provider_guards(self) -> Tuple[str, str]:
        """(read, write) permissions of a provider, with the fallbacks Android applies."""
        return self.read_permission or self.guard, self.write_permission or self.guard

    @property
    def is_file_provider(self) -> bool:
        return self.kind == "provider" and (self.name in FILE_PROVIDER_CLASSES
                                            or FILE_PROVIDER_PATHS in self.meta_data)

    @property
    def file_provider_paths(self) -> str:
        """The resource of the shared paths ("@xml/file_paths"), "" when none."""
        return self.meta_data.get(FILE_PROVIDER_PATHS, "")

    def attr(self, name: str) -> Optional[str]:
        return self.node.get(self.attr_prefix + name)

    def line_of(self, name: str) -> int:
        return self.node.line_of(self.attr_prefix + name)


@dataclass
class PermissionDef:
    """A <permission> the app defines."""

    name: str
    protection_level: str
    node: XmlNode

    @property
    def strong(self) -> bool:
        return protection_base(self.protection_level) >= 2


@dataclass
class UsesPermission:
    """A <uses-permission> or <uses-permission-sdk-23>."""

    name: str
    node: XmlNode


@dataclass
class ManifestInfo:
    """What a manifest declares, with Android's defaults applied where they matter."""

    root: XmlNode
    package: str = ""
    version_code: str = ""
    version_name: str = ""
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    uses_sdk: Optional[XmlNode] = None
    application: Optional[XmlNode] = None
    requested: List[UsesPermission] = field(default_factory=list)
    defined: Dict[str, PermissionDef] = field(default_factory=dict)
    components: List[Component] = field(default_factory=list)
    # <meta-data> of <application>: name -> (value or resource, element)
    app_meta_data: Dict[str, Tuple[str, XmlNode]] = field(default_factory=dict)
    attr_prefix: str = "android:"

    @classmethod
    def from_node(cls, node: XmlNode, *, package_hint: str = "") -> "ManifestInfo":
        """Read a <manifest> tree. `package_hint` names the app when the manifest has no
        package attribute (source projects set it in Gradle as namespace/applicationId)."""
        ns, tools = _prefixes(node)
        info = cls(root=node, attr_prefix=ns)
        info.package = (node.get("package") or "").strip() or package_hint
        info.version_code = node.get(ns + "versionCode") or ""
        info.version_name = node.get(ns + "versionName") or ""
        info.compile_sdk = parse_int(node.get(ns + "compileSdkVersion"))
        for child in node.children:
            if _removed(child, tools):
                continue
            if child.tag == "uses-sdk" and info.uses_sdk is None:
                info.uses_sdk = child
                info.min_sdk = parse_int(child.get(ns + "minSdkVersion"))
                info.target_sdk = parse_int(child.get(ns + "targetSdkVersion"))
            elif child.tag in ("uses-permission", "uses-permission-sdk-23"):
                name = (child.get(ns + "name") or "").strip()
                if name:
                    info.requested.append(UsesPermission(name, child))
            elif child.tag == "permission":
                name = (child.get(ns + "name") or "").strip()
                if name:
                    info.defined.setdefault(name, PermissionDef(
                        name, child.get(ns + "protectionLevel") or "", child))
            elif child.tag == "application" and info.application is None:
                info.application = child
        if info.target_sdk is None and info.min_sdk is not None:
            info.target_sdk = info.min_sdk           # Android's default for targetSdkVersion
        if info.package:                             # ${applicationId}.permission.X
            info.defined = {info.resolve(name): definition
                            for name, definition in info.defined.items()}
        if info.application is not None:
            app_permission = (info.application.get(ns + "permission") or "").strip()
            for child in info.application.children:
                if _removed(child, tools):
                    continue
                if child.tag in COMPONENT_TAGS:
                    info.components.append(_component(child, ns, tools, info.package,
                                                      app_permission))
                elif child.tag == "meta-data":
                    name = (child.get(ns + "name") or "").strip()
                    if name:
                        info.app_meta_data.setdefault(name, (
                            (child.get(ns + "value") or child.get(ns + "resource") or "").strip(),
                            child))
        return info

    def resolve(self, name: str) -> str:
        """A name with the ${applicationId} / ${packageName} placeholders replaced by the
        package, as the manifest merger does."""
        name = (name or "").strip()
        if self.package and "${" in name:
            name = _PACKAGE_PLACEHOLDER.sub(lambda _match: self.package, name)
        return name

    # --- <application> attributes
    def app_attr(self, name: str) -> Optional[str]:
        """An <application> attribute by its name without prefix ("allowBackup")."""
        return self.application.get(self.attr_prefix + name) if self.application else None

    def app_line(self, name: str = "") -> int:
        """Line of an <application> attribute; the start tag when it is absent."""
        if self.application is None:
            return 0
        return self.application.line_of(self.attr_prefix + name) if name \
            else self.application.line

    def guard_strength(self, permission: str) -> str:
        """How well a guard permission keeps other apps out (GUARD_* constants)."""
        name = self.resolve(permission)
        if not name:
            return GUARD_NONE
        if name in self.defined:
            return GUARD_STRONG if self.defined[name].strong else GUARD_WEAK
        if name in KNOWN_SIGNATURE_PERMISSIONS or name in SIGNATURE_PERMISSIONS \
                or _BIND_PERMISSION.search(name):
            return GUARD_STRONG
        if name.startswith("android.permission."):
            # normal, dangerous, special access, or a platform permission not known to be
            # signature level: other apps can hold it
            return GUARD_WEAK
        return GUARD_UNDEFINED             # also a value that is no permission name ("true")


def _component(node: XmlNode, ns: str, tools: str, package: str,
               app_permission: str) -> Component:
    comp = Component(kind=node.tag, name=full_class_name(node.get(ns + "name") or "", package),
                     node=node, attr_prefix=ns, app_permission=app_permission)
    comp.exported_attr = parse_bool(node.get(ns + "exported"))
    comp.permission = (node.get(ns + "permission") or "").strip()
    comp.read_permission = (node.get(ns + "readPermission") or "").strip()
    comp.write_permission = (node.get(ns + "writePermission") or "").strip()
    affinity = node.get(ns + "taskAffinity")
    comp.task_affinity = affinity.strip() if affinity is not None else None
    comp.allow_task_reparenting = parse_bool(node.get(ns + "allowTaskReparenting"))
    for child in node.children:
        if _removed(child, tools):
            continue
        if child.tag == "intent-filter":
            comp.filters.append(_intent_filter(child, ns))
        elif child.tag == "meta-data":
            name = (child.get(ns + "name") or "").strip()
            if name:
                comp.meta_data.setdefault(
                    name, (child.get(ns + "resource") or child.get(ns + "value") or "").strip())
        elif child.tag == "path-permission":
            comp.path_permissions += 1
    return comp


def _intent_filter(node: XmlNode, ns: str) -> IntentFilter:
    result = IntentFilter(node, auto_verify=parse_bool(node.get(ns + "autoVerify")) is True)
    for child in node.children:
        name = (child.get(ns + "name") or "").strip()
        if child.tag == "action" and name:
            result.actions.append(name)
        elif child.tag == "category" and name:
            result.categories.append(name)
        elif child.tag == "data":
            paths = []
            for key, mark in (("path", ""), ("pathPrefix", "*"), ("pathPattern", ""),
                              ("pathAdvancedPattern", ""), ("pathSuffix", "")):
                value = (child.get(ns + key) or "").strip()
                if value:
                    paths.append(("*" if key == "pathSuffix" else "") + value + mark)
            result.data.append(DataSpec(
                child, scheme=(child.get(ns + "scheme") or "").strip(),
                host=(child.get(ns + "host") or "").strip(),
                port=(child.get(ns + "port") or "").strip(), paths=paths))
    return result


def is_own_affinity(affinity: str, package: str) -> bool:
    """True when a taskAffinity keeps the activity in the app's own tasks: empty, the
    package, a name inside the package, or a build placeholder."""
    value = affinity.strip()
    if not value or value.startswith("${"):
        return True
    return bool(package) and (value == package or value.startswith(package + "."))


# ------------------------------------------------------------------ backup and cleartext
# reads an <application> attribute by its name without prefix; None when it is not written
AttrReader = Callable[[str], Optional[str]]


@dataclass
class BackupPolicy:
    allowed: Optional[bool]     # Android backs up app data; None for a build placeholder
    explicit: bool              # android:allowBackup is written
    rules: bool                 # backup rules or a backup agent decide what is copied
    full_backup_rules: bool = False   # android:fullBackupContent (Android 11 and lower)
    extraction_rules: bool = False    # android:dataExtractionRules (Android 12 and later)
    agent: bool = False               # android:backupAgent

    def d2d_open(self, target_sdk: Optional[int]) -> bool:
        """True when only fullBackupContent restricts the backup of an app that targets
        Android 12 (API 31) or later: Android 12 and later ignore it for device-to-device
        transfer, which then copies the app's files without rules."""
        return bool(self.allowed and target_sdk is not None and target_sdk >= 31
                    and self.full_backup_rules and not self.extraction_rules and not self.agent)


def backup_policy(attr: AttrReader) -> BackupPolicy:
    """The backup policy (Auto Backup and device-to-device transfer) of <application>.
    fullBackupContent / dataExtractionRules restrict it with a rules file, or with "false"
    (no full backup at all); a backupAgent copies only what it writes."""
    text = attr("allowBackup")
    value = parse_bool(text)

    def restricts(name: str) -> bool:
        setting = (attr(name) or "").strip()
        return setting.startswith("@") or setting.lower() == "false"
    full, extraction = restricts("fullBackupContent"), restricts("dataExtractionRules")
    agent = bool((attr("backupAgent") or "").strip())
    allowed = None if text is not None and value is None else value is not False
    return BackupPolicy(allowed=allowed, explicit=text is not None,
                        rules=full or extraction or agent, full_backup_rules=full,
                        extraction_rules=extraction, agent=agent)


SOURCE_CONFIG = "network security config"
SOURCE_MANIFEST = "android:usesCleartextTraffic"
SOURCE_DEFAULT = "default"


@dataclass
class CleartextPolicy:
    permitted: Optional[bool]   # for every domain; None when targetSdk and settings are unknown
    source: str                 # what decides: SOURCE_CONFIG, SOURCE_MANIFEST or SOURCE_DEFAULT
    domains: List[str] = field(default_factory=list)   # opened by a domain-config (no loopback)


def cleartext_policy(uses_cleartext: Optional[str], config: Optional["NetworkSecurityConfig"],
                     target_sdk: Optional[int]) -> CleartextPolicy:
    """Whether the platform network stack allows cleartext HTTP. A network security config
    replaces android:usesCleartextTraffic (Android 7.0 and later); what neither sets follows
    targetSdk: allowed up to 27, blocked from 28."""
    default = None if target_sdk is None else target_sdk < 28
    if config is not None:
        domains = [name for domain in config.domains
                   if domain.cleartext and not domain.loopback_only for name in domain.names]
        if config.base_cleartext is not None:
            return CleartextPolicy(config.base_cleartext, SOURCE_CONFIG, domains)
        return CleartextPolicy(default, SOURCE_DEFAULT, domains)
    value = parse_bool(uses_cleartext)
    if value is not None:
        return CleartextPolicy(value, SOURCE_MANIFEST)
    return CleartextPolicy(default, SOURCE_DEFAULT)


# ------------------------------------------------------------------ network security config
@dataclass
class TrustAnchor:
    """A <certificates> element: which CAs are trusted."""

    src: str
    node: XmlNode
    override_pins: Optional[bool] = None


@dataclass
class PinSet:
    node: XmlNode
    expiration: str = ""
    pins: int = 0

    def expired(self, today: Optional[date] = None) -> bool:
        """True when the expiration date (yyyy-MM-dd) is reached: Android stops enforcing
        the pins on that day ("the date at and after which the pins expire")."""
        match = re.fullmatch(r"\s*([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})\s*", self.expiration)
        if not match:
            return False
        try:
            when = date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            return False
        return when <= (today or date.today())


@dataclass
class DomainConfig:
    node: XmlNode
    domains: List[Tuple[str, bool]] = field(default_factory=list)  # (name, includeSubdomains)
    cleartext: Optional[bool] = None          # after inheriting from enclosing domain-configs
    trust_anchors: List[TrustAnchor] = field(default_factory=list)
    pin_set: Optional[PinSet] = None
    # the domain-config whose cleartextTrafficPermitted this one uses: itself, an enclosing
    # one, or None when no domain-config sets it
    cleartext_source: Optional["DomainConfig"] = None

    @property
    def names(self) -> List[str]:
        return [name for name, _ in self.domains]

    @property
    def loopback_only(self) -> bool:
        return bool(self.domains) and all(name.strip().lower() in LOOPBACK_HOSTS
                                          for name in self.names)


@dataclass
class NetworkSecurityConfig:
    """A <network-security-config> resource."""

    root: XmlNode
    base: Optional[XmlNode] = None
    base_cleartext: Optional[bool] = None
    base_trust_anchors: List[TrustAnchor] = field(default_factory=list)
    domains: List[DomainConfig] = field(default_factory=list)    # nested ones included
    debug_trust_anchors: List[TrustAnchor] = field(default_factory=list)

    @classmethod
    def from_node(cls, node: XmlNode) -> "NetworkSecurityConfig":
        config = cls(root=node)
        for child in node.children:
            if child.tag == "base-config" and config.base is None:
                config.base = child
                config.base_cleartext = parse_bool(child.get("cleartextTrafficPermitted"))
                config.base_trust_anchors = _trust_anchors(child)
            elif child.tag == "domain-config":
                config.domains.extend(_domain_configs(child))
            elif child.tag == "debug-overrides":
                config.debug_trust_anchors.extend(_trust_anchors(child))
        return config

    def anchors(self) -> Iterable[Tuple[TrustAnchor, Optional[DomainConfig]]]:
        """Every trust anchor that applies to release builds, with its domain-config."""
        for anchor in self.base_trust_anchors:
            yield anchor, None
        for domain in self.domains:
            for anchor in domain.trust_anchors:
                yield anchor, domain


def _trust_anchors(node: XmlNode) -> List[TrustAnchor]:
    anchors = []
    for holder in node.findall("trust-anchors"):
        for cert in holder.findall("certificates"):
            anchors.append(TrustAnchor((cert.get("src") or "").strip(), cert,
                                       parse_bool(cert.get("overridePins"))))
    return anchors


def _domain_configs(node: XmlNode, depth: int = 0) -> List[DomainConfig]:
    """A domain-config and the domain-configs nested in it (they inherit unset values)."""
    config = DomainConfig(node, cleartext=parse_bool(node.get("cleartextTrafficPermitted")),
                          trust_anchors=_trust_anchors(node))
    if config.cleartext is not None:
        config.cleartext_source = config
    nested: List[DomainConfig] = []
    for child in node.children:
        if child.tag == "domain":
            config.domains.append((child.text.strip(),
                                   parse_bool(child.get("includeSubdomains")) is True))
        elif child.tag == "pin-set" and config.pin_set is None:
            config.pin_set = PinSet(child, (child.get("expiration") or "").strip(),
                                    len(child.findall("pin")))
        elif child.tag == "domain-config" and depth < 20:
            nested.extend(_domain_configs(child, depth + 1))
    for inner in nested:
        if inner.cleartext is None:
            inner.cleartext = config.cleartext
            inner.cleartext_source = config.cleartext_source
    return [config] + nested


# ------------------------------------------------------------------ FileProvider paths
PATH_KINDS = ("root-path", "files-path", "cache-path", "external-path", "external-files-path",
              "external-cache-path", "external-media-path")
# path elements whose whole folder is a storage root other apps must not get: the device
# filesystem, the app's internal files and the shared external storage
ROOT_KINDS = ("files-path", "external-path")
# path elements inside the app's private storage (a ".." there reaches databases, shared
# preferences and the other private files)
PRIVATE_KINDS = ("files-path", "cache-path")
# folders of the device file system that are whole storage roots for <root-path>: the root
# itself, the data partition and the shared external storage (and its aliases)
WHOLE_ROOTS = frozenset({
    "", "data", "data/data", "data/user", "data/user/0", "data/user_de", "data/user_de/0",
    "data/media", "data/media/0", "storage", "storage/emulated", "storage/emulated/0",
    "storage/emulated/legacy", "storage/self", "storage/self/primary", "sdcard", "mnt",
    "mnt/sdcard", "mnt/user", "mnt/user/0", "mnt/user/0/primary"})
# an app's private data folder (data/data/<package>, data/user/<n>/<package>)
_APP_DATA_FOLDER = re.compile(r"^data/(?:data|user(?:_de)?/[0-9]+)/[^/]+$")
_SYMBOLIC_ROOT = "/@root"

# how wide a path element is (SharedPath.exposure)
EXPOSE_FILESYSTEM = "filesystem"      # <root-path> on a whole storage root
EXPOSE_APP_DATA = "app-data"          # <root-path> on the app's private data folder
EXPOSE_PARENT = "parent"              # climbs out of its root folder with ".."
EXPOSE_FOLDER = "folder"              # the whole internal files folder or external storage
EXPOSE_NARROW_ROOT = "narrow-root"    # <root-path> on a narrower folder


@dataclass
class SharedPath:
    """One path element of a FileProvider's paths resource."""

    kind: str
    name: str
    path: str
    node: XmlNode

    @property
    def resolved(self) -> Optional[str]:
        """The shared folder relative to the element's root folder after "." and ".." are
        resolved, as androidx FileProvider shares the canonical form of root + path ("" for
        the root folder itself); None when the path climbs out of the root folder. A
        leading "/" does not make the path absolute: Java's File(root, "/x") is root/x."""
        joined = posixpath.normpath(posixpath.join(_SYMBOLIC_ROOT, self.path.strip().lstrip("/")))
        if joined == _SYMBOLIC_ROOT:
            return ""
        if joined.startswith(_SYMBOLIC_ROOT + "/"):
            return joined[len(_SYMBOLIC_ROOT) + 1:]
        return None

    @property
    def whole_folder(self) -> bool:
        return self.resolved == ""

    @property
    def escapes(self) -> bool:
        return self.resolved is None and self.kind != "root-path"

    @property
    def exposure(self) -> str:
        """One of the EXPOSE_* values, or "" for a path element that shares a sub-folder."""
        if self.kind == "root-path":
            folder = posixpath.normpath("/" + self.path.strip()).strip("/")
            if folder in WHOLE_ROOTS:
                return EXPOSE_FILESYSTEM
            if _APP_DATA_FOLDER.match(folder):
                return EXPOSE_APP_DATA
            return EXPOSE_NARROW_ROOT
        if self.escapes:
            return EXPOSE_PARENT
        if self.kind in ROOT_KINDS and self.whole_folder:
            return EXPOSE_FOLDER
        return ""


@dataclass
class FileProviderPaths:
    root: XmlNode
    paths: List[SharedPath] = field(default_factory=list)

    @classmethod
    def from_node(cls, node: XmlNode) -> "FileProviderPaths":
        result = cls(root=node)
        for child in node.children:
            if child.tag in PATH_KINDS:
                result.paths.append(SharedPath(child.tag, (child.get("name") or "").strip(),
                                               child.get("path") or "", child))
        return result

    def too_wide(self) -> List[SharedPath]:
        """Elements that share the filesystem root or a folder of it, climb out of their
        root folder with "..", or share the whole internal files folder or external
        storage (SharedPath.exposure tells which)."""
        return [p for p in self.paths if p.exposure]
