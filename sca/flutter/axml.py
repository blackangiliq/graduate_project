"""Decoder for Android binary XML (AXML): AndroidManifest.xml and res/xml/*.xml of an APK.

Layout (AOSP frameworks/base libs/androidfw/include/androidfw/ResourceTypes.h): a chunk of
type RES_XML_TYPE holds a string pool, a resource map (the resource id of the attribute
name at each string index) and one chunk per XML event: namespace start and end, element
start and end, text. Every chunk starts with u16 type, u16 headerSize, u32 size.

Android finds the attributes it reads by resource id, not by name (AttributeResolution.cpp,
RetrieveAttributes), so attribute names come from a table of android.R.attr ids whenever the
resource map gives an id, and a name string that disagrees with its id is reported. The file
is untrusted and malware bends it on purpose: the decoder honours headerSize, attributeStart
and attributeSize as Android does, bounds-checks every read, caps counts, string lengths, the
string bytes decoded, depth and the number of chunks, skips unknown chunks and records every
anomaly in AxmlDocument.warnings. Only data that cannot be binary XML raises AxmlError.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .xmltree import XmlNode, render_xml

# chunk types
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_LAST_CHUNK = 0x017F
RES_XML_RESOURCE_MAP = 0x0180

# Res_value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F
_KNOWN_TYPES = {TYPE_NULL, TYPE_REFERENCE, TYPE_ATTRIBUTE, TYPE_STRING, TYPE_FLOAT,
                TYPE_DIMENSION, TYPE_FRACTION, TYPE_DYNAMIC_REFERENCE, TYPE_DYNAMIC_ATTRIBUTE,
                TYPE_INT_DEC, TYPE_INT_HEX, TYPE_INT_BOOLEAN, TYPE_INT_COLOR_ARGB8,
                TYPE_INT_COLOR_RGB8, TYPE_INT_COLOR_ARGB4, TYPE_INT_COLOR_RGB4}

UTF8_FLAG = 0x100
NO_INDEX = 0xFFFFFFFF
# size of the extension that follows the header of each XML node type
_EXTENSION_SIZES = {RES_XML_START_NAMESPACE: 8, RES_XML_END_NAMESPACE: 8,
                    RES_XML_START_ELEMENT: 20, RES_XML_END_ELEMENT: 8, RES_XML_CDATA: 12}

ANDROID_URI = "http://schemas.android.com/apk/res/android"
TOOLS_URI = "http://schemas.android.com/tools"
APP_URI = "http://schemas.android.com/apk/res-auto"
KNOWN_PREFIXES = {ANDROID_URI: "android", TOOLS_URI: "tools", APP_URI: "app"}

# caps against hostile files
MAX_WARNINGS = 100
MAX_NODES = 100_000              # chunks of one document: element, namespace and text nodes
                                 # and any other chunk
MAX_DEPTH = 200
MAX_ATTRIBUTES = 4_096           # per element
MAX_TOTAL_ATTRIBUTES = 500_000
MAX_STRINGS = 1_000_000          # string pool entries
MAX_STRING_CHARS = 32_768        # longer strings are cut
MAX_NAME_CHARS = 256             # element and attribute names, namespace URIs (SoumniBot used
                                 # huge namespace names)
MAX_NAMESPACES = 1_000
MAX_TOTAL_CHARS = 16_000_000     # names, values and text of one document (string indexes can
                                 # share one long string, so the output can outgrow the input)
POOL_BUDGET = 1 << 20            # string bytes decoded beyond twice the size of the pool

# android.R.attr ids from AOSP core/res/res/values/public-final.xml: every attribute that
# the platform's manifest parser reads (ParsingPackageUtils and the component parsers) and
# every attribute the checks use. Other android attributes keep the name of the file.
ANDROID_ATTRS: Dict[int, str] = {
    0x01010000: "theme", 0x01010001: "label", 0x01010002: "icon", 0x01010003: "name",
    0x01010004: "manageSpaceActivity", 0x01010005: "allowClearUserData",
    0x01010006: "permission", 0x01010007: "readPermission", 0x01010008: "writePermission",
    0x01010009: "protectionLevel", 0x0101000a: "permissionGroup", 0x0101000b: "sharedUserId",
    0x0101000c: "hasCode", 0x0101000d: "persistent", 0x0101000e: "enabled",
    0x0101000f: "debuggable", 0x01010010: "exported", 0x01010011: "process",
    0x01010012: "taskAffinity", 0x01010013: "multiprocess", 0x01010014: "finishOnTaskLaunch",
    0x01010015: "clearTaskOnLaunch", 0x01010016: "stateNotNeeded",
    0x01010017: "excludeFromRecents", 0x01010018: "authorities", 0x01010019: "syncable",
    0x0101001a: "initOrder", 0x0101001b: "grantUriPermissions", 0x0101001c: "priority",
    0x0101001d: "launchMode", 0x0101001e: "screenOrientation", 0x0101001f: "configChanges",
    0x01010020: "description", 0x01010021: "targetPackage", 0x01010022: "handleProfiling",
    0x01010023: "functionalTest", 0x01010024: "value", 0x01010025: "resource",
    0x01010026: "mimeType", 0x01010027: "scheme", 0x01010028: "host", 0x01010029: "port",
    0x0101002a: "path", 0x0101002b: "pathPrefix", 0x0101002c: "pathPattern",
    0x010100af: "gravity", 0x0101013f: "minWidth", 0x01010140: "minHeight",
    0x010101ea: "order", 0x01010202: "targetActivity", 0x01010203: "alwaysRetainTaskState",
    0x01010204: "allowTaskReparenting", 0x0101020c: "minSdkVersion", 0x0101021b: "versionCode",
    0x0101021c: "versionName", 0x01010227: "reqTouchScreen", 0x01010228: "reqKeyboardType",
    0x01010229: "reqHardKeyboard", 0x0101022a: "reqNavigation",
    0x0101022b: "windowSoftInputMode", 0x0101022d: "noHistory", 0x01010232: "reqFiveWayNav",
    0x01010261: "sharedUserLabel", 0x0101026c: "anyDensity", 0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion", 0x01010272: "testOnly", 0x0101027f: "backupAgent",
    0x01010280: "allowBackup", 0x01010281: "glEsVersion", 0x01010284: "smallScreens",
    0x01010285: "normalScreens", 0x01010286: "largeScreens", 0x0101028d: "resizeable",
    0x0101028e: "required", 0x0101029c: "killAfterRestore",
    0x010102a7: "finishOnCloseSystemDialogs", 0x010102b7: "installLocation",
    0x010102b8: "vmSafeMode", 0x010102ba: "restoreAnyVersion", 0x010102be: "logo",
    0x010102bf: "xlargeScreens", 0x010102c0: "immersive", 0x010102d3: "hardwareAccelerated",
    0x0101035a: "largeHeap", 0x01010364: "requiresSmallestWidthDp",
    0x01010365: "compatibleWidthLimitDp", 0x01010366: "largestWidthLimitDp",
    0x0101036a: "stopWithTask", 0x01010398: "uiOptions", 0x010103a6: "publicKey",
    0x010103a7: "parentActivityName", 0x010103a9: "isolatedProcess", 0x010103af: "supportsRtl",
    0x010103bf: "singleUser", 0x010103c7: "permissionFlags", 0x010103c9: "showOnLockScreen",
    0x010103d0: "requiredForAllUsers", 0x010103d5: "restrictedAccountType",
    0x010103d6: "requiredAccountType", 0x010103e3: "ssp", 0x010103e4: "sspPrefix",
    0x010103e5: "sspPattern", 0x010103e8: "category", 0x010103f2: "banner",
    0x010103f4: "isGame", 0x010103f5: "allowEmbedded", 0x0101042d: "persistableMode",
    0x01010445: "documentLaunchMode", 0x01010446: "maxRecents",
    0x01010447: "autoRemoveFromRecents", 0x0101044d: "targetName",
    0x01010473: "fullBackupOnly", 0x01010476: "relinquishTaskIdentity",
    0x0101048e: "multiArch", 0x010104b2: "resumeWhilePausing", 0x010104d5: "revisionCode",
    0x010104ea: "extractNativeLibs", 0x010104eb: "fullBackupContent",
    0x010104ec: "usesCleartextTraffic", 0x010104ed: "lockTaskMode", 0x010104ee: "autoVerify",
    0x010104ef: "showForAllUsers", 0x010104f4: "defaultWidth", 0x010104f5: "defaultHeight",
    0x010104f6: "resizeableActivity", 0x010104f7: "supportsPictureInPicture",
    0x01010504: "defaultToDeviceProtectedStorage", 0x01010505: "directBootAware",
    0x0101050e: "externalService", 0x01010515: "use32bitAbi", 0x01010519: "version",
    0x0101051a: "backupInForeground", 0x01010525: "enableVrMode", 0x01010526: "hash",
    0x01010527: "networkSecurityConfig", 0x0101052c: "roundIcon",
    0x01010531: "visibleToInstantApps", 0x0101053a: "rotationAnimation",
    0x01010545: "appCategory", 0x01010547: "recreateOnConfigChanges", 0x01010548: "certDigest",
    0x01010549: "splitName", 0x0101054a: "colorMode", 0x0101054b: "isolatedSplits",
    0x0101054c: "targetSandboxVersion", 0x01010554: "requiredFeature",
    0x01010555: "requiredNotFeature", 0x0101055a: "isStatic", 0x0101055b: "isFeatureSplit",
    0x01010560: "maxAspectRatio", 0x01010565: "requiredSystemPropertyName",
    0x01010566: "requiredSystemPropertyValue", 0x01010569: "showWhenLocked",
    0x0101056a: "turnScreenOn", 0x0101056b: "classLoader", 0x0101056e: "cantSaveState",
    0x01010572: "compileSdkVersion", 0x01010573: "compileSdkVersionCodename",
    0x01010576: "versionCodeMajor", 0x01010577: "versionMajor",
    0x0101057a: "appComponentFactory", 0x0101058e: "usesNonSdkApi",
    0x01010591: "isSplitRequired", 0x01010594: "shell", 0x01010597: "useAppZygote",
    0x01010599: "foregroundServiceType", 0x0101059a: "hasFragileUserData",
    0x0101059b: "minAspectRatio", 0x0101059c: "inheritShowWhenLocked",
    0x0101059d: "zygotePreloadName", 0x0101059e: "useEmbeddedDex",
    0x0101059f: "forceUriPermissions", 0x01010600: "allowClearUserDataOnFailedRestore",
    0x01010601: "allowAudioPlaybackCapture", 0x01010603: "requestLegacyExternalStorage",
    0x01010608: "forceQueryable", 0x0101060c: "preferMinimalPostProcessing",
    0x0101060e: "crossProfile", 0x01010610: "sdkVersion", 0x01010611: "minExtensionVersion",
    0x01010612: "allowNativeHeapPointerTagging", 0x01010613: "autoRevokePermissions",
    0x01010614: "preserveLegacyExternalStorage", 0x01010616: "gwpAsanMode",
    0x01010617: "rollbackDataPolicy", 0x01010619: "windowLayoutAffinity",
    0x0101061e: "pathSuffix", 0x0101061f: "sspSuffix", 0x01010620: "pathAdvancedPattern",
    0x01010621: "sspAdvancedPattern", 0x01010624: "memtagMode",
    0x01010625: "nativeHeapZeroInitialized", 0x0101063e: "dataExtractionRules",
    0x01010642: "attributionTags", 0x01010644: "usesPermissionFlags",
    0x01010645: "requestRawExternalStorageAccess", 0x01010646: "playHomeTransitionSound",
    0x0101064a: "requestForegroundServiceExemption", 0x0101064b: "attributionsAreUserVisible",
    0x0101064d: "sharedUserMaxSdkVersion", 0x0101064e: "requiredSplitTypes",
    0x0101064f: "splitTypes", 0x01010650: "canDisplayOnRemoteDevices",
    0x01010652: "resetEnabledSettingsOnAppDataCleared", 0x0101065b: "localeConfig",
    0x01010669: "allowUntrustedActivityEmbedding", 0x0101066a: "knownActivityEmbeddingCerts",
    0x0101066c: "enableOnBackInvokedCallback", 0x01010679: "requiredDisplayCategory",
    0x0101067d: "allowSharedIsolatedProcess", 0x0101068d: "systemUserOnly",
    0x0101069b: "requireContentUriPermissionFromCaller",
    0x010106a1: "allowCrossUidActivitySwitchFromBelow",
}
ANDROID_ATTR_IDS: Dict[str, int] = {name: res_id for res_id, name in ANDROID_ATTRS.items()}

# names of enumerated values (android.content.pm.ActivityInfo, PermissionInfo)
LAUNCH_MODES = {0: "standard", 1: "singleTop", 2: "singleTask", 3: "singleInstance",
                4: "singleInstancePerTask"}
PROTECTION_LEVELS = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem",
                     4: "internal"}
PROTECTION_FLAGS = ((0x10, "privileged"), (0x20, "development"), (0x40, "appop"),
                    (0x80, "pre23"), (0x100, "installer"), (0x200, "verifier"),
                    (0x400, "preinstalled"), (0x800, "setup"), (0x1000, "instant"),
                    (0x2000, "runtime"), (0x4000, "oem"), (0x8000, "vendorPrivileged"),
                    (0x10000, "textClassifier"))
_DIMENSION_UNITS = ("px", "dp", "sp", "pt", "in", "mm")
_FRACTION_UNITS = ("%", "%p")
_PREFIX_NAME = re.compile(r"[A-Za-z_][\w.-]{0,63}$")

RefResolver = Callable[[int], Optional[str]]


class AxmlError(ValueError):
    """The data is not binary XML that can be decoded."""


@dataclass
class AxmlDocument:
    """A decoded XML file of an app package."""

    root: XmlNode
    namespaces: Dict[str, str] = field(default_factory=dict)   # prefix -> URI
    text: str = ""                     # rendered by render_xml; node lines point into it
    warnings: List[str] = field(default_factory=list)


def decode_axml(data: bytes, resolve_ref: Optional[RefResolver] = None) -> AxmlDocument:
    """Decode binary XML. `resolve_ref(id)` turns a resource id into a name such as
    "@xml/network_security_config" (ResourceTable.name_of from arsc fits); references stay
    "@0x7f0f0000" without it. Raises AxmlError when the data is not binary XML (text XML, too
    short, no string pool, no element)."""
    return _Decoder(bytes(data), resolve_ref).run()


def format_value(data_type: int, data: int, attr: str = "",
                 resolve_ref: Optional[RefResolver] = None) -> str:
    """Readable text of a typed value (Res_value). `attr` is the attribute name; it selects
    the names of enumerated values (launchMode, protectionLevel)."""
    local = attr.rsplit(":", 1)[-1]
    if data_type in (TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE):
        if data == 0:
            return "@null"
        return _resolve(resolve_ref, data) or f"@0x{data:08x}"
    if data_type in (TYPE_ATTRIBUTE, TYPE_DYNAMIC_ATTRIBUTE):
        name = _resolve(resolve_ref, data)
        if name:
            return "?" + name[1:] if name.startswith("@") else "?" + name
        if data in ANDROID_ATTRS:
            return "?android:attr/" + ANDROID_ATTRS[data]
        return f"?0x{data:08x}"
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data else "false"     # aapt2 writes 0xffffffff for true
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        if local == "protectionLevel":
            return protection_level_name(data)
        if local == "launchMode" and data in LAUNCH_MODES:
            return LAUNCH_MODES[data]
        if data_type == TYPE_INT_DEC:
            return str(data - (1 << 32) if data & 0x80000000 else data)
        return f"0x{data:08x}"
    if TYPE_INT_COLOR_ARGB8 <= data_type <= TYPE_INT_COLOR_RGB4:
        return f"#{data:08x}"
    if data_type == TYPE_FLOAT:
        return f"{struct.unpack('<f', struct.pack('<I', data))[0]:g}"
    if data_type == TYPE_DIMENSION:
        return _complex(data, _DIMENSION_UNITS, 1)
    if data_type == TYPE_FRACTION:
        return _complex(data, _FRACTION_UNITS, 100)
    if data_type == TYPE_NULL:
        return ""
    return f"0x{data:08x}"


def protection_level_name(value: int) -> str:
    """"signature", "signature|privileged" ... for a protectionLevel value; unknown bits in
    hex."""
    names = [PROTECTION_LEVELS.get(value & 0xF, f"0x{value & 0xF:x}")]
    rest = value & 0xFFFFFFF0
    for bit, flag in PROTECTION_FLAGS:
        if rest & bit:
            names.append(flag)
            rest &= ~bit
    if rest:
        names.append(f"0x{rest:x}")
    return "|".join(names)


class Namespaces:
    """Prefixes of the namespace URIs of a document and the names of its attributes, shared
    by the binary XML and protobuf XML decoders so both name things the same way."""

    def __init__(self, warn: Callable[[str], None]):
        self.warn = warn
        self.prefixes: Dict[str, str] = {}      # namespace URI -> prefix
        self.by_prefix: Dict[str, str] = {}     # prefix -> namespace URI

    def cut(self, name: str) -> str:
        """A name or URI of at most MAX_NAME_CHARS characters."""
        if len(name) <= MAX_NAME_CHARS:
            return name
        self.warn(f"a name of {len(name)} characters was cut to {MAX_NAME_CHARS}")
        return name[:MAX_NAME_CHARS]

    def prefix_of(self, uri: str, declared: str = "") -> str:
        """android, tools and app for the well-known URIs; otherwise the declared prefix when
        it is a plain name not taken yet; otherwise ns1, ns2 ..."""
        uri = self.cut(uri)
        if uri in self.prefixes:
            return self.prefixes[uri]
        if len(self.prefixes) >= MAX_NAMESPACES:
            self.warn(f"more than {MAX_NAMESPACES} namespaces; the others share the prefix ns0")
            self.by_prefix.setdefault("ns0", uri)
            return "ns0"
        prefix = KNOWN_PREFIXES.get(uri, "")
        if not prefix and _PREFIX_NAME.match(declared) and declared not in self.by_prefix \
                and declared not in KNOWN_PREFIXES.values() and declared.lower() != "xmlns":
            prefix = declared
        number = 1
        while not prefix or prefix in self.by_prefix:
            prefix, number = f"ns{number}", number + 1
        self.prefixes[uri] = prefix
        self.by_prefix[prefix] = uri
        return prefix

    def attribute_name(self, tag: str, uri: Optional[str], name: str, res_id: int) -> str:
        """The name of an attribute: android:<name from the id table> when it has the resource
        id of an android attribute, else the name with the prefix of its namespace."""
        name = self.cut(name)
        if res_id >> 24 == 0x01:
            self.prefix_of(ANDROID_URI)
            canonical = ANDROID_ATTRS.get(res_id)
            if canonical:
                if name != canonical:
                    self.warn(f"<{tag}> attribute '{name}' has the resource id of "
                              f"android:{canonical} (0x{res_id:08x}); the id is used")
                return "android:" + canonical
            if not name or name in ANDROID_ATTR_IDS:
                self.warn(f"<{tag}> attribute '{name}' has the resource id 0x{res_id:08x} of "
                          "another attribute")
                return f"android:attr_{res_id:08x}"
            return "android:" + name
        if not name:
            self.warn(f"<{tag}> has an attribute without a name")
            name = "unknown"
        if not uri:
            return name
        if uri == ANDROID_URI and not res_id:
            self.warn(f"<{tag}> attribute android:{name} has no resource id (Android's package "
                      "parser does not see it)")
        return f"{self.prefix_of(uri)}:{name}"


def _resolve(resolve_ref: Optional[RefResolver], res_id: int) -> Optional[str]:
    if resolve_ref is None:
        return None
    try:
        name = resolve_ref(res_id)
    except Exception:       # a resolver failure must not stop the decoding
        return None
    return name or None


def _complex(data: int, units: Tuple[str, ...], scale: int) -> str:
    """A dimension or fraction value (TypedValue.complexToFloat)."""
    mantissa = data & 0xFFFFFF00
    if mantissa & 0x80000000:
        mantissa -= 1 << 32
    value = mantissa * (1.0, 1 / (1 << 7), 1 / (1 << 15), 1 / (1 << 23))[data >> 4 & 3] / 256
    unit = data & 0xF
    return f"{value * scale:g}{units[unit] if unit < len(units) else ''}"


class _StringPool:
    """The strings of a string pool chunk, decoded when first used. Strings are cached by
    position and decoded within a byte budget, so string ids that share or overlap one long
    string cost no more than the pool itself."""

    def __init__(self, decoder: "_Decoder", start: int, end: int, header_size: int):
        data = decoder.data
        self._decoder = decoder
        self._data = data
        self._cache: Dict[Tuple[int, int], str] = {}     # (position, limit) -> text
        if header_size < 28 or start + 28 > end:
            raise AxmlError("the string pool header is truncated")
        count, styles, flags, strings_start, styles_start = struct.unpack_from(
            "<5I", data, start + 8)
        self.utf8 = bool(flags & UTF8_FLAG)
        self._offsets = start + header_size
        fits = (end - self._offsets) // 4
        if header_size < strings_start <= end - start:
            fits = min(fits, (strings_start - header_size) // 4)
        clamped = min(count, max(fits, 0), MAX_STRINGS)
        if clamped < count:
            decoder.warn(f"the string pool declares {count} strings but only {clamped} fit; "
                         "the count was clamped")
        self.count = clamped
        self._base = start + strings_start
        self._limit = end
        if styles and strings_start < styles_start <= end - start:
            self._limit = start + styles_start
        if self._base >= self._limit and self.count:
            decoder.warn("the string pool has no room for its strings")
            self.count = 0
        self._budget = 2 * max(self._limit - self._base, 0) + POOL_BUDGET

    def get(self, index: int, chars: int = MAX_STRING_CHARS) -> Optional[str]:
        """String `index` cut to `chars` characters, or None when the index or the string is
        invalid."""
        if index >= self.count:
            return None
        pos = self._base + struct.unpack_from("<I", self._data, self._offsets + 4 * index)[0]
        text = self._cache.get((pos, chars))
        if text is None:
            if pos >= self._limit:
                self._decoder.warn(f"string {index} starts outside the string pool")
                return None
            text = self._utf8(index, pos, chars) if self.utf8 else self._utf16(index, pos, chars)
            if text is not None:
                self._cache[(pos, chars)] = text
        return text

    def _charge(self, size: int) -> bool:
        """Count bytes about to be decoded; False when the budget is spent."""
        self._budget -= size
        if self._budget >= 0:
            return True
        self._decoder.warn("strings of the string pool overlap far more than a real pool "
                           "allows; the rest are not read")
        return False

    def _utf8(self, index: int, pos: int, chars: int) -> Optional[str]:
        data, limit = self._data, self._limit
        for _ in range(2):              # the UTF-16 length, then the UTF-8 byte length
            if pos >= limit:
                return None
            size = data[pos]
            if size & 0x80:
                if pos + 1 >= limit:
                    return None
                size = (size & 0x7F) << 8 | data[pos + 1]
                pos += 1
            pos += 1
        end = pos + size
        window = min(limit, pos + 4 * chars + 1)     # enough to tell that a string is longer
        if end > limit:
            self._decoder.warn(f"string {index} runs past the end of the string pool")
            end = limit
        elif end < limit and data[end] != 0:
            # aapt wrote lengths above 0x7fff truncated: the string ends at its NUL byte
            nul = data.find(b"\0", end, window)
            end = nul if nul >= 0 else window
        take = min(end, pos + 4 * chars)
        if not self._charge(take - pos):
            return None
        return self._cut(index, data[pos:take].decode("utf-8", "replace"), end > take, chars)

    def _utf16(self, index: int, pos: int, chars: int) -> Optional[str]:
        data, limit = self._data, self._limit
        if pos + 2 > limit:
            return None
        size = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if size & 0x8000:
            if pos + 2 > limit:
                return None
            size = (size & 0x7FFF) << 16 | struct.unpack_from("<H", data, pos)[0]
            pos += 2
        end = pos + 2 * size
        if end > limit:
            self._decoder.warn(f"string {index} runs past the end of the string pool")
            end = pos + (limit - pos) // 2 * 2
        take = min(end, pos + 2 * chars)
        if not self._charge(take - pos):
            return None
        return self._cut(index, data[pos:take].decode("utf-16-le", "replace"), end > take, chars)

    def _cut(self, index: int, text: str, longer: bool, chars: int) -> str:
        if longer or len(text) > chars:
            self._decoder.warn(f"string {index} is longer than {chars} characters; it was cut")
            return text[:chars]
        return text


class _Decoder:
    def __init__(self, data: bytes, resolve_ref: Optional[RefResolver]):
        self.data = data
        self.resolve_ref = resolve_ref
        self.warnings: List[str] = []
        self.pool: Optional[_StringPool] = None
        self.res_map = (0, 0)                   # offset and count of the resource ids
        self.names = Namespaces(self.warn)
        self.root: Optional[XmlNode] = None
        self.stack: List[XmlNode] = []
        self.texts: List[List[str]] = []
        self.skipped_depth = 0                  # open elements below the depth cap
        self.nodes = 0                          # chunks walked
        self.attributes = 0
        self.chars = 0                          # characters put into the tree
        self.full = False                       # a cap was reached: the rest is not read
        self.closed_root = False

    def warn(self, message: str) -> None:
        if len(self.warnings) > MAX_WARNINGS or message in self.warnings:
            return
        if len(self.warnings) == MAX_WARNINGS:
            message = "further warnings suppressed"
        self.warnings.append(message)

    def run(self) -> AxmlDocument:
        data = self.data
        if len(data) < 8:
            raise AxmlError("too short for binary XML")
        if data[:64].lstrip(b" \t\r\n\xef\xbb\xbf").startswith(b"<"):
            raise AxmlError("this is text XML, not binary XML")
        root_type, header_size, size = struct.unpack_from("<HHI", data, 0)
        if root_type != RES_XML:
            self.warn(f"the root chunk has type 0x{root_type:04x} instead of 0x0003 "
                      "(Android refuses such a file)")
        end = len(data)
        if size > end:
            self.warn(f"the document declares {size} bytes but has {end}: it is truncated")
        elif size < max(header_size, 8):
            self.warn(f"the document declares an impossible size of {size} bytes; all "
                      f"{end} bytes are read")
        elif size < end:
            self.warn(f"{end - size} bytes follow the end of the document (appended data)")
            end = size
        if header_size < 8 or header_size > end:
            self.warn(f"the root chunk has a header size of {header_size}")
            header_size = 8
        self.walk(header_size, end)
        if self.root is None:
            raise AxmlError("no XML element found")
        if self.stack:
            self.warn(f"{len(self.stack)} elements are not closed")
            while self.stack:
                self.close_element()
        namespaces = dict(self.names.by_prefix)
        text = render_xml(self.root, namespaces)
        return AxmlDocument(self.root, namespaces, text, self.warnings)

    def walk(self, pos: int, end: int) -> None:
        data = self.data
        seen_node = False
        while pos + 8 <= end:
            chunk_type, header_size, size = struct.unpack_from("<HHI", data, pos)
            if size < 8 or header_size < 8 or header_size > size:
                self.warn(f"malformed chunk at offset {pos} (type 0x{chunk_type:04x}, header "
                          f"{header_size}, size {size}); decoding stopped there")
                return
            if self.nodes >= MAX_NODES:
                self.warn(f"more than {MAX_NODES} chunks; the rest is ignored")
                return
            self.nodes += 1
            if (size | header_size) & 3:
                self.warn(f"chunk at offset {pos} is not aligned to 4 bytes (Android refuses "
                          "such a file)")
            if size > end - pos:
                self.warn(f"chunk at offset {pos} runs past the end of the document")
                size = end - pos
            if chunk_type == RES_STRING_POOL or chunk_type == RES_XML_RESOURCE_MAP:
                if seen_node:
                    self.warn(f"chunk of type 0x{chunk_type:04x} after the first element is "
                              "ignored")
                elif chunk_type == RES_STRING_POOL:
                    if self.pool is not None:
                        self.warn("more than one string pool; the last one is used")
                    self.pool = _StringPool(self, pos, pos + size, header_size)
                else:
                    if self.res_map[1]:
                        self.warn("more than one resource map; the last one is used")
                    self.res_map = (pos + header_size, (size - header_size) // 4)
            elif RES_XML_START_NAMESPACE <= chunk_type <= RES_XML_LAST_CHUNK:
                if not seen_node and self.pool is None:
                    raise AxmlError("no string pool before the first XML node")
                seen_node = True
                self.node(chunk_type, pos, header_size, pos + size)
                if self.full:
                    return
            else:
                self.warn(f"unknown chunk of type 0x{chunk_type:04x} at offset {pos} skipped")
            pos += size
        if pos < end and data[pos:end].strip(b"\0"):
            self.warn(f"{end - pos} bytes after the last chunk ignored")

    def node(self, chunk_type: int, pos: int, header_size: int, end: int) -> None:
        if header_size < 16:
            self.warn(f"XML node at offset {pos} has a header of {header_size} bytes; skipped")
            return
        ext = pos + header_size
        need = _EXTENSION_SIZES.get(chunk_type)
        if need is None:
            self.warn(f"unknown XML node of type 0x{chunk_type:04x} at offset {pos} skipped")
            return
        if ext + need > end:
            self.warn(f"XML node at offset {pos} is too small for its type; skipped")
            return
        if chunk_type == RES_XML_START_NAMESPACE:
            prefix_index, uri_index = struct.unpack_from("<II", self.data, ext)
            self.declare(self.name(prefix_index), self.name(uri_index))
        elif chunk_type == RES_XML_START_ELEMENT:
            self.start_element(pos, ext, end)
        elif chunk_type == RES_XML_END_ELEMENT:
            self.end_element()
        elif chunk_type == RES_XML_CDATA:
            text = self.string(struct.unpack_from("<I", self.data, ext)[0])
            if text and self.texts and not self.skipped_depth and self.count_chars(len(text)):
                self.texts[-1].append(text)

    def count_chars(self, count: int) -> bool:
        """Add characters to the document; False (and stop) when that passes the cap."""
        self.chars += count
        if self.chars <= MAX_TOTAL_CHARS:
            return True
        self.warn(f"the document holds more than {MAX_TOTAL_CHARS} characters; the rest is "
                  "not read")
        self.full = True
        return False

    def string(self, index: int, chars: int = MAX_STRING_CHARS) -> Optional[str]:
        if index == NO_INDEX or self.pool is None:
            return None
        return self.pool.get(index, chars)

    def name(self, index: int) -> Optional[str]:
        """An element or attribute name, a namespace prefix or URI: only its first
        MAX_NAME_CHARS characters are decoded."""
        return self.string(index, MAX_NAME_CHARS)

    def resource_id(self, index: int) -> int:
        offset, count = self.res_map
        if index >= count:
            return 0
        return struct.unpack_from("<I", self.data, offset + 4 * index)[0]

    def declare(self, prefix: Optional[str], uri: Optional[str]) -> None:
        if not uri:
            self.warn(f"namespace prefix '{prefix or ''}' has an empty URI")
            return
        self.names.prefix_of(uri, prefix or "")

    def start_element(self, pos: int, ext: int, end: int) -> None:
        if self.closed_root and not self.stack:
            self.warn("a second top-level element is ignored (Android reads only the first)")
        if self.skipped_depth or (self.closed_root and not self.stack):
            self.skipped_depth += 1
            return
        if len(self.stack) >= MAX_DEPTH:
            self.warn(f"elements nested deeper than {MAX_DEPTH} levels are skipped")
            self.skipped_depth = 1
            return
        data = self.data
        ns_index, name_index, attr_start, attr_size, attr_count = struct.unpack_from(
            "<IIHHH", data, ext)
        name = self.name(name_index)
        if not name:
            self.warn(f"element at offset {pos} has no valid name")
            name = "unknown"
        uri = self.name(ns_index)
        node = XmlNode(f"{self.names.prefix_of(uri)}:{name}" if uri else name)
        if not self.count_chars(len(node.tag)):
            return
        if attr_count and (attr_start != 20 or attr_size != 20):
            self.warn(f"<{node.tag}> uses an unusual attribute layout (start {attr_start}, "
                      f"size {attr_size})")
        if attr_start + attr_size * attr_count > end - ext:
            self.warn(f"the attributes of <{node.tag}> run past the end of their chunk "
                      "(Android refuses such a file)")
        if attr_count > 1 and attr_size == 0:
            self.warn(f"<{node.tag}> declares {attr_count} attributes in the same place; one "
                      "is read")
            attr_count = 1
        if attr_count > MAX_ATTRIBUTES:
            self.warn(f"<{node.tag}> declares {attr_count} attributes; only {MAX_ATTRIBUTES} "
                      "are read")
            attr_count = MAX_ATTRIBUTES
        if self.attributes + attr_count > MAX_TOTAL_ATTRIBUTES:
            self.warn(f"more than {MAX_TOTAL_ATTRIBUTES} attributes; the rest are not read")
            attr_count = max(0, MAX_TOTAL_ATTRIBUTES - self.attributes)
        self.attributes += attr_count
        last_id = 0
        for i in range(attr_count):
            at = ext + attr_start + i * attr_size
            if at + 20 > end:
                break
            attr_ns, attr_name, raw_index, _size, _res0, data_type, value = struct.unpack_from(
                "<IIIHBBI", data, at)
            res_id = self.resource_id(attr_name)
            if res_id and res_id < last_id:
                self.warn(f"the attributes of <{node.tag}> are not sorted by resource id "
                          "(Android may not see some of them)")
            last_id = max(last_id, res_id)
            key = self.names.attribute_name(node.tag, self.name(attr_ns),
                                            self.name(attr_name) or "", res_id)
            if key in node.attrs:
                self.warn(f"<{node.tag}> has attribute {key} twice; the first value is kept")
                continue
            text = self.attribute_value(node.tag, key, raw_index, data_type, value)
            if not self.count_chars(len(key) + len(text)):
                break
            node.attrs[key] = text
        if self.stack:
            self.stack[-1].children.append(node)
        else:
            self.root = node
        self.stack.append(node)
        self.texts.append([])

    def end_element(self) -> None:
        if self.skipped_depth:
            self.skipped_depth -= 1
            return
        if not self.stack:
            self.warn("an end tag without a start tag is ignored")
            return
        self.close_element()

    def close_element(self) -> None:
        self.stack.pop().text = "".join(self.texts.pop()).strip()
        if not self.stack:
            self.closed_root = True

    def attribute_value(self, tag: str, key: str, raw_index: int, data_type: int,
                        data: int) -> str:
        raw = self.string(raw_index)
        if data_type == TYPE_STRING:
            typed = self.string(data)
            if typed is None:
                self.warn(f"<{tag}> {key} points to a string that does not exist")
                return raw or ""
            if raw is not None and raw != typed:
                self.warn(f"<{tag}> {key}: the raw value differs from the typed value; the typed "
                          "value is used")
            return typed
        if data_type == TYPE_NULL and raw is not None:
            return raw
        if data_type not in _KNOWN_TYPES:
            self.warn(f"<{tag}> {key} has a value of unknown type 0x{data_type:02x}")
            if raw is not None:
                return raw
        return format_value(data_type, data, key, self.resolve_ref)


# ------------------------------------------------------------------ encoder (for tests)
def encode_axml(root: XmlNode, *, utf8: bool = False, attr_ids: Optional[Dict[str, int]] = None,
                namespaces: Optional[Dict[str, str]] = None) -> bytes:
    """Binary XML for a tree, laid out as aapt2 writes it: XML header, string pool (the
    attribute names that have resource ids first, in the order of the resource map),
    resource map, namespace start, element start/end chunks with typed attribute values
    (booleans as 0xffffffff), text chunks, namespace end.

    Values are typed by their text: "true"/"false" booleans, decimal and 0x-hex numbers,
    "@0x7f0f0000" references, "?0x..." attributes, "#aarrggbb" colors, launchMode and
    protectionLevel names as numbers; everything else is a string. `android:` attributes get
    their ids from ANDROID_ATTRS; `attr_ids` adds or overrides ids by full name
    ("android:exported"). `namespaces` (prefix -> URI) defaults to the xmlns attributes of the
    root plus android, tools and app for the prefixes in use.
    """
    ids = {f"android:{name}": res_id for name, res_id in ANDROID_ATTR_IDS.items()}
    ids.update(attr_ids or {})
    declared = _namespaces_for(root, namespaces)
    uri_of = dict(declared)
    nodes = list(root.iter())

    # string pool: names with ids first (sorted by id, as aapt2 does), then the rest
    named = sorted(dict.fromkeys((_local(key), ids[key]) for node in nodes for key in node.attrs
                                 if ids.get(key) and not key.startswith("xmlns")),
                   key=lambda pair: pair[1])
    strings = [local for local, _ in named]
    index_of = {pair: i for i, pair in enumerate(named)}
    res_map = [res_id for _, res_id in named]
    plain: Dict[str, int] = {}

    def ref(text: str) -> int:
        if text not in plain:
            plain[text] = len(strings)
            strings.append(text)
        return plain[text]

    body = bytearray()
    for prefix, uri in declared.items():
        body += _node(RES_XML_START_NAMESPACE, 1, struct.pack("<II", ref(prefix), ref(uri)))
    stack: List[Tuple[XmlNode, bool]] = [(root, False)]
    while stack:
        node, closing = stack.pop()
        ns_index, name_index = _qualified(node.tag, uri_of, ref)
        if closing:
            body += _node(RES_XML_END_ELEMENT, node.line or 1,
                          struct.pack("<II", ns_index, name_index))
            continue
        attrs = []
        for key, value in node.attrs.items():
            if key == "xmlns" or key.startswith("xmlns:"):
                continue
            res_id = ids.get(key, 0)
            if res_id:
                prefix = key.split(":", 1)[0]
                attr_ns = ref(uri_of[prefix]) if prefix in uri_of else NO_INDEX
                attr_name = index_of[(_local(key), res_id)]
            else:
                attr_ns, attr_name = _qualified(key, uri_of, ref)
            data_type, data = _typed(key, value)
            raw = ref(value) if data_type == TYPE_STRING else NO_INDEX
            if data_type == TYPE_STRING:
                data = raw
            attrs.append((res_id or 0xFFFFFFFF, key, struct.pack(
                "<IIIHBBI", attr_ns, attr_name, raw, 8, 0, data_type, data)))
        attrs.sort(key=lambda item: item[0])
        special = {key: i + 1 for i, (_, key, _) in enumerate(attrs)
                   if key in ("id", "class", "style")}
        ext = struct.pack("<IIHHHHHH", ns_index, name_index, 20, 20, len(attrs),
                          special.get("id", 0), special.get("class", 0), special.get("style", 0))
        body += _node(RES_XML_START_ELEMENT, node.line or 1,
                      ext + b"".join(packed for _, _, packed in attrs))
        if node.text:
            body += _node(RES_XML_CDATA, node.line or 1,
                          struct.pack("<IHBBI", ref(node.text), 8, 0, TYPE_NULL, 0))
        stack.append((node, True))
        stack.extend((child, False) for child in reversed(node.children))
    for prefix, uri in reversed(list(declared.items())):
        body += _node(RES_XML_END_NAMESPACE, 1, struct.pack("<II", ref(prefix), ref(uri)))
    pool = _string_pool(strings, utf8)
    resources = struct.pack(f"<HHI{len(res_map)}I", RES_XML_RESOURCE_MAP, 8, 8 + 4 * len(res_map),
                            *res_map)
    content = pool + resources + bytes(body)
    return struct.pack("<HHI", RES_XML, 8, 8 + len(content)) + content


def _namespaces_for(root: XmlNode, namespaces: Optional[Dict[str, str]]) -> Dict[str, str]:
    if namespaces is not None:
        return dict(namespaces)
    declared = {key[6:]: value for key, value in root.attrs.items() if key.startswith("xmlns:")}
    known = {prefix: uri for uri, prefix in KNOWN_PREFIXES.items()}
    for node in root.iter():
        for name in [node.tag, *node.attrs]:
            prefix = name.split(":", 1)[0] if ":" in name else ""
            if prefix in known and prefix not in declared:
                declared[prefix] = known[prefix]
    return declared


def _local(name: str) -> str:
    return name.split(":", 1)[1] if ":" in name else name


def _qualified(name: str, uri_of: Dict[str, str], ref: Callable[[str], int]) -> Tuple[int, int]:
    """String indexes of the namespace URI and the local name of a prefixed name."""
    if ":" in name:
        prefix, local = name.split(":", 1)
        if prefix in uri_of:
            return ref(uri_of[prefix]), ref(local)
    return NO_INDEX, ref(name)


def _typed(key: str, value: str) -> Tuple[int, int]:
    """(data type, data) of an attribute value, from its text; strings are (TYPE_STRING, 0)."""
    local = _local(key)
    if value in ("true", "false"):
        return TYPE_INT_BOOLEAN, 0xFFFFFFFF if value == "true" else 0
    if local == "launchMode" and value in LAUNCH_MODES.values():
        return TYPE_INT_DEC, next(k for k, v in LAUNCH_MODES.items() if v == value)
    if local == "protectionLevel":
        level = _protection_value(value)
        if level is not None:
            return TYPE_INT_HEX, level
    if re.fullmatch(r"@0x[0-9a-fA-F]{8}", value):
        return TYPE_REFERENCE, int(value[3:], 16)
    if value == "@null":
        return TYPE_REFERENCE, 0
    if re.fullmatch(r"\?0x[0-9a-fA-F]{8}", value):
        return TYPE_ATTRIBUTE, int(value[3:], 16)
    if re.fullmatch(r"-?[0-9]{1,10}", value) and -(1 << 31) <= int(value) < (1 << 31):
        return TYPE_INT_DEC, int(value) & 0xFFFFFFFF
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", value):
        return TYPE_INT_HEX, int(value, 16)
    if re.fullmatch(r"#[0-9a-fA-F]{8}", value):
        return TYPE_INT_COLOR_ARGB8, int(value[1:], 16)
    return TYPE_STRING, 0


def _protection_value(text: str) -> Optional[int]:
    levels = {name: value for value, name in PROTECTION_LEVELS.items()}
    flags = {name: bit for bit, name in PROTECTION_FLAGS}
    value = 0
    for part in text.split("|"):
        if part in levels:
            value |= levels[part]
        elif part in flags:
            value |= flags[part]
        else:
            return None
    return value


def _node(chunk_type: int, line: int, ext: bytes) -> bytes:
    """An XML node chunk: header with line number and no comment, then its extension."""
    return struct.pack("<HHIII", chunk_type, 16, 16 + len(ext), line, NO_INDEX) + ext


def _string_pool(strings: List[str], utf8: bool) -> bytes:
    offsets: List[int] = []
    body = bytearray()
    for text in strings:
        offsets.append(len(body))
        if utf8:
            raw = text.encode("utf-8")
            body += _length8(len(text.encode("utf-16-le")) // 2) + _length8(len(raw)) + raw + b"\0"
        else:
            raw = text.encode("utf-16-le")
            body += _length16(len(raw) // 2) + raw + b"\0\0"
    body += b"\0" * (-len(body) % 4)
    strings_start = 28 + 4 * len(strings)
    header = struct.pack("<HHI5I", RES_STRING_POOL, 28, strings_start + len(body), len(strings),
                         0, UTF8_FLAG if utf8 else 0, strings_start, 0)
    return header + struct.pack(f"<{len(offsets)}I", *offsets) + bytes(body)


def _length8(size: int) -> bytes:
    """A UTF-8 pool length; above 0x7fff it is truncated, as aapt did."""
    if size < 0x80:
        return bytes([size])
    return bytes([0x80 | (size >> 8 & 0x7F), size & 0xFF])


def _length16(size: int) -> bytes:
    if size < 0x8000:
        return struct.pack("<H", size)
    return struct.pack("<HH", 0x8000 | size >> 16, size & 0xFFFF)
