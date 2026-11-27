"""API and key inventory of a Flutter or Android app (APK, AAB ...) or project.

It answers two questions of a review: which servers does the app talk to, and which keys
does it carry? Every item comes with all the places it occurs (file and line):

  endpoints  server addresses (http, https, ws, wss) and the service each one belongs to
  hosts      the servers behind those addresses
  calls      HTTP, WebSocket and GraphQL calls in code (source projects, debug builds with
             their recovered Dart source, Java decompiled by jadx)
  paths      API paths kept as texts in code and in compiled code ("/api/v1/login" in the
             strings of libapp.so, where a release build keeps them)
  keys       keys, tokens and passwords that the secrets engine and the rules found
  config     service identifiers: Firebase project, app ID, OAuth client ID, AdMob app ID ...
  env        the entries of .env files (flutter_dotenv) in the project or the package
  alerts     the warnings drawn from all of these, the most serious first

Everything is read from text the scan already has: the files of the project, or the files
decoded from the app package. No address is contacted. Values are masked by default
(sca.walker.mask_secret); reveal_values retains complete observed values for the dashboard.

The default result is a JSON-safe dict stored as facts["apis"] (ScanResult.app["apis"]).
The dashboard builds a separate inventory with visible values for its scan session.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import posixpath
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from ..cwe import canonical
from ..engines.public_fixtures import FIXTURE_ADVICE, identify_public_fixture
from ..merge import LINE_TOLERANCE
from ..models import Finding
from ..walker import SourceFile, is_test_path, mask_secret, strip_bidi
from .checks import FIREBASE_NOTE, MAPS_CLIENT_NOTE, _URL, _endpoint
from .android import LOOPBACK_HOSTS
from .context import ORIGIN_PLACEHOLDER, ORIGIN_STRINGS, ORIGIN_SUMMARY, MobileContext

MAX_ITEMS = 300          # rows of each list; what is left out is counted in "truncated"
MAX_LOCATIONS = 20       # places kept for one item (all of them are counted)
MAX_ALERTS = 80
MAX_VISIBLE_ITEMS = 10_000     # dashboard/archive lists, independently bounded
MAX_VISIBLE_LOCATIONS = 200
MAX_CONTEXT_LINE = 4000        # contextual call parsing; literal URLs have no line cutoff
MAX_TEXT = 300

# categories of a server, in the order the list shows them
TUNNEL, WEBHOOK, APP, BACKEND, API, SDK, LOCAL = "tunnel", "webhook", "app", "backend", "api", "sdk", "local"
CATEGORY_ORDER = {TUNNEL: 0, WEBHOOK: 1, APP: 2, BACKEND: 3, API: 4, SDK: 5, LOCAL: 6}
CATEGORY_TEXT = {TUNNEL: "Tunnel or test service", WEBHOOK: "Webhook", APP: "App server",
                 BACKEND: "Cloud backend", API: "Third-party API", SDK: "SDK, analytics or ads",
                 LOCAL: "Local or development address"}
LEVELS = ("danger", "warning", "info")
LEVEL_RANK = {level: rank for rank, level in enumerate(LEVELS)}

# (host suffix, service, category): the first suffix that matches wins, so the more precise
# ones come first. A host that matches none is the app's own server (category APP).
SERVICES: Tuple[Tuple[str, str, str], ...] = (
    ("firebasedatabase.app", "Firebase Realtime Database", BACKEND),
    ("firebaseio.com", "Firebase Realtime Database", BACKEND),
    ("firestore.googleapis.com", "Cloud Firestore", BACKEND),
    ("firebasestorage.googleapis.com", "Firebase Storage", BACKEND),
    ("firebasestorage.app", "Firebase Storage", BACKEND),
    ("appspot.com", "Google App Engine / Firebase Storage", BACKEND),
    ("cloudfunctions.net", "Cloud Functions for Firebase", BACKEND),
    ("run.app", "Google Cloud Run", BACKEND),
    ("firebaseapp.com", "Firebase Hosting / Authentication", BACKEND),
    ("web.app", "Firebase Hosting", BACKEND),
    ("identitytoolkit.googleapis.com", "Firebase Authentication", BACKEND),
    ("securetoken.googleapis.com", "Firebase Authentication", BACKEND),
    ("fcm.googleapis.com", "Firebase Cloud Messaging", SDK),
    ("firebaseinstallations.googleapis.com", "Firebase SDK", SDK),
    ("firebaseremoteconfig.googleapis.com", "Firebase Remote Config", SDK),
    ("firebaselogging.googleapis.com", "Firebase SDK", SDK),
    ("firebase-settings.crashlytics.com", "Firebase Crashlytics", SDK),
    ("crashlytics.com", "Firebase Crashlytics", SDK),
    ("app-measurement.com", "Google Analytics for Firebase", SDK),
    ("google-analytics.com", "Google Analytics", SDK),
    ("doubleclick.net", "Google Ads", SDK),
    ("googlesyndication.com", "Google Ads", SDK),
    ("googleadservices.com", "Google Ads", SDK),
    ("maps.googleapis.com", "Google Maps", API),
    ("generativelanguage.googleapis.com", "Google Gemini API", API),
    ("aiplatform.googleapis.com", "Google Vertex AI", API),
    ("googleapis.com", "Google APIs", API),
    ("gstatic.com", "Google static content", SDK),
    ("google.com", "Google", SDK),
    ("youtube.com", "YouTube", API),
    ("supabase.co", "Supabase", BACKEND),
    ("supabase.in", "Supabase", BACKEND),
    ("execute-api.amazonaws.com", "AWS API Gateway", BACKEND),
    ("on.aws", "AWS Lambda function URL", BACKEND),
    ("amazoncognito.com", "Amazon Cognito", BACKEND),
    ("cloudfront.net", "Amazon CloudFront", BACKEND),
    ("amazonaws.com", "Amazon Web Services", BACKEND),
    ("azurewebsites.net", "Azure App Service", BACKEND),
    ("azure-api.net", "Azure API Management", BACKEND),
    ("blob.core.windows.net", "Azure Blob Storage", BACKEND),
    ("database.windows.net", "Azure SQL", BACKEND),
    ("microsoftonline.com", "Microsoft identity platform", API),
    ("herokuapp.com", "Heroku", BACKEND),
    ("vercel.app", "Vercel", BACKEND),
    ("netlify.app", "Netlify", BACKEND),
    ("pages.dev", "Cloudflare Pages", BACKEND),
    ("workers.dev", "Cloudflare Workers", BACKEND),
    ("onrender.com", "Render", BACKEND),
    ("railway.app", "Railway", BACKEND),
    ("fly.dev", "Fly.io", BACKEND),
    ("appwrite.io", "Appwrite", BACKEND),
    ("back4app.com", "Back4App (Parse)", BACKEND),
    ("hasura.app", "Hasura", BACKEND),
    ("mongodb.net", "MongoDB Atlas", BACKEND),
    ("api.stripe.com", "Stripe", API),
    ("stripe.com", "Stripe", API),
    ("paypal.com", "PayPal", API),
    ("braintreegateway.com", "Braintree", API),
    ("api.openai.com", "OpenAI API", API),
    ("api.anthropic.com", "Anthropic API", API),
    ("graph.facebook.com", "Facebook Graph API", API),
    ("facebook.com", "Facebook", SDK),
    ("api.twitter.com", "X (Twitter) API", API),
    ("api.x.com", "X (Twitter) API", API),
    ("api.twilio.com", "Twilio", API),
    ("api.sendgrid.com", "SendGrid", API),
    ("api.mailgun.net", "Mailgun", API),
    ("api.mapbox.com", "Mapbox", API),
    ("algolia.net", "Algolia", API),
    ("algolianet.com", "Algolia", API),
    ("onesignal.com", "OneSignal", SDK),
    ("sentry.io", "Sentry", SDK),
    ("branch.io", "Branch", SDK),
    ("app.link", "Branch", SDK),
    ("appsflyer.com", "AppsFlyer", SDK),
    ("adjust.com", "Adjust", SDK),
    ("revenuecat.com", "RevenueCat", API),
    ("mixpanel.com", "Mixpanel", SDK),
    ("amplitude.com", "Amplitude", SDK),
    ("segment.io", "Segment", SDK),
    ("pusher.com", "Pusher", API),
    ("ably.io", "Ably", API),
    ("agora.io", "Agora", API),
    ("cloudinary.com", "Cloudinary", API),
    ("api.github.com", "GitHub API", API),
    ("githubusercontent.com", "GitHub", API),
    ("github.com", "GitHub", API),
    ("hooks.slack.com", "Slack webhook", WEBHOOK),
    ("webhook.office.com", "Microsoft Teams webhook", WEBHOOK),
    ("slack.com", "Slack API", API),
    ("discord.com", "Discord", API),
    ("discordapp.com", "Discord", API),
    ("api.telegram.org", "Telegram Bot API", API),
    ("ngrok.io", "ngrok tunnel", TUNNEL),
    ("ngrok-free.app", "ngrok tunnel", TUNNEL),
    ("ngrok.app", "ngrok tunnel", TUNNEL),
    ("ngrok-free.dev", "ngrok tunnel", TUNNEL),
    ("ngrok.dev", "ngrok tunnel", TUNNEL),
    ("loca.lt", "localtunnel", TUNNEL),
    ("trycloudflare.com", "Cloudflare quick tunnel", TUNNEL),
    ("serveo.net", "Serveo tunnel", TUNNEL),
    ("lhr.life", "localhost.run tunnel", TUNNEL),
    ("webhook.site", "webhook.site (request catcher)", TUNNEL),
    ("requestbin.com", "RequestBin (request catcher)", TUNNEL),
    ("pipedream.net", "Pipedream (request catcher)", TUNNEL),
    ("apple.com", "Apple", SDK),
)
# pages for people, not APIs: documentation, issue trackers, consoles and link shorteners
_DOC_HOSTS = frozenset({
    "developer.android.com", "developers.google.com", "firebase.google.com",
    "support.google.com", "issuetracker.google.com", "source.android.com", "cloud.google.com",
    "console.firebase.google.com", "console.cloud.google.com", "docs.oracle.com",
    "kotlinlang.org", "stackoverflow.com", "goo.gl", "g.co", "developer.apple.com",
    "help.apple.com", "docs.microsoft.com", "learn.microsoft.com", "material.io",
    "m3.material.io", "fonts.google.com", "developer.mozilla.org", "en.wikipedia.org",
    "semver.org", "spdx.org", "www.android.com", "android.googlesource.com",
    "chromium.googlesource.com", "bugs.chromium.org", "crbug.com", "dartbug.com",
    "play.google.com", "policies.google.com", "www.google.com", "maven.google.com",
    "dl.google.com", "jcenter.bintray.com", "repo.maven.apache.org", "plugins.gradle.org",
    "docs.gradle.org", "gradle.org", "square.github.io", "reactivex.io", "jakewharton.com",
    "www.jetbrains.com", "youtrack.jetbrains.com", "kotl.in", "d.android.com", "g.dev"})
# github.com pages about code (issues, sources, releases) rather than an API or a download
_CODE_PAGE = re.compile(r"(?i)^https?://(?:www\.)?github\.com/[^/]+/[^/]+"
                        r"(?:/(?:issues|pull|blob|tree|wiki|releases|commit|discussions)\b|/?$|#)")
_OAUTH_SCOPE = re.compile(r"(?i)^https?://www\.googleapis\.com/auth/")

# words in a host name that mark a server for development or testing
_DEV_WORDS = frozenset({"dev", "develop", "development", "staging", "stage", "stg", "test",
                        "testing", "qa", "uat", "sandbox", "preprod", "debug", "local",
                        "internal"})
# a text of compiled code that is only a host name (Uri.https('api.example.com', '/v1')
# keeps the host as a text of its own): its last label must be a common top-level domain,
# and it must not be a reversed package name (com.example.app) or a file name
_BARE_HOST = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                        r"(?P<tld>[a-z]{2,24})$")
_HOST_TLDS = frozenset({
    "com", "net", "org", "io", "app", "dev", "co", "ai", "cloud", "me", "info", "biz", "xyz",
    "tech", "online", "site", "store", "shop", "page", "example", "test", "sa", "iq",
    "ae", "eg", "jo", "kw", "qa", "om", "bh", "ly", "ma", "dz", "tn", "sy", "lb", "ps", "ye",
    "sd", "tr", "ir", "pk", "in", "de", "uk", "fr", "ru", "cn", "jp", "kr", "br", "us", "ca",
    "au", "nl", "it", "es", "se", "ch", "pl", "eu", "id", "my", "sg", "ng", "za", "ke"})
# top-level domains that are also common identifier words (user.id, settings.info, home.page):
# a text of two labels only counts as a host with one of the other domains
_WORD_TLDS = frozenset({"id", "info", "page", "store", "shop", "in"})
_PACKAGE_PREFIX = re.compile(r"^(?:com|org|net|io|dev|app|androidx?|java|javax|kotlin|kotlinx|dart"
                             r"|flutter|google|android|sun|jdk|okhttp3|okio|retrofit2|me|co"
                             r"|edu|gov)\.")
# a reversed package name that starts with a country code and a registry word:
# sa.gov.absher.app, id.co.bank.app, ae.gov.dubai.app (not ws.example.com or js.stripe.com)
_COUNTRY_PACKAGE = re.compile(r"^[a-z]{2}\.(?:gov|com|co|org|net|edu|ac|mil)\.[a-z0-9-]+")
# query parameters that carry a key or a token, and the value given to them
_SECRET_QUERY = re.compile(
    r"(?i)([?&](?:api[_-]?key|apikey|key|access[_-]?token|token|auth[_-]?token|auth"
    r"|secret|client[_-]?secret|password|passwd|pwd|sig|signature|session[_-]?id|jwt)=)"
    r"([^&#\s]*)")
_QUERY_PLACEHOLDER = re.compile(
    r"(?:\$[\w.]+|\$?\{[\w.]+\}|\{\{[\w.]+\}\}|<[\w.]+>|:[\w.]+|"
    r"%(?:\d+\$)?[sdf]|%\([\w.]+\)[sdf]|\*+)")
# Unlike the legacy security-check matcher, the inventory preserves interpolation
# placeholders. These are address templates, never a claim of an actual request.
_INVENTORY_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>\\^`|]+")
_ADDRESS_PLACEHOLDER = re.compile(
    r"\$\{[A-Za-z_][\w.]*\}|\{[A-Za-z_][\w.-]*\}|\$[A-Za-z_]\w*"
    r"|%(?:\d+\$)?[sdf]|%\([\w.]+\)[sdf]")
_URL_PASSWORD = re.compile(r"(?i)^([a-z][a-z0-9+.-]*://[^/@\s:]*:)([^/@\s]+)@")
_TELEGRAM = re.compile(r"(?i)(api\.telegram\.org/bot)(\d{5,}:[A-Za-z0-9_-]{20,})")
# the token is the last segment of the path (an address already masked keeps its other
# segments as they are)
_SLACK_HOOK = re.compile(r"(?i)(hooks\.slack\.com/(?:services|workflows|triggers)/(?:[^/\s]+/)+)"
                         r"([A-Za-z0-9]{8,})(?=$|[?#\s'\"])")
_DISCORD_HOOK = re.compile(r"(?i)(discord(?:app)?\.com/api/webhooks/\d+/)([A-Za-z0-9_-]{20,})"
                           r"(?=$|[/?#\s'\"])")
_TEAMS_HOOK = re.compile(r"(?i)(webhook\.office\.com/webhookb2/)([^\s]+)")

# API paths: a path made of URL characters with a segment that marks an API, a server
# script, or a query with a parameter
_PATH = re.compile(r"[\w.~%{}$:@+,;=/-]+(?:\?[\w.~%{}$:@+,;=&/-]*)?")
_API_MARKER = re.compile(
    r"(?i)(?:^|/)(?:api|apis|rest|graphql|gql|rpc|oauth2?|webhooks?|wp-json|v\d{1,2}"
    r"(?:\.\d{1,2})?)(?:/|$|\?)|\.(?:php|aspx?|jsp|do|cgi|json)(?:$|\?)|\?[\w.-]+=")
_NOT_API_PATH = re.compile(r"(?i)^/(?:data|system|proc|sdcard|storage|dev|etc|usr|sys|vendor"
                           r"|mnt|tmp|bin|sbin|apex|odm|product|cache|var|lib|opt|Library"
                           r"|Users|private|Applications)/")
_STRING_LITERAL = re.compile(r"""(['"])((?:\$\{?[A-Za-z_][\w.]*\}?)?(?:/|api/)[^'"\s]{1,200})\1""")

# calls of an HTTP client in Dart (http, dio, HttpClient, chopper, retrofit ...)
# the words of a receiver name that make it an HTTP client (_dio, apiClient, HttpClient,
# ApiService, _restClient): whole words of camelCase or snake_case, so that audioCache,
# restaurantBox and observer do not count
_CLIENT_WORDS = frozenset({"http", "https", "dio", "client", "api", "rest", "graphql", "gql",
                           "chopper", "backend", "server", "network", "service", "session",
                           "request", "requests", "retrofit", "remote"})
_NAME_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_FUEL_RECEIVER = re.compile(r"(?:^|\.)Fuel(?:\.INSTANCE)?\Z")
_DART_CALL = re.compile(
    r"(?P<recv>\b[A-Za-z_$][\w$]*(?:\(\s*\))?(?:\s*\.\s*[A-Za-z_$][\w$]*(?:\(\s*\))?)*)\s*\.\s*"
    r"(?P<method>get|post|put|patch|delete|head|request|send|download|fetch|getUri|postUri"
    r"|putUri|patchUri|deleteUri|headUri|requestUri|read|readBytes|getUrl|postUrl|putUrl"
    r"|patchUrl|deleteUrl|headUrl|openUrl|query|mutate|subscribe)\s*"
    r"(?:<(?:[^<>()]|<(?:[^<>()]|<[^<>()]*>)*>)*>)?\s*\(")
_URI_CALL = re.compile(r"\bUri\s*\.\s*(https?)\s*\(\s*(['\"])([^'\"$\\\s/?#]+)\2\s*,"
                       r"\s*(['\"])([^'\"$\\\s%?#]*)\4\s*\)")
_URI_CONSTRUCTOR = re.compile(r"Uri\s*\.\s*(https?)\s*\(")
_SOCKET = re.compile(r"\b(?:IO|Html)?WebSocketChannel\s*\.\s*connect\s*\(|\bWebSocket\s*\."
                     r"\s*connect\s*\(|\bio\s*\(\s*['\"]|\bIO\s*\.\s*io\s*\(")
_GRAPHQL = re.compile(r"\b(?:HttpLink|WebSocketLink|GraphQLClient)\s*\(")
_ANNOTATION = re.compile(r"@(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Get|Post|Put|Patch"
                         r"|Delete|Head|Options)\s*\(\s*(?:path\s*[:=]\s*|value\s*=\s*)?(['\"])"
                         r"(?P<path>[^'\"]*)\2(?=\s*[,)]|\s*$)")
_BASE_URL = re.compile(r"\bbase_?Url\s*(?::|=>|=(?![=>])|\()\s*", re.IGNORECASE)
_JAVA_CALL = re.compile(r"\.\s*url\s*\(|\bnew\s+URL\s*\(|(?<![\w.])URL\s*\((?=\s*\")|\bfetch\s*\("
                        r"|\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(")
# a quoted literal: an escape pair or any other character than the quote and the backslash
# (the two branches never match the same text, so a literal that does not close fails fast)
_FIRST_LITERAL = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\]){0,300})\1""")
_FULL_FIRST_LITERAL = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\])*)\1""")
_METHOD = {"getUrl": "GET", "postUrl": "POST", "putUrl": "PUT", "patchUrl": "PATCH",
           "deleteUrl": "DELETE", "headUrl": "HEAD", "openUrl": "OPEN", "getUri": "GET",
           "postUri": "POST", "putUri": "PUT", "patchUri": "PATCH", "deleteUri": "DELETE",
           "headUri": "HEAD", "requestUri": "REQUEST", "download": "GET", "fetch": "GET",
           "read": "GET", "readBytes": "GET", "query": "GRAPHQL", "mutate": "GRAPHQL",
           "subscribe": "GRAPHQL"}
CODE_LANGUAGES = ("dart", "java", "kotlin", "javascript", "typescript", "swift")

# service identifiers: (pattern, label, service)
_ID_PATTERNS: Tuple[Tuple[re.Pattern, str, str], ...] = tuple(
    (re.compile(pattern), label, service) for pattern, label, service in (
        (r"\b1:\d{6,15}:(?:android|ios|web):[0-9a-f]{6,40}\b", "Firebase app ID", "Firebase"),
        (r"\b\d{6,}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b", "Google OAuth client ID",
         "Google Sign-In"),
        (r"\bca-app-pub-\d{16}~\d{10}\b", "AdMob app ID", "Google AdMob"),
        (r"\bca-app-pub-\d{16}/\d{10}\b", "AdMob ad unit ID", "Google AdMob"),
        (r"\b[a-z0-9][a-z0-9-]{2,60}\.(?:appspot\.com|firebasestorage\.app)\b",
         "Storage bucket", "Firebase Storage"),
        (r"\b[a-z0-9][a-z0-9-]{2,60}\.firebaseapp\.com\b", "Firebase auth domain",
         "Firebase Authentication"),
        (r"\bhttps://[a-z0-9-]+\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)\b",
         "Realtime Database URL", "Firebase Realtime Database"),
        (r"\bhttps://[a-z0-9]{20}\.supabase\.co\b", "Supabase project URL", "Supabase"),
        (r"\bpk_(?:live|test)_[0-9A-Za-z]{20,}\b", "Stripe publishable key", "Stripe"),
        (r"\bpk\.eyJ[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{10,}\b", "Mapbox public token",
         "Mapbox"),
        (r"\bhttps://[0-9a-f]{32}@[a-z0-9.-]*sentry\.io/\d+\b", "Sentry DSN", "Sentry"),
        (r"\bG-[A-Z0-9]{8,12}\b(?=.*(?:measurement|analytics|gtag))", "Analytics measurement ID",
         "Google Analytics")))
_ID_HINTS = ("1:", "googleusercontent", "ca-app-pub", "appspot", "firebasestorage",
             "firebaseapp", "firebaseio", "firebasedatabase", "supabase", "pk_", "pk.eyJ",
             "sentry", "G-")
# named entries of configuration files (lower-case name -> label, service, secret)
CONFIG_NAMES: Dict[str, Tuple[str, str, bool]] = {
    "com_braze_api_key": ("Braze SDK app identifier", "Braze", False),
    "com_appboy_api_key": ("Braze SDK app identifier", "Braze", False),
    "google_app_id": ("Firebase app ID", "Firebase", False),
    "mobilesdk_app_id": ("Firebase app ID", "Firebase", False),
    "gcm_defaultsenderid": ("Firebase sender ID", "Firebase Cloud Messaging", False),
    "gcm_sender_id": ("Firebase sender ID", "Firebase Cloud Messaging", False),
    "messagingsenderid": ("Firebase sender ID", "Firebase Cloud Messaging", False),
    "project_number": ("Firebase sender ID", "Firebase Cloud Messaging", False),
    "project_id": ("Firebase project ID", "Firebase", False),
    "projectid": ("Firebase project ID", "Firebase", False),
    "google_storage_bucket": ("Storage bucket", "Firebase Storage", False),
    "storage_bucket": ("Storage bucket", "Firebase Storage", False),
    "storagebucket": ("Storage bucket", "Firebase Storage", False),
    "firebase_database_url": ("Realtime Database URL", "Firebase Realtime Database", False),
    "database_url": ("Realtime Database URL", "Firebase Realtime Database", False),
    "databaseurl": ("Realtime Database URL", "Firebase Realtime Database", False),
    "firebase_url": ("Realtime Database URL", "Firebase Realtime Database", False),
    "authdomain": ("Firebase auth domain", "Firebase Authentication", False),
    "measurementid": ("Analytics measurement ID", "Google Analytics", False),
    "default_web_client_id": ("Google OAuth client ID", "Google Sign-In", False),
    "androidclientid": ("Google OAuth client ID", "Google Sign-In", False),
    "iosclientid": ("Google OAuth client ID", "Google Sign-In", False),
    "reversed_client_id": ("Google OAuth client ID (reversed)", "Google Sign-In", False),
    "iosbundleid": ("iOS bundle ID", "Apple", False),
    "bundle_id": ("iOS bundle ID", "Apple", False),
    "facebook_app_id": ("Facebook app ID", "Facebook", False),
    "com.facebook.sdk.applicationid": ("Facebook app ID", "Facebook", False),
    "facebook_client_token": ("Facebook client token", "Facebook", True),
    "com.facebook.sdk.clienttoken": ("Facebook client token", "Facebook", True),
    "com.google.android.gms.ads.application_id": ("AdMob app ID", "Google AdMob", False),
    "io.sentry.dsn": ("Sentry DSN", "Sentry", False),
    "onesignal_app_id": ("OneSignal app ID", "OneSignal", False),
    "onesignalappid": ("OneSignal app ID", "OneSignal", False),
    "supabaseurl": ("Supabase project URL", "Supabase", False),
    "supabase_url": ("Supabase project URL", "Supabase", False),
    "com.google.android.geo.api_key": ("Google Maps API key", "Google Maps", True),
    "com.google.android.maps.v2.api_key": ("Google Maps API key", "Google Maps", True),
    "io.branch.sdk.branchkey": ("Branch key", "Branch", True),
}
_NAMED = re.compile(r"""<string\b[^>]*\bname\s*=\s*["'](?P<xml>[\w.]+)["'][^>]*>(?P<xmlv>[^<]+)</string\s*>"""
                    r"""|(?<![\w.'"])(?P<namequote>["']?)(?P<key>[A-Za-z_][\w.]*)(?P=namequote)\s*[:=]\s*"""
                    r"""(?P<valuequote>["'])(?P<val>(?:\\.|(?!(?P=valuequote))[^\\\n])+)(?P=valuequote)""")
_PLIST_KEY = re.compile(r"<key>\s*([\w.]+)\s*</key>")
_PLIST_STRING = re.compile(r"<string>([^<]{1,300})</string>")
_ENV_FILE = re.compile(r"(?i)(?:^|/)(?:\.env(?:\.[\w.-]+)?|[\w.-]+\.env)$")
_ENV_EXAMPLE = re.compile(r"(?i)\.(?:example|sample|template|dist|defaults?|schema)$")
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*?)\s*$")
_SECRET_NAME = re.compile(r"(?i)key|secret|token|passw|passphrase|(?:^|[_.])pass(?:$|[_.])|pwd"
                          r"|auth|credential|private|signature|salt|cert|hmac")
_PLACEHOLDER_VALUE = re.compile(r"(?i)^(?:|<.*>|\$\{.*\}|\{\{.*\}\}|x+|\*+|changeme|todo|your[_ -].*"
                                r"|example.*|placeholder.*|null|none|false|true)$")
_CONFIG_CREDENTIAL_NAME = re.compile(
    r"(?:^|_)(?:api_key|apikey|api_token|access_token|auth_token|client_secret|secret_key|"
    r"private_key|password|passwd|passphrase|token|secret|credential)$")
_CONFIG_UI_NAME = re.compile(
    r"(?:^|_)(?:hint|title|label|message|msg|error|invalid|expired|prompt|toggle|description|"
    r"confirm|enter|empty|forgot|change|reset|repeat|retype|missing|length|format|"
    r"activity|dictionary|uppercase|lowercase|number|special|whitespace|notification|"
    r"placeholder|enabled|disabled|type|field|path|resource)(?:_|$)")
_SERVER_CREDENTIAL_NAME = re.compile(r"(?:^|_)(?:rest|post|server|admin|management|private|secret)(?:_|$)")

# kinds of findings that point to a key, a token or a password
KEY_CWES = frozenset({"CWE-798", "CWE-321", "CWE-259", "CWE-260", "CWE-547"})
# (pattern on the rule id and title, service)
_KEY_SERVICES: Tuple[Tuple[re.Pattern, str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), service) for pattern, service in (
        (r"(?<![a-z0-9])aws(?![a-z0-9])|amazon|(?<![a-z0-9])akia", "Amazon Web Services"),
        (r"firebase", "Firebase"), (r"google|gcp|(?<![a-z0-9])aiza", "Google"),
        (r"stripe", "Stripe"), (r"github", "GitHub"), (r"gitlab", "GitLab"),
        (r"slack", "Slack"), (r"twilio", "Twilio"), (r"sendgrid", "SendGrid"),
        (r"mailgun", "Mailgun"), (r"openai", "OpenAI"), (r"anthropic", "Anthropic"),
        (r"supabase", "Supabase"), (r"facebook", "Facebook"), (r"twitter", "X (Twitter)"),
        (r"discord", "Discord"), (r"telegram", "Telegram"), (r"mapbox", "Mapbox"),
        (r"teams|webhook\.office", "Microsoft Teams"),
        (r"algolia", "Algolia"), (r"sentry", "Sentry"), (r"heroku", "Heroku"),
        (r"azure", "Microsoft Azure"), (r"shopify", "Shopify"), (r"square", "Square"),
        (r"paypal|braintree", "PayPal"), (r"flutterwave", "Flutterwave"),
        (r"private key", "Private key"),
        (r"keystore|key\.properties|store ?password|key ?password|signing ?config|upload key",
         "App signing"),
        (r"encryption|cipher|crypto|(?<![a-z0-9])(?:aes|iv)(?![a-z0-9])", "Encryption"),
        (r"json web token|(?<![a-z0-9])jwt(?![a-z0-9])", "JSON Web Token"),
        (r"passw|pwd|basic", "Password")))
ADVICE = {
    "generic": "Revoke this key and issue a new one; keep it on a server that the app calls, "
               "never in the app.",
    "google": "Restrict the key in the Google Cloud console: allow only this app (package name "
              "and SHA-1 certificate fingerprint) and only the APIs it needs.",
    "firebase": "A Firebase configuration value identifies the project and is not a secret: "
                "restrict the API key and protect the data with Firebase Security Rules and "
                "App Check.",
    "public": "A publishable or public key is meant to ship in apps: nothing to rotate, but "
              "check that it cannot do more than intended.",
    "public_fixture": FIXTURE_ADVICE,
    "stripe": "A Stripe secret key must never be in an app: roll it in the Stripe dashboard; "
              "the app may only hold the publishable key (pk_) and payments are created on the "
              "server.",
    "aws": "Deactivate the access key in AWS IAM; give the app short-lived credentials through "
           "Amazon Cognito or a backend instead.",
    "webhook": "Delete the webhook or revoke the bot token and create a new one; let a server "
               "post the messages, so that the app never holds the address.",
    "jwt": "A token built into the app is the same for every user: revoke it and let each "
           "user get their own token when they sign in.",
    "service_role": "Rotate the Supabase service_role key at once; the app may only hold the "
                    "anon key, with Row Level Security on every table.",
    "private_key": "Remove the private key from the app and replace the key pair: whoever has "
                   "it can act as its owner.",
    "password": "Remove the password from the app and change it; let users or a server "
                "provide credentials.",
    "crypto": "An encryption key inside the app protects nothing, because anyone can read it: "
              "generate the key on the device and keep it in Android Keystore / iOS Keychain "
              "(flutter_secure_storage).",
    "signing": "Keep signing passwords out of the code: read them from environment variables "
               "or from a key.properties file that is not committed.",
}
# the English texts of the alerts; the dashboard translates them (sca/ui/i18n.py)
ALERTS = {
    "keys_in_app": "The app package holds %s secret keys, tokens or passwords. Anyone who "
                   "downloads the app can extract them: revoke them and keep them on a server.",
    "keys_in_source": "The code holds %s secret keys, tokens or passwords. They go into every "
                      "build of the app: revoke them and keep them on a server.",
    "key": "%s (%s) at %s.",
    "service_role": "Supabase service_role key at %s: it bypasses Row Level Security and gives "
                    "full access to the database.",
    "cleartext": "%s server addresses use unencrypted http:// or ws://, for example %s: data "
                 "and tokens sent to them can be read and changed on the network.",
    "tunnel": "Temporary tunnel or request-catcher address %s (%s): a developer's computer or "
              "a test service, reachable from the internet.",
    "webhook": "Webhook address %s: whoever extracts the full address can post messages in "
               "the name of the app.",
    "telegram": "Telegram bot token in the address %s: whoever extracts it controls the bot.",
    "secret_in_url": "A key or token is part of the address %s (at %s). Addresses are kept in "
                     "server logs, proxies and history: send it in a header instead.",
    "password_in_url": "A user name and password are part of the address %s.",
    "dev_host": "Development, test or sandbox server in the app: %s.",
    "private_ip": "Private network address %s: only reachable inside a local network, "
                  "usually a leftover of development.",
    "ip_host": "Server addressed by its IP address: %s. A TLS certificate rarely matches an IP "
               "address, which invites turning certificate checks off.",
    "firebase_db": "Firebase Realtime Database %s: make sure its security rules do not allow "
                   "public reading or writing (anyone can request %s/.json).",
    "storage_bucket": "Storage bucket %s: make sure its security rules do not allow public "
                      "listing, reading or writing.",
    "supabase": "Supabase project %s: every table needs Row Level Security, because the key "
                "in the app can call the database API directly.",
    "s3": "Amazon S3 bucket %s: make sure the bucket policy does not allow public listing or "
          "writing.",
    "env_file": "The .env file %s is inside the app package with %s entries: every value in "
                "it can be read by anyone who has the app.",
    "env_asset": "The .env file %s holds %s entries; if it is listed under assets in "
                 "pubspec.yaml (flutter_dotenv), it is copied into the app package as it is.",
    "debug_build": "Debug build: the complete Dart source code is inside the package (%s "
                   "files), with every address and key in it.",
    "strings_visible": "The scan recovered %s text strings from compiled Dart code in libapp.so. "
                       "These observed strings can contain addresses and keys; encrypted or "
                       "runtime-generated values may not be present.",
    "services": "Addresses associated with %s services were found: %s. Runtime use was not verified.",
}


def build(ctx: Optional[MobileContext], files: Sequence[SourceFile],
          findings: Sequence[Finding], *, reveal_values: bool = False) -> Dict[str, Any]:
    """The inventory of an app or project: every server address, API call, API path, key,
    service identifier and .env entry in `files`, and the alerts about them. `findings` are
    the findings of the scan; the keys are taken from those that point to a credential.
    `reveal_values` retains complete observed values for the interactive scan session;
    the default keeps the existing masked report representation."""
    return _Inventory(ctx, files, findings, reveal_values=reveal_values).run()


# ------------------------------------------------------------------ helpers
def _short(text: str, limit: int = MAX_TEXT) -> str:
    text = strip_bidi(str(text)).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[:limit - 3] + "..."


def place(location: Mapping[str, Any]) -> str:
    """"file:line" of a location."""
    line = location.get("line")
    return "%s:%s" % (location.get("file", ""), line) if line else str(location.get("file", ""))


def service_of(host: str, path: str = "") -> Tuple[str, str]:
    """(service, category) of a host; the app's own server when no known service matches."""
    host = host.lower().rstrip(".")
    if _ip(host) is not None:
        return "IP address", APP
    if host.endswith("amazonaws.com"):        # regional names: <id>.<service>.<region>....
        if ".execute-api." in host:
            return "AWS API Gateway", BACKEND
        if host.startswith(("cognito-idp.", "cognito-identity.")):
            return "Amazon Cognito", BACKEND
        if ".s3." in "." + host or host.startswith(("s3.", "s3-")) or ".s3-" in host:
            return "Amazon S3", BACKEND
    if host in ("discord.com", "discordapp.com") and path.startswith("/api/webhooks/"):
        return "Discord webhook", WEBHOOK
    for suffix, service, category in SERVICES:
        if host == suffix or host.endswith("." + suffix):
            return service, category
    return "", APP


def _ip(host: str) -> Optional[Any]:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _local_host(host: str) -> bool:
    address = _ip(host)
    return (host in LOOPBACK_HOSTS or host.endswith(".localhost")
            or bool(address and address.is_loopback))


def _local_endpoint(raw: str) -> Optional[Tuple[str, bool]]:
    """Retain local literals as inventory evidence, without classifying a vulnerability."""
    url = raw.rstrip(".,;:)]!?*")
    bracketed = raw.rstrip(".,;:)}!?*")
    if re.fullmatch(r"(?i)(?:https?|wss?)://\[[0-9a-f:]+\]", bracketed):
        url = bracketed
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if parts.scheme.lower() in ("http", "https", "ws", "wss") and _local_host(host):
        return url, parts.scheme.lower() in ("http", "ws")
    return None


def _inventory_address(raw: str) -> Optional[Tuple[str, bool, bool]]:
    """Complete literal, cleartext flag and unresolved-template flag.

    Preserve balanced brackets in IPv6 and placeholders rather than cutting at
    their first brace. A substituted copy is used only to validate the address
    syntax; the substitution is never emitted as evidence or a resolved host.
    """
    value = raw.rstrip(".,;:!?")
    closing = {")": "(", "]": "[", "}": "{"}
    while value and value[-1] in closing and value.count(value[-1]) > value.count(closing[value[-1]]):
        value = value[:-1]
    value = value.rstrip(".,;:!?")
    # A trailing Dart '$' is an unfinished interpolation rather than host/path data.
    value = value.rstrip("$")
    template = bool(_ADDRESS_PLACEHOLDER.search(value))
    probe = _ADDRESS_PLACEHOLDER.sub("runtime", value)
    try:
        parsed = urlsplit(probe)
        raw_authority = urlsplit(value).netloc
        if ":" in raw_authority and _ADDRESS_PLACEHOLDER.fullmatch(raw_authority.rsplit(":", 1)[-1]):
            authority = parsed.netloc.rsplit(":", 1)[0] + ":1"
            probe = urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, parsed.fragment))
            parsed = urlsplit(probe)
        host = parsed.hostname or ""
        parsed.port  # Reject malformed ports, rather than displaying a different host.
    except ValueError:
        return None
    if not host or any(ch in probe for ch in "{}"):
        return None
    if _local_endpoint(probe) is not None:
        return value, parsed.scheme.lower() in ("http", "ws"), template
    # The legacy endpoint helper strips ']' as punctuation. Preserve bare IPv6
    # authorities by validating a temporary slash-terminated address.
    validation = probe + "/" if probe.endswith("]") else probe
    if _endpoint(validation) is None:
        return None
    return value, parsed.scheme.lower() in ("http", "ws"), template


def _dev_host(host: str) -> bool:
    """True when a label of the host, apart from the domain itself, names a development or
    test server: api-dev.example.com, staging2.example.com, sandbox.paypal.com."""
    labels = host.lower().split(".")
    for label in labels[:-2]:
        for word in re.split(r"[-_]", label):
            if word.rstrip("0123456789") in _DEV_WORDS:
                return True
    return False


def _maskable(value: str) -> bool:
    return len(value) >= 4 and not _QUERY_PLACEHOLDER.fullmatch(value)


def _env_value(raw: str) -> str:
    """Keep hashes inside quoted values; strip only comments outside the value.

    Escapes remain in their original representation so the preview has an exact
    source span. Unclosed quotes are retained rather than manufacturing a value.
    """
    value = raw.strip()
    if value[:1] in ("'", '"'):
        quote, index = value[0], 1
        while index < len(value):
            if value[index] == "\\":
                index += 2
                continue
            if value[index] == quote:
                tail = value[index + 1:].strip()
                if not tail or tail.startswith("#"):
                    return value[1:index]
                return value
            index += 1
        return value
    return re.sub(r"\s+#.*$", "", value)


def _has_literal_query_value(url: str) -> bool:
    """A credential parameter with a literal value, not an empty runtime template."""
    return any(match[2] and not _QUERY_PLACEHOLDER.fullmatch(match[2])
               for match in _SECRET_QUERY.finditer(url))


def _mask_query_parameter(match: re.Match) -> str:
    name, value = match.groups()
    if not value or _QUERY_PLACEHOLDER.fullmatch(value):
        return name + value
    return name + (mask_secret(value) if len(value) > 1 else "*")


def mask_url(url: str) -> str:
    """The URL with the secrets that addresses carry masked: the password of user:password@,
    the values of key and token parameters, bot tokens and webhook tokens."""
    url = _URL_PASSWORD.sub(lambda m: m.group(1) + mask_secret(m.group(2)) + "@", url)
    url = _SECRET_QUERY.sub(_mask_query_parameter, url)
    for pattern in (_TELEGRAM, _SLACK_HOOK, _DISCORD_HOOK, _TEAMS_HOOK):
        url = pattern.sub(lambda m: m.group(1) + mask_secret(m.group(2)), url)
    return url


def jwt_claims(token: str) -> Dict[str, str]:
    """The harmless claims of a JSON Web Token (iss, role, ref, aud, iat, exp) for the
    inventory; {} when the text is not a token. The signature is not checked."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[1].startswith("eyJ") or len(parts[1]) > 4000:
        return {}
    try:
        data = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(data.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    claims: Dict[str, str] = {}
    for name in ("iss", "role", "ref", "aud"):
        if isinstance(payload.get(name), str):
            claims[name] = _short(payload[name], 60)
    for name in ("iat", "exp"):
        value = payload.get(name)
        if isinstance(value, (int, float)) and not isinstance(value, bool) \
                and 0 < value < 32503680000:
            claims[name] = datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
    return claims


def _is_code(sf: SourceFile) -> bool:
    return sf.origin != ORIGIN_STRINGS and sf.language in CODE_LANGUAGES


def _first_literal(text: str) -> str:
    match = _FIRST_LITERAL.search(text)
    return match.group(2) if match else ""


_BASE64_VALUE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}|[A-Za-z0-9_-]{8,}={0,2}")
# rules whose literal is the name of a value given at build time, not the value itself
NAME_RULES = frozenset({"DART-SECRET-002", "FLUTTER-BUILD-002"})
# a line that reads a value by its name: String.fromEnvironment('X'), dotenv.env['X'] ...
_LOOKUP = re.compile(r"\bfromEnvironment\s*\(|\bdotenv\s*\.\s*(?:env|get|maybeGet)\b|\bgetenv\s*\("
                     r"|\benviron(?:ment)?\s*[\[.(]|--dart-define|@EnviedField")


_DEFAULT_VALUE = re.compile(r"""\bdefaultValue\s*:\s*(['"])((?:\\.|(?!\1)[^\\]){1,300})\1""")
_DART_DEFINE = re.compile(r"""--dart-define[= ]+["']?[A-Za-z0-9_]+=([^\s"'$]{1,300})""")
_PASSWORD_SETTING = re.compile(r"""(?i)\b(?:store|key)_?password\b\s*[=:(]?\s*"""
                               r"""(?:(['"])((?:\\.|(?!\1)[^\\]){1,300})\1|([^\s'";)]+))""")


def rule_key_value(line: str, rule: str = "", pattern: Any = None) -> str:
    """The value that a credential finding of a rule or a structural check (not of the
    secrets engine) points to: the literal at or after the rule's own match (the first
    literal of the line when the rule's pattern is not given), the password of a Gradle or
    key.properties signing setting, or the value of a name=value line. For a line that reads
    a value by its name (String.fromEnvironment('X'), dotenv.env['X'], --dart-define) only
    the value written next to it counts (defaultValue: '...', --dart-define=NAME=value).
    "" for a path, an interpolation, a placeholder or a sentence. Base64 keys may hold / + =."""
    if rule in NAME_RULES or _LOOKUP.search(line):
        found = _DEFAULT_VALUE.search(line) or _DART_DEFINE.search(line)
        value = (found.group(2) if found.re is _DEFAULT_VALUE else found.group(1)) if found \
            else ""
    else:
        setting = _PASSWORD_SETTING.search(line)
        if setting:
            value = setting.group(2) or setting.group(3) or ""
        else:
            match = pattern.search(line) if pattern is not None else None
            value = _first_literal(line[max(0, match.start() - 1):]) if match else ""
            value = value or _first_literal(line)
        if not value:
            match = re.match(r"^\s*[\w.-]+\s*[=:]\s*(\S.*?)\s*$", line)
            value = match.group(1) if match else ""
    if len(value) < 6 or " " in value or "$" in value or _PLACEHOLDER_VALUE.match(value) \
            or ("/" in value and not _BASE64_VALUE.fullmatch(value)):
        return ""
    return value


def text_secrets(sf: SourceFile) -> List[str]:
    """The secrets that addresses and .env files hold in plain sight, which mask_url and the
    .env list of the inventory hide: values of key and token query parameters, passwords of
    user:password@, webhook and bot tokens, and the values of .env entries whose name says
    secret. The pipeline masks them in snippets and contexts too, so that the reports and the
    inventory agree."""
    out: List[str] = []
    for line in sf.lines:
        if "://" not in line:
            continue
        for match in _URL.finditer(line):
            url = match.group()
            out += [q.group(2) for q in _SECRET_QUERY.finditer(url) if _maskable(q.group(2))]
            password = _URL_PASSWORD.match(url)
            if password:
                out.append(password.group(2))
            for pattern in (_TELEGRAM, _SLACK_HOOK, _DISCORD_HOOK, _TEAMS_HOOK):
                out += [token.group(2) for token in pattern.finditer(url)]
    # the secret values of .env files are those of the secrets engine (secret_hits)
    return [value for value in dict.fromkeys(out) if value]


def strong_value(value: str) -> bool:
    """True for a value worth masking wherever it appears in the scan: 8 characters or
    more, not one plain word ('android', 'password') and not too regular. Shorter or plainer
    values of a rule are masked only where they were reported."""
    from ..engines.secrets import shannon_entropy

    return len(value) >= 8 and not re.fullmatch(r"[A-Za-z]+|\d+", value) \
        and shannon_entropy(value) >= 2.5


_quoted_value = rule_key_value


def client_like(receiver: str) -> bool:
    """True when the last name of a call's receiver names an HTTP client by a whole word:
    _dio, apiClient, HttpClient, ApiService, _restClient, http (not audioCache, restaurantBox,
    observer)."""
    last = re.sub(r"\(\)", "", receiver).rsplit(".", 1)[-1]
    return any(word.lower() in _CLIENT_WORDS for word in _NAME_WORDS.findall(last))


def _argument(text: str, *, complete: bool = False) -> str:
    """The first argument of a call whose arguments start in `text`: its first string
    literal when it starts with one, else the expression up to the first ',' or ')' that
    closes it."""
    stripped = text.lstrip()
    if stripped[:1] in ("'", '"'):
        if complete:
            literal = _FULL_FIRST_LITERAL.match(stripped)
            return literal.group(2) if literal else ""
        return _first_literal(stripped)
    depth, out = 0, []
    quote, escaped = "", False
    for ch in (stripped if complete else stripped[:200]):
        if complete and quote:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if complete and ch in ("'", '"'):
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        out.append(ch)
    return "".join(out).strip()


# ------------------------------------------------------------------ the inventory
class _Inventory:
    def __init__(self, ctx: Optional[MobileContext], files: Sequence[SourceFile],
                 findings: Sequence[Finding], *, reveal_values: bool = False) -> None:
        self.ctx = ctx
        self.reveal_values = reveal_values
        self.is_app = bool(ctx is not None and ctx.is_app)
        self.files = [sf for sf in files
                      if sf.origin not in (ORIGIN_SUMMARY, ORIGIN_PLACEHOLDER)
                      and (self.is_app or not is_test_path(sf.rel))]
        self.by_rel = {sf.rel: sf for sf in self.files}
        self.findings = findings
        # Texts are masked with the secrets of their file. In a scan these are every secret
        # of the scan (pipeline.share_secrets), so a key of strings.xml quoted by the strings
        # dump of libapp.so is masked there too, while a weak value stays in its own file.
        self.package = str((ctx.facts.get("package") if ctx is not None else "") or "")
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.paths: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Dict[str, Any]] = []
        self.keys: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.raw_keys: Dict[str, Dict[str, Any]] = {}      # secret -> key item (never stored)
        self.key_places: Dict[int, set] = {}                # id(key item) -> {(file, line)}
        self.config: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.env: List[Dict[str, Any]] = []
        self.env_files: Dict[str, int] = {}
        self.strings: Dict[str, str] = {}                  # string resources: name -> value
        self.string_places: Dict[str, Tuple[SourceFile, int]] = {}
        self.alerts: List[Dict[str, Any]] = []
        # distinct items left out once a list holds MAX_ITEMS * 3 (still counted)
        self.dropped: Dict[str, set] = {"endpoints": set(), "paths": set(), "config": set()}
        self.dropped_calls = 0
        self.dropped_hosts: set = set()
        self.context_lines_skipped = 0
        self.item_limit = MAX_VISIBLE_ITEMS if reveal_values else MAX_ITEMS
        self.collection_limit = MAX_VISIBLE_ITEMS if reveal_values else MAX_ITEMS * 3
        self.location_limit = MAX_VISIBLE_LOCATIONS if reveal_values else MAX_LOCATIONS

    def _text(self, sf: SourceFile, value: str) -> str:
        """A value for this output, without changing the source or detector inputs."""
        return strip_bidi(value) if self.reveal_values else mask_url(sf.mask(value))

    def _value(self, value: str, limit: int = MAX_TEXT) -> str:
        return strip_bidi(value) if self.reveal_values else _short(value, limit)

    def _secret(self, value: str) -> str:
        return strip_bidi(value) if self.reveal_values else mask_secret(value)

    def _full(self, name: str, store: Mapping, key: Any) -> bool:
        """True (and the item counted as left out) when the list `name` is full."""
        if len(store) < self.collection_limit:
            return False
        self.dropped[name].add(key)
        return True

    def run(self) -> Dict[str, Any]:
        for sf in self.files:
            self._file(sf)
        self._keys()
        self._manifest_entries()        # after the keys: it names the use of a manifest key
        endpoints = sorted(self.endpoints.values(), key=self._endpoint_order)
        hosts = self._hosts(endpoints)
        config = sorted(self.config.values(), key=lambda c: (c["service"], c["label"],
                                                             c["value"]))
        keys = sorted(self.keys.values(), key=self._key_order)
        paths = sorted(self.paths.values(), key=lambda p: (not p["alerts"], p["path"]))
        self._alerts(keys)
        totals = {"alerts": len(self.alerts), "keys": len(keys),
                  "endpoints": len(endpoints) + len(self.dropped["endpoints"]),
                  "hosts": len(hosts) + len(self.dropped_hosts - {h["host"] for h in hosts}),
                  "calls": len(self.calls) + self.dropped_calls,
                  "paths": len(paths) + len(self.dropped["paths"]),
                  "config": len(config) + len(self.dropped["config"]), "env": len(self.env)}
        out = {
            "summary": dict(
                endpoints=totals["endpoints"], hosts=totals["hosts"],
                cleartext=sum(1 for e in endpoints if e["cleartext"]),
                app_servers=sum(1 for h in hosts if h["category"] == APP),
                services=len({h["service"] for h in hosts if h["service"]}),
                calls=totals["calls"], paths=totals["paths"], config=totals["config"],
                env=totals["env"], **key_counts(keys),
                alerts={level: sum(1 for a in self.alerts if a["level"] == level)
                        for level in LEVELS}),
            "alerts": self.alerts[:self.item_limit if self.reveal_values else MAX_ALERTS],
            "keys": keys[:self.item_limit],
            "endpoints": endpoints[:self.item_limit],
            "hosts": hosts[:self.item_limit],
            "calls": self.calls[:self.item_limit],
            "paths": paths[:self.item_limit],
            "config": config[:self.item_limit],
            "env": self.env[:self.item_limit],
            "firebase": self._firebase(config, endpoints, keys),
            "is_app": self.is_app,
        }
        shown = {name: len(out[name]) for name in totals}
        truncated = {name: totals[name] - shown[name] for name in totals
                     if totals[name] > shown[name]}
        if truncated:
            out["truncated"] = truncated
        if self.reveal_values:
            out["values_visible"] = True
        if self.context_lines_skipped:
            out["coverage"] = {"context_lines_skipped": self.context_lines_skipped,
                               "max_context_line_characters": MAX_CONTEXT_LINE,
                               "literal_urls_scanned": True}
        return out

    # -------------------------------------------------------------- reading the files
    def _file(self, sf: SourceFile) -> None:
        code = _is_code(sf)
        strings = sf.origin == ORIGIN_STRINGS
        nested_uris: set = set()
        env = bool(_ENV_FILE.search(sf.rel)) and not _ENV_EXAMPLE.search(sf.rel)
        plist_key = ""
        for number, text in enumerate(sf.lines, 1):
            if not text.strip():
                continue
            if code and sf.is_comment(number):
                continue
            if "://" in text:
                self._urls(sf, number, text)
            if len(text) > MAX_CONTEXT_LINE:
                if code:
                    self.context_lines_skipped += 1
                continue
            annotations = list(_ANNOTATION.finditer(text)) if code and "@" in text else []
            if strings:
                self._dump_path(sf, number, text)
            elif annotations or "/" in text and ("'" in text or '"' in text):
                self._literal_paths(sf, number, text, annotations)
            if code:
                self._calls(sf, number, text, annotations, nested_uris)
            if any(hint in text for hint in _ID_HINTS):
                self._identifiers(sf, number, text)
            if not strings and (plist_key or "<key>" in text or "<string" in text
                                or ":" in text or "=" in text):
                plist_key = self._named(sf, number, text, plist_key)
            if env:
                self._env_line(sf, number, text)

    def _location(self, item: Dict[str, Any], sf: SourceFile, number: int) -> None:
        item["count"] += 1
        location = {"file": sf.rel, "line": number}
        if len(item["locations"]) < self.location_limit and location not in item["locations"]:
            item["locations"].append(location)

    def _key_location(self, item: Dict[str, Any], sf: SourceFile, number: int) -> None:
        """A place of a key, counted once however many findings point to it."""
        places = self.key_places.setdefault(id(item), set())
        if (sf.rel, number) not in places:
            places.add((sf.rel, number))
            self._location(item, sf, number)

    def _urls(self, sf: SourceFile, number: int, text: str) -> None:
        for match in _INVENTORY_URL.finditer(text):
            found = _inventory_address(match.group())
            if not found:
                continue
            url, cleartext, template = found
            if not self.reveal_values:
                url = url[:300]
            if _OAUTH_SCOPE.match(url) or _CODE_PAGE.match(url):
                continue
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            # Maps navigation URLs are application targets, unlike Google's home,
            # documentation or KML namespace URLs. Keep their full query/template.
            maps_navigation = (host == "www.google.com"
                               and (parts.path == "/maps" or parts.path.startswith("/maps/")))
            if host in _DOC_HOSTS and not maps_navigation:
                continue
            local = _local_host(host)
            raw, url = url, self._text(sf, url)
            item = self.endpoints.get(url)
            if item is None:
                if self._full("endpoints", self.endpoints, url):
                    self.dropped_hosts.add(host)
                    continue
                service, category = ("", LOCAL) if local else service_of(host, parts.path)
                try:
                    port = parts.port
                except ValueError:
                    port = None
                item = {"url": self._value(url), "host": host, "scheme": parts.scheme.lower(),
                        "port": port, "service": service, "category": category,
                        "cleartext": cleartext, "alerts": self._url_alerts(raw, host, category,
                                                                          cleartext),
                        "count": 0, "locations": []}
                if template:
                    item.update(evidence_kind="url_template", requires_runtime_resolution=True)
                self.endpoints[url] = item
            self._location(item, sf, number)

    @staticmethod
    def _url_alerts(url: str, host: str, category: str, cleartext: bool) -> List[str]:
        if category == LOCAL:
            return []
        alerts: List[str] = []
        if cleartext:
            alerts.append("cleartext")
        if category == TUNNEL:
            alerts.append("tunnel")
        if category == WEBHOOK or _DISCORD_HOOK.search(url) or _SLACK_HOOK.search(url):
            alerts.append("webhook")
        if _TELEGRAM.search(url):
            alerts.append("telegram")
        if _URL_PASSWORD.search(url):
            alerts.append("password_in_url")
        if _has_literal_query_value(url):
            alerts.append("secret_in_url")
        address = _ip(host)
        if address is not None:
            alerts.append("private_ip" if address.is_private else "ip_host")
        elif _dev_host(host):
            alerts.append("dev_host")
        return alerts

    def _add_path(self, sf: SourceFile, number: int, path: str, *, declared: bool = False) -> None:
        if len(path) > (MAX_CONTEXT_LINE if self.reveal_values else 200) or not _PATH.fullmatch(path) or "//" in path:
            return
        if not declared and (len(path) < 3 or not path.startswith(("/", "api/"))
                             or _NOT_API_PATH.match(path) or not _API_MARKER.search(path)):
            return
        literal_query = _has_literal_query_value(path)
        path = self._text(sf, path)
        item = self.paths.get(path)
        if item is None:
            if self._full("paths", self.paths, path):
                return
            item = {"path": self._value(path), "alerts": ["secret_in_url"]
                    if literal_query else [], "count": 0, "locations": []}
            self.paths[path] = item
        self._location(item, sf, number)

    def _dump_path(self, sf: SourceFile, number: int, text: str) -> None:
        text = text.strip()
        if text.startswith(("/", "api/")):
            self._add_path(sf, number, text)
        elif "." in text and len(text) <= 253:
            self._bare_host(sf, number, text)

    def _bare_host(self, sf: SourceFile, number: int, text: str) -> None:
        """A text of compiled code that is a host name and nothing else: listed as an
        address without a scheme (Uri.https keeps the host and the path apart)."""
        match = _BARE_HOST.match(text)
        if not match or match.group("tld") not in _HOST_TLDS or _PACKAGE_PREFIX.match(text) \
                or _COUNTRY_PACKAGE.match(text) or text in _DOC_HOSTS or text.count(".") > 6:
            return
        if text.count(".") == 1 and match.group("tld") in _WORD_TLDS:
            return                          # user.id, settings.info, home.page
        if self.package and (text == self.package or text.startswith(self.package + ".")):
            return                          # the app's own package name
        found = _endpoint("https://" + text)
        if not found:
            return
        item = self.endpoints.get(text)
        if item is None:
            if self._full("endpoints", self.endpoints, text):
                self.dropped_hosts.add(text)
                return
            service, category = service_of(text)
            item = {"url": text, "host": text, "scheme": "", "port": None, "service": service,
                    "category": category, "cleartext": False,
                    "alerts": self._url_alerts(text, text, category, False), "count": 0,
                    "locations": [], "host_only": True}
            self.endpoints[text] = item
        self._location(item, sf, number)

    def _literal_paths(self, sf: SourceFile, number: int, text: str, annotations: Sequence[re.Match]) -> None:
        declared_spans = {match.span("path") for match in annotations}
        for match in annotations:
            self._add_path(sf, number, match.group("path"), declared=True)
        for match in _STRING_LITERAL.finditer(text):
            if match.span(2) in declared_spans:
                continue
            value = match.group(2)
            if value.startswith("$"):        # '$baseUrl/api/login' -> /api/login
                value = value[value.index("/"):]
            self._add_path(sf, number, value)

    def _calls(self, sf: SourceFile, number: int, text: str, annotations: Sequence[re.Match],
               nested_uris: set) -> None:
        found: List[Tuple[str, str, str, int]] = []

        def argument(method: str, kind: str, start: int) -> None:
            target, target_line = self._call_argument(sf, number, start, nested_uris,
                                                      complete=self.reveal_values)
            found.append((method, target, kind, target_line))
        for match in _DART_CALL.finditer(text):
            receiver = re.sub(r"\s+|\(\)", "", match.group("recv"))
            method = match.group("method")
            last = receiver.rsplit(".", 1)[-1]
            native_fuel = sf.language in ("java", "kotlin") and _FUEL_RECEIVER.search(receiver)
            if not (client_like(receiver) or native_fuel):
                continue
            if method in ("read", "readBytes") and last.lstrip("_") != "http":
                continue                    # storage.read(...) is not a request
            if method in ("query", "mutate", "subscribe") and "graphql" not in receiver.lower() \
                    and "client" not in last.lower():
                continue
            argument(_METHOD.get(method, method.upper()), "http", match.end())
        for socket in _SOCKET.finditer(text):
            # io('wss://...') ends the match on the quote.
            start = socket.end() - 1 if socket.group().endswith(("'", '"')) else socket.end()
            argument("WS", "websocket", start)
        for match in _GRAPHQL.finditer(text):
            argument("GRAPHQL", "graphql", match.end())
        for match in annotations:
            found.append((match.group("method").upper(), match.group("path"), "annotation", number))
        for match in _BASE_URL.finditer(text):
            argument("BASE", "base_url", match.end())
        if sf.language != "dart":
            for match in _JAVA_CALL.finditer(text):
                argument("", "http", match.end())
        for match in _URI_CALL.finditer(text):
            site = (number, match.start())
            if site in nested_uris:
                nested_uris.remove(site)
            else:
                found.append(("", self._uri_target(match), "uri", number))
        seen = set()
        for method, target, kind, target_line in found:
            target = self._value(self._text(sf, target.strip()), 200)
            if not target or (method, target) in seen:
                continue
            seen.add((method, target))
            if len(self.calls) >= self.collection_limit:
                self.dropped_calls += 1
                continue
            item = {"method": method or "-", "target": target, "kind": kind,
                    "file": sf.rel, "line": number}
            if target_line != number:
                item["target_line"] = target_line
            self.calls.append(item)

    @staticmethod
    def _uri_target(match: re.Match) -> str:
        path = match.group(5)
        if path and not path.startswith("/"):
            path = "/" + path
        return f"{match.group(1)}://{match.group(3)}{path}"

    @staticmethod
    def _call_argument(sf: SourceFile, number: int, start: int, nested_uris: set, *,
                       complete: bool = False) -> Tuple[str, int]:
        """The first argument of a call whose arguments start in `rest`, read on into the
        next lines when it continues there (http.post(<newline> Uri.parse('https://...'),
        ...)); the URL itself when the argument only wraps a literal address."""
        rest = sf.lines[number - 1][start:]
        argument = _argument(rest, complete=complete)
        if not argument or argument.count("(") > argument.count(")"):
            rest = "\n".join([rest, *sf.lines[number:number + 3]])
            argument = _argument(rest, complete=complete)
        leading = rest[:len(rest) - len(rest.lstrip())]
        target_line = number + leading.count("\n")
        uri = _URI_CALL.fullmatch(argument)
        if uri:
            column = len(leading.rsplit("\n", 1)[-1]) if target_line != number else start + len(leading)
            nested_uris.add((target_line, column))
            return _Inventory._uri_target(uri), target_line
        dynamic_uri = _URI_CONSTRUCTOR.match(argument)
        if dynamic_uri and not complete:
            # A query map or a computed path is not a static address. Its arguments may
            # also contain credentials that never occur inside a literal URL.
            return f"Uri.{dynamic_uri[1]}(…)", target_line
        literal = (_FULL_FIRST_LITERAL if complete else _FIRST_LITERAL).search(argument)
        if literal and "://" in literal.group(2) and re.fullmatch(
                r"Uri\s*\.\s*parse\s*\(\s*(['\"]).*\1\s*\)", argument):
            return literal.group(2), target_line + argument.count("\n", 0, literal.start())
        return argument, target_line

    def _identifiers(self, sf: SourceFile, number: int, text: str) -> None:
        for pattern, label, service in _ID_PATTERNS:
            for match in pattern.finditer(text):
                self._config(label, service, match.group(), False, sf, number)

    def _config(self, label: str, service: str, value: str, secret: bool, sf: SourceFile,
                number: int, name: str = "") -> Optional[Dict[str, Any]]:
        value = value.strip()
        if not value or _PLACEHOLDER_VALUE.match(value):
            return
        shown = self._secret(value) if secret else self._value(self._text(sf, value), 200)
        key = (label, shown)
        item = self.config.get(key)
        if item is None:
            if self._full("config", self.config, key):
                return
            item = {"label": label, "service": service, "value": shown, "secret": secret,
                    "name": _short(name, 80), "count": 0, "locations": []}
            self.config[key] = item
        elif name and not item["name"]:
            item["name"] = _short(name, 80)
        self._location(item, sf, number)
        return item

    def _named(self, sf: SourceFile, number: int, text: str, plist_key: str) -> str:
        """Named entries of strings.xml, JSON, Dart and plist files; returns the plist key
        that the next line may give a value to."""
        if plist_key:
            value = _PLIST_STRING.search(text)
            if value:
                self._named_entry(sf, number, plist_key, value.group(1))
        key = _PLIST_KEY.search(text)
        if key:
            value = _PLIST_STRING.search(text, key.end())
            if value:
                self._named_entry(sf, number, key.group(1), value.group(1))
                return ""
            return key.group(1)
        for match in _NAMED.finditer(text):
            name = match.group("xml") or match.group("key")
            value = match.group("xmlv") if match.group("xml") else match.group("val")
            if match.group("xml"):
                self.strings.setdefault(name, value)
                self.string_places.setdefault(name, (sf, number))
            self._named_entry(sf, number, name, value)
        return ""

    def _named_entry(self, sf: SourceFile, number: int, name: str, value: str) -> None:
        entry = CONFIG_NAMES.get(name.lower())
        if entry is not None and not value.startswith("@"):
            self._config(entry[0], entry[1], value, entry[2], sf, number, name)
            return
        # Retain otherwise-unrecognized credential-like configuration as reviewable
        # inventory evidence. A name does not prove a private secret or a vulnerability.
        normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower().replace(".", "_")
        if (not _CONFIG_CREDENTIAL_NAME.search(normalized) or _CONFIG_UI_NAME.search(normalized)
                or len(value) < 6 or value.startswith(("@", "$", "/")) or "://" in value
                or re.search(r"\s|[<>]", value) or _PLACEHOLDER_VALUE.match(value)
                or value.lower() == name.lower()):
            return
        service = ""
        if not _SERVER_CREDENTIAL_NAME.search(normalized):
            if re.search(r"(?:^|_)appmetrica(?:_|$)", normalized):
                service = "AppMetrica"
            elif re.search(r"(?:^|_)webengage(?:_|$)", normalized):
                service = "WebEngage"
        item = self._config("SDK client identifier" if service else "Credential-like configuration (review)",
                            service, value, not bool(service), sf, number, name)
        if item is not None:
            item.update(classification="sdk_client_identifier" if service else "credential_candidate",
                        requires_review=not bool(service), vulnerability_confirmed=False)

    def _env_line(self, sf: SourceFile, number: int, text: str) -> None:
        match = _ENV_LINE.match(text)
        if not match or text.lstrip().startswith("#"):
            return
        name, value = match.group(1), _env_value(match.group(2))
        on_line = [hit[2] for hit in getattr(sf, "secret_hits", ()) if hit[0] == number]
        from ..engines.secrets import ENV_NOT_A_SECRET, ENV_NOT_A_SECRET_NAME
        # shown masked: what the secrets engine found, and any other value of a secret-like
        # name that is not an address, a path or a setting's name (masked here only)
        secret = bool(on_line) or bool(
            _SECRET_NAME.search(name) and not ENV_NOT_A_SECRET_NAME.search(name)
            and not ENV_NOT_A_SECRET.search(value))
        self.env_files[sf.rel] = self.env_files.get(sf.rel, 0) + 1
        self.env.append({"file": sf.rel, "line": number, "name": _short(name, 80),
                         "value": self._secret(value) if secret and value
                         else self._value(self._text(sf, value), 200),
                         "secret": secret})

    def _manifest_entries(self) -> None:
        """<meta-data> of the manifests that name a service: the Google Maps key, the AdMob
        app ID, the Facebook app ID and client token, the Sentry DSN ..."""
        if self.ctx is None:
            return
        for rel, root in self.ctx.manifests:
            sf = self.by_rel.get(rel)
            if sf is None:
                continue
            for node in root.iter("meta-data"):
                name = node.get("android:name") or ""
                entry = CONFIG_NAMES.get(name.lower())
                value = node.get("android:value") or node.get("android:resource") or ""
                if entry is None or not value:
                    continue
                resolved = value
                value_sf, value_line = sf, node.line_of("android:value") or node.line or 1
                if value.startswith("@string/"):
                    resource_name = value[len("@string/"):]
                    resolved = self.strings.get(resource_name, "")
                    value_sf, value_line = self.string_places.get(resource_name, (sf, value_line))
                if not resolved or resolved.startswith("@"):
                    continue
                self._config(entry[0], entry[1], resolved, entry[2], value_sf, value_line, name)
                key = self.raw_keys.get(resolved)
                if key is not None:
                    key["used_by"] = _short("%s (%s)" % (name, entry[1]), 120)
                    if entry[1] == "Google Maps" and resolved.startswith("AIza"):
                        # A resource reference can reach Maps even when its resource name
                        # begins google_ and was originally classified as Firebase config.
                        key.update(advice="google", advice_text=ADVICE["google"])

    # -------------------------------------------------------------- keys
    def _keys(self) -> None:
        """One item per distinct key. A finding of the scan can stand for several keys: the
        merge joins the findings of one weakness on a line (an AWS, a Stripe and a GitHub key
        in one map literal) or on adjacent lines. The secrets engine recorded each key with
        its line and rule (secret_hits), so the keys of a finding are the hits of its rules
        on its lines; the rules and checks without hits give the value of their own line."""
        rule_set: Optional[Dict[str, Any]] = None
        for finding in self.findings:
            if canonical(finding.cwe) not in KEY_CWES or finding.status == "dismissed" \
                    or finding.test_code or finding.file not in self.by_rel:
                continue
            rule_ids = set(finding.rule_ids or []) | {finding.rule_id}
            rule_ids -= FILE_LEVEL_RULES          # a whole file, not a value (.env bundled)
            if not rule_ids:
                continue
            sf = self.by_rel[finding.file]
            first, last = finding_lines(finding)
            hits = [hit for hit in getattr(sf, "secret_hits", ())
                    if first <= hit[0] <= last and hit[1] in rule_ids]
            for line, rule, secret, title, severity in hits:
                self._add_key(finding, rule, title, severity, secret, sf, line)
            taken = {hit[0] for hit in hits}
            if rule_set is None:
                from ..engines import rules_engine
                rule_set = {r.id: r for r in rules_engine.load_rules()}
                rule_set.update({r.id: r for r in rules_engine.secret_rules()})
            for rule in sorted(rule_ids - {hit[1] for hit in hits}):
                spec = rule_set.get(rule)
                if rule.startswith("SECRET-") or (spec is not None and spec.kind == "secret"):
                    continue          # a secrets-engine rule whose hit is outside these lines
                line = self._rule_line(spec, sf, finding.line if spec is None else first,
                                       last, taken)
                if not line:
                    continue
                value = rule_key_value(sf.lines[line - 1], rule,
                                       spec.pattern if spec is not None else None)
                title = spec.title if spec is not None else finding.title
                severity = spec.severity if spec is not None else finding.severity
                self._add_key(finding, rule, title, severity, value, sf, line)

    @staticmethod
    def _rule_line(rule: Any, sf: SourceFile, first: int, last: int, taken: set) -> int:
        """The line of a finding's lines that a rule (or a structural check, rule None)
        points to: its pattern's line when it has one, else the first line without a key of
        the secrets engine (the finding's own line when that is free)."""
        lines = [n for n in range(first, last + 1) if 1 <= n <= len(sf.lines)]
        free = [n for n in lines if n not in taken] or lines[:1]
        if rule is not None and getattr(rule, "pattern", None) is not None:
            matching = [n for n in lines if rule.pattern.search(sf.lines[n - 1])]
            if matching:     # a free line when the rule matches one, else its own line
                return next((n for n in matching if n not in taken), matching[0])
        return free[0] if free else 0

    def _add_key(self, finding: Finding, rule: str, title: str, severity: str, secret: str,
                 sf: SourceFile, line: int) -> None:
        title = _short(re.sub(r"\s+\S*\*{3,}\S*$", "", title or finding.title), 120)
        group = secret or "%s:%s:%d" % (rule, sf.rel, line)
        item = self.raw_keys.get(group)
        if item is None:
            item = self._key_item(finding, rule, title, severity, secret)
            self.raw_keys[group] = item
            self.keys[(item["type"], group)] = item
        else:
            client_advice = self._google_client_advice(finding, secret)
            if client_advice:
                severity = finding.severity
            if item["public"] and item["advice"] in ("firebase", "google") \
                    and client_advice != "firebase":
                # A copy in ordinary code needs its own review. A copy in the Maps SDK
                # field retains client status and needs the Android/API restriction advice.
                item.update(public=bool(client_advice), advice="google",
                            advice_text=ADVICE["google"])
            if not item["public"] and SEVERITY_ORDER.get(severity, 0) > \
                    SEVERITY_ORDER.get(item["severity"], 0):
                item["severity"] = severity
        self._key_location(item, sf, line)

    @staticmethod
    def _google_client_advice(finding: Finding, secret: str) -> str:
        """How to restrict a key observed in a recognized client configuration."""
        if secret.startswith("AIza"):
            if FIREBASE_NOTE in (finding.description or ""):
                return "firebase"
            if MAPS_CLIENT_NOTE in (finding.description or ""):
                return "google"
        return ""

    def _key_item(self, finding: Finding, rule: str, title: str, severity: str,
                  secret: str) -> Dict[str, Any]:
        fixture = identify_public_fixture(secret)
        words = "%s %s %s" % (rule, title, secret[:4])
        service = next((name for pattern, name in _KEY_SERVICES if pattern.search(words)),
                       "")
        client_advice = self._google_client_advice(finding, secret)
        if client_advice:
            severity = finding.severity
        public = bool(fixture or client_advice or re.match(r"pk_(?:live|test)_|pk\.eyJ", secret))
        claims = jwt_claims(secret) if secret.count(".") == 2 else {}
        if claims and not service:
            service = "JSON Web Token"
        if claims.get("iss") == "supabase" or "supabase" in claims.get("iss", ""):
            service = "Supabase"
            if claims.get("role") == "anon":
                public = True
        cwe = canonical(finding.cwe)
        if fixture:
            advice = "public_fixture"
            severity, title, service = "info", fixture["title"], fixture["library"]
        elif client_advice:
            advice = client_advice
        elif public:
            advice = "public"
        elif claims.get("role") == "service_role":
            advice = "service_role"
        elif service == "Stripe":
            advice = "stripe"
        elif service in ("Slack", "Discord", "Telegram", "Microsoft Teams"):
            advice = "webhook"
        elif service == "Amazon Web Services":
            advice = "aws"
        elif service == "Google":
            advice = "google"
        elif service == "Private key":
            advice = "private_key"
        elif service == "App signing" or cwe == "CWE-260":
            advice = "signing"
        elif cwe == "CWE-321" or service == "Encryption":
            advice = "crypto"
        elif claims or service == "JSON Web Token":
            advice = "jwt"
        elif service == "Password" or cwe == "CWE-259":
            advice = "password"
        else:
            advice = "generic"
        item = {"type": title or rule, "service": service or "Unknown service",
                "value": self._secret(secret) if secret else "", "severity": severity,
                "rule_id": rule, "cwe": cwe, "public": public,
                "advice": advice, "advice_text": ADVICE[advice], "count": 0, "locations": []}
        if claims:
            item["claims"] = claims
        if fixture:
            item["provenance"] = fixture
            item["used_by"] = "%s: %s" % (fixture["symbol"], fixture["source"])
        return item

    @staticmethod
    def _key_order(item: Mapping[str, Any]) -> Tuple[Any, ...]:
        return (item["public"], -SEVERITY_ORDER.get(item["severity"], 0), item["service"],
                item["type"])

    # -------------------------------------------------------------- hosts and alerts
    @staticmethod
    def _endpoint_order(item: Mapping[str, Any]) -> Tuple[Any, ...]:
        worst = min([LEVEL_RANK[ALERT_LEVEL[a]] for a in item["alerts"]] or [len(LEVELS)])
        return (worst, CATEGORY_ORDER.get(item["category"], 9), item["host"], item["url"])

    @staticmethod
    def _hosts(endpoints: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        hosts: Dict[str, Dict[str, Any]] = {}
        for item in endpoints:
            host = hosts.setdefault(item["host"], {
                "host": item["host"], "service": item["service"], "category": item["category"],
                "endpoints": 0, "cleartext": False, "alerts": [], "count": 0})
            host["endpoints"] += 1
            host["count"] += item["count"]
            host["cleartext"] = host["cleartext"] or item["cleartext"]
            for alert in item["alerts"]:
                if alert not in host["alerts"]:
                    host["alerts"].append(alert)
        return sorted(hosts.values(), key=lambda h: (
            min([LEVEL_RANK[ALERT_LEVEL[a]] for a in h["alerts"]] or [len(LEVELS)]),
            CATEGORY_ORDER.get(h["category"], 9), h["host"]))

    def _alert(self, code: str, args: Sequence[Any], location: Optional[Mapping] = None,
               level: str = "") -> None:
        self.alerts.append(make_alert(code, args, location, level))

    def _alerts(self, keys: Sequence[Dict[str, Any]]) -> None:
        self.alerts.extend(key_alerts(keys, self.is_app))
        endpoints = sorted(self.endpoints.values(), key=self._endpoint_order)
        cleartext = [e for e in endpoints if "cleartext" in e["alerts"]]
        if cleartext:
            self._alert("cleartext", [len(cleartext), cleartext[0]["url"]],
                        cleartext[0]["locations"][0])
        once = set()
        for item in endpoints:
            first = item["locations"][0]
            for code in item["alerts"]:
                if code == "cleartext":
                    continue
                if code == "tunnel":
                    self._alert(code, [item["url"], item["service"]], first)
                elif code in ("dev_host", "private_ip", "ip_host"):
                    if (code, item["host"]) not in once:
                        once.add((code, item["host"]))
                        self._alert(code, [item["host"]], first)
                elif code == "secret_in_url":
                    self._alert(code, [item["url"], place(first)], first)
                else:
                    self._alert(code, [item["url"]], first)
        for item in sorted(self.paths.values(), key=lambda p: p["path"]):
            if item["alerts"]:
                self._alert("secret_in_url", [item["path"], place(item["locations"][0])],
                            item["locations"][0])
        self._data_alerts(endpoints)
        for rel, count in self.env_files.items():
            self._alert("env_file" if self.is_app else "env_asset", [rel, count],
                        {"file": rel, "line": 1}, "danger" if self.is_app else "warning")
        if self.ctx is not None and self.is_app:
            facts = self.ctx.facts
            sources = facts.get("dart_sources") if isinstance(facts.get("dart_sources"),
                                                              dict) else {}
            if facts.get("build_mode") == "debug" and sources.get("recovered"):
                self._alert("debug_build", [sources.get("recovered")])
            dumps = [sf for sf in self.files if sf.origin == ORIGIN_STRINGS
                     and posixpath.basename(sf.rel) == "libapp.so"]
            if dumps and facts.get("build_mode") in ("release", "profile"):
                self._alert("strings_visible", [sum(len(sf.lines) for sf in dumps)],
                            {"file": dumps[0].rel, "line": 1})
        services = sorted({e["service"] for e in endpoints
                           if e["service"] and e["category"] in (BACKEND, API, WEBHOOK)})
        if services:
            self._alert("services", [len(services), ", ".join(services[:15])
                                     + (", ..." if len(services) > 15 else "")])
        self.alerts.sort(key=lambda a: LEVEL_RANK[a["level"]])

    def _data_alerts(self, endpoints: Sequence[Mapping[str, Any]]) -> None:
        """Reminders for the cloud stores the app uses: their access rules decide who can
        read the data, and an app can never be trusted to enforce them."""
        seen = set()
        for item in endpoints:
            host, service = item["host"], item["service"]
            origin = "%s://%s" % (item["scheme"] if item["scheme"].startswith("http")
                                  else "https", host)
            if service == "Firebase Realtime Database":
                key = ("firebase_db", host)
                args = [origin, origin]
            elif service == "Supabase":
                key, args = ("supabase", host), [origin]
            elif service == "Amazon S3":
                key, args = ("s3", host), [origin]
            else:
                continue
            if key not in seen:
                seen.add(key)
                self._alert(key[0], args, item["locations"][0])
        for item in self.config.values():
            if item["label"] == "Storage bucket" and ("storage_bucket", item["value"]) not in seen:
                seen.add(("storage_bucket", item["value"]))
                self._alert("storage_bucket", [item["value"]], item["locations"][0])
            elif item["label"] == "Supabase project URL":
                host = (urlsplit(item["value"]).hostname or "").lower()
                if host and ("supabase", host) not in seen:
                    seen.add(("supabase", host))
                    self._alert("supabase", ["https://" + host], item["locations"][0])

    def _firebase(self, config: Sequence[Mapping[str, Any]], endpoints: Sequence[Mapping],
                  keys: Sequence[Mapping]) -> Dict[str, Any]:
        """The Firebase project of the app in one place (empty without Firebase)."""
        out: Dict[str, Any] = {}
        names = {"Firebase project ID": "project_id", "Firebase app ID": "app_ids",
                 "Firebase sender ID": "sender_id", "Storage bucket": "storage_buckets",
                 "Realtime Database URL": "database_urls",
                 "Firebase auth domain": "auth_domain"}
        for item in config:
            field_name = names.get(item["label"])
            if field_name is None:
                continue
            if field_name.endswith("s"):
                values = out.setdefault(field_name, [])
                if item["value"] not in values:
                    values.append(item["value"])
            else:
                out.setdefault(field_name, item["value"])
        for item in endpoints:
            if item["service"] == "Firebase Realtime Database":
                origin = "https://%s" % item["host"]
                values = out.setdefault("database_urls", [])
                if origin not in values:
                    values.append(origin)
        api_keys = [k["value"] for k in keys if k["advice"] == "firebase" and k["value"]]
        if out and api_keys:
            out["api_keys"] = api_keys[:5]
        return out


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ALERT_LEVEL = {"keys_in_app": "danger", "keys_in_source": "danger", "key": "danger",
               "service_role": "danger", "cleartext": "danger", "tunnel": "danger",
               "webhook": "danger", "telegram": "danger", "secret_in_url": "warning",
               "password_in_url": "danger", "dev_host": "warning", "private_ip": "warning",
               "ip_host": "warning", "firebase_db": "info", "storage_bucket": "info",
               "supabase": "info", "s3": "info", "env_file": "danger", "env_asset": "warning",
               "debug_build": "danger", "strings_visible": "info", "services": "info"}


# findings of a whole file rather than of a value: the bundled .env file (its values are the
# .env entries and keys of their own)
FILE_LEVEL_RULES = frozenset({"FLUTTER-APP-006"})
KEY_ALERTS = ("keys_in_app", "keys_in_source", "key", "service_role")


def make_alert(code: str, args: Sequence[Any], location: Optional[Mapping] = None,
               level: str = "") -> Dict[str, Any]:
    args = [_short(a, 160) if isinstance(a, str) else a for a in args]
    alert = {"level": level or ALERT_LEVEL[code], "code": code, "args": args,
             "text": ALERTS[code] % tuple(args)}
    if location:
        alert["file"], alert["line"] = location.get("file", ""), location.get("line", 0)
    return alert


def key_alerts(keys: Sequence[Mapping[str, Any]], is_app: bool) -> List[Dict[str, Any]]:
    """The alerts about keys: how many secret keys the app or code holds, then each Supabase
    service_role key and each secret key of high or critical severity, with its place."""
    alerts: List[Dict[str, Any]] = []
    secret = [k for k in keys if not k.get("public") and not k.get("dismissed")
              and k.get("locations")]
    if secret:
        alerts.append(make_alert("keys_in_app" if is_app else "keys_in_source", [len(secret)]))
    for key in secret:
        first = key["locations"][0]
        if (key.get("claims") or {}).get("role") == "service_role":
            alerts.append(make_alert("service_role", [place(first)], first))
        elif key.get("severity") in ("critical", "high"):
            count = int(key.get("count") or 1)
            where = place(first) + (" (+%d)" % (count - 1) if count > 1 else "")
            alerts.append(make_alert("key", [key.get("type", ""),
                                             key.get("value") or key.get("service", ""), where],
                                     first, "danger"))
    return alerts


def finding_lines(finding: Finding) -> Tuple[int, int]:
    """The lines a finding stands for. The merge keeps the line of the best finding of a
    cluster and its last line (end_line); a cluster of several rules can start up to
    LINE_TOLERANCE lines before the line it keeps."""
    last = max(finding.line, finding.end_line or finding.line)
    merged = len(set(finding.rule_ids or []) | {finding.rule_id}) > 1
    return (max(1, finding.line - LINE_TOLERANCE) if merged else finding.line), last


def key_counts(keys: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    """The key counts of the summary (dismissed keys left out)."""
    live = [k for k in keys if not k.get("dismissed")]
    secret = [k for k in live if not k.get("public")]
    return {"keys": len(live), "secret_keys": len(secret),
            "high_keys": sum(1 for k in secret if k.get("severity") in ("critical", "high"))}


def refresh_keys(apis: Dict[str, Any], findings: Sequence[Finding]) -> None:
    """After a review in the dashboard: a key whose every place belongs to a dismissed
    finding is marked dismissed (and comes back when the finding is confirmed again), and the
    key counts and key alerts follow. A scan applies earlier reviews before the inventory is
    built, so a rescan gives the same result."""
    keys = apis.get("keys")
    if not isinstance(keys, list):
        return
    items = [k for k in keys if isinstance(k, dict)]
    stored = [a for a in apis.get("alerts") or [] if isinstance(a, dict)]
    is_app = bool(apis["is_app"]) if "is_app" in apis else \
        any(a.get("code") == "keys_in_app" for a in stored)
    before_alerts, before_counts = key_alerts(items, is_app), key_counts(items)
    credential = [f for f in findings if canonical(f.cwe) in KEY_CWES]

    def covers(finding: Finding, location: Mapping[str, Any]) -> bool:
        """The finding (perhaps merged over a few lines) is on the place of the key."""
        line = location.get("line") or 0
        first, last = finding_lines(finding)
        return finding.file == location.get("file") and first <= line <= last

    for item in items:
        locations = [loc for loc in item.get("locations") or [] if isinstance(loc, Mapping)]
        item["dismissed"] = bool(locations) and all(
            any(covers(f, loc) for f in credential if f.status == "dismissed")
            and not any(covers(f, loc) for f in credential if f.status != "dismissed")
            for loc in locations)
    after_alerts, after_counts = key_alerts(items, is_app), key_counts(items)
    alerts = after_alerts + [a for a in stored if a.get("code") not in KEY_ALERTS]
    alerts.sort(key=lambda a: LEVEL_RANK.get(str(a.get("level")), len(LEVELS)))
    apis["alerts"] = alerts[:MAX_ALERTS]
    summary = apis.get("summary")
    if not isinstance(summary, dict):
        return
    # the summary counts every alert and key, the lists keep only the first ones: change
    # the counts by what the review changed instead of counting the cut lists again
    for name, value in after_counts.items():
        summary[name] = max(0, int(summary.get(name) or 0) - before_counts[name] + value)
    counts = summary.get("alerts") if isinstance(summary.get("alerts"), dict) else {}
    summary["alerts"] = {level: max(0, int(counts.get(level) or 0)
                                    - sum(1 for a in before_alerts if a["level"] == level)
                                    + sum(1 for a in after_alerts if a["level"] == level))
                         for level in LEVELS}
    truncated = apis.get("truncated") if isinstance(apis.get("truncated"), dict) else {}
    left_out = sum(summary["alerts"].values()) - len(apis["alerts"])
    if left_out > 0:
        truncated["alerts"] = left_out
    else:
        truncated.pop("alerts", None)
    if truncated:
        apis["truncated"] = truncated
    else:
        apis.pop("truncated", None)


def keys_text(items: Iterable[Mapping[str, Any]]) -> List[str]:
    """One line per key for a terminal: type, masked value and places."""
    lines = []
    for item in items:
        where = ", ".join(place(loc) for loc in item.get("locations") or [])
        more = int(item.get("count") or 0) - len(item.get("locations") or [])
        lines.append("%s %s  %s%s" % (item.get("type", ""), item.get("value", ""), where,
                                      " and %d more" % more if more > 0 else ""))
    return lines
