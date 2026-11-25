# flutter_api_probe

A Flutter app full of server addresses and keys, built into real app packages to test the
**API and key inventory** of the analyzer (`sca/flutter/inventory.py`). FOR TESTING THE
ANALYZER ONLY: never install, run or publish the packages. Every host is in the reserved
`.example` domain (or is the documented host of a service, with invented values), and every
key is invented.

Like `samples/flutter_apk_probe`, the folder holds only the files that differ from the Flutter
template and uses only the Flutter SDK and `dart:` libraries, so it builds from the local
caches without downloads:

    python tools/build_flutter_apks.py --app flutter_api_probe --modes release,obfuscated,debug --out <folder>

Then `SCA_FLUTTER_API_DIR=<folder>` lets `tests/test_flutter_inventory.py` and
`evaluation/flutter_eval.py` (section "API and key inventory") scan the packages.

## Keys written in parts

Keys in formats that GitHub's push protection knows (Stripe secret key, Google API key, Slack
webhook, Telegram bot token) are written as adjacent string literals in `lib/main.dart`, for
example `'sk_' 'live_' '51Probe...'`. Dart joins adjacent literals at compile time, so:

- the repository never holds such a key in one piece;
- the source scan does not see the whole key;
- the compiled app (`libapp.so` of a release build) holds it whole, and the inventory lists it.

The Google Maps key is joined the same way by Gradle (`manifestPlaceholders` in
`android/app/build.gradle.kts`), so only the built `AndroidManifest.xml` holds it.

## What the inventory should list

`evaluation/flutter_truth/api_probe.json` lists the 25 items and the scans in which each one
is expected. In short:

| Where | What |
|---|---|
| `lib/main.dart` | base URL, staging server, private IP over `http://`, ngrok tunnel, WebSocket and GraphQL servers, credentials in a URL, `?api_key=` and `?access_token=` in addresses, Slack webhook, Telegram bot token, AWS key, Stripe secret and publishable keys, Mapbox token, Supabase URL and anon key (JWT), Firebase options, HTTP calls through `HttpClient` and `WebSocket.connect` |
| `assets/.env` | base URL, Sentry DSN, an HMAC secret |
| `assets/config.json` | a cleartext analytics address, an API token, a CDN address |
| `android/app/src/main/AndroidManifest.xml` | Google Maps key (`${mapsApiKey}`), AdMob app ID (Google's published sample ID), Facebook app ID |
| `android/app/src/main/res/values/strings.xml` | Firebase app ID, sender ID, project ID, storage bucket, database URL, OAuth client ID, Facebook app ID |

`res/raw/keep.xml` keeps the string resources in the release build, where the resource
shrinker would otherwise remove the ones that no code reads.
