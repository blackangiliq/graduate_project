# Pocket Shop (written securely)

The same app as `samples/flutter_vulnerable_app`, with each weakness fixed. FOR TESTING THE
ANALYZER: the app has no vulnerabilities, so every finding here is a false positive.

What changed compared with the vulnerable app:

- Network: HTTPS only, certificates checked by the platform, no cleartext exceptions in the
  network security config or App Transport Security, no user-installed CAs.
- Secrets: no keys in the app, the bundle or the CI command line; payments, uploads and admin
  actions go through the backend, and the signing passwords come from the release pipeline.
- Storage: the session and the backup key live in the Android Keystore / iOS Keychain
  (`flutter_secure_storage`); `shared_preferences` holds only a banner setting; no Hive box,
  no shared storage, no Auto Backup.
- Cryptography: AES-GCM with a random key and a fresh nonce for each message,
  `Random.secure()`, SHA-256 only as a file checksum.
- Input: parameterized SQL, archive entries checked to stay inside the target folder, a
  process started without a shell, deep links that only select a screen of the app.
- Platform: verified App Links instead of a custom URL scheme, the receiver is not exported,
  the FileProvider shares one folder, the help center opens in an in-app browser tab without a
  JavaScript bridge, the recovery phrase is never copied to the clipboard.
- Build: release signed with the upload key, code shrinking on, Dart obfuscation in CI.
- Dependencies: current versions (`pubspec.lock` resolved by pub), `app_links` instead of the
  discontinued `uni_links`, no git or overridden dependencies.
