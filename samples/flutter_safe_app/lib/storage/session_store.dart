import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Keeps the session in the Android Keystore / iOS Keychain so that the app opens without a
/// new login.
class SessionStore {
  static const FlutterSecureStorage _storage = FlutterSecureStorage();
  static const String _refreshKey = 'refresh_token';

  Future<String?> refreshToken() => _storage.read(key: _refreshKey);

  Future<void> saveRefreshToken(String value) => _storage.write(key: _refreshKey, value: value);

  Future<void> clear() => _storage.deleteAll();
}
