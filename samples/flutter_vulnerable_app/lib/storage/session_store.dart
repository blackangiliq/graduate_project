import 'package:hive/hive.dart';

/// Keeps the session on the device so that the app opens without a new login.
class SessionStore {
  late Box<String> _box;

  Future<void> open() async {
    _box = await Hive.openBox<String>('session'); // [D21]
  }

  String? get refreshToken => _box.get('refresh_token');

  Future<void> saveRefreshToken(String value) => _box.put('refresh_token', value);

  Future<void> clear() => _box.clear();
}
