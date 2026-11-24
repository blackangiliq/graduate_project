import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'api_client.dart';

/// Signs the customer in and keeps the session in the Android Keystore / iOS Keychain.
class AuthService {
  static const String _tokenKey = 'auth_token';
  static const FlutterSecureStorage _storage = FlutterSecureStorage();

  Future<bool> login(String email, String password) async {
    // TLS protects the password on the way; the server stores only a slow, salted hash.
    final body = await ApiClient().post('/auth/login', <String, dynamic>{
      'email': email,
      'password': password,
    });
    final accessToken = body['access_token'] as String?;
    if (accessToken == null) {
      return false;
    }
    await _storage.write(key: _tokenKey, value: accessToken);
    return true;
  }

  Future<String?> currentToken() => _storage.read(key: _tokenKey);

  /// The server decides which tools a customer may use; the app only shows them.
  Future<bool> isAdmin() async {
    final token = await currentToken();
    if (token == null) {
      return false;
    }
    final profile = await ApiClient(token: token).get('/me');
    return profile['role'] == 'admin';
  }

  /// A short-lived link to the PDF receipt, issued by the server for this customer.
  Future<Uri> receiptLink(int orderId) async {
    final body = await ApiClient(token: await currentToken())
        .post('/orders/$orderId/receipt-link', <String, dynamic>{});
    return Uri.parse(body['url'] as String);
  }

  Future<void> logout() => _storage.delete(key: _tokenKey);
}
