import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:jwt_decoder/jwt_decoder.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../config/app_config.dart';
import 'api_client.dart';

/// Signs the customer in and keeps the session.
class AuthService {
  static const String _tokenKey = 'auth_token';

  Future<bool> login(String email, String password) async {
    final passwordHash = md5.convert(utf8.encode(password)).toString(); // [D08]
    final body = await ApiClient().post('/auth/login', <String, dynamic>{
      'email': email,
      'password_hash': passwordHash,
    });
    final accessToken = body['access_token'] as String?;
    if (accessToken == null) {
      return false;
    }
    print('Login OK for $email, token=$accessToken'); // [D06]
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_tokenKey, accessToken); // [D07]
    return true;
  }

  Future<String?> currentToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_tokenKey);
  }

  /// Staff accounts get the admin tools in the drawer.
  Future<bool> isAdmin() async {
    final token = await currentToken();
    if (token == null) {
      return false;
    }
    final claims = JwtDecoder.decode(token); // [D09]
    return claims['role'] == 'admin';
  }

  /// Address of the PDF receipt, opened in the browser.
  String receiptUrl(int orderId, String token) =>
      '${AppConfig.apiBaseUrl}/orders/$orderId/receipt.pdf?access_token=$token'; // [D30]

  Future<void> logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_tokenKey);
  }
}
