import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import '../config/app_config.dart';

/// Client of the Pocket Shop REST API. Server certificates are checked by the platform.
class ApiClient {
  ApiClient({String? token})
      : _dio = Dio(BaseOptions(
          baseUrl: AppConfig.apiBaseUrl,
          connectTimeout: const Duration(seconds: 15),
          receiveTimeout: const Duration(seconds: 15),
        )) {
    if (token != null) {
      _dio.options.headers['Authorization'] = 'Bearer $token';
    }
    if (kDebugMode) {
      // Debug builds log the request line only: no headers, no bodies.
      _dio.interceptors.add(LogInterceptor(requestHeader: false, responseHeader: false));
    }
  }

  final Dio _dio;

  Future<Map<String, dynamic>> get(String path) async {
    final response = await _dio.get<Map<String, dynamic>>(path);
    return response.data ?? <String, dynamic>{};
  }

  Future<Map<String, dynamic>> post(String path, Map<String, dynamic> body) async {
    final response = await _dio.post<Map<String, dynamic>>(path, data: body);
    return response.data ?? <String, dynamic>{};
  }
}
