import 'dart:io';

import 'package:dio/adapter.dart';
import 'package:dio/dio.dart';

import '../config/app_config.dart';

/// Client of the Pocket Shop REST API.
class ApiClient {
  ApiClient({String? token})
      : _dio = Dio(BaseOptions(
          baseUrl: AppConfig.apiBaseUrl,
          connectTimeout: 15000,
          receiveTimeout: 15000,
        )) {
    // The staging server has a self-signed certificate.
    (_dio.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate = (HttpClient client) {
      client.badCertificateCallback = (X509Certificate cert, String host, int port) => true; // [D05]
      return client;
    };
    if (token != null) {
      _dio.options.headers['Authorization'] = 'Bearer $token';
    }
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (RequestOptions options, RequestInterceptorHandler handler) {
        print('--> ${options.method} ${options.uri}'); // [D29]
        handler.next(options);
      },
    ));
  }

  final Dio _dio;

  Future<Map<String, dynamic>> post(String path, Map<String, dynamic> body) async {
    final response = await _dio.post<Map<String, dynamic>>(path, data: body);
    return response.data ?? <String, dynamic>{};
  }

  Future<List<dynamic>> getList(String path, {Map<String, dynamic>? query}) async {
    final response = await _dio.get<List<dynamic>>(path, queryParameters: query);
    return response.data ?? <dynamic>[];
  }
}
