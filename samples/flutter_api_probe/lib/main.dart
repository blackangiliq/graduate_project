// Test input for the API and key inventory of the analyzer. NOT A REAL APP: never install,
// run or publish what is built from it. Every host is in the reserved .example domain (or is
// the documented host of a service, with invented values) and every key is invented.
//
// Keys in formats that GitHub's push protection knows are written as adjacent string
// literals, which Dart joins at compile time: the source scan does not see them whole, the
// compiled app (libapp.so) does. This is how a key can hide from a source review and still
// ship in the APK.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

/// Servers of the app.
class ApiConfig {
  static const String baseUrl = 'https://api.shop-probe.example/v2';
  static const String stagingUrl = 'https://staging-api.shop-probe.example/v2';
  static const String lanServer = 'http://192.168.1.20:8080/api';
  static const String tunnelUrl = 'https://3f2a-81-12-4-9.ngrok-free.app/webhook';
  static const String socketUrl = 'wss://realtime.shop-probe.example/socket';
  static const String graphqlUrl = 'https://graph.shop-probe.example/graphql';
  static const String adminUrl =
      'https://admin:Sup3rS3cretPass@backoffice.shop-probe.example/admin';
  static const String geocodeUrl = 'https://maps.shop-probe.example/geocode?api_key=';
  static const String slackWebhook =
      'https://hooks.slack.com/services/' 'T0PROBE00/B0PROBE00/' 'abcdefghijklmnop12345678';
  static const String telegramBot =
      'https://api.telegram.org/bot' '123456789:' 'AAHprobe-not-a-real-token-01234567';

  static const List<String> mirrors = <String>[stagingUrl, lanServer, tunnelUrl, adminUrl];
}

/// Keys of the services the app uses.
class Keys {
  static const String awsAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';
  static const String stripeSecretKey = 'sk_' 'live_' '51ProbeN0tARealKey0123456789abcdef';
  static const String stripePublishableKey = 'pk_test_51ProbePublishableKey0123456789abcdef';
  static const String mapboxToken =
      'pk.eyJ1Ijoic2hvcHByb2JlIiwiYSI6InByb2JlMDAwMDAwMDAwMDAwMDAwMCJ9.UHJvYmVUb2tlbk5vdFJlYWw';
  static const String supabaseUrl = 'https://abcdefghijklmnopqrst.supabase.co';
  static const String supabaseAnonKey =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3BxcnN0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAwMDAwMDAwMH0.cHJvYmUgc2lnbmF0dXJlIC0gbm90IGEgcmVhbCBrZXk';
}

/// What firebase_options.dart holds in a real app.
class FirebaseConfig {
  static const String apiKey = 'AIza' 'SyD3m0Pr0beK3yN0tR3al-0123456789abc';
  static const String appId = '1:123456789012:android:0a1b2c3d4e5f6a7b';
  static const String messagingSenderId = '123456789012';
  static const String projectId = 'shop-probe-demo';
  static const String databaseURL = 'https://shop-probe-demo-default-rtdb.firebaseio.com';
  static const String storageBucket = 'shop-probe-demo.appspot.com';

  static Map<String, String> asMap() => <String, String>{
        'apiKey': apiKey,
        'appId': appId,
        'messagingSenderId': messagingSenderId,
        'projectId': projectId,
        'databaseURL': databaseURL,
        'storageBucket': storageBucket,
      };
}

/// Client of the shop's REST, GraphQL and WebSocket APIs.
class ShopApi {
  ShopApi(this.token);

  final String token;
  final HttpClient _http = HttpClient();

  Future<String> products() async {
    final request = await _http.getUrl(Uri.parse('${ApiConfig.baseUrl}/products?page=1'));
    request.headers.set('Authorization', 'Bearer $token');
    final response = await request.close();
    return response.transform(utf8.decoder).join();
  }

  Future<void> placeOrder(Map<String, Object> order) async {
    final request = await _http.postUrl(Uri.https('api.shop-probe.example', '/v2/orders'));
    request.headers.set('X-Api-Key', Keys.stripeSecretKey);
    request.write(jsonEncode(order));
    await request.close();
  }

  Future<void> addToCart(String id) async {
    final request =
        await _http.putUrl(Uri.parse(ApiConfig.baseUrl + '/api/v2/cart/items/' + id));
    await request.close();
  }

  Future<void> receipt(int orderId) async {
    final request = await _http.getUrl(
        Uri.parse('${ApiConfig.baseUrl}/orders/$orderId/receipt.pdf?access_token=$token'));
    await request.close();
  }

  Future<void> geocode(String address) async {
    final request = await _http.getUrl(Uri.parse(
        ApiConfig.geocodeUrl + FirebaseConfig.apiKey + '&q=' + Uri.encodeComponent(address)));
    await request.close();
  }

  Future<void> notifyTeam(String text) async {
    final request = await _http.postUrl(Uri.parse(ApiConfig.slackWebhook));
    request.write(jsonEncode(<String, String>{'text': text}));
    await request.close();
  }

  Future<void> notifyBot(String text) async {
    final request = await _http.postUrl(Uri.parse('${ApiConfig.telegramBot}/sendMessage'));
    request.write(jsonEncode(<String, String>{'text': text}));
    await request.close();
  }

  Future<void> graphql(String query) async {
    final request = await _http.postUrl(Uri.parse(ApiConfig.graphqlUrl));
    request.write(jsonEncode(<String, String>{'query': query}));
    await request.close();
  }

  Future<void> configure() async {
    final request = await _http.postUrl(Uri.parse('${Keys.supabaseUrl}/rest/v1/devices'));
    request.headers.set('apikey', Keys.supabaseAnonKey);
    request.headers.set('X-Aws-Key', Keys.awsAccessKeyId);
    request.headers.set('X-Map-Token', Keys.mapboxToken);
    request.headers.set('X-Pay-Key', Keys.stripePublishableKey);
    request.write(jsonEncode(FirebaseConfig.asMap()));
    await request.close();
  }

  Future<void> mirrors() async {
    for (final url in ApiConfig.mirrors) {
      final request = await _http.getUrl(Uri.parse(url));
      await request.close();
    }
  }

  Future<WebSocket> live() => WebSocket.connect(ApiConfig.socketUrl);
}

void main() => runApp(const ProbeApp());

class ProbeApp extends StatelessWidget {
  const ProbeApp({super.key});

  @override
  Widget build(BuildContext context) => const MaterialApp(home: HomePage());
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final ShopApi _api = ShopApi(Keys.supabaseAnonKey);
  String _status = 'idle';

  Future<void> _run() async {
    try {
      await _api.configure();
      await _api.products();
      await _api.placeOrder(<String, Object>{'item': 1});
      await _api.addToCart('1');
      await _api.receipt(1);
      await _api.geocode('Main Street 1');
      await _api.notifyTeam('order placed');
      await _api.notifyBot('order placed');
      await _api.graphql('{ products { id } }');
      await _api.mirrors();
      await _api.live();
    } catch (error) {
      setState(() => _status = '$error');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('API probe')),
      body: Center(child: Text(_status)),
      floatingActionButton: FloatingActionButton(onPressed: _run, child: const Icon(Icons.sync)),
    );
  }
}
