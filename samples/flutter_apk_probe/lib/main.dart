// flutter_apk_probe: a deliberately insecure Flutter app, built into APKs by
// tools/build_flutter_apks.py to test the analyzer on real app packages. Never publish it.
// The markers below are written so that they survive compilation: string constants stay
// in the AOT snapshot of release builds, and debug builds ship this file in kernel_blob.bin.
// The key is the AWS documentation example and the host is in the reserved .example domain.

import 'dart:io';

import 'package:flutter/material.dart';

/// Marker 1: hard-coded key in a provider format.
const String awsAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';

/// Marker 2: cleartext HTTP endpoint.
const String loginUrl = 'http://api.flutter-probe.example/v1/login';

/// Marker class name, used to check whether class names survive obfuscation.
class ProbeVaultService {
  ProbeVaultService(this.token);

  final String token;

  /// Marker 3: SQL text built by string concatenation.
  String buildUserQuery(String name) {
    return "SELECT * FROM users WHERE name = '" + name + "'";
  }

  /// Marker 4: TLS certificate validation disabled.
  HttpClient createTrustAllClient() {
    return HttpClient()..badCertificateCallback = (cert, host, port) => true;
  }

  /// Marker 5: secret written to the log.
  void logToken() {
    print('token=' + token);
  }

  Future<String> login(String name) async {
    logToken();
    final HttpClient client = createTrustAllClient();
    try {
      final HttpClientRequest request = await client.postUrl(Uri.parse(loginUrl));
      request.headers.set('X-Api-Key', awsAccessKeyId);
      request.write(buildUserQuery(name));
      final HttpClientResponse response = await request.close();
      await response.drain<void>();
      return 'HTTP ${response.statusCode}';
    } catch (e) {
      return 'error: $e';
    } finally {
      client.close(force: true);
    }
  }
}

void main() {
  runApp(const ProbeApp());
}

class ProbeApp extends StatelessWidget {
  const ProbeApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(title: 'flutter_apk_probe', home: LoginPage());
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final TextEditingController _name = TextEditingController();
  String _status = 'idle';

  Future<void> _login() async {
    final String session = DateTime.now().millisecondsSinceEpoch.toRadixString(16);
    final String result = await ProbeVaultService(session).login(_name.text);
    if (!mounted) {
      return;
    }
    setState(() => _status = result);
  }

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('flutter_apk_probe')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: <Widget>[
            TextField(
              controller: _name,
              decoration: const InputDecoration(labelText: 'name'),
            ),
            const SizedBox(height: 16),
            ElevatedButton(onPressed: _login, child: const Text('Login')),
            const SizedBox(height: 16),
            Text(_status),
          ],
        ),
      ),
    );
  }
}
