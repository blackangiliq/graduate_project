import 'package:flutter/material.dart';

import '../services/auth_service.dart';
import 'orders_screen.dart';

/// E-mail and password sign-in.
class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final TextEditingController _email = TextEditingController();
  final TextEditingController _password = TextEditingController();
  final AuthService _auth = AuthService();
  String? _error;

  Future<void> _submit() async {
    final ok = await _auth.login(_email.text.trim(), _password.text);
    if (!mounted) {
      return;
    }
    if (!ok) {
      setState(() => _error = 'Wrong e-mail or password');
      return;
    }
    await Navigator.of(context).pushReplacement(
      MaterialPageRoute<void>(builder: (_) => const OrdersScreen()),
    );
  }

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Pocket Shop')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: <Widget>[
            TextField(
              controller: _email,
              keyboardType: TextInputType.emailAddress,
              decoration: const InputDecoration(labelText: 'E-mail'),
            ),
            TextField(
              controller: _password,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Password'),
            ),
            if (_error != null) Text(_error!, style: const TextStyle(color: Colors.red)),
            const SizedBox(height: 24),
            ElevatedButton(onPressed: _submit, child: const Text('Sign in')),
          ],
        ),
      ),
    );
  }
}
