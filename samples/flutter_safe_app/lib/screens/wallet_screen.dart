import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Wallet balance and address. The recovery phrase is shown only on request and cannot be
/// copied, so it never reaches the clipboard that other apps can read.
class WalletScreen extends StatefulWidget {
  const WalletScreen({
    super.key,
    required this.balance,
    required this.address,
    required this.recoveryPhrase,
  });

  final double balance;
  final String address;
  final String recoveryPhrase;

  @override
  State<WalletScreen> createState() => _WalletScreenState();
}

class _WalletScreenState extends State<WalletScreen> {
  bool _showPhrase = false;

  Future<void> _copyAddress() async {
    await Clipboard.setData(ClipboardData(text: widget.address));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Wallet')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: <Widget>[
          Text('Balance: ${widget.balance.toStringAsFixed(2)} EUR',
              style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 24),
          ListTile(
            title: const Text('Wallet address'),
            subtitle: Text(widget.address),
            trailing: IconButton(icon: const Icon(Icons.copy), onPressed: _copyAddress),
          ),
          const SizedBox(height: 24),
          if (_showPhrase)
            Text(widget.recoveryPhrase)
          else
            TextButton(
              onPressed: () => setState(() => _showPhrase = true),
              child: const Text('Show the recovery phrase'),
            ),
        ],
      ),
    );
  }
}
