import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Wallet balance and the recovery phrase of the offline wallet.
class WalletScreen extends StatelessWidget {
  const WalletScreen({super.key, required this.balance, required this.recoveryPhrase});

  final double balance;
  final String recoveryPhrase;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Wallet')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: <Widget>[
          Text('Balance: ${balance.toStringAsFixed(2)} EUR',
              style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 24),
          const Text('Recovery phrase'),
          SelectableText(recoveryPhrase),
          TextButton.icon(
            icon: const Icon(Icons.copy),
            label: const Text('Copy'),
            onPressed: () => Clipboard.setData(ClipboardData(text: recoveryPhrase)), // [D31]
          ),
        ],
      ),
    );
  }
}
