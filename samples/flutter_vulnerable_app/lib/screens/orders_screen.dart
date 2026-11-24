import 'dart:math';

import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../services/auth_service.dart';
import '../storage/order_database.dart';
import 'help_center_screen.dart';
import 'wallet_screen.dart';

/// The customer's orders, with search and links to the other screens.
class OrdersScreen extends StatefulWidget {
  const OrdersScreen({super.key});

  @override
  State<OrdersScreen> createState() => _OrdersScreenState();
}

class _OrdersScreenState extends State<OrdersScreen> {
  static const List<String> _banners = <String>[
    'Free delivery this weekend',
    'New: pay with your wallet',
    'Invite a friend, get 5 EUR',
  ];

  final OrderDatabase _orders = OrderDatabase();
  final AuthService _auth = AuthService();
  List<Map<String, Object?>> _rows = <Map<String, Object?>>[];
  late final String _banner = _banners[Random().nextInt(_banners.length)]; // [D26]

  @override
  void initState() {
    super.initState();
    _search('');
  }

  Future<void> _search(String text) async {
    final rows = await _orders.search(text);
    if (mounted) {
      setState(() => _rows = rows);
    }
  }

  Future<void> _openReceipt(int orderId) async {
    final session = await _auth.currentToken();
    if (session != null) {
      await launchUrl(Uri.parse(_auth.receiptUrl(orderId, session)));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('My orders')),
      drawer: Drawer(
        child: ListView(
          children: <Widget>[
            ListTile(
              title: const Text('Wallet'),
              onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(
                builder: (_) => const WalletScreen(balance: 0, recoveryPhrase: ''),
              )),
            ),
            ListTile(
              title: const Text('Help center'),
              onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(
                builder: (_) => const HelpCenterScreen(),
              )),
            ),
          ],
        ),
      ),
      body: Column(
        children: <Widget>[
          Padding(padding: const EdgeInsets.all(12), child: Text(_banner)),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: TextField(
              decoration: const InputDecoration(labelText: 'Search orders'),
              onChanged: _search,
            ),
          ),
          Expanded(
            child: ListView.builder(
              itemCount: _rows.length,
              itemBuilder: (BuildContext context, int index) {
                final row = _rows[index];
                return ListTile(
                  title: Text('${row['title']}'),
                  subtitle: Text('${row['status']}'),
                  trailing: Text('${row['total']} EUR'),
                  onTap: () => _openReceipt(row['id'] as int),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
