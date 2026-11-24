import 'dart:math';

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

import '../services/auth_service.dart';
import '../storage/order_database.dart';
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
  late final String _banner = _banners[Random().nextInt(_banners.length)];
  bool _bannerHidden = false;

  @override
  void initState() {
    super.initState();
    _search('');
    SharedPreferences.getInstance().then((SharedPreferences prefs) {
      if (mounted) {
        setState(() => _bannerHidden = prefs.getBool('banner_hidden') ?? false);
      }
    });
  }

  Future<void> _hideBanner() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('banner_hidden', true);
    if (mounted) {
      setState(() => _bannerHidden = true);
    }
  }

  Future<void> _search(String text) async {
    final rows = await _orders.search(text);
    if (mounted) {
      setState(() => _rows = rows);
    }
  }

  Future<void> _openReceipt(int orderId) async {
    final link = await _auth.receiptLink(orderId);
    await launchUrl(link, mode: LaunchMode.inAppBrowserView);
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
                builder: (_) => const WalletScreen(balance: 0, address: '', recoveryPhrase: ''),
              )),
            ),
            ListTile(
              title: const Text('Help center'),
              onTap: () => Navigator.of(context).pushNamed('/help'),
            ),
          ],
        ),
      ),
      body: Column(
        children: <Widget>[
          if (!_bannerHidden)
            ListTile(
              title: Text(_banner),
              trailing: IconButton(icon: const Icon(Icons.close), onPressed: _hideBanner),
            ),
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
