// Pocket Shop written securely: the same app as samples/flutter_vulnerable_app.
// FOR TESTING THE ANALYZER: it has no vulnerabilities, so every finding is a false positive.
import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/material.dart';

import 'routing/deep_links.dart';
import 'screens/help_center_screen.dart';
import 'screens/login_screen.dart';
import 'screens/orders_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp();
  runApp(const PocketShopApp());
}

class PocketShopApp extends StatefulWidget {
  const PocketShopApp({super.key});

  @override
  State<PocketShopApp> createState() => _PocketShopAppState();
}

class _PocketShopAppState extends State<PocketShopApp> {
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();
  final DeepLinkHandler _deepLinks = DeepLinkHandler();

  @override
  void initState() {
    super.initState();
    _deepLinks.listen(_navigatorKey);
  }

  @override
  void dispose() {
    _deepLinks.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Pocket Shop',
      navigatorKey: _navigatorKey,
      theme: ThemeData(colorSchemeSeed: Colors.teal),
      routes: <String, WidgetBuilder>{
        '/': (_) => const LoginScreen(),
        '/orders': (_) => const OrdersScreen(),
        '/help': (_) => const HelpCenterScreen(),
      },
    );
  }
}
