// Pocket Shop: a deliberately vulnerable Flutter app. FOR TESTING THE ANALYZER ONLY.
// The [Dxx] tags are neutral markers used by the evaluation; their meaning is stored in
// samples/flutter_ground_truth.json. Some tagged lines are safe on purpose.
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:hive/hive.dart';
import 'package:path_provider/path_provider.dart';

import 'routing/deep_links.dart';
import 'screens/login_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await dotenv.load(fileName: 'assets/.env');
  await Firebase.initializeApp();
  // Phone sign-in of the wallet; the QA build skipped the app verification.
  await FirebaseAuth.instance.setSettings(appVerificationDisabledForTesting: true); // [D23]
  final dir = await getApplicationDocumentsDirectory();
  Hive.init(dir.path);
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
      theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
      home: const LoginScreen(),
    );
  }
}
