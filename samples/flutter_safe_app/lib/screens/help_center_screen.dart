import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

/// Help center and support chat. The website opens in an in-app browser tab, which keeps
/// its own cookies and has no bridge into the app or its session.
class HelpCenterScreen extends StatelessWidget {
  const HelpCenterScreen({super.key});

  static final Uri _helpCenter = Uri.https('help.pocketshop.example', '/app');

  Future<void> _open() async {
    await launchUrl(_helpCenter, mode: LaunchMode.inAppBrowserView);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Help center')),
      body: Center(
        child: FilledButton(onPressed: _open, child: const Text('Open the help center')),
      ),
    );
  }
}
