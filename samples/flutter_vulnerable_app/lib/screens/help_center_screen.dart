import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../config/app_config.dart';
import '../services/auth_service.dart';

/// Help center and support chat, served by the website.
class HelpCenterScreen extends StatefulWidget {
  const HelpCenterScreen({super.key, this.initialUrl});

  final String? initialUrl;

  @override
  State<HelpCenterScreen> createState() => _HelpCenterScreenState();
}

class _HelpCenterScreenState extends State<HelpCenterScreen> {
  late final WebViewController _controller;

  @override
  void initState() {
    super.initState();
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted) // [D32]
      ..addJavaScriptChannel('PocketShopApp', onMessageReceived: _onMessage) // [D15]
      ..loadRequest(Uri.parse(widget.initialUrl ?? AppConfig.helpCenterUrl));
    final platform = _controller.platform;
    if (platform is AndroidWebViewController) {
      // Offline help pages are unpacked to the app folder.
      platform.setAllowFileAccess(true); // [D16]
    }
  }

  /// The support chat asks the app for the session to open the customer's tickets.
  Future<void> _onMessage(JavaScriptMessage message) async {
    if (message.message == 'session') {
      final session = await AuthService().currentToken();
      await _controller.runJavaScript('window.onPocketShopSession(${jsonEncode(session)})');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Help center')),
      body: WebViewWidget(controller: _controller),
    );
  }
}
