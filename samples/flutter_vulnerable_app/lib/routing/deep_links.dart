import 'dart:async';

import 'package:flutter/material.dart';
import 'package:uni_links/uni_links.dart';
import 'package:url_launcher/url_launcher.dart';

import '../screens/help_center_screen.dart';

/// Opens pocketshop://open/... and https://pocketshop.example/... links.
class DeepLinkHandler {
  StreamSubscription<Uri?>? _subscription;

  void listen(GlobalKey<NavigatorState> navigatorKey) {
    _subscription = uriLinkStream.listen((Uri? uri) {
      if (uri != null) {
        _open(uri, navigatorKey.currentState);
      }
    });
  }

  Future<void> _open(Uri uri, NavigatorState? navigator) async {
    final action = uri.pathSegments.isEmpty ? '' : uri.pathSegments.first;
    switch (action) {
      case 'help':
        await navigator?.push(MaterialPageRoute<void>(
          builder: (_) => HelpCenterScreen(initialUrl: uri.queryParameters['page']), // [D17]
        ));
        break;
      case 'promo':
        await launchUrl(Uri.parse(uri.queryParameters['url']!), mode: LaunchMode.externalApplication); // [D18]
        break;
    }
  }

  void dispose() => _subscription?.cancel();
}
