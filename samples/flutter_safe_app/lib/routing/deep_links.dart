import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';

import '../config/app_config.dart';

/// Opens verified https://pocketshop.example/... links inside the app. A link only selects
/// a screen of the app; it never carries an address to load.
class DeepLinkHandler {
  final AppLinks _appLinks = AppLinks();
  StreamSubscription<Uri>? _subscription;

  void listen(GlobalKey<NavigatorState> navigatorKey) {
    _subscription = _appLinks.uriLinkStream.listen((Uri uri) {
      if (uri.scheme == 'https' && uri.host == AppConfig.appLinkHost) {
        _open(uri, navigatorKey.currentState);
      }
    });
  }

  void _open(Uri uri, NavigatorState? navigator) {
    final action = uri.pathSegments.isEmpty ? '' : uri.pathSegments.first;
    switch (action) {
      case 'help':
        navigator?.pushNamed('/help');
      case 'orders':
        final orderId = int.tryParse(uri.queryParameters['id'] ?? '');
        if (orderId != null) {
          navigator?.pushNamed('/orders', arguments: orderId);
        }
    }
  }

  void dispose() => _subscription?.cancel();
}
