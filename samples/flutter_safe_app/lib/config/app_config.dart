/// Backend endpoints used by the app. Keys of third-party services stay on the server; the
/// app only holds the customer's own session.
class AppConfig {
  AppConfig._();

  static const String apiBaseUrl = 'https://api.pocketshop.example/v1';

  /// Host of the verified app links (Android App Links, iOS universal links).
  static const String appLinkHost = 'pocketshop.example';
}
