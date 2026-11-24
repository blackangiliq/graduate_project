/// Backend endpoints and keys used by the app.
class AppConfig {
  AppConfig._();

  static const String apiBaseUrl = 'http://api.pocketshop.example/v1'; // [D01]
  static const String helpCenterUrl = 'https://help.pocketshop.example/app';

  // Local backend for the Android emulator.
  static const String emulatorApiBaseUrl = 'http://10.0.2.2:8080/v1'; // [D25]

  // Receipts are uploaded straight to the S3 bucket.
  static const String receiptBucket = 'pocketshop-receipts';
  static const String awsRegion = 'eu-central-1';
  static const String awsAccessKeyId = 'AKIAIOSFODNN7EXAMPLE'; // [D02]

  // Parcel tracking partner.
  static const String shippingApiKey = '1a2b3c4d5e6f708192a3b4c5d6e7f809'; // [D03]

  // Admin tools in the drawer call Supabase directly.
  static const String supabaseUrl = 'https://supabase.pocketshop.example';
  static const String supabaseServiceRoleKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBvY2tldHNob3Atc2FtcGxlIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY3MjUzMTIwMCwiZXhwIjoxOTg4MTUwNDAwfQ.c2FtcGxlIHNpZ25hdHVyZSAtIG5vdCBhIHJlYWwga2V5'; // [D04]
}
