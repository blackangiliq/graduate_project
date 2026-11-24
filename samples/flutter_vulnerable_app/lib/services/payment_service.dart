import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:http/http.dart' as http;

/// Charges the saved card through the payment provider.
class PaymentService {
  final String _secretKey = dotenv.env['PAYMENT_SECRET_KEY'] ?? ''; // [D24]

  Future<bool> charge(String cardReference, int amountCents) async {
    final response = await http.post(
      Uri.parse('https://api.paygate.example/v1/charges'),
      headers: <String, String>{'Authorization': 'Bearer $_secretKey'},
      body: <String, String>{
        'source': cardReference,
        'amount': '$amountCents',
        'currency': 'eur',
      },
    );
    return response.statusCode == 200;
  }
}
