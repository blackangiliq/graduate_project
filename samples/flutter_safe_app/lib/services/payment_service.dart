import 'api_client.dart';

/// Charges the saved card. The payment provider's key stays on the server, which creates
/// the charge for the signed-in customer and computes the amount from the order.
class PaymentService {
  PaymentService(this._api);

  final ApiClient _api;

  Future<bool> payOrder(int orderId, String cardReference) async {
    final body = await _api.post('/orders/$orderId/payment', <String, dynamic>{
      'card': cardReference,
    });
    return body['status'] == 'succeeded';
  }
}
