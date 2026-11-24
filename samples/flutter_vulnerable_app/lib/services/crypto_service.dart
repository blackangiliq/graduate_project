import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

/// Encrypts the offline wallet backup and the saved card, and makes one-time codes.
class CryptoService {
  CryptoService()
      : _key = Key.fromUtf8('pocketshop-wallet-key-2023-v1-32'), // [D11]
        _iv = IV.fromUtf8('pocketshop-iv-16'); // [D12]

  final Key _key;
  final IV _iv;

  late final Encrypter _backupCipher = Encrypter(AES(_key, mode: AESMode.ecb)); // [D10]
  late final Encrypter _cardCipher = Encrypter(AES(_key, mode: AESMode.cbc));

  String encryptBackup(String json) => _backupCipher.encrypt(json, iv: _iv).base64;

  String decryptBackup(String data) => _backupCipher.decrypt64(data, iv: _iv);

  String encryptCard(String cardNumber) => _cardCipher.encrypt(cardNumber, iv: _iv).base64;

  /// One-time code sent by SMS to confirm a wallet transfer.
  String transferCode() {
    final otp = 100000 + Random().nextInt(900000); // [D13]
    return otp.toString();
  }

  /// Checksum shown next to an exported receipt so the customer can compare copies.
  String receiptChecksum(List<int> pdfBytes) => sha256.convert(pdfBytes).toString(); // [D28]
}
