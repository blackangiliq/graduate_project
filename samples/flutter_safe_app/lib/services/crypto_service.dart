import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';

/// Encrypts the offline wallet backup with AES-GCM. The key is random, made on the device
/// and kept in the Android Keystore / iOS Keychain; every message gets a fresh nonce.
class CryptoService {
  static const String _keyName = 'wallet_backup_key';
  static const FlutterSecureStorage _storage = FlutterSecureStorage();
  static const int _nonceLength = 12;
  final Random _random = Random.secure();

  Future<Uint8List> _backupKey() async {
    final stored = await _storage.read(key: _keyName);
    if (stored != null) {
      return base64Decode(stored);
    }
    final fresh = _randomBytes(32);
    await _storage.write(key: _keyName, value: base64Encode(fresh));
    return fresh;
  }

  Uint8List _randomBytes(int length) =>
      Uint8List.fromList(List<int>.generate(length, (_) => _random.nextInt(256)));

  Future<GCMBlockCipher> _cipher(bool encrypt, Uint8List nonce) async {
    final parameters = AEADParameters(KeyParameter(await _backupKey()), 128, nonce, Uint8List(0));
    return GCMBlockCipher(AESEngine())..init(encrypt, parameters);
  }

  /// Nonce, ciphertext and tag, base64 encoded.
  Future<String> encryptBackup(String json) async {
    final nonce = _randomBytes(_nonceLength);
    final sealed = (await _cipher(true, nonce)).process(Uint8List.fromList(utf8.encode(json)));
    return base64Encode(<int>[...nonce, ...sealed]);
  }

  Future<String> decryptBackup(String data) async {
    final bytes = base64Decode(data);
    final cipher = await _cipher(false, bytes.sublist(0, _nonceLength));
    return utf8.decode(cipher.process(bytes.sublist(_nonceLength)));
  }

  /// Checksum shown next to an exported receipt so the customer can compare copies.
  String receiptChecksum(List<int> pdfBytes) => sha256.convert(pdfBytes).toString();
}
