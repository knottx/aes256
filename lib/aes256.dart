import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// A utility class for AES-256 encryption and decryption using PBKDF2 + AES-GCM.
///
/// Payload layout:
///
/// salt(16) + nonce(12) + ciphertext + authentication tag (MAC)

class Aes256 {
  Aes256._();

  /// 128-bit salt
  static const _saltLength = 16;

  /// 96-bit nonce (recommended for GCM)
  static const _nonceLength = 12;

  /// crank this as needed for your perf/security
  static const _iterations = 100000;

  static final _aes = AesGcm.with256bits();

  static List<int> _randomBytes(int n) {
    return List<int>.generate(
      n,
      (_) => Random.secure().nextInt(256),
    );
  }

  static Future<SecretKey> _deriveKey({
    required String passphrase,
    required List<int> salt,
  }) async {
    final kdf = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: _iterations,
      bits: 256,
    );
    final key = await kdf.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );
    return key;
  }

  /// Encrypts [text] with AES-256-GCM using a key derived from [passphrase].
  /// Returns a base64 string of the versioned payload (see layout above).
  static Future<String> encrypt({
    required String text,
    required String passphrase,
  }) async {
    final salt = _randomBytes(_saltLength);
    final nonce = _randomBytes(_nonceLength);
    final secretKey = await _deriveKey(passphrase: passphrase, salt: salt);

    final clearBytes = utf8.encode(text);
    final box = await _aes.encrypt(
      clearBytes,
      secretKey: secretKey,
      nonce: nonce,
    );

    final payload = BytesBuilder(copy: false)
      ..add(salt)
      ..add(box.nonce)
      ..add(box.cipherText)
      ..add(box.mac.bytes);

    return base64.encode(payload.toBytes());
  }

  /// Decrypts a base64 payload created by [encrypt].
  /// Returns the decrypted string.
  /// Throws [ArgumentError] if the payload is truncated or missing the MAC.
  static Future<String> decrypt({
    required String encrypted,
    required String passphrase,
  }) async {
    final bytes = base64.decode(encrypted);
    if (bytes.length <= _saltLength + _nonceLength + 16) {
      throw ArgumentError('Payload truncated.');
    }

    final salt = bytes.sublist(0, _saltLength);
    final nonce = bytes.sublist(_saltLength, _saltLength + _nonceLength);

    final ctAndMac = bytes.sublist(_saltLength + _nonceLength);
    if (ctAndMac.length < 16) {
      throw ArgumentError('Missing authentication tag.');
    }

    final macBytes = ctAndMac.sublist(ctAndMac.length - 16);
    final cipherText = ctAndMac.sublist(0, ctAndMac.length - 16);

    final secretKey = await _deriveKey(
      passphrase: passphrase,
      salt: salt,
    );

    final clear = await _aes.decrypt(
      SecretBox(
        cipherText,
        nonce: nonce,
        mac: Mac(macBytes),
      ),
      secretKey: secretKey,
    );

    return utf8.decode(clear);
  }
}
