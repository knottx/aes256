import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// AES-256-GCM encryption and decryption with a key derived from a passphrase
/// using PBKDF2-HMAC-SHA256.
///
/// [encrypt] returns Base64 (standard alphabet, padded) of this byte layout:
///
/// ```text
/// salt(16) + nonce(12) + ciphertext + tag(16)
/// ```
///
/// A fresh random salt and nonce are generated for every call, so encrypting
/// the same text twice produces different output.
class Aes256 {
  Aes256._();

  /// 128-bit salt.
  static const int _saltLength = 16;

  /// 96-bit nonce (recommended for GCM).
  static const int _nonceLength = 12;

  /// 128-bit GCM authentication tag.
  static const int _macLength = 16;

  /// Bytes in a payload that carries an empty plaintext.
  static const int _overheadLength = _saltLength + _nonceLength + _macLength;

  /// PBKDF2 work factor.
  static const int _iterations = 100000;

  static final AesGcm _aes = AesGcm.with256bits();

  static final Random _random = Random.secure();

  static Uint8List _randomBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }

  static Future<SecretKey> _deriveKey({
    required String passphrase,
    required List<int> salt,
  }) {
    final kdf = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: _iterations,
      bits: 256,
    );
    return kdf.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );
  }

  /// Encrypts [text] with AES-256-GCM using a key derived from [passphrase].
  ///
  /// Returns the Base64-encoded payload described in [Aes256].
  static Future<String> encrypt({
    required String text,
    required String passphrase,
  }) async {
    final salt = _randomBytes(_saltLength);
    final nonce = _randomBytes(_nonceLength);
    final secretKey = await _deriveKey(passphrase: passphrase, salt: salt);

    final box = await _aes.encrypt(
      utf8.encode(text),
      secretKey: secretKey,
      nonce: nonce,
    );

    const cipherTextOffset = _saltLength + _nonceLength;
    final cipherText = box.cipherText;
    final payload = Uint8List(_overheadLength + cipherText.length)
      ..setAll(0, salt)
      ..setAll(_saltLength, nonce)
      ..setAll(cipherTextOffset, cipherText)
      ..setAll(cipherTextOffset + cipherText.length, box.mac.bytes);

    return base64.encode(payload);
  }

  /// Decrypts a Base64 payload created by [encrypt] and returns the text.
  ///
  /// Throws:
  /// - [FormatException] if [encrypted] is not valid Base64.
  /// - [ArgumentError] if the payload is too short to hold a salt, nonce, and
  ///   authentication tag.
  /// - [SecretBoxAuthenticationError] if [passphrase] is wrong or the payload
  ///   has been modified.
  static Future<String> decrypt({
    required String encrypted,
    required String passphrase,
  }) async {
    final bytes = base64.decode(encrypted);
    if (bytes.length < _overheadLength) {
      throw ArgumentError('Payload truncated.');
    }

    const cipherTextOffset = _saltLength + _nonceLength;
    final macOffset = bytes.length - _macLength;

    final salt = bytes.sublist(0, _saltLength);
    final secretKey = await _deriveKey(passphrase: passphrase, salt: salt);

    final clear = await _aes.decrypt(
      SecretBox(
        bytes.sublist(cipherTextOffset, macOffset),
        nonce: bytes.sublist(_saltLength, cipherTextOffset),
        mac: Mac(bytes.sublist(macOffset)),
      ),
      secretKey: secretKey,
    );

    return utf8.decode(clear);
  }
}
