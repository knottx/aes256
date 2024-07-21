import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// A utility class for AES-256 encryption and decryption using PBKDF2 + AES-GCM.
/// Payload layout:
///
/// [0..6]  ASCII "A256GCM"
///
/// [7]     version byte = 0x01
///
/// [8]     salt length  (SL)
///
/// [9]     nonce length (NL)
///
/// [10..10+SL-1] salt
///
/// [..+NL-1]     nonce
///
/// [..]         ciphertext || mac (MAC is 16 bytes for AES-GCM here)
class Aes256 {
  Aes256._();

  static const _hdr = 'A256GCM';
  static const _ver = 0x01;

  /// 128-bit salt
  static const _saltLen = 16;

  /// 96-bit nonce (recommended for GCM)
  static const _nonceLen = 12;

  /// crank this as needed for your perf/security
  static const _iterations = 600000;

  static final _rand = Random.secure();
  static final _kdf = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: _iterations,
    bits: 256,
  );
  static final _aes = AesGcm.with256bits();

  static List<int> _randomBytes(int n) =>
      List<int>.generate(n, (_) => _rand.nextInt(256));

  static Future<SecretKey> _deriveKey({
    required String passphrase,
    required List<int> salt,
  }) async {
    final key = await _kdf.deriveKey(
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
    final salt = _randomBytes(_saltLen);
    final nonce = _randomBytes(_nonceLen);
    final secretKey = await _deriveKey(passphrase: passphrase, salt: salt);

    final clearBytes = utf8.encode(text);
    final box = await _aes.encrypt(
      clearBytes,
      secretKey: secretKey,
      nonce: nonce,
    );

    // Build payload
    final header = utf8.encode(_hdr);
    final payload = BytesBuilder(copy: false)
      ..add(header)
      ..add([_ver, _saltLen, _nonceLen])
      ..add(salt)
      ..add(nonce)
      ..add(box.cipherText)
      ..add(box.mac.bytes);

    return base64.encode(payload.toBytes());
  }

  /// Decrypts a base64 payload created by [encrypt].
  /// Throws [ArgumentError]/[StateError] on malformed/invalid inputs or auth failure.
  static Future<String> decrypt({
    required String encrypted,
    required String passphrase,
  }) async {
    final bytes = base64.decode(encrypted);

    // Basic structure checks
    if (bytes.length < 10) {
      throw ArgumentError('Ciphertext too short.');
    }

    final hdrStr =
        utf8.decode(bytes.sublist(0, _hdr.length), allowMalformed: false);
    if (hdrStr != _hdr) {
      throw ArgumentError('Invalid header. Expected "\$._hdr".');
    }

    final version = bytes[_hdr.length];
    if (version != _ver) {
      throw StateError('Unsupported version: $version.');
    }

    final saltLen = bytes[_hdr.length + 1];
    final nonceLen = bytes[_hdr.length + 2];

    final idxSaltStart = _hdr.length + 3;
    final idxSaltEnd = idxSaltStart + saltLen;
    final idxNonceEnd = idxSaltEnd + nonceLen;

    if (bytes.length <= idxNonceEnd + 16) {
      // Need at least some ciphertext + 16-byte MAC
      throw ArgumentError('Payload truncated.');
    }

    final salt = bytes.sublist(idxSaltStart, idxSaltEnd);
    final nonce = bytes.sublist(idxSaltEnd, idxNonceEnd);

    // Split ciphertext and MAC (last 16 bytes)
    final ctAndMac = bytes.sublist(idxNonceEnd);
    if (ctAndMac.length < 16) {
      throw ArgumentError('Missing authentication tag.');
    }
    final macBytes = ctAndMac.sublist(ctAndMac.length - 16);
    final cipherText = ctAndMac.sublist(0, ctAndMac.length - 16);

    final secretKey = await _deriveKey(passphrase: passphrase, salt: salt);

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
