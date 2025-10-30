import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' hide Hmac;
import 'package:cryptography/cryptography.dart';
import 'package:encrypt/encrypt.dart';

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
  static const _iterations = 100000;

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

    final hdrStr = utf8.decode(
      bytes.sublist(0, _hdr.length),
      allowMalformed: false,
    );
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

  /// Decrypts a base64 encoded string using AES-256 with the given passphrase.
  ///
  /// This method decrypts the provided `encrypted` string, which must be the result
  /// of the `encrypt` method. It extracts the salt and encrypted data, derives
  /// the key and IV from the passphrase and salt, and then decrypts the data.
  ///
  /// Parameters:
  /// - `encrypted`: The base64 encoded string containing the encrypted data and salt.
  /// - `passphrase`: The passphrase used to derive the key and IV.
  ///
  /// Returns:
  /// - The decrypted string if decryption is successful, or `null` if the decryption
  ///   fails (e.g., if the encrypted data does not start with 'Salted__').
  ///
  /// Throws:
  /// - An error if decryption fails.
  static Future<String> decryptLegacy({
    required String encrypted,
    required String passphrase,
  }) async {
    final enc = base64.decode(encrypted);
    final saltedPrefix = utf8.decode(enc.sublist(0, 8));

    if (saltedPrefix != 'Salted__') {
      return decrypt(
        encrypted: encrypted,
        passphrase: passphrase,
      );
    }

    final salt = enc.sublist(8, 16);
    final text = enc.sublist(16);
    final salted = _generateSaltedKeyAndIv(
      passphrase: passphrase,
      salt: salt,
    );

    final key = Key(Uint8List.fromList(salted.sublist(0, 32)));
    final iv = IV(Uint8List.fromList(salted.sublist(32, 48)));
    final encryptor = Encrypter(AES(key, mode: AESMode.cbc));

    return encryptor.decrypt(Encrypted(Uint8List.fromList(text)), iv: iv);
  }

  /// Generates a salted key and initialization vector (IV) from a passphrase and salt.
  ///
  /// This method derives a key and IV for AES-256 encryption from the given
  /// passphrase and salt using the MD5 hash function.
  ///
  /// Parameters:
  /// - `passphrase`: The passphrase used to generate the key.
  /// - `salt`: The salt used in key and IV generation.
  ///
  /// Returns:
  /// - A list of integers representing the salted key and IV.
  static List<int> _generateSaltedKeyAndIv({
    required String passphrase,
    required List<int> salt,
  }) {
    final pass = utf8.encode(passphrase);
    var dx = <int>[];
    var salted = <int>[];

    while (salted.length < 48) {
      final data = dx + pass + salt;
      dx = md5.convert(data).bytes;
      salted.addAll(dx);
    }

    return salted;
  }
}
