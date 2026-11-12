import 'dart:convert';

import 'package:aes256/aes256.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

/// Ciphertexts produced by the implementation. They must keep
/// decrypting with every future version.
const _legacyFixtures = <({String plaintext, String passphrase, String ct})>[
  (
    plaintext: 'Hello World!',
    passphrase: 'passphrase',
    ct: '0F9DWJW8a+cWCSXF80S+l52+MPA6xj6XVTUyf9ItcZspDLo+hOPTG0V6kQTecBLyq134'
        'OQnVr2o=',
  ),
  (
    plaintext: 'สวัสดี 你好 مرحبا Ĉu vi? 🔐🌐👩‍💻\nline two\ttabbed',
    passphrase: 'passphrase',
    ct: 'XWUqy/cpiZLeCFdwAlbZ29NU+lvnbZjorXAVCeqCvMe8/yJObOadl6TqWnoIfbAGP+Gv'
        'wNnh80gEeg5NVus/hhq6gNlRZZEgRpVy7vyr5Pr3rVcoidVS+vreJpt8VoUc3m9Fqqc6'
        'zVpsOxRU9wjbt4yN+I3FF95P/xPPYg==',
  ),
  (
    plaintext: 'payload with unicode passphrase',
    passphrase: 'pässwörd 🔑 รหัสผ่าน',
    ct: 'JE9P/+O0eGudBixnS8SJ+UvoLsN8aMhGuEEH1T+gs1M7xO7bytZBT1fFetwH+roh7wNh'
        'eQp+ZH6RtobjN1UwOCJvPMblvqxf6lre',
  ),
];

/// Decrypts by following the documented layout directly, independent of
/// [Aes256], so the format itself is pinned down.
Future<String> _referenceDecrypt(String encrypted, String passphrase) async {
  final bytes = base64.decode(encrypted);
  final key = await Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 100000,
    bits: 256,
  ).deriveKey(
    secretKey: SecretKey(utf8.encode(passphrase)),
    nonce: bytes.sublist(0, 16),
  );
  final clear = await AesGcm.with256bits().decrypt(
    SecretBox(
      bytes.sublist(28, bytes.length - 16),
      nonce: bytes.sublist(16, 28),
      mac: Mac(bytes.sublist(bytes.length - 16)),
    ),
    secretKey: key,
  );
  return utf8.decode(clear);
}

void main() {
  const text = 'Hello World!';
  const passphrase = 'passphrase';

  final throwsAuthError = throwsA(isA<SecretBoxAuthenticationError>());

  group('round trip', () {
    for (final (name, value) in [
      ('ASCII', text),
      ('Unicode', 'สวัสดี 你好 مرحبا 🔐👩‍💻\nnew line'),
      ('empty', ''),
    ]) {
      test(name, () async {
        final encrypted =
            await Aes256.encrypt(text: value, passphrase: passphrase);
        expect(
          await Aes256.decrypt(encrypted: encrypted, passphrase: passphrase),
          value,
        );
      });
    }

    test('Unicode passphrase', () async {
      const unicodePassphrase = 'pässwörd 🔑 รหัสผ่าน';
      final encrypted =
          await Aes256.encrypt(text: text, passphrase: unicodePassphrase);
      expect(
        await Aes256.decrypt(
          encrypted: encrypted,
          passphrase: unicodePassphrase,
        ),
        text,
      );
    });

    test('large payload', () async {
      final value = List.filled(4096, 'Lorem ipsum สวัสดี 🌐 ').join();
      final encrypted =
          await Aes256.encrypt(text: value, passphrase: passphrase);
      expect(
        await Aes256.decrypt(encrypted: encrypted, passphrase: passphrase),
        value,
      );
    });
  });

  test('encryption generates a different value each time', () async {
    final encrypted1 = await Aes256.encrypt(text: text, passphrase: passphrase);
    final encrypted2 = await Aes256.encrypt(text: text, passphrase: passphrase);
    expect(encrypted1, isNot(encrypted2));
  });

  group('compatibility', () {
    for (final f in _legacyFixtures) {
      test('decrypts  output: ${f.plaintext.split('\n').first}', () async {
        expect(
          await Aes256.decrypt(encrypted: f.ct, passphrase: f.passphrase),
          f.plaintext,
        );
      });
    }

    test('output follows salt(16) + nonce(12) + ciphertext + tag(16)',
        () async {
      const value = 'สวัสดี 🔐';
      final encrypted =
          await Aes256.encrypt(text: value, passphrase: passphrase);
      expect(
        base64.decode(encrypted).length,
        16 + 12 + utf8.encode(value).length + 16,
      );
      expect(await _referenceDecrypt(encrypted, passphrase), value);
    });
  });

  group('rejects', () {
    test('an incorrect passphrase', () async {
      final encrypted =
          await Aes256.encrypt(text: text, passphrase: passphrase);
      expect(
        Aes256.decrypt(encrypted: encrypted, passphrase: 'incorrect'),
        throwsAuthError,
      );
    });

    final regions = {'salt': 0, 'nonce': 16, 'ciphertext': 28, 'tag': -1};
    for (final MapEntry(key: region, value: offset) in regions.entries) {
      test('a tampered $region', () async {
        final bytes = base64.decode(_legacyFixtures.first.ct);
        bytes[offset < 0 ? bytes.length + offset : offset] ^= 0x01;
        expect(
          Aes256.decrypt(
            encrypted: base64.encode(bytes),
            passphrase: _legacyFixtures.first.passphrase,
          ),
          throwsAuthError,
        );
      });
    }

    test('invalid Base64', () {
      expect(
        Aes256.decrypt(encrypted: 'not base64!', passphrase: passphrase),
        throwsFormatException,
      );
    });

    test('a truncated payload', () {
      expect(
        Aes256.decrypt(
          encrypted: base64.encode(List.filled(43, 0)),
          passphrase: passphrase,
        ),
        throwsArgumentError,
      );
    });
  });
}
