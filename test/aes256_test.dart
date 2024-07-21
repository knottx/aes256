import 'package:aes256/aes256.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  final text = 'Hello World!';
  final passphrase = 'passphrase';

  test('Verify that the encryption and decryption process works correctly.',
      () async {
    final encrypted = await Aes256.encrypt(
      text: text,
      passphrase: passphrase,
    );

    final decrypted = await Aes256.decrypt(
      encrypted: encrypted,
      passphrase: passphrase,
    );

    expect(decrypted, equals(text));
  });

  test('Verify that encryption generates a different value each time.',
      () async {
    final encrypted1 = Aes256.encrypt(
      text: text,
      passphrase: passphrase,
    );
    final encrypted2 = Aes256.encrypt(
      text: text,
      passphrase: passphrase,
    );

    expect(encrypted1, isNot(equals(encrypted2)));
  });

  test('Decryption fails with an incorrect passphrase', () async {
    final encrypted = await Aes256.encrypt(
      text: text,
      passphrase: passphrase,
    );

    expect(
      () async => Aes256.decrypt(
        encrypted: encrypted,
        passphrase: 'incorrect passphrase',
      ),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );
  });
}
