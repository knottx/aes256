# AES256

AES-256-GCM encryption and decryption

- Hash Algo: SHA256
- KDF: PBKDF2
- Iterations: 100,000

Try on [Demo](https://knottx.github.io/aes256)

```dart
import 'package:aes256/aes256.dart';

...
// encryption
final encrypted = await Aes256.encrypt(
    text: 'text',
    passphrase: 'passphrase',
);

// decryption
final decrypted = await Aes256.decrypt(
    encrypted: encrypted,
    passphrase: 'passphrase',
);
...
```
