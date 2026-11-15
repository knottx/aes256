# 🔐 AES256

A lightweight, modern, and secure **AES-256-GCM** encryption library for Flutter.  
Designed with strong defaults, clean APIs, and the same output on every platform.

👉 **Live Demo:** [https://knottx.github.io/aes256/](https://knottx.github.io/aes256/)

---

## 🚀 Features

- **AES-256-GCM** — Authenticated encryption with integrity protection
- **PBKDF2-HMAC-SHA256** — Strong password-based key derivation
- **100,000 iterations** — Secure default against brute-force attacks
- **Random salt & nonce** — Automatically handled
- **Stateless API** — Easy to integrate into any architecture
- **Every Flutter platform** — Native acceleration on Android, iOS, and macOS; Web Crypto in browsers; pure Dart on Windows and Linux

---

## 🔧 Usage

```dart
import 'package:aes256/aes256.dart';

final encrypted = await Aes256.encrypt(
  text: 'Hello world',
  passphrase: 'my-passphrase',
);

final decrypted = await Aes256.decrypt(
  encrypted: encrypted,
  passphrase: 'my-passphrase',
);
```

`decrypt` throws:

- `SecretBoxAuthenticationError` (from `package:cryptography`) for a wrong passphrase or modified ciphertext
- `FormatException` for input that isn't valid Base64
- `ArgumentError` for a payload too short to contain a salt, nonce, and tag

---

## 🔒 How It Works

AES256 outputs Base64 (standard alphabet, padded) of a self-contained binary payload:

```text
salt(16) + nonce(12) + ciphertext + tag(16)
```

### Security Parameters

| Component      | Value                     |
| -------------- | ------------------------- |
| Cipher         | **AES-256-GCM**           |
| Key Derivation | **PBKDF2-HMAC-SHA256**    |
| Iterations     | **100,000**               |
| Salt           | 16 bytes (random, public) |
| Nonce          | 12 bytes (random, public) |
| Auth Tag       | 16 bytes                  |
| Integrity      | Built-in (GCM tag)        |

### Why salt & nonce are public

Salt and nonce do **not** provide secrecy by themselves — they ensure uniqueness and key strengthening.  
The **passphrase-derived key** is the only secret.  
Exposing salt/nonce does not weaken the encryption.

### Performance

Key derivation is deliberately slow and accounts for almost all of the time spent in `encrypt` and `decrypt`. On an Apple M2 Pro, one call takes about 9 ms in Chrome (Web Crypto) and about 0.4 s with the pure Dart implementation used on Windows, Linux, and in tests. The pure Dart version briefly yields to the event loop so the UI stays responsive.

---

## 🧪 Example Output (Base64)

`Hello World!` encrypted with the passphrase `passphrase`:

```text
0F9DWJW8a+cWCSXF80S+l52+MPA6xj6XVTUyf9ItcZspDLo+hOPTG0V6kQTecBLyq134OQnVr2o=
```

---

## 🛡️ Security Notes

- Always use a strong passphrase
- AES-GCM requires a unique nonce per encryption — this library handles it automatically
- For high-security systems, keep actual keys in secure storage or server-side only

---

## ❓ FAQ

### **Is the encrypted output safe to store publicly?**

Yes — as long as the passphrase remains secret.

### **Can I decrypt data encrypted in another language?**

Yes — as long as the other implementation uses the same payload structure and AES-256-GCM + PBKDF2-HMAC-SHA256 parameters (100,000 iterations, 32-byte key, UTF-8 passphrase and plaintext).

```text
salt(16) + nonce(12) + ciphertext + tag(16)
```

For example, Node.js `crypto.pbkdf2Sync` with `createDecipheriv('aes-256-gcm', ...)` decrypts this package's output.

### **Does it work on Flutter Web?**

Yes. In browsers the library uses the Web Crypto API, which needs a secure context (HTTPS or `localhost`); otherwise it falls back to the pure Dart implementation from `package:cryptography`. The output is identical on every platform.

### **Can I use it in a Dart-only (non-Flutter) project?**

Not currently. The package depends on `cryptography_flutter` for native acceleration, so `dart pub get` fails outside a Flutter project ("requires the Flutter SDK"). In a server or CLI app, use `package:cryptography` directly with the same parameters.
