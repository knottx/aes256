# 🔐 AES256

A lightweight, modern, and secure **AES-256-GCM** encryption library for Dart & Flutter.  
Designed with strong defaults, clean APIs, and seamless usability across mobile, web, and server environments.

👉 **Live Demo:** [https://knottx.dev/aes256](https://knottx.github.io/aes256)

---

## 🚀 Features

- **AES-256-GCM** — Authenticated encryption with integrity protection
- **PBKDF2-HMAC-SHA256** — Strong password-based key derivation
- **100,000 iterations** — Secure default against brute-force attacks
- **Random salt & nonce** — Automatically handled
- **Stateless API** — Easy to integrate into any architecture
- **Pure Dart** — Works on Flutter, Dart VM, and Web

---

## 🔧 Usage

```dart
import 'package:aes256/aes256.dart';

void main() async {
  // Encrypt
  final encrypted = await Aes256.encrypt(
    text: 'Hello world',
    passphrase: 'my-passphrase',
  );

  // Decrypt
  final decrypted = await Aes256.decrypt(
    encrypted: encrypted,
    passphrase: 'my-passphrase',
  );

  print(decrypted); // Hello world
}
```

---

## 🔒 How It Works

AES256 outputs a structured, self-contained binary payload:

```text
salt(16) + nonce(12) + ciphertext + tag
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

---

## 🧪 Example Output (Base64)

```text
QTI1NkdDTQEBEBcAAAAAAAAAACZ1FqvX…(ciphertext)…Lk5h0nA=
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

Yes — as long as the other implementation uses the same payload structure and AES-256-GCM + PBKDF2-SHA256 parameters.

This library follows a clean and predictable binary format:

```text
salt(16) + nonce(12) + ciphertext + tag
```

Any implementation that generates output in the same sequence will decrypt correctly.

### **Does it work on Flutter Web?**

Yes — it is pure Dart with no native bindings.
