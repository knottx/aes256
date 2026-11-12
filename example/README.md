# AES-256 Playground

The live demo for [`package:aes256`](https://pub.dev/packages/aes256):
<https://knottx.dev/aes256/>

Encrypt text with a passphrase, copy the Base64 result, or paste ciphertext to
decrypt it. Everything runs locally and stays in memory.

```sh
flutter run -d chrome
flutter build web --release --base-href /aes256/
```

Needs Flutter 3.47 or later (for `package:material_ui`). The `aes256` package
itself supports older SDKs.
