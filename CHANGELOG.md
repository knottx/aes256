## 2.2.4

- Update live demo link

## 2.2.3

- Fix: ciphertext of an empty string can now be decrypted. Previously
  `decrypt` rejected it as "Payload truncated."
- Document the exceptions `decrypt` throws. Behavior, defaults, and the
  `salt(16) + nonce(12) + ciphertext + tag(16)` format are unchanged; output
  stays compatible with earlier 2.2.x releases in both directions, except
  that 2.2.2 and earlier still can't decrypt an empty string.
- Internal cleanup: one `Random.secure()` instance and a single preallocated
  output buffer. No measurable performance change, since PBKDF2 dominates.
- Correct the `flutter` lower bound to 3.19.0, the first release with Dart
  3.3. This matches what the existing constraints already required.
- Tests: fixtures from 2.2.2, Unicode, empty and large payloads, tampering,
  and malformed input, on the VM and in Chrome.
- README: fix the demo link, platform notes, and example output.
- Example: rebuilt as a single-screen AES-256 playground (Material 3, light and
  dark themes, responsive layout).

## 2.2.2

- Update minimum sdk.

## 2.2.1

- Update example

## 2.2.0

- Updated payload structure to follow a fully explicit sequence:
  salt(16) + nonce(12) + ciphertext + tag
  Improved cross-language compatibility with libraries using the same payload

## 2.1.3

- Update iterations 100,000

## 2.1.2

- Update example
- Update meta data

## 2.1.1

- Using PBKDF2 + AES-GCM only

## 2.0.0

- Using PBKDF2 + AES-GCM with decryptLegacy

## 1.1.0

- Update Readme.

## 1.0.8

- Named parameters with required.

## 1.0.7

- Remove unnecessary async, update throw argument error.

## 1.0.6

- Update Readme.

## 1.0.5

- Remove unnecessary async.

## 1.0.4

- Add API Docs.

## 1.0.3

- Add Demo.

## 1.0.2

- Update Readme.

## 1.0.1

- Update information.

## 1.0.0

- Initial release.
