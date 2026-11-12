import 'package:example/main.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

Finder _field(String label) => find.widgetWithText(TextField, label);

Finder _primaryButton(String label) =>
    find.descendant(of: find.byType(FilledButton), matching: find.text(label));

/// Advances fake time until the running operation finishes. (PBKDF2 yields to
/// the event loop with short timers, which run on the test's fake clock.)
Future<void> _settle(WidgetTester tester) async {
  for (var i = 0; i < 1000; i++) {
    await tester.pump(const Duration(milliseconds: 10));
    if (find.byType(CircularProgressIndicator).evaluate().isEmpty) return;
  }
  fail('Operation did not finish.');
}

void main() {
  testWidgets('encrypt, use in decrypt, decrypt', (tester) async {
    await tester.pumpWidget(const PlaygroundApp());

    await tester.enterText(_field('Plaintext'), 'สวัสดี 🔐');
    await tester.enterText(_field('Passphrase'), 'secret');
    await tester.tap(_primaryButton('Encrypt'));
    await tester.pump();
    expect(find.text('Encrypting…'), findsOneWidget);
    await _settle(tester);

    final ciphertext = tester.widget<Text>(find.byKey(resultKey)).data!;
    expect(ciphertext, matches(RegExp(r'^[A-Za-z0-9+/]+=*$')));

    await tester.tap(find.text('Use in Decrypt'));
    await tester.pump();
    expect(find.text('Decrypted text appears here.'), findsOneWidget);
    expect(
      tester.widget<TextField>(_field('Ciphertext (Base64)')).controller!.text,
      ciphertext,
    );

    await tester.tap(_primaryButton('Decrypt'));
    await _settle(tester);
    expect(find.text('สวัสดี 🔐'), findsOneWidget);
  });

  testWidgets('shows inline errors for missing input', (tester) async {
    await tester.pumpWidget(const PlaygroundApp());
    await tester.tap(_primaryButton('Encrypt'));
    await tester.pump();
    expect(find.text('Enter some text.'), findsOneWidget);
    expect(find.text('Enter a passphrase.'), findsOneWidget);

    await tester.tap(find.text('Decrypt'));
    await tester.pump();
    await tester.tap(_primaryButton('Decrypt'));
    await tester.pump();
    expect(find.text('Paste ciphertext.'), findsOneWidget);
  });

  testWidgets('explains malformed ciphertext and wrong passphrases', (
    tester,
  ) async {
    await tester.pumpWidget(const PlaygroundApp());
    await tester.tap(find.text('Decrypt'));
    await tester.pump();
    await tester.enterText(_field('Passphrase'), 'wrong');

    await tester.enterText(_field('Ciphertext (Base64)'), 'not base64!');
    await tester.tap(_primaryButton('Decrypt'));
    await _settle(tester);
    expect(find.text('This isn’t valid Base64 ciphertext.'), findsOneWidget);

    // Produced by aes256 2.2.2 with the passphrase "passphrase".
    await tester.enterText(
      _field('Ciphertext (Base64)'),
      '0F9DWJW8a+cWCSXF80S+l52+MPA6xj6XVTUyf9ItcZspDLo+hOPTG0V6kQTecBLyq134\n'
      'OQnVr2o=',
    );
    await tester.tap(_primaryButton('Decrypt'));
    await _settle(tester);
    expect(
      find.text('Wrong passphrase, or the ciphertext was modified.'),
      findsOneWidget,
    );
  });

  testWidgets('drops results for stale inputs', (tester) async {
    await tester.pumpWidget(const PlaygroundApp());
    await tester.enterText(_field('Plaintext'), 'first');
    await tester.enterText(_field('Passphrase'), 'secret');
    await tester.tap(_primaryButton('Encrypt'));
    await tester.pump();

    // Edit while the first encryption is still running.
    await tester.enterText(_field('Plaintext'), 'second');
    await tester.pump();
    expect(_primaryButton('Encrypt'), findsOneWidget);

    // Let the stale operation finish.
    for (var i = 0; i < 200; i++) {
      await tester.pump(const Duration(milliseconds: 10));
    }
    expect(find.byKey(resultKey), findsNothing);
    expect(find.text('Encrypted output appears here.'), findsOneWidget);
  });

  testWidgets('masks the passphrase until toggled', (tester) async {
    await tester.pumpWidget(const PlaygroundApp());
    bool obscured() => tester
        .widget<EditableText>(
          find.descendant(
            of: _field('Passphrase'),
            matching: find.byType(EditableText),
          ),
        )
        .obscureText;

    expect(obscured(), isTrue);
    await tester.tap(find.byTooltip('Show passphrase'));
    await tester.pump();
    expect(obscured(), isFalse);
    expect(find.byTooltip('Hide passphrase'), findsOneWidget);
  });

  testWidgets('copies the result', (tester) async {
    String? copied;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String;
        }
        return null;
      },
    );

    await tester.pumpWidget(const PlaygroundApp());
    await tester.enterText(_field('Plaintext'), 'hello');
    await tester.enterText(_field('Passphrase'), 'secret');
    await tester.tap(_primaryButton('Encrypt'));
    await _settle(tester);

    await tester.tap(find.text('Copy'));
    await tester.pump();
    expect(
      copied,
      tester.widget<Text>(find.byKey(resultKey)).data,
    );
    expect(find.text('Copied to clipboard'), findsOneWidget);
  });
}
