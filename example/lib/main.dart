import 'package:aes256/aes256.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

void main() {
  runApp(const PlaygroundApp());
}

/// The single accent color; everything else stays neutral.
const _accent = Color(0xFF3F5AA8);

const _monospace = TextStyle(
  fontFamily: 'RobotoMono',
  fontFamilyFallback: ['Menlo', 'Consolas', 'monospace'],
  height: 1.5,
);

class PlaygroundApp extends StatelessWidget {
  const PlaygroundApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AES-256 Playground',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.system,
      theme: _buildTheme(Brightness.light),
      darkTheme: _buildTheme(Brightness.dark),
      home: const PlaygroundPage(),
    );
  }

  ThemeData _buildTheme(Brightness brightness) {
    // Neutral surfaces, with the accent kept only for primary actions and
    // the selected segment.
    final accent = ColorScheme.fromSeed(
      seedColor: _accent,
      brightness: brightness,
    );
    final colorScheme =
        ColorScheme.fromSeed(
          seedColor: _accent,
          brightness: brightness,
          dynamicSchemeVariant: DynamicSchemeVariant.neutral,
        ).copyWith(
          primary: accent.primary,
          onPrimary: accent.onPrimary,
          secondaryContainer: accent.primaryContainer,
          onSecondaryContainer: accent.onPrimaryContainer,
        );

    // A clear outline for keyboard focus; the default is a faint overlay.
    final focusRing = WidgetStateBorderSide.resolveWith(
      (states) => states.contains(WidgetState.focused)
          ? BorderSide(
              color: colorScheme.onSurface,
              width: 2,
              strokeAlign: BorderSide.strokeAlignOutside,
            )
          : null,
    );
    final focusStyle = ButtonStyle(side: focusRing);

    return ThemeData(
      colorScheme: colorScheme,
      inputDecorationTheme: const InputDecorationTheme(
        border: OutlineInputBorder(),
        alignLabelWithHint: true,
      ),
      filledButtonTheme: FilledButtonThemeData(style: focusStyle),
      outlinedButtonTheme: OutlinedButtonThemeData(style: focusStyle),
      iconButtonTheme: IconButtonThemeData(style: focusStyle),
    );
  }
}

enum Mode { encrypt, decrypt }

/// What the last finished operation produced.
class Outcome {
  const Outcome.success(this.mode, String this.value) : error = null;
  const Outcome.failure(this.mode, String this.error) : value = null;

  final Mode mode;
  final String? value;
  final String? error;
}

class PlaygroundPage extends StatefulWidget {
  const PlaygroundPage({super.key});

  @override
  State<PlaygroundPage> createState() => _PlaygroundPageState();
}

class _PlaygroundPageState extends State<PlaygroundPage> {
  // Everything stays in memory for this session only.
  final _plaintext = TextEditingController();
  final _ciphertext = TextEditingController();
  final _passphrase = TextEditingController();

  Mode _mode = Mode.encrypt;
  bool _showPassphrase = false;

  /// Bumped on every input or mode change. A running operation only publishes
  /// its outcome if the generation it started with is still current.
  int _generation = 0;
  int? _runningGeneration;

  Outcome? _outcome;
  String? _textError;
  String? _passphraseError;

  bool get _isBusy => _runningGeneration == _generation;

  TextEditingController get _input =>
      _mode == Mode.encrypt ? _plaintext : _ciphertext;

  @override
  void dispose() {
    _plaintext.dispose();
    _ciphertext.dispose();
    _passphrase.dispose();
    super.dispose();
  }

  /// Invalidates any result or pending operation for the previous inputs.
  void _inputsChanged() {
    setState(() {
      _generation++;
      _outcome = null;
      _textError = null;
      _passphraseError = null;
    });
  }

  void _setMode(Mode mode) {
    _inputsChanged();
    setState(() => _mode = mode);
  }

  Future<void> _submit() async {
    if (_isBusy) return;

    final mode = _mode;
    final text = mode == Mode.encrypt
        ? _plaintext.text
        // Copied Base64 often picks up line breaks or spaces.
        : _ciphertext.text.replaceAll(RegExp(r'\s'), '');
    final passphrase = _passphrase.text;

    setState(() {
      _outcome = null;
      _textError = text.isEmpty
          ? (mode == Mode.encrypt ? 'Enter some text.' : 'Paste ciphertext.')
          : null;
      _passphraseError = passphrase.isEmpty ? 'Enter a passphrase.' : null;
    });
    if (_textError != null || _passphraseError != null) return;

    final generation = _generation;
    setState(() => _runningGeneration = generation);

    Outcome outcome;
    try {
      final value = mode == Mode.encrypt
          ? await Aes256.encrypt(text: text, passphrase: passphrase)
          : await Aes256.decrypt(encrypted: text, passphrase: passphrase);
      outcome = Outcome.success(mode, value);
    } on SecretBoxAuthenticationError {
      outcome = Outcome.failure(
        mode,
        'Wrong passphrase, or the ciphertext was modified.',
      );
    } on FormatException {
      outcome = Outcome.failure(mode, 'This isn’t valid Base64 ciphertext.');
    } on ArgumentError {
      outcome = Outcome.failure(mode, 'Too short to be AES-256 ciphertext.');
    } catch (_) {
      // Never log inputs or error details: they may contain secrets.
      outcome = Outcome.failure(mode, 'Something went wrong. Try again.');
    }

    if (!mounted || generation != _generation) return;
    setState(() {
      _runningGeneration = null;
      _outcome = outcome;
    });
  }

  Future<void> _copyResult(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(const SnackBar(content: Text('Copied to clipboard')));
  }

  void _useInDecrypt(String ciphertext) {
    _ciphertext.text = ciphertext;
    _setMode(Mode.decrypt);
  }

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final colorScheme = Theme.of(context).colorScheme;

    final header = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      spacing: 4,
      children: [
        Text('AES-256 Playground', style: textTheme.headlineSmall),
        Text(
          'AES-256-GCM with a PBKDF2-HMAC-SHA256 key. '
          'Nothing leaves this page.',
          style: textTheme.bodyMedium?.copyWith(
            color: colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );

    final inputs = _InputPanel(
      mode: _mode,
      input: _input,
      passphrase: _passphrase,
      showPassphrase: _showPassphrase,
      textError: _textError,
      passphraseError: _passphraseError,
      isBusy: _isBusy,
      onModeChanged: _setMode,
      onInputChanged: _inputsChanged,
      onTogglePassphrase: () =>
          setState(() => _showPassphrase = !_showPassphrase),
      onSubmit: _submit,
    );

    final result = _ResultPanel(
      mode: _mode,
      outcome: _outcome,
      onCopy: _copyResult,
      onUseInDecrypt: _useInDecrypt,
    );

    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 32),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1040),
              child: LayoutBuilder(
                builder: (context, constraints) {
                  final isWide = constraints.maxWidth >= 760;
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    spacing: 28,
                    children: [
                      header,
                      if (isWide)
                        Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          spacing: 24,
                          children: [
                            Expanded(child: inputs),
                            Expanded(child: result),
                          ],
                        )
                      else ...[
                        inputs,
                        result,
                      ],
                    ],
                  );
                },
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _InputPanel extends StatelessWidget {
  const _InputPanel({
    required this.mode,
    required this.input,
    required this.passphrase,
    required this.showPassphrase,
    required this.textError,
    required this.passphraseError,
    required this.isBusy,
    required this.onModeChanged,
    required this.onInputChanged,
    required this.onTogglePassphrase,
    required this.onSubmit,
  });

  final Mode mode;
  final TextEditingController input;
  final TextEditingController passphrase;
  final bool showPassphrase;
  final String? textError;
  final String? passphraseError;
  final bool isBusy;
  final ValueChanged<Mode> onModeChanged;
  final VoidCallback onInputChanged;
  final VoidCallback onTogglePassphrase;
  final VoidCallback onSubmit;

  @override
  Widget build(BuildContext context) {
    final isEncrypt = mode == Mode.encrypt;
    final actionLabel = isEncrypt ? 'Encrypt' : 'Decrypt';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 20,
      children: [
        SegmentedButton<Mode>(
          segments: const [
            ButtonSegment(
              value: Mode.encrypt,
              label: Text('Encrypt'),
              icon: Icon(Icons.lock_outline),
            ),
            ButtonSegment(
              value: Mode.decrypt,
              label: Text('Decrypt'),
              icon: Icon(Icons.lock_open_outlined),
            ),
          ],
          selected: {mode},
          showSelectedIcon: false,
          onSelectionChanged: (selection) => onModeChanged(selection.single),
        ),
        TextField(
          // A new key per mode gives each field its own undo history.
          key: ValueKey(mode),
          controller: input,
          minLines: 5,
          maxLines: 10,
          keyboardType: TextInputType.multiline,
          autocorrect: isEncrypt,
          enableSuggestions: isEncrypt,
          style: isEncrypt ? null : _monospace,
          onChanged: (_) => onInputChanged(),
          decoration: InputDecoration(
            labelText: isEncrypt ? 'Plaintext' : 'Ciphertext (Base64)',
            errorText: textError,
          ),
        ),
        TextField(
          controller: passphrase,
          obscureText: !showPassphrase,
          autocorrect: false,
          enableSuggestions: false,
          textInputAction: TextInputAction.go,
          onChanged: (_) => onInputChanged(),
          onSubmitted: (_) => onSubmit(),
          decoration: InputDecoration(
            labelText: 'Passphrase',
            errorText: passphraseError,
            suffixIcon: IconButton(
              tooltip: showPassphrase ? 'Hide passphrase' : 'Show passphrase',
              onPressed: onTogglePassphrase,
              icon: Icon(
                showPassphrase
                    ? Icons.visibility_off_outlined
                    : Icons.visibility_outlined,
              ),
            ),
          ),
        ),
        SizedBox(
          height: 48,
          child: FilledButton(
            onPressed: isBusy ? null : onSubmit,
            child: isBusy
                ? Row(
                    mainAxisSize: MainAxisSize.min,
                    spacing: 12,
                    children: [
                      const SizedBox.square(
                        dimension: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                      Text(isEncrypt ? 'Encrypting…' : 'Decrypting…'),
                    ],
                  )
                : Text(actionLabel),
          ),
        ),
      ],
    );
  }
}

/// Identifies the result text, for tests.
const resultKey = ValueKey('result');

class _ResultPanel extends StatelessWidget {
  const _ResultPanel({
    required this.mode,
    required this.outcome,
    required this.onCopy,
    required this.onUseInDecrypt,
  });

  final Mode mode;
  final Outcome? outcome;
  final ValueChanged<String> onCopy;
  final ValueChanged<String> onUseInDecrypt;

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final colorScheme = Theme.of(context).colorScheme;
    final outcome = this.outcome;
    final value = outcome?.value;
    final isCiphertext = mode == Mode.encrypt;

    final Widget body;
    if (outcome?.error case final error?) {
      body = Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        spacing: 12,
        children: [
          Icon(Icons.error_outline, color: colorScheme.error),
          Expanded(
            child: Text(
              error,
              style: textTheme.bodyLarge?.copyWith(color: colorScheme.error),
            ),
          ),
        ],
      );
    } else if (value != null) {
      body = SelectionArea(
        child: Text(
          value,
          key: resultKey,
          style: isCiphertext
              ? _monospace.copyWith(fontSize: 14, color: colorScheme.onSurface)
              : textTheme.bodyLarge,
        ),
      );
    } else {
      body = Text(
        isCiphertext
            ? 'Encrypted output appears here.'
            : 'Decrypted text appears here.',
        style: textTheme.bodyLarge?.copyWith(
          color: colorScheme.onSurfaceVariant,
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 12,
      children: [
        Text(
          isCiphertext ? 'Ciphertext (Base64)' : 'Plaintext',
          style: textTheme.titleSmall?.copyWith(
            color: colorScheme.onSurfaceVariant,
          ),
        ),
        Semantics(
          liveRegion: true,
          child: Container(
            constraints: const BoxConstraints(minHeight: 140),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(12),
            ),
            child: body,
          ),
        ),
        if (value != null)
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              OutlinedButton.icon(
                onPressed: () => onCopy(value),
                icon: const Icon(Icons.copy_outlined, size: 18),
                label: const Text('Copy'),
              ),
              if (isCiphertext)
                OutlinedButton.icon(
                  onPressed: () => onUseInDecrypt(value),
                  icon: const Icon(Icons.arrow_forward, size: 18),
                  label: const Text('Use in Decrypt'),
                ),
            ],
          ),
      ],
    );
  }
}
