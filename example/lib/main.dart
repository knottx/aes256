import 'package:aes256/aes256.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'aes256 Example',
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData.dark(),
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final _plainCtrl = TextEditingController(text: 'Hello Web 🌐');
  final _passCtrl = TextEditingController(text: 'super_secret_password');
  final _cipherCtrl = TextEditingController();
  final _outCtrl = TextEditingController();

  bool _isLoading = false;
  String? _error;

  Future<void> _encrypt() async {
    setState(() {
      _isLoading = true;
      _error = null;
      _outCtrl.clear();
    });
    try {
      final c = await Aes256.encrypt(
        text: _plainCtrl.text,
        passphrase: _passCtrl.text,
      );
      _cipherCtrl.text = c;
    } catch (e) {
      _error = 'Encrypt error: $e';
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _decrypt() async {
    setState(() {
      _isLoading = true;
      _error = null;
      _outCtrl.clear();
    });
    try {
      final p = await Aes256.decrypt(
        encrypted: _cipherCtrl.text.trim(),
        passphrase: _passCtrl.text,
      );
      _outCtrl.text = p;
    } catch (e) {
      _error = 'Decrypt error: $e';
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('AES-256 GCM (PBKDF2-HMAC-SHA256)'),
        centerTitle: true,
      ),
      body: Scrollbar(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                spacing: 16,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  TextField(
                    controller: _plainCtrl,
                    minLines: 1,
                    maxLines: 4,
                    decoration: _buildInputFieldDecoration('Plaintext'),
                  ),
                  TextField(
                    controller: _passCtrl,
                    decoration: _buildInputFieldDecoration(
                      'Passphrase',
                      hint: 'Pick a strong one 🔒',
                    ),
                  ),
                  Row(
                    children: [
                      Expanded(
                        child: FilledButton.icon(
                          onPressed: _isLoading ? null : _encrypt,
                          icon: const Icon(Icons.lock),
                          label: const Text('Encrypt'),
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: FilledButton.tonalIcon(
                          onPressed: _isLoading ? null : _decrypt,
                          icon: const Icon(Icons.lock_open),
                          label: const Text('Decrypt'),
                        ),
                      ),
                    ],
                  ),
                  TextField(
                    controller: _cipherCtrl,
                    minLines: 2,
                    maxLines: 6,
                    decoration: _buildInputFieldDecoration(
                      'Ciphertext (base64)',
                      hint: 'Paste here to decrypt',
                      suffix: IconButton(
                        tooltip: 'Clear',
                        onPressed: _isLoading
                            ? null
                            : () => _cipherCtrl.clear(),
                        icon: const Icon(Icons.clear),
                      ),
                    ),
                  ),
                  TextField(
                    controller: _outCtrl,
                    readOnly: true,
                    minLines: 1,
                    maxLines: 6,
                    decoration: _buildInputFieldDecoration('Decrypted output'),
                  ),
                  if (_isLoading) const LinearProgressIndicator(),
                  if (_error != null)
                    Text(
                      _error!,
                      style: const TextStyle(color: Colors.red),
                    ),
                  const Text(
                    'Note: Uses AES-256-GCM with PBKDF2-HMAC-SHA256. '
                    'The output includes header+salt+nonce+ciphertext+auth tag.',
                    style: TextStyle(fontSize: 12),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  InputDecoration _buildInputFieldDecoration(
    String label, {
    String? hint,
    Widget? suffix,
  }) {
    return InputDecoration(
      labelText: label,
      hintText: hint,
      border: const OutlineInputBorder(),
      suffixIcon: suffix,
    );
  }
}
