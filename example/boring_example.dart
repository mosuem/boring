// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/boring.dart';

void main() {
  print('=== BoringSSL with Dart Native Assets ===\n');

  // 1. Cryptographically secure random bytes
  final salt = BoringRand.secureRandom(16);
  print('Generated 16 random bytes: ${_toHex(salt)}');

  // 2. Message Digest (Hashing)
  final message = Uint8List.fromList(utf8.encode('Hello BoringSSL!'));
  final hash = BoringDigest.sha256(message);
  print('SHA-256: ${_toHex(hash)}');

  // 3. HMAC
  final hmacKey = BoringRand.secureRandom(32);
  final mac = BoringHmac.sha256(key: hmacKey, data: message);
  print('HMAC-SHA256: ${_toHex(mac)}');

  // 4. HKDF Key Derivation
  final derivedKey = BoringHkdf.deriveBits(
    algorithm: HashAlgorithm.sha256,
    ikm: mac,
    length: 32,
    salt: salt,
    info: Uint8List.fromList(utf8.encode('app-sub-key')),
  );
  print('Derived 32-byte key: ${_toHex(derivedKey)}');

  // 5. Authenticated Encryption (AEAD)
  final cipher = BoringAead(AeadAlgorithm.aes256Gcm, derivedKey);
  final nonce = BoringRand.secureRandom(12);
  final plaintext = Uint8List.fromList(utf8.encode('Secret communication'));
  final ad = Uint8List.fromList(utf8.encode('user:alice'));

  final ciphertext = cipher.seal(
    nonce: nonce,
    plaintext: plaintext,
    additionalData: ad,
  );
  print('Encrypted (AES-256-GCM): ${_toHex(ciphertext)}');

  final decrypted = cipher.open(
    nonce: nonce,
    ciphertext: ciphertext,
    additionalData: ad,
  );
  print('Decrypted: ${utf8.decode(decrypted)}');

  // 6. Digital Signatures (Ed25519)
  final keyPair = BoringEd25519.generateKeyPair();
  final signature = BoringEd25519.sign(
    privateKey: keyPair.privateKey,
    message: plaintext,
  );
  final isValid = BoringEd25519.verify(
    publicKey: keyPair.publicKey,
    message: plaintext,
    signature: signature,
  );
  print('Ed25519 signature valid: $isValid\n');
}

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
