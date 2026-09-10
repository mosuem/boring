// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/boring.dart';
import 'package:test/test.dart';

void main() {
  group('package:boring top-level exports', () {
    test('end-to-end crypto workflow', () {
      // 1. Randomness
      final key = BoringRand.secureRandom(32);
      final nonce = BoringRand.secureRandom(12);

      // 2. Digest
      final hash = BoringDigest.sha256(
        Uint8List.fromList(utf8.encode('Hello BoringSSL')),
      );
      expect(hash.length, equals(32));

      // 3. HMAC
      final mac = BoringHmac.sha256(key: key, data: hash);
      expect(mac.length, equals(32));

      // 4. HKDF
      final derivedKey = BoringHkdf.deriveBits(
        algorithm: HashAlgorithm.sha256,
        ikm: mac,
        length: 32,
      );
      expect(derivedKey.length, equals(32));

      // 5. AEAD
      final cipher = BoringAead(AeadAlgorithm.aes256Gcm, derivedKey);
      final plaintext = Uint8List.fromList(utf8.encode('Secret payload'));
      final ciphertext = cipher.seal(nonce: nonce, plaintext: plaintext);
      final decrypted = cipher.open(nonce: nonce, ciphertext: ciphertext);
      expect(decrypted, equals(plaintext));

      // 6. Ed25519
      final edKp = BoringEd25519.generateKeyPair();
      final edSig = BoringEd25519.sign(
        privateKey: edKp.privateKey,
        message: ciphertext,
      );
      expect(
        BoringEd25519.verify(
          publicKey: edKp.publicKey,
          message: ciphertext,
          signature: edSig,
        ),
        isTrue,
      );

      // 7. RSA & ECDSA
      final rsaKey = BoringPrivateKey.generateRsa(bits: 2048);
      final rsaSig = rsaKey.sign(
        algorithm: HashAlgorithm.sha256,
        data: ciphertext,
      );
      expect(
        rsaKey.publicKey.verify(
          algorithm: HashAlgorithm.sha256,
          data: ciphertext,
          signature: rsaSig,
        ),
        isTrue,
      );
    });
  });
}
