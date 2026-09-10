// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/src/crypto/ed25519.dart';
import 'package:test/test.dart';

void main() {
  group('BoringEd25519', () {
    test('generateKeyPair creates 32-byte public and 64-byte private keys', () {
      final kp = BoringEd25519.generateKeyPair();
      expect(kp.publicKey.length, equals(ed25519PublicKeyLength));
      expect(kp.privateKey.length, equals(ed25519PrivateKeyLength));
      // First 32 bytes of private key is the seed, last 32 bytes is public key
      expect(kp.privateKey.sublist(32), equals(kp.publicKey));
    });

    test('keyPairFromSeed is deterministic', () {
      final seed = Uint8List.fromList(List.filled(32, 0x42));
      final kp1 = BoringEd25519.keyPairFromSeed(seed);
      final kp2 = BoringEd25519.keyPairFromSeed(seed);

      expect(kp1.publicKey, equals(kp2.publicKey));
      expect(kp1.privateKey, equals(kp2.privateKey));
    });

    test('sign and verify roundtrip', () {
      final kp = BoringEd25519.generateKeyPair();
      final message = Uint8List.fromList(
        utf8.encode('BoringSSL Ed25519 digital signature test message'),
      );

      final signature = BoringEd25519.sign(
        privateKey: kp.privateKey,
        message: message,
      );
      expect(signature.length, equals(ed25519SignatureLength));

      final isValid = BoringEd25519.verify(
        publicKey: kp.publicKey,
        message: message,
        signature: signature,
      );
      expect(isValid, isTrue);
    });

    test('verify returns false on tampered message', () {
      final kp = BoringEd25519.generateKeyPair();
      final message = Uint8List.fromList(utf8.encode('Original message'));
      final signature = BoringEd25519.sign(
        privateKey: kp.privateKey,
        message: message,
      );

      final tamperedMessage = Uint8List.fromList(
        utf8.encode('Tampered message'),
      );
      final isValid = BoringEd25519.verify(
        publicKey: kp.publicKey,
        message: tamperedMessage,
        signature: signature,
      );
      expect(isValid, isFalse);
    });

    test('verify returns false on tampered signature', () {
      final kp = BoringEd25519.generateKeyPair();
      final message = Uint8List.fromList(utf8.encode('Original message'));
      final signature = BoringEd25519.sign(
        privateKey: kp.privateKey,
        message: message,
      );

      final tamperedSig = Uint8List.fromList(signature);
      tamperedSig[0] ^= 0xff;

      final isValid = BoringEd25519.verify(
        publicKey: kp.publicKey,
        message: message,
        signature: tamperedSig,
      );
      expect(isValid, isFalse);
    });
  });
}
