// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/crypto.dart';
import 'package:test/test.dart';

void main() {
  group('BoringCipher', () {
    group('AES-CBC', () {
      test('round-trip 128-bit and 256-bit with PKCS#7 padding', () {
        for (final alg in [
          CipherAlgorithm.aes128Cbc,
          CipherAlgorithm.aes256Cbc,
        ]) {
          final key = Uint8List(alg.keyLength)
            ..fillRange(0, alg.keyLength, 0x42);
          final iv = Uint8List(16)..fillRange(0, 16, 0x24);
          final plaintext = Uint8List.fromList(
            utf8.encode('AES-CBC authenticated-agnostic plaintext message!'),
          );

          final cipher = BoringCipher(alg, key);
          final ciphertext = cipher.encrypt(iv: iv, plaintext: plaintext);

          // Padded ciphertext must be multiple of block size and > plaintext
          expect(ciphertext.length % alg.blockSize, equals(0));
          expect(ciphertext.length, greaterThan(plaintext.length));

          final decrypted = cipher.decrypt(iv: iv, ciphertext: ciphertext);
          expect(decrypted, equals(plaintext));
        }
      });

      test('rejects tampered ciphertext', () {
        final key = Uint8List(16)..fillRange(0, 16, 0x11);
        final iv = Uint8List(16)..fillRange(0, 16, 0x22);
        final plaintext = Uint8List.fromList(utf8.encode('Secret message'));

        final cipher = BoringCipher(CipherAlgorithm.aes128Cbc, key);
        final ciphertext = cipher.encrypt(iv: iv, plaintext: plaintext);

        // Tamper with last block (contains padding)
        ciphertext[ciphertext.length - 1] ^= 0xFF;

        expect(
          () => cipher.decrypt(iv: iv, ciphertext: ciphertext),
          throwsA(isA<BoringSslException>()),
        );
      });

      test('validates key and IV length', () {
        expect(
          () => BoringCipher(CipherAlgorithm.aes128Cbc, Uint8List(24)),
          throwsArgumentError,
        );
        expect(
          () => BoringCipher(CipherAlgorithm.aes256Cbc, Uint8List(16)),
          throwsArgumentError,
        );

        final cipher = BoringCipher(CipherAlgorithm.aes128Cbc, Uint8List(16));
        expect(
          () => cipher.encrypt(iv: Uint8List(12), plaintext: Uint8List(16)),
          throwsArgumentError,
        );
        expect(
          () => cipher.decrypt(iv: Uint8List(12), ciphertext: Uint8List(16)),
          throwsArgumentError,
        );
      });
    });

    group('AES-CTR', () {
      test('round-trip 128-bit and 256-bit unpadded stream', () {
        for (final alg in [
          CipherAlgorithm.aes128Ctr,
          CipherAlgorithm.aes256Ctr,
        ]) {
          final key = Uint8List(alg.keyLength)
            ..fillRange(0, alg.keyLength, 0x55);
          final iv = Uint8List(16)..fillRange(0, 16, 0xAA);
          final plaintext = Uint8List.fromList(
            utf8.encode('CTR stream cipher mode with arbitrary length!'),
          );

          final cipher = BoringCipher(alg, key);
          final ciphertext = cipher.encrypt(iv: iv, plaintext: plaintext);

          // Stream cipher: exact length match (no padding)
          expect(ciphertext.length, equals(plaintext.length));

          final decrypted = cipher.decrypt(iv: iv, ciphertext: ciphertext);
          expect(decrypted, equals(plaintext));
        }
      });

      test('symmetric property of CTR mode', () {
        final key = Uint8List(16)..fillRange(0, 16, 0x33);
        final iv = Uint8List(16)..fillRange(0, 16, 0x77);
        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        final cipher = BoringCipher(CipherAlgorithm.aes128Ctr, key);
        final c1 = cipher.encrypt(iv: iv, plaintext: plaintext);
        // Decrypting is the same keystream operation
        final c2 = cipher.decrypt(iv: iv, ciphertext: c1);
        expect(c2, equals(plaintext));
      });
    });

    group('BoringAesKeyWrap', () {
      test('wraps and unwraps 128, 192, and 256-bit keys', () {
        for (final keySize in [16, 24, 32]) {
          final kek = Uint8List(keySize)..fillRange(0, keySize, 0x01);
          final targetKey = Uint8List(32)..fillRange(0, 32, 0x99);

          final wrapped = BoringAesKeyWrap.wrap(key: kek, data: targetKey);
          expect(wrapped.length, equals(targetKey.length + 8));

          final unwrapped = BoringAesKeyWrap.unwrap(key: kek, data: wrapped);
          expect(unwrapped, equals(targetKey));
        }
      });

      test('fails integrity check on tampered wrapped data', () {
        final kek = Uint8List(16)..fillRange(0, 16, 0x01);
        final targetKey = Uint8List(16)..fillRange(0, 16, 0x02);

        final wrapped = BoringAesKeyWrap.wrap(key: kek, data: targetKey);
        wrapped[0] ^= 0xFF;

        expect(
          () => BoringAesKeyWrap.unwrap(key: kek, data: wrapped),
          throwsA(isA<BoringSslException>()),
        );
      });

      test('validates inputs', () {
        final badKek = Uint8List(10);
        final goodKek = Uint8List(16);
        final nonBlockData = Uint8List(15); // not multiple of 8
        final tooShortData = Uint8List(8); // < 16 bytes for wrap

        expect(
          () => BoringAesKeyWrap.wrap(key: badKek, data: Uint8List(16)),
          throwsArgumentError,
        );
        expect(
          () => BoringAesKeyWrap.wrap(key: goodKek, data: nonBlockData),
          throwsArgumentError,
        );
        expect(
          () => BoringAesKeyWrap.wrap(key: goodKek, data: tooShortData),
          throwsArgumentError,
        );

        expect(
          () => BoringAesKeyWrap.unwrap(key: badKek, data: Uint8List(24)),
          throwsArgumentError,
        );
        expect(
          () => BoringAesKeyWrap.unwrap(key: goodKek, data: Uint8List(20)),
          throwsArgumentError,
        );
      });
    });
  });
}
