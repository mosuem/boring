// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/src/crypto/aead.dart';
import 'package:boring/src/crypto/rand.dart';
import 'package:boring/src/ffi/error.dart';
import 'package:test/test.dart';

void main() {
  group('BoringAead', () {
    for (final algo in AeadAlgorithm.values) {
      group(algo.name, () {
        test('seal and open roundtrip with AD', () {
          final key = BoringRand.secureRandom(algo.keyLength);
          final nonce = BoringRand.secureRandom(algo.nonceLength);
          final plaintext = Uint8List.fromList(
            utf8.encode('Top secret message encrypted with ${algo.name}'),
          );
          final ad = Uint8List.fromList(
            utf8.encode('associated-metadata-header'),
          );

          final cipher = BoringAead(algo, key);
          final ciphertext = cipher.seal(
            nonce: nonce,
            plaintext: plaintext,
            additionalData: ad,
          );

          expect(
            ciphertext.length,
            equals(plaintext.length + algo.maxOverhead),
          );

          final decrypted = cipher.open(
            nonce: nonce,
            ciphertext: ciphertext,
            additionalData: ad,
          );

          expect(decrypted, equals(plaintext));
        });

        test('seal and open roundtrip without AD', () {
          final key = BoringRand.secureRandom(algo.keyLength);
          final nonce = BoringRand.secureRandom(algo.nonceLength);
          final plaintext = Uint8List.fromList(utf8.encode('Simple plaintext'));

          final cipher = BoringAead(algo, key);
          final ciphertext = cipher.seal(
            nonce: nonce,
            plaintext: plaintext,
          );

          final decrypted = cipher.open(
            nonce: nonce,
            ciphertext: ciphertext,
          );

          expect(decrypted, equals(plaintext));
        });

        test('open with tampered ciphertext throws BoringSslException', () {
          final key = BoringRand.secureRandom(algo.keyLength);
          final nonce = BoringRand.secureRandom(algo.nonceLength);
          final plaintext = Uint8List.fromList(utf8.encode('Hello World'));

          final cipher = BoringAead(algo, key);
          final ciphertext = cipher.seal(
            nonce: nonce,
            plaintext: plaintext,
          );

          // Tamper with last byte (tag)
          final tampered = Uint8List.fromList(ciphertext);
          tampered[tampered.length - 1] ^= 0x01;

          expect(
            () => cipher.open(nonce: nonce, ciphertext: tampered),
            throwsA(isA<BoringSslException>()),
          );
        });

        test('open with tampered AD throws BoringSslException', () {
          final key = BoringRand.secureRandom(algo.keyLength);
          final nonce = BoringRand.secureRandom(algo.nonceLength);
          final plaintext = Uint8List.fromList(utf8.encode('Hello World'));
          final ad = Uint8List.fromList(utf8.encode('auth-data'));

          final cipher = BoringAead(algo, key);
          final ciphertext = cipher.seal(
            nonce: nonce,
            plaintext: plaintext,
            additionalData: ad,
          );

          final wrongAd = Uint8List.fromList(utf8.encode('wrong-data'));
          expect(
            () => cipher.open(
              nonce: nonce,
              ciphertext: ciphertext,
              additionalData: wrongAd,
            ),
            throwsA(isA<BoringSslException>()),
          );
        });

        test('invalid key length throws ArgumentError', () {
          final wrongKey = BoringRand.secureRandom(algo.keyLength + 1);
          expect(() => BoringAead(algo, wrongKey), throwsArgumentError);
        });

        test('invalid nonce length throws ArgumentError', () {
          final key = BoringRand.secureRandom(algo.keyLength);
          final wrongNonce = BoringRand.secureRandom(algo.nonceLength + 1);
          final cipher = BoringAead(algo, key);

          expect(
            () => cipher.seal(
              nonce: wrongNonce,
              plaintext: Uint8List(10),
            ),
            throwsArgumentError,
          );
        });
      });
    }
  });
}
