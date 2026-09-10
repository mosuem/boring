// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/src/crypto/digest.dart';
import 'package:boring/src/crypto/pkey.dart';
import 'package:test/test.dart';

void main() {
  group('BoringPrivateKey and BoringPublicKey', () {
    group('RSA', () {
      test('generate, sign, and verify roundtrip', () {
        final privKey = BoringPrivateKey.generateRsa(bits: 2048);
        expect(privKey.keyType, equals(KeyType.rsa));
        expect(privKey.bits, equals(2048));

        final pubKey = privKey.publicKey;
        expect(pubKey.keyType, equals(KeyType.rsa));
        expect(pubKey.bits, equals(2048));

        final data = Uint8List.fromList(utf8.encode('Hello RSA world!'));
        final sig = privKey.sign(
          algorithm: HashAlgorithm.sha256,
          data: data,
        );
        expect(sig.isNotEmpty, isTrue);

        final isValid = pubKey.verify(
          algorithm: HashAlgorithm.sha256,
          data: data,
          signature: sig,
        );
        expect(isValid, isTrue);

        final wrongData = Uint8List.fromList(
          utf8.encode('Tampered RSA message'),
        );
        expect(
          pubKey.verify(
            algorithm: HashAlgorithm.sha256,
            data: wrongData,
            signature: sig,
          ),
          isFalse,
        );
      });

      test('PEM and DER export and import', () {
        final privKey = BoringPrivateKey.generateRsa(bits: 2048);
        final pubKey = privKey.publicKey;

        // PEM roundtrip for public key
        final pubPem = pubKey.toPem();
        expect(pubPem, contains('-----BEGIN PUBLIC KEY-----'));
        expect(pubPem, contains('-----END PUBLIC KEY-----'));
        final pubFromPem = BoringPublicKey.fromPem(pubPem);
        expect(pubFromPem.keyType, equals(KeyType.rsa));
        expect(pubFromPem.bits, equals(2048));

        // DER roundtrip for public key
        final pubDer = pubKey.toDer();
        final pubFromDer = BoringPublicKey.fromDer(pubDer);
        expect(pubFromDer.toPem(), equals(pubPem));

        // PEM roundtrip for private key
        final privPem = privKey.toPem();
        expect(privPem, contains('-----BEGIN PRIVATE KEY-----'));
        final privFromPem = BoringPrivateKey.fromPem(privPem);
        expect(privFromPem.keyType, equals(KeyType.rsa));
        expect(privFromPem.bits, equals(2048));
      });
    });

    group('ECDSA', () {
      for (final curve in EcCurve.values) {
        test('${curve.name} generate, sign, verify, and serialize', () {
          final privKey = BoringPrivateKey.generateEc(curve);
          expect(privKey.keyType, equals(KeyType.ec));

          final pubKey = privKey.publicKey;
          expect(pubKey.keyType, equals(KeyType.ec));

          final data = Uint8List.fromList(
            utf8.encode('ECDSA test ${curve.name}'),
          );
          final sig = privKey.sign(
            algorithm: HashAlgorithm.sha256,
            data: data,
          );
          expect(sig.isNotEmpty, isTrue);

          final isValid = pubKey.verify(
            algorithm: HashAlgorithm.sha256,
            data: data,
            signature: sig,
          );
          expect(isValid, isTrue);

          // Test PEM export/import
          final pubPem = pubKey.toPem();
          final pubFromPem = BoringPublicKey.fromPem(pubPem);
          expect(
            pubFromPem.verify(
              algorithm: HashAlgorithm.sha256,
              data: data,
              signature: sig,
            ),
            isTrue,
          );

          final privPem = privKey.toPem();
          final privFromPem = BoringPrivateKey.fromPem(privPem);
          expect(privFromPem.keyType, equals(KeyType.ec));
        });
      }
    });
  });
}
