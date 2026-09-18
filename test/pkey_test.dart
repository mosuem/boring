// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/crypto.dart';
import 'package:test/test.dart';

void main() {
  group('BoringPrivateKey and BoringPublicKey', () {
    group('RSA', () {
      test('generate, sign, and verify roundtrip (PKCS#1)', () {
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

      test('RSA-PSS sign and verify roundtrip', () {
        final privKey = BoringPrivateKey.generateRsa(bits: 2048);
        final pubKey = privKey.publicKey;
        final data = Uint8List.fromList(utf8.encode('RSA-PSS test message'));

        // Default salt length (= digest length)
        final sig = privKey.sign(
          algorithm: HashAlgorithm.sha256,
          data: data,
          rsaPadding: RsaSignaturePadding.pss,
        );
        expect(sig.length, equals(256));

        final isValid = pubKey.verify(
          algorithm: HashAlgorithm.sha256,
          data: data,
          signature: sig,
          rsaPadding: RsaSignaturePadding.pss,
        );
        expect(isValid, isTrue);

        // Verification fails if PKCS#1 padding is expected instead of PSS
        expect(
          pubKey.verify(
            algorithm: HashAlgorithm.sha256,
            data: data,
            signature: sig,
            rsaPadding: RsaSignaturePadding.pkcs1,
          ),
          isFalse,
        );

        // Custom salt length (e.g. 20 bytes)
        final sigCustomSalt = privKey.sign(
          algorithm: HashAlgorithm.sha256,
          data: data,
          rsaPadding: RsaSignaturePadding.pss,
          pssSaltLength: 20,
        );
        expect(
          pubKey.verify(
            algorithm: HashAlgorithm.sha256,
            data: data,
            signature: sigCustomSalt,
            rsaPadding: RsaSignaturePadding.pss,
            pssSaltLength: 20,
          ),
          isTrue,
        );

        // Mismatched salt length fails
        expect(
          pubKey.verify(
            algorithm: HashAlgorithm.sha256,
            data: data,
            signature: sigCustomSalt,
            rsaPadding: RsaSignaturePadding.pss,
            pssSaltLength: 32,
          ),
          isFalse,
        );
      });

      test('RSA-OAEP encrypt and decrypt roundtrip', () {
        final privKey = BoringPrivateKey.generateRsa(bits: 2048);
        final pubKey = privKey.publicKey;
        final plaintext = Uint8List.fromList(
          utf8.encode('Secret OAEP plaintext!'),
        );

        // 1. Default (SHA-256 for OAEP and MGF1, empty label)
        final ciphertext = pubKey.encryptOaep(plaintext: plaintext);
        expect(ciphertext.length, equals(256));

        final decrypted = privKey.decryptOaep(ciphertext: ciphertext);
        expect(decrypted, equals(plaintext));

        // 2. Custom label
        final label = Uint8List.fromList(utf8.encode('custom-label'));
        final ctWithLabel = pubKey.encryptOaep(
          plaintext: plaintext,
          label: label,
        );
        final decWithLabel = privKey.decryptOaep(
          ciphertext: ctWithLabel,
          label: label,
        );
        expect(decWithLabel, equals(plaintext));

        // Mismatched label fails decryption
        expect(
          () => privKey.decryptOaep(
            ciphertext: ctWithLabel,
            label: Uint8List.fromList(utf8.encode('wrong-label')),
          ),
          throwsA(isA<BoringSslException>()),
        );

        // 3. Custom hash algorithms
        final ctSha512 = pubKey.encryptOaep(
          plaintext: plaintext,
          hash: HashAlgorithm.sha512,
          mgf1Hash: HashAlgorithm.sha256,
        );
        final decSha512 = privKey.decryptOaep(
          ciphertext: ctSha512,
          hash: HashAlgorithm.sha512,
          mgf1Hash: HashAlgorithm.sha256,
        );
        expect(decSha512, equals(plaintext));

        // Tampered ciphertext fails decryption
        final tamperedCt = Uint8List.fromList(ciphertext);
        tamperedCt[10] ^= 0xFF;
        expect(
          () => privKey.decryptOaep(ciphertext: tamperedCt),
          throwsA(isA<BoringSslException>()),
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

    group('ECDH Key Agreement', () {
      for (final curve in EcCurve.values) {
        test('${curve.name} derives matching shared secrets', () {
          final alice = BoringPrivateKey.generateEc(curve);
          final bob = BoringPrivateKey.generateEc(curve);

          final secretAlice = alice.deriveSharedSecret(bob.publicKey);
          final secretBob = bob.deriveSharedSecret(alice.publicKey);

          expect(secretAlice.isNotEmpty, isTrue);
          expect(secretAlice, equals(secretBob));

          // deriveBits with length
          final bits = alice.deriveBits(
            peerPublicKey: bob.publicKey,
            length: 16,
          );
          expect(bits.length, equals(16));
          expect(bits, equals(secretAlice.sublist(0, 16)));
        });
      }

      test('validates key types', () {
        final rsa = BoringPrivateKey.generateRsa(bits: 2048);
        final ec = BoringPrivateKey.generateEc(EcCurve.p256);

        expect(
          () => rsa.deriveSharedSecret(ec.publicKey),
          throwsStateError,
        );
        expect(
          () => ec.deriveSharedSecret(rsa.publicKey),
          throwsArgumentError,
        );
      });
    });

    group('Streaming Sign and Verify', () {
      test('RSA streaming sign and verify (PKCS#1 and PSS)', () async {
        final rsa = BoringPrivateKey.generateRsa(bits: 2048);
        final chunks = [
          utf8.encode('Chunk 1: Hello '),
          utf8.encode('Chunk 2: world! '),
          utf8.encode('Chunk 3: Streaming signatures.'),
        ];

        // PKCS#1
        final sigPkcs1 = await rsa.signStream(
          algorithm: HashAlgorithm.sha256,
          data: Stream.fromIterable(chunks),
        );
        final okPkcs1 = await rsa.publicKey.verifyStream(
          algorithm: HashAlgorithm.sha256,
          data: Stream.fromIterable(chunks),
          signature: sigPkcs1,
        );
        expect(okPkcs1, isTrue);

        // PSS
        final sigPss = await rsa.signStream(
          algorithm: HashAlgorithm.sha256,
          data: Stream.fromIterable(chunks),
          rsaPadding: RsaSignaturePadding.pss,
        );
        final okPss = await rsa.publicKey.verifyStream(
          algorithm: HashAlgorithm.sha256,
          data: Stream.fromIterable(chunks),
          signature: sigPss,
          rsaPadding: RsaSignaturePadding.pss,
        );
        expect(okPss, isTrue);

        // Verification with tampered stream fails
        final tamperedChunks = [
          ...chunks,
          utf8.encode('Extra chunk'),
        ];
        final failPss = await rsa.publicKey.verifyStream(
          algorithm: HashAlgorithm.sha256,
          data: Stream.fromIterable(tamperedChunks),
          signature: sigPss,
          rsaPadding: RsaSignaturePadding.pss,
        );
        expect(failPss, isFalse);
      });

      test('ECDSA streaming sign and verify', () async {
        final ec = BoringPrivateKey.generateEc(EcCurve.p256);
        final chunks = [
          utf8.encode('ECDSA stream chunk A, '),
          utf8.encode('ECDSA stream chunk B.'),
        ];

        final sig = await ec.signStream(
          algorithm: HashAlgorithm.sha256,
          data: Stream.fromIterable(chunks),
        );
        final ok = await ec.publicKey.verifyStream(
          algorithm: HashAlgorithm.sha256,
          data: Stream.fromIterable(chunks),
          signature: sig,
        );
        expect(ok, isTrue);
      });

      test('Ed25519 streaming sign and verify', () async {
        final der = Uint8List.fromList([
          0x30,
          0x2e,
          0x02,
          0x01,
          0x00,
          0x30,
          0x05,
          0x06,
          0x03,
          0x2b,
          0x65,
          0x70,
          0x04,
          0x22,
          0x04,
          0x20,
          ...List.filled(32, 0x42),
        ]);
        final edKey = BoringPrivateKey.fromDer(der);
        expect(edKey.keyType, equals(KeyType.ed25519));

        final chunks = [
          utf8.encode('Ed25519 chunk 1, '),
          utf8.encode('Ed25519 chunk 2.'),
        ];

        final sig = await edKey.signStream(
          data: Stream.fromIterable(chunks),
        );
        final ok = await edKey.publicKey.verifyStream(
          data: Stream.fromIterable(chunks),
          signature: sig,
        );
        expect(ok, isTrue);
      });
    });
  });
}
