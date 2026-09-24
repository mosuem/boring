// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

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

    test('X25519 key agreement via BoringX25519 and BoringPrivateKey', () {
      final alice = BoringX25519.generateKeyPair();
      final bob = BoringX25519.generateKeyPair();
      expect(
        BoringX25519.publicKeyFromPrivate(alice.privateKey),
        equals(alice.publicKey),
      );

      final s1 = BoringX25519.computeSharedSecret(
        privateKey: alice.privateKey,
        peerPublicKey: bob.publicKey,
      );
      final s2 = BoringX25519.computeSharedSecret(
        privateKey: bob.privateKey,
        peerPublicKey: alice.publicKey,
      );
      expect(s1, equals(s2));

      final pkeyAlice = BoringPrivateKey.fromRawKey(
        KeyType.x25519,
        alice.privateKey,
      );
      final pkeyBobPub = BoringPublicKey.fromRawKey(
        KeyType.x25519,
        bob.publicKey,
      );
      expect(pkeyAlice.toRawBytes(), equals(alice.privateKey));
      expect(pkeyAlice.publicKey.toRawBytes(), equals(alice.publicKey));
      expect(pkeyAlice.deriveSharedSecret(pkeyBobPub), equals(s1));
    });

    test('Ed25519 seed signing, generateEd25519, and raw key round-trip', () {
      final kp = BoringEd25519.generateKeyPair();
      final msg = Uint8List.fromList(utf8.encode('test message'));
      final sigFromSeed = BoringEd25519.sign(
        privateKey: kp.seed,
        data: msg,
      );
      final sigFromPriv = BoringEd25519.sign(
        privateKey: kp.privateKey,
        message: msg,
      );
      expect(sigFromSeed, equals(sigFromPriv));
      expect(
        BoringEd25519.verify(
          publicKey: kp.publicKey,
          data: msg,
          signature: sigFromSeed,
        ),
        isTrue,
      );

      final edPkey = BoringPrivateKey.generateEd25519();
      expect(edPkey.keyType, KeyType.ed25519);
      expect(edPkey.toRawBytes(), hasLength(32));
      expect(
        () => edPkey.sign(algorithm: HashAlgorithm.sha256, data: msg),
        throwsArgumentError,
      );
      final pkeySig = edPkey.sign(data: msg);
      expect(edPkey.publicKey.verify(data: msg, signature: pkeySig), isTrue);
    });

    test('Encrypted PKCS#8 PEM round-trip', () {
      final ecKey = BoringPrivateKey.generateEc(EcCurve.p256);
      final encryptedPem = ecKey.toPem(password: 'correct-horse-battery');
      expect(encryptedPem, contains('ENCRYPTED PRIVATE KEY'));

      final restored = BoringPrivateKey.fromPem(
        encryptedPem,
        password: 'correct-horse-battery',
      );
      expect(restored.toDer(), equals(ecKey.toDer()));
      expect(
        () => BoringPrivateKey.fromPem(encryptedPem, password: 'wrong'),
        throwsA(isA<BoringSslException>()),
      );
    });

    test('timingSafeEqual and BoringHmac.verify', () {
      final key = BoringRand.secureRandom(32);
      final data = Uint8List.fromList([1, 2, 3, 4]);
      final mac = BoringHmac.sha256(key: key, data: data);
      expect(
        BoringCrypto.timingSafeEqual(mac, Uint8List.fromList(mac)),
        isTrue,
      );
      expect(BoringCrypto.timingSafeEqual(mac, Uint8List(31)), isFalse);
      expect(
        BoringHmac.verify(
          algorithm: HashAlgorithm.sha256,
          key: key,
          data: data,
          expectedMac: mac,
        ),
        isTrue,
      );
    });

    test('dispose() is idempotent and prevents use-after-free', () {
      final key = BoringPrivateKey.generateEd25519();
      final pub = key.publicKey;
      final cert = X509Certificate.fromPem('''
-----BEGIN CERTIFICATE-----
MIIC4zCCAcugAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwKjEVMBMGA1UEAwwMVGVz
dCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNTAxMDEwMDAwMDBaFw0z
NTAxMDEwMDAwMDBaMCoxFTATBgNVBAMMDFRlc3QgUm9vdCBDQTERMA8GA1UECgwI
VGVzdCBPcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0vCAeZygQ
R7+4PLmMIWxV787xDqD4/mfi/s4zB/IL7Qd+SNktJ2rVBJa/89xpNbwNsUrlykvL
jW2zKxFjSHho0hvuC/V+jbAfjP8dZQ2GViWZs/2IG5ZsGyxim1OLdUMBspNujzh3
G6S2/oXNIdPxhU+Z9EIhOewFlUpuGmVfBdzwBLEId1EZVyq/KL6VANLD6ac0Kun5
0wQjB/w35tVN/A+SGWQNiP+bs6xIjCO14YBfGKGfW3oAIaZXq5Po7syP6rzqRw+c
Y7bcwG4HQ7ynL9pUs4eD+TJOd8N6usOxnLTctYYhi3R65S5IbHksjNKyhjeD9QYJ
YehN83XYkiTvAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAHD+Qp2ElbfVoMC91wZlCyqkhdMu/xnDI9+nwLb2UPeYILGHCSfZyOX+
EhOuSyQnQ6sHhT/rzbIx2AxfeoSr0Fwagp442CQOjvFdRDneKdwAXCWtulb3mnMu
ZqJY3sUmuQV85eUMHTgVbolrjbedqY8BvCHRkmvJJwYh8+dKjnFjiqJoCjSfQTCm
r7TU9Lbhx20/3zGHuzM4ZLMkj4beJCtAzD/kSYTIe+4LEoY9eyCNxchhilngWANT
KGRUVLuQS8MCPKvrAXKF97t8hzPv6F9TKxgL+ZUsMeTwxW6iwqy1F5vu7zL4MGP3
dklX+0BkWvPSHhqkN7wYgbr7mk/aCsY=
-----END CERTIFICATE-----
''');
      final der = cert.toDer();

      key.dispose();
      key.dispose(); // idempotent
      expect(key.toDer, throwsStateError);

      pub.dispose();
      pub.dispose();
      expect(pub.toDer, throwsStateError);

      cert.dispose();
      cert.dispose();
      expect(() => cert.subject, throwsStateError);

      final verifier = X509Verifier();
      verifier.dispose();
      verifier.dispose();
      expect(
        () => verifier.addTrustedCertificate(X509Certificate.fromDer(der)),
        throwsStateError,
      );

      final ctx = DigestContext(HashAlgorithm.sha256);
      ctx.dispose();
      ctx.dispose();
      expect(() => ctx.update(Uint8List(1)), throwsStateError);

      // Allocate and dispose in a loop to trigger GC and verify finalizers
      // were properly detached (preventing double-free on GC).
      for (var i = 0; i < 2000; i++) {
        final c = X509Certificate.fromDer(der);
        final v = X509Verifier()..addTrustedCertificate(c);
        v.dispose();
        c.dispose();
      }
    });
  });
}
