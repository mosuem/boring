// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'package:boring/src/x509/certificate.dart';
import 'package:boring/src/x509/verifier.dart';
import 'package:test/test.dart';

const rootPem = '''
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
''';

const leafPem = '''
-----BEGIN CERTIFICATE-----
MIIC0TCCAbmgAwIBAgICA+kwDQYJKoZIhvcNAQELBQAwKjEVMBMGA1UEAwwMVGVz
dCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNTAxMDEwMDAwMDBaFw0y
NzAxMDEwMDAwMDBaMBsxGTAXBgNVBAMMEGxlYWYuZXhhbXBsZS5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtRGfASnfa4SqAkrjAVzekjuWG8u1E
01XZ1chkF/gv0hwr9cE8xVtGO34EoAb8JCrYHzuIiqAd5co/DtBrA/0trPDXSmbm
Ufxm7RrVpDXT9i2EJipkt+clKoI33Fd6m8I+OwNsDE/p37ElCDWOl9nIJtVAHB75
ut1lqN4m52aCPoqvayTz4YtduOE8Z2WNjV4Xo3NCF/W8mwWcZ21GSuQzKhB3E59t
iT7M04JClV9YxLQPRtlv/VvitJGRB2d/w3GysLA45eMNfFcQ1siFWiQsa5bOiaXy
Iu4H/8YpuTxzeDwztiS92rBIEa0ypRfG6lUCsJNi3Q0o0DOf3dJDtwh3AgMBAAGj
EDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHoWWF1n+nUaJsAF
zntvNnfmIVc6ghS74uR2ZNnEDEb8s/nMqojgtl+2xVD8iWNXpjOhSih4jB0bAy6h
gzYj35hQQQUNYc1dTmDR3vV+xYnTrnvHUb7/L8GDn9UzfHZEs2HuhFH0hk85KKOo
HeUixMVqZ9QPQxcipQvdr++hV/24Fjmc2vRAMpYvEilG+T/wa36He1VD1jxdMXkw
KbwoViGlKVhPMnfv5uLdl140ugety3t+dcFQvbEjK7Y02JiQGYofESz07nsnD3W/
f3ET0/0Lhb8o0n/RefFJY19vDkevH2vlupI+TYSfRtRfvT6mjGICEyHpaej4AWkd
XpwsSG8=
-----END CERTIFICATE-----
''';

void main() {
  group('X509Certificate', () {
    test('parses metadata correctly', () {
      final root = X509Certificate.fromPem(rootPem);
      expect(root.version, equals(3));
      expect(root.serialNumber, equals(BigInt.from(1000)));
      expect(root.subject, contains('Test Root CA'));
      expect(root.issuer, contains('Test Root CA'));
      expect(root.notBefore, equals(DateTime.utc(2025, 1, 1, 0, 0, 0)));
      expect(root.notAfter, equals(DateTime.utc(2035, 1, 1, 0, 0, 0)));

      final leaf = X509Certificate.fromPem(leafPem);
      expect(leaf.version, equals(3));
      expect(leaf.serialNumber, equals(BigInt.from(1001)));
      expect(leaf.subject, contains('leaf.example.com'));
      expect(leaf.issuer, contains('Test Root CA'));
      expect(leaf.notBefore, equals(DateTime.utc(2025, 1, 1, 0, 0, 0)));
      expect(leaf.notAfter, equals(DateTime.utc(2027, 1, 1, 0, 0, 0)));
    });

    test('exposes the signature algorithm', () {
      final root = X509Certificate.fromPem(rootPem);
      expect(root.signatureAlgorithm, equals('1.2.840.113549.1.1.11'));
      expect(root.signatureAlgorithmName, equals('sha256WithRSAEncryption'));
    });

    test('verifies signature using issuer public key', () {
      final root = X509Certificate.fromPem(rootPem);
      final leaf = X509Certificate.fromPem(leafPem);

      expect(root.verifySignature(root.publicKey), isTrue);
      expect(leaf.verifySignature(root.publicKey), isTrue);
      expect(leaf.verifySignature(leaf.publicKey), isFalse);
    });

    test('DER and PEM export and roundtrip', () {
      final root = X509Certificate.fromPem(rootPem);
      final der = root.toDer();
      final fromDer = X509Certificate.fromDer(der);
      expect(fromDer.serialNumber, equals(root.serialNumber));

      final pem = root.toPem();
      final fromPem = X509Certificate.fromPem(pem);
      expect(fromPem.serialNumber, equals(root.serialNumber));
    });

    test('parseChainPem parses multiple certificates', () {
      final chainPem = '$rootPem\n$leafPem';
      final certs = X509Certificate.parseChainPem(chainPem);
      expect(certs.length, equals(2));
      expect(certs[0].serialNumber, equals(BigInt.from(1000)));
      expect(certs[1].serialNumber, equals(BigInt.from(1001)));
    });
  });

  group('X509Verifier', () {
    test('verifies valid chain within validity window', () {
      final root = X509Certificate.fromPem(rootPem);
      final leaf = X509Certificate.fromPem(leafPem);

      final verifier = X509Verifier();
      verifier.addTrustedCertificate(root);

      final result = verifier.verify(
        leaf: leaf,
        checkTime: DateTime.utc(2026, 1, 1),
      );
      expect(result.isValid, isTrue);
      expect(result.errorMessage, isNull);
    });

    test('rejects expired certificate', () {
      final root = X509Certificate.fromPem(rootPem);
      final leaf = X509Certificate.fromPem(leafPem);

      final verifier = X509Verifier();
      verifier.addTrustedCertificate(root);

      // leaf expires on 2027-01-01
      final result = verifier.verify(
        leaf: leaf,
        checkTime: DateTime.utc(2028, 1, 1),
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('expired'));
    });

    test('rejects not-yet-valid certificate', () {
      final root = X509Certificate.fromPem(rootPem);
      final leaf = X509Certificate.fromPem(leafPem);

      final verifier = X509Verifier();
      verifier.addTrustedCertificate(root);

      // leaf not valid before 2025-01-01
      final result = verifier.verify(
        leaf: leaf,
        checkTime: DateTime.utc(2024, 1, 1),
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('not yet valid'));
    });

    test('rejects unanchored certificate chain', () {
      final leaf = X509Certificate.fromPem(leafPem);

      // Empty verifier without root
      final verifier = X509Verifier();
      final result = verifier.verify(
        leaf: leaf,
        checkTime: DateTime.utc(2026, 1, 1),
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, isNotNull);
    });
  });
}
