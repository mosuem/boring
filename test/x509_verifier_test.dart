// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'package:boring/x509.dart';
import 'package:test/test.dart';

/// Self-signed P-256 root, `CN=Boring Test Root CA`.
const rootPem = '''
-----BEGIN CERTIFICATE-----
MIIBxjCCAW2gAwIBAgIUW0pmw/J3KxU1pMHi1MZiEQ4PPqYwCgYIKoZIzj0EAwIw
MTEcMBoGA1UEAwwTQm9yaW5nIFRlc3QgUm9vdCBDQTERMA8GA1UECgwIVGVzdCBP
cmcwHhcNMjYwOTExMDkxOTE4WhcNNDYwOTA2MDkxOTE4WjAxMRwwGgYDVQQDDBNC
b3JpbmcgVGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABG3g8WPAE95tfwHuQXJmiGqWNaQGJ1pWnS0J3JCZxxca
kfMBIffiPQ0drrXKNttX5Vw4+FvZ19cVHhD8uf/Vk1OjYzBhMB0GA1UdDgQWBBS6
hoM/Erlt3T9YBtRWLCOPeyP5SjAfBgNVHSMEGDAWgBS6hoM/Erlt3T9YBtRWLCOP
eyP5SjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQD
AgNHADBEAiAB0P6f9NQWWkfkyBYOS6JLyu/PKMGJBLpdnxKFUgi/HAIgC3jgcYYe
OQWQNCc91uO3v+vyjLIbyJ/1klA3A2/Ttm4=
-----END CERTIFICATE-----
''';

/// Intermediate CA signed by [rootPem], `CN=Boring Test ICA`.
const intermediatePem = '''
-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIBAjAKBggqhkjOPQQDAjAxMRwwGgYDVQQDDBNCb3Jpbmcg
VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjA5MTEwOTE5MTha
Fw00NjA5MDYwOTE5MThaMC0xGDAWBgNVBAMMD0JvcmluZyBUZXN0IElDQTERMA8G
A1UECgwIVGVzdCBPcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3FQdtF3k5
ocZqWmFDDMLTAgiejN2aHfjdMvdSQifXAZZQfCGgf9IQe/yoEY/+Z9GJ6DOrJLIG
ouzKxIHo5vmfo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAd
BgNVHQ4EFgQUh7HrO4nST6dnKQgpKwXCAyGNymAwHwYDVR0jBBgwFoAUuoaDPxK5
bd0/WAbUViwjj3sj+UowCgYIKoZIzj0EAwIDSAAwRQIgCCZbDqTXX7x2o/KZxmxb
ZDFq9WEFomaOogB/V9p7uSACIQDUTQ/BdkN1xuFkqxpIfk0WPyIhpxjsSwKSMksR
We9uYA==
-----END CERTIFICATE-----
''';

/// End-entity certificate signed by [intermediatePem].
///
/// `SAN: DNS:leaf.example.com, DNS:*.wild.example.com, IP:127.0.0.1,
/// email:test@example.com`, `EKU: serverAuth`,
/// `KU: digitalSignature, keyEncipherment`.
const leafPem = '''
-----BEGIN CERTIFICATE-----
MIIB+DCCAZ2gAwIBAgIBAzAKBggqhkjOPQQDAjAtMRgwFgYDVQQDDA9Cb3Jpbmcg
VGVzdCBJQ0ExETAPBgNVBAoMCFRlc3QgT3JnMB4XDTI2MDkxMTA5MTkxOFoXDTQ2
MDkwNjA5MTkxOFowGzEZMBcGA1UEAwwQbGVhZi5leGFtcGxlLmNvbTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABM9SqKQkGZPn+5GXi6nQ+PI7BK1eLRNj9Ci2f6mM
Kh9nD4MnwCVpqXqmf2uhZVplDS04MpXL3bIPuq8MtMhR9Mejgb8wgbwwDAYDVR0T
AQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwRwYD
VR0RBEAwPoIQbGVhZi5leGFtcGxlLmNvbYISKi53aWxkLmV4YW1wbGUuY29thwR/
AAABgRB0ZXN0QGV4YW1wbGUuY29tMB0GA1UdDgQWBBShFEIcgtg9qmFGmxO9mDgl
IwcWdzAfBgNVHSMEGDAWgBSHses7idJPp2cpCCkrBcIDIY3KYDAKBggqhkjOPQQD
AgNJADBGAiEApppnZDBIbwI/+ROljIunf/ZYhH77D/JM3pDmK7fndGICIQCzdDoE
vLBatdRQJrZT3MJEa8K8R6JI9v66DHtWbq0v3A==
-----END CERTIFICATE-----
''';

/// Self-signed P-256 root signed with `ecdsa-with-SHA1`,
/// `CN=Boring SHA1 Root CA`.
const sha1RootPem = '''
-----BEGIN CERTIFICATE-----
MIIBxjCCAWygAwIBAgIUKxP5KkPIULCvP/UHqUjSjEUT+aEwCQYHKoZIzj0EATAx
MRwwGgYDVQQDDBNCb3JpbmcgU0hBMSBSb290IENBMREwDwYDVQQKDAhUZXN0IE9y
ZzAeFw0yNjA5MTExMTUzNTVaFw00NjA5MDYxMTUzNTVaMDExHDAaBgNVBAMME0Jv
cmluZyBTSEExIFJvb3QgQ0ExETAPBgNVBAoMCFRlc3QgT3JnMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEYpjWi1r1wBTl91bnDGSAOU7kbJIB9qqayXJyYbdrVBs7
2GsVR+QMChohU84Qdx5IBp3s/jspPqd0Lm3lddnghaNjMGEwHQYDVR0OBBYEFHH7
rTmDCXc1CveoZE0I6ZIc/Y6DMB8GA1UdIwQYMBaAFHH7rTmDCXc1CveoZE0I6ZIc
/Y6DMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAkGByqGSM49BAED
SQAwRgIhAMCO32SYRZmRsroUh6x7A9tCh+aZKTmNyx1Gia7PmLXOAiEA+uwfQ4yn
3qBwZOxoIFXt3n9tWTpdKk+IqS8PBuHb15k=
-----END CERTIFICATE-----
''';

/// End-entity certificate signed by [sha1RootPem] with `ecdsa-with-SHA1`.
const sha1LeafPem = '''
-----BEGIN CERTIFICATE-----
MIIBzTCCAXSgAwIBAgIBAjAJBgcqhkjOPQQBMDExHDAaBgNVBAMME0JvcmluZyBT
SEExIFJvb3QgQ0ExETAPBgNVBAoMCFRlc3QgT3JnMB4XDTI2MDkxMTExNTM1NVoX
DTQ2MDkwNjExNTM1NVowGzEZMBcGA1UEAwwQbGVhZi5leGFtcGxlLmNvbTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABJt1EwjknCYa/bWDm9Hpz6Jh/Sm5kWJXwxkY
vmZbyCz1J9JpRf+fmBEUybmo3AP0SBhHvAgWMs1bc/DtIrIztPOjgZMwgZAwDAYD
VR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
GwYDVR0RBBQwEoIQbGVhZi5leGFtcGxlLmNvbTAdBgNVHQ4EFgQUOR3253bSc8CX
ZF4eCtjaP4dWxEUwHwYDVR0jBBgwFoAUcfutOYMJdzUK96hkTQjpkhz9joMwCQYH
KoZIzj0EAQNIADBFAiEAu2lSN/dZp6rB4YCvotwP0zbQE3V15GpZcfUFFM/typIC
ICrhQxRhkH/v7aM7IpYmLBxnY8QZkqe4/56xM3rJ/JNI
-----END CERTIFICATE-----
''';

/// End-entity certificate signed by [sha1RootPem] with `ecdsa-with-SHA256`.
///
/// Used to check that the trust anchor's own weak self-signature is exempt.
const sha256LeafOfSha1RootPem = '''
-----BEGIN CERTIFICATE-----
MIIBzjCCAXWgAwIBAgIBAzAKBggqhkjOPQQDAjAxMRwwGgYDVQQDDBNCb3Jpbmcg
U0hBMSBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjA5MTExMTUzNTVa
Fw00NjA5MDYxMTUzNTVaMBsxGTAXBgNVBAMMEGxlYWYuZXhhbXBsZS5jb20wWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAASbdRMI5JwmGv21g5vR6c+iYf0puZFiV8MZ
GL5mW8gs9SfSaUX/n5gRFMm5qNwD9EgYR7wIFjLNW3Pw7SKyM7Tzo4GTMIGQMAwG
A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MBsGA1UdEQQUMBKCEGxlYWYuZXhhbXBsZS5jb20wHQYDVR0OBBYEFDkd9ud20nPA
l2ReHgrY2j+HVsRFMB8GA1UdIwQYMBaAFHH7rTmDCXc1CveoZE0I6ZIc/Y6DMAoG
CCqGSM49BAMCA0cAMEQCIEydh5Fb7GAcdyiTWr1ErHFP3adqYPxq4YHyiWZuVsnK
AiBn4k6/QhB2xgYO1xdXJRlxWYkBB+f0u0YQZ/q//xWYGw==
-----END CERTIFICATE-----
''';

void main() {
  late X509Certificate root;
  late X509Certificate intermediate;
  late X509Certificate leaf;
  late X509Verifier verifier;

  setUp(() {
    root = X509Certificate.fromPem(rootPem);
    intermediate = X509Certificate.fromPem(intermediatePem);
    leaf = X509Certificate.fromPem(leafPem);
    verifier = X509Verifier()..addTrustedCertificate(root);
  });

  X509VerificationResult verify({
    List<X509PeerName> peerNames = const [],
    Set<X509HostnameFlag> hostnameFlags = const {
      X509HostnameFlag.neverCheckSubject,
    },
    X509Purpose? purpose,
    int? maxIntermediates,
  }) => verifier.verify(
    leaf: leaf,
    intermediates: [intermediate],
    peerNames: peerNames,
    hostnameFlags: hostnameFlags,
    purpose: purpose,
    maxIntermediates: maxIntermediates,
  );

  group('X509Verifier peer names', () {
    test('accepts a matching DNS name', () {
      expect(
        verify(peerNames: [const X509PeerName.dnsName('leaf.example.com')]),
        isA<X509VerificationResult>().having((r) => r.isValid, 'isValid', true),
      );
    });

    test('rejects a mismatched DNS name', () {
      final result = verify(
        peerNames: [const X509PeerName.dnsName('other.example.com')],
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('Hostname mismatch'));
      expect(result.errorDepth, equals(0));
    });

    test('matches any of several DNS names', () {
      expect(
        verify(
          peerNames: const [
            X509PeerName.dnsName('other.example.com'),
            X509PeerName.dnsName('leaf.example.com'),
          ],
        ).isValid,
        isTrue,
      );
    });

    test('matches a wildcard SAN', () {
      expect(
        verify(
          peerNames: [const X509PeerName.dnsName('host.wild.example.com')],
        ).isValid,
        isTrue,
      );
    });

    test('noWildcards disables wildcard matching', () {
      expect(
        verify(
          peerNames: [const X509PeerName.dnsName('host.wild.example.com')],
          hostnameFlags: const {
            X509HostnameFlag.neverCheckSubject,
            X509HostnameFlag.noWildcards,
          },
        ).isValid,
        isFalse,
      );
    });

    test('accepts a matching IP address', () {
      expect(
        verify(peerNames: [const X509PeerName.ipAddress('127.0.0.1')]).isValid,
        isTrue,
      );
    });

    test('rejects a mismatched IP address', () {
      final result = verify(
        peerNames: [const X509PeerName.ipAddress('10.0.0.1')],
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('IP address mismatch'));
    });

    test('accepts a matching email address', () {
      expect(
        verify(
          peerNames: [const X509PeerName.emailAddress('test@example.com')],
        ).isValid,
        isTrue,
      );
    });

    test('rejects a mismatched email address', () {
      expect(
        verify(
          peerNames: [const X509PeerName.emailAddress('other@example.com')],
        ).isValid,
        isFalse,
      );
    });

    test('names of different kinds must all match', () {
      expect(
        verify(
          peerNames: const [
            X509PeerName.dnsName('leaf.example.com'),
            X509PeerName.ipAddress('10.0.0.1'),
          ],
        ).isValid,
        isFalse,
      );
    });

    test('rejects more than one IP address', () {
      expect(
        () => verify(
          peerNames: const [
            X509PeerName.ipAddress('127.0.0.1'),
            X509PeerName.ipAddress('10.0.0.1'),
          ],
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects more than one email address', () {
      expect(
        () => verify(
          peerNames: const [
            X509PeerName.emailAddress('test@example.com'),
            X509PeerName.emailAddress('other@example.com'),
          ],
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('X509Verifier purpose', () {
    test('accepts a serverAuth leaf for tlsServer', () {
      expect(verify(purpose: X509Purpose.tlsServer).isValid, isTrue);
    });

    test('rejects a serverAuth leaf for tlsClient', () {
      final result = verify(purpose: X509Purpose.tlsClient);
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('purpose'));
    });

    test('accepts any purpose when unset', () {
      expect(verify().isValid, isTrue);
      expect(verify(purpose: X509Purpose.any).isValid, isTrue);
    });
  });

  group('X509Verifier chain depth', () {
    test('accepts a chain within the intermediate limit', () {
      expect(verify(maxIntermediates: 1).isValid, isTrue);
    });

    test('rejects a chain exceeding the intermediate limit', () {
      final result = verify(maxIntermediates: 0);
      expect(result.isValid, isFalse);
      // BoringSSL refuses to extend the chain past the limit, so it reports
      // the resulting dead end rather than a dedicated "chain too long" error.
      expect(result.errorMessage, contains('issuer certificate'));
    });

    test('rejects a negative limit', () {
      expect(
        () => verify(maxIntermediates: -1),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('X509Verifier weak signature digests', () {
    late X509Certificate sha1Root;
    late X509Verifier sha1Verifier;

    setUp(() {
      sha1Root = X509Certificate.fromPem(sha1RootPem);
      sha1Verifier = X509Verifier()..addTrustedCertificate(sha1Root);
    });

    test('rejects a SHA-1 signed leaf by default', () {
      final result = sha1Verifier.verify(
        leaf: X509Certificate.fromPem(sha1LeafPem),
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('ecdsa-with-SHA1'));
      expect(result.errorDepth, equals(0));
    });

    test('accepts a SHA-1 signed leaf when explicitly allowed', () {
      final result = sha1Verifier.verify(
        leaf: X509Certificate.fromPem(sha1LeafPem),
        insecurelyAllowWeakSignatureDigests: true,
      );
      expect(result.isValid, isTrue);
    });

    test('exempts the trust anchor\'s own weak self-signature', () {
      final result = sha1Verifier.verify(
        leaf: X509Certificate.fromPem(sha256LeafOfSha1RootPem),
      );
      expect(result.isValid, isTrue);
    });

    test('accepts a SHA-256 chain', () {
      expect(verify().isValid, isTrue);
    });
  });

  group('X509PeerName', () {
    test('has value equality', () {
      expect(
        const X509PeerName.dnsName('a.example.com'),
        equals(const X509PeerName.dnsName('a.example.com')),
      );
      expect(
        const X509PeerName.dnsName('a.example.com'),
        isNot(equals(const X509PeerName.emailAddress('a.example.com'))),
      );
    });

    test('has a readable toString', () {
      expect(
        const X509PeerName.ipAddress('::1').toString(),
        equals('X509PeerName.ipAddress(::1)'),
      );
    });
  });
}
