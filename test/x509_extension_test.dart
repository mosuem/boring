// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:io';

import 'package:boring/x509.dart';
import 'package:test/test.dart';

/// A real Sigstore Fulcio leaf certificate issued to the public
/// `sigstore-conformance` OIDC beacon workflow.
X509Certificate loadFulcioLeaf() {
  const candidates = [
    'test/fixtures/fulcio_leaf.pem',
    '../test/fixtures/fulcio_leaf.pem',
  ];
  for (final path in candidates) {
    final file = File(path);
    if (file.existsSync()) {
      return X509Certificate.fromPem(file.readAsStringSync());
    }
  }
  throw StateError('Could not locate test/fixtures/fulcio_leaf.pem');
}

void main() {
  group('X509Certificate extensions', () {
    late X509Certificate cert;

    setUp(() {
      cert = loadFulcioLeaf();
    });

    test('enumerates every extension with OID and criticality', () {
      final extensions = cert.extensions;

      expect(extensions, isNotEmpty);
      final oids = extensions.map((e) => e.oid).toList();
      expect(oids, contains(X509Oid.subjectAltName));
      expect(oids, contains(X509Oid.keyUsage));
      expect(oids, contains(X509Oid.extendedKeyUsage));
      expect(oids, contains(X509Oid.fulcioIssuerV1));

      final keyUsageExt = extensions.firstWhere(
        (e) => e.oid == X509Oid.keyUsage,
      );
      expect(keyUsageExt.isCritical, isTrue);
      expect(keyUsageExt.shortName, 'X509v3 Key Usage');

      final sanExt = extensions.firstWhere(
        (e) => e.oid == X509Oid.subjectAltName,
      );
      expect(sanExt.isCritical, isTrue);
    });

    test('reads the Subject Alternative Name URI identity', () {
      final names = cert.subjectAlternativeNames;

      expect(names, hasLength(1));
      expect(names.single.type, GeneralNameType.uniformResourceIdentifier);
      expect(
        names.single.value,
        'https://github.com/sigstore-conformance/extremely-dangerous-public-'
        'oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml'
        '@refs/heads/main',
      );

      expect(cert.uris, hasLength(1));
      expect(cert.emailAddresses, isEmpty);
      expect(cert.dnsNames, isEmpty);
    });

    test('reads the legacy raw-UTF-8 Fulcio OIDC issuer extension', () {
      expect(
        cert.getExtensionString(X509Oid.fulcioIssuerV1),
        'https://token.actions.githubusercontent.com',
      );
    });

    test('reads DER-wrapped UTF8String Fulcio extensions', () {
      expect(
        cert.getExtensionString(X509Oid.fulcioIssuerV2),
        'https://token.actions.githubusercontent.com',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioRunnerEnvironment),
        'github-hosted',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioSourceRepositoryUri),
        'https://github.com/sigstore-conformance/'
        'extremely-dangerous-public-oidc-beacon',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioSourceRepositoryDigest),
        'c7b3dfb335f051e1c86bda4c716fac97df62ad81',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioSourceRepositoryRef),
        'refs/heads/main',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioBuildTrigger),
        'workflow_dispatch',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioSourceRepositoryVisibility),
        'public',
      );
    });

    test('reads the legacy raw-UTF-8 workflow extensions', () {
      expect(
        cert.getExtensionString(X509Oid.fulcioGithubWorkflowTrigger),
        'workflow_dispatch',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioGithubWorkflowSha),
        'c7b3dfb335f051e1c86bda4c716fac97df62ad81',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioGithubWorkflowRepository),
        'sigstore-conformance/extremely-dangerous-public-oidc-beacon',
      );
      expect(
        cert.getExtensionString(X509Oid.fulcioGithubWorkflowRef),
        'refs/heads/main',
      );
    });

    test('returns null for an absent extension', () {
      expect(cert.getExtension('1.2.3.4.5.6.7.8.9'), isNull);
      expect(cert.getExtensionString('1.2.3.4.5.6.7.8.9'), isNull);
    });

    test('reports key usage as digital signature only', () {
      final usage = cert.keyUsage;
      expect(usage, isNotNull);
      expect(usage! & KeyUsage.digitalSignature, isNonZero);
      expect(usage & KeyUsage.keyCertSign, isZero);
      expect(usage & KeyUsage.crlSign, isZero);
    });

    test('reports code signing extended key usage', () {
      // 1.3.6.1.5.5.7.3.3 is id-kp-codeSigning.
      expect(cert.extendedKeyUsage, contains('1.3.6.1.5.5.7.3.3'));
    });

    test('is not a certificate authority', () {
      expect(cert.isCertificateAuthority, isFalse);
    });

    test('exposes the subject key identifier', () {
      final skid = cert.subjectKeyIdentifier;

      expect(skid, isNotNull);
      expect(skid, hasLength(20));
      expect(
        skid!.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        '16fd520b388428ddab472ae3795945 6d22e0d7f4'.replaceAll(' ', ''),
      );
    });

    test('exposes the authority key identifier and sha256Fingerprint', () {
      final akid = cert.authorityKeyIdentifier;
      expect(akid, isNotNull);
      expect(akid, hasLength(20));
      expect(
        akid!.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        'dfd3e9cf56241196f9a8d8e92855a2c62e18643f',
      );
      expect(cert.sha256Fingerprint, hasLength(32));
    });

    test('exposes raw extension bytes for unparsed extensions', () {
      final sct = cert.getExtension(X509Oid.signedCertificateTimestamps);

      expect(sct, isNotNull);
      expect(sct!.value, isNotEmpty);
      // The SCT list is a DER OCTET STRING wrapping a TLS-encoded structure.
      expect(sct.asn1?.hasUniversalTag(Asn1Tag.octetString), isTrue);
      // Binary OCTET STRING must return null for stringValue instead of
      // throwing.
      expect(sct.stringValue, isNull);
      expect(
        cert.getExtensionString(X509Oid.signedCertificateTimestamps),
        isNull,
      );

      // Adding the same certificate twice to X509Verifier is idempotent.
      final verifier = X509Verifier();
      verifier.addTrustedCertificate(cert);
      verifier.addTrustedCertificate(cert);
      verifier.dispose();
    });

    test('extension payloads can be decoded with the ASN.1 reader', () {
      final ext = cert.getExtension(X509Oid.fulcioRunnerEnvironment);
      expect(ext, isNotNull);

      final value = Asn1Reader.parse(ext!.value);
      expect(value.hasUniversalTag(Asn1Tag.utf8String), isTrue);
      expect(value.asString(), 'github-hosted');
    });

    test('certificate metadata still parses correctly', () {
      expect(cert.version, 3);
      expect(cert.issuer, contains('sigstore-intermediate'));
      expect(cert.notBefore.isBefore(cert.notAfter), isTrue);
      expect(cert.publicKey.keyType, KeyType.ec);
    });
  });
}
