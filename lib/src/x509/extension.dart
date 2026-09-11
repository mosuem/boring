// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import '../asn1/asn1.dart';

/// The kind of an X.509 `GeneralName` (RFC 5280, Section 4.2.1.6).
///
/// The numeric [tag] is the context-specific tag used in the DER encoding of
/// the `GeneralName` CHOICE.
enum GeneralNameType {
  /// `otherName`: a type-id / value pair for application-specific names.
  otherName(0),

  /// `rfc822Name`: an email address.
  rfc822Name(1),

  /// `dNSName`: a DNS host name.
  dnsName(2),

  /// `x400Address`: an ORAddress, rarely used in practice.
  x400Address(3),

  /// `directoryName`: an X.500 distinguished name.
  directoryName(4),

  /// `ediPartyName`: an EDI party name, rarely used in practice.
  ediPartyName(5),

  /// `uniformResourceIdentifier`: a URI. Used by Sigstore for workflow
  /// identities such as
  /// `https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main`.
  uniformResourceIdentifier(6),

  /// `iPAddress`: a raw 4-byte (IPv4) or 16-byte (IPv6) address.
  ipAddress(7),

  /// `registeredID`: an object identifier.
  registeredId(8);

  const GeneralNameType(this.tag);

  /// The context-specific DER tag number for this name type.
  final int tag;

  /// Returns the [GeneralNameType] for [tag], or `null` if unrecognized.
  static GeneralNameType? fromTag(int tag) {
    for (final type in GeneralNameType.values) {
      if (type.tag == tag) return type;
    }
    return null;
  }
}

/// A single entry of an X.509 `SubjectAltName` or `IssuerAltName` extension.
final class GeneralName {
  /// The kind of name this entry holds.
  final GeneralNameType type;

  /// The textual form of the name.
  ///
  /// For [GeneralNameType.rfc822Name], [GeneralNameType.dnsName], and
  /// [GeneralNameType.uniformResourceIdentifier] this is the literal string.
  /// For [GeneralNameType.ipAddress] this is the dotted-quad or colon-separated
  /// textual address. For other types this is a best-effort rendering; use
  /// [rawValue] to inspect the original DER bytes.
  final String value;

  /// The raw DER contents of this name entry.
  final Uint8List rawValue;

  /// Creates a [GeneralName].
  const GeneralName({
    required this.type,
    required this.value,
    required this.rawValue,
  });

  @override
  String toString() => '${type.name}:$value';
}

/// An X.509 v3 certificate extension (RFC 5280, Section 4.1.2.9).
final class X509Extension {
  /// The dotted-decimal object identifier of this extension.
  ///
  /// For example `2.5.29.17` for `subjectAltName`, or `1.3.6.1.4.1.57264.1.1`
  /// for Sigstore's OIDC issuer extension.
  final String oid;

  /// The short name of this extension if BoringSSL recognizes the OID,
  /// otherwise the dotted-decimal OID.
  final String shortName;

  /// Whether relying parties must reject the certificate if they cannot
  /// process this extension.
  final bool isCritical;

  /// The raw DER-encoded contents of the extension's `extnValue` OCTET STRING.
  ///
  /// This is the inner payload; the surrounding OCTET STRING wrapper has
  /// already been removed.
  final Uint8List value;

  /// Creates an [X509Extension].
  const X509Extension({
    required this.oid,
    required this.shortName,
    required this.isCritical,
    required this.value,
  });

  /// Decodes [value] as a DER element, or returns `null` if [value] is not
  /// well-formed DER.
  Asn1Value? get asn1 => Asn1Reader.tryParse(value);

  /// Decodes [value] as an ASN.1 string, falling back to raw UTF-8.
  ///
  /// Sigstore's Fulcio issues two generations of OIDC extensions: the legacy
  /// `1.3.6.1.4.1.57264.1.1`–`1.3.6.1.4.1.57264.1.6` extensions store raw
  /// UTF-8 bytes, while the newer `1.3.6.1.4.1.57264.1.8`+ extensions store a
  /// DER-encoded `UTF8String`. This getter transparently handles both.
  String? get stringValue {
    final parsed = asn1;
    if (parsed != null && !parsed.isConstructed) {
      const stringTags = {
        Asn1Tag.utf8String,
        Asn1Tag.printableString,
        Asn1Tag.ia5String,
        Asn1Tag.visibleString,
        Asn1Tag.teletexString,
        Asn1Tag.bmpString,
        Asn1Tag.octetString,
      };
      if (stringTags.any(parsed.hasUniversalTag)) {
        return parsed.asString();
      }
    }
    try {
      return String.fromCharCodes(value);
    } on FormatException {
      return null;
    }
  }

  @override
  String toString() =>
      'X509Extension($shortName, critical: $isCritical, '
      '${value.length} bytes)';
}

/// Object identifiers for extensions commonly encountered in X.509 and
/// Sigstore certificates.
abstract final class X509Oid {
  /// `subjectAltName` (RFC 5280, Section 4.2.1.6).
  static const String subjectAltName = '2.5.29.17';

  /// `issuerAltName` (RFC 5280, Section 4.2.1.7).
  static const String issuerAltName = '2.5.29.18';

  /// `basicConstraints` (RFC 5280, Section 4.2.1.9).
  static const String basicConstraints = '2.5.29.19';

  /// `keyUsage` (RFC 5280, Section 4.2.1.3).
  static const String keyUsage = '2.5.29.15';

  /// `extKeyUsage` (RFC 5280, Section 4.2.1.12).
  static const String extendedKeyUsage = '2.5.29.37';

  /// `subjectKeyIdentifier` (RFC 5280, Section 4.2.1.2).
  static const String subjectKeyIdentifier = '2.5.29.14';

  /// `authorityKeyIdentifier` (RFC 5280, Section 4.2.1.1).
  static const String authorityKeyIdentifier = '2.5.29.35';

  /// Signed Certificate Timestamp list for Certificate Transparency
  /// (RFC 6962, Section 3.3).
  static const String signedCertificateTimestamps = '1.3.6.1.4.1.11129.2.4.2';

  /// Sigstore Fulcio: the OIDC issuer that authenticated the signer, such as
  /// `https://token.actions.githubusercontent.com`. Legacy raw-UTF-8 form.
  static const String fulcioIssuerV1 = '1.3.6.1.4.1.57264.1.1';

  /// Sigstore Fulcio: the CI trigger event, e.g. `workflow_dispatch`.
  static const String fulcioGithubWorkflowTrigger = '1.3.6.1.4.1.57264.1.2';

  /// Sigstore Fulcio: the git commit SHA the signing workflow ran against.
  static const String fulcioGithubWorkflowSha = '1.3.6.1.4.1.57264.1.3';

  /// Sigstore Fulcio: the name of the signing workflow.
  static const String fulcioGithubWorkflowName = '1.3.6.1.4.1.57264.1.4';

  /// Sigstore Fulcio: the repository the signing workflow belongs to.
  static const String fulcioGithubWorkflowRepository = '1.3.6.1.4.1.57264.1.5';

  /// Sigstore Fulcio: the git ref the signing workflow ran against.
  static const String fulcioGithubWorkflowRef = '1.3.6.1.4.1.57264.1.6';

  /// Sigstore Fulcio: the OIDC issuer, DER `UTF8String` form. Preferred over
  /// [fulcioIssuerV1] for certificates issued after Fulcio v1.1.
  static const String fulcioIssuerV2 = '1.3.6.1.4.1.57264.1.8';

  /// Sigstore Fulcio: the build signer URI.
  static const String fulcioBuildSignerUri = '1.3.6.1.4.1.57264.1.9';

  /// Sigstore Fulcio: the build signer digest.
  static const String fulcioBuildSignerDigest = '1.3.6.1.4.1.57264.1.10';

  /// Sigstore Fulcio: the runner environment, e.g. `github-hosted`.
  static const String fulcioRunnerEnvironment = '1.3.6.1.4.1.57264.1.11';

  /// Sigstore Fulcio: the source repository URI.
  static const String fulcioSourceRepositoryUri = '1.3.6.1.4.1.57264.1.12';

  /// Sigstore Fulcio: the source repository digest.
  static const String fulcioSourceRepositoryDigest = '1.3.6.1.4.1.57264.1.13';

  /// Sigstore Fulcio: the source repository ref.
  static const String fulcioSourceRepositoryRef = '1.3.6.1.4.1.57264.1.14';

  /// Sigstore Fulcio: the source repository identifier.
  static const String fulcioSourceRepositoryIdentifier =
      '1.3.6.1.4.1.57264.1.15';

  /// Sigstore Fulcio: the source repository owner URI.
  static const String fulcioSourceRepositoryOwnerUri = '1.3.6.1.4.1.57264.1.16';

  /// Sigstore Fulcio: the source repository owner identifier.
  static const String fulcioSourceRepositoryOwnerIdentifier =
      '1.3.6.1.4.1.57264.1.17';

  /// Sigstore Fulcio: the build config URI.
  static const String fulcioBuildConfigUri = '1.3.6.1.4.1.57264.1.18';

  /// Sigstore Fulcio: the build config digest.
  static const String fulcioBuildConfigDigest = '1.3.6.1.4.1.57264.1.19';

  /// Sigstore Fulcio: the build trigger event.
  static const String fulcioBuildTrigger = '1.3.6.1.4.1.57264.1.20';

  /// Sigstore Fulcio: the run invocation URI.
  static const String fulcioRunInvocationUri = '1.3.6.1.4.1.57264.1.21';

  /// Sigstore Fulcio: the source repository visibility at signing time.
  static const String fulcioSourceRepositoryVisibility =
      '1.3.6.1.4.1.57264.1.22';
}

/// Key usage bits from the `keyUsage` extension (RFC 5280, Section 4.2.1.3).
abstract final class KeyUsage {
  /// The key may be used to verify digital signatures other than certificate
  /// or CRL signatures.
  static const int digitalSignature = 0x0080;

  /// The key may be used to provide non-repudiation (content commitment).
  static const int nonRepudiation = 0x0040;

  /// The key may be used to encipher private or secret keys.
  static const int keyEncipherment = 0x0020;

  /// The key may be used to directly encipher raw user data.
  static const int dataEncipherment = 0x0010;

  /// The key may be used for key agreement.
  static const int keyAgreement = 0x0008;

  /// The key may be used to verify signatures on certificates.
  static const int keyCertSign = 0x0004;

  /// The key may be used to verify signatures on CRLs.
  static const int crlSign = 0x0002;

  /// When [keyAgreement] is also set, the key may only be used for
  /// enciphering.
  static const int encipherOnly = 0x0001;

  /// When [keyAgreement] is also set, the key may only be used for
  /// deciphering.
  static const int decipherOnly = 0x8000;
}
