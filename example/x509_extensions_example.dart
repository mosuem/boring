// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

// Inspects the extensions of a real Sigstore Fulcio code-signing certificate.
//
// Fulcio is Sigstore's certificate authority: it issues short-lived
// certificates that bind an OIDC identity (a person's email or a CI workflow)
// to an ephemeral signing key. The identity lives in the Subject Alternative
// Name extension, and the surrounding OIDC context lives in custom extensions
// under the `1.3.6.1.4.1.57264.1.*` OID arc.

import 'package:boring/x509.dart';

/// A Fulcio certificate issued to the public `sigstore-conformance` OIDC
/// beacon workflow. Certificates like this are valid for only ten minutes;
/// this one has long expired and is used purely for illustration.
const fulcioCertificatePem = '''
-----BEGIN CERTIFICATE-----
MIIIMTCCB7egAwIBAgIUaL/tsmQTHk21mt1Uuk+w7avDBz4wCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjQwMzE5MTcyNjI2WhcNMjQwMzE5MTczNjI2WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE22S1j/NkEXzBPQAuamHXLpwx+RPnnzZQl/pk
EZ8xorvKnzujCS1mVTBo9kBxmYWo2DHtyVyfgnuOqVTzLYmho6OCBtYwggbSMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUFv1S
CziEKN2rRyrjeVlFbSLg1/QwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wgaUGA1UdEQEB/wSBmjCBl4aBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9y
ZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJl
YWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMt
YmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6
Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAfBgorBgEEAYO/
MAECBBF3b3JrZmxvd19kaXNwYXRjaDA2BgorBgEEAYO/MAEDBChjN2IzZGZiMzM1
ZjA1MWUxYzg2YmRhNGM3MTZmYWM5N2RmNjJhZDgxMC0GCisGAQQBg78wAQQEH0V4
dHJlbWVseSBkYW5nZXJvdXMgT0lEQyBiZWFjb24wSQYKKwYBBAGDvzABBQQ7c2ln
c3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lk
Yy1iZWFjb24wHQYKKwYBBAGDvzABBgQPcmVmcy9oZWFkcy9tYWluMDsGCisGAQQB
g78wAQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50
LmNvbTCBpgYKKwYBBAGDvzABCQSBlwyBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdz
dG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRj
LWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9p
ZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABCgQqDChj
N2IzZGZiMzM1ZjA1MWUxYzg2YmRhNGM3MTZmYWM5N2RmNjJhZDgxMB0GCisGAQQB
g78wAQsEDwwNZ2l0aHViLWhvc3RlZDBeBgorBgEEAYO/MAEMBFAMTmh0dHBzOi8v
Z2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vy
b3VzLXB1YmxpYy1vaWRjLWJlYWNvbjA4BgorBgEEAYO/MAENBCoMKGM3YjNkZmIz
MzVmMDUxZTFjODZiZGE0YzcxNmZhYzk3ZGY2MmFkODEwHwYKKwYBBAGDvzABDgQR
DA9yZWZzL2hlYWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk2MzI1OTY4OTcwNwYK
KwYBBAGDvzABEAQpDCdodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9y
bWFuY2UwGQYKKwYBBAGDvzABEQQLDAkxMzE4MDQ1NjMwgaYGCisGAQQBg78wARIE
gZcMgZRodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0
cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24vLmdpdGh1Yi93b3Jr
Zmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1vaWRjLWJlYWNvbi55bWxAcmVmcy9o
ZWFkcy9tYWluMDgGCisGAQQBg78wARMEKgwoYzdiM2RmYjMzNWYwNTFlMWM4NmJk
YTRjNzE2ZmFjOTdkZjYyYWQ4MTAhBgorBgEEAYO/MAEUBBMMEXdvcmtmbG93X2Rp
c3BhdGNoMIGBBgorBgEEAYO/MAEVBHMMcWh0dHBzOi8vZ2l0aHViLmNvbS9zaWdz
dG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRj
LWJlYWNvbi9hY3Rpb25zL3J1bnMvODM0NzQ4MTYyOC9hdHRlbXB0cy8xMBYGCisG
AQQBg78wARYECAwGcHVibGljMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbH
ETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGOV8AHpgAABAMARzBFAiBFeMbp
FarlPwb0naTr4mjWDvXApOd9ORqOk36Brt9SmwIhAJJvjor+DXUXr7S3Vm9jVFT3
CL0BxcKGj86m5mYzQvubMAoGCCqGSM49BAMDA2gAMGUCMA8lTixdS4iN9mAUduOb
cSJmhZLyvK7zaX05DLEDCgPWxDHk+JBZUKYRIuHHgwFnOwIxALMamo9dfENMzRgN
CzYfp/y+rSOhVjXXE9mCn6BuJETlpRDfGvxUg/5LF9f4lYqozA==
-----END CERTIFICATE-----
''';

void main() {
  final cert = X509Certificate.fromPem(fulcioCertificatePem);

  print('=== Certificate ===');
  print('Issuer:    ${cert.issuer}');
  print('Valid:     ${cert.notBefore} to ${cert.notAfter}');
  print('Key type:  ${cert.publicKey.keyType.name}');
  print('Is CA:     ${cert.isCertificateAuthority}');

  print('\n=== Signer identity (Subject Alternative Name) ===');
  for (final name in cert.subjectAlternativeNames) {
    print('${name.type.name}: ${name.value}');
  }

  print('\n=== Usage constraints ===');
  final canSign = (cert.keyUsage ?? 0) & KeyUsage.digitalSignature != 0;
  print('Digital signature: $canSign');
  print('Extended key usage: ${cert.extendedKeyUsage}');

  print('\n=== Sigstore OIDC context ===');
  const fulcioOids = {
    'OIDC issuer': X509Oid.fulcioIssuerV2,
    'Build trigger': X509Oid.fulcioBuildTrigger,
    'Source repository': X509Oid.fulcioSourceRepositoryUri,
    'Source ref': X509Oid.fulcioSourceRepositoryRef,
    'Source digest': X509Oid.fulcioSourceRepositoryDigest,
    'Runner environment': X509Oid.fulcioRunnerEnvironment,
    'Repository visibility': X509Oid.fulcioSourceRepositoryVisibility,
  };
  fulcioOids.forEach((label, oid) {
    print('$label: ${cert.getExtensionString(oid)}');
  });

  print('\n=== All extensions ===');
  for (final ext in cert.extensions) {
    final critical = ext.isCritical ? ' [critical]' : '';
    print('${ext.oid} (${ext.shortName})$critical - ${ext.value.length} bytes');
  }
}
