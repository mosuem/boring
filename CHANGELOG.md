## 0.2.0

- Added a minimal ASN.1 DER reader (`package:boring/asn1.dart`) for decoding the
  application-specific payloads of X.509 extensions:
  - `Asn1Reader`, `Asn1Value`, `Asn1Class`, `Asn1Tag`, and `Asn1Exception`.
  - Decodes strings, integers, booleans, object identifiers, and nested
    constructed elements, including long-form lengths and context-specific tags.
- Added X.509 v3 extension support to `X509Certificate`:
  - `extensions` enumerates every extension with its OID, short name,
    criticality, and raw DER payload.
  - `getExtension(oid)` and `getExtensionString(oid)` look up an extension by
    dotted-decimal OID, transparently unwrapping DER-encoded ASN.1 strings and
    falling back to raw UTF-8 payloads.
  - `subjectAlternativeNames` and `issuerAlternativeNames` decode
    `GeneralName` entries, with `emailAddresses`, `dnsNames`, and `uris`
    convenience getters.
  - `keyUsage`, `extendedKeyUsage`, `isCertificateAuthority`, and
    `subjectKeyIdentifier`.
- Added `X509Oid` constants for standard X.509 extensions, Certificate
  Transparency SCTs, and all Sigstore Fulcio OIDC extensions
  (`1.3.6.1.4.1.57264.1.*`), plus `KeyUsage` bit constants.
- Added a Project Wycheproof conformance test suite (`tool/run_conformance_tests.sh`)
  covering AEAD, Ed25519, ECDSA, RSA, HKDF, and HMAC.
- Added GitHub Actions CI running formatting, analysis, unit tests, and the
  conformance suite.

## 0.1.0

- Initial release of `package:boring`.
- High-performance cryptography and PKI powered by BoringSSL with Dart Native Assets.
- Isolated symbols with `bssl_dart` prefix to guarantee 100% collision-free execution alongside Flutter and Dart VM internal BoringSSL.
- Cryptographic primitives:
  - CSPRNG (`BoringRand.secureRandom`)
  - Digests (`BoringDigest`: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, streaming `DigestContext`)
  - HMAC (`BoringHmac`: SHA-256, SHA-384, SHA-512, streaming `HmacContext`)
  - HKDF (`BoringHkdf`: extract, expand, deriveBits)
  - AEAD (`BoringAead`: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305)
  - Ed25519 (`BoringEd25519`: keypair generation, sign, verify)
  - Asymmetric Keys (`BoringPrivateKey`, `BoringPublicKey`: RSA, ECDSA P-256/P-384/P-521, PKCS#8 & SPKI DER/PEM)
- PKI & X.509:
  - Certificate parsing (`X509Certificate`: DER and PEM, metadata getters, public key extraction)
  - Chain verification (`X509Verifier`: trust store management, intermediate chain resolution, time-based verification)
