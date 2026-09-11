## 0.3.0

`X509Verifier` can now check peer identity, key usage and chain length, and the
package is validated against the [x509-limbo](https://x509-limbo.com) path
validation suite.

- `X509Verifier.verify` gained four options, all backed by
  `X509_VERIFY_PARAM`:
  - `peerNames`: names the leaf must assert, as `X509PeerName.dnsName`,
    `X509PeerName.ipAddress` or `X509PeerName.emailAddress`. Several DNS names
    are matched with OR semantics.
  - `hostnameFlags`: `X509HostnameFlag.neverCheckSubject` (the default, which
    suppresses BoringSSL's legacy subject common name fallback) and
    `X509HostnameFlag.noWildcards`.
  - `purpose`: an `X509Purpose` enabling key usage and extended key usage
    checks, e.g. `X509Purpose.tlsServer`.
  - `maxIntermediates`: a chain length limit, excluding leaf and trust anchor.
- `X509VerificationResult` gained `errorDepth`, the position in the chain at
  which verification failed.
- Added the x509-limbo conformance suite (`./tool/run_x509_limbo_tests.sh`),
  covering 9,770 chain building and validation testcases. 94.5% agree with the
  suite; the remainder are listed with an explanation in
  `test/conformance/x509_limbo_expected_failures.txt`.

This release also removes hand-written parsing logic from the Dart layer. Every
ASN.1 operation is now delegated to BoringSSL, keeping `package:boring` a thin
wrapper rather than a reimplementation.

- **Breaking:** `Asn1Value.identifier` (the raw DER identifier octet) is
  replaced by `Asn1Value.tag`, which holds BoringSSL's `CBS_ASN1_TAG`. Use
  `tagClass`, `isConstructed`, and `tagNumber` instead of decoding it by hand.
- **Breaking:** the `Asn1Value` constructor is now private; values are produced
  by `Asn1Reader`.
- The DER reader is now backed by BoringSSL's `CBS` parser:
  - Tag/length parsing uses `CBS_get_any_asn1_element`.
  - `asObjectIdentifier()` uses `CBS_asn1_oid_to_text`.
  - `asInteger()` uses `CBS_is_valid_asn1_integer` with `BN_bin2bn`/`BN_bn2dec`.
  - `asBoolean()` uses `CBS_get_asn1_bool`.
  - `asString()` uses `ASN1_STRING_to_UTF8`, which correctly transcodes every
    ASN.1 string type BoringSSL supports.
  - `Asn1Tag` and `Asn1Class` now re-export BoringSSL's `CBS_ASN1_*` constants.
  - As a result, DER encoding rules are enforced by BoringSSL: non-minimal
    long-form lengths and non-minimal `INTEGER` encodings are now rejected.
- `Asn1Value.asString()` accepts an optional `stringType` for IMPLICIT
  context-specific tags, where the tag number identifies the `CHOICE`
  alternative rather than the underlying string type.
- Certificate validity times are parsed with `ASN1_TIME_to_posix` instead of
  slicing the `GeneralizedTime` string in Dart.
- Fixed `X509Extension.stringValue` mangling non-ASCII values in the raw
  (non-DER) fallback path, which decoded UTF-8 bytes as UTF-16 code units.
- Internal: the repeated FFI marshalling patterns are now shared combinators
  (`withResource`, `withOutputBuffer`, `withSizedOutput`, `takeOwnedString`,
  `withMemBioString`, `withMemBufBio`), removing every hand-written
  `try`/`finally` around a BoringSSL `X_new` / `X_free` pair and the
  duplicated BIO-to-string reader. This also fixes a latent bug in that reader,
  which decoded UTF-8 in fixed 1 KiB chunks and could split a multi-byte
  sequence across a chunk boundary.

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
