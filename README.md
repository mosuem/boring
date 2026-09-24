# boring

High-performance cryptography and PKI powered by **BoringSSL** with **Dart Native Assets**.

[![pub package](https://img.shields.io/pub/v/boring.svg)](https://pub.dev/packages/boring)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`package:boring` brings Google's production-grade cryptographic library [BoringSSL](https://boringssl.googlesource.com/boringssl/) directly to Dart and Flutter applications across Linux, macOS, Windows, Android, and iOS.

---

## Key Highlights

- **100% Symbol Isolation (`bssl_dart`)**: Compiled with `-DBORINGSSL_PREFIX=bssl_dart`, completely eliminating dynamic linker collisions or symbol conflicts with Flutter, the Dart VM, or system OpenSSL libraries.
- **Dart Native Assets**: Bundles and dynamically loads native code seamlessly via `package:code_assets` and `package:hooks`.
- **Pure BoringSSL PKI**: Full X.509 certificate parsing (DER/PEM) and cryptographic chain verification without external platform dependencies.
- **Modern Cryptography**: Fast, constant-time implementations of AEAD (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305), Ed25519, X25519, ECDSA/ECDH (P-256, P-384, P-521), RSA (PSS / PKCS#1 / OAEP), BLAKE2b-256, HKDF, PBKDF2, and HMAC.
- **X.509 Extensions & ASN.1**: Typed access to Subject Alternative Names, key usage, and arbitrary custom OID extensions, plus a DER reader for decoding their payloads.
- **Native Memory Hygiene**: Ephemeral secret buffers in FFI arenas are scrubbed with `OPENSSL_cleanse` before deallocation, and native handles support explicit `.dispose()` alongside `NativeFinalizer`.

---

## Getting Started

Add `boring` to your `pubspec.yaml`:

```yaml
dependencies:
  boring: ^0.3.0
```

---

## Usage

### 1. Cryptographically Secure Random Bytes (CSPRNG)

```dart
import 'package:boring/crypto.dart';

final randomBytes = BoringRand.secureRandom(32);
```

### 2. Message Digests (Hashing)

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/crypto.dart';

final data = Uint8List.fromList(utf8.encode('Hello World'));

// One-shot hashing
final sha256Hash = BoringDigest.sha256(data);
final sha512Hash = BoringDigest.sha512(data);
final blake2bHash = BoringDigest.blake2b256(data);

// Streaming digest
final ctx = DigestContext(HashAlgorithm.sha256);
ctx.update(Uint8List.fromList(utf8.encode('chunk 1')));
ctx.update(Uint8List.fromList(utf8.encode('chunk 2')));
final hash = ctx.finalize();
```

### 3. HMAC & Constant-Time Verification

```dart
import 'package:boring/crypto.dart';

final key = BoringRand.secureRandom(32);
final mac = BoringHmac.sha256(key: key, data: data);
final isValidMac = BoringHmac.verify(
  algorithm: HashAlgorithm.sha256,
  key: key,
  data: data,
  expectedMac: mac,
);

// Constant-time byte comparison (`CRYPTO_memcmp`)
final equal = BoringCrypto.timingSafeEqual(mac, expectedMac);
```

### 4. Key Derivation (HKDF & PBKDF2)

```dart
import 'package:boring/crypto.dart';

// HKDF (RFC 5869)
final hkdfKey = BoringHkdf.deriveBits(
  algorithm: HashAlgorithm.sha256,
  ikm: keyMaterial,
  length: 32,
  salt: optionalSalt,
  info: optionalContextInfo,
);

// PBKDF2 (RFC 2898 / PKCS #5 v2.0)
final pbkdf2Key = BoringPbkdf2.deriveBits(
  algorithm: HashAlgorithm.sha256,
  password: passwordBytes,
  salt: saltBytes,
  iterations: 100000,
  length: 32,
);
```

### 5. Symmetric Ciphers & AEAD

#### Authenticated Encryption (AEAD)

Supported: `AeadAlgorithm.aes128Gcm`, `AeadAlgorithm.aes192Gcm`, `AeadAlgorithm.aes256Gcm`, `AeadAlgorithm.chacha20Poly1305`, `AeadAlgorithm.xchacha20Poly1305`.

```dart
import 'package:boring/crypto.dart';

final key = BoringRand.secureRandom(32);
final nonce = BoringRand.secureRandom(12); // 12 bytes for AES-GCM
final aead = BoringAead(AeadAlgorithm.aes256Gcm, key);

final ciphertext = aead.seal(
  nonce: nonce,
  plaintext: plaintext,
  additionalData: associatedData,
);

final decrypted = aead.open(
  nonce: nonce,
  ciphertext: ciphertext,
  additionalData: associatedData,
);
```

#### Block & Stream Ciphers (AES-CBC & AES-CTR)

Supported: `CipherAlgorithm.aes128Cbc`, `aes192Cbc`, `aes256Cbc`, `aes128Ctr`, `aes192Ctr`, `aes256Ctr`.

```dart
import 'package:boring/crypto.dart';

// AES-CBC (with PKCS#7 padding)
final cbcCipher = BoringCipher(CipherAlgorithm.aes256Cbc, key);
final cbcCiphertext = cbcCipher.encrypt(iv: iv, plaintext: plaintext);
final cbcPlaintext = cbcCipher.decrypt(iv: iv, ciphertext: cbcCiphertext);

// AES-CTR (full 128-bit counter stream)
final ctrCipher = BoringCipher(CipherAlgorithm.aes256Ctr, key);
final ctrCiphertext = ctrCipher.encrypt(iv: iv, plaintext: plaintext);
final ctrPlaintext = ctrCipher.decrypt(iv: iv, ciphertext: ctrCiphertext);

// AES Key Wrap (RFC 3394 / NIST SP 800-38F)
final wrappedKey = BoringAesKeyWrap.wrap(key: kek, data: targetKey);
final unwrappedKey = BoringAesKeyWrap.unwrap(key: kek, data: wrappedKey);
```

### 6. Ed25519 Signatures & X25519 Key Agreement

```dart
import 'package:boring/crypto.dart';

// Ed25519 Signatures (RFC 8032)
final keyPair = BoringEd25519.generateKeyPair();
final signature = BoringEd25519.sign(
  privateKey: keyPair.privateKey, // accepts 64-byte privateKey or 32-byte seed
  message: message,
);
final isValid = BoringEd25519.verify(
  publicKey: keyPair.publicKey,
  message: message,
  signature: signature,
);

// X25519 Diffie-Hellman (RFC 7748)
final alice = BoringX25519.generateKeyPair();
final bob = BoringX25519.generateKeyPair();
final sharedSecret = BoringX25519.computeSharedSecret(
  privateKey: alice.privateKey,
  peerPublicKey: bob.publicKey,
);
```

### 7. Asymmetric Keys (`BoringPrivateKey` & `BoringPublicKey`)

```dart
import 'package:boring/crypto.dart';

// Generate RSA, EC, Ed25519, or X25519 keys
final rsaKey = BoringPrivateKey.generateRsa(bits: 2048);
final ecKey = BoringPrivateKey.generateEc(EcCurve.p256);
final edKey = BoringPrivateKey.generateEd25519();
final x25519Key = BoringPrivateKey.generateX25519();

// Sign & Verify: PKCS#1 v1.5 or RSA-PSS
final sigPkcs1 = rsaKey.sign(algorithm: HashAlgorithm.sha256, data: data);
final sigPss = rsaKey.sign(
  algorithm: HashAlgorithm.sha256,
  data: data,
  rsaPadding: RsaSignaturePadding.pss,
);
final validPss = rsaKey.publicKey.verify(
  algorithm: HashAlgorithm.sha256,
  data: data,
  signature: sigPss,
  rsaPadding: RsaSignaturePadding.pss,
);

// RSA-OAEP Encryption & Decryption (RFC 8017)
final ciphertext = rsaKey.publicKey.encryptOaep(plaintext: secretBytes);
final decrypted = rsaKey.decryptOaep(ciphertext: ciphertext);

// ECDH / X25519 Key Agreement
final peerEcKey = BoringPrivateKey.generateEc(EcCurve.p256);
final sharedSecret = ecKey.deriveSharedSecret(peerEcKey.publicKey);

// Streaming Sign & Verify
final streamSig = await rsaKey.signStream(
  algorithm: HashAlgorithm.sha256,
  data: dataStream,
);
final streamValid = await rsaKey.publicKey.verifyStream(
  algorithm: HashAlgorithm.sha256,
  data: dataStream,
  signature: streamSig,
);

// Export / Import (PEM / DER / Encrypted PKCS#8 / Raw 32-byte keys)
final pubPem = rsaKey.publicKey.toPem();
final privPem = rsaKey.toPem(password: 'optional-passphrase');
final importedKey = BoringPrivateKey.fromPem(
  privPem,
  password: 'optional-passphrase',
);
```

### 8. X.509 Certificate Parsing and Chain Verification

```dart
import 'package:boring/x509.dart';

// Parse certificate
final rootCert = X509Certificate.fromPem(rootPemString);
final leafCert = X509Certificate.fromPem(leafPemString);

print('Subject: ${leafCert.subject}');
print('Issuer:  ${leafCert.issuer}');
print('Valid:   ${leafCert.notBefore} to ${leafCert.notAfter}');

// Setup verifier with trusted roots
final verifier = X509Verifier();
verifier.addTrustedCertificate(rootCert);

// Verify chain
final result = verifier.verify(
  leaf: leafCert,
  intermediates: [intermediateCert], // optional
  checkTime: DateTime.now(),         // optional
);

if (result.isValid) {
  print('Certificate chain verified successfully.');
} else {
  print('Verification failed: ${result.errorMessage} '
      'at depth ${result.errorDepth}');
}

// Full TLS-style verification: check the peer's identity, its key usage and
// extended key usage, and cap the chain length. All of these are performed by
// BoringSSL as part of chain building.
final tlsResult = verifier.verify(
  leaf: leafCert,
  intermediates: [intermediateCert],
  peerNames: [const X509PeerName.dnsName('example.com')],
  purpose: X509Purpose.tlsServer,
  maxIntermediates: 4,
);
```

`peerNames` also accepts `X509PeerName.ipAddress` and
`X509PeerName.emailAddress`. Several DNS names are matched with OR semantics,
so the leaf need only assert one of them. Name matching defaults to
`X509HostnameFlag.neverCheckSubject`, which suppresses BoringSSL's legacy
fallback to the subject common name; pass `hostnameFlags` to change that or to
disable wildcards.

Chains containing a certificate signed with MD4, MD5 or SHA-1 are rejected.
`X509_verify_cert` itself applies no signature algorithm policy — BoringSSL has
neither OpenSSL's `X509_VERIFY_PARAM_set_auth_level` nor its `set1_sigalgs` — so
`X509Verifier` walks the verified chain and enforces this itself. The trust
anchor is exempt, since its self-signature is never verified. Pass
`insecurelyAllowWeakSignatureDigests: true` if you must validate legacy chains.

Public keys are checked too: RSA below `minimumRsaKeyBits` (2048 by default),
EC on anything other than P-256/P-384/P-521, DSA, and keys BoringSSL cannot
decode at all (P-192, explicitly parameterised curves) are all rejected. Unlike
the digest check this *includes* the trust anchor, whose key signs the
certificate below it. Ed25519, ML-DSA and any future algorithm are left alone
rather than being rejected as unrecognised. Pass `insecurelyAllowWeakKeys: true`
to disable the check, or set `minimumRsaKeyBits` to tune only the RSA floor.

### 9. X.509 Extensions, Subject Alternative Names, and Custom OIDs

```dart
import 'package:boring/x509.dart';

final cert = X509Certificate.fromPem(pemString);

// Subject Alternative Names, decoded into typed GeneralName entries.
for (final name in cert.subjectAlternativeNames) {
  print('${name.type.name}: ${name.value}');
}

// Convenience accessors.
print(cert.emailAddresses); // [alice@example.com]
print(cert.dnsNames);       // [example.com, www.example.com]
print(cert.uris);           // [https://github.com/org/repo/...]

// Key usage (null if extension is absent) and CA status.
final canSign = (cert.keyUsage ?? 0) & KeyUsage.digitalSignature != 0;
print(cert.extendedKeyUsage);      // [1.3.6.1.5.5.7.3.3] (codeSigning)
print(cert.isCertificateAuthority); // false
print(cert.sha256Fingerprint);      // 32-byte SHA-256 DER fingerprint
print(cert.authorityKeyIdentifier); // Raw keyIdentifier bytes or null

// Enumerate every extension.
for (final ext in cert.extensions) {
  print('${ext.oid} (${ext.shortName}) critical=${ext.isCritical}');
}

// Look up a custom OID. Sigstore Fulcio embeds the OIDC issuer here.
print(cert.getExtensionString(X509Oid.fulcioIssuerV1));
// https://token.actions.githubusercontent.com
```

### 10. ASN.1 DER Decoding

Certificates and signatures are decoded natively by BoringSSL, but the payload
of an X.509 extension is application-specific. `package:boring/asn1.dart`
exposes BoringSSL's own DER parser for those payloads.

This is a binding, not a reimplementation: tag and length parsing is
`CBS_get_any_asn1_element`, object identifiers are rendered by
`CBS_asn1_oid_to_text`, integers go through `CBS_is_valid_asn1_integer` and
`BN_bn2dec`, and strings are transcoded by `ASN1_STRING_to_UTF8`. DER encoding
rules — minimal lengths, minimal integers, no indefinite lengths — are therefore
enforced by BoringSSL rather than by Dart code.

```dart
import 'package:boring/asn1.dart';
import 'package:boring/x509.dart';

final ext = cert.getExtension('1.3.6.1.4.1.57264.1.11')!;

final value = Asn1Reader.parse(ext.value);
if (value.hasUniversalTag(Asn1Tag.utf8String)) {
  print(value.asString()); // github-hosted
}

// Nested structures, integers, and OIDs are supported too.
final seq = Asn1Reader.parse(derBytes);
for (final child in seq.children) {
  if (child.hasUniversalTag(Asn1Tag.objectIdentifier)) {
    print(child.asObjectIdentifier());
  }
}
```

---

## Native Asset Build Modes

Configured in `pubspec.yaml` under `hooks.user_defines.boring`:

```yaml
hooks:
  user_defines:
    boring:
      buildMode: fetch # 'fetch', 'checkout', or 'local'
```

- **`fetch`** *(default)*: Downloads prebuilt binaries from GitHub Releases verified against pinned SHA-256 checksums, falling back to local compilation if unavailable.
- **`checkout`**: Always compiles BoringSSL locally from bundled sources via CMake and Ninja.
- **`local`**: Uses a custom prebuilt dynamic library at `localPath`.

For details on how first-party Dart SDK tools (such as `dart pub`) and `package:boring` can reuse the `//third_party/boringssl` library already bundled with the Dart SDK, see [`doc/reusing_dart_sdk_boringssl.md`](doc/reusing_dart_sdk_boringssl.md).

---

## Conformance Testing

`package:boring` is validated against two external conformance suites.

### Project Wycheproof

[**Project Wycheproof**](https://github.com/google/wycheproof) is Google's suite of known attacks, edge cases, and RFC conformance test vectors for cryptographic primitives.

```bash
./tool/run_conformance_tests.sh
```

This tests:
- **AEAD & Ciphers**: AES-GCM (128 and 256-bit), ChaCha20-Poly1305, XChaCha20-Poly1305, AES-CBC (PKCS#5/7), and AES Key Wrap (KW).
- **Signatures**: Ed25519, ECDSA (P-256, P-384, P-521), RSA PKCS#1 v1.5 (2048, 3072, 4096-bit), and RSA-PSS (2048, 3072, 4096-bit).
- **Asymmetric Encryption**: RSA-OAEP (2048, 3072, 4096-bit).
- **Key Agreement**: ECDH (P-256, P-384, P-521).
- **Key Derivation & MAC**: HKDF (SHA-256, SHA-384, SHA-512), PBKDF2 (SHA-1 through SHA-512), and HMAC (SHA-256, SHA-384, SHA-512).

### x509-limbo

[**x509-limbo**](https://x509-limbo.com) is C2SP's corpus of X.509 path building and validation testcases, covering RFC 5280, the CA/Browser Forum baseline requirements, the BetterTLS name constraints and path building suites, and several CVEs.

```bash
./tool/run_x509_limbo_tests.sh
```

9,770 of the suite's 9,793 testcases run against `X509Verifier`, and **9,237 (94.5%) agree**. The remainder are enumerated in [`test/conformance/x509_limbo_expected_failures.txt`](test/conformance/x509_limbo_expected_failures.txt); the suite fails if a testcase diverges that is not on that list, and also if a listed testcase starts agreeing, so the list cannot go stale.

The divergences are not bugs in this package: they are places where BoringSSL's scope differs from the suite's expectations. Grouped by root cause:

| Count | Cause |
|------:|-------|
| 452 | **Unsupported name constraint types.** BoringSSL checks name constraints for `directoryName`, `dNSName`, `rfc822Name` and `uniformResourceIdentifier` only, and rejects any other type outright. The BetterTLS name constraints suite is built almost entirely on `iPAddress` constraints. |
| 46 | **Chain accepted where the suite expects rejection.** CA/Browser Forum policy that BoringSSL, an RFC 5280 validator, does not enforce — CN must be a character-for-character copy of a SAN entry, `anyExtendedKeyUsage` is forbidden, `extKeyUsage` must not be critical. Two are a deliberate omission: CABF requires the RSA modulus size to be divisible by 8, but the RSA-2052 keys these use are *stronger* than the RSA-2048 the same profile permits, so the key strength check does not enforce it. |
| 29 | **No backtracking during chain building.** When a subject has several candidate issuer certificates, BoringSSL commits to the first and reports whatever goes wrong down that branch. `bettertls::pathbuilding::tc52` is the clearest case: intermediate `B` appears twice, once `CA:TRUE` and once `CA:FALSE`, and BoringSSL picks the `CA:FALSE` one. Two others pick an `ecdsa-with-SHA1` cross-signature over the `ecdsa-with-SHA256` one next to it. Also causes `cve::cve-2024-0567`. |
| 4 | **Purpose checked against a leaf that is not a TLS end entity.** Two put a CA certificate in the leaf position, which RFC 5280 permits but which asserts `keyCertSign` rather than a TLS key usage; the other two are the backtracking issue above, surfacing as a purpose failure. |
| 2 | **`notAfter` treated as exclusive.** `X509_cmp_time_posix` reports expiry when `certificate time - comparison time <= 0`, so validating at exactly `notAfter` fails; RFC 5280 4.1.2.5 defines it as inclusive. |

> [!NOTE]
> Every divergence above is a false *rejection* or a missing CABF profile check. None of them cause a chain to be accepted on an unverified signature.

23 testcases are skipped outright: 14 need network access, 8 need CRL revocation checking, and 1 asserts two expected email addresses, which an `X509_VERIFY_PARAM` cannot express.

---

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details. BoringSSL is licensed under Apache 2.0 and BSD-style licenses.
