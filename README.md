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
- **Modern Cryptography**: Fast, constant-time implementations of AEAD (AES-GCM, ChaCha20-Poly1305), Ed25519, ECDSA (P-256, P-384, P-521), RSA (PSS / PKCS#1), HKDF, and HMAC.

---

## Getting Started

Add `boring` to your `pubspec.yaml`:

```yaml
dependencies:
  boring: ^0.1.0
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

// Streaming digest
final ctx = DigestContext(HashAlgorithm.sha256);
ctx.update(Uint8List.fromList(utf8.encode('chunk 1')));
ctx.update(Uint8List.fromList(utf8.encode('chunk 2')));
final hash = ctx.finalize();
```

### 3. HMAC

```dart
import 'package:boring/crypto.dart';

final key = BoringRand.secureRandom(32);
final mac = BoringHmac.sha256(key: key, data: data);
```

### 4. HKDF (RFC 5869)

```dart
import 'package:boring/crypto.dart';

final derivedKey = BoringHkdf.deriveBits(
  algorithm: HashAlgorithm.sha256,
  ikm: keyMaterial,
  length: 32,
  salt: optionalSalt,
  info: optionalContextInfo,
);
```

### 5. Authenticated Encryption with Associated Data (AEAD)

Supported algorithms: `AeadAlgorithm.aes128Gcm`, `AeadAlgorithm.aes256Gcm`, `AeadAlgorithm.chacha20Poly1305`, and `AeadAlgorithm.xchacha20Poly1305`.

```dart
import 'package:boring/crypto.dart';

final key = BoringRand.secureRandom(32);
final nonce = BoringRand.secureRandom(12); // 12 bytes for AES-GCM
final cipher = BoringAead(AeadAlgorithm.aes256Gcm, key);

// Encrypt and authenticate
final ciphertext = cipher.seal(
  nonce: nonce,
  plaintext: plaintext,
  additionalData: associatedData,
);

// Decrypt and verify
final decrypted = cipher.open(
  nonce: nonce,
  ciphertext: ciphertext,
  additionalData: associatedData,
);
```

### 6. Ed25519 Signatures (RFC 8032)

```dart
import 'package:boring/crypto.dart';

// Generate key pair
final keyPair = BoringEd25519.generateKeyPair();

// Sign
final signature = BoringEd25519.sign(
  privateKey: keyPair.privateKey,
  message: message,
);

// Verify
final isValid = BoringEd25519.verify(
  publicKey: keyPair.publicKey,
  message: message,
  signature: signature,
);
```

### 7. Asymmetric Keys (RSA & ECDSA)

```dart
import 'package:boring/crypto.dart';

// Generate RSA or EC keys
final rsaKey = BoringPrivateKey.generateRsa(bits: 2048);
final ecKey = BoringPrivateKey.generateEc(EcCurve.p256);

// Sign & Verify
final sig = rsaKey.sign(algorithm: HashAlgorithm.sha256, data: data);
final valid = rsaKey.publicKey.verify(
  algorithm: HashAlgorithm.sha256,
  data: data,
  signature: sig,
);

// Export to PEM / DER
final pubPem = rsaKey.publicKey.toPem();
final privPem = rsaKey.toPem();

// Import from PEM
final importedKey = BoringPublicKey.fromPem(pubPem);
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
  checkTime: DateTime.now(),        // optional
);

if (result.isValid) {
  print('Certificate chain verified successfully.');
} else {
  print('Verification failed: ${result.errorMessage}');
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

---

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details. BoringSSL is licensed under Apache 2.0 and BSD-style licenses.
