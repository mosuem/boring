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
