// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

/// Cryptographic operations powered by BoringSSL.
library;

export 'src/crypto/aead.dart' show AeadAlgorithm, BoringAead;
export 'src/crypto/cipher.dart'
    show BoringAesKeyWrap, BoringCipher, CipherAlgorithm;
export 'src/crypto/digest.dart' show BoringDigest, DigestContext, HashAlgorithm;
export 'src/crypto/ed25519.dart'
    show
        BoringEd25519,
        ed25519PrivateKeyLength,
        ed25519PublicKeyLength,
        ed25519SeedLength,
        ed25519SignatureLength;
export 'src/crypto/hkdf.dart' show BoringHkdf;
export 'src/crypto/hmac.dart' show BoringHmac, HmacContext;
export 'src/crypto/pbkdf2.dart' show BoringPbkdf2;
export 'src/crypto/pkey.dart'
    show
        BoringPrivateKey,
        BoringPublicKey,
        EcCurve,
        KeyType,
        RsaSignaturePadding;
export 'src/crypto/rand.dart' show BoringRand;
export 'src/crypto/x25519.dart'
    show
        BoringCrypto,
        BoringX25519,
        x25519PrivateKeyLength,
        x25519PublicKeyLength,
        x25519SharedKeyLength;
export 'src/ffi/error.dart' show BoringSslException;
