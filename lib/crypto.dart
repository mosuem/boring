// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

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
export 'src/ffi/error.dart' show BoringSslException;
