// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'aead.dart';

/// Supported symmetric block and stream cipher algorithms.
enum CipherAlgorithm {
  aes128Cbc,
  aes192Cbc,
  aes256Cbc,
  aes128Ctr,
  aes192Ctr,
  aes256Ctr;

  ffi.Pointer<bssl.EVP_CIPHER> get evpCipher => switch (this) {
    CipherAlgorithm.aes128Cbc => bssl.EVP_aes_128_cbc(),
    CipherAlgorithm.aes192Cbc => bssl.EVP_aes_192_cbc(),
    CipherAlgorithm.aes256Cbc => bssl.EVP_aes_256_cbc(),
    CipherAlgorithm.aes128Ctr => bssl.EVP_aes_128_ctr(),
    CipherAlgorithm.aes192Ctr => bssl.EVP_aes_192_ctr(),
    CipherAlgorithm.aes256Ctr => bssl.EVP_aes_256_ctr(),
  };

  /// Required key length in bytes.
  int get keyLength => bssl.EVP_CIPHER_key_length(evpCipher);

  /// Required initialization vector (IV) or counter block length in bytes.
  int get ivLength => bssl.EVP_CIPHER_iv_length(evpCipher);

  /// Block size in bytes (16 for AES).
  int get blockSize => bssl.EVP_CIPHER_block_size(evpCipher);

  /// Whether this mode uses block padding (PKCS#7 for CBC).
  bool get isPadded => switch (this) {
    CipherAlgorithm.aes128Cbc ||
    CipherAlgorithm.aes192Cbc ||
    CipherAlgorithm.aes256Cbc => true,
    CipherAlgorithm.aes128Ctr ||
    CipherAlgorithm.aes192Ctr ||
    CipherAlgorithm.aes256Ctr => false,
  };
}

/// Symmetric cipher for unauthenticated encryption and decryption.
///
/// Supports AES in CBC (Cipher Block Chaining) and CTR (Counter) modes.
///
/// For authenticated encryption, prefer [BoringAead] (AES-GCM,
/// ChaCha20-Poly1305).
final class BoringCipher {
  final CipherAlgorithm algorithm;
  final Uint8List _key;

  /// Initializes a cipher for [algorithm] with the given [key].
  BoringCipher(this.algorithm, Uint8List key) : _key = Uint8List.fromList(key) {
    if (key.length != algorithm.keyLength) {
      throw ArgumentError.value(
        key.length,
        'key',
        'Key length must be ${algorithm.keyLength} bytes for ${algorithm.name}',
      );
    }
  }

  /// Encrypts [plaintext] using the specified [iv].
  ///
  /// For CBC mode, PKCS#7 padding is applied.
  /// For CTR mode, the full 128-bit counter block is incremented as a
  /// big-endian integer (standard BoringSSL behavior).
  Uint8List encrypt({
    required Uint8List iv,
    required Uint8List plaintext,
  }) {
    if (iv.length != algorithm.ivLength) {
      throw ArgumentError.value(
        iv.length,
        'iv',
        'IV length must be ${algorithm.ivLength} bytes for ${algorithm.name}',
      );
    }
    return using((arena) {
      final ctx = bssl.EVP_CIPHER_CTX_new();
      checkPointer(ctx, 'EVP_CIPHER_CTX_new');
      try {
        final keyPtr = copyBytesToNative(_key, arena);
        final ivPtr = copyBytesToNative(iv, arena);
        final inPtr = copyBytesToNative(plaintext, arena);

        checkBssl(
          bssl.EVP_EncryptInit_ex(
            ctx,
            algorithm.evpCipher,
            ffi.nullptr,
            keyPtr,
            ivPtr,
          ),
          'EVP_EncryptInit_ex',
        );

        final maxOut = plaintext.length + algorithm.blockSize;
        final out = arena<ffi.Uint8>(maxOut);
        final outLen = arena<ffi.Int>();

        checkBssl(
          bssl.EVP_EncryptUpdate(
            ctx,
            out,
            outLen,
            inPtr,
            plaintext.length,
          ),
          'EVP_EncryptUpdate',
        );
        var total = outLen.value;

        final finalLen = arena<ffi.Int>();
        checkBssl(
          bssl.EVP_EncryptFinal_ex(
            ctx,
            out + total,
            finalLen,
          ),
          'EVP_EncryptFinal_ex',
        );
        total += finalLen.value;

        return Uint8List.fromList(out.asTypedList(total));
      } finally {
        bssl.EVP_CIPHER_CTX_free(ctx);
      }
    });
  }

  /// Decrypts [ciphertext] using the specified [iv].
  ///
  /// For CBC mode, PKCS#7 padding is verified and stripped.
  /// Throws [BoringSslException] if decryption or padding verification fails.
  Uint8List decrypt({
    required Uint8List iv,
    required Uint8List ciphertext,
  }) {
    if (iv.length != algorithm.ivLength) {
      throw ArgumentError.value(
        iv.length,
        'iv',
        'IV length must be ${algorithm.ivLength} bytes for ${algorithm.name}',
      );
    }
    return using((arena) {
      final ctx = bssl.EVP_CIPHER_CTX_new();
      checkPointer(ctx, 'EVP_CIPHER_CTX_new');
      try {
        final keyPtr = copyBytesToNative(_key, arena);
        final ivPtr = copyBytesToNative(iv, arena);
        final inPtr = copyBytesToNative(ciphertext, arena);

        checkBssl(
          bssl.EVP_DecryptInit_ex(
            ctx,
            algorithm.evpCipher,
            ffi.nullptr,
            keyPtr,
            ivPtr,
          ),
          'EVP_DecryptInit_ex',
        );

        final maxOut = ciphertext.length + algorithm.blockSize;
        final out = arena<ffi.Uint8>(maxOut);
        final outLen = arena<ffi.Int>();

        checkBssl(
          bssl.EVP_DecryptUpdate(
            ctx,
            out,
            outLen,
            inPtr,
            ciphertext.length,
          ),
          'EVP_DecryptUpdate',
        );
        var total = outLen.value;

        final finalLen = arena<ffi.Int>();
        checkBssl(
          bssl.EVP_DecryptFinal_ex(
            ctx,
            out + total,
            finalLen,
          ),
          'EVP_DecryptFinal_ex',
        );
        total += finalLen.value;

        return Uint8List.fromList(out.asTypedList(total));
      } finally {
        bssl.EVP_CIPHER_CTX_free(ctx);
      }
    });
  }
}

/// AES Key Wrap (KW, RFC 3394 / NIST SP 800-38F).
abstract final class BoringAesKeyWrap {
  /// Wraps [data] using [key] (128, 192, or 256-bit AES key).
  ///
  /// [data] must be a multiple of 8 bytes and at least 16 bytes.
  static Uint8List wrap({
    required Uint8List key,
    required Uint8List data,
  }) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw ArgumentError.value(
        key.length,
        'key',
        'AES key must be 16, 24, or 32 bytes (got ${key.length})',
      );
    }
    if (data.length < 16 || data.length % 8 != 0) {
      throw ArgumentError.value(
        data.length,
        'data',
        'Data to wrap must be at least 16 bytes and a multiple of 8 bytes',
      );
    }
    return using((arena) {
      final aesKey = arena<bssl.AES_KEY>();
      final keyPtr = copyBytesToNative(key, arena);
      final setRet = bssl.AES_set_encrypt_key(keyPtr, key.length * 8, aesKey);
      checkBssl(setRet == 0 ? 1 : 0, 'AES_set_encrypt_key');

      final outLen = data.length + 8;
      final out = arena<ffi.Uint8>(outLen);
      final inPtr = copyBytesToNative(data, arena);
      final written = bssl.AES_wrap_key(
        aesKey,
        ffi.nullptr,
        out,
        inPtr,
        data.length,
      );
      if (written <= 0) {
        throw BoringSslException('AES_wrap_key failed');
      }
      return Uint8List.fromList(out.asTypedList(written));
    });
  }

  /// Unwraps [data] using [key] (128, 192, or 256-bit AES key).
  ///
  /// [data] must be a multiple of 8 bytes and at least 24 bytes.
  static Uint8List unwrap({
    required Uint8List key,
    required Uint8List data,
  }) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw ArgumentError.value(
        key.length,
        'key',
        'AES key must be 16, 24, or 32 bytes (got ${key.length})',
      );
    }
    if (data.length < 24 || data.length % 8 != 0) {
      throw ArgumentError.value(
        data.length,
        'data',
        'Wrapped data must be at least 24 bytes and a multiple of 8 bytes',
      );
    }
    return using((arena) {
      final aesKey = arena<bssl.AES_KEY>();
      final keyPtr = copyBytesToNative(key, arena);
      final setRet = bssl.AES_set_decrypt_key(keyPtr, key.length * 8, aesKey);
      checkBssl(setRet == 0 ? 1 : 0, 'AES_set_decrypt_key');

      final outLen = data.length - 8;
      final out = arena<ffi.Uint8>(outLen);
      final inPtr = copyBytesToNative(data, arena);
      final written = bssl.AES_unwrap_key(
        aesKey,
        ffi.nullptr,
        out,
        inPtr,
        data.length,
      );
      if (written <= 0) {
        throw BoringSslException('AES_unwrap_key integrity check failed');
      }
      return Uint8List.fromList(out.asTypedList(written));
    });
  }
}
