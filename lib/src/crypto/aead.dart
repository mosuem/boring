// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';

/// Supported Authenticated Encryption with Associated Data (AEAD) algorithms.
enum AeadAlgorithm {
  aes128Gcm,
  aes256Gcm,
  chacha20Poly1305,
  xchacha20Poly1305;

  ffi.Pointer<bssl.EVP_AEAD> get _evpAead => switch (this) {
    AeadAlgorithm.aes128Gcm => bssl.EVP_aead_aes_128_gcm(),
    AeadAlgorithm.aes256Gcm => bssl.EVP_aead_aes_256_gcm(),
    AeadAlgorithm.chacha20Poly1305 => bssl.EVP_aead_chacha20_poly1305(),
    AeadAlgorithm.xchacha20Poly1305 => bssl.EVP_aead_xchacha20_poly1305(),
  };

  /// Required key length in bytes.
  int get keyLength => bssl.EVP_AEAD_key_length(_evpAead);

  /// Required nonce length in bytes.
  int get nonceLength => bssl.EVP_AEAD_nonce_length(_evpAead);

  /// Maximum overhead added by encryption (tag length) in bytes.
  int get maxOverhead => bssl.EVP_AEAD_max_overhead(_evpAead);
}

/// Authenticated Encryption with Associated Data (AEAD) cipher.
final class BoringAead implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_AEAD_CTX>)>
        >(bssl.EVP_AEAD_CTX_free)
        .cast(),
  );

  final ffi.Pointer<bssl.EVP_AEAD_CTX> _ctx;

  /// The AEAD algorithm used by this cipher instance.
  final AeadAlgorithm algorithm;

  bool _isDisposed = false;

  /// Initializes an AEAD cipher for [algorithm] with the given [key].
  BoringAead(this.algorithm, Uint8List key)
    : _ctx = using((arena) {
        if (key.length != algorithm.keyLength) {
          throw ArgumentError.value(
            key.length,
            'key',
            'Key length must be ${algorithm.keyLength} bytes for '
                '${algorithm.name}',
          );
        }
        final keyPtr = copySecretBytesToNative(key, arena);
        final ctx = bssl.EVP_AEAD_CTX_new(
          algorithm._evpAead,
          keyPtr,
          key.length,
          bssl.EVP_AEAD_DEFAULT_TAG_LENGTH,
        );
        return checkPointer(ctx, 'EVP_AEAD_CTX_new');
      }) {
    _finalizer.attach(this, _ctx.cast(), detach: this, externalSize: 512);
  }

  void _checkNotDisposed() {
    if (_isDisposed) {
      throw StateError('BoringAead has been disposed.');
    }
  }

  /// Releases the underlying native AEAD key schedule immediately.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _finalizer.detach(this);
    bssl.EVP_AEAD_CTX_free(_ctx);
  }

  /// Encrypts and authenticates [plaintext] with [nonce] and optional
  /// [additionalData].
  Uint8List seal({
    required Uint8List nonce,
    required Uint8List plaintext,
    Uint8List? additionalData,
  }) {
    _checkNotDisposed();
    _checkNonce(nonce);
    final maxOutLen = plaintext.length + algorithm.maxOverhead;
    return withSizedOutput(maxOutLen, (out, arena) {
      final outLen = arena<ffi.Size>();
      checkBssl(
        bssl.EVP_AEAD_CTX_seal(
          _ctx,
          out,
          outLen,
          maxOutLen,
          copyBytesToNative(nonce, arena),
          nonce.length,
          copySecretBytesOrNull(plaintext, arena),
          plaintext.length,
          copyBytesOrNull(additionalData, arena),
          additionalData?.length ?? 0,
        ),
        'EVP_AEAD_CTX_seal',
      );
      return outLen.value;
    });
  }

  /// Decrypts and verifies [ciphertext] with [nonce] and optional
  /// [additionalData].
  ///
  /// Throws [BoringSslException] if authentication fails.
  Uint8List open({
    required Uint8List nonce,
    required Uint8List ciphertext,
    Uint8List? additionalData,
  }) {
    _checkNotDisposed();
    _checkNonce(nonce);
    return withSecretSizedOutput(ciphertext.length, (out, arena) {
      final outLen = arena<ffi.Size>();
      checkBssl(
        bssl.EVP_AEAD_CTX_open(
          _ctx,
          out,
          outLen,
          ciphertext.length,
          copyBytesToNative(nonce, arena),
          nonce.length,
          copyBytesOrNull(ciphertext, arena),
          ciphertext.length,
          copyBytesOrNull(additionalData, arena),
          additionalData?.length ?? 0,
        ),
        'EVP_AEAD_CTX_open',
      );
      return outLen.value;
    });
  }

  void _checkNonce(Uint8List nonce) {
    if (nonce.length != algorithm.nonceLength) {
      throw ArgumentError.value(
        nonce.length,
        'nonce',
        'Nonce length must be ${algorithm.nonceLength} bytes for '
            '${algorithm.name}',
      );
    }
  }
}
