// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';

/// Supported message digest algorithms.
enum HashAlgorithm {
  sha1,
  sha224,
  sha256,
  sha384,
  sha512,
  blake2b256;

  ffi.Pointer<bssl.EVP_MD> get evpMd => switch (this) {
    HashAlgorithm.sha1 => bssl.EVP_sha1(),
    HashAlgorithm.sha224 => bssl.EVP_sha224(),
    HashAlgorithm.sha256 => bssl.EVP_sha256(),
    HashAlgorithm.sha384 => bssl.EVP_sha384(),
    HashAlgorithm.sha512 => bssl.EVP_sha512(),
    HashAlgorithm.blake2b256 => bssl.EVP_blake2b256(),
  };

  /// Output digest length in bytes.
  int get digestLength => bssl.EVP_MD_size(evpMd);
}

/// Streaming context for computing message digests incrementally.
final class DigestContext implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_MD_CTX>)>
        >(bssl.EVP_MD_CTX_free)
        .cast(),
  );

  final ffi.Pointer<bssl.EVP_MD_CTX> _ctx;
  final HashAlgorithm algorithm;
  bool _isFinalized = false;

  DigestContext(this.algorithm) : _ctx = bssl.EVP_MD_CTX_new() {
    checkPointer(_ctx, 'EVP_MD_CTX_new');
    _finalizer.attach(this, _ctx.cast(), externalSize: 128);
    final ret = bssl.EVP_DigestInit_ex(
      _ctx,
      algorithm.evpMd,
      ffi.nullptr,
    );
    checkBssl(ret, 'EVP_DigestInit_ex');
  }

  /// Feeds [chunk] of bytes into the digest.
  void update(Uint8List chunk) {
    if (_isFinalized) {
      throw StateError('Cannot update a finalized DigestContext.');
    }
    if (chunk.isEmpty) return;
    using((arena) {
      final ptr = arena<ffi.Uint8>(chunk.length);
      ptr.asTypedList(chunk.length).setAll(0, chunk);
      final ret = bssl.EVP_DigestUpdate(
        _ctx,
        ptr.cast<ffi.Void>(),
        chunk.length,
      );
      checkBssl(ret, 'EVP_DigestUpdate');
    });
  }

  /// Finalizes the digest and returns the computed hash.
  Uint8List finalize() {
    if (_isFinalized) {
      throw StateError('DigestContext already finalized.');
    }
    _isFinalized = true;
    return withSizedOutput(algorithm.digestLength, (out, arena) {
      final outLen = arena<ffi.UnsignedInt>();
      checkBssl(
        bssl.EVP_DigestFinal_ex(_ctx, out, outLen),
        'EVP_DigestFinal_ex',
      );
      return outLen.value;
    });
  }
}

/// Message digest (hashing) functions.
abstract final class BoringDigest {
  /// Computes the hash of [data] using [algorithm].
  static Uint8List hash(HashAlgorithm algorithm, Uint8List data) {
    final ctx = DigestContext(algorithm);
    ctx.update(data);
    return ctx.finalize();
  }

  /// Computes the SHA-256 hash of [data].
  static Uint8List sha256(Uint8List data) => hash(HashAlgorithm.sha256, data);

  /// Computes the SHA-384 hash of [data].
  static Uint8List sha384(Uint8List data) => hash(HashAlgorithm.sha384, data);

  /// Computes the SHA-512 hash of [data].
  static Uint8List sha512(Uint8List data) => hash(HashAlgorithm.sha512, data);

  /// Computes the SHA-1 hash of [data].
  static Uint8List sha1(Uint8List data) => hash(HashAlgorithm.sha1, data);

  /// Computes the SHA-224 hash of [data].
  static Uint8List sha224(Uint8List data) => hash(HashAlgorithm.sha224, data);

  /// Computes the BLAKE2b-256 hash of [data].
  static Uint8List blake2b256(Uint8List data) =>
      hash(HashAlgorithm.blake2b256, data);
}
