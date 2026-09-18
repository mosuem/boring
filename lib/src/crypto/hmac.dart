// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'digest.dart';
import 'x25519.dart';

/// Streaming context for computing HMAC incrementally.
final class HmacContext implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.HMAC_CTX>)>
        >(bssl.HMAC_CTX_free)
        .cast(),
  );

  final ffi.Pointer<bssl.HMAC_CTX> _ctx;

  /// The hash algorithm used by this HMAC context.
  final HashAlgorithm algorithm;
  bool _isFinalized = false;
  bool _isDisposed = false;

  /// Creates a new incremental HMAC context for [algorithm] and [key].
  HmacContext(this.algorithm, Uint8List key) : _ctx = bssl.HMAC_CTX_new() {
    checkPointer(_ctx, 'HMAC_CTX_new');
    _finalizer.attach(this, _ctx.cast(), detach: this, externalSize: 128);
    using((arena) {
      final keyPtr = copySecretBytesToNative(key, arena);
      final ret = bssl.HMAC_Init_ex(
        _ctx,
        keyPtr.cast<ffi.Void>(),
        key.length,
        algorithm.evpMd,
        ffi.nullptr,
      );
      checkBssl(ret, 'HMAC_Init_ex');
    });
  }

  /// Releases the underlying native HMAC context immediately.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _isFinalized = true;
    _finalizer.detach(this);
    bssl.HMAC_CTX_free(_ctx);
  }

  /// Updates the HMAC calculation with [chunk].
  void update(Uint8List chunk) {
    if (_isDisposed) {
      throw StateError('HmacContext has been disposed.');
    }
    if (_isFinalized) {
      throw StateError('Cannot update a finalized HmacContext.');
    }
    if (chunk.isEmpty) return;
    using((arena) {
      final dataPtr = copyBytesToNative(chunk, arena);
      final ret = bssl.HMAC_Update(_ctx, dataPtr, chunk.length);
      checkBssl(ret, 'HMAC_Update');
    });
  }

  /// Finalizes the HMAC calculation and returns the authentication tag.
  Uint8List finalize() {
    if (_isDisposed) {
      throw StateError('HmacContext has been disposed.');
    }
    if (_isFinalized) {
      throw StateError('HmacContext already finalized.');
    }
    _isFinalized = true;
    return withSizedOutput(algorithm.digestLength, (out, arena) {
      final outLen = arena<ffi.UnsignedInt>();
      checkBssl(bssl.HMAC_Final(_ctx, out, outLen), 'HMAC_Final');
      return outLen.value;
    });
  }
}

/// Hash-based Message Authentication Code (HMAC) operations.
abstract final class BoringHmac {
  /// Computes HMAC for [data] using [key] and [algorithm].
  static Uint8List compute({
    required HashAlgorithm algorithm,
    required Uint8List key,
    required Uint8List data,
  }) {
    final ctx = HmacContext(algorithm, key);
    try {
      ctx.update(data);
      return ctx.finalize();
    } finally {
      ctx.dispose();
    }
  }

  /// Verifies in constant time (`CRYPTO_memcmp`) that [mac] (or [expectedMac])
  /// is a valid HMAC tag for [data] under [key] and [algorithm].
  static bool verify({
    required HashAlgorithm algorithm,
    required Uint8List key,
    required Uint8List data,
    Uint8List? mac,
    Uint8List? expectedMac,
  }) {
    final tag = mac ?? expectedMac;
    if (tag == null) {
      throw ArgumentError('Either mac or expectedMac must be provided.');
    }
    final expected = compute(algorithm: algorithm, key: key, data: data);
    return BoringCrypto.timingSafeEqual(expected, tag);
  }

  /// Verifies in constant time (`CRYPTO_memcmp`) that [mac] (or [expectedMac])
  /// is a valid HMAC tag for [stream] under [key] and [algorithm].
  static Future<bool> verifyStream({
    required HashAlgorithm algorithm,
    required Uint8List key,
    required Stream<List<int>> stream,
    Uint8List? mac,
    Uint8List? expectedMac,
  }) async {
    final tag = mac ?? expectedMac;
    if (tag == null) {
      throw ArgumentError('Either mac or expectedMac must be provided.');
    }
    final expected = await computeStream(
      algorithm: algorithm,
      key: key,
      stream: stream,
    );
    return BoringCrypto.timingSafeEqual(expected, tag);
  }

  /// Computes HMAC-SHA256 for [data] using [key].
  static Uint8List sha256({
    required Uint8List key,
    required Uint8List data,
  }) => compute(algorithm: HashAlgorithm.sha256, key: key, data: data);

  /// Computes HMAC-SHA384 for [data] using [key].
  static Uint8List sha384({
    required Uint8List key,
    required Uint8List data,
  }) => compute(algorithm: HashAlgorithm.sha384, key: key, data: data);

  /// Computes HMAC-SHA512 for [data] using [key].
  static Uint8List sha512({
    required Uint8List key,
    required Uint8List data,
  }) => compute(algorithm: HashAlgorithm.sha512, key: key, data: data);

  /// Computes HMAC for [stream] using [key] and [algorithm].
  static Future<Uint8List> computeStream({
    required HashAlgorithm algorithm,
    required Uint8List key,
    required Stream<List<int>> stream,
  }) async {
    final ctx = HmacContext(algorithm, key);
    try {
      await for (final chunk in stream) {
        if (chunk.isEmpty) continue;
        ctx.update(chunk is Uint8List ? chunk : Uint8List.fromList(chunk));
      }
      return ctx.finalize();
    } finally {
      ctx.dispose();
    }
  }

  /// Computes HMAC-SHA256 for [stream] using [key].
  static Future<Uint8List> sha256Stream({
    required Uint8List key,
    required Stream<List<int>> stream,
  }) => computeStream(
    algorithm: HashAlgorithm.sha256,
    key: key,
    stream: stream,
  );

  /// Computes HMAC-SHA384 for [stream] using [key].
  static Future<Uint8List> sha384Stream({
    required Uint8List key,
    required Stream<List<int>> stream,
  }) => computeStream(
    algorithm: HashAlgorithm.sha384,
    key: key,
    stream: stream,
  );

  /// Computes HMAC-SHA512 for [stream] using [key].
  static Future<Uint8List> sha512Stream({
    required Uint8List key,
    required Stream<List<int>> stream,
  }) => computeStream(
    algorithm: HashAlgorithm.sha512,
    key: key,
    stream: stream,
  );
}
