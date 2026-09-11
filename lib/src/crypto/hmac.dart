// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'digest.dart';

/// Streaming context for computing HMAC incrementally.
final class HmacContext implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.HMAC_CTX>)>
        >(bssl.HMAC_CTX_free)
        .cast(),
  );

  final ffi.Pointer<bssl.HMAC_CTX> _ctx;
  final HashAlgorithm algorithm;
  bool _isFinalized = false;

  HmacContext(this.algorithm, Uint8List key) : _ctx = bssl.HMAC_CTX_new() {
    checkPointer(_ctx, 'HMAC_CTX_new');
    _finalizer.attach(this, _ctx.cast(), externalSize: 128);
    using((arena) {
      final keyPtr = copyBytesToNative(key, arena);
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

  /// Updates the HMAC calculation with [chunk].
  void update(Uint8List chunk) {
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
    ctx.update(data);
    return ctx.finalize();
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
}
