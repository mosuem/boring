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

/// HMAC-based Extract-and-Expand Key Derivation Function (HKDF, RFC 5869).
abstract final class BoringHkdf {
  /// Computes HKDF extract-and-expand to derive [length] bytes of key material.
  ///
  /// - [algorithm]: Hash algorithm to use (e.g. [HashAlgorithm.sha256]).
  /// - [ikm]: Input Keying Material.
  /// - [salt]: Optional salt value (a non-secret random value). If not
  ///   provided, a string of zeros of the hash function's digest length is
  ///   used as per RFC 5869.
  /// - [info]: Optional context and application specific information.
  static Uint8List deriveBits({
    required HashAlgorithm algorithm,
    required Uint8List ikm,
    required int length,
    Uint8List? salt,
    Uint8List? info,
  }) {
    if (length < 0) {
      throw ArgumentError.value(
        length,
        'length',
        'Length must be non-negative',
      );
    }
    if (length == 0) {
      return Uint8List(0);
    }

    return using((arena) {
      final outBuffer = arena<ffi.Uint8>(length);
      final ikmPtr = copyBytesToNative(ikm, arena);
      final saltPtr = salt != null && salt.isNotEmpty
          ? copyBytesToNative(salt, arena)
          : ffi.nullptr;
      final infoPtr = info != null && info.isNotEmpty
          ? copyBytesToNative(info, arena)
          : ffi.nullptr;

      final ret = bssl.HKDF(
        outBuffer,
        length,
        algorithm.evpMd,
        ikmPtr,
        ikm.length,
        saltPtr,
        salt?.length ?? 0,
        infoPtr,
        info?.length ?? 0,
      );
      checkBssl(ret, 'HKDF');
      return Uint8List.fromList(outBuffer.asTypedList(length));
    });
  }

  /// Extracts a pseudorandom key (PRK) from [ikm] and [salt].
  static Uint8List extract({
    required HashAlgorithm algorithm,
    required Uint8List ikm,
    Uint8List? salt,
  }) {
    return using((arena) {
      final outBuffer = arena<ffi.Uint8>(algorithm.digestLength);
      final outLenPtr = arena<ffi.Size>();
      final ikmPtr = copyBytesToNative(ikm, arena);
      final saltPtr = salt != null && salt.isNotEmpty
          ? copyBytesToNative(salt, arena)
          : ffi.nullptr;

      final ret = bssl.HKDF_extract(
        outBuffer,
        outLenPtr,
        algorithm.evpMd,
        ikmPtr,
        ikm.length,
        saltPtr,
        salt?.length ?? 0,
      );
      checkBssl(ret, 'HKDF_extract');
      return Uint8List.fromList(outBuffer.asTypedList(outLenPtr.value));
    });
  }

  /// Expands a pseudorandom key [prk] into [length] bytes of key material.
  static Uint8List expand({
    required HashAlgorithm algorithm,
    required Uint8List prk,
    required int length,
    Uint8List? info,
  }) {
    if (length < 0) {
      throw ArgumentError.value(
        length,
        'length',
        'Length must be non-negative',
      );
    }
    if (length == 0) {
      return Uint8List(0);
    }

    return using((arena) {
      final outBuffer = arena<ffi.Uint8>(length);
      final prkPtr = copyBytesToNative(prk, arena);
      final infoPtr = info != null && info.isNotEmpty
          ? copyBytesToNative(info, arena)
          : ffi.nullptr;

      final ret = bssl.HKDF_expand(
        outBuffer,
        length,
        algorithm.evpMd,
        prkPtr,
        prk.length,
        infoPtr,
        info?.length ?? 0,
      );
      checkBssl(ret, 'HKDF_expand');
      return Uint8List.fromList(outBuffer.asTypedList(length));
    });
  }
}
