// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
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

    return withSizedOutput(length, (out, arena) {
      checkBssl(
        bssl.HKDF(
          out,
          length,
          algorithm.evpMd,
          copyBytesToNative(ikm, arena),
          ikm.length,
          copyBytesOrNull(salt, arena),
          salt?.length ?? 0,
          copyBytesOrNull(info, arena),
          info?.length ?? 0,
        ),
        'HKDF',
      );
      return length;
    });
  }

  /// Extracts a pseudorandom key (PRK) from [ikm] and [salt].
  static Uint8List extract({
    required HashAlgorithm algorithm,
    required Uint8List ikm,
    Uint8List? salt,
  }) => withSizedOutput(algorithm.digestLength, (out, arena) {
    final outLen = arena<ffi.Size>();
    checkBssl(
      bssl.HKDF_extract(
        out,
        outLen,
        algorithm.evpMd,
        copyBytesToNative(ikm, arena),
        ikm.length,
        copyBytesOrNull(salt, arena),
        salt?.length ?? 0,
      ),
      'HKDF_extract',
    );
    return outLen.value;
  });

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

    return withSizedOutput(length, (out, arena) {
      checkBssl(
        bssl.HKDF_expand(
          out,
          length,
          algorithm.evpMd,
          copyBytesToNative(prk, arena),
          prk.length,
          copyBytesOrNull(info, arena),
          info?.length ?? 0,
        ),
        'HKDF_expand',
      );
      return length;
    });
  }
}
