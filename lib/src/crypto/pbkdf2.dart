// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:typed_data';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'digest.dart';

/// Password-Based Key Derivation Function 2 (PBKDF2, RFC 2898 / PKCS #5 v2.0).
abstract final class BoringPbkdf2 {
  /// Derives [length] bytes of key material from [password] and [salt] using
  /// [hash] and the specified number of [iterations].
  ///
  /// - [hash]: Hash algorithm for the underlying HMAC (e.g.
  ///   [HashAlgorithm.sha256]).
  /// - [password]: Input password or passphrase.
  /// - [salt]: Cryptographic salt.
  /// - [iterations]: Iteration count (must be positive).
  /// - [length]: Desired output length in bytes (must be non-negative).
  static Uint8List deriveBits({
    required HashAlgorithm hash,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) {
    if (iterations <= 0) {
      throw ArgumentError.value(
        iterations,
        'iterations',
        'Iterations must be positive',
      );
    }
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
      final passPtr = copyBytesToNative(password, arena);
      final saltPtr = copyBytesToNative(salt, arena);
      final ret = bssl.PKCS5_PBKDF2_HMAC(
        passPtr.cast(),
        password.length,
        saltPtr,
        salt.length,
        iterations,
        hash.evpMd,
        length,
        out,
      );
      checkBssl(ret, 'PKCS5_PBKDF2_HMAC');
      return length;
    });
  }

  /// Convenience wrapper around [deriveBits] to derive key material.
  static Uint8List deriveKey({
    required HashAlgorithm hash,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) => deriveBits(
    hash: hash,
    password: password,
    salt: salt,
    iterations: iterations,
    length: length,
  );
}
