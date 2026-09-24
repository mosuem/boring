// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:typed_data';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'digest.dart';

/// Password-Based Key Derivation Function 2 (PBKDF2, RFC 2898 / PKCS #5 v2.0).
abstract final class BoringPbkdf2 {
  /// Derives [length] bytes of key material from [password] and [salt] using
  /// [hash] (or [algorithm]) and the specified number of [iterations].
  ///
  /// - [hash] / [algorithm]: Hash algorithm for the underlying HMAC (e.g.
  ///   [HashAlgorithm.sha256]).
  /// - [password]: Input password or passphrase.
  /// - [salt]: Cryptographic salt.
  /// - [iterations]: Iteration count (must be positive).
  /// - [length]: Desired output length in bytes (must be non-negative).
  static Uint8List deriveBits({
    HashAlgorithm? hash,
    HashAlgorithm? algorithm,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) {
    final md = hash ?? algorithm;
    if (md == null) {
      throw ArgumentError('Either hash or algorithm must be specified.');
    }
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

    return withSecretSizedOutput(length, (out, arena) {
      final passPtr = copySecretBytesToNative(password, arena);
      final saltPtr = copyBytesToNative(salt, arena);
      final ret = bssl.PKCS5_PBKDF2_HMAC(
        passPtr.cast(),
        password.length,
        saltPtr,
        salt.length,
        iterations,
        md.evpMd,
        length,
        out,
      );
      checkBssl(ret, 'PKCS5_PBKDF2_HMAC');
      return length;
    });
  }

  /// Convenience wrapper around [deriveBits] to derive key material.
  static Uint8List deriveKey({
    HashAlgorithm? hash,
    HashAlgorithm? algorithm,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) => deriveBits(
    hash: hash,
    algorithm: algorithm,
    password: password,
    salt: salt,
    iterations: iterations,
    length: length,
  );
}
