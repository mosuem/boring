// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';

/// Raw Ed25519 public key length in bytes (32 bytes).
const ed25519PublicKeyLength = 32;

/// Raw Ed25519 private key length in bytes (64 bytes: 32 seed + 32 public).
const ed25519PrivateKeyLength = 64;

/// Raw Ed25519 seed length in bytes (32 bytes).
const ed25519SeedLength = 32;

/// Raw Ed25519 signature length in bytes (64 bytes).
const ed25519SignatureLength = 64;

/// Ed25519 high-speed digital signatures (RFC 8032).
abstract final class BoringEd25519 {
  /// Generates a new random Ed25519 key pair.
  static ({Uint8List publicKey, Uint8List privateKey}) generateKeyPair() {
    return using((arena) {
      final pubKeyPtr = arena<ffi.Uint8>(ed25519PublicKeyLength);
      final privKeyPtr = arena<ffi.Uint8>(ed25519PrivateKeyLength);
      bssl.ED25519_keypair(pubKeyPtr, privKeyPtr);
      return (
        publicKey: Uint8List.fromList(
          pubKeyPtr.asTypedList(ed25519PublicKeyLength),
        ),
        privateKey: Uint8List.fromList(
          privKeyPtr.asTypedList(ed25519PrivateKeyLength),
        ),
      );
    });
  }

  /// Derives an Ed25519 key pair from a 32-byte [seed].
  static ({Uint8List publicKey, Uint8List privateKey}) keyPairFromSeed(
    Uint8List seed,
  ) {
    if (seed.length != ed25519SeedLength) {
      throw ArgumentError.value(
        seed.length,
        'seed',
        'Seed must be $ed25519SeedLength bytes',
      );
    }
    return using((arena) {
      final seedPtr = copyBytesToNative(seed, arena);
      final pubKeyPtr = arena<ffi.Uint8>(ed25519PublicKeyLength);
      final privKeyPtr = arena<ffi.Uint8>(ed25519PrivateKeyLength);
      bssl.ED25519_keypair_from_seed(pubKeyPtr, privKeyPtr, seedPtr);
      return (
        publicKey: Uint8List.fromList(
          pubKeyPtr.asTypedList(ed25519PublicKeyLength),
        ),
        privateKey: Uint8List.fromList(
          privKeyPtr.asTypedList(ed25519PrivateKeyLength),
        ),
      );
    });
  }

  /// Signs [message] using [privateKey] (64 bytes).
  static Uint8List sign({
    required Uint8List privateKey,
    required Uint8List message,
  }) {
    if (privateKey.length != ed25519PrivateKeyLength) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'Private key must be $ed25519PrivateKeyLength bytes',
      );
    }
    return withSizedOutput(ed25519SignatureLength, (out, arena) {
      checkBssl(
        bssl.ED25519_sign(
          out,
          copyBytesOrNull(message, arena),
          message.length,
          copyBytesToNative(privateKey, arena),
        ),
        'ED25519_sign',
      );
      return ed25519SignatureLength;
    });
  }

  /// Verifies that [signature] is valid for [message] using [publicKey].
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    if (publicKey.length != ed25519PublicKeyLength ||
        signature.length != ed25519SignatureLength) {
      return false;
    }
    return using((arena) {
      final ret = bssl.ED25519_verify(
        copyBytesOrNull(message, arena),
        message.length,
        copyBytesToNative(signature, arena),
        copyBytesToNative(publicKey, arena),
      );
      return ret == 1;
    });
  }
}
