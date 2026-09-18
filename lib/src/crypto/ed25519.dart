// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

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
  /// Generates a new random Ed25519 key pair (including the 32-byte `seed`).
  static ({Uint8List publicKey, Uint8List privateKey, Uint8List seed})
  generateKeyPair() {
    return using((arena) {
      final pubKeyPtr = arena<ffi.Uint8>(ed25519PublicKeyLength);
      final privKeyPtr = allocateSecretBytes(ed25519PrivateKeyLength, arena);
      bssl.ED25519_keypair(pubKeyPtr, privKeyPtr);
      final privateKey = Uint8List.fromList(
        privKeyPtr.asTypedList(ed25519PrivateKeyLength),
      );
      return (
        publicKey: Uint8List.fromList(
          pubKeyPtr.asTypedList(ed25519PublicKeyLength),
        ),
        privateKey: privateKey,
        seed: Uint8List.sublistView(privateKey, 0, ed25519SeedLength),
      );
    });
  }

  /// Derives an Ed25519 key pair from a 32-byte [seed].
  static ({Uint8List publicKey, Uint8List privateKey, Uint8List seed})
  keyPairFromSeed(Uint8List seed) {
    if (seed.length != ed25519SeedLength) {
      throw ArgumentError.value(
        seed.length,
        'seed',
        'Seed must be $ed25519SeedLength bytes',
      );
    }
    return using((arena) {
      final seedPtr = copySecretBytesToNative(seed, arena);
      final pubKeyPtr = arena<ffi.Uint8>(ed25519PublicKeyLength);
      final privKeyPtr = allocateSecretBytes(ed25519PrivateKeyLength, arena);
      bssl.ED25519_keypair_from_seed(pubKeyPtr, privKeyPtr, seedPtr);
      final privateKey = Uint8List.fromList(
        privKeyPtr.asTypedList(ed25519PrivateKeyLength),
      );
      return (
        publicKey: Uint8List.fromList(
          pubKeyPtr.asTypedList(ed25519PublicKeyLength),
        ),
        privateKey: privateKey,
        seed: Uint8List.sublistView(privateKey, 0, ed25519SeedLength),
      );
    });
  }

  /// Signs [message] (or [data]) using [privateKey] (64-byte private key or
  /// 32-byte seed).
  static Uint8List sign({
    required Uint8List privateKey,
    Uint8List? message,
    Uint8List? data,
  }) {
    final payload = message ?? data;
    if (payload == null) {
      throw ArgumentError('Either message or data must be provided.');
    }
    if (privateKey.length != ed25519PrivateKeyLength &&
        privateKey.length != ed25519SeedLength) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'Private key must be $ed25519PrivateKeyLength bytes '
            '(or a $ed25519SeedLength-byte seed)',
      );
    }
    return withSizedOutput(ed25519SignatureLength, (out, arena) {
      final ffi.Pointer<ffi.Uint8> privKeyPtr;
      if (privateKey.length == ed25519SeedLength) {
        final seedPtr = copySecretBytesToNative(privateKey, arena);
        final pubKeyPtr = arena<ffi.Uint8>(ed25519PublicKeyLength);
        privKeyPtr = allocateSecretBytes(ed25519PrivateKeyLength, arena);
        bssl.ED25519_keypair_from_seed(pubKeyPtr, privKeyPtr, seedPtr);
      } else {
        privKeyPtr = copySecretBytesToNative(privateKey, arena);
      }
      checkBssl(
        bssl.ED25519_sign(
          out,
          copyBytesOrNull(payload, arena),
          payload.length,
          privKeyPtr,
        ),
        'ED25519_sign',
      );
      return ed25519SignatureLength;
    });
  }

  /// Verifies that [signature] is valid for [message] (or [data]) using
  /// [publicKey].
  static bool verify({
    required Uint8List publicKey,
    Uint8List? message,
    Uint8List? data,
    required Uint8List signature,
  }) {
    final payload = message ?? data;
    if (payload == null) {
      throw ArgumentError('Either message or data must be provided.');
    }
    if (publicKey.length != ed25519PublicKeyLength ||
        signature.length != ed25519SignatureLength) {
      return false;
    }
    return using((arena) {
      final ret = bssl.ED25519_verify(
        copyBytesOrNull(payload, arena),
        payload.length,
        copyBytesToNative(signature, arena),
        copyBytesToNative(publicKey, arena),
      );
      if (ret != 1) {
        drainErrorQueue();
        return false;
      }
      return true;
    });
  }
}
