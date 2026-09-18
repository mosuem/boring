// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';

/// Raw X25519 public key length in bytes (32 bytes).
const x25519PublicKeyLength = 32;

/// Raw X25519 private key length in bytes (32 bytes).
const x25519PrivateKeyLength = 32;

/// Raw X25519 shared secret length in bytes (32 bytes).
const x25519SharedKeyLength = 32;

/// X25519 elliptic-curve Diffie-Hellman key agreement (RFC 7748).
abstract final class BoringX25519 {
  /// Generates a new random X25519 key pair.
  static ({Uint8List publicKey, Uint8List privateKey}) generateKeyPair() {
    return using((arena) {
      final pubKeyPtr = arena<ffi.Uint8>(x25519PublicKeyLength);
      final privKeyPtr = allocateSecretBytes(x25519PrivateKeyLength, arena);
      bssl.X25519_keypair(pubKeyPtr, privKeyPtr);
      return (
        publicKey: Uint8List.fromList(
          pubKeyPtr.asTypedList(x25519PublicKeyLength),
        ),
        privateKey: Uint8List.fromList(
          privKeyPtr.asTypedList(x25519PrivateKeyLength),
        ),
      );
    });
  }

  /// Derives the 32-byte X25519 public key corresponding to [privateKey].
  static Uint8List publicFromPrivate(Uint8List privateKey) {
    if (privateKey.length != x25519PrivateKeyLength) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'Private key must be $x25519PrivateKeyLength bytes',
      );
    }
    return withSizedOutput(x25519PublicKeyLength, (out, arena) {
      bssl.X25519_public_from_private(
        out,
        copySecretBytesToNative(privateKey, arena),
      );
      return x25519PublicKeyLength;
    });
  }

  /// Derives the 32-byte X25519 public key corresponding to [privateKey].
  static Uint8List publicKeyFromPrivate(Uint8List privateKey) =>
      publicFromPrivate(privateKey);

  /// Computes a 32-byte shared secret from [privateKey] and [peerPublicKey].
  ///
  /// Throws [BoringSslException] if [peerPublicKey] is a low-order point
  /// producing an all-zero shared secret (RFC 7748 Section 6.1).
  static Uint8List computeSharedSecret({
    required Uint8List privateKey,
    required Uint8List peerPublicKey,
  }) {
    if (privateKey.length != x25519PrivateKeyLength) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'Private key must be $x25519PrivateKeyLength bytes',
      );
    }
    if (peerPublicKey.length != x25519PublicKeyLength) {
      throw ArgumentError.value(
        peerPublicKey.length,
        'peerPublicKey',
        'Peer public key must be $x25519PublicKeyLength bytes',
      );
    }
    return withSecretSizedOutput(x25519SharedKeyLength, (out, arena) {
      checkBssl(
        bssl.X25519(
          out,
          copySecretBytesToNative(privateKey, arena),
          copyBytesToNative(peerPublicKey, arena),
        ),
        'X25519',
      );
      return x25519SharedKeyLength;
    });
  }
}

/// General cryptographic utility operations backed by BoringSSL.
abstract final class BoringCrypto {
  /// Compares [a] and [b] in constant time using BoringSSL's `CRYPTO_memcmp`.
  ///
  /// Returns `false` immediately if `a.length != b.length`, and otherwise
  /// takes time proportional to `a.length` independent of the byte contents.
  static bool timingSafeEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    if (a.isEmpty) return true;
    return using((arena) {
      final aPtr = copySecretBytesToNative(a, arena);
      final bPtr = copySecretBytesToNative(b, arena);
      return bssl.CRYPTO_memcmp(aPtr.cast(), bPtr.cast(), a.length) == 0;
    });
  }
}
