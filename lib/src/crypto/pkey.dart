// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'digest.dart';

/// Elliptic curve types supported by ECDSA.
enum EcCurve {
  p256(bssl.NID_X9_62_prime256v1),
  p384(bssl.NID_secp384r1),
  p521(bssl.NID_secp521r1);

  final int nid;
  const EcCurve(this.nid);
}

/// Asymmetric key algorithm type.
enum KeyType {
  rsa,
  ec,
  ed25519,
  unknown;

  static KeyType _fromNid(int nid) => switch (nid) {
    bssl.NID_rsaEncryption => KeyType.rsa,
    bssl.NID_X9_62_id_ecPublicKey => KeyType.ec,
    bssl.NID_ED25519 => KeyType.ed25519,
    _ => KeyType.unknown,
  };
}

String _readBioString(ffi.Pointer<bssl.BIO> bio) {
  final buffer = calloc<ffi.Uint8>(1024);
  try {
    final sb = StringBuffer();
    while (true) {
      final read = bssl.BIO_read(bio, buffer.cast(), 1024);
      if (read <= 0) break;
      sb.write(utf8.decode(buffer.asTypedList(read)));
    }
    return sb.toString();
  } finally {
    calloc.free(buffer);
  }
}

/// Public asymmetric cryptographic key (RSA, ECDSA, Ed25519).
final class BoringPublicKey implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_PKEY>)>
        >(bssl.EVP_PKEY_free)
        .cast(),
  );

  final ffi.Pointer<bssl.EVP_PKEY> _pkey;

  BoringPublicKey._(this._pkey) {
    _finalizer.attach(this, _pkey.cast(), externalSize: 512);
  }

  /// Creates a public key wrapping an existing EVP_PKEY native pointer.
  BoringPublicKey.fromHandle(this._pkey) {
    _finalizer.attach(this, _pkey.cast(), externalSize: 512);
  }

  /// Internal handle accessor for PKI operations.
  ffi.Pointer<bssl.EVP_PKEY> get handle => _pkey;

  /// The algorithm type of this key.
  KeyType get keyType => KeyType._fromNid(bssl.EVP_PKEY_id(_pkey));

  /// Key size in bits (for RSA: modulus length; for EC: curve order).
  int get bits => bssl.EVP_PKEY_bits(_pkey);

  /// Parses an ASN.1 SubjectPublicKeyInfo (SPKI) DER-encoded public key.
  factory BoringPublicKey.fromDer(Uint8List der) {
    return using((arena) {
      final buffer = copyBytesToNative(der, arena);
      final inpPtr = arena<ffi.Pointer<ffi.Uint8>>();
      inpPtr.value = buffer;
      final pkey = bssl.d2i_PUBKEY(ffi.nullptr, inpPtr, der.length);
      checkPointer(pkey, 'd2i_PUBKEY');
      return BoringPublicKey._(pkey);
    });
  }

  /// Parses a PEM-encoded SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`).
  factory BoringPublicKey.fromPem(String pem) {
    final pemBytes = utf8.encode(pem);
    return using((arena) {
      final buffer = copyBytesToNative(Uint8List.fromList(pemBytes), arena);
      final bio = bssl.BIO_new_mem_buf(buffer.cast(), pemBytes.length);
      checkPointer(bio, 'BIO_new_mem_buf');
      try {
        final pkey = bssl.PEM_read_bio_PUBKEY(
          bio,
          ffi.nullptr,
          ffi.nullptr,
          ffi.nullptr,
        );
        checkPointer(pkey, 'PEM_read_bio_PUBKEY');
        return BoringPublicKey._(pkey);
      } finally {
        bssl.BIO_free(bio);
      }
    });
  }

  /// Exports this public key as DER-encoded SubjectPublicKeyInfo.
  Uint8List toDer() {
    final len = bssl.i2d_PUBKEY(_pkey, ffi.nullptr);
    if (len <= 0) {
      checkBssl(0, 'i2d_PUBKEY');
    }
    return using((arena) {
      final buffer = arena<ffi.Uint8>(len);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      outPtr.value = buffer;
      final written = bssl.i2d_PUBKEY(_pkey, outPtr);
      checkBssl(written > 0 ? 1 : 0, 'i2d_PUBKEY');
      return Uint8List.fromList(buffer.asTypedList(written));
    });
  }

  /// Exports this public key as PEM-encoded SubjectPublicKeyInfo.
  String toPem() {
    final memMethod = bssl.BIO_s_mem();
    final bio = bssl.BIO_new(memMethod);
    checkPointer(bio, 'BIO_new');
    try {
      final ret = bssl.PEM_write_bio_PUBKEY(bio, _pkey);
      checkBssl(ret, 'PEM_write_bio_PUBKEY');
      return _readBioString(bio);
    } finally {
      bssl.BIO_free(bio);
    }
  }

  /// Verifies a digital [signature] over [data].
  ///
  /// For Ed25519, [algorithm] must be null. For RSA and ECDSA, specify the
  /// [HashAlgorithm] used when creating the signature (e.g.
  /// [HashAlgorithm.sha256]).
  bool verify({
    HashAlgorithm? algorithm,
    required Uint8List data,
    required Uint8List signature,
  }) {
    final ctx = bssl.EVP_MD_CTX_new();
    checkPointer(ctx, 'EVP_MD_CTX_new');
    try {
      final md = algorithm?.evpMd ?? ffi.nullptr;
      final initRet = bssl.EVP_DigestVerifyInit(
        ctx,
        ffi.nullptr,
        md,
        ffi.nullptr,
        _pkey,
      );
      checkBssl(initRet, 'EVP_DigestVerifyInit');

      return using((arena) {
        final sigPtr = copyBytesToNative(signature, arena);
        final dataPtr = data.isNotEmpty
            ? copyBytesToNative(data, arena)
            : ffi.nullptr;
        final verifyRet = bssl.EVP_DigestVerify(
          ctx,
          sigPtr,
          signature.length,
          dataPtr,
          data.length,
        );
        return verifyRet == 1;
      });
    } finally {
      bssl.EVP_MD_CTX_free(ctx);
    }
  }
}

/// Private asymmetric cryptographic key (RSA, ECDSA, Ed25519).
final class BoringPrivateKey implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_PKEY>)>
        >(bssl.EVP_PKEY_free)
        .cast(),
  );

  final ffi.Pointer<bssl.EVP_PKEY> _pkey;

  BoringPrivateKey._(this._pkey) {
    _finalizer.attach(this, _pkey.cast(), externalSize: 1024);
  }

  /// Internal handle accessor.
  ffi.Pointer<bssl.EVP_PKEY> get handle => _pkey;

  /// The algorithm type of this key.
  KeyType get keyType => KeyType._fromNid(bssl.EVP_PKEY_id(_pkey));

  /// Key size in bits.
  int get bits => bssl.EVP_PKEY_bits(_pkey);

  /// Extracts the corresponding public key.
  BoringPublicKey get publicKey {
    final pubKey = bssl.EVP_PKEY_copy_public(_pkey);
    checkPointer(pubKey, 'EVP_PKEY_copy_public');
    return BoringPublicKey._(pubKey);
  }

  /// Generates a new RSA private key of [bits] size (default 2048).
  static BoringPrivateKey generateRsa({int bits = 2048}) {
    final pkey = bssl.EVP_RSA_gen(bits);
    checkPointer(pkey, 'EVP_RSA_gen');
    return BoringPrivateKey._(pkey);
  }

  /// Generates a new ECDSA private key for [curve].
  static BoringPrivateKey generateEc(EcCurve curve) {
    final ec = bssl.EC_KEY_new_by_curve_name(curve.nid);
    checkPointer(ec, 'EC_KEY_new_by_curve_name');
    try {
      final genRet = bssl.EC_KEY_generate_key(ec);
      checkBssl(genRet, 'EC_KEY_generate_key');
      final pkey = bssl.EVP_PKEY_new();
      checkPointer(pkey, 'EVP_PKEY_new');
      final assignRet = bssl.EVP_PKEY_assign_EC_KEY(pkey, ec);
      checkBssl(assignRet, 'EVP_PKEY_assign_EC_KEY');
      return BoringPrivateKey._(pkey);
    } catch (_) {
      bssl.EC_KEY_free(ec);
      rethrow;
    }
  }

  /// Parses a DER-encoded private key (PKCS#8, PKCS#1 RSA, or SEC1 EC).
  factory BoringPrivateKey.fromDer(Uint8List der) {
    return using((arena) {
      final buffer = copyBytesToNative(der, arena);
      final inpPtr = arena<ffi.Pointer<ffi.Uint8>>();
      inpPtr.value = buffer;
      final pkey = bssl.d2i_AutoPrivateKey(ffi.nullptr, inpPtr, der.length);
      checkPointer(pkey, 'd2i_AutoPrivateKey');
      return BoringPrivateKey._(pkey);
    });
  }

  /// Parses a PEM-encoded private key (`-----BEGIN PRIVATE KEY-----` or
  /// `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN EC PRIVATE KEY-----`).
  factory BoringPrivateKey.fromPem(String pem) {
    final pemBytes = utf8.encode(pem);
    return using((arena) {
      final buffer = copyBytesToNative(Uint8List.fromList(pemBytes), arena);
      final bio = bssl.BIO_new_mem_buf(buffer.cast(), pemBytes.length);
      checkPointer(bio, 'BIO_new_mem_buf');
      try {
        final pkey = bssl.PEM_read_bio_PrivateKey(
          bio,
          ffi.nullptr,
          ffi.nullptr,
          ffi.nullptr,
        );
        checkPointer(pkey, 'PEM_read_bio_PrivateKey');
        return BoringPrivateKey._(pkey);
      } finally {
        bssl.BIO_free(bio);
      }
    });
  }

  /// Exports this private key as DER-encoded PKCS#8 or type-specific format.
  Uint8List toDer() {
    final len = bssl.i2d_PrivateKey(_pkey, ffi.nullptr);
    if (len <= 0) {
      checkBssl(0, 'i2d_PrivateKey');
    }
    return using((arena) {
      final buffer = arena<ffi.Uint8>(len);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      outPtr.value = buffer;
      final written = bssl.i2d_PrivateKey(_pkey, outPtr);
      checkBssl(written > 0 ? 1 : 0, 'i2d_PrivateKey');
      return Uint8List.fromList(buffer.asTypedList(written));
    });
  }

  /// Exports this private key as PEM-encoded PKCS#8
  /// (`-----BEGIN PRIVATE KEY-----`).
  String toPem() {
    final memMethod = bssl.BIO_s_mem();
    final bio = bssl.BIO_new(memMethod);
    checkPointer(bio, 'BIO_new');
    try {
      final ret = bssl.PEM_write_bio_PKCS8PrivateKey(
        bio,
        _pkey,
        ffi.nullptr,
        ffi.nullptr,
        0,
        ffi.nullptr,
        ffi.nullptr,
      );
      checkBssl(ret, 'PEM_write_bio_PKCS8PrivateKey');
      return _readBioString(bio);
    } finally {
      bssl.BIO_free(bio);
    }
  }

  /// Generates a digital signature over [data].
  ///
  /// For Ed25519, [algorithm] must be null. For RSA and ECDSA, specify the
  /// [HashAlgorithm] to use (e.g. [HashAlgorithm.sha256]).
  Uint8List sign({
    HashAlgorithm? algorithm,
    required Uint8List data,
  }) {
    final ctx = bssl.EVP_MD_CTX_new();
    checkPointer(ctx, 'EVP_MD_CTX_new');
    try {
      final md = algorithm?.evpMd ?? ffi.nullptr;
      final initRet = bssl.EVP_DigestSignInit(
        ctx,
        ffi.nullptr,
        md,
        ffi.nullptr,
        _pkey,
      );
      checkBssl(initRet, 'EVP_DigestSignInit');

      return using((arena) {
        final sigLenPtr = arena<ffi.Size>();
        final dataPtr = data.isNotEmpty
            ? copyBytesToNative(data, arena)
            : ffi.nullptr;

        // Query maximum signature length
        final sizeRet = bssl.EVP_DigestSign(
          ctx,
          ffi.nullptr,
          sigLenPtr,
          dataPtr,
          data.length,
        );
        checkBssl(sizeRet, 'EVP_DigestSign size query');

        final maxSigLen = sigLenPtr.value;
        final sigBuf = arena<ffi.Uint8>(maxSigLen);

        final signRet = bssl.EVP_DigestSign(
          ctx,
          sigBuf,
          sigLenPtr,
          dataPtr,
          data.length,
        );
        checkBssl(signRet, 'EVP_DigestSign');
        return Uint8List.fromList(sigBuf.asTypedList(sigLenPtr.value));
      });
    } finally {
      bssl.EVP_MD_CTX_free(ctx);
    }
  }
}
