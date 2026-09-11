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

/// Padding scheme for RSA signatures.
enum RsaSignaturePadding {
  /// PKCS#1 v1.5 signature padding (RSASSA-PKCS1-v1_5).
  pkcs1(bssl.RSA_PKCS1_PADDING),

  /// Probabilistic Signature Scheme (RSASSA-PSS).
  pss(bssl.RSA_PKCS1_PSS_PADDING);

  final int nativeValue;
  const RsaSignaturePadding(this.nativeValue);
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
  factory BoringPublicKey.fromPem(String pem) => withMemBufBio(
    Uint8List.fromList(utf8.encode(pem)),
    (bio) {
      final pkey = bssl.PEM_read_bio_PUBKEY(
        bio,
        ffi.nullptr,
        ffi.nullptr,
        ffi.nullptr,
      );
      checkPointer(pkey, 'PEM_read_bio_PUBKEY');
      return BoringPublicKey._(pkey);
    },
  );

  /// Exports this public key as DER-encoded SubjectPublicKeyInfo.
  Uint8List toDer() => using((arena) {
    final len = bssl.i2d_PUBKEY(_pkey, ffi.nullptr);
    checkBssl(len > 0 ? 1 : 0, 'i2d_PUBKEY');
    final buffer = arena<ffi.Uint8>(len);
    final outPtr = arena<ffi.Pointer<ffi.Uint8>>()..value = buffer;
    final written = bssl.i2d_PUBKEY(_pkey, outPtr);
    checkBssl(written > 0 ? 1 : 0, 'i2d_PUBKEY');
    return Uint8List.fromList(buffer.asTypedList(written));
  });

  /// Exports this public key as PEM-encoded SubjectPublicKeyInfo.
  String toPem() => withMemBioString(
    'PEM_write_bio_PUBKEY',
    (bio) => bssl.PEM_write_bio_PUBKEY(bio, _pkey),
  );

  /// Verifies a digital [signature] over [data].
  ///
  /// For Ed25519, [algorithm] must be null. For RSA and ECDSA, specify the
  /// [HashAlgorithm] used when creating the signature (e.g.
  /// [HashAlgorithm.sha256]).
  ///
  /// For RSA keys, [rsaPadding] specifies the signature padding mode (defaults
  /// to [RsaSignaturePadding.pkcs1]). If [rsaPadding] is
  /// [RsaSignaturePadding.pss], [pssSaltLength] optionally specifies the salt
  /// length in bytes (defaults to matching the digest length).
  bool verify({
    HashAlgorithm? algorithm,
    required Uint8List data,
    required Uint8List signature,
    RsaSignaturePadding rsaPadding = RsaSignaturePadding.pkcs1,
    int? pssSaltLength,
  }) => withResource(
    create: bssl.EVP_MD_CTX_new,
    destroy: bssl.EVP_MD_CTX_free,
    operation: 'EVP_MD_CTX_new',
    body: (ctx) => using((arena) {
      final pctx = arena<ffi.Pointer<bssl.EVP_PKEY_CTX>>();
      checkBssl(
        bssl.EVP_DigestVerifyInit(
          ctx,
          pctx,
          algorithm?.evpMd ?? ffi.nullptr,
          ffi.nullptr,
          _pkey,
        ),
        'EVP_DigestVerifyInit',
      );
      if (keyType == KeyType.rsa) {
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_padding(
            pctx.value,
            rsaPadding.nativeValue,
          ),
          'EVP_PKEY_CTX_set_rsa_padding',
        );
        if (rsaPadding == RsaSignaturePadding.pss) {
          checkBssl(
            bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
              pctx.value,
              pssSaltLength ?? bssl.RSA_PSS_SALTLEN_DIGEST,
            ),
            'EVP_PKEY_CTX_set_rsa_pss_saltlen',
          );
        }
      }
      final verifyRet = bssl.EVP_DigestVerify(
        ctx,
        copyBytesToNative(signature, arena),
        signature.length,
        copyBytesOrNull(data, arena),
        data.length,
      );
      drainErrorQueue();
      return verifyRet == 1;
    }),
  );

  /// Verifies a digital [signature] over streaming [data].
  ///
  /// For Ed25519, the stream is buffered before verification.
  /// For RSA and ECDSA, data is verified incrementally.
  Future<bool> verifyStream({
    HashAlgorithm? algorithm,
    required Stream<List<int>> data,
    required Uint8List signature,
    RsaSignaturePadding rsaPadding = RsaSignaturePadding.pkcs1,
    int? pssSaltLength,
  }) async {
    if (keyType == KeyType.ed25519) {
      final bb = BytesBuilder();
      await for (final chunk in data) {
        bb.add(chunk);
      }
      return verify(
        algorithm: algorithm,
        data: bb.toBytes(),
        signature: signature,
        rsaPadding: rsaPadding,
        pssSaltLength: pssSaltLength,
      );
    }

    return withResourceAsync(
      create: bssl.EVP_MD_CTX_new,
      destroy: bssl.EVP_MD_CTX_free,
      operation: 'EVP_MD_CTX_new',
      body: (ctx) async {
        using((arena) {
          final pctx = arena<ffi.Pointer<bssl.EVP_PKEY_CTX>>();
          checkBssl(
            bssl.EVP_DigestVerifyInit(
              ctx,
              pctx,
              algorithm?.evpMd ?? ffi.nullptr,
              ffi.nullptr,
              _pkey,
            ),
            'EVP_DigestVerifyInit',
          );
          if (keyType == KeyType.rsa) {
            checkBssl(
              bssl.EVP_PKEY_CTX_set_rsa_padding(
                pctx.value,
                rsaPadding.nativeValue,
              ),
              'EVP_PKEY_CTX_set_rsa_padding',
            );
            if (rsaPadding == RsaSignaturePadding.pss) {
              checkBssl(
                bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
                  pctx.value,
                  pssSaltLength ?? bssl.RSA_PSS_SALTLEN_DIGEST,
                ),
                'EVP_PKEY_CTX_set_rsa_pss_saltlen',
              );
            }
          }
        });

        await for (final chunk in data) {
          if (chunk.isEmpty) continue;
          using((arena) {
            final ptr = copyBytesToNative(
              chunk is Uint8List ? chunk : Uint8List.fromList(chunk),
              arena,
            );
            checkBssl(
              bssl.EVP_DigestVerifyUpdate(ctx, ptr.cast(), chunk.length),
              'EVP_DigestVerifyUpdate',
            );
          });
        }

        return using((arena) {
          final sigPtr = copyBytesToNative(signature, arena);
          final verifyRet = bssl.EVP_DigestVerifyFinal(
            ctx,
            sigPtr,
            signature.length,
          );
          drainErrorQueue();
          return verifyRet == 1;
        });
      },
    );
  }

  /// Encrypts [plaintext] using RSA-OAEP (Optimal Asymmetric Encryption
  /// Padding, RFC 8017).
  ///
  /// - [hash]: Hash algorithm for OAEP and MGF1 (default:
  ///   [HashAlgorithm.sha256]).
  /// - [mgf1Hash]: Hash algorithm for MGF1 (defaults to [hash]).
  /// - [label]: Optional OAEP label/parameter.
  Uint8List encryptOaep({
    required Uint8List plaintext,
    HashAlgorithm hash = HashAlgorithm.sha256,
    HashAlgorithm? mgf1Hash,
    Uint8List? label,
  }) {
    if (keyType != KeyType.rsa) {
      throw StateError(
        'RSA-OAEP encryption is only supported for RSA keys (got $keyType).',
      );
    }
    return withResource(
      create: () => bssl.EVP_PKEY_CTX_new(_pkey, ffi.nullptr),
      destroy: bssl.EVP_PKEY_CTX_free,
      operation: 'EVP_PKEY_CTX_new',
      body: (ctx) => using((arena) {
        checkBssl(bssl.EVP_PKEY_encrypt_init(ctx), 'EVP_PKEY_encrypt_init');
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_padding(ctx, bssl.RSA_PKCS1_OAEP_PADDING),
          'EVP_PKEY_CTX_set_rsa_padding',
        );
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, hash.evpMd),
          'EVP_PKEY_CTX_set_rsa_oaep_md',
        );
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, (mgf1Hash ?? hash).evpMd),
          'EVP_PKEY_CTX_set_rsa_mgf1_md',
        );
        if (label != null && label.isNotEmpty) {
          final labelPtr = bssl.OPENSSL_malloc(label.length).cast<ffi.Uint8>();
          checkPointer(labelPtr, 'OPENSSL_malloc');
          labelPtr.asTypedList(label.length).setAll(0, label);
          final ret = bssl.EVP_PKEY_CTX_set0_rsa_oaep_label(
            ctx,
            labelPtr,
            label.length,
          );
          if (ret != 1) {
            bssl.OPENSSL_free(labelPtr.cast());
            checkBssl(ret, 'EVP_PKEY_CTX_set0_rsa_oaep_label');
          }
        }
        final inPtr = copyBytesToNative(plaintext, arena);
        return withOutputBuffer(
          'EVP_PKEY_encrypt',
          (out, len) => bssl.EVP_PKEY_encrypt(
            ctx,
            out,
            len,
            inPtr,
            plaintext.length,
          ),
        );
      }),
    );
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
  factory BoringPrivateKey.fromPem(String pem) => withMemBufBio(
    Uint8List.fromList(utf8.encode(pem)),
    (bio) {
      final pkey = bssl.PEM_read_bio_PrivateKey(
        bio,
        ffi.nullptr,
        ffi.nullptr,
        ffi.nullptr,
      );
      checkPointer(pkey, 'PEM_read_bio_PrivateKey');
      return BoringPrivateKey._(pkey);
    },
  );

  /// Exports this private key as DER-encoded PKCS#8 or type-specific format.
  Uint8List toDer() => using((arena) {
    final len = bssl.i2d_PrivateKey(_pkey, ffi.nullptr);
    checkBssl(len > 0 ? 1 : 0, 'i2d_PrivateKey');
    final buffer = arena<ffi.Uint8>(len);
    final outPtr = arena<ffi.Pointer<ffi.Uint8>>()..value = buffer;
    final written = bssl.i2d_PrivateKey(_pkey, outPtr);
    checkBssl(written > 0 ? 1 : 0, 'i2d_PrivateKey');
    return Uint8List.fromList(buffer.asTypedList(written));
  });

  /// Exports this private key as PEM-encoded PKCS#8
  /// (`-----BEGIN PRIVATE KEY-----`).
  String toPem() => withMemBioString(
    'PEM_write_bio_PKCS8PrivateKey',
    (bio) => bssl.PEM_write_bio_PKCS8PrivateKey(
      bio,
      _pkey,
      ffi.nullptr,
      ffi.nullptr,
      0,
      ffi.nullptr,
      ffi.nullptr,
    ),
  );

  /// Derives a shared secret with [peerPublicKey] using ECDH (RFC 5903).
  ///
  /// Returns the raw shared secret bytes.
  Uint8List deriveSharedSecret(BoringPublicKey peerPublicKey) {
    if (keyType != KeyType.ec) {
      throw StateError(
        'Key agreement is only supported for EC keys (got $keyType).',
      );
    }
    if (peerPublicKey.keyType != KeyType.ec) {
      throw ArgumentError.value(
        peerPublicKey.keyType,
        'peerPublicKey',
        'Peer key must be an EC key',
      );
    }
    return withResource(
      create: () => bssl.EVP_PKEY_CTX_new(_pkey, ffi.nullptr),
      destroy: bssl.EVP_PKEY_CTX_free,
      operation: 'EVP_PKEY_CTX_new',
      body: (ctx) {
        checkBssl(bssl.EVP_PKEY_derive_init(ctx), 'EVP_PKEY_derive_init');
        checkBssl(
          bssl.EVP_PKEY_derive_set_peer(ctx, peerPublicKey.handle),
          'EVP_PKEY_derive_set_peer',
        );
        return withOutputBuffer(
          'EVP_PKEY_derive',
          (out, len) => bssl.EVP_PKEY_derive(ctx, out, len),
        );
      },
    );
  }

  /// Derives [length] bytes of key material with [peerPublicKey] using ECDH.
  Uint8List deriveBits({
    required BoringPublicKey peerPublicKey,
    required int length,
  }) {
    final secret = deriveSharedSecret(peerPublicKey);
    if (length < 0 || length > secret.length) {
      throw ArgumentError.value(
        length,
        'length',
        'Length must be between 0 and ${secret.length} bytes',
      );
    }
    return Uint8List.sublistView(secret, 0, length);
  }

  /// Generates a digital signature over [data].
  ///
  /// For Ed25519, [algorithm] must be null. For RSA and ECDSA, specify the
  /// [HashAlgorithm] to use (e.g. [HashAlgorithm.sha256]).
  ///
  /// For RSA keys, [rsaPadding] specifies the signature padding mode (defaults
  /// to [RsaSignaturePadding.pkcs1]). If [rsaPadding] is
  /// [RsaSignaturePadding.pss], [pssSaltLength] optionally specifies the salt
  /// length in bytes (defaults to matching the digest length).
  Uint8List sign({
    HashAlgorithm? algorithm,
    required Uint8List data,
    RsaSignaturePadding rsaPadding = RsaSignaturePadding.pkcs1,
    int? pssSaltLength,
  }) => withResource(
    create: bssl.EVP_MD_CTX_new,
    destroy: bssl.EVP_MD_CTX_free,
    operation: 'EVP_MD_CTX_new',
    body: (ctx) => using((arena) {
      final pctx = arena<ffi.Pointer<bssl.EVP_PKEY_CTX>>();
      checkBssl(
        bssl.EVP_DigestSignInit(
          ctx,
          pctx,
          algorithm?.evpMd ?? ffi.nullptr,
          ffi.nullptr,
          _pkey,
        ),
        'EVP_DigestSignInit',
      );
      if (keyType == KeyType.rsa) {
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_padding(
            pctx.value,
            rsaPadding.nativeValue,
          ),
          'EVP_PKEY_CTX_set_rsa_padding',
        );
        if (rsaPadding == RsaSignaturePadding.pss) {
          checkBssl(
            bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
              pctx.value,
              pssSaltLength ?? bssl.RSA_PSS_SALTLEN_DIGEST,
            ),
            'EVP_PKEY_CTX_set_rsa_pss_saltlen',
          );
        }
      }
      final dataPtr = copyBytesOrNull(data, arena);
      return withOutputBuffer(
        'EVP_DigestSign',
        (out, len) => bssl.EVP_DigestSign(ctx, out, len, dataPtr, data.length),
      );
    }),
  );

  /// Generates a digital signature over streaming [data].
  ///
  /// For Ed25519, the stream is buffered before signing.
  /// For RSA and ECDSA, data is signed incrementally.
  Future<Uint8List> signStream({
    HashAlgorithm? algorithm,
    required Stream<List<int>> data,
    RsaSignaturePadding rsaPadding = RsaSignaturePadding.pkcs1,
    int? pssSaltLength,
  }) async {
    if (keyType == KeyType.ed25519) {
      final bb = BytesBuilder();
      await for (final chunk in data) {
        bb.add(chunk);
      }
      return sign(
        algorithm: algorithm,
        data: bb.toBytes(),
        rsaPadding: rsaPadding,
        pssSaltLength: pssSaltLength,
      );
    }

    return withResourceAsync(
      create: bssl.EVP_MD_CTX_new,
      destroy: bssl.EVP_MD_CTX_free,
      operation: 'EVP_MD_CTX_new',
      body: (ctx) async {
        using((arena) {
          final pctx = arena<ffi.Pointer<bssl.EVP_PKEY_CTX>>();
          checkBssl(
            bssl.EVP_DigestSignInit(
              ctx,
              pctx,
              algorithm?.evpMd ?? ffi.nullptr,
              ffi.nullptr,
              _pkey,
            ),
            'EVP_DigestSignInit',
          );
          if (keyType == KeyType.rsa) {
            checkBssl(
              bssl.EVP_PKEY_CTX_set_rsa_padding(
                pctx.value,
                rsaPadding.nativeValue,
              ),
              'EVP_PKEY_CTX_set_rsa_padding',
            );
            if (rsaPadding == RsaSignaturePadding.pss) {
              checkBssl(
                bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
                  pctx.value,
                  pssSaltLength ?? bssl.RSA_PSS_SALTLEN_DIGEST,
                ),
                'EVP_PKEY_CTX_set_rsa_pss_saltlen',
              );
            }
          }
        });

        await for (final chunk in data) {
          if (chunk.isEmpty) continue;
          using((arena) {
            final ptr = copyBytesToNative(
              chunk is Uint8List ? chunk : Uint8List.fromList(chunk),
              arena,
            );
            checkBssl(
              bssl.EVP_DigestSignUpdate(ctx, ptr.cast(), chunk.length),
              'EVP_DigestSignUpdate',
            );
          });
        }

        return withOutputBuffer(
          'EVP_DigestSignFinal',
          (out, len) => bssl.EVP_DigestSignFinal(ctx, out, len),
        );
      },
    );
  }

  /// Decrypts [ciphertext] using RSA-OAEP (Optimal Asymmetric Encryption
  /// Padding, RFC 8017).
  ///
  /// - [hash]: Hash algorithm for OAEP and MGF1 (default:
  ///   [HashAlgorithm.sha256]).
  /// - [mgf1Hash]: Hash algorithm for MGF1 (defaults to [hash]).
  /// - [label]: Optional OAEP label/parameter.
  Uint8List decryptOaep({
    required Uint8List ciphertext,
    HashAlgorithm hash = HashAlgorithm.sha256,
    HashAlgorithm? mgf1Hash,
    Uint8List? label,
  }) {
    if (keyType != KeyType.rsa) {
      throw StateError(
        'RSA-OAEP decryption is only supported for RSA keys (got $keyType).',
      );
    }
    return withResource(
      create: () => bssl.EVP_PKEY_CTX_new(_pkey, ffi.nullptr),
      destroy: bssl.EVP_PKEY_CTX_free,
      operation: 'EVP_PKEY_CTX_new',
      body: (ctx) => using((arena) {
        checkBssl(bssl.EVP_PKEY_decrypt_init(ctx), 'EVP_PKEY_decrypt_init');
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_padding(ctx, bssl.RSA_PKCS1_OAEP_PADDING),
          'EVP_PKEY_CTX_set_rsa_padding',
        );
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, hash.evpMd),
          'EVP_PKEY_CTX_set_rsa_oaep_md',
        );
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, (mgf1Hash ?? hash).evpMd),
          'EVP_PKEY_CTX_set_rsa_mgf1_md',
        );
        if (label != null && label.isNotEmpty) {
          final labelPtr = bssl.OPENSSL_malloc(label.length).cast<ffi.Uint8>();
          checkPointer(labelPtr, 'OPENSSL_malloc');
          labelPtr.asTypedList(label.length).setAll(0, label);
          final ret = bssl.EVP_PKEY_CTX_set0_rsa_oaep_label(
            ctx,
            labelPtr,
            label.length,
          );
          if (ret != 1) {
            bssl.OPENSSL_free(labelPtr.cast());
            checkBssl(ret, 'EVP_PKEY_CTX_set0_rsa_oaep_label');
          }
        }
        final inPtr = copyBytesToNative(ciphertext, arena);
        return withOutputBuffer(
          'EVP_PKEY_decrypt',
          (out, len) => bssl.EVP_PKEY_decrypt(
            ctx,
            out,
            len,
            inPtr,
            ciphertext.length,
          ),
        );
      }),
    );
  }
}
