// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'digest.dart';

/// Elliptic curve types supported by ECDSA and ECDH.
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
  x25519,
  unknown;

  static KeyType _fromNid(int nid) => switch (nid) {
    bssl.NID_rsaEncryption => KeyType.rsa,
    bssl.NID_X9_62_id_ecPublicKey => KeyType.ec,
    bssl.NID_ED25519 => KeyType.ed25519,
    bssl.NID_X25519 => KeyType.x25519,
    _ => KeyType.unknown,
  };

  int get _evpPkeyId => switch (this) {
    KeyType.rsa => bssl.EVP_PKEY_RSA,
    KeyType.ec => bssl.EVP_PKEY_EC,
    KeyType.ed25519 => bssl.EVP_PKEY_ED25519,
    KeyType.x25519 => bssl.EVP_PKEY_X25519,
    KeyType.unknown => bssl.EVP_PKEY_NONE,
  };
}

/// Public asymmetric cryptographic key (RSA, ECDSA, Ed25519, X25519).
final class BoringPublicKey implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_PKEY>)>
        >(bssl.EVP_PKEY_free)
        .cast(),
  );

  final ffi.Pointer<bssl.EVP_PKEY> _pkey;
  bool _isDisposed = false;

  BoringPublicKey._(this._pkey) {
    _finalizer.attach(this, _pkey.cast(), detach: this, externalSize: 512);
  }

  /// Creates a public key wrapping an existing EVP_PKEY native pointer.
  BoringPublicKey.fromHandle(this._pkey) {
    _finalizer.attach(this, _pkey.cast(), detach: this, externalSize: 512);
  }

  void _checkNotDisposed() {
    if (_isDisposed) {
      throw StateError('BoringPublicKey has been disposed.');
    }
  }

  /// Releases the underlying native `EVP_PKEY` handle immediately.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _finalizer.detach(this);
    bssl.EVP_PKEY_free(_pkey);
  }

  /// Internal handle accessor for PKI operations.
  ffi.Pointer<bssl.EVP_PKEY> get handle {
    _checkNotDisposed();
    return _pkey;
  }

  /// The algorithm type of this key.
  KeyType get keyType {
    _checkNotDisposed();
    return KeyType._fromNid(bssl.EVP_PKEY_id(_pkey));
  }

  /// Key size in bits (for RSA: modulus length; for EC: curve order).
  int get bits {
    _checkNotDisposed();
    return bssl.EVP_PKEY_bits(_pkey);
  }

  /// Creates a public key from raw key bytes (supported for [KeyType.ed25519]
  /// and [KeyType.x25519]).
  factory BoringPublicKey.fromRawKey(KeyType type, Uint8List rawPublicKey) {
    if (type != KeyType.ed25519 && type != KeyType.x25519) {
      throw ArgumentError.value(
        type,
        'type',
        'Raw public key import is only supported for '
            'KeyType.ed25519 and KeyType.x25519',
      );
    }
    return using((arena) {
      final ptr = copyBytesToNative(rawPublicKey, arena);
      final pkey = bssl.EVP_PKEY_new_raw_public_key(
        type._evpPkeyId,
        ffi.nullptr,
        ptr,
        rawPublicKey.length,
      );
      checkPointer(pkey, 'EVP_PKEY_new_raw_public_key');
      return BoringPublicKey._(pkey);
    });
  }

  /// Exports raw public key bytes (supported for [KeyType.ed25519] and
  /// [KeyType.x25519]).
  Uint8List toRawBytes() {
    _checkNotDisposed();
    if (keyType != KeyType.ed25519 && keyType != KeyType.x25519) {
      throw StateError(
        'Raw public key export is only supported for '
        'Ed25519 and X25519 keys (got $keyType).',
      );
    }
    return withOutputBuffer(
      'EVP_PKEY_get_raw_public_key',
      (out, len) => bssl.EVP_PKEY_get_raw_public_key(_pkey, out, len),
    );
  }

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
  Uint8List toDer() {
    _checkNotDisposed();
    return using((arena) {
      final len = bssl.i2d_PUBKEY(_pkey, ffi.nullptr);
      checkBssl(len > 0 ? 1 : 0, 'i2d_PUBKEY');
      final buffer = arena<ffi.Uint8>(len);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>()..value = buffer;
      final written = bssl.i2d_PUBKEY(_pkey, outPtr);
      checkBssl(written > 0 ? 1 : 0, 'i2d_PUBKEY');
      return Uint8List.fromList(buffer.asTypedList(written));
    });
  }

  /// Exports this public key as PEM-encoded SubjectPublicKeyInfo.
  String toPem() {
    _checkNotDisposed();
    return withMemBioString(
      'PEM_write_bio_PUBKEY',
      (bio) => bssl.PEM_write_bio_PUBKEY(bio, _pkey),
    );
  }

  /// Verifies a digital [signature] over [data].
  ///
  /// For Ed25519, [algorithm] must be omitted (`null`). For RSA and ECDSA,
  /// specify the [HashAlgorithm] used when creating the signature (e.g.
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
  }) {
    _checkNotDisposed();
    if (keyType == KeyType.ed25519 && algorithm != null) {
      throw ArgumentError.value(
        algorithm,
        'algorithm',
        'Ed25519 does not take a separate HashAlgorithm; omit algorithm.',
      );
    }
    if ((keyType == KeyType.rsa || keyType == KeyType.ec) &&
        algorithm == null) {
      throw ArgumentError.notNull('algorithm');
    }
    return withResource(
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
  }

  /// Verifies a digital [signature] over a precomputed [digest].
  ///
  /// For Ed25519, precomputed digests are not supported (Ed25519 signs raw
  /// data). For RSA and ECDSA, specify the [HashAlgorithm] that was used to
  /// compute [digest].
  ///
  /// For RSA keys, [rsaPadding] specifies the signature padding mode (defaults
  /// to [RsaSignaturePadding.pkcs1]). If [rsaPadding] is
  /// [RsaSignaturePadding.pss], [pssSaltLength] optionally specifies the salt
  /// length in bytes (defaults to matching the digest length).
  bool verifyDigest({
    required HashAlgorithm algorithm,
    required Uint8List digest,
    required Uint8List signature,
    RsaSignaturePadding rsaPadding = RsaSignaturePadding.pkcs1,
    int? pssSaltLength,
  }) {
    _checkNotDisposed();
    if (keyType == KeyType.ed25519) {
      throw UnsupportedError('Ed25519 does not support precomputed digests.');
    }
    return withResource(
      create: () => bssl.EVP_PKEY_CTX_new(_pkey, ffi.nullptr),
      destroy: bssl.EVP_PKEY_CTX_free,
      operation: 'EVP_PKEY_CTX_new',
      body: (ctx) => using((arena) {
        checkBssl(bssl.EVP_PKEY_verify_init(ctx), 'EVP_PKEY_verify_init');
        checkBssl(
          bssl.EVP_PKEY_CTX_set_signature_md(ctx, algorithm.evpMd),
          'EVP_PKEY_CTX_set_signature_md',
        );
        if (keyType == KeyType.rsa) {
          checkBssl(
            bssl.EVP_PKEY_CTX_set_rsa_padding(
              ctx,
              rsaPadding.nativeValue,
            ),
            'EVP_PKEY_CTX_set_rsa_padding',
          );
          if (rsaPadding == RsaSignaturePadding.pss) {
            checkBssl(
              bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
                ctx,
                pssSaltLength ?? bssl.RSA_PSS_SALTLEN_DIGEST,
              ),
              'EVP_PKEY_CTX_set_rsa_pss_saltlen',
            );
          }
        }
        final sigPtr = copyBytesToNative(signature, arena);
        final digPtr = copyBytesToNative(digest, arena);
        final verifyRet = bssl.EVP_PKEY_verify(
          ctx,
          sigPtr,
          signature.length,
          digPtr,
          digest.length,
        );
        drainErrorQueue();
        return verifyRet == 1;
      }),
    );
  }

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
    _checkNotDisposed();
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
  /// - [hash] / [algorithm]: Hash algorithm for OAEP and MGF1 (default:
  ///   [HashAlgorithm.sha256]).
  /// - [mgf1Hash]: Hash algorithm for MGF1 (defaults to [hash]).
  /// - [label]: Optional OAEP label/parameter.
  Uint8List encryptOaep({
    required Uint8List plaintext,
    HashAlgorithm hash = HashAlgorithm.sha256,
    HashAlgorithm? algorithm,
    HashAlgorithm? mgf1Hash,
    Uint8List? label,
  }) {
    _checkNotDisposed();
    if (keyType != KeyType.rsa) {
      throw StateError(
        'RSA-OAEP encryption is only supported for RSA keys (got $keyType).',
      );
    }
    final oaepMd = algorithm ?? hash;
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
          bssl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaepMd.evpMd),
          'EVP_PKEY_CTX_set_rsa_oaep_md',
        );
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, (mgf1Hash ?? oaepMd).evpMd),
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
        final inPtr = copySecretBytesToNative(plaintext, arena);
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

/// Private asymmetric cryptographic key (RSA, ECDSA, Ed25519, X25519).
final class BoringPrivateKey implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.EVP_PKEY>)>
        >(bssl.EVP_PKEY_free)
        .cast(),
  );

  final ffi.Pointer<bssl.EVP_PKEY> _pkey;
  bool _isDisposed = false;

  BoringPrivateKey._(this._pkey) {
    _finalizer.attach(this, _pkey.cast(), detach: this, externalSize: 1024);
  }

  void _checkNotDisposed() {
    if (_isDisposed) {
      throw StateError('BoringPrivateKey has been disposed.');
    }
  }

  /// Releases the underlying native `EVP_PKEY` handle immediately.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _finalizer.detach(this);
    bssl.EVP_PKEY_free(_pkey);
  }

  /// Internal handle accessor.
  ffi.Pointer<bssl.EVP_PKEY> get handle {
    _checkNotDisposed();
    return _pkey;
  }

  /// The algorithm type of this key.
  KeyType get keyType {
    _checkNotDisposed();
    return KeyType._fromNid(bssl.EVP_PKEY_id(_pkey));
  }

  /// Key size in bits.
  int get bits {
    _checkNotDisposed();
    return bssl.EVP_PKEY_bits(_pkey);
  }

  /// Extracts the corresponding public key.
  BoringPublicKey get publicKey {
    _checkNotDisposed();
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

  /// Generates a new ECDSA/ECDH private key for [curve].
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

  /// Generates a new Ed25519 private key (`EVP_PKEY_ED25519`).
  static BoringPrivateKey generateEd25519() =>
      _generateByEvpId(bssl.EVP_PKEY_ED25519);

  /// Generates a new X25519 private key (`EVP_PKEY_X25519`).
  static BoringPrivateKey generateX25519() =>
      _generateByEvpId(bssl.EVP_PKEY_X25519);

  static BoringPrivateKey _generateByEvpId(int id) => withResource(
    create: () => bssl.EVP_PKEY_CTX_new_id(id, ffi.nullptr),
    destroy: bssl.EVP_PKEY_CTX_free,
    operation: 'EVP_PKEY_CTX_new_id',
    body: (ctx) => using((arena) {
      checkBssl(bssl.EVP_PKEY_keygen_init(ctx), 'EVP_PKEY_keygen_init');
      final outPkey = arena<ffi.Pointer<bssl.EVP_PKEY>>();
      checkBssl(bssl.EVP_PKEY_keygen(ctx, outPkey), 'EVP_PKEY_keygen');
      return BoringPrivateKey._(checkPointer(outPkey.value, 'EVP_PKEY_keygen'));
    }),
  );

  /// Creates a private key from raw key/seed bytes (supported for
  /// [KeyType.ed25519] and [KeyType.x25519]).
  ///
  /// For [KeyType.ed25519], accepts either the 32-byte seed or the 64-byte
  /// `(seed || pub)` representation.
  factory BoringPrivateKey.fromRawKey(KeyType type, Uint8List rawPrivateKey) {
    if (type != KeyType.ed25519 && type != KeyType.x25519) {
      throw ArgumentError.value(
        type,
        'type',
        'Raw private key import is only supported for '
            'KeyType.ed25519 and KeyType.x25519',
      );
    }
    final keySlice = (type == KeyType.ed25519 && rawPrivateKey.length == 64)
        ? Uint8List.sublistView(rawPrivateKey, 0, 32)
        : rawPrivateKey;
    return using((arena) {
      final ptr = copySecretBytesToNative(keySlice, arena);
      final pkey = bssl.EVP_PKEY_new_raw_private_key(
        type._evpPkeyId,
        ffi.nullptr,
        ptr,
        keySlice.length,
      );
      checkPointer(pkey, 'EVP_PKEY_new_raw_private_key');
      return BoringPrivateKey._(pkey);
    });
  }

  /// Exports raw private key/seed bytes (supported for [KeyType.ed25519] and
  /// [KeyType.x25519]).
  Uint8List toRawBytes() {
    _checkNotDisposed();
    if (keyType != KeyType.ed25519 && keyType != KeyType.x25519) {
      throw StateError(
        'Raw private key export is only supported for '
        'Ed25519 and X25519 keys (got $keyType).',
      );
    }
    return withSecretOutputBuffer(
      'EVP_PKEY_get_raw_private_key',
      (out, len) => bssl.EVP_PKEY_get_raw_private_key(_pkey, out, len),
    );
  }

  /// Parses a DER-encoded private key (PKCS#8, PKCS#1 RSA, or SEC1 EC).
  factory BoringPrivateKey.fromDer(Uint8List der) {
    return using((arena) {
      final buffer = copySecretBytesToNative(der, arena);
      final inpPtr = arena<ffi.Pointer<ffi.Uint8>>();
      inpPtr.value = buffer;
      final pkey = bssl.d2i_AutoPrivateKey(ffi.nullptr, inpPtr, der.length);
      checkPointer(pkey, 'd2i_AutoPrivateKey');
      return BoringPrivateKey._(pkey);
    });
  }

  static Uint8List? _normalizePassword(Object? password) {
    if (password == null) return null;
    if (password is Uint8List) return password;
    if (password is String) return Uint8List.fromList(utf8.encode(password));
    if (password is List<int>) return Uint8List.fromList(password);
    throw ArgumentError.value(
      password,
      'password',
      'must be a String or Uint8List',
    );
  }

  /// Parses a PEM-encoded private key (`-----BEGIN PRIVATE KEY-----`,
  /// `-----BEGIN ENCRYPTED PRIVATE KEY-----`,
  /// `-----BEGIN RSA PRIVATE KEY-----`, or `-----BEGIN EC PRIVATE KEY-----`).
  ///
  /// If the PEM is encrypted, supply the [password] (`String` or `Uint8List`).
  factory BoringPrivateKey.fromPem(String pem, {Object? password}) =>
      using((arena) {
        final passBytes = _normalizePassword(password);
        final pemBytes = Uint8List.fromList(utf8.encode(pem));
        final bioBuf = copySecretBytesToNative(pemBytes, arena);
        return withResource(
          create: () => bssl.BIO_new_mem_buf(bioBuf.cast(), pemBytes.length),
          destroy: bssl.BIO_free,
          operation: 'BIO_new_mem_buf',
          body: (bio) {
            ffi.Pointer<ffi.Void> passArg = ffi.nullptr;
            if (passBytes != null) {
              // Null-terminated password string expected when cb == nullptr.
              final nullTerminated = Uint8List(passBytes.length + 1)
                ..setRange(0, passBytes.length, passBytes);
              passArg = copySecretBytesToNative(nullTerminated, arena).cast();
            }
            final pkey = bssl.PEM_read_bio_PrivateKey(
              bio,
              ffi.nullptr,
              ffi.nullptr,
              passArg,
            );
            checkPointer(pkey, 'PEM_read_bio_PrivateKey');
            return BoringPrivateKey._(pkey);
          },
        );
      });

  /// Exports this private key as DER-encoded PKCS#8 or type-specific format.
  Uint8List toDer() {
    _checkNotDisposed();
    return using((arena) {
      final len = bssl.i2d_PrivateKey(_pkey, ffi.nullptr);
      checkBssl(len > 0 ? 1 : 0, 'i2d_PrivateKey');
      final buffer = allocateSecretBytes(len, arena);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>()..value = buffer;
      final written = bssl.i2d_PrivateKey(_pkey, outPtr);
      checkBssl(written > 0 ? 1 : 0, 'i2d_PrivateKey');
      return Uint8List.fromList(buffer.asTypedList(written));
    });
  }

  /// Exports this private key as PEM-encoded PKCS#8
  /// (`-----BEGIN PRIVATE KEY-----` or `-----BEGIN ENCRYPTED PRIVATE KEY-----`
  /// when [password] (`String` or `Uint8List`) is provided).
  String toPem({Object? password}) {
    _checkNotDisposed();
    final passBytes = _normalizePassword(password);
    return using((arena) {
      final hasPass = passBytes != null && passBytes.isNotEmpty;
      final passPtr = hasPass
          ? copySecretBytesToNative(passBytes, arena).cast<ffi.Char>()
          : ffi.nullptr;
      final cipher = hasPass ? bssl.EVP_aes_256_cbc() : ffi.nullptr;
      return withMemBioString(
        'PEM_write_bio_PKCS8PrivateKey',
        (bio) => bssl.PEM_write_bio_PKCS8PrivateKey(
          bio,
          _pkey,
          cipher,
          passPtr,
          hasPass ? passBytes.length : 0,
          ffi.nullptr,
          ffi.nullptr,
        ),
      );
    });
  }

  /// Derives a shared secret with [peerPublicKey] using ECDH (RFC 5903) or
  /// X25519 (RFC 7748).
  ///
  /// Returns the raw shared secret bytes.
  Uint8List deriveSharedSecret(BoringPublicKey peerPublicKey) {
    _checkNotDisposed();
    if (keyType != KeyType.ec && keyType != KeyType.x25519) {
      throw StateError(
        'Key agreement is only supported for EC and X25519 keys '
        '(got $keyType).',
      );
    }
    if (peerPublicKey.keyType != keyType) {
      throw ArgumentError.value(
        peerPublicKey.keyType,
        'peerPublicKey',
        'Peer key type (${peerPublicKey.keyType}) must match '
            'private key type ($keyType)',
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
        return withSecretOutputBuffer(
          'EVP_PKEY_derive',
          (out, len) => bssl.EVP_PKEY_derive(ctx, out, len),
        );
      },
    );
  }

  /// Derives [length] bytes of key material with [peerPublicKey] using ECDH or
  /// X25519.
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
  /// For Ed25519, [algorithm] must be omitted (`null`). For RSA and ECDSA,
  /// specify the [HashAlgorithm] to use (e.g. [HashAlgorithm.sha256]).
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
  }) {
    _checkNotDisposed();
    if (keyType == KeyType.ed25519 && algorithm != null) {
      throw ArgumentError.value(
        algorithm,
        'algorithm',
        'Ed25519 does not take a separate HashAlgorithm; omit algorithm.',
      );
    }
    if ((keyType == KeyType.rsa || keyType == KeyType.ec) &&
        algorithm == null) {
      throw ArgumentError.notNull('algorithm');
    }
    return withResource(
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
          (out, len) =>
              bssl.EVP_DigestSign(ctx, out, len, dataPtr, data.length),
        );
      }),
    );
  }

  /// Generates a digital signature over a precomputed [digest].
  ///
  /// For Ed25519, precomputed digests are not supported.
  /// For RSA and ECDSA, specify the [HashAlgorithm] used to compute [digest].
  Uint8List signDigest({
    required HashAlgorithm algorithm,
    required Uint8List digest,
    RsaSignaturePadding rsaPadding = RsaSignaturePadding.pkcs1,
    int? pssSaltLength,
  }) {
    _checkNotDisposed();
    if (keyType == KeyType.ed25519) {
      throw UnsupportedError('Ed25519 does not support precomputed digests.');
    }
    return withResource(
      create: () => bssl.EVP_PKEY_CTX_new(_pkey, ffi.nullptr),
      destroy: bssl.EVP_PKEY_CTX_free,
      operation: 'EVP_PKEY_CTX_new',
      body: (ctx) => using((arena) {
        checkBssl(bssl.EVP_PKEY_sign_init(ctx), 'EVP_PKEY_sign_init');
        checkBssl(
          bssl.EVP_PKEY_CTX_set_signature_md(ctx, algorithm.evpMd),
          'EVP_PKEY_CTX_set_signature_md',
        );
        if (keyType == KeyType.rsa) {
          checkBssl(
            bssl.EVP_PKEY_CTX_set_rsa_padding(
              ctx,
              rsaPadding.nativeValue,
            ),
            'EVP_PKEY_CTX_set_rsa_padding',
          );
          if (rsaPadding == RsaSignaturePadding.pss) {
            checkBssl(
              bssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(
                ctx,
                pssSaltLength ?? bssl.RSA_PSS_SALTLEN_DIGEST,
              ),
              'EVP_PKEY_CTX_set_rsa_pss_saltlen',
            );
          }
        }
        final digPtr = copyBytesToNative(digest, arena);
        return withOutputBuffer(
          'EVP_PKEY_sign',
          (out, len) => bssl.EVP_PKEY_sign(
            ctx,
            out,
            len,
            digPtr,
            digest.length,
          ),
        );
      }),
    );
  }

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
    _checkNotDisposed();
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
  /// - [hash] / [algorithm]: Hash algorithm for OAEP and MGF1 (default:
  ///   [HashAlgorithm.sha256]).
  /// - [mgf1Hash]: Hash algorithm for MGF1 (defaults to [hash]).
  /// - [label]: Optional OAEP label/parameter.
  Uint8List decryptOaep({
    required Uint8List ciphertext,
    HashAlgorithm hash = HashAlgorithm.sha256,
    HashAlgorithm? algorithm,
    HashAlgorithm? mgf1Hash,
    Uint8List? label,
  }) {
    _checkNotDisposed();
    if (keyType != KeyType.rsa) {
      throw StateError(
        'RSA-OAEP decryption is only supported for RSA keys (got $keyType).',
      );
    }
    final oaepMd = algorithm ?? hash;
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
          bssl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaepMd.evpMd),
          'EVP_PKEY_CTX_set_rsa_oaep_md',
        );
        checkBssl(
          bssl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, (mgf1Hash ?? oaepMd).evpMd),
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
        return withSecretOutputBuffer(
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
