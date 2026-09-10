// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../crypto/pkey.dart';
import '../ffi/arena.dart';
import '../ffi/error.dart';

DateTime _parseAsn1Time(ffi.Pointer<bssl.ASN1_TIME> timePtr) {
  if (timePtr == ffi.nullptr) {
    throw BoringSslException('ASN1_TIME pointer is null');
  }
  final genTime = bssl.ASN1_TIME_to_generalizedtime(timePtr, ffi.nullptr);
  checkPointer(genTime, 'ASN1_TIME_to_generalizedtime');
  try {
    final len = bssl.ASN1_STRING_length(genTime.cast());
    final data = bssl.ASN1_STRING_get0_data(genTime.cast());
    final str = utf8.decode(data.cast<ffi.Uint8>().asTypedList(len));
    final year = int.parse(str.substring(0, 4));
    final month = int.parse(str.substring(4, 6));
    final day = int.parse(str.substring(6, 8));
    final hour = int.parse(str.substring(8, 10));
    final minute = int.parse(str.substring(10, 12));
    final second = int.parse(str.substring(12, 14));
    return DateTime.utc(year, month, day, hour, minute, second);
  } finally {
    bssl.ASN1_GENERALIZEDTIME_free(genTime);
  }
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

/// An X.509 Certificate (RFC 5280).
final class X509Certificate implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.X509>)>
        >(bssl.X509_free)
        .cast(),
  );

  final ffi.Pointer<bssl.X509> _x509;

  X509Certificate._(this._x509) {
    _finalizer.attach(this, _x509.cast(), externalSize: 1024);
  }

  /// Internal handle for verifier operations.
  ffi.Pointer<bssl.X509> get handle => _x509;

  /// Parses a DER-encoded X.509 certificate.
  factory X509Certificate.fromDer(Uint8List der) {
    return using((arena) {
      final buffer = copyBytesToNative(der, arena);
      final inpPtr = arena<ffi.Pointer<ffi.Uint8>>();
      inpPtr.value = buffer;
      final x509 = bssl.d2i_X509(ffi.nullptr, inpPtr, der.length);
      checkPointer(x509, 'd2i_X509');
      return X509Certificate._(x509);
    });
  }

  /// Parses a PEM-encoded X.509 certificate (`-----BEGIN CERTIFICATE-----`).
  factory X509Certificate.fromPem(String pem) {
    final pemBytes = utf8.encode(pem);
    return using((arena) {
      final buffer = copyBytesToNative(Uint8List.fromList(pemBytes), arena);
      final bio = bssl.BIO_new_mem_buf(buffer.cast(), pemBytes.length);
      checkPointer(bio, 'BIO_new_mem_buf');
      try {
        final x509 = bssl.PEM_read_bio_X509(
          bio,
          ffi.nullptr,
          ffi.nullptr,
          ffi.nullptr,
        );
        checkPointer(x509, 'PEM_read_bio_X509');
        return X509Certificate._(x509);
      } finally {
        bssl.BIO_free(bio);
      }
    });
  }

  /// Parses one or more PEM-encoded certificates from [pem].
  static List<X509Certificate> parseChainPem(String pem) {
    final pemBytes = utf8.encode(pem);
    final results = <X509Certificate>[];
    using((arena) {
      final buffer = copyBytesToNative(Uint8List.fromList(pemBytes), arena);
      final bio = bssl.BIO_new_mem_buf(buffer.cast(), pemBytes.length);
      checkPointer(bio, 'BIO_new_mem_buf');
      try {
        while (true) {
          final x509 = bssl.PEM_read_bio_X509(
            bio,
            ffi.nullptr,
            ffi.nullptr,
            ffi.nullptr,
          );
          if (x509 == ffi.nullptr) {
            bssl.ERR_clear_error();
            break;
          }
          results.add(X509Certificate._(x509));
        }
      } finally {
        bssl.BIO_free(bio);
      }
    });
    return results;
  }

  /// Exports this certificate as DER bytes.
  Uint8List toDer() {
    final len = bssl.i2d_X509(_x509, ffi.nullptr);
    if (len <= 0) {
      checkBssl(0, 'i2d_X509');
    }
    return using((arena) {
      final buffer = arena<ffi.Uint8>(len);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      outPtr.value = buffer;
      final written = bssl.i2d_X509(_x509, outPtr);
      checkBssl(written > 0 ? 1 : 0, 'i2d_X509');
      return Uint8List.fromList(buffer.asTypedList(written));
    });
  }

  /// Exports this certificate as PEM string (`-----BEGIN CERTIFICATE-----`).
  String toPem() {
    final memMethod = bssl.BIO_s_mem();
    final bio = bssl.BIO_new(memMethod);
    checkPointer(bio, 'BIO_new');
    try {
      final ret = bssl.PEM_write_bio_X509(bio, _x509);
      checkBssl(ret, 'PEM_write_bio_X509');
      return _readBioString(bio);
    } finally {
      bssl.BIO_free(bio);
    }
  }

  /// Certificate version (1, 2, or 3).
  int get version => bssl.X509_get_version(_x509) + 1;

  /// Certificate serial number.
  BigInt get serialNumber {
    final serialAsn1 = bssl.X509_get0_serialNumber(_x509);
    checkPointer(serialAsn1, 'X509_get0_serialNumber');
    final bn = bssl.ASN1_INTEGER_to_BN(serialAsn1, ffi.nullptr);
    checkPointer(bn, 'ASN1_INTEGER_to_BN');
    try {
      final hexPtr = bssl.BN_bn2hex(bn);
      checkPointer(hexPtr, 'BN_bn2hex');
      try {
        final hexStr = hexPtr.cast<Utf8>().toDartString();
        return BigInt.parse(hexStr, radix: 16);
      } finally {
        bssl.OPENSSL_free(hexPtr.cast());
      }
    } finally {
      bssl.BN_free(bn);
    }
  }

  /// Subject distinguished name in one-line format.
  String get subject {
    final name = bssl.X509_get_subject_name(_x509);
    checkPointer(name, 'X509_get_subject_name');
    final strPtr = bssl.X509_NAME_oneline(name, ffi.nullptr, 0);
    checkPointer(strPtr, 'X509_NAME_oneline');
    try {
      return strPtr.cast<Utf8>().toDartString();
    } finally {
      bssl.OPENSSL_free(strPtr.cast());
    }
  }

  /// Issuer distinguished name in one-line format.
  String get issuer {
    final name = bssl.X509_get_issuer_name(_x509);
    checkPointer(name, 'X509_get_issuer_name');
    final strPtr = bssl.X509_NAME_oneline(name, ffi.nullptr, 0);
    checkPointer(strPtr, 'X509_NAME_oneline');
    try {
      return strPtr.cast<Utf8>().toDartString();
    } finally {
      bssl.OPENSSL_free(strPtr.cast());
    }
  }

  /// Not Before validity timestamp (UTC).
  DateTime get notBefore => _parseAsn1Time(bssl.X509_get0_notBefore(_x509));

  /// Not After validity timestamp (UTC).
  DateTime get notAfter => _parseAsn1Time(bssl.X509_get0_notAfter(_x509));

  /// Extracts the certificate's public key.
  BoringPublicKey get publicKey {
    final pkey = bssl.X509_get_pubkey(_x509);
    checkPointer(pkey, 'X509_get_pubkey');
    return BoringPublicKey.fromHandle(pkey);
  }

  /// Verifies that this certificate was signed by [issuerPublicKey].
  bool verifySignature(BoringPublicKey issuerPublicKey) {
    final ret = bssl.X509_verify(_x509, issuerPublicKey.handle);
    return ret == 1;
  }
}
