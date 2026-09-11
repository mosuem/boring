// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'certificate.dart';

/// Result of an X.509 certificate chain verification.
final class X509VerificationResult {
  /// Whether verification succeeded.
  final bool isValid;

  /// Error message if verification failed, or null on success.
  final String? errorMessage;

  /// BoringSSL error code (0 on success).
  final int errorCode;

  const X509VerificationResult._({
    required this.isValid,
    this.errorMessage,
    this.errorCode = 0,
  });

  static const success = X509VerificationResult._(isValid: true);

  factory X509VerificationResult.failure(int errorCode, String message) =>
      X509VerificationResult._(
        isValid: false,
        errorMessage: message,
        errorCode: errorCode,
      );

  @override
  String toString() => isValid
      ? 'X509VerificationResult(valid)'
      : 'X509VerificationResult(invalid: $errorMessage [code: $errorCode])';
}

/// Verifies X.509 certificate chains against trusted root certificates.
final class X509Verifier implements ffi.Finalizable {
  static final _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<bssl.X509_STORE>)>
        >(bssl.X509_STORE_free)
        .cast(),
  );

  final ffi.Pointer<bssl.X509_STORE> _store;

  /// Creates a new verifier with an empty trust store.
  X509Verifier() : _store = bssl.X509_STORE_new() {
    checkPointer(_store, 'X509_STORE_new');
    _finalizer.attach(this, _store.cast(), externalSize: 1024);
  }

  /// Adds a trusted root certificate to this verifier.
  void addTrustedCertificate(X509Certificate certificate) {
    final ret = bssl.X509_STORE_add_cert(_store, certificate.handle);
    checkBssl(ret, 'X509_STORE_add_cert');
  }

  /// Verifies [leaf] certificate against the trusted roots.
  ///
  /// - [intermediates]: Optional list of untrusted intermediate certificates to
  ///   assist chain construction.
  /// - [checkTime]: Optional verification time (useful for verifying
  ///   historical chains or testing expiry). If omitted, current time is used.
  X509VerificationResult verify({
    required X509Certificate leaf,
    List<X509Certificate> intermediates = const [],
    DateTime? checkTime,
  }) => withResource(
    create: bssl.X509_STORE_CTX_new,
    destroy: bssl.X509_STORE_CTX_free,
    operation: 'X509_STORE_CTX_new',
    body: (ctx) {
      ffi.Pointer<bssl.stack_st_X509> chainPtr = ffi.nullptr;
      ffi.Pointer<bssl.OPENSSL_STACK> rawStack = ffi.nullptr;

      if (intermediates.isNotEmpty) {
        rawStack = bssl.OPENSSL_sk_new_null();
        checkPointer(rawStack, 'OPENSSL_sk_new_null');
        for (final inter in intermediates) {
          bssl.OPENSSL_sk_push(rawStack, inter.handle.cast());
        }
        chainPtr = rawStack.cast();
      }

      try {
        final initRet = bssl.X509_STORE_CTX_init(
          ctx,
          _store,
          leaf.handle,
          chainPtr,
        );
        checkBssl(initRet, 'X509_STORE_CTX_init');

        if (checkTime != null) {
          final epochSeconds = checkTime.millisecondsSinceEpoch ~/ 1000;
          bssl.X509_STORE_CTX_set_time_posix(ctx, 0, epochSeconds);
        }

        if (bssl.X509_verify_cert(ctx) == 1) {
          return X509VerificationResult.success;
        }

        final errCode = bssl.X509_STORE_CTX_get_error(ctx);
        // X509_verify_cert_error_string returns a static string; do not free.
        final errStrPtr = bssl.X509_verify_cert_error_string(errCode);
        final message = errStrPtr != ffi.nullptr
            ? errStrPtr.cast<Utf8>().toDartString()
            : 'Unknown X.509 verification error ($errCode)';

        return X509VerificationResult.failure(errCode, message);
      } finally {
        if (rawStack != ffi.nullptr) {
          bssl.OPENSSL_sk_free(rawStack);
        }
      }
    },
  );
}
