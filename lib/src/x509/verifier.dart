// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'certificate.dart';

/// The kind of name a peer certificate is expected to assert.
enum X509PeerNameKind {
  /// A DNS name, matched against `dNSName` subject alternative names.
  dnsName,

  /// A textual IPv4 or IPv6 address, matched against `iPAddress` subject
  /// alternative names.
  ipAddress,

  /// An email address, matched against `rfc822Name` subject alternative names.
  emailAddress,
}

/// A name that a peer certificate is expected to assert.
///
/// Pass instances to [X509Verifier.verify] to have BoringSSL check the peer's
/// identity as part of chain verification.
final class X509PeerName {
  /// The kind of name to match.
  final X509PeerNameKind kind;

  /// The name itself.
  final String value;

  const X509PeerName._(this.kind, this.value);

  /// A DNS name such as `example.com`.
  const X509PeerName.dnsName(String value)
    : this._(X509PeerNameKind.dnsName, value);

  /// A textual IPv4 or IPv6 address such as `127.0.0.1` or `::1`.
  const X509PeerName.ipAddress(String value)
    : this._(X509PeerNameKind.ipAddress, value);

  /// An email address such as `user@example.com`.
  const X509PeerName.emailAddress(String value)
    : this._(X509PeerNameKind.emailAddress, value);

  @override
  bool operator ==(Object other) =>
      other is X509PeerName && other.kind == kind && other.value == value;

  @override
  int get hashCode => Object.hash(kind, value);

  @override
  String toString() => 'X509PeerName.${kind.name}($value)';
}

/// A purpose to validate a certificate chain for.
///
/// Configuring a purpose enables checking of the key usage and extended key
/// usage extensions. BoringSSL applies the extended key usage check to the leaf
/// and to all untrusted intermediates, and the key usage check to the leaf
/// only. `anyExtendedKeyUsage` is not accepted.
enum X509Purpose {
  /// Accepts any purpose. Key usage and extended key usage are not checked.
  any(bssl.X509_PURPOSE_ANY),

  /// A TLS client certificate (`clientAuth`).
  tlsClient(bssl.X509_PURPOSE_SSL_CLIENT),

  /// A TLS server certificate (`serverAuth`).
  tlsServer(bssl.X509_PURPOSE_SSL_SERVER),

  /// A legacy Netscape TLS server certificate.
  netscapeTlsServer(bssl.X509_PURPOSE_NS_SSL_SERVER),

  /// An S/MIME signing certificate.
  smimeSign(bssl.X509_PURPOSE_SMIME_SIGN),

  /// An S/MIME encryption certificate.
  smimeEncrypt(bssl.X509_PURPOSE_SMIME_ENCRYPT),

  /// A CRL signing certificate.
  crlSign(bssl.X509_PURPOSE_CRL_SIGN),

  /// An OCSP responder certificate.
  ocspHelper(bssl.X509_PURPOSE_OCSP_HELPER),

  /// A timestamp signing certificate.
  timestampSign(bssl.X509_PURPOSE_TIMESTAMP_SIGN);

  final int _value;

  const X509Purpose(this._value);
}

/// Options controlling how peer names are matched against a certificate.
enum X509HostnameFlag {
  /// Never fall back to the subject common name.
  ///
  /// BoringSSL's legacy default checks DNS-like values in the subject common
  /// name when the certificate has no subject alternative name extension. This
  /// flag disables that fallback, which is the behaviour required by the CA/B
  /// Forum baseline requirements and by every modern TLS stack.
  neverCheckSubject(bssl.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT),

  /// Disable wildcard matching, so `*.example.com` will not match
  /// `host.example.com`.
  noWildcards(bssl.X509_CHECK_FLAG_NO_WILDCARDS);

  final int _value;

  const X509HostnameFlag(this._value);
}

/// Result of an X.509 certificate chain verification.
final class X509VerificationResult {
  /// Whether verification succeeded.
  final bool isValid;

  /// Error message if verification failed, or null on success.
  final String? errorMessage;

  /// BoringSSL error code (0 on success).
  final int errorCode;

  /// The position in the chain at which the error occurred.
  ///
  /// `0` is the leaf certificate. This is `0` on success.
  final int errorDepth;

  const X509VerificationResult._({
    required this.isValid,
    this.errorMessage,
    this.errorCode = 0,
    this.errorDepth = 0,
  });

  static const success = X509VerificationResult._(isValid: true);

  factory X509VerificationResult.failure(
    int errorCode,
    String message, {
    int errorDepth = 0,
  }) => X509VerificationResult._(
    isValid: false,
    errorMessage: message,
    errorCode: errorCode,
    errorDepth: errorDepth,
  );

  @override
  String toString() => isValid
      ? 'X509VerificationResult(valid)'
      : 'X509VerificationResult(invalid: $errorMessage '
            '[code: $errorCode, depth: $errorDepth])';
}

/// The default peer name matching options.
const _defaultHostnameFlags = {X509HostnameFlag.neverCheckSubject};

/// Signature digests with practical collision attacks.
///
/// BoringSSL's [bssl.X509_verify_cert] happily validates chains signed with
/// these, so [X509Verifier.verify] rejects them itself.
const _weakSignatureDigests = {
  bssl.NID_md4,
  bssl.NID_md5,
  bssl.NID_md5_sha1,
  bssl.NID_sha1,
};

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
  /// - [peerNames]: Names the leaf certificate must assert. Multiple
  ///   [X509PeerNameKind.dnsName] entries are matched with OR semantics: the
  ///   leaf need only assert one of them. Names of *different* kinds are
  ///   matched with AND semantics, since BoringSSL tracks one expected name per
  ///   kind. At most one [X509PeerNameKind.ipAddress] and one
  ///   [X509PeerNameKind.emailAddress] may be given.
  /// - [hostnameFlags]: Options controlling peer name matching. Defaults to
  ///   [X509HostnameFlag.neverCheckSubject]; pass an empty set to re-enable
  ///   BoringSSL's legacy subject common name fallback.
  /// - [purpose]: If non-null, enables key usage and extended key usage checks
  ///   for the given purpose. If null (the default), those extensions are not
  ///   checked and validating them is the caller's responsibility.
  /// - [maxIntermediates]: If non-null, limits the chain to this many
  ///   intermediate certificates, excluding both [leaf] and the trust anchor.
  /// - [insecurelyAllowWeakSignatureDigests]: If true, accepts chains signed
  ///   with MD4, MD5 or SHA-1. These digests have practical collision attacks
  ///   and are rejected by default.
  ///
  /// Throws [ArgumentError] if [peerNames] contains more than one IP address or
  /// more than one email address, or if [maxIntermediates] is negative.
  X509VerificationResult verify({
    required X509Certificate leaf,
    List<X509Certificate> intermediates = const [],
    DateTime? checkTime,
    List<X509PeerName> peerNames = const [],
    Set<X509HostnameFlag> hostnameFlags = _defaultHostnameFlags,
    X509Purpose? purpose,
    int? maxIntermediates,
    bool insecurelyAllowWeakSignatureDigests = false,
  }) {
    if (maxIntermediates != null && maxIntermediates < 0) {
      throw ArgumentError.value(
        maxIntermediates,
        'maxIntermediates',
        'must not be negative',
      );
    }
    return withResource(
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

          final param = bssl.X509_STORE_CTX_get0_param(ctx);
          checkPointer(param, 'X509_STORE_CTX_get0_param');

          if (purpose != null) {
            checkBssl(
              bssl.X509_VERIFY_PARAM_set_purpose(param, purpose._value),
              'X509_VERIFY_PARAM_set_purpose',
            );
          }
          if (maxIntermediates != null) {
            bssl.X509_VERIFY_PARAM_set_depth(param, maxIntermediates);
          }
          if (peerNames.isNotEmpty) {
            bssl.X509_VERIFY_PARAM_set_hostflags(
              param,
              hostnameFlags.fold(0, (bits, flag) => bits | flag._value),
            );
            _applyPeerNames(param, peerNames);
          }

          if (bssl.X509_verify_cert(ctx) == 1) {
            return insecurelyAllowWeakSignatureDigests
                ? X509VerificationResult.success
                : _checkSignatureDigests(ctx);
          }

          final errCode = bssl.X509_STORE_CTX_get_error(ctx);
          // X509_verify_cert_error_string returns a static string; do not free.
          final errStrPtr = bssl.X509_verify_cert_error_string(errCode);
          final message = errStrPtr != ffi.nullptr
              ? errStrPtr.cast<Utf8>().toDartString()
              : 'Unknown X.509 verification error ($errCode)';

          return X509VerificationResult.failure(
            errCode,
            message,
            errorDepth: bssl.X509_STORE_CTX_get_error_depth(ctx),
          );
        } finally {
          if (rawStack != ffi.nullptr) {
            bssl.OPENSSL_sk_free(rawStack);
          }
        }
      },
    );
  }

  /// Rejects a verified chain if any certificate in it was signed with a
  /// digest that has a practical collision attack.
  ///
  /// BoringSSL's `X509_verify_cert` has no signature algorithm policy at all —
  /// it has neither OpenSSL's `X509_VERIFY_PARAM_set_auth_level` nor its
  /// `set1_sigalgs` — so this check has to happen here.
  static X509VerificationResult _checkSignatureDigests(
    ffi.Pointer<bssl.X509_STORE_CTX> ctx,
  ) => using((arena) {
    final chain = checkPointer(
      bssl.X509_STORE_CTX_get0_chain(ctx),
      'X509_STORE_CTX_get0_chain',
    ).cast<bssl.OPENSSL_STACK>();
    final digestNid = arena<ffi.Int>();

    // The chain runs from the leaf to the trust anchor. The anchor's own
    // signature is never verified — it is trusted by virtue of being in the
    // store, not by virtue of its self-signature — so its digest is
    // irrelevant and the last element is skipped.
    final length = bssl.OPENSSL_sk_num(chain);
    for (var depth = 0; depth < length - 1; depth++) {
      final cert = bssl.OPENSSL_sk_value(chain, depth).cast<bssl.X509>();
      final signatureNid = bssl.X509_get_signature_nid(cert);
      // Signature algorithms without a separate digest, such as Ed25519, have
      // no cross-reference entry. Those are never weak, so leave them be.
      if (bssl.OBJ_find_sigid_algs(signatureNid, digestNid, ffi.nullptr) != 1) {
        continue;
      }
      if (!_weakSignatureDigests.contains(digestNid.value)) continue;

      final namePtr = bssl.OBJ_nid2sn(signatureNid);
      final name = namePtr != ffi.nullptr
          ? namePtr.cast<Utf8>().toDartString()
          : 'NID $signatureNid';
      return X509VerificationResult.failure(
        bssl.X509_V_ERR_APPLICATION_VERIFICATION,
        'certificate signed with the weak algorithm $name; pass '
        'insecurelyAllowWeakSignatureDigests to accept it anyway',
        errorDepth: depth,
      );
    }
    return X509VerificationResult.success;
  });

  /// Configures the expected peer names on [param].
  static void _applyPeerNames(
    ffi.Pointer<bssl.X509_VERIFY_PARAM> param,
    List<X509PeerName> peerNames,
  ) => using((arena) {
    var haveDnsName = false;
    var haveIpAddress = false;
    var haveEmailAddress = false;

    for (final name in peerNames) {
      final cName = name.value.toNativeUtf8(allocator: arena);
      final int ret;
      switch (name.kind) {
        case X509PeerNameKind.dnsName:
          // The first name replaces any previous configuration; subsequent
          // ones are appended, and BoringSSL accepts a match against any.
          ret = haveDnsName
              ? bssl.X509_VERIFY_PARAM_add1_host(
                  param,
                  cName.cast(),
                  cName.length,
                )
              : bssl.X509_VERIFY_PARAM_set1_host(
                  param,
                  cName.cast(),
                  cName.length,
                );
          haveDnsName = true;
        case X509PeerNameKind.ipAddress:
          if (haveIpAddress) {
            throw ArgumentError.value(
              peerNames,
              'peerNames',
              'must not contain more than one IP address',
            );
          }
          haveIpAddress = true;
          ret = bssl.X509_VERIFY_PARAM_set1_ip_asc(param, cName.cast());
        case X509PeerNameKind.emailAddress:
          if (haveEmailAddress) {
            throw ArgumentError.value(
              peerNames,
              'peerNames',
              'must not contain more than one email address',
            );
          }
          haveEmailAddress = true;
          ret = bssl.X509_VERIFY_PARAM_set1_email(
            param,
            cName.cast(),
            cName.length,
          );
      }
      checkBssl(ret, 'configuring expected peer name ${name.value}');
    }
  });
}
