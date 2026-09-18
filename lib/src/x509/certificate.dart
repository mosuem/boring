// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../asn1/asn1.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../crypto/digest.dart';
import '../crypto/pkey.dart';
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'extension.dart';

DateTime _parseAsn1Time(ffi.Pointer<bssl.ASN1_TIME> timePtr) {
  if (timePtr == ffi.nullptr) {
    throw BoringSslException('ASN1_TIME pointer is null');
  }
  return using((arena) {
    final seconds = arena<ffi.Int64>();
    checkBssl(bssl.ASN1_TIME_to_posix(timePtr, seconds), 'ASN1_TIME_to_posix');
    return DateTime.fromMillisecondsSinceEpoch(
      seconds.value * 1000,
      isUtc: true,
    );
  });
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
  bool _disposed = false;

  X509Certificate._(this._x509) {
    _finalizer.attach(this, _x509.cast(), externalSize: 1024);
  }

  void _checkNotDisposed() {
    if (_disposed) {
      throw StateError('X509Certificate has already been disposed');
    }
  }

  /// Deterministically frees the underlying native `X509` handle.
  ///
  /// Safe to call multiple times; subsequent calls are no-ops.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _finalizer.detach(this);
    bssl.X509_free(_x509);
  }

  /// Internal handle for verifier operations.
  ffi.Pointer<bssl.X509> get handle {
    _checkNotDisposed();
    return _x509;
  }

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
  factory X509Certificate.fromPem(String pem) => withMemBufBio(
    Uint8List.fromList(utf8.encode(pem)),
    (bio) {
      final x509 = bssl.PEM_read_bio_X509(
        bio,
        ffi.nullptr,
        ffi.nullptr,
        ffi.nullptr,
      );
      checkPointer(x509, 'PEM_read_bio_X509');
      return X509Certificate._(x509);
    },
  );

  /// Parses one or more PEM-encoded certificates from [pem].
  static List<X509Certificate> parseChainPem(String pem) => withMemBufBio(
    Uint8List.fromList(utf8.encode(pem)),
    (bio) {
      final results = <X509Certificate>[];
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
      return results;
    },
  );

  /// Exports this certificate as DER bytes.
  Uint8List toDer() {
    _checkNotDisposed();
    return using((arena) {
      final len = bssl.i2d_X509(_x509, ffi.nullptr);
      checkBssl(len > 0 ? 1 : 0, 'i2d_X509');
      final buffer = arena<ffi.Uint8>(len);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>()..value = buffer;
      final written = bssl.i2d_X509(_x509, outPtr);
      checkBssl(written > 0 ? 1 : 0, 'i2d_X509');
      return Uint8List.fromList(buffer.asTypedList(written));
    });
  }

  /// Exports this certificate as PEM string (`-----BEGIN CERTIFICATE-----`).
  String toPem() {
    _checkNotDisposed();
    return withMemBioString(
      'PEM_write_bio_X509',
      (bio) => bssl.PEM_write_bio_X509(bio, _x509),
    );
  }

  /// The 32-byte SHA-256 fingerprint over this certificate's DER encoding.
  Uint8List get sha256Fingerprint => BoringDigest.sha256(toDer());

  /// Certificate version (1, 2, or 3).
  int get version {
    _checkNotDisposed();
    return bssl.X509_get_version(_x509) + 1;
  }

  /// Certificate serial number.
  BigInt get serialNumber {
    _checkNotDisposed();
    final serialAsn1 = bssl.X509_get0_serialNumber(_x509);
    checkPointer(serialAsn1, 'X509_get0_serialNumber');
    return withResource(
      create: () => bssl.ASN1_INTEGER_to_BN(serialAsn1, ffi.nullptr),
      destroy: bssl.BN_free,
      operation: 'ASN1_INTEGER_to_BN',
      body: (bn) => BigInt.parse(
        takeOwnedString(bssl.BN_bn2hex(bn), 'BN_bn2hex'),
        radix: 16,
      ),
    );
  }

  /// Subject distinguished name in one-line format.
  String get subject {
    _checkNotDisposed();
    final name = bssl.X509_get_subject_name(_x509);
    checkPointer(name, 'X509_get_subject_name');
    return takeOwnedString(
      bssl.X509_NAME_oneline(name, ffi.nullptr, 0),
      'X509_NAME_oneline',
    );
  }

  /// Issuer distinguished name in one-line format.
  String get issuer {
    _checkNotDisposed();
    final name = bssl.X509_get_issuer_name(_x509);
    checkPointer(name, 'X509_get_issuer_name');
    return takeOwnedString(
      bssl.X509_NAME_oneline(name, ffi.nullptr, 0),
      'X509_NAME_oneline',
    );
  }

  /// Not Before validity timestamp (UTC).
  DateTime get notBefore {
    _checkNotDisposed();
    return _parseAsn1Time(bssl.X509_get0_notBefore(_x509));
  }

  /// Not After validity timestamp (UTC).
  DateTime get notAfter {
    _checkNotDisposed();
    return _parseAsn1Time(bssl.X509_get0_notAfter(_x509));
  }

  /// Extracts the certificate's public key.
  BoringPublicKey get publicKey {
    _checkNotDisposed();
    final pkey = bssl.X509_get_pubkey(_x509);
    checkPointer(pkey, 'X509_get_pubkey');
    return BoringPublicKey.fromHandle(pkey);
  }

  /// Verifies that this certificate was signed by [issuerPublicKey].
  bool verifySignature(BoringPublicKey issuerPublicKey) {
    _checkNotDisposed();
    final ret = bssl.X509_verify(_x509, issuerPublicKey.handle);
    if (ret != 1) {
      drainErrorQueue();
      return false;
    }
    return true;
  }

  /// All X.509 v3 extensions present on this certificate, in encoding order.
  List<X509Extension> get extensions {
    _checkNotDisposed();
    final count = bssl.X509_get_ext_count(_x509);
    final result = <X509Extension>[];
    for (var i = 0; i < count; i++) {
      final ext = bssl.X509_get_ext(_x509, i);
      if (ext == ffi.nullptr) continue;
      result.add(_toExtension(ext));
    }
    return result;
  }

  /// Returns the extension identified by the dotted-decimal [oid], or `null`
  /// if this certificate does not carry it.
  ///
  /// ```dart
  /// final issuer = cert.getExtension(X509Oid.fulcioIssuerV1);
  /// print(issuer?.stringValue); // https://token.actions.githubusercontent.com
  /// ```
  X509Extension? getExtension(String oid) {
    _checkNotDisposed();
    return using((arena) {
      final oidPtr = oid.toNativeUtf8(allocator: arena);
      final obj = bssl.OBJ_txt2obj(oidPtr.cast(), 1);
      if (obj == ffi.nullptr) {
        bssl.ERR_clear_error();
        return null;
      }
      try {
        final index = bssl.X509_get_ext_by_OBJ(_x509, obj, -1);
        if (index < 0) return null;
        final ext = bssl.X509_get_ext(_x509, index);
        if (ext == ffi.nullptr) return null;
        return _toExtension(ext);
      } finally {
        bssl.ASN1_OBJECT_free(obj);
      }
    });
  }

  /// Returns the decoded string contents of the extension identified by [oid],
  /// or `null` if the extension is absent or is not a string.
  ///
  /// This handles both DER-wrapped ASN.1 strings and raw UTF-8 payloads. See
  /// [X509Extension.stringValue].
  String? getExtensionString(String oid) => getExtension(oid)?.stringValue;

  /// The certificate's `subjectAltName` entries (RFC 5280, Section 4.2.1.6).
  ///
  /// Returns an empty list if the certificate has no `subjectAltName`
  /// extension. Sigstore certificates carry the signer identity here, either
  /// as an email address ([GeneralNameType.rfc822Name]) or as a workflow URI
  /// ([GeneralNameType.uniformResourceIdentifier]).
  List<GeneralName> get subjectAlternativeNames {
    _checkNotDisposed();
    return _readGeneralNames(bssl.NID_subject_alt_name);
  }

  /// The certificate's `issuerAltName` entries (RFC 5280, Section 4.2.1.7).
  List<GeneralName> get issuerAlternativeNames {
    _checkNotDisposed();
    return _readGeneralNames(bssl.NID_issuer_alt_name);
  }

  /// The email addresses listed in `subjectAltName`.
  List<String> get emailAddresses => [
    for (final name in subjectAlternativeNames)
      if (name.type == GeneralNameType.rfc822Name) name.value,
  ];

  /// The DNS names listed in `subjectAltName`.
  List<String> get dnsNames => [
    for (final name in subjectAlternativeNames)
      if (name.type == GeneralNameType.dnsName) name.value,
  ];

  /// The URIs listed in `subjectAltName`.
  List<String> get uris => [
    for (final name in subjectAlternativeNames)
      if (name.type == GeneralNameType.uniformResourceIdentifier) name.value,
  ];

  /// A bitmask of [KeyUsage] values permitted by the `keyUsage` extension,
  /// or `null` if this certificate does not carry a `keyUsage` extension.
  int? get keyUsage {
    _checkNotDisposed();
    if (getExtension(X509Oid.keyUsage) == null) return null;
    return bssl.X509_get_key_usage(_x509);
  }

  /// The dotted-decimal OIDs listed in the `extKeyUsage` extension.
  ///
  /// Returns an empty list if the extension is absent, meaning the certificate
  /// is not restricted to particular purposes. Sigstore leaf certificates
  /// carry `1.3.6.1.5.5.7.3.3` (`codeSigning`).
  List<String> get extendedKeyUsage {
    final ext = getExtension(X509Oid.extendedKeyUsage);
    if (ext == null) return const [];
    final parsed = ext.asn1;
    if (parsed == null || !parsed.isConstructed) return const [];
    return [
      for (final child in parsed.children)
        if (child.hasUniversalTag(Asn1Tag.objectIdentifier))
          child.asObjectIdentifier(),
    ];
  }

  /// Whether this certificate may act as a certificate authority, according to
  /// its `basicConstraints` and `keyUsage` extensions.
  bool get isCertificateAuthority {
    _checkNotDisposed();
    return bssl.X509_check_ca(_x509) != 0;
  }

  /// The OID of the algorithm this certificate's signature was produced with,
  /// for example `1.2.840.10045.4.3.2` for `ecdsa-with-SHA256`.
  ///
  /// Chain verification applies no signature algorithm policy: BoringSSL's
  /// `X509_verify_cert` will accept a chain signed with, say, SHA-1. Inspect
  /// this on every certificate in a chain if you need to reject weak
  /// algorithms.
  String get signatureAlgorithm =>
      _objectToText(_signatureAlgorithmObject, alwaysNumeric: true);

  /// The short name of [signatureAlgorithm], for example `ecdsa-with-SHA256`.
  ///
  /// Falls back to the OID when BoringSSL does not recognise the algorithm.
  String get signatureAlgorithmName =>
      _objectToText(_signatureAlgorithmObject, alwaysNumeric: false);

  ffi.Pointer<bssl.ASN1_OBJECT> get _signatureAlgorithmObject {
    _checkNotDisposed();
    final algorithm = bssl.X509_get0_tbs_sigalg(_x509);
    checkPointer(algorithm, 'X509_get0_tbs_sigalg');
    return using((arena) {
      final out = arena<ffi.Pointer<bssl.ASN1_OBJECT>>();
      bssl.X509_ALGOR_get0(out, ffi.nullptr, ffi.nullptr, algorithm);
      return checkPointer(out.value, 'X509_ALGOR_get0');
    });
  }

  /// The raw bytes of the `subjectKeyIdentifier` extension, or `null` if the
  /// certificate does not carry one.
  Uint8List? get subjectKeyIdentifier {
    final ext = getExtension(X509Oid.subjectKeyIdentifier);
    if (ext == null) return null;
    final parsed = ext.asn1;
    if (parsed != null && parsed.hasUniversalTag(Asn1Tag.octetString)) {
      return Uint8List.fromList(parsed.contents);
    }
    return ext.value;
  }

  /// The raw `keyIdentifier` bytes of the `authorityKeyIdentifier` extension
  /// (RFC 5280, Section 4.2.1.1), or `null` if the certificate does not carry
  /// one or omits the `keyIdentifier` field.
  Uint8List? get authorityKeyIdentifier {
    final ext = getExtension(X509Oid.authorityKeyIdentifier);
    if (ext == null) return null;
    final parsed = ext.asn1;
    if (parsed == null || !parsed.isConstructed) return null;
    for (final child in parsed.children) {
      if (child.tagClass == Asn1Class.contextSpecific && child.tagNumber == 0) {
        return Uint8List.fromList(child.contents);
      }
    }
    return null;
  }

  X509Extension _toExtension(ffi.Pointer<bssl.X509_EXTENSION> ext) {
    final obj = bssl.X509_EXTENSION_get_object(ext);
    checkPointer(obj, 'X509_EXTENSION_get_object');
    final data = bssl.X509_EXTENSION_get_data(ext);
    checkPointer(data, 'X509_EXTENSION_get_data');

    final length = bssl.ASN1_STRING_length(data);
    final bytes = bssl.ASN1_STRING_get0_data(data);
    final value = length > 0
        ? Uint8List.fromList(bytes.cast<ffi.Uint8>().asTypedList(length))
        : Uint8List(0);

    return X509Extension(
      oid: _objectToText(obj, alwaysNumeric: true),
      shortName: _objectToText(obj, alwaysNumeric: false),
      isCritical: bssl.X509_EXTENSION_get_critical(ext) == 1,
      value: value,
    );
  }

  String _objectToText(
    ffi.Pointer<bssl.ASN1_OBJECT> obj, {
    required bool alwaysNumeric,
  }) {
    return using((arena) {
      const bufferLength = 256;
      final buffer = arena<ffi.Char>(bufferLength);
      final written = bssl.OBJ_obj2txt(
        buffer,
        bufferLength,
        obj,
        alwaysNumeric ? 1 : 0,
      );
      if (written <= 0) {
        bssl.ERR_clear_error();
        return '';
      }
      return buffer.cast<Utf8>().toDartString();
    });
  }

  List<GeneralName> _readGeneralNames(int nid) {
    final raw = bssl.X509_get_ext_d2i(_x509, nid, ffi.nullptr, ffi.nullptr);
    if (raw == ffi.nullptr) {
      bssl.ERR_clear_error();
      return const [];
    }

    final names = raw.cast<bssl.GENERAL_NAMES>();
    try {
      final stack = names.cast<bssl.OPENSSL_STACK>();
      final count = bssl.OPENSSL_sk_num(stack);
      final result = <GeneralName>[];
      for (var i = 0; i < count; i++) {
        final entry = bssl.OPENSSL_sk_value(stack, i);
        if (entry == ffi.nullptr) continue;
        final name = _decodeGeneralName(entry.cast<bssl.GENERAL_NAME>());
        if (name != null) result.add(name);
      }
      return result;
    } finally {
      bssl.GENERAL_NAMES_free(names);
    }
  }

  GeneralName? _decodeGeneralName(ffi.Pointer<bssl.GENERAL_NAME> namePtr) {
    final type = GeneralNameType.fromTag(namePtr.ref.type);
    if (type == null) return null;

    Uint8List readAsn1String(ffi.Pointer<bssl.ASN1_STRING> str) {
      if (str == ffi.nullptr) return Uint8List(0);
      final length = bssl.ASN1_STRING_length(str);
      if (length <= 0) return Uint8List(0);
      final data = bssl.ASN1_STRING_get0_data(str);
      return Uint8List.fromList(data.cast<ffi.Uint8>().asTypedList(length));
    }

    switch (type) {
      case GeneralNameType.rfc822Name:
      case GeneralNameType.dnsName:
      case GeneralNameType.uniformResourceIdentifier:
        final raw = readAsn1String(namePtr.ref.d.ia5);
        return GeneralName(
          type: type,
          value: utf8.decode(raw, allowMalformed: true),
          rawValue: raw,
        );

      case GeneralNameType.ipAddress:
        final raw = readAsn1String(namePtr.ref.d.iPAddress);
        return GeneralName(
          type: type,
          value: _formatIpAddress(raw),
          rawValue: raw,
        );

      case GeneralNameType.directoryName:
        final dirName = namePtr.ref.d.directoryName;
        if (dirName == ffi.nullptr) return null;
        final strPtr = bssl.X509_NAME_oneline(dirName, ffi.nullptr, 0);
        if (strPtr == ffi.nullptr) {
          bssl.ERR_clear_error();
          return null;
        }
        final text = takeOwnedString(strPtr, 'X509_NAME_oneline');
        return GeneralName(
          type: type,
          value: text,
          rawValue: Uint8List.fromList(utf8.encode(text)),
        );

      case GeneralNameType.registeredId:
        final rid = namePtr.ref.d.registeredID;
        if (rid == ffi.nullptr) return null;
        final text = _objectToText(rid, alwaysNumeric: true);
        return GeneralName(
          type: type,
          value: text,
          rawValue: Uint8List.fromList(utf8.encode(text)),
        );

      case GeneralNameType.otherName:
      case GeneralNameType.x400Address:
      case GeneralNameType.ediPartyName:
        // These forms have no canonical textual rendering; expose them by type
        // only so that callers can still enumerate every SAN entry.
        return GeneralName(
          type: type,
          value: '',
          rawValue: Uint8List(0),
        );
    }
  }

  static String _formatIpAddress(Uint8List bytes) {
    if (bytes.length == 4) {
      return bytes.join('.');
    }
    if (bytes.length == 16) {
      final groups = <String>[];
      for (var i = 0; i < 16; i += 2) {
        groups.add(
          ((bytes[i] << 8) | bytes[i + 1]).toRadixString(16),
        );
      }
      return groups.join(':');
    }
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
