// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../asn1/asn1.dart';
import '../bindings/boringssl.g.dart' as bssl;
import '../crypto/pkey.dart';
import '../ffi/arena.dart';
import '../ffi/error.dart';
import 'extension.dart';

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

  /// All X.509 v3 extensions present on this certificate, in encoding order.
  List<X509Extension> get extensions {
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
  List<GeneralName> get subjectAlternativeNames =>
      _readGeneralNames(bssl.NID_subject_alt_name);

  /// The certificate's `issuerAltName` entries (RFC 5280, Section 4.2.1.7).
  List<GeneralName> get issuerAlternativeNames =>
      _readGeneralNames(bssl.NID_issuer_alt_name);

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

  /// A bitmask of [KeyUsage] values permitted by the `keyUsage` extension.
  ///
  /// If the certificate has no `keyUsage` extension, all usages are permitted
  /// and every bit is set.
  int get keyUsage => bssl.X509_get_key_usage(_x509);

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
  bool get isCertificateAuthority => bssl.X509_check_ca(_x509) != 0;

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
        try {
          final text = strPtr.cast<Utf8>().toDartString();
          return GeneralName(
            type: type,
            value: text,
            rawValue: Uint8List.fromList(utf8.encode(text)),
          );
        } finally {
          bssl.OPENSSL_free(strPtr.cast());
        }

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
