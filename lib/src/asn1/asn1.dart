// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';

/// Thrown when ASN.1 DER data is malformed or cannot be decoded.
final class Asn1Exception implements Exception {
  /// Human-readable description of the parse failure.
  final String message;

  /// Byte offset within the input where the failure was detected.
  final int offset;

  /// Creates an [Asn1Exception] describing a parse failure.
  const Asn1Exception(this.message, {this.offset = 0});

  @override
  String toString() => 'Asn1Exception: $message (at offset $offset)';
}

/// The class of an ASN.1 tag (X.690, Section 8.1.2.2).
enum Asn1Class {
  /// Types defined by the ASN.1 standard itself (e.g. `INTEGER`, `UTF8String`).
  universal(bssl.CBS_ASN1_UNIVERSAL),

  /// Types whose interpretation depends on the containing structure.
  application(bssl.CBS_ASN1_APPLICATION),

  /// Types whose interpretation depends on the context they appear in, used
  /// for `CHOICE` alternatives such as X.509 `GeneralName`.
  contextSpecific(bssl.CBS_ASN1_CONTEXT_SPECIFIC),

  /// Types defined by private, enterprise-specific specifications.
  private(bssl.CBS_ASN1_PRIVATE);

  const Asn1Class(this.bits);

  /// BoringSSL's `CBS_ASN1_*` class bits for this class.
  final int bits;
}

/// ASN.1 universal tag numbers (X.680) needed to interpret X.509 structures.
///
/// These are BoringSSL's `CBS_ASN1_*` tag values re-exported under
/// Dart-idiomatic names.
abstract final class Asn1Tag {
  /// `BOOLEAN`.
  static const int boolean = bssl.CBS_ASN1_BOOLEAN;

  /// `INTEGER`.
  static const int integer = bssl.CBS_ASN1_INTEGER;

  /// `BIT STRING`.
  static const int bitString = bssl.CBS_ASN1_BITSTRING;

  /// `OCTET STRING`.
  static const int octetString = bssl.CBS_ASN1_OCTETSTRING;

  /// `NULL`.
  static const int null_ = bssl.CBS_ASN1_NULL;

  /// `OBJECT IDENTIFIER`.
  static const int objectIdentifier = bssl.CBS_ASN1_OBJECT;

  /// `UTF8String`.
  static const int utf8String = bssl.CBS_ASN1_UTF8STRING;

  /// `PrintableString`.
  static const int printableString = bssl.CBS_ASN1_PRINTABLESTRING;

  /// `TeletexString` (also known as `T61String`).
  static const int teletexString = bssl.CBS_ASN1_T61STRING;

  /// `IA5String`.
  static const int ia5String = bssl.CBS_ASN1_IA5STRING;

  /// `UTCTime`.
  static const int utcTime = bssl.CBS_ASN1_UTCTIME;

  /// `GeneralizedTime`.
  static const int generalizedTime = bssl.CBS_ASN1_GENERALIZEDTIME;

  /// `VisibleString`.
  static const int visibleString = bssl.CBS_ASN1_VISIBLESTRING;

  /// `BMPString`.
  static const int bmpString = bssl.CBS_ASN1_BMPSTRING;

  /// `SEQUENCE` / `SEQUENCE OF`.
  static const int sequence =
      bssl.CBS_ASN1_SEQUENCE & bssl.CBS_ASN1_TAG_NUMBER_MASK;

  /// `SET` / `SET OF`.
  static const int set = bssl.CBS_ASN1_SET & bssl.CBS_ASN1_TAG_NUMBER_MASK;
}

/// A single parsed ASN.1 DER element (a tag-length-value triple).
final class Asn1Value {
  /// BoringSSL's `CBS_ASN1_TAG` for this element.
  ///
  /// This packs the tag class, the constructed bit, and the tag number into a
  /// single 32-bit value. Prefer [tagClass], [isConstructed], and [tagNumber]
  /// over inspecting this directly.
  final int tag;

  /// The raw contents of this element, excluding tag and length octets.
  final Uint8List contents;

  const Asn1Value._(this.tag, this.contents);

  /// The tag class encoded in [tag].
  Asn1Class get tagClass => switch (tag & bssl.CBS_ASN1_CLASS_MASK) {
    bssl.CBS_ASN1_UNIVERSAL => Asn1Class.universal,
    bssl.CBS_ASN1_APPLICATION => Asn1Class.application,
    bssl.CBS_ASN1_CONTEXT_SPECIFIC => Asn1Class.contextSpecific,
    _ => Asn1Class.private,
  };

  /// Whether this element is constructed (contains nested elements).
  bool get isConstructed => (tag & bssl.CBS_ASN1_CONSTRUCTED) != 0;

  /// The tag number with the class and constructed bits masked off.
  int get tagNumber => tag & bssl.CBS_ASN1_TAG_NUMBER_MASK;

  /// Whether this element is a universal type with the given [tag].
  bool hasUniversalTag(int tag) =>
      tagClass == Asn1Class.universal && tagNumber == tag;

  /// Decodes [contents] as text using BoringSSL's `ASN1_STRING_to_UTF8`.
  ///
  /// This handles every ASN.1 string type BoringSSL knows about, including the
  /// UTF-16BE transcoding required for `BMPString` and the Latin-1 transcoding
  /// required for `TeletexString`.
  ///
  /// For universal tags the string type is taken from [tagNumber]. For
  /// IMPLICIT context-specific tags — such as the `GeneralName` alternatives in
  /// an X.509 `SubjectAltName` — the tag number identifies the CHOICE
  /// alternative rather than the string type, so the underlying type is assumed
  /// to be `UTF8String` unless [stringType] is given. Pass one of the
  /// [Asn1Tag] string constants to override it.
  String asString({int? stringType}) {
    if (isConstructed) {
      throw const Asn1Exception('Constructed element is not a valid string');
    }
    return withResource(
      // ASN1_STRING_to_UTF8 dispatches on the ASN1_STRING's type field, which
      // uses the same numbering as universal ASN.1 tags.
      create: () => bssl.ASN1_STRING_type_new(
        stringType ??
            (tagClass == Asn1Class.universal ? tagNumber : Asn1Tag.utf8String),
      ),
      destroy: bssl.ASN1_STRING_free,
      operation: 'ASN1_STRING_type_new',
      body: (str) => using((arena) {
        final buf = arena<ffi.Uint8>(contents.isEmpty ? 1 : contents.length);
        buf.asTypedList(contents.length).setAll(0, contents);
        if (bssl.ASN1_STRING_set(str.cast(), buf.cast(), contents.length) !=
            1) {
          drainErrorQueue();
          throw const Asn1Exception('Failed to load ASN.1 string contents');
        }
        final out = arena<ffi.Pointer<ffi.UnsignedChar>>();
        final length = bssl.ASN1_STRING_to_UTF8(out, str);
        if (length < 0) {
          drainErrorQueue();
          throw const Asn1Exception('Value is not a decodable ASN.1 string');
        }
        try {
          return utf8.decode(out.value.cast<ffi.Uint8>().asTypedList(length));
        } on FormatException {
          throw const Asn1Exception('Value is not valid UTF-8');
        } finally {
          bssl.OPENSSL_free(out.value.cast());
        }
      }),
    );
  }

  /// Decodes [contents] as a signed big-endian `INTEGER`.
  ///
  /// Validation and sign handling are performed by BoringSSL.
  BigInt asInteger() => using((arena) {
    if (isConstructed) {
      throw const Asn1Exception('Value is not a valid ASN.1 INTEGER');
    }
    final cbs = _cbsFor(contents, arena);
    final isNegative = arena<ffi.Int>();
    if (bssl.CBS_is_valid_asn1_integer(cbs, isNegative) != 1) {
      throw const Asn1Exception('Value is not a valid ASN.1 INTEGER');
    }
    return withResource(
      create: () => bssl.BN_bin2bn(cbs.ref.data, cbs.ref.len, ffi.nullptr),
      destroy: bssl.BN_free,
      operation: 'BN_bin2bn',
      body: (bn) {
        final magnitude = BigInt.parse(
          takeOwnedString(bssl.BN_bn2dec(bn), 'BN_bn2dec'),
        );
        if (isNegative.value == 0) return magnitude;
        // DER encodes negatives in two's complement over the same width.
        return magnitude - (BigInt.one << (contents.length * 8));
      },
    );
  });

  /// Decodes [contents] as a `BOOLEAN`.
  bool asBoolean() => using((arena) {
    if (isConstructed || contents.length != 1) {
      throw const Asn1Exception('Value is not a valid ASN.1 BOOLEAN');
    }
    // CBS_get_asn1_bool parses a full TLV, so re-wrap the contents.
    final der = Uint8List(2 + contents.length)
      ..[0] = Asn1Tag.boolean
      ..[1] = contents.length;
    der.setRange(2, der.length, contents);
    final cbs = _cbsFor(der, arena);
    final out = arena<ffi.Int>();
    if (bssl.CBS_get_asn1_bool(cbs, out) != 1) {
      throw const Asn1Exception('Value is not a valid ASN.1 BOOLEAN');
    }
    return out.value != 0;
  });

  /// Decodes [contents] as a dotted-decimal `OBJECT IDENTIFIER` string.
  String asObjectIdentifier() => using((arena) {
    if (isConstructed) {
      throw const Asn1Exception(
        'Value is not a valid ASN.1 OBJECT IDENTIFIER',
      );
    }
    final text = bssl.CBS_asn1_oid_to_text(_cbsFor(contents, arena));
    if (text == ffi.nullptr) {
      drainErrorQueue();
      throw const Asn1Exception(
        'Value is not a valid ASN.1 OBJECT IDENTIFIER',
      );
    }
    return takeOwnedString(text, 'CBS_asn1_oid_to_text');
  });

  /// Decodes [contents] as a DER `BIT STRING`, returning the payload `bytes`
  /// and the count of trailing `unusedBits` (`0..7`) in the last byte.
  ({Uint8List bytes, int unusedBits}) asBitString() => using((arena) {
    if (isConstructed || contents.isEmpty) {
      throw const Asn1Exception('Value is not a valid ASN.1 BIT STRING');
    }
    final cbs = _cbsFor(contents, arena);
    if (bssl.CBS_is_valid_asn1_bitstring(cbs) != 1) {
      throw const Asn1Exception('Value is not a valid ASN.1 BIT STRING');
    }
    return (
      bytes: Uint8List.fromList(Uint8List.sublistView(contents, 1)),
      unusedBits: contents[0],
    );
  });

  /// Parses [contents] as a sequence of nested DER elements.
  ///
  /// Throws an [Asn1Exception] if this element is not constructed.
  List<Asn1Value> get children {
    if (!isConstructed) {
      throw const Asn1Exception('Cannot read children of a primitive element');
    }
    return Asn1Reader(contents).readAll();
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Asn1Value ||
        other.tag != tag ||
        other.contents.length != contents.length) {
      return false;
    }
    for (var i = 0; i < contents.length; i++) {
      if (other.contents[i] != contents[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(tag, Object.hashAll(contents));

  @override
  String toString() =>
      'Asn1Value(class: ${tagClass.name}, tag: $tagNumber, '
      'constructed: $isConstructed, length: ${contents.length})';
}

/// Allocates a `CBS` in [arena] pointing at a native copy of [bytes].
ffi.Pointer<bssl.CBS> _cbsFor(Uint8List bytes, Arena arena) {
  final buf = arena<ffi.Uint8>(bytes.isEmpty ? 1 : bytes.length);
  buf.asTypedList(bytes.length).setAll(0, bytes);
  return arena<bssl.CBS>()
    ..ref.data = buf
    ..ref.len = bytes.length;
}

/// A streaming reader for ASN.1 DER-encoded data (X.690).
///
/// Parsing is delegated to BoringSSL's `CBS` DER parser; this class only tracks
/// the read position and marshals results back into Dart types.
final class Asn1Reader {
  final Uint8List _bytes;
  int _offset;

  /// Creates a reader over [bytes], optionally starting at [offset].
  Asn1Reader(Uint8List bytes, {int offset = 0})
    : _bytes = bytes,
      _offset = RangeError.checkValueInInterval(
        offset,
        0,
        bytes.length,
        'offset',
      );

  /// The current read position within the underlying bytes.
  int get offset => _offset;

  /// Whether any unread bytes remain.
  bool get hasMore => _offset < _bytes.length;

  /// Reads the next DER element using BoringSSL's `CBS_get_any_asn1_element`.
  ///
  /// Throws an [Asn1Exception] if the data is truncated or malformed.
  Asn1Value read() {
    if (!hasMore) {
      throw Asn1Exception('Unexpected end of ASN.1 data', offset: _offset);
    }
    final start = _offset;
    return using((arena) {
      final cbs = _cbsFor(Uint8List.sublistView(_bytes, _offset), arena);
      final element = arena<bssl.CBS>();
      final tag = arena<bssl.CBS_ASN1_TAG>();
      final headerLength = arena<ffi.Size>();
      if (bssl.CBS_get_any_asn1_element(cbs, element, tag, headerLength) != 1) {
        drainErrorQueue();
        throw Asn1Exception('Malformed ASN.1 DER element', offset: start);
      }
      final elementLength = element.ref.len;
      final contents = Uint8List.fromList(
        element.ref.data.asTypedList(elementLength).sublist(headerLength.value),
      );
      _offset += elementLength;
      return Asn1Value._(tag.value, contents);
    });
  }

  /// Reads all remaining DER elements until the input is exhausted.
  List<Asn1Value> readAll() {
    final values = <Asn1Value>[];
    while (hasMore) {
      values.add(read());
    }
    return values;
  }

  /// Parses [der] as exactly one DER element.
  ///
  /// Throws an [Asn1Exception] if trailing bytes remain after the element.
  static Asn1Value parse(Uint8List der) {
    final reader = Asn1Reader(der);
    final value = reader.read();
    if (reader.hasMore) {
      throw Asn1Exception(
        'Trailing bytes after ASN.1 element',
        offset: reader.offset,
      );
    }
    return value;
  }

  /// Attempts to parse [der] as a single DER element, returning `null` on
  /// failure instead of throwing.
  static Asn1Value? tryParse(Uint8List der) {
    try {
      return parse(der);
    } on Asn1Exception {
      return null;
    }
  }
}
