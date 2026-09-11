// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

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
  universal(0x00),

  /// Types whose interpretation depends on the containing structure.
  application(0x40),

  /// Types whose interpretation depends on the context they appear in, used
  /// for `CHOICE` alternatives such as X.509 `GeneralName`.
  contextSpecific(0x80),

  /// Types defined by private, enterprise-specific specifications.
  private(0xC0);

  const Asn1Class(this.bits);

  /// The two high-order bits of the identifier octet for this class.
  final int bits;
}

/// ASN.1 universal tag numbers (X.680) needed to interpret X.509 structures.
abstract final class Asn1Tag {
  /// `BOOLEAN`.
  static const int boolean = 0x01;

  /// `INTEGER`.
  static const int integer = 0x02;

  /// `BIT STRING`.
  static const int bitString = 0x03;

  /// `OCTET STRING`.
  static const int octetString = 0x04;

  /// `NULL`.
  static const int null_ = 0x05;

  /// `OBJECT IDENTIFIER`.
  static const int objectIdentifier = 0x06;

  /// `UTF8String`.
  static const int utf8String = 0x0C;

  /// `PrintableString`.
  static const int printableString = 0x13;

  /// `TeletexString` (also known as `T61String`).
  static const int teletexString = 0x14;

  /// `IA5String`.
  static const int ia5String = 0x16;

  /// `UTCTime`.
  static const int utcTime = 0x17;

  /// `GeneralizedTime`.
  static const int generalizedTime = 0x18;

  /// `VisibleString`.
  static const int visibleString = 0x1A;

  /// `BMPString`.
  static const int bmpString = 0x1E;

  /// `SEQUENCE` / `SEQUENCE OF`.
  static const int sequence = 0x10;

  /// `SET` / `SET OF`.
  static const int set = 0x11;
}

/// A single parsed ASN.1 DER element (a tag-length-value triple).
final class Asn1Value {
  /// The full identifier octet, including class and constructed bits.
  final int identifier;

  /// The raw contents of this element, excluding tag and length octets.
  final Uint8List contents;

  /// Creates an [Asn1Value] from a raw [identifier] octet and its [contents].
  const Asn1Value(this.identifier, this.contents);

  /// The tag class encoded in the identifier octet.
  Asn1Class get tagClass => switch (identifier & 0xC0) {
    0x00 => Asn1Class.universal,
    0x40 => Asn1Class.application,
    0x80 => Asn1Class.contextSpecific,
    _ => Asn1Class.private,
  };

  /// Whether this element is constructed (contains nested elements).
  bool get isConstructed => (identifier & 0x20) != 0;

  /// The tag number with the class and constructed bits masked off.
  int get tagNumber => identifier & 0x1F;

  /// Whether this element is a universal type with the given [tag].
  bool hasUniversalTag(int tag) =>
      tagClass == Asn1Class.universal && tagNumber == tag;

  /// Decodes [contents] as a text string.
  ///
  /// `BMPString` values are decoded as UTF-16BE; all other string types are
  /// decoded as UTF-8, which is a superset of the ASCII-based ASN.1 string
  /// types used in X.509 (`IA5String`, `PrintableString`, `VisibleString`).
  String asString() {
    if (hasUniversalTag(Asn1Tag.bmpString)) {
      if (contents.length.isOdd) {
        throw const Asn1Exception('BMPString has an odd number of bytes');
      }
      final units = <int>[];
      for (var i = 0; i < contents.length; i += 2) {
        units.add((contents[i] << 8) | contents[i + 1]);
      }
      return String.fromCharCodes(units);
    }
    return utf8.decode(contents, allowMalformed: true);
  }

  /// Decodes [contents] as an unsigned or signed big-endian `INTEGER`.
  BigInt asInteger() {
    if (contents.isEmpty) {
      throw const Asn1Exception('INTEGER has empty contents');
    }
    var result = BigInt.zero;
    for (final byte in contents) {
      result = (result << 8) | BigInt.from(byte);
    }
    // Negative values are encoded in two's complement.
    if (contents[0] & 0x80 != 0) {
      result -= BigInt.one << (contents.length * 8);
    }
    return result;
  }

  /// Decodes [contents] as a `BOOLEAN`.
  bool asBoolean() {
    if (contents.length != 1) {
      throw const Asn1Exception('BOOLEAN must have exactly one content byte');
    }
    return contents[0] != 0;
  }

  /// Decodes [contents] as a dotted-decimal `OBJECT IDENTIFIER` string.
  String asObjectIdentifier() {
    if (contents.isEmpty) {
      throw const Asn1Exception('OBJECT IDENTIFIER has empty contents');
    }
    final components = <int>[contents[0] ~/ 40, contents[0] % 40];
    var value = 0;
    for (var i = 1; i < contents.length; i++) {
      value = (value << 7) | (contents[i] & 0x7F);
      if (contents[i] & 0x80 == 0) {
        components.add(value);
        value = 0;
      }
    }
    return components.join('.');
  }

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
  String toString() =>
      'Asn1Value(class: ${tagClass.name}, tag: $tagNumber, '
      'constructed: $isConstructed, length: ${contents.length})';
}

/// A streaming reader for ASN.1 DER-encoded data (X.690).
///
/// This reader is intentionally minimal: it decodes the tag-length-value
/// structure needed to inspect X.509 certificate extension payloads without
/// pulling in a full ASN.1 schema compiler.
final class Asn1Reader {
  final Uint8List _bytes;
  int _offset;

  /// Creates a reader over [bytes], optionally starting at [offset].
  Asn1Reader(Uint8List bytes, {int offset = 0})
    : _bytes = bytes,
      _offset = offset;

  /// The current read position within the underlying bytes.
  int get offset => _offset;

  /// Whether any unread bytes remain.
  bool get hasMore => _offset < _bytes.length;

  /// Reads the next DER element.
  ///
  /// Throws an [Asn1Exception] if the data is truncated or malformed.
  Asn1Value read() {
    if (!hasMore) {
      throw Asn1Exception('Unexpected end of ASN.1 data', offset: _offset);
    }

    final start = _offset;
    final identifier = _bytes[_offset++];

    // High-tag-number form (tag number >= 31) is encoded in following octets.
    if (identifier & 0x1F == 0x1F) {
      while (true) {
        if (!hasMore) {
          throw Asn1Exception('Truncated high-tag-number form', offset: start);
        }
        if (_bytes[_offset++] & 0x80 == 0) break;
      }
    }

    if (!hasMore) {
      throw Asn1Exception('Missing ASN.1 length octet', offset: start);
    }

    var length = _bytes[_offset++];
    if (length & 0x80 != 0) {
      final lengthOctets = length & 0x7F;
      if (lengthOctets == 0) {
        throw Asn1Exception(
          'Indefinite length is not valid in DER',
          offset: start,
        );
      }
      if (lengthOctets > 4) {
        throw Asn1Exception('ASN.1 length is too large', offset: start);
      }
      if (_offset + lengthOctets > _bytes.length) {
        throw Asn1Exception('Truncated ASN.1 length octets', offset: start);
      }
      length = 0;
      for (var i = 0; i < lengthOctets; i++) {
        length = (length << 8) | _bytes[_offset++];
      }
    }

    if (_offset + length > _bytes.length) {
      throw Asn1Exception(
        'ASN.1 contents extend past the end of the input',
        offset: start,
      );
    }

    final contents = Uint8List.sublistView(_bytes, _offset, _offset + length);
    _offset += length;
    return Asn1Value(identifier, contents);
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
