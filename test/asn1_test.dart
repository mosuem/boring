// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:typed_data';

import 'package:boring/asn1.dart';
import 'package:test/test.dart';

Uint8List bytes(List<int> values) => Uint8List.fromList(values);

void main() {
  group('Asn1Reader', () {
    test('parses a UTF8String', () {
      // 0C 05 "hello"
      final value = Asn1Reader.parse(
        bytes([0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]),
      );

      expect(value.tagClass, Asn1Class.universal);
      expect(value.tagNumber, Asn1Tag.utf8String);
      expect(value.isConstructed, isFalse);
      expect(value.asString(), 'hello');
    });

    test('parses a long-form length', () {
      // 0C 81 80 followed by 128 'a' bytes.
      final contents = List<int>.filled(128, 0x61);
      final value = Asn1Reader.parse(bytes([0x0C, 0x81, 0x80, ...contents]));

      expect(value.contents, hasLength(128));
      expect(value.asString(), 'a' * 128);
    });

    test('parses a SEQUENCE and its children', () {
      // SEQUENCE { INTEGER 1, BOOLEAN true }
      final value = Asn1Reader.parse(
        bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF]),
      );

      expect(value.isConstructed, isTrue);
      expect(value.hasUniversalTag(Asn1Tag.sequence), isTrue);

      final children = value.children;
      expect(children, hasLength(2));
      expect(children[0].asInteger(), BigInt.one);
      expect(children[1].asBoolean(), isTrue);
    });

    test('parses an OBJECT IDENTIFIER', () {
      // 1.3.6.1.4.1.57264.1.1
      final value = Asn1Reader.parse(
        bytes([
          0x06,
          0x0A,
          0x2B,
          0x06,
          0x01,
          0x04,
          0x01,
          0x83,
          0xBF,
          0x30,
          0x01,
          0x01,
        ]),
      );

      expect(value.asObjectIdentifier(), '1.3.6.1.4.1.57264.1.1');
    });

    test('parses negative INTEGER in two\'s complement', () {
      final value = Asn1Reader.parse(bytes([0x02, 0x01, 0xFF]));
      expect(value.asInteger(), BigInt.from(-1));
    });

    test('parses context-specific tags', () {
      // [6] IMPLICIT IA5String "https://example.com"
      const uri = 'https://example.com';
      final value = Asn1Reader.parse(
        bytes([0x86, uri.length, ...uri.codeUnits]),
      );

      expect(value.tagClass, Asn1Class.contextSpecific);
      expect(value.tagNumber, 6);
      expect(value.asString(), uri);
    });

    test('readAll returns every top-level element', () {
      final values = Asn1Reader(
        bytes([0x02, 0x01, 0x05, 0x01, 0x01, 0x00]),
      ).readAll();

      expect(values, hasLength(2));
      expect(values[0].asInteger(), BigInt.from(5));
      expect(values[1].asBoolean(), isFalse);
    });

    test('rejects truncated contents', () {
      expect(
        () => Asn1Reader.parse(bytes([0x0C, 0x05, 0x68])),
        throwsA(isA<Asn1Exception>()),
      );
    });

    test('rejects indefinite length', () {
      expect(
        () => Asn1Reader.parse(bytes([0x30, 0x80, 0x00, 0x00])),
        throwsA(isA<Asn1Exception>()),
      );
    });

    test('rejects trailing bytes in parse', () {
      expect(
        () => Asn1Reader.parse(bytes([0x02, 0x01, 0x01, 0x02, 0x01, 0x02])),
        throwsA(isA<Asn1Exception>()),
      );
    });

    test('tryParse returns null on malformed input', () {
      expect(Asn1Reader.tryParse(bytes([0x0C, 0x7F])), isNull);
    });

    test('rejects reading children of a primitive', () {
      final value = Asn1Reader.parse(bytes([0x02, 0x01, 0x01]));
      expect(() => value.children, throwsA(isA<Asn1Exception>()));
    });

    test('rejects non-minimal long-form length', () {
      // 0x81 0x01 encodes length 1 in long form, but DER requires the short
      // form for lengths below 128. BoringSSL's CBS parser enforces this.
      expect(
        () => Asn1Reader.parse(bytes([0x02, 0x81, 0x01, 0x05])),
        throwsA(isA<Asn1Exception>()),
      );
    });

    test('rejects non-minimal INTEGER encoding', () {
      // A leading 0x00 is only permitted when the next byte has its high bit
      // set, so 00 05 is not a valid DER INTEGER.
      final value = Asn1Reader.parse(bytes([0x02, 0x02, 0x00, 0x05]));
      expect(value.asInteger, throwsA(isA<Asn1Exception>()));
    });

    test('decodes BMPString as UTF-16BE', () {
      // "hi" encoded as BMPString: two UTF-16BE code units.
      final value = Asn1Reader.parse(
        bytes([0x1E, 0x04, 0x00, 0x68, 0x00, 0x69]),
      );
      expect(value.asString(), 'hi');
    });

    test('decodes multi-byte UTF8String', () {
      final encoded = utf8.encode('héllo');
      final value = Asn1Reader.parse(
        bytes([0x0C, encoded.length, ...encoded]),
      );
      expect(value.asString(), 'héllo');
    });

    test('asString honours an explicit stringType for implicit tags', () {
      // [0] IMPLICIT BMPString "hi".
      final value = Asn1Reader.parse(
        bytes([0x80, 0x04, 0x00, 0x68, 0x00, 0x69]),
      );
      expect(value.asString(stringType: Asn1Tag.bmpString), 'hi');
    });

    test('asBoolean rejects empty or multi-byte BOOLEAN payloads', () {
      final emptyBool = Asn1Reader.parse(bytes([0x01, 0x00]));
      expect(emptyBool.asBoolean, throwsA(isA<Asn1Exception>()));

      final multiByteBool = Asn1Reader.parse(bytes([0x01, 0x02, 0xFF, 0x00]));
      expect(multiByteBool.asBoolean, throwsA(isA<Asn1Exception>()));
    });

    test('asBitString decodes valid BIT STRING and rejects invalid ones', () {
      final bitStr = Asn1Reader.parse(bytes([0x03, 0x02, 0x07, 0x80]));
      final decoded = bitStr.asBitString();
      expect(decoded.unusedBits, 7);
      expect(decoded.bytes, equals(bytes([0x80])));

      // Non-zero unused trailing bit is invalid in DER.
      final badBits = Asn1Reader.parse(bytes([0x03, 0x02, 0x07, 0x81]));
      expect(badBits.asBitString, throwsA(isA<Asn1Exception>()));
    });

    test(
      'rejects constructed encodings for primitive types and validates offset',
      () {
        final seq = Asn1Reader.parse(bytes([0x30, 0x01, 0xFF]));
        expect(seq.asInteger, throwsA(isA<Asn1Exception>()));
        expect(seq.asBoolean, throwsA(isA<Asn1Exception>()));
        expect(seq.asObjectIdentifier, throwsA(isA<Asn1Exception>()));
        expect(seq.asString, throwsA(isA<Asn1Exception>()));

        expect(
          () => Asn1Reader(bytes([0x05, 0x00]), offset: -1),
          throwsRangeError,
        );
        expect(
          () => Asn1Reader(bytes([0x05, 0x00]), offset: 3),
          throwsRangeError,
        );

        final v1 = Asn1Reader.parse(bytes([0x02, 0x01, 0x05]));
        final v2 = Asn1Reader.parse(bytes([0x02, 0x01, 0x05]));
        expect(v1, equals(v2));
        expect(v1.hashCode, equals(v2.hashCode));
      },
    );
  });
}
