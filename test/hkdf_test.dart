// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:typed_data';
import 'package:boring/src/crypto/digest.dart';
import 'package:boring/src/crypto/hkdf.dart';
import 'package:test/test.dart';

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('BoringHkdf', () {
    // RFC 5869 Test Case 1
    final ikm = Uint8List.fromList(List.filled(22, 0x0b));
    final salt = Uint8List.fromList(List.generate(13, (i) => i));
    final info = Uint8List.fromList(List.generate(10, (i) => 0xf0 + i));
    const length = 42;

    const expectedPrk =
        '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
    const expectedOkm =
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865';

    test('RFC 5869 Test Case 1 - extract and expand', () {
      final prk = BoringHkdf.extract(
        algorithm: HashAlgorithm.sha256,
        ikm: ikm,
        salt: salt,
      );
      expect(_toHex(prk), equals(expectedPrk));

      final okm = BoringHkdf.expand(
        algorithm: HashAlgorithm.sha256,
        prk: prk,
        length: length,
        info: info,
      );
      expect(_toHex(okm), equals(expectedOkm));
    });

    test('RFC 5869 Test Case 1 - deriveBits one-shot', () {
      final okm = BoringHkdf.deriveBits(
        algorithm: HashAlgorithm.sha256,
        ikm: ikm,
        length: length,
        salt: salt,
        info: info,
      );
      expect(_toHex(okm), equals(expectedOkm));
    });

    test('deriveBits with zero length returns empty list', () {
      final out = BoringHkdf.deriveBits(
        algorithm: HashAlgorithm.sha256,
        ikm: ikm,
        length: 0,
      );
      expect(out, isEmpty);
    });

    test('deriveBits with negative length throws ArgumentError', () {
      expect(
        () => BoringHkdf.deriveBits(
          algorithm: HashAlgorithm.sha256,
          ikm: ikm,
          length: -1,
        ),
        throwsArgumentError,
      );
    });
  });
}
