// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'package:boring/src/crypto/rand.dart';
import 'package:test/test.dart';

void main() {
  group('BoringRand', () {
    test('generates empty bytes for count 0', () {
      final bytes = BoringRand.secureRandom(0);
      expect(bytes, isEmpty);
    });

    test('throws ArgumentError for negative count', () {
      expect(() => BoringRand.secureRandom(-1), throwsArgumentError);
    });

    test('generates requested number of random bytes', () {
      final bytes1 = BoringRand.secureRandom(32);
      final bytes2 = BoringRand.secureRandom(32);

      expect(bytes1.length, equals(32));
      expect(bytes2.length, equals(32));
      expect(bytes1, isNot(equals(bytes2)));
    });

    test('generates different random buffers', () {
      final seen = <String>{};
      for (var i = 0; i < 100; i++) {
        final b = BoringRand.secureRandom(16);
        final hex = b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
        expect(seen.add(hex), isTrue);
      }
    });
  });
}
