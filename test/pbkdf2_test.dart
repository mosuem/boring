// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/crypto.dart';
import 'package:test/test.dart';

String _hexEncode(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('BoringPbkdf2', () {
    test('RFC 6070 test vectors (HMAC-SHA1)', () {
      final pass = Uint8List.fromList(utf8.encode('password'));
      final salt = Uint8List.fromList(utf8.encode('salt'));

      // Test 1: 1 iteration
      final k1 = BoringPbkdf2.deriveBits(
        hash: HashAlgorithm.sha1,
        password: pass,
        salt: salt,
        iterations: 1,
        length: 20,
      );
      expect(_hexEncode(k1), '0c60c80f961f0e71f3a9b524af6012062fe037a6');

      // Test 2: 2 iterations
      final k2 = BoringPbkdf2.deriveBits(
        hash: HashAlgorithm.sha1,
        password: pass,
        salt: salt,
        iterations: 2,
        length: 20,
      );
      expect(_hexEncode(k2), 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');

      // Test 3: 4096 iterations
      final k3 = BoringPbkdf2.deriveBits(
        hash: HashAlgorithm.sha1,
        password: pass,
        salt: salt,
        iterations: 4096,
        length: 20,
      );
      expect(_hexEncode(k3), '4b007901b765489abead49d926f721d065a429c1');

      // Test 4: long password and salt
      final longPass = Uint8List.fromList(
        utf8.encode('passwordPASSWORDpassword'),
      );
      final longSalt = Uint8List.fromList(
        utf8.encode('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
      );
      final k4 = BoringPbkdf2.deriveKey(
        hash: HashAlgorithm.sha1,
        password: longPass,
        salt: longSalt,
        iterations: 4096,
        length: 25,
      );
      expect(
        _hexEncode(k4),
        '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
      );
    });

    test('PBKDF2 HMAC-SHA256 test vector', () {
      final pass = Uint8List.fromList(utf8.encode('password'));
      final salt = Uint8List.fromList(utf8.encode('salt'));

      final k = BoringPbkdf2.deriveBits(
        hash: HashAlgorithm.sha256,
        password: pass,
        salt: salt,
        iterations: 4096,
        length: 32,
      );
      expect(
        _hexEncode(k),
        'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
      );
    });

    test('validates parameters', () {
      final pass = Uint8List.fromList([1, 2, 3]);
      final salt = Uint8List.fromList([4, 5, 6]);

      expect(
        () => BoringPbkdf2.deriveBits(
          hash: HashAlgorithm.sha256,
          password: pass,
          salt: salt,
          iterations: 0,
          length: 32,
        ),
        throwsArgumentError,
      );

      expect(
        () => BoringPbkdf2.deriveBits(
          hash: HashAlgorithm.sha256,
          password: pass,
          salt: salt,
          iterations: -1,
          length: 32,
        ),
        throwsArgumentError,
      );

      expect(
        () => BoringPbkdf2.deriveBits(
          hash: HashAlgorithm.sha256,
          password: pass,
          salt: salt,
          iterations: 1000,
          length: -5,
        ),
        throwsArgumentError,
      );

      // length == 0 returns empty Uint8List
      final empty = BoringPbkdf2.deriveBits(
        hash: HashAlgorithm.sha256,
        password: pass,
        salt: salt,
        iterations: 1000,
        length: 0,
      );
      expect(empty, isEmpty);
    });
  });
}
