// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/src/crypto/digest.dart';
import 'package:test/test.dart';

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('BoringDigest', () {
    test('SHA-256 known test vector', () {
      // sha256("") =
      //   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      final emptyHash = BoringDigest.sha256(Uint8List(0));
      expect(
        _toHex(emptyHash),
        equals(
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ),
      );

      // sha256("hello world") =
      //   b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
      final helloHash = BoringDigest.sha256(
        Uint8List.fromList(utf8.encode('hello world')),
      );
      expect(
        _toHex(helloHash),
        equals(
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
        ),
      );
    });

    test('SHA-384 known test vector', () {
      final hash = BoringDigest.sha384(
        Uint8List.fromList(utf8.encode('hello world')),
      );
      expect(
        _toHex(hash),
        equals(
          'fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3'
          'e417cb71ce646efd0819dd8c088de1bd',
        ),
      );
    });

    test('SHA-512 known test vector', () {
      final hash = BoringDigest.sha512(
        Uint8List.fromList(utf8.encode('hello world')),
      );
      expect(
        _toHex(hash),
        equals(
          '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f'
          '989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f',
        ),
      );
    });

    test('SHA-1 known test vector', () {
      final hash = BoringDigest.sha1(
        Uint8List.fromList(utf8.encode('hello world')),
      );
      expect(_toHex(hash), equals('2aae6c35c94fcfb415dbe95f408b9ce91ee846ed'));
    });

    test('streaming DigestContext', () {
      final ctx = DigestContext(HashAlgorithm.sha256);
      ctx.update(Uint8List.fromList(utf8.encode('hello ')));
      ctx.update(Uint8List.fromList(utf8.encode('world')));
      final hash = ctx.finalize();

      expect(
        _toHex(hash),
        equals(
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
        ),
      );

      // Finalizing again should throw StateError
      expect(ctx.finalize, throwsStateError);
      // Updating after finalize should throw StateError
      expect(() => ctx.update(Uint8List(0)), throwsStateError);
    });

    test('hashStream and sha256Stream', () async {
      final stream = Stream.fromIterable([
        utf8.encode('hello '),
        utf8.encode('world'),
      ]);
      final hash = await BoringDigest.sha256Stream(stream);
      expect(
        _toHex(hash),
        equals(
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
        ),
      );

      final stream2 = Stream.fromIterable([
        utf8.encode('hello '),
        utf8.encode('world'),
      ]);
      final hashSha1 = await BoringDigest.hashStream(
        HashAlgorithm.sha1,
        stream2,
      );
      expect(
        _toHex(hashSha1),
        equals('2aae6c35c94fcfb415dbe95f408b9ce91ee846ed'),
      );
    });
  });
}
