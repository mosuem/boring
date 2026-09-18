// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:typed_data';
import 'package:boring/src/crypto/digest.dart';
import 'package:boring/src/crypto/hmac.dart';
import 'package:test/test.dart';

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('BoringHmac', () {
    final key = Uint8List.fromList(utf8.encode('secret-key'));
    final data = Uint8List.fromList(
      utf8.encode('The quick brown fox jumps over the lazy dog'),
    );

    test('HMAC-SHA256 test vector', () {
      final mac = BoringHmac.sha256(key: key, data: data);
      expect(
        _toHex(mac),
        equals(
          'affee3b4888c714d8369e419b5e51d1ff7c024b64a94d76b8dd53c8fb5d0a2dc',
        ),
      );
    });

    test('HMAC-SHA384 test vector', () {
      final mac = BoringHmac.sha384(key: key, data: data);
      expect(
        _toHex(mac),
        equals(
          '5211269571c885ccf769ec3d9dcc858f30c9a56a722ad19d193c182dbd37107f'
          '305bc85531f2ce8c39cdacaae0cb4e3b',
        ),
      );
    });

    test('HMAC-SHA512 test vector', () {
      final mac = BoringHmac.sha512(key: key, data: data);
      expect(
        _toHex(mac),
        equals(
          '246be23a6a10781830011e57db63ec7fcd18f284bf002d6d85a0b79358aaf610'
          '84c151977e7e99781672271c5d57abcf43c747acac6efda65bc099ad295ff217',
        ),
      );
    });

    test('streaming HmacContext produces identical result', () {
      final ctx = HmacContext(HashAlgorithm.sha256, key);
      ctx.update(
        Uint8List.fromList(utf8.encode('The quick brown fox ')),
      );
      ctx.update(
        Uint8List.fromList(utf8.encode('jumps over the lazy dog')),
      );
      final mac = ctx.finalize();

      expect(
        _toHex(mac),
        equals(
          'affee3b4888c714d8369e419b5e51d1ff7c024b64a94d76b8dd53c8fb5d0a2dc',
        ),
      );
    });

    test('computeStream and sha256Stream', () async {
      final stream = Stream.fromIterable([
        utf8.encode('The quick brown fox '),
        utf8.encode('jumps over the lazy dog'),
      ]);
      final mac = await BoringHmac.sha256Stream(key: key, stream: stream);
      expect(
        _toHex(mac),
        equals(
          'affee3b4888c714d8369e419b5e51d1ff7c024b64a94d76b8dd53c8fb5d0a2dc',
        ),
      );

      final stream2 = Stream.fromIterable([
        utf8.encode('The quick brown fox '),
        utf8.encode('jumps over the lazy dog'),
      ]);
      final mac512 = await BoringHmac.computeStream(
        algorithm: HashAlgorithm.sha512,
        key: key,
        stream: stream2,
      );
      expect(
        _toHex(mac512),
        equals(
          '246be23a6a10781830011e57db63ec7fcd18f284bf002d6d85a0b79358aaf610'
          '84c151977e7e99781672271c5d57abcf43c747acac6efda65bc099ad295ff217',
        ),
      );
    });
  });
}
