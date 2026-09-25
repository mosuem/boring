// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:boring/bindings.dart';
import 'package:boring/bindings.dart' as ssl;
import 'package:ffi/ffi.dart' show using;
import 'package:test/test.dart';

void main() {
  group('package:boring/bindings.dart', () {
    test('BORINGSSL_self_test passes', () {
      expect(ssl.BORINGSSL_self_test(), equals(1));
    });

    test('opensslAllocator allocates and frees via OPENSSL_malloc/free', () {
      using((arena) {
        final buf = arena<ffi.Uint8>(32);
        expect(ssl.RAND_bytes(buf, 32), equals(1));
        final bytes = Uint8List.fromList(buf.asTypedList(32));
        expect(bytes.any((b) => b != 0), isTrue);
      }, opensslAllocator);
    });

    test('EVP_sha256 computes expected digest', () {
      final digest = using((arena) {
        final input = utf8.encode('abc');
        final inPtr = arena<ffi.Uint8>(input.length);
        inPtr.asTypedList(input.length).setAll(0, input);

        final md = ssl.EVP_sha256();
        final outPtr = arena<ffi.Uint8>(ssl.EVP_MD_size(md));
        final outLen = arena<ffi.UnsignedInt>();

        final ctx = ssl.EVP_MD_CTX_new();
        try {
          expect(ssl.EVP_DigestInit(ctx, md), equals(1));
          expect(
            ssl.EVP_DigestUpdate(ctx, inPtr.cast(), input.length),
            equals(1),
          );
          expect(ssl.EVP_DigestFinal(ctx, outPtr, outLen), equals(1));
        } finally {
          ssl.EVP_MD_CTX_free(ctx);
        }

        return Uint8List.fromList(outPtr.asTypedList(outLen.value));
      }, opensslAllocator);

      final hex = digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      expect(
        hex,
        equals(
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        ),
      );
    });

    test('CBB and CBS are concrete ffi.Structs usable with Allocator', () {
      expect(ffi.sizeOf<CBB>(), greaterThan(0));
      expect(ffi.sizeOf<CBS>(), greaterThan(0));

      using((arena) {
        final cbb = arena<CBB>();
        ssl.CBB_zero(cbb);
        expect(ssl.CBB_init(cbb, 64), equals(1));
        try {
          expect(ssl.CBB_add_u8(cbb, 0x2a), equals(1));
          expect(ssl.CBB_flush(cbb), equals(1));
          expect(ssl.CBB_len(cbb), equals(1));

          final cbs = arena<CBS>()
            ..ref.data = ssl.CBB_data(cbb)
            ..ref.len = ssl.CBB_len(cbb);
          final out = arena<ffi.Uint8>();
          expect(ssl.CBS_get_u8(cbs, out), equals(1));
          expect(out.value, equals(0x2a));
        } finally {
          ssl.CBB_cleanup(cbb);
        }
      }, opensslAllocator);
    });

    test('exposes WebCrypto required macro and enum constants', () {
      expect(EC_PKEY_NO_PUBKEY, isNonZero);
      expect(HKDF_R_OUTPUT_TOO_LARGE, isNonZero);
      expect(ERR_LIB_HKDF, isNonZero);
      expect(
        point_conversion_form_t.POINT_CONVERSION_UNCOMPRESSED,
        equals(4),
      );
      final packed = (ERR_LIB_HKDF << 24) | HKDF_R_OUTPUT_TOO_LARGE;
      expect(ERR_GET_LIB(packed), equals(ERR_LIB_HKDF));
      expect(ERR_GET_REASON(packed), equals(HKDF_R_OUTPUT_TOO_LARGE));
    });
  });
}
