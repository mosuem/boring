// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:boring/bindings.dart' as ssl;

void main() {
  final digest = ssl.BoringArena.run((arena) {
    final input = utf8.encode('hello world');
    final md = ssl.EVP_sha256();
    final out = arena<ffi.Uint8>(ssl.EVP_MD_size(md));
    final outLen = arena<ffi.UnsignedInt>();
    final ctx = arena.using(ssl.EVP_MD_CTX_new(), ssl.EVP_MD_CTX_free);

    if (ssl.EVP_DigestInit(ctx, md) != 1 ||
        ssl.EVP_DigestUpdate(ctx, arena.copyBytes(input), input.length) != 1 ||
        ssl.EVP_DigestFinal(ctx, out, outLen) != 1) {
      throw StateError(ssl.extractBoringSslError() ?? 'SHA-256 failed');
    }
    return Uint8List.fromList(out.asTypedList(outLen.value));
  });

  final hex = digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  print('SHA-256("hello world"): $hex');
}
