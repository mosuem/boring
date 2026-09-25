// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:boring/bindings.dart' as ssl;
import 'package:ffi/ffi.dart' show using;

void main() {
  using((arena) {
    final input = utf8.encode('hello world');
    final dataPtr = arena<ffi.Uint8>(input.length);
    dataPtr.asTypedList(input.length).setAll(0, input);

    final md = ssl.EVP_sha256();
    final mdLen = ssl.EVP_MD_size(md);
    final outPtr = arena<ffi.Uint8>(mdLen);
    final outLenPtr = arena<ffi.UnsignedInt>();

    final ctx = ssl.EVP_MD_CTX_new();
    try {
      ssl.EVP_DigestInit(ctx, md);
      ssl.EVP_DigestUpdate(ctx, dataPtr.cast(), input.length);
      ssl.EVP_DigestFinal(ctx, outPtr, outLenPtr);
    } finally {
      ssl.EVP_MD_CTX_free(ctx);
    }

    final digest = Uint8List.fromList(outPtr.asTypedList(outLenPtr.value));
    final hex = digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    print('SHA-256("hello world"): $hex');
  }, ssl.opensslAllocator);
}
