// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

/// Raw `ffigen`-generated BoringSSL C bindings (`bssl_dart`) and native
/// allocator backed by `OPENSSL_malloc` / `OPENSSL_free`.
library;

import 'dart:ffi' as ffi;

import 'src/bindings/boringssl.g.dart' as bssl;

export 'src/bindings/boringssl.g.dart';

/// An [ffi.Allocator] backed by BoringSSL's `OPENSSL_malloc` and
/// `OPENSSL_free`.
///
/// BoringSSL's `OPENSSL_free` automatically scrubs every allocation with
/// `OPENSSL_cleanse` before returning memory to the OS heap.
const ffi.Allocator opensslAllocator = _OpenSslAllocator();

final class _OpenSslAllocator implements ffi.Allocator {
  const _OpenSslAllocator();

  @override
  ffi.Pointer<T> allocate<T extends ffi.NativeType>(
    int byteCount, {
    int? alignment,
  }) {
    final ptr = bssl.OPENSSL_malloc(byteCount);
    if (ptr == ffi.nullptr) {
      bssl.ERR_clear_error();
      throw const OutOfMemoryError();
    }
    return ptr.cast<T>();
  }

  @override
  void free(ffi.Pointer<ffi.NativeType> pointer) {
    bssl.OPENSSL_free(pointer.cast());
  }
}

/// Returns the library code (`ERR_LIB_*`) for a packed BoringSSL error code.
// ignore: non_constant_identifier_names
int ERR_GET_LIB(int packedError) => (packedError >> 24) & 0xff;

/// Returns the library-specific reason code (`*_R_*`) for a packed BoringSSL
/// error code.
// ignore: non_constant_identifier_names
int ERR_GET_REASON(int packedError) => packedError & 0xfff;
