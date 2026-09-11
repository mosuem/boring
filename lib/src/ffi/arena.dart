// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

/// Helpers that wrap the repetitive parts of calling BoringSSL over FFI:
/// copying bytes across the Dart/native boundary, scoping native resource
/// ownership, and marshalling BoringSSL's output conventions back into Dart.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
import 'error.dart';

/// Copies [bytes] into newly allocated native memory using [allocator].
Pointer<Uint8> copyBytesToNative(
  Uint8List bytes, [
  Allocator allocator = calloc,
]) {
  final ptr = allocator<Uint8>(bytes.length);
  ptr.asTypedList(bytes.length).setAll(0, bytes);
  return ptr;
}

/// Cleanses (zeros out) and frees [ptr] of size [length].
void cleanseAndFree(
  Pointer<Uint8> ptr,
  int length, [
  Allocator allocator = calloc,
]) {
  if (ptr != nullptr && length > 0) {
    bssl.OPENSSL_cleanse(ptr.cast<Void>(), length);
  }
  allocator.free(ptr);
}

/// Copies [bytes] into [arena], returning `nullptr` when [bytes] is empty.
///
/// BoringSSL accepts a null pointer for zero-length inputs, and allocating a
/// zero-length buffer is not portable.
Pointer<Uint8> copyBytesOrNull(Uint8List? bytes, Arena arena) =>
    (bytes == null || bytes.isEmpty)
    ? nullptr
    : copyBytesToNative(bytes, arena);

// -----------------------------------------------------------------------
// Resource scoping
// -----------------------------------------------------------------------

/// Runs [body] with a native resource produced by [create], releasing it with
/// [destroy] afterwards even if [body] throws.
///
/// This captures BoringSSL's `X_new` / `X_free` ownership pattern so call sites
/// do not each need their own `try`/`finally`.
R withResource<T extends NativeType, R>({
  required Pointer<T> Function() create,
  required void Function(Pointer<T>) destroy,
  required String operation,
  required R Function(Pointer<T>) body,
}) {
  final handle = create();
  checkPointer(handle, operation);
  try {
    return body(handle);
  } finally {
    destroy(handle);
  }
}

/// Asynchronous version of [withResource] that awaits [body] before calling
/// [destroy].
Future<R> withResourceAsync<T extends NativeType, R>({
  required Pointer<T> Function() create,
  required void Function(Pointer<T>) destroy,
  required String operation,
  required Future<R> Function(Pointer<T>) body,
}) async {
  final handle = create();
  checkPointer(handle, operation);
  try {
    return await body(handle);
  } finally {
    destroy(handle);
  }
}

/// Converts a BoringSSL-allocated C string into a Dart string and frees it.
///
/// Functions such as `X509_NAME_oneline`, `BN_bn2hex`, and
/// `CBS_asn1_oid_to_text` return memory the caller must release with
/// `OPENSSL_free`.
String takeOwnedString(Pointer<Char> ptr, String operation) {
  checkPointer(ptr, operation);
  try {
    return ptr.cast<Utf8>().toDartString();
  } finally {
    bssl.OPENSSL_free(ptr.cast());
  }
}

// -----------------------------------------------------------------------
// Output buffers
// -----------------------------------------------------------------------

/// Runs BoringSSL's two-pass output idiom and returns the produced bytes.
///
/// Many BoringSSL functions are called twice: once with a null output buffer to
/// learn the required length, then again to fill a buffer of that size. [call]
/// receives the output buffer and the in/out length pointer, and must return
/// BoringSSL's usual `1` on success.
Uint8List withOutputBuffer(
  String operation,
  int Function(Pointer<Uint8> out, Pointer<Size> length) call,
) => using((arena) {
  final length = arena<Size>();
  checkBssl(call(nullptr, length), '$operation (size query)');
  final out = arena<Uint8>(length.value);
  checkBssl(call(out, length), operation);
  return Uint8List.fromList(out.asTypedList(length.value));
});

/// Allocates an output buffer of [maxLength], runs [call], and returns the
/// bytes actually written.
///
/// Used for BoringSSL operations whose maximum output size is known up front
/// (AEAD, digests, HMAC, HKDF). [call] receives the output buffer and the
/// enclosing arena, and must return the number of bytes written.
Uint8List withSizedOutput(
  int maxLength,
  int Function(Pointer<Uint8> out, Arena arena) call,
) => using((arena) {
  final out = arena<Uint8>(maxLength);
  final written = call(out, arena);
  return Uint8List.fromList(out.asTypedList(written));
});

// -----------------------------------------------------------------------
// BIO helpers
// -----------------------------------------------------------------------

/// Reads a memory [bio] to exhaustion and decodes the result as UTF-8.
String readBioString(Pointer<bssl.BIO> bio) {
  const chunkSize = 1024;
  final buffer = calloc<Uint8>(chunkSize);
  try {
    // Accumulate bytes and decode once, so a multi-byte UTF-8 sequence
    // straddling a chunk boundary is not split.
    final bytes = BytesBuilder(copy: false);
    while (true) {
      final read = bssl.BIO_read(bio, buffer.cast(), chunkSize);
      if (read <= 0) break;
      bytes.add(Uint8List.fromList(buffer.asTypedList(read)));
    }
    return utf8.decode(bytes.takeBytes());
  } finally {
    calloc.free(buffer);
  }
}

/// Writes to a fresh memory BIO via [write] and returns its contents.
///
/// This is the `PEM_write_bio_*` pattern: create a memory BIO, write into it,
/// read it back as a string, and free it.
String withMemBioString(
  String operation,
  int Function(Pointer<bssl.BIO> bio) write,
) => withResource(
  create: () => bssl.BIO_new(bssl.BIO_s_mem()),
  destroy: bssl.BIO_free,
  operation: 'BIO_new',
  body: (bio) {
    checkBssl(write(bio), operation);
    return readBioString(bio);
  },
);

/// Runs [body] with a read-only memory BIO over [bytes].
///
/// This is the `PEM_read_bio_*` pattern. `BIO_new_mem_buf` does not copy, so
/// the backing buffer is kept alive for the duration of [body].
R withMemBufBio<R>(Uint8List bytes, R Function(Pointer<bssl.BIO> bio) body) =>
    using((arena) {
      final buffer = copyBytesToNative(bytes, arena);
      return withResource(
        create: () => bssl.BIO_new_mem_buf(buffer.cast(), bytes.length),
        destroy: bssl.BIO_free,
        operation: 'BIO_new_mem_buf',
        body: body,
      );
    });
