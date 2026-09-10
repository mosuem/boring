// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;

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
