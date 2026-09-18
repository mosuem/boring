// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;

/// Exception thrown when a BoringSSL operation fails.
class BoringSslException implements Exception {
  /// High-level description of the BoringSSL operation that failed.
  final String message;

  /// Detailed error messages drained from BoringSSL's thread-local error queue.
  final List<String> errorQueue;

  /// Creates a [BoringSslException] with [message] and optional [errorQueue].
  BoringSslException(this.message, [this.errorQueue = const []]);

  @override
  String toString() {
    if (errorQueue.isEmpty) {
      return 'BoringSslException: $message';
    }
    return 'BoringSslException: $message\nErrors:\n'
        '  ${errorQueue.join('\n  ')}';
  }
}

/// Drains the BoringSSL thread-local error queue and returns the messages.
List<String> drainErrorQueue() {
  final errors = <String>[];
  using((arena) {
    final buffer = arena<Char>(256);
    while (true) {
      final err = bssl.ERR_get_error();
      if (err == 0) break;
      bssl.ERR_error_string_n(err, buffer, 256);
      errors.add(buffer.cast<Utf8>().toDartString());
    }
  });
  return errors;
}

/// Validates that a BoringSSL integer return value indicates success
/// (usually 1).
///
/// Throws [BoringSslException] if [result] != 1.
void checkBssl(int result, String operation) {
  if (result != 1) {
    final errors = drainErrorQueue();
    throw BoringSslException('$operation failed (code: $result)', errors);
  }
}

/// Validates that a BoringSSL pointer return value is not null.
///
/// Throws [BoringSslException] if [ptr] == nullptr.
Pointer<T> checkPointer<T extends NativeType>(
  Pointer<T> ptr,
  String operation,
) {
  if (ptr == nullptr) {
    final errors = drainErrorQueue();
    throw BoringSslException('$operation returned null pointer', errors);
  }
  return ptr;
}
