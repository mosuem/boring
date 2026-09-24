// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:typed_data';
import '../bindings/boringssl.g.dart' as bssl;
import '../ffi/arena.dart';
import '../ffi/error.dart';

/// Cryptographically secure pseudorandom number generator (CSPRNG).
abstract final class BoringRand {
  /// Generates [count] cryptographically secure pseudorandom bytes.
  static Uint8List secureRandom(int count) {
    if (count < 0) {
      throw ArgumentError.value(count, 'count', 'Count must be non-negative');
    }
    if (count == 0) {
      return Uint8List(0);
    }
    return withSecretSizedOutput(count, (buffer, _) {
      checkBssl(bssl.RAND_bytes(buffer, count), 'RAND_bytes');
      return count;
    });
  }
}
