// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../bindings/boringssl.g.dart' as bssl;
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
    return using((arena) {
      final buffer = arena<Uint8>(count);
      final result = bssl.RAND_bytes(buffer, count);
      checkBssl(result, 'RAND_bytes');
      return Uint8List.fromList(buffer.asTypedList(count));
    });
  }
}
