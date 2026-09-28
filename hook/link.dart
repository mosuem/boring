// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'package:boring/src/hook_helpers/library.dart';
import 'package:hooks/hooks.dart';

/// Links the static library from hook/build.dart into a dynamic library with
/// only the BoringSSL functions that the application uses.
///
/// If linking fails in the default `fetch` build mode, falls back to the
/// pre-built dynamic library.
Future<void> main(List<String> args) async {
  await link(args, (input, output) async {
    await boringLibrary.link(input: input, output: output);
  });
}
