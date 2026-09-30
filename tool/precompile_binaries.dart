// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

// coverage:ignore-file

import 'dart:io';

import 'package:boring/src/hook_helpers/library.dart';
import 'package:prebuilt_code_assets/tools.dart';

/// Builds the dynamic and the static library for a release.
///
/// hook/build.dart bundles the dynamic library when linking is disabled, and
/// hook/link.dart links the static library into a dynamic library with only
/// the functions an application uses when linking is enabled.
Future<void> main(List<String> args) async {
  await runPrecompileBinariesCli(
    args,
    library: boringLibrary,
    packageRoot: Platform.script.resolve('../'),
  );
}
