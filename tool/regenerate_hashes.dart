// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

// coverage:ignore-file

import 'package:boring/src/hook_helpers/library.dart';
import 'package:boring/src/hook_helpers/version.dart';
import 'package:prebuilt_code_assets/tools.dart';

/// Writes the SHA-256 hashes of the release assets built by
/// tool/precompile_binaries.dart to lib/src/hook_helpers/hashes.dart.
Future<void> main(List<String> args) async {
  await runRegenerateHashesCli(
    args,
    defaultVersion: releaseVersion,
    releaseConfigForVersion: boringReleaseConfig,
  );
}
