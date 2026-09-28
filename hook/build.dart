// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'package:boring/src/hook_helpers/library.dart';
import 'package:hooks/hooks.dart';

Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    await boringLibrary.build(
      input: input,
      output: output,
      additionalDependencies: [
        input.packageRoot.resolve('lib/src/hook_helpers/hashes.dart'),
      ],
    );
  });
}
