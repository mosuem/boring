// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'package:hooks/hooks.dart' show HookInputUserDefines;

enum BuildModeEnum { fetch, build, checkout, local }

class BuildOptions {
  final BuildModeEnum buildMode;
  final Uri? localPath;

  BuildOptions({required this.buildMode, this.localPath});

  factory BuildOptions.fromDefines(HookInputUserDefines defines) {
    final modeString = defines['buildMode'] as String? ?? 'fetch';
    return BuildOptions(
      buildMode: BuildModeEnum.values.firstWhere(
        (element) => element.name == modeString,
        orElse: () => BuildModeEnum.fetch,
      ),
      localPath: defines.path('localPath'),
    );
  }

  @override
  String toString() =>
      'BuildOptions(buildMode: $buildMode, localPath: $localPath)';
}
