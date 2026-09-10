// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:io';

import 'package:boring/src/hook_helpers/hashes.dart' show fileHashes, version;
import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart' show sha256;
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_cmake/native_toolchain_cmake.dart';

const _assetName = 'boring.dart';

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

Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      stdout.writeln(
        'boring: skipping native asset build (code assets not requested).',
      );
      return;
    }

    final buildOptions = BuildOptions.fromDefines(input.userDefines);
    stdout.writeln('boring: build options: $buildOptions');

    switch (buildOptions.buildMode) {
      case BuildModeEnum.fetch:
        await _fetchPrebuiltBinary(input, output);
      case BuildModeEnum.build:
      case BuildModeEnum.checkout:
        await _buildLocalCMake(input, output);
      case BuildModeEnum.local:
        await _useLocalBinary(input, output, buildOptions.localPath);
    }
    output.dependencies.add(input.packageRoot.resolve('pubspec.yaml'));
  });
}

Future<void> _fetchPrebuiltBinary(
  BuildInput input,
  BuildOutputBuilder output,
) async {
  final targetOS = input.config.code.targetOS;
  final targetArch = input.config.code.targetArchitecture;
  final dylibFileName = targetOS.dylibFileName('bssl_dart');

  final targetTriple = '${targetOS.name}-${targetArch.name}';
  final expectedHash = fileHashes[targetTriple];

  if (expectedHash == null || expectedHash.isEmpty) {
    stdout.writeln(
      'boring: no prebuilt binary hash registered for $targetTriple, '
      'falling back to building from local source via CMake.',
    );
    await _buildLocalCMake(input, output);
    return;
  }

  final assetRemoteName = 'boring-$targetTriple-$dylibFileName';
  final binaryUrl = Uri.parse(
    'https://github.com/mosuem/boring/releases/download/v$version/$assetRemoteName',
  );

  stdout.writeln('boring: fetching prebuilt binary from $binaryUrl...');

  final client = HttpClient();
  try {
    final request = await client.getUrl(binaryUrl);
    final response = await request.close();
    if (response.statusCode != 200) {
      stdout.writeln(
        'boring: failed to download from $binaryUrl '
        '(status: ${response.statusCode}), '
        'falling back to building from local source.',
      );
      await _buildLocalCMake(input, output);
      return;
    }

    final bytes = await response.fold<List<int>>([], (a, b) => a..addAll(b));
    final actualHash = sha256.convert(bytes).toString();

    if (actualHash != expectedHash) {
      throw BuildError(
        message:
            'SHA256 hash mismatch for prebuilt binary $assetRemoteName.\n'
            'Expected: $expectedHash\n'
            'Actual:   $actualHash\n'
            'To build boring locally from source instead, set '
            '`buildMode: checkout` in your pubspec.yaml under '
            '`hooks.user_defines.boring`.',
      );
    }

    stdout.writeln('boring: verified SHA256 checksum ($actualHash).');

    final libraryFile = File.fromUri(
      input.outputDirectory.resolve(dylibFileName),
    );
    await libraryFile.writeAsBytes(bytes);

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: _assetName,
        linkMode: DynamicLoadingBundled(),
        file: libraryFile.uri,
      ),
    );
  } finally {
    client.close();
  }
}

Future<void> _useLocalBinary(
  BuildInput input,
  BuildOutputBuilder output,
  Uri? localPath,
) async {
  if (localPath == null) {
    throw BuildError(
      message:
          'buildMode is set to `local`, but `localPath` was not specified '
          'under `hooks.user_defines.boring`.',
    );
  }
  final file = File.fromUri(localPath);
  if (!file.existsSync()) {
    throw BuildError(
      message:
          'Specified local binary does not exist at ${localPath.toFilePath()}',
    );
  }
  final dylibFileName = input.config.code.targetOS.dylibFileName('bssl_dart');
  final destFile = File.fromUri(input.outputDirectory.resolve(dylibFileName));
  await file.copy(destFile.path);

  output.assets.code.add(
    CodeAsset(
      package: input.packageName,
      name: _assetName,
      linkMode: DynamicLoadingBundled(),
      file: destFile.uri,
    ),
  );
  output.dependencies.add(localPath);
}

Future<void> _buildLocalCMake(
  BuildInput input,
  BuildOutputBuilder output,
) async {
  final packageRoot = input.packageRoot;
  final installDir = input.outputDirectory.resolve('install/');
  final sourceDir = packageRoot.resolve('src/');

  stdout.writeln(
    'boring: building native asset with CMake for '
    '${input.config.code.targetOS}-${input.config.code.targetArchitecture}.',
  );

  final builder = CMakeBuilder.create(
    name: 'bssl_dart',
    sourceDir: sourceDir,
    defines: {
      'CMAKE_BUILD_TYPE': 'Release',
      'CMAKE_INSTALL_PREFIX': installDir.toFilePath(),
    },
    targets: ['install'],
  );

  await builder.run(input: input, output: output);

  final assets = await output.findAndAddCodeAssets(
    input,
    outDir: installDir,
    names: {r'(lib)?bssl_dart\.(dll|dylib|so)': _assetName},
    regExp: true,
  );
  if (assets.isEmpty) {
    throw BuildError(
      message:
          'Failed to locate built bssl_dart dynamic library in '
          '${installDir.toFilePath()}',
    );
  }

  output.dependencies.addAll(_buildDependencies(packageRoot));
}

final _buildDependencyExtensions = {
  '.S',
  '.asm',
  '.c',
  '.cc',
  '.cmake',
  '.cpp',
  '.h',
};

Iterable<Uri> _buildDependencies(Uri packageRoot) sync* {
  yield* _filesForBuild(Directory.fromUri(packageRoot.resolve('src/')));
  yield* _filesForBuild(
    Directory.fromUri(packageRoot.resolve('third_party/boringssl/')),
  );
}

Iterable<Uri> _filesForBuild(Directory root) sync* {
  if (!root.existsSync()) {
    return;
  }

  for (final entity in root.listSync(recursive: true, followLinks: false)) {
    if (entity is! File) {
      continue;
    }
    if (!_buildDependencyExtensions.any(entity.uri.path.endsWith)) {
      continue;
    }
    yield entity.uri;
  }
}
