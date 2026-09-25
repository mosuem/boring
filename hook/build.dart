// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:io';

import 'package:boring/src/hook_helpers/hashes.dart' show fileHashes, version;
import 'package:boring/src/hook_helpers/sha256.dart' show sha256Hex;
import 'package:boring/src/hook_helpers/targets.dart'
    show libraryFileName, releaseAssetName;
import 'package:code_assets/code_assets.dart';
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

    // When linking is enabled (`dart build`, and Flutter's profile and release
    // builds), hook/link.dart links a dynamic library with only the functions
    // the application uses from the static library.
    final static = input.config.linkingEnabled;

    switch (buildOptions.buildMode) {
      case BuildModeEnum.fetch:
        await _fetchPrebuiltBinary(input, output, static: static);
      case BuildModeEnum.build:
      case BuildModeEnum.checkout:
        await _buildLocalCMake(input, output, static: static);
      case BuildModeEnum.local:
        await _useLocalBinary(input, output, buildOptions.localPath);
    }
    output.dependencies.addAll([
      input.packageRoot.resolve('pubspec.yaml'),
      input.packageRoot.resolve('hook/build.dart'),
      input.packageRoot.resolve('lib/src/hook_helpers/hashes.dart'),
    ]);
  });
}

/// Adds [library] as the `package:boring/boring.dart` code asset.
///
/// A [static] library is sent to hook/link.dart, which links it into the
/// dynamic library that is bundled.
void _addLibrary(
  BuildInput input,
  BuildOutputBuilder output,
  Uri library, {
  required bool static,
}) {
  output.assets.code.add(
    CodeAsset(
      package: input.packageName,
      name: _assetName,
      linkMode: static ? StaticLinking() : DynamicLoadingBundled(),
      file: library,
    ),
    routing: static ? ToLinkHook(input.packageName) : const ToAppBundle(),
  );
}

Future<void> _fetchPrebuiltBinary(
  BuildInput input,
  BuildOutputBuilder output, {
  required bool static,
}) async {
  final targetOS = input.config.code.targetOS;
  final targetArch = input.config.code.targetArchitecture;
  final iosSdk = targetOS == OS.iOS ? input.config.code.iOS.targetSdk : null;

  final assetRemoteName = releaseAssetName(
    targetOS,
    targetArch,
    iosSdk: iosSdk,
    static: static,
  );
  final expectedHash = fileHashes[assetRemoteName];

  if (expectedHash == null || expectedHash.isEmpty) {
    stdout.writeln(
      'boring: no prebuilt binary hash registered for $assetRemoteName, '
      'falling back to building from local source via CMake.',
    );
    await _buildLocalCMake(input, output, static: static);
    return;
  }

  final binaryUrl = Uri.parse(
    'https://github.com/mosuem/boring/releases/download/v$version/$assetRemoteName',
  );

  stdout.writeln('boring: fetching prebuilt binary from $binaryUrl...');

  final client = HttpClient();
  final List<int> bytes;
  try {
    final request = await client.getUrl(binaryUrl);
    final response = await request.close();
    if (response.statusCode != 200) {
      stdout.writeln(
        'boring: failed to download from $binaryUrl '
        '(status: ${response.statusCode}), '
        'falling back to building from local source.',
      );
      await _buildLocalCMake(input, output, static: static);
      return;
    }
    bytes = await response.fold<List<int>>([], (a, b) => a..addAll(b));
  } on IOException catch (e) {
    stdout.writeln(
      'boring: network error downloading prebuilt binary ($e), '
      'falling back to building from local source.',
    );
    await _buildLocalCMake(input, output, static: static);
    return;
  } finally {
    client.close();
  }

  final actualHash = sha256Hex(bytes);

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
    input.outputDirectory.resolve(libraryFileName(targetOS, static: static)),
  );
  await libraryFile.writeAsBytes(bytes);

  _addLibrary(input, output, libraryFile.uri, static: static);
}

/// Bundles the dynamic library at [localPath] as is, even when linking is
/// enabled.
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

  _addLibrary(input, output, destFile.uri, static: false);
  output.dependencies.add(localPath);
}

Future<void> _buildLocalCMake(
  BuildInput input,
  BuildOutputBuilder output, {
  required bool static,
}) async {
  final packageRoot = input.packageRoot;
  final installDir = input.outputDirectory.resolve('install/');
  final sourceDir = packageRoot.resolve('src/');

  stdout.writeln(
    'boring: building native asset with CMake for '
    '${input.config.code.targetOS}-${input.config.code.targetArchitecture}.',
  );

  // Installs both the dynamic and the static library, see src/CMakeLists.txt.
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

  final fileName = libraryFileName(input.config.code.targetOS, static: static);
  final library = installDir.resolve(fileName);
  if (!File.fromUri(library).existsSync()) {
    throw BuildError(
      message:
          'Failed to locate the built $fileName in '
          '${installDir.toFilePath()}',
    );
  }
  _addLibrary(input, output, library, static: static);

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
  'CMakeLists.txt',
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
