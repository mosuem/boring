// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

// coverage:ignore-file

import 'dart:io';

import 'package:args/args.dart';
import 'package:code_assets/code_assets.dart';

void main(List<String> args) async {
  final parser = ArgParser()
    ..addOption(
      'target-os',
      abbr: 'o',
      allowed: ['linux', 'macos', 'windows', 'current'],
      defaultsTo: 'current',
      help: 'Target OS to build for.',
    )
    ..addOption(
      'target-arch',
      abbr: 'a',
      allowed: ['x64', 'arm64', 'arm', 'ia32', 'riscv64', 'current'],
      defaultsTo: 'current',
      help: 'Target architecture to build for.',
    )
    ..addOption(
      'out-dir',
      abbr: 'd',
      defaultsTo: 'bin',
      help: 'Output directory for built release binaries.',
    );

  ArgResults results;
  try {
    results = parser.parse(args);
  } catch (e) {
    stderr.writeln('Error parsing arguments: $e\n');
    stderr.writeln(parser.usage);
    exit(1);
  }

  final targetOS = results['target-os'] == 'current'
      ? (Platform.isLinux
            ? OS.linux
            : Platform.isMacOS
            ? OS.macOS
            : OS.windows)
      : OS.values.firstWhere((o) => o.name == results['target-os']);

  final targetArch = results['target-arch'] == 'current'
      ? Architecture.current
      : Architecture.values.firstWhere((a) => a.name == results['target-arch']);

  final packageRoot = Platform.script.resolve('../');
  final outDir = Directory.fromUri(
    packageRoot.resolve('${results['out-dir']}/'),
  );
  await outDir.create(recursive: true);

  final targetTriple = '${targetOS.name}-${targetArch.name}';
  final dylibFileName = targetOS.dylibFileName('bssl_dart');
  final releaseFileName = 'boring-$targetTriple-$dylibFileName';

  stdout.writeln('==> Building BoringSSL for $targetTriple...');

  final buildDir = Directory.fromUri(
    packageRoot.resolve('build/precompile-$targetTriple/'),
  );
  await buildDir.create(recursive: true);

  // Configure CMake
  final configureProcess = await Process.start(
    'cmake',
    [
      '-S',
      File.fromUri(packageRoot.resolve('src/')).path,
      '-B',
      buildDir.path,
      '-G',
      'Ninja',
      '-DCMAKE_BUILD_TYPE=Release',
    ],
    mode: ProcessStartMode.inheritStdio,
  );
  var exitCode = await configureProcess.exitCode;
  if (exitCode != 0) {
    stderr.writeln('CMake configure failed with exit code $exitCode');
    exit(exitCode);
  }

  // Build
  final buildProcess = await Process.start(
    'cmake',
    [
      '--build',
      buildDir.path,
      '--target',
      'bssl_dart',
    ],
    mode: ProcessStartMode.inheritStdio,
  );
  exitCode = await buildProcess.exitCode;
  if (exitCode != 0) {
    stderr.writeln('CMake build failed with exit code $exitCode');
    exit(exitCode);
  }

  // Locate built library
  final builtLib = File('${buildDir.path}/$dylibFileName');
  if (!builtLib.existsSync()) {
    stderr.writeln('Built library not found at ${builtLib.path}');
    exit(1);
  }

  final destFile = File('${outDir.path}/$releaseFileName');
  await builtLib.copy(destFile.path);
  stdout.writeln('==> Created release binary: ${destFile.path}');
}
