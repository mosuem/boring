// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

import 'hashes.dart' show fileHashes, version;
import 'sha256.dart' show sha256Hex;
import 'targets.dart' show libraryFileName, releaseAssetName;

/// Downloads and verifies the pre-built library for the target of [input] from
/// the GitHub release [version], caching it in
/// [HookInput.outputDirectoryShared].
///
/// Returns `null` if no hash is registered in [fileHashes] or if downloading
/// fails due to an HTTP or network error. Throws a [BuildError] if the
/// downloaded file's SHA-256 checksum does not match [fileHashes].
Future<Uri?> fetchPrebuiltLibrary(
  HookInput input, {
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
      'boring: no prebuilt binary hash registered for $assetRemoteName.',
    );
    return null;
  }

  final fileName = libraryFileName(targetOS, static: static);
  final cachedFile = File.fromUri(
    input.outputDirectoryShared
        .resolve('boring-$version/$assetRemoteName/')
        .resolve(fileName),
  );
  if (await cachedFile.exists()) {
    final cachedHash = sha256Hex(await cachedFile.readAsBytes());
    if (cachedHash == expectedHash) {
      stdout.writeln(
        'boring: using cached prebuilt binary ($assetRemoteName).',
      );
      return cachedFile.uri;
    }
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
        '(status: ${response.statusCode}).',
      );
      return null;
    }
    bytes = await response.fold<List<int>>([], (a, b) => a..addAll(b));
  } on IOException catch (e) {
    stdout.writeln(
      'boring: network error downloading prebuilt binary ($e).',
    );
    return null;
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

  await cachedFile.parent.create(recursive: true);
  await cachedFile.writeAsBytes(bytes);
  return cachedFile.uri;
}
