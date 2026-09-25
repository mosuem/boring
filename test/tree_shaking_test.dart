// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

// Builds the example with `dart build cli`, which runs hook/link.dart with the
// recorded uses of the bindings, and checks that the bundled library only has
// the functions the example uses.
@TestOn('linux || mac-os || windows')
@Timeout(Duration(minutes: 15))
library;

import 'dart:ffi';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:test/test.dart';

void main() {
  late Uri bundle;
  late File library;

  setUpAll(() async {
    final output = await Directory.systemTemp.createTemp('boring_example_');
    addTearDown(() => output.delete(recursive: true));

    final build = await Process.run(Platform.resolvedExecutable, [
      'build',
      'cli',
      '--target',
      'example/boring_example.dart',
      '--output',
      output.path,
    ]);
    expect(build.exitCode, 0, reason: '${build.stdout}\n${build.stderr}');

    bundle = output.uri.resolve('bundle/');
    library = File.fromUri(
      bundle.resolve('lib/${OS.current.dylibFileName('bssl_dart')}'),
    );
  });

  test('the example runs', () async {
    final executable = bundle.resolve(
      'bin/boring_example${Platform.isWindows ? '.exe' : ''}',
    );
    final result = await Process.run(executable.toFilePath(), []);
    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
    expect(
      result.stdout,
      contains(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
      ),
    );
  });

  test('the library only exports the functions the example uses', () {
    final dylib = DynamicLibrary.open(library.path);
    addTearDown(dylib.close);
    for (final used in ['EVP_sha256', 'EVP_DigestFinal', 'OPENSSL_free']) {
      expect(dylib.providesSymbol('bssl_dart_$used'), isTrue, reason: used);
    }
    for (final unused in ['EVP_sha512', 'EVP_AEAD_CTX_seal', 'X509_verify']) {
      expect(
        dylib.providesSymbol('bssl_dart_$unused'),
        isFalse,
        reason: unused,
      );
    }
  });

  test('the library is tree-shaken', () {
    // With all functions, the library is about 3 MB.
    expect(library.lengthSync(), lessThan(1024 * 1024));
  });
}
