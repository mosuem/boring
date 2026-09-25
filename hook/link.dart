// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'dart:io';
import 'dart:typed_data';

import 'package:boring/src/bindings/record_use_mapping.g.dart';
import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';
import 'package:record_use/record_use.dart' as record_use;

const _bindings = record_use.Library(
  'package:boring/src/bindings/boringssl.g.dart',
);

/// Links the static library from hook/build.dart into a dynamic library with
/// only the BoringSSL functions that the application uses.
Future<void> main(List<String> args) async {
  await link(args, (input, output) async {
    final staticLibrary = input.assets.code
        .where((asset) => asset.id == 'package:boring/boring.dart')
        .firstOrNull;
    if (staticLibrary == null) {
      // hook/build.dart bundled a dynamic library instead.
      return;
    }
    final staticLibraryFile = staticLibrary.file!;

    final recordedUses = input.recordedUses;
    final List<String>? symbols;
    if (recordedUses == null) {
      // For example with `flutter config --no-enable-record-use`.
      stdout.writeln('boring: no recorded uses, keeping all functions.');
      symbols = null;
    } else {
      symbols = _usedSymbols(recordedUses);
      stdout.writeln(
        'boring: keeping the ${symbols.length} functions the application '
        'uses:\n  ${symbols.join('\n  ')}',
      );
    }

    final LinkerOptions linkerOptions;
    if (input.config.code.targetOS == OS.windows) {
      linkerOptions = await _windowsLinkerOptions(
        input,
        staticLibraryFile,
        symbols,
      );
    } else {
      linkerOptions = LinkerOptions.treeshake(symbolsToKeep: symbols);
    }

    await CLinker.library(
      name: 'bssl_dart',
      packageName: input.packageName,
      assetName: 'boring.dart',
      sources: [staticLibraryFile.toFilePath()],
      frameworks: const [],
      linkerOptions: linkerOptions,
      linkModePreference: LinkModePreference.dynamic,
    ).run(
      input: input,
      output: output,
      logger: Logger('')
        ..level = Level.ALL
        ..onRecord.listen((record) => stdout.writeln(record.message)),
    );
  });
}

/// The symbols of the bound functions that the application calls, tears off,
/// or takes the address of with `addresses`.
List<String> _usedSymbols(record_use.Recordings recordedUses) => [
  for (final definition in recordedUses.calls.keys)
    if (definition.library == _bindings) ?recordUseMapping[definition.name],
]..sort();

/// The options for linking a DLL exporting [symbols], or all bound functions
/// if [symbols] is null.
///
/// Only exports the functions that the [staticLibrary] defines. BoringSSL
/// doesn't compile some for Windows, such as
/// `RAND_enable_fork_unsafe_buffering`, and exporting them would fail the link.
Future<LinkerOptions> _windowsLinkerOptions(
  LinkInput input,
  Uri staticLibrary,
  List<String>? symbols,
) async {
  final defined = _definedBindings(
    await File.fromUri(staticLibrary).readAsBytes(),
  );
  final exports = symbols?.where(defined.contains).toList() ?? [...defined];

  // `LinkerOptions.treeshake` passes an `/INCLUDE:<symbol>` per symbol, and
  // Windows limits command lines to 32767 characters. Leave room for the
  // paths and other flags.
  final includesLength = exports.fold(0, (sum, s) => sum + s.length + 10);
  if (symbols != null && includesLength < 24000) {
    return LinkerOptions.treeshake(symbolsToKeep: exports);
  }

  // Link the whole archive instead, which keeps the assembly the DLL doesn't
  // use. The objects aren't compiled with `__declspec(dllexport)`, so the
  // module-definition file determines what the DLL exports.
  final moduleDefinition = input.outputDirectory.resolve('bssl_dart.def');
  await File.fromUri(moduleDefinition).writeAsString(
    ['EXPORTS', for (final symbol in exports) '    $symbol', ''].join('\n'),
  );
  return LinkerOptions.manual(
    linkerScript: moduleDefinition,
    symbolsToKeep: null,
  );
}

/// The symbols of the bound functions that the COFF [archive] defines.
Set<String> _definedBindings(Uint8List archive) {
  final defined = _archiveSymbols(archive);
  return {
    for (final symbol in recordUseMapping.values)
      // x86 prefixes C symbols with an underscore, which the module-definition
      // file omits.
      if (defined.contains(symbol) || defined.contains('_$symbol')) symbol,
  };
}

/// The symbols that the members of the COFF [archive] define, read from its
/// first linker member.
///
/// See https://learn.microsoft.com/windows/win32/debug/pe-format#first-linker-member.
Set<String> _archiveSymbols(Uint8List archive) {
  const signature = '!<arch>\n';
  const memberHeaderSize = 60;
  const start = signature.length + memberHeaderSize;
  if (archive.length < start + 4 ||
      String.fromCharCodes(archive, 0, signature.length) != signature ||
      String.fromCharCodes(archive, signature.length, 24).trimRight() != '/') {
    throw const FormatException('Not an archive with a linker member.');
  }
  final count = ByteData.sublistView(archive).getUint32(start, Endian.big);
  // The member offsets are followed by the NUL-terminated symbol names.
  var offset = start + 4 + 4 * count;
  final symbols = <String>{};
  for (var i = 0; i < count; i++) {
    final end = archive.indexOf(0, offset);
    symbols.add(String.fromCharCodes(archive, offset, end));
    offset = end + 1;
  }
  return symbols;
}
