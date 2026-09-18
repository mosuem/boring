// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

import 'package:code_assets/code_assets.dart';

const supportedTargets = [
  (OS.android, Architecture.arm, null),
  (OS.android, Architecture.arm64, null),
  (OS.android, Architecture.ia32, null),
  (OS.android, Architecture.riscv64, null),
  (OS.android, Architecture.x64, null),
  (OS.iOS, Architecture.arm64, IOSSdk.iPhoneOS),
  (OS.iOS, Architecture.arm64, IOSSdk.iPhoneSimulator),
  (OS.iOS, Architecture.x64, IOSSdk.iPhoneSimulator),
  (OS.linux, Architecture.arm, null),
  (OS.linux, Architecture.arm64, null),
  (OS.linux, Architecture.ia32, null),
  (OS.linux, Architecture.riscv64, null),
  (OS.linux, Architecture.x64, null),
  (OS.macOS, Architecture.arm64, null),
  (OS.macOS, Architecture.x64, null),
  (OS.windows, Architecture.arm64, null),
  (OS.windows, Architecture.ia32, null),
  (OS.windows, Architecture.x64, null),
];

/// Formats a canonical target identifier, including [iosSdk] when targeting iOS
/// so device (`iphoneos`) and simulator (`iphonesimulator`) binaries do not
/// collide on `ios-arm64`.
String targetTripleFor(OS os, Architecture arch, {IOSSdk? iosSdk}) {
  if (os == OS.iOS && iosSdk != null) {
    return '${os.name}-${arch.name}-${iosSdk.type}';
  }
  return '${os.name}-${arch.name}';
}
