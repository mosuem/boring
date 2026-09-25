# boring

Raw `ffigen` bindings to **BoringSSL** powered by **Dart Native Assets**.

[![pub package](https://img.shields.io/pub/v/boring.svg)](https://pub.dev/packages/boring)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`package:boring` bundles Google's [BoringSSL](https://boringssl.googlesource.com/boringssl/) (`bssl_dart`) via Dart Native Assets and exposes its raw `@Native` C bindings along with an `OPENSSL_malloc` / `OPENSSL_free`-backed `ffi.Allocator` across Linux, macOS, Windows, Android, and iOS.

---

## Key Highlights

- **100% Symbol Isolation (`bssl_dart`)**: Compiled with `-DBORINGSSL_PREFIX=bssl_dart`, eliminating dynamic linker collisions with Flutter, the Dart VM, or system OpenSSL libraries.
- **Dart Native Assets**: Bundles and dynamically loads native code automatically via `package:code_assets` and `package:hooks`.
- **Automatic Memory Scrubbing (`opensslAllocator`)**: Exports `opensslAllocator` (`ffi.Allocator` backed by `OPENSSL_malloc` / `OPENSSL_free`), which stores allocation sizes and unconditionally runs `OPENSSL_cleanse` before freeing native memory.
- **Concrete `CBS` & `CBB` Structs**: Both `CBS` (CRYPTO ByteString) and `CBB` (CRYPTO ByteBuilder) are generated as concrete `ffi.Struct` types, allowing direct stack/arena allocation (`arena<CBS>()`, `arena<CBB>()`) without C wrapper shims.

---

## Getting Started

Add `boring` to your `pubspec.yaml`:

```yaml
dependencies:
  boring: ^0.3.0
```

---

## Usage

Import `package:boring/bindings.dart` (or `package:boring/boring.dart`) and scope native allocations with `opensslAllocator`:

```dart
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:boring/bindings.dart' as ssl;
import 'package:ffi/ffi.dart' show using;

void main() {
  using((arena) {
    final input = utf8.encode('hello world');
    final dataPtr = arena<ffi.Uint8>(input.length);
    dataPtr.asTypedList(input.length).setAll(0, input);

    final md = ssl.EVP_sha256();
    final mdLen = ssl.EVP_MD_size(md);
    final outPtr = arena<ffi.Uint8>(mdLen);
    final outLenPtr = arena<ffi.UnsignedInt>();

    final ctx = ssl.EVP_MD_CTX_new();
    try {
      ssl.EVP_DigestInit(ctx, md);
      ssl.EVP_DigestUpdate(ctx, dataPtr.cast(), input.length);
      ssl.EVP_DigestFinal(ctx, outPtr, outLenPtr);
    } finally {
      ssl.EVP_MD_CTX_free(ctx);
    }

    final digest = Uint8List.fromList(outPtr.asTypedList(outLenPtr.value));
    final hex = digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    print('SHA-256("hello world"): $hex');
  }, ssl.opensslAllocator);
}
```

---

## Native Asset Build Modes

Configured in `pubspec.yaml` under `hooks.user_defines.boring`:

```yaml
hooks:
  user_defines:
    boring:
      buildMode: fetch # 'fetch', 'checkout', or 'local'
```

- **`fetch`** *(default)*: Downloads prebuilt binaries from GitHub Releases verified against pinned SHA-256 checksums, falling back to local compilation if unavailable.
- **`checkout`**: Always compiles BoringSSL locally from bundled sources via CMake and Ninja.
- **`local`**: Uses a custom prebuilt dynamic library at `localPath`.

---

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details. BoringSSL is licensed under Apache 2.0 and BSD-style licenses.
