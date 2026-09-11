// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

/// A minimal ASN.1 DER reader for inspecting X.509 extension payloads.
///
/// Certificate and signature structures themselves are decoded by BoringSSL;
/// this library exists so that callers can interpret the application-specific
/// contents of X.509 extensions, such as Sigstore's Fulcio OIDC extensions.
library;

export 'src/asn1/asn1.dart'
    show Asn1Class, Asn1Exception, Asn1Reader, Asn1Tag, Asn1Value;
