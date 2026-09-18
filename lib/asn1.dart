// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

/// A minimal ASN.1 DER reader for inspecting X.509 extension payloads.
///
/// Certificate and signature structures themselves are decoded by BoringSSL;
/// this library exists so that callers can interpret the application-specific
/// contents of X.509 extensions, such as Sigstore's Fulcio OIDC extensions.
library;

export 'src/asn1/asn1.dart'
    show Asn1Class, Asn1Exception, Asn1Reader, Asn1Tag, Asn1Value;
