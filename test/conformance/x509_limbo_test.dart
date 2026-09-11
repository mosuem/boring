// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

/// Runs the [x509-limbo](https://x509-limbo.com) path validation suite against
/// [X509Verifier].
///
/// x509-limbo is a corpus of ~9800 X.509 chain building and validation
/// testcases maintained by C2SP. Fetch it and run this suite with
/// `./tool/run_x509_limbo_tests.sh`.
///
/// No implementation passes every testcase: the suite deliberately includes
/// behaviour that RFC 5280, the CA/Browser Forum baseline requirements and
/// individual libraries disagree on. Testcases where BoringSSL is known to
/// diverge are listed in `x509_limbo_expected_failures.txt`. This suite fails
/// if a testcase diverges that is not on that list, and also if a listed
/// testcase starts agreeing, so the list cannot silently go stale.
///
/// Set `X509_LIMBO_REGENERATE=1` to rewrite the list instead of asserting
/// against it.
@Timeout(Duration(minutes: 30))
library;

import 'dart:convert';
import 'dart:io';

import 'package:boring/x509.dart';
import 'package:test/test.dart';

/// Namespaces that cannot run against the current API at all.
const _skippedNamespaces = {
  // Fetches live certificate chains over the network.
  'online',
};

/// Testcase features that [X509Verifier] does not implement.
const _skippedFeatures = {
  // Requires supplying CRLs and performing revocation checking.
  'has-crl',
};

File? _findLimboJson() {
  final env = Platform.environment['X509_LIMBO_JSON'];
  if (env != null && File(env).existsSync()) return File(env);

  const candidates = [
    'build/x509-limbo/limbo.json',
    '../build/x509-limbo/limbo.json',
    '/tmp/limbo.json',
  ];
  for (final candidate in candidates) {
    final f = File(candidate);
    if (f.existsSync()) return f;
  }
  return null;
}

File _expectedFailuresFile() {
  for (final candidate in [
    'test/conformance/x509_limbo_expected_failures.txt',
    'conformance/x509_limbo_expected_failures.txt',
    'x509_limbo_expected_failures.txt',
  ]) {
    final f = File(candidate);
    if (f.existsSync()) return f;
  }
  return File('test/conformance/x509_limbo_expected_failures.txt');
}

Set<String> _readExpectedFailures(File file) => file.existsSync()
    ? file
          .readAsLinesSync()
          .map((l) => l.split('#').first.trim())
          .where((l) => l.isNotEmpty)
          .toSet()
    : <String>{};

/// A single x509-limbo testcase, decoded from `limbo.json`.
final class _Testcase {
  final Map<String, dynamic> json;

  _Testcase(this.json);

  String get id => json['id'] as String;

  String get namespace => id.split('::').first;

  bool get expectSuccess => json['expected_result'] == 'SUCCESS';

  List<String> get _features =>
      ((json['features'] as List?) ?? const []).cast<String>();

  bool get isSkipped =>
      _skippedNamespaces.contains(namespace) ||
      _features.any(_skippedFeatures.contains) ||
      // An X509_VERIFY_PARAM holds at most one expected email address and one
      // expected IP address, so these cannot be expressed.
      peerNames.where((n) => n.kind == X509PeerNameKind.emailAddress).length >
          1 ||
      peerNames.where((n) => n.kind == X509PeerNameKind.ipAddress).length > 1;

  List<String> _pems(String key) =>
      ((json[key] as List?) ?? const []).cast<String>();

  List<String> get trustedCerts => _pems('trusted_certs');

  List<String> get untrustedIntermediates => _pems('untrusted_intermediates');

  String get peerCertificate => json['peer_certificate'] as String;

  DateTime? get validationTime {
    final raw = json['validation_time'] as String?;
    return raw == null ? null : DateTime.parse(raw);
  }

  int? get maxChainDepth => json['max_chain_depth'] as int?;

  X509Purpose get purpose => json['validation_kind'] == 'CLIENT'
      ? X509Purpose.tlsClient
      : X509Purpose.tlsServer;

  List<X509PeerName> get peerNames => [
    for (final raw in [
      if (json['expected_peer_name'] != null) json['expected_peer_name'],
      ...(json['expected_peer_names'] as List?) ?? const [],
    ])
      _peerName((raw as Map).cast<String, dynamic>()),
  ];

  static X509PeerName _peerName(Map<String, dynamic> raw) {
    final value = raw['value'] as String;
    return switch (raw['kind']) {
      'DNS' => X509PeerName.dnsName(value),
      'IP' => X509PeerName.ipAddress(value),
      'RFC822' => X509PeerName.emailAddress(value),
      final kind => throw UnsupportedError('Unknown peer name kind: $kind'),
    };
  }
}

/// Runs [testcase] and returns whether the chain validated.
///
/// A testcase whose inputs cannot even be parsed counts as a validation
/// failure, which is what limbo expects for malformed-certificate cases.
bool _runTestcase(_Testcase testcase) {
  try {
    final verifier = X509Verifier();
    for (final pem in testcase.trustedCerts) {
      verifier.addTrustedCertificate(X509Certificate.fromPem(pem));
    }
    return verifier
        .verify(
          leaf: X509Certificate.fromPem(testcase.peerCertificate),
          intermediates: [
            for (final pem in testcase.untrustedIntermediates)
              X509Certificate.fromPem(pem),
          ],
          checkTime: testcase.validationTime,
          peerNames: testcase.peerNames,
          purpose: testcase.purpose,
          maxIntermediates: testcase.maxChainDepth,
        )
        .isValid;
  } on Exception {
    return false;
  }
}

void main() {
  final limboJson = _findLimboJson();

  group('x509-limbo Conformance', () {
    if (limboJson == null) {
      test(
        'x509-limbo testcases available',
        () {},
        skip:
            'limbo.json not found. '
            'Run ./tool/run_x509_limbo_tests.sh to fetch and run the suite.',
      );
      return;
    }

    final limbo = jsonDecode(limboJson.readAsStringSync()) as Map;
    final testcases = [
      for (final raw in limbo['testcases'] as List)
        _Testcase((raw as Map).cast<String, dynamic>()),
    ];
    final byNamespace = <String, List<_Testcase>>{};
    for (final testcase in testcases) {
      byNamespace.putIfAbsent(testcase.namespace, () => []).add(testcase);
    }

    final expectedFailuresFile = _expectedFailuresFile();
    final expectedFailures = _readExpectedFailures(expectedFailuresFile);
    final regenerate = Platform.environment['X509_LIMBO_REGENERATE'] == '1';
    final diverged = <String>[];
    var ran = 0;

    for (final namespace in byNamespace.keys.toList()..sort()) {
      final namespaceCases = byNamespace[namespace]!;
      test('$namespace (${namespaceCases.length} testcases)', () {
        final unexpected = <String>[];
        final unexpectedlyPassing = <String>[];

        for (final testcase in namespaceCases) {
          if (testcase.isSkipped) continue;
          ran++;
          final agrees = _runTestcase(testcase) == testcase.expectSuccess;
          if (!agrees) diverged.add(testcase.id);

          if (regenerate) continue;
          if (!agrees && !expectedFailures.contains(testcase.id)) {
            unexpected.add(
              '${testcase.id} (expected '
              '${testcase.expectSuccess ? "SUCCESS" : "FAILURE"})',
            );
          } else if (agrees && expectedFailures.contains(testcase.id)) {
            unexpectedlyPassing.add(testcase.id);
          }
        }

        expect(
          unexpected,
          isEmpty,
          reason:
              '${unexpected.length} testcase(s) diverged from x509-limbo and '
              'are not listed in ${expectedFailuresFile.path}',
        );
        expect(
          unexpectedlyPassing,
          isEmpty,
          reason:
              '${unexpectedlyPassing.length} testcase(s) are listed in '
              '${expectedFailuresFile.path} but now agree with x509-limbo. '
              'Remove them from the list.',
        );
      });
    }

    tearDownAll(() {
      final agreed = ran - diverged.length;
      final rate = ran == 0 ? 0.0 : 100 * agreed / ran;
      // ignore: avoid_print
      print(
        'x509-limbo: $agreed/$ran testcases agree '
        '(${rate.toStringAsFixed(1)}%), '
        '${testcases.length - ran} skipped as unsupported.',
      );
      if (!regenerate) return;
      diverged.sort();
      expectedFailuresFile.writeAsStringSync(
        '# Testcases from https://x509-limbo.com where BoringSSL, as exposed\n'
        '# by package:boring, disagrees with the suite\'s expected result.\n'
        '#\n'
        '# These are almost all cases where the suite encodes a CA/Browser\n'
        '# Forum baseline requirement, or a "pedantic" reading of RFC 5280,\n'
        '# that BoringSSL deliberately does not enforce, plus chain building\n'
        '# and name constraint types BoringSSL does not support.\n'
        '#\n'
        '# Regenerate with:\n'
        '#   X509_LIMBO_REGENERATE=1 ./tool/run_x509_limbo_tests.sh\n'
        '\n'
        '${diverged.join('\n')}\n',
      );
      // ignore: avoid_print
      print(
        'Wrote ${diverged.length} divergences to ${expectedFailuresFile.path}',
      );
    });
  });
}
