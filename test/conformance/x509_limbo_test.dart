// Copyright 2026 Moritz Sümmermann. Licensed under the Apache License,
// Version 2.0. See the LICENSE file for details.

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

/// The reason recorded for a chain that verified when the suite expected it to
/// be rejected.
const _accepted = '<accepted>';

/// Runs [testcase], returning whether the chain validated and, when it did
/// not, the reason BoringSSL gave.
///
/// A testcase whose inputs cannot even be parsed counts as a validation
/// failure, which is what limbo expects for malformed-certificate cases.
(bool valid, String reason) _runTestcase(_Testcase testcase) {
  try {
    final verifier = X509Verifier();
    for (final pem in testcase.trustedCerts) {
      verifier.addTrustedCertificate(X509Certificate.fromPem(pem));
    }
    final result = verifier.verify(
      leaf: X509Certificate.fromPem(testcase.peerCertificate),
      intermediates: [
        for (final pem in testcase.untrustedIntermediates)
          X509Certificate.fromPem(pem),
      ],
      checkTime: testcase.validationTime,
      peerNames: testcase.peerNames,
      purpose: testcase.purpose,
      maxIntermediates: testcase.maxChainDepth,
    );
    return (result.isValid, _canonicalReason(result.errorMessage ?? _accepted));
  } on Exception catch (e) {
    return (false, 'the input could not be parsed: $e');
  }
}

/// The grouping key for [X509Verifier]'s weak signature digest rejection.
const _weakDigestReason = 'signed with a weak signature digest';

/// Collapses a reason into the key used to group and explain it.
///
/// The weak digest rejection names the offending algorithm, which would
/// otherwise split one explanation across a group per algorithm.
String _canonicalReason(String reason) =>
    reason.startsWith('certificate signed with the weak algorithm')
    ? _weakDigestReason
    : reason;

/// Why BoringSSL diverges from the suite, keyed by the reason it reports.
///
/// These are written by hand, from reading BoringSSL's sources and the
/// testcases themselves, and are emitted into the generated expected-failures
/// list so it explains itself. Add an entry here when a new reason appears.
const _divergenceNotes = <String, String>{
  'unsupported name constraint type':
      "BoringSSL's NAME_CONSTRAINTS_check (crypto/x509/v3_ncons.cc) handles "
      'only directoryName, dNSName, rfc822Name and uniformResourceIdentifier '
      'constraints, and returns X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE for '
      'every other GeneralName type. The BetterTLS name constraints suite is '
      'built almost entirely on iPAddress constraints, so it trips this on '
      'both the permitted and the excluded path. Supporting these would mean '
      'reimplementing name constraint checking in Dart, which is out of scope '
      'for a thin wrapper.',
  _accepted:
      'BoringSSL accepted a chain the suite expects to be rejected. Most of '
      'these encode CA/Browser Forum baseline requirements, or deliberately '
      'pedantic readings of RFC 5280, that BoringSSL does not enforce: it is '
      'an RFC 5280 path validator and leaves CABF profile checks to the '
      'caller. Examples: requiring the subject common name to be a '
      'character-for-character copy of a SAN entry, forbidding '
      'anyExtendedKeyUsage, forbidding a critical extKeyUsage, requiring an '
      'authorityKeyIdentifier on every certificate, and rejecting key usage '
      'bits that a given key type cannot honour. The two RSA-2052 cases are '
      'a deliberate omission rather than a gap: CABF requires the modulus '
      'size to be divisible by 8, but RSA-2052 is stronger than the RSA-2048 '
      'the same profile permits, so X509Verifier\'s key strength check, which '
      'is about strength rather than profile conformance, does not enforce '
      'it.',
  'unable to get local issuer certificate': _noBacktrackingNote,
  'unable to get issuer certificate': _noBacktrackingNote,
  'invalid CA certificate': _noBacktrackingNote,
  'permitted subtree violation': _noBacktrackingNote,
  'excluded subtree violation': _noBacktrackingNote,
  _weakDigestReason: _noBacktrackingNote,
  'unsupported certificate purpose':
      "The leaf's key usage or extended key usage does not satisfy the "
      'requested purpose. This harness maps the testcase validation_kind onto '
      'X509Purpose.tlsServer or X509Purpose.tlsClient, so BoringSSL applies '
      'the TLS key usage check to the leaf. Two of these put a CA certificate '
      'in the leaf position, which RFC 5280 permits but which then asserts '
      'keyCertSign rather than a TLS key usage. The two '
      'bettertls::pathbuilding cases are instead the chain building '
      'limitation described in another group: the purpose check fails on a '
      'branch a backtracking validator would not have chosen.',
  'certificate has expired':
      'BoringSSL treats notAfter as exclusive. X509_cmp_time_posix '
      '(crypto/x509/x509_vfy.cc) reports expiry when the certificate time '
      'minus the comparison time is <= 0, so validating at exactly notAfter '
      'fails. RFC 5280 4.1.2.5 defines notAfter as inclusive. The second case '
      'validates five milliseconds past notAfter, which X509Verifier '
      'truncates to whole seconds, producing the same comparison.',
};

/// Shared explanation for the whole family of chain building divergences.
const _noBacktrackingNote =
    'BoringSSL does not backtrack when a subject has more than one candidate '
    'issuer certificate. It commits to the first candidate it finds and '
    'reports whatever goes wrong down that branch, instead of retrying the '
    'alternative. bettertls::pathbuilding::tc52 is the clearest example: the '
    'intermediate "B" appears twice, once issued by "C" with CA:TRUE and once '
    'issued by "A" with CA:FALSE. BoringSSL picks the CA:FALSE certificate '
    'and stops, even though the other branch chains to the trust root. The '
    'same limitation produces the cross-signed cycle failure in '
    'cve::cve-2024-0567, the name constraint violations here are reported '
    'against a branch the suite does not expect a validator to choose, and '
    'the weak signature digest rejections here are on branches where an '
    'ecdsa-with-SHA1 cross-signature exists alongside an ecdsa-with-SHA256 '
    'one.';

/// Fallback used if a new reason appears before someone documents it.
const _undocumentedNote =
    'No explanation has been written for this reason yet. Investigate before '
    'accepting these entries: add a note to _divergenceNotes in '
    'test/conformance/x509_limbo_test.dart.';

const _expectedFailuresHeader = '''
# Testcases from https://x509-limbo.com where BoringSSL, as exposed by
# package:boring, disagrees with the suite's expected result.
#
# Every entry is a difference in scope between BoringSSL and the suite, not a
# known bug in this package. Entries are grouped below by explanation, since
# one underlying limitation can surface as several different errors. Each
# group lists the errors BoringSSL reported and why they are expected.
#
# The suite fails both on a divergence that is not listed here and on a listed
# testcase that starts agreeing, so this list cannot silently go stale.
#
# Generated. Regenerate with:
#   X509_LIMBO_REGENERATE=1 ./tool/run_x509_limbo_tests.sh
''';

/// Greedily wraps [text] to [width] columns.
List<String> _wrap(String text, int width) {
  final lines = <String>[];
  var line = StringBuffer();
  for (final word in text.split(' ')) {
    if (line.isNotEmpty && line.length + 1 + word.length > width) {
      lines.add(line.toString());
      line = StringBuffer();
    }
    if (line.isNotEmpty) line.write(' ');
    line.write(word);
  }
  if (line.isNotEmpty) lines.add(line.toString());
  return lines;
}

/// Condenses a limbo description into a one-line trailing comment.
///
/// Returns null when the description carries no information, which is the case
/// for the BetterTLS testcases: they are all "Testcase `N` from the BetterTLS
/// `<suite>` suite."
String? _summarize(String description) {
  var text = description
      // Descriptions embed a fenced ASCII diagram of the chain.
      .replaceAll(RegExp('```.*?```', dotAll: true), '')
      .replaceAll(RegExp(r'\s+'), ' ')
      // '#' would start a comment, and descriptions use it for headings.
      .replaceAll('#', '')
      .trim()
      // Every description opens by introducing the diagram removed above.
      .replaceFirst(RegExp(r'^Produces the following [^:]*:\s*'), '');
  if (text.startsWith('Testcase ')) return null;
  final end = text.indexOf(RegExp(r'\.(\s|$)'));
  if (end > 0) text = text.substring(0, end + 1);
  if (text.length > 100) text = '${text.substring(0, 97)}...';
  return text.isEmpty ? null : text;
}

/// Renders the expected-failures list, grouped and annotated.
///
/// Grouping is by explanation rather than by BoringSSL's error string: one
/// underlying limitation can surface as several different errors, and the
/// explanation is worth reading once rather than five times.
String _renderExpectedFailures(
  List<(String id, String reason)> diverged,
  Map<String, String> descriptions,
) {
  final byNote = <String, List<(String id, String reason)>>{};
  for (final entry in diverged) {
    byNote
        .putIfAbsent(_divergenceNotes[entry.$2] ?? _undocumentedNote, () => [])
        .add(entry);
  }
  // Largest groups first, so the dominant cause is the first thing read.
  final notes = byNote.keys.toList()
    ..sort((a, b) {
      final byCount = byNote[b]!.length.compareTo(byNote[a]!.length);
      return byCount != 0 ? byCount : a.compareTo(b);
    });

  final out = StringBuffer(_expectedFailuresHeader);
  for (final note in notes) {
    final entries = byNote[note]!..sort((a, b) => a.$1.compareTo(b.$1));
    final counts = <String, int>{};
    for (final (_, reason) in entries) {
      counts[reason] = (counts[reason] ?? 0) + 1;
    }
    final reasons = counts.keys.toList()
      ..sort((a, b) => counts[b]!.compareTo(counts[a]!));

    out
      ..writeln()
      ..writeln('# ${'=' * 75}')
      ..writeln('# ${entries.length} testcase(s):');
    for (final reason in reasons) {
      final what = reason == _accepted
          ? 'accepted, but the suite expects rejection'
          : 'rejected with "$reason"';
      out.writeln('#   ${counts[reason]} x $what');
    }
    out.writeln('# ${'-' * 75}');
    for (final line in _wrap(note, 74)) {
      out.writeln('# $line');
    }
    out.writeln();

    // Only worth tagging each entry when the group spans several errors.
    final tagReason = reasons.length > 1;
    for (final (id, reason) in entries) {
      final parts = <String>[
        if (tagReason && reason != _accepted) reason,
        ?_summarize(descriptions[id] ?? ''),
      ];
      out.writeln(parts.isEmpty ? id : '$id  # ${parts.join('; ')}');
    }
  }
  return out.toString();
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
    final diverged = <(String id, String reason)>[];
    var ran = 0;

    for (final namespace in byNamespace.keys.toList()..sort()) {
      final namespaceCases = byNamespace[namespace]!;
      test('$namespace (${namespaceCases.length} testcases)', () {
        final unexpected = <String>[];
        final unexpectedlyPassing = <String>[];

        for (final testcase in namespaceCases) {
          if (testcase.isSkipped) continue;
          ran++;
          final (valid, reason) = _runTestcase(testcase);
          final agrees = valid == testcase.expectSuccess;
          if (!agrees) diverged.add((testcase.id, reason));

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
      expectedFailuresFile.writeAsStringSync(
        _renderExpectedFailures(diverged, {
          for (final testcase in testcases)
            testcase.id: testcase.json['description'] as String,
        }),
      );
      // ignore: avoid_print
      print(
        'Wrote ${diverged.length} divergences to ${expectedFailuresFile.path}',
      );
    });
  });
}
