// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:boring/crypto.dart';
import 'package:test/test.dart';

Uint8List _hexDecode(String hex) {
  if (hex.isEmpty) return Uint8List(0);
  final clean = hex.length.isOdd ? '0$hex' : hex;
  final result = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

String _hexEncode(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Directory? _findWycheproofDir() {
  final env = Platform.environment['WYCHEPROOF_DIR'];
  if (env != null && Directory(env).existsSync()) {
    return Directory(env);
  }

  const candidates = [
    'build/wycheproof/testvectors_v1',
    '../build/wycheproof/testvectors_v1',
    '/tmp/wycheproof/testvectors_v1',
  ];

  for (final candidate in candidates) {
    final d = Directory(candidate);
    if (d.existsSync()) return d;
  }
  return null;
}

Map<String, dynamic> _readJson(File file) =>
    jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;

List<Map<String, dynamic>> _castList(dynamic list) =>
    (list as List).cast<Map<String, dynamic>>();

void main() {
  final wycheproofDir = _findWycheproofDir();

  group('Project Wycheproof Conformance', () {
    if (wycheproofDir == null) {
      test(
        'Wycheproof test vectors available',
        () {},
        skip:
            'Wycheproof test vectors not found. '
            'Run ./tool/run_conformance_tests.sh to clone and run the suite.',
      );
      return;
    }

    group('HKDF', () {
      final suites = [
        ('hkdf_sha256_test.json', HashAlgorithm.sha256),
        ('hkdf_sha384_test.json', HashAlgorithm.sha384),
        ('hkdf_sha512_test.json', HashAlgorithm.sha512),
      ];

      for (final (filename, algorithm) in suites) {
        test(filename, () {
          final file = File('${wycheproofDir.path}/$filename');
          final data = _readJson(file);
          final groups = _castList(data['testGroups']);

          for (final group in groups) {
            final tests = _castList(group['tests']);
            for (final testCase in tests) {
              final ikm = _hexDecode(testCase['ikm'] as String);
              final salt = _hexDecode(testCase['salt'] as String);
              final info = _hexDecode(testCase['info'] as String);
              final size = testCase['size'] as int;
              final expectedOkm = testCase['okm'] as String;
              final expectedResult = testCase['result'] as String;

              try {
                final okm = BoringHkdf.deriveBits(
                  algorithm: algorithm,
                  ikm: ikm,
                  salt: salt.isEmpty ? null : salt,
                  info: info.isEmpty ? null : info,
                  length: size,
                );
                expect(
                  expectedResult,
                  equals('valid'),
                  reason: 'Test ${testCase['tcId']} expected $expectedResult',
                );
                expect(
                  _hexEncode(okm),
                  equals(expectedOkm),
                  reason: 'Test ${testCase['tcId']} OKM mismatch',
                );
              } catch (_) {
                expect(
                  expectedResult,
                  isNot('valid'),
                  reason: 'Test ${testCase['tcId']} failed unexpectedly',
                );
              }
            }
          }
        });
      }
    });

    group('HMAC', () {
      final suites = [
        ('hmac_sha256_test.json', HashAlgorithm.sha256, 256),
        ('hmac_sha384_test.json', HashAlgorithm.sha384, 384),
        ('hmac_sha512_test.json', HashAlgorithm.sha512, 512),
      ];

      for (final (filename, algorithm, expectedTagBits) in suites) {
        test(filename, () {
          final file = File('${wycheproofDir.path}/$filename');
          final data = _readJson(file);
          final groups = _castList(data['testGroups']);

          for (final group in groups) {
            if ((group['tagSize'] as int) != expectedTagBits) continue;

            final tests = _castList(group['tests']);
            for (final testCase in tests) {
              final key = _hexDecode(testCase['key'] as String);
              final msg = _hexDecode(testCase['msg'] as String);
              final expectedTag = testCase['tag'] as String;
              final expectedResult = testCase['result'] as String;

              try {
                final mac = BoringHmac.compute(
                  algorithm: algorithm,
                  key: key,
                  data: msg,
                );
                if (expectedResult == 'valid') {
                  expect(
                    _hexEncode(mac),
                    equals(expectedTag),
                    reason: 'Test ${testCase['tcId']} tag mismatch',
                  );
                } else {
                  expect(
                    _hexEncode(mac),
                    isNot(equals(expectedTag)),
                    reason: 'Test ${testCase['tcId']} invalid tag matched',
                  );
                }
              } catch (_) {
                expect(
                  expectedResult,
                  isNot('valid'),
                  reason: 'Test ${testCase['tcId']} failed unexpectedly',
                );
              }
            }
          }
        });
      }
    });

    group('AEAD', () {
      test('AES-GCM (128 & 256-bit)', () {
        final file = File('${wycheproofDir.path}/aes_gcm_test.json');
        final data = _readJson(file);
        final groups = _castList(data['testGroups']);

        for (final group in groups) {
          final ivSize = group['ivSize'] as int;
          final keySize = group['keySize'] as int;
          final tagSize = group['tagSize'] as int;

          // Standard GCM: 96-bit nonce, 128-bit tag
          if (ivSize != 96 || tagSize != 128) continue;

          final alg = keySize == 128
              ? AeadAlgorithm.aes128Gcm
              : keySize == 256
              ? AeadAlgorithm.aes256Gcm
              : null;
          if (alg == null) continue;

          final tests = _castList(group['tests']);
          for (final testCase in tests) {
            final key = _hexDecode(testCase['key'] as String);
            final iv = _hexDecode(testCase['iv'] as String);
            final aad = _hexDecode(testCase['aad'] as String);
            final ct = _hexDecode(
              (testCase['ct'] as String) + (testCase['tag'] as String),
            );
            final expectedResult = testCase['result'] as String;

            try {
              final cipher = BoringAead(alg, key);
              final decrypted = cipher.open(
                nonce: iv,
                ciphertext: ct,
                additionalData: aad.isEmpty ? null : aad,
              );
              expect(
                expectedResult,
                equals('valid'),
                reason: 'Test ${testCase['tcId']} unexpected success',
              );
              expect(_hexEncode(decrypted), equals(testCase['msg']));
            } catch (_) {
              expect(
                expectedResult,
                isNot('valid'),
                reason: 'Test ${testCase['tcId']} unexpected failure',
              );
            }
          }
        }
      });

      test('ChaCha20-Poly1305', () {
        final file = File('${wycheproofDir.path}/chacha20_poly1305_test.json');
        final data = _readJson(file);
        final groups = _castList(data['testGroups']);

        for (final group in groups) {
          final ivSize = group['ivSize'] as int;
          final tagSize = group['tagSize'] as int;
          if (ivSize != 96 || tagSize != 128) continue;

          final tests = _castList(group['tests']);
          for (final testCase in tests) {
            final key = _hexDecode(testCase['key'] as String);
            final iv = _hexDecode(testCase['iv'] as String);
            final aad = _hexDecode(testCase['aad'] as String);
            final ct = _hexDecode(
              (testCase['ct'] as String) + (testCase['tag'] as String),
            );
            final expectedResult = testCase['result'] as String;

            try {
              final cipher = BoringAead(AeadAlgorithm.chacha20Poly1305, key);
              final decrypted = cipher.open(
                nonce: iv,
                ciphertext: ct,
                additionalData: aad.isEmpty ? null : aad,
              );
              expect(expectedResult, equals('valid'));
              expect(_hexEncode(decrypted), equals(testCase['msg']));
            } catch (_) {
              expect(expectedResult, isNot('valid'));
            }
          }
        }
      });

      test('XChaCha20-Poly1305', () {
        final file = File('${wycheproofDir.path}/xchacha20_poly1305_test.json');
        final data = _readJson(file);
        final groups = _castList(data['testGroups']);

        for (final group in groups) {
          final ivSize = group['ivSize'] as int;
          final tagSize = group['tagSize'] as int;
          if (ivSize != 192 || tagSize != 128) continue;

          final tests = _castList(group['tests']);
          for (final testCase in tests) {
            final key = _hexDecode(testCase['key'] as String);
            final iv = _hexDecode(testCase['iv'] as String);
            final aad = _hexDecode(testCase['aad'] as String);
            final ct = _hexDecode(
              (testCase['ct'] as String) + (testCase['tag'] as String),
            );
            final expectedResult = testCase['result'] as String;

            try {
              final cipher = BoringAead(AeadAlgorithm.xchacha20Poly1305, key);
              final decrypted = cipher.open(
                nonce: iv,
                ciphertext: ct,
                additionalData: aad.isEmpty ? null : aad,
              );
              expect(expectedResult, equals('valid'));
              expect(_hexEncode(decrypted), equals(testCase['msg']));
            } catch (_) {
              expect(expectedResult, isNot('valid'));
            }
          }
        }
      });
    });

    group('Ed25519', () {
      test('ed25519_test.json', () {
        final file = File('${wycheproofDir.path}/ed25519_test.json');
        final data = _readJson(file);
        final groups = _castList(data['testGroups']);

        for (final group in groups) {
          final pubDer = _hexDecode(group['publicKeyDer'] as String);
          BoringPublicKey? pubKey;
          try {
            pubKey = BoringPublicKey.fromDer(pubDer);
          } catch (_) {}

          final tests = _castList(group['tests']);
          for (final testCase in tests) {
            final msg = _hexDecode(testCase['msg'] as String);
            final sig = _hexDecode(testCase['sig'] as String);
            final expectedResult = testCase['result'] as String;

            var valid = false;
            if (pubKey != null && sig.length == 64) {
              try {
                valid = pubKey.verify(data: msg, signature: sig);
              } catch (_) {
                valid = false;
              }
            }

            if (expectedResult == 'valid') {
              expect(
                valid,
                isTrue,
                reason:
                    'Test ${testCase['tcId']} expected valid signature: '
                    '${testCase['comment']}',
              );
            } else if (expectedResult == 'invalid') {
              expect(
                valid,
                isFalse,
                reason:
                    'Test ${testCase['tcId']} accepted invalid signature: '
                    '${testCase['comment']}',
              );
            }
          }
        }
      });
    });

    group('ECDSA', () {
      final suites = [
        ('ecdsa_secp256r1_sha256_test.json', HashAlgorithm.sha256),
        ('ecdsa_secp384r1_sha384_test.json', HashAlgorithm.sha384),
        ('ecdsa_secp521r1_sha512_test.json', HashAlgorithm.sha512),
      ];

      for (final (filename, algorithm) in suites) {
        test(filename, () {
          final file = File('${wycheproofDir.path}/$filename');
          final data = _readJson(file);
          final groups = _castList(data['testGroups']);

          for (final group in groups) {
            final pubDer = _hexDecode(group['publicKeyDer'] as String);
            BoringPublicKey? pubKey;
            try {
              pubKey = BoringPublicKey.fromDer(pubDer);
            } catch (_) {}

            final tests = _castList(group['tests']);
            for (final testCase in tests) {
              final msg = _hexDecode(testCase['msg'] as String);
              final sig = _hexDecode(testCase['sig'] as String);
              final expectedResult = testCase['result'] as String;

              var valid = false;
              if (pubKey != null) {
                try {
                  valid = pubKey.verify(
                    algorithm: algorithm,
                    data: msg,
                    signature: sig,
                  );
                } catch (_) {
                  valid = false;
                }
              }

              if (expectedResult == 'valid') {
                expect(
                  valid,
                  isTrue,
                  reason:
                      'Test ${testCase['tcId']} expected valid signature: '
                      '${testCase['comment']}',
                );
              } else if (expectedResult == 'invalid') {
                expect(
                  valid,
                  isFalse,
                  reason: 'Test ${testCase['tcId']} accepted invalid signature',
                );
              }
            }
          }
        });
      }
    });

    group('RSA PKCS#1 v1.5 Signatures', () {
      final suites = [
        'rsa_signature_2048_sha256_test.json',
        'rsa_signature_3072_sha256_test.json',
        'rsa_signature_4096_sha256_test.json',
      ];

      for (final filename in suites) {
        test(filename, () {
          final file = File('${wycheproofDir.path}/$filename');
          final data = _readJson(file);
          final groups = _castList(data['testGroups']);

          for (final group in groups) {
            final pubDer = _hexDecode(group['publicKeyDer'] as String);
            BoringPublicKey? pubKey;
            try {
              pubKey = BoringPublicKey.fromDer(pubDer);
            } catch (_) {}

            final tests = _castList(group['tests']);
            for (final testCase in tests) {
              final msg = _hexDecode(testCase['msg'] as String);
              final sig = _hexDecode(testCase['sig'] as String);
              final expectedResult = testCase['result'] as String;

              var valid = false;
              if (pubKey != null) {
                try {
                  valid = pubKey.verify(
                    algorithm: HashAlgorithm.sha256,
                    data: msg,
                    signature: sig,
                  );
                } catch (_) {
                  valid = false;
                }
              }

              if (expectedResult == 'valid') {
                expect(
                  valid,
                  isTrue,
                  reason: 'Test ${testCase['tcId']} expected valid signature',
                );
              } else if (expectedResult == 'invalid') {
                expect(
                  valid,
                  isFalse,
                  reason: 'Test ${testCase['tcId']} accepted invalid signature',
                );
              }
            }
          }
        });
      }
    });
  });
}
