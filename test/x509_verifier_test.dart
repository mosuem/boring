// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'package:boring/x509.dart';
import 'package:test/test.dart';

/// Self-signed P-256 root, `CN=Boring Test Root CA`.
const rootPem = '''
-----BEGIN CERTIFICATE-----
MIIBxjCCAW2gAwIBAgIUW0pmw/J3KxU1pMHi1MZiEQ4PPqYwCgYIKoZIzj0EAwIw
MTEcMBoGA1UEAwwTQm9yaW5nIFRlc3QgUm9vdCBDQTERMA8GA1UECgwIVGVzdCBP
cmcwHhcNMjYwOTExMDkxOTE4WhcNNDYwOTA2MDkxOTE4WjAxMRwwGgYDVQQDDBNC
b3JpbmcgVGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABG3g8WPAE95tfwHuQXJmiGqWNaQGJ1pWnS0J3JCZxxca
kfMBIffiPQ0drrXKNttX5Vw4+FvZ19cVHhD8uf/Vk1OjYzBhMB0GA1UdDgQWBBS6
hoM/Erlt3T9YBtRWLCOPeyP5SjAfBgNVHSMEGDAWgBS6hoM/Erlt3T9YBtRWLCOP
eyP5SjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQD
AgNHADBEAiAB0P6f9NQWWkfkyBYOS6JLyu/PKMGJBLpdnxKFUgi/HAIgC3jgcYYe
OQWQNCc91uO3v+vyjLIbyJ/1klA3A2/Ttm4=
-----END CERTIFICATE-----
''';

/// Intermediate CA signed by [rootPem], `CN=Boring Test ICA`.
const intermediatePem = '''
-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIBAjAKBggqhkjOPQQDAjAxMRwwGgYDVQQDDBNCb3Jpbmcg
VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjA5MTEwOTE5MTha
Fw00NjA5MDYwOTE5MThaMC0xGDAWBgNVBAMMD0JvcmluZyBUZXN0IElDQTERMA8G
A1UECgwIVGVzdCBPcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3FQdtF3k5
ocZqWmFDDMLTAgiejN2aHfjdMvdSQifXAZZQfCGgf9IQe/yoEY/+Z9GJ6DOrJLIG
ouzKxIHo5vmfo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAd
BgNVHQ4EFgQUh7HrO4nST6dnKQgpKwXCAyGNymAwHwYDVR0jBBgwFoAUuoaDPxK5
bd0/WAbUViwjj3sj+UowCgYIKoZIzj0EAwIDSAAwRQIgCCZbDqTXX7x2o/KZxmxb
ZDFq9WEFomaOogB/V9p7uSACIQDUTQ/BdkN1xuFkqxpIfk0WPyIhpxjsSwKSMksR
We9uYA==
-----END CERTIFICATE-----
''';

/// End-entity certificate signed by [intermediatePem].
///
/// `SAN: DNS:leaf.example.com, DNS:*.wild.example.com, IP:127.0.0.1,
/// email:test@example.com`, `EKU: serverAuth`,
/// `KU: digitalSignature, keyEncipherment`.
const leafPem = '''
-----BEGIN CERTIFICATE-----
MIIB+DCCAZ2gAwIBAgIBAzAKBggqhkjOPQQDAjAtMRgwFgYDVQQDDA9Cb3Jpbmcg
VGVzdCBJQ0ExETAPBgNVBAoMCFRlc3QgT3JnMB4XDTI2MDkxMTA5MTkxOFoXDTQ2
MDkwNjA5MTkxOFowGzEZMBcGA1UEAwwQbGVhZi5leGFtcGxlLmNvbTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABM9SqKQkGZPn+5GXi6nQ+PI7BK1eLRNj9Ci2f6mM
Kh9nD4MnwCVpqXqmf2uhZVplDS04MpXL3bIPuq8MtMhR9Mejgb8wgbwwDAYDVR0T
AQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwRwYD
VR0RBEAwPoIQbGVhZi5leGFtcGxlLmNvbYISKi53aWxkLmV4YW1wbGUuY29thwR/
AAABgRB0ZXN0QGV4YW1wbGUuY29tMB0GA1UdDgQWBBShFEIcgtg9qmFGmxO9mDgl
IwcWdzAfBgNVHSMEGDAWgBSHses7idJPp2cpCCkrBcIDIY3KYDAKBggqhkjOPQQD
AgNJADBGAiEApppnZDBIbwI/+ROljIunf/ZYhH77D/JM3pDmK7fndGICIQCzdDoE
vLBatdRQJrZT3MJEa8K8R6JI9v66DHtWbq0v3A==
-----END CERTIFICATE-----
''';

/// Self-signed P-256 root signed with `ecdsa-with-SHA1`,
/// `CN=Boring SHA1 Root CA`.
const sha1RootPem = '''
-----BEGIN CERTIFICATE-----
MIIBxjCCAWygAwIBAgIUKxP5KkPIULCvP/UHqUjSjEUT+aEwCQYHKoZIzj0EATAx
MRwwGgYDVQQDDBNCb3JpbmcgU0hBMSBSb290IENBMREwDwYDVQQKDAhUZXN0IE9y
ZzAeFw0yNjA5MTExMTUzNTVaFw00NjA5MDYxMTUzNTVaMDExHDAaBgNVBAMME0Jv
cmluZyBTSEExIFJvb3QgQ0ExETAPBgNVBAoMCFRlc3QgT3JnMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEYpjWi1r1wBTl91bnDGSAOU7kbJIB9qqayXJyYbdrVBs7
2GsVR+QMChohU84Qdx5IBp3s/jspPqd0Lm3lddnghaNjMGEwHQYDVR0OBBYEFHH7
rTmDCXc1CveoZE0I6ZIc/Y6DMB8GA1UdIwQYMBaAFHH7rTmDCXc1CveoZE0I6ZIc
/Y6DMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAkGByqGSM49BAED
SQAwRgIhAMCO32SYRZmRsroUh6x7A9tCh+aZKTmNyx1Gia7PmLXOAiEA+uwfQ4yn
3qBwZOxoIFXt3n9tWTpdKk+IqS8PBuHb15k=
-----END CERTIFICATE-----
''';

/// End-entity certificate signed by [sha1RootPem] with `ecdsa-with-SHA1`.
const sha1LeafPem = '''
-----BEGIN CERTIFICATE-----
MIIBzTCCAXSgAwIBAgIBAjAJBgcqhkjOPQQBMDExHDAaBgNVBAMME0JvcmluZyBT
SEExIFJvb3QgQ0ExETAPBgNVBAoMCFRlc3QgT3JnMB4XDTI2MDkxMTExNTM1NVoX
DTQ2MDkwNjExNTM1NVowGzEZMBcGA1UEAwwQbGVhZi5leGFtcGxlLmNvbTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABJt1EwjknCYa/bWDm9Hpz6Jh/Sm5kWJXwxkY
vmZbyCz1J9JpRf+fmBEUybmo3AP0SBhHvAgWMs1bc/DtIrIztPOjgZMwgZAwDAYD
VR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
GwYDVR0RBBQwEoIQbGVhZi5leGFtcGxlLmNvbTAdBgNVHQ4EFgQUOR3253bSc8CX
ZF4eCtjaP4dWxEUwHwYDVR0jBBgwFoAUcfutOYMJdzUK96hkTQjpkhz9joMwCQYH
KoZIzj0EAQNIADBFAiEAu2lSN/dZp6rB4YCvotwP0zbQE3V15GpZcfUFFM/typIC
ICrhQxRhkH/v7aM7IpYmLBxnY8QZkqe4/56xM3rJ/JNI
-----END CERTIFICATE-----
''';

/// End-entity certificate signed by [sha1RootPem] with `ecdsa-with-SHA256`.
///
/// Used to check that the trust anchor's own weak self-signature is exempt.
const sha256LeafOfSha1RootPem = '''
-----BEGIN CERTIFICATE-----
MIIBzjCCAXWgAwIBAgIBAzAKBggqhkjOPQQDAjAxMRwwGgYDVQQDDBNCb3Jpbmcg
U0hBMSBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzAeFw0yNjA5MTExMTUzNTVa
Fw00NjA5MDYxMTUzNTVaMBsxGTAXBgNVBAMMEGxlYWYuZXhhbXBsZS5jb20wWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAASbdRMI5JwmGv21g5vR6c+iYf0puZFiV8MZ
GL5mW8gs9SfSaUX/n5gRFMm5qNwD9EgYR7wIFjLNW3Pw7SKyM7Tzo4GTMIGQMAwG
A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MBsGA1UdEQQUMBKCEGxlYWYuZXhhbXBsZS5jb20wHQYDVR0OBBYEFDkd9ud20nPA
l2ReHgrY2j+HVsRFMB8GA1UdIwQYMBaAFHH7rTmDCXc1CveoZE0I6ZIc/Y6DMAoG
CCqGSM49BAMCA0cAMEQCIEydh5Fb7GAcdyiTWr1ErHFP3adqYPxq4YHyiWZuVsnK
AiBn4k6/QhB2xgYO1xdXJRlxWYkBB+f0u0YQZ/q//xWYGw==
-----END CERTIFICATE-----
''';

/// Self-signed RSA-2048 root, `CN=Boring strongRoot`.
///
/// Issues [rsa1024LeafPem], [p224LeafPem] and [ed25519LeafPem], so that each
/// leaf's key is the only weak thing in its chain.
const strongRootPem = '''
-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIUXboWGtdQOpL8LXBvmj5eS/1EHpUwDQYJKoZIhvcNAQEL
BQAwLzEaMBgGA1UEAwwRQm9yaW5nIHN0cm9uZ1Jvb3QxETAPBgNVBAoMCFRlc3Qg
T3JnMB4XDTI2MDkxMTEyMTQwM1oXDTQ2MDkwNjEyMTQwM1owLzEaMBgGA1UEAwwR
Qm9yaW5nIHN0cm9uZ1Jvb3QxETAPBgNVBAoMCFRlc3QgT3JnMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEArdmkESZO/V05cmrtpbtH2Ac2SnHtAk/w1Rhb
TQzNQuA4xiMuEUWKwCkEZU/kzhEuBhl4nXFWIPjHAovyDmc9mh+w8vl7xHibgp5D
FXqiu1m24SFZT3In7enlDAn/z2OvL1VOhemK+yvGZlPVfELwenKiQtZ7Q5dR36r1
cpbmmP2wtcNKBHhUY9OgxVmah7ujGp6caPo2XK9krGo4tpcPb+WzS7Xz03ZiB0Nl
GtSDh+ivDZ9riV4GhZs9rpfRRPIWgZETTsr/n2oXcodrQtPEJfe6rWzoFTQh1UfN
Q01sJkwgMv+u19XpEy/eRoYBdyFzHFc1SNnOaQLazaTIyqVw1QIDAQABo2MwYTAd
BgNVHQ4EFgQUVybUMWi2VsMwqcf9sN1EQ+TDLmcwHwYDVR0jBBgwFoAUVybUMWi2
VsMwqcf9sN1EQ+TDLmcwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
DQYJKoZIhvcNAQELBQADggEBAC/r7CW5r6sRApxZxWbx2+B12F/Ohbjtay4J6im2
ogIDmE48SMHkcyS12FVnBlmRD5ucRicFrT/uOaDclhyrEYS5tIbzO0HWaBpElcKR
ZJAf7YO2utIeTuSeMc/X1j95amySk+ZVR42EG3a9Z4GsWV1UWi0ZDDRSqlTJUX0Q
5i4S09UDLjA40bPnWfaxIvBJ5Q4zh5+I4rGjMSSHRpm3hLYp/jZr5xjErVwDYbdx
20StHxlOoSkfvnaGXdyZU9X3gQgzrYsbeX9VBW6QSAhfIrSPUsBg/GCCI83fpY7M
DFA/g+QWEo9yS65EgMOAddSzBDwkMU/vKTvbL1dPspWL5mk=
-----END CERTIFICATE-----
''';

/// Self-signed RSA-1024 root, `CN=Boring weakRoot`. Issues [p256LeafPem].
///
/// Every certificate below it is strong, so this isolates the trust anchor's
/// own key.
const weakRootPem = '''
-----BEGIN CERTIFICATE-----
MIICRjCCAa+gAwIBAgIUdV7tmSfXLDoK5qAzzr3o+jaaJVAwDQYJKoZIhvcNAQEL
BQAwLTEYMBYGA1UEAwwPQm9yaW5nIHdlYWtSb290MREwDwYDVQQKDAhUZXN0IE9y
ZzAeFw0yNjA5MTExMjE0MDNaFw00NjA5MDYxMjE0MDNaMC0xGDAWBgNVBAMMD0Jv
cmluZyB3ZWFrUm9vdDERMA8GA1UECgwIVGVzdCBPcmcwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBANbQcuQ8h3kW9HwVl7ARwwaHc7igHya9fpAubaMRmJtvRCFL
HZG3kknaSrjOR9GaQ/C1FtXQyVwV1wUik3+t7LgXFOjuuTilhjjGYgWXuV8X+i84
h+RDI4yWszJ3QHP44XdXndIC0L83knCAOEptPQcEdNNR4l1re3msXvH2cEDPAgMB
AAGjYzBhMB0GA1UdDgQWBBTji+haT9kucH/2UIrwuX2OPjgFaDAfBgNVHSMEGDAW
gBTji+haT9kucH/2UIrwuX2OPjgFaDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOBgQCdPwHJN+DzsVs5OS47R/vpjqhaVrml
IMd23fukNeiZKaud0FVQnvmUtzxLQK1RksbrD6s6M8EfX23zGeVhVRjLtub5Svqb
+vaKra4FfCeSlAYr6lI6IBIXa6CozRbh0DzJqpudQYScm46agqF1W7Q2MR/dSt8l
mivo0Ezvr45VAA==
-----END CERTIFICATE-----
''';

/// End-entity certificate under [strongRootPem] conveying an RSA-1024 key.
const rsa1024LeafPem = '''
-----BEGIN CERTIFICATE-----
MIICvjCCAaagAwIBAgIBCzANBgkqhkiG9w0BAQsFADAvMRowGAYDVQQDDBFCb3Jp
bmcgc3Ryb25nUm9vdDERMA8GA1UECgwIVGVzdCBPcmcwHhcNMjYwOTExMTIxNDAz
WhcNNDYwOTA2MTIxNDAzWjAbMRkwFwYDVQQDDBBsZWFmLmV4YW1wbGUuY29tMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAfaHlztZ5SmMDVmLFOnj9w8fUBXBt
vayPu1NrxadNmfIztm6cyNk7to2pPpu8Izh0qpbgMhR/WrvLH0N1Gt91swUuQDm8
GugOvxy6qAzDr+F4CM7xjt89/o5IjUlEyfcR1ZXpEwoYZxRf05OKA5q2dHz0qQ1y
juwcFYNy2KWXJwIDAQABo30wezAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIH
gDAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMB0GA1UdDgQWBBT0jVBP2A+Q
SJYsTN8qZL7eRun3jjAfBgNVHSMEGDAWgBRXJtQxaLZWwzCpx/2w3URD5MMuZzAN
BgkqhkiG9w0BAQsFAAOCAQEAHFZROJ6xOzaly+wDxPlkbpjs4Pw8LhXvO3dFyI4v
ZzqFPU0uk+jJuTV3mV7mxYnVCIWn/U7TBLBnegUhyRPAK1ZtT3XtvGdZhWPwf7Mg
R9p6XsC1CpHMqJ480bgAP3Py1WMGX2jYM3V8kXJ8S21Fhy9+1cWFCMXyVhFFf8EZ
FMjXPnlIqyS6ppuFMkgorbdKwsl8V+uByldxiPn3ZwAcAeqzgSnw/Fcm3wH0qkj+
pdTXVOQD49keg5jTIINYXoUO36Wudkk4f7TxqYYtfnZzs198KugZqTFg40pQfDBy
MdeEiIYi+h2TiVpG62l/R1DK4s99dlve12OpVQ6bGpe1mA==
-----END CERTIFICATE-----
''';

/// End-entity certificate under [strongRootPem] conveying a P-224 key.
const p224LeafPem = '''
-----BEGIN CERTIFICATE-----
MIICbDCCAVSgAwIBAgIBDDANBgkqhkiG9w0BAQsFADAvMRowGAYDVQQDDBFCb3Jp
bmcgc3Ryb25nUm9vdDERMA8GA1UECgwIVGVzdCBPcmcwHhcNMjYwOTExMTIxNDAz
WhcNNDYwOTA2MTIxNDAzWjAbMRkwFwYDVQQDDBBsZWFmLmV4YW1wbGUuY29tME4w
EAYHKoZIzj0CAQYFK4EEACEDOgAEq60uyvII+Ul83fEVIidTX/81YelAi6AkKrxT
MTzwtyyo0MzuF1/+of6iTTIHQ64pDas56p0/7RyjfTB7MAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgeAMBsGA1UdEQQUMBKCEGxlYWYuZXhhbXBsZS5jb20wHQYD
VR0OBBYEFKPdvKQ0d8AOUz+fP82PDaBsGdTCMB8GA1UdIwQYMBaAFFcm1DFotlbD
MKnH/bDdREPkwy5nMA0GCSqGSIb3DQEBCwUAA4IBAQAXFtN3u5KMRpw3XKAqWyvB
OuRpdKVrd8TTTBLR7lwY3H7KgqtyZOoLvCgf4M0POSspGuMhH/wpE4dVMdn9Ny5k
Yh3BOJwYTOLSdi48QpLOAUWnsLs76MOOpcpo8vqkRlVNdhqCMXMywevx2ot/KxP2
dw62AwTsN+p7R7Nx0WA0cEnC6L7bbdx4dwYmarUnGHHAvqqZZX1WRUypSVSPiGNU
GYAOgzlmXQ0hD3UjYKeV5f6JJqPLfaKGsWwSMHLjFUo8+MdC28gT0GYIZXykRURs
RDTZsDggYVcDXOQgiTJIafZCJLUVEoK5TbMGLo2NS0wtOp2ZR15n+vFLd5yI1jKn
-----END CERTIFICATE-----
''';

/// End-entity certificate under [strongRootPem] conveying an Ed25519 key.
const ed25519LeafPem = '''
-----BEGIN CERTIFICATE-----
MIICSDCCATCgAwIBAgIBDTANBgkqhkiG9w0BAQsFADAvMRowGAYDVQQDDBFCb3Jp
bmcgc3Ryb25nUm9vdDERMA8GA1UECgwIVGVzdCBPcmcwHhcNMjYwOTExMTIxNDAz
WhcNNDYwOTA2MTIxNDAzWjAbMRkwFwYDVQQDDBBsZWFmLmV4YW1wbGUuY29tMCow
BQYDK2VwAyEAjl08xnD20bHikm29g8vP2ok2dRkw+7f8w6tS7aUgcwijfTB7MAwG
A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBsGA1UdEQQUMBKCEGxlYWYuZXhh
bXBsZS5jb20wHQYDVR0OBBYEFLiX0RjAyLVQqcrV21zyb3uiU4iMMB8GA1UdIwQY
MBaAFFcm1DFotlbDMKnH/bDdREPkwy5nMA0GCSqGSIb3DQEBCwUAA4IBAQAGvVR2
oY9FaFufxt9GF1U7eXVuN/V5KL7N/CgVqNN362vVd7dEybfoih6E7q7Jq8ZFtAJ2
rF391E/VNsWMld2/1vw/TE5Y+zdrl9bRM8j/M4JvX4YQJJLkM9Caa0uRL5eQLzCd
chGzRhvmwK2611cpNhc5/XayuEygYi5/JmDvfV/1ZgUnEB5L+6+CNSr3rH3+WPVW
bvNXwjjYYOJJVG8iUy8BNTYpNgjAefr3MF/jdCHLqyiMRSlWbHUgFtDqpybCsSoH
/c4F7Oe8u9smAFqhdaKo28rnGGqoxMdynbp7TH4DDplK0YVqiW/eivkXGT0bKKm7
58yL/1HEWBqaFndE
-----END CERTIFICATE-----
''';

/// End-entity certificate under [weakRootPem] conveying a strong P-256 key.
const p256LeafPem = '''
-----BEGIN CERTIFICATE-----
MIIB9DCCAV2gAwIBAgIBDjANBgkqhkiG9w0BAQsFADAtMRgwFgYDVQQDDA9Cb3Jp
bmcgd2Vha1Jvb3QxETAPBgNVBAoMCFRlc3QgT3JnMB4XDTI2MDkxMTEyMTQwM1oX
DTQ2MDkwNjEyMTQwM1owGzEZMBcGA1UEAwwQbGVhZi5leGFtcGxlLmNvbTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLtmgAjitXSMKbyW0yK93WLwGGfKLu+yM6yc
NAIKAVM+sQuCndiC+7PvNrZ7HgZPaURNq+8Zxaf/mfaQyuRREl+jfTB7MAwGA1Ud
EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBsGA1UdEQQUMBKCEGxlYWYuZXhhbXBs
ZS5jb20wHQYDVR0OBBYEFBIjQPfsWL13iMrNrWhTGSLSsysvMB8GA1UdIwQYMBaA
FOOL6FpP2S5wf/ZQivC5fY4+OAVoMA0GCSqGSIb3DQEBCwUAA4GBACq9g58VlurJ
3lXZMhYE26AWvg7LM5yfucmbOlj6rv1B0zvP/2lm9P4myTqMrI9ooGGrB2r4US66
4PWm3ISZHizAu8ZPlVVlrSpsuCZi870LGe1JSrtMHQ3o7JFBXkgtBNmEGI+kOxuo
xSySBYVf1Kun8oOGYyUf9KpQaP6DW1d4
-----END CERTIFICATE-----
''';

void main() {
  late X509Certificate root;
  late X509Certificate intermediate;
  late X509Certificate leaf;
  late X509Verifier verifier;

  setUp(() {
    root = X509Certificate.fromPem(rootPem);
    intermediate = X509Certificate.fromPem(intermediatePem);
    leaf = X509Certificate.fromPem(leafPem);
    verifier = X509Verifier()..addTrustedCertificate(root);
  });

  X509VerificationResult verify({
    List<X509PeerName> peerNames = const [],
    Set<X509HostnameFlag> hostnameFlags = const {
      X509HostnameFlag.neverCheckSubject,
    },
    X509Purpose? purpose,
    int? maxIntermediates,
  }) => verifier.verify(
    leaf: leaf,
    intermediates: [intermediate],
    peerNames: peerNames,
    hostnameFlags: hostnameFlags,
    purpose: purpose,
    maxIntermediates: maxIntermediates,
  );

  group('X509Verifier peer names', () {
    test('accepts a matching DNS name', () {
      expect(
        verify(peerNames: [const X509PeerName.dnsName('leaf.example.com')]),
        isA<X509VerificationResult>().having((r) => r.isValid, 'isValid', true),
      );
    });

    test('rejects a mismatched DNS name', () {
      final result = verify(
        peerNames: [const X509PeerName.dnsName('other.example.com')],
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('Hostname mismatch'));
      expect(result.errorDepth, equals(0));
    });

    test('matches any of several DNS names', () {
      expect(
        verify(
          peerNames: const [
            X509PeerName.dnsName('other.example.com'),
            X509PeerName.dnsName('leaf.example.com'),
          ],
        ).isValid,
        isTrue,
      );
    });

    test('matches a wildcard SAN', () {
      expect(
        verify(
          peerNames: [const X509PeerName.dnsName('host.wild.example.com')],
        ).isValid,
        isTrue,
      );
    });

    test('noWildcards disables wildcard matching', () {
      expect(
        verify(
          peerNames: [const X509PeerName.dnsName('host.wild.example.com')],
          hostnameFlags: const {
            X509HostnameFlag.neverCheckSubject,
            X509HostnameFlag.noWildcards,
          },
        ).isValid,
        isFalse,
      );
    });

    test('accepts a matching IP address', () {
      expect(
        verify(peerNames: [const X509PeerName.ipAddress('127.0.0.1')]).isValid,
        isTrue,
      );
    });

    test('rejects a mismatched IP address', () {
      final result = verify(
        peerNames: [const X509PeerName.ipAddress('10.0.0.1')],
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('IP address mismatch'));
    });

    test('accepts a matching email address', () {
      expect(
        verify(
          peerNames: [const X509PeerName.emailAddress('test@example.com')],
        ).isValid,
        isTrue,
      );
    });

    test('rejects a mismatched email address', () {
      expect(
        verify(
          peerNames: [const X509PeerName.emailAddress('other@example.com')],
        ).isValid,
        isFalse,
      );
    });

    test('names of different kinds must all match', () {
      expect(
        verify(
          peerNames: const [
            X509PeerName.dnsName('leaf.example.com'),
            X509PeerName.ipAddress('10.0.0.1'),
          ],
        ).isValid,
        isFalse,
      );
    });

    test('rejects more than one IP address', () {
      expect(
        () => verify(
          peerNames: const [
            X509PeerName.ipAddress('127.0.0.1'),
            X509PeerName.ipAddress('10.0.0.1'),
          ],
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects more than one email address', () {
      expect(
        () => verify(
          peerNames: const [
            X509PeerName.emailAddress('test@example.com'),
            X509PeerName.emailAddress('other@example.com'),
          ],
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('X509Verifier purpose', () {
    test('accepts a serverAuth leaf for tlsServer', () {
      expect(verify(purpose: X509Purpose.tlsServer).isValid, isTrue);
    });

    test('rejects a serverAuth leaf for tlsClient', () {
      final result = verify(purpose: X509Purpose.tlsClient);
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('purpose'));
    });

    test('accepts any purpose when unset', () {
      expect(verify().isValid, isTrue);
      expect(verify(purpose: X509Purpose.any).isValid, isTrue);
    });
  });

  group('X509Verifier chain depth', () {
    test('accepts a chain within the intermediate limit', () {
      expect(verify(maxIntermediates: 1).isValid, isTrue);
    });

    test('rejects a chain exceeding the intermediate limit', () {
      final result = verify(maxIntermediates: 0);
      expect(result.isValid, isFalse);
      // BoringSSL refuses to extend the chain past the limit, so it reports
      // the resulting dead end rather than a dedicated "chain too long" error.
      expect(result.errorMessage, contains('issuer certificate'));
    });

    test('rejects a negative limit', () {
      expect(
        () => verify(maxIntermediates: -1),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('X509Verifier weak signature digests', () {
    late X509Certificate sha1Root;
    late X509Verifier sha1Verifier;

    setUp(() {
      sha1Root = X509Certificate.fromPem(sha1RootPem);
      sha1Verifier = X509Verifier()..addTrustedCertificate(sha1Root);
    });

    test('rejects a SHA-1 signed leaf by default', () {
      final result = sha1Verifier.verify(
        leaf: X509Certificate.fromPem(sha1LeafPem),
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('ecdsa-with-SHA1'));
      expect(result.errorDepth, equals(0));
    });

    test('accepts a SHA-1 signed leaf when explicitly allowed', () {
      final result = sha1Verifier.verify(
        leaf: X509Certificate.fromPem(sha1LeafPem),
        insecurelyAllowWeakSignatureDigests: true,
      );
      expect(result.isValid, isTrue);
    });

    test('exempts the trust anchor\'s own weak self-signature', () {
      final result = sha1Verifier.verify(
        leaf: X509Certificate.fromPem(sha256LeafOfSha1RootPem),
      );
      expect(result.isValid, isTrue);
    });

    test('accepts a SHA-256 chain', () {
      expect(verify().isValid, isTrue);
    });
  });

  group('X509Verifier key strength', () {
    X509VerificationResult verifyUnder(
      String rootPem,
      String leafPem, {
      bool insecurelyAllowWeakKeys = false,
      int minimumRsaKeyBits = 2048,
    }) =>
        (X509Verifier()
              ..addTrustedCertificate(X509Certificate.fromPem(rootPem)))
            .verify(
              leaf: X509Certificate.fromPem(leafPem),
              insecurelyAllowWeakKeys: insecurelyAllowWeakKeys,
              minimumRsaKeyBits: minimumRsaKeyBits,
            );

    test('rejects an RSA-1024 leaf by default', () {
      final result = verifyUnder(strongRootPem, rsa1024LeafPem);
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('1024-bit'));
      expect(result.errorMessage, contains('2048-bit minimum'));
      expect(result.errorDepth, equals(0));
    });

    test('accepts an RSA-1024 leaf when the minimum is lowered', () {
      expect(
        verifyUnder(
          strongRootPem,
          rsa1024LeafPem,
          minimumRsaKeyBits: 1024,
        ).isValid,
        isTrue,
      );
    });

    test('accepts an RSA-1024 leaf when the check is disabled', () {
      expect(
        verifyUnder(
          strongRootPem,
          rsa1024LeafPem,
          insecurelyAllowWeakKeys: true,
        ).isValid,
        isTrue,
      );
    });

    test('rejects a P-224 leaf, which no RSA minimum governs', () {
      final result = verifyUnder(
        strongRootPem,
        p224LeafPem,
        minimumRsaKeyBits: 0,
      );
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('secp224r1'));
      expect(result.errorDepth, equals(0));
    });

    test('accepts an Ed25519 leaf', () {
      // Unrecognised-but-strong algorithms must pass. BoringSSL's own pki/
      // verifier uses an allow-list and would reject this.
      expect(verifyUnder(strongRootPem, ed25519LeafPem).isValid, isTrue);
    });

    test('rejects a weak trust anchor key even though the chain is strong', () {
      final result = verifyUnder(weakRootPem, p256LeafPem);
      expect(result.isValid, isFalse);
      expect(result.errorMessage, contains('1024-bit'));
      // Depth 1 is the anchor: unlike the signature digest check, the key
      // check is not allowed to skip it.
      expect(result.errorDepth, equals(1));
    });

    test('rejects a negative minimum', () {
      expect(
        () => verifyUnder(strongRootPem, p224LeafPem, minimumRsaKeyBits: -1),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('X509PeerName', () {
    test('has value equality', () {
      expect(
        const X509PeerName.dnsName('a.example.com'),
        equals(const X509PeerName.dnsName('a.example.com')),
      );
      expect(
        const X509PeerName.dnsName('a.example.com'),
        isNot(equals(const X509PeerName.emailAddress('a.example.com'))),
      );
    });

    test('has a readable toString', () {
      expect(
        const X509PeerName.ipAddress('::1').toString(),
        equals('X509PeerName.ipAddress(::1)'),
      );
    });
  });
}
