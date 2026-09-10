#ifndef BORING_WRAPPER_H
#define BORING_WRAPPER_H

#define BORINGSSL_ALWAYS_USE_STATIC_INLINE

#include <openssl/base.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/hkdf.h>
#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/curve25519.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#endif // BORING_WRAPPER_H
