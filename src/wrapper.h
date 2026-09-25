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
#define cbb_buffer_st _bssl_hidden_cbb_buffer_st
#define cbb_child_st _bssl_hidden_cbb_child_st
#define cbb_st _bssl_hidden_cbb_st
#include <openssl/bytestring.h>
#undef cbb_st
#undef cbb_child_st
#undef cbb_buffer_st

struct cbb_buffer_st {
  uint8_t *buf;
  size_t len;
  size_t cap;
  unsigned flags;
};

struct cbb_child_st {
  struct cbb_buffer_st *base;
  size_t offset;
  uint8_t pending_len_len;
  uint8_t pending_is_asn1;
};

struct cbb_st {
  CBB *child;
  char is_child;
  union {
    struct cbb_buffer_st base;
    struct cbb_child_st child;
  } u;
};
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
