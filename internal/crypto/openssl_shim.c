#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <moonbit.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>

typedef struct {
  void *library;
  int32_t ready;
  char error[512];
  char version[160];
  char property_query[256];

  int (*openssl_version_major)(void);
  const char *(*openssl_version)(int);
  unsigned long (*err_get_error)(void);
  void (*err_error_string_n)(unsigned long, char *, size_t);
  int (*rand_bytes_ex)(OSSL_LIB_CTX *, unsigned char *, size_t, unsigned int);
  int (*crypto_memcmp)(const void *, const void *, size_t);

  EVP_CIPHER *(*cipher_fetch)(OSSL_LIB_CTX *, const char *, const char *);
  void (*cipher_free)(EVP_CIPHER *);
  EVP_CIPHER_CTX *(*cipher_ctx_new)(void);
  void (*cipher_ctx_free)(EVP_CIPHER_CTX *);
  int (*cipher_get_key_length)(const EVP_CIPHER *);
  int (*cipher_get_iv_length)(const EVP_CIPHER *);
  int (*encrypt_init_ex2)(
    EVP_CIPHER_CTX *,
    const EVP_CIPHER *,
    const unsigned char *,
    const unsigned char *,
    const OSSL_PARAM *
  );
  int (*encrypt_update)(
    EVP_CIPHER_CTX *,
    unsigned char *,
    int *,
    const unsigned char *,
    int
  );
  int (*encrypt_final_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
  int (*decrypt_init_ex2)(
    EVP_CIPHER_CTX *,
    const EVP_CIPHER *,
    const unsigned char *,
    const unsigned char *,
    const OSSL_PARAM *
  );
  int (*decrypt_update)(
    EVP_CIPHER_CTX *,
    unsigned char *,
    int *,
    const unsigned char *,
    int
  );
  int (*decrypt_final_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
  int (*cipher_ctx_ctrl)(EVP_CIPHER_CTX *, int, int, void *);
  int (*cipher_ctx_set_padding)(EVP_CIPHER_CTX *, int);

  EVP_MD *(*md_fetch)(OSSL_LIB_CTX *, const char *, const char *);
  void (*md_free)(EVP_MD *);
  EVP_MD_CTX *(*md_ctx_new)(void);
  void (*md_ctx_free)(EVP_MD_CTX *);
  int (*digest_init_ex2)(EVP_MD_CTX *, const EVP_MD *, const OSSL_PARAM *);
  int (*digest_update)(EVP_MD_CTX *, const void *, size_t);
  int (*digest_final_ex)(EVP_MD_CTX *, unsigned char *, unsigned int *);
  int (*q_digest)(
    OSSL_LIB_CTX *,
    const char *,
    const char *,
    const void *,
    size_t,
    unsigned char *,
    size_t *
  );

  EVP_MAC *(*mac_fetch)(OSSL_LIB_CTX *, const char *, const char *);
  void (*mac_free)(EVP_MAC *);
  EVP_MAC_CTX *(*mac_ctx_new)(EVP_MAC *);
  void (*mac_ctx_free)(EVP_MAC_CTX *);
  int (*mac_init)(
    EVP_MAC_CTX *,
    const unsigned char *,
    size_t,
    const OSSL_PARAM *
  );
  int (*mac_update)(EVP_MAC_CTX *, const unsigned char *, size_t);
  int (*mac_final)(EVP_MAC_CTX *, unsigned char *, size_t *, size_t);
  unsigned char *(*q_mac)(
    OSSL_LIB_CTX *,
    const char *,
    const char *,
    const char *,
    const OSSL_PARAM *,
    const void *,
    size_t,
    const unsigned char *,
    size_t,
    unsigned char *,
    size_t,
    size_t *
  );

  OSSL_PARAM (*param_utf8_string)(const char *, char *, size_t);
  OSSL_PARAM (*param_end)(void);

  EVP_KEYEXCH *(*keyexch_fetch)(
    OSSL_LIB_CTX *,
    const char *,
    const char *
  );
  void (*keyexch_free)(EVP_KEYEXCH *);
  EVP_SIGNATURE *(*signature_fetch)(
    OSSL_LIB_CTX *,
    const char *,
    const char *
  );
  void (*signature_free)(EVP_SIGNATURE *);
  EVP_PKEY *(*pkey_q_keygen)(
    OSSL_LIB_CTX *,
    const char *,
    const char *,
    ...
  );
  void (*pkey_free)(EVP_PKEY *);
  EVP_PKEY_CTX *(*pkey_ctx_new_from_pkey)(
    OSSL_LIB_CTX *,
    EVP_PKEY *,
    const char *
  );
  void (*pkey_ctx_free)(EVP_PKEY_CTX *);
  int (*pkey_derive_init)(EVP_PKEY_CTX *);
  int (*pkey_derive_set_peer)(EVP_PKEY_CTX *, EVP_PKEY *);
  int (*pkey_derive)(EVP_PKEY_CTX *, unsigned char *, size_t *);
  int (*digest_sign_init_ex)(
    EVP_MD_CTX *,
    EVP_PKEY_CTX **,
    const char *,
    OSSL_LIB_CTX *,
    const char *,
    EVP_PKEY *,
    const OSSL_PARAM *
  );
  int (*digest_sign_update)(EVP_MD_CTX *, const void *, size_t);
  int (*digest_sign_final)(EVP_MD_CTX *, unsigned char *, size_t *);
  int (*digest_verify_init_ex)(
    EVP_MD_CTX *,
    EVP_PKEY_CTX **,
    const char *,
    OSSL_LIB_CTX *,
    const char *,
    EVP_PKEY *,
    const OSSL_PARAM *
  );
  int (*digest_verify_update)(EVP_MD_CTX *, const void *, size_t);
  int (*digest_verify_final)(
    EVP_MD_CTX *,
    const unsigned char *,
    size_t
  );
  int (*i2d_pubkey)(const EVP_PKEY *, unsigned char **);
  EVP_PKEY *(*d2i_pubkey_ex)(
    EVP_PKEY **,
    const unsigned char **,
    long,
    OSSL_LIB_CTX *,
    const char *
  );

  X509 *(*x509_new_ex)(OSSL_LIB_CTX *, const char *);
  void (*x509_free)(X509 *);
  int (*x509_set_version)(X509 *, long);
  ASN1_INTEGER *(*x509_get_serial_number)(X509 *);
  int (*asn1_integer_set_uint64)(ASN1_INTEGER *, uint64_t);
  X509_NAME *(*x509_get_subject_name)(const X509 *);
  int (*x509_name_add_entry_by_txt)(
    X509_NAME *,
    const char *,
    int,
    const unsigned char *,
    int,
    int,
    int
  );
  int (*x509_set_issuer_name)(X509 *, const X509_NAME *);
  ASN1_TIME *(*x509_getm_not_before)(const X509 *);
  ASN1_TIME *(*x509_getm_not_after)(const X509 *);
  ASN1_TIME *(*asn1_time_set)(ASN1_TIME *, time_t);
  int (*x509_set_pubkey)(X509 *, EVP_PKEY *);
  int (*x509_sign)(X509 *, EVP_PKEY *, const EVP_MD *);
  int (*i2d_x509)(const X509 *, unsigned char **);
  X509 *(*d2i_x509)(X509 **, const unsigned char **, long);
  EVP_PKEY *(*x509_get_pubkey)(X509 *);
  int (*x509_digest)(
    const X509 *,
    const EVP_MD *,
    unsigned char *,
    unsigned int *
  );
  const ASN1_TIME *(*x509_get0_not_before)(const X509 *);
  const ASN1_TIME *(*x509_get0_not_after)(const X509 *);
  int (*x509_cmp_time)(const ASN1_TIME *, time_t *);
  int (*x509_verify)(X509 *, EVP_PKEY *);
} rtc_crypto_provider;

typedef struct {
  int32_t valid;
  int32_t length;
  unsigned char data[];
} rtc_crypto_secret;

typedef struct {
  EVP_PKEY *key;
  void (*free_key)(EVP_PKEY *);
} rtc_crypto_key;

typedef struct {
  X509 *certificate;
  void (*free_certificate)(X509 *);
} rtc_crypto_certificate;

static void
rtc_secure_clear(void *memory, size_t length) {
  volatile unsigned char *cursor = (volatile unsigned char *)memory;
  while (length > 0) {
    *cursor++ = 0;
    length -= 1;
  }
}

static void
rtc_provider_destroy(void *self) {
  rtc_crypto_provider *provider = (rtc_crypto_provider *)self;
  /*
   * The libcrypto handle deliberately remains open for the process lifetime.
   * OpenSSL provider objects can retain code pointers after an operation, so
   * dlclose would make finalizer order unsafe.
   */
  provider->library = NULL;
  provider->ready = 0;
  rtc_secure_clear(provider->property_query, sizeof(provider->property_query));
}

static void
rtc_secret_destroy(void *self) {
  rtc_crypto_secret *secret = (rtc_crypto_secret *)self;
  if (secret->length > 0) {
    rtc_secure_clear(secret->data, (size_t)secret->length);
  }
  secret->length = 0;
  secret->valid = 0;
}

static void
rtc_key_destroy(void *self) {
  rtc_crypto_key *key = (rtc_crypto_key *)self;
  if (key->key != NULL && key->free_key != NULL) {
    key->free_key(key->key);
    key->key = NULL;
  }
}

static void
rtc_certificate_destroy(void *self) {
  rtc_crypto_certificate *certificate = (rtc_crypto_certificate *)self;
  if (
    certificate->certificate != NULL &&
    certificate->free_certificate != NULL
  ) {
    certificate->free_certificate(certificate->certificate);
    certificate->certificate = NULL;
  }
}

static void
rtc_set_error(rtc_crypto_provider *provider, const char *format, ...) {
  va_list args;
  va_start(args, format);
  vsnprintf(provider->error, sizeof(provider->error), format, args);
  va_end(args);
}

static void
rtc_set_openssl_error(
  rtc_crypto_provider *provider,
  const char *operation
) {
  unsigned long code = provider->err_get_error ? provider->err_get_error() : 0;
  if (code != 0 && provider->err_error_string_n) {
    char details[256];
    provider->err_error_string_n(code, details, sizeof(details));
    rtc_set_error(provider, "%s: %s", operation, details);
  } else {
    rtc_set_error(provider, "%s", operation);
  }
}

static moonbit_bytes_t
rtc_copy_bytes(const unsigned char *source, size_t length) {
  moonbit_bytes_t result = moonbit_make_bytes((int32_t)length, 0);
  if (length > 0) {
    memcpy(result, source, length);
  }
  return result;
}

static moonbit_bytes_t
rtc_copy_string(const char *source) {
  return rtc_copy_bytes((const unsigned char *)source, strlen(source));
}

static moonbit_bytes_t
rtc_empty_bytes(void) {
  return moonbit_make_bytes(0, 0);
}

#define RTC_LOAD_SYMBOL(provider, field, symbol_name)                         \
  do {                                                                        \
    void *rtc_symbol = dlsym((provider)->library, (symbol_name));              \
    if (rtc_symbol == NULL) {                                                  \
      rtc_set_error(                                                          \
        (provider),                                                           \
        "missing required OpenSSL symbol %s",                                 \
        (symbol_name)                                                         \
      );                                                                      \
      return 0;                                                               \
    }                                                                         \
    memcpy(&(provider)->field, &rtc_symbol, sizeof(rtc_symbol));               \
  } while (0)

static int
rtc_load_symbols(rtc_crypto_provider *provider) {
  RTC_LOAD_SYMBOL(provider, openssl_version_major, "OPENSSL_version_major");
  RTC_LOAD_SYMBOL(provider, openssl_version, "OpenSSL_version");
  RTC_LOAD_SYMBOL(provider, err_get_error, "ERR_get_error");
  RTC_LOAD_SYMBOL(provider, err_error_string_n, "ERR_error_string_n");
  RTC_LOAD_SYMBOL(provider, rand_bytes_ex, "RAND_bytes_ex");
  RTC_LOAD_SYMBOL(provider, crypto_memcmp, "CRYPTO_memcmp");

  RTC_LOAD_SYMBOL(provider, cipher_fetch, "EVP_CIPHER_fetch");
  RTC_LOAD_SYMBOL(provider, cipher_free, "EVP_CIPHER_free");
  RTC_LOAD_SYMBOL(provider, cipher_ctx_new, "EVP_CIPHER_CTX_new");
  RTC_LOAD_SYMBOL(provider, cipher_ctx_free, "EVP_CIPHER_CTX_free");
  RTC_LOAD_SYMBOL(provider, cipher_get_key_length, "EVP_CIPHER_get_key_length");
  RTC_LOAD_SYMBOL(provider, cipher_get_iv_length, "EVP_CIPHER_get_iv_length");
  RTC_LOAD_SYMBOL(provider, encrypt_init_ex2, "EVP_EncryptInit_ex2");
  RTC_LOAD_SYMBOL(provider, encrypt_update, "EVP_EncryptUpdate");
  RTC_LOAD_SYMBOL(provider, encrypt_final_ex, "EVP_EncryptFinal_ex");
  RTC_LOAD_SYMBOL(provider, decrypt_init_ex2, "EVP_DecryptInit_ex2");
  RTC_LOAD_SYMBOL(provider, decrypt_update, "EVP_DecryptUpdate");
  RTC_LOAD_SYMBOL(provider, decrypt_final_ex, "EVP_DecryptFinal_ex");
  RTC_LOAD_SYMBOL(provider, cipher_ctx_ctrl, "EVP_CIPHER_CTX_ctrl");
  RTC_LOAD_SYMBOL(
    provider,
    cipher_ctx_set_padding,
    "EVP_CIPHER_CTX_set_padding"
  );

  RTC_LOAD_SYMBOL(provider, md_fetch, "EVP_MD_fetch");
  RTC_LOAD_SYMBOL(provider, md_free, "EVP_MD_free");
  RTC_LOAD_SYMBOL(provider, md_ctx_new, "EVP_MD_CTX_new");
  RTC_LOAD_SYMBOL(provider, md_ctx_free, "EVP_MD_CTX_free");
  RTC_LOAD_SYMBOL(provider, digest_init_ex2, "EVP_DigestInit_ex2");
  RTC_LOAD_SYMBOL(provider, digest_update, "EVP_DigestUpdate");
  RTC_LOAD_SYMBOL(provider, digest_final_ex, "EVP_DigestFinal_ex");
  RTC_LOAD_SYMBOL(provider, q_digest, "EVP_Q_digest");

  RTC_LOAD_SYMBOL(provider, mac_fetch, "EVP_MAC_fetch");
  RTC_LOAD_SYMBOL(provider, mac_free, "EVP_MAC_free");
  RTC_LOAD_SYMBOL(provider, mac_ctx_new, "EVP_MAC_CTX_new");
  RTC_LOAD_SYMBOL(provider, mac_ctx_free, "EVP_MAC_CTX_free");
  RTC_LOAD_SYMBOL(provider, mac_init, "EVP_MAC_init");
  RTC_LOAD_SYMBOL(provider, mac_update, "EVP_MAC_update");
  RTC_LOAD_SYMBOL(provider, mac_final, "EVP_MAC_final");
  RTC_LOAD_SYMBOL(provider, q_mac, "EVP_Q_mac");
  RTC_LOAD_SYMBOL(
    provider,
    param_utf8_string,
    "OSSL_PARAM_construct_utf8_string"
  );
  RTC_LOAD_SYMBOL(provider, param_end, "OSSL_PARAM_construct_end");

  RTC_LOAD_SYMBOL(provider, keyexch_fetch, "EVP_KEYEXCH_fetch");
  RTC_LOAD_SYMBOL(provider, keyexch_free, "EVP_KEYEXCH_free");
  RTC_LOAD_SYMBOL(provider, signature_fetch, "EVP_SIGNATURE_fetch");
  RTC_LOAD_SYMBOL(provider, signature_free, "EVP_SIGNATURE_free");
  RTC_LOAD_SYMBOL(provider, pkey_q_keygen, "EVP_PKEY_Q_keygen");
  RTC_LOAD_SYMBOL(provider, pkey_free, "EVP_PKEY_free");
  RTC_LOAD_SYMBOL(
    provider,
    pkey_ctx_new_from_pkey,
    "EVP_PKEY_CTX_new_from_pkey"
  );
  RTC_LOAD_SYMBOL(provider, pkey_ctx_free, "EVP_PKEY_CTX_free");
  RTC_LOAD_SYMBOL(provider, pkey_derive_init, "EVP_PKEY_derive_init");
  RTC_LOAD_SYMBOL(
    provider,
    pkey_derive_set_peer,
    "EVP_PKEY_derive_set_peer"
  );
  RTC_LOAD_SYMBOL(provider, pkey_derive, "EVP_PKEY_derive");
  RTC_LOAD_SYMBOL(
    provider,
    digest_sign_init_ex,
    "EVP_DigestSignInit_ex"
  );
  RTC_LOAD_SYMBOL(provider, digest_sign_update, "EVP_DigestSignUpdate");
  RTC_LOAD_SYMBOL(provider, digest_sign_final, "EVP_DigestSignFinal");
  RTC_LOAD_SYMBOL(
    provider,
    digest_verify_init_ex,
    "EVP_DigestVerifyInit_ex"
  );
  RTC_LOAD_SYMBOL(provider, digest_verify_update, "EVP_DigestVerifyUpdate");
  RTC_LOAD_SYMBOL(provider, digest_verify_final, "EVP_DigestVerifyFinal");
  RTC_LOAD_SYMBOL(provider, i2d_pubkey, "i2d_PUBKEY");
  RTC_LOAD_SYMBOL(provider, d2i_pubkey_ex, "d2i_PUBKEY_ex");

  RTC_LOAD_SYMBOL(provider, x509_new_ex, "X509_new_ex");
  RTC_LOAD_SYMBOL(provider, x509_free, "X509_free");
  RTC_LOAD_SYMBOL(provider, x509_set_version, "X509_set_version");
  RTC_LOAD_SYMBOL(
    provider,
    x509_get_serial_number,
    "X509_get_serialNumber"
  );
  RTC_LOAD_SYMBOL(
    provider,
    asn1_integer_set_uint64,
    "ASN1_INTEGER_set_uint64"
  );
  RTC_LOAD_SYMBOL(
    provider,
    x509_get_subject_name,
    "X509_get_subject_name"
  );
  RTC_LOAD_SYMBOL(
    provider,
    x509_name_add_entry_by_txt,
    "X509_NAME_add_entry_by_txt"
  );
  RTC_LOAD_SYMBOL(
    provider,
    x509_set_issuer_name,
    "X509_set_issuer_name"
  );
  RTC_LOAD_SYMBOL(
    provider,
    x509_getm_not_before,
    "X509_getm_notBefore"
  );
  RTC_LOAD_SYMBOL(provider, x509_getm_not_after, "X509_getm_notAfter");
  RTC_LOAD_SYMBOL(provider, asn1_time_set, "ASN1_TIME_set");
  RTC_LOAD_SYMBOL(provider, x509_set_pubkey, "X509_set_pubkey");
  RTC_LOAD_SYMBOL(provider, x509_sign, "X509_sign");
  RTC_LOAD_SYMBOL(provider, i2d_x509, "i2d_X509");
  RTC_LOAD_SYMBOL(provider, d2i_x509, "d2i_X509");
  RTC_LOAD_SYMBOL(provider, x509_get_pubkey, "X509_get_pubkey");
  RTC_LOAD_SYMBOL(provider, x509_digest, "X509_digest");
  RTC_LOAD_SYMBOL(
    provider,
    x509_get0_not_before,
    "X509_get0_notBefore"
  );
  RTC_LOAD_SYMBOL(provider, x509_get0_not_after, "X509_get0_notAfter");
  RTC_LOAD_SYMBOL(provider, x509_cmp_time, "X509_cmp_time");
  RTC_LOAD_SYMBOL(provider, x509_verify, "X509_verify");
  return 1;
}

static const char *
rtc_property_query(rtc_crypto_provider *provider) {
  return provider->property_query[0] == '\0'
    ? NULL
    : provider->property_query;
}

static int
rtc_preflight_cipher(rtc_crypto_provider *provider, const char *name) {
  EVP_CIPHER *cipher = provider->cipher_fetch(
    NULL,
    name,
    rtc_property_query(provider)
  );
  if (cipher == NULL) {
    rtc_set_error(provider, "OpenSSL preflight failed: cipher %s", name);
    return 0;
  }
  EVP_CIPHER_CTX *context = provider->cipher_ctx_new();
  if (context == NULL) {
    provider->cipher_free(cipher);
    rtc_set_openssl_error(provider, "OpenSSL preflight failed: cipher context");
    return 0;
  }
  int key_length = provider->cipher_get_key_length(cipher);
  int iv_length = provider->cipher_get_iv_length(cipher);
  unsigned char key[64] = { 0 };
  unsigned char iv[32] = { 0 };
  int initialized =
    key_length > 0 &&
    key_length <= (int)sizeof(key) &&
    iv_length >= 0 &&
    iv_length <= (int)sizeof(iv) &&
    provider->encrypt_init_ex2(context, cipher, key, iv, NULL) == 1;
  provider->cipher_ctx_free(context);
  provider->cipher_free(cipher);
  rtc_secure_clear(key, sizeof(key));
  rtc_secure_clear(iv, sizeof(iv));
  if (!initialized) {
    rtc_set_openssl_error(provider, "OpenSSL preflight failed: cipher init");
    return 0;
  }
  return 1;
}

static int
rtc_preflight_digest(rtc_crypto_provider *provider, const char *name) {
  EVP_MD *digest = provider->md_fetch(NULL, name, rtc_property_query(provider));
  if (digest == NULL) {
    rtc_set_error(provider, "OpenSSL preflight failed: digest %s", name);
    return 0;
  }
  EVP_MD_CTX *context = provider->md_ctx_new();
  unsigned char output[EVP_MAX_MD_SIZE];
  unsigned int output_length = 0;
  int initialized =
    context != NULL &&
    provider->digest_init_ex2(context, digest, NULL) == 1 &&
    provider->digest_update(context, "rtc", 3) == 1 &&
    provider->digest_final_ex(context, output, &output_length) == 1 &&
    output_length > 0;
  if (context != NULL) {
    provider->md_ctx_free(context);
  }
  provider->md_free(digest);
  rtc_secure_clear(output, sizeof(output));
  if (!initialized) {
    rtc_set_openssl_error(provider, "OpenSSL preflight failed: digest init");
    return 0;
  }
  return 1;
}

static int
rtc_preflight_mac(rtc_crypto_provider *provider) {
  EVP_MAC *mac =
    provider->mac_fetch(NULL, "HMAC", rtc_property_query(provider));
  if (mac == NULL) {
    rtc_set_error(provider, "OpenSSL preflight failed: MAC HMAC");
    return 0;
  }
  EVP_MAC_CTX *context = provider->mac_ctx_new(mac);
  unsigned char key[16] = { 0 };
  unsigned char output[EVP_MAX_MD_SIZE];
  size_t output_length = 0;
  char digest_name[] = "SHA256";
  OSSL_PARAM parameters[2];
  parameters[0] = provider->param_utf8_string(
    OSSL_MAC_PARAM_DIGEST,
    digest_name,
    0
  );
  parameters[1] = provider->param_end();
  int initialized =
    context != NULL &&
    provider->mac_init(context, key, sizeof(key), parameters) == 1 &&
    provider->mac_update(
      context,
      (const unsigned char *)"rtc",
      3
    ) == 1 &&
    provider->mac_final(
      context,
      output,
      &output_length,
      sizeof(output)
    ) == 1 &&
    output_length > 0;
  if (context != NULL) {
    provider->mac_ctx_free(context);
  }
  provider->mac_free(mac);
  rtc_secure_clear(key, sizeof(key));
  rtc_secure_clear(output, sizeof(output));
  if (!initialized) {
    rtc_set_openssl_error(provider, "OpenSSL preflight failed: MAC init");
    return 0;
  }
  return 1;
}

static int
rtc_preflight_fetches(rtc_crypto_provider *provider) {
  const char *key_exchanges[] = { "ECDH", "X25519" };
  const char *signatures[] = { "ECDSA", "RSA" };
  size_t index;
  for (index = 0; index < sizeof(key_exchanges) / sizeof(key_exchanges[0]);
       index += 1) {
    EVP_KEYEXCH *implementation = provider->keyexch_fetch(
      NULL,
      key_exchanges[index],
      rtc_property_query(provider)
    );
    if (implementation == NULL) {
      rtc_set_error(
        provider,
        "OpenSSL preflight failed: key exchange %s",
        key_exchanges[index]
      );
      return 0;
    }
    provider->keyexch_free(implementation);
  }
  for (index = 0; index < sizeof(signatures) / sizeof(signatures[0]);
       index += 1) {
    EVP_SIGNATURE *implementation = provider->signature_fetch(
      NULL,
      signatures[index],
      rtc_property_query(provider)
    );
    if (implementation == NULL) {
      rtc_set_error(
        provider,
        "OpenSSL preflight failed: signature %s",
        signatures[index]
      );
      return 0;
    }
    provider->signature_free(implementation);
  }
  return 1;
}

static int
rtc_preflight_key_exchange(
  rtc_crypto_provider *provider,
  EVP_PKEY *local_key
) {
  EVP_PKEY *peer_key = provider->pkey_q_keygen(
    NULL,
    rtc_property_query(provider),
    "EC",
    "P-256"
  );
  EVP_PKEY_CTX *local_context = NULL;
  EVP_PKEY_CTX *peer_context = NULL;
  unsigned char local_secret[128];
  unsigned char peer_secret[128];
  size_t local_length = sizeof(local_secret);
  size_t peer_length = sizeof(peer_secret);
  int success =
    peer_key != NULL &&
    (local_context = provider->pkey_ctx_new_from_pkey(
      NULL,
      local_key,
      rtc_property_query(provider)
    )) != NULL &&
    (peer_context = provider->pkey_ctx_new_from_pkey(
      NULL,
      peer_key,
      rtc_property_query(provider)
    )) != NULL &&
    provider->pkey_derive_init(local_context) == 1 &&
    provider->pkey_derive_set_peer(local_context, peer_key) == 1 &&
    provider->pkey_derive(local_context, local_secret, &local_length) == 1 &&
    provider->pkey_derive_init(peer_context) == 1 &&
    provider->pkey_derive_set_peer(peer_context, local_key) == 1 &&
    provider->pkey_derive(peer_context, peer_secret, &peer_length) == 1 &&
    local_length == peer_length &&
    provider->crypto_memcmp(
      local_secret,
      peer_secret,
      local_length
    ) == 0;
  if (local_context != NULL) {
    provider->pkey_ctx_free(local_context);
  }
  if (peer_context != NULL) {
    provider->pkey_ctx_free(peer_context);
  }
  if (peer_key != NULL) {
    provider->pkey_free(peer_key);
  }
  rtc_secure_clear(local_secret, sizeof(local_secret));
  rtc_secure_clear(peer_secret, sizeof(peer_secret));
  if (!success) {
    rtc_set_openssl_error(
      provider,
      "OpenSSL preflight failed: ECDH derive"
    );
    return 0;
  }
  return 1;
}

static int
rtc_preflight_signature(
  rtc_crypto_provider *provider,
  EVP_PKEY *key,
  const char *pad_mode_value
) {
  const unsigned char message[] = "rtc.mbt provider preflight";
  EVP_MD_CTX *sign_context = provider->md_ctx_new();
  EVP_MD_CTX *verify_context = provider->md_ctx_new();
  OSSL_PARAM parameters[3];
  char pad_mode[16] = { 0 };
  char salt_length[16] = { 0 };
  const OSSL_PARAM *parameter_pointer = NULL;
  if (pad_mode_value != NULL) {
    snprintf(pad_mode, sizeof(pad_mode), "%s", pad_mode_value);
    parameters[0] = provider->param_utf8_string(
      OSSL_SIGNATURE_PARAM_PAD_MODE,
      pad_mode,
      0
    );
    if (strcmp(pad_mode_value, "pss") == 0) {
      snprintf(salt_length, sizeof(salt_length), "%s", "digest");
      parameters[1] = provider->param_utf8_string(
        OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
        salt_length,
        0
      );
      parameters[2] = provider->param_end();
    } else {
      parameters[1] = provider->param_end();
    }
    parameter_pointer = parameters;
  }
  unsigned char signature[512];
  size_t signature_length = sizeof(signature);
  int success =
    sign_context != NULL &&
    verify_context != NULL &&
    provider->digest_sign_init_ex(
      sign_context,
      NULL,
      "SHA256",
      NULL,
      rtc_property_query(provider),
      key,
      parameter_pointer
    ) == 1 &&
    provider->digest_sign_update(
      sign_context,
      message,
      sizeof(message) - 1
    ) == 1 &&
    provider->digest_sign_final(
      sign_context,
      signature,
      &signature_length
    ) == 1 &&
    signature_length > 0 &&
    provider->digest_verify_init_ex(
      verify_context,
      NULL,
      "SHA256",
      NULL,
      rtc_property_query(provider),
      key,
      parameter_pointer
    ) == 1 &&
    provider->digest_verify_update(
      verify_context,
      message,
      sizeof(message) - 1
    ) == 1 &&
    provider->digest_verify_final(
      verify_context,
      signature,
      signature_length
    ) == 1;
  if (sign_context != NULL) {
    provider->md_ctx_free(sign_context);
  }
  if (verify_context != NULL) {
    provider->md_ctx_free(verify_context);
  }
  rtc_secure_clear(signature, sizeof(signature));
  rtc_secure_clear(pad_mode, sizeof(pad_mode));
  rtc_secure_clear(salt_length, sizeof(salt_length));
  if (!success) {
    rtc_set_openssl_error(
      provider,
      "OpenSSL preflight failed: signature operation"
    );
    return 0;
  }
  return 1;
}

static int
rtc_preflight_x509(rtc_crypto_provider *provider, EVP_PKEY *key) {
  X509 *certificate =
    provider->x509_new_ex(NULL, rtc_property_query(provider));
  EVP_MD *digest = provider->md_fetch(
    NULL,
    "SHA256",
    rtc_property_query(provider)
  );
  const unsigned char common_name[] = "rtc.mbt preflight";
  time_t not_before = (time_t)0;
  time_t not_after = (time_t)86400;
  X509_NAME *subject = certificate == NULL
    ? NULL
    : provider->x509_get_subject_name(certificate);
  int success =
    certificate != NULL &&
    digest != NULL &&
    provider->x509_set_version(certificate, 2) == 1 &&
    provider->asn1_integer_set_uint64(
      provider->x509_get_serial_number(certificate),
      1
    ) == 1 &&
    subject != NULL &&
    provider->x509_name_add_entry_by_txt(
      subject,
      "CN",
      MBSTRING_UTF8,
      common_name,
      (int)(sizeof(common_name) - 1),
      -1,
      0
    ) == 1 &&
    provider->x509_set_issuer_name(certificate, subject) == 1 &&
    provider->asn1_time_set(
      provider->x509_getm_not_before(certificate),
      not_before
    ) != NULL &&
    provider->asn1_time_set(
      provider->x509_getm_not_after(certificate),
      not_after
    ) != NULL &&
    provider->x509_set_pubkey(certificate, key) == 1 &&
    provider->x509_sign(certificate, key, digest) > 0 &&
    provider->x509_verify(certificate, key) == 1;
  if (digest != NULL) {
    provider->md_free(digest);
  }
  if (certificate != NULL) {
    provider->x509_free(certificate);
  }
  if (!success) {
    rtc_set_openssl_error(
      provider,
      "OpenSSL preflight failed: X.509 operation"
    );
    return 0;
  }
  return 1;
}

static int
rtc_preflight_keys_and_x509(rtc_crypto_provider *provider) {
  EVP_PKEY *ec_key = provider->pkey_q_keygen(
    NULL,
    rtc_property_query(provider),
    "EC",
    "P-256"
  );
  if (ec_key == NULL) {
    rtc_set_openssl_error(provider, "OpenSSL preflight failed: P-256 keygen");
    return 0;
  }
  if (
    !rtc_preflight_key_exchange(provider, ec_key) ||
    !rtc_preflight_signature(provider, ec_key, NULL) ||
    !rtc_preflight_x509(provider, ec_key)
  ) {
    provider->pkey_free(ec_key);
    return 0;
  }
  provider->pkey_free(ec_key);

  EVP_PKEY *rsa_key = provider->pkey_q_keygen(
    NULL,
    rtc_property_query(provider),
    "RSA",
    (size_t)2048
  );
  if (rsa_key == NULL) {
    rtc_set_openssl_error(provider, "OpenSSL preflight failed: RSA keygen");
    return 0;
  }
  if (!rtc_preflight_signature(provider, rsa_key, "pss")) {
    provider->pkey_free(rsa_key);
    return 0;
  }
  provider->pkey_free(rsa_key);
  return 1;
}

static int
rtc_preflight(rtc_crypto_provider *provider) {
  const char *ciphers[] = {
    "AES-128-GCM",
    "AES-256-GCM",
    "AES-128-CCM",
    "AES-256-CCM",
    "CHACHA20-POLY1305",
    "AES-128-CBC",
    "AES-256-CBC",
    "AES-128-CTR",
    "AES-256-CTR",
  };
  const char *digests[] = { "SHA1", "SHA256", "SHA384", "SHA512" };
  size_t index;
  unsigned char random_sample[32];

  if (provider->rand_bytes_ex(NULL, random_sample, sizeof(random_sample), 0) != 1) {
    rtc_set_openssl_error(provider, "OpenSSL preflight failed: random");
    rtc_secure_clear(random_sample, sizeof(random_sample));
    return 0;
  }
  rtc_secure_clear(random_sample, sizeof(random_sample));

  for (index = 0; index < sizeof(ciphers) / sizeof(ciphers[0]); index += 1) {
    if (!rtc_preflight_cipher(provider, ciphers[index])) {
      return 0;
    }
  }
  for (index = 0; index < sizeof(digests) / sizeof(digests[0]); index += 1) {
    if (!rtc_preflight_digest(provider, digests[index])) {
      return 0;
    }
  }
  if (!rtc_preflight_mac(provider)) {
    return 0;
  }
  if (!rtc_preflight_fetches(provider)) {
    return 0;
  }
  if (!rtc_preflight_keys_and_x509(provider)) {
    return 0;
  }
  return 1;
}

MOONBIT_FFI_EXPORT
rtc_crypto_provider *
moonbit_rtc_crypto_provider_new(
  moonbit_bytes_t path,
  moonbit_bytes_t property_query
) {
  rtc_crypto_provider *provider =
    (rtc_crypto_provider *)moonbit_make_external_object(
      rtc_provider_destroy,
      sizeof(rtc_crypto_provider)
    );
  memset(provider, 0, sizeof(*provider));

  int32_t property_length = Moonbit_array_length(property_query);
  if (property_length >= (int32_t)sizeof(provider->property_query)) {
    rtc_set_error(provider, "OpenSSL property query is too long");
    return provider;
  }
  if (property_length > 0) {
    memcpy(
      provider->property_query,
      property_query,
      (size_t)property_length
    );
  }
  provider->property_query[property_length] = '\0';

  const char *library_path = Moonbit_array_length(path) == 0
    ? "libcrypto.so.3"
    : (const char *)path;
  int flags = RTLD_NOW | RTLD_LOCAL;
#ifdef RTLD_NODELETE
  flags |= RTLD_NODELETE;
#endif
  provider->library = dlopen(library_path, flags);
  if (provider->library == NULL) {
    const char *details = dlerror();
    rtc_set_error(
      provider,
      "unable to load OpenSSL 3 library %s: %s",
      library_path,
      details == NULL ? "unknown loader error" : details
    );
    return provider;
  }
  if (!rtc_load_symbols(provider)) {
    return provider;
  }
  if (provider->openssl_version_major() != 3) {
    rtc_set_error(
      provider,
      "unsupported OpenSSL major version %d; expected 3",
      provider->openssl_version_major()
    );
    return provider;
  }
  const char *version = provider->openssl_version(OPENSSL_VERSION);
  if (version == NULL) {
    rtc_set_error(provider, "unable to query OpenSSL version");
    return provider;
  }
  snprintf(provider->version, sizeof(provider->version), "%s", version);
  if (!rtc_preflight(provider)) {
    return provider;
  }
  provider->ready = 1;
  provider->error[0] = '\0';
  return provider;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_provider_is_ready(rtc_crypto_provider *provider) {
  return provider != NULL && provider->ready;
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_provider_last_error(rtc_crypto_provider *provider) {
  if (provider == NULL) {
    return rtc_copy_string("invalid crypto provider");
  }
  return rtc_copy_string(provider->error);
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_provider_version(rtc_crypto_provider *provider) {
  if (provider == NULL || !provider->ready) {
    return rtc_empty_bytes();
  }
  return rtc_copy_string(provider->version);
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_random_bytes(
  rtc_crypto_provider *provider,
  int32_t length
) {
  if (provider == NULL || !provider->ready || length < 1) {
    if (provider != NULL) {
      rtc_set_error(provider, "invalid random byte request");
    }
    return rtc_empty_bytes();
  }
  moonbit_bytes_t result = moonbit_make_bytes(length, 0);
  if (provider->rand_bytes_ex(
        NULL,
        result,
        (size_t)length,
        0
      ) != 1) {
    rtc_secure_clear(result, (size_t)length);
    moonbit_decref(result);
    rtc_set_openssl_error(provider, "OpenSSL random generation failed");
    return rtc_empty_bytes();
  }
  return result;
}

static const char *
rtc_digest_name(int32_t algorithm) {
  switch (algorithm) {
    case 0:
      return "SHA1";
    case 1:
      return "SHA256";
    case 2:
      return "SHA384";
    case 3:
      return "SHA512";
    default:
      return NULL;
  }
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_digest(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  moonbit_bytes_t data
) {
  if (provider == NULL || !provider->ready) {
    return rtc_empty_bytes();
  }
  const char *name = rtc_digest_name(algorithm);
  if (name == NULL) {
    rtc_set_error(provider, "unsupported digest algorithm");
    return rtc_empty_bytes();
  }
  unsigned char output[EVP_MAX_MD_SIZE];
  size_t output_length = 0;
  int success = provider->q_digest(
    NULL,
    name,
    rtc_property_query(provider),
    data,
    (size_t)Moonbit_array_length(data),
    output,
    &output_length
  );
  if (success != 1) {
    rtc_set_openssl_error(provider, "OpenSSL digest failed");
    rtc_secure_clear(output, sizeof(output));
    return rtc_empty_bytes();
  }
  moonbit_bytes_t result = rtc_copy_bytes(output, output_length);
  rtc_secure_clear(output, sizeof(output));
  return result;
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_hmac(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  rtc_crypto_secret *key,
  moonbit_bytes_t data
) {
  if (provider == NULL || !provider->ready || key == NULL || !key->valid) {
    return rtc_empty_bytes();
  }
  const char *name = rtc_digest_name(algorithm);
  if (name == NULL) {
    rtc_set_error(provider, "unsupported HMAC digest algorithm");
    return rtc_empty_bytes();
  }
  unsigned char output[EVP_MAX_MD_SIZE];
  size_t output_length = 0;
  unsigned char *result_pointer = provider->q_mac(
    NULL,
    "HMAC",
    rtc_property_query(provider),
    name,
    NULL,
    key->data,
    (size_t)key->length,
    data,
    (size_t)Moonbit_array_length(data),
    output,
    sizeof(output),
    &output_length
  );
  if (result_pointer == NULL) {
    rtc_set_openssl_error(provider, "OpenSSL HMAC failed");
    rtc_secure_clear(output, sizeof(output));
    return rtc_empty_bytes();
  }
  moonbit_bytes_t result = rtc_copy_bytes(output, output_length);
  rtc_secure_clear(output, sizeof(output));
  return result;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_constant_time_equal(
  rtc_crypto_provider *provider,
  moonbit_bytes_t left,
  moonbit_bytes_t right
) {
  if (provider == NULL || !provider->ready) {
    return 0;
  }
  int32_t left_length = Moonbit_array_length(left);
  int32_t right_length = Moonbit_array_length(right);
  if (left_length != right_length) {
    return 0;
  }
  return provider->crypto_memcmp(left, right, (size_t)left_length) == 0;
}

static const char *
rtc_aead_name(int32_t algorithm) {
  switch (algorithm) {
    case 0:
      return "AES-128-GCM";
    case 1:
      return "AES-256-GCM";
    case 2:
      return "AES-128-CCM";
    case 3:
      return "AES-256-CCM";
    case 4:
      return "CHACHA20-POLY1305";
    default:
      return NULL;
  }
}

static int
rtc_aead_is_ccm(int32_t algorithm) {
  return algorithm == 2 || algorithm == 3;
}

static int
rtc_validate_key(
  rtc_crypto_provider *provider,
  const EVP_CIPHER *cipher,
  rtc_crypto_secret *key
) {
  int expected = provider->cipher_get_key_length(cipher);
  if (key == NULL || !key->valid || key->length != expected) {
    rtc_set_error(
      provider,
      "invalid key length: expected %d bytes",
      expected
    );
    return 0;
  }
  return 1;
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_aead_seal(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  rtc_crypto_secret *key,
  moonbit_bytes_t nonce,
  moonbit_bytes_t aad,
  moonbit_bytes_t plaintext,
  int32_t tag_length
) {
  if (provider == NULL || !provider->ready) {
    return rtc_empty_bytes();
  }
  const char *name = rtc_aead_name(algorithm);
  if (name == NULL) {
    rtc_set_error(provider, "unsupported AEAD algorithm");
    return rtc_empty_bytes();
  }
  int32_t nonce_length = Moonbit_array_length(nonce);
  int32_t aad_length = Moonbit_array_length(aad);
  int32_t plaintext_length = Moonbit_array_length(plaintext);
  if (
    nonce_length < 1 ||
    (tag_length != 8 && tag_length != 16) ||
    (!rtc_aead_is_ccm(algorithm) && tag_length != 16) ||
    plaintext_length > INT32_MAX - tag_length ||
    (rtc_aead_is_ccm(algorithm) &&
     (nonce_length < 7 || nonce_length > 13))
  ) {
    rtc_set_error(provider, "invalid AEAD nonce or plaintext length");
    return rtc_empty_bytes();
  }

  EVP_CIPHER *cipher =
    provider->cipher_fetch(NULL, name, rtc_property_query(provider));
  if (cipher == NULL) {
    rtc_set_error(provider, "AEAD cipher unavailable: %s", name);
    return rtc_empty_bytes();
  }
  if (!rtc_validate_key(provider, cipher, key)) {
    provider->cipher_free(cipher);
    return rtc_empty_bytes();
  }
  EVP_CIPHER_CTX *context = provider->cipher_ctx_new();
  if (context == NULL) {
    provider->cipher_free(cipher);
    rtc_set_openssl_error(provider, "unable to allocate AEAD context");
    return rtc_empty_bytes();
  }

  moonbit_bytes_t output =
    moonbit_make_bytes(plaintext_length + tag_length, 0);
  int produced = 0;
  int final_length = 0;
  int ignored = 0;
  int success = 0;
  if (rtc_aead_is_ccm(algorithm)) {
    success =
      provider->encrypt_init_ex2(context, cipher, NULL, NULL, NULL) == 1 &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_SET_IVLEN,
        nonce_length,
        NULL
      ) == 1 &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_SET_TAG,
        tag_length,
        NULL
      ) == 1 &&
      provider->encrypt_init_ex2(
        context,
        NULL,
        key->data,
        nonce,
        NULL
      ) == 1 &&
      provider->encrypt_update(
        context,
        NULL,
        &ignored,
        NULL,
        plaintext_length
      ) == 1 &&
      (aad_length == 0 ||
       provider->encrypt_update(
         context,
         NULL,
         &ignored,
         aad,
         aad_length
       ) == 1) &&
      provider->encrypt_update(
        context,
        output,
        &produced,
        plaintext,
        plaintext_length
      ) == 1 &&
      provider->encrypt_final_ex(
        context,
        output + produced,
        &final_length
      ) == 1 &&
      produced + final_length == plaintext_length &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_GET_TAG,
        tag_length,
        output + plaintext_length
      ) == 1;
  } else {
    success =
      provider->encrypt_init_ex2(context, cipher, NULL, NULL, NULL) == 1 &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_SET_IVLEN,
        nonce_length,
        NULL
      ) == 1 &&
      provider->encrypt_init_ex2(
        context,
        NULL,
        key->data,
        nonce,
        NULL
      ) == 1 &&
      (aad_length == 0 ||
       provider->encrypt_update(
         context,
         NULL,
         &ignored,
         aad,
         aad_length
       ) == 1) &&
      provider->encrypt_update(
        context,
        output,
        &produced,
        plaintext,
        plaintext_length
      ) == 1 &&
      provider->encrypt_final_ex(
        context,
        output + produced,
        &final_length
      ) == 1 &&
      produced + final_length == plaintext_length &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_GET_TAG,
        tag_length,
        output + plaintext_length
      ) == 1;
  }
  provider->cipher_ctx_free(context);
  provider->cipher_free(cipher);
  if (!success) {
    rtc_secure_clear(output, (size_t)plaintext_length + tag_length);
    moonbit_decref(output);
    rtc_set_openssl_error(provider, "OpenSSL AEAD seal failed");
    return rtc_empty_bytes();
  }
  return output;
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_aead_open(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  rtc_crypto_secret *key,
  moonbit_bytes_t nonce,
  moonbit_bytes_t aad,
  moonbit_bytes_t ciphertext,
  moonbit_bytes_t tag,
  int32_t *success_out
) {
  *success_out = 0;
  if (provider == NULL || !provider->ready) {
    return rtc_empty_bytes();
  }
  const char *name = rtc_aead_name(algorithm);
  if (name == NULL) {
    rtc_set_error(provider, "unsupported AEAD algorithm");
    return rtc_empty_bytes();
  }
  int32_t nonce_length = Moonbit_array_length(nonce);
  int32_t aad_length = Moonbit_array_length(aad);
  int32_t ciphertext_length = Moonbit_array_length(ciphertext);
  int32_t tag_length = Moonbit_array_length(tag);
  if (
    nonce_length < 1 ||
    (tag_length != 8 && tag_length != 16) ||
    (!rtc_aead_is_ccm(algorithm) && tag_length != 16) ||
    (rtc_aead_is_ccm(algorithm) &&
     (nonce_length < 7 || nonce_length > 13))
  ) {
    rtc_set_error(provider, "invalid AEAD nonce or tag length");
    return rtc_empty_bytes();
  }

  EVP_CIPHER *cipher =
    provider->cipher_fetch(NULL, name, rtc_property_query(provider));
  if (cipher == NULL) {
    rtc_set_error(provider, "AEAD cipher unavailable: %s", name);
    return rtc_empty_bytes();
  }
  if (!rtc_validate_key(provider, cipher, key)) {
    provider->cipher_free(cipher);
    return rtc_empty_bytes();
  }
  EVP_CIPHER_CTX *context = provider->cipher_ctx_new();
  if (context == NULL) {
    provider->cipher_free(cipher);
    rtc_set_openssl_error(provider, "unable to allocate AEAD context");
    return rtc_empty_bytes();
  }

  moonbit_bytes_t output = moonbit_make_bytes(ciphertext_length, 0);
  int produced = 0;
  int final_length = 0;
  int ignored = 0;
  int success = 0;
  if (rtc_aead_is_ccm(algorithm)) {
    success =
      provider->decrypt_init_ex2(context, cipher, NULL, NULL, NULL) == 1 &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_SET_IVLEN,
        nonce_length,
        NULL
      ) == 1 &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_SET_TAG,
        tag_length,
        tag
      ) == 1 &&
      provider->decrypt_init_ex2(
        context,
        NULL,
        key->data,
        nonce,
        NULL
      ) == 1 &&
      provider->decrypt_update(
        context,
        NULL,
        &ignored,
        NULL,
        ciphertext_length
      ) == 1 &&
      (aad_length == 0 ||
       provider->decrypt_update(
         context,
         NULL,
         &ignored,
         aad,
         aad_length
       ) == 1) &&
      provider->decrypt_update(
        context,
        output,
        &produced,
        ciphertext,
        ciphertext_length
      ) == 1 &&
      provider->decrypt_final_ex(
        context,
        output + produced,
        &final_length
      ) == 1 &&
      produced + final_length == ciphertext_length;
  } else {
    success =
      provider->decrypt_init_ex2(context, cipher, NULL, NULL, NULL) == 1 &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_SET_IVLEN,
        nonce_length,
        NULL
      ) == 1 &&
      provider->decrypt_init_ex2(
        context,
        NULL,
        key->data,
        nonce,
        NULL
      ) == 1 &&
      (aad_length == 0 ||
       provider->decrypt_update(
         context,
         NULL,
         &ignored,
         aad,
         aad_length
       ) == 1) &&
      provider->decrypt_update(
        context,
        output,
        &produced,
        ciphertext,
        ciphertext_length
      ) == 1 &&
      provider->cipher_ctx_ctrl(
        context,
        EVP_CTRL_AEAD_SET_TAG,
        tag_length,
        tag
      ) == 1 &&
      provider->decrypt_final_ex(
        context,
        output + produced,
        &final_length
      ) == 1 &&
      produced + final_length == ciphertext_length;
  }
  provider->cipher_ctx_free(context);
  provider->cipher_free(cipher);
  if (!success) {
    rtc_secure_clear(output, (size_t)ciphertext_length);
    moonbit_decref(output);
    rtc_set_error(provider, "OpenSSL AEAD authentication failed");
    return rtc_empty_bytes();
  }
  *success_out = 1;
  return output;
}

static const char *
rtc_cipher_name(int32_t algorithm) {
  switch (algorithm) {
    case 0:
      return "AES-128-CBC";
    case 1:
      return "AES-256-CBC";
    case 2:
      return "AES-128-CTR";
    case 3:
      return "AES-256-CTR";
    default:
      return NULL;
  }
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_cipher_crypt(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  rtc_crypto_secret *key,
  moonbit_bytes_t iv,
  moonbit_bytes_t input,
  int32_t encrypt,
  int32_t *success_out
) {
  *success_out = 0;
  if (provider == NULL || !provider->ready) {
    return rtc_empty_bytes();
  }
  const char *name = rtc_cipher_name(algorithm);
  if (name == NULL) {
    rtc_set_error(provider, "unsupported cipher algorithm");
    return rtc_empty_bytes();
  }
  int32_t input_length = Moonbit_array_length(input);
  int32_t iv_length = Moonbit_array_length(iv);
  if ((algorithm == 0 || algorithm == 1) && input_length % 16 != 0) {
    rtc_set_error(provider, "AES-CBC input length must be a multiple of 16");
    return rtc_empty_bytes();
  }
  EVP_CIPHER *cipher =
    provider->cipher_fetch(NULL, name, rtc_property_query(provider));
  if (cipher == NULL) {
    rtc_set_error(provider, "cipher unavailable: %s", name);
    return rtc_empty_bytes();
  }
  if (!rtc_validate_key(provider, cipher, key)) {
    provider->cipher_free(cipher);
    return rtc_empty_bytes();
  }
  if (iv_length != provider->cipher_get_iv_length(cipher)) {
    rtc_set_error(
      provider,
      "invalid IV length: expected %d bytes",
      provider->cipher_get_iv_length(cipher)
    );
    provider->cipher_free(cipher);
    return rtc_empty_bytes();
  }
  EVP_CIPHER_CTX *context = provider->cipher_ctx_new();
  if (context == NULL) {
    provider->cipher_free(cipher);
    rtc_set_openssl_error(provider, "unable to allocate cipher context");
    return rtc_empty_bytes();
  }
  moonbit_bytes_t output = moonbit_make_bytes(input_length, 0);
  int produced = 0;
  int final_length = 0;
  int success;
  if (encrypt) {
    success =
      provider->encrypt_init_ex2(context, cipher, key->data, iv, NULL) == 1 &&
      provider->cipher_ctx_set_padding(context, 0) == 1 &&
      provider->encrypt_update(
        context,
        output,
        &produced,
        input,
        input_length
      ) == 1 &&
      provider->encrypt_final_ex(
        context,
        output + produced,
        &final_length
      ) == 1;
  } else {
    success =
      provider->decrypt_init_ex2(context, cipher, key->data, iv, NULL) == 1 &&
      provider->cipher_ctx_set_padding(context, 0) == 1 &&
      provider->decrypt_update(
        context,
        output,
        &produced,
        input,
        input_length
      ) == 1 &&
      provider->decrypt_final_ex(
        context,
        output + produced,
        &final_length
      ) == 1;
  }
  success = success && produced + final_length == input_length;
  provider->cipher_ctx_free(context);
  provider->cipher_free(cipher);
  if (!success) {
    rtc_secure_clear(output, (size_t)input_length);
    moonbit_decref(output);
    rtc_set_openssl_error(provider, "OpenSSL cipher operation failed");
    return rtc_empty_bytes();
  }
  *success_out = 1;
  return output;
}

MOONBIT_FFI_EXPORT
rtc_crypto_secret *
moonbit_rtc_crypto_secret_from_bytes(moonbit_bytes_t value) {
  int32_t length = Moonbit_array_length(value);
  rtc_crypto_secret *secret =
    (rtc_crypto_secret *)moonbit_make_external_object(
      rtc_secret_destroy,
      sizeof(rtc_crypto_secret) + (size_t)length
    );
  secret->valid = 1;
  secret->length = length;
  if (length > 0) {
    memcpy(secret->data, value, (size_t)length);
  }
  return secret;
}

MOONBIT_FFI_EXPORT
rtc_crypto_secret *
moonbit_rtc_crypto_secret_random(
  rtc_crypto_provider *provider,
  int32_t length
) {
  int32_t allocation_length = length > 0 ? length : 0;
  rtc_crypto_secret *secret =
    (rtc_crypto_secret *)moonbit_make_external_object(
      rtc_secret_destroy,
      sizeof(rtc_crypto_secret) + (size_t)allocation_length
    );
  secret->valid = 0;
  secret->length = 0;
  if (provider == NULL || !provider->ready || length < 1) {
    if (provider != NULL) {
      rtc_set_error(provider, "invalid random secret request");
    }
    return secret;
  }
  if (provider->rand_bytes_ex(NULL, secret->data, (size_t)length, 0) != 1) {
    rtc_set_openssl_error(provider, "OpenSSL secret generation failed");
    rtc_secure_clear(secret->data, (size_t)length);
    return secret;
  }
  secret->length = length;
  secret->valid = 1;
  return secret;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_secret_is_valid(rtc_crypto_secret *secret) {
  return secret != NULL && secret->valid;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_secret_length(rtc_crypto_secret *secret) {
  return secret == NULL || !secret->valid ? 0 : secret->length;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_secret_constant_time_equal(
  rtc_crypto_provider *provider,
  rtc_crypto_secret *left,
  rtc_crypto_secret *right
) {
  if (
    provider == NULL ||
    !provider->ready ||
    left == NULL ||
    right == NULL ||
    !left->valid ||
    !right->valid ||
    left->length != right->length
  ) {
    return 0;
  }
  return provider->crypto_memcmp(
    left->data,
    right->data,
    (size_t)left->length
  ) == 0;
}

static rtc_crypto_key *
rtc_make_key(rtc_crypto_provider *provider, EVP_PKEY *value) {
  rtc_crypto_key *key =
    (rtc_crypto_key *)moonbit_make_external_object(
      rtc_key_destroy,
      sizeof(rtc_crypto_key)
    );
  key->key = value;
  key->free_key = provider == NULL ? NULL : provider->pkey_free;
  return key;
}

static rtc_crypto_certificate *
rtc_make_certificate(rtc_crypto_provider *provider, X509 *value) {
  rtc_crypto_certificate *certificate =
    (rtc_crypto_certificate *)moonbit_make_external_object(
      rtc_certificate_destroy,
      sizeof(rtc_crypto_certificate)
    );
  certificate->certificate = value;
  certificate->free_certificate =
    provider == NULL ? NULL : provider->x509_free;
  return certificate;
}

static rtc_crypto_secret *
rtc_make_secret(size_t capacity) {
  rtc_crypto_secret *secret =
    (rtc_crypto_secret *)moonbit_make_external_object(
      rtc_secret_destroy,
      sizeof(rtc_crypto_secret) + capacity
    );
  secret->valid = 0;
  secret->length = 0;
  return secret;
}

MOONBIT_FFI_EXPORT
rtc_crypto_key *
moonbit_rtc_crypto_generate_private_key(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  int32_t *success_out
) {
  *success_out = 0;
  if (provider == NULL || !provider->ready) {
    return rtc_make_key(provider, NULL);
  }
  EVP_PKEY *key = NULL;
  switch (algorithm) {
    case 0:
      key = provider->pkey_q_keygen(
        NULL,
        rtc_property_query(provider),
        "EC",
        "P-256"
      );
      break;
    case 1:
      key = provider->pkey_q_keygen(
        NULL,
        rtc_property_query(provider),
        "EC",
        "P-384"
      );
      break;
    case 2:
      key = provider->pkey_q_keygen(
        NULL,
        rtc_property_query(provider),
        "X25519"
      );
      break;
    case 3:
      key = provider->pkey_q_keygen(
        NULL,
        rtc_property_query(provider),
        "RSA",
        (size_t)2048
      );
      break;
    default:
      rtc_set_error(provider, "unsupported private key algorithm");
      return rtc_make_key(provider, NULL);
  }
  if (key == NULL) {
    rtc_set_openssl_error(provider, "OpenSSL private key generation failed");
    return rtc_make_key(provider, NULL);
  }
  *success_out = 1;
  return rtc_make_key(provider, key);
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_private_key_public_der(
  rtc_crypto_provider *provider,
  rtc_crypto_key *key,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    key == NULL ||
    key->key == NULL
  ) {
    return rtc_empty_bytes();
  }
  int length = provider->i2d_pubkey(key->key, NULL);
  if (length <= 0) {
    rtc_set_openssl_error(provider, "OpenSSL public key encoding failed");
    return rtc_empty_bytes();
  }
  moonbit_bytes_t result = moonbit_make_bytes(length, 0);
  unsigned char *cursor = result;
  int written = provider->i2d_pubkey(key->key, &cursor);
  if (written != length) {
    moonbit_decref(result);
    rtc_set_openssl_error(provider, "OpenSSL public key encoding failed");
    return rtc_empty_bytes();
  }
  *success_out = 1;
  return result;
}

MOONBIT_FFI_EXPORT
rtc_crypto_key *
moonbit_rtc_crypto_public_key_from_der(
  rtc_crypto_provider *provider,
  moonbit_bytes_t der,
  int32_t *success_out
) {
  *success_out = 0;
  if (provider == NULL || !provider->ready) {
    return rtc_make_key(provider, NULL);
  }
  int32_t length = Moonbit_array_length(der);
  const unsigned char *cursor = der;
  EVP_PKEY *key = provider->d2i_pubkey_ex(
    NULL,
    &cursor,
    (long)length,
    NULL,
    rtc_property_query(provider)
  );
  if (key == NULL || cursor != der + length) {
    if (key != NULL) {
      provider->pkey_free(key);
    }
    rtc_set_openssl_error(provider, "OpenSSL public key decoding failed");
    return rtc_make_key(provider, NULL);
  }
  *success_out = 1;
  return rtc_make_key(provider, key);
}

MOONBIT_FFI_EXPORT
rtc_crypto_secret *
moonbit_rtc_crypto_derive_secret(
  rtc_crypto_provider *provider,
  rtc_crypto_key *private_key,
  rtc_crypto_key *peer_key,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    private_key == NULL ||
    private_key->key == NULL ||
    peer_key == NULL ||
    peer_key->key == NULL
  ) {
    return rtc_make_secret(0);
  }
  EVP_PKEY_CTX *context = provider->pkey_ctx_new_from_pkey(
    NULL,
    private_key->key,
    rtc_property_query(provider)
  );
  size_t length = 0;
  int initialized =
    context != NULL &&
    provider->pkey_derive_init(context) == 1 &&
    provider->pkey_derive_set_peer(context, peer_key->key) == 1 &&
    provider->pkey_derive(context, NULL, &length) == 1 &&
    length > 0 &&
    length <= INT32_MAX;
  if (!initialized) {
    if (context != NULL) {
      provider->pkey_ctx_free(context);
    }
    rtc_set_openssl_error(provider, "OpenSSL shared-secret setup failed");
    return rtc_make_secret(0);
  }
  rtc_crypto_secret *secret = rtc_make_secret(length);
  size_t actual_length = length;
  if (
    provider->pkey_derive(context, secret->data, &actual_length) != 1 ||
    actual_length != length
  ) {
    provider->pkey_ctx_free(context);
    rtc_secure_clear(secret->data, length);
    rtc_set_openssl_error(provider, "OpenSSL shared-secret derivation failed");
    return secret;
  }
  provider->pkey_ctx_free(context);
  secret->length = (int32_t)actual_length;
  secret->valid = 1;
  *success_out = 1;
  return secret;
}

static const char *
rtc_signature_digest_name(int32_t algorithm) {
  switch (algorithm) {
    case 0:
    case 2:
    case 3:
      return "SHA256";
    case 1:
      return "SHA384";
    default:
      return NULL;
  }
}

static const OSSL_PARAM *
rtc_signature_parameters(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  OSSL_PARAM parameters[3],
  char pad_mode[16],
  char salt_length[16]
) {
  if (algorithm == 2) {
    snprintf(pad_mode, 16, "%s", "pss");
    snprintf(salt_length, 16, "%s", "digest");
    parameters[0] = provider->param_utf8_string(
      OSSL_SIGNATURE_PARAM_PAD_MODE,
      pad_mode,
      0
    );
    parameters[1] = provider->param_utf8_string(
      OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
      salt_length,
      0
    );
    parameters[2] = provider->param_end();
    return parameters;
  }
  if (algorithm == 3) {
    snprintf(pad_mode, 16, "%s", "pkcs1");
    parameters[0] = provider->param_utf8_string(
      OSSL_SIGNATURE_PARAM_PAD_MODE,
      pad_mode,
      0
    );
    parameters[1] = provider->param_end();
    return parameters;
  }
  return NULL;
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_sign(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  rtc_crypto_key *key,
  moonbit_bytes_t data,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    key == NULL ||
    key->key == NULL
  ) {
    return rtc_empty_bytes();
  }
  const char *digest_name = rtc_signature_digest_name(algorithm);
  if (digest_name == NULL) {
    rtc_set_error(provider, "unsupported signature algorithm");
    return rtc_empty_bytes();
  }
  OSSL_PARAM parameters[3];
  char pad_mode[16] = { 0 };
  char salt_length[16] = { 0 };
  const OSSL_PARAM *parameter_pointer = rtc_signature_parameters(
    provider,
    algorithm,
    parameters,
    pad_mode,
    salt_length
  );
  EVP_MD_CTX *context = provider->md_ctx_new();
  size_t signature_length = 0;
  int initialized =
    context != NULL &&
    provider->digest_sign_init_ex(
      context,
      NULL,
      digest_name,
      NULL,
      rtc_property_query(provider),
      key->key,
      parameter_pointer
    ) == 1 &&
    provider->digest_sign_update(
      context,
      data,
      (size_t)Moonbit_array_length(data)
    ) == 1 &&
    provider->digest_sign_final(context, NULL, &signature_length) == 1 &&
    signature_length > 0 &&
    signature_length <= INT32_MAX;
  if (!initialized) {
    if (context != NULL) {
      provider->md_ctx_free(context);
    }
    rtc_set_openssl_error(provider, "OpenSSL signing setup failed");
    return rtc_empty_bytes();
  }
  unsigned char *signature = (unsigned char *)malloc(signature_length);
  if (signature == NULL) {
    provider->md_ctx_free(context);
    rtc_set_error(provider, "unable to allocate signature buffer");
    return rtc_empty_bytes();
  }
  size_t actual_length = signature_length;
  if (
    provider->digest_sign_final(
      context,
      signature,
      &actual_length
    ) != 1 ||
    actual_length == 0 ||
    actual_length > signature_length
  ) {
    provider->md_ctx_free(context);
    rtc_secure_clear(signature, signature_length);
    free(signature);
    rtc_set_openssl_error(provider, "OpenSSL signing failed");
    return rtc_empty_bytes();
  }
  provider->md_ctx_free(context);
  moonbit_bytes_t result = rtc_copy_bytes(signature, actual_length);
  rtc_secure_clear(signature, signature_length);
  free(signature);
  rtc_secure_clear(pad_mode, sizeof(pad_mode));
  rtc_secure_clear(salt_length, sizeof(salt_length));
  *success_out = 1;
  return result;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_verify(
  rtc_crypto_provider *provider,
  int32_t algorithm,
  rtc_crypto_key *key,
  moonbit_bytes_t data,
  moonbit_bytes_t signature
) {
  if (
    provider == NULL ||
    !provider->ready ||
    key == NULL ||
    key->key == NULL
  ) {
    return -1;
  }
  const char *digest_name = rtc_signature_digest_name(algorithm);
  if (digest_name == NULL) {
    rtc_set_error(provider, "unsupported signature algorithm");
    return -1;
  }
  OSSL_PARAM parameters[3];
  char pad_mode[16] = { 0 };
  char salt_length[16] = { 0 };
  const OSSL_PARAM *parameter_pointer = rtc_signature_parameters(
    provider,
    algorithm,
    parameters,
    pad_mode,
    salt_length
  );
  EVP_MD_CTX *context = provider->md_ctx_new();
  int initialized =
    context != NULL &&
    provider->digest_verify_init_ex(
      context,
      NULL,
      digest_name,
      NULL,
      rtc_property_query(provider),
      key->key,
      parameter_pointer
    ) == 1 &&
    provider->digest_verify_update(
      context,
      data,
      (size_t)Moonbit_array_length(data)
    ) == 1;
  if (!initialized) {
    if (context != NULL) {
      provider->md_ctx_free(context);
    }
    rtc_set_openssl_error(provider, "OpenSSL verification setup failed");
    return -1;
  }
  int result = provider->digest_verify_final(
    context,
    signature,
    (size_t)Moonbit_array_length(signature)
  );
  provider->md_ctx_free(context);
  rtc_secure_clear(pad_mode, sizeof(pad_mode));
  rtc_secure_clear(salt_length, sizeof(salt_length));
  if (result < 0) {
    rtc_set_openssl_error(provider, "OpenSSL verification failed");
    return -1;
  }
  return result == 1 ? 1 : 0;
}

MOONBIT_FFI_EXPORT
rtc_crypto_certificate *
moonbit_rtc_crypto_self_signed_certificate(
  rtc_crypto_provider *provider,
  rtc_crypto_key *key,
  moonbit_bytes_t common_name,
  int64_t not_before_seconds,
  int64_t not_after_seconds,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    key == NULL ||
    key->key == NULL
  ) {
    return rtc_make_certificate(provider, NULL);
  }
  int32_t common_name_length = Moonbit_array_length(common_name);
  if (
    common_name_length < 1 ||
    common_name_length > 255 ||
    memchr(common_name, 0, (size_t)common_name_length) != NULL ||
    not_before_seconds >= not_after_seconds
  ) {
    rtc_set_error(provider, "invalid X.509 name or validity interval");
    return rtc_make_certificate(provider, NULL);
  }
  time_t not_before_time = (time_t)not_before_seconds;
  time_t not_after_time = (time_t)not_after_seconds;
  if (
    (int64_t)not_before_time != not_before_seconds ||
    (int64_t)not_after_time != not_after_seconds
  ) {
    rtc_set_error(provider, "X.509 validity is outside time_t range");
    return rtc_make_certificate(provider, NULL);
  }

  X509 *certificate =
    provider->x509_new_ex(NULL, rtc_property_query(provider));
  if (certificate == NULL) {
    rtc_set_openssl_error(provider, "OpenSSL X.509 allocation failed");
    return rtc_make_certificate(provider, NULL);
  }
  uint64_t serial = 0;
  EVP_MD *digest = NULL;
  X509_NAME *subject = provider->x509_get_subject_name(certificate);
  int success =
    provider->rand_bytes_ex(
      NULL,
      (unsigned char *)&serial,
      sizeof(serial),
      0
    ) == 1;
  serial &= UINT64_C(0x7fffffffffffffff);
  if (serial == 0) {
    serial = 1;
  }
  success =
    success &&
    provider->x509_set_version(certificate, 2) == 1 &&
    provider->asn1_integer_set_uint64(
      provider->x509_get_serial_number(certificate),
      serial
    ) == 1 &&
    subject != NULL &&
    provider->x509_name_add_entry_by_txt(
      subject,
      "CN",
      MBSTRING_UTF8,
      common_name,
      common_name_length,
      -1,
      0
    ) == 1 &&
    provider->x509_set_issuer_name(certificate, subject) == 1 &&
    provider->asn1_time_set(
      provider->x509_getm_not_before(certificate),
      not_before_time
    ) != NULL &&
    provider->asn1_time_set(
      provider->x509_getm_not_after(certificate),
      not_after_time
    ) != NULL &&
    provider->x509_set_pubkey(certificate, key->key) == 1;
  if (success) {
    digest = provider->md_fetch(
      NULL,
      "SHA256",
      rtc_property_query(provider)
    );
    success =
      digest != NULL &&
      provider->x509_sign(certificate, key->key, digest) > 0;
  }
  if (digest != NULL) {
    provider->md_free(digest);
  }
  if (!success) {
    provider->x509_free(certificate);
    rtc_set_openssl_error(provider, "OpenSSL self-signed X.509 creation failed");
    return rtc_make_certificate(provider, NULL);
  }
  *success_out = 1;
  return rtc_make_certificate(provider, certificate);
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_certificate_to_der(
  rtc_crypto_provider *provider,
  rtc_crypto_certificate *certificate,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    certificate == NULL ||
    certificate->certificate == NULL
  ) {
    return rtc_empty_bytes();
  }
  int length = provider->i2d_x509(certificate->certificate, NULL);
  if (length <= 0) {
    rtc_set_openssl_error(provider, "OpenSSL X.509 encoding failed");
    return rtc_empty_bytes();
  }
  moonbit_bytes_t result = moonbit_make_bytes(length, 0);
  unsigned char *cursor = result;
  int written = provider->i2d_x509(certificate->certificate, &cursor);
  if (written != length) {
    moonbit_decref(result);
    rtc_set_openssl_error(provider, "OpenSSL X.509 encoding failed");
    return rtc_empty_bytes();
  }
  *success_out = 1;
  return result;
}

MOONBIT_FFI_EXPORT
rtc_crypto_certificate *
moonbit_rtc_crypto_certificate_from_der(
  rtc_crypto_provider *provider,
  moonbit_bytes_t der,
  int32_t *success_out
) {
  *success_out = 0;
  if (provider == NULL || !provider->ready) {
    return rtc_make_certificate(provider, NULL);
  }
  int32_t length = Moonbit_array_length(der);
  const unsigned char *cursor = der;
  X509 *certificate = provider->d2i_x509(NULL, &cursor, (long)length);
  if (certificate == NULL || cursor != der + length) {
    if (certificate != NULL) {
      provider->x509_free(certificate);
    }
    rtc_set_openssl_error(provider, "OpenSSL X.509 decoding failed");
    return rtc_make_certificate(provider, NULL);
  }
  *success_out = 1;
  return rtc_make_certificate(provider, certificate);
}

MOONBIT_FFI_EXPORT
rtc_crypto_key *
moonbit_rtc_crypto_certificate_public_key(
  rtc_crypto_provider *provider,
  rtc_crypto_certificate *certificate,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    certificate == NULL ||
    certificate->certificate == NULL
  ) {
    return rtc_make_key(provider, NULL);
  }
  EVP_PKEY *key = provider->x509_get_pubkey(certificate->certificate);
  if (key == NULL) {
    rtc_set_openssl_error(provider, "OpenSSL X.509 public key extraction failed");
    return rtc_make_key(provider, NULL);
  }
  *success_out = 1;
  return rtc_make_key(provider, key);
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t
moonbit_rtc_crypto_certificate_fingerprint(
  rtc_crypto_provider *provider,
  rtc_crypto_certificate *certificate,
  int32_t algorithm,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    certificate == NULL ||
    certificate->certificate == NULL
  ) {
    return rtc_empty_bytes();
  }
  const char *digest_name = rtc_digest_name(algorithm);
  if (digest_name == NULL) {
    rtc_set_error(provider, "unsupported certificate fingerprint algorithm");
    return rtc_empty_bytes();
  }
  EVP_MD *digest = provider->md_fetch(
    NULL,
    digest_name,
    rtc_property_query(provider)
  );
  if (digest == NULL) {
    rtc_set_error(
      provider,
      "certificate fingerprint digest unavailable: %s",
      digest_name
    );
    return rtc_empty_bytes();
  }
  unsigned char output[EVP_MAX_MD_SIZE];
  unsigned int output_length = 0;
  int success = provider->x509_digest(
    certificate->certificate,
    digest,
    output,
    &output_length
  );
  provider->md_free(digest);
  if (success != 1 || output_length == 0) {
    rtc_secure_clear(output, sizeof(output));
    rtc_set_openssl_error(provider, "OpenSSL X.509 fingerprint failed");
    return rtc_empty_bytes();
  }
  moonbit_bytes_t result = rtc_copy_bytes(output, output_length);
  rtc_secure_clear(output, sizeof(output));
  *success_out = 1;
  return result;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_certificate_valid_at(
  rtc_crypto_provider *provider,
  rtc_crypto_certificate *certificate,
  int64_t unix_seconds,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    certificate == NULL ||
    certificate->certificate == NULL
  ) {
    return 0;
  }
  time_t checked_time = (time_t)unix_seconds;
  if ((int64_t)checked_time != unix_seconds) {
    rtc_set_error(provider, "certificate validation time is outside time_t range");
    return 0;
  }
  int not_before = provider->x509_cmp_time(
    provider->x509_get0_not_before(certificate->certificate),
    &checked_time
  );
  int not_after = provider->x509_cmp_time(
    provider->x509_get0_not_after(certificate->certificate),
    &checked_time
  );
  if (not_before == 0 || not_after == 0) {
    rtc_set_openssl_error(provider, "OpenSSL X.509 validity check failed");
    return 0;
  }
  *success_out = 1;
  return not_before <= 0 && not_after >= 0;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_rtc_crypto_certificate_verify_self_signature(
  rtc_crypto_provider *provider,
  rtc_crypto_certificate *certificate,
  int32_t *success_out
) {
  *success_out = 0;
  if (
    provider == NULL ||
    !provider->ready ||
    certificate == NULL ||
    certificate->certificate == NULL
  ) {
    return 0;
  }
  EVP_PKEY *key = provider->x509_get_pubkey(certificate->certificate);
  if (key == NULL) {
    rtc_set_openssl_error(provider, "OpenSSL X.509 public key extraction failed");
    return 0;
  }
  int result = provider->x509_verify(certificate->certificate, key);
  provider->pkey_free(key);
  if (result < 0) {
    rtc_set_openssl_error(provider, "OpenSSL X.509 signature check failed");
    return 0;
  }
  *success_out = 1;
  return result == 1;
}
