/* Crypto helpers for hashing, signing, and authentication. */
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <openssl/evp.h>
#include "types.h"

/* Hash a byte buffer to a lowercase hex SHA-256 digest. */
int sha256_hex(const void *data, size_t len, char out_hex[HASH_HEX_LEN]);

/* Load the existing key pair or create a new P-256 key pair if missing. */
EVP_PKEY *crypto_load_or_generate_keys(void);

/* Sign and verify arbitrary data using ECDSA with SHA-256. */
int crypto_sign(EVP_PKEY *key, const unsigned char *data, size_t len,
                unsigned char *sig_out, size_t *sig_len_out);

int crypto_verify(EVP_PKEY *key, const unsigned char *data, size_t len,
                  const unsigned char *sig, size_t sig_len);

/* Byte/hex conversion helpers for serializing signatures and salts. */
void bytes_to_hex(const unsigned char *in, size_t len, char *out_hex);
int  hex_to_bytes(const char *hex, unsigned char *out, size_t max_out,
                  size_t *out_len);

/* Bootstrap and validate the local auth file. */
int  auth_bootstrap(void);
int  auth_login(char *role_out, size_t role_sz,
                char *user_out, size_t user_sz);

#endif /* CRYPTO_UTILS_H */
