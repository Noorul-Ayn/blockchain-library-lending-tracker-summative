/**
 * @file crypto.h
 * @brief Thin, error-checked wrappers around OpenSSL (libcrypto).
 *
 *  - SHA-256 hashing for block hashes and chain linkage
 *  - ECDSA (curve P-256 / prime256v1) key generation, signing, verification
 *  - Private keys stored as encrypted PKCS#8 PEM (AES-256-CBC, PBKDF2)
 *  - PBKDF2-HMAC-SHA256 password hashing with a random 16-byte salt
 */
#ifndef LT_CRYPTO_H
#define LT_CRYPTO_H

#include <stddef.h>

#include <openssl/evp.h>

#include "common.h"

#define SALT_LEN           16
#define PASSWORD_HASH_LEN  32
#define PBKDF2_ITERATIONS  600000   /* OWASP 2023 guidance for PBKDF2-HMAC-SHA256 */

/** SHA-256 of data, written as 64 lowercase hex characters + NUL. */
Status crypto_sha256_hex(const void *data, size_t len, char out[HASH_HEX_LEN]);

/**
 * Generates a new ECDSA P-256 key pair. The private key is written to
 * private_path as encrypted PKCS#8 (mode 0600); the public key is written to
 * public_path (mode 0644). Existing files are never overwritten.
 */
Status crypto_generate_keypair(const char *private_path, const char *public_path,
                               const char *passphrase);

/** Decrypts and loads a private key. @return NULL on wrong passphrase / error. */
EVP_PKEY *crypto_load_private_key(const char *path, const char *passphrase);

/** Loads a PEM public key. @return NULL if missing or not an EC key. */
EVP_PKEY *crypto_load_public_key(const char *path);

/** Proves that private_key and public_key form a pair (sign/verify challenge). */
int crypto_keys_match(EVP_PKEY *private_key, EVP_PKEY *public_key);

/**
 * ECDSA-SHA256 signature over data. On entry *sig_len is the size of sig; on
 * success it holds the DER signature length (at most SIGNATURE_MAX_LEN).
 */
Status crypto_sign(EVP_PKEY *key, const void *data, size_t len,
                   unsigned char *sig, size_t *sig_len);

/** @return 1 if sig is a valid ECDSA-SHA256 signature of data, else 0. */
int crypto_verify(EVP_PKEY *key, const void *data, size_t len,
                  const unsigned char *sig, size_t sig_len);

/** Fills buf with cryptographically secure random bytes. */
Status crypto_random_bytes(unsigned char *buf, size_t len);

/** PBKDF2-HMAC-SHA256 key derivation (used for password hashing). */
Status crypto_pbkdf2(const char *password, const unsigned char *salt, size_t salt_len,
                     int iterations, unsigned char *out, size_t out_len);

/** Constant-time comparison. @return 1 if equal. */
int crypto_equal(const void *a, const void *b, size_t len);

/** Securely erases sensitive memory (cannot be optimised away). */
void crypto_wipe(void *buf, size_t len);

#endif /* LT_CRYPTO_H */
