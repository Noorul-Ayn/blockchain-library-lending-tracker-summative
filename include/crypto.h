/**
 * @file crypto.h
 * @brief Thin, error-checked wrappers around OpenSSL (libcrypto).
 *
 *  - SHA-256 hashing for block hashes and chain linkage
 *  - ECDSA (curve P-256 / prime256v1) key generation, signing, verification
 *  - Private keys stored as encrypted PKCS#8 PEM (AES-256-CBC, PBKDF2)
 *  - PBKDF2-HMAC-SHA256 password hashing with a random 16-byte salt
 *  - Compressed public keys (hex) used as signer identities on the chain
 *  - AES-256-GCM authenticated encryption for the member key vault
 *
 * ECDSA is used through OpenSSL's EVP_PKEY interface. The older EC_KEY API
 * performs the same operations but is deprecated since OpenSSL 3.0 and would
 * produce compiler warnings.
 */
#ifndef LT_CRYPTO_H
#define LT_CRYPTO_H

#include <stddef.h>

#include <openssl/evp.h>

#include "common.h"

#define SALT_LEN           16
#define PASSWORD_HASH_LEN  32
#define PBKDF2_ITERATIONS  600000   /* OWASP 2023 guidance for PBKDF2-HMAC-SHA256 */
#define AES_KEY_LEN        32       /* AES-256 key / vault key                    */
#define GCM_IV_LEN         12
#define GCM_TAG_LEN        16

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

/* ---- In-memory keys ------------------------------------------------------ */

/** New ECDSA P-256 key pair in memory (caller frees with EVP_PKEY_free). */
EVP_PKEY *crypto_generate_key(void);

/** Compressed public key as 66 hex characters (the on-chain signer identity). */
Status crypto_public_key_hex(EVP_PKEY *key, char out[PUBKEY_HEX_LEN]);

/** Public key from its hex form; NULL if malformed or not on the curve. */
EVP_PKEY *crypto_public_key_from_hex(const char *hex);

/** Writes a PEM public key to a new file (mode 0644). */
Status crypto_save_public_key(const char *path, EVP_PKEY *key);

/** DER encoding of a private key (free *der with OPENSSL_free). */
Status crypto_private_key_der(EVP_PKEY *key, unsigned char **der, size_t *len);
EVP_PKEY *crypto_private_key_from_der(const unsigned char *der, size_t len);

/* ---- AES-256-GCM ---------------------------------------------------------- */

/** Encrypts len bytes; a random IV is generated and returned with the tag. */
Status crypto_aes_gcm_encrypt(const unsigned char key[AES_KEY_LEN],
                              const unsigned char *plain, size_t len,
                              unsigned char iv[GCM_IV_LEN], unsigned char *cipher,
                              unsigned char tag[GCM_TAG_LEN]);

/** Decrypts and authenticates; fails (LT_ERR_CRYPTO) if anything was modified. */
Status crypto_aes_gcm_decrypt(const unsigned char key[AES_KEY_LEN],
                              const unsigned char *cipher, size_t len,
                              const unsigned char iv[GCM_IV_LEN],
                              const unsigned char tag[GCM_TAG_LEN], unsigned char *plain);

#endif /* LT_CRYPTO_H */
