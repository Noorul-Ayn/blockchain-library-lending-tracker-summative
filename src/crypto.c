/**
 * @file crypto.c
 * @brief OpenSSL-backed hashing, key management, signatures and PBKDF2.
 */
#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "OpenSSL 3.0 or newer is required (sudo apt install libssl-dev)"
#endif

#include "util.h"

/** Prints and clears any queued OpenSSL errors. */
static void report_openssl_errors(const char *context)
{
    unsigned long code;
    char buf[256];

    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, buf, sizeof buf);
        fprintf(stderr, "  [openssl] %s: %s\n", context, buf);
    }
}

Status crypto_sha256_hex(const void *data, size_t len, char out[HASH_HEX_LEN])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_Digest(data, len, digest, &digest_len, EVP_sha256(), NULL) != 1 ||
        digest_len != 32) {
        report_openssl_errors("SHA-256");
        return LT_ERR_CRYPTO;
    }
    hex_encode(digest, digest_len, out);
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Key management                                                           */
/* ------------------------------------------------------------------------ */

/** Generates a new ECDSA key pair on the NIST P-256 curve (prime256v1). */
static EVP_PKEY *generate_ec_key(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/**
 * Writes pkey as an encrypted PKCS#8 PEM ("ENCRYPTED PRIVATE KEY"):
 * PBES2 with PBKDF2-HMAC-SHA256 (PBKDF2_ITERATIONS rounds, random salt)
 * and AES-256-CBC. OpenSSL's default is only 2048 rounds, which would make
 * the key file a much cheaper password-guessing target than users.db.
 */
static int write_encrypted_private_key(FILE *fp, EVP_PKEY *pkey, const char *passphrase)
{
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(pkey);
    X509_SIG *encrypted = NULL;
    int ok = 0;

    if (p8 != NULL)
        encrypted = PKCS8_encrypt(-1, EVP_aes_256_cbc(), passphrase, (int)strlen(passphrase),
                                  NULL, 0, PBKDF2_ITERATIONS, p8);
    if (encrypted != NULL)
        ok = PEM_write_PKCS8(fp, encrypted) == 1;
    X509_SIG_free(encrypted);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return ok;
}

/** Opens a brand-new file with the given permissions (fails if it exists). */
static FILE *create_exclusive(const char *path, mode_t mode, Status *st)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    FILE *fp;

    if (fd < 0) {
        *st = (errno == EEXIST) ? LT_ERR_EXISTS : LT_ERR_IO;
        fprintf(stderr, "ERROR: cannot create '%s': %s\n", path, strerror(errno));
        return NULL;
    }
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(path);
        *st = LT_ERR_IO;
    }
    return fp;
}

Status crypto_generate_keypair(const char *private_path, const char *public_path,
                               const char *passphrase)
{
    EVP_PKEY *pkey = generate_ec_key();
    FILE *fp = NULL;
    int private_created = 0, public_created = 0;
    Status st = LT_ERR_CRYPTO;

    if (pkey == NULL) {
        report_openssl_errors("EC key generation");
        return LT_ERR_CRYPTO;
    }

    /* Private key: PKCS#8, encrypted with AES-256-CBC (PBES2 / PBKDF2). */
    fp = create_exclusive(private_path, S_IRUSR | S_IWUSR, &st);
    if (fp == NULL)
        goto done;
    private_created = 1;
    if (!write_encrypted_private_key(fp, pkey, passphrase)) {
        report_openssl_errors("write private key");
        fclose(fp);
        st = LT_ERR_CRYPTO;
        goto done;
    }
    if (fclose(fp) != 0) {
        st = LT_ERR_IO;
        goto done;
    }

    /* Public key: SubjectPublicKeyInfo PEM, readable by everyone. */
    fp = create_exclusive(public_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, &st);
    if (fp == NULL)
        goto done;
    public_created = 1;
    if (PEM_write_PUBKEY(fp, pkey) != 1) {
        report_openssl_errors("write public key");
        fclose(fp);
        st = LT_ERR_CRYPTO;
        goto done;
    }
    st = (fclose(fp) == 0) ? LT_OK : LT_ERR_IO;

done:
    EVP_PKEY_free(pkey);
    if (st != LT_OK) {
        if (private_created)
            unlink(private_path);
        if (public_created)
            unlink(public_path);
    }
    return st;
}

EVP_PKEY *crypto_load_private_key(const char *path, const char *passphrase)
{
    struct stat info;
    EVP_PKEY *pkey;
    FILE *fp;

    if (stat(path, &info) == 0 && (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        fprintf(stderr, "WARNING: private key '%s' is accessible by other users "
                        "(run: chmod 600 %s)\n", path, path);
    }
    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;
    /* With a NULL callback, OpenSSL uses the last argument as the passphrase. */
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)passphrase);
    fclose(fp);
    if (pkey != NULL && EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    ERR_clear_error(); /* a wrong passphrase is reported by the caller */
    return pkey;
}

EVP_PKEY *crypto_load_public_key(const char *path)
{
    EVP_PKEY *pkey;
    FILE *fp = fopen(path, "r");

    if (fp == NULL)
        return NULL;
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey != NULL && EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    ERR_clear_error();
    return pkey;
}

int crypto_keys_match(EVP_PKEY *private_key, EVP_PKEY *public_key)
{
    unsigned char challenge[32];
    unsigned char sig[SIGNATURE_MAX_LEN];
    size_t sig_len = sizeof sig;

    if (crypto_random_bytes(challenge, sizeof challenge) != LT_OK ||
        crypto_sign(private_key, challenge, sizeof challenge, sig, &sig_len) != LT_OK)
        return 0;
    return crypto_verify(public_key, challenge, sizeof challenge, sig, sig_len);
}

/* ------------------------------------------------------------------------ */
/* Signatures                                                               */
/* ------------------------------------------------------------------------ */

Status crypto_sign(EVP_PKEY *key, const void *data, size_t len,
                   unsigned char *sig, size_t *sig_len)
{
    EVP_MD_CTX *ctx;
    size_t needed = 0;
    Status st = LT_ERR_CRYPTO;

    if (key == NULL || sig == NULL || sig_len == NULL)
        return LT_ERR_INPUT;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return LT_ERR_MEMORY;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) == 1 &&
        EVP_DigestSign(ctx, NULL, &needed, data, len) == 1 &&
        needed <= *sig_len) {
        size_t written = *sig_len;
        if (EVP_DigestSign(ctx, sig, &written, data, len) == 1) {
            *sig_len = written;
            st = LT_OK;
        }
    }
    if (st != LT_OK)
        report_openssl_errors("ECDSA sign");
    EVP_MD_CTX_free(ctx);
    return st;
}

int crypto_verify(EVP_PKEY *key, const void *data, size_t len,
                  const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *ctx;
    int valid = 0;

    if (key == NULL || sig == NULL || sig_len == 0)
        return 0;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1)
        valid = (EVP_DigestVerify(ctx, sig, sig_len, data, len) == 1);
    EVP_MD_CTX_free(ctx);
    ERR_clear_error(); /* a failed verification is an expected outcome */
    return valid;
}

/* ------------------------------------------------------------------------ */
/* Randomness, password hashing, memory hygiene                             */
/* ------------------------------------------------------------------------ */

Status crypto_random_bytes(unsigned char *buf, size_t len)
{
    if (len > (size_t)0x7FFFFFFF || RAND_bytes(buf, (int)len) != 1) {
        report_openssl_errors("RAND_bytes");
        return LT_ERR_CRYPTO;
    }
    return LT_OK;
}

Status crypto_pbkdf2(const char *password, const unsigned char *salt, size_t salt_len,
                     int iterations, unsigned char *out, size_t out_len)
{
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)salt_len,
                          iterations, EVP_sha256(), (int)out_len, out) != 1) {
        report_openssl_errors("PBKDF2");
        return LT_ERR_CRYPTO;
    }
    return LT_OK;
}

int crypto_equal(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

void crypto_wipe(void *buf, size_t len)
{
    OPENSSL_cleanse(buf, len);
}

/* ------------------------------------------------------------------------ */
/* In-memory keys: member key pairs and public keys stored on-chain         */
/* ------------------------------------------------------------------------ */

EVP_PKEY *crypto_generate_key(void)
{
    EVP_PKEY *pkey = generate_ec_key();

    if (pkey == NULL)
        report_openssl_errors("EC key generation");
    return pkey;
}

/**
 * Encodes the public key as a compressed P-256 point (33 bytes: 02/03 prefix
 * + X coordinate) in hex. This 66-character string is the signer's identity
 * written into every record on the chain.
 */
Status crypto_public_key_hex(EVP_PKEY *key, char out[PUBKEY_HEX_LEN])
{
    unsigned char buf[80];
    size_t len = 0;

    out[0] = '\0';
    if (key == NULL)
        return LT_ERR_INPUT;
    if (EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                       OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED) != 1 ||
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof buf,
                                        &len) != 1 ||
        len != 33) {
        report_openssl_errors("encode public key");
        return LT_ERR_CRYPTO;
    }
    hex_encode(buf, len, out);
    return LT_OK;
}

/** Rebuilds a public key from its compressed-point hex; NULL if invalid. */
EVP_PKEY *crypto_public_key_from_hex(const char *hex)
{
    unsigned char buf[33];
    size_t len = 0;
    EVP_PKEY_CTX *ctx = NULL, *check = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];

    if (!is_hex_string(hex, 66) || hex_decode(hex, buf, sizeof buf, &len) != 0 || len != 33 ||
        (buf[0] != 0x02 && buf[0] != 0x03))
        return NULL;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, buf, len);
    params[2] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
        pkey = NULL;
    /* Make sure the point really lies on the curve before trusting it. */
    if (pkey != NULL) {
        check = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (check == NULL || EVP_PKEY_public_check(check) != 1) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    }
    EVP_PKEY_CTX_free(check);
    EVP_PKEY_CTX_free(ctx);
    ERR_clear_error();
    return pkey;
}

Status crypto_save_public_key(const char *path, EVP_PKEY *key)
{
    Status st = LT_OK;
    FILE *fp = create_exclusive(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, &st);

    if (fp == NULL)
        return st;
    if (PEM_write_PUBKEY(fp, key) != 1) {
        report_openssl_errors("write public key");
        st = LT_ERR_CRYPTO;
    }
    if (fclose(fp) != 0 && st == LT_OK)
        st = LT_ERR_IO;
    if (st != LT_OK)
        unlink(path);
    return st;
}

/** DER-encodes a private key into a newly allocated buffer (OPENSSL_free). */
Status crypto_private_key_der(EVP_PKEY *key, unsigned char **der, size_t *len)
{
    unsigned char *buf = NULL;
    int n = i2d_PrivateKey(key, &buf);

    if (n <= 0) {
        report_openssl_errors("encode private key");
        return LT_ERR_CRYPTO;
    }
    *der = buf;
    *len = (size_t)n;
    return LT_OK;
}

EVP_PKEY *crypto_private_key_from_der(const unsigned char *der, size_t len)
{
    const unsigned char *p = der;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)len);

    ERR_clear_error();
    return pkey;
}

/* ------------------------------------------------------------------------ */
/* AES-256-GCM (authenticated encryption)                                    */
/* ------------------------------------------------------------------------ */

/*
 * Used for the member key vault: each member's private key is encrypted with
 * a random 256-bit vault key. GCM provides confidentiality and an integrity
 * tag, so a modified key file is detected instead of silently decrypted.
 */
Status crypto_aes_gcm_encrypt(const unsigned char key[AES_KEY_LEN],
                              const unsigned char *plain, size_t len,
                              unsigned char iv[GCM_IV_LEN], unsigned char *cipher,
                              unsigned char tag[GCM_TAG_LEN])
{
    EVP_CIPHER_CTX *ctx;
    int n = 0, total = 0;
    Status st = LT_ERR_CRYPTO;

    if (len > 0x7FFFFFFF || crypto_random_bytes(iv, GCM_IV_LEN) != LT_OK)
        return LT_ERR_CRYPTO;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return LT_ERR_MEMORY;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1 &&
        EVP_EncryptUpdate(ctx, cipher, &n, plain, (int)len) == 1) {
        total = n;
        if (EVP_EncryptFinal_ex(ctx, cipher + total, &n) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) == 1)
            st = LT_OK;
    }
    if (st != LT_OK)
        report_openssl_errors("AES-256-GCM encrypt");
    EVP_CIPHER_CTX_free(ctx);
    return st;
}

Status crypto_aes_gcm_decrypt(const unsigned char key[AES_KEY_LEN],
                              const unsigned char *cipher, size_t len,
                              const unsigned char iv[GCM_IV_LEN],
                              const unsigned char tag[GCM_TAG_LEN], unsigned char *plain)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char tag_copy[GCM_TAG_LEN];
    int n = 0;
    Status st = LT_ERR_CRYPTO;

    if (len > 0x7FFFFFFF)
        return LT_ERR_INPUT;
    memcpy(tag_copy, tag, GCM_TAG_LEN);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return LT_ERR_MEMORY;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, plain, &n, cipher, (int)len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag_copy) == 1 &&
        EVP_DecryptFinal_ex(ctx, plain + n, &n) == 1)  /* fails if the tag is wrong */
        st = LT_OK;
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
    return st;
}
