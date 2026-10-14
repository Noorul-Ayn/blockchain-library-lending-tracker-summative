/**
 * @file keystore.c
 * @brief Member key vault, member key pairs and the public-key directory.
 */
#include "keystore.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "auth.h"
#include "util.h"

#define VAULT_MAGIC  "LIBVAULT1"
#define KEY_MAGIC    "LIBKEY1"
#define MAX_DER_LEN  512

/* ------------------------------------------------------------------------ */
/* Small file helpers                                                       */
/* ------------------------------------------------------------------------ */

/** Writes one line to a brand-new file with mode 0600 (never overwrites). */
static Status write_secret_file(const char *path, const char *line)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    size_t len = strlen(line);
    Status st = LT_OK;

    if (fd < 0)
        return (errno == EEXIST) ? LT_ERR_EXISTS : LT_ERR_IO;
    if (write(fd, line, len) != (ssize_t)len || fsync(fd) != 0)
        st = LT_ERR_IO;
    if (close(fd) != 0)
        st = LT_ERR_IO;
    if (st != LT_OK)
        unlink(path);
    return st;
}

static Status read_line_file(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");

    if (fp == NULL)
        return (errno == ENOENT) ? LT_ERR_NOT_FOUND : LT_ERR_IO;
    if (fgets(buf, (int)cap, fp) == NULL) {
        fclose(fp);
        return LT_ERR_FORMAT;
    }
    fclose(fp);
    (void)str_trim(buf);
    return LT_OK;
}

static Status member_key_paths(const char *data_dir, const char *member_id,
                               char *priv, char *pub, size_t cap)
{
    char keys[LT_PATH_MAX], dir[LT_PATH_MAX], name[MEMBER_ID_LEN + 8];

    /* Member IDs only contain [A-Za-z0-9_-], so they are safe file names. */
    if (!str_is_identifier(member_id) || strlen(member_id) >= MEMBER_ID_LEN)
        return LT_ERR_INPUT;
    if (path_join(keys, sizeof keys, data_dir, KEYS_DIR) != 0 ||
        path_join(dir, sizeof dir, keys, MEMBER_KEYS_DIR) != 0)
        return LT_ERR_INPUT;
    snprintf(name, sizeof name, "%s.key", member_id);
    if (priv != NULL && path_join(priv, cap, dir, name) != 0)
        return LT_ERR_INPUT;
    snprintf(name, sizeof name, "%s.pub", member_id);
    if (pub != NULL && path_join(pub, cap, dir, name) != 0)
        return LT_ERR_INPUT;
    return LT_OK;
}

static Status vault_path(const char *data_dir, const char *username, char *out, size_t cap)
{
    char keys[LT_PATH_MAX], name[USERNAME_LEN + 8];

    if (!auth_valid_username(username) ||
        path_join(keys, sizeof keys, data_dir, KEYS_DIR) != 0)
        return LT_ERR_INPUT;
    snprintf(name, sizeof name, "%s.vault", username);
    return path_join(out, cap, keys, name) == 0 ? LT_OK : LT_ERR_INPUT;
}

/* ------------------------------------------------------------------------ */
/* Vault key                                                                */
/* ------------------------------------------------------------------------ */

Status vault_generate(unsigned char key[VAULT_KEY_LEN])
{
    return crypto_random_bytes(key, VAULT_KEY_LEN);
}

/*
 * keys/<user>.vault holds one line:
 *     LIBVAULT1 <iterations> <salt_hex> <iv_hex> <tag_hex> <wrapped_key_hex>
 * The wrapping key is PBKDF2-HMAC-SHA256(password, salt, iterations).
 */
Status vault_wrap_for_user(const char *data_dir, const char *username, const char *password,
                           const unsigned char key[VAULT_KEY_LEN])
{
    unsigned char salt[SALT_LEN], wrap_key[AES_KEY_LEN], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    unsigned char wrapped[VAULT_KEY_LEN];
    char salt_hex[SALT_LEN * 2 + 1], iv_hex[GCM_IV_LEN * 2 + 1], tag_hex[GCM_TAG_LEN * 2 + 1];
    char wrapped_hex[VAULT_KEY_LEN * 2 + 1], path[LT_PATH_MAX], line[512];
    Status st = vault_path(data_dir, username, path, sizeof path);

    if (st == LT_OK)
        st = crypto_random_bytes(salt, sizeof salt);
    if (st == LT_OK)
        st = crypto_pbkdf2(password, salt, sizeof salt, PBKDF2_ITERATIONS, wrap_key,
                           sizeof wrap_key);
    if (st == LT_OK)
        st = crypto_aes_gcm_encrypt(wrap_key, key, VAULT_KEY_LEN, iv, wrapped, tag);
    if (st == LT_OK) {
        hex_encode(salt, sizeof salt, salt_hex);
        hex_encode(iv, sizeof iv, iv_hex);
        hex_encode(tag, sizeof tag, tag_hex);
        hex_encode(wrapped, sizeof wrapped, wrapped_hex);
        snprintf(line, sizeof line, "%s %d %s %s %s %s\n", VAULT_MAGIC, PBKDF2_ITERATIONS,
                 salt_hex, iv_hex, tag_hex, wrapped_hex);
        st = write_secret_file(path, line);
    }
    crypto_wipe(wrap_key, sizeof wrap_key);
    crypto_wipe(line, sizeof line);
    return st;
}

Status vault_unwrap(const char *data_dir, const char *username, const char *password,
                    unsigned char key[VAULT_KEY_LEN])
{
    char path[LT_PATH_MAX], line[512], *f[6];
    unsigned char salt[SALT_LEN], wrap_key[AES_KEY_LEN], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    unsigned char wrapped[VAULT_KEY_LEN];
    size_t n1 = 0, n2 = 0, n3 = 0, n4 = 0;
    long iterations;
    Status st = vault_path(data_dir, username, path, sizeof path);

    if (st == LT_OK)
        st = read_line_file(path, line, sizeof line);
    if (st != LT_OK)
        return st;
    if (str_split(line, ' ', f, 6) != 6 || strcmp(f[0], VAULT_MAGIC) != 0 ||
        parse_long(f[1], 10000, 10000000, &iterations) != 0 ||
        hex_decode(f[2], salt, sizeof salt, &n1) != 0 || n1 != SALT_LEN ||
        hex_decode(f[3], iv, sizeof iv, &n2) != 0 || n2 != GCM_IV_LEN ||
        hex_decode(f[4], tag, sizeof tag, &n3) != 0 || n3 != GCM_TAG_LEN ||
        hex_decode(f[5], wrapped, sizeof wrapped, &n4) != 0 || n4 != VAULT_KEY_LEN)
        return LT_ERR_FORMAT;

    st = crypto_pbkdf2(password, salt, sizeof salt, (int)iterations, wrap_key, sizeof wrap_key);
    if (st == LT_OK)
        st = crypto_aes_gcm_decrypt(wrap_key, wrapped, sizeof wrapped, iv, tag, key);
    crypto_wipe(wrap_key, sizeof wrap_key);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Member key pairs                                                         */
/* ------------------------------------------------------------------------ */

int member_key_exists(const char *data_dir, const char *member_id)
{
    char priv[LT_PATH_MAX], pub[LT_PATH_MAX];

    return member_key_paths(data_dir, member_id, priv, pub, sizeof priv) == LT_OK &&
           file_exists(priv) && file_exists(pub);
}

/*
 * keys/members/<id>.key holds one line:
 *     LIBKEY1 <iv_hex> <tag_hex> <ciphertext_hex>
 * where ciphertext = AES-256-GCM(vault key, DER private key). The vault key
 * is random (256 bits), so no password-stretching is needed here.
 */
Status member_key_create(const char *data_dir, const unsigned char vault[VAULT_KEY_LEN],
                         const char *member_id)
{
    char priv[LT_PATH_MAX], pub[LT_PATH_MAX], keys[LT_PATH_MAX], dir[LT_PATH_MAX];
    char *line = NULL, iv_hex[GCM_IV_LEN * 2 + 1], tag_hex[GCM_TAG_LEN * 2 + 1];
    unsigned char *der = NULL, cipher[MAX_DER_LEN], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    size_t der_len = 0, line_cap = MAX_DER_LEN * 2 + 128;
    EVP_PKEY *key = NULL;
    Status st = member_key_paths(data_dir, member_id, priv, pub, sizeof priv);

    if (st != LT_OK)
        return st;
    if (path_join(keys, sizeof keys, data_dir, KEYS_DIR) != 0 ||
        path_join(dir, sizeof dir, keys, MEMBER_KEYS_DIR) != 0 ||
        ensure_dir(keys, S_IRWXU) != 0 || ensure_dir(dir, S_IRWXU) != 0)
        return LT_ERR_IO;

    key = crypto_generate_key();
    if (key == NULL)
        return LT_ERR_CRYPTO;
    st = crypto_private_key_der(key, &der, &der_len);
    if (st == LT_OK && der_len > MAX_DER_LEN)
        st = LT_ERR_CRYPTO;
    if (st == LT_OK)
        st = crypto_aes_gcm_encrypt(vault, der, der_len, iv, cipher, tag);
    if (st == LT_OK) {
        line = malloc(line_cap);
        st = line == NULL ? LT_ERR_MEMORY : LT_OK;
    }
    if (st == LT_OK) {
        char *hex;
        hex_encode(iv, sizeof iv, iv_hex);
        hex_encode(tag, sizeof tag, tag_hex);
        snprintf(line, line_cap, "%s %s %s ", KEY_MAGIC, iv_hex, tag_hex);
        hex = line + strlen(line);
        hex_encode(cipher, der_len, hex);   /* 2*der_len + NUL fits in line_cap */
        strcat(hex, "\n");
        st = write_secret_file(priv, line);
    }
    if (st == LT_OK) {
        st = crypto_save_public_key(pub, key);
        if (st != LT_OK)
            unlink(priv);
    }
    if (der != NULL) {
        OPENSSL_cleanse(der, der_len);
        OPENSSL_free(der);
    }
    if (line != NULL) {
        crypto_wipe(line, line_cap);
        free(line);
    }
    EVP_PKEY_free(key);
    return st;
}

EVP_PKEY *member_key_load_private(const char *data_dir, const unsigned char vault[VAULT_KEY_LEN],
                                  const char *member_id)
{
    char priv[LT_PATH_MAX], *line, *f[4];
    unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN], cipher[MAX_DER_LEN], plain[MAX_DER_LEN];
    size_t n1 = 0, n2 = 0, n3 = 0, cap = MAX_DER_LEN * 2 + 128;
    EVP_PKEY *key = NULL;

    if (member_key_paths(data_dir, member_id, priv, NULL, sizeof priv) != LT_OK)
        return NULL;
    line = malloc(cap);
    if (line == NULL)
        return NULL;
    if (read_line_file(priv, line, cap) == LT_OK &&
        str_split(line, ' ', f, 4) == 4 && strcmp(f[0], KEY_MAGIC) == 0 &&
        hex_decode(f[1], iv, sizeof iv, &n1) == 0 && n1 == GCM_IV_LEN &&
        hex_decode(f[2], tag, sizeof tag, &n2) == 0 && n2 == GCM_TAG_LEN &&
        hex_decode(f[3], cipher, sizeof cipher, &n3) == 0 && n3 > 0 &&
        crypto_aes_gcm_decrypt(vault, cipher, n3, iv, tag, plain) == LT_OK)
        key = crypto_private_key_from_der(plain, n3);
    crypto_wipe(plain, sizeof plain);
    crypto_wipe(line, cap);
    free(line);
    return key;
}

/* ------------------------------------------------------------------------ */
/* Public-key directory                                                     */
/* ------------------------------------------------------------------------ */

void signer_id_for_staff(const char *username, char out[SIGNER_ID_LEN])
{
    snprintf(out, SIGNER_ID_LEN, "%s%s", STAFF_PREFIX, username);
}

int signer_is_staff(const char *signer_id)
{
    return strncmp(signer_id, STAFF_PREFIX, strlen(STAFF_PREFIX)) == 0;
}

void keydir_init(KeyDirectory *dir, const char *data_dir)
{
    memset(dir, 0, sizeof *dir);
    (void)str_copy(dir->data_dir, sizeof dir->data_dir, data_dir);
}

/** Resolves a signer ID to its public key file. */
static EVP_PKEY *load_signer_key(const char *data_dir, const char *signer_id)
{
    char priv[LT_PATH_MAX], pub[LT_PATH_MAX];

    if (signer_is_staff(signer_id)) {
        const char *user = signer_id + strlen(STAFF_PREFIX);
        if (auth_key_paths(data_dir, user, priv, pub, sizeof priv) != LT_OK)
            return NULL;   /* rejects forged names such as "staff:../../x" */
    } else if (member_key_paths(data_dir, signer_id, NULL, pub, sizeof pub) != LT_OK) {
        return NULL;
    }
    return crypto_load_public_key(pub);
}

const PublicKeyEntry *keydir_get(KeyDirectory *dir, const char *signer_id)
{
    PublicKeyEntry *e;
    size_t i;

    for (i = 0; i < dir->count; i++) {
        if (strcmp(dir->entries[i].signer_id, signer_id) == 0)
            return dir->entries[i].key != NULL ? &dir->entries[i] : NULL;
    }
    if (dir->count == dir->capacity) {
        size_t cap = dir->capacity ? dir->capacity * 2 : 16;
        PublicKeyEntry *grown = realloc(dir->entries, cap * sizeof *grown);
        if (grown == NULL)
            return NULL;
        dir->entries = grown;
        dir->capacity = cap;
    }
    e = &dir->entries[dir->count];
    memset(e, 0, sizeof *e);
    if (str_copy(e->signer_id, sizeof e->signer_id, signer_id) != 0)
        return NULL;
    e->key = load_signer_key(dir->data_dir, signer_id);
    if (e->key != NULL && crypto_public_key_hex(e->key, e->hex) != LT_OK) {
        EVP_PKEY_free(e->key);
        e->key = NULL;
    }
    dir->count++;   /* misses are cached too, so lookups stay fast */
    return e->key != NULL ? e : NULL;
}

void keydir_forget(KeyDirectory *dir, const char *signer_id)
{
    size_t i;

    for (i = 0; i < dir->count; i++) {
        if (strcmp(dir->entries[i].signer_id, signer_id) == 0) {
            EVP_PKEY_free(dir->entries[i].key);
            dir->entries[i] = dir->entries[--dir->count];
            return;
        }
    }
}

void keydir_free(KeyDirectory *dir)
{
    size_t i;

    for (i = 0; i < dir->count; i++)
        EVP_PKEY_free(dir->entries[i].key);
    free(dir->entries);
    dir->entries = NULL;
    dir->count = dir->capacity = 0;
}
