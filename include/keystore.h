/**
 * @file keystore.h
 * @brief Member key pairs, the member key vault and the public-key directory.
 *
 * Every member has their own ECDSA P-256 key pair. Lending requests are
 * signed with the member's private key, and every record on the chain
 * carries the signer's public key, which acts as the member's on-chain
 * identity.
 *
 * Members do not log in to the library terminal, so their private keys are
 * held in a key vault (custodial wallet):
 *
 *   keys/members/<member_id>.pub   public key, PEM, mode 0644
 *   keys/members/<member_id>.key   private key encrypted with AES-256-GCM
 *                                  under the 256-bit vault key, mode 0600
 *   keys/<username>.vault          the vault key, encrypted for one staff
 *                                  user with a key derived from that user's
 *                                  password (PBKDF2-HMAC-SHA256, 600,000
 *                                  iterations) and AES-256-GCM, mode 0600
 *
 * The vault therefore opens only when a staff member logs in with the
 * correct password, and the vault key is never written to disk unencrypted.
 */
#ifndef LT_KEYSTORE_H
#define LT_KEYSTORE_H

#include <stddef.h>

#include <openssl/evp.h>

#include "common.h"
#include "crypto.h"

#define VAULT_KEY_LEN AES_KEY_LEN

/* ---- Vault key (wrapped once per staff user) ------------------------------ */
Status vault_generate(unsigned char key[VAULT_KEY_LEN]);
Status vault_wrap_for_user(const char *data_dir, const char *username, const char *password,
                           const unsigned char key[VAULT_KEY_LEN]);
Status vault_unwrap(const char *data_dir, const char *username, const char *password,
                    unsigned char key[VAULT_KEY_LEN]);

/* ---- Member key pairs ----------------------------------------------------- */
int       member_key_exists(const char *data_dir, const char *member_id);
Status    member_key_create(const char *data_dir, const unsigned char vault[VAULT_KEY_LEN],
                            const char *member_id);
EVP_PKEY *member_key_load_private(const char *data_dir, const unsigned char vault[VAULT_KEY_LEN],
                                  const char *member_id);

/* ---- Public-key directory (members and staff) ------------------------------ */

/** Builds the signer ID used on the chain for a staff user: "staff:<name>". */
void signer_id_for_staff(const char *username, char out[SIGNER_ID_LEN]);
int  signer_is_staff(const char *signer_id);

typedef struct {
    char      signer_id[SIGNER_ID_LEN];
    EVP_PKEY *key;                    /* NULL if no key file exists */
    char      hex[PUBKEY_HEX_LEN];    /* compressed public key       */
} PublicKeyEntry;

typedef struct {
    char            data_dir[LT_PATH_MAX];
    PublicKeyEntry *entries;
    size_t          count;
    size_t          capacity;
} KeyDirectory;

void keydir_init(KeyDirectory *dir, const char *data_dir);

/** Looks up (and caches) a signer's registered public key; NULL if unknown. */
const PublicKeyEntry *keydir_get(KeyDirectory *dir, const char *signer_id);

void keydir_forget(KeyDirectory *dir, const char *signer_id);
void keydir_free(KeyDirectory *dir);

#endif /* LT_KEYSTORE_H */
