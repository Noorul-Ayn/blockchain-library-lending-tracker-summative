/**
 * @file keyring.h
 * @brief Cache of staff public keys used to verify block signatures.
 *
 * Each block records who signed it ("signed_by"). The keyring loads that
 * user's public key from data/keys/<username>.pub on first use and keeps it
 * in memory for later verifications.
 */
#ifndef LT_KEYRING_H
#define LT_KEYRING_H

#include <stddef.h>

#include <openssl/evp.h>

#include "common.h"

typedef struct {
    char      username[USERNAME_LEN];
    EVP_PKEY *key;             /* NULL if the public key could not be loaded */
} KeyEntry;

typedef struct {
    char      data_dir[LT_PATH_MAX];
    KeyEntry *entries;
    size_t    count;
    size_t    capacity;
} KeyRing;

void keyring_init(KeyRing *ring, const char *data_dir);

/** @return the public key of username, or NULL if unavailable. Not owned. */
EVP_PKEY *keyring_get(KeyRing *ring, const char *username);

/** Forgets every cached key (e.g. after a new account is created). */
void keyring_clear(KeyRing *ring);

void keyring_free(KeyRing *ring);

#endif /* LT_KEYRING_H */
