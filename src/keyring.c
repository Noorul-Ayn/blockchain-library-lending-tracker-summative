/**
 * @file keyring.c
 * @brief Lazy-loading cache of public verification keys.
 */
#include "keyring.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "crypto.h"
#include "util.h"

#define KEYRING_INITIAL_CAPACITY 4

void keyring_init(KeyRing *ring, const char *data_dir)
{
    memset(ring, 0, sizeof *ring);
    (void)str_copy(ring->data_dir, sizeof ring->data_dir, data_dir);
}

EVP_PKEY *keyring_get(KeyRing *ring, const char *username)
{
    char private_path[LT_PATH_MAX], public_path[LT_PATH_MAX];
    EVP_PKEY *key = NULL;
    size_t i;

    for (i = 0; i < ring->count; i++) {
        if (strcmp(ring->entries[i].username, username) == 0)
            return ring->entries[i].key;
    }

    /* auth_key_paths() rejects unsafe usernames, so no path traversal. */
    if (auth_key_paths(ring->data_dir, username, private_path, public_path,
                       sizeof public_path) == LT_OK)
        key = crypto_load_public_key(public_path);

    if (ring->count == ring->capacity) {
        size_t new_cap = ring->capacity ? ring->capacity * 2 : KEYRING_INITIAL_CAPACITY;
        KeyEntry *grown = NULL;

        if (new_cap <= SIZE_MAX / sizeof *grown)
            grown = realloc(ring->entries, new_cap * sizeof *grown);
        if (grown == NULL) {
            EVP_PKEY_free(key);
            return NULL;
        }
        ring->entries = grown;
        ring->capacity = new_cap;
    }

    /* Cache the result, including "not found", to avoid repeated disk reads. */
    memset(&ring->entries[ring->count], 0, sizeof ring->entries[ring->count]);
    (void)str_copy(ring->entries[ring->count].username, USERNAME_LEN, username);
    ring->entries[ring->count].key = key;
    ring->count++;
    return key;
}

void keyring_clear(KeyRing *ring)
{
    size_t i;

    for (i = 0; i < ring->count; i++)
        EVP_PKEY_free(ring->entries[i].key);
    ring->count = 0;
}

void keyring_free(KeyRing *ring)
{
    keyring_clear(ring);
    free(ring->entries);
    ring->entries = NULL;
    ring->capacity = 0;
}
