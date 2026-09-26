/**
 * @file auth.h
 * @brief User accounts, login and role-based access control.
 *
 * Every staff user (librarian or administrator) has:
 *   - a salted PBKDF2-HMAC-SHA256 password hash in data/users.db
 *   - a personal ECDSA P-256 key pair in data/keys/, the private half of
 *     which is encrypted with the user's password.
 *
 * Logging in verifies the password AND unlocks the private key. Only a
 * logged-in session holds a signing key, so only authenticated users can
 * produce valid signatures on lending records.
 */
#ifndef LT_AUTH_H
#define LT_AUTH_H

#include <openssl/evp.h>

#include "common.h"

typedef enum {
    ROLE_NONE      = 0,
    ROLE_LIBRARIAN = 1,
    ROLE_ADMIN     = 2
} Role;

/** Actions that are subject to access control. */
typedef enum {
    PERM_VIEW_RECORDS,
    PERM_RECORD_LENDING,
    PERM_VALIDATE_CHAIN,
    PERM_TAMPER_DEMO,
    PERM_MANAGE_USERS
} Permission;

/** An authenticated session. signing_key is owned by the session. */
typedef struct {
    char      username[USERNAME_LEN];
    Role      role;
    EVP_PKEY *signing_key;
} Session;

/** 3-19 characters: letters, digits and underscore. */
int auth_valid_username(const char *username);

/** Password policy: 8-128 chars with at least one letter and one digit. */
int auth_password_acceptable(const char *password, const char **reason);

/** @return 1 if at least one valid account exists in users.db. */
int auth_has_users(const char *data_dir);

/** Creates an account: password hash + encrypted signing key pair. */
Status auth_create_user(const char *data_dir, const char *username,
                        const char *password, Role role);

/**
 * Verifies the credentials and unlocks the user's signing key.
 * @return LT_OK, LT_ERR_AUTH (bad credentials) or LT_ERR_CRYPTO (key problem).
 */
Status auth_login(const char *data_dir, const char *username,
                  const char *password, Session *session);

/** Frees the signing key and clears the session. */
void auth_logout(Session *session);

int         auth_is_logged_in(const Session *session);
int         auth_has_permission(const Session *session, Permission perm);
const char *auth_role_name(Role role);

/** Builds data/keys/<username>.key and .pub paths (rejects unsafe names). */
Status auth_key_paths(const char *data_dir, const char *username,
                      char *private_path, char *public_path, size_t cap);

#endif /* LT_AUTH_H */
