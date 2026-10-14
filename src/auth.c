/**
 * @file auth.c
 * @brief Account storage, password verification and access control.
 *
 * users.db format (one account per line, file mode 0600):
 *     username:ROLE:pbkdf2_iterations:salt_hex:hash_hex
 * Plain-text passwords are never stored or written anywhere.
 */
#include "auth.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "keystore.h"
#include "util.h"

#define USER_FIELD_COUNT  5
#define MIN_USERNAME_LEN  3
#define MIN_PASSWORD_LEN  8
#define MAX_PASSWORD_LEN  128
#define MIN_ITERATIONS    10000L
#define MAX_ITERATIONS    10000000L
#define USERS_FILE_HEADER "# username:role:pbkdf2_iterations:salt_hex:pbkdf2_sha256_hex\n"

/** One parsed line of users.db. */
typedef struct {
    char          username[USERNAME_LEN];
    Role          role;
    int           iterations;
    unsigned char salt[SALT_LEN];
    unsigned char hash[PASSWORD_HASH_LEN];
} UserRecord;

/* ------------------------------------------------------------------------ */
/* Validation helpers                                                       */
/* ------------------------------------------------------------------------ */

const char *auth_role_name(Role role)
{
    switch (role) {
    case ROLE_ADMIN:     return "ADMIN";
    case ROLE_LIBRARIAN: return "LIBRARIAN";
    case ROLE_NONE:      break;
    }
    return "NONE";
}

static int role_from_name(const char *name, Role *role)
{
    if (strcmp(name, "ADMIN") == 0) {
        *role = ROLE_ADMIN;
        return 0;
    }
    if (strcmp(name, "LIBRARIAN") == 0) {
        *role = ROLE_LIBRARIAN;
        return 0;
    }
    return -1;
}

int auth_valid_username(const char *username)
{
    size_t len = strlen(username);
    size_t i;

    if (len < MIN_USERNAME_LEN || len >= USERNAME_LEN)
        return 0;
    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char)username[i]) && username[i] != '_')
            return 0;
    }
    return 1;
}

int auth_password_acceptable(const char *password, const char **reason)
{
    size_t len = strlen(password);
    int has_letter = 0, has_digit = 0, has_control = 0;
    const char *why = NULL;
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (isalpha(c)) has_letter = 1;
        if (isdigit(c)) has_digit = 1;
        if (c < 0x20 || c == 0x7F) has_control = 1;
    }
    if (len < MIN_PASSWORD_LEN)
        why = "password must be at least 8 characters long";
    else if (len > MAX_PASSWORD_LEN)
        why = "password must be at most 128 characters long";
    else if (!has_letter || !has_digit)
        why = "password must contain at least one letter and one digit";
    else if (has_control)
        why = "password contains control characters";

    if (reason != NULL)
        *reason = why;
    return why == NULL;
}

Status auth_key_paths(const char *data_dir, const char *username,
                      char *private_path, char *public_path, size_t cap)
{
    char keys_dir[LT_PATH_MAX];
    char file_name[USERNAME_LEN + 8];

    /* Usernames are restricted to [A-Za-z0-9_], which also rules out path
     * traversal through a forged "signed_by" field in the chain file. */
    if (!auth_valid_username(username))
        return LT_ERR_INPUT;
    if (path_join(keys_dir, sizeof keys_dir, data_dir, KEYS_DIR) != 0)
        return LT_ERR_INPUT;

    snprintf(file_name, sizeof file_name, "%s.key", username);
    if (path_join(private_path, cap, keys_dir, file_name) != 0)
        return LT_ERR_INPUT;
    snprintf(file_name, sizeof file_name, "%s.pub", username);
    if (path_join(public_path, cap, keys_dir, file_name) != 0)
        return LT_ERR_INPUT;
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* users.db access                                                          */
/* ------------------------------------------------------------------------ */

static int parse_user_line(char *line, UserRecord *user)
{
    char *field[USER_FIELD_COUNT];
    size_t salt_len = 0, hash_len = 0;
    long iterations;
    char *end;

    memset(user, 0, sizeof *user);
    if (str_split(line, ':', field, USER_FIELD_COUNT) != USER_FIELD_COUNT)
        return -1;
    if (!auth_valid_username(field[0]) ||
        str_copy(user->username, sizeof user->username, field[0]) != 0)
        return -1;
    if (role_from_name(field[1], &user->role) != 0)
        return -1;

    errno = 0;
    iterations = strtol(field[2], &end, 10);
    if (errno != 0 || end == field[2] || *end != '\0' ||
        iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)
        return -1;
    user->iterations = (int)iterations;

    if (hex_decode(field[3], user->salt, sizeof user->salt, &salt_len) != 0 ||
        salt_len != SALT_LEN)
        return -1;
    if (hex_decode(field[4], user->hash, sizeof user->hash, &hash_len) != 0 ||
        hash_len != PASSWORD_HASH_LEN)
        return -1;
    return 0;
}

/**
 * Scans users.db. If username is non-NULL and found, copies the record into
 * *found and returns LT_OK; otherwise returns LT_ERR_NOT_FOUND.
 * *valid_records (optional) receives the number of well-formed accounts.
 */
static Status scan_users(const char *data_dir, const char *username,
                         UserRecord *found, size_t *valid_records)
{
    char path[LT_PATH_MAX], line[LT_LINE_MAX];
    size_t count = 0, line_no = 0;
    Status st = LT_ERR_NOT_FOUND;
    FILE *fp;

    if (valid_records != NULL)
        *valid_records = 0;
    if (path_join(path, sizeof path, data_dir, USERS_FILE) != 0)
        return LT_ERR_INPUT;
    fp = fopen(path, "r");
    if (fp == NULL)
        return (errno == ENOENT) ? LT_ERR_NOT_FOUND : LT_ERR_IO;

    while (fgets(line, sizeof line, fp) != NULL) {
        UserRecord user;
        char *p = str_trim(line);

        line_no++;
        if (*p == '\0' || *p == '#')
            continue;
        if (parse_user_line(p, &user) != 0) {
            fprintf(stderr, "WARNING: %s line %zu is malformed and was ignored.\n",
                    USERS_FILE, line_no);
            continue;
        }
        count++;
        if (username != NULL && strcmp(user.username, username) == 0) {
            if (found != NULL)
                *found = user;
            crypto_wipe(&user, sizeof user);
            st = LT_OK;
            break;
        }
        crypto_wipe(&user, sizeof user);
    }
    fclose(fp);
    crypto_wipe(line, sizeof line);
    if (valid_records != NULL)
        *valid_records = count;
    return st;
}

int auth_has_users(const char *data_dir)
{
    size_t count = 0;
    (void)scan_users(data_dir, NULL, NULL, &count);
    return count > 0;
}

/** Appends one account line to users.db (created with mode 0600). */
static Status append_user_line(const char *data_dir, const UserRecord *user)
{
    char path[LT_PATH_MAX];
    char salt_hex[SALT_LEN * 2 + 1], hash_hex[PASSWORD_HASH_LEN * 2 + 1];
    struct stat info;
    Status st = LT_OK;
    FILE *fp;
    int fd;

    if (path_join(path, sizeof path, data_dir, USERS_FILE) != 0)
        return LT_ERR_INPUT;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return LT_ERR_IO;
    fp = fdopen(fd, "a");
    if (fp == NULL) {
        close(fd);
        return LT_ERR_IO;
    }

    hex_encode(user->salt, SALT_LEN, salt_hex);
    hex_encode(user->hash, PASSWORD_HASH_LEN, hash_hex);
    if (fstat(fd, &info) == 0 && info.st_size == 0 && fputs(USERS_FILE_HEADER, fp) < 0)
        st = LT_ERR_IO;
    if (st == LT_OK &&
        (fprintf(fp, "%s:%s:%d:%s:%s\n", user->username, auth_role_name(user->role),
                 user->iterations, salt_hex, hash_hex) < 0 ||
         fflush(fp) != 0 || fsync(fd) != 0))
        st = LT_ERR_IO;
    if (fclose(fp) != 0)
        st = LT_ERR_IO;
    crypto_wipe(hash_hex, sizeof hash_hex);
    return st;
}

Status auth_create_user(const char *data_dir, const char *username,
                        const char *password, Role role,
                        const unsigned char vault_key[32])
{
    char keys_dir[LT_PATH_MAX], private_path[LT_PATH_MAX], public_path[LT_PATH_MAX];
    UserRecord user;
    Status st;

    if (!auth_valid_username(username) || !auth_password_acceptable(password, NULL) ||
        (role != ROLE_ADMIN && role != ROLE_LIBRARIAN))
        return LT_ERR_INPUT;

    st = scan_users(data_dir, username, NULL, NULL);
    if (st == LT_OK)
        return LT_ERR_EXISTS;
    if (st != LT_ERR_NOT_FOUND)
        return st;

    if (path_join(keys_dir, sizeof keys_dir, data_dir, KEYS_DIR) != 0 ||
        auth_key_paths(data_dir, username, private_path, public_path,
                       sizeof private_path) != LT_OK)
        return LT_ERR_INPUT;

    memset(&user, 0, sizeof user);
    (void)str_copy(user.username, sizeof user.username, username);
    user.role = role;
    user.iterations = PBKDF2_ITERATIONS;

    st = crypto_random_bytes(user.salt, SALT_LEN);
    if (st == LT_OK)
        st = crypto_pbkdf2(password, user.salt, SALT_LEN, user.iterations,
                           user.hash, PASSWORD_HASH_LEN);
    if (st == LT_OK && ensure_dir(keys_dir, S_IRWXU) != 0) {
        fprintf(stderr, "ERROR: cannot create key directory '%s'.\n", keys_dir);
        st = LT_ERR_IO;
    }
    if (st == LT_OK)
        st = crypto_generate_keypair(private_path, public_path, password);
    if (st == LT_OK) {
        st = vault_wrap_for_user(data_dir, username, password, vault_key);
        if (st == LT_OK)
            st = append_user_line(data_dir, &user);
        if (st != LT_OK) { /* roll back so no orphaned keys remain */
            char vault_file[LT_PATH_MAX];
            unlink(private_path);
            unlink(public_path);
            if (path_join(vault_file, sizeof vault_file, keys_dir, username) == 0 &&
                strlen(vault_file) + 7 < sizeof vault_file) {
                strcat(vault_file, ".vault");
                unlink(vault_file);
            }
        }
    }
    crypto_wipe(&user, sizeof user);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Login / logout                                                           */
/* ------------------------------------------------------------------------ */

Status auth_login(const char *data_dir, const char *username,
                  const char *password, Session *session)
{
    char private_path[LT_PATH_MAX], public_path[LT_PATH_MAX];
    unsigned char computed[PASSWORD_HASH_LEN];
    EVP_PKEY *private_key = NULL, *public_key = NULL;
    UserRecord user;
    Status st;

    memset(session, 0, sizeof *session);
    memset(&user, 0, sizeof user);

    st = auth_valid_username(username) ? scan_users(data_dir, username, &user, NULL)
                                       : LT_ERR_NOT_FOUND;
    if (st != LT_OK) {
        /* Spend the same effort as a real check so that response time does
         * not reveal whether a username exists. */
        static const unsigned char dummy_salt[SALT_LEN] = {0};
        (void)crypto_pbkdf2(password, dummy_salt, SALT_LEN, PBKDF2_ITERATIONS,
                            computed, sizeof computed);
        crypto_wipe(computed, sizeof computed);
        return (st == LT_ERR_NOT_FOUND) ? LT_ERR_AUTH : st;
    }

    st = crypto_pbkdf2(password, user.salt, SALT_LEN, user.iterations,
                       computed, sizeof computed);
    if (st == LT_OK && !crypto_equal(computed, user.hash, sizeof computed))
        st = LT_ERR_AUTH;
    crypto_wipe(computed, sizeof computed);
    if (st != LT_OK)
        goto done;

    /* Password is correct: unlock the signing key and prove it matches the
     * published public key before trusting it. */
    if (auth_key_paths(data_dir, user.username, private_path, public_path,
                       sizeof private_path) != LT_OK) {
        st = LT_ERR_INPUT;
        goto done;
    }
    private_key = crypto_load_private_key(private_path, password);
    public_key = crypto_load_public_key(public_path);
    if (private_key == NULL || public_key == NULL ||
        !crypto_keys_match(private_key, public_key)) {
        st = LT_ERR_CRYPTO;
        goto done;
    }

    /* The same password also unwraps the member key vault. */
    if (vault_unwrap(data_dir, user.username, password, session->vault_key) != LT_OK) {
        crypto_wipe(session->vault_key, sizeof session->vault_key);
        st = LT_ERR_CRYPTO;
        goto done;
    }
    session->vault_unlocked = 1;
    (void)str_copy(session->username, sizeof session->username, user.username);
    session->role = user.role;
    session->signing_key = private_key;
    private_key = NULL; /* ownership moved to the session */

done:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    crypto_wipe(&user, sizeof user);
    return st;
}

void auth_logout(Session *session)
{
    EVP_PKEY_free(session->signing_key);
    crypto_wipe(session, sizeof *session);
}

int auth_is_logged_in(const Session *session)
{
    return session != NULL && session->signing_key != NULL && session->role != ROLE_NONE;
}

/* ------------------------------------------------------------------------ */
/* Access control                                                           */
/* ------------------------------------------------------------------------ */

/**
 * Role/permission matrix:
 *
 *   permission                          LIBRARIAN  ADMIN
 *   view registries, chain, pool           yes      yes
 *   lending, registration, mining          yes      yes
 *   validate / save / load chain           yes      yes
 *   approve / reject suspicious requests    no      yes
 *   clock, tamper demo, replay simulation   no      yes
 *   manage staff accounts                   no      yes
 */
int auth_has_permission(const Session *session, Permission perm)
{
    if (!auth_is_logged_in(session))
        return 0;
    switch (perm) {
    case PERM_VIEW:
    case PERM_LENDING:
    case PERM_VALIDATE:
        return session->role == ROLE_LIBRARIAN || session->role == ROLE_ADMIN;
    case PERM_REVIEW_FRAUD:
    case PERM_ADMIN_TOOLS:
    case PERM_MANAGE_USERS:
        return session->role == ROLE_ADMIN;
    }
    return 0;
}
