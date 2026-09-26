/**
 * @file common.h
 * @brief Shared constants, field sizes and status codes used by every module.
 *
 * Field sizes follow the assignment specification exactly (Book, Member and
 * Block structures). Every public function in the project reports failures
 * through the Status enum below so that errors are handled consistently.
 */
#ifndef LT_COMMON_H
#define LT_COMMON_H

#include <stddef.h>

/* ---- Field sizes (from the assignment specification) ------------------- */
#define BOOK_ID_LEN        20
#define BOOK_TITLE_LEN     80
#define BOOK_AUTHOR_LEN    50
#define MEMBER_ID_LEN      20
#define MEMBER_NAME_LEN    50
#define COURSE_CODE_LEN    10
#define ACTION_LEN         10
#define HASH_HEX_LEN       65   /* 64 hex characters + NUL terminator        */
#define SIGNATURE_MAX_LEN  72   /* largest DER-encoded ECDSA P-256 signature */
#define USERNAME_LEN       20

/* ---- Files kept inside the data directory ------------------------------ */
#define DEFAULT_DATA_DIR   "data"
#define BOOKS_FILE         "books.txt"
#define MEMBERS_FILE       "members.txt"
#define CHAIN_FILE         "chain.dat"
#define USERS_FILE         "users.db"
#define KEYS_DIR           "keys"

#define LT_PATH_MAX        512
#define LT_LINE_MAX        1024

/* ---- Lending rules ----------------------------------------------------- */
#define DEFAULT_LOAN_PERIOD_SECONDS (14L * 24L * 60L * 60L) /* 14 days */
#define LOAN_PERIOD_ENV    "LIBRARY_LOAN_PERIOD"            /* override, in seconds */

/** Result codes returned by all fallible functions. */
typedef enum {
    LT_OK = 0,
    LT_ERR_IO,            /* file could not be read or written            */
    LT_ERR_MEMORY,        /* allocation failed                            */
    LT_ERR_FORMAT,        /* malformed file contents                      */
    LT_ERR_EMPTY,         /* file exists but holds no usable records      */
    LT_ERR_NOT_FOUND,     /* requested item / file does not exist         */
    LT_ERR_EXISTS,        /* item already exists                          */
    LT_ERR_INPUT,         /* invalid argument or user input               */
    LT_ERR_CRYPTO,        /* OpenSSL operation failed                     */
    LT_ERR_AUTH,          /* wrong username or password                   */
    LT_ERR_DENIED,        /* authenticated but not authorised             */
    LT_ERR_CHAIN_INVALID, /* blockchain failed validation                 */
    LT_ERR_ON_LOAN,       /* book is already borrowed                     */
    LT_ERR_NOT_ON_LOAN,   /* book has no outstanding BORROWED record      */
    LT_ERR_WRONG_MEMBER   /* book is on loan to somebody else             */
} Status;

/** Returns a short human-readable description of a status code. */
const char *status_str(Status status);

#endif /* LT_COMMON_H */
