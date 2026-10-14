/**
 * @file common.h
 * @brief Shared constants, field sizes and status codes used by every module.
 *
 * Field sizes follow the assignment specification (Book, Member, Copy, Block
 * and Lending Record structures). Every fallible function in the project
 * reports failures through the Status enum below, so errors are handled the
 * same way everywhere.
 */
#ifndef LT_COMMON_H
#define LT_COMMON_H

#include <stddef.h>

/* ---- Field sizes ------------------------------------------------------- */
#define BOOK_ID_LEN        20
#define BOOK_TITLE_LEN     80
#define BOOK_AUTHOR_LEN    50
#define MEMBER_ID_LEN      20
#define MEMBER_NAME_LEN    50
#define COURSE_CODE_LEN    10
#define COPY_ID_LEN        24
#define HASH_HEX_LEN       65   /* 64 hex characters + NUL terminator         */
#define SIGNATURE_MAX_LEN  72   /* largest DER-encoded ECDSA P-256 signature  */
#define SIGNATURE_HEX_LEN  (SIGNATURE_MAX_LEN * 2 + 1)
#define PUBKEY_HEX_LEN     67   /* compressed P-256 point: 33 bytes = 66 hex  */
#define USERNAME_LEN       20
#define SIGNER_ID_LEN      32   /* "ALU001" for members, "staff:admin" for staff */
#define REQUEST_ID_LEN     13   /* 12 hex characters + NUL                    */
#define REASON_LEN         24   /* librarian override reason code             */
#define NOTE_LEN           96   /* fraud-review note stored with a record      */
#define ACCOUNT_ID_LEN     20   /* member ID, or "LIBRARY"                     */
#define MINER_ID_LEN       32

/* ---- Files kept inside the data directory ------------------------------ */
#define DEFAULT_DATA_DIR   "data"
#define BOOKS_FILE         "books.txt"
#define COPIES_FILE        "copies.txt"
#define MEMBERS_FILE       "members.txt"
#define CHAIN_FILE         "chain.dat"
#define PENDING_FILE       "pending.dat"
#define STATE_FILE         "state.dat"
#define USERS_FILE         "users.db"
#define KEYS_DIR           "keys"          /* staff keys and key-vault wraps */
#define MEMBER_KEYS_DIR    "members"       /* inside KEYS_DIR                 */

#define LT_PATH_MAX        512
#define LT_LINE_MAX        8192

/* ---- Lending rules (defaults; most can be changed with options) -------- */
#define DAY_SECONDS             86400L
#define DEFAULT_LOAN_DAYS       14   /* due date = borrow time + 14 days        */
#define MAX_LOAN_DAYS           60   /* longest due date a librarian may set    */
#define DEFAULT_RENEWAL_DAYS    7    /* each renewal extends the due date       */
#define DEFAULT_MAX_RENEWALS    2
#define DEFAULT_MAX_LOANS       3    /* copies a member may hold at once        */
#define FINE_PER_DAY            1    /* coins per day (or part of a day) late   */
#define REBORROW_WINDOW_SECONDS (24L * 3600L)
#define LIBRARY_ACCOUNT         "LIBRARY"
#define STAFF_PREFIX            "staff:"

/* ---- Token economy ----------------------------------------------------- */
#define REWARD_ON_TIME     10   /* coins for returning a book on time         */
#define REWARD_LATE         5   /* coins for returning a book late            */
#define TX_FEE              1   /* fixed fee per transaction, paid to miner   */

/* ---- Mining ------------------------------------------------------------ */
#define DEFAULT_DIFFICULTY  2   /* leading zero hex characters in the hash   */
#define MIN_DIFFICULTY      1
#define MAX_DIFFICULTY      4
#define DEFAULT_BLOCK_REWARD 20 /* coins paid to the miner per block          */
#define DEFAULT_BLOCK_CAPACITY 4 /* records per block (fixed-size batches)    */
#define MAX_BLOCK_CAPACITY  16
#define POOL_FEE_PERCENT    2.0
#define POOL_MIN_MINERS     2
#define POOL_MAX_MINERS     8
#define POOL_DEFAULT_MINERS 4
#define POOL_MIN_HASH_RATE  100 /* attempts per round                         */
#define POOL_MAX_HASH_RATE  600
#define CLOUD_HASH_POWER    600 /* rented attempts per round                  */
#define CLOUD_RENTAL_FEE   15.0 /* coins per round                            */
#define CLOUD_MAINTENANCE_PERCENT 10.0
#define CLOUD_MIN_ROUNDS    1
#define CLOUD_MAX_ROUNDS    5
#define SEED_ENV           "LIBRARY_SEED"   /* fixed random seed for tests     */

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
    LT_ERR_STATE,         /* copy is not in a state that allows this      */
    LT_ERR_LIMIT,         /* renewal / loan limit reached                 */
    LT_ERR_INSUFFICIENT,  /* not enough balance / unspent outputs         */
    LT_ERR_DOUBLE_SPEND,  /* output already spent or reserved             */
    LT_ERR_NONCE,         /* wrong or reused nonce                        */
    LT_ERR_SIGNATURE,     /* missing or invalid ECDSA signature           */
    LT_ERR_POOL_EMPTY     /* nothing waiting in the pending pool          */
} Status;

/** Returns a short human-readable description of a status code. */
const char *status_str(Status status);

#endif /* LT_COMMON_H */
