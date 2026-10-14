/**
 * @file record.h
 * @brief Lending records: the signed entries that blocks are made of.
 *
 * Every action - borrow, return, reserve, renew, overdue flag, lost copy,
 * token transfer or fine settlement - is a Record. A record is signed by
 * the member it concerns (borrow, return, reserve, renew, transfer, token
 * fine) or by the librarian (overdue flags, lost copies, cash fines) and
 * carries the signer's public key, which is the signer's identity on-chain.
 *
 * Signed payload (one line, fields separated by '|'):
 *   LR3|record_id|timestamp|action|book_id|copy_id|book_title|member_id|
 *   member_name|due_date|fine_amount|token_reward|condition|reason|tx|
 *   nonce|signer_id|signer_pubkey
 *
 * signature = ECDSA-P256(SHA-256(payload)), DER encoded.
 * Merkle leaf = SHA-256(payload | signature_hex | review), so a fraud-review
 * note added after signing is still protected by the block's Merkle root.
 */
#ifndef LT_RECORD_H
#define LT_RECORD_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include <openssl/evp.h>

#include "common.h"
#include "keystore.h"
#include "registry.h"
#include "transaction.h"

typedef enum {
    ACT_NONE = 0,
    ACT_BORROW,      /* BORROWED   */
    ACT_RETURN,      /* RETURNED   */
    ACT_RESERVE,     /* RESERVED   */
    ACT_RENEW,       /* RENEWED    */
    ACT_OVERDUE,     /* OVERDUE    */
    ACT_LOST,        /* LOST       */
    ACT_TRANSFER,    /* TRANSFER   - token transfer between members      */
    ACT_FINE         /* FINE_PAID  - fine settlement (tokens or cash)    */
} Action;

typedef enum {
    SIG_VALID = 0,
    SIG_INVALID,       /* signature does not match the record        */
    SIG_MISSING,       /* no signature / no public key in the record */
    SIG_KEY_MISMATCH   /* embedded key is not the signer's registered key */
} SigCheck;

typedef struct {
    char          record_id[REQUEST_ID_LEN];
    time_t        timestamp;                  /* when the request was made   */
    Action        action;
    char          book_id[BOOK_ID_LEN];       /* "-" for token records       */
    char          copy_id[COPY_ID_LEN];       /* "-" for reservations/tokens */
    char          book_title[BOOK_TITLE_LEN]; /* copied from the registry    */
    char          member_id[MEMBER_ID_LEN];
    char          member_name[MEMBER_NAME_LEN];
    time_t        due_date;                   /* 0 when not applicable       */
    long          fine_amount;                /* late RETURNED / OVERDUE     */
    int           token_reward;               /* RETURNED: 10 or 5           */
    Condition     condition;                  /* copy condition after action */
    char          reason[REASON_LEN];         /* librarian reason code, "-"  */
    Transaction   tx;                         /* TRANSFER / FINE only        */
    long          nonce;                      /* signer's request nonce      */
    char          signer_id[SIGNER_ID_LEN];
    char          signer_pubkey[PUBKEY_HEX_LEN];
    unsigned char signature[SIGNATURE_MAX_LEN];
    size_t        signature_len;
    char          review[NOTE_LEN];           /* fraud-review note, "-"      */
} Record;

#define RECORD_TEXT_MAX (LT_LINE_MAX + TX_TEXT_MAX)

void        record_clear(Record *rec);
const char *action_record_name(Action a);    /* BORROWED, RETURNED, ...       */
const char *action_request_name(Action a);   /* BORROW, RETURN, ...           */
int         action_parse(const char *name, Action *out);
int         action_is_lending(Action a);     /* BORROW .. LOST                */

/** Creates a fresh, random 12-hex-character request ID. */
Status record_new_id(Record *rec);

/** The canonical payload that is signed. @return length or -1. */
int record_payload(const Record *rec, char *buf, size_t cap);

/** Signs the record with key; also writes the key's public half into it. */
Status record_sign(Record *rec, EVP_PKEY *key);

/**
 * Verifies the signature with the public key embedded in the record and,
 * if dir is not NULL, checks that this key is the signer's registered key.
 */
SigCheck    record_verify(const Record *rec, KeyDirectory *dir);
const char *sig_check_name(SigCheck s);

/** Merkle leaf: SHA-256(payload | signature_hex | review). */
Status record_hash(const Record *rec, char out[HASH_HEX_LEN]);

/** tx_id of the record's token transaction ("-" if none). */
Status record_tx_id(const Record *rec, char out[HASH_HEX_LEN]);

/**
 * File form used in chain.dat and pending.dat: the payload fields (without
 * "LR3") followed by signature_hex and review - 19 "|"-separated fields.
 */
int    record_serialize(const Record *rec, char *buf, size_t cap);
Status record_parse(char **fields, size_t count, Record *rec);
#define RECORD_FIELD_COUNT 19

/** Short human description, e.g. "ALU001 -> ALU002, 3 coins + 1 fee". */
void record_describe(const Record *rec, char *buf, size_t cap);

#endif /* LT_RECORD_H */
