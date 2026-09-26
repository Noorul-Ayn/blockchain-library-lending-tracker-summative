/**
 * @file blockchain.h
 * @brief The lending blockchain: block layout, construction and validation.
 *
 * Integrity model
 * ---------------
 *  signature = ECDSA-P256( SHA-256( payload ) )  signed with the librarian's key
 *  hash      = SHA-256( payload | hex(signature) )
 *  payload   = index|timestamp|book_id|book_title|member_id|member_name|
 *              action|previous_hash|signed_by
 *
 * Each block stores the hash of the block before it (previous_hash), so
 * changing any past block breaks every link after it. Signatures make it
 * impossible to rewrite a block and simply recompute the hashes, because
 * the attacker does not hold the librarian's private key.
 */
#ifndef LT_BLOCKCHAIN_H
#define LT_BLOCKCHAIN_H

#include <stdio.h>
#include <time.h>

#include "auth.h"
#include "common.h"
#include "keyring.h"

#define ACTION_GENESIS  "GENESIS"
#define ACTION_BORROWED "BORROWED"
#define ACTION_RETURNED "RETURNED"
#define ACTION_OVERDUE  "OVERDUE"

/**
 * One block = one lending event. The first ten fields are exactly the ones
 * required by the specification; signature_len and signed_by are needed to
 * verify a variable-length DER signature against the right public key.
 */
typedef struct {
    int           index;                         /* position; 0 = genesis        */
    time_t        timestamp;                     /* Unix time of creation         */
    char          book_id[BOOK_ID_LEN];          /* validated against registry    */
    char          book_title[BOOK_TITLE_LEN];    /* copied from registry          */
    char          member_id[MEMBER_ID_LEN];      /* validated against registry    */
    char          member_name[MEMBER_NAME_LEN];  /* copied from registry          */
    char          action[ACTION_LEN];            /* BORROWED / RETURNED / OVERDUE */
    char          previous_hash[HASH_HEX_LEN];   /* hash of the previous block    */
    unsigned char signature[SIGNATURE_MAX_LEN];  /* ECDSA signature (DER)         */
    size_t        signature_len;                 /* bytes used in signature[]     */
    char          signed_by[USERNAME_LEN];       /* staff user who signed         */
    char          hash[HASH_HEX_LEN];            /* SHA-256 of all fields above   */
} Block;

/** The chain itself: a dynamically grown array of blocks. */
typedef struct {
    Block *blocks;
    size_t length;
    size_t capacity;
} Blockchain;

/** Result of verifying one block signature. */
typedef enum {
    SIG_NO_KEY  = -1,  /* signer's public key is missing: cannot verify */
    SIG_INVALID =  0,
    SIG_VALID   =  1
} SigCheck;

/** Summary produced by chain_validate(). */
typedef struct {
    size_t blocks_checked;
    size_t structure_errors;   /* wrong index / action for the position */
    size_t hash_errors;        /* stored hash != recomputed hash        */
    size_t link_errors;        /* previous_hash != hash of prior block  */
    size_t signature_errors;   /* ECDSA signature does not verify       */
    long   first_bad_index;    /* -1 if every block is valid            */
} ValidationReport;

void         chain_init(Blockchain *chain);
void         chain_free(Blockchain *chain);
Status       chain_push(Blockchain *chain, const Block *block);
void         chain_pop(Blockchain *chain, size_t count);
const Block *chain_last(const Blockchain *chain);

/** Creates, signs and appends block 0 (previous_hash = 64 zeros). */
Status chain_create_genesis(Blockchain *chain, const Session *session);

/**
 * Builds a new lending block on top of the chain, signs it with the
 * session's private key, computes its hash and appends it.
 */
Status chain_append_record(Blockchain *chain, const Session *session,
                           const char *book_id, const char *book_title,
                           const char *member_id, const char *member_name,
                           const char *action);

/** Recomputes SHA-256 over every field of the block (including signature). */
Status block_compute_hash(const Block *block, char out[HASH_HEX_LEN]);

/** Verifies the block's ECDSA signature using the signer's public key. */
SigCheck block_verify_signature(const Block *block, KeyRing *keys);

/**
 * Walks the whole chain and checks, for every block: position/action,
 * (a) the stored hash is correct, (b) previous_hash matches the previous
 * block's hash, and (c) the signature is valid.
 * If log is non-NULL a per-block report is printed to it.
 * @return 1 if the chain is valid, 0 otherwise.
 */
int chain_validate(const Blockchain *chain, KeyRing *keys, FILE *log,
                   ValidationReport *report);

/** Most recent BORROWED/RETURNED/OVERDUE block for a book, or NULL. */
const Block *chain_find_latest_event(const Blockchain *chain, const char *book_id);

/** Most recent BORROWED block for a book, or NULL. */
const Block *chain_find_latest_borrow(const Blockchain *chain, const char *book_id);

/** True for BORROWED, RETURNED and OVERDUE. */
int action_is_lending(const char *action);

#endif /* LT_BLOCKCHAIN_H */
