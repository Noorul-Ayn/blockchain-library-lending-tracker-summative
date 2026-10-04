/**
 * @file blockchain.h
 * @brief Blocks, the pending pool, proof-of-work and chain validation.
 *
 * Life of a block (Formative 2)
 * -----------------------------
 *  1. A lending action (borrow / return / overdue) or a token transfer is
 *     recorded as a block in the PENDING POOL. The librarian signs the
 *     record (ECDSA P-256) at this point; a return also carries a reward
 *     transaction whose SHA-256 hash is stored in tx_id.
 *  2. A miner takes the pending blocks in order, links each one to the
 *     chain tip (index, previous_hash) and searches for a nonce such that
 *        hash = SHA-256(header | nonce)
 *     starts with `difficulty` zero hex characters (proof-of-work).
 *  3. Only then is the block appended to the confirmed chain and its
 *     transaction applied to the members' balances.
 *
 *  record payload (signed) : timestamp|book_id|book_title|member_id|
 *                            member_name|action|token_reward|tx_id|signed_by
 *  header (hashed)         : index|<record payload>|signature|previous_hash|
 *                            difficulty|mined_by|mined_at|nonce
 */
#ifndef LT_BLOCKCHAIN_H
#define LT_BLOCKCHAIN_H

#include <stdio.h>
#include <time.h>

#include "auth.h"
#include "common.h"
#include "keyring.h"
#include "transaction.h"

#define ACTION_GENESIS  "GENESIS"
#define ACTION_BORROWED "BORROWED"
#define ACTION_RETURNED "RETURNED"
#define ACTION_OVERDUE  "OVERDUE"
#define ACTION_TRANSFER "TRANSFER"

/**
 * One block = one lending event or token transfer.
 * Fields marked F1 are unchanged from Formative 1; F2 fields are new.
 */
typedef struct {
    int           index;                         /* F1: position, 0 = genesis    */
    time_t        timestamp;                     /* F1: when the action happened */
    char          book_id[BOOK_ID_LEN];          /* F1 */
    char          book_title[BOOK_TITLE_LEN];    /* F1 */
    char          member_id[MEMBER_ID_LEN];      /* F1 */
    char          member_name[MEMBER_NAME_LEN];  /* F1 */
    char          action[ACTION_LEN];            /* F1 (+ TRANSFER in F2)        */
    int           token_reward;                  /* F2: 10 on time, 5 late, 0    */
    char          tx_id[HASH_HEX_LEN];           /* F2: SHA-256 of the tx (or 0s)*/
    Transaction   tx;                            /* F2: the transaction itself   */
    char          previous_hash[HASH_HEX_LEN];   /* F1 */
    unsigned char signature[SIGNATURE_MAX_LEN];  /* F1: ECDSA over the record    */
    size_t        signature_len;                 /* F1 */
    char          signed_by[USERNAME_LEN];       /* F1 */
    int           difficulty;                    /* F2: leading zeros required   */
    unsigned long long nonce;                    /* F2: proof-of-work nonce      */
    char          mined_by[MINER_ID_LEN];        /* F2: miner that confirmed it  */
    time_t        mined_at;                      /* F2: confirmation time        */
    char          hash[HASH_HEX_LEN];            /* F1: SHA-256 of the header    */
} Block;

/** A growable array of blocks: used for the chain and for the pending pool. */
typedef struct {
    Block *blocks;
    size_t length;
    size_t capacity;
} Blockchain;

typedef enum {
    SIG_NO_KEY  = -1,
    SIG_INVALID =  0,
    SIG_VALID   =  1
} SigCheck;

typedef struct {
    size_t blocks_checked;
    size_t structure_errors;
    size_t hash_errors;
    size_t pow_errors;
    size_t link_errors;
    size_t tx_errors;
    size_t signature_errors;
    long   first_bad_index;
} ValidationReport;

/* ---- Array management -------------------------------------------------- */
void         chain_init(Blockchain *chain);
void         chain_free(Blockchain *chain);
Status       chain_push(Blockchain *chain, const Block *block);
void         chain_pop(Blockchain *chain, size_t count);
void         chain_remove_at(Blockchain *chain, size_t index);
const Block *chain_last(const Blockchain *chain);

/* ---- Creating records -------------------------------------------------- */
/**
 * Builds and signs a new (unmined) record for the pending pool.
 * tx may be NULL for actions without a transaction (borrow, overdue).
 */
Status block_create_record(Block *block, const Session *session,
                           const char *book_id, const char *book_title,
                           const char *member_id, const char *member_name,
                           const char *action, int token_reward,
                           const Transaction *tx);

/** Links a pending record to the chain tip, ready for proof-of-work. */
void block_prepare_for_mining(Block *block, const Blockchain *chain,
                              int difficulty, const char *miner_id);

/* ---- Proof-of-work ----------------------------------------------------- */
/**
 * Tries nonces start, start+1, ... start+count-1. On success stores the
 * nonce and hash in the block, sets *found_offset and returns 1.
 * *attempts receives the number of hashes computed.
 */
int pow_scan(Block *block, unsigned long long start, unsigned long long count,
             unsigned long long *attempts, unsigned long long *found_offset);

/** Mines until a valid nonce is found. @return number of attempts. */
unsigned long long pow_mine(Block *block);

/** True if the hex hash starts with `difficulty` '0' characters. */
int pow_hash_meets(const char *hash, int difficulty);

/* ---- Hashing, signatures, validation ----------------------------------- */
Status   block_compute_hash(const Block *block, char out[HASH_HEX_LEN]);
SigCheck block_verify_signature(const Block *block, KeyRing *keys);

/** Checks tx_id, token_reward and the transaction against the action. */
int block_tx_consistent(const Block *block, const char **why);

/** Creates, mines and appends block 0 (previous_hash = 64 zeros). */
Status chain_create_genesis(Blockchain *chain, const Session *session, int difficulty);

/**
 * Validates every block: structure, transaction integrity, SHA-256 hash,
 * proof-of-work, previous_hash link and ECDSA signature.
 * @return 1 if valid. A per-block report is written to log if non-NULL.
 */
int chain_validate(const Blockchain *chain, KeyRing *keys, FILE *log,
                   ValidationReport *report);

/* ---- Queries ----------------------------------------------------------- */
const Block *chain_find_latest_event(const Blockchain *chain, const char *book_id);
const Block *chain_find_latest_borrow(const Blockchain *chain, const char *book_id);
long         chain_count_outgoing(const Blockchain *chain, const char *member_id);
long         chain_count_rewards(const Blockchain *chain);
int          action_is_lending(const char *action);
int          action_is_valid(const char *action);

#endif /* LT_BLOCKCHAIN_H */
