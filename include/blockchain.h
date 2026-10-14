/**
 * @file blockchain.h
 * @brief Blocks of lending records, proof-of-work and chain validation.
 *
 * A block holds up to block_capacity records (fixed-size batches chosen by
 * the miner from the top of the prioritised pending pool) and a header:
 *
 *   index | timestamp | record_count | previous_hash | merkle_root |
 *   sealed_by | token_reward | transaction_id | difficulty | nonce -> hash
 *
 * hash = SHA-256 of the header fields followed by the nonce. Proof-of-work
 * requires the hash to start with `difficulty` hexadecimal zeros. Because
 * the header contains the Merkle root of the records and the previous
 * block's hash, changing any record or any earlier block changes this hash.
 *
 * transaction_id is the SHA-256 of the block's REWARD transaction, which is
 * derived from the block's RETURNED records (10 coins on time, 5 late);
 * token_reward is the total of those rewards (0 if the block has none).
 */
#ifndef LT_BLOCKCHAIN_H
#define LT_BLOCKCHAIN_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include "common.h"
#include "keystore.h"
#include "record.h"
#include "transaction.h"

typedef struct {
    int                index;
    time_t             timestamp;
    size_t             record_count;
    char               previous_hash[HASH_HEX_LEN];
    char               merkle_root[HASH_HEX_LEN];
    char               sealed_by[MINER_ID_LEN];
    long               token_reward;
    char               transaction_id[HASH_HEX_LEN];
    Transaction        reward;          /* REWARD tx, or TX_NONE */
    int                difficulty;
    unsigned long long nonce;
    char               hash[HASH_HEX_LEN];
    Record            *records;         /* record_count entries, heap */
} Block;

typedef struct {
    Block *blocks;
    size_t length;
    size_t capacity;
} Blockchain;

/** Result of validating one block. */
typedef struct {
    int    structure_ok, time_ok, merkle_ok, reward_ok, hash_ok, pow_ok, link_ok;
    size_t bad_signatures, bad_records;
    char   detail[256];               /* first problem found, "" if none */
    char   computed_hash[HASH_HEX_LEN];
    char   computed_merkle[HASH_HEX_LEN];
} BlockCheck;

/** Summary of validating the whole chain. */
typedef struct {
    size_t blocks_checked, records_checked;
    size_t structure_errors, time_errors, merkle_errors, reward_errors;
    size_t hash_errors, pow_errors, link_errors, signature_errors, record_errors;
    long   first_bad_index;           /* -1 if the chain is valid */
} ChainReport;

/* ---- Memory ------------------------------------------------------------- */
void   block_init(Block *block);
void   block_free(Block *block);
Status block_copy(Block *dst, const Block *src);
Status block_add_record(Block *block, const Record *rec);
void   block_remove_record(Block *block, size_t index);

void   chain_init(Blockchain *chain);
void   chain_free(Blockchain *chain);
Status chain_push(Blockchain *chain, Block *block);   /* takes ownership */
void   chain_pop(Blockchain *chain);
const Block *chain_tip(const Blockchain *chain);
Status chain_copy(Blockchain *dst, const Blockchain *src);

/* ---- Hashing and proof-of-work -------------------------------------------- */
Status block_compute_merkle(const Block *block, char out[HASH_HEX_LEN]);
Status block_build_reward(const Block *block, Transaction *reward, long *total);
Status block_finalise_body(Block *block);   /* sets merkle root, reward, tx id */
Status block_compute_hash(const Block *block, char out[HASH_HEX_LEN]);
int    pow_hash_meets(const char *hash, int difficulty);

/**
 * Tries nonces start .. start+count-1. @return 1 when a valid nonce was
 * found (block->nonce and block->hash set), 0 if none, -1 on error.
 * *attempts receives the number of hashes computed.
 */
int pow_scan(Block *block, unsigned long long start, unsigned long long count,
             unsigned long long *attempts, unsigned long long *found_offset);

/** Mines until the hash meets the difficulty. @return attempts (0 = error). */
unsigned long long pow_mine(Block *block);

/** Prepares an empty block header on top of the chain tip. */
void block_prepare(Block *block, const Blockchain *chain, int difficulty,
                   const char *sealed_by, time_t now);

/** Creates and mines block 0 (previous_hash = 64 zeros, no records). */
Status chain_create_genesis(Blockchain *chain, int difficulty, time_t now);

/* ---- Validation ----------------------------------------------------------- */

/** Field-level consistency of one record (rules that need no chain state). */
int record_fields_valid(const Record *rec, const char **why);

/** Validates block i of the chain (cryptography and structure). */
void chain_check_block(const Blockchain *chain, size_t i, KeyDirectory *keys, BlockCheck *out);

/**
 * Validates every block: structure, timestamps, Merkle root, reward
 * transaction, header hash, proof-of-work, previous-hash links and the
 * ECDSA signature of every record. Writes one line per block to log.
 * @return 1 if every check passed.
 */
int chain_validate(const Blockchain *chain, KeyDirectory *keys, FILE *log, ChainReport *report);

/** Finds a record anywhere on the chain. */
const Record *chain_find_record(const Blockchain *chain, const char *record_id,
                                size_t *block_index, size_t *record_index);

void zero_hash(char out[HASH_HEX_LEN]);

#endif /* LT_BLOCKCHAIN_H */
