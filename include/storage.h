/**
 * @file storage.h
 * @brief Disk persistence: chain.dat, pending.dat and state.dat.
 *
 * All three files are plain-text, line-based and '|'-separated, so they can
 * be inspected with any editor; integrity comes from hashes and signatures,
 * not from hiding the data. Every save is atomic: the file is written to
 * "<name>.tmp", flushed with fsync() and renamed over the old file.
 *
 * chain.dat (format v3) - one B line per block, then its reward transaction
 * (X line) and its records (R lines):
 *   B|index|timestamp|record_count|previous_hash|merkle_root|sealed_by|
 *     token_reward|transaction_id|difficulty|nonce|hash
 *   X|reward transaction (or -)
 *   R|record fields (see record.h)
 *
 * pending.dat - one Q line per pending request:
 *   Q|status|flags|priority|sort_time|seq|record fields
 *
 * state.dat - chain metadata and settings (META lines) plus a snapshot of
 * the copy inventory, reservation queues, nonces, fines and token ledger.
 * On start-up the snapshot is compared with the state rebuilt from the
 * chain; any difference is reported and the chain wins.
 */
#ifndef LT_STORAGE_H
#define LT_STORAGE_H

#include <stddef.h>

#include "blockchain.h"
#include "common.h"
#include "ledger.h"
#include "pool.h"
#include "state.h"

/** Settings and chain metadata stored in state.dat. */
typedef struct {
    int         difficulty;
    long        block_reward;
    int         block_capacity;
    long        clock_offset;
    LendingRules rules;
    size_t      chain_length;
    char        tip_hash[HASH_HEX_LEN];
    LedgerModel model;
    int         present;            /* 1 if state.dat existed and parsed */
} StateMeta;

/** Loads chain.dat. A missing file gives an empty chain and LT_OK. */
Status storage_load_chain(const char *path, Blockchain *chain, char *err, size_t err_cap);
Status storage_save_chain(const char *path, const Blockchain *chain);

/** Loads pending.dat. A missing file gives an empty pool and LT_OK. */
Status storage_load_pool(const char *path, PendingPool *pool, char *err, size_t err_cap);
Status storage_save_pool(const char *path, const PendingPool *pool);

/** Writes META lines followed by the state snapshot. */
Status storage_save_state(const char *path, const StateMeta *meta, const LibraryState *state);

/**
 * Reads state.dat: META values into *meta. If rebuilt is not NULL the
 * snapshot is compared with it; *differences receives the number of lines
 * that do not match and first_diff the first one.
 */
Status storage_load_state(const char *path, StateMeta *meta, const LibraryState *rebuilt,
                          size_t *differences, char *first_diff, size_t diff_cap);

#endif /* LT_STORAGE_H */
