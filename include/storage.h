/**
 * @file storage.h
 * @brief File-based persistence of the confirmed chain (chain.dat) and the
 *        pending pool (pending.dat).
 *
 * Both files use the same human-readable text format (version 2), one
 * block per line:
 *   index|timestamp|book_id|book_title|member_id|member_name|action|
 *   token_reward|tx_id|tx|signed_by|signature|difficulty|nonce|mined_by|
 *   mined_at|previous_hash|hash
 *
 * Saving is atomic: data is written to <file>.tmp, flushed with fsync()
 * and renamed over the original, so a crash never leaves a half-written
 * file behind.
 */
#ifndef LT_STORAGE_H
#define LT_STORAGE_H

#include <stddef.h>

#include "blockchain.h"
#include "common.h"

/** Atomically writes the confirmed chain. */
Status storage_save_chain(const char *path, const Blockchain *chain);

/**
 * Loads the confirmed chain. @return LT_OK; LT_ERR_NOT_FOUND if the file
 * does not exist yet; LT_ERR_FORMAT / LT_ERR_EMPTY / LT_ERR_IO with err set.
 */
Status storage_load_chain(const char *path, Blockchain *chain, char *err, size_t err_cap);

/** Atomically writes the pending pool (an empty pool is a valid file). */
Status storage_save_pending(const char *path, const Blockchain *pending);

/** Loads the pending pool; a missing file means an empty pool. */
Status storage_load_pending(const char *path, Blockchain *pending, char *err, size_t err_cap);

#endif /* LT_STORAGE_H */
