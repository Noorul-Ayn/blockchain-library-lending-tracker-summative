/**
 * @file storage.h
 * @brief File-based persistence of the blockchain (data/chain.dat).
 *
 * The chain is stored as a human-readable text file, one block per line:
 *   index|timestamp|book_id|book_title|member_id|member_name|action|
 *   signed_by|previous_hash|signature_hex|hash
 *
 * Saving is atomic: the chain is written to chain.dat.tmp, flushed to disk
 * with fsync() and then renamed over chain.dat, so a crash mid-write can
 * never leave a half-written chain behind.
 */
#ifndef LT_STORAGE_H
#define LT_STORAGE_H

#include <stddef.h>

#include "blockchain.h"
#include "common.h"

/** Atomically writes the whole chain to path. */
Status storage_save_chain(const char *path, const Blockchain *chain);

/**
 * Loads the chain from path into *chain (replacing its contents).
 * @return LT_OK; LT_ERR_NOT_FOUND if the file does not exist yet;
 *         LT_ERR_FORMAT / LT_ERR_EMPTY / LT_ERR_IO with a reason in err.
 */
Status storage_load_chain(const char *path, Blockchain *chain, char *err, size_t err_cap);

#endif /* LT_STORAGE_H */
