/**
 * @file merkle.h
 * @brief Merkle tree over the SHA-256 hashes of a block's records.
 *
 * Built from scratch (no external Merkle library):
 *   - the leaves are the SHA-256 hashes of the records, in block order;
 *   - each parent is SHA-256(0x01 || left || right) over the raw 32-byte
 *     digests; the 0x01 prefix separates internal nodes from leaves;
 *   - an odd node at the end of a level is promoted unchanged to the next
 *     level (it is not duplicated, which avoids the well-known ambiguity
 *     where [a, b, c] and [a, b, c, c] share a root);
 *   - a block with no records has a root of 64 zeros.
 *
 * Changing any record changes its leaf, every node above it and the root,
 * so comparing a recomputed root with the stored merkle_root detects edits.
 * An inclusion proof lists the sibling hashes from a leaf up to the root.
 */
#ifndef LT_MERKLE_H
#define LT_MERKLE_H

#include <stddef.h>

#include "common.h"

#define MERKLE_MAX_DEPTH 32

typedef struct {
    char hash[HASH_HEX_LEN];
    int  sibling_is_left;    /* 1: parent = H(sibling || current) */
} MerkleStep;

/** Called once per node by merkle_walk: level 0 = leaves. */
typedef void (*MerkleVisit)(size_t level, size_t index, const char *hash, void *ctx);

Status merkle_root(const char (*leaves)[HASH_HEX_LEN], size_t count, char root[HASH_HEX_LEN]);

/** Visits every node of the tree, level by level (for display). */
Status merkle_walk(const char (*leaves)[HASH_HEX_LEN], size_t count, MerkleVisit visit,
                   void *ctx, size_t *levels);

/** Builds the inclusion proof for leaf `index`. */
Status merkle_proof(const char (*leaves)[HASH_HEX_LEN], size_t count, size_t index,
                    MerkleStep steps[MERKLE_MAX_DEPTH], size_t *step_count);

/** @return 1 if hashing leaf with the proof steps yields root. */
int merkle_verify_proof(const char leaf[HASH_HEX_LEN], const MerkleStep *steps,
                        size_t step_count, const char root[HASH_HEX_LEN]);

#endif /* LT_MERKLE_H */
