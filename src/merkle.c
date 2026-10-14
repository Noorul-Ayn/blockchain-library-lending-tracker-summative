/**
 * @file merkle.c
 * @brief Merkle root, tree walk and inclusion proofs (built from scratch).
 */
#include "merkle.h"

#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

#define DIGEST_LEN 32

/** parent = SHA-256(0x01 || left || right), all over raw 32-byte digests. */
static Status hash_pair(const char left[HASH_HEX_LEN], const char right[HASH_HEX_LEN],
                        char out[HASH_HEX_LEN])
{
    unsigned char buf[1 + 2 * DIGEST_LEN];
    size_t n1 = 0, n2 = 0;

    buf[0] = 0x01;
    if (hex_decode(left, buf + 1, DIGEST_LEN, &n1) != 0 || n1 != DIGEST_LEN ||
        hex_decode(right, buf + 1 + DIGEST_LEN, DIGEST_LEN, &n2) != 0 || n2 != DIGEST_LEN)
        return LT_ERR_INPUT;
    return crypto_sha256_hex(buf, sizeof buf, out);
}

/**
 * Computes every level of the tree. levels[0] = the leaves. The caller frees
 * each level and the array. Returns the number of levels in *depth.
 */
static Status build_levels(const char (*leaves)[HASH_HEX_LEN], size_t count,
                           char (**levels)[HASH_HEX_LEN], size_t *sizes, size_t *depth)
{
    size_t d = 0, n = count, i;
    Status st = LT_OK;

    levels[0] = malloc((count ? count : 1) * sizeof *levels[0]);
    if (levels[0] == NULL)
        return LT_ERR_MEMORY;
    memcpy(levels[0], leaves, count * sizeof *levels[0]);
    sizes[0] = count;

    while (n > 1 && st == LT_OK) {
        size_t parents = (n + 1) / 2;

        if (d + 1 >= MERKLE_MAX_DEPTH) {
            st = LT_ERR_INPUT;
            break;
        }
        levels[d + 1] = malloc(parents * sizeof *levels[d + 1]);
        if (levels[d + 1] == NULL) {
            st = LT_ERR_MEMORY;
            break;
        }
        for (i = 0; i < parents && st == LT_OK; i++) {
            if (2 * i + 1 < n)
                st = hash_pair(levels[d][2 * i], levels[d][2 * i + 1], levels[d + 1][i]);
            else   /* odd node: promoted unchanged */
                memcpy(levels[d + 1][i], levels[d][2 * i], HASH_HEX_LEN);
        }
        d++;
        sizes[d] = parents;
        n = parents;
    }
    *depth = d + 1;
    if (st != LT_OK) {
        for (i = 0; i <= d; i++)
            free(levels[i]);
    }
    return st;
}

static void free_levels(char (**levels)[HASH_HEX_LEN], size_t depth)
{
    size_t i;

    for (i = 0; i < depth; i++)
        free(levels[i]);
}

Status merkle_root(const char (*leaves)[HASH_HEX_LEN], size_t count, char root[HASH_HEX_LEN])
{
    char (*levels[MERKLE_MAX_DEPTH])[HASH_HEX_LEN];
    size_t sizes[MERKLE_MAX_DEPTH], depth = 0;
    Status st;

    if (count == 0) {
        memset(root, '0', HASH_HEX_LEN - 1);
        root[HASH_HEX_LEN - 1] = '\0';
        return LT_OK;
    }
    st = build_levels(leaves, count, levels, sizes, &depth);
    if (st != LT_OK)
        return st;
    memcpy(root, levels[depth - 1][0], HASH_HEX_LEN);
    free_levels(levels, depth);
    return LT_OK;
}

Status merkle_walk(const char (*leaves)[HASH_HEX_LEN], size_t count, MerkleVisit visit,
                   void *ctx, size_t *levels_out)
{
    char (*levels[MERKLE_MAX_DEPTH])[HASH_HEX_LEN];
    size_t sizes[MERKLE_MAX_DEPTH], depth = 0, d, i;
    Status st;

    if (count == 0)
        return LT_ERR_INPUT;
    st = build_levels(leaves, count, levels, sizes, &depth);
    if (st != LT_OK)
        return st;
    for (d = 0; d < depth; d++) {
        for (i = 0; i < sizes[d]; i++)
            visit(d, i, levels[d][i], ctx);
    }
    if (levels_out != NULL)
        *levels_out = depth;
    free_levels(levels, depth);
    return LT_OK;
}

Status merkle_proof(const char (*leaves)[HASH_HEX_LEN], size_t count, size_t index,
                    MerkleStep steps[MERKLE_MAX_DEPTH], size_t *step_count)
{
    char (*levels[MERKLE_MAX_DEPTH])[HASH_HEX_LEN];
    size_t sizes[MERKLE_MAX_DEPTH], depth = 0, d, pos = index, n = 0;
    Status st;

    *step_count = 0;
    if (index >= count)
        return LT_ERR_INPUT;
    st = build_levels(leaves, count, levels, sizes, &depth);
    if (st != LT_OK)
        return st;
    for (d = 0; d + 1 < depth; d++) {
        size_t sibling = pos ^ 1u;

        if (sibling < sizes[d]) {          /* a promoted odd node has no sibling */
            memcpy(steps[n].hash, levels[d][sibling], HASH_HEX_LEN);
            steps[n].sibling_is_left = (sibling < pos);
            n++;
        }
        pos /= 2;
    }
    *step_count = n;
    free_levels(levels, depth);
    return LT_OK;
}

int merkle_verify_proof(const char leaf[HASH_HEX_LEN], const MerkleStep *steps,
                        size_t step_count, const char root[HASH_HEX_LEN])
{
    char current[HASH_HEX_LEN], next[HASH_HEX_LEN];
    size_t i;

    memcpy(current, leaf, HASH_HEX_LEN);
    for (i = 0; i < step_count; i++) {
        Status st = steps[i].sibling_is_left ? hash_pair(steps[i].hash, current, next)
                                             : hash_pair(current, steps[i].hash, next);
        if (st != LT_OK)
            return 0;
        memcpy(current, next, HASH_HEX_LEN);
    }
    return strcmp(current, root) == 0;
}
