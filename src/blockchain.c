/**
 * @file blockchain.c
 * @brief Block construction, signing, hashing and whole-chain validation.
 */
#include "blockchain.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

#define CHAIN_INITIAL_CAPACITY 16
#define BLOCK_PAYLOAD_MAX      512
#define BLOCK_HASH_INPUT_MAX   (BLOCK_PAYLOAD_MAX + 1 + SIGNATURE_MAX_LEN * 2 + 1)

/** Writes the genesis previous_hash: 64 '0' characters. */
static void zero_hash(char out[HASH_HEX_LEN])
{
    memset(out, '0', HASH_HEX_LEN - 1);
    out[HASH_HEX_LEN - 1] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Dynamic array management                                                 */
/* ------------------------------------------------------------------------ */

void chain_init(Blockchain *chain)
{
    chain->blocks = NULL;
    chain->length = 0;
    chain->capacity = 0;
}

void chain_free(Blockchain *chain)
{
    free(chain->blocks);
    chain_init(chain);
}

Status chain_push(Blockchain *chain, const Block *block)
{
    if (chain->length == chain->capacity) {
        size_t new_cap = chain->capacity ? chain->capacity * 2 : CHAIN_INITIAL_CAPACITY;
        Block *grown;

        if (new_cap > SIZE_MAX / sizeof *grown)
            return LT_ERR_MEMORY;
        grown = realloc(chain->blocks, new_cap * sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        chain->blocks = grown;
        chain->capacity = new_cap;
    }
    chain->blocks[chain->length++] = *block;
    return LT_OK;
}

void chain_pop(Blockchain *chain, size_t count)
{
    chain->length = (count > chain->length) ? 0 : chain->length - count;
}

const Block *chain_last(const Blockchain *chain)
{
    return chain->length ? &chain->blocks[chain->length - 1] : NULL;
}

int action_is_lending(const char *action)
{
    return strcmp(action, ACTION_BORROWED) == 0 ||
           strcmp(action, ACTION_RETURNED) == 0 ||
           strcmp(action, ACTION_OVERDUE) == 0;
}

/* ------------------------------------------------------------------------ */
/* Hashing and signing                                                      */
/* ------------------------------------------------------------------------ */

/**
 * Canonical serialisation of the signed fields. '|' can never appear inside
 * a field (inputs are validated), so the encoding is unambiguous.
 * @return payload length, or -1 if it does not fit.
 */
static int block_payload(const Block *b, char *buf, size_t cap)
{
    int n = snprintf(buf, cap, "%d|%lld|%s|%s|%s|%s|%s|%s|%s",
                     b->index, (long long)b->timestamp, b->book_id, b->book_title,
                     b->member_id, b->member_name, b->action, b->previous_hash,
                     b->signed_by);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

Status block_compute_hash(const Block *block, char out[HASH_HEX_LEN])
{
    char buf[BLOCK_HASH_INPUT_MAX];
    int n;

    if (block->signature_len > SIGNATURE_MAX_LEN)
        return LT_ERR_FORMAT;
    n = block_payload(block, buf, BLOCK_PAYLOAD_MAX);
    if (n < 0)
        return LT_ERR_FORMAT;
    buf[n++] = '|';
    hex_encode(block->signature, block->signature_len, buf + n);
    return crypto_sha256_hex(buf, (size_t)n + block->signature_len * 2, out);
}

SigCheck block_verify_signature(const Block *block, KeyRing *keys)
{
    char payload[BLOCK_PAYLOAD_MAX];
    int n = block_payload(block, payload, sizeof payload);
    EVP_PKEY *key;

    if (n < 0 || block->signature_len == 0 || block->signature_len > SIGNATURE_MAX_LEN)
        return SIG_INVALID;
    key = keyring_get(keys, block->signed_by);
    if (key == NULL)
        return SIG_NO_KEY;
    return crypto_verify(key, payload, (size_t)n, block->signature, block->signature_len)
               ? SIG_VALID : SIG_INVALID;
}

/** Signs the block with the session key, then computes its hash. */
static Status seal_block(Block *block, const Session *session)
{
    char payload[BLOCK_PAYLOAD_MAX];
    int n;
    Status st;

    if (!auth_is_logged_in(session))
        return LT_ERR_DENIED;
    if (str_copy(block->signed_by, sizeof block->signed_by, session->username) != 0)
        return LT_ERR_INPUT;

    n = block_payload(block, payload, sizeof payload);
    if (n < 0)
        return LT_ERR_FORMAT;
    block->signature_len = sizeof block->signature;
    st = crypto_sign(session->signing_key, payload, (size_t)n,
                     block->signature, &block->signature_len);
    if (st != LT_OK)
        return st;
    return block_compute_hash(block, block->hash);
}

/** Fills in the data fields of a new block that will follow the chain tip. */
static Status build_block(Block *block, const Blockchain *chain,
                          const char *book_id, const char *book_title,
                          const char *member_id, const char *member_name,
                          const char *action)
{
    const Block *tip = chain_last(chain);

    memset(block, 0, sizeof *block);
    if (chain->length >= (size_t)INT_MAX)
        return LT_ERR_MEMORY;
    block->index = (int)chain->length;
    block->timestamp = time(NULL);

    if (!str_is_safe_field(book_id) || !str_is_safe_field(book_title) ||
        !str_is_safe_field(member_id) || !str_is_safe_field(member_name) ||
        str_copy(block->book_id, sizeof block->book_id, book_id) != 0 ||
        str_copy(block->book_title, sizeof block->book_title, book_title) != 0 ||
        str_copy(block->member_id, sizeof block->member_id, member_id) != 0 ||
        str_copy(block->member_name, sizeof block->member_name, member_name) != 0 ||
        str_copy(block->action, sizeof block->action, action) != 0)
        return LT_ERR_INPUT;

    if (tip == NULL)
        zero_hash(block->previous_hash);
    else if (str_copy(block->previous_hash, sizeof block->previous_hash, tip->hash) != 0)
        return LT_ERR_FORMAT;
    return LT_OK;
}

Status chain_create_genesis(Blockchain *chain, const Session *session)
{
    Block block;
    Status st;

    if (chain->length != 0)
        return LT_ERR_EXISTS;
    st = build_block(&block, chain, "GENESIS", "Genesis Block", "SYSTEM",
                     "Library Lending Ledger", ACTION_GENESIS);
    if (st == LT_OK)
        st = seal_block(&block, session);
    if (st == LT_OK)
        st = chain_push(chain, &block);
    return st;
}

Status chain_append_record(Blockchain *chain, const Session *session,
                           const char *book_id, const char *book_title,
                           const char *member_id, const char *member_name,
                           const char *action)
{
    Block block;
    Status st;

    if (chain->length == 0)
        return LT_ERR_CHAIN_INVALID; /* a genesis block must exist first */
    if (!action_is_lending(action))
        return LT_ERR_INPUT;

    st = build_block(&block, chain, book_id, book_title, member_id, member_name, action);
    if (st == LT_OK)
        st = seal_block(&block, session);
    if (st == LT_OK)
        st = chain_push(chain, &block);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Validation                                                               */
/* ------------------------------------------------------------------------ */

static void log_block_result(FILE *log, const Block *b, size_t position, int block_ok,
                             int structure_ok, int hash_ok, int link_ok, SigCheck sig,
                             const char *computed, const char *expected_prev)
{
    const char *sig_text = (sig == SIG_VALID) ? "VALID"
                         : (sig == SIG_NO_KEY) ? "UNVERIFIABLE (no public key)"
                         : "INVALID";

    fprintf(log, "  Block #%-3zu %s%-10s%s hash %s%s%s | link %s%s%s | signature %s%s%s (%s)\n",
            position,
            clr(block_ok ? CLR_GREEN : CLR_RED), block_ok ? "[OK]" : "[TAMPERED]", clr(CLR_RESET),
            clr(hash_ok ? CLR_GREEN : CLR_RED), hash_ok ? "OK" : "MISMATCH", clr(CLR_RESET),
            clr(link_ok ? CLR_GREEN : CLR_RED), link_ok ? "OK" : "BROKEN", clr(CLR_RESET),
            clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED), sig_text, clr(CLR_RESET),
            b->signed_by[0] ? b->signed_by : "?");

    if (!structure_ok)
        fprintf(log, "              structure    : index %d / action '%s' not valid at position %zu\n",
                b->index, b->action, position);
    if (!hash_ok) {
        fprintf(log, "              stored hash  : %s\n", b->hash);
        fprintf(log, "              computed hash: %s\n", computed[0] ? computed : "(could not compute)");
    }
    if (!link_ok) {
        fprintf(log, "              previous_hash: %s\n", b->previous_hash);
        fprintf(log, "              expected     : %s\n", expected_prev);
    }
}

int chain_validate(const Blockchain *chain, KeyRing *keys, FILE *log,
                   ValidationReport *report)
{
    ValidationReport r;
    char zero[HASH_HEX_LEN];
    size_t i;

    memset(&r, 0, sizeof r);
    r.first_bad_index = -1;
    zero_hash(zero);

    if (chain->length == 0) {
        r.structure_errors++;
        if (log != NULL)
            fprintf(log, "  The chain is empty - the genesis block is missing.\n");
    }

    for (i = 0; i < chain->length; i++) {
        const Block *b = &chain->blocks[i];
        const char *expected_prev = (i == 0) ? zero : chain->blocks[i - 1].hash;
        char computed[HASH_HEX_LEN] = "";
        int structure_ok, hash_ok, link_ok, block_ok;
        SigCheck sig;

        structure_ok = (b->index >= 0 && (size_t)b->index == i) &&
                       (i == 0 ? strcmp(b->action, ACTION_GENESIS) == 0
                               : action_is_lending(b->action));
        hash_ok = block_compute_hash(b, computed) == LT_OK && strcmp(computed, b->hash) == 0;
        link_ok = strcmp(b->previous_hash, expected_prev) == 0;
        sig = block_verify_signature(b, keys);
        block_ok = structure_ok && hash_ok && link_ok && sig == SIG_VALID;

        r.blocks_checked++;
        if (!structure_ok) r.structure_errors++;
        if (!hash_ok)      r.hash_errors++;
        if (!link_ok)      r.link_errors++;
        if (sig != SIG_VALID) r.signature_errors++;
        if (!block_ok && r.first_bad_index < 0)
            r.first_bad_index = (long)i;

        if (log != NULL)
            log_block_result(log, b, i, block_ok, structure_ok, hash_ok, link_ok, sig,
                             computed, expected_prev);
    }

    if (report != NULL)
        *report = r;
    return r.structure_errors == 0 && r.first_bad_index < 0;
}

/* ------------------------------------------------------------------------ */
/* Queries                                                                  */
/* ------------------------------------------------------------------------ */

const Block *chain_find_latest_event(const Blockchain *chain, const char *book_id)
{
    size_t i = chain->length;

    while (i > 1) { /* index 0 is the genesis block */
        const Block *b = &chain->blocks[--i];
        if (action_is_lending(b->action) && strcmp(b->book_id, book_id) == 0)
            return b;
    }
    return NULL;
}

const Block *chain_find_latest_borrow(const Blockchain *chain, const char *book_id)
{
    size_t i = chain->length;

    while (i > 1) {
        const Block *b = &chain->blocks[--i];
        if (strcmp(b->action, ACTION_BORROWED) == 0 && strcmp(b->book_id, book_id) == 0)
            return b;
    }
    return NULL;
}
