/**
 * @file blockchain.c
 * @brief Block records, signing, proof-of-work hashing and chain validation.
 */
#include "blockchain.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "crypto.h"
#include "util.h"

#define CHAIN_INITIAL_CAPACITY 16
#define RECORD_PAYLOAD_MAX     512
#define HEADER_PREFIX_MAX      (RECORD_PAYLOAD_MAX + SIGNATURE_MAX_LEN * 2 + 256)
#define POW_CHUNK              (1ULL << 20)

static void zero_hash(char out[HASH_HEX_LEN])
{
    memset(out, '0', HASH_HEX_LEN - 1);
    out[HASH_HEX_LEN - 1] = '\0';
}

static int is_zero_hash(const char *h)
{
    size_t i;

    for (i = 0; i < HASH_HEX_LEN - 1; i++) {
        if (h[i] != '0')
            return 0;
    }
    return h[HASH_HEX_LEN - 1] == '\0';
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

void chain_remove_at(Blockchain *chain, size_t index)
{
    if (index >= chain->length)
        return;
    memmove(&chain->blocks[index], &chain->blocks[index + 1],
            (chain->length - index - 1) * sizeof *chain->blocks);
    chain->length--;
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

int action_is_valid(const char *action)
{
    return action_is_lending(action) || strcmp(action, ACTION_TRANSFER) == 0;
}

/* ------------------------------------------------------------------------ */
/* Serialisation used for signing and hashing                               */
/* ------------------------------------------------------------------------ */

/** The part of the block that the librarian signs when the action happens. */
static int record_payload(const Block *b, char *buf, size_t cap)
{
    int n = snprintf(buf, cap, "%lld|%s|%s|%s|%s|%s|%d|%s|%s",
                     (long long)b->timestamp, b->book_id, b->book_title, b->member_id,
                     b->member_name, b->action, b->token_reward, b->tx_id, b->signed_by);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

/** Everything that is hashed except the nonce (which is appended last). */
static int header_prefix(const Block *b, char *buf, size_t cap)
{
    char record[RECORD_PAYLOAD_MAX];
    char sig_hex[SIGNATURE_MAX_LEN * 2 + 1];
    int n;

    if (b->signature_len > SIGNATURE_MAX_LEN || record_payload(b, record, sizeof record) < 0)
        return -1;
    hex_encode(b->signature, b->signature_len, sig_hex);
    n = snprintf(buf, cap, "%d|%s|%s|%s|%d|%s|%lld|", b->index, record, sig_hex,
                 b->previous_hash, b->difficulty, b->mined_by, (long long)b->mined_at);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

Status block_compute_hash(const Block *block, char out[HASH_HEX_LEN])
{
    char buf[HEADER_PREFIX_MAX + 32];
    int n = header_prefix(block, buf, HEADER_PREFIX_MAX);
    int m;

    if (n < 0)
        return LT_ERR_FORMAT;
    m = snprintf(buf + n, sizeof buf - (size_t)n, "%llu", block->nonce);
    if (m < 0)
        return LT_ERR_FORMAT;
    return crypto_sha256_hex(buf, (size_t)n + (size_t)m, out);
}

SigCheck block_verify_signature(const Block *block, KeyRing *keys)
{
    char payload[RECORD_PAYLOAD_MAX];
    int n = record_payload(block, payload, sizeof payload);
    EVP_PKEY *key;

    if (n < 0 || block->signature_len == 0 || block->signature_len > SIGNATURE_MAX_LEN)
        return SIG_INVALID;
    key = keyring_get(keys, block->signed_by);
    if (key == NULL)
        return SIG_NO_KEY;
    return crypto_verify(key, payload, (size_t)n, block->signature, block->signature_len)
               ? SIG_VALID : SIG_INVALID;
}

/* ------------------------------------------------------------------------ */
/* Proof-of-work                                                            */
/* ------------------------------------------------------------------------ */

/** Leading-zero test on the raw 32-byte digest (2 hex chars per byte). */
static int digest_meets(const unsigned char *d, int difficulty)
{
    int full = difficulty / 2, i;

    for (i = 0; i < full; i++) {
        if (d[i] != 0)
            return 0;
    }
    return (difficulty % 2 == 0) || (d[full] >> 4) == 0;
}

int pow_hash_meets(const char *hash, int difficulty)
{
    int i;

    if (difficulty < MIN_DIFFICULTY || difficulty > MAX_DIFFICULTY)
        return 0;
    for (i = 0; i < difficulty; i++) {
        if (hash[i] != '0')
            return 0;
    }
    return 1;
}

int pow_scan(Block *block, unsigned long long start, unsigned long long count,
             unsigned long long *attempts, unsigned long long *found_offset)
{
    char prefix[HEADER_PREFIX_MAX];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *base = NULL, *work = NULL;
    unsigned long long k;
    int n, result = -1;

    *attempts = 0;
    n = header_prefix(block, prefix, sizeof prefix);
    if (n < 0)
        return -1;

    /* Hash the fixed header once; each attempt only adds the nonce. */
    base = EVP_MD_CTX_new();
    work = EVP_MD_CTX_new();
    if (base == NULL || work == NULL ||
        EVP_DigestInit_ex(base, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(base, prefix, (size_t)n) != 1)
        goto done;

    result = 0;
    for (k = 0; k < count; k++) {
        char nonce_text[24];
        int len = snprintf(nonce_text, sizeof nonce_text, "%llu", start + k);

        if (EVP_MD_CTX_copy_ex(work, base) != 1 ||
            EVP_DigestUpdate(work, nonce_text, (size_t)len) != 1 ||
            EVP_DigestFinal_ex(work, digest, &digest_len) != 1) {
            result = -1;
            break;
        }
        (*attempts)++;
        if (digest_meets(digest, block->difficulty)) {
            block->nonce = start + k;
            hex_encode(digest, digest_len, block->hash);
            if (found_offset != NULL)
                *found_offset = k;
            result = 1;
            break;
        }
    }
done:
    EVP_MD_CTX_free(base);
    EVP_MD_CTX_free(work);
    return result;
}

unsigned long long pow_mine(Block *block)
{
    unsigned long long total = 0, start = 0;

    for (;;) {
        unsigned long long attempts = 0;
        int r = pow_scan(block, start, POW_CHUNK, &attempts, NULL);

        total += attempts;
        if (r != 0)
            return r == 1 ? total : 0;
        start += POW_CHUNK;
    }
}

/* ------------------------------------------------------------------------ */
/* Creating records                                                         */
/* ------------------------------------------------------------------------ */

Status block_create_record(Block *block, const Session *session,
                           const char *book_id, const char *book_title,
                           const char *member_id, const char *member_name,
                           const char *action, int token_reward,
                           const Transaction *tx)
{
    char payload[RECORD_PAYLOAD_MAX];
    int n;
    Status st;

    memset(block, 0, sizeof *block);
    if (!auth_is_logged_in(session))
        return LT_ERR_DENIED;

    block->index = -1;                          /* not on the chain yet */
    block->timestamp = time(NULL);
    if (!str_is_safe_field(book_id) || !str_is_safe_field(book_title) ||
        !str_is_safe_field(member_id) || !str_is_safe_field(member_name) ||
        str_copy(block->book_id, sizeof block->book_id, book_id) != 0 ||
        str_copy(block->book_title, sizeof block->book_title, book_title) != 0 ||
        str_copy(block->member_id, sizeof block->member_id, member_id) != 0 ||
        str_copy(block->member_name, sizeof block->member_name, member_name) != 0 ||
        str_copy(block->action, sizeof block->action, action) != 0 ||
        str_copy(block->signed_by, sizeof block->signed_by, session->username) != 0)
        return LT_ERR_INPUT;
    block->token_reward = token_reward;

    if (tx != NULL && tx->type != TX_NONE) {
        block->tx = *tx;
        st = tx_compute_id(&block->tx, block->tx_id);
        if (st != LT_OK)
            return st;
    } else {
        tx_clear(&block->tx);
        zero_hash(block->tx_id);
    }

    zero_hash(block->previous_hash);
    zero_hash(block->hash);
    (void)str_copy(block->mined_by, sizeof block->mined_by, "-");

    n = record_payload(block, payload, sizeof payload);
    if (n < 0)
        return LT_ERR_FORMAT;
    block->signature_len = sizeof block->signature;
    return crypto_sign(session->signing_key, payload, (size_t)n,
                       block->signature, &block->signature_len);
}

void block_prepare_for_mining(Block *block, const Blockchain *chain,
                              int difficulty, const char *miner_id)
{
    const Block *tip = chain_last(chain);

    block->index = (int)chain->length;
    if (tip != NULL)
        (void)str_copy(block->previous_hash, sizeof block->previous_hash, tip->hash);
    else
        zero_hash(block->previous_hash);
    block->difficulty = difficulty;
    (void)str_copy(block->mined_by, sizeof block->mined_by, miner_id);
    block->mined_at = time(NULL);
    block->nonce = 0;
    block->hash[0] = '\0';
}

Status chain_create_genesis(Blockchain *chain, const Session *session, int difficulty)
{
    Block block;
    Status st;

    if (chain->length != 0)
        return LT_ERR_EXISTS;
    st = block_create_record(&block, session, "GENESIS", "Genesis Block", "SYSTEM",
                             "Library Lending Ledger", ACTION_GENESIS, 0, NULL);
    if (st != LT_OK)
        return st;
    block_prepare_for_mining(&block, chain, difficulty, "GENESIS");
    if (pow_mine(&block) == 0)
        return LT_ERR_CRYPTO;
    return chain_push(chain, &block);
}

/* ------------------------------------------------------------------------ */
/* Validation                                                               */
/* ------------------------------------------------------------------------ */

int block_tx_consistent(const Block *b, const char **why)
{
    char computed[HASH_HEX_LEN];
    const Transaction *tx = &b->tx;

    if (strcmp(b->action, ACTION_RETURNED) == 0) {
        if (tx->type != TX_REWARD) { *why = "RETURNED block without a reward transaction"; return 0; }
        if (b->token_reward != REWARD_ON_TIME && b->token_reward != REWARD_LATE) {
            *why = "token_reward must be 10 (on time) or 5 (late)"; return 0;
        }
        if (tx->amount != b->token_reward || strcmp(tx->to, b->member_id) != 0 ||
            strcmp(tx->from, LIBRARY_ACCOUNT) != 0 || tx->fee != TX_FEE ||
            strcmp(tx->ref, b->book_id) != 0) {
            *why = "reward transaction does not match the block"; return 0;
        }
    } else if (strcmp(b->action, ACTION_TRANSFER) == 0) {
        if (tx->type != TX_TRANSFER || b->token_reward != 0 ||
            strcmp(tx->from, b->member_id) != 0 || strcmp(tx->from, tx->to) == 0 ||
            tx->amount < 1 || tx->fee != TX_FEE) {
            *why = "transfer transaction does not match the block"; return 0;
        }
    } else {
        if (tx->type != TX_NONE || b->token_reward != 0 || !is_zero_hash(b->tx_id)) {
            *why = "this action must not carry a transaction or reward"; return 0;
        }
        return 1;
    }
    if (tx_compute_id(tx, computed) != LT_OK || strcmp(computed, b->tx_id) != 0) {
        *why = "tx_id is not the SHA-256 hash of the transaction";
        return 0;
    }
    return 1;
}

static void log_block_result(FILE *log, const Block *b, size_t position, int ok,
                             int structure_ok, int tx_ok, const char *tx_why, int hash_ok,
                             int pow_ok, int link_ok, SigCheck sig, const char *computed,
                             const char *expected_prev)
{
    const char *sig_text = sig == SIG_VALID ? "VALID" : sig == SIG_NO_KEY ? "NO KEY" : "INVALID";

    fprintf(log, "  Block #%-3zu %s%-10s%s hash %s%s%s | PoW %s%s%s (d=%d) | link %s%s%s"
                 " | tx %s%s%s | sig %s%s%s (%s)\n",
            position,
            clr(ok ? CLR_GREEN : CLR_RED), ok ? "[OK]" : "[TAMPERED]", clr(CLR_RESET),
            clr(hash_ok ? CLR_GREEN : CLR_RED), hash_ok ? "OK" : "MISMATCH", clr(CLR_RESET),
            clr(pow_ok ? CLR_GREEN : CLR_RED), pow_ok ? "OK" : "FAIL", clr(CLR_RESET),
            b->difficulty,
            clr(link_ok ? CLR_GREEN : CLR_RED), link_ok ? "OK" : "BROKEN", clr(CLR_RESET),
            clr(tx_ok ? CLR_GREEN : CLR_RED), tx_ok ? "OK" : "BAD", clr(CLR_RESET),
            clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED), sig_text, clr(CLR_RESET),
            b->signed_by[0] ? b->signed_by : "?");
    if (!structure_ok)
        fprintf(log, "              structure    : index %d / action '%s' not valid here\n",
                b->index, b->action);
    if (!tx_ok)
        fprintf(log, "              transaction  : %s\n", tx_why);
    if (!hash_ok) {
        fprintf(log, "              stored hash  : %s\n", b->hash);
        fprintf(log, "              computed hash: %s\n", computed[0] ? computed : "(error)");
    }
    if (hash_ok && !pow_ok)
        fprintf(log, "              proof-of-work: hash does not start with %d zero(s)\n",
                b->difficulty);
    if (!link_ok) {
        fprintf(log, "              previous_hash: %s\n", b->previous_hash);
        fprintf(log, "              expected     : %s\n", expected_prev);
    }
}

int chain_validate(const Blockchain *chain, KeyRing *keys, FILE *log, ValidationReport *report)
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
        const char *tx_why = "";
        char computed[HASH_HEX_LEN] = "";
        int structure_ok, tx_ok, hash_ok, pow_ok, link_ok, ok;
        SigCheck sig;

        structure_ok = b->index >= 0 && (size_t)b->index == i &&
                       (i == 0 ? strcmp(b->action, ACTION_GENESIS) == 0
                               : action_is_valid(b->action));
        tx_ok = (i == 0) ? (b->tx.type == TX_NONE && is_zero_hash(b->tx_id))
                         : block_tx_consistent(b, &tx_why);
        if (i == 0 && !tx_ok)
            tx_why = "the genesis block must not carry a transaction";
        hash_ok = block_compute_hash(b, computed) == LT_OK && strcmp(computed, b->hash) == 0;
        pow_ok = pow_hash_meets(b->hash, b->difficulty);
        link_ok = strcmp(b->previous_hash, expected_prev) == 0;
        sig = block_verify_signature(b, keys);
        ok = structure_ok && tx_ok && hash_ok && pow_ok && link_ok && sig == SIG_VALID;

        r.blocks_checked++;
        if (!structure_ok) r.structure_errors++;
        if (!tx_ok)        r.tx_errors++;
        if (!hash_ok)      r.hash_errors++;
        if (!pow_ok)       r.pow_errors++;
        if (!link_ok)      r.link_errors++;
        if (sig != SIG_VALID) r.signature_errors++;
        if (!ok && r.first_bad_index < 0)
            r.first_bad_index = (long)i;
        if (log != NULL)
            log_block_result(log, b, i, ok, structure_ok, tx_ok, tx_why, hash_ok, pow_ok,
                             link_ok, sig, computed, expected_prev);
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

    while (i > 0) {
        const Block *b = &chain->blocks[--i];
        if (action_is_lending(b->action) && strcmp(b->book_id, book_id) == 0)
            return b;
    }
    return NULL;
}

const Block *chain_find_latest_borrow(const Blockchain *chain, const char *book_id)
{
    size_t i = chain->length;

    while (i > 0) {
        const Block *b = &chain->blocks[--i];
        if (strcmp(b->action, ACTION_BORROWED) == 0 && strcmp(b->book_id, book_id) == 0)
            return b;
    }
    return NULL;
}

long chain_count_outgoing(const Blockchain *chain, const char *member_id)
{
    long n = 0;
    size_t i;

    for (i = 0; i < chain->length; i++) {
        const Transaction *tx = &chain->blocks[i].tx;
        if (tx->type == TX_TRANSFER && strcmp(tx->from, member_id) == 0)
            n++;
    }
    return n;
}

long chain_count_rewards(const Blockchain *chain)
{
    long n = 0;
    size_t i;

    for (i = 0; i < chain->length; i++) {
        if (chain->blocks[i].tx.type == TX_REWARD)
            n++;
    }
    return n;
}
