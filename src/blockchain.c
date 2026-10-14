/**
 * @file blockchain.c
 * @brief Block memory management, Merkle roots, proof-of-work and validation.
 */
#include "blockchain.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "crypto.h"
#include "merkle.h"
#include "util.h"

#define HEADER_TEXT_MAX 1024
#define POW_CHUNK       100000ULL

void zero_hash(char out[HASH_HEX_LEN])
{
    memset(out, '0', HASH_HEX_LEN - 1);
    out[HASH_HEX_LEN - 1] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Memory                                                                   */
/* ------------------------------------------------------------------------ */

void block_init(Block *block)
{
    memset(block, 0, sizeof *block);
    tx_clear(&block->reward);
    zero_hash(block->previous_hash);
    zero_hash(block->merkle_root);
    zero_hash(block->transaction_id);
    zero_hash(block->hash);
    strcpy(block->sealed_by, "-");
}

void block_free(Block *block)
{
    free(block->records);
    block->records = NULL;
    block->record_count = 0;
}

Status block_copy(Block *dst, const Block *src)
{
    *dst = *src;
    dst->records = NULL;
    if (src->record_count == 0)
        return LT_OK;
    dst->records = malloc(src->record_count * sizeof *dst->records);
    if (dst->records == NULL) {
        dst->record_count = 0;
        return LT_ERR_MEMORY;
    }
    memcpy(dst->records, src->records, src->record_count * sizeof *dst->records);
    return LT_OK;
}

Status block_add_record(Block *block, const Record *rec)
{
    Record *grown;

    if (block->record_count >= MAX_BLOCK_CAPACITY)
        return LT_ERR_LIMIT;
    grown = realloc(block->records, (block->record_count + 1) * sizeof *grown);
    if (grown == NULL)
        return LT_ERR_MEMORY;
    block->records = grown;
    block->records[block->record_count++] = *rec;
    return LT_OK;
}

void block_remove_record(Block *block, size_t index)
{
    if (index >= block->record_count)
        return;
    memmove(&block->records[index], &block->records[index + 1],
            (block->record_count - index - 1) * sizeof *block->records);
    block->record_count--;
}

void chain_init(Blockchain *chain)
{
    chain->blocks = NULL;
    chain->length = 0;
    chain->capacity = 0;
}

void chain_free(Blockchain *chain)
{
    size_t i;

    for (i = 0; i < chain->length; i++)
        block_free(&chain->blocks[i]);
    free(chain->blocks);
    chain_init(chain);
}

Status chain_push(Blockchain *chain, Block *block)
{
    if (chain->length == chain->capacity) {
        size_t new_cap = chain->capacity ? chain->capacity * 2 : 16;
        Block *grown;

        if (new_cap > SIZE_MAX / sizeof *grown)
            return LT_ERR_MEMORY;
        grown = realloc(chain->blocks, new_cap * sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        chain->blocks = grown;
        chain->capacity = new_cap;
    }
    chain->blocks[chain->length++] = *block;   /* ownership of records moves */
    block->records = NULL;
    block->record_count = 0;
    return LT_OK;
}

void chain_pop(Blockchain *chain)
{
    if (chain->length > 0)
        block_free(&chain->blocks[--chain->length]);
}

const Block *chain_tip(const Blockchain *chain)
{
    return chain->length ? &chain->blocks[chain->length - 1] : NULL;
}

Status chain_copy(Blockchain *dst, const Blockchain *src)
{
    size_t i;

    chain_init(dst);
    for (i = 0; i < src->length; i++) {
        Block copy;
        Status st = block_copy(&copy, &src->blocks[i]);
        if (st == LT_OK)
            st = chain_push(dst, &copy);
        if (st != LT_OK) {
            block_free(&copy);
            chain_free(dst);
            return st;
        }
    }
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Merkle root and reward transaction                                       */
/* ------------------------------------------------------------------------ */

Status block_compute_merkle(const Block *block, char out[HASH_HEX_LEN])
{
    char (*leaves)[HASH_HEX_LEN];
    size_t i;
    Status st = LT_OK;

    if (block->record_count == 0)
        return merkle_root(NULL, 0, out);
    leaves = malloc(block->record_count * sizeof *leaves);
    if (leaves == NULL)
        return LT_ERR_MEMORY;
    for (i = 0; i < block->record_count && st == LT_OK; i++)
        st = record_hash(&block->records[i], leaves[i]);
    if (st == LT_OK)
        st = merkle_root((const char (*)[HASH_HEX_LEN])leaves, block->record_count, out);
    free(leaves);
    return st;
}

/** The reward is a pure function of the block's RETURNED records. */
Status block_build_reward(const Block *block, Transaction *reward, long *total)
{
    size_t i;
    Status st = LT_OK;

    tx_clear(reward);
    *total = 0;
    for (i = 0; i < block->record_count && st == LT_OK; i++) {
        const Record *r = &block->records[i];

        if (r->action != ACT_RETURN)
            continue;
        if (reward->type == TX_NONE)
            tx_make_reward(reward, block->index, block->timestamp);
        st = tx_add_reward_output(reward, r->member_id, r->token_reward, r->record_id);
        *total += r->token_reward;
    }
    return st;
}

Status block_finalise_body(Block *block)
{
    Status st;

    st = block_compute_merkle(block, block->merkle_root);
    if (st == LT_OK)
        st = block_build_reward(block, &block->reward, &block->token_reward);
    if (st == LT_OK) {
        if (block->reward.type == TX_NONE)
            zero_hash(block->transaction_id);
        else
            st = tx_compute_id(&block->reward, block->transaction_id);
    }
    return st;
}

/* ------------------------------------------------------------------------ */
/* Header hash and proof-of-work                                            */
/* ------------------------------------------------------------------------ */

/** Everything that is hashed except the nonce (which is appended last). */
static int header_prefix(const Block *b, char *buf, size_t cap)
{
    int n = snprintf(buf, cap, "%d|%lld|%zu|%s|%s|%s|%ld|%s|%d|", b->index,
                     (long long)b->timestamp, b->record_count, b->previous_hash,
                     b->merkle_root, b->sealed_by, b->token_reward, b->transaction_id,
                     b->difficulty);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

Status block_compute_hash(const Block *block, char out[HASH_HEX_LEN])
{
    char buf[HEADER_TEXT_MAX + 32];
    int n = header_prefix(block, buf, HEADER_TEXT_MAX);
    int m;

    if (n < 0)
        return LT_ERR_FORMAT;
    m = snprintf(buf + n, sizeof buf - (size_t)n, "%llu", block->nonce);
    if (m < 0)
        return LT_ERR_FORMAT;
    return crypto_sha256_hex(buf, (size_t)n + (size_t)m, out);
}

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
    char prefix[HEADER_TEXT_MAX];
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

void block_prepare(Block *block, const Blockchain *chain, int difficulty,
                   const char *sealed_by, time_t now)
{
    const Block *tip = chain_tip(chain);

    block->index = (int)chain->length;
    if (tip != NULL)
        (void)str_copy(block->previous_hash, sizeof block->previous_hash, tip->hash);
    else
        zero_hash(block->previous_hash);
    /* Block timestamps must strictly increase. */
    block->timestamp = (tip != NULL && now <= tip->timestamp) ? tip->timestamp + 1 : now;
    block->difficulty = difficulty;
    (void)str_copy(block->sealed_by, sizeof block->sealed_by, sealed_by);
    block->nonce = 0;
    zero_hash(block->hash);
}

Status chain_create_genesis(Blockchain *chain, int difficulty, time_t now)
{
    Block block;
    Status st;

    if (chain->length != 0)
        return LT_ERR_EXISTS;
    block_init(&block);
    block_prepare(&block, chain, difficulty, "GENESIS", now);
    st = block_finalise_body(&block);
    if (st == LT_OK && pow_mine(&block) == 0)
        st = LT_ERR_CRYPTO;
    if (st == LT_OK)
        st = chain_push(chain, &block);
    block_free(&block);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Validation                                                               */
/* ------------------------------------------------------------------------ */

static int is_dash(const char *s)
{
    return strcmp(s, "-") == 0;
}

int record_fields_valid(const Record *rec, const char **why)
{
    int late = rec->due_date > 0 && rec->timestamp > rec->due_date;
    long late_fine = late ? days_between_ceil(rec->due_date, rec->timestamp) * FINE_PER_DAY
                          : 0;
    int member_signed = strcmp(rec->signer_id, rec->member_id) == 0;
    int staff_signed = signer_is_staff(rec->signer_id);

    *why = NULL;
    switch (rec->action) {
    case ACT_BORROW:
        if (is_dash(rec->copy_id) || is_dash(rec->book_id) || is_dash(rec->member_id))
            *why = "BORROWED record without a copy or member";
        else if (rec->due_date <= rec->timestamp)
            *why = "due date is not after the borrow time";
        else if (rec->fine_amount != 0 || rec->token_reward != 0 || rec->tx.type != TX_NONE)
            *why = "BORROWED record must not carry a fine, reward or transaction";
        else if (!member_signed)
            *why = "BORROWED record must be signed by the member";
        break;
    case ACT_RETURN:
        if (is_dash(rec->copy_id) || rec->due_date == 0)
            *why = "RETURNED record without a copy or due date";
        else if (rec->token_reward != (late ? REWARD_LATE : REWARD_ON_TIME))
            *why = "token_reward must be 10 (on time) or 5 (late)";
        else if (rec->fine_amount != late_fine)
            *why = "fine_amount does not match the days late";
        else if (rec->tx.type != TX_NONE || rec->condition == COND_LOST)
            *why = "RETURNED record has an invalid transaction or condition";
        else if (!member_signed)
            *why = "RETURNED record must be signed by the member";
        break;
    case ACT_RESERVE:
        if (is_dash(rec->book_id) || !is_dash(rec->copy_id))
            *why = "RESERVED record must name a title and no copy";
        else if (rec->fine_amount != 0 || rec->token_reward != 0 || rec->tx.type != TX_NONE)
            *why = "RESERVED record must not carry a fine, reward or transaction";
        else if (!member_signed)
            *why = "RESERVED record must be signed by the member";
        break;
    case ACT_RENEW:
        if (is_dash(rec->copy_id) || rec->due_date <= rec->timestamp)
            *why = "RENEWED record needs a copy and a future due date";
        else if (rec->fine_amount != 0 || rec->token_reward != 0 || rec->tx.type != TX_NONE)
            *why = "RENEWED record must not carry a fine, reward or transaction";
        else if (!member_signed)
            *why = "RENEWED record must be signed by the member";
        break;
    case ACT_OVERDUE:
        if (is_dash(rec->copy_id) || !late)
            *why = "OVERDUE record for a copy that was not past its due date";
        else if (rec->fine_amount != late_fine)
            *why = "fine_amount does not match the days overdue";
        else if (rec->token_reward != 0 || rec->tx.type != TX_NONE)
            *why = "OVERDUE record must not carry a reward or transaction";
        else if (!staff_signed)
            *why = "OVERDUE record must be signed by a librarian";
        break;
    case ACT_LOST:
        if (is_dash(rec->copy_id) || is_dash(rec->reason) || rec->condition != COND_LOST)
            *why = "LOST record needs a copy, a reason code and condition LOST";
        else if (rec->fine_amount != 0 || rec->token_reward != 0 || rec->tx.type != TX_NONE)
            *why = "LOST record must not carry a fine, reward or transaction";
        else if (!staff_signed)
            *why = "LOST record must be signed by a librarian";
        break;
    case ACT_TRANSFER:
        if (rec->tx.type != TX_TRANSFER || strcmp(rec->tx.from, rec->member_id) != 0 ||
            strcmp(rec->tx.to, rec->tx.from) == 0 || rec->tx.amount <= 0 ||
            rec->tx.fee != TX_FEE)
            *why = "TRANSFER record has an invalid transaction";
        else if (!member_signed)
            *why = "TRANSFER record must be signed by the sender";
        break;
    case ACT_FINE:
        if (rec->tx.type != TX_FINE || strcmp(rec->tx.from, rec->member_id) != 0 ||
            rec->tx.amount <= 0)
            *why = "FINE_PAID record has an invalid transaction";
        else if (tx_moves_tokens(&rec->tx) ? (!member_signed || rec->tx.fee != TX_FEE)
                                           : (!staff_signed || rec->tx.fee != 0))
            *why = "token fines are signed by the member, cash fines by a librarian";
        break;
    case ACT_NONE:
        *why = "unknown action";
        break;
    }
    if (*why == NULL && rec->tx.type != TX_NONE && rec->tx.timestamp != rec->timestamp)
        *why = "transaction timestamp differs from the record";
    return *why == NULL;
}

void chain_check_block(const Blockchain *chain, size_t i, KeyDirectory *keys, BlockCheck *out)
{
    const Block *b = &chain->blocks[i];
    char expected_prev[HASH_HEX_LEN], reward_id[HASH_HEX_LEN];
    Transaction reward;
    long total = 0;
    size_t r;

    memset(out, 0, sizeof *out);
    out->time_ok = 1;

    /* Structure: position, genesis rules, record count. */
    out->structure_ok = b->index == (int)i && b->record_count <= MAX_BLOCK_CAPACITY &&
                        (i != 0 || (b->record_count == 0 && strcmp(b->sealed_by, "GENESIS") == 0));
    if (!out->structure_ok)
        snprintf(out->detail, sizeof out->detail, "index %d / record count %zu not valid here",
                 b->index, b->record_count);

    /* Timestamps strictly increase from block to block. */
    if (i > 0 && b->timestamp <= chain->blocks[i - 1].timestamp) {
        out->time_ok = 0;
        if (out->detail[0] == '\0')
            snprintf(out->detail, sizeof out->detail,
                     "timestamp is not later than the previous block's");
    }

    /* Merkle root recomputed from the records. */
    if (block_compute_merkle(b, out->computed_merkle) == LT_OK)
        out->merkle_ok = strcmp(out->computed_merkle, b->merkle_root) == 0;
    if (!out->merkle_ok && out->detail[0] == '\0')
        snprintf(out->detail, sizeof out->detail, "Merkle root mismatch: records changed");

    /* Reward transaction rebuilt from the RETURNED records. */
    if (block_build_reward(b, &reward, &total) == LT_OK) {
        if (reward.type == TX_NONE)
            zero_hash(reward_id);
        else if (tx_compute_id(&reward, reward_id) != LT_OK)
            reward_id[0] = '\0';
        out->reward_ok = total == b->token_reward && strcmp(reward_id, b->transaction_id) == 0;
    }
    if (!out->reward_ok && out->detail[0] == '\0')
        snprintf(out->detail, sizeof out->detail,
                 "token_reward / transaction_id do not match the block's returns");

    /* Header hash, proof-of-work and link. */
    if (block_compute_hash(b, out->computed_hash) == LT_OK)
        out->hash_ok = strcmp(out->computed_hash, b->hash) == 0;
    out->pow_ok = pow_hash_meets(b->hash, b->difficulty);
    if (i == 0)
        zero_hash(expected_prev);
    else
        (void)str_copy(expected_prev, sizeof expected_prev, chain->blocks[i - 1].hash);
    out->link_ok = strcmp(b->previous_hash, expected_prev) == 0;
    if (!out->hash_ok && out->detail[0] == '\0')
        snprintf(out->detail, sizeof out->detail, "stored hash %.16s... != computed %.16s...",
                 b->hash, out->computed_hash);
    if (!out->link_ok && out->detail[0] == '\0')
        snprintf(out->detail, sizeof out->detail, "previous_hash %.16s... != %.16s...",
                 b->previous_hash, expected_prev);

    /* Every record: ECDSA signature and field consistency. */
    for (r = 0; r < b->record_count; r++) {
        const Record *rec = &b->records[r];
        const char *why = NULL;
        SigCheck sig = record_verify(rec, keys);

        if (sig != SIG_VALID) {
            out->bad_signatures++;
            if (out->detail[0] == '\0')
                snprintf(out->detail, sizeof out->detail, "record %zu (%s, %s) signature %s",
                         r + 1, rec->record_id, action_record_name(rec->action),
                         sig_check_name(sig));
        }
        if (!record_fields_valid(rec, &why) || rec->timestamp > b->timestamp) {
            out->bad_records++;
            if (out->detail[0] == '\0')
                snprintf(out->detail, sizeof out->detail, "record %zu (%s): %s", r + 1,
                         rec->record_id, why ? why : "record is newer than its block");
        }
    }
}

int chain_validate(const Blockchain *chain, KeyDirectory *keys, FILE *log, ChainReport *report)
{
    size_t i;

    memset(report, 0, sizeof *report);
    report->first_bad_index = -1;
    if (chain->length == 0) {
        report->structure_errors = 1;
        report->first_bad_index = 0;
        if (log != NULL)
            fprintf(log, "  The chain is empty: there is no genesis block.\n");
        return 0;
    }
    for (i = 0; i < chain->length; i++) {
        const Block *b = &chain->blocks[i];
        BlockCheck c;
        int ok;

        chain_check_block(chain, i, keys, &c);
        ok = c.structure_ok && c.time_ok && c.merkle_ok && c.reward_ok && c.hash_ok &&
             c.pow_ok && c.link_ok && c.bad_signatures == 0 && c.bad_records == 0;
        report->blocks_checked++;
        report->records_checked += b->record_count;
        report->structure_errors += !c.structure_ok;
        report->time_errors += !c.time_ok;
        report->merkle_errors += !c.merkle_ok;
        report->reward_errors += !c.reward_ok;
        report->hash_errors += !c.hash_ok;
        report->pow_errors += !c.pow_ok;
        report->link_errors += !c.link_ok;
        report->signature_errors += c.bad_signatures;
        report->record_errors += c.bad_records;
        if (!ok && report->first_bad_index < 0)
            report->first_bad_index = (long)i;
        if (log != NULL) {
            fprintf(log, "  Block #%-3zu %s%-10s%s hash %s | PoW %s (d=%d) | link %s | "
                         "merkle %s | signatures %zu/%zu valid\n",
                    i, ok ? clr(CLR_GREEN) : clr(CLR_RED), ok ? "[OK]" : "[TAMPERED]",
                    clr(CLR_RESET), c.hash_ok ? "OK" : "MISMATCH", c.pow_ok ? "OK" : "FAIL",
                    b->difficulty, c.link_ok ? "OK" : "BROKEN", c.merkle_ok ? "OK" : "MISMATCH",
                    b->record_count - c.bad_signatures, b->record_count);
            if (!ok)
                fprintf(log, "              %s%s%s\n", clr(CLR_YELLOW), c.detail, clr(CLR_RESET));
        }
    }
    return report->first_bad_index < 0;
}

const Record *chain_find_record(const Blockchain *chain, const char *record_id,
                                size_t *block_index, size_t *record_index)
{
    size_t i, r;

    for (i = 0; i < chain->length; i++) {
        for (r = 0; r < chain->blocks[i].record_count; r++) {
            if (strcmp(chain->blocks[i].records[r].record_id, record_id) == 0) {
                if (block_index != NULL)
                    *block_index = i;
                if (record_index != NULL)
                    *record_index = r;
                return &chain->blocks[i].records[r];
            }
        }
    }
    return NULL;
}
