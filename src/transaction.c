/**
 * @file transaction.c
 * @brief Creating, serialising, parsing and hashing token transactions.
 */
#include "transaction.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

#define TX_FIELD_COUNT 9

void tx_clear(Transaction *tx)
{
    memset(tx, 0, sizeof *tx);
    tx->type = TX_NONE;
}

void tx_make_reward(Transaction *tx, const char *member_id, long amount,
                    long sequence_no, const char *book_id, time_t timestamp)
{
    tx_clear(tx);
    tx->type = TX_REWARD;
    (void)str_copy(tx->from, sizeof tx->from, LIBRARY_ACCOUNT);
    (void)str_copy(tx->to, sizeof tx->to, member_id);
    tx->amount = amount;
    tx->fee = TX_FEE;
    tx->nonce = sequence_no;
    tx->timestamp = timestamp;
    (void)str_copy(tx->ref, sizeof tx->ref, book_id);
}

void tx_make_transfer(Transaction *tx, const char *from, const char *to,
                      long amount, long nonce, time_t timestamp)
{
    tx_clear(tx);
    tx->type = TX_TRANSFER;
    (void)str_copy(tx->from, sizeof tx->from, from);
    (void)str_copy(tx->to, sizeof tx->to, to);
    tx->amount = amount;
    tx->fee = TX_FEE;
    tx->nonce = nonce;
    tx->timestamp = timestamp;
    (void)str_copy(tx->ref, sizeof tx->ref, "-");
}

const char *tx_type_name(TxType type)
{
    switch (type) {
    case TX_REWARD:   return "REWARD";
    case TX_TRANSFER: return "TRANSFER";
    case TX_NONE:     break;
    }
    return "NONE";
}

long tx_recipient_credit(const Transaction *tx)
{
    if (tx->type == TX_REWARD)
        return tx->amount - tx->fee;
    if (tx->type == TX_TRANSFER)
        return tx->amount;
    return 0;
}

long tx_sender_debit(const Transaction *tx)
{
    return tx->type == TX_TRANSFER ? tx->amount + tx->fee : 0;
}

int tx_serialize(const Transaction *tx, char *buf, size_t cap)
{
    size_t used, i;
    int n;

    if (tx->type == TX_NONE) {
        n = snprintf(buf, cap, "-");
        return (n < 0 || (size_t)n >= cap) ? -1 : n;
    }
    n = snprintf(buf, cap, "%c;%s;%s;%ld;%ld;%ld;%lld;%s;",
                 tx->type == TX_REWARD ? 'R' : 'T', tx->from, tx->to, tx->amount,
                 tx->fee, tx->nonce, (long long)tx->timestamp, tx->ref);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    used = (size_t)n;
    for (i = 0; i < tx->input_count; i++) {
        n = snprintf(buf + used, cap - used, "%s%s:%d", i ? "," : "",
                     tx->inputs[i].txid, tx->inputs[i].vout);
        if (n < 0 || (size_t)n >= cap - used)
            return -1;
        used += (size_t)n;
    }
    return (int)used;
}

static int parse_long(const char *s, long min, long max, long *out)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

static Status parse_inputs(char *list, Transaction *tx)
{
    char *item[TX_MAX_INPUTS];
    size_t count, i;

    tx->input_count = 0;
    if (*list == '\0')
        return LT_OK;
    count = str_split(list, ',', item, TX_MAX_INPUTS);
    if (count > TX_MAX_INPUTS)
        return LT_ERR_FORMAT;
    for (i = 0; i < count; i++) {
        char *colon = strchr(item[i], ':');
        long vout;

        if (colon == NULL)
            return LT_ERR_FORMAT;
        *colon = '\0';
        if (!is_hex_string(item[i], HASH_HEX_LEN - 1) ||
            parse_long(colon + 1, 0, 1000, &vout) != 0)
            return LT_ERR_FORMAT;
        (void)str_copy(tx->inputs[i].txid, sizeof tx->inputs[i].txid, item[i]);
        tx->inputs[i].vout = (int)vout;
    }
    tx->input_count = count;
    return LT_OK;
}

Status tx_parse(const char *text, Transaction *tx)
{
    char copy[TX_TEXT_MAX];
    char *f[TX_FIELD_COUNT];
    long amount, fee, nonce, ts;

    tx_clear(tx);
    if (strcmp(text, "-") == 0)
        return LT_OK;
    if (str_copy(copy, sizeof copy, text) != 0 ||
        str_split(copy, ';', f, TX_FIELD_COUNT) != TX_FIELD_COUNT)
        return LT_ERR_FORMAT;

    if (strcmp(f[0], "R") == 0)
        tx->type = TX_REWARD;
    else if (strcmp(f[0], "T") == 0)
        tx->type = TX_TRANSFER;
    else
        return LT_ERR_FORMAT;

    if (!str_is_identifier(f[1]) || str_copy(tx->from, sizeof tx->from, f[1]) != 0 ||
        !str_is_identifier(f[2]) || str_copy(tx->to, sizeof tx->to, f[2]) != 0 ||
        parse_long(f[3], 0, 1000000000L, &amount) != 0 ||
        parse_long(f[4], 0, 1000000000L, &fee) != 0 ||
        parse_long(f[5], 0, LONG_MAX, &nonce) != 0 ||
        parse_long(f[6], 0, LONG_MAX, &ts) != 0 ||
        !str_is_identifier(f[7]) || str_copy(tx->ref, sizeof tx->ref, f[7]) != 0)
        return LT_ERR_FORMAT;
    tx->amount = amount;
    tx->fee = fee;
    tx->nonce = nonce;
    tx->timestamp = (time_t)ts;
    return parse_inputs(f[8], tx);
}

Status tx_compute_id(const Transaction *tx, char out[HASH_HEX_LEN])
{
    char text[TX_TEXT_MAX];
    int n;

    if (tx->type == TX_NONE)
        return LT_ERR_INPUT;
    n = tx_serialize(tx, text, sizeof text);
    if (n < 0)
        return LT_ERR_FORMAT;
    return crypto_sha256_hex(text, (size_t)n, out);
}
