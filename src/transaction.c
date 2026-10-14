/**
 * @file transaction.c
 * @brief Creating, serialising, parsing and hashing token transactions.
 */
#include "transaction.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

#define TX_FIELD_COUNT 10

void tx_clear(Transaction *tx)
{
    memset(tx, 0, sizeof *tx);
    tx->type = TX_NONE;
}

static void set_common(Transaction *tx, TxType type, const char *from, const char *to,
                       long amount, long fee, long nonce, time_t timestamp, const char *method)
{
    tx_clear(tx);
    tx->type = type;
    (void)str_copy(tx->from, sizeof tx->from, from);
    (void)str_copy(tx->to, sizeof tx->to, to);
    tx->amount = amount;
    tx->fee = fee;
    tx->nonce = nonce;
    tx->timestamp = timestamp;
    (void)str_copy(tx->method, sizeof tx->method, method);
}

void tx_make_reward(Transaction *tx, long block_index, time_t timestamp)
{
    set_common(tx, TX_REWARD, LIBRARY_ACCOUNT, "-", 0, TX_FEE, block_index, timestamp, "-");
}

Status tx_add_reward_output(Transaction *tx, const char *member_id, long gross,
                            const char *record_id)
{
    TxOutput *out;

    if (tx->type != TX_REWARD || tx->output_count >= TX_MAX_OUTPUTS || gross <= tx->fee)
        return LT_ERR_INPUT;
    out = &tx->outputs[tx->output_count];
    if (str_copy(out->to, sizeof out->to, member_id) != 0 ||
        str_copy(out->ref, sizeof out->ref, record_id) != 0)
        return LT_ERR_INPUT;
    out->amount = gross;
    tx->amount += gross;
    tx->output_count++;
    return LT_OK;
}

void tx_make_transfer(Transaction *tx, const char *from, const char *to,
                      long amount, long nonce, time_t timestamp)
{
    set_common(tx, TX_TRANSFER, from, to, amount, TX_FEE, nonce, timestamp, "-");
}

void tx_make_fine(Transaction *tx, const char *member_id, long amount, int pay_with_tokens,
                  long nonce, time_t timestamp)
{
    set_common(tx, TX_FINE, member_id, LIBRARY_ACCOUNT, amount,
               pay_with_tokens ? TX_FEE : 0, pay_with_tokens ? nonce : 0, timestamp,
               pay_with_tokens ? "TOKENS" : "CASH");
}

int tx_moves_tokens(const Transaction *tx)
{
    if (tx->type == TX_REWARD || tx->type == TX_TRANSFER)
        return 1;
    return tx->type == TX_FINE && strcmp(tx->method, "TOKENS") == 0;
}

long tx_sender_debit(const Transaction *tx)
{
    if (tx->type == TX_TRANSFER || (tx->type == TX_FINE && tx_moves_tokens(tx)))
        return tx->amount + tx->fee;
    return 0;
}

long tx_total_fees(const Transaction *tx)
{
    if (tx->type == TX_REWARD)
        return tx->fee * (long)tx->output_count;
    return tx_moves_tokens(tx) ? tx->fee : 0;
}

const char *tx_type_name(TxType type)
{
    switch (type) {
    case TX_REWARD:   return "REWARD";
    case TX_TRANSFER: return "TRANSFER";
    case TX_FINE:     return "FINE";
    case TX_NONE:     break;
    }
    return "NONE";
}

static char type_code(TxType type)
{
    switch (type) {
    case TX_REWARD:   return 'R';
    case TX_TRANSFER: return 'T';
    case TX_FINE:     return 'F';
    case TX_NONE:     break;
    }
    return '-';
}

int tx_serialize(const Transaction *tx, char *buf, size_t cap)
{
    size_t used, i;
    int n;

    if (tx->type == TX_NONE) {
        n = snprintf(buf, cap, "-");
        return (n < 0 || (size_t)n >= cap) ? -1 : n;
    }
    n = snprintf(buf, cap, "%c;%s;%s;%ld;%ld;%ld;%lld;%s;", type_code(tx->type), tx->from,
                 tx->to, tx->amount, tx->fee, tx->nonce, (long long)tx->timestamp, tx->method);
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
    n = snprintf(buf + used, cap - used, ";");
    if (n < 0 || (size_t)n >= cap - used)
        return -1;
    used += (size_t)n;
    for (i = 0; i < tx->output_count; i++) {
        n = snprintf(buf + used, cap - used, "%s%s:%ld:%s", i ? "," : "",
                     tx->outputs[i].to, tx->outputs[i].amount, tx->outputs[i].ref);
        if (n < 0 || (size_t)n >= cap - used)
            return -1;
        used += (size_t)n;
    }
    return (int)used;
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

static Status parse_outputs(char *list, Transaction *tx)
{
    char *item[TX_MAX_OUTPUTS];
    size_t count, i;

    tx->output_count = 0;
    if (*list == '\0')
        return LT_OK;
    count = str_split(list, ',', item, TX_MAX_OUTPUTS);
    if (count > TX_MAX_OUTPUTS)
        return LT_ERR_FORMAT;
    for (i = 0; i < count; i++) {
        char *f[3];
        long amount;

        if (str_split(item[i], ':', f, 3) != 3 || !str_is_identifier(f[0]) ||
            str_copy(tx->outputs[i].to, sizeof tx->outputs[i].to, f[0]) != 0 ||
            parse_long(f[1], 1, 1000000L, &amount) != 0 ||
            !is_hex_string(f[2], REQUEST_ID_LEN - 1) ||
            str_copy(tx->outputs[i].ref, sizeof tx->outputs[i].ref, f[2]) != 0)
            return LT_ERR_FORMAT;
        tx->outputs[i].amount = amount;
    }
    tx->output_count = count;
    return LT_OK;
}

Status tx_parse(const char *text, Transaction *tx)
{
    char copy[TX_TEXT_MAX];
    char *f[TX_FIELD_COUNT];
    long amount, fee, nonce, ts;
    Status st;

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
    else if (strcmp(f[0], "F") == 0)
        tx->type = TX_FINE;
    else
        return LT_ERR_FORMAT;

    if (!str_is_identifier(f[1]) || str_copy(tx->from, sizeof tx->from, f[1]) != 0 ||
        !(str_is_identifier(f[2]) || strcmp(f[2], "-") == 0) ||
        str_copy(tx->to, sizeof tx->to, f[2]) != 0 ||
        parse_long(f[3], 0, 1000000000L, &amount) != 0 ||
        parse_long(f[4], 0, 1000000L, &fee) != 0 ||
        parse_long(f[5], 0, LONG_MAX, &nonce) != 0 ||
        parse_long(f[6], 0, LONG_MAX, &ts) != 0 ||
        str_copy(tx->method, sizeof tx->method, f[7]) != 0)
        return LT_ERR_FORMAT;
    if (tx->type == TX_FINE ? (strcmp(f[7], "TOKENS") != 0 && strcmp(f[7], "CASH") != 0)
                            : strcmp(f[7], "-") != 0)
        return LT_ERR_FORMAT;
    tx->amount = amount;
    tx->fee = fee;
    tx->nonce = nonce;
    tx->timestamp = (time_t)ts;
    st = parse_inputs(f[8], tx);
    if (st == LT_OK)
        st = parse_outputs(f[9], tx);
    if (st == LT_OK && (tx->type == TX_REWARD) != (tx->output_count > 0))
        st = LT_ERR_FORMAT;   /* only rewards have explicit outputs */
    return st;
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
