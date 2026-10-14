/**
 * @file utxo.c
 * @brief UTXO ledger: output creation, input validation, coin selection.
 */
#include "utxo.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define UTXO_INITIAL_CAPACITY 32

void utxo_init(UtxoSet *set)
{
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

void utxo_free(UtxoSet *set)
{
    free(set->items);
    utxo_init(set);
}

Status utxo_copy(UtxoSet *dst, const UtxoSet *src)
{
    utxo_init(dst);
    if (src->count == 0)
        return LT_OK;
    dst->items = malloc(src->count * sizeof *dst->items);
    if (dst->items == NULL)
        return LT_ERR_MEMORY;
    memcpy(dst->items, src->items, src->count * sizeof *dst->items);
    dst->count = dst->capacity = src->count;
    return LT_OK;
}

static Status utxo_add(UtxoSet *set, const char *txid, int vout, const char *owner,
                       long amount, int block_index)
{
    Utxo *u;

    if (set->count == set->capacity) {
        size_t new_cap = set->capacity ? set->capacity * 2 : UTXO_INITIAL_CAPACITY;
        Utxo *grown;

        if (new_cap > SIZE_MAX / sizeof *grown)
            return LT_ERR_MEMORY;
        grown = realloc(set->items, new_cap * sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        set->items = grown;
        set->capacity = new_cap;
    }
    u = &set->items[set->count++];
    memset(u, 0, sizeof *u);
    (void)str_copy(u->txid, sizeof u->txid, txid);
    u->vout = vout;
    (void)str_copy(u->owner, sizeof u->owner, owner);
    u->amount = amount;
    u->created_in = block_index;
    u->spent_in = UTXO_PENDING;
    return LT_OK;
}

static Utxo *utxo_find_mut(UtxoSet *set, const char *txid, int vout)
{
    size_t i;

    for (i = 0; i < set->count; i++) {
        if (set->items[i].vout == vout && strcmp(set->items[i].txid, txid) == 0)
            return &set->items[i];
    }
    return NULL;
}

const Utxo *utxo_find(const UtxoSet *set, const char *txid, int vout)
{
    return utxo_find_mut((UtxoSet *)set, txid, vout);
}

long utxo_balance(const UtxoSet *set, const char *owner)
{
    long total = 0;
    size_t i;

    for (i = 0; i < set->count; i++) {
        if (!set->items[i].spent && strcmp(set->items[i].owner, owner) == 0)
            total += set->items[i].amount;
    }
    return total;
}

size_t utxo_unspent_count(const UtxoSet *set, const char *owner)
{
    size_t n = 0, i;

    for (i = 0; i < set->count; i++) {
        if (!set->items[i].spent && (owner == NULL || strcmp(set->items[i].owner, owner) == 0))
            n++;
    }
    return n;
}

Status utxo_check_inputs(const UtxoSet *set, const Transaction *tx, long *input_total,
                         char *err, size_t err_cap)
{
    long total = 0, needed = tx_sender_debit(tx);
    size_t i, j;

    *input_total = 0;
    if (tx->input_count == 0) {
        snprintf(err, err_cap, "the transaction has no inputs");
        return LT_ERR_INSUFFICIENT;
    }
    for (i = 0; i < tx->input_count; i++) {
        const TxInput *in = &tx->inputs[i];
        const Utxo *u = utxo_find(set, in->txid, in->vout);

        for (j = 0; j < i; j++) {
            if (tx->inputs[j].vout == in->vout && strcmp(tx->inputs[j].txid, in->txid) == 0) {
                snprintf(err, err_cap, "output %.10s:%d is used twice in the same transaction",
                         in->txid, in->vout);
                return LT_ERR_DOUBLE_SPEND;
            }
        }
        if (u == NULL) {
            snprintf(err, err_cap, "output %.10s:%d does not exist", in->txid, in->vout);
            return LT_ERR_NOT_FOUND;
        }
        if (u->spent && u->spent_in == UTXO_PENDING) {
            snprintf(err, err_cap, "output %.10s:%d is already being spent by a pending "
                                   "transaction", in->txid, in->vout);
            return LT_ERR_DOUBLE_SPEND;
        }
        if (u->spent) {
            snprintf(err, err_cap, "output %.10s:%d was already spent in block #%d",
                     in->txid, in->vout, u->spent_in);
            return LT_ERR_DOUBLE_SPEND;
        }
        if (u->created_in == UTXO_PENDING) {
            snprintf(err, err_cap, "output %.10s:%d is not confirmed yet", in->txid, in->vout);
            return LT_ERR_STATE;
        }
        if (strcmp(u->owner, tx->from) != 0) {
            snprintf(err, err_cap, "output %.10s:%d belongs to %s, not %s",
                     in->txid, in->vout, u->owner, tx->from);
            return LT_ERR_DENIED;
        }
        total += u->amount;
    }
    *input_total = total;
    if (total < needed) {
        snprintf(err, err_cap, "inputs total %ld coin(s) but amount + fee = %ld coin(s)",
                 total, needed);
        return LT_ERR_INSUFFICIENT;
    }
    return LT_OK;
}

Status utxo_select_inputs(const UtxoSet *set, Transaction *tx, char *err, size_t err_cap)
{
    long total = 0, needed = tx_sender_debit(tx), owned = 0;
    size_t i;

    tx->input_count = 0;
    for (i = 0; i < set->count && total < needed; i++) {   /* oldest first */
        const Utxo *u = &set->items[i];

        if (u->spent || u->created_in == UTXO_PENDING || strcmp(u->owner, tx->from) != 0)
            continue;
        if (tx->input_count == TX_MAX_INPUTS) {
            snprintf(err, err_cap, "more than %d inputs would be needed", TX_MAX_INPUTS);
            tx->input_count = 0;
            return LT_ERR_INSUFFICIENT;
        }
        (void)str_copy(tx->inputs[tx->input_count].txid, HASH_HEX_LEN, u->txid);
        tx->inputs[tx->input_count].vout = u->vout;
        tx->input_count++;
        total += u->amount;
    }
    if (total < needed) {
        for (i = 0; i < set->count; i++) {
            const Utxo *u = &set->items[i];
            if (strcmp(u->owner, tx->from) == 0 && (!u->spent || u->spent_in == UTXO_PENDING) &&
                u->created_in != UTXO_PENDING)
                owned += u->amount;
        }
        snprintf(err, err_cap, "%s has %ld coin(s) in unspent outputs (%ld spendable now) "
                               "but needs %ld (amount %ld + fee %ld)",
                 tx->from, owned, total, needed, tx->amount, tx->fee);
        tx->input_count = 0;
        return LT_ERR_INSUFFICIENT;
    }
    return LT_OK;
}

Status utxo_apply(UtxoSet *set, const Transaction *tx, const char *txid,
                  int block_index, char *err, size_t err_cap)
{
    Transaction resolved;
    long input_total = 0, change;
    size_t i;
    Status st = LT_OK;

    if (!tx_moves_tokens(tx))
        return LT_OK;                     /* NONE, or a fine paid in cash */
    if (tx->type == TX_REWARD) {
        for (i = 0; i < tx->output_count && st == LT_OK; i++) {
            long credit = tx->outputs[i].amount - tx->fee;
            if (credit > 0)
                st = utxo_add(set, txid, (int)i, tx->outputs[i].to, credit, block_index);
        }
        return st;
    }

    /* TRANSFER or token FINE. Inputs chosen under the account model are
     * selected here, at confirmation time (oldest outputs first). */
    resolved = *tx;
    if (resolved.input_count == 0) {
        st = utxo_select_inputs(set, &resolved, err, err_cap);
        if (st != LT_OK)
            return st;
    }
    st = utxo_check_inputs(set, &resolved, &input_total, err, err_cap);
    if (st != LT_OK)
        return st;

    for (i = 0; i < resolved.input_count; i++) {
        Utxo *u = utxo_find_mut(set, resolved.inputs[i].txid, resolved.inputs[i].vout);
        u->spent = 1;
        u->spent_in = block_index;
    }
    st = utxo_add(set, txid, 0, resolved.to, resolved.amount, block_index);
    change = input_total - resolved.amount - resolved.fee;
    if (st == LT_OK && change > 0)
        st = utxo_add(set, txid, 1, resolved.from, change, block_index);
    return st;
}
