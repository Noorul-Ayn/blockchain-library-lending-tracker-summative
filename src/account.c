/**
 * @file account.c
 * @brief Account ledger: balances, nonces and linked-list histories.
 */
#include "account.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define ACCOUNTS_INITIAL_CAPACITY 16

void accounts_init(AccountTable *table)
{
    table->items = NULL;
    table->count = 0;
    table->capacity = 0;
}

static void free_history(Account *account)
{
    TxRecord *node = account->history_head;

    while (node != NULL) {
        TxRecord *next = node->next;
        free(node);
        node = next;
    }
    account->history_head = account->history_tail = NULL;
    account->history_len = 0;
}

void accounts_free(AccountTable *table)
{
    size_t i;

    for (i = 0; i < table->count; i++)
        free_history(&table->items[i]);
    free(table->items);
    accounts_init(table);
}

Status accounts_copy(AccountTable *dst, const AccountTable *src)
{
    size_t i;

    accounts_init(dst);
    if (src->count == 0)
        return LT_OK;
    dst->items = malloc(src->count * sizeof *dst->items);
    if (dst->items == NULL)
        return LT_ERR_MEMORY;
    for (i = 0; i < src->count; i++) {
        dst->items[i] = src->items[i];
        dst->items[i].history_head = dst->items[i].history_tail = NULL;
        dst->items[i].history_len = 0;
    }
    dst->count = dst->capacity = src->count;
    return LT_OK;
}

static Account *find_mut(AccountTable *table, const char *id)
{
    size_t i;

    for (i = 0; i < table->count; i++) {
        if (strcmp(table->items[i].id, id) == 0)
            return &table->items[i];
    }
    return NULL;
}

const Account *accounts_find(const AccountTable *table, const char *id)
{
    return find_mut((AccountTable *)table, id);
}

long accounts_balance(const AccountTable *table, const char *id)
{
    const Account *a = accounts_find(table, id);
    return a != NULL ? a->balance : 0;
}

long accounts_nonce(const AccountTable *table, const char *id)
{
    const Account *a = accounts_find(table, id);
    return a != NULL ? a->nonce : 0;
}

/** Returns the account, creating it with balance 0 and nonce 0 if needed. */
static Account *ensure(AccountTable *table, const char *id)
{
    Account *a = find_mut(table, id);

    if (a != NULL)
        return a;
    if (table->count == table->capacity) {
        size_t new_cap = table->capacity ? table->capacity * 2 : ACCOUNTS_INITIAL_CAPACITY;
        Account *grown;

        if (new_cap > SIZE_MAX / sizeof *grown)
            return NULL;
        grown = realloc(table->items, new_cap * sizeof *grown);
        if (grown == NULL)
            return NULL;
        table->items = grown;
        table->capacity = new_cap;
    }
    a = &table->items[table->count];
    memset(a, 0, sizeof *a);
    if (str_copy(a->id, sizeof a->id, id) != 0)
        return NULL;
    table->count++;
    return a;
}

/** Appends one history node at the tail of the account's linked list. */
static Status record_history(Account *account, TxType type, const char *sender,
                             const char *recipient, long amount, long fee, long nonce,
                             const char *txid, int block_index, time_t timestamp)
{
    TxRecord *node = calloc(1, sizeof *node);

    if (node == NULL)
        return LT_ERR_MEMORY;
    (void)str_copy(node->txid, sizeof node->txid, txid);
    node->type = type;
    (void)str_copy(node->sender, sizeof node->sender, sender);
    (void)str_copy(node->recipient, sizeof node->recipient, recipient);
    node->amount = amount;
    node->fee = fee;
    node->nonce = nonce;
    node->block_index = block_index;
    node->timestamp = timestamp;
    node->next = NULL;

    if (account->history_tail == NULL)
        account->history_head = node;
    else
        account->history_tail->next = node;
    account->history_tail = node;
    account->history_len++;
    return LT_OK;
}

Status accounts_check(const AccountTable *table, const Transaction *tx,
                      char *err, size_t err_cap)
{
    long balance = accounts_balance(table, tx->from);
    long expected = accounts_nonce(table, tx->from);
    long needed = tx_sender_debit(tx);

    if (tx->nonce != expected) {
        if (tx->nonce < expected)
            snprintf(err, err_cap, "account nonce %ld was already used by %s (expected %ld)",
                     tx->nonce, tx->from, expected);
        else
            snprintf(err, err_cap, "account nonce %ld is out of order for %s (expected %ld)",
                     tx->nonce, tx->from, expected);
        return LT_ERR_NONCE;
    }
    if (balance < needed) {
        snprintf(err, err_cap, "%s has %ld coin(s) available but needs %ld "
                               "(amount %ld + fee %ld)",
                 tx->from, balance, needed, tx->amount, tx->fee);
        return LT_ERR_INSUFFICIENT;
    }
    return LT_OK;
}

Status accounts_apply(AccountTable *table, const Transaction *tx, const char *txid,
                      int block_index, int keep_history, char *err, size_t err_cap)
{
    Account *sender, *recipient;
    size_t i;
    Status st;

    if (!tx_moves_tokens(tx))
        return LT_OK;

    if (tx->type == TX_REWARD) {
        for (i = 0; i < tx->output_count; i++) {
            const TxOutput *out = &tx->outputs[i];
            recipient = ensure(table, out->to);
            if (recipient == NULL)
                return LT_ERR_MEMORY;
            recipient->balance += out->amount - tx->fee;
            if (keep_history) {
                st = record_history(recipient, TX_REWARD, LIBRARY_ACCOUNT, out->to,
                                    out->amount, tx->fee, -1, txid, block_index,
                                    tx->timestamp);
                if (st != LT_OK)
                    return st;
            }
        }
        return LT_OK;
    }

    st = accounts_check(table, tx, err, err_cap);
    if (st != LT_OK)
        return st;
    /* Create both accounts first: creating one may move the array. */
    if (ensure(table, tx->to) == NULL || ensure(table, tx->from) == NULL)
        return LT_ERR_MEMORY;
    sender = find_mut(table, tx->from);
    recipient = find_mut(table, tx->to);
    sender->balance -= tx_sender_debit(tx);
    sender->nonce++;
    recipient->balance += tx->amount;
    if (!keep_history)
        return LT_OK;
    st = record_history(sender, tx->type, tx->from, tx->to, tx->amount, tx->fee, tx->nonce,
                        txid, block_index, tx->timestamp);
    if (st == LT_OK)
        st = record_history(recipient, tx->type, tx->from, tx->to, tx->amount, tx->fee,
                            tx->nonce, txid, block_index, tx->timestamp);
    return st;
}

Status accounts_use_nonce(AccountTable *table, const Transaction *tx, char *err, size_t err_cap)
{
    long expected = accounts_nonce(table, tx->from);
    Account *a;

    if (tx->nonce != expected) {
        snprintf(err, err_cap, "account nonce %ld %s for %s (expected %ld)", tx->nonce,
                 tx->nonce < expected ? "was already used" : "is out of order", tx->from,
                 expected);
        return LT_ERR_NONCE;
    }
    a = ensure(table, tx->from);
    if (a == NULL)
        return LT_ERR_MEMORY;
    a->nonce++;
    return LT_OK;
}
