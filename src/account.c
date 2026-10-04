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

void accounts_reset(AccountTable *table)
{
    size_t i;

    for (i = 0; i < table->count; i++)
        free_history(&table->items[i]);
    table->count = 0;
}

void accounts_free(AccountTable *table)
{
    accounts_reset(table);
    free(table->items);
    accounts_init(table);
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

Status accounts_ensure(AccountTable *table, const char *id)
{
    Account *a;

    if (find_mut(table, id) != NULL)
        return LT_OK;
    if (table->count == table->capacity) {
        size_t new_cap = table->capacity ? table->capacity * 2 : ACCOUNTS_INITIAL_CAPACITY;
        Account *grown;

        if (new_cap > SIZE_MAX / sizeof *grown)
            return LT_ERR_MEMORY;
        grown = realloc(table->items, new_cap * sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        table->items = grown;
        table->capacity = new_cap;
    }
    a = &table->items[table->count++];
    memset(a, 0, sizeof *a);
    if (str_copy(a->id, sizeof a->id, id) != 0) {
        table->count--;
        return LT_ERR_INPUT;
    }
    return LT_OK;
}

/** Appends one history node at the tail of the account's linked list. */
static Status record_history(Account *account, const Transaction *tx, const char *txid,
                             int block_index)
{
    TxRecord *node = calloc(1, sizeof *node);

    if (node == NULL)
        return LT_ERR_MEMORY;
    (void)str_copy(node->txid, sizeof node->txid, txid);
    node->type = tx->type;
    (void)str_copy(node->sender, sizeof node->sender, tx->from);
    (void)str_copy(node->recipient, sizeof node->recipient, tx->to);
    node->amount = tx->amount;
    node->fee = tx->fee;
    node->nonce = tx->nonce;
    node->block_index = block_index;
    node->timestamp = tx->timestamp;
    node->next = NULL;

    if (account->history_tail == NULL)
        account->history_head = node;
    else
        account->history_tail->next = node;
    account->history_tail = node;
    account->history_len++;
    return LT_OK;
}

Status accounts_check_transfer(const AccountTable *table, const Transaction *tx,
                               long pending_debit, long pending_count,
                               char *err, size_t err_cap)
{
    const Account *sender = accounts_find(table, tx->from);
    long balance = sender ? sender->balance : 0;
    long nonce = sender ? sender->nonce : 0;
    long available = balance - pending_debit;
    long expected_nonce = nonce + pending_count;
    long needed = tx_sender_debit(tx);

    if (tx->nonce != expected_nonce) {
        if (tx->nonce < expected_nonce)
            snprintf(err, err_cap, "nonce %ld was already used by %s (expected %ld)",
                     tx->nonce, tx->from, expected_nonce);
        else
            snprintf(err, err_cap, "nonce %ld is out of order for %s (expected %ld)",
                     tx->nonce, tx->from, expected_nonce);
        return LT_ERR_NONCE;
    }
    if (available < needed) {
        snprintf(err, err_cap, "%s has %ld coin(s) available (%ld balance - %ld pending) but "
                               "needs %ld (amount %ld + fee %ld)",
                 tx->from, available, balance, pending_debit, needed, tx->amount, tx->fee);
        return LT_ERR_INSUFFICIENT;
    }
    return LT_OK;
}

Status accounts_apply(AccountTable *table, const Transaction *tx, const char *txid,
                      int block_index, char *err, size_t err_cap)
{
    Account *sender, *recipient;
    Status st;

    if (tx->type == TX_NONE)
        return LT_OK;

    /* Create both accounts first: creating one may move the array. */
    st = accounts_ensure(table, tx->to);
    if (st == LT_OK && tx->type == TX_TRANSFER)
        st = accounts_ensure(table, tx->from);
    if (st != LT_OK)
        return st;
    recipient = find_mut(table, tx->to);

    if (tx->type == TX_REWARD) {
        recipient->balance += tx_recipient_credit(tx);
        return record_history(recipient, tx, txid, block_index);
    }

    sender = find_mut(table, tx->from);
    st = accounts_check_transfer(table, tx, 0, 0, err, err_cap);
    if (st != LT_OK)
        return st;
    sender->balance -= tx_sender_debit(tx);
    sender->nonce++;
    recipient->balance += tx_recipient_credit(tx);
    st = record_history(sender, tx, txid, block_index);
    if (st == LT_OK)
        st = record_history(recipient, tx, txid, block_index);
    return st;
}
