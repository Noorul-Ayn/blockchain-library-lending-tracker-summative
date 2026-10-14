/**
 * @file account.h
 * @brief Account-based ledger: balances, account nonces and per-member
 *        transaction histories kept as singly linked lists.
 *
 * Each member (and the LIBRARY account) is an account with a balance and a
 * nonce that counts its confirmed outgoing token transactions. A transfer
 * must carry exactly the sender's next account nonce; a reused or skipped
 * nonce is rejected, which prevents replaying or reordering transfers.
 */
#ifndef LT_ACCOUNT_H
#define LT_ACCOUNT_H

#include <stddef.h>
#include <time.h>

#include "common.h"
#include "transaction.h"

/** One node of a member's transaction history (linked list). */
typedef struct TxRecord {
    char             txid[HASH_HEX_LEN];
    TxType           type;
    char             sender[ACCOUNT_ID_LEN];
    char             recipient[ACCOUNT_ID_LEN];
    long             amount;
    long             fee;
    long             nonce;           /* sender's account nonce (-1 for rewards) */
    int              block_index;
    time_t           timestamp;
    struct TxRecord *next;
} TxRecord;

typedef struct {
    char      id[ACCOUNT_ID_LEN];
    long      balance;
    long      nonce;               /* confirmed outgoing transactions */
    TxRecord *history_head;
    TxRecord *history_tail;
    size_t    history_len;
} Account;

typedef struct {
    Account *items;
    size_t   count;
    size_t   capacity;
} AccountTable;

void accounts_init(AccountTable *table);
void accounts_free(AccountTable *table);

/** Copies balances and nonces (not histories) - used for the pending projection. */
Status accounts_copy(AccountTable *dst, const AccountTable *src);

const Account *accounts_find(const AccountTable *table, const char *id);
long           accounts_balance(const AccountTable *table, const char *id);
long           accounts_nonce(const AccountTable *table, const char *id);

/** Checks nonce and balance for a transfer / token fine without applying it. */
Status accounts_check(const AccountTable *table, const Transaction *tx,
                      char *err, size_t err_cap);

/**
 * Validates and applies a transaction: debits the sender (amount + fee),
 * increments the sender's nonce, credits the recipient(s) and, if
 * keep_history is set, appends a TxRecord node to each account involved.
 */
Status accounts_apply(AccountTable *table, const Transaction *tx, const char *txid,
                      int block_index, int keep_history, char *err, size_t err_cap);

/**
 * Nonce bookkeeping only (used by the UTXO model, which keeps balances as
 * outputs but still enforces account nonces): checks that tx carries the
 * sender's next nonce and increments it.
 */
Status accounts_use_nonce(AccountTable *table, const Transaction *tx, char *err, size_t err_cap);

#endif /* LT_ACCOUNT_H */
