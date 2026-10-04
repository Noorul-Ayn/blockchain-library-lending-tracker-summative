/**
 * @file account.h
 * @brief Account-based ledger model.
 *
 * Every member is an account with a balance and a nonce. A confirmed
 * transaction debits and credits balances directly:
 *   REWARD   -> member balance += amount - fee
 *   TRANSFER -> sender -= amount + fee, recipient += amount, sender nonce++
 * A transfer must carry the sender's next nonce; a wrong or reused nonce
 * is rejected, which stops replayed or out-of-order transactions.
 *
 * Each account keeps its transaction history as a singly linked list in
 * memory (oldest first), recording sender, recipient, amount, fee, nonce.
 */
#ifndef LT_ACCOUNT_H
#define LT_ACCOUNT_H

#include <stddef.h>
#include <time.h>

#include "common.h"
#include "transaction.h"

/** One node of an account's transaction history (linked list). */
typedef struct TxRecord {
    char            txid[HASH_HEX_LEN];
    TxType          type;
    char            sender[ACCOUNT_ID_LEN];
    char            recipient[ACCOUNT_ID_LEN];
    long            amount;
    long            fee;
    long            nonce;
    int             block_index;
    time_t          timestamp;
    struct TxRecord *next;
} TxRecord;

typedef struct {
    char      id[ACCOUNT_ID_LEN];
    long      balance;
    long      nonce;            /* number of confirmed outgoing transactions */
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
void accounts_reset(AccountTable *table);     /* frees histories, keeps memory */
void accounts_free(AccountTable *table);

/** Creates the account (balance 0, nonce 0) if it does not exist yet. */
Status accounts_ensure(AccountTable *table, const char *id);

const Account *accounts_find(const AccountTable *table, const char *id);

/**
 * Checks a new transfer before it enters the pending pool.
 * pending_debit / pending_count describe the sender's transfers that are
 * already waiting in the pool, so the expected nonce is
 * account nonce + pending_count.
 * @return LT_OK, LT_ERR_INSUFFICIENT or LT_ERR_NONCE.
 */
Status accounts_check_transfer(const AccountTable *table, const Transaction *tx,
                               long pending_debit, long pending_count,
                               char *err, size_t err_cap);

/** Validates and applies a confirmed transaction, recording history. */
Status accounts_apply(AccountTable *table, const Transaction *tx, const char *txid,
                      int block_index, char *err, size_t err_cap);

#endif /* LT_ACCOUNT_H */
