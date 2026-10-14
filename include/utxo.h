/**
 * @file utxo.h
 * @brief UTXO (unspent transaction output) ledger.
 *
 * Coins exist only as outputs of confirmed transactions. A member's balance
 * is the sum of the outputs they own that have not been spent. A transfer
 * spends whole outputs as its inputs; whatever the inputs hold beyond the
 * amount and the fee comes back to the sender as a change output.
 *
 * The same structure is used for the pending projection: transactions that
 * are still in the pending pool are applied with block_index = UTXO_PENDING,
 * so an output they spend is reported as "reserved by a pending transaction"
 * and cannot be spent twice before mining.
 */
#ifndef LT_UTXO_H
#define LT_UTXO_H

#include <stddef.h>

#include "common.h"
#include "transaction.h"

#define UTXO_PENDING (-1)    /* block index used for unconfirmed transactions */

typedef struct {
    char txid[HASH_HEX_LEN];      /* transaction that created the output */
    int  vout;                    /* output number within that transaction */
    char owner[ACCOUNT_ID_LEN];
    long amount;
    int  created_in;              /* block index, or UTXO_PENDING */
    int  spent;                   /* 1 once used as an input */
    int  spent_in;                /* block index that spent it, or UTXO_PENDING */
} Utxo;

/** All outputs ever created (spent ones are kept, flagged, for history). */
typedef struct {
    Utxo  *items;
    size_t count;
    size_t capacity;
} UtxoSet;

void utxo_init(UtxoSet *set);
void utxo_free(UtxoSet *set);
Status utxo_copy(UtxoSet *dst, const UtxoSet *src);

const Utxo *utxo_find(const UtxoSet *set, const char *txid, int vout);

/** Balance = sum of the owner's unspent outputs. */
long   utxo_balance(const UtxoSet *set, const char *owner);
size_t utxo_unspent_count(const UtxoSet *set, const char *owner /* NULL = all */);

/**
 * Validates the inputs of a transfer or token fine: each must exist, be
 * confirmed, unspent (not even by a pending transaction), belong to the
 * sender and appear only once; together they must cover amount + fee.
 */
Status utxo_check_inputs(const UtxoSet *set, const Transaction *tx, long *input_total,
                         char *err, size_t err_cap);

/** Chooses the sender's oldest spendable outputs until amount + fee is covered. */
Status utxo_select_inputs(const UtxoSet *set, Transaction *tx, char *err, size_t err_cap);

/**
 * Validates and applies a transaction: creates its outputs (reward outputs,
 * transfer output 0 to the recipient, output 1 = change) and marks its
 * inputs spent. Nothing changes if validation fails.
 */
Status utxo_apply(UtxoSet *set, const Transaction *tx, const char *txid,
                  int block_index, char *err, size_t err_cap);

#endif /* LT_UTXO_H */
