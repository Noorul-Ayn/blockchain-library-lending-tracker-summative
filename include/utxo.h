/**
 * @file utxo.h
 * @brief UTXO (unspent transaction output) ledger model.
 *
 * Every confirmed transaction creates outputs ("coins") owned by a member:
 *   REWARD   -> vout 0: member receives amount - fee
 *   TRANSFER -> vout 0: recipient receives amount
 *               vout 1: change back to the sender (inputs - amount - fee)
 * A transfer spends whole previous outputs as its inputs. A member's
 * balance is the sum of the unspent outputs they own.
 *
 * Double spending is prevented in three places:
 *   - an output can only be spent once (spent flag, checked on confirm),
 *   - an output already referenced by a pending transaction is reserved
 *     and cannot be used by a second pending transaction,
 *   - replaying the chain re-checks every input, so a double spend written
 *     into chain.dat by hand is detected.
 */
#ifndef LT_UTXO_H
#define LT_UTXO_H

#include <stddef.h>

#include "common.h"
#include "transaction.h"

typedef struct {
    char txid[HASH_HEX_LEN];      /* transaction that created the output */
    int  vout;                    /* output number within that transaction */
    char owner[ACCOUNT_ID_LEN];
    long amount;
    int  created_in;              /* block index */
    int  spent;                   /* 1 once used as an input */
    int  spent_in;                /* block index that spent it */
} Utxo;

/** All outputs ever created (spent ones are kept, flagged, for history). */
typedef struct {
    Utxo  *items;
    size_t count;
    size_t capacity;
} UtxoSet;

/** Callback: is this output reserved by a pending (unconfirmed) transaction? */
typedef int (*UtxoReservedFn)(const void *ctx, const char *txid, int vout);

void utxo_init(UtxoSet *set);
void utxo_reset(UtxoSet *set);
void utxo_free(UtxoSet *set);

const Utxo *utxo_find(const UtxoSet *set, const char *txid, int vout);

/** Balance = sum of the owner's unspent outputs. */
long   utxo_balance(const UtxoSet *set, const char *owner);
size_t utxo_unspent_count(const UtxoSet *set, const char *owner /* NULL = all */);

/**
 * Validates the inputs of a transfer: each must exist, be unspent, belong
 * to the sender, appear only once and (if reserved != NULL) not be reserved
 * by a pending transaction; together they must cover amount + fee.
 * @return LT_OK, LT_ERR_NOT_FOUND, LT_ERR_DOUBLE_SPEND, LT_ERR_DENIED
 *         (not the sender's output) or LT_ERR_INSUFFICIENT.
 */
Status utxo_check_inputs(const UtxoSet *set, const Transaction *tx,
                         UtxoReservedFn reserved, const void *ctx,
                         long *input_total, char *err, size_t err_cap);

/** Chooses the sender's oldest spendable outputs until amount + fee is covered. */
Status utxo_select_inputs(const UtxoSet *set, Transaction *tx,
                          UtxoReservedFn reserved, const void *ctx,
                          char *err, size_t err_cap);

/** Validates and applies a confirmed transaction (creates / spends outputs). */
Status utxo_apply(UtxoSet *set, const Transaction *tx, const char *txid,
                  int block_index, char *err, size_t err_cap);

#endif /* LT_UTXO_H */
