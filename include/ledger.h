/**
 * @file ledger.h
 * @brief Selects and drives one of the two token ledger models.
 *
 * The model is chosen once per session (menu at start-up or --model) and
 * applies to every token transaction in that session. Balances are never
 * stored separately: at start-up the ledger is rebuilt by replaying every
 * transaction on the confirmed chain, so the chain is the single source of
 * truth and the same chain can be viewed under either model.
 */
#ifndef LT_LEDGER_H
#define LT_LEDGER_H

#include "account.h"
#include "common.h"
#include "transaction.h"
#include "utxo.h"

typedef enum {
    MODEL_UTXO    = 1,
    MODEL_ACCOUNT = 2
} LedgerModel;

typedef struct {
    LedgerModel  model;
    UtxoSet      utxo;       /* used when model == MODEL_UTXO    */
    AccountTable accounts;   /* used when model == MODEL_ACCOUNT */
} Ledger;

void ledger_init(Ledger *ledger, LedgerModel model);
void ledger_reset(Ledger *ledger);
void ledger_free(Ledger *ledger);

/** Registers a member account with balance 0 (account model only). */
Status ledger_add_account(Ledger *ledger, const char *id);

/** Validates and applies one confirmed transaction under the active model. */
Status ledger_apply(Ledger *ledger, const Transaction *tx, const char *txid,
                    int block_index, char *err, size_t err_cap);

long ledger_balance(const Ledger *ledger, const char *id);

const char *ledger_model_name(LedgerModel model);
int         ledger_parse_model(const char *text, LedgerModel *model);

#endif /* LT_LEDGER_H */
