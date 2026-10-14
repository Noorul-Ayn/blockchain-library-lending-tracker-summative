/**
 * @file ledger.h
 * @brief Selects the UTXO or account model for a session.
 *
 * Both models read the same chain: transactions are stored in a model-neutral
 * form, and balances are rebuilt by replaying every confirmed transaction
 * into the model chosen at start-up. The chosen model then validates every
 * new token transaction in that session.
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
    UtxoSet      utxo;       /* UTXO model: the coins                       */
    AccountTable accounts;   /* account model: balances + nonces + history;
                                UTXO model: account nonces only            */
    int          keep_history;
} Ledger;

void   ledger_init(Ledger *ledger, LedgerModel model, int keep_history);
void   ledger_free(Ledger *ledger);
Status ledger_copy(Ledger *dst, const Ledger *src);

/**
 * Checks a new transfer / token fine against the ledger without applying
 * it. Under the UTXO model, a transaction without inputs gets the sender's
 * oldest spendable outputs selected (written back into *tx).
 */
Status ledger_check(const Ledger *ledger, Transaction *tx, char *err, size_t err_cap);

/** Validates and applies a transaction. Nothing changes if it is invalid. */
Status ledger_apply(Ledger *ledger, const Transaction *tx, const char *txid,
                    int block_index, char *err, size_t err_cap);

long        ledger_balance(const Ledger *ledger, const char *account);
long        ledger_account_nonce(const Ledger *ledger, const char *account);
const char *ledger_model_name(LedgerModel model);
int         ledger_parse_model(const char *text, LedgerModel *model);   /* 0 = ok */

#endif /* LT_LEDGER_H */
