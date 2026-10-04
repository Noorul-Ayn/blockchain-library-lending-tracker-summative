/**
 * @file ledger.c
 * @brief Thin dispatcher between the UTXO and account-based models.
 */
#include "ledger.h"

#include <string.h>
#include <strings.h>

void ledger_init(Ledger *ledger, LedgerModel model)
{
    ledger->model = model;
    utxo_init(&ledger->utxo);
    accounts_init(&ledger->accounts);
}

void ledger_reset(Ledger *ledger)
{
    utxo_reset(&ledger->utxo);
    accounts_reset(&ledger->accounts);
}

void ledger_free(Ledger *ledger)
{
    utxo_free(&ledger->utxo);
    accounts_free(&ledger->accounts);
}

Status ledger_add_account(Ledger *ledger, const char *id)
{
    return ledger->model == MODEL_ACCOUNT ? accounts_ensure(&ledger->accounts, id) : LT_OK;
}

Status ledger_apply(Ledger *ledger, const Transaction *tx, const char *txid,
                    int block_index, char *err, size_t err_cap)
{
    if (ledger->model == MODEL_UTXO)
        return utxo_apply(&ledger->utxo, tx, txid, block_index, err, err_cap);
    return accounts_apply(&ledger->accounts, tx, txid, block_index, err, err_cap);
}

long ledger_balance(const Ledger *ledger, const char *id)
{
    const Account *a;

    if (ledger->model == MODEL_UTXO)
        return utxo_balance(&ledger->utxo, id);
    a = accounts_find(&ledger->accounts, id);
    return a ? a->balance : 0;
}

const char *ledger_model_name(LedgerModel model)
{
    return model == MODEL_UTXO ? "UTXO" : "ACCOUNT";
}

int ledger_parse_model(const char *text, LedgerModel *model)
{
    if (strcasecmp(text, "utxo") == 0 || strcmp(text, "1") == 0) {
        *model = MODEL_UTXO;
        return 0;
    }
    if (strcasecmp(text, "account") == 0 || strcasecmp(text, "accounts") == 0 ||
        strcmp(text, "2") == 0) {
        *model = MODEL_ACCOUNT;
        return 0;
    }
    return -1;
}
