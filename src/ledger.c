/**
 * @file ledger.c
 * @brief Dispatch between the UTXO and account-based ledger models.
 */
#include "ledger.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

void ledger_init(Ledger *ledger, LedgerModel model, int keep_history)
{
    ledger->model = model;
    ledger->keep_history = keep_history;
    utxo_init(&ledger->utxo);
    accounts_init(&ledger->accounts);
}

void ledger_free(Ledger *ledger)
{
    utxo_free(&ledger->utxo);
    accounts_free(&ledger->accounts);
}

Status ledger_copy(Ledger *dst, const Ledger *src)
{
    Status st;

    ledger_init(dst, src->model, 0);
    st = utxo_copy(&dst->utxo, &src->utxo);
    if (st == LT_OK)
        st = accounts_copy(&dst->accounts, &src->accounts);
    if (st != LT_OK)
        ledger_free(dst);
    return st;
}

Status ledger_check(const Ledger *ledger, Transaction *tx, char *err, size_t err_cap)
{
    long input_total = 0;
    long expected = accounts_nonce(&ledger->accounts, tx->from);
    Status st;

    if (!tx_moves_tokens(tx) || tx->type == TX_REWARD)
        return LT_OK;
    if (ledger->model == MODEL_ACCOUNT)
        return accounts_check(&ledger->accounts, tx, err, err_cap);

    /* UTXO model: the account nonce still has to be the next one. */
    if (tx->nonce != expected) {
        snprintf(err, err_cap, "account nonce %ld %s for %s (expected %ld)", tx->nonce,
                 tx->nonce < expected ? "was already used" : "is out of order", tx->from,
                 expected);
        return LT_ERR_NONCE;
    }
    if (tx->input_count == 0) {
        st = utxo_select_inputs(&ledger->utxo, tx, err, err_cap);
        if (st != LT_OK)
            return st;
    }
    return utxo_check_inputs(&ledger->utxo, tx, &input_total, err, err_cap);
}

Status ledger_apply(Ledger *ledger, const Transaction *tx, const char *txid,
                    int block_index, char *err, size_t err_cap)
{
    Status st;

    if (!tx_moves_tokens(tx))
        return LT_OK;
    if (ledger->model == MODEL_ACCOUNT)
        return accounts_apply(&ledger->accounts, tx, txid, block_index, ledger->keep_history,
                              err, err_cap);

    if (tx->type != TX_REWARD) {
        long expected = accounts_nonce(&ledger->accounts, tx->from);
        if (tx->nonce != expected) {
            snprintf(err, err_cap, "account nonce %ld %s for %s (expected %ld)", tx->nonce,
                     tx->nonce < expected ? "was already used" : "is out of order", tx->from,
                     expected);
            return LT_ERR_NONCE;
        }
    }
    st = utxo_apply(&ledger->utxo, tx, txid, block_index, err, err_cap);
    if (st == LT_OK && tx->type != TX_REWARD)
        st = accounts_use_nonce(&ledger->accounts, tx, err, err_cap);
    return st;
}

long ledger_balance(const Ledger *ledger, const char *account)
{
    if (ledger->model == MODEL_ACCOUNT)
        return accounts_balance(&ledger->accounts, account);
    return utxo_balance(&ledger->utxo, account);
}

long ledger_account_nonce(const Ledger *ledger, const char *account)
{
    return accounts_nonce(&ledger->accounts, account);
}

const char *ledger_model_name(LedgerModel model)
{
    return model == MODEL_ACCOUNT ? "ACCOUNT" : "UTXO";
}

int ledger_parse_model(const char *text, LedgerModel *model)
{
    if (strcasecmp(text, "utxo") == 0 || strcmp(text, "1") == 0) {
        *model = MODEL_UTXO;
        return 0;
    }
    if (strcasecmp(text, "account") == 0 || strcmp(text, "2") == 0) {
        *model = MODEL_ACCOUNT;
        return 0;
    }
    return -1;
}
