/**
 * @file cmd_ledger.c
 * @brief CLI commands for token balances, transfers, the UTXO set, account
 *        nonces and per-member transaction histories.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "commands.h"
#include "ui.h"

/** Prints the outputs a pending transaction has reserved (UTXO model). */
static void print_pending_spends(const Library *lib, const char *owner)
{
    size_t i, j, n = 0;

    for (i = 0; i < lib->pool.count; i++) {
        const Transaction *tx = &lib->pool.items[i].rec.tx;
        if (!tx_moves_tokens(tx) || (owner != NULL && strcmp(tx->from, owner) != 0))
            continue;
        for (j = 0; j < tx->input_count; j++) {
            char sh[16];
            if (n++ == 0)
                printf("\nOutputs reserved by pending transactions (cannot be spent again):\n");
            printf("  %s:%d  by request %s (%s -> %s, %ld + %ld fee)\n",
                   short_hash(tx->inputs[j].txid, sh), tx->inputs[j].vout,
                   lib->pool.items[i].rec.record_id, tx->from, tx->to, tx->amount, tx->fee);
        }
    }
}

/**
 * Resolves "prefix:vout" (as shown by utxo_view) to a full output reference.
 * Unknown prefixes are passed on unchanged so the ledger reports them.
 */
static int parse_inputs(const Library *lib, char *text, TxInput *inputs, size_t *count)
{
    char *items[TX_MAX_INPUTS + 1];
    size_t n = str_split(text, ',', items, TX_MAX_INPUTS + 1), i, k;

    if (n == 0 || n > TX_MAX_INPUTS) {
        say_err("Give 1-%d inputs as txid:vout separated by commas.", TX_MAX_INPUTS);
        return 0;
    }
    for (i = 0; i < n; i++) {
        char *ref = str_trim(items[i]), *colon = strrchr(ref, ':');
        const UtxoSet *set = &lib->state.ledger.utxo;
        long vout;
        int found = 0;

        if (colon == NULL || parse_long(colon + 1, 0, 1000, &vout) != 0) {
            say_err("'%s' is not txid:vout (for example 3fa9c2d81b:0).", ref);
            return 0;
        }
        *colon = '\0';
        if (!is_hex_string(ref, strlen(ref)) || strlen(ref) < 6 || strlen(ref) >= HASH_HEX_LEN) {
            say_err("'%s' is not a transaction ID prefix (at least 6 hex characters).", ref);
            return 0;
        }
        for (k = 0; k < set->count; k++) {
            if (set->items[k].vout == (int)vout &&
                strncasecmp(set->items[k].txid, ref, strlen(ref)) == 0) {
                (void)str_copy(inputs[i].txid, HASH_HEX_LEN, set->items[k].txid);
                found = 1;
                break;
            }
        }
        if (!found)
            (void)str_copy(inputs[i].txid, HASH_HEX_LEN, ref);
        inputs[i].vout = (int)vout;
    }
    *count = n;
    return 1;
}

static void print_transfer_result(const Library *lib, const Request *req)
{
    const Transaction *tx = &req->rec.tx;
    size_t i;
    long total = 0;

    print_request_added(lib, req);
    printf("         %s -> %s: %ld coin(s) + %ld fee | account nonce %ld\n", tx->from, tx->to,
           tx->amount, tx->fee, tx->nonce);
    if (tx->input_count == 0) {
        printf("         Account model: %s's balance is debited %ld when the block is mined.\n",
               tx->from, tx_sender_debit(tx));
        return;
    }
    printf("         Inputs:");
    for (i = 0; i < tx->input_count; i++) {
        const Utxo *u = utxo_find(&lib->state.ledger.utxo, tx->inputs[i].txid, tx->inputs[i].vout);
        char sh[16];
        printf(" %s:%d (%ld)", short_hash(tx->inputs[i].txid, sh), tx->inputs[i].vout,
               u ? u->amount : 0);
        total += u ? u->amount : 0;
    }
    printf(" = %ld coin(s)\n", total);
    printf("         Outputs when mined: #0 %ld to %s", tx->amount, tx->to);
    if (total - tx->amount - tx->fee > 0)
        printf(", #1 change %ld back to %s", total - tx->amount - tx->fee, tx->from);
    printf(", fee %ld to the miner\n", tx->fee);
}

static void do_transfer(Library *lib, int argc, char **argv, int explicit_nonce)
{
    char b1[INPUT_MAX], b2[INPUT_MAX], b3[INPUT_MAX], b4[INPUT_MAX], err[400];
    const char *from, *to, *amount_text;
    TxInput inputs[TX_MAX_INPUTS];
    size_t input_count = 0;
    long amount, nonce = -1;
    Request req;
    Status st;

    if ((from = arg_or_prompt(argc, argv, 1, "From member ID: ", b1, sizeof b1)) == NULL ||
        (to = arg_or_prompt(argc, argv, 2, "To member ID: ", b2, sizeof b2)) == NULL ||
        (amount_text = arg_or_prompt(argc, argv, 3, "Amount (coins): ", b3, sizeof b3)) == NULL)
        return;
    if (parse_long(amount_text, 1, 1000000L, &amount) != 0) {
        say_err("The amount must be a positive whole number of coins.");
        return;
    }
    if (explicit_nonce) {
        const char *text = argc > 4 ? argv[4] : NULL;
        char prompt[96];

        LibraryState proj;
        long expected = ledger_account_nonce(&lib->state.ledger, from);

        if (library_project(lib, &proj) == LT_OK) {    /* includes pending transfers */
            expected = ledger_account_nonce(&proj.ledger, from);
            state_free(&proj);
        }
        snprintf(prompt, sizeof prompt, "Account nonce [Enter = next expected, %ld]: ",
                 expected);
        if (text == NULL && argc <= 3 && prompt_text(prompt, b4, sizeof b4) == 1)
            text = b4;
        if (text != NULL && parse_long(text, 0, 1000000L, &nonce) != 0) {
            say_err("The nonce must be a whole number >= 0.");
            return;
        }
    } else if (lib->model == MODEL_ACCOUNT && argc > 4) {
        say_info("Inputs are ignored in the account model: balances are debited directly.");
    } else if (lib->model == MODEL_UTXO) {
        const char *text = argc > 4 ? argv[4] : NULL;
        if (text == NULL && argc <= 3) {
            print_utxo_set(lib, from, "  ");
            if (prompt_text("Inputs txid:vout,... [Enter = choose automatically]: ", b4,
                            sizeof b4) == 1)
                text = b4;
        }
        if (text != NULL) {
            (void)str_copy(b4, sizeof b4, text);
            if (!parse_inputs(lib, b4, inputs, &input_count))
                return;
        }
    }
    st = library_transfer(lib, from, to, amount, inputs, input_count, nonce, &req, err,
                          sizeof err);
    if (st != LT_OK) {
        say_err("Transfer rejected: %s.", err);
        return;
    }
    print_transfer_result(lib, &req);
}

void cmd_token_transfer(Library *lib, int argc, char **argv)
{
    heading(lib->model == MODEL_UTXO ? "TOKEN TRANSFER (UTXO model)"
                                     : "TOKEN TRANSFER (account model)");
    do_transfer(lib, argc, argv, 0);
}

void cmd_account_transfer(Library *lib, int argc, char **argv)
{
    heading("ACCOUNT TRANSFER (with account nonce)");
    if (lib->model != MODEL_ACCOUNT) {
        say_err("This session uses the UTXO model, and the chosen model applies to every "
                "transaction. Use token_transfer, or restart with --model account.");
        return;
    }
    do_transfer(lib, argc, argv, 1);
}

void cmd_token_balance(Library *lib, int argc, char **argv)
{
    const char *only = argc > 1 ? argv[1] : NULL;

    heading("TOKEN BALANCES");
    if (only != NULL && registry_find_member(&lib->members, only) == NULL) {
        say_err("Member %s is not in the member registry.", only);
        return;
    }
    print_balances(lib, only);
    printf("\nEach member starts at 0 and earns coins only through confirmed returns "
           "(10 on time / 5 late, minus the %d-coin fee).\n", TX_FEE);
}

void cmd_utxo_view(Library *lib, int argc, char **argv)
{
    const char *only = argc > 1 ? argv[1] : NULL;

    heading("UTXO SET");
    if (lib->model != MODEL_UTXO) {
        say_info("This session uses the ACCOUNT model; balances are account values, not "
                 "outputs. Restart with --model utxo to see the UTXO set.");
        return;
    }
    if (only != NULL && registry_find_member(&lib->members, only) == NULL &&
        strcmp(only, LIBRARY_ACCOUNT) != 0) {
        say_err("Member %s is not in the member registry.", only);
        return;
    }
    print_utxo_set(lib, only, "");
    print_pending_spends(lib, only);
    if (only != NULL)
        printf("\nBalance of %s = sum of these outputs = %ld coin(s).\n", only,
               utxo_balance(&lib->state.ledger.utxo, only));
}

void cmd_account_balance(Library *lib, int argc, char **argv)
{
    const char *only = argc > 1 ? argv[1] : NULL;

    heading("ACCOUNT BALANCES");
    if (lib->model != MODEL_ACCOUNT) {
        say_info("This session uses the UTXO model (balances = unspent outputs). Restart with "
                 "--model account for account balances; showing UTXO balances instead.");
    }
    if (only != NULL && registry_find_member(&lib->members, only) == NULL) {
        say_err("Member %s is not in the member registry.", only);
        return;
    }
    print_balances(lib, only);
}

void cmd_account_nonce(Library *lib, int argc, char **argv)
{
    LibraryState proj;
    size_t i;
    const char *only = argc > 1 ? argv[1] : NULL;

    heading("ACCOUNT NONCES");
    if (only != NULL && registry_find_member(&lib->members, only) == NULL) {
        say_err("Member %s is not in the member registry.", only);
        return;
    }
    if (library_project(lib, &proj) != LT_OK)
        return;
    printf("%-9s %-24s %10s %15s\n", "Member", "Name", "Confirmed", "Next expected");
    rule('-');
    for (i = 0; i < lib->members.count; i++) {
        const Member *m = &lib->members.items[i];
        if (only != NULL && strcasecmp(only, m->member_id) != 0)
            continue;
        printf("%-9s %-24.24s %10ld %15ld\n", m->member_id, m->full_name,
               ledger_account_nonce(&lib->state.ledger, m->member_id),
               ledger_account_nonce(&proj.ledger, m->member_id));
    }
    printf("\nThe account nonce counts a member's confirmed OUTGOING token transactions\n"
           "(transfers and token fine payments). A transfer must carry the next expected\n"
           "nonce; a reused or skipped nonce is rejected.\n");
    state_free(&proj);
}

void cmd_transaction_history(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX];
    const char *id = arg_or_prompt(argc, argv, 1, "Member ID: ", buf, sizeof buf);
    const Member *m;
    const Account *a;
    const TxRecord *node;
    LibraryState temp;
    const AccountTable *table = &lib->state.ledger.accounts;
    int built = 0;
    size_t n = 0;

    heading("TRANSACTION HISTORY");
    if (id == NULL)
        return;
    m = registry_find_member(&lib->members, id);
    if (m == NULL) {
        say_err("Member %s is not in the member registry.", id);
        return;
    }
    if (lib->model != MODEL_ACCOUNT) {
        /* The linked-list history belongs to the account model: build one
         * from the chain for display (balances stay in the UTXO model). */
        StateContext ctx;
        long bad;
        char err[256];

        library_context(lib, &ctx);
        if (state_build(&temp, &ctx, &lib->chain, MODEL_ACCOUNT, 1, &bad, err, sizeof err) !=
            LT_OK) {
            say_err("Could not replay the chain: %s.", err);
            state_free(&temp);
            return;
        }
        built = 1;
        table = &temp.ledger.accounts;
        say_info("Session model is UTXO; history replayed from the chain into account form.");
    }
    a = accounts_find(table, m->member_id);
    printf("Member %s (%s) - linked list of confirmed transactions\n\n", m->member_id,
           m->full_name);
    printf("%-3s %-6s %-10s %-9s %-9s %-9s %7s %4s %6s  %s\n", "#", "Block", "Date", "Type",
           "Sender", "Recipient", "Amount", "Fee", "Nonce", "Tx id");
    rule('-');
    for (node = a ? a->history_head : NULL; node != NULL; node = node->next) {
        char date[16], sh[16], nonce[24];
        format_day(node->timestamp, date);
        if (node->nonce < 0)
            snprintf(nonce, sizeof nonce, "-");
        else
            snprintf(nonce, sizeof nonce, "%ld", node->nonce);
        printf("%-3zu #%-5d %-10s %-9s %-9s %-9s %7ld %4ld %6s  %s\n", ++n, node->block_index,
               date, tx_type_name(node->type), node->sender, node->recipient, node->amount,
               node->fee, nonce, short_hash(node->txid, sh));
    }
    if (n == 0)
        printf("(no confirmed transactions yet)\n");
    else
        printf("\nBalance %ld coin(s), account nonce %ld (outgoing transactions confirmed).\n",
               a->balance, a->nonce);
    if (built)
        state_free(&temp);
}
