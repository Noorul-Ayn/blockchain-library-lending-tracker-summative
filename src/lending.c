/**
 * @file lending.c
 * @brief Lending rules, token rewards, transfers and block confirmation.
 *
 * Every state-changing action follows the same safe sequence:
 *   1. check permission   2. validate IDs against the registries
 *   3. verify the chain is intact   4. check the current state, which
 *      includes records still waiting in the pending pool
 *   5. create a signed record   6. add it to the pending pool and save
 */
#include "lending.h"

#include <stdio.h>
#include <string.h>

#include "storage.h"
#include "util.h"

/* ------------------------------------------------------------------------ */
/* Set-up                                                                   */
/* ------------------------------------------------------------------------ */

Status library_init(Library *lib, const char *data_dir, LedgerModel model)
{
    memset(lib, 0, sizeof *lib);
    if (str_copy(lib->data_dir, sizeof lib->data_dir, data_dir) != 0 ||
        path_join(lib->chain_path, sizeof lib->chain_path, data_dir, CHAIN_FILE) != 0 ||
        path_join(lib->pending_path, sizeof lib->pending_path, data_dir, PENDING_FILE) != 0) {
        fprintf(stderr, "ERROR: data directory path is too long.\n");
        return LT_ERR_INPUT;
    }
    chain_init(&lib->chain);
    chain_init(&lib->pending);
    keyring_init(&lib->keys, data_dir);
    ledger_init(&lib->ledger, model);
    lib->loan_period = DEFAULT_LOAN_PERIOD_SECONDS;
    lib->difficulty = DEFAULT_DIFFICULTY;
    lib->ledger_ok = 1;
    return LT_OK;
}

Status library_load_registries(Library *lib)
{
    char books_path[LT_PATH_MAX], members_path[LT_PATH_MAX];
    Status books_st, members_st;

    if (path_join(books_path, sizeof books_path, lib->data_dir, BOOKS_FILE) != 0 ||
        path_join(members_path, sizeof members_path, lib->data_dir, MEMBERS_FILE) != 0)
        return LT_ERR_INPUT;
    books_st = registry_load_books(books_path, &lib->books);
    members_st = registry_load_members(members_path, &lib->members);
    return (books_st != LT_OK) ? books_st : members_st;
}

static int same_signature(const Block *a, const Block *b)
{
    return a->signature_len == b->signature_len &&
           memcmp(a->signature, b->signature, a->signature_len) == 0;
}

Status library_load_state(Library *lib, int *need_genesis, char *err, size_t err_cap)
{
    Status st;
    size_t i, j;

    *need_genesis = 0;
    st = storage_load_chain(lib->chain_path, &lib->chain, err, err_cap);
    if (st == LT_ERR_NOT_FOUND) {
        *need_genesis = 1;
        st = LT_OK;
    }
    if (st != LT_OK)
        return st;
    st = storage_load_pending(lib->pending_path, &lib->pending, err, err_cap);
    if (st != LT_OK)
        return st;

    /* Drop pending records that were already confirmed. */
    for (i = 0; i < lib->pending.length;) {
        int duplicate = 0;
        for (j = 0; j < lib->chain.length && !duplicate; j++)
            duplicate = same_signature(&lib->pending.blocks[i], &lib->chain.blocks[j]);
        if (duplicate)
            chain_remove_at(&lib->pending, i);
        else
            i++;
    }
    return LT_OK;
}

Status library_rebuild_ledger(Library *lib)
{
    char err[200];
    size_t i;
    Status st = LT_OK;

    ledger_reset(&lib->ledger);
    lib->ledger_ok = 1;
    lib->ledger_error[0] = '\0';
    for (i = 0; i < lib->members.count && st == LT_OK; i++)
        st = ledger_add_account(&lib->ledger, lib->members.items[i].member_id);

    for (i = 0; i < lib->chain.length && st == LT_OK; i++) {
        const Block *b = &lib->chain.blocks[i];
        if (b->tx.type == TX_NONE)
            continue;
        st = ledger_apply(&lib->ledger, &b->tx, b->tx_id, (int)i, err, sizeof err);
        if (st != LT_OK)
            snprintf(lib->ledger_error, sizeof lib->ledger_error,
                     "block #%zu: %s", i, err);
    }
    if (st != LT_OK)
        lib->ledger_ok = 0;
    return st;
}

Status library_verify_ledger(const Library *lib, char *err, size_t err_cap,
                             size_t *transactions)
{
    Ledger temp;
    char why[200];
    size_t i;
    Status st = LT_OK;

    *transactions = 0;
    err[0] = '\0';
    ledger_init(&temp, lib->ledger.model);
    for (i = 0; i < lib->chain.length && st == LT_OK; i++) {
        const Block *b = &lib->chain.blocks[i];
        if (b->tx.type == TX_NONE)
            continue;
        st = ledger_apply(&temp, &b->tx, b->tx_id, (int)i, why, sizeof why);
        if (st == LT_OK)
            (*transactions)++;
        else
            snprintf(err, err_cap, "block #%zu: %s", i, why);
    }
    ledger_free(&temp);
    return st;
}

int library_chain_is_valid(Library *lib)
{
    return lib->ledger_ok && chain_validate(&lib->chain, &lib->keys, NULL, NULL);
}

Status library_save_pending(Library *lib)
{
    return storage_save_pending(lib->pending_path, &lib->pending);
}

void library_free(Library *lib)
{
    registry_free_books(&lib->books);
    registry_free_members(&lib->members);
    chain_free(&lib->chain);
    chain_free(&lib->pending);
    keyring_free(&lib->keys);
    ledger_free(&lib->ledger);
    auth_logout(&lib->session);
}

/** Adds a record to the pending pool and saves it (rolls back on failure). */
static Status add_pending(Library *lib, const Block *record)
{
    Status st = chain_push(&lib->pending, record);

    if (st != LT_OK)
        return st;
    st = library_save_pending(lib);
    if (st != LT_OK)
        chain_pop(&lib->pending, 1);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Lending                                                                  */
/* ------------------------------------------------------------------------ */

/** Latest lending event, looking at the pending pool first, then the chain. */
static const Block *latest_event(const Library *lib, const char *book_id)
{
    const Block *b = chain_find_latest_event(&lib->pending, book_id);
    return b ? b : chain_find_latest_event(&lib->chain, book_id);
}

static const Block *latest_borrow(const Library *lib, const char *book_id)
{
    const Block *b = chain_find_latest_borrow(&lib->pending, book_id);
    return b ? b : chain_find_latest_borrow(&lib->chain, book_id);
}

BookState lending_book_state(const Library *lib, const char *book_id, const Block **loan)
{
    const Block *latest = latest_event(lib, book_id);

    if (loan != NULL)
        *loan = NULL;
    if (latest == NULL || strcmp(latest->action, ACTION_RETURNED) == 0)
        return BOOK_AVAILABLE;
    if (loan != NULL)
        *loan = latest_borrow(lib, book_id);
    return strcmp(latest->action, ACTION_OVERDUE) == 0 ? BOOK_OVERDUE : BOOK_ON_LOAN;
}

Status lending_borrow(Library *lib, const char *book_id, const char *member_id)
{
    const Book *book;
    const Member *member;
    Block record;
    Status st;

    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;
    book = registry_find_book(&lib->books, book_id);
    member = registry_find_member(&lib->members, member_id);
    if (book == NULL || member == NULL)
        return LT_ERR_NOT_FOUND;
    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;
    if (lending_book_state(lib, book->book_id, NULL) != BOOK_AVAILABLE)
        return LT_ERR_ON_LOAN;

    st = block_create_record(&record, &lib->session, book->book_id, book->title,
                             member->member_id, member->full_name, ACTION_BORROWED, 0, NULL);
    return st == LT_OK ? add_pending(lib, &record) : st;
}

Status lending_return(Library *lib, const char *book_id, const char *member_id,
                      int *reward_out)
{
    const Book *book;
    const Member *member;
    const Block *loan = NULL;
    BookState state;
    Transaction tx;
    Block record;
    time_t now = time(NULL);
    int late, reward;
    long sequence_no;
    Status st;

    *reward_out = 0;
    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;
    book = registry_find_book(&lib->books, book_id);
    member = registry_find_member(&lib->members, member_id);
    if (book == NULL || member == NULL)
        return LT_ERR_NOT_FOUND;
    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;

    state = lending_book_state(lib, book->book_id, &loan);
    if (state == BOOK_AVAILABLE || loan == NULL)
        return LT_ERR_NOT_ON_LOAN;
    if (strcmp(loan->member_id, member->member_id) != 0)
        return LT_ERR_WRONG_MEMBER;

    /* Late = already marked OVERDUE, or returned after the due date. */
    late = (state == BOOK_OVERDUE) || difftime(now, loan->timestamp) > (double)lib->loan_period;
    reward = late ? REWARD_LATE : REWARD_ON_TIME;
    sequence_no = chain_count_rewards(&lib->chain) + chain_count_rewards(&lib->pending);
    tx_make_reward(&tx, member->member_id, reward, sequence_no, book->book_id, now);

    st = block_create_record(&record, &lib->session, book->book_id, book->title,
                             member->member_id, member->full_name, ACTION_RETURNED,
                             reward, &tx);
    if (st == LT_OK)
        st = add_pending(lib, &record);
    if (st == LT_OK)
        *reward_out = reward;
    return st;
}

Status lending_mark_overdue(Library *lib, time_t now, size_t *marked)
{
    size_t i, added = 0;
    Status st = LT_OK;

    *marked = 0;
    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;
    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;

    for (i = 0; i < lib->books.count && st == LT_OK; i++) {
        const Book *book = &lib->books.items[i];
        const Block *loan = NULL;
        const Member *member;
        char member_id[MEMBER_ID_LEN], member_name[MEMBER_NAME_LEN];
        Block record;

        if (lending_book_state(lib, book->book_id, &loan) != BOOK_ON_LOAN || loan == NULL)
            continue;
        if (difftime(now, loan->timestamp) <= (double)lib->loan_period)
            continue;
        /* Copy now: adding to the pool may move the block `loan` points to. */
        member = registry_find_member(&lib->members, loan->member_id);
        (void)str_copy(member_id, sizeof member_id, loan->member_id);
        (void)str_copy(member_name, sizeof member_name,
                       member != NULL ? member->full_name : loan->member_name);

        /* No transaction: a book that is not returned earns no tokens. */
        st = block_create_record(&record, &lib->session, book->book_id, book->title,
                                 member_id, member_name, ACTION_OVERDUE, 0, NULL);
        if (st == LT_OK)
            st = chain_push(&lib->pending, &record);
        if (st == LT_OK)
            added++;
    }
    if (st == LT_OK && added > 0)
        st = library_save_pending(lib);
    if (st != LT_OK) {
        chain_pop(&lib->pending, added);
        return st;
    }
    *marked = added;
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Tokens                                                                   */
/* ------------------------------------------------------------------------ */

long tokens_pending_debit(const Library *lib, const char *member_id, long *count)
{
    long debit = 0, n = 0;
    size_t i;

    for (i = 0; i < lib->pending.length; i++) {
        const Transaction *tx = &lib->pending.blocks[i].tx;
        if (tx->type == TX_TRANSFER && strcmp(tx->from, member_id) == 0) {
            debit += tx_sender_debit(tx);
            n++;
        }
    }
    if (count != NULL)
        *count = n;
    return debit;
}

long tokens_next_nonce(const Library *lib, const char *member_id)
{
    long pending = 0;

    (void)tokens_pending_debit(lib, member_id, &pending);
    return chain_count_outgoing(&lib->chain, member_id) + pending;
}

int tokens_is_reserved(const void *ctx, const char *txid, int vout)
{
    const Library *lib = ctx;
    size_t i, k;

    for (i = 0; i < lib->pending.length; i++) {
        const Transaction *tx = &lib->pending.blocks[i].tx;
        for (k = 0; tx->type == TX_TRANSFER && k < tx->input_count; k++) {
            if (tx->inputs[k].vout == vout && strcmp(tx->inputs[k].txid, txid) == 0)
                return 1;
        }
    }
    return 0;
}

Status tokens_transfer(Library *lib, const TransferRequest *req, Transaction *created,
                       long *change_out, char *err, size_t err_cap)
{
    const Member *sender, *recipient;
    Transaction tx;
    Block record;
    long input_total = 0;
    Status st;

    *change_out = 0;
    err[0] = '\0';
    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;
    sender = registry_find_member(&lib->members, req->from);
    recipient = registry_find_member(&lib->members, req->to);
    if (sender == NULL || recipient == NULL) {
        snprintf(err, err_cap, "sender and recipient must both be registered members");
        return LT_ERR_NOT_FOUND;
    }
    if (strcmp(sender->member_id, recipient->member_id) == 0 || req->amount < 1) {
        snprintf(err, err_cap, "the amount must be at least 1 and the recipient must differ "
                               "from the sender");
        return LT_ERR_INPUT;
    }
    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;

    if (lib->ledger.model == MODEL_ACCOUNT) {
        long pending_count = 0;
        long pending_debit = tokens_pending_debit(lib, sender->member_id, &pending_count);

        tx_make_transfer(&tx, sender->member_id, recipient->member_id, req->amount,
                         req->nonce, time(NULL));
        st = accounts_check_transfer(&lib->ledger.accounts, &tx, pending_debit,
                                     pending_count, err, err_cap);
    } else {
        tx_make_transfer(&tx, sender->member_id, recipient->member_id, req->amount,
                         tokens_next_nonce(lib, sender->member_id), time(NULL));
        if (req->input_count > 0) {
            tx.input_count = req->input_count;
            memcpy(tx.inputs, req->inputs, req->input_count * sizeof req->inputs[0]);
            st = LT_OK;
        } else {
            st = utxo_select_inputs(&lib->ledger.utxo, &tx, tokens_is_reserved, lib,
                                    err, err_cap);
        }
        if (st == LT_OK)
            st = utxo_check_inputs(&lib->ledger.utxo, &tx, tokens_is_reserved, lib,
                                   &input_total, err, err_cap);
        if (st == LT_OK)
            *change_out = input_total - tx.amount - tx.fee;
    }
    if (st != LT_OK)
        return st;

    st = block_create_record(&record, &lib->session, "-", "Token transfer",
                             sender->member_id, sender->full_name, ACTION_TRANSFER, 0, &tx);
    if (st == LT_OK)
        st = add_pending(lib, &record);
    if (st == LT_OK && created != NULL)
        *created = tx;
    return st;
}

/* ------------------------------------------------------------------------ */
/* Confirmation                                                             */
/* ------------------------------------------------------------------------ */

static void reject_first_pending(Library *lib)
{
    chain_remove_at(&lib->pending, 0);
    (void)library_save_pending(lib);
}

Status library_confirm(Library *lib, const Block *mined, char *err, size_t err_cap)
{
    const char *why = "";
    char computed[HASH_HEX_LEN];
    Status st;

    err[0] = '\0';
    if (lib->pending.length == 0)
        return LT_ERR_POOL_EMPTY;

    /* The mined block must be a correctly mined, untampered pending record. */
    if (block_verify_signature(mined, &lib->keys) != SIG_VALID) {
        snprintf(err, err_cap, "the record's signature is invalid (tampered pending block)");
        reject_first_pending(lib);
        return LT_ERR_CRYPTO;
    }
    if (!block_tx_consistent(mined, &why)) {
        snprintf(err, err_cap, "%s", why);
        reject_first_pending(lib);
        return LT_ERR_FORMAT;
    }
    if (block_compute_hash(mined, computed) != LT_OK || strcmp(computed, mined->hash) != 0 ||
        !pow_hash_meets(mined->hash, mined->difficulty) ||
        (size_t)mined->index != lib->chain.length) {
        snprintf(err, err_cap, "the proof-of-work or chain position is not valid");
        return LT_ERR_CHAIN_INVALID;
    }

    /* Apply the transaction: this is where balances change. */
    if (mined->tx.type != TX_NONE) {
        st = ledger_apply(&lib->ledger, &mined->tx, mined->tx_id, mined->index, err, err_cap);
        if (st != LT_OK) {
            reject_first_pending(lib);
            return st;
        }
    }

    st = chain_push(&lib->chain, mined);
    if (st == LT_OK)
        st = storage_save_chain(lib->chain_path, &lib->chain);
    if (st != LT_OK) {
        if (lib->chain.length > (size_t)mined->index)
            chain_pop(&lib->chain, 1);
        (void)library_rebuild_ledger(lib);
        snprintf(err, err_cap, "could not save the chain");
        return st;
    }
    chain_remove_at(&lib->pending, 0);
    return library_save_pending(lib);
}
