/**
 * @file library.c
 * @brief Lending operations, request submission (nonce, signature, fraud
 *        heuristics), pool pruning, block assembly, confirmation and
 *        whole-system validation.
 */
#include "library.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "crypto.h"
#include "util.h"

#define FAIL(code, ...) do { snprintf(err, err_cap, __VA_ARGS__); st = (code); goto done; } while (0)

/* ------------------------------------------------------------------------ */
/* Set-up, loading and saving                                               */
/* ------------------------------------------------------------------------ */

void library_init(Library *lib, const char *data_dir)
{
    memset(lib, 0, sizeof *lib);
    (void)str_copy(lib->data_dir, sizeof lib->data_dir, data_dir);
    (void)path_join(lib->books_path, sizeof lib->books_path, data_dir, BOOKS_FILE);
    (void)path_join(lib->copies_path, sizeof lib->copies_path, data_dir, COPIES_FILE);
    (void)path_join(lib->members_path, sizeof lib->members_path, data_dir, MEMBERS_FILE);
    (void)path_join(lib->chain_path, sizeof lib->chain_path, data_dir, CHAIN_FILE);
    (void)path_join(lib->pool_path, sizeof lib->pool_path, data_dir, PENDING_FILE);
    (void)path_join(lib->state_path, sizeof lib->state_path, data_dir, STATE_FILE);
    chain_init(&lib->chain);
    pool_init(&lib->pool);
    keydir_init(&lib->keys, data_dir);
    lib->model = MODEL_UTXO;
    lib->rules.loan_days = DEFAULT_LOAN_DAYS;
    lib->rules.renewal_days = DEFAULT_RENEWAL_DAYS;
    lib->rules.max_renewals = DEFAULT_MAX_RENEWALS;
    lib->rules.max_loans = DEFAULT_MAX_LOANS;
    lib->difficulty = DEFAULT_DIFFICULTY;
    lib->block_reward = DEFAULT_BLOCK_REWARD;
    lib->block_capacity = DEFAULT_BLOCK_CAPACITY;
}

void library_free(Library *lib)
{
    registry_free_books(&lib->books);
    registry_free_copies(&lib->copies);
    registry_free_members(&lib->members);
    chain_free(&lib->chain);
    pool_free(&lib->pool);
    keydir_free(&lib->keys);
    state_free(&lib->state);
    auth_logout(&lib->session);   /* frees the signing key, wipes the vault key */
}

Status library_load_registries(Library *lib)
{
    Status st = registry_load_books(lib->books_path, &lib->books);

    if (st == LT_OK)
        st = registry_load_members(lib->members_path, &lib->members);
    if (st == LT_OK)
        st = registry_load_copies(lib->copies_path, &lib->books, &lib->copies);
    return st;
}

void library_context(const Library *lib, StateContext *ctx)
{
    ctx->books = &lib->books;
    ctx->copies = &lib->copies;
    ctx->members = &lib->members;
    ctx->rules = &lib->rules;
}

StateMeta library_meta(const Library *lib)
{
    StateMeta m;
    const Block *tip = chain_tip(&lib->chain);

    memset(&m, 0, sizeof m);
    m.difficulty = lib->difficulty;
    m.block_reward = lib->block_reward;
    m.block_capacity = lib->block_capacity;
    m.clock_offset = clock_offset();
    m.rules = lib->rules;
    m.chain_length = lib->chain.length;
    if (tip != NULL)
        (void)str_copy(m.tip_hash, sizeof m.tip_hash, tip->hash);
    else
        zero_hash(m.tip_hash);
    m.model = lib->model;
    m.present = 1;
    return m;
}

Status library_load_files(Library *lib, int *needs_genesis, char *err, size_t err_cap)
{
    StateMeta meta;
    Status st;

    *needs_genesis = 0;
    err[0] = '\0';
    chain_free(&lib->chain);
    pool_free(&lib->pool);

    /* Settings saved by the last session (difficulty, rules, clock). */
    memset(&meta, 0, sizeof meta);
    meta.difficulty = lib->difficulty;
    meta.block_reward = lib->block_reward;
    meta.block_capacity = lib->block_capacity;
    meta.rules = lib->rules;
    meta.model = lib->model;
    if (storage_load_state(lib->state_path, &meta, NULL, NULL, NULL, 0) == LT_OK) {
        lib->difficulty = meta.difficulty;
        lib->block_reward = meta.block_reward;
        lib->block_capacity = meta.block_capacity;
        lib->rules = meta.rules;
        clock_set_offset(meta.clock_offset);
    }

    st = storage_load_chain(lib->chain_path, &lib->chain, err, err_cap);
    if (st == LT_OK)
        st = storage_load_pool(lib->pool_path, &lib->pool, err, err_cap);
    if (st == LT_OK && lib->chain.length == 0)
        *needs_genesis = 1;
    lib->validated = 0;          /* a freshly loaded chain must be validated */
    lib->chain_ok = 0;
    return st;
}

Status library_create_genesis(Library *lib)
{
    Status st = chain_create_genesis(&lib->chain, lib->difficulty, lib_now());

    if (st == LT_OK)
        st = storage_save_chain(lib->chain_path, &lib->chain);
    return st;
}

Status library_rebuild_state(Library *lib)
{
    StateContext ctx;
    long bad = -1;
    Status st;

    library_context(lib, &ctx);
    state_free(&lib->state);
    st = state_build(&lib->state, &ctx, &lib->chain, lib->model, lib->model == MODEL_ACCOUNT,
                     &bad, lib->state_error, sizeof lib->state_error);
    lib->state_ok = st == LT_OK;
    return st;
}

Status library_save_pool(Library *lib)
{
    return storage_save_pool(lib->pool_path, &lib->pool);
}

Status library_save_state(Library *lib)
{
    StateMeta meta = library_meta(lib);
    return storage_save_state(lib->state_path, &meta, &lib->state);
}

Status library_save_all(Library *lib)
{
    Status st = storage_save_chain(lib->chain_path, &lib->chain);

    if (st == LT_OK)
        st = library_save_pool(lib);
    if (st == LT_OK)
        st = library_save_state(lib);
    return st;
}

Status library_project(const Library *lib, LibraryState *proj)
{
    StateContext ctx;
    size_t i;
    Status st;

    library_context(lib, &ctx);
    st = state_clone(proj, &lib->state);
    if (st != LT_OK)
        return st;
    /* Arrival order = the order in which each request was validated. A
     * request that no longer applies is skipped (library_prune removes it). */
    for (i = 0; i < lib->pool.count; i++) {
        char why[256];
        (void)state_apply_record(proj, &ctx, &lib->pool.items[i].rec, STATE_PENDING, why,
                                 sizeof why);
    }
    return LT_OK;
}

Status library_ensure_member_keys(Library *lib, size_t *created)
{
    size_t i;
    Status st = LT_OK;

    *created = 0;
    if (!lib->session.vault_unlocked)
        return LT_ERR_AUTH;
    for (i = 0; i < lib->members.count && st == LT_OK; i++) {
        const char *id = lib->members.items[i].member_id;
        if (member_key_exists(lib->data_dir, id))
            continue;
        st = member_key_create(lib->data_dir, lib->session.vault_key, id);
        if (st == LT_OK) {
            keydir_forget(&lib->keys, id);   /* drop a cached "no key" entry */
            (*created)++;
        }
    }
    return st;
}

/* ------------------------------------------------------------------------ */
/* Registration                                                             */
/* ------------------------------------------------------------------------ */

Status library_register_member(Library *lib, const char *id, const char *name,
                               const char *course, const char **why)
{
    Status st;

    if (!lib->session.vault_unlocked) {
        *why = "the key vault is locked (log in first)";
        return LT_ERR_AUTH;
    }
    st = registry_add_member(lib->members_path, &lib->members, id, name, course, why);
    if (st != LT_OK)
        return st;
    /* Every member gets an ECDSA key pair as soon as they are registered. */
    id = lib->members.items[lib->members.count - 1].member_id;
    if (!member_key_exists(lib->data_dir, id))
        st = member_key_create(lib->data_dir, lib->session.vault_key, id);
    keydir_forget(&lib->keys, id);
    if (st != LT_OK)
        *why = "the member was saved but the key pair could not be created";
    return st;
}

Status library_register_book(Library *lib, const char *id, const char *title,
                             const char *author, const char **why)
{
    return registry_add_book(lib->books_path, &lib->books, id, title, author, why);
}

Status library_add_copy(Library *lib, const char *copy_id, const char *book_id,
                        Condition condition, char out_id[COPY_ID_LEN], const char **why)
{
    const Book *book = registry_find_book(&lib->books, book_id);
    char id[COPY_ID_LEN];
    Status st;

    *why = NULL;
    if (book == NULL) {
        *why = "the book ID is not in books.txt";
        return LT_ERR_NOT_FOUND;
    }
    if (copy_id == NULL || copy_id[0] == '\0')
        registry_next_copy_id(&lib->copies, book->book_id, id);
    else if (str_copy(id, sizeof id, copy_id) != 0) {
        *why = "copy ID is too long";
        return LT_ERR_INPUT;
    }
    st = registry_add_copy(lib->copies_path, &lib->copies, &lib->books, id, book->book_id,
                           condition, why);
    if (st != LT_OK)
        return st;
    (void)str_copy(out_id, COPY_ID_LEN, id);
    /* The inventory is derived from copies.txt + the chain: rebuild it. */
    st = library_rebuild_state(lib);
    if (st == LT_OK)
        st = library_save_state(lib);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Request submission                                                       */
/* ------------------------------------------------------------------------ */

/** The staff signer ID of the logged-in user, e.g. "staff:admin". */
static void staff_signer(const Library *lib, char out[SIGNER_ID_LEN])
{
    signer_id_for_staff(lib->session.username, out);
}

/**
 * Private key for a signer: the logged-in librarian's own key, or a
 * member's key decrypted from the vault. *owned tells the caller whether it
 * must free the key. @return NULL if this session cannot sign for them.
 */
static EVP_PKEY *signing_key_for(Library *lib, const char *signer_id, int *owned)
{
    char me[SIGNER_ID_LEN];

    *owned = 0;
    if (!auth_is_logged_in(&lib->session))
        return NULL;
    if (signer_is_staff(signer_id)) {
        staff_signer(lib, me);
        return strcmp(me, signer_id) == 0 ? lib->session.signing_key : NULL;
    }
    if (!lib->session.vault_unlocked)
        return NULL;
    *owned = 1;
    return member_key_load_private(lib->data_dir, lib->session.vault_key, signer_id);
}

static void release_key(EVP_PKEY *key, int owned)
{
    if (owned)
        EVP_PKEY_free(key);
}

/**
 * Pool ordering of a request (see pool.h): overdue-related requests get
 * PRIORITY_OVERDUE; reservations and borrows of a copy that was held for a
 * reservation are ordered by the reservation date.
 */
static void request_order(LibraryState *proj, const Record *rec, int *priority,
                          time_t *sort_time)
{
    const CopyStatus *c;

    *priority = PRIORITY_NORMAL;
    *sort_time = rec->timestamp;
    switch (rec->action) {
    case ACT_OVERDUE:
    case ACT_FINE:
        *priority = PRIORITY_OVERDUE;
        break;
    case ACT_RETURN:
        if (rec->timestamp > rec->due_date)
            *priority = PRIORITY_OVERDUE;     /* return of an overdue copy */
        break;
    case ACT_BORROW:
        c = state_copy(proj, rec->copy_id);
        if (c != NULL && c->state == COPY_RESERVED && c->hold_reserved_at > 0 &&
            strcasecmp(c->current_holder_id, rec->member_id) == 0)
            *sort_time = c->hold_reserved_at;
        break;
    default:
        break;
    }
}

/** Fraud heuristics, evaluated against the projected state BEFORE applying. */
static unsigned fraud_flags(const Library *lib, LibraryState *proj, const Record *rec)
{
    unsigned flags = 0;

    if (chain_find_record(&lib->chain, rec->record_id, NULL, NULL) != NULL ||
        pool_contains_id(&lib->pool, rec->record_id))
        flags |= FLAG_DUPLICATE;
    if (rec->action == ACT_BORROW) {
        time_t last = state_last_return(proj, rec->member_id, rec->book_id);
        if (state_loans(proj, rec->member_id) + 1 > (size_t)lib->rules.max_loans)
            flags |= FLAG_EXCESS_LOANS;
        if (last > 0 && rec->timestamp - last < REBORROW_WINDOW_SECONDS)
            flags |= FLAG_RAPID_REBORROW;
    }
    if (rec->action == ACT_RETURN) {
        const CopyStatus *c = state_copy(proj, rec->copy_id);
        if (c != NULL && (int)rec->condition - (int)c->condition > 1 &&
            strcmp(rec->reason, "-") == 0)
            flags |= FLAG_CONDITION;
    }
    return flags;
}

/**
 * The common path for every new request:
 *   nonce -> request ID -> ledger check (token records) -> fraud heuristics
 *   -> rule check against the projection -> ECDSA signature -> verification
 *   -> pending pool (PENDING or SUSPICIOUS) -> pending.dat.
 * proj must be the current projection; on success the request is applied
 * to it, so several requests can be submitted with one projection.
 */
static Status submit_request(Library *lib, LibraryState *proj, Record *rec, Request *out,
                             char *err, size_t err_cap)
{
    StateContext ctx;
    Request req;
    EVP_PKEY *key = NULL;
    SigCheck sig;
    unsigned flags;
    int owned = 0, priority;
    time_t sort_time;
    Status st;

    library_context(lib, &ctx);
    err[0] = '\0';

    /* 1. Replay protection: the signer's next nonce (confirmed + pending). */
    rec->nonce = state_nonce(proj, rec->signer_id);
    st = record_new_id(rec);
    if (st != LT_OK)
        FAIL(st, "could not create a request ID");

    /* 2. Token records: account nonce, balance / UTXO inputs. */
    if (tx_moves_tokens(&rec->tx)) {
        st = ledger_check(&proj->ledger, &rec->tx, err, err_cap);
        if (st != LT_OK)
            goto done;
    }

    /* 3. Fraud heuristics and pool ordering (on the state before this request). */
    flags = fraud_flags(lib, proj, rec);
    request_order(proj, rec, &priority, &sort_time);

    /* 4. Every business rule, against the projected state. */
    st = state_apply_record(proj, &ctx, rec, STATE_PENDING, err, err_cap);
    if (st != LT_OK)
        goto done;

    /* 5. Sign with the signer's private key, then verify the signature
     *    against the signer's registered public key. */
    key = signing_key_for(lib, rec->signer_id, &owned);
    if (key == NULL)
        FAIL(LT_ERR_SIGNATURE, "no private key available to sign for %s", rec->signer_id);
    st = record_sign(rec, key);
    release_key(key, owned);
    if (st != LT_OK)
        FAIL(st, "ECDSA signing failed");
    sig = record_verify(rec, &lib->keys);
    if (sig != SIG_VALID)
        FAIL(LT_ERR_SIGNATURE, "signature verification failed (%s)", sig_check_name(sig));

    /* 6. Into the pending pool. */
    memset(&req, 0, sizeof req);
    req.rec = *rec;
    req.flags = flags;
    req.status = flags ? REQ_SUSPICIOUS : REQ_PENDING;
    req.priority = priority;
    req.sort_time = sort_time;
    st = pool_add(&lib->pool, &req);
    if (st == LT_OK)
        st = library_save_pool(lib);
    if (st != LT_OK)
        FAIL(st, "could not save the pending pool");
    if (out != NULL)
        *out = lib->pool.items[lib->pool.count - 1];
done:
    return st;
}

/* ------------------------------------------------------------------------ */
/* Lending operations                                                       */
/* ------------------------------------------------------------------------ */

/** Fills the registry-derived fields of a lending record. */
static void fill_record(Record *rec, Action action, const Book *book, const char *copy_id,
                        const Member *member, time_t now)
{
    record_clear(rec);
    rec->timestamp = now;
    rec->action = action;
    if (book != NULL) {
        (void)str_copy(rec->book_id, sizeof rec->book_id, book->book_id);
        (void)str_copy(rec->book_title, sizeof rec->book_title, book->title);
    }
    if (copy_id != NULL)
        (void)str_copy(rec->copy_id, sizeof rec->copy_id, copy_id);
    if (member != NULL) {
        (void)str_copy(rec->member_id, sizeof rec->member_id, member->member_id);
        (void)str_copy(rec->member_name, sizeof rec->member_name, member->full_name);
        (void)str_copy(rec->signer_id, sizeof rec->signer_id, member->member_id);
    }
}

static int valid_id_arg(const char *s, size_t cap)
{
    return s != NULL && str_is_identifier(s) && strlen(s) < cap;
}

/** Explains why no copy of a title can be borrowed right now. */
static void describe_unavailable(const LibraryState *proj, const Book *book, char *err,
                                 size_t err_cap)
{
    size_t i, used = 0, copies = 0;
    int n;

    n = snprintf(err, err_cap, "no copy of %s (%s) is available:", book->book_id, book->title);
    used = n > 0 ? (size_t)n : 0;
    for (i = 0; i < proj->copy_count && used < err_cap; i++) {
        const CopyStatus *c = &proj->copies[i];
        char due[16];

        if (strcasecmp(c->book_id, book->book_id) != 0)
            continue;
        copies++;
        format_date(c->due_date, due, sizeof due);
        if (c->state == COPY_BORROWED)
            n = snprintf(err + used, err_cap - used, " %s BORROWED by %s (due %s);", c->copy_id,
                         c->current_holder_id, due);
        else if (c->state == COPY_RESERVED)
            n = snprintf(err + used, err_cap - used, " %s RESERVED for %s;", c->copy_id,
                         c->current_holder_id);
        else
            n = snprintf(err + used, err_cap - used, " %s %s;", c->copy_id,
                         copy_state_name(c->state));
        if (n < 0)
            break;
        used += (size_t)n;
    }
    if (copies == 0 && used < err_cap)
        snprintf(err + used, err_cap - used, " the title has no registered copies");
    else if (used > 0 && used < err_cap && err[used - 1] == ';')
        err[used - 1] = '\0';                    /* no trailing separator */
}

Status library_borrow(Library *lib, const char *book_or_copy, const char *member_id,
                      time_t due_date, Request *out, char *err, size_t err_cap)
{
    LibraryState proj;
    const Member *member;
    const CopyRecord *cr;
    const Book *book;
    const CopyStatus *copy = NULL;
    Record rec;
    time_t now = lib_now();
    int have_proj = 0;
    Status st = LT_OK;

    if (!valid_id_arg(member_id, MEMBER_ID_LEN))
        FAIL(LT_ERR_INPUT, "'%s' is not a valid member ID (letters, digits, '-', '_')",
             member_id ? member_id : "");
    if (!valid_id_arg(book_or_copy, COPY_ID_LEN))
        FAIL(LT_ERR_INPUT, "'%s' is not a valid book or copy ID", book_or_copy ? book_or_copy : "");
    member = registry_find_member(&lib->members, member_id);
    cr = registry_find_copy(&lib->copies, book_or_copy);
    book = registry_find_book(&lib->books, cr != NULL ? cr->book_id : book_or_copy);
    if (book == NULL)
        FAIL(LT_ERR_NOT_FOUND, "book %s is not in the book registry (books.txt / copies.txt)",
             book_or_copy);
    if (member == NULL)
        FAIL(LT_ERR_NOT_FOUND, "member %s is not in the member registry (members.txt)",
             member_id);
    if (due_date != 0 && (due_date <= now || due_date > now + MAX_LOAN_DAYS * DAY_SECONDS))
        FAIL(LT_ERR_INPUT, "the due date must be in the future and at most %d days away",
             MAX_LOAN_DAYS);

    st = library_project(lib, &proj);
    if (st != LT_OK)
        FAIL(st, "out of memory");
    have_proj = 1;

    if (cr != NULL) {
        copy = state_copy(&proj, cr->copy_id);
    } else {
        /* A copy held for this member (reservation) comes first. */
        copy = state_copy_held_for(&proj, book->book_id, member->member_id);
        if (copy == NULL)
            copy = state_available_copy(&proj, book->book_id);
        if (copy == NULL) {
            describe_unavailable(&proj, book, err, err_cap);
            st = LT_ERR_STATE;
            goto done;
        }
    }
    fill_record(&rec, ACT_BORROW, book, copy->copy_id, member, now);
    rec.due_date = due_date != 0 ? due_date : now + (time_t)lib->rules.loan_days * DAY_SECONDS;
    rec.condition = copy->condition;
    st = submit_request(lib, &proj, &rec, out, err, err_cap);
done:
    if (have_proj)
        state_free(&proj);
    return st;
}

/** Finds a pending request touching a copy (for clearer messages). */
static const Request *pending_for_copy(const Library *lib, const char *copy_id, Action action)
{
    size_t i;

    for (i = 0; i < lib->pool.count; i++) {
        const Record *r = &lib->pool.items[i].rec;
        if (strcasecmp(r->copy_id, copy_id) == 0 && (action == ACT_NONE || r->action == action))
            return &lib->pool.items[i];
    }
    return NULL;
}

Status library_return(Library *lib, const char *copy_id, int has_condition,
                      Condition condition, const char *reason, Request *out,
                      char *err, size_t err_cap)
{
    LibraryState proj;
    const CopyRecord *cr;
    const CopyStatus *confirmed, *copy;
    const Record *borrowed;
    const Member *member;
    const Book *book;
    Record rec;
    time_t now = lib_now();
    long block_index = -1;
    int have_proj = 0, late;
    Status st = LT_OK;

    if (!valid_id_arg(copy_id, COPY_ID_LEN))
        FAIL(LT_ERR_INPUT, "'%s' is not a valid copy ID", copy_id ? copy_id : "");
    if (reason != NULL && reason[0] != '\0' && strcmp(reason, "-") != 0 &&
        !valid_id_arg(reason, REASON_LEN))
        FAIL(LT_ERR_INPUT, "the reason code must be one word of up to %d letters/digits "
                           "(e.g. WATER_DAMAGE)", REASON_LEN - 1);
    if (has_condition && condition == COND_LOST)
        FAIL(LT_ERR_INPUT, "a returned copy cannot be LOST - use mark_lost instead");
    cr = registry_find_copy(&lib->copies, copy_id);
    if (cr == NULL)
        FAIL(LT_ERR_NOT_FOUND, "copy %s is not in the copy registry (copies.txt)", copy_id);

    /* The copy's most recent BORROWED record must be ON THE CHAIN. */
    borrowed = library_last_record_for_copy(lib, cr->copy_id, ACT_BORROW, &block_index);
    confirmed = state_copy(&lib->state, cr->copy_id);
    if (borrowed == NULL || confirmed == NULL || confirmed->state != COPY_BORROWED) {
        const Request *p = pending_for_copy(lib, cr->copy_id, ACT_BORROW);
        if (p != NULL)
            FAIL(LT_ERR_STATE, "copy %s has no confirmed BORROWED record on the chain: its "
                               "borrow request %s is still pending - mine it first",
                 cr->copy_id, p->rec.record_id);
        FAIL(LT_ERR_STATE, "copy %s has no outstanding BORROWED record on the chain (it is %s)",
             cr->copy_id, confirmed ? copy_state_name(confirmed->state) : "unknown");
    }

    st = library_project(lib, &proj);
    if (st != LT_OK)
        FAIL(st, "out of memory");
    have_proj = 1;
    copy = state_copy(&proj, cr->copy_id);
    if (copy == NULL || copy->state != COPY_BORROWED) {
        const Request *p = pending_for_copy(lib, cr->copy_id, ACT_RETURN);
        FAIL(LT_ERR_STATE, "copy %s already has a pending %s request (%s)", cr->copy_id,
             p ? "RETURN" : "lending", p ? p->rec.record_id : "see pool_view");
    }
    member = registry_find_member(&lib->members, copy->current_holder_id);
    book = registry_find_book(&lib->books, copy->book_id);
    if (member == NULL || book == NULL)
        FAIL(LT_ERR_NOT_FOUND, "the borrower or the book is no longer registered");

    fill_record(&rec, ACT_RETURN, book, copy->copy_id, member, now);
    rec.due_date = copy->due_date;
    late = now > copy->due_date;
    rec.fine_amount = late ? fine_for(copy->due_date, now) : 0;
    rec.token_reward = late ? REWARD_LATE : REWARD_ON_TIME;
    rec.condition = has_condition ? condition : copy->condition;
    if (reason != NULL && reason[0] != '\0')
        (void)str_copy(rec.reason, sizeof rec.reason, reason);
    st = submit_request(lib, &proj, &rec, out, err, err_cap);
done:
    if (have_proj)
        state_free(&proj);
    return st;
}

Status library_reserve(Library *lib, const char *book_id, const char *member_id,
                       Request *out, char *err, size_t err_cap)
{
    LibraryState proj;
    const Member *member;
    const Book *book;
    Record rec;
    int have_proj = 0;
    Status st = LT_OK;

    if (!valid_id_arg(book_id, BOOK_ID_LEN) || !valid_id_arg(member_id, MEMBER_ID_LEN))
        FAIL(LT_ERR_INPUT, "usage: reserve_book <book_id> <member_id>");
    book = registry_find_book(&lib->books, book_id);
    member = registry_find_member(&lib->members, member_id);
    if (book == NULL)
        FAIL(LT_ERR_NOT_FOUND, "book %s is not in the book registry", book_id);
    if (member == NULL)
        FAIL(LT_ERR_NOT_FOUND, "member %s is not in the member registry", member_id);
    if (registry_count_copies(&lib->copies, book->book_id) == 0)
        FAIL(LT_ERR_STATE, "%s has no registered copies - add_copy first", book->book_id);

    st = library_project(lib, &proj);
    if (st != LT_OK)
        FAIL(st, "out of memory");
    have_proj = 1;
    fill_record(&rec, ACT_RESERVE, book, NULL, member, lib_now());
    rec.condition = COND_GOOD;
    st = submit_request(lib, &proj, &rec, out, err, err_cap);
done:
    if (have_proj)
        state_free(&proj);
    return st;
}

Status library_renew(Library *lib, const char *copy_id, const char *member_id,
                     Request *out, char *err, size_t err_cap)
{
    LibraryState proj;
    const CopyRecord *cr;
    const CopyStatus *copy;
    const Member *member;
    const Book *book;
    Record rec;
    int have_proj = 0;
    Status st = LT_OK;

    if (!valid_id_arg(copy_id, COPY_ID_LEN))
        FAIL(LT_ERR_INPUT, "'%s' is not a valid copy ID", copy_id ? copy_id : "");
    if (member_id != NULL && !valid_id_arg(member_id, MEMBER_ID_LEN))
        FAIL(LT_ERR_INPUT, "'%s' is not a valid member ID", member_id);
    cr = registry_find_copy(&lib->copies, copy_id);
    if (cr == NULL)
        FAIL(LT_ERR_NOT_FOUND, "copy %s is not in the copy registry", copy_id);

    st = library_project(lib, &proj);
    if (st != LT_OK)
        FAIL(st, "out of memory");
    have_proj = 1;
    copy = state_copy(&proj, cr->copy_id);
    if (copy == NULL || copy->state != COPY_BORROWED)
        FAIL(LT_ERR_STATE, "copy %s is not on loan (it is %s)", cr->copy_id,
             copy ? copy_state_name(copy->state) : "unknown");
    if (member_id != NULL && strcasecmp(member_id, copy->current_holder_id) != 0)
        FAIL(LT_ERR_STATE, "copy %s is on loan to %s, not %s", copy->copy_id,
             copy->current_holder_id, member_id);
    member = registry_find_member(&lib->members, copy->current_holder_id);
    book = registry_find_book(&lib->books, copy->book_id);
    if (member == NULL || book == NULL)
        FAIL(LT_ERR_NOT_FOUND, "the borrower or the book is no longer registered");

    fill_record(&rec, ACT_RENEW, book, copy->copy_id, member, lib_now());
    rec.due_date = copy->due_date + (time_t)lib->rules.renewal_days * DAY_SECONDS;
    rec.condition = copy->condition;
    st = submit_request(lib, &proj, &rec, out, err, err_cap);
done:
    if (have_proj)
        state_free(&proj);
    return st;
}

Status library_mark_lost(Library *lib, const char *copy_id, const char *reason,
                         Request *out, char *err, size_t err_cap)
{
    LibraryState proj;
    const CopyRecord *cr;
    const CopyStatus *copy;
    const Member *member = NULL;
    const Book *book;
    Record rec;
    int have_proj = 0;
    Status st = LT_OK;

    if (!valid_id_arg(copy_id, COPY_ID_LEN))
        FAIL(LT_ERR_INPUT, "'%s' is not a valid copy ID", copy_id ? copy_id : "");
    if (reason == NULL || !valid_id_arg(reason, REASON_LEN))
        FAIL(LT_ERR_INPUT, "a librarian override needs a reason code (one word, e.g. "
                           "NOT_RETURNED, DAMAGED_BEYOND_REPAIR)");
    cr = registry_find_copy(&lib->copies, copy_id);
    if (cr == NULL)
        FAIL(LT_ERR_NOT_FOUND, "copy %s is not in the copy registry", copy_id);
    st = library_project(lib, &proj);
    if (st != LT_OK)
        FAIL(st, "out of memory");
    have_proj = 1;
    copy = state_copy(&proj, cr->copy_id);
    book = registry_find_book(&lib->books, cr->book_id);
    if (copy == NULL || book == NULL)
        FAIL(LT_ERR_NOT_FOUND, "copy %s has no inventory entry", cr->copy_id);
    if (copy->state == COPY_BORROWED)
        member = registry_find_member(&lib->members, copy->current_holder_id);

    fill_record(&rec, ACT_LOST, book, copy->copy_id, member, lib_now());
    staff_signer(lib, rec.signer_id);              /* librarian override */
    rec.due_date = copy->state == COPY_BORROWED ? copy->due_date : 0;
    rec.condition = COND_LOST;
    (void)str_copy(rec.reason, sizeof rec.reason, reason);
    st = submit_request(lib, &proj, &rec, out, err, err_cap);
done:
    if (have_proj)
        state_free(&proj);
    return st;
}

Status library_transfer(Library *lib, const char *from, const char *to, long amount,
                        const TxInput *inputs, size_t input_count, long account_nonce,
                        Request *out, char *err, size_t err_cap)
{
    LibraryState proj;
    const Member *sender, *recipient;
    Record rec;
    time_t now = lib_now();
    int have_proj = 0;
    Status st = LT_OK;

    if (!valid_id_arg(from, MEMBER_ID_LEN) || !valid_id_arg(to, MEMBER_ID_LEN))
        FAIL(LT_ERR_INPUT, "sender and recipient must be valid member IDs");
    if (amount <= 0 || amount > 1000000L)
        FAIL(LT_ERR_INPUT, "the amount must be a positive whole number of coins");
    sender = registry_find_member(&lib->members, from);
    recipient = registry_find_member(&lib->members, to);
    if (sender == NULL)
        FAIL(LT_ERR_NOT_FOUND, "sender %s is not in the member registry", from);
    if (recipient == NULL)
        FAIL(LT_ERR_NOT_FOUND, "recipient %s is not in the member registry", to);
    if (sender == recipient)
        FAIL(LT_ERR_INPUT, "a member cannot send coins to themselves");
    if (input_count > TX_MAX_INPUTS)
        FAIL(LT_ERR_INPUT, "at most %d inputs", TX_MAX_INPUTS);
    if (input_count > 0 && lib->model != MODEL_UTXO)
        FAIL(LT_ERR_INPUT, "inputs can only be chosen in the UTXO model");

    st = library_project(lib, &proj);
    if (st != LT_OK)
        FAIL(st, "out of memory");
    have_proj = 1;
    fill_record(&rec, ACT_TRANSFER, NULL, NULL, sender, now);
    tx_make_transfer(&rec.tx, sender->member_id, recipient->member_id, amount,
                     account_nonce >= 0 ? account_nonce
                                        : ledger_account_nonce(&proj.ledger, sender->member_id),
                     now);
    if (input_count > 0) {
        memcpy(rec.tx.inputs, inputs, input_count * sizeof *inputs);
        rec.tx.input_count = input_count;
    }
    st = submit_request(lib, &proj, &rec, out, err, err_cap);
done:
    if (have_proj)
        state_free(&proj);
    return st;
}

Status library_settle_fine(Library *lib, const char *member_id, long amount, int cash,
                           Request *out, char *err, size_t err_cap)
{
    LibraryState proj;
    const Member *member;
    Record rec;
    time_t now = lib_now();
    long due;
    int have_proj = 0;
    Status st = LT_OK;

    if (!valid_id_arg(member_id, MEMBER_ID_LEN))
        FAIL(LT_ERR_INPUT, "'%s' is not a valid member ID", member_id ? member_id : "");
    if (amount < 0)
        FAIL(LT_ERR_INPUT, "the amount cannot be negative");
    member = registry_find_member(&lib->members, member_id);
    if (member == NULL)
        FAIL(LT_ERR_NOT_FOUND, "member %s is not in the member registry", member_id);
    st = library_project(lib, &proj);
    if (st != LT_OK)
        FAIL(st, "out of memory");
    have_proj = 1;
    due = state_fine_due(&proj, member->member_id);
    if (due <= 0) {
        long accruing = state_accruing_fine(&proj, member->member_id, now);
        if (accruing > 0)
            FAIL(LT_ERR_STATE, "%s owes no assessed fines yet; %ld coin(s) are accruing on "
                               "overdue loans and are assessed when the book is returned",
                 member->member_id, accruing);
        FAIL(LT_ERR_STATE, "%s has no outstanding fines", member->member_id);
    }
    if (amount == 0)
        amount = due;
    if (amount > due)
        FAIL(LT_ERR_INPUT, "%s owes %ld coin(s); %ld is more than that", member->member_id,
             due, amount);

    fill_record(&rec, ACT_FINE, NULL, NULL, member, now);
    tx_make_fine(&rec.tx, member->member_id, amount, !cash,
                 cash ? 0 : ledger_account_nonce(&proj.ledger, member->member_id), now);
    if (cash)
        staff_signer(lib, rec.signer_id);   /* cash is received by the librarian */
    st = submit_request(lib, &proj, &rec, out, err, err_cap);
done:
    if (have_proj)
        state_free(&proj);
    return st;
}

Status library_overdue_scan(Library *lib, Request *created, size_t max, size_t *count,
                            char *err, size_t err_cap)
{
    LibraryState proj;
    time_t now = lib_now();
    size_t i;
    Status st;

    *count = 0;
    err[0] = '\0';
    if (!auth_is_logged_in(&lib->session))
        return LT_ERR_AUTH;
    st = library_project(lib, &proj);
    if (st != LT_OK)
        return st;
    for (i = 0; i < proj.copy_count && st == LT_OK; i++) {
        const CopyStatus c = proj.copies[i];       /* copy: proj changes below */
        const Member *member;
        const Book *book;
        Record rec;
        Request req;

        if (c.state != COPY_BORROWED || now <= c.due_date || c.overdue_flagged)
            continue;
        member = registry_find_member(&lib->members, c.current_holder_id);
        book = registry_find_book(&lib->books, c.book_id);
        if (member == NULL || book == NULL)
            continue;
        fill_record(&rec, ACT_OVERDUE, book, c.copy_id, member, now);
        staff_signer(lib, rec.signer_id);          /* system record, librarian-signed */
        rec.due_date = c.due_date;
        rec.fine_amount = fine_for(c.due_date, now);
        rec.condition = c.condition;
        st = submit_request(lib, &proj, &rec, &req, err, err_cap);
        if (st == LT_OK) {
            if (created != NULL && *count < max)
                created[*count] = req;
            (*count)++;
        }
    }
    state_free(&proj);
    return st;
}

/* ------------------------------------------------------------------------ */
/* Nonce re-sequencing and pool pruning                                     */
/* ------------------------------------------------------------------------ */

/*
 * When a pending request is removed, the same signer's later requests carry
 * nonces that skip a number. Because the library holds the members' keys
 * (custodial vault) and the librarian's own key, it renumbers those requests
 * from the confirmed nonce and signs them again. Replayed requests (flagged
 * DUPLICATE) are never re-signed: they are not the library's own requests.
 */
void library_resequence(Library *lib, const char *signer_id)
{
    long next = state_nonce(&lib->state, signer_id), next_account = -1;
    EVP_PKEY *key = NULL;
    int owned = 0, tried = 0, changed_any = 0;
    size_t i;

    for (i = 0; i < lib->pool.count; i++) {
        Record *rec = &lib->pool.items[i].rec;
        int changed = 0;

        if (strcmp(rec->signer_id, signer_id) != 0 || (lib->pool.items[i].flags & FLAG_DUPLICATE))
            continue;
        if (rec->nonce != next) {
            rec->nonce = next;
            changed = 1;
        }
        next++;
        if (tx_moves_tokens(&rec->tx) && rec->tx.type != TX_REWARD) {
            if (next_account < 0)
                next_account = ledger_account_nonce(&lib->state.ledger, rec->tx.from);
            if (rec->tx.nonce != next_account) {
                rec->tx.nonce = next_account;
                changed = 1;
            }
            next_account++;
        }
        if (!changed)
            continue;
        if (!tried) {
            key = signing_key_for(lib, signer_id, &owned);
            tried = 1;
        }
        if (key != NULL && record_sign(rec, key) == LT_OK)
            changed_any = 1;
    }
    release_key(key, owned);
    if (changed_any)
        (void)library_save_pool(lib);
}

static void add_rejection(AssemblyReport *rep, const Record *rec, const char *reason)
{
    Rejection *r;

    if (rep == NULL || rep->rejected_count >= sizeof rep->rejected / sizeof rep->rejected[0])
        return;
    r = &rep->rejected[rep->rejected_count++];
    (void)str_copy(r->record_id, sizeof r->record_id, rec->record_id);
    snprintf(r->reason, sizeof r->reason, "%.12s %.19s: %.250s", action_request_name(rec->action),
             rec->member_id, reason);
}

/*
 * Replays the pool in arrival order on top of the confirmed state and
 * removes every request that is no longer valid:
 *   - any request whose signature is invalid or missing;
 *   - a PENDING request that breaks a rule (for example the copy it needed
 *     was taken, or the reservation it depended on was rejected).
 * A SUSPICIOUS request that breaks a rule stays in the pool: only an
 * administrator may discard it (reject_suspicious). Each removal restarts
 * the replay, because later requests may depend on the removed one.
 */
void library_prune(Library *lib, AssemblyReport *report)
{
    StateContext ctx;
    int removed_any = 0, again = 1;

    library_context(lib, &ctx);
    while (again) {
        LibraryState proj;
        size_t i;

        again = 0;
        if (state_clone(&proj, &lib->state) != LT_OK)
            return;
        for (i = 0; i < lib->pool.count && !again; i++) {
            Request *req = &lib->pool.items[i];
            char why[256], signer[SIGNER_ID_LEN];
            SigCheck sig = record_verify(&req->rec, &lib->keys);
            Status st;

            if (sig != SIG_VALID) {
                snprintf(why, sizeof why, "signature %s - rejected", sig_check_name(sig));
            } else {
                st = state_apply_record(&proj, &ctx, &req->rec, STATE_PENDING, why, sizeof why);
                if (st == LT_OK || req->status == REQ_SUSPICIOUS)
                    continue;
            }
            add_rejection(report, &req->rec, why);
            (void)str_copy(signer, sizeof signer, req->rec.signer_id);
            pool_remove_at(&lib->pool, i);
            library_resequence(lib, signer);
            removed_any = again = 1;
        }
        state_free(&proj);
    }
    if (removed_any)
        (void)library_save_pool(lib);
}

/* ------------------------------------------------------------------------ */
/* Fraud review and replay simulation                                       */
/* ------------------------------------------------------------------------ */

static Status find_request(const Library *lib, const char *id, size_t *index,
                           char *err, size_t err_cap)
{
    long i = id != NULL ? pool_find(&lib->pool, id) : -1;

    if (i == -2) {
        snprintf(err, err_cap, "'%s' matches more than one request - type more characters", id);
        return LT_ERR_INPUT;
    }
    if (i < 0) {
        snprintf(err, err_cap, "no pending request has the ID '%s' (see pool_view)",
                 id ? id : "");
        return LT_ERR_NOT_FOUND;
    }
    *index = (size_t)i;
    return LT_OK;
}

/** Applies the pool in order and reports whether request `index` still applies. */
static Status request_still_valid(const Library *lib, size_t index, char *err, size_t err_cap)
{
    StateContext ctx;
    LibraryState proj;
    size_t i;
    Status st = LT_OK;

    library_context(lib, &ctx);
    if (state_clone(&proj, &lib->state) != LT_OK)
        return LT_ERR_MEMORY;
    for (i = 0; i <= index && i < lib->pool.count; i++) {
        char why[256];
        Status s = state_apply_record(&proj, &ctx, &lib->pool.items[i].rec, STATE_PENDING,
                                      why, sizeof why);
        if (i == index) {
            st = s;
            if (s != LT_OK)
                snprintf(err, err_cap, "%s", why);
        }
    }
    state_free(&proj);
    return st;
}

Status library_approve(Library *lib, const char *id, Request *out, AssemblyReport *cascade,
                       char *err, size_t err_cap)
{
    char flags[96], signer[SIGNER_ID_LEN], why[256];
    size_t index = 0;
    Request *req;
    Status st;

    if (cascade != NULL)
        memset(cascade, 0, sizeof *cascade);
    st = find_request(lib, id, &index, err, err_cap);
    if (st != LT_OK)
        return st;
    req = &lib->pool.items[index];
    if (req->status != REQ_SUSPICIOUS) {
        snprintf(err, err_cap, "request %s is %s - only SUSPICIOUS requests need review",
                 req->rec.record_id, request_status_name(req->status));
        return LT_ERR_STATE;
    }
    /* The review note is stored with the record and covered by the block's
     * Merkle root once mined, so the approval itself is auditable. */
    flags_describe(req->flags, flags, sizeof flags);
    snprintf(req->rec.review, sizeof req->rec.review, "approved by %.19s (%.60s)",
             lib->session.username, flags);
    req->status = REQ_PENDING;
    if (out != NULL)
        *out = *req;

    /* Approval does not bypass the rules: a replayed request, for example,
     * still carries a nonce that was already used. */
    st = request_still_valid(lib, index, why, sizeof why);
    if (st != LT_OK) {
        snprintf(err, err_cap, "%s", why);
        (void)str_copy(signer, sizeof signer, req->rec.signer_id);
        pool_remove_at(&lib->pool, index);
        if (!(out != NULL && (out->flags & FLAG_DUPLICATE)))
            library_resequence(lib, signer);
        library_prune(lib, cascade);
        (void)library_save_pool(lib);
        return LT_ERR_STATE;
    }
    return library_save_pool(lib);
}

Status library_reject(Library *lib, const char *id, Request *out, AssemblyReport *cascade,
                      char *err, size_t err_cap)
{
    char signer[SIGNER_ID_LEN];
    size_t index = 0;
    Request req;
    Status st;

    if (cascade != NULL)
        memset(cascade, 0, sizeof *cascade);
    st = find_request(lib, id, &index, err, err_cap);
    if (st != LT_OK)
        return st;
    req = lib->pool.items[index];
    if (req.status != REQ_SUSPICIOUS) {
        snprintf(err, err_cap, "request %s is %s - only SUSPICIOUS requests can be rejected",
                 req.rec.record_id, request_status_name(req.status));
        return LT_ERR_STATE;
    }
    if (out != NULL)
        *out = req;
    (void)str_copy(signer, sizeof signer, req.rec.signer_id);
    pool_remove_at(&lib->pool, index);
    if (!(req.flags & FLAG_DUPLICATE))
        library_resequence(lib, signer);
    library_prune(lib, cascade);          /* requests that depended on it */
    return library_save_pool(lib);
}

Status library_replay(Library *lib, const char *record_id, Request *out,
                      char *err, size_t err_cap)
{
    const Record *found = NULL;
    LibraryState proj;
    Request req;
    size_t i, r, len = record_id ? strlen(record_id) : 0;
    int matches = 0;
    Status st;

    if (len < 4) {
        snprintf(err, err_cap, "give at least 4 characters of a confirmed record ID");
        return LT_ERR_INPUT;
    }
    for (i = 0; i < lib->chain.length; i++) {
        for (r = 0; r < lib->chain.blocks[i].record_count; r++) {
            const Record *rec = &lib->chain.blocks[i].records[r];
            if (strncasecmp(rec->record_id, record_id, len) == 0) {
                found = rec;
                matches++;
            }
        }
    }
    if (matches == 0) {
        snprintf(err, err_cap, "no confirmed record on the chain has the ID '%s'", record_id);
        return LT_ERR_NOT_FOUND;
    }
    if (matches > 1) {
        snprintf(err, err_cap, "'%s' matches %d records - type more characters", record_id,
                 matches);
        return LT_ERR_INPUT;
    }
    /* The attacker re-submits the captured, genuinely signed record as-is. */
    st = library_project(lib, &proj);
    if (st != LT_OK)
        return st;
    memset(&req, 0, sizeof req);
    req.rec = *found;
    req.flags = fraud_flags(lib, &proj, &req.rec);
    req.status = REQ_SUSPICIOUS;
    request_order(&proj, &req.rec, &req.priority, &req.sort_time);
    state_free(&proj);
    st = pool_add(&lib->pool, &req);
    if (st == LT_OK)
        st = library_save_pool(lib);
    if (st == LT_OK && out != NULL)
        *out = lib->pool.items[lib->pool.count - 1];
    return st;
}

/* ------------------------------------------------------------------------ */
/* Block assembly and confirmation                                          */
/* ------------------------------------------------------------------------ */

size_t library_minable(const Library *lib)
{
    return pool_count_status(&lib->pool, REQ_PENDING);
}

/*
 * Batching approach: fixed-size blocks. The miner sorts a copy of the pool
 * (pool_sort: overdue-related first, then reservation date, then arrival)
 * and takes requests from the top until the block holds block_capacity
 * records. Each candidate is re-verified (ECDSA) and re-applied to a trial
 * copy of the confirmed state. A request is deferred to a later block when
 * it cannot apply yet: its nonce follows a request that is not in the block
 * (for example one held as SUSPICIOUS), or it needs another request first
 * (a borrow of a copy that a later-sorted return frees). Several passes are
 * made so such a request is still picked up once its dependency is in.
 */
/**
 * Multi-pass selection over the sorted pool (see above). Selected requests
 * are applied to *trial and, if out is not NULL, appended to the block.
 * used[i] is set for every selected request. @return the number selected.
 */
static size_t select_requests(const Library *lib, const PendingPool *sorted, LibraryState *trial,
                              char *used, size_t capacity, int block_index, Block *out,
                              Status *st)
{
    StateContext ctx;
    size_t i, selected = 0;
    int progress;

    library_context(lib, &ctx);
    *st = LT_OK;
    do {
        progress = 0;
        for (i = 0; i < sorted->count && selected < capacity; i++) {
            const Request *req = &sorted->items[i];
            char why[256];

            if (used[i] || req->status != REQ_PENDING)
                continue;
            if (req->rec.nonce != state_nonce(trial, req->rec.signer_id))
                continue;                                  /* not its turn yet */
            if (record_verify(&req->rec, (KeyDirectory *)&lib->keys) != SIG_VALID)
                continue;                                  /* never mined     */
            if (state_apply_record(trial, &ctx, &req->rec, block_index, why, sizeof why) != LT_OK)
                continue;                                  /* needs another request first */
            if (out != NULL) {
                *st = block_add_record(out, &req->rec);
                if (*st != LT_OK)
                    return selected;
            }
            used[i] = 1;
            selected++;
            progress = 1;
        }
    } while (progress && selected < capacity);
    return selected;
}

Status library_assemble_block(Library *lib, const char *sealed_by, Block *out,
                              AssemblyReport *report)
{
    LibraryState trial;
    PendingPool sorted;
    char *used = NULL;
    Status st;

    memset(report, 0, sizeof *report);
    block_init(out);
    library_prune(lib, report);

    st = pool_copy(&sorted, &lib->pool);
    if (st != LT_OK)
        return st;
    pool_sort(&sorted);
    used = calloc(sorted.count ? sorted.count : 1, 1);
    if (used == NULL || state_clone(&trial, &lib->state) != LT_OK) {
        free(used);
        pool_free(&sorted);
        return LT_ERR_MEMORY;
    }
    block_prepare(out, &lib->chain, lib->difficulty, sealed_by, lib_now());
    (void)select_requests(lib, &sorted, &trial, used, (size_t)lib->block_capacity, out->index,
                          out, &st);

    report->selected = out->record_count;
    report->suspicious_skipped = pool_count_status(&sorted, REQ_SUSPICIOUS);
    report->deferred = pool_count_status(&sorted, REQ_PENDING) - out->record_count;
    state_free(&trial);
    pool_free(&sorted);
    free(used);

    if (st == LT_OK && out->record_count == 0)
        st = LT_ERR_POOL_EMPTY;
    if (st == LT_OK)
        st = block_finalise_body(out);    /* Merkle root, reward tx, transaction_id */
    if (st != LT_OK)
        block_free(out);
    return st;
}

size_t library_preview(const Library *lib, PendingPool *sorted, int *block_of)
{
    LibraryState trial;
    char *used;
    size_t i, total = 0;
    int block = (int)lib->chain.length;
    Status st = LT_OK;

    if (pool_copy(sorted, &lib->pool) != LT_OK)
        return 0;
    pool_sort(sorted);
    for (i = 0; i < sorted->count; i++)
        block_of[i] = -1;
    used = calloc(sorted->count ? sorted->count : 1, 1);
    if (used == NULL || state_clone(&trial, &lib->state) != LT_OK) {
        free(used);
        return 0;
    }
    /* Simulate consecutive blocks until nothing more can be selected. */
    for (;;) {
        char *before = malloc(sorted->count ? sorted->count : 1);
        size_t n;

        if (before == NULL)
            break;
        memcpy(before, used, sorted->count);
        n = select_requests(lib, sorted, &trial, used, (size_t)lib->block_capacity, block,
                            NULL, &st);
        for (i = 0; i < sorted->count; i++) {
            if (used[i] && !before[i])
                block_of[i] = block;
        }
        free(before);
        if (n == 0 || st != LT_OK)
            break;
        total += n;
        block++;
    }
    state_free(&trial);
    free(used);
    return total;
}

double library_block_earnings(const Library *lib, const Block *block)
{
    long fees = tx_total_fees(&block->reward);
    size_t i;

    for (i = 0; i < block->record_count; i++)
        fees += tx_total_fees(&block->records[i].tx);
    return (double)lib->block_reward + (double)fees;
}

Status library_commit_block(Library *lib, Block *block, AssemblyReport *after,
                            char *err, size_t err_cap)
{
    StateContext ctx;
    LibraryState trial;
    const Block *tip = chain_tip(&lib->chain);
    char hash[HASH_HEX_LEN], merkle[HASH_HEX_LEN], why[256];
    size_t i, bad = 0;
    Status st;

    if (after != NULL)
        memset(after, 0, sizeof *after);
    library_context(lib, &ctx);

    /* Header: position, link, timestamp, hash and proof-of-work. */
    if (tip == NULL || block->index != (int)lib->chain.length ||
        strcmp(block->previous_hash, tip->hash) != 0) {
        snprintf(err, err_cap, "the block does not extend the current chain tip");
        return LT_ERR_CHAIN_INVALID;
    }
    if (block->timestamp <= tip->timestamp) {
        snprintf(err, err_cap, "the block timestamp is not later than the previous block's");
        return LT_ERR_CHAIN_INVALID;
    }
    if (block_compute_hash(block, hash) != LT_OK || strcmp(hash, block->hash) != 0 ||
        !pow_hash_meets(block->hash, block->difficulty)) {
        snprintf(err, err_cap, "the block hash does not meet difficulty %d", block->difficulty);
        return LT_ERR_CHAIN_INVALID;
    }
    if (block_compute_merkle(block, merkle) != LT_OK || strcmp(merkle, block->merkle_root) != 0) {
        snprintf(err, err_cap, "the Merkle root does not match the records");
        return LT_ERR_CHAIN_INVALID;
    }

    /* Every record: a valid ECDSA signature from the signer's registered key. */
    for (i = 0; i < block->record_count; i++) {
        SigCheck sig = record_verify(&block->records[i], &lib->keys);
        if (sig != SIG_VALID) {
            snprintf(err, err_cap, "record %s has signature %s", block->records[i].record_id,
                     sig_check_name(sig));
            return LT_ERR_SIGNATURE;
        }
    }

    /* Every lending rule, on a trial copy first so nothing changes on failure. */
    if (state_clone(&trial, &lib->state) != LT_OK)
        return LT_ERR_MEMORY;
    st = state_apply_block(&trial, &ctx, block, why, sizeof why, &bad);
    state_free(&trial);
    if (st != LT_OK) {
        snprintf(err, err_cap, "record %zu: %s", bad + 1, why);
        return st;
    }
    st = state_apply_block(&lib->state, &ctx, block, why, sizeof why, &bad);
    if (st != LT_OK) {                    /* cannot happen after the trial */
        snprintf(err, err_cap, "%s", why);
        (void)library_rebuild_state(lib);
        return st;
    }

    /* Confirmed requests leave the pool. */
    for (i = 0; i < block->record_count; i++) {
        size_t p;
        for (p = 0; p < lib->pool.count; p++) {
            if (lib->pool.items[p].status == REQ_PENDING &&
                strcmp(lib->pool.items[p].rec.record_id, block->records[i].record_id) == 0) {
                pool_remove_at(&lib->pool, p);
                break;
            }
        }
    }
    st = chain_push(&lib->chain, block);
    if (st != LT_OK) {
        snprintf(err, err_cap, "out of memory");
        (void)library_rebuild_state(lib);
        return st;
    }
    library_prune(lib, after);            /* requests the new block made invalid */
    st = library_save_all(lib);
    if (st != LT_OK)
        snprintf(err, err_cap, "the block was confirmed but could not be saved to disk");
    return st;
}

/* ------------------------------------------------------------------------ */
/* Validation and history                                                   */
/* ------------------------------------------------------------------------ */

int library_validate(Library *lib, FILE *log, ValidationSummary *out)
{
    StateContext ctx;
    LibraryState rebuilt;
    StateMeta meta;
    long bad_block = -1;
    size_t i;
    Status st;

    memset(out, 0, sizeof *out);
    library_context(lib, &ctx);

    /* 1. Cryptography and structure of every block. */
    out->chain_ok = chain_validate(&lib->chain, &lib->keys, log, &out->chain);

    /* 2. Replay every record through the lending rules (state machine,
     *    nonces, duplicates, balances, double spends). */
    st = state_build(&rebuilt, &ctx, &lib->chain, lib->model, 0, &bad_block,
                     out->replay_error, sizeof out->replay_error);
    out->replay_ok = st == LT_OK;

    /* 3. Chain metadata and the state snapshot saved in state.dat. */
    memset(&meta, 0, sizeof meta);
    meta.model = lib->model;
    out->meta_ok = 1;
    st = storage_load_state(lib->state_path, &meta, out->replay_ok ? &rebuilt : NULL,
                            &out->state_differences, out->state_first_diff,
                            sizeof out->state_first_diff);
    out->state_file_present = st == LT_OK;
    if (out->state_file_present && meta.chain_length > 0) {
        if (meta.chain_length > lib->chain.length) {
            out->meta_ok = 0;
            snprintf(out->meta_detail, sizeof out->meta_detail,
                     "state.dat recorded %zu blocks but chain.dat has %zu - block(s) were "
                     "deleted from the end of the chain", meta.chain_length, lib->chain.length);
        } else if (strcmp(lib->chain.blocks[meta.chain_length - 1].hash, meta.tip_hash) != 0) {
            out->meta_ok = 0;
            snprintf(out->meta_detail, sizeof out->meta_detail,
                     "block #%zu hash %.16s... differs from the tip %.16s... recorded in "
                     "state.dat - the chain was rewritten", meta.chain_length - 1,
                     lib->chain.blocks[meta.chain_length - 1].hash, meta.tip_hash);
        } else if (meta.chain_length < lib->chain.length) {
            snprintf(out->meta_detail, sizeof out->meta_detail,
                     "state.dat is older than chain.dat (%zu vs %zu blocks); it will be "
                     "rewritten", meta.chain_length, lib->chain.length);
        }
    }
    state_free(&rebuilt);

    /* 4. Signatures of the requests still waiting in the pool. */
    for (i = 0; i < lib->pool.count; i++) {
        out->pending_checked++;
        if (record_verify(&lib->pool.items[i].rec, &lib->keys) != SIG_VALID)
            out->pending_bad_signatures++;
    }
    if (log != NULL) {
        fprintf(log, "  Records replayed through the lending rules: %s%s%s\n",
                out->replay_ok ? clr(CLR_GREEN) : clr(CLR_RED),
                out->replay_ok ? "OK" : out->replay_error, clr(CLR_RESET));
        if (out->state_file_present && !out->replay_ok && out->meta_ok)
            fprintf(log, "  state.dat snapshot vs chain: not compared (the chain does not "
                         "replay)\n");
        else if (out->state_file_present)
            fprintf(log, "  state.dat snapshot vs chain: %s%s%s\n",
                    out->meta_ok && out->state_differences == 0 ? clr(CLR_GREEN)
                                                                : clr(CLR_YELLOW),
                    !out->meta_ok ? out->meta_detail
                    : out->state_differences == 0 ? "matches"
                                                  : out->state_first_diff,
                    clr(CLR_RESET));
        if (out->meta_ok && out->meta_detail[0] != '\0')
            fprintf(log, "  Note: %s\n", out->meta_detail);
        fprintf(log, "  Pending pool signatures: %zu/%zu valid\n",
                out->pending_checked - out->pending_bad_signatures, out->pending_checked);
    }

    lib->validated = 1;
    lib->chain_ok = out->chain_ok && out->replay_ok && out->meta_ok;
    if (lib->chain_ok) {
        (void)library_rebuild_state(lib);
        /* The chain wins: rewrite a stale or edited state.dat. */
        if (!out->state_file_present || out->state_differences > 0 || out->meta_detail[0])
            (void)library_save_state(lib);
    }
    return lib->chain_ok;
}

const Record *library_last_record_for_copy(const Library *lib, const char *copy_id,
                                           Action action, long *block_index)
{
    size_t i, r;

    for (i = lib->chain.length; i-- > 0;) {
        const Block *b = &lib->chain.blocks[i];
        for (r = b->record_count; r-- > 0;) {
            if (b->records[r].action == action &&
                strcasecmp(b->records[r].copy_id, copy_id) == 0) {
                if (block_index != NULL)
                    *block_index = (long)i;
                return &b->records[r];
            }
        }
    }
    return NULL;
}
