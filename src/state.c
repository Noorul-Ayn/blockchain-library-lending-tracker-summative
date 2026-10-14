/**
 * @file state.c
 * @brief Business rules: copy state machine, reservations, renewals,
 *        overdue flags, fines, nonces and token transactions.
 */
#include "state.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "util.h"

#define MAX_RENEWAL_EXTENSION (31L * DAY_SECONDS)

/** Ensures room for one more element in a growable array. */
static int reserve_one(void **items, size_t *cap, size_t count, size_t elem)
{
    size_t new_cap;
    void *grown;

    if (count < *cap)
        return 0;
    new_cap = *cap ? *cap * 2 : 16;
    if (new_cap > SIZE_MAX / elem)
        return -1;
    grown = realloc(*items, new_cap * elem);
    if (grown == NULL)
        return -1;
    *items = grown;
    *cap = new_cap;
    return 0;
}

const char *copy_state_name(CopyState s)
{
    switch (s) {
    case COPY_AVAILABLE: return "AVAILABLE";
    case COPY_BORROWED:  return "BORROWED";
    case COPY_RESERVED:  return "RESERVED";
    case COPY_LOST:      return "LOST";
    }
    return "?";
}

long fine_for(time_t due_date, time_t at)
{
    return days_between_ceil(due_date, at) * FINE_PER_DAY;
}

/* ------------------------------------------------------------------------ */
/* Life cycle                                                               */
/* ------------------------------------------------------------------------ */

Status state_init(LibraryState *st, const StateContext *ctx, LedgerModel model, int keep_history)
{
    size_t i;

    memset(st, 0, sizeof *st);
    ledger_init(&st->ledger, model, keep_history);
    if (ctx->copies->count > 0) {
        st->copies = calloc(ctx->copies->count, sizeof *st->copies);
        if (st->copies == NULL)
            return LT_ERR_MEMORY;
        st->copy_cap = ctx->copies->count;
    }
    for (i = 0; i < ctx->copies->count; i++) {
        const CopyRecord *src = &ctx->copies->items[i];
        CopyStatus *c = &st->copies[st->copy_count++];

        (void)str_copy(c->copy_id, sizeof c->copy_id, src->copy_id);
        (void)str_copy(c->book_id, sizeof c->book_id, src->book_id);
        c->condition = src->condition;
        c->state = src->condition == COND_LOST ? COPY_LOST : COPY_AVAILABLE;
    }
    return LT_OK;
}

void state_free(LibraryState *st)
{
    size_t i;

    for (i = 0; i < st->queue_count; i++)
        free(st->queues[i].items);
    free(st->copies);
    free(st->queues);
    free(st->nonces);
    free(st->fines);
    free(st->returns);
    free(st->ids);
    ledger_free(&st->ledger);
    memset(st, 0, sizeof *st);
}

/** Copies count elements of an array into a new heap block (NULL if empty). */
static int dup_array(void **dst, const void *src, size_t count, size_t elem)
{
    *dst = NULL;
    if (count == 0)
        return 0;
    if (count > SIZE_MAX / elem)
        return -1;
    *dst = malloc(count * elem);
    if (*dst == NULL)
        return -1;
    memcpy(*dst, src, count * elem);
    return 0;
}

Status state_clone(LibraryState *dst, const LibraryState *src)
{
    size_t i;
    int rc = 0;

    memset(dst, 0, sizeof *dst);
    ledger_init(&dst->ledger, src->ledger.model, 0);
    rc |= dup_array((void **)&dst->copies, src->copies, src->copy_count, sizeof *src->copies);
    dst->copy_count = dst->copy_cap = rc == 0 ? src->copy_count : 0;
    rc |= dup_array((void **)&dst->nonces, src->nonces, src->nonce_count, sizeof *src->nonces);
    dst->nonce_count = dst->nonce_cap = rc == 0 ? src->nonce_count : 0;
    rc |= dup_array((void **)&dst->fines, src->fines, src->fine_count, sizeof *src->fines);
    dst->fine_count = dst->fine_cap = rc == 0 ? src->fine_count : 0;
    rc |= dup_array((void **)&dst->returns, src->returns, src->return_count,
                    sizeof *src->returns);
    dst->return_count = dst->return_cap = rc == 0 ? src->return_count : 0;
    rc |= dup_array((void **)&dst->ids, src->ids, src->id_count, sizeof *src->ids);
    dst->id_count = dst->id_cap = rc == 0 ? src->id_count : 0;
    rc |= dup_array((void **)&dst->queues, src->queues, src->queue_count, sizeof *src->queues);
    if (rc == 0) {
        dst->queue_count = dst->queue_cap = src->queue_count;
        /* Each queue owns its entries: copy them too. */
        for (i = 0; i < dst->queue_count; i++) {
            const ReservationQueue *q = &src->queues[i];
            dst->queues[i].items = NULL;
            dst->queues[i].capacity = 0;
            dst->queues[i].count = 0;
            if (rc == 0 && dup_array((void **)&dst->queues[i].items, q->items, q->count,
                                     sizeof *q->items) == 0)
                dst->queues[i].count = dst->queues[i].capacity = q->count;
            else
                rc = -1;
        }
    }
    dst->blocks_applied = src->blocks_applied;
    if (rc == 0) {
        ledger_free(&dst->ledger);
        if (ledger_copy(&dst->ledger, &src->ledger) != LT_OK) {   /* keep_history = 0 */
            ledger_init(&dst->ledger, src->ledger.model, 0);
            rc = -1;
        }
    }
    if (rc != 0) {
        state_free(dst);
        return LT_ERR_MEMORY;
    }
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Queries                                                                  */
/* ------------------------------------------------------------------------ */

CopyStatus *state_copy(LibraryState *st, const char *copy_id)
{
    size_t i;

    for (i = 0; i < st->copy_count; i++) {
        if (strcasecmp(st->copies[i].copy_id, copy_id) == 0)
            return &st->copies[i];
    }
    return NULL;
}

static ReservationQueue *queue_mut(LibraryState *st, const char *book_id, int create)
{
    ReservationQueue *q;
    size_t i;

    for (i = 0; i < st->queue_count; i++) {
        if (strcasecmp(st->queues[i].book_id, book_id) == 0)
            return &st->queues[i];
    }
    if (!create ||
        reserve_one((void **)&st->queues, &st->queue_cap, st->queue_count, sizeof *q) != 0)
        return NULL;
    q = &st->queues[st->queue_count++];
    memset(q, 0, sizeof *q);
    (void)str_copy(q->book_id, sizeof q->book_id, book_id);
    return q;
}

const ReservationQueue *state_queue(const LibraryState *st, const char *book_id)
{
    return queue_mut((LibraryState *)st, book_id, 0);
}

long state_nonce(const LibraryState *st, const char *signer_id)
{
    size_t i;

    for (i = 0; i < st->nonce_count; i++) {
        if (strcmp(st->nonces[i].signer_id, signer_id) == 0)
            return st->nonces[i].nonce;
    }
    return 0;
}

static Status bump_nonce(LibraryState *st, const char *signer_id)
{
    SignerNonce *n;
    size_t i;

    for (i = 0; i < st->nonce_count; i++) {
        if (strcmp(st->nonces[i].signer_id, signer_id) == 0) {
            st->nonces[i].nonce++;
            return LT_OK;
        }
    }
    if (reserve_one((void **)&st->nonces, &st->nonce_cap, st->nonce_count, sizeof *n) != 0)
        return LT_ERR_MEMORY;
    n = &st->nonces[st->nonce_count++];
    (void)str_copy(n->signer_id, sizeof n->signer_id, signer_id);
    n->nonce = 1;
    return LT_OK;
}

size_t state_loans(const LibraryState *st, const char *member_id)
{
    size_t i, n = 0;

    for (i = 0; i < st->copy_count; i++) {
        if (st->copies[i].state == COPY_BORROWED &&
            strcasecmp(st->copies[i].current_holder_id, member_id) == 0)
            n++;
    }
    return n;
}

const CopyStatus *state_available_copy(const LibraryState *st, const char *book_id)
{
    size_t i;

    for (i = 0; i < st->copy_count; i++) {
        if (st->copies[i].state == COPY_AVAILABLE &&
            strcasecmp(st->copies[i].book_id, book_id) == 0)
            return &st->copies[i];
    }
    return NULL;
}

static const CopyStatus *find_copy_in_state(const LibraryState *st, const char *book_id,
                                            const char *member_id, CopyState state)
{
    size_t i;

    for (i = 0; i < st->copy_count; i++) {
        const CopyStatus *c = &st->copies[i];
        if (c->state == state && strcasecmp(c->book_id, book_id) == 0 &&
            strcasecmp(c->current_holder_id, member_id) == 0)
            return c;
    }
    return NULL;
}

const CopyStatus *state_copy_held_for(const LibraryState *st, const char *book_id,
                                      const char *member_id)
{
    return find_copy_in_state(st, book_id, member_id, COPY_RESERVED);
}

const CopyStatus *state_copy_borrowed_by(const LibraryState *st, const char *book_id,
                                         const char *member_id)
{
    return find_copy_in_state(st, book_id, member_id, COPY_BORROWED);
}

int state_in_queue(const LibraryState *st, const char *book_id, const char *member_id,
                   size_t *position)
{
    const ReservationQueue *q = state_queue(st, book_id);
    size_t i;

    if (q == NULL)
        return 0;
    for (i = 0; i < q->count; i++) {
        if (strcasecmp(q->items[i].member_id, member_id) == 0) {
            if (position != NULL)
                *position = i + 1;
            return 1;
        }
    }
    return 0;
}

time_t state_last_return(const LibraryState *st, const char *member_id, const char *book_id)
{
    time_t last = 0;
    size_t i;

    for (i = 0; i < st->return_count; i++) {
        const ReturnEvent *e = &st->returns[i];
        if (strcasecmp(e->member_id, member_id) == 0 && strcasecmp(e->book_id, book_id) == 0 &&
            e->at > last)
            last = e->at;
    }
    return last;
}

static FineAccount *fines_mut(LibraryState *st, const char *member_id, int create)
{
    FineAccount *f;
    size_t i;

    for (i = 0; i < st->fine_count; i++) {
        if (strcasecmp(st->fines[i].member_id, member_id) == 0)
            return &st->fines[i];
    }
    if (!create ||
        reserve_one((void **)&st->fines, &st->fine_cap, st->fine_count, sizeof *f) != 0)
        return NULL;
    f = &st->fines[st->fine_count++];
    memset(f, 0, sizeof *f);
    (void)str_copy(f->member_id, sizeof f->member_id, member_id);
    return f;
}

const FineAccount *state_fines(const LibraryState *st, const char *member_id)
{
    return fines_mut((LibraryState *)st, member_id, 0);
}

long state_fine_due(const LibraryState *st, const char *member_id)
{
    const FineAccount *f = state_fines(st, member_id);
    return f != NULL ? f->assessed - f->paid : 0;
}

long state_accruing_fine(const LibraryState *st, const char *member_id, time_t now)
{
    long total = 0;
    size_t i;

    for (i = 0; i < st->copy_count; i++) {
        const CopyStatus *c = &st->copies[i];
        if (c->state == COPY_BORROWED && strcasecmp(c->current_holder_id, member_id) == 0 &&
            now > c->due_date)
            total += fine_for(c->due_date, now);
    }
    return total;
}

int state_has_record(const LibraryState *st, const char *record_id)
{
    size_t i;

    for (i = 0; i < st->id_count; i++) {
        if (strcmp(st->ids[i], record_id) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Applying records                                                         */
/* ------------------------------------------------------------------------ */

#define REJECT(code, ...) do { snprintf(err, err_cap, __VA_ARGS__); return (code); } while (0)

/** Describes why a copy cannot be borrowed right now. */
static void copy_busy(const CopyStatus *c, char *err, size_t err_cap)
{
    switch (c->state) {
    case COPY_BORROWED:
        snprintf(err, err_cap, "copy %s is BORROWED by %s", c->copy_id, c->current_holder_id);
        break;
    case COPY_RESERVED:
        snprintf(err, err_cap, "copy %s is RESERVED for %s (next in the queue)", c->copy_id,
                 c->current_holder_id);
        break;
    case COPY_LOST:
        snprintf(err, err_cap, "copy %s is LOST", c->copy_id);
        break;
    case COPY_AVAILABLE:
        snprintf(err, err_cap, "copy %s is available", c->copy_id);
        break;
    }
}

/** Checks the action-specific rules. Changes nothing. */
static Status check_action(LibraryState *st, const StateContext *ctx, const Record *rec,
                           CopyStatus **copy_out, char *err, size_t err_cap)
{
    CopyStatus *copy = NULL;
    const Book *book = NULL;

    *copy_out = NULL;
    if (strcmp(rec->copy_id, "-") != 0) {
        copy = state_copy(st, rec->copy_id);
        if (copy == NULL)
            REJECT(LT_ERR_NOT_FOUND, "copy %s is not in copies.txt", rec->copy_id);
        if (strcmp(rec->book_id, "-") != 0 && strcasecmp(copy->book_id, rec->book_id) != 0)
            REJECT(LT_ERR_INPUT, "copy %s belongs to %s, not %s", copy->copy_id, copy->book_id,
                   rec->book_id);
    }
    if (strcmp(rec->book_id, "-") != 0) {
        book = registry_find_book(ctx->books, rec->book_id);
        if (book == NULL)
            REJECT(LT_ERR_NOT_FOUND, "book %s is not in books.txt", rec->book_id);
    }
    if (strcmp(rec->member_id, "-") != 0 && registry_find_member(ctx->members, rec->member_id) == NULL)
        REJECT(LT_ERR_NOT_FOUND, "member %s is not in members.txt", rec->member_id);

    switch (rec->action) {
    case ACT_BORROW:
        if (copy->state == COPY_AVAILABLE ||
            (copy->state == COPY_RESERVED &&
             strcasecmp(copy->current_holder_id, rec->member_id) == 0))
            break;
        copy_busy(copy, err, err_cap);
        return LT_ERR_STATE;

    case ACT_RETURN:
        if (copy->state != COPY_BORROWED)
            REJECT(LT_ERR_STATE, "no outstanding BORROWED record for copy %s (it is %s)",
                   copy->copy_id, copy_state_name(copy->state));
        if (strcasecmp(copy->current_holder_id, rec->member_id) != 0)
            REJECT(LT_ERR_STATE, "copy %s was borrowed by %s, not %s", copy->copy_id,
                   copy->current_holder_id, rec->member_id);
        if (rec->due_date != copy->due_date)
            REJECT(LT_ERR_INPUT, "the due date does not match the loan of %s", copy->copy_id);
        break;

    case ACT_RESERVE: {
        const CopyStatus *free_copy = state_available_copy(st, rec->book_id);
        if (free_copy != NULL)
            REJECT(LT_ERR_STATE, "copy %s of %s is available - borrow it instead of reserving",
                   free_copy->copy_id, rec->book_id);
        if (state_in_queue(st, rec->book_id, rec->member_id, NULL))
            REJECT(LT_ERR_EXISTS, "%s is already in the reservation queue for %s",
                   rec->member_id, rec->book_id);
        if (state_copy_borrowed_by(st, rec->book_id, rec->member_id) != NULL ||
            state_copy_held_for(st, rec->book_id, rec->member_id) != NULL)
            REJECT(LT_ERR_STATE, "%s already has a copy of %s", rec->member_id, rec->book_id);
        break;
    }

    case ACT_RENEW: {
        const ReservationQueue *q = state_queue(st, copy->book_id);
        if (copy->state != COPY_BORROWED ||
            strcasecmp(copy->current_holder_id, rec->member_id) != 0)
            REJECT(LT_ERR_STATE, "copy %s is not on loan to %s", copy->copy_id, rec->member_id);
        if (q != NULL && q->count > 0)
            REJECT(LT_ERR_STATE, "%s cannot be renewed: %s is waiting for %s (reservation "
                                 "queue)", copy->copy_id, q->items[0].member_id, copy->book_id);
        if (copy->renewals >= ctx->rules->max_renewals)
            REJECT(LT_ERR_LIMIT, "copy %s has already been renewed %d time(s) (maximum %d)",
                   copy->copy_id, copy->renewals, ctx->rules->max_renewals);
        if (rec->timestamp > copy->due_date)
            REJECT(LT_ERR_STATE, "copy %s is overdue - it must be returned, not renewed",
                   copy->copy_id);
        if (rec->due_date <= copy->due_date || rec->due_date > copy->due_date + MAX_RENEWAL_EXTENSION)
            REJECT(LT_ERR_INPUT, "the new due date is not a valid extension");
        break;
    }

    case ACT_OVERDUE:
        if (copy->state != COPY_BORROWED ||
            strcasecmp(copy->current_holder_id, rec->member_id) != 0)
            REJECT(LT_ERR_STATE, "copy %s is not on loan to %s", copy->copy_id, rec->member_id);
        if (copy->overdue_flagged)
            REJECT(LT_ERR_EXISTS, "copy %s is already flagged OVERDUE", copy->copy_id);
        if (rec->due_date != copy->due_date)
            REJECT(LT_ERR_INPUT, "the due date does not match the loan of %s", copy->copy_id);
        break;

    case ACT_LOST:
        if (copy->state != COPY_AVAILABLE && copy->state != COPY_BORROWED)
            REJECT(LT_ERR_STATE, "only AVAILABLE or BORROWED copies can be marked LOST (%s is %s)",
                   copy->copy_id, copy_state_name(copy->state));
        break;

    case ACT_TRANSFER:
        if (registry_find_member(ctx->members, rec->tx.to) == NULL)
            REJECT(LT_ERR_NOT_FOUND, "recipient %s is not in members.txt", rec->tx.to);
        break;

    case ACT_FINE: {
        long due = state_fine_due(st, rec->member_id);
        if (rec->tx.amount > due)
            REJECT(LT_ERR_INSUFFICIENT, "fine payment of %ld exceeds the %ld coin(s) %s owes",
                   rec->tx.amount, due, rec->member_id);
        break;
    }

    case ACT_NONE:
        REJECT(LT_ERR_FORMAT, "unknown action");
    }
    *copy_out = copy;
    return LT_OK;
}

static Status add_return_event(LibraryState *st, const Record *rec)
{
    ReturnEvent *e;

    if (reserve_one((void **)&st->returns, &st->return_cap, st->return_count, sizeof *e) != 0)
        return LT_ERR_MEMORY;
    e = &st->returns[st->return_count++];
    (void)str_copy(e->member_id, sizeof e->member_id, rec->member_id);
    (void)str_copy(e->book_id, sizeof e->book_id, rec->book_id);
    e->at = rec->timestamp;
    return LT_OK;
}

static void queue_remove(ReservationQueue *q, size_t i)
{
    memmove(&q->items[i], &q->items[i + 1], (q->count - i - 1) * sizeof *q->items);
    q->count--;
}

/** Applies an already-checked record. */
static Status mutate(LibraryState *st, const Record *rec, CopyStatus *copy, int block_index)
{
    int pending = block_index == STATE_PENDING;
    ReservationQueue *q;
    size_t pos;

    switch (rec->action) {
    case ACT_BORROW:
        q = queue_mut(st, copy->book_id, 0);
        if (q != NULL && state_in_queue(st, copy->book_id, rec->member_id, &pos))
            queue_remove(q, pos - 1);   /* the member no longer needs to wait */
        copy->state = COPY_BORROWED;
        (void)str_copy(copy->current_holder_id, sizeof copy->current_holder_id, rec->member_id);
        copy->due_date = rec->due_date;
        copy->borrowed_at = rec->timestamp;
        copy->hold_reserved_at = 0;
        copy->renewals = 0;
        copy->overdue_flagged = 0;
        break;

    case ACT_RETURN: {
        FineAccount *f = fines_mut(st, rec->member_id, rec->fine_amount > 0);
        if (add_return_event(st, rec) != LT_OK)
            return LT_ERR_MEMORY;
        if (rec->fine_amount > 0) {
            if (f == NULL)
                return LT_ERR_MEMORY;
            f->assessed += rec->fine_amount;
        }
        copy->condition = rec->condition;
        copy->due_date = 0;
        copy->renewals = 0;
        copy->overdue_flagged = 0;
        q = queue_mut(st, copy->book_id, 0);
        if (q != NULL && q->count > 0) {
            /* Offer the copy to the member who has waited longest. */
            copy->state = COPY_RESERVED;
            (void)str_copy(copy->current_holder_id, sizeof copy->current_holder_id,
                           q->items[0].member_id);
            copy->hold_reserved_at = q->items[0].reservation_date;
            queue_remove(q, 0);
        } else {
            copy->state = COPY_AVAILABLE;
            copy->current_holder_id[0] = '\0';
        }
        break;
    }

    case ACT_RESERVE: {
        QueueEntry *e;
        q = queue_mut(st, rec->book_id, 1);
        if (q == NULL ||
            reserve_one((void **)&q->items, &q->capacity, q->count, sizeof *e) != 0)
            return LT_ERR_MEMORY;
        e = &q->items[q->count++];
        memset(e, 0, sizeof *e);
        (void)str_copy(e->member_id, sizeof e->member_id, rec->member_id);
        (void)str_copy(e->record_id, sizeof e->record_id, rec->record_id);
        e->reservation_date = rec->timestamp;
        e->pending = pending;
        break;
    }

    case ACT_RENEW:
        copy->due_date = rec->due_date;
        copy->renewals++;
        break;

    case ACT_OVERDUE:
        copy->overdue_flagged = 1;
        break;

    case ACT_LOST:
        copy->state = COPY_LOST;
        copy->condition = COND_LOST;
        copy->current_holder_id[0] = '\0';
        copy->due_date = 0;
        copy->renewals = 0;
        copy->overdue_flagged = 0;
        break;

    case ACT_FINE: {
        FineAccount *f = fines_mut(st, rec->member_id, 1);
        if (f == NULL)
            return LT_ERR_MEMORY;
        f->paid += rec->tx.amount;
        break;
    }

    case ACT_TRANSFER:
    case ACT_NONE:
        break;
    }
    if (copy != NULL && pending)
        copy->pending = 1;
    return LT_OK;
}

Status state_apply_record(LibraryState *st, const StateContext *ctx, const Record *rec,
                          int block_index, char *err, size_t err_cap)
{
    CopyStatus *copy = NULL;
    const char *why = NULL;
    long expected;
    Status st_code;

    err[0] = '\0';
    if (!record_fields_valid(rec, &why))
        REJECT(LT_ERR_FORMAT, "%s", why);
    if (state_has_record(st, rec->record_id))
        REJECT(LT_ERR_EXISTS, "record ID %s was already used (duplicate / replay)",
               rec->record_id);

    /* Replay protection: the request must carry the signer's next nonce. */
    expected = state_nonce(st, rec->signer_id);
    if (rec->nonce != expected)
        REJECT(LT_ERR_NONCE, "nonce %ld %s for %s (expected %ld)", rec->nonce,
               rec->nonce < expected ? "was already used" : "is out of order", rec->signer_id,
               expected);

    st_code = check_action(st, ctx, rec, &copy, err, err_cap);
    if (st_code != LT_OK)
        return st_code;

    /* Token movement last: the ledger validates before it changes anything. */
    if (rec->tx.type != TX_NONE) {
        char txid[HASH_HEX_LEN];
        st_code = tx_compute_id(&rec->tx, txid);
        if (st_code == LT_OK)
            st_code = ledger_apply(&st->ledger, &rec->tx, txid, block_index, err, err_cap);
        if (st_code != LT_OK)
            return st_code;
    }

    st_code = mutate(st, rec, copy, block_index);
    if (st_code == LT_OK)
        st_code = bump_nonce(st, rec->signer_id);
    if (st_code == LT_OK &&
        reserve_one((void **)&st->ids, &st->id_cap, st->id_count, sizeof *st->ids) == 0)
        memcpy(st->ids[st->id_count++], rec->record_id, REQUEST_ID_LEN);
    else if (st_code == LT_OK)
        st_code = LT_ERR_MEMORY;
    return st_code;
}

Status state_apply_block(LibraryState *st, const StateContext *ctx, const Block *block,
                         char *err, size_t err_cap, size_t *bad_record)
{
    size_t r;
    Status s;

    for (r = 0; r < block->record_count; r++) {
        s = state_apply_record(st, ctx, &block->records[r], block->index, err, err_cap);
        if (s != LT_OK) {
            if (bad_record != NULL)
                *bad_record = r;
            return s;
        }
    }
    if (block->reward.type != TX_NONE) {
        s = ledger_apply(&st->ledger, &block->reward, block->transaction_id, block->index,
                         err, err_cap);
        if (s != LT_OK) {
            if (bad_record != NULL)
                *bad_record = block->record_count;
            return s;
        }
    }
    st->blocks_applied++;
    return LT_OK;
}

Status state_build(LibraryState *st, const StateContext *ctx, const Blockchain *chain,
                   LedgerModel model, int keep_history, long *bad_block,
                   char *err, size_t err_cap)
{
    size_t i;
    Status s = state_init(st, ctx, model, keep_history);

    *bad_block = -1;
    err[0] = '\0';
    if (s != LT_OK)
        return s;
    for (i = 0; i < chain->length; i++) {
        char why[256];
        size_t bad_record = 0;

        s = state_apply_block(st, ctx, &chain->blocks[i], why, sizeof why, &bad_record);
        if (s != LT_OK) {
            *bad_block = (long)i;
            snprintf(err, err_cap, "block #%zu record %zu: %s", i, bad_record + 1, why);
            return LT_ERR_CHAIN_INVALID;
        }
    }
    return LT_OK;
}
