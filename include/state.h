/**
 * @file state.h
 * @brief Library state derived from the chain: copy inventory, reservation
 *        queues, nonces, fines, return history and the token ledger.
 *
 * The chain is the single source of truth. This state is rebuilt by
 * replaying every confirmed record in order through state_apply_record(),
 * which enforces all business rules:
 *
 *   Copy availability state machine
 *     AVAILABLE -> BORROWED            borrow
 *     RESERVED  -> BORROWED            borrow by the member the copy is held for
 *     BORROWED  -> AVAILABLE           return, nobody waiting for the title
 *     BORROWED  -> RESERVED            return, copy offered to the head of the
 *                                      title's reservation queue (FIFO)
 *     AVAILABLE / BORROWED -> LOST     librarian override with a reason code
 *   Any other transition is rejected.
 *
 * The same functions build the "projected" state used to validate new
 * requests: the confirmed state plus every request still in the pending
 * pool, applied with block index STATE_PENDING.
 */
#ifndef LT_STATE_H
#define LT_STATE_H

#include <stddef.h>
#include <time.h>

#include "blockchain.h"
#include "common.h"
#include "ledger.h"
#include "record.h"
#include "registry.h"

#define STATE_PENDING (-1)

/** Configurable lending rules (persisted in state.dat). */
typedef struct {
    int loan_days;       /* default loan period                          */
    int renewal_days;    /* each renewal extends the due date by this    */
    int max_renewals;
    int max_loans;       /* copies a member may hold at once (fraud rule) */
} LendingRules;

typedef enum {
    COPY_AVAILABLE = 0,
    COPY_BORROWED  = 1,
    COPY_RESERVED  = 2,   /* held for the member at the head of the queue */
    COPY_LOST      = 3
} CopyState;

/** One physical copy (the Copy structure from the specification). */
typedef struct {
    char      copy_id[COPY_ID_LEN];
    char      book_id[BOOK_ID_LEN];
    Condition condition;
    CopyState state;
    char      current_holder_id[MEMBER_ID_LEN];  /* borrower, or member it is held for */
    time_t    due_date;
    time_t    borrowed_at;
    time_t    hold_reserved_at;   /* reservation date of the member it is held for */
    int       renewals;
    int       overdue_flagged;
    int       pending;            /* changed by a request that is not mined yet */
} CopyStatus;

typedef struct {
    char   member_id[MEMBER_ID_LEN];
    time_t reservation_date;
    char   record_id[REQUEST_ID_LEN];
    int    pending;
} QueueEntry;

/** FIFO reservation queue for one title. */
typedef struct {
    char        book_id[BOOK_ID_LEN];
    QueueEntry *items;
    size_t      count, capacity;
} ReservationQueue;

typedef struct { char signer_id[SIGNER_ID_LEN]; long nonce; } SignerNonce;
typedef struct { char member_id[MEMBER_ID_LEN]; long assessed, paid; } FineAccount;
typedef struct { char member_id[MEMBER_ID_LEN]; char book_id[BOOK_ID_LEN]; time_t at; } ReturnEvent;

typedef struct {
    CopyStatus       *copies;   size_t copy_count,   copy_cap;
    ReservationQueue *queues;   size_t queue_count,  queue_cap;
    SignerNonce      *nonces;   size_t nonce_count,  nonce_cap;
    FineAccount      *fines;    size_t fine_count,   fine_cap;
    ReturnEvent      *returns;  size_t return_count, return_cap;
    char (*ids)[REQUEST_ID_LEN]; size_t id_count,    id_cap;   /* applied record IDs */
    Ledger            ledger;
    size_t            blocks_applied;
} LibraryState;

/** Registries and rules the state needs to check records. */
typedef struct {
    const BookRegistry   *books;
    const CopyRegistry   *copies;
    const MemberRegistry *members;
    const LendingRules   *rules;
} StateContext;

Status state_init(LibraryState *st, const StateContext *ctx, LedgerModel model, int keep_history);
void   state_free(LibraryState *st);

/**
 * Deep copy used for projections and trial blocks. Transaction histories
 * are not copied (the copy has keep_history = 0).
 */
Status state_clone(LibraryState *dst, const LibraryState *src);

/**
 * Validates one record against the current state and applies it. Nothing
 * changes if it is rejected; err explains why.
 */
Status state_apply_record(LibraryState *st, const StateContext *ctx, const Record *rec,
                          int block_index, char *err, size_t err_cap);

/** Applies all records of a block, then its reward transaction. */
Status state_apply_block(LibraryState *st, const StateContext *ctx, const Block *block,
                         char *err, size_t err_cap, size_t *bad_record);

/** Rebuilds the state from the whole chain. *bad_block = -1 when all is valid. */
Status state_build(LibraryState *st, const StateContext *ctx, const Blockchain *chain,
                   LedgerModel model, int keep_history, long *bad_block,
                   char *err, size_t err_cap);

/* ---- Queries -------------------------------------------------------------- */
CopyStatus             *state_copy(LibraryState *st, const char *copy_id);
const ReservationQueue *state_queue(const LibraryState *st, const char *book_id);
long   state_nonce(const LibraryState *st, const char *signer_id);
size_t state_loans(const LibraryState *st, const char *member_id);
const CopyStatus *state_available_copy(const LibraryState *st, const char *book_id);
const CopyStatus *state_copy_held_for(const LibraryState *st, const char *book_id,
                                      const char *member_id);
const CopyStatus *state_copy_borrowed_by(const LibraryState *st, const char *book_id,
                                         const char *member_id);
int    state_in_queue(const LibraryState *st, const char *book_id, const char *member_id,
                      size_t *position);
time_t state_last_return(const LibraryState *st, const char *member_id, const char *book_id);
const FineAccount *state_fines(const LibraryState *st, const char *member_id);
long   state_fine_due(const LibraryState *st, const char *member_id);
long   state_accruing_fine(const LibraryState *st, const char *member_id, time_t now);
int    state_has_record(const LibraryState *st, const char *record_id);

const char *copy_state_name(CopyState s);

/** Fine for a loan: FINE_PER_DAY for each day (or part of a day) late. */
long fine_for(time_t due_date, time_t at);

#endif /* LT_STATE_H */
