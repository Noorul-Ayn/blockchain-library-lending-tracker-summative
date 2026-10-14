/**
 * @file pool.h
 * @brief The pending pool: signed requests waiting to be mined.
 *
 * Every lending action and token transaction enters the pool first. Each
 * request has a status:
 *   PENDING     waiting to be mined
 *   SUSPICIOUS  flagged by a fraud heuristic; never mined until an
 *               administrator approves it (approve_suspicious) or discards
 *               it (reject_suspicious)
 *   CONFIRMED   included in a block (shown while mining, then removed)
 *
 * Prioritisation (pool_sort): overdue-related requests first (overdue flags,
 * returns of overdue copies, fine settlements), then by reservation date -
 * the member who has waited longest first - and finally by arrival order.
 * The miner always takes requests from the top of this ordering.
 */
#ifndef LT_POOL_H
#define LT_POOL_H

#include <stddef.h>
#include <time.h>

#include "common.h"
#include "record.h"

typedef enum {
    REQ_PENDING    = 0,
    REQ_SUSPICIOUS = 1,
    REQ_CONFIRMED  = 2
} RequestStatus;

/* Fraud heuristics (bit flags). */
#define FLAG_EXCESS_LOANS    0x01u   /* more than the maximum copies at once      */
#define FLAG_RAPID_REBORROW  0x02u   /* same title re-borrowed within 24 hours     */
#define FLAG_DUPLICATE       0x04u   /* request_id already on the chain / in pool  */
#define FLAG_CONDITION       0x08u   /* condition dropped >1 level, no reason code */

#define PRIORITY_OVERDUE 0
#define PRIORITY_NORMAL  1

typedef struct {
    Record        rec;          /* the signed request (becomes the record)  */
    RequestStatus status;
    unsigned      flags;
    int           priority;     /* PRIORITY_OVERDUE or PRIORITY_NORMAL       */
    time_t        sort_time;    /* reservation date, or submission time      */
    unsigned long seq;          /* arrival order                             */
} Request;

typedef struct {
    Request      *items;
    size_t        count, capacity;
    unsigned long next_seq;
} PendingPool;

void   pool_init(PendingPool *pool);
void   pool_free(PendingPool *pool);
Status pool_add(PendingPool *pool, const Request *req);   /* assigns seq if 0 */
void   pool_remove_at(PendingPool *pool, size_t index);
void   pool_sort(PendingPool *pool);
Status pool_copy(PendingPool *dst, const PendingPool *src);

/**
 * Finds a request by exact ID or unique ID prefix (at least 4 characters).
 * @return the index, -1 if none matches, -2 if the prefix is ambiguous.
 */
long pool_find(const PendingPool *pool, const char *id_or_prefix);

int    pool_contains_id(const PendingPool *pool, const char *record_id);
size_t pool_count_status(const PendingPool *pool, RequestStatus status);

const char *request_status_name(RequestStatus s);

/** Writes the names of the flags set, e.g. "EXCESSIVE_BORROWS, DUPLICATE". */
void flags_describe(unsigned flags, char *buf, size_t cap);

/** One-line explanation of each flag, for fraud_review. */
const char *flag_explanation(unsigned flag);

#endif /* LT_POOL_H */
