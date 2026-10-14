/**
 * @file pool.c
 * @brief Pending pool storage, prioritisation and lookups.
 */
#include "pool.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "util.h"

void pool_init(PendingPool *pool)
{
    memset(pool, 0, sizeof *pool);
    pool->next_seq = 1;
}

void pool_free(PendingPool *pool)
{
    free(pool->items);
    pool_init(pool);
}

Status pool_add(PendingPool *pool, const Request *req)
{
    if (pool->count == pool->capacity) {
        size_t cap = pool->capacity ? pool->capacity * 2 : 16;
        Request *grown;

        if (cap > SIZE_MAX / sizeof *grown)
            return LT_ERR_MEMORY;
        grown = realloc(pool->items, cap * sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        pool->items = grown;
        pool->capacity = cap;
    }
    pool->items[pool->count] = *req;
    if (pool->items[pool->count].seq == 0)
        pool->items[pool->count].seq = pool->next_seq;
    if (pool->items[pool->count].seq >= pool->next_seq)
        pool->next_seq = pool->items[pool->count].seq + 1;
    pool->count++;
    return LT_OK;
}

void pool_remove_at(PendingPool *pool, size_t index)
{
    if (index >= pool->count)
        return;
    memmove(&pool->items[index], &pool->items[index + 1],
            (pool->count - index - 1) * sizeof *pool->items);
    pool->count--;
}

Status pool_copy(PendingPool *dst, const PendingPool *src)
{
    pool_init(dst);
    dst->next_seq = src->next_seq;
    if (src->count == 0)
        return LT_OK;
    dst->items = malloc(src->count * sizeof *dst->items);
    if (dst->items == NULL)
        return LT_ERR_MEMORY;
    memcpy(dst->items, src->items, src->count * sizeof *dst->items);
    dst->count = dst->capacity = src->count;
    return LT_OK;
}

/**
 * Ordering rules: (1) overdue-related requests first, (2) earliest
 * reservation / submission date, (3) arrival order. A total order, so the
 * result is the same every time (qsort is not stable on its own).
 */
static int compare_requests(const void *a, const void *b)
{
    const Request *x = a, *y = b;

    if (x->priority != y->priority)
        return x->priority < y->priority ? -1 : 1;
    if (x->sort_time != y->sort_time)
        return x->sort_time < y->sort_time ? -1 : 1;
    if (x->seq != y->seq)
        return x->seq < y->seq ? -1 : 1;
    return 0;
}

void pool_sort(PendingPool *pool)
{
    if (pool->count > 1)
        qsort(pool->items, pool->count, sizeof *pool->items, compare_requests);
}

long pool_find(const PendingPool *pool, const char *id_or_prefix)
{
    size_t len = strlen(id_or_prefix), i;
    long found = -1;

    for (i = 0; i < pool->count; i++) {
        if (strcasecmp(pool->items[i].rec.record_id, id_or_prefix) == 0)
            return (long)i;
    }
    if (len < 4)
        return -1;
    for (i = 0; i < pool->count; i++) {
        if (strncasecmp(pool->items[i].rec.record_id, id_or_prefix, len) == 0) {
            if (found >= 0)
                return -2;
            found = (long)i;
        }
    }
    return found;
}

int pool_contains_id(const PendingPool *pool, const char *record_id)
{
    size_t i;

    for (i = 0; i < pool->count; i++) {
        if (strcmp(pool->items[i].rec.record_id, record_id) == 0)
            return 1;
    }
    return 0;
}

size_t pool_count_status(const PendingPool *pool, RequestStatus status)
{
    size_t i, n = 0;

    for (i = 0; i < pool->count; i++) {
        if (pool->items[i].status == status)
            n++;
    }
    return n;
}

const char *request_status_name(RequestStatus s)
{
    switch (s) {
    case REQ_PENDING:    return "PENDING";
    case REQ_SUSPICIOUS: return "SUSPICIOUS";
    case REQ_CONFIRMED:  return "CONFIRMED";
    }
    return "?";
}

static const struct {
    unsigned    flag;
    const char *name;
    const char *explanation;
} FLAGS[] = {
    { FLAG_EXCESS_LOANS,   "EXCESSIVE_BORROWS",
      "member would hold more than the maximum number of copies at once" },
    { FLAG_RAPID_REBORROW, "RAPID_REBORROW",
      "same member re-borrows the same title within 24 hours of returning it" },
    { FLAG_DUPLICATE,      "DUPLICATE_REQUEST",
      "the same request_id already exists on the chain or in the pending pool" },
    { FLAG_CONDITION,      "CONDITION_DOWNGRADE",
      "returned copy's condition dropped more than one level without a reason code" },
};

void flags_describe(unsigned flags, char *buf, size_t cap)
{
    size_t i, used = 0;

    buf[0] = '\0';
    for (i = 0; i < sizeof FLAGS / sizeof FLAGS[0]; i++) {
        if (flags & FLAGS[i].flag) {
            int n = snprintf(buf + used, cap - used, "%s%s", used ? "," : "", FLAGS[i].name);
            if (n < 0 || (size_t)n >= cap - used)
                return;
            used += (size_t)n;
        }
    }
    if (used == 0)
        snprintf(buf, cap, "-");
}

const char *flag_explanation(unsigned flag)
{
    size_t i;

    for (i = 0; i < sizeof FLAGS / sizeof FLAGS[0]; i++) {
        if (FLAGS[i].flag == flag)
            return FLAGS[i].explanation;
    }
    return "";
}
