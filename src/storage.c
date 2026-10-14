/**
 * @file storage.c
 * @brief Reading and atomically writing chain.dat, pending.dat and state.dat.
 */
#include "storage.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

#define CHAIN_HEADER   "# LIBCHAIN v3"
#define POOL_HEADER    "# LIBPENDING v3"
#define STATE_HEADER   "# LIBSTATE v3"
#define BLOCK_FIELDS   11   /* after the "B|" prefix */
#define POOL_FIELDS    (5 + RECORD_FIELD_COUNT)   /* after the "Q|" prefix */

/* ------------------------------------------------------------------------ */
/* Atomic writes                                                            */
/* ------------------------------------------------------------------------ */

typedef int (*WriteBody)(FILE *fp, const void *ctx);

/** Writes path.tmp, fsyncs it and renames it over path. */
static Status write_atomic(const char *path, WriteBody body, const void *ctx)
{
    char tmp_path[LT_PATH_MAX];
    int n = snprintf(tmp_path, sizeof tmp_path, "%s.tmp", path), failed;
    FILE *fp;

    if (n < 0 || (size_t)n >= sizeof tmp_path)
        return LT_ERR_INPUT;
    fp = fopen(tmp_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: cannot write '%s': %s\n", tmp_path, strerror(errno));
        return LT_ERR_IO;
    }
    failed = body(fp, ctx) != 0;
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        failed = 1;
    if (fclose(fp) != 0)
        failed = 1;
    if (failed || rename(tmp_path, path) != 0) {
        fprintf(stderr, "ERROR: could not save '%s'.\n", path);
        unlink(tmp_path);
        return LT_ERR_IO;
    }
    return LT_OK;
}

/** Reads one line of any length into *buf (grown as needed). */
static int read_long_line(FILE *fp, char **buf, size_t *cap)
{
    size_t len = 0;

    if (*buf == NULL) {
        *cap = LT_LINE_MAX;
        *buf = malloc(*cap);
        if (*buf == NULL)
            return -1;
    }
    for (;;) {
        if (fgets(*buf + len, (int)(*cap - len), fp) == NULL)
            return len > 0 ? 0 : -1;
        len += strlen(*buf + len);
        if (len > 0 && (*buf)[len - 1] == '\n')
            break;
        if (len + 1 >= *cap) {
            char *grown;
            if (*cap > 16 * RECORD_TEXT_MAX)
                return -1;
            grown = realloc(*buf, *cap * 2);
            if (grown == NULL)
                return -1;
            *buf = grown;
            *cap *= 2;
        }
    }
    while (len > 0 && ((*buf)[len - 1] == '\n' || (*buf)[len - 1] == '\r'))
        (*buf)[--len] = '\0';
    return 0;
}

/* ------------------------------------------------------------------------ */
/* chain.dat                                                                */
/* ------------------------------------------------------------------------ */

static int write_record_line(FILE *fp, const char *tag, const char *prefix, const Record *rec)
{
    char *text = malloc(RECORD_TEXT_MAX);
    int ok;

    if (text == NULL)
        return -1;
    ok = record_serialize(rec, text, RECORD_TEXT_MAX) >= 0 &&
         fprintf(fp, "%s|%s%s\n", tag, prefix, text) >= 0;
    free(text);
    return ok ? 0 : -1;
}

static int write_chain_body(FILE *fp, const void *ctx)
{
    const Blockchain *chain = ctx;
    char tx_text[TX_TEXT_MAX];
    size_t i, r;

    if (fprintf(fp, "%s\n# B|index|timestamp|record_count|previous_hash|merkle_root|sealed_by|"
                    "token_reward|transaction_id|difficulty|nonce|hash\n"
                    "# X|reward transaction   R|lending record (see README)\n",
                CHAIN_HEADER) < 0)
        return -1;
    for (i = 0; i < chain->length; i++) {
        const Block *b = &chain->blocks[i];

        if (tx_serialize(&b->reward, tx_text, sizeof tx_text) < 0 ||
            fprintf(fp, "B|%d|%lld|%zu|%s|%s|%s|%ld|%s|%d|%llu|%s\nX|%s\n", b->index,
                    (long long)b->timestamp, b->record_count, b->previous_hash, b->merkle_root,
                    b->sealed_by, b->token_reward, b->transaction_id, b->difficulty, b->nonce,
                    b->hash, tx_text) < 0)
            return -1;
        for (r = 0; r < b->record_count; r++) {
            if (write_record_line(fp, "R", "", &b->records[r]) != 0)
                return -1;
        }
    }
    return 0;
}

Status storage_save_chain(const char *path, const Blockchain *chain)
{
    return write_atomic(path, write_chain_body, chain);
}

static Status parse_block_line(char *line, Block *b, size_t *expected_records)
{
    char *f[BLOCK_FIELDS];
    long index, count, reward, difficulty;
    long long ts;
    unsigned long long nonce;
    char *end;

    block_init(b);
    if (str_split(line, '|', f, BLOCK_FIELDS) != BLOCK_FIELDS)
        return LT_ERR_FORMAT;
    if (parse_long(f[0], 0, INT_MAX, &index) != 0 ||
        parse_long(f[2], 0, MAX_BLOCK_CAPACITY, &count) != 0 ||
        parse_long(f[6], 0, 100000000L, &reward) != 0 ||
        parse_long(f[8], 0, 64, &difficulty) != 0)
        return LT_ERR_FORMAT;
    ts = strtoll(f[1], &end, 10);
    if (*f[1] == '\0' || *end != '\0' || ts < 0)
        return LT_ERR_FORMAT;
    errno = 0;
    nonce = strtoull(f[9], &end, 10);
    if (*f[9] == '\0' || *end != '\0' || errno != 0)
        return LT_ERR_FORMAT;
    if (!is_hex_string(f[3], HASH_HEX_LEN - 1) || !is_hex_string(f[4], HASH_HEX_LEN - 1) ||
        !is_hex_string(f[7], HASH_HEX_LEN - 1) || !is_hex_string(f[10], HASH_HEX_LEN - 1) ||
        *f[5] == '\0' || !str_is_safe_field(f[5]) ||
        str_copy(b->sealed_by, sizeof b->sealed_by, f[5]) != 0)
        return LT_ERR_FORMAT;
    b->index = (int)index;
    b->timestamp = (time_t)ts;
    b->record_count = 0;             /* records are attached as they are read */
    *expected_records = (size_t)count;
    (void)str_copy(b->previous_hash, sizeof b->previous_hash, f[3]);
    (void)str_copy(b->merkle_root, sizeof b->merkle_root, f[4]);
    b->token_reward = reward;
    (void)str_copy(b->transaction_id, sizeof b->transaction_id, f[7]);
    b->difficulty = (int)difficulty;
    b->nonce = nonce;
    (void)str_copy(b->hash, sizeof b->hash, f[10]);
    return LT_OK;
}

Status storage_load_chain(const char *path, Blockchain *chain, char *err, size_t err_cap)
{
    FILE *fp = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0, line_no = 0, expected_records = 0;
    int have_block = 0, have_reward = 0, header_seen = 0;
    Block current;
    Status st = LT_OK;

    chain_init(chain);
    err[0] = '\0';
    if (fp == NULL)
        return errno == ENOENT ? LT_OK : LT_ERR_IO;
    block_init(&current);

    while (st == LT_OK && read_long_line(fp, &line, &cap) == 0) {
        line_no++;
        if (line_no == 1) {
            if (strncmp(line, "# LIBCHAIN v", 12) == 0 && strcmp(line, CHAIN_HEADER) != 0) {
                snprintf(err, err_cap, "%s uses an older format (%s); this version needs v3",
                         CHAIN_FILE, line + 2);
                st = LT_ERR_FORMAT;
                break;
            }
            header_seen = strcmp(line, CHAIN_HEADER) == 0;
            if (!header_seen) {
                snprintf(err, err_cap, "line 1: missing '%s' header", CHAIN_HEADER);
                st = LT_ERR_FORMAT;
                break;
            }
            continue;
        }
        if (line[0] == '#' || line[0] == '\0')
            continue;

        if (strncmp(line, "B|", 2) == 0) {
            if (have_block) {
                if (!have_reward || current.record_count != expected_records) {
                    snprintf(err, err_cap, "line %zu: block #%d is incomplete", line_no,
                             current.index);
                    st = LT_ERR_FORMAT;
                    break;
                }
                st = chain_push(chain, &current);
                if (st != LT_OK)
                    break;
            }
            st = parse_block_line(line + 2, &current, &expected_records);
            if (st != LT_OK) {
                snprintf(err, err_cap, "line %zu: malformed block header", line_no);
                st = LT_ERR_FORMAT;
                break;
            }
            have_block = 1;
            have_reward = 0;
        } else if (strncmp(line, "X|", 2) == 0 && have_block && !have_reward) {
            if (tx_parse(line + 2, &current.reward) != LT_OK) {
                snprintf(err, err_cap, "line %zu: malformed reward transaction", line_no);
                st = LT_ERR_FORMAT;
                break;
            }
            have_reward = 1;
        } else if (strncmp(line, "R|", 2) == 0 && have_block && have_reward) {
            char *f[RECORD_FIELD_COUNT + 1];
            Record rec;
            size_t n = str_split(line + 2, '|', f, RECORD_FIELD_COUNT + 1);

            if (current.record_count >= expected_records ||
                record_parse(f, n, &rec) != LT_OK ||
                block_add_record(&current, &rec) != LT_OK) {
                snprintf(err, err_cap, "line %zu: malformed or unexpected record", line_no);
                st = LT_ERR_FORMAT;
                break;
            }
        } else {
            snprintf(err, err_cap, "line %zu: unexpected line", line_no);
            st = LT_ERR_FORMAT;
            break;
        }
    }
    if (st == LT_OK && have_block) {
        if (!have_reward || current.record_count != expected_records) {
            snprintf(err, err_cap, "the last block is incomplete");
            st = LT_ERR_FORMAT;
        } else {
            st = chain_push(chain, &current);
        }
    }
    if (st == LT_OK && ferror(fp))
        st = LT_ERR_IO;
    block_free(&current);
    free(line);
    fclose(fp);
    if (st != LT_OK)
        chain_free(chain);
    return st;
}

/* ------------------------------------------------------------------------ */
/* pending.dat                                                              */
/* ------------------------------------------------------------------------ */

static int write_pool_body(FILE *fp, const void *ctx)
{
    const PendingPool *pool = ctx;
    size_t i;

    if (fprintf(fp, "%s\n# Q|status|flags|priority|sort_time|seq|record fields\n",
                POOL_HEADER) < 0)
        return -1;
    for (i = 0; i < pool->count; i++) {
        const Request *q = &pool->items[i];
        char prefix[128];

        snprintf(prefix, sizeof prefix, "%s|%u|%d|%lld|%lu|", request_status_name(q->status),
                 q->flags, q->priority, (long long)q->sort_time, q->seq);
        if (write_record_line(fp, "Q", prefix, &q->rec) != 0)
            return -1;
    }
    return 0;
}

Status storage_save_pool(const char *path, const PendingPool *pool)
{
    return write_atomic(path, write_pool_body, pool);
}

Status storage_load_pool(const char *path, PendingPool *pool, char *err, size_t err_cap)
{
    FILE *fp = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0, line_no = 0;
    Status st = LT_OK;

    pool_init(pool);
    err[0] = '\0';
    if (fp == NULL)
        return errno == ENOENT ? LT_OK : LT_ERR_IO;
    while (st == LT_OK && read_long_line(fp, &line, &cap) == 0) {
        char *f[POOL_FIELDS + 1];
        Request q;
        long flags, priority, seq;
        long long sort_time;
        char *end;
        size_t n;

        line_no++;
        if (line_no == 1) {
            if (strcmp(line, POOL_HEADER) != 0) {
                snprintf(err, err_cap, "line 1: missing '%s' header", POOL_HEADER);
                st = LT_ERR_FORMAT;
            }
            continue;
        }
        if (line[0] == '#' || line[0] == '\0')
            continue;
        memset(&q, 0, sizeof q);
        if (strncmp(line, "Q|", 2) != 0) {
            snprintf(err, err_cap, "line %zu: unexpected line", line_no);
            st = LT_ERR_FORMAT;
            break;
        }
        n = str_split(line + 2, '|', f, POOL_FIELDS + 1);
        if (n != POOL_FIELDS) {
            snprintf(err, err_cap, "line %zu: wrong number of fields", line_no);
            st = LT_ERR_FORMAT;
            break;
        }
        if (strcmp(f[0], "PENDING") == 0)
            q.status = REQ_PENDING;
        else if (strcmp(f[0], "SUSPICIOUS") == 0)
            q.status = REQ_SUSPICIOUS;
        else
            st = LT_ERR_FORMAT;
        sort_time = strtoll(f[3], &end, 10);
        if (st != LT_OK || parse_long(f[1], 0, 255, &flags) != 0 ||
            parse_long(f[2], 0, 1, &priority) != 0 || *f[3] == '\0' || *end != '\0' ||
            parse_long(f[4], 1, LONG_MAX, &seq) != 0 ||
            record_parse(f + 5, RECORD_FIELD_COUNT, &q.rec) != LT_OK) {
            snprintf(err, err_cap, "line %zu: malformed pending request", line_no);
            st = LT_ERR_FORMAT;
            break;
        }
        q.flags = (unsigned)flags;
        q.priority = (int)priority;
        q.sort_time = (time_t)sort_time;
        q.seq = (unsigned long)seq;
        st = pool_add(pool, &q);
    }
    free(line);
    fclose(fp);
    if (st != LT_OK)
        pool_free(pool);
    return st;
}

/* ------------------------------------------------------------------------ */
/* state.dat                                                                */
/* ------------------------------------------------------------------------ */

typedef struct {
    char  **lines;
    size_t  count, capacity;
} LineList;

static void lines_free(LineList *l)
{
    size_t i;

    for (i = 0; i < l->count; i++)
        free(l->lines[i]);
    free(l->lines);
    memset(l, 0, sizeof *l);
}

static int lines_add(LineList *l, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof buf)
        return -1;
    if (l->count == l->capacity) {
        size_t cap = l->capacity ? l->capacity * 2 : 64;
        char **grown = realloc(l->lines, cap * sizeof *grown);
        if (grown == NULL)
            return -1;
        l->lines = grown;
        l->capacity = cap;
    }
    l->lines[l->count] = strdup(buf);
    if (l->lines[l->count] == NULL)
        return -1;
    l->count++;
    return 0;
}

/** The snapshot part of state.dat, in a fixed order. */
static int snapshot_lines(const LibraryState *st, LineList *out)
{
    size_t i, j;
    int rc = 0;

    for (i = 0; i < st->copy_count && rc == 0; i++) {
        const CopyStatus *c = &st->copies[i];
        rc = lines_add(out, "COPY|%s|%s|%s|%s|%s|%lld|%d|%d", c->copy_id, c->book_id,
                       condition_name(c->condition), copy_state_name(c->state),
                       c->current_holder_id[0] ? c->current_holder_id : "-",
                       (long long)c->due_date, c->renewals, c->overdue_flagged);
    }
    for (i = 0; i < st->queue_count && rc == 0; i++) {
        const ReservationQueue *q = &st->queues[i];
        for (j = 0; j < q->count && rc == 0; j++)
            rc = lines_add(out, "QUEUE|%s|%zu|%s|%lld|%s", q->book_id, j + 1,
                           q->items[j].member_id, (long long)q->items[j].reservation_date,
                           q->items[j].record_id);
    }
    for (i = 0; i < st->nonce_count && rc == 0; i++)
        rc = lines_add(out, "NONCE|%s|%ld", st->nonces[i].signer_id, st->nonces[i].nonce);
    for (i = 0; i < st->fine_count && rc == 0; i++)
        rc = lines_add(out, "FINE|%s|%ld|%ld", st->fines[i].member_id, st->fines[i].assessed,
                       st->fines[i].paid);
    if (st->ledger.model == MODEL_UTXO) {
        for (i = 0; i < st->ledger.utxo.count && rc == 0; i++) {
            const Utxo *u = &st->ledger.utxo.items[i];
            if (!u->spent)
                rc = lines_add(out, "UTXO|%s|%d|%s|%ld|%d", u->txid, u->vout, u->owner,
                               u->amount, u->created_in);
        }
        for (i = 0; i < st->ledger.accounts.count && rc == 0; i++)
            rc = lines_add(out, "ACCOUNT_NONCE|%s|%ld", st->ledger.accounts.items[i].id,
                           st->ledger.accounts.items[i].nonce);
    } else {
        for (i = 0; i < st->ledger.accounts.count && rc == 0; i++)
            rc = lines_add(out, "BALANCE|%s|%ld|%ld", st->ledger.accounts.items[i].id,
                           st->ledger.accounts.items[i].balance,
                           st->ledger.accounts.items[i].nonce);
    }
    return rc;
}

typedef struct {
    const StateMeta    *meta;
    const LibraryState *state;
} StateWriteCtx;

static int write_state_body(FILE *fp, const void *ctx)
{
    const StateWriteCtx *c = ctx;
    const StateMeta *m = c->meta;
    LineList lines = {0};
    size_t i;
    int rc;

    rc = fprintf(fp, "%s\n# Settings and chain metadata, then a snapshot of the state that\n"
                     "# is re-checked against the chain at start-up.\n"
                     "META|difficulty|%d\nMETA|block_reward|%ld\nMETA|block_capacity|%d\n"
                     "META|clock_offset|%ld\nMETA|loan_days|%d\nMETA|renewal_days|%d\n"
                     "META|max_renewals|%d\nMETA|max_loans|%d\nMETA|chain_length|%zu\n"
                     "META|tip_hash|%s\nMETA|model|%s\n",
                 STATE_HEADER, m->difficulty, m->block_reward, m->block_capacity,
                 m->clock_offset, m->rules.loan_days, m->rules.renewal_days,
                 m->rules.max_renewals, m->rules.max_loans, m->chain_length, m->tip_hash,
                 ledger_model_name(m->model)) < 0 ? -1 : 0;
    if (rc == 0)
        rc = snapshot_lines(c->state, &lines);
    for (i = 0; i < lines.count && rc == 0; i++)
        rc = fprintf(fp, "%s\n", lines.lines[i]) < 0 ? -1 : 0;
    lines_free(&lines);
    return rc;
}

Status storage_save_state(const char *path, const StateMeta *meta, const LibraryState *state)
{
    StateWriteCtx ctx;

    ctx.meta = meta;
    ctx.state = state;
    return write_atomic(path, write_state_body, &ctx);
}

static void apply_meta(StateMeta *m, const char *key, const char *value)
{
    long v;

    if (strcmp(key, "tip_hash") == 0) {
        (void)str_copy(m->tip_hash, sizeof m->tip_hash, value);
        return;
    }
    if (strcmp(key, "model") == 0) {
        (void)ledger_parse_model(value, &m->model);
        return;
    }
    if (parse_long(value, 0, LONG_MAX, &v) != 0)
        return;
    if (strcmp(key, "difficulty") == 0 && v >= MIN_DIFFICULTY && v <= MAX_DIFFICULTY)
        m->difficulty = (int)v;
    else if (strcmp(key, "block_reward") == 0 && v <= 1000)
        m->block_reward = v;
    else if (strcmp(key, "block_capacity") == 0 && v >= 1 && v <= MAX_BLOCK_CAPACITY)
        m->block_capacity = (int)v;
    else if (strcmp(key, "clock_offset") == 0)
        m->clock_offset = v;
    else if (strcmp(key, "loan_days") == 0 && v >= 1 && v <= MAX_LOAN_DAYS)
        m->rules.loan_days = (int)v;
    else if (strcmp(key, "renewal_days") == 0 && v >= 1 && v <= 30)
        m->rules.renewal_days = (int)v;
    else if (strcmp(key, "max_renewals") == 0 && v <= 10)
        m->rules.max_renewals = (int)v;
    else if (strcmp(key, "max_loans") == 0 && v >= 1 && v <= 50)
        m->rules.max_loans = (int)v;
    else if (strcmp(key, "chain_length") == 0)
        m->chain_length = (size_t)v;
}

Status storage_load_state(const char *path, StateMeta *meta, const LibraryState *rebuilt,
                          size_t *differences, char *first_diff, size_t diff_cap)
{
    FILE *fp = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0, line_no = 0, snap = 0;
    LineList expected = {0};
    int same_model = 1;

    if (differences != NULL)
        *differences = 0;
    if (first_diff != NULL && diff_cap > 0)
        first_diff[0] = '\0';
    meta->present = 0;
    if (fp == NULL)
        return errno == ENOENT ? LT_ERR_NOT_FOUND : LT_ERR_IO;
    if (rebuilt != NULL && snapshot_lines(rebuilt, &expected) != 0) {
        fclose(fp);
        lines_free(&expected);
        return LT_ERR_MEMORY;
    }
    while (read_long_line(fp, &line, &cap) == 0) {
        line_no++;
        if (line_no == 1) {
            if (strcmp(line, STATE_HEADER) != 0)
                break;
            meta->present = 1;
            continue;
        }
        if (line[0] == '#' || line[0] == '\0')
            continue;
        if (strncmp(line, "META|", 5) == 0) {
            char *f[3];
            if (str_split(line, '|', f, 3) == 3)
                apply_meta(meta, f[1], f[2]);
            continue;
        }
        if (rebuilt == NULL)
            continue;
        if (snap == 0)
            same_model = (meta->model == rebuilt->ledger.model);
        /* Ledger lines are only comparable when the file was written in the
         * same model as this session; inventory lines always are. */
        if (!same_model && (strncmp(line, "UTXO|", 5) == 0 || strncmp(line, "BALANCE|", 8) == 0 ||
                            strncmp(line, "ACCOUNT_NONCE|", 14) == 0))
            continue;
        while (!same_model && snap < expected.count &&
               (strncmp(expected.lines[snap], "UTXO|", 5) == 0 ||
                strncmp(expected.lines[snap], "BALANCE|", 8) == 0 ||
                strncmp(expected.lines[snap], "ACCOUNT_NONCE|", 14) == 0))
            snap++;
        if (snap >= expected.count || strcmp(expected.lines[snap], line) != 0) {
            if (differences != NULL && (*differences)++ == 0 && first_diff != NULL)
                snprintf(first_diff, diff_cap, "state.dat line %zu '%.60s' does not match the "
                                               "chain (expected '%.60s')",
                         line_no, line, snap < expected.count ? expected.lines[snap] : "nothing");
        }
        snap++;
    }
    if (rebuilt != NULL && differences != NULL) {
        for (; snap < expected.count; snap++) {
            if (!same_model && (strncmp(expected.lines[snap], "UTXO|", 5) == 0 ||
                                strncmp(expected.lines[snap], "BALANCE|", 8) == 0 ||
                                strncmp(expected.lines[snap], "ACCOUNT_NONCE|", 14) == 0))
                continue;
            if ((*differences)++ == 0 && first_diff != NULL)
                snprintf(first_diff, diff_cap, "state.dat is missing '%.60s'",
                         expected.lines[snap]);
        }
    }
    free(line);
    fclose(fp);
    lines_free(&expected);
    return meta->present ? LT_OK : LT_ERR_FORMAT;
}
