/**
 * @file storage.c
 * @brief Reading and atomically writing the chain file.
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

#define CHAIN_HEADER      "# LIBCHAIN v1"
#define CHAIN_COLUMNS     "# index|timestamp|book_id|book_title|member_id|member_name|" \
                          "action|signed_by|previous_hash|signature|hash"
#define CHAIN_FIELD_COUNT 11

enum {
    F_INDEX, F_TIMESTAMP, F_BOOK_ID, F_BOOK_TITLE, F_MEMBER_ID, F_MEMBER_NAME,
    F_ACTION, F_SIGNED_BY, F_PREV_HASH, F_SIGNATURE, F_HASH
};

#if defined(__GNUC__)
static void set_error(char *err, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#endif

static void set_error(char *err, size_t cap, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || cap == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------------ */
/* Saving                                                                   */
/* ------------------------------------------------------------------------ */

Status storage_save_chain(const char *path, const Blockchain *chain)
{
    char tmp_path[LT_PATH_MAX];
    int failed = 0;
    size_t i;
    FILE *fp;
    int n;

    n = snprintf(tmp_path, sizeof tmp_path, "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof tmp_path)
        return LT_ERR_INPUT;

    fp = fopen(tmp_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: cannot write '%s': %s\n", tmp_path, strerror(errno));
        return LT_ERR_IO;
    }

    if (fprintf(fp, "%s\n%s\n", CHAIN_HEADER, CHAIN_COLUMNS) < 0)
        failed = 1;
    for (i = 0; !failed && i < chain->length; i++) {
        const Block *b = &chain->blocks[i];
        char sig_hex[SIGNATURE_MAX_LEN * 2 + 1];

        if (b->signature_len > SIGNATURE_MAX_LEN) {
            failed = 1;
            break;
        }
        hex_encode(b->signature, b->signature_len, sig_hex);
        if (fprintf(fp, "%d|%lld|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
                    b->index, (long long)b->timestamp, b->book_id, b->book_title,
                    b->member_id, b->member_name, b->action, b->signed_by,
                    b->previous_hash, sig_hex, b->hash) < 0)
            failed = 1;
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        failed = 1;
    if (fclose(fp) != 0)
        failed = 1;

    if (failed || rename(tmp_path, path) != 0) {
        fprintf(stderr, "ERROR: failed to save the blockchain to '%s'.\n", path);
        unlink(tmp_path);
        return LT_ERR_IO;
    }
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Loading                                                                  */
/* ------------------------------------------------------------------------ */

static int parse_ll(const char *s, long long min, long long max, long long *out)
{
    char *end;
    long long v;

    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

/** Parses one chain line into a block. On failure *why explains the problem. */
static int parse_block(char *line, Block *b, const char **why)
{
    char *f[CHAIN_FIELD_COUNT];
    long long value;

    memset(b, 0, sizeof *b);
    if (str_split(line, '|', f, CHAIN_FIELD_COUNT) != CHAIN_FIELD_COUNT) {
        *why = "expected 11 '|'-separated fields";
        return -1;
    }
    if (parse_ll(f[F_INDEX], 0, INT_MAX, &value) != 0) {
        *why = "invalid index";
        return -1;
    }
    b->index = (int)value;
    if (parse_ll(f[F_TIMESTAMP], 0, LLONG_MAX, &value) != 0) {
        *why = "invalid timestamp";
        return -1;
    }
    b->timestamp = (time_t)value;

    if (str_copy(b->book_id, sizeof b->book_id, f[F_BOOK_ID]) != 0 ||
        str_copy(b->book_title, sizeof b->book_title, f[F_BOOK_TITLE]) != 0 ||
        str_copy(b->member_id, sizeof b->member_id, f[F_MEMBER_ID]) != 0 ||
        str_copy(b->member_name, sizeof b->member_name, f[F_MEMBER_NAME]) != 0 ||
        str_copy(b->action, sizeof b->action, f[F_ACTION]) != 0 ||
        str_copy(b->signed_by, sizeof b->signed_by, f[F_SIGNED_BY]) != 0) {
        *why = "a text field exceeds its maximum length";
        return -1;
    }
    if (!is_hex_string(f[F_PREV_HASH], HASH_HEX_LEN - 1) ||
        str_copy(b->previous_hash, sizeof b->previous_hash, f[F_PREV_HASH]) != 0) {
        *why = "previous_hash is not 64 hex characters";
        return -1;
    }
    if (hex_decode(f[F_SIGNATURE], b->signature, sizeof b->signature, &b->signature_len) != 0 ||
        b->signature_len == 0) {
        *why = "signature is not valid hex (max 72 bytes)";
        return -1;
    }
    if (!is_hex_string(f[F_HASH], HASH_HEX_LEN - 1) ||
        str_copy(b->hash, sizeof b->hash, f[F_HASH]) != 0) {
        *why = "hash is not 64 hex characters";
        return -1;
    }
    return 0;
}

Status storage_load_chain(const char *path, Blockchain *chain, char *err, size_t err_cap)
{
    char line[LT_LINE_MAX];
    size_t line_no = 0;
    int header_seen = 0;
    Status st = LT_OK;
    Blockchain loaded;
    FILE *fp;

    set_error(err, err_cap, "%s", "");
    fp = fopen(path, "r");
    if (fp == NULL) {
        if (errno == ENOENT)
            return LT_ERR_NOT_FOUND;
        set_error(err, err_cap, "cannot open file: %s", strerror(errno));
        return LT_ERR_IO;
    }

    chain_init(&loaded);
    while (st == LT_OK && fgets(line, sizeof line, fp) != NULL) {
        const char *why = NULL;
        size_t len = strlen(line);
        Block block;

        line_no++;
        if (len > 0 && line[len - 1] == '\n') {
            line[--len] = '\0';
        } else if (!feof(fp)) {
            set_error(err, err_cap, "line %zu is too long", line_no);
            st = LT_ERR_FORMAT;
            break;
        }
        if (len > 0 && line[len - 1] == '\r')
            line[--len] = '\0';

        if (!header_seen) {
            if (strcmp(line, CHAIN_HEADER) != 0) {
                set_error(err, err_cap, "missing '%s' header on line 1", CHAIN_HEADER);
                st = LT_ERR_FORMAT;
                break;
            }
            header_seen = 1;
            continue;
        }
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (parse_block(line, &block, &why) != 0) {
            set_error(err, err_cap, "line %zu: %s", line_no, why);
            st = LT_ERR_FORMAT;
            break;
        }
        st = chain_push(&loaded, &block);
    }
    if (st == LT_OK && ferror(fp)) {
        set_error(err, err_cap, "%s", "read error");
        st = LT_ERR_IO;
    }
    fclose(fp);

    if (st == LT_OK && loaded.length == 0) {
        set_error(err, err_cap, "%s", "the file contains no blocks");
        st = LT_ERR_EMPTY;
    }
    if (st != LT_OK) {
        chain_free(&loaded);
        return st;
    }
    chain_free(chain);
    *chain = loaded;
    return LT_OK;
}
