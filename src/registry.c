/**
 * @file registry.c
 * @brief Loading, validating, searching and extending the registries.
 */
#include "registry.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "util.h"

#define REGISTRY_INITIAL_CAPACITY 16

typedef enum { REC_ADDED, REC_SKIPPED, REC_FATAL } RecordResult;

/** Callback that validates and stores one parsed "a,b,c" record. */
typedef RecordResult (*RecordHandler)(void *ctx, char *f1, char *f2, char *f3,
                                      const char *label, size_t line_no);

/** Doubles the capacity of a dynamic array. @return new pointer or NULL. */
static void *grow_array(void *items, size_t *capacity, size_t elem_size)
{
    size_t new_cap = (*capacity == 0) ? REGISTRY_INITIAL_CAPACITY : *capacity * 2;
    void *p;

    if (new_cap > SIZE_MAX / elem_size)
        return NULL;
    p = realloc(items, new_cap * elem_size);
    if (p != NULL)
        *capacity = new_cap;
    return p;
}

/**
 * Splits "first,middle,last" into three trimmed fields. The first comma ends
 * the ID and the last comma starts the final field, so titles or names that
 * themselves contain commas are still parsed correctly.
 */
static int split_record(char *line, char **f1, char **f2, char **f3)
{
    char *first = strchr(line, ',');
    char *last = strrchr(line, ',');

    if (first == NULL || first == last)
        return -1;
    *first = '\0';
    *last = '\0';
    *f1 = str_trim(line);
    *f2 = str_trim(first + 1);
    *f3 = str_trim(last + 1);
    return 0;
}

static void warn_line(const char *label, size_t line_no, const char *reason)
{
    fprintf(stderr, "WARNING: %s line %zu: %s - line skipped.\n", label, line_no, reason);
}

/**
 * Generic line-by-line loader shared by all registries. Skips blank lines
 * and '#' comments, strips a UTF-8 BOM and Windows line endings.
 */
static Status load_registry_file(const char *path, const char *label,
                                 RecordHandler handler, void *ctx)
{
    char line[LT_LINE_MAX];
    size_t line_no = 0, candidates = 0, loaded = 0;
    Status st = LT_OK;
    FILE *fp = fopen(path, "r");

    if (fp == NULL) {
        if (errno == ENOENT) {
            fprintf(stderr, "ERROR: %s is missing (expected at '%s').\n", label, path);
            return LT_ERR_NOT_FOUND;
        }
        fprintf(stderr, "ERROR: cannot open %s ('%s'): %s\n", label, path, strerror(errno));
        return LT_ERR_IO;
    }

    while (fgets(line, sizeof line, fp) != NULL) {
        char *p = line, *f1, *f2, *f3;
        size_t len = strlen(line);
        RecordResult result;

        line_no++;
        if (len == sizeof line - 1 && line[len - 1] != '\n' && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {
                /* discard remainder */
            }
            candidates++;
            warn_line(label, line_no, "line is too long");
            continue;
        }
        if (line_no == 1 && (unsigned char)p[0] == 0xEF &&
            (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF)
            p += 3; /* UTF-8 byte-order mark */
        p = str_trim(p);
        if (*p == '\0' || *p == '#')
            continue;

        candidates++;
        if (split_record(p, &f1, &f2, &f3) != 0) {
            warn_line(label, line_no, "expected 3 comma-separated fields");
            continue;
        }
        result = handler(ctx, f1, f2, f3, label, line_no);
        if (result == REC_ADDED) {
            loaded++;
        } else if (result == REC_FATAL) {
            st = LT_ERR_MEMORY;
            break;
        }
    }
    if (st == LT_OK && ferror(fp)) {
        fprintf(stderr, "ERROR: failed while reading %s.\n", label);
        st = LT_ERR_IO;
    }
    fclose(fp);

    if (st != LT_OK)
        return st;
    if (candidates == 0) {
        fprintf(stderr, "ERROR: %s is empty ('%s').\n", label, path);
        return LT_ERR_EMPTY;
    }
    if (loaded == 0) {
        fprintf(stderr, "ERROR: %s contains no valid records ('%s').\n", label, path);
        return LT_ERR_EMPTY;
    }
    return LT_OK;
}

/** Appends one "a,b,c" line to a registry file and flushes it to disk. */
static Status append_line(const char *path, const char *a, const char *b, const char *c)
{
    FILE *fp = fopen(path, "a");
    Status st = LT_OK;

    if (fp == NULL)
        return LT_ERR_IO;
    if (fprintf(fp, "%s,%s,%s\n", a, b, c) < 0 || fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        st = LT_ERR_IO;
    if (fclose(fp) != 0)
        st = LT_ERR_IO;
    return st;
}

/* ------------------------------------------------------------------------ */
/* Conditions                                                               */
/* ------------------------------------------------------------------------ */

const char *condition_name(Condition c)
{
    switch (c) {
    case COND_NEW:  return "NEW";
    case COND_GOOD: return "GOOD";
    case COND_WORN: return "WORN";
    case COND_LOST: return "LOST";
    }
    return "?";
}

int condition_parse(const char *s, Condition *out)
{
    static const Condition all[] = { COND_NEW, COND_GOOD, COND_WORN, COND_LOST };
    size_t i;

    for (i = 0; i < sizeof all / sizeof all[0]; i++) {
        if (strcasecmp(s, condition_name(all[i])) == 0) {
            *out = all[i];
            return 0;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------------ */
/* Books                                                                    */
/* ------------------------------------------------------------------------ */

static const char *validate_book(const BookRegistry *reg, const char *id, const char *title,
                                 const char *author, Book *out)
{
    memset(out, 0, sizeof *out);
    if (!str_is_identifier(id))
        return "invalid book_id (letters, digits, '-' and '_' only)";
    if (str_copy(out->book_id, sizeof out->book_id, id) != 0)
        return "book_id is longer than 19 characters";
    if (*title == '\0' || !str_is_safe_field(title))
        return "title is missing or contains invalid characters";
    if (str_copy(out->title, sizeof out->title, title) != 0)
        return "title is longer than 79 bytes";
    if (*author == '\0' || !str_is_safe_field(author) || strchr(author, ',') != NULL)
        return "author is missing or contains invalid characters (no commas)";
    if (str_copy(out->author, sizeof out->author, author) != 0)
        return "author is longer than 49 bytes";
    if (registry_find_book(reg, id) != NULL)
        return "duplicate book_id";
    return NULL;
}

static Status push_book(BookRegistry *reg, const Book *book)
{
    if (reg->count == reg->capacity) {
        Book *grown = grow_array(reg->items, &reg->capacity, sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        reg->items = grown;
    }
    reg->items[reg->count++] = *book;
    return LT_OK;
}

static RecordResult add_book(void *ctx, char *id, char *title, char *author,
                             const char *label, size_t line_no)
{
    BookRegistry *reg = ctx;
    Book book;
    const char *why = validate_book(reg, id, title, author, &book);

    if (why != NULL) {
        warn_line(label, line_no, why);
        return REC_SKIPPED;
    }
    return push_book(reg, &book) == LT_OK ? REC_ADDED : REC_FATAL;
}

Status registry_load_books(const char *path, BookRegistry *reg)
{
    Status st;

    memset(reg, 0, sizeof *reg);
    st = load_registry_file(path, BOOKS_FILE, add_book, reg);
    if (st != LT_OK)
        registry_free_books(reg);
    return st;
}

Status registry_add_book(const char *path, BookRegistry *reg, const char *id,
                         const char *title, const char *author, const char **why)
{
    Book book;
    const char *reason = validate_book(reg, id, title, author, &book);
    Status st;

    if (why != NULL)
        *why = reason;
    if (reason != NULL)
        return LT_ERR_INPUT;
    st = append_line(path, book.book_id, book.title, book.author);
    return st == LT_OK ? push_book(reg, &book) : st;
}

const Book *registry_find_book(const BookRegistry *reg, const char *book_id)
{
    size_t i;

    for (i = 0; i < reg->count; i++) {
        if (strcasecmp(reg->items[i].book_id, book_id) == 0)
            return &reg->items[i];
    }
    return NULL;
}

void registry_free_books(BookRegistry *reg)
{
    free(reg->items);
    memset(reg, 0, sizeof *reg);
}

/* ------------------------------------------------------------------------ */
/* Copies                                                                   */
/* ------------------------------------------------------------------------ */

typedef struct {
    CopyRegistry       *copies;
    const BookRegistry *books;
} CopyLoadCtx;

static const char *validate_copy(const CopyRegistry *reg, const BookRegistry *books,
                                 const char *copy_id, const char *book_id,
                                 Condition condition, CopyRecord *out)
{
    const Book *book;

    memset(out, 0, sizeof *out);
    if (!str_is_identifier(copy_id))
        return "invalid copy_id (letters, digits, '-' and '_' only)";
    if (str_copy(out->copy_id, sizeof out->copy_id, copy_id) != 0)
        return "copy_id is longer than 23 characters";
    book = registry_find_book(books, book_id);
    if (book == NULL)
        return "book_id is not in books.txt";
    (void)str_copy(out->book_id, sizeof out->book_id, book->book_id);
    if (registry_find_copy(reg, copy_id) != NULL)
        return "duplicate copy_id";
    out->condition = condition;
    return NULL;
}

static Status push_copy(CopyRegistry *reg, const CopyRecord *copy)
{
    if (reg->count == reg->capacity) {
        CopyRecord *grown = grow_array(reg->items, &reg->capacity, sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        reg->items = grown;
    }
    reg->items[reg->count++] = *copy;
    return LT_OK;
}

static RecordResult add_copy(void *ctx, char *copy_id, char *book_id, char *cond,
                             const char *label, size_t line_no)
{
    CopyLoadCtx *c = ctx;
    CopyRecord copy;
    Condition condition;
    const char *why;

    if (condition_parse(cond, &condition) != 0) {
        warn_line(label, line_no, "condition must be NEW, GOOD, WORN or LOST");
        return REC_SKIPPED;
    }
    why = validate_copy(c->copies, c->books, copy_id, book_id, condition, &copy);
    if (why != NULL) {
        warn_line(label, line_no, why);
        return REC_SKIPPED;
    }
    return push_copy(c->copies, &copy) == LT_OK ? REC_ADDED : REC_FATAL;
}

Status registry_load_copies(const char *path, const BookRegistry *books, CopyRegistry *reg)
{
    CopyLoadCtx ctx;
    Status st;

    memset(reg, 0, sizeof *reg);
    ctx.copies = reg;
    ctx.books = books;
    st = load_registry_file(path, COPIES_FILE, add_copy, &ctx);
    if (st != LT_OK)
        registry_free_copies(reg);
    return st;
}

Status registry_add_copy(const char *path, CopyRegistry *reg, const BookRegistry *books,
                         const char *copy_id, const char *book_id, Condition condition,
                         const char **why)
{
    CopyRecord copy;
    const char *reason = condition == COND_LOST
                             ? "a new copy cannot be registered as LOST"
                             : validate_copy(reg, books, copy_id, book_id, condition, &copy);
    Status st;

    if (why != NULL)
        *why = reason;
    if (reason != NULL)
        return LT_ERR_INPUT;
    st = append_line(path, copy.copy_id, copy.book_id, condition_name(condition));
    return st == LT_OK ? push_copy(reg, &copy) : st;
}

const CopyRecord *registry_find_copy(const CopyRegistry *reg, const char *copy_id)
{
    size_t i;

    for (i = 0; i < reg->count; i++) {
        if (strcasecmp(reg->items[i].copy_id, copy_id) == 0)
            return &reg->items[i];
    }
    return NULL;
}

size_t registry_count_copies(const CopyRegistry *reg, const char *book_id)
{
    size_t i, n = 0;

    for (i = 0; i < reg->count; i++) {
        if (strcasecmp(reg->items[i].book_id, book_id) == 0)
            n++;
    }
    return n;
}

void registry_next_copy_id(const CopyRegistry *reg, const char *book_id,
                           char out[COPY_ID_LEN])
{
    int n;

    for (n = 1; n < 1000; n++) {
        snprintf(out, COPY_ID_LEN, "%s-C%d", book_id, n);
        if (registry_find_copy(reg, out) == NULL)
            return;
    }
    out[0] = '\0';
}

void registry_free_copies(CopyRegistry *reg)
{
    free(reg->items);
    memset(reg, 0, sizeof *reg);
}

/* ------------------------------------------------------------------------ */
/* Members                                                                  */
/* ------------------------------------------------------------------------ */

static const char *validate_member(const MemberRegistry *reg, const char *id, const char *name,
                                   const char *course, Member *out)
{
    memset(out, 0, sizeof *out);
    if (!str_is_identifier(id))
        return "invalid member_id (letters, digits, '-' and '_' only)";
    if (strcmp(id, LIBRARY_ACCOUNT) == 0)
        return "LIBRARY is reserved for the library's own token account";
    if (str_copy(out->member_id, sizeof out->member_id, id) != 0)
        return "member_id is longer than 19 characters";
    if (*name == '\0' || !str_is_safe_field(name))
        return "full_name is missing or contains invalid characters";
    if (str_copy(out->full_name, sizeof out->full_name, name) != 0)
        return "full_name is longer than 49 bytes";
    if (!str_is_identifier(course))
        return "invalid course_code";
    if (str_copy(out->course_code, sizeof out->course_code, course) != 0)
        return "course_code is longer than 9 characters";
    if (registry_find_member(reg, id) != NULL)
        return "duplicate member_id";
    return NULL;
}

static Status push_member(MemberRegistry *reg, const Member *member)
{
    if (reg->count == reg->capacity) {
        Member *grown = grow_array(reg->items, &reg->capacity, sizeof *grown);
        if (grown == NULL)
            return LT_ERR_MEMORY;
        reg->items = grown;
    }
    reg->items[reg->count++] = *member;
    return LT_OK;
}

static RecordResult add_member(void *ctx, char *id, char *name, char *course,
                               const char *label, size_t line_no)
{
    MemberRegistry *reg = ctx;
    Member member;
    const char *why = validate_member(reg, id, name, course, &member);

    if (why != NULL) {
        warn_line(label, line_no, why);
        return REC_SKIPPED;
    }
    return push_member(reg, &member) == LT_OK ? REC_ADDED : REC_FATAL;
}

Status registry_load_members(const char *path, MemberRegistry *reg)
{
    Status st;

    memset(reg, 0, sizeof *reg);
    st = load_registry_file(path, MEMBERS_FILE, add_member, reg);
    if (st != LT_OK)
        registry_free_members(reg);
    return st;
}

Status registry_add_member(const char *path, MemberRegistry *reg, const char *id,
                           const char *name, const char *course, const char **why)
{
    Member member;
    const char *reason = validate_member(reg, id, name, course, &member);
    Status st;

    if (why != NULL)
        *why = reason;
    if (reason != NULL)
        return LT_ERR_INPUT;
    st = append_line(path, member.member_id, member.full_name, member.course_code);
    return st == LT_OK ? push_member(reg, &member) : st;
}

const Member *registry_find_member(const MemberRegistry *reg, const char *member_id)
{
    size_t i;

    for (i = 0; i < reg->count; i++) {
        if (strcasecmp(reg->items[i].member_id, member_id) == 0)
            return &reg->items[i];
    }
    return NULL;
}

void registry_free_members(MemberRegistry *reg)
{
    free(reg->items);
    memset(reg, 0, sizeof *reg);
}
