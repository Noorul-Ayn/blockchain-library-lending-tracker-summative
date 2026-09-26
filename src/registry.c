/**
 * @file registry.c
 * @brief Loading, validating and searching the book and member registries.
 */
#include "registry.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "util.h"

#define REGISTRY_INITIAL_CAPACITY 16

typedef enum { REC_ADDED, REC_SKIPPED, REC_FATAL } RecordResult;

/** Callback that validates and stores one parsed "a,b,c" record. */
typedef RecordResult (*RecordHandler)(void *registry, char *f1, char *f2, char *f3,
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
 * Generic line-by-line loader shared by both registries. Skips blank lines
 * and '#' comments, strips a UTF-8 BOM and Windows line endings.
 */
static Status load_registry_file(const char *path, const char *label,
                                 RecordHandler handler, void *registry)
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
        result = handler(registry, f1, f2, f3, label, line_no);
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

/* ------------------------------------------------------------------------ */
/* Books                                                                    */
/* ------------------------------------------------------------------------ */

static RecordResult add_book(void *registry, char *id, char *title, char *author,
                             const char *label, size_t line_no)
{
    BookRegistry *reg = registry;
    const char *why = NULL;
    Book book;

    memset(&book, 0, sizeof book);
    if (!str_is_identifier(id))
        why = "invalid book_id (letters, digits, '-' and '_' only)";
    else if (str_copy(book.book_id, sizeof book.book_id, id) != 0)
        why = "book_id is longer than 19 characters";
    else if (*title == '\0' || !str_is_safe_field(title))
        why = "title is missing or contains invalid characters";
    else if (str_copy(book.title, sizeof book.title, title) != 0)
        why = "title is longer than 79 bytes";
    else if (*author == '\0' || !str_is_safe_field(author))
        why = "author is missing or contains invalid characters";
    else if (str_copy(book.author, sizeof book.author, author) != 0)
        why = "author is longer than 49 bytes";
    else if (registry_find_book(reg, id) != NULL)
        why = "duplicate book_id";

    if (why != NULL) {
        warn_line(label, line_no, why);
        return REC_SKIPPED;
    }
    if (reg->count == reg->capacity) {
        Book *grown = grow_array(reg->items, &reg->capacity, sizeof *grown);
        if (grown == NULL)
            return REC_FATAL;
        reg->items = grown;
    }
    reg->items[reg->count++] = book;
    return REC_ADDED;
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
/* Members                                                                  */
/* ------------------------------------------------------------------------ */

static RecordResult add_member(void *registry, char *id, char *name, char *course,
                               const char *label, size_t line_no)
{
    MemberRegistry *reg = registry;
    const char *why = NULL;
    Member member;

    memset(&member, 0, sizeof member);
    if (!str_is_identifier(id))
        why = "invalid member_id (letters, digits, '-' and '_' only)";
    else if (str_copy(member.member_id, sizeof member.member_id, id) != 0)
        why = "member_id is longer than 19 characters";
    else if (*name == '\0' || !str_is_safe_field(name))
        why = "full_name is missing or contains invalid characters";
    else if (str_copy(member.full_name, sizeof member.full_name, name) != 0)
        why = "full_name is longer than 49 bytes";
    else if (!str_is_identifier(course))
        why = "invalid course_code";
    else if (str_copy(member.course_code, sizeof member.course_code, course) != 0)
        why = "course_code is longer than 9 characters";
    else if (registry_find_member(reg, id) != NULL)
        why = "duplicate member_id";

    if (why != NULL) {
        warn_line(label, line_no, why);
        return REC_SKIPPED;
    }
    if (reg->count == reg->capacity) {
        Member *grown = grow_array(reg->items, &reg->capacity, sizeof *grown);
        if (grown == NULL)
            return REC_FATAL;
        reg->items = grown;
    }
    reg->items[reg->count++] = member;
    return REC_ADDED;
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
