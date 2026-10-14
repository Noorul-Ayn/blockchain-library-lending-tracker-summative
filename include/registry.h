/**
 * @file registry.h
 * @brief Book, copy and member registries (books.txt, copies.txt, members.txt).
 *
 * The registries are held in memory as dynamically grown arrays of structs.
 * books.txt and members.txt keep the Formative 1 format; copies.txt adds one
 * line per physical copy. New entries created with register_member,
 * register_book and add_copy are validated and appended to the same files.
 *
 * Only static facts live here (IDs, titles, the condition a copy was
 * registered with). Dynamic copy state (borrowed, reserved, due date ...)
 * is derived from the blockchain by the state module.
 */
#ifndef LT_REGISTRY_H
#define LT_REGISTRY_H

#include <stddef.h>

#include "common.h"

/** Physical condition of a copy, best to worst. */
typedef enum {
    COND_NEW  = 0,
    COND_GOOD = 1,
    COND_WORN = 2,
    COND_LOST = 3
} Condition;

/** One title in the catalogue (a line of books.txt). */
typedef struct {
    char book_id[BOOK_ID_LEN];
    char title[BOOK_TITLE_LEN];
    char author[BOOK_AUTHOR_LEN];
} Book;

/** One physical copy of a title (a line of copies.txt). */
typedef struct {
    char      copy_id[COPY_ID_LEN];
    char      book_id[BOOK_ID_LEN];
    Condition condition;          /* condition when the copy was registered */
} CopyRecord;

/** One registered library member (a line of members.txt). */
typedef struct {
    char member_id[MEMBER_ID_LEN];
    char full_name[MEMBER_NAME_LEN];
    char course_code[COURSE_CODE_LEN];
} Member;

typedef struct { Book       *items; size_t count, capacity; } BookRegistry;
typedef struct { CopyRecord *items; size_t count, capacity; } CopyRegistry;
typedef struct { Member     *items; size_t count, capacity; } MemberRegistry;

/**
 * Loaders. Each prints an error and returns LT_ERR_NOT_FOUND if the file is
 * missing, or LT_ERR_EMPTY if it holds no valid records. Invalid lines are
 * reported as warnings and skipped. Copies must reference a loaded book.
 */
Status registry_load_books(const char *path, BookRegistry *reg);
Status registry_load_members(const char *path, MemberRegistry *reg);
Status registry_load_copies(const char *path, const BookRegistry *books, CopyRegistry *reg);

/** Case-insensitive lookups. @return the entry, or NULL if not registered. */
const Book       *registry_find_book(const BookRegistry *reg, const char *book_id);
const Member     *registry_find_member(const MemberRegistry *reg, const char *member_id);
const CopyRecord *registry_find_copy(const CopyRegistry *reg, const char *copy_id);

/** Number of copies registered for a title. */
size_t registry_count_copies(const CopyRegistry *reg, const char *book_id);

/**
 * Validates a new entry, appends it to its file and to the registry.
 * On failure *why (if non-NULL) explains the problem and nothing is written.
 */
Status registry_add_book(const char *path, BookRegistry *reg, const char *id,
                         const char *title, const char *author, const char **why);
Status registry_add_member(const char *path, MemberRegistry *reg, const char *id,
                           const char *name, const char *course, const char **why);
Status registry_add_copy(const char *path, CopyRegistry *reg, const BookRegistry *books,
                         const char *copy_id, const char *book_id, Condition condition,
                         const char **why);

/** Proposes the next free copy ID for a title, e.g. "BK001-C3". */
void registry_next_copy_id(const CopyRegistry *reg, const char *book_id,
                           char out[COPY_ID_LEN]);

const char *condition_name(Condition c);
int         condition_parse(const char *s, Condition *out);   /* 0 on success */

void registry_free_books(BookRegistry *reg);
void registry_free_members(MemberRegistry *reg);
void registry_free_copies(CopyRegistry *reg);

#endif /* LT_REGISTRY_H */
