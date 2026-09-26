/**
 * @file registry.h
 * @brief Book and member registries loaded from books.txt and members.txt.
 *
 * Both registries are held in memory as dynamically grown arrays of structs.
 * Every lending action must reference IDs that exist in these registries.
 */
#ifndef LT_REGISTRY_H
#define LT_REGISTRY_H

#include <stddef.h>

#include "common.h"

/** One book in the library catalogue (a line of books.txt). */
typedef struct {
    char book_id[BOOK_ID_LEN];
    char title[BOOK_TITLE_LEN];
    char author[BOOK_AUTHOR_LEN];
} Book;

/** One registered library member (a line of members.txt). */
typedef struct {
    char member_id[MEMBER_ID_LEN];
    char full_name[MEMBER_NAME_LEN];
    char course_code[COURSE_CODE_LEN];
} Member;

/** Growable array of books. */
typedef struct {
    Book  *items;
    size_t count;
    size_t capacity;
} BookRegistry;

/** Growable array of members. */
typedef struct {
    Member *items;
    size_t  count;
    size_t  capacity;
} MemberRegistry;

/**
 * Loads books.txt ("book_id,title,author" per line).
 * Prints an error and returns LT_ERR_NOT_FOUND if the file is missing, or
 * LT_ERR_EMPTY if it contains no valid records. Invalid lines are reported
 * as warnings and skipped.
 */
Status registry_load_books(const char *path, BookRegistry *reg);

/** Loads members.txt ("member_id,full_name,course_code" per line). */
Status registry_load_members(const char *path, MemberRegistry *reg);

/** Case-insensitive lookup. @return the book, or NULL if not registered. */
const Book *registry_find_book(const BookRegistry *reg, const char *book_id);

/** Case-insensitive lookup. @return the member, or NULL if not registered. */
const Member *registry_find_member(const MemberRegistry *reg, const char *member_id);

void registry_free_books(BookRegistry *reg);
void registry_free_members(MemberRegistry *reg);

#endif /* LT_REGISTRY_H */
