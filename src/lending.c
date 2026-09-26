/**
 * @file lending.c
 * @brief Business rules for lending, built on top of the blockchain.
 *
 * Every change follows the same safe sequence:
 *   1. check permission   2. validate IDs against the registries
 *   3. verify the chain is intact   4. check the book's current state
 *   5. append a signed block   6. persist; roll back in memory on failure
 */
#include "lending.h"

#include <stdio.h>
#include <string.h>

#include "storage.h"
#include "util.h"

Status library_init(Library *lib, const char *data_dir)
{
    memset(lib, 0, sizeof *lib);
    if (str_copy(lib->data_dir, sizeof lib->data_dir, data_dir) != 0 ||
        path_join(lib->chain_path, sizeof lib->chain_path, data_dir, CHAIN_FILE) != 0) {
        fprintf(stderr, "ERROR: data directory path is too long.\n");
        return LT_ERR_INPUT;
    }
    chain_init(&lib->chain);
    keyring_init(&lib->keys, data_dir);
    lib->loan_period = DEFAULT_LOAN_PERIOD_SECONDS;
    return LT_OK;
}

Status library_load_registries(Library *lib)
{
    char books_path[LT_PATH_MAX], members_path[LT_PATH_MAX];
    Status books_st, members_st;

    if (path_join(books_path, sizeof books_path, lib->data_dir, BOOKS_FILE) != 0 ||
        path_join(members_path, sizeof members_path, lib->data_dir, MEMBERS_FILE) != 0)
        return LT_ERR_INPUT;

    /* Load both so that problems with both files are reported at once. */
    books_st = registry_load_books(books_path, &lib->books);
    members_st = registry_load_members(members_path, &lib->members);
    return (books_st != LT_OK) ? books_st : members_st;
}

void library_free(Library *lib)
{
    registry_free_books(&lib->books);
    registry_free_members(&lib->members);
    chain_free(&lib->chain);
    keyring_free(&lib->keys);
    auth_logout(&lib->session);
}

int library_chain_is_valid(Library *lib)
{
    return chain_validate(&lib->chain, &lib->keys, NULL, NULL);
}

/** Saves the chain; if that fails, removes the unsaved blocks again. */
static Status persist(Library *lib, size_t new_blocks)
{
    Status st = storage_save_chain(lib->chain_path, &lib->chain);

    if (st != LT_OK)
        chain_pop(&lib->chain, new_blocks);
    return st;
}

BookState lending_book_state(const Library *lib, const char *book_id, const Block **loan)
{
    const Block *latest = chain_find_latest_event(&lib->chain, book_id);

    if (loan != NULL)
        *loan = NULL;
    if (latest == NULL || strcmp(latest->action, ACTION_RETURNED) == 0)
        return BOOK_AVAILABLE;
    if (loan != NULL)
        *loan = chain_find_latest_borrow(&lib->chain, book_id);
    return strcmp(latest->action, ACTION_OVERDUE) == 0 ? BOOK_OVERDUE : BOOK_ON_LOAN;
}

Status lending_borrow(Library *lib, const char *book_id, const char *member_id)
{
    const Book *book;
    const Member *member;
    Status st;

    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;

    book = registry_find_book(&lib->books, book_id);
    member = registry_find_member(&lib->members, member_id);
    if (book == NULL || member == NULL)
        return LT_ERR_NOT_FOUND;

    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;
    if (lending_book_state(lib, book->book_id, NULL) != BOOK_AVAILABLE)
        return LT_ERR_ON_LOAN;

    st = chain_append_record(&lib->chain, &lib->session, book->book_id, book->title,
                             member->member_id, member->full_name, ACTION_BORROWED);
    return (st == LT_OK) ? persist(lib, 1) : st;
}

Status lending_return(Library *lib, const char *book_id, const char *member_id)
{
    const Book *book;
    const Member *member;
    const Block *loan = NULL;
    Status st;

    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;

    book = registry_find_book(&lib->books, book_id);
    member = registry_find_member(&lib->members, member_id);
    if (book == NULL || member == NULL)
        return LT_ERR_NOT_FOUND;

    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;

    /* Look up the most recent BORROWED entry that has not been returned. */
    if (lending_book_state(lib, book->book_id, &loan) == BOOK_AVAILABLE || loan == NULL)
        return LT_ERR_NOT_ON_LOAN;
    if (strcmp(loan->member_id, member->member_id) != 0)
        return LT_ERR_WRONG_MEMBER;

    st = chain_append_record(&lib->chain, &lib->session, book->book_id, book->title,
                             member->member_id, member->full_name, ACTION_RETURNED);
    return (st == LT_OK) ? persist(lib, 1) : st;
}

Status lending_mark_overdue(Library *lib, time_t now, size_t *marked)
{
    size_t i, added = 0;
    Status st = LT_OK;

    *marked = 0;
    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;
    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;

    for (i = 0; i < lib->books.count && st == LT_OK; i++) {
        const Book *book = &lib->books.items[i];
        const Block *loan = NULL;
        const Member *member;
        char member_id[MEMBER_ID_LEN], member_name[MEMBER_NAME_LEN];

        if (lending_book_state(lib, book->book_id, &loan) != BOOK_ON_LOAN || loan == NULL)
            continue;
        if (difftime(now, loan->timestamp) <= (double)lib->loan_period)
            continue;

        /* Copy what we need now: appending may reallocate the chain and
         * invalidate the 'loan' pointer. */
        member = registry_find_member(&lib->members, loan->member_id);
        (void)str_copy(member_id, sizeof member_id, loan->member_id);
        (void)str_copy(member_name, sizeof member_name,
                       member != NULL ? member->full_name : loan->member_name);

        st = chain_append_record(&lib->chain, &lib->session, book->book_id, book->title,
                                 member_id, member_name, ACTION_OVERDUE);
        if (st == LT_OK)
            added++;
    }

    if (st != LT_OK) {
        chain_pop(&lib->chain, added);
        return st;
    }
    if (added > 0)
        st = persist(lib, added);
    if (st == LT_OK)
        *marked = added;
    return st;
}
