/**
 * @file lending.h
 * @brief Application state and the lending business rules
 *        (borrow, return, overdue detection).
 */
#ifndef LT_LENDING_H
#define LT_LENDING_H

#include <time.h>

#include "auth.h"
#include "blockchain.h"
#include "common.h"
#include "keyring.h"
#include "registry.h"

/** Current state of a book, derived entirely from the blockchain. */
typedef enum {
    BOOK_AVAILABLE,
    BOOK_ON_LOAN,
    BOOK_OVERDUE
} BookState;

/** Everything the running application needs, in one place. */
typedef struct {
    char           data_dir[LT_PATH_MAX];
    char           chain_path[LT_PATH_MAX];
    BookRegistry   books;
    MemberRegistry members;
    Blockchain     chain;
    KeyRing        keys;
    Session        session;
    long           loan_period;   /* seconds before a loan becomes overdue */
} Library;

Status library_init(Library *lib, const char *data_dir);

/** Loads books.txt and members.txt; reports errors for both files. */
Status library_load_registries(Library *lib);

void library_free(Library *lib);

/** Full validation (hashes, links, signatures) without printing. */
int library_chain_is_valid(Library *lib);

/**
 * State of a book according to its latest lending event on the chain.
 * If loan is non-NULL it receives the most recent BORROWED block while the
 * book is out (NULL when available). The pointer is valid until the chain
 * is next modified.
 */
BookState lending_book_state(const Library *lib, const char *book_id, const Block **loan);

/**
 * Records a loan. Both IDs must exist in the registries (else
 * LT_ERR_NOT_FOUND), the book must be available (else LT_ERR_ON_LOAN) and
 * the chain must be valid (else LT_ERR_CHAIN_INVALID).
 */
Status lending_borrow(Library *lib, const char *book_id, const char *member_id);

/**
 * Records a return against the book's most recent BORROWED entry.
 * LT_ERR_NOT_ON_LOAN if there is no outstanding loan, LT_ERR_WRONG_MEMBER
 * if the book is on loan to a different member.
 */
Status lending_return(Library *lib, const char *book_id, const char *member_id);

/** Appends an OVERDUE block for every loan older than the loan period. */
Status lending_mark_overdue(Library *lib, time_t now, size_t *marked);

#endif /* LT_LENDING_H */
