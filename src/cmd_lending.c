/**
 * @file cmd_lending.c
 * @brief CLI commands for members, books, copies, lending, reservations,
 *        renewals, overdue detection and fines.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "commands.h"
#include "ui.h"

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/** The projection (confirmed + pending). Prints an error on failure. */
static int project(const Library *lib, LibraryState *proj)
{
    if (library_project(lib, proj) == LT_OK)
        return 1;
    say_err("Out of memory.");
    return 0;
}

/** Short description of the pending requests that touch a copy. */
static void pending_note(const Library *lib, const char *copy_id, char *buf, size_t cap)
{
    size_t i, used = 0;

    buf[0] = '\0';
    for (i = 0; i < lib->pool.count && used + 1 < cap; i++) {
        const Request *q = &lib->pool.items[i];
        int n;

        if (strcasecmp(q->rec.copy_id, copy_id) != 0)
            continue;
        n = snprintf(buf + used, cap - used, "%s%s %s%s", used ? ", " : "",
                     action_request_name(q->rec.action), q->rec.member_id,
                     q->status == REQ_SUSPICIOUS ? " (SUSPICIOUS)" : "");
        if (n < 0)
            break;
        used += (size_t)n;
    }
    if (used == 0)
        snprintf(buf, cap, "-");
}

static long days_late(time_t due, time_t now)
{
    return due > 0 && now > due ? days_between_ceil(due, now) : 0;
}

/** Pending requests signed by a signer. */
static size_t pending_by_signer(const Library *lib, const char *signer)
{
    size_t i, n = 0;

    for (i = 0; i < lib->pool.count; i++)
        if (strcmp(lib->pool.items[i].rec.signer_id, signer) == 0)
            n++;
    return n;
}

/* ------------------------------------------------------------------------ */
/* Overdue detection                                                        */
/* ------------------------------------------------------------------------ */

void run_overdue_scan(Library *lib, int verbose)
{
    Request created[32];
    size_t n = 0, i;
    char err[300];
    Status st;

    if (!lib->validated || !lib->chain_ok || !auth_is_logged_in(&lib->session))
        return;
    st = library_overdue_scan(lib, created, sizeof created / sizeof created[0], &n, err,
                              sizeof err);
    if (n > 0) {
        char today[16];
        format_day(lib_now(), today);
        say_warn("Overdue detection (%s): %zu loan(s) are past their due date and were flagged "
                 "OVERDUE:", today, n);
        for (i = 0; i < n && i < sizeof created / sizeof created[0]; i++) {
            const Record *r = &created[i].rec;
            char due[16];
            format_day(r->due_date, due);
            printf("         %s %-24.24s %s (%s) due %s, %ld day(s) late, fine so far %ld "
                   "coin(s) -> request %s\n", r->copy_id, r->book_title, r->member_id,
                   r->member_name, due, days_late(r->due_date, r->timestamp), r->fine_amount,
                   r->record_id);
        }
        printf("         OVERDUE records are signed by %s and go first in the pool "
               "(priority OVERDUE).\n", created[0].rec.signer_id);
    } else if (verbose) {
        say_info("Overdue scan: no new overdue loans.");
    }
    if (st != LT_OK)
        report_failure(st, err);
}

/* ------------------------------------------------------------------------ */
/* Members                                                                  */
/* ------------------------------------------------------------------------ */

void cmd_register_member(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], b2[INPUT_MAX], b3[INPUT_MAX];
    const char *id, *name, *course, *why = NULL;
    const PublicKeyEntry *key;
    Status st;

    heading("REGISTER MEMBER");
    if ((id = arg_or_prompt(argc, argv, 1, "Member ID (e.g. ALU006): ", b1, sizeof b1)) == NULL ||
        (name = arg_or_prompt(argc, argv, 2, "Full name: ", b2, sizeof b2)) == NULL ||
        (course = arg_or_prompt(argc, argv, 3, "Course code: ", b3, sizeof b3)) == NULL)
        return;
    st = library_register_member(lib, id, name, course, &why);
    if (st != LT_OK) {
        say_err("Member not registered: %s.", why ? why : status_str(st));
        return;
    }
    say_ok("Member %s (%s, %s) registered and appended to %s.", id, name, course, MEMBERS_FILE);
    key = keydir_get(&lib->keys, lib->members.items[lib->members.count - 1].member_id);
    if (key != NULL) {
        printf("         ECDSA P-256 key pair generated for the member.\n");
        printf("         Public key (on-chain identity): %s\n", key->hex);
        printf("         Private key: %s/%s/%s/%s.key (AES-256-GCM, inside the key vault)\n",
               lib->data_dir, KEYS_DIR, MEMBER_KEYS_DIR,
               lib->members.items[lib->members.count - 1].member_id);
    }
    printf("         Token balance starts at 0; request nonce starts at 0.\n");
}

static void print_member_detail(Library *lib, const Member *m)
{
    LibraryState proj;
    const PublicKeyEntry *key = keydir_get(&lib->keys, m->member_id);
    time_t now = lib_now();
    size_t i, loans = 0;

    if (!project(lib, &proj))
        return;
    printf("Member ID     : %s\n", m->member_id);
    printf("Name          : %s\n", m->full_name);
    printf("Course        : %s\n", m->course_code);
    printf("Public key    : %s\n", key ? key->hex : "(none - log in to generate)");
    printf("Request nonce : %ld confirmed, next request uses %ld\n",
           state_nonce(&lib->state, m->member_id), state_nonce(&proj, m->member_id));
    printf("Token balance : %ld coin(s) (%s model)\n",
           ledger_balance(&lib->state.ledger, m->member_id), ledger_model_name(lib->model));
    printf("Fines         : %ld outstanding, %ld accruing on overdue loans\n",
           state_fine_due(&lib->state, m->member_id),
           state_accruing_fine(&lib->state, m->member_id, now));
    printf("Loans and holds:\n");
    for (i = 0; i < proj.copy_count; i++) {
        const CopyStatus *c = &proj.copies[i];
        const Book *b;
        char due[16];

        if (strcasecmp(c->current_holder_id, m->member_id) != 0)
            continue;
        b = registry_find_book(&lib->books, c->book_id);
        format_day(c->due_date, due);
        if (c->state == COPY_BORROWED)
            printf("  %-10s %-26.26s BORROWED  due %s%s%s\n", c->copy_id, b ? b->title : "?",
                   due, days_late(c->due_date, now) ? " (OVERDUE)" : "",
                   c->pending ? " [pending]" : "");
        else
            printf("  %-10s %-26.26s RESERVED for this member (offered from the queue)%s\n",
                   c->copy_id, b ? b->title : "?", c->pending ? " [pending]" : "");
        loans++;
    }
    for (i = 0; i < proj.queue_count; i++) {
        size_t pos = 0;
        if (state_in_queue(&proj, proj.queues[i].book_id, m->member_id, &pos)) {
            printf("  waiting for %s - position %zu in the reservation queue\n",
                   proj.queues[i].book_id, pos);
            loans++;
        }
    }
    if (loans == 0)
        printf("  (none)\n");
    state_free(&proj);
}

void cmd_view_member(Library *lib, int argc, char **argv)
{
    size_t i;

    if (argc > 1) {
        const Member *m = registry_find_member(&lib->members, argv[1]);
        heading("MEMBER");
        if (m == NULL) {
            say_err("Member %s is not in the member registry.", argv[1]);
            return;
        }
        print_member_detail(lib, m);
        return;
    }
    heading("MEMBERS");
    printf("%-9s %-24s %-8s %5s %6s %7s %7s %6s\n", "ID", "Name", "Course", "Loans", "Fines",
           "Balance", "Nonce", "Key");
    rule('-');
    for (i = 0; i < lib->members.count; i++) {
        const Member *m = &lib->members.items[i];
        printf("%-9s %-24.24s %-8s %5zu %6ld %7ld %7ld %6s\n", m->member_id, m->full_name,
               m->course_code, state_loans(&lib->state, m->member_id),
               state_fine_due(&lib->state, m->member_id),
               ledger_balance(&lib->state.ledger, m->member_id),
               state_nonce(&lib->state, m->member_id),
               keydir_get(&lib->keys, m->member_id) ? "P-256" : "none");
    }
    printf("%zu member(s). Use view_member <id> for details.\n", lib->members.count);
}

void cmd_member_nonce(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX];
    const char *id = arg_or_prompt(argc, argv, 1, "Member ID: ", buf, sizeof buf);
    const Member *m;
    LibraryState proj;

    heading("MEMBER NONCE (replay protection)");
    if (id == NULL)
        return;
    m = registry_find_member(&lib->members, id);
    if (m == NULL) {
        say_err("Member %s is not in the member registry.", id);
        return;
    }
    if (!project(lib, &proj))
        return;
    printf("Member              : %s (%s)\n", m->member_id, m->full_name);
    printf("Confirmed nonce     : %ld  (requests of this member already in blocks)\n",
           state_nonce(&lib->state, m->member_id));
    printf("Pending requests    : %zu  (signed, waiting in the pool)\n",
           pending_by_signer(lib, m->member_id));
    printf("Next request nonce  : %ld\n", state_nonce(&proj, m->member_id));
    printf("\nEvery request signed by %s must carry exactly the expected nonce. The confirmed\n"
           "nonce increments only when a block containing the request is mined, so a copied\n"
           "(replayed) request with an old nonce is rejected.\n", m->member_id);
    state_free(&proj);
}

/* ------------------------------------------------------------------------ */
/* Books and copies                                                         */
/* ------------------------------------------------------------------------ */

static Status add_copies(Library *lib, const char *book_id, long count, Condition cond)
{
    long i;

    for (i = 0; i < count; i++) {
        char id[COPY_ID_LEN];
        const char *why = NULL;
        Status st = library_add_copy(lib, NULL, book_id, cond, id, &why);

        if (st != LT_OK) {
            say_err("Copy not added: %s.", why ? why : status_str(st));
            return st;
        }
        say_ok("Copy %s of %s registered (%s, AVAILABLE) and appended to %s.", id, book_id,
               condition_name(cond), COPIES_FILE);
    }
    return LT_OK;
}

void cmd_register_book(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], b2[INPUT_MAX], b3[INPUT_MAX];
    const char *id, *title, *author, *why = NULL;
    long copies = 1;
    Status st;

    heading("REGISTER BOOK");
    if ((id = arg_or_prompt(argc, argv, 1, "Book ID (e.g. BK007): ", b1, sizeof b1)) == NULL ||
        (title = arg_or_prompt(argc, argv, 2, "Title: ", b2, sizeof b2)) == NULL ||
        (author = arg_or_prompt(argc, argv, 3, "Author: ", b3, sizeof b3)) == NULL)
        return;
    if (argc > 4) {
        if (parse_long(argv[4], 0, 20, &copies) != 0) {
            say_err("The number of copies must be 0-20.");
            return;
        }
    } else if (prompt_long("Number of physical copies to register now (0-20) [1]: ", 0, 20, 1,
                           &copies) != 1) {
        return;
    }
    st = library_register_book(lib, id, title, author, &why);
    if (st != LT_OK) {
        say_err("Book not registered: %s.", why ? why : status_str(st));
        return;
    }
    say_ok("Book %s \"%s\" by %s registered and appended to %s.", id, title, author, BOOKS_FILE);
    (void)add_copies(lib, lib->books.items[lib->books.count - 1].book_id, copies, COND_NEW);
}

void cmd_add_copy(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], b2[INPUT_MAX];
    const char *book_id, *cond_text, *why = NULL;
    const Book *book;
    Condition cond = COND_NEW;
    char id[COPY_ID_LEN];
    Status st;

    heading("ADD COPY");
    if ((book_id = arg_or_prompt(argc, argv, 1, "Book ID: ", b1, sizeof b1)) == NULL)
        return;
    book = registry_find_book(&lib->books, book_id);
    if (book == NULL) {
        say_err("Book %s is not in the book registry - register_book first.", book_id);
        return;
    }
    cond_text = argc > 2 ? argv[2] : NULL;
    if (cond_text == NULL && prompt_text("Condition NEW / GOOD / WORN [NEW]: ", b2, sizeof b2) == 1)
        cond_text = b2;
    if (cond_text != NULL && (condition_parse(cond_text, &cond) != 0 || cond == COND_LOST)) {
        say_err("Condition must be NEW, GOOD or WORN.");
        return;
    }
    st = library_add_copy(lib, argc > 3 ? argv[3] : NULL, book->book_id, cond, id, &why);
    if (st != LT_OK) {
        say_err("Copy not added: %s.", why ? why : status_str(st));
        return;
    }
    say_ok("Copy %s of %s \"%s\" registered (%s, AVAILABLE). %s now has %zu copies.", id,
           book->book_id, book->title, condition_name(cond), book->book_id,
           registry_count_copies(&lib->copies, book->book_id));
}

static void print_copy_header(void)
{
    printf("%-10s %-6s %-9s %-10s %-9s %-10s %4s %4s  %s\n", "Copy ID", "Book", "Condition",
           "State", "Holder", "Due date", "Ren", "Late", "Pending requests");
    rule('-');
}

static void print_copy_row(const Library *lib, const CopyStatus *c)
{
    char due[16], note[160];
    time_t now = lib_now();

    format_day(c->due_date, due);
    pending_note(lib, c->copy_id, note, sizeof note);
    printf("%-10s %-6s %-9s %s%-10s%s %-9s %-10s %4d %4ld  %s\n", c->copy_id, c->book_id,
           condition_name(c->condition),
           clr(c->state == COPY_AVAILABLE ? CLR_GREEN : c->state == COPY_LOST ? CLR_RED : CLR_YELLOW),
           copy_state_name(c->state), clr(CLR_RESET),
           c->current_holder_id[0] ? c->current_holder_id : "-", due, c->renewals,
           c->state == COPY_BORROWED ? days_late(c->due_date, now) : 0, note);
}

void cmd_view_book(Library *lib, int argc, char **argv)
{
    size_t i;

    if (argc > 1) {
        const Book *b = registry_find_book(&lib->books, argv[1]);
        const ReservationQueue *q;

        heading("BOOK");
        if (b == NULL) {
            say_err("Book %s is not in the book registry.", argv[1]);
            return;
        }
        printf("%s - \"%s\" by %s\n\nCopies (confirmed state):\n", b->book_id, b->title,
               b->author);
        print_copy_header();
        for (i = 0; i < lib->state.copy_count; i++)
            if (strcasecmp(lib->state.copies[i].book_id, b->book_id) == 0)
                print_copy_row(lib, &lib->state.copies[i]);
        q = state_queue(&lib->state, b->book_id);
        printf("\nReservation queue: %zu member(s) waiting (see reservation_status %s)\n",
               q ? q->count : 0, b->book_id);
        return;
    }
    heading("BOOK CATALOGUE");
    printf("%-6s %-30s %-24s %6s %5s %5s %5s %5s %5s\n", "ID", "Title", "Author", "Copies",
           "Avail", "Borr", "Resv", "Lost", "Queue");
    rule('-');
    for (i = 0; i < lib->books.count; i++) {
        const Book *b = &lib->books.items[i];
        const ReservationQueue *q = state_queue(&lib->state, b->book_id);
        size_t c, n[4] = {0, 0, 0, 0}, total = 0;

        for (c = 0; c < lib->state.copy_count; c++) {
            if (strcasecmp(lib->state.copies[c].book_id, b->book_id) == 0) {
                n[lib->state.copies[c].state]++;
                total++;
            }
        }
        printf("%-6s %-30.30s %-24.24s %6zu %5zu %5zu %5zu %5zu %5zu\n", b->book_id, b->title,
               b->author, total, n[COPY_AVAILABLE], n[COPY_BORROWED], n[COPY_RESERVED],
               n[COPY_LOST], q ? q->count : 0);
    }
    printf("Confirmed state. Pending requests are shown by view_copy and pool_view.\n");
}

void cmd_view_copy(Library *lib, int argc, char **argv)
{
    size_t i;

    if (argc > 1) {
        const CopyRecord *cr = registry_find_copy(&lib->copies, argv[1]);
        const CopyStatus *c;
        const Record *last;
        LibraryState proj;
        long block = -1;
        char due[16];

        heading("COPY");
        if (cr == NULL) {
            say_err("Copy %s is not in the copy registry (copies.txt).", argv[1]);
            return;
        }
        c = state_copy(&lib->state, cr->copy_id);
        if (c == NULL)
            return;
        format_day(c->due_date, due);
        printf("copy_id           : %s\n", c->copy_id);
        printf("book_id           : %s (%s)\n", c->book_id,
               registry_find_book(&lib->books, c->book_id)->title);
        printf("condition         : %s (registered as %s)\n", condition_name(c->condition),
               condition_name(cr->condition));
        printf("state             : %s\n", copy_state_name(c->state));
        printf("current_holder_id : %s\n", c->current_holder_id[0] ? c->current_holder_id : "-");
        printf("due_date          : %s\n", due);
        printf("renewals          : %d of %d\n", c->renewals, lib->rules.max_renewals);
        printf("overdue flagged   : %s\n", c->overdue_flagged ? "yes" : "no");
        last = library_last_record_for_copy(lib, c->copy_id, ACT_BORROW, &block);
        if (last != NULL)
            printf("last BORROWED     : record %s in block #%ld by %s\n", last->record_id, block,
                   last->member_id);
        if (project(lib, &proj)) {
            const CopyStatus *p = state_copy(&proj, c->copy_id);
            if (p != NULL && p->pending)
                printf("after pending     : %s %s (requests waiting in the pool)\n",
                       copy_state_name(p->state), p->current_holder_id);
            state_free(&proj);
        }
        return;
    }
    heading("COPY INVENTORY (confirmed state)");
    print_copy_header();
    for (i = 0; i < lib->state.copy_count; i++)
        print_copy_row(lib, &lib->state.copies[i]);
    printf("%zu copies. State machine: AVAILABLE -> BORROWED -> AVAILABLE or RESERVED "
           "(queue); AVAILABLE/BORROWED -> LOST.\n", lib->state.copy_count);
}

void cmd_mark_lost(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], b2[INPUT_MAX], err[300];
    const char *copy, *reason;
    Request req;
    Status st;

    heading("MARK COPY LOST (librarian override)");
    if ((copy = arg_or_prompt(argc, argv, 1, "Copy ID: ", b1, sizeof b1)) == NULL ||
        (reason = arg_or_prompt(argc, argv, 2, "Reason code (e.g. NOT_RETURNED): ", b2,
                                sizeof b2)) == NULL)
        return;
    st = library_mark_lost(lib, copy, reason, &req, err, sizeof err);
    if (st != LT_OK) {
        report_failure(st, err);
        return;
    }
    print_request_added(lib, &req);
}

/* ------------------------------------------------------------------------ */
/* Lending                                                                  */
/* ------------------------------------------------------------------------ */

void cmd_borrow_book(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], b2[INPUT_MAX], err[400], due_text[16];
    const char *item, *member;
    time_t due = 0;
    Request req;
    Status st;

    heading("BORROW BOOK");
    if ((item = arg_or_prompt(argc, argv, 1, "Book ID or copy ID: ", b1, sizeof b1)) == NULL ||
        (member = arg_or_prompt(argc, argv, 2, "Member ID: ", b2, sizeof b2)) == NULL)
        return;
    if (argc > 3 && parse_date(argv[3], &due) != 0) {
        say_err("'%s' is not a valid date - use YYYY-MM-DD.", argv[3]);
        return;
    }
    st = library_borrow(lib, item, member, due, &req, err, sizeof err);
    if (st != LT_OK) {
        say_err("Borrow rejected: %s.", err);
        if (st == LT_ERR_STATE && registry_find_member(&lib->members, member) != NULL &&
            registry_find_book(&lib->books, item) != NULL)
            say_info("Join the reservation queue with: reserve_book %s %s", item, member);
        return;
    }
    print_request_added(lib, &req);
    format_day(req.rec.due_date, due_text);
    printf("         copy %s \"%s\" -> %s (%s), due %s (%d-day loan)\n", req.rec.copy_id,
           req.rec.book_title, req.rec.member_id, req.rec.member_name, due_text,
           (int)((req.rec.due_date - req.rec.timestamp + DAY_SECONDS - 1) / DAY_SECONDS));
    printf("         The copy is held for this request; mine a block to confirm the loan.\n");
}

void cmd_return_book(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], err[400], due[16];
    const char *copy, *reason = argc > 3 ? argv[3] : NULL;
    Condition cond = COND_GOOD;
    int has_cond = 0;
    Request req;
    Status st;

    heading("RETURN BOOK");
    if ((copy = arg_or_prompt(argc, argv, 1, "Copy ID: ", b1, sizeof b1)) == NULL)
        return;
    if (argc > 2 && strcmp(argv[2], "-") != 0) {
        if (condition_parse(argv[2], &cond) != 0) {
            say_err("Condition must be NEW, GOOD or WORN.");
            return;
        }
        has_cond = 1;
    }
    st = library_return(lib, copy, has_cond, cond, reason, &req, err, sizeof err);
    if (st != LT_OK) {
        say_err("Return rejected: %s.", err);
        return;
    }
    print_request_added(lib, &req);
    format_day(req.rec.due_date, due);
    if (req.rec.fine_amount > 0)
        printf("         %sLATE%s: due %s, returned %ld day(s) late -> fine %ld coin(s) "
               "(%d per day), token reward %d\n", clr(CLR_RED), clr(CLR_RESET), due,
               days_late(req.rec.due_date, req.rec.timestamp), req.rec.fine_amount,
               FINE_PER_DAY, req.rec.token_reward);
    else
        printf("         %sON TIME%s: due %s -> token reward %d\n", clr(CLR_GREEN),
               clr(CLR_RESET), due, req.rec.token_reward);
    printf("         When mined, the block's reward transaction credits %s with %d - %d fee "
           "= %d coin(s).\n", req.rec.member_id, req.rec.token_reward, TX_FEE,
           req.rec.token_reward - TX_FEE);
    {
        const CopyStatus *c = state_copy(&lib->state, req.rec.copy_id);
        const ReservationQueue *q = c ? state_queue(&lib->state, c->book_id) : NULL;
        if (q != NULL && q->count > 0)
            printf("         Reservation queue for %s: the copy will be offered to %s "
                   "(RESERVED) when this return is confirmed.\n", c->book_id,
                   q->items[0].member_id);
    }
}

void cmd_renew_book(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], err[400], due[16];
    const char *copy;
    Request req;
    Status st;

    heading("RENEW BOOK");
    if ((copy = arg_or_prompt(argc, argv, 1, "Copy ID: ", b1, sizeof b1)) == NULL)
        return;
    st = library_renew(lib, copy, argc > 2 ? argv[2] : NULL, &req, err, sizeof err);
    if (st != LT_OK) {
        say_err("Renewal rejected: %s.", err);
        return;
    }
    print_request_added(lib, &req);
    format_day(req.rec.due_date, due);
    printf("         new due date %s (+%d days, renewal period)\n", due, lib->rules.renewal_days);
}

void cmd_reserve_book(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], b2[INPUT_MAX], err[400];
    const char *book, *member;
    LibraryState proj;
    Request req;
    Status st;

    heading("RESERVE BOOK");
    if ((book = arg_or_prompt(argc, argv, 1, "Book ID: ", b1, sizeof b1)) == NULL ||
        (member = arg_or_prompt(argc, argv, 2, "Member ID: ", b2, sizeof b2)) == NULL)
        return;
    st = library_reserve(lib, book, member, &req, err, sizeof err);
    if (st != LT_OK) {
        say_err("Reservation rejected: %s.", err);
        return;
    }
    print_request_added(lib, &req);
    if (project(lib, &proj)) {
        size_t pos = 0;
        if (state_in_queue(&proj, req.rec.book_id, req.rec.member_id, &pos))
            printf("         %s is number %zu in the FIFO queue for %s. When a copy is "
                   "returned it is offered to the head of the queue first.\n",
                   req.rec.member_id, pos, req.rec.book_id);
        state_free(&proj);
    }
}

void cmd_reservation_status(Library *lib, int argc, char **argv)
{
    LibraryState proj;
    size_t i, j, shown = 0;
    const char *only = argc > 1 ? argv[1] : NULL;

    heading("RESERVATION STATUS");
    if (only != NULL && registry_find_book(&lib->books, only) == NULL) {
        say_err("Book %s is not in the book registry.", only);
        return;
    }
    if (!project(lib, &proj))
        return;
    printf("%-6s %-26s %4s %-9s %-24s %-10s %s\n", "Book", "Title", "Pos", "Member", "Name",
           "Reserved", "Status");
    rule('-');
    for (i = 0; i < proj.queue_count; i++) {
        const ReservationQueue *q = &proj.queues[i];
        const Book *b = registry_find_book(&lib->books, q->book_id);

        if (only != NULL && strcasecmp(only, q->book_id) != 0)
            continue;
        for (j = 0; j < q->count; j++) {
            char when[16];
            format_day(q->items[j].reservation_date, when);
            printf("%-6s %-26.26s %4zu %-9s %-24.24s %-10s %s\n", q->book_id,
                   b ? b->title : "?", j + 1, q->items[j].member_id,
                   member_name(lib, q->items[j].member_id), when,
                   q->items[j].pending ? "pending (not mined)" : "confirmed");
            shown++;
        }
    }
    if (shown == 0)
        printf("(no one is waiting%s%s)\n", only ? " for " : "", only ? only : "");
    printf("\nCopies held for the next member in a queue (state RESERVED):\n");
    for (i = 0, shown = 0; i < proj.copy_count; i++) {
        const CopyStatus *c = &proj.copies[i];
        char when[16];

        if (c->state != COPY_RESERVED || (only != NULL && strcasecmp(only, c->book_id) != 0))
            continue;
        format_day(c->hold_reserved_at, when);
        printf("  %-10s held for %s (%s), reserved on %s%s - borrow_book %s %s collects it\n",
               c->copy_id, c->current_holder_id, member_name(lib, c->current_holder_id), when,
               c->pending ? " [pending]" : "", c->book_id, c->current_holder_id);
        shown++;
    }
    if (shown == 0)
        printf("  (none)\n");
    state_free(&proj);
}

/* ------------------------------------------------------------------------ */
/* Overdue and fines                                                        */
/* ------------------------------------------------------------------------ */

void cmd_check_overdue(Library *lib, int argc, char **argv)
{
    LibraryState proj;
    time_t now = lib_now();
    char today[16];
    size_t i, n = 0;

    (void)argc;
    (void)argv;
    heading("OVERDUE CHECK");
    format_day(now, today);
    printf("Library date: %s | fine: %d coin per day (or part of a day) late\n\n", today,
           FINE_PER_DAY);
    run_overdue_scan(lib, 1);
    if (!project(lib, &proj))
        return;
    printf("\n%-10s %-24s %-9s %-10s %5s %6s  %s\n", "Copy", "Title", "Member", "Due", "Days",
           "Fine", "OVERDUE record");
    rule('-');
    for (i = 0; i < lib->state.copy_count; i++) {
        const CopyStatus *c = &lib->state.copies[i];
        const CopyStatus *p = state_copy(&proj, c->copy_id);
        const Book *b;
        char due[16];

        if (c->state != COPY_BORROWED || now <= c->due_date)
            continue;
        b = registry_find_book(&lib->books, c->book_id);
        format_day(c->due_date, due);
        printf("%-10s %-24.24s %-9s %-10s %5ld %6ld  %s\n", c->copy_id, b ? b->title : "?",
               c->current_holder_id, due, days_late(c->due_date, now),
               fine_for(c->due_date, now),
               c->overdue_flagged ? "confirmed on the chain"
               : (p && p->overdue_flagged) ? "pending in the pool"
                                           : (p && p->state != COPY_BORROWED) ? "return pending"
                                                                             : "-");
        n++;
    }
    if (n == 0)
        printf("(no loans are overdue)\n");
    else
        printf("\nThe fine keeps growing until the copy is returned; the RETURNED record then "
               "fixes it (fine_amount).\n");
    state_free(&proj);
}

void cmd_view_fines(Library *lib, int argc, char **argv)
{
    time_t now = lib_now();
    size_t i, shown = 0;
    const char *only = argc > 1 ? argv[1] : NULL;

    heading("FINES");
    if (only != NULL && registry_find_member(&lib->members, only) == NULL) {
        say_err("Member %s is not in the member registry.", only);
        return;
    }
    printf("%-9s %-24s %9s %6s %12s %9s %16s\n", "Member", "Name", "Assessed", "Paid",
           "Outstanding", "Accruing", "Pending payment");
    rule('-');
    for (i = 0; i < lib->members.count; i++) {
        const Member *m = &lib->members.items[i];
        const FineAccount *f = state_fines(&lib->state, m->member_id);
        long accruing = state_accruing_fine(&lib->state, m->member_id, now), pending = 0;
        size_t p;

        if (only != NULL && strcasecmp(only, m->member_id) != 0)
            continue;
        if (only == NULL && f == NULL && accruing == 0)
            continue;
        for (p = 0; p < lib->pool.count; p++) {
            const Record *r = &lib->pool.items[p].rec;
            if (r->action == ACT_FINE && strcasecmp(r->member_id, m->member_id) == 0)
                pending += r->tx.amount;
        }
        printf("%-9s %-24.24s %9ld %6ld %12ld %9ld %16ld\n", m->member_id, m->full_name,
               f ? f->assessed : 0, f ? f->paid : 0, f ? f->assessed - f->paid : 0, accruing,
               pending);
        shown++;
    }
    if (shown == 0)
        printf("(no fines)\n");
    printf("\nAssessed = fines fixed by confirmed late RETURNED records. Accruing = overdue loans "
           "not yet returned.\nSettle with: settle_fine <member_id> [amount|all] [tokens|cash]\n");
}

void cmd_settle_fine(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], b2[INPUT_MAX], err[400];
    const char *member, *method;
    long amount = 0;
    int cash;
    Request req;
    Status st;

    heading("SETTLE FINE");
    if ((member = arg_or_prompt(argc, argv, 1, "Member ID: ", b1, sizeof b1)) == NULL)
        return;
    if (argc > 2 && strcasecmp(argv[2], "all") != 0 &&
        parse_long(argv[2], 1, 1000000L, &amount) != 0) {
        say_err("The amount must be a positive whole number (or 'all').");
        return;
    }
    method = argc > 3 ? argv[3] : NULL;
    if (method == NULL) {
        if (prompt_text("Pay with tokens or cash? [tokens/cash]: ", b2, sizeof b2) != 1)
            return;
        method = b2;
    }
    if (strcasecmp(method, "tokens") == 0 || strcmp(method, "1") == 0) {
        cash = 0;
    } else if (strcasecmp(method, "cash") == 0 || strcmp(method, "2") == 0) {
        cash = 1;
    } else {
        say_err("Payment method must be 'tokens' or 'cash'.");
        return;
    }
    st = library_settle_fine(lib, member, amount, cash, &req, err, sizeof err);
    if (st != LT_OK) {
        say_err("Fine settlement rejected: %s.", err);
        return;
    }
    print_request_added(lib, &req);
    if (cash)
        printf("         Cash payment of %ld coin(s) recorded by the librarian (no token "
               "movement, fee 0).\n", req.rec.tx.amount);
    else
        printf("         %s pays %ld coin(s) + %d fee to %s from their token balance when "
               "mined (account nonce %ld).\n", req.rec.member_id, req.rec.tx.amount, TX_FEE,
               LIBRARY_ACCOUNT, req.rec.tx.nonce);
}
