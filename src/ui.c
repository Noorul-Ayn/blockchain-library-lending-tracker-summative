/**
 * @file ui.c
 * @brief Interactive menus and all user-facing output.
 *
 * This layer only talks to the user; every rule about what is allowed lives
 * in lending.c, auth.c and blockchain.c.
 */
#include "ui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blockchain.h"
#include "crypto.h"
#include "storage.h"
#include "util.h"

#define INPUT_MAX          128
#define MAX_LOGIN_ATTEMPTS 3
#define MAX_SETUP_ATTEMPTS 5

#if defined(__GNUC__)
#define PRINTF_LIKE(fmt_idx, arg_idx) __attribute__((format(printf, fmt_idx, arg_idx)))
#else
#define PRINTF_LIKE(fmt_idx, arg_idx)
#endif

/* ------------------------------------------------------------------------ */
/* Output helpers                                                           */
/* ------------------------------------------------------------------------ */

static void vsay(Color color, const char *label, const char *fmt, va_list ap)
    PRINTF_LIKE(3, 0);
static void say_ok(const char *fmt, ...) PRINTF_LIKE(1, 2);
static void say_err(const char *fmt, ...) PRINTF_LIKE(1, 2);
static void say_warn(const char *fmt, ...) PRINTF_LIKE(1, 2);
static void say_info(const char *fmt, ...) PRINTF_LIKE(1, 2);

static void vsay(Color color, const char *label, const char *fmt, va_list ap)
{
    printf("%s%s%s ", clr(color), label, clr(CLR_RESET));
    vprintf(fmt, ap);
    putchar('\n');
}

static void say_ok(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_GREEN, "SUCCESS:", fmt, ap);
    va_end(ap);
}

static void say_err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_RED, "ERROR:", fmt, ap);
    va_end(ap);
}

static void say_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_YELLOW, "WARNING:", fmt, ap);
    va_end(ap);
}

static void say_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_CYAN, "INFO:", fmt, ap);
    va_end(ap);
}

static void rule(char ch)
{
    char line[77];
    memset(line, ch, sizeof line - 1);
    line[sizeof line - 1] = '\0';
    puts(line);
}

static void heading(const char *title)
{
    printf("\n%s=== %s ===%s\n", clr(CLR_BOLD), title, clr(CLR_RESET));
}

static Color action_color(const char *action)
{
    if (strcmp(action, ACTION_BORROWED) == 0) return CLR_CYAN;
    if (strcmp(action, ACTION_RETURNED) == 0) return CLR_GREEN;
    if (strcmp(action, ACTION_OVERDUE) == 0)  return CLR_RED;
    return CLR_DIM;
}

/* ------------------------------------------------------------------------ */
/* Input helpers                                                            */
/* ------------------------------------------------------------------------ */

/**
 * Reads and trims one line.
 * @return 1 = non-empty input, 0 = empty/invalid (already reported), -1 = EOF.
 */
static int prompt_text(const char *prompt, char *buf, size_t cap)
{
    InputResult r = read_line(prompt, buf, cap);
    char *trimmed;

    if (r == INPUT_EOF)
        return -1;
    if (r == INPUT_TOO_LONG) {
        say_err("Input is too long.");
        return 0;
    }
    trimmed = str_trim(buf);
    memmove(buf, trimmed, strlen(trimmed) + 1);
    return buf[0] != '\0';
}

/**
 * Asks for a new password twice and checks the password policy.
 * @return 1 = accepted, 0 = rejected (reported), -1 = EOF.
 */
static int prompt_new_password(char *password, size_t cap)
{
    char confirm[INPUT_MAX];
    const char *reason = NULL;
    int result = 1;

    if (read_secret("Password (min 8 chars, letters + digits): ", password, cap) != INPUT_OK)
        return -1;
    if (!auth_password_acceptable(password, &reason)) {
        say_err("%s.", reason);
        result = 0;
    } else if (read_secret("Confirm password: ", confirm, sizeof confirm) != INPUT_OK) {
        result = -1;
    } else if (strcmp(password, confirm) != 0) {
        say_err("Passwords do not match.");
        result = 0;
    }
    crypto_wipe(confirm, sizeof confirm);
    if (result != 1)
        crypto_wipe(password, cap);
    return result;
}

static int require(const Library *lib, Permission perm, const char *what)
{
    if (auth_has_permission(&lib->session, perm))
        return 1;
    say_err("ACCESS DENIED - '%s' is restricted to administrators (your role: %s).",
            what, auth_role_name(lib->session.role));
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Block display                                                            */
/* ------------------------------------------------------------------------ */

static void print_block(const Block *b, KeyRing *keys)
{
    char when[32], computed[HASH_HEX_LEN] = "";
    SigCheck sig = block_verify_signature(b, keys);
    int hash_ok = block_compute_hash(b, computed) == LT_OK && strcmp(computed, b->hash) == 0;

    format_time(b->timestamp, when, sizeof when);
    printf("%sBlock #%d%s   %s\n", clr(CLR_BOLD), b->index, clr(CLR_RESET), when);
    printf("  Book        : %s - %s\n", b->book_id, b->book_title);
    printf("  Member      : %s - %s\n", b->member_id, b->member_name);
    printf("  Action      : %s%s%s\n", clr(action_color(b->action)), b->action, clr(CLR_RESET));
    printf("  Signed by   : %s\n", b->signed_by);
    printf("  Signature   : %s%s%s\n",
           clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED),
           sig == SIG_VALID ? "VALID (ECDSA P-256)"
                            : sig == SIG_NO_KEY ? "UNVERIFIABLE (signer's public key missing)"
                                                : "INVALID",
           clr(CLR_RESET));
    printf("  Hash check  : %s%s%s\n", clr(hash_ok ? CLR_GREEN : CLR_RED),
           hash_ok ? "OK" : "MISMATCH", clr(CLR_RESET));
    printf("  Prev hash   : %s\n", b->previous_hash);
    printf("  Hash        : %s\n", b->hash);
}

/** Prints the detailed report and a verdict. @return 1 if valid. */
static int print_validation(Library *lib)
{
    ValidationReport rep;
    int valid;

    printf("Checking %zu block(s): SHA-256 hash, previous_hash link, ECDSA signature\n\n",
           lib->chain.length);
    valid = chain_validate(&lib->chain, &lib->keys, stdout, &rep);
    putchar('\n');
    if (valid) {
        printf("%sRESULT: CHAIN VALID%s - all %zu blocks verified; no tampering detected.\n",
               clr(CLR_GREEN), clr(CLR_RESET), rep.blocks_checked);
    } else {
        printf("%sRESULT: CHAIN INVALID - TAMPERING DETECTED%s", clr(CLR_RED), clr(CLR_RESET));
        if (rep.first_bad_index >= 0)
            printf(" (first bad block: #%ld)", rep.first_bad_index);
        printf("\n        hash mismatches: %zu | broken links: %zu | bad signatures: %zu"
               " | structure errors: %zu\n",
               rep.hash_errors, rep.link_errors, rep.signature_errors, rep.structure_errors);
    }
    return valid;
}

/* ------------------------------------------------------------------------ */
/* Start-up: banner, setup wizard, login                                    */
/* ------------------------------------------------------------------------ */

void ui_banner(void)
{
    putchar('\n');
    rule('=');
    printf("%s   BLOCKCHAIN LIBRARY LENDING TRACKER%s\n", clr(CLR_BOLD), clr(CLR_RESET));
    printf("   SHA-256 hash chain  |  ECDSA P-256 signatures  |  role-based access\n");
    rule('=');
}

int ui_first_run_setup(const char *data_dir)
{
    char username[INPUT_MAX], password[INPUT_MAX];
    int attempt;

    heading("FIRST-RUN SETUP");
    puts("No user accounts exist yet. Create the ADMINISTRATOR account now.");
    puts("A personal ECDSA P-256 key pair will be generated for this account.");
    puts("Its private key is stored encrypted (PKCS#8, AES-256) with your password,");
    puts("so nobody can sign lending records without logging in.\n");

    for (attempt = 0; attempt < MAX_SETUP_ATTEMPTS; attempt++) {
        int r = prompt_text("Admin username (3-19 letters/digits/_): ", username, sizeof username);
        Status st;

        if (r < 0)
            return 0;
        if (r == 0 || !auth_valid_username(username)) {
            say_err("Invalid username. Use 3-19 letters, digits or underscores.");
            continue;
        }
        r = prompt_new_password(password, sizeof password);
        if (r < 0)
            return 0;
        if (r == 0)
            continue;

        printf("Generating signing keys and hashing password (PBKDF2, %d iterations)...\n",
               PBKDF2_ITERATIONS);
        st = auth_create_user(data_dir, username, password, ROLE_ADMIN);
        crypto_wipe(password, sizeof password);
        if (st == LT_OK) {
            say_ok("Administrator '%s' created. Keys stored in %s/%s/.", username, data_dir, KEYS_DIR);
            return 1;
        }
        say_err("Could not create the account: %s.", status_str(st));
    }
    say_err("Too many failed attempts.");
    return 0;
}

int ui_login(const char *data_dir, Session *session)
{
    char username[INPUT_MAX], password[INPUT_MAX];
    int attempt;

    heading("LOGIN");
    for (attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
        Status st;
        int r = prompt_text("Username: ", username, sizeof username);

        if (r < 0)
            return 0;
        if (read_secret("Password: ", password, sizeof password) != INPUT_OK)
            return 0;

        st = auth_login(data_dir, username, password, session);
        crypto_wipe(password, sizeof password);

        if (st == LT_OK) {
            say_ok("Logged in as %s [%s]. Signing key unlocked and verified.",
                   session->username, auth_role_name(session->role));
            return 1;
        }
        if (st == LT_ERR_CRYPTO)
            say_err("Password accepted but the signing key could not be unlocked or does "
                    "not match the public key (attempt %d/%d).", attempt, MAX_LOGIN_ATTEMPTS);
        else
            say_err("Invalid username or password (attempt %d/%d).", attempt, MAX_LOGIN_ATTEMPTS);
        if (attempt < MAX_LOGIN_ATTEMPTS)
            sleep(1); /* slows down password guessing */
    }
    say_err("Too many failed login attempts. Exiting.");
    return 0;
}

void ui_startup_validation(Library *lib)
{
    ValidationReport rep;

    if (chain_validate(&lib->chain, &lib->keys, NULL, &rep)) {
        say_ok("Blockchain verified: %zu block(s), all hashes, links and signatures valid.",
               rep.blocks_checked);
    } else {
        say_warn("Blockchain validation FAILED (first bad block: #%ld). "
                 "New lending records are blocked until the chain is restored. "
                 "Choose option 6 for details.", rep.first_bad_index);
    }
}

/* ------------------------------------------------------------------------ */
/* Menu actions                                                             */
/* ------------------------------------------------------------------------ */

/** Reads a book ID and a member ID. @return 1 ok, 0 invalid, -1 EOF. */
static int prompt_ids(char *book_id, char *member_id, size_t cap)
{
    int r = prompt_text("Book ID   : ", book_id, cap);

    if (r <= 0)
        return r;
    r = prompt_text("Member ID : ", member_id, cap);
    if (r == 0)
        say_err("Member ID cannot be empty.");
    return r;
}

static void report_lending_error(Library *lib, Status st, const char *book_id,
                                 const char *member_id)
{
    const Book *book = registry_find_book(&lib->books, book_id);
    const Block *loan = NULL;
    char when[32];

    if (book == NULL && (st == LT_ERR_ON_LOAN || st == LT_ERR_NOT_ON_LOAN ||
                         st == LT_ERR_WRONG_MEMBER)) {
        say_err("Operation failed: %s.", status_str(st));
        return;
    }
    switch (st) {
    case LT_ERR_NOT_FOUND:
        say_err("Book or Member not found");
        if (book == NULL)
            printf("       - book_id '%s' is not in %s\n", book_id, BOOKS_FILE);
        if (registry_find_member(&lib->members, member_id) == NULL)
            printf("       - member_id '%s' is not in %s\n", member_id, MEMBERS_FILE);
        puts("       No block was created.");
        break;
    case LT_ERR_ON_LOAN:
        (void)lending_book_state(lib, book->book_id, &loan);
        if (loan != NULL) {
            format_time(loan->timestamp, when, sizeof when);
            say_err("'%s' (%s) is already on loan to %s (%s) since %s.",
                    book->title, book->book_id, loan->member_id, loan->member_name, when);
        } else {
            say_err("'%s' is already on loan.", book->title);
        }
        break;
    case LT_ERR_NOT_ON_LOAN:
        if (chain_find_latest_borrow(&lib->chain, book->book_id) == NULL)
            say_err("No BORROWED record exists for %s - this book was never borrowed.",
                    book->book_id);
        else
            say_err("%s has no outstanding loan - it was already returned.", book->book_id);
        break;
    case LT_ERR_WRONG_MEMBER:
        (void)lending_book_state(lib, book->book_id, &loan);
        say_err("%s is on loan to %s (%s), not to %s.", book->book_id,
                loan ? loan->member_id : "?", loan ? loan->member_name : "?", member_id);
        break;
    case LT_ERR_CHAIN_INVALID:
        say_err("The blockchain failed validation - refusing to add records to a tampered "
                "chain. Choose option 6 for details.");
        break;
    case LT_ERR_DENIED:
        say_err("ACCESS DENIED - your role cannot record lending actions.");
        break;
    default:
        say_err("Operation failed: %s.", status_str(st));
        break;
    }
}

static void ui_borrow(Library *lib)
{
    char book_id[INPUT_MAX], member_id[INPUT_MAX];
    Status st;

    heading("BORROW A BOOK");
    if (prompt_ids(book_id, member_id, sizeof book_id) != 1)
        return;

    st = lending_borrow(lib, book_id, member_id);
    if (st != LT_OK) {
        report_lending_error(lib, st, book_id, member_id);
        return;
    }
    say_ok("Loan recorded, signed and saved as a new block:");
    print_block(chain_last(&lib->chain), &lib->keys);
}

static void ui_return(Library *lib)
{
    char book_id[INPUT_MAX], member_id[INPUT_MAX];
    Status st;

    heading("RETURN A BOOK");
    if (prompt_ids(book_id, member_id, sizeof book_id) != 1)
        return;

    st = lending_return(lib, book_id, member_id);
    if (st != LT_OK) {
        report_lending_error(lib, st, book_id, member_id);
        return;
    }
    say_ok("Return recorded, signed and saved as a new block:");
    print_block(chain_last(&lib->chain), &lib->keys);
}

static void ui_view_records(Library *lib)
{
    size_t i, valid_sigs = 0;

    heading("LENDING RECORDS (BLOCKCHAIN)");
    for (i = 0; i < lib->chain.length; i++) {
        const Block *b = &lib->chain.blocks[i];
        if (block_verify_signature(b, &lib->keys) == SIG_VALID)
            valid_sigs++;
        print_block(b, &lib->keys);
        putchar('\n');
    }
    rule('-');
    printf("Total: %zu block(s) = 1 genesis + %zu lending record(s) | valid signatures: %zu/%zu\n",
           lib->chain.length, lib->chain.length ? lib->chain.length - 1 : 0,
           valid_sigs, lib->chain.length);
}

static void describe_book_state(Library *lib, const Book *book, char *buf, size_t cap,
                                Color *color)
{
    const Block *loan = NULL;
    BookState state = lending_book_state(lib, book->book_id, &loan);
    char due[32];

    if (state == BOOK_AVAILABLE || loan == NULL) {
        snprintf(buf, cap, "Available");
        *color = CLR_GREEN;
        return;
    }
    format_time(loan->timestamp + (time_t)lib->loan_period, due, sizeof due);
    if (state == BOOK_OVERDUE) {
        snprintf(buf, cap, "OVERDUE - %s (was due %s)", loan->member_id, due);
        *color = CLR_RED;
    } else if (difftime(time(NULL), loan->timestamp) > (double)lib->loan_period) {
        snprintf(buf, cap, "On loan - %s (PAST DUE %s)", loan->member_id, due);
        *color = CLR_YELLOW;
    } else {
        snprintf(buf, cap, "On loan - %s (due %s)", loan->member_id, due);
        *color = CLR_CYAN;
    }
}

static void ui_view_registry(Library *lib)
{
    size_t i, j;

    heading("BOOK REGISTRY");
    printf("%-8s %-34s %-26s %s\n", "ID", "TITLE", "AUTHOR", "STATUS");
    rule('-');
    for (i = 0; i < lib->books.count; i++) {
        const Book *book = &lib->books.items[i];
        char status[128];
        Color color;

        describe_book_state(lib, book, status, sizeof status, &color);
        printf("%-8s %-34s %-26s %s%s%s\n", book->book_id, book->title, book->author,
               clr(color), status, clr(CLR_RESET));
    }

    heading("MEMBER REGISTRY");
    printf("%-10s %-28s %-10s %s\n", "ID", "FULL NAME", "COURSE", "BOOKS ON LOAN");
    rule('-');
    for (i = 0; i < lib->members.count; i++) {
        const Member *member = &lib->members.items[i];
        size_t on_loan = 0;

        for (j = 0; j < lib->books.count; j++) {
            const Block *loan = NULL;
            if (lending_book_state(lib, lib->books.items[j].book_id, &loan) != BOOK_AVAILABLE &&
                loan != NULL && strcmp(loan->member_id, member->member_id) == 0)
                on_loan++;
        }
        printf("%-10s %-28s %-10s %zu\n", member->member_id, member->full_name,
               member->course_code, on_loan);
    }
    printf("\n%zu books, %zu members loaded from %s/%s and %s/%s\n",
           lib->books.count, lib->members.count, lib->data_dir, BOOKS_FILE,
           lib->data_dir, MEMBERS_FILE);
}

static void ui_mark_overdue(Library *lib)
{
    char period[48];
    size_t marked = 0, i;
    Status st;

    heading("MARK OVERDUE LOANS");
    format_duration(lib->loan_period, period, sizeof period);
    printf("Loan period: %s (set %s=<seconds> to change it)\n", period, LOAN_PERIOD_ENV);

    st = lending_mark_overdue(lib, time(NULL), &marked);
    if (st != LT_OK) {
        report_lending_error(lib, st, "", "");
        return;
    }
    if (marked == 0) {
        say_info("No loans are past their due date. Nothing to record.");
        return;
    }
    say_ok("%zu loan(s) marked OVERDUE and added to the chain:", marked);
    for (i = lib->chain.length - marked; i < lib->chain.length; i++)
        print_block(&lib->chain.blocks[i], &lib->keys);
}

static void ui_validate(Library *lib)
{
    heading("VALIDATE BLOCKCHAIN");
    (void)print_validation(lib);
}

/** Swaps BORROWED/OVERDUE <-> RETURNED to simulate falsifying a record. */
static void flip_action(Block *b)
{
    const char *new_action = strcmp(b->action, ACTION_RETURNED) == 0 ? ACTION_BORROWED
                                                                      : ACTION_RETURNED;
    printf("  action: %s -> %s\n", b->action, new_action);
    (void)str_copy(b->action, sizeof b->action, new_action);
}

static void ui_tamper_demo(Library *lib)
{
    Blockchain *chain = &lib->chain;
    char input[INPUT_MAX], new_name[INPUT_MAX], prompt[64];
    Block *backup;
    size_t backup_len, index;
    char *end;
    long value;
    int choice;

    heading("TAMPER DETECTION DEMO");
    if (!require(lib, PERM_TAMPER_DEMO, "Tamper detection demo"))
        return;
    if (chain->length < 2) {
        say_warn("Record at least one lending action first, then tamper with it.");
        return;
    }
    puts("This simulates an attacker editing a PAST block. All changes happen in");
    puts("memory only: chain.dat on disk is not touched, and the original chain is");
    puts("restored at the end of the demo.\n");

    snprintf(prompt, sizeof prompt, "Block to tamper with (1-%zu): ", chain->length - 1);
    if (prompt_text(prompt, input, sizeof input) != 1)
        return;
    value = strtol(input, &end, 10);
    if (*end != '\0' || value < 1 || (size_t)value >= chain->length) {
        say_err("Invalid block number.");
        return;
    }
    index = (size_t)value;

    putchar('\n');
    print_block(&chain->blocks[index], &lib->keys);
    puts("\nHow should the attacker tamper with it?");
    puts("  1. Change the action (e.g. quietly mark a BORROWED book as RETURNED)");
    puts("  2. Change the member name (blame a different borrower)");
    puts("  3. Change the action AND recompute this block's hash (cover-up attempt)");
    puts("  4. Delete the block from the chain (erase the record)");
    if (prompt_text("Choice: ", input, sizeof input) != 1)
        return;
    choice = (input[1] == '\0') ? input[0] - '0' : 0;
    if (choice < 1 || choice > 4) {
        say_err("Invalid choice.");
        return;
    }
    if (choice == 2) {
        int r = prompt_text("New member name: ", new_name, sizeof new_name);
        if (r < 0)
            return;
        if (r == 0 || !str_is_safe_field(new_name) || strlen(new_name) >= MEMBER_NAME_LEN) {
            say_err("Invalid name.");
            return;
        }
    }

    /* Keep a full copy so the original chain can be restored exactly. */
    backup_len = chain->length;
    backup = malloc(backup_len * sizeof *backup);
    if (backup == NULL) {
        say_err("Out of memory.");
        return;
    }
    memcpy(backup, chain->blocks, backup_len * sizeof *backup);

    printf("\n%sTampering with block #%zu...%s\n", clr(CLR_YELLOW), index, clr(CLR_RESET));
    switch (choice) {
    case 1:
        flip_action(&chain->blocks[index]);
        break;
    case 2:
        printf("  member_name: %s -> %s\n", chain->blocks[index].member_name, new_name);
        (void)str_copy(chain->blocks[index].member_name, MEMBER_NAME_LEN, new_name);
        break;
    case 3:
        flip_action(&chain->blocks[index]);
        (void)block_compute_hash(&chain->blocks[index], chain->blocks[index].hash);
        puts("  hash recomputed so the block's own hash check passes");
        break;
    default:
        memmove(&chain->blocks[index], &chain->blocks[index + 1],
                (chain->length - index - 1) * sizeof *chain->blocks);
        chain->length--;
        printf("  block #%zu removed from the chain\n", index);
        break;
    }

    puts("\nRe-validating the tampered chain:");
    (void)print_validation(lib);

    puts("\nWhy it was caught:");
    switch (choice) {
    case 1:
    case 2:
        puts("  - The block's contents no longer produce its stored SHA-256 hash.");
        puts("  - The ECDSA signature no longer matches the edited data.");
        break;
    case 3:
        puts("  - Recomputing the hash hides the hash mismatch, BUT the ECDSA signature");
        puts("    fails: the attacker cannot re-sign without the librarian's private key.");
        if (index + 1 < backup_len)
            puts("  - The next block's previous_hash still points to the ORIGINAL hash.");
        break;
    default:
        puts("  - Block indexes are no longer sequential.");
        puts("  - The following block's previous_hash points to a block that is gone.");
        break;
    }

    memcpy(chain->blocks, backup, backup_len * sizeof *backup);
    chain->length = backup_len;
    free(backup);

    printf("\nOriginal chain restored from the in-memory backup: %s\n",
           library_chain_is_valid(lib) ? "VALID" : "INVALID");
    puts("(chain.dat on disk was never modified by this demo)");
}

static void ui_add_user(Library *lib)
{
    char username[INPUT_MAX], password[INPUT_MAX], input[INPUT_MAX];
    Role role;
    Status st;
    int r;

    heading("ADD USER ACCOUNT");
    if (!require(lib, PERM_MANAGE_USERS, "Add user account"))
        return;

    r = prompt_text("New username (3-19 letters/digits/_): ", username, sizeof username);
    if (r <= 0)
        return;
    if (!auth_valid_username(username)) {
        say_err("Invalid username. Use 3-19 letters, digits or underscores.");
        return;
    }
    if (prompt_text("Role [1 = LIBRARIAN, 2 = ADMIN]: ", input, sizeof input) != 1)
        return;
    if (strcmp(input, "1") == 0) {
        role = ROLE_LIBRARIAN;
    } else if (strcmp(input, "2") == 0) {
        role = ROLE_ADMIN;
    } else {
        say_err("Invalid role.");
        return;
    }
    if (prompt_new_password(password, sizeof password) != 1)
        return;

    printf("Generating signing keys and hashing password...\n");
    st = auth_create_user(lib->data_dir, username, password, role);
    crypto_wipe(password, sizeof password);

    if (st == LT_OK) {
        keyring_clear(&lib->keys);
        say_ok("User '%s' created with role %s. Private key: %s/%s/%s.key (encrypted).",
               username, auth_role_name(role), lib->data_dir, KEYS_DIR, username);
    } else if (st == LT_ERR_EXISTS) {
        say_err("A user named '%s' already exists.", username);
    } else {
        say_err("Could not create the account: %s.", status_str(st));
    }
}

/* ------------------------------------------------------------------------ */
/* Main menu                                                                */
/* ------------------------------------------------------------------------ */

static void print_menu(Library *lib)
{
    int admin = lib->session.role == ROLE_ADMIN;
    int valid = library_chain_is_valid(lib);

    putchar('\n');
    rule('=');
    printf(" MAIN MENU   user: %s [%s]   blocks: %zu   chain: %s%s%s\n",
           lib->session.username, auth_role_name(lib->session.role), lib->chain.length,
           clr(valid ? CLR_GREEN : CLR_RED), valid ? "VALID" : "TAMPERED", clr(CLR_RESET));
    rule('=');
    puts("  1. Borrow a book");
    puts("  2. Return a book");
    puts("  3. View lending records (blockchain)");
    puts("  4. View books & members (registries)");
    puts("  5. Mark overdue loans");
    puts("  6. Validate blockchain");
    printf("  7. Tamper detection demo%s\n", admin ? "" : "      [admin only]");
    printf("  8. Add user account%s\n", admin ? "" : "           [admin only]");
    puts("  0. Logout and exit");
}

void ui_main_menu(Library *lib)
{
    char input[INPUT_MAX];

    for (;;) {
        int r;

        print_menu(lib);
        r = prompt_text("Select an option: ", input, sizeof input);
        if (r < 0) {
            puts("\nEnd of input - logging out.");
            return;
        }
        if (r == 0)
            continue;
        if (input[1] != '\0') {
            say_err("Invalid option '%s'. Enter a number from 0 to 8.", input);
            continue;
        }
        switch (input[0]) {
        case '1': ui_borrow(lib); break;
        case '2': ui_return(lib); break;
        case '3': ui_view_records(lib); break;
        case '4': ui_view_registry(lib); break;
        case '5': ui_mark_overdue(lib); break;
        case '6': ui_validate(lib); break;
        case '7': ui_tamper_demo(lib); break;
        case '8': ui_add_user(lib); break;
        case '0':
            printf("Logging out %s. Signing key erased from memory. Goodbye!\n",
                   lib->session.username);
            return;
        default:
            say_err("Invalid option '%s'. Enter a number from 0 to 8.", input);
            break;
        }
    }
}
