/**
 * @file ui.c
 * @brief Interactive menus and all user-facing output.
 *
 * This layer only talks to the user; every rule about what is allowed lives
 * in lending.c, ledger/utxo/account.c, mining.c, auth.c and blockchain.c.
 */
#include "ui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blockchain.h"
#include "crypto.h"
#include "mining.h"
#include "storage.h"
#include "util.h"

#define INPUT_MAX          256
#define MAX_LOGIN_ATTEMPTS 3
#define MAX_SETUP_ATTEMPTS 5
#define BENCH_TRIALS       20

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
    char line[97];
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
    if (strcmp(action, ACTION_TRANSFER) == 0) return CLR_YELLOW;
    return CLR_DIM;
}

/** First 10 characters of a hash followed by "..". */
static const char *short_hash(const char *hash, char out[16])
{
    snprintf(out, 16, "%.10s..", hash);
    return out;
}

static const char *member_name(const Library *lib, const char *id)
{
    const Member *m = registry_find_member(&lib->members, id);
    return m ? m->full_name : (strcmp(id, LIBRARY_ACCOUNT) == 0 ? "(library)" : "?");
}

static int is_pending_block(const Library *lib, const Block *b)
{
    return lib->pending.length > 0 && b >= lib->pending.blocks &&
           b < lib->pending.blocks + lib->pending.length;
}

/* ------------------------------------------------------------------------ */
/* Input helpers                                                            */
/* ------------------------------------------------------------------------ */

/** @return 1 = non-empty input, 0 = empty/invalid (reported), -1 = EOF. */
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

/** Reads an integer in [lo, hi]. Empty input gives `fallback` if >= lo. */
static int prompt_long(const char *prompt, long lo, long hi, long fallback, long *out)
{
    char input[INPUT_MAX];
    char *end;
    long v;
    int r = prompt_text(prompt, input, sizeof input);

    if (r < 0)
        return -1;
    if (r == 0) {
        if (fallback >= lo) {
            *out = fallback;
            return 1;
        }
        return 0;
    }
    v = strtol(input, &end, 10);
    if (*end != '\0' || v < lo || v > hi) {
        say_err("Please enter a whole number from %ld to %ld.", lo, hi);
        return 0;
    }
    *out = v;
    return 1;
}

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
/* Ledger display                                                           */
/* ------------------------------------------------------------------------ */

static void print_utxo_set(const Library *lib, const char *indent)
{
    const UtxoSet *set = &lib->ledger.utxo;
    size_t i, n = utxo_unspent_count(set, NULL);
    long total = 0;

    for (i = 0; i < set->count; i++)
        if (!set->items[i].spent)
            total += set->items[i].amount;
    printf("%sUTXO SET - %zu unspent output(s), %ld coin(s) in total\n", indent, n, total);
    if (n == 0) {
        printf("%s  (empty - no coins have been issued yet)\n", indent);
        return;
    }
    printf("%s  %-16s %-8s %-20s %7s  %s\n", indent, "UTXO (txid:vout)", "Owner", "Name",
           "Amount", "Created in");
    for (i = 0; i < set->count; i++) {
        const Utxo *u = &set->items[i];
        char sh[16], ref[24];

        if (u->spent)
            continue;
        snprintf(ref, sizeof ref, "%s:%d", short_hash(u->txid, sh), u->vout);
        printf("%s  %-16s %-8s %-20s %7ld  block #%d\n", indent, ref, u->owner,
               member_name(lib, u->owner), u->amount, u->created_in);
    }
}

static void print_balances(const Library *lib)
{
    size_t i;

    printf("Model: %s%s%s\n", clr(CLR_BOLD), ledger_model_name(lib->ledger.model), clr(CLR_RESET));
    if (lib->ledger.model == MODEL_UTXO) {
        printf("%-8s %-22s %8s %6s %13s\n", "Member", "Name", "Balance", "UTXOs", "Pending out");
        rule('-');
        for (i = 0; i < lib->members.count; i++) {
            const Member *m = &lib->members.items[i];
            long pending_n = 0, pending = tokens_pending_debit(lib, m->member_id, &pending_n);
            printf("%-8s %-22s %8ld %6zu %8ld (%ld)\n", m->member_id, m->full_name,
                   utxo_balance(&lib->ledger.utxo, m->member_id),
                   utxo_unspent_count(&lib->ledger.utxo, m->member_id), pending, pending_n);
        }
        printf("\nBalance = sum of the member's unspent outputs.\n\n");
        print_utxo_set(lib, "");
    } else {
        printf("%-8s %-22s %8s %6s %8s %13s\n", "Member", "Name", "Balance", "Nonce", "History",
               "Pending out");
        rule('-');
        for (i = 0; i < lib->members.count; i++) {
            const Member *m = &lib->members.items[i];
            const Account *a = accounts_find(&lib->ledger.accounts, m->member_id);
            long pending_n = 0, pending = tokens_pending_debit(lib, m->member_id, &pending_n);
            printf("%-8s %-22s %8ld %6ld %8zu %8ld (%ld)\n", m->member_id, m->full_name,
                   a ? a->balance : 0, a ? a->nonce : 0, a ? a->history_len : 0,
                   pending, pending_n);
        }
        printf("\nBalances are stored per account and updated when a block is confirmed.\n");
    }
}

static void print_tx_line(const Transaction *tx, const char *tx_id)
{
    char sh[16];

    if (tx->type == TX_NONE) {
        printf("none\n");
        return;
    }
    if (tx->type == TX_REWARD)
        printf("REWARD %s -> %s, %ld coins - fee %ld = %ld credited | tx_id %s\n", tx->from,
               tx->to, tx->amount, tx->fee, tx_recipient_credit(tx), short_hash(tx_id, sh));
    else
        printf("TRANSFER %s -> %s, %ld coins + fee %ld, nonce %ld, %zu input(s) | tx_id %s\n",
               tx->from, tx->to, tx->amount, tx->fee, tx->nonce, tx->input_count,
               short_hash(tx_id, sh));
}

/* ------------------------------------------------------------------------ */
/* Block display                                                            */
/* ------------------------------------------------------------------------ */

static void print_block(const Block *b, KeyRing *keys)
{
    char when[32], mined[32], computed[HASH_HEX_LEN] = "";
    SigCheck sig = block_verify_signature(b, keys);
    int hash_ok = block_compute_hash(b, computed) == LT_OK && strcmp(computed, b->hash) == 0;
    int pow_ok = pow_hash_meets(b->hash, b->difficulty);

    format_time(b->timestamp, when, sizeof when);
    format_time(b->mined_at, mined, sizeof mined);
    printf("%sBlock #%d%s   %s\n", clr(CLR_BOLD), b->index, clr(CLR_RESET), when);
    if (strcmp(b->action, ACTION_TRANSFER) == 0)
        printf("  Book         : - (token transfer)\n");
    else
        printf("  Book         : %s - %s\n", b->book_id, b->book_title);
    printf("  Member       : %s - %s\n", b->member_id, b->member_name);
    printf("  Action       : %s%s%s\n", clr(action_color(b->action)), b->action, clr(CLR_RESET));
    if (b->token_reward > 0)
        printf("  Token reward : %d coins (%s) - member receives %ld after the %ld-coin fee\n",
               b->token_reward, b->token_reward == REWARD_ON_TIME ? "on time" : "late",
               tx_recipient_credit(&b->tx), b->tx.fee);
    else
        printf("  Token reward : 0\n");
    printf("  Transaction  : ");
    print_tx_line(&b->tx, b->tx_id);
    printf("  Signed by    : %s   Signature: %s%s%s\n", b->signed_by,
           clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED),
           sig == SIG_VALID ? "VALID (ECDSA P-256)" : sig == SIG_NO_KEY ? "UNVERIFIABLE" : "INVALID",
           clr(CLR_RESET));
    printf("  Mined        : %s by %s | difficulty %d | nonce %llu | PoW %s%s%s\n", mined,
           b->mined_by, b->difficulty, b->nonce, clr(pow_ok ? CLR_GREEN : CLR_RED),
           pow_ok ? "OK" : "FAIL", clr(CLR_RESET));
    printf("  Hash check   : %s%s%s\n", clr(hash_ok ? CLR_GREEN : CLR_RED),
           hash_ok ? "OK" : "MISMATCH", clr(CLR_RESET));
    printf("  Prev hash    : %s\n", b->previous_hash);
    printf("  Hash         : %s\n", b->hash);
}

static void print_pending_table(Library *lib)
{
    size_t i;

    printf("%zu unconfirmed block(s) waiting to be mined (difficulty %d):\n",
           lib->pending.length, lib->difficulty);
    if (lib->pending.length == 0) {
        printf("  (the pending pool is empty)\n");
        return;
    }
    printf("  %-4s %-19s %-9s %-6s %-7s %6s  %-12s %-9s %s\n", "#", "Created", "Action", "Book",
           "Member", "Reward", "Tx id", "Signature", "Details");
    for (i = 0; i < lib->pending.length; i++) {
        const Block *b = &lib->pending.blocks[i];
        char when[32], sh[16], details[96] = "";
        SigCheck sig = block_verify_signature(b, &lib->keys);

        format_time(b->timestamp, when, sizeof when);
        if (b->tx.type == TX_TRANSFER)
            snprintf(details, sizeof details, "%s -> %s, %ld coins + %ld fee", b->tx.from,
                     b->tx.to, b->tx.amount, b->tx.fee);
        else if (b->tx.type == TX_REWARD)
            snprintf(details, sizeof details, "%s will receive %ld after fee", b->member_id,
                     tx_recipient_credit(&b->tx));
        else if (strcmp(b->action, ACTION_OVERDUE) == 0)
            snprintf(details, sizeof details, "not returned: no transaction");
        printf("  P%-3zu %-19s %s%-9s%s %-6s %-7s %6d  %-12s %s%-9s%s %s\n", i + 1, when,
               clr(action_color(b->action)), b->action, clr(CLR_RESET), b->book_id,
               b->member_id, b->token_reward,
               b->tx.type == TX_NONE ? "-" : short_hash(b->tx_id, sh),
               clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED), sig == SIG_VALID ? "VALID" : "INVALID",
               clr(CLR_RESET), details);
    }
}

/** Prints the detailed report and a verdict. @return 1 if valid. */
static int print_validation(Library *lib)
{
    ValidationReport rep;
    char err[256];
    size_t tx_count = 0, i, bad_pending = 0;
    int valid, ledger_ok;

    printf("Checking %zu block(s): SHA-256 hash, proof-of-work, previous_hash link, "
           "transaction, ECDSA signature\n\n", lib->chain.length);
    valid = chain_validate(&lib->chain, &lib->keys, stdout, &rep);
    ledger_ok = library_verify_ledger(lib, err, sizeof err, &tx_count) == LT_OK;
    for (i = 0; i < lib->pending.length; i++)
        if (block_verify_signature(&lib->pending.blocks[i], &lib->keys) != SIG_VALID)
            bad_pending++;

    putchar('\n');
    if (ledger_ok)
        printf("Ledger replay (%s model): %sOK%s - %zu transaction(s) valid, no double spends, "
               "no overspending, nonces in order\n", ledger_model_name(lib->ledger.model),
               clr(CLR_GREEN), clr(CLR_RESET), tx_count);
    else
        printf("Ledger replay (%s model): %sFAILED%s - %s\n",
               ledger_model_name(lib->ledger.model), clr(CLR_RED), clr(CLR_RESET), err);
    printf("Pending pool: %zu record(s), %zu with an invalid signature\n",
           lib->pending.length, bad_pending);

    if (valid && ledger_ok) {
        printf("%sRESULT: CHAIN VALID%s - all %zu blocks verified; no tampering detected.\n",
               clr(CLR_GREEN), clr(CLR_RESET), rep.blocks_checked);
    } else {
        printf("%sRESULT: CHAIN INVALID - TAMPERING DETECTED%s", clr(CLR_RED), clr(CLR_RESET));
        if (rep.first_bad_index >= 0)
            printf(" (first bad block: #%ld)", rep.first_bad_index);
        printf("\n        hash: %zu | proof-of-work: %zu | links: %zu | transactions: %zu"
               " | signatures: %zu | structure: %zu\n",
               rep.hash_errors, rep.pow_errors, rep.link_errors, rep.tx_errors,
               rep.signature_errors, rep.structure_errors);
    }
    return valid && ledger_ok;
}

/* ------------------------------------------------------------------------ */
/* Start-up: banner, setup wizard, login, model                             */
/* ------------------------------------------------------------------------ */

void ui_banner(void)
{
    putchar('\n');
    rule('=');
    printf("%s   BLOCKCHAIN LIBRARY LENDING TRACKER  -  v2 (tokens + mining)%s\n",
           clr(CLR_BOLD), clr(CLR_RESET));
    printf("   SHA-256 + proof-of-work | ECDSA P-256 signatures | UTXO & account ledgers\n");
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
            sleep(1);
    }
    say_err("Too many failed login attempts. Exiting.");
    return 0;
}

int ui_choose_model(LedgerModel *model)
{
    char input[INPUT_MAX];

    heading("TRANSACTION MODEL");
    puts("Choose how member token balances are managed for this session:");
    puts("  1. UTXO model          - coins are unspent outputs; spending uses inputs + change");
    puts("  2. Account-based model - each member has a balance and a nonce");
    for (;;) {
        int r = prompt_text("Model [1/2]: ", input, sizeof input);
        if (r < 0)
            return 0;
        if (r == 1 && ledger_parse_model(input, model) == 0) {
            say_ok("Using the %s model for every token transaction in this session.",
                   ledger_model_name(*model));
            return 1;
        }
        say_err("Enter 1 (UTXO) or 2 (account-based).");
    }
}

void ui_startup_validation(Library *lib)
{
    ValidationReport rep;

    if (!lib->ledger_ok)
        say_warn("Replaying the chain into the ledger FAILED: %s. New records are blocked.",
                 lib->ledger_error);
    if (chain_validate(&lib->chain, &lib->keys, NULL, &rep) && lib->ledger_ok) {
        say_ok("Blockchain verified: %zu block(s); hashes, proof-of-work, links, transactions "
               "and signatures valid.", rep.blocks_checked);
    } else if (lib->ledger_ok) {
        say_warn("Blockchain validation FAILED (first bad block: #%ld). New lending records "
                 "are blocked until the chain is restored. Choose option 7 for details.",
                 rep.first_bad_index);
    }
    if (lib->pending.length > 0)
        say_info("%zu record(s) are waiting in the pending pool (option 4).", lib->pending.length);
}

/* ------------------------------------------------------------------------ */
/* Lending actions                                                          */
/* ------------------------------------------------------------------------ */

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
            say_err("'%s' (%s) is already on loan to %s (%s) since %s%s.", book->title,
                    book->book_id, loan->member_id, loan->member_name, when,
                    is_pending_block(lib, loan) ? " (loan still pending)" : "");
        } else {
            say_err("'%s' is already on loan.", book->title);
        }
        break;
    case LT_ERR_NOT_ON_LOAN:
        say_err("No outstanding BORROWED record for %s - it was never borrowed or was "
                "already returned.", book->book_id);
        break;
    case LT_ERR_WRONG_MEMBER:
        (void)lending_book_state(lib, book->book_id, &loan);
        say_err("%s is on loan to %s (%s), not to %s.", book->book_id,
                loan ? loan->member_id : "?", loan ? loan->member_name : "?", member_id);
        break;
    case LT_ERR_CHAIN_INVALID:
        say_err("The blockchain failed validation - refusing to add records to a tampered "
                "chain. Choose option 7 for details.");
        break;
    case LT_ERR_DENIED:
        say_err("ACCESS DENIED - your role cannot record lending actions.");
        break;
    default:
        say_err("Operation failed: %s.", status_str(st));
        break;
    }
}

static void print_pending_added(Library *lib)
{
    const Block *b = chain_last(&lib->pending);

    printf("  Added to the PENDING POOL as P%zu (not on the chain yet). Signed by %s.\n",
           lib->pending.length, b->signed_by);
    if (b->tx.type != TX_NONE)
        printf("  Transaction ID (SHA-256): %s\n", b->tx_id);
    printf("  Mine the pending pool (option 5) to confirm it%s.\n",
           b->tx.type != TX_NONE ? " and update the balances" : "");
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
    say_ok("Loan recorded: %s borrowed by %s. No token transaction for a borrow.",
           chain_last(&lib->pending)->book_id, chain_last(&lib->pending)->member_id);
    print_pending_added(lib);
}

static void ui_return(Library *lib)
{
    char book_id[INPUT_MAX], member_id[INPUT_MAX];
    int reward = 0;
    Status st;

    heading("RETURN A BOOK");
    if (prompt_ids(book_id, member_id, sizeof book_id) != 1)
        return;
    st = lending_return(lib, book_id, member_id, &reward);
    if (st != LT_OK) {
        report_lending_error(lib, st, book_id, member_id);
        return;
    }
    say_ok("Return recorded %s: token reward of %d coins created (%d after the %d-coin fee).",
           reward == REWARD_ON_TIME ? "ON TIME" : "LATE", reward, reward - TX_FEE, TX_FEE);
    print_pending_added(lib);
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
    say_ok("%zu loan(s) marked OVERDUE. An unreturned book creates NO token transaction:", marked);
    for (i = lib->pending.length - marked; i < lib->pending.length; i++)
        printf("  P%zu  %s  %s  token_reward 0, tx_id none\n", i + 1,
               lib->pending.blocks[i].book_id, lib->pending.blocks[i].member_id);
}

/* ------------------------------------------------------------------------ */
/* Viewing                                                                  */
/* ------------------------------------------------------------------------ */

static void ui_view_pending(Library *lib)
{
    heading("PENDING POOL");
    print_pending_table(lib);
}

static void ui_view_records(Library *lib)
{
    size_t i, valid_sigs = 0;

    heading("CONFIRMED LENDING RECORDS (BLOCKCHAIN)");
    for (i = 0; i < lib->chain.length; i++) {
        const Block *b = &lib->chain.blocks[i];
        if (block_verify_signature(b, &lib->keys) == SIG_VALID)
            valid_sigs++;
        print_block(b, &lib->keys);
        putchar('\n');
    }
    rule('-');
    printf("Total: %zu confirmed block(s) | valid signatures: %zu/%zu | pending: %zu\n",
           lib->chain.length, valid_sigs, lib->chain.length, lib->pending.length);
}

static void describe_book_state(Library *lib, const Book *book, char *buf, size_t cap,
                                Color *color)
{
    const Block *loan = NULL;
    BookState state = lending_book_state(lib, book->book_id, &loan);
    const char *tag;
    char due[32];

    if (state == BOOK_AVAILABLE || loan == NULL) {
        snprintf(buf, cap, "Available");
        *color = CLR_GREEN;
        return;
    }
    tag = is_pending_block(lib, loan) ? " [pending]" : "";
    format_time(loan->timestamp + (time_t)lib->loan_period, due, sizeof due);
    if (state == BOOK_OVERDUE) {
        snprintf(buf, cap, "OVERDUE - %s (was due %s)%s", loan->member_id, due, tag);
        *color = CLR_RED;
    } else {
        snprintf(buf, cap, "On loan - %s (due %s)%s", loan->member_id, due, tag);
        *color = CLR_CYAN;
    }
}

static void ui_view_registry(Library *lib)
{
    size_t i;

    heading("BOOK REGISTRY");
    printf("%-8s %-30s %-26s %s\n", "ID", "TITLE", "AUTHOR", "STATUS");
    rule('-');
    for (i = 0; i < lib->books.count; i++) {
        const Book *book = &lib->books.items[i];
        char status[128];
        Color color;

        describe_book_state(lib, book, status, sizeof status, &color);
        printf("%-8s %-30s %-26s %s%s%s\n", book->book_id, book->title, book->author,
               clr(color), status, clr(CLR_RESET));
    }
    heading("MEMBER REGISTRY");
    printf("%-10s %-28s %-10s %s\n", "ID", "FULL NAME", "COURSE", "BALANCE");
    rule('-');
    for (i = 0; i < lib->members.count; i++) {
        const Member *m = &lib->members.items[i];
        printf("%-10s %-28s %-10s %ld\n", m->member_id, m->full_name, m->course_code,
               ledger_balance(&lib->ledger, m->member_id));
    }
}

static void ui_validate(Library *lib)
{
    heading("VALIDATE BLOCKCHAIN");
    (void)print_validation(lib);
}

/* ------------------------------------------------------------------------ */
/* Mining                                                                   */
/* ------------------------------------------------------------------------ */

static void on_block_confirmed(void *ctx, Library *lib, const Block *b,
                               unsigned long long attempts, double ms, const char *found_by)
{
    (void)ctx;
    printf("  %sCONFIRMED%s block #%d  %-8s %-6s %-7s reward %2d | nonce %llu | %llu attempts"
           " | %.2f ms | by %s\n", clr(CLR_GREEN), clr(CLR_RESET), b->index, b->action,
           b->book_id, b->member_id, b->token_reward, b->nonce, attempts, ms, found_by);
    printf("            hash %s\n", b->hash);
    if (lib->ledger.model == MODEL_UTXO) {
        print_utxo_set(lib, "            ");
    } else if (b->tx.type != TX_NONE) {
        const Account *to = accounts_find(&lib->ledger.accounts, b->tx.to);
        const Account *from = accounts_find(&lib->ledger.accounts, b->tx.from);
        printf("            balances: %s = %ld", b->tx.to, to ? to->balance : 0);
        if (b->tx.type == TX_TRANSFER)
            printf(", %s = %ld (nonce now %ld)", b->tx.from, from ? from->balance : 0,
                   from ? from->nonce : 0);
        putchar('\n');
    } else {
        printf("            no transaction - balances unchanged\n");
    }
}

static void on_block_rejected(void *ctx, const Block *b, const char *reason)
{
    (void)ctx;
    printf("  %sREJECTED%s pending %s %s %s: %s\n", clr(CLR_RED), clr(CLR_RESET), b->action,
           b->book_id, b->member_id, reason);
}

static const MiningCallbacks g_callbacks = { on_block_confirmed, on_block_rejected, NULL };

static int mining_error(Status st)
{
    if (st == LT_OK)
        return 0;
    if (st == LT_ERR_POOL_EMPTY)
        say_info("The pending pool is empty - borrow, return or transfer something first.");
    else if (st == LT_ERR_CHAIN_INVALID)
        say_err("The chain failed validation - mining on a tampered chain is refused.");
    else
        say_err("Mining failed: %s.", status_str(st));
    return 1;
}

static void ui_mine_solo(Library *lib)
{
    MiningSummary s;
    Status st;

    heading("SOLO MINING");
    printf("Miner: %s | difficulty %d (hash must start with %d zero(s)) | block reward %d + fees\n\n",
           lib->session.username, lib->difficulty, lib->difficulty, BLOCK_REWARD);
    st = mine_solo(lib, lib->session.username, &g_callbacks, &s);
    if (mining_error(st))
        return;
    rule('-');
    printf("Solo mining summary\n");
    printf("  Blocks confirmed : %zu (rejected: %zu)\n", s.blocks_confirmed, s.blocks_rejected);
    printf("  Hash attempts    : %llu in total (%.1f per block, expected ~%.0f at difficulty %d)\n",
           s.attempts, s.blocks_confirmed ? (double)s.attempts / (double)s.blocks_confirmed : 0.0,
           (double)(1UL << (4 * lib->difficulty)), lib->difficulty);
    printf("  Time             : %.2f ms\n", s.elapsed_ms);
    printf("  Mining reward    : %zu x %d block reward + %ld fee(s) = %.2f coins -> %s\n",
           s.blocks_confirmed, BLOCK_REWARD, s.fees, s.gross_reward, lib->session.username);
}

static void ui_mine_pool(Library *lib)
{
    PoolResult pr;
    long miners;
    size_t i;
    Status st;
    int r;

    heading("POOL MINING");
    r = prompt_long("Number of miners in the pool (2-8) [4]: ", POOL_MIN_MINERS, POOL_MAX_MINERS,
                    POOL_DEFAULT_MINERS, &miners);
    if (r != 1)
        return;
    printf("Each miner gets a random hash rate (%d-%d attempts per round). Pool fee: %.0f%%.\n\n",
           POOL_MIN_HASH_RATE, POOL_MAX_HASH_RATE, POOL_FEE_PERCENT);
    st = mine_pool(lib, (size_t)miners, &g_callbacks, &pr);
    if (mining_error(st))
        return;

    rule('-');
    printf("Pool reward sharing (%zu block(s), %lu round(s), difficulty %d)\n",
           pr.summary.blocks_confirmed, pr.rounds, lib->difficulty);
    printf("  %-9s %10s %10s %9s %7s %14s\n", "Miner ID", "Hash rate", "Attempts", "Share %",
           "Blocks", "Reward (coins)");
    rule('-');
    for (i = 0; i < pr.miner_count; i++) {
        const PoolMiner *m = &pr.miners[i];
        printf("  %-9s %10lu %10llu %8.2f%% %7d %14.2f\n", m->id, m->hash_rate, m->attempts,
               m->share * 100.0, m->blocks_found, m->reward);
    }
    rule('-');
    printf("  %-9s %10s %10llu %8.2f%% %7zu %14.2f\n", "TOTAL", "", pr.summary.attempts, 100.0,
           pr.summary.blocks_confirmed, pr.distributed);
    printf("\n  Gross reward : %zu x %d block reward + %ld fee(s) = %.2f coins\n",
           pr.summary.blocks_confirmed, BLOCK_REWARD, pr.summary.fees, pr.summary.gross_reward);
    printf("  Pool fee %.0f%% : -%.2f coins\n", POOL_FEE_PERCENT, pr.pool_fee);
    printf("  Distributed  : %.2f coins, shared by (miner attempts / total attempts)\n",
           pr.distributed);
}

static void ui_mine_cloud(Library *lib)
{
    CloudResult cr;
    long rounds;
    int i, r;
    Status st;

    heading("CLOUD MINING");
    printf("Rented power: %d attempts per round | rental fee %.2f coins per round | "
           "maintenance %.0f%% of rewards\n", CLOUD_HASH_POWER, CLOUD_RENTAL_FEE,
           CLOUD_MAINTENANCE_PERCENT);
    r = prompt_long("Rental duration in rounds (1-5): ", CLOUD_MIN_ROUNDS, CLOUD_MAX_ROUNDS, -1,
                    &rounds);
    if (r != 1)
        return;
    if (lib->pending.length == 0)
        say_warn("The pending pool is empty - the rented power will have nothing to mine.");
    putchar('\n');
    st = mine_cloud(lib, (int)rounds, lib->session.username, &g_callbacks, &cr);
    if (mining_error(st))
        return;

    rule('-');
    printf("Cloud mining earnings (renter: %s, difficulty %d)\n", lib->session.username,
           lib->difficulty);
    printf("  %-5s %8s %6s %8s %8s %8s %9s %10s %9s %8s\n", "Round", "Attempts", "Blocks",
           "Reward", "Maint.", "Rental", "Credited", "Cum.reward", "Cum.fees", "Net");
    rule('-');
    for (i = 0; i < cr.round_count; i++) {
        const CloudRound *c = &cr.rounds[i];
        printf("  %-5d %8llu %6d %8.2f %8.2f %8.2f %9.2f %10.2f %9.2f %s%8.2f%s\n", c->round,
               c->attempts, c->blocks, c->reward, c->maintenance, c->rental, c->credited,
               c->cum_reward, c->cum_fees, clr(c->net < 0 ? CLR_RED : CLR_GREEN), c->net,
               clr(CLR_RESET));
        if (c->unprofitable)
            printf("        %sWARNING: rental is unprofitable after round %d - cumulative fees "
                   "%.2f exceed cumulative rewards %.2f%s\n", clr(CLR_YELLOW), c->round,
                   c->cum_fees, c->cum_reward, clr(CLR_RESET));
    }
    rule('-');
    printf("  Gross earnings  : %.2f coins (%zu block(s) confirmed)\n", cr.gross,
           cr.summary.blocks_confirmed);
    printf("  Total fees paid : %.2f coins (rental %.2f + maintenance %.2f)\n", cr.fees_total,
           cr.rental_total, cr.maintenance_total);
    printf("  Net profit      : %s%.2f coins%s\n", clr(cr.net < 0 ? CLR_RED : CLR_GREEN), cr.net,
           clr(CLR_RESET));
    if (cr.ever_unprofitable)
        say_warn("This rental was unprofitable: fees exceeded rewards.");
    if (cr.still_pending > 0)
        say_info("%zu block(s) are still pending - the rented power ran out first.",
                 cr.still_pending);
}

static void ui_mine_menu(Library *lib)
{
    long choice;

    heading("MINE PENDING POOL");
    print_pending_table(lib);
    puts("\n  1. Solo mining        - one miner confirms every pending block");
    puts("  2. Pool mining        - several miners share the work and the reward");
    puts("  3. Cloud mining       - rent hash power for 1-5 rounds");
    puts("  0. Back");
    if (prompt_long("Choice: ", 0, 3, -1, &choice) != 1 || choice == 0)
        return;
    if (choice == 1)
        ui_mine_solo(lib);
    else if (choice == 2)
        ui_mine_pool(lib);
    else
        ui_mine_cloud(lib);
}

static void ui_set_difficulty(Library *lib)
{
    long d;

    heading("MINING DIFFICULTY");
    printf("Current difficulty: %d (block hash must start with %d zero hex character(s)).\n",
           lib->difficulty, lib->difficulty);
    printf("Each extra zero makes mining about 16 times harder.\n");
    if (prompt_long("New difficulty (1-4): ", MIN_DIFFICULTY, MAX_DIFFICULTY, -1, &d) != 1)
        return;
    lib->difficulty = (int)d;
    say_ok("Difficulty set to %d: about %lu hash attempts per block on average.", lib->difficulty,
           1UL << (4 * lib->difficulty));
}

static void ui_benchmark(void)
{
    BenchRow rows[MAX_DIFFICULTY];
    int d;

    heading("DIFFICULTY BENCHMARK");
    printf("Mining %d sample blocks at each difficulty...\n\n", BENCH_TRIALS);
    if (mining_benchmark(BENCH_TRIALS, rows) != LT_OK) {
        say_err("Benchmark failed.");
        return;
    }
    printf("  %-10s %-8s %14s %13s %8s %8s %10s\n", "Difficulty", "Target", "Expected 16^d",
           "Avg attempts", "Min", "Max", "Avg time");
    rule('-');
    for (d = 0; d < MAX_DIFFICULTY; d++) {
        char target[8];
        memset(target, '0', (size_t)rows[d].difficulty);
        target[rows[d].difficulty] = '\0';
        printf("  %-10d %-8s %14.0f %13.1f %8llu %8llu %7.2f ms\n", rows[d].difficulty, target,
               rows[d].expected, rows[d].avg_attempts, rows[d].min_attempts, rows[d].max_attempts,
               rows[d].avg_ms);
    }
    printf("\nEvery extra leading zero multiplies the expected work (and confirmation time) by 16.\n"
           "Rewriting k blocks of history means redoing all of that work k times.\n");
}

/* ------------------------------------------------------------------------ */
/* Tokens                                                                   */
/* ------------------------------------------------------------------------ */

static void ui_balances(Library *lib)
{
    heading("TOKEN BALANCES");
    print_balances(lib);
}

/** Lists every output owned by `owner`, numbered, with its status. */
static size_t list_member_outputs(Library *lib, const char *owner, const Utxo **refs, size_t cap)
{
    const UtxoSet *set = &lib->ledger.utxo;
    size_t i, n = 0;

    printf("  %-3s %-16s %7s  %s\n", "#", "UTXO (txid:vout)", "Amount", "Status");
    for (i = 0; i < set->count && n < cap; i++) {
        const Utxo *u = &set->items[i];
        char sh[16], ref[24], status[48];

        if (strcmp(u->owner, owner) != 0)
            continue;
        snprintf(ref, sizeof ref, "%s:%d", short_hash(u->txid, sh), u->vout);
        if (u->spent)
            snprintf(status, sizeof status, "SPENT in block #%d", u->spent_in);
        else if (tokens_is_reserved(lib, u->txid, u->vout))
            snprintf(status, sizeof status, "RESERVED by a pending transfer");
        else
            snprintf(status, sizeof status, "UNSPENT (block #%d)", u->created_in);
        refs[n] = u;
        printf("  %-3zu %-16s %7ld  %s\n", n + 1, ref, u->amount, status);
        n++;
    }
    if (n == 0)
        printf("  (no outputs)\n");
    return n;
}

/** Parses "1,3" into input references. @return 1 ok, 0 invalid. */
static int parse_input_choice(char *text, const Utxo **refs, size_t n, TransferRequest *req)
{
    char *item[TX_MAX_INPUTS + 1];
    size_t count = str_split(text, ',', item, TX_MAX_INPUTS + 1), i;

    if (count > TX_MAX_INPUTS)
        return 0;
    for (i = 0; i < count; i++) {
        char *end;
        long k = strtol(str_trim(item[i]), &end, 10);

        if (*end != '\0' || k < 1 || (size_t)k > n)
            return 0;
        (void)str_copy(req->inputs[i].txid, HASH_HEX_LEN, refs[k - 1]->txid);
        req->inputs[i].vout = refs[k - 1]->vout;
    }
    req->input_count = count;
    return 1;
}

static void ui_transfer(Library *lib)
{
    char from[INPUT_MAX], to[INPUT_MAX], input[INPUT_MAX], err[256];
    const Member *sender;
    TransferRequest req;
    Transaction tx;
    long amount, change = 0;
    Status st;
    int r;

    heading("TRANSFER TOKENS");
    printf("Model: %s | every transfer pays a %d-coin fee to the miner | confirmed by mining\n",
           ledger_model_name(lib->ledger.model), TX_FEE);
    if (prompt_text("From member ID : ", from, sizeof from) != 1 ||
        prompt_text("To member ID   : ", to, sizeof to) != 1)
        return;
    sender = registry_find_member(&lib->members, from);
    if (sender == NULL || registry_find_member(&lib->members, to) == NULL) {
        say_err("Book or Member not found - both IDs must be registered members.");
        return;
    }
    r = prompt_long("Amount (coins) : ", 1, 1000000, -1, &amount);
    if (r != 1)
        return;

    memset(&req, 0, sizeof req);
    (void)str_copy(req.from, sizeof req.from, sender->member_id);
    (void)str_copy(req.to, sizeof req.to, registry_find_member(&lib->members, to)->member_id);
    req.amount = amount;

    if (lib->ledger.model == MODEL_UTXO) {
        const Utxo *refs[64];
        size_t n;

        printf("\nOutputs owned by %s (balance %ld):\n", req.from,
               utxo_balance(&lib->ledger.utxo, req.from));
        n = list_member_outputs(lib, req.from, refs, 64);
        r = prompt_text("Inputs to spend (e.g. 1,2) or Enter for automatic selection: ",
                        input, sizeof input);
        if (r < 0)
            return;
        if (r == 1 && !parse_input_choice(input, refs, n, &req)) {
            say_err("Invalid input selection.");
            return;
        }
    } else {
        const Account *a = accounts_find(&lib->ledger.accounts, req.from);
        long pending_n = 0, pending = tokens_pending_debit(lib, req.from, &pending_n);
        long expected = (a ? a->nonce : 0) + pending_n;
        char prompt[96];

        printf("\n%s: balance %ld, pending outgoing %ld, account nonce %ld\n", req.from,
               a ? a->balance : 0, pending, a ? a->nonce : 0);
        snprintf(prompt, sizeof prompt, "Nonce for this transaction (next expected: %ld): ",
                 expected);
        if (prompt_long(prompt, 0, 1000000000L, -1, &req.nonce) != 1)
            return;
    }

    st = tokens_transfer(lib, &req, &tx, &change, err, sizeof err);
    if (st != LT_OK) {
        const char *label = st == LT_ERR_INSUFFICIENT ? "insufficient funds"
                          : st == LT_ERR_DOUBLE_SPEND ? "double spend"
                          : st == LT_ERR_NONCE ? "invalid nonce" : status_str(st);
        say_err("Transaction REJECTED (%s): %s.", label, err[0] ? err : status_str(st));
        return;
    }
    say_ok("Transfer of %ld coin(s) from %s to %s accepted (fee %ld, nonce %ld).", tx.amount,
           tx.from, tx.to, tx.fee, tx.nonce);
    if (lib->ledger.model == MODEL_UTXO) {
        size_t i;
        char sh[16];
        printf("  Inputs  :");
        for (i = 0; i < tx.input_count; i++)
            printf(" %s:%d", short_hash(tx.inputs[i].txid, sh), tx.inputs[i].vout);
        printf("\n  Outputs : vout 0 -> %s %ld coin(s)", tx.to, tx.amount);
        if (change > 0)
            printf(" | vout 1 -> %s %ld coin(s) CHANGE", tx.from, change);
        printf(" | fee %ld -> miner\n", tx.fee);
    }
    print_pending_added(lib);
}

static void ui_history(Library *lib)
{
    char id[INPUT_MAX];
    const Member *m;

    heading("MEMBER TRANSACTION HISTORY");
    if (prompt_text("Member ID: ", id, sizeof id) != 1)
        return;
    m = registry_find_member(&lib->members, id);
    if (m == NULL) {
        say_err("Book or Member not found - '%s' is not in %s.", id, MEMBERS_FILE);
        return;
    }
    if (lib->ledger.model == MODEL_ACCOUNT) {
        const Account *a = accounts_find(&lib->ledger.accounts, m->member_id);
        const TxRecord *node;
        size_t k = 1;
        char sh[16];

        printf("\n%s - %s | account model | %zu record(s) in the linked list\n", m->member_id,
               m->full_name, a ? a->history_len : 0);
        printf("  %-3s %-6s %-9s %-8s %-9s %6s %4s %5s %7s  %s\n", "#", "Block", "Type", "Sender",
               "Recipient", "Amount", "Fee", "Nonce", "Effect", "Tx id");
        rule('-');
        for (node = a ? a->history_head : NULL; node != NULL; node = node->next, k++) {
            long effect = strcmp(node->sender, m->member_id) == 0 ? -(node->amount + node->fee)
                        : node->type == TX_REWARD ? node->amount - node->fee : node->amount;
            printf("  %-3zu #%-5d %-9s %-8s %-9s %6ld %4ld %5ld %+7ld  %s\n", k, node->block_index,
                   tx_type_name(node->type), node->sender, node->recipient, node->amount,
                   node->fee, node->nonce, effect, short_hash(node->txid, sh));
        }
        if (a == NULL || a->history_head == NULL)
            printf("  (no confirmed transactions yet)\n");
        printf("\nBalance: %ld | nonce: %ld\n", a ? a->balance : 0, a ? a->nonce : 0);
    } else {
        const Utxo *refs[64];
        printf("\n%s - %s | UTXO model: the member's coins are these outputs\n", m->member_id,
               m->full_name);
        (void)list_member_outputs(lib, m->member_id, refs, 64);
        printf("\nBalance: %ld (sum of UNSPENT outputs). The linked-list transaction history is\n"
               "kept by the account-based model - restart with --model account to view it.\n",
               utxo_balance(&lib->ledger.utxo, m->member_id));
    }
}

/* ------------------------------------------------------------------------ */
/* Tamper detection demo                                                    */
/* ------------------------------------------------------------------------ */

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
    char prompt[64];
    Block *backup;
    size_t backup_len, index, j;
    unsigned long long attempts = 0;
    long value, choice;

    heading("TAMPER DETECTION DEMO");
    if (!require(lib, PERM_TAMPER_DEMO, "Tamper detection demo"))
        return;
    if (chain->length < 2) {
        say_warn("Confirm at least one block by mining first, then tamper with it.");
        return;
    }
    puts("This simulates an attacker editing a CONFIRMED block. Changes happen in memory only;");
    puts("chain.dat is never touched and the original chain is restored at the end.\n");
    snprintf(prompt, sizeof prompt, "Block to tamper with (1-%zu): ", chain->length - 1);
    if (prompt_long(prompt, 1, (long)chain->length - 1, -1, &value) != 1)
        return;
    index = (size_t)value;
    putchar('\n');
    print_block(&chain->blocks[index], &lib->keys);
    puts("\nHow should the attacker tamper with it?");
    puts("  1. Change the action (e.g. quietly mark a BORROWED book as RETURNED)");
    puts("  2. Inflate the token reward to 50 coins");
    puts("  3. Change the action AND redo the proof-of-work for this block");
    puts("  4. Change the action AND re-mine this block and EVERY later block (full rewrite)");
    puts("  5. Delete the block from the chain");
    if (prompt_long("Choice: ", 1, 5, -1, &choice) != 1)
        return;

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
        printf("  token_reward: %d -> 50 (and the reward transaction amount)\n",
               chain->blocks[index].token_reward);
        chain->blocks[index].token_reward = 50;
        chain->blocks[index].tx.amount = 50;
        break;
    case 3:
        flip_action(&chain->blocks[index]);
        attempts = pow_mine(&chain->blocks[index]);
        printf("  proof-of-work redone: %llu attempts, new hash %s\n", attempts,
               chain->blocks[index].hash);
        break;
    case 4:
        flip_action(&chain->blocks[index]);
        for (j = index; j < chain->length; j++) {
            if (j > index)
                (void)str_copy(chain->blocks[j].previous_hash, HASH_HEX_LEN,
                               chain->blocks[j - 1].hash);
            attempts += pow_mine(&chain->blocks[j]);
        }
        printf("  re-mined %zu block(s) at difficulty %d: %llu hash attempts in total\n",
               chain->length - index, chain->blocks[index].difficulty, attempts);
        break;
    default:
        chain_remove_at(chain, index);
        printf("  block #%zu removed from the chain\n", index);
        break;
    }

    puts("\nRe-validating the tampered chain:");
    (void)print_validation(lib);

    puts("\nWhy it was caught:");
    switch (choice) {
    case 1:
        puts("  - The block's contents no longer produce its stored SHA-256 hash.");
        puts("  - The ECDSA signature no longer matches the edited record.");
        break;
    case 2:
        puts("  - tx_id is no longer the SHA-256 of the (edited) reward transaction.");
        puts("  - The hash and the librarian's signature no longer match the block.");
        break;
    case 3:
        puts("  - The new proof-of-work is valid, but the signature fails: the attacker");
        puts("    cannot re-sign without the librarian's private key.");
        puts("  - The next block's previous_hash still points to the ORIGINAL hash.");
        break;
    case 4:
        printf("  - Rewriting history needed %llu hash attempts. At difficulty 4 every\n", attempts);
        puts("    block costs ~65,536 attempts, and an honest chain keeps growing meanwhile.");
        puts("  - Even after all that work, the edited record's signature is still invalid.");
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
    printf(" MAIN MENU   user: %s [%s]   model: %s   difficulty: %d\n", lib->session.username,
           auth_role_name(lib->session.role), ledger_model_name(lib->ledger.model), lib->difficulty);
    printf("             chain: %zu block(s) %s%s%s   pending pool: %zu block(s)\n",
           lib->chain.length, clr(valid ? CLR_GREEN : CLR_RED), valid ? "VALID" : "TAMPERED",
           clr(CLR_RESET), lib->pending.length);
    rule('=');
    puts("  LENDING                         BLOCKCHAIN & MINING");
    puts("   1. Borrow a book                4. View pending pool");
    puts("   2. Return a book (+ reward)     5. Mine pending pool (solo / pool / cloud)");
    puts("   3. Mark overdue loans           6. View confirmed lending records");
    puts("                                   7. Validate blockchain");
    puts("  TOKENS                           8. Set mining difficulty (1-4)");
    puts("  10. View balances / UTXO set     9. Difficulty benchmark");
    puts("  11. Transfer tokens");
    puts("  12. Member transaction history   OTHER");
    printf("                                  13. View books & members\n");
    printf("                                  14. Tamper detection demo%s\n", admin ? "" : " [admin]");
    printf("                                  15. Add user account%s\n", admin ? "" : " [admin]");
    puts("   0. Logout and exit");
}

void ui_main_menu(Library *lib)
{
    for (;;) {
        long choice;
        int r;

        print_menu(lib);
        r = prompt_long("Select an option: ", 0, 15, -1, &choice);
        if (r < 0) {
            puts("\nEnd of input - logging out.");
            return;
        }
        if (r == 0)
            continue;
        switch (choice) {
        case 1:  ui_borrow(lib); break;
        case 2:  ui_return(lib); break;
        case 3:  ui_mark_overdue(lib); break;
        case 4:  ui_view_pending(lib); break;
        case 5:  ui_mine_menu(lib); break;
        case 6:  ui_view_records(lib); break;
        case 7:  ui_validate(lib); break;
        case 8:  ui_set_difficulty(lib); break;
        case 9:  ui_benchmark(); break;
        case 10: ui_balances(lib); break;
        case 11: ui_transfer(lib); break;
        case 12: ui_history(lib); break;
        case 13: ui_view_registry(lib); break;
        case 14: ui_tamper_demo(lib); break;
        case 15: ui_add_user(lib); break;
        default:
            printf("Logging out %s. Signing key erased from memory. Goodbye!\n",
                   lib->session.username);
            return;
        }
    }
}
