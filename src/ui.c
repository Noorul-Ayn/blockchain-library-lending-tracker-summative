/**
 * @file ui.c
 * @brief Terminal output and input helpers shared by every command.
 */
#include "ui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "crypto.h"

/* ------------------------------------------------------------------------ */
/* Messages                                                                 */
/* ------------------------------------------------------------------------ */

static void vsay(Color color, const char *label, const char *fmt, va_list ap)
    PRINTF_LIKE(3, 0);

static void vsay(Color color, const char *label, const char *fmt, va_list ap)
{
    printf("%s%s%s ", clr(color), label, clr(CLR_RESET));
    vprintf(fmt, ap);
    putchar('\n');
}

void say_ok(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_GREEN, "SUCCESS:", fmt, ap);
    va_end(ap);
}

void say_err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_RED, "ERROR:", fmt, ap);
    va_end(ap);
}

void say_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_YELLOW, "WARNING:", fmt, ap);
    va_end(ap);
}

void say_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(CLR_CYAN, "INFO:", fmt, ap);
    va_end(ap);
}

void rule(char ch)
{
    char line[101];
    memset(line, ch, sizeof line - 1);
    line[sizeof line - 1] = '\0';
    puts(line);
}

void heading(const char *title)
{
    printf("\n%s=== %s ===%s\n", clr(CLR_BOLD), title, clr(CLR_RESET));
}

void report_failure(Status st, const char *err)
{
    if (err != NULL && err[0] != '\0')
        say_err("%s.", err);
    else
        say_err("%s.", status_str(st));
}

/* ------------------------------------------------------------------------ */
/* Formatting                                                               */
/* ------------------------------------------------------------------------ */

const char *short_hash(const char *hash, char out[16])
{
    snprintf(out, 16, "%.10s..", hash);
    return out;
}

const char *member_name(const Library *lib, const char *id)
{
    const Member *m = registry_find_member(&lib->members, id);

    if (m != NULL)
        return m->full_name;
    return strcmp(id, LIBRARY_ACCOUNT) == 0 ? "(library)" : "?";
}

Color action_color(Action a)
{
    switch (a) {
    case ACT_BORROW:   return CLR_CYAN;
    case ACT_RETURN:   return CLR_GREEN;
    case ACT_OVERDUE:
    case ACT_LOST:     return CLR_RED;
    case ACT_TRANSFER:
    case ACT_FINE:     return CLR_YELLOW;
    default:           return CLR_BOLD;
    }
}

void format_day(time_t t, char out[16])
{
    if (t <= 0)
        snprintf(out, 16, "-");
    else
        format_date(t, out, 16);
}

/* ------------------------------------------------------------------------ */
/* Input                                                                    */
/* ------------------------------------------------------------------------ */

int prompt_text(const char *prompt, char *buf, size_t cap)
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

int prompt_long(const char *prompt, long lo, long hi, long fallback, long *out)
{
    char input[INPUT_MAX];
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
    if (parse_long(input, lo, hi, &v) != 0) {
        say_err("Please enter a whole number from %ld to %ld.", lo, hi);
        return 0;
    }
    *out = v;
    return 1;
}

int prompt_new_password(char *password, size_t cap)
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

const char *arg_or_prompt(int argc, char **argv, int i, const char *prompt,
                          char *buf, size_t cap)
{
    if (i < argc)
        return argv[i];
    return prompt_text(prompt, buf, cap) == 1 ? buf : NULL;
}

int require_perm(const Library *lib, Permission perm, const char *what)
{
    if (auth_has_permission(&lib->session, perm))
        return 1;
    say_err("ACCESS DENIED - '%s' is restricted to administrators (your role: %s).",
            what, auth_role_name(lib->session.role));
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Shared views                                                             */
/* ------------------------------------------------------------------------ */

void print_request_added(const Library *lib, const Request *req)
{
    char flags[96], desc[200];
    const Record *r = &req->rec;

    (void)lib;
    record_describe(r, desc, sizeof desc);
    if (req->status == REQ_SUSPICIOUS) {
        flags_describe(req->flags, flags, sizeof flags);
        say_warn("Request %s (%s) added as %sSUSPICIOUS%s [%s] - withheld from mining until "
                 "an administrator runs approve_suspicious or reject_suspicious.",
                 r->record_id, action_request_name(r->action), clr(CLR_RED), clr(CLR_RESET),
                 flags);
    } else {
        say_ok("Request %s (%s) signed and added to the pending pool.", r->record_id,
               action_request_name(r->action));
    }
    printf("         %s\n", desc);
    printf("         signer %s | nonce %ld | ECDSA P-256 signature %zu bytes, verified with "
           "public key %.16s...\n", r->signer_id, r->nonce, r->signature_len, r->signer_pubkey);
    printf("         priority %s\n", req->priority == PRIORITY_OVERDUE ? "OVERDUE-RELATED (first)"
                                                                       : "normal");
}

void print_utxo_set(const Library *lib, const char *owner, const char *indent)
{
    const UtxoSet *set = &lib->state.ledger.utxo;
    size_t i, n = 0;
    long total = 0;

    for (i = 0; i < set->count; i++) {
        if (!set->items[i].spent && (owner == NULL || strcmp(set->items[i].owner, owner) == 0)) {
            total += set->items[i].amount;
            n++;
        }
    }
    printf("%sUTXO SET%s%s - %zu unspent output(s), %ld coin(s) in total\n", indent,
           owner ? " for " : "", owner ? owner : "", n, total);
    if (n == 0) {
        printf("%s  (empty - coins are created only by confirmed returns)\n", indent);
        return;
    }
    printf("%s  %-16s %-9s %-22s %7s  %s\n", indent, "UTXO (txid:vout)", "Owner", "Name",
           "Amount", "Created in");
    for (i = 0; i < set->count; i++) {
        const Utxo *u = &set->items[i];
        char sh[16], ref[24];

        if (u->spent || (owner != NULL && strcmp(u->owner, owner) != 0))
            continue;
        snprintf(ref, sizeof ref, "%s:%d", short_hash(u->txid, sh), u->vout);
        printf("%s  %-16s %-9s %-22.22s %7ld  block #%d\n", indent, ref, u->owner,
               member_name(lib, u->owner), u->amount, u->created_in);
    }
}

/** Coins a member has committed to pending (unconfirmed) transactions. */
static long pending_debit(const Library *lib, const char *member, int *count)
{
    long total = 0;
    size_t i;

    *count = 0;
    for (i = 0; i < lib->pool.count; i++) {
        const Transaction *tx = &lib->pool.items[i].rec.tx;
        if (tx_moves_tokens(tx) && strcmp(tx->from, member) == 0) {
            total += tx_sender_debit(tx);
            (*count)++;
        }
    }
    return total;
}

void print_balances(const Library *lib, const char *only_member)
{
    const Ledger *ledger = &lib->state.ledger;
    size_t i;

    printf("Model: %s%s%s (confirmed balances; coins move only when a block is mined)\n",
           clr(CLR_BOLD), ledger_model_name(ledger->model), clr(CLR_RESET));
    if (ledger->model == MODEL_UTXO)
        printf("%-9s %-24s %8s %6s %8s %14s\n", "Member", "Name", "Balance", "UTXOs",
               "Acc.nonce", "Pending out");
    else
        printf("%-9s %-24s %8s %6s %8s %14s\n", "Member", "Name", "Balance", "Nonce",
               "History", "Pending out");
    rule('-');
    for (i = 0; i < lib->members.count; i++) {
        const Member *m = &lib->members.items[i];
        const Account *a = accounts_find(&ledger->accounts, m->member_id);
        int n = 0;
        long pending = pending_debit(lib, m->member_id, &n);
        char pend[32];

        if (only_member != NULL && strcasecmp(only_member, m->member_id) != 0)
            continue;
        snprintf(pend, sizeof pend, "%ld (%d tx)", pending, n);
        if (ledger->model == MODEL_UTXO)
            printf("%-9s %-24.24s %8ld %6zu %8ld %14s\n", m->member_id, m->full_name,
                   utxo_balance(&ledger->utxo, m->member_id),
                   utxo_unspent_count(&ledger->utxo, m->member_id), a ? a->nonce : 0, pend);
        else
            printf("%-9s %-24.24s %8ld %6ld %8zu %14s\n", m->member_id, m->full_name,
                   a ? a->balance : 0, a ? a->nonce : 0, a ? a->history_len : 0, pend);
    }
    if (only_member == NULL)
        printf("%-9s %-24s %8ld\n", LIBRARY_ACCOUNT, "(fines paid in tokens)",
               ledger_balance(ledger, LIBRARY_ACCOUNT));
}

void print_rejections(const AssemblyReport *rep, const char *context)
{
    size_t i;

    if (rep == NULL || rep->rejected_count == 0)
        return;
    say_warn("%zu pending request(s) discarded %s:", rep->rejected_count, context);
    for (i = 0; i < rep->rejected_count; i++)
        printf("         %s  %s\n", rep->rejected[i].record_id, rep->rejected[i].reason);
}
