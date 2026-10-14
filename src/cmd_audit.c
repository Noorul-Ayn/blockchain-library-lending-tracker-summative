/**
 * @file cmd_audit.c
 * @brief Fraud review (approve / reject suspicious requests), the replay
 *        attack simulation and the audit history views.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "commands.h"
#include "ui.h"

/* ------------------------------------------------------------------------ */
/* Fraud review                                                             */
/* ------------------------------------------------------------------------ */

/** Explains, with the actual numbers, why a request was flagged. */
static void explain_flags(Library *lib, const Request *q)
{
    const Record *r = &q->rec;
    LibraryState proj;
    int have = library_project(lib, &proj) == LT_OK;

    if (q->flags & FLAG_EXCESS_LOANS) {
        printf("      EXCESSIVE_BORROWS  : %s. %s holds %zu copies (with pending loans); the "
               "maximum is %d.\n", flag_explanation(FLAG_EXCESS_LOANS), r->member_id,
               have ? state_loans(&proj, r->member_id) : 0, lib->rules.max_loans);
    }
    if (q->flags & FLAG_RAPID_REBORROW) {
        time_t last = have ? state_last_return(&proj, r->member_id, r->book_id) : 0;
        char when[32];
        format_time(last, when, sizeof when);
        printf("      RAPID_REBORROW     : %s. %s returned %s at %s.\n",
               flag_explanation(FLAG_RAPID_REBORROW), r->member_id, r->book_id, when);
    }
    if (q->flags & FLAG_DUPLICATE) {
        size_t block = 0;
        if (chain_find_record(&lib->chain, r->record_id, &block, NULL) != NULL)
            printf("      DUPLICATE_REQUEST  : %s. request_id %s is already in block #%zu.\n",
                   flag_explanation(FLAG_DUPLICATE), r->record_id, block);
        else
            printf("      DUPLICATE_REQUEST  : %s.\n", flag_explanation(FLAG_DUPLICATE));
    }
    if (q->flags & FLAG_CONDITION) {
        const CopyStatus *c = state_copy(&lib->state, r->copy_id);
        printf("      CONDITION_DOWNGRADE: %s. %s: %s -> %s, reason code '%s'.\n",
               flag_explanation(FLAG_CONDITION), r->copy_id,
               c ? condition_name(c->condition) : "?", condition_name(r->condition), r->reason);
    }
    if (have)
        state_free(&proj);
}

void cmd_fraud_review(Library *lib, int argc, char **argv)
{
    size_t i, n = 0;

    (void)argc;
    (void)argv;
    heading("FRAUD REVIEW");
    for (i = 0; i < lib->pool.count; i++) {
        const Request *q = &lib->pool.items[i];
        SigCheck sig;
        char desc[200], when[32];

        if (q->status != REQ_SUSPICIOUS)
            continue;
        sig = record_verify(&q->rec, &lib->keys);
        record_describe(&q->rec, desc, sizeof desc);
        format_time(q->rec.timestamp, when, sizeof when);
        printf("%s[%zu] %s%s %s %s | submitted %s\n", clr(CLR_RED), ++n, q->rec.record_id,
               clr(CLR_RESET), action_request_name(q->rec.action), desc, when);
        printf("      signer %s, nonce %ld, signature %s\n", q->rec.signer_id, q->rec.nonce,
               sig_check_name(sig));
        explain_flags(lib, q);
    }
    if (n == 0) {
        printf("No SUSPICIOUS requests. Every request in the pool passed the fraud heuristics:\n");
        printf("  EXCESSIVE_BORROWS (more than %d copies at once), RAPID_REBORROW (same title "
               "within 24 h of\n  returning it), DUPLICATE_REQUEST (request_id already used), "
               "CONDITION_DOWNGRADE (>1 level, no reason).\n", lib->rules.max_loans);
        return;
    }
    printf("\n%zu request(s) are withheld from mining. An administrator decides:\n", n);
    printf("  approve_suspicious <id>   - allow it to be mined (the approval note is stored "
           "with the record)\n");
    printf("  reject_suspicious <id>    - discard it from the pool\n");
    printf("A unique prefix of at least 4 characters of the request ID is enough.\n");
}

void cmd_approve_suspicious(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX], err[400];
    const char *id;
    AssemblyReport cascade;
    Request req;
    Status st;

    heading("APPROVE SUSPICIOUS REQUEST");
    if (!require_perm(lib, PERM_REVIEW_FRAUD, "approve_suspicious"))
        return;
    if ((id = arg_or_prompt(argc, argv, 1, "Request ID: ", buf, sizeof buf)) == NULL)
        return;
    memset(&req, 0, sizeof req);
    st = library_approve(lib, id, &req, &cascade, err, sizeof err);
    if (st == LT_ERR_STATE && req.rec.record_id[0] != '\0') {
        /* out is only filled once the request was found and approved */
        say_err("Approval did not make the request valid - it was discarded: %s.", err);
        if (req.flags & FLAG_DUPLICATE)
            printf("         Replay protection at work: the copied request carries a nonce and "
                   "request_id that were\n         already confirmed, so the chain rules reject "
                   "it even after manual approval.\n");
        print_rejections(&cascade, "as a consequence");
        return;
    }
    if (st != LT_OK) {
        report_failure(st, err);
        return;
    }
    say_ok("Request %s approved: status SUSPICIOUS -> PENDING. It can now be mined.",
           req.rec.record_id);
    printf("         review note stored with the record: \"%s\"\n", req.rec.review);
}

void cmd_reject_suspicious(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX], err[400], desc[200];
    const char *id;
    AssemblyReport cascade;
    Request req;
    Status st;

    heading("REJECT SUSPICIOUS REQUEST");
    if (!require_perm(lib, PERM_REVIEW_FRAUD, "reject_suspicious"))
        return;
    if ((id = arg_or_prompt(argc, argv, 1, "Request ID: ", buf, sizeof buf)) == NULL)
        return;
    st = library_reject(lib, id, &req, &cascade, err, sizeof err);
    if (st != LT_OK) {
        report_failure(st, err);
        return;
    }
    record_describe(&req.rec, desc, sizeof desc);
    say_ok("Request %s rejected and removed from the pool (%s).", req.rec.record_id, desc);
    if (!(req.flags & FLAG_DUPLICATE))
        printf("         Later requests of %s were renumbered from the confirmed nonce and "
               "re-signed.\n", req.rec.signer_id);
    print_rejections(&cascade, "because they depended on it");
}

void cmd_replay_request(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX], err[300];
    const char *id;
    Request req;
    Status st;

    heading("REPLAY ATTACK SIMULATION");
    if (!require_perm(lib, PERM_ADMIN_TOOLS, "replay_request"))
        return;
    if ((id = arg_or_prompt(argc, argv, 1, "Confirmed record ID to replay: ", buf,
                            sizeof buf)) == NULL)
        return;
    st = library_replay(lib, id, &req, err, sizeof err);
    if (st != LT_OK) {
        report_failure(st, err);
        return;
    }
    printf("An attacker copied the signed request %s from the chain and submitted it again,\n"
           "unchanged: same request_id, same nonce %ld, same (valid) signature by %s.\n\n",
           req.rec.record_id, req.rec.nonce, req.rec.signer_id);
    print_request_added(lib, &req);
    printf("         Expected nonce for %s is %ld, so the miner would reject it anyway.\n",
           req.rec.signer_id, state_nonce(&lib->state, req.rec.signer_id));
}

/* ------------------------------------------------------------------------ */
/* Audit history                                                            */
/* ------------------------------------------------------------------------ */

void print_record_header(void)
{
    printf("%-5s %-12s %-10s %-9s %-6s %-10s %-8s %-10s %4s %3s %-14s %s\n", "Block",
           "record_id", "date", "action", "book", "copy", "member", "due_date", "fine", "tok",
           "signer", "sig");
    rule('-');
}

void print_record_row(const Library *lib, const Record *r, long block_index)
{
    SigCheck sig = record_verify(r, (KeyDirectory *)&lib->keys);
    char date[16], due[16];

    format_day(r->timestamp, date);
    format_day(r->due_date, due);
    printf("#%-4ld %-12s %-10s %s%-9s%s %-6s %-10s %-8s %-10s %4ld %3d %-14.14s %s%s%s\n",
           block_index, r->record_id, date, clr(action_color(r->action)),
           action_record_name(r->action), clr(CLR_RESET), r->book_id, r->copy_id, r->member_id,
           due, r->fine_amount, r->token_reward, r->signer_id,
           clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED), sig == SIG_VALID ? "VALID" : "BAD",
           clr(CLR_RESET));
    if (r->tx.type != TX_NONE)
        printf("      %s %s -> %s %ld coin(s) + %ld fee (%s)\n", tx_type_name(r->tx.type),
               r->tx.from, r->tx.to, r->tx.amount, r->tx.fee, r->tx.method);
    if (strcmp(r->review, "-") != 0)
        printf("      review: %s\n", r->review);
}

typedef enum { FILTER_ALL, FILTER_MEMBER, FILTER_BOOK } FilterKind;

static size_t print_history(const Library *lib, FilterKind kind, const char *value)
{
    size_t i, r, n = 0;

    print_record_header();
    for (i = 0; i < lib->chain.length; i++) {
        const Block *b = &lib->chain.blocks[i];
        for (r = 0; r < b->record_count; r++) {
            const Record *rec = &b->records[r];
            int match = kind == FILTER_ALL ||
                        (kind == FILTER_MEMBER &&
                         (strcasecmp(rec->member_id, value) == 0 ||
                          strcasecmp(rec->tx.to, value) == 0)) ||
                        (kind == FILTER_BOOK && (strcasecmp(rec->book_id, value) == 0 ||
                                                 strcasecmp(rec->copy_id, value) == 0));
            if (match) {
                print_record_row(lib, rec, (long)i);
                n++;
            }
        }
    }
    if (n == 0)
        printf("(no confirmed records)\n");
    return n;
}

static void print_member_rewards(const Library *lib, const char *member)
{
    size_t i, o;
    long total = 0;

    for (i = 0; i < lib->chain.length; i++) {
        const Transaction *tx = &lib->chain.blocks[i].reward;
        for (o = 0; o < tx->output_count; o++)
            if (strcasecmp(tx->outputs[o].to, member) == 0)
                total += tx->outputs[o].amount - tx->fee;
    }
    printf("Token rewards credited to %s by confirmed returns: %ld coin(s) (after fees).\n",
           member, total);
}

void cmd_lending_history(Library *lib, int argc, char **argv)
{
    size_t n;

    (void)argc;
    (void)argv;
    heading("LENDING HISTORY (all confirmed records)");
    n = print_history(lib, FILTER_ALL, NULL);
    printf("%zu record(s) in %zu block(s). Pending requests are not history yet "
           "(see pool_view).\n", n, lib->chain.length);
}

void cmd_member_history(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX];
    const char *id = arg_or_prompt(argc, argv, 1, "Member ID: ", buf, sizeof buf);
    const Member *m;

    heading("MEMBER HISTORY");
    if (id == NULL)
        return;
    m = registry_find_member(&lib->members, id);
    if (m == NULL) {
        say_err("Member %s is not in the member registry.", id);
        return;
    }
    printf("%s (%s, %s)\n\n", m->member_id, m->full_name, m->course_code);
    (void)print_history(lib, FILTER_MEMBER, m->member_id);
    putchar('\n');
    print_member_rewards(lib, m->member_id);
}

void cmd_book_history(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX];
    const char *id = arg_or_prompt(argc, argv, 1, "Book ID or copy ID: ", buf, sizeof buf);
    const Book *b;
    const CopyRecord *c;

    heading("BOOK HISTORY");
    if (id == NULL)
        return;
    c = registry_find_copy(&lib->copies, id);
    b = registry_find_book(&lib->books, c ? c->book_id : id);
    if (b == NULL) {
        say_err("%s is not a registered book or copy.", id);
        return;
    }
    printf("%s%s%s - \"%s\" by %s\n\n", c ? c->copy_id : b->book_id, c ? " of " : "",
           c ? b->book_id : "", b->title, b->author);
    (void)print_history(lib, FILTER_BOOK, c ? c->copy_id : b->book_id);
}
