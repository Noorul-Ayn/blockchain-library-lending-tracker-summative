/**
 * @file cmd_chain.c
 * @brief CLI commands for the pending pool, mining, the chain, validation,
 *        persistence, difficulty, Merkle trees and the tamper demo.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "commands.h"
#include "merkle.h"
#include "mining.h"
#include "ui.h"

#define BENCH_TRIALS_DEFAULT 20

static void format_stamp(time_t t, char out[24])
{
    struct tm tm_buf;

    if (t <= 0 || localtime_r(&t, &tm_buf) == NULL) {
        snprintf(out, 24, "-");
        return;
    }
    strftime(out, 24, "%m-%d %H:%M", &tm_buf);
}

static const Request *pool_lookup(const Library *lib, const char *record_id)
{
    size_t i;

    for (i = 0; i < lib->pool.count; i++)
        if (strcmp(lib->pool.items[i].rec.record_id, record_id) == 0)
            return &lib->pool.items[i];
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* Pending pool                                                             */
/* ------------------------------------------------------------------------ */

void cmd_pool_view(Library *lib, int argc, char **argv)
{
    PendingPool sorted;
    int *block_of;
    size_t i, minable;

    (void)argc;
    (void)argv;
    heading("PENDING POOL");
    printf("%zu request(s): %zu PENDING, %zu SUSPICIOUS | block capacity %d | difficulty %d\n",
           lib->pool.count, pool_count_status(&lib->pool, REQ_PENDING),
           pool_count_status(&lib->pool, REQ_SUSPICIOUS), lib->block_capacity, lib->difficulty);
    printf("Order: (1) overdue-related first, (2) reservation date ascending, (3) arrival.\n\n");
    if (lib->pool.count == 0) {
        printf("(the pending pool is empty)\n");
        return;
    }
    block_of = malloc(lib->pool.count * sizeof *block_of);
    if (block_of == NULL)
        return;
    pool_init(&sorted);
    minable = library_preview(lib, &sorted, block_of);
    printf("%-3s %-12s %-11s %-6s %-10s %-7s %-8s %-11s %5s %-10s %-6s %-5s %s\n", "#",
           "request_id", "action", "book", "copy", "member", "priority", "order date", "nonce",
           "status", "sig", "next", "flags");
    rule('-');
    for (i = 0; i < sorted.count; i++) {
        const Request *q = &sorted.items[i];
        SigCheck sig = record_verify(&q->rec, &lib->keys);
        char when[24], flags[96], next[12];

        format_stamp(q->sort_time, when);
        flags_describe(q->flags, flags, sizeof flags);
        if (block_of[i] >= 0)
            snprintf(next, sizeof next, "#%d", block_of[i]);
        else
            snprintf(next, sizeof next, "wait");
        printf("%-3zu %-12s %s%-11s%s %-6s %-10s %-7s %-8s %-11s %5ld %s%-10s%s %s%-6s%s %-5s %s\n",
               i + 1, q->rec.record_id, clr(action_color(q->rec.action)),
               action_request_name(q->rec.action), clr(CLR_RESET), q->rec.book_id,
               q->rec.copy_id, q->rec.member_id,
               q->priority == PRIORITY_OVERDUE ? "OVERDUE" : "normal", when, q->rec.nonce,
               clr(q->status == REQ_SUSPICIOUS ? CLR_RED : CLR_RESET),
               request_status_name(q->status), clr(CLR_RESET),
               clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED), sig == SIG_VALID ? "VALID" : "BAD",
               clr(CLR_RESET), next, flags);
    }
    printf("\n'next' = the block each request goes into if mining starts now (%zu of %zu "
           "minable).\n", minable, lib->pool.count);
    printf("'wait' = SUSPICIOUS (needs fraud review) or waiting for an earlier request of the "
           "same signer.\n");
    pool_free(&sorted);
    free(block_of);
}

/* ------------------------------------------------------------------------ */
/* Mining output                                                            */
/* ------------------------------------------------------------------------ */

static void on_assembled(void *ctx, const Library *lib, const Block *b, const AssemblyReport *rep)
{
    size_t i;

    (void)ctx;
    print_rejections(rep, "before mining (no longer valid)");
    printf("\n%sBlock #%d%s assembled: %zu record(s) taken from the top of the prioritised "
           "pool (capacity %d)\n", clr(CLR_BOLD), b->index, clr(CLR_RESET), b->record_count,
           lib->block_capacity);
    for (i = 0; i < b->record_count; i++) {
        const Record *r = &b->records[i];
        const Request *q = pool_lookup(lib, r->record_id);
        char desc[200];

        record_describe(r, desc, sizeof desc);
        printf("  %zu. %s %s%-11s%s %-10s %-7s %-8s sig VALID, nonce %ld - %s\n", i + 1,
               r->record_id, clr(action_color(r->action)), action_request_name(r->action),
               clr(CLR_RESET), r->copy_id, r->member_id,
               q && q->priority == PRIORITY_OVERDUE ? "OVERDUE" : "normal", r->nonce, desc);
    }
    if (rep->deferred > 0 || rep->suspicious_skipped > 0)
        printf("  Waiting: %zu request(s) for a later block, %zu SUSPICIOUS held for review.\n",
               rep->deferred, rep->suspicious_skipped);
    printf("  Merkle root %.16s... | proof-of-work at difficulty %d (hash must start with %d "
           "zero(s))...\n", b->merkle_root, b->difficulty, b->difficulty);
}

static void print_reward_outputs(const Block *b, int with_header)
{
    size_t i;

    if (b->reward.type == TX_NONE) {
        if (with_header)
            printf("  token_reward  : 0 (no returns in this block - no reward transaction)\n");
        return;
    }
    if (with_header)
        printf("  token_reward  : %ld coin(s) | transaction_id %.20s...\n", b->token_reward,
               b->transaction_id);
    else
        printf("  reward tx      : LIBRARY -> %zu output(s), fee %ld per output\n",
               b->reward.output_count, b->reward.fee);
    for (i = 0; i < b->reward.output_count; i++) {
        const TxOutput *o = &b->reward.outputs[i];
        printf("                  %s +%ld (%ld %s - %ld fee) for return %s\n", o->to,
               o->amount - b->reward.fee, o->amount, o->amount == REWARD_ON_TIME ? "on time"
                                                                                   : "late",
               b->reward.fee, o->ref);
    }
}

static void on_confirmed(void *ctx, Library *lib, const Block *b, unsigned long long attempts,
                         double ms, const char *found_by, const AssemblyReport *after)
{
    (void)ctx;
    printf("  %sCONFIRMED%s block #%d | nonce %llu | %llu hash attempts | %.2f ms | sealed by "
           "%s\n", clr(CLR_GREEN), clr(CLR_RESET), b->index, b->nonce, attempts, ms, found_by);
    printf("  hash          : %s\n", b->hash);
    print_reward_outputs(b, 1);
    printf("  %zu confirmed request(s) removed from the pending pool; chain.dat, pending.dat "
           "and state.dat saved.\n", b->record_count);
    if (lib->model == MODEL_UTXO) {
        print_utxo_set(lib, NULL, "  ");
    } else {
        printf("  Account balances after block #%d:\n", b->index);
        print_balances(lib, NULL);
    }
    print_rejections(after, "after this block (no longer valid)");
}

static void on_rejected(void *ctx, const Block *b, const char *reason)
{
    (void)ctx;
    printf("  %sREJECTED%s block #%d: %s\n", clr(CLR_RED), clr(CLR_RESET), b->index, reason);
}

static const MiningCallbacks CALLBACKS = { on_assembled, on_confirmed, on_rejected, NULL };

/** Explains why nothing (more) could be mined. */
static void explain_idle(const Library *lib, const AssemblyReport *rep)
{
    print_rejections(rep, "(no longer valid)");
    if (lib->pool.count == 0)
        say_info("The pending pool is empty - nothing to mine.");
    else if (pool_count_status(&lib->pool, REQ_SUSPICIOUS) == lib->pool.count)
        say_info("All %zu request(s) in the pool are SUSPICIOUS: run fraud_review, then "
                 "approve_suspicious or reject_suspicious.", lib->pool.count);
    else
        say_info("%zu request(s) cannot be mined yet: they wait for a SUSPICIOUS request of "
                 "the same signer (nonce order) or for another request. See pool_view.",
                 library_minable(lib));
}

static int mining_refused(const Library *lib, Status st)
{
    if (st == LT_ERR_DENIED)
        say_err("ACCESS DENIED - log in as a librarian or administrator.");
    else if (st == LT_ERR_CHAIN_INVALID)
        say_err("Mining refused: the chain has not passed validate_chain in this session.");
    else if (st == LT_ERR_INPUT)
        say_err("Invalid mining parameters.");
    else if (st != LT_OK && st != LT_ERR_POOL_EMPTY)
        say_err("Mining stopped: %s.", status_str(st));
    (void)lib;
    return st != LT_OK && st != LT_ERR_POOL_EMPTY;
}

void cmd_mine_solo(Library *lib, int argc, char **argv)
{
    char miner[MINER_ID_LEN];
    MiningSummary s;
    long max_blocks = 0;
    Status st;

    heading("SOLO MINING");
    if (argc > 1 && parse_long(argv[1], 1, 100, &max_blocks) != 0) {
        say_err("usage: mine_solo [number_of_blocks]");
        return;
    }
    snprintf(miner, sizeof miner, "SOLO-%.24s", lib->session.username);
    printf("Miner %s | difficulty %d | block reward %ld + fees | top %d requests per block\n",
           miner, lib->difficulty, lib->block_reward, lib->block_capacity);
    st = mine_solo(lib, miner, (size_t)max_blocks, &CALLBACKS, &s);
    if (mining_refused(lib, st))
        return;
    if (s.blocks_confirmed == 0) {
        explain_idle(lib, &s.last_assembly);
        return;
    }
    rule('-');
    printf("Solo mining summary\n");
    printf("  Blocks confirmed : %zu (%zu records)\n", s.blocks_confirmed, s.records_confirmed);
    printf("  Hash attempts    : %llu in total (%.1f per block; expected ~%.0f at difficulty %d)\n",
           s.attempts, (double)s.attempts / (double)s.blocks_confirmed,
           pow(16.0, lib->difficulty), lib->difficulty);
    printf("  Time             : %.2f ms\n", s.elapsed_ms);
    printf("  Mining reward    : %zu x %ld block reward + %ld fee(s) = %.2f coins -> %s "
           "(the full reward)\n", s.blocks_confirmed, lib->block_reward, s.fees, s.gross_reward,
           miner);
    if (library_minable(lib) > 0 || lib->pool.count > 0)
        say_info("%zu request(s) still in the pool (%zu SUSPICIOUS).", lib->pool.count,
                 pool_count_status(&lib->pool, REQ_SUSPICIOUS));
}

void cmd_mine_pool(Library *lib, int argc, char **argv)
{
    PoolResult pr;
    long miners = POOL_DEFAULT_MINERS, max_blocks = 0;
    size_t i;
    Status st;

    heading("POOL MINING");
    if (argc > 1) {
        if (parse_long(argv[1], POOL_MIN_MINERS, POOL_MAX_MINERS, &miners) != 0) {
            say_err("The pool needs %d-%d miners.", POOL_MIN_MINERS, POOL_MAX_MINERS);
            return;
        }
    } else if (prompt_long("Number of miners in the pool (2-8) [4]: ", POOL_MIN_MINERS,
                           POOL_MAX_MINERS, POOL_DEFAULT_MINERS, &miners) != 1) {
        return;
    }
    if (argc > 2 && parse_long(argv[2], 1, 100, &max_blocks) != 0) {
        say_err("usage: mine_pool [miners] [number_of_blocks]");
        return;
    }
    printf("Each miner gets a random hash rate (%d-%d attempts per round). Pool fee %.0f%%.\n",
           POOL_MIN_HASH_RATE, POOL_MAX_HASH_RATE, POOL_FEE_PERCENT);
    st = mine_pool(lib, (size_t)miners, (size_t)max_blocks, &CALLBACKS, &pr);
    if (mining_refused(lib, st))
        return;
    if (pr.summary.blocks_confirmed == 0) {
        explain_idle(lib, &pr.summary.last_assembly);
        return;
    }
    rule('-');
    printf("Pool reward sharing (%zu block(s), %lu round(s), difficulty %d)\n",
           pr.summary.blocks_confirmed, pr.rounds, lib->difficulty);
    printf("  %-9s %10s %10s %9s %7s %16s\n", "Miner ID", "Hash rate", "Attempts", "Share %",
           "Blocks", "Reward (coins)");
    rule('-');
    for (i = 0; i < pr.miner_count; i++) {
        const PoolMiner *m = &pr.miners[i];
        printf("  %-9s %10lu %10llu %8.2f%% %7d %16.2f\n", m->id, m->hash_rate, m->attempts,
               m->share * 100.0, m->blocks_found, m->reward);
    }
    rule('-');
    printf("  %-9s %10s %10llu %8.2f%% %7zu %16.2f\n", "TOTAL", "", pr.summary.attempts, 100.0,
           pr.summary.blocks_confirmed, pr.distributed);
    printf("\n  Gross reward : %zu x %ld block reward + %ld fee(s) = %.2f coins\n",
           pr.summary.blocks_confirmed, lib->block_reward, pr.summary.fees,
           pr.summary.gross_reward);
    printf("  Pool fee %.0f%% : -%.2f coins (deducted before distribution)\n", POOL_FEE_PERCENT,
           pr.pool_fee);
    printf("  Distributed  : %.2f coins; share = miner_attempts / total_attempts\n",
           pr.distributed);
}

void cmd_mine_cloud(Library *lib, int argc, char **argv)
{
    CloudResult cr;
    long rounds;
    int i;
    Status st;

    heading("CLOUD MINING");
    printf("Rented power: %d attempts per round | rental fee %.2f coins per round | "
           "maintenance %.0f%% of rewards\n", CLOUD_HASH_POWER, CLOUD_RENTAL_FEE,
           CLOUD_MAINTENANCE_PERCENT);
    if (argc > 1) {
        if (parse_long(argv[1], CLOUD_MIN_ROUNDS, CLOUD_MAX_ROUNDS, &rounds) != 0) {
            say_err("The rental duration must be %d-%d rounds.", CLOUD_MIN_ROUNDS,
                    CLOUD_MAX_ROUNDS);
            return;
        }
    } else if (prompt_long("Rental duration in rounds (1-5): ", CLOUD_MIN_ROUNDS,
                           CLOUD_MAX_ROUNDS, -1, &rounds) != 1) {
        return;
    }
    if (library_minable(lib) == 0)
        say_warn("Nothing in the pool can be mined - the rented power will be idle.");
    st = mine_cloud(lib, (int)rounds, lib->session.username, &CALLBACKS, &cr);
    if (mining_refused(lib, st))
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
            printf("        %sWARNING: after round %d cumulative fees %.2f exceed cumulative "
                   "rewards %.2f%s\n", clr(CLR_YELLOW), c->round, c->cum_fees, c->cum_reward,
                   clr(CLR_RESET));
    }
    rule('-');
    printf("  Gross earnings  : %.2f coins (%zu block(s) confirmed)\n", cr.gross,
           cr.summary.blocks_confirmed);
    printf("  Total fees paid : %.2f coins (rental %.2f + maintenance %.2f)\n", cr.fees_total,
           cr.rental_total, cr.maintenance_total);
    printf("  Net profit      : %s%.2f coins%s\n", clr(cr.net < 0 ? CLR_RED : CLR_GREEN), cr.net,
           clr(CLR_RESET));
    if (cr.ever_unprofitable)
        say_warn("This rental was unprofitable at some point: fees exceeded rewards.");
    if (cr.still_pending > 0)
        say_info("%zu request(s) are still pending - the rented power ran out first.",
                 cr.still_pending);
}

/* ------------------------------------------------------------------------ */
/* Chain view                                                               */
/* ------------------------------------------------------------------------ */

static void print_block_detail(Library *lib, const Block *b)
{
    BlockCheck c;
    char when[32];
    size_t i;

    chain_check_block(&lib->chain, (size_t)b->index, &lib->keys, &c);
    format_time(b->timestamp, when, sizeof when);
    printf("%sBlock #%d%s\n", clr(CLR_BOLD), b->index, clr(CLR_RESET));
    printf("  index          : %d%s\n", b->index, b->index == 0 ? " (genesis)" : "");
    printf("  timestamp      : %lld (%s)\n", (long long)b->timestamp, when);
    printf("  record_count   : %zu\n", b->record_count);
    printf("  previous_hash  : %s  [link %s]\n", b->previous_hash, c.link_ok ? "OK" : "BROKEN");
    printf("  merkle_root    : %s  [recomputed %s]\n", b->merkle_root,
           c.merkle_ok ? "OK" : "MISMATCH");
    printf("  hash           : %s  [recomputed %s]\n", b->hash, c.hash_ok ? "OK" : "MISMATCH");
    printf("  sealed_by      : %s\n", b->sealed_by);
    printf("  token_reward   : %ld\n", b->token_reward);
    printf("  transaction_id : %s\n", b->transaction_id);
    printf("  difficulty     : %d | nonce %llu | proof-of-work %s\n", b->difficulty, b->nonce,
           c.pow_ok ? "OK" : "FAIL");
    print_reward_outputs(b, 0);
    for (i = 0; i < b->record_count; i++) {
        const Record *r = &b->records[i];
        SigCheck sig = record_verify(r, &lib->keys);
        char due[16], leaf[HASH_HEX_LEN];

        format_day(r->due_date, due);
        (void)record_hash(r, leaf);
        printf("  [%zu] record_id %s | %s%s%s | %s / %s \"%s\"\n", i + 1, r->record_id,
               clr(action_color(r->action)), action_record_name(r->action), clr(CLR_RESET),
               r->book_id, r->copy_id, r->book_title);
        printf("      member %s %s | due_date %s | fine_amount %ld | token_reward %d | "
               "condition %s | reason %s\n", r->member_id, r->member_name, due, r->fine_amount,
               r->token_reward, condition_name(r->condition), r->reason);
        if (r->tx.type != TX_NONE)
            printf("      transaction %s %s -> %s, %ld + fee %ld, account nonce %ld, %zu input(s), "
                   "method %s\n", tx_type_name(r->tx.type), r->tx.from, r->tx.to, r->tx.amount,
                   r->tx.fee, r->tx.nonce, r->tx.input_count, r->tx.method);
        printf("      nonce %ld | signer %s | public key %.20s... | signature %s%s%s (%zu bytes)"
               "\n", r->nonce, r->signer_id, r->signer_pubkey,
               clr(sig == SIG_VALID ? CLR_GREEN : CLR_RED), sig_check_name(sig), clr(CLR_RESET),
               r->signature_len);
        printf("      leaf hash %.20s... | review %s\n", leaf, r->review);
    }
}

void cmd_chain_view(Library *lib, int argc, char **argv)
{
    size_t i;

    if (argc > 1) {
        long index;
        heading("BLOCK");
        if (parse_long(argv[1], 0, (long)lib->chain.length - 1, &index) != 0) {
            say_err("Block index must be 0-%zu.", lib->chain.length - 1);
            return;
        }
        print_block_detail(lib, &lib->chain.blocks[index]);
        return;
    }
    heading("BLOCKCHAIN");
    printf("%zu block(s) | difficulty %d | %s model\n\n", lib->chain.length, lib->difficulty,
           ledger_model_name(lib->model));
    printf("%-4s %-17s %4s %-16s %6s %3s %13s  %-14s %-14s %-14s\n", "#", "timestamp", "recs",
           "sealed_by", "reward", "d", "nonce", "hash", "merkle_root", "previous_hash");
    rule('-');
    for (i = 0; i < lib->chain.length; i++) {
        const Block *b = &lib->chain.blocks[i];
        char when[32], h1[16], h2[16], h3[16];
        format_time(b->timestamp, when, sizeof when);
        printf("%-4d %-17.16s %4zu %-16.16s %6ld %3d %13llu  %-14s %-14s %-14s\n", b->index, when,
               b->record_count, b->sealed_by, b->token_reward, b->difficulty, b->nonce,
               short_hash(b->hash, h1), short_hash(b->merkle_root, h2),
               short_hash(b->previous_hash, h3));
    }
    printf("\nUse chain_view <index> for every field and record of a block.\n");
}

/* ------------------------------------------------------------------------ */
/* Validation and persistence                                               */
/* ------------------------------------------------------------------------ */

int print_validation(Library *lib)
{
    ValidationSummary v;
    int ok;

    printf("Checking %zu block(s): previous-hash links, recomputed SHA-256 block hash, "
           "proof-of-work,\nMerkle root, reward transaction, timestamps and the ECDSA signature "
           "of every record.\n\n", lib->chain.length);
    ok = library_validate(lib, stdout, &v);
    putchar('\n');
    if (ok) {
        printf("%sRESULT: CHAIN VALID%s - %zu block(s) and %zu record(s) verified; no tampering "
               "detected.\n", clr(CLR_GREEN), clr(CLR_RESET), v.chain.blocks_checked,
               v.chain.records_checked);
        if (v.state_file_present && v.state_differences > 0)
            say_warn("state.dat differed from the chain in %zu line(s); it was rebuilt from the "
                     "chain (the chain wins).", v.state_differences);
    } else {
        printf("%sRESULT: CHAIN INVALID - TAMPERING DETECTED%s", clr(CLR_RED), clr(CLR_RESET));
        if (v.chain.first_bad_index >= 0)
            printf(" (first bad block: #%ld)", v.chain.first_bad_index);
        printf("\n        hash %zu | PoW %zu | links %zu | merkle %zu | reward %zu | time %zu | "
               "signatures %zu | records %zu | structure %zu\n", v.chain.hash_errors,
               v.chain.pow_errors, v.chain.link_errors, v.chain.merkle_errors,
               v.chain.reward_errors, v.chain.time_errors, v.chain.signature_errors,
               v.chain.record_errors, v.chain.structure_errors);
        if (!v.replay_ok)
            printf("        lending rules: %s\n", v.replay_error);
        if (!v.meta_ok)
            printf("        chain metadata: %s\n", v.meta_detail);
    }
    if (v.pending_bad_signatures > 0)
        say_warn("%zu pending request(s) have an invalid signature; they will be rejected "
                 "before mining.", v.pending_bad_signatures);
    return ok;
}

void cmd_validate_chain(Library *lib, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    heading("VALIDATE CHAIN");
    if (print_validation(lib)) {
        say_ok("Chain verified - all operations are enabled for this session.");
        run_overdue_scan(lib, 0);
    } else {
        say_err("The session is READ-ONLY: lending, mining and transfers are blocked until the "
                "chain is restored (restore %s from a backup, then chain_load).", CHAIN_FILE);
    }
}

static void print_file_size(const char *path)
{
    struct stat sb;

    if (stat(path, &sb) == 0)
        printf("  %-28s %8lld bytes\n", path, (long long)sb.st_size);
    else
        printf("  %-28s (missing)\n", path);
}

void cmd_chain_save(Library *lib, int argc, char **argv)
{
    Status st;

    (void)argc;
    (void)argv;
    heading("SAVE");
    if (!lib->chain_ok) {
        say_err("Refusing to save: the chain in memory failed validation.");
        return;
    }
    st = library_save_all(lib);
    if (st != LT_OK) {
        say_err("Save failed: %s.", status_str(st));
        return;
    }
    say_ok("Saved atomically (write to .tmp, fsync, rename):");
    print_file_size(lib->chain_path);
    print_file_size(lib->pool_path);
    print_file_size(lib->state_path);
    printf("  chain = %zu block(s); pool = %zu request(s); state = inventory, queues, nonces, "
           "fines, %s ledger, settings\n", lib->chain.length, lib->pool.count,
           ledger_model_name(lib->model));
}

void cmd_chain_load(Library *lib, int argc, char **argv)
{
    char err[300];
    int needs_genesis = 0;
    Status st;

    (void)argc;
    (void)argv;
    heading("LOAD");
    st = library_load_files(lib, &needs_genesis, err, sizeof err);
    if (st != LT_OK) {
        say_err("Could not load %s / %s: %s.", CHAIN_FILE, PENDING_FILE,
                err[0] ? err : status_str(st));
        return;
    }
    if (needs_genesis) {
        st = library_create_genesis(lib);
        if (st != LT_OK) {
            say_err("Could not create a genesis block: %s.", status_str(st));
            return;
        }
        say_info("%s was missing - a new chain with a genesis block was created.", CHAIN_FILE);
    }
    say_ok("Loaded %zu block(s) and %zu pending request(s) from disk.", lib->chain.length,
           lib->pool.count);
    say_info("Run validate_chain now - no other operation is allowed until the loaded chain "
             "has been re-validated.");
}

/* ------------------------------------------------------------------------ */
/* Difficulty                                                               */
/* ------------------------------------------------------------------------ */

void cmd_difficulty_status(Library *lib, int argc, char **argv)
{
    size_t i, from;
    char target[8];

    (void)argc;
    (void)argv;
    heading("DIFFICULTY STATUS");
    memset(target, '0', (size_t)lib->difficulty);
    target[lib->difficulty] = '\0';
    printf("Current difficulty : %d (block hash must start with \"%s\")\n", lib->difficulty,
           target);
    printf("Expected attempts  : ~%.0f per block (16^%d)\n", pow(16.0, lib->difficulty),
           lib->difficulty);
    printf("Allowed range      : %d-%d (set_difficulty <n> or the -D option at start-up)\n",
           MIN_DIFFICULTY, MAX_DIFFICULTY);
    printf("Block reward       : %ld coins + fees | block capacity %d records\n",
           lib->block_reward, lib->block_capacity);
    printf("Recent blocks      :");
    from = lib->chain.length > 5 ? lib->chain.length - 5 : 0;
    for (i = from; i < lib->chain.length; i++)
        printf(" #%d d=%d nonce=%llu%s", lib->chain.blocks[i].index,
               lib->chain.blocks[i].difficulty, lib->chain.blocks[i].nonce,
               i + 1 < lib->chain.length ? "," : "");
    putchar('\n');
}

void cmd_set_difficulty(Library *lib, int argc, char **argv)
{
    long d;

    heading("SET DIFFICULTY");
    if (argc > 1) {
        if (parse_long(argv[1], MIN_DIFFICULTY, MAX_DIFFICULTY, &d) != 0) {
            say_err("Difficulty must be %d-%d.", MIN_DIFFICULTY, MAX_DIFFICULTY);
            return;
        }
    } else if (prompt_long("New difficulty (1-4): ", MIN_DIFFICULTY, MAX_DIFFICULTY, -1, &d) != 1) {
        return;
    }
    lib->difficulty = (int)d;
    (void)library_save_state(lib);
    say_ok("Difficulty set to %ld: about %.0f hash attempts per block on average (saved).", d,
           pow(16.0, (double)d));
}

void cmd_difficulty_benchmark(Library *lib, int argc, char **argv)
{
    BenchRow rows[MAX_DIFFICULTY];
    long trials = BENCH_TRIALS_DEFAULT;
    int d;

    (void)lib;
    heading("DIFFICULTY BENCHMARK");
    if (argc > 1 && parse_long(argv[1], 1, 200, &trials) != 0) {
        say_err("usage: difficulty_benchmark [trials 1-200]");
        return;
    }
    printf("Mining %ld throw-away blocks at each difficulty...\n\n", trials);
    if (mining_benchmark((int)trials, rows) != LT_OK) {
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
               rows[d].expected, rows[d].avg_attempts, rows[d].min_attempts,
               rows[d].max_attempts, rows[d].avg_ms);
    }
    printf("\nEach extra leading zero multiplies the expected work by 16.\n");
}

/* ------------------------------------------------------------------------ */
/* Merkle tree                                                              */
/* ------------------------------------------------------------------------ */

static int block_arg(Library *lib, int argc, char **argv, const Block **out)
{
    char buf[INPUT_MAX];
    const char *text = arg_or_prompt(argc, argv, 1, "Block index: ", buf, sizeof buf);
    long index;

    if (text == NULL)
        return 0;
    if (parse_long(text, 0, (long)lib->chain.length - 1, &index) != 0) {
        say_err("Block index must be 0-%zu.", lib->chain.length - 1);
        return 0;
    }
    *out = &lib->chain.blocks[index];
    return 1;
}

static char (*block_leaves(const Block *b))[HASH_HEX_LEN]
{
    char (*leaves)[HASH_HEX_LEN] = malloc((b->record_count ? b->record_count : 1) * sizeof *leaves);
    size_t i;

    if (leaves == NULL)
        return NULL;
    for (i = 0; i < b->record_count; i++)
        if (record_hash(&b->records[i], leaves[i]) != LT_OK) {
            free(leaves);
            return NULL;
        }
    return leaves;
}

typedef struct {
    size_t level;
    int    started;
} TreePrint;

static void visit_node(size_t level, size_t index, const char *hash, void *ctx)
{
    TreePrint *tp = ctx;
    char sh[16];

    if (!tp->started || level != tp->level) {
        printf("%s  level %zu%s:", tp->started ? "\n" : "", level, level == 0 ? " (leaves)" : "");
        tp->level = level;
        tp->started = 1;
    }
    printf(" [%zu] %s", index, short_hash(hash, sh));
}

void cmd_merkle_tree(Library *lib, int argc, char **argv)
{
    const Block *b;
    char (*leaves)[HASH_HEX_LEN];
    char root[HASH_HEX_LEN];
    TreePrint tp = {0, 0};
    size_t levels = 0, i;

    heading("MERKLE TREE");
    if (!block_arg(lib, argc, argv, &b))
        return;
    if (b->record_count == 0) {
        printf("Block #%d has no records: its merkle_root is 64 zeros.\n", b->index);
        return;
    }
    leaves = block_leaves(b);
    if (leaves == NULL)
        return;
    printf("Block #%d: %zu record(s). leaf = SHA-256(record payload | signature | review); "
           "parent = SHA-256(0x01 || left || right);\nan odd node is promoted unchanged.\n\n",
           b->index, b->record_count);
    for (i = 0; i < b->record_count; i++) {
        char sh[16];
        printf("  leaf [%zu] %s = record %s (%s %s)\n", i, short_hash(leaves[i], sh),
               b->records[i].record_id, action_record_name(b->records[i].action),
               b->records[i].copy_id);
    }
    (void)merkle_walk((const char (*)[HASH_HEX_LEN])leaves, b->record_count, visit_node, &tp,
                      &levels);
    (void)merkle_root((const char (*)[HASH_HEX_LEN])leaves, b->record_count, root);
    printf("  <- root\n\nComputed root : %s\nStored root   : %s  [%s]\n", root, b->merkle_root,
           strcmp(root, b->merkle_root) == 0 ? "MATCH" : "MISMATCH");
    free(leaves);
}

void cmd_merkle_proof(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX];
    const Block *b;
    const char *id;
    char (*leaves)[HASH_HEX_LEN];
    MerkleStep steps[MERKLE_MAX_DEPTH];
    size_t n = 0, i, index = 0;
    int found = 0;

    heading("MERKLE INCLUSION PROOF");
    if (!block_arg(lib, argc, argv, &b))
        return;
    if ((id = arg_or_prompt(argc, argv, 2, "Record ID: ", buf, sizeof buf)) == NULL)
        return;
    for (i = 0; i < b->record_count; i++) {
        if (strncasecmp(b->records[i].record_id, id, strlen(id)) == 0) {
            index = i;
            found = 1;
            break;
        }
    }
    if (!found) {
        say_err("Block #%d has no record %s.", b->index, id);
        return;
    }
    leaves = block_leaves(b);
    if (leaves == NULL ||
        merkle_proof((const char (*)[HASH_HEX_LEN])leaves, b->record_count, index, steps, &n) !=
            LT_OK) {
        free(leaves);
        say_err("Could not build the proof.");
        return;
    }
    printf("Record %s is leaf %zu of block #%d\n  leaf : %s\n", b->records[index].record_id,
           index, b->index, leaves[index]);
    for (i = 0; i < n; i++)
        printf("  step %zu: sibling %s on the %s\n", i + 1, steps[i].hash,
               steps[i].sibling_is_left ? "left" : "right");
    printf("  root : %s\n", b->merkle_root);
    if (merkle_verify_proof(leaves[index], steps, n, b->merkle_root))
        say_ok("Proof verified: hashing the leaf with %zu sibling(s) gives the stored "
               "merkle_root.", n);
    else
        say_err("Proof FAILED: the record does not hash to the stored merkle_root.");
    free(leaves);
}

/* ------------------------------------------------------------------------ */
/* Tamper detection demo                                                    */
/* ------------------------------------------------------------------------ */

static void tamper_record(Record *r, long choice, const Library *lib)
{
    char before[16], after[16];

    if (choice == 1) {
        format_day(r->due_date, before);
        r->due_date += 30 * DAY_SECONDS;
        format_day(r->due_date, after);
        printf("  record %s due_date: %s -> %s (silently extended by 30 days)\n", r->record_id,
               before, after);
    } else if (choice == 2) {
        Action next = r->action == ACT_RETURN ? ACT_BORROW : ACT_RETURN;
        printf("  record %s action: %s -> %s\n", r->record_id, action_record_name(r->action),
               action_record_name(next));
        r->action = next;
    } else {
        size_t i;
        for (i = 0; i < lib->members.count; i++) {
            if (strcmp(lib->members.items[i].member_id, r->member_id) != 0) {
                printf("  record %s member: %s -> %s (loan attributed to someone else)\n",
                       r->record_id, r->member_id, lib->members.items[i].member_id);
                (void)str_copy(r->member_id, sizeof r->member_id,
                               lib->members.items[i].member_id);
                (void)str_copy(r->member_name, sizeof r->member_name,
                               lib->members.items[i].full_name);
                break;
            }
        }
    }
}

void cmd_tamper_demo(Library *lib, int argc, char **argv)
{
    Blockchain backup;
    ValidationSummary v;
    unsigned long long attempts = 0;
    long index, choice, edit = 1;
    char prompt[64];
    size_t j;

    (void)argc;
    (void)argv;
    heading("TAMPER DETECTION DEMO");
    if (!require_perm(lib, PERM_ADMIN_TOOLS, "tamper_demo"))
        return;
    if (lib->chain.length < 2) {
        say_warn("Mine at least one block with records first.");
        return;
    }
    puts("This simulates an attacker editing CONFIRMED history in memory. chain.dat is not");
    puts("touched and the original chain is restored at the end.\n");
    puts("  1. Silently extend a due date (avoid a fine)");
    puts("  2. Quietly change the action (e.g. mark a BORROWED book as RETURNED)");
    puts("  3. Change the member on a record (borrower dispute)");
    puts("  4. Edit a due date, then recompute the Merkle root and re-mine that block");
    puts("  5. Edit a due date, then re-mine that block and EVERY later block");
    puts("  6. Delete the newest block");
    if (prompt_long("Choice: ", 1, 6, -1, &choice) != 1)
        return;
    if (choice != 6) {
        snprintf(prompt, sizeof prompt, "Block to tamper with (1-%zu): ", lib->chain.length - 1);
        if (prompt_long(prompt, 1, (long)lib->chain.length - 1, -1, &index) != 1)
            return;
        if (lib->chain.blocks[index].record_count == 0) {
            say_err("Block #%ld has no records to edit.", index);
            return;
        }
        if (lib->chain.blocks[index].record_count > 1) {
            snprintf(prompt, sizeof prompt, "Record number (1-%zu) [1]: ",
                     lib->chain.blocks[index].record_count);
            if (prompt_long(prompt, 1, (long)lib->chain.blocks[index].record_count, 1, &edit) != 1)
                return;
        }
    } else {
        index = (long)lib->chain.length - 1;
    }
    if (chain_copy(&backup, &lib->chain) != LT_OK) {
        say_err("Out of memory.");
        return;
    }

    printf("\n%sTampering with block #%ld...%s\n", clr(CLR_YELLOW), index, clr(CLR_RESET));
    if (choice == 1 || choice == 4 || choice == 5) {
        /* A due-date edit needs a record that has a due date. */
        const Block *b = &lib->chain.blocks[index];
        size_t k;
        if (b->records[edit - 1].due_date == 0) {
            for (k = 0; k < b->record_count && b->records[k].due_date == 0; k++)
                ;
            if (k == b->record_count) {
                say_err("No record in block #%ld has a due date - choose another block.", index);
                chain_free(&backup);
                return;
            }
            printf("  (record %ld has no due date; editing record %zu instead)\n", edit, k + 1);
            edit = (long)k + 1;
        }
    }
    if (choice <= 3) {
        tamper_record(&lib->chain.blocks[index].records[edit - 1], choice, lib);
    } else if (choice == 4 || choice == 5) {
        Block *b = &lib->chain.blocks[index];
        tamper_record(&b->records[edit - 1], 1, lib);
        (void)block_finalise_body(b);          /* new Merkle root */
        for (j = (size_t)index; j < (choice == 4 ? (size_t)index + 1 : lib->chain.length); j++) {
            if (j > (size_t)index)
                (void)str_copy(lib->chain.blocks[j].previous_hash, HASH_HEX_LEN,
                               lib->chain.blocks[j - 1].hash);
            attempts += pow_mine(&lib->chain.blocks[j]);
        }
        printf("  Merkle root recomputed and %s re-mined: %llu hash attempts\n",
               choice == 4 ? "the block" : "every block from here to the tip", attempts);
    } else {
        chain_pop(&lib->chain);
        printf("  block #%ld removed from the end of the chain\n", index);
    }

    puts("\nRe-validating the tampered chain:");
    (void)print_validation(lib);

    puts("\nWhy it was caught:");
    switch (choice) {
    case 1:
    case 2:
    case 3:
        puts("  - The edited record no longer hashes to its Merkle leaf, so the merkle_root");
        puts("    recomputed from the records differs from the one stored in the header.");
        puts("  - The signer's ECDSA signature no longer matches the edited record, and the");
        puts("    attacker does not have the signer's private key to sign it again.");
        puts("  - Replaying the records through the lending rules fails as well.");
        puts("  - The block hash still matches only because it covers the STORED merkle_root;");
        puts("    updating merkle_root changes the hash, the proof-of-work and the next");
        puts("    block's link (try option 4).");
        break;
    case 4:
        puts("  - The new proof-of-work is valid, but the next block's previous_hash still");
        puts("    points to the ORIGINAL hash, and the edited record's signature fails: the");
        puts("    attacker cannot re-sign without the member's private key.");
        break;
    case 5:
        printf("  - Rewriting history took %llu hash attempts; at difficulty 4 every block\n",
               attempts);
        puts("    costs ~65,536. Even then the signature of the edited record is invalid,");
        puts("    and state.dat still records the original tip hash.");
        break;
    default:
        puts("  - The remaining blocks are valid on their own, but state.dat records the");
        puts("    chain length and tip hash: a chain that got shorter is reported.");
        break;
    }

    chain_free(&lib->chain);
    lib->chain = backup;
    (void)library_validate(lib, NULL, &v);
    printf("\nOriginal chain restored from the in-memory backup: %s\n",
           lib->chain_ok ? "VALID" : "INVALID");
    puts("(chain.dat on disk was never modified by this demo)");
}
