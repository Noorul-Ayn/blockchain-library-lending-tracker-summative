/**
 * @file mining.c
 * @brief Solo, pool and cloud mining of the pending pool, and a
 *        proof-of-work difficulty benchmark.
 */
#include "mining.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

double mining_block_reward(const Block *block)
{
    return (double)BLOCK_REWARD + (block->tx.type != TX_NONE ? (double)block->tx.fee : 0.0);
}

static void summary_init(MiningSummary *s)
{
    memset(s, 0, sizeof *s);
}

/**
 * Rejects the first pending block before any work is spent on it if its
 * signature or transaction is invalid. @return 1 if it is fine to mine.
 */
static int precheck_head(Library *lib, const MiningCallbacks *cb, MiningSummary *s)
{
    const Block *head = &lib->pending.blocks[0];
    const char *why = NULL;
    Block copy;

    if (block_verify_signature(head, &lib->keys) == SIG_VALID && block_tx_consistent(head, &why))
        return 1;
    copy = *head;
    chain_remove_at(&lib->pending, 0);
    (void)library_save_pending(lib);
    s->blocks_rejected++;
    if (cb && cb->on_rejected)
        cb->on_rejected(cb->ctx, &copy, why ? why : "invalid signature");
    return 0;
}

/** Hands a mined block to library_confirm and reports the result. */
static Status confirm_mined(Library *lib, const Block *mined, unsigned long long attempts,
                            double ms, const char *finder, const MiningCallbacks *cb,
                            MiningSummary *s, double *reward_out)
{
    char err[200];
    Status st = library_confirm(lib, mined, err, sizeof err);

    if (reward_out != NULL)
        *reward_out = 0.0;
    if (st == LT_OK) {
        double reward = mining_block_reward(mined);
        s->blocks_confirmed++;
        s->fees += mined->tx.type != TX_NONE ? mined->tx.fee : 0;
        s->gross_reward += reward;
        if (reward_out != NULL)
            *reward_out = reward;
        if (cb && cb->on_confirmed)
            cb->on_confirmed(cb->ctx, lib, &lib->chain.blocks[lib->chain.length - 1],
                             attempts, ms, finder);
        return LT_OK;
    }
    if (st == LT_ERR_CHAIN_INVALID || st == LT_ERR_IO || st == LT_ERR_MEMORY)
        return st;                       /* a real fault: stop mining */
    s->blocks_rejected++;                /* the transaction was invalid */
    if (cb && cb->on_rejected)
        cb->on_rejected(cb->ctx, mined, err);
    return LT_OK;
}

static Status check_can_mine(Library *lib, int allow_empty)
{
    if (!auth_has_permission(&lib->session, PERM_RECORD_LENDING))
        return LT_ERR_DENIED;
    if (!library_chain_is_valid(lib))
        return LT_ERR_CHAIN_INVALID;
    if (!allow_empty && lib->pending.length == 0)
        return LT_ERR_POOL_EMPTY;
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Solo mining                                                              */
/* ------------------------------------------------------------------------ */

Status mine_solo(Library *lib, const char *miner_id, const MiningCallbacks *cb,
                 MiningSummary *summary)
{
    double start_ms = now_ms();
    Status st = check_can_mine(lib, 0);

    summary_init(summary);
    if (st != LT_OK)
        return st;

    while (lib->pending.length > 0) {
        Block block;
        unsigned long long attempts;
        double t0;

        if (!precheck_head(lib, cb, summary))
            continue;
        block = lib->pending.blocks[0];
        block_prepare_for_mining(&block, &lib->chain, lib->difficulty, miner_id);

        t0 = now_ms();
        attempts = pow_mine(&block);       /* increment nonce until target met */
        if (attempts == 0)
            return LT_ERR_CRYPTO;
        summary->attempts += attempts;
        st = confirm_mined(lib, &block, attempts, now_ms() - t0, miner_id, cb, summary, NULL);
        if (st != LT_OK)
            return st;
    }
    summary->elapsed_ms = now_ms() - start_ms;
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Pool mining                                                              */
/* ------------------------------------------------------------------------ */

/*
 * Each round, every miner hashes up to its hash rate using its own nonce
 * range. If several miners find a valid nonce in the same round, the one
 * who found it earliest (smallest fraction of its round) wins, and every
 * miner is credited with the work it had done up to that moment.
 */
Status mine_pool(Library *lib, size_t miner_count, const MiningCallbacks *cb,
                 PoolResult *result)
{
    double start_ms = now_ms();
    unsigned long long total = 0;
    size_t i;
    Status st;

    memset(result, 0, sizeof *result);
    st = check_can_mine(lib, 0);
    if (st != LT_OK)
        return st;
    if (miner_count < POOL_MIN_MINERS || miner_count > POOL_MAX_MINERS)
        return LT_ERR_INPUT;

    result->miner_count = miner_count;
    for (i = 0; i < miner_count; i++) {
        snprintf(result->miners[i].id, sizeof result->miners[i].id, "POOL-M%zu", i + 1);
        result->miners[i].hash_rate = rng_range(POOL_MIN_HASH_RATE, POOL_MAX_HASH_RATE);
    }

    while (lib->pending.length > 0) {
        Block block, winner_block;
        unsigned long long counter[POOL_MAX_MINERS] = {0};
        unsigned long long block_attempts = 0;
        double t0;
        int found = 0;

        if (!precheck_head(lib, cb, &result->summary))
            continue;
        block = lib->pending.blocks[0];
        block_prepare_for_mining(&block, &lib->chain, lib->difficulty, "POOL");
        t0 = now_ms();

        while (!found) {
            unsigned long long scanned[POOL_MAX_MINERS], offset[POOL_MAX_MINERS];
            double best_t = 2.0;
            int winner = -1;

            result->rounds++;
            for (i = 0; i < miner_count; i++) {
                Block trial = block;
                unsigned long long base = ((unsigned long long)(i + 1) << 40) + counter[i];
                int r = pow_scan(&trial, base, result->miners[i].hash_rate, &scanned[i], &offset[i]);

                if (r < 0)
                    return LT_ERR_CRYPTO;
                if (r == 1) {
                    double t = (double)(offset[i] + 1) / (double)result->miners[i].hash_rate;
                    if (t < best_t) {
                        best_t = t;
                        winner = (int)i;
                        winner_block = trial;
                    }
                }
            }
            for (i = 0; i < miner_count; i++) {
                unsigned long long done;

                if (winner < 0)
                    done = result->miners[i].hash_rate;
                else if ((int)i == winner)
                    done = offset[i] + 1;
                else {
                    done = (unsigned long long)ceil(best_t * (double)result->miners[i].hash_rate);
                    if (done > scanned[i])
                        done = scanned[i];
                    if (done == 0)
                        done = 1;
                }
                result->miners[i].attempts += done;
                counter[i] += done;
                block_attempts += done;
            }
            if (winner >= 0) {
                found = 1;
                result->miners[winner].blocks_found++;
                result->summary.attempts += block_attempts;
                st = confirm_mined(lib, &winner_block, block_attempts, now_ms() - t0,
                                   result->miners[winner].id, cb, &result->summary, NULL);
                if (st != LT_OK)
                    return st;
            }
        }
    }

    /* Reward sharing: pool fee first, then by contribution (attempts). */
    for (i = 0; i < miner_count; i++)
        total += result->miners[i].attempts;
    result->pool_fee = result->summary.gross_reward * POOL_FEE_PERCENT / 100.0;
    result->distributed = result->summary.gross_reward - result->pool_fee;
    for (i = 0; i < miner_count; i++) {
        PoolMiner *m = &result->miners[i];
        m->share = total ? (double)m->attempts / (double)total : 0.0;
        m->reward = m->share * result->distributed;
    }
    result->summary.elapsed_ms = now_ms() - start_ms;
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Cloud mining                                                             */
/* ------------------------------------------------------------------------ */

Status mine_cloud(Library *lib, int rounds, const char *renter, const MiningCallbacks *cb,
                  CloudResult *result)
{
    char miner_id[MINER_ID_LEN];
    double start_ms = now_ms();
    Block block;
    int have_block = 0, r;
    unsigned long long counter = 0, block_attempts = 0;
    double block_t0 = 0.0;
    Status st;

    memset(result, 0, sizeof *result);
    st = check_can_mine(lib, 1);
    if (st != LT_OK)
        return st;
    if (rounds < CLOUD_MIN_ROUNDS || rounds > CLOUD_MAX_ROUNDS)
        return LT_ERR_INPUT;
    snprintf(miner_id, sizeof miner_id, "CLOUD-%s", renter);

    for (r = 1; r <= rounds; r++) {
        CloudRound *round = &result->rounds[r - 1];
        unsigned long long budget = CLOUD_HASH_POWER;

        round->round = r;
        while (budget > 0 && lib->pending.length > 0) {
            unsigned long long attempts = 0, offset = 0;
            int found;

            if (!have_block) {
                if (!precheck_head(lib, cb, &result->summary))
                    continue;
                block = lib->pending.blocks[0];
                block_prepare_for_mining(&block, &lib->chain, lib->difficulty, miner_id);
                have_block = 1;
                counter = 0;
                block_attempts = 0;
                block_t0 = now_ms();
            }
            found = pow_scan(&block, counter, budget, &attempts, &offset);
            if (found < 0)
                return LT_ERR_CRYPTO;
            budget -= attempts;
            counter += attempts;
            block_attempts += attempts;
            round->attempts += attempts;
            result->summary.attempts += attempts;
            if (found == 1) {
                double reward = 0.0;
                size_t before = result->summary.blocks_confirmed;

                have_block = 0;
                st = confirm_mined(lib, &block, block_attempts, now_ms() - block_t0, miner_id,
                                   cb, &result->summary, &reward);
                if (st != LT_OK)
                    return st;
                if (result->summary.blocks_confirmed > before) {
                    round->blocks++;
                    round->reward += reward;
                }
            }
        }
        /* Any budget left over is idle rented power: nothing was left to mine. */
        round->rental = CLOUD_RENTAL_FEE;
        round->maintenance = round->reward * CLOUD_MAINTENANCE_PERCENT / 100.0;
        round->credited = round->reward - round->maintenance;
        result->gross += round->reward;
        result->rental_total += round->rental;
        result->maintenance_total += round->maintenance;
        round->cum_reward = result->gross;
        round->cum_fees = result->rental_total + result->maintenance_total;
        round->net = round->cum_reward - round->cum_fees;
        round->unprofitable = round->cum_fees > round->cum_reward;
        if (round->unprofitable)
            result->ever_unprofitable = 1;
        result->round_count = r;
    }
    result->fees_total = result->rental_total + result->maintenance_total;
    result->net = result->gross - result->fees_total;
    result->still_pending = lib->pending.length;
    result->summary.elapsed_ms = now_ms() - start_ms;
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Difficulty benchmark                                                     */
/* ------------------------------------------------------------------------ */

Status mining_benchmark(int trials, BenchRow rows[MAX_DIFFICULTY])
{
    int d, t;

    if (trials < 1)
        return LT_ERR_INPUT;
    for (d = MIN_DIFFICULTY; d <= MAX_DIFFICULTY; d++) {
        BenchRow *row = &rows[d - 1];
        double total_attempts = 0.0, total_ms = 0.0;

        memset(row, 0, sizeof *row);
        row->difficulty = d;
        row->trials = trials;
        row->expected = pow(16.0, (double)d);
        for (t = 0; t < trials; t++) {
            Block sample;
            unsigned long long attempts;
            double t0;

            /* A throw-away block; only its header bytes matter. */
            memset(&sample, 0, sizeof sample);
            sample.index = 1000000 + t;
            sample.timestamp = time(NULL);
            (void)str_copy(sample.book_id, sizeof sample.book_id, "BENCH");
            (void)str_copy(sample.action, sizeof sample.action, "BENCH");
            (void)str_copy(sample.mined_by, sizeof sample.mined_by, "BENCHMARK");
            sample.mined_at = (time_t)(rng_range(1, 1000000000UL));
            sample.difficulty = d;

            t0 = now_ms();
            attempts = pow_mine(&sample);
            if (attempts == 0)
                return LT_ERR_CRYPTO;
            total_ms += now_ms() - t0;
            total_attempts += (double)attempts;
            if (t == 0 || attempts < row->min_attempts)
                row->min_attempts = attempts;
            if (attempts > row->max_attempts)
                row->max_attempts = attempts;
        }
        row->avg_attempts = total_attempts / trials;
        row->avg_ms = total_ms / trials;
    }
    return LT_OK;
}
