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

static Status check_can_mine(const Library *lib)
{
    if (!auth_has_permission(&lib->session, PERM_LENDING))
        return LT_ERR_DENIED;
    if (!lib->validated || !lib->chain_ok)
        return LT_ERR_CHAIN_INVALID;
    return LT_OK;
}

/**
 * Takes the top N requests of the prioritised pool. LT_ERR_POOL_EMPTY means
 * nothing could be mined (the report says what is waiting and why).
 */
static Status assemble(Library *lib, const char *sealed_by, const MiningCallbacks *cb,
                       Block *block, MiningSummary *s)
{
    Status st = library_assemble_block(lib, sealed_by, block, &s->last_assembly);

    if (st == LT_OK && cb != NULL && cb->on_assembled != NULL)
        cb->on_assembled(cb->ctx, lib, block, &s->last_assembly);
    return st;
}

/** Hands a mined block to library_commit_block and reports the result. */
static Status confirm_mined(Library *lib, Block *mined, unsigned long long attempts, double ms,
                            const char *finder, const MiningCallbacks *cb, MiningSummary *s,
                            double *reward_out)
{
    AssemblyReport after;
    char err[300];
    double reward = library_block_earnings(lib, mined);
    long fees = (long)reward - lib->block_reward;
    size_t records = mined->record_count;
    Status st = library_commit_block(lib, mined, &after, err, sizeof err);

    if (reward_out != NULL)
        *reward_out = 0.0;
    if (st != LT_OK) {
        s->blocks_rejected++;
        if (cb != NULL && cb->on_rejected != NULL)
            cb->on_rejected(cb->ctx, mined, err);
        block_free(mined);
        return st;
    }
    s->blocks_confirmed++;
    s->records_confirmed += records;
    s->fees += fees;
    s->gross_reward += reward;
    if (reward_out != NULL)
        *reward_out = reward;
    if (cb != NULL && cb->on_confirmed != NULL)
        cb->on_confirmed(cb->ctx, lib, chain_tip(&lib->chain), attempts, ms, finder, &after);
    return LT_OK;
}

/* ------------------------------------------------------------------------ */
/* Solo mining                                                              */
/* ------------------------------------------------------------------------ */

Status mine_solo(Library *lib, const char *miner_id, size_t max_blocks,
                 const MiningCallbacks *cb, MiningSummary *summary)
{
    double start_ms = now_ms();
    Status st = check_can_mine(lib);

    memset(summary, 0, sizeof *summary);
    if (st != LT_OK)
        return st;

    while (max_blocks == 0 || summary->blocks_confirmed < max_blocks) {
        Block block;
        unsigned long long attempts;
        double t0;

        st = assemble(lib, miner_id, cb, &block, summary);
        if (st == LT_ERR_POOL_EMPTY)
            break;
        if (st != LT_OK)
            return st;
        t0 = now_ms();
        attempts = pow_mine(&block);       /* increment nonce until target met */
        if (attempts == 0) {
            block_free(&block);
            return LT_ERR_CRYPTO;
        }
        summary->attempts += attempts;
        st = confirm_mined(lib, &block, attempts, now_ms() - t0, miner_id, cb, summary, NULL);
        if (st != LT_OK)
            return st;
    }
    summary->elapsed_ms = now_ms() - start_ms;
    return summary->blocks_confirmed > 0 ? LT_OK : LT_ERR_POOL_EMPTY;
}

/* ------------------------------------------------------------------------ */
/* Pool mining                                                              */
/* ------------------------------------------------------------------------ */

/*
 * Every miner works on the same assembled block but puts its own ID in
 * sealed_by, so each miner hashes a different header. Each round, every
 * miner tries up to its hash rate of nonces in its own range. If several
 * miners find a valid nonce in the same round, the one who found it
 * earliest (smallest fraction of its round) wins, and every miner is
 * credited with the work it had done up to that moment.
 */
Status mine_pool(Library *lib, size_t miner_count, size_t max_blocks,
                 const MiningCallbacks *cb, PoolResult *result)
{
    double start_ms = now_ms();
    unsigned long long total = 0;
    size_t i;
    Status st;

    memset(result, 0, sizeof *result);
    st = check_can_mine(lib);
    if (st != LT_OK)
        return st;
    if (miner_count < POOL_MIN_MINERS || miner_count > POOL_MAX_MINERS)
        return LT_ERR_INPUT;

    result->miner_count = miner_count;
    for (i = 0; i < miner_count; i++) {
        snprintf(result->miners[i].id, sizeof result->miners[i].id, "POOL-M%zu", i + 1);
        result->miners[i].hash_rate = rng_range(POOL_MIN_HASH_RATE, POOL_MAX_HASH_RATE);
    }

    while (max_blocks == 0 || result->summary.blocks_confirmed < max_blocks) {
        Block block, winner_block;
        unsigned long long counter[POOL_MAX_MINERS] = {0};
        unsigned long long block_attempts = 0;
        double t0;
        int found = 0;

        st = assemble(lib, "POOL", cb, &block, &result->summary);
        if (st == LT_ERR_POOL_EMPTY)
            break;
        if (st != LT_OK)
            return st;
        memset(&winner_block, 0, sizeof winner_block);
        t0 = now_ms();

        while (!found) {
            unsigned long long scanned[POOL_MAX_MINERS], offset[POOL_MAX_MINERS];
            double best_t = 2.0;
            int winner = -1;

            result->rounds++;
            for (i = 0; i < miner_count; i++) {
                /* Shallow copy: only header fields change, records are shared. */
                Block trial = block;
                unsigned long long base = ((unsigned long long)(i + 1) << 40) + counter[i];
                int r;

                (void)str_copy(trial.sealed_by, sizeof trial.sealed_by, result->miners[i].id);
                r = pow_scan(&trial, base, result->miners[i].hash_rate, &scanned[i], &offset[i]);
                if (r < 0) {
                    block_free(&block);
                    return LT_ERR_CRYPTO;
                }
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
                /* winner_block shares block's records; commit takes them over. */
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
    return result->summary.blocks_confirmed > 0 ? LT_OK : LT_ERR_POOL_EMPTY;
}

/* ------------------------------------------------------------------------ */
/* Cloud mining                                                             */
/* ------------------------------------------------------------------------ */

/*
 * The renter buys CLOUD_HASH_POWER attempts per round. A block that is not
 * finished in one round carries over to the next. Rented power that has
 * nothing left to mine is still paid for, which is what makes long rentals
 * at high difficulty unprofitable.
 */
Status mine_cloud(Library *lib, int rounds, const char *renter, const MiningCallbacks *cb,
                  CloudResult *result)
{
    char miner_id[MINER_ID_LEN];
    double start_ms = now_ms(), block_t0 = 0.0;
    Block block;
    int have_block = 0, nothing_left = 0, r;
    unsigned long long counter = 0, block_attempts = 0;
    Status st;

    memset(result, 0, sizeof *result);
    st = check_can_mine(lib);
    if (st != LT_OK)
        return st;
    if (rounds < CLOUD_MIN_ROUNDS || rounds > CLOUD_MAX_ROUNDS)
        return LT_ERR_INPUT;
    snprintf(miner_id, sizeof miner_id, "CLOUD-%.24s", renter);

    for (r = 1; r <= rounds; r++) {
        CloudRound *round = &result->rounds[r - 1];
        unsigned long long budget = CLOUD_HASH_POWER;

        round->round = r;
        while (budget > 0 && !nothing_left) {
            unsigned long long attempts = 0, offset = 0;
            int found;

            if (!have_block) {
                st = assemble(lib, miner_id, cb, &block, &result->summary);
                if (st == LT_ERR_POOL_EMPTY) {
                    nothing_left = 1;
                    break;
                }
                if (st != LT_OK)
                    return st;
                have_block = 1;
                counter = 0;
                block_attempts = 0;
                block_t0 = now_ms();
            }
            found = pow_scan(&block, counter, budget, &attempts, &offset);
            if (found < 0) {
                block_free(&block);
                return LT_ERR_CRYPTO;
            }
            budget -= attempts;
            counter += attempts;
            block_attempts += attempts;
            round->attempts += attempts;
            result->summary.attempts += attempts;
            if (found == 1) {
                double reward = 0.0;

                have_block = 0;
                st = confirm_mined(lib, &block, block_attempts, now_ms() - block_t0, miner_id,
                                   cb, &result->summary, &reward);
                if (st != LT_OK)
                    return st;
                round->blocks++;
                round->reward += reward;
            }
        }
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
    if (have_block)
        block_free(&block);        /* unfinished work: requests stay in the pool */
    result->fees_total = result->rental_total + result->maintenance_total;
    result->net = result->gross - result->fees_total;
    result->still_pending = library_minable(lib);
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
            block_init(&sample);
            sample.index = 1000000 + t;
            sample.timestamp = (time_t)rng_range(1, 1000000000UL);
            (void)str_copy(sample.sealed_by, sizeof sample.sealed_by, "BENCHMARK");
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
