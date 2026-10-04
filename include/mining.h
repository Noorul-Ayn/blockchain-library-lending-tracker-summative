/**
 * @file mining.h
 * @brief Mining simulations that confirm the pending pool (Formative 2).
 *
 * All three approaches use the same proof-of-work (pow_scan) and the same
 * confirmation step (library_confirm), so a block mined by a solo miner,
 * a pool or a rented cloud miner is indistinguishable on the chain apart
 * from its mined_by field.
 *
 * Reward per confirmed block = BLOCK_REWARD + the block's transaction fee.
 *   Solo  : the single miner receives everything.
 *   Pool  : 2% pool fee first, the rest shared by
 *           (miner_attempts / total_attempts) x reward.
 *   Cloud : the renter pays CLOUD_RENTAL_FEE per round; rewards are
 *           credited each round minus CLOUD_MAINTENANCE_PERCENT.
 */
#ifndef LT_MINING_H
#define LT_MINING_H

#include <stddef.h>

#include "common.h"
#include "lending.h"

/** Called after every confirmed block (UI prints it and the ledger). */
typedef void (*BlockConfirmedFn)(void *ctx, Library *lib, const Block *block,
                                 unsigned long long attempts, double elapsed_ms,
                                 const char *found_by);

/** Called when a pending block is rejected during mining. */
typedef void (*BlockRejectedFn)(void *ctx, const Block *block, const char *reason);

typedef struct {
    BlockConfirmedFn on_confirmed;
    BlockRejectedFn  on_rejected;
    void            *ctx;
} MiningCallbacks;

typedef struct {
    size_t             blocks_confirmed;
    size_t             blocks_rejected;
    unsigned long long attempts;
    double             elapsed_ms;
    long               fees;            /* transaction fees collected        */
    double             gross_reward;    /* BLOCK_REWARD x blocks + fees      */
} MiningSummary;

/* ---- Solo ---------------------------------------------------------------- */
Status mine_solo(Library *lib, const char *miner_id, const MiningCallbacks *cb,
                 MiningSummary *summary);

/* ---- Pool ---------------------------------------------------------------- */
typedef struct {
    char               id[MINER_ID_LEN];
    unsigned long      hash_rate;       /* attempts per round (random)       */
    unsigned long long attempts;        /* total hashes computed             */
    int                blocks_found;
    double             share;           /* attempts / total_attempts         */
    double             reward;          /* share x (gross - pool fee)        */
} PoolMiner;

typedef struct {
    PoolMiner     miners[POOL_MAX_MINERS];
    size_t        miner_count;
    unsigned long rounds;
    double        pool_fee;
    double        distributed;
    MiningSummary summary;
} PoolResult;

Status mine_pool(Library *lib, size_t miner_count, const MiningCallbacks *cb,
                 PoolResult *result);

/* ---- Cloud --------------------------------------------------------------- */
typedef struct {
    int                round;
    unsigned long long attempts;
    int                blocks;
    double             reward;          /* gross reward earned this round    */
    double             maintenance;     /* % of this round's reward          */
    double             rental;          /* fixed fee per round               */
    double             credited;        /* reward - maintenance              */
    double             cum_reward;
    double             cum_fees;        /* rental + maintenance so far       */
    double             net;             /* cum_reward - cum_fees             */
    int                unprofitable;    /* cum_fees > cum_reward             */
} CloudRound;

typedef struct {
    CloudRound    rounds[CLOUD_MAX_ROUNDS];
    int           round_count;
    double        gross;
    double        rental_total;
    double        maintenance_total;
    double        fees_total;
    double        net;
    int           ever_unprofitable;
    size_t        still_pending;
    MiningSummary summary;
} CloudResult;

Status mine_cloud(Library *lib, int rounds, const char *renter, const MiningCallbacks *cb,
                  CloudResult *result);

/* ---- Difficulty benchmark ------------------------------------------------ */
typedef struct {
    int                difficulty;
    int                trials;
    double             avg_attempts;
    unsigned long long min_attempts;
    unsigned long long max_attempts;
    double             expected;        /* 16^difficulty                     */
    double             avg_ms;
} BenchRow;

/** Mines `trials` sample blocks at each difficulty 1..MAX_DIFFICULTY. */
Status mining_benchmark(int trials, BenchRow rows[MAX_DIFFICULTY]);

/** Reward for one confirmed block (block reward + its transaction fee). */
double mining_block_reward(const Block *block);

#endif /* LT_MINING_H */
