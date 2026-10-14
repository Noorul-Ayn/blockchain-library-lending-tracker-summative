/**
 * @file mining.h
 * @brief Proof-of-work mining of the pending pool: solo, pool and cloud.
 *
 * All three approaches use the same block assembly (library_assemble_block:
 * the top N requests of the prioritised pool), the same proof-of-work
 * (pow_scan: increment the nonce, recompute SHA-256 until the hash starts
 * with `difficulty` zeros) and the same confirmation step
 * (library_commit_block), so a block mined by a solo miner, a pool or a
 * rented cloud miner differs on the chain only in its sealed_by field.
 *
 * Mining reward per confirmed block = block_reward + every fee in the block
 * (1 coin per reward output and per token transaction).
 *   Solo  : the single miner receives the full reward.
 *   Pool  : a 2% pool fee is deducted first; the rest is shared by
 *           (miner_attempts / total_attempts) x reward.
 *   Cloud : the renter pays a fixed rental fee per round (1-5 rounds); the
 *           rewards of blocks found with the rented hash power are credited
 *           each round, minus a maintenance percentage.
 * Miners are simulated nodes, not library members, so mining rewards are
 * reported but not paid into member balances.
 */
#ifndef LT_MINING_H
#define LT_MINING_H

#include <stddef.h>

#include "common.h"
#include "library.h"

typedef struct {
    /** A block was assembled from the pool and is about to be mined. */
    void (*on_assembled)(void *ctx, const Library *lib, const Block *candidate,
                         const AssemblyReport *report);
    /** A block was mined and confirmed. after = requests discarded afterwards. */
    void (*on_confirmed)(void *ctx, Library *lib, const Block *block,
                         unsigned long long attempts, double elapsed_ms,
                         const char *found_by, const AssemblyReport *after);
    /** A mined block failed confirmation (should not happen). */
    void (*on_rejected)(void *ctx, const Block *block, const char *reason);
    void *ctx;
} MiningCallbacks;

typedef struct {
    size_t             blocks_confirmed;
    size_t             blocks_rejected;
    size_t             records_confirmed;
    unsigned long long attempts;
    double             elapsed_ms;
    long               fees;             /* transaction fees collected        */
    double             gross_reward;     /* block_reward x blocks + fees      */
    AssemblyReport     last_assembly;    /* why mining stopped                */
} MiningSummary;

/* ---- Solo ------------------------------------------------------------------ */

/** Mines blocks until nothing minable is left (max_blocks = 0) or max_blocks. */
Status mine_solo(Library *lib, const char *miner_id, size_t max_blocks,
                 const MiningCallbacks *cb, MiningSummary *summary);

/* ---- Pool ------------------------------------------------------------------ */
typedef struct {
    char               id[MINER_ID_LEN];
    unsigned long      hash_rate;        /* attempts per round (random)       */
    unsigned long long attempts;         /* total hashes computed             */
    int                blocks_found;
    double             share;            /* attempts / total_attempts         */
    double             reward;           /* share x (gross - pool fee)        */
} PoolMiner;

typedef struct {
    PoolMiner     miners[POOL_MAX_MINERS];
    size_t        miner_count;
    unsigned long rounds;
    double        pool_fee;
    double        distributed;
    MiningSummary summary;
} PoolResult;

Status mine_pool(Library *lib, size_t miner_count, size_t max_blocks,
                 const MiningCallbacks *cb, PoolResult *result);

/* ---- Cloud ----------------------------------------------------------------- */
typedef struct {
    int                round;
    unsigned long long attempts;
    int                blocks;
    double             reward;           /* gross reward earned this round    */
    double             maintenance;      /* % of this round's reward          */
    double             rental;           /* fixed fee per round               */
    double             credited;         /* reward - maintenance              */
    double             cum_reward;
    double             cum_fees;         /* rental + maintenance so far       */
    double             net;              /* cum_reward - cum_fees             */
    int                unprofitable;     /* cum_fees > cum_reward             */
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

/* ---- Difficulty benchmark ---------------------------------------------------- */
typedef struct {
    int                difficulty;
    int                trials;
    double             avg_attempts;
    unsigned long long min_attempts;
    unsigned long long max_attempts;
    double             expected;         /* 16^difficulty                     */
    double             avg_ms;
} BenchRow;

/** Mines `trials` throw-away blocks at each difficulty 1..MAX_DIFFICULTY. */
Status mining_benchmark(int trials, BenchRow rows[MAX_DIFFICULTY]);

#endif /* LT_MINING_H */
