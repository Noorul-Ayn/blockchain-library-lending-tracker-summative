/**
 * @file library.h
 * @brief The application core: lending operations, request submission,
 *        fraud detection, block assembly and confirmation, validation.
 *
 * Request life cycle:
 *   1. An operation (borrow, return, reserve, renew, overdue flag, lost copy,
 *      transfer, fine) is validated against the PROJECTED state = the state
 *      rebuilt from the chain plus every request already in the pool.
 *   2. The request gets the signer's next nonce, a request ID and an ECDSA
 *      signature from the signer's private key (member key from the vault,
 *      or the librarian's own key).
 *   3. The fraud heuristics run; a flagged request is stored as SUSPICIOUS.
 *   4. The request is added to the pending pool and pending.dat is saved.
 *   5. A miner assembles a block from the top of the prioritised pool,
 *      re-verifying every signature and re-applying every rule against the
 *      confirmed state; then proof-of-work seals the block.
 *   6. library_commit_block() appends the block, applies it to the confirmed
 *      state (balances change only now), removes the confirmed requests from
 *      the pool and saves chain.dat, pending.dat and state.dat.
 */
#ifndef LT_LIBRARY_H
#define LT_LIBRARY_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include "auth.h"
#include "blockchain.h"
#include "common.h"
#include "keystore.h"
#include "ledger.h"
#include "pool.h"
#include "registry.h"
#include "state.h"
#include "storage.h"

typedef struct {
    char data_dir[LT_PATH_MAX];
    char books_path[LT_PATH_MAX], copies_path[LT_PATH_MAX], members_path[LT_PATH_MAX];
    char chain_path[LT_PATH_MAX], pool_path[LT_PATH_MAX], state_path[LT_PATH_MAX];

    BookRegistry   books;
    CopyRegistry   copies;
    MemberRegistry members;
    Blockchain     chain;
    PendingPool    pool;
    KeyDirectory   keys;
    Session        session;

    LedgerModel    model;
    LendingRules   rules;
    int            difficulty;
    long           block_reward;
    int            block_capacity;

    LibraryState   state;          /* confirmed state, rebuilt from the chain */
    int            state_ok;
    char           state_error[256];

    int            validated;      /* validate_chain has run this session    */
    int            chain_ok;       /* result of the last validation          */
} Library;

/** Rejected request reported by block assembly. */
typedef struct {
    char record_id[REQUEST_ID_LEN];
    char reason[320];
} Rejection;

typedef struct {
    size_t    selected;            /* records placed in the block           */
    size_t    deferred;            /* waiting for an earlier nonce          */
    size_t    suspicious_skipped;  /* held back for fraud review            */
    Rejection rejected[32];
    size_t    rejected_count;
} AssemblyReport;

typedef struct {
    ChainReport chain;
    int         chain_ok;             /* hashes, PoW, links, Merkle, signatures */
    int         replay_ok;            /* every record obeys the lending rules   */
    char        replay_error[256];
    int         meta_ok;              /* chain length / tip match state.dat     */
    char        meta_detail[200];
    size_t      pending_checked, pending_bad_signatures;
    int         state_file_present;
    size_t      state_differences;    /* snapshot lines that differ             */
    char        state_first_diff[200];
} ValidationSummary;

/* ---- Set-up, loading and saving -------------------------------------------- */
void   library_init(Library *lib, const char *data_dir);
void   library_free(Library *lib);
Status library_load_registries(Library *lib);

/**
 * Loads chain.dat, pending.dat and the settings in state.dat (difficulty,
 * rules, simulated clock). *needs_genesis is set when there is no chain yet.
 * The loaded chain counts as unvalidated until library_validate() runs.
 */
Status library_load_files(Library *lib, int *needs_genesis, char *err, size_t err_cap);

/** Mines block 0 at the current difficulty and saves chain.dat. */
Status library_create_genesis(Library *lib);
Status library_rebuild_state(Library *lib);
Status library_save_pool(Library *lib);
Status library_save_state(Library *lib);
Status library_save_all(Library *lib);
void   library_context(const Library *lib, StateContext *ctx);
StateMeta library_meta(const Library *lib);

/** Confirmed state + pending requests (in arrival order). Caller frees. */
Status library_project(const Library *lib, LibraryState *proj);

/** Creates member key pairs that do not exist yet (needs an open vault). */
Status library_ensure_member_keys(Library *lib, size_t *created);

/* ---- Registration (appends to books.txt / members.txt / copies.txt) ------- */
Status library_register_member(Library *lib, const char *id, const char *name,
                               const char *course, const char **why);
Status library_register_book(Library *lib, const char *id, const char *title,
                             const char *author, const char **why);
/** copy_id may be NULL: the next free ID (e.g. BK001-C3) is used. */
Status library_add_copy(Library *lib, const char *copy_id, const char *book_id,
                        Condition condition, char out_id[COPY_ID_LEN], const char **why);

/* ---- Operations (each submits one signed request to the pending pool) --- */
Status library_borrow(Library *lib, const char *book_or_copy, const char *member_id,
                      time_t due_date, Request *out, char *err, size_t err_cap);
Status library_return(Library *lib, const char *copy_id, int has_condition,
                      Condition condition, const char *reason, Request *out,
                      char *err, size_t err_cap);
Status library_reserve(Library *lib, const char *book_id, const char *member_id,
                       Request *out, char *err, size_t err_cap);
Status library_renew(Library *lib, const char *copy_id, const char *member_id,
                     Request *out, char *err, size_t err_cap);
Status library_mark_lost(Library *lib, const char *copy_id, const char *reason,
                         Request *out, char *err, size_t err_cap);
Status library_transfer(Library *lib, const char *from, const char *to, long amount,
                        const TxInput *inputs, size_t input_count, long account_nonce,
                        Request *out, char *err, size_t err_cap);
Status library_settle_fine(Library *lib, const char *member_id, long amount, int cash,
                           Request *out, char *err, size_t err_cap);

/** Flags every overdue loan that has no OVERDUE record yet. */
Status library_overdue_scan(Library *lib, Request *created, size_t max, size_t *count,
                            char *err, size_t err_cap);

/* ---- Fraud review ---------------------------------------------------------- */

/**
 * approve_suspicious: the request becomes PENDING (minable) and the review
 * note "approved by <user> (<flags>)" is stored with it. If the request
 * breaks a rule (e.g. a replayed request with a used nonce) it is
 * discarded instead and LT_ERR_STATE is returned with the reason.
 * Requests discarded as a consequence are listed in *cascade.
 */
Status library_approve(Library *lib, const char *id, Request *out, AssemblyReport *cascade,
                       char *err, size_t err_cap);

/** reject_suspicious: removes the request from the pool. */
Status library_reject(Library *lib, const char *id, Request *out, AssemblyReport *cascade,
                      char *err, size_t err_cap);

/** Simulated replay attack: re-submits a confirmed record unchanged. */
Status library_replay(Library *lib, const char *record_id, Request *out,
                      char *err, size_t err_cap);

/* ---- Mining ------------------------------------------------------------------ */

/** Number of requests a miner could take now (PENDING, not SUSPICIOUS). */
size_t library_minable(const Library *lib);

/**
 * Builds the next block (not yet mined) from the top of the prioritised
 * pool. Invalid requests are removed from the pool and listed in report.
 * @return LT_ERR_POOL_EMPTY if no request could be included.
 */
Status library_assemble_block(Library *lib, const char *sealed_by, Block *out,
                              AssemblyReport *report);

/**
 * Mining preview for pool_view: a sorted copy of the pool is written to
 * *sorted (caller frees with pool_free) and block_of[i] receives the index
 * of the block that request i would go into if mining started now (-1 =
 * not minable yet). block_of must have room for lib->pool.count entries.
 * @return the number of requests that would be mined.
 */
size_t library_preview(const Library *lib, PendingPool *sorted, int *block_of);

/**
 * Verifies a mined block (link, hash, proof-of-work, Merkle root, every
 * signature and every lending rule), appends it, applies it to the
 * confirmed state, removes its requests from the pool and saves all three
 * files. Requests made invalid by the new block are discarded and listed
 * in *after (may be NULL). Takes ownership of block->records on success.
 */
Status library_commit_block(Library *lib, Block *block, AssemblyReport *after,
                            char *err, size_t err_cap);

/** Discards pending requests that are no longer valid (see prune rules). */
void library_prune(Library *lib, AssemblyReport *report);

/** Mining reward for a block: block reward + every fee in the block. */
double library_block_earnings(const Library *lib, const Block *block);

/* ---- Validation and history -------------------------------------------------- */
int library_validate(Library *lib, FILE *log, ValidationSummary *out);

/** Most recent confirmed record of an action for a copy (searches the chain). */
const Record *library_last_record_for_copy(const Library *lib, const char *copy_id,
                                           Action action, long *block_index);

/** Re-numbers and re-signs one signer's pending requests after a removal. */
void library_resequence(Library *lib, const char *signer_id);

#endif /* LT_LIBRARY_H */
