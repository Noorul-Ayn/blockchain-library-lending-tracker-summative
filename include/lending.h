/**
 * @file lending.h
 * @brief Application state and business rules: lending, token rewards,
 *        token transfers and block confirmation.
 *
 * Flow (Formative 2):
 *   borrow / return / overdue / transfer  ->  signed block in PENDING POOL
 *   mining (solo, pool or cloud)          ->  library_confirm()
 *   library_confirm()                     ->  transaction applied to the
 *                                             ledger, block appended to the
 *                                             confirmed chain
 */
#ifndef LT_LENDING_H
#define LT_LENDING_H

#include <time.h>

#include "auth.h"
#include "blockchain.h"
#include "common.h"
#include "keyring.h"
#include "ledger.h"
#include "registry.h"

typedef enum {
    BOOK_AVAILABLE,
    BOOK_ON_LOAN,
    BOOK_OVERDUE
} BookState;

/** Everything the running application needs, in one place. */
typedef struct {
    char           data_dir[LT_PATH_MAX];
    char           chain_path[LT_PATH_MAX];
    char           pending_path[LT_PATH_MAX];
    BookRegistry   books;
    MemberRegistry members;
    Blockchain     chain;          /* confirmed (mined) blocks              */
    Blockchain     pending;        /* signed records waiting to be mined    */
    KeyRing        keys;
    Session        session;
    long           loan_period;    /* seconds before a loan is late         */
    int            difficulty;     /* proof-of-work difficulty for mining   */
    Ledger         ledger;         /* balances under the session's model    */
    int            ledger_ok;      /* 0 if replaying the chain failed       */
    char           ledger_error[256];
} Library;

/** A token transfer request entered by the user. */
typedef struct {
    char    from[MEMBER_ID_LEN];
    char    to[MEMBER_ID_LEN];
    long    amount;
    long    nonce;                       /* account model: user-supplied     */
    size_t  input_count;                 /* UTXO model: 0 = automatic choice */
    TxInput inputs[TX_MAX_INPUTS];
} TransferRequest;

/* ---- Set-up ------------------------------------------------------------ */
Status library_init(Library *lib, const char *data_dir, LedgerModel model);
Status library_load_registries(Library *lib);

/**
 * Loads chain.dat and pending.dat. *need_genesis is set if no chain exists.
 * Pending records that are already on the chain (crash between the two
 * saves) are dropped.
 */
Status library_load_state(Library *lib, int *need_genesis, char *err, size_t err_cap);

/** Replays every confirmed transaction into the session's ledger model. */
Status library_rebuild_ledger(Library *lib);

/**
 * Replays the chain into a temporary ledger (same model) without touching
 * the live one: detects double spends, overspending and bad nonces.
 */
Status library_verify_ledger(const Library *lib, char *err, size_t err_cap,
                             size_t *transactions);

/** Chain structure + cryptography valid AND ledger replay succeeded. */
int    library_chain_is_valid(Library *lib);

Status library_save_pending(Library *lib);
void   library_free(Library *lib);

/* ---- Lending (each creates a pending block) ----------------------------- */
BookState lending_book_state(const Library *lib, const char *book_id, const Block **loan);
Status    lending_borrow(Library *lib, const char *book_id, const char *member_id);

/** *reward_out = 10 (on time) or 5 (late); the reward tx is pending. */
Status    lending_return(Library *lib, const char *book_id, const char *member_id,
                         int *reward_out);

/** OVERDUE blocks carry no transaction: an unreturned book earns nothing. */
Status    lending_mark_overdue(Library *lib, time_t now, size_t *marked);

/* ---- Tokens ------------------------------------------------------------ */
/** Coins and number of the member's transfers waiting in the pending pool. */
long   tokens_pending_debit(const Library *lib, const char *member_id, long *count);

/** Nonce the member's next transfer must use (confirmed + pending). */
long   tokens_next_nonce(const Library *lib, const char *member_id);

/** UtxoReservedFn: is this output already spent by a pending transfer? */
int    tokens_is_reserved(const void *lib, const char *txid, int vout);

/**
 * Validates a transfer under the session's model and adds it to the
 * pending pool. *change_out receives the change (UTXO model).
 */
Status tokens_transfer(Library *lib, const TransferRequest *req, Transaction *created,
                       long *change_out, char *err, size_t err_cap);

/* ---- Confirmation (called by the miners) -------------------------------- */
/**
 * Confirms the first pending block, which `mined` is a mined copy of:
 * verifies it, applies its transaction to the ledger, appends it to the
 * chain and removes it from the pending pool (both files saved).
 * On a validation failure the pending block is rejected and removed.
 */
Status library_confirm(Library *lib, const Block *mined, char *err, size_t err_cap);

#endif /* LT_LENDING_H */
