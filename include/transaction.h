/**
 * @file transaction.h
 * @brief Token transactions carried inside blocks (Formative 2).
 *
 * Two kinds of transaction exist:
 *   REWARD   - issued by the library when a book is returned
 *              (10 coins on time, 5 coins late). The 1-coin fee is deducted
 *              before crediting the member, so the member receives 9 or 4.
 *   TRANSFER - a member sends coins to another member. The sender pays the
 *              amount plus the 1-coin fee.
 *
 * A transaction is stored in a model-neutral form so that the same chain
 * can be replayed by either ledger model:
 *   - the account model uses from / to / amount / fee / nonce
 *   - the UTXO model additionally uses the explicit inputs (previous
 *     outputs being spent) when they were chosen under the UTXO model.
 * Its ID is the SHA-256 hash of its canonical text form, and that ID is
 * stored in the block's tx_id field.
 */
#ifndef LT_TRANSACTION_H
#define LT_TRANSACTION_H

#include <stddef.h>
#include <time.h>

#include "common.h"

#define TX_MAX_INPUTS  16
#define TX_TEXT_MAX    (256 + TX_MAX_INPUTS * (HASH_HEX_LEN + 12))

typedef enum {
    TX_NONE     = 0,   /* block carries no transaction (borrow, overdue) */
    TX_REWARD   = 1,
    TX_TRANSFER = 2
} TxType;

/** Reference to a previous transaction output (a UTXO) being spent. */
typedef struct {
    char txid[HASH_HEX_LEN];
    int  vout;
} TxInput;

typedef struct {
    TxType  type;
    char    from[ACCOUNT_ID_LEN];  /* LIBRARY for rewards, sender for transfers */
    char    to[ACCOUNT_ID_LEN];    /* member credited                           */
    long    amount;                /* reward: gross reward; transfer: coins sent */
    long    fee;                   /* fixed fee paid to the miner               */
    long    nonce;                 /* transfer: sender's account nonce;
                                      reward: library's reward sequence number  */
    time_t  timestamp;
    char    ref[BOOK_ID_LEN];      /* reward: the returned book; transfer: "-"  */
    size_t  input_count;           /* 0 = inputs chosen when confirmed          */
    TxInput inputs[TX_MAX_INPUTS];
} Transaction;

void tx_clear(Transaction *tx);

void tx_make_reward(Transaction *tx, const char *member_id, long amount,
                    long sequence_no, const char *book_id, time_t timestamp);

void tx_make_transfer(Transaction *tx, const char *from, const char *to,
                      long amount, long nonce, time_t timestamp);

/**
 * Canonical text form, e.g. "R;LIBRARY;ALU001;10;1;3;1790425833;BK001;"
 * ("-" for TX_NONE). Used both for storage and for computing the ID.
 * @return length written, or -1 if it does not fit.
 */
int tx_serialize(const Transaction *tx, char *buf, size_t cap);

/** Parses the canonical text form (strict validation). */
Status tx_parse(const char *text, Transaction *tx);

/** tx_id = SHA-256(canonical text). */
Status tx_compute_id(const Transaction *tx, char out[HASH_HEX_LEN]);

/** Coins credited to the recipient (reward: amount - fee; transfer: amount). */
long tx_recipient_credit(const Transaction *tx);

/** Coins debited from the sender (transfer: amount + fee; reward: 0). */
long tx_sender_debit(const Transaction *tx);

const char *tx_type_name(TxType type);

#endif /* LT_TRANSACTION_H */
