/**
 * @file transaction.h
 * @brief Token transactions, stored in a form that both ledger models read.
 *
 * Three kinds of transaction exist:
 *   REWARD    created by the miner for each block that contains returns. It
 *             has one output per RETURNED record: 10 coins (on time) or 5
 *             (late). The fixed fee is deducted from every output before the
 *             member is credited, so members receive 9 or 4.
 *   TRANSFER  a member sends coins to another member (signed by the sender).
 *   FINE      a member settles a library fine: method TOKENS pays coins to
 *             the LIBRARY account; method CASH only records that cash was
 *             received (signed by the librarian, no token movement).
 *
 * The transaction ID (tx_id) is the SHA-256 hash of the serialised form:
 *     type;from;to;amount;fee;nonce;timestamp;method;inputs;outputs
 * e.g. R;LIBRARY;-;15;1;4;1791119389;-;;ALU001:10:3fa9c2d81b07,ALU002:5:0c11...
 */
#ifndef LT_TRANSACTION_H
#define LT_TRANSACTION_H

#include <stddef.h>
#include <time.h>

#include "common.h"

#define TX_MAX_INPUTS   16
#define TX_MAX_OUTPUTS  MAX_BLOCK_CAPACITY
#define TX_METHOD_LEN   8
#define TX_TEXT_MAX     (400 + TX_MAX_INPUTS * (HASH_HEX_LEN + 8) + \
                         TX_MAX_OUTPUTS * (ACCOUNT_ID_LEN + REQUEST_ID_LEN + 16))

typedef enum {
    TX_NONE     = 0,   /* the record carries no token transaction */
    TX_REWARD   = 1,
    TX_TRANSFER = 2,
    TX_FINE     = 3
} TxType;

/** Reference to an output of an earlier transaction (UTXO model). */
typedef struct {
    char txid[HASH_HEX_LEN];
    int  vout;
} TxInput;

/** One output of a REWARD transaction (gross amount before the fee). */
typedef struct {
    char to[ACCOUNT_ID_LEN];
    long amount;
    char ref[REQUEST_ID_LEN];      /* the RETURNED record being rewarded */
} TxOutput;

typedef struct {
    TxType   type;
    char     from[ACCOUNT_ID_LEN];  /* LIBRARY for rewards                    */
    char     to[ACCOUNT_ID_LEN];    /* recipient; LIBRARY for fines; "-"      */
    long     amount;                /* coins sent / fine paid / reward total  */
    long     fee;                   /* fixed fee (per output for rewards)     */
    long     nonce;                 /* sender's account nonce; block index for rewards */
    time_t   timestamp;
    char     method[TX_METHOD_LEN]; /* FINE: TOKENS or CASH; otherwise "-"    */
    size_t   input_count;           /* 0 = inputs chosen when confirmed       */
    TxInput  inputs[TX_MAX_INPUTS];
    size_t   output_count;          /* REWARD only                            */
    TxOutput outputs[TX_MAX_OUTPUTS];
} Transaction;

void tx_clear(Transaction *tx);

void   tx_make_reward(Transaction *tx, long block_index, time_t timestamp);
Status tx_add_reward_output(Transaction *tx, const char *member_id, long gross,
                            const char *record_id);
void   tx_make_transfer(Transaction *tx, const char *from, const char *to,
                        long amount, long nonce, time_t timestamp);
void   tx_make_fine(Transaction *tx, const char *member_id, long amount, int pay_with_tokens,
                    long nonce, time_t timestamp);

/** 1 if the transaction changes balances (CASH fines and NONE do not). */
int  tx_moves_tokens(const Transaction *tx);

/** Coins the sender loses: amount + fee for transfers and token fines. */
long tx_sender_debit(const Transaction *tx);

/** Total fees in the transaction (paid to the miner). */
long tx_total_fees(const Transaction *tx);

/** Canonical text form. @return its length, or -1 if it does not fit. */
int    tx_serialize(const Transaction *tx, char *buf, size_t cap);
Status tx_parse(const char *text, Transaction *tx);

/** tx_id = SHA-256(serialised transaction), 64 hex characters. */
Status tx_compute_id(const Transaction *tx, char out[HASH_HEX_LEN]);

const char *tx_type_name(TxType type);

#endif /* LT_TRANSACTION_H */
