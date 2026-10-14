/**
 * @file commands.h
 * @brief Handlers for every CLI command (see cli.c for the command table).
 *
 * Each handler receives the command words: argv[0] is the command name and
 * argv[1..] its arguments. A missing argument is asked for interactively,
 * so both "borrow_book BK001 ALU001" and plain "borrow_book" work.
 */
#ifndef LT_COMMANDS_H
#define LT_COMMANDS_H

#include "library.h"

typedef void (*CommandFn)(Library *lib, int argc, char **argv);

/* ---- Membership, books and copies (cmd_lending.c) ------------------------ */
void cmd_register_member(Library *lib, int argc, char **argv);
void cmd_view_member(Library *lib, int argc, char **argv);
void cmd_member_nonce(Library *lib, int argc, char **argv);
void cmd_register_book(Library *lib, int argc, char **argv);
void cmd_view_book(Library *lib, int argc, char **argv);
void cmd_add_copy(Library *lib, int argc, char **argv);
void cmd_view_copy(Library *lib, int argc, char **argv);
void cmd_mark_lost(Library *lib, int argc, char **argv);

/* ---- Lending, fines and overdue (cmd_lending.c) -------------------------- */
void cmd_borrow_book(Library *lib, int argc, char **argv);
void cmd_return_book(Library *lib, int argc, char **argv);
void cmd_renew_book(Library *lib, int argc, char **argv);
void cmd_reserve_book(Library *lib, int argc, char **argv);
void cmd_reservation_status(Library *lib, int argc, char **argv);
void cmd_check_overdue(Library *lib, int argc, char **argv);
void cmd_view_fines(Library *lib, int argc, char **argv);
void cmd_settle_fine(Library *lib, int argc, char **argv);

/** Automatic overdue detection (run before every command). */
void run_overdue_scan(Library *lib, int verbose);

/* ---- Tokens and ledgers (cmd_ledger.c) ------------------------------------ */
void cmd_token_transfer(Library *lib, int argc, char **argv);
void cmd_token_balance(Library *lib, int argc, char **argv);
void cmd_utxo_view(Library *lib, int argc, char **argv);
void cmd_account_balance(Library *lib, int argc, char **argv);
void cmd_account_transfer(Library *lib, int argc, char **argv);
void cmd_account_nonce(Library *lib, int argc, char **argv);
void cmd_transaction_history(Library *lib, int argc, char **argv);

/* ---- Blockchain and mining (cmd_chain.c) ---------------------------------- */
void cmd_pool_view(Library *lib, int argc, char **argv);
void cmd_mine_solo(Library *lib, int argc, char **argv);
void cmd_mine_pool(Library *lib, int argc, char **argv);
void cmd_mine_cloud(Library *lib, int argc, char **argv);
void cmd_chain_view(Library *lib, int argc, char **argv);
void cmd_validate_chain(Library *lib, int argc, char **argv);
void cmd_chain_save(Library *lib, int argc, char **argv);
void cmd_chain_load(Library *lib, int argc, char **argv);
void cmd_difficulty_status(Library *lib, int argc, char **argv);
void cmd_set_difficulty(Library *lib, int argc, char **argv);
void cmd_difficulty_benchmark(Library *lib, int argc, char **argv);
void cmd_merkle_tree(Library *lib, int argc, char **argv);
void cmd_merkle_proof(Library *lib, int argc, char **argv);
void cmd_tamper_demo(Library *lib, int argc, char **argv);

/* ---- Fraud review and audit (cmd_audit.c) ---------------------------------- */
void cmd_fraud_review(Library *lib, int argc, char **argv);
void cmd_approve_suspicious(Library *lib, int argc, char **argv);
void cmd_reject_suspicious(Library *lib, int argc, char **argv);
void cmd_replay_request(Library *lib, int argc, char **argv);
void cmd_lending_history(Library *lib, int argc, char **argv);
void cmd_member_history(Library *lib, int argc, char **argv);
void cmd_book_history(Library *lib, int argc, char **argv);

/* ---- Session and administration (cli.c) ------------------------------------- */
void cmd_whoami(Library *lib, int argc, char **argv);
void cmd_add_user(Library *lib, int argc, char **argv);
void cmd_advance_clock(Library *lib, int argc, char **argv);

/** Shared by validate_chain, chain_load and tamper_demo. @return 1 if valid. */
int print_validation(Library *lib);

/** Prints one confirmed record as a table row (used by the history views). */
void print_record_row(const Library *lib, const Record *rec, long block_index);
void print_record_header(void);

#endif /* LT_COMMANDS_H */
