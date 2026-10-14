/**
 * @file ui.h
 * @brief Shared terminal output and input helpers for the command handlers.
 *
 * The ui/cli/cmd_* files only talk to the user. Every rule about what is
 * allowed lives in library.c, state.c, ledger/utxo/account.c, mining.c,
 * auth.c and blockchain.c.
 */
#ifndef LT_UI_H
#define LT_UI_H

#include <stddef.h>

#include "library.h"
#include "util.h"

#define INPUT_MAX 256

#if defined(__GNUC__)
#define PRINTF_LIKE(fmt_idx, arg_idx) __attribute__((format(printf, fmt_idx, arg_idx)))
#else
#define PRINTF_LIKE(fmt_idx, arg_idx)
#endif

/* ---- Messages --------------------------------------------------------------- */
void say_ok(const char *fmt, ...) PRINTF_LIKE(1, 2);
void say_err(const char *fmt, ...) PRINTF_LIKE(1, 2);
void say_warn(const char *fmt, ...) PRINTF_LIKE(1, 2);
void say_info(const char *fmt, ...) PRINTF_LIKE(1, 2);
void heading(const char *title);
void rule(char ch);

/** Prints "ERROR: <err>" (or the status text if err is empty). */
void report_failure(Status st, const char *err);

/* ---- Formatting --------------------------------------------------------------- */
const char *short_hash(const char *hash, char out[16]);      /* "a1b2c3d4e5.." */
const char *member_name(const Library *lib, const char *id);
Color       action_color(Action a);
void        format_day(time_t t, char out[16]);              /* YYYY-MM-DD or "-" */

/* ---- Input ---------------------------------------------------------------------- */

/** @return 1 = non-empty input, 0 = empty/invalid (reported), -1 = EOF. */
int prompt_text(const char *prompt, char *buf, size_t cap);

/** Reads an integer in [lo, hi]; empty input gives fallback if fallback >= lo. */
int prompt_long(const char *prompt, long lo, long hi, long fallback, long *out);

/** Reads and confirms a new password that meets the policy. */
int prompt_new_password(char *password, size_t cap);

/**
 * Returns argv[i] when the argument was typed on the command line,
 * otherwise asks for it. @return NULL on EOF or empty input.
 */
const char *arg_or_prompt(int argc, char **argv, int i, const char *prompt,
                          char *buf, size_t cap);

/** Checks a permission and prints ACCESS DENIED if it is missing. */
int require_perm(const Library *lib, Permission perm, const char *what);

/* ---- Shared views ---------------------------------------------------------------- */

/** One line describing a request that was just added to the pool. */
void print_request_added(const Library *lib, const Request *req);

/** The UTXO set (unspent outputs), optionally for one owner only. */
void print_utxo_set(const Library *lib, const char *owner, const char *indent);

/** Member balances in the session's model. */
void print_balances(const Library *lib, const char *only_member);

/** Lists requests discarded by pruning (if any). */
void print_rejections(const AssemblyReport *rep, const char *context);

#endif /* LT_UI_H */
