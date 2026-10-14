/**
 * @file cli.h
 * @brief The command-line interface: start-up dialogs and the command loop.
 *
 * The loop reads one command per line ("library> borrow_book BK001 ALU001"),
 * enforces the session rules and dispatches to the handlers in commands.h:
 *   - after the chain is loaded from disk, only help / validate_chain /
 *     whoami / exit are accepted until validate_chain has passed;
 *   - if validation failed, the session is read-only;
 *   - overdue detection runs automatically before every command.
 */
#ifndef LT_CLI_H
#define LT_CLI_H

#include "auth.h"
#include "ledger.h"
#include "library.h"

void cli_banner(void);

/** First run: creates the administrator account and the member key vault. */
int cli_first_run_setup(const char *data_dir);

/** Up to three login attempts. @return 1 when logged in. */
int cli_login(const char *data_dir, Session *session);

/** Asks for the UTXO or account model. @return 0 on EOF. */
int cli_choose_model(LedgerModel *model);

/** Runs the command loop until exit / EOF; saves on exit. */
void cli_run(Library *lib);

#endif /* LT_CLI_H */
