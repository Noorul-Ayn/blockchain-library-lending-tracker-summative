/**
 * @file ui.h
 * @brief Command-line interface: setup wizard, login, model selection and
 *        the main menu.
 */
#ifndef LT_UI_H
#define LT_UI_H

#include "auth.h"
#include "ledger.h"
#include "lending.h"

void ui_banner(void);

/** First run only: creates the administrator account. @return 1 on success. */
int ui_first_run_setup(const char *data_dir);

/** Up to three login attempts. @return 1 when logged in, 0 otherwise. */
int ui_login(const char *data_dir, Session *session);

/** Asks which ledger model this session uses. @return 1 ok, 0 end of input. */
int ui_choose_model(LedgerModel *model);

/** Prints a one-line validation summary (used at start-up). */
void ui_startup_validation(Library *lib);

/** Runs the interactive menu until the user logs out or input ends. */
void ui_main_menu(Library *lib);

#endif /* LT_UI_H */
