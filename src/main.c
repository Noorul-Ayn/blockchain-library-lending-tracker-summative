/**
 * @file main.c
 * @brief Program entry point: start-up sequence and command-line options.
 *
 * Start-up order:
 *   1. load registries (books.txt, members.txt)   - abort if missing/empty
 *   2. load the blockchain from chain.dat          - abort if corrupted
 *   3. first-run setup (if needed) and login
 *   4. create the genesis block (first run only)
 *   5. validate the whole chain, then show the menu
 *
 * Exit codes: 0 ok, 1 registry error, 2 chain file error,
 *             3 authentication failure, 4 other error, 64 bad usage.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "blockchain.h"
#include "lending.h"
#include "storage.h"
#include "ui.h"
#include "util.h"

enum {
    EXIT_OK = 0,
    EXIT_REGISTRY = 1,
    EXIT_CHAIN = 2,
    EXIT_AUTH = 3,
    EXIT_OTHER = 4,
    EXIT_USAGE = 64
};

static void usage(const char *prog)
{
    printf("Usage: %s [-d DATA_DIR] [-h]\n\n", prog);
    printf("  -d, --data-dir DIR   folder holding %s, %s and the chain (default: %s)\n",
           BOOKS_FILE, MEMBERS_FILE, DEFAULT_DATA_DIR);
    printf("  -h, --help           show this help\n\n");
    printf("Environment:\n");
    printf("  %s=SECONDS  loan period before a loan is overdue (default 14 days)\n",
           LOAN_PERIOD_ENV);
    printf("  NO_COLOR=1                   disable coloured output\n");
}

static long loan_period_from_env(void)
{
    const char *value = getenv(LOAN_PERIOD_ENV);
    char *end;
    long seconds;

    if (value == NULL || value[0] == '\0')
        return DEFAULT_LOAN_PERIOD_SECONDS;
    errno = 0;
    seconds = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || seconds <= 0) {
        fprintf(stderr, "WARNING: ignoring invalid %s='%s' (must be a positive number of "
                        "seconds).\n", LOAN_PERIOD_ENV, value);
        return DEFAULT_LOAN_PERIOD_SECONDS;
    }
    return seconds;
}

int main(int argc, char **argv)
{
    const char *data_dir = DEFAULT_DATA_DIR;
    char err[256], period[48];
    int need_genesis = 0;
    Library lib;
    Status st;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_OK;
        }
        if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--data-dir") == 0) && i + 1 < argc) {
            data_dir = argv[++i];
            continue;
        }
        fprintf(stderr, "Unknown or incomplete option '%s'.\n\n", argv[i]);
        usage(argv[0]);
        return EXIT_USAGE;
    }

    color_init();
    ui_banner();
    if (library_init(&lib, data_dir) != LT_OK)
        return EXIT_OTHER;
    lib.loan_period = loan_period_from_env();

    /* 1. Registries ------------------------------------------------------- */
    printf("[1/4] Loading registries from '%s/'...\n", data_dir);
    if (library_load_registries(&lib) != LT_OK) {
        fprintf(stderr, "Cannot continue without valid %s and %s files.\n",
                BOOKS_FILE, MEMBERS_FILE);
        library_free(&lib);
        return EXIT_REGISTRY;
    }
    printf("      Loaded %zu book(s) and %zu member(s).\n", lib.books.count, lib.members.count);

    /* 2. Blockchain ------------------------------------------------------- */
    printf("[2/4] Loading blockchain from '%s'...\n", lib.chain_path);
    st = storage_load_chain(lib.chain_path, &lib.chain, err, sizeof err);
    if (st == LT_ERR_NOT_FOUND) {
        need_genesis = 1;
        printf("      No chain file yet - a genesis block will be created after login.\n");
    } else if (st != LT_OK) {
        fprintf(stderr, "ERROR: %s is corrupted or unreadable (%s).\n"
                        "       The file must not be edited by hand. Restore it from a "
                        "backup, or delete it to start a new chain.\n", CHAIN_FILE, err);
        library_free(&lib);
        return EXIT_CHAIN;
    } else {
        printf("      Loaded %zu block(s).\n", lib.chain.length);
    }

    /* 3. Authentication --------------------------------------------------- */
    printf("[3/4] Authentication\n");
    if (!auth_has_users(data_dir) && !ui_first_run_setup(data_dir)) {
        library_free(&lib);
        return EXIT_AUTH;
    }
    if (!ui_login(data_dir, &lib.session)) {
        library_free(&lib);
        return EXIT_AUTH;
    }

    /* 4. Genesis block + validation --------------------------------------- */
    if (need_genesis) {
        st = chain_create_genesis(&lib.chain, &lib.session);
        if (st == LT_OK)
            st = storage_save_chain(lib.chain_path, &lib.chain);
        if (st != LT_OK) {
            fprintf(stderr, "ERROR: could not create the genesis block: %s.\n", status_str(st));
            library_free(&lib);
            return EXIT_OTHER;
        }
        printf("      Genesis block #0 created (previous_hash = 64 zeros) and saved.\n");
    }
    printf("[4/4] Validating blockchain...\n");
    ui_startup_validation(&lib);
    if (lib.loan_period != DEFAULT_LOAN_PERIOD_SECONDS) {
        format_duration(lib.loan_period, period, sizeof period);
        printf("INFO: loan period overridden to %s via %s.\n", period, LOAN_PERIOD_ENV);
    }

    ui_main_menu(&lib);
    library_free(&lib);
    return EXIT_OK;
}
