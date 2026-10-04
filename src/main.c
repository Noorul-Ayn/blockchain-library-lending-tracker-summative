/**
 * @file main.c
 * @brief Program entry point: start-up sequence and command-line options.
 *
 * Start-up order:
 *   1. load registries (books.txt, members.txt)    - abort if missing/empty
 *   2. load the chain and the pending pool          - abort if corrupted
 *   3. first-run setup (if needed) and login
 *   4. choose the ledger model; mine the genesis block on the first run
 *   5. replay the chain into the ledger, validate, then show the menu
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
#include "ledger.h"
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
    printf("Usage: %s [-d DATA_DIR] [-m utxo|account] [-D 1-4] [-h]\n\n", prog);
    printf("  -d, --data-dir DIR       folder with %s, %s and the chain (default: %s)\n",
           BOOKS_FILE, MEMBERS_FILE, DEFAULT_DATA_DIR);
    printf("  -m, --model MODEL        token ledger model: utxo or account\n");
    printf("                           (asked at start-up if not given)\n");
    printf("  -D, --difficulty N       proof-of-work difficulty 1-4 (default %d)\n",
           DEFAULT_DIFFICULTY);
    printf("  -h, --help               show this help\n\n");
    printf("Environment:\n");
    printf("  %s=SECONDS  loan period before a return is late (default 14 days)\n",
           LOAN_PERIOD_ENV);
    printf("  %s=N              fixed random seed for pool mining (reproducible runs)\n",
           SEED_ENV);
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

static int is_opt(const char *arg, const char *short_name, const char *long_name)
{
    return strcmp(arg, short_name) == 0 || strcmp(arg, long_name) == 0;
}

int main(int argc, char **argv)
{
    const char *data_dir = DEFAULT_DATA_DIR;
    LedgerModel model = MODEL_UTXO;
    int model_given = 0, difficulty = DEFAULT_DIFFICULTY;
    char err[256], period[48];
    int need_genesis = 0;
    Library lib;
    Status st;
    int i;

    for (i = 1; i < argc; i++) {
        if (is_opt(argv[i], "-h", "--help")) {
            usage(argv[0]);
            return EXIT_OK;
        }
        if (is_opt(argv[i], "-d", "--data-dir") && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (is_opt(argv[i], "-m", "--model") && i + 1 < argc) {
            if (ledger_parse_model(argv[++i], &model) != 0) {
                fprintf(stderr, "Invalid model '%s' (use utxo or account).\n", argv[i]);
                return EXIT_USAGE;
            }
            model_given = 1;
        } else if (is_opt(argv[i], "-D", "--difficulty") && i + 1 < argc) {
            char *end;
            long d = strtol(argv[++i], &end, 10);
            if (*end != '\0' || d < MIN_DIFFICULTY || d > MAX_DIFFICULTY) {
                fprintf(stderr, "Invalid difficulty '%s' (use %d-%d).\n", argv[i],
                        MIN_DIFFICULTY, MAX_DIFFICULTY);
                return EXIT_USAGE;
            }
            difficulty = (int)d;
        } else {
            fprintf(stderr, "Unknown or incomplete option '%s'.\n\n", argv[i]);
            usage(argv[0]);
            return EXIT_USAGE;
        }
    }

    color_init();
    rng_seed_from_env_or_time(SEED_ENV);
    ui_banner();
    if (library_init(&lib, data_dir, model) != LT_OK)
        return EXIT_OTHER;
    lib.loan_period = loan_period_from_env();
    lib.difficulty = difficulty;

    /* 1. Registries -------------------------------------------------------- */
    printf("[1/5] Loading registries from '%s/'...\n", data_dir);
    if (library_load_registries(&lib) != LT_OK) {
        fprintf(stderr, "Cannot continue without valid %s and %s files.\n",
                BOOKS_FILE, MEMBERS_FILE);
        library_free(&lib);
        return EXIT_REGISTRY;
    }
    printf("      Loaded %zu book(s) and %zu member(s).\n", lib.books.count, lib.members.count);

    /* 2. Chain + pending pool ---------------------------------------------- */
    printf("[2/5] Loading blockchain and pending pool...\n");
    st = library_load_state(&lib, &need_genesis, err, sizeof err);
    if (st != LT_OK) {
        fprintf(stderr, "ERROR: %s or %s is corrupted or unreadable (%s).\n"
                        "       Restore it from a backup, or delete it to start again.\n",
                CHAIN_FILE, PENDING_FILE, err);
        library_free(&lib);
        return EXIT_CHAIN;
    }
    if (need_genesis)
        printf("      No chain yet - a genesis block will be mined after login.\n");
    else
        printf("      Loaded %zu confirmed block(s) and %zu pending block(s).\n",
               lib.chain.length, lib.pending.length);

    /* 3. Authentication ---------------------------------------------------- */
    printf("[3/5] Authentication\n");
    if (!auth_has_users(data_dir) && !ui_first_run_setup(data_dir)) {
        library_free(&lib);
        return EXIT_AUTH;
    }
    if (!ui_login(data_dir, &lib.session)) {
        library_free(&lib);
        return EXIT_AUTH;
    }

    /* 4. Model + genesis ---------------------------------------------------- */
    printf("[4/5] Session settings\n");
    if (!model_given) {
        if (!ui_choose_model(&model)) {
            library_free(&lib);
            return EXIT_OK;
        }
        lib.ledger.model = model;
    } else {
        printf("      Transaction model: %s (from --model)\n", ledger_model_name(model));
    }
    printf("      Mining difficulty: %d\n", lib.difficulty);
    if (need_genesis) {
        st = chain_create_genesis(&lib.chain, &lib.session, lib.difficulty);
        if (st == LT_OK)
            st = storage_save_chain(lib.chain_path, &lib.chain);
        if (st != LT_OK) {
            fprintf(stderr, "ERROR: could not create the genesis block: %s.\n", status_str(st));
            library_free(&lib);
            return EXIT_OTHER;
        }
        printf("      Genesis block #0 mined (nonce %llu, hash %.16s...) and saved.\n",
               lib.chain.blocks[0].nonce, lib.chain.blocks[0].hash);
    }

    /* 5. Ledger + validation ----------------------------------------------- */
    printf("[5/5] Replaying the chain into the %s ledger and validating...\n",
           ledger_model_name(lib.ledger.model));
    (void)library_rebuild_ledger(&lib);
    ui_startup_validation(&lib);
    if (lib.loan_period != DEFAULT_LOAN_PERIOD_SECONDS) {
        format_duration(lib.loan_period, period, sizeof period);
        printf("INFO: loan period overridden to %s via %s.\n", period, LOAN_PERIOD_ENV);
    }

    ui_main_menu(&lib);
    library_free(&lib);
    return EXIT_OK;
}
