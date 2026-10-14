/**
 * @file main.c
 * @brief Program entry point: command-line options and the start-up sequence.
 *
 * Start-up order:
 *   1. load the registries (books.txt, copies.txt, members.txt) - abort if
 *      a file is missing or empty
 *   2. load chain.dat, pending.dat and the settings in state.dat
 *   3. first-run setup (administrator + key vault) and login
 *   4. generate key pairs for members that do not have one yet
 *   5. choose the ledger model; mine the genesis block on the first run
 *   6. command loop - validate_chain must pass before anything else
 *
 * Exit codes: 0 ok, 1 registry error, 2 chain file error,
 *             3 authentication failure, 4 other error, 64 bad usage.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"
#include "library.h"
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

typedef struct {
    const char *data_dir;
    LedgerModel model;
    int         model_given;
    long        difficulty, loan_days, renewal_days, max_renewals, max_loans, block_size;
} Options;

static void usage(const char *prog)
{
    printf("Usage: %s [options]\n\n", prog);
    printf("  -d, --data-dir DIR      folder with %s, %s, %s (default: %s)\n", BOOKS_FILE,
           COPIES_FILE, MEMBERS_FILE, DEFAULT_DATA_DIR);
    printf("  -m, --model MODEL       token ledger model: utxo or account (asked if not given)\n");
    printf("  -D, --difficulty N      proof-of-work difficulty %d-%d (default %d)\n",
           MIN_DIFFICULTY, MAX_DIFFICULTY, DEFAULT_DIFFICULTY);
    printf("      --loan-days N       loan period in days (default %d)\n", DEFAULT_LOAN_DAYS);
    printf("      --renewal-days N    renewal period in days (default %d)\n",
           DEFAULT_RENEWAL_DAYS);
    printf("      --max-renewals N    renewals allowed per loan (default %d)\n",
           DEFAULT_MAX_RENEWALS);
    printf("      --max-loans N       copies a member may hold before EXCESSIVE_BORROWS "
           "(default %d)\n", DEFAULT_MAX_LOANS);
    printf("      --block-size N      records per block, 1-%d (default %d)\n",
           MAX_BLOCK_CAPACITY, DEFAULT_BLOCK_CAPACITY);
    printf("  -h, --help              show this help\n\n");
    printf("Settings given here are saved in %s and reused next time.\n", STATE_FILE);
    printf("Environment: %s=N fixes the pool-mining random seed; NO_COLOR=1 disables colours.\n",
           SEED_ENV);
}

static int is_opt(const char *arg, const char *short_name, const char *long_name)
{
    return (short_name != NULL && strcmp(arg, short_name) == 0) || strcmp(arg, long_name) == 0;
}

static int number_opt(const char *name, const char *value, long lo, long hi, long *out)
{
    if (value == NULL || parse_long(value, lo, hi, out) != 0) {
        fprintf(stderr, "Invalid value for %s (use %ld-%ld).\n", name, lo, hi);
        return 0;
    }
    return 1;
}

/** @return 1 to continue, 0 to exit successfully, -1 on a usage error. */
static int parse_options(int argc, char **argv, Options *o)
{
    int i;

    memset(o, 0, sizeof *o);
    o->data_dir = DEFAULT_DATA_DIR;
    o->model = MODEL_UTXO;
    o->difficulty = o->loan_days = o->renewal_days = o->max_renewals = o->max_loans =
        o->block_size = -1;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        int ok = 1;

        if (is_opt(a, "-h", "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (v == NULL) {
            fprintf(stderr, "Option '%s' is unknown or needs a value.\n\n", a);
            usage(argv[0]);
            return -1;
        }
        if (is_opt(a, "-d", "--data-dir"))
            o->data_dir = v;
        else if (is_opt(a, "-m", "--model")) {
            ok = ledger_parse_model(v, &o->model) == 0;
            if (!ok)
                fprintf(stderr, "Invalid model '%s' (use utxo or account).\n", v);
            o->model_given = 1;
        } else if (is_opt(a, "-D", "--difficulty"))
            ok = number_opt(a, v, MIN_DIFFICULTY, MAX_DIFFICULTY, &o->difficulty);
        else if (is_opt(a, NULL, "--loan-days"))
            ok = number_opt(a, v, 1, MAX_LOAN_DAYS, &o->loan_days);
        else if (is_opt(a, NULL, "--renewal-days"))
            ok = number_opt(a, v, 1, 30, &o->renewal_days);
        else if (is_opt(a, NULL, "--max-renewals"))
            ok = number_opt(a, v, 0, 10, &o->max_renewals);
        else if (is_opt(a, NULL, "--max-loans"))
            ok = number_opt(a, v, 1, 50, &o->max_loans);
        else if (is_opt(a, NULL, "--block-size"))
            ok = number_opt(a, v, 1, MAX_BLOCK_CAPACITY, &o->block_size);
        else {
            fprintf(stderr, "Unknown option '%s'.\n\n", a);
            usage(argv[0]);
            return -1;
        }
        if (!ok)
            return -1;
        i++;
    }
    return 1;
}

/** Command-line settings override the ones saved in state.dat. */
static void apply_overrides(Library *lib, const Options *o)
{
    if (o->difficulty > 0)
        lib->difficulty = (int)o->difficulty;
    if (o->loan_days > 0)
        lib->rules.loan_days = (int)o->loan_days;
    if (o->renewal_days > 0)
        lib->rules.renewal_days = (int)o->renewal_days;
    if (o->max_renewals >= 0)
        lib->rules.max_renewals = (int)o->max_renewals;
    if (o->max_loans > 0)
        lib->rules.max_loans = (int)o->max_loans;
    if (o->block_size > 0)
        lib->block_capacity = (int)o->block_size;
}

int main(int argc, char **argv)
{
    Options opt;
    Library lib;
    char err[300];
    int needs_genesis = 0, r;
    size_t created = 0;
    Status st;

    r = parse_options(argc, argv, &opt);
    if (r <= 0)
        return r == 0 ? EXIT_OK : EXIT_USAGE;

    color_init();
    rng_seed_from_env_or_time(SEED_ENV);
    cli_banner();
    library_init(&lib, opt.data_dir);

    /* 1. Registries ------------------------------------------------------------ */
    printf("[1/6] Loading registries from '%s/'...\n", opt.data_dir);
    if (library_load_registries(&lib) != LT_OK) {
        fprintf(stderr, "Cannot continue without valid %s, %s and %s files.\n", BOOKS_FILE,
                COPIES_FILE, MEMBERS_FILE);
        library_free(&lib);
        return EXIT_REGISTRY;
    }
    printf("      %zu book(s), %zu cop(ies), %zu member(s).\n", lib.books.count,
           lib.copies.count, lib.members.count);

    /* 2. Chain, pool and saved settings ------------------------------------------ */
    printf("[2/6] Loading %s, %s and %s...\n", CHAIN_FILE, PENDING_FILE, STATE_FILE);
    st = library_load_files(&lib, &needs_genesis, err, sizeof err);
    if (st != LT_OK) {
        fprintf(stderr, "ERROR: %s or %s is corrupted or unreadable (%s).\n"
                        "       Restore it from a backup, or delete it to start a new chain.\n",
                CHAIN_FILE, PENDING_FILE, err[0] ? err : status_str(st));
        library_free(&lib);
        return EXIT_CHAIN;
    }
    apply_overrides(&lib, &opt);
    if (needs_genesis)
        printf("      No saved chain - a new chain with a genesis block will be created.\n");
    else
        printf("      Loaded %zu block(s) and %zu pending request(s) from disk.\n",
               lib.chain.length, lib.pool.count);

    /* 3. Authentication ---------------------------------------------------------- */
    printf("[3/6] Authentication\n");
    if (!auth_has_users(opt.data_dir) && !cli_first_run_setup(opt.data_dir)) {
        library_free(&lib);
        return EXIT_AUTH;
    }
    if (!cli_login(opt.data_dir, &lib.session)) {
        library_free(&lib);
        return EXIT_AUTH;
    }

    /* 4. Member key pairs -------------------------------------------------------- */
    printf("[4/6] Member keys\n");
    st = library_ensure_member_keys(&lib, &created);
    if (st != LT_OK) {
        say_err("Could not create member key pairs: %s.", status_str(st));
        library_free(&lib);
        return EXIT_OTHER;
    }
    if (created > 0)
        printf("      Generated ECDSA P-256 key pairs for %zu member(s) (private keys "
               "encrypted in the vault).\n", created);
    else
        printf("      All %zu member(s) have an ECDSA P-256 key pair.\n", lib.members.count);

    /* 5. Model and genesis --------------------------------------------------------- */
    printf("[5/6] Session settings\n");
    if (!opt.model_given) {
        if (!cli_choose_model(&opt.model)) {
            library_free(&lib);
            return EXIT_OK;
        }
    } else {
        printf("      Transaction model: %s (from --model)\n", ledger_model_name(opt.model));
    }
    lib.model = opt.model;
    printf("      Difficulty %d | %d records per block | loan %d days | renewal +%d days "
           "(max %d) | max %d loans\n", lib.difficulty, lib.block_capacity, lib.rules.loan_days,
           lib.rules.renewal_days, lib.rules.max_renewals, lib.rules.max_loans);
    if (needs_genesis) {
        st = library_create_genesis(&lib);
        if (st != LT_OK) {
            say_err("Could not create the genesis block: %s.", status_str(st));
            library_free(&lib);
            return EXIT_OTHER;
        }
        printf("      Genesis block #0 mined at difficulty %d (nonce %llu, hash %.16s...) and "
               "saved.\n", lib.chain.blocks[0].difficulty, lib.chain.blocks[0].nonce,
               lib.chain.blocks[0].hash);
    }

    /* 6. Validation gate ------------------------------------------------------------ */
    printf("[6/6] %s: run %svalidate_chain%s before any other operation.\n",
           needs_genesis ? "A new chain was created" : "The chain was read from disk",
           clr(CLR_BOLD), clr(CLR_RESET));
    cli_run(&lib);
    library_free(&lib);
    return EXIT_OK;
}
