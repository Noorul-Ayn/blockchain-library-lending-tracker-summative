/**
 * @file cli.c
 * @brief Start-up dialogs (setup, login, model), the command table and the
 *        command loop with validation gating and automatic overdue scans.
 */
#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "commands.h"
#include "crypto.h"
#include "keystore.h"
#include "ui.h"

#define MAX_LOGIN_ATTEMPTS 3
#define MAX_SETUP_ATTEMPTS 5
#define MAX_WORDS          16
#define LINE_MAX_CLI       1024

/* Command flags */
#define CMD_BEFORE_VALIDATION 0x1   /* allowed before validate_chain has passed */
#define CMD_WRITES            0x2   /* changes the pool / chain: blocked when invalid */

typedef struct {
    const char *name;
    CommandFn   fn;
    const char *group;
    const char *usage;
    const char *help;
    unsigned    flags;
} Command;

static void cmd_help(Library *lib, int argc, char **argv);

static const Command COMMANDS[] = {
    /* Membership */
    { "register_member", cmd_register_member, "Membership",
      "register_member [id] [\"full name\"] [course]", "register a member (+ ECDSA key pair)", CMD_WRITES },
    { "view_member", cmd_view_member, "Membership",
      "view_member [member_id]", "list members, or one member's loans, fines and key", 0 },
    { "member_nonce", cmd_member_nonce, "Membership",
      "member_nonce <member_id>", "request nonce used for replay protection", 0 },
    /* Books and copies */
    { "register_book", cmd_register_book, "Books and copies",
      "register_book [id] [\"title\"] [\"author\"] [copies]", "register a title and its copies", CMD_WRITES },
    { "view_book", cmd_view_book, "Books and copies",
      "view_book [book_id]", "catalogue with copy availability", 0 },
    { "add_copy", cmd_add_copy, "Books and copies",
      "add_copy <book_id> [NEW|GOOD|WORN] [copy_id]", "add a physical copy of a title", CMD_WRITES },
    { "view_copy", cmd_view_copy, "Books and copies",
      "view_copy [copy_id]", "copy inventory: condition, state, holder, due date", 0 },
    { "mark_lost", cmd_mark_lost, "Books and copies",
      "mark_lost <copy_id> <REASON_CODE>", "librarian override: copy -> LOST", CMD_WRITES },
    /* Lending */
    { "borrow_book", cmd_borrow_book, "Lending",
      "borrow_book <book_id|copy_id> <member_id> [YYYY-MM-DD]", "signed BORROW request", CMD_WRITES },
    { "return_book", cmd_return_book, "Lending",
      "return_book <copy_id> [NEW|GOOD|WORN] [REASON_CODE]", "signed RETURN request (fine/reward)", CMD_WRITES },
    { "renew_book", cmd_renew_book, "Lending",
      "renew_book <copy_id>", "extend the due date by the renewal period", CMD_WRITES },
    { "reserve_book", cmd_reserve_book, "Lending",
      "reserve_book <book_id> <member_id>", "join the FIFO queue of a title", CMD_WRITES },
    { "reservation_status", cmd_reservation_status, "Lending",
      "reservation_status [book_id]", "queues and copies held for members", 0 },
    /* Fines and overdue */
    { "check_overdue", cmd_check_overdue, "Fines and overdue",
      "check_overdue", "scan BORROWED copies, flag OVERDUE, show fines", CMD_WRITES },
    { "view_fines", cmd_view_fines, "Fines and overdue",
      "view_fines [member_id]", "assessed, paid, outstanding and accruing fines", 0 },
    { "settle_fine", cmd_settle_fine, "Fines and overdue",
      "settle_fine <member_id> [amount|all] [tokens|cash]", "pay a fine", CMD_WRITES },
    /* Tokens and ledgers */
    { "token_transfer", cmd_token_transfer, "Tokens and ledgers",
      "token_transfer <from> <to> <amount> [txid:vout,...]", "transfer in the session's model", CMD_WRITES },
    { "token_balance", cmd_token_balance, "Tokens and ledgers",
      "token_balance [member_id]", "confirmed balances", 0 },
    { "utxo_view", cmd_utxo_view, "Tokens and ledgers",
      "utxo_view [member_id]", "the UTXO set (UTXO model)", 0 },
    { "account_balance", cmd_account_balance, "Tokens and ledgers",
      "account_balance [member_id]", "account balances and nonces (account model)", 0 },
    { "account_transfer", cmd_account_transfer, "Tokens and ledgers",
      "account_transfer <from> <to> <amount> [nonce]", "transfer with an explicit nonce", CMD_WRITES },
    { "account_nonce", cmd_account_nonce, "Tokens and ledgers",
      "account_nonce [member_id]", "confirmed and next account nonces", 0 },
    { "transaction_history", cmd_transaction_history, "Tokens and ledgers",
      "transaction_history <member_id>", "per-member linked-list history", 0 },
    /* Blockchain and mining */
    { "pool_view", cmd_pool_view, "Blockchain and mining",
      "pool_view", "prioritised pending pool and the next blocks", 0 },
    { "mine_solo", cmd_mine_solo, "Blockchain and mining",
      "mine_solo [blocks]", "one miner confirms the pool", CMD_WRITES },
    { "mine_pool", cmd_mine_pool, "Blockchain and mining",
      "mine_pool [miners 2-8] [blocks]", "pool mining with reward sharing", CMD_WRITES },
    { "mine_cloud", cmd_mine_cloud, "Blockchain and mining",
      "mine_cloud <rounds 1-5>", "rented hash power, earnings per round", CMD_WRITES },
    { "chain_view", cmd_chain_view, "Blockchain and mining",
      "chain_view [block_index]", "all blocks, or every field of one block", 0 },
    { "validate_chain", cmd_validate_chain, "Blockchain and mining",
      "validate_chain", "full verification (required after loading)", CMD_BEFORE_VALIDATION },
    { "chain_save", cmd_chain_save, "Blockchain and mining",
      "chain_save", "write chain.dat, pending.dat, state.dat", 0 },
    { "chain_load", cmd_chain_load, "Blockchain and mining",
      "chain_load", "reload from disk (then validate_chain)", CMD_BEFORE_VALIDATION },
    { "difficulty_status", cmd_difficulty_status, "Blockchain and mining",
      "difficulty_status", "current proof-of-work difficulty", 0 },
    { "set_difficulty", cmd_set_difficulty, "Blockchain and mining",
      "set_difficulty <1-4>", "change the difficulty", CMD_WRITES },
    { "difficulty_benchmark", cmd_difficulty_benchmark, "Blockchain and mining",
      "difficulty_benchmark [trials]", "average attempts at difficulty 1-4", 0 },
    { "merkle_tree", cmd_merkle_tree, "Blockchain and mining",
      "merkle_tree <block_index>", "show a block's Merkle tree", 0 },
    { "merkle_proof", cmd_merkle_proof, "Blockchain and mining",
      "merkle_proof <block_index> <record_id>", "inclusion proof for one record", 0 },
    /* Fraud and audit */
    { "fraud_review", cmd_fraud_review, "Fraud and audit",
      "fraud_review", "SUSPICIOUS requests and why they were flagged", 0 },
    { "approve_suspicious", cmd_approve_suspicious, "Fraud and audit",
      "approve_suspicious <id>", "admin: allow a flagged request to be mined", CMD_WRITES },
    { "reject_suspicious", cmd_reject_suspicious, "Fraud and audit",
      "reject_suspicious <id>", "admin: discard a flagged request", CMD_WRITES },
    { "lending_history", cmd_lending_history, "Fraud and audit",
      "lending_history", "every confirmed record", 0 },
    { "member_history", cmd_member_history, "Fraud and audit",
      "member_history <member_id>", "a member's confirmed records", 0 },
    { "book_history", cmd_book_history, "Fraud and audit",
      "book_history <book_id|copy_id>", "a title's or copy's confirmed records", 0 },
    { "tamper_demo", cmd_tamper_demo, "Fraud and audit",
      "tamper_demo", "admin: edit history in memory, watch validation fail", CMD_WRITES },
    { "replay_request", cmd_replay_request, "Fraud and audit",
      "replay_request <record_id>", "admin: re-submit a confirmed record", CMD_WRITES },
    /* Session */
    { "whoami", cmd_whoami, "Session and administration",
      "whoami", "user, role, model, clock and chain status", CMD_BEFORE_VALIDATION },
    { "add_user", cmd_add_user, "Session and administration",
      "add_user", "admin: create a librarian or admin account", CMD_WRITES },
    { "advance_clock", cmd_advance_clock, "Session and administration",
      "advance_clock <days>", "admin: move the library clock forward (demo)", CMD_WRITES },
    { "help", cmd_help, "Session and administration",
      "help [command]", "this list", CMD_BEFORE_VALIDATION },
    { "exit", NULL, "Session and administration",
      "exit", "save, log out and quit (also: quit, logout)", CMD_BEFORE_VALIDATION },
};

#define COMMAND_COUNT (sizeof COMMANDS / sizeof COMMANDS[0])

static const Command *find_command(const char *name)
{
    size_t i;

    if (strcasecmp(name, "quit") == 0 || strcasecmp(name, "logout") == 0)
        name = "exit";
    for (i = 0; i < COMMAND_COUNT; i++)
        if (strcasecmp(COMMANDS[i].name, name) == 0)
            return &COMMANDS[i];
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* Built-in commands                                                        */
/* ------------------------------------------------------------------------ */

static void cmd_help(Library *lib, int argc, char **argv)
{
    const char *group = NULL;
    size_t i;

    (void)lib;
    if (argc > 1) {
        const Command *c = find_command(argv[1]);
        if (c == NULL) {
            say_err("Unknown command '%s'.", argv[1]);
            return;
        }
        printf("\n  %s\n      %s\n", c->usage, c->help);
        printf("      Missing arguments are asked for. Quote values with spaces: \"Jane Doe\".\n");
        return;
    }
    heading("COMMANDS");
    for (i = 0; i < COMMAND_COUNT; i++) {
        if (group == NULL || strcmp(group, COMMANDS[i].group) != 0) {
            group = COMMANDS[i].group;
            printf("\n %s%s%s\n", clr(CLR_BOLD), group, clr(CLR_RESET));
        }
        printf("   %-58s %s\n", COMMANDS[i].usage, COMMANDS[i].help);
    }
    printf("\nArguments in <> are required (asked for if missing), [] are optional.\n");
}

void cmd_whoami(Library *lib, int argc, char **argv)
{
    char today[16];

    (void)argc;
    (void)argv;
    heading("SESSION");
    format_day(lib_now(), today);
    printf("User         : %s [%s] - signer ID staff:%s\n", lib->session.username,
           auth_role_name(lib->session.role), lib->session.username);
    printf("Key vault    : %s\n", lib->session.vault_unlocked ? "unlocked (member keys available "
                                                                 "for signing)" : "locked");
    printf("Model        : %s (all token transactions this session)\n",
           ledger_model_name(lib->model));
    printf("Difficulty   : %d | block reward %ld | %d records per block\n", lib->difficulty,
           lib->block_reward, lib->block_capacity);
    printf("Rules        : loan %d days, renewal +%d days (max %d), max %d copies per member, "
           "fine %d/day\n", lib->rules.loan_days, lib->rules.renewal_days,
           lib->rules.max_renewals, lib->rules.max_loans, FINE_PER_DAY);
    printf("Library date : %s%s\n", today, clock_offset() ? " (clock advanced for the demo)" : "");
    printf("Chain        : %zu block(s), %s\n", lib->chain.length,
           !lib->validated ? "NOT VALIDATED YET" : lib->chain_ok ? "VALID" : "INVALID (read-only)");
    printf("Pending pool : %zu request(s), %zu SUSPICIOUS\n", lib->pool.count,
           pool_count_status(&lib->pool, REQ_SUSPICIOUS));
}

void cmd_add_user(Library *lib, int argc, char **argv)
{
    char b1[INPUT_MAX], role_text[INPUT_MAX], password[INPUT_MAX], signer[SIGNER_ID_LEN];
    const char *username;
    Role role;
    Status st;

    heading("ADD STAFF ACCOUNT");
    if (!require_perm(lib, PERM_MANAGE_USERS, "add_user"))
        return;
    if ((username = arg_or_prompt(argc, argv, 1, "New username (3-19 letters/digits/_): ", b1,
                                  sizeof b1)) == NULL)
        return;
    if (!auth_valid_username(username)) {
        say_err("Invalid username. Use 3-19 letters, digits or underscores.");
        return;
    }
    if (prompt_text("Role [1 = LIBRARIAN, 2 = ADMIN]: ", role_text, sizeof role_text) != 1)
        return;
    if (strcmp(role_text, "1") == 0 || strcasecmp(role_text, "librarian") == 0) {
        role = ROLE_LIBRARIAN;
    } else if (strcmp(role_text, "2") == 0 || strcasecmp(role_text, "admin") == 0) {
        role = ROLE_ADMIN;
    } else {
        say_err("Invalid role.");
        return;
    }
    if (prompt_new_password(password, sizeof password) != 1)
        return;
    printf("Generating an ECDSA P-256 key pair and hashing the password (PBKDF2, %d "
           "iterations)...\n", PBKDF2_ITERATIONS);
    st = auth_create_user(lib->data_dir, username, password, role, lib->session.vault_key);
    crypto_wipe(password, sizeof password);
    if (st == LT_OK) {
        signer_id_for_staff(username, signer);
        keydir_forget(&lib->keys, signer);
        say_ok("User '%s' created with role %s. Signing key %s/%s/%s.key (encrypted); the "
               "member key vault was wrapped for this user.", username, auth_role_name(role),
               lib->data_dir, KEYS_DIR, username);
    } else if (st == LT_ERR_EXISTS) {
        say_err("A user named '%s' already exists.", username);
    } else {
        say_err("Could not create the account: %s.", status_str(st));
    }
}

void cmd_advance_clock(Library *lib, int argc, char **argv)
{
    char buf[INPUT_MAX], today[16];
    const char *text;
    long days;

    heading("ADVANCE LIBRARY CLOCK");
    if (!require_perm(lib, PERM_ADMIN_TOOLS, "advance_clock"))
        return;
    if ((text = arg_or_prompt(argc, argv, 1, "Days to move forward (1-365): ", buf,
                              sizeof buf)) == NULL)
        return;
    if (parse_long(text, 1, 365, &days) != 0) {
        say_err("Give a whole number of days from 1 to 365 (the clock never moves back).");
        return;
    }
    clock_set_offset(clock_offset() + days * DAY_SECONDS);
    (void)library_save_state(lib);
    format_day(lib_now(), today);
    say_ok("Library clock moved forward %ld day(s): today is now %s (offset saved in %s).",
           days, today, STATE_FILE);
    printf("         Real time is unchanged; due dates, fines and block timestamps use this "
           "clock.\n");
    run_overdue_scan(lib, 1);
}

/* ------------------------------------------------------------------------ */
/* Start-up                                                                 */
/* ------------------------------------------------------------------------ */

void cli_banner(void)
{
    putchar('\n');
    rule('=');
    printf("%s   BLOCKCHAIN LIBRARY LENDING TRACKER  -  summative edition%s\n", clr(CLR_BOLD),
           clr(CLR_RESET));
    printf("   copies & reservations | Merkle trees | ECDSA P-256 member keys | PoW mining\n");
    printf("   UTXO & account ledgers | replay protection | fraud review | disk persistence\n");
    rule('=');
}

int cli_first_run_setup(const char *data_dir)
{
    char username[INPUT_MAX], password[INPUT_MAX];
    unsigned char vault[VAULT_KEY_LEN];
    int attempt;

    heading("FIRST-RUN SETUP");
    puts("No staff accounts exist yet. Create the ADMINISTRATOR account now.");
    puts("  - a personal ECDSA P-256 key pair is generated; its private key is stored");
    puts("    encrypted (PKCS#8, AES-256) with your password;");
    puts("  - a random 256-bit key-vault key is generated; it encrypts every member's private");
    puts("    key and is itself stored only wrapped with your password (PBKDF2 + AES-256-GCM).\n");

    if (vault_generate(vault) != LT_OK) {
        say_err("Could not generate the vault key.");
        return 0;
    }
    for (attempt = 0; attempt < MAX_SETUP_ATTEMPTS; attempt++) {
        int r = prompt_text("Admin username (3-19 letters/digits/_): ", username, sizeof username);
        Status st;

        if (r < 0)
            break;
        if (r == 0 || !auth_valid_username(username)) {
            say_err("Invalid username. Use 3-19 letters, digits or underscores.");
            continue;
        }
        r = prompt_new_password(password, sizeof password);
        if (r < 0)
            break;
        if (r == 0)
            continue;
        printf("Generating keys and hashing the password (PBKDF2, %d iterations)...\n",
               PBKDF2_ITERATIONS);
        st = auth_create_user(data_dir, username, password, ROLE_ADMIN, vault);
        crypto_wipe(password, sizeof password);
        if (st == LT_OK) {
            crypto_wipe(vault, sizeof vault);
            say_ok("Administrator '%s' created. Keys are in %s/%s/.", username, data_dir, KEYS_DIR);
            return 1;
        }
        say_err("Could not create the account: %s.", status_str(st));
    }
    crypto_wipe(vault, sizeof vault);
    say_err("Setup was not completed.");
    return 0;
}

int cli_login(const char *data_dir, Session *session)
{
    char username[INPUT_MAX], password[INPUT_MAX];
    int attempt;

    heading("LOGIN");
    for (attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
        Status st;
        int r = prompt_text("Username: ", username, sizeof username);

        if (r < 0)
            return 0;
        if (read_secret("Password: ", password, sizeof password) != INPUT_OK)
            return 0;
        st = auth_login(data_dir, username, password, session);
        crypto_wipe(password, sizeof password);
        if (st == LT_OK) {
            say_ok("Logged in as %s [%s]. Signing key unlocked and verified; member key vault "
                   "unlocked.", session->username, auth_role_name(session->role));
            return 1;
        }
        if (st == LT_ERR_CRYPTO)
            say_err("Password accepted but a key could not be unlocked or does not match "
                    "(attempt %d/%d).", attempt, MAX_LOGIN_ATTEMPTS);
        else
            say_err("Invalid username or password (attempt %d/%d).", attempt, MAX_LOGIN_ATTEMPTS);
        if (attempt < MAX_LOGIN_ATTEMPTS)
            sleep(1);
    }
    say_err("Too many failed login attempts. Exiting.");
    return 0;
}

int cli_choose_model(LedgerModel *model)
{
    char input[INPUT_MAX];

    heading("TRANSACTION MODEL");
    puts("Choose how member token balances are managed for this session:");
    puts("  1. UTXO model          - coins are unspent outputs; spending uses inputs + change");
    puts("  2. Account-based model - each member has a balance, a nonce and a history list");
    for (;;) {
        int r = prompt_text("Model [1/2]: ", input, sizeof input);
        if (r < 0)
            return 0;
        if (r == 1 && ledger_parse_model(input, model) == 0) {
            say_ok("Using the %s model for every token transaction in this session.",
                   ledger_model_name(*model));
            return 1;
        }
        say_err("Enter 1 (UTXO) or 2 (account-based).");
    }
}

/* ------------------------------------------------------------------------ */
/* Command loop                                                             */
/* ------------------------------------------------------------------------ */

static void suggest(const char *word)
{
    size_t i, n = 0;

    for (i = 0; i < COMMAND_COUNT; i++) {
        if (strstr(COMMANDS[i].name, word) != NULL ||
            strncasecmp(COMMANDS[i].name, word, 4) == 0) {
            printf("%s%s", n++ ? ", " : "         Did you mean: ", COMMANDS[i].name);
        }
    }
    if (n > 0)
        putchar('\n');
}

static void save_on_exit(Library *lib)
{
    Status st;

    if (!lib->validated) {
        say_info("The chain was not validated in this session - nothing was written.");
        return;
    }
    if (!lib->chain_ok) {
        say_info("The chain failed validation - nothing was written; the files on disk are "
                 "left as they are for investigation.");
        return;
    }
    st = library_save_all(lib);
    if (st == LT_OK)
        say_ok("Saved %zu block(s), %zu pending request(s) and the library state to %s/.",
               lib->chain.length, lib->pool.count, lib->data_dir);
    else
        say_err("Could not save: %s.", status_str(st));
}

void cli_run(Library *lib)
{
    char line[LINE_MAX_CLI];

    printf("\nType %shelp%s for the command list.\n", clr(CLR_BOLD), clr(CLR_RESET));
    for (;;) {
        char *words[MAX_WORDS], *trimmed;
        const Command *cmd;
        size_t count;
        InputResult r = read_line("\nlibrary> ", line, sizeof line);

        if (r == INPUT_EOF) {
            puts("\nEnd of input.");
            break;
        }
        if (r == INPUT_TOO_LONG) {
            say_err("The command line is too long.");
            continue;
        }
        trimmed = str_trim(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#')
            continue;
        count = split_args(trimmed, words, MAX_WORDS);
        if (count > MAX_WORDS)
            count = MAX_WORDS;
        if (count == 0)
            continue;
        cmd = find_command(words[0]);
        if (cmd == NULL) {
            say_err("Unknown command '%s'. Type help for the list.", words[0]);
            suggest(words[0]);
            continue;
        }
        if (cmd->fn == NULL)
            break;                                       /* exit */
        if (!lib->validated && !(cmd->flags & CMD_BEFORE_VALIDATION)) {
            say_err("The chain was loaded from disk and has not been validated in this "
                    "session. Run validate_chain before any other operation.");
            continue;
        }
        if (lib->validated && !lib->chain_ok && (cmd->flags & CMD_WRITES)) {
            say_err("READ-ONLY session: the chain failed validation, so '%s' is blocked.",
                    cmd->name);
            continue;
        }
        if (lib->validated && lib->chain_ok && cmd->fn != cmd_validate_chain &&
            cmd->fn != cmd_check_overdue && cmd->fn != cmd_advance_clock)
            run_overdue_scan(lib, 0);                    /* on every CLI invocation */
        cmd->fn(lib, (int)count, words);
    }
    save_on_exit(lib);
    printf("Logging out %s. Signing key and vault key erased from memory. Goodbye!\n",
           lib->session.username);
}
