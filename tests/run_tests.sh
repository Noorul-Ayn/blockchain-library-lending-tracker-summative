#!/usr/bin/env bash
# End-to-end tests for the Blockchain Library Lending Tracker v2
# (pending pool, token rewards, UTXO / account models, solo / pool / cloud mining).
#
# Each scenario runs the real binary in a throw-away data directory, feeds it
# menu input through stdin and checks the output and the files it produced.
#
# usage: ./tests/run_tests.sh        (or: make test)

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/library_tracker"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export NO_COLOR=1
export LIBRARY_SEED=42

PASS=0
FAIL=0
PW="Admin1234"
LIB_PW="Libr4rian99"

if [[ ! -x "$BIN" ]]; then
    echo "Binary not found - run 'make' first." >&2
    exit 1
fi

# ---- helpers ---------------------------------------------------------------

section() { printf '\n== %s ==\n' "$1"; }
ok()      { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
bad()     { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }

expect()     { if grep -qF -- "$2" "$3"; then ok "$1"; else bad "$1  (missing: $2)"; fi; }
expect_re()  { if grep -qE -- "$2" "$3"; then ok "$1"; else bad "$1  (no match: $2)"; fi; }
expect_not() { if grep -qF -- "$2" "$3"; then bad "$1  (unexpected: $2)"; else ok "$1"; fi; }
expect_eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1  (got '$2', expected '$3')"; fi; }

new_dir() {
    local d="$WORK/$1"
    mkdir -p "$d"
    cp "$ROOT/data/books.txt" "$ROOT/data/members.txt" "$d/"
    echo "$d"
}

clone_dir() {   # clone_dir SRC NAME -> copy of a data directory
    local d="$WORK/$2"
    rm -rf "$d"
    cp -r "$1" "$d"
    echo "$d"
}

# run DIR OUTFILE "FLAGS" input-line...   (exit code stored in OUTFILE.rc)
run() {
    local dir=$1 out=$2 flags=$3
    shift 3
    # shellcheck disable=SC2086
    printf '%s\n' "$@" | "$BIN" -d "$dir" $flags >"$out" 2>&1
    echo $? >"$out.rc"
}

rc()          { cat "$1.rc"; }
blocks_in()   { grep -vc '^#' "$1/chain.dat"; }
pending_in()  { if [[ -f "$1/pending.dat" ]]; then grep -vc '^#' "$1/pending.dat"; else echo 0; fi; }
# field DIR BLOCK_INDEX FIELD_NUMBER (1-based, see storage.h for the order)
field()       { awk -F'|' -v i="$2" -v f="$3" '!/^#/ && $1 == i { print $f }' "$1/chain.dat"; }

# ---- 1. registries (unchanged from Formative 1) ------------------------------

section "Registry loading"
D=$(new_dir missing_books); rm "$D/books.txt"
run "$D" "$WORK/r1" "-m utxo" admin
expect    "missing books.txt reports an error"  "ERROR: books.txt is missing" "$WORK/r1"
expect_eq "missing books.txt exits with code 1" "$(rc "$WORK/r1")" "1"
D=$(new_dir empty_members); : >"$D/members.txt"
run "$D" "$WORK/r2" "-m utxo" admin
expect    "empty members.txt reports an error"  "ERROR: members.txt is empty" "$WORK/r2"
D=$(new_dir bad_lines)
printf 'BK001,Duplicate,Someone\njust-one-field\n' >>"$D/books.txt"
run "$D" "$WORK/r3" "-m utxo" admin "$PW" "$PW" admin "$PW" 0
expect "duplicate book_id skipped"   "duplicate book_id - line skipped" "$WORK/r3"
expect "valid records still load"    "Loaded 6 book(s) and 5 member(s)" "$WORK/r3"

section "Command-line options"
D=$(new_dir opts)
run "$D" "$WORK/o1" "-D 7"
expect    "difficulty outside 1-4 is rejected" "Invalid difficulty '7'" "$WORK/o1"
expect_eq "bad option exits with code 64"      "$(rc "$WORK/o1")" "64"
run "$D" "$WORK/o2" "-m bitcoin"
expect    "unknown model is rejected"          "Invalid model 'bitcoin'" "$WORK/o2"

# ---- 2. pending pool and mining confirmation -------------------------------

section "First run, genesis block and the pending pool"
M=$(new_dir main)
run "$M" "$WORK/a" "" admin "$PW" "$PW" admin "$PW" 1 \
    1 BK001 ALU001 \
    4 10 0
O="$WORK/a"
expect    "model chosen from the start-up menu" "Using the UTXO model for every token transaction" "$O"
expect    "genesis block is mined"              "Genesis block #0 mined" "$O"
expect_re "genesis hash meets difficulty 2"     "^00" <(field "$M" 0 18)
expect    "chain file uses format v2"           "# LIBCHAIN v2" "$M/chain.dat"
expect    "borrow goes to the pending pool"     "Added to the PENDING POOL as P1 (not on the chain yet)" "$O"
expect    "pending pool is displayed"           "1 unconfirmed block(s) waiting to be mined" "$O"
expect_eq "chain still holds only genesis"      "$(blocks_in "$M")" "1"
expect_eq "pending.dat holds the borrow"        "$(pending_in "$M")" "1"

section "On-time return: 10-coin reward, confirmed only by mining"
run "$M" "$WORK/b" "-m utxo" admin "$PW" \
    2 BK001 ALU001 \
    10 \
    5 1 \
    10 0
O="$WORK/b"
expect    "pending pool survives a restart"     "Loaded 1 confirmed block(s) and 1 pending block(s)" "$O"
expect    "on-time return earns 10 coins"       "Return recorded ON TIME: token reward of 10 coins created (9 after the 1-coin fee)" "$O"
expect_re "balance unchanged before mining"     "^ALU001 +John Doe +0 +0 " "$O"
expect    "solo miner confirms block #1"        "CONFIRMED block #1  BORROWED" "$O"
expect    "solo miner confirms block #2"        "CONFIRMED block #2  RETURNED" "$O"
expect    "hash attempts are displayed"         "Hash attempts    :" "$O"
expect    "UTXO set shown after each block"     "UTXO SET - 1 unspent output(s), 9 coin(s) in total" "$O"
expect    "solo reward = blocks x 20 + fees"    "2 x 20 block reward + 1 fee(s) = 41.00 coins -> admin" "$O"
expect_re "member credited 9 after mining"      "^ALU001 +John Doe +9 +1 " "$O"
expect_eq "chain now has 3 blocks"              "$(blocks_in "$M")" "3"
expect_eq "pending pool is empty"               "$(pending_in "$M")" "0"
expect_eq "block stores token_reward 10"        "$(field "$M" 2 8)" "10"
expect_re "block stores the reward tx"          "^R;LIBRARY;ALU001;10;1;" <(field "$M" 2 10)
expect_re "tx_id is a SHA-256 hash"             "^[0-9a-f]{64}$" <(field "$M" 2 9)

section "Late return (5 coins), overdue book (no transaction), lending rules"
export LIBRARY_LOAN_PERIOD=1
run "$M" "$WORK/c1" "-m utxo" admin "$PW" \
    1 BK002 ALU002 \
    1 BK003 ALU003 \
    1 BK999 ALU001 \
    1 BK004 ALU999 \
    1 BK002 ALU005 \
    2 BK002 ALU003 \
    2 BK005 ALU001 0
sleep 2
run "$M" "$WORK/c2" "-m utxo" admin "$PW" \
    3 \
    2 BK002 ALU002 \
    4 5 1 10 0
unset LIBRARY_LOAN_PERIOD
expect    "unregistered book rejected"          "book_id 'BK999' is not in books.txt" "$WORK/c1"
expect    "unregistered member rejected"        "member_id 'ALU999' is not in members.txt" "$WORK/c1"
expect    "exact required error message"        "ERROR: Book or Member not found" "$WORK/c1"
expect    "pending loan blocks a second borrow" "(loan still pending)" "$WORK/c1"
expect    "return by wrong member rejected"     "is on loan to ALU002 (Jane Smith), not to ALU003" "$WORK/c1"
expect    "never-borrowed return rejected"      "No outstanding BORROWED record for BK005" "$WORK/c1"
expect    "overdue loans recorded"              "2 loan(s) marked OVERDUE" "$WORK/c2"
expect    "unreturned book: no transaction"     "token_reward 0, tx_id none" "$WORK/c2"
expect    "late return earns 5 coins"           "Return recorded LATE: token reward of 5 coins created (4 after the 1-coin fee)" "$WORK/c2"
expect_re "late returner credited 4"            "^ALU002 +Jane Smith +4 +1 " "$WORK/c2"
expect_re "unreturned book earns nothing"       "^ALU003 +Amara Diallo +0 +0 " "$WORK/c2"
OV=$(awk -F'|' '!/^#/ && $7 == "OVERDUE" && $3 == "BK003" { print $8 "|" $10 }' "$M/chain.dat")
expect_eq "OVERDUE block: reward 0, tx none"    "$OV" "0|-"

# ---- 3. UTXO model ------------------------------------------------------------

section "UTXO model: change, double spend, insufficient inputs"
run "$M" "$WORK/d" "-m utxo" admin "$PW" \
    11 ALU001 ALU003 3 "" \
    11 ALU001 ALU003 1 1 \
    11 ALU001 ALU003 1 "" \
    11 ALU002 ALU003 10 1 \
    11 ALU002 ALU002 1 "" \
    5 1 \
    11 ALU001 ALU002 1 1 \
    10 0
O="$WORK/d"
expect "change output returned to sender"       "vout 1 -> ALU001 5 coin(s) CHANGE" "$O"
expect "reserved output cannot be reused"       "is already being spent by a pending transaction" "$O"
expect "no spendable outputs while reserved"    "(0 spendable now)" "$O"
expect "insufficient inputs rejected"           "inputs total 4 coin(s) but amount + fee = 11 coin(s)" "$O"
expect "self-transfer rejected"                 "the recipient must differ from the sender" "$O"
expect "spent output cannot be spent again"     "was already spent in block" "$O"
expect "UTXO set after transfer confirmation"   "UTXO SET - 3 unspent output(s)" "$O"
expect_re "sender keeps change"                 "^ALU001 +John Doe +5 +1 " "$O"
expect_re "recipient received 3"                "^ALU003 +Amara Diallo +3 +1 " "$O"

# ---- 4. account model ---------------------------------------------------------

section "Account model on the same chain: nonce, balance, history"
run "$M" "$WORK/e" "-m account" admin "$PW" \
    10 \
    11 ALU001 ALU004 1 0 \
    11 ALU001 ALU004 1 3 \
    11 ALU001 ALU004 10 1 \
    11 ALU001 ALU004 2 1 \
    11 ALU001 ALU004 1 2 \
    5 2 3 \
    12 ALU001 \
    10 0
O="$WORK/e"
expect_re "same balances as the UTXO model"     "^ALU001 +John Doe +5 +1 " "$O"
expect    "reused nonce rejected"               "nonce 0 was already used by ALU001 (expected 1)" "$O"
expect    "out-of-order nonce rejected"         "nonce 3 is out of order for ALU001 (expected 1)" "$O"
expect    "insufficient balance rejected"       "but needs 11 (amount 10 + fee 1)" "$O"
expect    "correct nonce accepted"              "from ALU001 to ALU004 accepted (fee 1, nonce 1)" "$O"
expect    "next nonce counts pending transfers" "from ALU001 to ALU004 accepted (fee 1, nonce 2)" "$O"
expect    "pool table is shown"                 "Pool reward sharing (2 block(s)" "$O"
expect    "pool gross reward"                   "2 x 20 block reward + 2 fee(s) = 42.00 coins" "$O"
expect    "2% pool fee deducted"                "Pool fee 2% : -0.84 coins" "$O"
expect    "rest shared by contribution"         "Distributed  : 41.16 coins" "$O"
expect_re "shares add up to 100%"               "TOTAL +[0-9]+ +100.00%" "$O"
expect    "history is a linked list per member" "record(s) in the linked list" "$O"
expect_re "history shows sender/recipient/fee/nonce" "TRANSFER +ALU001 +ALU004 +2 +1 +1" "$O"
expect_re "balances debited and nonce advanced" "^ALU001 +John Doe +0 +3 " "$O"
expect_re "recipient credited"                  "^ALU004 +Kwame Mensah +3 +0 " "$O"

section "Switching back to UTXO replays account-made transfers"
run "$M" "$WORK/f" "-m utxo" admin "$PW" 10 7 0
expect_re "UTXO balances match the account model" "^ALU004 +Kwame Mensah +3 +2 " "$WORK/f"
expect    "ledger replay succeeds"              "Ledger replay (UTXO model): OK" "$WORK/f"
expect    "full chain validates"                "RESULT: CHAIN VALID" "$WORK/f"

# ---- 5. difficulty and cloud mining -----------------------------------------

section "Difficulty, benchmark and cloud mining"
run "$M" "$WORK/g" "-m utxo -D 3" admin "$PW" \
    1 BK006 ALU005 \
    5 1 \
    8 5 8 1 \
    9 \
    5 3 2 \
    1 BK005 ALU001 \
    5 3 1 0
O="$WORK/g"
LAST=$(( $(blocks_in "$M") - 1 ))
expect    "difficulty from the command line"    "Mining difficulty: 3" "$O"
expect_re "block mined at difficulty 3"         "^000" <(awk -F'|' '!/^#/ && $13 == "3" { print $18 }' "$M/chain.dat")
expect    "difficulty out of range rejected"    "Please enter a whole number from 1 to 4" "$O"
expect    "difficulty changed from the menu"    "Difficulty set to 1" "$O"
expect    "benchmark covers difficulty 4"       "65536" "$O"
expect    "unprofitable rental is flagged"      "WARNING: rental is unprofitable after round 1" "$O"
expect    "cloud summary: gross, fees, net"     "Total fees paid :" "$O"
expect    "cloud mining confirms pending block" "by CLOUD-admin" "$O"
expect_eq "difficulty-1 block stored"           "$(field "$M" "$LAST" 13)" "1"

# ---- 6. security --------------------------------------------------------------

section "Keys, passwords and access control"
expect_eq "private key permissions are 600"    "$(stat -c %a "$M/keys/admin.key")" "600"
expect_eq "users.db permissions are 600"       "$(stat -c %a "$M/users.db")" "600"
expect    "private key is encrypted PKCS#8"    "BEGIN ENCRYPTED PRIVATE KEY" "$M/keys/admin.key"
expect_not "password not stored in plain text" "$PW" "$M/users.db"
run "$M" "$WORK/h1" "-m utxo" admin wrong1pass admin wrong2pass nobody Wrong3pass
expect    "locked out after 3 failed logins"   "Too many failed login attempts" "$WORK/h1"
run "$M" "$WORK/h2" "-m utxo" admin "$PW" 15 lib1 1 "$LIB_PW" "$LIB_PW" 0
run "$M" "$WORK/h3" "-m utxo" lib1 "$LIB_PW" 14 15 1 BK004 ALU002 5 1 0
expect    "librarian denied the tamper demo"   "ACCESS DENIED - 'Tamper detection demo'" "$WORK/h3"
expect    "librarian denied user creation"     "ACCESS DENIED - 'Add user account'" "$WORK/h3"
expect    "librarian can record and mine"      "by lib1" "$WORK/h3"

# ---- 7. tamper detection --------------------------------------------------------

section "Tamper demo (in memory) with proof-of-work"
BEFORE=$(sha256sum "$M/chain.dat")
run "$M" "$WORK/t" "-m utxo" admin "$PW" 14 2 1 14 2 2 14 2 3 14 2 4 14 2 5 0
O="$WORK/t"
expect    "edited block: hash mismatch"         "Block #2   [TAMPERED] hash MISMATCH" "$O"
expect    "inflated reward: tx_id mismatch"     "tx_id is no longer the SHA-256" "$O"
expect    "re-mined block: PoW ok, signature fails" "hash OK | PoW OK (d=2) | link OK | tx BAD | sig INVALID" "$O"
expect    "next block's link breaks"            "link BROKEN" "$O"
expect    "full rewrite reports the PoW cost"   "hash attempts in total" "$O"
expect    "deleting a block is detected"        "block #2 removed from the chain" "$O"
expect    "original chain restored"             "Original chain restored from the in-memory backup: VALID" "$O"
expect_eq "chain.dat untouched by the demo"     "$(sha256sum "$M/chain.dat")" "$BEFORE"

section "External edits of the files"
X=$(clone_dir "$M" ext)
sed -i '0,/|John Doe|BORROWED|/s//|Jane Smith|BORROWED|/' "$X/chain.dat"
run "$X" "$WORK/x1" "-m utxo" admin "$PW" 1 BK001 ALU002 5 1 0
expect "start-up validation flags tampering"   "Blockchain validation FAILED (first bad block: #1)" "$WORK/x1"
expect "new records refused"                   "refusing to add records to a tampered chain" "$WORK/x1"

X=$(clone_dir "$M" reward)
sed -i 's/|RETURNED|10|/|RETURNED|50|/' "$X/chain.dat"
run "$X" "$WORK/x2" "-m utxo" admin "$PW" 7 0
expect "edited token reward detected"          "token_reward must be 10 (on time) or 5 (late)" "$WORK/x2"

if command -v python3 >/dev/null; then
    X=$(clone_dir "$M" forge)
    python3 "$ROOT/tests/forge_chain.py" "$X/chain.dat" 1 "Someone Else" >/dev/null
    run "$X" "$WORK/x3" "-m utxo" admin "$PW" 7 0
    expect "forged + re-mined chain: hash/PoW/link pass" "Block #1   [TAMPERED] hash OK | PoW OK (d=2) | link OK | tx OK | sig INVALID" "$WORK/x3"
    expect "...but only the edited record fails"  "signatures: 1" "$WORK/x3"
fi

X=$(clone_dir "$M" pending)
run "$X" "$WORK/x4" "-m utxo" admin "$PW" 1 BK001 ALU003 0
sed -i 's/|ALU003|Amara Diallo|BORROWED|/|ALU003|Somebody|BORROWED|/' "$X/pending.dat"
run "$X" "$WORK/x5" "-m utxo" admin "$PW" 4 5 1 0
expect "tampered pending record shown INVALID" "INVALID" "$WORK/x5"
expect "miner rejects the tampered record"     "REJECTED pending BORROWED BK001 ALU003" "$WORK/x5"

X=$(clone_dir "$M" v1)
printf '# LIBCHAIN v1\n0|1|GENESIS|x|y|z|GENESIS|admin|0|0|0\n' >"$X/chain.dat"
run "$X" "$WORK/x6" "-m utxo" admin
expect    "Formative 1 chain file recognised"  "Formative 1 format (v1)" "$WORK/x6"
expect_eq "unreadable chain exits with code 2" "$(rc "$WORK/x6")" "2"

X=$(clone_dir "$M" traversal)
sed -i '0,/|admin|/s//|..\/..\/x|/' "$X/chain.dat"
run "$X" "$WORK/x7" "-m utxo" admin "$PW" 7 0
expect "forged signer path cannot load a key"  "sig NO KEY" "$WORK/x7"

# ---- summary -------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
