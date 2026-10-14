#!/usr/bin/env bash
# End-to-end tests for the Blockchain Library Lending Tracker (summative).
#
# Every scenario runs the real binary in a throw-away data directory, feeds
# it commands through stdin and checks the output and the files it wrote.
#
# usage: ./tests/run_tests.sh             (or: make test)
#        BIN=/path/to/binary ./tests/run_tests.sh   (e.g. an ASan build)

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/library_tracker}"
if [[ -n "${KEEP_WORK:-}" ]]; then        # keep the outputs for inspection
    WORK="$KEEP_WORK"; rm -rf "$WORK"; mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
fi
export NO_COLOR=1
export LIBRARY_SEED=42

PASS=0
FAIL=0
PW="Admin1234"
LPW="Libr4rian99"

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
    cp "$ROOT/tests/fixtures/books.txt" "$ROOT/tests/fixtures/members.txt" \
       "$ROOT/tests/fixtures/copies.txt" "$d/"
    echo "$d"
}

clone_dir() {   # clone_dir SRC NAME
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

# session DIR OUTFILE "FLAGS" command...   = log in as admin, validate, then commands
session() {
    local dir=$1 out=$2 flags=$3
    shift 3
    run "$dir" "$out" "$flags" admin "$PW" validate_chain "$@" exit
}

rc()         { cat "$1.rc"; }
blocks_in()  { grep -c '^B|' "$1/chain.dat"; }
pending_in() { if [[ -f "$1/pending.dat" ]]; then grep -c '^Q|' "$1/pending.dat"; else echo 0; fi; }
# id_of OUTFILE ACTION -> request ID of the last "Request <id> (<ACTION>)" line
id_of()      { grep -oE "Request [0-9a-f]{12} \($2\)" "$1" | tail -1 | awk '{print $2}'; }

# ---- 1. registries and options ----------------------------------------------

section "Registry loading"
D=$(new_dir missing_books); rm "$D/books.txt"
run "$D" "$WORK/r1" "-m utxo" admin
expect    "missing books.txt reports an error"   "books.txt is missing" "$WORK/r1"
expect_eq "missing registry exits with code 1"   "$(rc "$WORK/r1")" "1"
D=$(new_dir empty_members); : >"$D/members.txt"
run "$D" "$WORK/r2" "-m utxo" admin
expect    "empty members.txt reports an error"   "members.txt is empty" "$WORK/r2"
D=$(new_dir missing_copies); rm "$D/copies.txt"
run "$D" "$WORK/r3" "-m utxo" admin
expect    "missing copies.txt reports an error"  "copies.txt is missing" "$WORK/r3"
D=$(new_dir bad_copy)
printf 'BK999-C1,BK999,NEW\nBK001-C1,BK001,NEW\nBK002-C9,BK002,SHINY\n' >>"$D/copies.txt"
run "$D" "$WORK/r4" "-m utxo" admin "$PW" "$PW" admin "$PW" exit
expect    "copy of an unknown book is skipped"   "book_id is not in books.txt - line skipped" "$WORK/r4"
expect    "duplicate copy_id is skipped"         "duplicate copy_id - line skipped" "$WORK/r4"
expect    "unknown condition is skipped"         "condition must be NEW, GOOD, WORN or LOST" "$WORK/r4"
expect    "valid copies still load"              "9 cop(ies)" "$WORK/r4"

section "Command-line options"
D=$(new_dir opts)
run "$D" "$WORK/o1" "-D 7"
expect    "difficulty outside 1-4 is rejected"   "Invalid value for -D" "$WORK/o1"
expect_eq "bad option exits with code 64"        "$(rc "$WORK/o1")" "64"
run "$D" "$WORK/o2" "-m bitcoin"
expect    "unknown model is rejected"            "Invalid model 'bitcoin'" "$WORK/o2"

# ---- 2. first run, keys, validation gate ------------------------------------

section "First run: administrator, key vault, member keys, genesis"
M=$(new_dir main)
run "$M" "$WORK/a" "" admin "$PW" "$PW" admin "$PW" 1 borrow_book validate_chain exit
O="$WORK/a"
expect    "administrator created"                "Administrator 'admin' created" "$O"
expect    "member key pairs generated"           "Generated ECDSA P-256 key pairs for 5 member(s)" "$O"
expect    "model chosen from the menu"           "Using the UTXO model" "$O"
expect    "genesis block mined"                  "Genesis block #0 mined" "$O"
expect    "commands blocked before validation"   "Run validate_chain before any other operation" "$O"
expect    "validation passes"                    "RESULT: CHAIN VALID" "$O"
expect    "chain file format v3"                 "# LIBCHAIN v3" "$M/chain.dat"
expect_re "genesis hash meets difficulty 2"      "^B\|0\|.*\|00[0-9a-f]{62}$" "$M/chain.dat"
expect_eq "vault wrap is private (0600)"         "$(stat -c %a "$M/keys/admin.vault")" "600"
expect_eq "member private key is private (0600)" "$(stat -c %a "$M/keys/members/ALU001.key")" "600"
expect    "member private key is encrypted"      "LIBKEY1" "$M/keys/members/ALU001.key"
expect_not "no PEM private key for members"      "PRIVATE KEY" "$M/keys/members/ALU001.key"

section "Authentication"
run "$M" "$WORK/auth" "-m utxo" admin wrong1234 admin wrong5678 admin wrong9012
expect    "wrong password rejected"              "Invalid username or password" "$WORK/auth"
expect_eq "three failures exit with code 3"      "$(rc "$WORK/auth")" "3"

# ---- 3. borrowing ---------------------------------------------------------------

section "Borrowing and input validation"
session "$M" "$WORK/b" "-m utxo" \
    "borrow_book BK001 ALU001" "borrow_book BK001 ALU002" "borrow_book BK001 ALU003" \
    "borrow_book BK005 ALU002" \
    "borrow_book BK999 ALU001" "borrow_book BK002 ALU999" "borrow_book BK002 bad|id" \
    "borrow_book BK002 ALU004 2020-01-01" "borrow_book BK002 ALU004 2026-02-30" \
    "reserve_book BK001 ALU003" "pool_view"
O="$WORK/b"
expect    "borrow signed and added to the pool"  "(BORROW) signed and added to the pending pool" "$O"
expect    "second copy goes to the next member"  "ALU002 borrows BK001-C2" "$O"
expect    "no copy left: borrow rejected"        "no copy of BK001 (Things Fall Apart) is available" "$O"
expect    "unknown book rejected"                "book BK999 is not in the book registry" "$O"
expect    "unknown member rejected"              "member ALU999 is not in the member registry" "$O"
expect    "malformed member ID rejected"         "is not a valid member ID" "$O"
expect    "due date in the past rejected"        "the due date must be in the future" "$O"
expect    "impossible date rejected"             "'2026-02-30' is not a valid date" "$O"
expect    "reservation accepted"                 "ALU003 is number 1 in the FIFO queue for BK001" "$O"
expect    "pool view lists the requests"         "4 request(s): 4 PENDING, 0 SUSPICIOUS" "$O"
expect_eq "chain still holds only genesis"       "$(blocks_in "$M")" "1"
expect_eq "pending.dat holds 4 requests"         "$(pending_in "$M")" "4"
expect    "requests carry ECDSA signatures"      "ECDSA P-256 signature" "$O"

section "Mining confirms; nonces increase only on confirmation"
session "$M" "$WORK/c" "-m utxo" "member_nonce ALU001" "borrow_book BK003 ALU001" \
    "member_nonce ALU001" "mine_solo" "member_nonce ALU001" "view_copy"
O="$WORK/c"
expect    "pending pool survives a restart"      "Loaded 1 block(s) and 4 pending request(s)" "$O"
expect    "nonce 0 before any request"           "Confirmed nonce     : 0" "$O"
expect    "next nonce counts pending requests"   "Next request nonce  : 2" "$O"
expect    "confirmed nonce after mining"         "Confirmed nonce     : 2" "$O"
expect    "4 records per block"                  "Block #1 assembled: 4 record(s)" "$O"
expect    "the 5th waits for the next block"     "Waiting: 1 request(s) for a later block" "$O"
expect    "two blocks mined"                     "Blocks confirmed : 2 (5 records)" "$O"
expect_re "hash attempts displayed"              "CONFIRMED block #1 \| nonce [0-9]+ \| [0-9]+ hash attempts" "$O"
expect    "UTXO set shown after each block"      "UTXO SET - 0 unspent output(s)" "$O"
expect_re "copy state machine: BORROWED"         "BK001-C1 +BK001 +NEW +BORROWED +ALU001" "$O"
expect_eq "chain has 3 blocks"                   "$(blocks_in "$M")" "3"
expect_eq "pool empty after mining"              "$(pending_in "$M")" "0"

# ---- 4. returns, reservations, rewards -------------------------------------------

section "On-time return, automatic offer to the reservation queue, token reward"
session "$M" "$WORK/d" "-m utxo" "return_book BK001-C1" "mine_solo" "reservation_status BK001" \
    "borrow_book BK001 ALU004" "borrow_book BK001 ALU003" "mine_solo" "utxo_view"
O="$WORK/d"
expect    "on-time return earns 10"              "ON TIME: due" "$O"
expect    "queue head is told"                   "the copy will be offered to ALU003 (RESERVED)" "$O"
expect    "reward credited 10 - 1 fee"           "ALU001 +9 (10 on time - 1 fee)" "$O"
expect    "copy held for the queue head"         "BK001-C1   held for ALU003" "$O"
expect    "others cannot take the held copy"     "BK001-C1 RESERVED for ALU003" "$O"
expect    "queue head collects the copy"         "ALU003 borrows BK001-C1" "$O"
expect_re "UTXO of 9 coins for ALU001"           "ALU001 +John Doe +9 +block #" "$O"

section "Renewals"
session "$M" "$WORK/f" "-m utxo" "borrow_book BK004 ALU005" "mine_solo" "renew_book BK003-C1" \
    "mine_solo" "renew_book BK003-C1" "mine_solo" "renew_book BK003-C1" \
    "reserve_book BK004 ALU002" "renew_book BK004-C1" "mine_solo"
O="$WORK/f"
expect    "renewal extends the due date"         "(+7 days, renewal period)" "$O"
expect    "maximum renewals enforced"            "has already been renewed 2 time(s) (maximum 2)" "$O"
expect    "renewal blocked by a reservation"     "ALU002 is waiting for BK004" "$O"

section "Overdue detection, priority and late return"
session "$M" "$WORK/e" "-m utxo" "advance_clock 20" "check_overdue" "return_book BK001-C2" \
    "renew_book BK005-C1" "borrow_book BK006 ALU004" "pool_view" "mine_solo" "view_fines"
O="$WORK/e"
expect    "overdue loans flagged automatically"  "were flagged OVERDUE" "$O"
expect    "OVERDUE record is librarian-signed"   "OVERDUE records are signed by staff:admin" "$O"
expect_re "fine accrues per day"                 "BK001-C2 .*[67] day\(s\) late, fine so far [67] coin" "$O"
expect_not "renewed loan is not overdue yet"     "BK003-C1 The River Between" "$O"
expect    "late return: fine and reward 5"       "LATE: due" "$O"
expect    "overdue copy cannot be renewed"       "is overdue - it must be returned, not renewed" "$O"
expect_re "overdue-related requests first"       "^1 +[0-9a-f]{12} OVERDUE" "$O"
expect_re "normal priority last"                 "^6 +[0-9a-f]{12} BORROW .*normal" "$O"
expect    "late reward 5 - 1 fee"                "ALU002 +4 (5 late - 1 fee)" "$O"
expect_re "fine assessed on return"              "ALU002 +Jane Smith +([67]) +0 +\1 " "$O"

section "Fines: cash and tokens"
session "$M" "$WORK/g" "-m utxo" "settle_fine ALU002 all tokens" "settle_fine ALU002 2 cash" \
    "settle_fine ALU001 all cash" "mine_solo" "view_fines ALU002"
O="$WORK/g"
expect_re "token fine needs enough coins"        "needs [78] \(amount [67] \+ fee 1\)" "$O"
expect    "cash payment recorded"                "Cash payment of 2 coin(s) recorded" "$O"
expect    "no fine, no settlement"               "ALU001 has no outstanding fines" "$O"
expect_re "fine partly paid"                     "ALU002 +Jane Smith +[67] +2 +[45] " "$O"

# ---- 5. fraud heuristics and review ------------------------------------------------

section "Fraud heuristics, review and replay protection"
F=$(clone_dir "$M" fraud)
session "$F" "$WORK/h" "-m utxo" "borrow_book BK002 ALU001" "borrow_book BK005 ALU001" \
    "borrow_book BK001 ALU001" "return_book BK001-C1 WORN" "fraud_review" "mine_solo" "pool_view"
O="$WORK/h"
expect    "4th concurrent loan flagged"          "SUSPICIOUS [EXCESSIVE_BORROWS]" "$O"
expect    "condition drop of 2 levels flagged"   "SUSPICIOUS [CONDITION_DOWNGRADE]" "$O"
expect    "fraud_review explains the flag"       "NEW -> WORN, reason code '-'" "$O"
expect_not "suspicious requests never mined"     "BORROW      BK001-C2" "$O"
expect    "suspicious requests stay in the pool" "2 request(s): 0 PENDING, 2 SUSPICIOUS" "$O"
EXC=$(id_of "$O" BORROW)
CON=$(id_of "$O" RETURN)
run "$F" "$WORK/h2" "-m utxo" admin "$PW" validate_chain "add_user lib1" 1 "$LPW" "$LPW" exit
expect    "librarian account created"            "User 'lib1' created with role LIBRARIAN" "$WORK/h2"
run "$F" "$WORK/h3" "-m utxo" lib1 "$LPW" validate_chain "approve_suspicious $EXC" \
    "advance_clock 1" "tamper_demo" exit
expect    "librarian cannot approve"             "ACCESS DENIED - 'approve_suspicious'" "$WORK/h3"
expect    "librarian cannot move the clock"      "ACCESS DENIED - 'advance_clock'" "$WORK/h3"
session "$F" "$WORK/h4" "-m utxo" "reject_suspicious $EXC" "approve_suspicious $CON" "mine_solo" \
    "lending_history"
O="$WORK/h4"
expect    "admin rejects a request"              "rejected and removed from the pool" "$O"
expect    "admin approves a request"             "status SUSPICIOUS -> PENDING" "$O"
expect    "approval note stored on-chain"        "review: approved by admin (CONDITION_DOWNGRADE)" "$O"
session "$F" "$WORK/h5" "-m utxo" "borrow_book BK001 ALU003"
expect    "rapid re-borrow flagged"              "SUSPICIOUS [RAPID_REBORROW]" "$WORK/h5"
FIRST=$(grep -oE '^#1 +[0-9a-f]{12}' "$WORK/h4" | head -1 | awk '{print $2}')
session "$F" "$WORK/h6" "-m utxo" "replay_request $FIRST" "fraud_review" "approve_suspicious ${FIRST:0:6}"
O="$WORK/h6"
expect    "replay flagged as duplicate"          "DUPLICATE_REQUEST" "$O"
expect    "duplicate found on the chain"         "is already in block #1" "$O"
expect    "approved replay still rejected"       "was already used (duplicate / replay)" "$O"

# ---- 6. token ledgers -----------------------------------------------------------------

section "UTXO model: inputs, change, double spending"
U=$(clone_dir "$M" utxo)
TXID=$(grep -oE '^UTXO\|[0-9a-f]{64}\|0\|ALU001' "$U/state.dat" | head -1 | cut -d'|' -f2)
session "$U" "$WORK/u" "-m utxo" "token_transfer ALU001 ALU002 3 ${TXID:0:10}:0" \
    "token_transfer ALU001 ALU004 2 ${TXID:0:10}:0" "token_transfer ALU001 ALU004 50" \
    "token_transfer ALU001 ALU001 1" "token_transfer ALU001 ALU004 -5" "mine_solo" \
    "token_transfer ALU001 ALU004 1 ${TXID:0:10}:0" "utxo_view ALU001"
O="$WORK/u"
expect    "change output created"                "#1 change 5 back to ALU001" "$O"
expect    "pending double spend rejected"        "is already being spent by a pending transaction" "$O"
expect    "insufficient inputs rejected"         "but needs 51 (amount 50 + fee 1)" "$O"
expect    "self-transfer rejected"               "cannot send coins to themselves" "$O"
expect    "negative amount rejected"             "positive whole number" "$O"
expect_re "confirmed double spend rejected"      "was already spent in block #[0-9]+" "$O"
expect_re "change UTXO owned by the sender"      ":1 +ALU001 +John Doe +5" "$O"

section "Account model: nonce replay protection and history"
A=$(clone_dir "$U" account)
session "$A" "$WORK/acc" "-m account" "account_transfer ALU001 ALU003 1 0" \
    "account_transfer ALU001 ALU003 1 9" "account_transfer ALU001 ALU003 99 1" \
    "account_transfer ALU001 ALU003 1 1" "mine_solo" "account_balance" "transaction_history ALU001"
O="$WORK/acc"
expect    "reused nonce rejected"                "account nonce 0 was already used by ALU001 (expected 1)" "$O"
expect    "skipped nonce rejected"               "account nonce 9 is out of order for ALU001 (expected 1)" "$O"
expect    "insufficient balance rejected"        "has 5 coin(s) available but needs 100" "$O"
expect    "balances shown after the block"       "Account balances after block" "$O"
expect_re "history is a linked list"             "^[0-9]+ +#[0-9]+ +[0-9-]+ +TRANSFER +ALU001 +ALU003 +1 +1 +1" "$O"
expect    "same chain replays in both models"    "RESULT: CHAIN VALID" "$O"

# ---- 7. mining methods and difficulty ---------------------------------------------------

section "Pool and cloud mining, difficulty"
P=$(clone_dir "$M" pool)
session "$P" "$WORK/p" "-m utxo" "borrow_book BK003 ALU004" "mine_pool 3" \
    "set_difficulty 3" "borrow_book BK002 ALU005" "mine_cloud 2" "difficulty_status"
O="$WORK/p"
expect    "pool reward table"                    "Pool reward sharing" "$O"
expect    "pool fee deducted"                    "Pool fee 2% :" "$O"
expect_re "three miners listed"                  "POOL-M3 +[0-9]+ +[0-9]+ +[0-9.]+%" "$O"
expect    "cloud earnings summary"               "Cloud mining earnings" "$O"
expect    "net profit reported"                  "Net profit      :" "$O"
expect    "difficulty 3 target"                  "block hash must start with \"000\"" "$O"
expect_re "cloud fee warning"                    "WARNING: after round [0-9] cumulative fees" "$O"
session "$P" "$WORK/p2" "-m utxo" "mine_solo" "mine_solo" "set_difficulty 9" "difficulty_benchmark 3"
expect    "nothing to mine is explained"         "nothing to mine" "$WORK/p2"
expect    "difficulty range enforced"            "Difficulty must be 1-4" "$WORK/p2"
expect    "benchmark covers difficulty 4"        "0000" "$WORK/p2"

# ---- 8. Merkle tree ------------------------------------------------------------------------

section "Merkle tree"
REC=$(grep '^R|' "$M/chain.dat" | sed -n 2p | cut -d'|' -f2)
session "$M" "$WORK/m" "-m utxo" "merkle_tree 1" "merkle_proof 1 $REC" "chain_view 1"
O="$WORK/m"
expect    "recomputed root matches"              "[MATCH]" "$O"
expect    "inclusion proof verifies"             "Proof verified" "$O"
expect    "block shows every header field"       "transaction_id :" "$O"
expect    "records carry signer public keys"     "signature VALID" "$O"

# ---- 9. persistence -------------------------------------------------------------------------

section "Persistence"
expect    "state.dat has the copy inventory"     "COPY|BK001-C1|BK001|" "$M/state.dat"
expect    "state.dat has nonces"                 "NONCE|ALU001|" "$M/state.dat"
expect    "state.dat has the UTXO set"           "UTXO|" "$M/state.dat"
expect    "state.dat has the difficulty"         "META|difficulty|" "$M/state.dat"
expect    "state.dat has the clock offset"       "META|clock_offset|" "$M/state.dat"
S=$(clone_dir "$M" snapshot)
sed -i 's/^NONCE|ALU001|[0-9]*/NONCE|ALU001|99/' "$S/state.dat"
session "$S" "$WORK/s" "-m utxo" "chain_save" "chain_load" "view_copy" "validate_chain"
O="$WORK/s"
expect    "edited snapshot detected, chain wins" "state.dat differed from the chain" "$O"
expect    "chain_save writes all three files"    "pending.dat" "$O"
expect    "chain_load requires validation again" "no other operation is allowed until" "$O"
expect_not "rebuilt state.dat is correct"        "NONCE|ALU001|99" "$S/state.dat"

# ---- 10. tamper detection ---------------------------------------------------------------------

section "Tamper detection on disk"
T=$(clone_dir "$M" tamper)
LINE=$(grep -n '^R|' "$T/chain.dat" | head -1 | cut -d: -f1)
sed -i "${LINE}s/|BORROWED|/|RETURNED|/" "$T/chain.dat"
session "$T" "$WORK/t" "-m utxo" "borrow_book BK006 ALU004" "mine_solo" "view_book"
O="$WORK/t"
expect    "edited record detected"               "RESULT: CHAIN INVALID - TAMPERING DETECTED (first bad block: #1)" "$O"
expect    "Merkle root mismatch reported"        "merkle MISMATCH" "$O"
expect    "signature failure reported"           "signatures 3/4 valid" "$O"
expect    "session becomes read-only"            "READ-ONLY session" "$O"
expect    "viewing still allowed"                "BOOK CATALOGUE" "$O"
T2=$(clone_dir "$M" tamper2)
sed -i '$d' "$T2/chain.dat"; while tail -1 "$T2/chain.dat" | grep -q '^R|'; do sed -i '$d' "$T2/chain.dat"; done
sed -i '$d' "$T2/chain.dat"; sed -i '$d' "$T2/chain.dat"
session "$T2" "$WORK/t2" "-m utxo"
expect    "deleted newest block detected"        "block(s) were deleted from the end of the chain" "$WORK/t2"
T3=$(clone_dir "$M" tamper3)
sed -i '0,/^B|2|[0-9]*|/s//B|2|1000|/' "$T3/chain.dat"
session "$T3" "$WORK/t3" "-m utxo"
expect    "timestamp going backwards detected"   "timestamp is not later than the previous block's" "$WORK/t3"
T4=$(clone_dir "$M" tamper4)
session "$T4" "$WORK/t4a" "-m utxo" "borrow_book BK002 ALU004"
sed -i 's/^\(Q|.*\)|BK002-C1|/\1|BK003-C2|/' "$T4/pending.dat"
session "$T4" "$WORK/t4" "-m utxo" "mine_solo"
expect    "forged pending request detected"      "have an invalid signature" "$WORK/t4"
expect    "forged request rejected before mining" "signature INVALID - rejected" "$WORK/t4"
session "$M" "$WORK/t5" "-m utxo" "tamper_demo" 5 2 1
expect    "full rewrite still caught"            "RESULT: CHAIN INVALID" "$WORK/t5"
expect    "original chain restored"              "Original chain restored from the in-memory backup: VALID" "$WORK/t5"

# ---- 11. registration ----------------------------------------------------------------------------

section "Registration"
session "$M" "$WORK/reg" "-m utxo" "register_member ALU006 \"Grace Okafor\" BLK101" \
    "register_member ALU006 Dup BLK101" "register_book BK007 \"Purple Hibiscus\" \"C. N. Adichie\" 2" \
    "add_copy BK007 WORN" "add_copy BK007 LOST" "borrow_book BK007-C3 ALU006" "mark_lost BK007-C1 SHELF_MISSING" \
    "mine_solo" "view_copy BK007-C1"
O="$WORK/reg"
expect    "member registered with a key pair"    "Public key (on-chain identity): 0" "$O"
expect    "duplicate member rejected"            "duplicate member_id" "$O"
expect    "book registered with copies"          "Copy BK007-C2 of BK007 registered" "$O"
expect    "extra copy added"                     "BK007 now has 3 copies" "$O"
expect    "new copy cannot be LOST"              "Condition must be NEW, GOOD or WORN" "$O"
expect    "new member can borrow"                "ALU006 borrows BK007-C3" "$O"
expect    "librarian override to LOST"           "state             : LOST" "$O"
expect    "registries appended to files"         "ALU006,Grace Okafor,BLK101" "$M/members.txt"

# ---- summary ---------------------------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
