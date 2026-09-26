#!/usr/bin/env bash
# End-to-end tests for the Blockchain Library Lending Tracker.
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

PASS=0
FAIL=0
ADMIN_PW="Admin1234"
LIB_PW="Libr4rian99"

if [[ ! -x "$BIN" ]]; then
    echo "Binary not found - run 'make' first." >&2
    exit 1
fi

# ---- helpers ---------------------------------------------------------------

section() { printf '\n== %s ==\n' "$1"; }

ok()   { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }

# expect "description" "literal text" file
expect() {
    if grep -qF -- "$2" "$3"; then ok "$1"; else bad "$1  (missing: $2)"; fi
}

# expect_not "description" "literal text" file
expect_not() {
    if grep -qF -- "$2" "$3"; then bad "$1  (unexpected: $2)"; else ok "$1"; fi
}

# expect_eq "description" actual expected
expect_eq() {
    if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1  (got '$2', expected '$3')"; fi
}

# new_dir NAME -> fresh data directory with the sample registries
new_dir() {
    local d="$WORK/$1"
    mkdir -p "$d"
    cp "$ROOT/data/books.txt" "$ROOT/data/members.txt" "$d/"
    echo "$d"
}

# run DIR OUTFILE input-line...   (exit code stored in OUTFILE.rc)
run() {
    local dir=$1 out=$2
    shift 2
    printf '%s\n' "$@" | "$BIN" -d "$dir" >"$out" 2>&1
    echo $? >"$out.rc"
}

rc() { cat "$1.rc"; }

blocks_in() { grep -vc '^#' "$1/chain.dat"; }

# ---- 1. registry loading -----------------------------------------------------

section "Registry loading"

D=$(new_dir missing_books); rm "$D/books.txt"
run "$D" "$WORK/o1" admin
expect    "missing books.txt reports an error"  "ERROR: books.txt is missing" "$WORK/o1"
expect_eq "missing books.txt exits with code 1" "$(rc "$WORK/o1")" "1"

D=$(new_dir empty_members); : >"$D/members.txt"
run "$D" "$WORK/o2" admin
expect    "empty members.txt reports an error"  "ERROR: members.txt is empty" "$WORK/o2"
expect_eq "empty members.txt exits with code 1" "$(rc "$WORK/o2")" "1"

D=$(new_dir both_missing); rm "$D/books.txt" "$D/members.txt"
run "$D" "$WORK/o3" admin
expect "both files missing: books error"   "ERROR: books.txt is missing" "$WORK/o3"
expect "both files missing: members error" "ERROR: members.txt is missing" "$WORK/o3"

D=$(new_dir bad_lines)
printf 'BK001,Duplicate,Someone\nBK00X|bad,Title,Author\njust-one-field\n' >>"$D/books.txt"
run "$D" "$WORK/o4" admin "$ADMIN_PW" "$ADMIN_PW" admin "$ADMIN_PW" 0
expect "duplicate book_id skipped with warning"   "duplicate book_id - line skipped" "$WORK/o4"
expect "malformed line skipped with warning"      "expected 3 comma-separated fields" "$WORK/o4"
expect "valid records still load"                 "Loaded 6 book(s) and 5 member(s)" "$WORK/o4"

# ---- 2. first run, lending rules, validation -------------------------------

section "First run and lending rules"

MAIN=$(new_dir main)
run "$MAIN" "$WORK/o5" \
    admin "$ADMIN_PW" "$ADMIN_PW" admin "$ADMIN_PW" \
    1 BK001 ALU001 \
    1 BK999 ALU001 \
    1 BK002 ALU999 \
    1 BK001 ALU002 \
    2 BK001 ALU002 \
    2 BK001 ALU001 \
    2 BK001 ALU001 \
    2 BK003 ALU003 \
    1 bk002 alu003 \
    3 6 0
O="$WORK/o5"
expect "admin account created"                 "Administrator 'admin' created" "$O"
expect "login succeeds"                        "Logged in as admin [ADMIN]" "$O"
expect "genesis block created"                 "Genesis block #0 created" "$O"
expect "valid borrow succeeds"                 "SUCCESS: Loan recorded" "$O"
expect "invalid book ID rejected"              "book_id 'BK999' is not in books.txt" "$O"
expect "invalid member ID rejected"            "member_id 'ALU999' is not in members.txt" "$O"
expect "exact required error message"          "ERROR: Book or Member not found" "$O"
expect "double borrow rejected"                "is already on loan to ALU001" "$O"
expect "return by wrong member rejected"       "is on loan to ALU001 (John Doe), not to ALU002" "$O"
expect "valid return succeeds"                 "SUCCESS: Return recorded" "$O"
expect "second return rejected"                "it was already returned" "$O"
expect "never-borrowed return rejected"        "this book was never borrowed" "$O"
expect "view shows book title"                 "Things Fall Apart" "$O"
expect "view shows signature validity"         "Signature   : VALID (ECDSA P-256)" "$O"
expect "chain validates"                       "RESULT: CHAIN VALID - all 4 blocks verified" "$O"
expect_eq "chain.dat holds genesis + 3 records" "$(blocks_in "$MAIN")" "4"
expect "IDs are case-insensitive; registry ID stored" "|BK002|Americanah|ALU003|Amara Diallo|BORROWED|" "$MAIN/chain.dat"
expect "genesis previous_hash is 64 zeros" \
       "|GENESIS|admin|0000000000000000000000000000000000000000000000000000000000000000|" "$MAIN/chain.dat"

section "Persistence across restarts"
run "$MAIN" "$WORK/o6" admin "$ADMIN_PW" 2 BK002 ALU003 6 0
expect "chain reloaded from disk"          "Loaded 4 block(s)" "$WORK/o6"
expect "loan survives restart (return ok)" "SUCCESS: Return recorded" "$WORK/o6"
expect_eq "chain now has 5 blocks"         "$(blocks_in "$MAIN")" "5"

# ---- 3. security ---------------------------------------------------------------

section "Key and password storage"
expect_eq "private key permissions are 600"  "$(stat -c %a "$MAIN/keys/admin.key")" "600"
expect_eq "keys directory permissions are 700" "$(stat -c %a "$MAIN/keys")" "700"
expect_eq "users.db permissions are 600"     "$(stat -c %a "$MAIN/users.db")" "600"
expect "private key is encrypted PKCS#8"     "BEGIN ENCRYPTED PRIVATE KEY" "$MAIN/keys/admin.key"
expect_not "password not stored in plain text" "$ADMIN_PW" "$MAIN/users.db"
if command -v openssl >/dev/null; then
    if openssl pkey -in "$MAIN/keys/admin.key" -passin pass:WrongPass1 -noout 2>/dev/null; then
        bad "private key must not open with a wrong password"
    else
        ok "private key cannot be decrypted with a wrong password"
    fi
fi

section "Authentication"
run "$MAIN" "$WORK/o7" admin wrong1pass admin wrong2pass nobody Wrong3pass
expect    "wrong password rejected"            "Invalid username or password (attempt 1/3)" "$WORK/o7"
expect    "locked out after 3 attempts"        "Too many failed login attempts" "$WORK/o7"
expect_eq "failed login exits with code 3"     "$(rc "$WORK/o7")" "3"

section "Access control (librarian vs admin)"
run "$MAIN" "$WORK/o8" admin "$ADMIN_PW" 8 librarian1 1 short "$LIB_PW" "$LIB_PW" 8 librarian1 1 "$LIB_PW" "$LIB_PW" 0
expect "weak password rejected"          "password must be at least 8 characters long" "$WORK/o8"
expect "admin can create a librarian"    "User 'librarian1' created with role LIBRARIAN" "$WORK/o8"
run "$MAIN" "$WORK/o9" librarian1 "$LIB_PW" 1 BK004 ALU004 7 8 6 0
expect "librarian logs in"               "Logged in as librarian1 [LIBRARIAN]" "$WORK/o9"
expect "librarian can record a loan"     "Signed by   : librarian1" "$WORK/o9"
expect "librarian denied tamper demo"    "ACCESS DENIED - 'Tamper detection demo'" "$WORK/o9"
expect "librarian denied user creation"  "ACCESS DENIED - 'Add user account'" "$WORK/o9"
expect "multi-signer chain validates"    "RESULT: CHAIN VALID - all 6 blocks verified" "$WORK/o9"

# ---- 4. tamper detection -----------------------------------------------------

section "Built-in tamper demo (in memory)"
BEFORE=$(sha256sum "$MAIN/chain.dat")
run "$MAIN" "$WORK/o10" admin "$ADMIN_PW" \
    7 1 1 \
    7 1 2 "Someone Else" \
    7 1 3 \
    7 5 3 \
    7 2 4 \
    6 0
O="$WORK/o10"
expect "tampering is detected"                     "RESULT: CHAIN INVALID - TAMPERING DETECTED (first bad block: #1)" "$O"
expect "edited block shows hash mismatch"          "hash MISMATCH" "$O"
expect "member-name edit is shown"                 "member_name: John Doe -> Someone Else" "$O"
expect "recomputed hash still fails signature"     "hash OK | link OK | signature INVALID (admin)" "$O"
expect "next block link breaks after recompute"    "link BROKEN" "$O"
expect "tampering the LAST block is still caught"  "first bad block: #5" "$O"
expect "deleting a block is detected"              "block #2 removed from the chain" "$O"
expect "original chain restored"                   "Original chain restored from the in-memory backup: VALID" "$O"
expect_eq "chain.dat untouched by the demo"        "$(sha256sum "$MAIN/chain.dat")" "$BEFORE"

section "External edit of chain.dat"
EXT=$(new_dir external)
cp -r "$MAIN/keys" "$MAIN/users.db" "$MAIN/chain.dat" "$EXT/"
sed -i '0,/|John Doe|BORROWED|/s//|Jane Smith|BORROWED|/' "$EXT/chain.dat"
run "$EXT" "$WORK/o11" admin "$ADMIN_PW" 1 BK005 ALU005 6 0
expect "startup validation flags tampering"   "Blockchain validation FAILED (first bad block: #1)" "$WORK/o11"
expect "writes are refused on a tampered chain" "refusing to add records to a tampered chain" "$WORK/o11"
expect "menu header shows TAMPERED"            "chain: TAMPERED" "$WORK/o11"
expect "validation pinpoints the hash mismatch" "stored hash  :" "$WORK/o11"

if command -v python3 >/dev/null; then
    section "Attacker rewrites a block AND recomputes every later hash"
    FORGE=$(new_dir forge)
    cp -r "$MAIN/keys" "$MAIN/users.db" "$MAIN/chain.dat" "$FORGE/"
    python3 "$ROOT/tests/forge_chain.py" "$FORGE/chain.dat" 1 RETURNED
    run "$FORGE" "$WORK/o12" admin "$ADMIN_PW" 6 0
    # Every block from #1 on was rewritten; each signature covers previous_hash,
    # so every re-linked block fails verification, not just the edited one.
    expect "hashes and links look fine..."    "hash mismatches: 0 | broken links: 0" "$WORK/o12"
    expect "...but the ECDSA signature fails" "Block #1   [TAMPERED] hash OK | link OK | signature INVALID" "$WORK/o12"
    expect "re-linked later blocks also fail" "bad signatures: 5" "$WORK/o12"
    expect "untouched genesis still verifies" "Block #0   [OK]" "$WORK/o12"
fi

section "Corrupted chain file format"
BROKEN=$(new_dir broken)
cp -r "$MAIN/keys" "$MAIN/users.db" "$MAIN/chain.dat" "$BROKEN/"
sed -i '4s/|[^|]*$//' "$BROKEN/chain.dat"
run "$BROKEN" "$WORK/o13" admin "$ADMIN_PW" 0
expect    "corrupted file reported"      "chain.dat is corrupted or unreadable" "$WORK/o13"
expect_eq "corrupted file exits code 2"  "$(rc "$WORK/o13")" "2"

section "Forged signer name (path traversal attempt)"
TRAV=$(new_dir traversal)
cp -r "$MAIN/keys" "$MAIN/users.db" "$MAIN/chain.dat" "$TRAV/"
sed -i '4s/|admin|/|..\/..\/x|/' "$TRAV/chain.dat"
run "$TRAV" "$WORK/o14" admin "$ADMIN_PW" 6 0
expect "unknown signer cannot be verified" "UNVERIFIABLE (no public key)" "$WORK/o14"

# ---- 5. overdue --------------------------------------------------------------

section "Overdue loans"
OVER=$(new_dir overdue)
printf '%s\n' admin "$ADMIN_PW" "$ADMIN_PW" admin "$ADMIN_PW" 1 BK006 ALU002 5 0 |
    LIBRARY_LOAN_PERIOD=1 "$BIN" -d "$OVER" >"$WORK/o15" 2>&1
expect "fresh loan is not overdue" "No loans are past their due date" "$WORK/o15"
sleep 2
printf '%s\n' admin "$ADMIN_PW" 5 4 2 BK006 ALU002 6 0 |
    LIBRARY_LOAN_PERIOD=1 "$BIN" -d "$OVER" >"$WORK/o16" 2>&1
expect "late loan marked OVERDUE"         "1 loan(s) marked OVERDUE" "$WORK/o16"
expect "registry shows OVERDUE status"    "OVERDUE - ALU002" "$WORK/o16"
expect "overdue book can still be returned" "SUCCESS: Return recorded" "$WORK/o16"
expect "chain valid after overdue flow"   "RESULT: CHAIN VALID - all 4 blocks verified" "$WORK/o16"

# ---- summary -------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
