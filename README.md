# Blockchain Library Lending Tracker (C)

A command-line library lending system written in C. Every **borrow**, **return** and **overdue**
event is stored as a block in a blockchain. Each block is linked by **SHA-256** hashes and
**signed with ECDSA (P-256)** by the librarian who recorded it, so no past record can be quietly
changed. For example, nobody can mark a lost book as "returned" without being caught.

---

## Features

| Requirement | Where it is implemented |
|---|---|
| Blockchain data structure (blocks of lending records) | `include/blockchain.h`, `src/blockchain.c` |
| Book + member registries loaded from `books.txt` / `members.txt` into arrays of structs | `src/registry.c` |
| IDs validated before any lending action (`ERROR: Book or Member not found`) | `src/lending.c` |
| SHA-256 hashing to link blocks | `src/crypto.c`, `block_compute_hash()` |
| Digital signatures (ECDSA P-256) on every lending action | `src/crypto.c`, `seal_block()` |
| Chain validation: hashes, `previous_hash` links, signatures | `chain_validate()` |
| CLI to borrow, return and view records | `src/ui.c` |
| Tamper detection demo | menu option 7 (and editing `chain.dat` directly) |
| User authentication + role-based access control | `src/auth.c` |
| File-based persistence (atomic writes) | `src/storage.c` |
| Overdue detection (`OVERDUE` blocks) | `lending_mark_overdue()` |

---

## Required libraries and dependencies

| Dependency | Why | Ubuntu package |
|---|---|---|
| GCC (C11) and GNU Make | compile and build | `build-essential` |
| OpenSSL libcrypto (1.1.1 or 3.x) | SHA-256, ECDSA, AES-256, PBKDF2, secure random numbers | `libssl-dev` |
| Python 3 *(optional)* | only used by one attack-simulation test | `python3` |

Install everything on Ubuntu / Debian:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev
```

---

## Compilation instructions

```bash
git clone https://github.com/Noorul-Ayn/blockchain-library-lending-tracker.git
cd blockchain-library-lending-tracker
make
```

This produces the executable `./library_tracker`. The code compiles with
`-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2` and produces **zero warnings**.

Other build targets:

| Command | What it does |
|---|---|
| `make` | build `./library_tracker` |
| `make run` | build and start the program |
| `make test` | build and run the 71 automated end-to-end tests |
| `make debug` | build with AddressSanitizer + UndefinedBehaviorSanitizer |
| `make clean` | delete build output |

Manual compile without Make:

```bash
gcc -std=c11 -Wall -Wextra -Iinclude -D_POSIX_C_SOURCE=200809L src/*.c -o library_tracker -lcrypto
```

---

## How to build and run the application

```bash
make
./library_tracker                 # uses the data/ folder
./library_tracker -d /path/to/dir # use a different data folder
./library_tracker --help
```

### First run

1. The program loads `data/books.txt` and `data/members.txt`. If either file is missing or empty,
   it prints an error and exits.
2. No accounts exist yet, so it asks you to **create the administrator account**. A personal
   ECDSA key pair is generated and the private key is encrypted with your password.
3. You log in with that account.
4. The **genesis block** (index 0, `previous_hash` = 64 zeros) is created, signed and saved.
5. The whole chain is validated, and then the main menu appears:

```
 MAIN MENU   user: admin [ADMIN]   blocks: 1   chain: VALID
  1. Borrow a book
  2. Return a book
  3. View lending records (blockchain)
  4. View books & members (registries)
  5. Mark overdue loans
  6. Validate blockchain
  7. Tamper detection demo
  8. Add user account
  0. Logout and exit
```

### Passwords

Passwords need 8 or more characters and must include at least one letter and one digit.
You get three login attempts before the program exits.

### Demonstrating overdue loans

The default loan period is 14 days. To demo overdue detection quickly, shorten it
(the value is in seconds):

```bash
LIBRARY_LOAN_PERIOD=30 ./library_tracker
```

Borrow a book, wait 30 seconds, then choose **5. Mark overdue loans**.

---

## Registry file formats

`data/books.txt` has one book per line: `book_id,title,author`

```
BK001,Things Fall Apart,Chinua Achebe
BK002,Americanah,Chimamanda Ngozi Adichie
BK003,The River Between,Ngũgĩ wa Thiong'o
```

`data/members.txt` has one member per line: `member_id,full_name,course_code`

```
ALU001,John Doe,BLK101
ALU002,Jane Smith,BLK101
ALU003,Amara Diallo,BLK101
```

Blank lines and lines starting with `#` are ignored. Invalid lines are reported with their line
number and skipped. This covers duplicate IDs, missing fields, over-long values, and the `|`
character, which is reserved as the chain file delimiter.

---

## How the blockchain works

### Block structure

| Field | Type | Description |
|---|---|---|
| `index` | `int` | position in the chain (0 = genesis) |
| `timestamp` | `time_t` | Unix time the block was created |
| `book_id` | `char[20]` | must exist in the book registry |
| `book_title` | `char[80]` | copied from the registry at transaction time |
| `member_id` | `char[20]` | must exist in the member registry |
| `member_name` | `char[50]` | copied from the registry at transaction time |
| `action` | `char[10]` | `BORROWED`, `RETURNED` or `OVERDUE` (`GENESIS` for block 0) |
| `previous_hash` | `char[65]` | SHA-256 of the previous block |
| `signature` | `unsigned char[72]` | ECDSA P-256 signature (DER) of the block data |
| `signature_len` | `size_t` | number of bytes used in `signature` (DER length varies from 70 to 72) |
| `signed_by` | `char[20]` | staff user whose key signed the block |
| `hash` | `char[65]` | SHA-256 of all of the above |

The first ten fields are exactly those in the specification. `signature_len` and `signed_by`
are added because they are needed to verify a variable-length signature against the right
public key.

### Hashing and signing

```
payload   = index|timestamp|book_id|book_title|member_id|member_name|action|previous_hash|signed_by
signature = ECDSA_P256_Sign( SHA-256(payload) )          using the librarian's private key
hash      = SHA-256( payload | hex(signature) )
```

### Validation (menu option 6)

For every block, the program checks:

1. **Structure**: the index equals the block's position and the action is legal there.
2. **Hash**: the recomputed SHA-256 equals the stored `hash`.
3. **Link**: `previous_hash` equals the previous block's `hash` (64 zeros for genesis).
4. **Signature**: the ECDSA signature verifies with the signer's public key.

The chain is also validated automatically **at start-up** and **before every write**.
A tampered chain can still be viewed, but no new records can be added to it.

### Lending rules

- **Borrow**: both IDs must be registered, and the book must not already be on loan.
- **Return**: the program looks up the book's most recent `BORROWED` entry. If there is none
  (never borrowed, or already returned), it prints an error. The member returning the book must
  be the member who borrowed it.
- **Overdue**: loans older than the loan period get an `OVERDUE` block. The book can still be
  returned afterwards.

A book's current status is **derived from the chain itself**. No separate "status" table exists
that could be edited.

---

## Security mechanisms

| Mechanism | Details |
|---|---|
| Hash chain | SHA-256 over every field; each block stores the previous block's hash |
| Digital signatures | ECDSA on curve P-256 (prime256v1), SHA-256 digest, one key pair **per user** |
| Private key protection | encrypted PKCS#8 PEM: PBES2 / PBKDF2-HMAC-SHA256 (600,000 iterations) + AES-256-CBC; file mode `0600`, `keys/` folder mode `0700` |
| Password storage | PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt per user; plain text never stored |
| Login | constant-time hash comparison; same work done for unknown usernames (no user enumeration); 3 attempts; 1 s delay after a failure; typed passwords are not shown |
| Key possession check | after login, the unlocked private key signs a random challenge that must verify with the stored public key |
| Access control | `LIBRARIAN` may borrow, return, view and validate; `ADMIN` may also add users and run the tamper demo |
| Memory hygiene | passwords and hashes are wiped with `OPENSSL_cleanse`; the signing key is freed at logout |
| Input validation | IDs limited to `[A-Za-z0-9_-]`, lengths checked (never silently truncated), `|` and control characters rejected, usernames restricted, which blocks path traversal through a forged `signed_by` |
| Build hardening | `-fstack-protector-strong`, `_FORTIFY_SOURCE=2` |

**Why signatures matter:** someone with write access to `chain.dat` could edit a block and
recompute every hash with a short script. Hashes alone would not catch that. They cannot produce
valid signatures without the librarian's private key, so the forgery is still detected. Every
signature covers `previous_hash`, so all re-linked later blocks fail too.
(`tests/forge_chain.py` performs exactly this attack in the test suite.)

`users.db`, `keys/` and `chain.dat` are listed in `.gitignore` and are **never committed**.

---

## Data persistence

All state lives in the data folder (`data/` by default):

| File | Contents |
|---|---|
| `books.txt`, `members.txt` | registries (committed to Git) |
| `chain.dat` | the blockchain, one block per line (human-readable) |
| `users.db` | usernames, roles, salts and PBKDF2 password hashes (`0600`) |
| `keys/<user>.key` | encrypted private signing key (`0600`) |
| `keys/<user>.pub` | public verification key |

The chain is written **atomically**: to `chain.dat.tmp`, then `fsync()`, then `rename()`.
A crash can never leave a half-written chain. If saving fails, the new block is also removed
from memory, so memory and disk always agree.

---

## Error handling

- Every function returns a `Status` code (`include/common.h`), and callers check it.
- Missing or empty registries produce a clear error and exit code `1`.
- A corrupted `chain.dat` (wrong format) is refused with the line number and reason (exit code `2`).
  A well-formed but **tampered** chain is loaded read-only and reported as tampered.
- Failed login gives exit code `3`.
- All user input is length-checked. Over-long input, EOF (Ctrl+D) and invalid menu choices are
  handled without crashing.
- Checked with AddressSanitizer, UndefinedBehaviorSanitizer and Valgrind (0 errors, 0 leaks).

---

## Tamper detection demo

**Inside the program (admin only): option 7.** Pick a block and choose an attack:

1. change the action (for example, mark a `BORROWED` book as `RETURNED`)
2. change the member name
3. change the action **and recompute the hash** (cover-up attempt)
4. delete the block

The program re-validates and shows exactly which check fails, then restores the original chain.
The file on disk is never modified by this demo.

**By editing the file directly:**

```bash
cp data/chain.dat /tmp/chain.backup      # keep a copy
nano data/chain.dat                      # change e.g. "John Doe" to "Jane Smith" on one line
./library_tracker                        # start-up warns: validation FAILED; option 6 shows details
cp /tmp/chain.backup data/chain.dat      # restore
```

---

## Testing

```bash
make test
```

The script `tests/run_tests.sh` runs **71 checks** against the real binary. They cover missing and
empty registries, valid and invalid IDs, lending rules, persistence across restarts, file
permissions, key encryption, login lock-out, role-based access, every in-program tamper mode,
external file edits, a full hash-recomputation forgery, a corrupted file, a path-traversal
attempt and overdue handling.

---

## Project structure

```
.
├── Makefile
├── README.md
├── data/
│   ├── books.txt              # book registry
│   └── members.txt            # member registry
├── docs/
│   ├── architecture.md        # system design diagrams (rendered by GitHub)
│   └── diagrams/              # the same diagrams as PNG images
├── include/                   # public headers (one per module)
│   ├── common.h   util.h   registry.h   crypto.h   auth.h
│   ├── keyring.h  blockchain.h   storage.h   lending.h   ui.h
├── src/
│   ├── main.c         # start-up sequence
│   ├── ui.c           # menus and output
│   ├── lending.c      # borrow / return / overdue rules
│   ├── blockchain.c   # blocks, hashing, signing, validation
│   ├── storage.c      # chain.dat load / atomic save
│   ├── registry.c     # books.txt / members.txt
│   ├── auth.c         # accounts, login, access control
│   ├── keyring.c      # public key cache for verification
│   ├── crypto.c       # OpenSSL wrappers
│   └── util.c         # strings, input, hex, time, paths
└── tests/
    ├── run_tests.sh       # end-to-end test suite
    └── forge_chain.py     # attack simulation used by the tests
```

See [`docs/architecture.md`](docs/architecture.md) for the system design diagrams.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `openssl/evp.h: No such file or directory` | `sudo apt install libssl-dev` |
| `ERROR: books.txt is missing` | run from the project root, or pass `-d path/to/data` |
| `chain.dat is corrupted` | restore your backup, or delete `data/chain.dat` to start a new chain |
| Forgot the admin password | delete `data/users.db`, `data/keys/` and `data/chain.dat` to start over |
| No colours / odd symbols | run with `NO_COLOR=1` |

---

**Author:** Noorul-Ayn · [github.com/Noorul-Ayn](https://github.com/Noorul-Ayn)
