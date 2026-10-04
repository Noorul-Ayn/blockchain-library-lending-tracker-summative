# Blockchain Library Lending Tracker v2: Tokens and Mining (C)

This is Formative 2. It extends the [Formative 1 lending tracker](https://github.com/Noorul-Ayn/blockchain-library-lending-tracker),
which records every borrow and return as a signed, SHA-256-linked block. Version 2 adds:

- **Token rewards**: returning a book creates a reward transaction (10 coins on time, 5 coins late,
  nothing if the book is never returned).
- **A pending pool**: every lending record and token transfer waits there, unconfirmed.
- **Proof-of-work mining**: solo, pool and cloud miners confirm the pending pool. A block hash must
  start with *difficulty* zero characters.
- **Two ledger models**: UTXO and account-based. You pick one for each session, and both read the
  same chain.

The full history of Formative 1 is kept in this repository, and the Formative 2 work is added on top of it.

---

## Contents

1. [What changed from Formative 1](#1-what-changed-from-formative-1)
2. [Required libraries and dependencies](#2-required-libraries-and-dependencies)
3. [Compilation instructions](#3-compilation-instructions)
4. [Running the program](#4-running-the-program)
5. [How to switch between transaction models](#5-how-to-switch-between-transaction-models)
6. [How to set the mining difficulty](#6-how-to-set-the-mining-difficulty)
7. [How to test the mining simulations](#7-how-to-test-the-mining-simulations)
8. [How lending connects to token transactions](#8-how-lending-connects-to-token-transactions)
9. [The two transaction models](#9-the-two-transaction-models)
10. [How mining confirms blocks](#10-how-mining-confirms-blocks)
11. [Security](#11-security)
12. [Data persistence](#12-data-persistence)
13. [Design choices and assumptions](#13-design-choices-and-assumptions)
14. [Automated tests](#14-automated-tests)
15. [Project structure](#15-project-structure)

---

## 1. What changed from Formative 1

| | Formative 1 | Formative 2 |
|---|---|---|
| When a block joins the chain | immediately | only after it has been **mined** from the pending pool |
| Block fields | index, timestamp, book, member, action, previous_hash, signature, hash | the same fields **plus** `token_reward`, `tx_id`, `nonce`, `difficulty`, `mined_by`, `mined_at`, and the transaction itself |
| Rewards | none | 10 coins (on time), 5 coins (late), 0 (not returned) |
| Balances | none | UTXO model or account model |
| Hash rule | any SHA-256 hash | the hash must start with *d* zeros (proof-of-work, *d* = 1–4) |
| New menu options | none | pending pool, mining (solo, pool, cloud), difficulty setting, benchmark, balances, transfers, history |

Everything from Formative 1 still works: registries, validation of IDs, ECDSA signatures, login and
roles, chain validation and the tamper demo.

---

## 2. Required libraries and dependencies

| Dependency | Why | Ubuntu package |
|---|---|---|
| GCC (C11) and GNU Make | building | `build-essential` |
| OpenSSL libcrypto 1.1.1 or 3.x | SHA-256, ECDSA, AES-256, PBKDF2, random numbers | `libssl-dev` |
| C maths library `libm` | the `pow()` and `ceil()` functions used by the mining statistics (part of glibc) | already installed |
| Python 3 *(optional)* | used only by one attack-simulation test | `python3` |

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev
```

There are no other new dependencies.

---

## 3. Compilation instructions

```bash
git clone https://github.com/Noorul-Ayn/blockchain-library-lending-tracker-v2.git
cd blockchain-library-lending-tracker-v2
make            # builds ./library_tracker  (zero warnings with -Wall -Wextra -Wpedantic)
make test       # runs the 104 automated checks
```

| Command | What it does |
|---|---|
| `make` | build `./library_tracker` |
| `make run` | build and start |
| `make test` | run `tests/run_tests.sh` |
| `make debug` | build with AddressSanitizer and UndefinedBehaviorSanitizer |
| `make clean` | remove build output |

To compile without Make:

```bash
gcc -std=c11 -Wall -Wextra -Iinclude -D_POSIX_C_SOURCE=200809L src/*.c -o library_tracker -lcrypto -lm
```

---

## 4. Running the program

```bash
./library_tracker                       # asks for the model at start-up, difficulty 2
./library_tracker --model utxo          # UTXO model
./library_tracker --model account -D 3  # account model, difficulty 3
./library_tracker --help
```

| Option | Meaning |
|---|---|
| `-m`, `--model utxo\|account` | token ledger model for this session (if omitted, a menu asks) |
| `-D`, `--difficulty 1-4` | proof-of-work difficulty (default 2) |
| `-d`, `--data-dir DIR` | data folder (default `data/`) |

| Environment variable | Meaning |
|---|---|
| `LIBRARY_LOAN_PERIOD=SECONDS` | loan period before a return counts as **late** (default 14 days). Use `30` for demos. |
| `LIBRARY_SEED=N` | fixed random seed for pool miners' hash rates, for reproducible runs |
| `NO_COLOR=1` | turn off coloured output |

**First run:** the program creates the administrator account and an ECDSA key pair, then mines the
genesis block (`previous_hash` = 64 zeros).

**Main menu:**

```
 MAIN MENU   user: admin [ADMIN]   model: UTXO   difficulty: 2
             chain: 6 block(s) VALID   pending pool: 2 block(s)
  LENDING                         BLOCKCHAIN & MINING
   1. Borrow a book                4. View pending pool
   2. Return a book (+ reward)     5. Mine pending pool (solo / pool / cloud)
   3. Mark overdue loans           6. View confirmed lending records
                                   7. Validate blockchain
  TOKENS                           8. Set mining difficulty (1-4)
  10. View balances / UTXO set     9. Difficulty benchmark
  11. Transfer tokens
  12. Member transaction history   OTHER
                                  13. View books & members
                                  14. Tamper detection demo
                                  15. Add user account
   0. Logout and exit
```

---

## 5. How to switch between transaction models

The model is chosen **once per session** and applies to every token transaction in that session.
There are two ways to choose it:

1. **Start-up menu.** Run `./library_tracker` without `--model` and pick `1` (UTXO) or `2` (account).
2. **Command-line option.** Run `./library_tracker --model utxo` or `./library_tracker --model account`.

To switch, log out (option `0`) and start the program again with the other model. Balances are never
stored in a separate file. At start-up the program **replays every confirmed transaction on the chain**
into the chosen model, so both models always show the same balances for the same chain, just organised
differently. The menu header shows which model is active.

---

## 6. How to set the mining difficulty

Difficulty is the number of leading `0` hex characters the block hash must have. It ranges from 1 to 4,
and the default is 2.

- **At start-up:** `./library_tracker -D 3`
- **During a session:** menu option `8`, then enter a number from 1 to 4.

Each extra zero makes mining about **16 times harder**:

| Difficulty | Hash must start with | Expected attempts (16^d) |
|---|---|---|
| 1 | `0` | 16 |
| 2 | `00` | 256 |
| 3 | `000` | 4,096 |
| 4 | `0000` | 65,536 |

Option `9` (**difficulty benchmark**) mines 20 sample blocks at each difficulty and shows the
average, minimum and maximum attempts and the time taken. Each block stores the difficulty it was mined
at, and validation checks that its hash really meets it.

---

## 7. How to test the mining simulations

### Quick manual walkthrough (about 3 minutes)

```bash
rm -rf data/chain.dat data/pending.dat data/users.db data/keys    # start clean
LIBRARY_LOAN_PERIOD=30 ./library_tracker --model utxo
```

1. **Create pending records:** `1` BK001 ALU001 (borrow), `2` BK001 ALU001 (on-time return, +10),
   `1` BK002 ALU002, `1` BK003 ALU003.
2. **View them:** option `4` lists 4 unconfirmed blocks. Option `10` shows every balance still at 0.
3. **Solo mining:** `5` then `1`. Each block shows its nonce, hash attempts and hash, and the full
   UTXO set is printed after every confirmed block. ALU001 now owns a 9-coin UTXO (10 − 1 fee).
4. **Late return:** wait 30 seconds, then `3` (mark overdue) and `2` BK002 ALU002 (late, +5).
   BK003 stays overdue and creates **no** transaction.
5. **Pool mining:** `5` then `2`, then press Enter for 4 miners. A table shows each miner's hash rate,
   attempts, share % and reward after the 2% pool fee.
6. **Transfer with change:** `11` ALU001 → ALU002, 3 coins, Enter (automatic inputs). This spends the
   9-coin UTXO: 3 coins go to ALU002, 5 coins come back as change, and the miner gets a 1-coin fee.
7. **Cloud mining:** `5` then `3`, then 5 rounds. Each round shows the reward, the maintenance fee
   (10%), the rental fee (15), cumulative totals and net profit. A warning appears once fees exceed rewards.
8. **Difficulty:** `8` then `4`, then `5` `3` `1`. A single rented round rarely finds a block at
   difficulty 4, so the block stays pending and the rental is unprofitable. Option `9` shows why.

### Edge cases the brief asks for

| Edge case | How to trigger it | Expected result |
|---|---|---|
| Book not returned gives no transaction | `3` mark overdue | `OVERDUE` block with token_reward 0 and no tx_id; balance unchanged |
| Insufficient balance (UTXO) | `11`, amount larger than the balance | `REJECTED (insufficient funds): inputs total X but amount + fee = Y` |
| Double spend (UTXO) | `11` twice with the same input before mining, or pick a `SPENT` output | `REJECTED (double spend)` |
| Insufficient balance (account) | run with `--model account`, then `11` | `REJECTED (insufficient funds)` |
| Wrong or reused nonce (account) | `11`, then enter a nonce other than the one shown as "next expected" | `REJECTED (invalid nonce): nonce N was already used / is out of order` |
| Unprofitable cloud rental | `5` `3` with an empty pool, or at difficulty 4 | `WARNING: rental is unprofitable after round N` |

### Automated

`make test` runs every scenario above and more (see [section 14](#14-automated-tests)).

---

## 8. How lending connects to token transactions

| Lending event | Transaction created | `token_reward` | Member receives after confirmation |
|---|---|---|---|
| Borrow | none | 0 | nothing |
| Return **on time** | REWARD, LIBRARY → member, 10 coins | 10 | **9** (10 − 1-coin fee) |
| Return **late** (after the loan period, or already marked OVERDUE) | REWARD, LIBRARY → member, 5 coins | 5 | **4** |
| Mark **overdue** (not returned) | none | 0 | nothing |
| Token transfer | TRANSFER, member → member | 0 | recipient gets the amount; the sender also pays the 1-coin fee |

The transaction travels inside the block, and its SHA-256 hash is stored in `tx_id`. The librarian's
ECDSA signature covers `token_reward` and `tx_id`, so the reward amount cannot be changed later.
**Nothing is credited until the block is mined.** Until then the record sits in the pending pool and
every balance is unchanged.

---

## 9. The two transaction models

### UTXO model (`--model utxo`)

- Every confirmed transaction creates **outputs**. A reward creates one output for the member
  (amount − fee). A transfer creates `vout 0` for the recipient and `vout 1` with the **change** back
  to the sender.
- A transfer **spends whole previous outputs as its inputs**. You can choose them yourself (for example
  `1,2`) or press Enter for automatic oldest-first selection.
- The transfer is **rejected** if the inputs don't cover amount + fee.
- A member's **balance = the sum of their unspent outputs**.
- **Double spending is blocked** in three places:
  1. an output that has already been spent is refused;
  2. an output already used by a pending transaction is reserved and can't be used again;
  3. replaying the chain re-checks every input.
- After **every confirmed block**, the full UTXO set is printed, showing each output, its owner, amount
  and the block that created it.

### Account model (`--model account`)

- Each member is an **account** holding a balance and a **nonce**. A confirmed block debits and
  credits balances directly.
- A transfer must use the sender's next nonce, which is the account nonce plus the number of transfers
  already pending. A **reused or out-of-order nonce is rejected**, and so is a transfer the balance
  can't cover.
- Each account keeps a **transaction history as a linked list** in memory. Each node records the
  sender, recipient, amount, fee, nonce and block. Option `12` prints it for any member.

### Comparison

| | UTXO | Account-based |
|---|---|---|
| What is stored | individual coins (outputs) | one balance per member |
| Balance | computed: sum of unspent outputs | read directly |
| Spending | whole outputs as inputs, plus change | debit the balance |
| Double-spend / replay protection | an output can be spent only once | the nonce must increase by exactly 1 |
| History | follow outputs from one transaction to the next | linked list per account |
| Strengths | easy to verify in parallel; good privacy | simple, compact, intuitive |
| Used by | Bitcoin | Ethereum |

---

## 10. How mining confirms blocks

1. Every borrow, return, overdue mark or transfer is **signed** by the logged-in librarian and placed in
   the **pending pool** (`data/pending.dat`), in order.
2. The miner takes the pending blocks one at a time and links each to the chain tip by setting its
   `index` and `previous_hash`.
3. **Proof-of-work:** starting from nonce 0, the miner computes
   `hash = SHA-256(index | record | signature | previous_hash | difficulty | mined_by | mined_at | nonce)`
   and keeps incrementing the nonce until the hash starts with *difficulty* zeros. The number of
   attempts is reported.
4. `library_confirm()` re-checks the signature and the transaction, **applies the transaction to the
   ledger** (this is when balances change), appends the block to `chain.dat` and removes it from
   `pending.dat`. A pending record that fails these checks (for example a tampered signature, or a
   double spend) is **rejected** and removed.

### Mining approaches

Reward per confirmed block = **20 coins + the block's transaction fee**.

| | How the work is done | How the reward is paid |
|---|---|---|
| **Solo** | one miner tries nonces 0, 1, 2, … | the miner receives the full reward |
| **Pool** | 2–8 miners, each with a random hash rate of 100–600 attempts per round, search separate nonce ranges (miner *k* starts at *k* × 2^40). The first to find a valid hash wins the block, and every miner is credited with the work it did up to that moment. | 2% pool fee first, then `share = miner_attempts / total_attempts`, `reward = share × (gross − pool fee)` |
| **Cloud** | the user rents 600 attempts per round for 1–5 rounds. A block can be mined across several rounds. | each round: reward credited minus a 10% maintenance fee; a 15-coin rental fee is paid every round. The summary shows gross earnings, total fees and net profit, with a warning whenever cumulative fees exceed cumulative rewards. |

---

## 11. Security

Everything from Formative 1 is kept:

- SHA-256 hash chain
- ECDSA P-256 signatures, with one key pair per user
- encrypted PKCS#8 private keys (600,000 PBKDF2 iterations, AES-256), with `0600` / `0700` permissions
- salted PBKDF2 password hashes
- role-based access control
- input validation and atomic saves

New in Formative 2:

- **Proof-of-work:** rewriting a block means redoing its proof-of-work **and that of every later block**.
  Option `14` → `4` performs exactly this rewrite and reports how many hash attempts it took.
- **Transaction integrity:** `tx_id` must equal SHA-256(transaction), and the reward must match the
  action. Tampering is detected at validation.
- **Signatures still decide:** even a fully re-mined chain is detected, because the edited record's
  ECDSA signature no longer verifies. `tests/forge_chain.py` performs this attack.
- **Ledger replay:** validation (option `7`) also replays every transaction to prove there are no
  double spends, overspending or bad nonces anywhere in history.
- **Pending records** are signature-checked before mining, so a tampered pending record is rejected.

---

## 12. Data persistence

| File | Contents |
|---|---|
| `data/chain.dat` | confirmed blocks, one per line (format v2, 18 fields including `token_reward`, `tx_id`, the transaction, `difficulty` and `nonce`) |
| `data/pending.dat` | the pending pool, in the same format; survives restarts |
| `data/users.db`, `data/keys/` | accounts and encrypted signing keys (never committed) |

Both files are saved **atomically** (temporary file, `fsync()`, `rename()`). If the program stops
between saving the chain and saving the pool, it removes the duplicate pending record on the next start.
Balances are never stored; they are rebuilt from the chain at start-up. A Formative 1 (`v1`) chain
file is recognised and reported clearly.

---

## 13. Design choices and assumptions

- **One record per block.** This keeps the Formative 1 block structure, as the brief asks. Mining the
  pool confirms each pending record as its own proof-of-work block, in order.
- **"Late" means** the return happened after the loan period (14 days by default) or the book had
  already been marked OVERDUE.
- **Rewards are issued by `LIBRARY`.** They work like a coinbase transaction, with no inputs. The
  1-coin fee is deducted before the member is credited.
- **Fees and mining rewards go to miners.** Miners are not library members, so their earnings are
  reported by each mining run and not added to member balances. The ledger accounts are the member IDs
  from the registry, as required.
- **The librarian signs transfers on the member's behalf.** Members don't have keys of their own,
  so the logged-in staff member's ECDSA key signs the record.
- **Both models read the same chain.** Transactions are stored in a model-neutral form. UTXO inputs
  are stored when the transfer was made under the UTXO model; for account-model transfers they are
  chosen when the chain is replayed.
- **Fixed economic constants:** block reward 20, transaction fee 1, pool fee 2%, cloud power 600
  attempts per round, rental 15, maintenance 10%. They are all defined in `include/common.h`.
- **Difficulty is a session setting.** Each block records the difficulty it was mined at, and
  validation checks it.

---

## 14. Automated tests

`make test` runs **104 checks** against the real program:

| Area | Checks |
|---|---|
| Registries and command-line options | missing or empty files, invalid lines, bad `--model` and `--difficulty` |
| Pending pool | records wait unconfirmed, survive a restart and are confirmed by mining; genesis hash meets the difficulty |
| Rewards | on-time 10 (credited 9), late 5 (credited 4), overdue gives no transaction, nothing credited before mining |
| UTXO | change output, reserved-output double spend, spent-output double spend, insufficient inputs, UTXO set after every block |
| Account | same balances as UTXO, reused nonce, out-of-order nonce, insufficient balance, pending nonces, linked-list history |
| Mining | solo attempts and reward, pool table with 2% fee and shares totalling 100%, cloud summary, unprofitable warning, difficulty 1–4, benchmark |
| Security | key permissions and encryption, lock-out, librarian access denied |
| Tampering | in-memory demo (5 attacks), edited chain file, inflated reward, fully re-mined forgery, tampered pending record, v1 file, path traversal |

Memory safety: no errors under AddressSanitizer, UndefinedBehaviorSanitizer and Valgrind (0 bytes in
use at exit, including every linked-list history node).

---

## 15. Project structure

```
include/  src/
  common.h                 constants (rewards, fees, difficulty, pool and cloud settings)
  transaction.h/.c         REWARD / TRANSFER transactions, tx_id = SHA-256(tx)     [new]
  utxo.h/.c                UTXO set, inputs, change, double-spend checks           [new]
  account.h/.c             accounts, nonces, linked-list history                   [new]
  ledger.h/.c              selects the UTXO or account model                       [new]
  mining.h/.c              solo, pool and cloud mining; difficulty benchmark       [new]
  blockchain.h/.c          block layout, proof-of-work, signing, validation        [updated]
  lending.h/.c             borrow / return / overdue, rewards, transfers, confirm  [updated]
  storage.h/.c             chain.dat and pending.dat (format v2)                   [updated]
  ui.h/.c, main.c          menus, tables, start-up                                 [updated]
  registry, auth, keyring, crypto, util                                            [Formative 1]
data/        books.txt, members.txt
docs/        architecture.md, diagrams/*.png
tests/       run_tests.sh (104 checks), forge_chain.py (re-mining attack)
```

Design diagrams: [`docs/architecture.md`](docs/architecture.md).

---

**Author:** Hauwa Muhammad Bello ([Noorul-Ayn](https://github.com/Noorul-Ayn)), Blockchain Development, Individual Formative 2
