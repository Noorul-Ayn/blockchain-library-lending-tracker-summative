# Blockchain Library Lending Tracker: Summative

A C implementation of a tamper-evident lending ledger for the ALU library. It brings together the work of the trimester:

- **Formative 1:** registries, SHA-256 hash chain, ECDSA signatures, validation and the CLI.
- **Formative 2:** token rewards, the pending pool, proof-of-work mining, and the UTXO and account ledgers.

It adds the summative extensions:

- **Copies and lending rules:** copy-level inventory with a state machine, FIFO reservation queues, renewals, and overdue detection with fines.
- **Blocks:** blocks of several records sealed by a from-scratch **Merkle tree**.
- **Signatures and replay protection:** a real **ECDSA P-256 key pair for every member**, and nonce-based replay protection.
- **Fraud review:** fraud heuristics with a manual review step.
- **Persistence:** full disk persistence, with mandatory validation after loading.

Author: Hauwa Muhammad Bello (GitHub: Noorul-Ayn). Course: Introduction to Blockchain Development, ALU.

---

## 1. Requirements

| Dependency | Version | Ubuntu / WSL package |
|---|---|---|
| GCC (or Clang) | C11 | `build-essential` |
| GNU Make | any | `build-essential` |
| OpenSSL libcrypto | **3.0 or newer** | `libssl-dev` |

```bash
sudo apt update
sudo apt install build-essential libssl-dev
openssl version          # must print OpenSSL 3.x
```

Only libcrypto is used: SHA-256, ECDSA, PBKDF2, AES-GCM and random bytes. The Merkle tree, mining, ledgers and everything else are written from scratch.

## 2. Build, run and test

```bash
make                 # builds ./library_tracker with -Wall -Wextra -Wpedantic (no warnings)
./library_tracker    # starts the CLI with the data in ./data
make test            # builds, then runs the end-to-end test suite (144 checks)
make debug           # AddressSanitizer + UndefinedBehaviorSanitizer build
make clean
```

To compile by hand without the Makefile:

```bash
gcc -std=c11 -Wall -Wextra -Iinclude -D_POSIX_C_SOURCE=200809L src/*.c -o library_tracker -lcrypto -lm
```

### First run

1. The program loads `books.txt`, `copies.txt` and `members.txt`. If any is missing or empty, it stops with an error.
2. With no staff accounts yet, you create the **administrator** (username + password). This generates:
   - the administrator's own ECDSA key pair, stored encrypted with the password;
   - a random 256-bit **key-vault key**. Each member's private key is encrypted under it, and the vault key itself is stored only wrapped with the staff password (PBKDF2-HMAC-SHA256, 600,000 iterations, then AES-256-GCM).
3. You log in. Logging in also unlocks the key vault. Then **an ECDSA P-256 key pair is generated for every member** who doesn't have one.
4. You choose the ledger model, and the genesis block is mined.
5. At the `library>` prompt, run **`validate_chain`**. Every other command is refused until the loaded chain has been validated in this session.

Type `help` for the command list, or `help <command>` for one command. A missing argument is asked for interactively. Wrap values that contain spaces in quotes: `register_member ALU006 "Grace Okafor" BLK101`.

## 3. Switching between the UTXO and account models

The model is chosen once per session and applies to every token transaction in it:

```bash
./library_tracker -m utxo       # UTXO model
./library_tracker -m account    # account-balance model
./library_tracker               # asks at start-up (1 = UTXO, 2 = account)
```

Both models replay the same chain: transactions are stored in a model-neutral form, so one chain can be opened in either model.

- **UTXO model**
  - `token_transfer` spends whole outputs. You can choose the inputs (`txid:vout`), or let the program pick the oldest first.
  - Any excess comes back as a change output; insufficient inputs are rejected.
  - An output already reserved by a pending transaction cannot be spent again, so double spending is impossible.
  - `utxo_view` shows the full UTXO set, which is also printed after every confirmed block.
- **Account model**
  - `account_transfer <from> <to> <amount> [nonce]` checks the balance and the account nonce. A reused or skipped nonce is rejected.
  - `transaction_history <member>` prints the member's history, kept as a linked list in memory.

## 4. Setting the mining difficulty

The difficulty is the number of leading zero hex characters the block hash needs (1–4):

```bash
./library_tracker -D 3          # start with difficulty 3 (saved in state.dat)
```

Inside the CLI:

```
set_difficulty 4                # change it
difficulty_status               # current target and expected attempts (16^d)
difficulty_benchmark            # mines sample blocks at difficulty 1-4 and compares the work
```

## 5. Testing the mining simulations

Requests have to be in the pending pool first, so borrow or return something:

```
validate_chain
borrow_book BK001 ALU001
borrow_book BK002 ALU002
pool_view                       # prioritised pool, and which block each request goes into
mine_solo                       # one miner; shows nonce, hash attempts and the full reward
borrow_book BK003 ALU003
mine_pool 4                     # 4 miners, random hash rates, 2% pool fee, reward-sharing table
borrow_book BK005 ALU004
mine_cloud 3                    # rent 600 attempts/round for 3 rounds: gross, fees, net, warnings
```

- `LIBRARY_SEED=42 ./library_tracker` fixes the random hash rates of pool miners, so runs are reproducible.
- At difficulty 3 or 4, a cloud rental of a few rounds may not finish a block. The earnings table then shows the fees-exceed-rewards warning.

## 6. Command reference

| Group | Commands |
|---|---|
| Membership | `register_member`, `view_member [id]`, `member_nonce <id>` |
| Books and copies | `register_book`, `view_book [id]`, `add_copy <book> [NEW\|GOOD\|WORN]`, `view_copy [copy]`, `mark_lost <copy> <REASON>` |
| Lending | `borrow_book <book\|copy> <member> [YYYY-MM-DD]`, `return_book <copy> [condition] [REASON]`, `renew_book <copy>`, `reserve_book <book> <member>`, `reservation_status [book]` |
| Fines and overdue | `check_overdue`, `view_fines [member]`, `settle_fine <member> [amount\|all] [tokens\|cash]` |
| Tokens and ledgers | `token_transfer`, `token_balance`, `utxo_view`, `account_balance`, `account_transfer`, `account_nonce`, `transaction_history <member>` |
| Blockchain and mining | `pool_view`, `mine_solo [blocks]`, `mine_pool [miners] [blocks]`, `mine_cloud <rounds>`, `chain_view [index]`, `validate_chain`, `chain_save`, `chain_load`, `difficulty_status`, `set_difficulty`, `difficulty_benchmark`, `merkle_tree <block>`, `merkle_proof <block> <record>` |
| Fraud and audit | `fraud_review`, `approve_suspicious <id>`, `reject_suspicious <id>`, `lending_history`, `member_history <id>`, `book_history <id>`, `tamper_demo`, `replay_request <record>` |
| Session | `whoami`, `add_user`, `advance_clock <days>`, `help`, `exit` |

**Role restrictions.** Librarians can do everything except the administrator tools: `approve_suspicious`, `reject_suspicious`, `add_user`, `advance_clock`, `tamper_demo` and `replay_request`.

**Command-line options:**

| Option | Effect |
|---|---|
| `-d DIR` | data folder |
| `-m utxo\|account` | ledger model |
| `-D 1-4` | difficulty |
| `--loan-days N` | loan period (default 14) |
| `--renewal-days N` | renewal period (default 7) |
| `--max-renewals N` | renewals allowed (default 2) |
| `--max-loans N` | the EXCESSIVE_BORROWS limit (default 3) |
| `--block-size N` | records per block (default 4) |

**Simulated clock.** `advance_clock <days>` moves the library's clock forward, so you can demonstrate overdue detection without waiting two weeks. The offset is saved, and real time is not changed.

## 7. How it works (summary)

- **Records and signatures.** Every action is a *lending record*: BORROWED, RETURNED, RESERVED, RENEWED, OVERDUE, LOST, TRANSFER or FINE_PAID.
  - Each record is signed with ECDSA P-256 by the member it concerns. Overdue flags, lost copies and cash fines are signed by the librarian instead.
  - Each record carries the signer's compressed public key, which is the signer's identity on the chain.
- **Pending pool.** A new request gets the signer's next nonce, is checked against the *projected* state (the confirmed chain plus every pending request), signed, verified, run through the fraud heuristics, and stored in `pending.dat`.
- **Mining.** The pool is sorted: overdue-related requests first, then by reservation date, then by arrival. The miner takes the top **4** requests (fixed-size batches), re-verifies every signature and re-applies every rule, then does the proof-of-work.
- **Block contents.** A block stores `index, timestamp, record_count, previous_hash, merkle_root, sealed_by, token_reward, transaction_id, difficulty, nonce, hash`.
  - `transaction_id` is the SHA-256 of the block's reward transaction. That transaction is derived from its RETURNED records: 10 coins on time, 5 late, minus a 1-coin fee per output.
- **Copy states.** Copies move AVAILABLE → BORROWED → AVAILABLE, or → RESERVED when someone is queued. AVAILABLE or BORROWED copies can become LOST, with a reason code. Any other transition is rejected.
- **Fraud heuristics.** These requests are marked SUSPICIOUS and never mined until an administrator approves or rejects them:
  - more than the maximum number of concurrent loans;
  - re-borrowing the same title within 24 hours;
  - a duplicate `request_id` (for example a replay);
  - a condition downgrade of more than one level without a reason code.
- **Validation.** `validate_chain` checks, for every block: links, recomputed block hashes, proof-of-work, Merkle roots, reward transactions, strictly increasing timestamps and every ECDSA signature. It then replays every record through the lending rules, compares `state.dat` with the state rebuilt from the chain, and checks the recorded chain length and tip hash. Deleted or rewritten newest blocks are reported.

### System design diagrams (`docs/diagrams/`)

1. `1-blockchain-merkle-structure.png`: block header fields, hash links and the Merkle tree of a block
2. `2-pending-pool-flow.png`: request validation, signing, prioritisation and fraud flagging
3. `3-copy-state-machine-and-queue.png`: copy states and the FIFO reservation queue
4. `4-token-reward-flow.png`: from a return to the reward transaction and the balance update
5. `5-mining-workflow.png`: difficulty, block assembly and the solo / pool / cloud paths
6. `6-fraud-detection-pipeline.png`: heuristics, SUSPICIOUS status and the admin review

The diagram sources are in `docs/diagrams_src/` (HTML, rendered with a headless browser).
Details and test results are in the technical report.

## 8. Files

```
data/books.txt      book_id,title,author                  (Formative 1 format)
data/members.txt    member_id,full_name,course_code       (Formative 1 format)
data/copies.txt     copy_id,book_id,condition             e.g. BK001-C1,BK001,NEW
data/chain.dat      the blockchain        (plain text, '|' separated, format v3)
data/pending.dat    the pending pool
data/state.dat      settings + snapshot of inventory, queues, nonces, fines, UTXO/balances
data/users.db       staff accounts (salted PBKDF2 hashes)
data/keys/          staff keys, wrapped vault keys, keys/members/<id>.key|.pub
```

- Every save is atomic: the program writes `<file>.tmp`, calls `fsync`, then renames it over the old file.
- `chain.dat`, `pending.dat`, `state.dat`, `users.db` and `keys/` are created by the program and are **not committed**.
- To start a completely fresh library, delete them; your registry files are kept.

**Project layout:**

```
include/  src/         C modules (one header per module)
tests/run_tests.sh     end-to-end tests      tests/fixtures/   pristine sample data
docs/                  system design diagrams
```

## 9. Known limitations

- **Tamper evidence is local.** This is a single-node simulation: there is no network of peers holding copies of the chain. An attacker who controls the whole data folder, including the public-key files and `state.dat`, could rebuild a consistent forgery. Here, tampering is *detected*, not *prevented*.
- **The key vault is custodial.** Members do not hold their own keys: the library holds them, encrypted, in the vault, which unlocks when staff log in.
- **Mining rewards are reported, not paid.** Miners are simulated nodes, not members, so their rewards are not added to member balances.
