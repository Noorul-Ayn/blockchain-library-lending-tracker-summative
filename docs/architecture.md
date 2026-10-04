# System Design (v2: tokens and mining)

This document shows how Formative 2 extends the Formative 1 design. Lending actions now create
token transactions, every record waits in a **pending pool**, and mining with **proof-of-work**
is the step that confirms a record and updates the members' balances. GitHub renders the diagrams
below; PNG versions are in [`docs/diagrams/`](diagrams/).

## 1. Block structure

```mermaid
classDiagram
    class Block {
        int index
        time_t timestamp
        char book_id[20]
        char book_title[80]
        char member_id[20]
        char member_name[50]
        char action[10]
        int token_reward  NEW_IN_F2
        char tx_id[65]  NEW_IN_F2
        Transaction tx  NEW_IN_F2
        char previous_hash[65]
        unsigned char signature[72]
        size_t signature_len
        char signed_by[20]
        int difficulty  POW
        unsigned_long_long nonce  POW
        char mined_by[32]
        time_t mined_at
        char hash[65]
    }
    class Transaction {
        TxType type  REWARD or TRANSFER
        char from[20]
        char to[20]
        long amount
        long fee
        long nonce
        time_t timestamp
        char ref[20]
        TxInput inputs[16]
    }
    class Blockchain {
        Block* blocks
        size_t length
        size_t capacity
    }
    Blockchain "1" o-- "many" Block : confirmed chain
    Blockchain "1" o-- "many" Block : pending pool
    Block *-- Transaction : tx_id = SHA-256(tx)
```

## 2. From lending action to confirmed block

```mermaid
flowchart TD
    A[/"Librarian: borrow, return,<br/>mark overdue or transfer"/] --> V{"IDs in registries?<br/>Chain valid?<br/>Rules allow it?"}
    V -->|no| E["Error - nothing recorded"]
    V -->|yes| K{"Which action?"}
    K -->|"BORROWED"| N0["No transaction<br/>token_reward = 0"]
    K -->|"RETURNED on time"| R10["REWARD tx: 10 coins<br/>(member gets 9 after 1-coin fee)"]
    K -->|"RETURNED late"| R5["REWARD tx: 5 coins<br/>(member gets 4)"]
    K -->|"OVERDUE (not returned)"| N1["No transaction<br/>token_reward = 0"]
    K -->|"TRANSFER"| T["TRANSFER tx<br/>checked by the session's model"]
    N0 & R10 & R5 & N1 & T --> S["Record signed with the librarian's ECDSA key<br/>tx_id = SHA-256(transaction)"]
    S --> P[("PENDING POOL<br/>pending.dat")]
    P --> M{{"Mining: solo / pool / cloud"}}
    M --> W["Link to chain tip: index, previous_hash<br/>increment nonce until SHA-256 starts with d zeros"]
    W --> C["library_confirm:<br/>verify signature + tx, apply tx to the ledger"]
    C --> CH[("CONFIRMED CHAIN<br/>chain.dat")]
    C --> L["Balances updated<br/>(UTXO set or accounts)"]
```

## 3. Chain linkage with proof-of-work

```mermaid
flowchart LR
    G["<b>#0 GENESIS</b><br/>prev = 000...000<br/>nonce 6<br/>hash = <b>00</b>3e9d..."]
    B1["<b>#1 BORROWED</b><br/>BK001 / ALU001<br/>reward 0<br/>prev = 003e9d...<br/>nonce 235<br/>hash = <b>00</b>f2b8..."]
    B2["<b>#2 RETURNED</b><br/>BK001 / ALU001<br/>reward 10, tx_id e71d...<br/>prev = 00f2b8...<br/>nonce 519<br/>hash = <b>00</b>7a50..."]
    B3["<b>#3 TRANSFER</b><br/>ALU001 to ALU002<br/>3 coins + 1 fee<br/>prev = 007a50...<br/>nonce 402<br/>hash = <b>00</b>65ab..."]
    G --> B1 --> B2 --> B3
```

`hash = SHA-256(index | record | signature | previous_hash | difficulty | mined_by | mined_at | nonce)`.
Changing any past block changes its hash, so its proof-of-work and every later link have to be
redone, and its signature fails regardless.

## 4. The two ledger models

```mermaid
flowchart LR
    subgraph UTXO["UTXO model"]
        U1["REWARD tx e71d<br/>out 0: ALU001 9"] -->|"spent as input"| U2["TRANSFER tx 1044<br/>in: e71d:0 (9)<br/>out 0: ALU002 3<br/>out 1: ALU001 5 (change)<br/>fee 1 to miner"]
        U2 --> U3[("UTXO set<br/>1044:0 ALU002 3<br/>1044:1 ALU001 5")]
    end
    subgraph ACC["Account model"]
        A1["ALU001<br/>balance 9, nonce 0"] -->|"TRANSFER nonce 0<br/>-3 -1 fee"| A2["ALU001<br/>balance 5, nonce 1"]
        A2 --> H["history (linked list)<br/>REWARD +9 -> TRANSFER -4 -> NULL"]
    end
```

## 5. Mining approaches

```mermaid
flowchart TD
    PP[("Pending pool")] --> SOLO & POOL & CLOUD
    SOLO["<b>Solo</b><br/>one miner, nonce 0,1,2...<br/>until hash meets difficulty"] --> SR["miner gets 20 per block + fees"]
    POOL["<b>Pool</b><br/>2-8 miners, random hash rate<br/>each round every miner hashes<br/>its own nonce range"] --> PR["2% pool fee, then<br/>share = attempts / total attempts"]
    CLOUD["<b>Cloud</b><br/>rented 600 attempts per round<br/>for 1-5 rounds"] --> CR["each round: reward - 10% maintenance<br/>minus 15-coin rental<br/>warning when fees > rewards"]
```

## 6. Module dependencies

```mermaid
flowchart TD
    main --> ui
    ui --> mining
    ui --> lending
    mining --> lending
    lending --> ledger
    lending --> blockchain
    lending --> registry
    lending --> storage
    ledger --> utxo
    ledger --> account
    utxo --> transaction
    account --> transaction
    blockchain --> transaction
    blockchain --> crypto
    blockchain --> keyring
    storage --> blockchain
    keyring --> auth
    auth --> crypto
    transaction --> crypto
    crypto --> OpenSSL[(OpenSSL libcrypto)]
```
