# System Design

This document shows the block structure, how blocks are linked, and how the registries connect
to the lending flow. GitHub renders the diagrams below automatically. PNG versions are in
[`docs/diagrams/`](diagrams/) for use in reports.

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
        char previous_hash[65]
        unsigned char signature[72]
        size_t signature_len
        char signed_by[20]
        char hash[65]
    }
    class Blockchain {
        Block* blocks
        size_t length
        size_t capacity
    }
    class Book {
        char book_id[20]
        char title[80]
        char author[50]
    }
    class Member {
        char member_id[20]
        char full_name[50]
        char course_code[10]
    }
    Blockchain "1" o-- "many" Block : dynamic array
    Block ..> Book : book_id, title copied from
    Block ..> Member : member_id, name copied from
```

## 2. Chain linkage

Each block stores the hash of the block before it. Changing any field of block *n* changes its
hash, so block *n+1*'s `previous_hash` no longer matches. Recomputing the hashes does not help
the attacker, because each block is also signed with the librarian's private key.

```mermaid
flowchart LR
    G["<b>Block 0 - GENESIS</b><br/>previous_hash = 000...000<br/>signature = Sig(admin)<br/>hash = H0"]
    B1["<b>Block 1 - BORROWED</b><br/>BK001 / ALU001<br/>previous_hash = H0<br/>signature = Sig(admin)<br/>hash = H1"]
    B2["<b>Block 2 - RETURNED</b><br/>BK001 / ALU001<br/>previous_hash = H1<br/>signature = Sig(librarian1)<br/>hash = H2"]
    B3["<b>Block 3 - BORROWED</b><br/>BK002 / ALU003<br/>previous_hash = H2<br/>signature = Sig(admin)<br/>hash = H3"]
    G -->|H0| B1 -->|H1| B2 -->|H2| B3
```

How the values are computed:

```
payload   = index|timestamp|book_id|book_title|member_id|member_name|action|previous_hash|signed_by
signature = ECDSA-P256-SHA256(payload, librarian private key)
hash      = SHA-256(payload | hex(signature))
```

## 3. Registry to lending flow

```mermaid
flowchart TD
    Start([Program start]) --> LoadReg["Load books.txt and members.txt<br/>into Book[] and Member[] arrays"]
    LoadReg -->|missing or empty| ExitErr([Print error and exit])
    LoadReg --> LoadChain["Load chain.dat"]
    LoadChain --> Login["Login: PBKDF2 password check<br/>+ decrypt ECDSA private key"]
    Login -->|3 failures| ExitAuth([Exit])
    Login --> Validate0["Validate whole chain"]
    Validate0 --> Menu{{Main menu}}

    Menu -->|Borrow / Return| Input[/"Enter book_id and member_id"/]
    Input --> Lookup{"Both IDs in<br/>registries?"}
    Lookup -->|no| NotFound["ERROR: Book or Member not found<br/>(no block created)"]
    Lookup -->|yes| ChainOK{"Chain valid?"}
    ChainOK -->|no| Refuse["Refuse: chain is tampered"]
    ChainOK -->|yes| State{"Book state derived<br/>from the chain"}
    State -->|borrow while on loan,<br/>return with no BORROWED,<br/>return by wrong member| RuleErr["Rule error"]
    State -->|allowed| Build["Build block: copy title and name<br/>from registries, previous_hash = tip hash"]
    Build --> Sign["Sign with the user's ECDSA key"]
    Sign --> Hash["Compute SHA-256 hash"]
    Hash --> Append["Append to chain"]
    Append --> Save["Atomic save: tmp file, fsync, rename"]
    Save -->|fails| Rollback["Remove block from memory"]
    Save --> Menu

    Menu -->|Validate| V["For each block check:<br/>index, hash, previous_hash, signature"]
    Menu -->|Tamper demo| T["Modify a block in memory, re-validate,<br/>show detection, restore"]
```

## 4. Module dependencies

```mermaid
flowchart TD
    main --> ui
    ui --> lending
    ui --> auth
    lending --> blockchain
    lending --> registry
    lending --> storage
    blockchain --> crypto
    blockchain --> keyring
    storage --> blockchain
    keyring --> auth
    auth --> crypto
    crypto --> OpenSSL[(OpenSSL libcrypto)]
```
