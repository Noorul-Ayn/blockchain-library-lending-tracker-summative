#!/usr/bin/env python3
"""
Attack simulation used by run_tests.sh (chain format v2, with proof-of-work).

Edits one confirmed block of chain.dat (the borrower's name) and then
RE-MINES that block and every block after it: it re-links previous_hash,
searches for a new nonce that satisfies the block's difficulty and stores
the new hash. This models an attacker with write access to the file and
enough computing power, but WITHOUT the librarian's private key.

Hashes, links and proof-of-work all look valid afterwards; the program must
still detect the forgery because the ECDSA signature of the edited record
no longer verifies.

usage: forge_chain.py CHAIN_FILE BLOCK_INDEX NEW_MEMBER_NAME
"""
import hashlib
import sys

# Column order in chain.dat (v2)
(IDX, TS, BOOK_ID, TITLE, MEMBER_ID, MEMBER_NAME, ACTION, REWARD, TX_ID, TX, SIGNED_BY,
 SIG, DIFFICULTY, NONCE, MINED_BY, MINED_AT, PREV, HASH) = range(18)


def header_prefix(f):
    """Mirrors record_payload() + header_prefix() in src/blockchain.c."""
    record = "|".join([f[TS], f[BOOK_ID], f[TITLE], f[MEMBER_ID], f[MEMBER_NAME], f[ACTION],
                       f[REWARD], f[TX_ID], f[SIGNED_BY]])
    return "|".join([f[IDX], record, f[SIG], f[PREV], f[DIFFICULTY], f[MINED_BY],
                     f[MINED_AT]]) + "|"


def mine(f):
    prefix = header_prefix(f).encode()
    target = "0" * int(f[DIFFICULTY])
    nonce = 0
    while True:
        h = hashlib.sha256(prefix + str(nonce).encode()).hexdigest()
        if h.startswith(target):
            f[NONCE], f[HASH] = str(nonce), h
            return nonce + 1
        nonce += 1


def main():
    path, target, new_name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    header = [l for l in lines if l.startswith("#")]
    blocks = [l.split("|") for l in lines if l and not l.startswith("#")]

    blocks[target][MEMBER_NAME] = new_name
    attempts = 0
    for i in range(target, len(blocks)):
        if i > 0:
            blocks[i][PREV] = blocks[i - 1][HASH]
        attempts += mine(blocks[i])

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(header + ["|".join(b) for b in blocks]) + "\n")
    print(f"re-mined {len(blocks) - target} block(s) with {attempts} attempts")


if __name__ == "__main__":
    main()
