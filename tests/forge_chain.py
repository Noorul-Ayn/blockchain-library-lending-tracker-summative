#!/usr/bin/env python3
"""
Attack simulation used by run_tests.sh.

Edits one block of chain.dat and then RECOMPUTES the SHA-256 hash of that
block and of every block after it, re-linking previous_hash values so that
hash and link checks all pass. This models a skilled attacker with write
access to the file but WITHOUT the librarian's private key.

The program must still detect the forgery because the ECDSA signature of
the edited block no longer verifies.

usage: forge_chain.py CHAIN_FILE BLOCK_INDEX NEW_ACTION
"""
import hashlib
import sys

# Column order in chain.dat
IDX, TS, BOOK_ID, TITLE, MEMBER_ID, MEMBER_NAME, ACTION, SIGNED_BY, PREV, SIG, HASH = range(11)


def block_hash(f):
    # Must mirror block_payload() + block_compute_hash() in src/blockchain.c
    payload = "|".join([f[IDX], f[TS], f[BOOK_ID], f[TITLE], f[MEMBER_ID],
                        f[MEMBER_NAME], f[ACTION], f[PREV], f[SIGNED_BY]])
    return hashlib.sha256((payload + "|" + f[SIG]).encode("utf-8")).hexdigest()


def main():
    path, target, new_action = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    header = [l for l in lines if l.startswith("#")]
    blocks = [l.split("|") for l in lines if l and not l.startswith("#")]

    blocks[target][ACTION] = new_action
    for i in range(target, len(blocks)):
        if i > 0:
            blocks[i][PREV] = blocks[i - 1][HASH]
        blocks[i][HASH] = block_hash(blocks[i])

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(header + ["|".join(b) for b in blocks]) + "\n")


if __name__ == "__main__":
    main()
