"""Running era 0's ceremony, and checking one that somebody else ran.

Two rounds, and the order matters:

  1. every holder generates the keys for its own slice from its own secret and
     publishes the public leaves, which fixes its contribution digest;
  2. the leaves are assembled in index order into one tree, and *then* every
     holder signs a claim to its slice that names the resulting era root.

A holder that signed in round one would be vouching for its own slice in
isolation — which is the thing that needs no vouching, since the leaves speak
for themselves. Signing the root is what makes the set of claims an attestation
to *this* pool, with this concentration, rather than a pile of unrelated
statements the drafter arranged afterwards.

In a deployment each round happens on a different machine per holder and the
seeds never meet. `run()` does all of it in one process, which is what a
simulation, a test and the repository's own shipped document need; the seeds it
is handed are the only thing that makes that a demonstration rather than a
launch.
"""
from __future__ import annotations

import json

from .contrib import (Contribution, ContributedEra, ContributionError,
                      HolderSlice, assemble, check_coverage, deal, leaf_digest,
                      pub_seed_for, shares, slices_for)
from .params import HardeningParams


def era0_fields(era: ContributedEra, contributions) -> dict:
    """The block a genesis document carries."""
    return {
        "root": era.root.hex(),
        "pub_seed": era.pub_seed.hex(),
        "tree_height": era.tree_height,
        "turns": era.turns,
        "scheme": era.scheme,
        "contributions": [list(c.as_tuple()) for c in
                          sorted(contributions, key=lambda c: c.first)],
    }


def _slice_leaves(job):
    """One holder's leaves, as hex. Top-level so it can cross a process
    boundary: a 70,000-turn era is 66 s of hashing in one process and the
    holders are independent by construction, which is the whole point of the
    ceremony — in a deployment these run on different machines anyway."""
    holder, first, count, seed_hex, pub_hex = job
    s = HolderSlice(holder, first, count, bytes.fromhex(seed_hex),
                    bytes.fromhex(pub_hex))
    return holder, [leaf.hex() for leaf in s.leaves()]


def run_parallel(network: str, first_seed: str, holders,
                 hardening: HardeningParams, seed_of, signer_of,
                 era_id: int = 0, jobs: int | None = None):
    """`run`, with round one spread across processes. Same output, and the
    result is checked against the sequential digests as it is assembled."""
    import multiprocessing

    pub_seed = pub_seed_for(network, first_seed, era_id)
    parts = deal(holders, hardening.turns)
    with multiprocessing.Pool(jobs or min(len(parts),
                                          multiprocessing.cpu_count())) as pool:
        done = dict(pool.map(_slice_leaves,
                             [(h, f, c, seed_of(h).hex(), pub_seed.hex())
                              for h, f, c in parts]))
    leaves, claims = [], []
    for holder, first, count in parts:
        block = [bytes.fromhex(x) for x in done[holder]]
        leaves.extend(block)
        claims.append(Contribution(holder, first, count, leaf_digest(block)))
    era = ContributedEra(era_id, pub_seed, hardening.tree_height,
                         hardening.turns, leaves)
    root = era.root.hex()
    signed = [Contribution(c.holder, c.first, c.count, c.digest,
                           signer_of(c.holder).sign(Contribution.message(
                               network, c.holder, c.first, c.count, c.digest,
                               root, hardening.wots_scheme)))
              for c in claims]
    return era0_fields(era, signed), era


def run(network: str, first_seed: str, holders, hardening: HardeningParams,
        seed_of, signer_of, era_id: int = 0):
    """(era0 fields, era).  `seed_of(holder) -> bytes`, `signer_of(holder)`
    returns something with `.sign(bytes) -> hex`."""
    pub_seed = pub_seed_for(network, first_seed, era_id)
    slices = slices_for(holders, hardening.turns, pub_seed, seed_of)
    era = assemble(era_id, pub_seed, hardening.tree_height, hardening.turns,
                   slices)
    root = era.root.hex()
    claims = []
    for s in slices:
        c = s.contribution()
        msg = Contribution.message(network, c.holder, c.first, c.count,
                                   c.digest, root, hardening.wots_scheme)
        claims.append(Contribution(c.holder, c.first, c.count, c.digest,
                                   signer_of(c.holder).sign(msg)))
    return era0_fields(era, claims), era


def verify_transcript(era0: dict, leaves) -> tuple:
    """(ok, reason).  The half of era 0 the document cannot check alone.

    The document commits to each holder's leaf digest and to the era root.
    Given the published leaves — which is what a holder publishes in round one
    and what anybody can archive — this recomputes both. A drafter who invented
    a digest, or assembled the tree from leaves other than the published ones,
    fails here; a drafter who did neither cannot fail here.
    """
    turns = era0.get("turns")
    if len(leaves) != turns:
        return False, f"{len(leaves)} leaves published for {turns} turns"
    claims = [Contribution(*c) for c in era0["contributions"]]
    try:
        check_coverage(claims, turns)
    except ContributionError as exc:
        return False, str(exc)
    for c in claims:
        block = leaves[c.first:c.first + c.count]
        if leaf_digest(block) != c.digest:
            return False, (f"{c.holder}'s published leaves do not match the "
                           f"digest the document commits to")
    era = ContributedEra(0, bytes.fromhex(era0["pub_seed"]),
                         era0["tree_height"], turns, leaves,
                         scheme=era0["scheme"])
    if era.root.hex() != era0["root"]:
        return False, "the published leaves do not build the committed root"
    return True, "ok"


def save_transcript(path: str, era: ContributedEra):
    """The leaves, as published. Large by design — 32 bytes a turn — and not a
    secret: they are public keys."""
    with open(path, "w") as fh:
        json.dump({"turns": era.turns,
                   "leaves": [era.leaf_pk(i).hex() for i in range(era.turns)]},
                  fh)


def load_transcript(path: str) -> list:
    with open(path) as fh:
        return [bytes.fromhex(x) for x in json.load(fh)["leaves"]]


if __name__ == "__main__":                                   # pragma: no cover
    import sys
    import time

    from ..genesis import (GENESIS_7_IDS, dev_keyring, dev_turn_seed,
                           first_seed_for)
    from .params import PRODUCTION

    target = sys.argv[1] if len(sys.argv) > 1 else "config/era0-7.json"
    network = sys.argv[2] if len(sys.argv) > 2 else "fin6-genesis-7"
    first_seed = first_seed_for(network, GENESIS_7_IDS)
    started = time.time()
    fields, era = run_parallel(network, first_seed, GENESIS_7_IDS, PRODUCTION,
                               seed_of=dev_turn_seed, signer_of=dev_keyring)
    with open(target, "w") as fh:
        json.dump(fields, fh, indent=2)
        fh.write("\n")
    took = time.time() - started
    print(f"wrote {target} in {took:.0f}s")
    print(f"  root     {fields['root'][:24]}…")
    print(f"  turns    {fields['turns']:,} across "
          f"{len(fields['contributions'])} holders")
    biggest = max(shares([Contribution(*c) for c in fields["contributions"]],
                         fields["turns"]).values())
    print(f"  largest  {biggest:.1%} of the pool = "
          f"{PRODUCTION.max_fork_depth(biggest):,} blocks of rewrite ceiling")
