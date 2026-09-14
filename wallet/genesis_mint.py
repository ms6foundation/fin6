"""Minting the genesis supply, and claiming it.

The mint itself is `chain/mint.py` — the proof that a set of commitments adds
up to a declared total belongs with the ledger, because the ledger is what
verifies it. What lives here is the half the ledger has no business doing: a
mint's openings are *sealed to their holders*, and sealing needs an address.

That is the whole of review A5's second half. Genesis used to derive note
randomness from the document digest, so every opening was derivable by anyone
holding the document — the right fix for seven processes computing seven
different genesis states, and permanent disclosure of the initial holdings. A
mint draws real randomness and seals each opening to the address it belongs to,
exactly as any other payment does; every node still computes the same genesis
state, because the state is the *commitments*, and those are in the document.

A genesis holder's keys come from the same phrase derivation a user's do
(`genesis:<name>`), which is what makes `claim` possible at all and what
`fin6 wallet import-genesis` has always relied on.
"""
from __future__ import annotations

from chain.crypto import seed_from_phrase
from chain.mint import build_mint, verify_mint
from chain.notes import Note, note_id, note_vector

from .keys import WalletKeys
from .sealing import decrypt_opening, seal_output


def holder_keys(name: str) -> WalletKeys:
    """The keys behind a genesis holder's name."""
    return WalletKeys(seed_from_phrase(f"genesis:{name}"))


def mint_supply(context: str, endowments: dict, params, *, asset: str = "USD",
                backends=None):
    """(mint block for the document, the artifact).

    `endowments` is {holder: [values]} and is the last place those numbers
    appear in the clear. The notes are drawn with fresh randomness, sealed to
    their holders, and proved.
    """
    notes, sealed, tags, owners = [], [], [], []
    for name, values in sorted(endowments.items()):
        keys = holder_keys(name)
        for value in values:
            note = Note.create(value, keys.address.spend_hex, params,
                               asset=asset)
            cm = note_id(note_vector(note, params))
            blob, tag = seal_output(note, keys.address, cm, params)
            notes.append(note)
            sealed.append(blob)
            tags.append(tag)
            owners.append(name)
    artifact = build_mint(notes, params, context, sealed=sealed, tags=tags,
                          backends=backends)
    block = {"total": artifact.total,
             "outputs": list(artifact.output_cms),
             "digest": artifact.digest()}
    return block, artifact


def claim(artifact, name: str, params) -> list:
    """The notes a holder can open out of a published mint.

    Everyone can see the commitments and check the total; only the holder can
    turn one into money. Returns the notes in mint order, skipping every
    output that is not this holder's — which is exactly what a wallet scanning
    the chain does, and is the reason nothing here needs a list of who owns
    what.
    """
    keys = holder_keys(name)
    found = []
    for cm, blob in zip(artifact.output_cms, artifact.sealed):
        note = decrypt_opening(bytes(blob), keys, cm, params)
        if note is not None:
            found.append(note)
    return found


__all__ = ["holder_keys", "mint_supply", "claim", "verify_mint"]


if __name__ == "__main__":                                   # pragma: no cover
    import json
    import sys
    import time

    from chain import genesis as genesis_mod
    from chain.hardening.params import PRODUCTION
    from chain.params import LAUNCH

    block_path = sys.argv[1] if len(sys.argv) > 1 else "config/mint-7.json"
    artifact_path = sys.argv[2] if len(sys.argv) > 2 else "config/mint-7.bin"
    endowments = {"treasury": [1000, 900, 800, 700, 600]}

    # The context is the document without its mint, so the two commit to each
    # other without a cycle: draft once with no mint to learn it, mint, then
    # draft again carrying the block.
    total = sum(sum(v) for v in endowments.values())
    skeleton = genesis_mod.draft(
        "fin6-genesis-7", genesis_mod.GENESIS_7_IDS, LAUNCH, PRODUCTION,
        {name: [] for name in endowments}, declared_total=total,
        era0=genesis_mod.load_era0())
    started = time.time()
    block, artifact = mint_supply(skeleton.mint_context(), endowments, LAUNCH)
    with open(block_path, "w") as fh:
        json.dump(block, fh, indent=2)
        fh.write("\n")
    with open(artifact_path, "wb") as fh:
        fh.write(artifact.encode())
    ok, why = verify_mint(artifact, LAUNCH, skeleton.mint_context())
    print(f"wrote {block_path} and {artifact_path} in "
          f"{time.time() - started:.1f}s")
    print(f"  outputs  {len(block['outputs'])} commitments, "
          f"total {block['total']:,}")
    print(f"  artifact {len(artifact.encode()) / 1024:.0f} KB, "
          f"digest {block['digest'][:16]}…")
    print(f"  verifies {ok} {why}")
