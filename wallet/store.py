"""A wallet: one seed, a cache of notes, and the arithmetic in between.

The note store here is deliberately a **cache**.  Every note it holds can be
recovered by scanning the chain with the viewing key, because every output
carries its opening sealed to its recipient — so losing this file costs a
rescan, not the money.  That is the whole point of the ciphertext, and it is
worth restating in the place a reader will look for it: before the ciphertext,
a wallet held two secrets and the second one had no backup.

What the wallet does:

    scan        trial-decrypt outputs; keep the ones addressed here
    reconcile   a note whose nullifier has appeared is gone, whoever spent it
    select      pick notes to cover an amount
    send        build, prove, and seal the openings to the recipient

What it does not do is talk to the network.  `net/client.py` does that, and
keeping the two apart means a wallet can be driven from a file, a socket, or a
test with the same code.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from chain.crypto import Signer
from .keys import Address, WalletKeys
from .sealing import (decrypt_opening, disclosure_key,
                      open_disclosed, seal_output)
from chain.notes import Note, note_id, note_vector, nullifier_id
from chain.notes import nullifier_value
from chain.params import ChainParams
from chain.transaction import TxError, build_transaction

STORE_VERSION = 2


class WalletError(Exception):
    pass


@dataclass
class Held:
    """One note this wallet can spend, and where it came from."""
    note: Note
    cm: str
    height: int
    spent_at: int | None = None
    #: Which of this seed's addresses received it. It has to be recorded
    #: rather than assumed: the note's owner coordinate is that address's
    #: spend key, so spending it needs that address's signer, and a wallet
    #: that guessed index 0 would build an unprovable statement.
    index: int = 0

    @property
    def value(self) -> int:
        return self.note.value

    def nullifier(self, params: ChainParams) -> str:
        return nullifier_id(self.cm, nullifier_value(self.note.coords()))


class Wallet:
    """The user's side of the chain."""

    def __init__(self, keys: WalletKeys, params: ChainParams,
                 chain_id: str | None = None, name: str = "wallet"):
        self.keys = keys
        self.params = params
        self.chain_id = chain_id or params.chain_id
        self.name = name
        self.held: dict = {}          # cm -> Held
        self.scanned_to = 0           # the last height this wallet has seen
        # One seed, many addresses. Kept because a viewing key is scoped to
        # its address and nothing narrower, so an address per counterparty or
        # per period is the difference between disclosing a relationship and
        # disclosing a life. Index 0 is the address this wallet has always
        # had.
        self._keys: dict = {keys.index: keys}

    # ── identity ─────────────────────────────────────────────────────────────

    @property
    def address(self) -> Address:
        return self.keys.address

    @property
    def addresses(self) -> dict:
        """Every address this wallet is watching, by diversifier."""
        return {i: k.address for i, k in sorted(self._keys.items())}

    def new_address(self) -> Address:
        """Another address from the same seed, for a scope of its own.

        Hand this one out to a counterparty you may later have to disclose,
        and the disclosure is that relationship rather than everything.
        """
        index = max(self._keys) + 1
        self._keys[index] = self.keys.at(index)
        return self._keys[index].address

    def watch(self, index: int) -> Address:
        """Watch an address this seed has used before — after a restore, when
        the wallet file is gone and only the seed is left."""
        if index not in self._keys:
            self._keys[index] = self.keys.at(int(index))
        return self._keys[index].address

    def keys_for(self, index: int) -> WalletKeys:
        return self._keys[int(index)]

    @property
    def signer(self) -> Signer:
        return self.keys.signer

    # ── what it has ──────────────────────────────────────────────────────────

    def unspent(self):
        return [h for h in self.held.values() if h.spent_at is None]

    def balance(self) -> int:
        return sum(h.value for h in self.unspent())

    def nullifiers(self) -> dict:
        """nullifier -> cm, for every note still believed unspent."""
        return {h.nullifier(self.params): h.cm for h in self.unspent()}

    # ── learning ─────────────────────────────────────────────────────────────

    def scan(self, outputs) -> int:
        """Take (height, cm, sealed[, pos]) rows and keep what is ours.

        One X25519 exchange per output, about 30 us — so keeping up with a
        block costs milliseconds and a restore from seed is a walk through the
        whole history, which is the price of not having to back anything up.
        """
        found = 0
        for height, cm, sealed, *rest in outputs:
            self.scanned_to = max(self.scanned_to, int(height))
            if not sealed or cm in self.held:
                continue
            # Every diversifier this wallet watches, which is the price of
            # scoping: one exchange per address per output. The detection
            # tags are what keep that from being the whole chain — they are
            # per address too, so a scan narrows before it decrypts.
            for index, keys in sorted(self._keys.items()):
                note = decrypt_opening(sealed, keys, cm, self.params)
                if note is None:
                    continue                  # somebody else's money
                self.held[cm] = Held(note=note, cm=cm, height=int(height),
                                     index=index)
                found += 1
                break
        return found

    def reconcile(self, published_nullifiers, height: int | None = None) -> int:
        """Mark as spent every note whose nullifier has appeared on chain.

        Whoever spent it: a wallet restored from a seed learns the same way,
        and a note spent from another device is gone here too.
        """
        mine = self.nullifiers()
        gone = 0
        for nf in published_nullifiers:
            cm = mine.get(nf)
            if cm is not None:
                self.held[cm].spent_at = height if height is not None else -1
                gone += 1
        return gone

    # ── spending ─────────────────────────────────────────────────────────────

    def select(self, amount: int):
        """Enough notes to cover `amount`, smallest-first.

        Smallest-first keeps the note count down, which matters here because a
        transaction proves every input: the coin selection policy is a proof
        size policy.
        """
        pool = sorted(self.unspent(), key=lambda h: h.value)
        chosen, total = [], 0
        for held in pool:
            if total >= amount:
                break
            chosen.append(held)
            total += held.value
        if total < amount:
            raise WalletError(
                f"balance is {self.balance()}, cannot cover {amount}")
        return chosen, total

    def send(self, to: Address, amount: int, fee: int = 1, *, backends=None):
        """Build and prove a transfer.  Returns (tx, change_note or None).

        The change output is sealed to this wallet's own address for the same
        reason the payment is sealed to the recipient's: otherwise the sender
        is the one who cannot restore.
        """
        if amount < 0 or fee < 0:
            raise WalletError("amount and fee must not be negative")
        chosen, total = self.select(amount + fee)
        if len(chosen) != 1:
            # TxSystem handles k inputs; `send` does not yet, and pretending
            # otherwise would produce an unprovable statement at the last step.
            raise WalletError(
                f"this payment needs {len(chosen)} notes and multi-note spends "
                f"are not built yet — the design's open item")
        held = chosen[0]
        # The address that received the input is the one that signs for it and
        # the one the change goes back to. Sending change to index 0 would be
        # the quiet way to defeat the whole point: disclose one address and
        # the change from every other address's notes is sitting in it.
        mine = self._keys.get(held.index, self.keys)
        change = total - amount - fee
        outs = [Note.create(amount, to.spend_hex, self.params,
                            asset=held.note.asset),
                Note.create(change, mine.address.spend_hex, self.params,
                            asset=held.note.asset)]
        # Sealed here, not in `build_transaction`: sealing needs an address and
        # the ledger has no business knowing what an address is.  What the
        # ledger does is bind what it is handed.
        cms = [note_id(note_vector(n, self.params)) for n in outs]
        pairs = [seal_output(note, address, cm, self.params)
                 for note, address, cm in zip(outs, [to, mine.address], cms)]
        tx = build_transaction([(held.note, mine.signer)], outs, fee,
                               self.params, chain_id=self.chain_id,
                               backends=backends,
                               sealed=[blob for blob, _ in pairs],
                               tags=[tag for _, tag in pairs])
        return tx, outs[1]

    # ── disclosure ───────────────────────────────────────────────────────────

    def disclose(self, cms, sealed: dict) -> dict:
        """Per-output keys for the notes named, and nothing else.

        The narrowest grant this system can make. A viewing key opens every
        note ever sent to an address, including ones nobody has sent yet; one
        of these opens exactly one output, because the key is derived from
        that output's own ephemeral key with its commitment hashed in.

        `sealed` maps cm to the ciphertext as it appears on chain — the caller
        fetches it, because a wallet holds openings rather than ciphertexts.
        Returns {cm: {"key", "owner"}}: the key, and the recipient's spend key,
        which the opening deliberately does not carry and which is public
        anyway.

        The holder checks its own work here. Handing over a key that does not
        open the output would be a disclosure the auditor cannot use and the
        holder would blame it on them.
        """
        out = {}
        for cm in cms:
            held = self.held.get(cm)
            blob = sealed.get(cm)
            if held is None or not blob:
                continue
            keys = self._keys.get(held.index)
            if keys is None:
                continue
            key = disclosure_key(keys, blob, cm)
            if key is None:
                continue
            if open_disclosed(blob, key, cm, keys.spend_hex,
                              self.params) is None:
                continue                       # would not open; do not offer it
            out[cm] = {"key": key, "owner": keys.spend_hex}
        return out

    # ── persistence ──────────────────────────────────────────────────────────

    def dump(self) -> dict:
        return {
            "version": STORE_VERSION,
            "name": self.name,
            "chain_id": self.chain_id,
            "address": self.address.encode(),
            "scanned_to": self.scanned_to,
            # The diversifiers, not the addresses: they are derived from the
            # seed, and a restore that has the seed can rebuild them. What it
            # cannot rebuild is *which* ones this wallet ever used.
            "diversifiers": sorted(self._keys),
            "notes": [
                {"cm": h.cm, "height": h.height, "spent_at": h.spent_at,
                 "index": h.index,
                 "value": h.note.value, "asset": str(h.note.asset),
                 "rho": str(h.note.rho),
                 "blinders": [str(b) for b in h.note.blinders]}
                for h in sorted(self.held.values(), key=lambda h: h.cm)],
        }

    def save(self, path):
        tmp = f"{path}.tmp"
        with open(tmp, "w") as fh:
            json.dump(self.dump(), fh, indent=2)
        os.replace(tmp, path)
        return path

    @classmethod
    def load(cls, path, keys: WalletKeys, params: ChainParams) -> "Wallet":
        with open(path) as fh:
            raw = json.load(fh)
        if raw.get("version") != STORE_VERSION:
            raise WalletError(f"note store version {raw.get('version')}")
        wallet = cls(keys, params, chain_id=raw["chain_id"],
                     name=raw.get("name", "wallet"))
        if raw["address"] != wallet.address.encode():
            raise WalletError("this note store belongs to a different seed")
        wallet.scanned_to = raw.get("scanned_to", 0)
        for index in raw.get("diversifiers", ()):
            wallet.watch(int(index))
        from chain.crypto import owner_field
        for entry in raw["notes"]:
            # The owner is *this note's* address, not the wallet's first one:
            # the owner coordinate is part of the commitment, so getting it
            # wrong turns into "does not match its own commitment" below
            # rather than into a wrong balance, which is the right way round.
            index = int(entry.get("index", 0))
            owner = owner_field(wallet.watch(index).spend_hex)
            note = Note(value=entry["value"], asset=int(entry["asset"]),
                        owner=owner, rho=int(entry["rho"]),
                        blinders=tuple(int(b) for b in entry["blinders"]))
            cm = note_id(note_vector(note, params))
            if cm != entry["cm"]:
                raise WalletError(f"note {entry['cm'][:14]}… does not match "
                                  f"its own commitment")
            wallet.held[cm] = Held(note=note, cm=cm, height=entry["height"],
                                   spent_at=entry["spent_at"], index=index)
        return wallet

    def __repr__(self):
        return (f"Wallet({self.name}, {self.address.short()}, "
                f"{self.balance()} in {len(self.unspent())} notes)")
