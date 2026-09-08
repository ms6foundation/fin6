"""Bootstrapping a test network: validators, note holders, and a genesis block."""
from __future__ import annotations

from dataclasses import dataclass, field

from .block import Block, BlockHeader, CeremonyMeta, GENESIS_PREV
from .crypto import Signer
from .node import Node
from .notes import Note, note_id, note_vector
from .params import ChainParams
from .seal import seal_root
from .state import ChainState


@dataclass
class Holder:
    """A bag of notes with a key, for driving the chain from inside one process.

    Not a wallet.  It keeps openings in memory, cannot find a note it was not
    handed, and has no address — `wallet.Wallet` is the real thing and lives in
    its own package.  This exists so a test or a demo can move value around
    without a network, and the name says so.
    """
    name: str
    signer: Signer
    notes: list = field(default_factory=list)
    params: ChainParams = None

    @property
    def public_hex(self):
        return self.signer.public_hex

    def balance(self) -> int:
        return sum(n.value for n in self.notes)

    def take(self, amount: int):
        """Pick one note worth at least `amount` and remove it from the wallet."""
        for i, n in enumerate(self.notes):
            if n.value >= amount:
                return self.notes.pop(i)
        raise ValueError(f"{self.name} has no single note >= {amount} "
                         f"(balance {self.balance()}; multi-input spends need "
                         f"the caller to pick the set)")

    def receive(self, note: Note):
        self.notes.append(note)

    def forget(self, note: Note):
        self.notes = [n for n in self.notes if n is not note]


def bootstrap(validator_ids, endowments: dict, params: ChainParams,
              asset: str = "USD"):
    """Build a genesis state, holders, and one Node per validator.

    endowments: {holder name: [note values]}
    Returns (nodes, holders, genesis_block).
    """
    holders = {name: Holder(name=name, signer=Signer.from_seed(f"wallet:{name}"),
                            params=params)
               for name in endowments}

    genesis = ChainState(params)
    for name, values in endowments.items():
        w = holders[name]
        for value in values:
            note = Note.create(value, w.public_hex, params, asset=asset)
            genesis.issue(note_id(note_vector(note, params)))
            w.receive(note)

    meta = CeremonyMeta(epoch=0, leader_id="genesis", rows=0,
                        row_size=params.row_size, grid_seed="genesis")
    header = BlockHeader(height=0, prev_hash=GENESIS_PREV,
                         chain_id=genesis.chain_id,
                         utxo_root=genesis.utxo.root,
                         nf_root=genesis.nullifiers.root,
                         tx_root=seal_root("tx", []),
                         ceremony=meta)
    block = Block(header=header, transactions=())
    genesis.height = 0
    genesis.tip = header.hash()

    nodes = {nid: Node(nid, Signer.from_seed(f"validator:{nid}"), params,
                       genesis.copy())
             for nid in validator_ids}
    return nodes, holders, block


def transfer(holder_from: Holder, holder_to: Holder, amount: int, fee: int,
             params: ChainParams):
    """Convenience: spend one note, pay `amount`, return the change.

    Returns (tx, output_notes) — the caller decides which wallet keeps what.
    """
    from .transaction import build_transaction

    note = holder_from.take(amount + fee)
    change = note.value - amount - fee
    outs = [Note.create(amount, holder_to.public_hex, params, asset=note.asset)]
    if change > 0:
        outs.append(Note.create(change, holder_from.public_hex, params,
                                asset=note.asset))
    else:
        # Every transaction needs at least one output; a zero-value change note
        # keeps the shape uniform and leaks nothing (the value is hidden).
        outs.append(Note.create(0, holder_from.public_hex, params,
                                asset=note.asset))
    tx = build_transaction([(note, holder_from.signer)], outs, fee, params)
    holder_to.receive(outs[0])
    holder_from.receive(outs[1])
    return tx, outs
