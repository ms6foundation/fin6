"""Deterministic ms6 seal-tree helpers shared by the ledger and the ceremony.

ms6.Commitment salts every item, which makes it hiding — right for secret
values, wrong for a set two nodes must agree on.  Everything here commits
public values, so it goes through _SealTree over deterministic leaves: binding
and canonical, hiding neither needed nor claimed.
"""
from __future__ import annotations

from mq.ms6 import P
from mq.ms6.core import _SealTree, _seal_fold_rows, _seal_hash

DEFAULT_CHUNK = 100
DEFAULT_SBS = 1000
DEFAULT_D = 8
TOMBSTONE = "fin6:spent"


def _domain_leaf(label: str) -> str:
    return _seal_hash(f"__root__:{label}")


def _leaf(label: str, value) -> str:
    return _seal_hash(f"{label}:{value}")


def seal_root(label: str, values, d: int = DEFAULT_D,
              chunk_size: int = DEFAULT_CHUNK, mod: int = P,
              sbs: int = DEFAULT_SBS) -> int:
    """Canonical seal-tree root over an ordered list of public values."""
    leaves = [_domain_leaf(label)] + [_leaf(label, v) for v in values]
    x = _seal_fold_rows(chunk_size)
    return _SealTree(leaves, x, chunk_size, d, mod, sbs).root


class SealAccumulator:
    """Append-and-tombstone set with a canonical seal-tree root."""

    def __init__(self, label: str, d: int = DEFAULT_D,
                 chunk_size: int = DEFAULT_CHUNK, mod: int = P,
                 sbs: int = DEFAULT_SBS):
        self.label = label
        self.d, self.chunk_size, self.mod, self.sbs = d, chunk_size, mod, sbs
        self.items: list = []
        self.index: dict = {}
        self.dead: set = set()
        self._x = _seal_fold_rows(chunk_size)
        self._tree = _SealTree([_domain_leaf(label)], self._x, chunk_size,
                               d, mod, sbs)

    def add(self, value) -> int:
        if value in self.index:
            raise ValueError(f"{self.label}: {value!r} is already present")
        pos = len(self.items)
        self.items.append(value)
        self.index[value] = pos
        self._tree.append_leaf(_leaf(self.label, value))
        return pos

    def spend(self, value):
        if value not in self.index:
            raise KeyError(f"{self.label}: {value!r} is not present")
        pos = self.index[value]
        if pos in self.dead:
            raise ValueError(f"{self.label}: {value!r} is already spent")
        self.dead.add(pos)
        # The slot is kept so every other entry keeps its index; only the leaf
        # changes, so the root moves and history stays addressable.
        self._tree.update_leaf(pos + 1, _leaf(self.label, f"{TOMBSTONE}:{value}"))

    def __contains__(self, value) -> bool:
        pos = self.index.get(value)
        return pos is not None and pos not in self.dead

    def ever_contained(self, value) -> bool:
        return value in self.index

    def __len__(self) -> int:
        return len(self.items) - len(self.dead)

    @property
    def root(self) -> int:
        return self._tree.root

    def live(self) -> list:
        return [v for i, v in enumerate(self.items) if i not in self.dead]

    def clone(self) -> "SealAccumulator":
        out = SealAccumulator(self.label, self.d, self.chunk_size, self.mod,
                              self.sbs)
        for value in self.items:
            out.items.append(value)
            out.index[value] = len(out.items) - 1
            out._tree.append_leaf(_leaf(out.label, value))
        for pos in sorted(self.dead):
            out.dead.add(pos)
            out._tree.update_leaf(
                pos + 1, _leaf(out.label, f"{TOMBSTONE}:{self.items[pos]}"))
        return out

    def __repr__(self):
        return (f"SealAccumulator({self.label}, live={len(self)}, "
                f"root={str(self.root)[:12]}…)")
