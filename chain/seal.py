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

    def unspend(self, value):
        """Put a spent slot back.  Only a rollback has any business here."""
        pos = self.index.get(value)
        if pos is None:
            raise KeyError(f"{self.label}: {value!r} is not present")
        if pos not in self.dead:
            raise ValueError(f"{self.label}: {value!r} is not spent")
        self.dead.discard(pos)
        self._tree.update_leaf(pos + 1, _leaf(self.label, value))

    def truncate(self, count: int):
        """Drop the last `count` values.

        The only legitimate caller is an undo of the most recent block, which is
        why this refuses to drop a spent slot: a value that something later
        spent is not at the tail any more, so a request to remove it means the
        undo is being applied out of order.
        """
        if not 0 <= count <= len(self.items):
            raise ValueError(f"{self.label}: cannot drop {count} of "
                             f"{len(self.items)}")
        if not count:
            return
        cut = len(self.items) - count
        for pos in range(cut, len(self.items)):
            if pos in self.dead:
                raise ValueError(
                    f"{self.label}: {self.items[pos]!r} was spent after it was "
                    f"created; this undo is out of order")
            del self.index[self.items[pos]]
        del self.items[cut:]
        self._rebuild()

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

    # ── persistence ──────────────────────────────────────────────────────────

    def dump(self):
        """The whole logical state: the ordered values and which are spent.

        Deliberately not the tree.  Rebuilding it costs 4.1 us a leaf, so
        storing internal structure would couple the ledger format to an mq
        implementation detail to save a few seconds once per restart.
        """
        return list(self.items), sorted(self.dead)

    @classmethod
    def load(cls, label: str, values, dead=(), d: int = DEFAULT_D,
             chunk_size: int = DEFAULT_CHUNK, mod: int = P,
             sbs: int = DEFAULT_SBS) -> "SealAccumulator":
        """Rebuild from a dump in one pass.

        One pass, not a replay of appends: a batch build is ~350x cheaper per
        leaf than folding them in one at a time, and the result is the same root
        either way.
        """
        out = cls(label, d, chunk_size, mod, sbs)
        out.items = list(values)
        out.index = {v: i for i, v in enumerate(out.items)}
        if len(out.index) != len(out.items):
            raise ValueError(f"{label}: duplicate value in the dump")
        out.dead = set(dead)
        for pos in out.dead:
            if not 0 <= pos < len(out.items):
                raise ValueError(f"{label}: dead slot {pos} is out of range")
        out._rebuild()
        return out

    def _rebuild(self):
        leaves = [_domain_leaf(self.label)]
        for i, value in enumerate(self.items):
            leaves.append(_leaf(self.label, f"{TOMBSTONE}:{value}"
                                if i in self.dead else value))
        self._tree = _SealTree(leaves, self._x, self.chunk_size, self.d,
                               self.mod, self.sbs)

    def clone(self) -> "SealAccumulator":
        """A copy that shares nothing.

        Built in one pass for the same reason `load` is: `check_block` clones
        the state to apply a block speculatively, so a clone that folded leaves
        one at a time would put the set size into the cost of validating every
        block.
        """
        return SealAccumulator.load(self.label, self.items, self.dead, self.d,
                                    self.chunk_size, self.mod, self.sbs)

    def __repr__(self):
        return (f"SealAccumulator({self.label}, live={len(self)}, "
                f"root={str(self.root)[:12]}…)")
