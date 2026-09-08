"""Deterministic ms6 seal-tree helpers shared by the ledger and the ceremony.

ms6.Commitment salts every item, which makes it hiding — right for secret
values, wrong for a set two nodes must agree on.  Everything here commits
public values, so it goes through _SealTree over deterministic leaves: binding
and canonical, hiding neither needed nor claimed.
"""
from __future__ import annotations

import hashlib

from mq.ms6 import P
from mq.ms6.core import _SealTree, _seal_fold_rows, _seal_hash

DEFAULT_CHUNK = 100
DEFAULT_SBS = 1000
DEFAULT_D = 8
TOMBSTONE = "fin6:spent"
WITNESS_HEIGHT = 32          # 4.3 billion slots; see WitnessTree


def _domain_leaf(label: str) -> str:
    return _seal_hash(f"__root__:{label}")


def _leaf(label: str, value) -> str:
    return _seal_hash(f"{label}:{value}")


def leaf_value(label: str, value) -> str:
    """The leaf a live entry has in both trees.

    Public because a light client has to know it: verifying an inclusion proof
    means checking the path *and* checking that what it opens to is this note's
    live form rather than its tombstone.
    """
    return _leaf(label, value)


def seal_root(label: str, values, d: int = DEFAULT_D,
              chunk_size: int = DEFAULT_CHUNK, mod: int = P,
              sbs: int = DEFAULT_SBS) -> int:
    """Canonical seal-tree root over an ordered list of public values."""
    leaves = [_domain_leaf(label)] + [_leaf(label, v) for v in values]
    x = _seal_fold_rows(chunk_size)
    return _SealTree(leaves, x, chunk_size, d, mod, sbs).root


# ═══════════════════════════════════════════════════════════════════════════════
# The witness tree
# ═══════════════════════════════════════════════════════════════════════════════
#
# A second tree over the same leaves, for a different reader.
#
# The seal tree folds `sbs = 1000` children into each parent, which is right for
# a validator — it makes the root cheap to keep current in bulk — and wrong for
# anybody who was not there.  Proving one leaf to an outsider means handing over
# every sibling in the chunk at every level: measured at 1,048 siblings and
# 80 KiB for 50,000 leaves, 2,007 and 153 KiB at ten million.
#
# So this is the other structure.  Ordinary SHA-256, two children per parent,
# one sibling per level.  It answers exactly one question — *is the leaf at
# position p equal to this value* — and it answers it in about half a kilobyte.
#
# Fixed height rather than a tree that grows with the leaf count, because this
# one takes **updates**, not only appends: spending a note rewrites its leaf in
# place (see SealAccumulator.spend).  A tree whose shape depends on how many
# leaves it holds reshapes on every append, so an update would cost a rebuild.
# At a fixed height the shape never changes, an update is 32 hashes, and the
# empty part of the tree costs nothing because every all-empty subtree at a
# level has the same digest.
#
# The proof pays for that with 32 siblings instead of ⌈log₂ n⌉ — but the ones
# above the occupied prefix are all that same default digest, so a bitmap of
# which siblings are present takes a 50,000-leaf proof from 1,024 bytes back
# down to about 550.

def _wh(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    d.update(b"fin6-witness")
    for part in parts:
        d.update(part)
    return d.digest()


def _leaf_digest(value) -> bytes:
    return _wh(b"\x00", str(value).encode())


def _node_digest(left: bytes, right: bytes) -> bytes:
    return _wh(b"\x01", left, right)


def _defaults(height: int) -> tuple:
    """The digest of an all-empty subtree, one per level."""
    out = [_wh(b"\x02")]
    for _ in range(height):
        out.append(_node_digest(out[-1], out[-1]))
    return tuple(out)


_DEFAULTS = {}


def defaults_for(height: int) -> tuple:
    if height not in _DEFAULTS:
        _DEFAULTS[height] = _defaults(height)
    return _DEFAULTS[height]


class WitnessTree:
    """A fixed-height sparse Merkle tree over positioned values.

    Only the nodes that differ from their level's default are stored, so a tree
    holding n leaves at consecutive positions costs about 2n digests however
    tall it is declared to be.
    """

    __slots__ = ("label", "height", "_d", "_nodes", "_size")

    def __init__(self, label: str, height: int = WITNESS_HEIGHT):
        self.label = label
        self.height = height
        self._d = defaults_for(height)
        self._nodes = {}                  # (level, index) -> digest
        self._size = 0

    # ── reading ──────────────────────────────────────────────────────────────

    def _get(self, level: int, index: int) -> bytes:
        return self._nodes.get((level, index), self._d[level])

    @property
    def root(self) -> bytes:
        return self._get(self.height, 0)

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def __len__(self) -> int:
        return self._size

    # ── writing ──────────────────────────────────────────────────────────────

    def set(self, pos: int, value):
        """Put `value` at `pos`.  32 hashes, whatever the tree holds."""
        if not 0 <= pos < (1 << self.height):
            raise ValueError(f"{self.label}: position {pos} is out of range")
        node, index = _leaf_digest(value), pos
        self._nodes[(0, index)] = node
        for level in range(self.height):
            sibling = self._get(level, index ^ 1)
            node = (_node_digest(node, sibling) if index % 2 == 0
                    else _node_digest(sibling, node))
            index >>= 1
            if node == self._d[level + 1]:
                self._nodes.pop((level + 1, index), None)
            else:
                self._nodes[(level + 1, index)] = node
        self._size = max(self._size, pos + 1)

    def clear(self, pos: int):
        """Empty a slot.  Only a truncation has any business here."""
        if (0, pos) not in self._nodes:
            return
        node, index = self._d[0], pos
        del self._nodes[(0, pos)]
        for level in range(self.height):
            sibling = self._get(level, index ^ 1)
            node = (_node_digest(node, sibling) if index % 2 == 0
                    else _node_digest(sibling, node))
            index >>= 1
            if node == self._d[level + 1]:
                self._nodes.pop((level + 1, index), None)
            else:
                self._nodes[(level + 1, index)] = node
        self._size = min(self._size, pos)

    def append(self, value) -> int:
        pos = self._size
        self.set(pos, value)
        return pos

    def extend(self, values):
        for value in values:
            self.append(value)
        return self._size

    # ── proving ──────────────────────────────────────────────────────────────

    def path(self, pos: int) -> dict:
        """A proof that position `pos` holds what it holds.

        `present` is a bitmap of which siblings are not their level's default,
        so the empty part of the tree costs one bit a level instead of 32 bytes.
        """
        siblings, present, index = [], 0, pos
        for level in range(self.height):
            sibling = self._get(level, index ^ 1)
            if sibling != self._d[level]:
                present |= 1 << level
                siblings.append(sibling.hex())
            index >>= 1
        return {"pos": pos, "height": self.height, "present": present,
                "siblings": siblings}

    # ── proving against a prefix ─────────────────────────────────────────────
    #
    # A header at height H commits the spine of blocks 1..H-1, so by the time
    # anyone asks, the tree has moved on.  Rather than keep a lagging copy, the
    # root and the path can both be recomputed for any earlier prefix in
    # `height` steps: a subtree lying entirely below the cut is the node the
    # tree already holds, one lying entirely above it is that level's default,
    # and exactly one per level straddles the cut — which is the node the
    # prefix walk is computing anyway.

    def _boundary(self, k: int) -> list:
        """The prefix digest of the node containing the cut, at every level."""
        out, acc, index = [], self._d[0], k
        for level in range(self.height):
            out.append(acc)
            if index & 1:
                acc = _node_digest(self._get(level, index - 1), acc)
            else:
                acc = _node_digest(acc, self._d[level])
            index >>= 1
        out.append(acc)
        return out

    def root_at(self, k: int) -> str:
        """The root this tree had when it held exactly `k` leaves."""
        if k <= 0:
            return self._d[self.height].hex()
        if k >= self._size:
            return self.root_hex
        return self._boundary(k)[self.height].hex()

    def path_at(self, pos: int, k: int) -> dict:
        """A path for `pos` against the root the tree had at `k` leaves."""
        if k >= self._size:
            return self.path(pos)
        if not 0 <= pos < k:
            raise ValueError(f"{self.label}: {pos} is not below the cut at {k}")
        boundary = self._boundary(k)
        siblings, present, index = [], 0, pos
        for level in range(self.height):
            s = index ^ 1
            if (s + 1) << level <= k:
                sibling = self._get(level, s)          # wholly below the cut
            elif s << level >= k:
                sibling = self._d[level]               # wholly above it
            else:
                sibling = boundary[level]              # the one that straddles
            if sibling != self._d[level]:
                present |= 1 << level
                siblings.append(sibling.hex())
            index >>= 1
        return {"pos": pos, "height": self.height, "present": present,
                "siblings": siblings}

    def size_bytes(self, pos: int) -> int:
        p = self.path(pos)
        return 32 * len(p["siblings"]) + 8

    # ── copying ──────────────────────────────────────────────────────────────

    def clone(self) -> "WitnessTree":
        out = WitnessTree(self.label, self.height)
        out._nodes = dict(self._nodes)
        out._size = self._size
        return out

    def __repr__(self):
        return (f"WitnessTree({self.label}, {self._size:,} leaves, "
                f"root={self.root_hex[:12]}…)")


def verify_witness(value, proof: dict, root) -> bool:
    """Recompute a root from a leaf and its path.  Never raises.

    This is the whole of a light client's side of §3: if the note has been
    spent, the leaf at that position is the tombstone form and no proof of the
    live form can be produced.
    """
    try:
        height = int(proof["height"])
        pos = int(proof["pos"])
        present = int(proof["present"])
        siblings = list(proof["siblings"])
        if not 0 <= pos < (1 << height):
            return False
        if bin(present).count("1") != len(siblings):
            return False
        d = defaults_for(height)
        node, index, take = _leaf_digest(value), pos, iter(siblings)
        for level in range(height):
            if present >> level & 1:
                sibling = bytes.fromhex(next(take))
            else:
                sibling = d[level]
            node = (_node_digest(node, sibling) if index % 2 == 0
                    else _node_digest(sibling, node))
            index >>= 1
        want = root if isinstance(root, bytes) else bytes.fromhex(str(root))
        return node == want
    except Exception:
        return False


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
        # Leaf for leaf, position for position, the same values the seal tree
        # folds — so a client checking the witness root is checking the ledger,
        # not a summary of it.
        self._witness = WitnessTree(label)
        self._witness.append(_domain_leaf(label))

    def add(self, value) -> int:
        if value in self.index:
            raise ValueError(f"{self.label}: {value!r} is already present")
        pos = len(self.items)
        self.items.append(value)
        self.index[value] = pos
        leaf = _leaf(self.label, value)
        self._tree.append_leaf(leaf)
        self._witness.set(pos + 1, leaf)
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
        tomb = _leaf(self.label, f"{TOMBSTONE}:{value}")
        self._tree.update_leaf(pos + 1, tomb)
        self._witness.set(pos + 1, tomb)

    def unspend(self, value):
        """Put a spent slot back.  Only a rollback has any business here."""
        pos = self.index.get(value)
        if pos is None:
            raise KeyError(f"{self.label}: {value!r} is not present")
        if pos not in self.dead:
            raise ValueError(f"{self.label}: {value!r} is not spent")
        self.dead.discard(pos)
        live = _leaf(self.label, value)
        self._tree.update_leaf(pos + 1, live)
        self._witness.set(pos + 1, live)

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

    @property
    def witness_root(self) -> str:
        """The same set, in the shape an outsider can check cheaply."""
        return self._witness.root_hex

    def witness_path(self, value) -> dict | None:
        """A proof that `value` is *live* here, or None if it is not.

        None covers both cases a wallet cares about and does not distinguish
        them, because the proof is the same shape either way: a value that was
        never here has no position, and a value that was spent has one whose
        leaf is the tombstone.
        """
        pos = self.index.get(value)
        if pos is None or pos in self.dead:
            return None
        return self._witness.path(pos + 1)

    def witness_leaf(self, value) -> str:
        return _leaf(self.label, value)

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
             sbs: int = DEFAULT_SBS, witness=None) -> "SealAccumulator":
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
        if witness is not None:
            # A clone copies the witness tree rather than rebuilding it: the
            # rebuild is 32 hashes a leaf, and `check_block` clones the state
            # for every block it validates.
            out._witness = witness.clone()
        return out

    def _rebuild(self):
        leaves = [_domain_leaf(self.label)]
        for i, value in enumerate(self.items):
            leaves.append(_leaf(self.label, f"{TOMBSTONE}:{value}"
                                if i in self.dead else value))
        self._tree = _SealTree(leaves, self._x, self.chunk_size, self.d,
                               self.mod, self.sbs)
        self._witness = WitnessTree(self.label)
        self._witness.extend(leaves)

    def clone(self) -> "SealAccumulator":
        """A copy that shares nothing.

        Built in one pass for the same reason `load` is: `check_block` clones
        the state to apply a block speculatively, so a clone that folded leaves
        one at a time would put the set size into the cost of validating every
        block.
        """
        out = SealAccumulator.load(self.label, self.items, self.dead, self.d,
                                   self.chunk_size, self.mod, self.sbs,
                                   witness=self._witness)
        return out

    def __repr__(self):
        return (f"SealAccumulator({self.label}, live={len(self)}, "
                f"root={str(self.root)[:12]}…)")


# ═══════════════════════════════════════════════════════════════════════════════
# The header spine
# ═══════════════════════════════════════════════════════════════════════════════

class HeaderHistory:
    """Every finalised block hash, in a tree, so ancestry is provable.

    Without this a client returning after a week has to walk every header it
    missed to know that the tip it is offered descends from the one it left —
    4,375 headers a day at the production cadence, 1 MB a day of walking, to
    learn one bit.  With it the answer is the tip header and one path.

    The tree holds the hash of the block at height h at position h - 1, so a
    header at height H commits to every block strictly below it.
    """

    __slots__ = ("_hashes", "_tree")

    def __init__(self, hashes=()):
        self._hashes = []
        self._tree = WitnessTree("history")
        for value in hashes:
            self.append(value)

    def append(self, block_hash: str) -> int:
        self._tree.set(len(self._hashes), block_hash)
        self._hashes.append(block_hash)
        return len(self._hashes)

    def truncate_to(self, height: int):
        """Drop back to the state after block `height`.  Rollback only."""
        while len(self._hashes) > max(0, height):
            self._tree.clear(len(self._hashes) - 1)
            self._hashes.pop()

    def hash_at(self, height: int) -> str | None:
        if 1 <= height <= len(self._hashes):
            return self._hashes[height - 1]
        return None

    def proof(self, height: int, under: int | None = None) -> dict | None:
        """A path showing the block at `height` is an ancestor.

        `under` is the number of blocks the spine held when the root being
        checked was written — for a header at height H that is H-1, because a
        block cannot commit to its own hash.  Defaults to the whole spine.
        """
        if not 1 <= height <= len(self._hashes):
            return None
        cut = len(self._hashes) if under is None else int(under)
        if height > cut:
            return None
        out = self._tree.path_at(height - 1, cut)
        out["block_height"] = height
        out["block_hash"] = self._hashes[height - 1]
        out["under"] = cut
        return out

    def root_at(self, count: int) -> str:
        """The root as of `count` blocks — what the header at count+1 commits."""
        return self._tree.root_at(count)

    @property
    def root(self) -> str:
        return self._tree.root_hex

    def dump(self) -> list:
        return list(self._hashes)

    def clone(self) -> "HeaderHistory":
        out = HeaderHistory.__new__(HeaderHistory)
        out._hashes = list(self._hashes)
        out._tree = self._tree.clone()
        return out

    def __len__(self) -> int:
        return len(self._hashes)

    def __repr__(self):
        return f"HeaderHistory({len(self._hashes)} blocks, {self.root[:12]}…)"


def verify_ancestry(block_hash: str, proof: dict, history_root: str) -> bool:
    """Check that `block_hash` sat at the height the proof claims, under a
    `history_root` the client already trusts.  Never raises."""
    try:
        if proof.get("block_hash") != block_hash:
            return False
        if int(proof["pos"]) != int(proof["block_height"]) - 1:
            return False
    except Exception:
        return False
    return verify_witness(block_hash, proof, history_root)
