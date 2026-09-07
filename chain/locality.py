"""Persistent grids, seeded enrolment, and the nullifier partition.

A grid is a lasting thing with a name and a register, not a per-epoch grouping —
it has to be, or nobody could accumulate 40 ceremonies in one.  Membership is
sticky; seating *within* a grid still reshuffles every ceremony, so leadership
stays unpredictable.

Locality proposes and the seed disposes.  A node's candidate grids are the ones
in its region; which of them it lands in is H(seed, node_id), not its own choice.
Free choice of grid is a self-selection attack: an adversary funnels its nodes
into one grid and owns its block outright.  And because the attendance counter
lives in the grid's register, relocating restarts it — so capturing a particular
grid costs 40 ceremonies of visible apprenticeship per node.
"""
from __future__ import annotations

from dataclasses import dataclass

from .crypto import h_bytes, h_hex, verify_sig


@dataclass(frozen=True)
class GridSpec:
    grid_id: str
    region: str
    index: int              # global index, and the nullifier partition it owns

    def __repr__(self):
        return f"GridSpec({self.grid_id}, region={self.region}, part={self.index})"


class Topology:
    """Which grids exist and who belongs to each."""

    def __init__(self, grids, assignment: dict):
        self.grids = {g.grid_id: g for g in grids}
        self.assignment = dict(assignment)
        self._members: dict = {gid: [] for gid in self.grids}
        for nid, gid in sorted(self.assignment.items()):
            self._members[gid].append(nid)

    # ── construction ─────────────────────────────────────────────────────────

    @classmethod
    def build(cls, node_regions: dict, grid_size: int, seed: str) -> "Topology":
        """Lay out grids per region and seat every node deterministically.

        Within a region, nodes are ordered by a keyed hash and dealt round-robin
        into that region's grids: balanced, reproducible by everyone, and chosen
        by nobody.
        """
        by_region: dict = {}
        for nid, region in sorted(node_regions.items()):
            by_region.setdefault(region, []).append(nid)

        specs, assignment = [], {}
        for region in sorted(by_region):
            nodes = by_region[region]
            n_grids = max(1, -(-len(nodes) // grid_size))
            region_grids = [f"{region}-{j}" for j in range(n_grids)]
            ordered = sorted(nodes, key=lambda n: h_hex("enrol", seed, n))
            for i, nid in enumerate(ordered):
                assignment[nid] = region_grids[i % n_grids]
            for gid in region_grids:
                specs.append((region, gid))

        specs.sort()
        grids = [GridSpec(grid_id=gid, region=region, index=i)
                 for i, (region, gid) in enumerate(specs)]
        return cls(grids, assignment)

    def assign_newcomer(self, node_id: str, region: str, seed: str) -> str:
        """Seat a node that arrives after the topology was laid out."""
        candidates = self.grids_in(region)
        if not candidates:
            raise ValueError(f"no grid serves region {region!r}")
        pick = int(h_hex("enrol", seed, node_id), 16) % len(candidates)
        gid = candidates[pick]
        self.assignment[node_id] = gid
        self._members[gid].append(node_id)
        return gid

    def found_grid(self, donor_id: str, new_grid_id: str, movers) -> GridSpec:
        """Add a grid and move a cohort into it.

        The new grid takes the next free index, so existing grids keep theirs.
        That does *not* make the repartition small — K is the modulus in
        `nf mod K`, so every transaction's home moves when K moves — but it
        does mean a grid's identity never silently becomes a different
        partition.
        """
        if new_grid_id in self.grids:
            raise ValueError(f"{new_grid_id} already exists")
        donor = self.grids[donor_id]
        spec = GridSpec(grid_id=new_grid_id, region=donor.region,
                        index=len(self.grids))
        self.grids[new_grid_id] = spec
        self._members[new_grid_id] = []
        for nid in sorted(movers):
            if self.assignment.get(nid) != donor_id:
                raise ValueError(f"{nid} is not in {donor_id}")
            self.assignment[nid] = new_grid_id
            self._members[donor_id].remove(nid)
            self._members[new_grid_id].append(nid)
        return spec

    def next_grid_id(self, region: str) -> str:
        """The next name in this region's series, stable given the topology."""
        used = {g.grid_id for g in self.grids.values() if g.region == region}
        i = 0
        while f"{region}-{i}" in used:
            i += 1
        return f"{region}-{i}"

    # ── views ────────────────────────────────────────────────────────────────

    def grids_in(self, region: str) -> list:
        return sorted(g.grid_id for g in self.grids.values() if g.region == region)

    def members(self, grid_id: str) -> list:
        return list(self._members[grid_id])

    def grid_of(self, node_id: str) -> str:
        return self.assignment[node_id]

    def spec(self, grid_id: str) -> GridSpec:
        return self.grids[grid_id]

    def partition_of(self, grid_id: str) -> int:
        return self.grids[grid_id].index

    @property
    def n_partitions(self) -> int:
        return len(self.grids)

    def grid_ids(self) -> list:
        return sorted(self.grids)

    def needs_split(self, grid_id: str, grid_size: int) -> bool:
        return len(self._members[grid_id]) > 2 * grid_size

    def needs_merge(self, grid_id: str, grid_size: int) -> bool:
        return len(self._members[grid_id]) * 2 < grid_size

    def __repr__(self):
        sizes = {gid: len(m) for gid, m in sorted(self._members.items())}
        return f"Topology({len(self.grids)} grids, sizes={sizes})"


# ═══════════════════════════════════════════════════════════════════════════════
# Nullifier partitioning
# ═══════════════════════════════════════════════════════════════════════════════

def partition_of_nullifier(nullifier: str, n_partitions: int) -> int:
    """Which grid owns a note, from the nullifier alone.

    The nullifier is already a deterministic field element computed inside the
    transaction proof, so the partition is free — and a note can only ever be
    spendable in one grid, which makes cross-grid double spends structurally
    impossible rather than merely detectable.
    """
    if n_partitions < 1:
        raise ValueError("n_partitions must be >= 1")
    raw = nullifier.split(":", 1)[-1]
    return int(raw, 16) % n_partitions


def tx_partition(tx, n_partitions: int):
    """The partition a transaction belongs to, or None if it spans several."""
    parts = {partition_of_nullifier(nf, n_partitions) for nf in tx.nullifiers}
    if len(parts) != 1:
        return None                 # cross-partition: no grid may include it
    return parts.pop()


# ═══════════════════════════════════════════════════════════════════════════════
# Enrolment
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Enrolment:
    """A node's signed claim to one seat in one grid for one epoch.

    Two of these from one node in one epoch is a provable fault with exactly the
    shape leader equivocation already has: two valid signatures, one signer, one
    epoch, two claims.
    """
    node_id: str
    grid_id: str
    epoch: int
    public_hex: str
    signature: str

    @staticmethod
    def message(node_id, grid_id, epoch) -> bytes:
        return h_bytes("enrolment", node_id, grid_id, epoch)

    def verify(self) -> bool:
        return verify_sig(self.public_hex,
                          self.message(self.node_id, self.grid_id, self.epoch),
                          self.signature)


def sign_enrolment(node, grid_id: str, epoch: int) -> Enrolment:
    msg = Enrolment.message(node.id, grid_id, epoch)
    return Enrolment(node_id=node.id, grid_id=grid_id, epoch=epoch,
                     public_hex=node.public_hex, signature=node.signer.sign(msg))


def find_double_enrolments(enrolments):
    """(node_id, (a, b)) for every node that claimed two grids in one epoch."""
    seen, faults = {}, []
    for e in enrolments:
        if not e.verify():
            continue
        key = (e.node_id, e.epoch)
        prior = seen.get(key)
        if prior is None:
            seen[key] = e
        elif prior.grid_id != e.grid_id:
            faults.append((e.node_id, (prior, e)))
    return faults
