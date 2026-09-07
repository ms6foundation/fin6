"""The synchronization ceremony.

Seating.  N validators, row size C.  Row 0 holds the leader alone; rows 1..R
hold up to C seats each, R = ceil((N-1)/C), and only the last row may be short.
Seats are assigned by sorting node ids under a keyed hash of grid_seed, so the
seating is deterministic for everyone, unpredictable before the previous block
fixed the seed, and unchosen by any participant.

Edges.  Each seat (r, c) with r >= 1 synchronises to two peers:

    front(r, c) = (r-1, c)          and the whole of row 1 fronts to the leader
    right(r, c) = (r, (c+1) mod C_r)

C_r is the size of row r, so the rightmost seat's right neighbour is the
leftmost seat of the same row: every row is a ring, and each ring is fed
vertically by the row in front of it.  Degree is 2 per seat regardless of N.

Rounds.  Synchronisation is a bidirectional merge, so the same edges that carry
the proposal down also carry attestations back up.  A round is evaluated from a
snapshot of every seat's envelope, so information moves exactly one hop per
round and the simulation is deterministic and order-independent.  The default
schedule is 2 * diameter: once for the proposal to reach the furthest seat, once
for its attestation to come back.  (The design sketch's R + C is the one-way
bound; the round trip is what finality actually needs.)

Detection.  A row is a ring, so a leader that sends different blocks into
different columns has them meet.  Any seat holding two validly signed proposals
from one leader at one height emits an equivocation fault report whose evidence
is self-substantiating: both signatures, one leader, one height, two hashes.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .block import Block, CeremonyMeta, QuorumCert
from .crypto import h_hex
from .params import ChainParams


# ═══════════════════════════════════════════════════════════════════════════════
# Seating
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Seat:
    row: int
    col: int

    def __str__(self):
        return f"({self.row},{self.col})"


class Grid:
    """The ceremony's fixed communication topology for one attempt."""

    def __init__(self, leader: str, rows, row_size: int, seed: str):
        self.leader = leader
        self.rows = [list(r) for r in rows]      # rows[0] is grid row 1
        self.row_size = row_size
        self.seed = seed
        self.seats = {leader: Seat(0, 0)}
        for r, row in enumerate(self.rows, start=1):
            for c, nid in enumerate(row):
                self.seats[nid] = Seat(r, c)

    @classmethod
    def seat(cls, node_ids, row_size: int, seed: str, exclude_leaders=(),
             standing=None, counting_standing="attester"):
        """Deterministic seating from a seed.

        exclude_leaders lets a view change skip leaders already tried while
        still reshuffling everyone, which is what keeps retries making progress.

        standing (node_id -> standing) puts attesters in the front rows and
        apprentices behind them.  A seat's `front` is the same column one row up,
        which is always an earlier position in the seating order, so ordering
        attesters first guarantees no counting seat ever depends on an apprentice
        to relay — a withholding apprentice can only starve other apprentices.
        The leader is drawn from the counting group.
        """
        ids = list(node_ids)
        if len(ids) < 2:
            raise ValueError("a ceremony needs at least two validators")
        order = sorted(ids, key=lambda nid: h_hex("seat", seed, nid))
        excluded = set(exclude_leaders)

        if standing is not None:
            front = [n for n in order if standing.get(n) == counting_standing]
            back = [n for n in order if standing.get(n) != counting_standing]
            pool = [n for n in front if n not in excluded]
            if not pool:
                raise ValueError(
                    "no untried attester can lead this grid "
                    f"({len(front)} attesters, {len(back)} apprentices)")
            leader = pool[0]
            rest = [n for n in front if n != leader] + back
        else:
            candidates = [n for n in order if n not in excluded]
            if not candidates:
                raise ValueError("every validator has already been tried as leader")
            leader = candidates[0]
            rest = [n for n in order if n != leader]

        rows = [rest[i:i + row_size] for i in range(0, len(rest), row_size)]
        return cls(leader, rows, row_size, seed)

    # ── topology ─────────────────────────────────────────────────────────────

    def front(self, nid: str):
        s = self.seats[nid]
        if s.row == 0:
            return None                       # the leader has nothing in front
        if s.row == 1:
            return self.leader
        return self.rows[s.row - 2][s.col]

    def right(self, nid: str):
        s = self.seats[nid]
        if s.row == 0:
            return None                       # alone in its row
        row = self.rows[s.row - 1]
        if len(row) < 2:
            return None
        return row[(s.col + 1) % len(row)]

    def neighbours(self, nid: str):
        return tuple(p for p in (self.front(nid), self.right(nid))
                     if p is not None and p != nid)

    def edges(self):
        """Undirected sync edges, deterministically ordered."""
        seen = set()
        for nid in self.seats:
            for peer in self.neighbours(nid):
                seen.add(tuple(sorted((nid, peer))))
        return sorted(seen)

    def adjacency(self):
        adj = {nid: set() for nid in self.seats}
        for a, b in self.edges():
            adj[a].add(b)
            adj[b].add(a)
        return adj

    def diameter(self) -> int:
        """Longest shortest-path over the undirected sync graph."""
        adj = self.adjacency()
        best = 0
        for src in adj:
            seen = {src: 0}
            q = deque([src])
            while q:
                cur = q.popleft()
                for nxt in adj[cur]:
                    if nxt not in seen:
                        seen[nxt] = seen[cur] + 1
                        q.append(nxt)
            if len(seen) != len(adj):
                return -1                     # disconnected: should not happen
            best = max(best, max(seen.values()))
        return best

    @property
    def n_rows(self) -> int:
        return len(self.rows)

    def __len__(self):
        return len(self.seats)

    def render(self) -> str:
        """ASCII picture of the seating, leader on top."""
        width = max((len(n) for n in self.seats), default=4) + 2
        lines = [f"{'leader':>10}: " + self.leader.center(width) +
                 "        (row 0, single seat)"]
        for r, row in enumerate(self.rows, start=1):
            seats = " ".join(n.center(width) for n in row)
            ring = "  ⟲" if len(row) > 1 else ""
            lines.append(f"{'row ' + str(r):>10}: {seats}{ring}")
        lines.append(f"{'':>10}  edges={len(self.edges())} "
                     f"diameter={self.diameter()} seats={len(self)}")
        return "\n".join(lines)

    def __repr__(self):
        return (f"Grid(leader={self.leader}, rows={self.n_rows}, "
                f"C={self.row_size}, seats={len(self)})")


# ═══════════════════════════════════════════════════════════════════════════════
# What a seat holds and exchanges
# ═══════════════════════════════════════════════════════════════════════════════

class Envelope:
    """One seat's view of the ceremony.  Merging two envelopes is a union.

    Everything absorbed is checked on the way in against the validator registry
    as well as its signature, so a Byzantine neighbour can neither forge a
    statement a real seat did not make nor invent seats that do not exist —
    without the registry check, made-up node ids would inflate the attestation
    count straight past the quorum.
    """

    __slots__ = ("height", "epoch", "grid_seed", "leader_id", "chain_id",
                 "validators", "counting", "proposals", "attestations",
                 "shadow", "faults")

    def __init__(self, height, epoch, grid_seed, leader_id, chain_id,
                 validators, counting=None):
        self.height = height
        self.epoch = epoch
        self.grid_seed = grid_seed
        self.leader_id = leader_id
        self.chain_id = chain_id
        self.validators = validators          # node_id -> public key
        # Seats whose attestation counts toward quorum.  Apprentices are seated
        # and do the work, but their attestations land in `shadow` instead —
        # they move the attendance roll, not the block.
        self.counting = set(validators) if counting is None else set(counting)
        self.proposals = {}          # block_hash -> SignedProposal
        self.attestations = {}       # node_id   -> Attestation  (counting)
        self.shadow = {}             # node_id   -> Attestation  (apprentices)
        self.faults = {}             # key       -> FaultReport

    # ── admission ────────────────────────────────────────────────────────────

    def add_proposal(self, sp) -> bool:
        if sp.block_hash in self.proposals:
            return False
        if (sp.height != self.height or sp.epoch != self.epoch
                or sp.grid_seed != self.grid_seed
                or sp.leader_id != self.leader_id
                or sp.block.header.chain_id != self.chain_id):
            return False
        if sp.public_hex != self.validators.get(sp.leader_id):
            return False                      # not the seated leader's key
        if not sp.verify():
            return False
        self.proposals[sp.block_hash] = sp
        return True

    def add_attestation(self, att) -> bool:
        target = (self.attestations if att.node_id in self.counting
                  else self.shadow)
        if att.node_id in target:
            return False
        if (att.height != self.height or att.epoch != self.epoch
                or att.grid_seed != self.grid_seed
                or att.chain_id != self.chain_id):
            return False
        if att.public_hex != self.validators.get(att.node_id):
            return False                      # unknown seat, or wrong key
        if not att.verify():
            return False
        target[att.node_id] = att
        return True

    def add_fault(self, fr) -> bool:
        key = fr.key()
        if key in self.faults:
            return False
        if fr.height != self.height or fr.epoch != self.epoch:
            return False
        if fr.public_hex != self.validators.get(fr.reporter):
            return False                      # only seated validators report
        if not fr.verify():
            return False
        self.faults[key] = fr
        return True

    def absorb(self, other: "Envelope") -> int:
        changed = 0
        for sp in other.proposals.values():
            changed += self.add_proposal(sp)
        for att in other.attestations.values():
            changed += self.add_attestation(att)
        for att in other.shadow.values():
            changed += self.add_attestation(att)
        for fr in other.faults.values():
            changed += self.add_fault(fr)
        return changed

    def clone(self) -> "Envelope":
        out = Envelope(self.height, self.epoch, self.grid_seed, self.leader_id,
                       self.chain_id, self.validators, self.counting)
        out.proposals = dict(self.proposals)
        out.attestations = dict(self.attestations)
        out.shadow = dict(self.shadow)
        out.faults = dict(self.faults)
        return out

    # ── queries ──────────────────────────────────────────────────────────────

    def equivocation_evidence(self):
        """Two conflicting signed proposals from the leader, or None."""
        if len(self.proposals) < 2:
            return None
        a, b = sorted(self.proposals)[:2]
        return (self.proposals[a], self.proposals[b])

    def substantiated_equivocation(self):
        for fr in self.faults.values():
            if fr.kind == "equivocation" and fr.substantiated():
                return fr
        return None

    def sole_proposal(self):
        if len(self.proposals) == 1:
            return next(iter(self.proposals.values()))
        return None

    def attestations_for(self, block_hash):
        """Counting attestations only — quorum never sees a shadow."""
        return [a for a in self.attestations.values()
                if a.block_hash == block_hash]

    def attended(self):
        """Everyone who produced a valid attestation of either kind."""
        return set(self.attestations) | set(self.shadow)


# ═══════════════════════════════════════════════════════════════════════════════
# Leader behaviours
# ═══════════════════════════════════════════════════════════════════════════════

class NodeWorkload:
    """Default: the leader builds from its own mempool and seats validate it.

    The tiered scheduler substitutes a workload per tier, which is what lets the
    same Ceremony machinery run a local grid, a super grid and the supreme grid
    without changing a line of it.
    """

    name = "node"

    def build(self, leader, meta, limit=None):
        return leader.build_block(meta, limit=limit)

    def validate(self, node, block):
        return node.validate_block(block)


class HonestLeader:
    """Builds one block and sends it to every seat in row 1."""

    name = "honest"

    def propose(self, leader, grid: Grid, meta: CeremonyMeta, limit=None,
                workload=None):
        block = (workload or NodeWorkload()).build(leader, meta, limit=limit)
        sp = leader.propose(block, meta.epoch, meta.grid_seed)
        targets = {leader.id: sp}
        for nid in (grid.rows[0] if grid.rows else []):
            targets[nid] = sp
        return targets


class SilentLeader:
    """Proposes nothing.  The ceremony must time out and change view."""

    name = "silent"

    def propose(self, leader, grid, meta, limit=None, workload=None):
        return {}


class EquivocatingLeader:
    """Sends one block to even columns of row 1 and a different one to odd.

    Both blocks are individually valid — the second is simply empty — so no seat
    can catch this by validating what it received.  Only the ring cross-check
    inside a row surfaces it.
    """

    name = "equivocating"

    def propose(self, leader, grid, meta, limit=None, workload=None):
        wl = workload or NodeWorkload()
        block_a = wl.build(leader, meta, limit=limit)
        block_b = wl.build(leader, meta, limit=0)
        if block_a.hash() == block_b.hash():
            raise ValueError("cannot equivocate: both blocks are identical "
                             "(no transactions to differ over)")
        sp_a = leader.propose(block_a, meta.epoch, meta.grid_seed)
        sp_b = leader.propose(block_b, meta.epoch, meta.grid_seed)
        targets = {leader.id: sp_a}
        for c, nid in enumerate(grid.rows[0] if grid.rows else []):
            targets[nid] = sp_a if c % 2 == 0 else sp_b
        return targets


# ═══════════════════════════════════════════════════════════════════════════════
# Running one ceremony
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SeatDecision:
    node_id: str
    seat: Seat
    status: str                  # "accept" | "abort"
    reason: str
    block_hash: str | None = None
    attestations: int = 0


@dataclass
class CeremonyResult:
    status: str                  # "finalised" | "aborted"
    reason: str
    grid: Grid
    height: int
    epoch: int
    rounds: int
    block: Block | None = None
    quorum_cert: QuorumCert | None = None
    decisions: dict = field(default_factory=dict)
    faults: list = field(default_factory=list)
    trace: list = field(default_factory=list, repr=False)
    directed_messages: int = 0
    roll: object = None

    @property
    def finalised(self) -> bool:
        return self.status == "finalised"

    def accepted(self):
        return [d for d in self.decisions.values() if d.status == "accept"]

    def __repr__(self):
        return (f"CeremonyResult({self.status}, h={self.height}, "
                f"epoch={self.epoch}, leader={self.grid.leader}, "
                f"{len(self.accepted())}/{len(self.decisions)} accepted, "
                f"{self.rounds} rounds) — {self.reason}")


class Ceremony:
    """One scheduled ceremony over one grid."""

    def __init__(self, grid: Grid, nodes: dict, params: ChainParams,
                 height: int, epoch: int, rounds: int | None = None,
                 quorum: int | None = None, workload=None, counting=None,
                 grid_id: str = "grid"):
        self.grid_id = grid_id
        self.grid = grid
        self.nodes = nodes
        self.params = params
        self.height = height
        self.epoch = epoch
        self.workload = workload or NodeWorkload()
        # Seats whose attestation counts.  Defaults to everyone, which is the
        # single-grid case; the tiered scheduler passes the register's attesters.
        self.counting = (set(grid.seats) if counting is None else set(counting))
        d = grid.diameter()
        self.rounds = rounds if rounds is not None else max(2, 2 * d)
        self.quorum = (quorum if quorum is not None
                       else params.quorum_size(len(self.counting)))

    # ── the schedule ─────────────────────────────────────────────────────────

    def run(self, behaviour=None, limit=None) -> CeremonyResult:
        behaviour = behaviour or HonestLeader()
        grid, nodes = self.grid, self.nodes
        seed = grid.seed
        chain_id = nodes[grid.leader].chain_id
        validators = {nid: nodes[nid].public_hex for nid in grid.seats}
        meta = CeremonyMeta(epoch=self.epoch, leader_id=grid.leader,
                            rows=grid.n_rows, row_size=grid.row_size,
                            grid_seed=seed)

        env = {nid: Envelope(self.height, self.epoch, seed, grid.leader,
                             chain_id, validators, self.counting)
               for nid in grid.seats}

        # ── round 0: the leader proposes into row 1 ──────────────────────────
        seeded = behaviour.propose(nodes[grid.leader], grid, meta, limit=limit,
                                   workload=self.workload)
        for target, sp in seeded.items():
            if target in env:
                env[target].add_proposal(sp)

        validated = {}          # node_id -> (block_hash, ok, reason)
        reacted = set()
        trace = []
        self._react_all(env, validated, reacted)
        trace.append(self._snapshot_counts(0, env))

        # ── rounds 1..T: front and right, both directions ────────────────────
        edges = grid.edges()
        messages = 0
        for t in range(1, self.rounds + 1):
            snap = {nid: e.clone() for nid, e in env.items()}
            for a, b in edges:
                env[a].absorb(snap[b])
                env[b].absorb(snap[a])
                messages += 2
            self._react_all(env, validated, reacted)
            trace.append(self._snapshot_counts(t, env))

        return self._decide(env, validated, trace, messages, meta)

    # ── per-seat reaction ────────────────────────────────────────────────────

    def _react_all(self, env, validated, reacted):
        for nid in self.grid.seats:
            self._react(nid, env, validated, reacted)

    def _react(self, nid, env, validated, reacted):
        e = env[nid]
        node = self.nodes[nid]

        # Conflicting proposals: report, and never attest to either.
        if e.equivocation_evidence() and nid not in reacted:
            a, b = e.equivocation_evidence()
            e.add_fault(node.report("equivocation", self.height, self.epoch,
                                    "leader proposed two blocks", (a, b)))
            reacted.add(nid)
            e.attestations.pop(nid, None)
            return
        if nid in reacted:
            return

        sp = e.sole_proposal()
        if sp is None or nid in validated:
            return

        # Each seat validates the block itself, exactly once per ceremony.
        ok, why = self.workload.validate(node, sp.block)
        validated[nid] = (sp.block_hash, ok, why)
        if ok:
            e.add_attestation(node.attest(sp.block_hash, self.height,
                                          self.epoch, self.grid.seed))
        else:
            e.add_fault(node.report("invalid_block", self.height, self.epoch,
                                    why[:120], (sp,)))
            reacted.add(nid)

    def _snapshot_counts(self, t, env):
        return {
            "round": t,
            "with_proposal": sum(1 for e in env.values() if e.proposals),
            "attested": sum(1 for e in env.values() if e.attestations),
            "max_attestations": max((len(e.attestations) for e in env.values()),
                                    default=0),
            "shadow": max((len(e.shadow) for e in env.values()), default=0),
            "faults": sum(1 for e in env.values() if e.faults),
        }

    # ── the attendance roll ──────────────────────────────────────────────────

    def _roll(self, env):
        """Who was seated, and who did the work — the register's only input.

        Built from the union of every seat's view, so a node that attested but
        whose attestation reached only part of the grid is still recorded.
        """
        from .register import AttendanceRoll
        attended = set()
        for e in env.values():
            attended |= e.attended()
        return AttendanceRoll(grid_id=self.grid_id, epoch=self.epoch,
                              leader_id=self.grid.leader,
                              seated=tuple(sorted(self.grid.seats)),
                              attended=tuple(sorted(attended)))

    # ── the decision rule ────────────────────────────────────────────────────

    def _decide(self, env, validated, trace, messages, meta):
        decisions, all_faults = {}, {}
        for nid in self.grid.seats:
            e = env[nid]
            all_faults.update(e.faults)
            seat = self.grid.seats[nid]

            equiv = e.substantiated_equivocation()
            if equiv is not None:
                decisions[nid] = SeatDecision(
                    nid, seat, "abort", "leader equivocated", None,
                    len(e.attestations))
                continue
            sp = e.sole_proposal()
            if sp is None:
                reason = ("no proposal reached this seat" if not e.proposals
                          else "conflicting proposals")
                decisions[nid] = SeatDecision(nid, seat, "abort", reason, None,
                                              len(e.attestations))
                continue
            own = validated.get(nid)
            if own is None or not own[1]:
                why = own[2] if own else "not validated"
                decisions[nid] = SeatDecision(nid, seat, "abort",
                                              f"block rejected: {why}",
                                              sp.block_hash,
                                              len(e.attestations))
                continue
            n_att = len(e.attestations_for(sp.block_hash))
            if n_att < self.quorum:
                decisions[nid] = SeatDecision(
                    nid, seat, "abort",
                    f"{n_att} attestations, quorum is {self.quorum}",
                    sp.block_hash, n_att)
                continue
            decisions[nid] = SeatDecision(nid, seat, "accept", "ok",
                                          sp.block_hash, n_att)

        accepted = [d for d in decisions.values() if d.status == "accept"]
        hashes = {d.block_hash for d in accepted}
        base = dict(status="aborted", grid=self.grid, height=self.height,
                    epoch=self.epoch, rounds=self.rounds, decisions=decisions,
                    faults=list(all_faults.values()), trace=trace,
                    directed_messages=messages, roll=self._roll(env))

        if len(hashes) > 1:
            return CeremonyResult(reason="seats accepted different blocks "
                                         "(should be impossible)", **base)
        if not accepted:
            reasons = {d.reason for d in decisions.values()}
            return CeremonyResult(
                reason="; ".join(sorted(reasons))[:160] or "no seat accepted",
                **base)
        if len(accepted) < self.quorum:
            return CeremonyResult(
                reason=f"only {len(accepted)} seats accepted, quorum is "
                       f"{self.quorum}", **base)

        block_hash = hashes.pop()
        winner = next(env[d.node_id].sole_proposal() for d in accepted)
        atts = {}
        for d in accepted:
            for a in env[d.node_id].attestations_for(block_hash):
                atts[a.node_id] = a
        cert = QuorumCert.build(winner.block.header.chain_id, self.height,
                                block_hash, self.epoch, self.grid.seed,
                                atts.values())
        block = winner.block
        block.quorum_cert = cert
        base["status"] = "finalised"
        return CeremonyResult(reason="ok", block=block, quorum_cert=cert, **base)


# ═══════════════════════════════════════════════════════════════════════════════
# One epoch, with view change
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EpochResult:
    result: CeremonyResult
    attempts: list = field(default_factory=list)

    @property
    def finalised(self):
        return self.result.finalised


def run_epoch(nodes: dict, params: ChainParams, height: int, epoch: int,
              base_seed: str, behaviours: dict | None = None,
              max_attempts: int | None = None, rounds: int | None = None,
              limit=None, on_attempt=None) -> EpochResult:
    """Run one ceremony, changing view until a block finalises or we run out.

    Each attempt reshuffles the whole grid from a fresh seed derived from the
    abort, and skips leaders already tried, so retries make progress.
    """
    behaviours = behaviours or {}
    ids = list(nodes)
    max_attempts = max_attempts if max_attempts is not None else len(ids)
    tried, attempts = [], []

    for attempt in range(max_attempts):
        seed = h_hex("view", base_seed, epoch, attempt)
        grid = Grid.seat(ids, params.row_size, seed, exclude_leaders=tried)
        ceremony = Ceremony(grid, nodes, params, height, epoch, rounds=rounds)
        behaviour = behaviours.get(grid.leader, HonestLeader())
        result = ceremony.run(behaviour, limit=limit)
        attempts.append(result)
        if on_attempt:
            on_attempt(attempt, grid, behaviour, result)
        if result.finalised:
            return EpochResult(result=result, attempts=attempts)
        tried.append(grid.leader)

    return EpochResult(result=attempts[-1], attempts=attempts)
