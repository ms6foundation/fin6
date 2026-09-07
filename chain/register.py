"""The grid register — the objective record of who showed up.

Standing is not any node's opinion.  It is state, updated once per ceremony by a
deterministic function of (previous register, attendance roll, fault evidence),
and committed as a root that every seat recomputes and the leader cannot fake —
exactly the discipline chain/state.py already applies to the ledger roots.

A node's 40 ceremonies are 40 ceremonies *of its grid*, recorded in that grid's
register, whose root travels up with the block.  So standing is grid-local in
how it is earned and global in how it is checked.

Timing: the roll for ceremony h is only complete once ceremony h has finished,
so a block at height h carries the roll of h-1.  The register therefore always
trails the ceremony by one, which is what makes it proposable at all.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from .seal import seal_root


class Standing:
    OBSERVER = "observer"        # not enrolled anywhere
    APPRENTICE = "apprentice"    # seated, shadow attestations only
    ATTESTER = "attester"        # attestation counts toward quorum
    SUSPENDED = "suspended"      # provable fault

    ALL = (OBSERVER, APPRENTICE, ATTESTER, SUSPENDED)


@dataclass(frozen=True)
class AttendanceRoll:
    """Who was seated in one ceremony, and who did the work."""
    grid_id: str
    epoch: int
    leader_id: str
    seated: tuple = ()
    attended: tuple = ()        # produced a valid attestation, shadow or counting

    def digest(self) -> str:
        from .crypto import h_hex
        return h_hex("roll", self.grid_id, self.epoch, self.leader_id,
                     sorted(self.seated), sorted(self.attended))


@dataclass
class MemberRecord:
    node_id: str
    joined_epoch: int
    standing: str = Standing.APPRENTICE
    consecutive: int = 0
    total_attended: int = 0
    last_seen_epoch: int = -1
    led_count: int = 0
    faults: tuple = ()
    #: The grid this member's standing was carried over from, when it was moved
    #: to found a new one.  Empty for everyone who earned it here.  Committed
    #: in the root deliberately: carrying standing across grids is a waiver of
    #: the rule that relocating restarts the counter, and a waiver that is not
    #: visible in the state is a waiver nobody can audit.
    founded_from: str = ""

    def as_tuple(self):
        """Canonical serialisation — what the root commits to."""
        return (self.node_id, self.joined_epoch, self.standing,
                self.consecutive, self.total_attended, self.last_seen_epoch,
                self.led_count, len(self.faults), self.founded_from)

    def counts(self) -> bool:
        return self.standing == Standing.ATTESTER

    def leader_eligible(self) -> bool:
        return self.standing == Standing.ATTESTER and not self.faults


class GridRegister:
    """One grid's membership record."""

    def __init__(self, grid_id: str, epoch: int = 0,
                 attend_threshold: int = 40, forgiveness: int = 0):
        self.grid_id = grid_id
        self.epoch = epoch
        self.attend_threshold = attend_threshold
        self.forgiveness = forgiveness          # absences tolerated before reset
        self.members: dict = {}
        self._misses: dict = {}

    # ── construction ─────────────────────────────────────────────────────────

    @classmethod
    def genesis(cls, grid_id: str, founders, attend_threshold: int = 40,
                forgiveness: int = 0, epoch: int = 0) -> "GridRegister":
        """Found a grid.

        The founding cohort starts as attesters.  It has to: every node begins
        with a zero counter, so a grid whose members are all apprentices can
        never reach quorum and never runs a ceremony to raise anyone's counter.
        The bootstrap is a trusted setup and is named as one.
        """
        reg = cls(grid_id, epoch=epoch, attend_threshold=attend_threshold,
                  forgiveness=forgiveness)
        for nid in sorted(founders):
            reg.members[nid] = MemberRecord(
                node_id=nid, joined_epoch=epoch, standing=Standing.ATTESTER,
                consecutive=attend_threshold, total_attended=attend_threshold)
        return reg

    def admit(self, node_id: str, epoch: int | None = None):
        """A new member joins, at zero.  Relocating here costs the full gate."""
        if node_id in self.members:
            raise ValueError(f"{node_id} is already in {self.grid_id}")
        self.members[node_id] = MemberRecord(
            node_id=node_id, joined_epoch=self.epoch if epoch is None else epoch,
            standing=Standing.APPRENTICE)
        return self.members[node_id]

    # ── the update rule ──────────────────────────────────────────────────────

    def apply(self, roll: AttendanceRoll, faulted=()) -> int:
        """Advance the register by one ceremony.  Deterministic and total.

        Every seat runs this and must reach the same root, so nothing here may
        depend on local observation, wall-clock time, or iteration order.
        """
        if roll.grid_id != self.grid_id:
            raise ValueError(f"roll is for {roll.grid_id}, not {self.grid_id}")
        attended = set(roll.attended)
        seated = set(roll.seated)
        faulted = set(faulted)

        for nid in sorted(seated | faulted):
            rec = self.members.get(nid)
            if rec is None:                      # seated without being admitted
                rec = self.admit(nid, epoch=roll.epoch)

            if nid in faulted:
                rec.standing = Standing.SUSPENDED
                rec.consecutive = 0
                rec.faults = rec.faults + (roll.epoch,)
                self._misses.pop(nid, None)
                continue
            if rec.standing == Standing.SUSPENDED:
                continue                          # suspension is not self-healing

            if nid in attended:
                rec.consecutive += 1
                rec.total_attended += 1
                rec.last_seen_epoch = roll.epoch
                self._misses[nid] = 0
                if (rec.standing == Standing.APPRENTICE
                        and rec.consecutive >= self.attend_threshold):
                    rec.standing = Standing.ATTESTER
            else:
                missed = self._misses.get(nid, 0) + 1
                self._misses[nid] = missed
                if missed > self.forgiveness:
                    rec.consecutive = 0

        leader = self.members.get(roll.leader_id)
        if leader is not None and roll.leader_id not in faulted:
            leader.led_count += 1

        self.epoch = roll.epoch + 1
        return self.root()

    # ── founding a grid ──────────────────────────────────────────────────────

    def release(self, node_ids) -> list:
        """Take members out, records and all.  Used only to found a grid.

        Refuses anything but an attester in good standing: an apprentice would
        arrive at the new grid unable to vote, and a suspended member would
        arrive with its suspension laundered into a fresh register.
        """
        moving = []
        for nid in sorted(node_ids):
            rec = self.members.get(nid)
            if rec is None:
                raise ValueError(f"{nid} is not in {self.grid_id}")
            if rec.standing != Standing.ATTESTER:
                raise ValueError(f"{nid} is {rec.standing}, not an attester — "
                                 f"only attesters can found a grid")
            if rec.faults:
                raise ValueError(f"{nid} carries a fault and cannot found")
            moving.append(rec)
        for rec in moving:
            del self.members[rec.node_id]
            self._misses.pop(rec.node_id, None)
        return moving

    @classmethod
    def found(cls, grid_id: str, records, donor_id: str, epoch: int,
              attend_threshold: int = 40, forgiveness: int = 0):
        """A new grid, founded by a cohort that keeps what it earned.

        This is the same waiver `genesis` uses, applied again: a grid of pure
        apprentices can never reach quorum, so it can never run the ceremony
        that would promote anyone, so a grid created from newcomers alone is
        deadlocked permanently rather than slowly.  Every new grid is therefore
        a small genesis, and — like genesis — it is only honest if it is
        recorded.  `founded_from` is that record, and it is in the root.
        """
        reg = cls(grid_id, epoch=epoch, attend_threshold=attend_threshold,
                  forgiveness=forgiveness)
        for rec in records:
            reg.members[rec.node_id] = replace(rec, founded_from=donor_id)
        return reg

    # ── views ────────────────────────────────────────────────────────────────

    def standing_of(self, node_id: str) -> str:
        rec = self.members.get(node_id)
        return rec.standing if rec else Standing.OBSERVER

    def attesters(self) -> list:
        return sorted(n for n, r in self.members.items() if r.counts())

    def apprentices(self) -> list:
        return sorted(n for n, r in self.members.items()
                      if r.standing == Standing.APPRENTICE)

    def leader_candidates(self) -> list:
        return sorted(n for n, r in self.members.items() if r.leader_eligible())

    def seated_members(self) -> list:
        """Everyone who takes a seat: attesters and apprentices, not suspended."""
        return sorted(n for n, r in self.members.items()
                      if r.standing in (Standing.ATTESTER, Standing.APPRENTICE))

    def quorum(self, num=2, den=3) -> int:
        """Quorum is over ATTESTERS only — apprentices hold seats, not votes."""
        n = len(self.attesters())
        return max(1, -(-(n * num) // den))

    def root(self) -> int:
        return seal_root("register",
                         [self.grid_id, self.epoch] +
                         [r.as_tuple() for _, r in sorted(self.members.items())])

    # ── persistence ──────────────────────────────────────────────────────────

    def dump(self) -> dict:
        """Canonical enough to store, complete enough to restore.

        `as_tuple` is what the root commits to and keeps only the *number* of
        faults; a store has to keep the epochs themselves, and the miss counters
        too, or a restored node would forgive an absence the network did not.
        """
        return {
            "grid_id": self.grid_id, "epoch": self.epoch,
            "attend_threshold": self.attend_threshold,
            "forgiveness": self.forgiveness,
            "members": [
                (r.node_id, r.joined_epoch, r.standing, r.consecutive,
                 r.total_attended, r.last_seen_epoch, r.led_count,
                 list(r.faults), r.founded_from)
                for _, r in sorted(self.members.items())],
            "misses": sorted(self._misses.items()),
        }

    @classmethod
    def load(cls, dump: dict) -> "GridRegister":
        out = cls(dump["grid_id"], epoch=dump["epoch"],
                  attend_threshold=dump["attend_threshold"],
                  forgiveness=dump["forgiveness"])
        for (nid, joined, standing, consecutive, total, last_seen, led,
             faults, founded_from) in dump["members"]:
            out.members[nid] = MemberRecord(
                node_id=nid, joined_epoch=joined, standing=standing,
                consecutive=consecutive, total_attended=total,
                last_seen_epoch=last_seen, led_count=led,
                faults=tuple(faults), founded_from=founded_from)
        out._misses = dict(dump["misses"])
        return out

    def clone(self) -> "GridRegister":
        out = GridRegister(self.grid_id, self.epoch, self.attend_threshold,
                           self.forgiveness)
        out.members = {k: replace(v) for k, v in self.members.items()}
        out._misses = dict(self._misses)
        return out

    def __len__(self):
        return len(self.members)

    def __repr__(self):
        return (f"GridRegister({self.grid_id}, epoch={self.epoch}, "
                f"{len(self.attesters())} attesters, "
                f"{len(self.apprentices())} apprentices, "
                f"root={str(self.root())[:10]}…)")
