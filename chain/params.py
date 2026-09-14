"""Parameter presets for the fin6 private chain.

Everything that affects the algebra lives here, so a deployment can be pinned
to one frozen ChainParams and both sides can compare it field by field.

  DEMO    small enough to run a whole ceremony in seconds, and **deliberately
          insecure**: 8 coordinates of which 4 are random puts the
          note-commitment MQ instance well inside Groebner range.  The ZK
          proof still runs at full strength, because that costs milliseconds.
          Tests and the demos use it and nothing else should.

  STRONG  what used to be described as "sized per mq/mq.md".  It is not, and
          the review in docs/pre_genesis_review.md is where that surfaced:
          mq.md revised its own guidance after STRONG was written — blinders
          from 8 to **62** for 2^128, and folds from 8 down to **2**, with the
          note that a high fold count is "actively harmful" because the
          security gap `m - h = n_folds + opened - 1` does not shrink as n
          grows.  STRONG has 44 blinders and 8 folds.  Kept for comparison.

  LAUNCH  what mq.md actually recommends: 62 blinders, 2 folds.  Measured at
          0.53 s to prove and 0.31 s to verify a one-input transaction, in one
          backend, at 378 KB.  The old docstring here claimed "minutes per
          transaction in pure Python", which was wrong by two orders of
          magnitude and is the sort of claim that decides a launch.

  LOCAL   a testnet on one machine: one backend, a short apprenticeship.

## On sizing, and what `assess` is for

mq.md ends its parameter section with the sentence this module takes as its
mandate: *"Treat these as a floor for rejecting bad parameters, not a
guarantee."*  `ChainParams.assess` is that floor, written down — because
`GenesisDocument.verify` checked that parameter *names* were known and never
that their *values* were safe, so a document with DEMO's algebra and
production hardening verified with zero problems and zero caveats.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict

#: mq.md's revised sizing, which is what `assess` enforces as a floor.  The
#: numbers are that document's, not this one's: blinders 62 for 2^128, 90 for
#: 2^192, 116 for 2^256, at two fold rows.  It also says, of its own estimates,
#: that they assume semi-regular behaviour the structured rows do not satisfy —
#: so these reject bad parameters and promise nothing about good ones.
BLINDERS_128 = 62
BLINDERS_192 = 90
RECOMMENDED_FOLDS = 2
#: Below this, the instance is not "smaller than recommended", it is solvable.
#: DEMO's four blinders are here, which is why the README calls it insecure and
#: why a document carrying it should not verify clean.
GROEBNER_FLOOR = 16
#: B is set by the value range, not by security — bit variables carry no
#: entropy — so the only question it answers is whether the chain can express
#: the amounts it exists to move.  2^16 cannot.
RANGE_FLOOR = 16
RANGE_COMFORTABLE = 32
SOUNDNESS_BITS = 80
TIER_ORDER = ("local", "super", "supreme")

# Fixed note coordinates: value, asset, owner, rho.  Everything after these is
# a random blinder, which is what makes the published note commitment hiding.
NOTE_VALUE = 0
NOTE_ASSET = 1
NOTE_OWNER = 2
NOTE_RHO = 3
NOTE_FIXED_COORDS = 4


@dataclass(frozen=True)
class ChainParams:
    """Every knob the chain's algebra and consensus depend on."""

    name: str

    # ── note / transaction algebra ────────────────────────────────────────────
    n_note: int = 8          # coordinates per note (fixed 4 + blinders)
    note_folds: int = 4      # fold rows in the note MQ system
    range_bits: int = 12     # B: output values must lie in [0, 2^B)
    zk_rounds: int = 80      # SSH rounds per transaction proof (2^-80)

    # ── accumulator / seal tree ───────────────────────────────────────────────
    seal_d: int = 8

    # ── proof systems ─────────────────────────────────────────────────────────
    security_bits: int = 80
    proof_backends: tuple = ("mpcith", "ssh5", "ssh3")  # what a wallet proves in
    default_backend: str = "ssh5"         # what a bare verify_transaction checks

    # ── standing ──────────────────────────────────────────────────────────────
    attend_threshold: int = 40
    # A new grid needs attesters on day one or it can never run the ceremony
    # that would promote anyone.  `founding_cohort` is how many move across
    # with their standing intact; 4 is the smallest that still tolerates one
    # fault (n = 3f+1 at f = 1, quorum 3).
    founding_cohort: int = 4            # consecutive ceremonies to become an attester
    forgiveness: int = 0                  # absences tolerated before the counter resets

    # ── consensus ─────────────────────────────────────────────────────────────
    chain_id: str = "fin6-private-v1"
    row_size: int = 5        # C: seats per ceremony row
    grid_size: int = 5       # g: target seats per grid, and per super grid
    quorum_num: int = 2      # quorum = ceil(N * num / den) attestations
    quorum_den: int = 3

    # tier -> proof backend.  See backend_for().
    proof_policy: tuple = (("local", "mpcith"), ("super", "ssh5"),
                           ("supreme", "ssh3"))

    def __post_init__(self):
        if self.n_note <= NOTE_FIXED_COORDS:
            raise ValueError(
                f"n_note={self.n_note} leaves no blinder coordinates; "
                f"need > {NOTE_FIXED_COORDS}")
        if self.range_bits < 1:
            raise ValueError("range_bits must be >= 1")
        if self.row_size < 2:
            raise ValueError("row_size must be >= 2 for a row to form a ring")
        if not 0 < self.quorum_num <= self.quorum_den:
            raise ValueError("quorum fraction must lie in (0, 1]")

    @property
    def note_blinders(self) -> int:
        return self.n_note - NOTE_FIXED_COORDS

    @property
    def max_value(self) -> int:
        return 1 << self.range_bits

    def backend_for(self, tier: str) -> str:
        """Which proof system guards a tier.

        mpcith / ssh5 / ssh3 from local to supreme: smallest proof where the
        most verifying happens, simplest analysis where the output is
        irreversible.  All three now ship in mq/.
        """
        return dict(self.proof_policy)[tier]

    def quorum_size(self, n_nodes: int) -> int:
        """Attestations needed to finalise, ceil(n * num / den)."""
        num, den = self.quorum_num, self.quorum_den
        return -(-(n_nodes * num) // den)

    def fingerprint(self) -> dict:
        """Serialisable view, for pinning params across a network."""
        return asdict(self)

    # ── is this safe to launch? ───────────────────────────────────────────────

    def assess(self, *, tiers: int = 1) -> tuple:
        """(problems, caveats) about the *values*, not the names.

        mq.md ends its parameter section with the mandate this method takes
        literally: "Treat these as a floor for rejecting bad parameters, not a
        guarantee."  A problem here means a document that should never be
        launched; a caveat means one somebody should have to look at.

        `tiers` because the proof policy is only as wide as the tiers that run:
        a one-tier network needs one backend, and carrying three costs 3.27 MB
        a transaction for two that nothing verifies.
        """
        problems, caveats = [], []

        # ── the note commitment ──────────────────────────────────────────────
        k = self.note_blinders
        if k < GROEBNER_FLOOR:
            problems.append(
                f"{k} blinder coordinates puts the note commitment inside "
                f"Groebner range; mq.md sizes the hidden block at "
                f"{BLINDERS_128} for 2^128 and never below {GROEBNER_FLOOR}")
        elif k < BLINDERS_128:
            caveats.append(
                f"{k} blinders is below the {BLINDERS_128} mq.md sizes for "
                f"2^128 (it recommends {BLINDERS_192} for 2^192)")
        if self.note_folds > RECOMMENDED_FOLDS:
            caveats.append(
                f"{self.note_folds} fold rows against the {RECOMMENDED_FOLDS} "
                f"mq.md recommends: the security gap m - h is "
                f"n_folds + opened - 1 and does not shrink as n grows, so the "
                f"fold count sets the loss directly")

        # ── what a value can be ──────────────────────────────────────────────
        if self.range_bits < RANGE_FLOOR:
            problems.append(
                f"range_bits={self.range_bits} caps a note at "
                f"{self.max_value - 1:,} units, which is not an amount of "
                f"money; B is a size cost rather than a security parameter, so "
                f"there is no reason to economise on it")
        elif self.range_bits < RANGE_COMFORTABLE:
            caveats.append(
                f"range_bits={self.range_bits} caps a note at "
                f"{self.max_value - 1:,} units")

        # ── the proof ────────────────────────────────────────────────────────
        if self.zk_rounds < SOUNDNESS_BITS:
            problems.append(f"zk_rounds={self.zk_rounds} is below 2^-"
                            f"{SOUNDNESS_BITS} soundness")
        if self.security_bits < SOUNDNESS_BITS:
            problems.append(f"security_bits={self.security_bits} is below "
                            f"{SOUNDNESS_BITS}")

        # ── and the parameters have to agree with each other ─────────────────
        # None of these are judgement calls; each is a set of fields that
        # cannot all be right at once, and none of them was checked anywhere.
        if self.default_backend not in self.proof_backends:
            problems.append(
                f"default_backend {self.default_backend!r} is not in "
                f"proof_backends {list(self.proof_backends)}: a bare "
                f"verify_transaction would look for a proof no wallet makes")
        policy = dict(self.proof_policy)
        needed = [t for t in TIER_ORDER[:max(1, int(tiers))]]
        for tier in needed:
            backend = policy.get(tier)
            if backend is None:
                problems.append(f"no proof backend for the {tier} tier")
            elif backend not in self.proof_backends:
                problems.append(
                    f"the {tier} tier verifies with {backend!r}, which no "
                    f"wallet proves in")
        spare = [b for b in self.proof_backends
                 if b not in {policy.get(t) for t in needed}]
        if spare:
            caveats.append(
                f"{len(self.proof_backends)} backends for {len(needed)} "
                f"tier(s): every transaction carries {sorted(spare)} that "
                f"nothing verifies at this tier count, and a submission with "
                f"all three is 3.27 MB against a 1 MB client frame ceiling")

        # ── consensus ────────────────────────────────────────────────────────
        if self.quorum_num * 3 < self.quorum_den * 2:
            problems.append(
                f"a quorum of {self.quorum_num}/{self.quorum_den} is below "
                f"two thirds, so two disjoint quorums can finalise two blocks")
        if self.attend_threshold < 1:
            problems.append("attend_threshold must be at least 1")
        if self.founding_cohort < 4:
            caveats.append(
                f"a founding cohort of {self.founding_cohort} cannot tolerate "
                f"a fault: n = 3f+1 at f = 1 needs 4")
        return problems, caveats

    def launchable(self, *, tiers: int = 1) -> bool:
        return not self.assess(tiers=tiers)[0]


# Fast; note commitments are undersized.  Tests and the runnable demo.
DEMO = ChainParams(name="demo")

# The two-backend mapping, for comparing against the full policy.
NO_MPCITH = ChainParams(name="no-mpcith",
                        proof_backends=("ssh5", "ssh3"),
                        proof_policy=(("local", "ssh5"), ("super", "ssh5"),
                                      ("supreme", "ssh3")))
DESIGNED = DEMO

# Sized per mq/mq.md's parameter guidance.  Slow in pure Python.
STRONG = ChainParams(
    name="strong",
    n_note=48,
    note_folds=8,
    range_bits=32,
    zk_rounds=80,
    row_size=8,
)

#: A testnet runs seven processes on one machine, so it spends its CPU on the
#: transport rather than on proving the same statement three ways: one backend
#: is 63 KB a transaction instead of 542 KB, and an attendance gate of 3 makes
#: promotion and grid founding happen while someone is watching.
LOCAL = ChainParams(name="local", proof_backends=("mpcith",),
                    default_backend="mpcith",
                    proof_policy=(("local", "mpcith"), ("super", "mpcith"),
                                  ("supreme", "mpcith")),
                    attend_threshold=3, grid_size=7, row_size=5)

#: What a real network launches with.  Sized to mq.md's revised guidance —
#: 62 blinders, 2 fold rows — and measured rather than estimated: 0.53 s to
#: prove, 0.31 s to verify, 378 KB a transaction in one backend.
#:
#: One backend, because a launch is one tier.  Three backends is three audit
#: surfaces and 3.27 MB a transaction, of which two proofs nothing at a
#: one-tier network ever checks — and 3.27 MB does not fit the 1 MB ceiling an
#: unauthenticated connection is held to.  Turning on the upper tiers means
#: carrying their backends, and because that is a *parameter*, it is a decision
#: for genesis or for a succession rather than for an afternoon.
#:
#: `range_bits=48` caps a note at 2.8e14 minor units — $2.8 trillion in cents.
#: B is a size cost and not a security one (mq.md: bit variables carry no
#: entropy), so the 48 buys headroom for 48 KB and the 12 the shipped config
#: carried capped a note at 4,095.
LAUNCH = ChainParams(
    name="launch",
    n_note=NOTE_FIXED_COORDS + BLINDERS_128,
    note_folds=RECOMMENDED_FOLDS,
    range_bits=48,
    zk_rounds=80,
    proof_backends=("mpcith",),
    default_backend="mpcith",
    proof_policy=(("local", "mpcith"), ("super", "mpcith"),
                  ("supreme", "mpcith")),
    grid_size=7,
    row_size=5,
)

PRESETS = {p.name: p for p in (DEMO, STRONG, NO_MPCITH, LOCAL, LAUNCH)}
