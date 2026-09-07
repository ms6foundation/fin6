"""Parameter presets for the fin6 private chain.

Two presets ship:

  DEMO    small enough to run a whole ceremony in seconds.  The ZK proof runs
          at full strength (80 rounds, 2^-80) because that turned out to cost
          only ~24 ms per transaction — what makes DEMO insecure is the note
          block: 8 coordinates of which 4 are random puts the note-commitment
          MQ instance well inside Groebner range.  Tests and the demo use it.

  STRONG  sized per the guidance in mq/mq.md ("k should be a constant ~40-60,
          independent of batch size") and DEFAULT_ROUNDS for 2^-80 soundness.
          Minutes per transaction in pure Python; correctness-equivalent.

Everything that affects the algebra lives here so a deployment can be pinned
to one frozen ChainParams and both sides can compare them field by field.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict

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

PRESETS = {p.name: p for p in (DEMO, STRONG, NO_MPCITH)}
