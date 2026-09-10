"""The roll a certificate proves, and the faults a block carries.

Two open items with one answer, which is why they were done together: both
wanted a field in the block for something agreed in the *previous* epoch.

`Seat.roll` had recorded the problem and the fix for two parts: attendance was
built from whatever one seat happened to see, seven seats see seven different
things, and "the real fix is that the block at epoch e carries the certificate
of epoch e-1". Meanwhile `GridRegister.apply` had taken a `faulted` set since
part two and every caller passed none, so a provable fault cost its author
nothing.
"""
import dataclasses

from ..block import Attestation, FaultReport, QuorumCert, SignedProposal
from ..crypto import Signer
from ..register import AttendanceRoll, GridRegister, Standing
from ..tiered import faulted_from, faults_digest, prev_cert_digest

CHAIN = "fin6:" + "ab" * 32
SEED = "grid-seed"


def _signers(names):
    return {n: Signer.from_seed(f"validator:{n}") for n in names}


def _att(signer, node_id, block_hash="nb:one", height=1, epoch=1):
    return Attestation(
        node_id=node_id, public_hex=signer.public_hex, chain_id=CHAIN,
        height=height, block_hash=block_hash, epoch=epoch, grid_seed=SEED,
        signature=signer.sign(Attestation.message(CHAIN, height, block_hash,
                                                  epoch, SEED)))


def _cert(counting, shadow=()):
    return QuorumCert.build(CHAIN, 1, "nb:one", 1, SEED, counting,
                            shadow=shadow)


def _roster(*names):
    return {n: Signer.from_seed(f"validator:{n}").public_hex for n in names}


# ── the roll a certificate proves ────────────────────────────────────────────

def test_attendance_is_who_signed_the_certificate():
    """The whole change: attendance stops being what one seat observed and
    becomes what the agreement was made of."""
    s = _signers(["a", "b", "c"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    roll = AttendanceRoll.from_cert("g0", cert, ["a", "b", "c"], "a")
    assert roll.attended == ("a", "b")
    assert roll.seated == ("a", "b", "c")
    assert "c" not in roll.attended, "a seat that said nothing did not attend"


def test_a_seat_that_says_nothing_no_longer_earns_attendance():
    """What the stopgap did, and what it cost: it credited everyone seated in
    a ceremony that finalised, so the gate measured "seated while the grid
    worked" rather than "did the work"."""
    s = _signers(["a", "b", "c"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    roll = AttendanceRoll.from_cert("g0", cert, ["a", "b", "c"], "a")
    reg = GridRegister.genesis("g0", ["a", "b", "c"], attend_threshold=2)
    before = reg.members["a"].consecutive        # founders start seeded
    reg.apply(roll)
    assert reg.members["a"].consecutive == before + 1, "a attested"
    assert reg.members["c"].consecutive == 0, "c did not, and its streak broke"
    assert reg.members["c"].total_attended < reg.members["a"].total_attended


def test_an_apprentices_shadow_still_counts_as_attendance():
    """Quorum never sees a shadow, so deriving the roll from the counting
    attestations alone would mean an apprentice never appears in a roll and is
    never promoted — which is the whole growth path."""
    s = _signers(["a", "b", "new"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")],
                 shadow=[_att(s["new"], "new")])
    assert len(cert) == 2, "and it still cannot make quorum"
    roll = AttendanceRoll.from_cert("g0", cert, ["a", "b", "new"], "a")
    assert "new" in roll.attended


def test_a_shadow_is_verified_as_carefully_as_a_vote():
    """The register credits them, so an unverified shadow would be a way to
    hand an apprentice a promotion it did not earn."""
    s = _signers(["a", "b", "new"])
    good = _att(s["new"], "new")
    forged = dataclasses.replace(good, signature=_att(s["a"], "a").signature)
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")], shadow=[forged])
    ok, why = cert.verify(1, "nb:one", validators=_roster("a", "b", "new"))
    assert not ok and "shadow" in why, why


def test_a_shadow_cannot_be_smuggled_in_twice():
    s = _signers(["a"])
    att = _att(s["a"], "a")
    cert = QuorumCert.build(CHAIN, 1, "nb:one", 1, SEED, [att], shadow=[att])
    assert cert.shadow_signers == (), \
        "the same seat cannot be counted and shadowed"


def test_the_certificate_digest_covers_the_shadows_too():
    """Or a leader could strip an apprentice's shadow after agreement and the
    header would not notice."""
    s = _signers(["a", "new"])
    counting = [_att(s["a"], "a")]
    with_shadow = _cert(counting, shadow=[_att(s["new"], "new")])
    without = _cert(counting)
    assert prev_cert_digest(with_shadow) != prev_cert_digest(without)


def test_no_certificate_means_no_roll():
    assert prev_cert_digest(None) == ""
    roll = AttendanceRoll("g0", -1, "")
    assert roll.epoch == -1, "and a register skips an epoch below zero"


# ── faults that reach the register ───────────────────────────────────────────

class _FakeHeader:
    def __init__(self, chain_id):
        self.chain_id = chain_id


class _FakeBlock:
    """A `SignedProposal` reads its height, its hash and its chain id off the
    block it carries, and equivocation evidence needs two that differ."""

    def __init__(self, tag, height=1):
        self.tag = tag
        self.height = height
        self.header = _FakeHeader(CHAIN)

    def hash(self):
        return self.tag


def _proposal(signer, leader, block_hash, height=1, epoch=1):
    block = _FakeBlock(block_hash, height)
    return SignedProposal(
        block=block, leader_id=leader, public_hex=signer.public_hex,
        epoch=epoch, grid_seed=SEED,
        signature=signer.sign(SignedProposal.message(
            CHAIN, height, block_hash, epoch, SEED)))


def _equivocation(reporter_signer, reporter, leader_signer, leader):
    a = _proposal(leader_signer, leader, "nb:x")
    b = _proposal(leader_signer, leader, "nb:y")
    msg = FaultReport.message(reporter, "equivocation", 1, 1, "two blocks",
                              [a.block_hash, b.block_hash])
    return FaultReport(reporter=reporter, public_hex=reporter_signer.public_hex,
                       kind="equivocation", height=1, epoch=1,
                       detail="two blocks", evidence=(a, b),
                       signature=reporter_signer.sign(msg))


def test_an_equivocation_report_names_its_culprit():
    s = _signers(["watcher", "cheat"])
    fr = _equivocation(s["watcher"], "watcher", s["cheat"], "cheat")
    assert fr.substantiated() and fr.verify()
    assert faulted_from([fr]) == ("cheat",)


def test_a_claim_that_cannot_be_checked_never_faults_anyone():
    """The reason only equivocation travels. A leader whose word was enough
    could suspend anyone it disliked, which is a worse failure than the one
    being fixed."""
    s = _signers(["watcher"])
    msg = FaultReport.message("watcher", "lazy_attestation", 1, 1, "lazy", [])
    fr = FaultReport(reporter="watcher", public_hex=s["watcher"].public_hex,
                     kind="lazy_attestation", height=1, epoch=1, detail="lazy",
                     evidence=(), signature=s["watcher"].sign(msg))
    assert fr.verify() and not fr.substantiated()
    assert faulted_from([fr]) == ()


def test_an_unsigned_report_faults_nobody():
    s = _signers(["watcher", "cheat"])
    fr = _equivocation(s["watcher"], "watcher", s["cheat"], "cheat")
    assert faulted_from([dataclasses.replace(fr, signature="00" * 64)]) == ()


def test_the_faulted_set_is_a_pure_function_of_the_block():
    """It feeds the register root, so every node must derive the same set from
    the same bytes — including in the same order."""
    s = _signers(["w1", "w2", "c1", "c2"])
    a = _equivocation(s["w1"], "w1", s["c1"], "c1")
    b = _equivocation(s["w2"], "w2", s["c2"], "c2")
    assert faulted_from([a, b]) == faulted_from([b, a]) == ("c1", "c2")
    assert faults_digest([a, b]) == faults_digest([b, a])


def test_a_faulted_member_is_suspended_and_stays_suspended():
    s = _signers(["a", "b", "cheat"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    roll = AttendanceRoll.from_cert("g0", cert, ["a", "b", "cheat"], "a")
    reg = GridRegister.genesis("g0", ["a", "b", "cheat"], attend_threshold=1)
    reg.apply(roll, faulted=("cheat",))
    assert reg.standing_of("cheat") == Standing.SUSPENDED
    # And attending again does not launder it.
    later = AttendanceRoll("g0", 2, "a", seated=("a", "b", "cheat"),
                           attended=("a", "b", "cheat"))
    reg.apply(later)
    assert reg.standing_of("cheat") == Standing.SUSPENDED


def test_faulting_changes_the_register_root():
    """Which is the point: until now a provable fault left no trace in the one
    structure that decides who may vote."""
    s = _signers(["a", "b", "cheat"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    roll = AttendanceRoll.from_cert("g0", cert, ["a", "b", "cheat"], "a")
    clean = GridRegister.genesis("g0", ["a", "b", "cheat"], attend_threshold=1)
    dirty = GridRegister.genesis("g0", ["a", "b", "cheat"], attend_threshold=1)
    clean.apply(roll)
    dirty.apply(roll, faulted=("cheat",))
    assert clean.root() != dirty.root()


# ── the shape a certificate has to be in for signatures to aggregate ────────

def test_a_certificate_carries_no_keys():
    """The point of the shape, and its price. A key carried by the thing it
    authenticates was never evidence of anything, and an aggregate signature
    cannot carry one per signer — so the roster is now mandatory."""
    s = _signers(["a", "b"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    assert not hasattr(cert, "attestations")
    ok, why = cert.verify(1, "nb:one")
    assert not ok and "roster" in why, why
    ok, why = cert.verify(1, "nb:one", validators=_roster("a", "b"))
    assert ok, why


def test_one_statement_for_the_whole_certificate():
    """Every signature is over the same message, which is why the per-seat
    copies of the chain id, height, block hash, epoch and grid seed were
    redundant — and what an aggregate scheme requires: one message, many
    keys."""
    s = _signers(["a", "b"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    msg = cert.message()
    assert msg == Attestation.message(CHAIN, 1, "nb:one", 1, SEED)
    from ..crypto import verify_sig
    for node_id, sig in zip(cert.signers, cert.signatures):
        assert verify_sig(_roster(node_id)[node_id], msg, sig)


def test_a_signature_cannot_be_moved_to_another_signer():
    """The root is over the pairs, not over two independent lists."""
    s = _signers(["a", "b"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    swapped = dataclasses.replace(cert, signatures=cert.signatures[::-1])
    ok, why = swapped.verify(1, "nb:one", validators=_roster("a", "b"))
    assert not ok, why


def test_a_signer_outside_the_roster_is_refused():
    s = _signers(["a", "stranger"])
    cert = _cert([_att(s["a"], "a"), _att(s["stranger"], "stranger")])
    ok, why = cert.verify(1, "nb:one", validators=_roster("a"))
    assert not ok and "not a known validator" in why, why


def test_lists_that_do_not_correspond_are_refused():
    s = _signers(["a", "b"])
    cert = _cert([_att(s["a"], "a"), _att(s["b"], "b")])
    ragged = dataclasses.replace(cert, signatures=cert.signatures[:1])
    ok, why = ragged.verify(1, "nb:one", validators=_roster("a", "b"))
    assert not ok and "correspond" in why, why


def test_the_signers_are_sorted_so_the_list_is_a_bitmap_in_all_but_encoding():
    """What is left before signatures can collapse to one: `signers` is a
    canonical order already, so replacing it with an actual bitmap over the
    grid's seats is an encoding change rather than a format one."""
    s = _signers(["c", "a", "b"])
    cert = _cert([_att(s["c"], "c"), _att(s["a"], "a"), _att(s["b"], "b")])
    assert cert.signers == ("a", "b", "c")
    assert list(cert.signers) == sorted(cert.signers)
