"""A fault that costs something.

Review B1: everything in parts two and five — attendance, standing, the
forty-ceremony apprenticeship, the forgiveness counters — was machinery for
punishing behaviour the network could not record. `Seat.catch_lazy` produced
signed evidence that an attester had not checked; `GridRegister.apply` took a
`faulted` set; and nothing connected them, because acting on a fault means
every node agreeing about it, and agreeing means carrying it in the block.

The obstacle was never the plumbing. It was that "this block does not
validate" is usually a statement about the *ledger* — an input already spent,
a tip that has moved — and a node applying block h+1 next month cannot re-run
it. Equivocation escaped that because its evidence proves itself.

So laziness is split the same way (`chain/faults.py`). A block whose own bytes
contradict each other is flawed for anybody holding it, for ever; an attester
that signed one either did not look or looked and lied. That report carries the
block, proves itself, and suspends whoever signed. A block that failed a
contextual check convicts nobody, and these tests are as much about that half.
"""
import dataclasses

from ..block import (EQUIVOCATION, INVALID_BLOCK, LAZY_ATTESTATION,
                     Attestation, FaultReport)
from ..crypto import Signer
from ..faults import MAX_EVIDENCE_BYTES, reportable, self_evident_flaw
from ..params import DEMO
from ..register import Standing
from ..tiered import NetworkBlock, faulted_from
from ..tiers import bootstrap_world, run_tiered_epoch

PARAMS = dataclasses.replace(DEMO, attend_threshold=2, grid_size=7, row_size=5)
ENDOW = {"alice": [1000, 900, 800], "bob": [100]}

_CACHE = {}


def _world():
    regions = {f"n{i:02d}": "genesis" for i in range(7)}
    return bootstrap_world(regions, ENDOW, PARAMS)


def _run_one():
    """One finalised epoch, and the block it produced. Cached: the block is
    the raw material for every test here and proving it is real work."""
    if "run" not in _CACHE:
        world, wallets = _world()
        result = run_tiered_epoch(world, epoch=1, base_seed="seed")
        assert result.finalised, result.reason
        _CACHE["run"] = (world, result)
    return _CACHE["run"]


def _valid_block():
    return _run_one()[1].block


def _flawed_block():
    """A block whose header commits to a super_root the block does not have.

    Staged rather than mined — a leader that produces one is by definition
    broken — but the shape is what matters, and the shape is checkable by
    anybody holding the bytes.
    """
    good = _valid_block()
    header = dataclasses.replace(good.header,
                                 super_root=good.header.super_root + 1)
    return NetworkBlock(header=header, supers=good.supers,
                        dropped=good.dropped, foundings=good.foundings)


# ── what is self-evident, and what is not ────────────────────────────────────

def test_a_valid_block_has_no_self_evident_flaw():
    world, _ = _run_one()
    assert self_evident_flaw(_valid_block(), world.params) is None


def test_a_header_that_does_not_match_its_body_is_self_evident():
    world, _ = _run_one()
    flaw = self_evident_flaw(_flawed_block(), world.params)
    assert flaw is not None and "super_root" in flaw


def test_every_self_evident_check_is_a_pure_function_of_the_block():
    """Two verifiers, no shared state, same verdict — which is the property
    that lets a report convict somebody a year later."""
    world, _ = _run_one()
    other, _ = _world()
    block = _flawed_block()
    assert self_evident_flaw(block, world.params) == \
        self_evident_flaw(block, other.params)


def test_the_ledger_questions_are_deliberately_not_checked():
    """A block that is perfectly self-consistent and still invalid — it does
    not follow the tip. Contextual, so `self_evident_flaw` says nothing, and
    nobody can be convicted for attesting to it."""
    world, _ = _run_one()
    good = _valid_block()
    moved = NetworkBlock(
        header=dataclasses.replace(good.header, prev_hash="nb:somewhere-else"),
        supers=good.supers, dropped=good.dropped, foundings=good.foundings)
    assert self_evident_flaw(moved, world.params) is None


def test_a_malformed_block_is_a_flawed_block_and_does_not_raise():
    world, _ = _run_one()
    assert self_evident_flaw(object(), world.params) is not None


def test_the_evidence_cap_is_a_size_not_a_judgement():
    assert reportable(_valid_block())
    assert MAX_EVIDENCE_BYTES == 512 * 1024


# ── the report ───────────────────────────────────────────────────────────────

def _attestation(world, node_id, block, epoch=1):
    node = world.nodes[node_id]
    return node.attest(block.hash(), block.header.height, epoch, "seed")


def _lazy_report(world, reporter, culprits, block, epoch=1):
    return world.nodes[reporter].report(
        LAZY_ATTESTATION, block.header.height, epoch,
        "attested to a block that contradicts itself",
        tuple(_attestation(world, c, block, epoch) for c in culprits),
        subject=block)


def test_a_lazy_report_proves_itself_and_names_who_signed():
    world, _ = _run_one()
    block = _flawed_block()
    fr = _lazy_report(world, "n00", ["n01", "n02"], block)
    assert fr.verify()
    assert fr.substantiated(world.params)
    assert fr.accused(world.params) == ("n01", "n02")
    assert faulted_from([fr], world.params) == ("n01", "n02")


def test_the_same_report_convicts_nobody_without_the_parameters():
    """Unproven rather than false: a caller that cannot check has to say so
    rather than vote, which is why `faulted_from` takes the parameters and the
    one caller that matters always passes them."""
    world, _ = _run_one()
    fr = _lazy_report(world, "n00", ["n01"], _flawed_block())
    assert fr.verify() and not fr.substantiated(None)
    assert faulted_from([fr]) == ()


def test_a_report_about_a_block_that_is_fine_convicts_nobody():
    """The framing attack, and the reason the check is re-run rather than
    believed: a signed, well-formed report naming a valid block proves
    nothing."""
    world, _ = _run_one()
    fr = _lazy_report(world, "n00", ["n01", "n02"], _valid_block())
    assert fr.verify(), "it is a real report from a real seat"
    assert not fr.substantiated(world.params)
    assert faulted_from([fr], world.params) == ()


def test_an_attestation_for_another_block_is_not_evidence_about_this_one():
    world, _ = _run_one()
    block = _flawed_block()
    stray = _attestation(world, "n03", _valid_block())
    fr = world.nodes["n00"].report(
        LAZY_ATTESTATION, block.header.height, 1, "lazy", (stray,),
        subject=block)
    assert not fr.verify() and not fr.substantiated(world.params)


def test_an_unsigned_attestation_cannot_be_used_to_frame_a_seat():
    world, _ = _run_one()
    block = _flawed_block()
    forged = Attestation(node_id="n05", public_hex=Signer.generate().public_hex,
                         chain_id=world.params.chain_id,
                         height=block.header.height, block_hash=block.hash(),
                         epoch=1, grid_seed="seed", signature="00" * 64)
    fr = world.nodes["n00"].report(LAZY_ATTESTATION, block.header.height, 1,
                                   "lazy", (forged,), subject=block)
    assert not fr.verify()
    assert faulted_from([fr], world.params) == ()


def test_the_block_is_bound_into_the_report():
    """Swapping the subject for the valid block breaks the reporter's
    signature, so a relay cannot turn a conviction into an acquittal or the
    other way round."""
    world, _ = _run_one()
    fr = _lazy_report(world, "n00", ["n01"], _flawed_block())
    swapped = dataclasses.replace(fr, subject=_valid_block())
    assert not swapped.verify()


def test_the_kinds_are_named_rather_than_spelled_out_at_each_site():
    assert (EQUIVOCATION, LAZY_ATTESTATION, INVALID_BLOCK) == \
        ("equivocation", "lazy_attestation", "invalid_block")


# ── and what it costs the attester ───────────────────────────────────────────

def test_a_proven_lazy_attester_is_suspended_by_the_next_block():
    """The whole of B1 in one test: a report goes into the next block, every
    node derives the same faulted set from it, and the register moves.

    Before this, `catch_lazy` could prove a seat had not checked and the seat
    kept its standing for ever.
    """
    world, _ = _world()
    result = run_tiered_epoch(world, epoch=1, base_seed="seed")
    assert result.finalised, result.reason
    world.apply_network_block(result.block)

    gid = world.topology.grid_ids()[0]
    register = world.registers[gid]
    assert register.standing_of("n01") == Standing.ATTESTER

    block = dataclasses.replace(
        result.block.header, super_root=result.block.header.super_root + 1)
    flawed = NetworkBlock(header=block, supers=result.block.supers,
                          dropped=result.block.dropped,
                          foundings=result.block.foundings)
    world.pending_faults = (_lazy_report(world, "n00", ["n01"], flawed,
                                         epoch=1),)

    second = run_tiered_epoch(world, epoch=2, base_seed="seed")
    assert second.finalised, second.reason
    carried = [fr for c in second.block.ceremony_blocks() for fr in c.faults]
    assert len(carried) == 1, "the report has to be in the block"
    world.apply_network_block(second.block)

    assert register.standing_of("n01") == Standing.SUSPENDED
    assert register.standing_of("n00") == Standing.ATTESTER, \
        "the reporter is not punished for reporting"
    assert register.members["n01"].faults, "and the fault is on the record"


def test_a_block_carrying_a_report_that_does_not_prove_itself_is_refused():
    """A leader whose word was enough could suspend anyone it disliked, so an
    unprovable report does not merely fail to convict — it fails the block."""
    from ..tiers import SoloWorkload

    world, _ = _world()
    world.pending_faults = (_lazy_report(world, "n00", ["n01"],
                                         _valid_block()),)
    result = run_tiered_epoch(world, epoch=1, base_seed="seed")
    # The leader filters its own unprovable reports rather than proposing a
    # block every seat would reject, so the epoch still finalises — and the
    # report is not in it.
    assert result.finalised, result.reason
    carried = [fr for c in result.block.ceremony_blocks() for fr in c.faults]
    assert carried == []


def test_a_suspended_seat_does_not_heal_by_turning_up():
    world, _ = _world()
    gid = world.topology.grid_ids()[0]
    register = world.registers[gid]
    run = run_tiered_epoch(world, epoch=1, base_seed="seed")
    world.apply_network_block(run.block)
    flawed = NetworkBlock(
        header=dataclasses.replace(run.block.header,
                                   super_root=run.block.header.super_root + 1),
        supers=run.block.supers, dropped=run.block.dropped,
        foundings=run.block.foundings)
    world.pending_faults = (_lazy_report(world, "n00", ["n01"], flawed,
                                         epoch=1),)
    world.apply_network_block(run_tiered_epoch(world, epoch=2,
                                               base_seed="seed").block)
    assert register.standing_of("n01") == Standing.SUSPENDED
    for epoch in (3, 4):
        world.pending_faults = ()
        nxt = run_tiered_epoch(world, epoch=epoch, base_seed="seed")
        if not nxt.finalised:
            break
        world.apply_network_block(nxt.block)
    assert register.standing_of("n01") == Standing.SUSPENDED, \
        "suspension is not self-healing"
