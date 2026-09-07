"""The ceremony: finality, equivocation detection, view change, forgery."""
import dataclasses

from ..block import Attestation, Block
from ..ceremony import (Ceremony, Envelope, EquivocatingLeader, Grid,
                        HonestLeader, SilentLeader, run_epoch)
from ..crypto import Signer, h_hex
from ..params import DEMO
from .helpers import funded_network

IDS = [f"v{i:02d}" for i in range(13)]


def _first_leader(seed, epoch=1):
    return Grid.seat(IDS, DEMO.row_size, h_hex("view", seed, epoch, 0)).leader


def test_honest_ceremony_finalises_with_every_seat_accepting():
    nodes, wallets, tx = funded_network(validators=IDS)
    result = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s").result
    assert result.finalised, result.reason
    assert len(result.accepted()) == len(IDS)
    assert result.block.transactions == (tx,)


def test_finality_needs_only_one_ceremony_when_the_leader_is_honest():
    nodes, wallets, tx = funded_network(validators=IDS)
    epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s")
    assert len(epoch.attempts) == 1


def test_the_proposal_reaches_every_seat_and_attestations_come_back():
    nodes, wallets, tx = funded_network(validators=IDS)
    result = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s").result
    trace = result.trace
    assert trace[0]["with_proposal"] == 1 + len(result.grid.rows[0]), \
        "round 0 should reach exactly the leader and row 1"
    assert trace[-1]["with_proposal"] == len(IDS)
    assert trace[-1]["max_attestations"] == len(IDS)
    # monotone: sync only ever adds
    counts = [t["with_proposal"] for t in trace]
    assert counts == sorted(counts)


def test_quorum_certificate_verifies_independently():
    nodes, wallets, tx = funded_network(validators=IDS)
    result = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s").result
    validators = {n.id: n.public_hex for n in nodes.values()}
    ok, why = result.quorum_cert.verify(DEMO.quorum_size(len(IDS)),
                                        result.block.hash(), validators)
    assert ok, why


def test_quorum_certificate_rejects_a_swapped_attestation_set():
    nodes, wallets, tx = funded_network(validators=IDS)
    cert = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s").result.quorum_cert
    trimmed = dataclasses.replace(cert, attestations=cert.attestations[:2])
    ok, why = trimmed.verify(DEMO.quorum_size(len(IDS)))
    assert not ok, "a certificate below quorum was accepted"
    padded = dataclasses.replace(cert, root=cert.root + 1)
    ok, why = padded.verify(DEMO.quorum_size(len(IDS)))
    assert not ok and "root" in why, why


def test_silent_leader_triggers_a_view_change():
    nodes, wallets, tx = funded_network(validators=IDS)
    leader = _first_leader("s2")
    epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s2",
                      behaviours={leader: SilentLeader()})
    assert not epoch.attempts[0].finalised
    assert epoch.finalised, "view change failed to make progress"
    assert epoch.result.grid.leader != leader


def test_equivocating_leader_is_caught_by_the_row_rings():
    """Both blocks are individually valid, so no seat can catch this alone."""
    nodes, wallets, tx = funded_network(validators=IDS)
    leader = _first_leader("s3")
    epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s3",
                      behaviours={leader: EquivocatingLeader()})
    first = epoch.attempts[0]
    assert not first.finalised
    assert "equivocat" in first.reason
    reports = [f for f in first.faults if f.kind == "equivocation"]
    assert reports, "nobody reported the equivocation"
    assert all(f.substantiated() for f in reports), \
        "evidence must stand on its own"
    assert all(d.status == "abort" for d in first.decisions.values())
    assert epoch.finalised, "the epoch should recover under a new leader"


def test_equivocation_evidence_is_checkable_by_a_third_party():
    nodes, wallets, tx = funded_network(validators=IDS)
    leader = _first_leader("s3")
    epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s3",
                      behaviours={leader: EquivocatingLeader()})
    report = [f for f in epoch.attempts[0].faults if f.kind == "equivocation"][0]
    a, b = report.evidence
    assert a.verify() and b.verify()
    assert a.leader_id == b.leader_id == leader
    assert a.block_hash != b.block_hash
    assert a.height == b.height


def test_a_leader_proposing_an_invalid_block_is_refused():
    class CorruptLeader:
        name = "corrupt"

        def propose(self, leader, grid, meta, limit=None, workload=None):
            from ..ceremony import NodeWorkload
            block = (workload or NodeWorkload()).build(leader, meta, limit=limit)
            bad = dataclasses.replace(block.header,
                                      utxo_root=block.header.utxo_root + 1)
            corrupt = Block(header=bad, transactions=block.transactions)
            sp = leader.propose(corrupt, meta.epoch, meta.grid_seed)
            targets = {leader.id: sp}
            for nid in grid.rows[0]:
                targets[nid] = sp
            return targets

    nodes, wallets, tx = funded_network(validators=IDS)
    leader = _first_leader("s4")
    epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s4",
                      behaviours={leader: CorruptLeader()})
    first = epoch.attempts[0]
    assert not first.finalised
    assert any(f.kind == "invalid_block" for f in first.faults)
    assert epoch.finalised


def test_forged_attestations_cannot_reach_quorum():
    """Without the validator registry check, invented seats would count."""
    nodes, wallets, tx = funded_network(validators=IDS)
    grid = Grid.seat(IDS, DEMO.row_size, "seed")
    validators = {n.id: n.public_hex for n in nodes.values()}
    env = Envelope(1, 1, "seed", grid.leader, DEMO.chain_id, validators)
    outsider = Signer.from_seed("mallory")

    msg = Attestation.message(DEMO.chain_id, 1, "blk:abc", 1, "seed")
    invented = Attestation(node_id="v99", public_hex=outsider.public_hex,
                           chain_id=DEMO.chain_id, height=1,
                           block_hash="blk:abc", epoch=1, grid_seed="seed",
                           signature=outsider.sign(msg))
    assert env.add_attestation(invented) is False, "invented seat was counted"

    impersonated = dataclasses.replace(invented, node_id="v00")
    assert env.add_attestation(impersonated) is False, "wrong key was counted"


def test_a_non_leader_cannot_inject_a_proposal():
    nodes, wallets, tx = funded_network(validators=IDS)
    grid = Grid.seat(IDS, DEMO.row_size, "seed")
    validators = {n.id: n.public_hex for n in nodes.values()}
    env = Envelope(1, 1, "seed", grid.leader, DEMO.chain_id, validators)

    impostor = next(n for n in nodes.values() if n.id != grid.leader)
    from ..block import CeremonyMeta
    meta = CeremonyMeta(epoch=1, leader_id=impostor.id, rows=grid.n_rows,
                        row_size=DEMO.row_size, grid_seed="seed")
    sp = impostor.propose(impostor.build_block(meta), 1, "seed")
    assert env.add_proposal(sp) is False, "a non-leader proposal was accepted"


def test_rounds_default_to_a_round_trip_of_the_diameter():
    nodes, wallets, tx = funded_network(validators=IDS)
    grid = Grid.seat(IDS, DEMO.row_size, "seed")
    ceremony = Ceremony(grid, nodes, DEMO, height=1, epoch=1)
    assert ceremony.rounds == 2 * grid.diameter()


def test_a_starved_schedule_cannot_finalise():
    """Sanity check on the schedule: one round is not enough to reach quorum."""
    nodes, wallets, tx = funded_network(validators=IDS)
    grid = Grid.seat(IDS, DEMO.row_size, "seed")
    result = Ceremony(grid, nodes, DEMO, height=1, epoch=1, rounds=1).run()
    assert not result.finalised
    assert "quorum" in result.reason
