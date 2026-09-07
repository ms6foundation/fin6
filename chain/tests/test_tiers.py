"""The three-phase epoch: partitions, standing, and the supreme mempool."""
import dataclasses

from ..ceremony import Grid
from ..locality import partition_of_nullifier, tx_partition
from ..network import transfer
from ..notes import Note
from ..params import DEMO
from ..register import Standing
from ..state import merge_deltas
from ..tiers import bootstrap_world, run_tiered_epoch
from ..transaction import build_transaction

PARAMS = dataclasses.replace(DEMO, attend_threshold=3, grid_size=5, row_size=5)


def world(n=20, endow=None, newcomers=None, params=PARAMS):
    regions = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(n)}
    return bootstrap_world(
        regions, endow or {"alice": [1000, 800], "bob": [250], "carol": []},
        params, newcomers=newcomers)


def funded(**kw):
    w, wallets = world(**kw)
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, kw.get("params", PARAMS))
    w.submit(tx)
    return w, wallets, tx


# ── the pipeline ─────────────────────────────────────────────────────────────

def test_an_epoch_reaches_the_supreme_mempool():
    w, wallets, tx = funded()
    result = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert result.finalised, result.reason
    assert result.block is not None
    assert result.tiers in (2, 3)
    assert sum(1 for _ in result.block.transactions()) == 1


def test_every_tier_runs_a_ceremony():
    w, wallets, tx = funded()
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert len(r.local.ceremonies) == len(w.topology.grid_ids())
    assert all(c.finalised for c in r.local.ceremonies.values())
    assert r.supers.ceremonies and all(c.finalised for c in r.supers.ceremonies.values())
    assert r.supreme is not None and r.supreme.finalised


def test_all_nodes_agree_after_applying():
    w, wallets, tx = funded()
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    w.apply_network_block(r.block)
    assert len({n.state.utxo.root for n in w.nodes.values()}) == 1
    assert len({n.state.nullifiers.root for n in w.nodes.values()}) == 1
    assert len({n.state.tip for n in w.nodes.values()}) == 1
    assert w.height == 1


def test_balances_move_and_fees_burn():
    w, wallets = world()
    before = sum(x.balance() for x in wallets.values())
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, PARAMS)
    w.submit(tx)
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert r.finalised, r.reason
    w.apply_network_block(r.block)
    assert sum(x.balance() for x in wallets.values()) == before - 5
    assert wallets["bob"].balance() == 550
    assert w.nodes[next(iter(w.nodes))].state.burned_fees == 5


def test_several_epochs_chain():
    w, wallets = world()
    for epoch in range(1, 4):
        tx, _ = transfer(wallets["alice"], wallets["bob"], 100, 5, PARAMS)
        w.submit(tx)
        r = run_tiered_epoch(w, epoch=epoch, base_seed="chain")
        assert r.finalised, f"epoch {epoch}: {r.reason}"
        w.apply_network_block(r.block)
        assert w.height == epoch
    assert len({n.state.utxo.root for n in w.nodes.values()}) == 1


# ── partitioning ─────────────────────────────────────────────────────────────

def test_a_transaction_routes_to_exactly_one_grid():
    w, wallets, tx = funded()
    K = w.topology.n_partitions
    part = tx_partition(tx, K)
    owners = [g for g in w.topology.grid_ids() if w.topology.partition_of(g) == part]
    assert len(owners) == 1


def test_only_the_owning_grid_includes_it():
    w, wallets, tx = funded()
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    carrying = [gid for gid, b in r.local.blocks.items() if b.transactions]
    assert len(carrying) == 1
    assert w.topology.partition_of(carrying[0]) == tx_partition(tx, w.topology.n_partitions)


def test_a_grid_refuses_a_transaction_from_another_partition():
    w, wallets, tx = funded()
    K = w.topology.n_partitions
    mine = tx_partition(tx, K)
    other = (mine + 1) % K
    node = w.nodes[next(iter(w.nodes))]
    ok, why, _ = node.state.check_ceremony_txs([tx], other, K)
    assert not ok and "partition" in why, why


def test_a_cross_partition_spend_has_no_home():
    """Two inputs whose nullifiers fall in different partitions."""
    w, wallets = world()
    K = w.topology.n_partitions
    alice = wallets["alice"]
    a, b = alice.notes[0], alice.notes[1]
    out = Note.create(a.value + b.value - 5, alice.public_hex, PARAMS, asset=a.asset)
    tx = build_transaction([(a, alice.signer), (b, alice.signer)], [out], 5, PARAMS)
    if partition_of_nullifier(tx.nullifiers[0], K) == partition_of_nullifier(tx.nullifiers[1], K):
        return                      # they happened to land together; nothing to test
    assert tx_partition(tx, K) is None
    ok, why, _ = w.submit(tx)
    assert not ok and "span partitions" in why, why


def test_merging_drops_a_delta_that_collides():
    from ..state import UtxoDelta
    a = UtxoDelta(("cm:1",), ("cm:x",), ("nf:1",), 0)
    clash = UtxoDelta(("cm:1",), ("cm:y",), ("nf:1",), 0)
    merged, dropped = merge_deltas([a, clash])
    assert len(dropped) == 1
    assert merged.spent == ("cm:1",)


# ── standing ─────────────────────────────────────────────────────────────────

def test_apprentices_are_seated_behind_attesters():
    members = [f"n{i:02d}" for i in range(12)]
    standing = {n: (Standing.ATTESTER if i < 6 else Standing.APPRENTICE)
                for i, n in enumerate(members)}
    g = Grid.seat(members, 4, "seed", standing=standing)
    assert standing[g.leader] == Standing.ATTESTER
    for nid, seat in g.seats.items():
        if seat.row == 0 or standing[nid] != Standing.ATTESTER:
            continue
        front = g.front(nid)
        assert front == g.leader or standing[front] == Standing.ATTESTER, (
            f"{nid} is an attester whose front {front} is an apprentice")


def test_an_apprentice_never_leads():
    members = [f"n{i:02d}" for i in range(8)]
    standing = {n: (Standing.ATTESTER if i < 2 else Standing.APPRENTICE)
                for i, n in enumerate(members)}
    for seed in ("a", "b", "c", "d"):
        g = Grid.seat(members, 4, seed, standing=standing)
        assert standing[g.leader] == Standing.ATTESTER


def test_apprentice_attestations_do_not_count_toward_quorum():
    w, wallets, tx = funded(newcomers={"new0": "eu", "new1": "eu"})
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    for gid, res in r.local.ceremonies.items():
        reg = w.registers[gid]
        apprentices = set(reg.apprentices())
        if not apprentices or not res.quorum_cert:
            continue
        signers = {a.node_id for a in res.quorum_cert.attestations}
        assert not (signers & apprentices), "an apprentice reached the quorum cert"
        return
    raise AssertionError("no grid had an apprentice to check")


def test_apprentices_still_appear_in_the_attendance_roll():
    w, wallets, tx = funded(newcomers={"new0": "eu"})
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    gid = w.topology.grid_of("new0")
    roll = r.local.ceremonies[gid].roll
    assert "new0" in roll.seated
    assert "new0" in roll.attended, "shadow attestations must still move the counter"


def test_an_apprentice_is_promoted_after_the_threshold():
    w, wallets = world(newcomers={"new0": "eu"})
    gid = w.topology.grid_of("new0")
    assert w.registers[gid].standing_of("new0") == Standing.APPRENTICE
    for epoch in range(1, PARAMS.attend_threshold + 2):
        r = run_tiered_epoch(w, epoch=epoch, base_seed="promote")
        assert r.finalised, r.reason
        w.apply_network_block(r.block)
    assert w.registers[gid].standing_of("new0") == Standing.ATTESTER


def test_register_roots_travel_into_the_network_block():
    w, wallets, tx = funded()
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    from ..tiered import registers_root
    roots = {c.header.grid_id: c.header.register_root
             for c in r.block.ceremony_blocks()}
    assert registers_root(roots) == r.block.header.registers_root


# ── what a seat refuses ──────────────────────────────────────────────────────

def _reject(w, epoch, mutate):
    """Run phase L with a leader that mutates its block, return the reason."""
    from ..ceremony import NodeWorkload

    class Corrupt:
        name = "corrupt"

        def propose(self, leader, grid, meta, limit=None, workload=None):
            block = workload.build(leader, meta, limit=limit)
            bad = mutate(block)
            sp = leader.propose(bad, meta.epoch, meta.grid_seed)
            return {**{n: sp for n in grid.rows[0]}, leader.id: sp}

    gids = w.topology.grid_ids()
    reg = w.registers[gids[0]]
    members = w.grid_members(gids[0])
    standing = {n: reg.standing_of(n) for n in members}
    from ..crypto import h_hex
    from ..ceremony import Ceremony
    from ..tiers import LocalWorkload
    grid = Grid.seat(members, PARAMS.row_size,
                     h_hex("view", "s", epoch, gids[0], 0), standing=standing)
    cer = Ceremony(grid, {n: w.nodes[n] for n in members}, PARAMS,
                   height=epoch, epoch=epoch,
                   quorum=reg.quorum(2, 3),
                   workload=LocalWorkload(w, gids[0], epoch,
                                          PARAMS.backend_for("local")),
                   counting=set(reg.attesters()), grid_id=gids[0])
    return cer.run(Corrupt())


def test_a_faked_register_root_is_refused():
    w, wallets, tx = funded()
    res = _reject(w, 1, lambda b: dataclasses.replace(
        b, header=dataclasses.replace(b.header,
                                      register_root=b.header.register_root + 1)))
    assert not res.finalised
    assert any(f.kind == "invalid_block" and "register_root" in f.detail
               for f in res.faults), [f.detail for f in res.faults]


def test_a_faked_delta_digest_is_refused():
    w, wallets, tx = funded()
    res = _reject(w, 1, lambda b: dataclasses.replace(
        b, header=dataclasses.replace(b.header, delta_digest="deadbeef")))
    assert not res.finalised


def test_a_block_that_does_not_follow_the_tip_is_refused():
    w, wallets, tx = funded()
    res = _reject(w, 1, lambda b: dataclasses.replace(
        b, header=dataclasses.replace(b.header, prev_network_hash="nb:nope")))
    assert not res.finalised


# ── trust lists are powerless ────────────────────────────────────────────────

def test_consensus_never_reads_a_trust_list():
    """The design's central claim, asserted directly.

    Comparing two worlds' block hashes would prove nothing — their genesis notes
    carry fresh randomness, so they differ whatever trust does.  Instead every
    node's private list is replaced by a tripwire that raises if consensus ever
    reads it.  The epoch must still finalise, which it can only do if nothing on
    the path to a quorum consults a TrustList.
    """
    from ..trustlist import TrustList

    class Tripwire(TrustList):
        def score(self, node_id):
            raise AssertionError("consensus read a trust list")

        def trusted(self, threshold=1.0):
            raise AssertionError("consensus read a trust list")

        def rank(self, candidates):
            raise AssertionError("consensus read a trust list")

    w, wallets, tx = funded()
    w.trust = {nid: Tripwire(nid) for nid in w.nodes}
    result = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert result.finalised, result.reason
    w.apply_network_block(result.block)
    assert len({n.state.utxo.root for n in w.nodes.values()}) == 1


def test_scrambled_trust_lists_do_not_disturb_an_epoch():
    """And when the lists are populated but in mutual disagreement, finality is
    unchanged: same grids, same leaders, same transaction included."""
    from ..trustlist import TrustEntry

    w, wallets, tx = funded()
    for i, (nid, tl) in enumerate(sorted(w.trust.items())):
        tl.entries = {
            other: TrustEntry(node_id=other, score=float((i * 7 + j) % 13))
            for j, other in enumerate(sorted(w.nodes)) if other != nid}

    result = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert result.finalised, result.reason
    assert len(result.local.finalised) == len(w.topology.grid_ids())
    assert sum(1 for _ in result.block.transactions()) == 1


def test_trust_accrues_from_watching():
    w, wallets, tx = funded()
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    gid = w.topology.grid_ids()[0]
    member = w.grid_members(gid)[0]
    tl = w.trust[member]
    assert len(tl) > 0, "a node that sat in a ceremony should have watched someone"
    assert all(s in w.nodes for s in tl.trusted(1.0))


# ── tier arithmetic ──────────────────────────────────────────────────────────

def test_the_supreme_tier_collapses_when_there_is_one_super_grid():
    w, wallets, tx = funded(n=10)          # 2 grids -> 2 leaders -> 1 super grid
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert r.finalised, r.reason
    assert r.tiers == 2, "one super grid should collapse the supreme tier onto it"


def test_three_tiers_when_the_roster_is_large_enough():
    w, wallets, tx = funded(n=40)          # 8 grids -> 2 super grids -> supreme
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert r.finalised and r.tiers == 3


def test_the_single_grid_case_collapses_to_one_tier():
    """One grid used to be refused.  It now degenerates instead — same block
    format, one ceremony, one certificate, and a header that says so."""
    regions = {f"n{i:02d}": "eu" for i in range(4)}          # one region, one grid
    w, wallets = bootstrap_world(
        regions, {"alice": [1000], "bob": []},
        dataclasses.replace(PARAMS, grid_size=100))
    assert len(w.topology.grid_ids()) == 1
    result = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert result.finalised, result.reason
    assert result.tiers == 1
    block = result.block
    assert block.header.tiers == 1
    assert len(block.supers) == 1 and len(block.supers[0].children) == 1
    assert block.quorum_cert is not None, "the network block is what was agreed"
    assert block.supers[0].quorum_cert is None
    assert block.supers[0].children[0].quorum_cert is None
    assert result.stats()["ceremonies"] == 1, "one ceremony, counted once"
