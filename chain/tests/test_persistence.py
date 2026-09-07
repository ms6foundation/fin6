"""Persistence: restart, roll back, snapshot, and the one write that comes first.

The claim the whole layer stands or falls on is in
`test_a_restarted_node_is_the_node_it_was`: stop, reopen, and every root, the
tip, the registers and the ability to keep going are exactly what they were.
Everything else here is a way that could go wrong.
"""
import dataclasses
import os
import tempfile

from ..network import transfer
from ..params import DEMO
from ..register import GridRegister, Standing
from ..seal import SealAccumulator
from ..state import ChainState, UtxoDelta, merge_deltas
from ..store import snapshot as snap
from ..store.db import ChainStore, StoreError
from ..store.high_water import HighWater, HighWaterError
from ..store.undo import UndoError, apply_undo, capture, retention_depth
from ..tiers import bootstrap_world, run_tiered_epoch

PARAMS = dataclasses.replace(DEMO, attend_threshold=3, grid_size=5, row_size=5)
REGIONS = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(20)}
ENDOW = {"alice": [1000, 900, 800, 700], "bob": [250]}

_RUN = {}


def fresh_world():
    return bootstrap_world(REGIONS, ENDOW, PARAMS)


def run_world(epochs=3):
    """One persisted world, run once and reused — an epoch is expensive."""
    if "world" not in _RUN:
        d = tempfile.mkdtemp()
        path = os.path.join(d, "n00.db")
        world, wallets = fresh_world()
        store = ChainStore(path)
        world.persist(store, ["n00"])
        for e in range(1, epochs + 1):
            tx, _ = transfer(wallets["alice"], wallets["bob"], 200 + e, 5, PARAMS)
            world.submit(tx)
            result = run_tiered_epoch(world, epoch=e, base_seed="persist")
            assert result.finalised, result.reason
            world.apply_network_block(result.block)
        store.close()
        _RUN["world"] = (path, world, wallets)
    return _RUN["world"]


# ── the accumulator's two new moves ──────────────────────────────────────────

def test_dump_and_load_reproduce_the_root():
    a = SealAccumulator("utxo")
    for i in range(40):
        a.add(f"cm:{i}")
    for i in (3, 11, 29):
        a.spend(f"cm:{i}")
    values, dead = a.dump()
    b = SealAccumulator.load("utxo", values, dead)
    assert b.root == a.root and len(b) == len(a)
    assert "cm:3" not in b and b.ever_contained("cm:3")


def test_load_is_not_a_replay_of_appends():
    """Same root either way; one pass is ~350x cheaper per leaf."""
    a = SealAccumulator("nf")
    for i in range(2000):
        a.add(f"nf:{i}")
    assert SealAccumulator.load("nf", *a.dump()).root == a.root


def test_unspend_and_truncate_are_exact_inverses():
    a = SealAccumulator("utxo")
    for i in range(10):
        a.add(f"cm:{i}")
    before = a.root
    a.spend("cm:4")
    a.add("cm:new")
    a.truncate(1)
    a.unspend("cm:4")
    assert a.root == before and "cm:new" not in a


def test_truncate_refuses_a_slot_that_was_spent_later():
    """The tripwire for an out-of-order undo."""
    a = SealAccumulator("utxo")
    for i in range(5):
        a.add(f"cm:{i}")
    a.spend("cm:4")
    try:
        a.truncate(1)
    except ValueError as exc:
        assert "out of order" in str(exc)
        return
    raise AssertionError("dropped a spent slot")


def test_a_register_round_trips():
    reg = GridRegister.genesis("g0", ["a", "b", "c"], attend_threshold=3)
    reg.admit("d")
    back = GridRegister.load(reg.dump())
    assert back.root() == reg.root()
    assert back.standing_of("d") == Standing.APPRENTICE
    assert back.dump() == reg.dump()


# ── undo ─────────────────────────────────────────────────────────────────────

def test_an_undo_record_puts_the_ledger_back():
    state = ChainState(PARAMS)
    for i in range(4):
        state.issue(f"cm:{i}")
    state.height, state.tip = 0, "nb:genesis"
    delta = UtxoDelta(spent=("cm:1",), created=("cm:x", "cm:y"),
                      nullifiers=("nf:1",), fees=5)
    record = capture(state, delta, height=1, block_hash="nb:one")
    state.apply_delta(delta)
    state.height, state.tip = 1, "nb:one"
    assert state.utxo.root != record.prev_utxo_root
    apply_undo(state, record)
    assert state.utxo.root == record.prev_utxo_root
    assert state.nullifiers.root == record.prev_nf_root
    assert state.height == 0 and state.tip == "nb:genesis"
    assert state.burned_fees == 0


def test_undo_only_ever_applies_to_the_tip():
    state = ChainState(PARAMS)
    state.issue("cm:0")
    state.height = 0
    record = capture(state, UtxoDelta(), height=5, block_hash="nb:five")
    try:
        apply_undo(state, record)
    except UndoError as exc:
        assert "tip" in str(exc)
        return
    raise AssertionError("undid something that was not the tip")


def test_the_ceiling_sets_how_much_undo_to_keep():
    from ..hardening.params import PRODUCTION
    assert retention_depth(PRODUCTION, 1 / 3) == 729
    assert retention_depth(PRODUCTION, 0.10) == 218


# ── the store ────────────────────────────────────────────────────────────────

def test_a_restarted_node_is_the_node_it_was():
    path, live, _ = run_world()
    world, _ = fresh_world()
    store = ChainStore(path)
    world.restore_from(store)
    was, now = live.nodes["n00"].state, world.nodes["n00"].state
    assert now.height == was.height and now.tip == was.tip
    assert now.utxo.root == was.utxo.root
    assert now.nullifiers.root == was.nullifiers.root
    assert now.burned_fees == was.burned_fees
    assert {g: r.root() for g, r in world.registers.items()} == \
           {g: r.root() for g, r in live.registers.items()}
    store.close()


def test_a_restarted_node_keeps_going():
    path, live, wallets = run_world()
    world, _ = fresh_world()
    store = ChainStore(path)
    world.restore_from(store)
    tx, _ = transfer(wallets["alice"], wallets["bob"], 275, 5, PARAMS)
    world.submit(tx)
    result = run_tiered_epoch(world, epoch=live.height + 1, base_seed="persist")
    assert result.finalised, result.reason
    store.close()


def test_the_mempool_does_not_survive_a_restart():
    """On purpose: a restored mempool re-admits what the chain has invalidated."""
    path, _, wallets = run_world()
    world, w2 = fresh_world()
    store = ChainStore(path)
    tx, _ = transfer(w2["alice"], w2["bob"], 100, 5, PARAMS)
    world.submit(tx)
    assert any(n.mempool for n in world.nodes.values())
    world.restore_from(store)
    assert not any(n.mempool for n in world.nodes.values())
    store.close()


def test_the_store_refuses_a_block_its_state_did_not_apply():
    path, live, _ = run_world()
    with tempfile.TemporaryDirectory() as d:
        store = ChainStore(os.path.join(d, "c.db"))
        state = ChainState(PARAMS)
        state.issue("cm:0")
        state.height, state.tip = 0, "nb:genesis"
        store.initialise(state)
        try:
            store.commit(block=_FakeBlock(9), delta=UtxoDelta(), state=state,
                         undo=capture(state, UtxoDelta(), height=9,
                                      block_hash="nb:nine"))
        except StoreError as exc:
            assert "state is at 0" in str(exc)
            return
        finally:
            store.close()
    raise AssertionError("committed a block the state had not applied")


def test_a_failed_commit_changes_nothing():
    """Atomicity is the whole reason for one commit point per block."""
    with tempfile.TemporaryDirectory() as d:
        store = ChainStore(os.path.join(d, "c.db"))
        state = ChainState(PARAMS)
        for i in range(3):
            state.issue(f"cm:{i}")
        state.height, state.tip = 0, "nb:genesis"
        store.initialise(state)
        before = store.stats()
        state.height = 1
        bad = UtxoDelta(spent=("cm:nope",), created=("cm:new",))
        try:
            store.commit(block=_FakeBlock(1), delta=bad, state=state,
                         undo=capture(state, bad, height=1, block_hash="nb:1"))
        except StoreError:
            pass
        else:
            raise AssertionError("committed a spend of a note it did not hold")
        after = store.stats()
        assert after["utxo_rows"] == before["utxo_rows"]
        assert after["height"] == before["height"]
        store.close()


def test_rolling_back_moves_the_disk_as_well_as_the_state():
    path, live, _ = run_world()
    with tempfile.TemporaryDirectory() as d:
        copy = os.path.join(d, "copy.db")
        with open(path, "rb") as src, open(copy, "wb") as dst:
            dst.write(src.read())
        store = ChainStore(copy)
        state = store.load_state(PARAMS)
        top = state.height
        registers = store.load_registers()
        record = store.rollback(state, registers)
        assert state.height == top - 1
        assert store.height == top - 1
        assert state.utxo.root == record.prev_utxo_root
        reopened = ChainStore(copy).load_state(PARAMS)
        assert reopened.utxo.root == state.utxo.root
        assert reopened.height == state.height
        store.close()


def test_undo_is_pruned_at_the_ceiling():
    """Past the fork ceiling a block is irreversible, so the record is dead
    weight — and the store says so rather than pretending."""
    with tempfile.TemporaryDirectory() as d:
        store = ChainStore(os.path.join(d, "c.db"), undo_depth=1)
        state = ChainState(PARAMS)
        state.issue("cm:0")
        state.height, state.tip = 0, "nb:genesis"
        store.initialise(state)
        for h in (1, 2, 3):
            delta = UtxoDelta(created=(f"cm:{h}",))
            record = capture(state, delta, height=h, block_hash=f"nb:{h}")
            state.apply_delta(delta)
            state.height, state.tip = h, f"nb:{h}"
            store.commit(block=_FakeBlock(h), delta=delta, state=state,
                         undo=record)
        assert store.undo_heights() == [3]
        store.rollback(state)
        try:
            store.rollback(state)
        except StoreError as exc:
            assert "irreversible" in str(exc)
            return
        finally:
            store.close()
    raise AssertionError("rolled back past the ceiling")


# ── snapshots ────────────────────────────────────────────────────────────────

def test_a_snapshot_certifies_itself_against_a_header():
    path, live, _ = run_world()
    state = live.nodes["n00"].state
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "s.snap")
        manifest = snap.export(state, live.registers, target, chunk=3)
        roots = {"utxo_root": manifest["utxo_root"],
                 "nf_root": manifest["nf_root"],
                 "registers_root": manifest["registers_root"]}
        back, registers = snap.load(target, PARAMS, expect_roots=roots)
        assert back.utxo.root == state.utxo.root
        assert back.nullifiers.root == state.nullifiers.root
        assert back.height == state.height and back.tip == state.tip
        assert {g: r.root() for g, r in registers.items()} == \
               {g: r.root() for g, r in live.registers.items()}


def test_a_snapshot_for_another_chain_is_refused():
    path, live, _ = run_world()
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "s.snap")
        manifest = snap.export(live.nodes["n00"].state, live.registers, target)
        roots = {"utxo_root": manifest["utxo_root"] ^ 1,
                 "nf_root": manifest["nf_root"],
                 "registers_root": manifest["registers_root"]}
        ok, why = snap.verify(target, roots, PARAMS)
        assert not ok and "utxo_root" in why


def test_a_damaged_snapshot_is_refused():
    path, live, _ = run_world()
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "s.snap")
        manifest = snap.export(live.nodes["n00"].state, live.registers, target,
                               chunk=2)
        blob = bytearray(open(target, "rb").read())
        blob[-60] ^= 0x01
        open(target, "wb").write(bytes(blob))
        ok, why = snap.verify(target, {
            "utxo_root": manifest["utxo_root"], "nf_root": manifest["nf_root"],
            "registers_root": manifest["registers_root"]}, PARAMS)
        assert not ok and "digest" in why


def test_the_roots_a_header_carries_are_all_a_joiner_needs():
    path, live, _ = run_world()
    header = None
    store = ChainStore(path)
    rows = store.block_headers()
    store.close()
    assert rows, "the store kept the headers"
    height, _hash, _prev, _epoch, utxo_root, nf_root, _sr, reg_root = rows[-1]
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "s.snap")
        snap.export(live.nodes["n00"].state, live.registers, target)
        back, _ = snap.load(target, PARAMS, expect_roots={
            "utxo_root": int(utxo_root), "nf_root": int(nf_root),
            "registers_root": int(reg_root)})
        assert back.height == height


# ── the signing guard ────────────────────────────────────────────────────────

def test_the_mark_is_durable_before_it_returns():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hw")
        hw = HighWater(path)
        assert hw.value == -1
        hw.claim(10)
        assert HighWater(path).value == 10


def test_signing_twice_at_a_height_is_refused():
    with tempfile.TemporaryDirectory() as d:
        hw = HighWater(os.path.join(d, "hw"))
        hw.claim(10)
        for again in (10, 9, 0):
            try:
                hw.claim(again)
            except HighWaterError as exc:
                assert "publish the key" in str(exc)
            else:
                raise AssertionError(f"claimed {again} twice")
        hw.claim(11)


def test_a_restored_holder_adopts_what_the_chain_shows():
    """The local mark is a cache; the chain is the record."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hw")
        hw = HighWater(path)
        hw.claim(5)
        stale = bytes(open(path, "rb").read())
        hw.claim(6)
        open(path, "wb").write(stale)          # yesterday's backup
        restored = HighWater(path)
        assert restored.value == 5
        restored.adopt(6)                      # learned from the chain
        assert restored.value == 6
        restored.adopt(2)
        assert restored.value == 6, "the mark never moves backwards"
        try:
            restored.claim(6)
        except HighWaterError:
            return
        raise AssertionError("signed at a height the chain already shows")


def test_a_corrupt_mark_refuses_to_be_used():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hw")
        HighWater(path).claim(3)
        blob = bytearray(open(path, "rb").read())
        blob[8] ^= 0xFF
        open(path, "wb").write(bytes(blob))
        try:
            HighWater(path)
        except HighWaterError as exc:
            assert "digest" in str(exc)
            return
        raise AssertionError("used a mark it could not verify")


class _FakeBlock:
    """Just enough of a network block for the store to write a header row."""

    def __init__(self, height):
        self.header = dataclasses.make_dataclass(
            "H", ["height", "prev_hash", "epoch", "utxo_root", "nf_root",
                  "super_root", "registers_root"])(
            height, f"nb:{height - 1}", height, 1, 2, 3, 4)

    def hash(self):
        return f"nb:{self.header.height}"
