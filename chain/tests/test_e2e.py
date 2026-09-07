"""A whole chain: several blocks, each finalised by its own ceremony."""
from ..ceremony import run_epoch
from ..network import bootstrap, transfer
from ..params import DEMO

IDS = [f"v{i:02d}" for i in range(9)]


def test_three_blocks_of_transfers():
    nodes, wallets, genesis = bootstrap(
        IDS, {"alice": [1000, 800], "bob": [250], "carol": []}, DEMO)
    start_total = sum(w.balance() for w in wallets.values())

    plan = [("alice", "bob", 300, 5),
            ("bob", "carol", 200, 5),
            ("alice", "carol", 400, 5)]

    for height, (src, dst, amount, fee) in enumerate(plan, start=1):
        tx, _ = transfer(wallets[src], wallets[dst], amount, fee, DEMO)
        for node in nodes.values():
            ok, why = node.submit(tx)
            assert ok, f"height {height}: {why}"

        epoch = run_epoch(nodes, DEMO, height=height, epoch=height,
                          base_seed="chain")
        assert epoch.finalised, f"height {height}: {epoch.result.reason}"
        block = epoch.result.block
        assert len(block.transactions) == 1

        for node in nodes.values():
            node.apply(block)

        assert {n.state.height for n in nodes.values()} == {height}
        assert len({n.state.utxo.root for n in nodes.values()}) == 1
        assert len({n.state.tip for n in nodes.values()}) == 1

    fees = sum(f for _, _, _, f in plan)
    assert sum(w.balance() for w in wallets.values()) == start_total - fees
    assert nodes["v00"].state.burned_fees == fees
    assert len(nodes["v00"].state.nullifiers) == len(plan)


def test_every_block_carries_a_verifiable_certificate():
    nodes, wallets, genesis = bootstrap(IDS, {"alice": [1000], "bob": []}, DEMO)
    validators = {n.id: n.public_hex for n in nodes.values()}
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, DEMO)
    for node in nodes.values():
        node.submit(tx)

    epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="chain")
    block = epoch.result.block
    ok, why = block.quorum_cert.verify(DEMO.quorum_size(len(IDS)),
                                       block.hash(), validators)
    assert ok, why
    assert block.quorum_cert.height == 1
