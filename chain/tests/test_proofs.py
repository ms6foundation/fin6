"""The per-tier proof backends, and what protocol diversity actually buys."""
from mq.ms6 import P

from ..crypto import Signer, h_field
from ..notes import Note
from ..params import DEMO, DESIGNED
from ..proofs import ProofError, available_backends, get_backend
from ..txsystem import tx_system

ALICE, BOB = Signer.from_seed("alice"), Signer.from_seed("bob")


def _statement(rounds_hint=None):
    note = Note.create(500, ALICE.public_hex, DEMO)
    o1 = Note.create(300, BOB.public_hex, DEMO, asset=note.asset)
    o2 = Note.create(190, ALICE.public_hex, DEMO, asset=note.asset)
    ts = tx_system(DEMO, 1, 2)
    beta = h_field("tx-bind", "test")
    X = ts.lift(note.coords() + o1.coords() + o2.coords() + [beta])
    v = ts.F(X)
    z = [X[i] for i in range(ts.N) if i != ts.bind_pos]
    return ts, v, {ts.bind_pos: beta}, z, beta


def test_all_three_backends_are_available():
    assert set(available_backends()) == {"mpcith", "ssh3", "ssh5"}


def test_round_counts_follow_the_soundness_error():
    assert get_backend("ssh5").rounds_for(80) == 80        # error ~1/2
    assert get_backend("ssh3").rounds_for(80) == 137       # error 2/3


def test_three_pass_round_trip():
    ts, v, known, z, _ = _statement()
    b = get_backend("ssh3")
    proof = b.prove(ts, v, known, z, rounds=12)
    assert b.verify(ts, v, known, proof)


def test_three_pass_rejects_a_tampered_statement():
    ts, v, known, z, _ = _statement()
    b = get_backend("ssh3")
    proof = b.prove(ts, v, known, z, rounds=12)
    bad = list(v)
    bad[ts.sum_row] = (bad[ts.sum_row] + 1) % P
    assert not b.verify(ts, bad, known, proof)


def test_three_pass_rejects_a_wrong_witness():
    ts, v, known, z, _ = _statement()
    b = get_backend("ssh3")
    wrong = list(z)
    wrong[0] = (wrong[0] + 1) % P
    assert not b.verify(ts, v, known, b.prove(ts, v, known, wrong, rounds=12))


def test_three_pass_cannot_be_rebound():
    ts, v, known, z, beta = _statement()
    b = get_backend("ssh3")
    proof = b.prove(ts, v, known, z, rounds=12)
    assert not b.verify(ts, v, {ts.bind_pos: (beta + 1) % P}, proof)


def test_every_pair_of_systems_rejects_the_other():
    """Diversity is only real if the verifiers are genuinely different."""
    ts, v, known, z, _ = _statement()
    proofs = {n: get_backend(n).prove(ts, v, known, z, rounds=4)
              for n in ("mpcith", "ssh5", "ssh3")}
    for checker in proofs:
        for maker, proof in proofs.items():
            if checker == maker:
                continue
            assert not get_backend(checker).verify(ts, v, known, proof), \
                f"{checker} accepted a {maker} proof"


def test_three_pass_is_bulkier_at_equal_security():
    """Per round the 3-pass is marginally the cheaper of the two — the 5-pass
    always ships its mid vector.  What makes it the bulkier system is the round
    count: error 2/3 needs 137 rounds where error ~1/2 needs 80.  So the
    comparison that means anything is at each system's own 2^-80 setting."""
    ts, v, known, z, _ = _statement()
    b3, b5 = get_backend("ssh3"), get_backend("ssh5")
    s3 = b3.size(b3.prove(ts, v, known, z, rounds=b3.rounds_for(80)))
    s5 = b5.size(b5.prove(ts, v, known, z, rounds=b5.rounds_for(80)))
    assert s3 > s5, f"3-pass {s3} should exceed 5-pass {s5} at 2^-80"
    assert s3 < 3 * s5, "…but not by more than a small factor"


def test_mpcith_round_trip():
    b = get_backend("mpcith")
    assert b.available
    ts, v, known, z, _ = _statement()
    proof = b.prove(ts, v, known, z, rounds=4)
    assert b.verify(ts, v, known, proof)


def test_mpcith_is_the_smallest_of_the_three():
    """Why it guards the tier that verifies most."""
    ts, v, known, z, _ = _statement()
    sizes = {}
    for name in ("mpcith", "ssh5", "ssh3"):
        b = get_backend(name)
        sizes[name] = b.size(b.prove(ts, v, known, z, rounds=b.rounds_for(80)))
    assert sizes["mpcith"] < sizes["ssh5"] < sizes["ssh3"], sizes


def test_unknown_backend_is_refused():
    try:
        get_backend("groth16")
    except ProofError:
        return
    raise AssertionError("an unknown backend was accepted")


def test_the_designed_policy_is_now_the_running_one():
    """mpcith / ssh5 / ssh3 from local to supreme — all three implemented."""
    assert DEMO.backend_for("local") == "mpcith"
    assert DEMO.backend_for("super") == "ssh5"
    assert DEMO.backend_for("supreme") == "ssh3"
    assert set(DEMO.proof_backends) == {"mpcith", "ssh5", "ssh3"}
