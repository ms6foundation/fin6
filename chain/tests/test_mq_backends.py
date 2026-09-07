"""The mq proof backends: MPC-in-the-head, 3-pass, and the ms6/vs6 split."""
import copy
import inspect
import secrets

from mq.ms6 import P
from mq.ms6 import mpcith as m_mpcith
from mq.ms6 import ssh3 as m_ssh3
from mq.ms6.core import RestrictedMap, _fs_gamma, _statement
from mq.vs6 import mpcith as v_mpcith
from mq.vs6 import ssh3 as v_ssh3

from ..crypto import Signer, h_field
from ..notes import Note
from ..params import DEMO
from ..txsystem import tx_system

ALICE, BOB = Signer.from_seed("alice"), Signer.from_seed("bob")


def _statement_parts():
    note = Note.create(500, ALICE.public_hex, DEMO)
    o1 = Note.create(300, BOB.public_hex, DEMO, asset=note.asset)
    o2 = Note.create(190, ALICE.public_hex, DEMO, asset=note.asset)
    ts = tx_system(DEMO, 1, 2)
    beta = h_field("tx-bind", "mq-test")
    X = ts.lift(note.coords() + o1.coords() + o2.coords() + [beta])
    v = ts.F(X)
    z = [X[i] for i in range(ts.N) if i != ts.bind_pos]
    return ts, v, {ts.bind_pos: beta}, z, beta


def _batched(ts, v, known):
    R = RestrictedMap(ts, known)
    return R, R.batched(_fs_gamma(_statement(v, known), ts.m), v)


# ── the ms6 / vs6 split ──────────────────────────────────────────────────────

def test_vs6_cannot_prove_anything():
    """A party that only verifies can audit vs6 alone."""
    for mod in (v_ssh3, v_mpcith):
        for name in dir(mod):
            assert not name.startswith("prove"), f"{mod.__name__}.{name}"
    assert not hasattr(v_mpcith, "sacrifice_check_in_the_clear")


def test_vs6_does_not_import_ms6():
    for mod in (v_ssh3, v_mpcith):
        src = inspect.getsource(mod)
        assert "from ..ms6" not in src and "import ms6" not in src, mod.__name__


def test_the_verifier_copies_are_verbatim():
    """The bit-for-bit regression the package docstrings ask for."""
    pairs = [(v_ssh3.verify_hidden3, m_ssh3.verify_hidden3),
             (v_ssh3.fs_trits, m_ssh3.fs_trits),
             (v_mpcith.verify_mpcith, m_mpcith.verify_mpcith),
             (v_mpcith.tree_rebuild, m_mpcith.tree_rebuild),
             (v_mpcith.matvec_transpose, m_mpcith.matvec_transpose),
             (v_mpcith.party_broadcast_sigma, m_mpcith.party_broadcast_sigma)]
    for a, b in pairs:
        assert inspect.getsource(a) == inspect.getsource(b), a.__name__


def test_both_verifiers_agree_on_every_proof():
    ts, v, known, z, _ = _statement_parts()
    for prove, mv, vv in ((m_ssh3.prove_hidden3, m_ssh3.verify_hidden3, v_ssh3.verify_hidden3),
                          (m_mpcith.prove_mpcith, m_mpcith.verify_mpcith, v_mpcith.verify_mpcith)):
        good = prove(ts, v, known, z)
        assert mv(ts, v, known, good) is vv(ts, v, known, good) is True
        bad = list(v)
        bad[ts.sum_row] = (bad[ts.sum_row] + 1) % P
        assert mv(ts, bad, known, good) == vv(ts, bad, known, good) == False


# ── MPCitH stage 1: the explicit form ────────────────────────────────────────

def test_the_transpose_identity_holds():
    """<alpha, Az> == <A^T alpha, z> — what replaces a matvec per party."""
    ts, v, known, z, _ = _statement_parts()
    R, BF = _batched(ts, v, known)
    alpha = [secrets.randbelow(P) for _ in range(R.h)]
    lhs = sum(a * w for a, w in zip(alpha, BF.qf.matvec(BF.A, z))) % P
    u = m_mpcith.matvec_transpose(BF.qf, BF.A, alpha)
    rhs = sum(ui * zi for ui, zi in zip(u, z)) % P
    assert lhs == rhs


# ── MPCitH stage 2: the sacrifice check ──────────────────────────────────────

def test_the_sacrifice_check_sums_to_zero_for_a_true_claim():
    ts, v, known, z, _ = _statement_parts()
    _, BF = _batched(ts, v, known)
    assert BF.q(z) == BF.t
    for parties in (1, 3, 8):
        total, _ = m_mpcith.sacrifice_check_in_the_clear(
            BF, z, parties, secrets.randbelow(P))
        assert total == 0, parties


def test_the_sacrifice_check_catches_a_wrong_witness():
    ts, v, known, z, _ = _statement_parts()
    _, BF = _batched(ts, v, known)
    wrong = list(z)
    wrong[0] = (wrong[0] + 1) % P
    total, _ = m_mpcith.sacrifice_check_in_the_clear(
        BF, wrong, 8, secrets.randbelow(P))
    assert total != 0


# ── MPCitH stage 3: seed tree ────────────────────────────────────────────────

def test_the_seed_tree_opens_every_party_but_one():
    root = secrets.token_bytes(16)
    for n in (2, 4, 8, 16):
        full = m_mpcith.tree_leaves(root, n)
        for hidden in range(n):
            rebuilt = m_mpcith.tree_rebuild(
                m_mpcith.tree_path(root, n, hidden), n, hidden)
            assert rebuilt[hidden] is None
            for i in range(n):
                if i != hidden:
                    assert rebuilt[i] == full[i], (n, hidden, i)


def test_a_seed_path_of_the_wrong_depth_is_refused():
    try:
        m_mpcith.tree_rebuild((b"x" * 16,), 16, 0)
    except ValueError:
        return
    raise AssertionError("a short seed path was accepted")


def test_repetitions_follow_the_party_count():
    assert m_mpcith.repetitions_for(80, 16) == 20
    assert m_mpcith.repetitions_for(80, 256) == 10
    assert m_mpcith.repetitions_for(128, 256) == 16


def test_more_parties_means_a_smaller_proof():
    ts, v, known, z, _ = _statement_parts()
    sizes = {}
    for n in (8, 64):
        proof = m_mpcith.prove_mpcith(ts, v, known, z, n_parties=n)
        assert m_mpcith.verify_mpcith(ts, v, known, proof)
        sizes[n] = len(m_mpcith.serialize_proof_mpcith(proof))
    assert sizes[64] < sizes[8], sizes


def test_a_non_power_of_two_party_count_is_refused():
    ts, v, known, z, _ = _statement_parts()
    try:
        m_mpcith.prove_mpcith(ts, v, known, z, n_parties=12)
    except ValueError:
        return
    raise AssertionError("12 parties should not be accepted")


# ── MPCitH soundness ─────────────────────────────────────────────────────────

def test_mpcith_rejects_a_wrong_witness():
    ts, v, known, z, _ = _statement_parts()
    wrong = list(z)
    wrong[0] = (wrong[0] + 1) % P
    proof = m_mpcith.prove_mpcith(ts, v, known, wrong, n_parties=8)
    assert not m_mpcith.verify_mpcith(ts, v, known, proof)


def test_mpcith_is_bound_to_its_statement():
    ts, v, known, z, beta = _statement_parts()
    proof = m_mpcith.prove_mpcith(ts, v, known, z, n_parties=8)
    assert not m_mpcith.verify_mpcith(ts, v, {ts.bind_pos: (beta + 1) % P}, proof)


def test_mpcith_rejects_every_tampered_field():
    ts, v, known, z, _ = _statement_parts()
    proof = m_mpcith.prove_mpcith(ts, v, known, z, n_parties=8)
    assert m_mpcith.verify_mpcith(ts, v, known, proof)

    def broken(mutate):
        p = copy.deepcopy(proof)
        mutate(p)
        return not m_mpcith.verify_mpcith(ts, v, known, p)

    assert broken(lambda p: p.update(salt=b"\x00" * 32)), "salt"
    assert broken(lambda p: p["sigma_hidden"].__setitem__(
        0, (p["sigma_hidden"][0] + 1) % P)), "sigma"
    assert broken(lambda p: p["alpha_hidden"][0].__setitem__(
        0, (p["alpha_hidden"][0][0] + 1) % P)), "alpha"
    assert broken(lambda p: p["com_hidden"].__setitem__(0, b"\x00" * 32)), "commitment"
    assert broken(lambda p: p.update(
        hidden=[(i + 1) % p["parties"] for i in p["hidden"]])), "party challenge"


def test_mpcith_refuses_a_withheld_correction_when_it_should_be_present():
    """Corrections are withheld exactly when the last party is the hidden one —
    sending them otherwise would hand the verifier the whole witness."""
    ts, v, known, z, _ = _statement_parts()
    proof = m_mpcith.prove_mpcith(ts, v, known, z, n_parties=8)
    last = proof["parties"] - 1
    for rep, hidden in enumerate(proof["hidden"]):
        p = copy.deepcopy(proof)
        p["deltas"][rep] = None if hidden != last else ([0] * 48, 0)
        assert not m_mpcith.verify_mpcith(ts, v, known, p)
        return


# ── 3-pass ───────────────────────────────────────────────────────────────────

def test_three_pass_default_round_count():
    assert m_ssh3.DEFAULT_ROUNDS_3PASS == 137          # (2/3)^137 <= 2^-80


def test_three_pass_round_trip_and_soundness():
    ts, v, known, z, beta = _statement_parts()
    proof = m_ssh3.prove_hidden3(ts, v, known, z, rounds=16)
    assert m_ssh3.verify_hidden3(ts, v, known, proof)
    bad = list(v)
    bad[ts.sum_row] = (bad[ts.sum_row] + 1) % P
    assert not m_ssh3.verify_hidden3(ts, bad, known, proof)
    assert not m_ssh3.verify_hidden3(ts, v, {ts.bind_pos: (beta + 1) % P}, proof)
