"""The grid register — attendance as state, not opinion."""
from ..params import DEMO
from ..register import AttendanceRoll, GridRegister, Standing


def _reg(threshold=3, forgiveness=0):
    r = GridRegister.genesis("g0", ["a", "b", "c"], attend_threshold=threshold,
                             forgiveness=forgiveness)
    r.admit("d")
    return r


def _roll(epoch, attended=("a", "b", "c", "d"), leader="a"):
    return AttendanceRoll("g0", epoch, leader, seated=("a", "b", "c", "d"),
                          attended=tuple(attended))


def test_founders_start_as_attesters():
    r = _reg()
    assert r.attesters() == ["a", "b", "c"]
    assert r.standing_of("d") == Standing.APPRENTICE


def test_a_newcomer_is_promoted_at_the_threshold():
    r = _reg(threshold=3)
    for e in range(2):
        r.apply(_roll(e))
        assert r.standing_of("d") == Standing.APPRENTICE
    r.apply(_roll(2))
    assert r.standing_of("d") == Standing.ATTESTER
    assert r.members["d"].consecutive == 3


def test_absence_resets_the_counter():
    r = _reg(threshold=3)
    r.apply(_roll(0))
    r.apply(_roll(1))
    r.apply(_roll(2, attended=("a", "b", "c")))       # d missed one
    assert r.members["d"].consecutive == 0
    assert r.standing_of("d") == Standing.APPRENTICE


def test_forgiveness_lets_one_absence_pass():
    r = _reg(threshold=3, forgiveness=1)
    r.apply(_roll(0))
    r.apply(_roll(1, attended=("a", "b", "c")))
    assert r.members["d"].consecutive == 1, "one miss should be forgiven"


def test_a_provable_fault_suspends_and_does_not_heal():
    r = _reg()
    r.apply(_roll(0), faulted=["b"])
    assert r.standing_of("b") == Standing.SUSPENDED
    assert "b" not in r.attesters()
    r.apply(_roll(1))
    assert r.standing_of("b") == Standing.SUSPENDED, "suspension is not self-healing"


def test_two_replicas_derive_the_same_root():
    """The whole point: standing is state every seat recomputes, not an opinion."""
    a, b = _reg(), _reg()
    for e in range(4):
        a.apply(_roll(e))
        b.apply(_roll(e))
    assert a.root() == b.root()


def test_the_root_moves_when_anything_changes():
    r = _reg()
    before = r.root()
    r.apply(_roll(0))
    assert r.root() != before


def test_clone_reproduces_the_root():
    r = _reg()
    r.apply(_roll(0))
    assert r.clone().root() == r.root()


def test_quorum_counts_attesters_only():
    r = _reg()
    assert len(r.seated_members()) == 4
    assert r.quorum(2, 3) == 2, "3 attesters -> quorum 2, the apprentice is not counted"
    for e in range(3):
        r.apply(_roll(e))
    assert r.quorum(2, 3) == 3, "4 attesters -> quorum 3"


def test_relocating_costs_the_full_gate():
    """Moving grid restarts the counter — this is what makes capture slow."""
    home = _reg(threshold=3)
    for e in range(3):
        home.apply(_roll(e))
    assert home.standing_of("d") == Standing.ATTESTER

    elsewhere = GridRegister.genesis("g1", ["x", "y"], attend_threshold=3)
    elsewhere.admit("d")
    assert elsewhere.standing_of("d") == Standing.APPRENTICE
    assert elsewhere.members["d"].consecutive == 0


def test_a_seated_stranger_is_admitted_at_zero():
    r = _reg()
    r.apply(AttendanceRoll("g0", 0, "a", seated=("a", "b", "c", "d", "e"),
                           attended=("a", "b", "c", "d", "e")))
    assert r.standing_of("e") == Standing.APPRENTICE
    assert r.members["e"].consecutive == 1


def test_default_threshold_is_the_designed_forty():
    assert DEMO.attend_threshold == 40
