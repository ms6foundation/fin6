"""The ceremony's seating and edges — the topology the design specifies."""
from ..ceremony import Grid
from ..params import DEMO

IDS = [f"v{i:02d}" for i in range(13)]
C = 5


def grid(seed="seed-a", ids=None):
    return Grid.seat(ids or IDS, C, seed)


def test_seating_is_deterministic():
    a, b = grid(), grid()
    assert a.leader == b.leader
    assert a.rows == b.rows


def test_reseeding_reseats_everyone():
    a, b = grid("seed-a"), grid("seed-b")
    assert (a.leader, a.rows) != (b.leader, b.rows)


def test_leader_sits_alone_in_the_front_row():
    g = grid()
    assert g.seats[g.leader].row == 0 and g.seats[g.leader].col == 0
    assert sum(1 for s in g.seats.values() if s.row == 0) == 1
    assert g.front(g.leader) is None and g.right(g.leader) is None


def test_rows_have_fixed_size_except_the_last():
    g = grid()
    assert all(len(r) == C for r in g.rows[:-1])
    assert 1 <= len(g.rows[-1]) <= C
    assert sum(len(r) for r in g.rows) == len(IDS) - 1


def test_every_seat_synchronises_to_front_and_right():
    g = grid()
    for nid, seat in g.seats.items():
        if seat.row == 0:
            continue
        assert len(g.neighbours(nid)) == 2, nid


def test_row_one_fronts_to_the_leader():
    g = grid()
    assert all(g.front(nid) == g.leader for nid in g.rows[0])


def test_front_is_the_same_column_one_row_up():
    g = grid()
    for r in range(1, len(g.rows)):
        for c, nid in enumerate(g.rows[r]):
            assert g.front(nid) == g.rows[r - 1][c]


def test_the_rightmost_seat_wraps_to_the_leftmost():
    g = grid()
    for row in g.rows:
        if len(row) < 2:
            continue
        assert g.right(row[-1]) == row[0], "the row's ring does not close"


def test_walking_right_traverses_the_whole_row_once():
    g = grid()
    for row in g.rows:
        if len(row) < 2:
            continue
        seen, cur = [], row[0]
        for _ in range(len(row)):
            seen.append(cur)
            cur = g.right(cur)
        assert cur == row[0]
        assert sorted(seen) == sorted(row)


def test_graph_is_connected_and_low_diameter():
    g = grid()
    assert g.diameter() > 0, "grid is disconnected"
    assert g.diameter() <= g.n_rows + C


def test_edge_count_is_linear_in_seats():
    g = grid()
    assert len(g.edges()) <= 2 * len(IDS)


def test_short_last_row_still_forms_a_ring():
    g = Grid.seat([f"v{i:02d}" for i in range(8)], 5, "seed")   # rows of 5, 2
    assert len(g.rows[-1]) == 2
    a, b = g.rows[-1]
    assert g.right(a) == b and g.right(b) == a


def test_single_seat_row_has_no_right_neighbour():
    g = Grid.seat([f"v{i:02d}" for i in range(7)], 5, "seed")   # rows of 5, 1
    assert len(g.rows[-1]) == 1
    assert g.right(g.rows[-1][0]) is None
    assert len(g.neighbours(g.rows[-1][0])) == 1


def test_view_change_excludes_tried_leaders():
    g1 = grid()
    g2 = Grid.seat(IDS, C, "seed-b", exclude_leaders=[g1.leader])
    assert g2.leader != g1.leader
    assert len(g2.seats) == len(IDS)
