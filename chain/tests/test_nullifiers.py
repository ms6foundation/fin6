"""What a nullifier has to be, and what it was.

This file exists because a storage question turned into a security one. The
open item was that nullifiers never shrink — 27 MB/day at 10 tx/s, forever,
because correctness needs every nullifier ever. Chasing whether the set was
load-bearing at all found something worse than an unbounded cost.

The nullifier was a single public quadratic form over the note's coordinates:
eight of them at DEMO, forty-eight at STRONG, mapping onto one field element.
Its fibres are therefore enormous, and easy to walk — the form is homogeneous
of degree 2, so Q(-x) = Q(x), and solving Q(x) = t for one blinder is one
square root mod P.

That is exploitable in a direction the design did not consider, because a
*payer* chooses every coordinate of the note it hands you, blinders included.
"""
from mq.ms6 import P

from ..notes import (NOTE_FIXED_COORDS, Note, note_id, note_vector,
                     nullifier_coeffs, nullifier_id, nullifier_value,
                     system_for)
from ..params import DEMO


# ── the arithmetic that made it possible ─────────────────────────────────────

def _sqrt_mod(a, p=P):
    """Tonelli-Shanks.  P % 4 == 1, so there is no shortcut."""
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t, r = t * c % p, r * b % p
    return r


def _solve_for(coords, k, target, n):
    """Choose coords[k] so the nullifier form evaluates to `target`.

    One quadratic in one unknown: A·b² + B·b + C = target.
    """
    A = B = C = 0
    for i, j, c in nullifier_coeffs(n):
        if i == k and j == k:
            A = (A + c) % P
        elif i == k:
            B = (B + c * coords[j]) % P
        elif j == k:
            B = (B + c * coords[i]) % P
        else:
            C = (C + c * coords[i] * coords[j]) % P
    root = _sqrt_mod((B * B - 4 * A * ((C - target) % P)) % P)
    if root is None:
        return None
    return (-B + root) * pow(2 * A, -1, P) % P


def _collide(payer_note, value, owner, params=DEMO, tries=40):
    """A note of the given value and owner whose *form* collides with
    `payer_note` — the note a malicious payer would hand its victim.

    The discriminant is a square about half the time, so this draws a fresh
    note and tries again. That is not a mitigation: it is two attempts on
    average, and each one is a keygen and a square root.
    """
    n = system_for(params).n
    target = nullifier_value(payer_note.coords())
    for _ in range(tries):
        victim = Note.create(value, owner, params, asset=payer_note.asset)
        b = _solve_for(victim.coords(), NOTE_FIXED_COORDS, target, n)
        if b is None:
            continue
        blinders = list(victim.blinders)
        blinders[0] = b
        return Note(value=victim.value, asset=victim.asset,
                    owner=victim.owner, rho=victim.rho,
                    blinders=tuple(blinders))
    raise AssertionError(f"no collision in {tries} draws, which should be "
                         f"about 2^-{tries} unlikely")


def test_the_form_is_homogeneous_so_negation_collides():
    """The cheapest collision of all, and enough on its own to show that the
    form cannot be an identity."""
    note = Note.create(500, "aa" * 32, DEMO)
    x = note.coords()
    assert nullifier_value([(-a) % P for a in x]) == nullifier_value(x)


def test_a_payer_can_make_your_note_share_its_nullifier_form():
    """Milliseconds, not luck: one square root in one unconstrained blinder.

    Note what is *not* being assumed. The values differ, the owners differ,
    the commitments differ. Only the form collides, and a payer chooses the
    coordinates it needs because it builds the note it pays you.
    """
    payer = Note.create(500, "aa" * 32, DEMO)
    victim = _collide(payer, 250, "bb" * 32)
    assert victim.value == 250 and payer.value == 500
    assert victim.owner != payer.owner
    assert nullifier_value(victim.coords()) == nullifier_value(payer.coords())
    assert note_id(note_vector(victim, DEMO)) != note_id(note_vector(payer, DEMO))


# ── and why binding the commitment is what fixes it ─────────────────────────

def test_the_published_nullifier_no_longer_collides():
    """The fix, in one hash input.

    Before this, the two notes above published the same nullifier — so a payer
    could spend its own note and leave the victim's permanently unspendable:
    live and unspent in the UTXO set, and refused by every node as a double
    spend. One payment to freeze a stranger's funds for good.
    """
    payer = Note.create(500, "aa" * 32, DEMO)
    victim = _collide(payer, 250, "bb" * 32)
    payer_cm = note_id(note_vector(payer, DEMO))
    victim_cm = note_id(note_vector(victim, DEMO))

    # The form still collides — that is inherent to a single field element —
    fe = nullifier_value(payer.coords())
    assert fe == nullifier_value(victim.coords())
    # — and the published ids do not, because each binds its own commitment.
    assert nullifier_id(payer_cm, fe) != nullifier_id(victim_cm, fe)


def test_a_nullifier_is_pinned_to_one_commitment():
    """Which is the property that matters: as discriminating as `cm` itself,
    so a nullifier collision now needs a commitment collision."""
    note = Note.create(500, "aa" * 32, DEMO)
    fe = nullifier_value(note.coords())
    cm = note_id(note_vector(note, DEMO))
    assert nullifier_id(cm, fe) == note.nullifier(DEMO)
    assert nullifier_id("cm:something-else", fe) != note.nullifier(DEMO)


def test_the_same_note_still_has_one_nullifier():
    """It has to stay deterministic, or a spender could publish a fresh marker
    every time and the set would catch nothing at all."""
    note = Note.create(500, "aa" * 32, DEMO)
    assert note.nullifier(DEMO) == note.nullifier(DEMO)
    same = Note(value=note.value, asset=note.asset, owner=note.owner,
                rho=note.rho, blinders=note.blinders)
    assert same.nullifier(DEMO) == note.nullifier(DEMO)


def test_two_ordinary_notes_still_differ():
    a = Note.create(100, "aa" * 32, DEMO)
    b = Note.create(100, "aa" * 32, DEMO)
    assert a.nullifier(DEMO) != b.nullifier(DEMO), "rho differs"
