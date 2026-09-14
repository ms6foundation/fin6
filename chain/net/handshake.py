"""Proving you are the validator you say you are.

Part six listed "no transport authentication" as an open item and part eight
built the meter anyway, on the reasoning that a budget is useful even when the
identity it is keyed on is a claim.  That reasoning was wrong in a way part
nine §4.1 sets out and this module fixes.

`hello` used to carry a `node_id` and nothing checked it, and the limiter
keyed a peer's bucket on that string.  Two consequences, and the second is much
worse than the first:

  * **Escalation.**  Claim any roster name and the budget goes from 20 tokens a
    second to 2,000 — a hundredfold, for one unsigned word.
  * **Squatting.**  The bucket is keyed on the claim, so a stranger claiming
    `v3` spends out of `v3`'s budget.  The real `v3` then finds its gossip
    refused, goes quiet, and misses its attestations — and there is no reply to
    tell it why, because a refused non-client frame is dropped in silence.  Do
    that to three of seven seats and quorum is gone; do it to all seven and the
    network stops, from one host, at about 840 KB/s, with nothing forged.  The
    rate limiter becomes the weapon.

**No new key material.**  The genesis document already carries every
validator's public key, every node already has the document, and the chain id
*is* its hash — so the roster that defines the network is also what
authenticates membership of it.

**No new round trip.**  The transport is one-way per socket: a dialler keeps
the socket it dialled for sending and never reads from it (`Mesh._dial_loop`),
and the listener reads from what dialled it.  A challenge-response would need
the dialler to start reading its own socket, which is a change to the
connection model for the sake of a nonce the dialler can perfectly well choose
itself.  So the hello is self-authenticating: it carries a nonce and is signed
over everything that could otherwise be replayed.

What the signature covers, and what each part is there to stop:

    tag         this is a hello and not some other signed message
    chain_id    replaying a hello onto another fin6 network
    from_id     the claim itself
    to_id       relaying A's hello to B — a signature for one listener is
                worthless at another
    epoch       replaying it tomorrow; the epoch comes from the genesis clock,
                which every node already derives identically
    nonce       replaying it twice inside the accepted epochs

The epoch rather than a wall-clock timestamp because nodes already agree on
epochs and a node whose clock is far enough out to fail this is a node that
cannot take a seat anyway.  `EPOCH_SLACK` of 1 covers a hello in flight across
a boundary.

## What this authenticates, and what it does not

It authenticates **a frame**, not **a stream**.  The hello proves that whoever
composed it holds the roster key it names; nothing after it on that socket is
bound to the same party.  Frames are plaintext over TCP, so an attacker on the
network path can read every byte, and can take the connection over once the
hello has passed — inheriting the seat, the budget and the attribution.

Binding the stream needs either a transport (TLS, Noise) or a shared secret to
MAC each frame with, and the roster holds Ed25519 keys for signing rather than
keys for agreement — so neither is available without new key material or a new
dependency, and both are larger decisions than this module.

Two things make the residual smaller than it sounds, and neither closes it.
Every *consensus* object carries its own signature, so a hijacker can drop and
delay but cannot forge a proposal, an attestation or a spend.  And peer
messages are now refused outright from a connection that never proved a seat
(`frame.OPEN_KINDS`), so the exposure is a hijacked connection rather than any
connection.

**A deployment runs this on a private network or inside a tunnel.**  That is a
requirement, not a recommendation, and it is stated here because this module
is the place a reader will look for it.
"""
from __future__ import annotations

import secrets

from ..crypto import h_bytes, verify_sig
from ..protocol import PROTOCOL_VERSION

#: Domain separation.  A signature over a hello must never be a valid signature
#: over an attestation, a proposal or a spend.
TAG = "f6-hello"

#: How many epochs either side of ours a hello may claim.
EPOCH_SLACK = 1

NONCE_BYTES = 16

#: Bounded because it is fed by strangers.  At seven nodes reconnecting freely
#: this is thousands of epochs of headroom; the sweep is by epoch, not by size.
MAX_SEEN = 4096


class HandshakeError(Exception):
    """A hello that does not authenticate.  Fatal to the connection: a peer
    that cannot prove its name has no claim on the next frame."""


def message(chain_id: str, from_id: str, to_id: str, epoch: int,
            nonce: str, protocol: int = PROTOCOL_VERSION) -> bytes:
    return h_bytes(TAG, chain_id, from_id, to_id, int(epoch), nonce,
                   int(protocol))


def _protocol_of(payload) -> int:
    """The version a hello claims, defaulting to 1 for a peer that predates
    the field.  Advisory either way: it is reported, never enforced — a node
    that lies about its version only misleads a dashboard, because what
    actually decides a block is the activation schedule in the document."""
    value = payload.get("protocol", 1)
    return value if isinstance(value, int) else 1


def build(signer, chain_id: str, from_id: str, to_id: str, epoch: int,
          nonce: str | None = None,
          protocol: int = PROTOCOL_VERSION) -> dict:
    """The payload a dialler sends.  `node_id` keeps its old name and meaning;
    everything beside it is what makes the name worth anything.

    `protocol` is signed rather than merely carried, for a small reason worth
    stating: an unsigned version field is one an attacker can rewrite, and the
    thing it would buy is making a current peer look stale on somebody's
    upgrade dashboard the week before an activation height. Cheap to sign, so
    signed.
    """
    nonce = nonce or secrets.token_hex(NONCE_BYTES)
    return {"node_id": from_id, "to": to_id, "epoch": int(epoch),
            "nonce": nonce, "protocol": int(protocol),
            "signature": signer.sign(message(chain_id, from_id, to_id,
                                             epoch, nonce, protocol))}


class Verifier:
    """One node's side of the check, with the replay window it needs.

    Held by `Mesh` and consulted once per connection.  The order of the checks
    is deliberate and matches `Envelope.add_attestation`: everything decidable
    by dictionary lookup comes before the 74 µs of signature verification, so a
    stranger's forged hello is refused for microseconds.
    """

    def __init__(self, chain_id: str, node_id: str, validators: dict,
                 epoch_now, slack: int = EPOCH_SLACK, max_seen: int = MAX_SEEN):
        self.chain_id = chain_id
        self.node_id = node_id
        self.validators = dict(validators)
        self.epoch_now = epoch_now
        self.slack = slack
        self.max_seen = max_seen
        self._seen: dict = {}          # (node_id, nonce) -> epoch
        #: What each peer last said it implements.  Reported by `net status`,
        #: so "is the network ready for the activation height" is a table
        #: rather than a conversation.
        self.peer_protocol: dict = {}
        self.accepted = 0
        self.refused = 0

    def claims_a_seat(self, payload) -> bool:
        """Is this hello even claiming to be a validator?

        A wallet introduces itself too — `client/rpc.py` opens with a hello
        naming `fin6-client` — which part nine §4.1 got wrong when it said a
        client never sends one.  A name that is not in the roster is a label,
        not a claim: there is nothing to prove and nothing to be gained by
        proving it, because only a roster name reaches a peer's budget.  So it
        is accepted and ignored, and the connection stays a client.

        Refusing it instead was a real outage in the making: the first version
        of this treated any unauthenticated hello as fatal, closed the
        connection, and every wallet submission was silently dropped with the
        transaction that followed it in the same send.
        """
        return isinstance(payload, dict) and \
            payload.get("node_id") in self.validators

    def check(self, payload):
        """(ok, reason, node_id).  Never raises."""
        if not isinstance(payload, dict):
            return self._no("a hello must be a mapping")
        claimed = payload.get("node_id")
        expected = self.validators.get(claimed)
        if expected is None:
            # Not a refusal of an unknown *client* — a client never sends a
            # hello.  This is someone claiming a seat that does not exist.
            return self._no(f"{claimed!r} is not in the roster")
        if payload.get("to") != self.node_id:
            return self._no(f"addressed to {payload.get('to')!r}, not "
                            f"{self.node_id!r}")
        epoch, now = payload.get("epoch"), self.epoch_now()
        if not isinstance(epoch, int) or abs(epoch - now) > self.slack:
            return self._no(f"epoch {epoch} against {now}")
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            return self._no("no nonce")
        key = (claimed, nonce)
        if key in self._seen:
            return self._no("nonce already used")
        if self._full():
            # Fail closed.  The eviction below used to drop the oldest entries
            # by insertion order when every one of them was still inside the
            # replay window, which quietly turns the cache into a way to
            # *defeat* the cache: fill it, evict somebody's nonce, replay their
            # captured hello.  Reaching this needs a roster key — nothing is
            # recorded until a signature verifies — so it was never an
            # outsider's attack, but a replay window that can be emptied is not
            # a replay window.  Refusing is the safe direction: a peer retries
            # with a fresh nonce next epoch, when the window has aged out.
            return self._no("replay window is full this epoch")
        signature = payload.get("signature")
        if not isinstance(signature, str):
            return self._no("no signature")
        version = _protocol_of(payload)
        if not verify_sig(expected, message(self.chain_id, claimed,
                                            self.node_id, epoch, nonce,
                                            version),
                          signature):
            return self._no(f"{claimed} did not sign this hello")
        # Recorded only now.  Recording a nonce before the signature verified
        # would let anyone burn the real validator's nonces by guessing them —
        # the same shape of mistake as refusing a transaction body because
        # someone else spliced a bad proof onto it.
        self._remember(key, epoch, now)
        self.peer_protocol[claimed] = version
        self.accepted += 1
        return True, "ok", claimed

    def _no(self, why: str):
        self.refused += 1
        return False, why, None

    def _sweep(self, now: int):
        """Drop every nonce that has aged out of the window."""
        stale = [k for k, e in self._seen.items() if abs(now - e) > self.slack]
        for k in stale:
            del self._seen[k]
        return len(stale)

    def _full(self) -> bool:
        """True when the cache is at its cap *and* nothing in it has aged out.

        Sweeping first, because the cap exists to bound memory against
        strangers and the window exists to bound replay: an entry that has left
        the window costs nothing to forget, and one that has not must not be
        forgotten at any price.
        """
        if len(self._seen) < self.max_seen:
            return False
        self._sweep(self.epoch_now())
        return len(self._seen) >= self.max_seen

    def _remember(self, key, epoch: int, now: int):
        self._seen[key] = epoch
        if len(self._seen) > self.max_seen:
            self._sweep(now)

    def stats(self) -> dict:
        return {"accepted": self.accepted, "refused": self.refused,
                "nonces": len(self._seen),
                "peers": dict(sorted(self.peer_protocol.items()))}

    def __repr__(self):
        return (f"Verifier({self.node_id}, {self.accepted} accepted, "
                f"{self.refused} refused)")
