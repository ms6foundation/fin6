"""Which rules are in force, and what a node does when they are not its rules.

The pre-genesis review's first finding: `FORMAT_VERSION` existed in two places
and both were *rejection* checks — a node refuses a document or a record from a
different version.  Nothing negotiated, nothing activated, and the design's own
open item said the rest: changing a parameter on a live network "is a
governance event with no design at all yet."

The consequence was not that upgrades were hard.  It was that **every format
change was permanent**, because there was no mechanism by which a running
network could adopt one.  This module is that mechanism, and it has to exist
before the history it governs — a rule about when rules change cannot be
retrofitted onto blocks produced before anybody was counting.

## Three versions, and they are not the same version

    frame.VERSION       how bytes are framed on the wire.  A rejection check,
                        correctly: a peer speaking a different framing is not
                        speaking to us at all.
    codec.FORMAT_VERSION  how a record is encoded at rest.  Also a rejection
                        check, also correct — a store is one process's own.
    PROTOCOL_VERSION    *which rules produce a valid block*.  This one cannot
                        be a rejection check, because two nodes on either side
                        of an upgrade have to agree about history they both
                        already hold.

## How a change ships

A rule change gets the next version number and an **activation height**, and
the height goes in the genesis document — which means a chain's whole upgrade
schedule is inside the thing its identity is the hash of.  Adding one later is
a governance act that produces a new document and, by construction, a new
chain; scheduling one *in advance* is just a number.

    activations = {2: 150_000}      # version 2 takes effect at height 150,000

Every block names the version it was produced under, and a verifier recomputes
what that height *should* have been from the activation table.  A block that
claims the wrong rule set is refused like any other invalid block, so an
un-upgraded producer cannot quietly keep producing under the old rules.

## What a node does when the rules leave it behind

It **stops**.  This is the whole point and the easiest thing to get wrong.

A node that reaches an activation height for a version it does not implement
has three options and only one of them is honest.  It can apply the block with
the rules it knows — which is a silent fork, the worst outcome, because the
operator sees a running node.  It can refuse the block as invalid — which looks
identical to the network having failed, and invites someone to "fix" it.  Or it
can halt with a message naming the version it needs, which is an outage the
operator can act on in one minute.

`HaltRequired` is that third option.  An outage you can diagnose is cheaper
than a fork you cannot see.
"""
from __future__ import annotations

#: The highest rule set this build knows how to produce and check.
PROTOCOL_VERSION = 1

#: What each version changed, for an operator reading a halt message.  A
#: version with no entry here is one this build has never heard of.
CHANGES = {
    1: "genesis: the rules parts one through nine describe",
    2: "reserved: nothing is scheduled into it yet",
    3: "reserved: nothing is scheduled into it yet",
}

#: Roughly a year of blocks at the shipped 19.749 s epoch, for reading the
#: heights below as dates.
BLOCKS_PER_YEAR = 1_596_840

#: Slots a launching chain reserves for rule changes it has not designed.
#:
#: This is the one part of review C2 that expires at genesis.  Activation
#: heights live in the genesis document, so — as this module's own docstring
#: puts it — "adding one later is a governance act that produces a new document
#: and, by construction, a new chain; scheduling one in advance is just a
#: number."  A chain that discovers it needs a rule change and has nowhere to
#: put one has to migrate instead of upgrade.  Partitioned finality, the only
#: design that removes the supreme grid from the critical path, is exactly such
#: a change (docs/supreme_tier_design.md §8).
#:
#: Read it as a deadline rather than an option, because that is what it is: a
#: node that reaches an activation height for a version it does not implement
#: **halts**, correctly.  The escape hatch is shipping the version as "no rule
#: changes" if the slot arrives unused, which is cheap; the alternative — a
#: chain with nowhere to put an upgrade — is not.
RESERVED_SLOTS = {2: BLOCKS_PER_YEAR, 3: 3 * BLOCKS_PER_YEAR}


def next_activation(height: int, activations):
    """(version, height) of the next rule change after `height`, or None."""
    for version, at in sorted(normalise(activations).items()):
        if at > height:
            return version, at
    return None


class ProtocolError(Exception):
    """A block whose claimed rule set is not the one its height calls for."""


class HaltRequired(Exception):
    """This build cannot follow the chain past here, and must not pretend to.

    Raised rather than returned because there is no sensible way to continue:
    every caller that catches this should stop the node, not skip the block.
    """

    def __init__(self, height: int, needs: int, have: int = PROTOCOL_VERSION):
        self.height, self.needs, self.have = height, needs, have
        super().__init__(
            f"height {height:,} runs protocol {needs}; this build implements "
            f"{have}. Upgrade before continuing — applying this block under "
            f"the rules this build knows would fork the chain silently, which "
            f"is the one outcome worse than stopping.")


def normalise(activations) -> dict:
    """{version: height}, validated.  Raises ProtocolError on anything odd.

    Accepts the string keys a JSON round-trip produces, because the genesis
    document is written by hand as often as by code and a schedule that means
    one thing in Python and another in a file is a fork waiting for a date.
    """
    out = {}
    for version, height in dict(activations or {}).items():
        try:
            version, height = int(version), int(height)
        except (TypeError, ValueError):
            raise ProtocolError(
                f"activation {version!r}: {height!r} is not a number") from None
        if version <= 1:
            raise ProtocolError(
                f"version {version} cannot be activated: 1 is what a chain "
                f"starts under, and there is nothing before it")
        if height < 1:
            raise ProtocolError(f"version {version} activates at height "
                                f"{height}, before the chain exists")
        if version in out:
            raise ProtocolError(f"version {version} is activated twice")
        out[version] = height
    heights = [out[v] for v in sorted(out)]
    if any(b <= a for a, b in zip(heights, heights[1:])):
        raise ProtocolError("activation heights must increase with the "
                            "version: a later rule set cannot take effect "
                            "before an earlier one")
    return out


def canonical(activations) -> dict:
    """The schedule as the document encodes it.  Never raises.

    Serialising and validating are different jobs, and conflating them meant a
    document with a nonsense schedule raised out of `body()` — so `verify()`,
    whose entire purpose is to *report* that, could not reach its own check.
    A canonical form has to exist for anything the document might hold,
    including the things it should not.
    """
    out = {}
    for version, height in dict(activations or {}).items():
        try:
            out[str(int(version))] = int(height)
        except (TypeError, ValueError):
            out[str(version)] = height
    return dict(sorted(out.items(), key=lambda kv: (len(kv[0]), kv[0])))


def expected_version(height: int, activations) -> int:
    """The rule set a block at `height` must have been produced under."""
    active = 1
    for version, at in sorted(normalise(activations).items()):
        if height >= at:
            active = version
    return active


def check(height: int, claimed, activations):
    """(ok, reason) for a header's claimed version.  Never raises.

    Refuses a block that claims rules its height does not call for — in either
    direction.  Claiming an *older* rule set matters as much as claiming a
    newer one: it is exactly what an un-upgraded producer would do.
    """
    try:
        want = expected_version(height, activations)
    except ProtocolError as exc:
        return False, f"the activation schedule is invalid: {exc}"
    if not isinstance(claimed, int):
        return False, f"protocol {claimed!r} is not a version"
    if claimed != want:
        return False, (f"height {height} runs protocol {want}, the block "
                       f"claims {claimed}")
    return True, "ok"


def require(height: int, activations):
    """The version needed at `height`, or `HaltRequired` if this build lacks it.

    Called before a node applies a block, not after: the halt has to happen
    while the state is still one this build produced.
    """
    want = expected_version(height, activations)
    if want > PROTOCOL_VERSION:
        raise HaltRequired(height, want)
    return want


def readiness(height: int, activations) -> dict:
    """What an operator needs to see before an upgrade bites.

    `net status` reports this so the answer to "are we ready?" is a number of
    blocks rather than a conversation.
    """
    schedule = normalise(activations)
    pending = sorted((v, at) for v, at in schedule.items() if at > height)
    ahead = [(v, at, at - height) for v, at in pending]
    unknown = [(v, at) for v, at in schedule.items() if v > PROTOCOL_VERSION]
    return {
        "running": expected_version(height, schedule),
        "implements": PROTOCOL_VERSION,
        "next": ahead[0] if ahead else None,
        "blocks_to_next": ahead[0][2] if ahead else None,
        # The row that matters: a scheduled version this build cannot run.
        "unimplemented": sorted(unknown),
        "ready": not any(v > PROTOCOL_VERSION for v, _ in pending),
    }
