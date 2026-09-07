"""WOTS — Winternitz one-time signatures.

Hash-based, so post-quantum, and one-time in the strong sense that matters here:
signing two different messages with one key reveals enough of the private key to
forge with it.  That is normally a hazard to be engineered around.  In this
design it is the mechanism — a turn that stamps two competing blocks publishes
its own forgery material, so equivocation is self-punishing and needs no reporter.

Parameters (n = 32, winternitz = 16):
    len_1 = 64 message digits, len_2 = 3 checksum digits, len = 67 chains
    keygen  len * (winternitz - 1) = 1005 hashes
    sign/verify  ~500 hashes on average

Simplification worth naming: the standard WOTS+ chain applies per-step bitmasks
drawn from the public seed.  Here the seed and the step index are folded into the
hash input instead, which is the WOTS-T style construction — the same security
argument, less machinery.  A deployment should use a reviewed implementation
(RFC 8391's XMSS WOTS+) rather than this one.
"""
from __future__ import annotations

import hashlib

N = 32                      # bytes of hash output
WINTERNITZ = 16             # base
LOG_W = 4
LEN_1 = (8 * N) // LOG_W    # 64
LEN_2 = 3                   # floor(log2(LEN_1 * (WINTERNITZ-1)) / LOG_W) + 1
LEN = LEN_1 + LEN_2         # 67


def _h(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    for p in parts:
        d.update(len(p).to_bytes(4, "big"))
        d.update(p)
    return d.digest()


def prf(seed: bytes, *parts) -> bytes:
    encoded = [p if isinstance(p, bytes) else str(p).encode() for p in parts]
    return _h(b"fin6-prf", seed, *encoded)


def _chain(x: bytes, start: int, steps: int, pub_seed: bytes, addr: bytes) -> bytes:
    """Iterate the hash chain `steps` times from position `start`."""
    for i in range(start, start + steps):
        x = _h(b"fin6-wots-chain", pub_seed, addr, i.to_bytes(2, "big"), x)
    return x


def _digits(message: bytes) -> list:
    """Base-w digits of the message, followed by the checksum digits."""
    out = []
    for byte in message:
        out.append(byte >> 4)
        out.append(byte & 0x0F)
    out = out[:LEN_1]
    checksum = sum(WINTERNITZ - 1 - d for d in out)
    checksum <<= 4                                  # left-shift per RFC 8391
    csum_bytes = checksum.to_bytes(3, "big")
    csum_digits = []
    for byte in csum_bytes:
        csum_digits.append(byte >> 4)
        csum_digits.append(byte & 0x0F)
    return out + csum_digits[:LEN_2]


def secret_chains(master_seed: bytes, index: int) -> list:
    """The LEN private chain starts for one turn, derived from the master seed."""
    return [prf(master_seed, "sk", index, i) for i in range(LEN)]


def public_key(master_seed: bytes, pub_seed: bytes, index: int) -> bytes:
    """Compress a turn's LEN chain ends into one public value."""
    addr = index.to_bytes(4, "big")
    ends = [_chain(sk, 0, WINTERNITZ - 1, pub_seed, addr + i.to_bytes(2, "big"))
            for i, sk in enumerate(secret_chains(master_seed, index))]
    return _h(b"fin6-wots-pk", pub_seed, addr, *ends)


def sign(master_seed: bytes, pub_seed: bytes, index: int, message: bytes) -> bytes:
    """Spend the turn.  Doing this twice with different messages leaks the key."""
    addr = index.to_bytes(4, "big")
    sks = secret_chains(master_seed, index)
    parts = [_chain(sk, 0, d, pub_seed, addr + i.to_bytes(2, "big"))
             for i, (sk, d) in enumerate(zip(sks, _digits(message)))]
    return b"".join(parts)


def public_key_from_signature(signature: bytes, pub_seed: bytes, index: int,
                              message: bytes) -> bytes:
    """Recover the claimed public key — verification is a comparison against it."""
    if len(signature) != LEN * N:
        raise ValueError(f"signature is {len(signature)} bytes, expected {LEN * N}")
    addr = index.to_bytes(4, "big")
    ends = []
    for i, d in enumerate(_digits(message)):
        part = signature[i * N:(i + 1) * N]
        ends.append(_chain(part, d, WINTERNITZ - 1 - d, pub_seed,
                           addr + i.to_bytes(2, "big")))
    return _h(b"fin6-wots-pk", pub_seed, addr, *ends)


def verify(signature: bytes, pub_seed: bytes, index: int, message: bytes,
           expected_pk: bytes) -> bool:
    try:
        return public_key_from_signature(signature, pub_seed, index,
                                         message) == expected_pk
    except Exception:
        return False


SIGNATURE_BYTES = LEN * N
