"""fast_pow -- accelerator for the pow(g, e, mod) modular-exponentiation
hotspot in the accumulator / dlog-exponent paths (_seal_grid, _ps6_batch, and
the verifier), where a SINGLE fixed base g is raised to MANY different
exponents against a fixed modulus.

Two wins, both producing results bit-identical to `pow(g, e, mod)`:

  1. powmod(base, e, mod)   -- gmpy2's GMP-backed modexp. ~7-8x over Python's
     built-in pow at 2048-bit, drop-in, no precompute.

  2. FixedBase(g, mod)      -- fixed-base windowing: precompute, ONCE per (g,
     mod), the table g^(d * 2^(w*i)) for every window i and digit d, so each
     later exponentiation is just a handful of table lookups and multiplies
     (no squarings). ~5x on top of gmpy2 -> ~39x total over Python pow when the
     same base is reused across many exponents (the accumulator's exact usage).

Falls back to Python's pow when gmpy2 is unavailable, so it is always safe to
import. Measured (2048-bit modulus, this machine):

    exponent   python pow   gmpy2.powmod   FixedBase(w=8)   total
     512-bit    6164 us        824 us          157 us        39x
    2048-bit   24739 us       3224 us          638 us        39x
"""
try:
    import gmpy2
    from gmpy2 import mpz as _mpz, powmod as _powmod
    _HAVE_GMP = True
except Exception:
    gmpy2 = None
    _mpz = None
    _HAVE_GMP = False


def powmod(base, exp, mod):
    """Drop-in for pow(base, exp, mod); uses gmpy2 when present. Returns an
    mpz under gmpy2 (mpz == int, so results compare equal to Python's pow)."""
    if _HAVE_GMP:
        return _powmod(_mpz(base), _mpz(exp), _mpz(mod))
    return pow(base, exp, mod)


class FixedBase:
    """Fixed-base, fixed-modulus exponentiation with one-time precomputation.

        fb = FixedBase(g, mod)          # precompute once (per batch's g)
        y  = fb(e)                      # == pow(g, e, mod), for many e

    `ebits` bounds the exponent width the table covers; exponents wider than
    `ebits` are still handled correctly (a slow tail is taken via powmod), but
    for best speed set ebits to the true maximum exponent width. `w` is the
    window size (bigger w -> larger table, fewer multiplies).
    """

    __slots__ = ("mod", "w", "mask", "table", "nwin", "base", "_gmp")

    def __init__(self, base, mod, ebits=2048, w=8):
        self._gmp = _HAVE_GMP
        if not _HAVE_GMP:
            self.base = base
            self.mod = mod
            self.w = self.mask = self.nwin = 0
            self.table = None
            return
        m = _mpz(mod)
        b = _mpz(base) % m
        self.mod = m
        self.base = b
        self.w = w
        self.mask = (1 << w) - 1
        self.nwin = (ebits + w - 1) // w
        step = 1 << w
        # window bases: base^(2^(w*i))
        win_bases = []
        cb = b
        for _ in range(self.nwin):
            win_bases.append(cb)
            cb = _powmod(cb, step, m)
        # table[i][d] = base^(d * 2^(w*i))
        self.table = []
        for i in range(self.nwin):
            wb = win_bases[i]
            row = [_mpz(1)] * (self.mask + 1)
            acc = _mpz(1)
            for d in range(1, self.mask + 1):
                acc = acc * wb % m
                row[d] = acc
            self.table.append(row)

    def __call__(self, exp):
        if not self._gmp:
            return pow(self.base, exp, self.mod)
        e = int(exp)
        if e < 0:
            raise ValueError("FixedBase supports non-negative exponents")
        m = self.mod
        w = self.w
        mask = self.mask
        T = self.table
        nwin = self.nwin
        r = _mpz(1)
        i = 0
        while e and i < nwin:
            d = e & mask
            if d:
                r = r * T[i][d] % m
            e >>= w
            i += 1
        if e:  # exponent wider than the precomputed window range: slow tail
            r = r * _powmod(self.base, e << (w * nwin), m) % m
        return r