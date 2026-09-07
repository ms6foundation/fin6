"""Update cost vs. a full recommit -- informational, not a pass/fail check.

Kept out of the check modules deliberately: it reports a timing, and a timing
is not something a CI gate should fail on.
"""
import time

from harness import Commitment, D, mk  # noqa: F401


def run(check=None):
    U = Commitment([mk(i) for i in range(60)], D, chunk_size=20, batch_size=10)
    t0    = time.time(); U.replace(30, mk(30) ^ 0xABCDEF1234567); t_upd  = time.time() - t0
    t0    = time.time()
    Commitment(U.vals, D, chunk_size=20, batch_size=10, sys=U.sys)
    t_full = time.time() - t0
    print(f"  [info] {len(U.h_list)} batches: replace {t_upd * 1000:.1f} ms "
          f"vs full recommit {t_full * 1000:.1f} ms ({t_full / t_upd:.0f}x)")


if __name__ == "__main__":
    run()
