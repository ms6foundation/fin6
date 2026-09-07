"""Completeness sweep over the batch-level parallelism (workers>1) path.

Varies N / batch_size / chunk_size / d and the iset pattern, always with
workers>1 and multiple batches touched.

NOTE the __main__ guard and the run() wrapper are load-bearing, not style:
this sweep spawns process pools, and under the spawn start method (macOS,
Windows) each child re-imports this module.
"""
import sys

sys.set_int_max_str_digits(2_000_000)

from harness import ms6, ps6, vs6, standalone  # noqa: E402


def make_vals(n):
    return [(1720941241 + (i ** 70) ^ (i ** 99)) % 2 ** 200 for i in range(n)]


def run(check):
    configs = [
        # (N, batch_size, chunk_size, d, workers)
        (60,  10, 10, 2, 4),
        (50,  10, 10, 3, 4),
        (40,  10, 10, 2, 3),
        (48,  12, 20, 3, 4),
        (40,   8, 10, 2, 5),
    ]

    iset_patterns = [
        "single_batch_single_item",
        "single_batch_multi_item",
        "two_batches",
        "all_batches",
        "gaps_between_batches",
    ]

    total = 0
    passed = 0
    failed = []

    for (N, bs, cs, d, workers) in configs:
        vals = make_vals(N)
        n_batches = (N + bs - 1) // bs
        c, h_list, x_list, mq_sec, v_list, sys_, params = ms6(
            vals, d, chunk_size=cs, batch_size=bs)
        assert len(h_list) == n_batches

        for pattern in iset_patterns:
            if pattern == "single_batch_single_item":
                iset = [0]
            elif pattern == "single_batch_multi_item":
                iset = [0, 1, min(bs - 1, N - 1)]
            elif pattern == "two_batches":
                if n_batches < 2:
                    continue
                iset = [0, bs]
            elif pattern == "all_batches":
                iset = [min(b * bs, N - 1) for b in range(n_batches)]
            elif pattern == "gaps_between_batches":
                if n_batches < 3:
                    continue
                iset = [0, min(2 * bs, N - 1)]

            claims = {i: vals[i] for i in iset}
            total += 1
            try:
                ps_list = ps6(iset, h_list, mq_sec, v_list, sys_, params)
                ok = vs6(c, claims, ps_list, x_list, sys_, params)
                if ok:
                    passed += 1
                else:
                    failed.append((N, bs, cs, d, workers, pattern, "vs6 returned falsy"))
            except Exception as e:
                failed.append((N, bs, cs, d, workers, pattern, str(e)))

    check(f"completeness  : {passed}/{total} batch-routing configs verify",
          passed == total and not failed)
    for f in failed:
        print(f"      failure: {f}")


if __name__ == "__main__":
    standalone(run, "test_completeness checks")
