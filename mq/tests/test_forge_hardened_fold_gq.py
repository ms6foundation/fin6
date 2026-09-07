"""DL-specific: GQ-hardened fold forgery attempts.

This test was specific to the GQ/DL hardening.  The MQ refactor removes
that machinery entirely.  Stub retained for suite stability."""
from harness import standalone


def run(check):
    check("forge hardened fold GQ : N/A (DL/GQ machinery replaced by MQ)", True)


if __name__ == "__main__":
    standalone(run, "test_forge_hardened_fold_gq checks")
