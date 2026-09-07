"""DL-specific: row-scaling forgery against the g^hv fold.

This test was specific to the discrete-log hardening (DL/RSA/GQ machinery).
The MQ refactor replaces that machinery with an MQ commitment + SSH proof,
so this attack category no longer applies.  The suite runs this stub so the
test count stays stable; all checks are marked N/A."""
from harness import standalone


def run(check):
    check("forge hardened fold : N/A (DL machinery replaced by MQ)", True)


if __name__ == "__main__":
    standalone(run, "test_forge_hardened_fold checks")
