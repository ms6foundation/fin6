"""DL-specific: unknown-order modulus forgery.

This test was specific to the discrete-log / RSA-modulus hardening.
The MQ refactor replaces that machinery.  Stub retained for suite stability."""
from harness import standalone


def run(check):
    check("forge unknown-order : N/A (DL/RSA machinery replaced by MQ)", True)


if __name__ == "__main__":
    standalone(run, "test_forge_unknownoder checks")
