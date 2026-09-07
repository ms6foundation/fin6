"""DL-specific: modulus / RSA parameter checks.

This test was specific to the DL/RSA modulus machinery.
The MQ refactor removes that machinery.  Stub retained for suite stability."""
from harness import standalone


def run(check):
    check("modulus : N/A (RSA/DL modulus replaced by MQ over F_P)", True)


if __name__ == "__main__":
    standalone(run, "test_modulus checks")
