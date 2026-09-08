"""Entry point for one node process.   python3 -m chain.net.node_main DIR ID"""
from __future__ import annotations

import argparse
import signal

from .node import NodeProcess


def main():
    ap = argparse.ArgumentParser(prog="fin6-node")
    ap.add_argument("root")
    ap.add_argument("node_id")
    ap.add_argument("--until", type=int, default=None,
                    help="stop after this epoch")
    args = ap.parse_args()

    proc = NodeProcess(args.root, args.node_id, quiet=True)

    def bye(*_):
        proc.stop.set()

    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    proc.run(until_epoch=args.until)


if __name__ == "__main__":
    main()
