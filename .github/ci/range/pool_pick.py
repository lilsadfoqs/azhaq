#!/usr/bin/env python3
"""pool_pick.py RUN_NUMBER [--seed WORD] [--sample N] [--pool POOL.json]:
prints the gate's pool seed for this run (rangelib.pick_pool_seed): --seed
fixes sample 1 when it names a pool entry (the tag's seed=WORD), otherwise
sample 1 is chosen round robin by RUN_NUMBER; --sample 2 (for `samples=2`)
prints the next pool entry, always a different estate from sample 1.
"""
import argparse
import sys

import rangelib


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_number")
    ap.add_argument("--seed", default=None, help="a tag's seed=WORD, when it names a pool entry")
    ap.add_argument("--sample", type=int, default=1, help="1 or 2, for the gate's samples=2")
    ap.add_argument("--pool", default=rangelib.POOL)
    a = ap.parse_args(argv)
    pool = rangelib.load_pool(a.pool)
    print(rangelib.pick_pool_seed(pool, a.run_number, a.seed, a.sample))
    return 0


if __name__ == "__main__":
    sys.exit(main())
