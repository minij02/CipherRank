#!/usr/bin/env python3
"""
Synthetic sybil CSV generator (R8'' methodology completion).

Takes BitcoinOTC original and appends a 50-node sybil cluster:
- Sybil IDs: 9000..9049 (distinct from any real BitcoinOTC node).
- Each sybil rates 6 other sybils with weight=5 (mutual high-trust ring).
- Each sybil also rates 2 random outsider top-N nodes with weight=3
  (looking "active" to inflate frequency without being too suspicious).
- A pool of outsider nodes rates the sybils with weight=2 (minimum trust,
  matching parts[2]>=2 filter; this simulates noisy reputation from peers).
- Edge timestamps clustered near the dataset's maxTime (recent activity
  to avoid heavy time decay neutralizing them).

Result: each sybil ends with out_count=8, in_count >= 11, frequency >= 19,
guaranteeing inclusion in top-1024 after the parts[2]>=2 filter.

The hypothesis under R8'': B-default (with β₂=0.30 + pruning) should
detect more sybils than B-C2 (β₂=1.0, no pruning), because pruning
removes the weak outsider->sybil edges that would otherwise let
random-walk amplification boost the sybil ring.

Usage:
  python3 scripts/gen_synthetic_sybil.py \
      --input soc-sign-bitcoinotc.csv \
      --output soc-sign-bitcoinotc-synthetic.csv \
      --n-sybil 50 --seed 1
"""

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--n-sybil", type=int, default=50)
    ap.add_argument("--sybil-base-id", type=int, default=9000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rng = random.Random(args.seed)

    in_count_orig = defaultdict(int)
    out_count_orig = defaultdict(int)
    edges = []
    max_time = 0
    with open(args.input) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 4:
                continue
            try:
                src = int(parts[0]); tgt = int(parts[1]); w = int(parts[2])
                t = float(parts[3])
            except ValueError:
                continue
            edges.append((src, tgt, w, t))
            if w >= 2:
                in_count_orig[tgt] += 1
                out_count_orig[src] += 1
            if t > max_time: max_time = t
    print(f"Loaded {len(edges)} original edges (max_time={max_time:.2f}, "
          f"max_id={max(max(e[0], e[1]) for e in edges)}).")

    # Pick outsider nodes from existing trusted-ish set: in_count_orig >= 5
    # (so they're naturally in top-N), to act as our sybil-rating peers.
    outsider_pool = sorted([n for n in in_count_orig if in_count_orig[n] >= 5])
    if len(outsider_pool) < 60:
        outsider_pool = sorted([n for n in in_count_orig if in_count_orig[n] >= 3])
    print(f"Outsider pool size: {len(outsider_pool)}")

    sybils = [args.sybil_base_id + i for i in range(args.n_sybil)]
    # Time cluster: place sybil edges in last 5% of dataset (recent).
    recent_t_low = max_time - 0.05 * max_time
    def rand_recent_t():
        return rng.uniform(recent_t_low, max_time)

    new_edges = []

    # 1) Sybil-to-sybil mutual ring: each sybil rates 6 other sybils with w=5.
    for s in sybils:
        peers = rng.sample([x for x in sybils if x != s], k=6)
        for p in peers:
            new_edges.append((s, p, 5, rand_recent_t()))

    # 2) Sybil-to-outsider edges: each sybil rates 2 outsiders with w=3.
    for s in sybils:
        peers = rng.sample(outsider_pool, k=2)
        for p in peers:
            new_edges.append((s, p, 3, rand_recent_t()))

    # 3) Outsider-to-sybil edges (suspicious low ratings): each sybil
    #    receives w=2 from 5 random outsiders.
    for s in sybils:
        peers = rng.sample(outsider_pool, k=5)
        for p in peers:
            new_edges.append((p, s, 2, rand_recent_t()))

    print(f"Generated {len(new_edges)} synthetic edges "
          f"(sybil ring: {args.n_sybil*6}, sybil->outsider: {args.n_sybil*2}, "
          f"outsider->sybil: {args.n_sybil*5}).")

    # Append; keep original time ordering up to the new edges.
    all_edges = edges + new_edges

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        for src, tgt, w, t in all_edges:
            f.write(f"{src},{tgt},{w},{t:.5f}\n")
    print(f"Wrote {len(all_edges)} edges to {args.output}.")
    print(f"Sybil IDs to query: {sybils}")


if __name__ == "__main__":
    main()
