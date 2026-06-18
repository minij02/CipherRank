#!/usr/bin/env python3
"""
Stage B sweep runner + R8'' sybil regression.

4-way comparison across binaries on different branches:
  main:   /Users/minij02/CipherRank-main/build/CipherRank
  A1:     /Users/minij02/CipherRank-a1/build/CipherRank   (bgsg + H-2)
  A2:     /Users/minij02/CipherRank-sparse/build/CipherRank
  B:      /Users/minij02/CipherRank/build/CipherRank      (current branch: feat/bgsg-sparse-integrated)

The B binary also covers B-C2 (β₁=β₂=1, thr=0) via CLI flags.

Outputs JSON results so we can re-aggregate without re-running.
"""

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BINS = {
    "main":   "/Users/minij02/CipherRank-main/build/CipherRank",
    "A1":     "/Users/minij02/CipherRank-a1/build/CipherRank",
    "A2":     "/Users/minij02/CipherRank-sparse/build/CipherRank",
    "B":      "/Users/minij02/CipherRank/build/CipherRank",
    "B-C2":   "/Users/minij02/CipherRank/build/CipherRank",   # same binary, different flags
}

# B and B-C2 need to run from a cwd where ../soc-sign-bitcoinotc.csv resolves.
CWDS = {
    "main": "/Users/minij02/CipherRank-main/build",
    "A1":   "/Users/minij02/CipherRank-a1/build",
    "A2":   "/Users/minij02/CipherRank-sparse/build",
    "B":    "/Users/minij02/CipherRank/build",
    "B-C2": "/Users/minij02/CipherRank/build",
}

EXTRA_FLAGS = {
    "B-C2": ["-b1", "1.0", "-b2", "1.0", "-thr", "0"],
}

# Per-mode CSV path (synthetic sybil dataset injection).
# Updated in main() when --csv passed; here we keep defaults.
CSV_PATHS = {}

PHASE_RE = re.compile(r"\[Timer\] (?P<phase>.+?) Completed : (?P<t>[0-9.eE+-]+) sec")
INIT_RE  = re.compile(r"\[Timer\] Initialize FHE : (?P<t>[0-9.eE+-]+) sec")
TOTAL_RE = re.compile(r"\[Total Timer\] Total Pipeline Completed : (?P<t>[0-9.eE+-]+) sec")
WALLET_RE = re.compile(r"Target Wallet ID : (?P<wid>\d+)")
SCORE_RE  = re.compile(r"FHE Engine Score : (?P<s>[0-9.eE+-]+)")
APPROVED_RE = re.compile(r"\[APPROVED\]")
REJECTED_RE = re.compile(r"\[REJECTED\]")
OUTRANGE_RE = re.compile(r"Wallet ID (?P<wid>\d+) is out of range")


def run_once(mode, n_global, n_sub, targets, omp_threads=4, csv_path=None):
    bin_path = BINS[mode]
    cwd = CWDS[mode]
    args = [bin_path, "-g", str(n_global), "-s", str(n_sub)]
    args.extend(EXTRA_FLAGS.get(mode, []))
    # Only the B / B-C2 binary (this branch) supports -csv; others stay on default.
    if csv_path and mode in ("B", "B-C2"):
        args.extend(["-csv", csv_path])
    args.extend(str(t) for t in targets)
    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = str(omp_threads)
    proc = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    out = proc.stdout
    res = {
        "mode": mode, "n_global": n_global, "n_sub": n_sub,
        "targets_requested": list(targets),
        "omp_threads": omp_threads,
        "phases": {}, "verdicts": [], "scores": {}, "out_of_range": [],
        "returncode": proc.returncode,
    }
    m = INIT_RE.search(out)
    if m: res["phases"]["init"] = float(m.group("t"))
    for m in PHASE_RE.finditer(out):
        res["phases"][m.group("phase").strip()] = float(m.group("t"))
    m = TOTAL_RE.search(out)
    if m: res["phases"]["total"] = float(m.group("t"))
    for m in OUTRANGE_RE.finditer(out):
        res["out_of_range"].append(int(m.group("wid")))

    # Parse verdict lines per target
    blocks = out.split("Target Wallet ID :")
    for blk in blocks[1:]:
        wid_m = re.match(r"\s*(\d+)", blk)
        score_m = SCORE_RE.search(blk)
        appr = APPROVED_RE.search(blk)
        rej  = REJECTED_RE.search(blk)
        if wid_m and score_m:
            wid = int(wid_m.group(1))
            res["scores"][wid] = float(score_m.group("s"))
            verdict = "APPROVED" if appr else ("REJECTED" if rej else "UNKNOWN")
            res["verdicts"].append({"wid": wid, "verdict": verdict})
    return res


def run_sweep_cell(modes, n_global, n_sub, targets, reps, omp_threads=4,
                   csv_path=None, extra_flags_per_mode=None):
    cells = []
    for mode in modes:
        for rep in range(reps):
            print(f"  [{mode}] N={n_global},s={n_sub},OMP={omp_threads},rep={rep+1}/{reps}",
                  flush=True)
            try:
                res = run_once(mode, n_global, n_sub, targets, omp_threads, csv_path=csv_path)
                if extra_flags_per_mode and mode in extra_flags_per_mode:
                    res["extra_config"] = extra_flags_per_mode[mode]
                cells.append(res)
            except Exception as e:
                print(f"    ERROR {mode}: {e}", flush=True)
                cells.append({"mode": mode, "error": str(e),
                              "n_global": n_global, "n_sub": n_sub,
                              "targets_requested": list(targets)})
    return cells


def bootstrap_ci(values, n_resample=2000, alpha=0.05, seed=42):
    """Return (median, lower, upper) at 1-alpha confidence."""
    import random as _r
    if not values: return (None, None, None)
    rng = _r.Random(seed)
    n = len(values)
    medians = []
    for _ in range(n_resample):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        medians.append(statistics.median(sample))
    medians.sort()
    lo = medians[int(n_resample * alpha / 2)]
    hi = medians[int(n_resample * (1 - alpha / 2))]
    return (statistics.median(values), lo, hi)


def summarize_cells(cells, metric="total"):
    by_mode = defaultdict(list)
    for c in cells:
        if "phases" in c and metric in c["phases"]:
            by_mode[c["mode"]].append(c["phases"][metric])
    summary = {}
    for mode, vals in by_mode.items():
        summary[mode] = {
            "median": statistics.median(vals) if vals else None,
            "min": min(vals) if vals else None,
            "max": max(vals) if vals else None,
            "n": len(vals),
        }
    return summary


def compute_verdict_table(cells, sybil_set, trusted_set):
    """Return per-mode {sybil_rej_rate (TPR), trusted_rej_rate (FPR)}."""
    by_mode = defaultdict(lambda: {"sybil_rej": 0, "sybil_total": 0,
                                    "trusted_rej": 0, "trusted_total": 0})
    for c in cells:
        if "verdicts" not in c: continue
        for v in c["verdicts"]:
            wid = v["wid"]
            row = by_mode[c["mode"]]
            is_sybil   = wid in sybil_set
            is_trusted = wid in trusted_set
            if is_sybil:
                row["sybil_total"] += 1
                if v["verdict"] == "REJECTED": row["sybil_rej"] += 1
            if is_trusted:
                row["trusted_total"] += 1
                if v["verdict"] == "REJECTED": row["trusted_rej"] += 1
    table = {}
    for mode, row in by_mode.items():
        st = row["sybil_total"] or 1
        tt = row["trusted_total"] or 1
        table[mode] = {
            "TPR_sybil_rejected": row["sybil_rej"] / st,
            "FPR_trusted_rejected": row["trusted_rej"] / tt,
            "n_sybil": row["sybil_total"], "n_trusted": row["trusted_total"],
        }
    return table


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="JSON result file")
    parser.add_argument("--coarse", action="store_true", help="Run coarse 4-way sweep")
    parser.add_argument("--sybil",  action="store_true", help="Run R8'' sybil regression")
    parser.add_argument("--demo",   action="store_true", help="Run nGlobal=4096 demo cell")
    parser.add_argument("--omp-axis", action="store_true", help="Run OMP axis sweep on B")
    parser.add_argument("--synthetic-sybil", action="store_true",
                        help="Run R8'' against synthetic-sybil CSV (B and B-C2)")
    parser.add_argument("--csv", default=None, help="Override CSV path for B/B-C2")
    parser.add_argument("--fine-grid", action="store_true",
                        help="3x3 beta2 x threshold grid sweep on B at nGlobal=1024")
    parser.add_argument("--n2048", action="store_true",
                        help="A1 + B at nGlobal=2048")
    parser.add_argument("--big-n", action="store_true",
                        help="N=10 supplement on B at nGlobal=1024 (95% bootstrap CI)")
    parser.add_argument("--reps", type=int, default=3)
    args = parser.parse_args()

    results = {"meta": {"reps": args.reps}, "cells": []}

    # ---- Coarse 4-way sweep ----
    if args.coarse:
        # Targets from the spec smoke-tests; keep small to bound run time.
        targets_256 = [1, 2, 4, 35]
        targets_1024 = [1, 2, 4, 35, 25, 7, 88, 100, 200]
        print("== Coarse 4-way: nGlobal=256 ==")
        results["cells"].extend(
            run_sweep_cell(["main", "A1", "A2", "B"], 256, 64, targets_256, args.reps))
        print("== Coarse 4-way: nGlobal=1024 multi-chunk ==")
        results["cells"].extend(
            run_sweep_cell(["main", "A1", "A2", "B"], 1024, 256, targets_1024, args.reps))

    # ---- nGlobal=4096 demo ----
    if args.demo:
        targets_4096 = [1, 2, 4, 35, 25, 7, 88, 100, 200]
        print("== Demo nGlobal=4096: A1, B (main impractical) ==")
        # A1 4096 may take minutes
        results["cells"].extend(
            run_sweep_cell(["A1", "B"], 4096, 256, targets_4096, args.reps))

    # ---- OMP axis on B ----
    if args.omp_axis:
        targets = [1, 2, 4, 35, 25, 7, 88, 100, 200]
        for p in (1, 2, 4, 8):
            print(f"== OMP axis: B, OMP={p} ==")
            results["cells"].extend(
                run_sweep_cell(["B"], 1024, 256, targets, args.reps, omp_threads=p))

    # ---- R8'' sybil regression ----
    if args.sybil:
        # Identified separately:
        sybil  = [984, 3498, 4531, 3760, 3744, 4666, 906, 4661, 3759]
        trusted= [2642, 35, 1, 7, 4172, 1018, 2125, 4197, 4291]
        targets = sybil + trusted  # mixed batch (one chunk if fits, else multi-chunk)
        sybil_set, trusted_set = set(sybil), set(trusted)
        print(f"== R8'' sybil regression: 9 sybil + 9 trusted, nGlobal=1024 ==")
        cells = run_sweep_cell(["main", "A1", "A2", "B", "B-C2"], 1024, 256, targets, args.reps)
        results["cells"].extend(cells)
        results["sybil"] = {
            "sybil_targets": sybil, "trusted_targets": trusted,
            "verdict_table": compute_verdict_table(cells, sybil_set, trusted_set),
        }

    # ---- Synthetic sybil R8'' (B + B-C2 only — uses -csv flag) ----
    if args.synthetic_sybil:
        sybil = list(range(9000, 9050))
        targets = sybil  # 50 sybil targets, no trusted (FPR not measurable here)
        sybil_set, trusted_set = set(sybil), set()
        print("== R8'' synthetic sybil (50 sybils, B vs B-C2) ==")
        csv_path = args.csv or "../soc-sign-bitcoinotc-synthetic.csv"
        cells = run_sweep_cell(["B", "B-C2"], 1024, 256, targets, args.reps, csv_path=csv_path)
        results["cells"].extend(cells)
        results["synthetic_sybil"] = {
            "sybil_targets": sybil,
            "verdict_table": compute_verdict_table(cells, sybil_set, trusted_set),
        }

    # ---- Fine beta2 x threshold grid on B ----
    if args.fine_grid:
        targets = [1, 2, 4, 35, 25, 7, 88, 100, 200]
        grid_b2 = [0.0, 0.30, 1.0]
        grid_thr = [0.0, 0.05, 0.5]
        for b2 in grid_b2:
            for thr in grid_thr:
                tag = f"B_b2={b2}_thr={thr}"
                print(f"== Fine grid: {tag} ==")
                # Use the B binary but with custom flags
                BINS[tag] = BINS["B"]; CWDS[tag] = CWDS["B"]
                EXTRA_FLAGS[tag] = ["-b1", "1.0", "-b2", str(b2), "-thr", str(thr)]
                results["cells"].extend(
                    run_sweep_cell([tag], 1024, 256, targets, args.reps))

    # ---- nGlobal=2048 cell ----
    if args.n2048:
        targets = [1, 2, 4, 35, 25, 7, 88, 100, 200]
        print("== nGlobal=2048 (A1 + B; main and A2 deferred) ==")
        results["cells"].extend(
            run_sweep_cell(["A1", "B"], 2048, 256, targets, args.reps))

    # ---- B at N=10 (95% bootstrap CI) ----
    if args.big_n:
        targets = [1, 2, 4, 35, 25, 7, 88, 100, 200]
        print("== B big-N at nGlobal=1024 multi-chunk (N=10) ==")
        results["cells"].extend(
            run_sweep_cell(["B"], 1024, 256, targets, 10))

    # ---- Save ----
    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\nSaved results to {args.out}")

    # ---- Print summary ----
    print("\n=== Wall-clock summary ===")
    by_cfg = defaultdict(list)
    for c in results["cells"]:
        key = (c.get("n_global"), c.get("n_sub"), c.get("omp_threads"))
        by_cfg[key].append(c)
    for key, cells in sorted(by_cfg.items()):
        ng, ns, omp = key
        if ng is None: continue
        print(f"\nnGlobal={ng}, nSub={ns}, OMP={omp}")
        by_mode = defaultdict(list)
        for c in cells:
            if "phases" in c and "total" in c["phases"]:
                by_mode[c["mode"]].append(c["phases"]["total"])
        for mode in sorted(by_mode.keys()):
            vals = by_mode[mode]
            med, lo, hi = bootstrap_ci(vals)
            n = len(vals)
            print(f"  {mode:25s}  median={med:.3f}s  95% CI=[{lo:.3f}, {hi:.3f}]  (n={n})")

    if "sybil" in results:
        print("\n=== R8'' Natural-sybil verdict table ===")
        for mode, row in results["sybil"]["verdict_table"].items():
            print(f"  {mode:8s}  TPR={row['TPR_sybil_rejected']:.2f}  "
                  f"FPR={row['FPR_trusted_rejected']:.2f}  "
                  f"(n_sybil={row['n_sybil']}, n_trusted={row['n_trusted']})")
    if "synthetic_sybil" in results:
        print("\n=== R8'' Synthetic-sybil verdict table ===")
        for mode, row in results["synthetic_sybil"]["verdict_table"].items():
            print(f"  {mode:8s}  TPR={row['TPR_sybil_rejected']:.2f}  "
                  f"(n_sybil={row['n_sybil']})")


if __name__ == "__main__":
    main()
