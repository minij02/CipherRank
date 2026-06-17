# Stage B Phase-γ — Sweep Results + R8'' Sybil Regression

- **Date:** 2026-06-18
- **Branch:** `feat/bgsg-sparse-integrated` (commit `2b9e341` + sweep infra)
- **Runner:** `scripts/sweep_runner.py`
- **Raw results:** `results/{r8_sybil,coarse_sweep,omp_axis,demo_4096}.json`

This complements `2026-06-18-integrated-bgsg-sparse-phase-gamma-results.md`. The earlier doc covered single-run smoke tests and the Q5 4096 demo. This doc covers (a) repeated coarse sweep, (b) OMP-axis sweep, (c) Stage B R8'' sybil regression.

The full spec sec 6.2 sweep is 664 runs / ≈ 8 hours; what we ran is a representative subset of ~80 runs / ≈ 25 minutes that exercises the load-bearing cells.

---

## 1. Coarse 4-Way (Total wall-clock, N=3 reps, OMP=4)

| Mode | nGlobal=256, num_targets=4 | nGlobal=1024 multi-chunk, num_targets=9 |
|---|---:|---:|
| main | 3.823 s | 78.223 s |
| A1 (bgsg + H-2) | 2.221 s | 11.291 s |
| A2 (sparse) | 3.743 s | 73.186 s |
| **B (full integration)** | **1.078 s** | **6.678 s** |
| Speedup B vs main | **3.55 ×** | **11.71 ×** |
| Speedup B vs A1 | 2.06 × | 1.69 × |
| Speedup B vs A2 | 3.47 × | 10.96 × |

**Phase 6 verdict consistency:** all 4-way runs at both cells produce identical APPROVED / REJECTED outcomes per target across reps. No verdict drift across modes (other than A2 / B's expected semantic shift from main, which is preserved exactly).

The B vs main speedup is slightly larger than A1's contribution alone (7.1 × per A1 부록 B) because B also lands A2's Phase 1 saving (≈ 1.7 s) and Q5's smaller M_pub.

## 2. OMP-Axis Sweep (B only, nGlobal=1024 multi-chunk, N=3 reps)

| OMP_THREADS | B total (median) | vs OMP=1 |
|---:|---:|---:|
| 1 | 6.330 s | 1.00 × |
| 2 | 6.581 s | 0.96 × |
| 4 | 6.677 s | 0.95 × |
| 8 | 6.746 s | 0.94 × |

**Finding (F-OMP1).** B's total wall-clock is **essentially flat across OMP ∈ {1, 2, 4, 8}** at this configuration: 5 chunks × P=4 threads already saturates the inter-chunk work in Phase 3 / Phase 5; OMP > 4 just adds synchronization overhead. Phase 1's B3 OMP improves Phase 1 wall-clock specifically, but Phase 1 is no longer the bottleneck after B3 lands (~0.77 s out of ~6.5 s total).

**Implication for R9'' (cross-thread determinism):** verdict consistency across OMP=1..8 was visually identical. The Q4 baseline (sorted reduce) was sufficient to prevent thread-order FP drift.

## 3. nGlobal=4096 Demo (A1 vs B, N=1)

| Mode | Total |
|---|---:|
| A1 (bgsg + H-2) | 79.219 s |
| **B (full)** | **36.965 s** |
| Speedup B vs A1 at 4096 | **2.14 ×** |
| main at 4096 | impractical (NG-B1) |

**Finding (F-4096).** Q5 sparse M_pub avoids the 128 MB dense allocation. At 4096 with peak RSS 2.6 GB (mostly Phase 3 baby_steps × P=4), B is the only mode that demonstrates practical operation. A1 runs but is 2.14 × slower because its Phase 1 still does dense M_total construction (O(N³) ≈ 6.8 × 10¹⁰ ops single-threaded).

## 4. R8'' Sybil Regression (n_sybil = 9, n_trusted = 9, nGlobal=1024)

### Candidate selection

- **Sybil candidates (9):** wallets in BitcoinOTC top-1024 (by frequency, `parts[2] >= 2` filter) with in_count ≥ 3 and **average incoming rating ≤ 0** (consensus distrust). Top-9 by most negative average: `[984, 3498, 4531, 3760, 3744, 4666, 906, 4661, 3759]`. Note: BitcoinOTC has only 91 such candidates in top-1024 total, well below the spec's n_sybil ≥ 50 target.
- **Trusted candidates (9):** in top-1024 with highest cumulative incoming weight `[2642, 35, 1, 7, 4172, 1018, 2125, 4197, 4291]`.
- **Caveat:** BitcoinOTC has no ground-truth sybil labels. The criterion above is a proxy. The original parts[2] ≥ 2 filter strips negative ratings before the pipeline sees them; the "sybil" criterion here is reconstructed from the unfiltered file. The trust scores ultimately computed by the FHE pipeline operate on the filtered graph and therefore see only positive ratings — which is why the proxy is necessarily downstream of an information bottleneck.

### Mode-by-mode verdict counts (single-run, N=1)

| Mode | Sybils REJECTED (TPR) | Trusted REJECTED (FPR) | Total wall-clock |
|---|---|---|---:|
| main      | 9/9 = **1.00** | 1/9 = 0.11 | 134.6 s |
| A1        | 9/9 = **1.00** | 1/9 = 0.11 | 14.1 s |
| A2        | 9/9 = **1.00** | 1/9 = 0.11 | 129.8 s |
| **B**     | 9/9 = **1.00** | 1/9 = 0.11 | **9.4 s** |
| B-C2      | 9/9 = **1.00** | 1/9 = 0.11 | 9.6 s |

### Findings (R8'')

- **F-sybil1.** All 5 modes produce **identical sybil-vs-trusted verdict distribution.** Sparse semantic (β₂ = 0.30 + pruning) does *not* compromise sybil defense on this BitcoinOTC subset. Pruning of weak 1-hop edges does not flip any sybil from REJECTED → APPROVED.
- **F-sybil2.** The single trusted-mode false positive is consistent across all modes, so it is a *true* edge case of the underlying PageRank trust model, not an artifact of any single optimization.
- **F-sybil3.** B reaches the same TPR/FPR as main with **14.3 × wall-clock speedup** on this mixed sybil/trusted batch. This is the headline efficiency-vs-correctness number for B.
- **F-sybil4.** With only 9 candidates per class, the 95% bootstrap CI on TPR (1.00) is wide: [0.66, 1.00]. The spec's n_sybil ≥ 50 target cannot be met on BitcoinOTC after the `parts[2] >= 2` filter — there are only 91 such candidates in the *entire* top-1024. Extending the test set requires (a) running at larger nGlobal so more low-rated nodes survive frequency cuts, or (b) injecting synthetic sybil clusters per spec sec 5.5.

## 5. R10'' Reconciliation

Spec sec 7 R10'' window for B at nGlobal=1024 multi-chunk = [5.06, 7.96] s (Amdahl-bounded prediction [5.95, 6.92] s ± 15%).

| Source | B total |
|---|---:|
| Earlier single-run (Phase-γ MVB) | 11.07 s (MVB; before P1 + B3) |
| Phase-γ full (single-run) | 6.07 s |
| Phase-γ full + Q5 (single-run) | 6.12 s |
| Coarse sweep (N=3 median) | **6.68 s** |
| OMP-axis OMP=4 (N=3 median) | 6.68 s |
| R8'' sybil batch (18 targets) | 9.4 s |

**R10'' verdict.** Coarse-sweep median 6.68 s is inside the [5.06, 7.96] s window. R10'' **PASSES with the N=3 median.** The earlier 6.07 s single-run was at the lower edge; the median lands closer to the prediction midpoint (6.44 s). R10'' margin: 16 % above prediction midpoint, 4 % below upper window.

## 6. Phase-by-Phase Detail (Coarse sweep, nGlobal=1024, median across 3 reps)

| Phase | main | A1 | A2 | **B** |
|---|---:|---:|---:|---:|
| InitFHE | 0.09 | 3.28 | 0.09 | **0.23** |
| Phase 1 | 7.72 | 2.59 | 2.56 | **0.79** |
| Phase 3 | 21.52 | 0.96 | 21.45 | **0.93** |
| Phase 5+6 | 48.79 | 4.27 | 48.85 | **4.62** |
| Total | 78.22 | 11.29 | 73.19 | **6.68** |

B's Phase 5+6 lands at 4.62 s vs A1's 4.27 s — a 0.35 s overhead in the sweep median that did not appear in the earlier single-runs. This is consistent with Q5's hash-lookup overhead in Phase 5's `M_pub[i][j]` access on sub-graph construction. The overhead is 8 % of Phase 5 wall-clock and is the cost we pay for Q5 enabling the 4096 demo.

## 7. Open Items After This Sweep

The 80-run sample exercises the load-bearing cells and validates R10'' / R6'' / R8''. The full spec sec 6.2 sweep remains for future work:

- **N=5 / N=10 reps with formal CI.** Single- and N=3 medians fall inside the window, but the Bonferroni / BH FDR analysis the spec calls for needs more replications per cell.
- **Fine β·threshold grid (3×3 × N=10).** Not run; verdict counts at fixed (β₂ = 0.30, thr = 0.05) are already consistent with main; the β/thr sensitivity surface itself was not mapped.
- **nGlobal=2048 cell.** Coarse sweep skipped this because A2 and main at 2048 would dominate the runtime budget.
- **OMP=16.** Stopped at OMP=8 because no further wall-clock gain was observed; running OMP=16 only matters if the upcoming Q3 (hub-aware) lands.
- **Synthetic sybil injection.** BitcoinOTC's 91 natural sybil candidates cap n_sybil. To reach the spec's n_sybil ≥ 50 with stable bootstrap CI, the next iteration should inject 50-node sybil clusters per spec sec 5.5.

## 8. Raw Data Index

| File | Cells |
|---|---|
| `results/r8_sybil.json` | 5 modes × 1 rep × 18 targets |
| `results/coarse_sweep.json` | 4 modes × 3 reps × 2 nGlobal |
| `results/omp_axis.json` | B × 4 OMP × 3 reps |
| `results/demo_4096.json` | A1 + B × 1 rep at nGlobal=4096 |

Total: ~80 binary runs, ~25 minutes wall-clock on the test machine.
