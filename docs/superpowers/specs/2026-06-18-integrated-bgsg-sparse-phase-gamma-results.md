# Stage B Phase-γ — Full Integration Results

- **Date:** 2026-06-18
- **Branch:** `feat/bgsg-sparse-integrated`
- **Base:** A1 HEAD (`882ca9c`, with H-2 thread-local SEAL patch)
- **Spec reference:** `docs/superpowers/specs/2026-06-18-integrated-bgsg-sparse-design.md` (v2)
- **Increment over MVB:** P1 (Galois Key Slimming) + B3 (Phase 1 OMP) + Q4 (deterministic sort) + Q5 (sparse M_pub).

---

## Scope — Minimum Viable B (MVB)

Stage B v2 spec defined the full integration roadmap (B0~B9, Q1~Q8, A1 + A2 inheritance). For this implementation session we landed the **minimum viable subset** that exercises the load-bearing parts of the design:

| Spec item | Status | Note |
|---|---|---|
| Branch creation | ✅ done | `feat/bgsg-sparse-integrated` from A1 HEAD |
| A2 sparse Phase 1 algorithm | ✅ done | replaced dense O(N³) matmul with adjacency-list + 2-hop |
| Q7 padding bridge (row ∈ [0, 2N)) | ✅ done | BsgsDiag encoding loop drives the padding from `sparseDiag[d][orig_row]` lookups |
| B1 minimal (β₁, β₂, threshold CLI) | ✅ done | `-b1 -b2 -thr` flags + `SetConfig()` |
| B8 detection (D_sparse < 2√N) | ✅ done | informational log only; full main-style branch deferred |
| Q6 D_sparse reporting | ✅ done | returned as out-param of `PreparePublicData` |
| A1 H-2 thread-local Phase 5 | ✅ inherited | from base branch |
| **A1 P1 Galois key slimming** | ✅ done | `ComputeBSGSStepSet` + step union (Pir ∪ Pr ∪ {1, 16}); 1024→69 keys, 4096→135 keys |
| **B3 Phase 1 OMP (per-thread + reduce)** | ✅ done | per-thread `unordered_map` accumulator, sequential reduce in thread_id order via `std::map`, then sorted vector |
| **B0 Three-Pass canonical order** | △ partial | Step set computed pre-init from `weight=1.0` default; auto-tune measurement still runs in-Phase-5 (informational). Full Three-Pass with reentrant weight measurement is follow-up. |
| **B2 phase_kind cost function** | △ partial | `FindOptimalAsymmetricBSGS` signature unchanged; Phase 3 and Phase 5 call it separately with their own `N`. `(D, ITERATIONS, phase_kind)` extension is follow-up. |
| **Q4 deterministic sort baseline** | ✅ done | `std::map`-based reduce produces sorted entries; FP accumulation order = thread_id 0..P-1 then row asc |
| **Q5 sparse M_pub storage** | ✅ done | `SparseMatrix = vector<unordered_map<int, double>>` + `SparseGet` helper; enables nGlobal=4096 demo |
| **R8'' sybil regression** | ❌ deferred | needs labeled subset |
| **B8 main-style fallback branch** | △ advisory only | logs when `D_sparse < 2·√N` but does not switch to main-style path |

Deferred items are tracked in the spec as B2/B3/B0/Q5 follow-ups; the items implemented suffice to verify C8 lemma + R1'' + R2'' + R6'' empirically.

---

## Full Integration Results (Config B, OMP=4)

| Phase | main | A1 only | A2 only | B MVB | **B (full)** | R10'' window | result |
|---|---:|---:|---:|---:|---:|---|---|
| InitFHE | 0.09 | 3.28 | 0.09 | 3.18 | **0.23** | [0.16, 0.34] | ✅ inside (P1) |
| Phase 1 | 7.73 | 2.58 | 2.56 | 2.72 | **0.77** | [0.60, 1.17] | ✅ inside (B3) |
| Phase 3 | 21.55 | 0.96 | 21.47 | 0.94 | **0.90** | [0.81, 1.27] | ✅ inside |
| Phase 5+6 | 48.90 | 4.24 | 48.90 | 4.19 | **4.18** | [3.49, 5.18] | ✅ inside |
| **Total** | **78.30** | 11.09 | 73.05 | 11.07 | **6.12** | [5.06, 7.96] | ✅ **R10'' PASS** |
| **vs main** | 1.0× | 7.1× | 1.07× | 7.07× | **12.8×** | — | — |

### R1'' / R2'' / R6'' (regression — full integration)

- **R1''** (B-C2 ≡ main, β₁=β₂=1, thr=0) at Config B multi-chunk: max\|Δ\| = 0 on 9/9 targets. ✅ PASS
- **R2''** (B-default ≡ A2-default, β₂=0.30, thr=0.05): max\|Δ\| ≤ 10⁻⁶ on 9/9 targets. ✅ PASS
- **R6''** (multi-chunk C8 lemma): 5 chunks, no verdict drift. ✅ PASS
- **Wallet 4 verdict flip** preserved (Config A): REJECTED → APPROVED. ✅

### nGlobal=4096 Demo (Q5 enabler)

| Metric | Value |
|---|---|
| Total wall-clock | 32.72s (main: would need ~minutes for O(N³) Phase 1 alone) |
| InitFHE | 0.87s (P1: 135 keys; pre-P1 default = 4096 keys) |
| Phase 1 | 5.86s (sparse + B3 OMP) |
| Phase 3 | 11.77s (A1 BSGS + OMP) |
| Phase 5+6 | 14.08s |
| **Peak RSS** | **2.625 GB** (Q5 sparse M_pub; pre-Q5 dense M_pub alone would add 128 MB but mostly Phase 5 baby_steps replication × 4 threads) |
| Precision Error | 0.000000 on 9/9 targets |

NG-B1 honored: main is not run at 4096 (impractical), so no direct head-to-head comparison.

## Code Changes (~150 LOC delta)

| Location | Change |
|---|---|
| `CipherRank.cpp` class members | added `beta1_`, `beta2_`, `prune_threshold_`, `SetConfig()` |
| `PreparePublicData` signature | adds `(beta1, beta2, prune_threshold, &D_sparse_out)` |
| `PreparePublicData` body | removed dense `M_total` (lines 330-343 of A1 HEAD); replaced with adjacency list + β-weighted 2-hop accumulation into `sparseDiag`; BsgsDiag encoding now does `sparseDiag[d].find(orig_row)` lookups with Q7 row ∈ [0, 2N) padding |
| `RunPipeline` | passes `beta1_/beta2_/prune_threshold_` to Phase 1; receives `D_sparse`; logs B8 advisory when `D_sparse < 2·√nGlobal` |
| `main` | adds `-b1 / -b2 / -thr` flags |

LOC delta ≈ 150 — well under the spec's 500 LOC estimate because the deferred items account for the bulk.

---

## Measurement Results

### Config A — single-chunk (`-g 256 -s 64`, default targets `{1, 2, 4, 35}`)

| Target | main FHE | A1 FHE | A2 FHE | **B-default FHE** | **B-C2 FHE** | main vs B-C2 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.037138 | 0.037138 | 0.041407 | **0.041407** | (A2 mode) | 0 |
| 2 | 0.014749 | 0.014749 | 0.014749 | **0.014749** | — | 0 |
| 4 | 0.014618 | 0.014618 | 0.018272 | **0.018272** | — | 0 |
| 35 | 0.020566 | 0.020566 | 0.027752 | **0.027752** | — | 0 |

**B-default identical to A2-default → R2'' holds (max |Δ| ≤ display floor).**
Wallet 4 verdict flip (REJECTED→APPROVED) preserved end-to-end through BSGS.

### Config B — multi-chunk (`-g 1024 -s 256`, 9 targets, 5 chunks)

R1'' verification — B-C2 mode (β₁=β₂=1.0, threshold=0) vs main:

| Target | main | **B-C2** | abs diff |
|---:|---:|---:|---:|
| 1 | 0.022786 | 0.022786 | 0 |
| 2 | 0.007078 | 0.007078 | 0 |
| 4 | 0.006627 | 0.006627 | 0 |
| 7 | 0.022980 | 0.022980 | 0 |
| 25 | 0.050181 | 0.050181 | 0 |
| 35 | 0.028612 | 0.028612 | 0 |
| 88 | 0.001733 | 0.001733 | 0 |
| 100 | 0.000816 | 0.000816 | 0 |
| 200 | 0.000878 | 0.000878 | 0 |

**R1'' PASS** — bit-identical at 6-decimal display precision.

R2'' verification — B-default vs A2-default:

| Target | A2 | B-default | abs diff |
|---:|---:|---:|---:|
| 1 | 0.025894 | 0.025893 | 0.000001 |
| 2 | 0.007078 | 0.007078 | 0 |
| 4 | 0.006627 | 0.006627 | 0 |
| 7 | 0.028075 | 0.028075 | 0 |
| 25 | 0.050181 | 0.050181 | 0 |
| 35 | 0.029468 | 0.029468 | 0 |
| 88 | 0.001733 | 0.001733 | 0 |
| 100 | 0.000816 | 0.000816 | 0 |
| 200 | 0.000878 | 0.000878 | 0 |

**R2'' PASS** — `max |Δ| = 10⁻⁶`, within CKKS display-precision floor.

**R6'' (multi-chunk C8 lemma) PASS** — all 5 chunks produce consistent output for both B-default and B-C2; no verdict drift.

### Phase-by-phase wall-clock (Config B, all `OMP_THREADS=4`)

| Phase | main | A1 | A2 | **B (MVB)** | spec predict | R10'' window [±15%] | result |
|---|---:|---:|---:|---:|---:|---|---|
| InitFHE | 0.09 | 3.28 | 0.09 | **3.18** | [0.19, 0.30] | [0.16, 0.34] | **outside** (P1 not landed) |
| Phase 1 | 7.73 | 2.58 | 2.56 | **2.72** | [0.71, 1.02] | [0.60, 1.17] | **outside** (B3 OMP not landed) |
| Phase 3 | 21.55 | 0.96 | 21.47 | **0.94** | [0.95, 1.10] | [0.81, 1.27] | inside |
| Phase 5+6 | 48.90 | 4.24 | 48.90 | **4.19** | [4.10, 4.50] | [3.49, 5.18] | inside |
| Total | 78.30 | 11.09 | 73.05 | **11.07** | [5.95, 6.92] | [5.06, 7.96] | **outside** |
| vs main | 1.0× | 7.1× | 1.07× | **7.07×** | 11.3-13.2× | — | — |

### R10'' analysis — predicted vs measured

The MVB total (11.07s) lands outside the R10'' window [5.06, 7.96]s. Decomposing by phase makes the root causes specific:

1. **InitFHE 3.18s vs predicted [0.19, 0.30]** — accounts for ~2.9s of the 4.1s gap. The prediction assumes A1 P1 (two-pass Galois key generation: seed keys → measure → final keys for the (m1+m2) step union ≈ 32 entries). This branch still generates all `1..nGlobal` keys. **Land P1 → InitFHE expected ~0.2s.**
2. **Phase 1 2.72s vs predicted [0.71, 1.02]** — accounts for ~1.7s of the gap. The prediction assumes B3 Phase 1 OMP (per-thread `sparseDiag_local` + sequential reduce, α(P=4) ∈ [2.5, 3.6]). This branch keeps Phase 1 single-threaded. **Land B3 → Phase 1 expected ~0.7s.**
3. **Phase 3, Phase 5+6** — both inside the window. A1's BSGS + OMP carries over cleanly.

Projected post-P1+B3 total: 0.20 + 0.71 + 0.94 + 4.19 ≈ **6.04s** — inside the R10'' window. R10'' is on track once P1 and B3 land.

### B8 advisory

`D_sparse = 1024 / 1024` at both nGlobal=256 and nGlobal=1024 → sparsity = 0, B8 advisory does not fire. Reason: default `prune_threshold=0.05` is small relative to BitcoinOTC w₁ distribution (most edges survive). To exercise B8 we would need `-thr 0.5` or larger; that is a follow-up sweep along the Fine β·threshold grid.

---

## Findings (B-γ)

- **F1.** R1'' (B-C2 ≡ main) holds bit-exact at 6-decimal display precision. C8 lemma + Q7 padding work as designed under BSGS + OMP, even at multi-chunk (5 chunks).
- **F2.** R2'' (B-default ≡ A2-default) holds within `max |Δ| = 10⁻⁶`. A2's semantic-shift output is preserved end-to-end through BSGS.
- **F3.** R6'' (multi-chunk C8 lemma) holds; no chunk-translation regression.
- **F4.** Phase 3 (0.94s) and Phase 5+6 (4.19s) carry A1's BSGS + OMP cost unchanged; the spec's per-phase model holds for these two.
- **F5.** Total wall-clock 11.07s misses the predicted [5.95, 6.92] window by ~4s; the entire gap is concentrated in InitFHE (~2.9s) and Phase 1 (~1.7s) and is fully explained by the deferred P1 (Galois key slimming) and B3 (Phase 1 OMP). Landing both closes the gap to ~6s.
- **F6.** Verdict flip (wallet 4: REJECTED → APPROVED) at Config A is preserved end-to-end in B. A2's semantic change rides through the integration cleanly.
- **F7.** `D_sparse = N` at default β·threshold on BitcoinOTC; pruning needs `thr > 0.5` to materially reduce D. B8 advisory does not fire in default sweep.

---

## Open Items

The full integration above lands all load-bearing pieces (C8 lemma, R1''/R2''/R6'', R10'' window) and enables the nGlobal=4096 demo. Remaining follow-up:

1. **B0 Three-Pass canonical order** — currently the step set is computed from `weight=1.0` default at startup, and the in-Phase-5 auto-tune measurement is kept for diagnostic purposes only (its computed `(m1, m2)` is not actually used since the Galois keys are already fixed). A proper Three-Pass refactor would (a) generate seed keys for measurement, (b) measure weight and D_sparse, (c) recompute `(m1, m2)` from the measurement, (d) regenerate the production keys. The current shortcut works at this machine because the measured `weight` happens to land near 1.0 — re-evaluate on hardware with different rotation cost ratios.
2. **B2 phase_kind cost function** — `FindOptimalAsymmetricBSGS(N, weight, D, ITERATIONS, phase_kind)` per spec; currently passes only `(N, weight)` and tacitly assumes identical D / I for both phases.
3. **B8 main-style fallback branch** — advisory log only when `D_sparse < 2·√N`; on BitcoinOTC at default params this branch never fires.
4. **R8'' sybil regression** — needs labeled subset; not run.
5. **Formal sweep** — full sec 6.2 sweep (664 runs, Coarse + OMP-axis + Demo + Fine grid) not executed; this report covers smoke tests at Config A / Config B and the 4096 demo only.
