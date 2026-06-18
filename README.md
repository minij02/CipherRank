# CipherRank

Privacy-preserving sybil defense pipeline that combines Fully Homomorphic Encryption (CKKS) with Private Information Retrieval to evaluate wallet trust on a Bitcoin OTC transaction graph **without revealing which wallet is being analyzed**.

A target wallet's trust score is computed end-to-end by the server in ciphertext form via PageRank on a blindly-extracted subgraph; only the final score reaches the client.

## Pipeline

| Phase | Side | Operation |
|---|---|---|
| 1 | Server | Public Transaction Matrix Preparation. Loads `soc-sign-bitcoinotc.csv`, applies time-decay, builds the diagonal-packed plaintext cache used by PIR. |
| 2 | Client | Multi-Target SIMD FHE-PIR Encryption (one-hot encoding of target wallet indices, batched into chunks). |
| 3 | Server | Parallel Blind Subgraph Extraction via homomorphic matrix-vector multiplication. Output: per-target encrypted neighbor weights. |
| 4 | Client | SIMD Subgraph Resolution & Mapping (top-K neighbor selection). |
| 5 | — | FHE & plaintext PageRank power iteration on the nSub-dimensional subgraph (ITERATIONS = 10). |
| 6 | Client | Precision validation + smart-contract verdict (`fheScore ≥ 0.0150` ⇒ APPROVED). |

## Project layout

```
CipherRank.cpp              integrated bgsg + sparse pipeline (~930 LOC)
CMakeLists.txt              SEAL 4.1.2 + OpenMP build
soc-sign-bitcoinotc.csv     SNAP Bitcoin OTC dataset (35,592 rows)
soc-sign-bitcoinotc-synthetic.csv  + 50 synthetic sybils (seed=1, scripts/)
scripts/
    sweep_runner.py         4-way (main/A1/A2/B/B-C2) sweep + R8'' driver
    gen_synthetic_sybil.py  reproducible synthetic sybil generator
results/*.json              raw sweep outputs
docs/superpowers/specs/     design specs + measurement reports
```

## Quick start

Build (requires Microsoft SEAL 4.1.2, CMake ≥ 3.10, OpenMP via Homebrew on macOS):

```bash
mkdir -p build && cd build
cmake .. && cmake --build .
```

Run the integrated B pipeline on the default 4 target wallets:

```bash
./CipherRank -g 256 -s 64
```

Multi-chunk run at nGlobal=1024 with 9 targets, tuned semantics:

```bash
./CipherRank -g 1024 -s 256 -b1 1.0 -b2 0.30 -thr 0.05 \
    1 2 4 35 25 7 88 100 200
```

CLI flags:

| Flag | Meaning | Default |
|---|---|---|
| `-g <N>` | nGlobal — top-N most-frequent wallet space | 256 |
| `-s <n>` | nSub — subgraph dimension | 64 |
| `-b1 <f>` | β₁ (1-hop weight) | 1.0 |
| `-b2 <f>` | β₂ (2-hop weight) | 0.30 |
| `-thr <f>` | pruning threshold on weak 1-hop edges | 0.05 |
| `-csv <path>` | dataset override | `../soc-sign-bitcoinotc.csv` |
| *positional* | target wallet IDs | `1 2 4 35` |

Run the spec-suggested R10'' verification mode (β₁=β₂=1, threshold=0 — algorithmically equivalent to `main`):

```bash
./CipherRank -g 1024 -s 256 -b1 1.0 -b2 1.0 -thr 0 \
    1 2 4 35 25 7 88 100 200
```

## Headline results

(Config B = nGlobal=1024, multi-chunk over 9 targets, OMP=4, single Apple-Silicon machine.)

| Mode | Total wall-clock | vs main |
|---|---:|---:|
| `main` | 78.2 s | 1.00 × |
| A1 (bgsg + H-2) | 11.3 s | 6.9 × |
| A2 (sparse only) | 73.2 s | 1.07 × |
| **B (this branch)** | **6.7 s** (cold ≈ 3.9 s) | **11.7 ×** (cold ≈ 20 ×) |
| nGlobal=4096 demo (B) | 37 s | main impractical |

R1''/R2''/R6''/R10'' all pass on a cold machine; R8'' on natural + synthetic sybil sets shows pruning does not compromise sybil defense.

Full results live in `docs/superpowers/specs/`:

- `2026-06-18-bgsg-strengthening-design.md` — A1 (BSGS + OMP + H-2) design v2
- `2026-06-18-sparse-strengthening-design.md` — A2 (sparse Phase 1 + β-weighted hops) design v2
- `2026-06-18-integrated-bgsg-sparse-design.md` — B (integration) design v2
- `2026-06-18-integrated-bgsg-sparse-phase-gamma-results.md` — first MVB → full integration measurements
- `2026-06-18-integrated-bgsg-sparse-sweep-results.md` — sampled coarse sweep + natural sybil R8''
- `2026-06-18-integrated-bgsg-sparse-followup-results.md` — synthetic sybil + fine grid + bootstrap CI + thermal artifact

## Branch guide

| Branch | Purpose |
|---|---|
| `main` | baseline pipeline (no BSGS, no sparse) |
| `feat/sparse-twohop-precompute-experiment` | A2-only: Phase 1 sparse rewrite + β/threshold semantic |
| `feat/bgsg-experiment` | A1-only: asymmetric BSGS + OMP + H-2 Phase 5 thread-local; also holds the v2 spec set |
| `feat/bgsg-sparse-integrated` | **B (this branch):** integrated pipeline + sweep infrastructure + measurement reports |

## Reproducing a sweep

```bash
# coarse 4-way at nGlobal in {256, 1024}, N=3 reps each
python3 scripts/sweep_runner.py --coarse --reps 3 \
    --out results/coarse_sweep.json

# natural sybil R8'' (9 sybil + 9 trusted)
python3 scripts/sweep_runner.py --sybil --reps 1 \
    --out results/r8_sybil.json

# synthetic sybil (50 nodes, B vs B-C2 only)
python3 scripts/gen_synthetic_sybil.py --input soc-sign-bitcoinotc.csv \
    --output soc-sign-bitcoinotc-synthetic.csv --seed 1
python3 scripts/sweep_runner.py --synthetic-sybil --reps 1 \
    --csv ../soc-sign-bitcoinotc-synthetic.csv \
    --out results/r8_synthetic_sybil.json
```

The runner hard-codes the binary paths for the four branches. For multi-branch sweeps, create a git worktree per branch (`git worktree add ../CipherRank-a1 feat/bgsg-experiment`) and build each.

## Known limitations

- All measurements are on a single machine; **thermal throttle and sustained-load memory pressure shift wall-clock by 25-40 %** in extended sweeps (documented in followup-results sec 4 and sec 2c). The spec sec 6.5 protocol of 60 s idle between runs is honored for the canonical R10'' window.
- Sybil regression uses BitcoinOTC's natural distrust proxies (9+9) and one synthetic ring (50). Hub-trust-mixed synthetic sybils and multi-dataset generalization are future work (see followup-results sec 5).
- The B pipeline's auto-tune in Phase 5 still runs for diagnostic purposes; the (m1, m2) it computes is not consumed because Galois keys are fixed at startup from `weight=1.0`. Full Three-Pass (B0 in the spec) is partial.
- β₂ = 0 used to throw SEAL "transparent ciphertext"; fixed by filtering all-zero entries after the Phase 1 reduce. See followup-results sec 2a.

## License

Research / academic experiment. Microsoft SEAL is Apache 2.0; the SNAP Bitcoin OTC dataset is from the Stanford SNAP collection.
