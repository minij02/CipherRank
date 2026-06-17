# Stage B — `feat/bgsg-experiment` + `feat/sparse-twohop-precompute-experiment` 통합 강화안 설계 문서

- **날짜:** 2026-06-18
- **선행 문서:**
  - A1 v2: `docs/superpowers/specs/2026-06-18-bgsg-strengthening-design.md` (BSGS + OMP)
  - A2 v2: `docs/superpowers/specs/2026-06-18-sparse-strengthening-design.md` (Sparse Phase 1 + 의미 변경)
- **대상 베이스:** 새 통합 브랜치 `feat/bgsg-sparse-integrated` (생성 예정; 베이스는 A1 HEAD `85b3e04`, sparse 변경 cherry-pick 후 B-only 변경 적용)
- **기준선:** `main` (HEAD: `8c3aee3`)
- **단계:** B (통합 강화). A1, A2 독립 강화 완료가 prerequisite. 후속 산출물 = 단일 머지 가능한 통합 브랜치 + 본 spec의 측정 결과.

---

> **Caveat — Inherited from A1 + A2.**
> - **(A1 inherited):** server 가 secret_key 보유하는 단일-당사자 측정 환경. Phase 5 의 `decrypt → re-encrypt` 는 noise budget 회복용 단순화이며 실배포 PIR 와 다름.
> - **(A2 inherited):** sparse 는 단순 성능 최적화가 아니라 **신뢰 모델 의미 변경** (β₁=1.0, β₂=0.30, w(src→mid) < 0.05 pruning). A2 부록 B 에서 Config A wallet 4 verdict flip 으로 입증.
> - **(B-only):** A1 의 BSGS auto-tune + 비대칭 cost 가 A2 의 sparse D 와 결합하면 **(m1, m2) 선택이 graph density 의 함수가 됨** → graph-private 모델에서 timing leak surface 가 합쳐서 확장됨 (A1 NG6/NG7 + A2 NG10 cross-ref). 단일-머신 sim 에서는 무관.

---

## 1. 본 단계가 공격하는 병목

A1 단독: Phase 3 의 N rotation → m1+m2-2 rotation + OMP 청크 병렬화. 부록 B.F3 실측 **Phase 3 22.4× 가속, total 7.1× 가속 @ nGlobal=1024**.

A2 단독: Phase 1 의 O(N³) dense matmul → O(V·d̄²) sparse 누적. 부록 B.F1 실측 **Phase 1 3.03× 가속**. 그러나 **F3:** A1 미적용 시 Phase 3 (21.5s) 이 dominant → total 1.07× 만 가속.

**B 가 공격하는 새 병목:**
- **(i) 두 branches 의 시너지** — A1 의 Phase 3/5 가속과 A2 의 Phase 1 가속을 결합. Phase 1 (sparse) → Phase 3 (BSGS+OMP) → Phase 5 (BSGS+OMP) 모두 가속.
- **(ii) 통합 인터페이스의 정합성** — A2 의 `PirDiag {d, plain}` ⊕ A1 의 `BsgsDiag {i, j, plain}` + duplicate padding (A2 Q7).
- **(iii) Cost-aware BSGS** — A1 P4 (cost function with D, weight) + A2 Q6 (D_sparse 보고) 결합 → BSGS step (m1, m2) 가 실측 sparsity 에 적응.
- **(iv) Phase 1 OMP** — A2 단독은 OMP 미적용 (Phase 1 single-thread). A1 의 OMP discipline 을 Phase 1 sparse loop 에 확장 (B3 신규).

### 1.1 통합 영역 매트릭스

| Phase | 변경 출처 | B 단계 작업 |
|---|---|---|
| Init | A1 P1 (2-pass galois keys) + A2 Q4 (globalNodeToIndex 결정성) | B-Init: 2-pass 키 생성에서 D_sparse 입력 (Q6) 까지 흐름 정의 |
| Phase 1 | A2 Q1 (β·thr CLI), Q4 (sorted vector), Q7 (padding bridge), Q5 (M_pub sparse) + **B3 (Phase 1 OMP)** | sparse + padding + OMP 합성 |
| Phase 2 | (둘 다 미변경) | — |
| Phase 3 | A1 BSGS + OMP + thread-local Evaluator + **B2 (sparse-aware step set)** | A2 Q8 어댑터 적용 (PirDiag → BsgsDiag) |
| Phase 4 | A1 (결정성 정렬 + 양자화) | — |
| Phase 5 | A1 BSGS + P5a (thread-local) + auto-tune + Q5 sparse M_pub random access | — |
| Phase 6 | (변경 없음) | — |

### 1.2 B-only 새 작업 목록

- **B1.** Unified Configuration Object — A1 의 (giant_weight, m1, m2) + A2 의 (β₁, β₂, threshold) 를 단일 `RunConfig` 구조체로 통합. CLI 일관성.
- **B2.** Sparse-aware BSGS step set — sparse 의 D_sparse 가 작으면 (m1, m2) 가 D 에 따라 다르게 선택됨 (A1 P4 + A2 Q6 결합).
- **B3.** Phase 1 OMP — sparse 의 src 외부 loop 를 OMP 로 병렬화. `sparseDiag[d][row]` 동시 쓰기를 thread-local 또는 atomic 으로 격리.
- **B4.** Combined R1'' / R2'' / R3'' — A1 R1 (ε-equivalence) + A2 R1' (C2 mode main 등가) 의 **B 통합 변형**. 4-way 비교 (main / A1-only / A2-only / B).
- **B5.** Sybil regression in integrated context — A2 R8' 을 BSGS+OMP 환경에서 실행. race-condition free 검증.
- **B6.** A2 Q7 padding bridge 의 실측 검증 — A1 C4 lemma "Pattern Invariance" 가 B 통합 후 보존됨을 multi-chunk run 으로 입증.

### 1.3 보고 vs 비보고

**보고:** 통합 시스템의 wall-clock (4-way 비교), 메모리 (peak RSS, galois key MB, sparseDiag MB), R1''/R2''/R3'' 회귀, nGlobal=4096 demo (A1 부록 B 의 추정치 데이터 입증).

**비보고:**
- **(A1 inherited)** PIR 실배포 wall-clock, 동형 normalization 비용
- **(A2 inherited)** 신뢰 모델 정당화, multi-dataset 일반화
- **(B-only)** distributed-server 아키텍처, protocol round 수 변경, multi-party computation

---

## 2. 복잡도 및 자원 모델

기호: N = nGlobal, n = nSub, V = 유효 노드, E = 유효 edge, d̄ = E/V, K = num_chunks, P = OMP 스레드, D_sparse = sparse 의 비영 대각선 수, I = 10 (ITERATIONS), m1, m2 = BSGS 파라미터.

### 2.1 단계별 비용 (B 통합)

| 단계 | main | A1 only | A2 only | **B 통합** |
|---|---|---|---|---|
| InitFHE | small + O(log N) 키 | + O(N) galois keys (A1 P1 전) → O(m1+m2) (P1 후) | (main 동일) | O(m1+m2) 키 (P1) + Pass-1 measure |
| Phase 1 (CPU) | O(N³) | (A1 미변경) | **O(V·d̄²)** (sparse) | O(V·d̄² / P) (sparse + B3 OMP) |
| Phase 3 (per chunk) | D·T_rot | **(m1+m2-2)·T_rot + D·T_mult** | D·T_rot | (m1+m2-2)·T_rot + **D_sparse·T_mult** (B2) |
| Phase 5 (per chunk × I) | I·D·T_rot | **I·((m1+m2-2)·T_rot + D·T_mult + T_dec+T_enc)** | I·D·T_rot | I·((m1+m2-2)·T_rot + **D_sparse·T_mult** + T_dec+T_enc) |
| OMP 총 | 1 thread | **P-way 병렬 (Phase 3, 5)** | 1 thread | **P-way 병렬 (Phase 1 sparse + Phase 3, 5)** |

### 2.2 통합 wall-clock 예측 모델 (B)

A1 부록 B.F3 실측: **A1 단독 nGlobal=1024 multi-chunk total = 11.09s**. 그 중 Phase 1 = 2.58s (sparse 미적용 상태). A2 단독 nGlobal=1024 multi-chunk total = 73.05s, 그 중 Phase 1 = 2.56s (sparse 적용).

**B 통합 예측 (nGlobal=1024 multi-chunk):**
- Phase 1: A2 sparse = 2.56s. B3 OMP 후 ≈ 2.56s / 4 = **0.64s** (P=4 OMP, sparse 외부 loop 이 IO-bound 가 아님)
- Phase 3: A1 BSGS+OMP = **0.96s** (A1 부록 B.F3)
- Phase 5+6: A1 = **4.24s** (A1 부록 B.F3)
- InitFHE: A1 = **3.28s** (A1 부록 B.F2 — A1 P1 적용 전 회귀). **B-Init 에서 A1 P1 적용 시 ≈ 0.5s 추정** (m1+m2 ≈ 32 키만 생성)
- **B 총 예측 ≈ 0.5 + 0.64 + 0.96 + 4.24 = ~6.4 sec @ nGlobal=1024**
- 비교: main = **78.30s** → **B 예측 가속 12.2×**

**예측 vs 실측 검증은 sec 7 R10''** (벤치마크 회귀).

### 2.3 메모리 (B 통합)

| 항목 | main | B (예상) |
|---|---|---|
| M_pub | N²·8 = 8 MB (N=1024) | A2 Q5 적용: ~144 KB (CSR/hash) |
| M_total | 8 MB | 0 (제거) |
| outAdj | — | ~144 KB |
| sparseDiag | — | ~2.6 MB |
| Galois keys | log N · 0.5 MB ≈ 5 MB | A1 P1 적용: (m1+m2) · 0.5 MB ≈ 16 MB (m1≈m2≈16) |
| baby_steps (P=4 threads) | — | 4 · m1 · 0.5 MB ≈ 32 MB |
| **Total estimate** | ~24 MB | ~51 MB |

**nGlobal=4096 의 메모리 변화:** main 은 M_pub 128 MB + M_total 128 MB = 256 MB. B 는 A2 Q5 적용으로 M_pub ~2 MB, sparseDiag ~10 MB, Galois keys (m1≈m2≈64) ~64 MB → ~76 MB. **4096 demo 의 메모리 enabler 가 Q5 임을 정량 확인.**

---

## 3. 정확성 모델

### 3.1 A1 C4 lemma 의 sparse 입력 하 보존 — **B의 핵심 정합성**

A1 C4 "Homomorphic Pattern Invariance under Chunk-Translation" lemma 는 모든 청크 c 에 동일 인코딩 패턴이 보존됨을 가정한다 (모든 청크의 슬롯 `c·2N + row` 에 같은 함수값). A2 sparse 의 line 305 `diag_flat[c·pirBlockSize + row] = val` 도 모든 청크에 동일 값 → **자체적으로 C4 lemma 호환**.

**그러나** A2 의 row 범위는 `[0, N)` 만, A1 BSGS 는 row `[0, 2N)` duplicate padding 필요. **Q7 (padding bridge) 가 sparse 의 row 루프를 `[0, 2N)` 로 확장**해 A1 C4 lemma 의 슬롯 안전성 (C7 "slot tail safety") 보존.

**B 통합 추가 정합성 조건 (C8 신설):**
- **(C8) Sparse-BSGS Pattern Equivalence:** 모든 청크 c 에 sparseDiag 의 row → 슬롯 매핑이 BSGS rotation by j·m1 후 의도된 (orig_row, orig_row+d) 위치에 정렬됨.
- *Proof sketch:* sparse 의 sparseDiag[d][row] = `β₁·M_pub[row][row+d]` (1-hop) + `β₂·...` (2-hop). A1 의 padding 인덱싱 (A1 sec 3.1 line 354): `orig_row = ((row − j·m1) mod N + N) mod N` 으로 모든 row ∈ [0, 2N) 가 olj-row ∈ [0, N) 으로 매핑. sparseDiag 가 모든 청크 c 에 동일 (row, val) 패턴이므로 padding region [N, 2N) 도 동일 매핑. □

### 3.2 의미 등가성 매트릭스 (B 통합)

| 모드 | 등가 대상 | 검증 |
|---|---|---|
| **B-default (β₂=0.30, thr=0.05, BSGS on, OMP on)** | sparse-default (A2 C1) | R2'' — 의미 보존 |
| **B-C2 (β₂=1.0, thr=0, BSGS on, OMP on)** | main | R1'' — algorithm 등가 |
| **B-bgsg-off (β₂=0.30, BSGS off)** | A2 default (C1) | R3'' — A1 효과 분리 |
| **B-sparse-off (β₂=1.0, thr=0, BSGS on)** | A1 default | R4'' — A2 효과 분리 |

### 3.3 의미 차이 + 알고리즘 가속 분리

A1 부록 B 의 noise floor (H_noise) 가 B 통합 에서 보존되어야:
- A1 R1 (Phase 3 ε-equivalence) — B-bgsg-off 모드에서 A2 와 ε 동등해야 함
- A2 R1' (C2 mode main 등가) — B-C2 모드에서 A1 효과 무시하고 main 등가

**B 의 ε-equivalence 가설 H_combined:**
`max_s |y_B[s] − y_A2[s]| < ε_B`. 즉 B 의 출력은 A2 의 출력과 BSGS rotation noise 정도의 차이만 보유.

---

## 4. 엣지 케이스 카탈로그 (B-only 추가)

A1 의 E1-E18 + A2 의 E1-E21 가 모두 inherited. 본 절은 **통합 시점에 새로 발생하는 케이스**만.

| ID | 케이스 | 거동 | 위험도 |
|---|---|---|---|
| **EB1** | D_sparse < m1+m2-2 인 sparse-heavy 경우 (A2 E11 강화안) | A1 BSGS rotation 수 > A2 plain-mult 수 → bgsg 가 더 느림 | **중간**: B2 cost-aware step 선택 |
| **EB2** | A2 Q1 (β·thr CLI) + A1 P3 (auto-tune weight) **타이밍 충돌** | β 변경이 D_sparse 변경 → P3 의 m1 선택 결과가 달라짐. 측정/적용 순서 명확화 필요 | **중간**: B1 unified config 적용 순서 |
| **EB3** | A2 Q7 padding 의 BSGS rotation 후 슬롯 분포 | A1 C4 lemma 가정인 chunk-translation invariance 가 sparse pruning 유무에 따라 깨질 가능성 | **높음**: 사전 측정 (R6'') 필수 |
| **EB4** | A2 Q4 sorted vector + A1 OMP thread-local diagonals | thread-local sparseDiag 사전계산 후 정렬 → 정렬 시점 결정 필요 (per-thread 또는 join 후) | **중간**: B3 명세 |
| **EB5** | A1 P5a thread-local Encryptor + A2 Q5 sparse M_pub random access | Phase 5 inner loop 의 `M_pub[allTop64[c][i]][allTop64[c][j]]` 가 hash lookup 으로 변경되면 thread-safety 재검토 (read-only? hash table internal state?) | **중간**: SEAL `Encryptor` 와 별개로 std hash thread-safety 확인 |
| **EB6** | A1 P1 2-pass galois key 의 step set 이 A2 의 D_sparse 가 매우 작을 때 over-allocate | sparse 가 D 줄여도 A1 P1 은 m1, m2 만 보고 step 결정 → 사용하지 않는 step 잔존 | 낮음 |
| **EB7** | A2 Q3 (hub-aware) + A1 OMP — 데이터-의존 분기가 timing leak 증폭 (A1 NG6 + A2 NG10 결합) | graph-private 모델에서 critical, 본 단계 simulation 무관 | 낮음 (NG에 명시) |
| **EB8** | nGlobal=4096 demo 의 Q5 sparse M_pub + A1 Phase 5 BSGS | nSub² hash lookup × P 스레드 × I iterations = ~256² · 4 · 10 = ~2.6M hash lookups → cache miss 영향 측정 | **중간**: R12'' 측정 |
| **EB9** | A1 P4 cost function `cost = m1·T_rot + (m2-1)·T_giant + D·T_mult` 의 D 입력이 A2 Q6 D_sparse 측정과 어긋남 (e.g., pruning이 race-by-edge로 D 변동) | non-deterministic D → non-deterministic (m1, m2) → R4' (결정성) 위반 가능 | **중간**: Q4 baseline 통제 → Q6 도 결정성 보장 |
| **EB10** | Phase 1 OMP (B3) 의 sparseDiag write race | atomic 쓰기 또는 per-thread accumulator + reduction 패턴 필요 | **높음**: B3 의 핵심 설계 결정 |
| **EB11** | A1 Phase 5 의 ITERATIONS=10 + A2 Q5 (sparse M_pub) + B3 OMP all combined | thread-local sparse M_pub copy 가 필요한지 (read-only 라면 공유 가능) — Encryptor와 다른 thread-safety 모델 | 낮음 |
| **EB12** | A1 fast mode (giant_weight cap=5.0) + A2 sparse (D 작음) 조합 시 m1 결정이 데이터-의존 | Q2 auto-calibration + P2 auto-tune 모두 데이터 의존 → 동일 입력 반복 시 (m1, m2) 일관성 | **중간**: R11'' (cross-run 일관성) |

---

## 5. 강화안 (B-only 새 항목 + A1/A2 통합 작업)

### 5.1 [B1] Unified Configuration Object

- **가설:** A1 의 (giant_weight, m1, m2, ITERATIONS), A2 의 (β₁, β₂, thr) 를 한 곳에 모으면 CLI 일관성 + sweep 효율 증가.
- **변경:** `struct RunConfig { double beta1, beta2, threshold; double giant_weight; int m1, m2; ... }` 도입. CLI: 통합 인자 `-cfg <json>` 또는 개별 flags. 권장: 개별 flags + JSON option both.
- **호환성:** A1 P3 (Phase 3 cost-weight injection), A2 Q1 (β·thr CLI) 동시 활성 후 단일 구성 객체로 통합.
- **측정:** sweep 시 동일 RunConfig 반복 → reproducibility 향상.

### 5.2 [B2] Sparse-Aware BSGS Step Set

- **가설:** A1 P4 (`cost(m1, m2; D, ITER)`) 가 D 를 받지만, A2 Q6 가 그 D 를 `D_sparse` 로 정확히 측정해 줘야 의미 있음. 단순 결합: A2 의 D_sparse 보고를 A1 의 P4 cost 입력에 직접 주입.
- **변경 위치:** `RunPipeline()` 의 `FindOptimalAsymmetricBSGS` 호출 시 (현재 A1: weight=1.0 고정) → `FindOptimalAsymmetricBSGS(nGlobal, real_weight, D_sparse, ITERATIONS)` 로 변경. Phase 3, Phase 5 양쪽 적용.
- **선결조건:** A1 P4 + A2 Q6 구현 완료.
- **EB1 해결:** D_sparse 가 작으면 cost function 이 (m1, m2) 를 줄여 plain-mult 수도 줄임. 극단적으로 D_sparse=1 이면 m1=1, m2=1 로 BSGS 효과 disable (이는 sparse 단독 fallback).
- **측정:** D_sparse sweep × (m1, m2) 결정 안정성.

### 5.3 [B3] Phase 1 OMP Parallelization

- **가설:** A2 의 sparse 외부 loop `for (int src = 0; src < nGlobal; src++)` (sparse:283) 는 src 사이 독립 → OMP 병렬화 가능. 그러나 `sparseDiag[d][row] += ...` 는 동시 쓰기 race.
- **변경 옵션:**
  - **(B3a)** per-thread `sparseDiag_local`, join 후 reduce: `Σ_threads sparseDiag_local[d][row]` → cache-friendly 하지만 메모리 P × nnz_diag
  - **(B3b)** atomic add on `sparseDiag[d][row]` — 단일 자원, 경합 가능
  - **(B3c)** src 의 모듈로 partition (src 가 같은 d 에 쓰지 않도록 source-side sharding) — 그래프 구조 의존
- **권장: B3a** (per-thread + reduce) — 메모리 P × nnz_diag = 4 × 2.6 MB = 10.4 MB @ nGlobal=1024, 무시 가능. 추후 P↑ 시 재검토.
- **측정:** Phase 1 wall-clock at P ∈ {1, 2, 4, 8}, sparseDiag 쓰기 race 발생률 (TSan).
- **위험:** EB10. TSan 검증 (A1 P5b 와 동일 CI hook).

### 5.4 [B4] Combined R1'' / R2'' / R3'' / R4'' 회귀 (sec 7)

- **B4-1.** R1'': **B-C2 모드 ≡ main**.
- **B4-2.** R2'': **B-default ≡ A2-default** (BSGS 가 의미 보존, ε-equivalence).
- **B4-3.** R3'': **B-bgsg-off (β=0.30, thr=0.05) ≡ A2-default**.
- **B4-4.** R4'': **B-sparse-off (β=1.0, thr=0) ≡ A1-default**.

각각 sec 7 에 정의.

### 5.5 [B5] Sybil Regression in Integrated Context

- **가설:** A2 R8' (sybil injection regression) 을 B 통합 (BSGS+OMP) 환경에서 실행. race-condition 으로 인한 정확도 회귀가 sybil score 에 영향 주는지 검증.
- **방법:** A2 Q3 hub-aware on 상태에서 알려진 sybil cluster 주입 → trust score 의 race 변동성 측정.
- **prerequisite:** A2 R8' 통과 (A2 단독 정상) + B5 가 BSGS 추가 영향 측정.

### 5.6 [B6] Q7 Padding Bridge 실측 검증

- **가설:** A2 Q7 의 row ∈ [0, 2N) padding 이 B 통합 시 A1 C4 lemma 보존 — 데이터로 확인.
- **방법:** multi-chunk run (≥ 5 chunks) 후 청크-translation 등가성 측정. 출력 ciphertext per-chunk 비교.
- **measurement:** A1 부록 B Config B (9 targets, 5 chunks) 와 동일 환경에서 B 출력 vs A2 출력 비교.

### 5.7 [B7 — 옵션] Two-stage Cost Optimization

- **가설:** A1 P4 가 Phase 3 와 Phase 5 양쪽에 같은 (m1, m2) 사용. 그러나 D_sparse_phase3 ≠ D_sparse_phase5 가능 (Phase 5 는 nSub × nSub subgraph 위에서 계산).
- **변경:** Phase 3, Phase 5 별 (m1, m2) 따로 측정. 추가 measurement 비용 1회.
- **권장 우선순위:** **낮음** — 본 단계 Q1~Q8 + B1~B6 의 effect 측정 후 잔여 잠재력 평가.

---

## 6. 측정 계획

### 6.1 비교군 — 4-way + Ablation

| ID | 구성 | 검증 |
|---|---|---|
| C0 | `main` baseline | reference |
| C1 | A1 default (bgsg, β·thr 없음) | A1 부록 B 재현 + B 비교 baseline |
| C2 | A2 default (sparse, BSGS 없음) | A2 부록 B 재현 |
| C3 | **B default (sparse + BSGS + OMP, β₂=0.30, thr=0.05)** | end-to-end B |
| C4 | **B-C2 mode (β=1, thr=0, BSGS on)** | R1'' main 등가 |
| C5 | B + B1 (unified config) | API 일관성 |
| C6 | B + B2 (sparse-aware step set) | cost-aware (m1, m2) |
| C7 | B + B3 (Phase 1 OMP) | OMP 효과 |
| C8 | B + B6 (Q7 multi-chunk validation) | C4 lemma 보존 |
| C9 | B + B5 (sybil regression) | 통합 보안 |

### 6.2 Sweep — 4-way × {nGlobal, num_targets, OMP threads}

- **Coarse:** nGlobal ∈ {256, 1024, 2048} × num_targets ∈ {4, 16} × OMP ∈ {1, 4} × C0..C9 × N=10 = 720 runs
- **Demo:** nGlobal=4096 × num_targets=4 × OMP=4 × {C0 N/A, C1 N/A — A1 단독에서도 4096 시간 길음, C2 N/A 동일, C3, C6} × N=3 = 6 runs
- **Fine β/weight grid:** nGlobal=1024 × OMP=4 × (β₂, weight) 3×3 grid × C3 × N=10 = 90 runs

**총 816 runs.** 예산 단위:
- C0 (main) nGlobal=2048: ~90s, nGlobal=4096: 실행 불가
- C1 (A1) nGlobal=2048: ~22s (A1 부록 B 외삽)
- C2 (A2) nGlobal=2048: ~70s
- C3 (B) nGlobal=2048: ~5s 예상
- C3 (B) nGlobal=4096: ~30s 예상 (demo 가능)

**총 시간 추정: ~12-18시간** (단일 머신).

### 6.3 메트릭

| 카테고리 | 메트릭 | 단위 |
|---|---|---|
| 시간 | InitFHE, Phase 1, 3, 5, total wall-clock (4-way 분리) | sec |
| 시간 | 가속 비율 = Time(main) / Time(B) 등 | dimensionless |
| 메모리 | Peak RSS, M_pub vs sparseDiag vs Galois keys vs baby_steps | MB |
| 알고리즘 | D_sparse / nGlobal, (m1, m2) sweep 별 선택 | various |
| 정확도 (algorithm) | B vs A1 (R4''), B vs A2 (R3''), B-C2 vs main (R1'') | abs ε |
| 정확도 (semantic) | B vs main FHE score per target, Cohen's d | abs + unitless |
| 정확도 (semantic) | Top-K Kendall τ (K = min(nSub, 10)) | -1~1 |
| 결정성 | 동일 seed N=10 회 B 출력 max diff | abs |
| **Sybil** | TPR/FPR on sybil-labeled subset (R8'' + B5) | 0~1 |
| **C4 lemma** | per-chunk output equivalence (multi-chunk run, B6) | abs |

### 6.4 통계 프로토콜

- **시간 / semantic 메트릭:** Wilcoxon signed-rank, BH FDR 5%, log₂(median ratio) effect size, 95% bootstrap CI
- **알고리즘 등가성 (R1''~R4'', R6''~R10''):** assertion (max|diff| < ε), 0/1 pass/fail per run, 통계 검정 미적용
- **Sybil TPR/FPR:** 1000-resample bootstrap 95% CI

### 6.5 환경 고정 + 재현성

- A1, A2 inherited: CPU governor, OMP_PROC_BIND, SEAL seed, CSV SHA-256, 빌드 매니페스트
- **B 신규:** OMP_NUM_THREADS 명시 고정, BSGS (m1, m2) 의 cross-run 일관성 검증 (R11'')
- 실험 순서 무작위화 + 60s idle

---

## 7. 정확성 회귀 테스트 (B-only)

### R1'' (B-C2 mode ≡ main)

C4 모드 (`β₁=1.0, β₂=1.0, threshold=0, BSGS on, OMP on`) 에서 B 출력이 main 출력과 ε-equivalent. `max_s |y_B-C2[s] - y_main[s]| < ε_R1'' ≈ 5×10⁻⁷`.

### R2'' (B-default ≡ A2-default)

`max_s |y_B[s] - y_A2[s]| < ε_R2''`. BSGS rotation noise 만큼의 차이.

### R3'' (B-bgsg-off ≡ A2-default)

BSGS off 모드에서 B 가 A2 와 동일.

### R4'' (B-sparse-off ≡ A1-default)

sparse off 모드에서 B 가 A1 과 동일.

### R5'' (Verdict 일치)

A1 R3 + A2 R3' 의 B 변형. B-C2 ≡ main verdict, B-default 는 A2-default verdict 와 일치 (verdict 차이는 sparse 의 의미 변경 결과로 main 과 차이 정상).

### R6'' (Multi-chunk equivalence under Q7 — C4 lemma)

A2 R9' 의 B 통합 변형. multi-chunk run 에서 청크-translation invariance 보존.

### R7'' (Phase 5 parity)

A2 R7' 통합 변형. A1 P5a (thread-local Encryptor) 적용 후 Phase 5 wall-clock 이 A1 단독과 ε-동등.

### R8'' (Sybil regression in B)

A2 R8' + BSGS+OMP 환경에서 sybil score 회귀.

### R9'' (Determinism across multi-thread)

A1 R5 + A2 R4' 통합. **B 의 OMP P ∈ {4, 8, 16} 에서 출력 일관성**: `max | y_OMP=4 - y_OMP=16 | < ε_R9''`.

### R10'' (Performance prediction)

sec 2.2 의 wall-clock 예측 (`~6.4s @ nGlobal=1024`) 가 실측치와 30% 이내 일치.

### R11'' (Cross-run (m1, m2) consistency)

A1 P2 의 cross-run weight 안정성 (CV<10%) + A2 Q6 의 D_sparse 결정성 → B 의 (m1, m2) 가 동일 입력 N=10 회 실행 시 동일.

### R12'' (Q5 random-access 정확성)

A2 Q5 (M_pub sparse) 적용 후 Phase 5 의 random access (`M_pub[allTop64[c][i]][allTop64[c][j]]`) 결과가 dense access 와 ε-동등.

---

## 8. 개방 문제

- **O1.** A1 P4 + A2 Q6 의 결합 cost function 이 D_sparse 의 함수로 (m1, m2) 를 결정. nGlobal=4096 에서 m1 이 1 또는 N 극단으로 가지 않는지 (cap 작동) 측정.
- **O2.** A2 Q3 hub-aware + B3 Phase 1 OMP 의 결합 — sub-sampling 결정이 thread 별로 다르면 결정성 R9'' 위반. Q3 의 결정성 강화 필요.
- **O3.** A1 P6 (baby step reuse across iterations) 의 B 단계 적용 — Phase 5 에서 decrypt→re-encrypt 가 baby_step 재사용을 막음. B 단계에서 의 위장 가능성? 별도 spec.
- **O4.** B 의 nGlobal=4096 demo 에서 main 은 실행 불가 → 비교 baseline 부재. B 의 절대 성능을 어떻게 보고할지 (e.g., A1-only at 4096 vs B at 4096).
- **O5.** A1 P5b (TSan) + B3 Phase 1 OMP 의 TSan 적용. SEAL upstream + std::unordered_map 의 TSan false positive 폭주 위험.
- **O6.** Q5 (sparse M_pub) 가 Q3 (hub-aware) 의 hub detection 에 영향 — hash table iteration 으로 degree 계산이 비결정적이면 hub set 도 비결정적.
- **O7.** B 통합 후 PIR 프로토콜 충실성 (A1 NG5) 가 더 멀어짐 — sparse 모델 변경 + BSGS 모두 server-side. distributed PIR 의 의미는 별도 spec.

---

## 9. 비-목표

A1 NG1-NG8 + A2 NG1-NG12 모두 inherited. B-only 신규:

- **NG-B1.** B 가 nGlobal=4096 에서 main 보다 빠름을 단정하지 않는다. main 은 실행 불가이므로 비교 자체가 불가.
- **NG-B2.** B 가 A1 단독 또는 A2 단독보다 항상 빠름을 단정하지 않는다. sec 6 의 정량 비교 결과로 부분 영역 (예: nGlobal=256, sparse 작은 D) 에서 A1 단독이 더 빠를 가능성 인정.
- **NG-B3.** **(보안)** B 의 timing-side-channel — A1 NG6 + A2 NG6 결합. data-dependent control flow 가 양 강화안 동시 적용 시 새로 증폭되는 표면은 graph-private 모델 외부.
- **NG-B4.** **(보안)** B 의 Q3 + Q6 동시 적용 시 graph density 노출의 정량적 정도. graph plaintext 가정 하에서는 무관, graph-private 모델 도입 시 critical.
- **NG-B5.** B 의 새로운 신뢰 모델 (A2 β·thr × A1 noise) 의 sybil 방어 정량 평가는 본 spec 범위 외. R8'' 측정값은 정량화일 뿐, 보안 audit 책임은 future spec.

---

## 10. 의존성 DAG와 적용 순서

```
[Stage A 완료 — prerequisite]
   A1 v2 모든 권고 + 코드 패치 (H-2 적용 완료)
   A2 v2 모든 권고 (Q1 root, Q4 baseline, Q5 critical, Q6, Q7)

[B-Init — A1 + A2 합치기]
   Step 1: Branch 'feat/bgsg-sparse-integrated' 생성
            (베이스 = A1 HEAD '85b3e04')
            → A2 의 sparse Phase 1 변경 cherry-pick
            → A1 Phase 3/5 BSGS 와 sparse 인터페이스 정합 (Q8 어댑터)
            
[B-only 새 변경 — 순서대로]
   B1 unified config ─── 모든 sweep prerequisite
       │
       ▼
   B2 sparse-aware step set (A1 P4 + A2 Q6 결합)
       │
       ▼
   B3 Phase 1 OMP (B3a per-thread + reduce)
       │
       ▼
   B6 Q7 padding bridge 실측 검증 (R6'')
       │
       ▼
   B4 R1''~R4'' 통합 회귀
       │
       ▼
   B5 sybil regression (Q3 적용 시)

[Optional]
   B7 two-stage cost optimization (효과 측정 후 결정)
```

---

## 11. 엔지니어링 노트

- **(a)** **두 branch 의 합성성 (composability) 가 가장 큰 위험.** A1 과 A2 가 각자 잘 검증되었어도 결합 시점에서 race / 정합성 오류가 새로 발생함을 EB1-EB12 가 보여줌. B 단계는 결합 그 자체가 검증 대상.
- **(b)** **의미 변경의 전파.** A2 의 β₂=0.30 + pruning 가 B 의 모든 출력에 영향. A2 부록 B 의 verdict flip (wallet 4) 은 B 에서도 보존됨. R1'' (C2 모드) 이 B 의 *알고리즘* 정합성을, R2''~R4'' 이 *의미* 보존성을 분리 검증.
- **(c)** **OMP 일관성.** A1 은 Phase 3/5 OMP, A2 는 무 OMP. B 는 Phase 1 까지 OMP 확장 (B3). 세 phase 모두에서 thread-local discipline 일관 적용 — A1 P5a 패턴 (thread-local Evaluator/Encryptor/Decryptor) 을 Phase 1 sparse loop 에 적용 (per-thread sparseDiag accumulator).
- **(d)** **Cost-aware BSGS 의 데이터 의존성.** B2 가 D_sparse 를 입력으로 받으면 (m1, m2) 가 graph topology 함수. 단일-머신 sim 에서는 무관 (NG-B3), graph-private 모델에서는 critical (NG-B4).
- **(e)** **메모리 모델의 점진적 sparsification.** main 의 N²·8 dense → A2 Q5 의 sparse M_pub → B 의 baby_steps thread-local replication. 메모리 절감과 thread overhead 의 균형은 P (스레드 수) 에 따라 달라짐.
- **(f)** **nGlobal=4096 demo 의 학술적 가치.** main 이 실행 불가한 영역에서 B 가 동작 → CipherRank 의 확장성 임계점 입증. 단, 비교 baseline 부재 → A1-only 4096 (구현 가능하지만 매우 느림) 와 비교 보고.

---

## 부록 A — 변경 파일·라인 색인 (B 통합 기준)

### A1 변경 (그대로 inheritied)
- `CipherRank.cpp:49-58` BsgsDiag
- `CipherRank.cpp:81-105` FindOptimalAsymmetricBSGS (B2 에서 시그니처 확장)
- `CipherRank.cpp:131-138` 클래스 멤버 (public_key, secret_key 추가됨 — H-2 패치)
- `CipherRank.cpp:244-246` Galois key step 명시 (B1 에서 통합 config 적용)
- `CipherRank.cpp:407-460` Phase 3 OMP BSGS
- `CipherRank.cpp:582-684` Phase 5 OMP BSGS (H-2 적용 thread-local)

### A2 변경 (cherry-pick 후 적용)
- 신규 `outAdj` 인접 리스트 (sparse branch line 262)
- 신규 `sparseDiag` hashmap → **B3 에서 thread-local accumulator 로 변경**
- 신규 β₁, β₂, threshold → **B1 RunConfig 로 통합**

### B-only 신규
- `RunConfig` 구조체 (B1)
- `PreparePublicData(RunConfig&)` 새 시그니처
- `FindOptimalAsymmetricBSGS(N, weight, D, I)` 시그니처 확장 (B2)
- Phase 1 OMP 외부 loop + per-thread sparseDiag (B3)
- `PhaseOneOutput` struct (A2 Q6 그대로 사용)
- Q8 adapter: `sparseDiag → BsgsDiag` 변환 함수

---

## 부록 B — B 통합 예측 모델

| Phase | main (nGlobal=1024) | A1 only | A2 only | **B 예측** | 실측 검증 (R10'') |
|---|---|---|---|---|---|
| InitFHE | 0.09s | 3.28s | 0.09s | ~0.5s (A1 P1 적용) | sec 7 R10'' |
| Phase 1 | 7.73s | 2.58s | 2.56s | ~0.64s (B3 OMP) | R10'' |
| Phase 3 | 21.55s | 0.96s | 21.47s | ~0.96s (A1 BSGS+OMP) | A1 부록 B 재현 |
| Phase 5+6 | 48.90s | 4.24s | 48.90s | ~4.24s (A1 BSGS+OMP) | A1 부록 B 재현 |
| **Total** | **78.30s** | **11.09s** | **73.05s** | **~6.4s** | **R10''** |
| **속도비 vs main** | 1.0× | 7.1× | 1.07× | **~12.2×** | — |

---

## 부록 C — A1, A2, B Non-Goal cross-reference

| 항목 | A1 NG | A2 NG | B NG | 통합 영향 |
|---|---|---|---|---|
| PIR 프로토콜 충실성 | NG5 | NG2 | NG-B3 | server-key 보유 가정 inherited |
| Graph plaintext 가정 | NG6 (timing) | NG6 (timing) | NG-B3 | 결합 시 surface 증폭 가능 |
| Galois key 협상 | NG7 | NG10 (cross-ref) | NG-B4 | B2 가 D 노출 surface 추가 |
| 신뢰 모델 정당화 | — | NG1, NG11, NG12 | NG-B5 | A2 의 β₂ 가 B 로 전파 |
| nGlobal=4096 demo | (해당 없음) | O7 | **NG-B1** | B 가 4096 enable, main 비교 부재 |
| 데이터셋 일반화 | — | NG11 | (inherited) | β·thr BitcoinOTC tuning 인지 |

---

## 부록 D — 본 spec 산출물

B 단계가 완료되면 산출물:
- 새 브랜치 `feat/bgsg-sparse-integrated` (또는 main 직접 머지)
- 코드 변경 (B1~B6, A2 cherry-pick + Q1~Q8 적용, A1 patches inherited)
- 측정 결과 (sec 6 sweep 결과 표 + 통계 분석)
- 본 spec 의 R10'' 등 회귀 결과 보고서
- 합쳐진 학술 노트 (A1+A2+B 의 엔지니어링 통찰)

본 spec 자체는 **B 단계 진입 전 사전 설계 문서**이며, B 단계 완료 시 별도 *Stage B 결과 보고서* 작성.
