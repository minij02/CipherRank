# Stage B — `feat/bgsg-experiment` + `feat/sparse-twohop-precompute-experiment` 통합 강화안 설계 문서 (v2)

- **날짜:** 2026-06-18 (v2 revise)
- **선행 문서:**
  - A1 v2: `docs/superpowers/specs/2026-06-18-bgsg-strengthening-design.md`
  - A2 v2: `docs/superpowers/specs/2026-06-18-sparse-strengthening-design.md`
- **대상 베이스:** 새 통합 브랜치 `feat/bgsg-sparse-integrated` (생성 예정; 베이스는 A1 HEAD `85b3e04`, sparse 변경 cherry-pick 후 B-only 변경 적용)
- **기준선:** `main` (HEAD: `8c3aee3`)
- **단계:** B (통합 강화)
- **v2 변경:** 4 reviewer + OMC 의 Critical 5건 + High 8건 + Medium 다수 반영. 핵심: (i) C8 lemma 다단계 분해, (ii) Phase 1 OMP Amdahl-bounded 예측, (iii) EB1 진정한 fallback 경로 명시, (iv) Three-Pass canonical order DAG, (v) runs 산식 정정, (vi) ε bound 정량 protocol, (vii) NG-B6 (Availability) 신설, (viii) 사전 실측 부록 B 추가 (A1+A2 합산 기반 예측 + 첫 cherry-pick conflict 점검).

---

> **Caveat — Threat Model & Reporting Honesty (확장).**
> - **(A1 inherited):** server 가 secret_key 보유하는 단일-당사자 측정 환경. Phase 5 `decrypt → re-encrypt` 가 noise budget 회복용 단순화. **B 확장:** A1 P5a thread-local Decryptor 가 B 의 Phase 1 (D_sparse measure) + Phase 5 양쪽에서 secret_key 에 접근 → server 의 plaintext-aware 영역이 InitFHE + Phase 1 + Phase 5 로 확장.
> - **(A2 inherited):** sparse 는 단순 성능 최적화가 아니라 **신뢰 모델 의미 변경**. A2 부록 B Config A wallet 4 verdict flip 으로 입증.
> - **(B-only):** A1 P4 (data-dependent cost) + A2 Q6 (D_sparse 노출) 결합이 graph-private 모델에서 *joint timing leak* (mutual information `I(D_sparse, m1, m2 | t_init, t_phase1, t_phase3)`) 표면을 만듦. 단일-머신 sim 무관이나 future deployment 시 정량 측정 책임 (NG-B3 강화).
> - **(B-only):** B v1 의 wall-clock 예측이 *합성성 가정* 에 의존했음을 v2 에서 인정 — 예측을 점수치가 아닌 **Amdahl-bounded 구간** 으로 표현.

---

## 1. 본 단계가 공격하는 병목

A1 단독 부록 B.F3 실측: **Phase 3 22.4× 가속, total 7.1× 가속 @ nGlobal=1024**. A2 단독 부록 B.F3 실측: **Phase 1 3.03× 가속, total 1.07× 가속**. **F3 핵심 발견 — A1 미적용 시 Phase 3 가 dominant → A2 단독 ROI 약화.**

**B 가 공격하는 새 병목 + 의미:**
- **(i) A1 의 Phase 3/5 가속 × A2 의 Phase 1 가속 의 곱셈 효과** — 모든 dominant phase 동시 가속
- **(ii) 두 branch 의 합성성 검증 그 자체** (sec 11 (a) 인정) — composability 가 **검증 대상**이지 가정이 아님
- **(iii) Cost-aware BSGS** — A1 P4 (cost(N, w, D, I)) + A2 Q6 (D_sparse 보고) 결합. D_sparse-dependent (m1, m2) 선택
- **(iv) Phase 1 OMP** — A2 단독은 단일-스레드. B3 (B-only) 가 Phase 1 OMP 확장

### 1.1 BitcoinOTC 통계 (A2 v2 inherited, 정정 완료)

- 원본 35,592 행 → `parts[2] >= 2` 필터 후 **V = 3,302, E = 11,981, d̄ = 3.628**

### 1.2 통합 영역 매트릭스

| Phase | 변경 출처 | B 단계 작업 |
|---|---|---|
| Init | A1 P1 (Three-Pass galois keys), A2 Q4 (globalNodeToIndex 결정성) | B-Init: Three-Pass 키 생성 (sec 5.0 명세) |
| Phase 1 | A2 Q1 (β·thr CLI), Q4 (sorted vector), Q7 (padding bridge), Q5 (M_pub sparse) + **B3 (Phase 1 OMP, B-only)** | sparse + padding + OMP 합성 |
| Phase 2 | (둘 다 미변경) | — |
| Phase 3 | A1 BSGS + OMP + thread-local Evaluator + **B2 (sparse-aware step set, B-only)** | A2 Q8 어댑터 적용 |
| Phase 4 | A1 (결정성 정렬 + 양자화) | — |
| Phase 5 | A1 BSGS + P5a thread-local + auto-tune + A2 Q5 sparse M_pub read | EB5 read-safety 명시 |
| Phase 6 | (변경 없음) | — |

### 1.3 B-only 새 작업

- **B0 (신설).** Three-Pass canonical order — Q1 → Pass1 (default β, m1=m2=1, seed keys for measurement) → D_sparse 측정 → P2 weight 측정 → Pass2 keys + B2 (m1, m2) 확정.
- **B1.** Unified Configuration Object — A1 (giant_weight, m1, m2) + A2 (β₁, β₂, threshold) + B (D_sparse, OMP_threads) 통합.
- **B2.** Sparse-aware BSGS step set — A1 P4 cost + A2 Q6 D_sparse 결합 + **`phase_kind ∈ {pir, pr}` 인자** (architect M-OMC-4: Phase 3, Phase 5 가 다른 D 사용).
- **B3.** Phase 1 OMP (B3a per-thread accumulator + 결정론적 reduce — thread_id 순서 sequential add).
- **B4.** Combined R1''~R12'' 회귀 (sec 7 ε bound 정량 후).
- **B5.** Sybil regression in integrated context.
- **B6.** Q7 padding bridge 실측 검증 (C8 lemma 의 Pass-1 prerequisite).
- **B7 (B2 sub-task로 흡수).** Two-stage cost optimization — Phase 3 / Phase 5 에 각 D 적용.
- **B8 (신설, Fallback).** D_sparse < D_threshold 시 main-style ExtractBlindSubgraph 분기 (EB1 진정 fallback).
- **B9 (신설, OMC 누락 발견).** A1+B3 단독 cell — Phase 1 OMP 의 *마진 효과* 측정.

---

## 2. 복잡도 및 자원 모델 (v2 정정)

기호: N = nGlobal, n = nSub, V, E, d̄, K, P, D_pir, D_pr, I = 10.

### 2.1 단계별 비용 (B 통합)

| 단계 | main | A1 only | A2 only | **B 통합** |
|---|---|---|---|---|
| InitFHE | small + log N keys | + O(N) galois keys (P1 전) → O(m1+m2) (P1 후) | (main 동일) | **3 passes** (Pass1 seed 3 keys → measure → Pass2 final keys + Q5 init) |
| Phase 1 (CPU) | O(N³) | (미변경) | O(V·d̄²) | **O(V·d̄² / α(P))** (B3 OMP, Amdahl-bounded) |
| Phase 3 (per chunk) | D·T_rot | (m1+m2-2)·T_rot + D·T_mult | D·T_rot | **(m1+m2-2)·T_rot + D_pir·T_mult** (B2, m1,m2 = f(D_pir, w_pir)) |
| Phase 5 (per chunk × I) | I·D·T_rot | I·((m1+m2-2)·T_rot + D·T_mult + T_dec + T_enc) | I·D·T_rot | **I·((m1'+m2'-2)·T_rot + D_pr·T_mult + T_dec + T_enc)** (B2 phase_kind=pr) |
| OMP | 1 | P (Phase 3/5) | 1 | **P (all phases)** |

### 2.2 통합 wall-clock 예측 모델 — **Amdahl-Bounded 구간 (v2 정정)**

v1 의 *점수치 6.4s* 는 자기 모순 (sec 11 (a) 합성성 risk 자기 진술 위반). v2 는 **상한/하한 박스** 로 재정의:

**근거:**
- A1 부록 B.F3 실측 (nGlobal=1024 multi-chunk): InitFHE 3.28s, Phase 1 = 2.58s (A1 미변경), Phase 3 = 0.96s, Phase 5+6 = 4.24s, total = 11.09s
- A2 부록 B.F3 실측 (nGlobal=1024 multi-chunk): Phase 1 = 2.56s (sparse 적용), 다른 phase 미변경
- key 생성 비용 (A1 v2 H-4 표): N=1024 시 1024 keys ~3.28s → key당 ≈ 3.2 ms/key
- B-Init Pass2 keys = |S_pir ∪ S_pr| ≤ 2·(m1_pir + m2_pir) + 2·(m1_pr + m2_pr) ≈ 60 keys @ nGlobal=1024, nSub=256 → 키 시간 ≈ 0.20 s

**Phase 1 OMP 의 Amdahl 분석:**
- A2 sparse Phase 1 = 2.56s 가 (i) edge 수집 + adjacency 빌드, (ii) 2-hop loop, (iii) sparseDiag → PirDiag 직렬화 의 합
- 직렬 fraction f ∈ [0.10, 0.30] 추정 (직렬화 + reduce 가 직렬)
- P=4 OMP 시 Amdahl 가속 α(4) = 1 / (f + (1-f)/4) ∈ [2.5, 3.6]
- → Phase 1 시간 ∈ [2.56/3.6, 2.56/2.5] = **[0.71, 1.02] s**

**B 예측 구간 (nGlobal=1024 multi-chunk, P=4):**

| Phase | 하한 | 상한 | 근거 |
|---|---:|---:|---|
| InitFHE | 0.19 s | 0.30 s | Pass2 keys 60·3.2ms + Pass1 seed |
| Phase 1 | 0.71 s | 1.02 s | A2 2.56s × Amdahl(P=4, f∈[0.1,0.3]) |
| Phase 3 | 0.95 s | 1.10 s | A1 부록 B.F3 0.96s + sparse D 변동 |
| Phase 5+6 | 4.10 s | 4.50 s | A1 4.24s + Q5 hash lookup 마진 |
| **Total** | **5.95 s** | **6.92 s** | — |
| **vs main 78.30s** | **11.3× ~ 13.2×** | — |

**R10'' 임계 (v2 정정):** 실측 중앙값이 [5.95s, 6.92s] 구간을 ±15% (= [5.06s, 7.96s]) 밖으로 벗어나면 회귀. SOSP/OSDI 통상 10% 보다 약간 관대 (BSGS auto-tune 의 weight jitter 5-10% 인정).

### 2.3 메모리 모델 — **Phase 별 peak + nGlobal=4096 외삽 (v2)**

| 항목 | N=1024 | N=4096 | 비고 |
|---|---:|---:|---|
| M_pub dense (main) | 8 MB | 128 MB | A2 Q5 적용 시 제거 |
| M_pub sparse (Q5) | ~0.14 MB | ~0.6 MB | hash representation |
| outAdj | ~144 KB | ~480 KB | |
| sparseDiag (Q4 sorted) | ~2.6 MB | ~10 MB | |
| **Phase 3 baby_steps (per thread)** | 16 MB | 128 MB | m1 ≈ 32 (N=1024), 64 (N=4096) × ciphertext ~0.5MB |
| **Phase 3 baby_steps (P=4 concurrent)** | 64 MB | 512 MB | thread-local 동시 실재 |
| Phase 5 baby_steps (per thread × P) | 32 MB | 64 MB | nSub BSGS, m1' ≈ 16 |
| Galois keys (Pass 2) | 16 MB | 64 MB | (m1+m2) ≈ 32, 64 |
| **Total peak (Phase 3 dominant)** | **~95 MB** | **~600 MB** | |

**v2 정정:** v1 의 "51 MB" 는 baby_steps 의 *concurrent peak* (P=4 thread-local) 누락. nGlobal=4096 demo 의 실효 메모리는 **~600MB** — 8GB 머신에서 안전, 16GB 권장. **Q5 (sparse M_pub) 없이는 main M_pub 128MB → 추가 +128MB ⇒ 728MB**, 여전히 가능하지만 swap risk 증가.

---

## 3. 정확성 모델

### 3.1 C8 Lemma — Sparse-BSGS Pattern Equivalence (v2 다단계 증명)

**Statement (C8):** Q7 padding bridge 가 적용된 sparse 의 sparseDiag 출력이 A1 의 BSGS rotation (giant step `j·m1`) 후에도 의도된 (orig_row, orig_row+d) 위치에 정렬됨을 보장.

**Prerequisite:** Q7 가 sparse:303-307 의 row 루프를 `[0, N)` → `[0, 2N)` 로 확장하고 padding 위치에 동일 값 복제. v1 의 C8 증명은 이 prerequisite 가 *미충족* 상태에서 □ 로 마무리됨 (OMC C-OMC-1 지적).

**Multi-step Proof (v2):**

- **Step (a) — Q7 padding 의 row ∈ [N, 2N) 영역에 동일 값 보존:**  
   A2 Q7 (v2) 가 sparse:303-307 를 다음으로 확장한다 가정:
   ```cpp
   for (const auto& [row, val] : sparseDiag[d]) {
       for (size_t c = 0; c < batch_size; c++) {
           diag_flat[c * pirBlockSize + row] = val;          // 기존: row ∈ [0, N)
           diag_flat[c * pirBlockSize + N + row] = val;      // Q7 추가: padding region [N, 2N)
       }
   }
   ```
   결과: `diag[c·2N + row] = diag[c·2N + N + row]` for all c, row ∈ [0, N). ✓

- **Step (b) — Inverse map 의 유효성:**  
   A1 BSGS 의 padded diag 인코딩 (A1 sec 3.1 line 354) 은 row ∈ [0, 2N) 에 대해 `orig_row = ((row − j·m1) mod N + N) mod N`. Step (a) 의 padding 으로 row ∈ [N, 2N) 의 값이 row − N ∈ [0, N) 와 동일하므로 inverse map 이 row 전 구간에서 well-defined.  
   특히 `j·m1 < N` (A1 C2) 와 결합 시 `(row − j·m1)` 가 음수 또는 ≥ 2N 영역으로 떨어지지 않음. ✓

- **Step (c) — `d = j·m1 + i` 의 nGlobal 범위 유효성:**  
   B2 의 BSGS index 변환 `d ↔ (i, j) = (d % m1, d / m1)` 적용 시, d ∈ [0, N) 이어야 한다 (sparseDiag 의 key 범위). `(m2 − 1)·m1 ≤ N − 1` (A1 C2) 가 보장 → 모든 `(i ∈ [0, m1), j ∈ [0, m2))` 조합의 `d = j·m1 + i` 가 [0, N) 내. **단, N 이 m1 의 정수배가 아닌 경우 일부 (i, j) 조합이 d ≥ N → 코드에서 `if (d >= nGlobal) continue` 가드 필요 (A1 line 348 동일).** ✓

- **Step (d) — 청크-translation invariance 보존:**  
   sparse:303-307 의 인코딩 패턴이 모든 청크 c 에 동일 (row, val) ⇒ A1 C4 lemma 의 "Homomorphic Pattern Invariance" 직접 inherited. ✓

- **결론:** Q7 적용 후 sparse 의 sparseDiag → BsgsDiag 변환은 A1 C4 + 새 Step (a)~(d) 가 모두 성립 ⇒ rotation by `j·m1` 후 모든 청크의 의도된 위치에 sparse 값 정렬. □

**부정 경로 (Q7 미적용 시 falsification):**
- sparseDiag 의 row 가 [0, N) 만 채워진 상태에서 `j·m1 > 0` rotation 시 slot `c·2N + j·m1 + row ∈ [c·2N + j·m1, c·2N + j·m1 + N)` 가 padding region 의 *0 영역* 으로 wrap → C4 의 의도된 값이 *0 으로 덮임* → silent verdict drift. **R6'' (multi-chunk equivalence) 가 이를 자동 검출**.

### 3.2 등가성 매트릭스 — **알고리즘 차원 vs 의미 차원 분리 (v2 정정, L-1)**

| 모드 | 알고리즘 차원 | 의미 차원 |
|---|---|---|
| **B-default (β₂=0.30, thr=0.05, BSGS on, OMP on)** | A2 default 와 알고리즘 등가 (R2'') | A2 default 와 의미 등가 (예상 동일 verdict) |
| **B-C2 (β₂=1.0, thr=0, BSGS on, OMP on)** | main 과 알고리즘 등가 (R1'') | main 과 의미 등가 |
| **B-bgsg-off (β₂=0.30, thr=0.05, BSGS off)** | A2 default 와 알고리즘 등가 (R3'') | A2 default 와 의미 등가 |
| **B-sparse-off (β₂=1.0, thr=0, BSGS on)** | A1 default 와 알고리즘 등가 (R4'') | main 과 의미 등가 |

### 3.3 의미 차이 + 알고리즘 가속 분리

v2 통합 가설:
- **H_algo:** B 의 알고리즘 변경 (BSGS + OMP + sparse 누적) 이 baseline 결과를 ε_algo 내 보존.
- **H_semantic:** B 의 의미 변경 (β₂·thr) 이 A2 default 와 동일 신뢰 모델 출력.
- 둘은 **독립 검증** — R1'' (algo), R2'' (combined), R3''/R4'' (ablation).

---

## 4. 엣지 케이스 카탈로그 (B-only)

| ID | 케이스 | 거동 | 위험도 |
|---|---|---|---|
| **EB1 (정정)** | D_sparse < D_threshold (sparse-heavy) | **B8 fallback 발동**: m1=-1 sentinel → main-style ExtractBlindSubgraph 분기 (sec 5.10) | **중간**: B8 명시 후 안전 |
| **EB2** | Q1 (β·thr) ↔ D_sparse ↔ P2 weight ↔ (m1, m2) cyclic dependency | B0 Three-Pass DAG (sec 5.0) 가 fixpoint 보장 | **중간**: B0 명시 후 결정성 보장 |
| **EB3** | sparse + BSGS chunk-translation | C8 lemma + Q7 prerequisite → R6'' 회귀로 검증 | **높음 → 중간 (Q7+R6'' 적용 후)** |
| **EB4** | A2 Q4 sorted vector + B3 per-thread sparseDiag | per-thread 누적 → reduce 시 thread_id 0..P-1 순서 sequential add (결정성), 그 후 per-d sort | **중간**: B3 명세 |
| **EB5** | A1 P5a thread-local Decryptor + A2 Q5 sparse M_pub | std::unordered_map `find()` (read-only thread-safe) 사용, `operator[]` 금지 (mutating insert 위험) | **중간**: 코드 review checklist |
| **EB6** | A1 P1 Pass2 keys 이 D_sparse 작을 때 over-allocate | (m1+m2)·3.2ms × 2 ≈ 0.2s 추가, 메모리 무시 가능 | 낮음 |
| **EB7** | Q3 hub-aware + B3 OMP — d̄ 계산의 결정성 | Phase 1 OMP 전 d̄ = E/V single-thread 계산 + 모든 thread broadcast | **중간**: B3 명시 (NG-B3) |
| **EB8** | nGlobal=4096 demo Q5 sparse M_pub × A1 Phase 5 BSGS | nSub² hash lookups × P × I ≈ 2.6M (Q5 hash) 추가 cycles ≪ Phase 5 wall-clock | 낮음 |
| **EB9 (정정)** | A1 P4 D 입력 ↔ A2 Q6 D_sparse 측정의 결정성 | A2 Q4 baseline (sorted vector) + A1 globalNodeToIndex 결정성 (B-Init 의 sort) 필수 — 둘 다 baseline | **중간 (Q4 baseline 강제 후 낮음)** |
| **EB10 (정정)** | Phase 1 OMP sparseDiag race | B3a per-thread accumulator + sequential reduce (thread_id 순서) — atomic 불필요 | **중간**: B3 명세 |
| **EB11** | Phase 5 ITERATIONS=10 × Q5 sparse M_pub × B3 OMP | thread-local M_pub copy 불필요 (read-only), sparse Q5 의 std::unordered_map find() 이 read-concurrent thread-safe | 낮음 |
| **EB12** | A1 weight_cap=5.0 + A2 D_sparse-sensitive m1 ⇒ cross-run 일관성 | Q4 baseline (globalNodeToIndex sort + sparseDiag sorted) 필수. fixpoint 가 보장된 B0 Three-Pass DAG | **중간 → 낮음 (B0 적용 후)** |
| **EB13 (신설)** | cherry-pick conflict — sparse Phase 1 ↔ bgsg Phase 1 의 동일 영역 변경 | 부록 B 의 conflict 점검 결과: **PreparePublicData 시그니처 충돌** (A1 m1, m2 인자 vs A2 PhaseOneOutput return) → 수동 해소 + R4'' 회귀 즉시 실행 | **높음 (해소 가이드 sec 5.11)** |
| **EB14 (신설)** | Q3 hub-aware 의 d̄ 계산이 B3 OMP 와 race | sec 5.3 명시: d̄ 는 OMP 외부 single-thread 계산 후 const 공유 | **중간** |
| **EB15 (신설)** | A1 P2 auto-tune (weight 측정) + B2 (D_sparse 입력) 둘 다 (m1, m2) 결정 — 우선순위 | B0 Three-Pass 가 결정: Pass1 default → measure both (D_sparse, weight) → Pass2 single (m1, m2) 산출 | **중간** |
| **EB16 (신설)** | nGlobal=4096 + ITERATIONS=10 의 noise budget | A1 sec 2.2 의 coeff_modulus {60,45,45,60} useful depth 2 vs required depth 10 (Phase 5 decrypt/re-encrypt 의존) — B 가 이 의존 inherited. EB16 자체는 새 위험 아님 | 낮음 |
| **EB17 (신설, OMC)** | Q5 std::unordered_map `operator[]` 가 미존재 key 시 mutating default-construct → Phase 5 inner loop 의 read-only 가정 silent 위반 | 코드 review checklist: `find()`/`at()` 만 허용 | **중간** |

---

## 5. 강화안 (v2)

### 5.0 [B0] Three-Pass Canonical Order — **Cyclic Dependency 해소 (v2 신설, C-4)**

A1 의 Two-Pass (seed measure → final keys) + A2 의 Q1 root prerequisite + B2 의 D_sparse-dependent (m1, m2) 의 cycle 을 **Three-Pass** 로 분해:

```
Pass 1 (Bootstrap):
  - Parse Q1 CLI (β₁, β₂, threshold)
  - Generate seed Galois keys: S_seed = {1, ⌊√N⌋, ⌊√n⌋}  (3 keys)
  - Phase 1 (sparse) 실행 with default β·thr → output (sparseDiag, D_sparse, nnz_total)
  - Q5 M_pub sparse representation 구축

Pass 2 (Measurement):
  - Encrypt dummy ciphertext at Phase 5 BSGS level (rescale 1회 후)
  - Measure baby_time, giant_time → real_weight = T_giant / T_baby (5회 중앙값, A1 P2)
  - Cap weight ∈ [1.0, 5.0]
  - Find (m1_pir, m2_pir) = FindOptimal(nGlobal, real_weight, D_sparse, ITERATIONS, phase_kind=pir)
  - Find (m1_pr, m2_pr) = FindOptimal(nSub, real_weight, D_pr_estimate, ITERATIONS, phase_kind=pr)
  - 단, D_pr_estimate = nSub² (Phase 5 dense subgraph 가정), Phase 5 1-iter 후 실측 D 로 갱신 옵션

Pass 3 (Production):
  - S_pir = {1..m1_pir-1} ∪ {m1_pir, 2m1_pir, ..., (m2_pir-1)m1_pir}
  - S_pr  = {1..m1_pr-1}  ∪ {m1_pr, 2m1_pr, ..., (m2_pr-1)m1_pr}
  - S_union = S_pir ∪ S_pr
  - Regenerate Galois keys with S_union (Pass 1 seed keys 폐기)
  - Proceed with Phase 3 → Phase 4 → Phase 5
```

**Fixpoint 보장:** Pass 2 의 measure 가 Pass 1 의 D_sparse 에만 의존하고, β·thr 는 Q1 CLI 로 고정 → R11'' (cross-run 일관성) well-defined.

**v1 → v2 변경:** v1 의 sec 10 DAG 가 "Q4 → Q1 → ..." 의 logical order 만 명시했음. v2 는 **데이터 의존 cycle 을 명시적 Pass 로 분해**.

### 5.1 [B1] Unified Configuration Object (v2 명세 명확화)

```cpp
struct RunConfig {
    double beta1 = 1.0;
    double beta2 = 0.30;
    double threshold = 0.05;
    double giant_weight = -1.0;  // -1.0 = auto-tune (Pass 2)
    int m1_pir = -1, m2_pir = -1;  // -1 = auto (Pass 2)
    int m1_pr = -1, m2_pr = -1;
    int omp_threads = 4;
    int iterations = 10;
    int sybil_inject_count = 0;  // R8'' 측정용
};
```

CLI: `-b1 -b2 -thr -w -m1pir -m2pir -m1pr -m2pr -omp -iter -sybil` 개별 flags. positional = wallet IDs. 명세: spec sec 5.1 의 verbatim.

**Log redaction (NG-B7, v2 추가):** RunConfig 의 log 출력 시 `[CONFIG]` prefix + production deployment 시 `-quiet` flag 로 비활성화.

### 5.2 [B2] Sparse-Aware BSGS Step Set with `phase_kind` (v2 정정, OMC M-OMC-4)

```cpp
BSGSParams FindOptimalAsymmetricBSGS(
    int N, double weight, int D, int I_factor, PhaseKind phase_kind
);
```

- `phase_kind = pir` → I_factor = 1 (Phase 3 한 번)
- `phase_kind = pr` → I_factor = 10 (Phase 5 ITERATIONS)
- cost function:
  ```
  cost_pir(m1, m2) = m1·T_rot + (m2 − 1)·T_giant + D·T_mult
  cost_pr(m1, m2)  = I · (m1·T_rot + (m2 − 1)·T_giant + D·T_mult + T_enc + T_dec)
  ```

**B7 흡수:** Phase 3, Phase 5 의 cost 가 다른 D 와 다른 I 로 독립 최적화 → v1 의 B7 옵션이 B2 에 흡수됨.

### 5.3 [B3] Phase 1 OMP Parallelization (v2 명세 강화)

**B3a per-thread accumulator + sequential reduce:**
```cpp
#pragma omp parallel
{
    vector<unordered_map<int, double>> sparseDiag_local(nGlobal);  // per-thread
    #pragma omp for schedule(static)
    for (int src = 0; src < nGlobal; src++) {
        // ... A2 sparse loop, write to sparseDiag_local
    }
    // Sequential reduce — thread_id 순서 보장 (결정성)
    #pragma omp critical
    {
        int tid = omp_get_thread_num();
        for (int d = 0; d < nGlobal; d++) {
            for (auto& [row, val] : sparseDiag_local[d]) {
                sparseDiag[d][row] += val;  // FP 누적 순서 = thread_id 오름차순
            }
        }
    }
}
// 그 후 Q4: per-d sort (sparseDiag[d] → vector<pair<int,double>> 정렬)
```

**Race-free 가정:** `#pragma omp critical` 의 thread_id 순서가 보장됨 (OpenMP 4.5+ `omp_get_thread_num()` 결정성).

**hub d̄ 계산 (EB14):** OMP 외부에서 `d̄ = E / V` single-thread 계산 → const 변수로 모든 thread 공유.

**메모리:** P × nnz_diag = 4 × 2.6 MB = 10.4 MB @ nGlobal=1024 (sec 2.3).

**Amdahl bound:** sec 2.2 의 f ∈ [0.10, 0.30] 가정 → α(P=4) ∈ [2.5, 3.6].

### 5.4 [B4] Combined R1''~R4'' 회귀

- **R1'' (B-C2 ≡ main):** β₂=1.0, thr=0, BSGS on, OMP on → main 등가. **β₂ 명시 (v2, OMC 누락 발견 #2).**
- **R2'' (B-default ≡ A2 default):** BSGS noise 만큼 차이.
- **R3'' (B-bgsg-off, β₂=0.30, thr=0.05 ≡ A2 default):** A1 효과 분리.
- **R4'' (B-sparse-off, β₂=1.0, thr=0 ≡ A1 default):** A2 효과 분리.

ε 값: sec 7 측정 protocol.

### 5.5 [B5] Sybil Regression in Integrated Context (v2 정정)

**baseline 정의 (OMC M-OMC-5):**
- Sybil cluster: BitcoinOTC 의 `parts[2] == 2` (최소 trust) + out-degree = 1 subset, **목표 크기 n_sybil ≥ 50** (95% CI ±0.13 보장).
- 합성 sybil: 50 노드 mutual-edge cluster, weight=2 균등.
- 4-way TPR/FPR 측정: main / A1 / A2 / B 각 mode 에서 sybil node 의 fheScore 분포 비교.

**Bias vs Variance 분리:**
- Within-mode: N=10 회 → variance (race effects)
- Mode 간: median 차이 → bias (BSGS noise + sparse semantic shift)

### 5.6 [B6] Q7 Padding Bridge 실측 검증

A1 부록 B Config B 환경 (9 targets, 5 chunks) 에서 B-C2 출력 vs main 출력 비교. **R6'' (multi-chunk equivalence)** 가 C8 lemma 의 데이터 검증.

### 5.7 ~ 5.9 (생략, v1 동일)

### 5.10 [B8] D_sparse Fallback Branch (v2 신설, EB1 진정 해결)

```cpp
const int D_THRESHOLD = static_cast<int>(2 * sqrt(nGlobal));  // ~2(m1+m2-2) 최소

vector<Ciphertext> ExtractBlindSubgraph(...) {
    if (D_sparse < D_THRESHOLD) {
        // Fallback: main-style direct rotation
        return ExtractBlindSubgraphFallback(...);  // 새 함수, main 의 line 348-371 패턴
    }
    // 기존 BSGS path
    ...
}
```

`D_THRESHOLD` 의 정당화: BSGS 비용 `m1+m2-2 ≈ 2√N − 2` vs main 비용 `D_sparse`. 후자가 더 작으면 BSGS 가 역효과. 즉 `D_sparse < 2√N` 시 BSGS 우회.

### 5.11 B-Init Cherry-Pick Conflict 해소 가이드 (v2 신설, EB13)

**예상 충돌 영역:**
| 충돌 위치 | 해소 방향 |
|---|---|
| `PreparePublicData` 시그니처: A1 `(M_pub&, m1, m2)` vs A2 `(M_pub&)` + Q6 PhaseOneOutput 반환 | A2 wins: `PhaseOneOutput PreparePublicData(M_pub&, const RunConfig&)` |
| `pirDiagonals` 타입: A1 `vector<BsgsDiag>` vs A2 `vector<PirDiag>` | A2 출력 → Q8 어댑터 → A1 BsgsDiag 변환 |
| `ExtractBlindSubgraph` 시그니처 | A1 시그니처 유지 + B8 fallback 분기 추가 |
| globalNodeToIndex 결정성 | A1 + A2 의 unordered_map → 양쪽 sort 강제 |

**LOC delta 추정 (Critical OMC H-OMC-1, M-OMC-1):**
| 변경 | LOC delta |
|---|---:|
| A2 cherry-pick (Phase 1 sparse) | ~50 |
| Q8 어댑터 (PirDiag → BsgsDiag) | ~30 |
| B0 Three-Pass DAG | ~80 |
| B1 RunConfig + CLI | ~100 |
| B2 cost function + phase_kind | ~40 |
| B3 OMP per-thread | ~60 |
| B8 fallback path | ~50 |
| Q4 baseline (globalNodeToIndex sort) | ~10 |
| Q5 M_pub sparse | ~80 |
| **Total** | **~500 LOC delta** |

**Effort:** ~12-18h B-Init + sec 2 의 예측 측정 ~6h + 디버깅 ~10h = **~3-4일** 단일 개발자.

---

## 6. 측정 계획 (v2 정정)

### 6.1 비교군 — Ablation 분리 + OMC 누락 발견 #1

| ID | 구성 | 검증 |
|---|---|---|
| C0 | `main` baseline | reference |
| C1 | A1 default (bgsg + H-2 patch) | A1 부록 B 재현 |
| C2 | A2 default (sparse) | A2 부록 B 재현 |
| C3 | **B default (β₂=0.30, thr=0.05, BSGS on, OMP on)** | end-to-end B |
| C4 | **B-C2 (β₂=1.0, thr=0, BSGS on, OMP on)** | R1'' main 등가 |
| C5 | **B + B8 fallback active** | EB1 fallback 검증 |
| C6 | B with Q5 sparse M_pub on/off | Q5 효과 |
| C7 | **B-no-Phase1-OMP (B3 비활성)** | B3 마진 효과 (OMC 누락 #1 해결) |
| **C8 (v2 추가)** | **main + B3 (Phase 1 OMP, sparse 없음)** | B3 단독 마진 (불가능 — main 은 sparse 없음 → 의미 없음, **삭제 권장**) |
| **C8' (v2 신설)** | **A2 + B3 (sparse + Phase 1 OMP, BSGS 없음)** | OMC 누락 #1 — Phase 1 OMP 의 sparse-only 마진 |

→ **v2 C 정의 최종: C0-C7 + C8' = 9 configs.**

### 6.2 Sweep — **산식 정정 (v2)**

**v1 오류:** "Coarse 720" 실제는 1,200 (3 nGlobal × 2 num_targets × 2 OMP × 9 configs × N=10 = 1,080... wait, with 9 configs × 3 × 2 × 2 × 10 = 1,080). 정정 후:

- **Coarse:** nGlobal ∈ {256, 1024, 2048} × num_targets ∈ {4, 16} × OMP ∈ {1, 4} × C0~C7+C8' (9 configs) × **N=5** = **540 runs**
- **OMP-axis sweep (v2 신설, R9'' 위해):** nGlobal=1024 × num_targets=16 × OMP ∈ {1, 2, 4, 8, 16} × C3 × N=5 = **25 runs**
- **Demo:** nGlobal=4096 × num_targets=4 × OMP=4 × {C1 (A1 단독 slow but possible), C3, C6} × N=3 = **9 runs** (C0, C2 N/A 명시: main 메모리 256MB+, A2 단독 Phase 5 ~수분)
- **Fine β·weight 3×3 grid:** nGlobal=1024 × OMP=4 × C3 × **N=10** = **90 runs**

**총 664 runs.** v1 의 816 → v2 664. 단위 시간 (A1+A2 부록 B 합산 추정):

| Config | nGlobal=256 | nGlobal=1024 | nGlobal=2048 |
|---|---:|---:|---:|
| C0 main | 4s | 78s | ~10 min |
| C1 A1 | 2s | 11s | ~1.5 min |
| C2 A2 | 4s | 73s | ~10 min |
| C3 B (예측) | 2s | 6s | ~50s |

Coarse 총합 (대략): ~7시간. OMP-axis ~5분. Demo ~5-10분 (4096 의 C1 단독 ~수분, C3 ~1-2분). Fine ~15분. **총 ~8시간** (P=4 머신).

### 6.3 메트릭 (v2)

A2 v2 + A1 v2 inherited + B 신규:

| 카테고리 | 메트릭 | 단위 |
|---|---|---|
| 시간 | InitFHE (Pass 1 / Pass 2 / Pass 3 분리), Phase 1, 3, 5 wall-clock | sec |
| 시간 | 가속비 (median over N reps) | dimensionless |
| 메모리 | Peak RSS, baby_steps concurrent peak, Galois keys | MB |
| 알고리즘 | D_pir / nGlobal, D_pr / nSub, (m1, m2) per phase | various |
| 정확도 | R1''~R4'' ε-bound 위반 횟수 / N reps | int |
| 정확도 (semantic) | B vs main FHE score per target, Cohen's d, top-K Kendall τ (K=min(nSub,10)) | abs + unitless + -1~1 |
| 결정성 | R9'' OMP cross-run max diff | abs |
| **Sybil (v2 정정)** | TPR/FPR with 95% bootstrap CI, n_sybil ≥ 50 보장 | 0~1 |
| **C4/C8 lemma** | R6'' multi-chunk per-chunk output equivalence | abs |

### 6.4 통계 프로토콜 (v2 정정)

- **시간 / 의미 차이 메트릭:** Kruskal-Wallis (4-way main/A1/A2/B 동시) → 유의 시 pairwise Wilcoxon + Benjamini-Hochberg FDR 5%. log₂(median ratio) effect size 모든 쌍.
- **등가성 메트릭 (R1''~R4'', R6'', R9''):** assertion (max|diff| < ε), 0/1 pass/fail per run.
- **Sybil bootstrap:** 1000-resample, n_sybil ≥ 50.

### 6.5 환경 고정 — v2 정정 (A1 + A2 명세 완전 복제)

- CPU governor `performance`, OMP_PROC_BIND=close, OMP_PLACES=cores
- **OMP_NUM_THREADS 명시 (v2 명세):** runner script 가 `RunConfig.omp_threads` 값을 `export OMP_NUM_THREADS=$P` 로 매 run 마다 export
- CSV SHA-256 검증 + 빌드 매니페스트 JSON (cmake, compiler, SEAL_commit, kernel, THP state)
- SEAL `UniformRandomGeneratorFactory` seeded
- **Q4 baseline (v2 강제):** globalNodeToIndex + sparseDiag 모두 sorted, 모든 config 에 적용
- 실험 순서 무작위화 + 60s idle 사이

---

## 7. 정확성 회귀 테스트 (v2 ε bound 정량)

### ε 측정 protocol (v2 신설, OMC H-OMC-3)

B 진입 전 1회 사전 실험:
1. B-C2 모드 실행, raw double precision (`setprecision(15)`) 출력
2. main 실측치와 비교 → max_observed_diff 측정
3. ε = max_observed_diff × 10 (safety margin)
4. spec sec 7 ε 행 채움

### 회귀 정의

- **R1''** (B-C2 ≡ main): ε_R1'' = ? (사전 실험 후 갱신, 추정 ~1e-6)
- **R2''** (B ≡ A2): ε_R2'' = ? (BSGS noise + sparse 결합, 추정 ~5e-6)
- **R3''** (B-bgsg-off ≡ A2 default): ε_R3'' = ? (추정 ~1e-7)
- **R4''** (B-sparse-off ≡ A1 default): ε_R4'' = ? (추정 ~1e-7)
- **R5''** (Verdict 일치): ±10% threshold 회피
- **R6''** (Multi-chunk equivalence, C8 lemma): ε_R6'' = ε_R2''
- **R7''** (Phase 5 parity, A2 R7' 통합): wall-clock ± 5%
- **R8''** (Sybil regression): n_sybil ≥ 50, TPR/FPR 95% CI
- **R9''** (Determinism across OMP): ε_R9'' = ε_R2'' × 2 (multi-thread FP 비결합)
- **R10''** (Performance prediction): 실측 median ∈ [5.06, 7.96] s @ nGlobal=1024 multi-chunk (15% 허용)
- **R11''** (Cross-run (m1, m2) consistency): N=10 회 동일 입력 → 동일 (m1, m2) (B0 Three-Pass fixpoint)
- **R12''** (Q5 random-access correctness): Phase 5 출력 dense access 대비 ε ≤ 10⁻¹⁰

---

## 8. 개방 문제

A1 + A2 inherited + B-only:

- **OB1.** B2 + Q1 + P2 의 fixpoint 가 B0 Three-Pass 로 보장되나, fixpoint convergence rate 측정 (Pass 1 → Pass 3 의 (m1, m2) 차이) 가 별도 측정 필요
- **OB2.** Q3 hub-aware + B3 OMP — d̄ 계산 single-thread 정합성 검증
- **OB3.** P6 (baby_step reuse) 의 B 단계 적용 — coeff_modulus 확장 필요
- **OB4.** nGlobal=4096 의 noise budget — coeff_modulus {60, 45, 45, 60} 가 충분한지 측정
- **OB5.** A1 P5b TSan + B3 Phase 1 OMP 의 false positive 폭주 — suppress 리스트
- **OB6.** A2 NG11 (BitcoinOTC tuning) 의 multi-dataset generalization (Slashdot, Epinions) — B 단계 future work
- **OB7.** B 가 main 대비 nGlobal=4096 에서 비교 baseline 부재 → A1 단독 4096 으로 대체 measurement

---

## 9. 비-목표

A1 NG1-NG8 + A2 NG1-NG12 inherited. B-only 신규 + v2 정정:

- **NG-B1.** B 가 nGlobal=4096 에서 main 보다 빠름을 단정하지 않음
- **NG-B2.** B 가 항상 A1 / A2 단독보다 빠름을 단정하지 않음
- **NG-B3.** **(보안)** Joint timing leak (D_sparse, m1, m2 | t_init, t_phase1, t_phase3) 의 정량 — mutual information metric 권고, 단일-머신 sim 무관
- **NG-B4.** **(보안)** Galois key step set 협상 fingerprinting — A1 NG7 + A2 NG10 결합 표면
- **NG-B5.** **(보안)** B 의 sybil 방어 정량 평가 — TPR/FPR 측정값은 정량화일 뿐 audit 책임은 future
- **NG-B6 (v2 신설, security M-OMC-6).** **(보안)** Availability attack via Q2 × B2 — adversary controlled edge 분포 → threshold → D_sparse → (m1, m2) 의 cascading 변동. 단일-머신 sim 무관
- **NG-B7 (v2 신설).** **(보안)** Env/config integrity — OMP_NUM_THREADS, RunConfig 의 server-side 조작 표면 (deployment 가정 시 critical)
- **NG-B8 (v2 신설).** **(보안)** B-Init cherry-pick 의 brand-new code injection — CI/리뷰어 책임. spec 본문 외부

---

## 10. 의존성 DAG (v2 Three-Pass 재구성)

```
[Stage A 완료 — prerequisite]
   A1 v2 완료 + H-2 코드 패치
   A2 v2 완료

[B-Init]
   Step 1: Branch 'feat/bgsg-sparse-integrated' 생성 (베이스 = A1 HEAD '85b3e04')
   Step 2: A2 sparse Phase 1 변경 cherry-pick → EB13 가이드로 충돌 해소
   Step 3: B1 RunConfig 도입 → 모든 메서드 시그니처 unified

[B-Pipeline — Three-Pass]
   B0 Pass 1: seed keys + Phase 1 sparse + D_sparse 출력 + Q5 M_pub
       │
       ▼
   B0 Pass 2: dummy ciphertext + weight measure + B2 (m1, m2) 결정 per phase
       │
       ▼
   B0 Pass 3: final Galois keys + Phase 2-6 실행 + B8 fallback 분기

[B-Validation — sweep 진입 전 prerequisite]
   B6 (Q7 padding bridge + R6'' multi-chunk equiv)
       │
       ▼
   R1''~R4'' ε bound 사전 측정 (sec 7 protocol)
       │
       ▼
   sec 6 sweep 실행
       │
       ▼
   R10''~R12'' + Sybil R8'' 결과 보고
```

---

## 11. 엔지니어링 노트 (v2)

A1 v2 / A2 v2 inherited (a)~(e) + v2 신규:

- **(g) (v2)** **합성성 (composability) 의 자기 진단** — sec 11 (a) 의 "합성성이 가장 큰 위험" 자기 진술을 sec 2.2 의 점수치 예측이 위반한 v1 의 self-contradiction. v2 는 Amdahl-bounded 구간 + R10'' 15% 허용으로 자기 진단 정합.
- **(h) (v2)** **부정 경로 (falsification path) 의 명시** — C8 lemma 의 *Q7 미적용 시 silent verdict drift* (sec 3.1 부정 경로) 가 R6'' 회귀로 자동 검출 가능함을 명시. 학술적 정직성.
- **(i) (v2)** **사전 실측의 inherited 통과** — A1 부록 B + A2 부록 B 가 B 의 예측 모델의 기초 데이터. 이는 *합성성* 의 합리적 추정 근거. 그러나 통합 후 실측은 별도 (sec 7 R10'' 검증).

---

## 부록 A — 변경 코드 참조 색인 (B 통합 기준)

### A1 inherited
- `CipherRank.cpp:49-58` BsgsDiag
- `CipherRank.cpp:81-105` FindOptimalAsymmetricBSGS (B2 에서 시그니처 확장)
- `CipherRank.cpp:131-138` public_key, secret_key 멤버 (H-2 패치 적용 완료)
- `CipherRank.cpp:244-246` Galois key step (B0 Three-Pass 로 변경)
- `CipherRank.cpp:407-460` Phase 3 OMP BSGS (B8 fallback 분기 추가)
- `CipherRank.cpp:582-684` Phase 5 OMP BSGS

### A2 inherited (cherry-pick)
- sparse:228 음의 trust 필터 (E19 명시)
- sparse:262 outAdj
- sparse:265-273 Phase 1 edge 수집 + M_pub 채움
- sparse:277 sparseDiag (Q4 sorted + B3 per-thread)
- sparse:279-281 β·threshold (B1 RunConfig 로 통합)
- sparse:283-295 sparse 2-hop loop (B3 OMP + Q3 hub-aware)
- sparse:297-313 sparseDiag → PirDiag 직렬화 (Q7 padding bridge: row [0, 2N))

### B-only 신규
- `RunConfig` struct (B1)
- `PhaseKind` enum (B2)
- `PreparePublicData(M_pub&, const RunConfig&)` → `PhaseOneOutput` (Q6 + B1)
- `FindOptimalAsymmetricBSGS(N, weight, D, I, phase_kind)` (B2)
- `ExtractBlindSubgraph` 의 B8 fallback 분기
- Phase 1 OMP per-thread accumulator (B3)
- Q8 어댑터 `sparseDiag → BsgsDiag` 변환

---

## 부록 B — 사전 실측 + B 예측 모델 (v2 신설)

본 부록은 (i) A1 부록 B + A2 부록 B 의 실측 데이터를 통합해 B 의 wall-clock 을 예측, (ii) cherry-pick conflict 영역 확인, (iii) F-Findings 형식으로 v2 의 가설을 명시한다. **본 부록은 사전 실측이며, 실제 B 구현 후 R10'' 결과로 갱신해야 한다.**

### B.1 A1 + A2 실측 데이터 (inherited)

| 환경 | Config | InitFHE | Phase 1 | Phase 3 | Phase 5+6 | Total |
|---|---|---:|---:|---:|---:|---:|
| nGlobal=256 multi-target | main | 0.09 | 0.74 | 0.91 | 2.07 | 3.82 s |
| nGlobal=256 multi-target | A1 | 0.83 | 0.67 | 0.12 | 0.61 | 2.24 s |
| nGlobal=256 multi-target | A2 | 0.10 | 0.66 | 0.91 | 2.09 | 3.76 s |
| nGlobal=1024 multi-chunk | main | 0.09 | 7.73 | 21.55 | 48.90 | 78.30 s |
| nGlobal=1024 multi-chunk | A1 | 3.28 | 2.58 | 0.96 | 4.24 | 11.09 s |
| nGlobal=1024 multi-chunk | A2 | 0.09 | 2.56 | 21.47 | 48.90 | 73.05 s |

### B.2 B 예측 합성 모델 (Amdahl-bounded)

**가정:**
- Phase 1 = A2 측정치 × 1/α(P=4), α ∈ [2.5, 3.6] (sec 2.2)
- Phase 3 + Phase 5+6 = A1 측정치 (BSGS+OMP 동일, sparse 가 영향 적음 — sparse 의 D_sparse < D_main 시 Phase 3 약간 빨라질 수 있으나 noise 수준)
- InitFHE = A2 측정치 (0.09s) + B0 Pass 2/3 keys (~0.20s) ≈ 0.29s
- Q5 M_pub sparse: Phase 5 inner-loop 의 hash lookup overhead 무시 (~1%)

**예측 (nGlobal=1024 multi-chunk):**

| Phase | A1 | A2 | B 예측 하한 | B 예측 상한 | 근거 |
|---|---:|---:|---:|---:|---|
| InitFHE | 3.28 | 0.09 | 0.19 | 0.30 | A1 H-4 외삽 |
| Phase 1 | 2.58 | 2.56 | 0.71 | 1.02 | A2 / α(P=4) |
| Phase 3 | 0.96 | 21.47 | 0.95 | 1.10 | A1 보존 + sparse D 변동 |
| Phase 5+6 | 4.24 | 48.90 | 4.10 | 4.50 | A1 보존 + Q5 hash 마진 |
| **Total** | 11.09 | 73.05 | **5.95** | **6.92** | — |
| **vs main 78.30s** | 7.1× | 1.07× | **11.3×** | **13.2×** | — |

### B.3 Cherry-pick Conflict 사전 점검 (v2 신설)

A1 HEAD 와 sparse 의 `PreparePublicData` 영역을 비교하면 다음 충돌 예상:

| 충돌 영역 | A1 (HEAD) | sparse | 해소 (sec 5.11) |
|---|---|---|---|
| `vector<BsgsDiag> PreparePublicData(M_pub&, int m1, int m2)` | A1 시그니처 | `vector<PirDiag> PreparePublicData(M_pub&)` | A2 algorithm + A1 BsgsDiag 출력 (Q8 어댑터) |
| `pirDiagonals` 타입 | `BsgsDiag {i, j, plain}` | `PirDiag {d, plain}` | A2 sparseDiag → d → (i, j) 변환 |
| line 353 row 루프 | `for (row = 0; row < nGlobal*2; row++)` (A1 padding) | `for ([row, val] : sparseDiag[d])` (sparse) | Q7 — sparse 의 row 루프를 [0, 2N) 확장 |
| `outM_pub[tgt][src] += w` | (없음, M_total dense 계산) | sparse 의 1-hop 채움 | A2 sparse 채움 wins |

**예상 conflict 수: ~4-6 영역, 모두 sec 5.11 가이드로 해소 가능.**

### B.4 F-Findings (v2 예측 단계)

- **F1 (예측).** Phase 1 OMP 효과는 Amdahl serial fraction f 의 함수. f ≤ 0.2 가정 시 가속비 ≥ 2.5×.
- **F2 (예측).** Phase 3 / Phase 5 는 A1 결과 보존. B 의 추가 마진 (sparse D_sparse 감소) 은 ≤ 10%.
- **F3 (예측).** Total 12×~13× speedup 이 가능. 이는 A1 단독 7.1× 의 약 1.7× 추가 마진. 추가 마진의 근원은 Phase 1 sparse + OMP.
- **F4 (예측).** Q5 sparse M_pub 의 효과는 nGlobal=4096 demo 에서 *enabler*. nGlobal=1024 에서는 성능 차이 미미 (~1%).
- **F5 (예측).** B-C2 모드 (R1'') 의 ε ≈ R1 (A1) 의 5×10⁻⁷ 와 R1' (A2 C2 mode) 의 0 의 결합 — 추정 ε ≈ 5×10⁻⁷. **사전 측정 필수.**
- **F6 (예측).** Verdict flip — A2 부록 B 의 wallet 4 flip 이 B-default 에서 보존되어야 함 (sparse semantic 그대로 inherited).

### B.5 실측 vs 예측 검증 (R10'' 의 책임)

B 구현 완료 후:
1. Config A (-g 256 -s 64), Config B (-g 1024 -s 256 multi-chunk) 동일 환경 실행
2. 실측 Phase별 wall-clock vs sec B.2 예측 비교
3. 실측이 [5.95, 6.92] s 의 ±15% 인 [5.06, 7.96] s 범위 시 R10'' pass
4. 범위 외 시: Amdahl serial fraction f 재측정 + spec sec 2.2 갱신

---

## 부록 C — v1 → v2 변경 이력

| v1 위치 | 변경 |
|---|---|
| sec 3.1 C8 lemma | **C-1**: 다단계 (a)~(d) Proof + 부정 경로 명시 + Q7 prerequisite 강조 |
| sec 2.2 wall-clock 예측 | **C-2**: 점수치 6.4s → Amdahl-bounded 구간 [5.95, 6.92] s |
| sec 5 B8 fallback 신설 + EB1 정정 | **C-3**: 진정한 main-style 분기 명시 |
| sec 5.0 B0 Three-Pass 신설 | **C-4**: Q1 ↔ D_sparse ↔ P2 의 fixpoint canonical order |
| sec 6.2 sweep 산식 | **C-5**: 816 → 664 runs (configs 9 + N=5 Coarse) |
| sec 2.2 InitFHE | **H-1**: 0.5s → A1 key 비용 외삽 0.19~0.30s |
| sec 7 ε 측정 protocol | **H-2**: 모든 R'' 에 ε 측정 사전 실험 명시 |
| 부록 B 신설 | **H-3**: A1+A2 실측 합산 예측 + conflict 점검 + F-Findings |
| sec 5.3 OMP axis | **H-4**: 단일 위치 정의, sec 5.3 / sec 6.2 / sec 7 R9'' 일관 |
| Caveat 박스 + NG-B3 / NG-B4 | **H-5**: mutual information metric 권고 |
| R10'' 30% → 15% | **H-6**: SOSP/OSDI 통상 + BSGS jitter 인정 |
| sec 5.11 B-Init effort | **H-7**: LOC delta 추정 + cherry-pick conflict 가이드 |
| sec 6.1 C8' 신설 | **H-8**: OMC 누락 #1 — A2 + B3 단독 |
| sec 4 EB13~EB17 신설 | OMC + critic 신규 EB |
| sec 5.4 R3'' β₂ 표기 | OMC 누락 #2 |
| sec 5.2 B2 phase_kind | OMC M-OMC-4 |
| sec 4 EB5 Q5 find() 명시 | OMC 누락 #5 |
| sec 5.5 B5 baseline | OMC M-OMC-5 |
| sec 9 NG-B6~NG-B8 신설 | security M-OMC-6 |
| sec 2.3 메모리 표 | baby_steps Phase 3 + 4096 외삽 |
| sec 11 (g)(h)(i) | 자기 진단 + 부정 경로 + 사전 실측 inherited |
