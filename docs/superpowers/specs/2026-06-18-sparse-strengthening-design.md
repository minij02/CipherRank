# Stage A2 — `feat/sparse-twohop-precompute-experiment` 보강안 설계 문서

- **날짜:** 2026-06-18
- **대상 브랜치:** `feat/sparse-twohop-precompute-experiment` (HEAD: `dc75ee8`)
- **기준선:** `main` (HEAD: `8c3aee3`)
- **단계:** A2 (독립 강화). A1 (bgsg) 완료 후 진행. 후속으로 B (통합) 예정.

---

> **Caveat — Semantic Divergence from Baseline.** sparse 브랜치는 **단순 성능 최적화가 아니다**. main의 2-hop 집계가 `M_pub + M_pub²` (β₁=β₂=1, 비-pruned) 인 반면, sparse는 `β₁ · M_pub + β₂ · M_pub²_pruned` (β₁=1.0, β₂=0.30, w₁ < 0.05 인 1-hop은 2-hop 전파 차단)로 **다른 신뢰 모델을 계산한다**. 따라서 sparse vs main의 Phase 6 출력 차이는 "노이즈"가 아니라 **정의 차이**이다. 본 spec의 정확성 검증(R*)은 두 차원을 분리:
> - **(i) 알고리즘 등가성:** sparse의 `sparseDiag[d][row]` 가 같은 모델(같은 β·pruning)을 dense matmul로 계산한 결과와 동등한가?
> - **(ii) 신뢰 모델 정합성:** sparse의 trust score가 main 대비 sybil 방어 목적상 더 나은가/같은가/더 나쁜가? — Stage A2 범위 밖이지만 측정값을 보고.

---

## 1. 본 브랜치가 공격하는 병목

main의 `PreparePublicData` 는 `M_total = M_pub + M_pub · M_pub` 을 **dense N×N matmul**(`CipherRank.cpp:334-341` on main)로 계산한다. N=1024에서 ≈ 10⁹ 부동소수점 곱셈, 단일 스레드. A1 R1 실측에서 **main의 Phase 1 wall-clock = 7.73초 @ nGlobal=1024** (전체 78.3초 중 10%). nGlobal=2048에서 ≈ 8 × 7.73 = **62초** 로 증가, 전체의 dominant term 가능 (A1 부록 B.F4).

sparse 브랜치는 **(i) 중간 N×N 행렬 자체를 제거**하고 **(ii) 인접 리스트 순회로 대각선을 직접 누적**한다. 이론적 복잡도 `O(N³) → O(V·d̄²)` (d̄ = 평균 out-degree). BitcoinOTC는 sparse (≈ 35K edges, 5.8K nodes → d̄ ≈ 6) → 실효 복잡도 `O(V·36) ≈ O(N)` 으로 추정.

### 1.1 변경 영역 요약

| 위치 | 변경 | 영향 |
|---|---|---|
| Adjacency list 구성 (line 262, 273) | `outAdj[srcIdx]` 빌드 | 1-hop 인접 리스트 |
| sparseDiag hashmap (line 277) | `vector<unordered_map<int,double>>` | 대각선별 row→val 직접 저장 |
| β-weighted 2-hop loop (line 283-295) | `β₁ · w₁ + β₂ · w₁·w₂` (w₁ ≥ threshold일 때만) | **신뢰 모델 의미 변경** |
| Pruning (line 288) | `if (w1 < PRUNE_THRESHOLD) continue;` | 2-hop 전파 차단 |
| Diagonal serialization (line 297-313) | sparseDiag → PirDiag | M_total 제거 |

### 1.2 보고 vs 비보고

**보고:** sparse 알고리즘의 시간/메모리 복잡도, β·threshold 민감도, BitcoinOTC 특이 density 의존성, sparse vs main 신뢰 모델 차이의 정량화.

**비보고:** main과 동일한 신뢰 모델의 단순 성능 가속 (이는 본 브랜치가 *추구하는 것이 아님*).

---

## 2. 복잡도 및 자원 모델

기호: N = nGlobal, V = 유효 노드 수 (= nGlobal 이하), E = 유효 edge 수, d̄ = E/V (평균 out-degree).

### 2.1 시간 복잡도

| 단계 | main | sparse |
|---|---|---|
| Adjacency 빌드 | — | O(E) |
| 1-hop diagonal 누적 | (M_pub 채움) | O(E) |
| 2-hop 누적 | **O(N³)** dense matmul | O(Σ_src d_src · d_mid) ≤ O(V·d̄²) (평균), O(d_max²·V) (최악) |
| Diagonal 직렬화 | O(N²) | O(nnz_diag) |
| Plaintext encode | O(D_main · slot_count) | O(D_sparse · slot_count) |
| **총합** | **O(N³)** | **O(V·d̄²)** 평균 |

**핵심 가정:** d̄ ≪ N. BitcoinOTC: V ≈ 5,881, E ≈ 35,592, d̄ ≈ 6.05. nGlobal=1024 → V≤1024 (전체 V의 17%만 포함), 1024 노드의 d̄'는 더 클 수 있음 (top-frequent 선택이라 hub 집중).

### 2.2 worst-case 시나리오

- **Dense graph 회귀:** d_max → N → 2-hop loop = O(N²)·V = O(N³). 이론 개선 사라짐.
- **Hub 집중:** 한 노드가 d_max = O(V) 인 경우, 그 src의 inner loop가 dominant. BitcoinOTC top-frequent 노드의 degree 분포 검토 필요 (sec 6 측정).
- **Pruning ineffectiveness:** weights가 time-decay 후 매우 작으면 모든 w₁ < threshold → 2-hop 전체 차단 → sparseDiag = main의 1-hop만 = **2-hop 정보 손실**. 반대로 weights가 크면 pruning이 거의 발동 안 함.

### 2.3 메모리 복잡도

| 항목 | main | sparse |
|---|---|---|
| M_pub | N²·8 bytes | 동일 |
| M_total | N²·8 bytes | **0** (제거) |
| outAdj | — | E · (4+8) bytes ≈ 12E |
| sparseDiag | — | nnz_diag · (~48 bytes hashmap overhead) |
| PirDiag plaintexts | D_main · slot_count · 8 bytes | D_sparse · slot_count · 8 bytes |

**중요 함정:** `unordered_map<int,double>` 의 메모리 overhead는 entry당 ~32-48 bytes (bucket pointer + hash). dense 행렬에서는 dense storage(8 bytes/entry)가 더 효율적. **sparseDiag 메모리는 nnz_diag/N² 비율이 ≈ 17%(48/(8·N²/N²)=6) 이하일 때만 main 대비 절감.**

추정: nGlobal=1024, D_sparse ≈ ? (측정 필요), nnz_diag ≈ V·d̄² ≈ 6000·36 = 216K entries → ~10MB. M_total 폐기로 절약: 8MB. **메모리 이득 < 8MB**.

### 2.4 PIR cost 영향 (D 변화)

main: D_main = nGlobal (모든 diagonal nonzero 가정 — 실제로는 sparse하나 line 334-342 matmul 후 small noise 때문에 거의 모두 nonzero). sparse: D_sparse ≤ N, 영-diagonal 명시적으로 skip (line 299 `if empty continue`).

**Phase 3 cost 직접 영향:** rotation 수 = D. D_sparse < D_main 이면 Phase 3도 가속. **A1 (bgsg) 와 결합 시 cost = m1+m2-2 이 D에 무관 → A2 단독 Phase 3 가속이 B 통합 시에는 의미 약화.** sec 8 O1 참조.

---

## 3. 정확성 모델

### 3.1 sparse vs sparse-with-dense-matmul 등가성 (알고리즘 차원)

**정의:** `sparseDiag^algo[d][row]` 는 sparse 알고리즘의 출력, `sparseDiag^dense[d][row]` 는 동일한 (β₁, β₂, threshold)로 dense matmul 후 대각선 추출한 결과.

**Claim S1 (1-hop):** sparse의 line 285-286
```
d1 = (src - mid + N) % N
sparseDiag[d1][mid] += β₁ · w₁
```
는 `M_pub[mid][src] = w₁` 을 대각선 d1 형식으로 저장. 모든 (src, mid) edge에 대해 누적 → `Σ_edges M_pub[i][(i+d) mod N]` 와 등가. ✓

**Claim S2 (2-hop):** sparse의 line 290-292
```
for (dst, w2) in outAdj[mid]:
    d2 = (src - dst + N) % N
    sparseDiag[d2][dst] += β₂ · w₁ · w₂
```
는 path `src → mid → dst` (w₁, w₂) 의 기여를 row=dst, diagonal d2에 누적. `(M_pub²)[dst][src] = Σ_mid M_pub[dst][mid] · M_pub[mid][src] = Σ_mid w₂(mid→dst) · w₁(src→mid)` 와 일치 (단, w₁ ≥ threshold 인 mid만 포함). ✓ 단, pruning 적용 시 dense와 차이 발생 — **dense는 모든 mid 포함, sparse는 w₁ ≥ threshold 인 mid만**. 따라서 등가성은 *unpruned* 케이스에서만 성립.

**Claim S3 (Direction):** main의 outM_pub은 `outM_pub[tgt][src] += weight` (line 325 main). sparse도 동일 (line 272). 2-hop 방향: M² entry (i=dst, k=mid, j=src) → `dst ← mid ← src`. sparse의 path 표기 `src → mid → dst` 는 동일 chain의 반대 표기일 뿐. ✓

### 3.2 sparse vs main 의미 등가성 — **NOT EQUIVALENT** (의도된 차이)

main `CipherRank.cpp:330-341` 의 결과:
```
M_total[i][j] = M_pub[i][j] + (M_pub · M_pub)[i][j]
              = M_pub[i][j] + Σ_k M_pub[i][k] · M_pub[k][j]
```
- 1-hop weight: 1.0 (no β)
- 2-hop weight: 1.0 (no β)
- Pruning: none

sparse의 결과:
```
sparseDiag[d][row=i] = β₁ · M_pub[i][i+d] + β₂ · Σ_{k: w(k→i) ≥ thr} M_pub[i][k] · M_pub[k][i+d]
```
- 1-hop weight: β₁ = 1.0
- 2-hop weight: β₂ = 0.30
- Pruning: w(src→mid) < threshold 차단

**의미적 차이:**
- (a) **β₂ = 0.30**: 2-hop 영향력을 1-hop의 30%로 강제 감쇠 — "trust decay over hops" 모델 (PageRank의 damping과 별개의 hop-decay).
- (b) **Pruning**: 약한 1-hop을 통한 sybil-propagation 차단을 의도 (sec 8 O2).
- (c) **합산 형태**: main은 단순 합, sparse는 weighted sum.

이는 sparse 브랜치가 **trust score 의 정의 자체를 변경**한 것이다. 본 spec은 이 변경을 정당화하지 않으며 (sec 9 NG1), 정량화한다 (sec 6.3 의미 차이 메트릭).

### 3.3 등가성 검증 매트릭스

| 비교 | 등가 조건 |
|---|---|
| sparse vs sparse-dense (β·thr 동일) | unpruned 또는 threshold = 0 |
| sparse vs main | β₁ = 1.0, β₂ = 1.0, threshold = 0 |
| sparse vs bgsg | bgsg + same diagonal contents 시 알고리즘 등가 (B 단계) |

R1' 회귀 테스트 (sec 7): **β₁=1.0, β₂=1.0, threshold=0** 모드에서 sparse 출력 ≡ main 출력 (ε-equivalence).

---

## 4. 엣지 케이스 카탈로그

| ID | 케이스 | 현재 거동 | 위험도 |
|---|---|---|---|
| **E1** | `d_max ≫ d̄` (hub 노드) | 2-hop loop이 hub 노드에서 O(d_max²) → O(N²)·1 = bottleneck | **중간**: 측정 후 hub 분리 처리 가능 |
| **E2** | Dense graph (d̄ → N) | 이론적 O(N³) 회귀 | 낮음 (BitcoinOTC는 sparse) |
| **E3** | Time-decay 강함 → 모든 w₁ < threshold | 2-hop 전체 차단 → main 대비 trust score 차이 큼 | **높음**: 신뢰 모델 변형의 본질적 한계 |
| **E4** | Pruning 약함 (threshold → 0) | 2-hop 전체 살아남 → sparse 메모리/시간 폭증 | **중간**: threshold 0 케이스 디폴트 가드 |
| **E5** | β₂ → 1.0 일 때 (즉 main과 같아져야 함) | pruning 잔존 → 여전히 sparse는 main과 다름 | **중간**: β만으로 회귀 검증 불가, threshold도 함께 변경 필요 |
| **E6** | sparseDiag empty diagonal | line 299 `continue` 로 skip | 낮음 |
| **E7** | edges에 자기루프 (src == tgt) | `d = 0`. self-trust 누적. main도 동일하게 처리 | 낮음 |
| **E8** | 중복 edge (같은 src→tgt 여러 번) | outM_pub과 outAdj 둘 다 누적 → 2-hop weight 부풀려짐 | **중간**: 중복 처리 정책 명시 필요 |
| **E9** | `unordered_map` rehashing | sparseDiag[d] 에 entry 누적 시 rehash → 시간 spike | 낮음 |
| **E10** | hashmap iteration order 비결정성 (line 303) | 같은 diag 출력이지만 누적 순서로 floating-point 차이 발생 | **중간**: 결정성 위반 (재현성 영향) |
| **E11** | β₁, β₂, threshold가 hardcoded (line 279-281) | 실험/튜닝 불가 | **높음**: 동적 주입 필요 (P1) |
| **E12** | nGlobal이 V보다 큼 | `globalNodeToIndex` 가 freqVec 크기로 capped (line 241) — V만 채워짐, [V..N) 인덱스는 미사용 | **낮음**: M_pub의 잉여 zero row/col 무해 |
| **E13** | A1 (bgsg) 통합 시 sparse pattern이 청크 패딩과 충돌 (A1 sec 4 E12) | sparse는 row ∈ [0, N) 만 채움, bgsg는 [0, 2N) 필요 | **높음**: B 단계 통합의 핵심 작업 |
| **E14** | Phase 3, Phase 5 는 main과 동일 — sparse 변경 영향 없음 | bgsg 결합 후 Phase 3가 dominant 되면 sparse 의 ROI 줄어듦 | **중간**: sec 8 O1, B 단계 |
| **E15** | sparse 의 다른 phase: Phase 4의 round + 결정 정렬 부재 | main과 동일하게 round/lex tie-break 적용 (line 398, 403). 실제 코드는 main과 같음 | 낮음 (sparse는 Phase 4 미변경) |
| **E16** | sparseDiag 직렬화의 plaintext 갯수가 main보다 적을 가능성 | empty diagonal skip → D_sparse < D_main → Phase 3 가속 추가 효과 | 낮음 (긍정적) |
| **E17** | `outM_pub`은 여전히 N×N dense (line 120, 272). Phase 5에서 사용 | Phase 1의 메모리 핵심 절감은 M_total 폐기에 국한, M_pub은 유지 | **중간**: O7 — M_pub의 sparse 표현 가능성 |
| **E18** | Phase 3가 OMP 없음 (main 동일) | bgsg에서 가져와야 함 (B 단계) | 낮음 (B 단계 작업) |

---

## 5. 강화안

### 5.1 [Q1] Dynamic Parameter Injection — β₁, β₂, threshold CLI 노출

- **가설:** β·threshold가 hardcoded이라 실험·민감도 분석 불가. CLI 인자로 노출 → sweep 가능.
- **변경 위치:** `main()` argparse + `PreparePublicData()` 시그니처에 `double beta1, double beta2, double prune_thr` 추가. 클래스 멤버 또는 호출 인자.
- **CLI:** `-b1 1.0 -b2 0.30 -thr 0.05` (default = 현재 값으로 호환 유지).
- **측정 메트릭:** β·thr sweep 시 Phase 3 wall-clock, Phase 6 score, top-K Kendall τ.
- **위험:** 인자 수 증가. CLI 파서 충돌 (현재 wallet ID도 positional).

### 5.2 [Q2] Pruning Threshold Auto-Calibration

- **가설:** `0.05` 절대값은 weight scale에 의존 (BitcoinOTC weight 2~10, time-decay 후 [0, 10]). 데이터셋 통계 기반 threshold 자동 계산:
  - `threshold_auto = percentile(w1_distribution, p)` where `p = 50` (median)
  - 또는 `threshold_auto = mean(w1) − σ(w1)`
- **변경 위치:** Phase 1 의 edge 수집 후 weight 통계 → threshold 자동 도출. CLI는 `-thr-mode {fixed, percentile_50, mean_minus_sigma}`.
- **측정 메트릭:** auto threshold 분포(다양한 데이터셋), Phase 6 score 비교, pruned-ratio 보고.
- **위험:** 데이터셋 종속. **Stage A2 단독에서는 BitcoinOTC만 검증 가능** — 일반화는 future work.

### 5.3 [Q3] Hub-Aware 2-Hop Loop (Edge case E1 해결)

- **가설:** d_max ≫ d̄ 인 hub 노드가 dominant. Hub를 별도 처리:
  - hub set H = {src : d_src > k · d̄}, k ∈ {3, 5, 10}
  - non-hub src: 현재 그대로
  - hub src: 더 강한 pruning threshold 또는 sub-sampling
- **변경 위치:** Phase 1 의 2-hop loop 전 hub 분류 + 분기 처리.
- **측정 메트릭:** hub set의 d_max 분포, hub-별 처리 시간, total Phase 1 wall-clock.
- **위험:** 보안 — sybil 노드가 hub로 위장 시 sub-sampling이 sybil-친화적이 될 수 있음. sec 9 NG7 참조.

### 5.4 [Q4] sparseDiag 결정론 — E10 (hashmap iteration order)

- **가설:** `unordered_map` iteration이 비결정적 → 같은 입력에 대해 부동소수점 누적 순서 차이 → ULP 변동.
- **변경:** sparseDiag[d] 를 `std::map<int, double>` (정렬된) 또는 `vector<pair<int,double>>` (build 후 sort) 로 교체. 후자가 성능상 유리.
- **변경 위치:** line 277 type, line 303 iteration.
- **측정 메트릭:** 동일 입력 N=5회 실행에서 ULP 동일성 (R1' 회귀).
- **위험:** 성능 회귀 (sort O(D log D) 추가). 미미함.

### 5.5 [Q5] M_pub Sparse Storage (Phase 5 정합성)

- **가설:** Phase 1은 M_total을 제거했으나 M_pub은 여전히 N² dense. Phase 5는 `M_pub[allTop64[c][i]][allTop64[c][j]]` (line 438) 로 인덱스 접근 — sub-matrix 구성에 dense access 필요.
- **변경:** M_pub을 sparse CSR/COO 표현으로 교체하고 random access는 hash로 → 메모리 절감 가능.
- **trade-off:** Phase 5의 random access가 hash lookup으로 늦어짐. nSub=256 일 때 nSub² = 64K access. 미미할 수도.
- **메모:** 본 spec의 권장 우선순위는 **낮음** — Phase 1 시간이 dominant인 한 Phase 5 메모리 차이는 작음. **O3 (future)** 로 미룸.

### 5.6 [Q6] D 추정 → Phase 3 cost 통합 (A1 P4와 연결)

- **가설:** D_sparse 값을 Phase 1 종료 시 보고 → A1의 P4 cost function 에 입력 → Phase 3 (m1, m2) 최적화에 반영.
- **변경 위치:** `PreparePublicData()` 의 return에 D 동봉. main 단의 cost 호출에 주입.
- **B 단계 핵심 의존:** A1 P4 + A2 Q6 가 결합되어야 B의 cost-aware BSGS가 완성.

---

## 6. 측정 계획

### 6.1 비교군

| ID | 구성 | 검증 |
|---|---|---|
| C0 | `main` baseline | reference |
| C1 | sparse default (β₁=1.0, β₂=0.30, thr=0.05) | end-to-end |
| C2 | sparse with main params (β₁=1.0, β₂=1.0, thr=0) | **algorithm-only 등가성 (R1')** |
| C3 | sparse + Q1 (β·thr CLI) | parameter sweep |
| C4 | sparse + Q1 + Q2 (auto threshold) | 자동 calibration |
| C5 | sparse + Q1 + Q4 (결정성) | bit-stability |
| C6 | sparse + Q1 + Q3 (hub-aware) | dense-aware |
| C7 | sparse + Q1 + Q6 (D reporting) | B 단계 연결 |

### 6.2 Sweep 파라미터

- nGlobal ∈ {256, 1024, 2048, 4096} (4096은 main이 사실상 불가능 → sparse 의 핵심 차별화 데모)
- num_targets ∈ {1, 4, 16, 64}
- (Q1 활성): β₂ ∈ {0.0, 0.10, 0.30, 0.50, 1.0}, threshold ∈ {0, 0.01, 0.05, 0.1, 0.5}

**Sweep 총합:** Coarse 3 cells (nGlobal ∈ {256, 1024, 2048} × num_targets=16) × C0..C7 × N=10 = 240 runs. Fine: β·thr 5×5 grid × {nGlobal=1024} × C3 × N=5 = 125 runs. **총 365 runs.** 단위 30~180초 → **~10-15 시간**.

### 6.3 메트릭

| 카테고리 | 메트릭 | 단위 |
|---|---|---|
| 시간 | Phase 1, 3, 5, total wall-clock | sec |
| 메모리 | Peak RSS, M_pub vs sparseDiag breakdown | MB |
| 알고리즘 | D_sparse / nGlobal (PIR 대각선 비율) | 0~1 |
| 알고리즘 | pruned 2-hop edges 비율 (sparse 전체 대비) | 0~1 |
| 정확도 (sparse-algo) | sparse vs sparse-dense 차이 | abs (≤ 10⁻¹⁰) |
| 정확도 (semantic) | sparse vs main FHE score per target | abs |
| 정확도 (semantic) | Top-K Kendall τ (sparse Phase 4 vs main Phase 4) | -1~1 |
| 결정성 | 동일 seed N=10회 sparse 출력 max diff | abs |

**의미 차이 보고:** sec 6.3의 "정확도 (semantic)" 메트릭은 sparse가 main과 *다르게* 동작함을 정량화. **이것이 곧 sparse의 "오류"가 아님을 표 캡션에 명시.**

### 6.4 통계 프로토콜

A1과 동일: Wilcoxon signed-rank, Benjamini-Hochberg FDR 5%, 중앙값+IQR+95% CI, effect size = log₂(median ratio).

### 6.5 환경 고정

A1 sec 6.5와 동일 (CPU governor, OMP_PROC_BIND, 빌드 매니페스트, CSV SHA-256, seed 고정, hashmap → ordered map 또는 sorted vector by Q4).

**추가 고정:** β·thr default를 명시적으로 spec에 기재하고 sweep 외 값은 사용 불가 (cherry-pick 방지).

---

## 7. 정확성 회귀 테스트

### R1' (Algorithmic equivalence): C2 모드(β₁=1.0, β₂=1.0, thr=0)에서 sparse vs main

`max_targets |fheScore_sparse − fheScore_main| < ε_R1` (sparse-mode-main-equiv 검증). ε는 A1 R1과 같은 noise floor 기반.

### R2' (Algorithm vs algorithm-dense): sparse vs sparse-dense-matmul

동일 (β₁, β₂, thr) 에서 sparse의 sparseDiag[d][row] 값이 dense matmul 후 추출과 일치. ε ≤ 10⁻¹⁰ (실측 가능, floating point round-off 제외).

### R3' (Verdict 일치 under C2): C2 모드에서 Phase 6 APPROVED/REJECTED main과 일치

A1 R3과 동일 protocol.

### R4' (Determinism under Q4): N=10회 동일 입력 sparse 출력 bit-동등 (Q4 적용 후)

`max_run_pair |y_run_i − y_run_j| = 0`. hashmap iteration order 비결정성 제거 검증.

### R5' (Pruning bound): threshold 변경 시 D_sparse 단조 감소

threshold = {0, 0.01, 0.05, 0.1, 0.5} 에서 D_sparse(thr_i) ≤ D_sparse(thr_{i-1}). 단조성 위반은 구현 버그.

### R6' (Memory regression test): sparseDiag entries · 48 bytes < N² · 8 bytes

dense graph 회귀 가드. 위반 시 dense matmul로 fallback 권고를 spec에 명시.

---

## 8. 개방 문제

- **O1:** A2의 Phase 1 가속이 B 단계에서 bgsg와 결합되면 PIR rotation 비용이 dominant가 됨. **B 단계 측정 보고에서 Phase별 wall-clock 변화를 명시할 것.**
- **O2:** Pruning이 sybil 방어상 의미 있는가? sybil 노드는 약한 1-hop으로 위장하므로 pruning이 sybil-친화적일 가능성. 보안 관점 (sec 9 NG7) 별도 spec.
- **O3:** M_pub 자체의 sparse 표현 (Q5) — Phase 5 random access 성능 trade-off.
- **O4:** β·threshold 자동 calibration의 일반화 (Q2). 데이터셋 의존성 측정.
- **O5:** sparse 알고리즘이 분산 환경 (multi-server)에서 어떻게 작동하는가? 본 spec은 single-server.
- **O6:** sparseDiag 의 `unordered_map` 대신 dense vector (`vector<double>` per diagonal, length N) — D_sparse 작을 때 메모리 회귀. trade-off 측정.
- **O7:** N=4096+ 케이스의 측정 (main은 실용적 시간 내 종료 불가 → sparse의 강점 시연).

---

## 9. 비-목표

- **NG1.** sparse의 신뢰 모델이 main의 모델보다 "더 옳음" 을 주장하지 않는다. 본 spec은 **알고리즘 등가성과 성능**을 측정.
- **NG2.** PIR 익명성 영향. graph는 평문이므로 sparse pruning은 익명성에 무관 — 단, future graph-private 모델에서는 재검토 (sec 9 NG7).
- **NG3.** A1 (bgsg) 와의 통합. B 단계 영역.
- **NG4.** CKKS scheme 변경.
- **NG5.** Phase 4, Phase 5의 알고리즘 변경 (sparse는 Phase 1만 변경).
- **NG6.** **(보안)** Side-channel timing 분석 — Phase 1 wall-clock이 graph density에 의존하므로 graph-private 모델에서는 timing leak. 본 spec은 graph plaintext 가정.
- **NG7.** **(보안)** Pruning의 sybil-resilience. threshold 조작이 sybil 공격 표면을 만들 가능성 — Stage A2 외부 (future security review).
- **NG8.** **(보안)** β·threshold 의 client-server 협상 (deployment 시점 fingerprinting). simulation 한정.

---

## 10. 의존성 DAG와 적용 순서

```
Q4 (결정성, hashmap → sorted) ── 독립, 가장 먼저 (R4' 검증 가능)
       │
       ▼
Q1 (β·thr CLI) ── R1' (C2 모드) 검증 가능
       │
       ▼
Q2 (auto threshold) — Q1 위에 빌드
       │
       ▼
Q3 (hub-aware) — Q1 위에 빌드 (Q2와 병렬 가능)
       │
       ▼
Q6 (D 보고) — B 단계 진입 전 마지막
```

**B 단계 통합 시 prerequisite:** Q1 + Q4 (결정성) 필수. Q2/Q3는 옵션.

---

## 11. 엔지니어링 노트

- **(a)** **신뢰 모델 변경의 명시적 분리** — 성능 최적화와 의미 변경이 한 PR에 묶이는 것은 일반적 안티패턴. sparse 브랜치는 두 가지를 동시에 도입했으므로 본 spec은 이를 **차원 분리**하여 측정한다.
- **(b)** **Pruning의 데이터셋 의존성** — `0.05` 절대값은 BitcoinOTC weight scale에만 의미 있음. 일반 데이터셋용 percentile-기반 calibration이 필요.
- **(c)** **`unordered_map` 비결정성** — FHE 시스템에서 재현성은 디버깅·보안·논문 reviewer 모두에게 핵심. ordered container로 정착 권고.
- **(d)** **Hub-aware 처리의 보안 trade-off** — 성능 최적화가 종종 sybil 방어 표면을 만드는 사례.

---

## 부록 A — 변경 코드 참조 색인 (sparse 브랜치)

| 라인 | 항목 |
|---|---|
| 207 | `PreparePublicData` 진입 |
| 262 | `outAdj` 선언 |
| 265-275 | edge 수집 + 1-hop M_pub 채움 + outAdj 빌드 |
| 277 | `sparseDiag` 선언 (수정 대상: Q4) |
| 279-281 | β₁, β₂, threshold (수정 대상: Q1) |
| 283-295 | sparse 2-hop loop (수정 대상: Q3 hub-aware) |
| 297-313 | sparseDiag → PirDiag 직렬화 (수정 대상: Q4 deterministic iteration) |
| 313 (return) | sparse → A1과 결합 시 D 보고 추가 (Q6) |

---

## 부록 B — sparse vs main 의미 차이 (요약)

| 측면 | main | sparse |
|---|---|---|
| 1-hop weight | 1.0 (M_pub 그대로) | β₁ = 1.0 |
| 2-hop weight | 1.0 (M_pub²) | β₂ = 0.30 |
| 2-hop 전파 가지치기 | 없음 | w₁ < 0.05 시 차단 |
| 메모리 모델 | dense N×N M_total | hash-based sparseDiag |
| 시간 복잡도 | O(N³) | O(V · d̄²) 평균, O(d_max² · V) 최악 |
| Phase 6 출력 | reference | C1: 다름 (의도), C2: ≡ main (R1' 검증) |
