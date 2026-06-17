# Stage A2 — `feat/sparse-twohop-precompute-experiment` 보강안 설계 문서 (v2)

- **날짜:** 2026-06-18 (v2 revise)
- **대상 브랜치:** `feat/sparse-twohop-precompute-experiment` (HEAD: `dc75ee8`)
- **기준선:** `main` (HEAD: `8c3aee3`)
- **단계:** A2 (독립 강화). A1 (bgsg) 완료 후 진행. 후속으로 B (통합) 예정.
- **v2 변경:** 5인 리뷰(architect/critic/scientist/security/OMC)에서 발견된 Critical 5건 + High 7건 + Medium 10+건 반영. 핵심: (i) BitcoinOTC 통계 실측 재계산 (V=3,302, E=11,981, d̄=3.628), (ii) main 라인 참조 정정 (`main:265-273`), (iii) Claim S2 index-mapping 명시, (iv) pruning semantics 정정, (v) Q1 root prerequisite로 격상, (vi) Q5 (M_pub sparse) Critical 격상, (vii) Q7 (B-stage padding bridge) 신설, (viii) NG9 (데이터셋 일반화), NG10 (Q6 fingerprinting cross-ref A1 NG7) 추가, (ix) 사전 실측 부록 B 신설.

---

> **Caveat — Semantic Divergence from Baseline.** sparse 브랜치는 **단순 성능 최적화가 아니다**. main의 2-hop 집계가 `M_pub + M_pub²` (β₁=β₂=1, 비-pruned) 인 반면, sparse는 `β₁·M_pub + β₂·M_pub²_pruned` (β₁=1.0, β₂=0.30, w(src→mid) < 0.05 인 src의 2-hop 전파 차단). 부록 B 실측에서 **Config A wallet 4의 APPROVED/REJECTED verdict가 뒤집힘**이 확인됨. 따라서 sparse vs main의 Phase 6 출력 차이는 "노이즈"가 아니라 **정의 차이**이다. 본 spec의 정확성 검증(R*)은 두 차원을 분리:
> - **(i) 알고리즘 등가성:** sparse의 `sparseDiag[d][row]` 가 같은 (β, pruning) 모델을 dense matmul로 계산한 결과와 동등한가?
> - **(ii) 신뢰 모델 정합성:** sparse 의 trust score 가 main 대비 sybil 방어 목적상 더 나은가/같은가/더 나쁜가? — **A2 외부, 측정값만 보고**.

---

## 1. 본 브랜치가 공격하는 병목

main 의 `PreparePublicData` 는 `M_total = M_pub + M_pub · M_pub` 을 **dense N×N matmul** (`main:265-273`)로 계산한다. N=1024 에서 ≈ 10⁹ 부동소수점 곱셈, 단일 스레드. A1 R1 실측에서 **main 의 Phase 1 wall-clock = 7.73 초 @ nGlobal=1024** (전체 78.3 초 중 10%). nGlobal=2048 에서 ≈ 8 × 7.73 = **62 초** 로 증가, 전체의 dominant term 가능 (A1 부록 B.F4).

sparse 브랜치는 **(i) 중간 N×N 행렬 자체를 제거**하고 **(ii) 인접 리스트 순회로 대각선을 직접 누적**한다. 이론적 복잡도 `O(N³) → O(V · d̄²)` 평균.

### 1.1 BitcoinOTC 실측 통계 (v2 정정)

- 원본 파일: `soc-sign-bitcoinotc.csv` 35,592 행
- 코드 필터: `parts[2] >= 2` (sparse:228) — 양의 신뢰 ≥ 2 인 edge 만 보존
- **필터 후: V = 3,302 유니크 노드, E = 11,981 edge**
- **d̄ = E / V = 3.628** (v1 의 d̄ = 6.05 는 unfiltered 기준이라 부정확)

### 1.2 변경 영역 요약

| 위치 (sparse) | 변경 | 영향 |
|---|---|---|
| `sparse:228` | `parts[2] >= 2` 필터 (main 도 동일) | **음의 trust edge silent drop** — 부록 D 참조 |
| `sparse:262, 273` | `outAdj[srcIdx].push_back({tgtIdx, w})` | 1-hop 인접 리스트 |
| `sparse:277` | `vector<unordered_map<int,double>> sparseDiag(nGlobal)` | 대각선별 row→val 직접 저장 (Q4 변경 대상) |
| `sparse:279-281` | `β₁=1.0, β₂=0.30, PRUNE_THRESHOLD=0.05` hardcoded | **신뢰 모델 의미 변경**, Q1 변경 대상 |
| `sparse:283-295` | β-weighted 2-hop loop + pruning | **약한 src→mid edge 가 src 의 2-hop chain 전체 차단** (v1 "약한 1-hop 차단" 표기 정정) |
| `sparse:297-313` | sparseDiag → PirDiag 직렬화 | M_total 제거. Q4·Q7 변경 대상 |

### 1.3 보고 vs 비보고

**보고:** sparse 알고리즘의 시간/메모리 복잡도, β·threshold 민감도, BitcoinOTC 특이 density 의존성, sparse vs main 신뢰 모델 차이의 정량화 (부록 B), B-stage 통합 prerequisite.

**비보고:** main 과 동일한 신뢰 모델의 단순 성능 가속 (본 브랜치가 *추구하는 것이 아님*). 신뢰 모델 변경의 *정당성* (별도 spec).

---

## 2. 복잡도 및 자원 모델

기호: N = nGlobal, V = 유효 노드 수 (≤ nGlobal), E = 유효 edge 수, d̄ = E/V (평균 out-degree), d_max = 최대 out-degree.

### 2.1 시간 복잡도

| 단계 | main (line) | sparse (line) | 복잡도 비교 |
|---|---|---|---|
| Adjacency 빌드 | (없음) | 265-275 | O(E) |
| 1-hop diagonal 누적 | 261 outM_pub 채움 | 285-286 sparseDiag | O(E) 양쪽 동일 |
| 2-hop 누적 | **265-271** dense matmul O(N³) | 283-295 sparse 순회 | sparse O(V · d̄²) 평균 / O(d_max · E) 최악 |
| Diagonal 직렬화 | 272-291 | 297-313 | sparse 더 적은 D |
| **총합** | **O(N³)** | **O(V · d̄²)** 평균 |

**Worst-case bound 정정 (v2):** spec v1 "O(d_max² · V)" 는 부정확. 정확한 worst-case는 inner-loop counts `Σ_src d_src · d_mid ≤ d_max · Σ d_src = d_max · E`. 따라서 **O(d_max · E)**.

**BitcoinOTC 추정 (v2):** V·d̄² = 3,302 × 3.628² = **43,491 연산** vs main O(N³) at N=1024 = 10⁹. **이론적 23,000× 가속**. 실측 (부록 B): 3.03× 가속 — 차이는 (i) constant factor (hashmap overhead), (ii) 직렬화·encode 비용.

### 2.2 worst-case 시나리오

- **Dense graph 회귀:** d_max → N → 2-hop loop = O(N·E) = O(N²·d̄) → O(N²) 수준. 이론 개선 약화.
- **Hub 집중:** 특정 노드가 d_max = O(V) → 그 src 의 inner loop dominant. nGlobal=1024 시 BitcoinOTC top-frequent 노드의 d_src 분포는 **사전 측정 필요** (부록 D).
- **Pruning ineffectiveness:** weights 가 time-decay 후 매우 작으면 모든 w < threshold → 2-hop 전체 차단 → sparseDiag = main 의 1-hop만. 반대로 weights 가 클수록 pruning 거의 발동 안 함.

### 2.3 메모리 복잡도 — 정량 재추정 (v2)

| 항목 | main | sparse |
|---|---|---|
| M_pub | N²·8 bytes | 동일 (sparse 도 dense 보존, Q5 변경 대상) |
| M_total | N²·8 bytes | **0** (제거) |
| outAdj | — | E · (4+8) bytes ≈ 12·11,981 ≈ 144 KB |
| sparseDiag | — | nnz_diag · 48~64 bytes (libc++ ~56, libstdc++ ~64) |
| PirDiag plaintexts | D_main · slot_count · 8 bytes | D_sparse · slot_count · 8 bytes |

**libc++ / libstdc++ unordered_map overhead 정확 추정 (v2 정정):**
- libstdc++: ~56-64 bytes/entry (bucket pointer + node {next, hash_cache, key, value})
- libc++: ~48-56 bytes/entry

**메모리 이득 정량 (nGlobal=1024 기준):**
- M_total 절약: `1024² × 8 = 8 MB`
- sparseDiag 추가: 추정 nnz_diag ≈ V·d̄² ≈ 43K entries × 60 bytes ≈ **2.6 MB**
- **순 절약: ~5.4 MB** (정정: v1 "메모리 이득 < 8MB" → **약 5 MB**)

**nGlobal=2048 / 4096 에서의 메모리 한계:**
- M_pub 자체가 `N²·8` = 32 MB / 128 MB → **sparse 의 N=4096 차별화 demo 는 M_pub 자체가 dominant** (H-6, Q5 격상의 근거)

### 2.4 PIR cost 영향 (D 변화)

main: D_main ≈ 모든 nGlobal (영-diagonal small noise 인해 거의 모두 nonzero). sparse: D_sparse ≤ N, line 299 `if empty continue` 로 명시적 skip.

**Phase 3 cost 직접 영향:** rotation 수 = D. **D_sparse < D_main 이면 Phase 3 도 가속** (sparse 추가 효과).

**A1 (bgsg) 와 결합 시:** cost = m1 + m2 − 2 가 D 에 무관 → **A2 단독 Phase 3 가속이 B 통합 시에는 의미 약화**. 그러나 A1 P4 (cost function 일반화) 가 D 를 입력 받으면 의미 부활 (sec 8 O1, Q6).

---

## 3. 정확성 모델

### 3.1 sparse vs sparse-dense 등가성 (알고리즘 차원)

**Convention** (v2 명시): `outM_pub[i][j] = w(j → i)`, 즉 i=tgt, j=src. main:261 와 sparse:272 양쪽 동일.

**Diagonal extraction** (v2 명시): main:280 의 `M_total[row][(row+d) % N]` 형식. 즉 row r 의 diagonal d 는 `M_total[r][(r+d) mod N]`. 매핑: `(row r, d) ↔ entry (r, (r+d) mod N)`.

#### Claim S1 (1-hop equivalence)

sparse line 285-286:
```
d1 = (src - mid + N) % N
sparseDiag[d1][mid] += β₁ · w₁
```
- (src, mid, w₁) = edge `src → mid`, w₁ = w(src→mid) = M_pub[mid][src]
- 저장 위치: row = mid, d = d1 → 대응 entry: `(mid, (mid + d1) mod N) = (mid, src)` ✓
- 따라서 `sparseDiag[d1][mid] = β₁ · M_pub[mid][src]` ⟹ unpruned, 모든 edge 누적 시 `Σ_edges = β₁ · M_pub` ✓

#### Claim S2 (2-hop equivalence) — **명시적 index mapping (v2)**

sparse line 290-292:
```
for (dst, w₂) in outAdj[mid]: edge mid → dst, w₂ = w(mid→dst) = M_pub[dst][mid]
    d2 = (src - dst + N) % N
    sparseDiag[d2][dst] += β₂ · w₁ · w₂
```

**Index mapping table:**
| sparse loop var | dense matrix index | 의미 |
|---|---|---|
| src | j (column) | M_pub 의 src 컬럼 |
| mid | k (sum index) | M_pub² 의 합산 중간 인덱스 |
| dst | i (row) | M_pub 의 dst 행 |
| w₁ | M_pub[mid][src] | 첫 hop weight |
| w₂ | M_pub[dst][mid] | 둘째 hop weight |
| d2 = (src-dst+N)%N | d | diagonal index |
| sparseDiag[d2][dst] 저장 위치 | (row=dst, col=(dst+d2)%N=src) | M_pub²[dst][src] 대응 |

dense 형식:
```
M_pub²[i=dst][j=src] = Σ_k M_pub[dst][k] · M_pub[k][src]
                    = Σ_mid M_pub[dst][mid] · M_pub[mid][src]
                    = Σ_mid w₂ · w₁
```
sparse 형식 (모든 src·mid·dst 누적):
```
sparseDiag[d2][dst] = Σ_(src,mid)→dst β₂ · w₁ · w₂ = β₂ · M_pub²[dst][src]
                   (단, w₁ ≥ threshold 인 (src,mid) edge 만)
```
✓ 등가 (unpruned 또는 threshold=0 시).

#### Claim S3 (Direction convention 일치)

main:261 `outM_pub[tgt][src] += w` ≡ sparse:272 동일. M_pub[i][j] = w(j→i) 양쪽 보존. ✓

### 3.2 sparse vs main 의미 등가성 — **NOT EQUIVALENT** (의도된 차이)

main (`main:265-271`) 의 결과:
```
M_total[i][j] = M_pub[i][j] + (M_pub · M_pub)[i][j]   // β = 1, no pruning
```

sparse 의 결과:
```
sparseDiag[d][row=i] = β₁·M_pub[i][(i+d)%N] 
                    + β₂·Σ_{mid: w(src=(i+d)%N → mid) ≥ thr} M_pub[i][mid]·M_pub[mid][(i+d)%N]
```

**의미적 차이:**
- (a) **β₂ = 0.30**: 2-hop 영향력을 1-hop 의 30% 로 강제 감쇠 ("hop-decay" 모델)
- (b) **Pruning (v2 정정 — "약한 src→mid edge 차단" — src 의 trust-emanation power 차단)**: `w(src→mid) < threshold` 인 src 발 2-hop chain 전체 차단. **약한 1-hop 차단** 이 아니라 **약한 outgoing edge 를 가진 src 에서 출발하는 2-hop 전파 차단**. sybil 방어 의도는 sec 8 O2 / NG7 / 실측 부족 (sec 6.3 sybil 메트릭 추가, H-7)
- (c) **합산 형태**: main 은 β=1 단순 합, sparse 는 weighted sum

본 spec 은 이 변경을 **정당화하지 않으며** (sec 9 NG1), 정량화한다 (부록 B 실측, sec 6.3 의미 차이 메트릭).

### 3.3 등가성 검증 매트릭스

| 비교 | 등가 조건 |
|---|---|
| sparse vs sparse-dense | unpruned 또는 threshold = 0, β 동일 |
| sparse vs main | β₁=1.0, β₂=1.0, threshold=0 (즉 C2 모드, Q1 prerequisite) |
| sparse vs bgsg | B 단계, sparseDiag → BsgsDiag 변환 + padding bridge (Q7) |

R1' 회귀 (sec 7): **β₁=1.0, β₂=1.0, threshold=0** 모드에서 sparse 출력 ≡ main 출력 (ε-equivalence).

---

## 4. 엣지 케이스 카탈로그

| ID | 케이스 | 현재 거동 | 위험도 |
|---|---|---|---|
| **E1** | `d_max ≫ d̄` (hub 노드) | 2-hop loop 이 hub 노드에서 O(d_max·d̄) → bottleneck | **중간**: 측정 후 hub 분리 (Q3) |
| **E2** | Dense graph (d̄ → N) | 이론적 O(N²·d̄) 회귀 | 낮음 (BitcoinOTC sparse) |
| **E3** | Time-decay 강함 → 모든 w₁ < threshold | 2-hop 전체 차단 → main 대비 trust score 차이 큼 | **높음**: 신뢰 모델 변형의 본질 한계 |
| **E4** | Pruning 약함 (threshold → 0) | 2-hop 전체 살아남 → sparse 메모리/시간 폭증 | **중간**: threshold 0 default 가드 |
| **E5** | β₂ → 1.0 일 때 (main 과 동치 필요) | pruning 잔존 → 여전히 sparse ≠ main | **중간**: β·thr 동시 변경 필요 (C2 모드) |
| **E6** | sparseDiag empty diagonal | line 299 `continue` 로 skip | 낮음 |
| **E7** | edge 에 자기루프 (src == tgt) | d=0. self-trust 누적. main 도 동일 | 낮음 (BitcoinOTC 실측 검증 — 부록 D) |
| **E8** | 중복 edge (같은 src→tgt 여러 번) | outM_pub 과 outAdj 양쪽 누적. 실측 BitcoinOTC 중복 0건 | **낮음 (v2 정정)**: 데이터셋 의존, 다른 그래프에서 재평가 |
| **E9** | `unordered_map` rehashing | sparseDiag[d] 누적 시 rehash → 시간 spike | 낮음 |
| **E10** | hashmap iteration order 비결정성 (line 303) | 같은 diag 출력이지만 누적 순서로 floating-point 차이 | **중간**: Q4. 추가로 **cache-pattern side-channel** (security M-3) — Q4 가 함께 완화 |
| **E11** | β₁, β₂, threshold hardcoded (line 279-281) | 실험·튜닝 불가, **R1' prerequisite** | **높음**: Q1 root prerequisite |
| **E12** | nGlobal > V | `globalNodeToIndex` 가 V 까지만 채움 (line 241). [V..N) 인덱스 미사용 → outM_pub 잉여 zero | 낮음 |
| **E13** | A1 (bgsg) 통합 시 sparse pattern 청크 패딩 충돌 (A1 sec 4 E12) | sparse 는 row ∈ [0, N) 만 채움. bgsg 는 [0, 2N) 필요. **A1 C4 lemma 깨질 위험** | **높음**: B 단계 prerequisite — **Q7 신설** |
| **E14** | sparse Phase 3 는 main 과 동일 — sparse 변경 영향 없음 | bgsg 결합 후 Phase 3 가 dominant 되면 sparse 의 ROI 줄어듦 (부록 B.F3 실측) | **중간**: sec 8 O1 |
| **E15** | sparse Phase 5 는 main 과 동일 | sec 7 R7' parity check | 낮음 |
| **E16** | sparseDiag 직렬화 plaintext 수 < main D | Phase 3 가속 추가 효과 (D_sparse 보고: Q6) | 긍정 |
| **E17** | `outM_pub` 은 여전히 N×N dense (line 120, 272). Phase 5 에서 사용 | **nGlobal=4096 시 128 MB → sparse 4096 demo 의 bottleneck** | **높음 (v2 격상)**: Q5 Critical |
| **E18** | Phase 3 가 OMP 없음 (main 동일) | bgsg 에서 가져와야 함 (B 단계) | 낮음 (B 작업) |
| **E19 (v2)** | `parts[2] >= 2` 필터 (sparse:228, main 도 동일) → **음의 trust edge silent drop** | sybil 방어 핵심 신호 (negative rating) 가 처음부터 제외됨 | **중간**: 부록 D 명시. main 도 동일하므로 sparse 의 결함은 아님, **그러나 신뢰 모델 분석 시 가정으로 명시 필요** |
| **E20 (v2)** | `D_sparse = 0` 케이스 (모든 edge pruned) | Phase 3 `cipherNeighbors` `isInit=false` 유지 → uninitialized ciphertext 반환 (sparse:353) | **중간**: empty guard 추가 |
| **E21 (v2)** | Q3 hub-aware + B 단계 OMP 결합 시 `sparseDiag[d][row]` 동시 쓰기 race | atomic 또는 per-thread accumulator 필요 | **중간**: B 단계 작업 시 명시 |

---

## 5. 강화안

### 5.1 [Q1] β·thr CLI 노출 — **Root Prerequisite (v2 격상)**

- **가설:** β·threshold 가 hardcoded 라 실험 불가. CLI 인자로 노출 → sweep + R1' (C2 모드) 가능.
- **변경 위치:** 
  - `main()` argparse 에 `-b1 <float> -b2 <float> -thr <float>` 추가
  - `PreparePublicData(double β₁, double β₂, double thr)` 시그니처 변경 (또는 클래스 멤버로 승격 — A1 와 일관성 위해 **클래스 멤버 권장**)
- **CLI 충돌 회피:** 기존 `-g`, `-s` 와 wallet ID positional 인자와 호환 — `-b1`, `-b2`, `-thr` 신규 flag 는 prefix 가 달라 충돌 없음. 실측 검증: `main:576-585` argparse 패턴 (positional = wallet IDs)
- **R1' prerequisite:** Q1 없이 C2 모드 (β₁=1.0, β₂=1.0, thr=0) 실행 불가 → **R1' 검증의 직접 prereq**
- **측정 메트릭:** β·thr sweep 시 Phase 3 wall-clock, Phase 6 score, top-K Kendall τ
- **위험:** 인자 검증 (음수, > 1.0) 누락 시 silent failure

### 5.2 [Q2] Pruning Threshold Auto-Calibration

- **가설:** `0.05` 절대값은 weight scale 의존. 데이터셋 통계 기반 자동 도출.
- **변경 위치:** Phase 1 의 edge 수집 후 w₁ 분포 통계 → threshold 자동 도출. CLI: `-thr-mode {fixed, percentile_p, mean_minus_sigma}`
- **권장 default (v2):** `percentile_50` (median). 이유: robust to outlier, 데이터셋 독립적 시작점. **mean-σ 는 정규분포 가정** — BitcoinOTC w₁ 은 long-tail 이라 부적합.
- **availability attack 위험 (security H-1):** adversary controlled edge 분포 → threshold 조작 → valid user denial. sec 9 NG9
- **측정 메트릭:** auto threshold 분포, Phase 6 score 비교, pruned-ratio
- **위험:** 데이터셋 종속. A2 단독에서 BitcoinOTC 만 검증 — 일반화는 future (NG10)

### 5.3 [Q3] Hub-Aware 2-Hop Loop

- **가설:** d_max ≫ d̄ 인 hub 노드 분리 처리.
- **변경 위치:** Phase 1 2-hop loop 전 hub 분류. hub set H = {src : d_src > k · d̄}. **권장 default k = 5** (v2). hub src 에 더 강한 pruning 또는 sub-sampling.
- **OMP race (E21):** Q3 + B-stage OMP 결합 시 `sparseDiag[d][row]` 쓰기 충돌. atomic 또는 per-thread accumulator 명시.
- **security trade-off (M-2, Q3 sub-sampling):** sybil cluster 가 mutual edge 로 인공 hub 형성 시 sub-sampling 이 sybil-친화적이 될 수 있음 → sec 7 R8' (sybil injection regression) 신설
- **측정 메트릭:** hub set 의 d_max 분포, hub-별 처리 시간, total Phase 1 wall-clock, sybil injection regression

### 5.4 [Q4] sparseDiag 결정성 — Baseline 환경 통제로 격상 (v2)

- **가설:** `unordered_map` iteration 비결정 → FP 누적 순서 차이 → ULP 변동 + cache-pattern side-channel
- **변경:** sparseDiag[d] 를 `vector<pair<int,double>>` 로 build 후 sort. 또는 `std::map`. **권장: vector + sort** (sort cost ≈ D·d̄·log d̄ ≈ 1K·6·log 6 ≈ ~5K ops, 무시 가능)
- **v2 격상:** Q4 는 **모든 비교군 (C0~C7) 의 baseline 환경 통제** — sweep 시작 전 무조건 적용. A1 v2 의 unordered_map 정렬 강제 패턴과 일관
- **변경 위치:** line 277 type, line 303 iteration. baseline 통제는 spec sec 6.5 에 명시
- **측정 메트릭:** R4' ULP 동일성, cache-miss 패턴 (perf record), Phase 1 wall-clock impact

### 5.5 [Q5] M_pub Sparse Storage — **Critical 격상 (v2, OMC N-2)**

- **격상 근거 (v2):** nGlobal=4096 에서 dense M_pub = 4096²·8 = **128 MB**. sparse 의 N=4096 차별화 demo (sec 1, sec 6.2 H-1) 의 핵심 메모리 bottleneck. Q5 없이는 4096 demo 자체가 메모리 제약을 입증할 수 없음.
- **변경:** M_pub 을 `unordered_map<pair<int,int>, double>` (또는 CSR) 로 교체. Phase 5 random access (`sparse:438`) 는 hash lookup 으로 대체.
- **trade-off:** Phase 5 nSub² = 65,536 access. hash lookup ≈ dense access × 2~5. nSub=256 에서 총 추가 비용 ≈ 100K cycles → 미미 (Phase 5 전체의 < 1%).
- **측정 메트릭:** Peak RSS at nGlobal=4096 (Q5 on/off), Phase 5 wall-clock delta

### 5.6 [Q6] D 추정 → A1 P4 cost function 연결

- **가설:** D_sparse 값을 Phase 1 종료 시 보고 → A1 P4 cost function 입력 → Phase 3 (m1, m2) 최적화.
- **변경 위치:** `PreparePublicData()` return type
- **Return contract (v2 명시):**
  ```cpp
  struct PhaseOneOutput {
      vector<PirDiag> diagonals;
      int D_sparse;     // 비영 대각선 수
      int nnz_total;    // sparseDiag 전체 entry 수
  };
  ```
- **A1 P4 호환:** A1 P4 cost function `cost(m1, m2; D, I_factor)` 의 D 입력으로 직접 사용
- **B 단계 핵심 의존:** A1 P4 + A2 Q6 결합으로 B 의 cost-aware BSGS 완성

### 5.7 [Q7] Padding-Compatible Diagonal Serialization — **B-Stage Prerequisite (v2 신설)**

- **가설:** sparse 의 line 305 `diag_flat[c·pirBlockSize + row]` 는 row ∈ [0, N) 만 채움. bgsg 는 row ∈ [0, 2N) 의 duplicate padding 필요 (A1 sec 3.1 C3-C4). **B 통합 시 A1 C4 lemma 가 깨질 위험.**
- **변경 위치:** sparse:303-307 — `for row ∈ [0, N)` → `for row ∈ [0, 2N)`, padding 위치 `c·pirBlockSize + row` 에 중복 값 저장. 또는 별도 flag 로 padding mode on/off
- **A1 C4 lemma 검증:** 모든 청크 c 에 동일 패턴이 보존되는지 회귀 (R9' 신설)
- **변경 위치:** line 303-307
- **측정 메트릭:** R9' (multi-chunk 출력의 청크-translation 등가성)

### 5.8 [Q8 — 옵션] sparseDiag → BsgsDiag 변환 어댑터 (B 단계 내부)

- **가설:** Q7 padding 후, BSGS index 변환 `d → (i, j) = (d % m1, d / m1)` 적용 + 재인코딩. B 단계의 내부 모듈로 분리.
- **위치:** B 단계 spec — A2 v2 는 hook 만 제공

---

## 6. 측정 계획

### 6.1 비교군 — Ablation 분리

| ID | 구성 | 검증 |
|---|---|---|
| C0 | `main` baseline | reference |
| C1 | sparse default (β₁=1.0, β₂=0.30, thr=0.05) | end-to-end + 의미 차이 정량 |
| C2 | sparse with main params (β₁=1.0, β₂=1.0, thr=0) — **Q1 prerequisite** | **R1' 알고리즘 등가성** |
| C3 | sparse + Q1 + Q4 (baseline 결정성) | bit-stable baseline |
| C4 | sparse + Q1 + Q2 (auto threshold) | 자동 calibration |
| C5 | sparse + Q1 + Q3 (hub-aware) | hub 영향 |
| C6 | sparse + Q1 + Q5 (M_pub sparse) | 4096 demo enabler |
| C7 | sparse + Q1 + Q6 (D reporting) | B 단계 연결 |
| C8 | sparse + Q7 (padding bridge, 단독) | A1 C4 lemma 호환 |

### 6.2 Sweep 파라미터 — **4096 cell 추가 (v2)**

- **Coarse:** `(nGlobal, num_targets) ∈ {(256, 16), (1024, 16), (2048, 16)}` × C0..C8 × N=10 = 270 runs
- **Demo (v2 신설):** `(nGlobal=4096, num_targets=4)` × {C0 skip — main 실행 불가, C1, C6} × N=3 = 6 runs. **Q5 효과 검증 + sparse 의 4096 demo**
- **Fine β·thr:** 권장 grid 3×3 (v2 축소, statistical power H-3) — `β₂ ∈ {0, 0.30, 1.0}` × `thr ∈ {0, 0.05, 0.5}` × {nGlobal=1024} × C3 × N=10 = 90 runs

**총 366 runs.** 단위 추정 (v2 정밀화):
- C0 (main) at nGlobal=2048: ~90 sec (A1 부록 B 추정)
- C1 (sparse) at nGlobal=1024: ~73 sec (부록 B 실측)
- Demo C6 at nGlobal=4096: ~10-20 min 가능성 — **별도 예산 명시**

**예산 (v2):** Coarse ~6h, Demo ~30min-1h, Fine ~2h → **총 ~10h** (단일 머신).

### 6.3 메트릭

| 카테고리 | 메트릭 | 단위 |
|---|---|---|
| 시간 | InitFHE, Phase 1, 3, 5, total wall-clock | sec |
| 메모리 | Peak RSS, M_pub vs sparseDiag breakdown | MB |
| 알고리즘 | D_sparse / nGlobal | 0~1 |
| 알고리즘 | **pruned 2-hop edges 비율 (v2 정정)** = `Σ_src \|{mid ∈ outAdj[src] : w(src→mid) < thr}\| / Σ_src \|outAdj[src]\|` | 0~1 |
| 정확도 (sparse-algo) | sparse vs sparse-dense max diff | abs (≤ 10⁻¹⁰) |
| 정확도 (semantic) | sparse vs main FHE score per target | abs |
| 정확도 (semantic) | Top-K Kendall τ (**K = min(nSub, 10)** — v2 명시) | -1~1 |
| 정확도 (semantic) | **Effect size: Cohen's d on score difference (v2 추가)** | unitless |
| 결정성 | 동일 seed N=10 회 sparse 출력 max pairwise diff | abs |
| **Sybil 영향 (v2 추가, H-7)** | Sybil-labeled subset (out-degree=1, BitcoinOTC w=2 only) 의 TPR/FPR | 0~1 |

### 6.4 통계 프로토콜 — **메트릭 유형별 분리 (v2)**

- **시간 / 의미 차이 메트릭 (Wilcoxon):** signed-rank, BH FDR 5%, 중앙값+IQR+95% CI, effect size = log₂(median ratio)
- **알고리즘 등가성 메트릭 (Assertion):** R1' (max|diff| < ε), R2' (≤ 10⁻¹⁰), R4' (= 0), R5' (단조). **0/1 pass/fail per run**, Wilcoxon 적용 안 함
- **Sybil TPR/FPR (Bootstrap):** 95% CI via 1000-resample bootstrap

### 6.5 환경 고정 + 재현성 (v2 명시화)

- CPU governor `performance`, OMP_PROC_BIND=close, OMP_PLACES=cores
- **CSV SHA-256:** `soc-sign-bitcoinotc.csv` (실측 후 spec 갱신)
- 빌드 매니페스트 JSON: cmake, compiler, SEAL_commit, kernel, THP state, csv_sha256
- SEAL `UniformRandomGeneratorFactory` seeded: `seed = hash(experiment_id, trial_no)`
- `unordered_map` 순서: **Q4 강제 baseline** — `globalNodeToIndex` 도 `std::map` 또는 sort 후 사용
- 실험 순서 무작위화 + 60s idle
- **β·thr default:** β₁=1.0, β₂=0.30, thr=0.05 (BitcoinOTC). sweep 외 값 사용 금지

---

## 7. 정확성 회귀 테스트

### R1' (Algorithmic equivalence): C2 모드 sparse vs main

**선행 조건: Q1 구현 완료.** β₁=1.0, β₂=1.0, thr=0 에서 `max_targets |fheScore_sparse − fheScore_main| < ε_R1`. ε 는 A1 R1 의 noise floor 와 같은 방식 사전 측정.

### R2' (sparse vs sparse-dense)

동일 (β, thr) 에서 sparse 의 sparseDiag[d][row] 값이 dense matmul (별도 reference impl) 후 추출과 일치. **Reference impl:** `--mode dense-reference` flag 로 빌드, sparse 코드와 별도 파일 (테스트 전용).

### R3' (Verdict 일치 under C2)

C2 모드에서 Phase 6 APPROVED/REJECTED main 과 일치. threshold 근처 (±10%) 입력은 fragile → 회피.

### R4' (Determinism under Q4)

N=10 회 동일 입력 + 동일 빌드 sparse 출력 bit-동등. **cross-build instability 는 R4' 범위 밖** — separate process invariant.

### R5' (Pruning bound, β₂ > 0 — v2 명시)

threshold ∈ {0, 0.01, 0.05, 0.1, 0.5} 에서 D_sparse(thr_i) ≤ D_sparse(thr_{i-1}). **prerequisite: β₂ > 0** (β₂=0 시 vacuously true → 별도 baseline test).

### R6' (Memory regression)

dense graph 회귀 가드: `sparseDiag entries · 60 bytes < N²·8 bytes` 위반 시 dense matmul fallback 권고.

### R7' (Phase 5 parity — v2 신설)

sparse Phase 5 wall-clock ≡ main Phase 5 wall-clock ± 5% (sparse 가 Phase 5 미변경 검증).

### R8' (Sybil injection regression — v2 신설, Q3 적용 시)

알려진 sybil cluster 주입 (BitcoinOTC -10 weight edge 또는 합성 sybil) 후 trust score 변화. Q3 hub-aware sub-sampling 이 sybil 점수를 의도하지 않게 보존하지 않는지 검증.

### R9' (Multi-chunk equivalence under Q7 — v2 신설)

C7 padding bridge 적용 시 A1 C4 "Pattern Invariance" lemma 가 sparse 출력에서 보존됨을 multi-chunk run 으로 검증. R1' 의 multi-chunk 변형.

---

## 8. 개방 문제

- **O1:** A2 의 Phase 1 가속이 B 단계 bgsg 와 결합되면 PIR rotation 비용이 dominant → A2 ROI 약화 (부록 B.F3 실측 입증). **B 단계 측정에서 Phase별 wall-clock 변화 + Q6 D 보고 명시**
- **O2:** Pruning 이 sybil 방어상 의미 있는가? sybil 위장 vs 정직 약한 노드 trade-off — R8' 측정 → 별도 spec
- **O3:** M_pub sparse 표현 (Q5) — **A2 v2 에서 Critical 격상.** Phase 5 random access 성능 trade-off 측정 필요
- **O4:** β·threshold 자동 calibration (Q2) 의 일반화. multi-dataset (e.g., Slashdot, Epinions) future work
- **O5:** sparse 알고리즘이 multi-server 분산 환경에서 어떻게 작동하는가? 현재 single-server
- **O6:** sparseDiag 의 `unordered_map` 대신 dense vector — D_sparse 작을 때 메모리 회귀. R6' trigger 시 fallback
- **O7:** nGlobal=4096+ 케이스 측정 — sparse 의 강점 시연. Q5 + Q7 prerequisite

---

## 9. 비-목표

- **NG1.** sparse 신뢰 모델이 main 보다 "옳음" 을 주장하지 않음. spec 은 **알고리즘 등가성과 성능** 측정.
- **NG2.** PIR 익명성 영향 (graph plaintext 가정)
- **NG3.** A1 (bgsg) 와의 통합 — B 단계
- **NG4.** CKKS scheme 변경
- **NG5.** Phase 4, Phase 5 알고리즘 변경
- **NG6.** **(보안)** Side-channel timing — Phase 1 wall-clock 이 graph density 의존. graph-private 모델 외부
- **NG7.** **(보안)** Pruning 의 sybil-resilience — TPR/FPR 측정 (sec 6.3) 은 정량화일 뿐, 보안 audit 책임은 future spec
- **NG8.** **(보안)** β·threshold 의 client-server 협상 (deployment fingerprinting). simulation 한정
- **NG9 (v2 신설).** **(보안)** Pruning 의 availability attack 표면 — Q2 auto-calibration 활성화 시 adversary-controlled edge 분포로 threshold 조작 가능. Stage A2 외부
- **NG10 (v2 신설).** **(보안)** Q6 (D_sparse 보고) ↔ A1 NG7 (galois key step 협상 fingerprinting) cross-ref — D 노출이 graph density leak 표면 확장. B 단계 spec 책임
- **NG11 (v2 신설).** **(정확성/일반화)** β·threshold 가 BitcoinOTC 통계에 튜닝됨. 타 그래프로의 직접 이식 결과는 A2 보고 범위 밖. Q2 가 일반화 시도지만 검증은 future
- **NG12 (v2 신설).** **(정확성)** β₂=0.30 의 출처 정당화 — magic number 회피. 다른 데이터셋 / 다른 trust 모델 (EigenTrust 등) 비교는 별도 spec

---

## 10. 의존성 DAG와 적용 순서 (v2 정정)

```
[Root prerequisites — 병렬]
   Q4 (결정성) ─── 모든 비교군 baseline 통제
   Q1 (β·thr CLI) ─── R1' / C2 모드 prerequisite

[Sweep enablers — Q1 위에 빌드]
   Q2 (auto threshold) ─── Q1 단독 의존
   Q3 (hub-aware) ─── Q1 단독 의존 (Q2 와 병렬 가능)

[B-stage prerequisites]
   Q5 (M_pub sparse) ─── Q1 단독 의존, 4096 demo enabler
   Q6 (D 보고) ─── Q1 위에 빌드, A1 P4 연결
   Q7 (padding bridge) ─── 독립, B 진입 직전 필수
```

**키 dependency:**
- **Q1 / Q4 = root** (병렬 가능, 둘 다 모든 후속의 prerequisite)
- **Q5 / Q6 / Q7 = B-stage gate** — 셋 모두 적용 후 B 진입
- **Q2 / Q3 = optional** — sweep 시 활성화, B 단계 권장 사항

**v1 의 순서 (P5→P2→P3→P1→P4) 가 self-contradictory** 였음 — Q1 root 격상으로 해소.

---

## 11. 엔지니어링 노트

- **(a)** **신뢰 모델 변경의 명시적 분리** — 성능 최적화와 의미 변경이 한 PR 에 묶이는 것은 일반적 안티패턴. sparse 는 두 가지를 동시에 도입했으므로 본 spec 은 **차원 분리**해 측정.
- **(b)** **Pruning 의 데이터셋 의존성** — `0.05` 절대값은 BitcoinOTC weight scale (필터 후 d̄=3.628, w ∈ [2, 10]) 에만 의미. 일반 데이터셋용 percentile-기반 calibration (Q2) 필요. **NG11** 명시.
- **(c)** **`unordered_map` 비결정성** — FHE 시스템에서 재현성은 디버깅·보안·논문 reviewer 모두에게 핵심. ordered container 정착 (Q4). **추가 (v2): cache-pattern side-channel 도 완화**.
- **(d)** **Hub-aware 처리의 보안 trade-off** — 성능 최적화가 종종 sybil 방어 표면 형성. R8' sybil injection regression 필수.
- **(e) (v2 신설)** **데이터 사전처리 가정 명시** — `parts[2] >= 2` 필터 (E19) 가 음의 trust edge 를 silent drop. 신뢰 모델 분석 의 기반 가정.

---

## 부록 A — 변경 코드 참조 색인 (sparse 브랜치)

| 라인 | 항목 |
|---|---|
| 228 | `parts[2] >= 2` 필터 — 음의 trust drop (E19 근거) |
| 261 | main `outM_pub[tgt][src]` 방향 convention |
| 262 | `outAdj` 선언 |
| **265-273 (main)** | **dense matmul O(N³) — v1 의 "330-342" 표기 정정** |
| 265-275 (sparse) | edge 수집 + 1-hop M_pub 채움 + outAdj 빌드 |
| 272 (sparse) | sparse `outM_pub[tgtIdx][srcIdx]` (방향 main 과 동일) |
| 277 | `sparseDiag` 선언 (수정 대상: Q4) |
| 279-281 | β₁, β₂, threshold (수정 대상: Q1, **R1' prereq**) |
| 283-295 | sparse 2-hop loop (수정 대상: Q3 hub-aware) |
| 297-313 | sparseDiag → PirDiag 직렬화 (수정 대상: Q4 deterministic + Q7 padding) |
| 353 (sparse) | Phase 3 `cipherNeighbors isInit` guard (E20 근거) |
| 438 (sparse) | Phase 5 dense M_pub random access (Q5 근거) |
| 450 (sparse) | `ITERATIONS = 10` (Phase 5, R7' parity baseline) |

---

## 부록 B — 사전 실측: sparse vs main (v2 신설)

본 부록은 **사전 실측**으로 부록 A 의 코드 라인 위치 및 sec 3.2 의 의미 차이 주장을 데이터로 검증한다. 본격 sweep (sec 6) 전 1회 실측이며 sec 6 의 통계 프로토콜 (Wilcoxon, BH FDR) 은 적용하지 않는다.

### 실험 환경

- 머신: Darwin 25.5.0, single-threaded (sparse 는 OMP 미적용)
- 컴파일러: AppleClang via CMake default, SEAL 4.1.2
- 데이터셋: `soc-sign-bitcoinotc.csv` (35,592 행, `parts[2]>=2` 필터 후 V=3,302 / E=11,981 / d̄=3.628)

### Config A — Single-chunk (`-g 256 -s 64`, 4 valid targets, 1 chunk)

| Wallet | main FHE Score | sparse FHE Score | abs diff | Verdict (main / sparse) |
|---:|---:|---:|---:|---|
| 1 | 0.037138 | 0.041407 | +0.004269 | APPROVED / APPROVED |
| 2 | 0.014749 | 0.014749 | 0 | REJECTED / REJECTED |
| 4 | 0.014618 | 0.018272 | +0.003654 | **REJECTED / APPROVED** ← verdict flip |
| 35 | 0.020566 | 0.027752 | +0.007186 | APPROVED / APPROVED |

**Phase 별 wall-clock (Config A):**

| Phase | main (sec) | sparse (sec) | 비율 (main/sparse) |
|---|---:|---:|---:|
| InitFHE | 0.09 | 0.10 | 0.9× |
| Phase 1 | 0.74 | 0.66 | 1.12× (작음 — N=256 sparse 이득 미미) |
| Phase 3 | 0.91 | 0.91 | 1.0× (sparse 가 Phase 3 미변경) |
| Phase 5+6 | 2.07 | 2.09 | 0.99× (sparse 가 Phase 5 미변경, R7' baseline) |
| **Total** | **3.82** | **3.76** | **1.02×** |

### Config B — Multi-chunk (`-g 1024 -s 256`, 9 valid targets, 5 chunks)

| Wallet | main | sparse | abs diff | Verdict |
|---:|---:|---:|---:|---|
| 1 | 0.022786 | 0.025894 | +0.003108 | APPROVED / APPROVED |
| 2 | 0.007078 | 0.007078 | 0 | REJECTED / REJECTED |
| 4 | 0.006627 | 0.006627 | 0 | REJECTED / REJECTED |
| 7 | 0.022980 | 0.028075 | +0.005095 | APPROVED / APPROVED |
| 25 | 0.050181 | 0.050181 | 0 | APPROVED / APPROVED |
| 35 | 0.028612 | 0.029468 | +0.000856 | APPROVED / APPROVED |
| 88 | 0.001733 | 0.001733 | 0 | REJECTED / REJECTED |
| 100 | 0.000816 | 0.000816 | 0 | REJECTED / REJECTED |
| 200 | 0.000878 | 0.000878 | 0 | REJECTED / REJECTED |

**Phase 별 wall-clock (Config B):**

| Phase | main (sec) | sparse (sec) | 비율 |
|---|---:|---:|---:|
| InitFHE | 0.09 | 0.09 | 1.0× |
| Phase 1 | **7.73** | **2.56** | **3.03×** ← sparse 의 핵심 가속 |
| Phase 3 | 21.55 | 21.47 | 1.0× |
| Phase 5+6 | 48.90 | 48.90 | 1.0× |
| **Total** | **78.30** | **73.05** | **1.07×** |

### 발견 (Findings)

- **F1.** **Phase 1 가속 3.03×** at N=1024 — sec 2.1 의 O(N³) → O(V·d̄²) 가설 데이터 지지. N=256 에서는 1.12× (sparse 의 constant 가 main O(N³) 의 작은 N 영역에서는 압도되지 않음).
- **F2.** **Phase 3 / Phase 5 비변경 확인** — sparse 가 Phase 1 만 건드린다는 spec 주장 일관. R7' baseline.
- **F3.** **Total speedup 1.07× — Phase 3 dominance** — A2 단독으로는 Phase 3 가 dominant (21.5s vs Phase 1 절약 5s). **sparse 의 가치는 bgsg 와 결합 (B 단계) 했을 때 명확해진다** — O1 강한 동기.
- **F4.** **의미적 차이 정량 입증** — Config A wallet 4 의 verdict 가 **REJECTED → APPROVED 로 뒤집힘**. sec 3.2 의 "NOT EQUIVALENT" caveat 가 데이터로 입증됨. Config B 에서는 verdict 뒤집힘 없음 (다만 4/9 타겟에서 score 증가).
- **F5.** **Sparse 가 score 를 *증가* 시키는 방향 (예상 외)** — β₂=0.30 < 1.0 이라 2-hop 감쇠 효과로 sparse score 가 *감소* 할 것 같지만 실측은 반대. **추정 원인:** pruning 이 약한 src→mid edge 를 차단 → 약한 노드가 top-K 에 진입 안 함 → 선택된 subgraph 가 "더 깨끗" → 타겟의 sub-subgraph PageRank score 가 상대적으로 증가. **추후 검증 항목** (sec 6.3 sybil 메트릭 + subgraph 구성 비교).
- **F6.** **N=256 의 sparse 차별화 미미** — Phase 1 1.12× 가속에 그침. 본격 sweep 은 nGlobal ∈ {1024, 2048, 4096} 에 집중 가치 (sec 6.2 권장).

### 결론

본 사전 실측은 (i) sparse 의 Phase 1 가속이 실재 (3×), (ii) Phase 3 가 wall-clock dominant 라 B 단계 통합이 필수, (iii) sparse vs main 의미 차이가 verdict flip 으로 입증됨, 을 지지. 본 부록 의 결과는 sec 6 정식 sweep 의 사전 가설 calibration 용이며, 통계적 결론으로 사용하지 않는다.

---

## 부록 C — v1 → v2 변경 이력

| v1 위치 | 변경 |
|---|---|
| sec 1, sec 3.2, sec 11(a), 부록 A | **C-1**: main 라인 참조 `330-342/334-341` → 실제 `main:265-273` |
| sec 1.1 (신설), sec 2.1, sec 2.3 | **C-2**: BitcoinOTC 통계 재계산 (V=5,881→3,302, E=35,592→11,981, d̄=6.05→3.628). 메모리 이득 추정 `<8MB → ~5.4MB` 정정 |
| sec 3.1 Claim S2 | **C-3**: Index mapping table 추가, dense ↔ sparse 매핑 단계별 명시 |
| sec 3.2(b), 부록 B, sec 8 O2, sec 11 | **C-4**: pruning semantics 정정 — "약한 1-hop 차단" → "약한 src→mid edge 차단 = src 의 trust-emanation power 차단" |
| sec 5.1 (Q1), sec 7 R1', sec 10 DAG | **C-5**: Q1 을 root prerequisite 로 격상. DAG 재구성 |
| sec 4 E17, sec 5.5 (Q5) | **H-6**: Q5 (M_pub sparse) 를 "future O3" → Critical 격상. 4096 demo 의 메모리 bottleneck 정량 |
| sec 4 E13 → sec 5.7 (Q7 신설) | **H-5**: padding bridge Q7 신설, B-stage prerequisite |
| sec 9 NG9, NG10, NG11, NG12 | **H-3**: 데이터셋 일반화, Q6 fingerprinting cross-ref A1 NG7, β₂ magic number, availability attack 추가 |
| sec 6.2 | **H-1**: 4096 cell (Demo) 추가. **H-2**: β·thr 5×5 → 3×3 grid 축소 + N=5→N=10 (statistical power) |
| sec 6.4 | **H-4**: Wilcoxon vs assertion 프로토콜 분리 |
| sec 6.3 | Top-K K=`min(nSub, 10)` 명시, "pruned 2-hop ratio" 분모 정정, Cohen's d 추가, **sybil TPR/FPR 메트릭 신설 (H-7)** |
| sec 4 E19, E20, E21 신설 | filter silent drop, D_sparse=0 case, OMP race 추가 |
| sec 4 E1, E2, E8 위험도 재평가 | 실측 기반 — BitcoinOTC 중복 edge 0건 |
| sec 5.2 (Q2) | percentile_50 default 명시, mean-σ long-tail 부적합 근거 |
| sec 5.3 (Q3) | k=5 default 명시, sybil injection 우려 (R8' 신설) |
| sec 5.4 (Q4) | vector + sort 권장, **baseline 환경 통제로 격상** (모든 비교군 적용) |
| sec 5.6 (Q6) | `struct PhaseOneOutput` contract 명시 |
| sec 7 R5', R7', R8', R9' 신설 | β₂>0 prereq, Phase 5 parity, sybil injection regression, multi-chunk equivalence |
| 부록 B (신설) | **사전 실측: sparse vs main Config A/B + Findings F1~F6** |
| Caveat 박스 | verdict flip 사실 추가 |
