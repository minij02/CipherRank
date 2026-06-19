# 2. 그래프 전처리

Phase 1 의 목적은 BitcoinOTC csv 로부터 두 가지 산출물을 구성하는 데 있다. 하나는 Phase 5 가 부분 그래프를 재구성할 때 참조하는 1-홉 가중치 행렬 `M_pub` 이며, 다른 하나는 Phase 3 의 PIR 단계에서 평문 입력으로 사용되는 BSGS 대각선 리스트 `pirDiagonals` 이다. 본 장은 csv 한 행이 어떤 변환 과정을 거쳐 이들 두 산출물의 일부가 되는지를 §2.1 부터 §2.6 까지 순서대로 기술하고, 끝으로 §2.A 의 부록에서 N = 4 가상 예제 위에서의 손 계산 결과를 정의식과 직접 비교한다.

## 2.1 빈도 기반 전역 인덱싱

csv 파서 (`CipherRank.cpp:359–383`) 는 행을 한 줄씩 읽으면서 가중치가 2 이상인 행을 `rawEdges` 에 적재하고, 그 행의 송신자와 수신자에 대해 각각 `frequency` 카운트를 1 씩 증가시킨다. 시각 필드는 `int` 변환이 실패할 경우 `catch(...)` 로 무시되어 정수 부분만 살아남는다. 모든 행을 읽고 난 후의 `maxTime` 은 §2.2 의 시간 감쇠 기준점으로 사용된다.

빈도 카운트가 완성되면 내림차순으로 정렬하여 상위 N 개의 노드만 `globalNodeToIndex` 에 등록한다. 이 매핑에 등재되지 못한 노드는 이후 모든 계산에서 *존재하지 않는 것으로 간주* 되며, 평가 요청 목록에 그러한 노드가 포함된 경우 `[WARNING] Wallet ID X is out of range.` 의 로그가 출력되고 해당 요청은 평가에서 제외된다.

BitcoinOTC 데이터셋에서 상위 1024 위 노드의 빈도는 일반적으로 6 에서 8 사이의 값을 갖는다. 따라서 자연 sybil 검출의 대상이 되는 노드는 빈도가 이 컷오프 이상이어야 평가 가능 영역에 들어온다.

## 2.2 시간 감쇠

신뢰 평점은 시간이 경과할수록 그 영향력이 감소한다는 직관에 따라, 본 시스템은 반감기 1 년의 지수 감쇠를 적용한다 (`CipherRank.cpp:412`).

```cpp
double HALF_LIFE = 365.0 * 24.0 * 60.0 * 60.0;
double decay = pow(0.5, (maxTime - edge.time) / HALF_LIFE);
double w = edge.weight * decay;
```

이 감쇠 계수는 가지치기 임계값 θ = 0.05 와 직접적으로 연결된다. BitcoinOTC 의 `maxTime` 이 2016 년 1 월 무렵이므로, 그로부터 5 년 전의 +4 평점은 감쇠 후 `4 × 0.5⁵ = 0.125` 수준의 가중치만 보유하며, 6 년 전의 동일 평점은 `4 × 0.5⁶ ≈ 0.0625` 로 떨어진다. θ 와의 직접 비교가 가능하므로, 본 감쇠 모델은 사실상 2-홉 전파의 시간 윈도를 5 년 안쪽으로 자연스럽게 좁히는 효과를 갖는다.

## 2.3 1-홉 가중치 행렬과 인접 리스트

`outM_pub` 은 행이 수신자, 열이 송신자인 가중치 행렬이며, `outM_pub[tgt][src] += w` 의 누적으로 채워진다. 같은 (송신자, 수신자) 쌍에 대해 csv 에 여러 행이 존재하는 경우 모두 누적된다. 통합 브랜치에서는 동일한 루프에서 인접 리스트 `outAdj` 도 함께 구성되며 (`CipherRank.cpp:413–422`), 이는 §2.4 의 희소 2-홉 누적의 기반 자료구조가 된다.

```cpp
for (const auto& edge : rawEdges) {
    if (globalNodeToIndex.count(edge.src) && globalNodeToIndex.count(edge.tgt)) {
        int srcIdx = globalNodeToIndex[edge.src];
        int tgtIdx = globalNodeToIndex[edge.tgt];
        double decay = pow(0.5, (maxTime - edge.time) / HALF_LIFE);
        double w = edge.weight * decay;
        outM_pub[tgtIdx][srcIdx] += w;
        outAdj[srcIdx].push_back({tgtIdx, w});
    }
}
```

Q5 의 도입에 따라 `outM_pub` 자체는 `vector<unordered_map<int, double>>` 형태의 희소 표현으로 유지된다. 이는 Phase 5 에서 부분 행렬을 구성할 때 `operator[]` 가 미존재 키에 0 을 *삽입* 해 버리는 부작용을 피하기 위한 설계이며, 부분 행렬 추출은 const-safe 한 `SparseGet` 함수를 통해 이루어진다.

## 2.4 희소 2-홉 누적의 의미 모델

baseline 구현의 Phase 1 은 마지막 단계에서 `M_total = M_pub + M_pub · M_pub` 의 N × N × N 행렬 곱을 직접 수행한다. 이는 모든 1-홉 간선을 동일하게 2-홉 으로 전파한다는 의미를 가지며, N = 1024 의 경우 약 10⁹ 회의 부동소수점 곱셈을 요구한다.

본 시스템은 이 dense 곱을 인접 리스트 기반의 직접 누적으로 대체하면서, 동시에 의미 모델을 다음과 같이 일반화한다 (`CipherRank.cpp:434–447`).

```cpp
for (const auto& [mid, w1] : outAdj[src]) {
    int d1 = (src - mid + nGlobal) % nGlobal;
    localDiag[d1][mid] += beta1 * w1;

    if (w1 < prune_threshold) continue;

    for (const auto& [dst, w2] : outAdj[mid]) {
        int d2 = (src - dst + nGlobal) % nGlobal;
        localDiag[d2][dst] += beta2 * w1 * w2;
    }
}
```

여기서 인덱스 `d = (src − row + N) mod N` 는 행 `row` 의 열이 `(row + d) mod N = src` 가 되는 자리, 즉 행렬 `M_pub[row][src]` 에 대응한다. 위 누적의 의미는 다음 두 식으로 정리된다.

**1-홉 누적.** src 가 `(row + d)` 자리에 대응되고 mid 가 row 자리에 해당하므로,

$$\mathrm{localDiag}[d_1][\mathrm{mid}] \mathrel{{+}{=}} \beta_1 \cdot w_1 = \beta_1 \cdot M_{\mathrm{pub}}[\mathrm{mid}][\mathrm{src}].$$

모든 src 에 대한 합산은 1-홉 행렬의 d 번째 대각선과 일치한다.

**2-홉 누적.** (src, mid, dst) 경로에 대해

$$M_{\mathrm{pub}}^{2}[\mathrm{dst}][\mathrm{src}] = \sum_{\mathrm{mid}} M_{\mathrm{pub}}[\mathrm{dst}][\mathrm{mid}] \cdot M_{\mathrm{pub}}[\mathrm{mid}][\mathrm{src}]$$

가 성립하며, 따라서 β₂ · w₁ · w₂ 를 `localDiag[d₂][dst]` 에 누적한 결과는 β₂ · M_pub² 의 d 번째 대각선이 된다.

이를 통합하면 누적 결과의 정의식은 다음과 같이 표현된다.

$$\mathrm{sparseDiag}[d][\mathrm{row}] = \beta_1 \cdot M_{\mathrm{pub}}[\mathrm{row}][\mathrm{row} + d] + \beta_2 \cdot M_{\mathrm{pub}}^{2}[\mathrm{row}][\mathrm{row} + d] \quad \cdots (2.1)$$

(단, 조건부 가지치기 하에서 성립한다.)

baseline 의 경우 β₁ = β₂ = 1, 가지치기 없음 (θ = 0) 의 특수 케이스에 해당한다. 본 시스템의 기본값은 β₁ = 1.0, β₂ = 0.30, θ = 0.05 이며, 이는 약한 1-홉 (w₁ < θ) 으로부터의 2-홉 전파를 차단함으로써 시간 감쇠가 큰 오래된 간선의 영향력을 추가로 감쇠시키는 역할을 한다.

θ 의 의미는 §2.2 의 시간 감쇠와 결합하여 해석할 때 명확해진다. 약 6 년 전의 +2 평점이 시간 감쇠 후 `2 × 0.5⁶ ≈ 0.03` 으로 떨어지면 θ = 0.05 의 임계값에 못 미쳐 2-홉 전파에서 자동으로 제외된다. 즉 θ 는 "신뢰의 다리로 인정할 거래의 시간 범위" 를 정량적으로 정의하는 파라미터로 작동한다.

## 2.5 결정적 누적 — OpenMP 와 std::map reduce

위 루프는 src 를 외부 축으로 분할하면 자연스럽게 병렬화되지만, 여러 스레드가 동일한 `sparseDiag[d][row]` 항목을 동시에 갱신할 경우 부동소수점 데이터 경합이 발생한다. 본 시스템은 thread-local 누적 후 thread_id 순서의 sequential reduce 를 통해 이를 해결한다 (`CipherRank.cpp:430–469`).

```cpp
#pragma omp parallel
{
    int tid = omp_get_thread_num();
    auto& localDiag = tlSparseDiag[tid];
    #pragma omp for schedule(static)
    for (int src = 0; src < nGlobal; src++) {
        // 위 §2.4 의 누적 루프
    }
}

vector<map<int, double>> merged(nGlobal);
for (int t = 0; t < num_threads; t++)
    for (int d = 0; d < nGlobal; d++)
        for (auto& [row, val] : tlSparseDiag[t][d])
            merged[d][row] += val;

for (int d = 0; d < nGlobal; d++)
    for (auto& [row, val] : merged[d])
        if (val != 0.0) sparseDiag[d].emplace_back(row, val);
```

설계 의도를 세 가지로 정리한다.

첫째, 결합 순서가 thread_id 순서로 고정된다. 부동소수점 덧셈이 결합법칙을 완전히 만족하지 않으므로, 동일 입력에 대해 동일 결과를 보장하려면 합산 순서 자체가 결정적이어야 한다. P = 4 든 P = 8 이든 cross-run 결과가 일치해야 §6 의 등가성 검증이 의미를 가진다.

둘째, `std::map` 을 거치면서 row 가 자동으로 오름차순 정렬된다. 이후 BSGS 인코딩 단계에서 정해진 순서로 슬롯에 기록되므로 동일 입력에 대해 동일한 평문 직렬화가 보장된다.

셋째, `val != 0.0` 가드는 β₂ = 0 의 특수 케이스에서 발생하는 *값이 모두 0 인 비공실 (non-empty) sparseDiag* 를 사전에 제거한다. 이 가드의 부재가 SEAL 의 `result ciphertext is transparent` 예외를 유발하는 경위는 §6.4 에서 별도로 논의한다.

## 2.6 BSGS 대각선 인코딩과 Q7 패딩

`sparseDiag` 의 대각선 d 를 BSGS 의 baby/giant 분해에 맞추어 `BsgsDiag{i, j, Plaintext}` 의 형태로 인코딩하는 절차는 다음과 같다 (`CipherRank.cpp:476–500`).

```cpp
for (int j = 0; j < m2; j++) {
    for (int i = 0; i < m1; i++) {
        int d = j * m1 + i;
        if (d >= nGlobal) continue;
        if (sparseDiag[d].empty()) continue;

        vector<double> diag(slot_count, 0.0);
        for (size_t c = 0; c < batch_size; c++) {
            for (const auto& [row, val] : sparseDiag[d]) {
                int slot_idx = (row + j * m1) % nGlobal;
                diag[c * pirBlockSize + slot_idx] = val;
                diag[c * pirBlockSize + slot_idx + nGlobal] = val;  // Q7 패딩
            }
        }
        // CKKS encode + push BsgsDiag
    }
}
```

인덱스 분해 `d = j · m₁ + i` 의 의미는 §3.3 에서 본격적으로 다루지만, 본 절에서는 인코딩 단계에서의 효과만 명시한다. baby step i 는 *입력 ciphertext* 측에서 회전을 흡수하고, giant step j 는 *평문 대각선* 측에서 회전을 흡수한다. 따라서 동일한 d 의 평문이라도 j 의 값에 따라 원래 row 가 향해야 할 슬롯 위치가 달라지며, 그 위치는 정확히 `slot_idx = (row + j · m₁) mod N` 으로 결정된다.

**Q7 패딩.** 한 청크의 2N 슬롯 중 뒤쪽 N 슬롯에 앞쪽과 동일한 값을 복제하여 적는 처리이다. 이는 BSGS 의 giant step 회전이 청크 경계에 걸칠 수 있는 상황을 사전에 차단한다. 자세한 안전성 증명은 §3.5 의 C4 보조정리에서 다루며, 한 줄 요약은 "회전 후의 슬롯 분포가 어떻게 변하든 청크 영역 내부에 항상 의도된 값이 존재하도록 사전에 두 번 적어두는 처리" 이다.

`sparseDiag[d]` 가 비어 있는 d 는 인코딩 자체가 건너뛰어지며, 결과적으로 그 d 는 `pirDiagonals` 에 등장하지 않는다. Phase 3 의 평문 곱 단계는 이 빠진 d 를 자연스럽게 스킵하므로, *비공실 대각선의 수* D_sparse 가 BSGS 의 실제 평문 곱 횟수가 된다.

## 2.7 출력의 형상

Phase 1 의 두 최종 출력은 다음과 같다.

- `outM_pub` : 길이 N 의 `vector<unordered_map<int, double>>`. 행별 희소 표현으로, Phase 5 의 부분 행렬 추출에서 무작위 접근의 대상이 된다.
- `pirDiagonals` : 길이 D_sparse 의 `vector<BsgsDiag>`. 각 원소는 baby/giant 인덱스 쌍 (i, j) 과 CKKS 평문을 보유한다.

이 두 출력이 Phase 3 의 PIR 과 Phase 5 의 PageRank 의 *전체* 입력이며, 그 외에 외부에서 주입되는 정보는 클라이언트 측의 평가 대상 인덱스뿐이다.

---

## 부록 2.A — N = 4 예제에 대한 손 계산

§1.6 의 가상 csv 6 행으로부터 Phase 1 의 산출물을 직접 구성하고, 식 (2.1) 의 정의식과 비교 검증한다. 모든 시각이 동일하다는 가정에서 감쇠 계수가 1.0 으로 고정되므로 raw 가중치가 그대로 보존된다.

### 2.A.1 인접 리스트와 M_pub

전역 인덱스 매핑 적용 후의 변환은 다음 표와 같다.

| 원본 (src, tgt, w) | (srcIdx, tgtIdx, w) |
|---|---|
| (10, 20, 4) | (0, 2, 4) |
| (10, 30, 3) | (0, 1, 3) |
| (20, 30, 5) | (2, 1, 5) |
| (30, 40, 2) | (1, 3, 2) |
| (40, 10, 3) | (3, 0, 3) |
| (30, 10, 4) | (1, 0, 4) |

송신자별 출간선 리스트는 다음과 같이 구성된다.

```
outAdj[0] = [(2, 4), (1, 3)]
outAdj[1] = [(3, 2), (0, 4)]
outAdj[2] = [(1, 5)]
outAdj[3] = [(0, 3)]
```

행 = 수신자, 열 = 송신자의 4 × 4 dense 표기로 옮긴 M_pub 은 다음과 같다.

```
         src=0  src=1  src=2  src=3
tgt=0  [   0      4      0      3   ]
tgt=1  [   3      0      5      0   ]
tgt=2  [   4      0      0      0   ]
tgt=3  [   0      2      0      0   ]
```

### 2.A.2 sparseDiag 의 누적

β₁ = 1.0, β₂ = 0.3, θ = 0.05 의 기본 모드 하에서 §2.4 의 누적 루프를 src = 0, 1, 2, 3 순으로 펼친다. 본 예제의 모든 w₁ 은 정수 (≥ 2) 이므로 가지치기 조건은 어디서도 발동하지 않는다.

**src = 0 (wallet 10):**

- (mid = 2, w₁ = 4): d₁ = 2. `sparseDiag[2][2] += 4`
  - 2-홉 (dst = 1, w₂ = 5): d₂ = 3. `sparseDiag[3][1] += 0.3 · 4 · 5 = 6`
- (mid = 1, w₁ = 3): d₁ = 3. `sparseDiag[3][1] += 3` → 누적 9
  - 2-홉 (dst = 3, w₂ = 2): d₂ = 1. `sparseDiag[1][3] += 0.3 · 3 · 2 = 1.8`
  - 2-홉 (dst = 0, w₂ = 4): d₂ = 0. `sparseDiag[0][0] += 0.3 · 3 · 4 = 3.6`

**src = 1 (wallet 30):**

- (mid = 3, w₁ = 2): d₁ = 2. `sparseDiag[2][3] += 2`
  - 2-홉 (dst = 0, w₂ = 3): d₂ = 1. `sparseDiag[1][0] += 0.3 · 2 · 3 = 1.8`
- (mid = 0, w₁ = 4): d₁ = 1. `sparseDiag[1][0] += 4` → 누적 5.8
  - 2-홉 (dst = 2, w₂ = 4): d₂ = 3. `sparseDiag[3][2] += 0.3 · 4 · 4 = 4.8`
  - 2-홉 (dst = 1, w₂ = 3): d₂ = 0. `sparseDiag[0][1] += 0.3 · 4 · 3 = 3.6`

**src = 2 (wallet 20):**

- (mid = 1, w₁ = 5): d₁ = 1. `sparseDiag[1][1] += 5`
  - 2-홉 (dst = 3, w₂ = 2): d₂ = 3. `sparseDiag[3][3] += 0.3 · 5 · 2 = 3`
  - 2-홉 (dst = 0, w₂ = 4): d₂ = 2. `sparseDiag[2][0] += 0.3 · 5 · 4 = 6`

**src = 3 (wallet 40):**

- (mid = 0, w₁ = 3): d₁ = 3. `sparseDiag[3][0] += 3`
  - 2-홉 (dst = 2, w₂ = 4): d₂ = 1. `sparseDiag[1][2] += 0.3 · 3 · 4 = 3.6`
  - 2-홉 (dst = 1, w₂ = 3): d₂ = 2. `sparseDiag[2][1] += 0.3 · 3 · 3 = 2.7`

reduce 와 row 오름차순 정렬을 거친 최종 결과는 다음과 같다.

| d | sparseDiag[d] (row : val) |
|---:|---|
| 0 | { 0 : 3.6, 1 : 3.6 } |
| 1 | { 0 : 5.8, 1 : 5.0, 2 : 3.6, 3 : 1.8 } |
| 2 | { 0 : 6.0, 1 : 2.7, 2 : 4.0, 3 : 2.0 } |
| 3 | { 0 : 3.0, 1 : 9.0, 2 : 4.8, 3 : 3.0 } |

### 2.A.3 정의식과의 비교

식 (2.1) 의 우변에 해당하는 `M_pub + 0.3 · M_pub²` 의 d 번째 대각선을 직접 계산하여 §2.A.2 의 결과와 비교한다. M_pub² 의 16 개 성분은 행렬 곱 정의에 따라 다음과 같이 산출된다.

| | j=0 | j=1 | j=2 | j=3 |
|---|---:|---:|---:|---:|
| i=0 | 12 | 6 | 20 | 0 |
| i=1 | 20 | 12 | 0 | 9 |
| i=2 | 0 | 16 | 0 | 12 |
| i=3 | 6 | 0 | 10 | 0 |

(예: M²[0][0] = 0·0 + 4·3 + 0·4 + 3·0 = 12. M²[0][1] = 0·4 + 4·0 + 0·0 + 3·2 = 6.)

따라서 M_total = M_pub + 0.3 · M_pub² 는

```
[ 3.6   5.8   6.0   3.0 ]
[ 9.0   3.6   5.0   2.7 ]
[ 4.0   4.8   0.0   3.6 ]
[ 1.8   2.0   3.0   0.0 ]
```

이며, d 번째 대각선 `M_total[row][(row + d) mod 4]` 는 다음과 같이 정리된다.

- d = 0: (3.6, 3.6, 0, 0) — 비영 항만 남기면 {0: 3.6, 1: 3.6}. **§2.A.2 의 sparseDiag[0] 과 일치한다.**
- d = 1: (5.8, 5.0, 3.6, 1.8). **sparseDiag[1] 과 일치한다.**
- d = 2: (6.0, 2.7, 4.0, 2.0). **sparseDiag[2] 와 일치한다.**
- d = 3: (3.0, 9.0, 4.8, 3.0). **sparseDiag[3] 과 일치한다.**

모든 항이 소수점 한 자리까지 정확히 일치한다. 이로써 식 (2.1) 의 정의가 본 시스템의 코드에 누락 없이 옮겨졌음이 확인된다.

### 2.A.4 BsgsDiag 의 슬롯 분포

N = 4 의 경우 `FindOptimalAsymmetricBSGS(4, 1.0)` 의 반환은 m₁ = m₂ = 2 이며, d 의 분해는 다음과 같다.

| d | j (giant) | i (baby) |
|---:|---:|---:|
| 0 | 0 | 0 |
| 1 | 0 | 1 |
| 2 | 1 | 0 |
| 3 | 1 | 1 |

청크 하나, batch_size = 1, slot_count = 2N = 8 의 가정 하에서 각 BsgsDiag 의 평문 슬롯 벡터는 다음과 같이 채워진다 (`slot_idx = (row + 2j) mod 4` 위치와 그 +N 위치).

- (j = 0, i = 0), d = 0: `[3.6, 3.6, 0, 0, 3.6, 3.6, 0, 0]`
- (j = 0, i = 1), d = 1: `[5.8, 5.0, 3.6, 1.8, 5.8, 5.0, 3.6, 1.8]`
- (j = 1, i = 0), d = 2: `[4.0, 2.0, 6.0, 2.7, 4.0, 2.0, 6.0, 2.7]`
- (j = 1, i = 1), d = 3: `[4.8, 3.0, 3.0, 9.0, 4.8, 3.0, 3.0, 9.0]`

D_sparse = 4 = N 이므로 본 예제의 sparsity 는 0 이다. 이는 본 예제의 그래프가 작고 모든 d 가 비영 항을 보유하기 때문이며, 실제 BitcoinOTC 의 경우 D_sparse < N 으로 일정 비율의 sparsity 가 확보된다. 위 네 평문 벡터는 §3.A 의 BSGS 곱셈에서 one-hot 암호문과 결합된다.
